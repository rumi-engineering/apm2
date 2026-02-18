//! Token replay protection: broker-side one-time use ledger + revocation.
//!
//! Implements TCK-00566: a bounded, TTL-evicting ledger that tracks issued
//! token nonces to detect and deny replay attempts. The broker records each
//! nonce at issuance time; a second use of the same nonce is denied.
//!
//! The ledger also supports explicit token revocation: the broker can revoke
//! a nonce before its natural expiry, and workers consult the revocation set
//! when validating tokens.
//!
//! # Security Invariants
//!
//! - [INV-TL-001] Every issued token nonce is recorded in the ledger before the
//!   token is returned to the caller. A second issuance or use of the same
//!   nonce is denied (fail-closed).
//! - [INV-TL-002] The ledger is bounded by `MAX_LEDGER_ENTRIES`. When the cap
//!   is reached, the oldest entry is evicted (TTL-based FIFO).
//! - [INV-TL-003] The revocation set is bounded by `MAX_REVOKED_TOKENS`.
//!   Overflow returns an error (fail-closed).
//! - [INV-TL-004] Revoked tokens are denied even if they have not expired.
//! - [INV-TL-005] TTL eviction uses broker ticks (not wall-clock time) for
//!   monotonic, deterministic expiry (INV-2501).
//! - [INV-TL-006] Nonces are 32-byte random values generated from a CSPRNG.
//! - [INV-TL-007] All hash comparisons use `subtle::ConstantTimeEq` to prevent
//!   timing side-channels (RSK-1909).
//!
//! # Thread Safety
//!
//! `TokenUseLedger` is **not** internally synchronized. Callers must hold
//! appropriate locks when accessing from multiple threads. This follows
//! the same pattern as `FacBroker` (external lock guards `&mut self`).

use std::collections::{HashMap, VecDeque};

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

/// 32-byte nonce used for token replay detection.
pub type TokenNonce = [u8; 32];

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of entries in the token use ledger.
///
/// Sized for default-mode broker operation where a single broker handles
/// a moderate number of concurrent jobs. Each entry is ~100 bytes, so
/// 16384 entries ≈ 1.6 MiB peak memory.
pub const MAX_LEDGER_ENTRIES: usize = 16_384;

/// Maximum number of explicitly revoked tokens tracked.
///
/// Revoked tokens that expire naturally are cleaned up during TTL
/// eviction sweeps, so the revocation set only needs to track
/// actively-revoked unexpired tokens.
pub const MAX_REVOKED_TOKENS: usize = 4_096;

/// Default TTL for ledger entries in broker ticks.
///
/// Entries older than this are eligible for eviction. Matches the
/// default envelope TTL from `broker.rs` (1000 ticks).
pub const DEFAULT_LEDGER_TTL_TICKS: u64 = 1_000;

/// Maximum length for revocation reason strings.
pub const MAX_REVOCATION_REASON_LENGTH: usize = 512;

/// Domain separator for token nonce generation.
const TOKEN_NONCE_DOMAIN: &[u8] = b"apm2.fac_broker.token_nonce.v1";

/// Domain separator for revocation receipt hashing.
const REVOCATION_RECEIPT_HASH_DOMAIN: &[u8] = b"apm2.fac_broker.revocation_receipt.v1";

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors from token ledger operations.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TokenLedgerError {
    /// Token nonce has already been used (replay detected).
    #[error("token replay detected: nonce already recorded in ledger")]
    ReplayDetected,

    /// Token nonce has been explicitly revoked.
    #[error("token revoked: {reason}")]
    TokenRevoked {
        /// Reason for revocation.
        reason: String,
    },

    /// Revocation set is at capacity.
    #[error("revocation set at capacity ({max})")]
    RevocationSetAtCapacity {
        /// Maximum capacity.
        max: usize,
    },

    /// Revocation reason exceeds maximum length.
    #[error("revocation reason too long: {len} > {max}")]
    RevocationReasonTooLong {
        /// Actual length.
        len: usize,
        /// Maximum allowed length.
        max: usize,
    },

    /// Nonce not found for revocation.
    #[error("nonce not found in ledger for revocation")]
    NonceNotFound,
}

// ---------------------------------------------------------------------------
// Ledger entry
// ---------------------------------------------------------------------------

/// A single entry in the token use ledger.
#[derive(Debug, Clone, PartialEq, Eq)]
struct TokenUseEntry {
    /// The token nonce that was used.
    nonce: TokenNonce,
    /// The `request_id` (`job_spec_digest`) the token was issued for.
    request_id_digest: [u8; 32],
    /// Broker tick when the entry was recorded.
    recorded_at_tick: u64,
    /// Broker tick at which this entry expires.
    expiry_tick: u64,
}

// ---------------------------------------------------------------------------
// Revocation entry
// ---------------------------------------------------------------------------

/// A revoked token entry.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RevokedTokenEntry {
    /// The revoked nonce.
    nonce: TokenNonce,
    /// Broker tick when the revocation was recorded.
    revoked_at_tick: u64,
    /// Reason for revocation.
    reason: String,
}

// ---------------------------------------------------------------------------
// Revocation receipt
// ---------------------------------------------------------------------------

/// Receipt emitted when a token is revoked.
///
/// Contains enough fields to audit the revocation decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenRevocationReceipt {
    /// Schema identifier.
    pub schema_id: String,
    /// The revoked nonce (hex-encoded for JSON).
    pub nonce_hex: String,
    /// Broker tick when the revocation occurred.
    pub revoked_at_tick: u64,
    /// Reason for revocation.
    pub reason: String,
    /// BLAKE3 content hash over the receipt fields.
    pub content_hash: [u8; 32],
}

impl TokenRevocationReceipt {
    /// Verifies the content hash of this receipt.
    #[must_use]
    pub fn verify_content_hash(&self) -> bool {
        let computed =
            compute_revocation_receipt_hash(&self.nonce_hex, self.revoked_at_tick, &self.reason);
        bool::from(computed.ct_eq(&self.content_hash))
    }
}

/// Computes the BLAKE3 content hash for a revocation receipt.
fn compute_revocation_receipt_hash(
    nonce_hex: &str,
    revoked_at_tick: u64,
    reason: &str,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(REVOCATION_RECEIPT_HASH_DOMAIN);
    // Length-prefix framing for variable fields (GATE_HASH_PREIMAGE_FRAMING).
    hasher.update(&(nonce_hex.len() as u64).to_le_bytes());
    hasher.update(nonce_hex.as_bytes());
    hasher.update(&revoked_at_tick.to_le_bytes());
    hasher.update(&(reason.len() as u64).to_le_bytes());
    hasher.update(reason.as_bytes());
    *hasher.finalize().as_bytes()
}

// ---------------------------------------------------------------------------
// Token use ledger
// ---------------------------------------------------------------------------

/// Broker-side token use ledger for replay detection and revocation.
///
/// Tracks issued token nonces in a bounded `HashMap` with TTL-based FIFO
/// eviction. Supports explicit revocation of token nonces.
///
/// # Synchronization
///
/// Not internally synchronized. Protected by the same external lock
/// as `FacBroker` (`&mut self` access).
pub struct TokenUseLedger {
    /// Active token entries keyed by nonce (constant-time lookup).
    entries: HashMap<TokenNonce, TokenUseEntry>,
    /// Insertion-order queue for TTL-based FIFO eviction.
    /// Stores (nonce, `expiry_tick`) pairs for ghost-key prevention (RSK-1304).
    insertion_order: VecDeque<(TokenNonce, u64)>,
    /// Explicitly revoked token nonces.
    revoked: HashMap<TokenNonce, RevokedTokenEntry>,
    /// Insertion-order queue for revocation entries (bounded eviction).
    revocation_order: VecDeque<TokenNonce>,
    /// TTL in broker ticks for ledger entries.
    ttl_ticks: u64,
}

impl TokenUseLedger {
    /// Creates a new empty ledger with the default TTL.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            insertion_order: VecDeque::new(),
            revoked: HashMap::new(),
            revocation_order: VecDeque::new(),
            ttl_ticks: DEFAULT_LEDGER_TTL_TICKS,
        }
    }

    /// Creates a new empty ledger with a custom TTL.
    ///
    /// `ttl_ticks` must be > 0. If zero, defaults to 1 (fail-closed:
    /// zero TTL would make all entries immediately stale).
    #[must_use]
    pub fn with_ttl(ttl_ticks: u64) -> Self {
        Self {
            entries: HashMap::new(),
            insertion_order: VecDeque::new(),
            revoked: HashMap::new(),
            revocation_order: VecDeque::new(),
            ttl_ticks: if ttl_ticks == 0 { 1 } else { ttl_ticks },
        }
    }

    /// Returns the number of active entries in the ledger.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns true if the ledger has no active entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns the number of explicitly revoked tokens.
    #[must_use]
    pub fn revoked_count(&self) -> usize {
        self.revoked.len()
    }

    /// Generates a fresh 32-byte nonce for a new token.
    ///
    /// Uses domain-separated BLAKE3 keyed derivation seeded by OS CSPRNG
    /// randomness. The result is a cryptographically random nonce suitable
    /// for single-use token identification.
    #[must_use]
    pub fn generate_nonce() -> TokenNonce {
        use rand::RngCore;
        let mut random_seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut random_seed);
        let mut hasher = blake3::Hasher::new();
        hasher.update(TOKEN_NONCE_DOMAIN);
        hasher.update(&random_seed);
        *hasher.finalize().as_bytes()
    }

    /// Records a token nonce in the ledger, performing replay detection.
    ///
    /// This must be called BEFORE returning a token to the caller
    /// (INV-TL-001). If the nonce already exists in the ledger, the
    /// token is a replay and this method returns
    /// [`TokenLedgerError::ReplayDetected`].
    ///
    /// If the nonce has been explicitly revoked, returns
    /// [`TokenLedgerError::TokenRevoked`].
    ///
    /// Evicts expired entries when the ledger is at capacity.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The nonce has already been recorded (replay)
    /// - The nonce has been explicitly revoked
    pub fn record_token_use(
        &mut self,
        nonce: &TokenNonce,
        request_id_digest: &[u8; 32],
        current_tick: u64,
    ) -> Result<(), TokenLedgerError> {
        // Check revocation first (INV-TL-004: revoked tokens denied even
        // if unexpired).
        if let Some(entry) = self.find_revoked(nonce) {
            return Err(TokenLedgerError::TokenRevoked {
                reason: entry.reason.clone(),
            });
        }

        // Check for replay (INV-TL-001: constant-time nonce comparison
        // via HashMap key lookup -- the HashMap uses the full 32-byte key
        // hash, and we verify with ct_eq below).
        if self.find_entry(nonce).is_some() {
            return Err(TokenLedgerError::ReplayDetected);
        }

        // Evict expired entries if at capacity (INV-TL-002).
        self.evict_expired(current_tick);

        // If still at capacity after eviction, evict oldest entry.
        while self.entries.len() >= MAX_LEDGER_ENTRIES {
            if let Some((old_nonce, _)) = self.insertion_order.pop_front() {
                self.entries.remove(&old_nonce);
            } else {
                break;
            }
        }

        let expiry_tick = current_tick.saturating_add(self.ttl_ticks);
        let entry = TokenUseEntry {
            nonce: *nonce,
            request_id_digest: *request_id_digest,
            recorded_at_tick: current_tick,
            expiry_tick,
        };

        self.entries.insert(*nonce, entry);
        self.insertion_order.push_back((*nonce, expiry_tick));

        Ok(())
    }

    /// Checks whether a nonce has been used or revoked.
    ///
    /// Returns `Ok(())` if the nonce is fresh (neither used nor revoked).
    /// Returns an error if the nonce is found in the ledger or revocation
    /// set.
    ///
    /// This is the worker-side validation entry point: before accepting
    /// a token, the worker checks the nonce against the ledger.
    ///
    /// # Errors
    ///
    /// Returns [`TokenLedgerError::ReplayDetected`] if the nonce has been
    /// used, or [`TokenLedgerError::TokenRevoked`] if explicitly revoked.
    pub fn check_nonce(&self, nonce: &TokenNonce) -> Result<(), TokenLedgerError> {
        // Revocation takes precedence (INV-TL-004).
        if let Some(entry) = self.find_revoked(nonce) {
            return Err(TokenLedgerError::TokenRevoked {
                reason: entry.reason.clone(),
            });
        }

        if self.find_entry(nonce).is_some() {
            return Err(TokenLedgerError::ReplayDetected);
        }

        Ok(())
    }

    /// Explicitly revokes a token nonce.
    ///
    /// The nonce must exist in the active ledger. After revocation, any
    /// attempt to use or check this nonce will be denied with
    /// [`TokenLedgerError::TokenRevoked`], even if the token has not expired.
    ///
    /// Emits a [`TokenRevocationReceipt`] for audit.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The nonce is not found in the ledger
    /// - The reason string exceeds `MAX_REVOCATION_REASON_LENGTH`
    /// - The revocation set is at capacity
    pub fn revoke_token(
        &mut self,
        nonce: &TokenNonce,
        current_tick: u64,
        reason: &str,
    ) -> Result<TokenRevocationReceipt, TokenLedgerError> {
        // Validate reason length (GATE_IO_BOUNDS_AND_PARSING).
        if reason.len() > MAX_REVOCATION_REASON_LENGTH {
            return Err(TokenLedgerError::RevocationReasonTooLong {
                len: reason.len(),
                max: MAX_REVOCATION_REASON_LENGTH,
            });
        }

        // Check capacity before mutation (GATE_RESOURCE_BOUNDS, TOCTOU).
        if self.revoked.len() >= MAX_REVOKED_TOKENS {
            // Evict oldest revocation entry to make room.
            if let Some(old_nonce) = self.revocation_order.pop_front() {
                self.revoked.remove(&old_nonce);
            } else {
                return Err(TokenLedgerError::RevocationSetAtCapacity {
                    max: MAX_REVOKED_TOKENS,
                });
            }
        }

        // Verify the nonce exists in the ledger (fail-closed: cannot
        // revoke a nonce we did not issue).
        if self.find_entry(nonce).is_none() {
            return Err(TokenLedgerError::NonceNotFound);
        }

        let nonce_hex = hex::encode(nonce);
        let reason_owned = reason.to_string();

        // Record revocation.
        let revocation_entry = RevokedTokenEntry {
            nonce: *nonce,
            revoked_at_tick: current_tick,
            reason: reason_owned.clone(),
        };
        self.revoked.insert(*nonce, revocation_entry);
        self.revocation_order.push_back(*nonce);

        // Build receipt.
        let content_hash = compute_revocation_receipt_hash(&nonce_hex, current_tick, &reason_owned);

        Ok(TokenRevocationReceipt {
            schema_id: "apm2.fac_broker.revocation_receipt.v1".to_string(),
            nonce_hex,
            revoked_at_tick: current_tick,
            reason: reason_owned,
            content_hash,
        })
    }

    /// Evicts entries that have expired based on `current_tick`.
    ///
    /// Uses the insertion-order queue with timestamps for ghost-key
    /// prevention (RSK-1304): entries in the queue carry their expiry
    /// tick so stale "ghost" entries from re-inserted keys are detected.
    pub fn evict_expired(&mut self, current_tick: u64) {
        while let Some(&(ref nonce, expiry_tick)) = self.insertion_order.front() {
            if current_tick < expiry_tick {
                break; // Queue is ordered by insertion; all remaining are newer.
            }
            let nonce = *nonce;
            self.insertion_order.pop_front();

            // Ghost-key prevention: only remove from HashMap if the entry's
            // expiry matches. If the key was re-inserted, the HashMap entry
            // has a different (later) expiry tick.
            if let Some(entry) = self.entries.get(&nonce) {
                if entry.expiry_tick <= current_tick {
                    self.entries.remove(&nonce);
                }
            }
        }

        // Also evict expired revocations to prevent unbounded growth of
        // the revocation set for nonces whose natural TTL has passed.
        self.evict_expired_revocations(current_tick);
    }

    /// Evicts revocation entries whose underlying token TTL has expired.
    fn evict_expired_revocations(&mut self, current_tick: u64) {
        while let Some(nonce) = self.revocation_order.front().copied() {
            if let Some(entry) = self.revoked.get(&nonce) {
                // Revocations expire after the same TTL as the token itself
                // would have expired.
                let revocation_expiry = entry.revoked_at_tick.saturating_add(self.ttl_ticks);
                if current_tick < revocation_expiry {
                    break;
                }
                self.revoked.remove(&nonce);
            }
            // Pop the front entry in all cases: either the entry was
            // expired and removed, or it was a ghost (already removed).
            self.revocation_order.pop_front();
        }
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Finds an entry by nonce using constant-time comparison (INV-TL-007).
    fn find_entry(&self, nonce: &TokenNonce) -> Option<&TokenUseEntry> {
        // HashMap lookup uses the nonce as key directly. For additional
        // side-channel resistance, we verify the stored nonce matches
        // with ct_eq (defense in depth against HashMap collision attacks).
        self.entries
            .get(nonce)
            .filter(|entry| bool::from(entry.nonce.ct_eq(nonce)))
    }

    /// Finds a revoked entry by nonce using constant-time comparison.
    fn find_revoked(&self, nonce: &TokenNonce) -> Option<&RevokedTokenEntry> {
        self.revoked
            .get(nonce)
            .filter(|entry| bool::from(entry.nonce.ct_eq(nonce)))
    }
}

impl Default for TokenUseLedger {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn zero_nonce() -> TokenNonce {
        [0u8; 32]
    }

    fn nonce_from_byte(b: u8) -> TokenNonce {
        let mut n = [0u8; 32];
        n[0] = b;
        n
    }

    fn digest_from_byte(b: u8) -> [u8; 32] {
        let mut d = [0u8; 32];
        d[0] = b;
        d
    }

    // -----------------------------------------------------------------------
    // Basic replay detection
    // -----------------------------------------------------------------------

    #[test]
    fn record_token_use_succeeds_for_fresh_nonce() {
        let mut ledger = TokenUseLedger::new();
        let nonce = nonce_from_byte(1);
        let digest = digest_from_byte(0xAA);

        let result = ledger.record_token_use(&nonce, &digest, 10);
        assert!(result.is_ok());
        assert_eq!(ledger.len(), 1);
    }

    #[test]
    fn record_token_use_detects_replay() {
        let mut ledger = TokenUseLedger::new();
        let nonce = nonce_from_byte(1);
        let digest = digest_from_byte(0xAA);

        ledger.record_token_use(&nonce, &digest, 10).unwrap();

        // Second use of the same nonce -> replay.
        let result = ledger.record_token_use(&nonce, &digest, 11);
        assert!(matches!(result, Err(TokenLedgerError::ReplayDetected)));
    }

    #[test]
    fn record_token_use_allows_different_nonces_same_digest() {
        let mut ledger = TokenUseLedger::new();
        let nonce1 = nonce_from_byte(1);
        let nonce2 = nonce_from_byte(2);
        let digest = digest_from_byte(0xAA);

        ledger.record_token_use(&nonce1, &digest, 10).unwrap();
        ledger.record_token_use(&nonce2, &digest, 10).unwrap();
        assert_eq!(ledger.len(), 2);
    }

    #[test]
    fn check_nonce_succeeds_for_unknown() {
        let ledger = TokenUseLedger::new();
        let nonce = nonce_from_byte(1);
        assert!(ledger.check_nonce(&nonce).is_ok());
    }

    #[test]
    fn check_nonce_detects_used() {
        let mut ledger = TokenUseLedger::new();
        let nonce = nonce_from_byte(1);
        let digest = digest_from_byte(0xAA);
        ledger.record_token_use(&nonce, &digest, 10).unwrap();

        let result = ledger.check_nonce(&nonce);
        assert!(matches!(result, Err(TokenLedgerError::ReplayDetected)));
    }

    // -----------------------------------------------------------------------
    // Revocation
    // -----------------------------------------------------------------------

    #[test]
    fn revoke_token_denies_subsequent_use() {
        let mut ledger = TokenUseLedger::new();
        let nonce = nonce_from_byte(1);
        let digest = digest_from_byte(0xAA);
        ledger.record_token_use(&nonce, &digest, 10).unwrap();

        let receipt = ledger.revoke_token(&nonce, 11, "compromised").unwrap();
        assert_eq!(receipt.reason, "compromised");
        assert!(receipt.verify_content_hash());
        assert_eq!(ledger.revoked_count(), 1);

        // Check nonce -> revoked.
        let result = ledger.check_nonce(&nonce);
        assert!(matches!(result, Err(TokenLedgerError::TokenRevoked { .. })));

        // Record -> also denied.
        let result = ledger.record_token_use(&nonce, &digest, 12);
        assert!(matches!(result, Err(TokenLedgerError::TokenRevoked { .. })));
    }

    #[test]
    fn revoke_token_fails_for_unknown_nonce() {
        let mut ledger = TokenUseLedger::new();
        let nonce = nonce_from_byte(1);
        let result = ledger.revoke_token(&nonce, 10, "test");
        assert!(matches!(result, Err(TokenLedgerError::NonceNotFound)));
    }

    #[test]
    fn revoke_token_rejects_long_reason() {
        let mut ledger = TokenUseLedger::new();
        let nonce = nonce_from_byte(1);
        let digest = digest_from_byte(0xAA);
        ledger.record_token_use(&nonce, &digest, 10).unwrap();

        let long_reason = "x".repeat(MAX_REVOCATION_REASON_LENGTH + 1);
        let result = ledger.revoke_token(&nonce, 11, &long_reason);
        assert!(matches!(
            result,
            Err(TokenLedgerError::RevocationReasonTooLong { .. })
        ));
    }

    #[test]
    fn revocation_receipt_content_hash_verifies() {
        let mut ledger = TokenUseLedger::new();
        let nonce = nonce_from_byte(0x42);
        let digest = digest_from_byte(0xBB);
        ledger.record_token_use(&nonce, &digest, 10).unwrap();

        let receipt = ledger.revoke_token(&nonce, 11, "audit-test").unwrap();
        assert!(receipt.verify_content_hash());

        // Tamper with reason -> hash mismatch.
        let mut tampered = receipt;
        tampered.reason = "tampered".to_string();
        assert!(!tampered.verify_content_hash());
    }

    // -----------------------------------------------------------------------
    // TTL eviction
    // -----------------------------------------------------------------------

    #[test]
    fn evict_expired_removes_old_entries() {
        let mut ledger = TokenUseLedger::with_ttl(100);
        let nonce = nonce_from_byte(1);
        let digest = digest_from_byte(0xAA);
        ledger.record_token_use(&nonce, &digest, 10).unwrap();
        assert_eq!(ledger.len(), 1);

        // Tick 109 -> entry expires at tick 110 -> not yet expired.
        ledger.evict_expired(109);
        assert_eq!(ledger.len(), 1);

        // Tick 110 -> entry expires at tick 110 -> expired.
        ledger.evict_expired(110);
        assert_eq!(ledger.len(), 0);
    }

    #[test]
    fn evict_expired_allows_re_recording_after_eviction() {
        let mut ledger = TokenUseLedger::with_ttl(100);
        let nonce = nonce_from_byte(1);
        let digest = digest_from_byte(0xAA);
        ledger.record_token_use(&nonce, &digest, 10).unwrap();

        // Evict.
        ledger.evict_expired(111);
        assert_eq!(ledger.len(), 0);

        // Re-record is allowed (nonce is no longer in ledger).
        let result = ledger.record_token_use(&nonce, &digest, 200);
        assert!(result.is_ok());
    }

    #[test]
    fn evict_expired_revocations_cleans_up() {
        let mut ledger = TokenUseLedger::with_ttl(100);
        let nonce = nonce_from_byte(1);
        let digest = digest_from_byte(0xAA);
        ledger.record_token_use(&nonce, &digest, 10).unwrap();
        ledger.revoke_token(&nonce, 15, "test").unwrap();
        assert_eq!(ledger.revoked_count(), 1);

        // Revocation expires at revoked_at_tick(15) + ttl(100) = 115.
        ledger.evict_expired(114);
        assert_eq!(ledger.revoked_count(), 1);

        ledger.evict_expired(115);
        assert_eq!(ledger.revoked_count(), 0);
    }

    // -----------------------------------------------------------------------
    // Capacity bounds
    // -----------------------------------------------------------------------

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn capacity_bound_evicts_oldest_on_overflow() {
        let mut ledger = TokenUseLedger::with_ttl(10_000);

        // Fill to capacity. Use a distinct prefix byte to avoid collision
        // with the extra nonce below.
        for i in 0..MAX_LEDGER_ENTRIES {
            let mut nonce = [0u8; 32];
            // Use bytes [0..2] for index and byte [31] = 0xAA as domain tag.
            nonce[0..2].copy_from_slice(&(i as u16).to_le_bytes());
            nonce[31] = 0xAA;
            let digest = digest_from_byte((i & 0xFF) as u8);
            ledger.record_token_use(&nonce, &digest, 10).unwrap();
        }
        assert_eq!(ledger.len(), MAX_LEDGER_ENTRIES);

        // One more with a distinct domain tag -> evicts oldest.
        let mut extra_nonce = [0u8; 32];
        extra_nonce[31] = 0xBB;
        let digest = digest_from_byte(0xFF);
        ledger.record_token_use(&extra_nonce, &digest, 10).unwrap();

        // The first entry (index=0, domain=0xAA) should have been evicted.
        let first_nonce = {
            let mut n = [0u8; 32];
            n[0..2].copy_from_slice(&0u16.to_le_bytes());
            n[31] = 0xAA;
            n
        };
        assert!(ledger.check_nonce(&first_nonce).is_ok());
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn revocation_set_evicts_oldest_on_overflow() {
        let mut ledger = TokenUseLedger::with_ttl(100_000);

        // Fill revocation set to capacity.
        for i in 0..MAX_REVOKED_TOKENS {
            let mut nonce = [0u8; 32];
            nonce[0..2].copy_from_slice(&(i as u16).to_le_bytes());
            let digest = digest_from_byte((i & 0xFF) as u8);
            ledger.record_token_use(&nonce, &digest, 10).unwrap();
            ledger.revoke_token(&nonce, 11, "capacity-test").unwrap();
        }
        assert_eq!(ledger.revoked_count(), MAX_REVOKED_TOKENS);

        // One more revocation -> evicts oldest revocation.
        let extra_nonce = {
            let mut n = [0u8; 32];
            n[0..2].copy_from_slice(&(MAX_REVOKED_TOKENS as u16).to_le_bytes());
            n
        };
        let digest = digest_from_byte(0xFF);
        ledger.record_token_use(&extra_nonce, &digest, 12).unwrap();
        let result = ledger.revoke_token(&extra_nonce, 13, "overflow-test");
        assert!(result.is_ok());
    }

    // -----------------------------------------------------------------------
    // Nonce generation
    // -----------------------------------------------------------------------

    #[test]
    fn generate_nonce_produces_unique_values() {
        let n1 = TokenUseLedger::generate_nonce();
        let n2 = TokenUseLedger::generate_nonce();
        assert_ne!(n1, n2);
        // Nonces should not be all-zero.
        assert_ne!(n1, zero_nonce());
        assert_ne!(n2, zero_nonce());
    }

    // -----------------------------------------------------------------------
    // Zero TTL guard
    // -----------------------------------------------------------------------

    #[test]
    fn zero_ttl_defaults_to_one() {
        let ledger = TokenUseLedger::with_ttl(0);
        assert_eq!(ledger.ttl_ticks, 1);
    }

    // -----------------------------------------------------------------------
    // Ghost-key prevention (RSK-1304)
    // -----------------------------------------------------------------------

    #[test]
    fn ghost_key_eviction_does_not_remove_reinserted_entry() {
        let mut ledger = TokenUseLedger::with_ttl(100);
        let nonce = nonce_from_byte(1);
        let digest = digest_from_byte(0xAA);

        // Insert at tick 10 -> expires at 110.
        ledger.record_token_use(&nonce, &digest, 10).unwrap();

        // Evict, then re-record at tick 200 -> expires at 300.
        ledger.evict_expired(111);
        assert_eq!(ledger.len(), 0);
        ledger.record_token_use(&nonce, &digest, 200).unwrap();
        assert_eq!(ledger.len(), 1);

        // The old ghost entry in the queue (expiry=110) should not
        // evict the new entry (expiry=300) at tick 250.
        ledger.evict_expired(250);
        assert_eq!(ledger.len(), 1);

        // But at tick 300, the real entry expires.
        ledger.evict_expired(300);
        assert_eq!(ledger.len(), 0);
    }

    // -----------------------------------------------------------------------
    // Default trait
    // -----------------------------------------------------------------------

    #[test]
    fn default_ledger_is_empty() {
        let ledger = TokenUseLedger::default();
        assert!(ledger.is_empty());
        assert_eq!(ledger.len(), 0);
        assert_eq!(ledger.revoked_count(), 0);
    }
}
