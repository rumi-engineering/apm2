//! Token replay protection: broker-side one-time use ledger + revocation.
//!
//! Implements TCK-00566: a bounded, TTL-evicting ledger that tracks issued
//! and consumed token nonces to detect and deny replay attempts. The broker
//! registers each nonce at issuance time in an `Issued` state; when the
//! worker validates and consumes the token, the entry transitions to
//! `Consumed`. A second presentation of the same nonce is denied.
//!
//! The ledger also supports explicit token revocation: the broker can revoke
//! a nonce before its first use (in the `Issued` state) or after use (in the
//! `Consumed` state), and workers consult the revocation set when validating
//! tokens.
//!
//! # Persistence Model
//!
//! The ledger uses a write-ahead log (WAL) for incremental persistence.
//! Individual operations (record, revoke) are appended to the WAL as
//! single-line JSON entries, which requires only a small fixed-size write
//! per job. Periodically, a full snapshot is written and the WAL is
//! truncated (compaction). On startup, the latest snapshot is loaded and
//! the WAL is replayed to restore full ledger state.
//!
//! # Security Invariants
//!
//! - [INV-TL-001] Every token nonce is registered in the ledger at issuance
//!   time in an `Issued` state. When the worker validates the token via
//!   `validate_and_record_token_nonce`, the entry transitions to `Consumed`. A
//!   second presentation of the same nonce is denied (fail-closed).
//! - [INV-TL-002] The ledger is bounded by `MAX_LEDGER_ENTRIES`. When the cap
//!   is reached, the oldest entry is evicted (TTL-based FIFO).
//! - [INV-TL-003] The revocation set is bounded by `MAX_REVOKED_TOKENS`.
//!   Overflow returns an error (fail-closed).
//! - [INV-TL-004] Revoked tokens are denied even if they have not expired.
//! - [INV-TL-005] TTL eviction uses broker ticks (not wall-clock time) for
//!   monotonic, deterministic expiry (INV-2501).
//! - [INV-TL-006] Nonces are 32-byte random values generated from a CSPRNG.
//! - [INV-TL-007] Nonce lookups use `HashMap::get()` (O(1) average) with a
//!   post-lookup `subtle::ConstantTimeEq::ct_eq()` verification as defense in
//!   depth against hash-collision-based timing attacks. The `HashMap` approach
//!   is NOT constant-time over the full entry set; however, 32-byte random
//!   nonces (INV-TL-006) make collision-based timing leakage infeasible in
//!   practice (RSK-1909).
//! - [INV-TL-008] Nonces are registered at issuance in `Issued` state.
//!   `revoke_token` can revoke nonces in either `Issued` or `Consumed` state,
//!   closing the window for leaked-but-unused token exploitation.
//! - [INV-TL-009] Ledger persistence is fail-closed: load errors from an
//!   existing ledger file are hard security faults that refuse to continue.
//!   Save errors are propagated so the caller cannot silently run with
//!   undurable replay state.
//! - [INV-TL-010] WAL entries are appended with fsync for crash durability.
//!   Full snapshots use atomic write (temp+fsync+rename) per CTR-2607.
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
///
/// NOTE: These are compile-time constants. A future revision may accept
/// them via the `TokenUseLedger` constructor for deployment flexibility.
pub const MAX_LEDGER_ENTRIES: usize = 16_384;

/// Maximum number of explicitly revoked tokens tracked.
///
/// Revoked tokens that expire naturally are cleaned up during TTL
/// eviction sweeps, so the revocation set only needs to track
/// actively-revoked unexpired tokens.
///
/// NOTE: Compile-time constant; see `MAX_LEDGER_ENTRIES` note.
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

/// Number of WAL entries before automatic compaction is suggested.
///
/// The caller is responsible for triggering compaction when
/// `wal_entries_since_snapshot()` exceeds this threshold.
pub const WAL_COMPACTION_THRESHOLD: usize = 256;

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

    /// Nonce not found for revocation (not in issued or consumed state).
    #[error("nonce not found in ledger for revocation")]
    NonceNotFound,

    /// Persistence error (serialization, deserialization, I/O).
    #[error("token ledger persistence: {detail}")]
    Persistence {
        /// Detail string describing the persistence failure.
        detail: String,
    },
}

// ---------------------------------------------------------------------------
// Nonce lifecycle state
// ---------------------------------------------------------------------------

/// Lifecycle state of a nonce in the ledger.
///
/// Nonces transition: `Issued` -> `Consumed`. Both states can be
/// revoked. This supports pre-use revocation (INV-TL-008).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NonceState {
    /// Nonce was generated and included in a token at issuance time.
    /// The token has not yet been presented for use.
    Issued,
    /// Nonce was presented and validated by the worker. The token
    /// has been consumed and cannot be used again.
    Consumed,
}

// ---------------------------------------------------------------------------
// Ledger entry
// ---------------------------------------------------------------------------

/// A single entry in the token use ledger.
#[derive(Debug, Clone, PartialEq, Eq)]
struct TokenUseEntry {
    /// The token nonce that was issued/used.
    nonce: TokenNonce,
    /// The `request_id` (`job_spec_digest`) the token was issued for.
    request_id_digest: [u8; 32],
    /// Broker tick when the entry was recorded.
    recorded_at_tick: u64,
    /// Broker tick at which this entry expires.
    expiry_tick: u64,
    /// Current lifecycle state of the nonce.
    state: NonceState,
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
/// Contains enough fields to audit the revocation decision. The receipt is
/// signed by the broker's Ed25519 key with domain separation (INV-BRK-002)
/// so it constitutes authoritative evidence of the revocation event.
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
    /// Broker signer public key (Ed25519 verifying key bytes).
    /// Present on receipts signed by the broker. Absent on legacy
    /// unsigned receipts (backwards-compatible via `serde(default)`).
    #[serde(default, skip_serializing_if = "is_zero_hash_32")]
    pub signer_id: [u8; 32],
    /// Ed25519 signature over `REVOCATION_RECEIPT_SIGNATURE_PREFIX ||
    /// content_hash`. Present on receipts signed by the broker.
    #[serde(
        default = "default_zero_signature",
        skip_serializing_if = "is_zero_signature",
        with = "serde_bytes"
    )]
    pub signature: [u8; 64],
}

/// Domain separator for revocation receipt signatures (INV-BRK-002).
pub const REVOCATION_RECEIPT_SIGNATURE_PREFIX: &[u8] = b"TOKEN_REVOCATION_RECEIPT:";

/// Default zero signature for serde deserialization of legacy unsigned
/// receipts.
const fn default_zero_signature() -> [u8; 64] {
    [0u8; 64]
}

/// Returns true if a 32-byte array is all zeros (serde skip helper).
fn is_zero_hash_32(v: &[u8; 32]) -> bool {
    v.iter().all(|&b| b == 0)
}

/// Returns true if a 64-byte array is all zeros (serde skip helper).
fn is_zero_signature(v: &[u8; 64]) -> bool {
    v.iter().all(|&b| b == 0)
}

impl TokenRevocationReceipt {
    /// Verifies the content hash of this receipt.
    #[must_use]
    pub fn verify_content_hash(&self) -> bool {
        let computed =
            compute_revocation_receipt_hash(&self.nonce_hex, self.revoked_at_tick, &self.reason);
        bool::from(computed.ct_eq(&self.content_hash))
    }

    /// Verifies the broker signature on this receipt.
    ///
    /// Returns `true` if the signature is valid, `false` if the receipt is
    /// unsigned (legacy) or the signature does not verify.
    #[must_use]
    pub fn verify_signature(&self, verifying_key: &crate::crypto::VerifyingKey) -> bool {
        // Unsigned legacy receipt — cannot verify.
        if is_zero_signature(&self.signature) {
            return false;
        }
        // Verify signer matches the provided key.
        if !bool::from(self.signer_id.ct_eq(&verifying_key.to_bytes())) {
            return false;
        }
        let Ok(sig) = crate::crypto::parse_signature(&self.signature) else {
            return false;
        };
        crate::fac::domain_separator::verify_with_domain(
            verifying_key,
            REVOCATION_RECEIPT_SIGNATURE_PREFIX,
            &self.content_hash,
            &sig,
        )
        .is_ok()
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
// WAL entry types
// ---------------------------------------------------------------------------

/// A single WAL entry representing an incremental ledger mutation.
///
/// Each entry is serialized as a single JSON line for append-only I/O.
/// Public so the broker can pass WAL entries to the persistence layer
/// for immediate fsync before job execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, tag = "op")]
pub enum WalEntry {
    /// Register a nonce at issuance time (Issued state).
    #[serde(rename = "register")]
    Register {
        /// Hex-encoded 32-byte nonce.
        nonce_hex: String,
        /// Hex-encoded request ID digest.
        request_id_digest_hex: String,
        /// Broker tick when the nonce was registered.
        recorded_at_tick: u64,
        /// Broker tick at which the entry expires.
        expiry_tick: u64,
    },
    /// Record a nonce as consumed (Issued -> Consumed transition).
    ///
    /// Carries sufficient fields to reconstruct the entry on replay
    /// even if no prior `Register` WAL entry exists (crash after WAL
    /// truncation but before snapshot write — MAJOR finding fix).
    #[serde(rename = "consume")]
    Consume {
        /// Hex-encoded 32-byte nonce.
        nonce_hex: String,
        /// Hex-encoded request ID digest (needed for crash replay
        /// reconstruction when no prior Register entry exists).
        #[serde(default)]
        request_id_digest_hex: Option<String>,
        /// Broker tick when the nonce was consumed.
        consumed_at_tick: u64,
        /// Expiry tick for reconstruction on replay (needed when no
        /// prior Register entry exists).
        #[serde(default)]
        expiry_tick: Option<u64>,
    },
    /// Revoke a nonce.
    #[serde(rename = "revoke")]
    Revoke {
        /// Hex-encoded 32-byte nonce.
        nonce_hex: String,
        /// Broker tick when the nonce was revoked.
        revoked_at_tick: u64,
        /// Reason for revocation.
        reason: String,
    },
}

/// Maximum size in bytes for a single WAL line.
///
/// Prevents unbounded allocation from a corrupted WAL file.
/// A single WAL entry is at most ~300 bytes in JSON.
const MAX_WAL_LINE_SIZE: usize = 4_096;

// ---------------------------------------------------------------------------
// Token use ledger
// ---------------------------------------------------------------------------

/// Broker-side token use ledger for replay detection and revocation.
///
/// Tracks issued and consumed token nonces in a bounded `HashMap` with
/// TTL-based FIFO eviction. Supports explicit revocation of token nonces
/// in both `Issued` and `Consumed` states (INV-TL-008).
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
    /// Number of WAL entries written since last snapshot.
    wal_entries_since_snapshot: usize,
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
            wal_entries_since_snapshot: 0,
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
            wal_entries_since_snapshot: 0,
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

    /// Returns the number of WAL entries written since last snapshot.
    ///
    /// The caller should trigger compaction (snapshot + WAL truncation)
    /// when this exceeds [`WAL_COMPACTION_THRESHOLD`].
    #[must_use]
    pub const fn wal_entries_since_snapshot(&self) -> usize {
        self.wal_entries_since_snapshot
    }

    /// Resets the WAL entry counter (call after successful compaction).
    pub const fn reset_wal_counter(&mut self) {
        self.wal_entries_since_snapshot = 0;
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

    /// Registers a nonce at issuance time in `Issued` state (INV-TL-008).
    ///
    /// Called by the broker when issuing a new token. The nonce is recorded
    /// in the ledger so it can be revoked before first use. When the
    /// worker later validates the token, `record_token_use` transitions
    /// the entry to `Consumed` state.
    ///
    /// Returns a WAL entry for the caller to persist.
    ///
    /// # Errors
    ///
    /// Returns an error if the nonce already exists (collision, should
    /// be statistically impossible with CSPRNG 32-byte nonces).
    pub fn register_nonce(
        &mut self,
        nonce: &TokenNonce,
        request_id_digest: &[u8; 32],
        current_tick: u64,
    ) -> Result<WalEntry, TokenLedgerError> {
        // Check for existing entry (collision detection).
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
            state: NonceState::Issued,
        };

        self.entries.insert(*nonce, entry);
        self.insertion_order.push_back((*nonce, expiry_tick));
        self.wal_entries_since_snapshot = self.wal_entries_since_snapshot.saturating_add(1);

        Ok(WalEntry::Register {
            nonce_hex: hex::encode(nonce),
            request_id_digest_hex: hex::encode(request_id_digest),
            recorded_at_tick: current_tick,
            expiry_tick,
        })
    }

    /// Records a token nonce as consumed, performing replay detection.
    ///
    /// Called by the worker validation path after extracting the nonce
    /// from a decoded token (INV-TL-001). If the nonce is in `Consumed`
    /// state, the token is a replay and this method returns
    /// [`TokenLedgerError::ReplayDetected`].
    ///
    /// If the nonce has been explicitly revoked, returns
    /// [`TokenLedgerError::TokenRevoked`].
    ///
    /// If the nonce is in `Issued` state, transitions it to `Consumed`.
    /// If the nonce is not found (pre-TCK-00566 token without issuance
    /// registration), creates a new `Consumed` entry.
    ///
    /// Returns a WAL entry for the caller to persist.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The nonce has already been consumed (replay)
    /// - The nonce has been explicitly revoked
    pub fn record_token_use(
        &mut self,
        nonce: &TokenNonce,
        request_id_digest: &[u8; 32],
        current_tick: u64,
    ) -> Result<WalEntry, TokenLedgerError> {
        // Check revocation first (INV-TL-004: revoked tokens denied even
        // if unexpired).
        if let Some(entry) = self.find_revoked(nonce) {
            return Err(TokenLedgerError::TokenRevoked {
                reason: entry.reason.clone(),
            });
        }

        // Check existing entry state.
        if let Some(existing) = self.find_entry(nonce) {
            match existing.state {
                NonceState::Consumed => {
                    return Err(TokenLedgerError::ReplayDetected);
                },
                NonceState::Issued => {
                    // Transition from Issued to Consumed. This is the
                    // expected first-use path.
                },
            }
        }

        // Evict expired entries if at capacity (INV-TL-002).
        self.evict_expired(current_tick);

        // If the nonce already exists (Issued state), update it in place.
        if let Some(entry) = self.entries.get_mut(nonce) {
            let existing_expiry = entry.expiry_tick;
            entry.state = NonceState::Consumed;
            self.wal_entries_since_snapshot = self.wal_entries_since_snapshot.saturating_add(1);
            return Ok(WalEntry::Consume {
                nonce_hex: hex::encode(nonce),
                request_id_digest_hex: Some(hex::encode(request_id_digest)),
                consumed_at_tick: current_tick,
                expiry_tick: Some(existing_expiry),
            });
        }

        // Nonce not in ledger (pre-TCK-00566 token or nonce registered
        // on a different broker instance). Create a Consumed entry directly.
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
            state: NonceState::Consumed,
        };

        self.entries.insert(*nonce, entry);
        self.insertion_order.push_back((*nonce, expiry_tick));
        self.wal_entries_since_snapshot = self.wal_entries_since_snapshot.saturating_add(1);

        Ok(WalEntry::Consume {
            nonce_hex: hex::encode(nonce),
            request_id_digest_hex: Some(hex::encode(request_id_digest)),
            consumed_at_tick: current_tick,
            expiry_tick: Some(expiry_tick),
        })
    }

    /// Checks whether a nonce has been consumed or revoked.
    ///
    /// Returns `Ok(())` if the nonce is fresh (not consumed, not revoked).
    /// A nonce in `Issued` state is considered fresh for the purpose of
    /// this check (it has not been consumed yet).
    ///
    /// Returns an error if the nonce is found in `Consumed` state or in
    /// the revocation set.
    ///
    /// This is the worker-side validation entry point: before accepting
    /// a token, the worker checks the nonce against the ledger.
    ///
    /// # Errors
    ///
    /// Returns [`TokenLedgerError::ReplayDetected`] if the nonce has been
    /// consumed, or [`TokenLedgerError::TokenRevoked`] if explicitly revoked.
    pub fn check_nonce(&self, nonce: &TokenNonce) -> Result<(), TokenLedgerError> {
        // Revocation takes precedence (INV-TL-004).
        if let Some(entry) = self.find_revoked(nonce) {
            return Err(TokenLedgerError::TokenRevoked {
                reason: entry.reason.clone(),
            });
        }

        if let Some(entry) = self.find_entry(nonce) {
            if entry.state == NonceState::Consumed {
                return Err(TokenLedgerError::ReplayDetected);
            }
            // NonceState::Issued is fresh for check purposes — the token
            // has been issued but not yet consumed.
        }

        Ok(())
    }

    /// Explicitly revokes a token nonce.
    ///
    /// The nonce must exist in the active ledger in either `Issued` or
    /// `Consumed` state (INV-TL-008). After revocation, any attempt to
    /// use or check this nonce will be denied with
    /// [`TokenLedgerError::TokenRevoked`], even if the token has not expired.
    ///
    /// Emits a signed [`TokenRevocationReceipt`] for audit and a WAL entry
    /// for the caller to persist. The receipt is signed by the provided
    /// `signer` (INV-BRK-002).
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The nonce is not found in the ledger (neither issued nor consumed)
    /// - The reason string exceeds `MAX_REVOCATION_REASON_LENGTH`
    /// - The revocation set is at capacity
    pub fn revoke_token(
        &mut self,
        nonce: &TokenNonce,
        current_tick: u64,
        reason: &str,
        signer: &crate::crypto::Signer,
    ) -> Result<(TokenRevocationReceipt, WalEntry), TokenLedgerError> {
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

        // Verify the nonce exists in the ledger in any state (INV-TL-008:
        // revocation works on both Issued and Consumed nonces).
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
        self.wal_entries_since_snapshot = self.wal_entries_since_snapshot.saturating_add(1);

        // Build receipt with broker signature (INV-BRK-002).
        let content_hash = compute_revocation_receipt_hash(&nonce_hex, current_tick, &reason_owned);

        // Sign content_hash with domain separation.
        let sig = crate::fac::domain_separator::sign_with_domain(
            signer,
            REVOCATION_RECEIPT_SIGNATURE_PREFIX,
            &content_hash,
        );

        let receipt = TokenRevocationReceipt {
            schema_id: "apm2.fac_broker.revocation_receipt.v1".to_string(),
            nonce_hex: nonce_hex.clone(),
            revoked_at_tick: current_tick,
            reason: reason_owned.clone(),
            content_hash,
            signer_id: signer.verifying_key().to_bytes(),
            signature: sig.to_bytes(),
        };

        let wal_entry = WalEntry::Revoke {
            nonce_hex,
            revoked_at_tick: current_tick,
            reason: reason_owned,
        };

        Ok((receipt, wal_entry))
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

            // Defense-in-depth ghost-key check (RSK-1304): only remove
            // from HashMap if the entry's expiry matches. If the key was
            // re-inserted after eviction then re-recorded, the HashMap
            // entry has a different (later) expiry tick. This branch is
            // currently unreachable under normal operation because
            // `record_token_use` denies re-insertion of an existing nonce,
            // but it is retained as defense-in-depth against future code
            // changes that might alter insertion semantics.
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
// Persistence (TCK-00566: durable ledger with WAL)
// ---------------------------------------------------------------------------

/// Maximum size in bytes for the persisted token ledger file.
///
/// Prevents OOM from crafted ledger files (RSK-1601). Each entry is
/// ~200 bytes in JSON, so 16384 entries + 4096 revocations is well
/// under 8 MiB.
pub const MAX_TOKEN_LEDGER_FILE_SIZE: usize = 8 * 1024 * 1024;

/// Maximum size in bytes for the WAL file.
///
/// Bounded to prevent OOM from a WAL that was never compacted.
pub const MAX_WAL_FILE_SIZE: usize = 4 * 1024 * 1024;

/// Schema identifier for persisted token ledger state.
const TOKEN_LEDGER_SCHEMA_ID: &str = "apm2.fac_broker.token_ledger.v1";

/// Schema version for persisted token ledger state.
const TOKEN_LEDGER_SCHEMA_VERSION: &str = "1.1.0";

/// Persisted representation of a single token use entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedTokenUseEntry {
    /// Hex-encoded nonce.
    nonce_hex: String,
    /// Hex-encoded `request_id_digest`.
    request_id_digest_hex: String,
    /// Broker tick when recorded.
    recorded_at_tick: u64,
    /// Broker tick at which the entry expires.
    expiry_tick: u64,
    /// Lifecycle state of the nonce.
    #[serde(default = "default_consumed_state")]
    state: NonceState,
}

/// Default state for backwards compatibility with v1.0.0 snapshots
/// that lack the `state` field. All entries in v1.0.0 were implicitly
/// consumed (they were only recorded at use time).
const fn default_consumed_state() -> NonceState {
    NonceState::Consumed
}

/// Persisted representation of a revoked token entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedRevokedEntry {
    /// Hex-encoded nonce.
    nonce_hex: String,
    /// Broker tick when revoked.
    revoked_at_tick: u64,
    /// Reason for revocation.
    reason: String,
}

/// Persisted token ledger state envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedTokenLedgerState {
    /// Schema identifier.
    schema_id: String,
    /// Schema version.
    schema_version: String,
    /// TTL in ticks.
    ttl_ticks: u64,
    /// Active entries (ordered by insertion).
    entries: Vec<PersistedTokenUseEntry>,
    /// Revoked entries (ordered by revocation time).
    revoked: Vec<PersistedRevokedEntry>,
}

impl TokenUseLedger {
    /// Serializes a single WAL entry to a newline-terminated JSON line.
    ///
    /// # Errors
    ///
    /// Returns an error if JSON serialization fails.
    pub fn serialize_wal_entry(entry: &WalEntry) -> Result<Vec<u8>, TokenLedgerError> {
        let mut line = serde_json::to_vec(entry).map_err(|e| TokenLedgerError::Persistence {
            detail: format!("WAL entry serialization failed: {e}"),
        })?;
        line.push(b'\n');
        Ok(line)
    }

    /// Replays WAL entries from bytes, applying them to the ledger.
    ///
    /// Each line in the WAL is a JSON-encoded [`WalEntry`]. Lines that
    /// fail to parse are treated as a hard error (INV-TL-009: fail-closed).
    ///
    /// # Errors
    ///
    /// Returns an error if the WAL is too large or any line fails to parse.
    pub fn replay_wal(&mut self, wal_bytes: &[u8]) -> Result<usize, TokenLedgerError> {
        if wal_bytes.len() > MAX_WAL_FILE_SIZE {
            return Err(TokenLedgerError::Persistence {
                detail: format!(
                    "WAL file too large: {} > {MAX_WAL_FILE_SIZE}",
                    wal_bytes.len()
                ),
            });
        }

        let mut replayed = 0usize;
        for (line_num, line) in wal_bytes.split(|&b| b == b'\n').enumerate() {
            if line.is_empty() {
                continue;
            }
            if line.len() > MAX_WAL_LINE_SIZE {
                return Err(TokenLedgerError::Persistence {
                    detail: format!(
                        "WAL line {line_num} too large: {} > {MAX_WAL_LINE_SIZE}",
                        line.len()
                    ),
                });
            }
            let entry: WalEntry =
                serde_json::from_slice(line).map_err(|e| TokenLedgerError::Persistence {
                    detail: format!("WAL line {line_num} parse failed: {e}"),
                })?;
            self.apply_wal_entry(&entry)?;
            replayed = replayed.saturating_add(1);
        }

        Ok(replayed)
    }

    /// Applies a single WAL entry to the in-memory ledger state.
    fn apply_wal_entry(&mut self, entry: &WalEntry) -> Result<(), TokenLedgerError> {
        match entry {
            WalEntry::Register {
                nonce_hex,
                request_id_digest_hex,
                recorded_at_tick,
                expiry_tick,
            } => {
                let nonce = parse_nonce_hex(nonce_hex)?;
                let request_id_digest = parse_digest_hex(request_id_digest_hex)?;
                // Only insert if not already present (idempotent replay).
                if !self.entries.contains_key(&nonce) {
                    // Enforce cap.
                    while self.entries.len() >= MAX_LEDGER_ENTRIES {
                        if let Some((old_nonce, _)) = self.insertion_order.pop_front() {
                            self.entries.remove(&old_nonce);
                        } else {
                            break;
                        }
                    }
                    let entry = TokenUseEntry {
                        nonce,
                        request_id_digest,
                        recorded_at_tick: *recorded_at_tick,
                        expiry_tick: *expiry_tick,
                        state: NonceState::Issued,
                    };
                    self.entries.insert(nonce, entry);
                    self.insertion_order.push_back((nonce, *expiry_tick));
                }
            },
            WalEntry::Consume {
                nonce_hex,
                request_id_digest_hex,
                consumed_at_tick,
                expiry_tick,
            } => {
                let nonce = parse_nonce_hex(nonce_hex)?;
                if let Some(entry) = self.entries.get_mut(&nonce) {
                    // Idempotent: already consumed is a no-op.
                    entry.state = NonceState::Consumed;
                } else {
                    // MAJOR fix: reconstruct a Consumed entry even if no
                    // prior Register entry exists. This happens when the
                    // WAL survived a crash but the snapshot did not include
                    // the registration.
                    let reconstructed_expiry = expiry_tick
                        .unwrap_or_else(|| consumed_at_tick.saturating_add(self.ttl_ticks));
                    let reconstructed_digest = match request_id_digest_hex {
                        Some(hex_str) => parse_digest_hex(hex_str)?,
                        None => [0u8; 32], // Legacy WAL entry without digest.
                    };
                    // Enforce cap.
                    while self.entries.len() >= MAX_LEDGER_ENTRIES {
                        if let Some((old_nonce, _)) = self.insertion_order.pop_front() {
                            self.entries.remove(&old_nonce);
                        } else {
                            break;
                        }
                    }
                    let entry = TokenUseEntry {
                        nonce,
                        request_id_digest: reconstructed_digest,
                        recorded_at_tick: *consumed_at_tick,
                        expiry_tick: reconstructed_expiry,
                        state: NonceState::Consumed,
                    };
                    self.entries.insert(nonce, entry);
                    self.insertion_order
                        .push_back((nonce, reconstructed_expiry));
                }
            },
            WalEntry::Revoke {
                nonce_hex,
                revoked_at_tick,
                reason,
            } => {
                let nonce = parse_nonce_hex(nonce_hex)?;
                // MAJOR fix: idempotent — skip if already revoked to
                // prevent duplicate entries in revocation_order on replay.
                if self.revoked.contains_key(&nonce) {
                    // Already revoked — no-op for idempotent replay.
                } else {
                    // Enforce revocation cap.
                    if self.revoked.len() >= MAX_REVOKED_TOKENS {
                        if let Some(old_nonce) = self.revocation_order.pop_front() {
                            self.revoked.remove(&old_nonce);
                        }
                    }
                    let revocation_entry = RevokedTokenEntry {
                        nonce,
                        revoked_at_tick: *revoked_at_tick,
                        reason: reason.clone(),
                    };
                    self.revoked.insert(nonce, revocation_entry);
                    self.revocation_order.push_back(nonce);
                }
            },
        }
        Ok(())
    }

    /// Serializes the ledger state to JSON bytes for persistence (snapshot).
    ///
    /// # Errors
    ///
    /// Returns an error if JSON serialization fails.
    pub fn serialize_state(&self) -> Result<Vec<u8>, TokenLedgerError> {
        let entries: Vec<PersistedTokenUseEntry> = self
            .insertion_order
            .iter()
            .filter_map(|(nonce, _)| {
                self.entries.get(nonce).map(|e| PersistedTokenUseEntry {
                    nonce_hex: hex::encode(e.nonce),
                    request_id_digest_hex: hex::encode(e.request_id_digest),
                    recorded_at_tick: e.recorded_at_tick,
                    expiry_tick: e.expiry_tick,
                    state: e.state,
                })
            })
            .collect();

        let revoked: Vec<PersistedRevokedEntry> = self
            .revocation_order
            .iter()
            .filter_map(|nonce| {
                self.revoked.get(nonce).map(|e| PersistedRevokedEntry {
                    nonce_hex: hex::encode(e.nonce),
                    revoked_at_tick: e.revoked_at_tick,
                    reason: e.reason.clone(),
                })
            })
            .collect();

        let state = PersistedTokenLedgerState {
            schema_id: TOKEN_LEDGER_SCHEMA_ID.to_string(),
            schema_version: TOKEN_LEDGER_SCHEMA_VERSION.to_string(),
            ttl_ticks: self.ttl_ticks,
            entries,
            revoked,
        };

        serde_json::to_vec_pretty(&state).map_err(|e| TokenLedgerError::Persistence {
            detail: format!("serialization failed: {e}"),
        })
    }

    /// Deserializes a ledger from JSON bytes, restoring unexpired entries.
    ///
    /// Entries whose `expiry_tick` is at or below `current_tick` are dropped
    /// during load (TTL eviction on reload). Entries beyond
    /// `MAX_LEDGER_ENTRIES` are dropped (newest kept, oldest discarded).
    /// Revoked entries beyond `MAX_REVOKED_TOKENS` are dropped similarly.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The input exceeds `MAX_TOKEN_LEDGER_FILE_SIZE`
    /// - JSON deserialization fails
    /// - Schema id mismatch
    /// - Hex-encoded nonce/digest is malformed
    pub fn deserialize_state(bytes: &[u8], current_tick: u64) -> Result<Self, TokenLedgerError> {
        // Size gate before parsing (RSK-1601).
        if bytes.len() > MAX_TOKEN_LEDGER_FILE_SIZE {
            return Err(TokenLedgerError::Persistence {
                detail: format!(
                    "ledger file too large: {} > {MAX_TOKEN_LEDGER_FILE_SIZE}",
                    bytes.len()
                ),
            });
        }

        let state: PersistedTokenLedgerState =
            serde_json::from_slice(bytes).map_err(|e| TokenLedgerError::Persistence {
                detail: format!("deserialization failed: {e}"),
            })?;

        // Schema validation.
        if state.schema_id != TOKEN_LEDGER_SCHEMA_ID {
            return Err(TokenLedgerError::Persistence {
                detail: format!(
                    "schema id mismatch: expected {TOKEN_LEDGER_SCHEMA_ID}, got {}",
                    state.schema_id
                ),
            });
        }
        // Accept both v1.0.0 (pre-NonceState) and v1.1.0 snapshots.
        if state.schema_version != TOKEN_LEDGER_SCHEMA_VERSION && state.schema_version != "1.0.0" {
            return Err(TokenLedgerError::Persistence {
                detail: format!(
                    "schema version unsupported: expected {TOKEN_LEDGER_SCHEMA_VERSION} or 1.0.0, got {}",
                    state.schema_version
                ),
            });
        }

        let ttl_ticks = if state.ttl_ticks == 0 {
            1
        } else {
            state.ttl_ticks
        };

        let mut ledger = Self {
            entries: HashMap::new(),
            insertion_order: VecDeque::new(),
            revoked: HashMap::new(),
            revocation_order: VecDeque::new(),
            ttl_ticks,
            wal_entries_since_snapshot: 0,
        };

        // Restore active entries, dropping expired ones and enforcing cap.
        for persisted in &state.entries {
            // Skip expired entries.
            if persisted.expiry_tick <= current_tick {
                continue;
            }
            // Enforce cap (MAX_LEDGER_ENTRIES).
            if ledger.entries.len() >= MAX_LEDGER_ENTRIES {
                break;
            }
            let nonce = parse_nonce_hex(&persisted.nonce_hex)?;
            let request_id_digest = parse_digest_hex(&persisted.request_id_digest_hex)?;
            let entry = TokenUseEntry {
                nonce,
                request_id_digest,
                recorded_at_tick: persisted.recorded_at_tick,
                expiry_tick: persisted.expiry_tick,
                state: persisted.state,
            };
            ledger.entries.insert(nonce, entry);
            ledger
                .insertion_order
                .push_back((nonce, persisted.expiry_tick));
        }

        // Restore revocation entries, dropping expired ones and enforcing cap.
        for persisted in &state.revoked {
            let revocation_expiry = persisted.revoked_at_tick.saturating_add(ttl_ticks);
            // Skip expired revocations.
            if revocation_expiry <= current_tick {
                continue;
            }
            // Enforce cap (MAX_REVOKED_TOKENS).
            if ledger.revoked.len() >= MAX_REVOKED_TOKENS {
                break;
            }
            // Validate reason length.
            if persisted.reason.len() > MAX_REVOCATION_REASON_LENGTH {
                return Err(TokenLedgerError::Persistence {
                    detail: format!(
                        "revocation reason too long on load: {} > {MAX_REVOCATION_REASON_LENGTH}",
                        persisted.reason.len()
                    ),
                });
            }
            let nonce = parse_nonce_hex(&persisted.nonce_hex)?;
            let entry = RevokedTokenEntry {
                nonce,
                revoked_at_tick: persisted.revoked_at_tick,
                reason: persisted.reason.clone(),
            };
            ledger.revoked.insert(nonce, entry);
            ledger.revocation_order.push_back(nonce);
        }

        Ok(ledger)
    }
}

/// Parses a hex-encoded 32-byte nonce.
fn parse_nonce_hex(hex_str: &str) -> Result<TokenNonce, TokenLedgerError> {
    let bytes = hex::decode(hex_str).map_err(|e| TokenLedgerError::Persistence {
        detail: format!("invalid nonce hex: {e}"),
    })?;
    if bytes.len() != 32 {
        return Err(TokenLedgerError::Persistence {
            detail: format!("nonce hex decodes to {} bytes, expected 32", bytes.len()),
        });
    }
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&bytes);
    Ok(nonce)
}

/// Parses a hex-encoded 32-byte digest.
fn parse_digest_hex(hex_str: &str) -> Result<[u8; 32], TokenLedgerError> {
    let bytes = hex::decode(hex_str).map_err(|e| TokenLedgerError::Persistence {
        detail: format!("invalid digest hex: {e}"),
    })?;
    if bytes.len() != 32 {
        return Err(TokenLedgerError::Persistence {
            detail: format!("digest hex decodes to {} bytes, expected 32", bytes.len()),
        });
    }
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&bytes);
    Ok(digest)
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

    fn test_signer() -> crate::crypto::Signer {
        crate::crypto::Signer::generate()
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
    // Issued state and pre-use revocation (INV-TL-008)
    // -----------------------------------------------------------------------

    #[test]
    fn register_nonce_creates_issued_entry() {
        let mut ledger = TokenUseLedger::new();
        let nonce = nonce_from_byte(1);
        let digest = digest_from_byte(0xAA);

        let wal = ledger.register_nonce(&nonce, &digest, 10).unwrap();
        assert!(matches!(wal, WalEntry::Register { .. }));
        assert_eq!(ledger.len(), 1);

        // Issued nonce should be considered fresh for check purposes.
        assert!(ledger.check_nonce(&nonce).is_ok());
    }

    #[test]
    fn registered_nonce_can_be_consumed() {
        let mut ledger = TokenUseLedger::new();
        let nonce = nonce_from_byte(1);
        let digest = digest_from_byte(0xAA);

        ledger.register_nonce(&nonce, &digest, 10).unwrap();

        // Consume should succeed (Issued -> Consumed transition).
        let wal = ledger.record_token_use(&nonce, &digest, 11).unwrap();
        assert!(matches!(wal, WalEntry::Consume { .. }));

        // Now check should report replay.
        assert!(matches!(
            ledger.check_nonce(&nonce),
            Err(TokenLedgerError::ReplayDetected)
        ));
    }

    #[test]
    fn revoke_issued_nonce_denies_first_use() {
        let mut ledger = TokenUseLedger::new();
        let nonce = nonce_from_byte(1);
        let digest = digest_from_byte(0xAA);

        // Register at issuance time.
        ledger.register_nonce(&nonce, &digest, 10).unwrap();

        // Revoke BEFORE first use.
        let (receipt, _wal) = ledger
            .revoke_token(&nonce, 11, "leaked token", &test_signer())
            .unwrap();
        assert!(receipt.verify_content_hash());

        // First use should be denied (revoked).
        let result = ledger.record_token_use(&nonce, &digest, 12);
        assert!(matches!(result, Err(TokenLedgerError::TokenRevoked { .. })));

        // Check also denied.
        let result = ledger.check_nonce(&nonce);
        assert!(matches!(result, Err(TokenLedgerError::TokenRevoked { .. })));
    }

    #[test]
    fn revoke_without_prior_use_was_blocked_now_works() {
        // Previously, revoke_token required the nonce to be in active entries
        // (only inserted at first use). Now, register_nonce creates the entry
        // at issuance, so pre-use revocation works.
        let mut ledger = TokenUseLedger::new();
        let nonce = nonce_from_byte(1);
        let digest = digest_from_byte(0xAA);

        // Register the nonce (simulates issuance).
        ledger.register_nonce(&nonce, &digest, 10).unwrap();

        // Revoke before use should succeed.
        let result = ledger.revoke_token(&nonce, 11, "pre-use revocation", &test_signer());
        assert!(result.is_ok());
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

        let (receipt, _wal) = ledger
            .revoke_token(&nonce, 11, "compromised", &test_signer())
            .unwrap();
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
        let result = ledger.revoke_token(&nonce, 10, "test", &test_signer());
        assert!(matches!(result, Err(TokenLedgerError::NonceNotFound)));
    }

    #[test]
    fn revoke_token_rejects_long_reason() {
        let mut ledger = TokenUseLedger::new();
        let nonce = nonce_from_byte(1);
        let digest = digest_from_byte(0xAA);
        ledger.record_token_use(&nonce, &digest, 10).unwrap();

        let long_reason = "x".repeat(MAX_REVOCATION_REASON_LENGTH + 1);
        let result = ledger.revoke_token(&nonce, 11, &long_reason, &test_signer());
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

        let (receipt, _wal) = ledger
            .revoke_token(&nonce, 11, "audit-test", &test_signer())
            .unwrap();
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
        ledger
            .revoke_token(&nonce, 15, "test", &test_signer())
            .unwrap();
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
            ledger
                .revoke_token(&nonce, 11, "capacity-test", &test_signer())
                .unwrap();
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
        let result = ledger.revoke_token(&extra_nonce, 13, "overflow-test", &test_signer());
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

    // -----------------------------------------------------------------------
    // Persistence (TCK-00566: durable ledger)
    // -----------------------------------------------------------------------

    #[test]
    fn serialize_deserialize_round_trip_preserves_entries() {
        let mut ledger = TokenUseLedger::with_ttl(100);
        let nonce = nonce_from_byte(1);
        let digest = digest_from_byte(0xAA);
        ledger.record_token_use(&nonce, &digest, 10).unwrap();
        assert_eq!(ledger.len(), 1);

        let bytes = ledger.serialize_state().expect("serialize should succeed");
        let restored =
            TokenUseLedger::deserialize_state(&bytes, 10).expect("deserialize should succeed");
        assert_eq!(restored.len(), 1);

        // The nonce should be detected as used in the restored ledger.
        assert!(matches!(
            restored.check_nonce(&nonce),
            Err(TokenLedgerError::ReplayDetected)
        ));
    }

    #[test]
    fn deserialize_drops_expired_entries() {
        let mut ledger = TokenUseLedger::with_ttl(100);
        let nonce = nonce_from_byte(1);
        let digest = digest_from_byte(0xAA);
        ledger.record_token_use(&nonce, &digest, 10).unwrap();
        // Entry expires at tick 110.

        let bytes = ledger.serialize_state().expect("serialize should succeed");

        // Deserialize at tick 111 -> entry should be dropped.
        let restored =
            TokenUseLedger::deserialize_state(&bytes, 111).expect("deserialize should succeed");
        assert_eq!(restored.len(), 0);
    }

    #[test]
    fn serialize_deserialize_preserves_revocations() {
        let mut ledger = TokenUseLedger::with_ttl(100);
        let nonce = nonce_from_byte(1);
        let digest = digest_from_byte(0xAA);
        ledger.record_token_use(&nonce, &digest, 10).unwrap();
        ledger
            .revoke_token(&nonce, 15, "test-reason", &test_signer())
            .unwrap();
        assert_eq!(ledger.revoked_count(), 1);

        let bytes = ledger.serialize_state().expect("serialize should succeed");
        let restored =
            TokenUseLedger::deserialize_state(&bytes, 15).expect("deserialize should succeed");
        assert_eq!(restored.revoked_count(), 1);

        // The nonce should be denied as revoked.
        assert!(matches!(
            restored.check_nonce(&nonce),
            Err(TokenLedgerError::TokenRevoked { .. })
        ));
    }

    #[test]
    fn deserialize_rejects_oversized_input() {
        let oversized = vec![0u8; MAX_TOKEN_LEDGER_FILE_SIZE + 1];
        let result = TokenUseLedger::deserialize_state(&oversized, 0);
        assert!(matches!(result, Err(TokenLedgerError::Persistence { .. })));
    }

    #[test]
    fn deserialize_rejects_invalid_schema_id() {
        let bad_json = r#"{"schema_id":"wrong","schema_version":"1.0.0","ttl_ticks":100,"entries":[],"revoked":[]}"#;
        let result = TokenUseLedger::deserialize_state(bad_json.as_bytes(), 0);
        assert!(matches!(result, Err(TokenLedgerError::Persistence { .. })));
    }

    #[test]
    fn deserialize_rejects_malformed_nonce_hex() {
        let bad_json = r#"{"schema_id":"apm2.fac_broker.token_ledger.v1","schema_version":"1.0.0","ttl_ticks":100,"entries":[{"nonce_hex":"gg","request_id_digest_hex":"00","recorded_at_tick":1,"expiry_tick":100}],"revoked":[]}"#;
        let result = TokenUseLedger::deserialize_state(bad_json.as_bytes(), 0);
        assert!(matches!(result, Err(TokenLedgerError::Persistence { .. })));
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn deserialize_enforces_max_entries_cap() {
        // Create a ledger at capacity and serialize.
        let mut ledger = TokenUseLedger::with_ttl(100_000);
        for i in 0..MAX_LEDGER_ENTRIES {
            let mut nonce = [0u8; 32];
            nonce[0..2].copy_from_slice(&(i as u16).to_le_bytes());
            nonce[31] = 0xAA;
            let digest = digest_from_byte((i & 0xFF) as u8);
            ledger.record_token_use(&nonce, &digest, 10).unwrap();
        }
        let bytes = ledger.serialize_state().expect("serialize should succeed");

        // Deserialize should succeed with exactly MAX_LEDGER_ENTRIES.
        let restored =
            TokenUseLedger::deserialize_state(&bytes, 10).expect("deserialize should succeed");
        assert_eq!(restored.len(), MAX_LEDGER_ENTRIES);
    }

    // -----------------------------------------------------------------------
    // WAL tests
    // -----------------------------------------------------------------------

    #[test]
    fn wal_register_entry_round_trips() {
        let mut ledger = TokenUseLedger::with_ttl(100);
        let nonce = nonce_from_byte(1);
        let digest = digest_from_byte(0xAA);

        let wal = ledger.register_nonce(&nonce, &digest, 10).unwrap();
        let wal_bytes = TokenUseLedger::serialize_wal_entry(&wal).unwrap();

        let mut restored = TokenUseLedger::with_ttl(100);
        let replayed = restored.replay_wal(&wal_bytes).unwrap();
        assert_eq!(replayed, 1);
        assert_eq!(restored.len(), 1);

        // Issued nonce should be fresh.
        assert!(restored.check_nonce(&nonce).is_ok());
    }

    #[test]
    fn wal_consume_entry_round_trips() {
        let mut ledger = TokenUseLedger::with_ttl(100);
        let nonce = nonce_from_byte(1);
        let digest = digest_from_byte(0xAA);

        let wal_reg = ledger.register_nonce(&nonce, &digest, 10).unwrap();
        let wal_consume = ledger.record_token_use(&nonce, &digest, 11).unwrap();

        let mut all_wal = TokenUseLedger::serialize_wal_entry(&wal_reg).unwrap();
        all_wal.extend(TokenUseLedger::serialize_wal_entry(&wal_consume).unwrap());

        let mut restored = TokenUseLedger::with_ttl(100);
        let replayed = restored.replay_wal(&all_wal).unwrap();
        assert_eq!(replayed, 2);
        assert_eq!(restored.len(), 1);

        // Consumed nonce should be detected as replay.
        assert!(matches!(
            restored.check_nonce(&nonce),
            Err(TokenLedgerError::ReplayDetected)
        ));
    }

    #[test]
    fn wal_revoke_entry_round_trips() {
        let mut ledger = TokenUseLedger::with_ttl(100);
        let nonce = nonce_from_byte(1);
        let digest = digest_from_byte(0xAA);

        let wal_register = ledger.register_nonce(&nonce, &digest, 10).unwrap();
        let (_receipt, wal_revoke) = ledger
            .revoke_token(&nonce, 11, "test", &test_signer())
            .unwrap();

        let mut all_wal = TokenUseLedger::serialize_wal_entry(&wal_register).unwrap();
        all_wal.extend(TokenUseLedger::serialize_wal_entry(&wal_revoke).unwrap());

        let mut restored = TokenUseLedger::with_ttl(100);
        let replayed = restored.replay_wal(&all_wal).unwrap();
        assert_eq!(replayed, 2);
        assert_eq!(restored.revoked_count(), 1);

        assert!(matches!(
            restored.check_nonce(&nonce),
            Err(TokenLedgerError::TokenRevoked { .. })
        ));
    }

    #[test]
    fn wal_rejects_oversized_file() {
        let oversized = vec![b'x'; MAX_WAL_FILE_SIZE + 1];
        let mut ledger = TokenUseLedger::new();
        let result = ledger.replay_wal(&oversized);
        assert!(matches!(result, Err(TokenLedgerError::Persistence { .. })));
    }

    #[test]
    fn wal_rejects_malformed_line() {
        let bad_wal = b"not valid json\n";
        let mut ledger = TokenUseLedger::new();
        let result = ledger.replay_wal(bad_wal);
        assert!(matches!(result, Err(TokenLedgerError::Persistence { .. })));
    }

    #[test]
    fn wal_counter_increments_and_resets() {
        let mut ledger = TokenUseLedger::new();
        assert_eq!(ledger.wal_entries_since_snapshot(), 0);

        let nonce = nonce_from_byte(1);
        let digest = digest_from_byte(0xAA);
        ledger.register_nonce(&nonce, &digest, 10).unwrap();
        assert_eq!(ledger.wal_entries_since_snapshot(), 1);

        ledger.record_token_use(&nonce, &digest, 11).unwrap();
        assert_eq!(ledger.wal_entries_since_snapshot(), 2);

        ledger.reset_wal_counter();
        assert_eq!(ledger.wal_entries_since_snapshot(), 0);
    }

    // -----------------------------------------------------------------------
    // Nonce state preservation in serialization
    // -----------------------------------------------------------------------

    #[test]
    fn serialize_preserves_issued_state() {
        let mut ledger = TokenUseLedger::with_ttl(100);
        let nonce = nonce_from_byte(1);
        let digest = digest_from_byte(0xAA);

        ledger.register_nonce(&nonce, &digest, 10).unwrap();

        let bytes = ledger.serialize_state().unwrap();
        let restored = TokenUseLedger::deserialize_state(&bytes, 10).unwrap();
        assert_eq!(restored.len(), 1);

        // Issued nonce should be fresh (not replay).
        assert!(restored.check_nonce(&nonce).is_ok());

        // Should be consumable.
        let mut restored = restored;
        assert!(restored.record_token_use(&nonce, &digest, 11).is_ok());

        // Now it should be replay.
        assert!(matches!(
            restored.check_nonce(&nonce),
            Err(TokenLedgerError::ReplayDetected)
        ));
    }

    #[test]
    fn deserialize_v1_snapshot_defaults_to_consumed() {
        // v1.0.0 snapshots lack the "state" field. The serde default
        // should produce Consumed entries.
        let v1_json = r#"{"schema_id":"apm2.fac_broker.token_ledger.v1","schema_version":"1.0.0","ttl_ticks":100,"entries":[{"nonce_hex":"0100000000000000000000000000000000000000000000000000000000000000","request_id_digest_hex":"aa00000000000000000000000000000000000000000000000000000000000000","recorded_at_tick":10,"expiry_tick":110}],"revoked":[]}"#;
        let restored = TokenUseLedger::deserialize_state(v1_json.as_bytes(), 10).unwrap();
        assert_eq!(restored.len(), 1);

        // Should be detected as consumed (replay).
        let nonce = nonce_from_byte(1);
        assert!(matches!(
            restored.check_nonce(&nonce),
            Err(TokenLedgerError::ReplayDetected)
        ));
    }

    // -----------------------------------------------------------------------
    // Regression tests for fix-round review findings
    // -----------------------------------------------------------------------

    /// MAJOR regression: WAL Consume replay without prior Register must
    /// reconstruct a Consumed entry (crash recovery path). Before the fix,
    /// `apply_wal_entry(Consume)` was a no-op when the nonce was absent,
    /// leaving the ledger unaware of the consumed nonce and allowing replay.
    #[test]
    fn wal_consume_replay_without_prior_register_reconstructs_entry() {
        let mut ledger = TokenUseLedger::with_ttl(100);
        let nonce = nonce_from_byte(42);
        let nonce_hex = hex::encode(nonce);
        let digest_hex = hex::encode(digest_from_byte(0xBB));

        // Simulate a WAL with only a Consume entry (Register was in snapshot
        // but snapshot was lost / never written before crash).
        let consume_entry = WalEntry::Consume {
            nonce_hex,
            request_id_digest_hex: Some(digest_hex),
            consumed_at_tick: 50,
            expiry_tick: Some(150),
        };
        let wal_bytes = TokenUseLedger::serialize_wal_entry(&consume_entry).unwrap();
        let replayed = ledger.replay_wal(&wal_bytes).unwrap();
        assert_eq!(replayed, 1);

        // The nonce must now be present as Consumed — replay denied.
        assert!(matches!(
            ledger.check_nonce(&nonce),
            Err(TokenLedgerError::ReplayDetected)
        ));
        assert_eq!(ledger.len(), 1);
    }

    /// MAJOR regression: WAL Consume replay without digest or expiry
    /// (legacy WAL format) still reconstructs the entry.
    #[test]
    fn wal_consume_replay_legacy_format_without_digest_or_expiry() {
        let mut ledger = TokenUseLedger::with_ttl(100);
        let nonce = nonce_from_byte(43);
        let nonce_hex = hex::encode(nonce);

        // Legacy WAL entry: no request_id_digest_hex, no expiry_tick.
        let consume_entry = WalEntry::Consume {
            nonce_hex,
            request_id_digest_hex: None,
            consumed_at_tick: 50,
            expiry_tick: None,
        };
        let wal_bytes = TokenUseLedger::serialize_wal_entry(&consume_entry).unwrap();
        let replayed = ledger.replay_wal(&wal_bytes).unwrap();
        assert_eq!(replayed, 1);

        // Should still be detected as consumed.
        assert!(matches!(
            ledger.check_nonce(&nonce),
            Err(TokenLedgerError::ReplayDetected)
        ));
    }

    /// MAJOR regression: WAL Revoke replay must be idempotent — replaying
    /// the same Revoke entry twice must not push duplicate nonces into
    /// `revocation_order`. Before the fix, each replay appended a new
    /// entry, inflating the revocation set and eventually hitting capacity.
    #[test]
    fn wal_revoke_replay_idempotent_no_duplicate_revocation_order() {
        let mut ledger = TokenUseLedger::with_ttl(100);
        let nonce = nonce_from_byte(44);
        let digest = digest_from_byte(0xCC);

        // Register and consume the nonce first so revoke_token works.
        ledger.register_nonce(&nonce, &digest, 10).unwrap();

        let signer = test_signer();
        let (_receipt, wal_entry) = ledger.revoke_token(&nonce, 20, "test", &signer).unwrap();
        assert_eq!(ledger.revoked_count(), 1);

        // Serialize and replay the same Revoke WAL entry twice.
        let wal_bytes = TokenUseLedger::serialize_wal_entry(&wal_entry).unwrap();
        let mut wal_double = wal_bytes.clone();
        wal_double.extend_from_slice(&wal_bytes);

        let mut fresh_ledger = TokenUseLedger::with_ttl(100);
        // Re-register so the nonce exists for the replay context.
        fresh_ledger.register_nonce(&nonce, &digest, 10).unwrap();
        let replayed = fresh_ledger.replay_wal(&wal_double).unwrap();
        assert_eq!(replayed, 2); // 2 entries parsed...

        // ...but only 1 revocation in the set (idempotent).
        assert_eq!(fresh_ledger.revoked_count(), 1);
    }

    /// MAJOR regression: Signed revocation receipts must verify with the
    /// broker's public key. Before the fix, receipts had no signature.
    #[test]
    fn revocation_receipt_signed_and_verifiable() {
        let mut ledger = TokenUseLedger::with_ttl(100);
        let nonce = nonce_from_byte(45);
        let digest = digest_from_byte(0xDD);
        ledger.register_nonce(&nonce, &digest, 10).unwrap();

        let signer = test_signer();
        let vk = signer.verifying_key();
        let (receipt, _wal) = ledger
            .revoke_token(&nonce, 20, "signed test", &signer)
            .unwrap();

        // Signature must be non-zero.
        assert!(!is_zero_signature(&receipt.signature));
        // Signer ID must match.
        assert_eq!(receipt.signer_id, vk.to_bytes());
        // Verification must succeed.
        assert!(receipt.verify_signature(&vk));

        // Verification must fail with a different key.
        let other_signer = test_signer();
        let other_vk = other_signer.verifying_key();
        assert!(!receipt.verify_signature(&other_vk));
    }

    /// MAJOR regression: unsigned (legacy) revocation receipt returns
    /// false from `verify_signature`, not a panic or error.
    #[test]
    fn unsigned_legacy_receipt_verify_returns_false() {
        let receipt = TokenRevocationReceipt {
            schema_id: "apm2.fac_broker.revocation_receipt.v1".to_string(),
            nonce_hex: hex::encode(nonce_from_byte(99)),
            revoked_at_tick: 10,
            reason: "legacy".to_string(),
            content_hash: [0u8; 32],
            signer_id: [0u8; 32],
            signature: [0u8; 64],
        };
        let signer = test_signer();
        assert!(!receipt.verify_signature(&signer.verifying_key()));
    }

    /// BLOCKER regression: WAL entry produced by `record_token_use`
    /// (Consume) must carry the `request_id_digest_hex` and `expiry_tick`
    /// fields for crash-replay reconstruction.
    #[test]
    fn record_token_use_wal_entry_carries_reconstruction_fields() {
        let mut ledger = TokenUseLedger::with_ttl(100);
        let nonce = nonce_from_byte(46);
        let digest = digest_from_byte(0xEE);

        // Register first so the Issued->Consumed path is taken.
        ledger.register_nonce(&nonce, &digest, 10).unwrap();
        let wal_entry = ledger.record_token_use(&nonce, &digest, 15).unwrap();

        match wal_entry {
            WalEntry::Consume {
                request_id_digest_hex,
                expiry_tick,
                ..
            } => {
                assert!(
                    request_id_digest_hex.is_some(),
                    "digest must be present for replay reconstruction"
                );
                assert!(
                    expiry_tick.is_some(),
                    "expiry must be present for replay reconstruction"
                );
                assert_eq!(request_id_digest_hex.unwrap(), hex::encode(digest));
                assert_eq!(expiry_tick.unwrap(), 110); // 10 + ttl(100)
            },
            other => panic!("expected Consume WAL entry, got {other:?}"),
        }
    }

    /// Regression: `TokenRevocationReceipt` with signature round-trips
    /// through `serde_json` (exercises `serde_bytes` integration).
    #[test]
    fn revocation_receipt_serde_round_trip_with_signature() {
        let mut ledger = TokenUseLedger::with_ttl(100);
        let nonce = nonce_from_byte(47);
        let digest = digest_from_byte(0xFF);
        ledger.register_nonce(&nonce, &digest, 10).unwrap();

        let signer = test_signer();
        let (receipt, _wal) = ledger
            .revoke_token(&nonce, 20, "serde test", &signer)
            .unwrap();

        let json = serde_json::to_string(&receipt).unwrap();
        let restored: TokenRevocationReceipt = serde_json::from_str(&json).unwrap();

        assert_eq!(restored.signature, receipt.signature);
        assert_eq!(restored.signer_id, receipt.signer_id);
        assert!(restored.verify_signature(&signer.verifying_key()));
    }
}
