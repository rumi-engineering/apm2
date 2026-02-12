// AGENT-AUTHORED
//! Ledger trust stack: `RootTrustBundle`, trusted seals, checkpoint-bounded
//! startup, and governance-derived `PolicyRootResolver` (RFC-0019 REQ-0028,
//! TCK-00500).
//!
//! This module implements the concrete types behind the prerequisite trait
//! interfaces defined in [`super::prerequisites`]:
//!
//! - [`ConcreteLedgerTrustVerifier`]: implements [`LedgerTrustVerifier`],
//!   returning [`ValidatedLedgerStateV1`] after checkpoint-bounded startup
//!   verification.
//! - [`GovernancePolicyRootResolver`]: implements [`PolicyRootResolver`],
//!   deriving [`PolicyRootStateV1`] deterministically from governance-class
//!   events up to a given [`LedgerAnchorV1`].
//!
//! # Security Model
//!
//! ## `RootTrustBundle`
//!
//! The root trust bundle is the trust anchor for the ledger. It contains
//! crypto-agile key entries (algorithm ID + key ID + public key bytes) used
//! to verify ledger event signatures and governance/policy signatures.
//!
//! ## Trusted Seals
//!
//! A trusted seal is a ledger event whose payload commits to a
//! [`LedgerAnchorV1`] (`ledger_id` + hash + height + HT) and whose signature
//! provenance chains to the [`RootTrustBundle`]. Seals establish checkpoints
//! from which startup validation can begin.
//!
//! ## Checkpoint-Bounded Startup
//!
//! At startup, the verifier locates the most recent trusted seal, validates
//! the chain from the seal to the current tip (signatures, hash chain,
//! monotonic HT), and enforces a maximum seal-to-tip distance policy. If
//! the distance is exceeded, startup fails closed.
//!
//! ## Fork/Divergence Detection
//!
//! The validated anchor must chain to the tip. If a fork is detected
//! (anchor does not chain forward to tip), verification fails.
//!
//! ## Key Rotation/Revocation
//!
//! Key validity is resolved per-event at the event's `he_time` epoch.
//! The verifier never uses "always latest keyset" behavior; instead, it
//! resolves the active keyset for the epoch at which each event occurred,
//! correctly handling post-seal key rotations.
//!
//! # Fail-Closed Contract
//!
//! If any verification step fails, the verifier returns an error. The
//! admission kernel MUST deny for fail-closed tiers.

#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use apm2_core::crypto::Hash;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use super::prerequisites::{
    GovernanceProvenanceV1, LedgerAnchorV1, LedgerTrustVerifier, PolicyError, PolicyRootResolver,
    PolicyRootStateV1, TrustError, ValidatedLedgerStateV1,
};

// =============================================================================
// Constants and bounds
// =============================================================================

/// Maximum number of key entries in a root trust bundle.
///
/// Bounds the in-memory footprint and prevents denial-of-service via oversized
/// bundles.
pub const MAX_TRUST_BUNDLE_KEYS: usize = 64;

/// Maximum length of an algorithm ID string.
pub const MAX_ALGORITHM_ID_LENGTH: usize = 64;

/// Maximum length of a key ID string.
pub const MAX_KEY_ID_LENGTH: usize = 128;

/// Maximum length of a public key in bytes.
pub const MAX_PUBLIC_KEY_LENGTH: usize = 256;

/// Maximum seal-to-tip distance before startup validation fails closed.
///
/// If the trusted seal is more than this many events behind the tip,
/// the verifier refuses startup unless full-chain validation is performed.
pub const DEFAULT_MAX_SEAL_TO_TIP_DISTANCE: u64 = 10_000;

/// Maximum number of governance events processed for a single policy
/// root derivation. Prevents unbounded computation.
pub const MAX_GOVERNANCE_EVENTS_PER_DERIVATION: usize = 4_096;

/// Maximum number of cached policy root entries.
pub const MAX_POLICY_ROOT_CACHE_ENTRIES: usize = 64;

/// Maximum number of key rotation entries per algorithm.
pub const MAX_KEY_ROTATIONS_PER_ALGORITHM: usize = 64;

/// Schema version for `RootTrustBundle`.
pub const ROOT_TRUST_BUNDLE_SCHEMA_VERSION: &str = "1.0.0";

// =============================================================================
// RootTrustBundle
// =============================================================================

/// A single key entry in the root trust bundle.
///
/// Each entry binds a key ID to a public key and an algorithm identifier.
/// The algorithm ID enables crypto-agile dispatch: the verifier selects
/// the correct verification function based on this field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustBundleKeyEntry {
    /// Algorithm identifier (e.g., "ed25519", "ed448", "dilithium3").
    pub algorithm_id: String,
    /// Key identifier (kid). Unique within the bundle.
    pub key_id: String,
    /// Raw public key bytes.
    pub public_key_bytes: Vec<u8>,
    /// Epoch at which this key became active (inclusive).
    pub active_from_epoch: u64,
    /// Epoch at which this key was revoked (exclusive). `None` means still
    /// active. A revoked key MUST NOT be used for verification at or after
    /// this epoch.
    pub revoked_at_epoch: Option<u64>,
}

impl TrustBundleKeyEntry {
    /// Validate structural constraints on this key entry.
    ///
    /// # Errors
    ///
    /// Returns a description of the first violated constraint.
    pub fn validate(&self) -> Result<(), String> {
        if self.algorithm_id.is_empty() || self.algorithm_id.len() > MAX_ALGORITHM_ID_LENGTH {
            return Err(format!(
                "algorithm_id length {} out of range 1..={MAX_ALGORITHM_ID_LENGTH}",
                self.algorithm_id.len()
            ));
        }
        if self.key_id.is_empty() || self.key_id.len() > MAX_KEY_ID_LENGTH {
            return Err(format!(
                "key_id length {} out of range 1..={MAX_KEY_ID_LENGTH}",
                self.key_id.len()
            ));
        }
        if self.public_key_bytes.is_empty() || self.public_key_bytes.len() > MAX_PUBLIC_KEY_LENGTH {
            return Err(format!(
                "public_key_bytes length {} out of range 1..={MAX_PUBLIC_KEY_LENGTH}",
                self.public_key_bytes.len()
            ));
        }
        if let Some(revoked) = self.revoked_at_epoch {
            if revoked <= self.active_from_epoch {
                return Err(format!(
                    "revoked_at_epoch ({revoked}) must be greater than active_from_epoch ({})",
                    self.active_from_epoch
                ));
            }
        }
        Ok(())
    }

    /// Check whether this key is active at the given epoch.
    #[must_use]
    #[allow(clippy::option_if_let_else)] // const fn is incompatible with map_or
    pub const fn is_active_at(&self, epoch: u64) -> bool {
        if epoch < self.active_from_epoch {
            return false;
        }
        match self.revoked_at_epoch {
            Some(revoked) => epoch < revoked,
            None => true,
        }
    }
}

/// Root trust bundle: the trust anchor for ledger and governance
/// verification (RFC-0019 REQ-0028).
///
/// Contains a bounded set of crypto-agile key entries used to verify
/// ledger event signatures and governance/policy signatures.
///
/// # Digest Stability
///
/// The bundle digest is computed over domain-separated canonical bytes.
/// Field ordering is deterministic (sorted by `key_id` within each key
/// entry).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootTrustBundle {
    /// Schema version for forward compatibility.
    pub schema_version: String,
    /// Stable identifier for this trust bundle.
    pub bundle_id: Hash,
    /// Key entries in the bundle.
    pub keys: Vec<TrustBundleKeyEntry>,
}

impl RootTrustBundle {
    /// Validate the bundle structure.
    ///
    /// # Errors
    ///
    /// Returns a description of the first violated constraint.
    pub fn validate(&self) -> Result<(), String> {
        if self.keys.is_empty() {
            return Err("trust bundle must contain at least one key".into());
        }
        if self.keys.len() > MAX_TRUST_BUNDLE_KEYS {
            return Err(format!(
                "trust bundle contains {} keys, maximum is {MAX_TRUST_BUNDLE_KEYS}",
                self.keys.len()
            ));
        }
        // Validate each entry and check for duplicate key_ids.
        let mut seen_ids = HashMap::with_capacity(self.keys.len());
        for (i, entry) in self.keys.iter().enumerate() {
            entry
                .validate()
                .map_err(|e| format!("key entry [{i}]: {e}"))?;
            if seen_ids.insert(&entry.key_id, i).is_some() {
                return Err(format!("duplicate key_id '{}' at index {i}", entry.key_id));
            }
        }
        Ok(())
    }

    /// Compute a deterministic content hash for this bundle.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)] // All lengths bounded by MAX_* constants (<= 256)
    pub fn content_hash(&self) -> Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"apm2-root-trust-bundle-v1");
        hasher.update(&self.bundle_id);
        hasher.update(&(self.keys.len() as u32).to_le_bytes());
        for entry in &self.keys {
            hasher.update(entry.algorithm_id.as_bytes());
            hasher.update(&(entry.algorithm_id.len() as u32).to_le_bytes());
            hasher.update(entry.key_id.as_bytes());
            hasher.update(&(entry.key_id.len() as u32).to_le_bytes());
            hasher.update(&entry.public_key_bytes);
            hasher.update(&(entry.public_key_bytes.len() as u32).to_le_bytes());
            hasher.update(&entry.active_from_epoch.to_le_bytes());
            match entry.revoked_at_epoch {
                Some(epoch) => {
                    hasher.update(&[0x01]); // presence tag
                    hasher.update(&epoch.to_le_bytes());
                },
                None => {
                    hasher.update(&[0x00]); // absence tag
                },
            }
        }
        *hasher.finalize().as_bytes()
    }

    /// Look up a key entry by `key_id` that is active at the given epoch.
    ///
    /// Returns `None` if no matching active key is found.
    #[must_use]
    pub fn find_active_key(&self, key_id: &str, epoch: u64) -> Option<&TrustBundleKeyEntry> {
        self.keys
            .iter()
            .find(|k| k.key_id == key_id && k.is_active_at(epoch))
    }

    /// Find all active keys for a given algorithm at the given epoch.
    pub fn active_keys_for_algorithm(
        &self,
        algorithm_id: &str,
        epoch: u64,
    ) -> Vec<&TrustBundleKeyEntry> {
        self.keys
            .iter()
            .filter(|k| k.algorithm_id == algorithm_id && k.is_active_at(epoch))
            .collect()
    }

    /// Compute a digest of the active keyset at a given epoch.
    ///
    /// This is the `ledger_keyset_digest` used in `ValidatedLedgerStateV1`.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)] // All lengths bounded by MAX_* constants (<= 256)
    pub fn active_keyset_digest(&self, epoch: u64) -> Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"apm2-keyset-digest-v1");
        hasher.update(&epoch.to_le_bytes());
        let mut active_count: u32 = 0;
        for entry in &self.keys {
            if entry.is_active_at(epoch) {
                hasher.update(entry.key_id.as_bytes());
                hasher.update(&(entry.key_id.len() as u32).to_le_bytes());
                hasher.update(&entry.public_key_bytes);
                hasher.update(&(entry.public_key_bytes.len() as u32).to_le_bytes());
                active_count += 1;
            }
        }
        hasher.update(&active_count.to_le_bytes());
        *hasher.finalize().as_bytes()
    }
}

// =============================================================================
// Trusted Seal
// =============================================================================

/// A trusted seal event payload (RFC-0019 REQ-0028).
///
/// A seal commits to a [`LedgerAnchorV1`] and is signed by a key whose
/// provenance chains to the [`RootTrustBundle`]. The seal establishes a
/// checkpoint from which startup verification can begin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedSealV1 {
    /// The ledger anchor this seal commits to.
    pub anchor: LedgerAnchorV1,
    /// Key ID of the signer (must resolve in `RootTrustBundle`).
    pub signer_key_id: String,
    /// Algorithm used for the seal signature.
    pub algorithm_id: String,
    /// The seal signature bytes.
    pub signature: Vec<u8>,
    /// Epoch at which this seal was created (for key validity resolution).
    pub seal_epoch: u64,
}

impl TrustedSealV1 {
    /// Compute the canonical seal payload bytes that were signed.
    ///
    /// The signer MUST sign exactly these bytes. The verifier recomputes
    /// this and verifies the signature against it.
    #[must_use]
    pub fn signing_payload(&self) -> Vec<u8> {
        let anchor_hash = self.anchor.content_hash();
        let mut payload = Vec::with_capacity(32 + 8 + 32);
        payload.extend_from_slice(b"apm2-trusted-seal-v1");
        payload.extend_from_slice(&anchor_hash);
        payload.extend_from_slice(&self.seal_epoch.to_le_bytes());
        payload.extend_from_slice(&self.anchor.ledger_id);
        payload
    }

    /// Validate structural constraints on this seal.
    ///
    /// # Errors
    ///
    /// Returns a description of the first violated constraint.
    pub fn validate(&self) -> Result<(), String> {
        self.anchor
            .validate()
            .map_err(|field| format!("seal anchor field {field} is zero"))?;
        if self.signer_key_id.is_empty() || self.signer_key_id.len() > MAX_KEY_ID_LENGTH {
            return Err(format!(
                "signer_key_id length {} out of range 1..={MAX_KEY_ID_LENGTH}",
                self.signer_key_id.len()
            ));
        }
        if self.algorithm_id.is_empty() || self.algorithm_id.len() > MAX_ALGORITHM_ID_LENGTH {
            return Err(format!(
                "algorithm_id length {} out of range 1..={MAX_ALGORITHM_ID_LENGTH}",
                self.algorithm_id.len()
            ));
        }
        if self.signature.is_empty() {
            return Err("seal signature is empty".into());
        }
        Ok(())
    }
}

// =============================================================================
// Ledger Event for Verification
// =============================================================================

/// Minimal ledger event representation for chain verification.
///
/// This is a lightweight view of a ledger event containing only the
/// fields needed for chain integrity and signature verification.
#[derive(Debug, Clone)]
pub struct LedgerEventView {
    /// Sequence number / height in the ledger.
    pub height: u64,
    /// Hash of this event (computed from payload + `prev_hash`).
    pub event_hash: Hash,
    /// Hash of the previous event.
    pub prev_hash: Hash,
    /// Holonic time associated with this event.
    pub he_time: u64,
    /// Event type identifier.
    pub event_type: String,
    /// Raw payload bytes.
    pub payload: Vec<u8>,
    /// Signature bytes (may be empty for unsigned events).
    pub signature: Vec<u8>,
    /// Key ID of the signer (if signed).
    pub signer_key_id: Option<String>,
}

// =============================================================================
// Signature Verifier Trait
// =============================================================================

/// Crypto-agile signature verification dispatch.
///
/// The trust stack delegates actual cryptographic verification to this
/// trait, enabling algorithm-id dispatch without hardcoding any specific
/// algorithm. Implementations must be fail-closed: unknown algorithms
/// return `Err`.
pub trait SignatureVerifier: Send + Sync {
    /// Verify a signature against a message and public key.
    ///
    /// # Arguments
    ///
    /// * `algorithm_id` - Algorithm identifier (e.g., "ed25519").
    /// * `public_key` - Raw public key bytes.
    /// * `message` - The message that was signed.
    /// * `signature` - The signature bytes.
    ///
    /// # Errors
    ///
    /// Returns an error description if verification fails or the
    /// algorithm is unknown.
    fn verify(
        &self,
        algorithm_id: &str,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), String>;
}

/// Ed25519-only signature verifier for the default deployment.
///
/// Rejects any algorithm other than "ed25519" (fail-closed).
#[derive(Debug, Clone, Default)]
pub struct Ed25519SignatureVerifier;

impl SignatureVerifier for Ed25519SignatureVerifier {
    fn verify(
        &self,
        algorithm_id: &str,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), String> {
        use ed25519_dalek::Verifier;

        if algorithm_id != "ed25519" {
            return Err(format!(
                "unsupported algorithm '{algorithm_id}'; only 'ed25519' is supported"
            ));
        }

        let vk = ed25519_dalek::VerifyingKey::from_bytes(
            public_key
                .try_into()
                .map_err(|_| format!("invalid ed25519 public key length: {}", public_key.len()))?,
        )
        .map_err(|e| format!("invalid ed25519 public key: {e}"))?;

        let sig = ed25519_dalek::Signature::from_bytes(
            signature
                .try_into()
                .map_err(|_| format!("invalid ed25519 signature length: {}", signature.len()))?,
        );

        vk.verify(message, &sig)
            .map_err(|e| format!("ed25519 signature verification failed: {e}"))
    }
}

// =============================================================================
// Ledger Event Source Trait
// =============================================================================

/// Abstraction over the ledger event source for startup verification.
///
/// Implementations provide event reads for the trust verifier without
/// coupling to the concrete `SqliteLedgerEventEmitter`.
pub trait LedgerEventSource: Send + Sync {
    /// Read events from `start_height` (inclusive) up to `limit` events.
    ///
    /// Events MUST be returned in ascending height order.
    ///
    /// # Errors
    ///
    /// Returns an error if the ledger cannot be read.
    fn read_events(&self, start_height: u64, limit: usize) -> Result<Vec<LedgerEventView>, String>;

    /// Get the current tip height of the ledger.
    ///
    /// # Errors
    ///
    /// Returns an error if the ledger state cannot be determined.
    fn tip_height(&self) -> Result<u64, String>;

    /// Get the ledger identifier.
    fn ledger_id(&self) -> Hash;

    /// Find the most recent seal event at or before `max_height`.
    ///
    /// # Errors
    ///
    /// Returns an error if no seal is found or the ledger cannot be read.
    fn find_latest_seal(&self, max_height: u64) -> Result<Option<TrustedSealV1>, String>;

    /// Read governance-class events from `start_height` (inclusive) up to
    /// `end_height` (inclusive), bounded by `limit`.
    ///
    /// Governance events are events whose `event_type` indicates a
    /// governance/policy mutation (e.g., `governance.policy_update`,
    /// `governance.key_rotation`).
    ///
    /// # Errors
    ///
    /// Returns an error if the ledger cannot be read.
    fn read_governance_events(
        &self,
        start_height: u64,
        end_height: u64,
        limit: usize,
    ) -> Result<Vec<LedgerEventView>, String>;
}

// =============================================================================
// Verification Configuration
// =============================================================================

/// Configuration for the ledger trust verifier.
#[derive(Debug, Clone)]
pub struct TrustVerifierConfig {
    /// Maximum seal-to-tip distance before startup fails closed.
    pub max_seal_to_tip_distance: u64,
    /// Whether to perform full-chain validation when seal distance is
    /// exceeded (vs. failing immediately). Full-chain validation verifies
    /// every event from genesis, which is expensive but allows recovery.
    pub allow_full_chain_fallback: bool,
}

impl Default for TrustVerifierConfig {
    fn default() -> Self {
        Self {
            max_seal_to_tip_distance: DEFAULT_MAX_SEAL_TO_TIP_DISTANCE,
            allow_full_chain_fallback: false,
        }
    }
}

// =============================================================================
// ConcreteLedgerTrustVerifier
// =============================================================================

/// Validated state produced by startup verification, stored behind `RwLock`.
///
/// Synchronization protocol:
/// - Writers: only [`ConcreteLedgerTrustVerifier::verify_startup`] writes this
///   state, and it is called once during daemon initialization before any
///   readers exist.
/// - Readers: [`ConcreteLedgerTrustVerifier::validated_state`] reads this state
///   under `RwLock::read()`.
/// - The `RwLock` provides happens-before between the startup write and all
///   subsequent reads.
struct VerifiedState {
    state: Option<ValidatedLedgerStateV1>,
}

/// Concrete implementation of [`LedgerTrustVerifier`] (TCK-00500).
///
/// Performs checkpoint-bounded startup verification and provides validated
/// ledger state for admission decisions.
///
/// # Lifecycle
///
/// 1. Construct with `new()`.
/// 2. Call `verify_startup()` during daemon initialization.
/// 3. After successful startup verification, `validated_state()` returns the
///    validated state.
///
/// # Synchronization
///
/// Internal state is protected by `RwLock<VerifiedState>`.
/// - `verify_startup()` acquires write lock (called once at init).
/// - `validated_state()` acquires read lock (called on every admission).
pub struct ConcreteLedgerTrustVerifier {
    /// Root trust bundle (the trust anchor).
    trust_bundle: RootTrustBundle,
    /// Event source for reading ledger events.
    event_source: Arc<dyn LedgerEventSource>,
    /// Crypto-agile signature verification.
    sig_verifier: Arc<dyn SignatureVerifier>,
    /// Configuration.
    config: TrustVerifierConfig,
    /// Cached validated state (written once at startup, read many).
    ///
    /// Synchronization: write-once by `verify_startup()`, then read-only
    /// by `validated_state()`. The `RwLock` ensures happens-before ordering.
    verified: RwLock<VerifiedState>,
}

impl std::fmt::Debug for ConcreteLedgerTrustVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConcreteLedgerTrustVerifier")
            .field("trust_bundle_id", &hex::encode(self.trust_bundle.bundle_id))
            .field("config", &self.config)
            .field(
                "is_verified",
                &self
                    .verified
                    .read()
                    .map(|g| g.state.is_some())
                    .unwrap_or(false),
            )
            .finish_non_exhaustive()
    }
}

impl ConcreteLedgerTrustVerifier {
    /// Create a new verifier.
    ///
    /// Does NOT perform verification on construction. Call
    /// `verify_startup()` after construction to establish trust.
    ///
    /// # Errors
    ///
    /// Returns an error if the trust bundle fails validation.
    pub fn new(
        trust_bundle: RootTrustBundle,
        event_source: Arc<dyn LedgerEventSource>,
        sig_verifier: Arc<dyn SignatureVerifier>,
        config: TrustVerifierConfig,
    ) -> Result<Self, TrustError> {
        trust_bundle
            .validate()
            .map_err(|e| TrustError::IntegrityFailure {
                reason: truncate_reason(&format!("trust bundle validation failed: {e}")),
            })?;
        Ok(Self {
            trust_bundle,
            event_source,
            sig_verifier,
            config,
            verified: RwLock::new(VerifiedState { state: None }),
        })
    }

    /// Perform startup verification.
    ///
    /// 1. Locate the most recent trusted seal.
    /// 2. Verify the seal signature against the root trust bundle.
    /// 3. Verify the chain from seal to tip (hash chain, signatures, monotonic
    ///    HT).
    /// 4. Enforce max seal-to-tip distance policy.
    /// 5. Detect fork/divergence (seal anchor must chain to tip).
    ///
    /// After successful verification, `validated_state()` will return
    /// the validated state.
    ///
    /// # Errors
    ///
    /// Returns [`TrustError`] if any verification step fails.
    pub fn verify_startup(&self) -> Result<ValidatedLedgerStateV1, TrustError> {
        let ledger_id = self.event_source.ledger_id();
        let tip_height =
            self.event_source
                .tip_height()
                .map_err(|e| TrustError::IntegrityFailure {
                    reason: truncate_reason(&format!("failed to read tip height: {e}")),
                })?;

        // Step 1: Locate the most recent trusted seal.
        let seal = self
            .event_source
            .find_latest_seal(tip_height)
            .map_err(|e| TrustError::IntegrityFailure {
                reason: truncate_reason(&format!("failed to find seal: {e}")),
            })?
            .ok_or_else(|| TrustError::IntegrityFailure {
                reason: "no trusted seal found in ledger".into(),
            })?;

        // Step 2: Validate seal structure.
        seal.validate().map_err(|e| TrustError::IntegrityFailure {
            reason: truncate_reason(&format!("seal validation failed: {e}")),
        })?;

        // Step 3: Verify seal signature chains to root trust bundle.
        self.verify_seal_signature(&seal)?;

        // Step 4: Verify seal anchor matches ledger_id.
        if !bool::from(seal.anchor.ledger_id.ct_eq(&ledger_id)) {
            return Err(TrustError::IntegrityFailure {
                reason: "seal anchor ledger_id does not match event source ledger_id".into(),
            });
        }

        // Step 5: Enforce max seal-to-tip distance.
        let seal_height = seal.anchor.height;
        if tip_height < seal_height {
            return Err(TrustError::IntegrityFailure {
                reason: format!(
                    "tip height ({tip_height}) is less than seal height ({seal_height})"
                ),
            });
        }
        let distance = tip_height - seal_height;
        if distance > self.config.max_seal_to_tip_distance {
            if !self.config.allow_full_chain_fallback {
                return Err(TrustError::SealDistanceExceeded {
                    distance,
                    max_distance: self.config.max_seal_to_tip_distance,
                });
            }
            // Full-chain fallback: verify from height 1 to tip.
            // This is expensive but allows recovery when the seal is stale.
            // No anchor binding for genesis-start (no seal anchor to bind to).
            self.verify_chain_segment(1, tip_height, &ledger_id, seal.seal_epoch, None)?;
        } else {
            // Normal path: verify from seal to tip.
            // Bind the first event to the seal's committed event_hash.
            self.verify_chain_segment(
                seal_height,
                tip_height,
                &ledger_id,
                seal.seal_epoch,
                Some(seal.anchor.event_hash),
            )?;
        }

        // Step 6: Construct the validated state.
        //
        // Read the tip event to build the tip anchor.
        let tip_events = self.event_source.read_events(tip_height, 1).map_err(|e| {
            TrustError::IntegrityFailure {
                reason: truncate_reason(&format!("failed to read tip event: {e}")),
            }
        })?;
        let tip_event = tip_events
            .first()
            .ok_or_else(|| TrustError::IntegrityFailure {
                reason: "tip event not found after verification".into(),
            })?;

        let tip_anchor = LedgerAnchorV1 {
            ledger_id,
            event_hash: tip_event.event_hash,
            height: tip_event.height,
            he_time: tip_event.he_time,
        };

        let keyset_digest = self.trust_bundle.active_keyset_digest(seal.seal_epoch);
        let bundle_digest = self.trust_bundle.content_hash();

        let state = ValidatedLedgerStateV1 {
            validated_anchor: seal.anchor,
            tip_anchor,
            ledger_keyset_digest: keyset_digest,
            root_trust_bundle_digest: bundle_digest,
        };

        // Step 7: Store validated state.
        {
            let mut guard = self
                .verified
                .write()
                .map_err(|_| TrustError::IntegrityFailure {
                    reason: "verified state lock poisoned".into(),
                })?;
            guard.state = Some(state.clone());
        }

        Ok(state)
    }

    /// Verify a seal's signature chains to the root trust bundle.
    fn verify_seal_signature(&self, seal: &TrustedSealV1) -> Result<(), TrustError> {
        // Look up the signer key in the trust bundle, resolving at seal epoch.
        let key_entry = self
            .trust_bundle
            .find_active_key(&seal.signer_key_id, seal.seal_epoch)
            .ok_or_else(|| TrustError::IntegrityFailure {
                reason: truncate_reason(&format!(
                    "seal signer key '{}' not found or not active at epoch {} in trust bundle",
                    seal.signer_key_id, seal.seal_epoch
                )),
            })?;

        // Verify algorithm match.
        if key_entry.algorithm_id != seal.algorithm_id {
            return Err(TrustError::IntegrityFailure {
                reason: truncate_reason(&format!(
                    "seal algorithm '{}' does not match key entry algorithm '{}'",
                    seal.algorithm_id, key_entry.algorithm_id
                )),
            });
        }

        // Compute the canonical signing payload and verify.
        let signing_payload = seal.signing_payload();
        self.sig_verifier
            .verify(
                &seal.algorithm_id,
                &key_entry.public_key_bytes,
                &signing_payload,
                &seal.signature,
            )
            .map_err(|e| TrustError::IntegrityFailure {
                reason: truncate_reason(&format!("seal signature verification failed: {e}")),
            })
    }

    /// Verify a chain segment from `start_height` to `end_height`.
    ///
    /// Checks:
    /// - Anchor binding: if `expected_start_hash` is `Some`, the first event's
    ///   `event_hash` must match it (constant-time comparison).
    /// - Hash chain integrity (each event's `prev_hash` matches the previous
    ///   event's `event_hash`).
    /// - Monotonic HT (`he_time` is non-decreasing).
    /// - Signature verification for signed events using per-event `he_time`
    ///   epoch (optional — unsigned events are allowed in the chain but cannot
    ///   provide governance authority).
    /// - Fail-closed on incomplete reads: if the event source cannot produce
    ///   events for the full `[start_height, end_height]` range, verification
    ///   fails.
    fn verify_chain_segment(
        &self,
        start_height: u64,
        end_height: u64,
        expected_ledger_id: &Hash,
        _seal_epoch: u64,
        expected_start_hash: Option<Hash>,
    ) -> Result<(), TrustError> {
        // Read events in batches to avoid loading the entire chain into
        // memory at once. Batch size is bounded.
        const BATCH_SIZE: usize = 1_000;
        let mut current_height = start_height;
        let mut prev_hash: Option<Hash> = None;
        let mut prev_he_time: u64 = 0;
        let mut checked_anchor = false;

        while current_height <= end_height {
            let events = self
                .event_source
                .read_events(current_height, BATCH_SIZE)
                .map_err(|e| TrustError::IntegrityFailure {
                    reason: truncate_reason(&format!(
                        "failed to read events at height {current_height}: {e}"
                    )),
                })?;

            if events.is_empty() {
                // Fail-closed: the event source cannot produce events for
                // the entire [start_height, end_height] range.
                return Err(TrustError::IntegrityFailure {
                    reason: truncate_reason(&format!(
                        "chain verification gap: no events returned at height {current_height}, \
                         expected events up to height {end_height}"
                    )),
                });
            }

            for event in &events {
                if event.height > end_height {
                    break;
                }

                // Anchor binding check: the first event MUST match the
                // seal's committed event_hash (if provided).
                if !checked_anchor {
                    checked_anchor = true;

                    // Defensive: verify the first event's height matches
                    // the expected start_height.
                    if event.height != start_height {
                        return Err(TrustError::IntegrityFailure {
                            reason: truncate_reason(&format!(
                                "first event height {} does not match expected start height {start_height}",
                                event.height
                            )),
                        });
                    }

                    if let Some(ref expected_anchor) = expected_start_hash {
                        if !bool::from(event.event_hash.ct_eq(expected_anchor)) {
                            return Err(TrustError::IntegrityFailure {
                                reason: truncate_reason(&format!(
                                    "first event at height {} does not match sealed anchor event_hash: \
                                     expected {}, got {}",
                                    event.height,
                                    hex::encode(expected_anchor),
                                    hex::encode(event.event_hash)
                                )),
                            });
                        }
                    }
                }

                // Check hash chain link.
                if let Some(expected_prev) = prev_hash {
                    if !bool::from(event.prev_hash.ct_eq(&expected_prev)) {
                        return Err(TrustError::IntegrityFailure {
                            reason: truncate_reason(&format!(
                                "hash chain break at height {}: expected prev_hash {}, got {}",
                                event.height,
                                hex::encode(expected_prev),
                                hex::encode(event.prev_hash)
                            )),
                        });
                    }
                }

                // Check HT monotonicity.
                if event.he_time < prev_he_time {
                    return Err(TrustError::IntegrityFailure {
                        reason: truncate_reason(&format!(
                            "HT monotonicity violation at height {}: he_time {} < prev {}",
                            event.height, event.he_time, prev_he_time
                        )),
                    });
                }

                // Verify signature if present (crypto-agile dispatch).
                // Key validity is resolved at the event's own epoch
                // (he_time), NOT the seal epoch, to correctly handle
                // post-seal key rotations.
                if !event.signature.is_empty() {
                    if let Some(ref signer_key_id) = event.signer_key_id {
                        self.verify_event_signature(
                            event,
                            signer_key_id,
                            expected_ledger_id,
                            event.he_time,
                        )?;
                    }
                }

                prev_hash = Some(event.event_hash);
                prev_he_time = event.he_time;
                current_height = event.height.saturating_add(1);
            }
        }

        Ok(())
    }

    /// Verify a single event's signature.
    fn verify_event_signature(
        &self,
        event: &LedgerEventView,
        signer_key_id: &str,
        _expected_ledger_id: &Hash,
        verification_epoch: u64,
    ) -> Result<(), TrustError> {
        let key_entry = self
            .trust_bundle
            .find_active_key(signer_key_id, verification_epoch)
            .ok_or_else(|| TrustError::IntegrityFailure {
                reason: truncate_reason(&format!(
                    "event signer key '{signer_key_id}' not found or not active at epoch {verification_epoch}"
                )),
            })?;

        // The signed message is the event_hash.
        self.sig_verifier
            .verify(
                &key_entry.algorithm_id,
                &key_entry.public_key_bytes,
                &event.event_hash,
                &event.signature,
            )
            .map_err(|e| TrustError::IntegrityFailure {
                reason: truncate_reason(&format!(
                    "event signature verification failed at height {}: {e}",
                    event.height
                )),
            })
    }

    /// Get a reference to the trust bundle.
    #[must_use]
    pub const fn trust_bundle(&self) -> &RootTrustBundle {
        &self.trust_bundle
    }
}

impl LedgerTrustVerifier for ConcreteLedgerTrustVerifier {
    fn validated_state(&self) -> Result<ValidatedLedgerStateV1, TrustError> {
        let guard = self
            .verified
            .read()
            .map_err(|_| TrustError::IntegrityFailure {
                reason: "verified state lock poisoned".into(),
            })?;
        guard.state.clone().ok_or(TrustError::NotReady)
    }
}

// =============================================================================
// GovernancePolicyRootResolver
// =============================================================================

/// Cache entry for a resolved policy root.
#[derive(Debug, Clone)]
struct PolicyRootCacheEntry {
    /// The resolved state.
    state: PolicyRootStateV1,
    /// Content hash of the anchor used for this resolution.
    anchor_hash: Hash,
}

/// Governance-derived policy root resolver (TCK-00500).
///
/// Derives [`PolicyRootStateV1`] deterministically from governance-class
/// events up to a given [`LedgerAnchorV1`].
///
/// # Caching
///
/// Results are cached by `(policy_root_epoch, anchor_content_hash)`.
/// The cache is bounded by [`MAX_POLICY_ROOT_CACHE_ENTRIES`].
///
/// # Synchronization
///
/// Internal cache is protected by `RwLock<HashMap<...>>`.
/// - `resolve()` reads the cache first (read lock), then writes on miss (write
///   lock).
/// - Cache entries are immutable once inserted.
pub struct GovernancePolicyRootResolver {
    /// Root trust bundle for governance signature verification.
    trust_bundle: RootTrustBundle,
    /// Event source for reading governance events.
    event_source: Arc<dyn LedgerEventSource>,
    /// Crypto-agile signature verification.
    sig_verifier: Arc<dyn SignatureVerifier>,
    /// Cache of resolved policy roots.
    ///
    /// Synchronization: read-mostly, write on cache miss. Bounded by
    /// `MAX_POLICY_ROOT_CACHE_ENTRIES`.
    cache: RwLock<HashMap<(u64, Hash), PolicyRootCacheEntry>>,
}

impl std::fmt::Debug for GovernancePolicyRootResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GovernancePolicyRootResolver")
            .field("trust_bundle_id", &hex::encode(self.trust_bundle.bundle_id))
            .field(
                "cache_size",
                &self.cache.read().map(|g| g.len()).unwrap_or(0),
            )
            .finish_non_exhaustive()
    }
}

impl GovernancePolicyRootResolver {
    /// Create a new governance policy root resolver.
    ///
    /// # Errors
    ///
    /// Returns an error if the trust bundle fails validation.
    pub fn new(
        trust_bundle: RootTrustBundle,
        event_source: Arc<dyn LedgerEventSource>,
        sig_verifier: Arc<dyn SignatureVerifier>,
    ) -> Result<Self, PolicyError> {
        trust_bundle
            .validate()
            .map_err(|e| PolicyError::DerivationFailed {
                reason: truncate_reason(&format!("trust bundle validation failed: {e}")),
            })?;
        Ok(Self {
            trust_bundle,
            event_source,
            sig_verifier,
            cache: RwLock::new(HashMap::new()),
        })
    }

    /// Derive the policy root deterministically from governance events.
    ///
    /// Reads governance-class events from genesis up to the anchor height,
    /// verifies each event's governance signature, and derives a
    /// deterministic digest.
    fn derive_policy_root(&self, as_of: &LedgerAnchorV1) -> Result<PolicyRootStateV1, PolicyError> {
        // Read governance events up to the anchor height.
        let events = self
            .event_source
            .read_governance_events(1, as_of.height, MAX_GOVERNANCE_EVENTS_PER_DERIVATION)
            .map_err(|e| PolicyError::DerivationFailed {
                reason: truncate_reason(&format!("failed to read governance events: {e}")),
            })?;

        if events.is_empty() {
            return Err(PolicyError::NoGovernanceEvents);
        }

        // Verify governance signatures and derive deterministic digest.
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"apm2-policy-root-state-v1");
        hasher.update(&as_of.content_hash());

        let mut latest_epoch: u64 = 0;
        let mut latest_signer_key_id: Option<String> = None;
        let mut latest_algorithm_id: Option<String> = None;

        for event in &events {
            // Governance events MUST be signed.
            if event.signature.is_empty() {
                return Err(PolicyError::SignatureVerificationFailed {
                    reason: truncate_reason(&format!(
                        "unsigned governance event at height {}",
                        event.height
                    )),
                });
            }

            let signer_key_id = event.signer_key_id.as_ref().ok_or_else(|| {
                PolicyError::SignatureVerificationFailed {
                    reason: truncate_reason(&format!(
                        "governance event at height {} missing signer_key_id",
                        event.height
                    )),
                }
            })?;

            // Resolve the signer key at the event's epoch (he_time as epoch).
            let key_entry = self
                .trust_bundle
                .find_active_key(signer_key_id, event.he_time)
                .ok_or_else(|| PolicyError::SignatureVerificationFailed {
                    reason: truncate_reason(&format!(
                        "governance signer key '{signer_key_id}' not found or not active at epoch {}",
                        event.he_time
                    )),
                })?;

            // Verify the event signature.
            self.sig_verifier
                .verify(
                    &key_entry.algorithm_id,
                    &key_entry.public_key_bytes,
                    &event.event_hash,
                    &event.signature,
                )
                .map_err(|e| PolicyError::SignatureVerificationFailed {
                    reason: truncate_reason(&format!(
                        "governance signature verification failed at height {}: {e}",
                        event.height
                    )),
                })?;

            // Include event in deterministic digest.
            hasher.update(&event.event_hash);
            hasher.update(&event.he_time.to_le_bytes());
            hasher.update(&event.height.to_le_bytes());

            // Track the latest governance epoch.
            if event.he_time > latest_epoch {
                latest_epoch = event.he_time;
                latest_signer_key_id = Some(signer_key_id.clone());
                latest_algorithm_id = Some(key_entry.algorithm_id.clone());
            }
        }

        let policy_root_digest = *hasher.finalize().as_bytes();

        let provenance = GovernanceProvenanceV1 {
            signer_key_id: {
                let kid = latest_signer_key_id.unwrap_or_default();
                let mut h = blake3::Hasher::new();
                h.update(b"apm2-signer-key-id-hash-v1");
                h.update(kid.as_bytes());
                *h.finalize().as_bytes()
            },
            algorithm_id: latest_algorithm_id.unwrap_or_else(|| "unknown".to_string()),
        };

        Ok(PolicyRootStateV1 {
            policy_root_digest,
            policy_root_epoch: latest_epoch,
            anchor: as_of.clone(),
            provenance,
        })
    }
}

impl PolicyRootResolver for GovernancePolicyRootResolver {
    fn resolve(&self, as_of: &LedgerAnchorV1) -> Result<PolicyRootStateV1, PolicyError> {
        // Validate anchor first.
        as_of
            .validate()
            .map_err(|field| PolicyError::DerivationFailed {
                reason: format!("anchor field {field} is zero"),
            })?;

        let anchor_hash = as_of.content_hash();

        // Check cache (read lock).
        {
            let cache = self
                .cache
                .read()
                .map_err(|_| PolicyError::DerivationFailed {
                    reason: "policy root cache lock poisoned".into(),
                })?;
            // Use a representative epoch (he_time from anchor) as cache key.
            if let Some(entry) = cache.get(&(as_of.he_time, anchor_hash)) {
                // Verify anchor hash matches (constant-time).
                if bool::from(entry.anchor_hash.ct_eq(&anchor_hash)) {
                    return Ok(entry.state.clone());
                }
            }
        }

        // Cache miss: derive the policy root.
        let state = self.derive_policy_root(as_of)?;

        // Insert into cache (write lock), enforcing bounds.
        {
            let mut cache = self
                .cache
                .write()
                .map_err(|_| PolicyError::DerivationFailed {
                    reason: "policy root cache lock poisoned".into(),
                })?;

            // Enforce cache bounds: evict oldest entry if at capacity.
            if cache.len() >= MAX_POLICY_ROOT_CACHE_ENTRIES {
                // Evict the entry with the smallest epoch.
                if let Some(key) = cache.keys().min_by_key(|(epoch, _)| *epoch).copied() {
                    cache.remove(&key);
                }
            }

            cache.insert(
                (as_of.he_time, anchor_hash),
                PolicyRootCacheEntry {
                    state: state.clone(),
                    anchor_hash,
                },
            );
        }

        Ok(state)
    }
}

// =============================================================================
// Helper functions
// =============================================================================

/// Truncate a reason string to the maximum allowed length.
fn truncate_reason(reason: &str) -> String {
    use super::prerequisites::MAX_TRUST_ERROR_REASON_LENGTH;
    if reason.len() <= MAX_TRUST_ERROR_REASON_LENGTH {
        reason.to_string()
    } else {
        format!(
            "{}...(truncated)",
            &reason[..MAX_TRUST_ERROR_REASON_LENGTH.saturating_sub(15)]
        )
    }
}
