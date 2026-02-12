// AGENT-AUTHORED
//! Prerequisite trait interfaces for `AdmissionKernel` (RFC-0019 Appendix A).
//!
//! These traits define the contracts that `AdmissionKernel` depends on for
//! ledger trust verification, policy root resolution, and anti-rollback
//! anchoring. Implementations are provided by TCK-00500; this module
//! defines only the trait interfaces and their associated types.
//!
//! # Fail-Closed Semantics
//!
//! All prerequisite resolution operations return `Result`. For fail-closed
//! tiers, `Err` MUST cause admission denial. Missing or unverifiable
//! prerequisites are never silently ignored.
//!
//! # Security Model
//!
//! - [`LedgerTrustVerifier`]: provides validated ledger state after startup
//!   verification establishes chain integrity and signature provenance.
//! - [`PolicyRootResolver`]: derives policy root deterministically from
//!   governance-class events with verified signature provenance.
//! - [`AntiRollbackAnchor`]: external anchoring for rollback resistance in
//!   fail-closed tiers.

use std::fmt;

use apm2_core::crypto::Hash;
use serde::{Deserialize, Serialize};

// =============================================================================
// Error types
// =============================================================================

/// Maximum length for error reason strings in prerequisite errors.
pub const MAX_TRUST_ERROR_REASON_LENGTH: usize = 512;

/// Error from ledger trust verification or anti-rollback anchoring.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustError {
    /// Ledger integrity cannot be established (chain break, signature
    /// failure, missing seal).
    IntegrityFailure {
        /// Bounded reason string.
        reason: String,
    },
    /// The trusted seal is too far from the current tip.
    SealDistanceExceeded {
        /// Distance from seal to tip.
        distance: u64,
        /// Maximum allowed distance.
        max_distance: u64,
    },
    /// External anti-rollback anchor is unavailable.
    ExternalAnchorUnavailable {
        /// Bounded reason string.
        reason: String,
    },
    /// External anchor does not match local ledger state.
    ExternalAnchorMismatch {
        /// Bounded reason string.
        reason: String,
    },
    /// Ledger not yet initialized or startup validation incomplete.
    NotReady,
}

impl fmt::Display for TrustError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IntegrityFailure { reason } => {
                write!(f, "ledger integrity failure: {reason}")
            },
            Self::SealDistanceExceeded {
                distance,
                max_distance,
            } => {
                write!(
                    f,
                    "seal-to-tip distance {distance} exceeds maximum {max_distance}"
                )
            },
            Self::ExternalAnchorUnavailable { reason } => {
                write!(f, "external anti-rollback anchor unavailable: {reason}")
            },
            Self::ExternalAnchorMismatch { reason } => {
                write!(f, "external anchor mismatch: {reason}")
            },
            Self::NotReady => write!(f, "ledger trust not yet established"),
        }
    }
}

impl std::error::Error for TrustError {}

/// Error from policy root resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyError {
    /// No governance events found up to the given anchor.
    NoGovernanceEvents,
    /// Governance signature verification failed.
    SignatureVerificationFailed {
        /// Bounded reason string.
        reason: String,
    },
    /// Policy root cannot be derived for the given anchor.
    DerivationFailed {
        /// Bounded reason string.
        reason: String,
    },
    /// The resolver is not yet ready (startup incomplete).
    NotReady,
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoGovernanceEvents => {
                write!(f, "no governance events found for policy root derivation")
            },
            Self::SignatureVerificationFailed { reason } => {
                write!(f, "governance signature verification failed: {reason}")
            },
            Self::DerivationFailed { reason } => {
                write!(f, "policy root derivation failed: {reason}")
            },
            Self::NotReady => write!(f, "policy root resolver not yet ready"),
        }
    }
}

impl std::error::Error for PolicyError {}

// =============================================================================
// Ledger anchor type
// =============================================================================

/// Minimal ledger snapshot identifier for admission (RFC-0019 §1.1).
///
/// Represents a validated point in the ledger's append-only history.
/// The anchor MUST refer to an event within the validated portion of the
/// ledger.
///
/// # Digest Stability
///
/// The content hash is computed over domain-separated canonical bytes:
/// `b"apm2-ledger-anchor-v1" || ledger_id || event_hash || height_le_bytes ||
/// he_time_le_bytes`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerAnchorV1 {
    /// Stable identifier for the ledger chain/namespace.
    pub ledger_id: Hash,
    /// Hash of the ledger event at this anchor point.
    pub event_hash: Hash,
    /// Height (or equivalent ordinal) of the event.
    pub height: u64,
    /// Holonic time associated with this event.
    pub he_time: u64,
}

impl LedgerAnchorV1 {
    /// Compute a deterministic content hash for this anchor.
    #[must_use]
    pub fn content_hash(&self) -> Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"apm2-ledger-anchor-v1");
        hasher.update(&self.ledger_id);
        hasher.update(&self.event_hash);
        hasher.update(&self.height.to_le_bytes());
        hasher.update(&self.he_time.to_le_bytes());
        *hasher.finalize().as_bytes()
    }

    /// Validate that no fields are zero-valued.
    ///
    /// # Errors
    ///
    /// Returns the name of the first zero-valued field.
    pub fn validate(&self) -> Result<(), &'static str> {
        const ZERO: Hash = [0u8; 32];
        if self.ledger_id == ZERO {
            return Err("ledger_id");
        }
        if self.event_hash == ZERO {
            return Err("event_hash");
        }
        if self.height == 0 {
            return Err("height");
        }
        if self.he_time == 0 {
            return Err("he_time");
        }
        Ok(())
    }
}

// =============================================================================
// Validated ledger state
// =============================================================================

/// Validated ledger state produced by startup verification (RFC-0019 §2.1).
///
/// Only produced after the ledger verifier establishes chain integrity,
/// signature provenance, and monotonic HT constraints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedLedgerStateV1 {
    /// The most recently validated anchor in the chain.
    pub validated_anchor: LedgerAnchorV1,
    /// The current tip of the ledger chain.
    pub tip_anchor: LedgerAnchorV1,
    /// Digest of the keyset used for ledger event verification.
    pub ledger_keyset_digest: Hash,
    /// Digest of the root trust bundle.
    pub root_trust_bundle_digest: Hash,
}

// =============================================================================
// External anchor state
// =============================================================================

/// External anti-rollback anchor state (RFC-0019 §2.4).
///
/// Represents the most recently verified external anchor that provides
/// rollback resistance beyond the local write scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalAnchorStateV1 {
    /// The external anchor point.
    pub anchor: LedgerAnchorV1,
    /// Mechanism identifier (e.g., `remote_witness_log`, `tpm_nv_index`).
    pub mechanism_id: String,
    /// Hash commitment to the external proof/receipt.
    pub proof_hash: Hash,
}

// =============================================================================
// Governance provenance
// =============================================================================

/// Provenance metadata for governance-derived policy root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GovernanceProvenanceV1 {
    /// Signer key identifier.
    pub signer_key_id: Hash,
    /// Algorithm identifier for the governance signature.
    pub algorithm_id: String,
}

// =============================================================================
// Policy root state
// =============================================================================

/// Policy root state derived from governance-class events (RFC-0019 §2.2).
///
/// The policy root digest is derived deterministically from governance
/// events up to a specific [`LedgerAnchorV1`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyRootStateV1 {
    /// Digest of the authoritative policy root.
    pub policy_root_digest: Hash,
    /// Monotonic generation/epoch for revalidation.
    pub policy_root_epoch: u64,
    /// The ledger anchor this policy root was derived from.
    pub anchor: LedgerAnchorV1,
    /// Governance signature provenance.
    pub provenance: GovernanceProvenanceV1,
}

// =============================================================================
// Trait interfaces
// =============================================================================

/// Ledger trust verification interface (RFC-0019 §2.1, Appendix A).
///
/// Provides validated ledger state after startup verification establishes
/// chain integrity, signature provenance, and monotonic HT constraints.
///
/// # Implementations
///
/// Implementations are provided by TCK-00500. The kernel depends only
/// on this trait interface.
///
/// # Fail-Closed Contract
///
/// If ledger trust cannot be established, `validated_state()` MUST
/// return `Err(TrustError)`. The kernel MUST deny admission for
/// fail-closed tiers when this returns an error.
pub trait LedgerTrustVerifier: Send + Sync {
    /// Returns the current validated ledger state.
    ///
    /// # Errors
    ///
    /// Returns [`TrustError`] if ledger integrity cannot be established.
    fn validated_state(&self) -> Result<ValidatedLedgerStateV1, TrustError>;
}

/// Policy root resolution interface (RFC-0019 §2.2, Appendix A).
///
/// Derives the authoritative policy root deterministically from
/// governance-class events up to a specific [`LedgerAnchorV1`].
///
/// # Implementations
///
/// Implementations are provided by TCK-00500.
///
/// # Fail-Closed Contract
///
/// If policy root cannot be resolved, `resolve()` MUST return
/// `Err(PolicyError)`. The kernel MUST deny admission for fail-closed
/// tiers when this returns an error.
pub trait PolicyRootResolver: Send + Sync {
    /// Resolve the policy root state as of the given ledger anchor.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError`] if the policy root cannot be derived.
    fn resolve(&self, as_of: &LedgerAnchorV1) -> Result<PolicyRootStateV1, PolicyError>;
}

/// External anti-rollback anchoring interface (RFC-0019 §2.4, Appendix A).
///
/// Provides rollback resistance by anchoring ledger state to an external
/// mechanism outside the adversary's local write scope.
///
/// # Fail-Closed Contract
///
/// Fail-closed tiers MUST require verified anti-rollback anchoring.
/// If the anchor is unavailable or does not match, admission MUST deny.
///
/// # Commit Contract
///
/// After successful admission (PCAC consume + effects complete), the caller
/// MUST call `commit()` to advance the external anchor to the new ledger
/// head. Failing to commit leaves the anchor stale, which causes subsequent
/// `verify_committed()` calls for higher anchors to fail (`DoS` on fresh
/// install where anchor is `None`).
pub trait AntiRollbackAnchor: Send + Sync {
    /// Returns the most recently verified external anchor state.
    ///
    /// # Errors
    ///
    /// Returns [`TrustError`] if the external anchor is unavailable.
    fn latest(&self) -> Result<ExternalAnchorStateV1, TrustError>;

    /// Verifies that `anchor` is committed externally.
    ///
    /// # Errors
    ///
    /// Returns [`TrustError`] if the anchor is not committed externally
    /// or the external state does not match.
    fn verify_committed(&self, anchor: &LedgerAnchorV1) -> Result<(), TrustError>;

    /// Commit a new anchor to the external anchor state, advancing
    /// the anti-rollback watermark.
    ///
    /// The new anchor MUST NOT regress relative to the current committed
    /// state (anti-rollback invariant). Implementations validate this
    /// before persisting.
    ///
    /// # Errors
    ///
    /// Returns [`TrustError`] if:
    /// - The new anchor regresses (lower height or fork at same height).
    /// - The anchor fails structural validation.
    /// - The persistence operation fails.
    fn commit(&self, anchor: &LedgerAnchorV1) -> Result<(), TrustError>;
}
