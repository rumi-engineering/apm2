// AGENT-AUTHORED
//! `EpochSealV1`: Monotonic sealing and validation for epoch-bound artifacts
//! (TCK-00365).
//!
//! This module implements epoch seals that bind directory heads and
//! receipt-batch epochs to a cryptographic commitment. The verifier
//! enforces strict monotonicity and rejects rollback or equivocation
//! attempts in the admission path.
//!
//! # Design
//!
//! [`EpochSealV1`] captures a sealed epoch number, the root hash of
//! the sealed artifact tree, the issuing cell identity, a signature,
//! and a content hash for CAS addressability. The
//! [`EpochSealVerifier`] maintains per-issuer epoch state and rejects
//! any seal whose epoch is not strictly greater than the last accepted
//! epoch from the same issuer, or whose root hash conflicts with a
//! previously accepted seal at the same epoch (equivocation).
//!
//! # Security Model
//!
//! - **Fail-closed**: Tier2+ authority admissions deny on missing or invalid
//!   seals.
//! - **Monotonicity**: Epoch numbers must strictly increase per issuer.
//! - **Anti-equivocation**: Two seals from the same issuer at the same epoch
//!   with different root hashes are rejected.
//! - **Deterministic**: Given the same inputs, the verifier always produces the
//!   same [`EpochSealVerdict`] and [`EpochSealAuditEvent`].
//!
//! # Authority Model
//!
//! Epoch seal authority is derived from the issuer cell identity and
//! the monotonically increasing epoch number. The sealed root hash
//! binds the seal to a specific artifact state.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::fac::RiskTier;

// =============================================================================
// Constants
// =============================================================================

/// Maximum length for string fields in epoch seal types (denial-of-service
/// protection).
pub const MAX_SEAL_STRING_LENGTH: usize = 4096;

/// Maximum number of issuers tracked by a single verifier (denial-of-service
/// protection).
pub const MAX_TRACKED_ISSUERS: usize = 1024;

/// Maximum number of audit events retained per verification call.
pub const MAX_SEAL_AUDIT_EVENTS: usize = 16;

/// Domain separator for epoch seal audit event hashing.
const EPOCH_SEAL_AUDIT_DOMAIN: &[u8] = b"apm2:epoch_seal_v1:audit:v1\0";

/// Signature byte length (Ed25519).
const SIGNATURE_SIZE: usize = 64;

// =============================================================================
// Custom serde for [u8; 64] (serde doesn't support arrays > 32)
// =============================================================================

mod signature_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use super::SIGNATURE_SIZE;

    pub fn serialize<S>(bytes: &[u8; SIGNATURE_SIZE], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        bytes.as_slice().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; SIGNATURE_SIZE], D::Error>
    where
        D: Deserializer<'de>,
    {
        let vec = Vec::<u8>::deserialize(deserializer)?;
        if vec.len() != SIGNATURE_SIZE {
            return Err(serde::de::Error::custom(format!(
                "expected {} bytes for signature, got {}",
                SIGNATURE_SIZE,
                vec.len()
            )));
        }
        let mut arr = [0u8; SIGNATURE_SIZE];
        arr.copy_from_slice(&vec);
        Ok(arr)
    }
}

// =============================================================================
// EpochSealV1
// =============================================================================

/// A monotonic epoch seal binding an artifact root to an epoch number.
///
/// Each seal commits to:
/// - `epoch_number`: Strictly increasing per issuer
/// - `sealed_root_hash`: BLAKE3 hash of the sealed artifact tree
/// - `issuer_cell_id`: Identity of the issuing cell
/// - `signature`: Cryptographic signature over the canonical content
/// - `content_hash`: BLAKE3 hash for CAS addressability
///
/// # Invariants
///
/// - `epoch_number > 0` (epoch zero is reserved as "no seal")
/// - `sealed_root_hash` and `content_hash` must be non-zero
/// - `issuer_cell_id` must be non-empty and bounded
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EpochSealV1 {
    /// Monotonically increasing epoch number (must be > 0).
    epoch_number: u64,

    /// BLAKE3 hash of the sealed artifact tree root.
    sealed_root_hash: [u8; 32],

    /// Identity of the issuing cell.
    issuer_cell_id: String,

    /// Cryptographic signature over the canonical seal content.
    #[serde(with = "signature_serde")]
    signature: [u8; 64],

    /// BLAKE3 content hash for CAS addressability.
    content_hash: [u8; 32],
}

impl EpochSealV1 {
    /// Creates a new epoch seal with validation.
    ///
    /// # Errors
    ///
    /// Returns [`EpochSealError`] if any field violates invariants.
    pub fn new(
        epoch_number: u64,
        sealed_root_hash: [u8; 32],
        issuer_cell_id: impl Into<String>,
        signature: [u8; 64],
        content_hash: [u8; 32],
    ) -> Result<Self, EpochSealError> {
        if epoch_number == 0 {
            return Err(EpochSealError::ZeroEpoch);
        }

        if sealed_root_hash == [0u8; 32] {
            return Err(EpochSealError::ZeroRootHash);
        }

        if content_hash == [0u8; 32] {
            return Err(EpochSealError::ZeroContentHash);
        }

        let issuer_cell_id = issuer_cell_id.into();
        if issuer_cell_id.is_empty() {
            return Err(EpochSealError::EmptyIssuerId);
        }
        if issuer_cell_id.len() > MAX_SEAL_STRING_LENGTH {
            return Err(EpochSealError::IssuerIdTooLong {
                length: issuer_cell_id.len(),
                max: MAX_SEAL_STRING_LENGTH,
            });
        }

        Ok(Self {
            epoch_number,
            sealed_root_hash,
            issuer_cell_id,
            signature,
            content_hash,
        })
    }

    /// Returns the epoch number.
    #[must_use]
    pub const fn epoch_number(&self) -> u64 {
        self.epoch_number
    }

    /// Returns the sealed root hash.
    #[must_use]
    pub const fn sealed_root_hash(&self) -> &[u8; 32] {
        &self.sealed_root_hash
    }

    /// Returns the issuer cell identity.
    #[must_use]
    pub fn issuer_cell_id(&self) -> &str {
        &self.issuer_cell_id
    }

    /// Returns the signature bytes.
    #[must_use]
    pub const fn signature(&self) -> &[u8; 64] {
        &self.signature
    }

    /// Returns the content hash.
    #[must_use]
    pub const fn content_hash(&self) -> &[u8; 32] {
        &self.content_hash
    }

    /// Computes the canonical BLAKE3 hash of this seal for verification.
    #[must_use]
    pub fn canonical_hash(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"apm2:epoch_seal_v1:canonical:v1\0");
        hasher.update(&self.epoch_number.to_le_bytes());
        hasher.update(&self.sealed_root_hash);
        hasher.update(self.issuer_cell_id.as_bytes());
        *hasher.finalize().as_bytes()
    }
}

impl std::fmt::Display for EpochSealV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "EpochSeal(epoch={}, issuer={}, root={}..)",
            self.epoch_number,
            self.issuer_cell_id,
            hex::encode(&self.sealed_root_hash[..8])
        )
    }
}

// =============================================================================
// EpochSealError
// =============================================================================

/// Errors that can occur when constructing or validating an [`EpochSealV1`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum EpochSealError {
    /// Epoch number must be greater than zero.
    #[error("epoch number must be > 0 (epoch zero is reserved)")]
    ZeroEpoch,

    /// Sealed root hash must be non-zero.
    #[error("sealed root hash must be non-zero")]
    ZeroRootHash,

    /// Content hash must be non-zero.
    #[error("content hash must be non-zero")]
    ZeroContentHash,

    /// Issuer cell ID is empty.
    #[error("issuer cell ID must be non-empty")]
    EmptyIssuerId,

    /// Issuer cell ID exceeds maximum length.
    #[error("issuer cell ID too long: {length} > {max}")]
    IssuerIdTooLong {
        /// Actual length.
        length: usize,
        /// Maximum allowed length.
        max: usize,
    },
}

// =============================================================================
// EpochSealIssuer
// =============================================================================

/// Issues monotonically increasing epoch seals for a given cell identity.
///
/// The issuer tracks the last issued epoch to guarantee monotonicity.
/// Each call to [`issue`](EpochSealIssuer::issue) produces a seal with
/// an epoch strictly greater than the previous one.
#[derive(Debug, Clone)]
pub struct EpochSealIssuer {
    /// The issuing cell identity.
    issuer_cell_id: String,

    /// The last issued epoch number (0 = none issued yet).
    last_epoch: u64,
}

impl EpochSealIssuer {
    /// Creates a new issuer for the given cell identity.
    ///
    /// # Errors
    ///
    /// Returns [`EpochSealError::EmptyIssuerId`] if the cell ID is empty.
    /// Returns [`EpochSealError::IssuerIdTooLong`] if the cell ID exceeds
    /// the maximum length.
    pub fn new(issuer_cell_id: impl Into<String>) -> Result<Self, EpochSealError> {
        let issuer_cell_id = issuer_cell_id.into();
        if issuer_cell_id.is_empty() {
            return Err(EpochSealError::EmptyIssuerId);
        }
        if issuer_cell_id.len() > MAX_SEAL_STRING_LENGTH {
            return Err(EpochSealError::IssuerIdTooLong {
                length: issuer_cell_id.len(),
                max: MAX_SEAL_STRING_LENGTH,
            });
        }
        Ok(Self {
            issuer_cell_id,
            last_epoch: 0,
        })
    }

    /// Returns the issuer cell identity.
    #[must_use]
    pub fn issuer_cell_id(&self) -> &str {
        &self.issuer_cell_id
    }

    /// Returns the last issued epoch number (0 = none issued).
    #[must_use]
    pub const fn last_epoch(&self) -> u64 {
        self.last_epoch
    }

    /// Issues a new epoch seal at the next monotonic epoch.
    ///
    /// The epoch is set to `last_epoch + 1`. The signature is provided
    /// by the caller (from an external signing oracle).
    ///
    /// # Arguments
    ///
    /// * `sealed_root_hash` - BLAKE3 hash of the artifact tree root
    /// * `signature` - Signature over the canonical seal content
    /// * `content_hash` - BLAKE3 content hash for CAS
    ///
    /// # Errors
    ///
    /// Returns [`EpochSealIssuanceError::EpochOverflow`] if the epoch
    /// counter would overflow `u64::MAX`.
    /// Returns [`EpochSealIssuanceError::Validation`] for field validation
    /// failures.
    pub fn issue(
        &mut self,
        sealed_root_hash: [u8; 32],
        signature: [u8; 64],
        content_hash: [u8; 32],
    ) -> Result<EpochSealV1, EpochSealIssuanceError> {
        let next_epoch = self
            .last_epoch
            .checked_add(1)
            .ok_or(EpochSealIssuanceError::EpochOverflow)?;

        let seal = EpochSealV1::new(
            next_epoch,
            sealed_root_hash,
            self.issuer_cell_id.clone(),
            signature,
            content_hash,
        )
        .map_err(EpochSealIssuanceError::Validation)?;

        self.last_epoch = next_epoch;
        Ok(seal)
    }
}

/// Errors during epoch seal issuance.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum EpochSealIssuanceError {
    /// Epoch counter overflow.
    #[error("epoch counter overflow: cannot exceed u64::MAX")]
    EpochOverflow,

    /// Seal field validation failed.
    #[error("seal validation failed: {0}")]
    Validation(EpochSealError),
}

// =============================================================================
// EpochSealVerdict
// =============================================================================

/// Outcome of verifying an epoch seal against the verifier state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochSealVerdict {
    /// Whether the seal was accepted.
    pub accepted: bool,

    /// The risk tier evaluated.
    pub risk_tier: RiskTier,

    /// The seal's epoch number.
    pub epoch_number: u64,

    /// The issuer cell ID.
    pub issuer_cell_id: String,

    /// Audit event for deterministic logging.
    pub audit_event: EpochSealAuditEvent,
}

// =============================================================================
// EpochSealAuditEvent
// =============================================================================

/// Deterministic audit event emitted for every epoch seal verification.
///
/// These events form a CAS-addressable audit trail. Given the same
/// inputs, the same event (and hash) is produced.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum EpochSealAuditEvent {
    /// Seal accepted: epoch is strictly greater than last seen.
    Accepted {
        /// Issuer cell ID.
        issuer_cell_id: String,
        /// The accepted epoch number.
        epoch_number: u64,
        /// The previous epoch for this issuer (0 = first seal).
        previous_epoch: u64,
    },

    /// Seal rejected: epoch is not monotonically increasing (rollback).
    RollbackRejected {
        /// Issuer cell ID.
        issuer_cell_id: String,
        /// The rejected epoch number.
        epoch_number: u64,
        /// The last accepted epoch for this issuer.
        last_accepted_epoch: u64,
    },

    /// Seal rejected: same epoch but different root hash (equivocation).
    EquivocationDetected {
        /// Issuer cell ID.
        issuer_cell_id: String,
        /// The epoch number where equivocation was detected.
        epoch_number: u64,
        /// Root hash from the previously accepted seal.
        existing_root_hash: [u8; 32],
        /// Root hash from the conflicting seal.
        conflicting_root_hash: [u8; 32],
    },

    /// Seal rejected: missing seal for Tier2+ admission.
    MissingSealDenied {
        /// Risk tier that required the seal.
        risk_tier: RiskTier,
    },

    /// Seal rejected: invalid seal (construction error).
    InvalidSeal {
        /// Description of the validation failure.
        reason: String,
    },
}

impl EpochSealAuditEvent {
    /// Returns a static event kind label for structured logging.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Accepted { .. } => "epoch_seal.accepted",
            Self::RollbackRejected { .. } => "epoch_seal.rollback_rejected",
            Self::EquivocationDetected { .. } => "epoch_seal.equivocation_detected",
            Self::MissingSealDenied { .. } => "epoch_seal.missing_seal_denied",
            Self::InvalidSeal { .. } => "epoch_seal.invalid_seal",
        }
    }

    /// Computes a deterministic BLAKE3 hash of this audit event for
    /// CAS-addressable storage.
    #[must_use]
    pub fn canonical_hash(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(EPOCH_SEAL_AUDIT_DOMAIN);
        hasher.update(self.kind().as_bytes());
        match self {
            Self::Accepted {
                issuer_cell_id,
                epoch_number,
                previous_epoch,
            } => {
                hasher.update(issuer_cell_id.as_bytes());
                hasher.update(&epoch_number.to_le_bytes());
                hasher.update(&previous_epoch.to_le_bytes());
            },
            Self::RollbackRejected {
                issuer_cell_id,
                epoch_number,
                last_accepted_epoch,
            } => {
                hasher.update(issuer_cell_id.as_bytes());
                hasher.update(&epoch_number.to_le_bytes());
                hasher.update(&last_accepted_epoch.to_le_bytes());
            },
            Self::EquivocationDetected {
                issuer_cell_id,
                epoch_number,
                existing_root_hash,
                conflicting_root_hash,
            } => {
                hasher.update(issuer_cell_id.as_bytes());
                hasher.update(&epoch_number.to_le_bytes());
                hasher.update(existing_root_hash);
                hasher.update(conflicting_root_hash);
            },
            Self::MissingSealDenied { risk_tier } => {
                hasher.update(&[*risk_tier as u8]);
            },
            Self::InvalidSeal { reason } => {
                hasher.update(reason.as_bytes());
            },
        }
        *hasher.finalize().as_bytes()
    }
}

// =============================================================================
// EpochSealVerificationError
// =============================================================================

/// Errors during epoch seal verification in the admission path.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum EpochSealVerificationError {
    /// Seal epoch is not strictly greater than last accepted (rollback).
    #[error(
        "epoch rollback: seal epoch {epoch_number} <= last accepted {last_accepted_epoch} for issuer {issuer_cell_id}"
    )]
    Rollback {
        /// The rejected epoch number.
        epoch_number: u64,
        /// The last accepted epoch for this issuer.
        last_accepted_epoch: u64,
        /// Issuer cell ID.
        issuer_cell_id: String,
    },

    /// Two seals at the same epoch with different root hashes.
    #[error(
        "equivocation detected: epoch {epoch_number} from issuer {issuer_cell_id} has conflicting root hashes"
    )]
    Equivocation {
        /// The epoch number.
        epoch_number: u64,
        /// Issuer cell ID.
        issuer_cell_id: String,
    },

    /// Missing seal for Tier2+ admission (fail-closed).
    #[error("missing epoch seal for {risk_tier:?} admission (fail-closed)")]
    MissingSeal {
        /// The risk tier that required the seal.
        risk_tier: RiskTier,
    },

    /// Too many tracked issuers (denial-of-service protection).
    #[error("too many tracked issuers: {count} >= {max}")]
    TooManyIssuers {
        /// Current count.
        count: usize,
        /// Maximum allowed.
        max: usize,
    },
}

// =============================================================================
// IssuerState (internal)
// =============================================================================

/// Per-issuer state tracked by the verifier.
#[derive(Debug, Clone)]
struct IssuerState {
    /// The last accepted epoch number.
    last_epoch: u64,

    /// The root hash of the last accepted seal.
    last_root_hash: [u8; 32],
}

// =============================================================================
// EpochSealVerifier
// =============================================================================

/// Verifies epoch seals for monotonicity, rollback rejection, and
/// equivocation detection.
///
/// The verifier maintains per-issuer state mapping each issuer cell ID
/// to its last accepted epoch and root hash. Verification enforces:
///
/// 1. **Monotonicity**: `seal.epoch_number > state[issuer].last_epoch`
/// 2. **Anti-equivocation**: If `seal.epoch_number ==
///    state[issuer].last_epoch`, the root hashes must match (duplicate
///    acceptance is idempotent).
/// 3. **Fail-closed**: Tier2+ admissions require a valid seal.
#[derive(Debug, Clone)]
pub struct EpochSealVerifier {
    /// Per-issuer epoch state.
    issuers: HashMap<String, IssuerState>,
}

impl EpochSealVerifier {
    /// Creates a new verifier with no tracked issuers.
    #[must_use]
    pub fn new() -> Self {
        Self {
            issuers: HashMap::new(),
        }
    }

    /// Returns the number of tracked issuers.
    #[must_use]
    pub fn tracked_issuer_count(&self) -> usize {
        self.issuers.len()
    }

    /// Returns the last accepted epoch for the given issuer, or `None`
    /// if no seal has been accepted from this issuer.
    #[must_use]
    pub fn last_epoch_for(&self, issuer_cell_id: &str) -> Option<u64> {
        self.issuers.get(issuer_cell_id).map(|s| s.last_epoch)
    }

    /// Verifies and accepts an epoch seal, updating internal state.
    ///
    /// # Returns
    ///
    /// An [`EpochSealVerdict`] describing the outcome.
    pub fn verify(&mut self, seal: &EpochSealV1, risk_tier: RiskTier) -> EpochSealVerdict {
        let issuer = seal.issuer_cell_id();

        if let Some(state) = self.issuers.get_mut(issuer) {
            if seal.epoch_number() < state.last_epoch {
                // Rollback: epoch is less than last accepted.
                return EpochSealVerdict {
                    accepted: false,
                    risk_tier,
                    epoch_number: seal.epoch_number(),
                    issuer_cell_id: issuer.to_string(),
                    audit_event: EpochSealAuditEvent::RollbackRejected {
                        issuer_cell_id: issuer.to_string(),
                        epoch_number: seal.epoch_number(),
                        last_accepted_epoch: state.last_epoch,
                    },
                };
            }

            if seal.epoch_number() == state.last_epoch {
                if seal.sealed_root_hash() != &state.last_root_hash {
                    // Equivocation: same epoch, different root hash.
                    return EpochSealVerdict {
                        accepted: false,
                        risk_tier,
                        epoch_number: seal.epoch_number(),
                        issuer_cell_id: issuer.to_string(),
                        audit_event: EpochSealAuditEvent::EquivocationDetected {
                            issuer_cell_id: issuer.to_string(),
                            epoch_number: seal.epoch_number(),
                            existing_root_hash: state.last_root_hash,
                            conflicting_root_hash: *seal.sealed_root_hash(),
                        },
                    };
                }

                // Idempotent re-acceptance of same seal.
                return EpochSealVerdict {
                    accepted: true,
                    risk_tier,
                    epoch_number: seal.epoch_number(),
                    issuer_cell_id: issuer.to_string(),
                    audit_event: EpochSealAuditEvent::Accepted {
                        issuer_cell_id: issuer.to_string(),
                        epoch_number: seal.epoch_number(),
                        previous_epoch: state.last_epoch,
                    },
                };
            }

            // Monotonically increasing: accept and update.
            let previous_epoch = state.last_epoch;
            state.last_epoch = seal.epoch_number();
            state.last_root_hash = *seal.sealed_root_hash();

            EpochSealVerdict {
                accepted: true,
                risk_tier,
                epoch_number: seal.epoch_number(),
                issuer_cell_id: issuer.to_string(),
                audit_event: EpochSealAuditEvent::Accepted {
                    issuer_cell_id: issuer.to_string(),
                    epoch_number: seal.epoch_number(),
                    previous_epoch,
                },
            }
        } else {
            // First seal from this issuer.
            if self.issuers.len() >= MAX_TRACKED_ISSUERS {
                return EpochSealVerdict {
                    accepted: false,
                    risk_tier,
                    epoch_number: seal.epoch_number(),
                    issuer_cell_id: issuer.to_string(),
                    audit_event: EpochSealAuditEvent::InvalidSeal {
                        reason: format!(
                            "too many tracked issuers: {} >= {MAX_TRACKED_ISSUERS}",
                            self.issuers.len()
                        ),
                    },
                };
            }

            self.issuers.insert(
                issuer.to_string(),
                IssuerState {
                    last_epoch: seal.epoch_number(),
                    last_root_hash: *seal.sealed_root_hash(),
                },
            );

            EpochSealVerdict {
                accepted: true,
                risk_tier,
                epoch_number: seal.epoch_number(),
                issuer_cell_id: issuer.to_string(),
                audit_event: EpochSealAuditEvent::Accepted {
                    issuer_cell_id: issuer.to_string(),
                    epoch_number: seal.epoch_number(),
                    previous_epoch: 0,
                },
            }
        }
    }

    /// Convenience method that verifies and returns `Ok(verdict)` for
    /// accepted seals, or `Err(EpochSealVerificationError)` for rejected
    /// seals.
    ///
    /// # Errors
    ///
    /// Returns an error describing the rejection reason.
    pub fn verify_or_reject(
        &mut self,
        seal: &EpochSealV1,
        risk_tier: RiskTier,
    ) -> Result<EpochSealVerdict, EpochSealVerificationError> {
        let verdict = self.verify(seal, risk_tier);
        if verdict.accepted {
            Ok(verdict)
        } else {
            match &verdict.audit_event {
                EpochSealAuditEvent::RollbackRejected {
                    epoch_number,
                    last_accepted_epoch,
                    issuer_cell_id,
                    ..
                } => Err(EpochSealVerificationError::Rollback {
                    epoch_number: *epoch_number,
                    last_accepted_epoch: *last_accepted_epoch,
                    issuer_cell_id: issuer_cell_id.clone(),
                }),
                EpochSealAuditEvent::EquivocationDetected {
                    epoch_number,
                    issuer_cell_id,
                    ..
                } => Err(EpochSealVerificationError::Equivocation {
                    epoch_number: *epoch_number,
                    issuer_cell_id: issuer_cell_id.clone(),
                }),
                EpochSealAuditEvent::InvalidSeal { .. } => {
                    Err(EpochSealVerificationError::TooManyIssuers {
                        count: self.issuers.len(),
                        max: MAX_TRACKED_ISSUERS,
                    })
                },
                _ => Err(EpochSealVerificationError::MissingSeal { risk_tier }),
            }
        }
    }

    /// Checks whether a valid seal is required for the given risk tier
    /// and returns an error if so and no seal is available.
    ///
    /// Tier2+ admissions fail closed on missing seals.
    ///
    /// # Errors
    ///
    /// Returns [`EpochSealVerificationError::MissingSeal`] if the tier
    /// requires a seal.
    pub const fn require_seal_for_tier(
        risk_tier: RiskTier,
    ) -> Result<(), EpochSealVerificationError> {
        if is_seal_required_tier(risk_tier) {
            Err(EpochSealVerificationError::MissingSeal { risk_tier })
        } else {
            Ok(())
        }
    }
}

impl Default for EpochSealVerifier {
    fn default() -> Self {
        Self::new()
    }
}

/// Returns true if the given risk tier requires a valid epoch seal
/// (Tier2+).
#[must_use]
pub const fn is_seal_required_tier(risk_tier: RiskTier) -> bool {
    (risk_tier as u8) >= 2
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // Helper functions
    // =========================================================================

    fn test_root_hash(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    fn test_signature() -> [u8; 64] {
        [0xAA; 64]
    }

    fn test_content_hash(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    fn make_seal(epoch: u64, issuer: &str, root_seed: u8) -> EpochSealV1 {
        EpochSealV1::new(
            epoch,
            test_root_hash(root_seed),
            issuer,
            test_signature(),
            test_content_hash(root_seed.wrapping_add(0x10)),
        )
        .expect("valid seal")
    }

    // =========================================================================
    // EpochSealV1 Construction Tests
    // =========================================================================

    #[test]
    fn seal_construction_valid() {
        let seal = EpochSealV1::new(
            1,
            test_root_hash(0x42),
            "cell-alpha",
            test_signature(),
            test_content_hash(0x43),
        )
        .unwrap();

        assert_eq!(seal.epoch_number(), 1);
        assert_eq!(seal.sealed_root_hash(), &test_root_hash(0x42));
        assert_eq!(seal.issuer_cell_id(), "cell-alpha");
        assert_eq!(seal.signature(), &test_signature());
        assert_eq!(seal.content_hash(), &test_content_hash(0x43));
    }

    #[test]
    fn seal_rejects_zero_epoch() {
        let result = EpochSealV1::new(
            0,
            test_root_hash(0x42),
            "cell-alpha",
            test_signature(),
            test_content_hash(0x43),
        );
        assert!(matches!(result, Err(EpochSealError::ZeroEpoch)));
    }

    #[test]
    fn seal_rejects_zero_root_hash() {
        let result = EpochSealV1::new(
            1,
            [0u8; 32],
            "cell-alpha",
            test_signature(),
            test_content_hash(0x43),
        );
        assert!(matches!(result, Err(EpochSealError::ZeroRootHash)));
    }

    #[test]
    fn seal_rejects_zero_content_hash() {
        let result = EpochSealV1::new(
            1,
            test_root_hash(0x42),
            "cell-alpha",
            test_signature(),
            [0u8; 32],
        );
        assert!(matches!(result, Err(EpochSealError::ZeroContentHash)));
    }

    #[test]
    fn seal_rejects_empty_issuer() {
        let result = EpochSealV1::new(
            1,
            test_root_hash(0x42),
            "",
            test_signature(),
            test_content_hash(0x43),
        );
        assert!(matches!(result, Err(EpochSealError::EmptyIssuerId)));
    }

    #[test]
    fn seal_rejects_oversized_issuer() {
        let long_id = "x".repeat(MAX_SEAL_STRING_LENGTH + 1);
        let result = EpochSealV1::new(
            1,
            test_root_hash(0x42),
            long_id,
            test_signature(),
            test_content_hash(0x43),
        );
        assert!(matches!(
            result,
            Err(EpochSealError::IssuerIdTooLong { .. })
        ));
    }

    #[test]
    fn seal_display() {
        let seal = make_seal(5, "cell-alpha", 0x42);
        let display = seal.to_string();
        assert!(display.contains("epoch=5"));
        assert!(display.contains("cell-alpha"));
    }

    #[test]
    fn seal_canonical_hash_deterministic() {
        let seal1 = make_seal(3, "cell-beta", 0x11);
        let seal2 = make_seal(3, "cell-beta", 0x11);
        assert_eq!(seal1.canonical_hash(), seal2.canonical_hash());
    }

    #[test]
    fn seal_canonical_hash_differs_on_epoch() {
        let seal1 = make_seal(3, "cell-beta", 0x11);
        let seal2 = make_seal(4, "cell-beta", 0x11);
        assert_ne!(seal1.canonical_hash(), seal2.canonical_hash());
    }

    #[test]
    fn seal_canonical_hash_differs_on_issuer() {
        let seal1 = make_seal(3, "cell-alpha", 0x11);
        let seal2 = make_seal(3, "cell-beta", 0x11);
        assert_ne!(seal1.canonical_hash(), seal2.canonical_hash());
    }

    #[test]
    fn seal_serde_roundtrip() {
        let seal = make_seal(7, "cell-gamma", 0x55);
        let json = serde_json::to_string(&seal).unwrap();
        let deserialized: EpochSealV1 = serde_json::from_str(&json).unwrap();
        assert_eq!(seal, deserialized);
    }

    // =========================================================================
    // EpochSealIssuer Tests
    // =========================================================================

    #[test]
    fn issuer_construction() {
        let issuer = EpochSealIssuer::new("cell-alpha").unwrap();
        assert_eq!(issuer.issuer_cell_id(), "cell-alpha");
        assert_eq!(issuer.last_epoch(), 0);
    }

    #[test]
    fn issuer_rejects_empty_id() {
        let result = EpochSealIssuer::new("");
        assert!(matches!(result, Err(EpochSealError::EmptyIssuerId)));
    }

    #[test]
    fn issuer_monotonic_epoch_increment() {
        let mut issuer = EpochSealIssuer::new("cell-alpha").unwrap();

        let seal1 = issuer
            .issue(
                test_root_hash(0x11),
                test_signature(),
                test_content_hash(0x21),
            )
            .unwrap();
        assert_eq!(seal1.epoch_number(), 1);
        assert_eq!(issuer.last_epoch(), 1);

        let seal2 = issuer
            .issue(
                test_root_hash(0x22),
                test_signature(),
                test_content_hash(0x32),
            )
            .unwrap();
        assert_eq!(seal2.epoch_number(), 2);
        assert_eq!(issuer.last_epoch(), 2);

        let seal3 = issuer
            .issue(
                test_root_hash(0x33),
                test_signature(),
                test_content_hash(0x43),
            )
            .unwrap();
        assert_eq!(seal3.epoch_number(), 3);
        assert_eq!(issuer.last_epoch(), 3);
    }

    #[test]
    fn issuer_rejects_zero_root_hash() {
        let mut issuer = EpochSealIssuer::new("cell-alpha").unwrap();
        let result = issuer.issue([0u8; 32], test_signature(), test_content_hash(0x21));
        assert!(matches!(
            result,
            Err(EpochSealIssuanceError::Validation(
                EpochSealError::ZeroRootHash
            ))
        ));
        // Epoch should not have advanced.
        assert_eq!(issuer.last_epoch(), 0);
    }

    // =========================================================================
    // EpochSealVerifier: Monotonicity Tests
    // =========================================================================

    #[test]
    fn verifier_accepts_first_seal() {
        let mut verifier = EpochSealVerifier::new();
        let seal = make_seal(1, "cell-alpha", 0x11);
        let verdict = verifier.verify(&seal, RiskTier::Tier2);

        assert!(verdict.accepted);
        assert_eq!(verdict.epoch_number, 1);
        assert!(matches!(
            verdict.audit_event,
            EpochSealAuditEvent::Accepted {
                previous_epoch: 0,
                ..
            }
        ));
        assert_eq!(verifier.last_epoch_for("cell-alpha"), Some(1));
    }

    #[test]
    fn verifier_accepts_monotonic_sequence() {
        let mut verifier = EpochSealVerifier::new();
        let seeds: [u8; 5] = [0x01, 0x02, 0x03, 0x04, 0x05];

        for (i, &seed) in seeds.iter().enumerate() {
            let epoch = (i as u64) + 1;
            let seal = make_seal(epoch, "cell-alpha", seed);
            let verdict = verifier.verify(&seal, RiskTier::Tier3);
            assert!(verdict.accepted, "epoch {epoch} should be accepted");
        }

        assert_eq!(verifier.last_epoch_for("cell-alpha"), Some(5));
    }

    #[test]
    fn verifier_accepts_non_consecutive_monotonic() {
        let mut verifier = EpochSealVerifier::new();

        let seal1 = make_seal(1, "cell-alpha", 0x11);
        assert!(verifier.verify(&seal1, RiskTier::Tier2).accepted);

        // Jump to epoch 10 (non-consecutive but monotonic).
        let seal2 = make_seal(10, "cell-alpha", 0x22);
        assert!(verifier.verify(&seal2, RiskTier::Tier2).accepted);

        assert_eq!(verifier.last_epoch_for("cell-alpha"), Some(10));
    }

    // =========================================================================
    // EpochSealVerifier: Rollback Rejection Tests
    // =========================================================================

    #[test]
    fn verifier_rejects_rollback() {
        let mut verifier = EpochSealVerifier::new();

        let seal1 = make_seal(5, "cell-alpha", 0x11);
        assert!(verifier.verify(&seal1, RiskTier::Tier2).accepted);

        // Attempt rollback to epoch 3.
        let seal2 = make_seal(3, "cell-alpha", 0x22);
        let verdict = verifier.verify(&seal2, RiskTier::Tier2);

        assert!(!verdict.accepted);
        assert!(matches!(
            verdict.audit_event,
            EpochSealAuditEvent::RollbackRejected {
                epoch_number: 3,
                last_accepted_epoch: 5,
                ..
            }
        ));

        // State should not have changed.
        assert_eq!(verifier.last_epoch_for("cell-alpha"), Some(5));
    }

    #[test]
    fn verifier_rejects_rollback_to_epoch_1() {
        let mut verifier = EpochSealVerifier::new();

        let seal1 = make_seal(10, "cell-alpha", 0x11);
        assert!(verifier.verify(&seal1, RiskTier::Tier2).accepted);

        let seal2 = make_seal(1, "cell-alpha", 0x22);
        let verdict = verifier.verify(&seal2, RiskTier::Tier2);
        assert!(!verdict.accepted);
        assert!(matches!(
            verdict.audit_event,
            EpochSealAuditEvent::RollbackRejected { .. }
        ));
    }

    // =========================================================================
    // EpochSealVerifier: Equivocation Detection Tests
    // =========================================================================

    #[test]
    fn verifier_detects_equivocation() {
        let mut verifier = EpochSealVerifier::new();

        let seal1 = make_seal(5, "cell-alpha", 0x11);
        assert!(verifier.verify(&seal1, RiskTier::Tier2).accepted);

        // Same epoch, different root hash = equivocation.
        let seal2 = make_seal(5, "cell-alpha", 0x22);
        let verdict = verifier.verify(&seal2, RiskTier::Tier2);

        assert!(!verdict.accepted);
        assert!(matches!(
            verdict.audit_event,
            EpochSealAuditEvent::EquivocationDetected {
                epoch_number: 5,
                ..
            }
        ));
    }

    #[test]
    fn verifier_idempotent_same_seal() {
        let mut verifier = EpochSealVerifier::new();

        let seal = make_seal(5, "cell-alpha", 0x11);
        assert!(verifier.verify(&seal, RiskTier::Tier2).accepted);

        // Same seal again (same epoch, same root hash) = idempotent accept.
        let verdict = verifier.verify(&seal, RiskTier::Tier2);
        assert!(verdict.accepted);
        assert!(matches!(
            verdict.audit_event,
            EpochSealAuditEvent::Accepted {
                epoch_number: 5,
                previous_epoch: 5,
                ..
            }
        ));
    }

    // =========================================================================
    // EpochSealVerifier: Multi-issuer Tests
    // =========================================================================

    #[test]
    fn verifier_tracks_multiple_issuers_independently() {
        let mut verifier = EpochSealVerifier::new();

        let alpha_first = make_seal(1, "cell-alpha", 0x11);
        let beta_first = make_seal(1, "cell-beta", 0x22);

        assert!(verifier.verify(&alpha_first, RiskTier::Tier2).accepted);
        assert!(verifier.verify(&beta_first, RiskTier::Tier2).accepted);

        // Alpha at epoch 5, beta at epoch 3.
        let alpha_second = make_seal(5, "cell-alpha", 0x33);
        let beta_second = make_seal(3, "cell-beta", 0x44);

        assert!(verifier.verify(&alpha_second, RiskTier::Tier2).accepted);
        assert!(verifier.verify(&beta_second, RiskTier::Tier2).accepted);

        assert_eq!(verifier.last_epoch_for("cell-alpha"), Some(5));
        assert_eq!(verifier.last_epoch_for("cell-beta"), Some(3));

        // Rollback for alpha but not beta.
        let alpha_rollback = make_seal(3, "cell-alpha", 0x55);
        assert!(!verifier.verify(&alpha_rollback, RiskTier::Tier2).accepted);

        let beta_advance = make_seal(4, "cell-beta", 0x66);
        assert!(verifier.verify(&beta_advance, RiskTier::Tier2).accepted);

        assert_eq!(verifier.last_epoch_for("cell-alpha"), Some(5));
        assert_eq!(verifier.last_epoch_for("cell-beta"), Some(4));
    }

    #[test]
    fn verifier_unknown_issuer_returns_none() {
        let verifier = EpochSealVerifier::new();
        assert_eq!(verifier.last_epoch_for("unknown"), None);
    }

    // =========================================================================
    // EpochSealVerifier: Tier-based Admission Tests
    // =========================================================================

    #[test]
    fn tier2_plus_requires_seal() {
        assert!(EpochSealVerifier::require_seal_for_tier(RiskTier::Tier2).is_err());
        assert!(EpochSealVerifier::require_seal_for_tier(RiskTier::Tier3).is_err());
        assert!(EpochSealVerifier::require_seal_for_tier(RiskTier::Tier4).is_err());
    }

    #[test]
    fn tier0_tier1_no_seal_required() {
        assert!(EpochSealVerifier::require_seal_for_tier(RiskTier::Tier0).is_ok());
        assert!(EpochSealVerifier::require_seal_for_tier(RiskTier::Tier1).is_ok());
    }

    #[test]
    fn is_seal_required_tier_values() {
        assert!(!is_seal_required_tier(RiskTier::Tier0));
        assert!(!is_seal_required_tier(RiskTier::Tier1));
        assert!(is_seal_required_tier(RiskTier::Tier2));
        assert!(is_seal_required_tier(RiskTier::Tier3));
        assert!(is_seal_required_tier(RiskTier::Tier4));
    }

    // =========================================================================
    // verify_or_reject Tests
    // =========================================================================

    #[test]
    fn verify_or_reject_accepted() {
        let mut verifier = EpochSealVerifier::new();
        let seal = make_seal(1, "cell-alpha", 0x11);
        let result = verifier.verify_or_reject(&seal, RiskTier::Tier2);
        assert!(result.is_ok());
        assert!(result.unwrap().accepted);
    }

    #[test]
    fn verify_or_reject_rollback_error() {
        let mut verifier = EpochSealVerifier::new();
        let seal1 = make_seal(5, "cell-alpha", 0x11);
        verifier.verify(&seal1, RiskTier::Tier2);

        let seal2 = make_seal(3, "cell-alpha", 0x22);
        let result = verifier.verify_or_reject(&seal2, RiskTier::Tier2);
        assert!(matches!(
            result,
            Err(EpochSealVerificationError::Rollback {
                epoch_number: 3,
                last_accepted_epoch: 5,
                ..
            })
        ));
    }

    #[test]
    fn verify_or_reject_equivocation_error() {
        let mut verifier = EpochSealVerifier::new();
        let seal1 = make_seal(5, "cell-alpha", 0x11);
        verifier.verify(&seal1, RiskTier::Tier2);

        let seal2 = make_seal(5, "cell-alpha", 0x22);
        let result = verifier.verify_or_reject(&seal2, RiskTier::Tier2);
        assert!(matches!(
            result,
            Err(EpochSealVerificationError::Equivocation {
                epoch_number: 5,
                ..
            })
        ));
    }

    // =========================================================================
    // Determinism Tests
    // =========================================================================

    #[test]
    fn audit_event_hash_is_deterministic() {
        let event1 = EpochSealAuditEvent::Accepted {
            issuer_cell_id: "cell-alpha".to_string(),
            epoch_number: 5,
            previous_epoch: 3,
        };
        let event2 = EpochSealAuditEvent::Accepted {
            issuer_cell_id: "cell-alpha".to_string(),
            epoch_number: 5,
            previous_epoch: 3,
        };
        assert_eq!(event1.canonical_hash(), event2.canonical_hash());
    }

    #[test]
    fn audit_event_hash_differs_on_different_inputs() {
        let event1 = EpochSealAuditEvent::Accepted {
            issuer_cell_id: "cell-alpha".to_string(),
            epoch_number: 5,
            previous_epoch: 3,
        };
        let event2 = EpochSealAuditEvent::Accepted {
            issuer_cell_id: "cell-beta".to_string(),
            epoch_number: 5,
            previous_epoch: 3,
        };
        assert_ne!(event1.canonical_hash(), event2.canonical_hash());
    }

    #[test]
    fn audit_event_hash_differs_accepted_vs_rollback() {
        let accepted = EpochSealAuditEvent::Accepted {
            issuer_cell_id: "cell-alpha".to_string(),
            epoch_number: 5,
            previous_epoch: 3,
        };
        let rollback = EpochSealAuditEvent::RollbackRejected {
            issuer_cell_id: "cell-alpha".to_string(),
            epoch_number: 5,
            last_accepted_epoch: 3,
        };
        assert_ne!(accepted.canonical_hash(), rollback.canonical_hash());
    }

    // =========================================================================
    // Audit Event Kind Labels
    // =========================================================================

    #[test]
    fn audit_event_kind_labels() {
        assert_eq!(
            EpochSealAuditEvent::Accepted {
                issuer_cell_id: "x".to_string(),
                epoch_number: 1,
                previous_epoch: 0,
            }
            .kind(),
            "epoch_seal.accepted"
        );
        assert_eq!(
            EpochSealAuditEvent::RollbackRejected {
                issuer_cell_id: "x".to_string(),
                epoch_number: 1,
                last_accepted_epoch: 5,
            }
            .kind(),
            "epoch_seal.rollback_rejected"
        );
        assert_eq!(
            EpochSealAuditEvent::EquivocationDetected {
                issuer_cell_id: "x".to_string(),
                epoch_number: 1,
                existing_root_hash: [0x11; 32],
                conflicting_root_hash: [0x22; 32],
            }
            .kind(),
            "epoch_seal.equivocation_detected"
        );
        assert_eq!(
            EpochSealAuditEvent::MissingSealDenied {
                risk_tier: RiskTier::Tier2,
            }
            .kind(),
            "epoch_seal.missing_seal_denied"
        );
        assert_eq!(
            EpochSealAuditEvent::InvalidSeal {
                reason: "test".to_string(),
            }
            .kind(),
            "epoch_seal.invalid_seal"
        );
    }

    // =========================================================================
    // Error Display Tests
    // =========================================================================

    #[test]
    fn error_display() {
        let err = EpochSealVerificationError::Rollback {
            epoch_number: 3,
            last_accepted_epoch: 5,
            issuer_cell_id: "cell-alpha".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("rollback"));
        assert!(msg.contains("epoch 3"));
        assert!(msg.contains("accepted 5"));

        let err = EpochSealVerificationError::Equivocation {
            epoch_number: 5,
            issuer_cell_id: "cell-alpha".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("equivocation"));
        assert!(msg.contains("epoch 5"));

        let err = EpochSealVerificationError::MissingSeal {
            risk_tier: RiskTier::Tier3,
        };
        let msg = err.to_string();
        assert!(msg.contains("missing epoch seal"));
        assert!(msg.contains("Tier3"));
    }

    #[test]
    fn seal_error_display() {
        assert!(EpochSealError::ZeroEpoch.to_string().contains("epoch"));
        assert!(
            EpochSealError::ZeroRootHash
                .to_string()
                .contains("root hash")
        );
        assert!(
            EpochSealError::ZeroContentHash
                .to_string()
                .contains("content hash")
        );
        assert!(
            EpochSealError::EmptyIssuerId
                .to_string()
                .contains("non-empty")
        );
        assert!(
            EpochSealError::IssuerIdTooLong {
                length: 5000,
                max: 4096,
            }
            .to_string()
            .contains("5000")
        );
    }

    #[test]
    fn issuance_error_display() {
        assert!(
            EpochSealIssuanceError::EpochOverflow
                .to_string()
                .contains("overflow")
        );
        assert!(
            EpochSealIssuanceError::Validation(EpochSealError::ZeroEpoch)
                .to_string()
                .contains("epoch")
        );
    }

    // =========================================================================
    // Default Implementation Test
    // =========================================================================

    #[test]
    fn verifier_default() {
        let verifier = EpochSealVerifier::default();
        assert_eq!(verifier.tracked_issuer_count(), 0);
    }

    // =========================================================================
    // Missing Seal Audit Event Hash
    // =========================================================================

    #[test]
    fn missing_seal_audit_hash_deterministic() {
        let event1 = EpochSealAuditEvent::MissingSealDenied {
            risk_tier: RiskTier::Tier2,
        };
        let event2 = EpochSealAuditEvent::MissingSealDenied {
            risk_tier: RiskTier::Tier2,
        };
        assert_eq!(event1.canonical_hash(), event2.canonical_hash());
    }

    #[test]
    fn missing_seal_audit_hash_differs_by_tier() {
        let event1 = EpochSealAuditEvent::MissingSealDenied {
            risk_tier: RiskTier::Tier2,
        };
        let event2 = EpochSealAuditEvent::MissingSealDenied {
            risk_tier: RiskTier::Tier3,
        };
        assert_ne!(event1.canonical_hash(), event2.canonical_hash());
    }

    // =========================================================================
    // DoS Protection: MAX_TRACKED_ISSUERS Test
    // =========================================================================

    #[test]
    fn verifier_rejects_when_max_issuers_reached() {
        let mut verifier = EpochSealVerifier::new();

        // Fill up to the limit.
        for i in 0..MAX_TRACKED_ISSUERS {
            // Ensure root_seed is in 1..=239 so that root_seed.wrapping_add(0x10)
            // used for content hash also stays non-zero.
            #[allow(clippy::cast_possible_truncation)]
            let root_seed = ((i % 239) + 1) as u8;
            let seal = make_seal(1, &format!("cell-{i}"), root_seed);
            let verdict = verifier.verify(&seal, RiskTier::Tier2);
            assert!(
                verdict.accepted,
                "issuer {i} should be accepted (under limit)"
            );
        }

        assert_eq!(verifier.tracked_issuer_count(), MAX_TRACKED_ISSUERS);

        // The next new issuer should be rejected.
        let seal = make_seal(1, "cell-overflow", 0xFE);
        let verdict = verifier.verify(&seal, RiskTier::Tier2);
        assert!(!verdict.accepted, "should reject when at issuer limit");
        assert!(matches!(
            verdict.audit_event,
            EpochSealAuditEvent::InvalidSeal { .. }
        ));

        // verify_or_reject should return TooManyIssuers.
        let seal2 = make_seal(1, "cell-overflow-2", 0xFD);
        let result = verifier.verify_or_reject(&seal2, RiskTier::Tier2);
        assert!(matches!(
            result,
            Err(EpochSealVerificationError::TooManyIssuers { .. })
        ));

        // But an existing issuer should still be accepted (monotonic advance).
        let seal3 = make_seal(2, "cell-0", 0xFC);
        let verdict3 = verifier.verify(&seal3, RiskTier::Tier2);
        assert!(
            verdict3.accepted,
            "existing issuer should still accept new epochs"
        );
    }

    // =========================================================================
    // Proptest: Seal Chain Invariants
    // =========================================================================

    mod proptests {
        use proptest::prelude::*;

        use super::*;

        fn arb_root_hash() -> impl Strategy<Value = [u8; 32]> {
            prop::array::uniform32(1u8..=255u8)
        }

        fn arb_content_hash() -> impl Strategy<Value = [u8; 32]> {
            prop::array::uniform32(1u8..=255u8)
        }

        fn arb_signature() -> impl Strategy<Value = [u8; 64]> {
            prop::collection::vec(0u8..=255u8, 64).prop_map(|v| {
                let mut arr = [0u8; 64];
                arr.copy_from_slice(&v);
                arr
            })
        }

        proptest! {
            /// A strictly increasing sequence of seals from one issuer must
            /// always be accepted.
            #[test]
            fn monotonic_chain_always_accepted(
                epochs in prop::collection::vec(1u64..=1_000_000, 2..50),
            ) {
                let mut sorted = epochs;
                sorted.sort_unstable();
                sorted.dedup();

                if sorted.len() < 2 {
                    return Ok(());
                }

                let mut verifier = EpochSealVerifier::new();
                for (i, &epoch) in sorted.iter().enumerate() {
                    #[allow(clippy::cast_possible_truncation)]
                    let root_seed = ((i % 254) + 1) as u8;
                    let seal = make_seal(epoch, "prop-issuer", root_seed);
                    let verdict = verifier.verify(&seal, RiskTier::Tier3);
                    prop_assert!(
                        verdict.accepted,
                        "epoch {} should be accepted (prev {:?})",
                        epoch,
                        if i > 0 { Some(sorted[i - 1]) } else { None }
                    );
                }

                prop_assert_eq!(
                    verifier.last_epoch_for("prop-issuer"),
                    Some(*sorted.last().unwrap())
                );
            }

            /// A seal with epoch <= last accepted from the same issuer must
            /// always be rejected (rollback).
            #[test]
            fn rollback_always_rejected(
                accepted_epoch in 2u64..=1_000_000,
                rollback_delta in 1u64..=1_000_000,
            ) {
                let rollback_epoch = accepted_epoch.saturating_sub(rollback_delta).max(1);
                if rollback_epoch >= accepted_epoch {
                    return Ok(());
                }

                let mut verifier = EpochSealVerifier::new();
                let seal1 = make_seal(accepted_epoch, "prop-issuer", 0x11);
                verifier.verify(&seal1, RiskTier::Tier2);

                let seal2 = make_seal(rollback_epoch, "prop-issuer", 0x22);
                let verdict = verifier.verify(&seal2, RiskTier::Tier2);
                prop_assert!(
                    !verdict.accepted,
                    "rollback from {} to {} should be rejected",
                    accepted_epoch,
                    rollback_epoch
                );
            }

            /// Two different root hashes at the same epoch from the same
            /// issuer must always detect equivocation.
            #[test]
            fn equivocation_always_detected(
                epoch in 1u64..=1_000_000,
                root_a in arb_root_hash(),
                root_b in arb_root_hash(),
                sig in arb_signature(),
                content_a in arb_content_hash(),
                content_b in arb_content_hash(),
            ) {
                prop_assume!(root_a != root_b);

                let seal_a = EpochSealV1::new(epoch, root_a, "prop-issuer", sig, content_a)
                    .unwrap();
                let seal_b = EpochSealV1::new(epoch, root_b, "prop-issuer", sig, content_b)
                    .unwrap();

                let mut verifier = EpochSealVerifier::new();
                let v1 = verifier.verify(&seal_a, RiskTier::Tier2);
                prop_assert!(v1.accepted);

                let v2 = verifier.verify(&seal_b, RiskTier::Tier2);
                prop_assert!(
                    !v2.accepted,
                    "same epoch with different root should be equivocation"
                );
                let is_equivocation = matches!(
                    v2.audit_event,
                    EpochSealAuditEvent::EquivocationDetected { .. }
                );
                prop_assert!(is_equivocation, "expected equivocation audit event");
            }

            /// Replaying the exact same seal is idempotent (accepted).
            #[test]
            fn replay_same_seal_is_idempotent(
                epoch in 1u64..=1_000_000,
                root in arb_root_hash(),
                sig in arb_signature(),
                content in arb_content_hash(),
            ) {
                let seal = EpochSealV1::new(epoch, root, "prop-issuer", sig, content)
                    .unwrap();

                let mut verifier = EpochSealVerifier::new();
                let v1 = verifier.verify(&seal, RiskTier::Tier2);
                prop_assert!(v1.accepted);

                let v2 = verifier.verify(&seal, RiskTier::Tier2);
                prop_assert!(
                    v2.accepted,
                    "replaying the exact same seal should be idempotent"
                );
            }

            /// Independent issuers have independent monotonicity chains.
            #[test]
            fn independent_issuers_independent_chains(
                epoch_a in 1u64..=1_000_000,
                epoch_b in 1u64..=1_000_000,
            ) {
                let mut verifier = EpochSealVerifier::new();

                let seal_a = make_seal(epoch_a, "issuer-a", 0x11);
                let seal_b = make_seal(epoch_b, "issuer-b", 0x22);

                let v_a = verifier.verify(&seal_a, RiskTier::Tier2);
                let v_b = verifier.verify(&seal_b, RiskTier::Tier2);

                prop_assert!(v_a.accepted);
                prop_assert!(v_b.accepted);

                prop_assert_eq!(verifier.last_epoch_for("issuer-a"), Some(epoch_a));
                prop_assert_eq!(verifier.last_epoch_for("issuer-b"), Some(epoch_b));
            }
        }
    }
}
