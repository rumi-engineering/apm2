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
//!   with different root hashes or content hashes are rejected.
//! - **Deterministic**: Given the same inputs, the verifier always produces the
//!   same [`EpochSealVerdict`] and [`EpochSealAuditEvent`].
//!
//! # Authority Model
//!
//! Epoch seal authority is derived from the issuer cell identity and
//! the monotonically increasing epoch number. The sealed root hash
//! binds the seal to a specific artifact state.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

// Re-export `is_seal_required_tier` so callers can query tier requirements
// independently if needed, but the primary verification path now integrates
// the tier-based seal-required check via `verify_with_policy`.
use crate::fac::RiskTier;
use crate::htf::vdf_profile::{
    MIN_VDF_DIFFICULTY, VdfPolicy, VdfPolicyResolver, VdfProfileError, VdfProfileV1, VdfVerifier,
};

// =============================================================================
// Constants
// =============================================================================

/// Maximum length for string fields in epoch seal types (denial-of-service
/// protection).
pub const MAX_SEAL_STRING_LENGTH: usize = 4096;

/// Maximum number of issuers tracked by a single verifier (denial-of-service
/// protection).
pub const MAX_TRACKED_ISSUERS: usize = 1024;

/// Maximum number of entries tracked per unique `cell_id`. Prevents a
/// single cell from exhausting the global `MAX_TRACKED_ISSUERS` capacity.
pub const MAX_ENTRIES_PER_CELL_ID: usize = 64;

/// Maximum number of audit events retained per verification call.
pub const MAX_SEAL_AUDIT_EVENTS: usize = 16;

/// Domain separator for epoch seal audit event hashing.
const EPOCH_SEAL_AUDIT_DOMAIN: &[u8] = b"apm2:epoch_seal_v1:audit:v1\0";

/// Signature byte length (Ed25519).
const SIGNATURE_SIZE: usize = 64;

/// Prior-epoch root for the first observed seal in a monotonic chain.
const GENESIS_PRIOR_EPOCH_ROOT: [u8; 32] = [0u8; 32];

// =============================================================================
// SignatureVerifier trait (fail-closed signature verification)
// =============================================================================

/// Error returned by a [`SignatureVerifier`] implementation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureVerificationError {
    /// Human-readable reason for rejection.
    pub reason: String,
}

impl fmt::Display for SignatureVerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "signature verification failed: {}", self.reason)
    }
}

impl std::error::Error for SignatureVerificationError {}

/// Trait for verifying epoch seal signatures.
///
/// Implementations should verify that:
/// 1. The seal's issuer is a trusted/known issuer.
/// 2. The signature over the seal's canonical content is valid for the issuer's
///    public key.
///
/// # Fail-Closed Semantics
///
/// When no `SignatureVerifier` is configured, the
/// [`EpochSealVerifier`] rejects ALL seals. This ensures that
/// forgetting to wire a verifier results in denial rather than
/// silent acceptance.
pub trait SignatureVerifier: fmt::Debug + Send + Sync {
    /// Verifies the cryptographic signature of an epoch seal.
    ///
    /// # Arguments
    ///
    /// * `seal` - The epoch seal whose signature is to be verified.
    ///
    /// # Errors
    ///
    /// Returns [`SignatureVerificationError`] if the signature is invalid,
    /// the issuer is unknown, or verification otherwise fails.
    fn verify_seal_signature(&self, seal: &EpochSealV1) -> Result<(), SignatureVerificationError>;
}

// =============================================================================
// Custom serde for [u8; 64] (serde doesn't support arrays > 32)
// =============================================================================

mod signature_serde {
    use serde::de::{self, SeqAccess, Visitor};
    use serde::{Deserializer, Serialize, Serializer};

    use super::SIGNATURE_SIZE;

    pub fn serialize<S>(bytes: &[u8; SIGNATURE_SIZE], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        bytes.as_slice().serialize(serializer)
    }

    /// Bounded deserializer for Ed25519 signatures.
    ///
    /// Uses a custom `Visitor` that rejects payloads exceeding
    /// [`SIGNATURE_SIZE`] (64) bytes **during** deserialization, before
    /// an unbounded `Vec<u8>` allocation can occur. This prevents
    /// memory-exhaustion attacks via oversized signature fields.
    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; SIGNATURE_SIZE], D::Error>
    where
        D: Deserializer<'de>,
    {
        struct BoundedSignatureVisitor;

        impl<'de> Visitor<'de> for BoundedSignatureVisitor {
            type Value = [u8; SIGNATURE_SIZE];

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(
                    formatter,
                    "a byte sequence of exactly {SIGNATURE_SIZE} bytes"
                )
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut arr = [0u8; SIGNATURE_SIZE];
                for (i, slot) in arr.iter_mut().enumerate() {
                    *slot = seq
                        .next_element()?
                        .ok_or_else(|| de::Error::invalid_length(i, &self))?;
                }
                // Reject oversized payloads: if there are more elements
                // beyond SIGNATURE_SIZE, the input is invalid.
                if seq.next_element::<u8>()?.is_some() {
                    return Err(de::Error::custom(format!(
                        "signature too long: more than {SIGNATURE_SIZE} bytes"
                    )));
                }
                Ok(arr)
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if v.len() != SIGNATURE_SIZE {
                    return Err(E::custom(format!(
                        "expected {SIGNATURE_SIZE} bytes for signature, got {}",
                        v.len()
                    )));
                }
                let mut arr = [0u8; SIGNATURE_SIZE];
                arr.copy_from_slice(v);
                Ok(arr)
            }

            fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                self.visit_bytes(&v)
            }
        }

        deserializer.deserialize_seq(BoundedSignatureVisitor)
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
/// - `cell_id`: Owning cell identity (RFC-required authority anchor)
/// - `directory_epoch`: Directory head epoch bound to this seal
/// - `receipt_batch_epoch`: Receipt-batch epoch bound to this seal
/// - `htf_time_envelope_ref`: Content-hash reference to the HTF time envelope
/// - `quorum_anchor`: Quorum-anchor hash for consensus binding
/// - `vdf_profile`: OPTIONAL VDF delay profile for adversarial federation links
/// - `authority_seal_hash`: Hash of the authority seal that authorized this
///   epoch
/// - `signature`: Cryptographic signature over the canonical content
/// - `content_hash`: BLAKE3 hash for CAS addressability
///
/// # Invariants
///
/// - `epoch_number > 0` (epoch zero is reserved as "no seal")
/// - `sealed_root_hash` and `content_hash` must be non-zero
/// - `issuer_cell_id` must be non-empty and bounded
/// - `cell_id` must be non-empty and bounded
/// - `htf_time_envelope_ref` must be non-zero
/// - `quorum_anchor` must be non-zero
/// - If present, `vdf_profile` must satisfy all VDF profile invariants
/// - `authority_seal_hash` must be non-zero
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EpochSealV1 {
    /// Monotonically increasing epoch number (must be > 0).
    epoch_number: u64,

    /// BLAKE3 hash of the sealed artifact tree root.
    sealed_root_hash: [u8; 32],

    /// Identity of the issuing cell.
    issuer_cell_id: String,

    /// Owning cell identity (RFC-required authority anchor).
    cell_id: String,

    /// Directory head epoch bound to this seal.
    directory_epoch: u64,

    /// Receipt-batch epoch bound to this seal.
    receipt_batch_epoch: u64,

    /// Content-hash reference to the HTF time envelope for this seal.
    htf_time_envelope_ref: [u8; 32],

    /// Quorum-anchor hash for consensus binding.
    quorum_anchor: [u8; 32],

    /// Optional VDF delay profile for adversarial federation links.
    #[serde(skip_serializing_if = "Option::is_none")]
    vdf_profile: Option<VdfProfileV1>,

    /// Hash of the authority seal that authorized this epoch.
    authority_seal_hash: [u8; 32],

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
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        epoch_number: u64,
        sealed_root_hash: [u8; 32],
        issuer_cell_id: impl Into<String>,
        signature: [u8; 64],
        content_hash: [u8; 32],
        cell_id: impl Into<String>,
        directory_epoch: u64,
        receipt_batch_epoch: u64,
        htf_time_envelope_ref: [u8; 32],
        quorum_anchor: [u8; 32],
        vdf_profile: Option<VdfProfileV1>,
        authority_seal_hash: [u8; 32],
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

        let cell_id = cell_id.into();
        if cell_id.is_empty() {
            return Err(EpochSealError::EmptyCellId);
        }
        if cell_id.len() > MAX_SEAL_STRING_LENGTH {
            return Err(EpochSealError::CellIdTooLong {
                length: cell_id.len(),
                max: MAX_SEAL_STRING_LENGTH,
            });
        }

        if htf_time_envelope_ref == [0u8; 32] {
            return Err(EpochSealError::ZeroTimeEnvelopeRef);
        }

        if quorum_anchor == [0u8; 32] {
            return Err(EpochSealError::ZeroQuorumAnchor);
        }

        if let Some(profile) = &vdf_profile {
            profile
                .validate()
                .map_err(EpochSealError::InvalidVdfProfile)?;
        }

        if authority_seal_hash == [0u8; 32] {
            return Err(EpochSealError::ZeroAuthoritySealHash);
        }

        Ok(Self {
            epoch_number,
            sealed_root_hash,
            issuer_cell_id,
            cell_id,
            directory_epoch,
            receipt_batch_epoch,
            htf_time_envelope_ref,
            quorum_anchor,
            vdf_profile,
            authority_seal_hash,
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

    /// Returns the owning cell identity.
    #[must_use]
    pub fn cell_id(&self) -> &str {
        &self.cell_id
    }

    /// Returns the directory head epoch.
    #[must_use]
    pub const fn directory_epoch(&self) -> u64 {
        self.directory_epoch
    }

    /// Returns the receipt-batch epoch.
    #[must_use]
    pub const fn receipt_batch_epoch(&self) -> u64 {
        self.receipt_batch_epoch
    }

    /// Returns the HTF time envelope content-hash reference.
    #[must_use]
    pub const fn htf_time_envelope_ref(&self) -> &[u8; 32] {
        &self.htf_time_envelope_ref
    }

    /// Returns the quorum-anchor hash.
    #[must_use]
    pub const fn quorum_anchor(&self) -> &[u8; 32] {
        &self.quorum_anchor
    }

    /// Returns the optional VDF delay profile.
    #[must_use]
    pub const fn vdf_profile(&self) -> Option<&VdfProfileV1> {
        self.vdf_profile.as_ref()
    }

    /// Returns the authority seal hash.
    #[must_use]
    pub const fn authority_seal_hash(&self) -> &[u8; 32] {
        &self.authority_seal_hash
    }

    /// Validates that all constructor invariants hold on this seal.
    ///
    /// This is intended for use after deserialization, where the struct
    /// may have been constructed without going through [`EpochSealV1::new`].
    /// The verifier calls this before accepting any seal.
    ///
    /// # Errors
    ///
    /// Returns [`EpochSealError`] if any invariant is violated.
    pub fn validate(&self) -> Result<(), EpochSealError> {
        if self.epoch_number == 0 {
            return Err(EpochSealError::ZeroEpoch);
        }
        if self.sealed_root_hash == [0u8; 32] {
            return Err(EpochSealError::ZeroRootHash);
        }
        if self.content_hash == [0u8; 32] {
            return Err(EpochSealError::ZeroContentHash);
        }
        if self.issuer_cell_id.is_empty() {
            return Err(EpochSealError::EmptyIssuerId);
        }
        if self.issuer_cell_id.len() > MAX_SEAL_STRING_LENGTH {
            return Err(EpochSealError::IssuerIdTooLong {
                length: self.issuer_cell_id.len(),
                max: MAX_SEAL_STRING_LENGTH,
            });
        }
        if self.cell_id.is_empty() {
            return Err(EpochSealError::EmptyCellId);
        }
        if self.cell_id.len() > MAX_SEAL_STRING_LENGTH {
            return Err(EpochSealError::CellIdTooLong {
                length: self.cell_id.len(),
                max: MAX_SEAL_STRING_LENGTH,
            });
        }
        if self.htf_time_envelope_ref == [0u8; 32] {
            return Err(EpochSealError::ZeroTimeEnvelopeRef);
        }
        if self.quorum_anchor == [0u8; 32] {
            return Err(EpochSealError::ZeroQuorumAnchor);
        }
        if let Some(profile) = &self.vdf_profile {
            profile
                .validate()
                .map_err(EpochSealError::InvalidVdfProfile)?;
        }
        if self.authority_seal_hash == [0u8; 32] {
            return Err(EpochSealError::ZeroAuthoritySealHash);
        }
        Ok(())
    }

    /// Computes the canonical BLAKE3 content hash of the seal payload
    /// (all fields except `content_hash` and `signature`).
    ///
    /// This is used to verify that the claimed `content_hash` is
    /// authentic. The preimage includes all semantically significant
    /// fields using length-prefixed framing to prevent ambiguity:
    /// - Domain separator
    /// - `epoch_number` (8 bytes LE)
    /// - `sealed_root_hash` (32 bytes)
    /// - `issuer_cell_id` (length-prefixed)
    /// - `cell_id` (length-prefixed)
    /// - `directory_epoch` (8 bytes LE)
    /// - `receipt_batch_epoch` (8 bytes LE)
    /// - `htf_time_envelope_ref` (32 bytes)
    /// - `quorum_anchor` (32 bytes)
    /// - OPTIONAL `vdf_profile` (scheme + `input_hash` + `output` +
    ///   `difficulty`)
    /// - `authority_seal_hash` (32 bytes)
    #[must_use]
    pub fn compute_content_hash(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"apm2:epoch_seal_v1:content:v1\0");
        hasher.update(&self.epoch_number.to_le_bytes());
        hasher.update(&self.sealed_root_hash);
        // Length-prefixed string fields to prevent concatenation ambiguity.
        let issuer_bytes = self.issuer_cell_id.as_bytes();
        hasher.update(&(issuer_bytes.len() as u64).to_le_bytes());
        hasher.update(issuer_bytes);
        let cell_bytes = self.cell_id.as_bytes();
        hasher.update(&(cell_bytes.len() as u64).to_le_bytes());
        hasher.update(cell_bytes);
        hasher.update(&self.directory_epoch.to_le_bytes());
        hasher.update(&self.receipt_batch_epoch.to_le_bytes());
        hasher.update(&self.htf_time_envelope_ref);
        hasher.update(&self.quorum_anchor);
        hash_optional_vdf_profile(&mut hasher, self.vdf_profile.as_ref());
        hasher.update(&self.authority_seal_hash);
        *hasher.finalize().as_bytes()
    }

    /// Computes the canonical BLAKE3 hash of this seal for CAS addressing.
    ///
    /// The preimage includes all semantically significant fields including
    /// `content_hash`, using length-prefixed framing to prevent ambiguity:
    /// - Domain separator
    /// - `epoch_number` (8 bytes LE)
    /// - `sealed_root_hash` (32 bytes)
    /// - `issuer_cell_id` (length-prefixed)
    /// - `cell_id` (length-prefixed)
    /// - `directory_epoch` (8 bytes LE)
    /// - `receipt_batch_epoch` (8 bytes LE)
    /// - `htf_time_envelope_ref` (32 bytes)
    /// - `quorum_anchor` (32 bytes)
    /// - OPTIONAL `vdf_profile` (scheme + `input_hash` + `output` +
    ///   `difficulty`)
    /// - `authority_seal_hash` (32 bytes)
    /// - `content_hash` (32 bytes)
    #[must_use]
    pub fn canonical_hash(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"apm2:epoch_seal_v1:canonical:v2\0");
        hasher.update(&self.epoch_number.to_le_bytes());
        hasher.update(&self.sealed_root_hash);
        // Length-prefixed string fields to prevent concatenation ambiguity.
        let issuer_bytes = self.issuer_cell_id.as_bytes();
        hasher.update(&(issuer_bytes.len() as u64).to_le_bytes());
        hasher.update(issuer_bytes);
        let cell_bytes = self.cell_id.as_bytes();
        hasher.update(&(cell_bytes.len() as u64).to_le_bytes());
        hasher.update(cell_bytes);
        hasher.update(&self.directory_epoch.to_le_bytes());
        hasher.update(&self.receipt_batch_epoch.to_le_bytes());
        hasher.update(&self.htf_time_envelope_ref);
        hasher.update(&self.quorum_anchor);
        hash_optional_vdf_profile(&mut hasher, self.vdf_profile.as_ref());
        hasher.update(&self.authority_seal_hash);
        hasher.update(&self.content_hash);
        *hasher.finalize().as_bytes()
    }

    /// Serializes this seal to canonical JSON bytes for wire transport.
    ///
    /// This uses `serde_json` for deterministic, portable encoding. The
    /// resulting bytes can be deserialized with [`Self::from_canonical_bytes`].
    ///
    /// # Errors
    ///
    /// Returns [`EpochSealError::SerializationFailed`] if serialization fails.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, EpochSealError> {
        serde_json::to_vec(self).map_err(|e| EpochSealError::SerializationFailed {
            reason: e.to_string(),
        })
    }

    /// Deserializes an `EpochSealV1` from canonical JSON bytes.
    ///
    /// This is the inverse of [`Self::to_canonical_bytes`].
    ///
    /// # Errors
    ///
    /// Returns [`EpochSealError::DeserializationFailed`] if the bytes
    /// cannot be parsed as a valid `EpochSealV1`.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, EpochSealError> {
        serde_json::from_slice(bytes).map_err(|e| EpochSealError::DeserializationFailed {
            reason: e.to_string(),
        })
    }
}

/// Hashes optional VDF profile fields into a seal hash preimage.
///
/// For backward compatibility with pre-VDF seals, no bytes are added when
/// `profile` is `None`.
fn hash_optional_vdf_profile(hasher: &mut blake3::Hasher, profile: Option<&VdfProfileV1>) {
    if let Some(vdf_profile) = profile {
        hasher.update(b"apm2:epoch_seal_v1:vdf_profile:v1\0");
        let scheme = vdf_profile.scheme().to_string();
        hasher.update(&(scheme.len() as u64).to_le_bytes());
        hasher.update(scheme.as_bytes());
        hasher.update(vdf_profile.input_hash());
        hasher.update(&(vdf_profile.output().len() as u64).to_le_bytes());
        hasher.update(vdf_profile.output());
        hasher.update(&vdf_profile.difficulty().to_le_bytes());
    }
}

/// Constant-time equality for 32-byte digests.
#[must_use]
fn ct_eq_32(left: &[u8; 32], right: &[u8; 32]) -> bool {
    left.ct_eq(right).unwrap_u8() == 1
}

impl std::fmt::Display for EpochSealV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "EpochSeal(epoch={}, issuer={}, cell={}, root={}.., content={}.., dir_epoch={}, rcpt_epoch={})",
            self.epoch_number,
            self.issuer_cell_id,
            self.cell_id,
            hex::encode(&self.sealed_root_hash[..8]),
            hex::encode(&self.content_hash[..8]),
            self.directory_epoch,
            self.receipt_batch_epoch,
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

    /// Cell ID is empty.
    #[error("cell ID must be non-empty")]
    EmptyCellId,

    /// Cell ID exceeds maximum length.
    #[error("cell ID too long: {length} > {max}")]
    CellIdTooLong {
        /// Actual length.
        length: usize,
        /// Maximum allowed length.
        max: usize,
    },

    /// HTF time envelope reference must be non-zero.
    #[error("HTF time envelope reference must be non-zero")]
    ZeroTimeEnvelopeRef,

    /// Quorum anchor must be non-zero.
    #[error("quorum anchor must be non-zero")]
    ZeroQuorumAnchor,

    /// Optional VDF profile is invalid.
    #[error("invalid vdf profile: {0}")]
    InvalidVdfProfile(VdfProfileError),

    /// Authority seal hash must be non-zero.
    #[error("authority seal hash must be non-zero")]
    ZeroAuthoritySealHash,

    /// Serialization to canonical bytes failed.
    #[error("serialization failed: {reason}")]
    SerializationFailed {
        /// Why serialization failed.
        reason: String,
    },

    /// Deserialization from canonical bytes failed.
    #[error("deserialization failed: {reason}")]
    DeserializationFailed {
        /// Why deserialization failed.
        reason: String,
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
    /// * `cell_id` - Owning cell identity
    /// * `directory_epoch` - Directory head epoch
    /// * `receipt_batch_epoch` - Receipt-batch epoch
    /// * `htf_time_envelope_ref` - Time envelope content-hash reference
    /// * `quorum_anchor` - Quorum-anchor hash
    /// * `vdf_profile` - Optional VDF delay profile
    /// * `authority_seal_hash` - Authority seal hash
    ///
    /// # Errors
    ///
    /// Returns [`EpochSealIssuanceError::EpochOverflow`] if the epoch
    /// counter would overflow `u64::MAX`.
    /// Returns [`EpochSealIssuanceError::Validation`] for field validation
    /// failures.
    #[allow(clippy::too_many_arguments)]
    pub fn issue(
        &mut self,
        sealed_root_hash: [u8; 32],
        signature: [u8; 64],
        content_hash: [u8; 32],
        cell_id: impl Into<String>,
        directory_epoch: u64,
        receipt_batch_epoch: u64,
        htf_time_envelope_ref: [u8; 32],
        quorum_anchor: [u8; 32],
        vdf_profile: Option<VdfProfileV1>,
        authority_seal_hash: [u8; 32],
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
            cell_id,
            directory_epoch,
            receipt_batch_epoch,
            htf_time_envelope_ref,
            quorum_anchor,
            vdf_profile,
            authority_seal_hash,
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

    /// Seal rejected: signature verification failed.
    SignatureRejected {
        /// Issuer cell ID.
        issuer_cell_id: String,
        /// The epoch number of the rejected seal.
        epoch_number: u64,
        /// Reason for signature rejection.
        reason: String,
    },

    /// Seal rejected: no signature verifier configured (fail-closed).
    NoSignatureVerifier {
        /// Issuer cell ID.
        issuer_cell_id: String,
        /// The epoch number of the rejected seal.
        epoch_number: u64,
    },

    /// Seal rejected: VDF profile is required by policy but missing.
    VdfRequiredByPolicy {
        /// Issuer cell ID.
        issuer_cell_id: String,
        /// The rejected seal epoch.
        epoch_number: u64,
        /// Minimum policy difficulty for this link/cell.
        min_difficulty: u64,
    },

    /// Seal rejected: VDF difficulty is below policy minimum.
    VdfDifficultyBelowPolicy {
        /// Issuer cell ID.
        issuer_cell_id: String,
        /// The rejected seal epoch.
        epoch_number: u64,
        /// Profile difficulty.
        difficulty: u64,
        /// Minimum policy difficulty.
        min_difficulty: u64,
    },

    /// Seal rejected: no VDF verifier configured (fail-closed).
    NoVdfVerifier {
        /// Issuer cell ID.
        issuer_cell_id: String,
        /// The epoch number of the rejected seal.
        epoch_number: u64,
    },

    /// Seal rejected: VDF challenge does not bind to expected prior root.
    VdfInputHashMismatch {
        /// Issuer cell ID.
        issuer_cell_id: String,
        /// The epoch number of the rejected seal.
        epoch_number: u64,
    },

    /// Seal rejected: VDF proof verification failed.
    VdfRejected {
        /// Issuer cell ID.
        issuer_cell_id: String,
        /// The epoch number of the rejected seal.
        epoch_number: u64,
        /// Reason for VDF rejection.
        reason: String,
    },

    /// Seal rejected: deserialization invariant validation failed.
    ValidationFailed {
        /// Description of the validation failure.
        reason: String,
    },

    /// Seal rejected: epoch is not strictly greater than evicted high-water
    /// mark (replay-after-eviction attack).
    EvictionReplayRejected {
        /// Issuer cell ID.
        issuer_cell_id: String,
        /// The rejected epoch number.
        epoch_number: u64,
        /// The evicted high-water epoch for this key.
        evicted_high_water_epoch: u64,
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
            Self::SignatureRejected { .. } => "epoch_seal.signature_rejected",
            Self::NoSignatureVerifier { .. } => "epoch_seal.no_signature_verifier",
            Self::VdfRequiredByPolicy { .. } => "epoch_seal.vdf_required_by_policy",
            Self::VdfDifficultyBelowPolicy { .. } => "epoch_seal.vdf_difficulty_below_policy",
            Self::NoVdfVerifier { .. } => "epoch_seal.no_vdf_verifier",
            Self::VdfInputHashMismatch { .. } => "epoch_seal.vdf_input_hash_mismatch",
            Self::VdfRejected { .. } => "epoch_seal.vdf_rejected",
            Self::ValidationFailed { .. } => "epoch_seal.validation_failed",
            Self::EvictionReplayRejected { .. } => "epoch_seal.eviction_replay_rejected",
        }
    }

    /// Computes a deterministic BLAKE3 hash of this audit event for
    /// CAS-addressable storage.
    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn canonical_hash(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(EPOCH_SEAL_AUDIT_DOMAIN);
        hasher.update(self.kind().as_bytes());

        // Helper closure: length-prefix a variable-length byte slice to
        // prevent concatenation ambiguity. Fixed-size fields (u64, [u8; 32])
        // do not need framing because their boundaries are unambiguous.
        let hash_lp = |hasher: &mut blake3::Hasher, data: &[u8]| {
            hasher.update(&(data.len() as u64).to_le_bytes());
            hasher.update(data);
        };

        match self {
            Self::Accepted {
                issuer_cell_id,
                epoch_number,
                previous_epoch,
            } => {
                hash_lp(&mut hasher, issuer_cell_id.as_bytes());
                hasher.update(&epoch_number.to_le_bytes());
                hasher.update(&previous_epoch.to_le_bytes());
            },
            Self::RollbackRejected {
                issuer_cell_id,
                epoch_number,
                last_accepted_epoch,
            } => {
                hash_lp(&mut hasher, issuer_cell_id.as_bytes());
                hasher.update(&epoch_number.to_le_bytes());
                hasher.update(&last_accepted_epoch.to_le_bytes());
            },
            Self::EquivocationDetected {
                issuer_cell_id,
                epoch_number,
                existing_root_hash,
                conflicting_root_hash,
            } => {
                hash_lp(&mut hasher, issuer_cell_id.as_bytes());
                hasher.update(&epoch_number.to_le_bytes());
                hasher.update(existing_root_hash);
                hasher.update(conflicting_root_hash);
            },
            Self::MissingSealDenied { risk_tier } => {
                hasher.update(&[*risk_tier as u8]);
            },
            Self::InvalidSeal { reason } | Self::ValidationFailed { reason } => {
                hash_lp(&mut hasher, reason.as_bytes());
            },
            Self::SignatureRejected {
                issuer_cell_id,
                epoch_number,
                reason,
            }
            | Self::VdfRejected {
                issuer_cell_id,
                epoch_number,
                reason,
            } => {
                hash_lp(&mut hasher, issuer_cell_id.as_bytes());
                hasher.update(&epoch_number.to_le_bytes());
                hash_lp(&mut hasher, reason.as_bytes());
            },
            Self::NoSignatureVerifier {
                issuer_cell_id,
                epoch_number,
            }
            | Self::NoVdfVerifier {
                issuer_cell_id,
                epoch_number,
            }
            | Self::VdfInputHashMismatch {
                issuer_cell_id,
                epoch_number,
            } => {
                hash_lp(&mut hasher, issuer_cell_id.as_bytes());
                hasher.update(&epoch_number.to_le_bytes());
            },
            Self::VdfRequiredByPolicy {
                issuer_cell_id,
                epoch_number,
                min_difficulty,
            } => {
                hash_lp(&mut hasher, issuer_cell_id.as_bytes());
                hasher.update(&epoch_number.to_le_bytes());
                hasher.update(&min_difficulty.to_le_bytes());
            },
            Self::VdfDifficultyBelowPolicy {
                issuer_cell_id,
                epoch_number,
                difficulty,
                min_difficulty,
            } => {
                hash_lp(&mut hasher, issuer_cell_id.as_bytes());
                hasher.update(&epoch_number.to_le_bytes());
                hasher.update(&difficulty.to_le_bytes());
                hasher.update(&min_difficulty.to_le_bytes());
            },
            Self::EvictionReplayRejected {
                issuer_cell_id,
                epoch_number,
                evicted_high_water_epoch,
            } => {
                hash_lp(&mut hasher, issuer_cell_id.as_bytes());
                hasher.update(&epoch_number.to_le_bytes());
                hasher.update(&evicted_high_water_epoch.to_le_bytes());
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

    /// Signature verification failed.
    #[error("signature verification failed for issuer {issuer_cell_id}: {reason}")]
    SignatureRejected {
        /// Issuer cell ID.
        issuer_cell_id: String,
        /// Reason for rejection.
        reason: String,
    },

    /// No signature verifier configured (fail-closed).
    #[error("no signature verifier configured (fail-closed): all seals rejected")]
    NoSignatureVerifier,

    /// Missing VDF profile when policy requires one.
    #[error(
        "vdf profile required by policy for issuer {issuer_cell_id} epoch {epoch_number} (min_difficulty={min_difficulty})"
    )]
    VdfRequiredByPolicy {
        /// Issuer cell ID.
        issuer_cell_id: String,
        /// Rejected epoch number.
        epoch_number: u64,
        /// Minimum required policy difficulty.
        min_difficulty: u64,
    },

    /// VDF profile difficulty below policy floor.
    #[error(
        "vdf difficulty {difficulty} below policy minimum {min_difficulty} for issuer {issuer_cell_id} epoch {epoch_number}"
    )]
    VdfDifficultyBelowPolicy {
        /// Issuer cell ID.
        issuer_cell_id: String,
        /// Rejected epoch number.
        epoch_number: u64,
        /// Difficulty declared by seal.
        difficulty: u64,
        /// Minimum required difficulty.
        min_difficulty: u64,
    },

    /// No VDF verifier configured (fail-closed when VDF profile is present).
    #[error("no vdf verifier configured (fail-closed): vdf-backed seals rejected")]
    NoVdfVerifier,

    /// Deterministic challenge mismatch for VDF profile.
    #[error(
        "vdf challenge mismatch for issuer {issuer_cell_id} epoch {epoch_number}: profile input hash does not match derived challenge"
    )]
    VdfInputHashMismatch {
        /// Issuer cell ID.
        issuer_cell_id: String,
        /// Rejected epoch number.
        epoch_number: u64,
    },

    /// VDF proof rejected.
    #[error("vdf verification failed for issuer {issuer_cell_id}: {reason}")]
    VdfRejected {
        /// Issuer cell ID.
        issuer_cell_id: String,
        /// Reason for rejection.
        reason: String,
    },

    /// Seal field validation failed (deserialization bypass).
    #[error("seal validation failed: {reason}")]
    ValidationFailed {
        /// Description of the failure.
        reason: String,
    },

    /// Seal epoch is not strictly greater than evicted high-water mark
    /// (replay-after-eviction attack).
    #[error(
        "eviction replay: seal epoch {epoch_number} <= evicted high-water {evicted_high_water_epoch} for issuer {issuer_cell_id}"
    )]
    EvictionReplay {
        /// The rejected epoch number.
        epoch_number: u64,
        /// The evicted high-water epoch.
        evicted_high_water_epoch: u64,
        /// Issuer cell ID.
        issuer_cell_id: String,
    },
}

// =============================================================================
// IssuerState (internal)
// =============================================================================

/// Composite key for per-cell monotonicity tracking.
///
/// Per HSI section 1.9 rule 4, monotonicity must be enforced on
/// `(cell_id, htf_time_envelope_ref, quorum_anchor)` -- not on
/// `issuer_cell_id` alone.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct MonotonicityKey {
    /// Owning cell identity (RFC-required authority anchor).
    cell_id: String,

    /// Content-hash reference to the HTF time envelope.
    htf_time_envelope_ref: [u8; 32],

    /// Quorum-anchor hash for consensus binding.
    quorum_anchor: [u8; 32],
}

/// Per-cell monotonicity state tracked by the verifier.
#[derive(Debug, Clone)]
struct CellState {
    /// The last accepted epoch number.
    epoch: u64,

    /// The root hash of the last accepted seal.
    root_hash: [u8; 32],

    /// The content hash of the last accepted seal.
    content_hash: [u8; 32],

    /// Directory epoch of the last accepted seal.
    directory_epoch: u64,

    /// Receipt-batch epoch of the last accepted seal.
    receipt_batch_epoch: u64,

    /// Authority seal hash of the last accepted seal.
    authority_seal_hash: [u8; 32],

    /// Optional VDF delay profile of the last accepted seal.
    vdf_profile: Option<VdfProfileV1>,

    /// Issuer cell ID of the last accepted seal.
    issuer_cell_id: String,

    /// Monotonically increasing counter for LRU eviction ordering.
    /// Higher values are more recently accessed.
    last_access: u64,
}

/// Tombstone persisted for an evicted monotonicity key.
///
/// Stores enough state to preserve both:
/// - replay-after-eviction high-water enforcement (`last_epoch`), and
/// - VDF challenge continuity (`last_root_hash`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EvictionTombstone {
    /// Last accepted epoch for the evicted key.
    last_epoch: u64,
    /// Root hash from the last accepted seal for the evicted key.
    last_root_hash: [u8; 32],
}

// =============================================================================
// EpochSealVerifier
// =============================================================================

/// Maximum number of eviction tombstones retained.
///
/// Bounded to prevent unbounded memory growth if many keys are evicted over
/// time.
pub const MAX_EVICTED_TOMBSTONES: usize = 256;

/// Backward-compatible alias for eviction tombstone capacity.
pub const MAX_EVICTION_TOMBSTONES: usize = MAX_EVICTED_TOMBSTONES;

/// Backward-compatible alias for eviction tombstone capacity.
pub const MAX_EVICTION_HIGH_WATER_MARKS: usize = MAX_EVICTED_TOMBSTONES;

/// Verifies epoch seals for monotonicity, rollback rejection,
/// equivocation detection, and signature authenticity.
///
/// The verifier maintains per-cell state keyed on
/// `(cell_id, htf_time_envelope_ref, quorum_anchor)` as required
/// by HSI section 1.9 rule 4. Verification enforces:
///
/// 1. **Validation**: Seal fields satisfy constructor invariants.
/// 2. **Content hash verification**: The claimed `content_hash` must match the
///    recomputed canonical hash of the seal payload.
/// 3. **Signature**: Cryptographic authenticity via [`SignatureVerifier`].
/// 4. **Monotonicity**: `seal.epoch_number > state[key].last_epoch`
/// 5. **Anti-equivocation**: If `seal.epoch_number == state[key].last_epoch`,
///    ALL seal fields must match (duplicate acceptance is idempotent). Any
///    field difference is equivocation.
/// 6. **Fail-closed**: Tier2+ admissions require a valid seal. When no
///    [`SignatureVerifier`] is configured, ALL seals are rejected.
/// 7. **Eviction safety**: When an entry is evicted from the LRU cache, its
///    high-water epoch is persisted. Re-introduced keys must present an epoch
///    strictly greater than the evicted high-water mark. This prevents replay
///    attacks that exploit LRU eviction to reset monotonic state.
#[derive(Debug)]
pub struct EpochSealVerifier {
    /// Per-cell epoch state, keyed on `(cell_id, htf_time_envelope_ref,
    /// quorum_anchor)`.
    cells: HashMap<MonotonicityKey, CellState>,

    /// Optional signature verifier. When `None`, all seals are rejected
    /// (fail-closed). This ensures that the verifier cannot accept seals
    /// without cryptographic authenticity checks.
    signature_verifier: Option<Box<dyn SignatureVerifier>>,

    /// Optional VDF verifier. When a seal carries a VDF profile and this is
    /// `None`, the seal is rejected (fail-closed).
    vdf_verifier: Option<Box<dyn VdfVerifier>>,

    /// Per-link/per-cell VDF enforcement policy.
    vdf_policy: VdfPolicy,

    /// Optional resolver for per-key VDF policy.
    ///
    /// When set, this resolver is authoritative and is used instead of
    /// `vdf_policy` for enforcement decisions.
    vdf_policy_resolver: Option<Arc<dyn VdfPolicyResolver>>,

    /// Monotonically increasing counter for LRU access ordering.
    access_counter: u64,

    /// Tombstones for evicted keys.
    ///
    /// When a key is evicted from `cells`, both its last-known epoch and root
    /// hash are stored here. On re-introduction:
    /// - the seal epoch must be strictly greater than `last_epoch`
    ///   (replay-after-eviction defense), and
    /// - `last_root_hash` is used to derive the expected VDF challenge input
    ///   for continuity.
    ///
    /// This map is bounded by [`MAX_EVICTION_TOMBSTONES`].
    evicted_tombstones: HashMap<MonotonicityKey, EvictionTombstone>,
}

impl Clone for EpochSealVerifier {
    fn clone(&self) -> Self {
        // Verifier trait objects are not cloneable; cloned verifiers start
        // without signature/VDF verifiers (fail-closed).
        Self {
            cells: self.cells.clone(),
            signature_verifier: None,
            vdf_verifier: None,
            vdf_policy: self.vdf_policy.clone(),
            vdf_policy_resolver: self.vdf_policy_resolver.clone(),
            access_counter: self.access_counter,
            evicted_tombstones: self.evicted_tombstones.clone(),
        }
    }
}

impl EpochSealVerifier {
    /// Creates a new verifier with no tracked cells and no signature
    /// verifier.
    ///
    /// **WARNING**: Without a signature verifier, ALL seals will be
    /// rejected (fail-closed). Use [`with_signature_verifier`] to
    /// configure one.
    ///
    /// [`with_signature_verifier`]: EpochSealVerifier::with_signature_verifier
    #[must_use]
    pub fn new() -> Self {
        Self {
            cells: HashMap::new(),
            signature_verifier: None,
            vdf_verifier: None,
            vdf_policy: VdfPolicy::Optional,
            vdf_policy_resolver: None,
            access_counter: 0,
            evicted_tombstones: HashMap::new(),
        }
    }

    /// Creates a new verifier with the given signature verifier.
    #[must_use]
    pub fn with_signature_verifier(signature_verifier: Box<dyn SignatureVerifier>) -> Self {
        Self {
            cells: HashMap::new(),
            signature_verifier: Some(signature_verifier),
            vdf_verifier: None,
            vdf_policy: VdfPolicy::Optional,
            vdf_policy_resolver: None,
            access_counter: 0,
            evicted_tombstones: HashMap::new(),
        }
    }

    /// Sets the signature verifier.
    pub fn set_signature_verifier(&mut self, verifier: Box<dyn SignatureVerifier>) {
        self.signature_verifier = Some(verifier);
    }

    /// Sets the VDF verifier.
    pub fn set_vdf_verifier(&mut self, verifier: Box<dyn VdfVerifier>) {
        self.vdf_verifier = Some(verifier);
    }

    /// Sets the per-link/per-cell VDF policy.
    pub const fn set_vdf_policy(&mut self, policy: VdfPolicy) {
        self.vdf_policy = policy;
    }

    /// Sets the per-key VDF policy resolver.
    pub fn set_vdf_policy_resolver(&mut self, resolver: Arc<dyn VdfPolicyResolver>) {
        self.vdf_policy_resolver = Some(resolver);
    }

    /// Clears the per-key VDF policy resolver.
    pub fn clear_vdf_policy_resolver(&mut self) {
        self.vdf_policy_resolver = None;
    }

    /// Returns whether a signature verifier is configured.
    #[must_use]
    pub fn has_signature_verifier(&self) -> bool {
        self.signature_verifier.is_some()
    }

    /// Returns whether a VDF verifier is configured.
    #[must_use]
    pub fn has_vdf_verifier(&self) -> bool {
        self.vdf_verifier.is_some()
    }

    /// Returns whether a VDF policy resolver is configured.
    #[must_use]
    pub fn has_vdf_policy_resolver(&self) -> bool {
        self.vdf_policy_resolver.is_some()
    }

    /// Returns the active VDF policy.
    #[must_use]
    pub const fn vdf_policy(&self) -> &VdfPolicy {
        &self.vdf_policy
    }

    /// Resolves the active VDF policy for a monotonicity key.
    #[must_use]
    fn effective_vdf_policy_for(&self, key: &MonotonicityKey) -> VdfPolicy {
        self.vdf_policy_resolver.as_ref().map_or_else(
            || self.vdf_policy.clone(),
            |resolver| resolver.resolve_policy(&key.cell_id),
        )
    }

    /// Increments and returns the next access counter value.
    const fn next_access_counter(&mut self) -> u64 {
        self.access_counter = self.access_counter.saturating_add(1);
        self.access_counter
    }

    /// Returns the number of tracked cell keys.
    #[must_use]
    pub fn tracked_issuer_count(&self) -> usize {
        self.cells.len()
    }

    /// Returns the number of entries for a specific `cell_id`.
    #[must_use]
    pub fn entries_for_cell_id(&self, cell_id: &str) -> usize {
        self.cells.keys().filter(|k| k.cell_id == cell_id).count()
    }

    /// Evicts the least recently used entry from the verifier state.
    ///
    /// The evicted key's tombstone is persisted in [`evicted_tombstones`] so
    /// replay-after-eviction and VDF continuity are preserved on
    /// re-introduction.
    /// Returns `true` if an entry was evicted, `false` if the map is empty.
    fn evict_lru(&mut self) -> bool {
        if let Some(lru_key) = self
            .cells
            .iter()
            .min_by_key(|(_, state)| state.last_access)
            .map(|(key, _)| key.clone())
        {
            if let Some(state) = self.cells.remove(&lru_key) {
                self.persist_eviction_tombstone(&lru_key, &state);
            }
            true
        } else {
            false
        }
    }

    /// Evicts the least recently used entry for a specific `cell_id`.
    ///
    /// The evicted key's tombstone is persisted in [`evicted_tombstones`] so
    /// replay-after-eviction and VDF continuity are preserved on
    /// re-introduction.
    /// Returns `true` if an entry was evicted.
    fn evict_lru_for_cell(&mut self, cell_id: &str) -> bool {
        if let Some(lru_key) = self
            .cells
            .iter()
            .filter(|(k, _)| k.cell_id == cell_id)
            .min_by_key(|(_, state)| state.last_access)
            .map(|(key, _)| key.clone())
        {
            if let Some(state) = self.cells.remove(&lru_key) {
                self.persist_eviction_tombstone(&lru_key, &state);
            }
            true
        } else {
            false
        }
    }

    /// Persists an eviction tombstone for an evicted key.
    ///
    /// If the tombstone map is at capacity, the entry with the lowest
    /// `last_epoch` is evicted to make room.
    fn persist_eviction_tombstone(&mut self, key: &MonotonicityKey, state: &CellState) {
        let tombstone = EvictionTombstone {
            last_epoch: state.epoch,
            last_root_hash: state.root_hash,
        };

        match self.evicted_tombstones.get(key).copied() {
            Some(existing) if existing.last_epoch > tombstone.last_epoch => {},
            _ => {
                self.evicted_tombstones.insert(key.clone(), tombstone);
            },
        }

        // Bound the tombstone map: evict the entry with the lowest epoch.
        if self.evicted_tombstones.len() > MAX_EVICTION_TOMBSTONES {
            if let Some(min_key) = self
                .evicted_tombstones
                .iter()
                .min_by_key(|(_, t)| t.last_epoch)
                .map(|(k, _)| k.clone())
            {
                self.evicted_tombstones.remove(&min_key);
            }
        }
    }

    /// Returns the number of eviction tombstones tracked.
    #[must_use]
    pub fn evicted_tombstone_count(&self) -> usize {
        self.evicted_tombstones.len()
    }

    /// Returns the number of evicted high-water marks tracked.
    ///
    /// Kept for backward compatibility. Equivalent to
    /// [`Self::evicted_tombstone_count`].
    #[must_use]
    pub fn evicted_high_water_count(&self) -> usize {
        self.evicted_tombstone_count()
    }

    /// Returns the last accepted epoch for the given issuer cell ID.
    ///
    /// This performs a linear scan to find entries matching the given
    /// `issuer_cell_id`. Returns `None` if no seal has been accepted
    /// from this issuer.
    #[must_use]
    pub fn last_epoch_for(&self, issuer_cell_id: &str) -> Option<u64> {
        self.cells
            .values()
            .filter(|s| s.issuer_cell_id == issuer_cell_id)
            .map(|s| s.epoch)
            .max()
    }

    /// Verifies and accepts an epoch seal, updating internal state.
    ///
    /// Verification order:
    /// 1. Validate seal fields (deserialization invariants).
    /// 2. Verify content hash (recompute canonical hash and compare).
    /// 3. Verify cryptographic signature (fail-closed when no verifier).
    /// 4. Verify optional VDF profile + policy (fail-closed on configured VDF
    ///    requirements).
    /// 5. Check monotonicity and equivocation.
    ///
    /// # Returns
    ///
    /// An [`EpochSealVerdict`] describing the outcome.
    pub fn verify(&mut self, seal: &EpochSealV1, risk_tier: RiskTier) -> EpochSealVerdict {
        // Step 1: Validate seal invariants (catches deserialization bypass).
        if let Err(e) = seal.validate() {
            return EpochSealVerdict {
                accepted: false,
                risk_tier,
                epoch_number: seal.epoch_number,
                issuer_cell_id: seal.issuer_cell_id.clone(),
                audit_event: EpochSealAuditEvent::ValidationFailed {
                    reason: e.to_string(),
                },
            };
        }

        // Step 2: Verify content hash (recompute and compare).
        let recomputed = seal.compute_content_hash();
        if !ct_eq_32(&recomputed, seal.content_hash()) {
            return EpochSealVerdict {
                accepted: false,
                risk_tier,
                epoch_number: seal.epoch_number,
                issuer_cell_id: seal.issuer_cell_id.clone(),
                audit_event: EpochSealAuditEvent::ValidationFailed {
                    reason: format!(
                        "content_hash mismatch: claimed {} != recomputed {}",
                        hex::encode(seal.content_hash),
                        hex::encode(recomputed),
                    ),
                },
            };
        }

        // Step 3: Verify signature (fail-closed when no verifier).
        if let Some(verdict) = self.verify_signature(seal, risk_tier) {
            return verdict;
        }

        // Step 4: Verify optional VDF profile + policy.
        if let Some(verdict) = self.verify_vdf(seal, risk_tier) {
            return verdict;
        }

        // Step 5: Monotonicity and equivocation checks.
        self.verify_monotonicity(seal, risk_tier)
    }

    /// Verifies the seal's cryptographic signature. Returns `Some(verdict)`
    /// on rejection, `None` on success.
    #[allow(clippy::option_if_let_else)]
    fn verify_signature(
        &self,
        seal: &EpochSealV1,
        risk_tier: RiskTier,
    ) -> Option<EpochSealVerdict> {
        let issuer = seal.issuer_cell_id();
        if let Some(verifier) = &self.signature_verifier {
            verifier
                .verify_seal_signature(seal)
                .err()
                .map(|e| EpochSealVerdict {
                    accepted: false,
                    risk_tier,
                    epoch_number: seal.epoch_number(),
                    issuer_cell_id: issuer.to_string(),
                    audit_event: EpochSealAuditEvent::SignatureRejected {
                        issuer_cell_id: issuer.to_string(),
                        epoch_number: seal.epoch_number(),
                        reason: e.reason,
                    },
                })
        } else {
            Some(EpochSealVerdict {
                accepted: false,
                risk_tier,
                epoch_number: seal.epoch_number(),
                issuer_cell_id: issuer.to_string(),
                audit_event: EpochSealAuditEvent::NoSignatureVerifier {
                    issuer_cell_id: issuer.to_string(),
                    epoch_number: seal.epoch_number(),
                },
            })
        }
    }

    /// Builds the monotonicity key used for state tracking and VDF challenge
    /// derivation.
    #[must_use]
    fn monotonicity_key_for(seal: &EpochSealV1) -> MonotonicityKey {
        MonotonicityKey {
            cell_id: seal.cell_id().to_string(),
            htf_time_envelope_ref: *seal.htf_time_envelope_ref(),
            quorum_anchor: *seal.quorum_anchor(),
        }
    }

    /// Verifies optional VDF policy and proof constraints.
    ///
    /// Returns `Some(verdict)` on rejection, `None` on success.
    #[allow(clippy::option_if_let_else)]
    #[allow(clippy::too_many_lines)]
    fn verify_vdf(&self, seal: &EpochSealV1, risk_tier: RiskTier) -> Option<EpochSealVerdict> {
        let issuer = seal.issuer_cell_id().to_string();
        let epoch_number = seal.epoch_number();
        let profile = seal.vdf_profile();
        let key = Self::monotonicity_key_for(seal);
        let tombstone = self.evicted_tombstones.get(&key).copied();

        // For same-or-lower epochs, defer to monotonicity handling. This
        // preserves rollback/equivocation semantics as the primary replay
        // defect signal.
        if let Some(state) = self.cells.get(&key) {
            if seal.epoch_number() <= state.epoch {
                return None;
            }
        } else if let Some(evicted) = tombstone {
            if seal.epoch_number() <= evicted.last_epoch {
                return None;
            }
        }

        let policy_min_difficulty = match self.effective_vdf_policy_for(&key) {
            VdfPolicy::Optional => None,
            VdfPolicy::Required { min_difficulty } => Some(min_difficulty),
        };

        if let Some(min_difficulty) = policy_min_difficulty {
            if min_difficulty < MIN_VDF_DIFFICULTY {
                return Some(EpochSealVerdict {
                    accepted: false,
                    risk_tier,
                    epoch_number,
                    issuer_cell_id: issuer.clone(),
                    audit_event: EpochSealAuditEvent::VdfDifficultyBelowPolicy {
                        issuer_cell_id: issuer,
                        epoch_number,
                        difficulty: 0,
                        min_difficulty,
                    },
                });
            }
        }

        match profile {
            None => {
                if let Some(min_difficulty) = policy_min_difficulty {
                    return Some(EpochSealVerdict {
                        accepted: false,
                        risk_tier,
                        epoch_number,
                        issuer_cell_id: issuer.clone(),
                        audit_event: EpochSealAuditEvent::VdfRequiredByPolicy {
                            issuer_cell_id: issuer,
                            epoch_number,
                            min_difficulty,
                        },
                    });
                }
                None
            },
            Some(vdf_profile) => {
                if let Some(min_difficulty) = policy_min_difficulty {
                    if vdf_profile.difficulty() < min_difficulty {
                        return Some(EpochSealVerdict {
                            accepted: false,
                            risk_tier,
                            epoch_number,
                            issuer_cell_id: issuer.clone(),
                            audit_event: EpochSealAuditEvent::VdfDifficultyBelowPolicy {
                                issuer_cell_id: issuer,
                                epoch_number,
                                difficulty: vdf_profile.difficulty(),
                                min_difficulty,
                            },
                        });
                    }
                }

                let prior_epoch_root = self
                    .cells
                    .get(&key)
                    .map(|state| state.root_hash)
                    .or_else(|| tombstone.map(|entry| entry.last_root_hash))
                    .unwrap_or(GENESIS_PRIOR_EPOCH_ROOT);
                let expected_input_hash = VdfProfileV1::derive_challenge(
                    seal.cell_id(),
                    &prior_epoch_root,
                    seal.quorum_anchor(),
                );

                if !ct_eq_32(&expected_input_hash, vdf_profile.input_hash()) {
                    return Some(EpochSealVerdict {
                        accepted: false,
                        risk_tier,
                        epoch_number,
                        issuer_cell_id: issuer.clone(),
                        audit_event: EpochSealAuditEvent::VdfInputHashMismatch {
                            issuer_cell_id: issuer,
                            epoch_number,
                        },
                    });
                }

                if let Some(verifier) = &self.vdf_verifier {
                    verifier
                        .verify_vdf(vdf_profile)
                        .err()
                        .map(|error| EpochSealVerdict {
                            accepted: false,
                            risk_tier,
                            epoch_number,
                            issuer_cell_id: issuer.clone(),
                            audit_event: EpochSealAuditEvent::VdfRejected {
                                issuer_cell_id: issuer,
                                epoch_number,
                                reason: error.to_string(),
                            },
                        })
                } else {
                    Some(EpochSealVerdict {
                        accepted: false,
                        risk_tier,
                        epoch_number,
                        issuer_cell_id: issuer.clone(),
                        audit_event: EpochSealAuditEvent::NoVdfVerifier {
                            issuer_cell_id: issuer,
                            epoch_number,
                        },
                    })
                }
            },
        }
    }

    /// Checks monotonicity and equivocation against per-cell state,
    /// updating state on acceptance.
    ///
    /// The key is `(cell_id, htf_time_envelope_ref, quorum_anchor)` per
    /// HSI section 1.9 rule 4.
    fn verify_monotonicity(&mut self, seal: &EpochSealV1, risk_tier: RiskTier) -> EpochSealVerdict {
        let issuer = seal.issuer_cell_id();
        let key = Self::monotonicity_key_for(seal);
        // Compute access counter before borrowing `cells` mutably to
        // satisfy the borrow checker.
        let access = self.next_access_counter();
        if let Some(state) = self.cells.get_mut(&key) {
            // Update LRU access counter on every access (even rejections
            // touch the entry, proving it is actively referenced).
            state.last_access = access;

            if seal.epoch_number() < state.epoch {
                return EpochSealVerdict {
                    accepted: false,
                    risk_tier,
                    epoch_number: seal.epoch_number(),
                    issuer_cell_id: issuer.to_string(),
                    audit_event: EpochSealAuditEvent::RollbackRejected {
                        issuer_cell_id: issuer.to_string(),
                        epoch_number: seal.epoch_number(),
                        last_accepted_epoch: state.epoch,
                    },
                };
            }
            if seal.epoch_number() == state.epoch {
                return verify_same_epoch(seal, state, risk_tier);
            }
            // Monotonically increasing: accept and update.
            let previous_epoch = state.epoch;
            state.epoch = seal.epoch_number();
            state.root_hash = *seal.sealed_root_hash();
            state.content_hash = *seal.content_hash();
            state.directory_epoch = seal.directory_epoch();
            state.receipt_batch_epoch = seal.receipt_batch_epoch();
            state.authority_seal_hash = *seal.authority_seal_hash();
            state.vdf_profile = seal.vdf_profile().cloned();
            state.issuer_cell_id = issuer.to_string();
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
            self.accept_first_seal(seal, &key, risk_tier)
        }
    }

    /// Accepts the first seal from a new cell key, evicting the oldest
    /// entry if the global or per-cell-id capacity is reached.
    ///
    /// Before accepting, checks the evicted high-water mark for this key.
    /// If the seal's epoch is not strictly greater than the evicted
    /// high-water mark, the seal is rejected (fail-closed) to prevent
    /// replay-after-eviction attacks. This check applies to Tier2+
    /// admissions; Tier0/Tier1 seals with no high-water mark or passing
    /// the check are accepted normally.
    fn accept_first_seal(
        &mut self,
        seal: &EpochSealV1,
        key: &MonotonicityKey,
        risk_tier: RiskTier,
    ) -> EpochSealVerdict {
        let issuer = seal.issuer_cell_id();

        // Check evicted tombstone for replay-after-eviction.
        // Fail-closed for Tier2+: reject if epoch <= evicted high-water.
        if let Some(tombstone) = self.evicted_tombstones.get(key).copied() {
            if seal.epoch_number() <= tombstone.last_epoch {
                return EpochSealVerdict {
                    accepted: false,
                    risk_tier,
                    epoch_number: seal.epoch_number(),
                    issuer_cell_id: issuer.to_string(),
                    audit_event: EpochSealAuditEvent::EvictionReplayRejected {
                        issuer_cell_id: issuer.to_string(),
                        epoch_number: seal.epoch_number(),
                        evicted_high_water_epoch: tombstone.last_epoch,
                    },
                };
            }
            // Seal passes high-water check: remove the high-water entry
            // since this key is being re-introduced with a valid epoch.
            self.evicted_tombstones.remove(key);
        }

        // Per-cell-id limit: prevent a single cell_id from exhausting
        // global capacity.
        if self.entries_for_cell_id(seal.cell_id()) >= MAX_ENTRIES_PER_CELL_ID {
            self.evict_lru_for_cell(seal.cell_id());
        }

        // Global capacity limit: evict LRU entry when full.
        if self.cells.len() >= MAX_TRACKED_ISSUERS {
            self.evict_lru();
        }

        let access = self.next_access_counter();
        self.cells.insert(
            key.clone(),
            CellState {
                epoch: seal.epoch_number(),
                root_hash: *seal.sealed_root_hash(),
                content_hash: *seal.content_hash(),
                directory_epoch: seal.directory_epoch(),
                receipt_batch_epoch: seal.receipt_batch_epoch(),
                authority_seal_hash: *seal.authority_seal_hash(),
                vdf_profile: seal.vdf_profile().cloned(),
                issuer_cell_id: issuer.to_string(),
                last_access: access,
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
                EpochSealAuditEvent::InvalidSeal { reason }
                | EpochSealAuditEvent::ValidationFailed { reason } => {
                    Err(EpochSealVerificationError::ValidationFailed {
                        reason: reason.clone(),
                    })
                },
                EpochSealAuditEvent::SignatureRejected {
                    issuer_cell_id,
                    reason,
                    ..
                } => Err(EpochSealVerificationError::SignatureRejected {
                    issuer_cell_id: issuer_cell_id.clone(),
                    reason: reason.clone(),
                }),
                EpochSealAuditEvent::NoSignatureVerifier { .. } => {
                    Err(EpochSealVerificationError::NoSignatureVerifier)
                },
                EpochSealAuditEvent::VdfRequiredByPolicy {
                    issuer_cell_id,
                    epoch_number,
                    min_difficulty,
                } => Err(EpochSealVerificationError::VdfRequiredByPolicy {
                    issuer_cell_id: issuer_cell_id.clone(),
                    epoch_number: *epoch_number,
                    min_difficulty: *min_difficulty,
                }),
                EpochSealAuditEvent::VdfDifficultyBelowPolicy {
                    issuer_cell_id,
                    epoch_number,
                    difficulty,
                    min_difficulty,
                } => Err(EpochSealVerificationError::VdfDifficultyBelowPolicy {
                    issuer_cell_id: issuer_cell_id.clone(),
                    epoch_number: *epoch_number,
                    difficulty: *difficulty,
                    min_difficulty: *min_difficulty,
                }),
                EpochSealAuditEvent::NoVdfVerifier { .. } => {
                    Err(EpochSealVerificationError::NoVdfVerifier)
                },
                EpochSealAuditEvent::VdfInputHashMismatch {
                    issuer_cell_id,
                    epoch_number,
                } => Err(EpochSealVerificationError::VdfInputHashMismatch {
                    issuer_cell_id: issuer_cell_id.clone(),
                    epoch_number: *epoch_number,
                }),
                EpochSealAuditEvent::VdfRejected {
                    issuer_cell_id,
                    reason,
                    ..
                } => Err(EpochSealVerificationError::VdfRejected {
                    issuer_cell_id: issuer_cell_id.clone(),
                    reason: reason.clone(),
                }),
                EpochSealAuditEvent::EvictionReplayRejected {
                    epoch_number,
                    evicted_high_water_epoch,
                    issuer_cell_id,
                } => Err(EpochSealVerificationError::EvictionReplay {
                    epoch_number: *epoch_number,
                    evicted_high_water_epoch: *evicted_high_water_epoch,
                    issuer_cell_id: issuer_cell_id.clone(),
                }),
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

    /// Verifies an epoch seal with integrated tier-based policy enforcement.
    ///
    /// This is the **recommended entry point** for admission-path seal
    /// verification. It combines the seal-required check with full
    /// verification, making it impossible to verify without also checking
    /// whether a seal is required for the given tier.
    ///
    /// When `seal` is `None` and the tier requires a seal, this returns
    /// an `Err(MissingSeal)`. When `seal` is `None` and the tier does NOT
    /// require a seal, it returns `Ok(None)`. When `seal` is `Some`, it
    /// performs full verification and returns `Ok(Some(verdict))` on
    /// acceptance or `Err(...)` on rejection.
    ///
    /// # Errors
    ///
    /// Returns [`EpochSealVerificationError`] on rejection.
    #[allow(clippy::option_if_let_else)]
    pub fn verify_with_policy(
        &mut self,
        seal: Option<&EpochSealV1>,
        risk_tier: RiskTier,
    ) -> Result<Option<EpochSealVerdict>, EpochSealVerificationError> {
        match seal {
            None => {
                if is_seal_required_tier(risk_tier) {
                    Err(EpochSealVerificationError::MissingSeal { risk_tier })
                } else {
                    Ok(None)
                }
            },
            Some(s) => self.verify_or_reject(s, risk_tier).map(Some),
        }
    }
}

/// Handles the same-epoch case: idempotent re-acceptance or equivocation
/// detection. Free function to avoid borrow-checker conflicts within
/// `verify_monotonicity`.
///
/// Identity for same-epoch idempotence requires ALL seal fields to match:
/// `sealed_root_hash`, `content_hash`, `directory_epoch`,
/// `receipt_batch_epoch`, `authority_seal_hash`, `vdf_profile`, and
/// `issuer_cell_id`.
/// Any field difference is equivocation (distinct seals at the same epoch).
///
/// Note: `cell_id`, `htf_time_envelope_ref`, and `quorum_anchor` are
/// already guaranteed to match because they form the monotonicity key.
fn verify_same_epoch(
    seal: &EpochSealV1,
    state: &CellState,
    risk_tier: RiskTier,
) -> EpochSealVerdict {
    let issuer = seal.issuer_cell_id();
    let all_match = ct_eq_32(seal.sealed_root_hash(), &state.root_hash)
        && ct_eq_32(seal.content_hash(), &state.content_hash)
        && seal.directory_epoch() == state.directory_epoch
        && seal.receipt_batch_epoch() == state.receipt_batch_epoch
        && ct_eq_32(seal.authority_seal_hash(), &state.authority_seal_hash)
        && seal.vdf_profile() == state.vdf_profile.as_ref()
        && seal.issuer_cell_id() == state.issuer_cell_id;

    if all_match {
        // Idempotent re-acceptance of identical seal.
        EpochSealVerdict {
            accepted: true,
            risk_tier,
            epoch_number: seal.epoch_number(),
            issuer_cell_id: issuer.to_string(),
            audit_event: EpochSealAuditEvent::Accepted {
                issuer_cell_id: issuer.to_string(),
                epoch_number: seal.epoch_number(),
                previous_epoch: state.epoch,
            },
        }
    } else {
        // Equivocation: same epoch, different field(s).
        EpochSealVerdict {
            accepted: false,
            risk_tier,
            epoch_number: seal.epoch_number(),
            issuer_cell_id: issuer.to_string(),
            audit_event: EpochSealAuditEvent::EquivocationDetected {
                issuer_cell_id: issuer.to_string(),
                epoch_number: seal.epoch_number(),
                existing_root_hash: state.root_hash,
                conflicting_root_hash: *seal.sealed_root_hash(),
            },
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
#[allow(clippy::cast_possible_truncation)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::htf::vdf_profile::{
        DefaultVdfVerifier, MAX_VDF_DIFFICULTY, MAX_VDF_OUTPUT_LENGTH, SlothV1Verifier,
        VdfProfileV1, VdfScheme,
    };

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

    fn test_anchor_hash(seed: u8) -> [u8; 32] {
        let mut h = [seed; 32];
        // Ensure non-zero by ORing the first byte with a nonzero value
        // when seed is zero (test helpers should never produce zero hashes).
        h[0] |= 0x01;
        h
    }

    /// Fixed anchor hashes for `make_seal` so all seals from the same
    /// `issuer` share the same monotonicity key
    /// `(cell_id, htf_time_envelope_ref, quorum_anchor)`.
    fn fixed_htf_ref() -> [u8; 32] {
        test_anchor_hash(0xA0)
    }
    fn fixed_quorum() -> [u8; 32] {
        test_anchor_hash(0xB0)
    }
    fn fixed_auth() -> [u8; 32] {
        test_anchor_hash(0xC0)
    }

    fn make_vdf_profile(
        cell_id: &str,
        prior_epoch_root: [u8; 32],
        quorum_anchor: [u8; 32],
        difficulty: u64,
    ) -> VdfProfileV1 {
        let input_hash = VdfProfileV1::derive_challenge(cell_id, &prior_epoch_root, &quorum_anchor);
        let output = SlothV1Verifier::evaluate(&input_hash, difficulty).to_vec();
        VdfProfileV1::new(VdfScheme::SlothV1, input_hash, output, difficulty)
            .expect("valid vdf profile")
    }

    /// Builds a seal whose `content_hash` equals `compute_content_hash()`.
    ///
    /// All seals from the same `issuer` share the same monotonicity key
    /// `(cell_id, htf_time_envelope_ref, quorum_anchor)` so that
    /// rollback/equivocation tests work correctly.
    fn make_seal(epoch: u64, issuer: &str, root_seed: u8) -> EpochSealV1 {
        make_seal_full(
            epoch,
            issuer,
            test_root_hash(root_seed),
            issuer,
            epoch,
            epoch,
            fixed_htf_ref(),
            fixed_quorum(),
            fixed_auth(),
        )
    }

    /// Builds a seal with explicit field control, `content_hash` set to
    /// `compute_content_hash()`.
    #[allow(clippy::too_many_arguments)]
    fn make_seal_full(
        epoch: u64,
        issuer: &str,
        root_hash: [u8; 32],
        cell_id: &str,
        directory_epoch: u64,
        receipt_batch_epoch: u64,
        htf_time_envelope_ref: [u8; 32],
        quorum_anchor: [u8; 32],
        authority_seal_hash: [u8; 32],
    ) -> EpochSealV1 {
        // First pass: build with placeholder content hash to compute the
        // correct content hash. `compute_content_hash()` does NOT include
        // `content_hash` in its preimage, so the result is stable.
        let placeholder = EpochSealV1::new(
            epoch,
            root_hash,
            issuer,
            test_signature(),
            [0xFF; 32], // placeholder (will be replaced)
            cell_id,
            directory_epoch,
            receipt_batch_epoch,
            htf_time_envelope_ref,
            quorum_anchor,
            None,
            authority_seal_hash,
        )
        .expect("valid seal (placeholder pass)");

        let content_hash = placeholder.compute_content_hash();
        EpochSealV1::new(
            epoch,
            root_hash,
            issuer,
            test_signature(),
            content_hash,
            cell_id,
            directory_epoch,
            receipt_batch_epoch,
            htf_time_envelope_ref,
            quorum_anchor,
            None,
            authority_seal_hash,
        )
        .expect("valid seal (final pass)")
    }

    /// Helper to build a seal with an explicit content hash (for tests
    /// that bypass the verifier or test content hash mismatch).
    /// The `content_hash` will NOT match `compute_content_hash()`.
    fn make_seal_with_content(
        epoch: u64,
        issuer: &str,
        root_seed: u8,
        content_seed: u8,
    ) -> EpochSealV1 {
        EpochSealV1::new(
            epoch,
            test_root_hash(root_seed),
            issuer,
            test_signature(),
            test_content_hash(content_seed),
            issuer,
            epoch,
            epoch,
            fixed_htf_ref(),
            fixed_quorum(),
            None,
            fixed_auth(),
        )
        .expect("valid seal")
    }

    #[allow(clippy::too_many_arguments)]
    fn make_seal_full_with_vdf(
        epoch: u64,
        issuer: &str,
        root_hash: [u8; 32],
        cell_id: &str,
        directory_epoch: u64,
        receipt_batch_epoch: u64,
        htf_time_envelope_ref: [u8; 32],
        quorum_anchor: [u8; 32],
        authority_seal_hash: [u8; 32],
        prior_epoch_root: [u8; 32],
        vdf_difficulty: u64,
    ) -> EpochSealV1 {
        let vdf_profile =
            make_vdf_profile(cell_id, prior_epoch_root, quorum_anchor, vdf_difficulty);

        let placeholder = EpochSealV1::new(
            epoch,
            root_hash,
            issuer,
            test_signature(),
            [0xEE; 32], // placeholder content hash
            cell_id,
            directory_epoch,
            receipt_batch_epoch,
            htf_time_envelope_ref,
            quorum_anchor,
            Some(vdf_profile.clone()),
            authority_seal_hash,
        )
        .expect("valid seal (vdf placeholder pass)");

        let content_hash = placeholder.compute_content_hash();
        EpochSealV1::new(
            epoch,
            root_hash,
            issuer,
            test_signature(),
            content_hash,
            cell_id,
            directory_epoch,
            receipt_batch_epoch,
            htf_time_envelope_ref,
            quorum_anchor,
            Some(vdf_profile),
            authority_seal_hash,
        )
        .expect("valid seal (vdf final pass)")
    }

    /// A test signature verifier that accepts all seals.
    #[derive(Debug)]
    struct AcceptAllVerifier;

    impl SignatureVerifier for AcceptAllVerifier {
        fn verify_seal_signature(
            &self,
            _seal: &EpochSealV1,
        ) -> Result<(), SignatureVerificationError> {
            Ok(())
        }
    }

    /// A test signature verifier that rejects all seals.
    #[derive(Debug)]
    struct RejectAllVerifier {
        reason: String,
    }

    impl RejectAllVerifier {
        fn new(reason: &str) -> Self {
            Self {
                reason: reason.to_string(),
            }
        }
    }

    impl SignatureVerifier for RejectAllVerifier {
        fn verify_seal_signature(
            &self,
            _seal: &EpochSealV1,
        ) -> Result<(), SignatureVerificationError> {
            Err(SignatureVerificationError {
                reason: self.reason.clone(),
            })
        }
    }

    /// Test resolver for per-cell VDF policy selection.
    #[derive(Debug)]
    struct StaticPolicyResolver {
        default_policy: VdfPolicy,
        by_cell: HashMap<String, VdfPolicy>,
    }

    impl StaticPolicyResolver {
        fn new(default_policy: VdfPolicy, by_cell: HashMap<String, VdfPolicy>) -> Self {
            Self {
                default_policy,
                by_cell,
            }
        }
    }

    impl VdfPolicyResolver for StaticPolicyResolver {
        fn resolve_policy(&self, key: &str) -> VdfPolicy {
            self.by_cell
                .get(key)
                .cloned()
                .unwrap_or_else(|| self.default_policy.clone())
        }
    }

    /// Creates a verifier with the accept-all test signature verifier.
    fn test_verifier() -> EpochSealVerifier {
        EpochSealVerifier::with_signature_verifier(Box::new(AcceptAllVerifier))
    }

    fn test_verifier_with_vdf(policy: VdfPolicy) -> EpochSealVerifier {
        let mut verifier = test_verifier();
        verifier.set_vdf_verifier(Box::new(DefaultVdfVerifier::default()));
        verifier.set_vdf_policy(policy);
        verifier
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
            "cell-alpha",
            10,
            20,
            test_anchor_hash(0x50),
            test_anchor_hash(0x60),
            None,
            test_anchor_hash(0x70),
        )
        .unwrap();

        assert_eq!(seal.epoch_number(), 1);
        assert_eq!(seal.sealed_root_hash(), &test_root_hash(0x42));
        assert_eq!(seal.issuer_cell_id(), "cell-alpha");
        assert_eq!(seal.signature(), &test_signature());
        assert_eq!(seal.content_hash(), &test_content_hash(0x43));
        assert_eq!(seal.cell_id(), "cell-alpha");
        assert_eq!(seal.directory_epoch(), 10);
        assert_eq!(seal.receipt_batch_epoch(), 20);
        assert_eq!(seal.htf_time_envelope_ref(), &test_anchor_hash(0x50));
        assert_eq!(seal.quorum_anchor(), &test_anchor_hash(0x60));
        assert_eq!(seal.authority_seal_hash(), &test_anchor_hash(0x70));
    }

    /// Helper to construct a seal with all default anchor fields, customizing
    /// only the fields under test.
    fn new_seal_with_defaults(
        epoch: u64,
        root: [u8; 32],
        issuer: &str,
        content: [u8; 32],
    ) -> Result<EpochSealV1, EpochSealError> {
        EpochSealV1::new(
            epoch,
            root,
            issuer,
            test_signature(),
            content,
            "cell-default",
            1,
            1,
            test_anchor_hash(0xA0),
            test_anchor_hash(0xB0),
            None,
            test_anchor_hash(0xC0),
        )
    }

    #[test]
    fn seal_rejects_zero_epoch() {
        let result = new_seal_with_defaults(
            0,
            test_root_hash(0x42),
            "cell-alpha",
            test_content_hash(0x43),
        );
        assert!(matches!(result, Err(EpochSealError::ZeroEpoch)));
    }

    #[test]
    fn seal_rejects_zero_root_hash() {
        let result = new_seal_with_defaults(1, [0u8; 32], "cell-alpha", test_content_hash(0x43));
        assert!(matches!(result, Err(EpochSealError::ZeroRootHash)));
    }

    #[test]
    fn seal_rejects_zero_content_hash() {
        let result = new_seal_with_defaults(1, test_root_hash(0x42), "cell-alpha", [0u8; 32]);
        assert!(matches!(result, Err(EpochSealError::ZeroContentHash)));
    }

    #[test]
    fn seal_rejects_empty_issuer() {
        let result = new_seal_with_defaults(1, test_root_hash(0x42), "", test_content_hash(0x43));
        assert!(matches!(result, Err(EpochSealError::EmptyIssuerId)));
    }

    #[test]
    fn seal_rejects_oversized_issuer() {
        let long_id = "x".repeat(MAX_SEAL_STRING_LENGTH + 1);
        let result =
            new_seal_with_defaults(1, test_root_hash(0x42), &long_id, test_content_hash(0x43));
        assert!(matches!(
            result,
            Err(EpochSealError::IssuerIdTooLong { .. })
        ));
    }

    #[test]
    fn seal_rejects_empty_cell_id() {
        let result = EpochSealV1::new(
            1,
            test_root_hash(0x42),
            "cell-alpha",
            test_signature(),
            test_content_hash(0x43),
            "",
            1,
            1,
            test_anchor_hash(0xA0),
            test_anchor_hash(0xB0),
            None,
            test_anchor_hash(0xC0),
        );
        assert!(matches!(result, Err(EpochSealError::EmptyCellId)));
    }

    #[test]
    fn seal_rejects_zero_time_envelope_ref() {
        let result = EpochSealV1::new(
            1,
            test_root_hash(0x42),
            "cell-alpha",
            test_signature(),
            test_content_hash(0x43),
            "cell-alpha",
            1,
            1,
            [0u8; 32], // zero time envelope ref
            test_anchor_hash(0xB0),
            None,
            test_anchor_hash(0xC0),
        );
        assert!(matches!(result, Err(EpochSealError::ZeroTimeEnvelopeRef)));
    }

    #[test]
    fn seal_rejects_zero_quorum_anchor() {
        let result = EpochSealV1::new(
            1,
            test_root_hash(0x42),
            "cell-alpha",
            test_signature(),
            test_content_hash(0x43),
            "cell-alpha",
            1,
            1,
            test_anchor_hash(0xA0),
            [0u8; 32], // zero quorum anchor
            None,
            test_anchor_hash(0xC0),
        );
        assert!(matches!(result, Err(EpochSealError::ZeroQuorumAnchor)));
    }

    #[test]
    fn seal_rejects_zero_authority_seal_hash() {
        let result = EpochSealV1::new(
            1,
            test_root_hash(0x42),
            "cell-alpha",
            test_signature(),
            test_content_hash(0x43),
            "cell-alpha",
            1,
            1,
            test_anchor_hash(0xA0),
            test_anchor_hash(0xB0),
            None,
            [0u8; 32], // zero authority seal hash
        );
        assert!(matches!(result, Err(EpochSealError::ZeroAuthoritySealHash)));
    }

    #[test]
    fn seal_display() {
        let seal = make_seal(5, "cell-alpha", 0x42);
        let display = seal.to_string();
        assert!(display.contains("epoch=5"));
        assert!(display.contains("cell-alpha"));
        assert!(display.contains("content="));
        assert!(display.contains("dir_epoch=5"));
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
                "cell-alpha",
                10,
                20,
                test_anchor_hash(0xA1),
                test_anchor_hash(0xB1),
                None,
                test_anchor_hash(0xC1),
            )
            .unwrap();
        assert_eq!(seal1.epoch_number(), 1);
        assert_eq!(issuer.last_epoch(), 1);

        let seal2 = issuer
            .issue(
                test_root_hash(0x22),
                test_signature(),
                test_content_hash(0x32),
                "cell-alpha",
                11,
                21,
                test_anchor_hash(0xA2),
                test_anchor_hash(0xB2),
                None,
                test_anchor_hash(0xC2),
            )
            .unwrap();
        assert_eq!(seal2.epoch_number(), 2);
        assert_eq!(issuer.last_epoch(), 2);

        let seal3 = issuer
            .issue(
                test_root_hash(0x33),
                test_signature(),
                test_content_hash(0x43),
                "cell-alpha",
                12,
                22,
                test_anchor_hash(0xA3),
                test_anchor_hash(0xB3),
                None,
                test_anchor_hash(0xC3),
            )
            .unwrap();
        assert_eq!(seal3.epoch_number(), 3);
        assert_eq!(issuer.last_epoch(), 3);
    }

    #[test]
    fn issuer_rejects_zero_root_hash() {
        let mut issuer = EpochSealIssuer::new("cell-alpha").unwrap();
        let result = issuer.issue(
            [0u8; 32],
            test_signature(),
            test_content_hash(0x21),
            "cell-alpha",
            1,
            1,
            test_anchor_hash(0xA0),
            test_anchor_hash(0xB0),
            None,
            test_anchor_hash(0xC0),
        );
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
        let mut verifier = test_verifier();
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
        let mut verifier = test_verifier();
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
        let mut verifier = test_verifier();

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
        let mut verifier = test_verifier();

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
        let mut verifier = test_verifier();

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
        let mut verifier = test_verifier();

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
        let mut verifier = test_verifier();

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
        let mut verifier = test_verifier();

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
        let verifier = test_verifier();
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
    // verify_with_policy Tests (integrated seal-required check)
    // =========================================================================

    #[test]
    fn verify_with_policy_rejects_missing_seal_at_tier2() {
        let mut verifier = test_verifier();
        let result = verifier.verify_with_policy(None, RiskTier::Tier2);
        assert!(
            matches!(result, Err(EpochSealVerificationError::MissingSeal { .. })),
            "missing seal at Tier2 must be rejected"
        );
    }

    #[test]
    fn verify_with_policy_rejects_missing_seal_at_tier3() {
        let mut verifier = test_verifier();
        let result = verifier.verify_with_policy(None, RiskTier::Tier3);
        assert!(
            matches!(result, Err(EpochSealVerificationError::MissingSeal { .. })),
            "missing seal at Tier3 must be rejected"
        );
    }

    #[test]
    fn verify_with_policy_accepts_missing_seal_at_tier0() {
        let mut verifier = test_verifier();
        let result = verifier.verify_with_policy(None, RiskTier::Tier0);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none(), "Tier0 should accept None seal");
    }

    #[test]
    fn verify_with_policy_accepts_missing_seal_at_tier1() {
        let mut verifier = test_verifier();
        let result = verifier.verify_with_policy(None, RiskTier::Tier1);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none(), "Tier1 should accept None seal");
    }

    #[test]
    fn verify_with_policy_accepts_valid_seal_at_tier2() {
        let mut verifier = test_verifier();
        let seal = make_seal(1, "cell-alpha", 0x11);
        let result = verifier.verify_with_policy(Some(&seal), RiskTier::Tier2);
        assert!(result.is_ok());
        let verdict = result.unwrap().expect("should return Some verdict");
        assert!(verdict.accepted, "valid seal at Tier2 must be accepted");
    }

    #[test]
    fn verify_with_policy_rejects_rollback_at_tier3() {
        let mut verifier = test_verifier();
        let seal1 = make_seal(5, "cell-alpha", 0x11);
        verifier.verify(&seal1, RiskTier::Tier3);

        let seal2 = make_seal(3, "cell-alpha", 0x22);
        let result = verifier.verify_with_policy(Some(&seal2), RiskTier::Tier3);
        assert!(
            matches!(result, Err(EpochSealVerificationError::Rollback { .. })),
            "rollback via verify_with_policy must be rejected"
        );
    }

    // =========================================================================
    // verify_or_reject Tests
    // =========================================================================

    #[test]
    fn verify_or_reject_accepted() {
        let mut verifier = test_verifier();
        let seal = make_seal(1, "cell-alpha", 0x11);
        let result = verifier.verify_or_reject(&seal, RiskTier::Tier2);
        assert!(result.is_ok());
        assert!(result.unwrap().accepted);
    }

    #[test]
    fn verify_or_reject_rollback_error() {
        let mut verifier = test_verifier();
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
        let mut verifier = test_verifier();
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
        assert!(
            EpochSealError::EmptyCellId
                .to_string()
                .contains("non-empty")
        );
        assert!(
            EpochSealError::CellIdTooLong {
                length: 5000,
                max: 4096,
            }
            .to_string()
            .contains("5000")
        );
        assert!(
            EpochSealError::ZeroTimeEnvelopeRef
                .to_string()
                .contains("time envelope")
        );
        assert!(
            EpochSealError::ZeroQuorumAnchor
                .to_string()
                .contains("quorum anchor")
        );
        assert!(
            EpochSealError::ZeroAuthoritySealHash
                .to_string()
                .contains("authority seal hash")
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
    // DoS Protection: LRU Eviction Tests
    // =========================================================================

    #[test]
    fn verifier_evicts_lru_when_max_issuers_reached() {
        let mut verifier = test_verifier();

        // Fill up to the limit.
        for i in 0..MAX_TRACKED_ISSUERS {
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

        // The next new issuer should be accepted via LRU eviction
        // (not rejected). The oldest entry is evicted to make room.
        let seal = make_seal(1, "cell-overflow", 0xFE);
        let verdict = verifier.verify(&seal, RiskTier::Tier2);
        assert!(
            verdict.accepted,
            "new issuer should be accepted after LRU eviction"
        );

        // Total count must not exceed the max.
        assert_eq!(verifier.tracked_issuer_count(), MAX_TRACKED_ISSUERS);

        // An existing (recently accessed) issuer should still work.
        // cell-overflow was just inserted so it is recent.
        let seal2 = make_seal(2, "cell-overflow", 0xFD);
        let verdict2 = verifier.verify(&seal2, RiskTier::Tier2);
        assert!(
            verdict2.accepted,
            "recently inserted issuer should still accept new epochs"
        );
    }

    #[test]
    fn verifier_eviction_does_not_panic_on_capacity_exhaustion() {
        let mut verifier = test_verifier();

        // Fill and then overflow repeatedly, proving no panics and
        // graceful eviction across many cycles.
        for i in 0..(MAX_TRACKED_ISSUERS + 100) {
            #[allow(clippy::cast_possible_truncation)]
            let root_seed = ((i % 239) + 1) as u8;
            let seal = make_seal(1, &format!("evict-cell-{i}"), root_seed);
            let verdict = verifier.verify(&seal, RiskTier::Tier2);
            assert!(
                verdict.accepted,
                "cell {i} should always be accepted (eviction provides capacity)"
            );
        }

        // Must never exceed the cap.
        assert!(
            verifier.tracked_issuer_count() <= MAX_TRACKED_ISSUERS,
            "tracked count must not exceed MAX_TRACKED_ISSUERS"
        );
    }

    #[test]
    fn verifier_per_cell_id_limit_prevents_single_cell_exhaustion() {
        let mut verifier = test_verifier();

        // Insert MAX_ENTRIES_PER_CELL_ID entries for a single cell_id
        // (with distinct htf_time_envelope_ref/quorum_anchor combos).
        for i in 0..MAX_ENTRIES_PER_CELL_ID {
            #[allow(clippy::cast_possible_truncation)]
            let htf_seed = ((i % 254) + 1) as u8;
            let seal = make_seal_full(
                1,
                "issuer-greedy",
                test_root_hash(htf_seed),
                "greedy-cell",
                1,
                1,
                test_anchor_hash(htf_seed),
                test_anchor_hash(0xB0),
                test_anchor_hash(0xC0),
            );
            let verdict = verifier.verify(&seal, RiskTier::Tier2);
            assert!(verdict.accepted, "entry {i} should be accepted");
        }

        assert_eq!(
            verifier.entries_for_cell_id("greedy-cell"),
            MAX_ENTRIES_PER_CELL_ID
        );

        // One more entry for the same cell_id triggers per-cell eviction.
        let seal_over = make_seal_full(
            1,
            "issuer-greedy",
            test_root_hash(0xFE),
            "greedy-cell",
            1,
            1,
            test_anchor_hash(0xFE),
            test_anchor_hash(0xB0),
            test_anchor_hash(0xC0),
        );
        let verdict = verifier.verify(&seal_over, RiskTier::Tier2);
        assert!(
            verdict.accepted,
            "should accept after per-cell LRU eviction"
        );
        assert_eq!(
            verifier.entries_for_cell_id("greedy-cell"),
            MAX_ENTRIES_PER_CELL_ID,
            "per-cell count must stay at the limit"
        );

        // Entries from other cell_ids should not have been evicted.
        // Add one for a different cell_id and confirm it works.
        let seal_other = make_seal(1, "other-cell", 0x11);
        let verdict_other = verifier.verify(&seal_other, RiskTier::Tier2);
        assert!(
            verdict_other.accepted,
            "other cell_id should not be affected by per-cell eviction"
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

        /// Builds a seal with valid `content_hash` from arbitrary fields.
        fn make_verified_seal(
            epoch: u64,
            root: [u8; 32],
            issuer: &str,
            cell_id: &str,
        ) -> EpochSealV1 {
            make_seal_full(
                epoch,
                issuer,
                root,
                cell_id,
                epoch,
                epoch,
                super::test_anchor_hash(0xA0),
                super::test_anchor_hash(0xB0),
                super::test_anchor_hash(0xC0),
            )
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

                let mut verifier = test_verifier();
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

                let mut verifier = test_verifier();
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
            ) {
                prop_assume!(root_a != root_b);

                let seal_a = make_verified_seal(epoch, root_a, "prop-issuer", "prop-cell");
                let seal_b = make_verified_seal(epoch, root_b, "prop-issuer", "prop-cell");

                let mut verifier = test_verifier();
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
            ) {
                let seal = make_verified_seal(epoch, root, "prop-issuer", "prop-cell");

                let mut verifier = test_verifier();
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
                let mut verifier = test_verifier();

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

    // =========================================================================
    // Signature Verification Tests (BLOCKER 1 regression)
    // =========================================================================

    #[test]
    fn verifier_without_signature_verifier_rejects_all_seals() {
        let mut verifier = EpochSealVerifier::new(); // No signature verifier
        let seal = make_seal(1, "cell-alpha", 0x11);
        let verdict = verifier.verify(&seal, RiskTier::Tier2);

        assert!(
            !verdict.accepted,
            "seal must be rejected without signature verifier"
        );
        assert!(matches!(
            verdict.audit_event,
            EpochSealAuditEvent::NoSignatureVerifier { .. }
        ));
    }

    #[test]
    fn verifier_without_signature_verifier_verify_or_reject_error() {
        let mut verifier = EpochSealVerifier::new();
        let seal = make_seal(1, "cell-alpha", 0x11);
        let result = verifier.verify_or_reject(&seal, RiskTier::Tier2);
        assert!(matches!(
            result,
            Err(EpochSealVerificationError::NoSignatureVerifier)
        ));
    }

    #[test]
    fn verifier_with_reject_all_rejects_forged_seal() {
        let mut verifier = EpochSealVerifier::with_signature_verifier(Box::new(
            RejectAllVerifier::new("forged signature"),
        ));
        let seal = make_seal(1, "cell-alpha", 0x11);
        let verdict = verifier.verify(&seal, RiskTier::Tier2);

        assert!(!verdict.accepted, "forged seal must be rejected");
        assert!(matches!(
            verdict.audit_event,
            EpochSealAuditEvent::SignatureRejected { ref reason, .. }
            if reason == "forged signature"
        ));
    }

    #[test]
    fn verifier_with_reject_all_verify_or_reject_error() {
        let mut verifier = EpochSealVerifier::with_signature_verifier(Box::new(
            RejectAllVerifier::new("unknown issuer"),
        ));
        let seal = make_seal(1, "cell-alpha", 0x11);
        let result = verifier.verify_or_reject(&seal, RiskTier::Tier2);
        assert!(matches!(
            result,
            Err(EpochSealVerificationError::SignatureRejected {
                ref reason,
                ..
            }) if reason == "unknown issuer"
        ));
    }

    #[test]
    fn verifier_with_accept_all_accepts_valid_seal() {
        let mut verifier = test_verifier();
        let seal = make_seal(1, "cell-alpha", 0x11);
        let verdict = verifier.verify(&seal, RiskTier::Tier2);
        assert!(verdict.accepted);
    }

    #[test]
    fn set_signature_verifier_enables_acceptance() {
        let mut verifier = EpochSealVerifier::new();
        let seal = make_seal(1, "cell-alpha", 0x11);

        // Without verifier: rejected.
        let verdict = verifier.verify(&seal, RiskTier::Tier2);
        assert!(!verdict.accepted);

        // Set verifier: now accepted.
        verifier.set_signature_verifier(Box::new(AcceptAllVerifier));
        let verdict = verifier.verify(&seal, RiskTier::Tier2);
        assert!(verdict.accepted);
    }

    #[test]
    fn has_signature_verifier_reports_correctly() {
        let verifier = EpochSealVerifier::new();
        assert!(!verifier.has_signature_verifier());

        let verifier = test_verifier();
        assert!(verifier.has_signature_verifier());
    }

    // =========================================================================
    // Deserialization Bypass / Validation Tests (BLOCKER 2 regression)
    // =========================================================================

    #[test]
    fn validate_rejects_zero_epoch() {
        // Manually construct a seal bypassing the constructor via serde.
        let valid_seal = make_seal(1, "cell-alpha", 0x11);
        let mut json: serde_json::Value = serde_json::to_value(&valid_seal).unwrap();
        json["epoch_number"] = serde_json::Value::from(0);
        let bad_seal: EpochSealV1 = serde_json::from_value(json).unwrap();
        assert!(matches!(
            bad_seal.validate(),
            Err(EpochSealError::ZeroEpoch)
        ));
    }

    #[test]
    fn validate_rejects_zero_root_hash() {
        let valid_seal = make_seal(1, "cell-alpha", 0x11);
        let mut json: serde_json::Value = serde_json::to_value(&valid_seal).unwrap();
        json["sealed_root_hash"] = serde_json::to_value(vec![0u8; 32]).unwrap();
        let bad_seal: EpochSealV1 = serde_json::from_value(json).unwrap();
        assert!(matches!(
            bad_seal.validate(),
            Err(EpochSealError::ZeroRootHash)
        ));
    }

    #[test]
    fn validate_rejects_empty_issuer() {
        let valid_seal = make_seal(1, "cell-alpha", 0x11);
        let mut json: serde_json::Value = serde_json::to_value(&valid_seal).unwrap();
        json["issuer_cell_id"] = serde_json::Value::from("");
        let bad_seal: EpochSealV1 = serde_json::from_value(json).unwrap();
        assert!(matches!(
            bad_seal.validate(),
            Err(EpochSealError::EmptyIssuerId)
        ));
    }

    #[test]
    fn validate_rejects_zero_content_hash() {
        let valid_seal = make_seal(1, "cell-alpha", 0x11);
        let mut json: serde_json::Value = serde_json::to_value(&valid_seal).unwrap();
        json["content_hash"] = serde_json::to_value(vec![0u8; 32]).unwrap();
        let bad_seal: EpochSealV1 = serde_json::from_value(json).unwrap();
        assert!(matches!(
            bad_seal.validate(),
            Err(EpochSealError::ZeroContentHash)
        ));
    }

    #[test]
    fn verifier_rejects_deserialized_seal_with_zero_epoch() {
        let mut verifier = test_verifier();
        let valid_seal = make_seal(1, "cell-alpha", 0x11);
        let mut json: serde_json::Value = serde_json::to_value(&valid_seal).unwrap();
        json["epoch_number"] = serde_json::Value::from(0);
        let bad_seal: EpochSealV1 = serde_json::from_value(json).unwrap();

        let verdict = verifier.verify(&bad_seal, RiskTier::Tier2);
        assert!(
            !verdict.accepted,
            "seal with epoch=0 must be rejected by verifier"
        );
        assert!(matches!(
            verdict.audit_event,
            EpochSealAuditEvent::ValidationFailed { .. }
        ));
    }

    #[test]
    fn verifier_rejects_deserialized_seal_with_empty_issuer() {
        let mut verifier = test_verifier();
        let valid_seal = make_seal(1, "cell-alpha", 0x11);
        let mut json: serde_json::Value = serde_json::to_value(&valid_seal).unwrap();
        json["issuer_cell_id"] = serde_json::Value::from("");
        let bad_seal: EpochSealV1 = serde_json::from_value(json).unwrap();

        let result = verifier.verify_or_reject(&bad_seal, RiskTier::Tier2);
        assert!(matches!(
            result,
            Err(EpochSealVerificationError::ValidationFailed { .. })
        ));
    }

    // =========================================================================
    // New Error Display Tests
    // =========================================================================

    #[test]
    fn new_error_variants_display() {
        let err = EpochSealVerificationError::SignatureRejected {
            issuer_cell_id: "cell-alpha".to_string(),
            reason: "bad sig".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("signature verification failed"));
        assert!(msg.contains("cell-alpha"));

        let err = EpochSealVerificationError::NoSignatureVerifier;
        let msg = err.to_string();
        assert!(msg.contains("no signature verifier"));
        assert!(msg.contains("fail-closed"));

        let err = EpochSealVerificationError::ValidationFailed {
            reason: "zero epoch".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("validation failed"));
        assert!(msg.contains("zero epoch"));
    }

    #[test]
    fn new_audit_event_kind_labels() {
        assert_eq!(
            EpochSealAuditEvent::SignatureRejected {
                issuer_cell_id: "x".to_string(),
                epoch_number: 1,
                reason: "bad".to_string(),
            }
            .kind(),
            "epoch_seal.signature_rejected"
        );
        assert_eq!(
            EpochSealAuditEvent::NoSignatureVerifier {
                issuer_cell_id: "x".to_string(),
                epoch_number: 1,
            }
            .kind(),
            "epoch_seal.no_signature_verifier"
        );
        assert_eq!(
            EpochSealAuditEvent::ValidationFailed {
                reason: "bad".to_string(),
            }
            .kind(),
            "epoch_seal.validation_failed"
        );
    }

    #[test]
    fn signature_verification_error_display() {
        let err = SignatureVerificationError {
            reason: "invalid key".to_string(),
        };
        assert!(err.to_string().contains("invalid key"));
    }

    // =========================================================================
    // BLOCKER 2 regression: content_hash in canonical binding + equivocation
    // =========================================================================

    #[test]
    fn canonical_hash_includes_content_hash() {
        // Two seals that differ ONLY in content_hash must produce
        // different canonical hashes.
        let seal_a = make_seal_with_content(5, "cell-alpha", 0x11, 0xAA);
        let seal_b = make_seal_with_content(5, "cell-alpha", 0x11, 0xBB);

        assert_ne!(
            seal_a.canonical_hash(),
            seal_b.canonical_hash(),
            "differing content_hash must yield different canonical hashes"
        );
    }

    #[test]
    fn equivocation_detected_on_differing_directory_epoch() {
        // Same (cell_id, htf_time_envelope_ref, quorum_anchor, epoch)
        // but different directory_epoch must be equivocation.
        let mut verifier = test_verifier();

        let seal_a = make_seal_full(
            5,
            "cell-alpha",
            test_root_hash(0x11),
            "cell-alpha",
            100,
            200,
            test_anchor_hash(0x31),
            test_anchor_hash(0x41),
            test_anchor_hash(0x51),
        );
        let verdict_a = verifier.verify(&seal_a, RiskTier::Tier2);
        assert!(verdict_a.accepted, "first seal should be accepted");

        let seal_b = make_seal_full(
            5,
            "cell-alpha",
            test_root_hash(0x11),
            "cell-alpha",
            999,
            200, // different directory_epoch
            test_anchor_hash(0x31),
            test_anchor_hash(0x41),
            test_anchor_hash(0x51),
        );
        let verdict_b = verifier.verify(&seal_b, RiskTier::Tier2);
        assert!(
            !verdict_b.accepted,
            "same epoch + different directory_epoch must be equivocation"
        );
        assert!(matches!(
            verdict_b.audit_event,
            EpochSealAuditEvent::EquivocationDetected {
                epoch_number: 5,
                ..
            }
        ));
    }

    #[test]
    fn equivocation_detected_on_differing_receipt_batch_epoch() {
        // Same epoch but different receipt_batch_epoch = equivocation.
        let mut verifier = test_verifier();

        let seal_a = make_seal_full(
            5,
            "cell-alpha",
            test_root_hash(0x11),
            "cell-alpha",
            100,
            200,
            test_anchor_hash(0x31),
            test_anchor_hash(0x41),
            test_anchor_hash(0x51),
        );
        assert!(verifier.verify(&seal_a, RiskTier::Tier2).accepted);

        let seal_b = make_seal_full(
            5,
            "cell-alpha",
            test_root_hash(0x11),
            "cell-alpha",
            100,
            999, // different receipt_batch_epoch
            test_anchor_hash(0x31),
            test_anchor_hash(0x41),
            test_anchor_hash(0x51),
        );
        let verdict_b = verifier.verify(&seal_b, RiskTier::Tier2);
        assert!(
            !verdict_b.accepted,
            "same epoch + different receipt_batch_epoch must be equivocation"
        );
    }

    #[test]
    fn equivocation_detected_on_differing_authority_seal_hash() {
        // Same epoch but different authority_seal_hash = equivocation.
        let mut verifier = test_verifier();

        let seal_a = make_seal_full(
            5,
            "cell-alpha",
            test_root_hash(0x11),
            "cell-alpha",
            100,
            200,
            test_anchor_hash(0x31),
            test_anchor_hash(0x41),
            test_anchor_hash(0x51),
        );
        assert!(verifier.verify(&seal_a, RiskTier::Tier2).accepted);

        let seal_b = make_seal_full(
            5,
            "cell-alpha",
            test_root_hash(0x11),
            "cell-alpha",
            100,
            200,
            test_anchor_hash(0x31),
            test_anchor_hash(0x41),
            test_anchor_hash(0xFF), // different authority_seal_hash
        );
        let verdict_b = verifier.verify(&seal_b, RiskTier::Tier2);
        assert!(
            !verdict_b.accepted,
            "same epoch + different authority_seal_hash must be equivocation"
        );
    }

    #[test]
    fn verifier_rejects_tampered_content_hash() {
        // A seal with a content_hash that does NOT match
        // compute_content_hash() must be rejected.
        let mut verifier = test_verifier();

        let seal = make_seal_with_content(5, "cell-alpha", 0x11, 0xAA);
        // content_hash is 0xAA... which won't match compute_content_hash()
        let verdict = verifier.verify(&seal, RiskTier::Tier2);
        assert!(
            !verdict.accepted,
            "seal with tampered content_hash must be rejected"
        );
        assert!(matches!(
            verdict.audit_event,
            EpochSealAuditEvent::ValidationFailed { ref reason }
            if reason.contains("content_hash mismatch")
        ));
    }

    #[test]
    fn idempotent_reaccept_requires_all_fields_matching() {
        // Same seal replayed = idempotent accept.
        let mut verifier = test_verifier();

        let seal = make_seal(5, "cell-alpha", 0x11);
        assert!(verifier.verify(&seal, RiskTier::Tier2).accepted);

        // Replay same seal: must be accepted idempotently.
        let verdict = verifier.verify(&seal, RiskTier::Tier2);
        assert!(verdict.accepted, "identical seal must be idempotent");
    }

    // =========================================================================
    // MAJOR 1 regression: deny_unknown_fields on serde deserialization
    // =========================================================================

    #[test]
    fn deny_unknown_fields_rejects_extra_json_field() {
        let seal = make_seal(1, "cell-alpha", 0x11);
        let mut json: serde_json::Value = serde_json::to_value(&seal).unwrap();

        // Inject an unknown field.
        json["unexpected_field"] = serde_json::Value::from("malicious");

        let result: Result<EpochSealV1, _> = serde_json::from_value(json);
        assert!(
            result.is_err(),
            "deserialization must reject unknown fields"
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("unknown field"),
            "error should mention unknown field, got: {err_msg}"
        );
    }

    #[test]
    fn deny_unknown_fields_accepts_valid_json() {
        let seal = make_seal(1, "cell-alpha", 0x11);
        let json = serde_json::to_value(&seal).unwrap();
        let result: Result<EpochSealV1, _> = serde_json::from_value(json);
        assert!(result.is_ok(), "valid JSON must deserialize successfully");
        assert_eq!(result.unwrap(), seal);
    }

    // =========================================================================
    // CQ BLOCKER 2 regression: RFC-required schema fields
    // =========================================================================

    #[test]
    fn seal_has_rfc_required_fields() {
        let seal = make_seal(3, "cell-alpha", 0x42);
        // All RFC-required fields must be accessible.
        assert!(!seal.cell_id().is_empty());
        assert!(seal.directory_epoch() > 0);
        assert!(seal.receipt_batch_epoch() > 0);
        assert_ne!(seal.htf_time_envelope_ref(), &[0u8; 32]);
        assert_ne!(seal.quorum_anchor(), &[0u8; 32]);
        assert_ne!(seal.authority_seal_hash(), &[0u8; 32]);
    }

    #[test]
    fn canonical_hash_includes_all_rfc_fields() {
        // Change each RFC field independently and verify the canonical
        // hash changes, proving all fields are bound into the preimage.
        let base = make_seal(3, "cell-alpha", 0x42);
        let base_hash = base.canonical_hash();

        // Different directory_epoch.
        let different_dir = EpochSealV1::new(
            3,
            test_root_hash(0x42),
            "cell-alpha",
            test_signature(),
            test_content_hash(0x42_u8.wrapping_add(0x10)),
            "cell-alpha",
            999, // different directory_epoch
            3,
            test_anchor_hash(0x42_u8.wrapping_add(0x20)),
            test_anchor_hash(0x42_u8.wrapping_add(0x30)),
            None,
            test_anchor_hash(0x42_u8.wrapping_add(0x40)),
        )
        .unwrap();
        assert_ne!(
            base_hash,
            different_dir.canonical_hash(),
            "directory_epoch must be in canonical preimage"
        );

        // Different quorum_anchor.
        let different_qa = EpochSealV1::new(
            3,
            test_root_hash(0x42),
            "cell-alpha",
            test_signature(),
            test_content_hash(0x42_u8.wrapping_add(0x10)),
            "cell-alpha",
            3,
            3,
            test_anchor_hash(0x42_u8.wrapping_add(0x20)),
            test_anchor_hash(0xFF), // different quorum anchor
            None,
            test_anchor_hash(0x42_u8.wrapping_add(0x40)),
        )
        .unwrap();
        assert_ne!(
            base_hash,
            different_qa.canonical_hash(),
            "quorum_anchor must be in canonical preimage"
        );
    }

    // =========================================================================
    // BLOCKER 3: Integration evidence (end-to-end seal verification flow)
    // =========================================================================

    // NOTE(TCK-00365): EpochSealVerifier::verify_with_policy() is now wired
    // into the daemon ToolBroker admission path (broker.rs). The verifier API
    // enforces monotonicity, anti-equivocation, and signature verification.
    // Request-carried seals are consumed via BrokerToolRequest.epoch_seal.

    #[test]
    fn end_to_end_seal_issuance_and_verification_flow() {
        // Demonstrates the complete seal lifecycle:
        // 1. Seals are created with valid content_hash.
        // 2. Verifier accepts monotonic seals.
        // 3. Verifier rejects rollback, equivocation, and missing signatures.

        // --- Phase 1: Build seals with correct content_hash ---
        // Both seals share the same (cell_id, htf_ref, quorum_anchor)
        // so they are in the same monotonicity chain.
        let seal1 = make_seal_full(
            1,
            "cell-authority",
            test_root_hash(0x01),
            "cell-authority",
            100,
            200,
            fixed_htf_ref(),
            fixed_quorum(),
            fixed_auth(),
        );
        assert_eq!(seal1.epoch_number(), 1);

        let seal2 = make_seal_full(
            2,
            "cell-authority",
            test_root_hash(0x02),
            "cell-authority",
            101,
            201,
            fixed_htf_ref(),
            fixed_quorum(),
            fixed_auth(),
        );
        assert_eq!(seal2.epoch_number(), 2);

        // --- Phase 2: Verification (accept monotonic) ---
        let mut verifier = test_verifier();
        let v1 = verifier.verify_or_reject(&seal1, RiskTier::Tier3);
        assert!(v1.is_ok(), "first seal must be accepted");

        let v2 = verifier.verify_or_reject(&seal2, RiskTier::Tier3);
        assert!(v2.is_ok(), "second seal must be accepted (monotonic)");

        // --- Phase 3: Rollback rejection ---
        let rollback = verifier.verify_or_reject(&seal1, RiskTier::Tier3);
        assert!(
            matches!(rollback, Err(EpochSealVerificationError::Rollback { .. })),
            "replaying old seal must be rejected as rollback"
        );

        // --- Phase 4: Fail-closed without signature verifier ---
        let mut bare_verifier = EpochSealVerifier::new();
        let bare_result = bare_verifier.verify_or_reject(&seal1, RiskTier::Tier3);
        assert!(
            matches!(
                bare_result,
                Err(EpochSealVerificationError::NoSignatureVerifier)
            ),
            "verifier without sig verifier must reject all seals"
        );

        // --- Phase 5: Tier2+ requires seal (fail-closed) ---
        assert!(EpochSealVerifier::require_seal_for_tier(RiskTier::Tier3).is_err());
        assert!(EpochSealVerifier::require_seal_for_tier(RiskTier::Tier0).is_ok());
    }

    // =========================================================================
    // VDF profile + policy tests (TCK-00366)
    // =========================================================================

    #[test]
    fn seal_without_vdf_is_accepted_when_policy_optional() {
        let mut verifier = test_verifier();
        verifier.set_vdf_policy(VdfPolicy::Optional);

        let seal = make_seal(1, "cell-optional", 0x21);
        let verdict = verifier.verify(&seal, RiskTier::Tier2);
        assert!(verdict.accepted);
        assert!(seal.vdf_profile().is_none());
    }

    #[test]
    fn verifier_configuration_tracks_vdf_settings() {
        let mut verifier = test_verifier();
        assert!(!verifier.has_vdf_verifier());
        assert_eq!(*verifier.vdf_policy(), VdfPolicy::Optional);

        verifier.set_vdf_policy(VdfPolicy::Required { min_difficulty: 7 });
        verifier.set_vdf_verifier(Box::new(DefaultVdfVerifier::default()));

        assert!(verifier.has_vdf_verifier());
        assert_eq!(
            *verifier.vdf_policy(),
            VdfPolicy::Required { min_difficulty: 7 }
        );
    }

    #[test]
    fn mixed_policy_enforcement_works_in_single_verifier_instance() {
        let mut verifier = test_verifier();
        verifier.set_vdf_verifier(Box::new(DefaultVdfVerifier::default()));
        verifier.set_vdf_policy(VdfPolicy::Required { min_difficulty: 99 });

        let resolver = StaticPolicyResolver::new(
            VdfPolicy::Optional,
            HashMap::from([
                (
                    "cell-required-valid".to_string(),
                    VdfPolicy::Required { min_difficulty: 4 },
                ),
                (
                    "cell-required-missing".to_string(),
                    VdfPolicy::Required { min_difficulty: 4 },
                ),
                ("cell-optional-missing".to_string(), VdfPolicy::Optional),
            ]),
        );
        verifier.set_vdf_policy_resolver(Arc::new(resolver));
        assert!(verifier.has_vdf_policy_resolver());

        let required_valid = make_seal_full_with_vdf(
            1,
            "issuer-required-valid",
            test_root_hash(0x34),
            "cell-required-valid",
            10,
            10,
            fixed_htf_ref(),
            fixed_quorum(),
            fixed_auth(),
            GENESIS_PRIOR_EPOCH_ROOT,
            4,
        );
        let required_missing = make_seal_full(
            1,
            "issuer-required-missing",
            test_root_hash(0x35),
            "cell-required-missing",
            11,
            11,
            fixed_htf_ref(),
            fixed_quorum(),
            fixed_auth(),
        );
        let optional_missing = make_seal_full(
            1,
            "issuer-optional-missing",
            test_root_hash(0x36),
            "cell-optional-missing",
            12,
            12,
            fixed_htf_ref(),
            fixed_quorum(),
            fixed_auth(),
        );

        let required_valid_verdict = verifier.verify(&required_valid, RiskTier::Tier2);
        assert!(required_valid_verdict.accepted);

        let required_missing_verdict = verifier.verify(&required_missing, RiskTier::Tier2);
        assert!(!required_missing_verdict.accepted);
        assert!(matches!(
            required_missing_verdict.audit_event,
            EpochSealAuditEvent::VdfRequiredByPolicy {
                min_difficulty: 4,
                ..
            }
        ));

        let optional_missing_verdict = verifier.verify(&optional_missing, RiskTier::Tier2);
        assert!(optional_missing_verdict.accepted);
    }

    #[test]
    fn valid_sloth_vdf_profile_passes_verification() {
        let mut verifier = test_verifier_with_vdf(VdfPolicy::Optional);
        let seal = make_seal_full_with_vdf(
            1,
            "issuer-vdf",
            test_root_hash(0x31),
            "cell-vdf",
            10,
            20,
            fixed_htf_ref(),
            fixed_quorum(),
            fixed_auth(),
            GENESIS_PRIOR_EPOCH_ROOT,
            4,
        );

        let verdict = verifier.verify(&seal, RiskTier::Tier2);
        assert!(verdict.accepted);
        assert!(seal.vdf_profile().is_some());
    }

    #[test]
    fn required_policy_accepts_vdf_when_min_difficulty_satisfied() {
        let mut verifier = test_verifier_with_vdf(VdfPolicy::Required { min_difficulty: 4 });
        let seal = make_seal_full_with_vdf(
            1,
            "issuer-required",
            test_root_hash(0x41),
            "cell-required",
            30,
            40,
            fixed_htf_ref(),
            fixed_quorum(),
            fixed_auth(),
            GENESIS_PRIOR_EPOCH_ROOT,
            4,
        );

        let verdict = verifier.verify(&seal, RiskTier::Tier3);
        assert!(verdict.accepted);
    }

    #[test]
    fn vdf_present_without_vdf_verifier_is_rejected_fail_closed() {
        let mut verifier = test_verifier();
        verifier.set_vdf_policy(VdfPolicy::Optional);

        let seal = make_seal_full_with_vdf(
            1,
            "issuer-no-vdf-verifier",
            test_root_hash(0x51),
            "cell-no-vdf-verifier",
            1,
            1,
            fixed_htf_ref(),
            fixed_quorum(),
            fixed_auth(),
            GENESIS_PRIOR_EPOCH_ROOT,
            3,
        );

        let verdict = verifier.verify(&seal, RiskTier::Tier2);
        assert!(!verdict.accepted);
        assert!(matches!(
            verdict.audit_event,
            EpochSealAuditEvent::NoVdfVerifier {
                epoch_number: 1,
                ..
            }
        ));
        let err = verifier.verify_or_reject(&seal, RiskTier::Tier2);
        assert!(matches!(
            err,
            Err(EpochSealVerificationError::NoVdfVerifier)
        ));
    }

    #[test]
    fn required_policy_rejects_missing_vdf_profile() {
        let mut verifier = test_verifier_with_vdf(VdfPolicy::Required {
            min_difficulty: MIN_VDF_DIFFICULTY,
        });
        let seal = make_seal(1, "cell-required-no-vdf", 0x61);

        let verdict = verifier.verify(&seal, RiskTier::Tier2);
        assert!(!verdict.accepted);
        assert!(matches!(
            verdict.audit_event,
            EpochSealAuditEvent::VdfRequiredByPolicy {
                min_difficulty: MIN_VDF_DIFFICULTY,
                ..
            }
        ));
    }

    #[test]
    fn required_policy_rejects_vdf_below_minimum_difficulty() {
        let mut verifier = test_verifier_with_vdf(VdfPolicy::Required { min_difficulty: 8 });
        let seal = make_seal_full_with_vdf(
            1,
            "issuer-low-vdf",
            test_root_hash(0x71),
            "cell-low-vdf",
            5,
            6,
            fixed_htf_ref(),
            fixed_quorum(),
            fixed_auth(),
            GENESIS_PRIOR_EPOCH_ROOT,
            4,
        );

        let verdict = verifier.verify(&seal, RiskTier::Tier2);
        assert!(!verdict.accepted);
        assert!(matches!(
            verdict.audit_event,
            EpochSealAuditEvent::VdfDifficultyBelowPolicy {
                difficulty: 4,
                min_difficulty: 8,
                ..
            }
        ));
    }

    #[test]
    fn forged_vdf_output_is_rejected_deterministically() {
        let mut verifier = test_verifier_with_vdf(VdfPolicy::Optional);
        let input_hash = VdfProfileV1::derive_challenge(
            "cell-forged-vdf",
            &GENESIS_PRIOR_EPOCH_ROOT,
            &fixed_quorum(),
        );
        let mut forged_output = SlothV1Verifier::evaluate(&input_hash, 5).to_vec();
        forged_output[0] ^= 0x01;
        let forged_profile = VdfProfileV1::new(VdfScheme::SlothV1, input_hash, forged_output, 5)
            .expect("forged profile remains structurally valid");

        let placeholder = EpochSealV1::new(
            1,
            test_root_hash(0x81),
            "issuer-forged-vdf",
            test_signature(),
            [0xEF; 32],
            "cell-forged-vdf",
            1,
            1,
            fixed_htf_ref(),
            fixed_quorum(),
            Some(forged_profile.clone()),
            fixed_auth(),
        )
        .expect("placeholder seal must be valid");
        let content_hash = placeholder.compute_content_hash();

        let seal = EpochSealV1::new(
            1,
            test_root_hash(0x81),
            "issuer-forged-vdf",
            test_signature(),
            content_hash,
            "cell-forged-vdf",
            1,
            1,
            fixed_htf_ref(),
            fixed_quorum(),
            Some(forged_profile),
            fixed_auth(),
        )
        .expect("final seal must be valid");

        let verdict = verifier.verify(&seal, RiskTier::Tier2);
        assert!(!verdict.accepted);
        assert!(matches!(
            verdict.audit_event,
            EpochSealAuditEvent::VdfRejected { .. }
        ));
    }

    #[test]
    fn vdf_challenge_mismatch_is_rejected() {
        let mut verifier = test_verifier_with_vdf(VdfPolicy::Optional);
        let wrong_input = VdfProfileV1::derive_challenge(
            "wrong-cell",
            &GENESIS_PRIOR_EPOCH_ROOT,
            &fixed_quorum(),
        );
        let output = SlothV1Verifier::evaluate(&wrong_input, 3).to_vec();
        let mismatched_profile =
            VdfProfileV1::new(VdfScheme::SlothV1, wrong_input, output, 3).expect("valid profile");

        let placeholder = EpochSealV1::new(
            1,
            test_root_hash(0x91),
            "issuer-input-mismatch",
            test_signature(),
            [0xCD; 32],
            "cell-input-mismatch",
            1,
            1,
            fixed_htf_ref(),
            fixed_quorum(),
            Some(mismatched_profile.clone()),
            fixed_auth(),
        )
        .expect("placeholder seal must be valid");
        let content_hash = placeholder.compute_content_hash();
        let seal = EpochSealV1::new(
            1,
            test_root_hash(0x91),
            "issuer-input-mismatch",
            test_signature(),
            content_hash,
            "cell-input-mismatch",
            1,
            1,
            fixed_htf_ref(),
            fixed_quorum(),
            Some(mismatched_profile),
            fixed_auth(),
        )
        .expect("final seal must be valid");

        let verdict = verifier.verify(&seal, RiskTier::Tier2);
        assert!(!verdict.accepted);
        assert!(matches!(
            verdict.audit_event,
            EpochSealAuditEvent::VdfInputHashMismatch { .. }
        ));
    }

    #[test]
    fn non_monotone_vdf_sealed_epochs_are_rejected() {
        let mut verifier = test_verifier_with_vdf(VdfPolicy::Optional);
        let seal1 = make_seal_full_with_vdf(
            1,
            "issuer-vdf-monotone",
            test_root_hash(0xA1),
            "cell-vdf-monotone",
            1,
            1,
            fixed_htf_ref(),
            fixed_quorum(),
            fixed_auth(),
            GENESIS_PRIOR_EPOCH_ROOT,
            2,
        );
        let seal2 = make_seal_full_with_vdf(
            2,
            "issuer-vdf-monotone",
            test_root_hash(0xA2),
            "cell-vdf-monotone",
            2,
            2,
            fixed_htf_ref(),
            fixed_quorum(),
            fixed_auth(),
            *seal1.sealed_root_hash(),
            2,
        );

        let verdict1 = verifier.verify(&seal1, RiskTier::Tier2);
        let verdict2 = verifier.verify(&seal2, RiskTier::Tier2);
        let verdict3 = verifier.verify(&seal1, RiskTier::Tier2);

        let events = [
            verdict1.audit_event.kind(),
            verdict2.audit_event.kind(),
            verdict3.audit_event.kind(),
        ];
        assert_eq!(events.len(), 3);
        assert_eq!(events[0], "epoch_seal.accepted");
        assert_eq!(events[1], "epoch_seal.accepted");
        assert_eq!(events[2], "epoch_seal.rollback_rejected");
        assert!(!verdict3.accepted);
    }

    #[test]
    fn vdf_profile_none_is_skipped_during_serialization() {
        let seal = make_seal(1, "cell-no-vdf-serde", 0x33);
        let json = serde_json::to_value(&seal).unwrap();
        assert!(json.get("vdf_profile").is_none());
    }

    #[test]
    fn vdf_profile_validation_rejects_bounded_violations() {
        let result_zero_hash = VdfProfileV1::new(VdfScheme::SlothV1, [0u8; 32], vec![0xAA; 32], 1);
        let result_empty_output =
            VdfProfileV1::new(VdfScheme::SlothV1, test_anchor_hash(0x01), Vec::new(), 1);
        let result_oversized_output = VdfProfileV1::new(
            VdfScheme::SlothV1,
            test_anchor_hash(0x01),
            vec![0xAA; MAX_VDF_OUTPUT_LENGTH + 1],
            1,
        );
        let result_zero_difficulty = VdfProfileV1::new(
            VdfScheme::SlothV1,
            test_anchor_hash(0x01),
            vec![0xAA; 32],
            0,
        );
        let result_over_max_difficulty = VdfProfileV1::new(
            VdfScheme::SlothV1,
            test_anchor_hash(0x01),
            vec![0xAA; 32],
            MAX_VDF_DIFFICULTY + 1,
        );

        assert!(matches!(
            result_zero_hash,
            Err(VdfProfileError::ZeroInputHash)
        ));
        assert!(matches!(
            result_empty_output,
            Err(VdfProfileError::EmptyOutput)
        ));
        assert!(matches!(
            result_oversized_output,
            Err(VdfProfileError::OutputTooLong { .. })
        ));
        assert!(matches!(
            result_zero_difficulty,
            Err(VdfProfileError::DifficultyTooLow { .. })
        ));
        assert!(matches!(
            result_over_max_difficulty,
            Err(VdfProfileError::DifficultyTooHigh { .. })
        ));
    }

    // =========================================================================
    // Validation of new anchor fields via deserialization bypass
    // =========================================================================

    #[test]
    fn validate_rejects_zero_time_envelope_ref_via_serde() {
        let valid_seal = make_seal(1, "cell-alpha", 0x11);
        let mut json: serde_json::Value = serde_json::to_value(&valid_seal).unwrap();
        json["htf_time_envelope_ref"] = serde_json::to_value(vec![0u8; 32]).unwrap();
        let bad_seal: EpochSealV1 = serde_json::from_value(json).unwrap();
        assert!(matches!(
            bad_seal.validate(),
            Err(EpochSealError::ZeroTimeEnvelopeRef)
        ));
    }

    #[test]
    fn validate_rejects_zero_quorum_anchor_via_serde() {
        let valid_seal = make_seal(1, "cell-alpha", 0x11);
        let mut json: serde_json::Value = serde_json::to_value(&valid_seal).unwrap();
        json["quorum_anchor"] = serde_json::to_value(vec![0u8; 32]).unwrap();
        let bad_seal: EpochSealV1 = serde_json::from_value(json).unwrap();
        assert!(matches!(
            bad_seal.validate(),
            Err(EpochSealError::ZeroQuorumAnchor)
        ));
    }

    #[test]
    fn validate_rejects_zero_authority_seal_hash_via_serde() {
        let valid_seal = make_seal(1, "cell-alpha", 0x11);
        let mut json: serde_json::Value = serde_json::to_value(&valid_seal).unwrap();
        json["authority_seal_hash"] = serde_json::to_value(vec![0u8; 32]).unwrap();
        let bad_seal: EpochSealV1 = serde_json::from_value(json).unwrap();
        assert!(matches!(
            bad_seal.validate(),
            Err(EpochSealError::ZeroAuthoritySealHash)
        ));
    }

    #[test]
    fn validate_rejects_empty_cell_id_via_serde() {
        let valid_seal = make_seal(1, "cell-alpha", 0x11);
        let mut json: serde_json::Value = serde_json::to_value(&valid_seal).unwrap();
        json["cell_id"] = serde_json::Value::from("");
        let bad_seal: EpochSealV1 = serde_json::from_value(json).unwrap();
        assert!(matches!(
            bad_seal.validate(),
            Err(EpochSealError::EmptyCellId)
        ));
    }

    // =========================================================================
    // BLOCKER 1 regression: monotonicity keyed on cell_id + HTF/quorum
    // =========================================================================

    #[test]
    fn monotonicity_keyed_on_cell_id_not_issuer() {
        // Two seals from the SAME issuer but different cell_id must
        // have independent monotonicity chains.
        let mut verifier = test_verifier();

        let seal_cell_a = make_seal_full(
            5,
            "issuer-1",
            test_root_hash(0x11),
            "cell-A",
            100,
            200,
            test_anchor_hash(0x31),
            test_anchor_hash(0x41),
            test_anchor_hash(0x51),
        );
        assert!(verifier.verify(&seal_cell_a, RiskTier::Tier2).accepted);

        // Same issuer, different cell_id: epoch 1 should be accepted
        // (independent chain).
        let seal_cell_b = make_seal_full(
            1,
            "issuer-1",
            test_root_hash(0x22),
            "cell-B",
            10,
            20,
            test_anchor_hash(0x31),
            test_anchor_hash(0x41),
            test_anchor_hash(0x51),
        );
        let verdict = verifier.verify(&seal_cell_b, RiskTier::Tier2);
        assert!(
            verdict.accepted,
            "different cell_id must have independent chain (epoch 1 accepted despite cell-A at 5)"
        );
    }

    #[test]
    fn monotonicity_includes_quorum_anchor_in_key() {
        // Same cell_id + htf_time_envelope_ref but different quorum_anchor
        // must be independent chains.
        let mut verifier = test_verifier();

        let seal_qa1 = make_seal_full(
            5,
            "issuer-1",
            test_root_hash(0x11),
            "cell-A",
            100,
            200,
            test_anchor_hash(0x31),
            test_anchor_hash(0x41),
            test_anchor_hash(0x51),
        );
        assert!(verifier.verify(&seal_qa1, RiskTier::Tier2).accepted);

        // Same cell_id, same htf_time_envelope_ref, different quorum_anchor:
        // epoch 1 should be accepted (independent key).
        let seal_qa2 = make_seal_full(
            1,
            "issuer-1",
            test_root_hash(0x22),
            "cell-A",
            10,
            20,
            test_anchor_hash(0x31),
            test_anchor_hash(0xFF),
            test_anchor_hash(0x51),
        );
        let verdict = verifier.verify(&seal_qa2, RiskTier::Tier2);
        assert!(
            verdict.accepted,
            "different quorum_anchor must yield independent monotonicity chain"
        );
    }

    #[test]
    fn monotonicity_includes_htf_time_envelope_ref_in_key() {
        // Same cell_id + quorum_anchor but different htf_time_envelope_ref
        // must be independent chains.
        let mut verifier = test_verifier();

        let seal_htf1 = make_seal_full(
            5,
            "issuer-1",
            test_root_hash(0x11),
            "cell-A",
            100,
            200,
            test_anchor_hash(0x31),
            test_anchor_hash(0x41),
            test_anchor_hash(0x51),
        );
        assert!(verifier.verify(&seal_htf1, RiskTier::Tier2).accepted);

        // Same cell_id, same quorum_anchor, different htf_time_envelope_ref:
        // epoch 1 should be accepted (independent key).
        let seal_htf2 = make_seal_full(
            1,
            "issuer-1",
            test_root_hash(0x22),
            "cell-A",
            10,
            20,
            test_anchor_hash(0xFF),
            test_anchor_hash(0x41),
            test_anchor_hash(0x51),
        );
        let verdict = verifier.verify(&seal_htf2, RiskTier::Tier2);
        assert!(
            verdict.accepted,
            "different htf_time_envelope_ref must yield independent monotonicity chain"
        );
    }

    #[test]
    fn rollback_detected_for_same_cell_id_and_anchors() {
        // Same (cell_id, htf_time_envelope_ref, quorum_anchor): rollback
        // must be detected.
        let mut verifier = test_verifier();

        let seal1 = make_seal_full(
            10,
            "issuer-1",
            test_root_hash(0x11),
            "cell-A",
            100,
            200,
            test_anchor_hash(0x31),
            test_anchor_hash(0x41),
            test_anchor_hash(0x51),
        );
        assert!(verifier.verify(&seal1, RiskTier::Tier2).accepted);

        // Same cell_id + anchors, lower epoch = rollback.
        let seal2 = make_seal_full(
            5,
            "issuer-1",
            test_root_hash(0x22),
            "cell-A",
            50,
            100,
            test_anchor_hash(0x31),
            test_anchor_hash(0x41),
            test_anchor_hash(0x51),
        );
        let verdict = verifier.verify(&seal2, RiskTier::Tier2);
        assert!(
            !verdict.accepted,
            "rollback must be detected for same (cell_id, htf_ref, quorum_anchor)"
        );
        assert!(matches!(
            verdict.audit_event,
            EpochSealAuditEvent::RollbackRejected {
                epoch_number: 5,
                last_accepted_epoch: 10,
                ..
            }
        ));
    }

    // =========================================================================
    // BLOCKER 2 regression: content_hash recomputation
    // =========================================================================

    #[test]
    fn compute_content_hash_deterministic() {
        let seal = make_seal(3, "cell-alpha", 0x42);
        let h1 = seal.compute_content_hash();
        let h2 = seal.compute_content_hash();
        assert_eq!(h1, h2, "compute_content_hash must be deterministic");
    }

    #[test]
    fn compute_content_hash_differs_on_different_fields() {
        let seal_a = make_seal(3, "cell-alpha", 0x42);
        let seal_b = make_seal(4, "cell-alpha", 0x42);
        assert_ne!(
            seal_a.compute_content_hash(),
            seal_b.compute_content_hash(),
            "different epoch must yield different content hash"
        );
    }

    #[test]
    fn valid_seal_content_hash_matches_compute() {
        let seal = make_seal(5, "cell-alpha", 0x11);
        assert_eq!(
            seal.content_hash(),
            &seal.compute_content_hash(),
            "make_seal must produce a seal whose content_hash matches compute_content_hash"
        );
    }

    // =========================================================================
    // Eviction high-water mark tests (replay-after-eviction defense)
    // =========================================================================

    #[test]
    fn evicted_key_valid_next_vdf_seal_uses_tombstone_root() {
        let mut verifier = test_verifier_with_vdf(VdfPolicy::Optional);

        let target = make_seal_full_with_vdf(
            10,
            "issuer-evict-vdf",
            test_root_hash(0x71),
            "cell-evict-vdf",
            10,
            10,
            fixed_htf_ref(),
            fixed_quorum(),
            fixed_auth(),
            GENESIS_PRIOR_EPOCH_ROOT,
            4,
        );
        assert!(verifier.verify(&target, RiskTier::Tier2).accepted);

        for i in 1..=MAX_TRACKED_ISSUERS {
            let cell_id = format!("fill-cell-vdf-{i}");
            let seal = make_seal_full(
                1,
                &cell_id,
                test_root_hash(0x22),
                &cell_id,
                1,
                1,
                test_anchor_hash((i & 0xFF) as u8),
                test_anchor_hash(((i >> 8) & 0xFF) as u8 | 0x01),
                test_anchor_hash(0xC2),
            );
            verifier.verify(&seal, RiskTier::Tier0);
        }

        assert_eq!(verifier.evicted_tombstone_count(), 1);

        let next_epoch = make_seal_full_with_vdf(
            11,
            "issuer-evict-vdf",
            test_root_hash(0x72),
            "cell-evict-vdf",
            11,
            11,
            fixed_htf_ref(),
            fixed_quorum(),
            fixed_auth(),
            *target.sealed_root_hash(),
            4,
        );
        let verdict = verifier.verify(&next_epoch, RiskTier::Tier2);
        assert!(verdict.accepted);

        // Promotion check: after re-admission from tombstone state, the key
        // must continue as a normal monotonic chain.
        let next_next = make_seal_full_with_vdf(
            12,
            "issuer-evict-vdf",
            test_root_hash(0x73),
            "cell-evict-vdf",
            12,
            12,
            fixed_htf_ref(),
            fixed_quorum(),
            fixed_auth(),
            *next_epoch.sealed_root_hash(),
            4,
        );
        let next_next_verdict = verifier.verify(&next_next, RiskTier::Tier2);
        assert!(next_next_verdict.accepted);
    }

    #[test]
    fn evicted_key_replay_with_vdf_is_rejected_by_tombstone_epoch() {
        let mut verifier = test_verifier_with_vdf(VdfPolicy::Optional);

        let target = make_seal_full_with_vdf(
            8,
            "issuer-evict-replay",
            test_root_hash(0x81),
            "cell-evict-replay",
            8,
            8,
            fixed_htf_ref(),
            fixed_quorum(),
            fixed_auth(),
            GENESIS_PRIOR_EPOCH_ROOT,
            4,
        );
        assert!(verifier.verify(&target, RiskTier::Tier2).accepted);

        for i in 1..=MAX_TRACKED_ISSUERS {
            let cell_id = format!("fill-cell-replay-{i}");
            let seal = make_seal_full(
                1,
                &cell_id,
                test_root_hash(0x44),
                &cell_id,
                1,
                1,
                test_anchor_hash((i & 0xFF) as u8),
                test_anchor_hash(((i >> 8) & 0xFF) as u8 | 0x01),
                test_anchor_hash(0xD2),
            );
            verifier.verify(&seal, RiskTier::Tier0);
        }

        assert_eq!(verifier.evicted_tombstone_count(), 1);

        let replay = make_seal_full_with_vdf(
            8,
            "issuer-evict-replay",
            test_root_hash(0x81),
            "cell-evict-replay",
            8,
            8,
            fixed_htf_ref(),
            fixed_quorum(),
            fixed_auth(),
            GENESIS_PRIOR_EPOCH_ROOT,
            4,
        );
        let verdict = verifier.verify(&replay, RiskTier::Tier2);
        assert!(!verdict.accepted);
        assert!(matches!(
            verdict.audit_event,
            EpochSealAuditEvent::EvictionReplayRejected {
                epoch_number: 8,
                evicted_high_water_epoch: 8,
                ..
            }
        ));
    }

    #[test]
    fn eviction_replay_rejected_after_lru_eviction() {
        // Fill verifier to capacity, evict, then replay the evicted
        // issuer with the same epoch. The replayed seal must be rejected.
        let mut verifier = test_verifier();

        // Accept seal at epoch 10 for a specific key.
        let target_seal = make_seal_full(
            10,
            "evict-target",
            test_root_hash(0x11),
            "evict-cell",
            1,
            1,
            test_anchor_hash(0xA1),
            test_anchor_hash(0xB1),
            test_anchor_hash(0xC1),
        );
        assert!(
            verifier.verify(&target_seal, RiskTier::Tier2).accepted,
            "target seal must be accepted initially"
        );

        // Fill remaining capacity to force LRU eviction of the target.
        // Each new cell gets a unique (cell_id, htf_ref, quorum_anchor)
        // key so they don't collide.
        for i in 1..=MAX_TRACKED_ISSUERS {
            let cell_id = format!("fill-cell-{i}");
            let seal = make_seal_full(
                1,
                &cell_id,
                test_root_hash(0x22),
                &cell_id,
                1,
                1,
                test_anchor_hash((i & 0xFF) as u8),
                test_anchor_hash(((i >> 8) & 0xFF) as u8 | 0x01),
                test_anchor_hash(0xC2),
            );
            verifier.verify(&seal, RiskTier::Tier0);
        }

        // The target should have been evicted (it was LRU).
        // Now replay the same seal at epoch 10 — must be rejected.
        let replay_seal = make_seal_full(
            10,
            "evict-target",
            test_root_hash(0x11),
            "evict-cell",
            1,
            1,
            test_anchor_hash(0xA1),
            test_anchor_hash(0xB1),
            test_anchor_hash(0xC1),
        );
        let verdict = verifier.verify(&replay_seal, RiskTier::Tier2);
        assert!(
            !verdict.accepted,
            "replay of evicted seal at same epoch must be rejected"
        );
        assert!(
            matches!(
                verdict.audit_event,
                EpochSealAuditEvent::EvictionReplayRejected {
                    epoch_number: 10,
                    evicted_high_water_epoch: 10,
                    ..
                }
            ),
            "expected EvictionReplayRejected, got {:?}",
            verdict.audit_event
        );
    }

    #[test]
    fn eviction_replay_accepted_with_higher_epoch() {
        // Same setup as above, but replay with epoch > evicted high-water.
        let mut verifier = test_verifier();

        let target_seal = make_seal_full(
            10,
            "evict-target",
            test_root_hash(0x11),
            "evict-cell",
            1,
            1,
            test_anchor_hash(0xA1),
            test_anchor_hash(0xB1),
            test_anchor_hash(0xC1),
        );
        assert!(verifier.verify(&target_seal, RiskTier::Tier2).accepted);

        for i in 1..=MAX_TRACKED_ISSUERS {
            let cell_id = format!("fill-cell-{i}");
            let seal = make_seal_full(
                1,
                &cell_id,
                test_root_hash(0x22),
                &cell_id,
                1,
                1,
                test_anchor_hash((i & 0xFF) as u8),
                test_anchor_hash(((i >> 8) & 0xFF) as u8 | 0x01),
                test_anchor_hash(0xC2),
            );
            verifier.verify(&seal, RiskTier::Tier0);
        }

        // Replay with epoch 11 (higher than evicted high-water 10).
        let replay_seal = make_seal_full(
            11,
            "evict-target",
            test_root_hash(0x33),
            "evict-cell",
            2,
            2,
            test_anchor_hash(0xA1),
            test_anchor_hash(0xB1),
            test_anchor_hash(0xC1),
        );
        let verdict = verifier.verify(&replay_seal, RiskTier::Tier2);
        assert!(
            verdict.accepted,
            "replay with higher epoch than evicted high-water must be accepted"
        );
    }

    #[test]
    fn eviction_high_water_count_bounded() {
        // Verify that the eviction tombstone map doesn't grow unbounded.
        let mut verifier = test_verifier();

        // Create and evict many keys.
        for i in 0..(MAX_EVICTION_HIGH_WATER_MARKS + 100) {
            let cell_id = format!("hw-cell-{i}");
            let seal = make_seal_full(
                1,
                &cell_id,
                test_root_hash(0x11),
                &cell_id,
                1,
                1,
                test_anchor_hash((i & 0xFF) as u8),
                test_anchor_hash(((i >> 8) & 0xFF) as u8 | 0x01),
                test_anchor_hash(0xC1),
            );
            verifier.verify(&seal, RiskTier::Tier0);
        }
        // Force eviction of all by filling with new keys.
        for i in 0..(MAX_TRACKED_ISSUERS + 100) {
            let cell_id = format!("new-cell-{i}");
            let seal = make_seal_full(
                1,
                &cell_id,
                test_root_hash(0x22),
                &cell_id,
                1,
                1,
                test_anchor_hash(((i + 0x80) & 0xFF) as u8),
                test_anchor_hash((((i + 0x80) >> 8) & 0xFF) as u8 | 0x01),
                test_anchor_hash(0xC2),
            );
            verifier.verify(&seal, RiskTier::Tier0);
        }

        assert!(
            verifier.evicted_high_water_count() <= MAX_EVICTION_HIGH_WATER_MARKS,
            "eviction tombstone map must be bounded at {}, got {}",
            MAX_EVICTION_HIGH_WATER_MARKS,
            verifier.evicted_high_water_count()
        );
    }

    #[test]
    fn verify_or_reject_maps_eviction_replay_error() {
        let mut verifier = test_verifier();

        let target_seal = make_seal_full(
            5,
            "evict-target",
            test_root_hash(0x11),
            "evict-cell",
            1,
            1,
            test_anchor_hash(0xA1),
            test_anchor_hash(0xB1),
            test_anchor_hash(0xC1),
        );
        assert!(
            verifier
                .verify_or_reject(&target_seal, RiskTier::Tier2)
                .is_ok()
        );

        // Evict by filling capacity.
        for i in 1..=MAX_TRACKED_ISSUERS {
            let cell_id = format!("fill-{i}");
            let seal = make_seal_full(
                1,
                &cell_id,
                test_root_hash(0x22),
                &cell_id,
                1,
                1,
                test_anchor_hash((i & 0xFF) as u8),
                test_anchor_hash(((i >> 8) & 0xFF) as u8 | 0x01),
                test_anchor_hash(0xC2),
            );
            verifier.verify(&seal, RiskTier::Tier0);
        }

        // Replay at same epoch — verify_or_reject returns EvictionReplay error.
        let replay = make_seal_full(
            5,
            "evict-target",
            test_root_hash(0x11),
            "evict-cell",
            1,
            1,
            test_anchor_hash(0xA1),
            test_anchor_hash(0xB1),
            test_anchor_hash(0xC1),
        );
        let err = verifier
            .verify_or_reject(&replay, RiskTier::Tier2)
            .unwrap_err();
        assert!(
            matches!(
                err,
                EpochSealVerificationError::EvictionReplay {
                    epoch_number: 5,
                    evicted_high_water_epoch: 5,
                    ..
                }
            ),
            "expected EvictionReplay error, got {err:?}"
        );
    }

    // =========================================================================
    // Bounded signature deserialization tests
    // =========================================================================

    #[test]
    fn signature_deser_rejects_oversized_payload() {
        // Build a valid seal, serialize it, tamper with the signature
        // to be oversized, then attempt deserialization.
        let seal = make_seal(1, "cell-alpha", 0x11);
        let mut value = serde_json::to_value(&seal).expect("serialize");

        // Replace signature with 65 bytes (one over the limit).
        let oversized: Vec<u8> = vec![0xAA; 65];
        value["signature"] = serde_json::Value::Array(
            oversized
                .iter()
                .map(|&b| serde_json::Value::Number(b.into()))
                .collect(),
        );

        let result: Result<EpochSealV1, _> = serde_json::from_value(value);
        assert!(
            result.is_err(),
            "deserialization must reject signature with 65 bytes"
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("more than 64 bytes") || err_msg.contains("signature too long"),
            "error should mention oversized signature, got: {err_msg}"
        );
    }

    #[test]
    fn signature_deser_rejects_undersized_payload() {
        let seal = make_seal(1, "cell-alpha", 0x11);
        let mut value = serde_json::to_value(&seal).expect("serialize");

        // Replace signature with 63 bytes (one under).
        let undersized: Vec<u8> = vec![0xAA; 63];
        value["signature"] = serde_json::Value::Array(
            undersized
                .iter()
                .map(|&b| serde_json::Value::Number(b.into()))
                .collect(),
        );

        let result: Result<EpochSealV1, _> = serde_json::from_value(value);
        assert!(
            result.is_err(),
            "deserialization must reject signature with 63 bytes"
        );
    }

    #[test]
    fn signature_deser_accepts_exact_size() {
        let seal = make_seal(1, "cell-alpha", 0x11);
        let json = serde_json::to_string(&seal).expect("serialize");
        let result: Result<EpochSealV1, _> = serde_json::from_str(&json);
        assert!(
            result.is_ok(),
            "deserialization must accept exact 64-byte signature"
        );
    }

    #[test]
    fn signature_roundtrip_preserves_bytes() {
        let seal = make_seal(1, "cell-alpha", 0x11);
        let json = serde_json::to_string(&seal).expect("serialize");
        let roundtripped: EpochSealV1 = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(seal, roundtripped, "roundtrip must preserve all fields");
    }

    // =========================================================================
    // Canonical Bytes Serialization Tests (TCK-00365)
    // =========================================================================

    #[test]
    fn canonical_bytes_roundtrip() {
        let seal = make_seal(7, "cell-gamma", 0x42);
        let bytes = seal
            .to_canonical_bytes()
            .expect("serialization must succeed");
        assert!(!bytes.is_empty(), "canonical bytes must be non-empty");
        let deserialized =
            EpochSealV1::from_canonical_bytes(&bytes).expect("deserialization must succeed");
        assert_eq!(seal, deserialized, "roundtrip must preserve all fields");
    }

    #[test]
    fn canonical_bytes_invalid_input_fails() {
        let result = EpochSealV1::from_canonical_bytes(b"not valid json");
        assert!(result.is_err(), "invalid bytes must fail deserialization");
        let err = result.unwrap_err();
        assert!(
            matches!(err, EpochSealError::DeserializationFailed { .. }),
            "error must be DeserializationFailed, got: {err:?}"
        );
    }

    // =========================================================================
    // Length-Prefix Collision Resistance Tests (TCK-00365 MAJOR-2)
    // =========================================================================

    /// Regression: without length-prefix framing, issuer="A" + reason="AA"
    /// and issuer="AA" + reason="A" produce identical hash preimages when
    /// concatenated directly. Length-prefix framing must prevent this.
    #[test]
    fn signature_rejected_hash_collision_resistance() {
        let event_a = EpochSealAuditEvent::SignatureRejected {
            issuer_cell_id: "A".to_string(),
            epoch_number: 1,
            reason: "AA".to_string(),
        };
        let event_b = EpochSealAuditEvent::SignatureRejected {
            issuer_cell_id: "AA".to_string(),
            epoch_number: 1,
            reason: "A".to_string(),
        };
        assert_ne!(
            event_a.canonical_hash(),
            event_b.canonical_hash(),
            "length-prefix framing must prevent concatenation collision \
             (issuer='A'+reason='AA' vs issuer='AA'+reason='A')"
        );
    }

    /// Regression: verify collision resistance for Accepted variant with
    /// different issuer lengths at the same epoch boundary.
    #[test]
    fn accepted_hash_collision_resistance() {
        let event_a = EpochSealAuditEvent::Accepted {
            issuer_cell_id: "ab".to_string(),
            epoch_number: 1,
            previous_epoch: 0,
        };
        // Without length-prefix, if somehow the issuer bytes leak into
        // epoch_number LE bytes, the hash could collide. With framing,
        // different issuers always produce different hashes.
        let event_b = EpochSealAuditEvent::Accepted {
            issuer_cell_id: "abc".to_string(),
            epoch_number: 1,
            previous_epoch: 0,
        };
        assert_ne!(
            event_a.canonical_hash(),
            event_b.canonical_hash(),
            "different issuers must produce different hashes"
        );
    }

    /// Regression: verify collision resistance for `InvalidSeal` variant
    /// which only has a reason string field.
    #[test]
    fn invalid_seal_hash_collision_resistance() {
        let event_a = EpochSealAuditEvent::InvalidSeal {
            reason: "ab".to_string(),
        };
        let event_b = EpochSealAuditEvent::InvalidSeal {
            reason: "abc".to_string(),
        };
        assert_ne!(
            event_a.canonical_hash(),
            event_b.canonical_hash(),
            "different reasons must produce different hashes"
        );
    }
}
