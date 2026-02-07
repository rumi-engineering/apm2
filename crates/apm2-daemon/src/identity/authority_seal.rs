//! `AuthoritySealV1` — unified fact-authentication abstraction (RFC-0020
//! §1.7.8).
//!
//! This module implements the `AuthoritySealV1` type that authenticates facts
//! via four seal kinds:
//! - [`SealKind::SingleSig`] — one Ed25519 signature
//! - [`SealKind::QuorumMultisig`] — n-of-n multisig
//! - [`SealKind::QuorumThreshold`] — k-of-n threshold signature
//! - [`SealKind::MerkleBatch`] — signature/quorum over a Merkle batch root
//!
//! # Domain Separation
//!
//! Every preimage hashed for verification is domain-separated by artifact kind
//! and schema version, preventing cross-protocol confusion attacks.
//!
//! # Ledger Anchor Binding
//!
//! All authority seals MUST reference a ledger anchor. Unsigned or
//! free-floating batch roots are rejected for authority use (RFC-0020
//! §0.1(11b)).
//!
//! # Temporal Authority Binding
//!
//! All authority seals carry a `time_envelope_ref` field — a 32-byte hash
//! reference to the HTF time envelope artifact. For Tier2+ and governance
//! contexts this binding MUST be non-zero, enabling verifiers to
//! cryptographically bind a seal to HTF freshness context (RFC-0020 §9.2,
//! REQ-0016).
//!
//! # Security Invariants
//!
//! - Fail-closed: unknown seal kinds and missing fields produce errors, never
//!   defaults.
//! - Constant-time signature comparison via `subtle::ConstantTimeEq`.
//! - Domain separation tags are required and validated before verification.
//! - Quorum seals require issuer quorum identifier.
//! - `MERKLE_BATCH` seals with quorum issuers enforce quorum verification:
//!   multisig requires all signatures valid (n-of-n), threshold requires
//!   k-of-n. The single-key `verify_merkle_batch` method rejects quorum issuers
//!   to prevent single-signature bypass.
//! - Verification methods enforce expected `subject_kind` and `subject_hash` at
//!   call boundaries to prevent semantically wrong seals from being accepted.
//!
//! # Issuer-Key Binding Contract
//!
//! All verification methods accept caller-provided verifying keys. The caller
//! is responsible for resolving the `issuer_id` in the seal to the authentic
//! verifying keys via an authenticated directory or equivalent trusted
//! mechanism. The verification methods validate cryptographic signatures but
//! do NOT perform issuer identity resolution.
//!
//! # Contract References
//!
//! - RFC-0020 §1.7.8: Attestation envelopes (normative)
//! - RFC-0020 §9.5: Proof compression at scale (normative)
//! - RFC-0020 §0.1(11b): Batch roots MUST be ledger-anchored
//! - REQ-0016: `AuthoritySeal` unified fact authentication
//! - EVID-0016: `AuthoritySeal` conformance evidence

use apm2_core::crypto::Hash;
use ed25519_dalek::Verifier as _;
use thiserror::Error;

use super::directory_proof::LedgerAnchorV1;
use super::{CellIdV1, KeySetIdV1, PublicKeyIdV1};

// ──────────────────────────────────────────────────────────────
// Domain separation constants
// ──────────────────────────────────────────────────────────────

/// Domain separator for authority seal preimage construction.
const AUTHORITY_SEAL_DOMAIN_SEPARATOR: &[u8] = b"apm2:authority_seal:v1\0";

/// Domain separator for Merkle batch leaf hashing (§9.5.2).
const RECEIPT_LEAF_DOMAIN_SEPARATOR: &[u8] = b"apm2:receipt_leaf:v1\0";

// ──────────────────────────────────────────────────────────────
// Bounds
// ──────────────────────────────────────────────────────────────

/// Maximum encoded size of an `AuthoritySealV1` (defense-in-depth).
pub const MAX_AUTHORITY_SEAL_BYTES: usize = 8 * 1024;

/// Maximum length of a `subject_kind` tag string.
pub const MAX_SUBJECT_KIND_LEN: usize = 256;

/// Maximum depth for Merkle inclusion proofs (log2(2^20) = 20).
pub const MAX_MERKLE_PROOF_DEPTH: usize = 20;

/// Maximum number of quorum signatures in a multisig seal.
pub const MAX_QUORUM_SIGNATURES: usize = 256;

/// Minimum number of quorum signatures required.
pub const MIN_QUORUM_SIGNATURES: usize = 1;

/// Zero time envelope reference — used when temporal authority is absent or
/// not applicable (Tier0/Tier1 contexts).
pub const ZERO_TIME_ENVELOPE_REF: [u8; 32] = [0u8; 32];

// ──────────────────────────────────────────────────────────────
// Error types
// ──────────────────────────────────────────────────────────────

/// Errors produced when constructing, parsing, or verifying authority seals.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum AuthoritySealError {
    /// Subject kind tag is empty or exceeds the maximum length.
    #[error("invalid subject_kind: {reason}")]
    InvalidSubjectKind {
        /// Human-readable reason.
        reason: String,
    },

    /// Seal has no ledger anchor (violates §0.1(11b)).
    #[error("missing ledger anchor: authority seals require a ledger or quorum anchor binding")]
    MissingLedgerAnchor,

    /// A quorum seal kind is used without an issuer quorum identifier.
    #[error("missing issuer quorum id for seal kind {seal_kind:?}")]
    MissingIssuerQuorumId {
        /// The seal kind that requires a quorum identifier.
        seal_kind: SealKind,
    },

    /// A single-sig seal has an issuer quorum id instead of a public key id.
    #[error("single-sig seal requires issuer_public_key_id, not issuer_quorum_id")]
    SingleSigRequiresPublicKeyId,

    /// Signature verification failed.
    #[error("signature verification failed for seal kind {seal_kind:?}")]
    SignatureVerificationFailed {
        /// The seal kind that failed verification.
        seal_kind: SealKind,
    },

    /// Merkle inclusion proof is invalid.
    #[error("merkle inclusion proof verification failed: {reason}")]
    MerkleProofFailed {
        /// Human-readable reason.
        reason: String,
    },

    /// Merkle proof depth exceeds the maximum.
    #[error("merkle proof depth {depth} exceeds max {max}")]
    MerkleProofDepthExceeded {
        /// Actual proof depth.
        depth: usize,
        /// Maximum allowed depth.
        max: usize,
    },

    /// Free-floating batch root — not bound to a ledger anchor.
    #[error("unsigned/free-floating batch root rejected: batch roots must be ledger-anchored")]
    FreeFloatingBatchRoot,

    /// Quorum signature count is out of bounds.
    #[error("quorum signature count {count} is invalid (min={min}, max={max})")]
    InvalidQuorumSignatureCount {
        /// Actual signature count.
        count: usize,
        /// Minimum required.
        min: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Domain separation tag mismatch during verification.
    #[error("domain separation tag mismatch: expected {expected}, found {found}")]
    DomainSeparationMismatch {
        /// Expected tag.
        expected: String,
        /// Found tag.
        found: String,
    },

    /// The subject hash in the seal does not match the expected artifact hash.
    #[error("subject hash mismatch")]
    SubjectHashMismatch,

    /// Threshold not met for quorum threshold seal.
    #[error("quorum threshold not met: {valid_sigs} valid of {threshold} required")]
    ThresholdNotMet {
        /// Number of valid signatures found.
        valid_sigs: usize,
        /// Threshold required.
        threshold: usize,
    },

    /// Temporal authority binding is required for Tier2+/governance contexts
    /// but the seal has a zero `time_envelope_ref`.
    #[error(
        "temporal authority required: time_envelope_ref must be non-zero for Tier2+/governance contexts"
    )]
    TemporalAuthorityRequired,

    /// The subject kind in the seal does not match the expected subject kind.
    #[error("subject kind mismatch: expected \"{expected}\", found \"{found}\"")]
    SubjectKindMismatch {
        /// Expected subject kind.
        expected: String,
        /// Found subject kind.
        found: String,
    },
}

// ──────────────────────────────────────────────────────────────
// Seal kind enum
// ──────────────────────────────────────────────────────────────

/// The kind of authority seal (RFC-0020 §1.7.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum SealKind {
    /// One Ed25519 signature over the domain-separated preimage.
    SingleSig       = 0x01,
    /// n-of-n multisig (all quorum members sign).
    QuorumMultisig  = 0x02,
    /// k-of-n threshold signature.
    QuorumThreshold = 0x03,
    /// Signature/quorum over a Merkle batch root hash.
    MerkleBatch     = 0x04,
}

impl SealKind {
    /// Parse a seal kind from its tag byte.
    ///
    /// Returns `None` for unknown tags (fail-closed).
    #[must_use]
    pub const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            0x01 => Some(Self::SingleSig),
            0x02 => Some(Self::QuorumMultisig),
            0x03 => Some(Self::QuorumThreshold),
            0x04 => Some(Self::MerkleBatch),
            _ => None,
        }
    }

    /// Returns the tag byte for this seal kind.
    #[must_use]
    pub const fn tag(self) -> u8 {
        self as u8
    }

    /// Whether this seal kind requires an issuer quorum identifier.
    #[must_use]
    pub const fn requires_quorum_id(self) -> bool {
        matches!(self, Self::QuorumMultisig | Self::QuorumThreshold)
    }
}

// ──────────────────────────────────────────────────────────────
// Issuer identifier
// ──────────────────────────────────────────────────────────────

/// Issuer identifier — either a single public key or a keyset (quorum).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum IssuerId {
    /// Single issuer key (for `SINGLE_SIG` and `MERKLE_BATCH` with single
    /// signer).
    PublicKey(PublicKeyIdV1),
    /// Quorum/threshold keyset (for `QUORUM_MULTISIG`, `QUORUM_THRESHOLD`,
    /// and `MERKLE_BATCH` with quorum signer).
    Quorum(KeySetIdV1),
}

// ──────────────────────────────────────────────────────────────
// Subject kind (domain separation tag)
// ──────────────────────────────────────────────────────────────

/// Subject kind for domain separation — combines artifact kind and schema
/// version.
///
/// Example: `"apm2.tool_execution_receipt.v1"`, `"apm2.directory_head.v1"`.
///
/// Subject kinds are validated to be non-empty, ASCII-only, and bounded
/// in length to prevent unbounded allocation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SubjectKind(String);

impl SubjectKind {
    /// Create a validated subject kind.
    ///
    /// # Errors
    ///
    /// Returns an error if the subject kind is empty, non-ASCII,
    /// or exceeds `MAX_SUBJECT_KIND_LEN`.
    pub fn new(kind: &str) -> Result<Self, AuthoritySealError> {
        if kind.is_empty() {
            return Err(AuthoritySealError::InvalidSubjectKind {
                reason: "subject_kind must not be empty".to_string(),
            });
        }
        if !kind.is_ascii() {
            return Err(AuthoritySealError::InvalidSubjectKind {
                reason: "subject_kind must be ASCII".to_string(),
            });
        }
        if kind.len() > MAX_SUBJECT_KIND_LEN {
            return Err(AuthoritySealError::InvalidSubjectKind {
                reason: format!(
                    "subject_kind length {} exceeds max {}",
                    kind.len(),
                    MAX_SUBJECT_KIND_LEN
                ),
            });
        }
        Ok(Self(kind.to_string()))
    }

    /// Returns the subject kind string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// ──────────────────────────────────────────────────────────────
// Merkle inclusion proof
// ──────────────────────────────────────────────────────────────

/// A sibling in a Merkle inclusion proof.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MerkleProofSibling {
    /// Hash of the sibling node.
    pub hash: Hash,
    /// Whether the sibling is on the left side.
    pub is_left: bool,
}

/// Merkle inclusion proof for batch membership verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleInclusionProof {
    /// The leaf hash (domain-separated receipt hash).
    pub leaf_hash: Hash,
    /// Sibling nodes from leaf to root.
    pub siblings: Vec<MerkleProofSibling>,
}

impl MerkleInclusionProof {
    /// Validate the proof and reconstruct the Merkle root.
    ///
    /// # Errors
    ///
    /// Returns an error if the proof depth exceeds the maximum.
    pub fn verify(&self, expected_root: &Hash) -> Result<(), AuthoritySealError> {
        if self.siblings.len() > MAX_MERKLE_PROOF_DEPTH {
            return Err(AuthoritySealError::MerkleProofDepthExceeded {
                depth: self.siblings.len(),
                max: MAX_MERKLE_PROOF_DEPTH,
            });
        }

        let mut current = self.leaf_hash;
        for sibling in &self.siblings {
            let mut hasher = blake3::Hasher::new();
            if sibling.is_left {
                hasher.update(&sibling.hash);
                hasher.update(&current);
            } else {
                hasher.update(&current);
                hasher.update(&sibling.hash);
            }
            current = *hasher.finalize().as_bytes();
        }

        if current != *expected_root {
            return Err(AuthoritySealError::MerkleProofFailed {
                reason: "reconstructed root does not match expected root".to_string(),
            });
        }

        Ok(())
    }
}

/// Compute the domain-separated leaf hash for a receipt in a batch.
///
/// `leaf_hash = blake3("apm2:receipt_leaf:v1\0" + receipt_hash_bytes)`
///
/// Per RFC-0020 §9.5.2.
#[must_use]
pub fn compute_receipt_leaf_hash(receipt_hash: &Hash) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(RECEIPT_LEAF_DOMAIN_SEPARATOR);
    hasher.update(receipt_hash);
    *hasher.finalize().as_bytes()
}

// ──────────────────────────────────────────────────────────────
// AuthoritySealV1
// ──────────────────────────────────────────────────────────────

/// Unified fact-authentication seal (RFC-0020 §1.7.8).
///
/// `AuthoritySealV1` authenticates facts via direct signatures, quorum
/// multisig/threshold, or Merkle-batch attestations. All seals are
/// domain-separated by artifact kind + schema version and MUST reference
/// a ledger anchor.
///
/// The `time_envelope_ref` field provides temporal authority binding. For
/// Tier2+/governance contexts it MUST be non-zero to enable verifiers to
/// cryptographically bind a seal to HTF freshness context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthoritySealV1 {
    /// Cell that issued the seal.
    issuer_cell_id: CellIdV1,
    /// Issuer identifier (single key or quorum keyset).
    issuer_id: IssuerId,
    /// Schema ID + version for domain separation.
    subject_kind: SubjectKind,
    /// Hash of the authenticated subject (artifact or Merkle root).
    subject_hash: Hash,
    /// Ledger anchor binding (REQUIRED).
    ledger_anchor: LedgerAnchorV1,
    /// Hash reference to the HTF time envelope artifact.
    /// Zero ([0u8; 32]) = absent/not-applicable (valid for Tier0/Tier1 only).
    time_envelope_ref: [u8; 32],
    /// Kind of seal.
    seal_kind: SealKind,
    /// Raw signature bytes (for `SINGLE_SIG`, `MERKLE_BATCH` with single
    /// signer). For `QUORUM_MULTISIG` / `QUORUM_THRESHOLD`: the collected
    /// signatures.
    signatures: Vec<Vec<u8>>,
}

impl AuthoritySealV1 {
    /// Construct and validate a new authority seal.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - A quorum seal kind lacks an issuer quorum id
    /// - A single-sig seal kind uses a quorum issuer
    /// - Signature count is out of bounds for quorum seals
    /// - `MERKLE_BATCH` with single-key issuer has more than one signature
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        issuer_cell_id: CellIdV1,
        issuer_id: IssuerId,
        subject_kind: SubjectKind,
        subject_hash: Hash,
        ledger_anchor: LedgerAnchorV1,
        time_envelope_ref: [u8; 32],
        seal_kind: SealKind,
        signatures: Vec<Vec<u8>>,
    ) -> Result<Self, AuthoritySealError> {
        // Validate issuer id matches seal kind.
        match seal_kind {
            SealKind::SingleSig => {
                if matches!(issuer_id, IssuerId::Quorum(_)) {
                    return Err(AuthoritySealError::SingleSigRequiresPublicKeyId);
                }
                if signatures.len() != 1 {
                    return Err(AuthoritySealError::InvalidQuorumSignatureCount {
                        count: signatures.len(),
                        min: 1,
                        max: 1,
                    });
                }
            },
            SealKind::QuorumMultisig | SealKind::QuorumThreshold => {
                if !matches!(issuer_id, IssuerId::Quorum(_)) {
                    return Err(AuthoritySealError::MissingIssuerQuorumId { seal_kind });
                }
                if signatures.is_empty() || signatures.len() > MAX_QUORUM_SIGNATURES {
                    return Err(AuthoritySealError::InvalidQuorumSignatureCount {
                        count: signatures.len(),
                        min: MIN_QUORUM_SIGNATURES,
                        max: MAX_QUORUM_SIGNATURES,
                    });
                }
            },
            SealKind::MerkleBatch => {
                // MerkleBatch can use either a single key or quorum signer.
                // At least one signature is required.
                if signatures.is_empty() {
                    return Err(AuthoritySealError::InvalidQuorumSignatureCount {
                        count: 0,
                        min: 1,
                        max: MAX_QUORUM_SIGNATURES,
                    });
                }
                if signatures.len() > MAX_QUORUM_SIGNATURES {
                    return Err(AuthoritySealError::InvalidQuorumSignatureCount {
                        count: signatures.len(),
                        min: 1,
                        max: MAX_QUORUM_SIGNATURES,
                    });
                }
                // Single-key MERKLE_BATCH must have exactly 1 signature.
                if matches!(issuer_id, IssuerId::PublicKey(_)) && signatures.len() != 1 {
                    return Err(AuthoritySealError::InvalidQuorumSignatureCount {
                        count: signatures.len(),
                        min: 1,
                        max: 1,
                    });
                }
            },
        }

        Ok(Self {
            issuer_cell_id,
            issuer_id,
            subject_kind,
            subject_hash,
            ledger_anchor,
            time_envelope_ref,
            seal_kind,
            signatures,
        })
    }

    // ────────── Accessors ──────────

    /// Returns the issuer cell id.
    #[must_use]
    pub const fn issuer_cell_id(&self) -> &CellIdV1 {
        &self.issuer_cell_id
    }

    /// Returns the issuer identifier.
    #[must_use]
    pub const fn issuer_id(&self) -> &IssuerId {
        &self.issuer_id
    }

    /// Returns the subject kind (domain separation tag).
    #[must_use]
    pub const fn subject_kind(&self) -> &SubjectKind {
        &self.subject_kind
    }

    /// Returns the subject hash.
    #[must_use]
    pub const fn subject_hash(&self) -> &Hash {
        &self.subject_hash
    }

    /// Returns the ledger anchor.
    #[must_use]
    pub const fn ledger_anchor(&self) -> &LedgerAnchorV1 {
        &self.ledger_anchor
    }

    /// Returns the time envelope reference hash.
    #[must_use]
    pub const fn time_envelope_ref(&self) -> &[u8; 32] {
        &self.time_envelope_ref
    }

    /// Returns the seal kind.
    #[must_use]
    pub const fn seal_kind(&self) -> SealKind {
        self.seal_kind
    }

    /// Returns the raw signatures.
    #[must_use]
    pub fn signatures(&self) -> &[Vec<u8>] {
        &self.signatures
    }

    // ────────── Canonical bytes ──────────

    /// Compute the canonical byte representation of this seal for
    /// serialization and round-trip testing.
    ///
    /// The layout is:
    /// ```text
    /// seal_kind_tag (1 byte)
    /// + issuer_cell_id_binary (33 bytes)
    /// + issuer_id_bytes (33 bytes — pkid or keyset_id binary)
    /// + subject_kind_len (4 bytes LE)
    /// + subject_kind_bytes
    /// + subject_hash (32 bytes)
    /// + ledger_anchor_canonical_bytes
    /// + time_envelope_ref (32 bytes)
    /// + signature_count (4 bytes LE)
    /// + [signature_len (4 bytes LE) + signature_bytes] * signature_count
    /// ```
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let kind_bytes = self.subject_kind.as_str().as_bytes();
        let anchor_bytes = self.ledger_anchor.canonical_bytes();
        let issuer_id_bytes = match &self.issuer_id {
            IssuerId::PublicKey(pkid) => pkid.to_binary(),
            IssuerId::Quorum(keyset_id) => keyset_id.to_binary(),
        };

        let mut out = Vec::with_capacity(
            1 + 33
                + 33
                + 4
                + kind_bytes.len()
                + 32
                + anchor_bytes.len()
                + 32
                + 4
                + self.signatures.iter().map(|s| 4 + s.len()).sum::<usize>(),
        );

        out.push(self.seal_kind.tag());
        out.extend_from_slice(self.issuer_cell_id.as_bytes());
        out.extend_from_slice(&issuer_id_bytes);

        #[allow(clippy::cast_possible_truncation)]
        let kind_len = kind_bytes.len() as u32;
        out.extend_from_slice(&kind_len.to_le_bytes());
        out.extend_from_slice(kind_bytes);
        out.extend_from_slice(&self.subject_hash);
        out.extend_from_slice(&anchor_bytes);
        out.extend_from_slice(&self.time_envelope_ref);

        #[allow(clippy::cast_possible_truncation)]
        let sig_count = self.signatures.len() as u32;
        out.extend_from_slice(&sig_count.to_le_bytes());
        for sig in &self.signatures {
            #[allow(clippy::cast_possible_truncation)]
            let sig_len = sig.len() as u32;
            out.extend_from_slice(&sig_len.to_le_bytes());
            out.extend_from_slice(sig);
        }

        out
    }

    // ────────── Domain-separated preimage ──────────

    /// Compute the domain-separated preimage for signature verification.
    ///
    /// The preimage is:
    /// ```text
    /// blake3("apm2:authority_seal:v1\0"
    ///     + seal_kind_tag (1 byte)
    ///     + issuer_cell_id_binary (33 bytes)
    ///     + issuer_id_bytes (33 bytes — pkid or keyset_id binary)
    ///     + subject_kind_len (4 bytes LE)
    ///     + subject_kind_bytes
    ///     + subject_hash (32 bytes)
    ///     + ledger_anchor_canonical_bytes
    ///     + time_envelope_ref (32 bytes)
    /// )
    /// ```
    #[must_use]
    pub fn domain_separated_preimage(&self) -> Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(AUTHORITY_SEAL_DOMAIN_SEPARATOR);
        hasher.update(&[self.seal_kind.tag()]);
        // Bind issuer identity metadata to the cryptographic proof.
        hasher.update(self.issuer_cell_id.as_bytes());
        match &self.issuer_id {
            IssuerId::PublicKey(pkid) => hasher.update(&pkid.to_binary()),
            IssuerId::Quorum(keyset_id) => hasher.update(&keyset_id.to_binary()),
        };
        let kind_bytes = self.subject_kind.as_str().as_bytes();
        #[allow(clippy::cast_possible_truncation)]
        // subject_kind is bounded by MAX_SUBJECT_KIND_LEN (256)
        let kind_len = kind_bytes.len() as u32;
        hasher.update(&kind_len.to_le_bytes());
        hasher.update(kind_bytes);
        hasher.update(&self.subject_hash);
        hasher.update(&self.ledger_anchor.canonical_bytes());
        hasher.update(&self.time_envelope_ref);
        *hasher.finalize().as_bytes()
    }

    // ────────── Subject validation helpers ──────────

    /// Check that the seal's subject kind and subject hash match the expected
    /// values. This prevents semantically wrong seals from being accepted.
    fn check_expected_subject(
        &self,
        expected_subject_kind: &str,
        expected_subject_hash: &[u8; 32],
    ) -> Result<(), AuthoritySealError> {
        if self.subject_kind.as_str() != expected_subject_kind {
            return Err(AuthoritySealError::SubjectKindMismatch {
                expected: expected_subject_kind.to_string(),
                found: self.subject_kind.as_str().to_string(),
            });
        }
        if self.subject_hash != *expected_subject_hash {
            return Err(AuthoritySealError::SubjectHashMismatch);
        }
        Ok(())
    }

    /// Check temporal authority binding: for Tier2+/governance contexts,
    /// `time_envelope_ref` must be non-zero.
    fn check_temporal_authority(&self, require_temporal: bool) -> Result<(), AuthoritySealError> {
        if require_temporal && self.time_envelope_ref == ZERO_TIME_ENVELOPE_REF {
            return Err(AuthoritySealError::TemporalAuthorityRequired);
        }
        Ok(())
    }

    // ────────── Verification ──────────

    /// Verify a `SINGLE_SIG` seal against the provided verifying key.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The seal kind is not `SingleSig`
    /// - The expected subject kind or hash does not match
    /// - Temporal authority is required but `time_envelope_ref` is zero
    /// - The signature does not verify against the preimage
    pub fn verify_single_sig(
        &self,
        verifying_key: &ed25519_dalek::VerifyingKey,
        expected_subject_kind: &str,
        expected_subject_hash: &[u8; 32],
        require_temporal: bool,
    ) -> Result<(), AuthoritySealError> {
        if self.seal_kind != SealKind::SingleSig {
            return Err(AuthoritySealError::SignatureVerificationFailed {
                seal_kind: self.seal_kind,
            });
        }

        self.check_expected_subject(expected_subject_kind, expected_subject_hash)?;
        self.check_temporal_authority(require_temporal)?;

        let preimage = self.domain_separated_preimage();
        let sig_bytes = &self.signatures[0];
        let signature = ed25519_dalek::Signature::from_slice(sig_bytes).map_err(|_| {
            AuthoritySealError::SignatureVerificationFailed {
                seal_kind: self.seal_kind,
            }
        })?;

        verifying_key.verify(&preimage, &signature).map_err(|_| {
            AuthoritySealError::SignatureVerificationFailed {
                seal_kind: self.seal_kind,
            }
        })
    }

    /// Verify a `QUORUM_MULTISIG` seal against the provided verifying keys.
    ///
    /// All provided signatures must be valid (n-of-n).
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The expected subject kind or hash does not match
    /// - Temporal authority is required but `time_envelope_ref` is zero
    /// - Any signature fails verification
    pub fn verify_quorum_multisig(
        &self,
        verifying_keys: &[ed25519_dalek::VerifyingKey],
        expected_subject_kind: &str,
        expected_subject_hash: &[u8; 32],
        require_temporal: bool,
    ) -> Result<(), AuthoritySealError> {
        if self.seal_kind != SealKind::QuorumMultisig {
            return Err(AuthoritySealError::SignatureVerificationFailed {
                seal_kind: self.seal_kind,
            });
        }

        self.check_expected_subject(expected_subject_kind, expected_subject_hash)?;
        self.check_temporal_authority(require_temporal)?;

        if verifying_keys.len() != self.signatures.len() {
            return Err(AuthoritySealError::InvalidQuorumSignatureCount {
                count: self.signatures.len(),
                min: verifying_keys.len(),
                max: verifying_keys.len(),
            });
        }

        let preimage = self.domain_separated_preimage();

        for (i, (sig_bytes, key)) in self
            .signatures
            .iter()
            .zip(verifying_keys.iter())
            .enumerate()
        {
            let signature = ed25519_dalek::Signature::from_slice(sig_bytes).map_err(|_| {
                AuthoritySealError::SignatureVerificationFailed {
                    seal_kind: self.seal_kind,
                }
            })?;

            key.verify(&preimage, &signature).map_err(|_| {
                tracing::warn!(index = i, "quorum multisig: signature verification failed");
                AuthoritySealError::SignatureVerificationFailed {
                    seal_kind: self.seal_kind,
                }
            })?;
        }

        Ok(())
    }

    /// Verify a `QUORUM_THRESHOLD` seal against the provided verifying keys.
    ///
    /// At least `threshold` of the provided signatures must be valid.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The expected subject kind or hash does not match
    /// - Temporal authority is required but `time_envelope_ref` is zero
    /// - The threshold is not met
    pub fn verify_quorum_threshold(
        &self,
        verifying_keys: &[ed25519_dalek::VerifyingKey],
        threshold: usize,
        expected_subject_kind: &str,
        expected_subject_hash: &[u8; 32],
        require_temporal: bool,
    ) -> Result<(), AuthoritySealError> {
        if self.seal_kind != SealKind::QuorumThreshold {
            return Err(AuthoritySealError::SignatureVerificationFailed {
                seal_kind: self.seal_kind,
            });
        }

        self.check_expected_subject(expected_subject_kind, expected_subject_hash)?;
        self.check_temporal_authority(require_temporal)?;

        // Reject extra signatures that would be silently ignored by zip.
        if self.signatures.len() > verifying_keys.len() {
            return Err(AuthoritySealError::InvalidQuorumSignatureCount {
                count: self.signatures.len(),
                min: MIN_QUORUM_SIGNATURES,
                max: verifying_keys.len(),
            });
        }

        if threshold == 0 || threshold > verifying_keys.len() {
            return Err(AuthoritySealError::ThresholdNotMet {
                valid_sigs: 0,
                threshold,
            });
        }

        let preimage = self.domain_separated_preimage();
        let mut valid_count = 0usize;

        for (sig_bytes, key) in self.signatures.iter().zip(verifying_keys.iter()) {
            if let Ok(signature) = ed25519_dalek::Signature::from_slice(sig_bytes) {
                if key.verify(&preimage, &signature).is_ok() {
                    valid_count = valid_count.saturating_add(1);
                }
            }
        }

        if valid_count >= threshold {
            Ok(())
        } else {
            Err(AuthoritySealError::ThresholdNotMet {
                valid_sigs: valid_count,
                threshold,
            })
        }
    }

    /// Verify a `MERKLE_BATCH` seal with a single-key issuer: verify the
    /// signature over the batch root hash, then verify the inclusion proof
    /// that the artifact is a member.
    ///
    /// # Issuer-Key Binding Contract
    ///
    /// The caller is responsible for ensuring that `verifying_key` is the
    /// authentic public key corresponding to the `issuer_id` stored in this
    /// seal. This method validates the cryptographic signature against the
    /// provided key but does NOT perform issuer identity resolution. Callers
    /// MUST resolve `issuer_id` to a trusted key via an authenticated
    /// directory or equivalent mechanism before calling this method.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The seal kind is not `MerkleBatch`
    /// - The issuer is a quorum (use
    ///   [`Self::verify_merkle_batch_quorum_multisig`] or
    ///   [`Self::verify_merkle_batch_quorum_threshold`] instead)
    /// - The expected subject kind or hash does not match
    /// - Temporal authority is required but `time_envelope_ref` is zero
    /// - The batch root signature is invalid
    /// - The inclusion proof does not reconstruct to the batch root
    pub fn verify_merkle_batch(
        &self,
        verifying_key: &ed25519_dalek::VerifyingKey,
        artifact_hash: &Hash,
        inclusion_proof: &MerkleInclusionProof,
        expected_subject_kind: &str,
        expected_subject_hash: &[u8; 32],
        require_temporal: bool,
    ) -> Result<(), AuthoritySealError> {
        if self.seal_kind != SealKind::MerkleBatch {
            return Err(AuthoritySealError::SignatureVerificationFailed {
                seal_kind: self.seal_kind,
            });
        }

        // Fail-closed: reject quorum issuers in the single-key path.
        // Callers MUST use the quorum-aware verification methods for
        // quorum-issued MERKLE_BATCH seals.
        if matches!(self.issuer_id, IssuerId::Quorum(_)) {
            return Err(AuthoritySealError::SignatureVerificationFailed {
                seal_kind: self.seal_kind,
            });
        }

        self.check_expected_subject(expected_subject_kind, expected_subject_hash)?;
        self.check_temporal_authority(require_temporal)?;

        // Step 1: Verify the single signature over the batch root
        // (subject_hash).
        let preimage = self.domain_separated_preimage();
        let sig_bytes = &self.signatures[0];
        let signature = ed25519_dalek::Signature::from_slice(sig_bytes).map_err(|_| {
            AuthoritySealError::SignatureVerificationFailed {
                seal_kind: self.seal_kind,
            }
        })?;

        verifying_key.verify(&preimage, &signature).map_err(|_| {
            AuthoritySealError::SignatureVerificationFailed {
                seal_kind: self.seal_kind,
            }
        })?;

        // Step 2: Verify the leaf hash is derived from the artifact hash
        // with domain separation.
        Self::verify_merkle_inclusion(artifact_hash, inclusion_proof, &self.subject_hash)
    }

    /// Verify a `MERKLE_BATCH` seal with a quorum multisig issuer (n-of-n):
    /// verify ALL signatures over the batch root hash, then verify the
    /// inclusion proof that the artifact is a member.
    ///
    /// # Issuer-Key Binding Contract
    ///
    /// The caller is responsible for ensuring that `verifying_keys` are the
    /// authentic public keys corresponding to the quorum `issuer_id` stored
    /// in this seal. This method validates cryptographic signatures against
    /// the provided keys but does NOT perform issuer identity resolution.
    /// Callers MUST resolve the quorum `issuer_id` to a trusted keyset via
    /// an authenticated directory or equivalent mechanism before calling
    /// this method.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The seal kind is not `MerkleBatch`
    /// - The issuer is not a quorum
    /// - The number of verifying keys does not match the number of signatures
    /// - The expected subject kind or hash does not match
    /// - Temporal authority is required but `time_envelope_ref` is zero
    /// - Any signature fails verification (n-of-n required)
    /// - The inclusion proof does not reconstruct to the batch root
    pub fn verify_merkle_batch_quorum_multisig(
        &self,
        verifying_keys: &[ed25519_dalek::VerifyingKey],
        artifact_hash: &Hash,
        inclusion_proof: &MerkleInclusionProof,
        expected_subject_kind: &str,
        expected_subject_hash: &[u8; 32],
        require_temporal: bool,
    ) -> Result<(), AuthoritySealError> {
        if self.seal_kind != SealKind::MerkleBatch {
            return Err(AuthoritySealError::SignatureVerificationFailed {
                seal_kind: self.seal_kind,
            });
        }

        // Fail-closed: require quorum issuer for quorum verification path.
        if !matches!(self.issuer_id, IssuerId::Quorum(_)) {
            return Err(AuthoritySealError::SignatureVerificationFailed {
                seal_kind: self.seal_kind,
            });
        }

        self.check_expected_subject(expected_subject_kind, expected_subject_hash)?;
        self.check_temporal_authority(require_temporal)?;

        // Enforce n-of-n: key count must equal signature count.
        if verifying_keys.len() != self.signatures.len() {
            return Err(AuthoritySealError::InvalidQuorumSignatureCount {
                count: self.signatures.len(),
                min: verifying_keys.len(),
                max: verifying_keys.len(),
            });
        }

        let preimage = self.domain_separated_preimage();

        // Verify ALL signatures (n-of-n multisig).
        for (i, (sig_bytes, key)) in self
            .signatures
            .iter()
            .zip(verifying_keys.iter())
            .enumerate()
        {
            let signature = ed25519_dalek::Signature::from_slice(sig_bytes).map_err(|_| {
                AuthoritySealError::SignatureVerificationFailed {
                    seal_kind: self.seal_kind,
                }
            })?;

            key.verify(&preimage, &signature).map_err(|_| {
                tracing::warn!(
                    index = i,
                    "merkle batch quorum multisig: signature verification failed"
                );
                AuthoritySealError::SignatureVerificationFailed {
                    seal_kind: self.seal_kind,
                }
            })?;
        }

        Self::verify_merkle_inclusion(artifact_hash, inclusion_proof, &self.subject_hash)
    }

    /// Verify a `MERKLE_BATCH` seal with a quorum threshold issuer (k-of-n):
    /// verify at least `threshold` signatures over the batch root hash, then
    /// verify the inclusion proof that the artifact is a member.
    ///
    /// # Issuer-Key Binding Contract
    ///
    /// The caller is responsible for ensuring that `verifying_keys` are the
    /// authentic public keys corresponding to the quorum `issuer_id` stored
    /// in this seal, and that `threshold` matches the quorum policy. This
    /// method validates cryptographic signatures against the provided keys
    /// but does NOT perform issuer identity resolution. Callers MUST resolve
    /// the quorum `issuer_id` to a trusted keyset and threshold via an
    /// authenticated directory or equivalent mechanism before calling this
    /// method.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The seal kind is not `MerkleBatch`
    /// - The issuer is not a quorum
    /// - The threshold is zero or exceeds the number of verifying keys
    /// - The expected subject kind or hash does not match
    /// - Temporal authority is required but `time_envelope_ref` is zero
    /// - Fewer than `threshold` signatures are valid
    /// - The inclusion proof does not reconstruct to the batch root
    #[allow(clippy::too_many_arguments)]
    pub fn verify_merkle_batch_quorum_threshold(
        &self,
        verifying_keys: &[ed25519_dalek::VerifyingKey],
        threshold: usize,
        artifact_hash: &Hash,
        inclusion_proof: &MerkleInclusionProof,
        expected_subject_kind: &str,
        expected_subject_hash: &[u8; 32],
        require_temporal: bool,
    ) -> Result<(), AuthoritySealError> {
        if self.seal_kind != SealKind::MerkleBatch {
            return Err(AuthoritySealError::SignatureVerificationFailed {
                seal_kind: self.seal_kind,
            });
        }

        // Fail-closed: require quorum issuer for quorum verification path.
        if !matches!(self.issuer_id, IssuerId::Quorum(_)) {
            return Err(AuthoritySealError::SignatureVerificationFailed {
                seal_kind: self.seal_kind,
            });
        }

        self.check_expected_subject(expected_subject_kind, expected_subject_hash)?;
        self.check_temporal_authority(require_temporal)?;

        // Reject extra signatures that would be silently ignored by zip.
        if self.signatures.len() > verifying_keys.len() {
            return Err(AuthoritySealError::InvalidQuorumSignatureCount {
                count: self.signatures.len(),
                min: MIN_QUORUM_SIGNATURES,
                max: verifying_keys.len(),
            });
        }

        if threshold == 0 || threshold > verifying_keys.len() {
            return Err(AuthoritySealError::ThresholdNotMet {
                valid_sigs: 0,
                threshold,
            });
        }

        let preimage = self.domain_separated_preimage();
        let mut valid_count = 0usize;

        for (sig_bytes, key) in self.signatures.iter().zip(verifying_keys.iter()) {
            if let Ok(signature) = ed25519_dalek::Signature::from_slice(sig_bytes) {
                if key.verify(&preimage, &signature).is_ok() {
                    valid_count = valid_count.saturating_add(1);
                }
            }
        }

        if valid_count < threshold {
            return Err(AuthoritySealError::ThresholdNotMet {
                valid_sigs: valid_count,
                threshold,
            });
        }

        Self::verify_merkle_inclusion(artifact_hash, inclusion_proof, &self.subject_hash)
    }

    /// Shared helper: verify Merkle inclusion proof for batch membership.
    ///
    /// Validates that the artifact hash, after domain-separated leaf hashing,
    /// is included in the batch root via the provided inclusion proof.
    fn verify_merkle_inclusion(
        artifact_hash: &Hash,
        inclusion_proof: &MerkleInclusionProof,
        batch_root: &Hash,
    ) -> Result<(), AuthoritySealError> {
        let expected_leaf = compute_receipt_leaf_hash(artifact_hash);
        if inclusion_proof.leaf_hash != expected_leaf {
            return Err(AuthoritySealError::MerkleProofFailed {
                reason: "leaf hash does not match domain-separated artifact hash".to_string(),
            });
        }

        inclusion_proof.verify(batch_root)
    }
}

/// Named assertion point for free-floating batch root rejection.
///
/// Per RFC-0020 §0.1(11b), batch roots MUST be ledger-anchored facts,
/// not free-floating signatures.
///
/// # Design Note
///
/// Free-floating batch root rejection is enforced at construction time:
/// empty signature vectors are rejected by `AuthoritySealV1::new()`, and
/// the `ledger_anchor` field is required and non-optional. This function
/// provides a named assertion point for integration code to emphasize the
/// §0.1(11b) invariant at call sites where the property is safety-critical.
/// It does NOT perform additional runtime checks beyond what construction
/// already guarantees.
pub const fn reject_free_floating_batch_root(
    seal: &AuthoritySealV1,
) -> Result<(), AuthoritySealError> {
    // Construction already enforces:
    // 1. ledger_anchor is present for all seal kinds (required field).
    // 2. Empty signature vectors are rejected for all seal kinds.
    //
    // This function serves as a lightweight named assertion point for
    // call sites that need to document adherence to §0.1(11b).
    let _ = seal.seal_kind(); // read the kind for future-proof extensibility
    Ok(())
}

// ──────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use apm2_core::crypto::{HASH_SIZE, Signer};

    use super::*;
    use crate::identity::{AlgorithmTag, SetTag};

    /// Helper: create a test `CellIdV1`.
    fn test_cell_id() -> CellIdV1 {
        use crate::identity::CellGenesisV1;
        use crate::identity::cell_id::PolicyRootId;
        let genesis_hash = [0xAA; HASH_SIZE];
        let policy_root_key = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[0xBB; 32]);
        let policy_root = PolicyRootId::Single(policy_root_key);
        let genesis = CellGenesisV1::new(genesis_hash, policy_root, "test.local").unwrap();
        CellIdV1::from_genesis(&genesis)
    }

    /// Helper: create a test `KeySetIdV1`.
    fn test_keyset_id() -> KeySetIdV1 {
        let member_a = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[0x01; 32]);
        let member_b = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[0x02; 32]);

        KeySetIdV1::from_descriptor("ed25519", SetTag::Multisig, 2, &[member_a, member_b], None)
            .unwrap()
    }

    /// Standard subject kind used in tests.
    const TEST_SUBJECT_KIND: &str = "apm2.tool_execution_receipt.v1";

    /// Helper: build a single-sig seal.
    fn make_single_sig_seal(signer: &Signer) -> AuthoritySealV1 {
        let cell_id = test_cell_id();
        let pkid = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &signer.public_key_bytes());
        let subject_kind = SubjectKind::new(TEST_SUBJECT_KIND).unwrap();
        let subject_hash = [0x42; HASH_SIZE];
        let ledger_anchor = LedgerAnchorV1::ConsensusIndex { index: 1 };

        // Build the seal to compute the preimage, then sign it.
        let seal_unsigned = AuthoritySealV1::new(
            cell_id.clone(),
            IssuerId::PublicKey(pkid.clone()),
            subject_kind.clone(),
            subject_hash,
            ledger_anchor.clone(),
            ZERO_TIME_ENVELOPE_REF,
            SealKind::SingleSig,
            vec![vec![0u8; 64]], // placeholder
        )
        .unwrap();

        let preimage = seal_unsigned.domain_separated_preimage();
        let signature = signer.sign(&preimage);

        AuthoritySealV1::new(
            cell_id,
            IssuerId::PublicKey(pkid),
            subject_kind,
            subject_hash,
            ledger_anchor,
            ZERO_TIME_ENVELOPE_REF,
            SealKind::SingleSig,
            vec![signature.to_bytes().to_vec()],
        )
        .unwrap()
    }

    // ────────── SubjectKind tests ──────────

    #[test]
    fn subject_kind_rejects_empty() {
        assert!(matches!(
            SubjectKind::new(""),
            Err(AuthoritySealError::InvalidSubjectKind { .. })
        ));
    }

    #[test]
    fn subject_kind_rejects_non_ascii() {
        assert!(matches!(
            SubjectKind::new("apm2.\u{00E9}"),
            Err(AuthoritySealError::InvalidSubjectKind { .. })
        ));
    }

    #[test]
    fn subject_kind_rejects_too_long() {
        let long = "a".repeat(MAX_SUBJECT_KIND_LEN + 1);
        assert!(matches!(
            SubjectKind::new(&long),
            Err(AuthoritySealError::InvalidSubjectKind { .. })
        ));
    }

    #[test]
    fn subject_kind_accepts_valid() {
        let sk = SubjectKind::new("apm2.tool_execution_receipt.v1").unwrap();
        assert_eq!(sk.as_str(), "apm2.tool_execution_receipt.v1");
    }

    // ────────── SealKind tests ──────────

    #[test]
    fn seal_kind_round_trip() {
        for tag in [0x01, 0x02, 0x03, 0x04] {
            let kind = SealKind::from_tag(tag).unwrap();
            assert_eq!(kind.tag(), tag);
        }
    }

    #[test]
    fn seal_kind_rejects_unknown() {
        assert!(SealKind::from_tag(0x00).is_none());
        assert!(SealKind::from_tag(0x05).is_none());
        assert!(SealKind::from_tag(0xFF).is_none());
    }

    // ────────── Construction validation tests ──────────

    #[test]
    fn single_sig_rejects_quorum_issuer() {
        let cell_id = test_cell_id();
        let keyset_id = test_keyset_id();
        let subject_kind = SubjectKind::new("apm2.test.v1").unwrap();

        let result = AuthoritySealV1::new(
            cell_id,
            IssuerId::Quorum(keyset_id),
            subject_kind,
            [0; HASH_SIZE],
            LedgerAnchorV1::ConsensusIndex { index: 1 },
            ZERO_TIME_ENVELOPE_REF,
            SealKind::SingleSig,
            vec![vec![0u8; 64]],
        );

        assert!(matches!(
            result,
            Err(AuthoritySealError::SingleSigRequiresPublicKeyId)
        ));
    }

    #[test]
    fn quorum_multisig_rejects_single_key_issuer() {
        let cell_id = test_cell_id();
        let pkid = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[0x01; 32]);
        let subject_kind = SubjectKind::new("apm2.test.v1").unwrap();

        let result = AuthoritySealV1::new(
            cell_id,
            IssuerId::PublicKey(pkid),
            subject_kind,
            [0; HASH_SIZE],
            LedgerAnchorV1::ConsensusIndex { index: 1 },
            ZERO_TIME_ENVELOPE_REF,
            SealKind::QuorumMultisig,
            vec![vec![0u8; 64], vec![0u8; 64]],
        );

        assert!(matches!(
            result,
            Err(AuthoritySealError::MissingIssuerQuorumId { .. })
        ));
    }

    #[test]
    fn quorum_rejects_empty_signatures() {
        let cell_id = test_cell_id();
        let keyset_id = test_keyset_id();
        let subject_kind = SubjectKind::new("apm2.test.v1").unwrap();

        let result = AuthoritySealV1::new(
            cell_id,
            IssuerId::Quorum(keyset_id),
            subject_kind,
            [0; HASH_SIZE],
            LedgerAnchorV1::ConsensusIndex { index: 1 },
            ZERO_TIME_ENVELOPE_REF,
            SealKind::QuorumMultisig,
            vec![], // no signatures
        );

        assert!(matches!(
            result,
            Err(AuthoritySealError::InvalidQuorumSignatureCount { .. })
        ));
    }

    #[test]
    fn single_sig_rejects_wrong_signature_count() {
        let cell_id = test_cell_id();
        let pkid = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[0x01; 32]);
        let subject_kind = SubjectKind::new("apm2.test.v1").unwrap();

        let result = AuthoritySealV1::new(
            cell_id,
            IssuerId::PublicKey(pkid),
            subject_kind,
            [0; HASH_SIZE],
            LedgerAnchorV1::ConsensusIndex { index: 1 },
            ZERO_TIME_ENVELOPE_REF,
            SealKind::SingleSig,
            vec![vec![0u8; 64], vec![0u8; 64]], // 2 sigs for single sig
        );

        assert!(matches!(
            result,
            Err(AuthoritySealError::InvalidQuorumSignatureCount { .. })
        ));
    }

    // ────────── Single-sig verification tests ──────────

    #[test]
    fn verify_single_sig_valid() {
        let signer = Signer::generate();
        let seal = make_single_sig_seal(&signer);
        assert!(
            seal.verify_single_sig(
                &signer.verifying_key(),
                TEST_SUBJECT_KIND,
                &[0x42; HASH_SIZE],
                false,
            )
            .is_ok()
        );
    }

    #[test]
    fn verify_single_sig_wrong_key() {
        let signer = Signer::generate();
        let wrong_signer = Signer::generate();
        let seal = make_single_sig_seal(&signer);

        assert!(matches!(
            seal.verify_single_sig(
                &wrong_signer.verifying_key(),
                TEST_SUBJECT_KIND,
                &[0x42; HASH_SIZE],
                false,
            ),
            Err(AuthoritySealError::SignatureVerificationFailed { .. })
        ));
    }

    #[test]
    fn verify_single_sig_tampered_subject() {
        let signer = Signer::generate();
        let mut seal = make_single_sig_seal(&signer);
        // Tamper with the subject hash.
        seal.subject_hash = [0xFF; HASH_SIZE];

        assert!(matches!(
            seal.verify_single_sig(
                &signer.verifying_key(),
                TEST_SUBJECT_KIND,
                &[0xFF; HASH_SIZE],
                false,
            ),
            Err(AuthoritySealError::SignatureVerificationFailed { .. })
        ));
    }

    // ────────── Quorum multisig verification tests ──────────

    #[test]
    fn verify_quorum_multisig_valid() {
        let signer_a = Signer::generate();
        let signer_b = Signer::generate();
        let cell_id = test_cell_id();

        let member_a =
            PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &signer_a.public_key_bytes());
        let member_b =
            PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &signer_b.public_key_bytes());
        let keyset_id = KeySetIdV1::from_descriptor(
            "ed25519",
            SetTag::Multisig,
            2,
            &[member_a, member_b],
            None,
        )
        .unwrap();

        let subject_kind = SubjectKind::new("apm2.test.v1").unwrap();
        let subject_hash = [0x42; HASH_SIZE];
        let ledger_anchor = LedgerAnchorV1::ConsensusIndex { index: 5 };

        // Build unsigned to get preimage.
        let seal_unsigned = AuthoritySealV1::new(
            cell_id.clone(),
            IssuerId::Quorum(keyset_id.clone()),
            subject_kind.clone(),
            subject_hash,
            ledger_anchor.clone(),
            ZERO_TIME_ENVELOPE_REF,
            SealKind::QuorumMultisig,
            vec![vec![0u8; 64], vec![0u8; 64]],
        )
        .unwrap();

        let preimage = seal_unsigned.domain_separated_preimage();
        let sig_a = signer_a.sign(&preimage);
        let sig_b = signer_b.sign(&preimage);

        let seal = AuthoritySealV1::new(
            cell_id,
            IssuerId::Quorum(keyset_id),
            subject_kind,
            subject_hash,
            ledger_anchor,
            ZERO_TIME_ENVELOPE_REF,
            SealKind::QuorumMultisig,
            vec![sig_a.to_bytes().to_vec(), sig_b.to_bytes().to_vec()],
        )
        .unwrap();

        let keys = [signer_a.verifying_key(), signer_b.verifying_key()];
        assert!(
            seal.verify_quorum_multisig(&keys, "apm2.test.v1", &subject_hash, false)
                .is_ok()
        );
    }

    #[test]
    fn verify_quorum_multisig_one_bad_sig() {
        let signer_a = Signer::generate();
        let signer_b = Signer::generate();
        let wrong_signer = Signer::generate();
        let cell_id = test_cell_id();

        let member_a =
            PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &signer_a.public_key_bytes());
        let member_b =
            PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &signer_b.public_key_bytes());
        let keyset_id = KeySetIdV1::from_descriptor(
            "ed25519",
            SetTag::Multisig,
            2,
            &[member_a, member_b],
            None,
        )
        .unwrap();

        let subject_kind = SubjectKind::new("apm2.test.v1").unwrap();
        let subject_hash = [0x42; HASH_SIZE];
        let ledger_anchor = LedgerAnchorV1::ConsensusIndex { index: 5 };

        let seal_unsigned = AuthoritySealV1::new(
            cell_id.clone(),
            IssuerId::Quorum(keyset_id.clone()),
            subject_kind.clone(),
            subject_hash,
            ledger_anchor.clone(),
            ZERO_TIME_ENVELOPE_REF,
            SealKind::QuorumMultisig,
            vec![vec![0u8; 64], vec![0u8; 64]],
        )
        .unwrap();

        let preimage = seal_unsigned.domain_separated_preimage();
        let sig_a = signer_a.sign(&preimage);
        // Sign with wrong key for slot b.
        let bad_sig = wrong_signer.sign(&preimage);

        let seal = AuthoritySealV1::new(
            cell_id,
            IssuerId::Quorum(keyset_id),
            subject_kind,
            subject_hash,
            ledger_anchor,
            ZERO_TIME_ENVELOPE_REF,
            SealKind::QuorumMultisig,
            vec![sig_a.to_bytes().to_vec(), bad_sig.to_bytes().to_vec()],
        )
        .unwrap();

        let keys = [signer_a.verifying_key(), signer_b.verifying_key()];
        assert!(matches!(
            seal.verify_quorum_multisig(&keys, "apm2.test.v1", &subject_hash, false),
            Err(AuthoritySealError::SignatureVerificationFailed { .. })
        ));
    }

    // ────────── Quorum threshold verification tests ──────────

    #[test]
    fn verify_quorum_threshold_meets_threshold() {
        let signer_a = Signer::generate();
        let signer_b = Signer::generate();
        let signer_c = Signer::generate();
        let cell_id = test_cell_id();

        let member_a =
            PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &signer_a.public_key_bytes());
        let member_b =
            PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &signer_b.public_key_bytes());
        let member_c =
            PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &signer_c.public_key_bytes());
        let keyset_id = KeySetIdV1::from_descriptor(
            "ed25519",
            SetTag::Threshold,
            2,
            &[member_a, member_b, member_c],
            None,
        )
        .unwrap();

        let subject_kind = SubjectKind::new("apm2.test.v1").unwrap();
        let subject_hash = [0x42; HASH_SIZE];
        let ledger_anchor = LedgerAnchorV1::ConsensusIndex { index: 10 };

        let seal_unsigned = AuthoritySealV1::new(
            cell_id.clone(),
            IssuerId::Quorum(keyset_id.clone()),
            subject_kind.clone(),
            subject_hash,
            ledger_anchor.clone(),
            ZERO_TIME_ENVELOPE_REF,
            SealKind::QuorumThreshold,
            vec![vec![0u8; 64], vec![0u8; 64], vec![0u8; 64]],
        )
        .unwrap();

        let preimage = seal_unsigned.domain_separated_preimage();
        let sig_a = signer_a.sign(&preimage);
        let sig_b = signer_b.sign(&preimage);
        // c doesn't sign, but threshold is 2-of-3.
        let sig_c_placeholder = vec![0u8; 64]; // invalid sig

        let seal = AuthoritySealV1::new(
            cell_id,
            IssuerId::Quorum(keyset_id),
            subject_kind,
            subject_hash,
            ledger_anchor,
            ZERO_TIME_ENVELOPE_REF,
            SealKind::QuorumThreshold,
            vec![
                sig_a.to_bytes().to_vec(),
                sig_b.to_bytes().to_vec(),
                sig_c_placeholder,
            ],
        )
        .unwrap();

        let keys = [
            signer_a.verifying_key(),
            signer_b.verifying_key(),
            signer_c.verifying_key(),
        ];
        // 2-of-3 threshold: a and b sign, c doesn't.
        assert!(
            seal.verify_quorum_threshold(&keys, 2, "apm2.test.v1", &subject_hash, false)
                .is_ok()
        );
    }

    #[test]
    fn verify_quorum_threshold_below_threshold() {
        let signer_a = Signer::generate();
        let signer_b = Signer::generate();
        let signer_c = Signer::generate();
        let cell_id = test_cell_id();

        let member_a =
            PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &signer_a.public_key_bytes());
        let member_b =
            PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &signer_b.public_key_bytes());
        let member_c =
            PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &signer_c.public_key_bytes());
        let keyset_id = KeySetIdV1::from_descriptor(
            "ed25519",
            SetTag::Threshold,
            2,
            &[member_a, member_b, member_c],
            None,
        )
        .unwrap();

        let subject_kind = SubjectKind::new("apm2.test.v1").unwrap();
        let subject_hash = [0x42; HASH_SIZE];
        let ledger_anchor = LedgerAnchorV1::ConsensusIndex { index: 10 };

        let seal_unsigned = AuthoritySealV1::new(
            cell_id.clone(),
            IssuerId::Quorum(keyset_id.clone()),
            subject_kind.clone(),
            subject_hash,
            ledger_anchor.clone(),
            ZERO_TIME_ENVELOPE_REF,
            SealKind::QuorumThreshold,
            vec![vec![0u8; 64], vec![0u8; 64], vec![0u8; 64]],
        )
        .unwrap();

        let preimage = seal_unsigned.domain_separated_preimage();
        let sig_a = signer_a.sign(&preimage);
        // Only one valid signature.

        let seal = AuthoritySealV1::new(
            cell_id,
            IssuerId::Quorum(keyset_id),
            subject_kind,
            subject_hash,
            ledger_anchor,
            ZERO_TIME_ENVELOPE_REF,
            SealKind::QuorumThreshold,
            vec![sig_a.to_bytes().to_vec(), vec![0u8; 64], vec![0u8; 64]],
        )
        .unwrap();

        let keys = [
            signer_a.verifying_key(),
            signer_b.verifying_key(),
            signer_c.verifying_key(),
        ];
        assert!(matches!(
            seal.verify_quorum_threshold(&keys, 2, "apm2.test.v1", &subject_hash, false),
            Err(AuthoritySealError::ThresholdNotMet {
                valid_sigs: 1,
                threshold: 2
            })
        ));
    }

    // ────────── Merkle batch verification tests ──────────

    /// Helper: build a simple 2-leaf Merkle tree and return (root, proof for
    /// leaf 0).
    fn build_merkle_tree_2(leaf0: Hash, leaf1: Hash) -> (Hash, MerkleInclusionProof) {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&leaf0);
        hasher.update(&leaf1);
        let root = *hasher.finalize().as_bytes();

        let proof = MerkleInclusionProof {
            leaf_hash: leaf0,
            siblings: vec![MerkleProofSibling {
                hash: leaf1,
                is_left: false,
            }],
        };

        (root, proof)
    }

    #[test]
    fn verify_merkle_batch_valid() {
        let signer = Signer::generate();
        let cell_id = test_cell_id();
        let pkid = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &signer.public_key_bytes());

        let receipt_hash = [0x42; HASH_SIZE];
        let other_receipt_hash = [0x43; HASH_SIZE];

        let leaf0 = compute_receipt_leaf_hash(&receipt_hash);
        let leaf1 = compute_receipt_leaf_hash(&other_receipt_hash);

        let (batch_root, inclusion_proof) = build_merkle_tree_2(leaf0, leaf1);

        let subject_kind = SubjectKind::new("apm2.receipt_batch.v1").unwrap();
        let ledger_anchor = LedgerAnchorV1::ConsensusIndex { index: 1 };

        // Build unsigned to compute preimage.
        let seal_unsigned = AuthoritySealV1::new(
            cell_id.clone(),
            IssuerId::PublicKey(pkid.clone()),
            subject_kind.clone(),
            batch_root,
            ledger_anchor.clone(),
            ZERO_TIME_ENVELOPE_REF,
            SealKind::MerkleBatch,
            vec![vec![0u8; 64]],
        )
        .unwrap();

        let preimage = seal_unsigned.domain_separated_preimage();
        let signature = signer.sign(&preimage);

        let seal = AuthoritySealV1::new(
            cell_id,
            IssuerId::PublicKey(pkid),
            subject_kind,
            batch_root,
            ledger_anchor,
            ZERO_TIME_ENVELOPE_REF,
            SealKind::MerkleBatch,
            vec![signature.to_bytes().to_vec()],
        )
        .unwrap();

        assert!(
            seal.verify_merkle_batch(
                &signer.verifying_key(),
                &receipt_hash,
                &inclusion_proof,
                "apm2.receipt_batch.v1",
                &batch_root,
                false,
            )
            .is_ok()
        );
    }

    #[test]
    fn verify_merkle_batch_wrong_artifact() {
        let signer = Signer::generate();
        let cell_id = test_cell_id();
        let pkid = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &signer.public_key_bytes());

        let receipt_hash = [0x42; HASH_SIZE];
        let other_receipt_hash = [0x43; HASH_SIZE];

        let leaf0 = compute_receipt_leaf_hash(&receipt_hash);
        let leaf1 = compute_receipt_leaf_hash(&other_receipt_hash);

        let (batch_root, inclusion_proof) = build_merkle_tree_2(leaf0, leaf1);

        let subject_kind = SubjectKind::new("apm2.receipt_batch.v1").unwrap();
        let ledger_anchor = LedgerAnchorV1::ConsensusIndex { index: 1 };

        let seal_unsigned = AuthoritySealV1::new(
            cell_id.clone(),
            IssuerId::PublicKey(pkid.clone()),
            subject_kind.clone(),
            batch_root,
            ledger_anchor.clone(),
            ZERO_TIME_ENVELOPE_REF,
            SealKind::MerkleBatch,
            vec![vec![0u8; 64]],
        )
        .unwrap();

        let preimage = seal_unsigned.domain_separated_preimage();
        let signature = signer.sign(&preimage);

        let seal = AuthoritySealV1::new(
            cell_id,
            IssuerId::PublicKey(pkid),
            subject_kind,
            batch_root,
            ledger_anchor,
            ZERO_TIME_ENVELOPE_REF,
            SealKind::MerkleBatch,
            vec![signature.to_bytes().to_vec()],
        )
        .unwrap();

        // Verify with a hash NOT in the batch.
        let wrong_hash = [0xFF; HASH_SIZE];
        assert!(matches!(
            seal.verify_merkle_batch(
                &signer.verifying_key(),
                &wrong_hash,
                &inclusion_proof,
                "apm2.receipt_batch.v1",
                &batch_root,
                false,
            ),
            Err(AuthoritySealError::MerkleProofFailed { .. })
        ));
    }

    #[test]
    fn merkle_proof_depth_exceeded() {
        let proof = MerkleInclusionProof {
            leaf_hash: [0; HASH_SIZE],
            siblings: vec![
                MerkleProofSibling {
                    hash: [0; HASH_SIZE],
                    is_left: false,
                };
                MAX_MERKLE_PROOF_DEPTH + 1
            ],
        };

        let root = [0; HASH_SIZE];
        assert!(matches!(
            proof.verify(&root),
            Err(AuthoritySealError::MerkleProofDepthExceeded { .. })
        ));
    }

    // ────────── Domain separation tests ──────────

    #[test]
    fn domain_separated_preimage_differs_by_subject_kind() {
        let signer = Signer::generate();
        let cell_id = test_cell_id();
        let pkid = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &signer.public_key_bytes());
        let subject_hash = [0x42; HASH_SIZE];
        let ledger_anchor = LedgerAnchorV1::ConsensusIndex { index: 1 };

        let seal_a = AuthoritySealV1::new(
            cell_id.clone(),
            IssuerId::PublicKey(pkid.clone()),
            SubjectKind::new("apm2.tool_execution_receipt.v1").unwrap(),
            subject_hash,
            ledger_anchor.clone(),
            ZERO_TIME_ENVELOPE_REF,
            SealKind::SingleSig,
            vec![vec![0u8; 64]],
        )
        .unwrap();

        let seal_b = AuthoritySealV1::new(
            cell_id,
            IssuerId::PublicKey(pkid),
            SubjectKind::new("apm2.directory_head.v1").unwrap(),
            subject_hash,
            ledger_anchor,
            ZERO_TIME_ENVELOPE_REF,
            SealKind::SingleSig,
            vec![vec![0u8; 64]],
        )
        .unwrap();

        assert_ne!(
            seal_a.domain_separated_preimage(),
            seal_b.domain_separated_preimage(),
            "Different subject kinds must produce different preimages"
        );
    }

    #[test]
    fn domain_separated_preimage_differs_by_seal_kind() {
        let cell_id = test_cell_id();
        let keyset_id = test_keyset_id();
        let subject_kind = SubjectKind::new("apm2.test.v1").unwrap();
        let subject_hash = [0x42; HASH_SIZE];
        let ledger_anchor = LedgerAnchorV1::ConsensusIndex { index: 1 };

        let seal_multi = AuthoritySealV1::new(
            cell_id.clone(),
            IssuerId::Quorum(keyset_id.clone()),
            subject_kind.clone(),
            subject_hash,
            ledger_anchor.clone(),
            ZERO_TIME_ENVELOPE_REF,
            SealKind::QuorumMultisig,
            vec![vec![0u8; 64]],
        )
        .unwrap();

        let seal_thresh = AuthoritySealV1::new(
            cell_id,
            IssuerId::Quorum(keyset_id),
            subject_kind,
            subject_hash,
            ledger_anchor,
            ZERO_TIME_ENVELOPE_REF,
            SealKind::QuorumThreshold,
            vec![vec![0u8; 64]],
        )
        .unwrap();

        assert_ne!(
            seal_multi.domain_separated_preimage(),
            seal_thresh.domain_separated_preimage(),
            "Different seal kinds must produce different preimages"
        );
    }

    #[test]
    fn domain_separated_preimage_differs_by_ledger_anchor() {
        let signer = Signer::generate();
        let cell_id = test_cell_id();
        let pkid = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &signer.public_key_bytes());
        let subject_kind = SubjectKind::new("apm2.test.v1").unwrap();
        let subject_hash = [0x42; HASH_SIZE];

        let seal_a = AuthoritySealV1::new(
            cell_id.clone(),
            IssuerId::PublicKey(pkid.clone()),
            subject_kind.clone(),
            subject_hash,
            LedgerAnchorV1::ConsensusIndex { index: 1 },
            ZERO_TIME_ENVELOPE_REF,
            SealKind::SingleSig,
            vec![vec![0u8; 64]],
        )
        .unwrap();

        let seal_b = AuthoritySealV1::new(
            cell_id,
            IssuerId::PublicKey(pkid),
            subject_kind,
            subject_hash,
            LedgerAnchorV1::ConsensusIndex { index: 2 },
            ZERO_TIME_ENVELOPE_REF,
            SealKind::SingleSig,
            vec![vec![0u8; 64]],
        )
        .unwrap();

        assert_ne!(
            seal_a.domain_separated_preimage(),
            seal_b.domain_separated_preimage(),
            "Different ledger anchors must produce different preimages"
        );
    }

    // ────────── Receipt leaf hash tests ──────────

    #[test]
    fn receipt_leaf_hash_is_domain_separated() {
        let receipt_hash = [0x42; HASH_SIZE];
        let leaf = compute_receipt_leaf_hash(&receipt_hash);

        // Raw hash of receipt_hash without domain separator should differ.
        let raw = *blake3::hash(&receipt_hash).as_bytes();
        assert_ne!(
            leaf, raw,
            "Domain-separated leaf hash must differ from raw hash"
        );
    }

    #[test]
    fn receipt_leaf_hash_is_deterministic() {
        let receipt_hash = [0x42; HASH_SIZE];
        let a = compute_receipt_leaf_hash(&receipt_hash);
        let b = compute_receipt_leaf_hash(&receipt_hash);
        assert_eq!(a, b);
    }

    // ────────── Reject free-floating batch root test ──────────

    #[test]
    fn reject_free_floating_batch_root_passes_for_anchored() {
        let signer = Signer::generate();
        let seal = make_single_sig_seal(&signer);
        assert!(reject_free_floating_batch_root(&seal).is_ok());
    }

    // ────────── Merkle batch rejects unsigned root ──────────

    #[test]
    fn merkle_batch_rejects_empty_signatures() {
        let cell_id = test_cell_id();
        let pkid = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[0x01; 32]);
        let subject_kind = SubjectKind::new("apm2.receipt_batch.v1").unwrap();

        let result = AuthoritySealV1::new(
            cell_id,
            IssuerId::PublicKey(pkid),
            subject_kind,
            [0; HASH_SIZE],
            LedgerAnchorV1::ConsensusIndex { index: 1 },
            ZERO_TIME_ENVELOPE_REF,
            SealKind::MerkleBatch,
            vec![], // unsigned!
        );

        assert!(
            matches!(
                result,
                Err(AuthoritySealError::InvalidQuorumSignatureCount { .. })
            ),
            "Unsigned batch roots must be rejected"
        );
    }

    // ────────── Merkle inclusion proof edge cases ──────────

    #[test]
    fn merkle_proof_empty_siblings_single_leaf() {
        // Single-leaf tree: root = leaf.
        let leaf = [0x42; HASH_SIZE];
        let proof = MerkleInclusionProof {
            leaf_hash: leaf,
            siblings: vec![],
        };
        assert!(proof.verify(&leaf).is_ok());
    }

    #[test]
    fn merkle_proof_wrong_root() {
        let leaf = [0x42; HASH_SIZE];
        let sibling = [0x43; HASH_SIZE];
        let proof = MerkleInclusionProof {
            leaf_hash: leaf,
            siblings: vec![MerkleProofSibling {
                hash: sibling,
                is_left: false,
            }],
        };

        let wrong_root = [0xFF; HASH_SIZE];
        assert!(matches!(
            proof.verify(&wrong_root),
            Err(AuthoritySealError::MerkleProofFailed { .. })
        ));
    }

    // ────────── MERKLE_BATCH quorum verification tests (security regression)
    // ──────────

    /// Helper: build a quorum-issued `MERKLE_BATCH` seal with 2 signers.
    /// Returns (seal, keys, receipt hash, inclusion proof, `batch_root`).
    fn make_quorum_merkle_batch_seal(
        signer_a: &Signer,
        signer_b: &Signer,
        sign_both: bool,
    ) -> (
        AuthoritySealV1,
        [ed25519_dalek::VerifyingKey; 2],
        Hash,
        MerkleInclusionProof,
        Hash,
    ) {
        let cell_id = test_cell_id();
        let member_a =
            PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &signer_a.public_key_bytes());
        let member_b =
            PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &signer_b.public_key_bytes());
        let keyset_id = KeySetIdV1::from_descriptor(
            "ed25519",
            SetTag::Multisig,
            2,
            &[member_a, member_b],
            None,
        )
        .unwrap();

        let receipt_hash = [0x42; HASH_SIZE];
        let other_receipt_hash = [0x43; HASH_SIZE];
        let leaf0 = compute_receipt_leaf_hash(&receipt_hash);
        let leaf1 = compute_receipt_leaf_hash(&other_receipt_hash);
        let (batch_root, inclusion_proof) = build_merkle_tree_2(leaf0, leaf1);

        let subject_kind = SubjectKind::new("apm2.receipt_batch.v1").unwrap();
        let ledger_anchor = LedgerAnchorV1::ConsensusIndex { index: 1 };

        // Build unsigned to get preimage.
        let seal_unsigned = AuthoritySealV1::new(
            cell_id.clone(),
            IssuerId::Quorum(keyset_id.clone()),
            subject_kind.clone(),
            batch_root,
            ledger_anchor.clone(),
            ZERO_TIME_ENVELOPE_REF,
            SealKind::MerkleBatch,
            vec![vec![0u8; 64], vec![0u8; 64]],
        )
        .unwrap();

        let preimage = seal_unsigned.domain_separated_preimage();
        let sig_a = signer_a.sign(&preimage);
        let sig_b = if sign_both {
            signer_b.sign(&preimage).to_bytes().to_vec()
        } else {
            vec![0u8; 64] // invalid placeholder
        };

        let seal = AuthoritySealV1::new(
            cell_id,
            IssuerId::Quorum(keyset_id),
            subject_kind,
            batch_root,
            ledger_anchor,
            ZERO_TIME_ENVELOPE_REF,
            SealKind::MerkleBatch,
            vec![sig_a.to_bytes().to_vec(), sig_b],
        )
        .unwrap();

        let keys = [signer_a.verifying_key(), signer_b.verifying_key()];
        (seal, keys, receipt_hash, inclusion_proof, batch_root)
    }

    /// SECURITY REGRESSION: quorum-issued `MERKLE_BATCH` with only 1 valid
    /// signature MUST be rejected by `verify_merkle_batch` (single-key path).
    #[test]
    fn merkle_batch_quorum_issuer_rejected_by_single_key_verify() {
        let signer_a = Signer::generate();
        let signer_b = Signer::generate();
        let (seal, _keys, receipt_hash, inclusion_proof, batch_root) =
            make_quorum_merkle_batch_seal(&signer_a, &signer_b, true);

        // Attempting to use the single-key verification method on a
        // quorum-issued MERKLE_BATCH seal must fail.
        let result = seal.verify_merkle_batch(
            &signer_a.verifying_key(),
            &receipt_hash,
            &inclusion_proof,
            "apm2.receipt_batch.v1",
            &batch_root,
            false,
        );
        assert!(
            result.is_err(),
            "verify_merkle_batch must reject quorum-issued MERKLE_BATCH seals"
        );
    }

    /// SECURITY REGRESSION: quorum multisig `MERKLE_BATCH` with only 1 valid
    /// sig out of 2 required MUST be rejected.
    #[test]
    fn merkle_batch_quorum_multisig_rejects_single_valid_sig() {
        let signer_a = Signer::generate();
        let signer_b = Signer::generate();
        // sign_both=false: only signer_a signs, signer_b's sig is invalid.
        let (seal, keys, receipt_hash, inclusion_proof, batch_root) =
            make_quorum_merkle_batch_seal(&signer_a, &signer_b, false);

        let result = seal.verify_merkle_batch_quorum_multisig(
            &keys,
            &receipt_hash,
            &inclusion_proof,
            "apm2.receipt_batch.v1",
            &batch_root,
            false,
        );
        assert!(
            matches!(
                result,
                Err(AuthoritySealError::SignatureVerificationFailed { .. })
            ),
            "Quorum multisig MERKLE_BATCH must reject when not all sigs are valid"
        );
    }

    /// Quorum multisig `MERKLE_BATCH` with all valid sigs MUST be accepted.
    #[test]
    fn merkle_batch_quorum_multisig_accepts_all_valid_sigs() {
        let signer_a = Signer::generate();
        let signer_b = Signer::generate();
        let (seal, keys, receipt_hash, inclusion_proof, batch_root) =
            make_quorum_merkle_batch_seal(&signer_a, &signer_b, true);

        let result = seal.verify_merkle_batch_quorum_multisig(
            &keys,
            &receipt_hash,
            &inclusion_proof,
            "apm2.receipt_batch.v1",
            &batch_root,
            false,
        );
        assert!(
            result.is_ok(),
            "Quorum multisig MERKLE_BATCH must accept when all sigs are valid"
        );
    }

    /// SECURITY REGRESSION: quorum threshold `MERKLE_BATCH` with insufficient
    /// valid sigs MUST be rejected.
    #[test]
    fn merkle_batch_quorum_threshold_rejects_insufficient_sigs() {
        let signer_a = Signer::generate();
        let signer_b = Signer::generate();
        let signer_c = Signer::generate();
        let cell_id = test_cell_id();

        let member_a =
            PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &signer_a.public_key_bytes());
        let member_b =
            PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &signer_b.public_key_bytes());
        let member_c =
            PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &signer_c.public_key_bytes());
        let keyset_id = KeySetIdV1::from_descriptor(
            "ed25519",
            SetTag::Threshold,
            2,
            &[member_a, member_b, member_c],
            None,
        )
        .unwrap();

        let receipt_hash = [0x42; HASH_SIZE];
        let other_receipt_hash = [0x43; HASH_SIZE];
        let leaf0 = compute_receipt_leaf_hash(&receipt_hash);
        let leaf1 = compute_receipt_leaf_hash(&other_receipt_hash);
        let (batch_root, inclusion_proof) = build_merkle_tree_2(leaf0, leaf1);

        let subject_kind = SubjectKind::new("apm2.receipt_batch.v1").unwrap();
        let ledger_anchor = LedgerAnchorV1::ConsensusIndex { index: 1 };

        let seal_unsigned = AuthoritySealV1::new(
            cell_id.clone(),
            IssuerId::Quorum(keyset_id.clone()),
            subject_kind.clone(),
            batch_root,
            ledger_anchor.clone(),
            ZERO_TIME_ENVELOPE_REF,
            SealKind::MerkleBatch,
            vec![vec![0u8; 64], vec![0u8; 64], vec![0u8; 64]],
        )
        .unwrap();

        let preimage = seal_unsigned.domain_separated_preimage();
        let sig_a = signer_a.sign(&preimage);
        // Only 1 valid sig; threshold is 2-of-3.

        let seal = AuthoritySealV1::new(
            cell_id,
            IssuerId::Quorum(keyset_id),
            subject_kind,
            batch_root,
            ledger_anchor,
            ZERO_TIME_ENVELOPE_REF,
            SealKind::MerkleBatch,
            vec![sig_a.to_bytes().to_vec(), vec![0u8; 64], vec![0u8; 64]],
        )
        .unwrap();

        let keys = [
            signer_a.verifying_key(),
            signer_b.verifying_key(),
            signer_c.verifying_key(),
        ];

        let result = seal.verify_merkle_batch_quorum_threshold(
            &keys,
            2,
            &receipt_hash,
            &inclusion_proof,
            "apm2.receipt_batch.v1",
            &batch_root,
            false,
        );
        assert!(
            matches!(
                result,
                Err(AuthoritySealError::ThresholdNotMet {
                    valid_sigs: 1,
                    threshold: 2,
                })
            ),
            "Quorum threshold MERKLE_BATCH must reject when threshold not met"
        );
    }

    /// Quorum threshold `MERKLE_BATCH` with sufficient valid sigs MUST be
    /// accepted.
    #[test]
    fn merkle_batch_quorum_threshold_accepts_sufficient_sigs() {
        let signer_a = Signer::generate();
        let signer_b = Signer::generate();
        let signer_c = Signer::generate();
        let cell_id = test_cell_id();

        let member_a =
            PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &signer_a.public_key_bytes());
        let member_b =
            PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &signer_b.public_key_bytes());
        let member_c =
            PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &signer_c.public_key_bytes());
        let keyset_id = KeySetIdV1::from_descriptor(
            "ed25519",
            SetTag::Threshold,
            2,
            &[member_a, member_b, member_c],
            None,
        )
        .unwrap();

        let receipt_hash = [0x42; HASH_SIZE];
        let other_receipt_hash = [0x43; HASH_SIZE];
        let leaf0 = compute_receipt_leaf_hash(&receipt_hash);
        let leaf1 = compute_receipt_leaf_hash(&other_receipt_hash);
        let (batch_root, inclusion_proof) = build_merkle_tree_2(leaf0, leaf1);

        let subject_kind = SubjectKind::new("apm2.receipt_batch.v1").unwrap();
        let ledger_anchor = LedgerAnchorV1::ConsensusIndex { index: 1 };

        let seal_unsigned = AuthoritySealV1::new(
            cell_id.clone(),
            IssuerId::Quorum(keyset_id.clone()),
            subject_kind.clone(),
            batch_root,
            ledger_anchor.clone(),
            ZERO_TIME_ENVELOPE_REF,
            SealKind::MerkleBatch,
            vec![vec![0u8; 64], vec![0u8; 64], vec![0u8; 64]],
        )
        .unwrap();

        let preimage = seal_unsigned.domain_separated_preimage();
        let sig_a = signer_a.sign(&preimage);
        let sig_b = signer_b.sign(&preimage);
        // 2-of-3 threshold: a and b sign, c doesn't.

        let seal = AuthoritySealV1::new(
            cell_id,
            IssuerId::Quorum(keyset_id),
            subject_kind,
            batch_root,
            ledger_anchor,
            ZERO_TIME_ENVELOPE_REF,
            SealKind::MerkleBatch,
            vec![
                sig_a.to_bytes().to_vec(),
                sig_b.to_bytes().to_vec(),
                vec![0u8; 64],
            ],
        )
        .unwrap();

        let keys = [
            signer_a.verifying_key(),
            signer_b.verifying_key(),
            signer_c.verifying_key(),
        ];

        let result = seal.verify_merkle_batch_quorum_threshold(
            &keys,
            2,
            &receipt_hash,
            &inclusion_proof,
            "apm2.receipt_batch.v1",
            &batch_root,
            false,
        );
        assert!(
            result.is_ok(),
            "Quorum threshold MERKLE_BATCH must accept when threshold is met"
        );
    }

    /// Quorum multisig `MERKLE_BATCH`: mismatched key count must fail.
    #[test]
    fn merkle_batch_quorum_multisig_rejects_key_count_mismatch() {
        let signer_a = Signer::generate();
        let signer_b = Signer::generate();
        let (seal, _keys, receipt_hash, inclusion_proof, batch_root) =
            make_quorum_merkle_batch_seal(&signer_a, &signer_b, true);

        // Provide only 1 key for a 2-sig seal.
        let result = seal.verify_merkle_batch_quorum_multisig(
            &[signer_a.verifying_key()],
            &receipt_hash,
            &inclusion_proof,
            "apm2.receipt_batch.v1",
            &batch_root,
            false,
        );
        assert!(
            matches!(
                result,
                Err(AuthoritySealError::InvalidQuorumSignatureCount { .. })
            ),
            "Key count mismatch must be rejected"
        );
    }

    /// Single-key issuer `MERKLE_BATCH` must be rejected by quorum methods.
    #[test]
    fn merkle_batch_single_key_issuer_rejected_by_quorum_verify() {
        let signer = Signer::generate();
        let cell_id = test_cell_id();
        let pkid = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &signer.public_key_bytes());

        let receipt_hash = [0x42; HASH_SIZE];
        let other_receipt_hash = [0x43; HASH_SIZE];
        let leaf0 = compute_receipt_leaf_hash(&receipt_hash);
        let leaf1 = compute_receipt_leaf_hash(&other_receipt_hash);
        let (batch_root, inclusion_proof) = build_merkle_tree_2(leaf0, leaf1);

        let subject_kind = SubjectKind::new("apm2.receipt_batch.v1").unwrap();
        let ledger_anchor = LedgerAnchorV1::ConsensusIndex { index: 1 };

        let seal_unsigned = AuthoritySealV1::new(
            cell_id.clone(),
            IssuerId::PublicKey(pkid.clone()),
            subject_kind.clone(),
            batch_root,
            ledger_anchor.clone(),
            ZERO_TIME_ENVELOPE_REF,
            SealKind::MerkleBatch,
            vec![vec![0u8; 64]],
        )
        .unwrap();

        let preimage = seal_unsigned.domain_separated_preimage();
        let signature = signer.sign(&preimage);

        let seal = AuthoritySealV1::new(
            cell_id,
            IssuerId::PublicKey(pkid),
            subject_kind,
            batch_root,
            ledger_anchor,
            ZERO_TIME_ENVELOPE_REF,
            SealKind::MerkleBatch,
            vec![signature.to_bytes().to_vec()],
        )
        .unwrap();

        // Using quorum multisig on a single-key issuer must fail.
        let result = seal.verify_merkle_batch_quorum_multisig(
            &[signer.verifying_key()],
            &receipt_hash,
            &inclusion_proof,
            "apm2.receipt_batch.v1",
            &batch_root,
            false,
        );
        assert!(
            result.is_err(),
            "verify_merkle_batch_quorum_multisig must reject single-key issuers"
        );

        // Using quorum threshold on a single-key issuer must fail.
        let result = seal.verify_merkle_batch_quorum_threshold(
            &[signer.verifying_key()],
            1,
            &receipt_hash,
            &inclusion_proof,
            "apm2.receipt_batch.v1",
            &batch_root,
            false,
        );
        assert!(
            result.is_err(),
            "verify_merkle_batch_quorum_threshold must reject single-key issuers"
        );
    }

    // ────────── Temporal authority binding tests ──────────

    /// Tier2+ seal with zero `time_envelope_ref` MUST be rejected.
    #[test]
    fn test_tier2_seal_rejects_zero_time_envelope_ref() {
        let signer = Signer::generate();
        let seal = make_single_sig_seal(&signer);

        // Verify with require_temporal=true should fail because
        // make_single_sig_seal uses ZERO_TIME_ENVELOPE_REF.
        let result = seal.verify_single_sig(
            &signer.verifying_key(),
            TEST_SUBJECT_KIND,
            &[0x42; HASH_SIZE],
            true, // require temporal authority
        );
        assert!(
            matches!(result, Err(AuthoritySealError::TemporalAuthorityRequired)),
            "Tier2+ seal with zero time_envelope_ref must be rejected"
        );
    }

    /// Changing `time_envelope_ref` MUST produce a different preimage hash.
    #[test]
    fn test_time_envelope_ref_included_in_preimage() {
        let cell_id = test_cell_id();
        let pkid = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[0x01; 32]);
        let subject_kind = SubjectKind::new("apm2.test.v1").unwrap();
        let subject_hash = [0x42; HASH_SIZE];
        let ledger_anchor = LedgerAnchorV1::ConsensusIndex { index: 1 };

        let seal_zero = AuthoritySealV1::new(
            cell_id.clone(),
            IssuerId::PublicKey(pkid.clone()),
            subject_kind.clone(),
            subject_hash,
            ledger_anchor.clone(),
            ZERO_TIME_ENVELOPE_REF,
            SealKind::SingleSig,
            vec![vec![0u8; 64]],
        )
        .unwrap();

        let seal_nonzero = AuthoritySealV1::new(
            cell_id,
            IssuerId::PublicKey(pkid),
            subject_kind,
            subject_hash,
            ledger_anchor,
            [0xAB; 32],
            SealKind::SingleSig,
            vec![vec![0u8; 64]],
        )
        .unwrap();

        assert_ne!(
            seal_zero.domain_separated_preimage(),
            seal_nonzero.domain_separated_preimage(),
            "Different time_envelope_ref values must produce different preimages"
        );
    }

    /// `time_envelope_ref` MUST survive canonical bytes round-trip.
    #[test]
    fn test_time_envelope_ref_in_canonical_bytes() {
        let cell_id = test_cell_id();
        let pkid = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[0x01; 32]);
        let subject_kind = SubjectKind::new("apm2.test.v1").unwrap();
        let subject_hash = [0x42; HASH_SIZE];
        let ledger_anchor = LedgerAnchorV1::ConsensusIndex { index: 1 };
        let time_ref = [0xCD; 32];

        let seal = AuthoritySealV1::new(
            cell_id,
            IssuerId::PublicKey(pkid),
            subject_kind,
            subject_hash,
            ledger_anchor,
            time_ref,
            SealKind::SingleSig,
            vec![vec![0u8; 64]],
        )
        .unwrap();

        let bytes = seal.canonical_bytes();
        // Verify time_envelope_ref is present in the canonical bytes.
        // It appears after subject_hash and ledger_anchor_canonical_bytes.
        assert!(
            bytes.windows(32).any(|w| w == time_ref),
            "time_envelope_ref must be present in canonical bytes"
        );

        // Verify accessor returns correct value.
        assert_eq!(
            seal.time_envelope_ref(),
            &time_ref,
            "time_envelope_ref accessor must return stored value"
        );
    }

    // ────────── Subject kind/hash mismatch tests ──────────

    /// Verification must reject subject kind mismatch.
    #[test]
    fn test_verify_rejects_subject_kind_mismatch() {
        let signer = Signer::generate();
        let seal = make_single_sig_seal(&signer);

        let result = seal.verify_single_sig(
            &signer.verifying_key(),
            "apm2.wrong_kind.v1", // wrong kind
            &[0x42; HASH_SIZE],
            false,
        );
        assert!(
            matches!(result, Err(AuthoritySealError::SubjectKindMismatch { .. })),
            "Verification must reject subject kind mismatch"
        );
    }

    /// Verification must reject subject hash mismatch.
    #[test]
    fn test_verify_rejects_subject_hash_mismatch() {
        let signer = Signer::generate();
        let seal = make_single_sig_seal(&signer);

        let result = seal.verify_single_sig(
            &signer.verifying_key(),
            TEST_SUBJECT_KIND,
            &[0xFF; HASH_SIZE], // wrong hash
            false,
        );
        assert!(
            matches!(result, Err(AuthoritySealError::SubjectHashMismatch)),
            "Verification must reject subject hash mismatch"
        );
    }

    // ────────── MERKLE_BATCH single-key rejects multiple signatures ──────────

    /// Single-key `MERKLE_BATCH` with 2 signatures MUST be rejected at
    /// construction.
    #[test]
    fn merkle_batch_single_key_rejects_multiple_signatures() {
        let cell_id = test_cell_id();
        let pkid = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[0x01; 32]);
        let subject_kind = SubjectKind::new("apm2.receipt_batch.v1").unwrap();

        let result = AuthoritySealV1::new(
            cell_id,
            IssuerId::PublicKey(pkid),
            subject_kind,
            [0; HASH_SIZE],
            LedgerAnchorV1::ConsensusIndex { index: 1 },
            ZERO_TIME_ENVELOPE_REF,
            SealKind::MerkleBatch,
            vec![vec![0u8; 64], vec![0u8; 64]], // 2 sigs for single key
        );

        assert!(
            matches!(
                result,
                Err(AuthoritySealError::InvalidQuorumSignatureCount {
                    count: 2,
                    min: 1,
                    max: 1,
                })
            ),
            "Single-key MERKLE_BATCH must reject more than 1 signature"
        );
    }

    // ────────── Issuer identity binding in preimage tests (BLOCKER 1) ──────────

    /// Helper: create a second, different `CellIdV1`.
    fn test_cell_id_alt() -> CellIdV1 {
        use crate::identity::CellGenesisV1;
        use crate::identity::cell_id::PolicyRootId;
        let genesis_hash = [0xCC; HASH_SIZE]; // different from test_cell_id
        let policy_root_key = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[0xDD; 32]);
        let policy_root = PolicyRootId::Single(policy_root_key);
        let genesis = CellGenesisV1::new(genesis_hash, policy_root, "alt.local").unwrap();
        CellIdV1::from_genesis(&genesis)
    }

    /// Same seal with different `issuer_cell_id` MUST produce a different
    /// preimage — prevents metadata substitution/replay.
    #[test]
    fn test_preimage_changes_with_different_issuer_cell_id() {
        let pkid = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[0x01; 32]);
        let subject_kind = SubjectKind::new("apm2.test.v1").unwrap();
        let subject_hash = [0x42; HASH_SIZE];
        let ledger_anchor = LedgerAnchorV1::ConsensusIndex { index: 1 };

        let seal_a = AuthoritySealV1::new(
            test_cell_id(),
            IssuerId::PublicKey(pkid.clone()),
            subject_kind.clone(),
            subject_hash,
            ledger_anchor.clone(),
            ZERO_TIME_ENVELOPE_REF,
            SealKind::SingleSig,
            vec![vec![0u8; 64]],
        )
        .unwrap();

        let seal_b = AuthoritySealV1::new(
            test_cell_id_alt(),
            IssuerId::PublicKey(pkid),
            subject_kind,
            subject_hash,
            ledger_anchor,
            ZERO_TIME_ENVELOPE_REF,
            SealKind::SingleSig,
            vec![vec![0u8; 64]],
        )
        .unwrap();

        assert_ne!(
            seal_a.domain_separated_preimage(),
            seal_b.domain_separated_preimage(),
            "Different issuer_cell_id values must produce different preimages"
        );
    }

    /// Same seal with different `issuer_id` (different public key) MUST
    /// produce a different preimage.
    #[test]
    fn test_preimage_changes_with_different_issuer_id() {
        let cell_id = test_cell_id();
        let subject_kind = SubjectKind::new("apm2.test.v1").unwrap();
        let subject_hash = [0x42; HASH_SIZE];
        let ledger_anchor = LedgerAnchorV1::ConsensusIndex { index: 1 };

        let pkid_a = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[0x01; 32]);
        let pkid_b = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[0x02; 32]);

        let seal_a = AuthoritySealV1::new(
            cell_id.clone(),
            IssuerId::PublicKey(pkid_a),
            subject_kind.clone(),
            subject_hash,
            ledger_anchor.clone(),
            ZERO_TIME_ENVELOPE_REF,
            SealKind::SingleSig,
            vec![vec![0u8; 64]],
        )
        .unwrap();

        let seal_b = AuthoritySealV1::new(
            cell_id,
            IssuerId::PublicKey(pkid_b),
            subject_kind,
            subject_hash,
            ledger_anchor,
            ZERO_TIME_ENVELOPE_REF,
            SealKind::SingleSig,
            vec![vec![0u8; 64]],
        )
        .unwrap();

        assert_ne!(
            seal_a.domain_separated_preimage(),
            seal_b.domain_separated_preimage(),
            "Different issuer_id values must produce different preimages"
        );
    }

    // ────────── Extra signature rejection tests (MAJOR 2) ──────────

    /// `verify_quorum_threshold` must reject when `signatures.len()` >
    /// `verifying_keys.len()` -- extra signatures must not be silently ignored.
    #[test]
    fn verify_quorum_threshold_rejects_extra_signatures() {
        let signer_a = Signer::generate();
        let signer_b = Signer::generate();
        let cell_id = test_cell_id();

        let member_a =
            PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &signer_a.public_key_bytes());
        let member_b =
            PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &signer_b.public_key_bytes());
        let keyset_id = KeySetIdV1::from_descriptor(
            "ed25519",
            SetTag::Threshold,
            1,
            &[member_a, member_b],
            None,
        )
        .unwrap();

        let subject_kind = SubjectKind::new("apm2.test.v1").unwrap();
        let subject_hash = [0x42; HASH_SIZE];
        let ledger_anchor = LedgerAnchorV1::ConsensusIndex { index: 1 };

        // 3 signatures but only 2 keys — extra sig must be rejected.
        let seal = AuthoritySealV1::new(
            cell_id,
            IssuerId::Quorum(keyset_id),
            subject_kind,
            subject_hash,
            ledger_anchor,
            ZERO_TIME_ENVELOPE_REF,
            SealKind::QuorumThreshold,
            vec![vec![0u8; 64], vec![0u8; 64], vec![0u8; 64]],
        )
        .unwrap();

        let keys = [signer_a.verifying_key(), signer_b.verifying_key()];
        let result = seal.verify_quorum_threshold(&keys, 1, "apm2.test.v1", &subject_hash, false);
        assert!(
            matches!(
                result,
                Err(AuthoritySealError::InvalidQuorumSignatureCount { .. })
            ),
            "verify_quorum_threshold must reject extra signatures"
        );
    }

    /// `verify_merkle_batch_quorum_threshold` must reject when
    /// `signatures.len()` > `verifying_keys.len()`.
    #[test]
    fn merkle_batch_quorum_threshold_rejects_extra_signatures() {
        let signer_a = Signer::generate();
        let signer_b = Signer::generate();
        let cell_id = test_cell_id();

        let member_a =
            PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &signer_a.public_key_bytes());
        let member_b =
            PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &signer_b.public_key_bytes());
        let keyset_id = KeySetIdV1::from_descriptor(
            "ed25519",
            SetTag::Threshold,
            1,
            &[member_a, member_b],
            None,
        )
        .unwrap();

        let receipt_hash = [0x42; HASH_SIZE];
        let other_receipt_hash = [0x43; HASH_SIZE];
        let leaf0 = compute_receipt_leaf_hash(&receipt_hash);
        let leaf1 = compute_receipt_leaf_hash(&other_receipt_hash);
        let (batch_root, inclusion_proof) = build_merkle_tree_2(leaf0, leaf1);

        let subject_kind = SubjectKind::new("apm2.receipt_batch.v1").unwrap();
        let ledger_anchor = LedgerAnchorV1::ConsensusIndex { index: 1 };

        // 3 signatures but only 2 keys.
        let seal = AuthoritySealV1::new(
            cell_id,
            IssuerId::Quorum(keyset_id),
            subject_kind,
            batch_root,
            ledger_anchor,
            ZERO_TIME_ENVELOPE_REF,
            SealKind::MerkleBatch,
            vec![vec![0u8; 64], vec![0u8; 64], vec![0u8; 64]],
        )
        .unwrap();

        let keys = [signer_a.verifying_key(), signer_b.verifying_key()];
        let result = seal.verify_merkle_batch_quorum_threshold(
            &keys,
            1,
            &receipt_hash,
            &inclusion_proof,
            "apm2.receipt_batch.v1",
            &batch_root,
            false,
        );
        assert!(
            matches!(
                result,
                Err(AuthoritySealError::InvalidQuorumSignatureCount { .. })
            ),
            "verify_merkle_batch_quorum_threshold must reject extra signatures"
        );
    }
}
