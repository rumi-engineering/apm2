//! `ReceiptPointerV1` and `ReceiptMultiProofV1` — cross-holon receipt
//! reference and batched multi-receipt membership verification (RFC-0020
//! §9.5.1, §9.5.5).
//!
//! This module implements:
//! - [`ReceiptPointerV1`]: the default cross-holon pointer for authoritative
//!   receipts, supporting both direct-signature and batch/FactRoot
//!   authentication paths.
//! - [`ReceiptMultiProofV1`]: a batched verification container that proves
//!   multiple receipt hashes are members of a single batch root. Each receipt
//!   currently carries its own independent inclusion proof; the compact
//!   shared-sibling wire shape (`proof_nodes[]` + `proof_structure`) from
//!   RFC-0020 §9.5.5 is deferred to TCK-00370. Correctness and acceptance
//!   equivalence take priority.
//! - [`ReceiptPointerVerifier`]: a unified verifier that accepts both direct
//!   and batched semantics with equivalent acceptance behavior.
//!
//! # Normative Rules (RFC-0020 §9.5.1)
//!
//! A verifier MUST be able to validate a receipt using only:
//! 1. the receipt bytes (from CAS),
//! 2. the authority seal (from CAS),
//! 3. and an inclusion proof when batching is used,
//!
//! without any additional "search the ledger to find which batch included
//! this receipt".
//!
//! # Authentication Paths
//!
//! - **Direct**: receipt hash + authority seal hash (seal authenticates the
//!   receipt hash directly via `SINGLE_SIG`).
//! - **Batch**: receipt hash + authority seal hash + Merkle inclusion proof
//!   (seal authenticates the batch root; inclusion proof proves receipt
//!   membership).
//! - **`FactRoot`** (BFT cells): receipt hash + `fact_root_proof` +
//!   `qc_pointer`. This allows BFT deployments to avoid distributing
//!   independent authority seals per receipt batch.
//!
//! # Batched Verification (RFC-0020 §9.5.5)
//!
//! When a sender transmits multiple receipt pointers from the same batch,
//! it bundles them into a `ReceiptMultiProofV1` container. The current
//! implementation uses K independent inclusion proofs (one per receipt).
//! The compact multiproof optimization (shared-node deduplication via
//! `proof_nodes[]` + `proof_structure`) that would reduce network fanout
//! and verifier hashing work is deferred to TCK-00370.
//!
//! # Security Invariants
//!
//! - Fail-closed: unknown pointer kinds and missing fields produce errors.
//! - Bounded proof depth (`MAX_MERKLE_PROOF_DEPTH`).
//! - Bounded multiproof leaf count (`MAX_MULTIPROOF_LEAVES`).
//! - Domain-separated leaf hashing per §9.5.2.
//! - Direct and batched paths yield equivalent acceptance semantics.
//!
//! # Contract References
//!
//! - RFC-0020 §9.5.1: `ReceiptPointerV1` (normative wire shape)
//! - RFC-0020 §9.5.5: Merkle multiproofs (normative shape)
//! - RFC-0020 §9.5.3: Verification cost target
//! - REQ-0017: `ReceiptPointer` and multiproof acceptance equivalence
//! - EVID-0017: `ReceiptPointer` conformance evidence

use apm2_core::consensus::{
    AttestationOverheadGate, AttestationScaleMeasurement, DEFAULT_MAX_P99_OVERHEAD_RATIO,
};
use apm2_core::crypto::Hash;
use thiserror::Error;

use super::authority_seal::{
    AuthoritySealError, AuthoritySealV1, IssuerId, MAX_MERKLE_PROOF_DEPTH, MerkleInclusionProof,
    SealKind, compute_receipt_leaf_hash,
};

// ──────────────────────────────────────────────────────────────
// Bounds
// ──────────────────────────────────────────────────────────────

/// Maximum number of leaves in a `ReceiptMultiProofV1`.
///
/// Bounded to prevent excessive memory/hashing at decode time.
/// 2^20 = 1,048,576 matches the `max_batch_leaves` cap from §9.5.2.
pub const MAX_MULTIPROOF_LEAVES: usize = 1 << 20;

/// Maximum number of proof nodes in a `ReceiptMultiProofV1`.
///
/// For K leaves at depth D, at most K * D internal nodes are needed.
/// Conservatively bounded to prevent denial-of-service. This allows up to
/// `MAX_MERKLE_PROOF_DEPTH` * `MAX_MULTIPROOF_LEAVES` nodes, but we use a
/// more practical bound: 20 * 1024 = 20480 covers most real batches.
pub const MAX_MULTIPROOF_NODES: usize = 20 * 1024;

/// Maximum serialized size of a `ReceiptPointerV1` in bytes.
pub const MAX_RECEIPT_POINTER_BYTES: usize = 32 * 1024;

/// Maximum serialized size of a `ReceiptMultiProofV1` in bytes.
pub const MAX_RECEIPT_MULTIPROOF_BYTES: usize = 1024 * 1024;

/// Domain separator for receipt pointer canonical bytes.
const RECEIPT_POINTER_DOMAIN_SEPARATOR: &[u8] = b"apm2:receipt_pointer:v1\0";

/// Domain separator for receipt multiproof canonical bytes.
const RECEIPT_MULTIPROOF_DOMAIN_SEPARATOR: &[u8] = b"apm2:receipt_multiproof:v1\0";

// ──────────────────────────────────────────────────────────────
// Error types
// ──────────────────────────────────────────────────────────────

/// Errors produced when constructing, parsing, or verifying receipt
/// pointers and multiproofs.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ReceiptPointerError {
    /// Unknown pointer kind tag.
    #[error("unknown pointer kind tag: 0x{tag:02x}")]
    UnknownPointerKind {
        /// The unknown tag byte.
        tag: u8,
    },

    /// The pointer kind does not match verifier entry-point expectations.
    #[error("pointer kind mismatch: expected {expected:?}, got {actual:?}")]
    PointerKindMismatch {
        /// Pointer kind expected by the verifier entry point.
        expected: PointerKind,
        /// Actual pointer kind encoded in the pointer.
        actual: PointerKind,
    },

    /// The receipt hash is missing (all zeros).
    #[error("receipt hash must not be zero")]
    ZeroReceiptHash,

    /// The authority seal hash is missing when required.
    #[error("authority seal hash is required for {pointer_kind} pointers")]
    MissingSealHash {
        /// The pointer kind that requires a seal hash.
        pointer_kind: &'static str,
    },

    /// An inclusion proof is required for batch pointers but was not
    /// provided.
    #[error("inclusion proof is required for batch pointers")]
    MissingInclusionProof,

    /// An inclusion proof was provided for a direct pointer (not
    /// applicable).
    #[error("inclusion proof must not be present for direct pointers")]
    UnexpectedInclusionProof,

    /// The authority seal error during verification.
    #[error("authority seal verification failed: {0}")]
    SealError(#[from] AuthoritySealError),

    /// The receipt hash is not a member of the authenticated batch root.
    #[error("receipt hash not a member of batch root")]
    NotAMember,

    /// Multiproof has too many leaves.
    #[error("multiproof leaf count {count} exceeds max {max}")]
    TooManyLeaves {
        /// Actual leaf count.
        count: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Multiproof has too many proof nodes.
    #[error("multiproof node count {count} exceeds max {max}")]
    TooManyProofNodes {
        /// Actual node count.
        count: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Multiproof proof count does not match receipt count.
    #[error("multiproof proof count mismatch: expected {expected}, got {actual}")]
    ProofCountMismatch {
        /// Expected proof count (one proof per receipt).
        expected: usize,
        /// Actual provided proof count.
        actual: usize,
    },

    /// Multiproof has zero leaves.
    #[error("multiproof must contain at least one leaf hash")]
    EmptyMultiproof,

    /// Multiproof leaf hashes are not in canonical (sorted) order.
    #[error("multiproof leaf hashes must be in canonical sorted order")]
    UnsortedLeaves,

    /// Multiproof contains duplicate leaf hashes.
    #[error("multiproof contains duplicate leaf hashes")]
    DuplicateLeaves,

    /// Multiproof verification: reconstructed root does not match
    /// expected batch root.
    #[error("multiproof root mismatch: reconstructed root does not match batch root")]
    MultiproofRootMismatch,

    /// Serialized size exceeds the maximum bound.
    #[error("serialized size {actual} exceeds maximum {max}")]
    SizeExceeded {
        /// Maximum allowed size.
        max: usize,
        /// Actual or estimated size.
        actual: usize,
    },

    /// The `FactRoot` proof path is not yet supported.
    #[error("FactRoot proof path is not yet implemented (deferred to TCK-00370)")]
    FactRootNotImplemented,

    /// A direct pointer was verified against a batch seal.
    #[error(
        "direct pointer authentication requires SingleSig seal, but seal kind is {seal_kind:?}"
    )]
    DirectPointerRequiresSingleSig {
        /// The actual seal kind found.
        seal_kind: SealKind,
    },

    /// The authority seal hash in the pointer/multiproof does not match
    /// the hash computed from the provided seal's canonical bytes.
    #[error("authority seal hash mismatch: pointer seal hash does not match provided seal")]
    SealHashMismatch {
        /// The hash referenced in the pointer/multiproof.
        expected: Hash,
        /// The hash computed from the provided seal.
        actual: Hash,
    },

    /// Batch pointer verification requires a `MERKLE_BATCH` seal.
    #[error("batch pointer verification requires MERKLE_BATCH seal, got {seal_kind:?}")]
    UnsupportedBatchSealKind {
        /// The encountered non-batch seal kind.
        seal_kind: SealKind,
    },

    /// Provided batch verification material does not match the seal issuer.
    #[error(
        "batch verifier material does not match seal issuer {issuer_id:?} for seal kind {seal_kind:?}"
    )]
    BatchVerifierMismatch {
        /// The encountered seal kind.
        seal_kind: SealKind,
        /// Issuer encoded in the seal.
        issuer_id: IssuerId,
    },

    /// Batch attestation overhead gate exceeded configured CPU/network limits.
    #[error(
        "batch attestation overhead exceeded: cpu_overhead_ppm={cpu_overhead_ppm}, \
         network_overhead_ppm={network_overhead_ppm}, \
         max_cpu_overhead_ppm={max_cpu_overhead_ppm}, \
         max_network_overhead_ppm={max_network_overhead_ppm}"
    )]
    BatchOverheadExceeded {
        /// CPU overhead in parts-per-million.
        cpu_overhead_ppm: u32,
        /// Network overhead in parts-per-million.
        network_overhead_ppm: u32,
        /// Configured maximum CPU overhead in parts-per-million.
        max_cpu_overhead_ppm: u32,
        /// Configured maximum network overhead in parts-per-million.
        max_network_overhead_ppm: u32,
    },

    /// Fallback pointer targets a different receipt hash.
    #[error("fallback pointer receipt hash mismatch")]
    FallbackReceiptHashMismatch {
        /// Batch pointer receipt hash.
        batch_receipt_hash: Hash,
        /// Fallback direct pointer receipt hash.
        direct_receipt_hash: Hash,
    },

    /// Fallback direct material does not preserve batch-path authority
    /// semantics (issuer identity and quorum requirements).
    #[error(
        "fallback authority semantics mismatch: batch_issuer={batch_issuer_id:?}, \
         fallback_issuer={fallback_issuer_id:?}, \
         batch_requires_quorum={batch_requires_quorum}, \
         batch_threshold={batch_threshold:?}"
    )]
    FallbackAuthoritySemanticsMismatch {
        /// Issuer required by the batch-path seal.
        batch_issuer_id: IssuerId,
        /// Issuer encoded in the fallback direct seal.
        fallback_issuer_id: IssuerId,
        /// Whether batch verification required quorum semantics.
        batch_requires_quorum: bool,
        /// Threshold implied by batch verifier material (`Some(n)` for
        /// multisig n-of-n and threshold k-of-n).
        batch_threshold: Option<usize>,
    },

    /// Batch verification failed with a fallback-eligible reason, but no
    /// direct fallback verifier was provided.
    #[error("fallback unavailable for reason {reason}: primary={primary}")]
    FallbackUnavailable {
        /// Classified fallback reason.
        reason: BatchFallbackReason,
        /// Primary batch-path error.
        primary: Box<Self>,
    },

    /// Batch verification failed and direct fallback verification also failed.
    #[error(
        "fallback verification failed for reason {reason}: primary={primary}, fallback={fallback}"
    )]
    FallbackVerificationFailed {
        /// Classified fallback reason.
        reason: BatchFallbackReason,
        /// Primary batch-path error.
        primary: Box<Self>,
        /// Direct fallback-path error.
        fallback: Box<Self>,
    },
}

/// Reason category that triggers automatic batched->direct fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BatchFallbackReason {
    /// Overhead gate degraded beyond contract limits.
    Degradation,
    /// Integrity verification failure in the batched path.
    IntegrityFailure,
    /// Freshness/temporal semantics failure in the batched path.
    FreshnessFailure,
}

impl std::fmt::Display for BatchFallbackReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Degradation => write!(f, "degradation"),
            Self::IntegrityFailure => write!(f, "integrity_failure"),
            Self::FreshnessFailure => write!(f, "freshness_failure"),
        }
    }
}

// ──────────────────────────────────────────────────────────────
// Pointer kind enum
// ──────────────────────────────────────────────────────────────

/// The authentication path used by a `ReceiptPointerV1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum PointerKind {
    /// Direct: the authority seal authenticates the receipt hash directly.
    Direct   = 0x01,
    /// Batch: the authority seal authenticates a batch root; an inclusion
    /// proof proves the receipt hash is a member of that root.
    Batch    = 0x02,
    /// `FactRoot`: BFT-cell path — receipt membership proven via
    /// `fact_root_proof` + `qc_pointer`. Deferred to TCK-00370.
    FactRoot = 0x03,
}

impl PointerKind {
    /// Parse a pointer kind from its tag byte.
    ///
    /// Returns `None` for unknown tags (fail-closed).
    #[must_use]
    pub const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            0x01 => Some(Self::Direct),
            0x02 => Some(Self::Batch),
            0x03 => Some(Self::FactRoot),
            _ => None,
        }
    }

    /// Returns the tag byte for this pointer kind.
    #[must_use]
    pub const fn tag(self) -> u8 {
        self as u8
    }

    /// Returns a human-readable label for error messages.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Batch => "batch",
            Self::FactRoot => "fact_root",
        }
    }
}

// ──────────────────────────────────────────────────────────────
// ReceiptPointerV1
// ──────────────────────────────────────────────────────────────

/// Cross-holon pointer to an authoritative receipt (RFC-0020 §9.5.1).
///
/// A `ReceiptPointerV1` allows a verifier to validate a receipt using
/// only:
/// 1. the receipt bytes (looked up by `receipt_hash` from CAS),
/// 2. the authority seal (looked up by `authority_seal_hash` from CAS),
/// 3. and an inclusion proof when batching is used.
///
/// No ledger search is required.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptPointerV1 {
    /// Hash of the receipt being pointed to.
    receipt_hash: Hash,
    /// Hash of the authority seal that authenticates this receipt
    /// (directly or via a batch root).
    authority_seal_hash: Hash,
    /// Authentication path kind.
    pointer_kind: PointerKind,
    /// Merkle inclusion proof (only present for `Batch` pointers).
    inclusion_proof: Option<MerkleInclusionProof>,
}

impl ReceiptPointerV1 {
    /// Construct a direct receipt pointer.
    ///
    /// The authority seal authenticates the receipt hash directly via a
    /// `SINGLE_SIG` seal.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `receipt_hash` is all zeros
    /// - `authority_seal_hash` is all zeros
    pub fn new_direct(
        receipt_hash: Hash,
        authority_seal_hash: Hash,
    ) -> Result<Self, ReceiptPointerError> {
        if receipt_hash == [0u8; 32] {
            return Err(ReceiptPointerError::ZeroReceiptHash);
        }
        if authority_seal_hash == [0u8; 32] {
            return Err(ReceiptPointerError::MissingSealHash {
                pointer_kind: "direct",
            });
        }
        Ok(Self {
            receipt_hash,
            authority_seal_hash,
            pointer_kind: PointerKind::Direct,
            inclusion_proof: None,
        })
    }

    /// Construct a batch receipt pointer.
    ///
    /// The authority seal authenticates a batch root; the inclusion proof
    /// proves the receipt hash is a member of that root.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `receipt_hash` is all zeros
    /// - `authority_seal_hash` is all zeros
    /// - `inclusion_proof` depth exceeds `MAX_MERKLE_PROOF_DEPTH`
    pub fn new_batch(
        receipt_hash: Hash,
        authority_seal_hash: Hash,
        inclusion_proof: MerkleInclusionProof,
    ) -> Result<Self, ReceiptPointerError> {
        if receipt_hash == [0u8; 32] {
            return Err(ReceiptPointerError::ZeroReceiptHash);
        }
        if authority_seal_hash == [0u8; 32] {
            return Err(ReceiptPointerError::MissingSealHash {
                pointer_kind: "batch",
            });
        }
        if inclusion_proof.siblings.len() > MAX_MERKLE_PROOF_DEPTH {
            return Err(ReceiptPointerError::SealError(
                AuthoritySealError::MerkleProofDepthExceeded {
                    depth: inclusion_proof.siblings.len(),
                    max: MAX_MERKLE_PROOF_DEPTH,
                },
            ));
        }

        // Validate that the leaf hash matches the domain-separated
        // receipt hash.
        let expected_leaf = compute_receipt_leaf_hash(&receipt_hash);
        if inclusion_proof.leaf_hash != expected_leaf {
            return Err(ReceiptPointerError::NotAMember);
        }

        Ok(Self {
            receipt_hash,
            authority_seal_hash,
            pointer_kind: PointerKind::Batch,
            inclusion_proof: Some(inclusion_proof),
        })
    }

    // ────────── Accessors ──────────

    /// Returns the receipt hash.
    #[must_use]
    pub const fn receipt_hash(&self) -> &Hash {
        &self.receipt_hash
    }

    /// Returns the authority seal hash.
    #[must_use]
    pub const fn authority_seal_hash(&self) -> &Hash {
        &self.authority_seal_hash
    }

    /// Returns the pointer kind.
    #[must_use]
    pub const fn pointer_kind(&self) -> PointerKind {
        self.pointer_kind
    }

    /// Returns the inclusion proof (only present for batch pointers).
    #[must_use]
    pub const fn inclusion_proof(&self) -> Option<&MerkleInclusionProof> {
        self.inclusion_proof.as_ref()
    }

    // ────────── Canonical bytes ──────────

    /// Compute the canonical byte representation for serialization and
    /// content-addressing.
    ///
    /// Layout:
    /// ```text
    /// domain_separator
    /// + pointer_kind_tag (1 byte)
    /// + receipt_hash (32 bytes)
    /// + authority_seal_hash (32 bytes)
    /// + has_inclusion_proof (1 byte: 0x00 or 0x01)
    /// + [if has_inclusion_proof:
    ///     leaf_hash (32 bytes)
    ///     + sibling_count (4 bytes LE)
    ///     + [sibling_hash (32 bytes) + is_left (1 byte)] * sibling_count
    ///   ]
    /// ```
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let proof_size = self
            .inclusion_proof
            .as_ref()
            .map_or(0, |p| 32 + 4 + p.siblings.len() * 33);
        let total = RECEIPT_POINTER_DOMAIN_SEPARATOR.len()
            + 1  // pointer_kind
            + 32 // receipt_hash
            + 32 // authority_seal_hash
            + 1  // has_inclusion_proof
            + proof_size;

        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(RECEIPT_POINTER_DOMAIN_SEPARATOR);
        out.push(self.pointer_kind.tag());
        out.extend_from_slice(&self.receipt_hash);
        out.extend_from_slice(&self.authority_seal_hash);

        if let Some(proof) = &self.inclusion_proof {
            out.push(0x01);
            out.extend_from_slice(&proof.leaf_hash);
            #[allow(clippy::cast_possible_truncation)]
            let sibling_count = proof.siblings.len() as u32;
            out.extend_from_slice(&sibling_count.to_le_bytes());
            for sibling in &proof.siblings {
                out.extend_from_slice(&sibling.hash);
                out.push(u8::from(sibling.is_left));
            }
        } else {
            out.push(0x00);
        }

        out
    }

    /// Compute the content-address hash of this pointer.
    #[must_use]
    pub fn content_hash(&self) -> Hash {
        let bytes = self.canonical_bytes();
        *blake3::hash(&bytes).as_bytes()
    }
}

// ──────────────────────────────────────────────────────────────
// ReceiptMultiProofV1
// ──────────────────────────────────────────────────────────────

/// Batched multi-receipt membership verification container (RFC-0020
/// §9.5.5).
///
/// When a sender transmits multiple receipt pointers from the same batch,
/// it bundles them into a single `ReceiptMultiProofV1` so the verifier
/// can validate the authority seal signature once and then verify each
/// receipt's inclusion proof against the authenticated batch root.
///
/// # Current Implementation
///
/// Each receipt carries its own independent `MerkleInclusionProof`.
/// This is correct and yields the same acceptance semantics as verifying
/// K individual batch pointers. The "compact multiproof" optimization
/// from §9.5.5 (shared-node deduplication across proofs) is deferred to
/// a future ticket; correctness and acceptance equivalence take priority.
///
/// # Wire Shape
///
/// - `batch_root_hash`: the batch Merkle root
/// - `receipt_hashes[]`: K receipt hashes, canonically sorted
/// - `authority_seal_hash`: hash of the seal authenticating the batch root
/// - `individual_proofs[]`: one `MerkleInclusionProof` per receipt
///
/// Target compact wire shape (`proof_nodes[]` + `proof_structure`) is
/// deferred to TCK-00370.
// TODO(TCK-00370): Implement compact shared-sibling multiproof wire shape per RFC-0020 §9.5.5.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptMultiProofV1 {
    /// The batch Merkle root hash being proven against.
    batch_root_hash: Hash,
    /// Receipt hashes whose membership is being proven. These are the
    /// original receipt hashes (NOT domain-separated leaf hashes).
    /// Must be in canonical (sorted) order.
    receipt_hashes: Vec<Hash>,
    /// The authority seal hash that authenticates the batch root.
    authority_seal_hash: Hash,
    /// Individual inclusion proofs for each receipt (one per receipt,
    /// same order as `receipt_hashes`). Shared-node deduplication is
    /// deferred to a future ticket.
    individual_proofs: Vec<MerkleInclusionProof>,
}

/// Validate canonical sort/dedup invariants for multiproof receipt hashes.
fn validate_canonical_receipt_hashes(receipt_hashes: &[Hash]) -> Result<(), ReceiptPointerError> {
    for window in receipt_hashes.windows(2) {
        match window[0].cmp(&window[1]) {
            std::cmp::Ordering::Greater => {
                return Err(ReceiptPointerError::UnsortedLeaves);
            },
            std::cmp::Ordering::Equal => {
                return Err(ReceiptPointerError::DuplicateLeaves);
            },
            std::cmp::Ordering::Less => {},
        }
    }
    Ok(())
}

/// Estimate canonical serialized size for `ReceiptMultiProofV1`.
#[must_use]
fn estimate_multiproof_serialized_size(
    receipt_count: usize,
    individual_proofs: &[MerkleInclusionProof],
) -> usize {
    RECEIPT_MULTIPROOF_DOMAIN_SEPARATOR.len()
        + 32 // batch_root_hash
        + 32 // authority_seal_hash
        + 4  // receipt_count
        + receipt_count * 32
        + individual_proofs
            .iter()
            .map(|proof| 32 + 4 + proof.siblings.len() * 33)
            .sum::<usize>()
}

impl ReceiptMultiProofV1 {
    /// Construct a validated multiproof.
    ///
    /// # Arguments
    ///
    /// - `batch_root_hash`: the Merkle root of the receipt batch.
    /// - `receipt_hashes`: the receipt hashes (NOT leaf hashes) to prove
    ///   membership for. Must be in canonical sorted order.
    /// - `authority_seal_hash`: hash of the authority seal authenticating the
    ///   batch root.
    /// - `individual_proofs`: one inclusion proof per receipt, in the same
    ///   order as `receipt_hashes`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `receipt_hashes` is empty
    /// - `receipt_hashes` exceeds `MAX_MULTIPROOF_LEAVES`
    /// - `receipt_hashes` is not in canonical sorted order
    /// - `receipt_hashes` contains duplicates
    /// - Proof count does not match receipt count
    /// - Any proof has depth exceeding `MAX_MERKLE_PROOF_DEPTH`
    /// - Any proof leaf hash does not match the domain-separated receipt hash
    pub fn new(
        batch_root_hash: Hash,
        receipt_hashes: Vec<Hash>,
        authority_seal_hash: Hash,
        individual_proofs: Vec<MerkleInclusionProof>,
    ) -> Result<Self, ReceiptPointerError> {
        // Validate non-empty.
        if receipt_hashes.is_empty() {
            return Err(ReceiptPointerError::EmptyMultiproof);
        }

        // Validate bounded leaf count.
        if receipt_hashes.len() > MAX_MULTIPROOF_LEAVES {
            return Err(ReceiptPointerError::TooManyLeaves {
                count: receipt_hashes.len(),
                max: MAX_MULTIPROOF_LEAVES,
            });
        }

        // Validate canonical sorted order and no duplicates.
        validate_canonical_receipt_hashes(&receipt_hashes)?;

        // Validate proof count matches receipt count.
        if individual_proofs.len() != receipt_hashes.len() {
            return Err(ReceiptPointerError::ProofCountMismatch {
                expected: receipt_hashes.len(),
                actual: individual_proofs.len(),
            });
        }

        // Validate authority seal hash is non-zero.
        if authority_seal_hash == [0u8; 32] {
            return Err(ReceiptPointerError::MissingSealHash {
                pointer_kind: "multiproof",
            });
        }

        // Enforce MAX_MULTIPROOF_NODES: total sibling nodes across all
        // proofs must not exceed the bound (denial-of-service prevention).
        // Check BEFORE expensive proof verification (fail-fast, admission
        // before computation).
        let total_nodes: usize = individual_proofs.iter().map(|p| p.siblings.len()).sum();
        if total_nodes > MAX_MULTIPROOF_NODES {
            return Err(ReceiptPointerError::TooManyProofNodes {
                count: total_nodes,
                max: MAX_MULTIPROOF_NODES,
            });
        }

        // Enforce MAX_RECEIPT_MULTIPROOF_BYTES: estimated serialized size
        // must not exceed the bound. Check BEFORE expensive proof
        // verification.
        let estimated_size =
            estimate_multiproof_serialized_size(receipt_hashes.len(), &individual_proofs);
        if estimated_size > MAX_RECEIPT_MULTIPROOF_BYTES {
            return Err(ReceiptPointerError::SizeExceeded {
                max: MAX_RECEIPT_MULTIPROOF_BYTES,
                actual: estimated_size,
            });
        }

        // Validate each proof: depth bound, leaf hash correctness, and
        // Merkle root reconstruction. This is the expensive part, so all
        // admission checks are above.
        for (i, (receipt_hash, proof)) in receipt_hashes
            .iter()
            .zip(individual_proofs.iter())
            .enumerate()
        {
            if proof.siblings.len() > MAX_MERKLE_PROOF_DEPTH {
                return Err(ReceiptPointerError::SealError(
                    AuthoritySealError::MerkleProofDepthExceeded {
                        depth: proof.siblings.len(),
                        max: MAX_MERKLE_PROOF_DEPTH,
                    },
                ));
            }

            // Verify the leaf hash is the domain-separated receipt hash.
            let expected_leaf = compute_receipt_leaf_hash(receipt_hash);
            if proof.leaf_hash != expected_leaf {
                return Err(ReceiptPointerError::NotAMember);
            }

            // Verify each proof reconstructs to the batch root.
            proof.verify(&batch_root_hash).map_err(|e| {
                let _ = i; // bind index for debugging clarity
                ReceiptPointerError::SealError(e)
            })?;
        }

        Ok(Self {
            batch_root_hash,
            receipt_hashes,
            authority_seal_hash,
            individual_proofs,
        })
    }

    // ────────── Accessors ──────────

    /// Returns the batch root hash.
    #[must_use]
    pub const fn batch_root_hash(&self) -> &Hash {
        &self.batch_root_hash
    }

    /// Returns the receipt hashes (original, not domain-separated).
    #[must_use]
    pub fn receipt_hashes(&self) -> &[Hash] {
        &self.receipt_hashes
    }

    /// Returns the authority seal hash.
    #[must_use]
    pub const fn authority_seal_hash(&self) -> &Hash {
        &self.authority_seal_hash
    }

    /// Returns the number of receipts in this multiproof.
    #[must_use]
    pub fn receipt_count(&self) -> usize {
        self.receipt_hashes.len()
    }

    /// Returns the individual inclusion proofs.
    #[must_use]
    pub fn individual_proofs(&self) -> &[MerkleInclusionProof] {
        &self.individual_proofs
    }

    // ────────── Canonical bytes ──────────

    /// Compute the canonical byte representation for serialization and
    /// content-addressing.
    ///
    /// Layout:
    /// ```text
    /// domain_separator
    /// + batch_root_hash (32 bytes)
    /// + authority_seal_hash (32 bytes)
    /// + receipt_count (4 bytes LE)
    /// + [receipt_hash (32 bytes)] * receipt_count
    /// + [proof: leaf_hash (32 bytes)
    ///          + sibling_count (4 bytes LE)
    ///          + [sibling_hash (32 bytes) + is_left (1 byte)] * sibling_count
    ///   ] * receipt_count
    /// ```
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let proofs_size: usize = self
            .individual_proofs
            .iter()
            .map(|p| 32 + 4 + p.siblings.len() * 33)
            .sum();
        let total = RECEIPT_MULTIPROOF_DOMAIN_SEPARATOR.len()
            + 32 // batch_root_hash
            + 32 // authority_seal_hash
            + 4  // receipt_count
            + self.receipt_hashes.len() * 32
            + proofs_size;

        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(RECEIPT_MULTIPROOF_DOMAIN_SEPARATOR);
        out.extend_from_slice(&self.batch_root_hash);
        out.extend_from_slice(&self.authority_seal_hash);

        #[allow(clippy::cast_possible_truncation)]
        let receipt_count = self.receipt_hashes.len() as u32;
        out.extend_from_slice(&receipt_count.to_le_bytes());

        for hash in &self.receipt_hashes {
            out.extend_from_slice(hash);
        }

        for proof in &self.individual_proofs {
            out.extend_from_slice(&proof.leaf_hash);
            #[allow(clippy::cast_possible_truncation)]
            let sibling_count = proof.siblings.len() as u32;
            out.extend_from_slice(&sibling_count.to_le_bytes());
            for sibling in &proof.siblings {
                out.extend_from_slice(&sibling.hash);
                out.push(u8::from(sibling.is_left));
            }
        }

        out
    }

    /// Compute the content-address hash of this multiproof.
    #[must_use]
    pub fn content_hash(&self) -> Hash {
        let bytes = self.canonical_bytes();
        *blake3::hash(&bytes).as_bytes()
    }

    /// Check whether a specific receipt hash is proven by this
    /// multiproof.
    ///
    /// Returns `true` if the receipt hash is in the proven set.
    #[must_use]
    pub fn contains_receipt(&self, receipt_hash: &Hash) -> bool {
        self.receipt_hashes.binary_search(receipt_hash).is_ok()
    }

    /// Test-only: construct a `ReceiptMultiProofV1` WITHOUT validation.
    ///
    /// This bypasses all constructor checks (proof verification, sorting,
    /// bounds) to allow testing that `verify_multiproof` independently
    /// catches tampered proofs at the verification boundary.
    ///
    /// # Safety (logical)
    ///
    /// Only available in `#[cfg(test)]`. MUST NOT be used in production.
    #[cfg(test)]
    #[allow(clippy::missing_const_for_fn)]
    fn new_unchecked(
        batch_root_hash: Hash,
        receipt_hashes: Vec<Hash>,
        authority_seal_hash: Hash,
        individual_proofs: Vec<MerkleInclusionProof>,
    ) -> Self {
        Self {
            batch_root_hash,
            receipt_hashes,
            authority_seal_hash,
            individual_proofs,
        }
    }
}

// ──────────────────────────────────────────────────────────────
// ReceiptPointerVerifier
// ──────────────────────────────────────────────────────────────

/// Verification result for receipt pointer validation.
///
/// Both direct and batched paths produce the same result type,
/// ensuring behavioral acceptance equivalence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationResult {
    /// The receipt hash that was verified.
    pub receipt_hash: Hash,
    /// The authority seal hash used for verification.
    pub authority_seal_hash: Hash,
    /// The authentication path used.
    pub pointer_kind: PointerKind,
}

/// Verification material for `MERKLE_BATCH` seal validation.
///
/// This allows receipt-pointer verification to support both single-key and
/// quorum-issued batch seals.
#[derive(Debug, Clone, Copy)]
pub enum BatchSealVerifier<'a> {
    /// Verify using the single-key `MERKLE_BATCH` path.
    SingleKey(&'a ed25519_dalek::VerifyingKey),
    /// Verify using quorum multisig (n-of-n).
    QuorumMultisig {
        /// Verifying keys for the quorum keyset.
        verifying_keys: &'a [ed25519_dalek::VerifyingKey],
        /// Optional key weights (required for weighted keysets).
        weights: Option<&'a [u64]>,
    },
    /// Verify using quorum threshold (k-of-n).
    QuorumThreshold {
        /// Verifying keys for the quorum keyset.
        verifying_keys: &'a [ed25519_dalek::VerifyingKey],
        /// Required valid signature threshold.
        threshold: usize,
        /// Optional key weights (required for weighted keysets).
        weights: Option<&'a [u64]>,
    },
}

/// Deterministic overhead policy for batched attestation verification.
///
/// The policy carries direct-path baseline envelopes used to evaluate whether
/// authenticated batch proof structure violates the `<1%` overhead contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CalibrationProvenance {
    /// Versioned identifier for the baseline/coefficient bundle.
    pub baseline_version: &'static str,
    /// UTC date for the calibration snapshot.
    pub measurement_date_utc: &'static str,
    /// Hardware class the calibration applies to.
    pub hardware_class: &'static str,
}

/// Provenance classification for overhead baseline calibration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CalibrationSource {
    /// Baselines and coefficients came from measured evidence artifacts.
    MeasuredArtifact(CalibrationProvenance),
    /// Baselines were explicitly configured by the caller/operator.
    ExplicitConfiguration(CalibrationProvenance),
    /// Baselines are built-in defaults and should be treated as uncalibrated.
    DefaultHeuristic(CalibrationProvenance),
}

impl CalibrationSource {
    /// Returns calibration provenance metadata attached to this source.
    #[must_use]
    pub const fn provenance(self) -> CalibrationProvenance {
        match self {
            Self::MeasuredArtifact(provenance)
            | Self::ExplicitConfiguration(provenance)
            | Self::DefaultHeuristic(provenance) => provenance,
        }
    }
}

/// Structural CPU model coefficients used by degradation gating.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct StructuralCpuCalibration {
    /// Constant CPU floor per verification.
    pub base_us: f64,
    /// CPU slope per signature checked.
    pub us_per_signature: f64,
    /// CPU slope per Merkle proof layer.
    pub us_per_merkle_layer: f64,
    /// CPU slope per canonicalized byte processed.
    pub us_per_canonical_byte: f64,
}

/// Deterministic overhead policy for batched attestation verification.
///
/// The policy carries direct-path baseline envelopes used to evaluate whether
/// authenticated batch proof structure violates the `<1%` overhead contract.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BatchOverheadPolicy {
    /// Direct verification CPU p99 baseline in microseconds.
    pub direct_cpu_p99_us: f64,
    /// Direct verification network p99 baseline in bytes.
    pub direct_network_p99_bytes: f64,
    /// Maximum CPU overhead ratio allowed.
    pub max_cpu_overhead_ratio: f64,
    /// Maximum network overhead ratio allowed.
    pub max_network_overhead_ratio: f64,
    /// Calibration source/provenance for baseline envelopes.
    pub calibration_source: CalibrationSource,
    /// Structural CPU coefficients for batch-path overhead estimation.
    pub structural_cpu_calibration: StructuralCpuCalibration,
}

const DEFAULT_BATCH_CALIBRATION_PROVENANCE: CalibrationProvenance = CalibrationProvenance {
    baseline_version: "tck-00372-default-v2",
    measurement_date_utc: "2026-02-10",
    hardware_class: "x86_64-linux-generic",
};

const EXPLICIT_CONFIGURATION_PROVENANCE: CalibrationProvenance = CalibrationProvenance {
    baseline_version: "explicit-config",
    measurement_date_utc: "unspecified",
    hardware_class: "unspecified",
};

const DEFAULT_STRUCTURAL_CPU_CALIBRATION: StructuralCpuCalibration = StructuralCpuCalibration {
    base_us: 8.0,
    us_per_signature: 40.0,
    us_per_merkle_layer: 2.0,
    us_per_canonical_byte: 0.01,
};

impl Default for BatchOverheadPolicy {
    fn default() -> Self {
        const DEFAULT_DIRECT_CPU_P99_US: f64 = 100.0;
        const DEFAULT_DIRECT_NETWORK_P99_BYTES: f64 = 2_048.0;

        Self {
            // Safe, realistic baseline envelopes to avoid sentinel-triggered
            // near-constant fallback behavior when callers use defaults.
            direct_cpu_p99_us: DEFAULT_DIRECT_CPU_P99_US,
            direct_network_p99_bytes: DEFAULT_DIRECT_NETWORK_P99_BYTES,
            max_cpu_overhead_ratio: DEFAULT_MAX_P99_OVERHEAD_RATIO,
            max_network_overhead_ratio: DEFAULT_MAX_P99_OVERHEAD_RATIO,
            calibration_source: CalibrationSource::DefaultHeuristic(
                DEFAULT_BATCH_CALIBRATION_PROVENANCE,
            ),
            structural_cpu_calibration: DEFAULT_STRUCTURAL_CPU_CALIBRATION,
        }
    }
}

impl BatchOverheadPolicy {
    /// Creates a policy with explicit baseline envelopes.
    #[must_use]
    pub const fn new(
        direct_cpu_p99_us: f64,
        direct_network_p99_bytes: f64,
        max_cpu_overhead_ratio: f64,
        max_network_overhead_ratio: f64,
    ) -> Self {
        Self::with_calibration(
            direct_cpu_p99_us,
            direct_network_p99_bytes,
            max_cpu_overhead_ratio,
            max_network_overhead_ratio,
            CalibrationSource::ExplicitConfiguration(EXPLICIT_CONFIGURATION_PROVENANCE),
            DEFAULT_STRUCTURAL_CPU_CALIBRATION,
        )
    }

    /// Creates a policy with explicit baseline envelopes and calibration
    /// metadata.
    #[must_use]
    pub const fn with_calibration(
        direct_cpu_p99_us: f64,
        direct_network_p99_bytes: f64,
        max_cpu_overhead_ratio: f64,
        max_network_overhead_ratio: f64,
        calibration_source: CalibrationSource,
        structural_cpu_calibration: StructuralCpuCalibration,
    ) -> Self {
        Self {
            direct_cpu_p99_us,
            direct_network_p99_bytes,
            max_cpu_overhead_ratio,
            max_network_overhead_ratio,
            calibration_source,
            structural_cpu_calibration,
        }
    }

    /// Returns `true` when the policy uses built-in default heuristics.
    #[must_use]
    pub const fn is_uncalibrated_default(&self) -> bool {
        matches!(
            self.calibration_source,
            CalibrationSource::DefaultHeuristic(_)
        )
    }
}

/// Direct verification material used for batch-path fallback.
#[derive(Debug, Clone, Copy)]
pub struct DirectVerificationFallback<'a> {
    /// Direct pointer for the same receipt hash.
    pub pointer: &'a ReceiptPointerV1,
    /// Resolved direct seal.
    pub seal: &'a AuthoritySealV1,
    /// Verifying key for the direct seal.
    pub verifying_key: &'a ed25519_dalek::VerifyingKey,
}

/// Unified verifier for receipt pointers (RFC-0020 §9.5.1).
///
/// Accepts both direct and batched semantics with equivalent acceptance
/// behavior. The verifier does NOT resolve CAS lookups itself — the
/// caller must provide the resolved `AuthoritySealV1` and receipt bytes.
pub struct ReceiptPointerVerifier;

impl ReceiptPointerVerifier {
    /// Shared helper for batch-path seal verification.
    ///
    /// Dispatches to single-key or quorum verification paths based on
    /// seal kind + issuer identity. Mismatched verifier material is
    /// rejected (fail-closed).
    #[allow(clippy::needless_pass_by_value)]
    fn verify_batch_membership(
        seal: &AuthoritySealV1,
        batch_verifier: BatchSealVerifier<'_>,
        receipt_hash: &Hash,
        inclusion_proof: &MerkleInclusionProof,
        expected_subject_kind: &str,
        require_temporal: bool,
    ) -> Result<(), ReceiptPointerError> {
        if seal.seal_kind() != SealKind::MerkleBatch {
            return Err(ReceiptPointerError::UnsupportedBatchSealKind {
                seal_kind: seal.seal_kind(),
            });
        }

        match (seal.issuer_id(), batch_verifier) {
            (IssuerId::PublicKey(_), BatchSealVerifier::SingleKey(verifying_key)) => {
                seal.verify_merkle_batch(
                    verifying_key,
                    receipt_hash,
                    inclusion_proof,
                    expected_subject_kind,
                    seal.subject_hash(),
                    require_temporal,
                )?;
            },
            (
                IssuerId::Quorum(_),
                BatchSealVerifier::QuorumMultisig {
                    verifying_keys,
                    weights,
                },
            ) => {
                seal.verify_merkle_batch_quorum_multisig(
                    verifying_keys,
                    receipt_hash,
                    inclusion_proof,
                    expected_subject_kind,
                    seal.subject_hash(),
                    require_temporal,
                    weights,
                )?;
            },
            (
                IssuerId::Quorum(_),
                BatchSealVerifier::QuorumThreshold {
                    verifying_keys,
                    threshold,
                    weights,
                },
            ) => {
                seal.verify_merkle_batch_quorum_threshold(
                    verifying_keys,
                    threshold,
                    receipt_hash,
                    inclusion_proof,
                    expected_subject_kind,
                    seal.subject_hash(),
                    require_temporal,
                    weights,
                )?;
            },
            _ => {
                return Err(ReceiptPointerError::BatchVerifierMismatch {
                    seal_kind: seal.seal_kind(),
                    issuer_id: seal.issuer_id().clone(),
                });
            },
        }

        Ok(())
    }

    /// Verify a direct receipt pointer against a resolved authority seal.
    ///
    /// For direct pointers, the seal's `subject_hash` must equal the
    /// receipt hash, and the seal must be a `SINGLE_SIG` seal.
    ///
    /// # Arguments
    ///
    /// - `pointer`: the receipt pointer to verify.
    /// - `seal`: the resolved authority seal.
    /// - `verifying_key`: the public key to verify the seal's signature.
    /// - `expected_subject_kind`: the expected subject kind for the seal.
    /// - `require_temporal`: whether to require temporal authority.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The pointer kind is not `Direct`
    /// - The seal kind is not `SingleSig`
    /// - The seal's subject hash does not match the receipt hash
    /// - Signature verification fails
    pub fn verify_direct(
        pointer: &ReceiptPointerV1,
        seal: &AuthoritySealV1,
        verifying_key: &ed25519_dalek::VerifyingKey,
        expected_subject_kind: &str,
        require_temporal: bool,
    ) -> Result<VerificationResult, ReceiptPointerError> {
        if pointer.pointer_kind != PointerKind::Direct {
            return Err(ReceiptPointerError::PointerKindMismatch {
                expected: PointerKind::Direct,
                actual: pointer.pointer_kind,
            });
        }

        // Bind authority_seal_hash: compute hash from seal canonical bytes
        // and reject mismatch (fail-closed).
        let actual_seal_hash = *blake3::hash(&seal.canonical_bytes()).as_bytes();
        if pointer.authority_seal_hash != actual_seal_hash {
            return Err(ReceiptPointerError::SealHashMismatch {
                expected: pointer.authority_seal_hash,
                actual: actual_seal_hash,
            });
        }

        if seal.seal_kind() != SealKind::SingleSig {
            return Err(ReceiptPointerError::DirectPointerRequiresSingleSig {
                seal_kind: seal.seal_kind(),
            });
        }

        // For direct pointers, the seal authenticates the receipt hash
        // directly.
        seal.verify_single_sig(
            verifying_key,
            expected_subject_kind,
            &pointer.receipt_hash,
            require_temporal,
        )?;

        Ok(VerificationResult {
            receipt_hash: pointer.receipt_hash,
            authority_seal_hash: pointer.authority_seal_hash,
            pointer_kind: pointer.pointer_kind,
        })
    }

    const OVERHEAD_RATIO_PPM_SCALE: f64 = 1_000_000.0;

    fn ratio_to_ppm(overhead_ratio: f64) -> u32 {
        if !overhead_ratio.is_finite() {
            return u32::MAX;
        }
        let scaled = (overhead_ratio * Self::OVERHEAD_RATIO_PPM_SCALE).round();
        if scaled <= 0.0 {
            0
        } else if scaled >= f64::from(u32::MAX) {
            u32::MAX
        } else {
            // Avoid lossy float->int casts under strict clippy settings.
            format!("{scaled:.0}").parse::<u32>().unwrap_or(u32::MAX)
        }
    }

    const fn classify_batch_fallback_reason(
        error: &ReceiptPointerError,
    ) -> Option<BatchFallbackReason> {
        match error {
            ReceiptPointerError::BatchOverheadExceeded { .. } => {
                Some(BatchFallbackReason::Degradation)
            },
            ReceiptPointerError::SealError(AuthoritySealError::TemporalAuthorityRequired) => {
                Some(BatchFallbackReason::FreshnessFailure)
            },
            ReceiptPointerError::SealHashMismatch { .. }
            | ReceiptPointerError::NotAMember
            | ReceiptPointerError::MultiproofRootMismatch
            | ReceiptPointerError::UnsupportedBatchSealKind { .. }
            | ReceiptPointerError::BatchVerifierMismatch { .. }
            | ReceiptPointerError::SealError(
                AuthoritySealError::MerkleProofFailed { .. }
                | AuthoritySealError::SubjectHashMismatch
                | AuthoritySealError::SubjectKindMismatch { .. }
                | AuthoritySealError::SignatureVerificationFailed { .. }
                | AuthoritySealError::ThresholdNotMet { .. }
                | AuthoritySealError::InvalidQuorumSignatureCount { .. }
                | AuthoritySealError::IssuerKeyMismatch { .. }
                | AuthoritySealError::DomainSeparationMismatch { .. }
                | AuthoritySealError::InvalidSignatureLength { .. },
            ) => Some(BatchFallbackReason::IntegrityFailure),
            _ => None,
        }
    }

    fn estimate_verification_bytes(pointer: &ReceiptPointerV1, seal: &AuthoritySealV1) -> f64 {
        let pointer_bytes = u32::try_from(pointer.canonical_bytes().len()).unwrap_or(u32::MAX);
        let seal_bytes = u32::try_from(seal.canonical_bytes().len()).unwrap_or(u32::MAX);
        f64::from(pointer_bytes) + f64::from(seal_bytes)
    }

    fn estimate_structural_batch_cpu_us(
        pointer: &ReceiptPointerV1,
        seal: &AuthoritySealV1,
        calibration: StructuralCpuCalibration,
    ) -> f64 {
        let signature_count = f64::from(u32::try_from(seal.signatures().len()).unwrap_or(u32::MAX));
        let merkle_layers = f64::from(
            u32::try_from(
                pointer
                    .inclusion_proof()
                    .map_or(0usize, |proof| proof.siblings.len().saturating_add(1)),
            )
            .unwrap_or(u32::MAX),
        );
        let canonical_bytes = Self::estimate_verification_bytes(pointer, seal);
        let structural_cpu_us = merkle_layers.mul_add(
            calibration.us_per_merkle_layer,
            signature_count.mul_add(calibration.us_per_signature, calibration.base_us),
        );
        canonical_bytes.mul_add(calibration.us_per_canonical_byte, structural_cpu_us)
    }

    fn emit_uncalibrated_overhead_warning(policy: &BatchOverheadPolicy) {
        if !policy.is_uncalibrated_default() {
            return;
        }
        let provenance = policy.calibration_source.provenance();
        tracing::warn!(
            baseline_version = provenance.baseline_version,
            measurement_date_utc = provenance.measurement_date_utc,
            hardware_class = provenance.hardware_class,
            "batch overhead degradation gate using default heuristic calibration; prefer measured artifact calibration for production enforcement"
        );
    }

    const fn batch_quorum_requirements(
        batch_verifier: BatchSealVerifier<'_>,
    ) -> (bool, Option<usize>) {
        match batch_verifier {
            BatchSealVerifier::SingleKey(_) => (false, None),
            BatchSealVerifier::QuorumMultisig { verifying_keys, .. } => {
                (true, Some(verifying_keys.len()))
            },
            BatchSealVerifier::QuorumThreshold { threshold, .. } => (true, Some(threshold)),
        }
    }

    fn enforce_fallback_authority_semantics(
        batch_seal: &AuthoritySealV1,
        batch_verifier: BatchSealVerifier<'_>,
        fallback_seal: &AuthoritySealV1,
    ) -> Result<(), ReceiptPointerError> {
        let (verifier_requires_quorum, batch_threshold) =
            Self::batch_quorum_requirements(batch_verifier);
        let batch_requires_quorum =
            verifier_requires_quorum || matches!(batch_seal.issuer_id(), IssuerId::Quorum(_));

        if !batch_requires_quorum && batch_seal.issuer_id() == fallback_seal.issuer_id() {
            return Ok(());
        }

        Err(ReceiptPointerError::FallbackAuthoritySemanticsMismatch {
            batch_issuer_id: batch_seal.issuer_id().clone(),
            fallback_issuer_id: fallback_seal.issuer_id().clone(),
            batch_requires_quorum,
            batch_threshold,
        })
    }

    fn evaluate_batch_overhead_policy(
        batch_estimated_cpu_us: f64,
        batch_network_bytes: f64,
        policy: &BatchOverheadPolicy,
    ) -> Result<(), ReceiptPointerError> {
        let measurement = AttestationScaleMeasurement::new(
            1,
            policy.direct_cpu_p99_us,
            batch_estimated_cpu_us,
            policy.direct_network_p99_bytes,
            batch_network_bytes,
        )
        .map_err(|_| ReceiptPointerError::BatchOverheadExceeded {
            cpu_overhead_ppm: u32::MAX,
            network_overhead_ppm: u32::MAX,
            max_cpu_overhead_ppm: Self::ratio_to_ppm(policy.max_cpu_overhead_ratio),
            max_network_overhead_ppm: Self::ratio_to_ppm(policy.max_network_overhead_ratio),
        })?;

        let gate = AttestationOverheadGate::new(
            policy.max_cpu_overhead_ratio,
            policy.max_network_overhead_ratio,
        );
        gate.enforce(&measurement)
            .map_err(|_| ReceiptPointerError::BatchOverheadExceeded {
                cpu_overhead_ppm: Self::ratio_to_ppm(measurement.cpu_overhead_ratio()),
                network_overhead_ppm: Self::ratio_to_ppm(measurement.network_overhead_ratio()),
                max_cpu_overhead_ppm: Self::ratio_to_ppm(policy.max_cpu_overhead_ratio),
                max_network_overhead_ppm: Self::ratio_to_ppm(policy.max_network_overhead_ratio),
            })
    }

    #[allow(clippy::too_many_arguments)]
    fn verify_direct_fallback_or_fail(
        batch_pointer: &ReceiptPointerV1,
        batch_seal: &AuthoritySealV1,
        batch_verifier: BatchSealVerifier<'_>,
        expected_subject_kind: &str,
        require_temporal: bool,
        fallback: Option<DirectVerificationFallback<'_>>,
        reason: BatchFallbackReason,
        primary: ReceiptPointerError,
    ) -> Result<VerificationResult, ReceiptPointerError> {
        let Some(fallback) = fallback else {
            return Err(ReceiptPointerError::FallbackUnavailable {
                reason,
                primary: Box::new(primary),
            });
        };

        if batch_pointer.receipt_hash != fallback.pointer.receipt_hash {
            let mismatch = ReceiptPointerError::FallbackReceiptHashMismatch {
                batch_receipt_hash: batch_pointer.receipt_hash,
                direct_receipt_hash: fallback.pointer.receipt_hash,
            };
            return Err(ReceiptPointerError::FallbackVerificationFailed {
                reason,
                primary: Box::new(primary),
                fallback: Box::new(mismatch),
            });
        }

        if let Err(mismatch) =
            Self::enforce_fallback_authority_semantics(batch_seal, batch_verifier, fallback.seal)
        {
            return Err(ReceiptPointerError::FallbackVerificationFailed {
                reason,
                primary: Box::new(primary),
                fallback: Box::new(mismatch),
            });
        }

        Self::verify_direct(
            fallback.pointer,
            fallback.seal,
            fallback.verifying_key,
            expected_subject_kind,
            require_temporal,
        )
        .map_err(
            |fallback_error| ReceiptPointerError::FallbackVerificationFailed {
                reason,
                primary: Box::new(primary),
                fallback: Box::new(fallback_error),
            },
        )
    }

    fn verify_batch_internal(
        pointer: &ReceiptPointerV1,
        seal: &AuthoritySealV1,
        batch_verifier: BatchSealVerifier<'_>,
        expected_subject_kind: &str,
        require_temporal: bool,
    ) -> Result<VerificationResult, ReceiptPointerError> {
        if pointer.pointer_kind != PointerKind::Batch {
            return Err(ReceiptPointerError::PointerKindMismatch {
                expected: PointerKind::Batch,
                actual: pointer.pointer_kind,
            });
        }

        // Bind authority_seal_hash: compute hash from seal canonical bytes
        // and reject mismatch (fail-closed).
        let actual_seal_hash = *blake3::hash(&seal.canonical_bytes()).as_bytes();
        if pointer.authority_seal_hash != actual_seal_hash {
            return Err(ReceiptPointerError::SealHashMismatch {
                expected: pointer.authority_seal_hash,
                actual: actual_seal_hash,
            });
        }

        let inclusion_proof = pointer
            .inclusion_proof
            .as_ref()
            .ok_or(ReceiptPointerError::MissingInclusionProof)?;

        // The seal's subject_hash is the batch root. Verify the seal
        // signatures (single-key or quorum path) and the inclusion proof.
        Self::verify_batch_membership(
            seal,
            batch_verifier,
            &pointer.receipt_hash,
            inclusion_proof,
            expected_subject_kind,
            require_temporal,
        )?;

        Ok(VerificationResult {
            receipt_hash: pointer.receipt_hash,
            authority_seal_hash: pointer.authority_seal_hash,
            pointer_kind: pointer.pointer_kind,
        })
    }

    /// Verify a batch receipt pointer against a resolved authority seal.
    ///
    /// For batch pointers, the seal authenticates a batch root, and the
    /// inclusion proof proves the receipt hash is a member.
    ///
    /// # Arguments
    ///
    /// - `pointer`: the receipt pointer to verify.
    /// - `seal`: the resolved authority seal (must be `MerkleBatch`).
    /// - `batch_verifier`: single-key or quorum verification material for the
    ///   batch seal.
    /// - `expected_subject_kind`: the expected subject kind for the seal.
    /// - `require_temporal`: whether to require temporal authority.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The pointer kind is not `Batch`
    /// - The inclusion proof is missing
    /// - The seal kind is not `MerkleBatch`
    /// - The inclusion proof does not verify
    /// - Signature verification fails
    pub fn verify_batch(
        pointer: &ReceiptPointerV1,
        seal: &AuthoritySealV1,
        batch_verifier: BatchSealVerifier<'_>,
        expected_subject_kind: &str,
        require_temporal: bool,
    ) -> Result<VerificationResult, ReceiptPointerError> {
        Self::verify_batch_internal(
            pointer,
            seal,
            batch_verifier,
            expected_subject_kind,
            require_temporal,
        )
    }

    /// Verify a batch pointer with automatic batched->direct fallback.
    ///
    /// Fallback is attempted when the batch path fails due:
    /// - degradation (`BatchOverheadExceeded`),
    /// - integrity failures (proof/signature/seal mismatches), or
    /// - freshness failures (`TemporalAuthorityRequired`).
    ///
    /// Degradation gates are evaluated from deterministic structural cost
    /// estimates (proof depth, signature count, canonical bytes), not
    /// process-local wall-clock timing.
    ///
    /// If fallback data is absent or fallback verification fails, this method
    /// fails closed.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_batch_with_fallback(
        pointer: &ReceiptPointerV1,
        seal: &AuthoritySealV1,
        batch_verifier: BatchSealVerifier<'_>,
        expected_subject_kind: &str,
        require_temporal: bool,
        fallback: Option<DirectVerificationFallback<'_>>,
        overhead_policy: Option<BatchOverheadPolicy>,
    ) -> Result<VerificationResult, ReceiptPointerError> {
        let batch_result = Self::verify_batch_internal(
            pointer,
            seal,
            batch_verifier,
            expected_subject_kind,
            require_temporal,
        );

        match batch_result {
            Ok(batch_ok) => {
                if let Some(policy) = overhead_policy {
                    Self::emit_uncalibrated_overhead_warning(&policy);
                    let batch_network_bytes = Self::estimate_verification_bytes(pointer, seal);
                    let batch_estimated_cpu_us = Self::estimate_structural_batch_cpu_us(
                        pointer,
                        seal,
                        policy.structural_cpu_calibration,
                    );
                    if let Err(overhead_error) = Self::evaluate_batch_overhead_policy(
                        batch_estimated_cpu_us,
                        batch_network_bytes,
                        &policy,
                    ) {
                        return Self::verify_direct_fallback_or_fail(
                            pointer,
                            seal,
                            batch_verifier,
                            expected_subject_kind,
                            require_temporal,
                            fallback,
                            BatchFallbackReason::Degradation,
                            overhead_error,
                        );
                    }
                }
                Ok(batch_ok)
            },
            Err(primary) => {
                if let Some(reason) = Self::classify_batch_fallback_reason(&primary) {
                    return Self::verify_direct_fallback_or_fail(
                        pointer,
                        seal,
                        batch_verifier,
                        expected_subject_kind,
                        require_temporal,
                        fallback,
                        reason,
                        primary,
                    );
                }
                Err(primary)
            },
        }
    }

    /// Verify a receipt pointer (either direct or batch) against a
    /// resolved authority seal, with explicit batch-verifier dispatch and
    /// optional batched->direct fallback.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_with_verifier_and_fallback(
        pointer: &ReceiptPointerV1,
        seal: &AuthoritySealV1,
        verifying_key: &ed25519_dalek::VerifyingKey,
        batch_verifier: BatchSealVerifier<'_>,
        expected_subject_kind: &str,
        require_temporal: bool,
        fallback: Option<DirectVerificationFallback<'_>>,
        overhead_policy: Option<BatchOverheadPolicy>,
    ) -> Result<VerificationResult, ReceiptPointerError> {
        match pointer.pointer_kind {
            PointerKind::Direct => Self::verify_direct(
                pointer,
                seal,
                verifying_key,
                expected_subject_kind,
                require_temporal,
            ),
            PointerKind::Batch => Self::verify_batch_with_fallback(
                pointer,
                seal,
                batch_verifier,
                expected_subject_kind,
                require_temporal,
                fallback,
                overhead_policy,
            ),
            // TODO(TCK-00370): Route to FactRootVerifier once daemon-side
            // integration lands. For now, return the existing error so callers
            // know this path is not yet wired up.
            PointerKind::FactRoot => Err(ReceiptPointerError::FactRootNotImplemented),
        }
    }

    /// Verify a receipt pointer (either direct or batch) against a
    /// resolved authority seal, with explicit batch-verifier dispatch.
    ///
    /// This unified entry point dispatches to the appropriate verification
    /// method based on pointer kind:
    /// - `Direct`: uses `verifying_key`
    /// - `Batch`: uses `batch_verifier` (single-key or quorum)
    ///
    /// Both paths produce equivalent `VerificationResult` values.
    ///
    /// # Errors
    ///
    /// Returns an error if verification fails for any reason.
    pub fn verify_with_verifier(
        pointer: &ReceiptPointerV1,
        seal: &AuthoritySealV1,
        verifying_key: &ed25519_dalek::VerifyingKey,
        batch_verifier: BatchSealVerifier<'_>,
        expected_subject_kind: &str,
        require_temporal: bool,
    ) -> Result<VerificationResult, ReceiptPointerError> {
        Self::verify_with_verifier_and_fallback(
            pointer,
            seal,
            verifying_key,
            batch_verifier,
            expected_subject_kind,
            require_temporal,
            None,
            None,
        )
    }

    /// Verify a receipt pointer (either direct or batch) against a
    /// resolved authority seal.
    ///
    /// Backward-compatible convenience wrapper that uses single-key batch
    /// verification. Use [`Self::verify_with_verifier`] to dispatch quorum
    /// batch verification via the same unified API.
    pub fn verify(
        pointer: &ReceiptPointerV1,
        seal: &AuthoritySealV1,
        verifying_key: &ed25519_dalek::VerifyingKey,
        expected_subject_kind: &str,
        require_temporal: bool,
    ) -> Result<VerificationResult, ReceiptPointerError> {
        Self::verify_with_verifier(
            pointer,
            seal,
            verifying_key,
            BatchSealVerifier::SingleKey(verifying_key),
            expected_subject_kind,
            require_temporal,
        )
    }

    /// Verify a multiproof: validate that the authority seal
    /// authenticates the batch root, and that all receipt hashes are
    /// proven members.
    ///
    /// # Arguments
    ///
    /// - `multiproof`: the multiproof to verify.
    /// - `seal`: the resolved authority seal (must be `MerkleBatch`).
    /// - `batch_verifier`: single-key or quorum verification material for the
    ///   batch seal.
    /// - `expected_subject_kind`: the expected subject kind for the seal.
    /// - `require_temporal`: whether to require temporal authority.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The seal does not authenticate the batch root
    /// - Any receipt hash is not a member of the batch root
    pub fn verify_multiproof(
        multiproof: &ReceiptMultiProofV1,
        seal: &AuthoritySealV1,
        batch_verifier: BatchSealVerifier<'_>,
        expected_subject_kind: &str,
        require_temporal: bool,
    ) -> Result<Vec<VerificationResult>, ReceiptPointerError> {
        // ── Structural validation (fail-closed, treat as untrusted) ──
        // Do NOT rely on constructor-time invariants; re-validate
        // structure at the verification boundary.
        if multiproof.receipt_hashes.is_empty() {
            return Err(ReceiptPointerError::EmptyMultiproof);
        }
        if multiproof.receipt_hashes.len() > MAX_MULTIPROOF_LEAVES {
            return Err(ReceiptPointerError::TooManyLeaves {
                count: multiproof.receipt_hashes.len(),
                max: MAX_MULTIPROOF_LEAVES,
            });
        }
        validate_canonical_receipt_hashes(&multiproof.receipt_hashes)?;
        if multiproof.individual_proofs.len() != multiproof.receipt_hashes.len() {
            return Err(ReceiptPointerError::ProofCountMismatch {
                expected: multiproof.receipt_hashes.len(),
                actual: multiproof.individual_proofs.len(),
            });
        }
        let total_nodes: usize = multiproof
            .individual_proofs
            .iter()
            .map(|proof| proof.siblings.len())
            .sum();
        if total_nodes > MAX_MULTIPROOF_NODES {
            return Err(ReceiptPointerError::TooManyProofNodes {
                count: total_nodes,
                max: MAX_MULTIPROOF_NODES,
            });
        }
        let estimated_size = estimate_multiproof_serialized_size(
            multiproof.receipt_hashes.len(),
            &multiproof.individual_proofs,
        );
        if estimated_size > MAX_RECEIPT_MULTIPROOF_BYTES {
            return Err(ReceiptPointerError::SizeExceeded {
                max: MAX_RECEIPT_MULTIPROOF_BYTES,
                actual: estimated_size,
            });
        }

        // Bind authority_seal_hash: compute hash from seal canonical bytes
        // and reject mismatch (fail-closed).
        let actual_seal_hash = *blake3::hash(&seal.canonical_bytes()).as_bytes();
        if multiproof.authority_seal_hash != actual_seal_hash {
            return Err(ReceiptPointerError::SealHashMismatch {
                expected: multiproof.authority_seal_hash,
                actual: actual_seal_hash,
            });
        }
        if multiproof.batch_root_hash != *seal.subject_hash() {
            return Err(ReceiptPointerError::MultiproofRootMismatch);
        }

        // Verify the seal authenticates the batch root for the first
        // receipt. This validates the seal signature once (O(1)).
        let first_proof = &multiproof.individual_proofs[0];
        Self::verify_batch_membership(
            seal,
            batch_verifier,
            &multiproof.receipt_hashes[0],
            first_proof,
            expected_subject_kind,
            require_temporal,
        )?;

        // ── Per-receipt inclusion proof verification (fail-closed) ──
        // Independently verify EVERY (receipt_hash, inclusion_proof)
        // pair against the authenticated batch root. Do NOT trust
        // constructor-time validation — treat the multiproof as
        // untrusted at this verification boundary.
        //
        // The seal's subject_hash is the batch root for MERKLE_BATCH
        // seals. The first receipt was already verified above via
        // verify_merkle_batch (which checks both seal signature AND
        // inclusion proof), but we re-verify it here for uniformity
        // and defense-in-depth — the cost is negligible.
        let batch_root = seal.subject_hash();
        for (receipt_hash, proof) in multiproof
            .receipt_hashes
            .iter()
            .zip(multiproof.individual_proofs.iter())
        {
            // Verify leaf hash is the domain-separated receipt hash.
            let expected_leaf = compute_receipt_leaf_hash(receipt_hash);
            if proof.leaf_hash != expected_leaf {
                return Err(ReceiptPointerError::NotAMember);
            }
            // Verify the inclusion proof reconstructs to the batch root.
            proof
                .verify(batch_root)
                .map_err(ReceiptPointerError::SealError)?;
        }

        // All proofs verified — emit results transactionally.
        let results = multiproof
            .receipt_hashes
            .iter()
            .map(|receipt_hash| VerificationResult {
                receipt_hash: *receipt_hash,
                authority_seal_hash: multiproof.authority_seal_hash,
                pointer_kind: PointerKind::Batch,
            })
            .collect();

        Ok(results)
    }
}

// ──────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use apm2_core::crypto::{HASH_SIZE, Signer};

    use super::*;
    use crate::identity::authority_seal::{
        AuthoritySealV1, IssuerId, MerkleInclusionProof, MerkleProofSibling, SealKind, SubjectKind,
        ZERO_TIME_ENVELOPE_REF, compute_receipt_leaf_hash,
    };
    use crate::identity::directory_proof::LedgerAnchorV1;
    use crate::identity::{AlgorithmTag, CellIdV1, KeySetIdV1, PublicKeyIdV1, SetTag};

    // ────────── Test helpers ──────────

    /// Standard subject kind used in tests.
    const TEST_SUBJECT_KIND: &str = "apm2.tool_execution_receipt.v1";

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

    /// Helper: build a direct authority seal for a given receipt hash.
    fn make_direct_seal_with_time_ref(
        signer: &Signer,
        receipt_hash: &Hash,
        time_envelope_ref: [u8; 32],
    ) -> AuthoritySealV1 {
        let cell_id = test_cell_id();
        let pkid = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &signer.public_key_bytes());
        let subject_kind = SubjectKind::new(TEST_SUBJECT_KIND).unwrap();
        let ledger_anchor = LedgerAnchorV1::ConsensusIndex { index: 1 };

        // Build with placeholder signature to compute preimage.
        let seal_unsigned = AuthoritySealV1::new(
            cell_id.clone(),
            IssuerId::PublicKey(pkid.clone()),
            subject_kind.clone(),
            *receipt_hash,
            ledger_anchor.clone(),
            time_envelope_ref,
            SealKind::SingleSig,
            vec![vec![0u8; 64]],
        )
        .unwrap();

        let preimage = seal_unsigned.domain_separated_preimage();
        let signature = signer.sign(&preimage);

        AuthoritySealV1::new(
            cell_id,
            IssuerId::PublicKey(pkid),
            subject_kind,
            *receipt_hash,
            ledger_anchor,
            time_envelope_ref,
            SealKind::SingleSig,
            vec![signature.to_bytes().to_vec()],
        )
        .unwrap()
    }

    fn make_direct_seal(signer: &Signer, receipt_hash: &Hash) -> AuthoritySealV1 {
        make_direct_seal_with_time_ref(signer, receipt_hash, ZERO_TIME_ENVELOPE_REF)
    }

    /// Helper: build a Merkle tree with given leaves and return (root,
    /// proofs).
    fn build_merkle_tree(receipt_hashes: &[Hash]) -> (Hash, Vec<MerkleInclusionProof>) {
        // Compute leaf hashes with domain separation.
        let leaf_hashes: Vec<Hash> = receipt_hashes
            .iter()
            .map(compute_receipt_leaf_hash)
            .collect();

        // Build a simple binary Merkle tree.
        // Pad to next power of 2 with zero hashes.
        let n = leaf_hashes.len().next_power_of_two();
        let mut layer: Vec<Hash> = leaf_hashes.clone();
        layer.resize(n, [0u8; 32]);

        // Store all layers for proof construction.
        let mut layers: Vec<Vec<Hash>> = vec![layer.clone()];

        while layer.len() > 1 {
            let mut next = Vec::with_capacity(layer.len() / 2);
            for chunk in layer.chunks(2) {
                let mut hasher = blake3::Hasher::new();
                hasher.update(&chunk[0]);
                hasher.update(&chunk[1]);
                next.push(*hasher.finalize().as_bytes());
            }
            layers.push(next.clone());
            layer = next;
        }

        let root = layer[0];

        // Build inclusion proofs for each original leaf.
        let mut proofs = Vec::with_capacity(receipt_hashes.len());
        for (leaf_idx, leaf_hash) in leaf_hashes.iter().enumerate().take(receipt_hashes.len()) {
            let mut siblings = Vec::new();
            let mut idx = leaf_idx;
            for layer in &layers[..layers.len() - 1] {
                let sibling_idx = idx ^ 1;
                if sibling_idx < layer.len() {
                    siblings.push(MerkleProofSibling {
                        hash: layer[sibling_idx],
                        is_left: sibling_idx < idx,
                    });
                }
                idx /= 2;
            }

            proofs.push(MerkleInclusionProof {
                leaf_hash: *leaf_hash,
                siblings,
            });
        }

        (root, proofs)
    }

    /// Helper: build a batch authority seal for a given batch root.
    fn make_batch_seal_with_time_ref(
        signer: &Signer,
        batch_root: &Hash,
        time_envelope_ref: [u8; 32],
    ) -> AuthoritySealV1 {
        let cell_id = test_cell_id();
        let pkid = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &signer.public_key_bytes());
        let subject_kind = SubjectKind::new(TEST_SUBJECT_KIND).unwrap();
        let ledger_anchor = LedgerAnchorV1::ConsensusIndex { index: 1 };

        let seal_unsigned = AuthoritySealV1::new(
            cell_id.clone(),
            IssuerId::PublicKey(pkid.clone()),
            subject_kind.clone(),
            *batch_root,
            ledger_anchor.clone(),
            time_envelope_ref,
            SealKind::MerkleBatch,
            vec![vec![0u8; 64]],
        )
        .unwrap();

        let preimage = seal_unsigned.domain_separated_preimage();
        let signature = signer.sign(&preimage);

        AuthoritySealV1::new(
            cell_id,
            IssuerId::PublicKey(pkid),
            subject_kind,
            *batch_root,
            ledger_anchor,
            time_envelope_ref,
            SealKind::MerkleBatch,
            vec![signature.to_bytes().to_vec()],
        )
        .unwrap()
    }

    fn make_batch_seal(signer: &Signer, batch_root: &Hash) -> AuthoritySealV1 {
        make_batch_seal_with_time_ref(signer, batch_root, ZERO_TIME_ENVELOPE_REF)
    }

    /// Helper: build a quorum multisig `MERKLE_BATCH` seal for a batch root.
    fn make_quorum_batch_seal_multisig(
        signer_a: &Signer,
        signer_b: &Signer,
        batch_root: &Hash,
    ) -> (AuthoritySealV1, Vec<ed25519_dalek::VerifyingKey>) {
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
        let subject_kind = SubjectKind::new(TEST_SUBJECT_KIND).unwrap();
        let ledger_anchor = LedgerAnchorV1::ConsensusIndex { index: 1 };

        let seal_unsigned = AuthoritySealV1::new(
            cell_id.clone(),
            IssuerId::Quorum(keyset_id.clone()),
            subject_kind.clone(),
            *batch_root,
            ledger_anchor.clone(),
            ZERO_TIME_ENVELOPE_REF,
            SealKind::MerkleBatch,
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
            *batch_root,
            ledger_anchor,
            ZERO_TIME_ENVELOPE_REF,
            SealKind::MerkleBatch,
            vec![sig_a.to_bytes().to_vec(), sig_b.to_bytes().to_vec()],
        )
        .unwrap();

        let verifying_keys = vec![signer_a.verifying_key(), signer_b.verifying_key()];
        (seal, verifying_keys)
    }

    /// Helper: build a 2-of-3 quorum threshold `MERKLE_BATCH` seal.
    ///
    /// `include_signer_b=true` produces 2 valid signatures (threshold met).
    /// `include_signer_b=false` produces 1 valid signature (threshold not met).
    fn make_quorum_batch_seal_threshold_2of3(
        signer_a: &Signer,
        signer_b: &Signer,
        signer_c: &Signer,
        batch_root: &Hash,
        include_signer_b: bool,
    ) -> (AuthoritySealV1, Vec<ed25519_dalek::VerifyingKey>) {
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
        let subject_kind = SubjectKind::new(TEST_SUBJECT_KIND).unwrap();
        let ledger_anchor = LedgerAnchorV1::ConsensusIndex { index: 1 };

        let seal_unsigned = AuthoritySealV1::new(
            cell_id.clone(),
            IssuerId::Quorum(keyset_id.clone()),
            subject_kind.clone(),
            *batch_root,
            ledger_anchor.clone(),
            ZERO_TIME_ENVELOPE_REF,
            SealKind::MerkleBatch,
            vec![vec![0u8; 64], vec![0u8; 64], vec![0u8; 64]],
        )
        .unwrap();
        let preimage = seal_unsigned.domain_separated_preimage();
        let sig_a = signer_a.sign(&preimage);
        let sig_b = signer_b.sign(&preimage);

        let seal = AuthoritySealV1::new(
            cell_id,
            IssuerId::Quorum(keyset_id),
            subject_kind,
            *batch_root,
            ledger_anchor,
            ZERO_TIME_ENVELOPE_REF,
            SealKind::MerkleBatch,
            vec![
                sig_a.to_bytes().to_vec(),
                if include_signer_b {
                    sig_b.to_bytes().to_vec()
                } else {
                    vec![0u8; 64]
                },
                vec![0u8; 64],
            ],
        )
        .unwrap();

        let verifying_keys = vec![
            signer_a.verifying_key(),
            signer_b.verifying_key(),
            signer_c.verifying_key(),
        ];
        (seal, verifying_keys)
    }

    // ────────── PointerKind tests ──────────

    #[test]
    fn pointer_kind_round_trip() {
        for tag in [0x01, 0x02, 0x03] {
            let kind = PointerKind::from_tag(tag).unwrap();
            assert_eq!(kind.tag(), tag);
        }
    }

    #[test]
    fn pointer_kind_rejects_unknown() {
        assert!(PointerKind::from_tag(0x00).is_none());
        assert!(PointerKind::from_tag(0x04).is_none());
        assert!(PointerKind::from_tag(0xFF).is_none());
    }

    // ────────── ReceiptPointerV1 construction tests ──────────

    #[test]
    fn direct_pointer_rejects_zero_receipt_hash() {
        let result = ReceiptPointerV1::new_direct([0u8; 32], [0x42; 32]);
        assert!(matches!(result, Err(ReceiptPointerError::ZeroReceiptHash)));
    }

    #[test]
    fn direct_pointer_rejects_zero_seal_hash() {
        let result = ReceiptPointerV1::new_direct([0x42; 32], [0u8; 32]);
        assert!(matches!(
            result,
            Err(ReceiptPointerError::MissingSealHash { .. })
        ));
    }

    #[test]
    fn direct_pointer_accepts_valid() {
        let ptr = ReceiptPointerV1::new_direct([0x42; 32], [0xAA; 32]).unwrap();
        assert_eq!(ptr.pointer_kind(), PointerKind::Direct);
        assert_eq!(*ptr.receipt_hash(), [0x42; 32]);
        assert_eq!(*ptr.authority_seal_hash(), [0xAA; 32]);
        assert!(ptr.inclusion_proof().is_none());
    }

    #[test]
    fn batch_pointer_rejects_zero_receipt_hash() {
        let proof = MerkleInclusionProof {
            leaf_hash: compute_receipt_leaf_hash(&[0u8; 32]),
            siblings: vec![],
        };
        let result = ReceiptPointerV1::new_batch([0u8; 32], [0xAA; 32], proof);
        assert!(matches!(result, Err(ReceiptPointerError::ZeroReceiptHash)));
    }

    #[test]
    fn batch_pointer_rejects_zero_seal_hash() {
        let receipt_hash = [0x42; 32];
        let proof = MerkleInclusionProof {
            leaf_hash: compute_receipt_leaf_hash(&receipt_hash),
            siblings: vec![],
        };
        let result = ReceiptPointerV1::new_batch(receipt_hash, [0u8; 32], proof);
        assert!(matches!(
            result,
            Err(ReceiptPointerError::MissingSealHash { .. })
        ));
    }

    #[test]
    fn batch_pointer_rejects_wrong_leaf_hash() {
        let receipt_hash = [0x42; 32];
        let proof = MerkleInclusionProof {
            leaf_hash: [0xFF; 32], // Wrong leaf hash.
            siblings: vec![],
        };
        let result = ReceiptPointerV1::new_batch(receipt_hash, [0xAA; 32], proof);
        assert!(matches!(result, Err(ReceiptPointerError::NotAMember)));
    }

    #[test]
    fn batch_pointer_accepts_valid() {
        let receipt_hash = [0x42; 32];
        let proof = MerkleInclusionProof {
            leaf_hash: compute_receipt_leaf_hash(&receipt_hash),
            siblings: vec![],
        };
        let ptr = ReceiptPointerV1::new_batch(receipt_hash, [0xAA; 32], proof).unwrap();
        assert_eq!(ptr.pointer_kind(), PointerKind::Batch);
        assert!(ptr.inclusion_proof().is_some());
    }

    #[test]
    fn batch_pointer_rejects_excessive_proof_depth() {
        let receipt_hash = [0x42; 32];
        let siblings: Vec<MerkleProofSibling> = (0..=MAX_MERKLE_PROOF_DEPTH)
            .map(|i| MerkleProofSibling {
                #[allow(clippy::cast_possible_truncation)]
                hash: [i as u8; 32],
                is_left: false,
            })
            .collect();
        let proof = MerkleInclusionProof {
            leaf_hash: compute_receipt_leaf_hash(&receipt_hash),
            siblings,
        };
        let result = ReceiptPointerV1::new_batch(receipt_hash, [0xAA; 32], proof);
        assert!(matches!(
            result,
            Err(ReceiptPointerError::SealError(
                AuthoritySealError::MerkleProofDepthExceeded { .. }
            ))
        ));
    }

    // ────────── Canonical bytes tests ──────────

    #[test]
    fn direct_pointer_canonical_bytes_deterministic() {
        let ptr = ReceiptPointerV1::new_direct([0x42; 32], [0xAA; 32]).unwrap();
        let bytes1 = ptr.canonical_bytes();
        let bytes2 = ptr.canonical_bytes();
        assert_eq!(bytes1, bytes2);
    }

    #[test]
    fn batch_pointer_canonical_bytes_deterministic() {
        let receipt_hash = [0x42; 32];
        let proof = MerkleInclusionProof {
            leaf_hash: compute_receipt_leaf_hash(&receipt_hash),
            siblings: vec![MerkleProofSibling {
                hash: [0xBB; 32],
                is_left: true,
            }],
        };
        let ptr = ReceiptPointerV1::new_batch(receipt_hash, [0xAA; 32], proof).unwrap();
        let bytes1 = ptr.canonical_bytes();
        let bytes2 = ptr.canonical_bytes();
        assert_eq!(bytes1, bytes2);
    }

    #[test]
    fn direct_and_batch_canonical_bytes_differ() {
        let receipt_hash = [0x42; 32];
        let direct = ReceiptPointerV1::new_direct(receipt_hash, [0xAA; 32]).unwrap();
        let proof = MerkleInclusionProof {
            leaf_hash: compute_receipt_leaf_hash(&receipt_hash),
            siblings: vec![],
        };
        let batch = ReceiptPointerV1::new_batch(receipt_hash, [0xAA; 32], proof).unwrap();
        assert_ne!(direct.canonical_bytes(), batch.canonical_bytes());
    }

    #[test]
    fn content_hash_deterministic() {
        let ptr = ReceiptPointerV1::new_direct([0x42; 32], [0xAA; 32]).unwrap();
        assert_eq!(ptr.content_hash(), ptr.content_hash());
    }

    // ────────── Direct verification tests ──────────

    #[test]
    fn verify_direct_pointer_valid() {
        let signer = Signer::generate();
        let receipt_hash = [0x42; HASH_SIZE];
        let seal = make_direct_seal(&signer, &receipt_hash);
        let seal_bytes = seal.canonical_bytes();
        let seal_hash = *blake3::hash(&seal_bytes).as_bytes();

        let ptr = ReceiptPointerV1::new_direct(receipt_hash, seal_hash).unwrap();

        let result = ReceiptPointerVerifier::verify_direct(
            &ptr,
            &seal,
            &signer.verifying_key(),
            TEST_SUBJECT_KIND,
            false,
        );

        assert!(result.is_ok());
        let vr = result.unwrap();
        assert_eq!(vr.receipt_hash, receipt_hash);
        assert_eq!(vr.pointer_kind, PointerKind::Direct);
    }

    #[test]
    fn verify_direct_pointer_wrong_key() {
        let signer = Signer::generate();
        let wrong_signer = Signer::generate();
        let receipt_hash = [0x42; HASH_SIZE];
        let seal = make_direct_seal(&signer, &receipt_hash);
        let seal_bytes = seal.canonical_bytes();
        let seal_hash = *blake3::hash(&seal_bytes).as_bytes();

        let ptr = ReceiptPointerV1::new_direct(receipt_hash, seal_hash).unwrap();

        let result = ReceiptPointerVerifier::verify_direct(
            &ptr,
            &seal,
            &wrong_signer.verifying_key(),
            TEST_SUBJECT_KIND,
            false,
        );

        assert!(result.is_err());
    }

    #[test]
    fn verify_direct_pointer_wrong_receipt_hash() {
        let signer = Signer::generate();
        let receipt_hash = [0x42; HASH_SIZE];
        let seal = make_direct_seal(&signer, &receipt_hash);
        let seal_bytes = seal.canonical_bytes();
        let seal_hash = *blake3::hash(&seal_bytes).as_bytes();

        // Pointer references a different receipt hash.
        let wrong_receipt_hash = [0x99; HASH_SIZE];
        let ptr = ReceiptPointerV1::new_direct(wrong_receipt_hash, seal_hash).unwrap();

        let result = ReceiptPointerVerifier::verify_direct(
            &ptr,
            &seal,
            &signer.verifying_key(),
            TEST_SUBJECT_KIND,
            false,
        );

        assert!(result.is_err());
    }

    // ────────── Batch verification tests ──────────

    #[test]
    fn verify_batch_pointer_valid() {
        let signer = Signer::generate();
        let receipt_hashes = [[0x42; 32], [0x43; 32], [0x44; 32], [0x45; 32]];
        let (root, proofs) = build_merkle_tree(&receipt_hashes);

        let seal = make_batch_seal(&signer, &root);
        let seal_bytes = seal.canonical_bytes();
        let seal_hash = *blake3::hash(&seal_bytes).as_bytes();

        // Verify each receipt individually via batch pointer.
        for (i, receipt_hash) in receipt_hashes.iter().enumerate() {
            let ptr =
                ReceiptPointerV1::new_batch(*receipt_hash, seal_hash, proofs[i].clone()).unwrap();

            let result = ReceiptPointerVerifier::verify_batch(
                &ptr,
                &seal,
                BatchSealVerifier::SingleKey(&signer.verifying_key()),
                TEST_SUBJECT_KIND,
                false,
            );

            assert!(result.is_ok(), "batch verification failed for receipt {i}");
            let vr = result.unwrap();
            assert_eq!(vr.receipt_hash, *receipt_hash);
            assert_eq!(vr.pointer_kind, PointerKind::Batch);
        }
    }

    #[test]
    fn verify_batch_pointer_wrong_receipt() {
        let signer = Signer::generate();
        let receipt_hashes = [[0x42; 32], [0x43; 32]];
        let (root, proofs) = build_merkle_tree(&receipt_hashes);

        let seal = make_batch_seal(&signer, &root);
        let seal_bytes = seal.canonical_bytes();
        let seal_hash = *blake3::hash(&seal_bytes).as_bytes();

        // Try to prove a receipt that is NOT in the batch.
        let wrong_hash = [0xFF; 32];
        // The proof for receipt 0 but with wrong receipt hash should
        // fail at pointer construction.
        let proof = MerkleInclusionProof {
            leaf_hash: compute_receipt_leaf_hash(&wrong_hash),
            siblings: proofs[0].siblings.clone(),
        };
        let ptr = ReceiptPointerV1::new_batch(wrong_hash, seal_hash, proof).unwrap();

        let result = ReceiptPointerVerifier::verify_batch(
            &ptr,
            &seal,
            BatchSealVerifier::SingleKey(&signer.verifying_key()),
            TEST_SUBJECT_KIND,
            false,
        );

        // Verification should fail because the inclusion proof does not
        // verify against the batch root.
        assert!(result.is_err());
    }

    #[test]
    fn verify_batch_pointer_rejects_quorum_seal_with_single_key_verifier() {
        let signer_a = Signer::generate();
        let signer_b = Signer::generate();
        let receipt_hashes = [[0x42; 32], [0x43; 32]];
        let (root, proofs) = build_merkle_tree(&receipt_hashes);
        let (seal, _quorum_keys) = make_quorum_batch_seal_multisig(&signer_a, &signer_b, &root);
        let seal_hash = *blake3::hash(&seal.canonical_bytes()).as_bytes();

        let ptr =
            ReceiptPointerV1::new_batch(receipt_hashes[0], seal_hash, proofs[0].clone()).unwrap();

        let result = ReceiptPointerVerifier::verify_batch(
            &ptr,
            &seal,
            BatchSealVerifier::SingleKey(&signer_a.verifying_key()),
            TEST_SUBJECT_KIND,
            false,
        );

        assert!(
            matches!(
                result,
                Err(ReceiptPointerError::BatchVerifierMismatch {
                    seal_kind: SealKind::MerkleBatch,
                    ..
                })
            ),
            "single-key verifier must reject quorum-issued MERKLE_BATCH pointer, got: {result:?}",
        );
    }

    #[test]
    fn verify_batch_pointer_accepts_quorum_multisig_verifier() {
        let signer_a = Signer::generate();
        let signer_b = Signer::generate();
        let receipt_hashes = [[0x42; 32], [0x43; 32]];
        let (root, proofs) = build_merkle_tree(&receipt_hashes);
        let (seal, quorum_keys) = make_quorum_batch_seal_multisig(&signer_a, &signer_b, &root);
        let seal_hash = *blake3::hash(&seal.canonical_bytes()).as_bytes();

        let ptr =
            ReceiptPointerV1::new_batch(receipt_hashes[1], seal_hash, proofs[1].clone()).unwrap();

        let result = ReceiptPointerVerifier::verify_batch(
            &ptr,
            &seal,
            BatchSealVerifier::QuorumMultisig {
                verifying_keys: &quorum_keys,
                weights: None,
            },
            TEST_SUBJECT_KIND,
            false,
        );

        assert!(
            result.is_ok(),
            "quorum multisig verifier must accept quorum-issued MERKLE_BATCH pointer, got: {result:?}",
        );
    }

    #[test]
    fn verify_batch_pointer_accepts_quorum_threshold_verifier() {
        let signer_a = Signer::generate();
        let signer_b = Signer::generate();
        let signer_c = Signer::generate();
        let receipt_hashes = [[0x42; 32], [0x43; 32], [0x44; 32], [0x45; 32]];
        let (root, proofs) = build_merkle_tree(&receipt_hashes);
        let (seal, quorum_keys) =
            make_quorum_batch_seal_threshold_2of3(&signer_a, &signer_b, &signer_c, &root, true);
        let seal_hash = *blake3::hash(&seal.canonical_bytes()).as_bytes();

        let ptr =
            ReceiptPointerV1::new_batch(receipt_hashes[0], seal_hash, proofs[0].clone()).unwrap();

        let result = ReceiptPointerVerifier::verify_batch(
            &ptr,
            &seal,
            BatchSealVerifier::QuorumThreshold {
                verifying_keys: &quorum_keys,
                threshold: 2,
                weights: None,
            },
            TEST_SUBJECT_KIND,
            false,
        );

        assert!(
            result.is_ok(),
            "quorum threshold verifier must accept when threshold is met, got: {result:?}",
        );
    }

    #[test]
    fn verify_batch_pointer_rejects_quorum_threshold_when_threshold_not_met() {
        let signer_a = Signer::generate();
        let signer_b = Signer::generate();
        let signer_c = Signer::generate();
        let receipt_hashes = [[0x42; 32], [0x43; 32], [0x44; 32], [0x45; 32]];
        let (root, proofs) = build_merkle_tree(&receipt_hashes);
        let (seal, quorum_keys) =
            make_quorum_batch_seal_threshold_2of3(&signer_a, &signer_b, &signer_c, &root, false);
        let seal_hash = *blake3::hash(&seal.canonical_bytes()).as_bytes();

        let ptr =
            ReceiptPointerV1::new_batch(receipt_hashes[2], seal_hash, proofs[2].clone()).unwrap();

        let result = ReceiptPointerVerifier::verify_batch(
            &ptr,
            &seal,
            BatchSealVerifier::QuorumThreshold {
                verifying_keys: &quorum_keys,
                threshold: 2,
                weights: None,
            },
            TEST_SUBJECT_KIND,
            false,
        );

        assert!(
            matches!(
                result,
                Err(ReceiptPointerError::SealError(
                    AuthoritySealError::ThresholdNotMet {
                        valid_sigs: 1,
                        threshold: 2,
                    }
                ))
            ),
            "quorum threshold verifier must reject when threshold is not met, got: {result:?}",
        );
    }

    #[test]
    fn verify_batch_falls_back_to_direct_on_integrity_failure() {
        let signer = Signer::generate();
        let receipt_hashes = [[0x42; 32], [0x43; 32]];
        let (root, proofs) = build_merkle_tree(&receipt_hashes);

        let batch_seal = make_batch_seal(&signer, &root);
        let batch_seal_hash = *blake3::hash(&batch_seal.canonical_bytes()).as_bytes();

        let mut tampered_proof = proofs[0].clone();
        tampered_proof.siblings[0].hash = [0xFF; 32];
        let batch_ptr =
            ReceiptPointerV1::new_batch(receipt_hashes[0], batch_seal_hash, tampered_proof)
                .expect("tampered proof should still be structurally valid");

        let direct_seal = make_direct_seal(&signer, &receipt_hashes[0]);
        let direct_seal_hash = *blake3::hash(&direct_seal.canonical_bytes()).as_bytes();
        let direct_ptr =
            ReceiptPointerV1::new_direct(receipt_hashes[0], direct_seal_hash).expect("direct ptr");

        let result = ReceiptPointerVerifier::verify_batch_with_fallback(
            &batch_ptr,
            &batch_seal,
            BatchSealVerifier::SingleKey(&signer.verifying_key()),
            TEST_SUBJECT_KIND,
            false,
            Some(DirectVerificationFallback {
                pointer: &direct_ptr,
                seal: &direct_seal,
                verifying_key: &signer.verifying_key(),
            }),
            None,
        )
        .expect("integrity failure should trigger direct fallback");

        assert_eq!(result.pointer_kind, PointerKind::Direct);
        assert_eq!(result.receipt_hash, receipt_hashes[0]);
    }

    #[test]
    fn verify_batch_falls_back_to_direct_on_freshness_failure() {
        let signer = Signer::generate();
        let receipt_hashes = [[0x52; 32], [0x53; 32]];
        let (root, proofs) = build_merkle_tree(&receipt_hashes);

        // Batch seal intentionally lacks temporal binding (zero time ref).
        let stale_batch_seal =
            make_batch_seal_with_time_ref(&signer, &root, ZERO_TIME_ENVELOPE_REF);
        let stale_batch_hash = *blake3::hash(&stale_batch_seal.canonical_bytes()).as_bytes();
        let batch_ptr =
            ReceiptPointerV1::new_batch(receipt_hashes[0], stale_batch_hash, proofs[0].clone())
                .expect("batch ptr");

        // Direct fallback uses a non-zero temporal binding to satisfy
        // require_temporal=true checks.
        let temporal_direct_seal =
            make_direct_seal_with_time_ref(&signer, &receipt_hashes[0], [0xAB; 32]);
        let temporal_direct_hash =
            *blake3::hash(&temporal_direct_seal.canonical_bytes()).as_bytes();
        let direct_ptr = ReceiptPointerV1::new_direct(receipt_hashes[0], temporal_direct_hash)
            .expect("direct ptr");

        let result = ReceiptPointerVerifier::verify_batch_with_fallback(
            &batch_ptr,
            &stale_batch_seal,
            BatchSealVerifier::SingleKey(&signer.verifying_key()),
            TEST_SUBJECT_KIND,
            true,
            Some(DirectVerificationFallback {
                pointer: &direct_ptr,
                seal: &temporal_direct_seal,
                verifying_key: &signer.verifying_key(),
            }),
            None,
        )
        .expect("freshness failure should trigger direct fallback");

        assert_eq!(result.pointer_kind, PointerKind::Direct);
        assert_eq!(result.receipt_hash, receipt_hashes[0]);
    }

    #[test]
    fn verify_batch_falls_back_to_direct_on_degradation_overhead_gate() {
        let signer = Signer::generate();
        let receipt_hashes = [[0x62; 32], [0x63; 32]];
        let (root, proofs) = build_merkle_tree(&receipt_hashes);

        let batch_seal = make_batch_seal(&signer, &root);
        let batch_seal_hash = *blake3::hash(&batch_seal.canonical_bytes()).as_bytes();
        let batch_ptr =
            ReceiptPointerV1::new_batch(receipt_hashes[0], batch_seal_hash, proofs[0].clone())
                .expect("batch ptr");

        let direct_seal = make_direct_seal(&signer, &receipt_hashes[0]);
        let direct_seal_hash = *blake3::hash(&direct_seal.canonical_bytes()).as_bytes();
        let direct_ptr =
            ReceiptPointerV1::new_direct(receipt_hashes[0], direct_seal_hash).expect("direct ptr");

        // Intentionally impossible baseline to force degradation fallback.
        let degraded_policy = BatchOverheadPolicy::new(0.001, 0.001, 0.01, 0.01);

        let result = ReceiptPointerVerifier::verify_batch_with_fallback(
            &batch_ptr,
            &batch_seal,
            BatchSealVerifier::SingleKey(&signer.verifying_key()),
            TEST_SUBJECT_KIND,
            false,
            Some(DirectVerificationFallback {
                pointer: &direct_ptr,
                seal: &direct_seal,
                verifying_key: &signer.verifying_key(),
            }),
            Some(degraded_policy),
        )
        .expect("degradation should trigger direct fallback");

        assert_eq!(result.pointer_kind, PointerKind::Direct);
    }

    #[test]
    fn batch_overhead_policy_default_uses_safe_baselines() {
        let policy = BatchOverheadPolicy::default();
        assert!(
            policy.direct_cpu_p99_us >= 50.0,
            "default CPU baseline must be realistic, got: {}",
            policy.direct_cpu_p99_us
        );
        assert!(
            policy.direct_network_p99_bytes >= 512.0,
            "default network baseline must be realistic, got: {}",
            policy.direct_network_p99_bytes
        );
        assert!(
            policy.is_uncalibrated_default(),
            "default policy must be marked as uncalibrated/default provenance",
        );
        let provenance = policy.calibration_source.provenance();
        assert!(
            provenance.baseline_version.starts_with("tck-00372-default"),
            "default provenance must expose versioned baseline identity, got: {}",
            provenance.baseline_version
        );
        assert!(
            provenance.measurement_date_utc != "unspecified",
            "default provenance must include a measurement date"
        );
        assert!(
            provenance.hardware_class != "unspecified",
            "default provenance must include hardware class"
        );
        assert!(
            policy.structural_cpu_calibration.us_per_signature > 0.0,
            "structural CPU calibration must be positive"
        );
    }

    #[test]
    fn verify_batch_fail_closed_when_fallback_is_unavailable() {
        let signer = Signer::generate();
        let receipt_hashes = [[0x72; 32], [0x73; 32]];
        let (root, proofs) = build_merkle_tree(&receipt_hashes);

        let batch_seal = make_batch_seal(&signer, &root);
        let batch_seal_hash = *blake3::hash(&batch_seal.canonical_bytes()).as_bytes();

        let mut tampered_proof = proofs[0].clone();
        tampered_proof.siblings[0].hash = [0xCD; 32];
        let batch_ptr =
            ReceiptPointerV1::new_batch(receipt_hashes[0], batch_seal_hash, tampered_proof)
                .expect("batch ptr");

        let err = ReceiptPointerVerifier::verify_batch_with_fallback(
            &batch_ptr,
            &batch_seal,
            BatchSealVerifier::SingleKey(&signer.verifying_key()),
            TEST_SUBJECT_KIND,
            false,
            None,
            None,
        )
        .expect_err("fallback must fail closed when unavailable");

        assert!(matches!(
            err,
            ReceiptPointerError::FallbackUnavailable {
                reason: BatchFallbackReason::IntegrityFailure,
                ..
            }
        ));
    }

    #[test]
    fn verify_batch_fail_closed_when_fallback_receipt_mismatches() {
        let signer = Signer::generate();
        let receipt_hashes = [[0x82; 32], [0x83; 32]];
        let (root, proofs) = build_merkle_tree(&receipt_hashes);

        let batch_seal = make_batch_seal(&signer, &root);
        let batch_seal_hash = *blake3::hash(&batch_seal.canonical_bytes()).as_bytes();
        let mut tampered_proof = proofs[0].clone();
        tampered_proof.siblings[0].hash = [0xEF; 32];
        let batch_ptr =
            ReceiptPointerV1::new_batch(receipt_hashes[0], batch_seal_hash, tampered_proof)
                .expect("batch ptr");

        let direct_seal = make_direct_seal(&signer, &receipt_hashes[1]);
        let direct_seal_hash = *blake3::hash(&direct_seal.canonical_bytes()).as_bytes();
        let direct_ptr =
            ReceiptPointerV1::new_direct(receipt_hashes[1], direct_seal_hash).expect("direct ptr");

        let err = ReceiptPointerVerifier::verify_batch_with_fallback(
            &batch_ptr,
            &batch_seal,
            BatchSealVerifier::SingleKey(&signer.verifying_key()),
            TEST_SUBJECT_KIND,
            false,
            Some(DirectVerificationFallback {
                pointer: &direct_ptr,
                seal: &direct_seal,
                verifying_key: &signer.verifying_key(),
            }),
            None,
        )
        .expect_err("receipt mismatch in fallback must fail closed");

        assert!(matches!(
            err,
            ReceiptPointerError::FallbackVerificationFailed {
                reason: BatchFallbackReason::IntegrityFailure,
                fallback,
                ..
            } if matches!(
                *fallback,
                ReceiptPointerError::FallbackReceiptHashMismatch { .. }
            )
        ));
    }

    #[test]
    fn verify_batch_fail_closed_when_fallback_issuer_semantics_mismatch() {
        let batch_signer = Signer::generate();
        let fallback_signer = Signer::generate();
        let receipt_hashes = [[0x92; 32], [0x93; 32]];
        let (root, proofs) = build_merkle_tree(&receipt_hashes);

        let batch_seal = make_batch_seal(&batch_signer, &root);
        let batch_seal_hash = *blake3::hash(&batch_seal.canonical_bytes()).as_bytes();
        let mut tampered_proof = proofs[0].clone();
        tampered_proof.siblings[0].hash = [0xEE; 32];
        let batch_ptr =
            ReceiptPointerV1::new_batch(receipt_hashes[0], batch_seal_hash, tampered_proof)
                .expect("batch ptr");

        let direct_seal = make_direct_seal(&fallback_signer, &receipt_hashes[0]);
        let direct_seal_hash = *blake3::hash(&direct_seal.canonical_bytes()).as_bytes();
        let direct_ptr =
            ReceiptPointerV1::new_direct(receipt_hashes[0], direct_seal_hash).expect("direct ptr");

        let err = ReceiptPointerVerifier::verify_batch_with_fallback(
            &batch_ptr,
            &batch_seal,
            BatchSealVerifier::SingleKey(&batch_signer.verifying_key()),
            TEST_SUBJECT_KIND,
            false,
            Some(DirectVerificationFallback {
                pointer: &direct_ptr,
                seal: &direct_seal,
                verifying_key: &fallback_signer.verifying_key(),
            }),
            None,
        )
        .expect_err("fallback with mismatched issuer semantics must fail closed");

        assert!(matches!(
            err,
            ReceiptPointerError::FallbackVerificationFailed {
                reason: BatchFallbackReason::IntegrityFailure,
                fallback,
                ..
            } if matches!(
                *fallback,
                ReceiptPointerError::FallbackAuthoritySemanticsMismatch {
                    batch_requires_quorum: false,
                    batch_threshold: None,
                    ..
                }
            )
        ));
    }

    #[test]
    fn verify_batch_fail_closed_when_quorum_batch_falls_back_to_direct() {
        let signer_a = Signer::generate();
        let signer_b = Signer::generate();
        let signer_c = Signer::generate();
        let receipt_hashes = [[0xA2; 32], [0xA3; 32]];
        let (root, proofs) = build_merkle_tree(&receipt_hashes);

        let (quorum_batch_seal, quorum_keys) =
            make_quorum_batch_seal_threshold_2of3(&signer_a, &signer_b, &signer_c, &root, true);
        let batch_seal_hash = *blake3::hash(&quorum_batch_seal.canonical_bytes()).as_bytes();
        let mut tampered_proof = proofs[0].clone();
        tampered_proof.siblings[0].hash = [0xDD; 32];
        let batch_ptr =
            ReceiptPointerV1::new_batch(receipt_hashes[0], batch_seal_hash, tampered_proof)
                .expect("batch ptr");

        let direct_seal = make_direct_seal(&signer_a, &receipt_hashes[0]);
        let direct_seal_hash = *blake3::hash(&direct_seal.canonical_bytes()).as_bytes();
        let direct_ptr =
            ReceiptPointerV1::new_direct(receipt_hashes[0], direct_seal_hash).expect("direct ptr");

        let err = ReceiptPointerVerifier::verify_batch_with_fallback(
            &batch_ptr,
            &quorum_batch_seal,
            BatchSealVerifier::QuorumThreshold {
                verifying_keys: &quorum_keys,
                threshold: 2,
                weights: None,
            },
            TEST_SUBJECT_KIND,
            false,
            Some(DirectVerificationFallback {
                pointer: &direct_ptr,
                seal: &direct_seal,
                verifying_key: &signer_a.verifying_key(),
            }),
            None,
        )
        .expect_err("quorum batch fallback to direct must fail closed");

        assert!(matches!(
            err,
            ReceiptPointerError::FallbackVerificationFailed {
                reason: BatchFallbackReason::IntegrityFailure,
                fallback,
                ..
            } if matches!(
                *fallback,
                ReceiptPointerError::FallbackAuthoritySemanticsMismatch {
                    batch_requires_quorum: true,
                    batch_threshold: Some(2),
                    ..
                }
            )
        ));
    }

    // ────────── Unified verify() dispatch tests ──────────

    #[test]
    fn unified_verify_dispatches_direct() {
        let signer = Signer::generate();
        let receipt_hash = [0x42; HASH_SIZE];
        let seal = make_direct_seal(&signer, &receipt_hash);
        let seal_bytes = seal.canonical_bytes();
        let seal_hash = *blake3::hash(&seal_bytes).as_bytes();

        let ptr = ReceiptPointerV1::new_direct(receipt_hash, seal_hash).unwrap();

        let result = ReceiptPointerVerifier::verify(
            &ptr,
            &seal,
            &signer.verifying_key(),
            TEST_SUBJECT_KIND,
            false,
        );

        assert!(result.is_ok());
        assert_eq!(result.unwrap().pointer_kind, PointerKind::Direct);
    }

    #[test]
    fn unified_verify_dispatches_batch() {
        let signer = Signer::generate();
        let receipt_hashes = [[0x42; 32], [0x43; 32]];
        let (root, proofs) = build_merkle_tree(&receipt_hashes);

        let seal = make_batch_seal(&signer, &root);
        let seal_bytes = seal.canonical_bytes();
        let seal_hash = *blake3::hash(&seal_bytes).as_bytes();

        let ptr =
            ReceiptPointerV1::new_batch(receipt_hashes[0], seal_hash, proofs[0].clone()).unwrap();

        let result = ReceiptPointerVerifier::verify(
            &ptr,
            &seal,
            &signer.verifying_key(),
            TEST_SUBJECT_KIND,
            false,
        );

        assert!(result.is_ok());
        assert_eq!(result.unwrap().pointer_kind, PointerKind::Batch);
    }

    #[test]
    fn unified_verify_with_verifier_dispatches_quorum_batch() {
        let signer_a = Signer::generate();
        let signer_b = Signer::generate();
        let receipt_hashes = [[0x42; 32], [0x43; 32]];
        let (root, proofs) = build_merkle_tree(&receipt_hashes);
        let (seal, quorum_keys) = make_quorum_batch_seal_multisig(&signer_a, &signer_b, &root);
        let seal_hash = *blake3::hash(&seal.canonical_bytes()).as_bytes();
        let ptr =
            ReceiptPointerV1::new_batch(receipt_hashes[1], seal_hash, proofs[1].clone()).unwrap();

        let result = ReceiptPointerVerifier::verify_with_verifier(
            &ptr,
            &seal,
            &quorum_keys[0],
            BatchSealVerifier::QuorumMultisig {
                verifying_keys: &quorum_keys,
                weights: None,
            },
            TEST_SUBJECT_KIND,
            false,
        );

        assert!(
            result.is_ok(),
            "unified verifier must accept quorum-issued MERKLE_BATCH pointer when quorum verifier is provided, got: {result:?}",
        );
        assert_eq!(result.unwrap().pointer_kind, PointerKind::Batch);
    }

    #[test]
    fn unified_verify_rejects_fact_root() {
        let signer = Signer::generate();
        let receipt_hash = [0x42; HASH_SIZE];
        let seal = make_direct_seal(&signer, &receipt_hash);

        // Manually construct a FactRoot pointer.
        let ptr = ReceiptPointerV1 {
            receipt_hash,
            authority_seal_hash: [0xAA; 32],
            pointer_kind: PointerKind::FactRoot,
            inclusion_proof: None,
        };

        let result = ReceiptPointerVerifier::verify(
            &ptr,
            &seal,
            &signer.verifying_key(),
            TEST_SUBJECT_KIND,
            false,
        );

        assert!(matches!(
            result,
            Err(ReceiptPointerError::FactRootNotImplemented)
        ));
    }

    // ────────── Acceptance equivalence tests ──────────

    #[test]
    fn direct_and_batch_produce_equivalent_verification_results() {
        let signer = Signer::generate();
        let receipt_hash = [0x42; HASH_SIZE];

        // Direct path.
        let direct_seal = make_direct_seal(&signer, &receipt_hash);
        let direct_seal_hash = *blake3::hash(&direct_seal.canonical_bytes()).as_bytes();
        let direct_ptr = ReceiptPointerV1::new_direct(receipt_hash, direct_seal_hash).unwrap();
        let direct_result = ReceiptPointerVerifier::verify_direct(
            &direct_ptr,
            &direct_seal,
            &signer.verifying_key(),
            TEST_SUBJECT_KIND,
            false,
        )
        .unwrap();

        // Batch path (single receipt in batch).
        let (root, proofs) = build_merkle_tree(&[receipt_hash]);
        let batch_seal = make_batch_seal(&signer, &root);
        let batch_seal_hash = *blake3::hash(&batch_seal.canonical_bytes()).as_bytes();
        let batch_ptr =
            ReceiptPointerV1::new_batch(receipt_hash, batch_seal_hash, proofs[0].clone()).unwrap();
        let batch_result = ReceiptPointerVerifier::verify_batch(
            &batch_ptr,
            &batch_seal,
            BatchSealVerifier::SingleKey(&signer.verifying_key()),
            TEST_SUBJECT_KIND,
            false,
        )
        .unwrap();

        // Both paths produce the same receipt hash in the result.
        assert_eq!(direct_result.receipt_hash, batch_result.receipt_hash);
        // Pointer kinds differ (expected), but the verified receipt hash
        // is identical — this is behavioral acceptance equivalence.
        assert_eq!(direct_result.pointer_kind, PointerKind::Direct);
        assert_eq!(batch_result.pointer_kind, PointerKind::Batch);
    }

    // ────────── ReceiptMultiProofV1 construction tests ──────────

    #[test]
    fn multiproof_rejects_empty() {
        let result = ReceiptMultiProofV1::new([0x42; 32], vec![], [0xAA; 32], vec![]);
        assert!(matches!(result, Err(ReceiptPointerError::EmptyMultiproof)));
    }

    #[test]
    fn multiproof_rejects_unsorted_leaves() {
        let hashes = vec![[0x43; 32], [0x42; 32]]; // Not sorted.
        let result = ReceiptMultiProofV1::new([0x42; 32], hashes, [0xAA; 32], vec![]);
        assert!(matches!(result, Err(ReceiptPointerError::UnsortedLeaves)));
    }

    #[test]
    fn multiproof_rejects_duplicate_leaves() {
        let hashes = vec![[0x42; 32], [0x42; 32]]; // Duplicate.
        let result = ReceiptMultiProofV1::new([0x42; 32], hashes, [0xAA; 32], vec![]);
        assert!(matches!(result, Err(ReceiptPointerError::DuplicateLeaves)));
    }

    #[test]
    fn multiproof_rejects_mismatched_proof_count() {
        let hashes = vec![[0x42; 32], [0x43; 32]];
        let (root, proofs) = build_merkle_tree(&hashes);
        // Only provide one proof for two receipts.
        let result = ReceiptMultiProofV1::new(root, hashes, [0xAA; 32], vec![proofs[0].clone()]);
        assert!(matches!(
            result,
            Err(ReceiptPointerError::ProofCountMismatch {
                expected: 2,
                actual: 1,
            })
        ));
    }

    #[test]
    fn multiproof_rejects_zero_seal_hash() {
        let hashes = vec![[0x42; 32]];
        let (root, proofs) = build_merkle_tree(&hashes);
        let result = ReceiptMultiProofV1::new(root, hashes, [0u8; 32], proofs);
        assert!(matches!(
            result,
            Err(ReceiptPointerError::MissingSealHash { .. })
        ));
    }

    #[test]
    fn multiproof_valid_construction_and_membership() {
        let mut hashes = vec![[0x42; 32], [0x43; 32], [0x44; 32], [0x45; 32]];
        hashes.sort_unstable();
        let (root, proofs) = build_merkle_tree(&hashes);

        let multiproof =
            ReceiptMultiProofV1::new(root, hashes.clone(), [0xAA; 32], proofs).unwrap();

        assert_eq!(multiproof.receipt_count(), 4);
        assert_eq!(*multiproof.batch_root_hash(), root);

        for hash in &hashes {
            assert!(multiproof.contains_receipt(hash));
        }
        assert!(!multiproof.contains_receipt(&[0xFF; 32]));
    }

    #[test]
    fn multiproof_canonical_bytes_deterministic() {
        let mut hashes = vec![[0x42; 32], [0x43; 32]];
        hashes.sort_unstable();
        let (root, proofs) = build_merkle_tree(&hashes);

        let mp = ReceiptMultiProofV1::new(root, hashes, [0xAA; 32], proofs).unwrap();
        assert_eq!(mp.canonical_bytes(), mp.canonical_bytes());
    }

    #[test]
    fn multiproof_content_hash_deterministic() {
        let mut hashes = vec![[0x42; 32], [0x43; 32]];
        hashes.sort_unstable();
        let (root, proofs) = build_merkle_tree(&hashes);

        let mp = ReceiptMultiProofV1::new(root, hashes, [0xAA; 32], proofs).unwrap();
        assert_eq!(mp.content_hash(), mp.content_hash());
    }

    // ────────── Multiproof verification tests ──────────

    #[test]
    fn verify_multiproof_valid() {
        let signer = Signer::generate();
        let mut hashes = vec![[0x42; 32], [0x43; 32], [0x44; 32], [0x45; 32]];
        hashes.sort_unstable();
        let (root, proofs) = build_merkle_tree(&hashes);

        let seal = make_batch_seal(&signer, &root);
        let seal_hash = *blake3::hash(&seal.canonical_bytes()).as_bytes();

        let multiproof = ReceiptMultiProofV1::new(root, hashes.clone(), seal_hash, proofs).unwrap();

        let results = ReceiptPointerVerifier::verify_multiproof(
            &multiproof,
            &seal,
            BatchSealVerifier::SingleKey(&signer.verifying_key()),
            TEST_SUBJECT_KIND,
            false,
        )
        .unwrap();

        assert_eq!(results.len(), 4);
        for (result, hash) in results.iter().zip(hashes.iter()) {
            assert_eq!(result.receipt_hash, *hash);
            assert_eq!(result.pointer_kind, PointerKind::Batch);
        }
    }

    #[test]
    fn verify_multiproof_rejects_quorum_seal_with_single_key_verifier() {
        let signer_a = Signer::generate();
        let signer_b = Signer::generate();
        let mut hashes = vec![[0x42; 32], [0x43; 32], [0x44; 32], [0x45; 32]];
        hashes.sort_unstable();
        let (root, proofs) = build_merkle_tree(&hashes);
        let (seal, _quorum_keys) = make_quorum_batch_seal_multisig(&signer_a, &signer_b, &root);
        let seal_hash = *blake3::hash(&seal.canonical_bytes()).as_bytes();
        let multiproof = ReceiptMultiProofV1::new(root, hashes.clone(), seal_hash, proofs).unwrap();

        let result = ReceiptPointerVerifier::verify_multiproof(
            &multiproof,
            &seal,
            BatchSealVerifier::SingleKey(&signer_a.verifying_key()),
            TEST_SUBJECT_KIND,
            false,
        );

        assert!(
            matches!(
                result,
                Err(ReceiptPointerError::BatchVerifierMismatch {
                    seal_kind: SealKind::MerkleBatch,
                    ..
                })
            ),
            "single-key verifier must reject quorum-issued MERKLE_BATCH multiproof, got: {result:?}",
        );
    }

    #[test]
    fn verify_multiproof_accepts_quorum_multisig_verifier() {
        let signer_a = Signer::generate();
        let signer_b = Signer::generate();
        let mut hashes = vec![[0x42; 32], [0x43; 32], [0x44; 32], [0x45; 32]];
        hashes.sort_unstable();
        let (root, proofs) = build_merkle_tree(&hashes);
        let (seal, quorum_keys) = make_quorum_batch_seal_multisig(&signer_a, &signer_b, &root);
        let seal_hash = *blake3::hash(&seal.canonical_bytes()).as_bytes();
        let multiproof = ReceiptMultiProofV1::new(root, hashes.clone(), seal_hash, proofs).unwrap();

        let result = ReceiptPointerVerifier::verify_multiproof(
            &multiproof,
            &seal,
            BatchSealVerifier::QuorumMultisig {
                verifying_keys: &quorum_keys,
                weights: None,
            },
            TEST_SUBJECT_KIND,
            false,
        );

        assert!(
            result.is_ok(),
            "quorum multisig verifier must accept quorum-issued MERKLE_BATCH multiproof, got: {result:?}",
        );
        assert_eq!(result.unwrap().len(), 4);
    }

    #[test]
    fn verify_multiproof_rejects_quorum_threshold_when_threshold_not_met() {
        let signer_a = Signer::generate();
        let signer_b = Signer::generate();
        let signer_c = Signer::generate();
        let mut hashes = vec![[0x42; 32], [0x43; 32], [0x44; 32], [0x45; 32]];
        hashes.sort_unstable();
        let (root, proofs) = build_merkle_tree(&hashes);
        let (seal, quorum_keys) =
            make_quorum_batch_seal_threshold_2of3(&signer_a, &signer_b, &signer_c, &root, false);
        let seal_hash = *blake3::hash(&seal.canonical_bytes()).as_bytes();
        let multiproof = ReceiptMultiProofV1::new(root, hashes, seal_hash, proofs).unwrap();

        let result = ReceiptPointerVerifier::verify_multiproof(
            &multiproof,
            &seal,
            BatchSealVerifier::QuorumThreshold {
                verifying_keys: &quorum_keys,
                threshold: 2,
                weights: None,
            },
            TEST_SUBJECT_KIND,
            false,
        );

        assert!(
            matches!(
                result,
                Err(ReceiptPointerError::SealError(
                    AuthoritySealError::ThresholdNotMet {
                        valid_sigs: 1,
                        threshold: 2,
                    }
                ))
            ),
            "quorum threshold verifier must reject when threshold is not met, got: {result:?}",
        );
    }

    #[test]
    fn verify_multiproof_wrong_key() {
        let signer = Signer::generate();
        let wrong_signer = Signer::generate();
        let mut hashes = vec![[0x42; 32], [0x43; 32]];
        hashes.sort_unstable();
        let (root, proofs) = build_merkle_tree(&hashes);

        let seal = make_batch_seal(&signer, &root);
        let seal_hash = *blake3::hash(&seal.canonical_bytes()).as_bytes();

        let multiproof = ReceiptMultiProofV1::new(root, hashes, seal_hash, proofs).unwrap();

        let result = ReceiptPointerVerifier::verify_multiproof(
            &multiproof,
            &seal,
            BatchSealVerifier::SingleKey(&wrong_signer.verifying_key()),
            TEST_SUBJECT_KIND,
            false,
        );

        assert!(result.is_err());
    }

    #[test]
    fn multiproof_rejects_wrong_root() {
        let hashes = vec![[0x42; 32]];
        let (_, proofs) = build_merkle_tree(&hashes);
        let wrong_root = [0xFF; 32];

        let result = ReceiptMultiProofV1::new(wrong_root, hashes, [0xAA; 32], proofs);
        // Should fail because the proof doesn't verify against the wrong root.
        assert!(result.is_err());
    }

    #[test]
    fn verify_direct_rejects_non_direct_pointer_kind() {
        let signer = Signer::generate();
        let receipt_hashes = [[0x42; 32], [0x43; 32]];
        let (_root, proofs) = build_merkle_tree(&receipt_hashes);
        let seal_hash = [0xAA; 32];
        let batch_pointer =
            ReceiptPointerV1::new_batch(receipt_hashes[0], seal_hash, proofs[0].clone()).unwrap();
        let direct_seal = make_direct_seal(&signer, &receipt_hashes[0]);

        let result = ReceiptPointerVerifier::verify_direct(
            &batch_pointer,
            &direct_seal,
            &signer.verifying_key(),
            TEST_SUBJECT_KIND,
            false,
        );

        assert!(
            matches!(
                result,
                Err(ReceiptPointerError::PointerKindMismatch {
                    expected: PointerKind::Direct,
                    actual: PointerKind::Batch,
                })
            ),
            "expected PointerKindMismatch(Direct, Batch), got: {result:?}",
        );
    }

    #[test]
    fn verify_batch_rejects_non_batch_pointer_kind() {
        let signer = Signer::generate();
        let receipt_hash = [0x42; 32];
        let seal_hash = [0xAA; 32];
        let direct_pointer = ReceiptPointerV1::new_direct(receipt_hash, seal_hash).unwrap();
        let batch_seal = make_batch_seal(&signer, &[0xBB; 32]);

        let result = ReceiptPointerVerifier::verify_batch(
            &direct_pointer,
            &batch_seal,
            BatchSealVerifier::SingleKey(&signer.verifying_key()),
            TEST_SUBJECT_KIND,
            false,
        );

        assert!(
            matches!(
                result,
                Err(ReceiptPointerError::PointerKindMismatch {
                    expected: PointerKind::Batch,
                    actual: PointerKind::Direct,
                })
            ),
            "expected PointerKindMismatch(Batch, Direct), got: {result:?}",
        );
    }

    // ────────── Seal-hash binding negative tests ──────────

    #[test]
    fn verify_direct_rejects_seal_hash_mismatch() {
        let signer = Signer::generate();
        let receipt_hash = [0x42; HASH_SIZE];
        let seal = make_direct_seal(&signer, &receipt_hash);

        // Use a wrong seal hash (not derived from this seal).
        let wrong_seal_hash = [0xFF; 32];
        let ptr = ReceiptPointerV1::new_direct(receipt_hash, wrong_seal_hash).unwrap();

        let result = ReceiptPointerVerifier::verify_direct(
            &ptr,
            &seal,
            &signer.verifying_key(),
            TEST_SUBJECT_KIND,
            false,
        );

        assert!(
            matches!(result, Err(ReceiptPointerError::SealHashMismatch { .. })),
            "expected SealHashMismatch, got: {result:?}",
        );
    }

    #[test]
    fn verify_batch_rejects_seal_hash_mismatch() {
        let signer = Signer::generate();
        let receipt_hashes = [[0x42; 32], [0x43; 32]];
        let (root, proofs) = build_merkle_tree(&receipt_hashes);
        let seal = make_batch_seal(&signer, &root);

        // Use a wrong seal hash.
        let wrong_seal_hash = [0xFF; 32];
        let ptr =
            ReceiptPointerV1::new_batch(receipt_hashes[0], wrong_seal_hash, proofs[0].clone())
                .unwrap();

        let result = ReceiptPointerVerifier::verify_batch(
            &ptr,
            &seal,
            BatchSealVerifier::SingleKey(&signer.verifying_key()),
            TEST_SUBJECT_KIND,
            false,
        );

        assert!(
            matches!(result, Err(ReceiptPointerError::SealHashMismatch { .. })),
            "expected SealHashMismatch, got: {result:?}",
        );
    }

    #[test]
    fn verify_multiproof_rejects_seal_hash_mismatch() {
        let signer = Signer::generate();
        let mut hashes = vec![[0x42; 32], [0x43; 32]];
        hashes.sort_unstable();
        let (root, proofs) = build_merkle_tree(&hashes);
        let seal = make_batch_seal(&signer, &root);

        // Use a wrong seal hash (not the actual seal hash).
        let wrong_seal_hash = [0xDD; 32];
        let multiproof = ReceiptMultiProofV1::new(root, hashes, wrong_seal_hash, proofs).unwrap();

        let result = ReceiptPointerVerifier::verify_multiproof(
            &multiproof,
            &seal,
            BatchSealVerifier::SingleKey(&signer.verifying_key()),
            TEST_SUBJECT_KIND,
            false,
        );

        assert!(
            matches!(result, Err(ReceiptPointerError::SealHashMismatch { .. })),
            "expected SealHashMismatch, got: {result:?}",
        );
    }

    #[test]
    fn verify_multiproof_rejects_batch_root_mismatch() {
        let signer = Signer::generate();
        let mut hashes = vec![[0x42; 32], [0x43; 32]];
        hashes.sort_unstable();
        let (root, proofs) = build_merkle_tree(&hashes);
        let seal = make_batch_seal(&signer, &root);
        let seal_hash = *blake3::hash(&seal.canonical_bytes()).as_bytes();

        // Tamper the declared batch root while keeping proofs + seal hash.
        let tampered_root = [0xEE; 32];
        let tampered = ReceiptMultiProofV1::new_unchecked(tampered_root, hashes, seal_hash, proofs);

        let result = ReceiptPointerVerifier::verify_multiproof(
            &tampered,
            &seal,
            BatchSealVerifier::SingleKey(&signer.verifying_key()),
            TEST_SUBJECT_KIND,
            false,
        );

        assert!(
            matches!(result, Err(ReceiptPointerError::MultiproofRootMismatch)),
            "expected MultiproofRootMismatch, got: {result:?}",
        );
    }

    /// SECURITY: `verify_multiproof` must independently verify every
    /// inclusion proof -- not just the first. A multiproof where the
    /// first proof is valid but a subsequent proof has a tampered leaf
    /// hash MUST be rejected (fail-closed, transactional: all-or-nothing).
    ///
    /// Uses `new_unchecked` to bypass constructor validation, simulating
    /// state corruption or a decoder bug that produces a multiproof
    /// with a tampered proof.
    #[test]
    fn verify_multiproof_rejects_tampered_subsequent_proof() {
        let signer = Signer::generate();
        let mut hashes = vec![[0x42; 32], [0x43; 32], [0x44; 32], [0x45; 32]];
        hashes.sort_unstable();
        let (root, mut proofs) = build_merkle_tree(&hashes);

        let seal = make_batch_seal(&signer, &root);
        let seal_hash = *blake3::hash(&seal.canonical_bytes()).as_bytes();

        // Tamper with the SECOND proof's leaf hash so it won't verify
        // against the batch root, while keeping the first proof intact.
        proofs[1].leaf_hash = [0xFF; 32];

        // Bypass constructor validation via `new_unchecked` to simulate
        // a decoder bug or state corruption that lets a tampered
        // multiproof through.
        let tampered = ReceiptMultiProofV1::new_unchecked(root, hashes.clone(), seal_hash, proofs);

        let result = ReceiptPointerVerifier::verify_multiproof(
            &tampered,
            &seal,
            BatchSealVerifier::SingleKey(&signer.verifying_key()),
            TEST_SUBJECT_KIND,
            false,
        );

        assert!(
            result.is_err(),
            "verify_multiproof must reject multiproof with tampered \
             subsequent proof, got: {result:?}",
        );
    }

    /// SECURITY: `verify_multiproof` must reject a multiproof where
    /// a subsequent proof reconstructs to a DIFFERENT root than the
    /// seal's batch root. This tests the inclusion-proof-to-root
    /// verification (not just the leaf hash check).
    #[test]
    fn verify_multiproof_rejects_wrong_root_in_subsequent_proof() {
        let signer = Signer::generate();
        let mut hashes = vec![[0x42; 32], [0x43; 32]];
        hashes.sort_unstable();
        let (root, proofs) = build_merkle_tree(&hashes);

        let seal = make_batch_seal(&signer, &root);
        let seal_hash = *blake3::hash(&seal.canonical_bytes()).as_bytes();

        // Build a proof for the second receipt from a DIFFERENT tree.
        let mut other_hashes = vec![[0x43; 32], [0x99; 32]];
        other_hashes.sort_unstable();
        let (_other_root, other_proofs) = build_merkle_tree(&other_hashes);

        // Find which index in other_proofs corresponds to [0x43; 32].
        let other_idx = other_hashes.iter().position(|h| *h == [0x43; 32]).unwrap();

        // Use the first valid proof, but swap the second proof with one
        // from the other tree. The leaf hash is correct (same receipt
        // hash) but the proof path reconstructs to a different root.
        let tampered_proofs = vec![proofs[0].clone(), other_proofs[other_idx].clone()];

        let tampered =
            ReceiptMultiProofV1::new_unchecked(root, hashes.clone(), seal_hash, tampered_proofs);

        let result = ReceiptPointerVerifier::verify_multiproof(
            &tampered,
            &seal,
            BatchSealVerifier::SingleKey(&signer.verifying_key()),
            TEST_SUBJECT_KIND,
            false,
        );

        assert!(
            result.is_err(),
            "verify_multiproof must reject when subsequent proof \
             reconstructs to wrong root, got: {result:?}",
        );
    }

    /// SECURITY: `verify_multiproof` must verify all inclusion proofs at
    /// the verification boundary. This test constructs a valid 4-receipt
    /// multiproof and confirms all 4 receipts are verified (not just
    /// the first). We verify by checking that the result contains
    /// exactly 4 entries and each matches.
    #[test]
    fn verify_multiproof_verifies_all_receipts_not_just_first() {
        let signer = Signer::generate();
        let mut hashes = vec![[0x42; 32], [0x43; 32], [0x44; 32], [0x45; 32]];
        hashes.sort_unstable();
        let (root, proofs) = build_merkle_tree(&hashes);

        let seal = make_batch_seal(&signer, &root);
        let seal_hash = *blake3::hash(&seal.canonical_bytes()).as_bytes();

        let multiproof = ReceiptMultiProofV1::new(root, hashes.clone(), seal_hash, proofs).unwrap();

        let results = ReceiptPointerVerifier::verify_multiproof(
            &multiproof,
            &seal,
            BatchSealVerifier::SingleKey(&signer.verifying_key()),
            TEST_SUBJECT_KIND,
            false,
        )
        .unwrap();

        // All 4 receipts must be present in results.
        assert_eq!(results.len(), 4, "must verify all 4 receipts");
        for (i, result) in results.iter().enumerate() {
            assert_eq!(result.receipt_hash, hashes[i], "receipt {i} hash mismatch");
            assert_eq!(
                result.pointer_kind,
                PointerKind::Batch,
                "receipt {i} pointer kind mismatch"
            );
            assert_eq!(
                result.authority_seal_hash, seal_hash,
                "receipt {i} seal hash mismatch"
            );
        }
    }

    // ────────── Multiproof bounds enforcement tests ──────────

    #[test]
    fn multiproof_rejects_too_many_proof_nodes() {
        // The node-count check runs BEFORE proof verification (admission
        // before computation), so we can construct proofs with many
        // siblings that don't need to be cryptographically valid.
        //
        // We need: total siblings across all proofs > MAX_MULTIPROOF_NODES.
        // Use 2 receipts, each with (MAX_MULTIPROOF_NODES / 2 + 1)
        // siblings. Each individual proof stays within MAX_MERKLE_PROOF_DEPTH?
        // No — MAX_MERKLE_PROOF_DEPTH = 20, which is much smaller. So each
        // proof can have at most 20 siblings. We'd need > 1024 proofs.
        //
        // Instead, test with a smaller number but enough to exceed the
        // total: use (MAX_MULTIPROOF_NODES / MAX_MERKLE_PROOF_DEPTH) + 1
        // receipts, each at max depth.
        let receipts_needed = (MAX_MULTIPROOF_NODES / MAX_MERKLE_PROOF_DEPTH) + 1;
        let mut hashes: Vec<Hash> = (0..receipts_needed)
            .map(|i| {
                let mut h = [0u8; 32];
                // Encode index across multiple bytes for uniqueness.
                #[allow(clippy::cast_possible_truncation)]
                h[..4].copy_from_slice(&(i as u32).to_le_bytes());
                h
            })
            .collect();
        hashes.sort_unstable();
        hashes.dedup();
        hashes.truncate(receipts_needed);
        assert_eq!(hashes.len(), receipts_needed);

        // Build fake proofs, each with MAX_MERKLE_PROOF_DEPTH siblings.
        let proofs: Vec<MerkleInclusionProof> = hashes
            .iter()
            .map(|receipt_hash| {
                let leaf_hash = compute_receipt_leaf_hash(receipt_hash);
                let siblings: Vec<MerkleProofSibling> = (0..MAX_MERKLE_PROOF_DEPTH)
                    .map(|j| MerkleProofSibling {
                        #[allow(clippy::cast_possible_truncation)]
                        hash: [(j & 0xFF) as u8; 32],
                        is_left: false,
                    })
                    .collect();
                MerkleInclusionProof {
                    leaf_hash,
                    siblings,
                }
            })
            .collect();

        let total_nodes: usize = proofs.iter().map(|p| p.siblings.len()).sum();
        assert!(
            total_nodes > MAX_MULTIPROOF_NODES,
            "total nodes {total_nodes} should exceed MAX_MULTIPROOF_NODES {MAX_MULTIPROOF_NODES}",
        );

        let result = ReceiptMultiProofV1::new([0xBB; 32], hashes, [0xAA; 32], proofs);
        assert!(
            matches!(result, Err(ReceiptPointerError::TooManyProofNodes { .. })),
            "expected TooManyProofNodes, got: {result:?}",
        );
    }

    #[test]
    fn multiproof_enforces_size_limit() {
        // Verify that the MAX_RECEIPT_MULTIPROOF_BYTES check is enforced.
        // A valid multiproof's canonical bytes should be well below the
        // limit, confirming the check is wired but not triggered for
        // normal-sized inputs.
        let mut hashes = vec![[0x42; 32], [0x43; 32]];
        hashes.sort_unstable();
        let (root, proofs) = build_merkle_tree(&hashes);

        let mp = ReceiptMultiProofV1::new(root, hashes, [0xAA; 32], proofs).unwrap();

        // The canonical bytes should be well below the limit.
        let bytes = mp.canonical_bytes();
        assert!(
            bytes.len() < MAX_RECEIPT_MULTIPROOF_BYTES,
            "canonical bytes {} should be < {}",
            bytes.len(),
            MAX_RECEIPT_MULTIPROOF_BYTES,
        );
    }

    #[test]
    fn verify_multiproof_rejects_too_many_leaves_at_verification_boundary() {
        let signer = Signer::generate();
        let seal_root = [0xAB; 32];
        let seal = make_batch_seal(&signer, &seal_root);
        let seal_hash = *blake3::hash(&seal.canonical_bytes()).as_bytes();

        // Bypass constructor validation to simulate oversized decoded data.
        let oversized_receipts = vec![[0x11; 32]; MAX_MULTIPROOF_LEAVES + 1];
        let oversized = ReceiptMultiProofV1::new_unchecked(
            seal_root,
            oversized_receipts,
            seal_hash,
            Vec::new(),
        );

        let result = ReceiptPointerVerifier::verify_multiproof(
            &oversized,
            &seal,
            BatchSealVerifier::SingleKey(&signer.verifying_key()),
            TEST_SUBJECT_KIND,
            false,
        );

        assert!(
            matches!(result, Err(ReceiptPointerError::TooManyLeaves { .. })),
            "expected TooManyLeaves, got: {result:?}",
        );
    }

    #[test]
    fn verify_multiproof_rejects_too_many_nodes_at_verification_boundary() {
        let signer = Signer::generate();
        let receipt_hash = [0x42; 32];
        let seal_root = [0xAC; 32];
        let seal = make_batch_seal(&signer, &seal_root);
        let seal_hash = *blake3::hash(&seal.canonical_bytes()).as_bytes();

        let oversized_siblings: Vec<MerkleProofSibling> = (0..=MAX_MULTIPROOF_NODES)
            .map(|i| {
                #[allow(clippy::cast_possible_truncation)]
                let byte = (i & 0xFF) as u8;
                MerkleProofSibling {
                    hash: [byte; 32],
                    is_left: false,
                }
            })
            .collect();
        let oversized_proof = MerkleInclusionProof {
            leaf_hash: compute_receipt_leaf_hash(&receipt_hash),
            siblings: oversized_siblings,
        };
        let oversized = ReceiptMultiProofV1::new_unchecked(
            seal_root,
            vec![receipt_hash],
            seal_hash,
            vec![oversized_proof],
        );

        let result = ReceiptPointerVerifier::verify_multiproof(
            &oversized,
            &seal,
            BatchSealVerifier::SingleKey(&signer.verifying_key()),
            TEST_SUBJECT_KIND,
            false,
        );

        assert!(
            matches!(result, Err(ReceiptPointerError::TooManyProofNodes { .. })),
            "expected TooManyProofNodes, got: {result:?}",
        );
    }

    #[test]
    fn verify_multiproof_rejects_oversized_serialized_input_at_verification_boundary() {
        let signer = Signer::generate();
        let seal_root = [0xAD; 32];
        let seal = make_batch_seal(&signer, &seal_root);
        let seal_hash = *blake3::hash(&seal.canonical_bytes()).as_bytes();

        // 16k receipts with zero-sibling proofs exceed the 1 MiB multiproof
        // byte cap but still satisfy leaf/node cardinality bounds.
        let receipt_count = 16_000usize;
        let receipt_hashes: Vec<Hash> = (0..receipt_count)
            .map(|i| {
                let mut hash = [0u8; 32];
                #[allow(clippy::cast_possible_truncation)]
                let index = i as u32;
                hash[..4].copy_from_slice(&index.to_be_bytes());
                hash
            })
            .collect();
        let individual_proofs: Vec<MerkleInclusionProof> = receipt_hashes
            .iter()
            .map(|receipt_hash| MerkleInclusionProof {
                leaf_hash: compute_receipt_leaf_hash(receipt_hash),
                siblings: Vec::new(),
            })
            .collect();
        let estimated_size =
            estimate_multiproof_serialized_size(receipt_hashes.len(), &individual_proofs);
        assert!(
            estimated_size > MAX_RECEIPT_MULTIPROOF_BYTES,
            "test setup must exceed multiproof byte cap: estimated_size={estimated_size}, max={MAX_RECEIPT_MULTIPROOF_BYTES}",
        );

        // Bypass constructor validation to simulate decoded untrusted input.
        let oversized = ReceiptMultiProofV1::new_unchecked(
            seal_root,
            receipt_hashes,
            seal_hash,
            individual_proofs,
        );
        let result = ReceiptPointerVerifier::verify_multiproof(
            &oversized,
            &seal,
            BatchSealVerifier::SingleKey(&signer.verifying_key()),
            TEST_SUBJECT_KIND,
            false,
        );

        match result {
            Err(ReceiptPointerError::SizeExceeded { max, actual }) => {
                assert_eq!(max, MAX_RECEIPT_MULTIPROOF_BYTES);
                assert!(
                    actual > max,
                    "expected actual size {actual} to exceed max {max}",
                );
            },
            other => panic!("expected SizeExceeded, got: {other:?}"),
        }
    }

    #[test]
    fn verify_multiproof_rejects_proof_count_mismatch_at_verification_boundary() {
        let signer = Signer::generate();
        let mut hashes = vec![[0x42; 32], [0x43; 32]];
        hashes.sort_unstable();
        let (root, proofs) = build_merkle_tree(&hashes);
        let seal = make_batch_seal(&signer, &root);
        let seal_hash = *blake3::hash(&seal.canonical_bytes()).as_bytes();
        let malformed =
            ReceiptMultiProofV1::new_unchecked(root, hashes, seal_hash, vec![proofs[0].clone()]);

        let result = ReceiptPointerVerifier::verify_multiproof(
            &malformed,
            &seal,
            BatchSealVerifier::SingleKey(&signer.verifying_key()),
            TEST_SUBJECT_KIND,
            false,
        );

        assert!(
            matches!(
                result,
                Err(ReceiptPointerError::ProofCountMismatch {
                    expected: 2,
                    actual: 1,
                })
            ),
            "expected ProofCountMismatch(expected=2, actual=1), got: {result:?}",
        );
    }

    #[test]
    fn verify_multiproof_rejects_unsorted_receipts_at_verification_boundary() {
        let signer = Signer::generate();
        let unsorted_receipts = vec![[0x43; 32], [0x42; 32]];
        let (root, proofs) = build_merkle_tree(&unsorted_receipts);
        let seal = make_batch_seal(&signer, &root);
        let seal_hash = *blake3::hash(&seal.canonical_bytes()).as_bytes();
        let unsorted =
            ReceiptMultiProofV1::new_unchecked(root, unsorted_receipts, seal_hash, proofs);

        let result = ReceiptPointerVerifier::verify_multiproof(
            &unsorted,
            &seal,
            BatchSealVerifier::SingleKey(&signer.verifying_key()),
            TEST_SUBJECT_KIND,
            false,
        );

        assert!(
            matches!(result, Err(ReceiptPointerError::UnsortedLeaves)),
            "expected UnsortedLeaves, got: {result:?}",
        );
    }

    #[test]
    fn verify_multiproof_rejects_duplicate_receipts_at_verification_boundary() {
        let signer = Signer::generate();
        let duplicate_receipt = [0x55; 32];
        let duplicates = vec![duplicate_receipt, duplicate_receipt];
        let seal_root = [0xAD; 32];
        let seal = make_batch_seal(&signer, &seal_root);
        let seal_hash = *blake3::hash(&seal.canonical_bytes()).as_bytes();
        let duplicate_proofs = vec![
            MerkleInclusionProof {
                leaf_hash: compute_receipt_leaf_hash(&duplicate_receipt),
                siblings: vec![],
            },
            MerkleInclusionProof {
                leaf_hash: compute_receipt_leaf_hash(&duplicate_receipt),
                siblings: vec![],
            },
        ];
        let duplicate_multiproof =
            ReceiptMultiProofV1::new_unchecked(seal_root, duplicates, seal_hash, duplicate_proofs);

        let result = ReceiptPointerVerifier::verify_multiproof(
            &duplicate_multiproof,
            &seal,
            BatchSealVerifier::SingleKey(&signer.verifying_key()),
            TEST_SUBJECT_KIND,
            false,
        );

        assert!(
            matches!(result, Err(ReceiptPointerError::DuplicateLeaves)),
            "expected DuplicateLeaves, got: {result:?}",
        );
    }

    // ────────── FactRoot deferred test ──────────

    #[test]
    fn fact_root_pointer_kind_exists_but_deferred() {
        assert_eq!(PointerKind::from_tag(0x03), Some(PointerKind::FactRoot));
        assert_eq!(PointerKind::FactRoot.label(), "fact_root");
    }
}
