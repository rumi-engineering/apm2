// AGENT-AUTHORED
//! `FactRootV1` composition with RFC-0014 quorum checkpoints (TCK-00370).
//!
//! This module provides:
//! - [`FactRootV1`]: binds batch Merkle roots into QC-certified checkpoints so
//!   that BFT-mode batch roots are checkpoint-composed by default.
//! - [`FactRootVerifier`]: validates a `FactRootV1` against a quorum
//!   certificate, rejecting free-floating batch roots that lack a QC anchor.
//! - [`CompactMultiProof`]: compact shared-sibling multiproof wire shape
//!   (`proof_nodes[]` + `proof_structure`) per RFC-0020 §9.5.5, enabling
//!   sibling deduplication across multiple Merkle inclusion proofs.
//!
//! # Security Properties
//!
//! - **Fail-closed**: unknown or missing fields produce errors; free-floating
//!   batch roots (no QC anchor) are unconditionally rejected.
//! - **Bounded collections (CTR-1303)**: all vectors are bounded to prevent
//!   denial-of-service via memory exhaustion.
//! - **Domain-separated hashing**: `FactRootV1` canonical bytes use a unique
//!   domain separator to prevent cross-protocol hash collisions.
//! - **Content-addressed**: every `FactRootV1` is CAS-addressable via its
//!   content hash.
//!
//! # References
//!
//! - RFC-0014: Distributed Consensus and Replication Layer
//! - RFC-0020 §9.5.5: Compact multiproof wire shape
//! - TCK-00363: `ReceiptPointerV1` and `ReceiptMultiProofV1` (deferred compact
//!   multiproof to this ticket)
//! - REQ-0024: `FactRoot` composition requirement

use thiserror::Error;

use super::merkle::{MAX_TREE_DEPTH, hash_internal, hash_leaf};
use super::qc_aggregator::{QcVerificationContext, verify_qc};
use crate::crypto::{EventHasher, HASH_SIZE, Hash};

// ============================================================================
// Constants
// ============================================================================

/// Domain separator for `FactRootV1` canonical bytes.
const FACT_ROOT_DOMAIN_SEPARATOR: &[u8] = b"apm2:fact_root:v1\0";

/// Domain separator for compact multiproof canonical bytes.
const COMPACT_MULTIPROOF_DOMAIN_SEPARATOR: &[u8] = b"apm2:compact_multiproof:v1\0";

/// Maximum number of batch roots a single `FactRootV1` can bind.
///
/// Bounded to prevent denial-of-service. 1024 batches per checkpoint is
/// generous for practical deployments.
pub const MAX_BATCH_ROOTS: usize = 1024;

/// Maximum number of proof nodes in a `CompactMultiProof`.
///
/// For K leaves at depth D, at most K * D sibling nodes are needed.
/// Conservatively bounded to prevent denial-of-service.
pub const MAX_COMPACT_PROOF_NODES: usize = 20 * 1024;

/// Maximum proof structure bytes in a `CompactMultiProof`.
///
/// The proof structure is a bit-encoded description of sibling sharing.
/// Each leaf path requires at most `MAX_TREE_DEPTH` bits, so for
/// `MAX_BATCH_ROOTS` leaves: ceil(1024 * 21 / 8) = 2688 bytes.
pub const MAX_COMPACT_PROOF_STRUCTURE: usize = 4096;

/// Maximum number of leaves in a `CompactMultiProof`.
pub const MAX_COMPACT_MULTIPROOF_LEAVES: usize = 1 << 20;

// ============================================================================
// QC canonical hash
// ============================================================================

/// Domain separator for QC anchor hash computation.
const QC_ANCHOR_DOMAIN_SEPARATOR: &[u8] = b"apm2:qc_anchor:v1\0";

/// Computes the anchor-binding hash of a `QuorumCertificate`.
///
/// This hash covers the QC's identity fields (epoch, round) and quorum
/// signatures but **excludes** `block_hash`, because `block_hash` is already
/// separately verified via `fact_root.content_hash() == qc.block_hash`.
/// Excluding `block_hash` avoids a circular dependency: the fact root's
/// `content_hash()` depends on `qc_anchor_hash`, which would depend on
/// `block_hash`, which in turn depends on `content_hash()`.
///
/// Layout:
/// ```text
/// domain_separator
/// + epoch (8 bytes LE)
/// + round (8 bytes LE)
/// + sig_count (4 bytes LE)
/// + [validator_id (32 bytes) + signature (64 bytes)] * sig_count
/// ```
///
/// Signatures are canonicalized by sorting on `validator_id` before hashing,
/// so that any permutation of the same QC signatures produces the same anchor
/// hash. Without this canonicalization, a Byzantine relay could reorder
/// signatures (which still pass QC verification) to produce a different anchor
/// hash, causing a denial-of-service via `QcAnchorHashMismatch`.
#[must_use]
pub fn compute_qc_anchor_hash(qc: &super::bft::QuorumCertificate) -> Hash {
    // Sort signatures by validator_id for canonical ordering.
    let mut sorted_sigs: Vec<&super::bft::ValidatorSignature> = qc.signatures.iter().collect();
    sorted_sigs.sort_by(|a, b| a.validator_id.cmp(&b.validator_id));

    let sig_count = sorted_sigs.len();
    let total = QC_ANCHOR_DOMAIN_SEPARATOR.len()
        + 8 // epoch
        + 8 // round
        + 4 // sig_count
        + sig_count * (32 + 64); // validator_id + signature per sig

    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(QC_ANCHOR_DOMAIN_SEPARATOR);
    out.extend_from_slice(&qc.epoch.to_le_bytes());
    out.extend_from_slice(&qc.round.to_le_bytes());
    #[allow(clippy::cast_possible_truncation)]
    let count = sig_count as u32;
    out.extend_from_slice(&count.to_le_bytes());
    for sig in &sorted_sigs {
        out.extend_from_slice(&sig.validator_id);
        out.extend_from_slice(&sig.signature);
    }

    EventHasher::hash_content(&out)
}

// ============================================================================
// Errors
// ============================================================================

/// Errors produced when constructing, verifying, or manipulating fact roots
/// and compact multiproofs.
#[derive(Debug, Error)]
pub enum FactRootError {
    /// The batch root hash is all zeros.
    #[error("batch root hash must not be zero")]
    ZeroBatchRoot,

    /// The quorum certificate hash is all zeros (free-floating batch root).
    #[error("QC anchor hash must not be zero: free-floating batch roots are rejected")]
    MissingQcAnchor,

    /// Too many batch roots in a single `FactRootV1`.
    #[error("batch root count {count} exceeds maximum {max}")]
    TooManyBatchRoots {
        /// Actual batch root count.
        count: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// No batch roots provided.
    #[error("FactRootV1 must contain at least one batch root")]
    EmptyBatchRoots,

    /// Duplicate batch roots detected.
    #[error("duplicate batch root at index {index}")]
    DuplicateBatchRoot {
        /// Index of the duplicate.
        index: usize,
    },

    /// Epoch mismatch between `FactRootV1` and QC.
    #[error("epoch mismatch: FactRoot epoch {fact_root_epoch}, QC epoch {qc_epoch}")]
    EpochMismatch {
        /// Epoch in the `FactRootV1`.
        fact_root_epoch: u64,
        /// Epoch in the QC.
        qc_epoch: u64,
    },

    /// The `FactRootV1` content hash does not match the QC block hash.
    #[error("FactRoot content hash does not match QC block hash")]
    ContentHashMismatch,

    /// QC verification failed.
    #[error("QC verification failed: {0}")]
    QcVerificationFailed(String),

    /// Genesis QC is not allowed in non-genesis verification context.
    #[error("genesis QC (round=0, no signatures) is not accepted in non-genesis context")]
    GenesisQcNotAllowed,

    /// The QC anchor hash does not match the canonical hash of the provided QC.
    #[error("QC anchor hash mismatch: fact root references a different QC")]
    QcAnchorHashMismatch,

    /// Compact multiproof has too many proof nodes.
    #[error("compact multiproof node count {count} exceeds maximum {max}")]
    TooManyProofNodes {
        /// Actual node count.
        count: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Compact multiproof structure is too large.
    #[error("compact multiproof structure size {size} exceeds maximum {max}")]
    ProofStructureTooLarge {
        /// Actual structure size in bytes.
        size: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Compact multiproof has too many leaves.
    #[error("compact multiproof leaf count {count} exceeds maximum {max}")]
    TooManyLeaves {
        /// Actual leaf count.
        count: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Compact multiproof has no leaves.
    #[error("compact multiproof must contain at least one leaf")]
    EmptyLeaves,

    /// Compact multiproof leaf hashes are not in sorted order.
    #[error("compact multiproof leaf hashes must be in canonical sorted order")]
    UnsortedLeaves,

    /// Compact multiproof contains duplicate leaf hashes.
    #[error("compact multiproof contains duplicate leaf hashes")]
    DuplicateLeaves,

    /// Compact multiproof root reconstruction failed.
    #[error("compact multiproof root mismatch: reconstructed root does not match expected root")]
    CompactProofRootMismatch,

    /// Compact multiproof structure is inconsistent with proof nodes.
    #[error("compact multiproof structure is inconsistent: {reason}")]
    InvalidProofStructure {
        /// Human-readable reason.
        reason: String,
    },

    /// Proof depth exceeded maximum tree depth.
    #[error("proof depth {depth} exceeds maximum tree depth {max}")]
    ProofDepthExceeded {
        /// Actual depth.
        depth: usize,
        /// Maximum allowed.
        max: usize,
    },
}

// ============================================================================
// FactRootV1
// ============================================================================

/// BFT-mode batch root composition checkpoint (RFC-0020).
///
/// A `FactRootV1` binds one or more batch Merkle roots into a QC-certified
/// checkpoint. This ensures that:
/// 1. Batch roots are not accepted without quorum authority.
/// 2. Verifiers can validate receipt membership via the QC + `FactRoot` path.
/// 3. Free-floating batch roots are unconditionally rejected.
///
/// # Content Addressing
///
/// The `content_hash()` of a `FactRootV1` is deterministic and serves as
/// the binding between the fact root and the QC's `block_hash`. A verifier
/// checks that `fact_root.content_hash() == qc.block_hash` to confirm the
/// QC certifies this specific fact root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FactRootV1 {
    /// Batch root hashes bound into this checkpoint.
    /// Must contain at least one root and at most `MAX_BATCH_ROOTS`.
    batch_roots: Vec<Hash>,
    /// Epoch of this checkpoint (must match the QC epoch).
    epoch: u64,
    /// Hash of the quorum certificate that anchors this fact root.
    /// Must not be zero (free-floating roots are rejected).
    qc_anchor_hash: Hash,
    /// Merkle root over all `batch_roots` for compact membership proofs.
    /// Computed deterministically from `batch_roots`.
    composed_root: Hash,
}

impl FactRootV1 {
    /// Construct a validated `FactRootV1`.
    ///
    /// # Arguments
    ///
    /// - `batch_roots`: one or more batch Merkle root hashes to bind.
    /// - `epoch`: the epoch of this checkpoint.
    /// - `qc_anchor_hash`: hash of the anchoring QC.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `batch_roots` is empty
    /// - `batch_roots` exceeds `MAX_BATCH_ROOTS`
    /// - Any batch root is all zeros
    /// - `qc_anchor_hash` is all zeros (free-floating)
    /// - Duplicate batch roots are present
    pub fn new(
        batch_roots: Vec<Hash>,
        epoch: u64,
        qc_anchor_hash: Hash,
    ) -> Result<Self, FactRootError> {
        if batch_roots.is_empty() {
            return Err(FactRootError::EmptyBatchRoots);
        }
        if batch_roots.len() > MAX_BATCH_ROOTS {
            return Err(FactRootError::TooManyBatchRoots {
                count: batch_roots.len(),
                max: MAX_BATCH_ROOTS,
            });
        }
        if qc_anchor_hash == [0u8; HASH_SIZE] {
            return Err(FactRootError::MissingQcAnchor);
        }

        // Validate no zero batch roots and no duplicates.
        for (i, root) in batch_roots.iter().enumerate() {
            if *root == [0u8; HASH_SIZE] {
                return Err(FactRootError::ZeroBatchRoot);
            }
            // Check for duplicates against earlier roots.
            for (j, earlier) in batch_roots[..i].iter().enumerate() {
                if root == earlier {
                    let _ = j; // bind for debugging
                    return Err(FactRootError::DuplicateBatchRoot { index: i });
                }
            }
        }

        let composed_root = Self::compute_composed_root(&batch_roots);

        Ok(Self {
            batch_roots,
            epoch,
            qc_anchor_hash,
            composed_root,
        })
    }

    /// Compute the Merkle root over the batch roots.
    ///
    /// Uses domain-separated leaf hashing consistent with the consensus
    /// Merkle tree implementation.
    #[must_use]
    fn compute_composed_root(batch_roots: &[Hash]) -> Hash {
        if batch_roots.len() == 1 {
            return hash_leaf(&batch_roots[0]);
        }

        // Build a balanced Merkle tree over batch roots.
        let mut current_level: Vec<Hash> = batch_roots.iter().map(hash_leaf).collect();

        while current_level.len() > 1 {
            let mut next_level = Vec::with_capacity(current_level.len().div_ceil(2));
            for chunk in current_level.chunks(2) {
                let hash = if chunk.len() == 2 {
                    hash_internal(&chunk[0], &chunk[1])
                } else {
                    hash_internal(&chunk[0], &[0u8; HASH_SIZE])
                };
                next_level.push(hash);
            }
            current_level = next_level;
        }

        current_level[0]
    }

    // ────────── Accessors ──────────

    /// Returns the batch root hashes.
    #[must_use]
    pub fn batch_roots(&self) -> &[Hash] {
        &self.batch_roots
    }

    /// Returns the epoch.
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Returns the QC anchor hash.
    #[must_use]
    pub const fn qc_anchor_hash(&self) -> &Hash {
        &self.qc_anchor_hash
    }

    /// Returns the composed Merkle root over all batch roots.
    #[must_use]
    pub const fn composed_root(&self) -> &Hash {
        &self.composed_root
    }

    /// Returns the number of batch roots.
    #[must_use]
    pub fn batch_count(&self) -> usize {
        self.batch_roots.len()
    }

    // ────────── Canonical bytes and content hash ──────────

    /// Compute the canonical byte representation for content-addressing.
    ///
    /// Layout:
    /// ```text
    /// domain_separator
    /// + epoch (8 bytes LE)
    /// + qc_anchor_hash (32 bytes)
    /// + composed_root (32 bytes)
    /// + batch_count (4 bytes LE)
    /// + [batch_root (32 bytes)] * batch_count
    /// ```
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let total = FACT_ROOT_DOMAIN_SEPARATOR.len()
            + 8  // epoch
            + 32 // qc_anchor_hash
            + 32 // composed_root
            + 4  // batch_count
            + self.batch_roots.len() * 32;

        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(FACT_ROOT_DOMAIN_SEPARATOR);
        out.extend_from_slice(&self.epoch.to_le_bytes());
        out.extend_from_slice(&self.qc_anchor_hash);
        out.extend_from_slice(&self.composed_root);
        #[allow(clippy::cast_possible_truncation)]
        let batch_count = self.batch_roots.len() as u32;
        out.extend_from_slice(&batch_count.to_le_bytes());
        for root in &self.batch_roots {
            out.extend_from_slice(root);
        }
        out
    }

    /// Compute the content-address hash of this fact root.
    ///
    /// This hash is used as the binding to the QC's `block_hash`.
    #[must_use]
    pub fn content_hash(&self) -> Hash {
        EventHasher::hash_content(&self.canonical_bytes())
    }
}

// ============================================================================
// FactRootVerifier
// ============================================================================

/// Verifier for `FactRootV1` against QC-certified checkpoints.
///
/// Validates that:
/// 1. Genesis QCs are rejected unless explicitly trusted.
/// 2. The QC is valid (quorum met, signatures verified).
/// 3. The `FactRootV1` epoch matches the QC epoch.
/// 4. The `FactRootV1` content hash matches the QC block hash (binding).
/// 5. The `qc_anchor_hash` matches the canonical hash of the provided QC.
/// 6. Free-floating batch roots (no QC anchor) are rejected.
pub struct FactRootVerifier;

/// Result of `FactRootV1` verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FactRootVerificationResult {
    /// The content hash of the verified fact root.
    pub content_hash: Hash,
    /// The composed Merkle root over the batch roots.
    pub composed_root: Hash,
    /// The epoch of the verified checkpoint.
    pub epoch: u64,
    /// The number of batch roots in the fact root.
    pub batch_count: usize,
}

impl FactRootVerifier {
    /// Verify a `FactRootV1` against a quorum certificate.
    ///
    /// Genesis QCs (round=0, no signatures) are **rejected** in this path.
    /// Use [`Self::verify_trusted_genesis`] for explicitly trusted genesis
    /// contexts.
    ///
    /// # Arguments
    ///
    /// - `fact_root`: the fact root to verify.
    /// - `qc`: the quorum certificate to verify against.
    /// - `context`: the QC verification context (validator set + threshold).
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The QC is a genesis QC (use `verify_trusted_genesis` instead)
    /// - The QC fails verification (insufficient quorum, invalid signatures)
    /// - The fact root epoch does not match the QC epoch
    /// - The fact root content hash does not match the QC block hash
    /// - The `qc_anchor_hash` does not match the canonical hash of the QC
    pub fn verify(
        fact_root: &FactRootV1,
        qc: &super::bft::QuorumCertificate,
        context: &QcVerificationContext,
    ) -> Result<FactRootVerificationResult, FactRootError> {
        // 1. Reject genesis QCs in non-genesis context.
        if qc.is_genesis() {
            return Err(FactRootError::GenesisQcNotAllowed);
        }

        Self::verify_inner(fact_root, qc, context)
    }

    /// Verify a `FactRootV1` against an explicitly trusted genesis QC.
    ///
    /// This method accepts genesis QCs (round=0, no signatures) and should
    /// only be used in trusted genesis bootstrap contexts where the genesis
    /// state is known to be authentic.
    ///
    /// # Arguments
    ///
    /// - `fact_root`: the fact root to verify.
    /// - `qc`: the genesis quorum certificate.
    /// - `context`: the QC verification context (validator set + threshold).
    ///
    /// # Errors
    ///
    /// Returns an error if verification fails for any other reason.
    pub fn verify_trusted_genesis(
        fact_root: &FactRootV1,
        qc: &super::bft::QuorumCertificate,
        context: &QcVerificationContext,
    ) -> Result<FactRootVerificationResult, FactRootError> {
        Self::verify_inner(fact_root, qc, context)
    }

    /// Shared verification logic for both genesis and non-genesis paths.
    fn verify_inner(
        fact_root: &FactRootV1,
        qc: &super::bft::QuorumCertificate,
        context: &QcVerificationContext,
    ) -> Result<FactRootVerificationResult, FactRootError> {
        // 1. Verify the QC itself.
        verify_qc(qc, context).map_err(|e| FactRootError::QcVerificationFailed(e.to_string()))?;

        // 2. QC anchor hash binding: the fact root's qc_anchor_hash must match the
        //    canonical hash of the provided QC.
        let qc_canonical_hash = compute_qc_anchor_hash(qc);
        if fact_root.qc_anchor_hash != qc_canonical_hash {
            return Err(FactRootError::QcAnchorHashMismatch);
        }

        // 3. Epoch binding: fact root epoch must match QC epoch.
        if fact_root.epoch != qc.epoch {
            return Err(FactRootError::EpochMismatch {
                fact_root_epoch: fact_root.epoch,
                qc_epoch: qc.epoch,
            });
        }

        // 4. Content binding: fact root content hash must match QC block hash.
        let content_hash = fact_root.content_hash();
        if content_hash != qc.block_hash {
            return Err(FactRootError::ContentHashMismatch);
        }

        Ok(FactRootVerificationResult {
            content_hash,
            composed_root: fact_root.composed_root,
            epoch: fact_root.epoch,
            batch_count: fact_root.batch_roots.len(),
        })
    }

    /// Verify that a specific batch root is a member of a verified fact root.
    ///
    /// This is used after `verify()` to check that a particular batch root
    /// is included in the checkpoint.
    ///
    /// # Arguments
    ///
    /// - `fact_root`: the fact root (already verified via `verify()`).
    /// - `batch_root`: the batch root hash to look up.
    ///
    /// # Returns
    ///
    /// `true` if the batch root is present in the fact root's batch roots.
    #[must_use]
    pub fn contains_batch_root(fact_root: &FactRootV1, batch_root: &Hash) -> bool {
        fact_root.batch_roots.iter().any(|r| r == batch_root)
    }
}

// ============================================================================
// CompactMultiProof
// ============================================================================

/// Compact shared-sibling multiproof wire shape (RFC-0020 §9.5.5).
///
/// Instead of K independent Merkle inclusion proofs (each containing
/// overlapping sibling hashes), a `CompactMultiProof` deduplicates shared
/// siblings into a single `proof_nodes` array and encodes the tree
/// traversal structure in a bit-encoded `proof_structure`.
///
/// # Wire Shape
///
/// - `root_hash`: the Merkle root being proven against.
/// - `leaf_hashes`: K leaf hashes in canonical sorted order.
/// - `proof_nodes`: deduplicated sibling hashes, referenced by index.
/// - `proof_structure`: bit-encoded traversal instructions per leaf.
///
/// # Encoding of `proof_structure`
///
/// For each leaf, the structure encodes a sequence of (direction, `node_index`)
/// pairs from leaf to root. Each byte encodes one level:
/// - Bit 7 (high): 0 = sibling is on the right, 1 = sibling is on the left
/// - Bits 0-6: 1-based index into `proof_nodes` (value 1 = `proof_nodes[0]`,
///   value 2 = `proof_nodes[1]`, etc.)
///
/// A zero-byte (0x00) terminates the path for each leaf. Since node indices
/// are 1-based, 0x00 is unambiguously a terminator.
///
/// This encoding supports up to 126 unique proof nodes per proof, which is
/// sufficient for trees of depth up to 21 (`MAX_TREE_DEPTH`) with many
/// shared siblings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompactMultiProof {
    /// The Merkle root hash being proven against.
    root_hash: Hash,
    /// Leaf hashes whose membership is being proven (canonical sorted order).
    leaf_hashes: Vec<Hash>,
    /// Deduplicated sibling hashes. Referenced by index from
    /// `proof_structure`.
    proof_nodes: Vec<Hash>,
    /// Bit-encoded sibling sharing structure.
    proof_structure: Vec<u8>,
}

/// Terminator byte in proof structure (signals end of a leaf's path).
const PROOF_PATH_TERMINATOR: u8 = 0x00;

/// Bit mask for the "sibling is on the left" flag in proof structure bytes.
const SIBLING_LEFT_BIT: u8 = 0x80;

/// Mask for the node index in proof structure bytes (bits 0-6).
const NODE_INDEX_MASK: u8 = 0x7F;

impl CompactMultiProof {
    /// Construct a validated `CompactMultiProof`.
    ///
    /// # Arguments
    ///
    /// - `root_hash`: the Merkle root hash.
    /// - `leaf_hashes`: leaf hashes in canonical sorted order.
    /// - `proof_nodes`: deduplicated sibling hashes.
    /// - `proof_structure`: bit-encoded traversal structure.
    ///
    /// # Errors
    ///
    /// Returns an error if bounds are exceeded or leaves are unsorted/empty.
    pub fn new(
        root_hash: Hash,
        leaf_hashes: Vec<Hash>,
        proof_nodes: Vec<Hash>,
        proof_structure: Vec<u8>,
    ) -> Result<Self, FactRootError> {
        // Validate non-empty leaves.
        if leaf_hashes.is_empty() {
            return Err(FactRootError::EmptyLeaves);
        }

        // Validate bounded leaf count.
        if leaf_hashes.len() > MAX_COMPACT_MULTIPROOF_LEAVES {
            return Err(FactRootError::TooManyLeaves {
                count: leaf_hashes.len(),
                max: MAX_COMPACT_MULTIPROOF_LEAVES,
            });
        }

        // Validate canonical sorted order and no duplicates.
        for window in leaf_hashes.windows(2) {
            match window[0].cmp(&window[1]) {
                std::cmp::Ordering::Greater => return Err(FactRootError::UnsortedLeaves),
                std::cmp::Ordering::Equal => return Err(FactRootError::DuplicateLeaves),
                std::cmp::Ordering::Less => {},
            }
        }

        // Validate bounded proof nodes.
        if proof_nodes.len() > MAX_COMPACT_PROOF_NODES {
            return Err(FactRootError::TooManyProofNodes {
                count: proof_nodes.len(),
                max: MAX_COMPACT_PROOF_NODES,
            });
        }

        // Validate bounded proof structure.
        if proof_structure.len() > MAX_COMPACT_PROOF_STRUCTURE {
            return Err(FactRootError::ProofStructureTooLarge {
                size: proof_structure.len(),
                max: MAX_COMPACT_PROOF_STRUCTURE,
            });
        }

        Ok(Self {
            root_hash,
            leaf_hashes,
            proof_nodes,
            proof_structure,
        })
    }

    // ────────── Accessors ──────────

    /// Returns the root hash.
    #[must_use]
    pub const fn root_hash(&self) -> &Hash {
        &self.root_hash
    }

    /// Returns the leaf hashes.
    #[must_use]
    pub fn leaf_hashes(&self) -> &[Hash] {
        &self.leaf_hashes
    }

    /// Returns the deduplicated proof nodes.
    #[must_use]
    pub fn proof_nodes(&self) -> &[Hash] {
        &self.proof_nodes
    }

    /// Returns the proof structure.
    #[must_use]
    pub fn proof_structure(&self) -> &[u8] {
        &self.proof_structure
    }

    /// Returns the number of leaves in this multiproof.
    #[must_use]
    pub fn leaf_count(&self) -> usize {
        self.leaf_hashes.len()
    }

    // ────────── Verification ──────────

    /// Verify that all leaf hashes are members of the Merkle root.
    ///
    /// Decodes the `proof_structure` and reconstructs each leaf's path to
    /// the root using the deduplicated `proof_nodes`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The proof structure is malformed
    /// - Any node index in the structure is out of bounds
    /// - Any reconstructed root does not match `root_hash`
    /// - Proof depth exceeds `MAX_TREE_DEPTH`
    pub fn verify(&self) -> Result<(), FactRootError> {
        let mut structure_offset = 0;

        for leaf_hash in &self.leaf_hashes {
            let mut current = *leaf_hash;
            let mut depth = 0;

            loop {
                if structure_offset >= self.proof_structure.len() {
                    return Err(FactRootError::InvalidProofStructure {
                        reason: "proof structure truncated before path terminator".into(),
                    });
                }

                let byte = self.proof_structure[structure_offset];
                structure_offset += 1;

                if byte == PROOF_PATH_TERMINATOR {
                    break;
                }

                depth += 1;
                if depth > MAX_TREE_DEPTH {
                    return Err(FactRootError::ProofDepthExceeded {
                        depth,
                        max: MAX_TREE_DEPTH,
                    });
                }

                let sibling_is_left = (byte & SIBLING_LEFT_BIT) != 0;
                // Node indices are 1-based in the encoding (0 is the
                // terminator). Subtract 1 to get the 0-based proof_nodes
                // index.
                let raw_index = (byte & NODE_INDEX_MASK) as usize;
                if raw_index == 0 {
                    // Should not happen (0x00 is caught as terminator above,
                    // but 0x80 would be sibling_is_left with index 0 which
                    // is invalid in 1-based encoding).
                    return Err(FactRootError::InvalidProofStructure {
                        reason: "zero node index in non-terminator byte".into(),
                    });
                }
                let node_index = raw_index - 1;

                if node_index >= self.proof_nodes.len() {
                    return Err(FactRootError::InvalidProofStructure {
                        reason: format!(
                            "node index {} out of bounds (have {} nodes)",
                            node_index,
                            self.proof_nodes.len()
                        ),
                    });
                }

                let sibling = &self.proof_nodes[node_index];

                current = if sibling_is_left {
                    hash_internal(sibling, &current)
                } else {
                    hash_internal(&current, sibling)
                };
            }

            if current != self.root_hash {
                return Err(FactRootError::CompactProofRootMismatch);
            }
        }

        // All structure bytes should be consumed.
        if structure_offset != self.proof_structure.len() {
            return Err(FactRootError::InvalidProofStructure {
                reason: format!(
                    "trailing bytes in proof structure: {} remaining",
                    self.proof_structure.len() - structure_offset
                ),
            });
        }

        Ok(())
    }

    // ────────── Canonical bytes ──────────

    /// Compute the canonical byte representation.
    ///
    /// Layout:
    /// ```text
    /// domain_separator
    /// + root_hash (32 bytes)
    /// + leaf_count (4 bytes LE)
    /// + [leaf_hash (32 bytes)] * leaf_count
    /// + node_count (4 bytes LE)
    /// + [node_hash (32 bytes)] * node_count
    /// + structure_len (4 bytes LE)
    /// + proof_structure (structure_len bytes)
    /// ```
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let total = COMPACT_MULTIPROOF_DOMAIN_SEPARATOR.len()
            + 32 // root_hash
            + 4  // leaf_count
            + self.leaf_hashes.len() * 32
            + 4  // node_count
            + self.proof_nodes.len() * 32
            + 4  // structure_len
            + self.proof_structure.len();

        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(COMPACT_MULTIPROOF_DOMAIN_SEPARATOR);
        out.extend_from_slice(&self.root_hash);

        #[allow(clippy::cast_possible_truncation)]
        let leaf_count = self.leaf_hashes.len() as u32;
        out.extend_from_slice(&leaf_count.to_le_bytes());
        for hash in &self.leaf_hashes {
            out.extend_from_slice(hash);
        }

        #[allow(clippy::cast_possible_truncation)]
        let node_count = self.proof_nodes.len() as u32;
        out.extend_from_slice(&node_count.to_le_bytes());
        for node in &self.proof_nodes {
            out.extend_from_slice(node);
        }

        #[allow(clippy::cast_possible_truncation)]
        let structure_len = self.proof_structure.len() as u32;
        out.extend_from_slice(&structure_len.to_le_bytes());
        out.extend_from_slice(&self.proof_structure);

        out
    }

    /// Compute the content-address hash of this multiproof.
    #[must_use]
    pub fn content_hash(&self) -> Hash {
        EventHasher::hash_content(&self.canonical_bytes())
    }

    /// Check whether a specific leaf hash is in this multiproof.
    #[must_use]
    pub fn contains_leaf(&self, leaf_hash: &Hash) -> bool {
        self.leaf_hashes.binary_search(leaf_hash).is_ok()
    }
}

// ============================================================================
// Builder: construct CompactMultiProof from individual Merkle proofs
// ============================================================================

/// Individual Merkle inclusion proof path entry.
#[derive(Debug, Clone)]
pub struct ProofPathEntry {
    /// Sibling hash at this level.
    pub sibling_hash: Hash,
    /// Whether the sibling is on the left.
    pub sibling_is_left: bool,
}

/// Build a `CompactMultiProof` from individual per-leaf Merkle proofs.
///
/// This deduplicates shared sibling nodes across multiple proof paths and
/// produces the compact `proof_nodes[]` + `proof_structure` encoding.
///
/// # Arguments
///
/// - `root_hash`: the Merkle root hash.
/// - `leaves_and_proofs`: pairs of (`leaf_hash`, `proof_path`) where each proof
///   path is a sequence of sibling hashes from leaf to root. Leaves must be in
///   canonical sorted order.
///
/// # Errors
///
/// Returns an error if the input is empty, unsorted, or exceeds bounds.
pub fn build_compact_multiproof(
    root_hash: Hash,
    leaves_and_proofs: &[(Hash, Vec<ProofPathEntry>)],
) -> Result<CompactMultiProof, FactRootError> {
    if leaves_and_proofs.is_empty() {
        return Err(FactRootError::EmptyLeaves);
    }

    if leaves_and_proofs.len() > MAX_COMPACT_MULTIPROOF_LEAVES {
        return Err(FactRootError::TooManyLeaves {
            count: leaves_and_proofs.len(),
            max: MAX_COMPACT_MULTIPROOF_LEAVES,
        });
    }

    let mut leaf_hashes = Vec::with_capacity(leaves_and_proofs.len());
    let mut proof_nodes: Vec<Hash> = Vec::new();
    let mut proof_structure: Vec<u8> = Vec::new();

    // Node deduplication map: hash -> index in proof_nodes.
    let mut node_index_map = std::collections::HashMap::new();

    for (leaf_hash, proof_path) in leaves_and_proofs {
        leaf_hashes.push(*leaf_hash);

        if proof_path.len() > MAX_TREE_DEPTH {
            return Err(FactRootError::ProofDepthExceeded {
                depth: proof_path.len(),
                max: MAX_TREE_DEPTH,
            });
        }

        for entry in proof_path {
            let node_idx = if let Some(&idx) = node_index_map.get(&entry.sibling_hash) {
                idx
            } else {
                let idx = proof_nodes.len();
                // 1-based encoding: index 0 encodes as 1, so max 0-based
                // index is (NODE_INDEX_MASK - 1) = 126.
                if idx >= NODE_INDEX_MASK as usize {
                    return Err(FactRootError::TooManyProofNodes {
                        count: idx + 1,
                        max: NODE_INDEX_MASK as usize,
                    });
                }
                proof_nodes.push(entry.sibling_hash);
                node_index_map.insert(entry.sibling_hash, idx);
                idx
            };

            // Encode as 1-based index (0x00 is reserved as path terminator).
            #[allow(clippy::cast_possible_truncation)]
            let mut byte = (node_idx + 1) as u8;
            if entry.sibling_is_left {
                byte |= SIBLING_LEFT_BIT;
            }
            proof_structure.push(byte);
        }

        // Terminate this leaf's path.
        proof_structure.push(PROOF_PATH_TERMINATOR);
    }

    CompactMultiProof::new(root_hash, leaf_hashes, proof_nodes, proof_structure)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tck_00370_unit_tests {
    use super::*;
    use crate::consensus::merkle::MerkleTree;

    fn test_hash(i: u64) -> Hash {
        EventHasher::hash_content(&i.to_le_bytes())
    }

    // ── FactRootV1 construction tests ──

    #[test]
    fn fact_root_construction_valid() {
        let batch_roots = vec![test_hash(1), test_hash(2), test_hash(3)];
        let qc_anchor = test_hash(100);
        let fact_root = FactRootV1::new(batch_roots.clone(), 1, qc_anchor).unwrap();

        assert_eq!(fact_root.batch_roots(), &batch_roots);
        assert_eq!(fact_root.epoch(), 1);
        assert_eq!(fact_root.qc_anchor_hash(), &qc_anchor);
        assert_eq!(fact_root.batch_count(), 3);
    }

    #[test]
    fn fact_root_rejects_empty_batch_roots() {
        let result = FactRootV1::new(vec![], 1, test_hash(100));
        assert!(matches!(result, Err(FactRootError::EmptyBatchRoots)));
    }

    #[test]
    fn fact_root_rejects_too_many_batch_roots() {
        let batch_roots: Vec<Hash> = (0..=MAX_BATCH_ROOTS as u64)
            .map(|i| test_hash(i + 1))
            .collect();
        let result = FactRootV1::new(batch_roots, 1, test_hash(100));
        assert!(matches!(
            result,
            Err(FactRootError::TooManyBatchRoots { .. })
        ));
    }

    #[test]
    fn fact_root_rejects_zero_qc_anchor() {
        let result = FactRootV1::new(vec![test_hash(1)], 1, [0u8; 32]);
        assert!(matches!(result, Err(FactRootError::MissingQcAnchor)));
    }

    #[test]
    fn fact_root_rejects_zero_batch_root() {
        let result = FactRootV1::new(vec![[0u8; 32]], 1, test_hash(100));
        assert!(matches!(result, Err(FactRootError::ZeroBatchRoot)));
    }

    #[test]
    fn fact_root_rejects_duplicate_batch_roots() {
        let h = test_hash(1);
        let result = FactRootV1::new(vec![h, h], 1, test_hash(100));
        assert!(matches!(
            result,
            Err(FactRootError::DuplicateBatchRoot { index: 1 })
        ));
    }

    #[test]
    fn fact_root_content_hash_deterministic() {
        let batch_roots = vec![test_hash(1), test_hash(2)];
        let fr1 = FactRootV1::new(batch_roots.clone(), 1, test_hash(100)).unwrap();
        let fr2 = FactRootV1::new(batch_roots, 1, test_hash(100)).unwrap();
        assert_eq!(fr1.content_hash(), fr2.content_hash());
    }

    #[test]
    fn fact_root_content_hash_changes_with_epoch() {
        let batch_roots = vec![test_hash(1)];
        let fr1 = FactRootV1::new(batch_roots.clone(), 1, test_hash(100)).unwrap();
        let fr2 = FactRootV1::new(batch_roots, 2, test_hash(100)).unwrap();
        assert_ne!(fr1.content_hash(), fr2.content_hash());
    }

    #[test]
    fn fact_root_content_hash_changes_with_batch_roots() {
        let fr1 = FactRootV1::new(vec![test_hash(1)], 1, test_hash(100)).unwrap();
        let fr2 = FactRootV1::new(vec![test_hash(2)], 1, test_hash(100)).unwrap();
        assert_ne!(fr1.content_hash(), fr2.content_hash());
    }

    #[test]
    fn fact_root_single_batch_root() {
        let fr = FactRootV1::new(vec![test_hash(42)], 5, test_hash(200)).unwrap();
        assert_eq!(fr.batch_count(), 1);
        // Composed root of a single leaf should be the hashed leaf.
        assert_eq!(fr.composed_root(), &hash_leaf(&test_hash(42)));
    }

    // ── FactRootVerifier tests ──

    #[test]
    fn fact_root_verifier_rejects_genesis_qc_in_non_genesis_context() {
        use crate::consensus::bft::QuorumCertificate;

        let qc = QuorumCertificate::genesis(0, [0xab; 32]);
        let qc_anchor = compute_qc_anchor_hash(&qc);
        let batch_roots = vec![test_hash(1)];
        let fact_root = FactRootV1::new(batch_roots, 0, qc_anchor).unwrap();

        let validators = create_test_validators(4);
        let context = QcVerificationContext::new(&validators, 3);

        // verify() must reject genesis QCs
        let result = FactRootVerifier::verify(&fact_root, &qc, &context);
        assert!(
            matches!(result, Err(FactRootError::GenesisQcNotAllowed)),
            "expected GenesisQcNotAllowed, got: {result:?}"
        );
    }

    #[test]
    fn fact_root_verifier_rejects_epoch_mismatch() {
        use crate::consensus::bft::QuorumCertificate;

        // Use genesis path (via verify_trusted_genesis) to isolate the epoch check.
        let qc = QuorumCertificate::genesis(2, [0xab; 32]);
        let qc_anchor = compute_qc_anchor_hash(&qc);
        let batch_roots = vec![test_hash(1)];
        let fact_root = FactRootV1::new(batch_roots, 1, qc_anchor).unwrap();

        let validators = create_test_validators(4);
        let context = QcVerificationContext::new(&validators, 3);

        let result = FactRootVerifier::verify_trusted_genesis(&fact_root, &qc, &context);
        assert!(matches!(result, Err(FactRootError::EpochMismatch { .. })));
    }

    #[test]
    fn fact_root_verifier_rejects_content_hash_mismatch() {
        use crate::consensus::bft::QuorumCertificate;

        let qc = QuorumCertificate::genesis(1, [0xab; 32]);
        let qc_anchor = compute_qc_anchor_hash(&qc);
        let batch_roots = vec![test_hash(1)];
        let fact_root = FactRootV1::new(batch_roots, 1, qc_anchor).unwrap();

        let validators = create_test_validators(4);
        let context = QcVerificationContext::new(&validators, 3);

        let result = FactRootVerifier::verify_trusted_genesis(&fact_root, &qc, &context);
        assert!(matches!(result, Err(FactRootError::ContentHashMismatch)));
    }

    #[test]
    fn fact_root_verifier_rejects_wrong_qc_anchor_hash() {
        use crate::consensus::bft::QuorumCertificate;

        // Build a genesis QC and a fact root whose qc_anchor_hash is
        // arbitrary (non-zero but does NOT match the QC's canonical hash).
        let qc = QuorumCertificate::genesis(0, [0xab; 32]);
        let wrong_anchor = test_hash(999); // not the canonical QC hash
        let batch_roots = vec![test_hash(1)];
        let fact_root = FactRootV1::new(batch_roots, 0, wrong_anchor).unwrap();

        let validators = create_test_validators(4);
        let context = QcVerificationContext::new(&validators, 3);

        let result = FactRootVerifier::verify_trusted_genesis(&fact_root, &qc, &context);
        assert!(
            matches!(result, Err(FactRootError::QcAnchorHashMismatch)),
            "expected QcAnchorHashMismatch, got: {result:?}"
        );
    }

    #[test]
    fn fact_root_verifier_valid_trusted_genesis_qc() {
        use crate::consensus::bft::QuorumCertificate;

        // The anchor hash excludes block_hash, so all genesis QCs for the
        // same epoch share the same anchor hash regardless of block_hash.
        let qc_anchor = compute_qc_anchor_hash(&QuorumCertificate::genesis(0, [0u8; 32]));
        let batch_roots = vec![test_hash(1), test_hash(2)];
        let fact_root = FactRootV1::new(batch_roots, 0, qc_anchor).unwrap();
        let content_hash = fact_root.content_hash();

        // Build the real QC whose block_hash = fact root content hash.
        let qc = QuorumCertificate::genesis(0, content_hash);

        let validators = create_test_validators(4);
        let context = QcVerificationContext::new(&validators, 3);

        let result = FactRootVerifier::verify_trusted_genesis(&fact_root, &qc, &context).unwrap();
        assert_eq!(result.content_hash, content_hash);
        assert_eq!(result.epoch, 0);
        assert_eq!(result.batch_count, 2);
    }

    #[test]
    fn fact_root_verifier_contains_batch_root() {
        let h1 = test_hash(1);
        let h2 = test_hash(2);
        let h3 = test_hash(3);
        let fact_root = FactRootV1::new(vec![h1, h2], 0, test_hash(100)).unwrap();

        assert!(FactRootVerifier::contains_batch_root(&fact_root, &h1));
        assert!(FactRootVerifier::contains_batch_root(&fact_root, &h2));
        assert!(!FactRootVerifier::contains_batch_root(&fact_root, &h3));
    }

    // ── CompactMultiProof tests ──

    #[test]
    fn compact_multiproof_rejects_empty_leaves() {
        let result = CompactMultiProof::new([0xab; 32], vec![], vec![], vec![]);
        assert!(matches!(result, Err(FactRootError::EmptyLeaves)));
    }

    #[test]
    fn compact_multiproof_rejects_unsorted_leaves() {
        let h1 = test_hash(1);
        let h2 = test_hash(2);
        // Ensure h1 > h2 or h2 > h1 and put them in wrong order
        let (first, second) = if h1 < h2 { (h2, h1) } else { (h1, h2) };
        let result = CompactMultiProof::new([0xab; 32], vec![first, second], vec![], vec![]);
        assert!(matches!(result, Err(FactRootError::UnsortedLeaves)));
    }

    #[test]
    fn compact_multiproof_rejects_duplicate_leaves() {
        let h = test_hash(1);
        let result = CompactMultiProof::new([0xab; 32], vec![h, h], vec![], vec![]);
        assert!(matches!(result, Err(FactRootError::DuplicateLeaves)));
    }

    #[test]
    fn compact_multiproof_round_trip_single_leaf() {
        // Build a Merkle tree with 4 leaves, then build a compact multiproof
        // for leaf 0 and verify it.
        let leaves: Vec<Hash> = (0..4).map(test_hash).collect();
        let tree = MerkleTree::new(leaves.iter().copied()).unwrap();
        let root = tree.root();

        // Get proof for leaf 0
        let proof = tree.proof_for(0).unwrap();

        // Convert to ProofPathEntry format
        let path_entries: Vec<ProofPathEntry> = proof
            .path
            .iter()
            .map(|(sibling_hash, is_right)| ProofPathEntry {
                sibling_hash: *sibling_hash,
                sibling_is_left: *is_right,
            })
            .collect();

        let compact = build_compact_multiproof(root, &[(proof.leaf_hash, path_entries)]).unwrap();

        assert_eq!(compact.leaf_count(), 1);
        assert_eq!(compact.root_hash(), &root);
        compact.verify().unwrap();
    }

    #[test]
    fn compact_multiproof_round_trip_multiple_leaves() {
        let leaves: Vec<Hash> = (0..8).map(test_hash).collect();
        let tree = MerkleTree::new(leaves.iter().copied()).unwrap();
        let root = tree.root();

        // Build proofs for leaves 1 and 5
        let mut leaves_and_proofs = Vec::new();
        for leaf_idx in [1, 5] {
            let proof = tree.proof_for(leaf_idx).unwrap();
            let path_entries: Vec<ProofPathEntry> = proof
                .path
                .iter()
                .map(|(sibling_hash, is_right)| ProofPathEntry {
                    sibling_hash: *sibling_hash,
                    sibling_is_left: *is_right,
                })
                .collect();
            leaves_and_proofs.push((proof.leaf_hash, path_entries));
        }

        // Sort by leaf hash for canonical order
        leaves_and_proofs.sort_by(|a, b| a.0.cmp(&b.0));

        let compact = build_compact_multiproof(root, &leaves_and_proofs).unwrap();

        assert_eq!(compact.leaf_count(), 2);
        compact.verify().unwrap();
    }

    #[test]
    fn compact_multiproof_shared_siblings_reduce_node_count() {
        // When two leaves share siblings (e.g., are in the same subtree),
        // the compact proof should have fewer nodes than two independent proofs.
        let leaves: Vec<Hash> = (0..8).map(test_hash).collect();
        let tree = MerkleTree::new(leaves.iter().copied()).unwrap();
        let root = tree.root();

        // Leaves 0 and 1 are siblings - they share the upper proof path
        let mut leaves_and_proofs = Vec::new();
        let mut total_individual_nodes = 0;
        for leaf_idx in [0, 1] {
            let proof = tree.proof_for(leaf_idx).unwrap();
            total_individual_nodes += proof.path.len();
            let path_entries: Vec<ProofPathEntry> = proof
                .path
                .iter()
                .map(|(sibling_hash, is_right)| ProofPathEntry {
                    sibling_hash: *sibling_hash,
                    sibling_is_left: *is_right,
                })
                .collect();
            leaves_and_proofs.push((proof.leaf_hash, path_entries));
        }

        leaves_and_proofs.sort_by(|a, b| a.0.cmp(&b.0));

        let compact = build_compact_multiproof(root, &leaves_and_proofs).unwrap();

        // With deduplication, shared siblings should be stored only once.
        // Leaves 0 and 1 share all upper siblings, so we save nodes.
        assert!(
            compact.proof_nodes().len() < total_individual_nodes,
            "compact should have fewer nodes ({}) than independent ({})",
            compact.proof_nodes().len(),
            total_individual_nodes
        );

        compact.verify().unwrap();
    }

    #[test]
    fn compact_multiproof_content_hash_deterministic() {
        let leaves: Vec<Hash> = (0..4).map(test_hash).collect();
        let tree = MerkleTree::new(leaves.iter().copied()).unwrap();
        let root = tree.root();

        let proof = tree.proof_for(0).unwrap();
        let path_entries: Vec<ProofPathEntry> = proof
            .path
            .iter()
            .map(|(sibling_hash, is_right)| ProofPathEntry {
                sibling_hash: *sibling_hash,
                sibling_is_left: *is_right,
            })
            .collect();

        let compact1 =
            build_compact_multiproof(root, &[(proof.leaf_hash, path_entries.clone())]).unwrap();
        let compact2 = build_compact_multiproof(root, &[(proof.leaf_hash, path_entries)]).unwrap();

        assert_eq!(compact1.content_hash(), compact2.content_hash());
    }

    #[test]
    fn compact_multiproof_verify_rejects_wrong_root() {
        let leaves: Vec<Hash> = (0..4).map(test_hash).collect();
        let tree = MerkleTree::new(leaves.iter().copied()).unwrap();

        let proof = tree.proof_for(0).unwrap();
        let path_entries: Vec<ProofPathEntry> = proof
            .path
            .iter()
            .map(|(sibling_hash, is_right)| ProofPathEntry {
                sibling_hash: *sibling_hash,
                sibling_is_left: *is_right,
            })
            .collect();

        // Build with wrong root
        let wrong_root = [0xff; 32];
        let compact =
            build_compact_multiproof(wrong_root, &[(proof.leaf_hash, path_entries)]).unwrap();

        let result = compact.verify();
        assert!(matches!(
            result,
            Err(FactRootError::CompactProofRootMismatch)
        ));
    }

    #[test]
    fn compact_multiproof_contains_leaf() {
        let leaves: Vec<Hash> = (0..4).map(test_hash).collect();
        let tree = MerkleTree::new(leaves.iter().copied()).unwrap();
        let root = tree.root();

        let proof = tree.proof_for(0).unwrap();
        let path_entries: Vec<ProofPathEntry> = proof
            .path
            .iter()
            .map(|(sibling_hash, is_right)| ProofPathEntry {
                sibling_hash: *sibling_hash,
                sibling_is_left: *is_right,
            })
            .collect();

        let compact = build_compact_multiproof(root, &[(proof.leaf_hash, path_entries)]).unwrap();

        assert!(compact.contains_leaf(&proof.leaf_hash));
        assert!(!compact.contains_leaf(&[0xff; 32]));
    }

    // ── Property-like round-trip tests ──

    #[test]
    fn fact_root_round_trip_canonical_bytes() {
        for batch_count in [1u64, 2, 5, 10] {
            let batch_roots: Vec<Hash> = (1..=batch_count).map(test_hash).collect();
            let fr = FactRootV1::new(batch_roots, 42, test_hash(999)).unwrap();
            let bytes = fr.canonical_bytes();
            let hash = fr.content_hash();

            // Same inputs should produce same bytes and hash.
            let fr2 = FactRootV1::new(fr.batch_roots().to_vec(), fr.epoch(), *fr.qc_anchor_hash())
                .unwrap();
            assert_eq!(fr2.canonical_bytes(), bytes);
            assert_eq!(fr2.content_hash(), hash);
        }
    }

    #[test]
    fn compact_multiproof_round_trip_all_leaves() {
        // Build a compact multiproof for ALL leaves and verify.
        for tree_size in [2usize, 3, 4, 7, 8, 15, 16] {
            let leaves: Vec<Hash> = (0..tree_size).map(|i| test_hash(i as u64)).collect();
            let tree = MerkleTree::new(leaves.iter().copied()).unwrap();
            let root = tree.root();

            let mut leaves_and_proofs = Vec::new();
            for idx in 0..tree_size {
                let proof = tree.proof_for(idx).unwrap();
                let path_entries: Vec<ProofPathEntry> = proof
                    .path
                    .iter()
                    .map(|(sibling_hash, is_right)| ProofPathEntry {
                        sibling_hash: *sibling_hash,
                        sibling_is_left: *is_right,
                    })
                    .collect();
                leaves_and_proofs.push((proof.leaf_hash, path_entries));
            }

            leaves_and_proofs.sort_by(|a, b| a.0.cmp(&b.0));

            let compact = build_compact_multiproof(root, &leaves_and_proofs).unwrap();
            compact.verify().unwrap_or_else(|e| {
                panic!("compact multiproof verification failed for tree_size={tree_size}: {e}");
            });
        }
    }

    #[test]
    fn compact_multiproof_round_trip_subset_of_leaves() {
        let leaves: Vec<Hash> = (0u64..16).map(test_hash).collect();
        let tree = MerkleTree::new(leaves.iter().copied()).unwrap();
        let root = tree.root();

        // Prove a subset of leaves (indices 2, 7, 11)
        let mut leaves_and_proofs = Vec::new();
        for &idx in &[2, 7, 11] {
            let proof = tree.proof_for(idx).unwrap();
            let path_entries: Vec<ProofPathEntry> = proof
                .path
                .iter()
                .map(|(sibling_hash, is_right)| ProofPathEntry {
                    sibling_hash: *sibling_hash,
                    sibling_is_left: *is_right,
                })
                .collect();
            leaves_and_proofs.push((proof.leaf_hash, path_entries));
        }

        leaves_and_proofs.sort_by(|a, b| a.0.cmp(&b.0));

        let compact = build_compact_multiproof(root, &leaves_and_proofs).unwrap();
        assert_eq!(compact.leaf_count(), 3);
        compact.verify().unwrap();
    }

    // ── QC anchor hash canonicalization regression tests ──

    /// Regression test: permuting QC signatures must produce the same anchor
    /// hash.
    ///
    /// This validates the fix for the Byzantine relay signature-permutation
    /// `DoS` attack. Before the fix, `compute_qc_anchor_hash` hashed
    /// signatures in received order, so a relay could reorder valid
    /// signatures to produce a different anchor hash, causing
    /// `QcAnchorHashMismatch` denial.
    #[test]
    fn qc_anchor_hash_is_permutation_invariant() {
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;

        use crate::consensus::bft::{QuorumCertificate, ValidatorSignature};

        // Create 4 validator signing keys and corresponding signatures.
        let keys: Vec<SigningKey> = (0..4).map(|_| SigningKey::generate(&mut OsRng)).collect();
        let validators: Vec<crate::consensus::bft::ValidatorInfo> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| {
                let pk = k.verifying_key();
                let id: [u8; 32] = *blake3::hash(pk.as_bytes()).as_bytes();
                crate::consensus::bft::ValidatorInfo {
                    id,
                    index: i,
                    public_key: pk.to_bytes(),
                }
            })
            .collect();

        // Build signed votes from 3 validators (quorum = 3 for n=4).
        let epoch = 1u64;
        let round = 10u64;
        let block_hash = test_hash(42);

        let vote_message =
            super::super::qc_aggregator::build_vote_message(epoch, round, &block_hash);
        let sigs: Vec<ValidatorSignature> = keys
            .iter()
            .take(3)
            .map(|k| {
                use ed25519_dalek::Signer;
                let pk = k.verifying_key();
                let id: [u8; 32] = *blake3::hash(pk.as_bytes()).as_bytes();
                let sig_bytes = k.sign(&vote_message);
                ValidatorSignature::new(id, sig_bytes.to_bytes())
            })
            .collect();

        // QC with signatures in original order.
        let qc_original = QuorumCertificate {
            epoch,
            round,
            block_hash,
            signatures: sigs.clone(),
        };

        // QC with signatures in reversed order (simulates Byzantine relay reordering).
        let mut reversed_sigs = sigs.clone();
        reversed_sigs.reverse();
        let qc_reversed = QuorumCertificate {
            epoch,
            round,
            block_hash,
            signatures: reversed_sigs,
        };

        // QC with signatures in a different permutation (rotate left by 1).
        let mut rotated_sigs = sigs;
        rotated_sigs.rotate_left(1);
        let qc_rotated = QuorumCertificate {
            epoch,
            round,
            block_hash,
            signatures: rotated_sigs,
        };

        // All three permutations MUST produce the same anchor hash.
        let hash_original = compute_qc_anchor_hash(&qc_original);
        let hash_reversed = compute_qc_anchor_hash(&qc_reversed);
        let hash_rotated = compute_qc_anchor_hash(&qc_rotated);

        assert_eq!(
            hash_original, hash_reversed,
            "reversed signature order must produce same anchor hash"
        );
        assert_eq!(
            hash_original, hash_rotated,
            "rotated signature order must produce same anchor hash"
        );

        // Verify all three QCs pass QC verification against the validator set.
        let context = QcVerificationContext::new(&validators, 3);
        for (label, qc) in [
            ("original", &qc_original),
            ("reversed", &qc_reversed),
            ("rotated", &qc_rotated),
        ] {
            assert!(
                super::super::qc_aggregator::verify_qc(qc, &context).is_ok(),
                "QC verification must pass for {label} permutation"
            );
        }
    }

    /// Regression test: `FactRoot` verification via `verify_trusted_genesis`
    /// succeeds regardless of how the anchor hash was computed, confirming
    /// that canonicalization produces a stable binding. Combined with the
    /// `qc_anchor_hash_is_permutation_invariant` test above (which proves
    /// non-genesis QC anchor hashes are permutation-invariant with real
    /// Ed25519 signatures), this covers the full attack surface.
    #[test]
    fn fact_root_anchor_hash_binding_stable_across_construction_paths() {
        use crate::consensus::bft::QuorumCertificate;

        // Genesis QCs have no signatures, so the anchor hash depends only on
        // epoch and round. Two genesis QCs for the same epoch share the same
        // anchor hash regardless of block_hash (which is excluded).
        let qc_a = QuorumCertificate::genesis(5, [0xAA; 32]);
        let qc_b = QuorumCertificate::genesis(5, [0xBB; 32]);

        let anchor_a = compute_qc_anchor_hash(&qc_a);
        let anchor_b = compute_qc_anchor_hash(&qc_b);
        assert_eq!(
            anchor_a, anchor_b,
            "genesis QCs for same epoch must have same anchor hash"
        );

        // Build FactRoot and verify end-to-end.
        let batch_roots = vec![test_hash(1), test_hash(2)];
        let fact_root = FactRootV1::new(batch_roots, 5, anchor_a).unwrap();
        let content_hash = fact_root.content_hash();

        let qc = QuorumCertificate::genesis(5, content_hash);
        let validators = create_test_validators(4);
        let context = QcVerificationContext::new(&validators, 3);

        let result = FactRootVerifier::verify_trusted_genesis(&fact_root, &qc, &context);
        assert!(
            result.is_ok(),
            "FactRoot verification must succeed, got: {result:?}"
        );
        assert_eq!(result.unwrap().content_hash, content_hash);
    }

    // ── Helper for creating test validators ──

    fn create_test_validators(count: usize) -> Vec<crate::consensus::bft::ValidatorInfo> {
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;

        (0..count)
            .map(|i| {
                let key = SigningKey::generate(&mut OsRng);
                let public_key = key.verifying_key();
                let id: [u8; 32] = *blake3::hash(public_key.as_bytes()).as_bytes();
                crate::consensus::bft::ValidatorInfo {
                    id,
                    index: i,
                    public_key: public_key.to_bytes(),
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tck_00370_property_tests {
    use proptest::prelude::*;

    use super::*;
    use crate::consensus::merkle::MerkleTree;

    proptest! {
        /// Property: FactRootV1 construction and content hash are deterministic.
        #[test]
        fn prop_fact_root_deterministic(
            batch_count in 1usize..=16,
            epoch in 0u64..1000,
            seed in 1u64..10000,
        ) {
            let batch_roots: Vec<Hash> = (seed..seed + batch_count as u64)
                .map(|i| EventHasher::hash_content(&i.to_le_bytes()))
                .collect();
            let qc_anchor = EventHasher::hash_content(&(seed + 99999).to_le_bytes());

            let fr1 = FactRootV1::new(batch_roots.clone(), epoch, qc_anchor).unwrap();
            let fr2 = FactRootV1::new(batch_roots, epoch, qc_anchor).unwrap();

            prop_assert_eq!(fr1.content_hash(), fr2.content_hash());
            prop_assert_eq!(fr1.canonical_bytes(), fr2.canonical_bytes());
        }

        /// Property: FactRootV1 rejects zero QC anchor (no free-floating roots).
        #[test]
        fn prop_fact_root_rejects_zero_anchor(
            batch_count in 1usize..=8,
            seed in 1u64..10000,
        ) {
            let batch_roots: Vec<Hash> = (seed..seed + batch_count as u64)
                .map(|i| EventHasher::hash_content(&i.to_le_bytes()))
                .collect();
            let result = FactRootV1::new(batch_roots, 0, [0u8; 32]);
            prop_assert!(matches!(result, Err(FactRootError::MissingQcAnchor)));
        }

        /// Property: compact multiproof round-trip verification succeeds for
        /// any valid tree size and leaf subset.
        #[test]
        fn prop_compact_multiproof_round_trip(
            tree_size in 2usize..=32,
            leaf_selector in prop::collection::vec(prop::bool::ANY, 1..=32),
        ) {
            let leaves: Vec<Hash> = (0..tree_size)
                .map(|i| EventHasher::hash_content(&(i as u64).to_le_bytes()))
                .collect();
            let tree = MerkleTree::new(leaves.iter().copied()).unwrap();
            let root = tree.root();

            // Select at least 1 leaf
            let selected_indices: Vec<usize> = leaf_selector
                .iter()
                .enumerate()
                .filter_map(|(i, &selected)| {
                    if selected && i < tree_size {
                        Some(i)
                    } else {
                        None
                    }
                })
                .collect();

            if selected_indices.is_empty() {
                // Skip if no leaves selected
                return Ok(());
            }

            let mut leaves_and_proofs = Vec::new();
            for &idx in &selected_indices {
                let proof = tree.proof_for(idx).unwrap();
                let path_entries: Vec<ProofPathEntry> = proof
                    .path
                    .iter()
                    .map(|(sibling_hash, is_right)| ProofPathEntry {
                        sibling_hash: *sibling_hash,
                        sibling_is_left: *is_right,
                    })
                    .collect();
                leaves_and_proofs.push((proof.leaf_hash, path_entries));
            }

            // Sort by leaf hash for canonical order, dedup
            leaves_and_proofs.sort_by(|a, b| a.0.cmp(&b.0));
            leaves_and_proofs.dedup_by(|a, b| a.0 == b.0);

            let compact = build_compact_multiproof(root, &leaves_and_proofs).unwrap();
            prop_assert!(compact.verify().is_ok());
            prop_assert_eq!(compact.leaf_count(), leaves_and_proofs.len());
        }
    }
}
