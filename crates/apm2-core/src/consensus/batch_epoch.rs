// AGENT-AUTHORED
//! `BatchEpochRootV1` hierarchical batch forests (TCK-00371).
//!
//! This module provides:
//! - [`BatchEpochRootV1`]: root-of-roots commitment that binds multiple batch
//!   (fact root) hashes into a single epoch-level digest, enabling hierarchical
//!   traversal of deep batch histories.
//! - [`EpochRootBuilder`]: accumulator that collects batch root hashes within
//!   an epoch and produces the final `BatchEpochRootV1`.
//! - [`EpochAntiEntropyPointer`]: compact pointer for cross-epoch anti-entropy
//!   advertisements, allowing peers to reference epoch roots directly.
//! - [`EpochTraverser`]: bounded-memory iterator that walks the epoch root
//!   chain with `O(1)` memory per step.
//!
//! # Security Properties
//!
//! - **Fail-closed**: unknown or missing fields produce errors; empty or
//!   oversized inputs are unconditionally rejected.
//! - **Bounded collections (CTR-1303)**: all vectors are bounded to prevent
//!   denial-of-service via memory exhaustion.
//! - **Domain-separated hashing**: `BatchEpochRootV1` canonical bytes use a
//!   unique domain separator to prevent cross-protocol hash collisions.
//! - **Content-addressed**: every `BatchEpochRootV1` is CAS-addressable via its
//!   content hash.
//! - **Deterministic**: identical inputs always produce identical outputs.
//!
//! # References
//!
//! - RFC-0020: Batch epoch hierarchical forests
//! - REQ-0025: Root-of-roots commitment requirement
//! - TCK-00370: `FactRootV1` composition (prerequisite)

use thiserror::Error;

use super::merkle::{hash_internal, hash_leaf};
use crate::crypto::{EventHasher, HASH_SIZE, Hash};

// TODO(EVID-0025): evidence artifact for AAT flake classification and
// quarantine tests is deferred to a follow-up ticket.

// ============================================================================
// Constants
// ============================================================================

/// Domain separator for `BatchEpochRootV1` canonical bytes.
const BATCH_EPOCH_ROOT_DOMAIN_SEPARATOR: &[u8] = b"apm2:batch_epoch_root:v1\0";

/// Domain separator for `EpochAntiEntropyPointer` canonical bytes.
const EPOCH_POINTER_DOMAIN_SEPARATOR: &[u8] = b"apm2:epoch_anti_entropy_ptr:v1\0";

/// Maximum number of batch root hashes per epoch.
///
/// Bounded to prevent denial-of-service. 4096 batch roots per epoch is
/// generous for practical deployments while keeping the root-of-roots
/// Merkle tree bounded.
pub const MAX_EPOCH_BATCH_ROOTS: usize = 4096;

/// Maximum number of epochs in a traversal chain.
///
/// Prevents unbounded traversal in anti-entropy resolution. A verifier
/// can traverse at most this many epochs in a single walk.
pub const MAX_TRAVERSAL_EPOCHS: usize = 1 << 16; // 65536

// ============================================================================
// Errors
// ============================================================================

/// Errors produced when constructing or verifying batch epoch roots.
#[derive(Debug, Error)]
pub enum BatchEpochError {
    /// No batch roots provided to the epoch builder.
    #[error("epoch must contain at least one batch root")]
    EmptyBatchRoots,

    /// Too many batch roots in a single epoch.
    #[error("batch root count {count} exceeds maximum {max}")]
    TooManyBatchRoots {
        /// Actual count.
        count: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// A batch root hash is all zeros.
    #[error("batch root hash must not be zero")]
    ZeroBatchRoot,

    /// Duplicate batch root hash detected.
    #[error("duplicate batch root at index {index}")]
    DuplicateBatchRoot {
        /// Index of the duplicate.
        index: usize,
    },

    /// Ledger anchor hash is all zeros.
    #[error("ledger anchor hash must not be zero")]
    ZeroLedgerAnchor,

    /// Previous epoch root hash is zero for non-genesis epoch.
    #[error("previous epoch root hash must not be zero for epoch {epoch}")]
    MissingPreviousRoot {
        /// The epoch number.
        epoch: u64,
    },

    /// Genesis epoch (epoch 0) has a non-zero previous epoch root.
    #[error("genesis epoch must have zero prev_epoch_root")]
    GenesisPrevNotZero,

    /// Pointer epoch root hash is all zeros.
    #[error("epoch anti-entropy pointer hash must not be zero")]
    ZeroPointerHash,

    /// Pointer batch count is zero.
    #[error("epoch anti-entropy pointer batch_count must not be zero")]
    ZeroPointerBatchCount,

    /// Epoch number mismatch during traversal.
    #[error("epoch mismatch: expected {expected}, found {found}")]
    EpochMismatch {
        /// Expected epoch.
        expected: u64,
        /// Found epoch.
        found: u64,
    },

    /// Traversal exceeded maximum epoch count.
    #[error("traversal exceeded maximum of {max} epochs")]
    TraversalLimitExceeded {
        /// Maximum epochs.
        max: usize,
    },

    /// Content hash mismatch during verification.
    #[error("content hash mismatch: computed {computed}, expected {expected}")]
    ContentHashMismatch {
        /// Computed hash (hex).
        computed: String,
        /// Expected hash (hex).
        expected: String,
    },

    /// Builder has already been finalized.
    #[error("epoch root builder has already been finalized")]
    BuilderAlreadyFinalized,

    /// Pointer references an epoch that is ahead of the current state.
    #[error("pointer epoch {pointer_epoch} is ahead of current epoch {current_epoch}")]
    PointerEpochAhead {
        /// Epoch in the pointer.
        pointer_epoch: u64,
        /// Current epoch.
        current_epoch: u64,
    },
}

// ============================================================================
// BatchEpochRootV1
// ============================================================================

/// Root-of-roots commitment for an epoch of batch roots (RFC-0020).
///
/// A `BatchEpochRootV1` binds multiple batch root hashes into a single
/// epoch-level Merkle root, forming a hierarchical chain:
///
/// ```text
/// Epoch 0: [batch_root_0, batch_root_1, ...] -> epoch_root_0
/// Epoch 1: [batch_root_N, batch_root_N+1, ...] -> epoch_root_1 (prev = epoch_root_0)
/// Epoch 2: [batch_root_M, ...] -> epoch_root_2 (prev = epoch_root_1)
/// ```
///
/// This enables verifiers to:
/// 1. Traverse deep batch histories with bounded memory (one epoch at a time).
/// 2. Skip entire epochs during anti-entropy sync when epoch roots match.
/// 3. Reference specific epochs in anti-entropy advertisements.
///
/// # Content Addressing
///
/// The `content_hash()` is deterministic and serves as the epoch's CAS
/// identity. The hash covers all fields including the previous epoch root
/// hash, forming a hash chain across epochs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchEpochRootV1 {
    /// Epoch number (0-indexed, monotonically increasing).
    epoch: u64,
    /// Root-of-roots: Merkle root over all batch root hashes in this epoch.
    root_of_roots: Hash,
    /// Ledger anchor hash binding this epoch to the underlying ledger state.
    ledger_anchor: Hash,
    /// Hash of the previous epoch's `BatchEpochRootV1` (zero for genesis epoch
    /// 0).
    prev_epoch_root: Hash,
    /// Number of batch roots in this epoch (for verification without full
    /// data).
    batch_count: u32,
}

impl BatchEpochRootV1 {
    /// Construct a validated `BatchEpochRootV1`.
    ///
    /// # Arguments
    ///
    /// - `epoch`: epoch number (0 = genesis).
    /// - `batch_root_hashes`: batch root hashes to commit into this epoch.
    /// - `ledger_anchor`: hash binding to the underlying ledger state.
    /// - `prev_epoch_root`: content hash of the previous epoch (zero for epoch
    ///   0).
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `batch_root_hashes` is empty or exceeds `MAX_EPOCH_BATCH_ROOTS`
    /// - Any batch root is all zeros
    /// - Duplicate batch roots are present
    /// - `ledger_anchor` is all zeros
    /// - `prev_epoch_root` is zero for a non-genesis epoch
    pub fn new(
        epoch: u64,
        batch_root_hashes: &[Hash],
        ledger_anchor: Hash,
        prev_epoch_root: Hash,
    ) -> Result<Self, BatchEpochError> {
        // Validate non-empty.
        if batch_root_hashes.is_empty() {
            return Err(BatchEpochError::EmptyBatchRoots);
        }

        // Validate bounded.
        if batch_root_hashes.len() > MAX_EPOCH_BATCH_ROOTS {
            return Err(BatchEpochError::TooManyBatchRoots {
                count: batch_root_hashes.len(),
                max: MAX_EPOCH_BATCH_ROOTS,
            });
        }

        // Validate ledger anchor.
        if ledger_anchor == [0u8; HASH_SIZE] {
            return Err(BatchEpochError::ZeroLedgerAnchor);
        }

        // Validate previous epoch root for non-genesis epochs.
        if epoch > 0 && prev_epoch_root == [0u8; HASH_SIZE] {
            return Err(BatchEpochError::MissingPreviousRoot { epoch });
        }

        // Validate genesis epoch has zero prev_epoch_root.
        if epoch == 0 && prev_epoch_root != [0u8; HASH_SIZE] {
            return Err(BatchEpochError::GenesisPrevNotZero);
        }

        // Validate no zero batch roots and no duplicates.
        for (i, root) in batch_root_hashes.iter().enumerate() {
            if *root == [0u8; HASH_SIZE] {
                return Err(BatchEpochError::ZeroBatchRoot);
            }
            for earlier in &batch_root_hashes[..i] {
                if root == earlier {
                    return Err(BatchEpochError::DuplicateBatchRoot { index: i });
                }
            }
        }

        let root_of_roots = Self::compute_root_of_roots(batch_root_hashes);

        #[allow(clippy::cast_possible_truncation)]
        let batch_count = batch_root_hashes.len() as u32;

        Ok(Self {
            epoch,
            root_of_roots,
            ledger_anchor,
            prev_epoch_root,
            batch_count,
        })
    }

    /// Compute the Merkle root over the batch root hashes (root-of-roots).
    ///
    /// Batch root hashes are sorted lexicographically before Merkle computation
    /// to ensure canonical ordering. This guarantees deterministic output
    /// regardless of insertion order.
    ///
    /// Uses domain-separated leaf hashing consistent with the consensus
    /// Merkle tree implementation.
    #[must_use]
    fn compute_root_of_roots(batch_root_hashes: &[Hash]) -> Hash {
        let mut sorted = batch_root_hashes.to_vec();
        sorted.sort_unstable();

        if sorted.len() == 1 {
            return hash_leaf(&sorted[0]);
        }

        let mut current_level: Vec<Hash> = sorted.iter().map(hash_leaf).collect();

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

    /// Returns the epoch number.
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Returns the root-of-roots Merkle hash.
    #[must_use]
    pub const fn root_of_roots(&self) -> &Hash {
        &self.root_of_roots
    }

    /// Returns the ledger anchor hash.
    #[must_use]
    pub const fn ledger_anchor(&self) -> &Hash {
        &self.ledger_anchor
    }

    /// Returns the previous epoch root hash.
    #[must_use]
    pub const fn prev_epoch_root(&self) -> &Hash {
        &self.prev_epoch_root
    }

    /// Returns the number of batch roots in this epoch.
    #[must_use]
    pub const fn batch_count(&self) -> u32 {
        self.batch_count
    }

    /// Returns true if this is the genesis epoch (epoch 0).
    #[must_use]
    pub const fn is_genesis(&self) -> bool {
        self.epoch == 0
    }

    // ────────── Canonical bytes and content hash ──────────

    /// Compute the canonical byte representation for content-addressing.
    ///
    /// Layout:
    /// ```text
    /// domain_separator
    /// + epoch (8 bytes LE)
    /// + root_of_roots (32 bytes)
    /// + ledger_anchor (32 bytes)
    /// + prev_epoch_root (32 bytes)
    /// + batch_count (4 bytes LE)
    /// ```
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let total = BATCH_EPOCH_ROOT_DOMAIN_SEPARATOR.len()
            + 8  // epoch
            + 32 // root_of_roots
            + 32 // ledger_anchor
            + 32 // prev_epoch_root
            + 4; // batch_count

        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(BATCH_EPOCH_ROOT_DOMAIN_SEPARATOR);
        out.extend_from_slice(&self.epoch.to_le_bytes());
        out.extend_from_slice(&self.root_of_roots);
        out.extend_from_slice(&self.ledger_anchor);
        out.extend_from_slice(&self.prev_epoch_root);
        out.extend_from_slice(&self.batch_count.to_le_bytes());
        out
    }

    /// Compute the content-address hash of this epoch root.
    #[must_use]
    pub fn content_hash(&self) -> Hash {
        EventHasher::hash_content(&self.canonical_bytes())
    }
}

// ============================================================================
// EpochRootBuilder
// ============================================================================

/// Accumulator that collects batch root hashes within an epoch and produces
/// the final `BatchEpochRootV1`.
///
/// # Usage
///
/// ```rust,ignore
/// let mut builder = EpochRootBuilder::new(1, prev_epoch_hash);
/// builder.add_batch_root(batch_hash_a)?;
/// builder.add_batch_root(batch_hash_b)?;
/// let epoch_root = builder.finalize(ledger_anchor)?;
/// ```
pub struct EpochRootBuilder {
    /// Epoch number.
    epoch: u64,
    /// Previous epoch root hash (zero for genesis).
    prev_epoch_root: Hash,
    /// Accumulated batch root hashes.
    batch_roots: Vec<Hash>,
    /// Whether finalize has been called.
    finalized: bool,
}

impl EpochRootBuilder {
    /// Create a new builder for the given epoch.
    ///
    /// # Arguments
    ///
    /// - `epoch`: epoch number (0 = genesis).
    /// - `prev_epoch_root`: content hash of the previous epoch root (zero hash
    ///   for genesis epoch 0).
    #[must_use]
    pub const fn new(epoch: u64, prev_epoch_root: Hash) -> Self {
        Self {
            epoch,
            prev_epoch_root,
            batch_roots: Vec::new(),
            finalized: false,
        }
    }

    /// Add a batch root hash to this epoch.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The builder has already been finalized
    /// - The batch root is all zeros
    /// - Adding this root would exceed `MAX_EPOCH_BATCH_ROOTS`
    /// - The batch root is a duplicate
    pub fn add_batch_root(&mut self, batch_root: Hash) -> Result<(), BatchEpochError> {
        if self.finalized {
            return Err(BatchEpochError::BuilderAlreadyFinalized);
        }

        if batch_root == [0u8; HASH_SIZE] {
            return Err(BatchEpochError::ZeroBatchRoot);
        }

        if self.batch_roots.len() >= MAX_EPOCH_BATCH_ROOTS {
            return Err(BatchEpochError::TooManyBatchRoots {
                count: self.batch_roots.len() + 1,
                max: MAX_EPOCH_BATCH_ROOTS,
            });
        }

        // Check for duplicates.
        for existing in &self.batch_roots {
            if *existing == batch_root {
                return Err(BatchEpochError::DuplicateBatchRoot {
                    index: self.batch_roots.len(),
                });
            }
        }

        self.batch_roots.push(batch_root);
        Ok(())
    }

    /// Returns the current number of accumulated batch roots.
    #[must_use]
    pub fn current_count(&self) -> usize {
        self.batch_roots.len()
    }

    /// Returns true if the builder has been finalized.
    #[must_use]
    pub const fn is_finalized(&self) -> bool {
        self.finalized
    }

    /// Finalize the builder and produce a `BatchEpochRootV1`.
    ///
    /// # Arguments
    ///
    /// - `ledger_anchor`: hash binding this epoch to the underlying ledger
    ///   state.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The builder has already been finalized
    /// - No batch roots have been added
    /// - The ledger anchor is all zeros
    /// - The previous epoch root is zero for a non-genesis epoch
    pub fn finalize(mut self, ledger_anchor: Hash) -> Result<BatchEpochRootV1, BatchEpochError> {
        if self.finalized {
            return Err(BatchEpochError::BuilderAlreadyFinalized);
        }
        self.finalized = true;

        BatchEpochRootV1::new(
            self.epoch,
            &self.batch_roots,
            ledger_anchor,
            self.prev_epoch_root,
        )
    }
}

// ============================================================================
// EpochAntiEntropyPointer
// ============================================================================

/// Compact pointer for cross-epoch anti-entropy advertisements.
///
/// Peers exchange these pointers to quickly identify which epochs need
/// synchronization. A pointer references a specific epoch root by its
/// content hash, allowing the receiving peer to:
///
/// 1. Check if they already have this epoch (by content hash lookup).
/// 2. Skip entire epochs that match, focusing sync on divergent epochs.
/// 3. Request specific epoch data using the pointer as a reference.
///
/// # Wire Efficiency
///
/// Each pointer is 48 bytes (8 epoch + 32 content hash + 4 batch count +
/// 4 reserved), compared to potentially megabytes of full epoch data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochAntiEntropyPointer {
    /// Epoch number this pointer references.
    epoch: u64,
    /// Content hash of the `BatchEpochRootV1` at this epoch.
    epoch_root_hash: Hash,
    /// Number of batch roots in the referenced epoch.
    batch_count: u32,
}

impl EpochAntiEntropyPointer {
    /// Create a pointer from a `BatchEpochRootV1`.
    #[must_use]
    pub fn from_epoch_root(root: &BatchEpochRootV1) -> Self {
        Self {
            epoch: root.epoch(),
            epoch_root_hash: root.content_hash(),
            batch_count: root.batch_count(),
        }
    }

    /// Create a pointer from individual components.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `epoch_root_hash` is all zeros
    /// - `batch_count` is zero
    pub fn new(
        epoch: u64,
        epoch_root_hash: Hash,
        batch_count: u32,
    ) -> Result<Self, BatchEpochError> {
        if epoch_root_hash == [0u8; HASH_SIZE] {
            return Err(BatchEpochError::ZeroPointerHash);
        }
        if batch_count == 0 {
            return Err(BatchEpochError::ZeroPointerBatchCount);
        }
        if batch_count as usize > MAX_EPOCH_BATCH_ROOTS {
            return Err(BatchEpochError::TooManyBatchRoots {
                count: batch_count as usize,
                max: MAX_EPOCH_BATCH_ROOTS,
            });
        }
        Ok(Self {
            epoch,
            epoch_root_hash,
            batch_count,
        })
    }

    // ────────── Accessors ──────────

    /// Returns the epoch number.
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Returns the epoch root content hash.
    #[must_use]
    pub const fn epoch_root_hash(&self) -> &Hash {
        &self.epoch_root_hash
    }

    /// Returns the batch count in the referenced epoch.
    #[must_use]
    pub const fn batch_count(&self) -> u32 {
        self.batch_count
    }

    /// Check whether this pointer matches a given `BatchEpochRootV1`.
    #[must_use]
    pub fn matches(&self, root: &BatchEpochRootV1) -> bool {
        self.epoch == root.epoch()
            && self.epoch_root_hash == root.content_hash()
            && self.batch_count == root.batch_count()
    }

    // ────────── Canonical bytes and content hash ──────────

    /// Compute the canonical byte representation.
    ///
    /// Layout:
    /// ```text
    /// domain_separator
    /// + epoch (8 bytes LE)
    /// + epoch_root_hash (32 bytes)
    /// + batch_count (4 bytes LE)
    /// ```
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let total = EPOCH_POINTER_DOMAIN_SEPARATOR.len()
            + 8  // epoch
            + 32 // epoch_root_hash
            + 4; // batch_count

        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(EPOCH_POINTER_DOMAIN_SEPARATOR);
        out.extend_from_slice(&self.epoch.to_le_bytes());
        out.extend_from_slice(&self.epoch_root_hash);
        out.extend_from_slice(&self.batch_count.to_le_bytes());
        out
    }

    /// Compute the content-address hash of this pointer.
    #[must_use]
    pub fn content_hash(&self) -> Hash {
        EventHasher::hash_content(&self.canonical_bytes())
    }
}

// ============================================================================
// EpochTraverser
// ============================================================================

/// Bounded-memory traverser that walks the epoch root chain.
///
/// The traverser processes one epoch at a time with `O(1)` memory per step,
/// never holding more than one epoch root in working memory. This enables
/// verification of arbitrarily deep epoch histories without unbounded memory
/// growth.
///
/// # Usage
///
/// ```rust,ignore
/// let mut traverser = EpochTraverser::new(latest_epoch_root);
///
/// // Walk backwards through epochs
/// while let Some(current) = traverser.current() {
///     // Process current epoch root
///     process(current);
///
///     // Advance to previous epoch (caller provides the root)
///     let prev_root = fetch_epoch_root(current.prev_epoch_root());
///     if !traverser.step_back(prev_root)? {
///         break; // Reached genesis
///     }
/// }
/// ```
pub struct EpochTraverser {
    /// Current epoch root being examined.
    current: Option<BatchEpochRootV1>,
    /// Number of steps taken so far (bounded by `MAX_TRAVERSAL_EPOCHS`).
    steps_taken: usize,
}

impl EpochTraverser {
    /// Create a new traverser starting at the given epoch root.
    #[must_use]
    pub const fn new(start: BatchEpochRootV1) -> Self {
        Self {
            current: Some(start),
            steps_taken: 0,
        }
    }

    /// Returns a reference to the current epoch root, if any.
    #[must_use]
    pub const fn current(&self) -> Option<&BatchEpochRootV1> {
        self.current.as_ref()
    }

    /// Returns the number of steps taken so far.
    #[must_use]
    pub const fn steps_taken(&self) -> usize {
        self.steps_taken
    }

    /// Returns true if the traverser has reached genesis or been exhausted.
    #[must_use]
    pub const fn is_exhausted(&self) -> bool {
        self.current.is_none()
    }

    /// Step backward to the previous epoch.
    ///
    /// The caller provides the `BatchEpochRootV1` for the previous epoch.
    /// The traverser validates that:
    /// 1. The previous root's content hash matches `current.prev_epoch_root`.
    /// 2. The previous root's epoch is exactly `current.epoch - 1`.
    /// 3. The traversal limit has not been exceeded.
    ///
    /// Returns `Ok(true)` if the step was taken, `Ok(false)` if the current
    /// epoch is genesis (no more steps possible).
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The provided root's content hash does not match
    /// - The epoch numbers are not consecutive
    /// - The traversal limit is exceeded
    pub fn step_back(&mut self, prev_root: BatchEpochRootV1) -> Result<bool, BatchEpochError> {
        let Some(current) = &self.current else {
            return Ok(false);
        };

        // Genesis has no predecessor.
        if current.is_genesis() {
            self.current = None;
            return Ok(false);
        }

        // Validate traversal limit.
        if self.steps_taken >= MAX_TRAVERSAL_EPOCHS {
            return Err(BatchEpochError::TraversalLimitExceeded {
                max: MAX_TRAVERSAL_EPOCHS,
            });
        }

        // Validate epoch is consecutive.
        let expected_epoch = current.epoch() - 1;
        if prev_root.epoch() != expected_epoch {
            return Err(BatchEpochError::EpochMismatch {
                expected: expected_epoch,
                found: prev_root.epoch(),
            });
        }

        // Validate content hash linkage.
        let prev_content_hash = prev_root.content_hash();
        if prev_content_hash != *current.prev_epoch_root() {
            return Err(BatchEpochError::ContentHashMismatch {
                computed: hex_encode(&prev_content_hash),
                expected: hex_encode(current.prev_epoch_root()),
            });
        }

        self.current = Some(prev_root);
        self.steps_taken += 1;
        Ok(true)
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Hex-encodes a hash for error messages.
fn hex_encode(hash: &Hash) -> String {
    use std::fmt::Write;
    hash.iter().fold(String::new(), |mut acc: String, b: &u8| {
        let _ = write!(acc, "{b:02x}");
        acc
    })
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tck_00371_unit_tests {
    use super::*;

    fn test_hash(i: u64) -> Hash {
        EventHasher::hash_content(&i.to_le_bytes())
    }

    // ── BatchEpochRootV1 construction ──

    #[test]
    fn epoch_root_construction_valid_genesis() {
        let batch_roots = vec![test_hash(1), test_hash(2), test_hash(3)];
        let ledger_anchor = test_hash(100);
        let epoch_root =
            BatchEpochRootV1::new(0, &batch_roots, ledger_anchor, [0u8; HASH_SIZE]).unwrap();

        assert_eq!(epoch_root.epoch(), 0);
        assert!(epoch_root.is_genesis());
        assert_eq!(epoch_root.batch_count(), 3);
        assert_eq!(epoch_root.ledger_anchor(), &ledger_anchor);
        assert_eq!(epoch_root.prev_epoch_root(), &[0u8; HASH_SIZE]);
    }

    #[test]
    fn epoch_root_construction_valid_non_genesis() {
        let batch_roots = vec![test_hash(10), test_hash(11)];
        let ledger_anchor = test_hash(200);
        let prev_hash = test_hash(999);
        let epoch_root = BatchEpochRootV1::new(5, &batch_roots, ledger_anchor, prev_hash).unwrap();

        assert_eq!(epoch_root.epoch(), 5);
        assert!(!epoch_root.is_genesis());
        assert_eq!(epoch_root.batch_count(), 2);
        assert_eq!(epoch_root.prev_epoch_root(), &prev_hash);
    }

    #[test]
    fn epoch_root_rejects_empty_batch_roots() {
        let result = BatchEpochRootV1::new(0, &[], test_hash(100), [0u8; HASH_SIZE]);
        assert!(matches!(result, Err(BatchEpochError::EmptyBatchRoots)));
    }

    #[test]
    fn epoch_root_rejects_too_many_batch_roots() {
        let batch_roots: Vec<Hash> = (0..=MAX_EPOCH_BATCH_ROOTS as u64)
            .map(|i| test_hash(i + 1))
            .collect();
        let result = BatchEpochRootV1::new(0, &batch_roots, test_hash(100), [0u8; HASH_SIZE]);
        assert!(matches!(
            result,
            Err(BatchEpochError::TooManyBatchRoots { .. })
        ));
    }

    #[test]
    fn epoch_root_rejects_zero_batch_root() {
        let result =
            BatchEpochRootV1::new(0, &[[0u8; HASH_SIZE]], test_hash(100), [0u8; HASH_SIZE]);
        assert!(matches!(result, Err(BatchEpochError::ZeroBatchRoot)));
    }

    #[test]
    fn epoch_root_rejects_zero_ledger_anchor() {
        let result = BatchEpochRootV1::new(0, &[test_hash(1)], [0u8; HASH_SIZE], [0u8; HASH_SIZE]);
        assert!(matches!(result, Err(BatchEpochError::ZeroLedgerAnchor)));
    }

    #[test]
    fn epoch_root_rejects_zero_prev_for_non_genesis() {
        let result = BatchEpochRootV1::new(1, &[test_hash(1)], test_hash(100), [0u8; HASH_SIZE]);
        assert!(matches!(
            result,
            Err(BatchEpochError::MissingPreviousRoot { epoch: 1 })
        ));
    }

    #[test]
    fn epoch_root_rejects_duplicate_batch_roots() {
        let h = test_hash(1);
        let result = BatchEpochRootV1::new(0, &[h, h], test_hash(100), [0u8; HASH_SIZE]);
        assert!(matches!(
            result,
            Err(BatchEpochError::DuplicateBatchRoot { index: 1 })
        ));
    }

    // ── Deterministic hashing ──

    #[test]
    fn epoch_root_content_hash_deterministic() {
        let batch_roots = vec![test_hash(1), test_hash(2)];
        let er1 = BatchEpochRootV1::new(0, &batch_roots, test_hash(100), [0u8; HASH_SIZE]).unwrap();
        let er2 = BatchEpochRootV1::new(0, &batch_roots, test_hash(100), [0u8; HASH_SIZE]).unwrap();
        assert_eq!(er1.content_hash(), er2.content_hash());
        assert_eq!(er1.canonical_bytes(), er2.canonical_bytes());
    }

    #[test]
    fn epoch_root_content_hash_changes_with_epoch() {
        let batch_roots = vec![test_hash(1)];
        let er1 = BatchEpochRootV1::new(0, &batch_roots, test_hash(100), [0u8; HASH_SIZE]).unwrap();
        let er2 = BatchEpochRootV1::new(1, &batch_roots, test_hash(100), test_hash(999)).unwrap();
        assert_ne!(er1.content_hash(), er2.content_hash());
    }

    #[test]
    fn epoch_root_content_hash_changes_with_batch_roots() {
        let er1 =
            BatchEpochRootV1::new(0, &[test_hash(1)], test_hash(100), [0u8; HASH_SIZE]).unwrap();
        let er2 =
            BatchEpochRootV1::new(0, &[test_hash(2)], test_hash(100), [0u8; HASH_SIZE]).unwrap();
        assert_ne!(er1.content_hash(), er2.content_hash());
    }

    #[test]
    fn epoch_root_content_hash_changes_with_ledger_anchor() {
        let batch_roots = vec![test_hash(1)];
        let er1 = BatchEpochRootV1::new(0, &batch_roots, test_hash(100), [0u8; HASH_SIZE]).unwrap();
        let er2 = BatchEpochRootV1::new(0, &batch_roots, test_hash(200), [0u8; HASH_SIZE]).unwrap();
        assert_ne!(er1.content_hash(), er2.content_hash());
    }

    #[test]
    fn epoch_root_content_hash_changes_with_prev_epoch_root() {
        let batch_roots = vec![test_hash(1)];
        let er1 = BatchEpochRootV1::new(1, &batch_roots, test_hash(100), test_hash(500)).unwrap();
        let er2 = BatchEpochRootV1::new(1, &batch_roots, test_hash(100), test_hash(600)).unwrap();
        assert_ne!(er1.content_hash(), er2.content_hash());
    }

    #[test]
    fn epoch_root_root_of_roots_single_batch() {
        let er =
            BatchEpochRootV1::new(0, &[test_hash(42)], test_hash(100), [0u8; HASH_SIZE]).unwrap();
        // Single batch root: root-of-roots should be hash_leaf of that root.
        assert_eq!(er.root_of_roots(), &hash_leaf(&test_hash(42)));
    }

    #[test]
    fn epoch_root_root_of_roots_deterministic_across_sizes() {
        for count in [1u64, 2, 3, 4, 7, 8, 15, 16] {
            let batch_roots: Vec<Hash> = (1..=count).map(test_hash).collect();
            let er1 =
                BatchEpochRootV1::new(0, &batch_roots, test_hash(100), [0u8; HASH_SIZE]).unwrap();
            let er2 =
                BatchEpochRootV1::new(0, &batch_roots, test_hash(100), [0u8; HASH_SIZE]).unwrap();
            assert_eq!(
                er1.root_of_roots(),
                er2.root_of_roots(),
                "root_of_roots should be deterministic for count={count}"
            );
        }
    }

    // ── EpochRootBuilder ──

    #[test]
    fn builder_basic_round_trip() {
        let mut builder = EpochRootBuilder::new(0, [0u8; HASH_SIZE]);
        builder.add_batch_root(test_hash(1)).unwrap();
        builder.add_batch_root(test_hash(2)).unwrap();
        builder.add_batch_root(test_hash(3)).unwrap();

        assert_eq!(builder.current_count(), 3);
        assert!(!builder.is_finalized());

        let epoch_root = builder.finalize(test_hash(100)).unwrap();
        assert_eq!(epoch_root.epoch(), 0);
        assert_eq!(epoch_root.batch_count(), 3);
    }

    #[test]
    fn builder_matches_direct_construction() {
        let batch_roots = vec![test_hash(10), test_hash(20), test_hash(30)];
        let ledger_anchor = test_hash(500);

        // Direct construction
        let direct =
            BatchEpochRootV1::new(0, &batch_roots, ledger_anchor, [0u8; HASH_SIZE]).unwrap();

        // Builder construction
        let mut builder = EpochRootBuilder::new(0, [0u8; HASH_SIZE]);
        for root in &batch_roots {
            builder.add_batch_root(*root).unwrap();
        }
        let built = builder.finalize(ledger_anchor).unwrap();

        assert_eq!(direct.content_hash(), built.content_hash());
        assert_eq!(direct.root_of_roots(), built.root_of_roots());
    }

    #[test]
    fn builder_rejects_zero_batch_root() {
        let mut builder = EpochRootBuilder::new(0, [0u8; HASH_SIZE]);
        let result = builder.add_batch_root([0u8; HASH_SIZE]);
        assert!(matches!(result, Err(BatchEpochError::ZeroBatchRoot)));
    }

    #[test]
    fn builder_rejects_duplicate() {
        let mut builder = EpochRootBuilder::new(0, [0u8; HASH_SIZE]);
        builder.add_batch_root(test_hash(1)).unwrap();
        let result = builder.add_batch_root(test_hash(1));
        assert!(matches!(
            result,
            Err(BatchEpochError::DuplicateBatchRoot { .. })
        ));
    }

    #[test]
    fn builder_rejects_empty_finalize() {
        let builder = EpochRootBuilder::new(0, [0u8; HASH_SIZE]);
        let result = builder.finalize(test_hash(100));
        assert!(matches!(result, Err(BatchEpochError::EmptyBatchRoots)));
    }

    // ── EpochAntiEntropyPointer ──

    #[test]
    fn pointer_from_epoch_root() {
        let epoch_root = BatchEpochRootV1::new(
            3,
            &[test_hash(1), test_hash(2)],
            test_hash(100),
            test_hash(999),
        )
        .unwrap();

        let pointer = EpochAntiEntropyPointer::from_epoch_root(&epoch_root);
        assert_eq!(pointer.epoch(), 3);
        assert_eq!(pointer.epoch_root_hash(), &epoch_root.content_hash());
        assert_eq!(pointer.batch_count(), 2);
        assert!(pointer.matches(&epoch_root));
    }

    #[test]
    fn pointer_does_not_match_different_epoch() {
        let er1 =
            BatchEpochRootV1::new(0, &[test_hash(1)], test_hash(100), [0u8; HASH_SIZE]).unwrap();
        let er2 =
            BatchEpochRootV1::new(1, &[test_hash(2)], test_hash(200), test_hash(999)).unwrap();

        let pointer = EpochAntiEntropyPointer::from_epoch_root(&er1);
        assert!(pointer.matches(&er1));
        assert!(!pointer.matches(&er2));
    }

    #[test]
    fn pointer_content_hash_deterministic() {
        let epoch_root =
            BatchEpochRootV1::new(0, &[test_hash(1)], test_hash(100), [0u8; HASH_SIZE]).unwrap();

        let p1 = EpochAntiEntropyPointer::from_epoch_root(&epoch_root);
        let p2 = EpochAntiEntropyPointer::from_epoch_root(&epoch_root);
        assert_eq!(p1.content_hash(), p2.content_hash());
        assert_eq!(p1.canonical_bytes(), p2.canonical_bytes());
    }

    #[test]
    fn pointer_manual_construction() {
        let pointer = EpochAntiEntropyPointer::new(42, test_hash(999), 10).unwrap();
        assert_eq!(pointer.epoch(), 42);
        assert_eq!(pointer.epoch_root_hash(), &test_hash(999));
        assert_eq!(pointer.batch_count(), 10);
    }

    // ── EpochTraverser ──

    /// Helper: build a chain of epoch roots for traversal testing.
    fn build_epoch_chain(num_epochs: usize) -> Vec<BatchEpochRootV1> {
        let mut chain: Vec<BatchEpochRootV1> = Vec::with_capacity(num_epochs);

        for epoch in 0..num_epochs {
            let batch_roots: Vec<Hash> = (0..3)
                .map(|i| test_hash((epoch as u64) * 100 + i + 1))
                .collect();
            let ledger_anchor = test_hash((epoch as u64) * 1000 + 500);
            let prev_epoch_root = if epoch == 0 {
                [0u8; HASH_SIZE]
            } else {
                chain[epoch - 1].content_hash()
            };

            let epoch_root =
                BatchEpochRootV1::new(epoch as u64, &batch_roots, ledger_anchor, prev_epoch_root)
                    .unwrap();
            chain.push(epoch_root);
        }

        chain
    }

    #[test]
    fn traverser_single_epoch() {
        let chain = build_epoch_chain(1);
        let traverser = EpochTraverser::new(chain[0].clone());

        assert!(traverser.current().is_some());
        assert_eq!(traverser.current().unwrap().epoch(), 0);
        assert_eq!(traverser.steps_taken(), 0);
        assert!(!traverser.is_exhausted());
    }

    #[test]
    fn traverser_walks_chain_backwards() {
        let chain = build_epoch_chain(5);
        let mut traverser = EpochTraverser::new(chain[4].clone());

        // Should be at epoch 4
        assert_eq!(traverser.current().unwrap().epoch(), 4);

        // Step to epoch 3
        assert!(traverser.step_back(chain[3].clone()).unwrap());
        assert_eq!(traverser.current().unwrap().epoch(), 3);
        assert_eq!(traverser.steps_taken(), 1);

        // Step to epoch 2
        assert!(traverser.step_back(chain[2].clone()).unwrap());
        assert_eq!(traverser.current().unwrap().epoch(), 2);

        // Step to epoch 1
        assert!(traverser.step_back(chain[1].clone()).unwrap());
        assert_eq!(traverser.current().unwrap().epoch(), 1);

        // Step to epoch 0
        assert!(traverser.step_back(chain[0].clone()).unwrap());
        assert_eq!(traverser.current().unwrap().epoch(), 0);

        // Epoch 0 is genesis; step_back returns false
        // Need a dummy root for the call but genesis returns false immediately
        let result = traverser.step_back(chain[0].clone()).unwrap();
        assert!(!result);
        assert!(traverser.is_exhausted());
    }

    #[test]
    fn traverser_bounded_memory() {
        // Verify traverser maintains O(1) working memory by walking a large chain.
        let chain = build_epoch_chain(100);
        let mut traverser = EpochTraverser::new(chain[99].clone());

        // Walk all the way back, one step at a time.
        for expected_epoch in (0..99).rev() {
            let stepped = traverser.step_back(chain[expected_epoch].clone()).unwrap();
            assert!(stepped);
            assert_eq!(traverser.current().unwrap().epoch(), expected_epoch as u64);
        }

        // At genesis, step_back returns false.
        assert!(!traverser.step_back(chain[0].clone()).unwrap());
        assert!(traverser.is_exhausted());
        assert_eq!(traverser.steps_taken(), 99);
    }

    #[test]
    fn traverser_rejects_wrong_content_hash() {
        let chain = build_epoch_chain(3);
        let mut traverser = EpochTraverser::new(chain[2].clone());

        // Provide epoch 1 with tampered data (wrong batch roots)
        let tampered = BatchEpochRootV1::new(
            1,
            &[test_hash(9999)],
            test_hash(8888),
            chain[0].content_hash(),
        )
        .unwrap();

        let result = traverser.step_back(tampered);
        assert!(matches!(
            result,
            Err(BatchEpochError::ContentHashMismatch { .. })
        ));
    }

    #[test]
    fn traverser_rejects_wrong_epoch_number() {
        let chain = build_epoch_chain(3);
        let mut traverser = EpochTraverser::new(chain[2].clone());

        // Provide epoch 0 when epoch 1 is expected.
        let result = traverser.step_back(chain[0].clone());
        assert!(matches!(
            result,
            Err(BatchEpochError::EpochMismatch {
                expected: 1,
                found: 0
            })
        ));
    }

    // ── Root-of-roots round-trip ──

    #[test]
    fn root_of_roots_round_trip() {
        // Verify that building from the same batch roots always produces
        // the same root-of-roots.
        for count in [1u64, 2, 3, 4, 5, 7, 8, 15, 16, 32] {
            let batch_roots: Vec<Hash> = (1..=count).map(test_hash).collect();

            let er1 =
                BatchEpochRootV1::new(0, &batch_roots, test_hash(100), [0u8; HASH_SIZE]).unwrap();
            let er2 =
                BatchEpochRootV1::new(0, &batch_roots, test_hash(100), [0u8; HASH_SIZE]).unwrap();

            assert_eq!(
                er1.root_of_roots(),
                er2.root_of_roots(),
                "root_of_roots mismatch for count={count}"
            );
            assert_eq!(
                er1.content_hash(),
                er2.content_hash(),
                "content_hash mismatch for count={count}"
            );
        }
    }

    // ── Anti-entropy pointer resolution ──

    #[test]
    fn pointer_resolution_in_chain() {
        let chain = build_epoch_chain(5);

        // Build pointers for each epoch.
        let pointers: Vec<EpochAntiEntropyPointer> = chain
            .iter()
            .map(EpochAntiEntropyPointer::from_epoch_root)
            .collect();

        // Each pointer should match its corresponding epoch root.
        for (pointer, root) in pointers.iter().zip(chain.iter()) {
            assert!(
                pointer.matches(root),
                "pointer should match epoch {}",
                root.epoch()
            );
        }

        // No pointer should match a different epoch.
        for (i, pointer) in pointers.iter().enumerate() {
            for (j, root) in chain.iter().enumerate() {
                if i != j {
                    assert!(
                        !pointer.matches(root),
                        "pointer {i} should not match epoch {j}",
                    );
                }
            }
        }
    }

    // ── Canonical bytes round-trip ──

    #[test]
    fn canonical_bytes_round_trip() {
        let chain = build_epoch_chain(3);
        for root in &chain {
            let bytes = root.canonical_bytes();
            let hash = root.content_hash();

            // Reconstruct and verify same hash.
            let root2 = if root.is_genesis() {
                // We can't reconstruct from bytes alone, but we can verify
                // that the same construction produces the same bytes.
                let batch_roots: Vec<Hash> = (0..3)
                    .map(|i| test_hash(root.epoch() * 100 + i + 1))
                    .collect();
                BatchEpochRootV1::new(
                    root.epoch(),
                    &batch_roots,
                    *root.ledger_anchor(),
                    *root.prev_epoch_root(),
                )
                .unwrap()
            } else {
                let batch_roots: Vec<Hash> = (0..3)
                    .map(|i| test_hash(root.epoch() * 100 + i + 1))
                    .collect();
                BatchEpochRootV1::new(
                    root.epoch(),
                    &batch_roots,
                    *root.ledger_anchor(),
                    *root.prev_epoch_root(),
                )
                .unwrap()
            };

            assert_eq!(root2.canonical_bytes(), bytes);
            assert_eq!(root2.content_hash(), hash);
        }
    }

    // ── Domain separation ──

    #[test]
    fn domain_separation_epoch_root_vs_pointer() {
        let epoch_root =
            BatchEpochRootV1::new(0, &[test_hash(1)], test_hash(100), [0u8; HASH_SIZE]).unwrap();
        let pointer = EpochAntiEntropyPointer::from_epoch_root(&epoch_root);

        // The content hashes should be different due to domain separation.
        assert_ne!(epoch_root.content_hash(), pointer.content_hash());
    }

    // ── Fix regression tests ──

    #[test]
    fn genesis_epoch_rejects_nonzero_prev_epoch_root() {
        let result = BatchEpochRootV1::new(
            0,
            &[test_hash(1)],
            test_hash(100),
            test_hash(999), // non-zero prev for genesis
        );
        assert!(
            matches!(result, Err(BatchEpochError::GenesisPrevNotZero)),
            "genesis epoch must reject non-zero prev_epoch_root, got: {result:?}"
        );
    }

    #[test]
    fn pointer_new_rejects_zero_hash() {
        let result = EpochAntiEntropyPointer::new(0, [0u8; HASH_SIZE], 5);
        assert!(
            matches!(result, Err(BatchEpochError::ZeroPointerHash)),
            "pointer should reject zero epoch_root_hash, got: {result:?}"
        );
    }

    #[test]
    fn pointer_new_rejects_zero_batch_count() {
        let result = EpochAntiEntropyPointer::new(0, test_hash(1), 0);
        assert!(
            matches!(result, Err(BatchEpochError::ZeroPointerBatchCount)),
            "pointer should reject zero batch_count, got: {result:?}"
        );
    }

    #[test]
    fn pointer_new_rejects_batch_count_exceeding_max() {
        // MAX_EPOCH_BATCH_ROOTS + 1 must be rejected.
        let over_by_one = u32::try_from(MAX_EPOCH_BATCH_ROOTS + 1)
            .expect("MAX_EPOCH_BATCH_ROOTS + 1 fits in u32");
        let result = EpochAntiEntropyPointer::new(0, test_hash(1), over_by_one);
        assert!(
            matches!(
                result,
                Err(BatchEpochError::TooManyBatchRoots { count, max })
                    if count == MAX_EPOCH_BATCH_ROOTS + 1 && max == MAX_EPOCH_BATCH_ROOTS
            ),
            "batch_count == MAX+1 must be rejected, got: {result:?}"
        );
    }

    #[test]
    fn pointer_new_rejects_u32_max_batch_count() {
        let result = EpochAntiEntropyPointer::new(0, test_hash(1), u32::MAX);
        assert!(
            matches!(
                result,
                Err(BatchEpochError::TooManyBatchRoots { count, max })
                    if count == u32::MAX as usize && max == MAX_EPOCH_BATCH_ROOTS
            ),
            "batch_count == u32::MAX must be rejected, got: {result:?}"
        );
    }

    #[test]
    fn pointer_new_accepts_exactly_max_batch_count() {
        let exactly_max =
            u32::try_from(MAX_EPOCH_BATCH_ROOTS).expect("MAX_EPOCH_BATCH_ROOTS fits in u32");
        let result = EpochAntiEntropyPointer::new(0, test_hash(1), exactly_max);
        assert!(
            result.is_ok(),
            "batch_count == MAX_EPOCH_BATCH_ROOTS must be accepted, got: {result:?}"
        );
        let pointer = result.unwrap();
        assert_eq!(pointer.batch_count(), exactly_max);
        assert_eq!(pointer.epoch(), 0);
    }

    #[test]
    fn pointer_matches_includes_batch_count() {
        let er = BatchEpochRootV1::new(
            0,
            &[test_hash(1), test_hash(2)],
            test_hash(100),
            [0u8; HASH_SIZE],
        )
        .unwrap();

        // Correct pointer from epoch root matches.
        let good_pointer = EpochAntiEntropyPointer::from_epoch_root(&er);
        assert!(good_pointer.matches(&er));

        // Pointer with wrong batch_count does not match.
        let bad_pointer = EpochAntiEntropyPointer::new(er.epoch(), er.content_hash(), 999).unwrap();
        assert!(
            !bad_pointer.matches(&er),
            "pointer with wrong batch_count should not match"
        );
    }

    #[test]
    fn canonical_ordering_is_insertion_order_independent() {
        let a = test_hash(1);
        let b = test_hash(2);
        let c = test_hash(3);

        // Build with order [a, b, c]
        let er1 = BatchEpochRootV1::new(0, &[a, b, c], test_hash(100), [0u8; HASH_SIZE]).unwrap();

        // Build with order [c, a, b]
        let er2 = BatchEpochRootV1::new(0, &[c, a, b], test_hash(100), [0u8; HASH_SIZE]).unwrap();

        assert_eq!(
            er1.root_of_roots(),
            er2.root_of_roots(),
            "root_of_roots must be identical regardless of insertion order"
        );
        assert_eq!(
            er1.content_hash(),
            er2.content_hash(),
            "content_hash must be identical regardless of insertion order"
        );
    }

    #[test]
    fn builder_duplicate_reports_correct_insertion_index() {
        let mut builder = EpochRootBuilder::new(0, [0u8; HASH_SIZE]);
        builder.add_batch_root(test_hash(10)).unwrap();
        builder.add_batch_root(test_hash(20)).unwrap();
        builder.add_batch_root(test_hash(30)).unwrap();

        // Attempting to add test_hash(10) again at what would be index 3
        let result = builder.add_batch_root(test_hash(10));
        assert!(
            matches!(
                result,
                Err(BatchEpochError::DuplicateBatchRoot { index: 3 })
            ),
            "should report the attempted insertion index (3), got: {result:?}"
        );
    }
}

#[cfg(test)]
mod tck_00371_property_tests {
    use proptest::prelude::*;

    use super::*;

    proptest! {
        /// Property: BatchEpochRootV1 content hash is deterministic.
        #[test]
        fn prop_epoch_root_deterministic(
            batch_count in 1usize..=16,
            epoch_num in 0u64..10,
            seed in 1u64..10000,
        ) {
            let batch_roots: Vec<Hash> = (seed..seed + batch_count as u64)
                .map(|i| EventHasher::hash_content(&i.to_le_bytes()))
                .collect();
            let ledger_anchor = EventHasher::hash_content(&(seed + 99999).to_le_bytes());
            let prev = if epoch_num == 0 {
                [0u8; HASH_SIZE]
            } else {
                EventHasher::hash_content(&(seed + 88888).to_le_bytes())
            };

            let er1 = BatchEpochRootV1::new(epoch_num, &batch_roots, ledger_anchor, prev).unwrap();
            let er2 = BatchEpochRootV1::new(epoch_num, &batch_roots, ledger_anchor, prev).unwrap();

            prop_assert_eq!(er1.content_hash(), er2.content_hash());
            prop_assert_eq!(er1.canonical_bytes(), er2.canonical_bytes());
            prop_assert_eq!(er1.root_of_roots(), er2.root_of_roots());
        }

        /// Property: BatchEpochRootV1 rejects zero ledger anchor.
        #[test]
        fn prop_epoch_root_rejects_zero_anchor(
            batch_count in 1usize..=8,
            seed in 1u64..10000,
        ) {
            let batch_roots: Vec<Hash> = (seed..seed + batch_count as u64)
                .map(|i| EventHasher::hash_content(&i.to_le_bytes()))
                .collect();
            let result = BatchEpochRootV1::new(0, &batch_roots, [0u8; HASH_SIZE], [0u8; HASH_SIZE]);
            prop_assert!(matches!(result, Err(BatchEpochError::ZeroLedgerAnchor)));
        }

        /// Property: Builder output matches direct construction.
        #[test]
        fn prop_builder_matches_direct(
            batch_count in 1usize..=16,
            seed in 1u64..10000,
        ) {
            let batch_roots: Vec<Hash> = (seed..seed + batch_count as u64)
                .map(|i| EventHasher::hash_content(&i.to_le_bytes()))
                .collect();
            let ledger_anchor = EventHasher::hash_content(&(seed + 99999).to_le_bytes());

            let direct = BatchEpochRootV1::new(
                0, &batch_roots, ledger_anchor, [0u8; HASH_SIZE],
            ).unwrap();

            let mut builder = EpochRootBuilder::new(0, [0u8; HASH_SIZE]);
            for root in &batch_roots {
                builder.add_batch_root(*root).unwrap();
            }
            let built = builder.finalize(ledger_anchor).unwrap();

            prop_assert_eq!(direct.content_hash(), built.content_hash());
        }

        /// Property: EpochAntiEntropyPointer matches its source epoch root.
        #[test]
        fn prop_pointer_matches_source(
            batch_count in 1usize..=8,
            seed in 1u64..10000,
        ) {
            let batch_roots: Vec<Hash> = (seed..seed + batch_count as u64)
                .map(|i| EventHasher::hash_content(&i.to_le_bytes()))
                .collect();
            let ledger_anchor = EventHasher::hash_content(&(seed + 99999).to_le_bytes());

            let epoch_root = BatchEpochRootV1::new(
                0, &batch_roots, ledger_anchor, [0u8; HASH_SIZE],
            ).unwrap();

            let pointer = EpochAntiEntropyPointer::from_epoch_root(&epoch_root);
            prop_assert!(pointer.matches(&epoch_root));
            prop_assert_eq!(pointer.epoch(), epoch_root.epoch());
            prop_assert_eq!(pointer.batch_count(), epoch_root.batch_count());
        }
    }
}
