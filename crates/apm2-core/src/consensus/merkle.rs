// AGENT-AUTHORED
//! Merkle tree implementation for anti-entropy synchronization.
//!
//! This module provides a BLAKE3-based Merkle tree implementation optimized
//! for efficient anti-entropy reconciliation between peers. The tree enables
//! `O(log n)` identification of divergent event ranges.
//!
//! # Protocol Overview
//!
//! 1. Peers exchange root digests
//! 2. On mismatch, they recursively compare subtree digests
//! 3. Divergent ranges are identified in `O(log n)` comparisons
//! 4. Missing events are pulled from peer
//!
//! # Security Properties
//!
//! - **Integrity**: BLAKE3 provides collision resistance for tree nodes
//! - **`DoS` Prevention**: Bounded tree depth and node count prevent memory
//!   exhaustion
//! - **Bounded Storage**: Tree construction respects CTR-1303 limits
//!
//! # References
//!
//! - RFC-0014: Distributed Consensus and Replication Layer (DD-0006)
//! - Merkle, Ralph C. "A Digital Signature Based on a Conventional Encryption
//!   Function." CRYPTO 1987.

use std::collections::VecDeque;

use thiserror::Error;

use crate::crypto::{EventHasher, HASH_SIZE, Hash};

// ============================================================================
// Constants
// ============================================================================

/// Maximum number of leaves in a Merkle tree.
///
/// Bounded to prevent denial-of-service via memory exhaustion. 2^20 leaves
/// supports approximately 1 million events per sync range.
pub const MAX_TREE_LEAVES: usize = 1 << 20; // 1,048,576

/// Maximum tree depth.
///
/// `log2(MAX_TREE_LEAVES)` = 20, plus 1 for the root level.
pub const MAX_TREE_DEPTH: usize = 21;

/// Maximum number of nodes in a proof.
///
/// A proof for any leaf in a tree of `MAX_TREE_DEPTH` requires at most
/// `MAX_TREE_DEPTH` - 1 sibling hashes.
pub const MAX_PROOF_NODES: usize = MAX_TREE_DEPTH;

/// Empty hash (32 zero bytes) used for padding.
pub const EMPTY_HASH: Hash = [0u8; HASH_SIZE];

/// Domain separator for internal node hashing.
const INTERNAL_NODE_PREFIX: &[u8] = b"merkle:internal:";

/// Domain separator for leaf node hashing.
const LEAF_NODE_PREFIX: &[u8] = b"merkle:leaf:";

// ============================================================================
// Errors
// ============================================================================

/// Errors that can occur during Merkle tree operations.
#[derive(Debug, Error)]
pub enum MerkleError {
    /// Too many leaves in tree construction.
    #[error("too many leaves: {count} exceeds limit of {}", MAX_TREE_LEAVES)]
    TooManyLeaves {
        /// Number of leaves provided.
        count: usize,
    },

    /// Empty tree (no leaves provided).
    #[error("cannot construct tree with no leaves")]
    EmptyTree,

    /// Invalid proof structure.
    #[error("invalid proof: {0}")]
    InvalidProof(String),

    /// Proof verification failed.
    #[error("proof verification failed: computed {computed}, expected {expected}")]
    ProofVerificationFailed {
        /// The computed root hash.
        computed: String,
        /// The expected root hash.
        expected: String,
    },

    /// Invalid range specification.
    #[error("invalid range: start {start} must be less than end {end}")]
    InvalidRange {
        /// Range start index.
        start: usize,
        /// Range end index.
        end: usize,
    },

    /// Index out of bounds.
    #[error("index {index} out of bounds for tree with {tree_size} leaves")]
    IndexOutOfBounds {
        /// The requested index.
        index: usize,
        /// The tree size.
        tree_size: usize,
    },

    /// Proof path does not match claimed leaf index.
    ///
    /// The proof path encodes the position of the leaf in the tree through
    /// the direction bits. If the claimed `leaf_index` doesn't match the
    /// position encoded in the proof path, the proof is invalid.
    #[error("leaf index mismatch: claimed {claimed}, computed from path {computed}")]
    LeafIndexMismatch {
        /// The claimed leaf index in the proof.
        claimed: usize,
        /// The index computed from the proof path.
        computed: usize,
    },
}

// ============================================================================
// Merkle Tree Types
// ============================================================================

/// A Merkle tree node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleNode {
    /// The hash of this node.
    pub hash: Hash,
    /// Range of leaf indices covered by this subtree [start, end).
    pub range: (usize, usize),
}

/// A complete Merkle tree.
///
/// The tree is stored as a vector of levels, where level 0 contains leaves
/// and the last level contains the root. Each level has half the nodes of
/// the previous level (rounded up for odd counts).
#[derive(Debug, Clone)]
pub struct MerkleTree {
    /// Tree levels from leaves (index 0) to root (last index).
    levels: Vec<Vec<Hash>>,
    /// Number of original leaves.
    leaf_count: usize,
}

/// A Merkle proof for a leaf or range.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleProof {
    /// Sibling hashes from leaf to root.
    /// Each entry is `(sibling_hash, is_left)` where `is_left` indicates if the
    /// sibling is on the left side.
    pub path: Vec<(Hash, bool)>,
    /// The leaf hash being proven.
    pub leaf_hash: Hash,
    /// Index of the leaf in the tree.
    pub leaf_index: usize,
}

/// A range digest for comparing subtrees.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RangeDigest {
    /// The hash covering this range.
    pub hash: Hash,
    /// Range of leaf indices [start, end).
    pub range: (usize, usize),
    /// Depth in the tree (0 = root level for this range).
    pub depth: usize,
}

/// Result of comparing two trees to find divergent ranges.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DivergentRange {
    /// Start index (inclusive).
    pub start: usize,
    /// End index (exclusive).
    pub end: usize,
}

// ============================================================================
// Merkle Tree Implementation
// ============================================================================

impl MerkleTree {
    /// Constructs a new Merkle tree from event hashes.
    ///
    /// # Arguments
    ///
    /// * `leaves` - Iterator of event hashes to include as leaves.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - No leaves are provided
    /// - More than `MAX_TREE_LEAVES` leaves are provided
    ///
    /// # Panics
    ///
    /// This method will not panic under normal conditions. The internal
    /// `expect` call is guarded by the loop invariant that ensures levels
    /// is never empty.
    ///
    /// # Example
    ///
    /// ```rust
    /// use apm2_core::consensus::merkle::MerkleTree;
    /// use apm2_core::crypto::EventHasher;
    ///
    /// let hashes: Vec<_> = (0..10)
    ///     .map(|i| EventHasher::hash_content(&[i as u8]))
    ///     .collect();
    ///
    /// let tree = MerkleTree::new(hashes.iter().copied()).unwrap();
    /// assert_eq!(tree.leaf_count(), 10);
    /// ```
    pub fn new(leaves: impl IntoIterator<Item = Hash>) -> Result<Self, MerkleError> {
        let leaves: Vec<Hash> = leaves.into_iter().collect();

        if leaves.is_empty() {
            return Err(MerkleError::EmptyTree);
        }

        if leaves.len() > MAX_TREE_LEAVES {
            return Err(MerkleError::TooManyLeaves {
                count: leaves.len(),
            });
        }

        let leaf_count = leaves.len();

        // Hash leaves with domain separator
        let leaf_hashes: Vec<Hash> = leaves.iter().map(hash_leaf).collect();

        // Build tree levels from bottom up
        let mut levels: Vec<Vec<Hash>> = vec![leaf_hashes];

        while levels.last().is_some_and(|l: &Vec<Hash>| l.len() > 1) {
            // The condition above guarantees levels.last() is Some
            let Some(prev_level) = levels.last() else {
                // This branch is unreachable due to the while condition,
                // but we handle it gracefully instead of using expect()
                break;
            };
            let mut next_level: Vec<Hash> = Vec::with_capacity(prev_level.len().div_ceil(2));

            for chunk in prev_level.chunks(2) {
                let hash: Hash = if chunk.len() == 2 {
                    hash_internal(&chunk[0], &chunk[1])
                } else {
                    // Odd node: promote with empty sibling
                    hash_internal(&chunk[0], &EMPTY_HASH)
                };
                next_level.push(hash);
            }

            levels.push(next_level);
        }

        Ok(Self { levels, leaf_count })
    }

    /// Returns the root hash of the tree.
    #[must_use]
    pub fn root(&self) -> Hash {
        self.levels
            .last()
            .and_then(|l: &Vec<Hash>| l.first())
            .copied()
            .unwrap_or(EMPTY_HASH)
    }

    /// Returns the number of leaves in the tree.
    #[must_use]
    pub const fn leaf_count(&self) -> usize {
        self.leaf_count
    }

    /// Returns the number of levels in the tree.
    #[must_use]
    pub fn depth(&self) -> usize {
        self.levels.len()
    }

    /// Returns the hash at a specific level and index.
    ///
    /// Level 0 is the leaf level, and the last level contains the root.
    #[must_use]
    pub fn hash_at(&self, level: usize, index: usize) -> Option<Hash> {
        self.levels
            .get(level)
            .and_then(|l: &Vec<Hash>| l.get(index))
            .copied()
    }

    /// Generates a Merkle proof for a specific leaf index.
    ///
    /// # Errors
    ///
    /// Returns an error if the index is out of bounds.
    pub fn proof_for(&self, leaf_index: usize) -> Result<MerkleProof, MerkleError> {
        if leaf_index >= self.leaf_count {
            return Err(MerkleError::IndexOutOfBounds {
                index: leaf_index,
                tree_size: self.leaf_count,
            });
        }

        let leaf_hash = self.levels[0][leaf_index];
        let mut path = Vec::with_capacity(self.levels.len() - 1);
        let mut current_index = leaf_index;

        for level in self.levels.iter().take(self.levels.len() - 1) {
            let is_right = current_index % 2 == 1;
            let sibling_index = if is_right {
                current_index - 1
            } else {
                current_index + 1
            };

            let sibling_hash: Hash = level.get(sibling_index).copied().unwrap_or(EMPTY_HASH);
            path.push((sibling_hash, is_right));

            current_index /= 2;
        }

        Ok(MerkleProof {
            path,
            leaf_hash,
            leaf_index,
        })
    }

    /// Gets the digest for a range of leaves.
    ///
    /// Returns the smallest subtree hash that covers the entire range.
    /// This is used for efficient range comparison during anti-entropy sync.
    ///
    /// # Arguments
    ///
    /// * `start` - Start index (inclusive).
    /// * `end` - End index (exclusive).
    ///
    /// # Errors
    ///
    /// Returns an error if the range is invalid or out of bounds.
    pub fn range_digest(&self, start: usize, end: usize) -> Result<RangeDigest, MerkleError> {
        if start >= end {
            return Err(MerkleError::InvalidRange { start, end });
        }

        if end > self.leaf_count {
            return Err(MerkleError::IndexOutOfBounds {
                index: end - 1,
                tree_size: self.leaf_count,
            });
        }

        // Find the smallest subtree covering [start, end)
        // Walk up from leaf level until we find a node that covers the range
        let mut level = 0;
        let mut node_start = start;
        let mut node_end = end;

        while level < self.levels.len() - 1 {
            // Check if current level has a single node covering our range
            let node_size = 1 << level;
            let aligned_start = (node_start / node_size) * node_size;
            let aligned_end = aligned_start + node_size;

            if aligned_start <= start && aligned_end >= end && node_start == node_end - 1 {
                // Found a single node covering the range
                break;
            }

            // Move to parent level
            node_start /= 2;
            node_end = node_end.div_ceil(2);
            level += 1;
        }

        // If we couldn't find a single covering node, use root
        if level >= self.levels.len() - 1 {
            return Ok(RangeDigest {
                hash: self.root(),
                range: (0, self.leaf_count),
                depth: self.levels.len() - 1,
            });
        }

        let hash = self.levels[level][node_start];
        let node_size = 1 << level;
        let range_start = node_start * node_size;
        let range_end = (range_start + node_size).min(self.leaf_count);

        Ok(RangeDigest {
            hash,
            range: (range_start, range_end),
            depth: level,
        })
    }

    /// Gets digests for all subtrees at a given depth.
    ///
    /// This is used for progressive comparison: start at depth 0 (root),
    /// and on mismatch, compare children at depth 1, and so on.
    ///
    /// # Arguments
    ///
    /// * `depth` - Tree depth (0 = leaves, max = root).
    ///
    /// # Returns
    ///
    /// Vector of range digests at the specified depth. Returns empty if depth
    /// exceeds tree height.
    #[must_use]
    pub fn digests_at_depth(&self, depth: usize) -> Vec<RangeDigest> {
        // Map depth (0=leaves, max=root) to level index (0=leaves, max=root)
        if depth >= self.levels.len() {
            return vec![];
        }

        let level = &self.levels[depth];
        let node_size = 1 << depth;

        level
            .iter()
            .enumerate()
            .map(|(i, hash): (usize, &Hash)| {
                let range_start: usize = i * node_size;
                let range_end: usize = (range_start + node_size).min(self.leaf_count);
                RangeDigest {
                    hash: *hash,
                    range: (range_start, range_end),
                    depth,
                }
            })
            .collect()
    }

    /// Compares this tree with another tree to find divergent ranges.
    ///
    /// Uses a top-down BFS approach: compare roots, then iteratively compare
    /// children of mismatched nodes. Returns the minimal set of leaf ranges
    /// where the trees differ.
    ///
    /// # Arguments
    ///
    /// * `other` - The other tree to compare against.
    ///
    /// # Returns
    ///
    /// Vector of divergent ranges. Empty if trees are identical.
    ///
    /// # Memory Characteristics
    ///
    /// In the worst case (completely divergent trees), this function may
    /// return up to `leaf_count` individual ranges before merging. After
    /// merging adjacent ranges, the result is typically much smaller.
    ///
    /// For a tree with `MAX_TREE_LEAVES` (1M leaves), worst-case memory
    /// usage for the result vector is approximately:
    /// - Before merge: ~16 MB (1M ranges * 16 bytes each)
    /// - After merge: typically 1-2 ranges for fully divergent trees
    ///
    /// The BFS queue may temporarily hold up to `O(leaf_count)` nodes in
    /// the worst case of all leaves diverging.
    ///
    /// Callers should use `AntiEntropyEngine::find_divergences()` which
    /// enforces `MAX_DIVERGENT_RANGES` to bound the returned result.
    #[must_use]
    pub fn find_divergent_ranges(&self, other: &Self) -> Vec<DivergentRange> {
        let mut divergent = Vec::new();

        // Handle different tree sizes
        if self.leaf_count != other.leaf_count {
            // Trees have different sizes - mark all as divergent
            let max_count = self.leaf_count.max(other.leaf_count);
            divergent.push(DivergentRange {
                start: 0,
                end: max_count,
            });
            return divergent;
        }

        // Same size - compare from root down
        if self.root() == other.root() {
            return divergent;
        }

        // BFS from root to find divergent leaves
        let mut queue: VecDeque<(usize, usize)> = VecDeque::new();
        // Start at root level
        let root_level = self.levels.len() - 1;
        queue.push_back((root_level, 0));

        while let Some((level, index)) = queue.pop_front() {
            if level == 0 {
                // Reached leaf level - this is a divergent leaf
                divergent.push(DivergentRange {
                    start: index,
                    end: index + 1,
                });
                continue;
            }

            // Compare children
            let left_idx = index * 2;
            let right_idx = index * 2 + 1;
            let child_level = level - 1;

            let self_left = self.hash_at(child_level, left_idx);
            let other_left = other.hash_at(child_level, left_idx);

            if self_left != other_left {
                queue.push_back((child_level, left_idx));
            }

            let self_right = self.hash_at(child_level, right_idx);
            let other_right = other.hash_at(child_level, right_idx);

            if self_right != other_right {
                queue.push_back((child_level, right_idx));
            }
        }

        // Merge adjacent ranges
        merge_ranges(&mut divergent);

        divergent
    }
}

impl MerkleProof {
    /// Verifies this proof against a root hash.
    ///
    /// This method verifies both:
    /// 1. That the proof path computes to the expected root hash
    /// 2. That the claimed `leaf_index` matches the position encoded in the
    ///    proof path
    ///
    /// # Arguments
    ///
    /// * `root` - The expected root hash.
    ///
    /// # Errors
    ///
    /// Returns `MerkleError::LeafIndexMismatch` if the claimed `leaf_index`
    /// doesn't match the index computed from the proof path direction bits.
    ///
    /// Returns `MerkleError::ProofVerificationFailed` if the computed root
    /// doesn't match the expected root.
    ///
    /// # Security
    ///
    /// This prevents an attacker from providing a valid proof for one leaf
    /// position while claiming it proves a different position. The proof
    /// path encodes the leaf position through the `is_right` direction
    /// bits.
    pub fn verify(&self, root: &Hash) -> Result<(), MerkleError> {
        // First, verify that the claimed leaf_index matches the proof path.
        // The proof path encodes the position through the is_right bits:
        // - If is_right is true, the current node is on the right (odd index)
        // - If is_right is false, the current node is on the left (even index)
        // Reconstruct the index from the path (LSB to MSB).
        let computed_index = self.compute_leaf_index();
        if computed_index != self.leaf_index {
            return Err(MerkleError::LeafIndexMismatch {
                claimed: self.leaf_index,
                computed: computed_index,
            });
        }

        // Then verify the hash chain computes to the expected root
        let computed = self.compute_root();

        if &computed != root {
            return Err(MerkleError::ProofVerificationFailed {
                computed: hex_encode(&computed),
                expected: hex_encode(root),
            });
        }

        Ok(())
    }

    /// Computes the leaf index from the proof path direction bits.
    ///
    /// The proof path encodes the leaf position through the `is_right` bits.
    /// Each level contributes one bit to the index, starting from the LSB.
    #[must_use]
    pub fn compute_leaf_index(&self) -> usize {
        let mut index = 0usize;
        for (level, (_, is_right)) in self.path.iter().enumerate() {
            if *is_right {
                // Current node is on the right, so this bit is 1
                index |= 1 << level;
            }
        }
        index
    }

    /// Computes the root hash from this proof.
    #[must_use]
    pub fn compute_root(&self) -> Hash {
        let mut current = self.leaf_hash;

        for (sibling, is_right) in &self.path {
            if *is_right {
                // Current node is on the right, sibling is on the left
                current = hash_internal(sibling, &current);
            } else {
                // Current node is on the left, sibling is on the right
                current = hash_internal(&current, sibling);
            }
        }

        current
    }

    /// Returns the number of nodes in the proof path.
    #[must_use]
    pub fn path_len(&self) -> usize {
        self.path.len()
    }
}

// ============================================================================
// Hash Functions
// ============================================================================

/// Hashes a leaf node with domain separation.
#[must_use]
pub fn hash_leaf(data: &Hash) -> Hash {
    let mut content = Vec::with_capacity(LEAF_NODE_PREFIX.len() + HASH_SIZE);
    content.extend_from_slice(LEAF_NODE_PREFIX);
    content.extend_from_slice(data);
    EventHasher::hash_content(&content)
}

/// Hashes an internal node from two children with domain separation.
#[must_use]
pub fn hash_internal(left: &Hash, right: &Hash) -> Hash {
    let mut content = Vec::with_capacity(INTERNAL_NODE_PREFIX.len() + 2 * HASH_SIZE);
    content.extend_from_slice(INTERNAL_NODE_PREFIX);
    content.extend_from_slice(left);
    content.extend_from_slice(right);
    EventHasher::hash_content(&content)
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Merges adjacent divergent ranges.
fn merge_ranges(ranges: &mut Vec<DivergentRange>) {
    if ranges.len() <= 1 {
        return;
    }

    ranges.sort_by_key(|r| r.start);

    let mut merged = Vec::with_capacity(ranges.len());
    let mut current = ranges[0].clone();

    for range in ranges.iter().skip(1) {
        if range.start <= current.end {
            // Overlapping or adjacent - merge
            current.end = current.end.max(range.end);
        } else {
            // Gap - push current and start new
            merged.push(current);
            current = range.clone();
        }
    }
    merged.push(current);

    *ranges = merged;
}

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
mod tck_00191_unit_tests {
    use super::*;

    fn test_hashes(count: usize) -> Vec<Hash> {
        (0..count)
            .map(|i| EventHasher::hash_content(&(i as u64).to_le_bytes()))
            .collect()
    }

    #[test]
    fn test_merkle_tree_construction() {
        let hashes = test_hashes(8);
        let tree = MerkleTree::new(hashes.iter().copied()).unwrap();

        assert_eq!(tree.leaf_count(), 8);
        assert_eq!(tree.depth(), 4); // 8 leaves -> 4 -> 2 -> 1 (root)
    }

    #[test]
    fn test_merkle_tree_single_leaf() {
        let hashes = test_hashes(1);
        let tree = MerkleTree::new(hashes.iter().copied()).unwrap();

        assert_eq!(tree.leaf_count(), 1);
        assert_eq!(tree.depth(), 1);
    }

    #[test]
    fn test_merkle_tree_odd_leaves() {
        let hashes = test_hashes(7);
        let tree = MerkleTree::new(hashes.iter().copied()).unwrap();

        assert_eq!(tree.leaf_count(), 7);
        // 7 -> 4 -> 2 -> 1
        assert_eq!(tree.depth(), 4);
    }

    #[test]
    fn test_merkle_tree_empty_rejected() {
        let result = MerkleTree::new(std::iter::empty::<Hash>());
        assert!(matches!(result, Err(MerkleError::EmptyTree)));
    }

    #[test]
    fn test_merkle_tree_root_deterministic() {
        let hashes = test_hashes(10);
        let tree1 = MerkleTree::new(hashes.iter().copied()).unwrap();
        let tree2 = MerkleTree::new(hashes.iter().copied()).unwrap();

        assert_eq!(tree1.root(), tree2.root());
    }

    #[test]
    fn test_merkle_tree_root_different_for_different_leaves() {
        let hashes1 = test_hashes(10);
        let mut hashes2 = hashes1.clone();
        hashes2[5] = EventHasher::hash_content(b"different");

        let tree1 = MerkleTree::new(hashes1.iter().copied()).unwrap();
        let tree2 = MerkleTree::new(hashes2.iter().copied()).unwrap();

        assert_ne!(tree1.root(), tree2.root());
    }

    #[test]
    fn test_merkle_proof_generation() {
        let hashes = test_hashes(8);
        let tree = MerkleTree::new(hashes.iter().copied()).unwrap();

        for i in 0..8 {
            let proof = tree.proof_for(i).unwrap();
            assert_eq!(proof.leaf_index, i);
            assert_eq!(proof.path_len(), 3); // log2(8) = 3
        }
    }

    #[test]
    fn test_merkle_proof_verification() {
        let hashes = test_hashes(16);
        let tree = MerkleTree::new(hashes.iter().copied()).unwrap();
        let root = tree.root();

        for i in 0..16 {
            let proof = tree.proof_for(i).unwrap();
            assert!(proof.verify(&root).is_ok());
        }
    }

    #[test]
    fn test_merkle_proof_invalid_root() {
        let hashes = test_hashes(8);
        let tree = MerkleTree::new(hashes.iter().copied()).unwrap();

        let proof = tree.proof_for(0).unwrap();
        let wrong_root = [0xFFu8; 32];

        let result = proof.verify(&wrong_root);
        assert!(matches!(
            result,
            Err(MerkleError::ProofVerificationFailed { .. })
        ));
    }

    #[test]
    fn test_merkle_proof_out_of_bounds() {
        let hashes = test_hashes(8);
        let tree = MerkleTree::new(hashes.iter().copied()).unwrap();

        let result = tree.proof_for(8);
        assert!(matches!(result, Err(MerkleError::IndexOutOfBounds { .. })));
    }

    #[test]
    fn test_find_divergent_ranges_identical() {
        let hashes = test_hashes(16);
        let tree1 = MerkleTree::new(hashes.iter().copied()).unwrap();
        let tree2 = MerkleTree::new(hashes.iter().copied()).unwrap();

        let divergent = tree1.find_divergent_ranges(&tree2);
        assert!(divergent.is_empty());
    }

    #[test]
    fn test_find_divergent_ranges_single_diff() {
        let hashes1 = test_hashes(8);
        let mut hashes2 = hashes1.clone();
        hashes2[3] = EventHasher::hash_content(b"modified");

        let tree1 = MerkleTree::new(hashes1.iter().copied()).unwrap();
        let tree2 = MerkleTree::new(hashes2.iter().copied()).unwrap();

        let divergent = tree1.find_divergent_ranges(&tree2);
        assert_eq!(divergent.len(), 1);
        assert_eq!(divergent[0].start, 3);
        assert_eq!(divergent[0].end, 4);
    }

    #[test]
    fn test_find_divergent_ranges_multiple_diff() {
        let hashes1 = test_hashes(16);
        let mut hashes2 = hashes1.clone();
        hashes2[2] = EventHasher::hash_content(b"mod1");
        hashes2[10] = EventHasher::hash_content(b"mod2");

        let tree1 = MerkleTree::new(hashes1.iter().copied()).unwrap();
        let tree2 = MerkleTree::new(hashes2.iter().copied()).unwrap();

        let divergent = tree1.find_divergent_ranges(&tree2);
        assert_eq!(divergent.len(), 2);
        assert!(divergent.iter().any(|r| r.start == 2 && r.end == 3));
        assert!(divergent.iter().any(|r| r.start == 10 && r.end == 11));
    }

    #[test]
    fn test_find_divergent_ranges_adjacent_merged() {
        let hashes1 = test_hashes(8);
        let mut hashes2 = hashes1.clone();
        hashes2[2] = EventHasher::hash_content(b"mod1");
        hashes2[3] = EventHasher::hash_content(b"mod2");

        let tree1 = MerkleTree::new(hashes1.iter().copied()).unwrap();
        let tree2 = MerkleTree::new(hashes2.iter().copied()).unwrap();

        let divergent = tree1.find_divergent_ranges(&tree2);
        // Should be merged into single range [2, 4)
        assert_eq!(divergent.len(), 1);
        assert_eq!(divergent[0].start, 2);
        assert_eq!(divergent[0].end, 4);
    }

    #[test]
    fn test_find_divergent_ranges_different_sizes() {
        let hashes1 = test_hashes(8);
        let hashes2 = test_hashes(16);

        let tree1 = MerkleTree::new(hashes1.iter().copied()).unwrap();
        let tree2 = MerkleTree::new(hashes2.iter().copied()).unwrap();

        let divergent = tree1.find_divergent_ranges(&tree2);
        // Entire range marked as divergent
        assert_eq!(divergent.len(), 1);
        assert_eq!(divergent[0].start, 0);
        assert_eq!(divergent[0].end, 16);
    }

    #[test]
    fn test_digests_at_depth() {
        let hashes = test_hashes(8);
        let tree = MerkleTree::new(hashes.iter().copied()).unwrap();

        // Level 0: 8 leaves
        let level0 = tree.digests_at_depth(0);
        assert_eq!(level0.len(), 8);
        for (i, digest) in level0.iter().enumerate() {
            assert_eq!(digest.range, (i, i + 1));
            assert_eq!(digest.depth, 0);
        }

        // Level 1: 4 nodes
        let level1 = tree.digests_at_depth(1);
        assert_eq!(level1.len(), 4);
        for (i, digest) in level1.iter().enumerate() {
            assert_eq!(digest.range, (i * 2, i * 2 + 2));
            assert_eq!(digest.depth, 1);
        }

        // Level 3: 1 node (root)
        let level3 = tree.digests_at_depth(3);
        assert_eq!(level3.len(), 1);
        assert_eq!(level3[0].range, (0, 8));
        assert_eq!(level3[0].hash, tree.root());
    }

    #[test]
    fn test_range_digest() {
        let hashes = test_hashes(8);
        let tree = MerkleTree::new(hashes.iter().copied()).unwrap();

        // Range [0, 8) should return root
        let digest = tree.range_digest(0, 8).unwrap();
        assert_eq!(digest.hash, tree.root());
        assert_eq!(digest.range, (0, 8));
    }

    #[test]
    fn test_range_digest_invalid() {
        let hashes = test_hashes(8);
        let tree = MerkleTree::new(hashes.iter().copied()).unwrap();

        // Invalid range: start >= end
        assert!(matches!(
            tree.range_digest(5, 3),
            Err(MerkleError::InvalidRange { .. })
        ));

        // Out of bounds
        assert!(matches!(
            tree.range_digest(0, 16),
            Err(MerkleError::IndexOutOfBounds { .. })
        ));
    }

    #[test]
    fn test_hash_leaf_domain_separation() {
        let data = [1u8; 32];
        let leaf_hash = hash_leaf(&data);
        let internal_hash = hash_internal(&data, &EMPTY_HASH);

        // Different domain separators should produce different hashes
        assert_ne!(leaf_hash, internal_hash);
    }

    #[test]
    fn test_hash_internal_order_matters() {
        let left = EventHasher::hash_content(b"left");
        let right = EventHasher::hash_content(b"right");

        let hash1 = hash_internal(&left, &right);
        let hash2 = hash_internal(&right, &left);

        // Order should matter for reproducibility
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_large_tree_bounded() {
        // Verify we can construct trees up to the limit
        let hashes = test_hashes(1024);
        let tree = MerkleTree::new(hashes.iter().copied()).unwrap();

        assert_eq!(tree.leaf_count(), 1024);
        // 1024 = 2^10, so depth should be 11
        assert_eq!(tree.depth(), 11);
    }

    #[test]
    fn test_proof_for_large_tree() {
        let hashes = test_hashes(1000);
        let tree = MerkleTree::new(hashes.iter().copied()).unwrap();
        let root = tree.root();

        // Verify proofs for several indices
        for i in [0, 100, 500, 999] {
            let proof = tree.proof_for(i).unwrap();
            assert!(proof.verify(&root).is_ok());
        }
    }

    #[test]
    fn test_compute_leaf_index_from_proof() {
        let hashes = test_hashes(16);
        let tree = MerkleTree::new(hashes.iter().copied()).unwrap();

        // Verify compute_leaf_index matches for all leaves
        for i in 0..16 {
            let proof = tree.proof_for(i).unwrap();
            assert_eq!(
                proof.compute_leaf_index(),
                i,
                "computed index should match for leaf {i}"
            );
        }
    }

    #[test]
    fn test_merkle_proof_index_verification_prevents_spoofing() {
        // SECURITY TEST: Verify that a proof for one index cannot be used
        // to claim a different index.
        let hashes = test_hashes(8);
        let tree = MerkleTree::new(hashes.iter().copied()).unwrap();
        let root = tree.root();

        // Get a valid proof for index 3
        let mut proof = tree.proof_for(3).unwrap();
        assert!(proof.verify(&root).is_ok());

        // Now try to spoof by claiming this proof is for index 5
        proof.leaf_index = 5;

        // Verification should fail with LeafIndexMismatch
        let result = proof.verify(&root);
        assert!(
            matches!(
                result,
                Err(MerkleError::LeafIndexMismatch {
                    claimed: 5,
                    computed: 3
                })
            ),
            "proof with spoofed index should fail with LeafIndexMismatch, got: {result:?}"
        );
    }

    #[test]
    fn test_merkle_proof_index_verification_all_indices() {
        // Verify index verification works for all possible index spoofing attempts
        let hashes = test_hashes(8);
        let tree = MerkleTree::new(hashes.iter().copied()).unwrap();
        let root = tree.root();

        for real_index in 0..8 {
            let mut proof = tree.proof_for(real_index).unwrap();

            // Try to claim every other index
            for claimed_index in 0..8 {
                proof.leaf_index = claimed_index;
                let result = proof.verify(&root);

                if claimed_index == real_index {
                    // Should succeed for the correct index
                    assert!(
                        result.is_ok(),
                        "proof for {real_index} should verify as {claimed_index}"
                    );
                } else {
                    // Should fail for incorrect indices
                    assert!(
                        matches!(result, Err(MerkleError::LeafIndexMismatch { .. })),
                        "proof for {real_index} claimed as {claimed_index} should fail, got: {result:?}"
                    );
                }
            }
        }
    }
}
