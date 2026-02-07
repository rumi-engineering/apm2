// AGENT-AUTHORED
//! Transcript chain binding for Agent Acceptance Testing (AAT).
//!
//! This module provides types for binding transcript chunks to AAT receipts,
//! ensuring transcript immutability through Merkle root computation.
//!
//! # Overview
//!
//! The transcript chain binding ensures that AAT transcripts are
//! cryptographically linked to the receipt. Any modification of transcript
//! chunks invalidates the chain root, providing tamper-evidence for the entire
//! transcript.
//!
//! # Components
//!
//! - [`TranscriptChunk`]: A single chunk of transcript content with hash
//!   binding
//! - [`AatTranscriptBinding`]: Wrapper for binding transcript chunks to AAT
//!   receipts
//!
//! # Security Model
//!
//! Transcript chain binding provides:
//!
//! - **Immutability**: Once the chain root is computed, any modification to
//!   transcript chunks is detectable
//! - **Completeness**: All chunks are included in the Merkle root computation
//! - **Ordering**: Chunk order is preserved and verified
//! - **Domain Separation**: Uses the `consensus::merkle` module which properly
//!   separates leaf and internal nodes to prevent structural ambiguity attacks
//!
//! # Example
//!
//! ```rust
//! use apm2_core::fac::transcript_binding::{AatTranscriptBinding, TranscriptChunk};
//!
//! // Create transcript chunks
//! let chunks = vec![
//!     TranscriptChunk::try_new(b"First message", 0).unwrap(),
//!     TranscriptChunk::try_new(b"Second message", 1).unwrap(),
//!     TranscriptChunk::try_new(b"Third message", 2).unwrap(),
//! ];
//!
//! // Create binding with run transcript hashes
//! let run_hashes = vec![[0x11; 32], [0x22; 32]];
//! let binding = AatTranscriptBinding::try_new(chunks, run_hashes).unwrap();
//!
//! // Verify chain integrity
//! assert!(binding.validate().is_ok());
//!
//! // Get the chain root for inclusion in AAT receipt
//! let chain_root = binding.transcript_chain_root_hash();
//! ```

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::consensus::merkle::{MerkleError, MerkleTree};
use crate::crypto::{EventHasher, Hash};

// =============================================================================
// Resource Limits
// =============================================================================

/// Maximum number of transcript chunks allowed.
///
/// This prevents denial-of-service attacks via oversized transcript
/// collections. Aligned with `consensus::merkle::MAX_TREE_LEAVES`.
pub const MAX_TRANSCRIPT_CHUNKS: usize = 65536;

/// Maximum size of a single transcript chunk content in bytes.
pub const MAX_CHUNK_CONTENT_BYTES: usize = 1024 * 1024; // 1 MiB

/// Maximum number of run transcript hashes allowed.
pub const MAX_RUN_TRANSCRIPT_HASHES: usize = 256;

// =============================================================================
// Error Types
// =============================================================================

/// Errors that can occur during transcript binding operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TranscriptBindingError {
    /// Chain root hash mismatch during validation.
    #[error("transcript chain root hash mismatch: computed {computed:?}, stored {stored:?}")]
    ChainRootMismatch {
        /// The hash computed from chunks.
        computed: [u8; 32],
        /// The hash stored in the binding.
        stored: [u8; 32],
    },

    /// Transcript chunk content exceeds maximum size.
    #[error("transcript chunk content exceeds max size: {actual} > {max} bytes")]
    ChunkTooLarge {
        /// Actual size of the chunk content.
        actual: usize,
        /// Maximum allowed size.
        max: usize,
    },

    /// Too many transcript chunks.
    #[error("too many transcript chunks: {actual} > {max}")]
    TooManyChunks {
        /// Actual number of chunks.
        actual: usize,
        /// Maximum allowed number.
        max: usize,
    },

    /// Too many run transcript hashes.
    #[error("too many run transcript hashes: {actual} > {max}")]
    TooManyRunHashes {
        /// Actual number of hashes.
        actual: usize,
        /// Maximum allowed number.
        max: usize,
    },

    /// Chunk sequence number is out of order.
    #[error("chunk sequence number out of order: expected {expected}, got {actual}")]
    SequenceOutOfOrder {
        /// Expected sequence number.
        expected: u64,
        /// Actual sequence number found.
        actual: u64,
    },

    /// Merkle tree construction failed.
    #[error("merkle tree error: {0}")]
    MerkleError(String),
}

impl From<MerkleError> for TranscriptBindingError {
    fn from(e: MerkleError) -> Self {
        Self::MerkleError(e.to_string())
    }
}

// =============================================================================
// Wire Format Types (for bounded deserialization)
// =============================================================================

/// Wire format for `TranscriptChunk` with bounded deserialization.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TranscriptChunkWire {
    #[serde(with = "serde_bytes")]
    content_hash: [u8; 32],
    sequence: u64,
    content_size: u64,
}

/// Wire format for `AatTranscriptBinding` with bounded deserialization.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AatTranscriptBindingWire {
    transcript_chunks: Vec<TranscriptChunkWire>,
    #[serde(with = "serde_bytes")]
    transcript_chain_root_hash: [u8; 32],
    #[serde(with = "vec_hash_serde")]
    run_transcript_hashes: Vec<[u8; 32]>,
}

// =============================================================================
// TranscriptChunk
// =============================================================================

/// A single chunk of transcript content.
///
/// Each chunk represents a portion of the AAT transcript (e.g., a single
/// message or tool invocation). Chunks are ordered by sequence number and
/// hashed for integrity verification.
///
/// # Fields
///
/// - `content_hash`: BLAKE3 hash of the chunk content
/// - `sequence`: Monotonically increasing sequence number (0-indexed)
/// - `content_size`: Size of the original content in bytes
///
/// # Invariants
///
/// - Sequence numbers must be monotonically increasing (0, 1, 2, ...)
/// - Content hash must match the hash of the original content
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TranscriptChunk {
    /// BLAKE3 hash of the chunk content.
    content_hash: Hash,

    /// Sequence number for ordering (0-indexed).
    sequence: u64,

    /// Size of the original content in bytes.
    content_size: u64,
}

impl TranscriptChunk {
    /// Attempts to create a new transcript chunk from raw content.
    ///
    /// # Arguments
    ///
    /// * `content` - The raw bytes of the transcript chunk
    /// * `sequence` - The sequence number for ordering
    ///
    /// # Errors
    ///
    /// Returns [`TranscriptBindingError::ChunkTooLarge`] if content exceeds
    /// the maximum size.
    pub fn try_new(content: &[u8], sequence: u64) -> Result<Self, TranscriptBindingError> {
        if content.len() > MAX_CHUNK_CONTENT_BYTES {
            return Err(TranscriptBindingError::ChunkTooLarge {
                actual: content.len(),
                max: MAX_CHUNK_CONTENT_BYTES,
            });
        }

        let content_hash = EventHasher::hash_content(content);

        Ok(Self {
            content_hash,
            sequence,
            content_size: content.len() as u64,
        })
    }

    /// Creates a transcript chunk from a pre-computed hash.
    ///
    /// Use this when the content hash is already known (e.g., when
    /// deserializing or when content is stored externally).
    ///
    /// # Arguments
    ///
    /// * `content_hash` - The pre-computed BLAKE3 hash of the content
    /// * `sequence` - The sequence number for ordering
    /// * `content_size` - The size of the original content in bytes
    #[must_use]
    pub const fn from_hash(content_hash: Hash, sequence: u64, content_size: u64) -> Self {
        Self {
            content_hash,
            sequence,
            content_size,
        }
    }

    /// Returns the content hash.
    #[must_use]
    pub const fn content_hash(&self) -> Hash {
        self.content_hash
    }

    /// Returns the sequence number.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the content size in bytes.
    #[must_use]
    pub const fn content_size(&self) -> u64 {
        self.content_size
    }

    /// Verifies that this chunk's hash matches the given content.
    ///
    /// # Arguments
    ///
    /// * `content` - The raw bytes to verify against the stored hash
    ///
    /// # Returns
    ///
    /// `true` if the content matches the stored hash, `false` otherwise.
    #[must_use]
    pub fn verify_content(&self, content: &[u8]) -> bool {
        let computed_hash = EventHasher::hash_content(content);
        computed_hash == self.content_hash
    }
}

impl Serialize for TranscriptChunk {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        TranscriptChunkWire {
            content_hash: self.content_hash,
            sequence: self.sequence,
            content_size: self.content_size,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for TranscriptChunk {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = TranscriptChunkWire::deserialize(deserializer)?;
        Ok(Self {
            content_hash: wire.content_hash,
            sequence: wire.sequence,
            content_size: wire.content_size,
        })
    }
}

// =============================================================================
// AatTranscriptBinding
// =============================================================================

/// Binding of transcript chunks to an AAT receipt.
///
/// This struct contains the transcript chunks, computes the Merkle root for
/// chain integrity verification, and tracks run-level transcript hashes.
///
/// # Fields
///
/// - `transcript_chunks`: Ordered list of transcript chunks
/// - `transcript_chain_root_hash`: Merkle root computed from chunk hashes
/// - `run_transcript_hashes`: Hashes linking to individual run transcripts
///
/// # Merkle Root Computation
///
/// The chain root is computed using the `consensus::merkle` module which
/// provides domain-separated hashing:
/// - Leaf nodes are hashed with `merkle:leaf:` prefix
/// - Internal nodes are hashed with `merkle:internal:` prefix
///
/// This prevents structural ambiguity attacks (e.g., duplicate leaf attacks).
///
/// For an empty chunk list, the root is the hash of an empty byte array.
/// For a single chunk, the root uses the domain-separated leaf hash.
/// For multiple chunks, a balanced Merkle tree is constructed.
///
/// # Security Model
///
/// The chain root provides:
///
/// - **Completeness**: All chunks contribute to the root
/// - **Ordering**: Chunk order affects the root value
/// - **Tamper-evidence**: Any modification changes the root
/// - **Domain Separation**: Leaf and internal nodes use different prefixes
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AatTranscriptBinding {
    /// Ordered list of transcript chunks.
    transcript_chunks: Vec<TranscriptChunk>,

    /// Merkle root hash of the transcript chain.
    transcript_chain_root_hash: Hash,

    /// Hashes linking to individual run transcripts.
    run_transcript_hashes: Vec<Hash>,
}

/// Custom serde for `Vec<[u8; 32]>` with bounded deserialization.
///
/// Uses a custom visitor that:
/// 1. Limits the number of elements to `MAX_RUN_TRANSCRIPT_HASHES`
/// 2. Enforces exactly 32 bytes per element during read (not after allocation)
mod vec_hash_serde {
    use serde::de::{SeqAccess, Visitor};
    use serde::{Deserializer, Serialize, Serializer};

    use super::MAX_RUN_TRANSCRIPT_HASHES;

    pub fn serialize<S>(hashes: &[[u8; 32]], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Serialize as array of fixed-size byte arrays
        let vec_of_vecs: Vec<&[u8]> = hashes.iter().map(<[u8; 32]>::as_slice).collect();
        vec_of_vecs.serialize(serializer)
    }

    struct HashVecVisitor;

    impl<'de> Visitor<'de> for HashVecVisitor {
        type Value = Vec<[u8; 32]>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(
                formatter,
                "a sequence of at most {MAX_RUN_TRANSCRIPT_HASHES} 32-byte hashes",
            )
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            // Pre-allocate with a reasonable hint, but cap at max
            let size_hint = seq.size_hint().unwrap_or(0).min(MAX_RUN_TRANSCRIPT_HASHES);
            let mut hashes = Vec::with_capacity(size_hint);

            while let Some(bytes) = seq.next_element::<serde_bytes::ByteBuf>()? {
                // Enforce count limit BEFORE allocation
                if hashes.len() >= MAX_RUN_TRANSCRIPT_HASHES {
                    return Err(serde::de::Error::custom(format!(
                        "too many run transcript hashes: > {MAX_RUN_TRANSCRIPT_HASHES}"
                    )));
                }

                // Enforce 32-byte constraint
                if bytes.len() != 32 {
                    return Err(serde::de::Error::custom(format!(
                        "expected 32 bytes, got {}",
                        bytes.len()
                    )));
                }

                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                hashes.push(arr);
            }

            Ok(hashes)
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<[u8; 32]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(HashVecVisitor)
    }
}

impl AatTranscriptBinding {
    /// Attempts to create a new transcript binding from chunks and run hashes.
    ///
    /// The chain root hash is computed automatically from the provided chunks
    /// using the domain-separated Merkle tree from `consensus::merkle`.
    ///
    /// # Errors
    ///
    /// Returns [`TranscriptBindingError::TooManyChunks`] if the number of
    /// chunks exceeds [`MAX_TRANSCRIPT_CHUNKS`].
    ///
    /// Returns [`TranscriptBindingError::TooManyRunHashes`] if the number of
    /// run hashes exceeds [`MAX_RUN_TRANSCRIPT_HASHES`].
    pub fn try_new(
        transcript_chunks: Vec<TranscriptChunk>,
        run_transcript_hashes: Vec<Hash>,
    ) -> Result<Self, TranscriptBindingError> {
        if transcript_chunks.len() > MAX_TRANSCRIPT_CHUNKS {
            return Err(TranscriptBindingError::TooManyChunks {
                actual: transcript_chunks.len(),
                max: MAX_TRANSCRIPT_CHUNKS,
            });
        }

        if run_transcript_hashes.len() > MAX_RUN_TRANSCRIPT_HASHES {
            return Err(TranscriptBindingError::TooManyRunHashes {
                actual: run_transcript_hashes.len(),
                max: MAX_RUN_TRANSCRIPT_HASHES,
            });
        }

        let transcript_chain_root_hash = Self::compute_chain_root_from_chunks(&transcript_chunks)?;

        Ok(Self {
            transcript_chunks,
            transcript_chain_root_hash,
            run_transcript_hashes,
        })
    }

    /// Creates a transcript binding from pre-computed values.
    ///
    /// Use this when deserializing or when values are already known. The caller
    /// is responsible for ensuring the chain root hash is valid by calling
    /// `validate()` after construction.
    ///
    /// # Arguments
    ///
    /// * `transcript_chunks` - Ordered list of transcript chunks
    /// * `transcript_chain_root_hash` - Pre-computed Merkle root hash
    /// * `run_transcript_hashes` - Hashes linking to individual run transcripts
    #[must_use]
    pub const fn from_parts(
        transcript_chunks: Vec<TranscriptChunk>,
        transcript_chain_root_hash: Hash,
        run_transcript_hashes: Vec<Hash>,
    ) -> Self {
        Self {
            transcript_chunks,
            transcript_chain_root_hash,
            run_transcript_hashes,
        }
    }

    /// Returns the transcript chunks.
    #[must_use]
    pub fn transcript_chunks(&self) -> &[TranscriptChunk] {
        &self.transcript_chunks
    }

    /// Returns the transcript chain root hash.
    #[must_use]
    pub const fn transcript_chain_root_hash(&self) -> Hash {
        self.transcript_chain_root_hash
    }

    /// Returns the run transcript hashes.
    #[must_use]
    pub fn run_transcript_hashes(&self) -> &[Hash] {
        &self.run_transcript_hashes
    }

    /// Returns the number of transcript chunks.
    #[must_use]
    pub fn chunk_count(&self) -> usize {
        self.transcript_chunks.len()
    }

    /// Returns the total content size across all chunks.
    #[must_use]
    pub fn total_content_size(&self) -> u64 {
        self.transcript_chunks
            .iter()
            .map(TranscriptChunk::content_size)
            .sum()
    }

    /// Computes the chain root hash from the current chunks.
    ///
    /// This recomputes the Merkle root from the stored chunks. Use this to
    /// verify that the stored `transcript_chain_root_hash` is valid.
    ///
    /// # Errors
    ///
    /// Returns an error if Merkle tree construction fails.
    pub fn compute_chain_root(&self) -> Result<Hash, TranscriptBindingError> {
        Self::compute_chain_root_from_chunks(&self.transcript_chunks)
    }

    /// Computes the Merkle root from a list of chunks.
    ///
    /// Uses the `consensus::merkle` module which provides:
    /// - Domain-separated leaf hashing (`merkle:leaf:` prefix)
    /// - Domain-separated internal node hashing (`merkle:internal:` prefix)
    /// - Proper handling of odd node counts with empty hash padding
    ///
    /// # Algorithm
    ///
    /// 1. If no chunks, return hash of empty byte array
    /// 2. Otherwise, build a Merkle tree using `MerkleTree::new()`
    ///
    /// # Errors
    ///
    /// Returns an error if Merkle tree construction fails.
    pub fn compute_chain_root_from_chunks(
        chunks: &[TranscriptChunk],
    ) -> Result<Hash, TranscriptBindingError> {
        if chunks.is_empty() {
            // Empty transcript: hash of empty content
            return Ok(EventHasher::hash_content(&[]));
        }

        // Build Merkle tree using domain-separated hashing
        let leaves = chunks.iter().map(TranscriptChunk::content_hash);
        let tree = MerkleTree::new(leaves)?;

        Ok(tree.root())
    }

    /// Validates the transcript chain integrity.
    ///
    /// This method verifies:
    ///
    /// 1. The stored chain root hash matches the computed Merkle root
    /// 2. Chunk sequence numbers are monotonically increasing (0, 1, 2, ...)
    /// 3. Collection sizes are within limits
    ///
    /// Note: Duplicate chunk hashes are allowed, as legitimate transcripts
    /// may contain identical messages. Integrity is guaranteed by the Merkle
    /// root and sequence numbers.
    ///
    /// # Returns
    ///
    /// `Ok(())` if validation passes.
    ///
    /// # Errors
    ///
    /// Returns [`TranscriptBindingError::ChainRootMismatch`] if the stored
    /// hash does not match the computed hash.
    ///
    /// Returns [`TranscriptBindingError::SequenceOutOfOrder`] if chunk
    /// sequence numbers are not monotonically increasing.
    ///
    /// Returns [`TranscriptBindingError::TooManyChunks`] if there are too
    /// many chunks.
    ///
    /// Returns [`TranscriptBindingError::TooManyRunHashes`] if there are too
    /// many run transcript hashes.
    pub fn validate(&self) -> Result<(), TranscriptBindingError> {
        // Check collection sizes
        if self.transcript_chunks.len() > MAX_TRANSCRIPT_CHUNKS {
            return Err(TranscriptBindingError::TooManyChunks {
                actual: self.transcript_chunks.len(),
                max: MAX_TRANSCRIPT_CHUNKS,
            });
        }

        if self.run_transcript_hashes.len() > MAX_RUN_TRANSCRIPT_HASHES {
            return Err(TranscriptBindingError::TooManyRunHashes {
                actual: self.run_transcript_hashes.len(),
                max: MAX_RUN_TRANSCRIPT_HASHES,
            });
        }

        // Validate sequence numbers are monotonically increasing from 0
        for (expected, chunk) in self.transcript_chunks.iter().enumerate() {
            let expected_seq = expected as u64;
            if chunk.sequence() != expected_seq {
                return Err(TranscriptBindingError::SequenceOutOfOrder {
                    expected: expected_seq,
                    actual: chunk.sequence(),
                });
            }
        }

        // Verify chain root hash matches computed value
        let computed = self.compute_chain_root()?;
        if computed != self.transcript_chain_root_hash {
            return Err(TranscriptBindingError::ChainRootMismatch {
                computed,
                stored: self.transcript_chain_root_hash,
            });
        }

        Ok(())
    }
}

impl Serialize for AatTranscriptBinding {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let wire = AatTranscriptBindingWire {
            transcript_chunks: self
                .transcript_chunks
                .iter()
                .map(|c| TranscriptChunkWire {
                    content_hash: c.content_hash,
                    sequence: c.sequence,
                    content_size: c.content_size,
                })
                .collect(),
            transcript_chain_root_hash: self.transcript_chain_root_hash,
            run_transcript_hashes: self.run_transcript_hashes.clone(),
        };
        wire.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for AatTranscriptBinding {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = AatTranscriptBindingWire::deserialize(deserializer)?;

        // Enforce resource limits during deserialization to prevent DoS
        if wire.transcript_chunks.len() > MAX_TRANSCRIPT_CHUNKS {
            return Err(serde::de::Error::custom(format!(
                "too many transcript chunks: {} > {}",
                wire.transcript_chunks.len(),
                MAX_TRANSCRIPT_CHUNKS
            )));
        }

        // Note: run_transcript_hashes limit is already enforced by vec_hash_serde
        // during deserialization via the custom visitor

        let transcript_chunks: Vec<TranscriptChunk> = wire
            .transcript_chunks
            .into_iter()
            .map(|w| TranscriptChunk {
                content_hash: w.content_hash,
                sequence: w.sequence,
                content_size: w.content_size,
            })
            .collect();

        let binding = Self {
            transcript_chunks,
            transcript_chain_root_hash: wire.transcript_chain_root_hash,
            run_transcript_hashes: wire.run_transcript_hashes,
        };

        // SECURITY: Validate integrity to prevent fail-open.
        // Ensures the stored chain root hash matches the computed Merkle root,
        // preventing acceptance of tampered evidence.
        binding.validate().map_err(serde::de::Error::custom)?;

        Ok(binding)
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
#[allow(missing_docs, clippy::cast_possible_truncation)]
pub mod tests {
    use super::*;

    // =========================================================================
    // TranscriptChunk Tests
    // =========================================================================

    #[test]
    fn test_transcript_chunk_try_new() {
        let content = b"Hello, world!";
        let chunk = TranscriptChunk::try_new(content, 0).unwrap();

        assert_eq!(chunk.sequence(), 0);
        assert_eq!(chunk.content_size(), content.len() as u64);
        assert!(chunk.verify_content(content));
    }

    #[test]
    fn test_transcript_chunk_hash_determinism() {
        let content = b"Test content";
        let chunk1 = TranscriptChunk::try_new(content, 0).unwrap();
        let chunk2 = TranscriptChunk::try_new(content, 0).unwrap();

        assert_eq!(chunk1.content_hash(), chunk2.content_hash());
    }

    #[test]
    fn test_transcript_chunk_different_content_different_hash() {
        let chunk1 = TranscriptChunk::try_new(b"Content A", 0).unwrap();
        let chunk2 = TranscriptChunk::try_new(b"Content B", 0).unwrap();

        assert_ne!(chunk1.content_hash(), chunk2.content_hash());
    }

    #[test]
    fn test_transcript_chunk_verify_content() {
        let content = b"Verify me!";
        let chunk = TranscriptChunk::try_new(content, 0).unwrap();

        assert!(chunk.verify_content(content));
        assert!(!chunk.verify_content(b"Wrong content"));
    }

    #[test]
    fn test_transcript_chunk_from_hash() {
        let content = b"Pre-hashed content";
        let content_hash = EventHasher::hash_content(content);

        let chunk = TranscriptChunk::from_hash(content_hash, 5, content.len() as u64);

        assert_eq!(chunk.content_hash(), content_hash);
        assert_eq!(chunk.sequence(), 5);
        assert_eq!(chunk.content_size(), content.len() as u64);
        assert!(chunk.verify_content(content));
    }

    #[test]
    fn test_transcript_chunk_serde_roundtrip() {
        let chunk = TranscriptChunk::try_new(b"Serializable content", 42).unwrap();
        let json = serde_json::to_string(&chunk).unwrap();
        let deserialized: TranscriptChunk = serde_json::from_str(&json).unwrap();

        assert_eq!(chunk, deserialized);
    }

    #[test]
    fn test_transcript_chunk_too_large() {
        let large_content = vec![0u8; MAX_CHUNK_CONTENT_BYTES + 1];
        let result = TranscriptChunk::try_new(&large_content, 0);

        assert!(matches!(
            result,
            Err(TranscriptBindingError::ChunkTooLarge { .. })
        ));
    }

    #[test]
    fn test_transcript_chunk_at_max_size() {
        let max_content = vec![0u8; MAX_CHUNK_CONTENT_BYTES];
        let result = TranscriptChunk::try_new(&max_content, 0);

        assert!(result.is_ok());
    }

    // =========================================================================
    // AatTranscriptBinding Chain Root Tests
    // =========================================================================

    #[test]
    fn test_empty_chunks_chain_root() {
        let binding = AatTranscriptBinding::try_new(vec![], vec![]).unwrap();

        let expected_root = EventHasher::hash_content(&[]);
        assert_eq!(binding.transcript_chain_root_hash(), expected_root);
        assert!(binding.validate().is_ok());
    }

    #[test]
    fn test_single_chunk_chain_root() {
        let content = b"Single chunk content";
        let chunk = TranscriptChunk::try_new(content, 0).unwrap();

        let binding = AatTranscriptBinding::try_new(vec![chunk.clone()], vec![]).unwrap();

        // Single chunk uses MerkleTree which applies domain separation
        let tree = MerkleTree::new(std::iter::once(chunk.content_hash())).unwrap();
        let expected_root = tree.root();

        assert_eq!(binding.transcript_chain_root_hash(), expected_root);
        assert!(binding.validate().is_ok());
    }

    #[test]
    fn test_two_chunks_chain_root() {
        let chunk1 = TranscriptChunk::try_new(b"First", 0).unwrap();
        let chunk2 = TranscriptChunk::try_new(b"Second", 1).unwrap();

        let binding =
            AatTranscriptBinding::try_new(vec![chunk1.clone(), chunk2.clone()], vec![]).unwrap();

        // Build expected using MerkleTree
        let tree = MerkleTree::new([chunk1.content_hash(), chunk2.content_hash()]).unwrap();
        let expected_root = tree.root();

        assert_eq!(binding.transcript_chain_root_hash(), expected_root);
        assert!(binding.validate().is_ok());
    }

    #[test]
    fn test_three_chunks_chain_root() {
        let chunk1 = TranscriptChunk::try_new(b"A", 0).unwrap();
        let chunk2 = TranscriptChunk::try_new(b"B", 1).unwrap();
        let chunk3 = TranscriptChunk::try_new(b"C", 2).unwrap();

        let binding = AatTranscriptBinding::try_new(
            vec![chunk1.clone(), chunk2.clone(), chunk3.clone()],
            vec![],
        )
        .unwrap();

        // Build expected using MerkleTree
        let tree = MerkleTree::new([
            chunk1.content_hash(),
            chunk2.content_hash(),
            chunk3.content_hash(),
        ])
        .unwrap();
        let expected_root = tree.root();

        assert_eq!(binding.transcript_chain_root_hash(), expected_root);
        assert!(binding.validate().is_ok());
    }

    #[test]
    fn test_chain_root_deterministic() {
        let chunks = vec![
            TranscriptChunk::try_new(b"Chunk 1", 0).unwrap(),
            TranscriptChunk::try_new(b"Chunk 2", 1).unwrap(),
            TranscriptChunk::try_new(b"Chunk 3", 2).unwrap(),
            TranscriptChunk::try_new(b"Chunk 4", 3).unwrap(),
        ];

        let binding1 = AatTranscriptBinding::try_new(chunks.clone(), vec![]).unwrap();
        let binding2 = AatTranscriptBinding::try_new(chunks, vec![]).unwrap();

        assert_eq!(
            binding1.transcript_chain_root_hash(),
            binding2.transcript_chain_root_hash()
        );
    }

    #[test]
    fn test_chain_root_order_matters() {
        let chunk1 = TranscriptChunk::try_new(b"First", 0).unwrap();
        let chunk2 = TranscriptChunk::try_new(b"Second", 1).unwrap();

        let binding1 =
            AatTranscriptBinding::try_new(vec![chunk1.clone(), chunk2.clone()], vec![]).unwrap();

        // Create with different sequence numbers to reorder
        let reordered_chunk1 =
            TranscriptChunk::from_hash(chunk2.content_hash(), 0, chunk2.content_size());
        let reordered_chunk2 =
            TranscriptChunk::from_hash(chunk1.content_hash(), 1, chunk1.content_size());
        let binding2 =
            AatTranscriptBinding::try_new(vec![reordered_chunk1, reordered_chunk2], vec![])
                .unwrap();

        // Different order = different root
        assert_ne!(
            binding1.transcript_chain_root_hash(),
            binding2.transcript_chain_root_hash()
        );
    }

    // =========================================================================
    // Domain Separation Tests (Duplicate Leaf Attack Prevention)
    // =========================================================================

    #[test]
    fn test_merkle_tree_domain_separation() {
        // Verify that we're using the domain-separated Merkle tree
        // This ensures [A, B, C] produces a different root than [A, B, C, C]
        let chunk1 = TranscriptChunk::try_new(b"A", 0).unwrap();
        let chunk2 = TranscriptChunk::try_new(b"B", 1).unwrap();
        let chunk3 = TranscriptChunk::try_new(b"C", 2).unwrap();
        // chunk3_dup has the same content hash as chunk3
        let chunk3_dup =
            TranscriptChunk::from_hash(chunk3.content_hash(), 3, chunk3.content_size());

        let binding_3 = AatTranscriptBinding::try_new(
            vec![chunk1.clone(), chunk2.clone(), chunk3.clone()],
            vec![],
        )
        .unwrap();

        let binding_4 =
            AatTranscriptBinding::try_new(vec![chunk1, chunk2, chunk3, chunk3_dup], vec![])
                .unwrap();

        // With proper domain separation, these should have different roots
        // even though the last two chunks in binding_4 have the same hash
        assert_ne!(
            binding_3.transcript_chain_root_hash(),
            binding_4.transcript_chain_root_hash()
        );
    }

    // =========================================================================
    // AatTranscriptBinding Validation Tests
    // =========================================================================

    #[test]
    fn test_validate_chain_root_mismatch() {
        let chunk = TranscriptChunk::try_new(b"Content", 0).unwrap();
        let wrong_root = [0xAB; 32];

        let binding = AatTranscriptBinding::from_parts(vec![chunk], wrong_root, vec![]);

        let result = binding.validate();
        assert!(matches!(
            result,
            Err(TranscriptBindingError::ChainRootMismatch { .. })
        ));
    }

    #[test]
    fn test_validate_sequence_out_of_order() {
        // Create chunks with non-sequential sequence numbers
        let chunk1 = TranscriptChunk::from_hash([0x11; 32], 0, 10);
        let chunk2 = TranscriptChunk::from_hash([0x22; 32], 5, 10); // Should be 1

        // Compute the root from these chunks
        let root =
            AatTranscriptBinding::compute_chain_root_from_chunks(&[chunk1.clone(), chunk2.clone()])
                .unwrap();
        let binding = AatTranscriptBinding::from_parts(vec![chunk1, chunk2], root, vec![]);

        let result = binding.validate();
        assert!(matches!(
            result,
            Err(TranscriptBindingError::SequenceOutOfOrder {
                expected: 1,
                actual: 5,
            })
        ));
    }

    #[test]
    fn test_validate_duplicate_chunk_hash_allowed() {
        // Duplicate chunk hashes are now allowed - legitimate transcripts
        // may contain identical messages
        let content = b"Duplicate content";
        let chunk1 = TranscriptChunk::try_new(content, 0).unwrap();
        let chunk2 = TranscriptChunk::from_hash(chunk1.content_hash(), 1, chunk1.content_size());

        let binding =
            AatTranscriptBinding::try_new(vec![chunk1, chunk2], vec![]).expect("should succeed");

        // Validation should pass - duplicates are allowed
        assert!(binding.validate().is_ok());
    }

    #[test]
    fn test_validate_success() {
        let chunks = vec![
            TranscriptChunk::try_new(b"Message 1", 0).unwrap(),
            TranscriptChunk::try_new(b"Message 2", 1).unwrap(),
            TranscriptChunk::try_new(b"Message 3", 2).unwrap(),
        ];
        let run_hashes = vec![[0x11; 32], [0x22; 32]];

        let binding = AatTranscriptBinding::try_new(chunks, run_hashes).unwrap();

        assert!(binding.validate().is_ok());
    }

    // =========================================================================
    // AatTranscriptBinding Resource Limit Tests
    // =========================================================================

    #[test]
    fn test_too_many_chunks() {
        let chunks: Vec<TranscriptChunk> = (0..=MAX_TRANSCRIPT_CHUNKS as u64)
            .map(|i| TranscriptChunk::from_hash([i as u8; 32], i, 10))
            .collect();

        let result = AatTranscriptBinding::try_new(chunks, vec![]);
        assert!(matches!(
            result,
            Err(TranscriptBindingError::TooManyChunks { .. })
        ));
    }

    #[test]
    fn test_too_many_run_hashes() {
        let run_hashes: Vec<Hash> = (0..=MAX_RUN_TRANSCRIPT_HASHES)
            .map(|i| [i as u8; 32])
            .collect();

        let result = AatTranscriptBinding::try_new(vec![], run_hashes);
        assert!(matches!(
            result,
            Err(TranscriptBindingError::TooManyRunHashes { .. })
        ));
    }

    #[test]
    fn test_at_max_chunks_boundary() {
        // Test exactly at the MAX_TRANSCRIPT_CHUNKS boundary
        // Note: This test uses unique hashes to avoid MerkleTree issues
        let chunks: Vec<TranscriptChunk> = (0..MAX_TRANSCRIPT_CHUNKS as u64)
            .map(|i| {
                // Create unique hashes by including sequence in the hash
                let mut hash = [0u8; 32];
                hash[0..8].copy_from_slice(&i.to_le_bytes());
                TranscriptChunk::from_hash(hash, i, 10)
            })
            .collect();

        let result = AatTranscriptBinding::try_new(chunks, vec![]);
        assert!(
            result.is_ok(),
            "should accept exactly MAX_TRANSCRIPT_CHUNKS"
        );
    }

    // =========================================================================
    // Bounded Deserialization Tests (DoS Prevention)
    // =========================================================================

    #[test]
    fn test_deserialize_rejects_too_many_chunks() {
        // Create a wire format with too many chunks
        let chunks: Vec<TranscriptChunkWire> = (0..=MAX_TRANSCRIPT_CHUNKS)
            .map(|i| TranscriptChunkWire {
                content_hash: [i as u8; 32],
                sequence: i as u64,
                content_size: 10,
            })
            .collect();

        let wire = AatTranscriptBindingWire {
            transcript_chunks: chunks,
            transcript_chain_root_hash: [0u8; 32],
            run_transcript_hashes: vec![],
        };

        let json = serde_json::to_string(&wire).unwrap();
        let result: Result<AatTranscriptBinding, _> = serde_json::from_str(&json);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too many"));
    }

    #[test]
    fn test_deserialize_rejects_too_many_run_hashes() {
        let run_hashes: Vec<[u8; 32]> = (0..=MAX_RUN_TRANSCRIPT_HASHES)
            .map(|i| [i as u8; 32])
            .collect();

        let wire = AatTranscriptBindingWire {
            transcript_chunks: vec![],
            transcript_chain_root_hash: [0u8; 32],
            run_transcript_hashes: run_hashes,
        };

        let json = serde_json::to_string(&wire).unwrap();
        let result: Result<AatTranscriptBinding, _> = serde_json::from_str(&json);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too many"));
    }

    // =========================================================================
    // AatTranscriptBinding Accessor Tests
    // =========================================================================

    #[test]
    fn test_accessors() {
        let chunks = vec![
            TranscriptChunk::try_new(b"A", 0).unwrap(),
            TranscriptChunk::try_new(b"BB", 1).unwrap(),
            TranscriptChunk::try_new(b"CCC", 2).unwrap(),
        ];
        let run_hashes = vec![[0x11; 32]];

        let binding = AatTranscriptBinding::try_new(chunks, run_hashes).unwrap();

        assert_eq!(binding.chunk_count(), 3);
        assert_eq!(binding.total_content_size(), 1 + 2 + 3);
        assert_eq!(binding.transcript_chunks().len(), 3);
        assert_eq!(binding.run_transcript_hashes().len(), 1);
    }

    // =========================================================================
    // Serde Tests
    // =========================================================================

    #[test]
    fn test_binding_serde_roundtrip() {
        let chunks = vec![
            TranscriptChunk::try_new(b"First", 0).unwrap(),
            TranscriptChunk::try_new(b"Second", 1).unwrap(),
        ];
        let run_hashes = vec![[0x11; 32], [0x22; 32]];

        let binding = AatTranscriptBinding::try_new(chunks, run_hashes).unwrap();

        let json = serde_json::to_string(&binding).unwrap();
        let deserialized: AatTranscriptBinding = serde_json::from_str(&json).unwrap();

        assert_eq!(binding, deserialized);
    }

    #[test]
    fn test_binding_serde_deny_unknown_fields() {
        let json = r#"{
            "transcript_chunks": [],
            "transcript_chain_root_hash": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
            "run_transcript_hashes": [],
            "unknown_field": "should_fail"
        }"#;

        let result: Result<AatTranscriptBinding, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    // =========================================================================
    // Fail-Closed Deserialization Tests (Security)
    // =========================================================================

    #[test]
    fn test_deserialize_validates_merkle_root() {
        // SECURITY TEST: Ensures deserialization validates the Merkle root,
        // preventing acceptance of tampered evidence.
        let chunk = TranscriptChunk::try_new(b"Content", 0).unwrap();
        let valid_binding = AatTranscriptBinding::try_new(vec![chunk], vec![]).unwrap();

        // Serialize valid binding, then tamper with the root
        let mut wire: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&valid_binding).unwrap()).unwrap();

        // Tamper: replace root hash with wrong value
        wire["transcript_chain_root_hash"] = serde_json::json!([
            0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB,
            0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB,
            0xAB, 0xAB, 0xAB, 0xAB
        ]);

        let tampered_json = serde_json::to_string(&wire).unwrap();
        let result: Result<AatTranscriptBinding, _> = serde_json::from_str(&tampered_json);

        // Should fail during deserialization due to validation
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("chain root hash mismatch")
        );
    }

    #[test]
    fn test_deserialize_validates_sequence_order() {
        // SECURITY TEST: Ensures deserialization validates sequence numbers.
        // Create wire format with out-of-order sequences
        let chunks = vec![
            TranscriptChunkWire {
                content_hash: [0x11; 32],
                sequence: 0,
                content_size: 10,
            },
            TranscriptChunkWire {
                content_hash: [0x22; 32],
                sequence: 5, // Should be 1
                content_size: 10,
            },
        ];

        // Compute a "valid" root for these chunks (doesn't matter, sequence check comes
        // first)
        let wire = AatTranscriptBindingWire {
            transcript_chunks: chunks,
            transcript_chain_root_hash: [0u8; 32], // Will fail anyway
            run_transcript_hashes: vec![],
        };

        let json = serde_json::to_string(&wire).unwrap();
        let result: Result<AatTranscriptBinding, _> = serde_json::from_str(&json);

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("sequence number out of order")
        );
    }

    // =========================================================================
    // compute_chain_root Tests
    // =========================================================================

    #[test]
    fn test_compute_chain_root_matches_stored() {
        let chunks = vec![
            TranscriptChunk::try_new(b"X", 0).unwrap(),
            TranscriptChunk::try_new(b"Y", 1).unwrap(),
            TranscriptChunk::try_new(b"Z", 2).unwrap(),
        ];

        let binding = AatTranscriptBinding::try_new(chunks, vec![]).unwrap();

        // compute_chain_root should match the stored hash
        assert_eq!(
            binding.compute_chain_root().unwrap(),
            binding.transcript_chain_root_hash()
        );
    }

    // =========================================================================
    // Edge Cases
    // =========================================================================

    #[test]
    fn test_large_chunk_merkle_tree() {
        // Test with power of 2 chunks (no duplication needed)
        let chunks: Vec<TranscriptChunk> = (0..8u64)
            .map(|i| TranscriptChunk::try_new(format!("Chunk {i}").as_bytes(), i).unwrap())
            .collect();

        let binding = AatTranscriptBinding::try_new(chunks, vec![]).unwrap();
        assert!(binding.validate().is_ok());
    }

    #[test]
    fn test_non_power_of_two_chunks() {
        // Test with 7 chunks (requires padding for odd count)
        let chunks: Vec<TranscriptChunk> = (0..7u64)
            .map(|i| TranscriptChunk::try_new(format!("Chunk {i}").as_bytes(), i).unwrap())
            .collect();

        let binding = AatTranscriptBinding::try_new(chunks, vec![]).unwrap();
        assert!(binding.validate().is_ok());
    }
}
