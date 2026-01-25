//! Content-addressed storage (CAS) for evidence artifacts.
//!
//! The CAS stores artifacts by their BLAKE3 hash, ensuring:
//! - Content integrity: hash verification on storage and retrieval
//! - Deduplication: identical content is stored only once
//! - Immutability: stored content cannot be modified
//!
//! # Architecture
//!
//! The CAS is designed as a trait to allow different backends:
//! - [`MemoryCas`]: In-memory storage for testing
//! - Future: Filesystem, S3, or other backends
//!
//! # Security
//!
//! - All content is verified against its hash on both store and retrieve
//! - Hash collisions are cryptographically infeasible with BLAKE3
//! - Content is stored immutably; attempts to overwrite are rejected

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use thiserror::Error;

use crate::crypto::{EventHasher, HASH_SIZE, Hash};

/// Maximum artifact size (100 MB).
pub const MAX_ARTIFACT_SIZE: usize = 100 * 1024 * 1024;

/// Default maximum total size for in-memory CAS (1 GB).
pub const DEFAULT_MAX_TOTAL_SIZE: usize = 1024 * 1024 * 1024;

/// Errors that can occur during CAS operations.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CasError {
    /// Content not found for the given hash.
    #[error("content not found for hash: {hash}")]
    NotFound {
        /// The hash that was not found (hex-encoded).
        hash: String,
    },

    /// Hash mismatch between expected and actual content hash.
    #[error("hash mismatch: expected {expected}, got {actual}")]
    HashMismatch {
        /// The expected hash (hex-encoded).
        expected: String,
        /// The actual hash (hex-encoded).
        actual: String,
    },

    /// Content already exists with different hash.
    ///
    /// This should never happen with a proper hash function, but we check
    /// defensively.
    #[error("content collision: hash {hash} already exists with different content")]
    Collision {
        /// The hash that collided (hex-encoded).
        hash: String,
    },

    /// Content exceeds maximum allowed size.
    #[error("content too large: {size} bytes exceeds maximum of {max_size} bytes")]
    ContentTooLarge {
        /// The actual size.
        size: usize,
        /// The maximum allowed size.
        max_size: usize,
    },

    /// Empty content is not allowed.
    #[error("empty content is not allowed")]
    EmptyContent,

    /// Invalid hash format.
    #[error("invalid hash: expected {expected} bytes, got {actual} bytes")]
    InvalidHash {
        /// The expected number of bytes.
        expected: usize,
        /// The actual number of bytes.
        actual: usize,
    },

    /// Storage backend error.
    #[error("storage error: {message}")]
    StorageError {
        /// Description of the error.
        message: String,
    },

    /// Total storage capacity exceeded.
    #[error(
        "storage full: total size {current_size} + {new_size} exceeds limit of {max_size} bytes"
    )]
    StorageFull {
        /// Current total size.
        current_size: usize,
        /// Size of new content.
        new_size: usize,
        /// Maximum allowed total size.
        max_size: usize,
    },
}

/// Result of a store operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreResult {
    /// The content hash.
    pub hash: Hash,

    /// The size of the stored content in bytes.
    pub size: usize,

    /// Whether this was a new store (true) or deduplicated (false).
    pub is_new: bool,
}

/// Trait for content-addressed storage backends.
///
/// Implementations must ensure:
/// 1. Content is verified against its hash on store
/// 2. Content is verified against its hash on retrieve
/// 3. Duplicate content is deduplicated
/// 4. Stored content is immutable
pub trait ContentAddressedStore: Send + Sync {
    /// Stores content and returns its hash.
    ///
    /// If content with the same hash already exists, this is a no-op and
    /// returns the existing hash (deduplication).
    ///
    /// # Errors
    ///
    /// - [`CasError::EmptyContent`] if content is empty
    /// - [`CasError::ContentTooLarge`] if content exceeds size limit
    /// - [`CasError::Collision`] if hash collision detected (should never
    ///   happen)
    fn store(&self, content: &[u8]) -> Result<StoreResult, CasError>;

    /// Retrieves content by hash.
    ///
    /// The returned content is verified against the hash before returning.
    ///
    /// # Errors
    ///
    /// - [`CasError::NotFound`] if content is not found
    /// - [`CasError::InvalidHash`] if hash is malformed
    /// - [`CasError::HashMismatch`] if stored content doesn't match hash
    ///   (indicates corruption)
    fn retrieve(&self, hash: &Hash) -> Result<Vec<u8>, CasError>;

    /// Checks if content with the given hash exists.
    ///
    /// # Errors
    ///
    /// - [`CasError::InvalidHash`] if hash is malformed
    fn exists(&self, hash: &Hash) -> Result<bool, CasError>;

    /// Returns the size of content with the given hash, without retrieving it.
    ///
    /// # Errors
    ///
    /// - [`CasError::NotFound`] if content is not found
    /// - [`CasError::InvalidHash`] if hash is malformed
    fn size(&self, hash: &Hash) -> Result<usize, CasError>;

    /// Verifies that content matches the expected hash.
    ///
    /// This is a convenience method that computes the hash of content and
    /// compares it to the expected hash.
    ///
    /// # Errors
    ///
    /// - [`CasError::HashMismatch`] if content doesn't match expected hash
    fn verify(&self, content: &[u8], expected_hash: &Hash) -> Result<(), CasError> {
        let actual_hash = EventHasher::hash_content(content);
        if actual_hash != *expected_hash {
            return Err(CasError::HashMismatch {
                expected: hex_encode(expected_hash),
                actual: hex_encode(&actual_hash),
            });
        }
        Ok(())
    }
}

/// In-memory content-addressed store for testing.
///
/// This implementation stores all content in memory and is not suitable for
/// production use with large artifacts.
#[derive(Debug)]
pub struct MemoryCas {
    /// Content storage, keyed by hash.
    storage: Arc<RwLock<HashMap<Hash, Vec<u8>>>>,
    /// Maximum total size allowed.
    max_total_size: usize,
}

impl Default for MemoryCas {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryCas {
    /// Creates a new in-memory CAS with the default size limit.
    #[must_use]
    pub fn new() -> Self {
        Self::with_max_size(DEFAULT_MAX_TOTAL_SIZE)
    }

    /// Creates a new in-memory CAS with a custom size limit.
    #[must_use]
    pub fn with_max_size(max_total_size: usize) -> Self {
        Self {
            storage: Arc::new(RwLock::new(HashMap::new())),
            max_total_size,
        }
    }

    /// Returns the number of stored items.
    ///
    /// # Panics
    ///
    /// Panics if the internal lock is poisoned (indicates a thread panic).
    #[must_use]
    pub fn len(&self) -> usize {
        self.storage.read().expect("lock poisoned").len()
    }

    /// Returns true if the store is empty.
    ///
    /// # Panics
    ///
    /// Panics if the internal lock is poisoned (indicates a thread panic).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.storage.read().expect("lock poisoned").is_empty()
    }

    /// Clears all stored content.
    ///
    /// # Panics
    ///
    /// Panics if the internal lock is poisoned (indicates a thread panic).
    pub fn clear(&self) {
        self.storage.write().expect("lock poisoned").clear();
    }

    /// Returns the total size of all stored content in bytes.
    ///
    /// # Panics
    ///
    /// Panics if the internal lock is poisoned (indicates a thread panic).
    #[must_use]
    pub fn total_size(&self) -> usize {
        self.storage
            .read()
            .expect("lock poisoned")
            .values()
            .map(Vec::len)
            .sum()
    }
}

impl Clone for MemoryCas {
    fn clone(&self) -> Self {
        Self {
            storage: Arc::clone(&self.storage),
            max_total_size: self.max_total_size,
        }
    }
}

impl ContentAddressedStore for MemoryCas {
    fn store(&self, content: &[u8]) -> Result<StoreResult, CasError> {
        // Validate content
        if content.is_empty() {
            return Err(CasError::EmptyContent);
        }
        if content.len() > MAX_ARTIFACT_SIZE {
            return Err(CasError::ContentTooLarge {
                size: content.len(),
                max_size: MAX_ARTIFACT_SIZE,
            });
        }

        // Compute hash
        let hash = EventHasher::hash_content(content);
        let size = content.len();

        // Check total size limit (before acquiring write lock)
        let current_size = self.total_size();
        if current_size.saturating_add(size) > self.max_total_size {
            return Err(CasError::StorageFull {
                current_size,
                new_size: size,
                max_size: self.max_total_size,
            });
        }

        // Store with deduplication
        let mut storage = self.storage.write().expect("lock poisoned");

        if let Some(existing) = storage.get(&hash) {
            // Verify existing content matches (collision detection)
            if existing != content {
                return Err(CasError::Collision {
                    hash: hex_encode(&hash),
                });
            }
            return Ok(StoreResult {
                hash,
                size,
                is_new: false,
            });
        }

        storage.insert(hash, content.to_vec());
        Ok(StoreResult {
            hash,
            size,
            is_new: true,
        })
    }

    fn retrieve(&self, hash: &Hash) -> Result<Vec<u8>, CasError> {
        let storage = self.storage.read().expect("lock poisoned");

        let content = storage.get(hash).ok_or_else(|| CasError::NotFound {
            hash: hex_encode(hash),
        })?;

        // Verify content integrity
        let actual_hash = EventHasher::hash_content(content);
        if actual_hash != *hash {
            return Err(CasError::HashMismatch {
                expected: hex_encode(hash),
                actual: hex_encode(&actual_hash),
            });
        }

        Ok(content.clone())
    }

    fn exists(&self, hash: &Hash) -> Result<bool, CasError> {
        let storage = self.storage.read().expect("lock poisoned");
        Ok(storage.contains_key(hash))
    }

    fn size(&self, hash: &Hash) -> Result<usize, CasError> {
        let storage = self.storage.read().expect("lock poisoned");
        storage
            .get(hash)
            .map(Vec::len)
            .ok_or_else(|| CasError::NotFound {
                hash: hex_encode(hash),
            })
    }
}

/// Converts a hash to hex string.
fn hex_encode(hash: &Hash) -> String {
    use std::fmt::Write;
    hash.iter().fold(
        String::with_capacity(HASH_SIZE * 2),
        |mut acc: String, b| {
            let _ = write!(acc, "{b:02x}");
            acc
        },
    )
}

/// Converts a hex string to a hash.
///
/// # Errors
///
/// Returns `CasError::InvalidHash` if the string is not a valid hex-encoded
/// hash.
#[allow(dead_code)]
pub fn hex_decode(s: &str) -> Result<Hash, CasError> {
    if s.len() != HASH_SIZE * 2 {
        return Err(CasError::InvalidHash {
            expected: HASH_SIZE,
            actual: s.len() / 2,
        });
    }

    let mut hash = [0u8; HASH_SIZE];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let high = hex_char_to_nibble(chunk[0]).ok_or(CasError::InvalidHash {
            expected: HASH_SIZE,
            actual: 0,
        })?;
        let low = hex_char_to_nibble(chunk[1]).ok_or(CasError::InvalidHash {
            expected: HASH_SIZE,
            actual: 0,
        })?;
        hash[i] = (high << 4) | low;
    }

    Ok(hash)
}

/// Converts a hex character to its nibble value.
#[allow(dead_code)]
const fn hex_char_to_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn test_store_and_retrieve() {
        let cas = MemoryCas::new();
        let content = b"hello world";

        let result = cas.store(content).unwrap();
        assert!(result.is_new);
        assert_eq!(result.size, content.len());

        let retrieved = cas.retrieve(&result.hash).unwrap();
        assert_eq!(retrieved, content);
    }

    #[test]
    fn test_deduplication() {
        let cas = MemoryCas::new();
        let content = b"duplicate content";

        let result1 = cas.store(content).unwrap();
        assert!(result1.is_new);

        let result2 = cas.store(content).unwrap();
        assert!(!result2.is_new);
        assert_eq!(result1.hash, result2.hash);
        assert_eq!(cas.len(), 1);
    }

    #[test]
    fn test_different_content_different_hash() {
        let cas = MemoryCas::new();

        let result1 = cas.store(b"content 1").unwrap();
        let result2 = cas.store(b"content 2").unwrap();

        assert_ne!(result1.hash, result2.hash);
        assert_eq!(cas.len(), 2);
    }

    #[test]
    fn test_empty_content_rejected() {
        let cas = MemoryCas::new();
        let result = cas.store(b"");
        assert!(matches!(result, Err(CasError::EmptyContent)));
    }

    #[test]
    fn test_content_too_large() {
        let cas = MemoryCas::new();
        let large_content = vec![0u8; MAX_ARTIFACT_SIZE + 1];
        let result = cas.store(&large_content);
        assert!(matches!(result, Err(CasError::ContentTooLarge { .. })));
    }

    #[test]
    fn test_retrieve_not_found() {
        let cas = MemoryCas::new();
        let fake_hash = [0u8; HASH_SIZE];
        let result = cas.retrieve(&fake_hash);
        assert!(matches!(result, Err(CasError::NotFound { .. })));
    }

    #[test]
    fn test_exists() {
        let cas = MemoryCas::new();
        let content = b"test content";

        let result = cas.store(content).unwrap();

        assert!(cas.exists(&result.hash).unwrap());

        let fake_hash = [0u8; HASH_SIZE];
        assert!(!cas.exists(&fake_hash).unwrap());
    }

    #[test]
    fn test_size() {
        let cas = MemoryCas::new();
        let content = b"test content for size";

        let result = cas.store(content).unwrap();
        let size = cas.size(&result.hash).unwrap();
        assert_eq!(size, content.len());
    }

    #[test]
    fn test_size_not_found() {
        let cas = MemoryCas::new();
        let fake_hash = [0u8; HASH_SIZE];
        let result = cas.size(&fake_hash);
        assert!(matches!(result, Err(CasError::NotFound { .. })));
    }

    #[test]
    fn test_verify() {
        let cas = MemoryCas::new();
        let content = b"content to verify";
        let result = cas.store(content).unwrap();

        // Verification should pass for correct content
        assert!(cas.verify(content, &result.hash).is_ok());

        // Verification should fail for wrong content
        let wrong_content = b"wrong content";
        assert!(matches!(
            cas.verify(wrong_content, &result.hash),
            Err(CasError::HashMismatch { .. })
        ));
    }

    #[test]
    fn test_clear() {
        let cas = MemoryCas::new();
        cas.store(b"content 1").unwrap();
        cas.store(b"content 2").unwrap();
        assert_eq!(cas.len(), 2);

        cas.clear();
        assert!(cas.is_empty());
    }

    #[test]
    fn test_total_size() {
        let cas = MemoryCas::new();
        cas.store(b"12345").unwrap(); // 5 bytes
        cas.store(b"1234567890").unwrap(); // 10 bytes
        assert_eq!(cas.total_size(), 15);
    }

    #[test]
    fn test_clone_shares_storage() {
        let cas1 = MemoryCas::new();
        let cas2 = cas1.clone();

        let result = cas1.store(b"shared content").unwrap();
        assert!(cas2.exists(&result.hash).unwrap());
    }

    #[test]
    fn test_hex_encode_decode_roundtrip() {
        let original: Hash = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
            0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67,
            0x89, 0xab, 0xcd, 0xef,
        ];

        let encoded = hex_encode(&original);
        let decoded = hex_decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_hex_decode_invalid_length() {
        let result = hex_decode("0123");
        assert!(matches!(result, Err(CasError::InvalidHash { .. })));
    }

    #[test]
    fn test_deterministic_hash() {
        let cas1 = MemoryCas::new();
        let cas2 = MemoryCas::new();

        let content = b"deterministic content";
        let result1 = cas1.store(content).unwrap();
        let result2 = cas2.store(content).unwrap();

        assert_eq!(result1.hash, result2.hash);
    }
}
