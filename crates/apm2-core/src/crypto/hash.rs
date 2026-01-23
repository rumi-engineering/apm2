//! Blake3 hashing and hash-chain primitives.

use thiserror::Error;

/// Size of a Blake3 hash in bytes.
pub const HASH_SIZE: usize = 32;

/// Type alias for a 32-byte hash.
pub type Hash = [u8; HASH_SIZE];

/// Errors that can occur during hash chain operations.
#[derive(Debug, Error)]
pub enum HashChainError {
    /// The previous hash doesn't match the expected value.
    #[error("hash chain broken: expected {expected}, got {actual}")]
    ChainBroken {
        /// The expected previous hash.
        expected: String,
        /// The actual previous hash found.
        actual: String,
    },

    /// The event hash doesn't match the computed value.
    #[error("event hash mismatch: expected {expected}, got {actual}")]
    HashMismatch {
        /// The expected hash.
        expected: String,
        /// The actual hash computed.
        actual: String,
    },
}

/// Hasher for kernel events using Blake3.
///
/// The `EventHasher` computes cryptographic hashes of event content and
/// manages hash-chain linking between sequential events.
pub struct EventHasher;

impl EventHasher {
    /// The zero hash used as the previous hash for the genesis event.
    pub const GENESIS_PREV_HASH: Hash = [0u8; HASH_SIZE];

    /// Hashes event content with chain linking.
    ///
    /// The hash is computed over: `prev_hash || content`
    ///
    /// This ensures that each event is cryptographically linked to the
    /// previous event, forming an immutable chain.
    #[must_use]
    pub fn hash_event(content: &[u8], prev_hash: &Hash) -> Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(prev_hash);
        hasher.update(content);
        *hasher.finalize().as_bytes()
    }

    /// Hashes raw content without chain linking.
    ///
    /// Use this for hashing artifacts or other content that doesn't
    /// participate in the event chain.
    #[must_use]
    pub fn hash_content(content: &[u8]) -> Hash {
        *blake3::hash(content).as_bytes()
    }

    /// Verifies that an event hash matches the expected value.
    ///
    /// # Errors
    ///
    /// Returns `HashMismatch` if the computed hash doesn't match.
    pub fn verify_hash(
        content: &[u8],
        prev_hash: &Hash,
        expected_hash: &Hash,
    ) -> Result<(), HashChainError> {
        let computed = Self::hash_event(content, prev_hash);
        if computed != *expected_hash {
            return Err(HashChainError::HashMismatch {
                expected: hex::encode(expected_hash),
                actual: hex::encode(&computed),
            });
        }
        Ok(())
    }

    /// Verifies the chain link between two consecutive events.
    ///
    /// # Arguments
    ///
    /// * `current_prev_hash` - The previous hash stored in the current event
    /// * `previous_event_hash` - The computed hash of the previous event
    ///
    /// # Errors
    ///
    /// Returns `ChainBroken` if the hashes don't match.
    pub fn verify_chain_link(
        current_prev_hash: &Hash,
        previous_event_hash: &Hash,
    ) -> Result<(), HashChainError> {
        if current_prev_hash != previous_event_hash {
            return Err(HashChainError::ChainBroken {
                expected: hex::encode(previous_event_hash),
                actual: hex::encode(current_prev_hash),
            });
        }
        Ok(())
    }

    /// Verifies an entire chain of events.
    ///
    /// # Arguments
    ///
    /// * `events` - Iterator of (content, `prev_hash`, `event_hash`) tuples
    ///
    /// # Errors
    ///
    /// Returns an error if any hash is invalid or any chain link is broken.
    pub fn verify_chain<'a>(
        events: impl IntoIterator<Item = (&'a [u8], &'a Hash, &'a Hash)>,
    ) -> Result<(), HashChainError> {
        let mut expected_prev_hash = Self::GENESIS_PREV_HASH;

        for (content, prev_hash, event_hash) in events {
            // Verify chain link
            Self::verify_chain_link(prev_hash, &expected_prev_hash)?;

            // Verify event hash
            Self::verify_hash(content, prev_hash, event_hash)?;

            // Update expected previous hash for next iteration
            expected_prev_hash = *event_hash;
        }

        Ok(())
    }
}

/// Utility module for hex encoding (used in error messages).
mod hex {
    use std::fmt::Write;

    /// Encodes bytes as a hex string.
    pub fn encode(bytes: &[u8]) -> String {
        bytes
            .iter()
            .fold(String::with_capacity(bytes.len() * 2), |mut acc, b| {
                let _ = write!(acc, "{b:02x}");
                acc
            })
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn test_hash_content() {
        let content = b"hello world";
        let hash = EventHasher::hash_content(content);

        assert_eq!(hash.len(), HASH_SIZE);

        // Same content should produce same hash
        let hash2 = EventHasher::hash_content(content);
        assert_eq!(hash, hash2);

        // Different content should produce different hash
        let hash3 = EventHasher::hash_content(b"different");
        assert_ne!(hash, hash3);
    }

    #[test]
    fn test_hash_event_with_chain() {
        let content = b"event content";
        let prev_hash = [1u8; HASH_SIZE];

        let hash = EventHasher::hash_event(content, &prev_hash);

        // Hash should be deterministic
        let hash2 = EventHasher::hash_event(content, &prev_hash);
        assert_eq!(hash, hash2);

        // Different prev_hash should produce different hash
        let hash3 = EventHasher::hash_event(content, &[2u8; HASH_SIZE]);
        assert_ne!(hash, hash3);
    }

    #[test]
    fn test_genesis_event() {
        let content = b"genesis event";
        let hash = EventHasher::hash_event(content, &EventHasher::GENESIS_PREV_HASH);

        assert_eq!(hash.len(), HASH_SIZE);

        // Verify the hash
        EventHasher::verify_hash(content, &EventHasher::GENESIS_PREV_HASH, &hash).unwrap();
    }

    #[test]
    fn test_verify_hash_success() {
        let content = b"test content";
        let prev_hash = [0u8; HASH_SIZE];
        let hash = EventHasher::hash_event(content, &prev_hash);

        let result = EventHasher::verify_hash(content, &prev_hash, &hash);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_hash_failure() {
        let content = b"test content";
        let prev_hash = [0u8; HASH_SIZE];
        let wrong_hash = [1u8; HASH_SIZE];

        let result = EventHasher::verify_hash(content, &prev_hash, &wrong_hash);
        assert!(matches!(result, Err(HashChainError::HashMismatch { .. })));
    }

    #[test]
    fn test_verify_chain_link_success() {
        let hash = EventHasher::hash_content(b"event");
        let result = EventHasher::verify_chain_link(&hash, &hash);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_chain_link_failure() {
        let hash1 = EventHasher::hash_content(b"event1");
        let hash2 = EventHasher::hash_content(b"event2");

        let result = EventHasher::verify_chain_link(&hash1, &hash2);
        assert!(matches!(result, Err(HashChainError::ChainBroken { .. })));
    }
}
