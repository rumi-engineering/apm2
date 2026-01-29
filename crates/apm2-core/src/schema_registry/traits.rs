//! Schema registry trait definitions.
//!
//! This module defines the [`SchemaRegistry`] trait for distributed schema
//! governance. All nodes must agree on schema digests before accepting events,
//! implementing a fail-closed policy for unknown schemas.
//!
//! # Security Properties
//!
//! - **Fail-closed**: Unknown schemas trigger rejection (never silent
//!   acceptance)
//! - **Digest verification**: Schema identity is determined by content hash
//! - **Peer handshake**: Nodes exchange schema digests to verify compatibility
//!
//! # Design Decision DD-0004
//!
//! From RFC-0014: "Implement a distributed schema registry where all nodes
//! must agree on schema digests before accepting events. Unknown schemas
//! trigger rejection (fail-closed)."

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use bytes::Bytes;
use thiserror::Error;

use crate::crypto::Hash;

/// A boxed future for async trait methods.
///
/// This pattern follows the established convention in
/// `apm2_core::adapter::traits`.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Size limit for schema content (1 MB).
///
/// Schemas exceeding this size are rejected to prevent resource exhaustion.
pub const MAX_SCHEMA_SIZE: usize = 1024 * 1024;

/// Maximum number of schemas that can be stored in memory.
///
/// This limit prevents unbounded memory growth in `InMemorySchemaRegistry`.
/// With `MAX_SCHEMA_SIZE` of 1MB, this gives a maximum footprint of 1GB.
/// [CTR-1303]: In-memory stores have `max_entries` limit with O(1) eviction.
pub const DEFAULT_MAX_SCHEMAS: usize = 1_000;

/// Maximum number of digests allowed in a handshake request.
///
/// This limit prevents memory exhaustion denial-of-service attacks where a
/// malicious peer sends an arbitrarily large list of digests to overwhelm
/// the registry.
pub const MAX_HANDSHAKE_DIGESTS: usize = 10_000;

/// Errors that can occur during schema registry operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SchemaRegistryError {
    /// Schema not found for the given digest.
    #[error("schema not found: {digest}")]
    NotFound {
        /// The digest that was not found (hex-encoded).
        digest: String,
    },

    /// Schema already exists with a different digest.
    ///
    /// This indicates an attempt to register a schema with the same stable ID
    /// but different content.
    #[error("schema conflict: stable_id {stable_id} already exists with different digest")]
    Conflict {
        /// The stable ID that conflicts.
        stable_id: String,
    },

    /// Schema content exceeds the maximum allowed size.
    #[error("schema too large: {size} bytes exceeds maximum of {max_size} bytes")]
    SchemaTooLarge {
        /// The actual size in bytes.
        size: usize,
        /// The maximum allowed size in bytes.
        max_size: usize,
    },

    /// Empty schema content is not allowed.
    #[error("empty schema content is not allowed")]
    EmptySchema,

    /// Invalid schema stable ID format.
    #[error("invalid stable ID: {reason}")]
    InvalidStableId {
        /// The reason the stable ID is invalid.
        reason: String,
    },

    /// Registry is at capacity.
    ///
    /// [CTR-1303]: In-memory stores have `max_entries` limit.
    #[error("registry full: {current} schemas at capacity of {max}")]
    RegistryFull {
        /// Current number of schemas.
        current: usize,
        /// Maximum allowed schemas.
        max: usize,
    },

    /// Hash mismatch between expected and actual digest.
    #[error("hash mismatch: expected {expected}, got {actual}")]
    HashMismatch {
        /// The expected hash (hex-encoded).
        expected: String,
        /// The actual hash (hex-encoded).
        actual: String,
    },

    /// Peer handshake failed due to incompatible schemas.
    #[error("handshake failed: {reason}")]
    HandshakeFailed {
        /// Description of the incompatibility.
        reason: String,
    },

    /// Too many digests in handshake request.
    ///
    /// This prevents memory exhaustion attacks from malicious peers.
    #[error("too many digests in handshake: {count} exceeds maximum of {max}")]
    TooManyDigests {
        /// The number of digests received.
        count: usize,
        /// The maximum allowed number of digests.
        max: usize,
    },

    /// Internal registry error.
    #[error("internal error: {message}")]
    Internal {
        /// Description of the error.
        message: String,
    },
}

/// A schema digest (BLAKE3 hash of canonical schema content).
///
/// Digests are the primary identifier for schemas in the registry.
/// Two schemas with identical content will have identical digests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SchemaDigest(pub Hash);

impl SchemaDigest {
    /// Creates a new digest from a 32-byte hash.
    #[must_use]
    pub const fn new(hash: Hash) -> Self {
        Self(hash)
    }

    /// Returns the digest as a byte slice.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns the digest as a hex-encoded string with `b3-256:` prefix.
    #[must_use]
    pub fn to_hex(&self) -> String {
        format!("b3-256:{}", hex_encode(&self.0))
    }
}

impl From<Hash> for SchemaDigest {
    fn from(hash: Hash) -> Self {
        Self(hash)
    }
}

impl AsRef<[u8]> for SchemaDigest {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// A registered schema entry.
///
/// Each entry contains the schema's stable ID, content digest, and metadata
/// about when and by whom it was registered.
///
/// # Performance
///
/// The `content` field uses `bytes::Bytes` for zero-copy cloning. This avoids
/// expensive deep copies of schema content (up to 1MB) when entries are
/// returned from lookup methods. Cloning a `SchemaEntry` only increments a
/// reference count for the content, making it O(1) regardless of content size.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaEntry {
    /// The stable ID for this schema (e.g., `"dcp://org/schema@v1"`).
    pub stable_id: String,

    /// The BLAKE3 digest of the canonical schema content.
    pub digest: SchemaDigest,

    /// The raw schema content (JSON).
    ///
    /// Uses `bytes::Bytes` for zero-copy cloning to avoid expensive deep
    /// copies when returning entries from lookup methods.
    pub content: Bytes,

    /// The canonicalizer version used to compute the digest.
    ///
    /// This tracks which version of the canonicalizer was used, enabling
    /// migration when canonicalization rules change.
    pub canonicalizer_version: String,

    /// Unix timestamp (nanoseconds) when the schema was registered.
    pub registered_at: u64,

    /// Actor ID that registered this schema.
    pub registered_by: String,
}

impl SchemaEntry {
    /// Returns the content size in bytes.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // Bytes::len() is not const
    pub fn content_size(&self) -> usize {
        self.content.len()
    }
}

/// Result of a peer handshake operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeResult {
    /// Schemas that are compatible (present in both registries).
    pub compatible: Vec<SchemaDigest>,

    /// Schemas that this peer is missing (peer has, we don't).
    pub missing_local: Vec<SchemaDigest>,

    /// Schemas that the peer is missing (we have, peer doesn't).
    pub missing_remote: Vec<SchemaDigest>,
}

impl HandshakeResult {
    /// Returns true if the handshake indicates full compatibility.
    #[must_use]
    pub fn is_fully_compatible(&self) -> bool {
        self.missing_local.is_empty() && self.missing_remote.is_empty()
    }

    /// Returns true if the handshake indicates any incompatibility.
    #[must_use]
    pub fn has_incompatibilities(&self) -> bool {
        !self.is_fully_compatible()
    }
}

/// Trait for schema registry implementations.
///
/// The schema registry provides distributed schema governance where all nodes
/// must agree on schema digests before accepting events. This is a fail-closed
/// system: unknown schemas trigger rejection.
///
/// # Invariants
///
/// - [INV-0001] Digests are computed from canonical schema content using BLAKE3
/// - [INV-0002] Schema entries are immutable once registered
/// - [INV-0003] Stable IDs are unique within the registry
/// - [INV-0004] Unknown schema digests cause fail-closed rejection
///
/// # Contracts
///
/// - [CTR-0001] `register()` fails if schema with same stable ID exists with
///   different content
/// - [CTR-0002] `lookup_by_digest()` returns `None` for unknown digests (not
///   error)
/// - [CTR-0003] `handshake()` compares digests to determine compatibility
/// - [CTR-0004] Empty schema content is rejected with `EmptySchema`
/// - [CTR-0005] Schemas exceeding `MAX_SCHEMA_SIZE` are rejected
///
/// # Example
///
/// ```rust,ignore
/// use apm2_core::schema_registry::{SchemaRegistry, SchemaEntry, InMemorySchemaRegistry};
///
/// let registry = InMemorySchemaRegistry::new();
///
/// // Register a schema
/// let entry = SchemaEntry { ... };
/// registry.register(&entry).await?;
///
/// // Look up by digest
/// if let Some(found) = registry.lookup_by_digest(&entry.digest).await? {
///     println!("Found schema: {}", found.stable_id);
/// }
/// ```
pub trait SchemaRegistry: Send + Sync {
    /// Registers a new schema entry.
    ///
    /// If a schema with the same stable ID already exists with identical
    /// content (same digest), this is a no-op. If the content differs,
    /// returns `SchemaRegistryError::Conflict`.
    ///
    /// # Arguments
    ///
    /// * `entry` - The schema entry to register
    ///
    /// # Errors
    ///
    /// - [`SchemaRegistryError::Conflict`] if stable ID exists with different
    ///   digest
    /// - [`SchemaRegistryError::EmptySchema`] if content is empty
    /// - [`SchemaRegistryError::SchemaTooLarge`] if content exceeds size limit
    /// - [`SchemaRegistryError::RegistryFull`] if registry is at capacity
    fn register<'a>(
        &'a self,
        entry: &'a SchemaEntry,
    ) -> BoxFuture<'a, Result<(), SchemaRegistryError>>;

    /// Looks up a schema entry by its digest.
    ///
    /// Returns `None` if no schema with the given digest is registered.
    /// This follows the fail-closed principle: unknown digests return `None`,
    /// and callers must decide how to handle missing schemas.
    ///
    /// # Arguments
    ///
    /// * `digest` - The BLAKE3 digest to look up
    ///
    /// # Returns
    ///
    /// An `Arc<SchemaEntry>` if found, or `None` if not registered.
    /// Using `Arc` avoids cloning the entry, especially the content bytes.
    fn lookup_by_digest<'a>(
        &'a self,
        digest: &'a SchemaDigest,
    ) -> BoxFuture<'a, Result<Option<Arc<SchemaEntry>>, SchemaRegistryError>>;

    /// Looks up a schema entry by its stable ID.
    ///
    /// Returns `None` if no schema with the given stable ID is registered.
    ///
    /// # Arguments
    ///
    /// * `stable_id` - The stable ID to look up
    ///
    /// # Returns
    ///
    /// An `Arc<SchemaEntry>` if found, or `None` if not registered.
    /// Using `Arc` avoids cloning the entry, especially the content bytes.
    fn lookup_by_stable_id<'a>(
        &'a self,
        stable_id: &'a str,
    ) -> BoxFuture<'a, Result<Option<Arc<SchemaEntry>>, SchemaRegistryError>>;

    /// Performs a peer handshake to compare schema registries.
    ///
    /// Given a list of digests from a peer, determines which schemas are
    /// compatible, missing locally, or missing remotely. This is used during
    /// peer connection setup to verify schema agreement.
    ///
    /// # Arguments
    ///
    /// * `peer_digests` - Digests of schemas the peer has registered
    ///
    /// # Returns
    ///
    /// A `HandshakeResult` indicating compatibility and missing schemas.
    fn handshake<'a>(
        &'a self,
        peer_digests: &'a [SchemaDigest],
    ) -> BoxFuture<'a, Result<HandshakeResult, SchemaRegistryError>>;

    /// Returns all registered schema digests.
    ///
    /// This is primarily used for handshake operations and debugging.
    fn all_digests(&self) -> BoxFuture<'_, Result<Vec<SchemaDigest>, SchemaRegistryError>>;

    /// Returns the number of registered schemas.
    fn len(&self) -> BoxFuture<'_, Result<usize, SchemaRegistryError>>;

    /// Returns true if the registry is empty.
    fn is_empty(&self) -> BoxFuture<'_, Result<bool, SchemaRegistryError>> {
        Box::pin(async move { Ok(self.len().await? == 0) })
    }
}

/// Converts a hash to a hex-encoded string.
fn hex_encode(hash: &Hash) -> String {
    use std::fmt::Write;
    hash.iter().fold(
        String::with_capacity(hash.len() * 2),
        |mut acc: String, b| {
            let _ = write!(acc, "{b:02x}");
            acc
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tck_00181_schema_digest_to_hex() {
        let hash = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
            0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67,
            0x89, 0xab, 0xcd, 0xef,
        ];
        let digest = SchemaDigest::new(hash);

        let hex = digest.to_hex();
        assert!(hex.starts_with("b3-256:"));
        assert_eq!(hex.len(), "b3-256:".len() + 64);
    }

    #[test]
    fn tck_00181_schema_digest_from_hash() {
        let hash = [42u8; 32];
        let digest: SchemaDigest = hash.into();
        assert_eq!(digest.as_bytes(), &hash);
    }

    #[test]
    fn tck_00181_handshake_result_compatibility() {
        let compatible_result = HandshakeResult {
            compatible: vec![SchemaDigest::new([1u8; 32])],
            missing_local: vec![],
            missing_remote: vec![],
        };
        assert!(compatible_result.is_fully_compatible());
        assert!(!compatible_result.has_incompatibilities());

        let incompatible_result = HandshakeResult {
            compatible: vec![],
            missing_local: vec![SchemaDigest::new([2u8; 32])],
            missing_remote: vec![],
        };
        assert!(!incompatible_result.is_fully_compatible());
        assert!(incompatible_result.has_incompatibilities());
    }

    #[test]
    fn tck_00181_schema_entry_content_size() {
        let entry = SchemaEntry {
            stable_id: "test:schema.v1".to_string(),
            digest: SchemaDigest::new([0u8; 32]),
            content: Bytes::from_static(&[1, 2, 3, 4, 5]),
            canonicalizer_version: "cac-json-v1".to_string(),
            registered_at: 0,
            registered_by: "test".to_string(),
        };
        assert_eq!(entry.content_size(), 5);
    }

    #[test]
    fn tck_00181_error_display() {
        let err = SchemaRegistryError::NotFound {
            digest: "abc123".to_string(),
        };
        assert!(err.to_string().contains("abc123"));

        let err = SchemaRegistryError::Conflict {
            stable_id: "test:schema.v1".to_string(),
        };
        assert!(err.to_string().contains("test:schema.v1"));

        let err = SchemaRegistryError::SchemaTooLarge {
            size: 2_000_000,
            max_size: 1_000_000,
        };
        assert!(err.to_string().contains("2000000"));
    }
}
