//! In-memory schema registry implementation.
//!
//! This module provides [`InMemorySchemaRegistry`], a non-persistent schema
//! registry for testing and single-node deployments. For production distributed
//! deployments, a consensus-backed implementation should be used.
//!
//! # Security Properties
//!
//! - **Bounded size**: Registry has a maximum capacity to prevent memory
//!   exhaustion, with O(1) FIFO eviction when full ([CTR-1303])
//! - **Bounded handshake**: Handshake requests limited to
//!   `MAX_HANDSHAKE_DIGESTS` to prevent memory denial-of-service attacks
//! - **Content verification**: Schema digests are verified on registration
//! - **Fail-closed**: Unknown schemas return `None`, not errors
//! - **Pre-validation ordering**: Capacity checks before expensive hash
//!   validation to prevent CPU exhaustion
//! - **One `stable_id` per schema**: Each digest maps to exactly one
//!   `stable_id` to prevent ghost entries and unbounded memory growth
//!
//! # Thread Safety
//!
//! The implementation uses `RwLock` for thread-safe concurrent access.
//! Clone shares the underlying storage via `Arc`.
//!
//! # Lock Ordering
//!
//! To prevent deadlocks, all methods MUST acquire locks in this order:
//! 1. `insertion_order` (if needed)
//! 2. `by_digest` (if needed)
//! 3. `by_stable_id` (if needed)
//!
//! Never acquire locks in a different order.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, RwLock};

use super::traits::{
    BoxFuture, DEFAULT_MAX_SCHEMAS, HandshakeResult, MAX_HANDSHAKE_DIGESTS, MAX_SCHEMA_SIZE,
    SchemaDigest, SchemaEntry, SchemaRegistry, SchemaRegistryError,
};
use crate::crypto::EventHasher;

/// In-memory schema registry for testing and single-node deployments.
///
/// This implementation stores all schemas in memory and is not suitable for
/// production distributed deployments. Use a consensus-backed implementation
/// for multi-node scenarios.
///
/// # Invariants
///
/// - [INV-0010] Schema count cannot exceed `max_schemas` (eviction when full)
/// - [INV-0011] Clone shares storage via `Arc` (not deep copy)
/// - [INV-0012] Digests are computed from content using BLAKE3
/// - [INV-0013] Eviction is O(1) via `VecDeque` insertion order tracking
/// - [INV-0014] One `stable_id` per digest (no aliases) - prevents ghost
///   entries
/// - [INV-0015] Lock ordering: `insertion_order` -> `by_digest` ->
///   `by_stable_id`
///
/// # Example
///
/// ```rust
/// use apm2_core::crypto::EventHasher;
/// use apm2_core::schema_registry::{
///     InMemorySchemaRegistry, SchemaDigest, SchemaEntry,
/// };
///
/// let registry = InMemorySchemaRegistry::new();
///
/// // Create a schema entry
/// let content = br#"{"type": "object"}"#;
/// let digest = SchemaDigest::new(EventHasher::hash_content(content));
///
/// let entry = SchemaEntry {
///     stable_id: "test:schema.v1".to_string(),
///     digest,
///     content: content.to_vec(),
///     canonicalizer_version: "cac-json-v1".to_string(),
///     registered_at: 0,
///     registered_by: "test-actor".to_string(),
/// };
///
/// // Registration would be done via the async trait methods
/// ```
#[derive(Debug)]
pub struct InMemorySchemaRegistry {
    /// Insertion order tracking for O(1) FIFO eviction ([INV-0013]).
    /// Listed first to document lock ordering ([INV-0015]).
    insertion_order: Arc<RwLock<VecDeque<SchemaDigest>>>,
    /// Schema storage, keyed by digest.
    by_digest: Arc<RwLock<HashMap<SchemaDigest, SchemaEntry>>>,
    /// Index from stable ID to digest for fast lookup.
    /// Note: One `stable_id` per digest ([INV-0014]).
    by_stable_id: Arc<RwLock<HashMap<String, SchemaDigest>>>,
    /// Maximum number of schemas allowed.
    max_schemas: usize,
}

impl Default for InMemorySchemaRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemorySchemaRegistry {
    /// Creates a new in-memory schema registry with default capacity.
    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_MAX_SCHEMAS)
    }

    /// Creates a new in-memory schema registry with custom capacity.
    ///
    /// # Arguments
    ///
    /// * `max_schemas` - Maximum number of schemas that can be stored
    #[must_use]
    pub fn with_capacity(max_schemas: usize) -> Self {
        // Fields ordered to match lock ordering: insertion_order -> by_digest ->
        // by_stable_id
        Self {
            insertion_order: Arc::new(RwLock::new(VecDeque::new())),
            by_digest: Arc::new(RwLock::new(HashMap::new())),
            by_stable_id: Arc::new(RwLock::new(HashMap::new())),
            max_schemas,
        }
    }

    /// Returns the number of registered schemas.
    ///
    /// # Panics
    ///
    /// Panics if the internal lock is poisoned (indicates a thread panic).
    #[must_use]
    pub fn count(&self) -> usize {
        self.by_digest.read().expect("lock poisoned").len()
    }

    /// Returns true if the registry is empty.
    ///
    /// # Panics
    ///
    /// Panics if the internal lock is poisoned (indicates a thread panic).
    #[must_use]
    pub fn is_empty_sync(&self) -> bool {
        self.by_digest.read().expect("lock poisoned").is_empty()
    }

    /// Clears all registered schemas.
    ///
    /// # Panics
    ///
    /// Panics if the internal lock is poisoned (indicates a thread panic).
    ///
    /// # Lock Ordering
    ///
    /// Acquires locks in order: `insertion_order` -> `by_digest` ->
    /// `by_stable_id`
    pub fn clear(&self) {
        // Lock ordering: insertion_order -> by_digest -> by_stable_id ([INV-0015])
        let mut insertion_order = self.insertion_order.write().expect("lock poisoned");
        let mut by_digest = self.by_digest.write().expect("lock poisoned");
        let mut by_stable_id = self.by_stable_id.write().expect("lock poisoned");

        insertion_order.clear();
        by_digest.clear();
        by_stable_id.clear();
    }

    /// Performs cheap validation of a schema entry (without hash verification).
    ///
    /// This checks empty content, size limits, and stable ID format.
    /// Hash verification is deferred to avoid CPU exhaustion attacks.
    fn validate_entry_cheap(entry: &SchemaEntry) -> Result<(), SchemaRegistryError> {
        // Check for empty content
        if entry.content.is_empty() {
            return Err(SchemaRegistryError::EmptySchema);
        }

        // Check size limit
        if entry.content.len() > MAX_SCHEMA_SIZE {
            return Err(SchemaRegistryError::SchemaTooLarge {
                size: entry.content.len(),
                max_size: MAX_SCHEMA_SIZE,
            });
        }

        // Validate stable ID format (non-empty, reasonable length)
        if entry.stable_id.is_empty() {
            return Err(SchemaRegistryError::InvalidStableId {
                reason: "stable ID cannot be empty".to_string(),
            });
        }
        if entry.stable_id.len() > 256 {
            return Err(SchemaRegistryError::InvalidStableId {
                reason: format!(
                    "stable ID too long: {} bytes exceeds maximum of 256",
                    entry.stable_id.len()
                ),
            });
        }

        Ok(())
    }

    /// Performs expensive hash verification of a schema entry.
    ///
    /// This should only be called after cheap validation and existence checks
    /// to prevent CPU exhaustion attacks ([CTR-1303]).
    fn verify_hash(entry: &SchemaEntry) -> Result<(), SchemaRegistryError> {
        let computed = EventHasher::hash_content(&entry.content);
        if computed != entry.digest.0 {
            return Err(SchemaRegistryError::HashMismatch {
                expected: hex_encode(&entry.digest.0),
                actual: hex_encode(&computed),
            });
        }
        Ok(())
    }
}

impl Clone for InMemorySchemaRegistry {
    fn clone(&self) -> Self {
        // Fields ordered to match lock ordering: insertion_order -> by_digest ->
        // by_stable_id
        Self {
            insertion_order: Arc::clone(&self.insertion_order),
            by_digest: Arc::clone(&self.by_digest),
            by_stable_id: Arc::clone(&self.by_stable_id),
            max_schemas: self.max_schemas,
        }
    }
}

impl SchemaRegistry for InMemorySchemaRegistry {
    fn register<'a>(
        &'a self,
        entry: &'a SchemaEntry,
    ) -> BoxFuture<'a, Result<(), SchemaRegistryError>> {
        Box::pin(async move {
            // SECURITY: Staging pattern to prevent DoS via lock contention.
            //
            // Phase 1 (NO LOCKS): Validate input and compute hash
            //   - Cheap validation (size limits, format)
            //   - Expensive hash verification (BLAKE3 of up to 1MB content)
            //
            // Phase 2 (READ LOCKS): Quick existence check
            //   - Check if already registered (idempotent no-op)
            //
            // Phase 3 (WRITE LOCKS): Commit the registration
            //   - Re-check under write lock (double-checked locking)
            //   - Evict if needed, then insert
            //
            // This prevents blocking read operations during hash verification.
            // [INV-0015]: Lock ordering: insertion_order -> by_digest -> by_stable_id

            // ===== PHASE 1: Pre-validation WITHOUT locks =====
            // Cheap validation (O(1) checks, no hashing)
            Self::validate_entry_cheap(entry)?;

            // Expensive hash verification BEFORE acquiring any locks.
            // This prevents DoS where an attacker submits large content
            // and blocks all registry operations during hash computation.
            Self::verify_hash(entry)?;

            // ===== PHASE 2: Quick existence check with READ locks =====
            // Use read locks for fast-path duplicate detection
            {
                let by_digest = self.by_digest.read().expect("lock poisoned");
                let by_stable_id = self.by_stable_id.read().expect("lock poisoned");

                // Check for stable ID conflict
                if let Some(existing_digest) = by_stable_id.get(&entry.stable_id) {
                    if *existing_digest != entry.digest {
                        return Err(SchemaRegistryError::Conflict {
                            stable_id: entry.stable_id.clone(),
                        });
                    }
                    // Same stable ID with same digest - this is a no-op
                    return Ok(());
                }

                // Check if digest already exists.
                // SECURITY [INV-0014]: First stable_id wins - subsequent registrations
                // with same digest are true no-ops. This prevents alias hijacking.
                if by_digest.contains_key(&entry.digest) {
                    return Ok(());
                }
            }
            // Read locks released here

            // ===== PHASE 3: Commit with WRITE locks =====
            // Acquire write locks in consistent order: insertion_order -> by_digest ->
            // by_stable_id
            let mut insertion_order = self.insertion_order.write().expect("lock poisoned");
            let mut by_digest = self.by_digest.write().expect("lock poisoned");
            let mut by_stable_id = self.by_stable_id.write().expect("lock poisoned");

            // Double-checked locking: Re-verify under write lock since another
            // thread may have registered between our read check and write lock
            if let Some(existing_digest) = by_stable_id.get(&entry.stable_id) {
                if *existing_digest != entry.digest {
                    return Err(SchemaRegistryError::Conflict {
                        stable_id: entry.stable_id.clone(),
                    });
                }
                return Ok(());
            }
            if by_digest.contains_key(&entry.digest) {
                return Ok(());
            }

            // Evict oldest entries if at capacity ([CTR-1303])
            // O(1) eviction via insertion_order VecDeque ([INV-0013])
            while by_digest.len() >= self.max_schemas {
                if let Some(oldest_digest) = insertion_order.pop_front() {
                    // Remove the oldest entry and its stable_id mapping
                    if let Some(evicted) = by_digest.remove(&oldest_digest) {
                        by_stable_id.remove(&evicted.stable_id);
                    }
                    // Note: If digest not found (shouldn't happen with
                    // [INV-0014]), continue evicting
                } else {
                    // Queue is empty but map is full - should not happen
                    // This is a safety check to prevent infinite loop
                    break;
                }
            }

            // Register the new schema
            by_digest.insert(entry.digest, entry.clone());
            by_stable_id.insert(entry.stable_id.clone(), entry.digest);
            insertion_order.push_back(entry.digest);

            Ok(())
        })
    }

    fn lookup_by_digest<'a>(
        &'a self,
        digest: &'a SchemaDigest,
    ) -> BoxFuture<'a, Result<Option<SchemaEntry>, SchemaRegistryError>> {
        Box::pin(async move {
            let by_digest = self.by_digest.read().expect("lock poisoned");
            Ok(by_digest.get(digest).cloned())
        })
    }

    fn lookup_by_stable_id<'a>(
        &'a self,
        stable_id: &'a str,
    ) -> BoxFuture<'a, Result<Option<SchemaEntry>, SchemaRegistryError>> {
        Box::pin(async move {
            // LOCK ORDERING ([INV-0015]): by_digest -> by_stable_id
            // Note: insertion_order not needed for read-only lookup
            let by_digest = self.by_digest.read().expect("lock poisoned");
            let by_stable_id = self.by_stable_id.read().expect("lock poisoned");

            Ok(by_stable_id
                .get(stable_id)
                .and_then(|digest| by_digest.get(digest).cloned()))
        })
    }

    fn handshake<'a>(
        &'a self,
        peer_digests: &'a [SchemaDigest],
    ) -> BoxFuture<'a, Result<HandshakeResult, SchemaRegistryError>> {
        Box::pin(async move {
            // SECURITY: Limit input size to prevent memory exhaustion DoS
            if peer_digests.len() > MAX_HANDSHAKE_DIGESTS {
                return Err(SchemaRegistryError::TooManyDigests {
                    count: peer_digests.len(),
                    max: MAX_HANDSHAKE_DIGESTS,
                });
            }

            let by_digest = self.by_digest.read().expect("lock poisoned");

            let local_digests: std::collections::HashSet<_> = by_digest.keys().copied().collect();
            let peer_digest_set: std::collections::HashSet<_> =
                peer_digests.iter().copied().collect();

            let compatible: Vec<_> = local_digests
                .intersection(&peer_digest_set)
                .copied()
                .collect();

            let missing_local: Vec<_> = peer_digest_set
                .difference(&local_digests)
                .copied()
                .collect();

            let missing_remote: Vec<_> = local_digests
                .difference(&peer_digest_set)
                .copied()
                .collect();

            Ok(HandshakeResult {
                compatible,
                missing_local,
                missing_remote,
            })
        })
    }

    fn all_digests(&self) -> BoxFuture<'_, Result<Vec<SchemaDigest>, SchemaRegistryError>> {
        Box::pin(async move {
            let by_digest = self.by_digest.read().expect("lock poisoned");
            Ok(by_digest.keys().copied().collect())
        })
    }

    fn len(&self) -> BoxFuture<'_, Result<usize, SchemaRegistryError>> {
        Box::pin(async move {
            let by_digest = self.by_digest.read().expect("lock poisoned");
            Ok(by_digest.len())
        })
    }
}

/// Converts a hash to a hex-encoded string.
fn hex_encode(hash: &[u8; 32]) -> String {
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
#[allow(clippy::large_stack_arrays)]
mod tests {
    use super::*;

    /// Helper to create a test schema entry with computed digest.
    fn make_entry(stable_id: &str, content: &[u8]) -> SchemaEntry {
        let digest = SchemaDigest::new(EventHasher::hash_content(content));
        SchemaEntry {
            stable_id: stable_id.to_string(),
            digest,
            content: content.to_vec(),
            canonicalizer_version: "cac-json-v1".to_string(),
            registered_at: 0,
            registered_by: "test-actor".to_string(),
        }
    }

    #[tokio::test]
    async fn tck_00181_register_and_lookup_by_digest() {
        let registry = InMemorySchemaRegistry::new();
        let entry = make_entry("test:schema.v1", br#"{"type": "object"}"#);

        // Register
        registry.register(&entry).await.unwrap();

        // Lookup by digest
        let found = registry.lookup_by_digest(&entry.digest).await.unwrap();
        assert!(found.is_some());
        let found = found.unwrap();
        assert_eq!(found.stable_id, "test:schema.v1");
        assert_eq!(found.content, entry.content);
    }

    #[tokio::test]
    async fn tck_00181_register_and_lookup_by_stable_id() {
        let registry = InMemorySchemaRegistry::new();
        let entry = make_entry("test:schema.v1", br#"{"type": "string"}"#);

        registry.register(&entry).await.unwrap();

        let found = registry
            .lookup_by_stable_id("test:schema.v1")
            .await
            .unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().digest, entry.digest);
    }

    #[tokio::test]
    async fn tck_00181_lookup_not_found() {
        let registry = InMemorySchemaRegistry::new();

        // Lookup by digest - should return None, not error
        let fake_digest = SchemaDigest::new([0u8; 32]);
        let result = registry.lookup_by_digest(&fake_digest).await.unwrap();
        assert!(result.is_none());

        // Lookup by stable ID - should return None, not error
        let result = registry.lookup_by_stable_id("nonexistent").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn tck_00181_register_duplicate_is_noop() {
        let registry = InMemorySchemaRegistry::new();
        let entry = make_entry("test:schema.v1", br#"{"type": "boolean"}"#);

        registry.register(&entry).await.unwrap();
        assert_eq!(registry.count(), 1);

        // Register same entry again - should be no-op
        registry.register(&entry).await.unwrap();
        assert_eq!(registry.count(), 1);
    }

    #[tokio::test]
    async fn tck_00181_register_conflict_different_content() {
        let registry = InMemorySchemaRegistry::new();
        let entry1 = make_entry("test:schema.v1", br#"{"type": "object"}"#);
        let entry2 = make_entry("test:schema.v1", br#"{"type": "string"}"#);

        registry.register(&entry1).await.unwrap();

        // Try to register same stable ID with different content
        let result = registry.register(&entry2).await;
        assert!(matches!(result, Err(SchemaRegistryError::Conflict { .. })));
    }

    #[tokio::test]
    async fn tck_00181_register_empty_content_rejected() {
        let registry = InMemorySchemaRegistry::new();
        let entry = SchemaEntry {
            stable_id: "test:empty.v1".to_string(),
            digest: SchemaDigest::new([0u8; 32]),
            content: vec![],
            canonicalizer_version: "cac-json-v1".to_string(),
            registered_at: 0,
            registered_by: "test".to_string(),
        };

        let result = registry.register(&entry).await;
        assert!(matches!(result, Err(SchemaRegistryError::EmptySchema)));
    }

    #[tokio::test]
    async fn tck_00181_register_oversized_content_rejected() {
        let registry = InMemorySchemaRegistry::new();
        let large_content = vec![0u8; MAX_SCHEMA_SIZE + 1];
        let entry = SchemaEntry {
            stable_id: "test:large.v1".to_string(),
            digest: SchemaDigest::new(EventHasher::hash_content(&large_content)),
            content: large_content,
            canonicalizer_version: "cac-json-v1".to_string(),
            registered_at: 0,
            registered_by: "test".to_string(),
        };

        let result = registry.register(&entry).await;
        assert!(matches!(
            result,
            Err(SchemaRegistryError::SchemaTooLarge { .. })
        ));
    }

    #[tokio::test]
    async fn tck_00181_register_invalid_stable_id_rejected() {
        let registry = InMemorySchemaRegistry::new();
        let content = br#"{"type": "object"}"#;

        // Empty stable ID
        let entry = SchemaEntry {
            stable_id: String::new(),
            digest: SchemaDigest::new(EventHasher::hash_content(content)),
            content: content.to_vec(),
            canonicalizer_version: "cac-json-v1".to_string(),
            registered_at: 0,
            registered_by: "test".to_string(),
        };
        let result = registry.register(&entry).await;
        assert!(matches!(
            result,
            Err(SchemaRegistryError::InvalidStableId { .. })
        ));

        // Too long stable ID
        let long_id = "x".repeat(300);
        let entry = SchemaEntry {
            stable_id: long_id,
            digest: SchemaDigest::new(EventHasher::hash_content(content)),
            content: content.to_vec(),
            canonicalizer_version: "cac-json-v1".to_string(),
            registered_at: 0,
            registered_by: "test".to_string(),
        };
        let result = registry.register(&entry).await;
        assert!(matches!(
            result,
            Err(SchemaRegistryError::InvalidStableId { .. })
        ));
    }

    #[tokio::test]
    async fn tck_00181_register_hash_mismatch_rejected() {
        let registry = InMemorySchemaRegistry::new();
        let content = br#"{"type": "object"}"#;

        // Wrong digest
        let entry = SchemaEntry {
            stable_id: "test:mismatch.v1".to_string(),
            digest: SchemaDigest::new([42u8; 32]), // Wrong hash
            content: content.to_vec(),
            canonicalizer_version: "cac-json-v1".to_string(),
            registered_at: 0,
            registered_by: "test".to_string(),
        };

        let result = registry.register(&entry).await;
        assert!(matches!(
            result,
            Err(SchemaRegistryError::HashMismatch { .. })
        ));
    }

    #[tokio::test]
    async fn tck_00181_registry_capacity_eviction() {
        // Test O(1) FIFO eviction when registry is full ([CTR-1303], [INV-0013])
        let registry = InMemorySchemaRegistry::with_capacity(2);

        let entry1 = make_entry("test:schema1.v1", br#"{"id": 1}"#);
        let entry2 = make_entry("test:schema2.v1", br#"{"id": 2}"#);
        let entry3 = make_entry("test:schema3.v1", br#"{"id": 3}"#);

        registry.register(&entry1).await.unwrap();
        registry.register(&entry2).await.unwrap();
        assert_eq!(registry.count(), 2);

        // Third registration should evict the oldest (entry1)
        registry.register(&entry3).await.unwrap();
        assert_eq!(registry.count(), 2);

        // entry1 should be evicted
        let found1 = registry.lookup_by_digest(&entry1.digest).await.unwrap();
        assert!(found1.is_none(), "entry1 should have been evicted");

        // entry2 and entry3 should still exist
        let found2 = registry.lookup_by_digest(&entry2.digest).await.unwrap();
        let found3 = registry.lookup_by_digest(&entry3.digest).await.unwrap();
        assert!(found2.is_some(), "entry2 should still exist");
        assert!(found3.is_some(), "entry3 should still exist");

        // Stable ID lookup for entry1 should also return None
        let found1_by_id = registry
            .lookup_by_stable_id("test:schema1.v1")
            .await
            .unwrap();
        assert!(found1_by_id.is_none());
    }

    #[tokio::test]
    async fn tck_00181_handshake_full_compatibility() {
        let registry = InMemorySchemaRegistry::new();
        let entry1 = make_entry("test:schema1.v1", br#"{"id": 1}"#);
        let entry2 = make_entry("test:schema2.v1", br#"{"id": 2}"#);

        registry.register(&entry1).await.unwrap();
        registry.register(&entry2).await.unwrap();

        // Peer has same schemas
        let peer_digests = vec![entry1.digest, entry2.digest];
        let result = registry.handshake(&peer_digests).await.unwrap();

        assert!(result.is_fully_compatible());
        assert_eq!(result.compatible.len(), 2);
        assert!(result.missing_local.is_empty());
        assert!(result.missing_remote.is_empty());
    }

    #[tokio::test]
    async fn tck_00181_handshake_partial_compatibility() {
        let registry = InMemorySchemaRegistry::new();
        let entry1 = make_entry("test:schema1.v1", br#"{"id": 1}"#);
        let entry2 = make_entry("test:schema2.v1", br#"{"id": 2}"#);
        let entry3 = make_entry("test:schema3.v1", br#"{"id": 3}"#);

        registry.register(&entry1).await.unwrap();
        registry.register(&entry2).await.unwrap();

        // Peer has entry1 and entry3 (not entry2)
        let peer_digests = vec![entry1.digest, entry3.digest];
        let result = registry.handshake(&peer_digests).await.unwrap();

        assert!(!result.is_fully_compatible());
        assert_eq!(result.compatible.len(), 1);
        assert!(result.compatible.contains(&entry1.digest));
        assert_eq!(result.missing_local.len(), 1);
        assert!(result.missing_local.contains(&entry3.digest));
        assert_eq!(result.missing_remote.len(), 1);
        assert!(result.missing_remote.contains(&entry2.digest));
    }

    #[tokio::test]
    async fn tck_00181_handshake_no_overlap() {
        let registry = InMemorySchemaRegistry::new();
        let entry1 = make_entry("test:schema1.v1", br#"{"id": 1}"#);
        let entry2 = make_entry("test:schema2.v1", br#"{"id": 2}"#);

        registry.register(&entry1).await.unwrap();

        // Peer has completely different schema
        let peer_digests = vec![entry2.digest];
        let result = registry.handshake(&peer_digests).await.unwrap();

        assert!(!result.is_fully_compatible());
        assert!(result.compatible.is_empty());
        assert_eq!(result.missing_local.len(), 1);
        assert_eq!(result.missing_remote.len(), 1);
    }

    #[tokio::test]
    async fn tck_00181_all_digests() {
        let registry = InMemorySchemaRegistry::new();
        let entry1 = make_entry("test:schema1.v1", br#"{"id": 1}"#);
        let entry2 = make_entry("test:schema2.v1", br#"{"id": 2}"#);

        registry.register(&entry1).await.unwrap();
        registry.register(&entry2).await.unwrap();

        let digests = registry.all_digests().await.unwrap();
        assert_eq!(digests.len(), 2);
        assert!(digests.contains(&entry1.digest));
        assert!(digests.contains(&entry2.digest));
    }

    #[tokio::test]
    async fn tck_00181_len_and_is_empty() {
        let registry = InMemorySchemaRegistry::new();

        assert!(registry.is_empty().await.unwrap());
        assert_eq!(registry.len().await.unwrap(), 0);

        let entry = make_entry("test:schema.v1", br#"{"type": "null"}"#);
        registry.register(&entry).await.unwrap();

        assert!(!registry.is_empty().await.unwrap());
        assert_eq!(registry.len().await.unwrap(), 1);
    }

    #[tokio::test]
    async fn tck_00181_clone_shares_storage() {
        let registry1 = InMemorySchemaRegistry::new();
        let registry2 = registry1.clone();

        let entry = make_entry("test:schema.v1", br#"{"shared": true}"#);
        registry1.register(&entry).await.unwrap();

        // Clone should see the registered schema
        let found = registry2.lookup_by_digest(&entry.digest).await.unwrap();
        assert!(found.is_some());
    }

    #[tokio::test]
    async fn tck_00181_clear() {
        let registry = InMemorySchemaRegistry::new();
        let entry = make_entry("test:schema.v1", br#"{"type": "array"}"#);

        registry.register(&entry).await.unwrap();
        assert_eq!(registry.count(), 1);

        registry.clear();
        assert_eq!(registry.count(), 0);
        assert!(registry.is_empty_sync());
    }

    #[tokio::test]
    async fn tck_00181_re_register_same_digest_preserves_first_stable_id() {
        // SECURITY [INV-0014]: First stable_id wins - subsequent registrations
        // with same digest are true no-ops. This prevents alias hijacking where
        // an attacker registers kernel schema content under a different stable_id
        // to remove the original "kernel:" mapping.
        let registry = InMemorySchemaRegistry::new();
        let content = br#"{"type": "object"}"#;

        let entry1 = make_entry("kernel:schema1.v1", content);
        let entry2 = make_entry("attacker:schema2.v1", content); // Same content, different stable ID

        registry.register(&entry1).await.unwrap();
        assert_eq!(registry.count(), 1);

        // Attempt to register same content with different stable ID - should be no-op
        registry.register(&entry2).await.unwrap();
        assert_eq!(registry.count(), 1); // Still only one schema

        // ORIGINAL stable_id should still work (first wins, prevents hijacking)
        let found1 = registry
            .lookup_by_stable_id("kernel:schema1.v1")
            .await
            .unwrap();
        assert!(
            found1.is_some(),
            "Original stable_id should still resolve (first wins)"
        );
        assert_eq!(found1.unwrap().stable_id, "kernel:schema1.v1");

        // Attacker's stable_id should NOT work (true no-op, no mapping created)
        let found2 = registry
            .lookup_by_stable_id("attacker:schema2.v1")
            .await
            .unwrap();
        assert!(
            found2.is_none(),
            "Attacker's stable_id should not resolve (first wins)"
        );

        // Digest lookup should return the ORIGINAL entry
        let found_by_digest = registry.lookup_by_digest(&entry1.digest).await.unwrap();
        assert!(found_by_digest.is_some());
        assert_eq!(found_by_digest.unwrap().stable_id, "kernel:schema1.v1");
    }

    // =========================================================================
    // Security-focused tests for DoS prevention
    // =========================================================================

    #[tokio::test]
    async fn tck_00181_handshake_rejects_too_many_digests() {
        // Test that handshake rejects input exceeding MAX_HANDSHAKE_DIGESTS.
        // We construct the Vec dynamically to avoid large-stack-arrays clippy warning.
        let registry = InMemorySchemaRegistry::new();

        // Create the digests one at a time to avoid compile-time array allocation
        let mut too_many_digests = Vec::with_capacity(MAX_HANDSHAKE_DIGESTS + 1);
        for i in 0..=MAX_HANDSHAKE_DIGESTS {
            let mut hash = [0u8; 32];
            hash[0..8].copy_from_slice(&i.to_le_bytes());
            too_many_digests.push(SchemaDigest::new(hash));
        }

        let result = registry.handshake(&too_many_digests).await;
        assert!(
            matches!(
                result,
                Err(SchemaRegistryError::TooManyDigests { count, max })
                if count == MAX_HANDSHAKE_DIGESTS + 1 && max == MAX_HANDSHAKE_DIGESTS
            ),
            "Expected TooManyDigests error, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn tck_00181_handshake_accepts_under_limit() {
        // Test that handshake accepts input under MAX_HANDSHAKE_DIGESTS.
        // We test with a smaller number to keep tests fast.
        let registry = InMemorySchemaRegistry::new();

        let under_limit_digests: Vec<SchemaDigest> = (0_u64..100)
            .map(|i| {
                let mut hash = [0u8; 32];
                hash[0..8].copy_from_slice(&i.to_le_bytes());
                SchemaDigest::new(hash)
            })
            .collect();

        let result = registry.handshake(&under_limit_digests).await;
        assert!(result.is_ok(), "Should accept digests under limit");
    }

    #[tokio::test]
    async fn tck_00181_register_validates_before_hash() {
        // Test that cheap validation runs before expensive hash verification.
        // This is verified by providing an entry with empty content (cheap check)
        // and an invalid hash - the EmptySchema error should be returned,
        // not HashMismatch.
        let registry = InMemorySchemaRegistry::new();

        let entry = SchemaEntry {
            stable_id: "test:empty.v1".to_string(),
            digest: SchemaDigest::new([42u8; 32]), // Wrong hash, but irrelevant
            content: vec![],                       // Empty content - cheap check fails first
            canonicalizer_version: "cac-json-v1".to_string(),
            registered_at: 0,
            registered_by: "test".to_string(),
        };

        let result = registry.register(&entry).await;
        assert!(
            matches!(result, Err(SchemaRegistryError::EmptySchema)),
            "Expected EmptySchema error (cheap check), not HashMismatch"
        );
    }

    #[tokio::test]
    async fn tck_00181_register_checks_conflict_with_valid_hash() {
        // Test that conflict detection works for valid entries.
        // SECURITY: Hash verification now happens BEFORE conflict check (outside
        // locks) to prevent DoS via lock contention. This means invalid hashes
        // fail early with HashMismatch, not Conflict.
        //
        // This test verifies conflict detection with VALID hashes.
        let registry = InMemorySchemaRegistry::new();

        let entry1 = make_entry("test:schema.v1", br#"{"id": 1}"#);
        registry.register(&entry1).await.unwrap();

        // Conflicting entry with same stable ID but different content (valid hash)
        let entry2 = make_entry("test:schema.v1", br#"{"id": 2}"#);

        let result = registry.register(&entry2).await;
        assert!(
            matches!(result, Err(SchemaRegistryError::Conflict { .. })),
            "Expected Conflict error for same stable_id with different content"
        );
    }

    #[tokio::test]
    async fn tck_00181_register_hash_verified_before_conflict_check() {
        // SECURITY: Verify that hash is checked BEFORE acquiring locks.
        // This prevents DoS where an attacker submits entries with invalid
        // hashes to hold locks during expensive validation.
        //
        // Invalid hash should fail with HashMismatch even if stable_id would
        // conflict with an existing entry.
        let registry = InMemorySchemaRegistry::new();

        let entry1 = make_entry("test:schema.v1", br#"{"id": 1}"#);
        registry.register(&entry1).await.unwrap();

        // Entry with same stable ID but INVALID hash
        let entry2 = SchemaEntry {
            stable_id: "test:schema.v1".to_string(),
            digest: SchemaDigest::new([42u8; 32]), // Wrong hash
            content: br#"{"id": 2}"#.to_vec(),     // Different content
            canonicalizer_version: "cac-json-v1".to_string(),
            registered_at: 0,
            registered_by: "test".to_string(),
        };

        let result = registry.register(&entry2).await;
        // HashMismatch is returned because hash verification happens BEFORE
        // conflict check (outside locks, per staging pattern)
        assert!(
            matches!(result, Err(SchemaRegistryError::HashMismatch { .. })),
            "Expected HashMismatch error (hash verified before conflict check)"
        );
    }

    #[tokio::test]
    async fn tck_00181_eviction_fifo_order() {
        // Test that eviction follows FIFO order (oldest first)
        let registry = InMemorySchemaRegistry::with_capacity(3);

        let entry1 = make_entry("test:schema1.v1", br#"{"id": 1}"#);
        let entry2 = make_entry("test:schema2.v1", br#"{"id": 2}"#);
        let entry3 = make_entry("test:schema3.v1", br#"{"id": 3}"#);
        let entry4 = make_entry("test:schema4.v1", br#"{"id": 4}"#);
        let entry5 = make_entry("test:schema5.v1", br#"{"id": 5}"#);

        // Register 1, 2, 3
        registry.register(&entry1).await.unwrap();
        registry.register(&entry2).await.unwrap();
        registry.register(&entry3).await.unwrap();
        assert_eq!(registry.count(), 3);

        // Register 4 - should evict 1
        registry.register(&entry4).await.unwrap();
        assert_eq!(registry.count(), 3);
        assert!(
            registry
                .lookup_by_digest(&entry1.digest)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            registry
                .lookup_by_digest(&entry2.digest)
                .await
                .unwrap()
                .is_some()
        );

        // Register 5 - should evict 2
        registry.register(&entry5).await.unwrap();
        assert_eq!(registry.count(), 3);
        assert!(
            registry
                .lookup_by_digest(&entry2.digest)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            registry
                .lookup_by_digest(&entry3.digest)
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            registry
                .lookup_by_digest(&entry4.digest)
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            registry
                .lookup_by_digest(&entry5.digest)
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn tck_00181_duplicate_registration_no_eviction() {
        // Test that re-registering an existing entry does not trigger eviction
        let registry = InMemorySchemaRegistry::with_capacity(2);

        let entry1 = make_entry("test:schema1.v1", br#"{"id": 1}"#);
        let entry2 = make_entry("test:schema2.v1", br#"{"id": 2}"#);

        registry.register(&entry1).await.unwrap();
        registry.register(&entry2).await.unwrap();
        assert_eq!(registry.count(), 2);

        // Re-register entry1 (duplicate) - should be a no-op, no eviction
        registry.register(&entry1).await.unwrap();
        assert_eq!(registry.count(), 2);

        // Both entries should still exist
        assert!(
            registry
                .lookup_by_digest(&entry1.digest)
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            registry
                .lookup_by_digest(&entry2.digest)
                .await
                .unwrap()
                .is_some()
        );
    }

    // =========================================================================
    // Concurrent access tests for deadlock prevention ([INV-0015])
    // =========================================================================

    #[tokio::test]
    async fn tck_00181_concurrent_register_and_lookup() {
        // Test that concurrent register and lookup operations don't deadlock.
        // This validates the lock ordering fix ([INV-0015]).
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::time::Duration;

        let registry = InMemorySchemaRegistry::new();
        let completed = Arc::new(AtomicBool::new(false));
        let completed_clone = Arc::clone(&completed);

        // Pre-register some schemas
        for i in 0..10 {
            let entry = make_entry(
                &format!("test:schema{i}.v1"),
                format!(r#"{{"id": {i}}}"#).as_bytes(),
            );
            registry.register(&entry).await.unwrap();
        }

        let registry1 = registry.clone();
        let registry2 = registry.clone();

        // Spawn concurrent tasks
        let handle1 = tokio::spawn(async move {
            for i in 10..100 {
                let entry = make_entry(
                    &format!("test:schema{i}.v1"),
                    format!(r#"{{"id": {i}}}"#).as_bytes(),
                );
                registry1.register(&entry).await.unwrap();
            }
        });

        let handle2 = tokio::spawn(async move {
            for i in 0..100 {
                let _ = registry2
                    .lookup_by_stable_id(&format!("test:schema{i}.v1"))
                    .await;
            }
        });

        // Use a timeout to detect deadlocks
        let timeout_handle = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(5)).await;
            assert!(
                completed_clone.load(Ordering::SeqCst),
                "Deadlock detected: concurrent operations did not complete within 5 seconds"
            );
        });

        // Wait for both operations to complete
        handle1.await.unwrap();
        handle2.await.unwrap();
        completed.store(true, Ordering::SeqCst);

        // Cancel the timeout
        timeout_handle.abort();
    }

    #[tokio::test]
    async fn tck_00181_concurrent_lookups() {
        // Test concurrent lookups from multiple tasks don't cause issues.
        let registry = InMemorySchemaRegistry::new();

        // Register some schemas
        for i in 0..50 {
            let entry = make_entry(
                &format!("test:schema{i}.v1"),
                format!(r#"{{"id": {i}}}"#).as_bytes(),
            );
            registry.register(&entry).await.unwrap();
        }

        // Spawn many concurrent lookup tasks
        let mut handles = Vec::new();
        for _ in 0..10 {
            let registry_clone = registry.clone();
            handles.push(tokio::spawn(async move {
                for i in 0_u8..50 {
                    let _ = registry_clone
                        .lookup_by_stable_id(&format!("test:schema{i}.v1"))
                        .await;
                    let digest = SchemaDigest::new([i; 32]);
                    let _ = registry_clone.lookup_by_digest(&digest).await;
                }
            }));
        }

        // All should complete without deadlock
        for handle in handles {
            handle.await.unwrap();
        }
    }

    #[tokio::test]
    async fn tck_00181_eviction_removes_stable_id_mapping() {
        // Test that eviction properly removes the stable_id mapping (no ghost entries).
        let registry = InMemorySchemaRegistry::with_capacity(2);

        let entry1 = make_entry("test:schema1.v1", br#"{"id": 1}"#);
        let entry2 = make_entry("test:schema2.v1", br#"{"id": 2}"#);
        let entry3 = make_entry("test:schema3.v1", br#"{"id": 3}"#);

        registry.register(&entry1).await.unwrap();
        registry.register(&entry2).await.unwrap();

        // Verify entry1 is accessible by stable_id
        assert!(
            registry
                .lookup_by_stable_id("test:schema1.v1")
                .await
                .unwrap()
                .is_some()
        );

        // Register entry3 - should evict entry1
        registry.register(&entry3).await.unwrap();

        // entry1's stable_id should no longer resolve (no ghost entry)
        assert!(
            registry
                .lookup_by_stable_id("test:schema1.v1")
                .await
                .unwrap()
                .is_none(),
            "Evicted entry's stable_id should not resolve (no ghost entries)"
        );

        // entry2 and entry3 should still work
        assert!(
            registry
                .lookup_by_stable_id("test:schema2.v1")
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            registry
                .lookup_by_stable_id("test:schema3.v1")
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn tck_00181_no_unbounded_stable_id_growth() {
        // SECURITY: Test that we can't create unbounded stable_ids for the same digest.
        // [INV-0014]: First stable_id wins - prevents alias hijacking attacks.
        let registry = InMemorySchemaRegistry::with_capacity(10);
        let content = br#"{"type": "object"}"#;

        // Try to register the same content with 100 different stable_ids
        for i in 0..100 {
            let entry = make_entry(&format!("test:alias{i}.v1"), content);
            registry.register(&entry).await.unwrap();
        }

        // Should still only have 1 schema (the FIRST one registered)
        assert_eq!(registry.count(), 1, "Should only have one schema stored");

        // Only the FIRST stable_id should work (first wins)
        assert!(
            registry
                .lookup_by_stable_id("test:alias0.v1")
                .await
                .unwrap()
                .is_some(),
            "First registered stable_id should work"
        );
        assert!(
            registry
                .lookup_by_stable_id("test:alias99.v1")
                .await
                .unwrap()
                .is_none(),
            "Later stable_ids should not work (first wins)"
        );
    }
}
