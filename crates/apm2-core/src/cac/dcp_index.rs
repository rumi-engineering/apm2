//! DCP (Deterministic Content Path) stable-ID index.
//!
//! The DCP index is a projection over ledger events that maps stable
//! identifiers to content hashes for artifact resolution. It enables:
//!
//! - **Stable references**: Artifacts can be referenced by human-readable names
//!   (e.g., `org:ticket:TCK-00134@v1`) instead of raw content hashes
//! - **Schema tracking**: Each artifact entry tracks its schema for validation
//! - **Dependency graphs**: Edges between artifacts for impact analysis
//! - **Collision detection**: Duplicate `stable_id` registrations are rejected
//!
//! # Architecture
//!
//! Per DD-0008, the DCP index is a projection over the authoritative ledger:
//!
//! ```text
//! Ledger Events --> DCP Index Reducer --> DCP Index (Projection)
//!                                              |
//!                                        stable_id -> content_hash
//!                                        schema tracking
//!                                        dependency graph
//! ```
//!
//! The index can be rebuilt from scratch by replaying ledger events.
//!
//! # Namespace Format
//!
//! Stable IDs follow the format: `namespace:kind:identifier[@version]`
//!
//! Examples:
//! - `org:ticket:TCK-00134` (latest version)
//! - `org:ticket:TCK-00134@v1` (specific version)
//! - `cac:schema:ticket-v1` (reserved namespace)
//!
//! # Reserved Prefixes
//!
//! The following namespace prefixes are reserved:
//! - `cac:*` - Context-as-Code system artifacts
//! - `bootstrap:*` - Bootstrap configuration
//! - `internal:*` - Internal system use
//!
//! # Example
//!
//! ```rust
//! use apm2_core::cac::dcp_index::{DcpEntry, DcpIndex};
//!
//! let mut index = DcpIndex::new();
//!
//! // Register an artifact
//! let entry = DcpEntry::new(
//!     "org:ticket:TCK-00134",
//!     "abc123def456...",      // content hash
//!     "cac:schema:ticket-v1", // schema reference
//! );
//! index.register(entry).unwrap();
//!
//! // Resolve the artifact
//! let content_hash = index.resolve("org:ticket:TCK-00134");
//! assert!(content_hash.is_some());
//! ```

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::ledger::{EventRecord, LedgerError};
use crate::reducer::{Reducer, ReducerContext};

/// Reserved namespace prefixes that require special permissions.
pub const RESERVED_PREFIXES: &[&str] = &["cac:", "bootstrap:", "internal:"];

/// Maximum length for stable IDs.
pub const MAX_STABLE_ID_LENGTH: usize = 1024;

/// Maximum length for content hashes (hex-encoded BLAKE3 = 64 chars).
pub const MAX_CONTENT_HASH_LENGTH: usize = 64;

/// Event type for artifact registration in the ledger.
pub const EVENT_TYPE_ARTIFACT_REGISTERED: &str = "dcp.artifact.registered";

/// Event type for artifact deprecation in the ledger.
pub const EVENT_TYPE_ARTIFACT_DEPRECATED: &str = "dcp.artifact.deprecated";

/// Errors that can occur during DCP index operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DcpIndexError {
    /// A `stable_id` collision was detected.
    #[error(
        "collision: stable_id '{stable_id}' already registered with content_hash '{existing_hash}'"
    )]
    Collision {
        /// The stable ID that collided.
        stable_id: String,
        /// The existing content hash for this stable ID.
        existing_hash: String,
        /// The new content hash that was attempted.
        new_hash: String,
    },

    /// The `stable_id` format is invalid.
    #[error("invalid stable_id format: {reason}")]
    InvalidStableId {
        /// The reason the stable ID is invalid.
        reason: String,
    },

    /// The `stable_id` uses a reserved prefix without authorization.
    #[error("reserved prefix: stable_id '{stable_id}' uses reserved prefix '{prefix}'")]
    ReservedPrefix {
        /// The stable ID that used a reserved prefix.
        stable_id: String,
        /// The reserved prefix that was used.
        prefix: String,
    },

    /// The content hash format is invalid.
    #[error("invalid content_hash: {reason}")]
    InvalidContentHash {
        /// The reason the content hash is invalid.
        reason: String,
    },

    /// A dependency reference is invalid.
    #[error("invalid dependency: '{dependency}' does not exist in the index")]
    InvalidDependency {
        /// The dependency that doesn't exist.
        dependency: String,
    },

    /// The `stable_id` was not found in the index.
    #[error("not found: stable_id '{stable_id}' does not exist")]
    NotFound {
        /// The stable ID that was not found.
        stable_id: String,
    },

    /// Ledger error during index rebuild.
    #[error("ledger error: {0}")]
    Ledger(String),
}

impl From<LedgerError> for DcpIndexError {
    fn from(err: LedgerError) -> Self {
        Self::Ledger(err.to_string())
    }
}

/// A single entry in the DCP index.
///
/// Each entry maps a stable identifier to its content hash and metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DcpEntry {
    /// The stable identifier (e.g., "org:ticket:TCK-00134@v1").
    pub stable_id: String,

    /// The BLAKE3 content hash (hex-encoded).
    pub content_hash: String,

    /// Reference to the schema used for validation.
    pub schema_id: String,

    /// Dependencies on other artifacts (`stable_ids`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dependencies: Vec<String>,

    /// Timestamp when this entry was registered (nanoseconds since epoch).
    #[serde(default)]
    pub registered_at_ns: u64,

    /// Whether this entry has been deprecated.
    #[serde(default)]
    pub deprecated: bool,
}

impl DcpEntry {
    /// Creates a new DCP entry.
    ///
    /// # Arguments
    ///
    /// * `stable_id` - The stable identifier
    /// * `content_hash` - The BLAKE3 content hash (hex-encoded)
    /// * `schema_id` - Reference to the validation schema
    #[must_use]
    pub fn new(
        stable_id: impl Into<String>,
        content_hash: impl Into<String>,
        schema_id: impl Into<String>,
    ) -> Self {
        Self {
            stable_id: stable_id.into(),
            content_hash: content_hash.into(),
            schema_id: schema_id.into(),
            dependencies: Vec::new(),
            registered_at_ns: 0,
            deprecated: false,
        }
    }

    /// Adds dependencies to this entry.
    #[must_use]
    pub fn with_dependencies(mut self, deps: Vec<String>) -> Self {
        self.dependencies = deps;
        self
    }

    /// Sets the registration timestamp.
    #[must_use]
    pub const fn with_timestamp(mut self, timestamp_ns: u64) -> Self {
        self.registered_at_ns = timestamp_ns;
        self
    }
}

/// The DCP stable-ID index.
///
/// This is a projection over ledger events that maintains:
/// - A map from `stable_id` to `content_hash` for resolution
/// - Schema references for each artifact
/// - Dependency graph edges between artifacts
///
/// The index can be rebuilt from scratch by replaying ledger events.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DcpIndex {
    /// Map from `stable_id` to entry.
    entries: HashMap<String, DcpEntry>,

    /// Reverse map from `content_hash` to `stable_ids` (for deduplication
    /// queries).
    #[serde(default)]
    content_to_stable: HashMap<String, HashSet<String>>,

    /// Dependents graph: `stable_id` -> set of `stable_ids` that depend on it.
    #[serde(default)]
    dependents: HashMap<String, HashSet<String>>,

    /// Last processed ledger sequence ID.
    #[serde(default)]
    last_seq_id: u64,

    /// Whether to enforce reserved prefix restrictions.
    #[serde(default = "default_enforce_reserved")]
    enforce_reserved: bool,
}

const fn default_enforce_reserved() -> bool {
    true
}

impl DcpIndex {
    /// Creates a new empty DCP index.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            content_to_stable: HashMap::new(),
            dependents: HashMap::new(),
            last_seq_id: 0,
            enforce_reserved: true,
        }
    }

    /// Creates a new DCP index with reserved prefix enforcement disabled.
    ///
    /// This is intended for internal/bootstrap use only.
    #[must_use]
    pub fn new_unrestricted() -> Self {
        Self {
            entries: HashMap::new(),
            content_to_stable: HashMap::new(),
            dependents: HashMap::new(),
            last_seq_id: 0,
            enforce_reserved: false,
        }
    }

    /// Resolves a `stable_id` to its content hash.
    ///
    /// Returns `None` if the `stable_id` is not registered or is deprecated.
    #[must_use]
    pub fn resolve(&self, stable_id: &str) -> Option<&str> {
        self.entries.get(stable_id).and_then(|entry| {
            if entry.deprecated {
                None
            } else {
                Some(entry.content_hash.as_str())
            }
        })
    }

    /// Resolves a `stable_id` to its full entry.
    ///
    /// Returns `None` if the `stable_id` is not registered.
    /// Note: This returns entries even if deprecated (for audit purposes).
    #[must_use]
    pub fn get_entry(&self, stable_id: &str) -> Option<&DcpEntry> {
        self.entries.get(stable_id)
    }

    /// Registers a new artifact entry in the index.
    ///
    /// # Errors
    ///
    /// - [`DcpIndexError::Collision`] if the `stable_id` is already registered
    ///   with a different `content_hash`
    /// - [`DcpIndexError::InvalidStableId`] if the `stable_id` format is
    ///   invalid
    /// - [`DcpIndexError::ReservedPrefix`] if the `stable_id` uses a reserved
    ///   prefix without authorization
    /// - [`DcpIndexError::InvalidContentHash`] if the `content_hash` is invalid
    /// - [`DcpIndexError::InvalidDependency`] if a dependency doesn't exist
    pub fn register(&mut self, entry: DcpEntry) -> Result<(), DcpIndexError> {
        // Validate stable_id format
        validate_stable_id(&entry.stable_id)?;

        // Check reserved prefixes
        if self.enforce_reserved {
            check_reserved_prefix(&entry.stable_id)?;
        }

        // Validate content_hash format
        validate_content_hash(&entry.content_hash)?;

        // Check for collision
        if let Some(existing) = self.entries.get(&entry.stable_id) {
            if existing.content_hash != entry.content_hash {
                return Err(DcpIndexError::Collision {
                    stable_id: entry.stable_id.clone(),
                    existing_hash: existing.content_hash.clone(),
                    new_hash: entry.content_hash.clone(),
                });
            }
            // Same hash = idempotent, no-op
            return Ok(());
        }

        // Validate dependencies exist
        for dep in &entry.dependencies {
            if !self.entries.contains_key(dep) {
                return Err(DcpIndexError::InvalidDependency {
                    dependency: dep.clone(),
                });
            }
        }

        // Update reverse index
        self.content_to_stable
            .entry(entry.content_hash.clone())
            .or_default()
            .insert(entry.stable_id.clone());

        // Update dependents graph
        for dep in &entry.dependencies {
            self.dependents
                .entry(dep.clone())
                .or_default()
                .insert(entry.stable_id.clone());
        }

        // Insert entry
        self.entries.insert(entry.stable_id.clone(), entry);

        Ok(())
    }

    /// Deprecates an artifact, making it unresolvable.
    ///
    /// The entry is kept for audit purposes but `resolve()` will return `None`.
    ///
    /// # Errors
    ///
    /// Returns [`DcpIndexError::NotFound`] if the `stable_id` doesn't exist.
    pub fn deprecate(&mut self, stable_id: &str) -> Result<(), DcpIndexError> {
        let entry = self
            .entries
            .get_mut(stable_id)
            .ok_or_else(|| DcpIndexError::NotFound {
                stable_id: stable_id.to_string(),
            })?;

        entry.deprecated = true;
        Ok(())
    }

    /// Returns all `stable_ids` that point to a given content hash.
    #[must_use]
    pub fn find_by_content_hash(&self, content_hash: &str) -> Vec<&str> {
        self.content_to_stable
            .get(content_hash)
            .map(|set| set.iter().map(String::as_str).collect())
            .unwrap_or_default()
    }

    /// Returns all `stable_ids` that depend on the given artifact.
    #[must_use]
    pub fn get_dependents(&self, stable_id: &str) -> Vec<&str> {
        self.dependents
            .get(stable_id)
            .map(|set| set.iter().map(String::as_str).collect())
            .unwrap_or_default()
    }

    /// Returns the dependencies of an artifact.
    #[must_use]
    pub fn get_dependencies(&self, stable_id: &str) -> Vec<&str> {
        self.entries
            .get(stable_id)
            .map(|entry| entry.dependencies.iter().map(String::as_str).collect())
            .unwrap_or_default()
    }

    /// Returns the total number of registered entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns true if the index is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns the last processed ledger sequence ID.
    #[must_use]
    pub const fn last_seq_id(&self) -> u64 {
        self.last_seq_id
    }

    /// Returns an iterator over all entries.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &DcpEntry)> {
        self.entries.iter().map(|(k, v)| (k.as_str(), v))
    }

    /// Clears the index and resets state.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.content_to_stable.clear();
        self.dependents.clear();
        self.last_seq_id = 0;
    }

    /// Applies a ledger event to update the index.
    ///
    /// This is the core reducer logic for building the index from events.
    ///
    /// # Errors
    ///
    /// Returns an error if the event payload is malformed or violates index
    /// constraints.
    pub fn apply_event(&mut self, event: &EventRecord) -> Result<(), DcpIndexError> {
        match event.event_type.as_str() {
            EVENT_TYPE_ARTIFACT_REGISTERED => {
                let entry: DcpEntry = serde_json::from_slice(&event.payload).map_err(|e| {
                    DcpIndexError::InvalidStableId {
                        reason: format!("failed to parse event payload: {e}"),
                    }
                })?;

                // During replay, we allow reserved prefixes (they were already validated)
                let old_enforce = self.enforce_reserved;
                self.enforce_reserved = false;
                let result = self.register(entry);
                self.enforce_reserved = old_enforce;

                result?;
            },
            EVENT_TYPE_ARTIFACT_DEPRECATED => {
                #[derive(Deserialize)]
                struct DeprecatePayload {
                    stable_id: String,
                }

                let payload: DeprecatePayload =
                    serde_json::from_slice(&event.payload).map_err(|e| {
                        DcpIndexError::InvalidStableId {
                            reason: format!("failed to parse deprecate payload: {e}"),
                        }
                    })?;

                self.deprecate(&payload.stable_id)?;
            },
            _ => {
                // Ignore unknown event types
            },
        }

        if let Some(seq_id) = event.seq_id {
            self.last_seq_id = seq_id;
        }

        Ok(())
    }
}

/// Validates `stable_id` format: `namespace:kind:identifier[@version]`
fn validate_stable_id(stable_id: &str) -> Result<(), DcpIndexError> {
    // Check empty
    if stable_id.is_empty() {
        return Err(DcpIndexError::InvalidStableId {
            reason: "stable_id cannot be empty".to_string(),
        });
    }

    // Check length
    if stable_id.len() > MAX_STABLE_ID_LENGTH {
        return Err(DcpIndexError::InvalidStableId {
            reason: format!(
                "stable_id exceeds maximum length of {} (got {})",
                MAX_STABLE_ID_LENGTH,
                stable_id.len()
            ),
        });
    }

    // Check for control characters
    if let Some(pos) = stable_id.chars().position(char::is_control) {
        return Err(DcpIndexError::InvalidStableId {
            reason: format!("stable_id contains control character at position {pos}"),
        });
    }

    // Parse format: namespace:kind:identifier[@version]
    let (base, _version) = stable_id.rfind('@').map_or((stable_id, None), |at_pos| {
        (&stable_id[..at_pos], Some(&stable_id[at_pos + 1..]))
    });

    // Must have at least 3 colon-separated parts
    let parts: Vec<&str> = base.split(':').collect();
    if parts.len() < 3 {
        return Err(DcpIndexError::InvalidStableId {
            reason: format!(
                "stable_id must have format 'namespace:kind:identifier', got {} parts",
                parts.len()
            ),
        });
    }

    // Each part must be non-empty
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            return Err(DcpIndexError::InvalidStableId {
                reason: format!("stable_id part {} is empty", i + 1),
            });
        }
    }

    Ok(())
}

/// Checks if `stable_id` uses a reserved prefix.
fn check_reserved_prefix(stable_id: &str) -> Result<(), DcpIndexError> {
    for prefix in RESERVED_PREFIXES {
        if stable_id.starts_with(prefix) {
            return Err(DcpIndexError::ReservedPrefix {
                stable_id: stable_id.to_string(),
                prefix: (*prefix).to_string(),
            });
        }
    }
    Ok(())
}

/// Validates content hash format (hex-encoded BLAKE3).
fn validate_content_hash(content_hash: &str) -> Result<(), DcpIndexError> {
    if content_hash.is_empty() {
        return Err(DcpIndexError::InvalidContentHash {
            reason: "content_hash cannot be empty".to_string(),
        });
    }

    if content_hash.len() != MAX_CONTENT_HASH_LENGTH {
        return Err(DcpIndexError::InvalidContentHash {
            reason: format!(
                "content_hash must be {} hex characters (got {})",
                MAX_CONTENT_HASH_LENGTH,
                content_hash.len()
            ),
        });
    }

    // Validate hex characters
    if !content_hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(DcpIndexError::InvalidContentHash {
            reason: "content_hash must contain only hexadecimal characters".to_string(),
        });
    }

    Ok(())
}

/// Parses a `stable_id` into its components.
///
/// Returns (namespace, kind, identifier, version) where version is optional.
#[must_use]
pub fn parse_stable_id(stable_id: &str) -> Option<(&str, &str, &str, Option<&str>)> {
    let (base, version) = stable_id.rfind('@').map_or((stable_id, None), |at_pos| {
        (&stable_id[..at_pos], Some(&stable_id[at_pos + 1..]))
    });

    let parts: Vec<&str> = base.splitn(3, ':').collect();
    if parts.len() < 3 {
        return None;
    }

    Some((parts[0], parts[1], parts[2], version))
}

// ============================================================================
// Reducer Implementation
// ============================================================================

/// Reducer state for the DCP index.
pub type DcpIndexState = DcpIndex;

/// Error type for DCP index reducer.
#[derive(Debug, Error)]
pub enum DcpIndexReducerError {
    /// Index operation failed.
    #[error("index error: {0}")]
    Index(#[from] DcpIndexError),
}

/// DCP index reducer for processing ledger events.
#[derive(Debug, Default)]
pub struct DcpIndexReducer {
    index: DcpIndex,
}

impl DcpIndexReducer {
    /// Creates a new DCP index reducer.
    #[must_use]
    pub fn new() -> Self {
        Self {
            index: DcpIndex::new_unrestricted(), // Reducer allows all prefixes
        }
    }

    /// Returns a reference to the underlying index.
    #[must_use]
    pub const fn index(&self) -> &DcpIndex {
        &self.index
    }
}

impl Reducer for DcpIndexReducer {
    type State = DcpIndexState;
    type Error = DcpIndexReducerError;

    fn name(&self) -> &'static str {
        "dcp_index"
    }

    fn apply(&mut self, event: &EventRecord, _ctx: &ReducerContext) -> Result<(), Self::Error> {
        self.index.apply_event(event)?;
        Ok(())
    }

    fn state(&self) -> &Self::State {
        &self.index
    }

    fn state_mut(&mut self) -> &mut Self::State {
        &mut self.index
    }

    fn reset(&mut self) {
        self.index.clear();
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Creates a valid hex content hash for testing.
    fn test_hash() -> String {
        "a".repeat(64)
    }

    /// Creates a different valid hex content hash for testing.
    fn test_hash_2() -> String {
        "b".repeat(64)
    }

    // =========================================================================
    // DcpEntry Tests
    // =========================================================================

    #[test]
    fn test_dcp_entry_new() {
        let entry = DcpEntry::new("org:ticket:TCK-001", test_hash(), "cac:schema:ticket");

        assert_eq!(entry.stable_id, "org:ticket:TCK-001");
        assert_eq!(entry.content_hash, test_hash());
        assert_eq!(entry.schema_id, "cac:schema:ticket");
        assert!(entry.dependencies.is_empty());
        assert!(!entry.deprecated);
    }

    #[test]
    fn test_dcp_entry_with_dependencies() {
        let entry = DcpEntry::new("org:ticket:TCK-002", test_hash(), "cac:schema:ticket")
            .with_dependencies(vec!["org:ticket:TCK-001".to_string()]);

        assert_eq!(entry.dependencies.len(), 1);
        assert_eq!(entry.dependencies[0], "org:ticket:TCK-001");
    }

    #[test]
    fn test_dcp_entry_serialization() {
        let entry = DcpEntry::new("org:ticket:TCK-001", test_hash(), "cac:schema:ticket")
            .with_timestamp(1_234_567_890);

        let json = serde_json::to_string(&entry).unwrap();
        let deserialized: DcpEntry = serde_json::from_str(&json).unwrap();

        assert_eq!(entry.stable_id, deserialized.stable_id);
        assert_eq!(entry.content_hash, deserialized.content_hash);
        assert_eq!(entry.registered_at_ns, deserialized.registered_at_ns);
    }

    // =========================================================================
    // DcpIndex Basic Tests
    // =========================================================================

    #[test]
    fn test_index_new() {
        let index = DcpIndex::new();
        assert!(index.is_empty());
        assert_eq!(index.len(), 0);
    }

    #[test]
    fn test_index_register_and_resolve() {
        let mut index = DcpIndex::new();
        let entry = DcpEntry::new("org:ticket:TCK-001", test_hash(), "cac:schema:ticket");

        index.register(entry).unwrap();

        let resolved = index.resolve("org:ticket:TCK-001");
        assert_eq!(resolved, Some(test_hash().as_str()));
    }

    #[test]
    fn test_index_resolve_not_found() {
        let index = DcpIndex::new();
        assert!(index.resolve("org:ticket:NONEXISTENT").is_none());
    }

    #[test]
    fn test_index_get_entry() {
        let mut index = DcpIndex::new();
        let entry = DcpEntry::new("org:ticket:TCK-001", test_hash(), "cac:schema:ticket");

        index.register(entry.clone()).unwrap();

        let retrieved = index.get_entry("org:ticket:TCK-001").unwrap();
        assert_eq!(retrieved.stable_id, entry.stable_id);
        assert_eq!(retrieved.content_hash, entry.content_hash);
    }

    // =========================================================================
    // Collision Detection Tests
    // =========================================================================

    #[test]
    fn test_index_collision_rejected() {
        let mut index = DcpIndex::new();

        let entry1 = DcpEntry::new("org:ticket:TCK-001", test_hash(), "cac:schema:ticket");
        index.register(entry1).unwrap();

        // Same stable_id, different hash = collision
        let entry2 = DcpEntry::new("org:ticket:TCK-001", test_hash_2(), "cac:schema:ticket");
        let result = index.register(entry2);

        assert!(matches!(result, Err(DcpIndexError::Collision { .. })));
    }

    #[test]
    fn test_index_idempotent_registration() {
        let mut index = DcpIndex::new();

        let entry = DcpEntry::new("org:ticket:TCK-001", test_hash(), "cac:schema:ticket");
        index.register(entry.clone()).unwrap();

        // Same stable_id, same hash = idempotent
        let result = index.register(entry);
        assert!(result.is_ok());
        assert_eq!(index.len(), 1);
    }

    // =========================================================================
    // Reserved Prefix Tests
    // =========================================================================

    #[test]
    fn test_reserved_prefix_cac_rejected() {
        let mut index = DcpIndex::new();
        let entry = DcpEntry::new("cac:schema:test", test_hash(), "cac:schema:meta");

        let result = index.register(entry);
        assert!(matches!(result, Err(DcpIndexError::ReservedPrefix { .. })));
    }

    #[test]
    fn test_reserved_prefix_bootstrap_rejected() {
        let mut index = DcpIndex::new();
        let entry = DcpEntry::new("bootstrap:config:main", test_hash(), "cac:schema:config");

        let result = index.register(entry);
        assert!(matches!(result, Err(DcpIndexError::ReservedPrefix { .. })));
    }

    #[test]
    fn test_reserved_prefix_internal_rejected() {
        let mut index = DcpIndex::new();
        let entry = DcpEntry::new("internal:system:state", test_hash(), "cac:schema:state");

        let result = index.register(entry);
        assert!(matches!(result, Err(DcpIndexError::ReservedPrefix { .. })));
    }

    #[test]
    fn test_unrestricted_index_allows_reserved() {
        let mut index = DcpIndex::new_unrestricted();
        let entry = DcpEntry::new("cac:schema:test", test_hash(), "cac:schema:meta");

        let result = index.register(entry);
        assert!(result.is_ok());
    }

    // =========================================================================
    // Stable ID Format Validation Tests
    // =========================================================================

    #[test]
    fn test_stable_id_empty_rejected() {
        let mut index = DcpIndex::new();
        let entry = DcpEntry::new("", test_hash(), "cac:schema:ticket");

        let result = index.register(entry);
        assert!(matches!(result, Err(DcpIndexError::InvalidStableId { .. })));
    }

    #[test]
    fn test_stable_id_too_long_rejected() {
        let mut index = DcpIndex::new();
        let long_id = format!("org:ticket:{}", "x".repeat(MAX_STABLE_ID_LENGTH));
        let entry = DcpEntry::new(&long_id, test_hash(), "cac:schema:ticket");

        let result = index.register(entry);
        assert!(matches!(result, Err(DcpIndexError::InvalidStableId { .. })));
    }

    #[test]
    fn test_stable_id_control_char_rejected() {
        let mut index = DcpIndex::new();
        let entry = DcpEntry::new("org:ticket:TCK\n001", test_hash(), "cac:schema:ticket");

        let result = index.register(entry);
        assert!(matches!(result, Err(DcpIndexError::InvalidStableId { .. })));
    }

    #[test]
    fn test_stable_id_missing_parts_rejected() {
        let mut index = DcpIndex::new();

        // Only 2 parts
        let entry = DcpEntry::new("org:ticket", test_hash(), "cac:schema:ticket");
        let result = index.register(entry);
        assert!(matches!(result, Err(DcpIndexError::InvalidStableId { .. })));
    }

    #[test]
    fn test_stable_id_empty_part_rejected() {
        let mut index = DcpIndex::new();
        let entry = DcpEntry::new("org::TCK-001", test_hash(), "cac:schema:ticket");

        let result = index.register(entry);
        assert!(matches!(result, Err(DcpIndexError::InvalidStableId { .. })));
    }

    #[test]
    fn test_stable_id_with_version_valid() {
        let mut index = DcpIndex::new();
        let entry = DcpEntry::new("org:ticket:TCK-001@v1", test_hash(), "cac:schema:ticket");

        let result = index.register(entry);
        assert!(result.is_ok());
    }

    // =========================================================================
    // Content Hash Validation Tests
    // =========================================================================

    #[test]
    fn test_content_hash_empty_rejected() {
        let mut index = DcpIndex::new();
        let entry = DcpEntry::new("org:ticket:TCK-001", "", "cac:schema:ticket");

        let result = index.register(entry);
        assert!(matches!(
            result,
            Err(DcpIndexError::InvalidContentHash { .. })
        ));
    }

    #[test]
    fn test_content_hash_wrong_length_rejected() {
        let mut index = DcpIndex::new();
        let entry = DcpEntry::new("org:ticket:TCK-001", "abc123", "cac:schema:ticket");

        let result = index.register(entry);
        assert!(matches!(
            result,
            Err(DcpIndexError::InvalidContentHash { .. })
        ));
    }

    #[test]
    fn test_content_hash_non_hex_rejected() {
        let mut index = DcpIndex::new();
        let entry = DcpEntry::new("org:ticket:TCK-001", "g".repeat(64), "cac:schema:ticket");

        let result = index.register(entry);
        assert!(matches!(
            result,
            Err(DcpIndexError::InvalidContentHash { .. })
        ));
    }

    // =========================================================================
    // Dependency Tests
    // =========================================================================

    #[test]
    fn test_dependency_valid() {
        let mut index = DcpIndex::new();

        // Register dependency first
        let dep = DcpEntry::new("org:ticket:TCK-001", test_hash(), "cac:schema:ticket");
        index.register(dep).unwrap();

        // Register dependent with valid dependency
        let entry = DcpEntry::new("org:ticket:TCK-002", test_hash_2(), "cac:schema:ticket")
            .with_dependencies(vec!["org:ticket:TCK-001".to_string()]);
        let result = index.register(entry);

        assert!(result.is_ok());
    }

    #[test]
    fn test_dependency_invalid_rejected() {
        let mut index = DcpIndex::new();

        // Try to register with non-existent dependency
        let entry = DcpEntry::new("org:ticket:TCK-002", test_hash(), "cac:schema:ticket")
            .with_dependencies(vec!["org:ticket:NONEXISTENT".to_string()]);
        let result = index.register(entry);

        assert!(matches!(
            result,
            Err(DcpIndexError::InvalidDependency { .. })
        ));
    }

    #[test]
    fn test_get_dependents() {
        let mut index = DcpIndex::new();

        let dep = DcpEntry::new("org:ticket:TCK-001", test_hash(), "cac:schema:ticket");
        index.register(dep).unwrap();

        let entry = DcpEntry::new("org:ticket:TCK-002", test_hash_2(), "cac:schema:ticket")
            .with_dependencies(vec!["org:ticket:TCK-001".to_string()]);
        index.register(entry).unwrap();

        let dependents = index.get_dependents("org:ticket:TCK-001");
        assert_eq!(dependents.len(), 1);
        assert_eq!(dependents[0], "org:ticket:TCK-002");
    }

    #[test]
    fn test_get_dependencies() {
        let mut index = DcpIndex::new();

        let dep = DcpEntry::new("org:ticket:TCK-001", test_hash(), "cac:schema:ticket");
        index.register(dep).unwrap();

        let entry = DcpEntry::new("org:ticket:TCK-002", test_hash_2(), "cac:schema:ticket")
            .with_dependencies(vec!["org:ticket:TCK-001".to_string()]);
        index.register(entry).unwrap();

        let deps = index.get_dependencies("org:ticket:TCK-002");
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0], "org:ticket:TCK-001");
    }

    // =========================================================================
    // Deprecation Tests
    // =========================================================================

    #[test]
    fn test_deprecate_makes_unresolvable() {
        let mut index = DcpIndex::new();
        let entry = DcpEntry::new("org:ticket:TCK-001", test_hash(), "cac:schema:ticket");
        index.register(entry).unwrap();

        // Before deprecation
        assert!(index.resolve("org:ticket:TCK-001").is_some());

        // Deprecate
        index.deprecate("org:ticket:TCK-001").unwrap();

        // After deprecation
        assert!(index.resolve("org:ticket:TCK-001").is_none());

        // But entry still exists for audit
        assert!(index.get_entry("org:ticket:TCK-001").is_some());
    }

    #[test]
    fn test_deprecate_not_found() {
        let mut index = DcpIndex::new();
        let result = index.deprecate("org:ticket:NONEXISTENT");
        assert!(matches!(result, Err(DcpIndexError::NotFound { .. })));
    }

    // =========================================================================
    // Content Hash Lookup Tests
    // =========================================================================

    #[test]
    fn test_find_by_content_hash() {
        let mut index = DcpIndex::new();

        // Same content hash, different stable_ids
        let entry1 = DcpEntry::new("org:ticket:TCK-001", test_hash(), "cac:schema:ticket");
        let entry2 = DcpEntry::new("org:ticket:TCK-001@v1", test_hash(), "cac:schema:ticket");

        index.register(entry1).unwrap();
        index.register(entry2).unwrap();

        let stable_ids = index.find_by_content_hash(&test_hash());
        assert_eq!(stable_ids.len(), 2);
    }

    // =========================================================================
    // Ledger Event Tests
    // =========================================================================

    #[test]
    fn test_apply_event_register() {
        let mut index = DcpIndex::new_unrestricted();

        let entry = DcpEntry::new("cac:schema:test", test_hash(), "cac:schema:meta");
        let payload = serde_json::to_vec(&entry).unwrap();

        let event = EventRecord::new(
            EVENT_TYPE_ARTIFACT_REGISTERED,
            "session-1",
            "actor-1",
            payload,
        )
        .with_seq_id(1);

        index.apply_event(&event).unwrap();

        assert_eq!(index.resolve("cac:schema:test"), Some(test_hash().as_str()));
        assert_eq!(index.last_seq_id(), 1);
    }

    #[test]
    fn test_apply_event_deprecate() {
        let mut index = DcpIndex::new_unrestricted();

        // First register
        let entry = DcpEntry::new("cac:schema:test", test_hash(), "cac:schema:meta");
        index.register(entry).unwrap();

        // Then deprecate via event
        let payload = serde_json::to_vec(&serde_json::json!({
            "stable_id": "cac:schema:test"
        }))
        .unwrap();

        let event = EventRecord::new(
            EVENT_TYPE_ARTIFACT_DEPRECATED,
            "session-1",
            "actor-1",
            payload,
        )
        .with_seq_id(2);

        index.apply_event(&event).unwrap();

        assert!(index.resolve("cac:schema:test").is_none());
    }

    #[test]
    fn test_apply_event_unknown_type_ignored() {
        let mut index = DcpIndex::new();

        let event = EventRecord::new("unknown.event.type", "session-1", "actor-1", vec![]);

        let result = index.apply_event(&event);
        assert!(result.is_ok());
    }

    // =========================================================================
    // Parse Stable ID Tests
    // =========================================================================

    #[test]
    fn test_parse_stable_id_basic() {
        let result = parse_stable_id("org:ticket:TCK-001");
        assert_eq!(result, Some(("org", "ticket", "TCK-001", None)));
    }

    #[test]
    fn test_parse_stable_id_with_version() {
        let result = parse_stable_id("org:ticket:TCK-001@v1");
        assert_eq!(result, Some(("org", "ticket", "TCK-001", Some("v1"))));
    }

    #[test]
    fn test_parse_stable_id_with_colons_in_identifier() {
        // Identifier can contain colons
        let result = parse_stable_id("org:ticket:TCK:001:sub");
        assert_eq!(result, Some(("org", "ticket", "TCK:001:sub", None)));
    }

    #[test]
    fn test_parse_stable_id_invalid() {
        assert!(parse_stable_id("org:ticket").is_none());
        assert!(parse_stable_id("").is_none());
    }

    // =========================================================================
    // Reducer Tests
    // =========================================================================

    #[test]
    fn test_reducer_apply() {
        let mut reducer = DcpIndexReducer::new();

        let entry = DcpEntry::new("cac:schema:test", test_hash(), "cac:schema:meta");
        let payload = serde_json::to_vec(&entry).unwrap();

        let event = EventRecord::new(
            EVENT_TYPE_ARTIFACT_REGISTERED,
            "session-1",
            "actor-1",
            payload,
        )
        .with_seq_id(1);

        let ctx = ReducerContext::new(1);
        reducer.apply(&event, &ctx).unwrap();

        assert_eq!(
            reducer.index().resolve("cac:schema:test"),
            Some(test_hash().as_str())
        );
    }

    #[test]
    fn test_reducer_reset() {
        let mut reducer = DcpIndexReducer::new();

        let entry = DcpEntry::new("cac:schema:test", test_hash(), "cac:schema:meta");
        let payload = serde_json::to_vec(&entry).unwrap();

        let event = EventRecord::new(
            EVENT_TYPE_ARTIFACT_REGISTERED,
            "session-1",
            "actor-1",
            payload,
        );

        let ctx = ReducerContext::new(1);
        reducer.apply(&event, &ctx).unwrap();
        assert_eq!(reducer.index().len(), 1);

        reducer.reset();
        assert!(reducer.index().is_empty());
    }

    #[test]
    fn test_reducer_name() {
        let reducer = DcpIndexReducer::new();
        assert_eq!(reducer.name(), "dcp_index");
    }

    // =========================================================================
    // Index Iterator Tests
    // =========================================================================

    #[test]
    fn test_index_iter() {
        let mut index = DcpIndex::new();

        let entry1 = DcpEntry::new("org:ticket:TCK-001", test_hash(), "cac:schema:ticket");
        let entry2 = DcpEntry::new("org:ticket:TCK-002", test_hash_2(), "cac:schema:ticket");

        index.register(entry1).unwrap();
        index.register(entry2).unwrap();

        assert_eq!(index.iter().count(), 2);
    }

    // =========================================================================
    // Clear Tests
    // =========================================================================

    #[test]
    fn test_index_clear() {
        let mut index = DcpIndex::new();

        let entry = DcpEntry::new("org:ticket:TCK-001", test_hash(), "cac:schema:ticket");
        index.register(entry).unwrap();
        assert_eq!(index.len(), 1);

        index.clear();
        assert!(index.is_empty());
        assert_eq!(index.last_seq_id(), 0);
    }
}
