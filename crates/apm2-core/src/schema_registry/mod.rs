//! Schema registry for distributed schema governance.
//!
//! This module provides the schema registry infrastructure for APM2's
//! distributed consensus layer. All nodes must agree on schema digests
//! before accepting events, implementing a fail-closed policy.
//!
//! # Architecture
//!
//! ```text
//! +-------------------+     +-------------------+
//! |   Node A          |     |   Node B          |
//! |  SchemaRegistry   |<--->|  SchemaRegistry   |
//! +-------------------+     +-------------------+
//!         |                         |
//!         v                         v
//!    [Handshake]               [Handshake]
//!         |                         |
//!         +-------------------------+
//!                     |
//!                     v
//!            [Schema Agreement]
//! ```
//!
//! # Key Concepts
//!
//! - **Schema Digest**: BLAKE3 hash of canonical schema content, used as the
//!   primary identifier
//! - **Stable ID**: Human-readable identifier (e.g., `dcp://org/schema@v1`)
//! - **Fail-Closed**: Unknown schemas cause rejection, never silent acceptance
//! - **Handshake**: Peers exchange digests to verify compatibility
//!
//! # Security Properties
//!
//! - **Content verification**: Digests are verified against content on
//!   registration
//! - **Bounded storage**: Registries have capacity limits to prevent exhaustion
//! - **Immutability**: Registered schemas cannot be modified
//!
//! # Design Decision DD-0004 (RFC-0014)
//!
//! "Implement a distributed schema registry where all nodes must agree on
//! schema digests before accepting events. Unknown schemas trigger rejection
//! (fail-closed)."
//!
//! # Example
//!
//! ```rust
//! use apm2_core::crypto::EventHasher;
//! use apm2_core::schema_registry::{
//!     InMemorySchemaRegistry, SchemaDigest, SchemaEntry, SchemaRegistry,
//! };
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create a registry
//! let registry = InMemorySchemaRegistry::new();
//!
//! // Create a schema entry
//! let content = br#"{"type": "object"}"#;
//! let digest = SchemaDigest::new(EventHasher::hash_content(content));
//! let entry = SchemaEntry {
//!     stable_id: "test:schema.v1".to_string(),
//!     digest,
//!     content: content.to_vec().into(),
//!     canonicalizer_version: "cac-json-v1".to_string(),
//!     registered_at: 0,
//!     registered_by: "system".to_string(),
//! };
//!
//! // Register the schema
//! registry.register(&entry).await?;
//!
//! // Look up by digest (fail-closed: returns None for unknown)
//! if let Some(found) = registry.lookup_by_digest(&digest).await? {
//!     println!("Found: {}", found.stable_id);
//! }
//! # Ok(())
//! # }
//! ```

mod memory;
mod traits;

use bytes::Bytes;
pub use memory::InMemorySchemaRegistry;
pub use traits::{
    BoxFuture, DEFAULT_MAX_SCHEMAS, HandshakeResult, MAX_SCHEMA_SIZE, SchemaDigest, SchemaEntry,
    SchemaRegistry, SchemaRegistryError,
};

use crate::crypto::EventHasher;

/// Canonicalizer version for kernel schemas.
///
/// This matches the version used in the determinism module.
pub const KERNEL_CANONICALIZER_VERSION: &str = "cac-json-v1";

/// Kernel schema stable ID prefix.
pub const KERNEL_SCHEMA_PREFIX: &str = "kernel:";

/// Creates a schema entry for a kernel event type.
///
/// This is a helper for registering core kernel schemas during bootstrap.
///
/// # Arguments
///
/// * `type_name` - The event type name (e.g., `"session.started"`)
/// * `content` - The JSON schema content
///
/// # Returns
///
/// A `SchemaEntry` with computed digest and kernel metadata.
/// Note: `registered_at` is set to 0; callers should update this if timestamp
/// tracking is needed.
///
/// # Example
///
/// ```rust
/// use apm2_core::schema_registry::create_kernel_schema;
///
/// let entry = create_kernel_schema(
///     "session.started",
///     br#"{"type": "object", "properties": {"session_id": {"type": "string"}}}"#,
/// );
/// assert!(entry.stable_id.starts_with("kernel:"));
/// ```
#[must_use]
pub fn create_kernel_schema(type_name: &str, content: &[u8]) -> SchemaEntry {
    let digest = SchemaDigest::new(EventHasher::hash_content(content));
    SchemaEntry {
        stable_id: format!("{KERNEL_SCHEMA_PREFIX}{type_name}"),
        digest,
        content: Bytes::copy_from_slice(content),
        canonicalizer_version: KERNEL_CANONICALIZER_VERSION.to_string(),
        registered_at: 0,
        registered_by: "kernel".to_string(),
    }
}

/// Core kernel event schema definitions.
///
/// These schemas are registered during kernel bootstrap and define the
/// structure of all kernel events.
pub mod kernel_schemas {
    /// Session started event schema.
    pub const SESSION_STARTED: &[u8] = br#"{
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "required": ["session_id", "actor_id", "adapter_type", "work_id"],
        "properties": {
            "session_id": {"type": "string"},
            "actor_id": {"type": "string"},
            "adapter_type": {"type": "string"},
            "work_id": {"type": "string"},
            "lease_id": {"type": "string"},
            "entropy_budget": {"type": "integer"},
            "resume_cursor": {"type": "integer"},
            "restart_attempt": {"type": "integer"}
        }
    }"#;

    /// Session terminated event schema.
    pub const SESSION_TERMINATED: &[u8] = br#"{
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "required": ["session_id", "reason"],
        "properties": {
            "session_id": {"type": "string"},
            "reason": {"type": "string"},
            "exit_code": {"type": "integer"},
            "signal": {"type": "integer"},
            "entropy_used": {"type": "integer"}
        }
    }"#;

    /// Lease issued event schema.
    pub const LEASE_ISSUED: &[u8] = br#"{
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "required": ["lease_id", "work_id", "actor_id", "scope_hash"],
        "properties": {
            "lease_id": {"type": "string"},
            "work_id": {"type": "string"},
            "actor_id": {"type": "string"},
            "scope_hash": {"type": "string"},
            "budget_hash": {"type": "string"},
            "expires_at": {"type": "integer"}
        }
    }"#;

    /// Evidence published event schema.
    pub const EVIDENCE_PUBLISHED: &[u8] = br#"{
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "required": ["evidence_id", "work_id", "artifact_hash", "category"],
        "properties": {
            "evidence_id": {"type": "string"},
            "work_id": {"type": "string"},
            "artifact_hash": {"type": "string"},
            "artifact_size": {"type": "integer"},
            "category": {"type": "string"},
            "classification": {"type": "string"},
            "verification_command_ids": {
                "type": "array",
                "items": {"type": "string"}
            }
        }
    }"#;

    /// Tool requested event schema.
    pub const TOOL_REQUESTED: &[u8] = br#"{
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "required": ["request_id", "session_id", "tool_name"],
        "properties": {
            "request_id": {"type": "string"},
            "session_id": {"type": "string"},
            "tool_name": {"type": "string"},
            "arguments_hash": {"type": "string"},
            "capability_proof": {"type": "string"}
        }
    }"#;

    /// Work opened event schema.
    pub const WORK_OPENED: &[u8] = br#"{
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "required": ["work_id", "title"],
        "properties": {
            "work_id": {"type": "string"},
            "title": {"type": "string"},
            "description": {"type": "string"},
            "parent_work_id": {"type": "string"},
            "assigned_to": {"type": "string"}
        }
    }"#;

    /// All kernel schema definitions with their type names.
    pub const ALL_SCHEMAS: &[(&str, &[u8])] = &[
        ("session.started", SESSION_STARTED),
        ("session.terminated", SESSION_TERMINATED),
        ("lease.issued", LEASE_ISSUED),
        ("evidence.published", EVIDENCE_PUBLISHED),
        ("tool.requested", TOOL_REQUESTED),
        ("work.opened", WORK_OPENED),
    ];
}

/// Registers all core kernel schemas with the given registry.
///
/// This function should be called during kernel bootstrap to ensure all
/// kernel event types are registered before processing any events.
///
/// # Arguments
///
/// * `registry` - The schema registry to register schemas with
///
/// # Errors
///
/// Returns an error if any schema fails to register (e.g., registry full).
///
/// # Example
///
/// ```rust
/// use apm2_core::schema_registry::{InMemorySchemaRegistry, register_kernel_schemas};
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let registry = InMemorySchemaRegistry::new();
/// register_kernel_schemas(&registry).await?;
/// # Ok(())
/// # }
/// ```
pub async fn register_kernel_schemas<R: SchemaRegistry>(
    registry: &R,
) -> Result<(), SchemaRegistryError> {
    for (type_name, content) in kernel_schemas::ALL_SCHEMAS {
        let entry = create_kernel_schema(type_name, content);
        registry.register(&entry).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tck_00181_create_kernel_schema() {
        let entry = create_kernel_schema("test.event", br#"{"type": "object"}"#);

        assert_eq!(entry.stable_id, "kernel:test.event");
        assert_eq!(entry.canonicalizer_version, KERNEL_CANONICALIZER_VERSION);
        assert_eq!(entry.registered_by, "kernel");
        assert!(!entry.content.is_empty());
    }

    #[test]
    fn tck_00181_kernel_schema_prefix() {
        assert_eq!(KERNEL_SCHEMA_PREFIX, "kernel:");
    }

    #[tokio::test]
    async fn tck_00181_register_kernel_schemas() {
        let registry = InMemorySchemaRegistry::new();

        register_kernel_schemas(&registry).await.unwrap();

        // Verify all schemas are registered
        let count = registry.len().await.unwrap();
        assert_eq!(count, kernel_schemas::ALL_SCHEMAS.len());

        // Verify each schema is accessible
        for (type_name, _) in kernel_schemas::ALL_SCHEMAS {
            let stable_id = format!("{KERNEL_SCHEMA_PREFIX}{type_name}");
            let found = registry.lookup_by_stable_id(&stable_id).await.unwrap();
            assert!(found.is_some(), "Schema {stable_id} not found");
        }
    }

    #[tokio::test]
    async fn tck_00181_register_kernel_schemas_idempotent() {
        let registry = InMemorySchemaRegistry::new();

        // Register twice - should be idempotent
        register_kernel_schemas(&registry).await.unwrap();
        register_kernel_schemas(&registry).await.unwrap();

        let count = registry.len().await.unwrap();
        assert_eq!(count, kernel_schemas::ALL_SCHEMAS.len());
    }

    #[tokio::test]
    async fn tck_00181_kernel_schema_digests_deterministic() {
        let entry1 = create_kernel_schema("session.started", kernel_schemas::SESSION_STARTED);
        let entry2 = create_kernel_schema("session.started", kernel_schemas::SESSION_STARTED);

        // Same content should produce same digest
        assert_eq!(entry1.digest, entry2.digest);
    }

    #[test]
    fn tck_00181_all_kernel_schemas_valid() {
        // Verify all kernel schemas can be created without panicking
        for (type_name, content) in kernel_schemas::ALL_SCHEMAS {
            let entry = create_kernel_schema(type_name, content);
            assert!(!entry.stable_id.is_empty());
            assert!(!entry.content.is_empty());

            // Verify the content is valid JSON
            let parsed: Result<serde_json::Value, _> = serde_json::from_slice(&entry.content);
            assert!(
                parsed.is_ok(),
                "Kernel schema {type_name} is not valid JSON: {:?}",
                parsed.err()
            );
        }
    }

    #[tokio::test]
    async fn tck_00181_handshake_with_kernel_schemas() {
        let registry1 = InMemorySchemaRegistry::new();
        let registry2 = InMemorySchemaRegistry::new();

        // Register kernel schemas in both
        register_kernel_schemas(&registry1).await.unwrap();
        register_kernel_schemas(&registry2).await.unwrap();

        // Handshake should show full compatibility
        let digests = registry2.all_digests().await.unwrap();
        let result = registry1.handshake(&digests).await.unwrap();

        assert!(result.is_fully_compatible());
        assert_eq!(result.compatible.len(), kernel_schemas::ALL_SCHEMAS.len());
    }
}
