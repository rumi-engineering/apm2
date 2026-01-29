# Schema Registry Module

> Distributed schema governance with fail-closed validation for the APM2 consensus layer.

## Overview

The `apm2_core::schema_registry` module implements distributed schema governance where all nodes must agree on schema digests before accepting events. This follows Design Decision DD-0004 from RFC-0014.

Key security property: **Fail-closed** - unknown schemas trigger rejection, never silent acceptance.

## Key Types

### `SchemaDigest`

```rust
pub struct SchemaDigest(pub Hash);
```

A BLAKE3 hash of canonical schema content, used as the primary identifier.

**Invariants:**
- [INV-0001] Digests are exactly 32 bytes (BLAKE3 output)
- [INV-0002] Digests are deterministic: same content produces same digest

### `SchemaEntry`

```rust
pub struct SchemaEntry {
    pub stable_id: String,
    pub digest: SchemaDigest,
    pub content: Vec<u8>,
    pub canonicalizer_version: String,
    pub registered_at: u64,
    pub registered_by: String,
}
```

**Invariants:**
- [INV-0003] `stable_id` is unique within a registry
- [INV-0004] `digest` is computed from `content` using BLAKE3
- [INV-0005] Entries are immutable once registered

**Contracts:**
- [CTR-0001] `stable_id` must be 1-256 bytes
- [CTR-0002] `content` must be non-empty
- [CTR-0003] `content` must not exceed `MAX_SCHEMA_SIZE` (1 MB)

### `SchemaRegistry` Trait

```rust
pub trait SchemaRegistry: Send + Sync {
    fn register<'a>(&'a self, entry: &'a SchemaEntry)
        -> BoxFuture<'a, Result<(), SchemaRegistryError>>;
    fn lookup_by_digest<'a>(&'a self, digest: &'a SchemaDigest)
        -> BoxFuture<'a, Result<Option<SchemaEntry>, SchemaRegistryError>>;
    fn lookup_by_stable_id<'a>(&'a self, stable_id: &'a str)
        -> BoxFuture<'a, Result<Option<SchemaEntry>, SchemaRegistryError>>;
    fn handshake<'a>(&'a self, peer_digests: &'a [SchemaDigest])
        -> BoxFuture<'a, Result<HandshakeResult, SchemaRegistryError>>;
    fn all_digests(&self) -> BoxFuture<'_, Result<Vec<SchemaDigest>, SchemaRegistryError>>;
    fn len(&self) -> BoxFuture<'_, Result<usize, SchemaRegistryError>>;
}
```

**Invariants:**
- [INV-0010] Lookup returns `None` for unknown digests (fail-closed)
- [INV-0011] Registration is idempotent for same stable_id + content
- [INV-0012] Conflict error if stable_id exists with different content

**Contracts:**
- [CTR-0010] `register()` verifies digest matches content
- [CTR-0011] `handshake()` never fails due to incompatibility (returns result)

### `InMemorySchemaRegistry`

```rust
pub struct InMemorySchemaRegistry {
    insertion_order: Arc<RwLock<VecDeque<SchemaDigest>>>,
    by_digest: Arc<RwLock<HashMap<SchemaDigest, SchemaEntry>>>,
    by_stable_id: Arc<RwLock<HashMap<String, SchemaDigest>>>,
    max_schemas: usize,
}
```

Non-persistent implementation for testing and single-node deployments.

**Invariants:**
- [INV-0020] Schema count cannot exceed `max_schemas`
- [INV-0021] Clone shares storage via `Arc` (not deep copy)
- [INV-0022] Thread-safe via `RwLock`
- [INV-0014] One stable_id per digest (no aliases) - prevents ghost entries
- [INV-0015] Lock ordering: insertion_order -> by_digest -> by_stable_id (prevents deadlocks)

**Contracts:**
- [CTR-0020] Evicts oldest entries when capacity exceeded (O(1) FIFO)
- [CTR-0021] `clear()` removes all schemas
- [CTR-0022] Re-registering same digest with different stable_id is a no-op (first stable_id wins)

### `SchemaRegistryError`

```rust
pub enum SchemaRegistryError {
    NotFound { digest: String },
    Conflict { stable_id: String },
    SchemaTooLarge { size: usize, max_size: usize },
    EmptySchema,
    InvalidStableId { reason: String },
    RegistryFull { current: usize, max: usize },
    HashMismatch { expected: String, actual: String },
    HandshakeFailed { reason: String },
    Internal { message: String },
}
```

## Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `MAX_SCHEMA_SIZE` | 1 MB | Maximum schema content size |
| `DEFAULT_MAX_SCHEMAS` | 1,000 | Default registry capacity |
| `MAX_HANDSHAKE_DIGESTS` | 10,000 | Max digests in handshake request |
| `KERNEL_SCHEMA_PREFIX` | `"kernel:"` | Prefix for kernel schemas |
| `KERNEL_CANONICALIZER_VERSION` | `"cac-json-v1"` | Canonicalizer version |

## Kernel Schemas

The module provides pre-defined kernel event schemas:

| Type Name | Stable ID |
|-----------|-----------|
| `session.started` | `kernel:session.started` |
| `session.terminated` | `kernel:session.terminated` |
| `lease.issued` | `kernel:lease.issued` |
| `evidence.published` | `kernel:evidence.published` |
| `tool.requested` | `kernel:tool.requested` |
| `work.opened` | `kernel:work.opened` |

Use `register_kernel_schemas(&registry).await` during bootstrap.

## Public API

| Function | Description |
|----------|-------------|
| `create_kernel_schema(type_name, content)` | Create kernel schema entry |
| `register_kernel_schemas(registry)` | Register all kernel schemas |

## Examples

### Register and Lookup

```rust
use apm2_core::schema_registry::{InMemorySchemaRegistry, SchemaEntry, SchemaDigest, SchemaRegistry};
use apm2_core::crypto::EventHasher;

let registry = InMemorySchemaRegistry::new();
let content = br#"{"type": "object"}"#;
let entry = SchemaEntry {
    stable_id: "my:schema.v1".to_string(),
    digest: SchemaDigest::new(EventHasher::hash_content(content)),
    content: content.to_vec(),
    canonicalizer_version: "cac-json-v1".to_string(),
    registered_at: 0,
    registered_by: "system".to_string(),
};

registry.register(&entry).await?;

// Lookup - returns None for unknown (fail-closed)
if let Some(found) = registry.lookup_by_digest(&entry.digest).await? {
    println!("Found: {}", found.stable_id);
}
```

### Peer Handshake

```rust
use apm2_core::schema_registry::{InMemorySchemaRegistry, SchemaRegistry};

let registry1 = InMemorySchemaRegistry::new();
let registry2 = InMemorySchemaRegistry::new();

// ... register schemas in both ...

let peer_digests = registry2.all_digests().await?;
let result = registry1.handshake(&peer_digests).await?;

if result.is_fully_compatible() {
    println!("Peers have matching schemas");
} else {
    println!("Missing local: {:?}", result.missing_local);
    println!("Missing remote: {:?}", result.missing_remote);
}
```

## Security Considerations

1. **Fail-Closed**: Unknown schemas return `None`, not errors. Callers must explicitly handle missing schemas.

2. **Bounded Storage**: `InMemorySchemaRegistry` has capacity limits (`max_schemas`) to prevent memory exhaustion. [CTR-1303]

3. **Content Verification**: Schema digests are verified against content on registration. Mismatches are rejected with `HashMismatch`.

4. **Immutability**: Registered schemas cannot be modified. Attempting to register the same stable_id with different content fails with `Conflict`.

5. **No Ghost Entries**: One stable_id per digest ([INV-0014]). When a schema is evicted or re-registered with a different stable_id, the old stable_id mapping is removed. This prevents stale lookups returning success for non-existent data.

6. **Bounded stable_id Growth**: Since each digest can only have one stable_id, an attacker cannot exhaust memory by registering unlimited aliases for the same content.

7. **Deadlock Prevention**: Consistent lock ordering ([INV-0015]) prevents AB-BA deadlocks between concurrent operations. Lock order: `insertion_order` -> `by_digest` -> `by_stable_id`.

## Related Modules

- [`apm2_core::crypto`](../crypto/AGENTS.md) - BLAKE3 hashing via `EventHasher::hash_content()`
- [`apm2_core::bootstrap`](../bootstrap/AGENTS.md) - Bootstrap schema registration
- [`apm2_core::determinism`](../determinism/AGENTS.md) - Canonical JSON for digests

## References

- RFC-0014: Distributed Consensus Layer Design
- DD-0004: Schema Registry with Fail-Closed Validation
- TCK-00181: Define SchemaRegistry Trait and InMemory Implementation
