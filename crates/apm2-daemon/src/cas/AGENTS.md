# CAS Module

> Durable filesystem-based content-addressed storage (CAS) for evidence artifacts.

## Overview

The `cas` module provides a persistent, hash-prefix-sharded CAS backend for the daemon. Per TCK-00293 and RFC-0018, evidence artifacts must be durable and content-addressed for the Forge Admission Cycle (FAC). The CAS stores immutable artifacts on the filesystem, verifying BLAKE3 content hashes on both store and retrieve operations. It uses atomic rename for crash-safe writes and enforces per-artifact and total storage size limits to prevent resource exhaustion.

Storage layout:

```text
{base_path}/
├── objects/
│   ├── 01/
│   │   └── 23456789abcdef...  (hash prefix sharding)
│   └── ...
└── metadata/
    └── total_size  (persistent size tracking)
```

## Key Types

### `DurableCas`

```rust
pub struct DurableCas {
    base_path: PathBuf,
    objects_path: PathBuf,
    metadata_path: PathBuf,
    max_artifact_size: usize,
    max_total_size: usize,
    current_total_size: AtomicUsize,
}
```

Filesystem-based CAS with atomic writes and BLAKE3 verification. Thread-safe via atomic operations for size tracking.

**Invariants:**

- [INV-CS01] Content is immutable after store; overwrite attempts are rejected.
- [INV-CS02] Content hash (BLAKE3) is verified on both store and retrieve.
- [INV-CS03] Per-artifact size is bounded by `max_artifact_size` (default 100 MB).
- [INV-CS04] Total storage is bounded by `max_total_size` (default 10 GB).
- [INV-CS05] Directories are created with mode 0700 (owner-only access).
- [INV-CS06] Base path must be absolute, free of symlink components, and owned by the daemon UID.

**Contracts:**

- [CTR-CS01] `store()` writes to a temporary file and atomically renames to prevent partial writes.
- [CTR-CS02] `store()` returns `StoreResult { is_new: false }` for deduplicated content (idempotent).
- [CTR-CS03] `retrieve()` verifies content hash before returning data.
- [CTR-CS04] `new()` validates base path security (absolute, no symlinks, owner match, mode 0700).

### `DurableCasConfig`

```rust
pub struct DurableCasConfig {
    pub base_path: PathBuf,
    pub max_artifact_size: usize,
    pub max_total_size: usize,
}
```

Configuration for the durable CAS with builder-style methods.

### `StoreResult`

```rust
pub struct StoreResult {
    pub hash: Hash,
    pub size: usize,
    pub is_new: bool,
}
```

Result of a store operation indicating whether content was new or deduplicated.

### `DurableCasError`

```rust
pub enum DurableCasError {
    NotFound { hash: String },
    HashMismatch { expected: String, actual: String },
    Collision { hash: String },
    ContentTooLarge { size: usize, max_size: usize },
    EmptyContent,
    InvalidHash { expected: usize, actual: usize },
    StorageFull { current_size: usize, new_size: usize, max_size: usize },
    Io { context: String, source: std::io::Error },
    InitializationFailed { message: String },
}
```

**Contracts:**

- [CTR-CS05] `kind()` returns a stable string identifier for each error variant.
- [CTR-CS06] `is_retriable()` returns `true` only for `Io` errors.

## Public API

### Store and Retrieve

```rust
impl DurableCas {
    pub fn new(config: DurableCasConfig) -> Result<Self, DurableCasError>;
    pub fn store(&self, content: &[u8]) -> Result<StoreResult, DurableCasError>;
    pub fn retrieve(&self, hash: &Hash) -> Result<Vec<u8>, DurableCasError>;
    pub fn exists(&self, hash: &Hash) -> bool;
    pub fn current_total_size(&self) -> usize;
}
```

### Constants

- `MAX_ARTIFACT_SIZE`: 100 MB per artifact
- `DEFAULT_MAX_TOTAL_SIZE`: 10 GB total storage
- `MIN_TOTAL_SIZE`: 100 MB minimum total size

## Related Modules

- [`apm2_daemon::evidence`](../evidence/AGENTS.md) -- Evidence artifacts stored in CAS
- [`apm2_daemon::projection`](../projection/AGENTS.md) -- Projection receipts stored in CAS
- [`apm2_core::evidence`](../../../apm2-core/src/evidence/AGENTS.md) -- Core evidence types

## Safe I/O (TCK-00537)

All persistent file operations use `crate::fs_safe` primitives:

- **Writes**: `fs_safe::atomic_write` (temp file + fsync + rename + dir fsync)
- **Reads**: `fs_safe::bounded_read` (symlink refusal via O_NOFOLLOW, bounded size, regular-file check)
- The `persist_total_size()` method uses `atomic_write` for crash-safe metadata updates.
- The `recover_total_size()` method uses `bounded_read` for symlink-safe, size-bounded reads.

## References

- TCK-00293: Durable CAS backend + wiring
- TCK-00537: Safe atomic file I/O primitives migration
- RFC-0018: HEF requirements for evidence durability
- REQ-HEF-0009: `ChangeSetBundle` in CAS referenced by ledger
