# Evidence Module

> Content-addressed artifact storage with integrity verification and progressive disclosure for work completion proofs.

## Overview

The `apm2_core::evidence` module implements the evidence bundle infrastructure for the APM2 kernel. Evidence bundles contain artifacts that prove work completion and are stored in a content-addressed store (CAS) using BLAKE3 hashes for integrity verification and deduplication.

This module integrates with three core APM2 architectural patterns:

1. **Content-Addressed Storage**: Artifacts stored by BLAKE3 hash, providing deduplication, integrity verification, and immutability
2. **Event Sourcing**: Only hash references recorded in events; content fetched on demand (progressive disclosure)
3. **Reducer Pattern**: `EvidenceReducer` derives projection state from `EvidencePublished` events

### Publishing Flow

```
ArtifactPublish (tool request)
       |
       v
EvidencePublisher.publish()
       |
       v
ContentAddressedStore.store(content)
       |
       v
EvidencePublished (kernel event)
       |
       v
EvidenceReducer.apply(event)
       |
       v
Evidence (projection)
```

## Key Types

### `ContentAddressedStore`

```rust
pub trait ContentAddressedStore: Send + Sync {
    fn store(&self, content: &[u8]) -> Result<StoreResult, CasError>;
    fn retrieve(&self, hash: &Hash) -> Result<Vec<u8>, CasError>;
    fn exists(&self, hash: &Hash) -> Result<bool, CasError>;
    fn size(&self, hash: &Hash) -> Result<usize, CasError>;
    fn verify(&self, content: &[u8], expected_hash: &Hash) -> Result<(), CasError>;
}
```

**Invariants:**
- [INV-0001] Content is verified against its hash on both store and retrieve
- [INV-0002] Duplicate content is deduplicated (same hash = same storage location)
- [INV-0003] Stored content is immutable; attempts to overwrite are rejected
- [INV-0004] Hash collisions are cryptographically infeasible with BLAKE3

**Contracts:**
- [CTR-0001] `store()` returns `CasError::EmptyContent` if content is empty
- [CTR-0002] `store()` returns `CasError::ContentTooLarge` if content exceeds `MAX_ARTIFACT_SIZE` (100 MB)
- [CTR-0003] `retrieve()` returns `CasError::NotFound` if content is not found
- [CTR-0004] `retrieve()` returns `CasError::HashMismatch` if stored content doesn't match hash (corruption)

### `MemoryCas`

```rust
pub struct MemoryCas {
    storage: Arc<RwLock<HashMap<Hash, Vec<u8>>>>,
    max_total_size: usize,
}
```

In-memory CAS implementation for testing. Uses `Arc<RwLock<_>>` for thread-safe shared storage.

**Invariants:**
- [INV-0005] `Clone` shares storage via `Arc` (not deep copy)
- [INV-0006] Total stored size cannot exceed `max_total_size` (default 1 GB)

**Constants:**
- `MAX_ARTIFACT_SIZE`: 100 MB per artifact
- `DEFAULT_MAX_TOTAL_SIZE`: 1 GB total

### `DataClassification`

```rust
pub enum DataClassification {
    Public       = 0,  // No access restrictions
    Internal     = 1,  // Organization internal only
    Confidential = 2,  // Need-to-know basis
    Restricted   = 3,  // Highest sensitivity, special handling
}
```

**Invariants:**
- [INV-0007] Classifications are ordered: `Public < Internal < Confidential < Restricted`
- [INV-0008] More sensitive data has shorter default retention periods
- [INV-0009] Downgrading classification requires explicit authorization

**Contracts:**
- [CTR-0005] `Confidential` and `Restricted` require progressive disclosure (only hash shared by default)
- [CTR-0006] `Restricted` requires log redaction
- [CTR-0007] Default retention: Public=7y, Internal=3y, Confidential=1y, Restricted=90d

### `EvidenceCategory`

```rust
pub enum EvidenceCategory {
    TestResults,        // Test execution results and coverage
    LintReports,        // Static analysis outputs
    BuildArtifacts,     // Compilation outputs
    SecurityScans,      // Vulnerability reports
    ReviewRecords,      // Code review and approvals
    AuditLogs,          // Compliance records
    ConfigSnapshots,    // Environment captures
    Documentation,      // Generated docs
    Benchmarks,         // Performance metrics
    DeploymentRecords,  // Release artifacts
}
```

**Contracts:**
- [CTR-0008] Categories requiring verification: `TestResults`, `LintReports`, `SecurityScans`, `BuildArtifacts`, `Benchmarks`
- [CTR-0009] Categories NOT requiring verification: `ReviewRecords`, `AuditLogs`, `ConfigSnapshots`, `Documentation`, `DeploymentRecords`

### `Evidence`

```rust
pub struct Evidence {
    pub evidence_id: String,
    pub work_id: String,
    pub category: EvidenceCategory,
    pub artifact_hash: Hash,           // [u8; 32] BLAKE3 hash
    pub artifact_size: usize,
    pub classification: DataClassification,
    pub verification_command_ids: Vec<String>,
    pub metadata: Vec<(String, String)>,
    pub published_at: u64,             // Unix nanos
    pub published_by: String,          // Actor ID
}
```

**Invariants:**
- [INV-0010] `evidence_id` must be non-empty and <= 256 bytes
- [INV-0011] `work_id` must be non-empty and <= 256 bytes
- [INV-0012] `artifact_hash` must be exactly 32 bytes (BLAKE3 output)
- [INV-0013] `verification_command_ids` limited to 100 entries (DoS protection)

### `EvidenceBundle`

```rust
pub struct EvidenceBundle {
    pub work_id: String,
    pub bundle_hash: Hash,             // BLAKE3 hash of sorted evidence IDs
    pub evidence_ids: Vec<String>,
    pub categories: Vec<EvidenceCategory>,
    pub total_size: usize,
    pub created_at: u64,
}
```

**Invariants:**
- [INV-0014] `bundle_hash` is deterministic: computed from sorted evidence IDs joined by `,`
- [INV-0015] Bundle created when `GateReceiptGenerated` event is processed

### `EvidencePublisher<C: ContentAddressedStore>`

```rust
pub struct EvidencePublisher<C: ContentAddressedStore> {
    cas: C,
}
```

**Contracts:**
- [CTR-0010] `publish()` does NOT emit events directly; returns `PublishResult` for caller to create event
- [CTR-0011] `publish()` validates all inputs before CAS storage
- [CTR-0012] Metadata format: `["key=value", ...]` strings

### `EvidenceReducer`

```rust
pub struct EvidenceReducer {
    state: EvidenceReducerState,
}

pub struct EvidenceReducerState {
    pub evidence: HashMap<String, Evidence>,
    pub evidence_by_work: HashMap<String, Vec<String>>,
    pub bundles: HashMap<String, EvidenceBundle>,
}
```

**Invariants:**
- [INV-0016] Reducer is deterministic: same events produce same state
- [INV-0017] Only processes events with `event_type.starts_with("evidence.")`
- [INV-0018] Does NOT verify artifact content matches hash (CAS layer responsibility)

**Contracts:**
- [CTR-0013] Rejects duplicate `evidence_id` with `EvidenceError::DuplicateEvidence`
- [CTR-0014] Rejects empty `evidence_id` or `work_id`
- [CTR-0015] Rejects invalid hash size (must be 32 bytes)

### `EvidenceError`

```rust
pub enum EvidenceError {
    CasError(CasError),
    InvalidEvidenceId { value: String },
    InvalidWorkId { value: String },
    DuplicateEvidence { evidence_id: String },
    EvidenceNotFound { evidence_id: String },
    InvalidCategory { value: String },
    InvalidClassification { value: String },
    HashMismatch { expected: String, actual: String },
    MalformedMetadata { index: usize },
    ClassificationViolation { required, actual, message },
    CategoryMismatch { expected, actual },
    ContentTooLarge { size, max_size },
    EmptyContent,
    InvalidVerificationCommand { index, reason },
}
```

### `CasError`

```rust
pub enum CasError {
    NotFound { hash: String },
    HashMismatch { expected: String, actual: String },
    Collision { hash: String },
    ContentTooLarge { size, max_size },
    EmptyContent,
    InvalidHash { expected, actual },
    StorageError { message: String },
    StorageFull { current_size, new_size, max_size },
}
```

## Public API

### `EvidencePublisher::new(cas: C) -> Self`

Creates a new evidence publisher with the given CAS backend.

### `EvidencePublisher::publish(evidence_id, work_id, content, category, classification, verification_command_ids) -> Result<PublishResult, EvidenceError>`

Publishes an artifact to the CAS. Returns metadata for creating an `EvidencePublished` event.

### `EvidencePublisher::publish_with_metadata(..., metadata: &[String]) -> Result<(PublishResult, Vec<(String, String)>), EvidenceError>`

Publishes with additional metadata parsing and validation.

### `EvidencePublisher::retrieve(hash) -> Result<Vec<u8>, EvidenceError>`

Retrieves artifact content by hash from the CAS.

### `EvidencePublisher::exists(hash) -> Result<bool, EvidenceError>`

Checks if an artifact exists in the CAS.

### `EvidencePublisher::verify(content, expected_hash) -> Result<(), EvidenceError>`

Verifies that content matches the expected hash.

### `EvidenceReducer::apply(event, ctx) -> Result<(), EvidenceError>`

Applies an event to update the reducer state. Handles:
- `evidence.published` -> creates `Evidence` entry
- `evidence.gate_receipt` -> assembles `EvidenceBundle`

### `EvidenceReducerState::get(evidence_id) -> Option<&Evidence>`

Returns evidence by ID.

### `EvidenceReducerState::get_by_work(work_id) -> Vec<&Evidence>`

Returns all evidence for a work ID.

### `EvidenceReducerState::get_by_category(category) -> Vec<&Evidence>`

Returns all evidence with the given category.

### `EvidenceReducerState::get_bundle(work_id) -> Option<&EvidenceBundle>`

Returns the bundle for a work ID, if assembled.

## Examples

### Publishing Evidence

```rust
use apm2_core::evidence::{
    ContentAddressedStore, DataClassification, EvidenceCategory,
    EvidencePublisher, MemoryCas,
};

// Create an in-memory CAS for testing
let cas = MemoryCas::new();
let publisher = EvidencePublisher::new(cas);

// Publish an artifact
let result = publisher.publish(
    "test-results-001",
    "work-123",
    b"test output: all tests passed",
    EvidenceCategory::TestResults,
    DataClassification::Internal,
    &["CMD-001".to_string()],
).unwrap();

// Result contains hash for event creation
assert!(result.is_new_content);
println!("Artifact hash: {:?}", result.artifact_hash);
```

### Applying Events with Reducer

```rust
use apm2_core::evidence::{EvidenceReducer, EvidenceCategory};
use apm2_core::reducer::{Reducer, ReducerContext};

let mut reducer = EvidenceReducer::new();

// Create and apply evidence.published event
// (payload created via helpers::evidence_published_payload in tests)
reducer.apply(&event, &ReducerContext::new(1)).unwrap();

// Query state
let evidence = reducer.state().get("evid-001").unwrap();
assert_eq!(evidence.category, EvidenceCategory::TestResults);
```

### CAS Deduplication

```rust
use apm2_core::evidence::{ContentAddressedStore, MemoryCas};

let cas = MemoryCas::new();
let content = b"duplicate content";

let result1 = cas.store(content).unwrap();
let result2 = cas.store(content).unwrap();

// Same hash, second is deduplicated
assert_eq!(result1.hash, result2.hash);
assert!(result1.is_new);
assert!(!result2.is_new);
assert_eq!(cas.len(), 1);  // Only one copy stored
```

### Progressive Disclosure Check

```rust
use apm2_core::evidence::DataClassification;

// Only Confidential and Restricted require progressive disclosure
assert!(!DataClassification::Public.requires_progressive_disclosure());
assert!(!DataClassification::Internal.requires_progressive_disclosure());
assert!(DataClassification::Confidential.requires_progressive_disclosure());
assert!(DataClassification::Restricted.requires_progressive_disclosure());
```

## Trust Boundaries

### CAS Trust Boundary

The `EvidenceReducer` does NOT verify that artifact content matches the hash. Content verification is the responsibility of the CAS layer. The reducer assumes:

1. **CAS integrity**: The CAS has verified content on storage
2. **Hash authenticity**: The event was validated by the command handler before being appended to the ledger

### Event Trust Boundary

Events in the ledger are assumed to be:
- Properly signed by the actor
- Part of a valid hash chain
- Schema-compliant (protobuf decoded successfully)

The reducer validates:
- ID format and length constraints
- Hash size (must be 32 bytes)
- Duplicate detection
- DoS limits (max 100 verification commands)

## Related Modules

- [`apm2_core::crypto`](../crypto/AGENTS.md) - BLAKE3 hashing via `EventHasher::hash_content()`, `Hash` type alias
- [`apm2_core::reducer`](../reducer/AGENTS.md) - `Reducer` trait, `ReducerContext`, checkpoint support
- [`apm2_core::ledger`](../ledger/AGENTS.md) - `EventRecord` structure, event storage
- [`apm2_core::events`](../events/AGENTS.md) - `EvidenceEvent`, `EvidencePublished`, `GateReceiptGenerated` protobuf messages

## References

- [32 — Testing, Fuzz, Miri, Evidence](/documents/skills/rust-standards/references/32_testing_fuzz_miri_evidence.md) - verification patterns
- [25 — API Design, stdlib Quality](/documents/skills/rust-standards/references/25_api_design_stdlib_quality.md) - trait design for `ContentAddressedStore`
- [15 — Errors, Panics, Diagnostics](/documents/skills/rust-standards/references/15_errors_panics_diagnostics.md) - error type design with `thiserror`
