# Context-as-Code (CAC) Module

> CAC v1 validation infrastructure for Context-as-Code artifacts.

## Overview

The `apm2_core::cac` module provides JSON Schema validation for Context-as-Code (CAC) artifacts. CAC artifacts are JSON documents that pass through an admission pipeline:

1. **Canonicalization** (via `determinism::canonicalize_json`): Produces deterministic JSON output
2. **Validation** (this module): Enforces schema and size constraints
3. **CAS storage**: Content-addressed storage with hash integrity

The validator enforces a strict CAC profile with fail-closed semantics.

## Key Types

### `CacValidator`

```rust
pub struct CacValidator {
    validator: jsonschema::Validator,
}
```

A compiled JSON Schema validator with CAC-specific configuration.

**Invariants:**
- [INV-0020] Schema is validated at construction time
- [INV-0021] Size limits are checked before schema validation (DoS prevention)
- [INV-0022] Unknown fields rejected when schema uses `unevaluatedProperties: false`

**Contracts:**
- [CTR-0020] `new()` returns `Err(InvalidSchema)` for invalid schemas
- [CTR-0021] `validate()` returns first error encountered (fail-fast)
- [CTR-0022] All errors include JSON path to the violation

### `AdmissionGate`

```rust
pub struct AdmissionGate<C: ContentAddressedStore> { /* fields private */ }
```

The admission gate that orchestrates validation, canonicalization, and storage of CAC artifacts.

**Invariants:**
- [INV-0029] Reserved prefixes (`cac:`, `bootstrap:`, `internal:`) are enforced at admission time
- [INV-0030] `schema_id` is tracked in receipts when provided
- [INV-0031] DCP IDs must not contain control characters (metadata injection prevention)

**Contracts:**
- [CTR-0025] `admit()` enforces reserved prefix restrictions (critical: DcpIndexReducer disables this during replay)
- [CTR-0026] `admit()` validates DCP ID length and character safety before any expensive operations
- [CTR-0027] `with_schema_id()` enables schema reference tracking in admission receipts


### `DcpIndex`

```rust
pub struct DcpIndex { /* fields private */ }
```

A stable-ID resolution index projected from ledger events.

**Invariants:**
- [INV-0023] Stable IDs must be unique (collision detection)
- [INV-0024] Stable IDs must follow `namespace:kind:identifier[@version]` format
- [INV-0025] Reserved prefixes (`cac:`, `bootstrap:`, `internal:`) require authorization
- [INV-0026] Dependencies must exist and not be deprecated (DAG enforcement)

**Contracts:**
- [CTR-0023] `register()` is idempotent for identical entries
- [CTR-0024] `resolve()` returns `None` for deprecated entries

### `DcpEntry`

```rust
pub struct DcpEntry {
    pub stable_id: String,
    pub content_hash: String,
    pub schema_id: String,
    pub dependencies: Vec<String>,
    // ...
}
```

A registered artifact entry.

**Invariants:**
- [INV-0027] `content_hash` must be a valid 64-char hex BLAKE3 hash
- [INV-0028] `dependencies` list cannot exceed `MAX_DEPENDENCIES` (128)

### `ContextPackSpec`

```rust
pub struct ContextPackSpec {
    pub schema: String,
    pub schema_version: String,
    pub spec_id: String,
    pub roots: Vec<String>,
    pub budget: BudgetConstraint,
    pub target_profile: String,
    pub dependency_reviews: Vec<DependencyReview>,
    pub metadata: Option<PackMetadata>,
}
```

Specification for a ContextPack defining artifacts and budget constraints for hermetic consumption.

**Invariants:**
- [INV-0032] `spec_id` must match pattern `[A-Za-z0-9_.:-]+`
- [INV-0033] `roots` list must have at least 1 and at most 1024 entries
- [INV-0034] All budget constraint quantities must use correct units (tokens for max_tokens, etc.)
- [INV-0035] All types use `#[serde(deny_unknown_fields)]` for strict validation

**Contracts:**
- [CTR-0028] `TypedQuantity` arithmetic operations return errors on overflow (no panics)
- [CTR-0029] Unit mismatch in arithmetic operations is rejected at runtime
- [CTR-0030] Builder validates all constraints before returning `ContextPackSpec`

### `TypedQuantity`

```rust
pub struct TypedQuantity {
    value: u64,
    unit: QuantityUnit,
}
```

A quantity with explicit unit for type-safe arithmetic (per DD-0007 "Mars Climate Orbiter" prevention).

**Invariants:**
- [INV-0036] Value must be non-negative (u64)
- [INV-0037] Unit must be one of: `tokens`, `bytes`, `artifacts`, `ms`, `count`

**Contracts:**
- [CTR-0031] `checked_add/sub/mul/div` return `PackSpecError` on overflow/underflow
- [CTR-0032] Operations between quantities with different units return `UnitMismatch` error
- [CTR-0033] `saturating_add/sub` clamp to bounds instead of overflowing

### `BudgetConstraint`

```rust
pub struct BudgetConstraint {
    pub max_tokens: Option<TypedQuantity>,
    pub max_bytes: Option<TypedQuantity>,
    pub max_artifacts: Option<TypedQuantity>,
    pub max_time_ms: Option<TypedQuantity>,
}
```

Budget constraints for ContextPack consumption.

**Invariants:**
- [INV-0038] If `max_tokens` is set, its unit must be `tokens`
- [INV-0039] If `max_bytes` is set, its unit must be `bytes`
- [INV-0040] If `max_artifacts` is set, its unit must be `artifacts`
- [INV-0041] If `max_time_ms` is set, its unit must be `ms`

### `ContextPackCompiler`

```rust
pub struct ContextPackCompiler<'a> {
    index: &'a DcpIndex,
}
```

Compiler for ContextPack specifications that resolves transitive dependencies,
detects cycles, enforces budget constraints, and generates deterministic manifests.

**Invariants:**
- [INV-0042] Cycle detection uses Tarjan's SCC algorithm for O(V+E) complexity
- [INV-0043] Manifest entries are sorted by stable_id for determinism
- [INV-0044] Deep-pinning resolves all stable_ids to content_hashes before output

**Contracts:**
- [CTR-0034] `compile()` returns `CycleDetected` error with full cycle path
- [CTR-0035] `compile()` returns `BudgetExceeded` if any budget dimension is violated
- [CTR-0036] Same input spec always produces identical manifest bytes (determinism)
- [CTR-0037] `CompilationReceipt` includes manifest hash for integrity verification

### `CompiledContextPack`

```rust
pub struct CompiledContextPack {
    pub manifest: CompiledManifest,
    pub content_hashes: BTreeMap<String, String>,
    pub budget_used: BudgetUsed,
}
```

The result of compiling a ContextPackSpec, containing the deterministic manifest
and all resolved content hashes.

**Invariants:**
- [INV-0045] `content_hashes` is keyed by stable_id, values are 64-char hex hashes
- [INV-0046] All entries in `manifest.entries` have corresponding `content_hashes` entries

### `CompilationReceipt`

```rust
pub struct CompilationReceipt {
    pub spec_id: String,
    pub compile_time_ms: u64,
    pub artifact_count: usize,
    pub root_count: usize,
    pub warnings: Vec<CompilationWarning>,
    pub manifest_hash: String,
}
```

Receipt capturing compilation metadata for audit and verification.

**Invariants:**
- [INV-0047] `manifest_hash` is BLAKE3 hash of canonical manifest JSON (64 hex chars)
- [INV-0048] Warnings are generated for unused dependency reviews or hash mismatches

### `CompilationError`

```rust
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CompilationError {
    CycleDetected { path: Vec<String> },
    ArtifactNotFound { stable_id: String },
    ArtifactDeprecated { stable_id: String },
    BudgetExceeded { dimension: String, limit: u64, actual: u64 },
    TooManyArtifacts { count: usize, max: usize },
    ResolutionDepthExceeded { depth: usize, max: usize },
    InvalidPackSpec(PackSpecError),
    ManifestGenerationFailed { message: String },
}
```

Comprehensive error types for compilation failures.

**Design Rationale:**
- `CycleDetected` includes full path for debugging cyclic dependencies
- `BudgetExceeded` reports dimension, limit, and actual for clear error messages
- `#[non_exhaustive]` allows adding error variants without breaking semver

### `ValidationError`

```rust
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ValidationError {
    UnknownField { field: String, path: String },
    ArrayTooLarge { path: String, count: usize, limit: usize },
    ObjectTooLarge { path: String, count: usize, limit: usize },
    MaxDepthExceeded { path: String, max_depth: usize },
    SchemaValidation { path: String, message: String },
    InvalidSchema { message: String },
}
```

Comprehensive error types with JSON path locations.

**Design Rationale:**
- `UnknownField` is distinct from `SchemaValidation` for fail-closed policy enforcement
- Size limit errors are distinct for DoS attack detection
- `#[non_exhaustive]` allows adding error variants without breaking semver

## Public API

| Function | Description |
|----------|-------------|
| `CacValidator::new(schema)` | Create validator from JSON Schema |
| `CacValidator::validate(value)` | Validate value with size limits and schema |
| `validate_cac_artifact(schema, artifact)` | One-shot validation for admission pipeline |
| `DcpIndex::register(entry)` | Register an artifact (idempotent) |
| `DcpIndex::resolve(id)` | Resolve stable ID to content hash |
| `DcpIndex::deprecate(id)` | Mark artifact as deprecated |
| `DcpIndex::apply_event(evt)` | Update index from ledger event |
| `ContextPackSpec::builder()` | Create a builder for pack specs |
| `TypedQuantity::tokens(v)` | Create token quantity |
| `TypedQuantity::bytes(v)` | Create byte quantity |
| `TypedQuantity::checked_add(q)` | Checked addition with unit validation |
| `BudgetConstraint::builder()` | Create a builder for budget constraints |
| `ContextPackCompiler::new(index)` | Create compiler with DCP index |
| `ContextPackCompiler::compile(spec)` | Compile pack spec to CompiledContextPack |

## Examples

### Basic Validation

```rust
use apm2_core::cac::{CacValidator, ValidationError};
use serde_json::json;

let schema = json!({
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "properties": {
        "id": { "type": "string" }
    },
    "unevaluatedProperties": false
});

let validator = CacValidator::new(&schema)?;

// Valid artifact
let valid = json!({"id": "TCK-00128"});
validator.validate(&valid)?;

// Unknown field rejected
let invalid = json!({"id": "TCK-00128", "extra": "field"});
assert!(matches!(
    validator.validate(&invalid),
    Err(ValidationError::UnknownField { .. })
));
```

### Admission Pipeline Integration

```rust
use apm2_core::cac::validate_cac_artifact;
use apm2_core::determinism::canonicalize_json;
use serde_json::json;

let schema = json!({
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "properties": {
        "ticket_id": { "type": "string" }
    },
    "unevaluatedProperties": false
});

// Step 1: Canonicalize input
let input = r#"{ "ticket_id": "TCK-00128" }"#;
let canonical = canonicalize_json(input)?;

// Step 2: Validate against schema
let value: serde_json::Value = serde_json::from_str(&canonical)?;
validate_cac_artifact(&schema, &value)?;

// Step 3: Store in CAS (not shown)
```

### DCP Index Resolution

```rust
use apm2_core::cac::{DcpIndex, DcpEntry};

let mut index = DcpIndex::new();

// Register artifact
let entry = DcpEntry::new(
    "org:ticket:TCK-00134",
    "a".repeat(64), // Valid hash
    "cac:schema:ticket-v1"
);
index.register(entry)?;

// Resolve
if let Some(hash) = index.resolve("org:ticket:TCK-00134") {
    println!("Artifact hash: {}", hash);
}
```

### Handling Size Limit Errors

```rust
use apm2_core::cac::{CacValidator, ValidationError, MAX_ARRAY_MEMBERS};
use serde_json::json;

let schema = json!({
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "array"
});

let validator = CacValidator::new(&schema)?;

// Large array exceeds limit
let large_array: Vec<i32> = (0..(MAX_ARRAY_MEMBERS + 1) as i32).collect();
let value = json!(large_array);

match validator.validate(&value) {
    Err(ValidationError::ArrayTooLarge { path, count, limit }) => {
        println!("Array at {} has {} items (limit: {})", path, count, limit);
    }
    _ => unreachable!()
}
```

## Design Principles

1. **Fail-Closed**: Unknown fields are rejected, not ignored
2. **DoS Prevention**: Size limits checked before expensive schema validation
3. **Location Reporting**: All errors include JSON path for debugging
4. **Two-Phase Validation**: Size limits, then schema validation

## Security

- Pre-validating size limits prevents DoS attacks via maliciously large inputs
- `unevaluatedProperties: false` ensures schema bypass attacks fail
- Unknown field rejection provides defense-in-depth against schema evolution attacks

### `ConformanceTest`

```rust
pub struct ConformanceTest {
    pub test_id: String,
    pub expected_hash: Option<String>,
    pub pack_ref: String,
}
```

A conformance test specification for export verification.

**Contracts:**
- [CTR-0038] `test_id` must be unique within a test suite
- [CTR-0039] `expected_hash` format is `sha256:...` or `blake3:...` when provided

### `ExportReceipt`

```rust
pub struct ExportReceipt {
    pub schema: String,
    pub schema_version: String,
    pub pack_hash: String,
    pub profile_id: String,
    pub conformance_tests: Vec<ConformanceTestResult>,
    pub overall_passed: bool,
    pub timestamp: String,
    pub total_duration_ms: Option<u64>,
}
```

Receipt documenting the results of export conformance testing.

**Invariants:**
- [INV-0049] `overall_passed` is true if and only if all conformance tests passed
- [INV-0050] `timestamp` is ISO 8601 format (YYYY-MM-DDTHH:MM:SSZ)
- [INV-0051] All structs use `#[serde(deny_unknown_fields)]` for strict validation

**Contracts:**
- [CTR-0040] `new()` automatically computes `overall_passed` from test results
- [CTR-0041] `summary()` returns human-readable test result summary

### `ConformanceError`

```rust
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ConformanceError {
    DeterminismFailure { hash1: String, hash2: String, path: String },
    ProvenanceParsingFailed { path: String, reason: String },
    ProvenanceMissingField { field: String, path: String },
    ProvenanceInvalidField { field: String, path: String, reason: String },
    SchemaValidationFailed { path: String, reason: String },
    ExportFailed(ExportError),
    TooManyTests { count: usize, max: usize },
    InvalidTestSpec { reason: String },
    InvalidUtf8 { path: String },
}
```

Comprehensive error types for conformance testing failures.

### Conformance Functions

| Function | Description |
|----------|-------------|
| `verify_determinism(pack, resolver, ...)` | Export twice and compare for byte-identical output |
| `verify_provenance(content, path, profile)` | Parse and validate YAML frontmatter provenance |
| `verify_schema(content, path, format)` | Validate output matches expected format schema |
| `run_conformance_suite(pack, resolver, ...)` | Run full conformance suite and produce receipt |

## Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `MAX_ARRAY_MEMBERS` | 100,000 | Maximum array size |
| `MAX_OBJECT_PROPERTIES` | 100,000 | Maximum object size |
| `MAX_DEPTH` | 128 | Maximum nesting depth |
| `MAX_STABLE_ID_LENGTH` | 1024 | Maximum stable ID length |
| `MAX_CONTENT_HASH_LENGTH` | 64 | Hex-encoded BLAKE3 hash length |
| `MAX_DEPENDENCIES` | 128 | Maximum dependencies per artifact |
| `MAX_ARTIFACTS_IN_PACK` | 10,000 | Maximum artifacts in a compiled pack |
| `MAX_RESOLUTION_DEPTH` | 256 | Maximum dependency resolution depth |
| `MAX_CONFORMANCE_TESTS` | 1,000 | Maximum conformance tests per suite |

## Related Modules

- [`apm2_core::determinism`](../determinism/AGENTS.md) - CAC-JSON canonicalization
- [`apm2_core::evidence`](../evidence/AGENTS.md) - CAS storage for validated artifacts
