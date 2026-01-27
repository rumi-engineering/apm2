# Bootstrap Module

> Embedded bootstrap schema bundle forming the CAC trust root.

## Overview

The `apm2_core::bootstrap` module provides the foundational trust root for the Context-as-Code (CAC) system. Bootstrap schemas are embedded in the binary at build time and verified at runtime startup to ensure integrity.

## Key Types

### `BootstrapSchema`

```rust
pub struct BootstrapSchema {
    pub stable_id: String,
    pub content: String,
    pub content_hash: Hash,
}
```

A bootstrap schema entry with its content and BLAKE3 hash.

**Methods:**
- `content_hash_hex()` - Returns hash as `b3-256:{hex}` format
- `parse_json()` - Parses content as JSON Value

### `BootstrapError`

```rust
pub enum BootstrapError {
    VerificationFailed { expected: String, actual: String },
    BootstrapProtected { stable_id: String },
    SchemaNotFound { stable_id: String },
    InvalidSchemaJson { stable_id: String, message: String },
}
```

**Invariants:**
- [INV-0030] `VerificationFailed` indicates binary tampering or build inconsistency
- [INV-0031] `BootstrapProtected` prevents all modifications to bootstrap schemas
- [INV-0032] Error messages include stable_id for debugging

**Contracts:**
- [CTR-0030] `verify_bootstrap_hash()` MUST be called before processing CAC artifacts
- [CTR-0031] Application MUST terminate on `VerificationFailed`

## Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `BOOTSTRAP_PREFIX` | `"bootstrap:"` | Reserved prefix for bootstrap IDs |
| `BOOTSTRAP_BUNDLE_HASH` | `[u8; 32]` | Build-time bundle hash |
| `BOOTSTRAP_SCHEMA_COUNT` | Generated | Number of embedded schemas |

## Public API

| Function | Description |
|----------|-------------|
| `verify_bootstrap_hash()` | Verify bundle integrity at startup |
| `is_bootstrap_id(stable_id)` | Check if ID is protected |
| `reject_bootstrap_patch(target)` | Validate patch target is not bootstrap |
| `get_bootstrap_schema(id)` | Retrieve schema by stable ID |
| `get_all_bootstrap_schemas()` | Iterator over all schemas |
| `get_bootstrap_stable_ids()` | Slice of all stable IDs |
| `verify_schema_hash(id)` | Verify individual schema hash |

## Build Process

The `build.rs` script generates `bootstrap_manifest.rs` with:

1. **Schema collection**: Reads `bootstrap/schemas/*.schema.json`
2. **Hash computation**: BLAKE3 hash for each schema
3. **Bundle hash**: Combined hash over all schema hashes
4. **Code generation**: Constants and arrays for runtime access

Build trigger: `cargo:rerun-if-changed=bootstrap/`

## Bootstrap Schemas

| Stable ID | Purpose |
|-----------|---------|
| `bootstrap:common.v1` | Common type definitions |
| `bootstrap:envelope.v1` | Artifact envelope structure |
| `bootstrap:patch_record.v1` | Patch record format |
| `bootstrap:admission_receipt.v1` | Admission receipt format |

## Security

### Trust Boundary (TB-0002)

Bootstrap schemas are the root of trust for CAC:

1. **Build-time embedding**: Schemas embedded via `include!` macro
2. **Hash verification**: Bundle hash checked at startup
3. **Immutability**: Patches targeting `bootstrap:*` rejected

### Threat Mitigations

| Threat | Mitigation |
|--------|------------|
| Binary tampering | Hash verification at startup |
| Filesystem attacks | Schemas embedded in binary |
| Patch bypass | `reject_bootstrap_patch()` in admission |
| Hash collision | BLAKE3 256-bit cryptographic hash |

## Examples

### Startup Verification

```rust
use apm2_core::bootstrap::verify_bootstrap_hash;

fn main() {
    if let Err(e) = verify_bootstrap_hash() {
        eprintln!("CRITICAL: {}", e);
        std::process::exit(1);
    }
}
```

### Admission Pipeline Integration

```rust
use apm2_core::bootstrap::reject_bootstrap_patch;

fn process_patch(target_stable_id: &str) -> Result<(), Error> {
    // Check bootstrap protection first
    reject_bootstrap_patch(target_stable_id)?;

    // Continue with normal patch processing...
    Ok(())
}
```

### Schema Access for Validation

```rust
use apm2_core::bootstrap::get_bootstrap_schema;

fn validate_with_bootstrap_schema(artifact: &Value) -> Result<(), Error> {
    let schema = get_bootstrap_schema("bootstrap:envelope.v1")?;
    let schema_json = schema.parse_json()?;

    // Use schema for validation...
    Ok(())
}
```

## Related Modules

- [`apm2_core::cac`](../cac/AGENTS.md) - CAC validation using bootstrap schemas
- [`apm2_core::crypto`](../crypto/AGENTS.md) - BLAKE3 hashing primitives
- [`apm2_core::evidence`](../evidence/AGENTS.md) - Evidence categories including BootstrapSchema

## References

- RFC-0011: Context-as-Code v1 specification
- TCK-00129: Embed bootstrap schema bundle in binary
- TB-0002: Bootstrap trust boundary
