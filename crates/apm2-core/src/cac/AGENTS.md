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

## Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `MAX_ARRAY_MEMBERS` | 100,000 | Maximum array size |
| `MAX_OBJECT_PROPERTIES` | 100,000 | Maximum object size |
| `MAX_DEPTH` | 128 | Maximum nesting depth |

## Public API

| Function | Description |
|----------|-------------|
| `CacValidator::new(schema)` | Create validator from JSON Schema |
| `CacValidator::validate(value)` | Validate value with size limits and schema |
| `validate_cac_artifact(schema, artifact)` | One-shot validation for admission pipeline |

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

## Related Modules

- [`apm2_core::determinism`](../determinism/AGENTS.md) - CAC-JSON canonicalization
- [`apm2_core::evidence`](../evidence/AGENTS.md) - CAS storage for validated artifacts
