# Determinism Module

> Primitives for reproducible, crash-safe file output in the APM2 compiler pipeline.

## Overview

The `apm2_core::determinism` module provides foundational capabilities for ensuring deterministic, reproducible output from all compiler stages. It addresses four core challenges:

1. **YAML Canonicalization**: Produces identical output regardless of input key order or formatting, enabling meaningful diffs and reproducible builds.

2. **JSON Canonicalization (CAC-JSON)**: RFC 8785 JCS-based canonicalization with CAC-specific constraints for Context-as-Code artifacts. Ensures deterministic hashing across platforms.

3. **Atomic File Writes**: Ensures files are either fully written or not modified at all, preventing corruption on crashes or interruptions.

4. **Diff Classification**: Distinguishes structural changes from free-text content changes, enabling intelligent merge decisions in the compiler.

## Key Types

### `canonicalize_yaml`

```rust
pub fn canonicalize_yaml(value: &Value) -> Result<String, CanonicalizeError>
```

Canonicalizes a YAML value to a deterministic string representation.

**Invariants:**
- [INV-0001] All mapping keys are sorted lexicographically (byte order)
- [INV-0002] Uses 2-space indentation consistently
- [INV-0003] No trailing whitespace on any line
- [INV-0004] Idempotent: `canonicalize_yaml(parse(canonicalize_yaml(v))) == canonicalize_yaml(v)`

**Contracts:**
- [CTR-0001] Returns `CanonicalizeError::UnsupportedComplexKey` for sequence or mapping keys
- [CTR-0002] Scalar keys (string, number, bool, null) are converted to their string representation
- [CTR-0003] Empty strings and reserved words ("true", "false", "null", etc.) are quoted

### `CanonicalizeError`

```rust
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CanonicalizeError {
    /// A complex key (sequence or mapping) was encountered.
    #[error("unsupported complex YAML key: {key_type} keys cannot be canonicalized")]
    UnsupportedComplexKey {
        key_type: &'static str,
    },
}
```

**Design Rationale:**
Complex keys (sequences or mappings used as YAML keys) are explicitly rejected rather than silently dropped. This prevents silent data loss and forces callers to handle edge cases explicitly.

### `canonicalize_json` (CAC-JSON)

```rust
pub fn canonicalize_json(input: &str) -> Result<String, CacJsonError>
```

Canonicalizes a JSON string to CAC-JSON canonical form (RFC 8785 JCS profile with CAC constraints).

**Invariants:**
- [INV-0010] Object keys are sorted lexicographically (byte order)
- [INV-0011] No whitespace between tokens
- [INV-0012] Idempotent: `canonicalize_json(canonicalize_json(s)) == canonicalize_json(s)`
- [INV-0013] Output is deterministic across platforms

**Contracts:**
- [CTR-0008] Rejects floating-point numbers (`CacJsonError::FloatNotAllowed`)
- [CTR-0009] Rejects numbers outside i64 range (`CacJsonError::NumberOutOfRange`)
- [CTR-0010] Rejects duplicate object keys (`CacJsonError::DuplicateKey`)
- [CTR-0011] Rejects non-NFC normalized strings (`CacJsonError::NonNfcString`)
- [CTR-0012] Rejects nesting deeper than 128 levels (`CacJsonError::MaxDepthExceeded`)

### `CacJsonError`

```rust
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CacJsonError {
    FloatNotAllowed,
    NumberOutOfRange { value: String },
    DuplicateKey { key: String },
    NonNfcString { path: String },
    MaxDepthExceeded { max_depth: usize },
    ParseError { message: String },
}
```

**Design Rationale:**
CAC-JSON is a strict JSON profile designed for deterministic hashing of context artifacts. Integer-only numbers eliminate float representation ambiguity. NFC normalization ensures consistent string comparison. Duplicate key rejection prevents parser-dependent behavior. The depth limit prevents stack overflow attacks.

### `CacJson`

```rust
pub struct CacJson { /* validated JSON value */ }
```

A validated CAC-JSON value that has passed all constraints. Use `validate_and_parse()` to create, then `to_canonical_string()` for output.

### `write_atomic`

```rust
pub fn write_atomic(path: &Path, content: &[u8]) -> Result<(), AtomicWriteError>
```

Writes content to a file atomically using rename-based semantics.

**Invariants:**
- [INV-0005] Target file is either fully written or unchanged (crash safety)
- [INV-0006] Uses `fsync` before rename on Unix to ensure durability
- [INV-0007] Temporary files are created in the same directory as target

**Contracts:**
- [CTR-0004] Parent directory must exist
- [CTR-0005] Caller must have write permissions to the target directory

### `AtomicWriteError`

```rust
#[derive(Debug, Error)]
pub enum AtomicWriteError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("parent directory does not exist: {path}")]
    ParentNotFound { path: String },
}
```

### `DiffClassification`

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffClassification {
    /// No changes detected.
    Identical,
    /// Only free-text fields (description, notes, etc.) changed.
    FreeText,
    /// Structural fields (id, status, dependencies, etc.) changed.
    Structural,
}
```

**Design Rationale:**
Distinguishing free-text from structural changes enables the compiler to auto-merge documentation updates while requiring human review for structural changes.

### `classify_diff`

```rust
pub fn classify_diff(old: &str, new: &str) -> DiffClassification
pub fn classify_diff_with_fields(old: &str, new: &str, free_text_fields: &[&str]) -> DiffClassification
```

**Invariants:**
- [INV-0008] Classification is symmetric: `classify_diff(a, b)` produces same category as `classify_diff(b, a)` (though "added" vs "removed" may differ)
- [INV-0009] Identical inputs always return `DiffClassification::Identical`

**Contracts:**
- [CTR-0006] Default free-text fields: `description`, `notes`, `summary`, `rationale`, `details`
- [CTR-0007] Custom field lists can be provided via `classify_diff_with_fields`

## Public API

| Function | Description |
|----------|-------------|
| `canonicalize_yaml(value)` | Convert YAML value to canonical string |
| `canonicalize_json(input)` | Convert JSON string to CAC-JSON canonical form |
| `validate_and_parse(input)` | Parse and validate JSON against CAC constraints |
| `is_canonical(input)` | Check if JSON string is already canonical |
| `write_atomic(path, content)` | Write file atomically (crash-safe) |
| `classify_diff(old, new)` | Classify changes between two strings |
| `classify_diff_with_fields(old, new, fields)` | Classify with custom free-text fields |

| Constant | Description |
|----------|-------------|
| `DEFAULT_FREE_TEXT_FIELDS` | Default fields considered free-text |
| `CANONICALIZER_ID` | CAC-JSON canonicalizer identifier (`"cac-json-v1"`) |
| `CANONICALIZER_VERSION` | CAC-JSON canonicalizer semver (`"1.0.0"`) |
| `MAX_DEPTH` | Maximum nesting depth (128) |

## Examples

### Canonicalize YAML for Deterministic Output

```rust
use apm2_core::determinism::canonicalize_yaml;
use serde_yaml::Value;

let yaml: Value = serde_yaml::from_str(r"
zebra: 1
apple: 2
").unwrap();

let canonical = canonicalize_yaml(&yaml).unwrap();
assert_eq!(canonical, "apple: 2\nzebra: 1\n");
```

### Atomic File Writes

```rust
use apm2_core::determinism::write_atomic;
use std::path::Path;

let content = b"important data";
write_atomic(Path::new("/tmp/output.yaml"), content).unwrap();
// File is either fully written or not modified at all
```

### Classify Changes

```rust
use apm2_core::determinism::{classify_diff, DiffClassification};

let old = "id: TCK-001\ndescription: Old text";
let new = "id: TCK-001\ndescription: New text";

// Only description changed - free-text
assert_eq!(classify_diff(old, new), DiffClassification::FreeText);

let structural = "id: TCK-002\ndescription: New text";
// ID changed - structural
assert_eq!(classify_diff(old, structural), DiffClassification::Structural);
```

### Handling Complex Keys

```rust
use apm2_core::determinism::{canonicalize_yaml, CanonicalizeError};
use serde_yaml::Value;

// Complex keys are rejected explicitly
let mut map = serde_yaml::Mapping::new();
let key = Value::Sequence(vec![Value::String("a".to_string())]);
map.insert(key, Value::String("value".to_string()));

let result = canonicalize_yaml(&Value::Mapping(map));
assert!(matches!(
    result,
    Err(CanonicalizeError::UnsupportedComplexKey { key_type: "sequence" })
));
```

### Canonicalize JSON (CAC-JSON Profile)

```rust
use apm2_core::determinism::{canonicalize_json, CacJsonError};

// Keys are sorted, whitespace removed
let canonical = canonicalize_json(r#"{"z": 1, "a": 2}"#).unwrap();
assert_eq!(canonical, r#"{"a":2,"z":1}"#);

// Floats are rejected
let err = canonicalize_json(r#"{"x": 1.5}"#).unwrap_err();
assert!(matches!(err, CacJsonError::FloatNotAllowed));

// Duplicate keys are rejected
let err = canonicalize_json(r#"{"a": 1, "a": 2}"#).unwrap_err();
assert!(matches!(err, CacJsonError::DuplicateKey { .. }));
```

### Check if JSON is Canonical

```rust
use apm2_core::determinism::is_canonical;

assert!(is_canonical(r#"{"a":1,"b":2}"#));
assert!(!is_canonical(r#"{"b":2,"a":1}"#));  // Wrong key order
assert!(!is_canonical(r#"{ "a": 1 }"#));     // Has whitespace
```

## Design Principles

1. **Idempotency**: Processing the same input twice produces identical output.

2. **Crash Safety**: Interrupted writes never produce partial or corrupt files.

3. **Determinism**: Output depends only on input content, not environment.

4. **Explicit Failure**: Unsupported inputs cause explicit errors, never silent data loss.

## Related Modules

- [`apm2_core::evidence`](../evidence/AGENTS.md) - Uses atomic writes for evidence storage
- [`apm2_core::ledger`](../ledger/AGENTS.md) - Event storage that benefits from deterministic serialization
