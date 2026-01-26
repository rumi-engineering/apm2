# Determinism Module

> Primitives for reproducible, crash-safe file output in the APM2 compiler pipeline.

## Overview

The `apm2_core::determinism` module provides foundational capabilities for ensuring deterministic, reproducible output from all compiler stages. It addresses three core challenges:

1. **YAML Canonicalization**: Produces identical output regardless of input key order or formatting, enabling meaningful diffs and reproducible builds.

2. **Atomic File Writes**: Ensures files are either fully written or not modified at all, preventing corruption on crashes or interruptions.

3. **Diff Classification**: Distinguishes structural changes from free-text content changes, enabling intelligent merge decisions in the compiler.

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
| `write_atomic(path, content)` | Write file atomically (crash-safe) |
| `classify_diff(old, new)` | Classify changes between two strings |
| `classify_diff_with_fields(old, new, fields)` | Classify with custom free-text fields |

| Constant | Description |
|----------|-------------|
| `DEFAULT_FREE_TEXT_FIELDS` | Default fields considered free-text |

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

## Design Principles

1. **Idempotency**: Processing the same input twice produces identical output.

2. **Crash Safety**: Interrupted writes never produce partial or corrupt files.

3. **Determinism**: Output depends only on input content, not environment.

4. **Explicit Failure**: Unsupported inputs cause explicit errors, never silent data loss.

## Related Modules

- [`apm2_core::evidence`](../evidence/AGENTS.md) - Uses atomic writes for evidence storage
- [`apm2_core::ledger`](../ledger/AGENTS.md) - Event storage that benefits from deterministic serialization
