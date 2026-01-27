//! Determinism primitives for reproducible compiler output.
//!
//! This module provides foundational capabilities for ensuring deterministic,
//! reproducible output from all compiler stages:
//!
//! - **YAML Canonicalization**: Produces identical output regardless of input
//!   key order or formatting
//! - **JSON Canonicalization (CAC-JSON)**: RFC 8785 JCS-based canonicalization
//!   with CAC-specific constraints (integer-only, NFC strings, depth limits)
//! - **Atomic File Writes**: Ensures files are either fully written or not
//!   modified, preventing corruption on crashes
//! - **Diff Classification**: Distinguishes structural changes from free-text
//!   content changes for intelligent merge decisions
//!
//! # Design Principles
//!
//! 1. **Idempotency**: Processing the same input twice produces identical
//!    output
//! 2. **Crash Safety**: Interrupted writes never produce partial or corrupt
//!    files
//! 3. **Determinism**: Output depends only on input content, not environment
//!
//! # Example
//!
//! ```
//! use apm2_core::determinism::{
//!     DiffClassification, canonicalize_json, canonicalize_yaml, classify_diff,
//! };
//! use serde_yaml::Value;
//!
//! // Canonicalize YAML for consistent output
//! let yaml: Value = serde_yaml::from_str(
//!     r"
//! zebra: 1
//! apple: 2
//! ",
//! )
//! .unwrap();
//! let canonical = canonicalize_yaml(&yaml).unwrap();
//! assert!(canonical.starts_with("apple:"));
//!
//! // Canonicalize JSON (CAC-JSON profile)
//! let json_canonical = canonicalize_json(r#"{"z": 1, "a": 2}"#).unwrap();
//! assert_eq!(json_canonical, r#"{"a":2,"z":1}"#);
//!
//! // Classify changes between versions
//! let old = "id: TCK-001\ndescription: Old desc";
//! let new = "id: TCK-001\ndescription: New desc";
//! assert_eq!(classify_diff(old, new), DiffClassification::FreeText);
//! ```
//!
//! # Module Structure
//!
//! - `canonicalize`: YAML canonicalization functions
//! - `canonicalize_json`: CAC-JSON canonicalization (RFC 8785 JCS profile)
//! - `atomic_write`: Crash-safe file writing
//! - `diff_classify`: Diff classification logic

mod atomic_write;
mod canonicalize;
mod canonicalize_json;
mod diff_classify;

// Re-export primary API
pub use atomic_write::{AtomicWriteError, write_atomic};
pub use canonicalize::{CanonicalizeError, canonicalize_yaml};
pub use canonicalize_json::{
    CANONICALIZER_ID, CANONICALIZER_VERSION, CacJson, CacJsonError, MAX_DEPTH, canonicalize_json,
    is_canonical, validate_and_parse,
};
pub use diff_classify::{
    DEFAULT_FREE_TEXT_FIELDS, DiffClassification, classify_diff, classify_diff_with_fields,
};

#[cfg(test)]
mod tests {
    use std::fs;

    use serde_yaml::Value;
    use tempfile::TempDir;

    use super::*;

    /// Integration test: canonicalize and write atomically.
    #[test]
    fn test_canonicalize_and_write() {
        let temp_dir = TempDir::new().unwrap();
        let target = temp_dir.path().join("output.yaml");

        let input = r"
zebra: 3
apple: 1
mango:
  z_nested: value
  a_nested: value
";

        let value: Value = serde_yaml::from_str(input).unwrap();
        let canonical = canonicalize_yaml(&value).unwrap();

        // Write atomically
        write_atomic(&target, canonical.as_bytes()).unwrap();

        // Read back and verify
        let content = fs::read_to_string(&target).unwrap();
        assert_eq!(content, canonical);

        // Verify key ordering
        let apple_pos = content.find("apple:").unwrap();
        let mango_pos = content.find("mango:").unwrap();
        let zebra_pos = content.find("zebra:").unwrap();
        assert!(apple_pos < mango_pos);
        assert!(mango_pos < zebra_pos);
    }

    /// Integration test: write, modify description, classify as free-text.
    #[test]
    fn test_write_and_classify_freetext_change() {
        let temp_dir = TempDir::new().unwrap();
        let target = temp_dir.path().join("doc.yaml");

        let original = r"
id: TCK-001
title: Feature X
description: Original description of the feature
status: READY
";

        // Write original
        let orig_value: Value = serde_yaml::from_str(original).unwrap();
        let orig_canonical = canonicalize_yaml(&orig_value).unwrap();
        write_atomic(&target, orig_canonical.as_bytes()).unwrap();

        // Modify only the description
        let modified = r"
id: TCK-001
title: Feature X
description: Updated description with more details about the feature
status: READY
";

        let mod_value: Value = serde_yaml::from_str(modified).unwrap();
        let mod_canonical = canonicalize_yaml(&mod_value).unwrap();

        // Classify the diff
        let classification = classify_diff(&orig_canonical, &mod_canonical);
        assert_eq!(classification, DiffClassification::FreeText);
    }

    /// Integration test: write, modify id, classify as structural.
    #[test]
    fn test_write_and_classify_structural_change() {
        let temp_dir = TempDir::new().unwrap();
        let target = temp_dir.path().join("doc.yaml");

        let original = r"
id: TCK-001
title: Feature X
description: Description
";

        // Write original
        let orig_value: Value = serde_yaml::from_str(original).unwrap();
        let orig_canonical = canonicalize_yaml(&orig_value).unwrap();
        write_atomic(&target, orig_canonical.as_bytes()).unwrap();

        // Modify the id (structural change)
        let modified = r"
id: TCK-002
title: Feature X
description: Description
";

        let mod_value: Value = serde_yaml::from_str(modified).unwrap();
        let mod_canonical = canonicalize_yaml(&mod_value).unwrap();

        // Classify the diff
        let classification = classify_diff(&orig_canonical, &mod_canonical);
        assert_eq!(classification, DiffClassification::Structural);
    }

    /// Integration test: verify canonicalization is deterministic across
    /// parses.
    #[test]
    fn test_canonicalization_determinism() {
        let inputs = [
            "{ a: 1, b: 2, c: 3 }",
            "{ c: 3, b: 2, a: 1 }",
            "{ b: 2, a: 1, c: 3 }",
        ];

        let mut canonicals: Vec<String> = Vec::new();
        for input in &inputs {
            let value: Value = serde_yaml::from_str(input).unwrap();
            canonicals.push(canonicalize_yaml(&value).unwrap());
        }

        // All should produce identical output
        assert!(
            canonicals.windows(2).all(|w| w[0] == w[1]),
            "All inputs should produce identical canonical output"
        );
    }

    /// Integration test: full workflow with nested structures.
    #[test]
    fn test_full_workflow_nested() {
        let temp_dir = TempDir::new().unwrap();

        let doc = r"
schema_version: '2024-01'
ticket:
  id: TCK-00110
  title: Implement determinism module
  status: READY
  implementation:
    summary: Create the determinism module in apm2-core
    files_to_create:
      - path: src/determinism/mod.rs
        purpose: Module root
      - path: src/determinism/canonicalize.rs
        purpose: YAML canonicalization
notes: This is a test document
";

        // Parse, canonicalize, and write
        let value: Value = serde_yaml::from_str(doc).unwrap();
        let canonical = canonicalize_yaml(&value).unwrap();

        let target = temp_dir.path().join("ticket.yaml");
        write_atomic(&target, canonical.as_bytes()).unwrap();

        // Read back
        let content = fs::read_to_string(&target).unwrap();
        assert_eq!(content, canonical);

        // Re-parse and re-canonicalize should be identical (idempotent)
        let reparsed: Value = serde_yaml::from_str(&content).unwrap();
        let recanonical = canonicalize_yaml(&reparsed).unwrap();
        assert_eq!(canonical, recanonical);

        // Diff with itself should be identical
        assert_eq!(
            classify_diff(&canonical, &recanonical),
            DiffClassification::Identical
        );
    }
}
