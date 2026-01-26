//! Diff classification for distinguishing structural from content changes.
//!
//! This module provides functionality to classify differences between two YAML
//! documents as either "structural" (changes to keys, types, or structure) or
//! "free-text" (changes only to designated text content fields).
//!
//! # Classification Rules
//!
//! ## Structural Changes
//! - Adding or removing keys
//! - Changing the type of a value (e.g., string to array)
//! - Changing array lengths
//! - Any change to a field not designated as free-text
//!
//! ## Free-Text Changes
//! - Changes only to designated free-text fields (e.g., description, summary)
//! - The structure, types, and non-text fields remain identical
//!
//! # Example
//!
//! ```
//! use apm2_core::determinism::{DiffClassification, classify_diff};
//!
//! let old = r"
//! id: TCK-001
//! title: Fix bug
//! description: Old description
//! ";
//!
//! let new = r"
//! id: TCK-001
//! title: Fix bug
//! description: New and improved description
//! ";
//!
//! let classification = classify_diff(old, new);
//! assert_eq!(classification, DiffClassification::FreeText);
//! ```

use serde_yaml::Value;

/// Default list of field names considered to contain free-text content.
///
/// Changes to these fields are classified as free-text changes, while
/// changes to any other fields are classified as structural changes.
pub const DEFAULT_FREE_TEXT_FIELDS: &[&str] = &[
    "description",
    "summary",
    "rationale",
    "notes",
    "comment",
    "comments",
    "details",
    "explanation",
    "justification",
    "reasoning",
    "remarks",
    "purpose",
    "context",
    "background",
];

/// Classification of differences between two YAML documents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DiffClassification {
    /// The documents are identical.
    Identical,

    /// Only free-text fields have changed.
    FreeText,

    /// Structural changes are present (keys, types, array lengths, or non-text
    /// fields).
    Structural,
}

/// Classifies the difference between two YAML documents.
///
/// Uses the default list of free-text fields to determine classification.
///
/// # Arguments
///
/// * `old` - The original YAML content as a string
/// * `new` - The new YAML content as a string
///
/// # Returns
///
/// The classification of the difference:
/// - `Identical` if both documents are semantically equal
/// - `FreeText` if only free-text fields differ
/// - `Structural` if any structural changes exist (including parse errors)
#[must_use]
pub fn classify_diff(old: &str, new: &str) -> DiffClassification {
    classify_diff_with_fields(old, new, DEFAULT_FREE_TEXT_FIELDS)
}

/// Classifies the difference between two YAML documents with custom free-text
/// fields.
///
/// # Arguments
///
/// * `old` - The original YAML content as a string
/// * `new` - The new YAML content as a string
/// * `free_text_fields` - Field names to treat as free-text
///
/// # Returns
///
/// The classification of the difference.
#[must_use]
pub fn classify_diff_with_fields(
    old: &str,
    new: &str,
    free_text_fields: &[&str],
) -> DiffClassification {
    // Parse both documents
    let Ok(old_value): Result<Value, _> = serde_yaml::from_str(old) else {
        return DiffClassification::Structural;
    };

    let Ok(new_value): Result<Value, _> = serde_yaml::from_str(new) else {
        return DiffClassification::Structural;
    };

    // Compare the values
    compare_values(&old_value, &new_value, free_text_fields, &[])
}

/// Recursively compares two YAML values and classifies their difference.
fn compare_values(
    old: &Value,
    new: &Value,
    free_text_fields: &[&str],
    path: &[String],
) -> DiffClassification {
    // Check if current field is a free-text field
    let current_field = path.last().map(String::as_str);
    let is_free_text = current_field.is_some_and(|f| free_text_fields.contains(&f));

    match (old, new) {
        // Both null
        (Value::Null, Value::Null) => DiffClassification::Identical,

        // Both booleans
        (Value::Bool(a), Value::Bool(b)) => {
            if a == b {
                DiffClassification::Identical
            } else {
                DiffClassification::Structural
            }
        },

        // Both numbers
        (Value::Number(a), Value::Number(b)) => {
            if a == b {
                DiffClassification::Identical
            } else {
                DiffClassification::Structural
            }
        },

        // Both strings
        (Value::String(a), Value::String(b)) => {
            if a == b {
                DiffClassification::Identical
            } else if is_free_text {
                DiffClassification::FreeText
            } else {
                DiffClassification::Structural
            }
        },

        // Both sequences
        (Value::Sequence(a), Value::Sequence(b)) => {
            // Different lengths are structural changes
            if a.len() != b.len() {
                return DiffClassification::Structural;
            }

            // Compare each element
            let mut has_freetext_diff = false;
            for (i, (old_elem, new_elem)) in a.iter().zip(b.iter()).enumerate() {
                let mut elem_path = path.to_vec();
                elem_path.push(format!("[{i}]"));

                match compare_values(old_elem, new_elem, free_text_fields, &elem_path) {
                    DiffClassification::Structural => return DiffClassification::Structural,
                    DiffClassification::FreeText => has_freetext_diff = true,
                    DiffClassification::Identical => {},
                }
            }

            if has_freetext_diff {
                DiffClassification::FreeText
            } else {
                DiffClassification::Identical
            }
        },

        // Both mappings
        (Value::Mapping(a), Value::Mapping(b)) => {
            // Check for key differences (structural change)
            let old_keys: std::collections::HashSet<_> =
                a.keys().filter_map(|k| k.as_str()).collect();
            let new_keys: std::collections::HashSet<_> =
                b.keys().filter_map(|k| k.as_str()).collect();

            if old_keys != new_keys {
                return DiffClassification::Structural;
            }

            // Compare values for each key
            let mut has_freetext_diff = false;
            for (key, old_value) in a {
                let Some(key_str) = key.as_str() else {
                    return DiffClassification::Structural;
                };

                let Some(new_value) = b.get(key) else {
                    return DiffClassification::Structural;
                };

                let mut child_path = path.to_vec();
                child_path.push(key_str.to_string());

                match compare_values(old_value, new_value, free_text_fields, &child_path) {
                    DiffClassification::Structural => return DiffClassification::Structural,
                    DiffClassification::FreeText => has_freetext_diff = true,
                    DiffClassification::Identical => {},
                }
            }

            if has_freetext_diff {
                DiffClassification::FreeText
            } else {
                DiffClassification::Identical
            }
        },

        // Type mismatch is always structural
        _ => DiffClassification::Structural,
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    pub fn test_structural_diff() {
        // Test adding a key
        let old = r"
id: TCK-001
title: Test
";
        let new = r"
id: TCK-001
title: Test
new_key: value
";
        assert_eq!(classify_diff(old, new), DiffClassification::Structural);

        // Test removing a key
        let old = r"
id: TCK-001
title: Test
status: active
";
        let new = r"
id: TCK-001
title: Test
";
        assert_eq!(classify_diff(old, new), DiffClassification::Structural);

        // Test changing a type
        let old = r"
id: TCK-001
count: 5
";
        let new = r"
id: TCK-001
count: five
";
        assert_eq!(classify_diff(old, new), DiffClassification::Structural);

        // Test changing array length
        let old = r"
items:
  - one
  - two
";
        let new = r"
items:
  - one
  - two
  - three
";
        assert_eq!(classify_diff(old, new), DiffClassification::Structural);
    }

    #[test]
    pub fn test_freetext_diff() {
        // Test changing description only
        let old = r"
id: TCK-001
title: Test
description: Old description text
";
        let new = r"
id: TCK-001
title: Test
description: New description with more details
";
        assert_eq!(classify_diff(old, new), DiffClassification::FreeText);

        // Test changing summary only
        let old = r"
id: RFC-001
summary: Original summary
status: draft
";
        let new = r"
id: RFC-001
summary: Updated summary with more context
status: draft
";
        assert_eq!(classify_diff(old, new), DiffClassification::FreeText);

        // Test changing multiple free-text fields
        let old = r"
id: TCK-001
description: Old desc
notes: Old notes
rationale: Old rationale
";
        let new = r"
id: TCK-001
description: New desc
notes: New notes
rationale: New rationale
";
        assert_eq!(classify_diff(old, new), DiffClassification::FreeText);
    }

    #[test]
    fn test_identical_documents() {
        let doc = r"
id: TCK-001
title: Test
description: Some description
";
        assert_eq!(classify_diff(doc, doc), DiffClassification::Identical);
    }

    #[test]
    fn test_mixed_changes_is_structural() {
        // When both structural and free-text changes exist, classify as structural
        let old = r"
id: TCK-001
title: Test
description: Old description
";
        let new = r"
id: TCK-002
title: Test
description: New description
";
        assert_eq!(classify_diff(old, new), DiffClassification::Structural);
    }

    #[test]
    fn test_nested_freetext_field() {
        let old = r"
ticket:
  id: TCK-001
  description: Old nested description
";
        let new = r"
ticket:
  id: TCK-001
  description: New nested description
";
        assert_eq!(classify_diff(old, new), DiffClassification::FreeText);
    }

    #[test]
    fn test_nested_structural_change() {
        let old = r"
ticket:
  id: TCK-001
  status: open
";
        let new = r"
ticket:
  id: TCK-001
  status: closed
";
        assert_eq!(classify_diff(old, new), DiffClassification::Structural);
    }

    #[test]
    fn test_parse_error_is_structural() {
        let valid = "key: value";
        let invalid = "key: [unclosed";

        assert_eq!(
            classify_diff(valid, invalid),
            DiffClassification::Structural
        );
        assert_eq!(
            classify_diff(invalid, valid),
            DiffClassification::Structural
        );
    }

    #[test]
    fn test_custom_free_text_fields() {
        let old = r"
id: TCK-001
custom_field: old value
";
        let new = r"
id: TCK-001
custom_field: new value
";

        // With default fields, this is structural
        assert_eq!(classify_diff(old, new), DiffClassification::Structural);

        // With custom fields including custom_field, this is free-text
        let custom_fields = &["custom_field"];
        assert_eq!(
            classify_diff_with_fields(old, new, custom_fields),
            DiffClassification::FreeText
        );
    }

    #[test]
    fn test_array_element_freetext_change() {
        let old = r"
items:
  - id: 1
    description: Old item desc
  - id: 2
    description: Another old desc
";
        let new = r"
items:
  - id: 1
    description: New item desc
  - id: 2
    description: Another new desc
";
        assert_eq!(classify_diff(old, new), DiffClassification::FreeText);
    }

    #[test]
    fn test_array_element_structural_change() {
        let old = r"
items:
  - id: 1
    status: open
  - id: 2
    status: open
";
        let new = r"
items:
  - id: 1
    status: closed
  - id: 2
    status: open
";
        assert_eq!(classify_diff(old, new), DiffClassification::Structural);
    }

    #[test]
    fn test_empty_documents() {
        assert_eq!(classify_diff("", ""), DiffClassification::Identical);
        assert_eq!(classify_diff("null", "null"), DiffClassification::Identical);
        assert_eq!(classify_diff("~", "~"), DiffClassification::Identical);
    }

    #[test]
    fn test_whitespace_normalization() {
        // YAML ignores most whitespace differences
        let old = "key:   value";
        let new = "key: value";
        assert_eq!(classify_diff(old, new), DiffClassification::Identical);
    }

    #[test]
    fn test_boolean_change_is_structural() {
        let old = "enabled: true";
        let new = "enabled: false";
        assert_eq!(classify_diff(old, new), DiffClassification::Structural);
    }

    #[test]
    fn test_number_change_is_structural() {
        let old = "count: 10";
        let new = "count: 20";
        assert_eq!(classify_diff(old, new), DiffClassification::Structural);
    }

    #[test]
    fn test_null_change_is_structural() {
        let old = "value: null";
        let new = "value: something";
        assert_eq!(classify_diff(old, new), DiffClassification::Structural);
    }

    #[test]
    fn test_deeply_nested_freetext() {
        let old = r"
level1:
  level2:
    level3:
      description: Deep old description
";
        let new = r"
level1:
  level2:
    level3:
      description: Deep new description
";
        assert_eq!(classify_diff(old, new), DiffClassification::FreeText);
    }

    #[test]
    fn test_complex_document() {
        let old = r"
schema_version: '2024-01'
ticket:
  id: TCK-00110
  title: Implement feature
  status: READY
  description: Original description for the feature
  implementation:
    summary: Original summary of implementation
    files:
      - path: src/lib.rs
        changes: Add module
      - path: src/mod.rs
        changes: Export
    steps:
      - step: 1
        action: Create files
        details: Create the necessary files
  notes: Original notes about the ticket
";
        let new = r"
schema_version: '2024-01'
ticket:
  id: TCK-00110
  title: Implement feature
  status: READY
  description: Updated description with more context
  implementation:
    summary: Updated summary with clearer explanation
    files:
      - path: src/lib.rs
        changes: Add module
      - path: src/mod.rs
        changes: Export
    steps:
      - step: 1
        action: Create files
        details: Create the necessary source files
  notes: Updated notes with additional information
";
        assert_eq!(classify_diff(old, new), DiffClassification::FreeText);
    }

    #[test]
    fn test_all_default_freetext_fields() {
        // Test each default free-text field
        for field in DEFAULT_FREE_TEXT_FIELDS {
            let old = format!("{field}: old value");
            let new = format!("{field}: new value");
            assert_eq!(
                classify_diff(&old, &new),
                DiffClassification::FreeText,
                "Field '{field}' should be classified as free-text",
            );
        }
    }
}
