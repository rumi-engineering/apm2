//! YAML canonicalization for deterministic output.
//!
//! This module provides functions to produce canonical YAML output that is
//! identical regardless of the input key order or formatting. This is
//! essential for reproducible builds and meaningful diffs.
//!
//! # Canonicalization Rules
//!
//! 1. All mapping keys are sorted lexicographically (byte order)
//! 2. Two-space indentation is used consistently
//! 3. No trailing whitespace on any line
//! 4. Consistent quoting: simple strings are unquoted, complex strings quoted
//! 5. Null values are represented as `null`
//!
//! # Complex Keys
//!
//! YAML allows sequences and mappings as keys, but this canonicalizer does not
//! support them. If a complex key is encountered, an error is returned. This is
//! by design: complex keys are rare in practice and require explicit handling
//! by the caller.
//!
//! # Float Keys
//!
//! Float values as map keys are rejected because they cannot be reliably
//! normalized to a canonical string representation (e.g., `1.0` vs `1.00`).
//!
//! # Recursion Limit
//!
//! To prevent stack overflow from deeply nested input, a maximum recursion
//! depth of 128 levels is enforced.
//!
//! # Example
//!
//! ```
//! use apm2_core::determinism::canonicalize_yaml;
//! use serde_yaml::Value;
//!
//! let yaml: Value = serde_yaml::from_str(
//!     r"
//! zebra: 1
//! apple: 2
//! ",
//! )
//! .unwrap();
//!
//! let canonical = canonicalize_yaml(&yaml).unwrap();
//! assert_eq!(canonical, "apple: 2\nzebra: 1\n");
//! ```

use std::cmp::Ordering;
use std::collections::BTreeMap;

use serde_yaml::Value;
use thiserror::Error;

/// Maximum recursion depth for canonicalization to prevent stack overflow.
const MAX_DEPTH: usize = 128;

/// Errors that can occur during YAML canonicalization.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CanonicalizeError {
    /// A complex key (sequence or mapping) was encountered in a YAML mapping.
    ///
    /// YAML allows sequences and mappings as keys, but this canonicalizer does
    /// not support them because they cannot be reliably sorted as strings.
    #[error("unsupported complex YAML key: {key_type} keys cannot be canonicalized")]
    UnsupportedComplexKey {
        /// The type of complex key that was encountered ("sequence" or
        /// "mapping").
        key_type: &'static str,
    },

    /// A float key was encountered in a YAML mapping.
    ///
    /// Float keys are rejected because they cannot be reliably normalized to
    /// a canonical string representation (e.g., `1.0` vs `1.00` may produce
    /// different strings despite being semantically identical).
    #[error("unsupported float YAML key: float keys cannot be reliably canonicalized")]
    UnsupportedFloatKey,

    /// The recursion depth limit was exceeded.
    ///
    /// This error is returned when the YAML structure is nested deeper than
    /// the maximum allowed depth (128 levels). This limit exists to prevent
    /// stack overflow attacks from maliciously crafted input.
    #[error("recursion limit exceeded: YAML nested deeper than {max_depth} levels")]
    RecursionLimitExceeded {
        /// The maximum depth that was exceeded.
        max_depth: usize,
    },
}

/// A typed key representation that preserves type information for sorting.
///
/// This ensures that keys of different types (e.g., integer `123` and string
/// `"123"`) are kept distinct and sorted separately, preventing data loss from
/// key collisions.
#[derive(Debug, Clone, PartialEq, Eq)]
enum TypedKey {
    /// Null key
    Null,
    /// Boolean key
    Bool(bool),
    /// Integer key (i64)
    Int(i64),
    /// Unsigned integer key (u64 values > `i64::MAX`)
    Uint(u64),
    /// String key
    String(String),
}

impl TypedKey {
    /// Returns the type tag for ordering different types.
    /// Types are ordered: Null < Bool < Int < Uint < String
    const fn type_order(&self) -> u8 {
        match self {
            Self::Null => 0,
            Self::Bool(_) => 1,
            Self::Int(_) => 2,
            Self::Uint(_) => 3,
            Self::String(_) => 4,
        }
    }

    /// Converts the key back to a YAML `Value` for output.
    fn to_value(&self) -> Value {
        match self {
            Self::Null => Value::Null,
            Self::Bool(b) => Value::Bool(*b),
            Self::Int(n) => Value::Number((*n).into()),
            Self::Uint(n) => Value::Number((*n).into()),
            Self::String(s) => Value::String(s.clone()),
        }
    }
}

impl Ord for TypedKey {
    fn cmp(&self, other: &Self) -> Ordering {
        // First compare by type
        let type_cmp = self.type_order().cmp(&other.type_order());
        if type_cmp != Ordering::Equal {
            return type_cmp;
        }

        // Then compare within the same type
        match (self, other) {
            (Self::Bool(a), Self::Bool(b)) => a.cmp(b),
            (Self::Int(a), Self::Int(b)) => a.cmp(b),
            (Self::Uint(a), Self::Uint(b)) => a.cmp(b),
            (Self::String(a), Self::String(b)) => a.cmp(b),
            // Null == Null, and any other combinations should never happen
            // due to type_order check above
            _ => Ordering::Equal,
        }
    }
}

impl PartialOrd for TypedKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Canonicalizes a YAML value to a deterministic string representation.
///
/// The output has the following properties:
/// - All mapping keys are sorted by type first, then by value within each type
/// - Uses 2-space indentation
/// - No trailing whitespace
/// - Idempotent: `canonicalize_yaml(parse(canonicalize_yaml(v))) ==
///   canonicalize_yaml(v)`
///
/// # Arguments
///
/// * `value` - The YAML value to canonicalize
///
/// # Returns
///
/// A canonical string representation of the YAML value, or an error if the
/// value contains unsupported keys or exceeds the recursion limit.
///
/// # Errors
///
/// Returns [`CanonicalizeError::UnsupportedComplexKey`] if the YAML value
/// contains a mapping with a sequence or mapping as a key.
///
/// Returns [`CanonicalizeError::UnsupportedFloatKey`] if a float is used as a
/// map key.
///
/// Returns [`CanonicalizeError::RecursionLimitExceeded`] if the YAML structure
/// is nested deeper than 128 levels.
pub fn canonicalize_yaml(value: &Value) -> Result<String, CanonicalizeError> {
    let sorted = sort_keys_recursive(value, 0)?;
    let mut output = String::new();
    emit_value(&sorted, 0, true, &mut output);
    Ok(output)
}

/// Recursively sorts all mapping keys in a YAML value.
///
/// # Arguments
///
/// * `value` - The YAML value to process
/// * `depth` - Current recursion depth (starts at 0)
///
/// # Errors
///
/// Returns an error if any mapping contains a complex key (sequence or
/// mapping), a float key, or if the recursion limit is exceeded.
fn sort_keys_recursive(value: &Value, depth: usize) -> Result<Value, CanonicalizeError> {
    // Check recursion limit
    if depth > MAX_DEPTH {
        return Err(CanonicalizeError::RecursionLimitExceeded {
            max_depth: MAX_DEPTH,
        });
    }

    match value {
        Value::Mapping(map) => {
            // Convert to BTreeMap with TypedKey for type-safe sorted iteration
            let mut sorted: BTreeMap<TypedKey, Value> = BTreeMap::new();
            for (k, v) in map {
                let key = yaml_key_to_typed(k)?;
                let value = sort_keys_recursive(v, depth + 1)?;
                sorted.insert(key, value);
            }

            // Convert back to a Mapping with sorted keys
            let mut result = serde_yaml::Mapping::new();
            for (key, val) in sorted {
                result.insert(key.to_value(), val);
            }
            Ok(Value::Mapping(result))
        },
        Value::Sequence(seq) => {
            let sorted: Result<Vec<Value>, CanonicalizeError> = seq
                .iter()
                .map(|v| sort_keys_recursive(v, depth + 1))
                .collect();
            Ok(Value::Sequence(sorted?))
        },
        other => Ok(other.clone()),
    }
}

/// Converts a YAML key to a `TypedKey` for type-safe sorting.
///
/// # Errors
///
/// Returns an error if the key is a complex type (sequence or mapping) or a
/// float.
fn yaml_key_to_typed(key: &Value) -> Result<TypedKey, CanonicalizeError> {
    match key {
        Value::String(s) => Ok(TypedKey::String(s.clone())),
        Value::Number(n) => {
            // Strictly reject floats - they cannot be reliably normalized.
            // This rejects all float representations including integral floats
            // like 1.0 to avoid normalization ambiguity where 1.0 could collide
            // with integer 1.
            if n.is_f64() {
                return Err(CanonicalizeError::UnsupportedFloatKey);
            }
            // Handle integers: try i64 first, then u64
            n.as_i64().map_or_else(
                || {
                    n.as_u64()
                        .map_or(Err(CanonicalizeError::UnsupportedFloatKey), |u| {
                            // u64 values that fit in i64
                            i64::try_from(u).map_or_else(
                                |_| {
                                    // Large u64 values (> i64::MAX) - use Uint variant
                                    // to prevent collision with string representation
                                    Ok(TypedKey::Uint(u))
                                },
                                |i| Ok(TypedKey::Int(i)),
                            )
                        })
                },
                |i| Ok(TypedKey::Int(i)),
            )
        },
        Value::Bool(b) => Ok(TypedKey::Bool(*b)),
        Value::Null => Ok(TypedKey::Null),
        Value::Sequence(_) => Err(CanonicalizeError::UnsupportedComplexKey {
            key_type: "sequence",
        }),
        Value::Mapping(_) => Err(CanonicalizeError::UnsupportedComplexKey {
            key_type: "mapping",
        }),
        Value::Tagged(tagged) => yaml_key_to_typed(&tagged.value),
    }
}

/// Emits a YAML value to the output string.
fn emit_value(value: &Value, indent: usize, at_line_start: bool, output: &mut String) {
    match value {
        Value::Null => output.push_str("null"),
        Value::Bool(b) => output.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => output.push_str(&n.to_string()),
        Value::String(s) => emit_string(s, output),
        Value::Sequence(seq) => emit_sequence(seq, indent, at_line_start, output),
        Value::Mapping(map) => emit_mapping(map, indent, at_line_start, output),
        Value::Tagged(tagged) => {
            // Handle tagged values by emitting the tag and then the value
            output.push('!');
            output.push_str(&tagged.tag.to_string());
            output.push(' ');
            emit_value(&tagged.value, indent, false, output);
        },
    }
}

/// Emits a string value, quoting if necessary.
fn emit_string(s: &str, output: &mut String) {
    if needs_quoting(s) {
        emit_quoted_string(s, output);
    } else {
        output.push_str(s);
    }
}

/// Determines if a string needs to be quoted in YAML.
fn needs_quoting(s: &str) -> bool {
    if s.is_empty() {
        return true;
    }

    // Check for reserved words
    let lower = s.to_lowercase();
    if matches!(
        lower.as_str(),
        "true" | "false" | "null" | "yes" | "no" | "on" | "off" | "~"
    ) {
        return true;
    }

    // Check for characters that require quoting
    let first = s.chars().next().unwrap();
    if first.is_ascii_digit()
        || first == '-'
        || first == '.'
        || first == '['
        || first == '{'
        || first == '!'
        || first == '&'
        || first == '*'
        || first == '\''
        || first == '"'
        || first == '|'
        || first == '>'
        || first == '%'
        || first == '@'
        || first == '`'
    {
        return true;
    }

    // Check for special characters anywhere in the string
    s.contains(':')
        || s.contains('#')
        || s.contains('\n')
        || s.contains('\r')
        || s.contains('\t')
        || s.starts_with(' ')
        || s.ends_with(' ')
        || s.contains("  ")
}

/// Emits a double-quoted string with proper escaping.
fn emit_quoted_string(s: &str, output: &mut String) {
    use std::fmt::Write;
    output.push('"');
    for c in s.chars() {
        match c {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            c if c.is_control() => {
                let code = c as u32;
                let _ = write!(output, "\\u{code:04x}");
            },
            c => output.push(c),
        }
    }
    output.push('"');
}

/// Emits a sequence (array) value.
fn emit_sequence(seq: &[Value], indent: usize, at_line_start: bool, output: &mut String) {
    if seq.is_empty() {
        output.push_str("[]");
        return;
    }

    // For sequences that are not at the start of a line, we need a newline first
    if !at_line_start {
        output.push('\n');
    }

    for item in seq {
        // Add indent
        for _ in 0..indent {
            output.push_str("  ");
        }
        output.push_str("- ");

        // Check if item is a mapping - if so, emit first key on same line
        if let Value::Mapping(map) = item {
            if map.is_empty() {
                output.push_str("{}");
            } else {
                emit_mapping_inline_first(map, indent + 1, output);
            }
        } else {
            emit_value(item, indent + 1, false, output);
        }

        // Ensure each item ends with a newline
        if !output.ends_with('\n') {
            output.push('\n');
        }
    }
}

/// Emits a mapping's first key-value on the current line, rest indented below.
fn emit_mapping_inline_first(map: &serde_yaml::Mapping, indent: usize, output: &mut String) {
    let mut first = true;
    for (key, val) in map {
        if first {
            first = false;
            // Emit first key-value on current line
            emit_value(key, indent, false, output);
        } else {
            // Emit subsequent key-values on new lines with indent
            for _ in 0..indent {
                output.push_str("  ");
            }
            emit_value(key, indent, true, output);
        }

        // Common code for all key-value pairs
        output.push(':');
        if is_scalar(val) {
            output.push(' ');
            emit_value(val, indent, false, output);
            output.push('\n');
        } else if is_inline_empty(val) {
            // Handle empty sequences [] and empty mappings {} on same line
            output.push(' ');
            emit_value(val, indent, false, output);
            output.push('\n');
        } else {
            emit_value(val, indent, false, output);
        }
    }
}

/// Emits a mapping (object) value.
fn emit_mapping(
    map: &serde_yaml::Mapping,
    indent: usize,
    at_line_start: bool,
    output: &mut String,
) {
    if map.is_empty() {
        output.push_str("{}");
        return;
    }

    // For mappings that are not at the start of a line, we need a newline first
    if !at_line_start {
        output.push('\n');
    }

    for (key, val) in map {
        // Add indent
        for _ in 0..indent {
            output.push_str("  ");
        }
        emit_value(key, indent, true, output);
        output.push(':');

        if is_scalar(val) {
            output.push(' ');
            emit_value(val, indent + 1, false, output);
            output.push('\n');
        } else if is_inline_empty(val) {
            // Handle empty sequences [] and empty mappings {} on same line
            output.push(' ');
            emit_value(val, indent + 1, false, output);
            output.push('\n');
        } else {
            emit_value(val, indent + 1, false, output);
        }
    }
}

/// Returns true if the value is an empty sequence or mapping that will be
/// emitted inline.
fn is_inline_empty(value: &Value) -> bool {
    match value {
        Value::Sequence(seq) => seq.is_empty(),
        Value::Mapping(map) => map.is_empty(),
        _ => false,
    }
}

/// Returns true if the value is a scalar (not a collection).
#[allow(clippy::missing_const_for_fn)] // matches! on Value is not const-compatible
fn is_scalar(value: &Value) -> bool {
    matches!(
        value,
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_)
    )
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    pub fn test_canonicalize_idempotent() {
        let inputs = [
            r"
zebra: 1
apple: 2
mango: 3
",
            r"
nested:
  z_key: value
  a_key: value
  m_key:
    deep_z: 1
    deep_a: 2
",
            r"
list:
  - c: 3
    a: 1
    b: 2
  - single: value
",
        ];

        for input in &inputs {
            let value: Value = serde_yaml::from_str(input).unwrap();
            let canonical1 = canonicalize_yaml(&value).unwrap();
            let reparsed: Value = serde_yaml::from_str(&canonical1).unwrap();
            let canonical2 = canonicalize_yaml(&reparsed).unwrap();
            assert_eq!(
                canonical1, canonical2,
                "Canonicalization should be idempotent"
            );
        }
    }

    #[test]
    pub fn test_nested_key_sorting() {
        let input = r"
outer:
  zebra: 1
  apple: 2
  nested:
    zoo: deep
    ant: value
";
        let value: Value = serde_yaml::from_str(input).unwrap();
        let canonical = canonicalize_yaml(&value).unwrap();

        // Verify outer keys are sorted
        let apple_pos = canonical.find("apple:").unwrap();
        let nested_pos = canonical.find("nested:").unwrap();
        let zebra_pos = canonical.find("zebra:").unwrap();
        assert!(
            apple_pos < nested_pos,
            "apple should come before nested: apple_pos={apple_pos}, nested_pos={nested_pos}",
        );
        assert!(
            nested_pos < zebra_pos,
            "nested should come before zebra: nested_pos={nested_pos}, zebra_pos={zebra_pos}",
        );

        // Verify nested keys are sorted
        let ant_pos = canonical.find("ant:").unwrap();
        let zoo_pos = canonical.find("zoo:").unwrap();
        assert!(
            ant_pos < zoo_pos,
            "ant should come before zoo: ant_pos={ant_pos}, zoo_pos={zoo_pos}",
        );
    }

    #[test]
    fn test_two_space_indent() {
        let input = r"
parent:
  child:
    grandchild: value
";
        let value: Value = serde_yaml::from_str(input).unwrap();
        let canonical = canonicalize_yaml(&value).unwrap();

        // Check that grandchild is indented with 4 spaces (2 levels * 2 spaces)
        assert!(
            canonical.contains("    grandchild:"),
            "Expected 4-space indent for grandchild, got:\n{canonical}",
        );
    }

    #[test]
    fn test_no_trailing_whitespace() {
        let input = r"
key1: value1
key2: value2
nested:
  inner: value
";
        let value: Value = serde_yaml::from_str(input).unwrap();
        let canonical = canonicalize_yaml(&value).unwrap();

        for (i, line) in canonical.lines().enumerate() {
            assert!(
                !line.ends_with(' ') && !line.ends_with('\t'),
                "Line {} has trailing whitespace: {line:?}",
                i + 1,
            );
        }
    }

    #[test]
    fn test_empty_mapping() {
        let value = Value::Mapping(serde_yaml::Mapping::new());
        let canonical = canonicalize_yaml(&value).unwrap();
        assert_eq!(canonical, "{}");
    }

    #[test]
    fn test_empty_sequence() {
        let value = Value::Sequence(vec![]);
        let canonical = canonicalize_yaml(&value).unwrap();
        assert_eq!(canonical, "[]");
    }

    #[test]
    fn test_null_value() {
        let input = "key: null";
        let value: Value = serde_yaml::from_str(input).unwrap();
        let canonical = canonicalize_yaml(&value).unwrap();
        assert_eq!(canonical, "key: null\n");
    }

    #[test]
    fn test_boolean_values() {
        let input = r"
yes_val: true
no_val: false
";
        let value: Value = serde_yaml::from_str(input).unwrap();
        let canonical = canonicalize_yaml(&value).unwrap();
        assert!(canonical.contains("no_val: false"));
        assert!(canonical.contains("yes_val: true"));
    }

    #[test]
    fn test_string_quoting() {
        // Strings that need quoting
        let cases = [
            ("key: 'true'", "key: \"true\"\n"), // Reserved word
            ("key: ''", "key: \"\"\n"),         // Empty string
            ("key: 'hello world: test'", "key: \"hello world: test\"\n"), // Contains colon
        ];

        for (input, expected) in &cases {
            let value: Value = serde_yaml::from_str(input).unwrap();
            let canonical = canonicalize_yaml(&value).unwrap();
            assert_eq!(
                &canonical, expected,
                "Input {input:?} should produce {expected:?}, got {canonical:?}",
            );
        }
    }

    #[test]
    fn test_sequence_of_mappings() {
        let input = r"
items:
  - z: 3
    a: 1
    m: 2
  - single: value
";
        let value: Value = serde_yaml::from_str(input).unwrap();
        let canonical = canonicalize_yaml(&value).unwrap();

        // Verify keys in each mapping are sorted
        let a_pos = canonical.find("a:").unwrap();
        let m_pos = canonical.find("m:").unwrap();
        let z_pos = canonical.find("z:").unwrap();
        assert!(a_pos < m_pos, "a should come before m");
        assert!(m_pos < z_pos, "m should come before z");
    }

    #[test]
    fn test_different_input_same_output() {
        let input1 = r"
b: 2
a: 1
";
        let input2 = r"
a: 1
b: 2
";
        let value1: Value = serde_yaml::from_str(input1).unwrap();
        let value2: Value = serde_yaml::from_str(input2).unwrap();
        let canonical1 = canonicalize_yaml(&value1).unwrap();
        let canonical2 = canonicalize_yaml(&value2).unwrap();

        assert_eq!(
            canonical1, canonical2,
            "Same content with different key order should produce identical output"
        );
    }

    #[test]
    fn test_multiline_string_escaping() {
        let mut map = serde_yaml::Mapping::new();
        map.insert(
            Value::String("key".to_string()),
            Value::String("line1\nline2\nline3".to_string()),
        );
        let value = Value::Mapping(map);
        let canonical = canonicalize_yaml(&value).unwrap();

        // Should be quoted with escaped newlines
        assert!(
            canonical.contains("\\n"),
            "Multiline strings should have escaped newlines"
        );
    }

    #[test]
    fn test_numeric_values() {
        let input = r"
integer: 42
float: 3.14
negative: -10
";
        let value: Value = serde_yaml::from_str(input).unwrap();
        let canonical = canonicalize_yaml(&value).unwrap();

        assert!(canonical.contains("float: 3.14"));
        assert!(canonical.contains("integer: 42"));
        assert!(canonical.contains("negative: -10"));
    }

    #[test]
    fn test_deeply_nested_structure() {
        let input = r"
level1:
  level2:
    level3:
      level4:
        value: deep
";
        let value: Value = serde_yaml::from_str(input).unwrap();
        let canonical = canonicalize_yaml(&value).unwrap();

        // Verify proper indentation at each level
        assert!(canonical.contains("level1:\n"));
        assert!(canonical.contains("  level2:\n"));
        assert!(canonical.contains("    level3:\n"));
        assert!(canonical.contains("      level4:\n"));
        assert!(canonical.contains("        value: deep"));
    }

    #[test]
    fn test_complex_key_sequence_error() {
        // Create a mapping with a sequence as a key
        let mut map = serde_yaml::Mapping::new();
        let key = Value::Sequence(vec![Value::String("a".to_string())]);
        map.insert(key, Value::String("value".to_string()));
        let value = Value::Mapping(map);

        let result = canonicalize_yaml(&value);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(
            err,
            CanonicalizeError::UnsupportedComplexKey {
                key_type: "sequence"
            }
        );
        assert!(err.to_string().contains("sequence"));
    }

    #[test]
    fn test_complex_key_mapping_error() {
        // Create a mapping with a mapping as a key
        let mut inner_map = serde_yaml::Mapping::new();
        inner_map.insert(
            Value::String("nested".to_string()),
            Value::String("key".to_string()),
        );
        let key = Value::Mapping(inner_map);

        let mut map = serde_yaml::Mapping::new();
        map.insert(key, Value::String("value".to_string()));
        let value = Value::Mapping(map);

        let result = canonicalize_yaml(&value);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(
            err,
            CanonicalizeError::UnsupportedComplexKey {
                key_type: "mapping"
            }
        );
        assert!(err.to_string().contains("mapping"));
    }

    #[test]
    fn test_complex_key_in_nested_mapping_error() {
        // Create a nested structure with a complex key deeper in the tree
        let mut inner_map = serde_yaml::Mapping::new();
        let key = Value::Sequence(vec![Value::Number(1.into())]);
        inner_map.insert(key, Value::String("value".to_string()));

        let mut outer_map = serde_yaml::Mapping::new();
        outer_map.insert(
            Value::String("outer".to_string()),
            Value::Mapping(inner_map),
        );
        let value = Value::Mapping(outer_map);

        let result = canonicalize_yaml(&value);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            CanonicalizeError::UnsupportedComplexKey {
                key_type: "sequence"
            }
        );
    }

    // =========================================================================
    // Security fix tests (TCK-00110)
    // =========================================================================

    /// CRITICAL: Test that integer and string keys with same representation
    /// are NOT collapsed (data loss prevention).
    #[test]
    fn test_type_collision_int_vs_string_keys_preserved() {
        // Create a mapping with integer 123 and string "123" as separate keys
        let mut map = serde_yaml::Mapping::new();
        map.insert(Value::Number(123.into()), Value::String("int".to_string()));
        map.insert(
            Value::String("123".to_string()),
            Value::String("str".to_string()),
        );
        let value = Value::Mapping(map);

        let canonical = canonicalize_yaml(&value).unwrap();

        // Both keys must be present in output - no collision/data loss
        assert!(
            canonical.contains("int") && canonical.contains("str"),
            "Both integer 123 and string '123' keys must be preserved, got:\n{canonical}"
        );

        // Verify the output can be reparsed and contains both entries
        let reparsed: Value = serde_yaml::from_str(&canonical).unwrap();
        if let Value::Mapping(m) = reparsed {
            assert_eq!(
                m.len(),
                2,
                "Reparsed mapping should have 2 entries, got {}",
                m.len()
            );
        } else {
            panic!("Expected mapping");
        }
    }

    /// Test that bool and string keys are kept distinct
    #[test]
    fn test_type_collision_bool_vs_string_keys_preserved() {
        let mut map = serde_yaml::Mapping::new();
        map.insert(Value::Bool(true), Value::String("bool".to_string()));
        map.insert(
            Value::String("true".to_string()),
            Value::String("str".to_string()),
        );
        let value = Value::Mapping(map);

        let canonical = canonicalize_yaml(&value).unwrap();

        // Both values must be present
        assert!(
            canonical.contains("bool") && canonical.contains("str"),
            "Both bool true and string 'true' keys must be preserved, got:\n{canonical}"
        );
    }

    /// Test that null and string "null" keys are kept distinct
    #[test]
    fn test_type_collision_null_vs_string_keys_preserved() {
        let mut map = serde_yaml::Mapping::new();
        map.insert(Value::Null, Value::String("null_key".to_string()));
        map.insert(
            Value::String("null".to_string()),
            Value::String("str_key".to_string()),
        );
        let value = Value::Mapping(map);

        let canonical = canonicalize_yaml(&value).unwrap();

        // Both values must be present
        assert!(
            canonical.contains("null_key") && canonical.contains("str_key"),
            "Both null and string 'null' keys must be preserved, got:\n{canonical}"
        );
    }

    /// HIGH: Test that deeply nested YAML returns an error instead of crashing.
    #[test]
    fn test_recursion_limit_exceeded() {
        // Build a deeply nested structure that exceeds MAX_DEPTH (128)
        let mut value = Value::String("deep".to_string());
        for i in 0..150 {
            let mut map = serde_yaml::Mapping::new();
            map.insert(Value::String(format!("level{i}")), value);
            value = Value::Mapping(map);
        }

        let result = canonicalize_yaml(&value);
        assert!(result.is_err(), "Should return error for deep nesting");
        assert_eq!(
            result.unwrap_err(),
            CanonicalizeError::RecursionLimitExceeded { max_depth: 128 }
        );
    }

    /// Test that structures at exactly `MAX_DEPTH` succeed
    #[test]
    fn test_recursion_at_limit_succeeds() {
        // Build a structure at exactly MAX_DEPTH (128) - should succeed
        let mut value = Value::String("leaf".to_string());
        for i in 0..128 {
            let mut map = serde_yaml::Mapping::new();
            map.insert(Value::String(format!("level{i}")), value);
            value = Value::Mapping(map);
        }

        let result = canonicalize_yaml(&value);
        assert!(
            result.is_ok(),
            "Should succeed at exactly MAX_DEPTH: {:?}",
            result.err()
        );
    }

    /// MEDIUM: Test that float keys are rejected (normalization ambiguity).
    #[test]
    fn test_float_key_rejected() {
        let mut map = serde_yaml::Mapping::new();
        map.insert(
            Value::Number(serde_yaml::Number::from(1.5)),
            Value::String("value".to_string()),
        );
        let value = Value::Mapping(map);

        let result = canonicalize_yaml(&value);
        assert!(result.is_err(), "Float keys should be rejected");
        assert_eq!(result.unwrap_err(), CanonicalizeError::UnsupportedFloatKey);
    }

    /// Test that integer keys (which could be confused with floats) work fine
    #[test]
    fn test_integer_key_works() {
        let mut map = serde_yaml::Mapping::new();
        map.insert(Value::Number(42.into()), Value::String("value".to_string()));
        let value = Value::Mapping(map);

        let result = canonicalize_yaml(&value);
        assert!(
            result.is_ok(),
            "Integer keys should work: {:?}",
            result.err()
        );
        let canonical = result.unwrap();
        assert!(canonical.contains("42:"), "Should contain integer key 42");
    }

    /// Test that keys are sorted by type first, then by value
    #[test]
    fn test_typed_key_ordering() {
        let mut map = serde_yaml::Mapping::new();
        // Add keys in random order
        map.insert(
            Value::String("z".to_string()),
            Value::String("s1".to_string()),
        );
        map.insert(Value::Bool(false), Value::String("b1".to_string()));
        map.insert(Value::Number(100.into()), Value::String("n1".to_string()));
        map.insert(Value::Null, Value::String("null1".to_string()));
        map.insert(
            Value::String("a".to_string()),
            Value::String("s2".to_string()),
        );
        map.insert(Value::Bool(true), Value::String("b2".to_string()));
        map.insert(Value::Number(1.into()), Value::String("n2".to_string()));

        let value = Value::Mapping(map);
        let canonical = canonicalize_yaml(&value).unwrap();

        // Expected order: null < bool(false) < bool(true) < int(1) < int(100) < str(a)
        // < str(z)
        let null_pos = canonical.find("null1").unwrap();
        let b1_pos = canonical.find("b1").unwrap();
        let b2_pos = canonical.find("b2").unwrap();
        let n2_pos = canonical.find("n2").unwrap();
        let n1_pos = canonical.find("n1").unwrap();
        let s2_pos = canonical.find("s2").unwrap();
        let s1_pos = canonical.find("s1").unwrap();

        assert!(null_pos < b1_pos, "null should come before bool(false)");
        assert!(b1_pos < b2_pos, "bool(false) should come before bool(true)");
        assert!(b2_pos < n2_pos, "bool(true) should come before int(1)");
        assert!(n2_pos < n1_pos, "int(1) should come before int(100)");
        assert!(n1_pos < s2_pos, "int(100) should come before str(a)");
        assert!(s2_pos < s1_pos, "str(a) should come before str(z)");
    }

    /// Test recursion limit with sequences
    #[test]
    fn test_recursion_limit_with_sequences() {
        // Build deeply nested sequences
        let mut value = Value::String("deep".to_string());
        for _ in 0..150 {
            value = Value::Sequence(vec![value]);
        }

        let result = canonicalize_yaml(&value);
        assert!(
            result.is_err(),
            "Should return error for deeply nested sequences"
        );
        assert_eq!(
            result.unwrap_err(),
            CanonicalizeError::RecursionLimitExceeded { max_depth: 128 }
        );
    }

    // =========================================================================
    // Security review fix tests (TCK-00110 - review findings)
    // =========================================================================

    /// BLOCKER/HIGH: Test that `u64::MAX` as number and its string
    /// representation are both preserved (no collision). This guards
    /// against data loss where large integers would collide with their
    /// string representations.
    #[test]
    fn test_large_uint_vs_string_no_collision() {
        // u64::MAX = 18446744073709551615
        let large_uint = u64::MAX;
        let large_uint_str = large_uint.to_string();

        let mut map = serde_yaml::Mapping::new();
        map.insert(
            Value::Number(large_uint.into()),
            Value::String("uint_value".to_string()),
        );
        map.insert(
            Value::String(large_uint_str),
            Value::String("string_value".to_string()),
        );
        let value = Value::Mapping(map);

        let canonical = canonicalize_yaml(&value).unwrap();

        // Both keys must be present - no collision/data loss
        assert!(
            canonical.contains("uint_value") && canonical.contains("string_value"),
            "Both u64::MAX as number and its string representation must be preserved. \
             Got:\n{canonical}"
        );

        // Verify the output can be reparsed and contains both entries
        let reparsed: Value = serde_yaml::from_str(&canonical).unwrap();
        if let Value::Mapping(m) = reparsed {
            assert_eq!(
                m.len(),
                2,
                "Reparsed mapping should have 2 entries (both keys preserved), got {}. \
                 This indicates a key collision occurred.",
                m.len()
            );
        } else {
            panic!("Expected mapping after reparse");
        }
    }

    /// MAJOR/MEDIUM: Test that integral floats (e.g., 1.0) are rejected as
    /// keys. This prevents ambiguity where 1.0 could be normalized to
    /// integer 1, causing a collision with an explicit integer 1 key.
    #[test]
    fn test_integral_float_key_rejected() {
        let mut map = serde_yaml::Mapping::new();
        // 1.0 is an integral float - should still be rejected
        map.insert(
            Value::Number(serde_yaml::Number::from(1.0)),
            Value::String("value".to_string()),
        );
        let value = Value::Mapping(map);

        let result = canonicalize_yaml(&value);
        assert!(
            result.is_err(),
            "Integral float key 1.0 should be rejected to prevent collision with integer 1"
        );
        assert_eq!(
            result.unwrap_err(),
            CanonicalizeError::UnsupportedFloatKey,
            "Expected UnsupportedFloatKey error for integral float 1.0"
        );
    }
}
