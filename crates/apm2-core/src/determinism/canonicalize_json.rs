//! CAC-JSON canonicalization for deterministic output.
//!
//! This module provides functions to produce canonical JSON output following
//! the CAC (Context-as-Code) profile, which is based on RFC 8785 (JCS - JSON
//! Canonicalization Scheme) with additional constraints for determinism and
//! safety.
//!
//! # CAC-JSON Profile
//!
//! CAC-JSON is a strict JSON profile with the following constraints:
//!
//! - **Integer-only numbers**: Floats are rejected. Numbers must be integers
//!   within signed 64-bit range (`i64::MIN` to `i64::MAX`).
//! - **No duplicate keys**: Objects must not contain duplicate keys.
//! - **UTF-8 NFC normalized strings**: All strings must be in Unicode NFC form.
//! - **Deterministic key ordering**: Object keys are sorted lexicographically.
//! - **Maximum depth**: Structures nested deeper than 128 levels are rejected.
//!
//! # Canonicalization Rules (RFC 8785 JCS)
//!
//! 1. Object keys are sorted in lexicographic (byte-order) order
//! 2. No whitespace between tokens
//! 3. Numbers are formatted without unnecessary leading zeros or trailing zeros
//! 4. Strings use minimal escaping (only required escapes)
//!
//! # Example
//!
//! ```
//! use apm2_core::determinism::canonicalize_json;
//!
//! let input = r#"{"z": 1, "a": 2}"#;
//! let canonical = canonicalize_json(input).unwrap();
//! assert_eq!(canonical, r#"{"a":2,"z":1}"#);
//! ```
//!
//! # Integration with Canonicalize Trait
//!
//! The [`CacJson`] newtype implements the
//! [`Canonicalize`](super::super::events::Canonicalize) trait for integration
//! with the events canonicalization system.

use std::collections::BTreeSet;
use std::fmt::Write as _;

use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use thiserror::Error;
use unicode_normalization::UnicodeNormalization;

/// Canonicalizer ID for CAC-JSON profile.
pub const CANONICALIZER_ID: &str = "cac-json-v1";

/// Canonicalizer version following semver.
pub const CANONICALIZER_VERSION: &str = "1.0.0";

/// Maximum recursion depth for canonicalization to prevent stack overflow.
pub const MAX_DEPTH: usize = 128;

/// Errors that can occur during CAC-JSON canonicalization.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CacJsonError {
    /// A floating-point number was encountered.
    ///
    /// CAC-JSON requires integer-only numbers to ensure deterministic
    /// representation across platforms.
    #[error("float not allowed: CAC-JSON requires integer-only numbers")]
    FloatNotAllowed,

    /// A number is outside the signed 64-bit integer range.
    ///
    /// CAC-JSON restricts numbers to the i64 range for deterministic
    /// representation.
    #[error("number out of range: {value} is outside signed 64-bit integer range")]
    NumberOutOfRange {
        /// String representation of the out-of-range number.
        value: String,
    },

    /// A duplicate key was found in an object.
    ///
    /// JSON allows duplicate keys but CAC-JSON rejects them to ensure
    /// deterministic parsing.
    #[error("duplicate key: '{key}' appears multiple times in object")]
    DuplicateKey {
        /// The duplicated key.
        key: String,
    },

    /// A string is not in NFC normalized form.
    ///
    /// CAC-JSON requires all strings to be Unicode NFC normalized for
    /// deterministic comparison.
    #[error("non-NFC string: string at path '{path}' is not NFC normalized")]
    NonNfcString {
        /// JSON path to the non-NFC string.
        path: String,
    },

    /// The maximum nesting depth was exceeded.
    ///
    /// CAC-JSON limits nesting to 128 levels to prevent stack overflow
    /// attacks.
    #[error("max depth exceeded: JSON nested deeper than {max_depth} levels")]
    MaxDepthExceeded {
        /// The maximum depth that was exceeded.
        max_depth: usize,
    },

    /// JSON parsing failed.
    #[error("JSON parse error: {message}")]
    ParseError {
        /// Description of the parse error.
        message: String,
    },
}

/// A validated CAC-JSON value ready for canonicalization.
///
/// This newtype ensures the JSON has been validated against CAC constraints
/// before canonicalization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacJson {
    value: Value,
}

impl CacJson {
    /// Creates a new `CacJson` from a validated `serde_json::Value`.
    ///
    /// This is private because construction should go through
    /// [`validate_and_parse`].
    const fn new(value: Value) -> Self {
        Self { value }
    }

    /// Returns a reference to the inner value.
    #[must_use]
    pub const fn value(&self) -> &Value {
        &self.value
    }

    /// Consumes self and returns the inner value.
    #[must_use]
    pub fn into_value(self) -> Value {
        self.value
    }

    /// Produces canonical JSON output.
    ///
    /// The output is deterministic and follows RFC 8785 JCS format.
    #[must_use]
    pub fn to_canonical_string(&self) -> String {
        let mut output = String::new();
        emit_value(&self.value, &mut output);
        output
    }
}

/// Canonicalizes a JSON string to CAC-JSON canonical form.
///
/// This is the primary entry point for JSON canonicalization. It parses the
/// input, validates against CAC constraints, and produces deterministic output.
///
/// # Arguments
///
/// * `input` - A JSON string to canonicalize
///
/// # Returns
///
/// A canonical JSON string, or an error if validation fails.
///
/// # Errors
///
/// Returns [`CacJsonError`] if:
/// - The input is not valid JSON
/// - The JSON contains floating-point numbers
/// - The JSON contains numbers outside i64 range
/// - The JSON contains duplicate object keys
/// - The JSON contains non-NFC normalized strings
/// - The JSON is nested deeper than 128 levels
///
/// # Example
///
/// ```
/// use apm2_core::determinism::canonicalize_json;
///
/// // Keys are sorted, whitespace removed
/// let result = canonicalize_json(r#"{ "b": 1, "a": 2 }"#).unwrap();
/// assert_eq!(result, r#"{"a":2,"b":1}"#);
///
/// // Floats are rejected
/// let err = canonicalize_json(r#"{"x": 1.5}"#).unwrap_err();
/// assert!(matches!(
///     err,
///     apm2_core::determinism::CacJsonError::FloatNotAllowed
/// ));
/// ```
pub fn canonicalize_json(input: &str) -> Result<String, CacJsonError> {
    let cac_json = validate_and_parse(input)?;
    Ok(cac_json.to_canonical_string())
}

/// Parses and validates a JSON string against CAC constraints.
///
/// This function performs full validation:
/// 1. Parse JSON
/// 2. Check for duplicate keys
/// 3. Validate all numbers are integers in i64 range
/// 4. Validate all strings are NFC normalized
/// 5. Check nesting depth
///
/// # Arguments
///
/// * `input` - A JSON string to validate
///
/// # Returns
///
/// A validated [`CacJson`] value, or an error if validation fails.
///
/// # Errors
///
/// Returns [`CacJsonError`] if:
/// - The input is not valid JSON ([`CacJsonError::ParseError`])
/// - The JSON contains floating-point numbers
///   ([`CacJsonError::FloatNotAllowed`])
/// - The JSON contains numbers outside i64 range
///   ([`CacJsonError::NumberOutOfRange`])
/// - The JSON contains duplicate object keys ([`CacJsonError::DuplicateKey`])
/// - The JSON contains non-NFC normalized strings
///   ([`CacJsonError::NonNfcString`])
/// - The JSON is nested deeper than 128 levels
///   ([`CacJsonError::MaxDepthExceeded`])
pub fn validate_and_parse(input: &str) -> Result<CacJson, CacJsonError> {
    // Parse with duplicate key detection
    let value = parse_with_duplicate_detection(input)?;

    // Validate constraints recursively
    validate_value(&value, "", 0)?;

    Ok(CacJson::new(value))
}

/// Parses JSON with duplicate key detection using serde's Visitor pattern.
///
/// Standard JSON parsers silently accept duplicate keys (last value wins).
/// This function explicitly rejects duplicate keys by using a custom
/// deserializer that checks for duplicates after decoding key strings, ensuring
/// escape sequences like `"\u0061"` are properly decoded before comparison.
fn parse_with_duplicate_detection(input: &str) -> Result<Value, CacJsonError> {
    // Use custom deserializer that detects duplicates on decoded keys
    let mut deserializer = serde_json::Deserializer::from_str(input);
    let value = ValueWithDuplicateCheck::deserialize(&mut deserializer).map_err(|e| {
        // Check if this is our duplicate key error
        let msg = e.to_string();
        if msg.starts_with("duplicate key: ") {
            // Extract just the key, removing serde_json's " at line X column Y" suffix
            let key_with_location = msg.strip_prefix("duplicate key: ").unwrap_or("");
            // serde_json appends " at line X column Y", so strip it
            let key = key_with_location
                .split(" at line ")
                .next()
                .unwrap_or(key_with_location)
                .to_string();
            CacJsonError::DuplicateKey { key }
        } else {
            CacJsonError::ParseError { message: msg }
        }
    })?;

    Ok(value.0)
}

/// Wrapper type for JSON values that checks for duplicate keys during
/// deserialization.
struct ValueWithDuplicateCheck(Value);

impl<'de> Deserialize<'de> for ValueWithDuplicateCheck {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ValueVisitor;

        impl<'de> Visitor<'de> for ValueVisitor {
            type Value = Value;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("any valid JSON value")
            }

            fn visit_bool<E>(self, v: bool) -> Result<Self::Value, E> {
                Ok(Value::Bool(v))
            }

            fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E> {
                Ok(Value::Number(v.into()))
            }

            fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E> {
                Ok(Value::Number(v.into()))
            }

            fn visit_f64<E>(self, v: f64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                // Convert to Number, preserving float representation
                Number::from_f64(v)
                    .map(Value::Number)
                    .ok_or_else(|| de::Error::custom("invalid float value"))
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E> {
                Ok(Value::String(v.to_owned()))
            }

            fn visit_string<E>(self, v: String) -> Result<Self::Value, E> {
                Ok(Value::String(v))
            }

            fn visit_none<E>(self) -> Result<Self::Value, E> {
                Ok(Value::Null)
            }

            fn visit_unit<E>(self) -> Result<Self::Value, E> {
                Ok(Value::Null)
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut vec = Vec::new();
                while let Some(elem) = seq.next_element::<ValueWithDuplicateCheck>()? {
                    vec.push(elem.0);
                }
                Ok(Value::Array(vec))
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut seen_keys = BTreeSet::new();
                let mut obj = Map::new();

                while let Some(key) = map.next_key::<String>()? {
                    // Check for duplicates using the decoded key
                    if !seen_keys.insert(key.clone()) {
                        return Err(de::Error::custom(format!("duplicate key: {key}")));
                    }
                    let value = map.next_value::<ValueWithDuplicateCheck>()?;
                    obj.insert(key, value.0);
                }
                Ok(Value::Object(obj))
            }
        }

        deserializer
            .deserialize_any(ValueVisitor)
            .map(ValueWithDuplicateCheck)
    }
}

/// Recursively validates a JSON value against CAC constraints.
fn validate_value(value: &Value, path: &str, depth: usize) -> Result<(), CacJsonError> {
    // Check depth limit
    if depth > MAX_DEPTH {
        return Err(CacJsonError::MaxDepthExceeded {
            max_depth: MAX_DEPTH,
        });
    }

    match value {
        Value::Null | Value::Bool(_) => Ok(()),
        Value::Number(n) => validate_number(n),
        Value::String(s) => validate_string(s, path),
        Value::Array(arr) => {
            for (i, item) in arr.iter().enumerate() {
                let item_path = format!("{path}[{i}]");
                validate_value(item, &item_path, depth + 1)?;
            }
            Ok(())
        },
        Value::Object(obj) => {
            for (key, val) in obj {
                // Validate the key is NFC
                validate_string(key, &format!("{path}.{key}(key)"))?;
                let val_path = if path.is_empty() {
                    key.clone()
                } else {
                    format!("{path}.{key}")
                };
                validate_value(val, &val_path, depth + 1)?;
            }
            Ok(())
        },
    }
}

/// Validates that a number is an integer within i64 range.
fn validate_number(n: &Number) -> Result<(), CacJsonError> {
    // Check if it's a float
    if n.is_f64() && !n.is_i64() && !n.is_u64() {
        return Err(CacJsonError::FloatNotAllowed);
    }

    // For integers, check range
    if let Some(_i) = n.as_i64() {
        return Ok(());
    }

    if let Some(u) = n.as_u64() {
        // u64 values that don't fit in i64 are out of range
        if u > i64::MAX as u64 {
            return Err(CacJsonError::NumberOutOfRange {
                value: u.to_string(),
            });
        }
        return Ok(());
    }

    // If we get here, it's a float
    Err(CacJsonError::FloatNotAllowed)
}

/// Validates that a string is in NFC normalized form.
fn validate_string(s: &str, path: &str) -> Result<(), CacJsonError> {
    let nfc: String = s.nfc().collect();
    if nfc != s {
        return Err(CacJsonError::NonNfcString {
            path: path.to_string(),
        });
    }
    Ok(())
}

/// Emits a JSON value in canonical form (RFC 8785 JCS).
fn emit_value(value: &Value, output: &mut String) {
    match value {
        Value::Null => output.push_str("null"),
        Value::Bool(b) => output.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => emit_number(n, output),
        Value::String(s) => emit_string(s, output),
        Value::Array(arr) => emit_array(arr, output),
        Value::Object(obj) => emit_object(obj, output),
    }
}

/// Emits a number in canonical form.
///
/// For integers, this is straightforward. We've already validated that all
/// numbers are integers.
fn emit_number(n: &Number, output: &mut String) {
    // JCS requires specific number formatting
    // For integers, just emit the decimal representation
    if let Some(i) = n.as_i64() {
        let _ = write!(output, "{i}");
    } else if let Some(u) = n.as_u64() {
        let _ = write!(output, "{u}");
    } else {
        // This shouldn't happen after validation, but handle gracefully
        output.push_str(&n.to_string());
    }
}

/// Emits a string in canonical form with minimal escaping per RFC 8785 Section
/// 3.2.2.2.
///
/// Per JCS, only the following characters MUST be escaped:
/// - Quotation mark (U+0022): \"
/// - Reverse solidus (U+005C): \\
/// - Control characters U+0000 through U+001F
///
/// For control characters, we use the short escapes where defined (\b, \f, \n,
/// \r, \t) and \uXXXX for others.
fn emit_string(s: &str, output: &mut String) {
    output.push('"');
    for c in s.chars() {
        match c {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            // Control characters U+0000 through U+001F that have short escapes
            '\u{0008}' => output.push_str("\\b"),
            '\u{000C}' => output.push_str("\\f"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            // Other control characters in U+0000..=U+001F use \uXXXX
            c if ('\u{0000}'..='\u{001F}').contains(&c) => {
                let _ = write!(output, "\\u{:04x}", c as u32);
            },
            // All other characters are output as-is (including U+007F and C1 controls)
            c => output.push(c),
        }
    }
    output.push('"');
}

/// Emits an array in canonical form.
fn emit_array(arr: &[Value], output: &mut String) {
    output.push('[');
    for (i, item) in arr.iter().enumerate() {
        if i > 0 {
            output.push(',');
        }
        emit_value(item, output);
    }
    output.push(']');
}

/// Emits an object in canonical form with sorted keys.
fn emit_object(obj: &Map<String, Value>, output: &mut String) {
    // Sort keys lexicographically (byte order)
    let mut sorted_keys: Vec<&String> = obj.keys().collect();
    sorted_keys.sort();

    output.push('{');
    for (i, key) in sorted_keys.iter().enumerate() {
        if i > 0 {
            output.push(',');
        }
        emit_string(key, output);
        output.push(':');
        emit_value(&obj[*key], output);
    }
    output.push('}');
}

/// Checks if the input JSON is already in canonical form.
///
/// This is useful for idempotence checks.
#[must_use]
pub fn is_canonical(input: &str) -> bool {
    canonicalize_json(input).is_ok_and(|canonical| canonical == input)
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // Basic Canonicalization Tests
    // =========================================================================

    #[test]
    fn test_canonicalize_simple_object() {
        let input = r#"{"z": 1, "a": 2, "m": 3}"#;
        let result = canonicalize_json(input).unwrap();
        assert_eq!(result, r#"{"a":2,"m":3,"z":1}"#);
    }

    #[test]
    fn test_canonicalize_nested_object() {
        let input = r#"{"outer": {"z": 1, "a": 2}}"#;
        let result = canonicalize_json(input).unwrap();
        assert_eq!(result, r#"{"outer":{"a":2,"z":1}}"#);
    }

    #[test]
    fn test_canonicalize_array() {
        let input = r"[3, 1, 2]";
        let result = canonicalize_json(input).unwrap();
        // Arrays preserve order
        assert_eq!(result, r"[3,1,2]");
    }

    #[test]
    fn test_canonicalize_removes_whitespace() {
        let input = r#"{
            "key" :   "value" ,
            "num" : 42
        }"#;
        let result = canonicalize_json(input).unwrap();
        assert_eq!(result, r#"{"key":"value","num":42}"#);
    }

    #[test]
    fn test_canonicalize_primitives() {
        assert_eq!(canonicalize_json("null").unwrap(), "null");
        assert_eq!(canonicalize_json("true").unwrap(), "true");
        assert_eq!(canonicalize_json("false").unwrap(), "false");
        assert_eq!(canonicalize_json("42").unwrap(), "42");
        assert_eq!(canonicalize_json(r#""hello""#).unwrap(), r#""hello""#);
    }

    // =========================================================================
    // Idempotence Tests
    // =========================================================================

    #[test]
    fn test_idempotent() {
        let inputs = [
            r#"{"z": 1, "a": 2}"#,
            r#"{"nested": {"b": 2, "a": 1}, "top": "value"}"#,
            r#"[1, 2, {"y": 3, "x": 4}]"#,
        ];

        for input in &inputs {
            let canonical1 = canonicalize_json(input).unwrap();
            let canonical2 = canonicalize_json(&canonical1).unwrap();
            assert_eq!(
                canonical1, canonical2,
                "Canonicalization should be idempotent for input: {input}"
            );
        }
    }

    #[test]
    fn test_is_canonical() {
        assert!(is_canonical(r#"{"a":1,"b":2}"#));
        assert!(!is_canonical(r#"{"b":2,"a":1}"#));
        assert!(!is_canonical(r#"{ "a": 1 }"#));
    }

    // =========================================================================
    // Float Rejection Tests
    // =========================================================================

    #[test]
    fn test_reject_float() {
        let result = canonicalize_json(r#"{"x": 1.5}"#);
        assert!(matches!(result, Err(CacJsonError::FloatNotAllowed)));
    }

    #[test]
    fn test_reject_float_in_array() {
        let result = canonicalize_json(r"[1, 2.5, 3]");
        assert!(matches!(result, Err(CacJsonError::FloatNotAllowed)));
    }

    #[test]
    fn test_reject_float_scientific_notation() {
        let result = canonicalize_json(r#"{"x": 1.5e10}"#);
        assert!(matches!(result, Err(CacJsonError::FloatNotAllowed)));
    }

    #[test]
    fn test_accept_integer() {
        let result = canonicalize_json(r#"{"x": 42}"#);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), r#"{"x":42}"#);
    }

    #[test]
    fn test_accept_negative_integer() {
        let result = canonicalize_json(r#"{"x": -42}"#);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), r#"{"x":-42}"#);
    }

    #[test]
    fn test_accept_zero() {
        let result = canonicalize_json(r#"{"x": 0}"#);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), r#"{"x":0}"#);
    }

    #[test]
    fn test_accept_i64_max() {
        let max = i64::MAX;
        let input = format!(r#"{{"x": {max}}}"#);
        let result = canonicalize_json(&input);
        assert!(result.is_ok());
    }

    #[test]
    fn test_accept_i64_min() {
        let min = i64::MIN;
        let input = format!(r#"{{"x": {min}}}"#);
        let result = canonicalize_json(&input);
        assert!(result.is_ok());
    }

    #[test]
    fn test_reject_u64_above_i64_max() {
        // u64::MAX is outside i64 range
        let large = (i64::MAX as u64) + 1;
        let input = format!(r#"{{"x": {large}}}"#);
        let result = canonicalize_json(&input);
        assert!(matches!(result, Err(CacJsonError::NumberOutOfRange { .. })));
    }

    // =========================================================================
    // Duplicate Key Rejection Tests
    // =========================================================================

    #[test]
    fn test_reject_duplicate_key() {
        let input = r#"{"a": 1, "a": 2}"#;
        let result = canonicalize_json(input);
        assert!(matches!(
            result,
            Err(CacJsonError::DuplicateKey { key }) if key == "a"
        ));
    }

    #[test]
    fn test_reject_duplicate_key_nested() {
        let input = r#"{"outer": {"x": 1, "x": 2}}"#;
        let result = canonicalize_json(input);
        assert!(matches!(
            result,
            Err(CacJsonError::DuplicateKey { key }) if key == "x"
        ));
    }

    #[test]
    fn test_accept_same_key_different_objects() {
        // Same key in different objects is fine
        let input = r#"{"a": {"x": 1}, "b": {"x": 2}}"#;
        let result = canonicalize_json(input);
        assert!(result.is_ok());
    }

    #[test]
    fn test_reject_duplicate_key_with_escape_sequence() {
        // "a" and "\u0061" are the same key after decoding (U+0061 is 'a')
        // This should be rejected as a duplicate
        let input = r#"{"a": 1, "\u0061": 2}"#;
        let result = canonicalize_json(input);
        assert!(matches!(
            result,
            Err(CacJsonError::DuplicateKey { key }) if key == "a"
        ));
    }

    #[test]
    fn test_reject_duplicate_key_with_multiple_escapes() {
        // Both keys decode to "abc"
        let input = r#"{"abc": 1, "\u0061\u0062\u0063": 2}"#;
        let result = canonicalize_json(input);
        assert!(matches!(
            result,
            Err(CacJsonError::DuplicateKey { key }) if key == "abc"
        ));
    }

    // =========================================================================
    // NFC Normalization Tests
    // =========================================================================

    #[test]
    fn test_accept_nfc_string() {
        // "e\u0301" (e + combining acute) in NFC is "\u00e9" (e-acute)
        // This is already NFC
        let input = r#"{"key": "\u00e9"}"#;
        let result = canonicalize_json(input);
        assert!(result.is_ok());
    }

    #[test]
    fn test_reject_non_nfc_string_value() {
        // "e\u0301" (e + combining acute accent) is NOT NFC
        // NFC form would be "\u00e9"
        let input = r#"{"key": "e\u0301"}"#;
        let result = canonicalize_json(input);
        assert!(matches!(result, Err(CacJsonError::NonNfcString { .. })));
    }

    #[test]
    fn test_reject_non_nfc_string_key() {
        // Non-NFC in key
        let input = r#"{"e\u0301": "value"}"#;
        let result = canonicalize_json(input);
        assert!(matches!(result, Err(CacJsonError::NonNfcString { .. })));
    }

    #[test]
    fn test_accept_ascii_string() {
        // ASCII is always NFC
        let input = r#"{"key": "hello world"}"#;
        let result = canonicalize_json(input);
        assert!(result.is_ok());
    }

    // =========================================================================
    // Depth Limit Tests
    // =========================================================================

    #[test]
    fn test_reject_excessive_depth() {
        // Build JSON nested deeper than 128 levels
        let mut json = String::from("0");
        for _ in 0..150 {
            json = format!(r#"{{"nested": {json}}}"#);
        }
        let result = canonicalize_json(&json);
        // Should fail with either our depth limit or serde_json's recursion limit
        assert!(
            result.is_err(),
            "Deep nesting should be rejected, got: {result:?}"
        );
        // Accept either MaxDepthExceeded or ParseError (from serde_json recursion
        // limit)
        match &result {
            Err(CacJsonError::MaxDepthExceeded { max_depth: 128 }) => {},
            Err(CacJsonError::ParseError { message }) if message.contains("recursion") => {},
            other => panic!("Expected depth/recursion error, got: {other:?}"),
        }
    }

    #[test]
    fn test_accept_depth_at_limit() {
        // Build JSON at exactly MAX_DEPTH levels (should succeed)
        // Note: serde_json may have its own recursion limit
        let mut json = String::from("0");
        for _ in 0..MAX_DEPTH {
            json = format!(r#"{{"n": {json}}}"#);
        }
        let result = canonicalize_json(&json);
        // This may fail if serde_json's recursion limit is lower
        // In that case, we just verify we get some error
        if result.is_err() {
            // If it fails, it should be a recursion/parse error from serde_json
            // not our depth check (since we're at exactly MAX_DEPTH, not over)
            match &result {
                Err(CacJsonError::ParseError { .. }) => {
                    // serde_json hit its limit before us - that's acceptable
                },
                Err(CacJsonError::MaxDepthExceeded { .. }) => {
                    panic!("Should not fail our depth check at exactly MAX_DEPTH");
                },
                other => panic!("Unexpected error: {other:?}"),
            }
        }
    }

    #[test]
    fn test_reject_excessive_array_depth() {
        // Arrays also count toward depth
        let mut json = String::from("0");
        for _ in 0..150 {
            json = format!("[{json}]");
        }
        let result = canonicalize_json(&json);
        // Should fail with either our depth limit or serde_json's recursion limit
        assert!(
            result.is_err(),
            "Deep array nesting should be rejected, got: {result:?}"
        );
        // Accept either MaxDepthExceeded or ParseError (from serde_json recursion
        // limit)
        match &result {
            Err(CacJsonError::MaxDepthExceeded { max_depth: 128 }) => {},
            Err(CacJsonError::ParseError { message }) if message.contains("recursion") => {},
            other => panic!("Expected depth/recursion error, got: {other:?}"),
        }
    }

    // =========================================================================
    // String Escaping Tests
    // =========================================================================

    #[test]
    fn test_escape_special_chars() {
        let input = r#"{"text": "line1\nline2\ttab"}"#;
        let result = canonicalize_json(input).unwrap();
        assert_eq!(result, r#"{"text":"line1\nline2\ttab"}"#);
    }

    #[test]
    fn test_escape_quotes_and_backslash() {
        let input = r#"{"text": "say \"hello\" and use \\"}"#;
        let result = canonicalize_json(input).unwrap();
        assert_eq!(result, r#"{"text":"say \"hello\" and use \\"}"#);
    }

    #[test]
    fn test_escape_control_chars() {
        // Control character \u0000 should be escaped as \u0000
        let value = serde_json::json!({"text": "\u{0000}"});
        let cac = CacJson::new(value);
        let result = cac.to_canonical_string();
        assert!(result.contains("\\u0000"));
    }

    #[test]
    fn test_jcs_minimal_escaping_del() {
        // U+007F (DEL) should NOT be escaped per RFC 8785 Section 3.2.2.2
        // Only U+0000 through U+001F must be escaped (plus \ and ")
        let value = serde_json::json!({"text": "\u{007F}"});
        let cac = CacJson::new(value);
        let result = cac.to_canonical_string();
        // Should contain the raw byte, not an escape sequence
        assert!(
            !result.contains("\\u007f"),
            "DEL should not be escaped: {result}"
        );
        assert!(
            result.contains('\u{007F}'),
            "DEL should be raw in output: {result}"
        );
    }

    #[test]
    fn test_jcs_minimal_escaping_c1_controls() {
        // C1 control characters (U+0080 through U+009F) should NOT be escaped
        // per RFC 8785 minimal escaping rules
        let value = serde_json::json!({"text": "\u{0085}"});
        let cac = CacJson::new(value);
        let result = cac.to_canonical_string();
        // Should NOT contain escape sequence
        assert!(
            !result.contains("\\u0085"),
            "C1 controls should not be escaped: {result}"
        );
    }

    // =========================================================================
    // Parse Error Tests
    // =========================================================================

    #[test]
    fn test_reject_invalid_json() {
        let result = canonicalize_json("not json");
        assert!(matches!(result, Err(CacJsonError::ParseError { .. })));
    }

    #[test]
    fn test_reject_truncated_json() {
        let result = canonicalize_json(r#"{"key":"#);
        assert!(matches!(result, Err(CacJsonError::ParseError { .. })));
    }

    // =========================================================================
    // Constants Tests
    // =========================================================================

    #[test]
    fn test_canonicalizer_constants() {
        assert_eq!(CANONICALIZER_ID, "cac-json-v1");
        assert_eq!(CANONICALIZER_VERSION, "1.0.0");
        assert_eq!(MAX_DEPTH, 128);
    }

    // =========================================================================
    // CacJson Type Tests
    // =========================================================================

    #[test]
    fn test_cac_json_value_access() {
        let cac = validate_and_parse(r#"{"a": 1}"#).unwrap();
        assert!(cac.value().is_object());
        let value = cac.into_value();
        assert!(value.is_object());
    }

    #[test]
    fn test_cac_json_to_canonical_string() {
        let cac = validate_and_parse(r#"{"b": 2, "a": 1}"#).unwrap();
        assert_eq!(cac.to_canonical_string(), r#"{"a":1,"b":2}"#);
    }

    // =========================================================================
    // Property-based style tests
    // =========================================================================

    #[test]
    fn test_determinism_across_key_orders() {
        let inputs = [
            r#"{"c": 3, "a": 1, "b": 2}"#,
            r#"{"a": 1, "b": 2, "c": 3}"#,
            r#"{"b": 2, "c": 3, "a": 1}"#,
        ];

        let canonicals: Vec<String> = inputs
            .iter()
            .map(|i| canonicalize_json(i).unwrap())
            .collect();

        // All should be identical
        assert!(
            canonicals.windows(2).all(|w| w[0] == w[1]),
            "All key orderings should produce identical canonical output"
        );
    }

    #[test]
    fn test_determinism_with_nested_structures() {
        let input1 = r#"{"z": {"c": 3, "a": 1}, "a": [1, 2, {"y": 1, "x": 2}]}"#;
        let input2 = r#"{"a": [1, 2, {"x": 2, "y": 1}], "z": {"a": 1, "c": 3}}"#;

        let c1 = canonicalize_json(input1).unwrap();
        let c2 = canonicalize_json(input2).unwrap();

        assert_eq!(
            c1, c2,
            "Equivalent JSON should produce identical canonical form"
        );
    }

    // =========================================================================
    // Edge Cases
    // =========================================================================

    #[test]
    fn test_empty_object() {
        assert_eq!(canonicalize_json("{}").unwrap(), "{}");
    }

    #[test]
    fn test_empty_array() {
        assert_eq!(canonicalize_json("[]").unwrap(), "[]");
    }

    #[test]
    fn test_empty_string() {
        assert_eq!(canonicalize_json(r#""""#).unwrap(), r#""""#);
    }

    #[test]
    fn test_unicode_in_keys_and_values() {
        let input = r#"{"emoji": "\u2764", "chinese": "\u4e2d\u6587"}"#;
        let result = canonicalize_json(input);
        assert!(result.is_ok());
    }
}
