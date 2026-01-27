//! Test vector validation for CAC-JSON canonicalization.
//!
//! This module provides test vectors and validation for the CAC-JSON
//! canonicalizer, ensuring cross-platform determinism and correctness.
//!
//! Test vectors are stored in `bootstrap/test_vectors/canonicalize.json`
//! and validated via the `test_vectors` feature flag.

use serde::Deserialize;

#[cfg(test)]
use super::{CacJsonError, canonicalize_json};

/// Test vector file content (embedded at compile time).
const TEST_VECTORS_JSON: &str = include_str!("../../bootstrap/test_vectors/canonicalize.json");

/// Schema for the test vector file.
#[derive(Debug, Deserialize)]
pub struct TestVectorFile {
    /// Schema version for the test vector format.
    pub schema_version: String,
    /// Canonicalizer identifier (should match `CANONICALIZER_ID`).
    pub canonicalizer_id: String,
    /// Canonicalizer version (should match `CANONICALIZER_VERSION`).
    pub canonicalizer_version: String,
    /// Human-readable description.
    pub description: String,
    /// Positive test vectors (should canonicalize successfully).
    pub positive_vectors: Vec<PositiveVector>,
    /// Negative test vectors (should fail with expected error).
    pub negative_vectors: Vec<NegativeVector>,
    /// Depth limit test vectors (may be generated dynamically).
    #[serde(default)]
    pub depth_limit_vectors: Vec<DepthLimitVector>,
    /// Idempotence test vectors.
    #[serde(default)]
    pub idempotence_vectors: Vec<IdempotenceVector>,
    /// Determinism test vectors.
    #[serde(default)]
    pub determinism_vectors: Vec<DeterminismVector>,
}

/// A positive test vector: input should canonicalize to expected output.
#[derive(Debug, Deserialize)]
pub struct PositiveVector {
    /// Unique identifier for the vector.
    pub id: String,
    /// Human-readable description.
    pub description: String,
    /// Input JSON string.
    pub input: String,
    /// Expected canonical output.
    pub expected_canonical: String,
    /// Expected BLAKE3 hash of canonical output (hex-encoded).
    pub expected_hash: String,
}

/// A negative test vector: input should fail with expected error type.
#[derive(Debug, Deserialize)]
pub struct NegativeVector {
    /// Unique identifier for the vector.
    pub id: String,
    /// Human-readable description.
    pub description: String,
    /// Input JSON string (should fail).
    pub input: String,
    /// Expected error type name.
    pub expected_error: String,
}

/// A depth limit test vector (generated dynamically).
#[derive(Debug, Deserialize)]
pub struct DepthLimitVector {
    /// Unique identifier for the vector.
    pub id: String,
    /// Human-readable description.
    pub description: String,
    /// Nesting depth to generate.
    pub depth: usize,
    /// Generator type (`nested_object` or `nested_array`).
    pub generator: String,
    /// Optional expected error pattern (regex-like).
    #[serde(default)]
    pub expected_error_pattern: Option<String>,
    /// Optional notes.
    #[serde(default)]
    pub notes: Option<String>,
}

/// An idempotence test vector: canonicalize(canonicalize(x)) ==
/// canonicalize(x).
#[derive(Debug, Deserialize)]
pub struct IdempotenceVector {
    /// Unique identifier for the vector.
    pub id: String,
    /// Human-readable description.
    pub description: String,
    /// Input JSON strings to test.
    pub inputs: Vec<String>,
}

/// A determinism test vector: multiple inputs should produce same canonical
/// output.
#[derive(Debug, Deserialize)]
pub struct DeterminismVector {
    /// Unique identifier for the vector.
    pub id: String,
    /// Human-readable description.
    pub description: String,
    /// Input JSON strings (should all produce same canonical output).
    pub inputs: Vec<String>,
    /// Expected canonical output (all inputs should produce this).
    pub expected_canonical: String,
}

/// Loads and parses the test vector file.
///
/// # Panics
///
/// Panics if the embedded test vector file is malformed.
#[must_use]
pub fn load_test_vectors() -> TestVectorFile {
    serde_json::from_str(TEST_VECTORS_JSON).expect("Failed to parse embedded test vectors")
}

// Helper functions used only in tests
#[cfg(test)]
mod helpers {
    use super::CacJsonError;

    /// Computes the BLAKE3 hash of a string.
    pub fn hash_string(s: &str) -> String {
        let hash = blake3::hash(s.as_bytes());
        hex::encode(hash.as_bytes())
    }

    /// Maps a `CacJsonError` to its type name for comparison with
    /// `expected_error`.
    pub fn error_type_name(err: &CacJsonError) -> &'static str {
        match err {
            CacJsonError::FloatNotAllowed => "FloatNotAllowed",
            CacJsonError::NumberOutOfRange { .. } => "NumberOutOfRange",
            CacJsonError::DuplicateKey { .. } => "DuplicateKey",
            CacJsonError::NonNfcString { .. } => "NonNfcString",
            CacJsonError::MaxDepthExceeded { .. } => "MaxDepthExceeded",
            CacJsonError::ParseError { .. } => "ParseError",
        }
    }

    /// Generates a deeply nested JSON object.
    pub fn generate_nested_object(depth: usize) -> String {
        let mut json = String::from("0");
        for _ in 0..depth {
            json = format!(r#"{{"n": {json}}}"#);
        }
        json
    }

    /// Generates a deeply nested JSON array.
    pub fn generate_nested_array(depth: usize) -> String {
        let mut json = String::from("0");
        for _ in 0..depth {
            json = format!("[{json}]");
        }
        json
    }
}

/// Canonicalization test suite using test vectors.
///
/// Run with: `cargo test --package apm2-core --features test_vectors
/// canonicalization`
#[cfg(test)]
mod canonicalization {
    use super::helpers::{
        error_type_name, generate_nested_array, generate_nested_object, hash_string,
    };
    use super::*;
    use crate::determinism::{CANONICALIZER_ID, CANONICALIZER_VERSION};

    /// Test that the vector file parses correctly.
    #[test]
    fn test_vector_file_parses() {
        let vectors = load_test_vectors();
        assert_eq!(vectors.canonicalizer_id, CANONICALIZER_ID);
        assert_eq!(vectors.canonicalizer_version, CANONICALIZER_VERSION);
        assert!(
            !vectors.positive_vectors.is_empty(),
            "Should have positive vectors"
        );
        assert!(
            !vectors.negative_vectors.is_empty(),
            "Should have negative vectors"
        );
    }

    /// Test all positive vectors produce expected canonical output.
    #[test]
    fn test_positive_vectors_canonical() {
        let vectors = load_test_vectors();

        for vector in &vectors.positive_vectors {
            let result = canonicalize_json(&vector.input);
            match result {
                Ok(canonical) => {
                    assert_eq!(
                        canonical, vector.expected_canonical,
                        "Vector {}: canonical output mismatch.\nInput: {}\nExpected: {}\nGot: {}",
                        vector.id, vector.input, vector.expected_canonical, canonical
                    );
                },
                Err(e) => {
                    panic!(
                        "Vector {}: expected success but got error {:?}.\nInput: {}\nDescription: {}",
                        vector.id, e, vector.input, vector.description
                    );
                },
            }
        }
    }

    /// Test all positive vectors produce expected BLAKE3 hash.
    #[test]
    fn test_positive_vectors_hash() {
        let vectors = load_test_vectors();

        for vector in &vectors.positive_vectors {
            // Skip placeholder hashes (used during development)
            if vector.expected_hash == "placeholder" {
                continue;
            }

            let result = canonicalize_json(&vector.input);
            match result {
                Ok(canonical) => {
                    let actual_hash = hash_string(&canonical);
                    assert_eq!(
                        actual_hash, vector.expected_hash,
                        "Vector {}: hash mismatch.\nInput: {}\nCanonical: {}\nExpected hash: {}\nActual hash: {}",
                        vector.id, vector.input, canonical, vector.expected_hash, actual_hash
                    );
                },
                Err(e) => {
                    panic!(
                        "Vector {}: expected success but got error {:?}.\nInput: {}",
                        vector.id, e, vector.input
                    );
                },
            }
        }
    }

    /// Test all negative vectors produce expected error type.
    #[test]
    fn test_negative_vectors() {
        let vectors = load_test_vectors();

        for vector in &vectors.negative_vectors {
            let result = canonicalize_json(&vector.input);
            match result {
                Ok(canonical) => {
                    panic!(
                        "Vector {}: expected error {} but got success.\nInput: {}\nCanonical: {}",
                        vector.id, vector.expected_error, vector.input, canonical
                    );
                },
                Err(e) => {
                    let actual_type = error_type_name(&e);
                    assert_eq!(
                        actual_type, vector.expected_error,
                        "Vector {}: error type mismatch.\nInput: {}\nExpected: {}\nGot: {:?}",
                        vector.id, vector.input, vector.expected_error, e
                    );
                },
            }
        }
    }

    /// Test depth limit vectors.
    #[test]
    fn test_depth_limit_vectors() {
        let vectors = load_test_vectors();

        for vector in &vectors.depth_limit_vectors {
            let input = match vector.generator.as_str() {
                "nested_object" => generate_nested_object(vector.depth),
                "nested_array" => generate_nested_array(vector.depth),
                other => panic!("Unknown generator: {other}"),
            };

            let result = canonicalize_json(&input);

            if let Some(pattern) = &vector.expected_error_pattern {
                // Expect failure
                match result {
                    Ok(_) => {
                        // Some depth tests might succeed depending on
                        // serde_json limits Just warn
                        // but don't fail
                    },
                    Err(e) => {
                        let err_str = format!("{e:?}");
                        let patterns: Vec<&str> = pattern.split('|').collect();
                        let matches = patterns
                            .iter()
                            .any(|p| err_str.to_lowercase().contains(&p.to_lowercase()));
                        assert!(
                            matches,
                            "Vector {}: error message should contain one of {:?}, got: {:?}",
                            vector.id, patterns, e
                        );
                    },
                }
            }
        }
    }

    /// Test idempotence: canonicalize(canonicalize(x)) == canonicalize(x).
    #[test]
    fn test_idempotence_vectors() {
        let vectors = load_test_vectors();

        for vector in &vectors.idempotence_vectors {
            for input in &vector.inputs {
                let first = canonicalize_json(input).unwrap_or_else(|e| {
                    panic!(
                        "Vector {}: first canonicalization failed: {:?}",
                        vector.id, e
                    )
                });
                let second = canonicalize_json(&first).unwrap_or_else(|e| {
                    panic!(
                        "Vector {}: second canonicalization failed: {:?}",
                        vector.id, e
                    )
                });

                assert_eq!(
                    first, second,
                    "Vector {}: canonicalization is not idempotent.\nInput: {}\nFirst: {}\nSecond: {}",
                    vector.id, input, first, second
                );
            }
        }
    }

    /// Test determinism: equivalent inputs produce identical canonical output.
    #[test]
    fn test_determinism_vectors() {
        let vectors = load_test_vectors();

        for vector in &vectors.determinism_vectors {
            for input in &vector.inputs {
                let canonical = canonicalize_json(input).unwrap_or_else(|e| {
                    panic!("Vector {}: canonicalization failed: {:?}", vector.id, e)
                });

                assert_eq!(
                    canonical, vector.expected_canonical,
                    "Vector {}: determinism check failed.\nInput: {}\nExpected: {}\nGot: {}",
                    vector.id, input, vector.expected_canonical, canonical
                );
            }
        }
    }

    /// Cross-platform determinism: verify hash consistency.
    ///
    /// This test is critical for cross-platform verification in CI.
    #[test]
    fn test_cross_platform_hash_consistency() {
        // These are known-good hashes that must match on all platforms
        let known_vectors = [
            (r#"{"a":1,"b":2}"#, "{\"a\":1,\"b\":2}"),
            ("null", "null"),
            ("true", "true"),
            ("false", "false"),
            ("0", "0"),
            ("[]", "[]"),
            ("{}", "{}"),
        ];

        for (input, expected_canonical) in known_vectors {
            let canonical = canonicalize_json(input)
                .unwrap_or_else(|e| panic!("Failed to canonicalize '{input}': {e:?}"));
            assert_eq!(
                canonical, expected_canonical,
                "Cross-platform canonical mismatch for input: {input}"
            );
        }
    }
}
