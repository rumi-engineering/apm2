//! Cross-language conformance vectors for canonical key identifiers.
//!
//! These vectors provide stable test data for verifying that canonical key
//! identifier implementations correctly accept valid encodings and reject
//! non-canonical / malformed inputs. They are suitable for cross-language
//! conformance testing.
//!
//! # Vector Categories
//!
//! 1. **Valid `PublicKeyIdV1` vectors**: known-good binary + text round-trips
//! 2. **Valid `KeySetIdV1` vectors**: known-good binary + text round-trips
//! 3. **Invalid text vectors**: inputs that MUST be rejected by conforming
//!    parsers
//!
//! # Contract References
//!
//! - REQ-0007: Canonical key identifier formats
//! - EVID-0007: Canonical key identifier conformance evidence
//! - EVID-0303: Rollout phase S0.75 evidence

use super::{AlgorithmTag, KeyIdError, KeySetIdV1, PublicKeyIdV1, SetTag};

/// A valid `PublicKeyIdV1` conformance vector.
///
/// Both text and binary forms MUST parse successfully and produce equal
/// identifiers. The text form re-encoded from binary MUST equal the
/// original text.
#[derive(Debug)]
pub struct ValidPublicKeyIdVector {
    /// Human-readable vector name.
    pub name: &'static str,
    /// Expected algorithm tag.
    pub algorithm: AlgorithmTag,
    /// Raw 33-byte binary form (hex-encoded for readability).
    pub binary_hex: &'static str,
    /// Canonical text form.
    pub text: &'static str,
}

/// A valid `KeySetIdV1` conformance vector.
#[derive(Debug)]
pub struct ValidKeySetIdVector {
    /// Human-readable vector name.
    pub name: &'static str,
    /// Expected set tag.
    pub set_tag: SetTag,
    /// Raw 33-byte binary form (hex-encoded for readability).
    pub binary_hex: &'static str,
    /// Canonical text form.
    pub text: &'static str,
}

/// An invalid text input vector that MUST be rejected.
#[derive(Debug)]
pub struct InvalidTextVector {
    /// Human-readable vector name.
    pub name: &'static str,
    /// The invalid input string.
    pub input: &'static str,
    /// Which type this input is tested against.
    pub target_type: TargetType,
    /// Expected error category.
    pub expected_error: ExpectedError,
}

/// Which identifier type is being tested.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetType {
    /// `PublicKeyIdV1`
    PublicKeyId,
    /// `KeySetIdV1`
    KeySetId,
}

/// Broad category of expected parse error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpectedError {
    /// Empty string.
    Empty,
    /// Leading/trailing whitespace.
    Whitespace,
    /// Interior whitespace.
    InteriorWhitespace,
    /// Input too long.
    TooLong,
    /// Contains uppercase letters.
    Uppercase,
    /// Contains padding characters.
    Padding,
    /// Wrong prefix for the target type.
    WrongPrefix,
    /// Truncated payload (too few base32 characters).
    Truncated,
    /// Invalid base32 characters.
    InvalidBase32,
    /// Unknown algorithm/set tag.
    UnknownTag,
    /// Extended payload (too many base32 characters).
    Extended,
}

// ============================================================================
// Valid PublicKeyIdV1 Vectors
// ============================================================================

/// Generate valid `PublicKeyIdV1` conformance vectors at runtime.
///
/// These vectors are computed from known key material to ensure
/// deterministic derivation across implementations.
pub fn valid_public_key_id_vectors() -> Vec<(ValidPublicKeyIdVector, PublicKeyIdV1)> {
    let vectors = [
        ("ed25519_zeros", AlgorithmTag::Ed25519, [0x00u8; 32]),
        ("ed25519_ones", AlgorithmTag::Ed25519, [0x01u8; 32]),
        ("ed25519_ff", AlgorithmTag::Ed25519, [0xFFu8; 32]),
        ("ed25519_ascending", AlgorithmTag::Ed25519, {
            let mut buf = [0u8; 32];
            let mut i: u8 = 0;
            for b in &mut buf {
                *b = i;
                i = i.wrapping_add(1);
            }
            buf
        }),
        ("ed25519_descending", AlgorithmTag::Ed25519, {
            let mut buf = [0u8; 32];
            let mut i: u8 = 31;
            for b in &mut buf {
                *b = i;
                i = i.wrapping_sub(1);
            }
            buf
        }),
    ];

    vectors
        .into_iter()
        .map(|(name, alg, key_bytes)| {
            let id = PublicKeyIdV1::from_key_bytes(alg, &key_bytes);
            let text = id.to_text();
            let binary = id.to_binary();
            let binary_hex_owned = hex::encode(binary);
            // Leak the strings so they live for 'static (test-only pattern)
            let text_leaked: &'static str = Box::leak(text.into_boxed_str());
            let hex_leaked: &'static str = Box::leak(binary_hex_owned.into_boxed_str());
            let vector = ValidPublicKeyIdVector {
                name,
                algorithm: alg,
                binary_hex: hex_leaked,
                text: text_leaked,
            };
            (vector, id)
        })
        .collect()
}

// ============================================================================
// Valid KeySetIdV1 Vectors
// ============================================================================

/// Generate valid `KeySetIdV1` conformance vectors at runtime.
pub fn valid_keyset_id_vectors() -> Vec<(ValidKeySetIdVector, KeySetIdV1)> {
    let key_a = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[0xAA; 32]);
    let key_b = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[0xBB; 32]);
    let key_c = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[0xCC; 32]);

    let vectors: Vec<(&str, SetTag, Vec<PublicKeyIdV1>)> = vec![
        (
            "multisig_two_members",
            SetTag::Multisig,
            vec![key_a.clone(), key_b.clone()],
        ),
        (
            "multisig_three_members",
            SetTag::Multisig,
            vec![key_a.clone(), key_b.clone(), key_c.clone()],
        ),
        (
            "threshold_two_members",
            SetTag::Threshold,
            vec![key_a.clone(), key_b.clone()],
        ),
        (
            "threshold_three_members",
            SetTag::Threshold,
            vec![key_a, key_b, key_c],
        ),
    ];

    vectors
        .into_iter()
        .map(|(name, tag, members)| {
            let id = KeySetIdV1::from_members(tag, &members);
            let text = id.to_text();
            let binary = id.to_binary();
            let binary_hex_owned = hex::encode(binary);
            let text_leaked: &'static str = Box::leak(text.into_boxed_str());
            let hex_leaked: &'static str = Box::leak(binary_hex_owned.into_boxed_str());
            let vector = ValidKeySetIdVector {
                name,
                set_tag: tag,
                binary_hex: hex_leaked,
                text: text_leaked,
            };
            (vector, id)
        })
        .collect()
}

// ============================================================================
// Invalid Text Vectors
// ============================================================================

/// Return invalid text vectors that conforming parsers MUST reject.
///
/// Each vector specifies the target type and the expected error category.
pub fn invalid_text_vectors() -> Vec<InvalidTextVector> {
    vec![
        // === Empty / Whitespace ===
        InvalidTextVector {
            name: "empty_string",
            input: "",
            target_type: TargetType::PublicKeyId,
            expected_error: ExpectedError::Empty,
        },
        InvalidTextVector {
            name: "only_whitespace",
            input: "   ",
            target_type: TargetType::PublicKeyId,
            expected_error: ExpectedError::Whitespace,
        },
        InvalidTextVector {
            name: "leading_space",
            input: " pk1:aeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcai",
            target_type: TargetType::PublicKeyId,
            expected_error: ExpectedError::Whitespace,
        },
        InvalidTextVector {
            name: "trailing_space",
            input: "pk1:aeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcai ",
            target_type: TargetType::PublicKeyId,
            expected_error: ExpectedError::Whitespace,
        },
        InvalidTextVector {
            name: "interior_space",
            input: "pk1:aeaqcaib aeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcai",
            target_type: TargetType::PublicKeyId,
            expected_error: ExpectedError::InteriorWhitespace,
        },
        InvalidTextVector {
            name: "interior_tab",
            input: "pk1:aeaq\tcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcai",
            target_type: TargetType::PublicKeyId,
            expected_error: ExpectedError::InteriorWhitespace,
        },
        // === Uppercase / Mixed Case ===
        InvalidTextVector {
            name: "all_uppercase_pk",
            input: "PK1:AEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAI",
            target_type: TargetType::PublicKeyId,
            expected_error: ExpectedError::Uppercase,
        },
        InvalidTextVector {
            name: "mixed_case_prefix",
            input: "Pk1:aeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcai",
            target_type: TargetType::PublicKeyId,
            expected_error: ExpectedError::Uppercase,
        },
        InvalidTextVector {
            name: "mixed_case_payload",
            input: "pk1:AeaqcaibaeaqcaibAeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcai",
            target_type: TargetType::PublicKeyId,
            expected_error: ExpectedError::Uppercase,
        },
        InvalidTextVector {
            name: "all_uppercase_ks",
            input: "KS1:AEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAI",
            target_type: TargetType::KeySetId,
            expected_error: ExpectedError::Uppercase,
        },
        // === Padding ===
        InvalidTextVector {
            name: "base32_padding",
            input: "pk1:aeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcai=",
            target_type: TargetType::PublicKeyId,
            expected_error: ExpectedError::Padding,
        },
        InvalidTextVector {
            name: "base32_double_padding",
            input: "pk1:aeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaq==",
            target_type: TargetType::PublicKeyId,
            expected_error: ExpectedError::Padding,
        },
        // === Wrong Prefix ===
        InvalidTextVector {
            name: "ks_prefix_for_pk",
            input: "ks1:aeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcai",
            target_type: TargetType::PublicKeyId,
            expected_error: ExpectedError::WrongPrefix,
        },
        InvalidTextVector {
            name: "pk_prefix_for_ks",
            input: "pk1:aeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcai",
            target_type: TargetType::KeySetId,
            expected_error: ExpectedError::WrongPrefix,
        },
        InvalidTextVector {
            name: "no_prefix",
            input: "aeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaib",
            target_type: TargetType::PublicKeyId,
            expected_error: ExpectedError::WrongPrefix,
        },
        InvalidTextVector {
            name: "unknown_prefix",
            input: "xx1:aeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcai",
            target_type: TargetType::PublicKeyId,
            expected_error: ExpectedError::WrongPrefix,
        },
        // === Truncated ===
        InvalidTextVector {
            name: "truncated_pk",
            input: "pk1:aeaq",
            target_type: TargetType::PublicKeyId,
            expected_error: ExpectedError::Truncated,
        },
        InvalidTextVector {
            name: "truncated_ks",
            input: "ks1:aeaq",
            target_type: TargetType::KeySetId,
            expected_error: ExpectedError::Truncated,
        },
        InvalidTextVector {
            name: "prefix_only_pk",
            input: "pk1:",
            target_type: TargetType::PublicKeyId,
            expected_error: ExpectedError::Truncated,
        },
        // === Invalid Base32 Characters ===
        InvalidTextVector {
            name: "digit_zero_in_base32",
            input: "pk1:0eaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcai",
            target_type: TargetType::PublicKeyId,
            expected_error: ExpectedError::InvalidBase32,
        },
        InvalidTextVector {
            name: "digit_one_in_base32",
            input: "pk1:1eaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcai",
            target_type: TargetType::PublicKeyId,
            expected_error: ExpectedError::InvalidBase32,
        },
        InvalidTextVector {
            name: "digit_eight_in_base32",
            input: "pk1:8eaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcai",
            target_type: TargetType::PublicKeyId,
            expected_error: ExpectedError::InvalidBase32,
        },
        InvalidTextVector {
            name: "digit_nine_in_base32",
            input: "pk1:9eaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcai",
            target_type: TargetType::PublicKeyId,
            expected_error: ExpectedError::InvalidBase32,
        },
        InvalidTextVector {
            name: "special_char_in_base32",
            input: "pk1:aeaq+aibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcai",
            target_type: TargetType::PublicKeyId,
            expected_error: ExpectedError::InvalidBase32,
        },
        // === Too Long ===
        InvalidTextVector {
            name: "too_long_pk",
            input: "pk1:aeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaib",
            target_type: TargetType::PublicKeyId,
            expected_error: ExpectedError::TooLong,
        },
    ]
}

// ============================================================================
// Conformance Test Runner
// ============================================================================

/// Run all conformance tests and return the results.
///
/// Each entry in the returned vector is `(vector_name, passed, detail)`.
/// A conforming implementation MUST have all entries pass.
pub fn run_conformance_tests() -> Vec<(&'static str, bool, String)> {
    let mut results = Vec::new();

    // --- Valid PublicKeyIdV1 vectors ---
    for (vector, expected_id) in valid_public_key_id_vectors() {
        // Text parse must succeed
        let text_result = PublicKeyIdV1::parse_text(vector.text);
        let text_pass = match &text_result {
            Ok(parsed) => *parsed == expected_id,
            Err(e) => {
                results.push((vector.name, false, format!("text parse failed: {e}")));
                continue;
            },
        };
        results.push((
            vector.name,
            text_pass,
            if text_pass {
                "text parse OK".to_string()
            } else {
                "text parse mismatch".to_string()
            },
        ));

        // Binary parse must succeed
        let binary_bytes = hex::decode(vector.binary_hex).expect("valid hex in vector");
        let binary_result = PublicKeyIdV1::from_binary(&binary_bytes);
        let binary_pass = match &binary_result {
            Ok(parsed) => *parsed == expected_id,
            Err(e) => {
                results.push((vector.name, false, format!("binary parse failed: {e}")));
                continue;
            },
        };
        results.push((
            vector.name,
            binary_pass,
            if binary_pass {
                "binary parse OK".to_string()
            } else {
                "binary parse mismatch".to_string()
            },
        ));

        // Text re-encoding must match
        let re_encoded = text_result.unwrap().to_text();
        let re_pass = re_encoded == vector.text;
        results.push((
            vector.name,
            re_pass,
            if re_pass {
                "text re-encode OK".to_string()
            } else {
                format!("text re-encode mismatch: got {re_encoded}")
            },
        ));

        // Algorithm tag must match
        let alg_pass = expected_id.algorithm() == vector.algorithm;
        results.push((
            vector.name,
            alg_pass,
            if alg_pass {
                "algorithm tag OK".to_string()
            } else {
                format!("algorithm tag mismatch: got {:?}", expected_id.algorithm())
            },
        ));
    }

    // --- Valid KeySetIdV1 vectors ---
    for (vector, expected_id) in valid_keyset_id_vectors() {
        let text_result = KeySetIdV1::parse_text(vector.text);
        let text_pass = match &text_result {
            Ok(parsed) => *parsed == expected_id,
            Err(e) => {
                results.push((vector.name, false, format!("text parse failed: {e}")));
                continue;
            },
        };
        results.push((
            vector.name,
            text_pass,
            if text_pass {
                "text parse OK".to_string()
            } else {
                "text parse mismatch".to_string()
            },
        ));

        let binary_bytes = hex::decode(vector.binary_hex).expect("valid hex in vector");
        let binary_result = KeySetIdV1::from_binary(&binary_bytes);
        let binary_pass = match &binary_result {
            Ok(parsed) => *parsed == expected_id,
            Err(e) => {
                results.push((vector.name, false, format!("binary parse failed: {e}")));
                continue;
            },
        };
        results.push((
            vector.name,
            binary_pass,
            if binary_pass {
                "binary parse OK".to_string()
            } else {
                "binary parse mismatch".to_string()
            },
        ));

        let re_encoded = text_result.unwrap().to_text();
        let re_pass = re_encoded == vector.text;
        results.push((
            vector.name,
            re_pass,
            if re_pass {
                "text re-encode OK".to_string()
            } else {
                format!("text re-encode mismatch: got {re_encoded}")
            },
        ));

        let tag_pass = expected_id.set_tag() == vector.set_tag;
        results.push((
            vector.name,
            tag_pass,
            if tag_pass {
                "set tag OK".to_string()
            } else {
                format!("set tag mismatch: got {:?}", expected_id.set_tag())
            },
        ));
    }

    // --- Invalid text vectors ---
    for vector in invalid_text_vectors() {
        let parse_result = match vector.target_type {
            TargetType::PublicKeyId => PublicKeyIdV1::parse_text(vector.input).map(|_| ()),
            TargetType::KeySetId => KeySetIdV1::parse_text(vector.input).map(|_| ()),
        };

        let rejected = parse_result.is_err();
        let error_matches = if let Err(ref e) = parse_result {
            match vector.expected_error {
                ExpectedError::Empty => matches!(e, KeyIdError::EmptyInput),
                ExpectedError::Whitespace => matches!(e, KeyIdError::ContainsWhitespace),
                ExpectedError::InteriorWhitespace => {
                    matches!(e, KeyIdError::ContainsInteriorWhitespace)
                },
                ExpectedError::TooLong => matches!(e, KeyIdError::TextTooLong { .. }),
                ExpectedError::Uppercase => matches!(e, KeyIdError::ContainsUppercase),
                ExpectedError::Padding => matches!(e, KeyIdError::ContainsPadding),
                ExpectedError::WrongPrefix => matches!(e, KeyIdError::WrongPrefix { .. }),
                ExpectedError::Truncated => {
                    matches!(e, KeyIdError::BinaryLengthMismatch { .. })
                        || matches!(e, KeyIdError::Base32DecodeError { .. })
                },
                ExpectedError::InvalidBase32 => {
                    matches!(e, KeyIdError::InvalidBase32Characters)
                },
                ExpectedError::UnknownTag => {
                    matches!(e, KeyIdError::UnknownAlgorithmTag { .. })
                        || matches!(e, KeyIdError::UnknownSetTag { .. })
                },
                ExpectedError::Extended => {
                    matches!(e, KeyIdError::BinaryLengthMismatch { .. })
                        || matches!(e, KeyIdError::TextTooLong { .. })
                },
            }
        } else {
            false
        };

        results.push((
            vector.name,
            rejected && error_matches,
            if !rejected {
                format!("FAIL: accepted invalid input {:?}", vector.input)
            } else if !error_matches {
                format!(
                    "FAIL: rejected with wrong error: expected {:?}, got {:?}",
                    vector.expected_error, parse_result
                )
            } else {
                format!("correctly rejected with {:?}", vector.expected_error)
            },
        ));
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Run all conformance vectors and assert every one passes.
    ///
    /// This is the primary evidence test for REQ-0007 / EVID-0007.
    #[test]
    fn all_conformance_vectors_pass() {
        let results = run_conformance_tests();
        let total = results.len();
        let failures: Vec<_> = results.iter().filter(|(_, pass, _)| !pass).collect();

        assert!(
            failures.is_empty(),
            "conformance failures ({} of {total}):\n{}",
            failures.len(),
            failures
                .iter()
                .map(|(name, _, detail)| format!("  - {name}: {detail}"))
                .collect::<Vec<_>>()
                .join("\n")
        );

        // Binding assertion: total vector count must be specific non-zero value
        // (prevents silent test-count regression)
        assert_eq!(total, 61, "expected exactly 61 conformance vector checks");
    }

    /// Verify valid `PublicKeyIdV1` vectors produce non-zero distinct
    /// identifiers.
    #[test]
    fn valid_pk_vectors_are_distinct() {
        let vectors = valid_public_key_id_vectors();
        assert_eq!(
            vectors.len(),
            5,
            "expected exactly 5 valid PublicKeyIdV1 vectors"
        );

        let mut seen = std::collections::HashSet::new();
        for (vector, id) in &vectors {
            assert!(
                seen.insert(id.to_binary()),
                "duplicate PublicKeyIdV1 in vector set: {}",
                vector.name
            );
        }
    }

    /// Verify valid `KeySetIdV1` vectors produce non-zero distinct identifiers.
    #[test]
    fn valid_ks_vectors_are_distinct() {
        let vectors = valid_keyset_id_vectors();
        assert_eq!(
            vectors.len(),
            4,
            "expected exactly 4 valid KeySetIdV1 vectors"
        );

        let mut seen = std::collections::HashSet::new();
        for (vector, id) in &vectors {
            assert!(
                seen.insert(id.to_binary()),
                "duplicate KeySetIdV1 in vector set: {}",
                vector.name
            );
        }
    }

    /// Verify all invalid text vectors are present and accounted for.
    #[test]
    fn invalid_vector_count() {
        let vectors = invalid_text_vectors();
        assert_eq!(
            vectors.len(),
            25,
            "expected exactly 25 invalid text vectors"
        );
    }

    /// Parser differential: `PublicKeyIdV1::parse_text` and `from_binary`
    /// agree on all valid vectors.
    #[test]
    fn pk_parser_differential_valid() {
        for (vector, expected) in valid_public_key_id_vectors() {
            let from_text =
                PublicKeyIdV1::parse_text(vector.text).expect("valid vector must parse");
            let binary_bytes = hex::decode(vector.binary_hex).expect("valid hex");
            let from_binary =
                PublicKeyIdV1::from_binary(&binary_bytes).expect("valid vector must parse");

            assert_eq!(
                from_text, from_binary,
                "text/binary parser differential for {}",
                vector.name
            );
            assert_eq!(
                from_text, expected,
                "parser output mismatch for {}",
                vector.name
            );
        }
    }

    /// Parser differential: `KeySetIdV1::parse_text` and `from_binary`
    /// agree on all valid vectors.
    #[test]
    fn ks_parser_differential_valid() {
        for (vector, expected) in valid_keyset_id_vectors() {
            let from_text = KeySetIdV1::parse_text(vector.text).expect("valid vector must parse");
            let binary_bytes = hex::decode(vector.binary_hex).expect("valid hex");
            let from_binary =
                KeySetIdV1::from_binary(&binary_bytes).expect("valid vector must parse");

            assert_eq!(
                from_text, from_binary,
                "text/binary parser differential for {}",
                vector.name
            );
            assert_eq!(
                from_text, expected,
                "parser output mismatch for {}",
                vector.name
            );
        }
    }

    /// Verify that each invalid vector is rejected by the correct parser.
    #[test]
    fn invalid_vectors_rejected() {
        for vector in invalid_text_vectors() {
            let result = match vector.target_type {
                TargetType::PublicKeyId => PublicKeyIdV1::parse_text(vector.input).map(|_| ()),
                TargetType::KeySetId => KeySetIdV1::parse_text(vector.input).map(|_| ()),
            };

            assert!(
                result.is_err(),
                "invalid vector {:?} was accepted (input: {:?})",
                vector.name,
                vector.input
            );
        }
    }

    /// Binary -> text -> binary round-trip for all valid `PublicKeyIdV1`
    /// vectors.
    #[test]
    fn pk_binary_text_binary_round_trip() {
        for (vector, _) in valid_public_key_id_vectors() {
            let binary_bytes = hex::decode(vector.binary_hex).expect("valid hex");
            let id = PublicKeyIdV1::from_binary(&binary_bytes).expect("valid binary");
            let text = id.to_text();
            let reparsed = PublicKeyIdV1::parse_text(&text).expect("re-parse must succeed");
            assert_eq!(
                id.to_binary(),
                reparsed.to_binary(),
                "round-trip failure for {}",
                vector.name
            );
        }
    }

    /// Binary -> text -> binary round-trip for all valid `KeySetIdV1` vectors.
    #[test]
    fn ks_binary_text_binary_round_trip() {
        for (vector, _) in valid_keyset_id_vectors() {
            let binary_bytes = hex::decode(vector.binary_hex).expect("valid hex");
            let id = KeySetIdV1::from_binary(&binary_bytes).expect("valid binary");
            let text = id.to_text();
            let reparsed = KeySetIdV1::parse_text(&text).expect("re-parse must succeed");
            assert_eq!(
                id.to_binary(),
                reparsed.to_binary(),
                "round-trip failure for {}",
                vector.name
            );
        }
    }
}
