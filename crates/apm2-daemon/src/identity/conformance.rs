//! Cross-language conformance vectors for canonical identity identifiers.
//!
//! These vectors provide stable test data for verifying that canonical key
//! identifier implementations correctly accept valid encodings and reject
//! non-canonical / malformed inputs. They are suitable for cross-language
//! conformance testing.
//!
//! # Design: Frozen Static Fixtures
//!
//! Valid vectors use **precomputed, frozen** hex/text values derived once
//! from known key material and then checked in as static string constants.
//! This ensures that conformance tests detect regressions in derivation
//! logic rather than tautologically re-deriving expected values at runtime.
//!
//! Parser-differential tests (which *do* derive at runtime and compare
//! text vs binary parsers) are kept separate in the `#[cfg(test)]` section.
//!
//! # Vector Categories
//!
//! 1. **Valid `PublicKeyIdV1` vectors**: known-good binary + text round-trips
//! 2. **Valid `KeySetIdV1` vectors**: known-good binary + text round-trips
//! 3. **Valid `CellIdV1` vectors**: known-good binary + text round-trips
//! 4. **Valid `HolonIdV1` vectors**: known-good binary + text round-trips
//! 5. **Invalid text vectors**: inputs that MUST be rejected by conforming
//!    parsers
//!
//! # Text Form Grammar (RFC-0020 section 1.7.5b)
//!
//! ```text
//! public_key_id ::= "pkid:v1:ed25519:blake3:" hash64
//! keyset_id     ::= "kset:v1:blake3:" hash64
//! cell_id       ::= "cell:v1:blake3:" hash64
//! holon_id      ::= "holon:v1:blake3:" hash64
//! hash64        ::= 64 * HEXLOWER
//! ```
//!
//! # Contract References
//!
//! - REQ-0007: Canonical key identifier formats
//! - EVID-0007: Canonical key identifier conformance evidence
//! - EVID-0303: Rollout phase S0.75 evidence

use super::{AlgorithmTag, CellIdV1, HolonIdV1, KeyIdError, KeySetIdV1, PublicKeyIdV1, SetTag};

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
    /// Canonical text form (`pkid:v1:ed25519:blake3:<64-hex>`).
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
    /// Canonical text form (`kset:v1:blake3:<64-hex>`).
    pub text: &'static str,
}

/// A valid `CellIdV1` conformance vector.
#[derive(Debug)]
pub struct ValidCellIdVector {
    /// Human-readable vector name.
    pub name: &'static str,
    /// Raw 33-byte binary form (hex-encoded for readability).
    pub binary_hex: &'static str,
    /// Canonical text form (`cell:v1:blake3:<64-hex>`).
    pub text: &'static str,
}

/// A valid `HolonIdV1` conformance vector.
#[derive(Debug)]
pub struct ValidHolonIdVector {
    /// Human-readable vector name.
    pub name: &'static str,
    /// Raw 33-byte binary form (hex-encoded for readability).
    pub binary_hex: &'static str,
    /// Canonical text form (`holon:v1:blake3:<64-hex>`).
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
    /// `CellIdV1`
    CellId,
    /// `HolonIdV1`
    HolonId,
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
    /// Truncated payload (too few hex characters).
    Truncated,
    /// Invalid hex characters.
    InvalidHex,
    /// Unknown algorithm/set tag.
    UnknownTag,
    /// Extended payload (too many hex characters).
    Extended,
    /// Percent-encoded characters.
    PercentEncoded,
    /// Non-ASCII / Unicode normalization variant.
    NonAscii,
}

// ============================================================================
// Valid PublicKeyIdV1 Vectors (frozen static fixtures)
// ============================================================================

/// Frozen valid `PublicKeyIdV1` conformance vectors.
///
/// These values were derived once from known key material:
///   - `ed25519_zeros`:      Ed25519, `key_bytes` = `[0x00; 32]`
///   - `ed25519_ones`:       Ed25519, `key_bytes` = `[0x01; 32]`
///   - `ed25519_ff`:         Ed25519, `key_bytes` = `[0xFF; 32]`
///   - `ed25519_ascending`:  Ed25519, `key_bytes` = `[0, 1, 2, ..., 31]`
///   - `ed25519_descending`: Ed25519, `key_bytes` = `[31, 30, ..., 0]`
///
/// Text form: `pkid:v1:ed25519:blake3:<64-lowercase-hex>`
///
/// They are now checked in as static constants. Any change to the
/// derivation algorithm will cause these tests to fail, which is the
/// intended regression-detection behavior.
pub fn valid_public_key_id_vectors() -> Vec<ValidPublicKeyIdVector> {
    vec![
        ValidPublicKeyIdVector {
            name: "ed25519_zeros",
            algorithm: AlgorithmTag::Ed25519,
            binary_hex: "01e75e981fde14df8a9ced962f1ac75bd10acc7d561eac03feebbe9206137bff4d",
            text: "pkid:v1:ed25519:blake3:e75e981fde14df8a9ced962f1ac75bd10acc7d561eac03feebbe9206137bff4d",
        },
        ValidPublicKeyIdVector {
            name: "ed25519_ones",
            algorithm: AlgorithmTag::Ed25519,
            binary_hex: "01cbdd01abdad3a310a236bdd30c66844bdbb5d6900e31f3c755e22a8a56b00b04",
            text: "pkid:v1:ed25519:blake3:cbdd01abdad3a310a236bdd30c66844bdbb5d6900e31f3c755e22a8a56b00b04",
        },
        ValidPublicKeyIdVector {
            name: "ed25519_ff",
            algorithm: AlgorithmTag::Ed25519,
            binary_hex: "01914b4ecc450789be90462cec21b1012da35085b5a08efebc136632dc7bf6719c",
            text: "pkid:v1:ed25519:blake3:914b4ecc450789be90462cec21b1012da35085b5a08efebc136632dc7bf6719c",
        },
        ValidPublicKeyIdVector {
            name: "ed25519_ascending",
            algorithm: AlgorithmTag::Ed25519,
            binary_hex: "013a3b4abb8571e625ff5ac950526527eba0b6f1d8110e97fd70a7c7d08fb2cc3a",
            text: "pkid:v1:ed25519:blake3:3a3b4abb8571e625ff5ac950526527eba0b6f1d8110e97fd70a7c7d08fb2cc3a",
        },
        ValidPublicKeyIdVector {
            name: "ed25519_descending",
            algorithm: AlgorithmTag::Ed25519,
            binary_hex: "01a02d40fc8cb608ad2a6d798607543625c3a041cc61e30e2be5ab0675387aadbc",
            text: "pkid:v1:ed25519:blake3:a02d40fc8cb608ad2a6d798607543625c3a041cc61e30e2be5ab0675387aadbc",
        },
    ]
}

// ============================================================================
// Valid KeySetIdV1 Vectors (frozen static fixtures)
// ============================================================================

/// Frozen valid `KeySetIdV1` conformance vectors.
///
/// These values were derived once from known member key material using the
/// full descriptor format per RFC-0020:
///   - `key_a` = Ed25519 from `[0xAA; 32]`
///   - `key_b` = Ed25519 from `[0xBB; 32]`
///   - `key_c` = Ed25519 from `[0xCC; 32]`
///
/// The descriptor includes `key_algorithm`, `mode`, `threshold_k`, sorted
/// members, and optional weights. Different descriptor fields produce
/// distinct identifiers even for the same member set.
///
/// Text form: `kset:v1:blake3:<64-lowercase-hex>`
pub fn valid_keyset_id_vectors() -> Vec<ValidKeySetIdVector> {
    vec![
        ValidKeySetIdVector {
            name: "multisig_two_members",
            set_tag: SetTag::Multisig,
            binary_hex: "01c9f5e8de481c1e63066d0a4531af41be075bbba759b1f7e741ef4a64f0a95ec8",
            text: "kset:v1:blake3:c9f5e8de481c1e63066d0a4531af41be075bbba759b1f7e741ef4a64f0a95ec8",
        },
        ValidKeySetIdVector {
            name: "multisig_three_members",
            set_tag: SetTag::Multisig,
            binary_hex: "01715dfa2421c3140985c33abd94f77c9f367ebffb711317b3b3c58391bd7f5bf9",
            text: "kset:v1:blake3:715dfa2421c3140985c33abd94f77c9f367ebffb711317b3b3c58391bd7f5bf9",
        },
        ValidKeySetIdVector {
            name: "threshold_two_members",
            set_tag: SetTag::Threshold,
            binary_hex: "022afc4549f84212a64bfb0264281a800880222a7d9db3415289f4b6bbfb83c067",
            text: "kset:v1:blake3:2afc4549f84212a64bfb0264281a800880222a7d9db3415289f4b6bbfb83c067",
        },
        ValidKeySetIdVector {
            name: "threshold_three_members",
            set_tag: SetTag::Threshold,
            binary_hex: "02ab69d122b0b8165d758073d4f37165db6d82165f7411c17028aaeaa97a79a3c0",
            text: "kset:v1:blake3:ab69d122b0b8165d758073d4f37165db6d82165f7411c17028aaeaa97a79a3c0",
        },
    ]
}

// ============================================================================
// Valid CellIdV1 Vectors (frozen static fixtures)
// ============================================================================

/// Frozen valid `CellIdV1` conformance vectors.
///
/// Values are derived from known `(ledger_genesis_hash, policy_root_id)`
/// commitments as specified in HSI 1.7.3.
pub fn valid_cell_id_vectors() -> Vec<ValidCellIdVector> {
    vec![
        ValidCellIdVector {
            name: "cell_single_policy_11aa",
            binary_hex: "01db758443ad405611a5ad982f7c04211b248707a048f6642cf76e6ce4aa1cf54d",
            text: "cell:v1:blake3:db758443ad405611a5ad982f7c04211b248707a048f6642cf76e6ce4aa1cf54d",
        },
        ValidCellIdVector {
            name: "cell_single_policy_22bb",
            binary_hex: "013de80e9fcf47e09ddebbfa8a831ec4b62b5a540a6af05e5457ea3d147bb0c3a8",
            text: "cell:v1:blake3:3de80e9fcf47e09ddebbfa8a831ec4b62b5a540a6af05e5457ea3d147bb0c3a8",
        },
        ValidCellIdVector {
            name: "cell_quorum_threshold",
            binary_hex: "014bfce8b5d0f7010a087a5119818d795352bf8dd651812b35f008d5ad90195efa",
            text: "cell:v1:blake3:4bfce8b5d0f7010a087a5119818d795352bf8dd651812b35f008d5ad90195efa",
        },
        ValidCellIdVector {
            name: "cell_single_policy_ff00",
            binary_hex: "01d45d3bf6b8f3a5c860cbfc98f9420e7ac18d59e5bc5d0ac349a41f468f136f72",
            text: "cell:v1:blake3:d45d3bf6b8f3a5c860cbfc98f9420e7ac18d59e5bc5d0ac349a41f468f136f72",
        },
    ]
}

// ============================================================================
// Valid HolonIdV1 Vectors (frozen static fixtures)
// ============================================================================

/// Frozen valid `HolonIdV1` conformance vectors.
///
/// Values are derived from known `(cell_id, holon_genesis_public_key_id)`
/// commitments as specified in HSI 1.7.4.
pub fn valid_holon_id_vectors() -> Vec<ValidHolonIdVector> {
    vec![
        ValidHolonIdVector {
            name: "holon_cell1_keyaa",
            binary_hex: "011fd7fda75b1481c99d39aecb01880bb85ce029aaef603d4fc8392e0859b8933c",
            text: "holon:v1:blake3:1fd7fda75b1481c99d39aecb01880bb85ce029aaef603d4fc8392e0859b8933c",
        },
        ValidHolonIdVector {
            name: "holon_cell1_keybb",
            binary_hex: "017669a3e04f011b4c3b4325d80325fd0706cd36e235b3136eb239afa9a0ecee0a",
            text: "holon:v1:blake3:7669a3e04f011b4c3b4325d80325fd0706cd36e235b3136eb239afa9a0ecee0a",
        },
        ValidHolonIdVector {
            name: "holon_cell2_keyaa",
            binary_hex: "01a8311ce1ac405a7a30bd94f7d45ee217e26acf8563fcc9b3f6bc32086119c1ed",
            text: "holon:v1:blake3:a8311ce1ac405a7a30bd94f7d45ee217e26acf8563fcc9b3f6bc32086119c1ed",
        },
        ValidHolonIdVector {
            name: "holon_cell3_keycc",
            binary_hex: "0198a30b3215f1f52211dfa95b71344d011b200010218dc95c6aff57582b4ba773",
            text: "holon:v1:blake3:98a30b3215f1f52211dfa95b71344d011b200010218dc95c6aff57582b4ba773",
        },
    ]
}

// ============================================================================
// Invalid Text Vectors
// ============================================================================

/// Return invalid text vectors that conforming parsers MUST reject.
///
/// Each vector specifies the target type and the expected error category.
/// Includes vectors for percent-encoding and Unicode normalization rejection
/// per REQ-0007.
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
            name: "leading_space_pk",
            input: " pkid:v1:ed25519:blake3:0000000000000000000000000000000000000000000000000000000000000000",
            target_type: TargetType::PublicKeyId,
            expected_error: ExpectedError::Whitespace,
        },
        InvalidTextVector {
            name: "trailing_space_pk",
            input: "pkid:v1:ed25519:blake3:0000000000000000000000000000000000000000000000000000000000000000 ",
            target_type: TargetType::PublicKeyId,
            expected_error: ExpectedError::Whitespace,
        },
        InvalidTextVector {
            name: "interior_space_pk",
            input: "pkid:v1:ed25519: blake3:0000000000000000000000000000000000000000000000000000000000000000",
            target_type: TargetType::PublicKeyId,
            expected_error: ExpectedError::InteriorWhitespace,
        },
        InvalidTextVector {
            name: "interior_tab_pk",
            input: "pkid:v1:\ted25519:blake3:0000000000000000000000000000000000000000000000000000000000000000",
            target_type: TargetType::PublicKeyId,
            expected_error: ExpectedError::InteriorWhitespace,
        },
        // === Uppercase / Mixed Case ===
        InvalidTextVector {
            name: "all_uppercase_pk",
            input: "PKID:V1:ED25519:BLAKE3:0000000000000000000000000000000000000000000000000000000000000000",
            target_type: TargetType::PublicKeyId,
            expected_error: ExpectedError::Uppercase,
        },
        InvalidTextVector {
            name: "mixed_case_prefix_pk",
            input: "Pkid:v1:ed25519:blake3:0000000000000000000000000000000000000000000000000000000000000000",
            target_type: TargetType::PublicKeyId,
            expected_error: ExpectedError::Uppercase,
        },
        InvalidTextVector {
            name: "mixed_case_payload_pk",
            input: "pkid:v1:ed25519:blake3:000000000000000000000000000000000000000000000000000000000000000A",
            target_type: TargetType::PublicKeyId,
            expected_error: ExpectedError::Uppercase,
        },
        InvalidTextVector {
            name: "all_uppercase_ks",
            input: "KSET:V1:BLAKE3:0000000000000000000000000000000000000000000000000000000000000000",
            target_type: TargetType::KeySetId,
            expected_error: ExpectedError::Uppercase,
        },
        // === Padding ===
        InvalidTextVector {
            name: "padding_char_pk",
            input: "pkid:v1:ed25519:blake3:0000000000000000000000000000000000000000000000000000000000000000=",
            target_type: TargetType::PublicKeyId,
            expected_error: ExpectedError::Padding,
        },
        // === Wrong Prefix ===
        InvalidTextVector {
            name: "ks_prefix_for_pk",
            input: "kset:v1:blake3:0000000000000000000000000000000000000000000000000000000000000000",
            target_type: TargetType::PublicKeyId,
            expected_error: ExpectedError::WrongPrefix,
        },
        InvalidTextVector {
            name: "pk_prefix_for_ks",
            input: "pkid:v1:ed25519:blake3:0000000000000000000000000000000000000000000000000000000000000000",
            target_type: TargetType::KeySetId,
            expected_error: ExpectedError::WrongPrefix,
        },
        InvalidTextVector {
            name: "no_prefix_pk",
            input: "0000000000000000000000000000000000000000000000000000000000000000",
            target_type: TargetType::PublicKeyId,
            expected_error: ExpectedError::WrongPrefix,
        },
        InvalidTextVector {
            name: "unknown_prefix_pk",
            input: "xxid:v1:ed25519:blake3:0000000000000000000000000000000000000000000000000000000000000000",
            target_type: TargetType::PublicKeyId,
            expected_error: ExpectedError::WrongPrefix,
        },
        InvalidTextVector {
            name: "old_pk1_prefix",
            input: "pk1:aeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcai",
            target_type: TargetType::PublicKeyId,
            expected_error: ExpectedError::WrongPrefix,
        },
        InvalidTextVector {
            name: "old_ks1_prefix",
            input: "ks1:aeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcai",
            target_type: TargetType::KeySetId,
            expected_error: ExpectedError::WrongPrefix,
        },
        // === Truncated ===
        InvalidTextVector {
            name: "truncated_pk",
            input: "pkid:v1:ed25519:blake3:abcd",
            target_type: TargetType::PublicKeyId,
            expected_error: ExpectedError::Truncated,
        },
        InvalidTextVector {
            name: "truncated_ks",
            input: "kset:v1:blake3:abcd",
            target_type: TargetType::KeySetId,
            expected_error: ExpectedError::Truncated,
        },
        InvalidTextVector {
            name: "prefix_only_pk",
            input: "pkid:v1:ed25519:blake3:",
            target_type: TargetType::PublicKeyId,
            expected_error: ExpectedError::Truncated,
        },
        // === Invalid Hex Characters ===
        InvalidTextVector {
            name: "letter_g_in_hex_pk",
            input: "pkid:v1:ed25519:blake3:g000000000000000000000000000000000000000000000000000000000000000",
            target_type: TargetType::PublicKeyId,
            expected_error: ExpectedError::InvalidHex,
        },
        InvalidTextVector {
            name: "letter_z_in_hex_pk",
            input: "pkid:v1:ed25519:blake3:z000000000000000000000000000000000000000000000000000000000000000",
            target_type: TargetType::PublicKeyId,
            expected_error: ExpectedError::InvalidHex,
        },
        InvalidTextVector {
            name: "special_char_in_hex_pk",
            input: "pkid:v1:ed25519:blake3:+000000000000000000000000000000000000000000000000000000000000000",
            target_type: TargetType::PublicKeyId,
            expected_error: ExpectedError::InvalidHex,
        },
        // === Too Long ===
        InvalidTextVector {
            name: "too_long_pk",
            input: "pkid:v1:ed25519:blake3:00000000000000000000000000000000000000000000000000000000000000000000000000000000",
            target_type: TargetType::PublicKeyId,
            expected_error: ExpectedError::TooLong,
        },
        // === Percent-Encoding Rejection (REQ-0007) ===
        InvalidTextVector {
            name: "percent_encoded_pk_colons",
            input: "pkid%3av1%3aed25519%3ablake3%3a0000000000000000000000000000000000000000000000000000000000000000",
            target_type: TargetType::PublicKeyId,
            expected_error: ExpectedError::PercentEncoded,
        },
        InvalidTextVector {
            name: "percent_encoded_ks_colons",
            input: "kset%3av1%3ablake3%3a0000000000000000000000000000000000000000000000000000000000000000",
            target_type: TargetType::KeySetId,
            expected_error: ExpectedError::PercentEncoded,
        },
        InvalidTextVector {
            name: "percent_encoded_partial_pk",
            input: "pkid:v1:ed25519:blake3:%300000000000000000000000000000000000000000000000000000000000000000",
            target_type: TargetType::PublicKeyId,
            expected_error: ExpectedError::PercentEncoded,
        },
        // === Unicode Normalization Rejection (REQ-0007) ===
        InvalidTextVector {
            name: "fullwidth_colon_pk",
            input: "pkid\u{FF1A}v1:ed25519:blake3:0000000000000000000000000000000000000000000000000000000000000000",
            target_type: TargetType::PublicKeyId,
            expected_error: ExpectedError::NonAscii,
        },
        InvalidTextVector {
            name: "fullwidth_colon_ks",
            input: "kset\u{FF1A}v1:blake3:0000000000000000000000000000000000000000000000000000000000000000",
            target_type: TargetType::KeySetId,
            expected_error: ExpectedError::NonAscii,
        },
        InvalidTextVector {
            name: "nfc_combining_accent_pk",
            input: "pkid:v1:e\u{0301}d25519:blake3:0000000000000000000000000000000000000000000000000000000000000000",
            target_type: TargetType::PublicKeyId,
            expected_error: ExpectedError::NonAscii,
        },
        InvalidTextVector {
            name: "nfkc_fullwidth_k_ks",
            input: "\u{FF4B}set:v1:blake3:0000000000000000000000000000000000000000000000000000000000000000",
            target_type: TargetType::KeySetId,
            expected_error: ExpectedError::NonAscii,
        },
        InvalidTextVector {
            name: "nfd_combining_diaeresis_pk",
            input: "pkid:v1:ed25519:blake3:00000000000000000000000000000000000000000000000000000000000000\u{0308}0",
            target_type: TargetType::PublicKeyId,
            expected_error: ExpectedError::NonAscii,
        },
        // === CellIdV1 invalid text vectors ===
        InvalidTextVector {
            name: "leading_space_cell",
            input: " cell:v1:blake3:0000000000000000000000000000000000000000000000000000000000000000",
            target_type: TargetType::CellId,
            expected_error: ExpectedError::Whitespace,
        },
        InvalidTextVector {
            name: "all_uppercase_cell",
            input: "CELL:V1:BLAKE3:0000000000000000000000000000000000000000000000000000000000000000",
            target_type: TargetType::CellId,
            expected_error: ExpectedError::Uppercase,
        },
        InvalidTextVector {
            name: "wrong_prefix_cell",
            input: "holon:v1:blake3:0000000000000000000000000000000000000000000000000000000000000000",
            target_type: TargetType::CellId,
            expected_error: ExpectedError::WrongPrefix,
        },
        InvalidTextVector {
            name: "truncated_cell",
            input: "cell:v1:blake3:abcd",
            target_type: TargetType::CellId,
            expected_error: ExpectedError::Truncated,
        },
        InvalidTextVector {
            name: "invalid_hex_cell",
            input: "cell:v1:blake3:g000000000000000000000000000000000000000000000000000000000000000",
            target_type: TargetType::CellId,
            expected_error: ExpectedError::InvalidHex,
        },
        InvalidTextVector {
            name: "percent_encoded_cell",
            input: "cell%3av1%3ablake3%3a0000000000000000000000000000000000000000000000000000000000000000",
            target_type: TargetType::CellId,
            expected_error: ExpectedError::PercentEncoded,
        },
        InvalidTextVector {
            name: "non_ascii_cell",
            input: "cell\u{FF1A}v1:blake3:0000000000000000000000000000000000000000000000000000000000000000",
            target_type: TargetType::CellId,
            expected_error: ExpectedError::NonAscii,
        },
        // === HolonIdV1 invalid text vectors ===
        InvalidTextVector {
            name: "leading_space_holon",
            input: " holon:v1:blake3:0000000000000000000000000000000000000000000000000000000000000000",
            target_type: TargetType::HolonId,
            expected_error: ExpectedError::Whitespace,
        },
        InvalidTextVector {
            name: "all_uppercase_holon",
            input: "HOLON:V1:BLAKE3:0000000000000000000000000000000000000000000000000000000000000000",
            target_type: TargetType::HolonId,
            expected_error: ExpectedError::Uppercase,
        },
        InvalidTextVector {
            name: "wrong_prefix_holon",
            input: "cell:v1:blake3:0000000000000000000000000000000000000000000000000000000000000000",
            target_type: TargetType::HolonId,
            expected_error: ExpectedError::WrongPrefix,
        },
        InvalidTextVector {
            name: "truncated_holon",
            input: "holon:v1:blake3:abcd",
            target_type: TargetType::HolonId,
            expected_error: ExpectedError::Truncated,
        },
        InvalidTextVector {
            name: "invalid_hex_holon",
            input: "holon:v1:blake3:g000000000000000000000000000000000000000000000000000000000000000",
            target_type: TargetType::HolonId,
            expected_error: ExpectedError::InvalidHex,
        },
        InvalidTextVector {
            name: "percent_encoded_holon",
            input: "holon%3av1%3ablake3%3a0000000000000000000000000000000000000000000000000000000000000000",
            target_type: TargetType::HolonId,
            expected_error: ExpectedError::PercentEncoded,
        },
        InvalidTextVector {
            name: "non_ascii_holon",
            input: "holon\u{FF1A}v1:blake3:0000000000000000000000000000000000000000000000000000000000000000",
            target_type: TargetType::HolonId,
            expected_error: ExpectedError::NonAscii,
        },
    ]
}

// ============================================================================
// Key Role Separation Vectors (REQ-0009)
// ============================================================================

/// Key-role separation conformance vector.
#[derive(Debug)]
pub struct KeyRoleConformanceVector {
    /// Human-readable vector name.
    pub name: &'static str,
    /// Root/genesis key material fill byte.
    pub root_key_fill: u8,
    /// Operational key material fill byte.
    pub operational_key_fill: u8,
    /// Optional session key material fill byte.
    pub session_key_fill: Option<u8>,
    /// Expected pass/fail result.
    pub should_pass: bool,
}

/// Return key-role separation vectors for REQ-0009.
pub fn key_role_conformance_vectors() -> Vec<KeyRoleConformanceVector> {
    vec![
        KeyRoleConformanceVector {
            name: "distinct_root_operational_session",
            root_key_fill: 0xA1,
            operational_key_fill: 0xB2,
            session_key_fill: Some(0xC3),
            should_pass: true,
        },
        KeyRoleConformanceVector {
            name: "reject_root_equals_operational",
            root_key_fill: 0xA1,
            operational_key_fill: 0xA1,
            session_key_fill: Some(0xC3),
            should_pass: false,
        },
        KeyRoleConformanceVector {
            name: "reject_operational_equals_session",
            root_key_fill: 0xA1,
            operational_key_fill: 0xB2,
            session_key_fill: Some(0xB2),
            should_pass: false,
        },
        KeyRoleConformanceVector {
            name: "reject_root_equals_session",
            root_key_fill: 0xA1,
            operational_key_fill: 0xB2,
            session_key_fill: Some(0xA1),
            should_pass: false,
        },
    ]
}

// ============================================================================
// Conformance Test Runner
// ============================================================================

/// Run all conformance tests against frozen fixture vectors and return the
/// results.
///
/// Each entry in the returned vector is `(vector_name, passed, detail)`.
/// A conforming implementation MUST have all entries pass.
///
/// Valid vectors use precomputed static hex/text values. The test runner
/// parses these fixtures through the production parsers and verifies
/// round-trip fidelity without re-deriving expected values at runtime.
pub fn run_conformance_tests() -> Vec<(&'static str, bool, String)> {
    let mut results = Vec::new();

    // --- Valid PublicKeyIdV1 vectors (static fixtures) ---
    for vector in valid_public_key_id_vectors() {
        // Text parse must succeed
        let text_result = PublicKeyIdV1::parse_text(vector.text);
        let text_ok = match &text_result {
            Ok(_) => true,
            Err(e) => {
                results.push((vector.name, false, format!("text parse failed: {e}")));
                continue;
            },
        };
        results.push((
            vector.name,
            text_ok,
            if text_ok {
                "text parse OK".to_string()
            } else {
                "text parse failed".to_string()
            },
        ));

        // Binary parse must succeed
        let binary_bytes = hex::decode(vector.binary_hex).expect("valid hex in vector");
        let binary_result = PublicKeyIdV1::from_binary(&binary_bytes);
        let binary_ok = match &binary_result {
            Ok(_) => true,
            Err(e) => {
                results.push((vector.name, false, format!("binary parse failed: {e}")));
                continue;
            },
        };
        results.push((
            vector.name,
            binary_ok,
            if binary_ok {
                "binary parse OK".to_string()
            } else {
                "binary parse failed".to_string()
            },
        ));

        // Text and binary parsers must agree
        let from_text = text_result.unwrap();
        let from_binary = binary_result.unwrap();
        let agree = from_text == from_binary;
        results.push((
            vector.name,
            agree,
            if agree {
                "text/binary agree".to_string()
            } else {
                "text/binary DISAGREE".to_string()
            },
        ));

        // Text re-encoding must match frozen fixture
        let re_encoded = from_text.to_text();
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
        let alg_pass = from_text.algorithm() == vector.algorithm;
        results.push((
            vector.name,
            alg_pass,
            if alg_pass {
                "algorithm tag OK".to_string()
            } else {
                format!("algorithm tag mismatch: got {:?}", from_text.algorithm())
            },
        ));
    }

    // --- Valid KeySetIdV1 vectors (static fixtures) ---
    for vector in valid_keyset_id_vectors() {
        let text_result = KeySetIdV1::parse_text(vector.text);
        let text_ok = match &text_result {
            Ok(_) => true,
            Err(e) => {
                results.push((vector.name, false, format!("text parse failed: {e}")));
                continue;
            },
        };
        results.push((
            vector.name,
            text_ok,
            if text_ok {
                "text parse OK".to_string()
            } else {
                "text parse failed".to_string()
            },
        ));

        let binary_bytes = hex::decode(vector.binary_hex).expect("valid hex in vector");
        let binary_result = KeySetIdV1::from_binary(&binary_bytes);
        let binary_ok = match &binary_result {
            Ok(_) => true,
            Err(e) => {
                results.push((vector.name, false, format!("binary parse failed: {e}")));
                continue;
            },
        };
        results.push((
            vector.name,
            binary_ok,
            if binary_ok {
                "binary parse OK".to_string()
            } else {
                "binary parse failed".to_string()
            },
        ));

        let from_text = text_result.unwrap();
        let from_binary = binary_result.unwrap();
        let text_round_trip = KeySetIdV1::parse_text(&from_text.to_text())
            .is_ok_and(|reparsed| reparsed == from_text);
        let binary_round_trip = KeySetIdV1::from_binary(from_binary.as_bytes())
            .is_ok_and(|reparsed| reparsed == from_binary);
        let round_trip_ok = text_round_trip && binary_round_trip;
        results.push((
            vector.name,
            round_trip_ok,
            if round_trip_ok {
                "text-origin and binary-origin round-trips OK".to_string()
            } else {
                format!(
                    "round-trip failed: text_origin_ok={text_round_trip}, \
                     binary_origin_ok={binary_round_trip}"
                )
            },
        ));

        let re_encoded = from_binary.to_text();
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

        // Verify set tag from binary parse
        let tag_pass = from_binary.set_tag() == Some(vector.set_tag);
        results.push((
            vector.name,
            tag_pass,
            if tag_pass {
                "set tag OK".to_string()
            } else {
                format!("set tag mismatch: got {:?}", from_binary.set_tag())
            },
        ));
    }

    // --- Valid CellIdV1 vectors (static fixtures) ---
    for vector in valid_cell_id_vectors() {
        let text_result = CellIdV1::parse_text(vector.text);
        let text_ok = match &text_result {
            Ok(_) => true,
            Err(e) => {
                results.push((vector.name, false, format!("text parse failed: {e}")));
                continue;
            },
        };
        results.push((
            vector.name,
            text_ok,
            if text_ok {
                "text parse OK".to_string()
            } else {
                "text parse failed".to_string()
            },
        ));

        let binary_bytes = hex::decode(vector.binary_hex).expect("valid hex in vector");
        let binary_result = CellIdV1::from_binary(&binary_bytes);
        let binary_ok = match &binary_result {
            Ok(_) => true,
            Err(e) => {
                results.push((vector.name, false, format!("binary parse failed: {e}")));
                continue;
            },
        };
        results.push((
            vector.name,
            binary_ok,
            if binary_ok {
                "binary parse OK".to_string()
            } else {
                "binary parse failed".to_string()
            },
        ));

        let from_text = text_result.unwrap();
        let from_binary = binary_result.unwrap();
        let agree = from_text == from_binary;
        results.push((
            vector.name,
            agree,
            if agree {
                "text/binary agree".to_string()
            } else {
                "text/binary DISAGREE".to_string()
            },
        ));

        let re_encoded = from_binary.to_text();
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

        let tag_ok = from_binary.version_tag() == 0x01;
        results.push((
            vector.name,
            tag_ok,
            if tag_ok {
                "version tag OK".to_string()
            } else {
                format!(
                    "version tag mismatch: got 0x{:02x}",
                    from_binary.version_tag()
                )
            },
        ));
    }

    // --- Valid HolonIdV1 vectors (static fixtures) ---
    for vector in valid_holon_id_vectors() {
        let text_result = HolonIdV1::parse_text(vector.text);
        let text_ok = match &text_result {
            Ok(_) => true,
            Err(e) => {
                results.push((vector.name, false, format!("text parse failed: {e}")));
                continue;
            },
        };
        results.push((
            vector.name,
            text_ok,
            if text_ok {
                "text parse OK".to_string()
            } else {
                "text parse failed".to_string()
            },
        ));

        let binary_bytes = hex::decode(vector.binary_hex).expect("valid hex in vector");
        let binary_result = HolonIdV1::from_binary(&binary_bytes);
        let binary_ok = match &binary_result {
            Ok(_) => true,
            Err(e) => {
                results.push((vector.name, false, format!("binary parse failed: {e}")));
                continue;
            },
        };
        results.push((
            vector.name,
            binary_ok,
            if binary_ok {
                "binary parse OK".to_string()
            } else {
                "binary parse failed".to_string()
            },
        ));

        let from_text = text_result.unwrap();
        let from_binary = binary_result.unwrap();
        let agree = from_text == from_binary;
        results.push((
            vector.name,
            agree,
            if agree {
                "text/binary agree".to_string()
            } else {
                "text/binary DISAGREE".to_string()
            },
        ));

        let re_encoded = from_binary.to_text();
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

        let tag_ok = from_binary.version_tag() == 0x01;
        results.push((
            vector.name,
            tag_ok,
            if tag_ok {
                "version tag OK".to_string()
            } else {
                format!(
                    "version tag mismatch: got 0x{:02x}",
                    from_binary.version_tag()
                )
            },
        ));
    }

    // --- Invalid text vectors ---
    for vector in invalid_text_vectors() {
        let parse_result = match vector.target_type {
            TargetType::PublicKeyId => PublicKeyIdV1::parse_text(vector.input).map(|_| ()),
            TargetType::KeySetId => KeySetIdV1::parse_text(vector.input).map(|_| ()),
            TargetType::CellId => CellIdV1::parse_text(vector.input).map(|_| ()),
            TargetType::HolonId => HolonIdV1::parse_text(vector.input).map(|_| ()),
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
                    matches!(e, KeyIdError::HexLengthMismatch { .. })
                        || matches!(e, KeyIdError::HexDecodeError { .. })
                },
                ExpectedError::InvalidHex => {
                    matches!(e, KeyIdError::InvalidHexCharacters)
                },
                ExpectedError::UnknownTag => {
                    matches!(e, KeyIdError::UnknownAlgorithmTag { .. })
                        || matches!(e, KeyIdError::UnknownSetTag { .. })
                        || matches!(e, KeyIdError::UnknownVersionTag { .. })
                },
                ExpectedError::Extended => {
                    matches!(e, KeyIdError::HexLengthMismatch { .. })
                        || matches!(e, KeyIdError::TextTooLong { .. })
                },
                ExpectedError::PercentEncoded => {
                    matches!(e, KeyIdError::ContainsPercentEncoding)
                },
                ExpectedError::NonAscii => {
                    matches!(e, KeyIdError::ContainsNonAscii)
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
    use crate::identity::{
        CellGenesisV1, HolonGenesisV1, HolonPurpose, PolicyRootId, validate_key_roles,
    };

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

        // Binding assertion: total vector count must be specific non-zero
        // value (prevents silent test-count regression).
        // 5 PK vectors x 5 checks + 4 KS vectors x 5 checks
        // + 4 Cell vectors x 5 checks + 4 Holon vectors x 5 checks
        // + 46 invalid = 131
        assert_eq!(
            total, 131,
            "expected exactly 131 conformance vector checks, got {total}"
        );
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
        for vector in &vectors {
            let binary = hex::decode(vector.binary_hex).expect("valid hex");
            assert!(
                seen.insert(binary),
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
        for vector in &vectors {
            let binary = hex::decode(vector.binary_hex).expect("valid hex");
            assert!(
                seen.insert(binary),
                "duplicate KeySetIdV1 in vector set: {}",
                vector.name
            );
        }
    }

    /// Verify valid `CellIdV1` vectors produce non-zero distinct identifiers.
    #[test]
    fn valid_cell_vectors_are_distinct() {
        let vectors = valid_cell_id_vectors();
        assert_eq!(
            vectors.len(),
            4,
            "expected exactly 4 valid CellIdV1 vectors"
        );

        let mut seen = std::collections::HashSet::new();
        for vector in &vectors {
            let binary = hex::decode(vector.binary_hex).expect("valid hex");
            assert!(
                seen.insert(binary),
                "duplicate CellIdV1 in vector set: {}",
                vector.name
            );
        }
    }

    /// Verify valid `HolonIdV1` vectors produce non-zero distinct identifiers.
    #[test]
    fn valid_holon_vectors_are_distinct() {
        let vectors = valid_holon_id_vectors();
        assert_eq!(
            vectors.len(),
            4,
            "expected exactly 4 valid HolonIdV1 vectors"
        );

        let mut seen = std::collections::HashSet::new();
        for vector in &vectors {
            let binary = hex::decode(vector.binary_hex).expect("valid hex");
            assert!(
                seen.insert(binary),
                "duplicate HolonIdV1 in vector set: {}",
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
            46,
            "expected exactly 46 invalid text vectors"
        );
    }

    /// Verify REQ-0009 key role separation vectors.
    #[test]
    fn key_role_conformance_vectors_pass() {
        let vectors = key_role_conformance_vectors();
        assert_eq!(
            vectors.len(),
            4,
            "expected exactly 4 key-role conformance vectors"
        );

        for vector in vectors {
            let root_key_id =
                PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[vector.root_key_fill; 32]);
            let operational_key_id = PublicKeyIdV1::from_key_bytes(
                AlgorithmTag::Ed25519,
                &[vector.operational_key_fill; 32],
            );
            let session_key_id = vector
                .session_key_fill
                .map(|fill| PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[fill; 32]));

            let result =
                validate_key_roles(&root_key_id, &operational_key_id, session_key_id.as_ref());
            assert_eq!(
                result.is_ok(),
                vector.should_pass,
                "key-role conformance vector {} failed unexpectedly: {:?}",
                vector.name,
                result
            );
        }
    }

    /// Parser differential: runtime-derived `PublicKeyIdV1` values must match
    /// the frozen fixture hex/text values. This test re-derives from known
    /// key material and compares against the static fixtures.
    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn pk_derivation_matches_frozen_fixtures() {
        let ascending = {
            let mut buf = [0u8; 32];
            for (i, b) in buf.iter_mut().enumerate() {
                *b = i as u8;
            }
            buf
        };
        let descending = {
            let mut buf = [0u8; 32];
            for (i, b) in buf.iter_mut().enumerate() {
                *b = (31 - i) as u8;
            }
            buf
        };
        let key_materials: &[(&str, AlgorithmTag, [u8; 32])] = &[
            ("ed25519_zeros", AlgorithmTag::Ed25519, [0x00u8; 32]),
            ("ed25519_ones", AlgorithmTag::Ed25519, [0x01u8; 32]),
            ("ed25519_ff", AlgorithmTag::Ed25519, [0xFFu8; 32]),
            ("ed25519_ascending", AlgorithmTag::Ed25519, ascending),
            ("ed25519_descending", AlgorithmTag::Ed25519, descending),
        ];

        let fixtures = valid_public_key_id_vectors();
        assert_eq!(key_materials.len(), fixtures.len());

        for (i, (name, alg, key_bytes)) in key_materials.iter().enumerate() {
            let derived = PublicKeyIdV1::from_key_bytes(*alg, key_bytes);
            let fixture = &fixtures[i];
            assert_eq!(
                fixture.name, *name,
                "fixture ordering mismatch at index {i}"
            );
            assert_eq!(
                hex::encode(derived.to_binary()),
                fixture.binary_hex,
                "binary mismatch for {name}"
            );
            assert_eq!(derived.to_text(), fixture.text, "text mismatch for {name}");
        }
    }

    /// Parser differential: runtime-derived `KeySetIdV1` values must match
    /// the frozen fixture hex/text values. Uses the full descriptor format
    /// with `key_algorithm`, `threshold_k`, and optional weights.
    #[test]
    #[allow(clippy::type_complexity)]
    fn ks_derivation_matches_frozen_fixtures() {
        let key_a = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[0xAA; 32]);
        let key_b = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[0xBB; 32]);
        let key_c = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[0xCC; 32]);

        let derivations: Vec<(&str, SetTag, u32, Vec<PublicKeyIdV1>, Option<&[u64]>)> = vec![
            (
                "multisig_two_members",
                SetTag::Multisig,
                2,
                vec![key_a.clone(), key_b.clone()],
                None,
            ),
            (
                "multisig_three_members",
                SetTag::Multisig,
                3,
                vec![key_a.clone(), key_b.clone(), key_c.clone()],
                None,
            ),
            (
                "threshold_two_members",
                SetTag::Threshold,
                1,
                vec![key_a.clone(), key_b.clone()],
                None,
            ),
            (
                "threshold_three_members",
                SetTag::Threshold,
                2,
                vec![key_a, key_b, key_c],
                None,
            ),
        ];

        let fixtures = valid_keyset_id_vectors();
        assert_eq!(derivations.len(), fixtures.len());

        for (i, (name, tag, threshold_k, members, weights)) in derivations.iter().enumerate() {
            let derived =
                KeySetIdV1::from_descriptor("ed25519", *tag, *threshold_k, members, *weights)
                    .expect("valid descriptor must succeed");
            let fixture = &fixtures[i];
            assert_eq!(
                fixture.name, *name,
                "fixture ordering mismatch at index {i}"
            );
            assert_eq!(
                hex::encode(derived.to_binary()),
                fixture.binary_hex,
                "binary mismatch for {name}"
            );
            assert_eq!(derived.to_text(), fixture.text, "text mismatch for {name}");
        }
    }

    /// Parser differential: runtime-derived `CellIdV1` values must match
    /// the frozen fixture hex/text values.
    #[test]
    fn cell_derivation_matches_frozen_fixtures() {
        let pk_aa = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[0xAA; 32]);
        let pk_bb = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[0xBB; 32]);
        let pk_00 = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[0x00; 32]);

        let quorum = KeySetIdV1::from_descriptor(
            "ed25519",
            SetTag::Threshold,
            1,
            &[pk_aa.clone(), pk_bb.clone()],
            None,
        )
        .unwrap();

        let derivations = [
            (
                "cell_single_policy_11aa",
                CellGenesisV1::new(
                    [0x11; 32],
                    PolicyRootId::Single(pk_aa),
                    "cell.alpha.internal",
                )
                .unwrap(),
            ),
            (
                "cell_single_policy_22bb",
                CellGenesisV1::new(
                    [0x22; 32],
                    PolicyRootId::Single(pk_bb),
                    "cell.beta.internal",
                )
                .unwrap(),
            ),
            (
                "cell_quorum_threshold",
                CellGenesisV1::new(
                    [0x33; 32],
                    PolicyRootId::Quorum(quorum),
                    "cell.gamma.internal",
                )
                .unwrap(),
            ),
            (
                "cell_single_policy_ff00",
                CellGenesisV1::new(
                    [0xFF; 32],
                    PolicyRootId::Single(pk_00),
                    "cell.delta.internal",
                )
                .unwrap(),
            ),
        ];

        let fixtures = valid_cell_id_vectors();
        assert_eq!(derivations.len(), fixtures.len());

        for (i, (name, genesis)) in derivations.iter().enumerate() {
            let derived = CellIdV1::from_genesis(genesis);
            let fixture = &fixtures[i];
            assert_eq!(
                fixture.name, *name,
                "fixture ordering mismatch at index {i}"
            );
            assert_eq!(
                hex::encode(derived.to_binary()),
                fixture.binary_hex,
                "binary mismatch for {name}"
            );
            assert_eq!(derived.to_text(), fixture.text, "text mismatch for {name}");
        }
    }

    /// Parser differential: runtime-derived `HolonIdV1` values must match
    /// the frozen fixture hex/text values.
    #[test]
    fn holon_derivation_matches_frozen_fixtures() {
        let pk_aa_bytes = [0xAA; 32];
        let pk_bb_bytes = [0xBB; 32];
        let pk_cc_bytes = [0xCC; 32];
        let pk_aa = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &pk_aa_bytes);
        let pk_bb = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &pk_bb_bytes);
        let pk_cc = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &pk_cc_bytes);

        let cell_fixtures = valid_cell_id_vectors();
        let cell1_binary = hex::decode(cell_fixtures[0].binary_hex).unwrap();
        let cell2_binary = hex::decode(cell_fixtures[1].binary_hex).unwrap();
        let cell3_binary = hex::decode(cell_fixtures[2].binary_hex).unwrap();
        let cell1 = CellIdV1::from_binary(&cell1_binary).unwrap();
        let cell2 = CellIdV1::from_binary(&cell2_binary).unwrap();
        let cell3 = CellIdV1::from_binary(&cell3_binary).unwrap();

        let derivations = [
            (
                "holon_cell1_keyaa",
                HolonGenesisV1::new(
                    cell1.clone(),
                    pk_aa.clone(),
                    pk_aa_bytes.to_vec(),
                    None,
                    None,
                )
                .unwrap(),
            ),
            (
                "holon_cell1_keybb",
                HolonGenesisV1::new(cell1, pk_bb, pk_bb_bytes.to_vec(), None, None).unwrap(),
            ),
            (
                "holon_cell2_keyaa",
                HolonGenesisV1::new(cell2, pk_aa, pk_aa_bytes.to_vec(), None, None).unwrap(),
            ),
            (
                "holon_cell3_keycc",
                HolonGenesisV1::new(
                    cell3,
                    pk_cc,
                    pk_cc_bytes.to_vec(),
                    Some(HolonPurpose::Validator),
                    Some("anchor:fixture".to_string()),
                )
                .unwrap(),
            ),
        ];

        let fixtures = valid_holon_id_vectors();
        assert_eq!(derivations.len(), fixtures.len());

        for (i, (name, genesis)) in derivations.iter().enumerate() {
            let derived = HolonIdV1::from_genesis(genesis);
            let fixture = &fixtures[i];
            assert_eq!(
                fixture.name, *name,
                "fixture ordering mismatch at index {i}"
            );
            assert_eq!(
                hex::encode(derived.to_binary()),
                fixture.binary_hex,
                "binary mismatch for {name}"
            );
            assert_eq!(derived.to_text(), fixture.text, "text mismatch for {name}");
        }
    }

    /// Parser differential: `PublicKeyIdV1::parse_text` and `from_binary`
    /// agree on all frozen fixture vectors.
    #[test]
    fn pk_parser_differential_valid() {
        for vector in valid_public_key_id_vectors() {
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
        }
    }

    /// Parser differential: both origin-specific round-trips are lossless for
    /// all frozen `KeySetIdV1` fixture vectors.
    #[test]
    fn ks_parser_differential_valid() {
        for vector in valid_keyset_id_vectors() {
            let from_text = KeySetIdV1::parse_text(vector.text).expect("valid vector must parse");
            let binary_bytes = hex::decode(vector.binary_hex).expect("valid hex");
            let from_binary =
                KeySetIdV1::from_binary(&binary_bytes).expect("valid vector must parse");

            let text_reparsed = KeySetIdV1::parse_text(&from_text.to_text())
                .expect("text-origin re-parse must succeed");
            assert_eq!(
                from_text, text_reparsed,
                "text-origin round-trip failure for {}",
                vector.name
            );

            let binary_reparsed = KeySetIdV1::from_binary(from_binary.as_bytes())
                .expect("binary-origin re-parse must succeed");
            assert_eq!(
                from_binary, binary_reparsed,
                "binary-origin round-trip failure for {}",
                vector.name
            );

            assert_eq!(
                from_text.to_text(),
                from_binary.to_text(),
                "canonical text mismatch for {}",
                vector.name
            );
        }
    }

    /// Parser differential: `CellIdV1::parse_text` and `from_binary` agree
    /// on all frozen fixture vectors.
    #[test]
    fn cell_parser_differential_valid() {
        for vector in valid_cell_id_vectors() {
            let from_text = CellIdV1::parse_text(vector.text).expect("valid vector must parse");
            let binary_bytes = hex::decode(vector.binary_hex).expect("valid hex");
            let from_binary =
                CellIdV1::from_binary(&binary_bytes).expect("valid vector must parse");

            assert_eq!(
                from_text, from_binary,
                "text/binary parser differential for {}",
                vector.name
            );
        }
    }

    /// Parser differential: `HolonIdV1::parse_text` and `from_binary` agree
    /// on all frozen fixture vectors.
    #[test]
    fn holon_parser_differential_valid() {
        for vector in valid_holon_id_vectors() {
            let from_text = HolonIdV1::parse_text(vector.text).expect("valid vector must parse");
            let binary_bytes = hex::decode(vector.binary_hex).expect("valid hex");
            let from_binary =
                HolonIdV1::from_binary(&binary_bytes).expect("valid vector must parse");

            assert_eq!(
                from_text, from_binary,
                "text/binary parser differential for {}",
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
                TargetType::CellId => CellIdV1::parse_text(vector.input).map(|_| ()),
                TargetType::HolonId => HolonIdV1::parse_text(vector.input).map(|_| ()),
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
        for vector in valid_public_key_id_vectors() {
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

    /// Origin-specific round-trips for all valid `KeySetIdV1` vectors.
    #[test]
    fn ks_binary_text_binary_round_trip() {
        for vector in valid_keyset_id_vectors() {
            let binary_bytes = hex::decode(vector.binary_hex).expect("valid hex");
            let binary_origin = KeySetIdV1::from_binary(&binary_bytes).expect("valid binary");
            let binary_reparsed = KeySetIdV1::from_binary(binary_origin.as_bytes())
                .expect("binary-origin re-parse must succeed");
            assert_eq!(
                binary_origin, binary_reparsed,
                "binary-origin round-trip failure for {}",
                vector.name
            );

            let text_origin = KeySetIdV1::parse_text(vector.text).expect("valid text");
            let text_reparsed = KeySetIdV1::parse_text(&text_origin.to_text())
                .expect("text-origin re-parse must succeed");
            assert_eq!(
                text_origin, text_reparsed,
                "text-origin round-trip failure for {}",
                vector.name
            );
        }
    }

    /// Binary -> text -> binary round-trip for all valid `CellIdV1` vectors.
    #[test]
    fn cell_binary_text_binary_round_trip() {
        for vector in valid_cell_id_vectors() {
            let binary_bytes = hex::decode(vector.binary_hex).expect("valid hex");
            let id = CellIdV1::from_binary(&binary_bytes).expect("valid binary");
            let text = id.to_text();
            let reparsed = CellIdV1::parse_text(&text).expect("re-parse must succeed");
            assert_eq!(
                id.to_binary(),
                reparsed.to_binary(),
                "round-trip failure for {}",
                vector.name
            );
        }
    }

    /// Binary -> text -> binary round-trip for all valid `HolonIdV1` vectors.
    #[test]
    fn holon_binary_text_binary_round_trip() {
        for vector in valid_holon_id_vectors() {
            let binary_bytes = hex::decode(vector.binary_hex).expect("valid hex");
            let id = HolonIdV1::from_binary(&binary_bytes).expect("valid binary");
            let text = id.to_text();
            let reparsed = HolonIdV1::parse_text(&text).expect("re-parse must succeed");
            assert_eq!(
                id.to_binary(),
                reparsed.to_binary(),
                "round-trip failure for {}",
                vector.name
            );
        }
    }

    /// Verify that different `threshold_k` values produce different IDs
    /// for the same member set.
    #[test]
    fn different_threshold_k_produces_different_keyset_ids() {
        let key_a = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[0xAA; 32]);
        let key_b = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[0xBB; 32]);
        let key_c = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[0xCC; 32]);

        let id_1of3 = KeySetIdV1::from_descriptor(
            "ed25519",
            SetTag::Threshold,
            1,
            &[key_a.clone(), key_b.clone(), key_c.clone()],
            None,
        )
        .unwrap();
        let id_2of3 = KeySetIdV1::from_descriptor(
            "ed25519",
            SetTag::Threshold,
            2,
            &[key_a, key_b, key_c],
            None,
        )
        .unwrap();

        assert_ne!(
            id_1of3.merkle_root(),
            id_2of3.merkle_root(),
            "different threshold_k must produce different merkle roots"
        );
    }

    /// Verify that different weights produce different IDs for the same
    /// member set and threshold.
    #[test]
    fn different_weights_produces_different_keyset_ids() {
        let key_a = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[0xAA; 32]);
        let key_b = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[0xBB; 32]);

        let id_no_w = KeySetIdV1::from_descriptor(
            "ed25519",
            SetTag::Threshold,
            1,
            &[key_a.clone(), key_b.clone()],
            None,
        )
        .unwrap();
        let id_w12 = KeySetIdV1::from_descriptor(
            "ed25519",
            SetTag::Threshold,
            1,
            &[key_a.clone(), key_b.clone()],
            Some(&[1, 2]),
        )
        .unwrap();
        let id_w34 = KeySetIdV1::from_descriptor(
            "ed25519",
            SetTag::Threshold,
            1,
            &[key_a, key_b],
            Some(&[3, 4]),
        )
        .unwrap();

        assert_ne!(
            id_no_w.merkle_root(),
            id_w12.merkle_root(),
            "no-weights vs weights=[1,2] must differ"
        );
        assert_ne!(
            id_w12.merkle_root(),
            id_w34.merkle_root(),
            "weights=[1,2] vs weights=[3,4] must differ"
        );
    }
}
