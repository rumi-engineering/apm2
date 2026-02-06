//! Canonical key identifiers for the Holonic Substrate Interface (RFC-0020).
//!
//! This module implements [`PublicKeyIdV1`] and [`KeySetIdV1`], the canonical
//! binary and text forms for self-certifying cryptographic key identifiers.
//!
//! # Text Form Grammar
//!
//! ```text
//! PublicKeyIdV1 ::= "pk1:" <base32lower_no_pad(algorithm_tag || key_hash)>
//! KeySetIdV1   ::= "ks1:" <base32lower_no_pad(set_tag || merkle_root)>
//! ```
//!
//! - `algorithm_tag`: 1 byte identifying the key algorithm
//! - `key_hash`: 32-byte BLAKE3 hash of the domain-separated key material
//! - `set_tag`: 1 byte identifying the key-set mode
//! - `merkle_root`: 32-byte BLAKE3 hash of sorted member key IDs
//! - Base32 encoding: RFC 4648 lowercase, no padding (`a-z2-7`)
//!
//! # Security Invariants
//!
//! - **Fail-closed parsing**: unknown algorithm/set tags are rejected, never
//!   defaulted.
//! - **Strict canonical form**: mixed case, whitespace, padding characters, and
//!   non-canonical base32 are all rejected.
//! - **Bounded length**: text forms are bounded to [`MAX_TEXT_LEN`] characters.
//! - **Lossless round-trip**: binary-to-text-to-binary produces identical
//!   bytes.
//!
//! # Contract References
//!
//! - RFC-0020 section 1.7.2: `PublicKeyIdV1` canonical key identifiers
//! - RFC-0020 section 1.7.2a: `KeySetIdV1` quorum/threshold verifier identity
//! - REQ-0007: Canonical key identifier formats
//! - EVID-0007: Canonical key identifier conformance evidence
//! - EVID-0303: Rollout phase S0.75 evidence

mod keyset_id;
mod public_key_id;

pub mod conformance;

pub use keyset_id::{KeySetIdV1, SetTag};
pub use public_key_id::{AlgorithmTag, PublicKeyIdV1};
use thiserror::Error;

/// Maximum length of any canonical text form (bytes).
///
/// Both `pk1:` (4 bytes) and `ks1:` (4 bytes) prefixes + base32-encoded
/// 33 bytes (ceil(33*8/5) = 53 characters) = 57 characters total.
/// We set the bound to 64 to allow modest future growth while still
/// preventing unbounded input.
pub const MAX_TEXT_LEN: usize = 64;

/// Size of the hash portion of a key identifier (BLAKE3 output).
pub const HASH_LEN: usize = 32;

/// Size of the full binary form: 1-byte tag + 32-byte hash.
pub const BINARY_LEN: usize = 33;

/// Errors produced when parsing or constructing key identifiers.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum KeyIdError {
    /// Input text exceeds [`MAX_TEXT_LEN`].
    #[error("text form exceeds maximum length of {MAX_TEXT_LEN} bytes (got {len})")]
    TextTooLong {
        /// Actual length of the input.
        len: usize,
    },

    /// Input text is empty.
    #[error("empty input")]
    EmptyInput,

    /// Input contains leading or trailing whitespace.
    #[error("input contains leading or trailing whitespace")]
    ContainsWhitespace,

    /// Input contains interior whitespace.
    #[error("input contains interior whitespace")]
    ContainsInteriorWhitespace,

    /// Wrong prefix for the expected type (e.g. `ks1:` when `pk1:` expected).
    #[error("wrong prefix: expected \"{expected}\", got \"{got}\"")]
    WrongPrefix {
        /// Expected prefix.
        expected: &'static str,
        /// Actual prefix found.
        got: String,
    },

    /// Input contains uppercase characters (non-canonical).
    #[error("input contains uppercase characters; canonical form is lowercase")]
    ContainsUppercase,

    /// Input contains padding characters (`=`) which are not permitted.
    #[error("input contains base32 padding characters")]
    ContainsPadding,

    /// Base32 decoding failed.
    #[error("base32 decode error: {reason}")]
    Base32DecodeError {
        /// Description of the decode failure.
        reason: String,
    },

    /// Decoded binary length does not match expected [`BINARY_LEN`].
    #[error("decoded binary length mismatch: expected {BINARY_LEN}, got {got}")]
    BinaryLengthMismatch {
        /// Actual decoded length.
        got: usize,
    },

    /// Binary input length does not match expected [`BINARY_LEN`].
    #[error("binary input length mismatch: expected {BINARY_LEN}, got {got}")]
    InvalidBinaryLength {
        /// Actual input length.
        got: usize,
    },

    /// Unknown algorithm tag byte (fail-closed).
    #[error("unknown algorithm tag: 0x{tag:02x}")]
    UnknownAlgorithmTag {
        /// The unrecognized tag byte.
        tag: u8,
    },

    /// Unknown key-set tag byte (fail-closed).
    #[error("unknown set tag: 0x{tag:02x}")]
    UnknownSetTag {
        /// The unrecognized tag byte.
        tag: u8,
    },

    /// Input contains characters outside the base32 lowercase alphabet.
    #[error("input contains invalid base32 characters")]
    InvalidBase32Characters,
}

/// Validate common text-form invariants before type-specific parsing.
///
/// Checks:
/// 1. Non-empty
/// 2. No leading/trailing whitespace
/// 3. No interior whitespace
/// 4. Bounded length
/// 5. No uppercase letters (strict lowercase)
fn validate_text_common(input: &str) -> Result<(), KeyIdError> {
    if input.is_empty() {
        return Err(KeyIdError::EmptyInput);
    }

    // Check leading/trailing whitespace
    if input != input.trim() {
        return Err(KeyIdError::ContainsWhitespace);
    }

    // Check interior whitespace
    if input.chars().any(char::is_whitespace) {
        return Err(KeyIdError::ContainsInteriorWhitespace);
    }

    // Bounded length
    if input.len() > MAX_TEXT_LEN {
        return Err(KeyIdError::TextTooLong { len: input.len() });
    }

    // Strict lowercase (reject mixed case)
    if input.chars().any(|c| c.is_ascii_uppercase()) {
        return Err(KeyIdError::ContainsUppercase);
    }

    // Reject padding characters
    if input.contains('=') {
        return Err(KeyIdError::ContainsPadding);
    }

    Ok(())
}

/// Decode the base32-encoded payload after the prefix.
///
/// Uses RFC 4648 base32 lowercase without padding.
fn decode_base32_payload(encoded: &str) -> Result<Vec<u8>, KeyIdError> {
    // Validate characters are in the base32 lowercase alphabet (a-z, 2-7)
    for ch in encoded.chars() {
        if !matches!(ch, 'a'..='z' | '2'..='7') {
            return Err(KeyIdError::InvalidBase32Characters);
        }
    }

    // Use data_encoding's BASE32_NOPAD with lowercase
    // data_encoding expects uppercase; we'll use the lowercase hex variant
    // Actually, data_encoding has BASE32_NOPAD which is uppercase.
    // We need to convert to uppercase for decoding, but ONLY after we've
    // already verified the input is strictly lowercase (enforced above).
    let upper: String = encoded.to_ascii_uppercase();
    data_encoding::BASE32_NOPAD
        .decode(upper.as_bytes())
        .map_err(|e| KeyIdError::Base32DecodeError {
            reason: e.to_string(),
        })
}

/// Encode binary data to base32 lowercase without padding.
fn encode_base32_payload(data: &[u8]) -> String {
    // data_encoding::BASE32_NOPAD produces uppercase; convert to lowercase
    data_encoding::BASE32_NOPAD
        .encode(data)
        .to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_text_rejects_empty() {
        assert_eq!(validate_text_common(""), Err(KeyIdError::EmptyInput));
    }

    #[test]
    fn validate_text_rejects_leading_whitespace() {
        assert_eq!(
            validate_text_common(" pk1:abc"),
            Err(KeyIdError::ContainsWhitespace)
        );
    }

    #[test]
    fn validate_text_rejects_trailing_whitespace() {
        assert_eq!(
            validate_text_common("pk1:abc "),
            Err(KeyIdError::ContainsWhitespace)
        );
    }

    #[test]
    fn validate_text_rejects_interior_whitespace() {
        assert_eq!(
            validate_text_common("pk1:a\tb"),
            Err(KeyIdError::ContainsInteriorWhitespace)
        );
    }

    #[test]
    fn validate_text_rejects_too_long() {
        let long = "a".repeat(MAX_TEXT_LEN + 1);
        assert_eq!(
            validate_text_common(&long),
            Err(KeyIdError::TextTooLong {
                len: MAX_TEXT_LEN + 1
            })
        );
    }

    #[test]
    fn validate_text_rejects_uppercase() {
        assert_eq!(
            validate_text_common("PK1:abc"),
            Err(KeyIdError::ContainsUppercase)
        );
    }

    #[test]
    fn validate_text_rejects_padding() {
        assert_eq!(
            validate_text_common("pk1:abc="),
            Err(KeyIdError::ContainsPadding)
        );
    }

    #[test]
    fn validate_text_accepts_valid() {
        assert!(validate_text_common("pk1:abcdefg234567").is_ok());
    }

    #[test]
    fn base32_round_trip() {
        let data = [0x01u8; 33];
        let encoded = encode_base32_payload(&data);
        let decoded = decode_base32_payload(&encoded).unwrap();
        assert_eq!(&decoded, &data);
    }
}
