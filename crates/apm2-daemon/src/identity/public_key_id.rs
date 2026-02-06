//! `PublicKeyIdV1` — canonical identifier for a single public key.
//!
//! # Binary Form
//!
//! ```text
//! +------------------+----------------------------+
//! | algorithm_tag    | key_hash                   |
//! | (1 byte)         | (32 bytes, BLAKE3)         |
//! +------------------+----------------------------+
//! ```
//!
//! # Text Form
//!
//! ```text
//! pk1:<base32lower_no_pad(algorithm_tag || key_hash)>
//! ```
//!
//! # Algorithm Tags
//!
//! | Tag  | Algorithm |
//! |------|-----------|
//! | 0x01 | Ed25519   |
//!
//! Unknown tags are rejected (fail-closed).
//!
//! # Contract References
//!
//! - RFC-0020 section 1.7.2: Canonical key identifiers
//! - REQ-0007: Canonical key identifier formats

use std::fmt;

use super::{
    BINARY_LEN, HASH_LEN, KeyIdError, decode_base32_payload, encode_base32_payload,
    validate_text_common,
};

/// Prefix for `PublicKeyIdV1` text form.
const PREFIX: &str = "pk1:";

/// Domain separation string for BLAKE3 key hashing.
const DOMAIN_SEPARATION: &[u8] = b"apm2:pkid:v1\0";

/// Known algorithm tag values.
///
/// Unknown values are rejected at parse time (fail-closed per REQ-0007).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum AlgorithmTag {
    /// Ed25519 signing algorithm.
    Ed25519 = 0x01,
}

impl AlgorithmTag {
    /// Parse an algorithm tag from a raw byte.
    ///
    /// Returns `Err` for unknown tags (fail-closed).
    pub const fn from_byte(byte: u8) -> Result<Self, KeyIdError> {
        match byte {
            0x01 => Ok(Self::Ed25519),
            other => Err(KeyIdError::UnknownAlgorithmTag { tag: other }),
        }
    }

    /// Return the canonical byte representation.
    pub const fn to_byte(self) -> u8 {
        self as u8
    }

    /// Return the human-readable algorithm name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Ed25519 => "ed25519",
        }
    }
}

impl fmt::Display for AlgorithmTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// A canonical identifier for a single public key (RFC-0020 section 1.7.2).
///
/// Instances are guaranteed to contain a valid algorithm tag and exactly
/// 32 bytes of BLAKE3 key hash. The type is cheaply cloneable (33 bytes
/// inline).
///
/// # Construction
///
/// Use [`PublicKeyIdV1::from_key_bytes`] to derive from raw key material,
/// or [`PublicKeyIdV1::parse_text`] / [`PublicKeyIdV1::from_binary`] for
/// deserialization.
///
/// # Examples
///
/// ```
/// use apm2_daemon::identity::{AlgorithmTag, PublicKeyIdV1};
///
/// // Derive from raw Ed25519 public key bytes
/// let key_bytes = [0xABu8; 32];
/// let id = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &key_bytes);
///
/// // Round-trip through text form
/// let text = id.to_text();
/// let parsed = PublicKeyIdV1::parse_text(&text).unwrap();
/// assert_eq!(id, parsed);
///
/// // Round-trip through binary form
/// let binary = id.to_binary();
/// let from_bin = PublicKeyIdV1::from_binary(&binary).unwrap();
/// assert_eq!(id, from_bin);
/// ```
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PublicKeyIdV1 {
    /// Raw binary form: `algorithm_tag` (1 byte) + `key_hash` (32 bytes).
    binary: [u8; BINARY_LEN],
}

impl PublicKeyIdV1 {
    /// Derive a `PublicKeyIdV1` from raw public key bytes.
    ///
    /// Computes the BLAKE3 hash with domain separation:
    /// `blake3("apm2:pkid:v1\0" + algorithm_name + "\n" + key_bytes)`
    pub fn from_key_bytes(algorithm: AlgorithmTag, key_bytes: &[u8]) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(DOMAIN_SEPARATION);
        hasher.update(algorithm.name().as_bytes());
        hasher.update(b"\n");
        hasher.update(key_bytes);
        let hash = hasher.finalize();

        let mut binary = [0u8; BINARY_LEN];
        binary[0] = algorithm.to_byte();
        binary[1..].copy_from_slice(hash.as_bytes());
        Self { binary }
    }

    /// Parse a `PublicKeyIdV1` from its canonical text form.
    ///
    /// Enforces:
    /// - Correct `pk1:` prefix
    /// - Strict lowercase base32 without padding
    /// - No whitespace, no mixed case
    /// - Known algorithm tag (fail-closed)
    /// - Exactly 33 decoded bytes
    pub fn parse_text(input: &str) -> Result<Self, KeyIdError> {
        validate_text_common(input)?;

        // Check prefix
        let payload = input.strip_prefix(PREFIX).ok_or_else(|| {
            let got = if input.len() >= PREFIX.len() {
                input[..PREFIX.len()].to_string()
            } else {
                input.to_string()
            };
            KeyIdError::WrongPrefix {
                expected: PREFIX,
                got,
            }
        })?;

        // Decode base32 payload
        let decoded = decode_base32_payload(payload)?;

        // Validate length
        if decoded.len() != BINARY_LEN {
            return Err(KeyIdError::BinaryLengthMismatch { got: decoded.len() });
        }

        // Validate algorithm tag (fail-closed)
        let _algorithm = AlgorithmTag::from_byte(decoded[0])?;

        let mut binary = [0u8; BINARY_LEN];
        binary.copy_from_slice(&decoded);
        Ok(Self { binary })
    }

    /// Construct from raw binary form (1-byte tag + 32-byte hash).
    ///
    /// Validates the algorithm tag (fail-closed) and exact length.
    pub fn from_binary(bytes: &[u8]) -> Result<Self, KeyIdError> {
        if bytes.len() != BINARY_LEN {
            return Err(KeyIdError::InvalidBinaryLength { got: bytes.len() });
        }

        // Validate algorithm tag (fail-closed)
        let _algorithm = AlgorithmTag::from_byte(bytes[0])?;

        let mut binary = [0u8; BINARY_LEN];
        binary.copy_from_slice(bytes);
        Ok(Self { binary })
    }

    /// Return the canonical text form: `pk1:<base32lower_no_pad>`.
    pub fn to_text(&self) -> String {
        let mut result = String::with_capacity(PREFIX.len() + 53);
        result.push_str(PREFIX);
        result.push_str(&encode_base32_payload(&self.binary));
        result
    }

    /// Return the raw binary form (33 bytes).
    pub const fn to_binary(&self) -> [u8; BINARY_LEN] {
        self.binary
    }

    /// Return the algorithm tag.
    pub fn algorithm(&self) -> AlgorithmTag {
        // Safe: we validated the tag at construction time.
        AlgorithmTag::from_byte(self.binary[0])
            .expect("algorithm tag was validated at construction")
    }

    /// Return the 32-byte BLAKE3 key hash.
    pub fn key_hash(&self) -> &[u8; HASH_LEN] {
        self.binary[1..]
            .try_into()
            .expect("binary is exactly 33 bytes")
    }

    /// Return a reference to the full binary form.
    pub const fn as_bytes(&self) -> &[u8; BINARY_LEN] {
        &self.binary
    }
}

impl fmt::Debug for PublicKeyIdV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublicKeyIdV1")
            .field("text", &self.to_text())
            .finish()
    }
}

impl fmt::Display for PublicKeyIdV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_text())
    }
}

impl std::str::FromStr for PublicKeyIdV1 {
    type Err = KeyIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse_text(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create a known Ed25519 key ID for testing.
    fn make_test_id() -> PublicKeyIdV1 {
        let key_bytes = [0xABu8; 32];
        PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &key_bytes)
    }

    #[test]
    fn text_round_trip() {
        let id = make_test_id();
        let text = id.to_text();
        let parsed = PublicKeyIdV1::parse_text(&text).unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn binary_round_trip() {
        let id = make_test_id();
        let binary = id.to_binary();
        let from_bin = PublicKeyIdV1::from_binary(&binary).unwrap();
        assert_eq!(id, from_bin);
    }

    #[test]
    fn text_then_binary_round_trip() {
        let id = make_test_id();
        let text = id.to_text();
        let parsed = PublicKeyIdV1::parse_text(&text).unwrap();
        let binary = parsed.to_binary();
        let from_bin = PublicKeyIdV1::from_binary(&binary).unwrap();
        assert_eq!(id, from_bin);
    }

    #[test]
    fn rejects_wrong_prefix() {
        let id = make_test_id();
        let text = id.to_text().replacen("pk1:", "ks1:", 1);
        let err = PublicKeyIdV1::parse_text(&text).unwrap_err();
        assert!(matches!(err, KeyIdError::WrongPrefix { .. }));
    }

    #[test]
    fn rejects_uppercase() {
        let id = make_test_id();
        let text = id.to_text().to_ascii_uppercase();
        let err = PublicKeyIdV1::parse_text(&text).unwrap_err();
        assert_eq!(err, KeyIdError::ContainsUppercase);
    }

    #[test]
    fn rejects_mixed_case() {
        let id = make_test_id();
        let text = id.to_text();
        // Capitalize the first lowercase letter in the payload
        let mixed: String = text
            .char_indices()
            .map(|(i, c)| {
                // Capitalize the character right after "pk1:" (index 4)
                if i == 4 && c.is_ascii_lowercase() {
                    c.to_ascii_uppercase()
                } else {
                    c
                }
            })
            .collect();
        let err = PublicKeyIdV1::parse_text(&mixed).unwrap_err();
        assert_eq!(err, KeyIdError::ContainsUppercase);
    }

    #[test]
    fn rejects_whitespace_leading() {
        let id = make_test_id();
        let text = format!(" {}", id.to_text());
        let err = PublicKeyIdV1::parse_text(&text).unwrap_err();
        assert_eq!(err, KeyIdError::ContainsWhitespace);
    }

    #[test]
    fn rejects_whitespace_trailing() {
        let id = make_test_id();
        let text = format!("{} ", id.to_text());
        let err = PublicKeyIdV1::parse_text(&text).unwrap_err();
        assert_eq!(err, KeyIdError::ContainsWhitespace);
    }

    #[test]
    fn rejects_padding() {
        let id = make_test_id();
        let text = format!("{}=", id.to_text());
        let err = PublicKeyIdV1::parse_text(&text).unwrap_err();
        assert_eq!(err, KeyIdError::ContainsPadding);
    }

    #[test]
    fn rejects_empty_input() {
        let err = PublicKeyIdV1::parse_text("").unwrap_err();
        assert_eq!(err, KeyIdError::EmptyInput);
    }

    #[test]
    fn rejects_truncated() {
        let err = PublicKeyIdV1::parse_text("pk1:ab").unwrap_err();
        // Truncated input may fail at base32 decode (incomplete group) or
        // at binary length validation; either is correct fail-closed behavior.
        assert!(
            matches!(err, KeyIdError::BinaryLengthMismatch { .. })
                || matches!(err, KeyIdError::Base32DecodeError { .. }),
            "expected BinaryLengthMismatch or Base32DecodeError, got {err:?}"
        );
    }

    #[test]
    fn rejects_unknown_algorithm_tag_binary() {
        let mut binary = [0u8; BINARY_LEN];
        binary[0] = 0xFF; // Unknown tag
        let err = PublicKeyIdV1::from_binary(&binary).unwrap_err();
        assert!(matches!(err, KeyIdError::UnknownAlgorithmTag { tag: 0xFF }));
    }

    #[test]
    fn rejects_binary_wrong_length() {
        let err = PublicKeyIdV1::from_binary(&[0x01; 10]).unwrap_err();
        assert!(matches!(err, KeyIdError::InvalidBinaryLength { got: 10 }));
    }

    #[test]
    fn algorithm_tag_round_trip() {
        let tag = AlgorithmTag::Ed25519;
        assert_eq!(AlgorithmTag::from_byte(tag.to_byte()), Ok(tag));
    }

    #[test]
    fn algorithm_tag_unknown_rejected() {
        assert_eq!(
            AlgorithmTag::from_byte(0x00),
            Err(KeyIdError::UnknownAlgorithmTag { tag: 0x00 })
        );
        assert_eq!(
            AlgorithmTag::from_byte(0x02),
            Err(KeyIdError::UnknownAlgorithmTag { tag: 0x02 })
        );
        assert_eq!(
            AlgorithmTag::from_byte(0xFF),
            Err(KeyIdError::UnknownAlgorithmTag { tag: 0xFF })
        );
    }

    #[test]
    fn display_and_debug() {
        let id = make_test_id();
        let display = format!("{id}");
        let debug = format!("{id:?}");
        assert!(display.starts_with("pk1:"));
        assert!(debug.contains("PublicKeyIdV1"));
        assert!(debug.contains("pk1:"));
    }

    #[test]
    fn from_str_trait() {
        let id = make_test_id();
        let text = id.to_text();
        let parsed: PublicKeyIdV1 = text.parse().unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn different_keys_produce_different_ids() {
        let id1 = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[0xAA; 32]);
        let id2 = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[0xBB; 32]);
        assert_ne!(id1, id2);
    }

    #[test]
    fn same_key_produces_same_id() {
        let key = [0xCC; 32];
        let id1 = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &key);
        let id2 = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &key);
        assert_eq!(id1, id2);
    }

    #[test]
    fn text_form_bounded_length() {
        let id = make_test_id();
        let text = id.to_text();
        assert!(
            text.len() <= crate::identity::MAX_TEXT_LEN,
            "text form length {} exceeds MAX_TEXT_LEN {}",
            text.len(),
            crate::identity::MAX_TEXT_LEN,
        );
    }

    #[test]
    fn key_hash_accessor() {
        let key_bytes = [0xAB; 32];
        let id = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &key_bytes);
        assert_eq!(id.key_hash().len(), 32);
        assert_eq!(id.algorithm(), AlgorithmTag::Ed25519);
    }

    #[test]
    fn rejects_invalid_base32_chars() {
        // '0' is not valid base32 (valid: a-z, 2-7)
        let err =
            PublicKeyIdV1::parse_text("pk1:00000000000000000000000000000000000000000000000000000");
        assert!(err.is_err());
    }

    #[test]
    fn rejects_non_canonical_base32_with_digit_one() {
        // '1' is not in the base32 alphabet
        let err =
            PublicKeyIdV1::parse_text("pk1:1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        assert!(err.is_err());
    }
}
