//! `KeySetIdV1` — canonical identifier for a set of public keys.
//!
//! # Binary Form
//!
//! ```text
//! +------------------+----------------------------+
//! | set_tag          | merkle_root                |
//! | (1 byte)         | (32 bytes, BLAKE3)         |
//! +------------------+----------------------------+
//! ```
//!
//! # Text Form
//!
//! ```text
//! ks1:<base32lower_no_pad(set_tag || merkle_root)>
//! ```
//!
//! # Set Tags
//!
//! | Tag  | Mode       |
//! |------|------------|
//! | 0x01 | Multisig   |
//! | 0x02 | Threshold  |
//!
//! Unknown tags are rejected (fail-closed).
//!
//! # Merkle Root Derivation
//!
//! The merkle root is computed as:
//! ```text
//! blake3("apm2:keyset_id:v1\0" + canonical_sorted_member_key_ids)
//! ```
//!
//! Member key IDs are sorted lexicographically by their raw binary form
//! before hashing, ensuring deterministic derivation regardless of input
//! order.
//!
//! # Contract References
//!
//! - RFC-0020 section 1.7.2a: `KeySetIdV1` quorum/threshold verifier identity
//! - REQ-0007: Canonical key identifier formats

use std::fmt;

use super::{
    BINARY_LEN, HASH_LEN, KeyIdError, PublicKeyIdV1, decode_base32_payload, encode_base32_payload,
    validate_text_common,
};

/// Prefix for `KeySetIdV1` text form.
const PREFIX: &str = "ks1:";

/// Domain separation string for BLAKE3 keyset hashing.
const DOMAIN_SEPARATION: &[u8] = b"apm2:keyset_id:v1\0";

/// Known key-set mode tags.
///
/// Unknown values are rejected at parse time (fail-closed per REQ-0007).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum SetTag {
    /// n-of-n multisig (all members must sign).
    Multisig  = 0x01,
    /// k-of-n threshold (at least `k` members must sign).
    Threshold = 0x02,
}

impl SetTag {
    /// Parse a set tag from a raw byte.
    ///
    /// Returns `Err` for unknown tags (fail-closed).
    pub const fn from_byte(byte: u8) -> Result<Self, KeyIdError> {
        match byte {
            0x01 => Ok(Self::Multisig),
            0x02 => Ok(Self::Threshold),
            other => Err(KeyIdError::UnknownSetTag { tag: other }),
        }
    }

    /// Return the canonical byte representation.
    pub const fn to_byte(self) -> u8 {
        self as u8
    }

    /// Return the human-readable mode name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Multisig => "multisig",
            Self::Threshold => "threshold",
        }
    }
}

impl fmt::Display for SetTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// A canonical identifier for a set of public keys (RFC-0020 section 1.7.2a).
///
/// Instances are guaranteed to contain a valid set tag and exactly 32 bytes
/// of BLAKE3 merkle root. The type is cheaply cloneable (33 bytes inline).
///
/// # Construction
///
/// Use [`KeySetIdV1::from_members`] to derive from a set of `PublicKeyIdV1`
/// member keys, or [`KeySetIdV1::parse_text`] / [`KeySetIdV1::from_binary`]
/// for deserialization.
///
/// # Examples
///
/// ```
/// use apm2_daemon::identity::{
///     AlgorithmTag, KeySetIdV1, PublicKeyIdV1, SetTag,
/// };
///
/// let key1 =
///     PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[0xAA; 32]);
/// let key2 =
///     PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[0xBB; 32]);
///
/// let set_id = KeySetIdV1::from_members(SetTag::Multisig, &[key1, key2]);
///
/// // Round-trip through text form
/// let text = set_id.to_text();
/// let parsed = KeySetIdV1::parse_text(&text).unwrap();
/// assert_eq!(set_id, parsed);
/// ```
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct KeySetIdV1 {
    /// Raw binary form: `set_tag` (1 byte) + `merkle_root` (32 bytes).
    binary: [u8; BINARY_LEN],
}

impl KeySetIdV1 {
    /// Derive a `KeySetIdV1` from a set of member `PublicKeyIdV1` keys.
    ///
    /// Members are sorted lexicographically by their raw binary form before
    /// hashing, ensuring deterministic derivation regardless of input order.
    ///
    /// The merkle root is computed as:
    /// `blake3("apm2:keyset_id:v1\0" + sorted_member_binaries)`
    pub fn from_members(set_tag: SetTag, members: &[PublicKeyIdV1]) -> Self {
        // Sort members by their binary representation for determinism
        let mut sorted_binaries: Vec<[u8; BINARY_LEN]> =
            members.iter().map(PublicKeyIdV1::to_binary).collect();
        sorted_binaries.sort_unstable();

        let mut hasher = blake3::Hasher::new();
        hasher.update(DOMAIN_SEPARATION);
        for member_binary in &sorted_binaries {
            hasher.update(member_binary);
        }
        let root = hasher.finalize();

        let mut binary = [0u8; BINARY_LEN];
        binary[0] = set_tag.to_byte();
        binary[1..].copy_from_slice(root.as_bytes());
        Self { binary }
    }

    /// Parse a `KeySetIdV1` from its canonical text form.
    ///
    /// Enforces:
    /// - Correct `ks1:` prefix
    /// - Strict lowercase base32 without padding
    /// - No whitespace, no mixed case
    /// - Known set tag (fail-closed)
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

        // Validate set tag (fail-closed)
        let _set_tag = SetTag::from_byte(decoded[0])?;

        let mut binary = [0u8; BINARY_LEN];
        binary.copy_from_slice(&decoded);
        Ok(Self { binary })
    }

    /// Construct from raw binary form (1-byte tag + 32-byte merkle root).
    ///
    /// Validates the set tag (fail-closed) and exact length.
    pub fn from_binary(bytes: &[u8]) -> Result<Self, KeyIdError> {
        if bytes.len() != BINARY_LEN {
            return Err(KeyIdError::InvalidBinaryLength { got: bytes.len() });
        }

        // Validate set tag (fail-closed)
        let _set_tag = SetTag::from_byte(bytes[0])?;

        let mut binary = [0u8; BINARY_LEN];
        binary.copy_from_slice(bytes);
        Ok(Self { binary })
    }

    /// Return the canonical text form: `ks1:<base32lower_no_pad>`.
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

    /// Return the set tag.
    pub fn set_tag(&self) -> SetTag {
        // Safe: we validated the tag at construction time.
        SetTag::from_byte(self.binary[0]).expect("set tag was validated at construction")
    }

    /// Return the 32-byte BLAKE3 merkle root.
    pub fn merkle_root(&self) -> &[u8; HASH_LEN] {
        self.binary[1..]
            .try_into()
            .expect("binary is exactly 33 bytes")
    }

    /// Return a reference to the full binary form.
    pub const fn as_bytes(&self) -> &[u8; BINARY_LEN] {
        &self.binary
    }
}

impl fmt::Debug for KeySetIdV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeySetIdV1")
            .field("text", &self.to_text())
            .finish()
    }
}

impl fmt::Display for KeySetIdV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_text())
    }
}

impl std::str::FromStr for KeySetIdV1 {
    type Err = KeyIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse_text(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{AlgorithmTag, PublicKeyIdV1};

    /// Helper: create a test key set with two Ed25519 members.
    fn make_test_keyset() -> KeySetIdV1 {
        let key1 = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[0xAA; 32]);
        let key2 = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[0xBB; 32]);
        KeySetIdV1::from_members(SetTag::Multisig, &[key1, key2])
    }

    #[test]
    fn text_round_trip() {
        let id = make_test_keyset();
        let text = id.to_text();
        let parsed = KeySetIdV1::parse_text(&text).unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn binary_round_trip() {
        let id = make_test_keyset();
        let binary = id.to_binary();
        let from_bin = KeySetIdV1::from_binary(&binary).unwrap();
        assert_eq!(id, from_bin);
    }

    #[test]
    fn text_then_binary_round_trip() {
        let id = make_test_keyset();
        let text = id.to_text();
        let parsed = KeySetIdV1::parse_text(&text).unwrap();
        let binary = parsed.to_binary();
        let from_bin = KeySetIdV1::from_binary(&binary).unwrap();
        assert_eq!(id, from_bin);
    }

    #[test]
    fn member_order_does_not_matter() {
        let key1 = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[0xAA; 32]);
        let key2 = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[0xBB; 32]);

        let id_ab = KeySetIdV1::from_members(SetTag::Multisig, &[key1.clone(), key2.clone()]);
        let id_ba = KeySetIdV1::from_members(SetTag::Multisig, &[key2, key1]);

        assert_eq!(id_ab, id_ba);
    }

    #[test]
    fn different_members_produce_different_ids() {
        let key1 = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[0xAA; 32]);
        let key2 = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[0xBB; 32]);
        let key3 = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[0xCC; 32]);

        let id1 = KeySetIdV1::from_members(SetTag::Multisig, &[key1.clone(), key2]);
        let id2 = KeySetIdV1::from_members(SetTag::Multisig, &[key1, key3]);

        assert_ne!(id1, id2);
    }

    #[test]
    fn different_tags_produce_different_ids() {
        let key1 = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[0xAA; 32]);
        let key2 = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[0xBB; 32]);

        // from_members uses the tag in the binary form but not in hash derivation
        // so the hash is the same but the binary differs at byte 0
        let id_multi = KeySetIdV1::from_members(SetTag::Multisig, &[key1.clone(), key2.clone()]);
        let id_thresh = KeySetIdV1::from_members(SetTag::Threshold, &[key1, key2]);

        assert_ne!(id_multi, id_thresh);
    }

    #[test]
    fn rejects_wrong_prefix() {
        let id = make_test_keyset();
        let text = id.to_text().replacen("ks1:", "pk1:", 1);
        let err = KeySetIdV1::parse_text(&text).unwrap_err();
        assert!(matches!(err, KeyIdError::WrongPrefix { .. }));
    }

    #[test]
    fn rejects_uppercase() {
        let id = make_test_keyset();
        let text = id.to_text().to_ascii_uppercase();
        let err = KeySetIdV1::parse_text(&text).unwrap_err();
        assert_eq!(err, KeyIdError::ContainsUppercase);
    }

    #[test]
    fn rejects_whitespace() {
        let id = make_test_keyset();
        let text = format!(" {}", id.to_text());
        let err = KeySetIdV1::parse_text(&text).unwrap_err();
        assert_eq!(err, KeyIdError::ContainsWhitespace);
    }

    #[test]
    fn rejects_padding() {
        let id = make_test_keyset();
        let text = format!("{}=", id.to_text());
        let err = KeySetIdV1::parse_text(&text).unwrap_err();
        assert_eq!(err, KeyIdError::ContainsPadding);
    }

    #[test]
    fn rejects_empty_input() {
        let err = KeySetIdV1::parse_text("").unwrap_err();
        assert_eq!(err, KeyIdError::EmptyInput);
    }

    #[test]
    fn rejects_truncated() {
        let err = KeySetIdV1::parse_text("ks1:ab").unwrap_err();
        // Truncated input may fail at base32 decode (incomplete group) or
        // at binary length validation; either is correct fail-closed behavior.
        assert!(
            matches!(err, KeyIdError::BinaryLengthMismatch { .. })
                || matches!(err, KeyIdError::Base32DecodeError { .. }),
            "expected BinaryLengthMismatch or Base32DecodeError, got {err:?}"
        );
    }

    #[test]
    fn rejects_unknown_set_tag_binary() {
        let mut binary = [0u8; BINARY_LEN];
        binary[0] = 0xFF; // Unknown tag
        let err = KeySetIdV1::from_binary(&binary).unwrap_err();
        assert!(matches!(err, KeyIdError::UnknownSetTag { tag: 0xFF }));
    }

    #[test]
    fn rejects_binary_wrong_length() {
        let err = KeySetIdV1::from_binary(&[0x01; 10]).unwrap_err();
        assert!(matches!(err, KeyIdError::InvalidBinaryLength { got: 10 }));
    }

    #[test]
    fn set_tag_round_trip() {
        assert_eq!(
            SetTag::from_byte(SetTag::Multisig.to_byte()),
            Ok(SetTag::Multisig)
        );
        assert_eq!(
            SetTag::from_byte(SetTag::Threshold.to_byte()),
            Ok(SetTag::Threshold)
        );
    }

    #[test]
    fn set_tag_unknown_rejected() {
        assert_eq!(
            SetTag::from_byte(0x00),
            Err(KeyIdError::UnknownSetTag { tag: 0x00 })
        );
        assert_eq!(
            SetTag::from_byte(0x03),
            Err(KeyIdError::UnknownSetTag { tag: 0x03 })
        );
        assert_eq!(
            SetTag::from_byte(0xFF),
            Err(KeyIdError::UnknownSetTag { tag: 0xFF })
        );
    }

    #[test]
    fn display_and_debug() {
        let id = make_test_keyset();
        let display = format!("{id}");
        let debug = format!("{id:?}");
        assert!(display.starts_with("ks1:"));
        assert!(debug.contains("KeySetIdV1"));
        assert!(debug.contains("ks1:"));
    }

    #[test]
    fn from_str_trait() {
        let id = make_test_keyset();
        let text = id.to_text();
        let parsed: KeySetIdV1 = text.parse().unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn text_form_bounded_length() {
        let id = make_test_keyset();
        let text = id.to_text();
        assert!(
            text.len() <= crate::identity::MAX_TEXT_LEN,
            "text form length {} exceeds MAX_TEXT_LEN {}",
            text.len(),
            crate::identity::MAX_TEXT_LEN,
        );
    }

    #[test]
    fn accessors_work() {
        let id = make_test_keyset();
        assert_eq!(id.set_tag(), SetTag::Multisig);
        assert_eq!(id.merkle_root().len(), 32);
        assert_eq!(id.as_bytes().len(), 33);
    }
}
