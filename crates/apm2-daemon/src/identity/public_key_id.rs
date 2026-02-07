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
//! # Text Form (RFC-0020 section 1.7.5b)
//!
//! ```text
//! pkid:v1:ed25519:blake3:<64-lowercase-hex>
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
//! - RFC-0020 section 1.7.5b: ABNF canonical text forms
//! - REQ-0007: Canonical key identifier formats

use std::fmt;

use super::canonical_digest_id_kit::{IdentityWireKernel, impl_digest_id_fmt};
use super::{
    BINARY_LEN, HASH_LEN, IdentityDerivationSemantics, IdentityParseState,
    IdentityResolutionSemantics, IdentitySemanticCompleteness, IdentitySpec, IdentityTagSemantics,
    IdentityTextTagPolicy, IdentityWireFormSemantics, KeyIdError,
};

/// Prefix for `PublicKeyIdV1` text form (RFC-0020 canonical grammar).
const PREFIX: &str = "pkid:v1:ed25519:blake3:";

/// Domain separation string for BLAKE3 key hashing.
const DOMAIN_SEPARATION: &[u8] = b"apm2:pkid:v1\0";

fn validate_public_key_tag(tag: u8) -> Result<IdentitySemanticCompleteness, KeyIdError> {
    match AlgorithmTag::from_byte(tag) {
        Ok(_) => Ok(IdentitySemanticCompleteness::Resolved),
        Err(err) => Err(err),
    }
}

const PUBLIC_KEY_ID_SPEC: IdentitySpec = IdentitySpec {
    text_prefix: PREFIX,
    wire_form: IdentityWireFormSemantics::Tagged33Only,
    tag_semantics: IdentityTagSemantics::AlgorithmRegistry {
        registry: "AlgorithmTag",
    },
    derivation_semantics: IdentityDerivationSemantics::DomainSeparatedDigest {
        domain_separator: "apm2:pkid:v1\\0 + algorithm + '\\n' + key_bytes",
    },
    resolution_semantics: IdentityResolutionSemantics::SelfContained,
    text_tag_policy: IdentityTextTagPolicy::FixedTag {
        tag: AlgorithmTag::Ed25519 as u8,
    },
    unresolved_compat_tag: None,
    validate_tag: validate_public_key_tag,
};

const WIRE_KERNEL: IdentityWireKernel = IdentityWireKernel::new(&PUBLIC_KEY_ID_SPEC);

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
/// assert!(text.starts_with("pkid:v1:ed25519:blake3:"));
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
    /// The canonical text form is:
    /// `pkid:v1:ed25519:blake3:<64-lowercase-hex>`
    ///
    /// Enforces:
    /// - Correct `pkid:v1:ed25519:blake3:` prefix
    /// - Strict lowercase hex encoding (0-9, a-f)
    /// - No whitespace, no mixed case, no percent-encoding
    /// - Known algorithm tag (fail-closed)
    /// - Exactly 64 hex characters (32 bytes)
    pub fn parse_text(input: &str) -> Result<Self, KeyIdError> {
        Self::parse_text_with_state(input).map(|(id, _)| id)
    }

    /// Parse from canonical text and return explicit parse state metadata.
    pub fn parse_text_with_state(input: &str) -> Result<(Self, IdentityParseState), KeyIdError> {
        let parsed = WIRE_KERNEL.parse_text(input)?;
        Ok((
            Self {
                binary: parsed.binary,
            },
            parsed.state,
        ))
    }

    /// Construct from raw binary form (1-byte tag + 32-byte hash).
    ///
    /// Validates the algorithm tag (fail-closed) and exact length.
    pub fn from_binary(bytes: &[u8]) -> Result<Self, KeyIdError> {
        Self::from_binary_with_state(bytes).map(|(id, _)| id)
    }

    /// Parse from binary and return explicit parse state metadata.
    pub fn from_binary_with_state(bytes: &[u8]) -> Result<(Self, IdentityParseState), KeyIdError> {
        let parsed = WIRE_KERNEL.parse_binary(bytes)?;
        Ok((
            Self {
                binary: parsed.binary,
            },
            parsed.state,
        ))
    }

    /// Return the canonical text form: `pkid:v1:ed25519:blake3:<64-hex>`.
    pub fn to_text(&self) -> String {
        WIRE_KERNEL.to_text(self.key_hash())
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

impl_digest_id_fmt!(PublicKeyIdV1, "PublicKeyIdV1");

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{IdentityParseProvenance, IdentitySemanticCompleteness};

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
    fn parse_state_from_text_is_resolved() {
        let id = make_test_id();
        let (parsed, state) = PublicKeyIdV1::parse_text_with_state(&id.to_text()).unwrap();
        assert_eq!(state.provenance(), IdentityParseProvenance::FromText);
        assert_eq!(state.completeness(), IdentitySemanticCompleteness::Resolved);
        assert_eq!(parsed, id);
    }

    #[test]
    fn parse_state_from_tagged_binary_is_resolved() {
        let id = make_test_id();
        let (parsed, state) = PublicKeyIdV1::from_binary_with_state(&id.to_binary()).unwrap();
        assert_eq!(
            state.provenance(),
            IdentityParseProvenance::FromTaggedBinary
        );
        assert_eq!(state.completeness(), IdentitySemanticCompleteness::Resolved);
        assert_eq!(parsed, id);
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
    fn text_format_matches_rfc() {
        let id = make_test_id();
        let text = id.to_text();
        assert!(
            text.starts_with("pkid:v1:ed25519:blake3:"),
            "text form must start with RFC-0020 prefix, got: {text}"
        );
        // Prefix (23) + 64 hex = 87 total
        assert_eq!(
            text.len(),
            87,
            "text form must be exactly 88 characters, got: {}",
            text.len()
        );
    }

    #[test]
    fn rejects_wrong_prefix() {
        let id = make_test_id();
        let text = id.to_text().replacen("pkid:", "kset:", 1);
        let err = PublicKeyIdV1::parse_text(&text).unwrap_err();
        assert!(matches!(err, KeyIdError::WrongPrefix { .. }));
    }

    #[test]
    fn rejects_old_prefix() {
        // Old "pk1:" format must be rejected
        let err =
            PublicKeyIdV1::parse_text("pk1:ahtv5ga73ykn7cu45wlc6gwhlpiqvtd5kypkya765o7jebqtpp7u2")
                .unwrap_err();
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
        // Capitalize a hex character in the payload
        let mut chars: Vec<char> = text.chars().collect();
        // Find first lowercase hex char after prefix
        for ch in &mut chars[PREFIX.len()..] {
            if ch.is_ascii_lowercase() {
                *ch = ch.to_ascii_uppercase();
                break;
            }
        }
        let mixed: String = chars.into_iter().collect();
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
        let err = PublicKeyIdV1::parse_text("pkid:v1:ed25519:blake3:ab").unwrap_err();
        assert!(
            matches!(err, KeyIdError::HexLengthMismatch { .. }),
            "expected HexLengthMismatch, got {err:?}"
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
        assert!(display.starts_with("pkid:v1:ed25519:blake3:"));
        assert!(debug.contains("PublicKeyIdV1"));
        assert!(debug.contains("pkid:v1:ed25519:blake3:"));
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
    fn rejects_invalid_hex_chars() {
        // 'g' is not valid lowercase hex
        let bad = format!("pkid:v1:ed25519:blake3:{}", "g".repeat(64));
        let err = PublicKeyIdV1::parse_text(&bad);
        assert!(err.is_err());
    }

    #[test]
    fn rejects_percent_encoded() {
        let err = PublicKeyIdV1::parse_text(
            "pkid%3av1%3aed25519%3ablake3%3a0000000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap_err();
        assert_eq!(err, KeyIdError::ContainsPercentEncoding);
    }

    #[test]
    fn rejects_non_ascii_unicode() {
        // Fullwidth colon U+FF1A
        let err = PublicKeyIdV1::parse_text(
            "pkid\u{FF1A}v1:ed25519:blake3:0000000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap_err();
        assert_eq!(err, KeyIdError::ContainsNonAscii);
    }

    /// Regression test: multi-byte Unicode at the prefix boundary must return
    /// `Err`, never panic via byte-index slicing on a non-char boundary.
    #[test]
    fn unicode_prefix_boundary_does_not_panic() {
        let inputs = [
            "\u{00E9}\u{00E9}xx",               // 2-byte chars at positions 0..4
            "\u{1F600}garbage",                 // 4-byte emoji at position 0
            "p\u{00E9}1:stuff",                 // multi-byte char overlapping prefix boundary
            "\u{0301}\u{0301}\u{0301}\u{0301}", // combining accents
        ];
        for input in &inputs {
            let result = PublicKeyIdV1::parse_text(input);
            assert!(
                result.is_err(),
                "expected Err for malformed Unicode input {input:?}, got Ok"
            );
        }
    }
}
