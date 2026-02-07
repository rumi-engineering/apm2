//! Canonical identity identifiers for the Holonic Substrate Interface
//! (RFC-0020).
//!
//! This module implements canonical binary and text forms for:
//! - [`PublicKeyIdV1`]
//! - [`KeySetIdV1`]
//! - [`CellIdV1`]
//! - [`HolonIdV1`]
//! - [`CellCertificateV1`]
//! - [`HolonCertificateV1`]
//! - [`SessionKeyDelegationV1`]
//! - [`HolonDirectoryHeadV1`]
//! - [`DirectoryProofV1`]
//! - [`IdentityProofV1`]
//!
//! # V1 Canonical Text Form Grammar (RFC-0020 section 1.7.5b)
//!
//! The following grammar defines the **v1 canonical text form** for key
//! identifiers. This is the authoritative grammar for this implementation;
//! future versions may extend it with additional prefixes or tag values while
//! preserving backward compatibility.
//!
//! ```text
//! identifier    ::= public_key_id | keyset_id | cell_id | holon_id
//! public_key_id ::= "pkid:v1:ed25519:blake3:" hash64
//! keyset_id     ::= "kset:v1:blake3:" hash64
//! cell_id       ::= "cell:v1:blake3:" hash64
//! holon_id      ::= "holon:v1:blake3:" hash64
//! hash64        ::= 64 * HEXLOWER          ; 64 lowercase hex characters
//! HEXLOWER      ::= [0-9a-f]
//! ```
//!
//! The binary form (33 bytes) is structured as:
//!
//! ```text
//! binary_form  ::= tag_byte hash_bytes
//! tag_byte     ::= OCTET              ; 1 byte, must be a known tag value
//! hash_bytes   ::= 32*OCTET           ; 32-byte BLAKE3 digest
//! ```
//!
//! ## Tag Byte Values
//!
//! | Text prefix              | Tag  | Meaning            |
//! |--------------------------|------|--------------------|
//! | `pkid:v1:ed25519:blake3` | 0x01 | Ed25519            |
//! | `kset:v1:blake3`         | 0x01 | Multisig (n-of-n)  |
//! | `kset:v1:blake3`         | 0x02 | Threshold (k-of-n) |
//! | `cell:v1:blake3`         | 0x01 | Cell identity V1   |
//! | `holon:v1:blake3`        | 0x01 | Holon identity V1  |
//!
//! Unknown tag values MUST be rejected (fail-closed per REQ-0007).
//!
//! ## Derivation Details
//!
//! **`PublicKeyIdV1` hash:**
//!
//! ```text
//! blake3("apm2:pkid:v1\0" + algorithm_name + "\n" + key_bytes)
//! ```
//!
//! **`KeySetIdV1` hash (full descriptor):**
//!
//! ```text
//! blake3("apm2:keyset_id:v1\0" + canonical_bytes(KeySetDescriptorV1))
//! ```
//!
//! Where `canonical_bytes(KeySetDescriptorV1)` is:
//! ```text
//! key_algorithm + "\n" + mode_name + "\n" + threshold_k (4-byte LE) + "\n"
//!   + sorted_member_binaries
//!   + [optional: "\n" + weights as 8-byte LE values]
//! ```
//!
//! **`CellIdV1` hash:**
//!
//! ```text
//! blake3("apm2:cell_id:v1\n" + ledger_genesis_hash_bytes
//!        + genesis_policy_root_public_key_id_bytes)
//! ```
//!
//! **`HolonIdV1` hash:**
//!
//! ```text
//! blake3("apm2:holon_id:v1\0" + cell_id_bytes
//!        + holon_genesis_public_key_id_bytes)
//! ```
//!
//! - Lowercase hex encoding (0-9, a-f), exactly 64 characters for 32 bytes
//!
//! # Security Invariants
//!
//! - **Fail-closed parsing**: unknown algorithm/set tags are rejected, never
//!   defaulted.
//! - **Strict canonical form**: mixed case, whitespace, padding characters,
//!   percent-encoded forms, and Unicode normalization variants are all
//!   rejected.
//! - **Bounded length**: text forms are bounded to [`MAX_TEXT_LEN`] characters.
//! - **Lossless round-trip**: binary-to-text-to-binary produces identical
//!   bytes.
//!
//! ## Abstraction Boundary: `CanonicalDigestIdKit`
//!
//! `CanonicalDigestIdKit` centralizes shared fail-closed codec steps for
//! digest-first IDs:
//! - canonical text validation + prefix stripping + lowercase hex decode
//! - binary length + tag-gate parsing
//! - canonical text serialization (`prefix + 64-lowercase-hex`)
//!
//! The kit intentionally excludes domain-specific derivation and semantic
//! validation (algorithm policy, set-tag semantics, descriptor invariants,
//! genesis commitments). Those checks remain in each ID type.
//!
//! # Contract References
//!
//! - RFC-0020 section 1.7.2: `PublicKeyIdV1` canonical key identifiers
//! - RFC-0020 section 1.7.2a: `KeySetIdV1` quorum/threshold verifier identity
//! - RFC-0020 section 1.7.3: `CellIdV1`
//! - RFC-0020 section 1.7.4: `HolonIdV1`
//! - RFC-0020 section 1.7.5b: ABNF for canonical text forms
//! - REQ-0007: Canonical key identifier formats
//! - EVID-0007: Canonical key identifier conformance evidence
//! - REQ-0008: Genesis artifacts are hash-addressed in CAS
//! - EVID-0008: Genesis artifact CAS conformance evidence
//! - EVID-0303: Rollout phase S0.75 evidence

mod canonical_digest_id_kit;
mod cell_id;
mod certificate;
pub(crate) mod directory_proof;
mod holon_id;
mod keyset_id;
mod public_key_id;
mod session_delegation;

pub mod conformance;

pub use cell_id::{CellGenesisV1, CellIdV1, PolicyRootId};
pub use certificate::{
    CellCertificateV1, CertificateError, HolonCertificateV1, RevocationPointer, validate_key_roles,
};
pub use directory_proof::{
    DirectoryEntryStatus, DirectoryKindV1, DirectoryProofKind, DirectoryProofKindV1,
    DirectoryProofV1, HolonDirectoryHeadV1, IdentityProofError, IdentityProofProfileV1,
    IdentityProofV1, LedgerAnchorV1, MAX_DIRECTORY_HEAD_BYTES, MAX_DIRECTORY_PROOF_BYTES,
    MAX_DIRECTORY_SIBLINGS, MAX_HASH_OPS_PER_MEMBERSHIP_PROOF_10E12, MAX_IDENTITY_PROOF_BYTES,
    MAX_IDENTITY_PROOF_PROFILE_BYTES, MAX_SMT_DEPTH, MIN_SMT_DEPTH_10E12, SiblingNode,
    VerifierCostTarget, check_directory_kind_compatibility, default_empty_value_hash,
    derive_directory_key, resolve_known_profile, validate_identity_proof_hash,
};
pub use holon_id::{HolonGenesisV1, HolonIdV1, HolonPurpose};
pub use keyset_id::{KeySetIdV1, SetTag};
pub use public_key_id::{AlgorithmTag, PublicKeyIdV1};
pub use session_delegation::{
    MAX_SESSION_DELEGATION_TICKS, SessionKeyDelegationV1, UncheckedSessionDelegation,
};
use thiserror::Error;

/// Maximum length of any canonical text form (bytes).
///
/// `pkid:v1:ed25519:blake3:` (24 bytes) + 64 hex chars = 88 characters.
/// `kset:v1:blake3:` (16 bytes) + 64 hex chars = 80 characters.
/// `cell:v1:blake3:` (15 bytes) + 64 hex chars = 79 characters.
/// `holon:v1:blake3:` (16 bytes) + 64 hex chars = 80 characters.
/// We set the bound to 96 to allow modest future growth while still
/// preventing unbounded input.
pub const MAX_TEXT_LEN: usize = 96;

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

    /// Wrong prefix for the expected type (e.g. `kset:` when `pkid:` expected).
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

    /// Hex decoding failed.
    #[error("hex decode error: {reason}")]
    HexDecodeError {
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

    /// Unknown identity version tag byte (fail-closed).
    #[error("unknown version tag: 0x{tag:02x}")]
    UnknownVersionTag {
        /// The unrecognized version tag byte.
        tag: u8,
    },

    /// Input contains characters outside the hex lowercase alphabet.
    #[error("input contains invalid hex characters")]
    InvalidHexCharacters,

    /// Input contains percent-encoded characters (rejected per REQ-0007).
    #[error("input contains percent-encoded characters")]
    ContainsPercentEncoding,

    /// Input contains non-ASCII characters (rejected per REQ-0007).
    #[error("input contains non-ASCII characters")]
    ContainsNonAscii,

    /// Input contains ASCII control characters (0x00-0x1F, 0x7F) that are
    /// not in the printable ASCII range (0x21-0x7E).
    #[error("input contains ASCII control characters")]
    ContainsControlCharacter,

    /// Hex payload has wrong length (expected exactly 64 hex characters).
    #[error("hex payload length mismatch: expected 64, got {got}")]
    HexLengthMismatch {
        /// Actual hex payload length.
        got: usize,
    },

    /// Descriptor invariants violated (e.g. empty members, bad threshold).
    #[error("invalid descriptor: {reason}")]
    InvalidDescriptor {
        /// Description of the invariant violation.
        reason: String,
    },
}

/// Validate common text-form invariants before type-specific parsing.
///
/// Checks:
/// 1. Non-empty
/// 2. ASCII-only (rejects Unicode normalization variants)
/// 3. No percent-encoding tricks
/// 4. No leading/trailing whitespace
/// 5. No interior whitespace
/// 6. Bounded length
/// 7. No uppercase letters (strict lowercase)
fn validate_text_common(input: &str) -> Result<(), KeyIdError> {
    if input.is_empty() {
        return Err(KeyIdError::EmptyInput);
    }

    // Reject non-ASCII (catches Unicode normalization variants, fullwidth
    // colons U+FF1A, combining characters, etc.)
    if !input.is_ascii() {
        return Err(KeyIdError::ContainsNonAscii);
    }

    // Reject percent-encoded forms (e.g. `pkid%3av1%3a...`)
    if input.contains('%') {
        return Err(KeyIdError::ContainsPercentEncoding);
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

    // Reject padding characters (legacy base32 compat check)
    if input.contains('=') {
        return Err(KeyIdError::ContainsPadding);
    }

    Ok(())
}

/// Decode a 64-character lowercase hex payload into 32 bytes.
///
/// Validates that the payload is exactly 64 characters and contains only
/// lowercase hex digits (0-9, a-f). Returns the decoded 32-byte hash.
fn decode_hex_payload(hex_str: &str) -> Result<[u8; HASH_LEN], KeyIdError> {
    // Validate length
    if hex_str.len() != 64 {
        return Err(KeyIdError::HexLengthMismatch { got: hex_str.len() });
    }

    // Validate characters are strictly lowercase hex (0-9, a-f)
    for ch in hex_str.chars() {
        if !matches!(ch, '0'..='9' | 'a'..='f') {
            return Err(KeyIdError::InvalidHexCharacters);
        }
    }

    let decoded = hex::decode(hex_str).map_err(|e| KeyIdError::HexDecodeError {
        reason: e.to_string(),
    })?;

    let mut result = [0u8; HASH_LEN];
    result.copy_from_slice(&decoded);
    Ok(result)
}

/// Encode 32 bytes as 64 lowercase hex characters.
fn encode_hex_payload(data: &[u8; HASH_LEN]) -> String {
    hex::encode(data)
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
            validate_text_common(" pkid:v1:ed25519:blake3:abc"),
            Err(KeyIdError::ContainsWhitespace)
        );
    }

    #[test]
    fn validate_text_rejects_trailing_whitespace() {
        assert_eq!(
            validate_text_common("pkid:v1:ed25519:blake3:abc "),
            Err(KeyIdError::ContainsWhitespace)
        );
    }

    #[test]
    fn validate_text_rejects_interior_whitespace() {
        assert_eq!(
            validate_text_common("pkid:v1:\ted25519:blake3:abc"),
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
            validate_text_common("PKID:V1:ED25519:BLAKE3:abc"),
            Err(KeyIdError::ContainsUppercase)
        );
    }

    #[test]
    fn validate_text_rejects_padding() {
        assert_eq!(
            validate_text_common("pkid:v1:ed25519:blake3:abc="),
            Err(KeyIdError::ContainsPadding)
        );
    }

    #[test]
    fn validate_text_rejects_percent_encoding() {
        assert_eq!(
            validate_text_common("pkid%3av1%3aed25519%3ablake3%3aabc"),
            Err(KeyIdError::ContainsPercentEncoding)
        );
    }

    #[test]
    fn validate_text_rejects_non_ascii() {
        // Fullwidth colon U+FF1A
        assert_eq!(
            validate_text_common("pkid\u{FF1A}v1:ed25519:blake3:abc"),
            Err(KeyIdError::ContainsNonAscii)
        );
    }

    #[test]
    fn validate_text_accepts_valid() {
        assert!(validate_text_common("pkid:v1:ed25519:blake3:abcdef0123456789").is_ok());
    }

    #[test]
    fn hex_round_trip() {
        let data = [0x01u8; 32];
        let encoded = encode_hex_payload(&data);
        let decoded = decode_hex_payload(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn hex_decode_rejects_uppercase() {
        let upper = "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789";
        assert!(matches!(
            decode_hex_payload(upper),
            Err(KeyIdError::InvalidHexCharacters)
        ));
    }

    #[test]
    fn hex_decode_rejects_wrong_length() {
        assert!(matches!(
            decode_hex_payload("abcd"),
            Err(KeyIdError::HexLengthMismatch { got: 4 })
        ));
    }
}
