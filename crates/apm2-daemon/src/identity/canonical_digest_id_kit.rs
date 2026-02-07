//! Shared fail-closed codec helpers for canonical digest-based ID types.
//!
//! # Macros
//!
//! This module also provides declarative macros that eliminate boilerplate
//! trait implementations across the four digest-based ID types:
//!
//! * [`impl_digest_id_fmt!`] -- `Display`, `FromStr`, and `Debug` impls that
//!   delegate to the type's `to_text()` and `parse_text()` methods.
//! * [`impl_version_tagged_digest_id!`] -- full method body for ID types whose
//!   binary form is a single fixed version tag (`0x01`) plus 32-byte hash,
//!   covering `parse_text`, `from_binary`, `to_text`, `to_binary`,
//!   `version_tag`, `as_bytes`, and the named hash accessor.

use super::{
    BINARY_LEN, HASH_LEN, KeyIdError, decode_hex_payload, encode_hex_payload, validate_text_common,
};

// ---------------------------------------------------------------------------
// Declarative macros for identical trait impls
// ---------------------------------------------------------------------------

/// Implement `Display`, `FromStr`, and `Debug` for a digest-based ID type.
///
/// Requirements on `$type`:
/// - `fn to_text(&self) -> String`
/// - `fn parse_text(input: &str) -> Result<Self, KeyIdError>`
///
/// The `$debug_name` argument is the struct name string used in the `Debug`
/// output (e.g. `"CellIdV1"`).
macro_rules! impl_digest_id_fmt {
    ($type:ty, $debug_name:expr) => {
        impl std::fmt::Display for $type {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(&self.to_text())
            }
        }

        impl std::str::FromStr for $type {
            type Err = $crate::identity::KeyIdError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Self::parse_text(s)
            }
        }

        impl std::fmt::Debug for $type {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_struct($debug_name)
                    .field("text", &self.to_text())
                    .finish()
            }
        }
    };
}

/// Implement the full method body for a version-tagged digest ID type.
///
/// This covers ID types whose binary form is `VERSION_TAG_V1 (0x01) + 32-byte
/// hash` and whose text form is `PREFIX + 64-lowercase-hex`. The macro emits:
///
/// - `parse_text(input) -> Result<Self, KeyIdError>`
/// - `from_binary(bytes) -> Result<Self, KeyIdError>`
/// - `to_text() -> String`
/// - `to_binary() -> [u8; BINARY_LEN]`
/// - `$hash_accessor() -> &[u8; HASH_LEN]` (named by caller, e.g. `cell_hash`)
/// - `version_tag() -> u8`
/// - `as_bytes() -> &[u8; BINARY_LEN]`
///
/// The caller must provide:
/// - `$codec`: a `CanonicalDigestIdKit` const for the type.
/// - `$version_tag`: the expected version tag byte (e.g. `0x01`).
/// - `$hash_accessor`: identifier for the public hash accessor method.
macro_rules! impl_version_tagged_digest_id {
    ($codec:expr, $version_tag:expr, $hash_accessor:ident) => {
        /// Parse from canonical text form.
        pub fn parse_text(input: &str) -> Result<Self, $crate::identity::KeyIdError> {
            let binary = $codec.parse_text_binary_with_tag(input, $version_tag)?;
            Ok(Self { binary })
        }

        /// Construct from binary form (`version_tag + 32-byte hash`).
        pub fn from_binary(bytes: &[u8]) -> Result<Self, $crate::identity::KeyIdError> {
            let binary = $codec.parse_binary_exact(bytes, |tag| {
                if tag == $version_tag {
                    Ok(())
                } else {
                    Err($crate::identity::KeyIdError::UnknownVersionTag { tag })
                }
            })?;
            Ok(Self { binary })
        }

        /// Return canonical text form.
        pub fn to_text(&self) -> String {
            $codec.to_text(self.$hash_accessor())
        }

        /// Return binary form (`version_tag + hash`).
        pub const fn to_binary(&self) -> [u8; $crate::identity::BINARY_LEN] {
            self.binary
        }

        /// Return the 32-byte hash portion (without version tag).
        pub fn $hash_accessor(&self) -> &[u8; $crate::identity::HASH_LEN] {
            self.binary[1..]
                .try_into()
                .expect("binary is exactly 33 bytes")
        }

        /// Return the version tag.
        pub const fn version_tag(&self) -> u8 {
            self.binary[0]
        }

        /// Return a reference to the full binary bytes.
        pub const fn as_bytes(&self) -> &[u8; $crate::identity::BINARY_LEN] {
            &self.binary
        }
    };
}

pub(super) use {impl_digest_id_fmt, impl_version_tagged_digest_id};

/// Reusable codec helper for identifiers whose canonical text form is:
/// `"<prefix><64-lowercase-hex>"` and whose binary form is `tag + 32-byte
/// hash`.
#[derive(Debug, Clone, Copy)]
pub(super) struct CanonicalDigestIdKit {
    prefix: &'static str,
}

impl CanonicalDigestIdKit {
    /// Build a codec helper for a specific canonical text prefix.
    pub(super) const fn new(prefix: &'static str) -> Self {
        Self { prefix }
    }

    /// Parse canonical text and return the 32-byte digest payload.
    pub(super) fn parse_text_hash(self, input: &str) -> Result<[u8; HASH_LEN], KeyIdError> {
        validate_text_common(input)?;

        let hex_payload = input.strip_prefix(self.prefix).ok_or_else(|| {
            let got = input
                .get(..self.prefix.len())
                .map_or_else(|| input.to_string(), str::to_string);
            KeyIdError::WrongPrefix {
                expected: self.prefix,
                got,
            }
        })?;

        decode_hex_payload(hex_payload)
    }

    /// Parse canonical text and materialize binary bytes with a fixed tag.
    pub(super) fn parse_text_binary_with_tag(
        self,
        input: &str,
        tag: u8,
    ) -> Result<[u8; BINARY_LEN], KeyIdError> {
        let hash = self.parse_text_hash(input)?;
        Ok(Self::binary_from_tag_and_hash(tag, hash))
    }

    /// Parse canonical binary form (`tag + hash`) with caller-provided
    /// fail-closed tag validation.
    #[allow(clippy::unused_self)] // method syntax mirrors other codec helpers
    pub(super) fn parse_binary_exact(
        self,
        bytes: &[u8],
        validate_tag: impl FnOnce(u8) -> Result<(), KeyIdError>,
    ) -> Result<[u8; BINARY_LEN], KeyIdError> {
        if bytes.len() != BINARY_LEN {
            return Err(KeyIdError::InvalidBinaryLength { got: bytes.len() });
        }
        validate_tag(bytes[0])?;

        let mut binary = [0u8; BINARY_LEN];
        binary.copy_from_slice(bytes);
        Ok(binary)
    }

    /// Render canonical text as `prefix + 64-lowercase-hex`.
    pub(super) fn to_text(self, hash: &[u8; HASH_LEN]) -> String {
        let mut out = String::with_capacity(self.prefix.len() + 64);
        out.push_str(self.prefix);
        out.push_str(&encode_hex_payload(hash));
        out
    }

    /// Build `tag + hash` binary bytes.
    pub(super) fn binary_from_tag_and_hash(tag: u8, hash: [u8; HASH_LEN]) -> [u8; BINARY_LEN] {
        let mut binary = [0u8; BINARY_LEN];
        binary[0] = tag;
        binary[1..].copy_from_slice(&hash);
        binary
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PREFIX: &str = "test:v1:blake3:";
    const KIT: CanonicalDigestIdKit = CanonicalDigestIdKit::new(PREFIX);

    fn valid_text() -> String {
        format!("{PREFIX}{}", "ab".repeat(32))
    }

    #[test]
    fn parse_text_hash_round_trip() {
        let text = valid_text();
        let hash = KIT.parse_text_hash(&text).unwrap();
        assert_eq!(KIT.to_text(&hash), text);
    }

    #[test]
    fn parse_text_binary_with_tag_sets_tag() {
        let binary = KIT.parse_text_binary_with_tag(&valid_text(), 0x42).unwrap();
        assert_eq!(binary[0], 0x42);
    }

    #[test]
    fn parse_binary_exact_runs_tag_gate() {
        let hash = [0x11; HASH_LEN];
        let binary = CanonicalDigestIdKit::binary_from_tag_and_hash(0x01, hash);
        let parsed = KIT
            .parse_binary_exact(&binary, |tag| {
                if tag == 0x01 {
                    Ok(())
                } else {
                    Err(KeyIdError::UnknownVersionTag { tag })
                }
            })
            .unwrap();
        assert_eq!(parsed, binary);
    }

    #[test]
    fn parse_binary_exact_rejects_wrong_length() {
        let err = KIT.parse_binary_exact(&[0x01; 32], |_| Ok(())).unwrap_err();
        assert_eq!(err, KeyIdError::InvalidBinaryLength { got: 32 });
    }
}
