//! Shared fail-closed codec helpers for canonical digest-based ID types.

use super::{
    BINARY_LEN, HASH_LEN, KeyIdError, decode_hex_payload, encode_hex_payload, validate_text_common,
};

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
