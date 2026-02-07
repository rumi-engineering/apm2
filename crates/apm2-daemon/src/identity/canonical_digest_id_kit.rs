//! Shared fail-closed wire kernel for canonical digest-based identity types.
//!
//! # Macros
//!
//! This module also provides declarative macros that remove repeated
//! trait/method boilerplate:
//!
//! - [`impl_digest_id_fmt!`] for `Display` / `FromStr` / `Debug`.
//! - [`impl_version_tagged_digest_id!`] for types whose wire contract is
//!   fixed-version `Tagged33` only.

use super::{
    BINARY_LEN, HASH_LEN, IdentityParseProvenance, IdentityParseState,
    IdentitySemanticCompleteness, IdentitySpec, IdentityTextTagPolicy, IdentityWireVariant,
    KeyIdError, decode_hex_payload, encode_hex_payload, validate_text_common,
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

/// Implement the full method body for a fixed-version `Tagged33` digest ID.
///
/// The caller must provide:
/// - `$kernel`: an `IdentityWireKernel` configured with a fixed-tag spec.
/// - `$version_tag`: expected version-tag byte.
/// - `$hash_accessor`: identifier for the public hash accessor method.
macro_rules! impl_version_tagged_digest_id {
    ($kernel:expr, $version_tag:expr, $hash_accessor:ident) => {
        /// Parse from canonical text form.
        pub fn parse_text(input: &str) -> Result<Self, $crate::identity::KeyIdError> {
            let parsed = $kernel.parse_text(input)?;
            if parsed.state.completeness()
                != $crate::identity::IdentitySemanticCompleteness::Resolved
            {
                return Err($crate::identity::KeyIdError::InvalidDescriptor {
                    reason: "fixed-version identity parsed as unresolved".to_string(),
                });
            }
            debug_assert_eq!(parsed.binary[0], $version_tag);
            Ok(Self {
                binary: parsed.binary,
            })
        }

        /// Construct from binary form (`version_tag + 32-byte hash`).
        pub fn from_binary(bytes: &[u8]) -> Result<Self, $crate::identity::KeyIdError> {
            let parsed = $kernel.parse_binary(bytes)?;
            if parsed.state.completeness()
                != $crate::identity::IdentitySemanticCompleteness::Resolved
            {
                return Err($crate::identity::KeyIdError::InvalidDescriptor {
                    reason: "fixed-version identity parsed as unresolved".to_string(),
                });
            }
            debug_assert_eq!(parsed.binary[0], $version_tag);
            Ok(Self {
                binary: parsed.binary,
            })
        }

        /// Return canonical text form.
        pub fn to_text(&self) -> String {
            $kernel.to_text(self.$hash_accessor())
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

/// Parsed wire payload from [`IdentityWireKernel`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct IdentityWireParse {
    /// Materialized `Tagged33` bytes. For hash-only inputs this uses the
    /// spec's `unresolved_compat_tag`.
    pub(super) binary: [u8; BINARY_LEN],
    /// Digest payload.
    pub(super) hash: [u8; HASH_LEN],
    /// Admitted binary wire variant.
    pub(super) wire_variant: IdentityWireVariant,
    /// Parse provenance and semantic completeness.
    pub(super) state: IdentityParseState,
}

/// Shared fail-closed wire kernel for digest-based identities.
#[derive(Debug, Clone, Copy)]
pub(super) struct IdentityWireKernel {
    spec: &'static IdentitySpec,
}

impl IdentityWireKernel {
    /// Build a wire kernel for a specific identity spec.
    pub(super) const fn new(spec: &'static IdentitySpec) -> Self {
        Self { spec }
    }

    /// Parse canonical text and return the 32-byte digest payload.
    pub(super) fn parse_text_hash(self, input: &str) -> Result<[u8; HASH_LEN], KeyIdError> {
        validate_text_common(input)?;

        let hex_payload = input.strip_prefix(self.spec.text_prefix).ok_or_else(|| {
            let got = input
                .get(..self.spec.text_prefix.len())
                .map_or_else(|| input.to_string(), str::to_string);
            KeyIdError::WrongPrefix {
                expected: self.spec.text_prefix,
                got,
            }
        })?;

        decode_hex_payload(hex_payload)
    }

    /// Parse canonical text using the configured text-tag policy.
    pub(super) fn parse_text(self, input: &str) -> Result<IdentityWireParse, KeyIdError> {
        let hash = self.parse_text_hash(input)?;
        let (tag, completeness) = match self.spec.text_tag_policy {
            IdentityTextTagPolicy::FixedTag { tag } => {
                (tag, IdentitySemanticCompleteness::Resolved)
            },
            IdentityTextTagPolicy::Omitted => (
                self.unresolved_compat_tag()?,
                IdentitySemanticCompleteness::Unresolved,
            ),
        };
        Ok(IdentityWireParse {
            binary: Self::binary_from_tag_and_hash(tag, hash),
            hash,
            wire_variant: IdentityWireVariant::Tagged33,
            state: IdentityParseState::new(IdentityParseProvenance::FromText, completeness),
        })
    }

    /// Parse binary input according to the configured wire/tag contracts.
    pub(super) fn parse_binary(self, bytes: &[u8]) -> Result<IdentityWireParse, KeyIdError> {
        match bytes.len() {
            BINARY_LEN => {
                if !self.spec.wire_form.allows(IdentityWireVariant::Tagged33) {
                    return Err(KeyIdError::InvalidDescriptor {
                        reason: "tagged-33 binary form is not admissible for this identity"
                            .to_string(),
                    });
                }

                let mut binary = [0u8; BINARY_LEN];
                binary.copy_from_slice(bytes);

                let completeness = (self.spec.validate_tag)(binary[0])?;
                let mut hash = [0u8; HASH_LEN];
                hash.copy_from_slice(&binary[1..]);

                Ok(IdentityWireParse {
                    binary,
                    hash,
                    wire_variant: IdentityWireVariant::Tagged33,
                    state: IdentityParseState::new(
                        IdentityParseProvenance::FromTaggedBinary,
                        completeness,
                    ),
                })
            },
            HASH_LEN => {
                if !self.spec.wire_form.allows(IdentityWireVariant::Hash32) {
                    return Err(KeyIdError::InvalidBinaryLength { got: bytes.len() });
                }

                let mut hash = [0u8; HASH_LEN];
                hash.copy_from_slice(bytes);
                let compat_tag = self.unresolved_compat_tag()?;

                Ok(IdentityWireParse {
                    binary: Self::binary_from_tag_and_hash(compat_tag, hash),
                    hash,
                    wire_variant: IdentityWireVariant::Hash32,
                    state: IdentityParseState::new(
                        IdentityParseProvenance::FromHashOnlyBinary,
                        IdentitySemanticCompleteness::Unresolved,
                    ),
                })
            },
            _ => Err(KeyIdError::InvalidBinaryLength { got: bytes.len() }),
        }
    }

    /// Render canonical text as `prefix + 64-lowercase-hex`.
    pub(super) fn to_text(self, hash: &[u8; HASH_LEN]) -> String {
        let mut out = String::with_capacity(self.spec.text_prefix.len() + 64);
        out.push_str(self.spec.text_prefix);
        out.push_str(&encode_hex_payload(hash));
        out
    }

    /// Build `tag + hash` bytes.
    pub(super) fn binary_from_tag_and_hash(tag: u8, hash: [u8; HASH_LEN]) -> [u8; BINARY_LEN] {
        let mut binary = [0u8; BINARY_LEN];
        binary[0] = tag;
        binary[1..].copy_from_slice(&hash);
        binary
    }

    fn unresolved_compat_tag(self) -> Result<u8, KeyIdError> {
        self.spec
            .unresolved_compat_tag
            .ok_or_else(|| KeyIdError::InvalidDescriptor {
                reason:
                    "identity spec requires unresolved compatibility tag but none is configured"
                        .to_string(),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{
        IdentityDerivationSemantics, IdentityResolutionSemantics, IdentityTagSemantics,
        IdentityWireFormSemantics,
    };

    const PREFIX_FIXED: &str = "test:v1:blake3:";
    const PREFIX_DIGEST_FIRST: &str = "digest:v1:blake3:";

    const fn validate_fixed_tag(tag: u8) -> Result<IdentitySemanticCompleteness, KeyIdError> {
        if tag == 0x42 {
            Ok(IdentitySemanticCompleteness::Resolved)
        } else {
            Err(KeyIdError::UnknownVersionTag { tag })
        }
    }

    const fn validate_set_mode(tag: u8) -> Result<IdentitySemanticCompleteness, KeyIdError> {
        match tag {
            0x01 | 0x02 => Ok(IdentitySemanticCompleteness::Resolved),
            0x00 => Ok(IdentitySemanticCompleteness::Unresolved),
            other => Err(KeyIdError::UnknownSetTag { tag: other }),
        }
    }

    const FIXED_SPEC: IdentitySpec = IdentitySpec {
        text_prefix: PREFIX_FIXED,
        wire_form: IdentityWireFormSemantics::Tagged33Only,
        tag_semantics: IdentityTagSemantics::FixedVersionTag { tag: 0x42 },
        derivation_semantics: IdentityDerivationSemantics::DomainSeparatedDigest {
            domain_separator: "test:fixed",
        },
        resolution_semantics: IdentityResolutionSemantics::SelfContained,
        text_tag_policy: IdentityTextTagPolicy::FixedTag { tag: 0x42 },
        unresolved_compat_tag: None,
        validate_tag: validate_fixed_tag,
    };

    const DIGEST_FIRST_SPEC: IdentitySpec = IdentitySpec {
        text_prefix: PREFIX_DIGEST_FIRST,
        wire_form: IdentityWireFormSemantics::Tagged33AndHash32,
        tag_semantics: IdentityTagSemantics::SetMode {
            text_omits_mode: true,
            unresolved_compat_tag: Some(0x00),
        },
        derivation_semantics: IdentityDerivationSemantics::DescriptorDigest {
            domain_separator: "test:digest-first",
            descriptor: "TestDescriptor",
        },
        resolution_semantics: IdentityResolutionSemantics::DigestFirstResolver {
            contract: "test-resolver",
        },
        text_tag_policy: IdentityTextTagPolicy::Omitted,
        unresolved_compat_tag: Some(0x00),
        validate_tag: validate_set_mode,
    };

    const FIXED_KERNEL: IdentityWireKernel = IdentityWireKernel::new(&FIXED_SPEC);
    const DIGEST_FIRST_KERNEL: IdentityWireKernel = IdentityWireKernel::new(&DIGEST_FIRST_SPEC);

    fn valid_text(prefix: &str) -> String {
        format!("{prefix}{}", "ab".repeat(32))
    }

    #[test]
    fn parse_text_hash_round_trip() {
        let text = valid_text(PREFIX_FIXED);
        let hash = FIXED_KERNEL.parse_text_hash(&text).unwrap();
        assert_eq!(FIXED_KERNEL.to_text(&hash), text);
    }

    #[test]
    fn parse_text_fixed_tag_is_resolved() {
        let parsed = FIXED_KERNEL.parse_text(&valid_text(PREFIX_FIXED)).unwrap();
        assert_eq!(parsed.state.provenance(), IdentityParseProvenance::FromText);
        assert_eq!(
            parsed.state.completeness(),
            IdentitySemanticCompleteness::Resolved
        );
        assert_eq!(parsed.binary[0], 0x42);
    }

    #[test]
    fn parse_text_digest_first_is_unresolved() {
        let parsed = DIGEST_FIRST_KERNEL
            .parse_text(&valid_text(PREFIX_DIGEST_FIRST))
            .unwrap();
        assert_eq!(parsed.state.provenance(), IdentityParseProvenance::FromText);
        assert_eq!(
            parsed.state.completeness(),
            IdentitySemanticCompleteness::Unresolved
        );
        assert_eq!(parsed.binary[0], 0x00);
    }

    #[test]
    fn parse_binary_tagged_runs_tag_gate() {
        let hash = [0x11; HASH_LEN];
        let binary = IdentityWireKernel::binary_from_tag_and_hash(0x42, hash);
        let parsed = FIXED_KERNEL.parse_binary(&binary).unwrap();
        assert_eq!(parsed.binary, binary);
        assert_eq!(parsed.hash, hash);
        assert_eq!(parsed.wire_variant, IdentityWireVariant::Tagged33);
        assert_eq!(
            parsed.state.provenance(),
            IdentityParseProvenance::FromTaggedBinary
        );
    }

    #[test]
    fn parse_binary_hash_only_sets_hash32_provenance() {
        let hash = [0x22; HASH_LEN];
        let parsed = DIGEST_FIRST_KERNEL.parse_binary(&hash).unwrap();
        assert_eq!(parsed.hash, hash);
        assert_eq!(parsed.wire_variant, IdentityWireVariant::Hash32);
        assert_eq!(
            parsed.state.provenance(),
            IdentityParseProvenance::FromHashOnlyBinary
        );
        assert_eq!(
            parsed.state.completeness(),
            IdentitySemanticCompleteness::Unresolved
        );
    }

    #[test]
    fn parse_binary_rejects_hash_only_when_not_admissible() {
        let err = FIXED_KERNEL.parse_binary(&[0x01; HASH_LEN]).unwrap_err();
        assert_eq!(err, KeyIdError::InvalidBinaryLength { got: HASH_LEN });
    }
}
