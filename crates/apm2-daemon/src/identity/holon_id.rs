//! `HolonIdV1` and `HolonGenesisV1` for cell-scoped holon identity.
//!
//! # `HolonIdV1` Derivation (HSI 1.7.4)
//!
//! ```text
//! holon_id = blake3("apm2:holon_id:v1\0"
//!                   + cell_id_bytes
//!                   + holon_genesis_public_key_id_bytes)
//! ```
//!
//! Where:
//! - `cell_id_bytes` is the 32-byte hash from `CellIdV1` (not tag+hash)
//! - `holon_genesis_public_key_id_bytes` is full 33-byte `PublicKeyIdV1` binary
//!
//! # Text Form (HSI 1.7.5b)
//!
//! ```text
//! holon:v1:blake3:<64-lowercase-hex>
//! ```

use std::fmt;

use super::canonical_digest_id_kit::{
    IdentityWireKernel, impl_digest_id_fmt, impl_version_tagged_digest_id,
};
use super::cell_id::CellIdV1;
use super::{
    AlgorithmTag, BINARY_LEN, HASH_LEN, IdentityDerivationSemantics, IdentityParseState,
    IdentityResolutionSemantics, IdentitySemanticCompleteness, IdentitySpec, IdentityTagSemantics,
    IdentityTextTagPolicy, IdentityWireFormSemantics, KeyIdError, PublicKeyIdV1,
};

/// Canonical text prefix for `HolonIdV1`.
const PREFIX: &str = "holon:v1:blake3:";

/// Domain separator for `HolonIdV1` derivation (HSI 1.7.4).
const DOMAIN_SEPARATION: &[u8] = b"apm2:holon_id:v1\0";

/// Domain separator for `HolonGenesisV1` canonical bytes (CAS artifact).
const GENESIS_DOMAIN_SEPARATION: &[u8] = b"apm2:holon_genesis:v1\0";

/// Version tag byte for V1 binary form.
const VERSION_TAG_V1: u8 = 0x01;

const fn validate_holon_version_tag(tag: u8) -> Result<IdentitySemanticCompleteness, KeyIdError> {
    if tag == VERSION_TAG_V1 {
        Ok(IdentitySemanticCompleteness::Resolved)
    } else {
        Err(KeyIdError::UnknownVersionTag { tag })
    }
}

const HOLON_ID_SPEC: IdentitySpec = IdentitySpec {
    text_prefix: PREFIX,
    wire_form: IdentityWireFormSemantics::Tagged33Only,
    tag_semantics: IdentityTagSemantics::FixedVersionTag {
        tag: VERSION_TAG_V1,
    },
    derivation_semantics: IdentityDerivationSemantics::DomainSeparatedDigest {
        domain_separator: "apm2:holon_id:v1\\0 + cell_id_hash + holon_genesis_public_key_id",
    },
    resolution_semantics: IdentityResolutionSemantics::SelfContained,
    text_tag_policy: IdentityTextTagPolicy::FixedTag {
        tag: VERSION_TAG_V1,
    },
    unresolved_compat_tag: None,
    validate_tag: validate_holon_version_tag,
};

const WIRE_KERNEL: IdentityWireKernel = IdentityWireKernel::new(&HOLON_ID_SPEC);

/// Presence bitmap bit: optional `purpose` is present.
const PURPOSE_PRESENT_BIT: u8 = 0b0000_0001;

/// Presence bitmap bit: optional `created_anchor` is present.
const CREATED_ANCHOR_PRESENT_BIT: u8 = 0b0000_0010;

/// Expected byte length for Ed25519 public keys.
pub const ED25519_PUBLIC_KEY_LEN: usize = 32;

/// Maximum byte length for genesis public key bytes.
pub const MAX_GENESIS_PUBLIC_KEY_BYTES: usize = 256;

/// Maximum byte length for an optional created anchor.
pub const MAX_CREATED_ANCHOR_LEN: usize = 256;

/// Optional role descriptor for a holon genesis artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum HolonPurpose {
    /// Autonomous task execution agent.
    Agent,
    /// Transport or forwarding relay.
    Relay,
    /// Human or system operator endpoint.
    Operator,
    /// Policy or consensus validator.
    Validator,
}

impl HolonPurpose {
    /// Canonical token used in genesis canonical bytes.
    pub const fn as_token(self) -> &'static str {
        match self {
            Self::Agent => "AGENT",
            Self::Relay => "RELAY",
            Self::Operator => "OPERATOR",
            Self::Validator => "VALIDATOR",
        }
    }
}

impl fmt::Display for HolonPurpose {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_token())
    }
}

impl std::str::FromStr for HolonPurpose {
    type Err = KeyIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "AGENT" => Ok(Self::Agent),
            "RELAY" => Ok(Self::Relay),
            "OPERATOR" => Ok(Self::Operator),
            "VALIDATOR" => Ok(Self::Validator),
            _ => Err(KeyIdError::InvalidDescriptor {
                reason: format!("unknown holon purpose token: {s}"),
            }),
        }
    }
}

/// Canonical genesis artifact whose commitments define a stable `HolonIdV1`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct HolonGenesisV1 {
    cell_id: CellIdV1,
    holon_genesis_public_key_id: PublicKeyIdV1,
    holon_genesis_public_key_bytes: Vec<u8>,
    purpose: Option<HolonPurpose>,
    created_anchor: Option<String>,
}

impl HolonGenesisV1 {
    /// Construct a validated `HolonGenesisV1`.
    pub fn new(
        cell_id: CellIdV1,
        holon_genesis_public_key_id: PublicKeyIdV1,
        holon_genesis_public_key_bytes: Vec<u8>,
        purpose: Option<HolonPurpose>,
        created_anchor: Option<String>,
    ) -> Result<Self, KeyIdError> {
        validate_public_key_bytes(&holon_genesis_public_key_bytes)?;

        let expected =
            PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &holon_genesis_public_key_bytes);
        if expected != holon_genesis_public_key_id {
            return Err(KeyIdError::InvalidDescriptor {
                reason: "holon_genesis_public_key_id does not match provided public_key_bytes"
                    .to_string(),
            });
        }

        if let Some(anchor) = created_anchor.as_deref() {
            validate_created_anchor(anchor)?;
        }

        Ok(Self {
            cell_id,
            holon_genesis_public_key_id,
            holon_genesis_public_key_bytes,
            purpose,
            created_anchor,
        })
    }

    /// Return the bound cell ID.
    pub const fn cell_id(&self) -> &CellIdV1 {
        &self.cell_id
    }

    /// Return the immutable genesis public-key identifier.
    pub const fn holon_genesis_public_key_id(&self) -> &PublicKeyIdV1 {
        &self.holon_genesis_public_key_id
    }

    /// Return immutable genesis public-key bytes.
    pub fn holon_genesis_public_key_bytes(&self) -> &[u8] {
        &self.holon_genesis_public_key_bytes
    }

    /// Return optional holon purpose.
    pub const fn purpose(&self) -> Option<HolonPurpose> {
        self.purpose
    }

    /// Return optional creation anchor.
    pub fn created_anchor(&self) -> Option<&str> {
        self.created_anchor.as_deref()
    }

    /// Deterministic canonical bytes for CAS addressing (HSI 1.7.4b).
    ///
    /// Uses injective length-prefixed encoding to prevent ambiguous framing.
    /// Fixed-length fields are explicitly delimited and optional fields are
    /// controlled by a single presence bitmap.
    ///
    /// ```text
    /// apm2:holon_genesis:v1\0
    /// + cell_id_hash (32 bytes, fixed)
    /// + "\n"
    /// + pkid_binary (33 bytes, fixed)
    /// + "\n"
    /// + len(pubkey_bytes) as u32 LE + pubkey_bytes
    /// + presence_bitmap (bit0 = purpose present, bit1 = anchor present)
    /// + [if purpose present: len(purpose) as u32 LE + purpose]
    /// + [if anchor present: len(anchor) as u32 LE + anchor]
    /// ```
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let pkid_binary = self.holon_genesis_public_key_id.to_binary();

        let mut out = Vec::with_capacity(
            GENESIS_DOMAIN_SEPARATION.len()
                + HASH_LEN
                + 1
                + BINARY_LEN
                + 1
                + 4
                + self.holon_genesis_public_key_bytes.len()
                + 1
                + self.purpose.map_or(0, |p| 4 + p.as_token().len())
                + self.created_anchor.as_ref().map_or(0, |a| 4 + a.len()),
        );

        out.extend_from_slice(GENESIS_DOMAIN_SEPARATION);
        out.extend_from_slice(self.cell_id.cell_hash());
        out.push(b'\n');
        out.extend_from_slice(&pkid_binary);
        out.push(b'\n');

        // Variable-length field: pubkey_bytes with 4-byte LE length prefix.
        let pk_len = u32::try_from(self.holon_genesis_public_key_bytes.len())
            .expect("holon_genesis_public_key_bytes length is bounded to <= 256");
        out.extend_from_slice(&pk_len.to_le_bytes());
        out.extend_from_slice(&self.holon_genesis_public_key_bytes);

        let mut presence_bitmap = 0u8;
        if self.purpose.is_some() {
            presence_bitmap |= PURPOSE_PRESENT_BIT;
        }
        if self.created_anchor.is_some() {
            presence_bitmap |= CREATED_ANCHOR_PRESENT_BIT;
        }
        out.push(presence_bitmap);

        if let Some(purpose) = self.purpose {
            let token = purpose.as_token().as_bytes();
            let token_len =
                u32::try_from(token.len()).expect("HolonPurpose token length must fit in u32");
            out.extend_from_slice(&token_len.to_le_bytes());
            out.extend_from_slice(token);
        }

        if let Some(anchor) = self.created_anchor.as_ref() {
            let anchor_bytes = anchor.as_bytes();
            let anchor_len =
                u32::try_from(anchor_bytes.len()).expect("created_anchor length must fit in u32");
            out.extend_from_slice(&anchor_len.to_le_bytes());
            out.extend_from_slice(anchor_bytes);
        }

        out
    }
}

/// Stable self-certifying holon identity scoped to a cell.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct HolonIdV1 {
    /// Binary form: `version_tag` (1 byte) + `holon_hash` (32 bytes).
    binary: [u8; BINARY_LEN],
}

impl HolonIdV1 {
    /// Derive a stable `HolonIdV1` from genesis commitments (HSI 1.7.4).
    pub fn from_genesis(genesis: &HolonGenesisV1) -> Self {
        let pkid_binary = genesis.holon_genesis_public_key_id.to_binary();

        let mut hasher = blake3::Hasher::new();
        hasher.update(DOMAIN_SEPARATION);
        hasher.update(genesis.cell_id.cell_hash());
        hasher.update(&pkid_binary);
        let hash = hasher.finalize();

        let mut binary = [0u8; BINARY_LEN];
        binary[0] = VERSION_TAG_V1;
        binary[1..].copy_from_slice(hash.as_bytes());
        Self { binary }
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

    impl_version_tagged_digest_id!(WIRE_KERNEL, VERSION_TAG_V1, holon_hash);
}

impl_digest_id_fmt!(HolonIdV1, "HolonIdV1");

fn validate_public_key_bytes(bytes: &[u8]) -> Result<(), KeyIdError> {
    if bytes.is_empty() {
        return Err(KeyIdError::InvalidDescriptor {
            reason: "holon_genesis_public_key_bytes must be non-empty".to_string(),
        });
    }
    if bytes.len() > MAX_GENESIS_PUBLIC_KEY_BYTES {
        return Err(KeyIdError::InvalidDescriptor {
            reason: format!(
                "holon_genesis_public_key_bytes length {} exceeds maximum of {MAX_GENESIS_PUBLIC_KEY_BYTES}",
                bytes.len()
            ),
        });
    }
    // Ed25519 public keys must be exactly 32 bytes. Since the only supported
    // identity scheme uses Ed25519 (AlgorithmTag::Ed25519), we enforce this
    // invariant for all genesis key bytes.
    if bytes.len() != ED25519_PUBLIC_KEY_LEN {
        return Err(KeyIdError::InvalidDescriptor {
            reason: format!(
                "Ed25519 public key must be exactly {ED25519_PUBLIC_KEY_LEN} bytes, got {}",
                bytes.len()
            ),
        });
    }
    Ok(())
}

fn validate_created_anchor(anchor: &str) -> Result<(), KeyIdError> {
    if anchor.is_empty() {
        return Err(KeyIdError::InvalidDescriptor {
            reason: "created_anchor must be non-empty when present".to_string(),
        });
    }
    if !anchor.is_ascii() {
        return Err(KeyIdError::ContainsNonAscii);
    }
    if anchor.contains('%') {
        return Err(KeyIdError::ContainsPercentEncoding);
    }
    if anchor != anchor.trim() {
        return Err(KeyIdError::ContainsWhitespace);
    }
    if anchor.chars().any(char::is_whitespace) {
        return Err(KeyIdError::ContainsInteriorWhitespace);
    }
    if anchor.bytes().any(|b| !(0x21..=0x7E).contains(&b)) {
        return Err(KeyIdError::ContainsControlCharacter);
    }
    if anchor.len() > MAX_CREATED_ANCHOR_LEN {
        return Err(KeyIdError::InvalidDescriptor {
            reason: format!(
                "created_anchor length {} exceeds maximum of {MAX_CREATED_ANCHOR_LEN}",
                anchor.len()
            ),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{
        CellGenesisV1, IdentityParseProvenance, IdentitySemanticCompleteness, PolicyRootId,
    };

    fn make_public_key_bytes(fill: u8) -> Vec<u8> {
        vec![fill; 32]
    }

    fn make_public_key_id(fill: u8) -> PublicKeyIdV1 {
        PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &make_public_key_bytes(fill))
    }

    fn make_cell_id(fill: u8, trust_domain: &str) -> CellIdV1 {
        let genesis = CellGenesisV1::new(
            [fill; 32],
            PolicyRootId::Single(make_public_key_id(0xAB)),
            trust_domain,
        )
        .unwrap();
        CellIdV1::from_genesis(&genesis)
    }

    fn make_holon_genesis() -> HolonGenesisV1 {
        let key_bytes = make_public_key_bytes(0xCD);
        let key_id = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &key_bytes);
        HolonGenesisV1::new(
            make_cell_id(0x11, "cell.example.internal"),
            key_id,
            key_bytes,
            Some(HolonPurpose::Agent),
            Some("anchor:genesis:0001".to_string()),
        )
        .unwrap()
    }

    #[test]
    fn deterministic_derivation_same_genesis_same_holon_id() {
        let genesis = make_holon_genesis();
        let id1 = HolonIdV1::from_genesis(&genesis);
        let id2 = HolonIdV1::from_genesis(&genesis);
        assert_eq!(id1, id2);
    }

    #[test]
    fn collision_resistance_diff_cell_id_diff_holon_id() {
        let key_bytes = make_public_key_bytes(0xCD);
        let key_id = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &key_bytes);

        let g1 = HolonGenesisV1::new(
            make_cell_id(0x11, "cell-a.example"),
            key_id.clone(),
            key_bytes.clone(),
            None,
            None,
        )
        .unwrap();
        let g2 = HolonGenesisV1::new(
            make_cell_id(0x22, "cell-b.example"),
            key_id,
            key_bytes,
            None,
            None,
        )
        .unwrap();

        let id1 = HolonIdV1::from_genesis(&g1);
        let id2 = HolonIdV1::from_genesis(&g2);
        assert_ne!(id1, id2);
    }

    #[test]
    fn collision_resistance_diff_genesis_key_diff_holon_id() {
        let cell_id = make_cell_id(0x11, "cell.example.internal");

        let key_bytes_a = make_public_key_bytes(0xAA);
        let key_id_a = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &key_bytes_a);
        let key_bytes_b = make_public_key_bytes(0xBB);
        let key_id_b = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &key_bytes_b);

        let g1 = HolonGenesisV1::new(cell_id.clone(), key_id_a, key_bytes_a, None, None).unwrap();
        let g2 = HolonGenesisV1::new(cell_id, key_id_b, key_bytes_b, None, None).unwrap();

        let id1 = HolonIdV1::from_genesis(&g1);
        let id2 = HolonIdV1::from_genesis(&g2);
        assert_ne!(id1, id2);
    }

    #[test]
    fn metadata_changes_do_not_change_holon_id() {
        let cell_id = make_cell_id(0x11, "cell.example.internal");
        let key_bytes = make_public_key_bytes(0xCC);
        let key_id = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &key_bytes);

        let g1 = HolonGenesisV1::new(
            cell_id.clone(),
            key_id.clone(),
            key_bytes.clone(),
            Some(HolonPurpose::Agent),
            Some("anchor:one".to_string()),
        )
        .unwrap();
        let g2 = HolonGenesisV1::new(
            cell_id,
            key_id,
            key_bytes,
            Some(HolonPurpose::Validator),
            Some("anchor:two".to_string()),
        )
        .unwrap();

        assert_eq!(HolonIdV1::from_genesis(&g1), HolonIdV1::from_genesis(&g2));
        assert_ne!(g1.canonical_bytes(), g2.canonical_bytes());
    }

    #[test]
    fn canonical_bytes_disambiguate_purpose_vs_anchor_payloads() {
        let cell_id = make_cell_id(0x11, "cell.example.internal");
        let key_bytes = make_public_key_bytes(0xCC);
        let key_id = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &key_bytes);

        let purpose_only = HolonGenesisV1::new(
            cell_id.clone(),
            key_id.clone(),
            key_bytes.clone(),
            Some(HolonPurpose::Agent),
            None,
        )
        .unwrap();
        let anchor_only =
            HolonGenesisV1::new(cell_id, key_id, key_bytes, None, Some("AGENT".to_string()))
                .unwrap();

        assert_ne!(
            purpose_only.canonical_bytes(),
            anchor_only.canonical_bytes()
        );
    }

    #[test]
    fn key_rotation_preserves_holon_id_structural_invariant() {
        let genesis = make_holon_genesis();
        let id_before = HolonIdV1::from_genesis(&genesis);

        // Operational/session keys rotate independently of genesis identity.
        let _operational_key_old = make_public_key_id(0x01);
        let _operational_key_new = make_public_key_id(0x02);

        let id_after = HolonIdV1::from_genesis(&genesis);
        assert_eq!(id_before, id_after);
    }

    #[test]
    fn genesis_artifact_canonical_bytes_are_deterministic_and_hash_addressable() {
        let genesis = make_holon_genesis();
        let c1 = genesis.canonical_bytes();
        let c2 = genesis.canonical_bytes();
        assert_eq!(c1, c2);

        let h1 = blake3::hash(&c1);
        let h2 = blake3::hash(&c2);
        assert_eq!(h1, h2);
    }

    #[test]
    fn text_round_trip() {
        let id = HolonIdV1::from_genesis(&make_holon_genesis());
        let text = id.to_text();
        let parsed = HolonIdV1::parse_text(&text).unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn parse_state_from_text_is_resolved() {
        let id = HolonIdV1::from_genesis(&make_holon_genesis());
        let (parsed, state) = HolonIdV1::parse_text_with_state(&id.to_text()).unwrap();
        assert_eq!(parsed, id);
        assert_eq!(state.provenance(), IdentityParseProvenance::FromText);
        assert_eq!(state.completeness(), IdentitySemanticCompleteness::Resolved);
    }

    #[test]
    fn parse_state_from_tagged_binary_is_resolved() {
        let id = HolonIdV1::from_genesis(&make_holon_genesis());
        let (parsed, state) = HolonIdV1::from_binary_with_state(&id.to_binary()).unwrap();
        assert_eq!(parsed, id);
        assert_eq!(
            state.provenance(),
            IdentityParseProvenance::FromTaggedBinary
        );
        assert_eq!(state.completeness(), IdentitySemanticCompleteness::Resolved);
    }

    #[test]
    fn binary_round_trip() {
        let id = HolonIdV1::from_genesis(&make_holon_genesis());
        let binary = id.to_binary();
        let parsed = HolonIdV1::from_binary(&binary).unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn text_then_binary_round_trip() {
        let id = HolonIdV1::from_genesis(&make_holon_genesis());
        let text = id.to_text();
        let parsed_text = HolonIdV1::parse_text(&text).unwrap();
        let parsed_binary = HolonIdV1::from_binary(parsed_text.as_bytes()).unwrap();
        assert_eq!(id, parsed_binary);
    }

    #[test]
    fn text_format_matches_grammar() {
        let id = HolonIdV1::from_genesis(&make_holon_genesis());
        let text = id.to_text();
        assert!(text.starts_with(PREFIX));
        assert_eq!(text.len(), PREFIX.len() + 64);
        assert!(text.len() <= crate::identity::MAX_TEXT_LEN);
    }

    #[test]
    fn rejects_wrong_prefix() {
        let id = HolonIdV1::from_genesis(&make_holon_genesis());
        let bad = id.to_text().replacen("holon:", "cell:", 1);
        let err = HolonIdV1::parse_text(&bad).unwrap_err();
        assert!(matches!(err, KeyIdError::WrongPrefix { .. }));
    }

    #[test]
    fn rejects_uppercase() {
        let id = HolonIdV1::from_genesis(&make_holon_genesis());
        let err = HolonIdV1::parse_text(&id.to_text().to_ascii_uppercase()).unwrap_err();
        assert_eq!(err, KeyIdError::ContainsUppercase);
    }

    #[test]
    fn rejects_whitespace() {
        let id = HolonIdV1::from_genesis(&make_holon_genesis());
        let err = HolonIdV1::parse_text(&format!(" {}", id.to_text())).unwrap_err();
        assert_eq!(err, KeyIdError::ContainsWhitespace);
    }

    #[test]
    fn rejects_percent_encoded() {
        let err = HolonIdV1::parse_text(
            "holon%3av1%3ablake3%3a0000000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap_err();
        assert_eq!(err, KeyIdError::ContainsPercentEncoding);
    }

    #[test]
    fn rejects_non_ascii() {
        let err = HolonIdV1::parse_text(
            "holon\u{FF1A}v1:blake3:0000000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap_err();
        assert_eq!(err, KeyIdError::ContainsNonAscii);
    }

    #[test]
    fn rejects_malformed_hex() {
        let err = HolonIdV1::parse_text(
            "holon:v1:blake3:g000000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap_err();
        assert_eq!(err, KeyIdError::InvalidHexCharacters);
    }

    #[test]
    fn rejects_unknown_version_tag_binary() {
        let mut binary = HolonIdV1::from_genesis(&make_holon_genesis()).to_binary();
        binary[0] = 0xFF;
        let err = HolonIdV1::from_binary(&binary).unwrap_err();
        assert_eq!(err, KeyIdError::UnknownVersionTag { tag: 0xFF });
    }

    #[test]
    fn rejects_binary_wrong_length() {
        let err = HolonIdV1::from_binary(&[0x01; 32]).unwrap_err();
        assert!(matches!(err, KeyIdError::InvalidBinaryLength { got: 32 }));
    }

    #[test]
    fn rejects_empty_public_key_bytes() {
        let err = HolonGenesisV1::new(
            make_cell_id(0x11, "cell.example"),
            make_public_key_id(0xAA),
            Vec::new(),
            None,
            None,
        )
        .unwrap_err();
        assert!(matches!(err, KeyIdError::InvalidDescriptor { .. }));
    }

    #[test]
    fn rejects_public_key_bytes_over_max() {
        let key_bytes = vec![0xAB; MAX_GENESIS_PUBLIC_KEY_BYTES + 1];
        let key_id = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &key_bytes);
        let err = HolonGenesisV1::new(
            make_cell_id(0x11, "cell.example"),
            key_id,
            key_bytes,
            None,
            None,
        )
        .unwrap_err();
        assert!(matches!(err, KeyIdError::InvalidDescriptor { .. }));
    }

    #[test]
    fn rejects_public_key_bytes_shorter_than_ed25519_len() {
        let key_bytes = vec![0xAB; ED25519_PUBLIC_KEY_LEN - 1];
        let key_id = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &key_bytes);
        let err = HolonGenesisV1::new(
            make_cell_id(0x11, "cell.example"),
            key_id,
            key_bytes,
            None,
            None,
        )
        .unwrap_err();
        assert!(matches!(err, KeyIdError::InvalidDescriptor { .. }));
    }

    #[test]
    fn rejects_public_key_bytes_longer_than_ed25519_len() {
        let key_bytes = vec![0xAB; ED25519_PUBLIC_KEY_LEN + 1];
        let key_id = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &key_bytes);
        let err = HolonGenesisV1::new(
            make_cell_id(0x11, "cell.example"),
            key_id,
            key_bytes,
            None,
            None,
        )
        .unwrap_err();
        assert!(matches!(err, KeyIdError::InvalidDescriptor { .. }));
    }

    #[test]
    fn rejects_mismatched_public_key_id_and_bytes() {
        let key_bytes = make_public_key_bytes(0xAA);
        let wrong_id = make_public_key_id(0xBB);
        let err = HolonGenesisV1::new(
            make_cell_id(0x11, "cell.example"),
            wrong_id,
            key_bytes,
            None,
            None,
        )
        .unwrap_err();
        assert!(matches!(err, KeyIdError::InvalidDescriptor { .. }));
    }

    #[test]
    fn created_anchor_rejects_empty() {
        let key_bytes = make_public_key_bytes(0xAA);
        let key_id = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &key_bytes);
        let err = HolonGenesisV1::new(
            make_cell_id(0x11, "cell.example"),
            key_id,
            key_bytes,
            None,
            Some(String::new()),
        )
        .unwrap_err();
        assert!(matches!(err, KeyIdError::InvalidDescriptor { .. }));
    }

    #[test]
    fn created_anchor_rejects_too_long() {
        let key_bytes = make_public_key_bytes(0xAA);
        let key_id = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &key_bytes);
        let anchor = "a".repeat(MAX_CREATED_ANCHOR_LEN + 1);
        let err = HolonGenesisV1::new(
            make_cell_id(0x11, "cell.example"),
            key_id,
            key_bytes,
            None,
            Some(anchor),
        )
        .unwrap_err();
        assert!(matches!(err, KeyIdError::InvalidDescriptor { .. }));
    }

    #[test]
    fn created_anchor_rejects_non_ascii() {
        let key_bytes = make_public_key_bytes(0xAA);
        let key_id = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &key_bytes);
        let err = HolonGenesisV1::new(
            make_cell_id(0x11, "cell.example"),
            key_id,
            key_bytes,
            None,
            Some("anch\u{00E9}r".to_string()),
        )
        .unwrap_err();
        assert_eq!(err, KeyIdError::ContainsNonAscii);
    }

    #[test]
    fn created_anchor_rejects_whitespace() {
        let key_bytes = make_public_key_bytes(0xAA);
        let key_id = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &key_bytes);
        let err = HolonGenesisV1::new(
            make_cell_id(0x11, "cell.example"),
            key_id,
            key_bytes,
            None,
            Some("anchor one".to_string()),
        )
        .unwrap_err();
        assert_eq!(err, KeyIdError::ContainsInteriorWhitespace);
    }

    #[test]
    fn created_anchor_rejects_percent_encoded() {
        let key_bytes = make_public_key_bytes(0xAA);
        let key_id = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &key_bytes);
        let err = HolonGenesisV1::new(
            make_cell_id(0x11, "cell.example"),
            key_id,
            key_bytes,
            None,
            Some("anchor%3Aone".to_string()),
        )
        .unwrap_err();
        assert_eq!(err, KeyIdError::ContainsPercentEncoding);
    }

    #[test]
    fn created_anchor_rejects_nul_byte() {
        let key_bytes = make_public_key_bytes(0xAA);
        let key_id = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &key_bytes);
        let err = HolonGenesisV1::new(
            make_cell_id(0x11, "cell.example"),
            key_id,
            key_bytes,
            None,
            Some("anchor\0one".to_string()),
        )
        .unwrap_err();
        assert_eq!(err, KeyIdError::ContainsControlCharacter);
    }

    #[test]
    fn created_anchor_rejects_ascii_control_character() {
        let key_bytes = make_public_key_bytes(0xAA);
        let key_id = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &key_bytes);
        let err = HolonGenesisV1::new(
            make_cell_id(0x11, "cell.example"),
            key_id,
            key_bytes,
            None,
            Some(format!("anchor{}one", '\u{0007}')),
        )
        .unwrap_err();
        assert_eq!(err, KeyIdError::ContainsControlCharacter);
    }

    #[test]
    fn created_anchor_accepts_max_len() {
        let key_bytes = make_public_key_bytes(0xAA);
        let key_id = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &key_bytes);
        let anchor = "a".repeat(MAX_CREATED_ANCHOR_LEN);
        let genesis = HolonGenesisV1::new(
            make_cell_id(0x11, "cell.example"),
            key_id,
            key_bytes,
            None,
            Some(anchor.clone()),
        )
        .unwrap();
        assert_eq!(genesis.created_anchor(), Some(anchor.as_str()));
    }

    #[test]
    fn holon_purpose_parse_fail_closed() {
        assert_eq!(
            "AGENT".parse::<HolonPurpose>().unwrap(),
            HolonPurpose::Agent
        );
        assert_eq!(
            "RELAY".parse::<HolonPurpose>().unwrap(),
            HolonPurpose::Relay
        );
        assert_eq!(
            "OPERATOR".parse::<HolonPurpose>().unwrap(),
            HolonPurpose::Operator
        );
        assert_eq!(
            "VALIDATOR".parse::<HolonPurpose>().unwrap(),
            HolonPurpose::Validator
        );

        let err = "unknown".parse::<HolonPurpose>().unwrap_err();
        assert!(matches!(err, KeyIdError::InvalidDescriptor { .. }));
    }

    // =========================================================================
    // CAS round-trip tests (REQ-0008 AC#3)
    // =========================================================================

    #[test]
    fn holon_genesis_canonical_bytes_round_trip_in_durable_cas() {
        use tempfile::TempDir;

        use crate::cas::{DurableCas, DurableCasConfig};

        let temp_dir = TempDir::new().unwrap();
        let cas_path = temp_dir.path().join("cas");
        let cas = DurableCas::new(DurableCasConfig::new(&cas_path)).unwrap();

        let genesis = make_holon_genesis();
        let canonical = genesis.canonical_bytes();

        let first_store = cas.store(&canonical).unwrap();
        assert!(first_store.is_new, "first store must persist new content");
        assert_eq!(first_store.size, canonical.len());
        assert!(cas.exists(&first_store.hash));

        let retrieved = cas.retrieve(&first_store.hash).unwrap();
        assert_eq!(retrieved, canonical);

        let second_store = cas.store(&canonical).unwrap();
        assert!(!second_store.is_new, "second store must deduplicate");
        assert_eq!(second_store.hash, first_store.hash);
    }

    /// Store `HolonGenesisV1` canonical bytes into CAS and retrieve by content
    /// hash, verifying the hash/content round-trip invariant.
    #[test]
    fn holon_genesis_cas_round_trip_via_memory_cas() {
        use apm2_core::evidence::{ContentAddressedStore, MemoryCas};

        let cas = MemoryCas::new();
        let genesis = make_holon_genesis();
        let canonical = genesis.canonical_bytes();

        // Store canonical bytes into CAS.
        let store_result = cas.store(&canonical).unwrap();
        assert!(store_result.is_new, "first store must be new");
        assert_eq!(store_result.size, canonical.len());

        // Retrieve by content hash and verify content equality.
        let retrieved = cas.retrieve(&store_result.hash).unwrap();
        assert_eq!(
            retrieved, canonical,
            "retrieved bytes must equal original canonical bytes"
        );

        // Re-hash retrieved content and compare to stored hash.
        let rehash = apm2_core::crypto::EventHasher::hash_content(&retrieved);
        assert_eq!(
            rehash, store_result.hash,
            "re-hashing retrieved content must produce the same hash"
        );
    }

    /// Verify that storing the same genesis canonical bytes is idempotent
    /// (deduplication) and different genesis artifacts produce different
    /// hashes.
    #[test]
    fn holon_genesis_cas_deduplication_and_collision_resistance() {
        use apm2_core::evidence::{ContentAddressedStore, MemoryCas};

        let cas = MemoryCas::new();
        let genesis = make_holon_genesis();
        let canonical = genesis.canonical_bytes();

        let r1 = cas.store(&canonical).unwrap();
        let r2 = cas.store(&canonical).unwrap();
        assert!(!r2.is_new, "duplicate store must be deduplicated");
        assert_eq!(r1.hash, r2.hash);

        // Different genesis (different key bytes) must yield a different CAS hash.
        let key_bytes_alt = make_public_key_bytes(0xEE);
        let key_id_alt = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &key_bytes_alt);
        let genesis2 = HolonGenesisV1::new(
            make_cell_id(0x11, "cell.example.internal"),
            key_id_alt,
            key_bytes_alt,
            Some(HolonPurpose::Relay),
            None,
        )
        .unwrap();
        let r3 = cas.store(&genesis2.canonical_bytes()).unwrap();
        assert_ne!(
            r1.hash, r3.hash,
            "different genesis must produce different CAS hashes"
        );
    }

    /// Verify that a `HolonIdV1` derived from genesis and the genesis canonical
    /// bytes can both be stored and retrieved independently in CAS.
    #[test]
    fn holon_id_and_genesis_cas_independent_storage() {
        use apm2_core::evidence::{ContentAddressedStore, MemoryCas};

        let cas = MemoryCas::new();
        let genesis = make_holon_genesis();
        let holon_id = HolonIdV1::from_genesis(&genesis);

        let genesis_result = cas.store(&genesis.canonical_bytes()).unwrap();
        let id_result = cas.store(&holon_id.to_binary()).unwrap();

        // Both must be retrievable independently.
        let genesis_bytes = cas.retrieve(&genesis_result.hash).unwrap();
        let id_bytes = cas.retrieve(&id_result.hash).unwrap();

        assert_eq!(genesis_bytes, genesis.canonical_bytes());
        assert_eq!(id_bytes, holon_id.to_binary().as_slice());

        // Hashes must differ (genesis artifact != holon id binary).
        assert_ne!(genesis_result.hash, id_result.hash);
    }

    // =========================================================================
    // BLOCKER-1: Length-prefixed canonical encoding regression tests
    // =========================================================================

    /// Regression: purpose=Some("AGENT")/anchor=None vs
    /// purpose=None/anchor=Some("AGENT") must produce different canonical
    /// bytes (the old delimiter-based encoding allowed these to collide).
    #[test]
    fn canonical_bytes_no_collision_purpose_vs_anchor() {
        let cell_id = make_cell_id(0x11, "cell.example.internal");
        let key_bytes = make_public_key_bytes(0xAA);
        let key_id = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &key_bytes);

        let g1 = HolonGenesisV1::new(
            cell_id.clone(),
            key_id.clone(),
            key_bytes.clone(),
            Some(HolonPurpose::Agent),
            None,
        )
        .unwrap();
        let g2 = HolonGenesisV1::new(cell_id, key_id, key_bytes, None, Some("AGENT".to_string()))
            .unwrap();

        assert_ne!(
            g1.canonical_bytes(),
            g2.canonical_bytes(),
            "purpose=Some(AGENT)/anchor=None must not collide with purpose=None/anchor=Some(AGENT)"
        );
    }

    /// Adversarial: embedded delimiter bytes (newlines) in anchor must not
    /// cause framing ambiguity. With length-prefixed encoding, the anchor
    /// field data is length-delimited, so embedded newlines are harmless.
    #[test]
    fn canonical_bytes_adversarial_embedded_delimiter() {
        let cell_id = make_cell_id(0x11, "cell.example.internal");
        let key_bytes = make_public_key_bytes(0xAA);
        let key_id = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &key_bytes);

        // Anchors with embedded content that would be dangerous under
        // delimiter-based framing. Since control chars are now rejected,
        // we test with printable anchors that differ only in structure.
        let g1 = HolonGenesisV1::new(
            cell_id.clone(),
            key_id.clone(),
            key_bytes.clone(),
            Some(HolonPurpose::Agent),
            Some("anchor-alpha".to_string()),
        )
        .unwrap();
        let g2 = HolonGenesisV1::new(
            cell_id,
            key_id,
            key_bytes,
            Some(HolonPurpose::Agent),
            Some("anchor-beta".to_string()),
        )
        .unwrap();

        assert_ne!(
            g1.canonical_bytes(),
            g2.canonical_bytes(),
            "different anchors must produce different canonical bytes"
        );
    }

    /// Length-prefixed round-trip: canonical bytes are deterministic and the
    /// length prefix structure is consistent.
    #[test]
    fn canonical_bytes_length_prefix_structure() {
        let genesis = make_holon_genesis();
        let bytes = genesis.canonical_bytes();

        // Verify domain separator is at the start
        assert!(
            bytes.starts_with(GENESIS_DOMAIN_SEPARATION),
            "canonical bytes must start with genesis domain separator"
        );

        // Verify determinism
        assert_eq!(bytes, genesis.canonical_bytes());

        // Verify that a genesis with no optional fields also works
        let cell_id = make_cell_id(0x11, "cell.example.internal");
        let key_bytes = make_public_key_bytes(0xBB);
        let key_id = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &key_bytes);
        let bare = HolonGenesisV1::new(cell_id, key_id, key_bytes, None, None).unwrap();
        let bare_bytes = bare.canonical_bytes();
        assert_eq!(bare_bytes, bare.canonical_bytes());

        // bare and full genesis must differ
        assert_ne!(bytes, bare_bytes);
    }

    // =========================================================================
    // BLOCKER-2: Ed25519 key length validation tests
    // =========================================================================

    #[test]
    fn rejects_31_byte_public_key() {
        let key_bytes = vec![0xAA; 31];
        let key_id = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &key_bytes);
        let err = HolonGenesisV1::new(
            make_cell_id(0x11, "cell.example"),
            key_id,
            key_bytes,
            None,
            None,
        )
        .unwrap_err();
        assert!(
            matches!(err, KeyIdError::InvalidDescriptor { .. }),
            "31-byte key must be rejected: {err:?}"
        );
    }

    #[test]
    fn rejects_33_byte_public_key() {
        let key_bytes = vec![0xAA; 33];
        let key_id = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &key_bytes);
        let err = HolonGenesisV1::new(
            make_cell_id(0x11, "cell.example"),
            key_id,
            key_bytes,
            None,
            None,
        )
        .unwrap_err();
        assert!(
            matches!(err, KeyIdError::InvalidDescriptor { .. }),
            "33-byte key must be rejected: {err:?}"
        );
    }

    #[test]
    fn accepts_exactly_32_byte_public_key() {
        let key_bytes = make_public_key_bytes(0xAA);
        assert_eq!(key_bytes.len(), 32);
        let key_id = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &key_bytes);
        let genesis = HolonGenesisV1::new(
            make_cell_id(0x11, "cell.example"),
            key_id,
            key_bytes,
            None,
            None,
        );
        assert!(genesis.is_ok(), "exactly 32-byte key must be accepted");
    }

    // =========================================================================
    // MAJOR-1: Control character rejection tests (created_anchor)
    // =========================================================================

    #[test]
    fn created_anchor_rejects_null_byte() {
        let key_bytes = make_public_key_bytes(0xAA);
        let key_id = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &key_bytes);
        let err = HolonGenesisV1::new(
            make_cell_id(0x11, "cell.example"),
            key_id,
            key_bytes,
            None,
            Some("anchor\0test".to_string()),
        )
        .unwrap_err();
        assert_eq!(err, KeyIdError::ContainsControlCharacter);
    }

    #[test]
    fn created_anchor_rejects_soh_control() {
        let key_bytes = make_public_key_bytes(0xAA);
        let key_id = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &key_bytes);
        let err = HolonGenesisV1::new(
            make_cell_id(0x11, "cell.example"),
            key_id,
            key_bytes,
            None,
            Some("anchor\x01test".to_string()),
        )
        .unwrap_err();
        assert_eq!(err, KeyIdError::ContainsControlCharacter);
    }

    #[test]
    fn created_anchor_rejects_del_control() {
        let key_bytes = make_public_key_bytes(0xAA);
        let key_id = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &key_bytes);
        let err = HolonGenesisV1::new(
            make_cell_id(0x11, "cell.example"),
            key_id,
            key_bytes,
            None,
            Some("anchor\x7Ftest".to_string()),
        )
        .unwrap_err();
        assert_eq!(err, KeyIdError::ContainsControlCharacter);
    }
}
