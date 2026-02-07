//! `CellIdV1` and `CellGenesisV1` for stable cell identity derivation.
//!
//! # `CellIdV1` Derivation (HSI 1.7.3)
//!
//! ```text
//! cell_id = blake3("apm2:cell_id:v1\n"
//!                  + ledger_genesis_hash_bytes
//!                  + genesis_policy_root_public_key_id_bytes)
//! ```
//!
//! Note the domain separator is newline (`\n`), not NUL.
//!
//! # Text Form (HSI 1.7.5b)
//!
//! ```text
//! cell:v1:blake3:<64-lowercase-hex>
//! ```

use super::canonical_digest_id_kit::{
    IdentityWireKernel, impl_digest_id_fmt, impl_version_tagged_digest_id,
};
use super::{
    BINARY_LEN, HASH_LEN, IdentityDerivationSemantics, IdentityParseState,
    IdentityResolutionSemantics, IdentitySemanticCompleteness, IdentitySpec, IdentityTagSemantics,
    IdentityTextTagPolicy, IdentityWireFormSemantics, KeyIdError, KeySetIdV1, PublicKeyIdV1,
};

/// Canonical text prefix for `CellIdV1`.
const PREFIX: &str = "cell:v1:blake3:";

/// Domain separator for `CellIdV1` derivation (HSI 1.7.3).
const DOMAIN_SEPARATION: &[u8] = b"apm2:cell_id:v1\n";

/// Domain separator for `CellGenesisV1` canonical bytes (CAS artifact).
const GENESIS_DOMAIN_SEPARATION: &[u8] = b"apm2:cell_genesis:v1\0";

/// Version tag byte for V1 binary form.
const VERSION_TAG_V1: u8 = 0x01;

const fn validate_cell_version_tag(tag: u8) -> Result<IdentitySemanticCompleteness, KeyIdError> {
    if tag == VERSION_TAG_V1 {
        Ok(IdentitySemanticCompleteness::Resolved)
    } else {
        Err(KeyIdError::UnknownVersionTag { tag })
    }
}

const CELL_ID_SPEC: IdentitySpec = IdentitySpec {
    text_prefix: PREFIX,
    wire_form: IdentityWireFormSemantics::Tagged33Only,
    tag_semantics: IdentityTagSemantics::FixedVersionTag {
        tag: VERSION_TAG_V1,
    },
    derivation_semantics: IdentityDerivationSemantics::DomainSeparatedDigest {
        domain_separator: "apm2:cell_id:v1\\n + ledger_genesis_hash + genesis_policy_root_id",
    },
    resolution_semantics: IdentityResolutionSemantics::SelfContained,
    text_tag_policy: IdentityTextTagPolicy::FixedTag {
        tag: VERSION_TAG_V1,
    },
    unresolved_compat_tag: None,
    validate_tag: validate_cell_version_tag,
};

const WIRE_KERNEL: IdentityWireKernel = IdentityWireKernel::new(&CELL_ID_SPEC);

/// Maximum trust-domain length (bytes).
///
/// 253 follows DNS host label limits and bounds memory usage.
pub const MAX_TRUST_DOMAIN_LEN: usize = 253;

/// Policy root commitment for a cell genesis artifact.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PolicyRootId {
    /// Single public-key root authority.
    Single(PublicKeyIdV1),
    /// Quorum/threshold root authority.
    Quorum(KeySetIdV1),
}

impl PolicyRootId {
    /// Return canonical binary bytes for this policy root commitment.
    ///
    /// Both variants are 33 bytes (`tag + hash`) in canonical binary form.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        match self {
            Self::Single(id) => id.to_binary().to_vec(),
            Self::Quorum(id) => id.to_binary().to_vec(),
        }
    }

    /// Validate internal invariants for fail-closed construction.
    fn validate(&self) -> Result<(), KeyIdError> {
        if let Self::Quorum(id) = self {
            // Digest-first KeySet IDs parsed from text/hash-only forms are
            // explicitly unresolved. For genesis commitments we require an
            // explicit resolved mode tag.
            if id.set_tag().is_none() {
                return Err(KeyIdError::InvalidDescriptor {
                    reason: "quorum policy root must include known set tag".to_string(),
                });
            }
        }
        Ok(())
    }
}

/// Canonical genesis artifact whose commitments define a stable `CellIdV1`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CellGenesisV1 {
    ledger_genesis_hash: [u8; HASH_LEN],
    genesis_policy_root_id: PolicyRootId,
    trust_domain: String,
}

impl CellGenesisV1 {
    /// Construct a validated `CellGenesisV1`.
    pub fn new(
        ledger_genesis_hash: [u8; HASH_LEN],
        genesis_policy_root_id: PolicyRootId,
        trust_domain: impl Into<String>,
    ) -> Result<Self, KeyIdError> {
        genesis_policy_root_id.validate()?;

        let trust_domain = trust_domain.into();
        validate_trust_domain(&trust_domain)?;

        Ok(Self {
            ledger_genesis_hash,
            genesis_policy_root_id,
            trust_domain,
        })
    }

    /// Return the 32-byte ledger genesis hash commitment.
    pub const fn ledger_genesis_hash(&self) -> &[u8; HASH_LEN] {
        &self.ledger_genesis_hash
    }

    /// Return the root policy commitment.
    pub const fn genesis_policy_root_id(&self) -> &PolicyRootId {
        &self.genesis_policy_root_id
    }

    /// Return the trust-domain token.
    pub fn trust_domain(&self) -> &str {
        &self.trust_domain
    }

    /// Deterministic canonical bytes for CAS addressing (HSI 1.7.3b).
    ///
    /// Encoding:
    /// ```text
    /// apm2:cell_genesis:v1\0 + ledger_hash + "\n" + policy_root_binary + "\n" + trust_domain
    /// ```
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let policy_root_bytes = self.genesis_policy_root_id.canonical_bytes();
        let mut out = Vec::with_capacity(
            GENESIS_DOMAIN_SEPARATION.len()
                + HASH_LEN
                + 1
                + policy_root_bytes.len()
                + 1
                + self.trust_domain.len(),
        );

        out.extend_from_slice(GENESIS_DOMAIN_SEPARATION);
        out.extend_from_slice(&self.ledger_genesis_hash);
        out.push(b'\n');
        out.extend_from_slice(&policy_root_bytes);
        out.push(b'\n');
        out.extend_from_slice(self.trust_domain.as_bytes());
        out
    }
}

/// Stable self-certifying cell identity.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CellIdV1 {
    /// Binary form: `version_tag` (1 byte) + `cell_hash` (32 bytes).
    binary: [u8; BINARY_LEN],
}

impl CellIdV1 {
    /// Derive a stable `CellIdV1` from genesis commitments (HSI 1.7.3).
    pub fn from_genesis(genesis: &CellGenesisV1) -> Self {
        let policy_root = genesis.genesis_policy_root_id.canonical_bytes();

        let mut hasher = blake3::Hasher::new();
        hasher.update(DOMAIN_SEPARATION);
        hasher.update(&genesis.ledger_genesis_hash);
        hasher.update(&policy_root);
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

    impl_version_tagged_digest_id!(WIRE_KERNEL, VERSION_TAG_V1, cell_hash);
}

impl_digest_id_fmt!(CellIdV1, "CellIdV1");

/// Validate trust-domain invariants for fail-closed genesis construction.
fn validate_trust_domain(value: &str) -> Result<(), KeyIdError> {
    if value.is_empty() {
        return Err(KeyIdError::InvalidDescriptor {
            reason: "trust_domain must be non-empty".to_string(),
        });
    }
    if !value.is_ascii() {
        return Err(KeyIdError::ContainsNonAscii);
    }
    if value.contains('%') {
        return Err(KeyIdError::ContainsPercentEncoding);
    }
    if value != value.trim() {
        return Err(KeyIdError::ContainsWhitespace);
    }
    if value.chars().any(char::is_whitespace) {
        return Err(KeyIdError::ContainsInteriorWhitespace);
    }
    if value.bytes().any(|b| !(0x21..=0x7E).contains(&b)) {
        return Err(KeyIdError::ContainsControlCharacter);
    }
    if value.len() > MAX_TRUST_DOMAIN_LEN {
        return Err(KeyIdError::InvalidDescriptor {
            reason: format!(
                "trust_domain length {} exceeds maximum of {MAX_TRUST_DOMAIN_LEN}",
                value.len()
            ),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{
        AlgorithmTag, IdentityParseProvenance, IdentitySemanticCompleteness, KeySetIdV1, SetTag,
    };

    fn make_public_key_id(fill: u8) -> PublicKeyIdV1 {
        PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[fill; 32])
    }

    fn make_quorum_keyset() -> KeySetIdV1 {
        let key_a = make_public_key_id(0xA1);
        let key_b = make_public_key_id(0xB2);
        KeySetIdV1::from_descriptor("ed25519", SetTag::Threshold, 1, &[key_a, key_b], None).unwrap()
    }

    fn make_genesis_single() -> CellGenesisV1 {
        CellGenesisV1::new(
            [0x11; 32],
            PolicyRootId::Single(make_public_key_id(0xAB)),
            "cell.example.internal",
        )
        .unwrap()
    }

    #[test]
    fn deterministic_derivation_same_genesis_same_cell_id() {
        let genesis = make_genesis_single();
        let id1 = CellIdV1::from_genesis(&genesis);
        let id2 = CellIdV1::from_genesis(&genesis);
        assert_eq!(id1, id2);
    }

    #[test]
    fn collision_resistance_diff_ledger_hash_diff_cell_id() {
        let policy = PolicyRootId::Single(make_public_key_id(0xAB));
        let g1 = CellGenesisV1::new([0x11; 32], policy.clone(), "cell.example.internal").unwrap();
        let g2 = CellGenesisV1::new([0x22; 32], policy, "cell.example.internal").unwrap();

        let id1 = CellIdV1::from_genesis(&g1);
        let id2 = CellIdV1::from_genesis(&g2);
        assert_ne!(id1, id2);
    }

    #[test]
    fn collision_resistance_diff_policy_root_diff_cell_id() {
        let g1 = CellGenesisV1::new(
            [0x11; 32],
            PolicyRootId::Single(make_public_key_id(0xAA)),
            "cell.example.internal",
        )
        .unwrap();
        let g2 = CellGenesisV1::new(
            [0x11; 32],
            PolicyRootId::Single(make_public_key_id(0xBB)),
            "cell.example.internal",
        )
        .unwrap();

        let id1 = CellIdV1::from_genesis(&g1);
        let id2 = CellIdV1::from_genesis(&g2);
        assert_ne!(id1, id2);
    }

    #[test]
    fn collision_resistance_diff_policy_root_variant_diff_cell_id() {
        let ledger = [0x33; 32];
        let single = CellGenesisV1::new(
            ledger,
            PolicyRootId::Single(make_public_key_id(0xAB)),
            "cell.example.internal",
        )
        .unwrap();
        let quorum = CellGenesisV1::new(
            ledger,
            PolicyRootId::Quorum(make_quorum_keyset()),
            "cell.example.internal",
        )
        .unwrap();

        let id_single = CellIdV1::from_genesis(&single);
        let id_quorum = CellIdV1::from_genesis(&quorum);
        assert_ne!(id_single, id_quorum);
    }

    #[test]
    fn trust_domain_does_not_change_cell_id_but_changes_genesis_artifact() {
        let policy = PolicyRootId::Single(make_public_key_id(0xAB));
        let g1 = CellGenesisV1::new([0x11; 32], policy.clone(), "alpha.example").unwrap();
        let g2 = CellGenesisV1::new([0x11; 32], policy, "beta.example").unwrap();

        // CellIdV1 is intentionally bound to genesis commitments from HSI 1.7.3.
        assert_eq!(CellIdV1::from_genesis(&g1), CellIdV1::from_genesis(&g2));

        // CellGenesisV1 artifacts remain distinct and CAS-addressable.
        assert_ne!(g1.canonical_bytes(), g2.canonical_bytes());
    }

    #[test]
    fn key_rotation_preserves_cell_id_structural_invariant() {
        let genesis = make_genesis_single();
        let id_before = CellIdV1::from_genesis(&genesis);

        // Operational keys may rotate over time, but they are not derivation
        // inputs for CellIdV1.
        let _operational_key_old = make_public_key_id(0x01);
        let _operational_key_new = make_public_key_id(0x02);

        let id_after = CellIdV1::from_genesis(&genesis);
        assert_eq!(id_before, id_after);
    }

    #[test]
    fn genesis_artifact_canonical_bytes_are_deterministic_and_hash_addressable() {
        let genesis = make_genesis_single();

        let c1 = genesis.canonical_bytes();
        let c2 = genesis.canonical_bytes();
        assert_eq!(c1, c2);

        let h1 = blake3::hash(&c1);
        let h2 = blake3::hash(&c2);
        assert_eq!(h1, h2);
    }

    #[test]
    fn text_round_trip() {
        let id = CellIdV1::from_genesis(&make_genesis_single());
        let text = id.to_text();
        let parsed = CellIdV1::parse_text(&text).unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn parse_state_from_text_is_resolved() {
        let id = CellIdV1::from_genesis(&make_genesis_single());
        let (parsed, state) = CellIdV1::parse_text_with_state(&id.to_text()).unwrap();
        assert_eq!(parsed, id);
        assert_eq!(state.provenance(), IdentityParseProvenance::FromText);
        assert_eq!(state.completeness(), IdentitySemanticCompleteness::Resolved);
    }

    #[test]
    fn parse_state_from_tagged_binary_is_resolved() {
        let id = CellIdV1::from_genesis(&make_genesis_single());
        let (parsed, state) = CellIdV1::from_binary_with_state(&id.to_binary()).unwrap();
        assert_eq!(parsed, id);
        assert_eq!(
            state.provenance(),
            IdentityParseProvenance::FromTaggedBinary
        );
        assert_eq!(state.completeness(), IdentitySemanticCompleteness::Resolved);
    }

    #[test]
    fn binary_round_trip() {
        let id = CellIdV1::from_genesis(&make_genesis_single());
        let binary = id.to_binary();
        let parsed = CellIdV1::from_binary(&binary).unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn text_then_binary_round_trip() {
        let id = CellIdV1::from_genesis(&make_genesis_single());
        let text = id.to_text();
        let parsed_text = CellIdV1::parse_text(&text).unwrap();
        let parsed_binary = CellIdV1::from_binary(parsed_text.as_bytes()).unwrap();
        assert_eq!(id, parsed_binary);
    }

    #[test]
    fn text_format_matches_grammar() {
        let id = CellIdV1::from_genesis(&make_genesis_single());
        let text = id.to_text();
        assert!(text.starts_with(PREFIX));
        assert_eq!(text.len(), PREFIX.len() + 64);
        assert!(text.len() <= crate::identity::MAX_TEXT_LEN);
    }

    #[test]
    fn rejects_wrong_prefix() {
        let id = CellIdV1::from_genesis(&make_genesis_single());
        let bad = id.to_text().replacen("cell:", "holon:", 1);
        let err = CellIdV1::parse_text(&bad).unwrap_err();
        assert!(matches!(err, KeyIdError::WrongPrefix { .. }));
    }

    #[test]
    fn rejects_uppercase() {
        let id = CellIdV1::from_genesis(&make_genesis_single());
        let err = CellIdV1::parse_text(&id.to_text().to_ascii_uppercase()).unwrap_err();
        assert_eq!(err, KeyIdError::ContainsUppercase);
    }

    #[test]
    fn rejects_whitespace() {
        let id = CellIdV1::from_genesis(&make_genesis_single());
        let err = CellIdV1::parse_text(&format!(" {}", id.to_text())).unwrap_err();
        assert_eq!(err, KeyIdError::ContainsWhitespace);
    }

    #[test]
    fn rejects_percent_encoded() {
        let err = CellIdV1::parse_text(
            "cell%3av1%3ablake3%3a0000000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap_err();
        assert_eq!(err, KeyIdError::ContainsPercentEncoding);
    }

    #[test]
    fn rejects_non_ascii() {
        let err = CellIdV1::parse_text(
            "cell\u{FF1A}v1:blake3:0000000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap_err();
        assert_eq!(err, KeyIdError::ContainsNonAscii);
    }

    #[test]
    fn rejects_malformed_hex() {
        let err = CellIdV1::parse_text(
            "cell:v1:blake3:g000000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap_err();
        assert_eq!(err, KeyIdError::InvalidHexCharacters);
    }

    #[test]
    fn rejects_unknown_version_tag_binary() {
        let mut binary = CellIdV1::from_genesis(&make_genesis_single()).to_binary();
        binary[0] = 0xFF;
        let err = CellIdV1::from_binary(&binary).unwrap_err();
        assert_eq!(err, KeyIdError::UnknownVersionTag { tag: 0xFF });
    }

    #[test]
    fn rejects_binary_wrong_length() {
        let err = CellIdV1::from_binary(&[0x01; 32]).unwrap_err();
        assert!(matches!(err, KeyIdError::InvalidBinaryLength { got: 32 }));
    }

    #[test]
    fn trust_domain_rejects_empty() {
        let err = CellGenesisV1::new(
            [0x11; 32],
            PolicyRootId::Single(make_public_key_id(0xAB)),
            "",
        )
        .unwrap_err();
        assert!(matches!(err, KeyIdError::InvalidDescriptor { .. }));
    }

    #[test]
    fn trust_domain_rejects_too_long() {
        let too_long = "a".repeat(MAX_TRUST_DOMAIN_LEN + 1);
        let err = CellGenesisV1::new(
            [0x11; 32],
            PolicyRootId::Single(make_public_key_id(0xAB)),
            too_long,
        )
        .unwrap_err();
        assert!(matches!(err, KeyIdError::InvalidDescriptor { .. }));
    }

    #[test]
    fn trust_domain_rejects_whitespace() {
        let err = CellGenesisV1::new(
            [0x11; 32],
            PolicyRootId::Single(make_public_key_id(0xAB)),
            "cell example",
        )
        .unwrap_err();
        assert_eq!(err, KeyIdError::ContainsInteriorWhitespace);
    }

    #[test]
    fn trust_domain_rejects_percent_encoding() {
        let err = CellGenesisV1::new(
            [0x11; 32],
            PolicyRootId::Single(make_public_key_id(0xAB)),
            "cell%2eexample",
        )
        .unwrap_err();
        assert_eq!(err, KeyIdError::ContainsPercentEncoding);
    }

    #[test]
    fn trust_domain_rejects_non_ascii() {
        let err = CellGenesisV1::new(
            [0x11; 32],
            PolicyRootId::Single(make_public_key_id(0xAB)),
            "c\u{00E9}ll.example",
        )
        .unwrap_err();
        assert_eq!(err, KeyIdError::ContainsNonAscii);
    }

    #[test]
    fn trust_domain_accepts_max_len() {
        let max_len = "a".repeat(MAX_TRUST_DOMAIN_LEN);
        let genesis = CellGenesisV1::new(
            [0x11; 32],
            PolicyRootId::Single(make_public_key_id(0xAB)),
            max_len.clone(),
        )
        .unwrap();
        assert_eq!(genesis.trust_domain(), max_len);
    }

    #[test]
    fn rejects_quorum_policy_root_without_known_set_tag() {
        let known_quorum = make_quorum_keyset();
        let unknown_tag_quorum = KeySetIdV1::parse_text(&known_quorum.to_text()).unwrap();
        assert_eq!(unknown_tag_quorum.set_tag(), None);

        let err = CellGenesisV1::new(
            [0x11; 32],
            PolicyRootId::Quorum(unknown_tag_quorum),
            "cell.example.internal",
        )
        .unwrap_err();

        assert!(matches!(err, KeyIdError::InvalidDescriptor { .. }));
    }

    // =========================================================================
    // CAS round-trip tests (REQ-0008 AC#3)
    // =========================================================================

    #[test]
    fn cell_genesis_canonical_bytes_round_trip_in_durable_cas() {
        use tempfile::TempDir;

        use crate::cas::{DurableCas, DurableCasConfig};

        let temp_dir = TempDir::new().unwrap();
        let cas_path = temp_dir.path().join("cas");
        let cas = DurableCas::new(DurableCasConfig::new(&cas_path)).unwrap();

        let genesis = make_genesis_single();
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

    /// Store `CellGenesisV1` canonical bytes into CAS and retrieve by content
    /// hash, verifying the hash/content round-trip invariant.
    #[test]
    fn cell_genesis_cas_round_trip_via_memory_cas() {
        use apm2_core::evidence::{ContentAddressedStore, MemoryCas};

        let cas = MemoryCas::new();
        let genesis = make_genesis_single();
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
    fn cell_genesis_cas_deduplication_and_collision_resistance() {
        use apm2_core::evidence::{ContentAddressedStore, MemoryCas};

        let cas = MemoryCas::new();
        let genesis = make_genesis_single();
        let canonical = genesis.canonical_bytes();

        let r1 = cas.store(&canonical).unwrap();
        let r2 = cas.store(&canonical).unwrap();
        assert!(!r2.is_new, "duplicate store must be deduplicated");
        assert_eq!(r1.hash, r2.hash);

        // Different genesis (different ledger hash) must yield a different CAS hash.
        let genesis2 = CellGenesisV1::new(
            [0x22; 32],
            PolicyRootId::Single(make_public_key_id(0xAB)),
            "cell.example.internal",
        )
        .unwrap();
        let r3 = cas.store(&genesis2.canonical_bytes()).unwrap();
        assert_ne!(
            r1.hash, r3.hash,
            "different genesis must produce different CAS hashes"
        );
    }

    /// Verify that a `CellIdV1` derived from genesis and the genesis canonical
    /// bytes can both be stored and retrieved independently in CAS.
    #[test]
    fn cell_id_and_genesis_cas_independent_storage() {
        use apm2_core::evidence::{ContentAddressedStore, MemoryCas};

        let cas = MemoryCas::new();
        let genesis = make_genesis_single();
        let cell_id = CellIdV1::from_genesis(&genesis);

        let genesis_result = cas.store(&genesis.canonical_bytes()).unwrap();
        let id_result = cas.store(&cell_id.to_binary()).unwrap();

        // Both must be retrievable independently.
        let genesis_bytes = cas.retrieve(&genesis_result.hash).unwrap();
        let id_bytes = cas.retrieve(&id_result.hash).unwrap();

        assert_eq!(genesis_bytes, genesis.canonical_bytes());
        assert_eq!(id_bytes, cell_id.to_binary().as_slice());

        // Hashes must differ (genesis artifact != cell id binary).
        assert_ne!(genesis_result.hash, id_result.hash);
    }

    // =========================================================================
    // MAJOR-1: Control character rejection tests (trust_domain)
    // =========================================================================

    #[test]
    fn trust_domain_rejects_null_byte() {
        let err = CellGenesisV1::new(
            [0x11; 32],
            PolicyRootId::Single(make_public_key_id(0xAB)),
            "cell\0example",
        )
        .unwrap_err();
        assert_eq!(err, KeyIdError::ContainsControlCharacter);
    }

    #[test]
    fn trust_domain_rejects_soh_control() {
        let err = CellGenesisV1::new(
            [0x11; 32],
            PolicyRootId::Single(make_public_key_id(0xAB)),
            "cell\x01example",
        )
        .unwrap_err();
        assert_eq!(err, KeyIdError::ContainsControlCharacter);
    }

    #[test]
    fn trust_domain_rejects_del_control() {
        let err = CellGenesisV1::new(
            [0x11; 32],
            PolicyRootId::Single(make_public_key_id(0xAB)),
            "cell\x7Fexample",
        )
        .unwrap_err();
        assert_eq!(err, KeyIdError::ContainsControlCharacter);
    }
}
