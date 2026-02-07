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
//! # Text Form (RFC-0020 section 1.7.5b)
//!
//! ```text
//! kset:v1:blake3:<64-lowercase-hex>
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
//! # Merkle Root Derivation (RFC-0020 `KeySetDescriptorV1`)
//!
//! The merkle root is computed as:
//! ```text
//! blake3("apm2:keyset_id:v1\0" + canonical_bytes(KeySetDescriptorV1))
//! ```
//!
//! Where `canonical_bytes(KeySetDescriptorV1)` encodes ALL descriptor
//! fields in canonical order:
//! ```text
//! key_algorithm + "\n" + mode_name + "\n" + threshold_k (4-byte LE) + "\n"
//!   + sorted_member_binaries
//!   + [optional: "\n" + weights (each as 8-byte LE)]
//! ```
//!
//! This ensures that different `threshold_k` values, `weights`, or
//! `key_algorithm` produce distinct identifiers for the same member set.
//!
//! Member key IDs are sorted lexicographically by their raw binary form
//! before hashing, ensuring deterministic derivation regardless of input
//! order.
//!
//! # Contract References
//!
//! - RFC-0020 section 1.7.2a: `KeySetIdV1` quorum/threshold verifier identity
//! - RFC-0020 section 1.7.5b: ABNF canonical text forms
//! - REQ-0007: Canonical key identifier formats

use std::fmt;

use super::canonical_digest_id_kit::{CanonicalDigestIdKit, impl_digest_id_fmt};
use super::{AlgorithmTag, BINARY_LEN, HASH_LEN, KeyIdError, PublicKeyIdV1};

/// Prefix for `KeySetIdV1` text form (RFC-0020 canonical grammar).
const PREFIX: &str = "kset:v1:blake3:";
const CODEC: CanonicalDigestIdKit = CanonicalDigestIdKit::new(PREFIX);

/// Domain separation string for BLAKE3 keyset hashing.
const DOMAIN_SEPARATION: &[u8] = b"apm2:keyset_id:v1\0";

/// Maximum number of members allowed in a keyset descriptor.
///
/// This bounds allocations during canonicalization (sorting, hashing) and
/// prevents adversarial descriptors from forcing unbounded memory use.
/// 256 is generous for any practical multisig/threshold scheme.
const MAX_KEYSET_MEMBERS: usize = 256;

/// Maximum byte length of the `key_algorithm` token.
///
/// Algorithm names are already validated as exact canonical matches (e.g.
/// `"ed25519"`), but this cap provides defense-in-depth against oversized
/// inputs reaching the allocation/hash path.
const MAX_ALGORITHM_TOKEN_LEN: usize = 32;

/// Sentinel value for "set tag unknown" (text-parsed IDs).
const UNKNOWN_SET_TAG_SENTINEL: u8 = 0x00;

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
/// Instances contain exactly 32 bytes of BLAKE3 merkle root and an
/// **optional** set tag. The type is cheaply cloneable (33 bytes inline).
///
/// # Tag Semantics
///
/// - When constructed via [`KeySetIdV1::from_descriptor`] or
///   [`KeySetIdV1::from_binary`], the set tag is known and
///   [`KeySetIdV1::set_tag`] returns `Some(tag)`.
/// - When parsed from text via [`KeySetIdV1::parse_text`], the set tag is **not
///   available** because the text form `kset:v1:blake3:<hex>` does not encode
///   the mode. In this case [`KeySetIdV1::set_tag`] returns `None`. To resolve
///   the mode, callers must look up the descriptor via CAS.
///
/// # Construction
///
/// Use [`KeySetIdV1::from_descriptor`] to derive from a full
/// `KeySetDescriptorV1`, or [`KeySetIdV1::parse_text`] /
/// [`KeySetIdV1::from_binary`] for deserialization.
///
/// # Examples
///
/// ```
/// use apm2_daemon::identity::{AlgorithmTag, KeySetIdV1, PublicKeyIdV1, SetTag};
///
/// let key1 = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[0xAA; 32]);
/// let key2 = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[0xBB; 32]);
///
/// let set_id = KeySetIdV1::from_descriptor(
///     "ed25519",
///     SetTag::Multisig,
///     2, // threshold_k = n for multisig
///     &[key1, key2],
///     None, // no weights
/// )
/// .unwrap();
///
/// // Round-trip through text form (text form is hash-only, no tag)
/// let text = set_id.to_text();
/// assert!(text.starts_with("kset:v1:blake3:"));
/// let parsed = KeySetIdV1::parse_text(&text).unwrap();
/// assert_eq!(set_id.merkle_root(), parsed.merkle_root());
/// // Tag is only available from binary/descriptor, not text
/// assert_eq!(set_id.set_tag(), Some(SetTag::Multisig));
/// assert_eq!(parsed.set_tag(), None);
/// ```
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct KeySetIdV1 {
    /// Storage: `tag_or_sentinel` (1 byte) + `merkle_root` (32 bytes).
    ///
    /// When constructed from binary or descriptor, byte 0 is a valid
    /// [`SetTag`] value (0x01 or 0x02). When parsed from text, byte 0 is
    /// 0x00 (sentinel for "tag unknown").
    binary: [u8; BINARY_LEN],
}

impl KeySetIdV1 {
    /// Derive a `KeySetIdV1` from a full `KeySetDescriptorV1`.
    ///
    /// This is the primary constructor that includes ALL descriptor fields
    /// in the hash derivation per RFC-0020:
    ///
    /// - `key_algorithm`: algorithm name (e.g. "ed25519")
    /// - `set_tag`: mode (Multisig or Threshold)
    /// - `threshold_k`: quorum threshold (for Multisig, must equal `n`)
    /// - `members`: the member `PublicKeyIdV1` keys (must be non-empty)
    /// - `weights`: optional per-member weights (length must match members)
    ///
    /// # Validation
    ///
    /// Returns `Err(KeyIdError::InvalidDescriptor)` if:
    /// - `key_algorithm` exceeds `MAX_ALGORITHM_TOKEN_LEN` (32) bytes
    /// - `key_algorithm` is not the canonical lowercase `"ed25519"`
    /// - `members.len()` exceeds `MAX_KEYSET_MEMBERS` (256)
    /// - `members` is empty
    /// - `members` contains duplicate keys (violates set semantics)
    /// - For `Multisig`: `threshold_k != members.len()`
    /// - For `Threshold`: `threshold_k < 1` or `threshold_k > members.len()`
    /// - `weights` is `Some` but its length differs from `members.len()`
    ///
    /// # Deterministic Canonicalization
    ///
    /// Members (and their corresponding weights, if present) are sorted
    /// lexicographically by member binary representation before hashing,
    /// ensuring deterministic derivation regardless of input order.
    ///
    /// The hash is computed as:
    /// ```text
    /// blake3("apm2:keyset_id:v1\0" + key_algorithm + "\n" + mode_name
    ///        + "\n" + threshold_k(4-byte LE) + "\n" + sorted_member_binaries
    ///        + ["\n" + sorted_weights(each 8-byte LE)])
    /// ```
    pub fn from_descriptor(
        key_algorithm: &str,
        set_tag: SetTag,
        threshold_k: u32,
        members: &[PublicKeyIdV1],
        weights: Option<&[u64]>,
    ) -> Result<Self, KeyIdError> {
        // Enforce algorithm token length cap before any further processing.
        if key_algorithm.len() > MAX_ALGORITHM_TOKEN_LEN {
            return Err(KeyIdError::InvalidDescriptor {
                reason: format!(
                    "key_algorithm token length {} exceeds maximum of {MAX_ALGORITHM_TOKEN_LEN}",
                    key_algorithm.len()
                ),
            });
        }

        let canonical_algorithm = AlgorithmTag::Ed25519.name();
        if key_algorithm != canonical_algorithm {
            return Err(KeyIdError::InvalidDescriptor {
                reason: format!(
                    "key_algorithm must be canonical \"{canonical_algorithm}\", got \"{key_algorithm}\""
                ),
            });
        }

        // Enforce member count cap before allocations/sort.
        if members.len() > MAX_KEYSET_MEMBERS {
            return Err(KeyIdError::InvalidDescriptor {
                reason: format!(
                    "members.len() ({}) exceeds maximum of {MAX_KEYSET_MEMBERS}",
                    members.len()
                ),
            });
        }

        // Validate: members must be non-empty
        if members.is_empty() {
            return Err(KeyIdError::InvalidDescriptor {
                reason: "members must be non-empty".to_string(),
            });
        }

        let n = members.len();
        let n_u32 = u32::try_from(n).map_err(|_| KeyIdError::InvalidDescriptor {
            reason: format!("members.len() ({n}) exceeds u32::MAX"),
        })?;

        // Validate threshold_k against mode
        match set_tag {
            SetTag::Multisig => {
                if threshold_k != n_u32 {
                    return Err(KeyIdError::InvalidDescriptor {
                        reason: format!(
                            "Multisig requires threshold_k == members.len(), \
                             got threshold_k={threshold_k}, members.len()={n}"
                        ),
                    });
                }
            },
            SetTag::Threshold => {
                if threshold_k < 1 || threshold_k > n_u32 {
                    return Err(KeyIdError::InvalidDescriptor {
                        reason: format!(
                            "Threshold requires 1 <= threshold_k <= members.len(), \
                             got threshold_k={threshold_k}, members.len()={n}"
                        ),
                    });
                }
            },
        }

        // Validate weights alignment
        if let Some(w) = weights {
            if w.len() != n {
                return Err(KeyIdError::InvalidDescriptor {
                    reason: format!(
                        "weights.len() must equal members.len(), \
                         got weights.len()={}, members.len()={n}",
                        w.len()
                    ),
                });
            }
        }

        // Sort (member, weight) pairs together by member binary for determinism.
        // This ensures that different input orderings of the same logical
        // descriptor always produce the same canonical hash.
        let member_binaries: Vec<[u8; BINARY_LEN]> =
            members.iter().map(PublicKeyIdV1::to_binary).collect();

        let mut indices: Vec<usize> = (0..n).collect();
        indices.sort_unstable_by(|&a, &b| member_binaries[a].cmp(&member_binaries[b]));

        let sorted_binaries: Vec<[u8; BINARY_LEN]> =
            indices.iter().map(|&i| member_binaries[i]).collect();
        let sorted_weights: Option<Vec<u64>> =
            weights.map(|w| indices.iter().map(|&i| w[i]).collect());

        // Reject duplicate member keys. After sorting, duplicates are
        // consecutive, so a single pass over adjacent pairs suffices.
        // This enforces set semantics: each signer must be unique.
        if sorted_binaries.windows(2).any(|w| w[0] == w[1]) {
            return Err(KeyIdError::InvalidDescriptor {
                reason: "duplicate member keys".into(),
            });
        }

        let mut hasher = blake3::Hasher::new();
        hasher.update(DOMAIN_SEPARATION);
        // Include key_algorithm
        hasher.update(key_algorithm.as_bytes());
        hasher.update(b"\n");
        // Include mode name
        hasher.update(set_tag.name().as_bytes());
        hasher.update(b"\n");
        // Include threshold_k as 4-byte little-endian
        hasher.update(&threshold_k.to_le_bytes());
        hasher.update(b"\n");
        // Include sorted member binaries
        for member_binary in &sorted_binaries {
            hasher.update(member_binary);
        }
        // Include optional weights (sorted to match member order)
        if let Some(ref w) = sorted_weights {
            hasher.update(b"\n");
            for weight in w {
                hasher.update(&weight.to_le_bytes());
            }
        }
        let root = hasher.finalize();

        let mut binary = [0u8; BINARY_LEN];
        binary[0] = set_tag.to_byte();
        binary[1..].copy_from_slice(root.as_bytes());
        Ok(Self { binary })
    }

    /// Parse a `KeySetIdV1` from its canonical text form.
    ///
    /// The canonical text form is:
    /// `kset:v1:blake3:<64-lowercase-hex>`
    ///
    /// Enforces:
    /// - Correct `kset:v1:blake3:` prefix
    /// - Strict lowercase hex encoding (0-9, a-f)
    /// - No whitespace, no mixed case, no percent-encoding
    /// - Exactly 64 hex characters (32 bytes)
    ///
    /// # Tag Semantics
    ///
    /// The text form does **not** encode the set tag (mode). The returned
    /// `KeySetIdV1` will have [`set_tag()`](KeySetIdV1::set_tag) returning
    /// `None`. To resolve the mode, callers must look up the full descriptor
    /// via CAS, or use [`from_binary`](KeySetIdV1::from_binary) /
    /// [`from_descriptor`](KeySetIdV1::from_descriptor) which do carry the
    /// tag.
    pub fn parse_text(input: &str) -> Result<Self, KeyIdError> {
        let hash = CODEC.parse_text_hash(input)?;
        let binary = CanonicalDigestIdKit::binary_from_tag_and_hash(UNKNOWN_SET_TAG_SENTINEL, hash);
        Ok(Self { binary })
    }

    /// Construct from binary form.
    ///
    /// Accepted encodings:
    /// - 33 bytes: `set_tag (1 byte) + merkle_root (32 bytes)`
    /// - 32 bytes: `merkle_root` only (tag unknown; stored with sentinel)
    ///
    /// For 33-byte inputs, set tags must be known (`0x01`, `0x02`) except for
    /// the reserved sentinel `0x00`, which represents "tag unknown" and is
    /// used by text-parsed IDs.
    pub fn from_binary(bytes: &[u8]) -> Result<Self, KeyIdError> {
        match bytes.len() {
            HASH_LEN => {
                let mut hash = [0u8; HASH_LEN];
                hash.copy_from_slice(bytes);
                let binary =
                    CanonicalDigestIdKit::binary_from_tag_and_hash(UNKNOWN_SET_TAG_SENTINEL, hash);
                Ok(Self { binary })
            },
            BINARY_LEN => {
                let binary = CODEC.parse_binary_exact(bytes, |tag| {
                    if tag == UNKNOWN_SET_TAG_SENTINEL {
                        Ok(())
                    } else {
                        SetTag::from_byte(tag).map(|_| ())
                    }
                })?;
                Ok(Self { binary })
            },
            _ => Err(KeyIdError::InvalidBinaryLength { got: bytes.len() }),
        }
    }

    /// Return the canonical text form: `kset:v1:blake3:<64-hex>`.
    ///
    /// The text form encodes only the merkle root hash, not the set tag.
    /// Two `KeySetIdV1` values with different set tags but the same merkle
    /// root will produce the same text form. This is by design: the text
    /// form is a content-addressed hash reference; mode resolution requires
    /// a CAS lookup of the full descriptor.
    pub fn to_text(&self) -> String {
        CODEC.to_text(self.merkle_root())
    }

    /// Return the raw binary form (33 bytes).
    pub const fn to_binary(&self) -> [u8; BINARY_LEN] {
        self.binary
    }

    /// Return the set tag, if known.
    ///
    /// Returns `Some(tag)` when constructed via
    /// [`from_descriptor`](Self::from_descriptor)
    /// or [`from_binary`](Self::from_binary), which both carry the tag byte.
    /// Returns `None` when parsed from text via
    /// [`parse_text`](Self::parse_text), because the text form
    /// `kset:v1:blake3:<hex>` does not encode the mode.
    pub fn set_tag(&self) -> Option<SetTag> {
        SetTag::from_byte(self.binary[0]).ok()
    }

    /// Return the 32-byte BLAKE3 merkle root.
    pub fn merkle_root(&self) -> &[u8; HASH_LEN] {
        self.binary[1..]
            .try_into()
            .expect("binary is exactly 33 bytes")
    }

    /// Return a reference to the internal binary form (`tag_or_sentinel +
    /// hash`).
    pub const fn as_bytes(&self) -> &[u8; BINARY_LEN] {
        &self.binary
    }
}

impl_digest_id_fmt!(KeySetIdV1, "KeySetIdV1");

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{AlgorithmTag, PublicKeyIdV1};

    /// Helper: create a test key set with two Ed25519 members.
    fn make_test_keyset() -> KeySetIdV1 {
        let key1 = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[0xAA; 32]);
        let key2 = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[0xBB; 32]);
        KeySetIdV1::from_descriptor("ed25519", SetTag::Multisig, 2, &[key1, key2], None).unwrap()
    }

    #[test]
    fn text_round_trip() {
        let text_origin = KeySetIdV1::parse_text(&make_test_keyset().to_text()).unwrap();
        let reparsed = KeySetIdV1::parse_text(&text_origin.to_text()).unwrap();
        assert_eq!(text_origin, reparsed);
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
        let text_origin = KeySetIdV1::parse_text(&make_test_keyset().to_text()).unwrap();
        let reparsed = KeySetIdV1::from_binary(text_origin.as_bytes()).unwrap();
        assert_eq!(text_origin, reparsed);
    }

    #[test]
    fn from_binary_accepts_hash_only_form() {
        let tagged = make_test_keyset();
        let from_hash_only = KeySetIdV1::from_binary(tagged.merkle_root()).unwrap();
        let expected = KeySetIdV1::parse_text(&tagged.to_text()).unwrap();
        assert_eq!(from_hash_only, expected);
        assert_eq!(from_hash_only.set_tag(), None);
    }

    #[test]
    fn text_format_matches_rfc() {
        let id = make_test_keyset();
        let text = id.to_text();
        assert!(
            text.starts_with("kset:v1:blake3:"),
            "text form must start with RFC-0020 prefix, got: {text}"
        );
        // Prefix (15) + 64 hex = 79 total
        assert_eq!(
            text.len(),
            79,
            "text form must be exactly 79 characters, got: {}",
            text.len()
        );
    }

    #[test]
    fn member_order_does_not_matter() {
        let key1 = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[0xAA; 32]);
        let key2 = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[0xBB; 32]);

        let id_ab = KeySetIdV1::from_descriptor(
            "ed25519",
            SetTag::Multisig,
            2,
            &[key1.clone(), key2.clone()],
            None,
        )
        .unwrap();
        let id_ba =
            KeySetIdV1::from_descriptor("ed25519", SetTag::Multisig, 2, &[key2, key1], None)
                .unwrap();

        assert_eq!(id_ab, id_ba);
    }

    #[test]
    fn different_members_produce_different_ids() {
        let key1 = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[0xAA; 32]);
        let key2 = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[0xBB; 32]);
        let key3 = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[0xCC; 32]);

        let id1 = KeySetIdV1::from_descriptor(
            "ed25519",
            SetTag::Multisig,
            2,
            &[key1.clone(), key2],
            None,
        )
        .unwrap();
        let id2 = KeySetIdV1::from_descriptor("ed25519", SetTag::Multisig, 2, &[key1, key3], None)
            .unwrap();

        assert_ne!(id1, id2);
    }

    #[test]
    fn different_tags_produce_different_ids() {
        let key1 = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[0xAA; 32]);
        let key2 = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[0xBB; 32]);

        let id_multi = KeySetIdV1::from_descriptor(
            "ed25519",
            SetTag::Multisig,
            2,
            &[key1.clone(), key2.clone()],
            None,
        )
        .unwrap();
        let id_thresh =
            KeySetIdV1::from_descriptor("ed25519", SetTag::Threshold, 1, &[key1, key2], None)
                .unwrap();

        assert_ne!(id_multi, id_thresh);
        assert_ne!(id_multi.merkle_root(), id_thresh.merkle_root());
    }

    #[test]
    fn different_threshold_k_produces_different_ids() {
        let key1 = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[0xAA; 32]);
        let key2 = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[0xBB; 32]);
        let key3 = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[0xCC; 32]);

        let id_1of3 = KeySetIdV1::from_descriptor(
            "ed25519",
            SetTag::Threshold,
            1,
            &[key1.clone(), key2.clone(), key3.clone()],
            None,
        )
        .unwrap();
        let id_2of3 =
            KeySetIdV1::from_descriptor("ed25519", SetTag::Threshold, 2, &[key1, key2, key3], None)
                .unwrap();

        assert_ne!(id_1of3, id_2of3);
        assert_ne!(id_1of3.merkle_root(), id_2of3.merkle_root());
    }

    #[test]
    fn different_weights_produce_different_ids() {
        let key1 = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[0xAA; 32]);
        let key2 = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[0xBB; 32]);

        let id_no_weights = KeySetIdV1::from_descriptor(
            "ed25519",
            SetTag::Threshold,
            1,
            &[key1.clone(), key2.clone()],
            None,
        )
        .unwrap();
        let id_with_weights = KeySetIdV1::from_descriptor(
            "ed25519",
            SetTag::Threshold,
            1,
            &[key1.clone(), key2.clone()],
            Some(&[1, 2]),
        )
        .unwrap();
        let id_diff_weights = KeySetIdV1::from_descriptor(
            "ed25519",
            SetTag::Threshold,
            1,
            &[key1, key2],
            Some(&[3, 4]),
        )
        .unwrap();

        assert_ne!(id_no_weights, id_with_weights);
        assert_ne!(id_with_weights, id_diff_weights);
    }

    /// Regression test: weighted keyset canonicalization must sort (member,
    /// weight) pairs together, so different input orderings of the same
    /// logical descriptor produce identical IDs.
    #[test]
    fn weighted_keyset_order_independent() {
        let key1 = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[0xBB; 32]);
        let key2 = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[0xAA; 32]);

        // Order 1: [key1=BB, key2=AA] with weights [10, 20]
        let id_ab = KeySetIdV1::from_descriptor(
            "ed25519",
            SetTag::Threshold,
            1,
            &[key1.clone(), key2.clone()],
            Some(&[10, 20]),
        )
        .unwrap();

        // Order 2: [key2=AA, key1=BB] with weights [20, 10]
        // Same logical descriptor, different input order.
        let id_ba = KeySetIdV1::from_descriptor(
            "ed25519",
            SetTag::Threshold,
            1,
            &[key2, key1],
            Some(&[20, 10]),
        )
        .unwrap();

        assert_eq!(
            id_ab, id_ba,
            "different input orderings of the same (member, weight) pairs \
             must produce identical KeySetIdV1"
        );
    }

    #[test]
    fn rejects_wrong_prefix() {
        let id = make_test_keyset();
        let text = id.to_text().replacen("kset:", "pkid:", 1);
        let err = KeySetIdV1::parse_text(&text).unwrap_err();
        assert!(matches!(err, KeyIdError::WrongPrefix { .. }));
    }

    #[test]
    fn rejects_old_prefix() {
        // Old "ks1:" format must be rejected
        let err =
            KeySetIdV1::parse_text("ks1:aglcich4juqooex7i3hp3fgxs3qdgiyl4e7zxjc57ez7daj76ukym")
                .unwrap_err();
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
        let err = KeySetIdV1::parse_text("kset:v1:blake3:ab").unwrap_err();
        assert!(
            matches!(err, KeyIdError::HexLengthMismatch { .. }),
            "expected HexLengthMismatch, got {err:?}"
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
        assert!(display.starts_with("kset:v1:blake3:"));
        assert!(debug.contains("KeySetIdV1"));
        assert!(debug.contains("kset:v1:blake3:"));
    }

    #[test]
    fn from_str_trait() {
        let id = make_test_keyset();
        let text = id.to_text();
        let parsed: KeySetIdV1 = text.parse().unwrap();
        assert_eq!(id.merkle_root(), parsed.merkle_root());
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
        assert_eq!(id.set_tag(), Some(SetTag::Multisig));
        assert_eq!(id.merkle_root().len(), 32);
        assert_eq!(id.as_bytes().len(), 33);
    }

    #[test]
    fn text_parsed_has_no_tag() {
        let id = make_test_keyset();
        let text = id.to_text();
        let parsed = KeySetIdV1::parse_text(&text).unwrap();
        assert_eq!(parsed.set_tag(), None, "text-parsed IDs must have no tag");
        assert_eq!(id.set_tag(), Some(SetTag::Multisig));
    }

    // --- Descriptor validation tests ---

    #[test]
    fn rejects_empty_members() {
        let err =
            KeySetIdV1::from_descriptor("ed25519", SetTag::Multisig, 0, &[], None).unwrap_err();
        assert!(
            matches!(err, KeyIdError::InvalidDescriptor { .. }),
            "expected InvalidDescriptor, got {err:?}"
        );
    }

    #[test]
    fn rejects_multisig_threshold_mismatch() {
        let key1 = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[0xAA; 32]);
        let key2 = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[0xBB; 32]);

        // Multisig with threshold_k != n
        let err = KeySetIdV1::from_descriptor("ed25519", SetTag::Multisig, 1, &[key1, key2], None)
            .unwrap_err();
        assert!(
            matches!(err, KeyIdError::InvalidDescriptor { .. }),
            "expected InvalidDescriptor, got {err:?}"
        );
    }

    #[test]
    fn rejects_threshold_k_zero() {
        let key1 = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[0xAA; 32]);

        let err = KeySetIdV1::from_descriptor("ed25519", SetTag::Threshold, 0, &[key1], None)
            .unwrap_err();
        assert!(
            matches!(err, KeyIdError::InvalidDescriptor { .. }),
            "expected InvalidDescriptor for threshold_k=0, got {err:?}"
        );
    }

    #[test]
    fn rejects_threshold_k_exceeds_n() {
        let key1 = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[0xAA; 32]);
        let key2 = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[0xBB; 32]);

        let err = KeySetIdV1::from_descriptor("ed25519", SetTag::Threshold, 3, &[key1, key2], None)
            .unwrap_err();
        assert!(
            matches!(err, KeyIdError::InvalidDescriptor { .. }),
            "expected InvalidDescriptor for threshold_k > n, got {err:?}"
        );
    }

    #[test]
    fn rejects_weights_length_mismatch() {
        let key1 = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[0xAA; 32]);
        let key2 = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[0xBB; 32]);

        let err = KeySetIdV1::from_descriptor(
            "ed25519",
            SetTag::Threshold,
            1,
            &[key1, key2],
            Some(&[1, 2, 3]), // 3 weights for 2 members
        )
        .unwrap_err();
        assert!(
            matches!(err, KeyIdError::InvalidDescriptor { .. }),
            "expected InvalidDescriptor for weights/members mismatch, got {err:?}"
        );
    }

    #[test]
    fn rejects_non_canonical_algorithm_camel_case() {
        let key1 = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[0xAA; 32]);
        let err = KeySetIdV1::from_descriptor("Ed25519", SetTag::Threshold, 1, &[key1], None)
            .unwrap_err();
        assert!(
            matches!(err, KeyIdError::InvalidDescriptor { .. }),
            "expected InvalidDescriptor for non-canonical algorithm, got {err:?}"
        );
    }

    #[test]
    fn rejects_non_canonical_algorithm_uppercase() {
        let key1 = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[0xAA; 32]);
        let err = KeySetIdV1::from_descriptor("ED25519", SetTag::Threshold, 1, &[key1], None)
            .unwrap_err();
        assert!(
            matches!(err, KeyIdError::InvalidDescriptor { .. }),
            "expected InvalidDescriptor for non-canonical algorithm, got {err:?}"
        );
    }

    #[test]
    fn rejects_percent_encoded() {
        let err = KeySetIdV1::parse_text(
            "kset%3av1%3ablake3%3a0000000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap_err();
        assert_eq!(err, KeyIdError::ContainsPercentEncoding);
    }

    #[test]
    fn rejects_non_ascii_unicode() {
        let err = KeySetIdV1::parse_text(
            "kset\u{FF1A}v1:blake3:0000000000000000000000000000000000000000000000000000000000000000",
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
            "k\u{00E9}1:stuff",                 // multi-byte char overlapping prefix boundary
            "\u{0301}\u{0301}\u{0301}\u{0301}", // combining accents
        ];
        for input in &inputs {
            let result = KeySetIdV1::parse_text(input);
            assert!(
                result.is_err(),
                "expected Err for malformed Unicode input {input:?}, got Ok"
            );
        }
    }

    // --- Duplicate member rejection tests ---

    /// Regression: exact same key appearing twice in multisig must be rejected.
    #[test]
    fn rejects_duplicate_member_keys_multisig() {
        let key = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[0xAA; 32]);
        let err =
            KeySetIdV1::from_descriptor("ed25519", SetTag::Multisig, 2, &[key.clone(), key], None)
                .unwrap_err();
        match err {
            KeyIdError::InvalidDescriptor { reason } => {
                assert!(
                    reason.contains("duplicate member keys"),
                    "expected 'duplicate member keys' in reason, got: {reason}"
                );
            },
            other => panic!("expected InvalidDescriptor, got {other:?}"),
        }
    }

    /// Regression: same key appearing twice in a weighted threshold descriptor
    /// must be rejected even when weights differ.
    #[test]
    fn rejects_duplicate_member_keys_weighted_threshold() {
        let key = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[0xBB; 32]);
        let err = KeySetIdV1::from_descriptor(
            "ed25519",
            SetTag::Threshold,
            1,
            &[key.clone(), key],
            Some(&[10, 20]),
        )
        .unwrap_err();
        match err {
            KeyIdError::InvalidDescriptor { reason } => {
                assert!(
                    reason.contains("duplicate member keys"),
                    "expected 'duplicate member keys' in reason, got: {reason}"
                );
            },
            other => panic!("expected InvalidDescriptor, got {other:?}"),
        }
    }

    /// Unique keys must still be accepted (positive control for duplicate
    /// check).
    #[test]
    fn accepts_unique_member_keys() {
        let key1 = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[0xAA; 32]);
        let key2 = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[0xBB; 32]);
        let result =
            KeySetIdV1::from_descriptor("ed25519", SetTag::Multisig, 2, &[key1, key2], None);
        assert!(
            result.is_ok(),
            "unique member keys must be accepted, got: {result:?}"
        );
    }

    // --- Descriptor size cap tests ---

    /// Helper: create a unique key from a `usize` index by encoding it in
    /// the first 4 bytes of the key material (little-endian).
    fn key_from_index(i: usize) -> PublicKeyIdV1 {
        let mut key_bytes = [0u8; 32];
        let le = u32::try_from(i).expect("test index fits u32").to_le_bytes();
        key_bytes[..4].copy_from_slice(&le);
        PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &key_bytes)
    }

    /// Member count exceeding `MAX_KEYSET_MEMBERS` must be rejected.
    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn rejects_members_exceeding_max_cap() {
        let count = MAX_KEYSET_MEMBERS + 1;
        let members: Vec<PublicKeyIdV1> = (0..count).map(key_from_index).collect();
        assert!(
            members.len() > MAX_KEYSET_MEMBERS,
            "test precondition: need > {MAX_KEYSET_MEMBERS} members"
        );
        let n = u32::try_from(members.len()).unwrap();
        let err = KeySetIdV1::from_descriptor("ed25519", SetTag::Multisig, n, &members, None)
            .unwrap_err();
        match err {
            KeyIdError::InvalidDescriptor { reason } => {
                assert!(
                    reason.contains("exceeds maximum"),
                    "expected 'exceeds maximum' in reason, got: {reason}"
                );
            },
            other => panic!("expected InvalidDescriptor, got {other:?}"),
        }
    }

    /// Exactly `MAX_KEYSET_MEMBERS` members must still be accepted.
    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn accepts_members_at_max_cap() {
        let members: Vec<PublicKeyIdV1> = (0..MAX_KEYSET_MEMBERS).map(key_from_index).collect();
        assert_eq!(members.len(), MAX_KEYSET_MEMBERS);
        let n = u32::try_from(members.len()).unwrap();
        let result = KeySetIdV1::from_descriptor("ed25519", SetTag::Multisig, n, &members, None);
        assert!(
            result.is_ok(),
            "exactly {MAX_KEYSET_MEMBERS} unique members must be accepted, got: {result:?}"
        );
    }

    /// Algorithm token exceeding `MAX_ALGORITHM_TOKEN_LEN` must be rejected
    /// before reaching the canonical algorithm check.
    #[test]
    fn rejects_algorithm_token_exceeding_max_len() {
        let key = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[0xAA; 32]);
        let long_alg = "a".repeat(MAX_ALGORITHM_TOKEN_LEN + 1);
        let err =
            KeySetIdV1::from_descriptor(&long_alg, SetTag::Threshold, 1, &[key], None).unwrap_err();
        match err {
            KeyIdError::InvalidDescriptor { reason } => {
                assert!(
                    reason.contains("exceeds maximum"),
                    "expected 'exceeds maximum' in reason, got: {reason}"
                );
            },
            other => panic!("expected InvalidDescriptor, got {other:?}"),
        }
    }

    /// Algorithm token at exactly `MAX_ALGORITHM_TOKEN_LEN` must still be
    /// checked against the canonical algorithm (and rejected as non-canonical,
    /// not as too-long).
    #[test]
    fn algorithm_token_at_max_len_still_checked_canonical() {
        let key = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[0xAA; 32]);
        // 32 chars is within cap but not "ed25519"
        let at_max = "a".repeat(MAX_ALGORITHM_TOKEN_LEN);
        let err =
            KeySetIdV1::from_descriptor(&at_max, SetTag::Threshold, 1, &[key], None).unwrap_err();
        match err {
            KeyIdError::InvalidDescriptor { reason } => {
                assert!(
                    reason.contains("key_algorithm must be canonical"),
                    "expected canonical algorithm error, got: {reason}"
                );
            },
            other => {
                panic!("expected InvalidDescriptor for non-canonical algorithm, got {other:?}")
            },
        }
    }
}
