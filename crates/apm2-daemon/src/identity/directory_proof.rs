//! Directory-head and proof-carrying identity artifacts (RFC-0020 §1.7.7).
//!
//! This module introduces:
//! - `HolonDirectoryHeadV1`
//! - `DirectoryProofV1`
//! - `IdentityProofV1`
//!
//! These artifacts provide bounded, deterministic, CAS-addressable identity
//! verification inputs for boundary-crossing authority decisions.

use std::collections::{HashMap, VecDeque};

use apm2_core::crypto::Hash;
use apm2_core::evidence::{CasError, ContentAddressedStore};
use apm2_core::fac::RiskTier;
use thiserror::Error;
use tracing::warn;

use super::{
    CellCertificateV1, CellIdV1, CertificateError, HolonCertificateV1, HolonGenesisV1, HolonIdV1,
    KeyIdError, PublicKeyIdV1,
};

const DIRECTORY_HEAD_DOMAIN_SEPARATOR: &[u8] = b"apm2:holon_directory_head:v1\0";
const DIRECTORY_PROOF_DOMAIN_SEPARATOR: &[u8] = b"apm2:directory_proof:v1\0";
const IDENTITY_PROOF_DOMAIN_SEPARATOR: &[u8] = b"apm2:identity_proof:v1\0";
const IDENTITY_PROOF_PROFILE_DOMAIN_SEPARATOR: &[u8] = b"apm2:identity_proof_profile.v1\n";
const DIRECTORY_KEY_DOMAIN_SEPARATOR: &[u8] = b"apm2:dir_key:v1\n";
const DIRECTORY_LEAF_DOMAIN_SEPARATOR: &[u8] = b"apm2:dir_leaf:v1\0";
const DIRECTORY_NODE_DOMAIN_SEPARATOR: &[u8] = b"apm2:dir_node:v1\0";
const DIRECTORY_EMPTY_VALUE_DOMAIN_SEPARATOR: &[u8] = b"apm2:dir_value:empty:v1\0";

const HASH_BYTES: usize = 32;
const CELL_ID_BINARY_BYTES: usize = 33;

/// Absolute upper bound for serialized `HolonDirectoryHeadV1` bytes.
pub const MAX_DIRECTORY_HEAD_BYTES: usize = 4 * 1024;
/// Absolute upper bound for serialized `DirectoryProofV1` bytes.
pub const MAX_DIRECTORY_PROOF_BYTES: usize = 64 * 1024;
/// Absolute upper bound for serialized `IdentityProofV1` bytes.
pub const MAX_IDENTITY_PROOF_BYTES: usize = 128 * 1024;
/// Absolute upper bound for serialized `IdentityProofProfileV1` bytes.
pub const MAX_IDENTITY_PROOF_PROFILE_BYTES: usize = 4 * 1024;
/// Maximum allowed sibling nodes in `DirectoryProofV1`.
pub const MAX_DIRECTORY_SIBLINGS: usize = 256;
/// SMT verifier depth cap for 10^12 namespace target (`ceil(log2(10^12)) ~=
/// 40`) with safety margin.
pub const MAX_SMT_DEPTH: u32 = 48;
/// Minimum profile depth for 10^12 namespace target.
pub const MIN_SMT_DEPTH_10E12: u32 = 40;
/// Maximum hash operations per membership proof for the baseline profile.
pub const MAX_HASH_OPS_PER_MEMBERSHIP_PROOF_10E12: u32 = 96;

/// Errors for directory-head/proof parsing and verification.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum IdentityProofError {
    /// Underlying CAS operation failed.
    #[error("CAS operation failed: {0}")]
    Cas(String),

    /// Underlying certificate/key validation failed.
    #[error("certificate validation failed: {0}")]
    Certificate(String),

    /// Input exceeds configured pre-decode bound.
    #[error("decode bound exceeded: size {size} > max {max}")]
    DecodeBoundExceeded {
        /// Input size in bytes.
        size: usize,
        /// Configured bound in bytes.
        max: usize,
    },

    /// Input uses an unexpected domain separator.
    #[error("invalid domain separator for {kind}")]
    InvalidDomainSeparator {
        /// Artifact kind being decoded.
        kind: &'static str,
    },

    /// Input ended before a complete field was available.
    #[error("truncated input while reading {field}")]
    Truncated {
        /// Field being decoded.
        field: &'static str,
    },

    /// Extra bytes remained after decoding completed.
    #[error("trailing bytes after {kind} decode: {remaining}")]
    TrailingBytes {
        /// Artifact kind being decoded.
        kind: &'static str,
        /// Remaining trailing bytes.
        remaining: usize,
    },

    /// Invalid enum tag in encoded bytes.
    #[error("invalid enum tag for {field}: 0x{tag:02x}")]
    InvalidEnumTag {
        /// Enum field name.
        field: &'static str,
        /// Raw tag byte.
        tag: u8,
    },

    /// Invalid field value.
    #[error("invalid {field}: {reason}")]
    InvalidField {
        /// Field name.
        field: &'static str,
        /// Human-readable reason.
        reason: String,
    },

    /// Proof exceeds a directory-head-provided bound.
    #[error("proof_bytes_len {proof_bytes_len} exceeds max_proof_bytes {max_proof_bytes}")]
    ProofBytesExceeded {
        /// Encoded proof byte length from proof artifact.
        proof_bytes_len: u32,
        /// Directory head policy bound.
        max_proof_bytes: u32,
    },

    /// Encoded proof length field is inconsistent with actual bytes.
    #[error("proof_bytes_len mismatch: declared {declared}, actual {actual} for {artifact_kind}")]
    ProofLengthMismatch {
        /// Artifact kind.
        artifact_kind: &'static str,
        /// Declared length in bytes.
        declared: u32,
        /// Actual serialized length in bytes.
        actual: usize,
    },

    /// Unsupported proof kind for this implementation phase.
    #[error("unsupported directory proof kind: {kind:?}")]
    UnsupportedDirectoryProofKind {
        /// Proof kind.
        kind: DirectoryProofKindV1,
    },

    /// Directory proof has too many siblings.
    #[error("sibling count {count} exceeds max {max}")]
    TooManySiblings {
        /// Actual sibling count.
        count: usize,
        /// Maximum allowed sibling count.
        max: usize,
    },

    /// Proof depth exceeds policy/profile bound.
    #[error("proof depth {depth} exceeds max_depth {max_depth}")]
    DepthExceeded {
        /// Actual sibling depth.
        depth: usize,
        /// Allowed maximum depth.
        max_depth: u32,
    },

    /// Proof has too many non-default siblings for configured economics.
    #[error("non-default sibling count {count} exceeds max {max}")]
    NonDefaultSiblingsExceeded {
        /// Actual non-default sibling count.
        count: usize,
        /// Allowed maximum count.
        max: u32,
    },

    /// SMT proof depth exceeded 256-bit key space.
    #[error("SMT proof depth {depth} exceeds 256-bit key space")]
    SmtDepthExceeded {
        /// Attempted depth.
        depth: usize,
    },

    /// Directory root reconstruction mismatch.
    #[error("directory root hash mismatch")]
    DirectoryRootMismatch,

    /// Directory proof key does not match derived key from holon id.
    #[error("directory proof key does not match derived key for holon id")]
    DirectoryKeyMismatch,

    /// Hash commitment mismatch.
    #[error("hash mismatch for {field}")]
    HashMismatch {
        /// Field being compared.
        field: &'static str,
    },

    /// Directory kind in head is incompatible with proof kind.
    #[error(
        "directory kind mismatch: head kind {head_kind:?} is incompatible with proof kind {proof_kind:?}"
    )]
    DirectoryKindMismatch {
        /// Head directory kind.
        head_kind: DirectoryKindV1,
        /// Proof kind.
        proof_kind: DirectoryProofKindV1,
    },

    /// Value hash mismatch between proof and caller expectation.
    #[error("directory entry value_hash mismatch: expected {field}")]
    ValueHashMismatch {
        /// Field being compared.
        field: &'static str,
    },

    /// Directory entry has been revoked; authoritative operations are denied.
    #[error("directory entry is revoked; authoritative operations denied")]
    EntryRevoked,

    /// Missing `cell_certificate_hash` when direct trust is not pinned.
    #[error("cell_certificate_hash is required unless direct trust is pinned")]
    MissingCellCertificateHash,

    /// Cell binding mismatch between artifacts.
    #[error("cell binding mismatch between artifacts")]
    CellBindingMismatch,

    /// Holon binding mismatch between artifacts.
    #[error("holon binding mismatch between artifacts")]
    HolonBindingMismatch,

    /// Freshness policy mismatch between expected policy and head binding.
    #[error("freshness policy hash mismatch")]
    FreshnessPolicyMismatch,

    /// Identity proof profile kind does not match proof kind.
    #[error("identity proof profile kind mismatch: profile {profile_kind:?}, proof {proof_kind:?}")]
    IdentityProofProfileKindMismatch {
        /// Profile-advertised proof kind.
        profile_kind: DirectoryProofKindV1,
        /// Proof-advertised kind.
        proof_kind: DirectoryProofKindV1,
    },

    /// Directory head profile hash is not recognized by this verifier.
    #[error("unknown identity proof profile hash: {profile_hash_hex}")]
    UnknownIdentityProofProfile {
        /// Unknown profile hash in lowercase hex.
        profile_hash_hex: String,
    },

    /// Directory head profile hash does not match expected profile hash.
    #[error(
        "identity proof profile hash mismatch: head {head_profile_hash_hex}, profile {profile_hash_hex}"
    )]
    IdentityProofProfileHashMismatch {
        /// Profile hash pinned in the directory head.
        head_profile_hash_hex: String,
        /// Canonical hash of the provided profile.
        profile_hash_hex: String,
    },

    /// Current tick predates proof generation tick.
    #[error("proof not yet valid at current tick {current_tick}; generated_at {generated_at_tick}")]
    ProofNotYetValid {
        /// Verifier tick.
        current_tick: u64,
        /// Proof generation tick.
        generated_at_tick: u64,
    },

    /// Proof is stale under configured staleness policy.
    #[error("proof stale: age_ticks {age_ticks} exceeds max_staleness_ticks {max_staleness_ticks}")]
    ProofStale {
        /// Computed age in ticks.
        age_ticks: u64,
        /// Maximum allowed staleness in ticks.
        max_staleness_ticks: u64,
    },

    /// Requested head is not cached in verifier.
    #[error("verified head cache miss")]
    VerifiedHeadCacheMiss,

    /// Admission of a stale head was rejected because a newer epoch for the
    /// same cell already exists in the cache.
    #[error(
        "stale epoch rejected: admitted epoch {admitted_epoch} is older than cached epoch {cached_epoch} for same cell"
    )]
    StaleEpochRejected {
        /// The epoch of the head being admitted.
        admitted_epoch: u64,
        /// The highest epoch already cached for the same cell.
        cached_epoch: u64,
    },
}

impl From<CasError> for IdentityProofError {
    fn from(value: CasError) -> Self {
        Self::Cas(value.to_string())
    }
}

impl From<CertificateError> for IdentityProofError {
    fn from(value: CertificateError) -> Self {
        Self::Certificate(value.to_string())
    }
}

impl From<KeyIdError> for IdentityProofError {
    fn from(value: KeyIdError) -> Self {
        Self::Certificate(value.to_string())
    }
}

/// Directory commitment kind advertised by a directory head.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum DirectoryKindV1 {
    /// Sparse Merkle tree in a 256-bit key space.
    Smt256V1       = 0x01,
    /// Patricia trie authenticated dictionary.
    PatriciaTrieV1 = 0x02,
}

impl DirectoryKindV1 {
    const fn from_byte(tag: u8) -> Result<Self, IdentityProofError> {
        match tag {
            0x01 => Ok(Self::Smt256V1),
            0x02 => Ok(Self::PatriciaTrieV1),
            _ => Err(IdentityProofError::InvalidEnumTag {
                field: "directory_kind",
                tag,
            }),
        }
    }

    const fn to_byte(self) -> u8 {
        self as u8
    }
}

/// Ledger anchor commitment bound into a directory head.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum LedgerAnchorV1 {
    /// Sequence/event hash anchor.
    SeqEvent {
        /// Monotonic sequence identifier.
        seq_id: u64,
        /// Event hash at `seq_id`.
        event_hash: [u8; HASH_BYTES],
    },
    /// Consensus index anchor.
    ConsensusIndex {
        /// Consensus index.
        index: u64,
    },
}

impl LedgerAnchorV1 {
    /// Returns the canonical byte representation of this ledger anchor.
    ///
    /// Used for domain-separated preimage construction in authority seals
    /// and directory heads.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        match self {
            Self::SeqEvent { seq_id, event_hash } => {
                let mut out = Vec::with_capacity(1 + 8 + HASH_BYTES);
                out.push(0x01);
                out.extend_from_slice(&seq_id.to_le_bytes());
                out.extend_from_slice(event_hash);
                out
            },
            Self::ConsensusIndex { index } => {
                let mut out = Vec::with_capacity(1 + 8);
                out.push(0x02);
                out.extend_from_slice(&index.to_le_bytes());
                out
            },
        }
    }
}

/// Authenticated directory head commitment for identity verification.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HolonDirectoryHeadV1 {
    cell_id: CellIdV1,
    directory_epoch: u64,
    ledger_anchor: LedgerAnchorV1,
    directory_root_hash: [u8; HASH_BYTES],
    directory_kind: DirectoryKindV1,
    entry_count: u64,
    max_proof_bytes: u32,
    identity_proof_profile_hash: [u8; HASH_BYTES],
    authority_seal_hash: [u8; HASH_BYTES],
    freshness_policy_hash: [u8; HASH_BYTES],
    prev_head_hash: Option<[u8; HASH_BYTES]>,
}

impl HolonDirectoryHeadV1 {
    /// Constructs a validated directory head.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        cell_id: CellIdV1,
        directory_epoch: u64,
        ledger_anchor: LedgerAnchorV1,
        directory_root_hash: [u8; HASH_BYTES],
        directory_kind: DirectoryKindV1,
        entry_count: u64,
        max_proof_bytes: u32,
        identity_proof_profile_hash: [u8; HASH_BYTES],
        authority_seal_hash: [u8; HASH_BYTES],
        freshness_policy_hash: [u8; HASH_BYTES],
        prev_head_hash: Option<[u8; HASH_BYTES]>,
    ) -> Result<Self, IdentityProofError> {
        let head = Self {
            cell_id,
            directory_epoch,
            ledger_anchor,
            directory_root_hash,
            directory_kind,
            entry_count,
            max_proof_bytes,
            identity_proof_profile_hash,
            authority_seal_hash,
            freshness_policy_hash,
            prev_head_hash,
        };
        head.validate()?;
        Ok(head)
    }

    /// Validates fail-closed structural invariants.
    pub fn validate(&self) -> Result<(), IdentityProofError> {
        if self.max_proof_bytes == 0 {
            return Err(IdentityProofError::InvalidField {
                field: "max_proof_bytes",
                reason: "must be non-zero".to_string(),
            });
        }

        if usize::try_from(self.max_proof_bytes).ok() > Some(MAX_DIRECTORY_PROOF_BYTES) {
            return Err(IdentityProofError::InvalidField {
                field: "max_proof_bytes",
                reason: format!(
                    "{} exceeds absolute verifier cap {MAX_DIRECTORY_PROOF_BYTES}",
                    self.max_proof_bytes
                ),
            });
        }

        if self.directory_root_hash == [0u8; HASH_BYTES] {
            return Err(IdentityProofError::InvalidField {
                field: "directory_root_hash",
                reason: "must be non-zero".to_string(),
            });
        }

        if self.identity_proof_profile_hash == [0u8; HASH_BYTES] {
            return Err(IdentityProofError::InvalidField {
                field: "identity_proof_profile_hash",
                reason: "must be non-zero".to_string(),
            });
        }

        if self.authority_seal_hash == [0u8; HASH_BYTES] {
            return Err(IdentityProofError::InvalidField {
                field: "authority_seal_hash",
                reason: "must be non-zero".to_string(),
            });
        }

        if self.freshness_policy_hash == [0u8; HASH_BYTES] {
            return Err(IdentityProofError::InvalidField {
                field: "freshness_policy_hash",
                reason: "must be non-zero".to_string(),
            });
        }

        if self.prev_head_hash == Some([0u8; HASH_BYTES]) {
            return Err(IdentityProofError::InvalidField {
                field: "prev_head_hash",
                reason: "when present, must be non-zero".to_string(),
            });
        }

        Ok(())
    }

    /// Deterministic canonical bytes for CAS addressing.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, IdentityProofError> {
        self.validate()?;

        let anchor_bytes = self.ledger_anchor.canonical_bytes();
        let mut out = Vec::with_capacity(
            DIRECTORY_HEAD_DOMAIN_SEPARATOR.len()
                + CELL_ID_BINARY_BYTES
                + 8
                + anchor_bytes.len()
                + 1
                + HASH_BYTES
                + 8
                + 4
                + HASH_BYTES
                + HASH_BYTES
                + HASH_BYTES
                + 1
                + self.prev_head_hash.map_or(0, |_| HASH_BYTES),
        );

        out.extend_from_slice(DIRECTORY_HEAD_DOMAIN_SEPARATOR);
        out.extend_from_slice(&self.cell_id.to_binary());
        out.extend_from_slice(&self.directory_epoch.to_le_bytes());
        out.extend_from_slice(&anchor_bytes);
        out.push(self.directory_kind.to_byte());
        out.extend_from_slice(&self.directory_root_hash);
        out.extend_from_slice(&self.entry_count.to_le_bytes());
        out.extend_from_slice(&self.max_proof_bytes.to_le_bytes());
        out.extend_from_slice(&self.identity_proof_profile_hash);
        out.extend_from_slice(&self.authority_seal_hash);
        out.extend_from_slice(&self.freshness_policy_hash);

        out.push(u8::from(self.prev_head_hash.is_some()));
        if let Some(prev) = self.prev_head_hash {
            out.extend_from_slice(&prev);
        }

        Ok(out)
    }

    /// Blake3 content hash over canonical bytes.
    pub fn content_hash(&self) -> Result<Hash, IdentityProofError> {
        let bytes = self.canonical_bytes()?;
        Ok(hash_bytes(&bytes))
    }

    /// Parses canonical bytes with a caller-provided decode bound.
    pub fn from_canonical_bytes_bounded(
        bytes: &[u8],
        max_bytes: usize,
    ) -> Result<Self, IdentityProofError> {
        if bytes.len() > max_bytes {
            return Err(IdentityProofError::DecodeBoundExceeded {
                size: bytes.len(),
                max: max_bytes,
            });
        }

        if bytes.len() > MAX_DIRECTORY_HEAD_BYTES {
            return Err(IdentityProofError::DecodeBoundExceeded {
                size: bytes.len(),
                max: MAX_DIRECTORY_HEAD_BYTES,
            });
        }

        let mut cursor = Cursor::new(bytes);
        cursor.consume_prefix(
            DIRECTORY_HEAD_DOMAIN_SEPARATOR,
            "HolonDirectoryHeadV1",
            "HolonDirectoryHeadV1",
        )?;

        let cell_id_raw = cursor.read_array::<CELL_ID_BINARY_BYTES>("cell_id")?;
        let cell_id = CellIdV1::from_binary(&cell_id_raw)?;

        let directory_epoch = cursor.read_u64("directory_epoch")?;

        let ledger_anchor = match cursor.read_u8("ledger_anchor.kind")? {
            0x01 => {
                let seq_id = cursor.read_u64("ledger_anchor.seq_id")?;
                let event_hash = cursor.read_array::<HASH_BYTES>("ledger_anchor.event_hash")?;
                LedgerAnchorV1::SeqEvent { seq_id, event_hash }
            },
            0x02 => {
                let index = cursor.read_u64("ledger_anchor.index")?;
                LedgerAnchorV1::ConsensusIndex { index }
            },
            tag => {
                return Err(IdentityProofError::InvalidEnumTag {
                    field: "ledger_anchor.kind",
                    tag,
                });
            },
        };

        let directory_kind = DirectoryKindV1::from_byte(cursor.read_u8("directory_kind")?)?;
        let directory_root_hash = cursor.read_array::<HASH_BYTES>("directory_root_hash")?;
        let entry_count = cursor.read_u64("entry_count")?;
        let max_proof_bytes = cursor.read_u32("max_proof_bytes")?;
        let identity_proof_profile_hash =
            cursor.read_array::<HASH_BYTES>("identity_proof_profile_hash")?;
        let authority_seal_hash = cursor.read_array::<HASH_BYTES>("authority_seal_hash")?;
        let freshness_policy_hash = cursor.read_array::<HASH_BYTES>("freshness_policy_hash")?;

        let has_prev = cursor.read_u8("prev_head_hash.present")?;
        let prev_head_hash = match has_prev {
            0 => None,
            1 => Some(cursor.read_array::<HASH_BYTES>("prev_head_hash")?),
            _ => {
                return Err(IdentityProofError::InvalidField {
                    field: "prev_head_hash.present",
                    reason: "must be 0 or 1".to_string(),
                });
            },
        };

        cursor.ensure_exhausted("HolonDirectoryHeadV1")?;

        Self::new(
            cell_id,
            directory_epoch,
            ledger_anchor,
            directory_root_hash,
            directory_kind,
            entry_count,
            max_proof_bytes,
            identity_proof_profile_hash,
            authority_seal_hash,
            freshness_policy_hash,
            prev_head_hash,
        )
    }

    /// Returns bound `cell_id`.
    pub const fn cell_id(&self) -> &CellIdV1 {
        &self.cell_id
    }

    /// Returns directory epoch.
    pub const fn directory_epoch(&self) -> u64 {
        self.directory_epoch
    }

    /// Returns ledger anchor.
    pub const fn ledger_anchor(&self) -> &LedgerAnchorV1 {
        &self.ledger_anchor
    }

    /// Returns directory root hash.
    pub const fn directory_root_hash(&self) -> &[u8; HASH_BYTES] {
        &self.directory_root_hash
    }

    /// Returns directory kind.
    pub const fn directory_kind(&self) -> DirectoryKindV1 {
        self.directory_kind
    }

    /// Returns entry count.
    pub const fn entry_count(&self) -> u64 {
        self.entry_count
    }

    /// Returns max proof bytes.
    pub const fn max_proof_bytes(&self) -> u32 {
        self.max_proof_bytes
    }

    /// Returns identity proof profile hash.
    pub const fn identity_proof_profile_hash(&self) -> &[u8; HASH_BYTES] {
        &self.identity_proof_profile_hash
    }

    /// Verifies that this head is pinned to the provided proof profile.
    pub fn verify_profile_binding(
        &self,
        profile: &IdentityProofProfileV1,
    ) -> Result<(), IdentityProofError> {
        let profile_hash = profile.content_hash()?;
        if self.identity_proof_profile_hash != profile_hash {
            return Err(IdentityProofError::IdentityProofProfileHashMismatch {
                head_profile_hash_hex: hex::encode(self.identity_proof_profile_hash),
                profile_hash_hex: hex::encode(profile_hash),
            });
        }
        Ok(())
    }

    /// Returns authority seal hash.
    pub const fn authority_seal_hash(&self) -> &[u8; HASH_BYTES] {
        &self.authority_seal_hash
    }

    /// Returns freshness policy hash.
    pub const fn freshness_policy_hash(&self) -> &[u8; HASH_BYTES] {
        &self.freshness_policy_hash
    }

    /// Returns optional previous head hash.
    pub const fn prev_head_hash(&self) -> Option<&[u8; HASH_BYTES]> {
        self.prev_head_hash.as_ref()
    }
}

/// Explicit directory proof kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum DirectoryProofKindV1 {
    /// Compressed sparse Merkle proof.
    Smt256CompressedV1   = 0x01,
    /// Compressed Patricia proof.
    PatriciaCompressedV1 = 0x02,
}

impl DirectoryProofKindV1 {
    const fn from_byte(tag: u8) -> Result<Self, IdentityProofError> {
        match tag {
            0x01 => Ok(Self::Smt256CompressedV1),
            0x02 => Ok(Self::PatriciaCompressedV1),
            _ => Err(IdentityProofError::InvalidEnumTag {
                field: "directory_proof.kind",
                tag,
            }),
        }
    }

    const fn to_byte(self) -> u8 {
        self as u8
    }
}

/// Alias for `DirectoryProofKindV1` used by verification economics artifacts.
pub type DirectoryProofKind = DirectoryProofKindV1;

/// Verifier economics target for one identity-proof profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VerifierCostTarget {
    /// Maximum hash operations for one membership proof verification.
    pub max_hash_ops_per_membership_proof: u32,
    /// Maximum signature/quorum checks required per cached head admission.
    pub max_signature_or_quorum_checks_per_cached_head: u32,
    /// Maximum bytes a verifier is expected to fetch for one verification path.
    pub max_bytes_fetched_for_verification: u32,
}

impl VerifierCostTarget {
    fn validate(self, max_depth: u32) -> Result<(), IdentityProofError> {
        if self.max_hash_ops_per_membership_proof == 0 {
            return Err(IdentityProofError::InvalidField {
                field: "verifier_cost_target.max_hash_ops_per_membership_proof",
                reason: "must be non-zero".to_string(),
            });
        }
        if self.max_hash_ops_per_membership_proof > MAX_HASH_OPS_PER_MEMBERSHIP_PROOF_10E12 {
            return Err(IdentityProofError::InvalidField {
                field: "verifier_cost_target.max_hash_ops_per_membership_proof",
                reason: format!(
                    "{} exceeds 10^12 scale target cap {}",
                    self.max_hash_ops_per_membership_proof, MAX_HASH_OPS_PER_MEMBERSHIP_PROOF_10E12
                ),
            });
        }
        if self.max_hash_ops_per_membership_proof < max_depth {
            return Err(IdentityProofError::InvalidField {
                field: "verifier_cost_target.max_hash_ops_per_membership_proof",
                reason: format!(
                    "{} must be >= max_depth {max_depth}",
                    self.max_hash_ops_per_membership_proof
                ),
            });
        }

        if self.max_signature_or_quorum_checks_per_cached_head == 0 {
            return Err(IdentityProofError::InvalidField {
                field: "verifier_cost_target.max_signature_or_quorum_checks_per_cached_head",
                reason: "must be non-zero".to_string(),
            });
        }

        // O(1) check budget per cached head admission.
        if self.max_signature_or_quorum_checks_per_cached_head > 8 {
            return Err(IdentityProofError::InvalidField {
                field: "verifier_cost_target.max_signature_or_quorum_checks_per_cached_head",
                reason: "must be bounded to O(1)".to_string(),
            });
        }

        let max_fetch_budget = u32::try_from(
            MAX_DIRECTORY_HEAD_BYTES + MAX_DIRECTORY_PROOF_BYTES + MAX_IDENTITY_PROOF_BYTES,
        )
        .map_err(|_| IdentityProofError::InvalidField {
            field: "verifier_cost_target.max_bytes_fetched_for_verification",
            reason: "internal max fetch budget exceeds u32".to_string(),
        })?;
        if self.max_bytes_fetched_for_verification == 0
            || self.max_bytes_fetched_for_verification > max_fetch_budget
        {
            return Err(IdentityProofError::InvalidField {
                field: "verifier_cost_target.max_bytes_fetched_for_verification",
                reason: format!(
                    "must be in 1..={max_fetch_budget}, got {}",
                    self.max_bytes_fetched_for_verification
                ),
            });
        }

        Ok(())
    }
}

/// Verification economics contract artifact (HSI §1.7.7b).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IdentityProofProfileV1 {
    /// Directory proof kind this profile admits.
    pub directory_kind: DirectoryProofKind,
    /// Maximum proof depth (siblings) admitted by verifier.
    pub max_depth: u32,
    /// Maximum serialized proof bytes admitted by verifier.
    pub max_proof_bytes: u32,
    /// Maximum non-default siblings admitted by verifier.
    pub max_non_default_siblings: u32,
    /// Whether this profile supports membership multiproofs.
    pub supports_membership_multiproof: bool,
    /// Whether this profile supports explicit non-membership proofs.
    pub supports_non_membership_proof: bool,
    /// Verifier resource budget target.
    pub verifier_cost_target: VerifierCostTarget,
}

impl IdentityProofProfileV1 {
    /// Baseline 10^12 namespace profile for SMT-256 verification.
    pub const fn baseline_smt_10e12() -> Self {
        Self {
            directory_kind: DirectoryProofKindV1::Smt256CompressedV1,
            max_depth: MAX_SMT_DEPTH,
            max_proof_bytes: 8192,
            max_non_default_siblings: MAX_SMT_DEPTH,
            supports_membership_multiproof: false,
            supports_non_membership_proof: true,
            verifier_cost_target: VerifierCostTarget {
                max_hash_ops_per_membership_proof: MAX_HASH_OPS_PER_MEMBERSHIP_PROOF_10E12,
                max_signature_or_quorum_checks_per_cached_head: 1,
                max_bytes_fetched_for_verification: 16 * 1024,
            },
        }
    }

    /// Validates fail-closed profile invariants.
    pub fn validate(&self) -> Result<(), IdentityProofError> {
        if self.max_depth < MIN_SMT_DEPTH_10E12 {
            return Err(IdentityProofError::InvalidField {
                field: "max_depth",
                reason: format!(
                    "{} below 10^12 scale target floor {MIN_SMT_DEPTH_10E12}",
                    self.max_depth
                ),
            });
        }
        if self.max_depth > MAX_SMT_DEPTH {
            return Err(IdentityProofError::InvalidField {
                field: "max_depth",
                reason: format!("{} exceeds verifier cap {MAX_SMT_DEPTH}", self.max_depth),
            });
        }

        if self.max_proof_bytes == 0 {
            return Err(IdentityProofError::InvalidField {
                field: "max_proof_bytes",
                reason: "must be non-zero".to_string(),
            });
        }
        if usize::try_from(self.max_proof_bytes).ok() > Some(MAX_DIRECTORY_PROOF_BYTES) {
            return Err(IdentityProofError::InvalidField {
                field: "max_proof_bytes",
                reason: format!(
                    "{} exceeds absolute verifier cap {MAX_DIRECTORY_PROOF_BYTES}",
                    self.max_proof_bytes
                ),
            });
        }

        if self.max_non_default_siblings == 0 {
            return Err(IdentityProofError::InvalidField {
                field: "max_non_default_siblings",
                reason: "must be non-zero".to_string(),
            });
        }
        if self.max_non_default_siblings > self.max_depth {
            return Err(IdentityProofError::InvalidField {
                field: "max_non_default_siblings",
                reason: format!(
                    "{} exceeds max_depth {}",
                    self.max_non_default_siblings, self.max_depth
                ),
            });
        }

        self.verifier_cost_target.validate(self.max_depth)?;
        Ok(())
    }

    /// Deterministic canonical bytes for CAS addressing.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, IdentityProofError> {
        self.validate()?;

        let mut out = Vec::with_capacity(
            IDENTITY_PROOF_PROFILE_DOMAIN_SEPARATOR.len() + 1 + 4 + 4 + 4 + 1 + 1 + 4 + 4 + 4,
        );
        out.extend_from_slice(IDENTITY_PROOF_PROFILE_DOMAIN_SEPARATOR);
        out.push(self.directory_kind.to_byte());
        out.extend_from_slice(&self.max_depth.to_le_bytes());
        out.extend_from_slice(&self.max_proof_bytes.to_le_bytes());
        out.extend_from_slice(&self.max_non_default_siblings.to_le_bytes());
        out.push(u8::from(self.supports_membership_multiproof));
        out.push(u8::from(self.supports_non_membership_proof));
        out.extend_from_slice(
            &self
                .verifier_cost_target
                .max_hash_ops_per_membership_proof
                .to_le_bytes(),
        );
        out.extend_from_slice(
            &self
                .verifier_cost_target
                .max_signature_or_quorum_checks_per_cached_head
                .to_le_bytes(),
        );
        out.extend_from_slice(
            &self
                .verifier_cost_target
                .max_bytes_fetched_for_verification
                .to_le_bytes(),
        );

        Ok(out)
    }

    /// Blake3 content hash over canonical bytes.
    pub fn content_hash(&self) -> Result<Hash, IdentityProofError> {
        let bytes = self.canonical_bytes()?;
        Ok(hash_bytes(&bytes))
    }

    /// Parses canonical bytes with caller-provided decode bound.
    pub fn from_canonical_bytes_bounded(
        bytes: &[u8],
        max_bytes: usize,
    ) -> Result<Self, IdentityProofError> {
        if bytes.len() > max_bytes {
            return Err(IdentityProofError::DecodeBoundExceeded {
                size: bytes.len(),
                max: max_bytes,
            });
        }
        if bytes.len() > MAX_IDENTITY_PROOF_PROFILE_BYTES {
            return Err(IdentityProofError::DecodeBoundExceeded {
                size: bytes.len(),
                max: MAX_IDENTITY_PROOF_PROFILE_BYTES,
            });
        }

        let mut cursor = Cursor::new(bytes);
        cursor.consume_prefix(
            IDENTITY_PROOF_PROFILE_DOMAIN_SEPARATOR,
            "IdentityProofProfileV1",
            "IdentityProofProfileV1",
        )?;

        let directory_kind = DirectoryProofKindV1::from_byte(cursor.read_u8("directory_kind")?)?;
        let max_depth = cursor.read_u32("max_depth")?;
        let max_proof_bytes = cursor.read_u32("max_proof_bytes")?;
        let max_non_default_siblings = cursor.read_u32("max_non_default_siblings")?;

        let supports_membership_multiproof =
            match cursor.read_u8("supports_membership_multiproof")? {
                0 => false,
                1 => true,
                _ => {
                    return Err(IdentityProofError::InvalidField {
                        field: "supports_membership_multiproof",
                        reason: "must be 0 or 1".to_string(),
                    });
                },
            };
        let supports_non_membership_proof = match cursor.read_u8("supports_non_membership_proof")? {
            0 => false,
            1 => true,
            _ => {
                return Err(IdentityProofError::InvalidField {
                    field: "supports_non_membership_proof",
                    reason: "must be 0 or 1".to_string(),
                });
            },
        };

        let verifier_cost_target = VerifierCostTarget {
            max_hash_ops_per_membership_proof: cursor
                .read_u32("verifier_cost_target.max_hash_ops_per_membership_proof")?,
            max_signature_or_quorum_checks_per_cached_head: cursor
                .read_u32("verifier_cost_target.max_signature_or_quorum_checks_per_cached_head")?,
            max_bytes_fetched_for_verification: cursor
                .read_u32("verifier_cost_target.max_bytes_fetched_for_verification")?,
        };

        cursor.ensure_exhausted("IdentityProofProfileV1")?;

        let profile = Self {
            directory_kind,
            max_depth,
            max_proof_bytes,
            max_non_default_siblings,
            supports_membership_multiproof,
            supports_non_membership_proof,
            verifier_cost_target,
        };
        profile.validate()?;
        Ok(profile)
    }

    /// Verifies one directory proof under this profile and the provided head.
    pub fn verify_directory_proof(
        &self,
        head: &HolonDirectoryHeadV1,
        proof: &DirectoryProofV1,
    ) -> Result<(), IdentityProofError> {
        self.validate()?;
        head.verify_profile_binding(self)?;

        if self.directory_kind != proof.kind() {
            return Err(IdentityProofError::IdentityProofProfileKindMismatch {
                profile_kind: self.directory_kind,
                proof_kind: proof.kind(),
            });
        }
        check_directory_kind_compatibility(head.directory_kind(), self.directory_kind)?;

        proof.verify_against_root(
            head.directory_root_hash(),
            self.max_proof_bytes.min(head.max_proof_bytes()),
            self.max_depth,
            self.max_non_default_siblings,
        )
    }
}

/// Resolves a known/supported proof profile by its canonical hash.
pub fn resolve_known_profile(
    profile_hash: &[u8; HASH_BYTES],
) -> Result<IdentityProofProfileV1, IdentityProofError> {
    let baseline = IdentityProofProfileV1::baseline_smt_10e12();
    if baseline.content_hash()? == *profile_hash {
        return Ok(baseline);
    }

    Err(IdentityProofError::UnknownIdentityProofProfile {
        profile_hash_hex: hex::encode(profile_hash),
    })
}

const fn requires_strict_profile_enforcement(risk_tier: RiskTier) -> bool {
    matches!(
        risk_tier,
        RiskTier::Tier2 | RiskTier::Tier3 | RiskTier::Tier4
    )
}

fn resolve_profile_for_verification(
    directory_head: &HolonDirectoryHeadV1,
    risk_tier: RiskTier,
    expected_profile: Option<&IdentityProofProfileV1>,
) -> Result<Option<IdentityProofProfileV1>, IdentityProofError> {
    let strict = requires_strict_profile_enforcement(risk_tier);

    // SECURITY (REQ-0012): In strict mode (Tier2+), the known-profile registry
    // check is MANDATORY and cannot be bypassed by supplying an expected_profile.
    // We must validate that the directory head's profile hash is in the known
    // registry BEFORE accepting any profile, including a caller-supplied one.
    if strict {
        // Fail-closed: reject if the head's profile hash is not in the
        // known-profile registry, regardless of whether expected_profile
        // was supplied and hash-matches.
        let known = resolve_known_profile(directory_head.identity_proof_profile_hash())?;

        // If caller supplied an expected_profile, verify it binds to the head.
        if let Some(profile) = expected_profile {
            directory_head.verify_profile_binding(profile)?;
            return Ok(Some(profile.clone()));
        }

        // No expected_profile supplied; use the registry-resolved profile.
        directory_head.verify_profile_binding(&known)?;
        return Ok(Some(known));
    }

    // Non-strict mode (Tier0/Tier1): tolerate unknown or mismatched profiles
    // with warnings to preserve local/self-signed development flows.
    if let Some(profile) = expected_profile {
        match directory_head.verify_profile_binding(profile) {
            Ok(()) => return Ok(Some(profile.clone())),
            Err(err) => {
                warn!(
                    risk_tier = ?risk_tier,
                    profile_hash = %hex::encode(directory_head.identity_proof_profile_hash()),
                    error = %err,
                    "identity proof profile mismatch allowed for Tier0/Tier1 (strict enforcement starts at Tier2)"
                );
            },
        }
    }

    match resolve_known_profile(directory_head.identity_proof_profile_hash()) {
        Ok(profile) => match directory_head.verify_profile_binding(&profile) {
            Ok(()) => Ok(Some(profile)),
            Err(err) => {
                warn!(
                    risk_tier = ?risk_tier,
                    profile_hash = %hex::encode(directory_head.identity_proof_profile_hash()),
                    error = %err,
                    "identity proof profile binding check failed but was tolerated for Tier0/Tier1"
                );
                Ok(None)
            },
        },
        Err(err) => {
            warn!(
                risk_tier = ?risk_tier,
                profile_hash = %hex::encode(directory_head.identity_proof_profile_hash()),
                error = %err,
                "unknown identity proof profile allowed for Tier0/Tier1 (strict enforcement starts at Tier2)"
            );
            Ok(None)
        },
    }
}

/// Status of a directory entry (K-V binding semantics).
///
/// A directory entry maps a holon identity key to a value (e.g., holon
/// certificate hash). The status governs whether the binding is considered
/// active for authoritative operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum DirectoryEntryStatus {
    /// Entry is active and eligible for authoritative operations.
    Active    = 0x01,
    /// Entry has been revoked; authoritative operations MUST be denied.
    Revoked   = 0x02,
    /// Entry is temporarily suspended; authoritative operations MUST be denied.
    Suspended = 0x03,
}

impl DirectoryEntryStatus {
    /// Parses a status byte (fail-closed: unknown tags are rejected).
    pub const fn from_byte(tag: u8) -> Result<Self, IdentityProofError> {
        match tag {
            0x01 => Ok(Self::Active),
            0x02 => Ok(Self::Revoked),
            0x03 => Ok(Self::Suspended),
            _ => Err(IdentityProofError::InvalidEnumTag {
                field: "directory_entry_status",
                tag,
            }),
        }
    }

    /// Returns the canonical byte encoding.
    pub const fn to_byte(self) -> u8 {
        self as u8
    }

    /// Returns `true` if the entry is active.
    #[must_use]
    pub const fn is_active(self) -> bool {
        matches!(self, Self::Active)
    }
}

/// Checks whether a directory head kind is compatible with a proof kind.
///
/// The compatibility matrix is:
/// - `Smt256V1` head <-> `Smt256CompressedV1` proof
/// - `PatriciaTrieV1` head <-> `PatriciaCompressedV1` proof
///
/// Any other combination is rejected (fail-closed).
pub const fn check_directory_kind_compatibility(
    head_kind: DirectoryKindV1,
    proof_kind: DirectoryProofKindV1,
) -> Result<(), IdentityProofError> {
    let compatible = matches!(
        (head_kind, proof_kind),
        (
            DirectoryKindV1::Smt256V1,
            DirectoryProofKindV1::Smt256CompressedV1
        ) | (
            DirectoryKindV1::PatriciaTrieV1,
            DirectoryProofKindV1::PatriciaCompressedV1
        )
    );
    if !compatible {
        return Err(IdentityProofError::DirectoryKindMismatch {
            head_kind,
            proof_kind,
        });
    }
    Ok(())
}

/// Sibling node hash used in path reconstruction.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SiblingNode {
    hash: [u8; HASH_BYTES],
}

impl SiblingNode {
    /// Creates a sibling node.
    pub const fn new(hash: [u8; HASH_BYTES]) -> Self {
        Self { hash }
    }

    /// Returns sibling hash.
    pub const fn hash(&self) -> &[u8; HASH_BYTES] {
        &self.hash
    }
}

/// Bounded authenticated-directory proof for identity membership checks.
///
/// The `entry_status` field is cryptographically bound by the ADS leaf
/// commitment (`key || value_hash || entry_status`). This ensures the entry
/// status is proof-derived and cannot be caller-asserted (TCK-00356 Fix 4).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DirectoryProofV1 {
    kind: DirectoryProofKindV1,
    key: [u8; HASH_BYTES],
    value_hash: [u8; HASH_BYTES],
    entry_status: DirectoryEntryStatus,
    siblings: Vec<SiblingNode>,
    proof_bytes_len: u32,
}

impl DirectoryProofV1 {
    /// Constructs a validated proof and computes `proof_bytes_len`.
    pub fn new(
        kind: DirectoryProofKindV1,
        key: [u8; HASH_BYTES],
        value_hash: [u8; HASH_BYTES],
        entry_status: DirectoryEntryStatus,
        siblings: Vec<SiblingNode>,
    ) -> Result<Self, IdentityProofError> {
        let mut proof = Self {
            kind,
            key,
            value_hash,
            entry_status,
            siblings,
            proof_bytes_len: 0,
        };
        proof.proof_bytes_len =
            u32::try_from(proof.encoded_len()).map_err(|_| IdentityProofError::InvalidField {
                field: "proof_bytes_len",
                reason: "encoded length exceeds u32::MAX".to_string(),
            })?;
        proof.validate()?;
        Ok(proof)
    }

    /// Validates fail-closed structural invariants.
    pub fn validate(&self) -> Result<(), IdentityProofError> {
        if self.siblings.is_empty() {
            return Err(IdentityProofError::InvalidField {
                field: "siblings",
                reason: "must contain at least one sibling".to_string(),
            });
        }

        if self.siblings.len() > MAX_DIRECTORY_SIBLINGS {
            return Err(IdentityProofError::TooManySiblings {
                count: self.siblings.len(),
                max: MAX_DIRECTORY_SIBLINGS,
            });
        }

        let actual_len = self.encoded_len();
        if self.proof_bytes_len != u32::try_from(actual_len).unwrap_or(u32::MAX) {
            return Err(IdentityProofError::ProofLengthMismatch {
                artifact_kind: "DirectoryProofV1",
                declared: self.proof_bytes_len,
                actual: actual_len,
            });
        }

        if actual_len > MAX_DIRECTORY_PROOF_BYTES {
            return Err(IdentityProofError::DecodeBoundExceeded {
                size: actual_len,
                max: MAX_DIRECTORY_PROOF_BYTES,
            });
        }

        Ok(())
    }

    /// Deterministic canonical bytes for CAS addressing.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, IdentityProofError> {
        self.validate()?;

        let mut out = Vec::with_capacity(self.encoded_len());
        out.extend_from_slice(DIRECTORY_PROOF_DOMAIN_SEPARATOR);
        out.push(self.kind.to_byte());
        out.extend_from_slice(&self.key);
        out.extend_from_slice(&self.value_hash);
        out.push(self.entry_status.to_byte());
        out.extend_from_slice(&self.proof_bytes_len.to_le_bytes());

        let sibling_count =
            u32::try_from(self.siblings.len()).map_err(|_| IdentityProofError::InvalidField {
                field: "siblings",
                reason: "count exceeds u32::MAX".to_string(),
            })?;
        out.extend_from_slice(&sibling_count.to_le_bytes());
        for sibling in &self.siblings {
            out.extend_from_slice(&sibling.hash);
        }

        Ok(out)
    }

    /// Parses canonical bytes with a caller-provided decode bound.
    pub fn from_canonical_bytes_bounded(
        bytes: &[u8],
        max_bytes: usize,
    ) -> Result<Self, IdentityProofError> {
        if bytes.len() > max_bytes {
            return Err(IdentityProofError::DecodeBoundExceeded {
                size: bytes.len(),
                max: max_bytes,
            });
        }

        if bytes.len() > MAX_DIRECTORY_PROOF_BYTES {
            return Err(IdentityProofError::DecodeBoundExceeded {
                size: bytes.len(),
                max: MAX_DIRECTORY_PROOF_BYTES,
            });
        }

        let mut cursor = Cursor::new(bytes);
        cursor.consume_prefix(
            DIRECTORY_PROOF_DOMAIN_SEPARATOR,
            "DirectoryProofV1",
            "DirectoryProofV1",
        )?;

        let kind = DirectoryProofKindV1::from_byte(cursor.read_u8("kind")?)?;
        // Phase 1: only SMT-256 proof verification is implemented.
        // Reject Patricia proofs at admission/decode time to avoid deferred
        // availability failures at verification.
        if kind == DirectoryProofKindV1::PatriciaCompressedV1 {
            return Err(IdentityProofError::UnsupportedDirectoryProofKind { kind });
        }
        let key = cursor.read_array::<HASH_BYTES>("key")?;
        let value_hash = cursor.read_array::<HASH_BYTES>("value_hash")?;
        let entry_status = DirectoryEntryStatus::from_byte(cursor.read_u8("entry_status")?)?;
        let proof_bytes_len = cursor.read_u32("proof_bytes_len")?;
        let sibling_count = cursor.read_u32("siblings.count")?;

        let sibling_count_usize =
            usize::try_from(sibling_count).map_err(|_| IdentityProofError::InvalidField {
                field: "siblings.count",
                reason: "cannot fit into usize".to_string(),
            })?;

        if sibling_count_usize > MAX_DIRECTORY_SIBLINGS {
            return Err(IdentityProofError::TooManySiblings {
                count: sibling_count_usize,
                max: MAX_DIRECTORY_SIBLINGS,
            });
        }

        let mut siblings = Vec::with_capacity(sibling_count_usize);
        for _ in 0..sibling_count_usize {
            siblings.push(SiblingNode {
                hash: cursor.read_array::<HASH_BYTES>("siblings.hash")?,
            });
        }

        cursor.ensure_exhausted("DirectoryProofV1")?;

        let proof = Self {
            kind,
            key,
            value_hash,
            entry_status,
            siblings,
            proof_bytes_len,
        };
        proof.validate()?;
        Ok(proof)
    }

    /// Verifies this proof against the provided root and explicit size bound.
    pub fn verify_against_root(
        &self,
        root_hash: &[u8; HASH_BYTES],
        max_proof_bytes: u32,
        max_depth: u32,
        max_non_default_siblings: u32,
    ) -> Result<(), IdentityProofError> {
        self.validate()?;

        if self.proof_bytes_len > max_proof_bytes {
            return Err(IdentityProofError::ProofBytesExceeded {
                proof_bytes_len: self.proof_bytes_len,
                max_proof_bytes,
            });
        }

        if max_depth == 0 {
            return Err(IdentityProofError::InvalidField {
                field: "max_depth",
                reason: "must be non-zero".to_string(),
            });
        }
        if max_depth > MAX_SMT_DEPTH {
            return Err(IdentityProofError::InvalidField {
                field: "max_depth",
                reason: format!("{max_depth} exceeds verifier cap {MAX_SMT_DEPTH}"),
            });
        }
        if self.siblings.len()
            > usize::try_from(max_depth).map_err(|_| IdentityProofError::InvalidField {
                field: "max_depth",
                reason: "cannot fit into usize".to_string(),
            })?
        {
            return Err(IdentityProofError::DepthExceeded {
                depth: self.siblings.len(),
                max_depth,
            });
        }

        let non_default_sibling_count = self.non_default_sibling_count();
        let max_non_default_siblings_usize =
            usize::try_from(max_non_default_siblings).map_err(|_| {
                IdentityProofError::InvalidField {
                    field: "max_non_default_siblings",
                    reason: "cannot fit into usize".to_string(),
                }
            })?;
        if non_default_sibling_count > max_non_default_siblings_usize {
            return Err(IdentityProofError::NonDefaultSiblingsExceeded {
                count: non_default_sibling_count,
                max: max_non_default_siblings,
            });
        }

        match self.kind {
            DirectoryProofKindV1::Smt256CompressedV1 => self.verify_smt256(root_hash),
            DirectoryProofKindV1::PatriciaCompressedV1 => {
                Err(IdentityProofError::UnsupportedDirectoryProofKind { kind: self.kind })
            },
        }
    }

    fn verify_smt256(&self, expected_root: &[u8; HASH_BYTES]) -> Result<(), IdentityProofError> {
        if self.siblings.len() > HASH_BYTES * 8 {
            return Err(IdentityProofError::SmtDepthExceeded {
                depth: self.siblings.len(),
            });
        }

        let mut current = hash_directory_leaf(&self.key, &self.value_hash, self.entry_status);

        for (depth, sibling) in self.siblings.iter().enumerate() {
            let bit = key_bit_at_depth(&self.key, depth)?;
            current = if bit == 0 {
                hash_directory_node(&current, sibling.hash())
            } else {
                hash_directory_node(sibling.hash(), &current)
            };
        }

        if &current != expected_root {
            return Err(IdentityProofError::DirectoryRootMismatch);
        }

        Ok(())
    }

    fn encoded_len(&self) -> usize {
        DIRECTORY_PROOF_DOMAIN_SEPARATOR.len()
            + 1              // kind byte
            + HASH_BYTES     // key
            + HASH_BYTES     // value_hash
            + 1              // entry_status byte
            + 4              // proof_bytes_len
            + 4              // sibling_count
            + (self.siblings.len() * HASH_BYTES)
    }

    /// Returns proof kind.
    pub const fn kind(&self) -> DirectoryProofKindV1 {
        self.kind
    }

    /// Returns directory key.
    pub const fn key(&self) -> &[u8; HASH_BYTES] {
        &self.key
    }

    /// Returns value hash.
    pub const fn value_hash(&self) -> &[u8; HASH_BYTES] {
        &self.value_hash
    }

    /// Returns the proof-derived entry status.
    ///
    /// This status is committed into the directory leaf value by the
    /// directory authority and is verified as part of the ADS proof.
    /// It MUST NOT be caller-asserted (TCK-00356 Fix 4).
    pub const fn entry_status(&self) -> DirectoryEntryStatus {
        self.entry_status
    }

    /// Returns siblings.
    pub fn siblings(&self) -> &[SiblingNode] {
        &self.siblings
    }

    /// Returns the number of non-default siblings (all-zero hash is default).
    pub fn non_default_sibling_count(&self) -> usize {
        self.siblings
            .iter()
            .filter(|sibling| sibling.hash() != &[0u8; HASH_BYTES])
            .count()
    }

    /// Returns explicit proof byte length.
    pub const fn proof_bytes_len(&self) -> u32 {
        self.proof_bytes_len
    }
}

/// Identity proof artifact for proof-carrying boundary identity checks.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IdentityProofV1 {
    cell_certificate_hash: Option<[u8; HASH_BYTES]>,
    holon_certificate_hash: [u8; HASH_BYTES],
    holon_directory_head_hash: [u8; HASH_BYTES],
    directory_proof: DirectoryProofV1,
    proof_generated_at_tick: u64,
}

impl IdentityProofV1 {
    /// Constructs a validated identity proof.
    pub fn new(
        cell_certificate_hash: Option<[u8; HASH_BYTES]>,
        holon_certificate_hash: [u8; HASH_BYTES],
        holon_directory_head_hash: [u8; HASH_BYTES],
        directory_proof: DirectoryProofV1,
        proof_generated_at_tick: u64,
    ) -> Result<Self, IdentityProofError> {
        let proof = Self {
            cell_certificate_hash,
            holon_certificate_hash,
            holon_directory_head_hash,
            directory_proof,
            proof_generated_at_tick,
        };
        proof.validate()?;
        Ok(proof)
    }

    /// Validates fail-closed structural invariants.
    pub fn validate(&self) -> Result<(), IdentityProofError> {
        if self.holon_certificate_hash == [0u8; HASH_BYTES] {
            return Err(IdentityProofError::InvalidField {
                field: "holon_certificate_hash",
                reason: "must be non-zero".to_string(),
            });
        }

        if self.holon_directory_head_hash == [0u8; HASH_BYTES] {
            return Err(IdentityProofError::InvalidField {
                field: "holon_directory_head_hash",
                reason: "must be non-zero".to_string(),
            });
        }

        if self.cell_certificate_hash == Some([0u8; HASH_BYTES]) {
            return Err(IdentityProofError::InvalidField {
                field: "cell_certificate_hash",
                reason: "when present, must be non-zero".to_string(),
            });
        }

        self.directory_proof.validate()?;
        Ok(())
    }

    /// Deterministic canonical bytes for CAS addressing.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, IdentityProofError> {
        self.validate()?;
        let directory_proof_bytes = self.directory_proof.canonical_bytes()?;

        let mut out = Vec::with_capacity(
            IDENTITY_PROOF_DOMAIN_SEPARATOR.len()
                + 1
                + self.cell_certificate_hash.map_or(0, |_| HASH_BYTES)
                + HASH_BYTES
                + HASH_BYTES
                + 8
                + 4
                + directory_proof_bytes.len(),
        );
        out.extend_from_slice(IDENTITY_PROOF_DOMAIN_SEPARATOR);
        out.push(u8::from(self.cell_certificate_hash.is_some()));
        if let Some(cell_hash) = self.cell_certificate_hash {
            out.extend_from_slice(&cell_hash);
        }
        out.extend_from_slice(&self.holon_certificate_hash);
        out.extend_from_slice(&self.holon_directory_head_hash);
        out.extend_from_slice(&self.proof_generated_at_tick.to_le_bytes());

        let proof_len = u32::try_from(directory_proof_bytes.len()).map_err(|_| {
            IdentityProofError::InvalidField {
                field: "directory_proof",
                reason: "encoded length exceeds u32::MAX".to_string(),
            }
        })?;
        out.extend_from_slice(&proof_len.to_le_bytes());
        out.extend_from_slice(&directory_proof_bytes);
        Ok(out)
    }

    /// Blake3 content hash over canonical bytes.
    pub fn content_hash(&self) -> Result<Hash, IdentityProofError> {
        let bytes = self.canonical_bytes()?;
        Ok(hash_bytes(&bytes))
    }

    /// Parses canonical bytes with a caller-provided decode bound.
    pub fn from_canonical_bytes_bounded(
        bytes: &[u8],
        max_bytes: usize,
    ) -> Result<Self, IdentityProofError> {
        if bytes.len() > max_bytes {
            return Err(IdentityProofError::DecodeBoundExceeded {
                size: bytes.len(),
                max: max_bytes,
            });
        }

        if bytes.len() > MAX_IDENTITY_PROOF_BYTES {
            return Err(IdentityProofError::DecodeBoundExceeded {
                size: bytes.len(),
                max: MAX_IDENTITY_PROOF_BYTES,
            });
        }

        let mut cursor = Cursor::new(bytes);
        cursor.consume_prefix(
            IDENTITY_PROOF_DOMAIN_SEPARATOR,
            "IdentityProofV1",
            "IdentityProofV1",
        )?;

        let has_cell_hash = cursor.read_u8("cell_certificate_hash.present")?;
        let cell_certificate_hash = match has_cell_hash {
            0 => None,
            1 => Some(cursor.read_array::<HASH_BYTES>("cell_certificate_hash")?),
            _ => {
                return Err(IdentityProofError::InvalidField {
                    field: "cell_certificate_hash.present",
                    reason: "must be 0 or 1".to_string(),
                });
            },
        };

        let holon_certificate_hash = cursor.read_array::<HASH_BYTES>("holon_certificate_hash")?;
        let holon_directory_head_hash =
            cursor.read_array::<HASH_BYTES>("holon_directory_head_hash")?;
        let proof_generated_at_tick = cursor.read_u64("proof_generated_at_tick")?;
        let directory_proof_len = cursor.read_u32("directory_proof.len")?;

        let proof_len_usize =
            usize::try_from(directory_proof_len).map_err(|_| IdentityProofError::InvalidField {
                field: "directory_proof.len",
                reason: "cannot fit into usize".to_string(),
            })?;

        let directory_proof_bytes = cursor.read_bytes("directory_proof", proof_len_usize)?;
        let directory_proof =
            DirectoryProofV1::from_canonical_bytes_bounded(directory_proof_bytes, proof_len_usize)?;

        cursor.ensure_exhausted("IdentityProofV1")?;

        Self::new(
            cell_certificate_hash,
            holon_certificate_hash,
            holon_directory_head_hash,
            directory_proof,
            proof_generated_at_tick,
        )
    }

    /// Retrieves and bounded-decodes an `IdentityProofV1` from CAS.
    pub fn fetch_from_cas(
        cas: &dyn ContentAddressedStore,
        identity_proof_hash: &Hash,
        max_bytes: usize,
    ) -> Result<Self, IdentityProofError> {
        let bytes = cas.retrieve(identity_proof_hash)?;
        Self::from_canonical_bytes_bounded(&bytes, max_bytes)
    }

    /// Verifies the identity proof against provided certificates/head and
    /// verifier policy.
    ///
    /// Verification steps (RFC-0020 §1.7.7):
    ///
    /// 1. Proof object is already fetched and decoded with bounds. 1a.
    ///    Directory kind compatibility check (head kind vs. proof kind).
    /// 2. Verify `CellCertificateV1`.
    /// 3. Verify `HolonCertificateV1` and recompute identity bindings.
    /// 4. Verify directory head authority seal binding.
    /// 5. Verify ADS proof against head root. 5a. Verify K->V semantics:
    ///    `expected_value_hash` matches proof `value_hash`. 5b. Verify
    ///    directory entry status is Active (proof-derived, not
    ///    caller-asserted).
    /// 6. Enforce tick-based freshness.
    ///
    /// # Entry Status (TCK-00356 Fix 4)
    ///
    /// The entry status is **proof-derived**: it comes from the
    /// `DirectoryProofV1::entry_status` field, which is committed into the
    /// directory leaf by the directory authority. Callers do NOT supply the
    /// expected status — if the proof carries a Revoked or Suspended status,
    /// verification fails with `EntryRevoked`.
    #[allow(clippy::too_many_arguments)]
    pub fn verify<F>(
        &self,
        expected_holon_id: &HolonIdV1,
        cell_certificate: &CellCertificateV1,
        holon_certificate: &HolonCertificateV1,
        directory_head: &HolonDirectoryHeadV1,
        direct_trust_pinned: bool,
        current_tick: u64,
        max_staleness_ticks: u64,
        expected_freshness_policy_hash: &[u8; HASH_BYTES],
        expected_value_hash: &[u8; HASH_BYTES],
        authority_seal_verifier: F,
    ) -> Result<(), IdentityProofError>
    where
        F: FnOnce(
            &CellCertificateV1,
            &[u8; HASH_BYTES],
            &[u8; HASH_BYTES],
        ) -> Result<(), IdentityProofError>,
    {
        self.verify_with_profile_policy(
            expected_holon_id,
            cell_certificate,
            holon_certificate,
            directory_head,
            direct_trust_pinned,
            current_tick,
            max_staleness_ticks,
            expected_freshness_policy_hash,
            expected_value_hash,
            RiskTier::Tier2,
            None,
            authority_seal_verifier,
        )
    }

    /// Verifies the identity proof with explicit profile policy controls.
    ///
    /// Tier2+ risk tiers enforce strict profile pinning (unknown/mismatched
    /// profile hashes are rejected fail-closed). Tier0/Tier1 tolerate unknown
    /// or mismatched profiles with warnings to preserve local/self-signed
    /// development flows during rollout.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_with_profile_policy<F>(
        &self,
        expected_holon_id: &HolonIdV1,
        cell_certificate: &CellCertificateV1,
        holon_certificate: &HolonCertificateV1,
        directory_head: &HolonDirectoryHeadV1,
        direct_trust_pinned: bool,
        current_tick: u64,
        max_staleness_ticks: u64,
        expected_freshness_policy_hash: &[u8; HASH_BYTES],
        expected_value_hash: &[u8; HASH_BYTES],
        risk_tier: RiskTier,
        expected_profile: Option<&IdentityProofProfileV1>,
        authority_seal_verifier: F,
    ) -> Result<(), IdentityProofError>
    where
        F: FnOnce(
            &CellCertificateV1,
            &[u8; HASH_BYTES],
            &[u8; HASH_BYTES],
        ) -> Result<(), IdentityProofError>,
    {
        self.validate()?;

        // Step 1a: Directory kind compatibility check (fail-closed).
        //
        // The directory head advertises a `directory_kind` and the proof
        // carries a `DirectoryProofKindV1`. They MUST be compatible per the
        // defined matrix. Without this check, a proof of one kind could be
        // verified against a head of an incompatible kind.
        check_directory_kind_compatibility(
            directory_head.directory_kind(),
            self.directory_proof.kind(),
        )?;

        // Step 2: Verify CellCertificateV1.
        cell_certificate.validate()?;

        if !direct_trust_pinned && self.cell_certificate_hash.is_none() {
            return Err(IdentityProofError::MissingCellCertificateHash);
        }

        if let Some(expected_cell_hash) = self.cell_certificate_hash {
            let cell_hash = hash_bytes(&cell_certificate.canonical_bytes()?);
            if cell_hash != expected_cell_hash {
                return Err(IdentityProofError::HashMismatch {
                    field: "cell_certificate_hash",
                });
            }
        }

        // Step 3: Verify HolonCertificateV1 and recompute identity bindings.
        holon_certificate.validate()?;

        if holon_certificate.cell_id() != cell_certificate.cell_id() {
            return Err(IdentityProofError::CellBindingMismatch);
        }

        let recomputed_genesis_key_id = PublicKeyIdV1::from_key_bytes(
            super::AlgorithmTag::Ed25519,
            holon_certificate.genesis_public_key_bytes(),
        );
        if &recomputed_genesis_key_id != holon_certificate.genesis_public_key_id() {
            return Err(IdentityProofError::HolonBindingMismatch);
        }

        let recomputed_holon_id = HolonIdV1::from_genesis(&HolonGenesisV1::new(
            holon_certificate.cell_id().clone(),
            holon_certificate.genesis_public_key_id().clone(),
            holon_certificate.genesis_public_key_bytes().to_vec(),
            None,
            None,
        )?);

        if &recomputed_holon_id != holon_certificate.holon_id()
            || &recomputed_holon_id != expected_holon_id
        {
            return Err(IdentityProofError::HolonBindingMismatch);
        }

        let holon_hash = hash_bytes(&holon_certificate.canonical_bytes()?);
        if holon_hash != self.holon_certificate_hash {
            return Err(IdentityProofError::HashMismatch {
                field: "holon_certificate_hash",
            });
        }

        // Step 4: Verify directory head authority seal binding.
        directory_head.validate()?;

        if directory_head.cell_id() != cell_certificate.cell_id() {
            return Err(IdentityProofError::CellBindingMismatch);
        }

        let head_hash = directory_head.content_hash()?;
        if head_hash != self.holon_directory_head_hash {
            return Err(IdentityProofError::HashMismatch {
                field: "holon_directory_head_hash",
            });
        }

        if directory_head.freshness_policy_hash() != expected_freshness_policy_hash {
            return Err(IdentityProofError::FreshnessPolicyMismatch);
        }

        authority_seal_verifier(
            cell_certificate,
            &head_hash,
            directory_head.authority_seal_hash(),
        )?;

        // Step 5: Verify ADS proof against directory root.
        let derived_key = derive_directory_key(expected_holon_id);
        if self.directory_proof.key() != &derived_key {
            return Err(IdentityProofError::DirectoryKeyMismatch);
        }

        let active_profile =
            resolve_profile_for_verification(directory_head, risk_tier, expected_profile)?;

        if let Some(profile) = active_profile {
            profile.verify_directory_proof(directory_head, self.directory_proof())?;
        } else {
            // Tier0/Tier1 transitional fallback while session-open identity
            // dereference wiring remains deferred (WVR-0103 / TCK-00361).
            self.directory_proof.verify_against_root(
                directory_head.directory_root_hash(),
                directory_head.max_proof_bytes(),
                MAX_SMT_DEPTH,
                MAX_SMT_DEPTH,
            )?;
        }

        // Step 5a: Verify K->V value semantics.
        //
        // The caller provides the expected value_hash (e.g., the hash of
        // the holon certificate for the claimed identity). The proof's
        // value_hash MUST match to ensure the directory entry represents
        // the expected identity state.
        if self.directory_proof.value_hash() != expected_value_hash {
            return Err(IdentityProofError::ValueHashMismatch {
                field: "directory_proof.value_hash",
            });
        }

        // Step 5b: Verify directory entry status (proof-derived).
        //
        // SECURITY (TCK-00356 Fix 4): The entry status is extracted from
        // the proof's `DirectoryProofV1::entry_status` field, which is
        // committed into the directory leaf by the directory authority.
        // This prevents callers from asserting an Active status for a
        // Revoked/Suspended entry. If the proof-derived status is not
        // Active, authoritative operations MUST be denied (fail-closed).
        if !self.directory_proof.entry_status().is_active() {
            return Err(IdentityProofError::EntryRevoked);
        }

        // Step 6: Tick-based freshness checks.
        if current_tick < self.proof_generated_at_tick {
            return Err(IdentityProofError::ProofNotYetValid {
                current_tick,
                generated_at_tick: self.proof_generated_at_tick,
            });
        }

        let age_ticks = current_tick - self.proof_generated_at_tick;
        if age_ticks > max_staleness_ticks {
            return Err(IdentityProofError::ProofStale {
                age_ticks,
                max_staleness_ticks,
            });
        }

        Ok(())
    }

    /// Optional cell certificate hash pointer.
    pub const fn cell_certificate_hash(&self) -> Option<&[u8; HASH_BYTES]> {
        self.cell_certificate_hash.as_ref()
    }

    /// Holon certificate hash pointer.
    pub const fn holon_certificate_hash(&self) -> &[u8; HASH_BYTES] {
        &self.holon_certificate_hash
    }

    /// Directory head hash pointer.
    pub const fn holon_directory_head_hash(&self) -> &[u8; HASH_BYTES] {
        &self.holon_directory_head_hash
    }

    /// Directory proof object.
    pub const fn directory_proof(&self) -> &DirectoryProofV1 {
        &self.directory_proof
    }

    /// Proof generation tick.
    pub const fn proof_generated_at_tick(&self) -> u64 {
        self.proof_generated_at_tick
    }
}

/// Structurally admitted directory head retained in verifier cache.
#[allow(clippy::redundant_pub_crate)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VerifiedHead {
    /// Cached directory head commitment.
    pub(crate) head: HolonDirectoryHeadV1,
    /// Directory epoch tick at which this head was admitted to the cache.
    /// Uses the same epoch unit as `HolonDirectoryHeadV1::directory_epoch`.
    pub(crate) verified_at: u64,
}

/// Deterministic audit event emitted for every cache invalidation action.
///
/// All invalidation paths produce an audit event that records the reason,
/// the affected head hashes, and the trigger context. These events enable
/// post-hoc verification that no stale cache entry survived a revocation,
/// rotation, or head advancement.
///
/// # Contract (REQ-0013)
///
/// The invalidation path is deterministic and auditable: every cache mutation
/// emits exactly one event of this type, and the event is sufficient to
/// reconstruct the invalidation decision.
// NOTE: `pub(crate)` for session-open integration (TCK-00361). Until that
// wiring is complete, these types are exercised only by the test suite.
#[allow(dead_code)]
#[allow(clippy::redundant_pub_crate)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum VerifierCacheAuditEvent {
    /// A head was admitted into the cache.
    HeadAdmitted {
        /// Content hash of the admitted head.
        head_hash: [u8; HASH_BYTES],
        /// Directory epoch of the admitted head.
        directory_epoch: u64,
        /// Cell identity of the admitted head.
        cell_id: CellIdV1,
    },
    /// A specific head was explicitly invalidated (e.g., revocation of
    /// an identity whose proof was cached against this head).
    HeadInvalidated {
        /// Content hash of the invalidated head.
        head_hash: [u8; HASH_BYTES],
        /// Reason for invalidation.
        reason: InvalidationReason,
    },
    /// All heads for a cell were invalidated (e.g., key rotation).
    CellInvalidated {
        /// Cell identity whose heads were evicted.
        cell_id: CellIdV1,
        /// Number of heads evicted.
        evicted_count: usize,
        /// Content hashes of every evicted head (deterministic, sorted).
        evicted_head_hashes: Vec<[u8; HASH_BYTES]>,
        /// Reason for invalidation.
        reason: InvalidationReason,
    },
    /// Heads older than a cutoff epoch were evicted (global staleness sweep).
    StaleEvicted {
        /// Cutoff epoch used for eviction.
        cutoff_epoch: u64,
        /// Number of heads evicted.
        evicted_count: usize,
        /// Content hashes of every evicted head (deterministic, sorted).
        evicted_head_hashes: Vec<[u8; HASH_BYTES]>,
    },
    /// Heads for a cell older than a cutoff epoch were evicted
    /// (per-cell head advancement).
    CellHeadAdvanced {
        /// Cell identity whose old heads were evicted.
        cell_id: CellIdV1,
        /// New epoch beyond which old heads are stale.
        new_epoch: u64,
        /// Number of heads evicted.
        evicted_count: usize,
        /// Content hashes of every evicted head (deterministic, sorted).
        evicted_head_hashes: Vec<[u8; HASH_BYTES]>,
    },
    /// All entries were purged (emergency invalidation).
    FullPurge {
        /// Number of heads evicted.
        evicted_count: usize,
        /// Content hashes of every evicted head (deterministic, sorted).
        evicted_head_hashes: Vec<[u8; HASH_BYTES]>,
        /// Reason for the purge.
        reason: InvalidationReason,
    },
    /// Capacity-based eviction removed the oldest entry.
    CapacityEviction {
        /// Content hash of the evicted head.
        head_hash: [u8; HASH_BYTES],
    },
    /// A stale head admission was rejected because a newer epoch for the
    /// same cell already exists in the cache (monotonic admission guard).
    StaleAdmissionRejected {
        /// Cell identity of the rejected head.
        cell_id: CellIdV1,
        /// Epoch of the rejected head.
        rejected_epoch: u64,
        /// Highest epoch currently cached for the cell.
        cached_epoch: u64,
    },
    /// Audit log reached capacity and older events were dropped.
    ///
    /// This sentinel is emitted exactly once when overflow occurs.
    /// Consumers seeing this event know that earlier audit entries
    /// were lost and should treat the log as incomplete.
    AuditOverflow {
        /// Number of audit events that were dropped.
        dropped_count: usize,
    },
}

/// Reason for a cache invalidation event.
#[allow(dead_code)]
#[allow(clippy::redundant_pub_crate)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum InvalidationReason {
    /// Identity was revoked in the directory.
    Revocation,
    /// Key rotation occurred for a cell or holon.
    KeyRotation,
    /// Head was superseded by a newer epoch.
    HeadAdvancement,
    /// Emergency invalidation requested by operator/policy.
    Emergency,
}

/// Structural verification cache for directory heads (REQ-0013).
///
/// **Cache amortization contract (HSI section 1.7.7c):**
/// One verified directory head admits O(log n) identity proof
/// verifications without repeated signature/quorum checks. The
/// head admission itself is O(1) in signature checks.
///
/// **Invalidation contract:**
/// The cache MUST invalidate deterministically on:
/// - **Revocation**: when a directory entry is marked Revoked/Suspended, the
///   cached head that committed that directory state is invalidated.
/// - **Key rotation**: when a cell's operational key rotates, all cached heads
///   for that cell are invalidated (the directory authority changed).
/// - **Head advancement**: when a newer epoch head is admitted for the same
///   cell, older epoch heads for that cell are superseded.
///
/// **Security invariant:** Stale cache entries CANNOT authorize revoked
/// identities. `verify_identity` returns the proof-derived entry status,
/// which the caller MUST check before granting authority. Additionally,
/// explicit invalidation methods remove heads from the cache entirely,
/// ensuring that even structural proof checks cannot proceed against
/// invalidated heads.
///
/// **Audit invariant:** Every cache mutation emits a
/// [`VerifierCacheAuditEvent`] into the audit log, enabling deterministic
/// post-hoc reconstruction of all invalidation decisions.
///
/// **Bounded audit buffer (REQ-0013 / security review R1):** The audit log
/// is bounded to `max_audit_events` entries. When the log reaches capacity,
/// old events are dropped and an `AuditOverflow` sentinel is emitted so
/// that consumers know events were lost. Callers SHOULD drain the log
/// periodically via [`drain_audit_log`] to avoid overflow.
#[allow(dead_code)]
#[allow(clippy::redundant_pub_crate)]
#[derive(Debug, Clone)]
pub(crate) struct VerifiedHeadCache {
    heads: HashMap<[u8; HASH_BYTES], VerifiedHead>,
    admission_order: VecDeque<[u8; HASH_BYTES]>,
    max_entries: usize,
    /// Bounded audit log of cache mutations.
    audit_log: VecDeque<VerifierCacheAuditEvent>,
    /// Maximum number of audit events retained before overflow.
    max_audit_events: usize,
}

/// Default maximum number of audit events retained before overflow.
///
/// This limit prevents unbounded memory growth in long-lived daemon
/// processes. At 4096 events the audit log stays well under 1 MiB
/// even with large `evicted_head_hashes` vectors.
#[allow(dead_code)]
const DEFAULT_MAX_AUDIT_EVENTS: usize = 4096;

#[allow(dead_code)]
impl VerifiedHeadCache {
    /// Creates a new bounded cache with at least one entry of capacity.
    ///
    /// The audit log is bounded to [`DEFAULT_MAX_AUDIT_EVENTS`] entries.
    #[must_use]
    pub(crate) fn new(max_entries: usize) -> Self {
        Self {
            heads: HashMap::new(),
            admission_order: VecDeque::new(),
            max_entries: max_entries.max(1),
            audit_log: VecDeque::new(),
            max_audit_events: DEFAULT_MAX_AUDIT_EVENTS,
        }
    }

    /// Creates a new bounded cache with explicit audit log capacity.
    ///
    /// Use this in tests or constrained environments where the default
    /// audit capacity is too large or too small.
    #[must_use]
    pub(crate) fn with_audit_capacity(max_entries: usize, max_audit_events: usize) -> Self {
        Self {
            heads: HashMap::new(),
            admission_order: VecDeque::new(),
            max_entries: max_entries.max(1),
            audit_log: VecDeque::new(),
            max_audit_events: max_audit_events.max(1),
        }
    }

    /// Pushes an audit event into the bounded log.
    ///
    /// If the log is at capacity, older events are dropped and an
    /// `AuditOverflow` sentinel replaces them. The sentinel itself
    /// counts toward the capacity, so the log never exceeds
    /// `max_audit_events`.
    ///
    /// **Post-condition:** `self.audit_log.len() <= self.max_audit_events`
    /// for all `max_audit_events >= 1`.
    fn push_audit_event(&mut self, event: VerifierCacheAuditEvent) {
        if self.audit_log.len() >= self.max_audit_events {
            // We need room for: the AuditOverflow sentinel + the new event = 2 slots.
            // For max_audit_events == 1, there is only 1 slot total, so the
            // new event replaces the overflow sentinel (we drop everything and
            // only push the new event with no sentinel).
            if self.max_audit_events <= 1 {
                // Only one slot: drop everything, push only the new event.
                let dropped = self.audit_log.len();
                self.audit_log.clear();
                // The new event implicitly replaces whatever was here.
                // We cannot fit both a sentinel and the event, so we log
                // the overflow count into tracing and push only the event.
                if dropped > 0 {
                    warn!(
                        dropped_count = dropped,
                        "audit log overflow (capacity=1): dropped all events"
                    );
                }
            } else {
                // We need exactly 2 free slots: one for AuditOverflow, one for the event.
                // Drop enough to make room for both, ensuring at least 1 is dropped.
                let target_len = self.max_audit_events.saturating_sub(2);
                let current_len = self.audit_log.len();
                let drop_count = current_len.saturating_sub(target_len).max(1);
                for _ in 0..drop_count {
                    self.audit_log.pop_front();
                }
                self.audit_log
                    .push_back(VerifierCacheAuditEvent::AuditOverflow {
                        dropped_count: drop_count,
                    });
            }
        }
        self.audit_log.push_back(event);

        // Defensive: guarantee post-condition even if logic above has a bug.
        while self.audit_log.len() > self.max_audit_events {
            self.audit_log.pop_front();
        }
        debug_assert!(self.audit_log.len() <= self.max_audit_events);
    }

    /// Admits a structurally verified head into cache.
    ///
    /// **Monotonic epoch admission (security review R2):** If the cache
    /// already contains a head for the same cell at a strictly higher
    /// epoch, the admission is rejected with
    /// [`IdentityProofError::StaleEpochRejected`]
    /// and a `StaleAdmissionRejected` audit event is emitted. This prevents
    /// out-of-order admission from reintroducing stale heads.
    ///
    /// **Atomic head-advancement (code-quality review R1):** If the cache
    /// already contains heads for the same cell at older epochs, those
    /// heads are atomically evicted before the new head is inserted.
    /// This enforces the head-advancement invariant at admission time,
    /// preventing stale same-cell heads from surviving in the cache.
    ///
    /// If the cache is at capacity after insertion, the oldest entry
    /// (by FIFO admission order) is evicted and a `CapacityEviction`
    /// audit event is emitted.
    pub(crate) fn admit_head(
        &mut self,
        head_hash: [u8; HASH_BYTES],
        head: HolonDirectoryHeadV1,
    ) -> Result<(), IdentityProofError> {
        head.validate()?;

        let computed_hash = head.content_hash()?;
        if computed_hash != head_hash {
            return Err(IdentityProofError::HashMismatch {
                field: "verified_head_cache.head_hash",
            });
        }

        let cell_id = head.cell_id().clone();
        let directory_epoch = head.directory_epoch();

        // --- Monotonic epoch guard: reject stale re-admissions ---
        // Check BEFORE any state mutation (transactional admission pattern).
        let max_cached_epoch = self
            .heads
            .values()
            .filter(|vh| vh.head.cell_id() == &cell_id)
            .map(|vh| vh.verified_at)
            .max();
        if let Some(cached_epoch) = max_cached_epoch {
            if directory_epoch < cached_epoch {
                self.push_audit_event(VerifierCacheAuditEvent::StaleAdmissionRejected {
                    cell_id,
                    rejected_epoch: directory_epoch,
                    cached_epoch,
                });
                return Err(IdentityProofError::StaleEpochRejected {
                    admitted_epoch: directory_epoch,
                    cached_epoch,
                });
            }
        }

        // --- Atomic head-advancement: evict older same-cell epochs ---
        let mut advancement_evicted: Vec<[u8; HASH_BYTES]> = self
            .heads
            .iter()
            .filter(|(h, vh)| {
                **h != head_hash
                    && vh.head.cell_id() == &cell_id
                    && vh.verified_at < directory_epoch
            })
            .map(|(h, _)| *h)
            .collect();
        if !advancement_evicted.is_empty() {
            for evicted_hash in &advancement_evicted {
                self.heads.remove(evicted_hash);
            }
            self.admission_order
                .retain(|h| self.heads.contains_key(h) || *h == head_hash);
            advancement_evicted.sort_unstable();
            self.push_audit_event(VerifierCacheAuditEvent::CellHeadAdvanced {
                cell_id: cell_id.clone(),
                new_epoch: directory_epoch,
                evicted_count: advancement_evicted.len(),
                evicted_head_hashes: advancement_evicted,
            });
        }

        // Keep admission order unique and bounded.
        self.admission_order
            .retain(|cached_hash| cached_hash != &head_hash);
        self.admission_order.push_back(head_hash);

        self.heads.insert(
            head_hash,
            VerifiedHead {
                verified_at: directory_epoch,
                head,
            },
        );

        // Evict oldest entries that exceed capacity.
        while self.heads.len() > self.max_entries {
            if let Some(evicted_hash) = self.admission_order.pop_front() {
                if self.heads.remove(&evicted_hash).is_some() {
                    self.push_audit_event(VerifierCacheAuditEvent::CapacityEviction {
                        head_hash: evicted_hash,
                    });
                }
            } else {
                break;
            }
        }

        self.push_audit_event(VerifierCacheAuditEvent::HeadAdmitted {
            head_hash,
            directory_epoch,
            cell_id,
        });

        Ok(())
    }

    /// Verify a proof against a cached head's root. Returns the
    /// proof-derived `DirectoryEntryStatus`.
    ///
    /// **SECURITY: This verifies structural proof validity only.
    /// Callers MUST check the returned `DirectoryEntryStatus` and
    /// deny authoritative operations for `Revoked` or `Suspended`
    /// entries. The full identity verification pipeline
    /// (`IdentityProofV1::verify()`) remains authoritative.**
    ///
    /// **Cache amortization (REQ-0013):** This method performs only
    /// O(log n) hash operations (proof path reconstruction), avoiding
    /// the O(1) signature/quorum checks that were already performed
    /// during head admission. This is the core cost reduction that
    /// makes the cache worthwhile.
    pub(crate) fn verify_identity(
        &self,
        head_hash: &[u8; HASH_BYTES],
        proof: &IdentityProofV1,
    ) -> Result<DirectoryEntryStatus, IdentityProofError> {
        let cached_head = self
            .heads
            .get(head_hash)
            .ok_or(IdentityProofError::VerifiedHeadCacheMiss)?;

        if proof.holon_directory_head_hash() != head_hash {
            return Err(IdentityProofError::HashMismatch {
                field: "holon_directory_head_hash",
            });
        }

        check_directory_kind_compatibility(
            cached_head.head.directory_kind(),
            proof.directory_proof().kind(),
        )?;

        let profile = resolve_known_profile(cached_head.head.identity_proof_profile_hash())?;
        cached_head.head.verify_profile_binding(&profile)?;
        profile.verify_directory_proof(&cached_head.head, proof.directory_proof())?;

        let structural_status = proof.directory_proof().entry_status();
        Ok(structural_status)
    }

    /// Invalidates a specific cached head by its content hash.
    ///
    /// Use this when a directory entry under the head is known to be
    /// revoked or suspended. Removing the head forces subsequent
    /// identity checks to re-verify via the full pipeline, which will
    /// observe the updated directory state.
    ///
    /// Returns `true` if the head was present and removed.
    pub(crate) fn invalidate_head(
        &mut self,
        head_hash: &[u8; HASH_BYTES],
        reason: InvalidationReason,
    ) -> bool {
        let removed = self.heads.remove(head_hash).is_some();
        if removed {
            self.admission_order
                .retain(|cached_hash| cached_hash != head_hash);
            self.push_audit_event(VerifierCacheAuditEvent::HeadInvalidated {
                head_hash: *head_hash,
                reason,
            });
        }
        removed
    }

    /// Invalidates all cached heads for a given cell identity.
    ///
    /// Use this when a cell's operational key rotates: the directory
    /// authority has changed, so all previously cached heads for that
    /// cell are potentially stale (the authority seal would need
    /// re-verification against the new key).
    ///
    /// Returns the number of heads evicted.
    pub(crate) fn invalidate_for_cell(
        &mut self,
        cell_id: &CellIdV1,
        reason: InvalidationReason,
    ) -> usize {
        let mut evicted_hashes: Vec<[u8; HASH_BYTES]> = self
            .heads
            .iter()
            .filter(|(_, vh)| vh.head.cell_id() == cell_id)
            .map(|(h, _)| *h)
            .collect();
        for evicted_hash in &evicted_hashes {
            self.heads.remove(evicted_hash);
        }
        let evicted_count = evicted_hashes.len();
        self.admission_order
            .retain(|head_hash| self.heads.contains_key(head_hash));
        if evicted_count > 0 {
            evicted_hashes.sort_unstable();
            self.push_audit_event(VerifierCacheAuditEvent::CellInvalidated {
                cell_id: cell_id.clone(),
                evicted_count,
                evicted_head_hashes: evicted_hashes,
                reason,
            });
        }
        evicted_count
    }

    /// Invalidates cached heads for a cell that are older than `new_epoch`.
    ///
    /// Use this when a newer directory head is observed for a cell:
    /// older epoch heads are superseded because the directory state has
    /// advanced. The newer head should be admitted separately via
    /// `admit_head`.
    ///
    /// Returns the number of heads evicted.
    pub(crate) fn invalidate_on_head_advance(
        &mut self,
        cell_id: &CellIdV1,
        new_epoch: u64,
    ) -> usize {
        let mut evicted_hashes: Vec<[u8; HASH_BYTES]> = self
            .heads
            .iter()
            .filter(|(_, vh)| vh.head.cell_id() == cell_id && vh.verified_at < new_epoch)
            .map(|(h, _)| *h)
            .collect();
        for evicted_hash in &evicted_hashes {
            self.heads.remove(evicted_hash);
        }
        let evicted_count = evicted_hashes.len();
        self.admission_order
            .retain(|head_hash| self.heads.contains_key(head_hash));
        if evicted_count > 0 {
            evicted_hashes.sort_unstable();
            self.push_audit_event(VerifierCacheAuditEvent::CellHeadAdvanced {
                cell_id: cell_id.clone(),
                new_epoch,
                evicted_count,
                evicted_head_hashes: evicted_hashes,
            });
        }
        evicted_count
    }

    /// Evicts cached heads older than `cutoff_epoch` directory epoch ticks.
    ///
    /// This is a global staleness sweep, independent of cell identity.
    /// Returns the number of heads evicted.
    pub(crate) fn evict_stale(&mut self, cutoff_epoch: u64) -> usize {
        let mut evicted_hashes: Vec<[u8; HASH_BYTES]> = self
            .heads
            .iter()
            .filter(|(_, vh)| vh.verified_at < cutoff_epoch)
            .map(|(h, _)| *h)
            .collect();
        for evicted_hash in &evicted_hashes {
            self.heads.remove(evicted_hash);
        }
        let evicted_count = evicted_hashes.len();
        self.admission_order
            .retain(|head_hash| self.heads.contains_key(head_hash));
        if evicted_count > 0 {
            evicted_hashes.sort_unstable();
            self.push_audit_event(VerifierCacheAuditEvent::StaleEvicted {
                cutoff_epoch,
                evicted_count,
                evicted_head_hashes: evicted_hashes,
            });
        }
        evicted_count
    }

    /// Emergency full purge: removes all cached heads.
    ///
    /// Use this when a policy or security event requires immediate
    /// invalidation of all cached state (e.g., key compromise detected).
    /// Returns the number of heads evicted.
    pub(crate) fn purge_all(&mut self, reason: InvalidationReason) -> usize {
        let mut evicted_hashes: Vec<[u8; HASH_BYTES]> = self.heads.keys().copied().collect();
        let evicted_count = evicted_hashes.len();
        self.heads.clear();
        self.admission_order.clear();
        if evicted_count > 0 {
            evicted_hashes.sort_unstable();
            self.push_audit_event(VerifierCacheAuditEvent::FullPurge {
                evicted_count,
                evicted_head_hashes: evicted_hashes,
                reason,
            });
        }
        evicted_count
    }

    /// Returns `true` if the cache contains a head with the given hash.
    pub(crate) fn contains_head(&self, head_hash: &[u8; HASH_BYTES]) -> bool {
        self.heads.contains_key(head_hash)
    }

    /// Returns the number of currently cached heads.
    pub(crate) fn len(&self) -> usize {
        self.heads.len()
    }

    /// Returns the number of audit events currently retained.
    pub(crate) fn audit_log_len(&self) -> usize {
        self.audit_log.len()
    }

    /// Returns a snapshot of the audit log as a `Vec`.
    ///
    /// The log is bounded to `max_audit_events` entries. If overflow
    /// occurred, an `AuditOverflow` event will be present indicating
    /// that earlier events were dropped.
    ///
    /// This enables deterministic post-hoc reconstruction of all
    /// invalidation decisions (REQ-0013), subject to the bounded
    /// retention window.
    pub(crate) fn audit_log(&self) -> Vec<VerifierCacheAuditEvent> {
        self.audit_log.iter().cloned().collect()
    }

    /// Drains the audit log, returning all events accumulated so far.
    ///
    /// This is useful for forwarding audit events to a persistent
    /// telemetry or ledger sink. Callers SHOULD drain periodically
    /// to prevent audit overflow.
    pub(crate) fn drain_audit_log(&mut self) -> Vec<VerifierCacheAuditEvent> {
        self.audit_log.drain(..).collect()
    }
}

/// Derives canonical directory key for a holon.
#[must_use]
pub fn derive_directory_key(holon_id: &HolonIdV1) -> [u8; HASH_BYTES] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(DIRECTORY_KEY_DOMAIN_SEPARATOR);
    hasher.update(&holon_id.to_binary());
    *hasher.finalize().as_bytes()
}

/// Returns canonical default-empty value hash used for non-membership proofs.
#[must_use]
pub fn default_empty_value_hash() -> [u8; HASH_BYTES] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(DIRECTORY_EMPTY_VALUE_DOMAIN_SEPARATOR);
    *hasher.finalize().as_bytes()
}

fn hash_directory_leaf(
    key: &[u8; HASH_BYTES],
    value_hash: &[u8; HASH_BYTES],
    entry_status: DirectoryEntryStatus,
) -> [u8; HASH_BYTES] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(DIRECTORY_LEAF_DOMAIN_SEPARATOR);
    hasher.update(key);
    hasher.update(value_hash);
    hasher.update(&[entry_status.to_byte()]);
    *hasher.finalize().as_bytes()
}

fn hash_directory_node(left: &[u8; HASH_BYTES], right: &[u8; HASH_BYTES]) -> [u8; HASH_BYTES] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(DIRECTORY_NODE_DOMAIN_SEPARATOR);
    hasher.update(left);
    hasher.update(right);
    *hasher.finalize().as_bytes()
}

const fn key_bit_at_depth(key: &[u8; HASH_BYTES], depth: usize) -> Result<u8, IdentityProofError> {
    if depth >= HASH_BYTES * 8 {
        return Err(IdentityProofError::SmtDepthExceeded { depth });
    }
    let byte = key[depth / 8];
    let shift = 7 - (depth % 8);
    Ok((byte >> shift) & 0x01)
}

fn hash_bytes(bytes: &[u8]) -> Hash {
    *blake3::hash(bytes).as_bytes()
}

/// Validates an identity proof hash at the handler admission boundary.
///
/// **WVR-0103 (Phase 1 limitation):** This validates that the hash is
/// well-formed and non-zero, acting as a shape-only binding commitment.
/// The caller attests they hold a valid `IdentityProofV1` by providing
/// its content hash.
///
/// Full CAS dereference + `IdentityProofV1::verify()` requires CAS
/// transport integration, which is deferred to TCK-00359 (verifier cache
/// contract and invalidation correctness). Until then, the hash is bound
/// into signed ledger event payloads for audit traceability.
///
/// See `documents/work/waivers/WVR-0103.yaml` for the formal waiver.
///
/// # Errors
///
/// Returns `IdentityProofError::InvalidField` if:
/// - The hash is not exactly 32 bytes
/// - The hash is all zeros (null commitment)
pub fn validate_identity_proof_hash(hash: &[u8]) -> Result<(), IdentityProofError> {
    if hash.len() != HASH_BYTES {
        return Err(IdentityProofError::InvalidField {
            field: "identity_proof_hash",
            reason: format!("must be exactly {HASH_BYTES} bytes, got {}", hash.len()),
        });
    }

    // SECURITY: A zero hash is a null commitment. Reject it to prevent
    // callers from bypassing the proof-carrying pointer requirement.
    if hash.iter().all(|&b| b == 0) {
        return Err(IdentityProofError::InvalidField {
            field: "identity_proof_hash",
            reason: "must be non-zero (null commitment rejected)".to_string(),
        });
    }

    // NOTE(TCK-00359): The verifier cache contract is implemented in
    // `VerifiedHeadCache` with deterministic invalidation on revocation,
    // rotation, and head advancement. Full CAS dereference integration
    // is tracked as a follow-on integration concern. The hash continues
    // to serve as a binding commitment included in signed event payloads
    // for audit traceability.

    Ok(())
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn consume_prefix(
        &mut self,
        prefix: &[u8],
        kind: &'static str,
        field: &'static str,
    ) -> Result<(), IdentityProofError> {
        if self.remaining() < prefix.len() {
            return Err(IdentityProofError::Truncated { field });
        }
        if &self.bytes[self.offset..self.offset + prefix.len()] != prefix {
            return Err(IdentityProofError::InvalidDomainSeparator { kind });
        }
        self.offset += prefix.len();
        Ok(())
    }

    fn read_u8(&mut self, field: &'static str) -> Result<u8, IdentityProofError> {
        if self.remaining() < 1 {
            return Err(IdentityProofError::Truncated { field });
        }
        let out = self.bytes[self.offset];
        self.offset += 1;
        Ok(out)
    }

    fn read_u32(&mut self, field: &'static str) -> Result<u32, IdentityProofError> {
        let raw = self.read_array::<4>(field)?;
        Ok(u32::from_le_bytes(raw))
    }

    fn read_u64(&mut self, field: &'static str) -> Result<u64, IdentityProofError> {
        let raw = self.read_array::<8>(field)?;
        Ok(u64::from_le_bytes(raw))
    }

    fn read_array<const N: usize>(
        &mut self,
        field: &'static str,
    ) -> Result<[u8; N], IdentityProofError> {
        if self.remaining() < N {
            return Err(IdentityProofError::Truncated { field });
        }
        let mut out = [0u8; N];
        out.copy_from_slice(&self.bytes[self.offset..self.offset + N]);
        self.offset += N;
        Ok(out)
    }

    fn read_bytes(
        &mut self,
        field: &'static str,
        len: usize,
    ) -> Result<&'a [u8], IdentityProofError> {
        if self.remaining() < len {
            return Err(IdentityProofError::Truncated { field });
        }
        let out = &self.bytes[self.offset..self.offset + len];
        self.offset += len;
        Ok(out)
    }

    const fn ensure_exhausted(&self, kind: &'static str) -> Result<(), IdentityProofError> {
        if self.remaining() == 0 {
            Ok(())
        } else {
            Err(IdentityProofError::TrailingBytes {
                kind,
                remaining: self.remaining(),
            })
        }
    }

    const fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.offset)
    }
}

#[cfg(test)]
mod tests {
    use apm2_core::evidence::{ContentAddressedStore, MemoryCas};
    use ed25519_dalek::SigningKey;

    use super::*;
    use crate::identity::{AlgorithmTag, CellGenesisV1, PolicyRootId};

    fn make_public_key_id(fill: u8) -> PublicKeyIdV1 {
        PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[fill; 32])
    }

    fn make_cell_certificate() -> CellCertificateV1 {
        let policy_root = PolicyRootId::Single(make_public_key_id(0xAB));
        let cell_genesis =
            CellGenesisV1::new([0x11; 32], policy_root.clone(), "cell.example.internal").unwrap();
        let cell_id = CellIdV1::from_genesis(&cell_genesis);
        CellCertificateV1::new(
            cell_id,
            "cell.example.internal",
            [0x11; 32],
            policy_root,
            super::super::RevocationPointer::LedgerAnchor {
                stream: "ledger.rotations".to_string(),
                from_envelope_ref: 7,
            },
            None,
            Vec::new(),
        )
        .unwrap()
    }

    fn make_holon_certificate(cell_id: CellIdV1) -> HolonCertificateV1 {
        let genesis_key_bytes = SigningKey::from_bytes(&[0x55u8; 32])
            .verifying_key()
            .to_bytes();
        let operational_key_bytes = SigningKey::from_bytes(&[0x66u8; 32])
            .verifying_key()
            .to_bytes();
        let genesis_key_id =
            PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &genesis_key_bytes);
        let operational_key_id =
            PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &operational_key_bytes);

        let genesis = HolonGenesisV1::new(
            cell_id.clone(),
            genesis_key_id.clone(),
            genesis_key_bytes.to_vec(),
            None,
            None,
        )
        .unwrap();
        let holon_id = HolonIdV1::from_genesis(&genesis);

        HolonCertificateV1::new(
            holon_id.clone(),
            cell_id,
            genesis_key_id,
            &genesis_key_bytes,
            operational_key_id,
            &operational_key_bytes,
            None,
            Some(format!(
                "spiffe://cell.example.internal/apm2/cell/{}/holon/{}",
                genesis.cell_id().to_text(),
                holon_id.to_text()
            )),
            vec!["relay.cell.internal:7443".to_string()],
            vec![super::super::HolonPurpose::Relay],
        )
        .unwrap()
    }

    fn compute_root_from_proof(proof: &DirectoryProofV1) -> [u8; HASH_BYTES] {
        let mut current =
            hash_directory_leaf(proof.key(), proof.value_hash(), proof.entry_status());
        for (depth, sibling) in proof.siblings().iter().enumerate() {
            let bit = key_bit_at_depth(proof.key(), depth).unwrap();
            current = if bit == 0 {
                hash_directory_node(&current, sibling.hash())
            } else {
                hash_directory_node(sibling.hash(), &current)
            };
        }
        current
    }

    fn baseline_profile_hash() -> [u8; HASH_BYTES] {
        IdentityProofProfileV1::baseline_smt_10e12()
            .content_hash()
            .expect("baseline profile hash should compute")
    }

    fn make_test_head(
        cell_id: CellIdV1,
        root: [u8; HASH_BYTES],
        directory_kind: DirectoryKindV1,
        max_proof_bytes: u32,
    ) -> HolonDirectoryHeadV1 {
        HolonDirectoryHeadV1::new(
            cell_id,
            12,
            LedgerAnchorV1::ConsensusIndex { index: 99 },
            root,
            directory_kind,
            1,
            max_proof_bytes,
            baseline_profile_hash(),
            [0x62; HASH_BYTES],
            [0x63; HASH_BYTES],
            None,
        )
        .unwrap()
    }

    fn make_test_identity_proof(
        cell_cert: &CellCertificateV1,
        holon_cert: &HolonCertificateV1,
        head: &HolonDirectoryHeadV1,
        proof: DirectoryProofV1,
        proof_generated_at_tick: u64,
    ) -> IdentityProofV1 {
        IdentityProofV1::new(
            Some(hash_bytes(&cell_cert.canonical_bytes().unwrap())),
            hash_bytes(&holon_cert.canonical_bytes().unwrap()),
            head.content_hash().unwrap(),
            proof,
            proof_generated_at_tick,
        )
        .unwrap()
    }

    #[test]
    fn directory_proof_smt_verifies_against_computed_root() {
        let key = [0x11; HASH_BYTES];
        let value_hash = [0x22; HASH_BYTES];
        let siblings = vec![
            SiblingNode::new([0x33; HASH_BYTES]),
            SiblingNode::new([0x44; HASH_BYTES]),
            SiblingNode::new([0x55; HASH_BYTES]),
            SiblingNode::new([0x66; HASH_BYTES]),
        ];

        let proof = DirectoryProofV1::new(
            DirectoryProofKindV1::Smt256CompressedV1,
            key,
            value_hash,
            DirectoryEntryStatus::Active,
            siblings,
        )
        .unwrap();

        let root = compute_root_from_proof(&proof);
        proof
            .verify_against_root(&root, proof.proof_bytes_len(), MAX_SMT_DEPTH, MAX_SMT_DEPTH)
            .expect("SMT proof should verify");
    }

    #[test]
    fn directory_proof_smt_rejects_status_tampering_without_root_update() {
        let key = [0x11; HASH_BYTES];
        let value_hash = [0x22; HASH_BYTES];
        let siblings = vec![
            SiblingNode::new([0x33; HASH_BYTES]),
            SiblingNode::new([0x44; HASH_BYTES]),
            SiblingNode::new([0x55; HASH_BYTES]),
            SiblingNode::new([0x66; HASH_BYTES]),
        ];

        let proof = DirectoryProofV1::new(
            DirectoryProofKindV1::Smt256CompressedV1,
            key,
            value_hash,
            DirectoryEntryStatus::Active,
            siblings,
        )
        .unwrap();

        let root = compute_root_from_proof(&proof);
        proof
            .verify_against_root(&root, proof.proof_bytes_len(), MAX_SMT_DEPTH, MAX_SMT_DEPTH)
            .expect("active proof should verify against its root");

        // Adversarial tampering: mutate only `entry_status` in the proof bytes
        // while keeping key/value/siblings/root unchanged.
        let mut tampered_bytes = proof.canonical_bytes().unwrap();
        let status_offset = DIRECTORY_PROOF_DOMAIN_SEPARATOR.len() + 1 + HASH_BYTES + HASH_BYTES;
        tampered_bytes[status_offset] = DirectoryEntryStatus::Revoked.to_byte();

        let tampered =
            DirectoryProofV1::from_canonical_bytes_bounded(&tampered_bytes, tampered_bytes.len())
                .expect("tampered bytes should still decode structurally");

        let err = tampered
            .verify_against_root(
                &root,
                tampered.proof_bytes_len(),
                MAX_SMT_DEPTH,
                MAX_SMT_DEPTH,
            )
            .unwrap_err();
        assert!(
            matches!(err, IdentityProofError::DirectoryRootMismatch),
            "status tampering must invalidate root reconstruction, got: {err:?}"
        );
    }

    #[test]
    fn directory_proof_rejects_oversized_policy_bound_violation() {
        let key = [0xAA; HASH_BYTES];
        let value_hash = [0xBB; HASH_BYTES];
        let siblings = vec![SiblingNode::new([0xCC; HASH_BYTES]); 8];

        let proof = DirectoryProofV1::new(
            DirectoryProofKindV1::Smt256CompressedV1,
            key,
            value_hash,
            DirectoryEntryStatus::Active,
            siblings,
        )
        .unwrap();
        let root = compute_root_from_proof(&proof);

        let err = proof
            .verify_against_root(
                &root,
                proof.proof_bytes_len() - 1,
                MAX_SMT_DEPTH,
                MAX_SMT_DEPTH,
            )
            .unwrap_err();
        assert!(matches!(err, IdentityProofError::ProofBytesExceeded { .. }));
    }

    #[test]
    fn directory_proof_round_trip_preserves_bytes_len() {
        let proof = DirectoryProofV1::new(
            DirectoryProofKindV1::Smt256CompressedV1,
            [0x01; HASH_BYTES],
            [0x02; HASH_BYTES],
            DirectoryEntryStatus::Active,
            vec![SiblingNode::new([0x03; HASH_BYTES])],
        )
        .unwrap();

        let bytes = proof.canonical_bytes().unwrap();
        let parsed = DirectoryProofV1::from_canonical_bytes_bounded(&bytes, bytes.len()).unwrap();

        assert_eq!(proof, parsed);
        assert_eq!(
            parsed.proof_bytes_len(),
            u32::try_from(bytes.len()).expect("test proof bytes length should fit in u32")
        );
    }

    #[test]
    fn directory_proof_patricia_kind_rejected_at_admission() {
        let proof = DirectoryProofV1::new(
            DirectoryProofKindV1::Smt256CompressedV1,
            [0x01; HASH_BYTES],
            [0x02; HASH_BYTES],
            DirectoryEntryStatus::Active,
            vec![SiblingNode::new([0x03; HASH_BYTES])],
        )
        .unwrap();

        let mut bytes = proof.canonical_bytes().unwrap();
        let kind_offset = DIRECTORY_PROOF_DOMAIN_SEPARATOR.len();
        bytes[kind_offset] = DirectoryProofKindV1::PatriciaCompressedV1.to_byte();

        let err = DirectoryProofV1::from_canonical_bytes_bounded(&bytes, bytes.len()).unwrap_err();
        assert!(matches!(
            err,
            IdentityProofError::UnsupportedDirectoryProofKind {
                kind: DirectoryProofKindV1::PatriciaCompressedV1
            }
        ));
    }

    #[test]
    fn directory_proof_patricia_kind_is_fail_closed_for_verification() {
        let proof = DirectoryProofV1::new(
            DirectoryProofKindV1::PatriciaCompressedV1,
            [0x10; HASH_BYTES],
            [0x20; HASH_BYTES],
            DirectoryEntryStatus::Active,
            vec![SiblingNode::new([0x30; HASH_BYTES])],
        )
        .unwrap();

        let err = proof
            .verify_against_root(
                &[0x40; HASH_BYTES],
                proof.proof_bytes_len(),
                MAX_SMT_DEPTH,
                MAX_SMT_DEPTH,
            )
            .unwrap_err();

        assert!(matches!(
            err,
            IdentityProofError::UnsupportedDirectoryProofKind { .. }
        ));
    }

    #[test]
    fn directory_head_round_trip_is_deterministic() {
        let cert = make_cell_certificate();
        let head = HolonDirectoryHeadV1::new(
            cert.cell_id().clone(),
            42,
            LedgerAnchorV1::SeqEvent {
                seq_id: 7,
                event_hash: [0x11; HASH_BYTES],
            },
            [0x22; HASH_BYTES],
            DirectoryKindV1::Smt256V1,
            12,
            8192,
            [0x33; HASH_BYTES],
            [0x44; HASH_BYTES],
            [0x45; HASH_BYTES],
            Some([0x55; HASH_BYTES]),
        )
        .unwrap();

        let bytes = head.canonical_bytes().unwrap();
        let parsed = HolonDirectoryHeadV1::from_canonical_bytes_bounded(&bytes, bytes.len())
            .expect("head should parse");
        assert_eq!(head, parsed);
        assert_eq!(head.content_hash().unwrap(), parsed.content_hash().unwrap());
    }

    #[test]
    fn test_directory_head_rejects_zero_profile_hash() {
        let cert = make_cell_certificate();
        let err = HolonDirectoryHeadV1::new(
            cert.cell_id().clone(),
            7,
            LedgerAnchorV1::ConsensusIndex { index: 1 },
            [0x22; HASH_BYTES],
            DirectoryKindV1::Smt256V1,
            1,
            4096,
            [0u8; HASH_BYTES],
            [0x33; HASH_BYTES],
            [0x44; HASH_BYTES],
            None,
        )
        .unwrap_err();

        assert!(matches!(
            err,
            IdentityProofError::InvalidField {
                field: "identity_proof_profile_hash",
                ..
            }
        ));
    }

    #[test]
    fn test_profile_binding_verified_against_head() {
        let cert = make_cell_certificate();
        let profile = IdentityProofProfileV1::baseline_smt_10e12();
        let profile_hash = profile.content_hash().unwrap();
        let head = HolonDirectoryHeadV1::new(
            cert.cell_id().clone(),
            7,
            LedgerAnchorV1::ConsensusIndex { index: 1 },
            [0x22; HASH_BYTES],
            DirectoryKindV1::Smt256V1,
            1,
            4096,
            profile_hash,
            [0x33; HASH_BYTES],
            [0x44; HASH_BYTES],
            None,
        )
        .unwrap();

        head.verify_profile_binding(&profile)
            .expect("profile hash should match head pin");

        let mut wrong_profile = IdentityProofProfileV1::baseline_smt_10e12();
        wrong_profile.max_depth -= 1;
        wrong_profile.max_non_default_siblings -= 1;
        wrong_profile.validate().unwrap();

        let err = head.verify_profile_binding(&wrong_profile).unwrap_err();
        assert!(matches!(
            err,
            IdentityProofError::IdentityProofProfileHashMismatch { .. }
        ));
    }

    #[test]
    fn identity_proof_verify_success_path() {
        let cell_cert = make_cell_certificate();
        let holon_cert = make_holon_certificate(cell_cert.cell_id().clone());

        let key = derive_directory_key(holon_cert.holon_id());
        let proof = DirectoryProofV1::new(
            DirectoryProofKindV1::Smt256CompressedV1,
            key,
            [0xAB; HASH_BYTES],
            DirectoryEntryStatus::Active,
            vec![
                SiblingNode::new([0x10; HASH_BYTES]),
                SiblingNode::new([0x11; HASH_BYTES]),
                SiblingNode::new([0x12; HASH_BYTES]),
            ],
        )
        .unwrap();

        let root = compute_root_from_proof(&proof);

        let head = HolonDirectoryHeadV1::new(
            cell_cert.cell_id().clone(),
            12,
            LedgerAnchorV1::ConsensusIndex { index: 99 },
            root,
            DirectoryKindV1::Smt256V1,
            1,
            8192,
            baseline_profile_hash(),
            [0x62; HASH_BYTES],
            [0x63; HASH_BYTES],
            None,
        )
        .unwrap();

        let identity_proof = IdentityProofV1::new(
            Some(hash_bytes(&cell_cert.canonical_bytes().unwrap())),
            hash_bytes(&holon_cert.canonical_bytes().unwrap()),
            head.content_hash().unwrap(),
            proof,
            100,
        )
        .unwrap();

        identity_proof
            .verify(
                holon_cert.holon_id(),
                &cell_cert,
                &holon_cert,
                &head,
                false,
                105,
                10,
                head.freshness_policy_hash(),
                &[0xAB; HASH_BYTES],
                |_, _, authority_seal_hash| {
                    if authority_seal_hash == &[0u8; HASH_BYTES] {
                        return Err(IdentityProofError::InvalidField {
                            field: "authority_seal_hash",
                            reason: "must be non-zero".to_string(),
                        });
                    }
                    Ok(())
                },
            )
            .expect("identity proof should verify");
    }

    #[test]
    fn test_unknown_profile_hash_rejected_for_tier2() {
        let cell_cert = make_cell_certificate();
        let holon_cert = make_holon_certificate(cell_cert.cell_id().clone());

        let key = derive_directory_key(holon_cert.holon_id());
        let proof = DirectoryProofV1::new(
            DirectoryProofKindV1::Smt256CompressedV1,
            key,
            [0xAB; HASH_BYTES],
            DirectoryEntryStatus::Active,
            vec![SiblingNode::new([0x10; HASH_BYTES])],
        )
        .unwrap();
        let root = compute_root_from_proof(&proof);

        let unknown_profile_hash = [0xEE; HASH_BYTES];
        assert_ne!(
            unknown_profile_hash,
            baseline_profile_hash(),
            "test requires an unknown profile hash"
        );

        let head = HolonDirectoryHeadV1::new(
            cell_cert.cell_id().clone(),
            12,
            LedgerAnchorV1::ConsensusIndex { index: 99 },
            root,
            DirectoryKindV1::Smt256V1,
            1,
            8192,
            unknown_profile_hash,
            [0x62; HASH_BYTES],
            [0x63; HASH_BYTES],
            None,
        )
        .unwrap();
        let identity_proof = make_test_identity_proof(&cell_cert, &holon_cert, &head, proof, 100);

        let err = identity_proof
            .verify_with_profile_policy(
                holon_cert.holon_id(),
                &cell_cert,
                &holon_cert,
                &head,
                false,
                105,
                10,
                head.freshness_policy_hash(),
                &[0xAB; HASH_BYTES],
                RiskTier::Tier2,
                None,
                |_, _, _| Ok(()),
            )
            .unwrap_err();
        assert!(matches!(
            err,
            IdentityProofError::UnknownIdentityProofProfile { .. }
        ));
    }

    #[test]
    fn test_profile_mismatch_rejected_during_verification() {
        let cell_cert = make_cell_certificate();
        let holon_cert = make_holon_certificate(cell_cert.cell_id().clone());

        let key = derive_directory_key(holon_cert.holon_id());
        let proof = DirectoryProofV1::new(
            DirectoryProofKindV1::Smt256CompressedV1,
            key,
            [0xAB; HASH_BYTES],
            DirectoryEntryStatus::Active,
            vec![SiblingNode::new([0x10; HASH_BYTES])],
        )
        .unwrap();
        let root = compute_root_from_proof(&proof);
        let head = make_test_head(
            cell_cert.cell_id().clone(),
            root,
            DirectoryKindV1::Smt256V1,
            8192,
        );
        let identity_proof = make_test_identity_proof(&cell_cert, &holon_cert, &head, proof, 100);

        let mut profile_b = IdentityProofProfileV1::baseline_smt_10e12();
        profile_b.max_depth -= 1;
        profile_b.max_non_default_siblings -= 1;
        profile_b.validate().unwrap();

        let err = identity_proof
            .verify_with_profile_policy(
                holon_cert.holon_id(),
                &cell_cert,
                &holon_cert,
                &head,
                false,
                105,
                10,
                head.freshness_policy_hash(),
                &[0xAB; HASH_BYTES],
                RiskTier::Tier2,
                Some(&profile_b),
                |_, _, _| Ok(()),
            )
            .unwrap_err();
        assert!(matches!(
            err,
            IdentityProofError::IdentityProofProfileHashMismatch { .. }
        ));
    }

    #[test]
    fn identity_proof_rejects_missing_cell_hash_without_direct_trust_pin() {
        let cell_cert = make_cell_certificate();
        let holon_cert = make_holon_certificate(cell_cert.cell_id().clone());

        let key = derive_directory_key(holon_cert.holon_id());
        let proof = DirectoryProofV1::new(
            DirectoryProofKindV1::Smt256CompressedV1,
            key,
            [0xAA; HASH_BYTES],
            DirectoryEntryStatus::Active,
            vec![SiblingNode::new([0xBB; HASH_BYTES])],
        )
        .unwrap();
        let root = compute_root_from_proof(&proof);

        let head = HolonDirectoryHeadV1::new(
            cell_cert.cell_id().clone(),
            1,
            LedgerAnchorV1::ConsensusIndex { index: 1 },
            root,
            DirectoryKindV1::Smt256V1,
            1,
            4096,
            baseline_profile_hash(),
            [0xC2; HASH_BYTES],
            [0xC3; HASH_BYTES],
            None,
        )
        .unwrap();

        let identity_proof = IdentityProofV1::new(
            None,
            hash_bytes(&holon_cert.canonical_bytes().unwrap()),
            head.content_hash().unwrap(),
            proof,
            10,
        )
        .unwrap();

        let err = identity_proof
            .verify(
                holon_cert.holon_id(),
                &cell_cert,
                &holon_cert,
                &head,
                false,
                10,
                10,
                head.freshness_policy_hash(),
                &[0xAA; HASH_BYTES],
                |_, _, _| Ok(()),
            )
            .unwrap_err();

        assert_eq!(err, IdentityProofError::MissingCellCertificateHash);
    }

    #[test]
    fn identity_proof_rejects_stale_tick() {
        let cell_cert = make_cell_certificate();
        let holon_cert = make_holon_certificate(cell_cert.cell_id().clone());

        let key = derive_directory_key(holon_cert.holon_id());
        let proof = DirectoryProofV1::new(
            DirectoryProofKindV1::Smt256CompressedV1,
            key,
            [0x01; HASH_BYTES],
            DirectoryEntryStatus::Active,
            vec![SiblingNode::new([0x02; HASH_BYTES])],
        )
        .unwrap();
        let root = compute_root_from_proof(&proof);

        let head = HolonDirectoryHeadV1::new(
            cell_cert.cell_id().clone(),
            1,
            LedgerAnchorV1::ConsensusIndex { index: 1 },
            root,
            DirectoryKindV1::Smt256V1,
            1,
            4096,
            baseline_profile_hash(),
            [0x04; HASH_BYTES],
            [0x05; HASH_BYTES],
            None,
        )
        .unwrap();

        let identity_proof = IdentityProofV1::new(
            Some(hash_bytes(&cell_cert.canonical_bytes().unwrap())),
            hash_bytes(&holon_cert.canonical_bytes().unwrap()),
            head.content_hash().unwrap(),
            proof,
            100,
        )
        .unwrap();

        let err = identity_proof
            .verify(
                holon_cert.holon_id(),
                &cell_cert,
                &holon_cert,
                &head,
                false,
                120,
                5,
                head.freshness_policy_hash(),
                &[0x01; HASH_BYTES],
                |_, _, _| Ok(()),
            )
            .unwrap_err();

        assert!(matches!(err, IdentityProofError::ProofStale { .. }));
    }

    #[test]
    fn identity_proof_fetch_from_cas_round_trip() {
        let proof = DirectoryProofV1::new(
            DirectoryProofKindV1::Smt256CompressedV1,
            [0x99; HASH_BYTES],
            default_empty_value_hash(),
            DirectoryEntryStatus::Active,
            vec![SiblingNode::new([0x88; HASH_BYTES])],
        )
        .unwrap();

        let identity_proof = IdentityProofV1::new(
            Some([0x77; HASH_BYTES]),
            [0x66; HASH_BYTES],
            [0x55; HASH_BYTES],
            proof,
            4242,
        )
        .unwrap();

        let bytes = identity_proof.canonical_bytes().unwrap();
        let cas = MemoryCas::new();
        let store_result = cas.store(&bytes).unwrap();

        let loaded =
            IdentityProofV1::fetch_from_cas(&cas, &store_result.hash, MAX_IDENTITY_PROOF_BYTES)
                .unwrap();
        assert_eq!(identity_proof, loaded);
    }

    // ====================================================================
    // FIX 1: validate_identity_proof_hash tests
    // ====================================================================

    #[test]
    fn validate_identity_proof_hash_rejects_zero_hash() {
        let err = validate_identity_proof_hash(&[0u8; 32]).unwrap_err();
        assert!(
            matches!(
                err,
                IdentityProofError::InvalidField {
                    field: "identity_proof_hash",
                    ..
                }
            ),
            "expected InvalidField for zero hash, got: {err:?}"
        );
    }

    #[test]
    fn validate_identity_proof_hash_rejects_wrong_length() {
        let short = vec![0x99u8; 16];
        let err = validate_identity_proof_hash(&short).unwrap_err();
        assert!(
            matches!(
                err,
                IdentityProofError::InvalidField {
                    field: "identity_proof_hash",
                    ..
                }
            ),
            "expected InvalidField for wrong length, got: {err:?}"
        );
    }

    #[test]
    fn validate_identity_proof_hash_accepts_random_non_zero_hash() {
        // Phase 1: a random non-CAS-resolvable hash is accepted.
        // The hash acts as a binding commitment.
        let hash = [0xDE; 32];
        validate_identity_proof_hash(&hash).expect("non-zero 32-byte hash should be accepted");
    }

    // ====================================================================
    // FIX 2: K->V value semantics tests
    // ====================================================================

    #[test]
    fn identity_proof_verify_rejects_mismatched_value_hash() {
        let cell_cert = make_cell_certificate();
        let holon_cert = make_holon_certificate(cell_cert.cell_id().clone());

        let key = derive_directory_key(holon_cert.holon_id());
        let actual_value_hash = [0xAB; HASH_BYTES];
        let proof = DirectoryProofV1::new(
            DirectoryProofKindV1::Smt256CompressedV1,
            key,
            actual_value_hash,
            DirectoryEntryStatus::Active,
            vec![
                SiblingNode::new([0x10; HASH_BYTES]),
                SiblingNode::new([0x11; HASH_BYTES]),
            ],
        )
        .unwrap();
        let root = compute_root_from_proof(&proof);

        let head = HolonDirectoryHeadV1::new(
            cell_cert.cell_id().clone(),
            12,
            LedgerAnchorV1::ConsensusIndex { index: 99 },
            root,
            DirectoryKindV1::Smt256V1,
            1,
            8192,
            baseline_profile_hash(),
            [0x62; HASH_BYTES],
            [0x63; HASH_BYTES],
            None,
        )
        .unwrap();

        let identity_proof = IdentityProofV1::new(
            Some(hash_bytes(&cell_cert.canonical_bytes().unwrap())),
            hash_bytes(&holon_cert.canonical_bytes().unwrap()),
            head.content_hash().unwrap(),
            proof,
            100,
        )
        .unwrap();

        // Provide a WRONG expected value hash
        let wrong_expected = [0xFF; HASH_BYTES];
        let err = identity_proof
            .verify(
                holon_cert.holon_id(),
                &cell_cert,
                &holon_cert,
                &head,
                false,
                105,
                10,
                head.freshness_policy_hash(),
                &wrong_expected,
                |_, _, _| Ok(()),
            )
            .unwrap_err();

        assert!(
            matches!(err, IdentityProofError::ValueHashMismatch { .. }),
            "expected ValueHashMismatch, got: {err:?}"
        );
    }

    #[test]
    fn identity_proof_verify_rejects_revoked_entry() {
        let cell_cert = make_cell_certificate();
        let holon_cert = make_holon_certificate(cell_cert.cell_id().clone());

        let key = derive_directory_key(holon_cert.holon_id());
        let value_hash = [0xAB; HASH_BYTES];
        // TCK-00356 Fix 4: Revoked status is now proof-derived, not caller-asserted.
        // The directory proof itself carries DirectoryEntryStatus::Revoked.
        let proof = DirectoryProofV1::new(
            DirectoryProofKindV1::Smt256CompressedV1,
            key,
            value_hash,
            DirectoryEntryStatus::Revoked,
            vec![
                SiblingNode::new([0x10; HASH_BYTES]),
                SiblingNode::new([0x11; HASH_BYTES]),
            ],
        )
        .unwrap();
        let root = compute_root_from_proof(&proof);

        let head = HolonDirectoryHeadV1::new(
            cell_cert.cell_id().clone(),
            12,
            LedgerAnchorV1::ConsensusIndex { index: 99 },
            root,
            DirectoryKindV1::Smt256V1,
            1,
            8192,
            baseline_profile_hash(),
            [0x62; HASH_BYTES],
            [0x63; HASH_BYTES],
            None,
        )
        .unwrap();

        let identity_proof = IdentityProofV1::new(
            Some(hash_bytes(&cell_cert.canonical_bytes().unwrap())),
            hash_bytes(&holon_cert.canonical_bytes().unwrap()),
            head.content_hash().unwrap(),
            proof,
            100,
        )
        .unwrap();

        // Proof-derived status is Revoked — verify must reject
        let err = identity_proof
            .verify(
                holon_cert.holon_id(),
                &cell_cert,
                &holon_cert,
                &head,
                false,
                105,
                10,
                head.freshness_policy_hash(),
                &value_hash,
                |_, _, _| Ok(()),
            )
            .unwrap_err();

        assert_eq!(err, IdentityProofError::EntryRevoked);
    }

    #[test]
    fn identity_proof_verify_rejects_suspended_entry() {
        // Suspended entries MUST also be denied (same as revoked).
        assert!(!DirectoryEntryStatus::Suspended.is_active());
    }

    #[test]
    fn identity_proof_verify_active_entry_passes() {
        assert!(DirectoryEntryStatus::Active.is_active());
    }

    // ====================================================================
    // FIX 3: Directory kind compatibility tests
    // ====================================================================

    #[test]
    fn directory_kind_smt_head_with_smt_proof_is_compatible() {
        check_directory_kind_compatibility(
            DirectoryKindV1::Smt256V1,
            DirectoryProofKindV1::Smt256CompressedV1,
        )
        .expect("SMT head with SMT proof should be compatible");
    }

    #[test]
    fn directory_kind_patricia_head_with_patricia_proof_is_compatible() {
        check_directory_kind_compatibility(
            DirectoryKindV1::PatriciaTrieV1,
            DirectoryProofKindV1::PatriciaCompressedV1,
        )
        .expect("Patricia head with Patricia proof should be compatible");
    }

    #[test]
    fn directory_kind_smt_head_with_patricia_proof_is_rejected() {
        let err = check_directory_kind_compatibility(
            DirectoryKindV1::Smt256V1,
            DirectoryProofKindV1::PatriciaCompressedV1,
        )
        .unwrap_err();

        assert!(
            matches!(err, IdentityProofError::DirectoryKindMismatch { .. }),
            "expected DirectoryKindMismatch, got: {err:?}"
        );
    }

    #[test]
    fn directory_kind_patricia_head_with_smt_proof_is_rejected() {
        let err = check_directory_kind_compatibility(
            DirectoryKindV1::PatriciaTrieV1,
            DirectoryProofKindV1::Smt256CompressedV1,
        )
        .unwrap_err();

        assert!(
            matches!(err, IdentityProofError::DirectoryKindMismatch { .. }),
            "expected DirectoryKindMismatch, got: {err:?}"
        );
    }

    // ====================================================================
    // TCK-00357: malformed proof negatives
    // ====================================================================

    #[test]
    fn test_forged_root_hash_rejected() {
        let proof = DirectoryProofV1::new(
            DirectoryProofKindV1::Smt256CompressedV1,
            [0x11; HASH_BYTES],
            [0x22; HASH_BYTES],
            DirectoryEntryStatus::Active,
            vec![
                SiblingNode::new([0x33; HASH_BYTES]),
                SiblingNode::new([0x44; HASH_BYTES]),
                SiblingNode::new([0x55; HASH_BYTES]),
            ],
        )
        .unwrap();
        let mut forged_root = compute_root_from_proof(&proof);
        forged_root[0] ^= 0x80;

        let err = proof
            .verify_against_root(
                &forged_root,
                proof.proof_bytes_len(),
                MAX_SMT_DEPTH,
                MAX_SMT_DEPTH,
            )
            .unwrap_err();
        assert!(matches!(err, IdentityProofError::DirectoryRootMismatch));
    }

    #[test]
    fn test_truncated_proof_bytes_rejected() {
        let proof = DirectoryProofV1::new(
            DirectoryProofKindV1::Smt256CompressedV1,
            [0x10; HASH_BYTES],
            [0x20; HASH_BYTES],
            DirectoryEntryStatus::Active,
            vec![
                SiblingNode::new([0x30; HASH_BYTES]),
                SiblingNode::new([0x40; HASH_BYTES]),
            ],
        )
        .unwrap();
        let bytes = proof.canonical_bytes().unwrap();
        let truncated = &bytes[..bytes.len() - 10];

        let err =
            DirectoryProofV1::from_canonical_bytes_bounded(truncated, truncated.len()).unwrap_err();
        assert!(matches!(err, IdentityProofError::Truncated { .. }));
    }

    #[test]
    fn test_corrupted_sibling_hash_rejected() {
        let proof = DirectoryProofV1::new(
            DirectoryProofKindV1::Smt256CompressedV1,
            [0x01; HASH_BYTES],
            [0x02; HASH_BYTES],
            DirectoryEntryStatus::Active,
            vec![
                SiblingNode::new([0x03; HASH_BYTES]),
                SiblingNode::new([0x04; HASH_BYTES]),
            ],
        )
        .unwrap();
        let root = compute_root_from_proof(&proof);

        let mut bytes = proof.canonical_bytes().unwrap();
        let first_sibling_offset =
            DIRECTORY_PROOF_DOMAIN_SEPARATOR.len() + 1 + HASH_BYTES + HASH_BYTES + 1 + 4 + 4;
        bytes[first_sibling_offset] ^= 0x01;

        let corrupted =
            DirectoryProofV1::from_canonical_bytes_bounded(&bytes, bytes.len()).unwrap();
        let err = corrupted
            .verify_against_root(
                &root,
                corrupted.proof_bytes_len(),
                MAX_SMT_DEPTH,
                MAX_SMT_DEPTH,
            )
            .unwrap_err();
        assert!(matches!(err, IdentityProofError::DirectoryRootMismatch));
    }

    #[test]
    fn test_empty_siblings_list_rejected() {
        let err = DirectoryProofV1::new(
            DirectoryProofKindV1::Smt256CompressedV1,
            [0xAA; HASH_BYTES],
            [0xBB; HASH_BYTES],
            DirectoryEntryStatus::Active,
            Vec::new(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            IdentityProofError::InvalidField {
                field: "siblings",
                ..
            }
        ));
    }

    // ====================================================================
    // TCK-00357: over-depth / over-size negatives
    // ====================================================================

    #[test]
    fn test_proof_exceeds_max_depth_rejected() {
        let siblings = (0..=MAX_SMT_DEPTH)
            .map(|i| SiblingNode::new([u8::try_from(i).unwrap_or(0xFE); HASH_BYTES]))
            .collect::<Vec<_>>();
        let proof = DirectoryProofV1::new(
            DirectoryProofKindV1::Smt256CompressedV1,
            [0x10; HASH_BYTES],
            [0x20; HASH_BYTES],
            DirectoryEntryStatus::Active,
            siblings,
        )
        .unwrap();
        let root = compute_root_from_proof(&proof);

        let err = proof
            .verify_against_root(&root, proof.proof_bytes_len(), MAX_SMT_DEPTH, MAX_SMT_DEPTH)
            .unwrap_err();
        assert!(matches!(err, IdentityProofError::DepthExceeded { .. }));
    }

    #[test]
    fn test_proof_exceeds_max_proof_bytes_rejected() {
        let oversized = vec![0u8; MAX_DIRECTORY_PROOF_BYTES + 1];
        let err = DirectoryProofV1::from_canonical_bytes_bounded(&oversized, oversized.len())
            .unwrap_err();
        assert!(matches!(
            err,
            IdentityProofError::DecodeBoundExceeded {
                max: MAX_DIRECTORY_PROOF_BYTES,
                ..
            }
        ));
    }

    #[test]
    fn test_proof_exceeds_max_siblings_rejected() {
        let proof = DirectoryProofV1::new(
            DirectoryProofKindV1::Smt256CompressedV1,
            [0x01; HASH_BYTES],
            [0x02; HASH_BYTES],
            DirectoryEntryStatus::Active,
            vec![SiblingNode::new([0x03; HASH_BYTES])],
        )
        .unwrap();

        let mut bytes = proof.canonical_bytes().unwrap();
        let sibling_count_offset =
            DIRECTORY_PROOF_DOMAIN_SEPARATOR.len() + 1 + HASH_BYTES + HASH_BYTES + 1 + 4;
        let excessive_count =
            u32::try_from(MAX_DIRECTORY_SIBLINGS).expect("MAX_DIRECTORY_SIBLINGS fits in u32") + 1;
        bytes[sibling_count_offset..sibling_count_offset + 4]
            .copy_from_slice(&excessive_count.to_le_bytes());

        let err = DirectoryProofV1::from_canonical_bytes_bounded(&bytes, bytes.len()).unwrap_err();
        assert!(matches!(err, IdentityProofError::TooManySiblings { .. }));
    }

    #[test]
    fn test_proof_exceeds_profile_max_depth_rejected() {
        let cell_cert = make_cell_certificate();
        let holon_cert = make_holon_certificate(cell_cert.cell_id().clone());
        let key = derive_directory_key(holon_cert.holon_id());
        let profile = IdentityProofProfileV1 {
            max_depth: MIN_SMT_DEPTH_10E12,
            max_non_default_siblings: MIN_SMT_DEPTH_10E12,
            ..IdentityProofProfileV1::baseline_smt_10e12()
        };
        let profile_hash = profile
            .content_hash()
            .expect("test profile hash should compute");

        let siblings = (0..=MIN_SMT_DEPTH_10E12)
            .map(|i| SiblingNode::new([u8::try_from(i).unwrap_or(0xEE); HASH_BYTES]))
            .collect::<Vec<_>>();
        let proof = DirectoryProofV1::new(
            DirectoryProofKindV1::Smt256CompressedV1,
            key,
            [0xAB; HASH_BYTES],
            DirectoryEntryStatus::Active,
            siblings,
        )
        .unwrap();
        let root = compute_root_from_proof(&proof);
        let head = HolonDirectoryHeadV1::new(
            cell_cert.cell_id().clone(),
            12,
            LedgerAnchorV1::ConsensusIndex { index: 99 },
            root,
            DirectoryKindV1::Smt256V1,
            1,
            8192,
            profile_hash,
            [0x62; HASH_BYTES],
            [0x63; HASH_BYTES],
            None,
        )
        .expect("test head should be valid");
        let err = profile.verify_directory_proof(&head, &proof).unwrap_err();
        assert!(matches!(err, IdentityProofError::DepthExceeded { .. }));
    }

    // ====================================================================
    // TCK-00357: forged proof negatives
    // ====================================================================

    #[test]
    fn test_inclusion_proof_with_wrong_key_rejected() {
        let cell_cert = make_cell_certificate();
        let holon_cert = make_holon_certificate(cell_cert.cell_id().clone());

        let mut wrong_key = derive_directory_key(holon_cert.holon_id());
        wrong_key[0] ^= 0x01;
        let proof = DirectoryProofV1::new(
            DirectoryProofKindV1::Smt256CompressedV1,
            wrong_key,
            [0xAB; HASH_BYTES],
            DirectoryEntryStatus::Active,
            vec![
                SiblingNode::new([0x10; HASH_BYTES]),
                SiblingNode::new([0x11; HASH_BYTES]),
            ],
        )
        .unwrap();
        let root = compute_root_from_proof(&proof);
        let head = make_test_head(
            cell_cert.cell_id().clone(),
            root,
            DirectoryKindV1::Smt256V1,
            8192,
        );
        let identity_proof = make_test_identity_proof(&cell_cert, &holon_cert, &head, proof, 100);

        let err = identity_proof
            .verify(
                holon_cert.holon_id(),
                &cell_cert,
                &holon_cert,
                &head,
                false,
                105,
                10,
                head.freshness_policy_hash(),
                &[0xAB; HASH_BYTES],
                |_, _, _| Ok(()),
            )
            .unwrap_err();
        assert!(matches!(err, IdentityProofError::DirectoryKeyMismatch));
    }

    #[test]
    fn test_inclusion_proof_with_wrong_value_rejected() {
        let cell_cert = make_cell_certificate();
        let holon_cert = make_holon_certificate(cell_cert.cell_id().clone());
        let key = derive_directory_key(holon_cert.holon_id());

        let proof = DirectoryProofV1::new(
            DirectoryProofKindV1::Smt256CompressedV1,
            key,
            [0xAB; HASH_BYTES],
            DirectoryEntryStatus::Active,
            vec![
                SiblingNode::new([0x10; HASH_BYTES]),
                SiblingNode::new([0x11; HASH_BYTES]),
            ],
        )
        .unwrap();
        let root = compute_root_from_proof(&proof);
        let head = make_test_head(
            cell_cert.cell_id().clone(),
            root,
            DirectoryKindV1::Smt256V1,
            8192,
        );
        let identity_proof = make_test_identity_proof(&cell_cert, &holon_cert, &head, proof, 100);

        let err = identity_proof
            .verify(
                holon_cert.holon_id(),
                &cell_cert,
                &holon_cert,
                &head,
                false,
                105,
                10,
                head.freshness_policy_hash(),
                &[0xCD; HASH_BYTES],
                |_, _, _| Ok(()),
            )
            .unwrap_err();
        assert!(matches!(err, IdentityProofError::ValueHashMismatch { .. }));
    }

    #[test]
    fn test_non_membership_proof_forged_as_membership_rejected() {
        let cell_cert = make_cell_certificate();
        let holon_cert = make_holon_certificate(cell_cert.cell_id().clone());
        let key = derive_directory_key(holon_cert.holon_id());

        let proof = DirectoryProofV1::new(
            DirectoryProofKindV1::Smt256CompressedV1,
            key,
            default_empty_value_hash(),
            DirectoryEntryStatus::Active,
            vec![
                SiblingNode::new([0x10; HASH_BYTES]),
                SiblingNode::new([0x11; HASH_BYTES]),
            ],
        )
        .unwrap();
        let root = compute_root_from_proof(&proof);
        let head = make_test_head(
            cell_cert.cell_id().clone(),
            root,
            DirectoryKindV1::Smt256V1,
            8192,
        );
        let identity_proof = make_test_identity_proof(&cell_cert, &holon_cert, &head, proof, 100);

        let err = identity_proof
            .verify(
                holon_cert.holon_id(),
                &cell_cert,
                &holon_cert,
                &head,
                false,
                105,
                10,
                head.freshness_policy_hash(),
                &[0xEF; HASH_BYTES],
                |_, _, _| Ok(()),
            )
            .unwrap_err();
        assert!(matches!(err, IdentityProofError::ValueHashMismatch { .. }));
    }

    // ====================================================================
    // TCK-00357: kind compatibility negatives
    // ====================================================================

    #[test]
    fn test_patricia_proof_rejected_at_admission() {
        let proof = DirectoryProofV1::new(
            DirectoryProofKindV1::Smt256CompressedV1,
            [0x01; HASH_BYTES],
            [0x02; HASH_BYTES],
            DirectoryEntryStatus::Active,
            vec![SiblingNode::new([0x03; HASH_BYTES])],
        )
        .unwrap();

        let mut bytes = proof.canonical_bytes().unwrap();
        let kind_offset = DIRECTORY_PROOF_DOMAIN_SEPARATOR.len();
        bytes[kind_offset] = DirectoryProofKindV1::PatriciaCompressedV1.to_byte();

        let err = DirectoryProofV1::from_canonical_bytes_bounded(&bytes, bytes.len()).unwrap_err();
        assert!(matches!(
            err,
            IdentityProofError::UnsupportedDirectoryProofKind {
                kind: DirectoryProofKindV1::PatriciaCompressedV1
            }
        ));
    }

    #[test]
    fn test_profile_kind_mismatch_rejected() {
        let cell_cert = make_cell_certificate();
        let holon_cert = make_holon_certificate(cell_cert.cell_id().clone());
        let key = derive_directory_key(holon_cert.holon_id());
        let proof = DirectoryProofV1::new(
            DirectoryProofKindV1::Smt256CompressedV1,
            key,
            [0xAB; HASH_BYTES],
            DirectoryEntryStatus::Active,
            vec![SiblingNode::new([0x10; HASH_BYTES])],
        )
        .unwrap();
        let root = compute_root_from_proof(&proof);
        let patricia_head = make_test_head(
            cell_cert.cell_id().clone(),
            root,
            DirectoryKindV1::PatriciaTrieV1,
            8192,
        );
        let identity_proof =
            make_test_identity_proof(&cell_cert, &holon_cert, &patricia_head, proof, 100);

        let err = identity_proof
            .verify(
                holon_cert.holon_id(),
                &cell_cert,
                &holon_cert,
                &patricia_head,
                false,
                105,
                10,
                patricia_head.freshness_policy_hash(),
                &[0xAB; HASH_BYTES],
                |_, _, _| Ok(()),
            )
            .unwrap_err();
        assert!(matches!(
            err,
            IdentityProofError::DirectoryKindMismatch { .. }
        ));
    }

    // ====================================================================
    // TCK-00357: profile/cache implementation tests
    // ====================================================================

    #[test]
    fn identity_proof_profile_round_trip_and_bounded_decode() {
        let profile = IdentityProofProfileV1::baseline_smt_10e12();
        let bytes = profile.canonical_bytes().unwrap();
        let parsed =
            IdentityProofProfileV1::from_canonical_bytes_bounded(&bytes, bytes.len()).unwrap();
        assert_eq!(parsed, profile);

        let err = IdentityProofProfileV1::from_canonical_bytes_bounded(&bytes, bytes.len() - 1)
            .unwrap_err();
        assert!(matches!(
            err,
            IdentityProofError::DecodeBoundExceeded { .. }
        ));
    }

    #[test]
    fn identity_proof_profile_rejects_scale_target_violations() {
        let bad_depth = IdentityProofProfileV1 {
            max_depth: MIN_SMT_DEPTH_10E12 - 1,
            ..IdentityProofProfileV1::baseline_smt_10e12()
        };
        let err = bad_depth.validate().unwrap_err();
        assert!(matches!(
            err,
            IdentityProofError::InvalidField {
                field: "max_depth",
                ..
            }
        ));

        let mut bad_hash_ops = IdentityProofProfileV1::baseline_smt_10e12();
        bad_hash_ops
            .verifier_cost_target
            .max_hash_ops_per_membership_proof = MAX_HASH_OPS_PER_MEMBERSHIP_PROOF_10E12 + 1;
        let err = bad_hash_ops.validate().unwrap_err();
        assert!(matches!(
            err,
            IdentityProofError::InvalidField {
                field: "verifier_cost_target.max_hash_ops_per_membership_proof",
                ..
            }
        ));
    }

    #[test]
    fn directory_proof_rejects_non_default_sibling_inflation() {
        let proof = DirectoryProofV1::new(
            DirectoryProofKindV1::Smt256CompressedV1,
            [0x01; HASH_BYTES],
            [0x02; HASH_BYTES],
            DirectoryEntryStatus::Active,
            vec![
                SiblingNode::new([0x10; HASH_BYTES]),
                SiblingNode::new([0x11; HASH_BYTES]),
                SiblingNode::new([0x12; HASH_BYTES]),
                SiblingNode::new([0x00; HASH_BYTES]),
            ],
        )
        .unwrap();
        let root = compute_root_from_proof(&proof);

        let err = proof
            .verify_against_root(&root, proof.proof_bytes_len(), 8, 2)
            .unwrap_err();
        assert!(matches!(
            err,
            IdentityProofError::NonDefaultSiblingsExceeded { .. }
        ));
    }

    #[test]
    fn verified_head_cache_amortizes_head_verification() {
        let cell_cert = make_cell_certificate();
        let holon_cert = make_holon_certificate(cell_cert.cell_id().clone());
        let key = derive_directory_key(holon_cert.holon_id());
        let proof = DirectoryProofV1::new(
            DirectoryProofKindV1::Smt256CompressedV1,
            key,
            [0xAB; HASH_BYTES],
            DirectoryEntryStatus::Active,
            vec![
                SiblingNode::new([0x10; HASH_BYTES]),
                SiblingNode::new([0x11; HASH_BYTES]),
            ],
        )
        .unwrap();
        let root = compute_root_from_proof(&proof);
        let head = make_test_head(
            cell_cert.cell_id().clone(),
            root,
            DirectoryKindV1::Smt256V1,
            8192,
        );
        let head_hash = head.content_hash().unwrap();
        let identity_proof = make_test_identity_proof(&cell_cert, &holon_cert, &head, proof, 100);

        let mut cache = VerifiedHeadCache::new(8);
        cache.admit_head(head_hash, head).unwrap();
        let status = cache.verify_identity(&head_hash, &identity_proof).unwrap();
        assert_eq!(status, DirectoryEntryStatus::Active);
    }

    #[test]
    fn verified_head_cache_evict_stale_entries() {
        // Use distinct cells for each head to avoid triggering atomic
        // head-advancement eviction within `admit_head`.
        let cell_cert = make_cell_certificate();
        let other_cert = make_other_cell_certificate();
        // Third distinct cell via make_epoch_head with a fresh genesis.
        let third_cell_genesis = CellGenesisV1::new(
            [0x33; 32],
            PolicyRootId::Single(make_public_key_id(0xEE)),
            "third.cell.internal",
        )
        .unwrap();
        let third_cell_id = CellIdV1::from_genesis(&third_cell_genesis);

        let stale_head = make_epoch_head(cell_cert.cell_id().clone(), 5, 0xA1);
        let boundary_head = make_epoch_head(other_cert.cell_id().clone(), 20, 0xA2);
        let fresh_head = make_epoch_head(third_cell_id, 25, 0xA3);

        let stale_hash = stale_head.content_hash().unwrap();
        let boundary_hash = boundary_head.content_hash().unwrap();
        let fresh_hash = fresh_head.content_hash().unwrap();

        let mut cache = VerifiedHeadCache::new(8);
        cache.admit_head(stale_hash, stale_head).unwrap();
        cache.admit_head(boundary_hash, boundary_head).unwrap();
        cache.admit_head(fresh_hash, fresh_head).unwrap();
        assert_eq!(cache.len(), 3);

        cache.evict_stale(20);

        assert!(!cache.heads.contains_key(&stale_hash));
        assert!(cache.heads.contains_key(&boundary_hash));
        assert!(cache.heads.contains_key(&fresh_hash));
    }

    #[test]
    fn directory_entry_status_byte_round_trip() {
        for (status, byte) in [
            (DirectoryEntryStatus::Active, 0x01),
            (DirectoryEntryStatus::Revoked, 0x02),
            (DirectoryEntryStatus::Suspended, 0x03),
        ] {
            assert_eq!(status.to_byte(), byte);
            assert_eq!(DirectoryEntryStatus::from_byte(byte).unwrap(), status);
        }
    }

    #[test]
    fn directory_entry_status_rejects_unknown_tag() {
        let err = DirectoryEntryStatus::from_byte(0xFF).unwrap_err();
        assert!(
            matches!(
                err,
                IdentityProofError::InvalidEnumTag {
                    field: "directory_entry_status",
                    tag: 0xFF
                }
            ),
            "expected InvalidEnumTag for 0xFF, got: {err:?}"
        );
    }

    // ---------------------------------------------------------------
    // TCK-00359: Verifier cache invalidation correctness tests
    // ---------------------------------------------------------------

    /// Helper to create a second cell certificate with a different `cell_id`.
    fn make_other_cell_certificate() -> CellCertificateV1 {
        let policy_root = PolicyRootId::Single(make_public_key_id(0xCD));
        let cell_genesis =
            CellGenesisV1::new([0x22; 32], policy_root.clone(), "other.cell.internal").unwrap();
        let cell_id = CellIdV1::from_genesis(&cell_genesis);
        CellCertificateV1::new(
            cell_id,
            "other.cell.internal",
            [0x22; 32],
            policy_root,
            super::super::RevocationPointer::LedgerAnchor {
                stream: "ledger.rotations".to_string(),
                from_envelope_ref: 8,
            },
            None,
            Vec::new(),
        )
        .unwrap()
    }

    /// Helper to create a head with a specific epoch for a cell.
    fn make_epoch_head(cell_id: CellIdV1, epoch: u64, root_fill: u8) -> HolonDirectoryHeadV1 {
        HolonDirectoryHeadV1::new(
            cell_id,
            epoch,
            LedgerAnchorV1::ConsensusIndex { index: epoch },
            [root_fill; HASH_BYTES],
            DirectoryKindV1::Smt256V1,
            1,
            8192,
            [root_fill.wrapping_add(0x10); HASH_BYTES],
            [root_fill.wrapping_add(0x20); HASH_BYTES],
            [root_fill.wrapping_add(0x30); HASH_BYTES],
            None,
        )
        .unwrap()
    }

    // --- Cache amortization: verify that cache hit reduces cost ---

    #[test]
    fn cache_admits_and_verifies_multiple_proofs_against_same_head() {
        // REQ-0013: "Cache reuse measurably reduces repeated verification cost"
        //
        // Once a head is admitted, multiple identity proofs can be verified
        // against it using only O(log n) hash ops per proof, without
        // re-verifying the head's authority seal.
        let cell_cert = make_cell_certificate();
        let holon_cert = make_holon_certificate(cell_cert.cell_id().clone());
        let key = derive_directory_key(holon_cert.holon_id());
        let proof = DirectoryProofV1::new(
            DirectoryProofKindV1::Smt256CompressedV1,
            key,
            [0xAB; HASH_BYTES],
            DirectoryEntryStatus::Active,
            vec![
                SiblingNode::new([0x10; HASH_BYTES]),
                SiblingNode::new([0x11; HASH_BYTES]),
            ],
        )
        .unwrap();
        let root = compute_root_from_proof(&proof);
        let head = make_test_head(
            cell_cert.cell_id().clone(),
            root,
            DirectoryKindV1::Smt256V1,
            8192,
        );
        let head_hash = head.content_hash().unwrap();
        let identity_proof = make_test_identity_proof(&cell_cert, &holon_cert, &head, proof, 100);

        let mut cache = VerifiedHeadCache::new(8);
        cache.admit_head(head_hash, head).unwrap();

        // Verify the same proof multiple times -- each time is a cache hit.
        for _ in 0..5 {
            let status = cache.verify_identity(&head_hash, &identity_proof).unwrap();
            assert_eq!(status, DirectoryEntryStatus::Active);
        }

        // Verify audit log records exactly one admission.
        let admission_count = cache
            .audit_log()
            .iter()
            .filter(|e| matches!(e, VerifierCacheAuditEvent::HeadAdmitted { .. }))
            .count();
        assert_eq!(admission_count, 1, "exactly one admission event expected");
    }

    // --- Invalidation on revocation ---

    #[test]
    fn cache_invalidate_head_removes_revoked_entry() {
        // REQ-0013: "Stale cache entries cannot authorize revoked identities"
        let cell_cert = make_cell_certificate();
        let head = make_epoch_head(cell_cert.cell_id().clone(), 10, 0xA1);
        let head_hash = head.content_hash().unwrap();

        let mut cache = VerifiedHeadCache::new(8);
        cache.admit_head(head_hash, head).unwrap();
        assert!(cache.contains_head(&head_hash));

        // Simulate revocation: invalidate the specific head.
        let removed = cache.invalidate_head(&head_hash, InvalidationReason::Revocation);
        assert!(removed, "head should have been present and removed");
        assert!(
            !cache.contains_head(&head_hash),
            "head must not survive revocation invalidation"
        );
        assert_eq!(cache.len(), 0);

        // Verify identity against invalidated head must fail with cache miss.
        let holon_cert = make_holon_certificate(cell_cert.cell_id().clone());
        let key = derive_directory_key(holon_cert.holon_id());
        let proof = DirectoryProofV1::new(
            DirectoryProofKindV1::Smt256CompressedV1,
            key,
            [0xAB; HASH_BYTES],
            DirectoryEntryStatus::Active,
            vec![SiblingNode::new([0x10; HASH_BYTES])],
        )
        .unwrap();
        let identity_proof = IdentityProofV1::new(
            Some([0x99; HASH_BYTES]),
            [0x88; HASH_BYTES],
            head_hash,
            proof,
            100,
        )
        .unwrap();
        let err = cache
            .verify_identity(&head_hash, &identity_proof)
            .unwrap_err();
        assert!(
            matches!(err, IdentityProofError::VerifiedHeadCacheMiss),
            "revoked head should produce cache miss, got: {err:?}"
        );
    }

    #[test]
    fn cache_invalidate_head_returns_false_for_absent_head() {
        let mut cache = VerifiedHeadCache::new(8);
        let removed = cache.invalidate_head(&[0xFF; HASH_BYTES], InvalidationReason::Revocation);
        assert!(!removed, "invalidating absent head should return false");
        assert!(
            cache.audit_log().is_empty(),
            "no audit event for absent head"
        );
    }

    #[test]
    fn cache_verify_returns_revoked_status_for_revoked_proof() {
        // Even before explicit invalidation, verify_identity returns the
        // proof-derived status. Callers must check this status to deny
        // authoritative operations for revoked entries.
        let cell_cert = make_cell_certificate();
        let holon_cert = make_holon_certificate(cell_cert.cell_id().clone());
        let key = derive_directory_key(holon_cert.holon_id());
        let proof = DirectoryProofV1::new(
            DirectoryProofKindV1::Smt256CompressedV1,
            key,
            [0xAB; HASH_BYTES],
            DirectoryEntryStatus::Revoked,
            vec![
                SiblingNode::new([0x10; HASH_BYTES]),
                SiblingNode::new([0x11; HASH_BYTES]),
            ],
        )
        .unwrap();
        let root = compute_root_from_proof(&proof);
        let head = make_test_head(
            cell_cert.cell_id().clone(),
            root,
            DirectoryKindV1::Smt256V1,
            8192,
        );
        let head_hash = head.content_hash().unwrap();
        let identity_proof = make_test_identity_proof(&cell_cert, &holon_cert, &head, proof, 100);

        let mut cache = VerifiedHeadCache::new(8);
        cache.admit_head(head_hash, head).unwrap();

        // Cache returns Revoked status -- caller MUST deny authority.
        let status = cache.verify_identity(&head_hash, &identity_proof).unwrap();
        assert_eq!(
            status,
            DirectoryEntryStatus::Revoked,
            "cache must return proof-derived Revoked status"
        );
    }

    // --- Invalidation on key rotation ---

    #[test]
    fn cache_invalidate_for_cell_removes_all_heads_for_cell() {
        // REQ-0013: Key rotation invalidation.
        //
        // Atomic head-advancement in `admit_head` means only the latest
        // epoch for a given cell survives admission. We test that
        // `invalidate_for_cell` removes even the surviving latest head,
        // plus verify that the other cell's head is untouched.
        let cell_cert = make_cell_certificate();
        let other_cert = make_other_cell_certificate();

        // head2 will auto-evict head1 on admission (same cell, higher epoch).
        let head1 = make_epoch_head(cell_cert.cell_id().clone(), 10, 0xA1);
        let head2 = make_epoch_head(cell_cert.cell_id().clone(), 15, 0xA2);
        let other_head = make_epoch_head(other_cert.cell_id().clone(), 12, 0xB1);

        let hash1 = head1.content_hash().unwrap();
        let hash2 = head2.content_hash().unwrap();
        let other_hash = other_head.content_hash().unwrap();

        let mut cache = VerifiedHeadCache::new(16);
        cache.admit_head(hash1, head1).unwrap();
        cache.admit_head(hash2, head2).unwrap();
        // head1 was auto-evicted by head2's admission.
        assert!(
            !cache.contains_head(&hash1),
            "head1 should be auto-evicted by head2 admission"
        );
        cache.admit_head(other_hash, other_head).unwrap();
        assert_eq!(cache.len(), 2, "head2 + other_head");

        // Simulate key rotation for the first cell.
        let evicted =
            cache.invalidate_for_cell(cell_cert.cell_id(), InvalidationReason::KeyRotation);
        assert_eq!(evicted, 1, "remaining head for cell should be evicted");
        assert!(!cache.contains_head(&hash2));
        assert!(
            cache.contains_head(&other_hash),
            "other cell's head must survive"
        );
        assert_eq!(cache.len(), 1);

        // Verify audit log records the cell invalidation.
        let cell_event_count = cache
            .audit_log()
            .iter()
            .filter(|e| matches!(e, VerifierCacheAuditEvent::CellInvalidated { .. }))
            .count();
        assert_eq!(cell_event_count, 1, "exactly one cell invalidation event");
    }

    #[test]
    fn cache_invalidate_for_cell_returns_zero_for_absent_cell() {
        let cell_cert = make_cell_certificate();
        let mut cache = VerifiedHeadCache::new(8);
        let evicted =
            cache.invalidate_for_cell(cell_cert.cell_id(), InvalidationReason::KeyRotation);
        assert_eq!(evicted, 0);
    }

    // --- Invalidation on head advancement ---

    #[test]
    fn cache_invalidate_on_head_advance_removes_old_epochs() {
        // REQ-0013: Head advancement invalidation via explicit method.
        //
        // Use distinct cells to hold one head each so that the atomic
        // advancement inside `admit_head` does not pre-evict them.
        // Then call `invalidate_on_head_advance` to test the explicit
        // method against a cell that has only a single head.
        let cell_cert = make_cell_certificate();
        let other_cert = make_other_cell_certificate();

        // Admit a single head per cell (no atomic same-cell eviction).
        let cell_head = make_epoch_head(cell_cert.cell_id().clone(), 15, 0xA2);
        let other_head = make_epoch_head(other_cert.cell_id().clone(), 3, 0xB1);

        let cell_hash = cell_head.content_hash().unwrap();
        let other_hash = other_head.content_hash().unwrap();

        let mut cache = VerifiedHeadCache::new(16);
        cache.admit_head(cell_hash, cell_head).unwrap();
        cache.admit_head(other_hash, other_head).unwrap();
        assert_eq!(cache.len(), 2);

        // Advance: invalidate heads for cell_cert older than epoch 20.
        // cell_head (epoch 15 < 20) should be evicted; other_head preserved.
        let evicted = cache.invalidate_on_head_advance(cell_cert.cell_id(), 20);
        assert_eq!(evicted, 1, "cell_head (15) should be evicted");
        assert!(!cache.contains_head(&cell_hash));
        assert!(cache.contains_head(&other_hash), "other cell must survive");

        // Verify audit event from explicit call.
        let advance_event_count = cache
            .audit_log()
            .iter()
            .filter(|e| matches!(e, VerifierCacheAuditEvent::CellHeadAdvanced { .. }))
            .count();
        assert_eq!(advance_event_count, 1);
    }

    #[test]
    fn cache_invalidate_on_head_advance_keeps_equal_epoch() {
        // Head at exactly the new_epoch boundary should be retained.
        let cell_cert = make_cell_certificate();
        let boundary_head = make_epoch_head(cell_cert.cell_id().clone(), 20, 0xA1);
        let boundary_hash = boundary_head.content_hash().unwrap();

        let mut cache = VerifiedHeadCache::new(8);
        cache.admit_head(boundary_hash, boundary_head).unwrap();

        let evicted = cache.invalidate_on_head_advance(cell_cert.cell_id(), 20);
        assert_eq!(evicted, 0, "epoch == new_epoch should be retained");
        assert!(cache.contains_head(&boundary_hash));
    }

    // --- Atomic head-advancement on admission (regression) ---

    #[test]
    fn admit_head_atomically_evicts_older_same_cell_epochs() {
        // Regression test (code-quality + security review R1):
        // Admitting epoch N+1 for the same cell MUST automatically
        // evict epoch N without requiring a separate call to
        // `invalidate_on_head_advance`.
        let cell_cert = make_cell_certificate();
        let other_cert = make_other_cell_certificate();

        let head_n = make_epoch_head(cell_cert.cell_id().clone(), 10, 0xA1);
        let head_n1 = make_epoch_head(cell_cert.cell_id().clone(), 20, 0xA2);
        let other_head = make_epoch_head(other_cert.cell_id().clone(), 5, 0xB1);

        let hash_n = head_n.content_hash().unwrap();
        let hash_n1 = head_n1.content_hash().unwrap();
        let other_hash = other_head.content_hash().unwrap();

        let mut cache = VerifiedHeadCache::new(16);
        cache.admit_head(hash_n, head_n).unwrap();
        cache.admit_head(other_hash, other_head).unwrap();
        assert_eq!(cache.len(), 2);

        // Admit epoch N+1 for the same cell -- epoch N must be auto-evicted.
        cache.admit_head(hash_n1, head_n1).unwrap();

        assert!(
            !cache.contains_head(&hash_n),
            "epoch-N head must be evicted atomically on epoch-N+1 admission"
        );
        assert!(
            cache.contains_head(&hash_n1),
            "newly admitted epoch-N+1 head must be present"
        );
        assert!(
            cache.contains_head(&other_hash),
            "other cell's head must not be affected"
        );
        assert_eq!(
            cache.len(),
            2,
            "only epoch-N+1 and other_head should remain"
        );

        // Verify audit log contains a CellHeadAdvanced event for the
        // atomic eviction, proving no external invalidation was needed.
        let all_events = cache.drain_audit_log();
        let advancement_events: Vec<_> = all_events
            .iter()
            .filter(|e| matches!(e, VerifierCacheAuditEvent::CellHeadAdvanced { .. }))
            .collect();
        assert_eq!(
            advancement_events.len(),
            1,
            "exactly one CellHeadAdvanced event expected from atomic admission"
        );
        if let VerifierCacheAuditEvent::CellHeadAdvanced {
            cell_id,
            new_epoch,
            evicted_count,
            evicted_head_hashes,
        } = advancement_events[0]
        {
            assert_eq!(cell_id, cell_cert.cell_id());
            assert_eq!(*new_epoch, 20);
            assert_eq!(*evicted_count, 1);
            assert_eq!(evicted_head_hashes.len(), 1);
            assert_eq!(evicted_head_hashes[0], hash_n);
        } else {
            panic!("expected CellHeadAdvanced event");
        }
    }

    #[test]
    fn admit_head_atomically_evicts_multiple_older_same_cell_epochs() {
        // Admitting a head at epoch 30 should evict ALL remaining older
        // same-cell heads. We use two different cells to accumulate
        // multiple heads for the target cell without triggering
        // intermediate advancement evictions between them.
        let cell_cert = make_cell_certificate();
        let other_cert = make_other_cell_certificate();

        // Two heads for cell_cert at different epochs, admitted
        // with an interleaving other-cell head to show selectivity.
        let early_head = make_epoch_head(cell_cert.cell_id().clone(), 5, 0xA1);
        let middle_head = make_epoch_head(cell_cert.cell_id().clone(), 15, 0xA2);
        let latest_head = make_epoch_head(cell_cert.cell_id().clone(), 30, 0xA3);
        let other_head = make_epoch_head(other_cert.cell_id().clone(), 8, 0xB1);

        let early_hash = early_head.content_hash().unwrap();
        let middle_hash = middle_head.content_hash().unwrap();
        let latest_hash = latest_head.content_hash().unwrap();
        let other_hash = other_head.content_hash().unwrap();

        let mut cache = VerifiedHeadCache::new(16);
        cache.admit_head(early_hash, early_head).unwrap();
        // Admitting middle_head for the same cell auto-evicts early_head.
        cache.admit_head(middle_hash, middle_head).unwrap();
        assert!(
            !cache.contains_head(&early_hash),
            "epoch-5 must already be evicted by epoch-15 admission"
        );

        cache.admit_head(other_hash, other_head).unwrap();
        assert_eq!(cache.len(), 2, "middle_head + other_head");

        // Admit epoch 30 -- middle_head must be evicted, other_head preserved.
        cache.admit_head(latest_hash, latest_head).unwrap();

        assert!(!cache.contains_head(&early_hash), "epoch 5 must be evicted");
        assert!(
            !cache.contains_head(&middle_hash),
            "epoch 15 must be evicted"
        );
        assert!(
            cache.contains_head(&latest_hash),
            "epoch 30 must be present"
        );
        assert!(
            cache.contains_head(&other_hash),
            "other cell must be unaffected"
        );
        assert_eq!(cache.len(), 2, "epoch-30 + other_head should remain");

        // Two CellHeadAdvanced events total: one for middle_head evicting
        // early_head, one for latest_head evicting middle_head.
        let advancement_count = cache
            .audit_log()
            .iter()
            .filter(|e| matches!(e, VerifierCacheAuditEvent::CellHeadAdvanced { .. }))
            .count();
        assert_eq!(
            advancement_count, 2,
            "two atomic advancement evictions expected"
        );
    }

    #[test]
    fn admit_head_does_not_evict_equal_epoch_same_cell() {
        // Re-admitting the same head (same hash, same epoch) should NOT
        // trigger a head-advancement eviction event.
        let cell_cert = make_cell_certificate();
        let head = make_epoch_head(cell_cert.cell_id().clone(), 10, 0xA1);
        let head_clone = head.clone();
        let hash = head.content_hash().unwrap();

        let mut cache = VerifiedHeadCache::new(8);
        cache.admit_head(hash, head).unwrap();
        cache.admit_head(hash, head_clone).unwrap();

        assert!(cache.contains_head(&hash));
        assert_eq!(cache.len(), 1);

        // No CellHeadAdvanced event should be emitted for re-admission.
        let advancement_count = cache
            .audit_log()
            .iter()
            .filter(|e| matches!(e, VerifierCacheAuditEvent::CellHeadAdvanced { .. }))
            .count();
        assert_eq!(
            advancement_count, 0,
            "re-admitting same head should not trigger advancement eviction"
        );
    }

    // --- Global stale eviction ---

    #[test]
    fn cache_evict_stale_returns_count_and_emits_audit() {
        // Use distinct cells to avoid atomic same-cell head advancement.
        let cell_cert = make_cell_certificate();
        let other_cert = make_other_cell_certificate();
        let stale_head = make_epoch_head(cell_cert.cell_id().clone(), 5, 0xA1);
        let fresh_head = make_epoch_head(other_cert.cell_id().clone(), 25, 0xA3);

        let stale_hash = stale_head.content_hash().unwrap();
        let fresh_hash = fresh_head.content_hash().unwrap();

        let mut cache = VerifiedHeadCache::new(8);
        cache.admit_head(stale_hash, stale_head).unwrap();
        cache.admit_head(fresh_hash, fresh_head).unwrap();
        assert_eq!(cache.len(), 2);

        let evicted = cache.evict_stale(20);
        assert_eq!(evicted, 1, "only the stale head should be evicted");
        assert!(!cache.contains_head(&stale_hash));
        assert!(cache.contains_head(&fresh_hash));

        // Verify audit event.
        let stale_event_count = cache
            .audit_log()
            .iter()
            .filter(|e| matches!(e, VerifierCacheAuditEvent::StaleEvicted { .. }))
            .count();
        assert_eq!(stale_event_count, 1);
    }

    // --- Emergency purge ---

    #[test]
    fn cache_purge_all_removes_everything() {
        let cell_cert = make_cell_certificate();
        let other_cert = make_other_cell_certificate();

        let head1 = make_epoch_head(cell_cert.cell_id().clone(), 10, 0xA1);
        let head2 = make_epoch_head(other_cert.cell_id().clone(), 20, 0xB1);
        let hash1 = head1.content_hash().unwrap();
        let hash2 = head2.content_hash().unwrap();

        let mut cache = VerifiedHeadCache::new(8);
        cache.admit_head(hash1, head1).unwrap();
        cache.admit_head(hash2, head2).unwrap();
        assert_eq!(cache.len(), 2);

        let evicted = cache.purge_all(InvalidationReason::Emergency);
        assert_eq!(evicted, 2);
        assert_eq!(cache.len(), 0);
        assert!(!cache.contains_head(&hash1));
        assert!(!cache.contains_head(&hash2));

        // Verify audit event.
        let purge_event_count = cache
            .audit_log()
            .iter()
            .filter(|e| matches!(e, VerifierCacheAuditEvent::FullPurge { .. }))
            .count();
        assert_eq!(purge_event_count, 1);
    }

    #[test]
    fn cache_purge_all_on_empty_cache_is_noop() {
        let mut cache = VerifiedHeadCache::new(8);
        let evicted = cache.purge_all(InvalidationReason::Emergency);
        assert_eq!(evicted, 0);
        // No audit event for empty purge.
        let purge_event_count = cache
            .audit_log()
            .iter()
            .filter(|e| matches!(e, VerifierCacheAuditEvent::FullPurge { .. }))
            .count();
        assert_eq!(purge_event_count, 0);
    }

    // --- Capacity eviction audit ---

    #[test]
    fn cache_capacity_eviction_emits_audit_event() {
        // Use distinct cells to avoid atomic same-cell head advancement.
        let cell_cert = make_cell_certificate();
        let other_cert = make_other_cell_certificate();
        let third_genesis = CellGenesisV1::new(
            [0x44; 32],
            PolicyRootId::Single(make_public_key_id(0xDD)),
            "third.cap.cell.internal",
        )
        .unwrap();
        let third_cell_id = CellIdV1::from_genesis(&third_genesis);

        // Cache with capacity 2
        let mut cache = VerifiedHeadCache::new(2);

        let head1 = make_epoch_head(cell_cert.cell_id().clone(), 1, 0xA1);
        let head2 = make_epoch_head(other_cert.cell_id().clone(), 2, 0xA2);
        let head3 = make_epoch_head(third_cell_id, 3, 0xA3);
        let hash1 = head1.content_hash().unwrap();
        let hash2 = head2.content_hash().unwrap();
        let hash3 = head3.content_hash().unwrap();

        cache.admit_head(hash1, head1).unwrap();
        cache.admit_head(hash2, head2).unwrap();
        assert_eq!(cache.len(), 2);

        // Admitting a third head should evict the first (FIFO).
        cache.admit_head(hash3, head3).unwrap();
        assert_eq!(cache.len(), 2);
        assert!(
            !cache.contains_head(&hash1),
            "oldest head should be evicted"
        );
        assert!(cache.contains_head(&hash2));
        assert!(cache.contains_head(&hash3));

        // Verify capacity eviction audit event.
        let cap_event_count = cache
            .audit_log()
            .iter()
            .filter(|e| matches!(e, VerifierCacheAuditEvent::CapacityEviction { .. }))
            .count();
        assert_eq!(cap_event_count, 1, "one capacity eviction event expected");
    }

    // --- Audit log drain ---

    #[test]
    fn cache_drain_audit_log_clears_events() {
        let cell_cert = make_cell_certificate();
        let head = make_epoch_head(cell_cert.cell_id().clone(), 10, 0xA1);
        let hash = head.content_hash().unwrap();

        let mut cache = VerifiedHeadCache::new(8);
        cache.admit_head(hash, head).unwrap();
        assert!(!cache.audit_log().is_empty());

        let drained = cache.drain_audit_log();
        assert!(!drained.is_empty());
        assert!(
            cache.audit_log().is_empty(),
            "audit log should be empty after drain"
        );
    }

    // --- Stale cache negative: revoked identity cannot be authorized ---

    #[test]
    fn stale_cache_cannot_authorize_revoked_identity() {
        // REQ-0013: "Stale cache entries cannot authorize revoked identities"
        //
        // Scenario: A head is admitted. Later, the identity is revoked.
        // Even if the old head is still in the cache, verify_identity
        // returns `Revoked` status, preventing authorization.
        // Then, explicit invalidation removes the head entirely.
        let cell_cert = make_cell_certificate();
        let holon_cert = make_holon_certificate(cell_cert.cell_id().clone());
        let key = derive_directory_key(holon_cert.holon_id());

        // Build a proof with Revoked status (as the directory has been updated).
        let proof = DirectoryProofV1::new(
            DirectoryProofKindV1::Smt256CompressedV1,
            key,
            [0xAB; HASH_BYTES],
            DirectoryEntryStatus::Revoked,
            vec![
                SiblingNode::new([0x10; HASH_BYTES]),
                SiblingNode::new([0x11; HASH_BYTES]),
            ],
        )
        .unwrap();
        let root = compute_root_from_proof(&proof);
        let head = make_test_head(
            cell_cert.cell_id().clone(),
            root,
            DirectoryKindV1::Smt256V1,
            8192,
        );
        let head_hash = head.content_hash().unwrap();
        let identity_proof = make_test_identity_proof(&cell_cert, &holon_cert, &head, proof, 100);

        let mut cache = VerifiedHeadCache::new(8);
        cache.admit_head(head_hash, head).unwrap();

        // Step 1: verify_identity returns Revoked -- caller MUST deny.
        let status = cache.verify_identity(&head_hash, &identity_proof).unwrap();
        assert_eq!(status, DirectoryEntryStatus::Revoked);

        // Step 2: Explicit invalidation removes the head entirely.
        cache.invalidate_head(&head_hash, InvalidationReason::Revocation);
        assert!(!cache.contains_head(&head_hash));

        // Step 3: Subsequent verification fails with cache miss.
        let err = cache
            .verify_identity(&head_hash, &identity_proof)
            .unwrap_err();
        assert!(matches!(err, IdentityProofError::VerifiedHeadCacheMiss));
    }

    // --- Deterministic invalidation path ---

    #[test]
    fn invalidation_path_is_deterministic_and_auditable() {
        // REQ-0013: "Invalidation path is deterministic and auditable"
        //
        // The same sequence of operations always produces the same
        // audit log, enabling deterministic post-hoc reconstruction.
        let cell_cert = make_cell_certificate();
        let head1 = make_epoch_head(cell_cert.cell_id().clone(), 5, 0xA1);
        let head2 = make_epoch_head(cell_cert.cell_id().clone(), 15, 0xA2);
        let hash1 = head1.content_hash().unwrap();
        let hash2 = head2.content_hash().unwrap();

        // Run the same sequence twice.
        let run = || {
            let mut cache = VerifiedHeadCache::new(8);
            cache.admit_head(hash1, head1.clone()).unwrap();
            cache.admit_head(hash2, head2.clone()).unwrap();
            // head1 is atomically evicted by admit_head(head2) since
            // epoch 5 < 15 for the same cell. Explicit invalidation
            // of hash1 returns false (already evicted).
            let already_gone = !cache.invalidate_head(&hash1, InvalidationReason::Revocation);
            assert!(
                already_gone,
                "head1 should already be gone via atomic advancement"
            );
            cache.evict_stale(20);
            cache.drain_audit_log()
        };

        let log1 = run();
        let log2 = run();
        assert_eq!(log1, log2, "audit logs must be identical across runs");
        // Expected events:
        //   1. Admit(head1)
        //   2. CellHeadAdvanced (head1 evicted atomically by head2 admission)
        //   3. Admit(head2)
        //   4. StaleEvicted (head2 epoch 15 < cutoff 20)
        assert_eq!(log1.len(), 4, "expected 4 audit events");
    }

    /// Regression test (Round 3): Tier2+ strict mode MUST reject an
    /// `expected_profile` whose hash matches the directory head but is NOT in
    /// the known-profile registry. Before the fix, supplying `expected_profile`
    /// bypassed `resolve_known_profile()`, violating REQ-0012.
    #[test]
    fn test_tier2_rejects_unknown_but_hash_matching_expected_profile() {
        let cell_cert = make_cell_certificate();
        let holon_cert = make_holon_certificate(cell_cert.cell_id().clone());

        let key = derive_directory_key(holon_cert.holon_id());
        let proof = DirectoryProofV1::new(
            DirectoryProofKindV1::Smt256CompressedV1,
            key,
            [0xAB; HASH_BYTES],
            DirectoryEntryStatus::Active,
            vec![SiblingNode::new([0x10; HASH_BYTES])],
        )
        .unwrap();
        let root = compute_root_from_proof(&proof);

        // Construct a custom profile that is NOT in the known-profile registry.
        // It differs from baseline_smt_10e12 by using a different max_proof_bytes.
        let custom_profile = IdentityProofProfileV1 {
            directory_kind: DirectoryProofKindV1::Smt256CompressedV1,
            max_depth: MAX_SMT_DEPTH,
            max_proof_bytes: 4096, // different from baseline's 8192
            max_non_default_siblings: MAX_SMT_DEPTH,
            supports_membership_multiproof: false,
            supports_non_membership_proof: true,
            verifier_cost_target: VerifierCostTarget {
                max_hash_ops_per_membership_proof: MAX_HASH_OPS_PER_MEMBERSHIP_PROOF_10E12,
                max_signature_or_quorum_checks_per_cached_head: 1,
                max_bytes_fetched_for_verification: 16 * 1024,
            },
        };

        // Confirm the custom profile is NOT the baseline (different hash).
        let custom_hash = custom_profile
            .content_hash()
            .expect("custom profile hash should compute");
        assert_ne!(
            custom_hash,
            baseline_profile_hash(),
            "test requires a profile hash that differs from the baseline"
        );

        // Confirm resolve_known_profile rejects it.
        assert!(
            resolve_known_profile(&custom_hash).is_err(),
            "custom profile must not be in the known-profile registry"
        );

        // Build a directory head whose identity_proof_profile_hash matches
        // the custom (unknown) profile hash.
        let head = HolonDirectoryHeadV1::new(
            cell_cert.cell_id().clone(),
            12,
            LedgerAnchorV1::ConsensusIndex { index: 99 },
            root,
            DirectoryKindV1::Smt256V1,
            1,
            8192,
            custom_hash,
            [0x62; HASH_BYTES],
            [0x63; HASH_BYTES],
            None,
        )
        .unwrap();

        let identity_proof = make_test_identity_proof(&cell_cert, &holon_cert, &head, proof, 100);

        // Supply expected_profile = custom_profile (hash matches the head).
        // In Tier2+ strict mode, this MUST be rejected because the profile
        // hash is not in the known-profile registry.
        let err = identity_proof
            .verify_with_profile_policy(
                holon_cert.holon_id(),
                &cell_cert,
                &holon_cert,
                &head,
                false,
                105,
                10,
                head.freshness_policy_hash(),
                &[0xAB; HASH_BYTES],
                RiskTier::Tier2,
                Some(&custom_profile),
                |_, _, _| Ok(()),
            )
            .unwrap_err();

        assert!(
            matches!(err, IdentityProofError::UnknownIdentityProofProfile { .. }),
            "Tier2+ must reject unknown-but-hash-matching expected_profile; got: {err:?}"
        );
    }

    // --- Bounded audit log regression (security review BLOCKER) ---

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn push_audit_event_respects_cap_at_capacity_1() {
        // Regression: with max_audit_events=1, repeated pushes MUST NOT
        // exceed the cap. The log should always contain exactly 1 event
        // (the most recent one).
        let mut cache = VerifiedHeadCache::with_audit_capacity(8, 1);
        let cell_cert = make_cell_certificate();

        // Push 10 events and verify the cap after each push.
        for i in 0u64..10 {
            let head = make_epoch_head(cell_cert.cell_id().clone(), i + 1, (i as u8) + 1);
            let hash = head.content_hash().unwrap();
            cache.admit_head(hash, head).unwrap();
            assert!(
                cache.audit_log_len() <= 1,
                "audit log len {} exceeds cap 1 after push {}",
                cache.audit_log_len(),
                i + 1,
            );
        }
        // Final state: exactly 1 event.
        assert_eq!(
            cache.audit_log_len(),
            1,
            "audit log must have exactly 1 event at cap 1"
        );
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn push_audit_event_respects_cap_at_capacity_2() {
        // Regression: with max_audit_events=2, pushing many events MUST
        // never exceed 2 entries.
        let mut cache = VerifiedHeadCache::with_audit_capacity(8, 2);
        let cell_cert = make_cell_certificate();

        for i in 0u64..10 {
            let head = make_epoch_head(cell_cert.cell_id().clone(), i + 1, (i as u8) + 1);
            let hash = head.content_hash().unwrap();
            cache.admit_head(hash, head).unwrap();
            assert!(
                cache.audit_log_len() <= 2,
                "audit log len {} exceeds cap 2 after push {}",
                cache.audit_log_len(),
                i + 1,
            );
        }
        assert!(
            cache.audit_log_len() <= 2,
            "final audit log len {} exceeds cap 2",
            cache.audit_log_len(),
        );
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn push_audit_event_respects_cap_at_capacity_3() {
        // Regression: with max_audit_events=3, pushing many events MUST
        // never exceed 3 entries.
        let mut cache = VerifiedHeadCache::with_audit_capacity(8, 3);
        let cell_cert = make_cell_certificate();

        for i in 0u64..20 {
            let head = make_epoch_head(cell_cert.cell_id().clone(), i + 1, (i as u8) + 1);
            let hash = head.content_hash().unwrap();
            cache.admit_head(hash, head).unwrap();
            assert!(
                cache.audit_log_len() <= 3,
                "audit log len {} exceeds cap 3 after push {}",
                cache.audit_log_len(),
                i + 1,
            );
        }
        assert!(
            cache.audit_log_len() <= 3,
            "final audit log len {} exceeds cap 3",
            cache.audit_log_len(),
        );
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn push_audit_event_overflow_sentinel_present_at_cap_2_plus() {
        // For cap >= 2, after overflow an AuditOverflow sentinel should
        // be present somewhere in the log.
        let mut cache = VerifiedHeadCache::with_audit_capacity(8, 3);
        let cell_cert = make_cell_certificate();

        // Push enough events to trigger overflow (cap=3, so 4+ events).
        for i in 0u64..6 {
            let head = make_epoch_head(cell_cert.cell_id().clone(), i + 1, (i as u8) + 1);
            let hash = head.content_hash().unwrap();
            cache.admit_head(hash, head).unwrap();
        }

        let events = cache.audit_log();
        let overflow_count = events
            .iter()
            .filter(|e| matches!(e, VerifierCacheAuditEvent::AuditOverflow { .. }))
            .count();
        assert!(
            overflow_count >= 1,
            "expected at least one AuditOverflow sentinel after overflow, got {overflow_count}"
        );
        assert!(
            events.len() <= 3,
            "audit log len {} exceeds cap 3",
            events.len(),
        );
    }

    // --- Monotonic epoch admission regression (code-quality review MAJOR 2) ---

    #[test]
    fn admit_head_rejects_stale_epoch_for_same_cell() {
        // Regression: admitting an older epoch after a newer one for the
        // same cell MUST be rejected with StaleEpochRejected.
        let cell_cert = make_cell_certificate();

        let newer_head = make_epoch_head(cell_cert.cell_id().clone(), 20, 0xA1);
        let stale_head = make_epoch_head(cell_cert.cell_id().clone(), 10, 0xA2);

        let newer_hash = newer_head.content_hash().unwrap();
        let stale_hash = stale_head.content_hash().unwrap();

        let mut cache = VerifiedHeadCache::new(16);
        cache.admit_head(newer_hash, newer_head).unwrap();

        // Attempt to admit the stale head -- must fail.
        let err = cache.admit_head(stale_hash, stale_head).unwrap_err();
        assert!(
            matches!(
                err,
                IdentityProofError::StaleEpochRejected {
                    admitted_epoch: 10,
                    cached_epoch: 20,
                }
            ),
            "expected StaleEpochRejected, got: {err:?}"
        );

        // The stale head must NOT be in the cache.
        assert!(
            !cache.contains_head(&stale_hash),
            "stale head must not be admitted into cache"
        );
        // The newer head must still be present.
        assert!(
            cache.contains_head(&newer_hash),
            "newer head must remain in cache"
        );
        assert_eq!(cache.len(), 1);

        // Verify audit event for the rejection.
        let rejection_events: Vec<_> = cache
            .audit_log()
            .into_iter()
            .filter(|e| matches!(e, VerifierCacheAuditEvent::StaleAdmissionRejected { .. }))
            .collect();
        assert_eq!(
            rejection_events.len(),
            1,
            "exactly one StaleAdmissionRejected event expected"
        );
        if let VerifierCacheAuditEvent::StaleAdmissionRejected {
            cell_id,
            rejected_epoch,
            cached_epoch,
        } = &rejection_events[0]
        {
            assert_eq!(cell_id, cell_cert.cell_id());
            assert_eq!(*rejected_epoch, 10);
            assert_eq!(*cached_epoch, 20);
        } else {
            panic!("expected StaleAdmissionRejected event");
        }
    }

    #[test]
    fn admit_head_allows_equal_epoch_readmission() {
        // Re-admitting the same epoch (same hash) should succeed.
        // This test ensures the monotonic guard uses strict less-than,
        // not less-than-or-equal.
        let cell_cert = make_cell_certificate();
        let head = make_epoch_head(cell_cert.cell_id().clone(), 15, 0xA1);
        let head_clone = head.clone();
        let hash = head.content_hash().unwrap();

        let mut cache = VerifiedHeadCache::new(8);
        cache.admit_head(hash, head).unwrap();
        // Re-admit same hash and epoch -- should succeed.
        cache.admit_head(hash, head_clone).unwrap();

        assert!(cache.contains_head(&hash));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn admit_head_allows_different_cells_at_any_epoch() {
        // Monotonic guard is per-cell. Different cells can have any epoch
        // relationship.
        let cell_cert = make_cell_certificate();
        let other_cert = make_other_cell_certificate();

        let cell_head = make_epoch_head(cell_cert.cell_id().clone(), 50, 0xA1);
        let other_head = make_epoch_head(other_cert.cell_id().clone(), 5, 0xB1);

        let cell_hash = cell_head.content_hash().unwrap();
        let other_hash = other_head.content_hash().unwrap();

        let mut cache = VerifiedHeadCache::new(16);
        cache.admit_head(cell_hash, cell_head).unwrap();
        // Admit a head for a different cell at a much lower epoch -- must succeed.
        cache.admit_head(other_hash, other_head).unwrap();

        assert!(cache.contains_head(&cell_hash));
        assert!(cache.contains_head(&other_hash));
        assert_eq!(cache.len(), 2);
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn admit_head_rejects_repeated_stale_attempts() {
        // Repeatedly attempting to admit stale heads for the same cell
        // must be rejected each time, and the cache must not grow.
        let cell_cert = make_cell_certificate();

        let newer_head = make_epoch_head(cell_cert.cell_id().clone(), 30, 0xA1);
        let newer_hash = newer_head.content_hash().unwrap();

        let mut cache = VerifiedHeadCache::new(16);
        cache.admit_head(newer_hash, newer_head).unwrap();

        for i in 1u64..=5 {
            let stale = make_epoch_head(cell_cert.cell_id().clone(), i, (i as u8) + 0x10);
            let stale_hash = stale.content_hash().unwrap();
            let err = cache.admit_head(stale_hash, stale).unwrap_err();
            assert!(
                matches!(err, IdentityProofError::StaleEpochRejected { .. }),
                "attempt {i}: expected StaleEpochRejected, got: {err:?}"
            );
            assert_eq!(cache.len(), 1, "cache must not grow on rejected admissions");
        }

        // Verify 5 rejection audit events.
        let rejection_count = cache
            .audit_log()
            .iter()
            .filter(|e| matches!(e, VerifierCacheAuditEvent::StaleAdmissionRejected { .. }))
            .count();
        assert_eq!(
            rejection_count, 5,
            "expected 5 StaleAdmissionRejected events"
        );
    }
}
