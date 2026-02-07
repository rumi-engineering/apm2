//! Directory-head and proof-carrying identity artifacts (RFC-0020 §1.7.7).
//!
//! This module introduces:
//! - `HolonDirectoryHeadV1`
//! - `DirectoryProofV1`
//! - `IdentityProofV1`
//!
//! These artifacts provide bounded, deterministic, CAS-addressable identity
//! verification inputs for boundary-crossing authority decisions.

use apm2_core::crypto::Hash;
use apm2_core::evidence::{CasError, ContentAddressedStore};
use thiserror::Error;

use super::{
    CellCertificateV1, CellIdV1, CertificateError, HolonCertificateV1, HolonGenesisV1, HolonIdV1,
    KeyIdError, PublicKeyIdV1,
};

const DIRECTORY_HEAD_DOMAIN_SEPARATOR: &[u8] = b"apm2:holon_directory_head:v1\0";
const DIRECTORY_PROOF_DOMAIN_SEPARATOR: &[u8] = b"apm2:directory_proof:v1\0";
const IDENTITY_PROOF_DOMAIN_SEPARATOR: &[u8] = b"apm2:identity_proof:v1\0";
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
/// Maximum allowed sibling nodes in `DirectoryProofV1`.
pub const MAX_DIRECTORY_SIBLINGS: usize = 256;

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
    fn canonical_bytes(&self) -> Vec<u8> {
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
    ) -> Result<(), IdentityProofError> {
        self.validate()?;

        if self.proof_bytes_len > max_proof_bytes {
            return Err(IdentityProofError::ProofBytesExceeded {
                proof_bytes_len: self.proof_bytes_len,
                max_proof_bytes,
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

        self.directory_proof.verify_against_root(
            directory_head.directory_root_hash(),
            directory_head.max_proof_bytes(),
        )?;

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
/// **WVR-0003 (Phase 1 limitation):** This validates that the hash is
/// well-formed and non-zero, acting as a shape-only binding commitment.
/// The caller attests they hold a valid `IdentityProofV1` by providing
/// its content hash.
///
/// Full CAS dereference + `IdentityProofV1::verify()` requires CAS
/// transport integration, which is deferred to TCK-00359 (verifier cache
/// contract and invalidation correctness). Until then, the hash is bound
/// into signed ledger event payloads for audit traceability.
///
/// See `documents/security/waivers/WVR-0003.yaml` for the formal waiver.
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

    // TODO(TCK-00359): When CAS transport is available, dereference the
    // hash from CAS and call `IdentityProofV1::verify()` for full
    // cryptographic verification. Until then, the hash acts as a binding
    // commitment that is included in signed event payloads for audit
    // traceability.

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
            .verify_against_root(&root, proof.proof_bytes_len())
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
            .verify_against_root(&root, proof.proof_bytes_len())
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
            .verify_against_root(&root, tampered.proof_bytes_len())
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
            .verify_against_root(&root, proof.proof_bytes_len() - 1)
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
            .verify_against_root(&[0x40; HASH_BYTES], proof.proof_bytes_len())
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
            [0x61; HASH_BYTES],
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
            [0xC1; HASH_BYTES],
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
            [0x03; HASH_BYTES],
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
            [0x61; HASH_BYTES],
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
            [0x61; HASH_BYTES],
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
}
