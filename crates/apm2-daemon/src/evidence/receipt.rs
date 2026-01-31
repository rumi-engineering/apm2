//! Tool receipt types for evidence and audit trails.
//!
//! This module implements tool receipts per AD-RECEIPT-001. Receipts bind
//! envelope hash, policy hash, and evidence refs with a deterministic
//! canonical encoding for signing.
//!
//! # Architecture
//!
//! ```text
//! ToolReceipt
//!     |-- kind: ReceiptKind (ToolExecution, EpisodeStart, etc.)
//!     |-- envelope_hash: Hash (bound to episode envelope)
//!     |-- policy_hash: Hash (policy version used for evaluation)
//!     |-- canonicalizer_id: CanonicalizerId (identifies encoding scheme)
//!     |-- canonicalizer_version: u32 (version for determinism)
//!     |-- evidence_refs: Vec<Hash> (CAS hashes for args, result, etc.)
//!     |-- timestamp_ns: u64 (when receipt was created)
//!     |-- unsigned_bytes_hash: Hash (BLAKE3 of canonical_bytes)
//!     |-- signature: Option<Signature> (populated after signing)
//!     `-- signer_identity: Option<SignerIdentity> (who signed)
//! ```
//!
//! # Security Model
//!
//! Per AD-RECEIPT-001:
//! - Receipts are immutable after creation
//! - `canonical_bytes()` excludes signature for signing
//! - Evidence refs are sorted for determinism
//! - Signature binds all fields to signer identity
//!
//! # Contract References
//!
//! - AD-RECEIPT-001: Tool receipt generation
//! - AD-VERIFY-001: Deterministic serialization
//! - CTR-1303: Bounded collections with MAX_* constants
//! - CTR-1604: `deny_unknown_fields` on ledger/audit types

use std::fmt;

use apm2_core::htf::TimeEnvelopeRef;
use prost::Message;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// Import EpisodeId and its validation constants from the episode module
pub use crate::episode::{EpisodeId, MAX_EPISODE_ID_LEN};

/// BLAKE3-256 hash type.
pub type Hash = [u8; 32];

/// Ed25519 signature (64 bytes).
pub type Signature = [u8; 64];

// =============================================================================
// Serde helpers for byte arrays
// =============================================================================

/// Serde helper for optional fixed-size byte arrays.
mod serde_opt_signature {
    use serde::{Deserialize, Deserializer, Serializer};

    #[allow(clippy::ref_option)]
    pub fn serialize<S>(opt: &Option<[u8; 64]>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match opt {
            Some(bytes) => serializer.serialize_some(&bytes.as_slice()),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<[u8; 64]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt: Option<Vec<u8>> = Option::deserialize(deserializer)?;
        match opt {
            Some(vec) => {
                let arr: [u8; 64] = vec.try_into().map_err(|v: Vec<u8>| {
                    serde::de::Error::custom(format!("expected 64 bytes, got {}", v.len()))
                })?;
                Ok(Some(arr))
            },
            None => Ok(None),
        }
    }
}

// =============================================================================
// Limits (CTR-1303)
// =============================================================================

/// Maximum number of evidence references in a receipt.
pub const MAX_EVIDENCE_REFS: usize = 1000;

/// Maximum length for canonicalizer ID.
pub const MAX_CANONICALIZER_ID_LEN: usize = 64;

/// Maximum length for signer identity.
pub const MAX_SIGNER_IDENTITY_LEN: usize = 256;

/// Maximum length for request ID.
pub const MAX_REQUEST_ID_LEN: usize = 256;

// Note: Episode ID length is validated by the EpisodeId type from the episode
// module. We re-export the constant from there for compatibility.

/// Maximum length for capability ID.
pub const MAX_CAPABILITY_ID_LEN: usize = 256;

/// Maximum length for result message.
pub const MAX_RESULT_MESSAGE_LEN: usize = 4096;

// =============================================================================
// ReceiptKind
// =============================================================================

/// Kind of receipt, indicating the event type being recorded.
///
/// # Security
///
/// Uses `deny_unknown_fields` to prevent field injection attacks when
/// deserializing from untrusted input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
#[non_exhaustive]
pub enum ReceiptKind {
    /// Receipt for a tool execution.
    ToolExecution,

    /// Receipt for episode start.
    EpisodeStart,

    /// Receipt for episode stop (normal termination).
    EpisodeStop,

    /// Receipt for episode quarantine (abnormal termination).
    EpisodeQuarantine,

    /// Receipt for budget checkpoint.
    BudgetCheckpoint,

    /// Receipt for policy evaluation.
    PolicyEvaluation,
}

impl ReceiptKind {
    /// Returns the numeric value for protobuf encoding.
    #[must_use]
    pub const fn value(&self) -> u32 {
        match self {
            Self::ToolExecution => 1,
            Self::EpisodeStart => 2,
            Self::EpisodeStop => 3,
            Self::EpisodeQuarantine => 4,
            Self::BudgetCheckpoint => 5,
            Self::PolicyEvaluation => 6,
        }
    }

    /// Creates a `ReceiptKind` from its numeric value.
    #[must_use]
    pub const fn from_value(value: u32) -> Option<Self> {
        match value {
            1 => Some(Self::ToolExecution),
            2 => Some(Self::EpisodeStart),
            3 => Some(Self::EpisodeStop),
            4 => Some(Self::EpisodeQuarantine),
            5 => Some(Self::BudgetCheckpoint),
            6 => Some(Self::PolicyEvaluation),
            _ => None,
        }
    }
}

impl fmt::Display for ReceiptKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ToolExecution => write!(f, "tool_execution"),
            Self::EpisodeStart => write!(f, "episode_start"),
            Self::EpisodeStop => write!(f, "episode_stop"),
            Self::EpisodeQuarantine => write!(f, "episode_quarantine"),
            Self::BudgetCheckpoint => write!(f, "budget_checkpoint"),
            Self::PolicyEvaluation => write!(f, "policy_evaluation"),
        }
    }
}

// =============================================================================
// CanonicalizerId
// =============================================================================

/// Identifier for the canonicalization scheme used.
///
/// This ensures receipts can be verified even if encoding schemes evolve.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalizerId(String);

impl CanonicalizerId {
    /// The standard APM2 protobuf canonicalizer.
    pub const APM2_PROTO_V1: &'static str = "apm2-proto-v1";

    /// Creates a new canonicalizer ID with validation.
    ///
    /// # Errors
    ///
    /// Returns an error if the ID exceeds `MAX_CANONICALIZER_ID_LEN`.
    pub fn new(id: impl Into<String>) -> Result<Self, ReceiptError> {
        let id = id.into();
        if id.len() > MAX_CANONICALIZER_ID_LEN {
            return Err(ReceiptError::CanonicalizerIdTooLong {
                len: id.len(),
                max: MAX_CANONICALIZER_ID_LEN,
            });
        }
        if id.is_empty() {
            return Err(ReceiptError::EmptyField {
                field: "canonicalizer_id",
            });
        }
        Ok(Self(id))
    }

    /// Returns the standard APM2 protobuf canonicalizer.
    #[must_use]
    pub fn apm2_proto_v1() -> Self {
        Self(Self::APM2_PROTO_V1.to_string())
    }

    /// Returns the ID as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CanonicalizerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// =============================================================================
// SignerIdentity
// =============================================================================

/// Identity of the receipt signer.
///
/// # Security
///
/// Uses `deny_unknown_fields` to prevent field injection attacks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerIdentity {
    /// Public key of the signer (Ed25519, 32 bytes).
    pub public_key: [u8; 32],

    /// Human-readable identifier for the signer.
    pub identity: String,
}

impl SignerIdentity {
    /// Creates a new signer identity with validation.
    ///
    /// # Errors
    ///
    /// Returns an error if the identity exceeds `MAX_SIGNER_IDENTITY_LEN`.
    pub fn new(public_key: [u8; 32], identity: impl Into<String>) -> Result<Self, ReceiptError> {
        let identity = identity.into();
        if identity.len() > MAX_SIGNER_IDENTITY_LEN {
            return Err(ReceiptError::SignerIdentityTooLong {
                len: identity.len(),
                max: MAX_SIGNER_IDENTITY_LEN,
            });
        }
        Ok(Self {
            public_key,
            identity,
        })
    }
}

// =============================================================================
// ToolExecutionDetails
// =============================================================================

/// Details specific to tool execution receipts.
///
/// # Security
///
/// Uses `deny_unknown_fields` to prevent field injection attacks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolExecutionDetails {
    /// Unique request ID for this tool execution.
    pub request_id: String,

    /// The capability ID that authorized this execution.
    pub capability_id: String,

    /// Hash of the tool arguments.
    pub args_hash: Hash,

    /// Hash of the tool result.
    pub result_hash: Hash,

    /// Whether the tool execution succeeded.
    pub success: bool,

    /// Optional result message (truncated to `MAX_RESULT_MESSAGE_LEN`).
    pub result_message: Option<String>,

    /// Duration of execution in nanoseconds.
    pub duration_ns: u64,
}

impl ToolExecutionDetails {
    /// Validates the details structure.
    ///
    /// # Errors
    ///
    /// Returns an error if any field exceeds its maximum length.
    pub fn validate(&self) -> Result<(), ReceiptError> {
        if self.request_id.is_empty() {
            return Err(ReceiptError::EmptyField {
                field: "request_id",
            });
        }
        if self.request_id.len() > MAX_REQUEST_ID_LEN {
            return Err(ReceiptError::RequestIdTooLong {
                len: self.request_id.len(),
                max: MAX_REQUEST_ID_LEN,
            });
        }
        if self.capability_id.is_empty() {
            return Err(ReceiptError::EmptyField {
                field: "capability_id",
            });
        }
        if self.capability_id.len() > MAX_CAPABILITY_ID_LEN {
            return Err(ReceiptError::CapabilityIdTooLong {
                len: self.capability_id.len(),
                max: MAX_CAPABILITY_ID_LEN,
            });
        }
        if let Some(ref msg) = self.result_message {
            if msg.len() > MAX_RESULT_MESSAGE_LEN {
                return Err(ReceiptError::ResultMessageTooLong {
                    len: msg.len(),
                    max: MAX_RESULT_MESSAGE_LEN,
                });
            }
        }
        Ok(())
    }
}

/// Internal protobuf representation for `ToolExecutionDetails`.
#[derive(Clone, PartialEq, Message)]
struct ToolExecutionDetailsProto {
    #[prost(string, tag = "1")]
    request_id: String,
    #[prost(string, tag = "2")]
    capability_id: String,
    #[prost(bytes = "vec", tag = "3")]
    args_hash: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    result_hash: Vec<u8>,
    #[prost(bool, optional, tag = "5")]
    success: Option<bool>,
    #[prost(string, optional, tag = "6")]
    result_message: Option<String>,
    #[prost(uint64, optional, tag = "7")]
    duration_ns: Option<u64>,
}

impl ToolExecutionDetails {
    /// Returns the canonical bytes for this details structure.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let proto = ToolExecutionDetailsProto {
            request_id: self.request_id.clone(),
            capability_id: self.capability_id.clone(),
            args_hash: self.args_hash.to_vec(),
            result_hash: self.result_hash.to_vec(),
            success: Some(self.success),
            result_message: self.result_message.clone(),
            duration_ns: Some(self.duration_ns),
        };
        proto.encode_to_vec()
    }
}

// =============================================================================
// ReceiptError
// =============================================================================

/// Errors that can occur during receipt operations.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReceiptError {
    /// Too many evidence references.
    #[error("too many evidence references: {count} (max {max})")]
    TooManyEvidenceRefs {
        /// Actual count.
        count: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Canonicalizer ID too long.
    #[error("canonicalizer ID too long: {len} bytes (max {max})")]
    CanonicalizerIdTooLong {
        /// Actual length.
        len: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Signer identity too long.
    #[error("signer identity too long: {len} bytes (max {max})")]
    SignerIdentityTooLong {
        /// Actual length.
        len: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Request ID too long.
    #[error("request ID too long: {len} bytes (max {max})")]
    RequestIdTooLong {
        /// Actual length.
        len: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Capability ID too long.
    #[error("capability ID too long: {len} bytes (max {max})")]
    CapabilityIdTooLong {
        /// Actual length.
        len: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Result message too long.
    #[error("result message too long: {len} bytes (max {max})")]
    ResultMessageTooLong {
        /// Actual length.
        len: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Episode ID too long.
    #[error("episode ID too long: {len} bytes (max {max})")]
    EpisodeIdTooLong {
        /// Actual length.
        len: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Required field is empty.
    #[error("required field is empty: {field}")]
    EmptyField {
        /// Name of the empty field.
        field: &'static str,
    },

    /// Invalid receipt kind value.
    #[error("invalid receipt kind value: {value}")]
    InvalidReceiptKind {
        /// The invalid value.
        value: u32,
    },

    /// Signature verification failed.
    #[error("signature verification failed")]
    SignatureVerificationFailed,

    /// Receipt is not signed.
    #[error("receipt is not signed")]
    NotSigned,

    /// Receipt is already signed.
    #[error("receipt is already signed")]
    AlreadySigned,

    /// Missing required details for receipt kind.
    #[error("missing required details for {kind}")]
    MissingDetails {
        /// The receipt kind requiring details.
        kind: ReceiptKind,
    },

    /// Hash mismatch between stored and computed digest.
    #[error("hash mismatch: expected {expected:?}, got {actual:?}")]
    HashMismatch {
        /// Expected hash (computed digest).
        expected: Hash,
        /// Actual hash (stored value).
        actual: Hash,
    },
}

// =============================================================================
// ToolReceipt
// =============================================================================

/// A tool receipt providing cryptographic proof of tool execution.
///
/// Per AD-RECEIPT-001, receipts bind:
/// - Episode envelope (via `envelope_hash`)
/// - Policy version (via `policy_hash`)
/// - Evidence artifacts (via `evidence_refs`)
/// - Execution details (via `tool_execution_details`)
/// - Signer identity (via `signer_identity` in canonical bytes)
///
/// # Security
///
/// - Uses `deny_unknown_fields` to prevent field injection
/// - `canonical_bytes()` excludes signature for signing but INCLUDES
///   `signer_identity`
/// - Evidence refs are sorted for determinism per AD-VERIFY-001
/// - `signer_identity` is cryptographically bound to the receipt via canonical
///   bytes
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolReceipt {
    /// Kind of receipt.
    pub kind: ReceiptKind,

    /// Episode ID this receipt belongs to.
    pub episode_id: EpisodeId,

    /// Hash of the episode envelope.
    pub envelope_hash: Hash,

    /// Hash of the policy version used for evaluation.
    pub policy_hash: Hash,

    /// Canonicalizer identifier.
    pub canonicalizer_id: CanonicalizerId,

    /// Canonicalizer version for determinism tracking.
    pub canonicalizer_version: u32,

    /// Evidence references (CAS hashes for args, result, etc.).
    ///
    /// Sorted for deterministic encoding per AD-VERIFY-001.
    pub evidence_refs: Vec<Hash>,

    /// Timestamp when the receipt was created (nanoseconds since epoch).
    pub timestamp_ns: u64,

    /// BLAKE3 hash of the canonical unsigned bytes.
    pub unsigned_bytes_hash: Hash,

    /// Optional tool execution details (required for `ToolExecution` kind).
    pub tool_execution_details: Option<ToolExecutionDetails>,

    /// Reference to the `TimeEnvelope` for this receipt (RFC-0016 HTF).
    ///
    /// Per TCK-00240, tool receipts include a time envelope reference for
    /// temporal ordering and causality tracking. The referenced envelope
    /// should be stored in CAS for verification.
    pub time_envelope_ref: Option<TimeEnvelopeRef>,

    /// Optional signature (populated after signing).
    #[serde(with = "serde_opt_signature")]
    pub signature: Option<Signature>,

    /// Optional signer identity (populated after signing).
    pub signer_identity: Option<SignerIdentity>,
}

impl ToolReceipt {
    /// Validates the receipt structure.
    ///
    /// # Errors
    ///
    /// Returns an error if any field exceeds its limits or required fields
    /// are missing. Also verifies that `unsigned_bytes_hash` matches the
    /// computed digest.
    pub fn validate(&self) -> Result<(), ReceiptError> {
        // Note: episode_id is validated by the EpisodeId type at construction time

        // Check evidence refs count (CTR-1303)
        if self.evidence_refs.len() > MAX_EVIDENCE_REFS {
            return Err(ReceiptError::TooManyEvidenceRefs {
                count: self.evidence_refs.len(),
                max: MAX_EVIDENCE_REFS,
            });
        }

        // Validate tool execution details if present
        if let Some(ref details) = self.tool_execution_details {
            details.validate()?;
        }

        // ToolExecution kind requires details
        if self.kind == ReceiptKind::ToolExecution && self.tool_execution_details.is_none() {
            return Err(ReceiptError::MissingDetails {
                kind: ReceiptKind::ToolExecution,
            });
        }

        // Validate signer identity if present
        if let Some(ref identity) = self.signer_identity {
            if identity.identity.len() > MAX_SIGNER_IDENTITY_LEN {
                return Err(ReceiptError::SignerIdentityTooLong {
                    len: identity.identity.len(),
                    max: MAX_SIGNER_IDENTITY_LEN,
                });
            }
        }

        // Verify unsigned_bytes_hash matches computed digest
        let computed_digest = self.digest();
        if self.unsigned_bytes_hash != computed_digest {
            return Err(ReceiptError::HashMismatch {
                expected: computed_digest,
                actual: self.unsigned_bytes_hash,
            });
        }

        Ok(())
    }

    /// Returns `true` if this receipt is signed.
    #[must_use]
    pub const fn is_signed(&self) -> bool {
        self.signature.is_some()
    }

    /// Returns the canonical bytes for signing.
    ///
    /// Per AD-VERIFY-001:
    /// - Fields are serialized in tag order
    /// - Evidence refs are sorted by hash value
    /// - Signature and `unsigned_bytes_hash` are excluded
    /// - `signer_identity` IS included to cryptographically bind the signer
    ///
    /// # Design Note
    ///
    /// The `unsigned_bytes_hash` is excluded because it IS the digest of the
    /// canonical bytes - including it would create a circular dependency.
    /// The signature is computed over these canonical bytes, and the
    /// `unsigned_bytes_hash` is stored for convenience (to verify without
    /// re-computing).
    ///
    /// The `signer_identity` is INCLUDED because it must be cryptographically
    /// bound to the receipt. Without this, an attacker could replace the
    /// signer identity without invalidating the signature.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        // Sort evidence refs for determinism
        let mut sorted_refs: Vec<_> = self.evidence_refs.clone();
        sorted_refs.sort_unstable();

        let proto = ToolReceiptProto {
            kind: Some(self.kind.value()),
            episode_id: self.episode_id.as_str().to_string(),
            envelope_hash: self.envelope_hash.to_vec(),
            policy_hash: self.policy_hash.to_vec(),
            canonicalizer_id: self.canonicalizer_id.as_str().to_string(),
            canonicalizer_version: Some(self.canonicalizer_version),
            evidence_refs: sorted_refs.into_iter().map(|h| h.to_vec()).collect(),
            timestamp_ns: Some(self.timestamp_ns),
            tool_execution_details: self
                .tool_execution_details
                .as_ref()
                .map(ToolExecutionDetails::canonical_bytes),
            // signer_identity IS included for cryptographic binding
            signer_identity: self
                .signer_identity
                .as_ref()
                .map(SignerIdentity::canonical_bytes),
            // time_envelope_ref IS included for temporal ordering (RFC-0016 HTF)
            time_envelope_ref: self
                .time_envelope_ref
                .as_ref()
                .map(|r| r.as_bytes().to_vec()),
            // NOTE: signature and unsigned_bytes_hash are EXCLUDED
            // (unsigned_bytes_hash would create circular dependency)
        };
        proto.encode_to_vec()
    }

    /// Computes the BLAKE3 digest of the canonical bytes.
    #[must_use]
    pub fn digest(&self) -> Hash {
        *blake3::hash(&self.canonical_bytes()).as_bytes()
    }

    /// Returns the bytes that should be signed.
    ///
    /// This is equivalent to `canonical_bytes()` - the signature is computed
    /// over the canonical representation.
    #[must_use]
    pub fn unsigned_bytes(&self) -> Vec<u8> {
        self.canonical_bytes()
    }
}

/// Internal protobuf representation for `SignerIdentity`.
#[derive(Clone, PartialEq, Message)]
struct SignerIdentityProto {
    #[prost(bytes = "vec", tag = "1")]
    public_key: Vec<u8>,
    #[prost(string, tag = "2")]
    identity: String,
}

impl SignerIdentity {
    /// Returns the canonical bytes for this signer identity.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let proto = SignerIdentityProto {
            public_key: self.public_key.to_vec(),
            identity: self.identity.clone(),
        };
        proto.encode_to_vec()
    }
}

/// Internal protobuf representation for `ToolReceipt`.
///
/// Note: This excludes signature and `unsigned_bytes_hash` for canonical
/// encoding. The `unsigned_bytes_hash` would create a circular dependency if
/// included. The `signer_identity` IS included to cryptographically bind the
/// signer to the receipt.
#[derive(Clone, PartialEq, Message)]
struct ToolReceiptProto {
    #[prost(uint32, optional, tag = "1")]
    kind: Option<u32>,
    #[prost(string, tag = "2")]
    episode_id: String,
    #[prost(bytes = "vec", tag = "3")]
    envelope_hash: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    policy_hash: Vec<u8>,
    #[prost(string, tag = "5")]
    canonicalizer_id: String,
    #[prost(uint32, optional, tag = "6")]
    canonicalizer_version: Option<u32>,
    #[prost(bytes = "vec", repeated, tag = "7")]
    evidence_refs: Vec<Vec<u8>>,
    #[prost(uint64, optional, tag = "8")]
    timestamp_ns: Option<u64>,
    // Tag 9 reserved for unsigned_bytes_hash (not included in canonical encoding)
    #[prost(bytes = "vec", optional, tag = "10")]
    tool_execution_details: Option<Vec<u8>>,
    // Tag 11: signer_identity - INCLUDED for cryptographic binding
    #[prost(bytes = "vec", optional, tag = "11")]
    signer_identity: Option<Vec<u8>>,
    // Tag 12: time_envelope_ref - INCLUDED for temporal ordering (RFC-0016 HTF)
    #[prost(bytes = "vec", optional, tag = "12")]
    time_envelope_ref: Option<Vec<u8>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_receipt() -> ToolReceipt {
        let mut receipt = ToolReceipt {
            kind: ReceiptKind::ToolExecution,
            episode_id: EpisodeId::new("ep-test-001").unwrap(),
            envelope_hash: [0xaa; 32],
            policy_hash: [0xbb; 32],
            canonicalizer_id: CanonicalizerId::apm2_proto_v1(),
            canonicalizer_version: 1,
            evidence_refs: vec![[0xcc; 32], [0xdd; 32]],
            timestamp_ns: 1_704_067_200_000_000_000,
            unsigned_bytes_hash: [0; 32], // Will be computed below
            tool_execution_details: Some(ToolExecutionDetails {
                request_id: "req-001".to_string(),
                capability_id: "cap-read".to_string(),
                args_hash: [0x11; 32],
                result_hash: [0x22; 32],
                success: true,
                result_message: Some("completed".to_string()),
                duration_ns: 100_000_000,
            }),
            time_envelope_ref: None,
            signature: None,
            signer_identity: None,
        };
        // Compute the correct unsigned_bytes_hash
        receipt.unsigned_bytes_hash = receipt.digest();
        receipt
    }

    #[test]
    fn test_receipt_kind_value_roundtrip() {
        for kind in [
            ReceiptKind::ToolExecution,
            ReceiptKind::EpisodeStart,
            ReceiptKind::EpisodeStop,
            ReceiptKind::EpisodeQuarantine,
            ReceiptKind::BudgetCheckpoint,
            ReceiptKind::PolicyEvaluation,
        ] {
            let value = kind.value();
            let restored = ReceiptKind::from_value(value);
            assert_eq!(restored, Some(kind), "roundtrip failed for {kind:?}");
        }
    }

    #[test]
    fn test_receipt_kind_from_invalid_value() {
        assert!(ReceiptKind::from_value(0).is_none());
        assert!(ReceiptKind::from_value(100).is_none());
    }

    #[test]
    fn test_canonicalizer_id_validation() {
        // Valid
        assert!(CanonicalizerId::new("valid-id").is_ok());
        assert!(CanonicalizerId::new(CanonicalizerId::APM2_PROTO_V1).is_ok());

        // Too long
        let long_id = "x".repeat(MAX_CANONICALIZER_ID_LEN + 1);
        assert!(matches!(
            CanonicalizerId::new(long_id),
            Err(ReceiptError::CanonicalizerIdTooLong { .. })
        ));

        // Empty
        assert!(matches!(
            CanonicalizerId::new(""),
            Err(ReceiptError::EmptyField { .. })
        ));
    }

    #[test]
    fn test_signer_identity_validation() {
        // Valid
        let identity = SignerIdentity::new([0u8; 32], "test-signer");
        assert!(identity.is_ok());

        // Too long
        let long_identity = "x".repeat(MAX_SIGNER_IDENTITY_LEN + 1);
        assert!(matches!(
            SignerIdentity::new([0u8; 32], long_identity),
            Err(ReceiptError::SignerIdentityTooLong { .. })
        ));
    }

    #[test]
    fn test_tool_execution_details_validation() {
        let details = ToolExecutionDetails {
            request_id: "req-001".to_string(),
            capability_id: "cap-001".to_string(),
            args_hash: [0; 32],
            result_hash: [0; 32],
            success: true,
            result_message: None,
            duration_ns: 100,
        };
        assert!(details.validate().is_ok());

        // Empty request_id
        let invalid = ToolExecutionDetails {
            request_id: String::new(),
            ..details
        };
        assert!(matches!(
            invalid.validate(),
            Err(ReceiptError::EmptyField {
                field: "request_id"
            })
        ));

        // Request ID too long
        let invalid = ToolExecutionDetails {
            request_id: "x".repeat(MAX_REQUEST_ID_LEN + 1),
            capability_id: "cap-001".to_string(),
            args_hash: [0; 32],
            result_hash: [0; 32],
            success: true,
            result_message: None,
            duration_ns: 100,
        };
        assert!(matches!(
            invalid.validate(),
            Err(ReceiptError::RequestIdTooLong { .. })
        ));

        // Empty capability_id
        let invalid = ToolExecutionDetails {
            request_id: "req-001".to_string(),
            capability_id: String::new(),
            args_hash: [0; 32],
            result_hash: [0; 32],
            success: true,
            result_message: None,
            duration_ns: 100,
        };
        assert!(matches!(
            invalid.validate(),
            Err(ReceiptError::EmptyField {
                field: "capability_id"
            })
        ));
    }

    #[test]
    fn test_receipt_validation() {
        let receipt = make_test_receipt();
        assert!(receipt.validate().is_ok());
    }

    // Note: Episode ID validation is handled by the EpisodeId newtype at
    // construction time, so we don't need a test for empty episode_id here.

    #[test]
    fn test_receipt_validation_too_many_evidence_refs() {
        let mut receipt = make_test_receipt();
        receipt.evidence_refs = vec![[0; 32]; MAX_EVIDENCE_REFS + 1];
        assert!(matches!(
            receipt.validate(),
            Err(ReceiptError::TooManyEvidenceRefs { .. })
        ));
    }

    #[test]
    fn test_receipt_validation_missing_details_for_tool_execution() {
        let mut receipt = make_test_receipt();
        receipt.tool_execution_details = None;
        assert!(matches!(
            receipt.validate(),
            Err(ReceiptError::MissingDetails {
                kind: ReceiptKind::ToolExecution
            })
        ));
    }

    #[test]
    fn test_receipt_is_signed() {
        let mut receipt = make_test_receipt();
        assert!(!receipt.is_signed());

        receipt.signature = Some([0; 64]);
        assert!(receipt.is_signed());
    }

    #[test]
    fn test_canonical_bytes_determinism() {
        let receipt1 = make_test_receipt();
        let receipt2 = make_test_receipt();

        assert_eq!(
            receipt1.canonical_bytes(),
            receipt2.canonical_bytes(),
            "identical receipts must produce identical canonical bytes"
        );
        assert_eq!(
            receipt1.digest(),
            receipt2.digest(),
            "identical receipts must produce identical digests"
        );
    }

    #[test]
    fn test_canonical_bytes_sorts_evidence_refs() {
        let mut receipt1 = make_test_receipt();
        receipt1.evidence_refs = vec![[0xff; 32], [0x00; 32], [0x88; 32]];

        let mut receipt2 = make_test_receipt();
        receipt2.evidence_refs = vec![[0x00; 32], [0x88; 32], [0xff; 32]];

        assert_eq!(
            receipt1.canonical_bytes(),
            receipt2.canonical_bytes(),
            "evidence refs must be sorted for determinism"
        );
    }

    #[test]
    fn test_canonical_bytes_excludes_signature_but_includes_signer_identity() {
        let receipt_unsigned = make_test_receipt();

        // Add only signature (not signer_identity) - canonical bytes should be same
        let mut receipt_with_sig_only = make_test_receipt();
        receipt_with_sig_only.signature = Some([0xab; 64]);

        assert_eq!(
            receipt_unsigned.canonical_bytes(),
            receipt_with_sig_only.canonical_bytes(),
            "signature must be excluded from canonical bytes"
        );

        // Add signer_identity - canonical bytes should be DIFFERENT (signer is bound)
        let mut receipt_with_signer = make_test_receipt();
        receipt_with_signer.signer_identity = Some(SignerIdentity {
            public_key: [0x12; 32],
            identity: "test-signer".to_string(),
        });

        assert_ne!(
            receipt_unsigned.canonical_bytes(),
            receipt_with_signer.canonical_bytes(),
            "signer_identity must be INCLUDED in canonical bytes for cryptographic binding"
        );
    }

    #[test]
    fn test_unsigned_bytes_equals_canonical_bytes() {
        let receipt = make_test_receipt();
        assert_eq!(
            receipt.unsigned_bytes(),
            receipt.canonical_bytes(),
            "unsigned_bytes must equal canonical_bytes"
        );
    }

    #[test]
    fn test_receipt_kind_display() {
        assert_eq!(ReceiptKind::ToolExecution.to_string(), "tool_execution");
        assert_eq!(ReceiptKind::EpisodeStart.to_string(), "episode_start");
        assert_eq!(ReceiptKind::EpisodeStop.to_string(), "episode_stop");
    }

    #[test]
    fn test_tool_execution_details_canonical_bytes() {
        let details = ToolExecutionDetails {
            request_id: "req-001".to_string(),
            capability_id: "cap-001".to_string(),
            args_hash: [0x11; 32],
            result_hash: [0x22; 32],
            success: true,
            result_message: Some("done".to_string()),
            duration_ns: 1000,
        };

        let bytes = details.canonical_bytes();
        assert!(!bytes.is_empty());

        // Verify determinism
        let bytes2 = details.canonical_bytes();
        assert_eq!(bytes, bytes2);
    }

    #[test]
    fn test_receipt_serde_roundtrip() {
        let receipt = make_test_receipt();
        let json = serde_json::to_string(&receipt).unwrap();
        let restored: ToolReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(receipt, restored);
    }

    #[test]
    fn test_receipt_serde_deny_unknown_fields() {
        let json = r#"{
            "kind": "tool_execution",
            "episode_id": "ep-001",
            "envelope_hash": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
            "policy_hash": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
            "canonicalizer_id": "test",
            "canonicalizer_version": 1,
            "evidence_refs": [],
            "timestamp_ns": 0,
            "unsigned_bytes_hash": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
            "tool_execution_details": null,
            "signature": null,
            "signer_identity": null,
            "unknown_field": "should_fail"
        }"#;

        let result: Result<ToolReceipt, _> = serde_json::from_str(json);
        assert!(result.is_err(), "should reject unknown fields");
    }

    #[test]
    fn test_receipt_validation_verifies_unsigned_bytes_hash() {
        let mut receipt = make_test_receipt();
        // Corrupt the hash
        receipt.unsigned_bytes_hash = [0xff; 32];

        assert!(matches!(
            receipt.validate(),
            Err(ReceiptError::HashMismatch { .. })
        ));
    }

    #[test]
    fn test_canonical_bytes_includes_time_envelope_ref() {
        let mut receipt_none = make_test_receipt();
        receipt_none.time_envelope_ref = None;

        let mut receipt_some = make_test_receipt();
        let ref_bytes = [0x55; 32];
        receipt_some.time_envelope_ref = Some(TimeEnvelopeRef::new(ref_bytes));

        let bytes_none = receipt_none.canonical_bytes();
        let bytes_some = receipt_some.canonical_bytes();

        assert_ne!(
            bytes_none, bytes_some,
            "canonical bytes must differ when time_envelope_ref is present"
        );

        // Verify the bytes are included by decoding or checking length
        assert!(
            bytes_some.len() > bytes_none.len(),
            "receipt with envelope ref should be larger"
        );

        // Sanity check: ensure we can roundtrip this field if we were to decode
        // (We don't have a decode_canonical exposed, but we can verify digest
        // difference)
        assert_ne!(
            receipt_none.digest(),
            receipt_some.digest(),
            "digests must differ"
        );
    }

    #[test]
    fn test_signer_identity_canonical_bytes() {
        let identity = SignerIdentity {
            public_key: [0x12; 32],
            identity: "test-signer".to_string(),
        };

        let bytes = identity.canonical_bytes();
        assert!(!bytes.is_empty());

        // Verify determinism
        let bytes2 = identity.canonical_bytes();
        assert_eq!(bytes, bytes2);
    }
}
