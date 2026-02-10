// AGENT-AUTHORED
//! Holonic Message Protocol (HMP) — digest-first channels and admission
//! receipt semantics (TCK-00380, REQ-0034).
//!
//! This module implements:
//! - [`ChannelClass`]: the five HMP channel classes (DISCOVERY, HANDSHAKE,
//!   WORK, EVIDENCE, GOVERNANCE) that separate routing facts from acceptance
//!   facts.
//! - [`HmpMessageV1`]: the HMP message envelope with digest-first payload
//!   references and bounded metadata.
//! - [`BodyRef`]: CAS hash + content type for digest-first payload referencing.
//! - [`AdmissionReceiptV1`]: receipt for imported authoritative facts from
//!   cross-cell ingestion, binding source cell identity, admitted range/hash
//!   set, verification method, and local ledger anchor.
//! - [`ImportReceiptV1`]: typed wrapper around [`AdmissionReceiptV1`] for
//!   specific import categories (ledger ranges, policy roots, permeability
//!   grants).
//!
//! # Digest-First Design
//!
//! All message payloads are referenced by CAS hash (`body_ref`) rather than
//! inlined. This keeps the wire envelope bounded and separates routing
//! (envelope-level metadata) from content (CAS-resolved bodies). Unsolicited
//! large payloads are never parsed; instead the envelope is validated first
//! and the body is fetched only if the envelope passes admission checks.
//!
//! # Channel Class Semantics (RFC-0020 §7.3)
//!
//! - **DISCOVERY**: Signed holon/relay endpoint announcements.
//! - **HANDSHAKE**: Session establishment and permeability grant exchange.
//! - **WORK**: Task delegation and tool execution requests.
//! - **EVIDENCE**: Anti-entropy offers, CAS artifact requests/deliveries.
//! - **GOVERNANCE**: Stop/rotation governance messages across cells.
//!
//! Routing facts (envelope-level metadata) and acceptance facts (receipt-
//! bound imported truth) are operationally distinct: routing facts determine
//! delivery, acceptance facts determine truth-plane admission.
//!
//! # Admission Receipt Semantics (RFC-0020 §2.4.0b)
//!
//! Cross-cell ingestion of ledger event ranges, policy root/cell
//! certificates, or permeability grants MUST emit an [`AdmissionReceiptV1`]
//! in the receiving cell. Without an admission receipt, replicated bytes are
//! treated as untrusted cache, not truth-plane facts.
//!
//! # Security Properties
//!
//! - **Fail-closed**: Unknown channel classes, oversized envelopes, and missing
//!   required fields produce errors.
//! - **Bounded**: All string fields, parent lists, and envelope sizes are
//!   bounded by explicit constants.
//! - **Digest-first**: Body content is never inlined in the envelope wire
//!   shape.
//! - **Deterministic**: All hash computations use domain-separated preimages.
//! - **Strict deserialization**: `#[serde(deny_unknown_fields)]` on all
//!   boundary structs.
//!
//! # Contract References
//!
//! - RFC-0020 §7.3: `HMPMessageV1` envelope and classes
//! - RFC-0020 §2.4.0b: Admission receipts (normative)
//! - RFC-0020 §2.4.0: Control-plane vs data-plane separation
//! - REQ-0034: Digest-first HMP classes and admission receipts
//! - EVID-0034: HMP conformance evidence
//! - EVID-0107: Import receipt conformance evidence

pub mod admission;

use apm2_core::crypto::Hash;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// =============================================================================
// Constants
// =============================================================================

/// Maximum envelope size in bytes (pre-decode bound).
///
/// HMP envelopes are digest-first: the body is a CAS hash reference, not
/// inlined content. 16 KiB is generous for metadata-only envelopes.
pub const MAX_ENVELOPE_BYTES: usize = 16_384;

/// Maximum number of causal parent references.
///
/// Bounded to prevent memory amplification via oversized parent lists.
pub const MAX_PARENTS: usize = 64;

/// Maximum length of a `protocol_id` string.
pub const MAX_PROTOCOL_ID_LEN: usize = 128;

/// Maximum length of a `message_class` string.
pub const MAX_MESSAGE_CLASS_LEN: usize = 128;

/// Maximum length of a `content_type` string in [`BodyRef`].
pub const MAX_CONTENT_TYPE_LEN: usize = 256;

/// Maximum length of an `idempotency_key` string.
pub const MAX_IDEMPOTENCY_KEY_LEN: usize = 256;

/// Maximum length of sender/receiver ID strings.
pub const MAX_ID_LEN: usize = 256;

/// Maximum number of rejection reasons in an admission receipt.
pub const MAX_REJECTION_REASONS: usize = 1_000;

/// Maximum length of a single rejection reason string.
pub const MAX_REJECTION_REASON_LEN: usize = 1_024;

/// Maximum number of admitted hashes in an admission receipt.
pub const MAX_ADMITTED_HASHES: usize = 100_000;

/// Domain separator for HMP envelope hash computation.
const ENVELOPE_DOMAIN_SEPARATOR: &[u8] = b"apm2:hmp_envelope:v1\0";

/// Domain separator for admission receipt hash computation.
const ADMISSION_RECEIPT_DOMAIN_SEPARATOR: &[u8] = b"apm2:admission_receipt:v1\0";

// =============================================================================
// Channel Classes
// =============================================================================

/// HMP channel class (RFC-0020 §7.3).
///
/// Channel classes enforce separation between message categories at the
/// protocol level. Each channel class has distinct trust and admission
/// semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ChannelClass {
    /// Signed holon/relay endpoint announcements.
    Discovery,
    /// Session establishment and permeability grant exchange.
    Handshake,
    /// Task delegation and tool execution requests.
    Work,
    /// Anti-entropy offers, CAS artifact requests/deliveries.
    Evidence,
    /// Stop/rotation governance messages across cells.
    Governance,
}

impl ChannelClass {
    /// Returns `true` if this channel class can carry authority-bearing
    /// messages that require permeability receipts.
    #[must_use]
    pub const fn is_authority_bearing(&self) -> bool {
        matches!(self, Self::Handshake | Self::Work | Self::Governance)
    }

    /// Returns `true` if this channel class is a routing-only class
    /// (DISCOVERY, EVIDENCE) that never directly conveys delegated authority.
    #[must_use]
    pub const fn is_routing_only(&self) -> bool {
        matches!(self, Self::Discovery | Self::Evidence)
    }

    /// Canonical string representation for domain separation and logging.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Discovery => "DISCOVERY",
            Self::Handshake => "HANDSHAKE",
            Self::Work => "WORK",
            Self::Evidence => "EVIDENCE",
            Self::Governance => "GOVERNANCE",
        }
    }
}

impl std::fmt::Display for ChannelClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// =============================================================================
// Body Reference (Digest-First)
// =============================================================================

/// Digest-first CAS body reference (RFC-0020 §7.3).
///
/// Payloads are never inlined. The envelope carries only a CAS hash and
/// content type. The receiver fetches the body from CAS only after envelope
/// admission checks pass.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BodyRef {
    /// BLAKE3 hash of the body content in CAS.
    pub cas_hash: Hash,

    /// MIME-like content type (e.g., `"application/cbor"`,
    /// `"application/json"`).
    pub content_type: String,
}

impl BodyRef {
    /// Create a new body reference.
    ///
    /// # Errors
    ///
    /// Returns [`HmpError::ContentTypeTooLong`] if `content_type` exceeds
    /// [`MAX_CONTENT_TYPE_LEN`].
    pub fn new(cas_hash: Hash, content_type: String) -> Result<Self, HmpError> {
        if content_type.len() > MAX_CONTENT_TYPE_LEN {
            return Err(HmpError::ContentTypeTooLong {
                len: content_type.len(),
                max: MAX_CONTENT_TYPE_LEN,
            });
        }
        Ok(Self {
            cas_hash,
            content_type,
        })
    }
}

// =============================================================================
// HMP Message V1
// =============================================================================

/// HMP message envelope V1 (RFC-0020 §7.3).
///
/// The envelope carries routing metadata and a digest-first body reference.
/// All payload content is resolved from CAS after envelope admission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HmpMessageV1 {
    /// Protocol identifier (e.g., `"hsi:v1"`).
    pub protocol_id: String,

    /// Message class within the protocol (e.g., `"HSI.ANTI_ENTROPY.OFFER"`).
    pub message_class: String,

    /// Unique message identifier (BLAKE3 hash).
    pub message_id: Hash,

    /// Idempotency key for deduplication.
    pub idempotency_key: String,

    /// HLC timestamp (logical, not wall-clock).
    pub hlc_timestamp: u64,

    /// Causal parent message IDs.
    pub parents: Vec<Hash>,

    /// Sender holon ID (canonical text form).
    pub sender_holon_id: String,

    /// Sender actor ID within the holon.
    pub sender_actor_id: String,

    /// Channel class for this message.
    pub channel_class: ChannelClass,

    /// Sender cell ID (canonical text form).
    pub sender_cell_id: String,

    /// Receiver cell ID (canonical text form, or `"*"` for broadcast).
    pub receiver_cell_id: String,

    /// Sender policy root key ID (key identifier only, not private material).
    pub sender_policy_root_key_id: String,

    /// Digest-first body reference (CAS hash + content type).
    pub body_ref: BodyRef,

    /// Ledger head hash commitment.
    pub ledger_head_hash: Hash,

    /// Context pack hash commitment (when applicable).
    pub context_pack_hash: Option<Hash>,

    /// Capability manifest hash commitment (when applicable).
    pub manifest_hash: Option<Hash>,

    /// View commitment hash (when message affects cognition/claims).
    pub view_commitment_hash: Option<Hash>,

    /// Permeability receipt hash (when message conveys delegated authority).
    pub permeability_receipt_hash: Option<Hash>,
}

impl HmpMessageV1 {
    /// Validate the envelope against bounded constraints.
    ///
    /// This performs structural validation without verifying signatures or
    /// resolving CAS references. It enforces:
    /// - Field length bounds
    /// - Parent list cardinality bounds
    /// - Authority-bearing channel class constraints
    ///
    /// # Errors
    ///
    /// Returns [`HmpError`] for any constraint violation.
    pub fn validate(&self) -> Result<(), HmpError> {
        // Field length bounds
        if self.protocol_id.len() > MAX_PROTOCOL_ID_LEN {
            return Err(HmpError::FieldTooLong {
                field: "protocol_id",
                len: self.protocol_id.len(),
                max: MAX_PROTOCOL_ID_LEN,
            });
        }
        if self.message_class.len() > MAX_MESSAGE_CLASS_LEN {
            return Err(HmpError::FieldTooLong {
                field: "message_class",
                len: self.message_class.len(),
                max: MAX_MESSAGE_CLASS_LEN,
            });
        }
        if self.idempotency_key.len() > MAX_IDEMPOTENCY_KEY_LEN {
            return Err(HmpError::FieldTooLong {
                field: "idempotency_key",
                len: self.idempotency_key.len(),
                max: MAX_IDEMPOTENCY_KEY_LEN,
            });
        }
        if self.sender_holon_id.len() > MAX_ID_LEN {
            return Err(HmpError::FieldTooLong {
                field: "sender_holon_id",
                len: self.sender_holon_id.len(),
                max: MAX_ID_LEN,
            });
        }
        if self.sender_actor_id.len() > MAX_ID_LEN {
            return Err(HmpError::FieldTooLong {
                field: "sender_actor_id",
                len: self.sender_actor_id.len(),
                max: MAX_ID_LEN,
            });
        }
        if self.sender_cell_id.len() > MAX_ID_LEN {
            return Err(HmpError::FieldTooLong {
                field: "sender_cell_id",
                len: self.sender_cell_id.len(),
                max: MAX_ID_LEN,
            });
        }
        if self.receiver_cell_id.len() > MAX_ID_LEN {
            return Err(HmpError::FieldTooLong {
                field: "receiver_cell_id",
                len: self.receiver_cell_id.len(),
                max: MAX_ID_LEN,
            });
        }
        if self.sender_policy_root_key_id.len() > MAX_ID_LEN {
            return Err(HmpError::FieldTooLong {
                field: "sender_policy_root_key_id",
                len: self.sender_policy_root_key_id.len(),
                max: MAX_ID_LEN,
            });
        }
        if self.body_ref.content_type.len() > MAX_CONTENT_TYPE_LEN {
            return Err(HmpError::ContentTypeTooLong {
                len: self.body_ref.content_type.len(),
                max: MAX_CONTENT_TYPE_LEN,
            });
        }

        // Parent list bound
        if self.parents.len() > MAX_PARENTS {
            return Err(HmpError::TooManyParents {
                count: self.parents.len(),
                max: MAX_PARENTS,
            });
        }

        // Authority-bearing channel constraint: permeability receipt required
        if self.channel_class.is_authority_bearing()
            && self.permeability_receipt_hash.is_none()
            && self.channel_class != ChannelClass::Work
        {
            // HANDSHAKE and GOVERNANCE require permeability receipt per §8.3
            // WORK messages may operate under existing session authority
            return Err(HmpError::MissingPermeabilityReceipt {
                channel: self.channel_class,
            });
        }

        Ok(())
    }

    /// Compute the deterministic envelope hash using domain separation.
    ///
    /// The hash is computed over a canonical preimage that includes all
    /// envelope fields in a deterministic order.
    #[must_use]
    pub fn compute_envelope_hash(&self) -> Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(ENVELOPE_DOMAIN_SEPARATOR);
        hasher.update(self.protocol_id.as_bytes());
        hasher.update(b"\n");
        hasher.update(self.message_class.as_bytes());
        hasher.update(b"\n");
        hasher.update(&self.message_id);
        hasher.update(self.idempotency_key.as_bytes());
        hasher.update(b"\n");
        hasher.update(&self.hlc_timestamp.to_le_bytes());
        hasher.update(b"\n");
        for parent in &self.parents {
            hasher.update(parent);
        }
        hasher.update(b"\n");
        hasher.update(self.sender_holon_id.as_bytes());
        hasher.update(b"\n");
        hasher.update(self.sender_actor_id.as_bytes());
        hasher.update(b"\n");
        hasher.update(self.channel_class.as_str().as_bytes());
        hasher.update(b"\n");
        hasher.update(self.sender_cell_id.as_bytes());
        hasher.update(b"\n");
        hasher.update(self.receiver_cell_id.as_bytes());
        hasher.update(b"\n");
        hasher.update(self.sender_policy_root_key_id.as_bytes());
        hasher.update(b"\n");
        hasher.update(&self.body_ref.cas_hash);
        hasher.update(self.body_ref.content_type.as_bytes());
        hasher.update(b"\n");
        hasher.update(&self.ledger_head_hash);

        // Optional fields: use presence marker to ensure canonical ordering
        Self::hash_optional_field(&mut hasher, self.context_pack_hash.as_ref());
        Self::hash_optional_field(&mut hasher, self.manifest_hash.as_ref());
        Self::hash_optional_field(&mut hasher, self.view_commitment_hash.as_ref());
        Self::hash_optional_field(&mut hasher, self.permeability_receipt_hash.as_ref());

        *hasher.finalize().as_bytes()
    }

    /// Hash an optional field with a presence tag for canonical ordering.
    fn hash_optional_field(hasher: &mut blake3::Hasher, field: Option<&Hash>) {
        match field {
            Some(hash) => {
                hasher.update(&[0x01]);
                hasher.update(hash);
            },
            None => {
                hasher.update(&[0x00]);
            },
        }
    }
}

// =============================================================================
// Envelope Admission Gate
// =============================================================================

/// Pre-fetch admission gate for HMP envelopes.
///
/// This gate validates the envelope metadata before any CAS body fetch
/// occurs. Unsolicited messages with oversized or malformed envelopes are
/// rejected without allocating resources for body resolution.
pub struct EnvelopeAdmissionGate {
    /// Maximum allowed envelope size in bytes.
    max_envelope_bytes: usize,
}

impl EnvelopeAdmissionGate {
    /// Create a new envelope admission gate with the given size bound.
    #[must_use]
    pub const fn new(max_envelope_bytes: usize) -> Self {
        Self { max_envelope_bytes }
    }

    /// Create a gate with the default maximum envelope size.
    #[must_use]
    pub const fn default_bounded() -> Self {
        Self::new(MAX_ENVELOPE_BYTES)
    }

    /// Admit a raw envelope by checking size bounds, then deserializing
    /// and validating the envelope structure.
    ///
    /// # Errors
    ///
    /// Returns [`HmpError::EnvelopeTooLarge`] if the raw bytes exceed the
    /// size bound. Returns other [`HmpError`] variants for structural
    /// validation failures.
    pub fn admit(&self, raw_bytes: &[u8]) -> Result<HmpMessageV1, HmpError> {
        // Pre-decode size bound
        if raw_bytes.len() > self.max_envelope_bytes {
            return Err(HmpError::EnvelopeTooLarge {
                size: raw_bytes.len(),
                max: self.max_envelope_bytes,
            });
        }

        // Bounded deserialization
        let envelope: HmpMessageV1 =
            serde_json::from_slice(raw_bytes).map_err(|e| HmpError::DeserializationFailed {
                detail: e.to_string(),
            })?;

        // Structural validation
        envelope.validate()?;

        Ok(envelope)
    }
}

impl Default for EnvelopeAdmissionGate {
    fn default() -> Self {
        Self::default_bounded()
    }
}

// =============================================================================
// Verification Method
// =============================================================================

/// Verification method used during cross-cell admission.
///
/// Records how the imported facts were authenticated at the receiving cell.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VerificationMethod {
    /// Single Ed25519 signature verification.
    SingleSignature,
    /// Quorum multisig verification (n-of-n).
    QuorumMultisig,
    /// Threshold signature verification (k-of-n).
    QuorumThreshold,
    /// Merkle batch verification with authority seal.
    MerkleBatch,
}

impl std::fmt::Display for VerificationMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SingleSignature => f.write_str("SINGLE_SIGNATURE"),
            Self::QuorumMultisig => f.write_str("QUORUM_MULTISIG"),
            Self::QuorumThreshold => f.write_str("QUORUM_THRESHOLD"),
            Self::MerkleBatch => f.write_str("MERKLE_BATCH"),
        }
    }
}

// =============================================================================
// Admission Receipt V1
// =============================================================================

/// Admission receipt for imported authoritative facts (RFC-0020 §2.4.0b).
///
/// Emitted by the receiving cell when cross-cell ingestion of ledger event
/// ranges, policy root/cell certificates, or permeability grants is
/// admitted. Without this receipt, replicated bytes are untrusted cache.
///
/// # Required Bindings
///
/// - `sender_cell_id`: source cell identity (observed).
/// - `sender_policy_root_key_id`: source policy root key ID (observed).
/// - `admitted_hashes`: the exact set of admitted artifact hashes.
/// - `verification_method`: how the facts were authenticated.
/// - `local_ledger_anchor`: local ledger hash at time of admission.
/// - `rejection_reasons`: reasons for any omitted elements.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionReceiptV1 {
    /// Unique receipt identifier (BLAKE3 hash).
    pub receipt_id: Hash,

    /// Source cell ID (canonical text form).
    pub sender_cell_id: String,

    /// Source policy root key ID.
    pub sender_policy_root_key_id: String,

    /// Exact set of admitted artifact hashes.
    pub admitted_hashes: Vec<Hash>,

    /// Verification method used for authentication.
    pub verification_method: VerificationMethod,

    /// Local ledger head hash at time of admission.
    pub local_ledger_anchor: Hash,

    /// HLC timestamp at admission.
    pub admitted_at_hlc: u64,

    /// Rejection reasons for omitted elements (may be empty).
    pub rejection_reasons: Vec<RejectionReason>,
}

/// A rejection reason for an element that was not admitted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RejectionReason {
    /// Hash of the rejected artifact.
    pub artifact_hash: Hash,
    /// Human-readable reason for rejection.
    pub reason: String,
}

impl AdmissionReceiptV1 {
    /// Validate the receipt against bounded constraints.
    ///
    /// # Errors
    ///
    /// Returns [`HmpError`] for any constraint violation.
    pub fn validate(&self) -> Result<(), HmpError> {
        if self.sender_cell_id.len() > MAX_ID_LEN {
            return Err(HmpError::FieldTooLong {
                field: "sender_cell_id",
                len: self.sender_cell_id.len(),
                max: MAX_ID_LEN,
            });
        }
        if self.sender_policy_root_key_id.len() > MAX_ID_LEN {
            return Err(HmpError::FieldTooLong {
                field: "sender_policy_root_key_id",
                len: self.sender_policy_root_key_id.len(),
                max: MAX_ID_LEN,
            });
        }
        if self.admitted_hashes.len() > MAX_ADMITTED_HASHES {
            return Err(HmpError::TooManyAdmittedHashes {
                count: self.admitted_hashes.len(),
                max: MAX_ADMITTED_HASHES,
            });
        }
        if self.rejection_reasons.len() > MAX_REJECTION_REASONS {
            return Err(HmpError::TooManyRejectionReasons {
                count: self.rejection_reasons.len(),
                max: MAX_REJECTION_REASONS,
            });
        }
        for reason in &self.rejection_reasons {
            if reason.reason.len() > MAX_REJECTION_REASON_LEN {
                return Err(HmpError::RejectionReasonTooLong {
                    len: reason.reason.len(),
                    max: MAX_REJECTION_REASON_LEN,
                });
            }
        }
        Ok(())
    }

    /// Compute the deterministic receipt hash using domain separation.
    #[must_use]
    pub fn compute_receipt_hash(&self) -> Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(ADMISSION_RECEIPT_DOMAIN_SEPARATOR);
        hasher.update(&self.receipt_id);
        hasher.update(self.sender_cell_id.as_bytes());
        hasher.update(b"\n");
        hasher.update(self.sender_policy_root_key_id.as_bytes());
        hasher.update(b"\n");
        // Hash admitted hashes in order (deterministic).
        let count = self.admitted_hashes.len() as u64;
        hasher.update(&count.to_le_bytes());
        for hash in &self.admitted_hashes {
            hasher.update(hash);
        }
        hasher.update(self.verification_method.to_string().as_bytes());
        hasher.update(b"\n");
        hasher.update(&self.local_ledger_anchor);
        hasher.update(&self.admitted_at_hlc.to_le_bytes());
        // Rejection reasons also hashed for integrity.
        let reason_count = self.rejection_reasons.len() as u64;
        hasher.update(&reason_count.to_le_bytes());
        for reason in &self.rejection_reasons {
            hasher.update(&reason.artifact_hash);
            hasher.update(reason.reason.as_bytes());
            hasher.update(b"\n");
        }
        *hasher.finalize().as_bytes()
    }

    /// Returns `true` if all elements were admitted (no rejections).
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.rejection_reasons.is_empty()
    }
}

// =============================================================================
// Import Category
// =============================================================================

/// Category of cross-cell import that triggered an admission receipt.
///
/// Used by [`ImportReceiptV1`] to distinguish between different import
/// categories for audit and policy purposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ImportCategory {
    /// Ledger event ranges from another cell.
    LedgerEventRange,
    /// Policy root or cell certificate.
    PolicyRootCertificate,
    /// Permeability grant.
    PermeabilityGrant,
    /// CAS artifacts (content-addressed evidence).
    CasArtifact,
}

impl std::fmt::Display for ImportCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LedgerEventRange => f.write_str("LEDGER_EVENT_RANGE"),
            Self::PolicyRootCertificate => f.write_str("POLICY_ROOT_CERTIFICATE"),
            Self::PermeabilityGrant => f.write_str("PERMEABILITY_GRANT"),
            Self::CasArtifact => f.write_str("CAS_ARTIFACT"),
        }
    }
}

// =============================================================================
// Import Receipt V1
// =============================================================================

/// Typed import receipt wrapping an [`AdmissionReceiptV1`] with category
/// metadata (RFC-0020 §2.4.0b).
///
/// This provides a richer audit trail by recording not just the admission
/// facts but also the category of import that triggered the admission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportReceiptV1 {
    /// The underlying admission receipt.
    pub admission_receipt: AdmissionReceiptV1,

    /// Category of the import.
    pub import_category: ImportCategory,

    /// Source ledger range start (inclusive), if applicable.
    pub source_range_start: Option<u64>,

    /// Source ledger range end (inclusive), if applicable.
    pub source_range_end: Option<u64>,
}

impl ImportReceiptV1 {
    /// Validate the import receipt against bounded constraints.
    ///
    /// # Errors
    ///
    /// Returns [`HmpError`] for any constraint violation.
    pub fn validate(&self) -> Result<(), HmpError> {
        self.admission_receipt.validate()?;

        // If range is specified, start must not exceed end.
        if let (Some(start), Some(end)) = (self.source_range_start, self.source_range_end) {
            if start > end {
                return Err(HmpError::InvalidSourceRange { start, end });
            }
        }

        Ok(())
    }
}

// =============================================================================
// Errors
// =============================================================================

/// Errors for HMP envelope and admission receipt processing.
#[derive(Debug, Error)]
pub enum HmpError {
    /// Envelope exceeds the pre-decode size bound.
    #[error("envelope too large: {size} bytes exceeds max {max}")]
    EnvelopeTooLarge {
        /// Actual size.
        size: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// A string field exceeds its length bound.
    #[error("field `{field}` too long: {len} bytes exceeds max {max}")]
    FieldTooLong {
        /// Field name.
        field: &'static str,
        /// Actual length.
        len: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Content type string exceeds its length bound.
    #[error("content_type too long: {len} bytes exceeds max {max}")]
    ContentTypeTooLong {
        /// Actual length.
        len: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Too many causal parent references.
    #[error("too many parents: {count} exceeds max {max}")]
    TooManyParents {
        /// Actual count.
        count: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Authority-bearing channel missing permeability receipt hash.
    #[error("authority-bearing channel {channel} requires permeability_receipt_hash")]
    MissingPermeabilityReceipt {
        /// The offending channel class.
        channel: ChannelClass,
    },

    /// Deserialization failed.
    #[error("envelope deserialization failed: {detail}")]
    DeserializationFailed {
        /// Error detail.
        detail: String,
    },

    /// Too many admitted hashes in an admission receipt.
    #[error("too many admitted hashes: {count} exceeds max {max}")]
    TooManyAdmittedHashes {
        /// Actual count.
        count: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Too many rejection reasons in an admission receipt.
    #[error("too many rejection reasons: {count} exceeds max {max}")]
    TooManyRejectionReasons {
        /// Actual count.
        count: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Rejection reason string exceeds its length bound.
    #[error("rejection reason too long: {len} bytes exceeds max {max}")]
    RejectionReasonTooLong {
        /// Actual length.
        len: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Invalid source range in import receipt.
    #[error("invalid source range: start {start} > end {end}")]
    InvalidSourceRange {
        /// Range start.
        start: u64,
        /// Range end.
        end: u64,
    },

    /// Import admission denied: facts below attestation floor.
    #[error("import admission denied: {detail}")]
    AdmissionDenied {
        /// Denial detail.
        detail: String,
    },

    /// Duplicate idempotency key detected.
    #[error("duplicate idempotency key: {key}")]
    DuplicateIdempotencyKey {
        /// The duplicate key.
        key: String,
    },
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to create a test hash from a byte.
    fn test_hash(b: u8) -> Hash {
        [b; 32]
    }

    /// Helper to create a valid test envelope.
    fn valid_envelope() -> HmpMessageV1 {
        HmpMessageV1 {
            protocol_id: "hsi:v1".to_string(),
            message_class: "HSI.ANTI_ENTROPY.OFFER".to_string(),
            message_id: test_hash(0x01),
            idempotency_key: "idem-001".to_string(),
            hlc_timestamp: 1000,
            parents: vec![test_hash(0x02)],
            sender_holon_id: "holon:v1:blake3:aabb".to_string(),
            sender_actor_id: "actor-1".to_string(),
            channel_class: ChannelClass::Evidence,
            sender_cell_id: "cell:v1:blake3:ccdd".to_string(),
            receiver_cell_id: "cell:v1:blake3:eeff".to_string(),
            sender_policy_root_key_id: "pkid:v1:ed25519:blake3:1122".to_string(),
            body_ref: BodyRef {
                cas_hash: test_hash(0x03),
                content_type: "application/cbor".to_string(),
            },
            ledger_head_hash: test_hash(0x04),
            context_pack_hash: None,
            manifest_hash: None,
            view_commitment_hash: None,
            permeability_receipt_hash: None,
        }
    }

    // ─── ChannelClass tests ─────────────────────────────────────

    #[test]
    fn channel_class_authority_bearing() {
        assert!(!ChannelClass::Discovery.is_authority_bearing());
        assert!(ChannelClass::Handshake.is_authority_bearing());
        assert!(ChannelClass::Work.is_authority_bearing());
        assert!(!ChannelClass::Evidence.is_authority_bearing());
        assert!(ChannelClass::Governance.is_authority_bearing());
    }

    #[test]
    fn channel_class_routing_only() {
        assert!(ChannelClass::Discovery.is_routing_only());
        assert!(!ChannelClass::Handshake.is_routing_only());
        assert!(!ChannelClass::Work.is_routing_only());
        assert!(ChannelClass::Evidence.is_routing_only());
        assert!(!ChannelClass::Governance.is_routing_only());
    }

    #[test]
    fn channel_class_display() {
        assert_eq!(ChannelClass::Discovery.to_string(), "DISCOVERY");
        assert_eq!(ChannelClass::Handshake.to_string(), "HANDSHAKE");
        assert_eq!(ChannelClass::Work.to_string(), "WORK");
        assert_eq!(ChannelClass::Evidence.to_string(), "EVIDENCE");
        assert_eq!(ChannelClass::Governance.to_string(), "GOVERNANCE");
    }

    #[test]
    fn channel_class_serde_roundtrip() {
        for class in &[
            ChannelClass::Discovery,
            ChannelClass::Handshake,
            ChannelClass::Work,
            ChannelClass::Evidence,
            ChannelClass::Governance,
        ] {
            let json = serde_json::to_string(class).unwrap();
            let deser: ChannelClass = serde_json::from_str(&json).unwrap();
            assert_eq!(class, &deser);
        }
    }

    // ─── BodyRef tests ──────────────────────────────────────────

    #[test]
    fn body_ref_valid() {
        let br = BodyRef::new(test_hash(0x01), "application/json".to_string());
        assert!(br.is_ok());
    }

    #[test]
    fn body_ref_content_type_too_long() {
        let long = "x".repeat(MAX_CONTENT_TYPE_LEN + 1);
        let br = BodyRef::new(test_hash(0x01), long);
        assert!(matches!(br, Err(HmpError::ContentTypeTooLong { .. })));
    }

    // ─── HmpMessageV1 validation tests ─────────────────────────

    #[test]
    fn valid_evidence_envelope_passes() {
        let env = valid_envelope();
        assert!(env.validate().is_ok());
    }

    #[test]
    fn work_channel_without_permeability_receipt_passes() {
        // WORK messages may operate under existing session authority.
        let mut env = valid_envelope();
        env.channel_class = ChannelClass::Work;
        env.permeability_receipt_hash = None;
        assert!(env.validate().is_ok());
    }

    #[test]
    fn handshake_without_permeability_receipt_fails() {
        let mut env = valid_envelope();
        env.channel_class = ChannelClass::Handshake;
        env.permeability_receipt_hash = None;
        assert!(matches!(
            env.validate(),
            Err(HmpError::MissingPermeabilityReceipt { .. })
        ));
    }

    #[test]
    fn governance_without_permeability_receipt_fails() {
        let mut env = valid_envelope();
        env.channel_class = ChannelClass::Governance;
        env.permeability_receipt_hash = None;
        assert!(matches!(
            env.validate(),
            Err(HmpError::MissingPermeabilityReceipt { .. })
        ));
    }

    #[test]
    fn handshake_with_permeability_receipt_passes() {
        let mut env = valid_envelope();
        env.channel_class = ChannelClass::Handshake;
        env.permeability_receipt_hash = Some(test_hash(0xFF));
        assert!(env.validate().is_ok());
    }

    #[test]
    fn too_many_parents_fails() {
        let mut env = valid_envelope();
        env.parents = vec![test_hash(0x01); MAX_PARENTS + 1];
        assert!(matches!(
            env.validate(),
            Err(HmpError::TooManyParents { .. })
        ));
    }

    #[test]
    fn oversized_protocol_id_fails() {
        let mut env = valid_envelope();
        env.protocol_id = "x".repeat(MAX_PROTOCOL_ID_LEN + 1);
        assert!(matches!(
            env.validate(),
            Err(HmpError::FieldTooLong {
                field: "protocol_id",
                ..
            })
        ));
    }

    #[test]
    fn envelope_hash_deterministic() {
        let env = valid_envelope();
        let h1 = env.compute_envelope_hash();
        let h2 = env.compute_envelope_hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn envelope_hash_changes_with_field_mutation() {
        let env1 = valid_envelope();
        let mut env2 = valid_envelope();
        env2.hlc_timestamp = 9999;
        assert_ne!(env1.compute_envelope_hash(), env2.compute_envelope_hash());
    }

    #[test]
    fn envelope_hash_changes_with_optional_field() {
        let env1 = valid_envelope();
        let mut env2 = valid_envelope();
        env2.view_commitment_hash = Some(test_hash(0xAA));
        assert_ne!(env1.compute_envelope_hash(), env2.compute_envelope_hash());
    }

    // ─── EnvelopeAdmissionGate tests ────────────────────────────

    #[test]
    fn gate_rejects_oversized_envelope() {
        let gate = EnvelopeAdmissionGate::new(10);
        let result = gate.admit(&[0u8; 11]);
        assert!(matches!(result, Err(HmpError::EnvelopeTooLarge { .. })));
    }

    #[test]
    fn gate_rejects_invalid_json() {
        let gate = EnvelopeAdmissionGate::default_bounded();
        let result = gate.admit(b"not json");
        assert!(matches!(
            result,
            Err(HmpError::DeserializationFailed { .. })
        ));
    }

    #[test]
    fn gate_admits_valid_envelope() {
        let env = valid_envelope();
        let json = serde_json::to_vec(&env).unwrap();
        let gate = EnvelopeAdmissionGate::default_bounded();
        let admitted = gate.admit(&json).unwrap();
        assert_eq!(admitted.message_id, env.message_id);
    }

    // ─── AdmissionReceiptV1 tests ───────────────────────────────

    fn valid_admission_receipt() -> AdmissionReceiptV1 {
        AdmissionReceiptV1 {
            receipt_id: test_hash(0x10),
            sender_cell_id: "cell:v1:blake3:aabb".to_string(),
            sender_policy_root_key_id: "pkid:v1:ed25519:blake3:ccdd".to_string(),
            admitted_hashes: vec![test_hash(0x20), test_hash(0x21)],
            verification_method: VerificationMethod::SingleSignature,
            local_ledger_anchor: test_hash(0x30),
            admitted_at_hlc: 2000,
            rejection_reasons: vec![],
        }
    }

    #[test]
    fn admission_receipt_valid() {
        let receipt = valid_admission_receipt();
        assert!(receipt.validate().is_ok());
        assert!(receipt.is_complete());
    }

    #[test]
    fn admission_receipt_with_rejections() {
        let mut receipt = valid_admission_receipt();
        receipt.rejection_reasons.push(RejectionReason {
            artifact_hash: test_hash(0x40),
            reason: "signature verification failed".to_string(),
        });
        assert!(receipt.validate().is_ok());
        assert!(!receipt.is_complete());
    }

    #[test]
    fn admission_receipt_too_many_hashes() {
        let mut receipt = valid_admission_receipt();
        receipt.admitted_hashes = vec![test_hash(0x01); MAX_ADMITTED_HASHES + 1];
        assert!(matches!(
            receipt.validate(),
            Err(HmpError::TooManyAdmittedHashes { .. })
        ));
    }

    #[test]
    fn admission_receipt_too_many_rejection_reasons() {
        let mut receipt = valid_admission_receipt();
        receipt.rejection_reasons = (0..=MAX_REJECTION_REASONS)
            .map(|i| RejectionReason {
                #[allow(clippy::cast_possible_truncation)]
                artifact_hash: test_hash((i & 0xFF) as u8),
                reason: "reason".to_string(),
            })
            .collect();
        assert!(matches!(
            receipt.validate(),
            Err(HmpError::TooManyRejectionReasons { .. })
        ));
    }

    #[test]
    fn admission_receipt_rejection_reason_too_long() {
        let mut receipt = valid_admission_receipt();
        receipt.rejection_reasons.push(RejectionReason {
            artifact_hash: test_hash(0x50),
            reason: "x".repeat(MAX_REJECTION_REASON_LEN + 1),
        });
        assert!(matches!(
            receipt.validate(),
            Err(HmpError::RejectionReasonTooLong { .. })
        ));
    }

    #[test]
    fn admission_receipt_hash_deterministic() {
        let receipt = valid_admission_receipt();
        let h1 = receipt.compute_receipt_hash();
        let h2 = receipt.compute_receipt_hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn admission_receipt_hash_changes_with_mutation() {
        let r1 = valid_admission_receipt();
        let mut r2 = valid_admission_receipt();
        r2.admitted_at_hlc = 9999;
        assert_ne!(r1.compute_receipt_hash(), r2.compute_receipt_hash());
    }

    // ─── ImportReceiptV1 tests ──────────────────────────────────

    #[test]
    fn import_receipt_valid() {
        let ir = ImportReceiptV1 {
            admission_receipt: valid_admission_receipt(),
            import_category: ImportCategory::LedgerEventRange,
            source_range_start: Some(100),
            source_range_end: Some(200),
        };
        assert!(ir.validate().is_ok());
    }

    #[test]
    fn import_receipt_invalid_range() {
        let ir = ImportReceiptV1 {
            admission_receipt: valid_admission_receipt(),
            import_category: ImportCategory::LedgerEventRange,
            source_range_start: Some(200),
            source_range_end: Some(100),
        };
        assert!(matches!(
            ir.validate(),
            Err(HmpError::InvalidSourceRange { .. })
        ));
    }

    #[test]
    fn import_receipt_no_range() {
        let ir = ImportReceiptV1 {
            admission_receipt: valid_admission_receipt(),
            import_category: ImportCategory::CasArtifact,
            source_range_start: None,
            source_range_end: None,
        };
        assert!(ir.validate().is_ok());
    }

    // ─── VerificationMethod tests ───────────────────────────────

    #[test]
    fn verification_method_display() {
        assert_eq!(
            VerificationMethod::SingleSignature.to_string(),
            "SINGLE_SIGNATURE"
        );
        assert_eq!(
            VerificationMethod::QuorumMultisig.to_string(),
            "QUORUM_MULTISIG"
        );
        assert_eq!(
            VerificationMethod::QuorumThreshold.to_string(),
            "QUORUM_THRESHOLD"
        );
        assert_eq!(VerificationMethod::MerkleBatch.to_string(), "MERKLE_BATCH");
    }

    #[test]
    fn verification_method_serde_roundtrip() {
        for method in &[
            VerificationMethod::SingleSignature,
            VerificationMethod::QuorumMultisig,
            VerificationMethod::QuorumThreshold,
            VerificationMethod::MerkleBatch,
        ] {
            let json = serde_json::to_string(method).unwrap();
            let deser: VerificationMethod = serde_json::from_str(&json).unwrap();
            assert_eq!(method, &deser);
        }
    }

    // ─── ImportCategory tests ───────────────────────────────────

    #[test]
    fn import_category_serde_roundtrip() {
        for cat in &[
            ImportCategory::LedgerEventRange,
            ImportCategory::PolicyRootCertificate,
            ImportCategory::PermeabilityGrant,
            ImportCategory::CasArtifact,
        ] {
            let json = serde_json::to_string(cat).unwrap();
            let deser: ImportCategory = serde_json::from_str(&json).unwrap();
            assert_eq!(cat, &deser);
        }
    }

    // ─── Routing vs acceptance fact distinction ─────────────────

    #[test]
    fn routing_facts_and_acceptance_facts_are_distinct() {
        // Routing facts: envelope metadata (channel_class, sender/receiver IDs)
        // Acceptance facts: admission receipts bound to evidence
        let envelope = valid_envelope();
        let receipt = valid_admission_receipt();

        // Envelope hash (routing) and receipt hash (acceptance) are independent
        let envelope_hash = envelope.compute_envelope_hash();
        let receipt_hash = receipt.compute_receipt_hash();
        assert_ne!(envelope_hash, receipt_hash);

        // Channel class determines routing semantics
        assert!(envelope.channel_class.is_routing_only());

        // Receipt is the acceptance gate
        assert!(receipt.is_complete());
    }

    // ─── Unsolicited large payload drop test ────────────────────

    #[test]
    fn unsolicited_large_payload_dropped_bounded() {
        // Simulates an oversized envelope arriving — the gate drops it
        // before any body fetch occurs (bounded resource use).
        let gate = EnvelopeAdmissionGate::default_bounded();
        let oversized = vec![0u8; MAX_ENVELOPE_BYTES + 1];
        let result = gate.admit(&oversized);
        assert!(matches!(result, Err(HmpError::EnvelopeTooLarge { .. })));
    }

    // ─── Fail-closed: unknown fields in serde ───────────────────

    #[test]
    fn unknown_fields_rejected_body_ref() {
        let json = r#"{"cas_hash":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"content_type":"app/json","extra":"bad"}"#;
        let result: Result<BodyRef, _> = serde_json::from_str(json);
        assert!(result.is_err(), "unknown fields must be rejected");
    }

    #[test]
    fn unknown_fields_rejected_admission_receipt() {
        let receipt = valid_admission_receipt();
        let mut json_val = serde_json::to_value(&receipt).unwrap();
        json_val
            .as_object_mut()
            .unwrap()
            .insert("extra".to_string(), serde_json::json!("bad"));
        let result: Result<AdmissionReceiptV1, _> = serde_json::from_value(json_val);
        assert!(result.is_err(), "unknown fields must be rejected");
    }
}
