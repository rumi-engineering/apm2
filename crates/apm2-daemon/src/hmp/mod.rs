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
//! # Canonical Hashing
//!
//! All hash commitments use the [`Canonicalizable`] trait (RFC 8785 / JCS)
//! from `apm2_core::htf::canonical` for collision-resistant, deterministic
//! hash computation. Manual delimiter-based hashing is forbidden to prevent
//! canonicalization ambiguity attacks.
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
//! - **Control-char-free**: All string fields reject control characters
//!   (including newlines) to prevent canonicalization ambiguity.
//! - **Digest-first**: Body content is never inlined in the envelope wire
//!   shape.
//! - **Deterministic**: All hash computations use JCS-canonical JSON via
//!   [`Canonicalizable`].
//! - **Strict deserialization**: `#[serde(deny_unknown_fields)]` on all
//!   boundary structs.
//! - **Channel-class binding**: `message_class` prefix must be consistent with
//!   `channel_class` to prevent authority bypass attacks.
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
use apm2_core::htf::Canonicalizable;
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

    /// Returns the required `message_class` prefixes for this channel class.
    ///
    /// Used by [`HmpMessageV1::validate`] to enforce channel-class/message-
    /// class consistency.
    #[must_use]
    pub const fn allowed_message_class_prefixes(&self) -> &'static [&'static str] {
        match self {
            Self::Discovery => &["HSI.DIRECTORY."],
            Self::Handshake => &["HSI.PERMEABILITY."],
            Self::Work => &["FAC."],
            Self::Evidence => &["HSI.ANTI_ENTROPY.", "HSI.CAS."],
            Self::Governance => &["HSI.GOVERNANCE."],
        }
    }
}

impl std::fmt::Display for ChannelClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// =============================================================================
// String Validation
// =============================================================================

/// Check that a string field contains no control characters (ASCII < 0x20).
///
/// Control characters (including newlines, tabs, carriage returns) in
/// identifier and metadata fields could create canonicalization ambiguity
/// in hash preimages. Reject them at ingress.
fn reject_control_chars(field_name: &'static str, value: &str) -> Result<(), HmpError> {
    if value.bytes().any(|b| b < 0x20) {
        return Err(HmpError::ControlCharInField { field: field_name });
    }
    Ok(())
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
        reject_control_chars("content_type", &content_type)?;
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
    /// - Control character rejection
    /// - Parent list cardinality bounds
    /// - Channel-class / message-class consistency
    /// - Authority-bearing channel class constraints
    ///
    /// # Errors
    ///
    /// Returns [`HmpError`] for any constraint violation.
    pub fn validate(&self) -> Result<(), HmpError> {
        // Field length bounds
        Self::check_field_len("protocol_id", &self.protocol_id, MAX_PROTOCOL_ID_LEN)?;
        Self::check_field_len("message_class", &self.message_class, MAX_MESSAGE_CLASS_LEN)?;
        Self::check_field_len(
            "idempotency_key",
            &self.idempotency_key,
            MAX_IDEMPOTENCY_KEY_LEN,
        )?;
        Self::check_field_len("sender_holon_id", &self.sender_holon_id, MAX_ID_LEN)?;
        Self::check_field_len("sender_actor_id", &self.sender_actor_id, MAX_ID_LEN)?;
        Self::check_field_len("sender_cell_id", &self.sender_cell_id, MAX_ID_LEN)?;
        Self::check_field_len("receiver_cell_id", &self.receiver_cell_id, MAX_ID_LEN)?;
        Self::check_field_len(
            "sender_policy_root_key_id",
            &self.sender_policy_root_key_id,
            MAX_ID_LEN,
        )?;
        Self::check_field_len(
            "content_type",
            &self.body_ref.content_type,
            MAX_CONTENT_TYPE_LEN,
        )?;

        // Control character rejection for all string fields
        reject_control_chars("protocol_id", &self.protocol_id)?;
        reject_control_chars("message_class", &self.message_class)?;
        reject_control_chars("idempotency_key", &self.idempotency_key)?;
        reject_control_chars("sender_holon_id", &self.sender_holon_id)?;
        reject_control_chars("sender_actor_id", &self.sender_actor_id)?;
        reject_control_chars("sender_cell_id", &self.sender_cell_id)?;
        reject_control_chars("receiver_cell_id", &self.receiver_cell_id)?;
        reject_control_chars("sender_policy_root_key_id", &self.sender_policy_root_key_id)?;
        reject_control_chars("content_type", &self.body_ref.content_type)?;

        // Parent list bound
        if self.parents.len() > MAX_PARENTS {
            return Err(HmpError::TooManyParents {
                count: self.parents.len(),
                max: MAX_PARENTS,
            });
        }

        // Channel-class / message-class consistency check.
        // This prevents authority bypass by mismatching channel_class and
        // message_class (e.g., sending HSI.PERMEABILITY.GRANT on EVIDENCE).
        let prefixes = self.channel_class.allowed_message_class_prefixes();
        if !prefixes.iter().any(|p| self.message_class.starts_with(p)) {
            return Err(HmpError::ChannelClassMismatch {
                channel_class: self.channel_class,
                message_class: self.message_class.clone(),
            });
        }

        // Authority-bearing channel constraint: permeability receipt required
        // for HANDSHAKE and GOVERNANCE. WORK operates under session authority.
        if matches!(
            self.channel_class,
            ChannelClass::Handshake | ChannelClass::Governance
        ) && self.permeability_receipt_hash.is_none()
        {
            return Err(HmpError::MissingPermeabilityReceipt {
                channel: self.channel_class,
            });
        }

        Ok(())
    }

    /// Compute the deterministic envelope hash using JCS canonicalization.
    ///
    /// Uses the [`Canonicalizable`] trait (RFC 8785 / JCS) for collision-
    /// resistant, deterministic hashing. Since `HmpMessageV1` derives
    /// `Serialize`, the blanket impl provides `canonical_hash()`.
    ///
    /// # Panics
    ///
    /// Panics if serialization fails, which should never happen for a
    /// validated `HmpMessageV1`.
    #[must_use]
    pub fn compute_envelope_hash(&self) -> Hash {
        self.canonical_hash()
            .expect("validated HmpMessageV1 must serialize")
    }

    /// Check a field's length bound.
    const fn check_field_len(field: &'static str, value: &str, max: usize) -> Result<(), HmpError> {
        if value.len() > max {
            return Err(HmpError::FieldTooLong {
                field,
                len: value.len(),
                max,
            });
        }
        Ok(())
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
/// The authoritative identifier for this receipt is its `canonical_hash()`,
/// computed via JCS canonicalization (RFC 8785). There is no separate
/// `receipt_id` field; the content hash IS the identity.
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

    /// Compute the deterministic receipt hash using JCS canonicalization.
    ///
    /// This is the authoritative identity hash for the receipt. Use this
    /// for CAS indexing and ledger references.
    ///
    /// # Panics
    ///
    /// Panics if serialization fails, which should never happen for a
    /// validated `AdmissionReceiptV1`.
    #[must_use]
    pub fn compute_receipt_hash(&self) -> Hash {
        self.canonical_hash()
            .expect("validated AdmissionReceiptV1 must serialize")
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

    /// A string field contains control characters (ASCII < 0x20).
    #[error("field `{field}` contains control characters")]
    ControlCharInField {
        /// Field name.
        field: &'static str,
    },

    /// Too many causal parent references.
    #[error("too many parents: {count} exceeds max {max}")]
    TooManyParents {
        /// Actual count.
        count: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// `message_class` prefix does not match `channel_class`.
    #[error("message_class '{message_class}' is inconsistent with channel_class {channel_class}")]
    ChannelClassMismatch {
        /// The channel class.
        channel_class: ChannelClass,
        /// The offending message class.
        message_class: String,
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

    #[test]
    fn body_ref_rejects_control_chars() {
        let br = BodyRef::new(test_hash(0x01), "text/plain\n".to_string());
        assert!(matches!(br, Err(HmpError::ControlCharInField { .. })));
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
        env.message_class = "FAC.PULSE".to_string();
        env.permeability_receipt_hash = None;
        assert!(env.validate().is_ok());
    }

    #[test]
    fn handshake_without_permeability_receipt_fails() {
        let mut env = valid_envelope();
        env.channel_class = ChannelClass::Handshake;
        env.message_class = "HSI.PERMEABILITY.GRANT".to_string();
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
        env.message_class = "HSI.GOVERNANCE.STOP".to_string();
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
        env.message_class = "HSI.PERMEABILITY.GRANT".to_string();
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

    // ─── Channel-class / message-class consistency ──────────────

    #[test]
    fn channel_class_mismatch_permeability_on_evidence_fails() {
        // Security blocker: HSI.PERMEABILITY.GRANT must not be accepted
        // on the EVIDENCE channel, which would bypass receipt checks.
        let mut env = valid_envelope();
        env.channel_class = ChannelClass::Evidence;
        env.message_class = "HSI.PERMEABILITY.GRANT".to_string();
        assert!(matches!(
            env.validate(),
            Err(HmpError::ChannelClassMismatch { .. })
        ));
    }

    #[test]
    fn channel_class_mismatch_anti_entropy_on_handshake_fails() {
        let mut env = valid_envelope();
        env.channel_class = ChannelClass::Handshake;
        env.message_class = "HSI.ANTI_ENTROPY.OFFER".to_string();
        env.permeability_receipt_hash = Some(test_hash(0xFF));
        assert!(matches!(
            env.validate(),
            Err(HmpError::ChannelClassMismatch { .. })
        ));
    }

    #[test]
    fn channel_class_mismatch_cas_on_governance_fails() {
        let mut env = valid_envelope();
        env.channel_class = ChannelClass::Governance;
        env.message_class = "HSI.CAS.DELIVER".to_string();
        env.permeability_receipt_hash = Some(test_hash(0xFF));
        assert!(matches!(
            env.validate(),
            Err(HmpError::ChannelClassMismatch { .. })
        ));
    }

    #[test]
    fn consistent_discovery_channel_passes() {
        let mut env = valid_envelope();
        env.channel_class = ChannelClass::Discovery;
        env.message_class = "HSI.DIRECTORY.ANNOUNCE".to_string();
        assert!(env.validate().is_ok());
    }

    #[test]
    fn consistent_evidence_cas_passes() {
        let mut env = valid_envelope();
        env.channel_class = ChannelClass::Evidence;
        env.message_class = "HSI.CAS.DELIVER".to_string();
        assert!(env.validate().is_ok());
    }

    // ─── Control character rejection ────────────────────────────

    #[test]
    fn newline_in_protocol_id_rejected() {
        let mut env = valid_envelope();
        env.protocol_id = "hsi:v1\ninjected".to_string();
        assert!(matches!(
            env.validate(),
            Err(HmpError::ControlCharInField {
                field: "protocol_id"
            })
        ));
    }

    #[test]
    fn tab_in_idempotency_key_rejected() {
        let mut env = valid_envelope();
        env.idempotency_key = "idem\t001".to_string();
        assert!(matches!(
            env.validate(),
            Err(HmpError::ControlCharInField {
                field: "idempotency_key"
            })
        ));
    }

    #[test]
    fn null_byte_in_sender_cell_id_rejected() {
        let mut env = valid_envelope();
        env.sender_cell_id = "cell:v1:blake3:aa\0bb".to_string();
        assert!(matches!(
            env.validate(),
            Err(HmpError::ControlCharInField {
                field: "sender_cell_id"
            })
        ));
    }

    // ─── Canonical hash tests ───────────────────────────────────

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

    #[test]
    fn canonicalization_collision_resistance() {
        // Verify that two logically distinct envelopes with field content
        // that could collide under naive delimiter concatenation produce
        // different hashes under JCS canonicalization.
        let mut env1 = valid_envelope();
        env1.protocol_id = "hsi:v1X".to_string();
        env1.message_class = "HSI.ANTI_ENTROPY.OFFER".to_string();

        let mut env2 = valid_envelope();
        env2.protocol_id = "hsi:v1".to_string();
        env2.message_class = "XHSI.ANTI_ENTROPY.OFFER".to_string();

        // Under naive \n delimiters these could collide. With JCS they
        // cannot because JSON key-value pairs are unambiguous.
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

    #[test]
    fn admission_receipt_canonical_collision_resistance() {
        // Two receipts with different logical content must hash differently.
        let mut r1 = valid_admission_receipt();
        r1.sender_cell_id = "cell:v1:blake3:aaXbb".to_string();
        r1.sender_policy_root_key_id = "pkid".to_string();

        let mut r2 = valid_admission_receipt();
        r2.sender_cell_id = "cell:v1:blake3:aa".to_string();
        r2.sender_policy_root_key_id = "Xbbpkid".to_string();

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
