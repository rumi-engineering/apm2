// AGENT-AUTHORED
//! Dual lattice taint/classification propagation and declassification receipts
//! (TCK-00378).
//!
//! This module enforces RFC-0020 Section 5 dual-lattice security:
//!
//! - **Taint lattice**: Tracks data provenance integrity. Taint propagates
//!   upward via `join` (least upper bound). Higher taint = less trusted input.
//! - **Confidentiality lattice**: Tracks information classification level.
//!   Confidentiality propagates upward via `join` (least upper bound) when
//!   merging data from multiple sources. At boundary crossings, explicit
//!   [`DeclassificationReceipt`]-based downgrade is required -- there is no
//!   implicit meet-based clamping.
//! - **Declassification receipts**: Explicit, policy-gated downgrades of
//!   confidentiality level that produce auditable, time-bounded receipts.
//! - **Boundary crossing hooks**: Dual-lattice policy enforcement at trust
//!   boundary transitions and actuator entry points.
//!
//! # Security Model
//!
//! - **Fail-closed**: Any lattice violation rejects the request.
//! - **No implicit declassification**: Confidentiality can only be lowered via
//!   an explicit [`DeclassificationReceipt`] referencing a policy rule.
//!   Boundary crossings that exceed clearance are **denied**, not clamped.
//! - **Taint monotonicity**: Taint levels can only increase through joins;
//!   there is no "untainting" operation.
//! - **Tier-gated actuators**: Tier3+ actuators reject inputs above a
//!   configured taint threshold or confidentiality floor.
//!
//! # Contract References
//!
//! - `REQ-0032`: Dual lattice taint/classification propagation
//! - `EVID-0032`: Taint propagation correctness evidence
//! - `EVID-0308`: Declassification receipt evidence
//!
//! # Runtime Integration
//!
//! **Architecture note**: This module is the *taint policy primitive library*.
//! It provides types, lattice operations, declassification receipt issuance,
//! and boundary-crossing enforcement as pure functions / methods with no I/O.
//!
//! Runtime integration -- injecting labels into work-object flows, wiring
//! boundary checks into protocol dispatch, persisting receipts to the ledger,
//! and plugging in concrete [`SignatureVerifier`] implementations backed by
//! the daemon's key material -- is handled by daemon-layer wiring in a
//! follow-on ticket.
//!
//! Until the daemon-layer wiring lands, the API is library-only and must be
//! called explicitly by consumers.

// TODO(daemon-wiring): Wire DualLatticePolicy into daemon actuator/boundary
// dispatch (tracked by TCK-00378-daemon). Specifically:
//   - Wire taint labels into work-object instruction flow
//   - Boundary check hooks in protocol dispatch
//   - Ledger persistence for declassification receipts
//   - Concrete SignatureVerifier backed by daemon key material

use std::collections::HashMap;
use std::fmt;

use serde::de::{Deserializer, Visitor};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use thiserror::Error;

// =============================================================================
// Constants
// =============================================================================

/// Maximum length for a policy reference string in a declassification receipt.
const MAX_POLICY_REF_LEN: usize = 512;

/// Maximum length for the justification field in a declassification receipt.
const MAX_JUSTIFICATION_LEN: usize = 1024;

/// Maximum length for a boundary identifier.
const MAX_BOUNDARY_ID_LEN: usize = 256;

/// Maximum length for an authority identifier in a declassification receipt.
const MAX_AUTHORITY_ID_LEN: usize = 256;

/// Maximum allowed size in bytes for an authority signature on a
/// declassification receipt. This bounds the `authority_signature` field to
/// prevent denial-of-service via oversized deserialized receipts.
const MAX_SIGNATURE_SIZE: usize = 256;

/// Maximum lifetime of a declassification receipt in milliseconds (1 hour).
/// Receipts whose `expires_at_ms - issued_at_ms` exceeds this window are
/// rejected even if not yet expired. This bounds replay risk.
const MAX_RECEIPT_LIFETIME_MS: u64 = 3_600_000;

/// Maximum length for a receipt ID (nonce / unique identifier).
const MAX_RECEIPT_ID_LEN: usize = 256;

/// Maximum length for a payload hash or envelope hash in a receipt.
const MAX_EFFECT_HASH_LEN: usize = 64;

/// Required length for BLAKE3 digest bytes used in effect-binding hashes
/// (`payload_hash` and `envelope_hash`). Both issuance and consumption
/// enforce that these fields are exactly 32 bytes, preventing callers from
/// supplying empty or malformed hashes that would weaken replay protection
/// from effect-scoped to boundary-scoped.
const BLAKE3_DIGEST_LEN: usize = 32;

/// Maximum number of consumed receipt IDs tracked for anti-replay.
/// Once this limit is reached, further declassification attempts are
/// denied (fail-closed) to prevent unbounded memory growth.
const MAX_CONSUMED_RECEIPTS: usize = 100_000;

/// Maximum length for any individual `String` field when deserializing
/// a [`DeclassificationReceipt`]. Used by the bounded deserialization
/// helper to reject oversized payloads during deserialization before
/// allocation completes.
const MAX_DESERIALIZE_STRING_LEN: usize = 2048;

// =============================================================================
// Bounded deserialization helpers
// =============================================================================

/// A serde visitor that enforces a maximum string length DURING
/// deserialization. For formats that report the string length before
/// allocation (e.g., bincode, CBOR), the visitor can reject oversized
/// payloads without allocating. For self-describing formats (JSON),
/// the string is visited through `visit_str` / `visit_string` and
/// checked immediately.
struct BoundedStringVisitor {
    max_len: usize,
}

impl Visitor<'_> for BoundedStringVisitor {
    type Value = String;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "a string with at most {} bytes", self.max_len)
    }

    fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
        if v.len() > self.max_len {
            return Err(E::custom(format!(
                "string field length {} exceeds maximum {}",
                v.len(),
                self.max_len,
            )));
        }
        Ok(v.to_owned())
    }

    fn visit_string<E: serde::de::Error>(self, v: String) -> Result<Self::Value, E> {
        if v.len() > self.max_len {
            return Err(E::custom(format!(
                "string field length {} exceeds maximum {}",
                v.len(),
                self.max_len,
            )));
        }
        Ok(v)
    }
}

/// Serde deserializer that rejects strings exceeding
/// [`MAX_DESERIALIZE_STRING_LEN`] during deserialization via a visitor,
/// preventing memory allocation of oversized payloads before the receipt
/// is even fully constructed.
fn deserialize_bounded_string<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_string(BoundedStringVisitor {
        max_len: MAX_DESERIALIZE_STRING_LEN,
    })
}

/// A serde visitor that enforces a maximum byte-sequence length DURING
/// deserialization. Checks length before accepting.
struct BoundedBytesVisitor {
    max_len: usize,
    field_name: &'static str,
}

impl<'de> Visitor<'de> for BoundedBytesVisitor {
    type Value = Vec<u8>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "a byte sequence ({}) with at most {} bytes",
            self.field_name, self.max_len
        )
    }

    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        // If the format provides a size hint, check it before allocating.
        if let Some(size) = seq.size_hint() {
            if size > self.max_len {
                return Err(serde::de::Error::custom(format!(
                    "{} field length {} exceeds maximum {}",
                    self.field_name, size, self.max_len,
                )));
            }
        }
        let mut buf = Vec::with_capacity(seq.size_hint().unwrap_or(0).min(self.max_len));
        while let Some(byte) = seq.next_element::<u8>()? {
            if buf.len() >= self.max_len {
                return Err(serde::de::Error::custom(format!(
                    "{} field length exceeds maximum {}",
                    self.field_name, self.max_len,
                )));
            }
            buf.push(byte);
        }
        Ok(buf)
    }

    fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
        if v.len() > self.max_len {
            return Err(E::custom(format!(
                "{} field length {} exceeds maximum {}",
                self.field_name,
                v.len(),
                self.max_len,
            )));
        }
        Ok(v.to_vec())
    }

    fn visit_byte_buf<E: serde::de::Error>(self, v: Vec<u8>) -> Result<Self::Value, E> {
        if v.len() > self.max_len {
            return Err(E::custom(format!(
                "{} field length {} exceeds maximum {}",
                self.field_name,
                v.len(),
                self.max_len,
            )));
        }
        Ok(v)
    }
}

/// Serde deserializer that rejects byte vectors exceeding
/// [`MAX_EFFECT_HASH_LEN`] during deserialization via a visitor.
fn deserialize_bounded_bytes<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_seq(BoundedBytesVisitor {
        max_len: MAX_EFFECT_HASH_LEN,
        field_name: "bytes",
    })
}

/// Serde deserializer that rejects signature byte vectors exceeding
/// [`MAX_SIGNATURE_SIZE`] during deserialization via a visitor.
fn deserialize_bounded_signature<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_seq(BoundedBytesVisitor {
        max_len: MAX_SIGNATURE_SIZE,
        field_name: "signature",
    })
}

// =============================================================================
// Errors
// =============================================================================

/// Errors from dual-lattice policy enforcement.
#[derive(Debug, Clone, PartialEq, Eq, Error, Serialize, Deserialize)]
#[non_exhaustive]
pub enum TaintError {
    /// Taint level exceeds the maximum allowed for this actuator tier.
    #[error("taint level {actual} exceeds maximum {max_allowed} for tier {tier}")]
    TaintCeilingExceeded {
        /// The actual taint level of the input.
        actual: TaintLevel,
        /// The maximum taint level allowed.
        max_allowed: TaintLevel,
        /// The actuator tier that rejected the input.
        tier: u8,
    },

    /// Confidentiality level exceeds the maximum allowed for this boundary.
    #[error(
        "confidentiality level {actual} exceeds maximum {max_allowed} for boundary '{boundary}'"
    )]
    ConfidentialityFloorViolation {
        /// The actual confidentiality level of the data.
        actual: ConfidentialityLevel,
        /// The maximum confidentiality level allowed at this boundary.
        max_allowed: ConfidentialityLevel,
        /// The boundary that rejected the data.
        boundary: String,
    },

    /// Attempted declassification without explicit policy authorization.
    #[error("declassification from {from} to {to} denied: {reason}")]
    DeclassificationDenied {
        /// The current confidentiality level.
        from: ConfidentialityLevel,
        /// The requested target level.
        to: ConfidentialityLevel,
        /// Why the declassification was denied.
        reason: String,
    },

    /// Invalid policy reference in declassification request.
    #[error("invalid policy reference: {reason}")]
    InvalidPolicyRef {
        /// Why the reference is invalid.
        reason: String,
    },

    /// Boundary crossing denied by dual-lattice policy.
    #[error("boundary crossing denied at '{boundary}': {reason}")]
    BoundaryCrossingDenied {
        /// The boundary identifier.
        boundary: String,
        /// Why the crossing was denied.
        reason: String,
    },

    /// Authority signature verification failed on a declassification receipt.
    #[error("authority signature verification failed: {reason}")]
    SignatureVerificationFailed {
        /// Why the signature check failed.
        reason: String,
    },

    /// A receipt field exceeds its maximum allowed size at consumption time.
    #[error("receipt field size exceeded: {reason}")]
    ReceiptFieldSizeExceeded {
        /// Which field and its actual/allowed sizes.
        reason: String,
    },

    /// A duplicate boundary ID was detected during policy construction.
    #[error("duplicate boundary ID: '{boundary_id}'")]
    DuplicateBoundaryId {
        /// The duplicated boundary identifier.
        boundary_id: String,
    },

    /// A duplicate declassification rule ID was detected during policy
    /// construction.
    #[error("duplicate declassification rule ID: '{rule_id}'")]
    DuplicateRuleId {
        /// The duplicated rule identifier.
        rule_id: String,
    },

    /// A declassification receipt has expired or has invalid timestamps.
    #[error("receipt expired or invalid timestamps: {reason}")]
    ReceiptExpired {
        /// Why the receipt was rejected.
        reason: String,
    },

    /// A receipt has already been consumed (anti-replay).
    #[error("receipt already consumed: {receipt_id}")]
    ReceiptAlreadyConsumed {
        /// The receipt ID that was already consumed.
        receipt_id: String,
    },

    /// The consumed-receipt anti-replay set has reached its capacity limit.
    /// New declassification attempts are denied (fail-closed) until the set
    /// is cleared or compacted.
    #[error("consumed receipt set is full (capacity {capacity})")]
    ConsumedReceiptSetFull {
        /// The maximum capacity of the anti-replay set.
        capacity: usize,
    },

    /// Effect binding mismatch: the receipt's payload or envelope hash
    /// does not match the expected values at consumption time.
    #[error("receipt effect binding mismatch: {reason}")]
    EffectBindingMismatch {
        /// Why the effect binding check failed.
        reason: String,
    },

    /// An effect-binding hash (payload or envelope) has an invalid length.
    /// Both fields must be exactly 32 bytes (BLAKE3 digest length).
    #[error("invalid effect hash: {reason}")]
    InvalidEffectHash {
        /// Which field and its actual/required length.
        reason: String,
    },
}

// =============================================================================
// TaintLevel
// =============================================================================

/// Taint level in the integrity lattice.
///
/// Taint tracks data provenance integrity. Higher values indicate less
/// trustworthy data. Taint propagates upward: when combining data from
/// multiple sources, the result takes the highest (least trusted) taint
/// level via [`TaintLevel::join`] (least upper bound).
///
/// Lattice ordering: `Untainted < LowTaint < MediumTaint < HighTaint < Toxic`
///
/// # Invariants
///
/// - Taint is monotonically non-decreasing through data flow.
/// - There is no "untaint" operation; only the lattice join is provided.
/// - Tier3+ actuators reject inputs with taint above their configured ceiling.
#[derive(
    Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[repr(u8)]
pub enum TaintLevel {
    /// Data from fully trusted, validated sources.
    #[default]
    Untainted   = 0,
    /// Data from partially trusted sources (e.g., authenticated but external).
    LowTaint    = 1,
    /// Data that has passed through semi-trusted processing.
    MediumTaint = 2,
    /// Data from untrusted or unvalidated sources.
    HighTaint   = 3,
    /// Data that is known-compromised or must never reach actuators.
    Toxic       = 4,
}

impl TaintLevel {
    /// Lattice join (least upper bound): returns the higher taint level.
    ///
    /// When combining data from two sources, the result inherits the
    /// taint of the less-trusted source.
    #[must_use]
    pub const fn join(self, other: Self) -> Self {
        if (self as u8) >= (other as u8) {
            self
        } else {
            other
        }
    }

    /// Returns `true` if this taint level is at or below the given ceiling.
    #[must_use]
    pub const fn within_ceiling(self, ceiling: Self) -> bool {
        (self as u8) <= (ceiling as u8)
    }

    /// Returns the numeric ordinal for serialization.
    #[must_use]
    pub const fn ordinal(self) -> u8 {
        self as u8
    }

    /// Construct from ordinal, returning `None` for out-of-range values.
    #[must_use]
    pub const fn from_ordinal(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Untainted),
            1 => Some(Self::LowTaint),
            2 => Some(Self::MediumTaint),
            3 => Some(Self::HighTaint),
            4 => Some(Self::Toxic),
            _ => None,
        }
    }
}

impl fmt::Display for TaintLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Untainted => write!(f, "Untainted"),
            Self::LowTaint => write!(f, "LowTaint"),
            Self::MediumTaint => write!(f, "MediumTaint"),
            Self::HighTaint => write!(f, "HighTaint"),
            Self::Toxic => write!(f, "Toxic"),
        }
    }
}

// =============================================================================
// ConfidentialityLevel
// =============================================================================

/// Confidentiality level in the classification lattice.
///
/// Confidentiality tracks information sensitivity. Higher values indicate
/// more sensitive data. At boundary crossings, confidentiality is checked
/// strictly: data whose level exceeds the boundary's clearance is
/// **denied** unless an explicit [`DeclassificationReceipt`] is presented.
/// There is no implicit meet-based clamping at boundaries.
///
/// Lattice ordering: `Public < Internal < Confidential < Secret < TopSecret`
///
/// # Invariants
///
/// - Data cannot cross a boundary whose clearance is below the data's
///   confidentiality level unless a [`DeclassificationReceipt`] is presented.
/// - Combining data from multiple sources takes the *highest* confidentiality
///   via [`ConfidentialityLevel::join`] (a Secret + Public merge is Secret).
/// - Declassification requires explicit policy and produces an auditable
///   receipt.
#[derive(
    Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[repr(u8)]
pub enum ConfidentialityLevel {
    /// Publicly releasable data.
    #[default]
    Public       = 0,
    /// Internal-use-only data (not for external release).
    Internal     = 1,
    /// Confidential data requiring access controls.
    Confidential = 2,
    /// Secret data with strict need-to-know.
    Secret       = 3,
    /// Top-secret data with compartmented access.
    TopSecret    = 4,
}

impl ConfidentialityLevel {
    /// Lattice meet (greatest lower bound): returns the lower confidentiality
    /// level.
    ///
    /// Used at boundary crossings to enforce that outbound data does not
    /// exceed the boundary's clearance.
    #[must_use]
    pub const fn meet(self, other: Self) -> Self {
        if (self as u8) <= (other as u8) {
            self
        } else {
            other
        }
    }

    /// Lattice join (least upper bound): returns the higher confidentiality
    /// level.
    ///
    /// When combining data from multiple sources, the result inherits
    /// the highest classification.
    #[must_use]
    pub const fn join(self, other: Self) -> Self {
        if (self as u8) >= (other as u8) {
            self
        } else {
            other
        }
    }

    /// Returns `true` if this level is at or below the given clearance.
    #[must_use]
    pub const fn within_clearance(self, clearance: Self) -> bool {
        (self as u8) <= (clearance as u8)
    }

    /// Returns the numeric ordinal for serialization.
    #[must_use]
    pub const fn ordinal(self) -> u8 {
        self as u8
    }

    /// Construct from ordinal, returning `None` for out-of-range values.
    #[must_use]
    pub const fn from_ordinal(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Public),
            1 => Some(Self::Internal),
            2 => Some(Self::Confidential),
            3 => Some(Self::Secret),
            4 => Some(Self::TopSecret),
            _ => None,
        }
    }
}

impl fmt::Display for ConfidentialityLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Public => write!(f, "Public"),
            Self::Internal => write!(f, "Internal"),
            Self::Confidential => write!(f, "Confidential"),
            Self::Secret => write!(f, "Secret"),
            Self::TopSecret => write!(f, "TopSecret"),
        }
    }
}

// =============================================================================
// RFC/Schema Confidentiality Taxonomy Mapping
// =============================================================================

/// Normative RFC/schema confidentiality levels.
///
/// The RFC and JSON schema use `PUBLIC`, `INTERNAL`, `CONFIDENTIAL`,
/// `RESTRICTED` (4 levels). The internal engine uses 5 levels
/// (`Public`..`TopSecret`). This enum provides the normative
/// representation with fail-closed lossless mapping to/from
/// [`ConfidentialityLevel`].
///
/// Mapping:
/// - `PUBLIC`       <-> `Public`
/// - `INTERNAL`     <-> `Internal`
/// - `CONFIDENTIAL` <-> `Confidential`
/// - `RESTRICTED`   <-> `Secret`
///
/// `TopSecret` has **no** RFC counterpart and is rejected (fail-closed)
/// when mapping to the RFC taxonomy. Any unknown RFC string is also
/// rejected (fail-closed).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RfcConfidentialityLevel {
    /// Publicly releasable data. Maps to [`ConfidentialityLevel::Public`].
    #[serde(rename = "PUBLIC")]
    Public,
    /// Internal-use-only data. Maps to [`ConfidentialityLevel::Internal`].
    #[serde(rename = "INTERNAL")]
    Internal,
    /// Confidential data requiring access controls.
    /// Maps to [`ConfidentialityLevel::Confidential`].
    #[serde(rename = "CONFIDENTIAL")]
    Confidential,
    /// Restricted data with strict need-to-know.
    /// Maps to [`ConfidentialityLevel::Secret`].
    #[serde(rename = "RESTRICTED")]
    Restricted,
}

impl RfcConfidentialityLevel {
    /// All valid RFC level string representations.
    const VALID_NAMES: &'static [&'static str] =
        &["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"];
}

impl fmt::Display for RfcConfidentialityLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Public => write!(f, "PUBLIC"),
            Self::Internal => write!(f, "INTERNAL"),
            Self::Confidential => write!(f, "CONFIDENTIAL"),
            Self::Restricted => write!(f, "RESTRICTED"),
        }
    }
}

impl ConfidentialityLevel {
    /// Convert from the normative RFC/schema confidentiality level to the
    /// internal engine level. This is a lossless mapping.
    #[must_use]
    pub const fn from_rfc_level(rfc: RfcConfidentialityLevel) -> Self {
        match rfc {
            RfcConfidentialityLevel::Public => Self::Public,
            RfcConfidentialityLevel::Internal => Self::Internal,
            RfcConfidentialityLevel::Confidential => Self::Confidential,
            RfcConfidentialityLevel::Restricted => Self::Secret,
        }
    }

    /// Convert from the internal engine level to the normative RFC/schema
    /// confidentiality level.
    ///
    /// # Errors
    ///
    /// Returns [`TaintError::InvalidPolicyRef`] if the internal level has
    /// no RFC counterpart (fail-closed). Currently,
    /// [`ConfidentialityLevel::TopSecret`] is the only unmapped level.
    pub fn to_rfc_level(self) -> Result<RfcConfidentialityLevel, TaintError> {
        match self {
            Self::Public => Ok(RfcConfidentialityLevel::Public),
            Self::Internal => Ok(RfcConfidentialityLevel::Internal),
            Self::Confidential => Ok(RfcConfidentialityLevel::Confidential),
            Self::Secret => Ok(RfcConfidentialityLevel::Restricted),
            Self::TopSecret => Err(TaintError::InvalidPolicyRef {
                reason: format!(
                    "ConfidentialityLevel::TopSecret has no RFC counterpart \
                     (valid RFC levels: {:?})",
                    RfcConfidentialityLevel::VALID_NAMES
                ),
            }),
        }
    }

    /// Parse from an RFC-level string (e.g., `"PUBLIC"`, `"RESTRICTED"`).
    ///
    /// # Errors
    ///
    /// Returns [`TaintError::InvalidPolicyRef`] if the string does not match
    /// any normative RFC level (fail-closed).
    pub fn from_rfc_str(s: &str) -> Result<Self, TaintError> {
        let rfc = match s {
            "PUBLIC" => RfcConfidentialityLevel::Public,
            "INTERNAL" => RfcConfidentialityLevel::Internal,
            "CONFIDENTIAL" => RfcConfidentialityLevel::Confidential,
            "RESTRICTED" => RfcConfidentialityLevel::Restricted,
            _ => {
                return Err(TaintError::InvalidPolicyRef {
                    reason: format!(
                        "unknown RFC confidentiality level '{s}' \
                         (valid: {:?})",
                        RfcConfidentialityLevel::VALID_NAMES
                    ),
                });
            },
        };
        Ok(Self::from_rfc_level(rfc))
    }
}

// =============================================================================
// DataLabel
// =============================================================================

/// Combined taint + confidentiality label for a data item.
///
/// Every data item flowing through the system carries a dual label:
/// taint (integrity) and confidentiality (classification). Policy
/// decisions consider both dimensions simultaneously.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DataLabel {
    /// Integrity dimension: how trusted is this data?
    pub taint: TaintLevel,
    /// Classification dimension: how sensitive is this data?
    pub confidentiality: ConfidentialityLevel,
}

impl DataLabel {
    /// Create a new data label.
    #[must_use]
    pub const fn new(taint: TaintLevel, confidentiality: ConfidentialityLevel) -> Self {
        Self {
            taint,
            confidentiality,
        }
    }

    /// A fully trusted, public data label.
    pub const TRUSTED_PUBLIC: Self = Self {
        taint: TaintLevel::Untainted,
        confidentiality: ConfidentialityLevel::Public,
    };

    /// Join two labels: taint joins (goes up), confidentiality joins (goes up).
    ///
    /// Used when merging/combining data from multiple sources.
    #[must_use]
    pub const fn join(self, other: Self) -> Self {
        Self {
            taint: self.taint.join(other.taint),
            confidentiality: self.confidentiality.join(other.confidentiality),
        }
    }
}

impl Default for DataLabel {
    fn default() -> Self {
        Self::TRUSTED_PUBLIC
    }
}

impl fmt::Display for DataLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[taint={}, conf={}]", self.taint, self.confidentiality)
    }
}

// =============================================================================
// Free propagation functions
// =============================================================================

/// Propagate taint across multiple inputs via lattice join (least upper bound).
///
/// Returns the highest taint level among all inputs, or
/// [`TaintLevel::Untainted`] for an empty slice (the join identity).
///
/// # Examples
///
/// ```
/// use apm2_core::policy::taint::{TaintLevel, propagate_taint};
///
/// let inputs = [
///     TaintLevel::LowTaint,
///     TaintLevel::HighTaint,
///     TaintLevel::Untainted,
/// ];
/// assert_eq!(propagate_taint(&inputs), TaintLevel::HighTaint);
/// assert_eq!(propagate_taint(&[]), TaintLevel::Untainted);
/// ```
#[must_use]
pub fn propagate_taint(inputs: &[TaintLevel]) -> TaintLevel {
    inputs
        .iter()
        .copied()
        .fold(TaintLevel::Untainted, TaintLevel::join)
}

/// Propagate confidentiality across multiple inputs via lattice join (least
/// upper bound).
///
/// Returns the highest confidentiality level among all inputs, or
/// [`ConfidentialityLevel::Public`] for an empty slice (the join identity).
///
/// # Examples
///
/// ```
/// use apm2_core::policy::taint::{ConfidentialityLevel, propagate_classification};
///
/// let inputs = [ConfidentialityLevel::Internal, ConfidentialityLevel::Secret];
/// assert_eq!(
///     propagate_classification(&inputs),
///     ConfidentialityLevel::Secret
/// );
/// assert_eq!(propagate_classification(&[]), ConfidentialityLevel::Public);
/// ```
#[must_use]
pub fn propagate_classification(inputs: &[ConfidentialityLevel]) -> ConfidentialityLevel {
    inputs
        .iter()
        .copied()
        .fold(ConfidentialityLevel::Public, ConfidentialityLevel::join)
}

// =============================================================================
// BoundaryPolicy
// =============================================================================

/// Policy for a trust boundary crossing point.
///
/// Each boundary defines maximum taint and confidentiality levels. Data
/// crossing the boundary must satisfy both constraints or be rejected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoundaryPolicy {
    /// Human-readable identifier for this boundary.
    boundary_id: String,
    /// Maximum taint level allowed through this boundary.
    max_taint: TaintLevel,
    /// Maximum confidentiality level allowed through this boundary.
    max_confidentiality: ConfidentialityLevel,
    /// The actuator tier this boundary guards (0 = no tier restriction).
    tier: u8,
}

impl BoundaryPolicy {
    /// Create a new boundary policy.
    ///
    /// # Errors
    ///
    /// Returns [`TaintError::InvalidPolicyRef`] if the boundary ID is empty
    /// or too long.
    pub fn new(
        boundary_id: &str,
        max_taint: TaintLevel,
        max_confidentiality: ConfidentialityLevel,
        tier: u8,
    ) -> Result<Self, TaintError> {
        if boundary_id.is_empty() {
            return Err(TaintError::InvalidPolicyRef {
                reason: "boundary ID must be non-empty".to_string(),
            });
        }
        if boundary_id.len() > MAX_BOUNDARY_ID_LEN {
            return Err(TaintError::InvalidPolicyRef {
                reason: format!("boundary ID exceeds maximum length of {MAX_BOUNDARY_ID_LEN}"),
            });
        }

        Ok(Self {
            boundary_id: boundary_id.to_string(),
            max_taint,
            max_confidentiality,
            tier,
        })
    }

    /// Returns the boundary identifier.
    #[must_use]
    pub fn boundary_id(&self) -> &str {
        &self.boundary_id
    }

    /// Returns the maximum taint level allowed.
    #[must_use]
    pub const fn max_taint(&self) -> TaintLevel {
        self.max_taint
    }

    /// Returns the maximum confidentiality level allowed.
    #[must_use]
    pub const fn max_confidentiality(&self) -> ConfidentialityLevel {
        self.max_confidentiality
    }

    /// Returns the actuator tier.
    #[must_use]
    pub const fn tier(&self) -> u8 {
        self.tier
    }

    /// Check whether a data label is allowed to cross this boundary.
    ///
    /// # Errors
    ///
    /// Returns [`TaintError::TaintCeilingExceeded`] if the taint level is
    /// too high, or [`TaintError::ConfidentialityFloorViolation`] if the
    /// confidentiality level is too high for the boundary's clearance.
    pub fn check(&self, label: &DataLabel) -> Result<(), TaintError> {
        if !label.taint.within_ceiling(self.max_taint) {
            return Err(TaintError::TaintCeilingExceeded {
                actual: label.taint,
                max_allowed: self.max_taint,
                tier: self.tier,
            });
        }

        if !label
            .confidentiality
            .within_clearance(self.max_confidentiality)
        {
            return Err(TaintError::ConfidentialityFloorViolation {
                actual: label.confidentiality,
                max_allowed: self.max_confidentiality,
                boundary: self.boundary_id.clone(),
            });
        }

        Ok(())
    }
}

// =============================================================================
// SignatureVerifier trait
// =============================================================================

/// Trait for verifying authority signatures on declassification receipts.
///
/// Implementors bind the receipt to a cryptographic identity, ensuring that
/// only an authorized principal can produce a valid receipt.
///
/// The trait is object-safe so that callers can pass `&dyn SignatureVerifier`
/// at boundary-crossing time without monomorphization.
///
/// # Fail-Closed Semantics
///
/// When no verifier is available (i.e., `None` is passed to
/// [`DualLatticePolicy::propagate_with_declassification`]), the receipt is
/// **rejected** -- fail-closed.
// TODO(RFC-0020): Wire concrete Ed25519/HSM SignatureVerifier into daemon
// actuation path
pub trait SignatureVerifier: fmt::Debug + Send + Sync {
    /// Verify that `signature` is a valid signature by `authority_id` over
    /// `message`.
    ///
    /// Returns `true` if and only if the signature is valid for the given
    /// authority and message. Returns `false` for any error, unknown
    /// authority, or invalid signature (fail-closed).
    fn verify(&self, authority_id: &str, message: &[u8], signature: &[u8]) -> bool;
}

// =============================================================================
// DeclassificationReceipt
// =============================================================================

/// An auditable receipt for an explicit confidentiality downgrade.
///
/// Declassification is the only way to lower a data item's confidentiality
/// level. It requires:
/// 1. An explicit policy rule authorizing the downgrade.
/// 2. A justification string for audit.
/// 3. An authority binding (who authorized the declassification).
/// 4. A boundary binding (which boundary the receipt applies to).
/// 5. The receipt is content-addressed (BLAKE3 hash) for tamper evidence.
/// 6. A cryptographic authority signature over the content hash, verified via
///    [`SignatureVerifier`] at consumption time.
///
/// # Security Properties
///
/// - Receipts are immutable once created.
/// - The policy reference must name a real, active declassification rule.
/// - The `authority_id` binds the receipt to the principal that authorized the
///   declassification.
/// - The `authority_signature` is verified via a caller-supplied
///   [`SignatureVerifier`] during
///   [`DualLatticePolicy::propagate_with_declassification`].
/// - The `boundary_id` scopes the receipt to a specific boundary crossing.
///   [`DualLatticePolicy::propagate_with_declassification`] validates that the
///   receipt's boundary matches the boundary being crossed.
/// - The content hash covers **all** fields (including authority and boundary)
///   to prevent tampering or replay across boundaries.
/// - Receipts are logged to the ledger for post-hoc audit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeclassificationReceipt {
    /// The confidentiality level before declassification.
    from_level: ConfidentialityLevel,
    /// The confidentiality level after declassification.
    to_level: ConfidentialityLevel,
    /// Unique receipt identifier / nonce for anti-replay enforcement.
    /// Each receipt MUST have a globally unique `receipt_id`. The
    /// [`DualLatticePolicy`] tracks consumed IDs and rejects duplicates.
    #[serde(deserialize_with = "deserialize_bounded_string")]
    receipt_id: String,
    /// Reference to the policy rule that authorized this declassification.
    #[serde(deserialize_with = "deserialize_bounded_string")]
    policy_ref: String,
    /// Human-readable justification for audit trail.
    #[serde(deserialize_with = "deserialize_bounded_string")]
    justification: String,
    /// Identifier of the authority (principal) that authorized the
    /// declassification.
    #[serde(deserialize_with = "deserialize_bounded_string")]
    authority_id: String,
    /// Identifier of the boundary this receipt is scoped to. The receipt is
    /// only valid when crossing this specific boundary.
    #[serde(deserialize_with = "deserialize_bounded_string")]
    boundary_id: String,
    /// BLAKE3 hash of the payload / request that this receipt is bound to.
    /// Verified at consumption time to ensure the receipt is not replayed
    /// for a different effect.
    #[serde(default, deserialize_with = "deserialize_bounded_bytes")]
    payload_hash: Vec<u8>,
    /// BLAKE3 hash of the episode envelope that this receipt is bound to.
    /// Verified at consumption time to ensure the receipt is not replayed
    /// across episodes.
    #[serde(default, deserialize_with = "deserialize_bounded_bytes")]
    envelope_hash: Vec<u8>,
    /// Millisecond-precision UTC timestamp when this receipt was issued.
    issued_at_ms: u64,
    /// Millisecond-precision UTC timestamp when this receipt expires.
    /// Must be strictly after `issued_at_ms` and within
    /// [`MAX_RECEIPT_LIFETIME_MS`] of it.
    expires_at_ms: u64,
    /// BLAKE3 hash of the receipt content for tamper evidence.
    content_hash: [u8; 32],
    /// Cryptographic signature by the authority over the content hash.
    ///
    /// Verified at consumption time via a caller-supplied
    /// [`SignatureVerifier`]. Receipts without a valid signature are
    /// rejected (fail-closed). Bounded to [`MAX_SIGNATURE_SIZE`] bytes.
    #[serde(default, deserialize_with = "deserialize_bounded_signature")]
    authority_signature: Vec<u8>,
}

impl DeclassificationReceipt {
    /// Returns the level before declassification.
    #[must_use]
    pub const fn from_level(&self) -> ConfidentialityLevel {
        self.from_level
    }

    /// Returns the level after declassification.
    #[must_use]
    pub const fn to_level(&self) -> ConfidentialityLevel {
        self.to_level
    }

    /// Returns the unique receipt identifier / nonce.
    #[must_use]
    pub fn receipt_id(&self) -> &str {
        &self.receipt_id
    }

    /// Returns the policy rule reference that authorized this.
    #[must_use]
    pub fn policy_ref(&self) -> &str {
        &self.policy_ref
    }

    /// Returns the justification string.
    #[must_use]
    pub fn justification(&self) -> &str {
        &self.justification
    }

    /// Returns the authority that authorized this declassification.
    #[must_use]
    pub fn authority_id(&self) -> &str {
        &self.authority_id
    }

    /// Returns the boundary this receipt is scoped to.
    #[must_use]
    pub fn boundary_id(&self) -> &str {
        &self.boundary_id
    }

    /// Returns the payload hash this receipt is bound to.
    #[must_use]
    pub fn payload_hash(&self) -> &[u8] {
        &self.payload_hash
    }

    /// Returns the envelope hash this receipt is bound to.
    #[must_use]
    pub fn envelope_hash(&self) -> &[u8] {
        &self.envelope_hash
    }

    /// Returns the issuance timestamp in milliseconds (UTC).
    #[must_use]
    pub const fn issued_at_ms(&self) -> u64 {
        self.issued_at_ms
    }

    /// Returns the expiry timestamp in milliseconds (UTC).
    #[must_use]
    pub const fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }

    /// Returns the BLAKE3 content hash of this receipt.
    #[must_use]
    pub const fn content_hash(&self) -> &[u8; 32] {
        &self.content_hash
    }

    /// Returns the content hash as a hex-encoded string.
    #[must_use]
    pub fn content_hash_hex(&self) -> String {
        self.content_hash.iter().fold(String::new(), |mut acc, b| {
            use fmt::Write;
            let _ = write!(acc, "{b:02x}");
            acc
        })
    }

    /// Returns the authority signature bytes.
    #[must_use]
    pub fn authority_signature(&self) -> &[u8] {
        &self.authority_signature
    }
}

// =============================================================================
// DeclassificationPolicy
// =============================================================================

/// Policy rule authorizing a specific confidentiality downgrade.
///
/// Each rule specifies the allowed downgrade range and is identified
/// by a unique rule ID that must be referenced in the receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeclassificationPolicy {
    /// Unique rule identifier (referenced by receipts).
    rule_id: String,
    /// Maximum source level this rule can declassify from.
    max_from: ConfidentialityLevel,
    /// Minimum target level this rule allows declassification to.
    min_to: ConfidentialityLevel,
}

impl DeclassificationPolicy {
    /// Create a new declassification policy rule.
    ///
    /// # Errors
    ///
    /// Returns [`TaintError::InvalidPolicyRef`] if the rule ID is invalid
    /// or the level range is non-decreasing (from must be strictly greater
    /// than to).
    pub fn new(
        rule_id: &str,
        max_from: ConfidentialityLevel,
        min_to: ConfidentialityLevel,
    ) -> Result<Self, TaintError> {
        if rule_id.is_empty() {
            return Err(TaintError::InvalidPolicyRef {
                reason: "declassification rule ID must be non-empty".to_string(),
            });
        }
        if rule_id.len() > MAX_POLICY_REF_LEN {
            return Err(TaintError::InvalidPolicyRef {
                reason: format!(
                    "declassification rule ID exceeds maximum length of {MAX_POLICY_REF_LEN}"
                ),
            });
        }
        if max_from.ordinal() <= min_to.ordinal() {
            return Err(TaintError::InvalidPolicyRef {
                reason: format!(
                    "declassification range invalid: max_from ({max_from}) must be \
                     strictly greater than min_to ({min_to})"
                ),
            });
        }

        Ok(Self {
            rule_id: rule_id.to_string(),
            max_from,
            min_to,
        })
    }

    /// Returns the rule identifier.
    #[must_use]
    pub fn rule_id(&self) -> &str {
        &self.rule_id
    }

    /// Returns the maximum source level.
    #[must_use]
    pub const fn max_from(&self) -> ConfidentialityLevel {
        self.max_from
    }

    /// Returns the minimum target level.
    #[must_use]
    pub const fn min_to(&self) -> ConfidentialityLevel {
        self.min_to
    }

    /// Check whether a specific declassification is allowed by this rule.
    const fn allows(&self, from: ConfidentialityLevel, to: ConfidentialityLevel) -> bool {
        from.within_clearance(self.max_from)
            && to.ordinal() >= self.min_to.ordinal()
            && from.ordinal() > to.ordinal()
    }
}

// =============================================================================
// DualLatticePolicy
// =============================================================================

/// The dual-lattice policy engine combining taint and confidentiality.
///
/// Holds boundary policies and declassification rules. All data crossing
/// boundaries or entering actuators is checked against this policy.
///
/// # Fail-Closed Behavior
///
/// - If no boundary policy is configured for a crossing point, the crossing is
///   denied (fail-closed).
/// - If no declassification rule matches a downgrade request, the downgrade is
///   denied.
#[derive(Debug, Clone)]
pub struct DualLatticePolicy {
    /// Boundary policies keyed by boundary ID.
    boundaries: Vec<BoundaryPolicy>,
    /// Declassification rules.
    declassification_rules: Vec<DeclassificationPolicy>,
    /// Anti-replay map of consumed receipt IDs to their `expires_at_ms`
    /// timestamps. A receipt can only be consumed once; subsequent
    /// attempts are rejected. Bounded to [`MAX_CONSUMED_RECEIPTS`]
    /// entries. Expired entries are evicted before checking capacity,
    /// preventing indefinite growth as receipts age out.
    consumed_receipts: HashMap<String, u64>,
}

impl DualLatticePolicy {
    /// Create a new dual-lattice policy with the given boundaries and
    /// declassification rules.
    ///
    /// # Errors
    ///
    /// Returns [`TaintError::DuplicateBoundaryId`] if any two boundaries share
    /// the same ID, or [`TaintError::DuplicateRuleId`] if any two
    /// declassification rules share the same rule ID.
    pub fn new(
        boundaries: Vec<BoundaryPolicy>,
        declassification_rules: Vec<DeclassificationPolicy>,
    ) -> Result<Self, TaintError> {
        // Validate boundary ID uniqueness.
        {
            let mut seen = std::collections::HashSet::with_capacity(boundaries.len());
            for b in &boundaries {
                if !seen.insert(b.boundary_id()) {
                    return Err(TaintError::DuplicateBoundaryId {
                        boundary_id: b.boundary_id().to_string(),
                    });
                }
            }
        }
        // Validate rule ID uniqueness.
        {
            let mut seen = std::collections::HashSet::with_capacity(declassification_rules.len());
            for r in &declassification_rules {
                if !seen.insert(r.rule_id()) {
                    return Err(TaintError::DuplicateRuleId {
                        rule_id: r.rule_id().to_string(),
                    });
                }
            }
        }
        Ok(Self {
            boundaries,
            declassification_rules,
            consumed_receipts: HashMap::new(),
        })
    }

    /// Create an empty (deny-all) policy. No boundaries are configured,
    /// so all crossings are denied.
    #[must_use]
    pub fn deny_all() -> Self {
        Self {
            boundaries: Vec::new(),
            declassification_rules: Vec::new(),
            consumed_receipts: HashMap::new(),
        }
    }

    /// Check a data label against a named boundary.
    ///
    /// # Errors
    ///
    /// Returns [`TaintError::BoundaryCrossingDenied`] if no boundary with
    /// the given ID is configured (fail-closed), or the specific taint/
    /// confidentiality violation error if the label fails the check.
    // TODO(RFC-0020): Wire into daemon protocol dispatch boundary hooks
    pub fn check_boundary(&self, boundary_id: &str, label: &DataLabel) -> Result<(), TaintError> {
        let boundary = self
            .boundaries
            .iter()
            .find(|b| b.boundary_id() == boundary_id)
            .ok_or_else(|| TaintError::BoundaryCrossingDenied {
                boundary: boundary_id.to_string(),
                reason: "no boundary policy configured (fail-closed)".to_string(),
            })?;

        boundary.check(label)
    }

    /// Check a data label against an actuator tier.
    ///
    /// Tier3+ actuators require taint at or below the boundary's
    /// configured ceiling and confidentiality at or below its clearance.
    ///
    /// # Errors
    ///
    /// Returns the appropriate [`TaintError`] variant if the label
    /// violates the tier's policy.
    // TODO(RFC-0020): Wire into daemon actuator dispatch path
    pub fn check_actuator_tier(&self, tier: u8, label: &DataLabel) -> Result<(), TaintError> {
        // Find all boundary policies for this tier; data must satisfy all.
        let tier_boundaries: Vec<&BoundaryPolicy> = self
            .boundaries
            .iter()
            .filter(|b| b.tier() == tier)
            .collect();

        if tier >= 3 && tier_boundaries.is_empty() {
            return Err(TaintError::BoundaryCrossingDenied {
                boundary: format!("tier-{tier}"),
                reason: "no boundary policy configured for tier (fail-closed)".to_string(),
            });
        }

        for boundary in tier_boundaries {
            boundary.check(label)?;
        }

        Ok(())
    }

    /// Validate all string/bytes input fields for a declassification request.
    /// Extracted to keep `declassify()` under clippy's line limit.
    #[allow(clippy::too_many_arguments)]
    fn validate_declassify_inputs(
        receipt_id: &str,
        policy_ref: &str,
        justification: &str,
        authority_id: &str,
        boundary_id: &str,
        payload_hash: &[u8],
        envelope_hash: &[u8],
        authority_signature: &[u8],
    ) -> Result<(), TaintError> {
        Self::validate_nonempty_bounded(receipt_id, "receipt_id", MAX_RECEIPT_ID_LEN)?;
        Self::validate_nonempty_bounded(policy_ref, "policy reference", MAX_POLICY_REF_LEN)?;
        Self::validate_nonempty_bounded(authority_id, "authority_id", MAX_AUTHORITY_ID_LEN)?;
        Self::validate_nonempty_bounded(boundary_id, "boundary_id", MAX_BOUNDARY_ID_LEN)?;
        if justification.len() > MAX_JUSTIFICATION_LEN {
            return Err(TaintError::InvalidPolicyRef {
                reason: format!("justification exceeds maximum length of {MAX_JUSTIFICATION_LEN}"),
            });
        }
        Self::validate_exact_hash(payload_hash, "payload_hash")?;
        Self::validate_exact_hash(envelope_hash, "envelope_hash")?;
        Self::validate_bytes_bounded(
            authority_signature,
            "authority_signature",
            MAX_SIGNATURE_SIZE,
        )?;
        Ok(())
    }

    /// Validate that a string field is non-empty and within a length limit.
    fn validate_nonempty_bounded(
        value: &str,
        name: &str,
        max_len: usize,
    ) -> Result<(), TaintError> {
        if value.is_empty() {
            return Err(TaintError::InvalidPolicyRef {
                reason: format!("{name} must be non-empty"),
            });
        }
        if value.len() > max_len {
            return Err(TaintError::InvalidPolicyRef {
                reason: format!("{name} exceeds maximum length of {max_len}"),
            });
        }
        Ok(())
    }

    /// Validate that a byte-slice field is within a length limit.
    fn validate_bytes_bounded(value: &[u8], name: &str, max_len: usize) -> Result<(), TaintError> {
        if value.len() > max_len {
            return Err(TaintError::ReceiptFieldSizeExceeded {
                reason: format!("{name} length {} exceeds maximum {max_len}", value.len()),
            });
        }
        Ok(())
    }

    /// Validate that an effect-binding hash is exactly [`BLAKE3_DIGEST_LEN`]
    /// bytes. Rejects both empty and non-32-byte hashes, ensuring that
    /// effect binding provides cryptographic strength rather than a trivial
    /// empty match.
    fn validate_exact_hash(value: &[u8], name: &str) -> Result<(), TaintError> {
        if value.len() != BLAKE3_DIGEST_LEN {
            return Err(TaintError::InvalidEffectHash {
                reason: format!(
                    "{name} must be exactly {BLAKE3_DIGEST_LEN} bytes (got {} bytes)",
                    value.len()
                ),
            });
        }
        Ok(())
    }

    /// Request a declassification, producing a receipt if authorized.
    ///
    /// # Errors
    ///
    /// Returns [`TaintError::DeclassificationDenied`] if no matching rule
    /// is found. Returns [`TaintError::InvalidPolicyRef`] if any identifier
    /// is invalid. Returns [`TaintError::ReceiptExpired`] if the timestamp
    /// window is invalid.
    // TODO(RFC-0020): Wire into daemon actuation path
    #[allow(clippy::too_many_arguments)] // All params are semantically distinct security inputs
    pub fn declassify(
        &self,
        from: ConfidentialityLevel,
        to: ConfidentialityLevel,
        receipt_id: &str,
        policy_ref: &str,
        justification: &str,
        authority_id: &str,
        boundary_id: &str,
        payload_hash: &[u8],
        envelope_hash: &[u8],
        authority_signature: &[u8],
        issued_at_ms: u64,
        expires_at_ms: u64,
    ) -> Result<DeclassificationReceipt, TaintError> {
        // Validate level ordering.
        if from.ordinal() <= to.ordinal() {
            return Err(TaintError::DeclassificationDenied {
                from,
                to,
                reason: "declassification requires from > to".to_string(),
            });
        }

        // Validate all string/bytes input fields.
        Self::validate_declassify_inputs(
            receipt_id,
            policy_ref,
            justification,
            authority_id,
            boundary_id,
            payload_hash,
            envelope_hash,
            authority_signature,
        )?;

        // Validate freshness window.
        if expires_at_ms <= issued_at_ms {
            return Err(TaintError::ReceiptExpired {
                reason: format!(
                    "expires_at_ms ({expires_at_ms}) must be strictly after \
                     issued_at_ms ({issued_at_ms})"
                ),
            });
        }
        let lifetime = expires_at_ms - issued_at_ms;
        if lifetime > MAX_RECEIPT_LIFETIME_MS {
            return Err(TaintError::ReceiptExpired {
                reason: format!(
                    "receipt lifetime {lifetime}ms exceeds maximum {MAX_RECEIPT_LIFETIME_MS}ms"
                ),
            });
        }

        // Find a matching declassification rule.
        let rule = self
            .declassification_rules
            .iter()
            .find(|r| r.rule_id() == policy_ref && r.allows(from, to))
            .ok_or_else(|| TaintError::DeclassificationDenied {
                from,
                to,
                reason: format!(
                    "no declassification rule '{policy_ref}' authorizes {from} -> {to}"
                ),
            })?;

        // Compute content hash (length-prefixed canonical hashing).
        let content_hash = Self::compute_receipt_hash(
            from,
            to,
            receipt_id,
            rule.rule_id(),
            justification,
            authority_id,
            boundary_id,
            payload_hash,
            envelope_hash,
            issued_at_ms,
            expires_at_ms,
        );

        Ok(DeclassificationReceipt {
            from_level: from,
            to_level: to,
            receipt_id: receipt_id.to_string(),
            policy_ref: policy_ref.to_string(),
            justification: justification.to_string(),
            authority_id: authority_id.to_string(),
            boundary_id: boundary_id.to_string(),
            payload_hash: payload_hash.to_vec(),
            envelope_hash: envelope_hash.to_vec(),
            issued_at_ms,
            expires_at_ms,
            content_hash,
            authority_signature: authority_signature.to_vec(),
        })
    }

    /// Compute the canonical content hash for a declassification receipt.
    ///
    /// Uses domain-separated, length-prefixed hashing to prevent
    /// delimiter-boundary collision attacks. Each variable-length field
    /// is preceded by its byte length as a little-endian `u64`.
    ///
    /// The hash preimage includes effect-binding fields (`receipt_id`,
    /// `payload_hash`, `envelope_hash`) to prevent receipt replay across
    /// unrelated effects.
    #[allow(clippy::too_many_arguments)] // All params are semantically distinct hash inputs
    fn compute_receipt_hash(
        from: ConfidentialityLevel,
        to: ConfidentialityLevel,
        receipt_id: &str,
        rule_id: &str,
        justification: &str,
        authority_id: &str,
        boundary_id: &str,
        payload_hash: &[u8],
        envelope_hash: &[u8],
        issued_at_ms: u64,
        expires_at_ms: u64,
    ) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        // Domain separation tag to bind this hash to receipt semantics.
        // Bumped to v3 to reflect effect-binding fields.
        hasher.update(b"apm2.declassification-receipt.v3");
        // Fixed-length fields: from and to ordinals.
        hasher.update(&[from.ordinal()]);
        hasher.update(&[to.ordinal()]);
        // Length-prefixed variable-length fields.
        Self::hash_length_prefixed(&mut hasher, receipt_id.as_bytes());
        Self::hash_length_prefixed(&mut hasher, rule_id.as_bytes());
        Self::hash_length_prefixed(&mut hasher, justification.as_bytes());
        Self::hash_length_prefixed(&mut hasher, authority_id.as_bytes());
        Self::hash_length_prefixed(&mut hasher, boundary_id.as_bytes());
        // Effect-binding fields (length-prefixed byte slices).
        Self::hash_length_prefixed(&mut hasher, payload_hash);
        Self::hash_length_prefixed(&mut hasher, envelope_hash);
        // Fixed-length timestamp fields.
        hasher.update(&issued_at_ms.to_le_bytes());
        hasher.update(&expires_at_ms.to_le_bytes());
        hasher.finalize().into()
    }

    /// Hash a byte slice with a length prefix (little-endian u64).
    fn hash_length_prefixed(hasher: &mut blake3::Hasher, data: &[u8]) {
        hasher.update(&(data.len() as u64).to_le_bytes());
        hasher.update(data);
    }

    /// Verify a receipt's content hash by recomputing it from the receipt's
    /// fields and comparing.
    ///
    /// Returns `true` if the hash matches, `false` if the receipt has been
    /// tampered with or was constructed outside the trusted path.
    fn verify_receipt_hash(receipt: &DeclassificationReceipt) -> bool {
        let expected = Self::compute_receipt_hash(
            receipt.from_level(),
            receipt.to_level(),
            receipt.receipt_id(),
            receipt.policy_ref(),
            receipt.justification(),
            receipt.authority_id(),
            receipt.boundary_id(),
            receipt.payload_hash(),
            receipt.envelope_hash(),
            receipt.issued_at_ms(),
            receipt.expires_at_ms(),
        );
        // Constant-time comparison to avoid timing side-channels.
        // Uses `subtle::ConstantTimeEq` so that comparison time is
        // independent of which byte differs.
        bool::from(expected.ct_eq(receipt.content_hash()))
    }

    /// Validate that all variable-length receipt fields are within the
    /// configured `MAX_*` size limits. This catches oversized receipts
    /// that may have been injected via deserialization.
    fn validate_receipt_field_sizes(receipt: &DeclassificationReceipt) -> Result<(), TaintError> {
        if receipt.receipt_id().len() > MAX_RECEIPT_ID_LEN {
            return Err(TaintError::ReceiptFieldSizeExceeded {
                reason: format!(
                    "receipt_id length {} exceeds maximum {MAX_RECEIPT_ID_LEN}",
                    receipt.receipt_id().len()
                ),
            });
        }
        if receipt.policy_ref().len() > MAX_POLICY_REF_LEN {
            return Err(TaintError::ReceiptFieldSizeExceeded {
                reason: format!(
                    "policy_ref length {} exceeds maximum {MAX_POLICY_REF_LEN}",
                    receipt.policy_ref().len()
                ),
            });
        }
        if receipt.justification().len() > MAX_JUSTIFICATION_LEN {
            return Err(TaintError::ReceiptFieldSizeExceeded {
                reason: format!(
                    "justification length {} exceeds maximum {MAX_JUSTIFICATION_LEN}",
                    receipt.justification().len()
                ),
            });
        }
        if receipt.authority_id().len() > MAX_AUTHORITY_ID_LEN {
            return Err(TaintError::ReceiptFieldSizeExceeded {
                reason: format!(
                    "authority_id length {} exceeds maximum {MAX_AUTHORITY_ID_LEN}",
                    receipt.authority_id().len()
                ),
            });
        }
        if receipt.boundary_id().len() > MAX_BOUNDARY_ID_LEN {
            return Err(TaintError::ReceiptFieldSizeExceeded {
                reason: format!(
                    "boundary_id length {} exceeds maximum {MAX_BOUNDARY_ID_LEN}",
                    receipt.boundary_id().len()
                ),
            });
        }
        // Effect-binding hashes must be exactly BLAKE3_DIGEST_LEN bytes.
        Self::validate_exact_hash(receipt.payload_hash(), "payload_hash")?;
        Self::validate_exact_hash(receipt.envelope_hash(), "envelope_hash")?;
        if receipt.authority_signature().len() > MAX_SIGNATURE_SIZE {
            return Err(TaintError::ReceiptFieldSizeExceeded {
                reason: format!(
                    "authority_signature length {} exceeds maximum {MAX_SIGNATURE_SIZE}",
                    receipt.authority_signature().len()
                ),
            });
        }
        Ok(())
    }

    /// Verify the receipt's authority signature using the supplied verifier.
    ///
    /// # Fail-Closed Behavior
    ///
    /// If `verifier` is `None`, the receipt is **rejected**. An attacker
    /// cannot bypass signature verification by omitting the verifier.
    fn verify_authority_signature(
        receipt: &DeclassificationReceipt,
        verifier: Option<&dyn SignatureVerifier>,
    ) -> Result<(), TaintError> {
        let verifier = verifier.ok_or_else(|| TaintError::SignatureVerificationFailed {
            reason: "no signature verifier provided (fail-closed)".to_string(),
        })?;

        if receipt.authority_signature().is_empty() {
            return Err(TaintError::SignatureVerificationFailed {
                reason: "receipt has empty authority_signature".to_string(),
            });
        }

        if !verifier.verify(
            receipt.authority_id(),
            receipt.content_hash(),
            receipt.authority_signature(),
        ) {
            return Err(TaintError::SignatureVerificationFailed {
                reason: format!(
                    "authority '{}' signature over content hash is invalid",
                    receipt.authority_id()
                ),
            });
        }

        Ok(())
    }

    /// Propagate a label through a boundary crossing **without** implicit
    /// declassification.
    ///
    /// If the label's confidentiality exceeds the boundary's clearance, the
    /// crossing is **denied** rather than silently clamped. To cross a
    /// boundary that requires a confidentiality downgrade, use
    /// [`Self::propagate_with_declassification`] with a valid receipt.
    ///
    /// # Errors
    ///
    /// - [`TaintError::BoundaryCrossingDenied`] if no boundary with the given
    ///   ID is configured (fail-closed).
    /// - [`TaintError::TaintCeilingExceeded`] if taint exceeds the boundary
    ///   ceiling.
    /// - [`TaintError::ConfidentialityFloorViolation`] if confidentiality
    ///   exceeds the boundary clearance (requires explicit declassification).
    // TODO(RFC-0020): Wire into work-object instruction flow
    pub fn propagate_through_boundary(
        &self,
        boundary_id: &str,
        label: &DataLabel,
    ) -> Result<DataLabel, TaintError> {
        let boundary = self
            .boundaries
            .iter()
            .find(|b| b.boundary_id() == boundary_id)
            .ok_or_else(|| TaintError::BoundaryCrossingDenied {
                boundary: boundary_id.to_string(),
                reason: "no boundary policy configured (fail-closed)".to_string(),
            })?;

        // Taint is checked strictly: never auto-lowered.
        if !label.taint.within_ceiling(boundary.max_taint()) {
            return Err(TaintError::TaintCeilingExceeded {
                actual: label.taint,
                max_allowed: boundary.max_taint(),
                tier: boundary.tier(),
            });
        }

        // Confidentiality is checked strictly: no implicit declassification.
        if !label
            .confidentiality
            .within_clearance(boundary.max_confidentiality())
        {
            return Err(TaintError::ConfidentialityFloorViolation {
                actual: label.confidentiality,
                max_allowed: boundary.max_confidentiality(),
                boundary: boundary_id.to_string(),
            });
        }

        Ok(*label)
    }

    /// Validate receipt lifetime, integrity, authority signature, and freshness
    /// at consumption time. Extracted to keep `propagate_with_declassification`
    /// under clippy's line limit.
    fn validate_receipt_at_consumption(
        receipt: &DeclassificationReceipt,
        boundary_id: &str,
        verifier: Option<&dyn SignatureVerifier>,
        now_ms: u64,
    ) -> Result<(), TaintError> {
        // MAX_RECEIPT_LIFETIME_MS enforcement at consumption.
        let receipt_lifetime = receipt
            .expires_at_ms()
            .saturating_sub(receipt.issued_at_ms());
        if receipt_lifetime > MAX_RECEIPT_LIFETIME_MS {
            return Err(TaintError::ReceiptExpired {
                reason: format!(
                    "receipt lifetime {receipt_lifetime}ms exceeds maximum \
                     {MAX_RECEIPT_LIFETIME_MS}ms (enforced at consumption)"
                ),
            });
        }
        if receipt.expires_at_ms() <= receipt.issued_at_ms() {
            return Err(TaintError::ReceiptExpired {
                reason: format!(
                    "receipt expires_at_ms ({}) must be strictly after issued_at_ms ({}) \
                     (enforced at consumption)",
                    receipt.expires_at_ms(),
                    receipt.issued_at_ms()
                ),
            });
        }
        // Receipt integrity verification.
        if !Self::verify_receipt_hash(receipt) {
            return Err(TaintError::BoundaryCrossingDenied {
                boundary: boundary_id.to_string(),
                reason: "receipt content hash verification failed (forged or tampered receipt)"
                    .to_string(),
            });
        }
        // Authority signature verification (fail-closed).
        Self::verify_authority_signature(receipt, verifier)?;
        // Freshness check.
        if now_ms < receipt.issued_at_ms() {
            return Err(TaintError::ReceiptExpired {
                reason: format!(
                    "current time ({now_ms}ms) is before receipt issued_at_ms ({}ms)",
                    receipt.issued_at_ms()
                ),
            });
        }
        if now_ms >= receipt.expires_at_ms() {
            return Err(TaintError::ReceiptExpired {
                reason: format!(
                    "receipt expired: current time ({now_ms}ms) >= expires_at_ms ({}ms)",
                    receipt.expires_at_ms()
                ),
            });
        }
        Ok(())
    }

    /// Verify that the receipt's effect-binding hashes match the expected
    /// values. Validates exact 32-byte BLAKE3 digest length on both the
    /// receipt's hashes and the expected hashes, then uses constant-time
    /// comparison.
    fn verify_effect_binding(
        receipt: &DeclassificationReceipt,
        expected_payload_hash: &[u8],
        expected_envelope_hash: &[u8],
    ) -> Result<(), TaintError> {
        // Enforce exact 32-byte length on the receipt's stored hashes.
        Self::validate_exact_hash(receipt.payload_hash(), "receipt payload_hash")?;
        Self::validate_exact_hash(receipt.envelope_hash(), "receipt envelope_hash")?;
        // Enforce exact 32-byte length on the caller-supplied expected hashes.
        Self::validate_exact_hash(expected_payload_hash, "expected payload_hash")?;
        Self::validate_exact_hash(expected_envelope_hash, "expected envelope_hash")?;
        if !bool::from(receipt.payload_hash().ct_eq(expected_payload_hash)) {
            return Err(TaintError::EffectBindingMismatch {
                reason: "receipt payload_hash does not match expected payload hash".to_string(),
            });
        }
        if !bool::from(receipt.envelope_hash().ct_eq(expected_envelope_hash)) {
            return Err(TaintError::EffectBindingMismatch {
                reason: "receipt envelope_hash does not match expected envelope hash".to_string(),
            });
        }
        Ok(())
    }

    /// Propagate a label through a boundary crossing with an explicit
    /// declassification receipt. Validates field sizes, lifetime, integrity,
    /// signature, freshness, anti-replay, effect binding, policy authorization,
    /// boundary scoping, and downgrade coverage.
    ///
    /// # Errors
    ///
    /// Returns the appropriate [`TaintError`] variant on any validation failure
    /// (fail-closed).
    // TODO(RFC-0020): Wire into daemon actuation path
    #[allow(clippy::too_many_arguments)]
    pub fn propagate_with_declassification(
        &mut self,
        boundary_id: &str,
        label: &DataLabel,
        receipt: &DeclassificationReceipt,
        verifier: Option<&dyn SignatureVerifier>,
        now_ms: u64,
        expected_payload_hash: &[u8],
        expected_envelope_hash: &[u8],
    ) -> Result<DataLabel, TaintError> {
        let boundary = self
            .boundaries
            .iter()
            .find(|b| b.boundary_id() == boundary_id)
            .ok_or_else(|| TaintError::BoundaryCrossingDenied {
                boundary: boundary_id.to_string(),
                reason: "no boundary policy configured (fail-closed)".to_string(),
            })?;

        // ---- Receipt field-size validation (MAJOR fix) ----
        // Re-validate field sizes at consumption time to reject oversized
        // receipts that may have been crafted via deserialization.
        Self::validate_receipt_field_sizes(receipt)?;

        // Validate receipt lifetime, integrity, signature, freshness.
        Self::validate_receipt_at_consumption(receipt, boundary_id, verifier, now_ms)?;

        // ---- Anti-replay: one-time consumption check ----
        if self.consumed_receipts.contains_key(receipt.receipt_id()) {
            return Err(TaintError::ReceiptAlreadyConsumed {
                receipt_id: receipt.receipt_id().to_string(),
            });
        }
        // Evict expired entries before checking capacity, so that the
        // anti-replay set does not fill up permanently with stale entries.
        Self::evict_expired_receipts(&mut self.consumed_receipts, now_ms);
        if self.consumed_receipts.len() >= MAX_CONSUMED_RECEIPTS {
            return Err(TaintError::ConsumedReceiptSetFull {
                capacity: MAX_CONSUMED_RECEIPTS,
            });
        }

        // ---- Effect-binding verification ----
        Self::verify_effect_binding(receipt, expected_payload_hash, expected_envelope_hash)?;

        // Verify that the receipt's policy_ref maps to an active declassification
        //    rule that authorizes the from -> to transition. This prevents attackers
        //    from crafting receipts referencing nonexistent or unauthorized policy
        //    rules.
        let has_authorizing_rule = self.declassification_rules.iter().any(|r| {
            r.rule_id() == receipt.policy_ref()
                && r.allows(receipt.from_level(), receipt.to_level())
        });
        if !has_authorizing_rule {
            return Err(TaintError::BoundaryCrossingDenied {
                boundary: boundary_id.to_string(),
                reason: format!(
                    "receipt policy_ref '{}' does not map to an active rule authorizing \
                     {} -> {} (fail-closed)",
                    receipt.policy_ref(),
                    receipt.from_level(),
                    receipt.to_level()
                ),
            });
        }

        // ---- Standard boundary checks ----

        // Taint is checked strictly: never auto-lowered.
        if !label.taint.within_ceiling(boundary.max_taint()) {
            return Err(TaintError::TaintCeilingExceeded {
                actual: label.taint,
                max_allowed: boundary.max_taint(),
                tier: boundary.tier(),
            });
        }

        // Validate that the receipt is scoped to this boundary.
        if receipt.boundary_id() != boundary_id {
            return Err(TaintError::BoundaryCrossingDenied {
                boundary: boundary_id.to_string(),
                reason: format!(
                    "receipt is scoped to boundary '{}', not '{boundary_id}'",
                    receipt.boundary_id()
                ),
            });
        }

        // If confidentiality already fits, pass through unchanged.
        // Note: receipt is still fully validated above even in this case.
        // The receipt is consumed to prevent replay.
        if label
            .confidentiality
            .within_clearance(boundary.max_confidentiality())
        {
            self.consumed_receipts
                .insert(receipt.receipt_id().to_string(), receipt.expires_at_ms());
            return Ok(*label);
        }

        // Validate that the receipt covers the required downgrade range:
        // from_level must be >= label.confidentiality (covers the source),
        // to_level must be <= boundary.max_confidentiality (reaches the target).
        if receipt.from_level() < label.confidentiality {
            return Err(TaintError::BoundaryCrossingDenied {
                boundary: boundary_id.to_string(),
                reason: format!(
                    "receipt from_level ({}) does not cover label confidentiality ({})",
                    receipt.from_level(),
                    label.confidentiality
                ),
            });
        }

        if !receipt
            .to_level()
            .within_clearance(boundary.max_confidentiality())
        {
            return Err(TaintError::BoundaryCrossingDenied {
                boundary: boundary_id.to_string(),
                reason: format!(
                    "receipt to_level ({}) exceeds boundary max_confidentiality ({})",
                    receipt.to_level(),
                    boundary.max_confidentiality()
                ),
            });
        }

        // ---- Mark receipt as consumed (anti-replay) ----
        // Insert into the consumed map AFTER all validation passes but
        // BEFORE returning success, so a failed validation does not
        // consume the receipt.
        self.consumed_receipts
            .insert(receipt.receipt_id().to_string(), receipt.expires_at_ms());

        // Apply the declassification: set confidentiality to the receipt's
        // target level.
        Ok(DataLabel::new(label.taint, receipt.to_level()))
    }

    /// Returns the configured boundaries.
    #[must_use]
    pub fn boundaries(&self) -> &[BoundaryPolicy] {
        &self.boundaries
    }

    /// Returns the configured declassification rules.
    #[must_use]
    pub fn declassification_rules(&self) -> &[DeclassificationPolicy] {
        &self.declassification_rules
    }
}

impl Default for DualLatticePolicy {
    fn default() -> Self {
        Self::deny_all()
    }
}

impl DualLatticePolicy {
    /// Returns the number of consumed receipt IDs currently tracked.
    #[must_use]
    pub fn consumed_receipt_count(&self) -> usize {
        self.consumed_receipts.len()
    }

    /// Evict consumed receipt entries whose `expires_at_ms` has passed.
    ///
    /// Called before checking capacity to ensure the anti-replay set does
    /// not fill up permanently with stale entries. An expired receipt can
    /// never be validly reused (the freshness check rejects it), so
    /// removing it from the anti-replay map is safe.
    fn evict_expired_receipts(map: &mut HashMap<String, u64>, now_ms: u64) {
        map.retain(|_id, expires_at_ms| *expires_at_ms > now_ms);
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // Test helpers
    // =========================================================================

    /// A test signature verifier that accepts any signature whose first byte
    /// matches 0xAA (our "valid" marker) and rejects everything else.
    #[derive(Debug)]
    struct TestVerifier;

    impl SignatureVerifier for TestVerifier {
        fn verify(&self, _authority_id: &str, _message: &[u8], signature: &[u8]) -> bool {
            // Accept signatures that start with 0xAA as "valid".
            signature.first() == Some(&0xAA)
        }
    }

    /// A dummy "valid" signature for test receipts.
    const VALID_TEST_SIG: &[u8] = &[0xAA, 0x01, 0x02, 0x03];

    /// A dummy "invalid" signature for test receipts.
    const INVALID_TEST_SIG: &[u8] = &[0xBB, 0x01, 0x02, 0x03];

    /// Test issuance timestamp (arbitrary fixed value for deterministic tests).
    const TEST_ISSUED_AT_MS: u64 = 1_700_000_000_000;

    /// Test expiry timestamp (1 hour after issuance, within
    /// `MAX_RECEIPT_LIFETIME_MS`).
    const TEST_EXPIRES_AT_MS: u64 = TEST_ISSUED_AT_MS + 3_600_000;

    /// Test "now" timestamp (midway in the validity window).
    const TEST_NOW_MS: u64 = TEST_ISSUED_AT_MS + 1_800_000;

    /// Test payload hash for effect binding.
    const TEST_PAYLOAD_HASH: &[u8] = b"test-payload-hash-32bytes-padded";

    /// Test envelope hash for effect binding.
    const TEST_ENVELOPE_HASH: &[u8] = b"test-envelope-hash-32bytes-pad00";

    /// Atomic counter for generating unique receipt IDs in tests.
    fn unique_receipt_id() -> String {
        use std::sync::atomic::{AtomicU64, Ordering};
        static CTR: AtomicU64 = AtomicU64::new(0);
        format!("test-receipt-{}", CTR.fetch_add(1, Ordering::Relaxed))
    }

    // =========================================================================
    // TaintLevel lattice tests
    // =========================================================================

    #[test]
    fn taint_join_is_commutative() {
        for a in 0..=4u8 {
            for b in 0..=4u8 {
                let la = TaintLevel::from_ordinal(a).unwrap();
                let lb = TaintLevel::from_ordinal(b).unwrap();
                assert_eq!(
                    la.join(lb),
                    lb.join(la),
                    "join({la}, {lb}) != join({lb}, {la})"
                );
            }
        }
    }

    #[test]
    fn taint_join_is_associative() {
        for a in 0..=4u8 {
            for b in 0..=4u8 {
                for c in 0..=4u8 {
                    let la = TaintLevel::from_ordinal(a).unwrap();
                    let lb = TaintLevel::from_ordinal(b).unwrap();
                    let lc = TaintLevel::from_ordinal(c).unwrap();
                    assert_eq!(
                        la.join(lb).join(lc),
                        la.join(lb.join(lc)),
                        "join not associative for ({la}, {lb}, {lc})"
                    );
                }
            }
        }
    }

    #[test]
    fn taint_join_is_idempotent() {
        for a in 0..=4u8 {
            let la = TaintLevel::from_ordinal(a).unwrap();
            assert_eq!(la.join(la), la, "join({la}, {la}) != {la}");
        }
    }

    #[test]
    fn taint_join_selects_higher() {
        assert_eq!(
            TaintLevel::Untainted.join(TaintLevel::HighTaint),
            TaintLevel::HighTaint
        );
        assert_eq!(
            TaintLevel::LowTaint.join(TaintLevel::MediumTaint),
            TaintLevel::MediumTaint
        );
        assert_eq!(
            TaintLevel::Toxic.join(TaintLevel::Untainted),
            TaintLevel::Toxic
        );
    }

    #[test]
    fn taint_within_ceiling() {
        assert!(TaintLevel::Untainted.within_ceiling(TaintLevel::LowTaint));
        assert!(TaintLevel::LowTaint.within_ceiling(TaintLevel::LowTaint));
        assert!(!TaintLevel::MediumTaint.within_ceiling(TaintLevel::LowTaint));
        assert!(!TaintLevel::Toxic.within_ceiling(TaintLevel::HighTaint));
    }

    #[test]
    fn taint_from_ordinal_roundtrip() {
        for v in 0..=4u8 {
            let level = TaintLevel::from_ordinal(v).unwrap();
            assert_eq!(level.ordinal(), v);
        }
        assert!(TaintLevel::from_ordinal(5).is_none());
        assert!(TaintLevel::from_ordinal(255).is_none());
    }

    #[test]
    fn taint_ordering() {
        assert!(TaintLevel::Untainted < TaintLevel::LowTaint);
        assert!(TaintLevel::LowTaint < TaintLevel::MediumTaint);
        assert!(TaintLevel::MediumTaint < TaintLevel::HighTaint);
        assert!(TaintLevel::HighTaint < TaintLevel::Toxic);
    }

    #[test]
    fn taint_default_is_untainted() {
        assert_eq!(TaintLevel::default(), TaintLevel::Untainted);
    }

    #[test]
    fn taint_display() {
        assert_eq!(TaintLevel::Untainted.to_string(), "Untainted");
        assert_eq!(TaintLevel::Toxic.to_string(), "Toxic");
    }

    // =========================================================================
    // ConfidentialityLevel lattice tests
    // =========================================================================

    #[test]
    fn conf_meet_is_commutative() {
        for a in 0..=4u8 {
            for b in 0..=4u8 {
                let la = ConfidentialityLevel::from_ordinal(a).unwrap();
                let lb = ConfidentialityLevel::from_ordinal(b).unwrap();
                assert_eq!(
                    la.meet(lb),
                    lb.meet(la),
                    "meet({la}, {lb}) != meet({lb}, {la})"
                );
            }
        }
    }

    #[test]
    fn conf_meet_is_associative() {
        for a in 0..=4u8 {
            for b in 0..=4u8 {
                for c in 0..=4u8 {
                    let la = ConfidentialityLevel::from_ordinal(a).unwrap();
                    let lb = ConfidentialityLevel::from_ordinal(b).unwrap();
                    let lc = ConfidentialityLevel::from_ordinal(c).unwrap();
                    assert_eq!(
                        la.meet(lb).meet(lc),
                        la.meet(lb.meet(lc)),
                        "meet not associative for ({la}, {lb}, {lc})"
                    );
                }
            }
        }
    }

    #[test]
    fn conf_meet_is_idempotent() {
        for a in 0..=4u8 {
            let la = ConfidentialityLevel::from_ordinal(a).unwrap();
            assert_eq!(la.meet(la), la, "meet({la}, {la}) != {la}");
        }
    }

    #[test]
    fn conf_meet_selects_lower() {
        assert_eq!(
            ConfidentialityLevel::Secret.meet(ConfidentialityLevel::Public),
            ConfidentialityLevel::Public
        );
        assert_eq!(
            ConfidentialityLevel::TopSecret.meet(ConfidentialityLevel::Internal),
            ConfidentialityLevel::Internal
        );
    }

    #[test]
    fn conf_join_selects_higher() {
        assert_eq!(
            ConfidentialityLevel::Public.join(ConfidentialityLevel::Secret),
            ConfidentialityLevel::Secret
        );
        assert_eq!(
            ConfidentialityLevel::Internal.join(ConfidentialityLevel::Confidential),
            ConfidentialityLevel::Confidential
        );
    }

    #[test]
    fn conf_join_is_commutative() {
        for a in 0..=4u8 {
            for b in 0..=4u8 {
                let la = ConfidentialityLevel::from_ordinal(a).unwrap();
                let lb = ConfidentialityLevel::from_ordinal(b).unwrap();
                assert_eq!(la.join(lb), lb.join(la));
            }
        }
    }

    #[test]
    fn conf_within_clearance() {
        assert!(ConfidentialityLevel::Public.within_clearance(ConfidentialityLevel::Internal));
        assert!(ConfidentialityLevel::Secret.within_clearance(ConfidentialityLevel::Secret));
        assert!(!ConfidentialityLevel::TopSecret.within_clearance(ConfidentialityLevel::Secret));
    }

    #[test]
    fn conf_from_ordinal_roundtrip() {
        for v in 0..=4u8 {
            let level = ConfidentialityLevel::from_ordinal(v).unwrap();
            assert_eq!(level.ordinal(), v);
        }
        assert!(ConfidentialityLevel::from_ordinal(5).is_none());
    }

    #[test]
    fn conf_ordering() {
        assert!(ConfidentialityLevel::Public < ConfidentialityLevel::Internal);
        assert!(ConfidentialityLevel::Internal < ConfidentialityLevel::Confidential);
        assert!(ConfidentialityLevel::Confidential < ConfidentialityLevel::Secret);
        assert!(ConfidentialityLevel::Secret < ConfidentialityLevel::TopSecret);
    }

    #[test]
    fn conf_default_is_public() {
        assert_eq!(
            ConfidentialityLevel::default(),
            ConfidentialityLevel::Public
        );
    }

    #[test]
    fn conf_display() {
        assert_eq!(ConfidentialityLevel::Public.to_string(), "Public");
        assert_eq!(ConfidentialityLevel::TopSecret.to_string(), "TopSecret");
    }

    // =========================================================================
    // DataLabel tests
    // =========================================================================

    #[test]
    fn data_label_join_propagates_both() {
        let a = DataLabel::new(TaintLevel::LowTaint, ConfidentialityLevel::Internal);
        let b = DataLabel::new(TaintLevel::HighTaint, ConfidentialityLevel::Secret);
        let joined = a.join(b);
        assert_eq!(joined.taint, TaintLevel::HighTaint);
        assert_eq!(joined.confidentiality, ConfidentialityLevel::Secret);
    }

    #[test]
    fn data_label_join_is_commutative() {
        let a = DataLabel::new(TaintLevel::MediumTaint, ConfidentialityLevel::Confidential);
        let b = DataLabel::new(TaintLevel::LowTaint, ConfidentialityLevel::TopSecret);
        assert_eq!(a.join(b), b.join(a));
    }

    #[test]
    fn data_label_trusted_public() {
        let label = DataLabel::TRUSTED_PUBLIC;
        assert_eq!(label.taint, TaintLevel::Untainted);
        assert_eq!(label.confidentiality, ConfidentialityLevel::Public);
    }

    #[test]
    fn data_label_display() {
        let label = DataLabel::new(TaintLevel::LowTaint, ConfidentialityLevel::Secret);
        assert_eq!(label.to_string(), "[taint=LowTaint, conf=Secret]");
    }

    #[test]
    fn data_label_default() {
        assert_eq!(DataLabel::default(), DataLabel::TRUSTED_PUBLIC);
    }

    // =========================================================================
    // BoundaryPolicy tests
    // =========================================================================

    #[test]
    fn boundary_allows_clean_data() {
        let boundary = BoundaryPolicy::new(
            "actuator-input",
            TaintLevel::LowTaint,
            ConfidentialityLevel::Internal,
            3,
        )
        .unwrap();

        let label = DataLabel::new(TaintLevel::Untainted, ConfidentialityLevel::Public);
        assert!(boundary.check(&label).is_ok());
    }

    #[test]
    fn boundary_rejects_high_taint() {
        let boundary = BoundaryPolicy::new(
            "actuator-input",
            TaintLevel::LowTaint,
            ConfidentialityLevel::Internal,
            3,
        )
        .unwrap();

        let label = DataLabel::new(TaintLevel::HighTaint, ConfidentialityLevel::Public);
        let err = boundary.check(&label).unwrap_err();
        assert!(matches!(
            err,
            TaintError::TaintCeilingExceeded { tier: 3, .. }
        ));
    }

    #[test]
    fn boundary_rejects_high_confidentiality() {
        let boundary = BoundaryPolicy::new(
            "external-api",
            TaintLevel::Toxic,
            ConfidentialityLevel::Internal,
            0,
        )
        .unwrap();

        let label = DataLabel::new(TaintLevel::Untainted, ConfidentialityLevel::Secret);
        let err = boundary.check(&label).unwrap_err();
        assert!(matches!(
            err,
            TaintError::ConfidentialityFloorViolation { .. }
        ));
    }

    #[test]
    fn boundary_at_exact_limits() {
        let boundary = BoundaryPolicy::new(
            "edge",
            TaintLevel::MediumTaint,
            ConfidentialityLevel::Confidential,
            2,
        )
        .unwrap();

        let label = DataLabel::new(TaintLevel::MediumTaint, ConfidentialityLevel::Confidential);
        assert!(boundary.check(&label).is_ok());
    }

    #[test]
    fn boundary_rejects_empty_id() {
        let err = BoundaryPolicy::new("", TaintLevel::Untainted, ConfidentialityLevel::Public, 0)
            .unwrap_err();
        assert!(matches!(err, TaintError::InvalidPolicyRef { .. }));
    }

    #[test]
    fn boundary_rejects_long_id() {
        let long_id = "x".repeat(MAX_BOUNDARY_ID_LEN + 1);
        let err = BoundaryPolicy::new(
            &long_id,
            TaintLevel::Untainted,
            ConfidentialityLevel::Public,
            0,
        )
        .unwrap_err();
        assert!(matches!(err, TaintError::InvalidPolicyRef { .. }));
    }

    // =========================================================================
    // DeclassificationPolicy tests
    // =========================================================================

    #[test]
    fn declass_policy_valid() {
        let policy = DeclassificationPolicy::new(
            "DECLASS-001",
            ConfidentialityLevel::Secret,
            ConfidentialityLevel::Internal,
        );
        assert!(policy.is_ok());
    }

    #[test]
    fn declass_policy_rejects_non_decreasing() {
        let err = DeclassificationPolicy::new(
            "DECLASS-BAD",
            ConfidentialityLevel::Internal,
            ConfidentialityLevel::Secret,
        )
        .unwrap_err();
        assert!(matches!(err, TaintError::InvalidPolicyRef { .. }));
    }

    #[test]
    fn declass_policy_rejects_equal() {
        let err = DeclassificationPolicy::new(
            "DECLASS-EQ",
            ConfidentialityLevel::Secret,
            ConfidentialityLevel::Secret,
        )
        .unwrap_err();
        assert!(matches!(err, TaintError::InvalidPolicyRef { .. }));
    }

    #[test]
    fn declass_policy_rejects_empty_id() {
        let err = DeclassificationPolicy::new(
            "",
            ConfidentialityLevel::Secret,
            ConfidentialityLevel::Public,
        )
        .unwrap_err();
        assert!(matches!(err, TaintError::InvalidPolicyRef { .. }));
    }

    #[test]
    fn declass_policy_allows_check() {
        let policy = DeclassificationPolicy::new(
            "DECLASS-001",
            ConfidentialityLevel::Secret,
            ConfidentialityLevel::Internal,
        )
        .unwrap();

        assert!(policy.allows(ConfidentialityLevel::Secret, ConfidentialityLevel::Internal));
        assert!(policy.allows(
            ConfidentialityLevel::Confidential,
            ConfidentialityLevel::Internal
        ));
        // Cannot declassify below min_to.
        assert!(!policy.allows(ConfidentialityLevel::Secret, ConfidentialityLevel::Public));
        // Cannot declassify above max_from.
        assert!(!policy.allows(
            ConfidentialityLevel::TopSecret,
            ConfidentialityLevel::Internal
        ));
        // Not a downgrade.
        assert!(!policy.allows(ConfidentialityLevel::Internal, ConfidentialityLevel::Secret));
    }

    // =========================================================================
    // DualLatticePolicy boundary crossing tests
    // =========================================================================

    fn test_policy() -> DualLatticePolicy {
        let boundaries = vec![
            BoundaryPolicy::new(
                "tier3-actuator",
                TaintLevel::LowTaint,
                ConfidentialityLevel::Internal,
                3,
            )
            .unwrap(),
            BoundaryPolicy::new(
                "tier4-actuator",
                TaintLevel::Untainted,
                ConfidentialityLevel::Public,
                4,
            )
            .unwrap(),
            BoundaryPolicy::new(
                "external-api",
                TaintLevel::MediumTaint,
                ConfidentialityLevel::Internal,
                0,
            )
            .unwrap(),
        ];

        let declass_rules = vec![
            DeclassificationPolicy::new(
                "DECLASS-SECRET-TO-INTERNAL",
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Internal,
            )
            .unwrap(),
            DeclassificationPolicy::new(
                "DECLASS-INTERNAL-TO-PUBLIC",
                ConfidentialityLevel::Internal,
                ConfidentialityLevel::Public,
            )
            .unwrap(),
        ];

        DualLatticePolicy::new(boundaries, declass_rules).unwrap()
    }

    #[test]
    fn dual_policy_tier3_allows_clean_input() {
        let policy = test_policy();
        let label = DataLabel::new(TaintLevel::Untainted, ConfidentialityLevel::Public);
        assert!(policy.check_boundary("tier3-actuator", &label).is_ok());
    }

    #[test]
    fn dual_policy_tier3_rejects_high_taint() {
        let policy = test_policy();
        let label = DataLabel::new(TaintLevel::HighTaint, ConfidentialityLevel::Public);
        let err = policy.check_boundary("tier3-actuator", &label).unwrap_err();
        assert!(matches!(
            err,
            TaintError::TaintCeilingExceeded { tier: 3, .. }
        ));
    }

    #[test]
    fn dual_policy_tier3_rejects_over_confidential() {
        let policy = test_policy();
        let label = DataLabel::new(TaintLevel::Untainted, ConfidentialityLevel::Secret);
        let err = policy.check_boundary("tier3-actuator", &label).unwrap_err();
        assert!(matches!(
            err,
            TaintError::ConfidentialityFloorViolation { .. }
        ));
    }

    #[test]
    fn dual_policy_tier4_most_restrictive() {
        let policy = test_policy();

        // Only untainted + public passes tier4.
        let good = DataLabel::new(TaintLevel::Untainted, ConfidentialityLevel::Public);
        assert!(policy.check_boundary("tier4-actuator", &good).is_ok());

        // LowTaint fails tier4.
        let tainted = DataLabel::new(TaintLevel::LowTaint, ConfidentialityLevel::Public);
        assert!(policy.check_boundary("tier4-actuator", &tainted).is_err());

        // Internal fails tier4.
        let internal = DataLabel::new(TaintLevel::Untainted, ConfidentialityLevel::Internal);
        assert!(policy.check_boundary("tier4-actuator", &internal).is_err());
    }

    #[test]
    fn dual_policy_unknown_boundary_fails_closed() {
        let policy = test_policy();
        let label = DataLabel::TRUSTED_PUBLIC;
        let err = policy.check_boundary("nonexistent", &label).unwrap_err();
        assert!(matches!(err, TaintError::BoundaryCrossingDenied { .. }));
    }

    #[test]
    fn dual_policy_deny_all_rejects_everything() {
        let policy = DualLatticePolicy::deny_all();
        let label = DataLabel::TRUSTED_PUBLIC;
        assert!(policy.check_boundary("anything", &label).is_err());
    }

    // =========================================================================
    // Actuator tier enforcement tests
    // =========================================================================

    #[test]
    fn actuator_tier3_enforced() {
        let policy = test_policy();

        let clean = DataLabel::new(TaintLevel::LowTaint, ConfidentialityLevel::Internal);
        assert!(policy.check_actuator_tier(3, &clean).is_ok());

        let dirty = DataLabel::new(TaintLevel::MediumTaint, ConfidentialityLevel::Public);
        assert!(policy.check_actuator_tier(3, &dirty).is_err());
    }

    #[test]
    fn actuator_tier4_strictest() {
        let policy = test_policy();

        let clean = DataLabel::new(TaintLevel::Untainted, ConfidentialityLevel::Public);
        assert!(policy.check_actuator_tier(4, &clean).is_ok());

        let any_taint = DataLabel::new(TaintLevel::LowTaint, ConfidentialityLevel::Public);
        assert!(policy.check_actuator_tier(4, &any_taint).is_err());
    }

    #[test]
    fn actuator_unconfigured_tier3_fails_closed() {
        let policy = DualLatticePolicy::new(vec![], vec![]).unwrap();
        let label = DataLabel::TRUSTED_PUBLIC;
        assert!(policy.check_actuator_tier(3, &label).is_err());
    }

    #[test]
    fn actuator_tier_below_3_passes_without_boundary() {
        // Tiers below 3 do not require boundary policies.
        let policy = DualLatticePolicy::new(vec![], vec![]).unwrap();
        let label = DataLabel::new(TaintLevel::Toxic, ConfidentialityLevel::TopSecret);
        assert!(policy.check_actuator_tier(1, &label).is_ok());
        assert!(policy.check_actuator_tier(2, &label).is_ok());
    }

    // =========================================================================
    // Declassification tests
    // =========================================================================

    #[test]
    fn declassification_produces_receipt() {
        let policy = test_policy();
        let receipt = policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Internal,
                &unique_receipt_id(),
                "DECLASS-SECRET-TO-INTERNAL",
                "Approved by security review SR-2026-042",
                "security-officer-1",
                "external-api",
                TEST_PAYLOAD_HASH,
                TEST_ENVELOPE_HASH,
                VALID_TEST_SIG,
                TEST_ISSUED_AT_MS,
                TEST_EXPIRES_AT_MS,
            )
            .unwrap();

        assert_eq!(receipt.from_level(), ConfidentialityLevel::Secret);
        assert_eq!(receipt.to_level(), ConfidentialityLevel::Internal);
        assert_eq!(receipt.policy_ref(), "DECLASS-SECRET-TO-INTERNAL");
        assert_eq!(
            receipt.justification(),
            "Approved by security review SR-2026-042"
        );
        assert_eq!(receipt.authority_id(), "security-officer-1");
        assert_eq!(receipt.boundary_id(), "external-api");
        assert!(!receipt.content_hash_hex().is_empty());
        assert_eq!(receipt.content_hash_hex().len(), 64); // 32 bytes hex
    }

    #[test]
    fn declassification_receipt_hash_is_deterministic() {
        let policy = test_policy();
        // Use the same receipt_id for both calls to prove determinism.
        let same_rid = "deterministic-receipt-id";
        let r1 = policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Internal,
                same_rid,
                "DECLASS-SECRET-TO-INTERNAL",
                "same justification",
                "authority-1",
                "external-api",
                TEST_PAYLOAD_HASH,
                TEST_ENVELOPE_HASH,
                VALID_TEST_SIG,
                TEST_ISSUED_AT_MS,
                TEST_EXPIRES_AT_MS,
            )
            .unwrap();
        let r2 = policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Internal,
                same_rid,
                "DECLASS-SECRET-TO-INTERNAL",
                "same justification",
                "authority-1",
                "external-api",
                TEST_PAYLOAD_HASH,
                TEST_ENVELOPE_HASH,
                VALID_TEST_SIG,
                TEST_ISSUED_AT_MS,
                TEST_EXPIRES_AT_MS,
            )
            .unwrap();
        assert_eq!(r1.content_hash(), r2.content_hash());
    }

    #[test]
    fn declassification_receipt_hash_varies_with_justification() {
        let policy = test_policy();
        let r1 = policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Internal,
                &unique_receipt_id(),
                "DECLASS-SECRET-TO-INTERNAL",
                "justification A",
                "authority-1",
                "external-api",
                TEST_PAYLOAD_HASH,
                TEST_ENVELOPE_HASH,
                VALID_TEST_SIG,
                TEST_ISSUED_AT_MS,
                TEST_EXPIRES_AT_MS,
            )
            .unwrap();
        let r2 = policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Internal,
                &unique_receipt_id(),
                "DECLASS-SECRET-TO-INTERNAL",
                "justification B",
                "authority-1",
                "external-api",
                TEST_PAYLOAD_HASH,
                TEST_ENVELOPE_HASH,
                VALID_TEST_SIG,
                TEST_ISSUED_AT_MS,
                TEST_EXPIRES_AT_MS,
            )
            .unwrap();
        assert_ne!(r1.content_hash(), r2.content_hash());
    }

    #[test]
    fn declassification_receipt_hash_varies_with_authority() {
        let policy = test_policy();
        let r1 = policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Internal,
                &unique_receipt_id(),
                "DECLASS-SECRET-TO-INTERNAL",
                "same justification",
                "authority-A",
                "external-api",
                TEST_PAYLOAD_HASH,
                TEST_ENVELOPE_HASH,
                VALID_TEST_SIG,
                TEST_ISSUED_AT_MS,
                TEST_EXPIRES_AT_MS,
            )
            .unwrap();
        let r2 = policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Internal,
                &unique_receipt_id(),
                "DECLASS-SECRET-TO-INTERNAL",
                "same justification",
                "authority-B",
                "external-api",
                TEST_PAYLOAD_HASH,
                TEST_ENVELOPE_HASH,
                VALID_TEST_SIG,
                TEST_ISSUED_AT_MS,
                TEST_EXPIRES_AT_MS,
            )
            .unwrap();
        assert_ne!(r1.content_hash(), r2.content_hash());
    }

    #[test]
    fn declassification_receipt_hash_varies_with_boundary() {
        let policy = test_policy();
        let r1 = policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Internal,
                &unique_receipt_id(),
                "DECLASS-SECRET-TO-INTERNAL",
                "same justification",
                "authority-1",
                "external-api",
                TEST_PAYLOAD_HASH,
                TEST_ENVELOPE_HASH,
                VALID_TEST_SIG,
                TEST_ISSUED_AT_MS,
                TEST_EXPIRES_AT_MS,
            )
            .unwrap();
        let r2 = policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Internal,
                &unique_receipt_id(),
                "DECLASS-SECRET-TO-INTERNAL",
                "same justification",
                "authority-1",
                "tier3-actuator",
                TEST_PAYLOAD_HASH,
                TEST_ENVELOPE_HASH,
                VALID_TEST_SIG,
                TEST_ISSUED_AT_MS,
                TEST_EXPIRES_AT_MS,
            )
            .unwrap();
        assert_ne!(r1.content_hash(), r2.content_hash());
    }

    #[test]
    fn declassification_denied_without_matching_rule() {
        let policy = test_policy();
        let err = policy
            .declassify(
                ConfidentialityLevel::TopSecret,
                ConfidentialityLevel::Public,
                &unique_receipt_id(),
                "DECLASS-SECRET-TO-INTERNAL",
                "trying to leak",
                "authority-1",
                "external-api",
                TEST_PAYLOAD_HASH,
                TEST_ENVELOPE_HASH,
                VALID_TEST_SIG,
                TEST_ISSUED_AT_MS,
                TEST_EXPIRES_AT_MS,
            )
            .unwrap_err();
        assert!(matches!(err, TaintError::DeclassificationDenied { .. }));
    }

    #[test]
    fn declassification_denied_wrong_rule_id() {
        let policy = test_policy();
        let err = policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Internal,
                &unique_receipt_id(),
                "NONEXISTENT-RULE",
                "no such rule",
                "authority-1",
                "external-api",
                TEST_PAYLOAD_HASH,
                TEST_ENVELOPE_HASH,
                VALID_TEST_SIG,
                TEST_ISSUED_AT_MS,
                TEST_EXPIRES_AT_MS,
            )
            .unwrap_err();
        assert!(matches!(err, TaintError::DeclassificationDenied { .. }));
    }

    #[test]
    fn declassification_denied_not_a_downgrade() {
        let policy = test_policy();
        let err = policy
            .declassify(
                ConfidentialityLevel::Public,
                ConfidentialityLevel::Secret,
                &unique_receipt_id(),
                "DECLASS-SECRET-TO-INTERNAL",
                "upgrade attempt",
                "authority-1",
                "external-api",
                TEST_PAYLOAD_HASH,
                TEST_ENVELOPE_HASH,
                VALID_TEST_SIG,
                TEST_ISSUED_AT_MS,
                TEST_EXPIRES_AT_MS,
            )
            .unwrap_err();
        assert!(matches!(err, TaintError::DeclassificationDenied { .. }));
    }

    #[test]
    fn declassification_denied_same_level() {
        let policy = test_policy();
        let err = policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Secret,
                &unique_receipt_id(),
                "DECLASS-SECRET-TO-INTERNAL",
                "no-op attempt",
                "authority-1",
                "external-api",
                TEST_PAYLOAD_HASH,
                TEST_ENVELOPE_HASH,
                VALID_TEST_SIG,
                TEST_ISSUED_AT_MS,
                TEST_EXPIRES_AT_MS,
            )
            .unwrap_err();
        assert!(matches!(err, TaintError::DeclassificationDenied { .. }));
    }

    #[test]
    fn declassification_denied_empty_policy_ref() {
        let policy = test_policy();
        let err = policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Internal,
                &unique_receipt_id(),
                "",
                "missing ref",
                "authority-1",
                "external-api",
                TEST_PAYLOAD_HASH,
                TEST_ENVELOPE_HASH,
                VALID_TEST_SIG,
                TEST_ISSUED_AT_MS,
                TEST_EXPIRES_AT_MS,
            )
            .unwrap_err();
        assert!(matches!(err, TaintError::InvalidPolicyRef { .. }));
    }

    #[test]
    fn declassification_denied_long_justification() {
        let policy = test_policy();
        let long_just = "x".repeat(MAX_JUSTIFICATION_LEN + 1);
        let err = policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Internal,
                &unique_receipt_id(),
                "DECLASS-SECRET-TO-INTERNAL",
                &long_just,
                "authority-1",
                "external-api",
                TEST_PAYLOAD_HASH,
                TEST_ENVELOPE_HASH,
                VALID_TEST_SIG,
                TEST_ISSUED_AT_MS,
                TEST_EXPIRES_AT_MS,
            )
            .unwrap_err();
        assert!(matches!(err, TaintError::InvalidPolicyRef { .. }));
    }

    #[test]
    fn declassification_denied_empty_authority_id() {
        let policy = test_policy();
        let err = policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Internal,
                &unique_receipt_id(),
                "DECLASS-SECRET-TO-INTERNAL",
                "valid justification",
                "",
                "external-api",
                TEST_PAYLOAD_HASH,
                TEST_ENVELOPE_HASH,
                VALID_TEST_SIG,
                TEST_ISSUED_AT_MS,
                TEST_EXPIRES_AT_MS,
            )
            .unwrap_err();
        assert!(matches!(err, TaintError::InvalidPolicyRef { .. }));
    }

    #[test]
    fn declassification_denied_empty_boundary_id() {
        let policy = test_policy();
        let err = policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Internal,
                &unique_receipt_id(),
                "DECLASS-SECRET-TO-INTERNAL",
                "valid justification",
                "authority-1",
                "",
                TEST_PAYLOAD_HASH,
                TEST_ENVELOPE_HASH,
                VALID_TEST_SIG,
                TEST_ISSUED_AT_MS,
                TEST_EXPIRES_AT_MS,
            )
            .unwrap_err();
        assert!(matches!(err, TaintError::InvalidPolicyRef { .. }));
    }

    #[test]
    fn declassification_denied_long_authority_id() {
        let policy = test_policy();
        let long_auth = "x".repeat(MAX_AUTHORITY_ID_LEN + 1);
        let err = policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Internal,
                &unique_receipt_id(),
                "DECLASS-SECRET-TO-INTERNAL",
                "valid justification",
                &long_auth,
                "external-api",
                TEST_PAYLOAD_HASH,
                TEST_ENVELOPE_HASH,
                VALID_TEST_SIG,
                TEST_ISSUED_AT_MS,
                TEST_EXPIRES_AT_MS,
            )
            .unwrap_err();
        assert!(matches!(err, TaintError::InvalidPolicyRef { .. }));
    }

    #[test]
    fn declassification_denied_long_boundary_id() {
        let policy = test_policy();
        let long_bnd = "x".repeat(MAX_BOUNDARY_ID_LEN + 1);
        let err = policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Internal,
                &unique_receipt_id(),
                "DECLASS-SECRET-TO-INTERNAL",
                "valid justification",
                "authority-1",
                &long_bnd,
                TEST_PAYLOAD_HASH,
                TEST_ENVELOPE_HASH,
                VALID_TEST_SIG,
                TEST_ISSUED_AT_MS,
                TEST_EXPIRES_AT_MS,
            )
            .unwrap_err();
        assert!(matches!(err, TaintError::InvalidPolicyRef { .. }));
    }

    #[test]
    fn declassification_two_step_chain() {
        // First: Secret -> Internal, then Internal -> Public
        let policy = test_policy();

        let r1 = policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Internal,
                &unique_receipt_id(),
                "DECLASS-SECRET-TO-INTERNAL",
                "step 1",
                "authority-1",
                "external-api",
                TEST_PAYLOAD_HASH,
                TEST_ENVELOPE_HASH,
                VALID_TEST_SIG,
                TEST_ISSUED_AT_MS,
                TEST_EXPIRES_AT_MS,
            )
            .unwrap();
        assert_eq!(r1.to_level(), ConfidentialityLevel::Internal);

        let r2 = policy
            .declassify(
                ConfidentialityLevel::Internal,
                ConfidentialityLevel::Public,
                &unique_receipt_id(),
                "DECLASS-INTERNAL-TO-PUBLIC",
                "step 2",
                "authority-1",
                "tier4-actuator",
                TEST_PAYLOAD_HASH,
                TEST_ENVELOPE_HASH,
                VALID_TEST_SIG,
                TEST_ISSUED_AT_MS,
                TEST_EXPIRES_AT_MS,
            )
            .unwrap();
        assert_eq!(r2.to_level(), ConfidentialityLevel::Public);
    }

    // =========================================================================
    // Boundary propagation tests
    // =========================================================================

    #[test]
    fn propagation_denies_over_confidential_without_receipt() {
        // propagate_through_boundary must DENY when confidentiality exceeds
        // the boundary's clearance. No implicit clamping allowed.
        let policy = test_policy();
        let label = DataLabel::new(TaintLevel::Untainted, ConfidentialityLevel::Secret);
        let err = policy
            .propagate_through_boundary("external-api", &label)
            .unwrap_err();
        assert!(
            matches!(err, TaintError::ConfidentialityFloorViolation { .. }),
            "expected ConfidentialityFloorViolation, got {err:?}"
        );
    }

    #[test]
    fn propagation_with_receipt_allows_declassified_crossing() {
        // With a valid receipt scoped to the correct boundary, the crossing
        // succeeds and the label's confidentiality is set to the receipt's
        // to_level.
        let mut policy = test_policy();
        let label = DataLabel::new(TaintLevel::Untainted, ConfidentialityLevel::Secret);

        let receipt = policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Internal,
                &unique_receipt_id(),
                "DECLASS-SECRET-TO-INTERNAL",
                "Approved for external release",
                "security-officer-1",
                "external-api",
                TEST_PAYLOAD_HASH,
                TEST_ENVELOPE_HASH,
                VALID_TEST_SIG,
                TEST_ISSUED_AT_MS,
                TEST_EXPIRES_AT_MS,
            )
            .unwrap();

        let result = policy
            .propagate_with_declassification(
                "external-api",
                &label,
                &receipt,
                Some(&TestVerifier),
                TEST_NOW_MS,
                TEST_PAYLOAD_HASH,
                TEST_ENVELOPE_HASH,
            )
            .unwrap();
        assert_eq!(result.taint, TaintLevel::Untainted);
        assert_eq!(result.confidentiality, ConfidentialityLevel::Internal);
    }

    #[test]
    fn propagation_with_receipt_rejects_wrong_boundary() {
        // A receipt scoped to a different boundary must be rejected.
        let mut policy = test_policy();
        let label = DataLabel::new(TaintLevel::Untainted, ConfidentialityLevel::Secret);

        // Receipt scoped to "tier3-actuator", not "external-api".
        let receipt = policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Internal,
                &unique_receipt_id(),
                "DECLASS-SECRET-TO-INTERNAL",
                "wrong boundary",
                "security-officer-1",
                "tier3-actuator",
                TEST_PAYLOAD_HASH,
                TEST_ENVELOPE_HASH,
                VALID_TEST_SIG,
                TEST_ISSUED_AT_MS,
                TEST_EXPIRES_AT_MS,
            )
            .unwrap();

        let err = policy
            .propagate_with_declassification(
                "external-api",
                &label,
                &receipt,
                Some(&TestVerifier),
                TEST_NOW_MS,
                TEST_PAYLOAD_HASH,
                TEST_ENVELOPE_HASH,
            )
            .unwrap_err();
        assert!(
            matches!(err, TaintError::BoundaryCrossingDenied { .. }),
            "expected BoundaryCrossingDenied, got {err:?}"
        );
    }

    #[test]
    fn propagation_with_receipt_passes_when_already_within_clearance() {
        // If the label is already within the boundary clearance, the receipt
        // is validated (boundary_id must still match) but the label passes
        // through unchanged.
        let mut policy = test_policy();
        let label = DataLabel::new(TaintLevel::Untainted, ConfidentialityLevel::Public);

        let receipt = policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Internal,
                &unique_receipt_id(),
                "DECLASS-SECRET-TO-INTERNAL",
                "not needed but valid",
                "security-officer-1",
                "external-api",
                TEST_PAYLOAD_HASH,
                TEST_ENVELOPE_HASH,
                VALID_TEST_SIG,
                TEST_ISSUED_AT_MS,
                TEST_EXPIRES_AT_MS,
            )
            .unwrap();

        let result = policy
            .propagate_with_declassification(
                "external-api",
                &label,
                &receipt,
                Some(&TestVerifier),
                TEST_NOW_MS,
                TEST_PAYLOAD_HASH,
                TEST_ENVELOPE_HASH,
            )
            .unwrap();
        assert_eq!(result, label);
    }

    #[test]
    fn propagation_with_receipt_rejects_insufficient_downgrade() {
        // Receipt's to_level is still above the boundary's max_confidentiality.
        let mut policy = test_policy();
        // tier4-actuator max_confidentiality = Public
        let label = DataLabel::new(TaintLevel::Untainted, ConfidentialityLevel::Secret);

        // Receipt only goes down to Internal, but tier4 requires Public.
        let receipt = policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Internal,
                &unique_receipt_id(),
                "DECLASS-SECRET-TO-INTERNAL",
                "insufficient downgrade",
                "security-officer-1",
                "tier4-actuator",
                TEST_PAYLOAD_HASH,
                TEST_ENVELOPE_HASH,
                VALID_TEST_SIG,
                TEST_ISSUED_AT_MS,
                TEST_EXPIRES_AT_MS,
            )
            .unwrap();

        let err = policy
            .propagate_with_declassification(
                "tier4-actuator",
                &label,
                &receipt,
                Some(&TestVerifier),
                TEST_NOW_MS,
                TEST_PAYLOAD_HASH,
                TEST_ENVELOPE_HASH,
            )
            .unwrap_err();
        assert!(
            matches!(err, TaintError::BoundaryCrossingDenied { .. }),
            "expected BoundaryCrossingDenied for insufficient downgrade, got {err:?}"
        );
    }

    #[test]
    fn propagation_preserves_low_confidentiality() {
        let policy = test_policy();
        let label = DataLabel::new(TaintLevel::Untainted, ConfidentialityLevel::Public);
        let result = policy
            .propagate_through_boundary("external-api", &label)
            .unwrap();
        assert_eq!(result.confidentiality, ConfidentialityLevel::Public);
    }

    #[test]
    fn propagation_rejects_taint_violation() {
        let policy = test_policy();
        let label = DataLabel::new(TaintLevel::HighTaint, ConfidentialityLevel::Public);
        let err = policy
            .propagate_through_boundary("external-api", &label)
            .unwrap_err();
        assert!(matches!(err, TaintError::TaintCeilingExceeded { .. }));
    }

    #[test]
    fn propagation_unknown_boundary_fails_closed() {
        let policy = test_policy();
        let label = DataLabel::TRUSTED_PUBLIC;
        assert!(
            policy
                .propagate_through_boundary("unknown", &label)
                .is_err()
        );
    }

    // =========================================================================
    // Secret leakage adversarial tests
    // =========================================================================

    #[test]
    fn adversarial_secret_to_external_api_blocked() {
        let policy = test_policy();
        let secret_data = DataLabel::new(TaintLevel::Untainted, ConfidentialityLevel::Secret);
        let err = policy
            .check_boundary("external-api", &secret_data)
            .unwrap_err();
        assert!(matches!(
            err,
            TaintError::ConfidentialityFloorViolation { .. }
        ));
    }

    #[test]
    fn adversarial_top_secret_to_any_boundary_blocked() {
        let policy = test_policy();
        let top_secret = DataLabel::new(TaintLevel::Untainted, ConfidentialityLevel::TopSecret);

        // TopSecret should be blocked at every configured boundary.
        for boundary in policy.boundaries() {
            assert!(
                boundary.check(&top_secret).is_err(),
                "TopSecret should be blocked at boundary '{}'",
                boundary.boundary_id()
            );
        }
    }

    #[test]
    fn adversarial_toxic_taint_blocked_at_all_tier3plus() {
        let policy = test_policy();
        let toxic = DataLabel::new(TaintLevel::Toxic, ConfidentialityLevel::Public);

        // Toxic data should be blocked at tier3 and tier4.
        assert!(policy.check_actuator_tier(3, &toxic).is_err());
        assert!(policy.check_actuator_tier(4, &toxic).is_err());
    }

    #[test]
    fn adversarial_join_elevates_both_dimensions() {
        // An adversary combining clean data with tainted+secret data
        // should produce a label that is blocked everywhere sensitive.
        let clean = DataLabel::TRUSTED_PUBLIC;
        let malicious = DataLabel::new(TaintLevel::Toxic, ConfidentialityLevel::TopSecret);
        let combined = clean.join(malicious);

        assert_eq!(combined.taint, TaintLevel::Toxic);
        assert_eq!(combined.confidentiality, ConfidentialityLevel::TopSecret);

        let policy = test_policy();
        assert!(policy.check_boundary("tier3-actuator", &combined).is_err());
        assert!(policy.check_boundary("tier4-actuator", &combined).is_err());
        assert!(policy.check_boundary("external-api", &combined).is_err());
    }

    #[test]
    fn adversarial_declassify_skip_denied() {
        // Trying to jump Secret -> Public in one step when the rule only
        // allows Secret -> Internal.
        let policy = test_policy();
        let err = policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Public,
                &unique_receipt_id(),
                "DECLASS-SECRET-TO-INTERNAL",
                "trying to skip levels",
                "authority-1",
                "external-api",
                TEST_PAYLOAD_HASH,
                TEST_ENVELOPE_HASH,
                VALID_TEST_SIG,
                TEST_ISSUED_AT_MS,
                TEST_EXPIRES_AT_MS,
            )
            .unwrap_err();
        assert!(matches!(err, TaintError::DeclassificationDenied { .. }));
    }

    #[test]
    fn adversarial_declassify_wrong_direction() {
        let policy = test_policy();
        let err = policy
            .declassify(
                ConfidentialityLevel::Internal,
                ConfidentialityLevel::TopSecret,
                &unique_receipt_id(),
                "DECLASS-SECRET-TO-INTERNAL",
                "reverse declassification attempt",
                "authority-1",
                "external-api",
                TEST_PAYLOAD_HASH,
                TEST_ENVELOPE_HASH,
                VALID_TEST_SIG,
                TEST_ISSUED_AT_MS,
                TEST_EXPIRES_AT_MS,
            )
            .unwrap_err();
        assert!(matches!(err, TaintError::DeclassificationDenied { .. }));
    }

    #[test]
    fn adversarial_propagation_does_not_lower_taint() {
        // Propagation through a boundary must never lower taint.
        let policy = test_policy();
        let label = DataLabel::new(TaintLevel::LowTaint, ConfidentialityLevel::Public);
        let result = policy
            .propagate_through_boundary("external-api", &label)
            .unwrap();
        // Taint must be preserved, not lowered.
        assert_eq!(result.taint, TaintLevel::LowTaint);
    }

    #[test]
    fn adversarial_declassify_no_rules_configured() {
        let policy = DualLatticePolicy::new(vec![], vec![]).unwrap();
        let err = policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Public,
                &unique_receipt_id(),
                "ANY-RULE",
                "no rules exist",
                "authority-1",
                "some-boundary",
                TEST_PAYLOAD_HASH,
                TEST_ENVELOPE_HASH,
                VALID_TEST_SIG,
                TEST_ISSUED_AT_MS,
                TEST_EXPIRES_AT_MS,
            )
            .unwrap_err();
        assert!(matches!(err, TaintError::DeclassificationDenied { .. }));
    }

    #[test]
    fn adversarial_propagation_denies_implicit_declassification() {
        // Verify that propagate_through_boundary never silently lowers
        // confidentiality. This is the core fix for the implicit
        // declassification vulnerability.
        let policy = test_policy();

        // Secret data must be blocked at external-api (max_conf = Internal)
        // without an explicit receipt.
        let secret = DataLabel::new(TaintLevel::Untainted, ConfidentialityLevel::Secret);
        assert!(
            policy
                .propagate_through_boundary("external-api", &secret)
                .is_err(),
            "propagation must not silently declassify"
        );

        // TopSecret data must be blocked at tier3-actuator (max_conf = Internal).
        let top_secret = DataLabel::new(TaintLevel::Untainted, ConfidentialityLevel::TopSecret);
        assert!(
            policy
                .propagate_through_boundary("tier3-actuator", &top_secret)
                .is_err(),
            "propagation must not silently declassify"
        );

        // Confidential data must be blocked at tier4-actuator (max_conf = Public).
        let confidential =
            DataLabel::new(TaintLevel::Untainted, ConfidentialityLevel::Confidential);
        assert!(
            policy
                .propagate_through_boundary("tier4-actuator", &confidential)
                .is_err(),
            "propagation must not silently declassify"
        );
    }

    // =========================================================================
    // Error display tests
    // =========================================================================

    #[test]
    fn error_display_taint_ceiling() {
        let err = TaintError::TaintCeilingExceeded {
            actual: TaintLevel::HighTaint,
            max_allowed: TaintLevel::LowTaint,
            tier: 3,
        };
        assert!(err.to_string().contains("HighTaint"));
        assert!(err.to_string().contains("LowTaint"));
        assert!(err.to_string().contains("tier 3"));
    }

    #[test]
    fn error_display_confidentiality_violation() {
        let err = TaintError::ConfidentialityFloorViolation {
            actual: ConfidentialityLevel::Secret,
            max_allowed: ConfidentialityLevel::Internal,
            boundary: "external-api".to_string(),
        };
        assert!(err.to_string().contains("Secret"));
        assert!(err.to_string().contains("Internal"));
        assert!(err.to_string().contains("external-api"));
    }

    #[test]
    fn error_display_declassification_denied() {
        let err = TaintError::DeclassificationDenied {
            from: ConfidentialityLevel::TopSecret,
            to: ConfidentialityLevel::Public,
            reason: "not authorized".to_string(),
        };
        assert!(err.to_string().contains("TopSecret"));
        assert!(err.to_string().contains("Public"));
        assert!(err.to_string().contains("not authorized"));
    }

    // =========================================================================
    // Free propagation function tests
    // =========================================================================

    #[test]
    fn propagate_taint_empty_returns_identity() {
        assert_eq!(super::propagate_taint(&[]), TaintLevel::Untainted);
    }

    #[test]
    fn propagate_taint_single() {
        assert_eq!(
            super::propagate_taint(&[TaintLevel::HighTaint]),
            TaintLevel::HighTaint
        );
    }

    #[test]
    fn propagate_taint_multiple_returns_highest() {
        let inputs = [
            TaintLevel::LowTaint,
            TaintLevel::Untainted,
            TaintLevel::MediumTaint,
            TaintLevel::LowTaint,
        ];
        assert_eq!(super::propagate_taint(&inputs), TaintLevel::MediumTaint);
    }

    #[test]
    fn propagate_taint_all_toxic() {
        let inputs = [TaintLevel::Toxic, TaintLevel::Toxic];
        assert_eq!(super::propagate_taint(&inputs), TaintLevel::Toxic);
    }

    #[test]
    fn propagate_classification_empty_returns_identity() {
        assert_eq!(
            super::propagate_classification(&[]),
            ConfidentialityLevel::Public
        );
    }

    #[test]
    fn propagate_classification_single() {
        assert_eq!(
            super::propagate_classification(&[ConfidentialityLevel::Secret]),
            ConfidentialityLevel::Secret
        );
    }

    #[test]
    fn propagate_classification_multiple_returns_highest() {
        let inputs = [
            ConfidentialityLevel::Internal,
            ConfidentialityLevel::Public,
            ConfidentialityLevel::Secret,
            ConfidentialityLevel::Confidential,
        ];
        assert_eq!(
            super::propagate_classification(&inputs),
            ConfidentialityLevel::Secret
        );
    }

    #[test]
    fn propagate_classification_all_top_secret() {
        let inputs = [
            ConfidentialityLevel::TopSecret,
            ConfidentialityLevel::TopSecret,
        ];
        assert_eq!(
            super::propagate_classification(&inputs),
            ConfidentialityLevel::TopSecret
        );
    }

    // =========================================================================
    // BLOCKER: Forged receipt adversarial tests
    // =========================================================================

    #[test]
    fn forged_receipt_wrong_content_hash_rejected() {
        // An attacker crafts a receipt via deserialization with a wrong
        // content hash. The propagation MUST reject it.
        let mut policy = test_policy();
        let label = DataLabel::new(TaintLevel::Untainted, ConfidentialityLevel::Secret);

        // Create a legitimate receipt first, then forge the hash.
        let legit = policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Internal,
                &unique_receipt_id(),
                "DECLASS-SECRET-TO-INTERNAL",
                "legitimate",
                "security-officer-1",
                "external-api",
                TEST_PAYLOAD_HASH,
                TEST_ENVELOPE_HASH,
                VALID_TEST_SIG,
                TEST_ISSUED_AT_MS,
                TEST_EXPIRES_AT_MS,
            )
            .unwrap();

        // Forge: construct via serde with a zeroed hash.
        let forged_json = serde_json::json!({
            "from_level": "Secret",
            "to_level": "Internal",
            "receipt_id": unique_receipt_id(),
            "policy_ref": legit.policy_ref(),
            "justification": "FORGED justification",
            "authority_id": legit.authority_id(),
            "boundary_id": legit.boundary_id(),
            "payload_hash": TEST_PAYLOAD_HASH,
            "envelope_hash": TEST_ENVELOPE_HASH,
            "issued_at_ms": TEST_ISSUED_AT_MS,
            "expires_at_ms": TEST_EXPIRES_AT_MS,
            "content_hash": vec![0u8; 32],
        });
        let forged: DeclassificationReceipt = serde_json::from_value(forged_json).unwrap();

        let err = policy
            .propagate_with_declassification(
                "external-api",
                &label,
                &forged,
                Some(&TestVerifier),
                TEST_NOW_MS,
                TEST_PAYLOAD_HASH,
                TEST_ENVELOPE_HASH,
            )
            .unwrap_err();
        assert!(
            matches!(err, TaintError::BoundaryCrossingDenied { .. }),
            "forged receipt with wrong hash must be rejected, got {err:?}"
        );
        assert!(
            err.to_string().contains("hash verification failed"),
            "error should mention hash verification, got: {err}"
        );
    }

    #[test]
    fn forged_receipt_tampered_fields_rejected() {
        // Attacker takes a legitimate receipt, modifies the to_level to
        // a more permissive value, but keeps the original hash.
        let mut policy = test_policy();
        let label = DataLabel::new(TaintLevel::Untainted, ConfidentialityLevel::Secret);

        let legit = policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Internal,
                &unique_receipt_id(),
                "DECLASS-SECRET-TO-INTERNAL",
                "legitimate",
                "security-officer-1",
                "external-api",
                TEST_PAYLOAD_HASH,
                TEST_ENVELOPE_HASH,
                VALID_TEST_SIG,
                TEST_ISSUED_AT_MS,
                TEST_EXPIRES_AT_MS,
            )
            .unwrap();

        // Tamper: change to_level to Public but keep the old hash.
        let tampered_json = serde_json::json!({
            "from_level": "Secret",
            "to_level": "Public",
            "receipt_id": unique_receipt_id(),
            "policy_ref": legit.policy_ref(),
            "justification": legit.justification(),
            "authority_id": legit.authority_id(),
            "boundary_id": legit.boundary_id(),
            "payload_hash": TEST_PAYLOAD_HASH,
            "envelope_hash": TEST_ENVELOPE_HASH,
            "issued_at_ms": TEST_ISSUED_AT_MS,
            "expires_at_ms": TEST_EXPIRES_AT_MS,
            "content_hash": legit.content_hash(),
        });
        let tampered: DeclassificationReceipt = serde_json::from_value(tampered_json).unwrap();

        let err = policy
            .propagate_with_declassification(
                "external-api",
                &label,
                &tampered,
                Some(&TestVerifier),
                TEST_NOW_MS,
                TEST_PAYLOAD_HASH,
                TEST_ENVELOPE_HASH,
            )
            .unwrap_err();
        assert!(
            matches!(err, TaintError::BoundaryCrossingDenied { .. }),
            "tampered receipt must be rejected, got {err:?}"
        );
    }

    #[test]
    fn forged_receipt_invalid_policy_ref_rejected() {
        // Attacker constructs a receipt with a nonexistent policy_ref
        // but correct hash. The policy_ref authorization check must reject.
        let mut policy = test_policy();
        let label = DataLabel::new(TaintLevel::Untainted, ConfidentialityLevel::Secret);

        // Compute a valid hash for a nonexistent rule.
        let forged_rid = unique_receipt_id();
        let hash = DualLatticePolicy::compute_receipt_hash(
            ConfidentialityLevel::Secret,
            ConfidentialityLevel::Internal,
            &forged_rid,
            "NONEXISTENT-RULE",
            "trying to bypass",
            "attacker",
            "external-api",
            TEST_PAYLOAD_HASH,
            TEST_ENVELOPE_HASH,
            TEST_ISSUED_AT_MS,
            TEST_EXPIRES_AT_MS,
        );

        let forged_json = serde_json::json!({
            "from_level": "Secret",
            "to_level": "Internal",
            "receipt_id": forged_rid,
            "policy_ref": "NONEXISTENT-RULE",
            "justification": "trying to bypass",
            "authority_id": "attacker",
            "boundary_id": "external-api",
            "payload_hash": TEST_PAYLOAD_HASH,
            "envelope_hash": TEST_ENVELOPE_HASH,
            "issued_at_ms": TEST_ISSUED_AT_MS,
            "expires_at_ms": TEST_EXPIRES_AT_MS,
            "content_hash": hash,
            "authority_signature": VALID_TEST_SIG,
        });
        let forged: DeclassificationReceipt = serde_json::from_value(forged_json).unwrap();

        let err = policy
            .propagate_with_declassification(
                "external-api",
                &label,
                &forged,
                Some(&TestVerifier),
                TEST_NOW_MS,
                TEST_PAYLOAD_HASH,
                TEST_ENVELOPE_HASH,
            )
            .unwrap_err();
        assert!(
            matches!(err, TaintError::BoundaryCrossingDenied { .. }),
            "receipt with invalid policy_ref must be rejected, got {err:?}"
        );
        assert!(
            err.to_string().contains("does not map to an active rule"),
            "error should mention active rule check, got: {err}"
        );
    }

    #[test]
    fn forged_receipt_unauthorized_level_transition_rejected() {
        // Receipt references a real rule but the transition is not
        // authorized by that rule (e.g., TopSecret -> Public via a
        // rule that only allows Secret -> Internal).
        let mut policy = test_policy();
        let label = DataLabel::new(TaintLevel::Untainted, ConfidentialityLevel::TopSecret);

        let forged_rid = unique_receipt_id();
        let hash = DualLatticePolicy::compute_receipt_hash(
            ConfidentialityLevel::TopSecret,
            ConfidentialityLevel::Public,
            &forged_rid,
            "DECLASS-SECRET-TO-INTERNAL",
            "level skip",
            "attacker",
            "external-api",
            TEST_PAYLOAD_HASH,
            TEST_ENVELOPE_HASH,
            TEST_ISSUED_AT_MS,
            TEST_EXPIRES_AT_MS,
        );

        let forged_json = serde_json::json!({
            "from_level": "TopSecret",
            "to_level": "Public",
            "receipt_id": forged_rid,
            "policy_ref": "DECLASS-SECRET-TO-INTERNAL",
            "justification": "level skip",
            "authority_id": "attacker",
            "boundary_id": "external-api",
            "payload_hash": TEST_PAYLOAD_HASH,
            "envelope_hash": TEST_ENVELOPE_HASH,
            "issued_at_ms": TEST_ISSUED_AT_MS,
            "expires_at_ms": TEST_EXPIRES_AT_MS,
            "content_hash": hash,
            "authority_signature": VALID_TEST_SIG,
        });
        let forged: DeclassificationReceipt = serde_json::from_value(forged_json).unwrap();

        let err = policy
            .propagate_with_declassification(
                "external-api",
                &label,
                &forged,
                Some(&TestVerifier),
                TEST_NOW_MS,
                TEST_PAYLOAD_HASH,
                TEST_ENVELOPE_HASH,
            )
            .unwrap_err();
        assert!(
            matches!(err, TaintError::BoundaryCrossingDenied { .. }),
            "unauthorized level transition must be rejected, got {err:?}"
        );
    }

    // =========================================================================
    // BLOCKER: Authority signature verification tests
    // =========================================================================

    #[test]
    fn signature_rejected_when_no_verifier_provided() {
        // Fail-closed: if no verifier is supplied, receipts must be rejected.
        let mut policy = test_policy();
        let label = DataLabel::new(TaintLevel::Untainted, ConfidentialityLevel::Secret);
        let receipt = policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Internal,
                &unique_receipt_id(),
                "DECLASS-SECRET-TO-INTERNAL",
                "valid request",
                "security-officer-1",
                "external-api",
                TEST_PAYLOAD_HASH,
                TEST_ENVELOPE_HASH,
                VALID_TEST_SIG,
                TEST_ISSUED_AT_MS,
                TEST_EXPIRES_AT_MS,
            )
            .unwrap();

        let err = policy
            .propagate_with_declassification(
                "external-api",
                &label,
                &receipt,
                None,
                TEST_NOW_MS,
                TEST_PAYLOAD_HASH,
                TEST_ENVELOPE_HASH,
            )
            .unwrap_err();
        assert!(
            matches!(err, TaintError::SignatureVerificationFailed { .. }),
            "must reject when no verifier is provided (fail-closed), got {err:?}"
        );
        assert!(
            err.to_string().contains("no signature verifier provided"),
            "error should mention missing verifier, got: {err}"
        );
    }

    #[test]
    fn signature_rejected_when_empty() {
        // Empty signature must be rejected even with a verifier.
        let mut policy = test_policy();
        let label = DataLabel::new(TaintLevel::Untainted, ConfidentialityLevel::Secret);
        let receipt = policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Internal,
                &unique_receipt_id(),
                "DECLASS-SECRET-TO-INTERNAL",
                "valid request",
                "security-officer-1",
                "external-api",
                TEST_PAYLOAD_HASH,
                TEST_ENVELOPE_HASH,
                &[], // empty signature
                TEST_ISSUED_AT_MS,
                TEST_EXPIRES_AT_MS,
            )
            .unwrap();

        let err = policy
            .propagate_with_declassification(
                "external-api",
                &label,
                &receipt,
                Some(&TestVerifier),
                TEST_NOW_MS,
                TEST_PAYLOAD_HASH,
                TEST_ENVELOPE_HASH,
            )
            .unwrap_err();
        assert!(
            matches!(err, TaintError::SignatureVerificationFailed { .. }),
            "must reject empty signature, got {err:?}"
        );
        assert!(
            err.to_string().contains("empty authority_signature"),
            "error should mention empty signature, got: {err}"
        );
    }

    #[test]
    fn signature_rejected_when_invalid() {
        // Invalid signature (wrong first byte) must be rejected.
        let mut policy = test_policy();
        let label = DataLabel::new(TaintLevel::Untainted, ConfidentialityLevel::Secret);
        let receipt = policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Internal,
                &unique_receipt_id(),
                "DECLASS-SECRET-TO-INTERNAL",
                "valid request",
                "security-officer-1",
                "external-api",
                TEST_PAYLOAD_HASH,
                TEST_ENVELOPE_HASH,
                INVALID_TEST_SIG,
                TEST_ISSUED_AT_MS,
                TEST_EXPIRES_AT_MS,
            )
            .unwrap();

        let err = policy
            .propagate_with_declassification(
                "external-api",
                &label,
                &receipt,
                Some(&TestVerifier),
                TEST_NOW_MS,
                TEST_PAYLOAD_HASH,
                TEST_ENVELOPE_HASH,
            )
            .unwrap_err();
        assert!(
            matches!(err, TaintError::SignatureVerificationFailed { .. }),
            "must reject invalid signature, got {err:?}"
        );
        assert!(
            err.to_string()
                .contains("signature over content hash is invalid"),
            "error should mention invalid signature, got: {err}"
        );
    }

    #[test]
    fn signature_accepted_when_valid() {
        // Valid signature (correct first byte) must be accepted.
        let mut policy = test_policy();
        let label = DataLabel::new(TaintLevel::Untainted, ConfidentialityLevel::Secret);
        let receipt = policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Internal,
                &unique_receipt_id(),
                "DECLASS-SECRET-TO-INTERNAL",
                "approved release",
                "security-officer-1",
                "external-api",
                TEST_PAYLOAD_HASH,
                TEST_ENVELOPE_HASH,
                VALID_TEST_SIG,
                TEST_ISSUED_AT_MS,
                TEST_EXPIRES_AT_MS,
            )
            .unwrap();

        let result = policy
            .propagate_with_declassification(
                "external-api",
                &label,
                &receipt,
                Some(&TestVerifier),
                TEST_NOW_MS,
                TEST_PAYLOAD_HASH,
                TEST_ENVELOPE_HASH,
            )
            .unwrap();
        assert_eq!(result.confidentiality, ConfidentialityLevel::Internal);
    }

    // =========================================================================
    // MAJOR: Receipt field size validation at consumption time tests
    // =========================================================================

    #[test]
    fn oversized_policy_ref_rejected_at_consumption() {
        let mut policy = test_policy();
        let label = DataLabel::new(TaintLevel::Untainted, ConfidentialityLevel::Secret);

        // Create a receipt with an oversized policy_ref via deserialization.
        let legit = policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Internal,
                &unique_receipt_id(),
                "DECLASS-SECRET-TO-INTERNAL",
                "valid",
                "authority-1",
                "external-api",
                TEST_PAYLOAD_HASH,
                TEST_ENVELOPE_HASH,
                VALID_TEST_SIG,
                TEST_ISSUED_AT_MS,
                TEST_EXPIRES_AT_MS,
            )
            .unwrap();

        let oversized_ref = "X".repeat(MAX_POLICY_REF_LEN + 1);
        let forged_json = serde_json::json!({
            "from_level": "Secret",
            "to_level": "Internal",
            "receipt_id": unique_receipt_id(),
            "policy_ref": oversized_ref,
            "justification": legit.justification(),
            "authority_id": legit.authority_id(),
            "boundary_id": legit.boundary_id(),
            "payload_hash": TEST_PAYLOAD_HASH,
            "envelope_hash": TEST_ENVELOPE_HASH,
            "issued_at_ms": TEST_ISSUED_AT_MS,
            "expires_at_ms": TEST_EXPIRES_AT_MS,
            "content_hash": legit.content_hash(),
            "authority_signature": VALID_TEST_SIG,
        });
        let forged: DeclassificationReceipt = serde_json::from_value(forged_json).unwrap();

        let err = policy
            .propagate_with_declassification(
                "external-api",
                &label,
                &forged,
                Some(&TestVerifier),
                TEST_NOW_MS,
                TEST_PAYLOAD_HASH,
                TEST_ENVELOPE_HASH,
            )
            .unwrap_err();
        assert!(
            matches!(err, TaintError::ReceiptFieldSizeExceeded { .. }),
            "oversized policy_ref must be rejected, got {err:?}"
        );
    }

    #[test]
    fn oversized_justification_rejected_at_consumption() {
        let mut policy = test_policy();
        let label = DataLabel::new(TaintLevel::Untainted, ConfidentialityLevel::Secret);

        let legit = policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Internal,
                &unique_receipt_id(),
                "DECLASS-SECRET-TO-INTERNAL",
                "valid",
                "authority-1",
                "external-api",
                TEST_PAYLOAD_HASH,
                TEST_ENVELOPE_HASH,
                VALID_TEST_SIG,
                TEST_ISSUED_AT_MS,
                TEST_EXPIRES_AT_MS,
            )
            .unwrap();

        let oversized_just = "Y".repeat(MAX_JUSTIFICATION_LEN + 1);
        let forged_json = serde_json::json!({
            "from_level": "Secret",
            "to_level": "Internal",
            "receipt_id": unique_receipt_id(),
            "policy_ref": legit.policy_ref(),
            "justification": oversized_just,
            "authority_id": legit.authority_id(),
            "boundary_id": legit.boundary_id(),
            "payload_hash": TEST_PAYLOAD_HASH,
            "envelope_hash": TEST_ENVELOPE_HASH,
            "issued_at_ms": TEST_ISSUED_AT_MS,
            "expires_at_ms": TEST_EXPIRES_AT_MS,
            "content_hash": legit.content_hash(),
            "authority_signature": VALID_TEST_SIG,
        });
        let forged: DeclassificationReceipt = serde_json::from_value(forged_json).unwrap();

        let err = policy
            .propagate_with_declassification(
                "external-api",
                &label,
                &forged,
                Some(&TestVerifier),
                TEST_NOW_MS,
                TEST_PAYLOAD_HASH,
                TEST_ENVELOPE_HASH,
            )
            .unwrap_err();
        assert!(
            matches!(err, TaintError::ReceiptFieldSizeExceeded { .. }),
            "oversized justification must be rejected, got {err:?}"
        );
    }

    #[test]
    fn oversized_authority_id_rejected_at_consumption() {
        let mut policy = test_policy();
        let label = DataLabel::new(TaintLevel::Untainted, ConfidentialityLevel::Secret);

        let legit = policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Internal,
                &unique_receipt_id(),
                "DECLASS-SECRET-TO-INTERNAL",
                "valid",
                "authority-1",
                "external-api",
                TEST_PAYLOAD_HASH,
                TEST_ENVELOPE_HASH,
                VALID_TEST_SIG,
                TEST_ISSUED_AT_MS,
                TEST_EXPIRES_AT_MS,
            )
            .unwrap();

        let oversized_auth = "Z".repeat(MAX_AUTHORITY_ID_LEN + 1);
        let forged_json = serde_json::json!({
            "from_level": "Secret",
            "to_level": "Internal",
            "receipt_id": unique_receipt_id(),
            "policy_ref": legit.policy_ref(),
            "justification": legit.justification(),
            "authority_id": oversized_auth,
            "boundary_id": legit.boundary_id(),
            "payload_hash": TEST_PAYLOAD_HASH,
            "envelope_hash": TEST_ENVELOPE_HASH,
            "issued_at_ms": TEST_ISSUED_AT_MS,
            "expires_at_ms": TEST_EXPIRES_AT_MS,
            "content_hash": legit.content_hash(),
            "authority_signature": VALID_TEST_SIG,
        });
        let forged: DeclassificationReceipt = serde_json::from_value(forged_json).unwrap();

        let err = policy
            .propagate_with_declassification(
                "external-api",
                &label,
                &forged,
                Some(&TestVerifier),
                TEST_NOW_MS,
                TEST_PAYLOAD_HASH,
                TEST_ENVELOPE_HASH,
            )
            .unwrap_err();
        assert!(
            matches!(err, TaintError::ReceiptFieldSizeExceeded { .. }),
            "oversized authority_id must be rejected, got {err:?}"
        );
    }

    #[test]
    fn oversized_boundary_id_rejected_at_consumption() {
        let mut policy = test_policy();
        let label = DataLabel::new(TaintLevel::Untainted, ConfidentialityLevel::Secret);

        let legit = policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Internal,
                &unique_receipt_id(),
                "DECLASS-SECRET-TO-INTERNAL",
                "valid",
                "authority-1",
                "external-api",
                TEST_PAYLOAD_HASH,
                TEST_ENVELOPE_HASH,
                VALID_TEST_SIG,
                TEST_ISSUED_AT_MS,
                TEST_EXPIRES_AT_MS,
            )
            .unwrap();

        let oversized_bnd = "W".repeat(MAX_BOUNDARY_ID_LEN + 1);
        let forged_json = serde_json::json!({
            "from_level": "Secret",
            "to_level": "Internal",
            "receipt_id": unique_receipt_id(),
            "policy_ref": legit.policy_ref(),
            "justification": legit.justification(),
            "authority_id": legit.authority_id(),
            "boundary_id": oversized_bnd,
            "payload_hash": TEST_PAYLOAD_HASH,
            "envelope_hash": TEST_ENVELOPE_HASH,
            "issued_at_ms": TEST_ISSUED_AT_MS,
            "expires_at_ms": TEST_EXPIRES_AT_MS,
            "content_hash": legit.content_hash(),
            "authority_signature": VALID_TEST_SIG,
        });
        let forged: DeclassificationReceipt = serde_json::from_value(forged_json).unwrap();

        let err = policy
            .propagate_with_declassification(
                "external-api",
                &label,
                &forged,
                Some(&TestVerifier),
                TEST_NOW_MS,
                TEST_PAYLOAD_HASH,
                TEST_ENVELOPE_HASH,
            )
            .unwrap_err();
        assert!(
            matches!(err, TaintError::ReceiptFieldSizeExceeded { .. }),
            "oversized boundary_id must be rejected, got {err:?}"
        );
    }

    // =========================================================================
    // MAJOR 1: Length-framed hash collision boundary tests
    // =========================================================================

    #[test]
    fn hash_length_framing_prevents_field_boundary_collision() {
        // Without length framing, authority_id="ab" + boundary_id="cd"
        // and authority_id="abc" + boundary_id="d" would produce the
        // same hash. With length framing, they must differ.

        // Set up a policy covering both boundaries for the test.
        let boundaries = vec![
            BoundaryPolicy::new("cd", TaintLevel::Toxic, ConfidentialityLevel::Internal, 0)
                .unwrap(),
            BoundaryPolicy::new("d", TaintLevel::Toxic, ConfidentialityLevel::Internal, 0).unwrap(),
        ];
        let declass_rules = vec![
            DeclassificationPolicy::new(
                "DECLASS-SECRET-TO-INTERNAL",
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Internal,
            )
            .unwrap(),
        ];
        let extended_policy = DualLatticePolicy::new(boundaries, declass_rules).unwrap();

        let r1 = extended_policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Internal,
                &unique_receipt_id(),
                "DECLASS-SECRET-TO-INTERNAL",
                "same-justification",
                "ab",
                "cd",
                TEST_PAYLOAD_HASH,
                TEST_ENVELOPE_HASH,
                VALID_TEST_SIG,
                TEST_ISSUED_AT_MS,
                TEST_EXPIRES_AT_MS,
            )
            .unwrap();

        let r2 = extended_policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Internal,
                &unique_receipt_id(),
                "DECLASS-SECRET-TO-INTERNAL",
                "same-justification",
                "abc",
                "d",
                TEST_PAYLOAD_HASH,
                TEST_ENVELOPE_HASH,
                VALID_TEST_SIG,
                TEST_ISSUED_AT_MS,
                TEST_EXPIRES_AT_MS,
            )
            .unwrap();

        assert_ne!(
            r1.content_hash(),
            r2.content_hash(),
            "different authority/boundary splits must produce different hashes \
             (length framing prevents delimiter collision)"
        );
    }

    #[test]
    fn hash_length_framing_prevents_rule_justification_collision() {
        // rule_id="RULE" + justification="JUST" vs
        // rule_id="RULEJ" + justification="UST" must differ.
        let boundaries = vec![
            BoundaryPolicy::new(
                "boundary",
                TaintLevel::Toxic,
                ConfidentialityLevel::Internal,
                0,
            )
            .unwrap(),
        ];
        let declass_rules = vec![
            DeclassificationPolicy::new(
                "RULE",
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Internal,
            )
            .unwrap(),
            DeclassificationPolicy::new(
                "RULEJ",
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Internal,
            )
            .unwrap(),
        ];
        let policy = DualLatticePolicy::new(boundaries, declass_rules).unwrap();

        let r1 = policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Internal,
                &unique_receipt_id(),
                "RULE",
                "JUST",
                "auth",
                "boundary",
                TEST_PAYLOAD_HASH,
                TEST_ENVELOPE_HASH,
                VALID_TEST_SIG,
                TEST_ISSUED_AT_MS,
                TEST_EXPIRES_AT_MS,
            )
            .unwrap();
        let r2 = policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Internal,
                &unique_receipt_id(),
                "RULEJ",
                "UST",
                "auth",
                "boundary",
                TEST_PAYLOAD_HASH,
                TEST_ENVELOPE_HASH,
                VALID_TEST_SIG,
                TEST_ISSUED_AT_MS,
                TEST_EXPIRES_AT_MS,
            )
            .unwrap();

        assert_ne!(
            r1.content_hash(),
            r2.content_hash(),
            "different rule_id/justification splits must produce different hashes"
        );
    }

    // =========================================================================
    // MAJOR 2: RFC taxonomy mapping tests
    // =========================================================================

    #[test]
    fn rfc_from_level_roundtrip() {
        // All RFC levels map to an internal level and back.
        let rfc_levels = [
            RfcConfidentialityLevel::Public,
            RfcConfidentialityLevel::Internal,
            RfcConfidentialityLevel::Confidential,
            RfcConfidentialityLevel::Restricted,
        ];
        let expected_internal = [
            ConfidentialityLevel::Public,
            ConfidentialityLevel::Internal,
            ConfidentialityLevel::Confidential,
            ConfidentialityLevel::Secret,
        ];

        for (rfc, internal) in rfc_levels.iter().zip(expected_internal.iter()) {
            let converted = ConfidentialityLevel::from_rfc_level(*rfc);
            assert_eq!(
                converted, *internal,
                "from_rfc_level({rfc:?}) should produce {internal:?}"
            );
            let back = converted.to_rfc_level().unwrap();
            assert_eq!(
                back, *rfc,
                "to_rfc_level({internal:?}) should produce {rfc:?}"
            );
        }
    }

    #[test]
    fn rfc_top_secret_has_no_mapping() {
        // TopSecret must be rejected (fail-closed) with no RFC counterpart.
        let err = ConfidentialityLevel::TopSecret.to_rfc_level().unwrap_err();
        assert!(
            matches!(err, TaintError::InvalidPolicyRef { .. }),
            "TopSecret should fail to map to RFC level, got {err:?}"
        );
        assert!(
            err.to_string().contains("no RFC counterpart"),
            "error should mention no RFC counterpart, got: {err}"
        );
    }

    #[test]
    fn rfc_from_str_valid_levels() {
        assert_eq!(
            ConfidentialityLevel::from_rfc_str("PUBLIC").unwrap(),
            ConfidentialityLevel::Public
        );
        assert_eq!(
            ConfidentialityLevel::from_rfc_str("INTERNAL").unwrap(),
            ConfidentialityLevel::Internal
        );
        assert_eq!(
            ConfidentialityLevel::from_rfc_str("CONFIDENTIAL").unwrap(),
            ConfidentialityLevel::Confidential
        );
        assert_eq!(
            ConfidentialityLevel::from_rfc_str("RESTRICTED").unwrap(),
            ConfidentialityLevel::Secret
        );
    }

    #[test]
    fn rfc_from_str_unknown_rejected() {
        // Unknown strings must be rejected (fail-closed).
        let unknown = ["Secret", "TopSecret", "TOP_SECRET", "public", "UNKNOWN", ""];
        for s in unknown {
            let err = ConfidentialityLevel::from_rfc_str(s).unwrap_err();
            assert!(
                matches!(err, TaintError::InvalidPolicyRef { .. }),
                "unknown RFC string '{s}' should be rejected, got {err:?}"
            );
        }
    }

    #[test]
    fn rfc_display() {
        assert_eq!(RfcConfidentialityLevel::Public.to_string(), "PUBLIC");
        assert_eq!(RfcConfidentialityLevel::Internal.to_string(), "INTERNAL");
        assert_eq!(
            RfcConfidentialityLevel::Confidential.to_string(),
            "CONFIDENTIAL"
        );
        assert_eq!(
            RfcConfidentialityLevel::Restricted.to_string(),
            "RESTRICTED"
        );
    }

    #[test]
    fn rfc_serde_roundtrip() {
        let levels = [
            RfcConfidentialityLevel::Public,
            RfcConfidentialityLevel::Internal,
            RfcConfidentialityLevel::Confidential,
            RfcConfidentialityLevel::Restricted,
        ];
        for level in levels {
            let json = serde_json::to_string(&level).unwrap();
            let parsed: RfcConfidentialityLevel = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, level, "serde roundtrip failed for {level:?}");
        }
    }

    #[test]
    fn rfc_cross_layer_compatibility() {
        // Ensure the RFC schema's 4 levels all map to valid internal levels
        // and that internal levels 0-3 all map back to RFC levels.
        for ordinal in 0..=3u8 {
            let internal = ConfidentialityLevel::from_ordinal(ordinal).unwrap();
            let rfc = internal.to_rfc_level().unwrap_or_else(|_| {
                panic!("ordinal {ordinal} ({internal}) should have RFC mapping")
            });
            let back = ConfidentialityLevel::from_rfc_level(rfc);
            assert_eq!(
                back, internal,
                "cross-layer roundtrip failed for ordinal {ordinal}"
            );
        }
        // Ordinal 4 (TopSecret) must fail.
        let top = ConfidentialityLevel::from_ordinal(4).unwrap();
        assert!(
            top.to_rfc_level().is_err(),
            "ordinal 4 (TopSecret) must not map to RFC"
        );
    }

    // =========================================================================
    // BLOCKER: Receipt freshness / replay-protection tests
    // =========================================================================

    #[test]
    fn expired_receipt_rejected() {
        let mut policy = test_policy();
        let label = DataLabel::new(TaintLevel::Untainted, ConfidentialityLevel::Secret);
        let receipt = policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Internal,
                &unique_receipt_id(),
                "DECLASS-SECRET-TO-INTERNAL",
                "approved release",
                "security-officer-1",
                "external-api",
                TEST_PAYLOAD_HASH,
                TEST_ENVELOPE_HASH,
                VALID_TEST_SIG,
                TEST_ISSUED_AT_MS,
                TEST_EXPIRES_AT_MS,
            )
            .unwrap();

        // now_ms is at or after expires_at_ms -> must be rejected.
        let err = policy
            .propagate_with_declassification(
                "external-api",
                &label,
                &receipt,
                Some(&TestVerifier),
                TEST_EXPIRES_AT_MS, // exactly at expiry
                TEST_PAYLOAD_HASH,
                TEST_ENVELOPE_HASH,
            )
            .unwrap_err();
        assert!(
            matches!(err, TaintError::ReceiptExpired { .. }),
            "expired receipt must be rejected, got {err:?}"
        );
        assert!(
            err.to_string().contains("expired"),
            "error should mention expiry, got: {err}"
        );
    }

    #[test]
    fn receipt_before_issuance_rejected() {
        let mut policy = test_policy();
        let label = DataLabel::new(TaintLevel::Untainted, ConfidentialityLevel::Secret);
        let receipt = policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Internal,
                &unique_receipt_id(),
                "DECLASS-SECRET-TO-INTERNAL",
                "approved release",
                "security-officer-1",
                "external-api",
                TEST_PAYLOAD_HASH,
                TEST_ENVELOPE_HASH,
                VALID_TEST_SIG,
                TEST_ISSUED_AT_MS,
                TEST_EXPIRES_AT_MS,
            )
            .unwrap();

        // now_ms is before issued_at_ms -> must be rejected.
        let err = policy
            .propagate_with_declassification(
                "external-api",
                &label,
                &receipt,
                Some(&TestVerifier),
                TEST_ISSUED_AT_MS - 1, // before issuance
                TEST_PAYLOAD_HASH,
                TEST_ENVELOPE_HASH,
            )
            .unwrap_err();
        assert!(
            matches!(err, TaintError::ReceiptExpired { .. }),
            "pre-issuance receipt must be rejected, got {err:?}"
        );
    }

    #[test]
    fn receipt_lifetime_exceeds_max_rejected_at_creation() {
        let policy = test_policy();
        let err = policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Internal,
                &unique_receipt_id(),
                "DECLASS-SECRET-TO-INTERNAL",
                "too long lifetime",
                "security-officer-1",
                "external-api",
                TEST_PAYLOAD_HASH,
                TEST_ENVELOPE_HASH,
                VALID_TEST_SIG,
                TEST_ISSUED_AT_MS,
                TEST_ISSUED_AT_MS + MAX_RECEIPT_LIFETIME_MS + 1,
            )
            .unwrap_err();
        assert!(
            matches!(err, TaintError::ReceiptExpired { .. }),
            "over-long lifetime must be rejected, got {err:?}"
        );
    }

    #[test]
    fn receipt_invalid_timestamps_rejected_at_creation() {
        let policy = test_policy();
        // expires_at_ms <= issued_at_ms
        let err = policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Internal,
                &unique_receipt_id(),
                "DECLASS-SECRET-TO-INTERNAL",
                "bad timestamps",
                "security-officer-1",
                "external-api",
                TEST_PAYLOAD_HASH,
                TEST_ENVELOPE_HASH,
                VALID_TEST_SIG,
                TEST_ISSUED_AT_MS,
                TEST_ISSUED_AT_MS, // same as issued = invalid
            )
            .unwrap_err();
        assert!(
            matches!(err, TaintError::ReceiptExpired { .. }),
            "equal timestamps must be rejected, got {err:?}"
        );
    }

    #[test]
    fn receipt_well_after_expiry_rejected() {
        let mut policy = test_policy();
        let label = DataLabel::new(TaintLevel::Untainted, ConfidentialityLevel::Secret);
        let receipt = policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Internal,
                &unique_receipt_id(),
                "DECLASS-SECRET-TO-INTERNAL",
                "approved release",
                "security-officer-1",
                "external-api",
                TEST_PAYLOAD_HASH,
                TEST_ENVELOPE_HASH,
                VALID_TEST_SIG,
                TEST_ISSUED_AT_MS,
                TEST_EXPIRES_AT_MS,
            )
            .unwrap();

        // Way past expiry.
        let err = policy
            .propagate_with_declassification(
                "external-api",
                &label,
                &receipt,
                Some(&TestVerifier),
                TEST_EXPIRES_AT_MS + 86_400_000, // 1 day later
                TEST_PAYLOAD_HASH,
                TEST_ENVELOPE_HASH,
            )
            .unwrap_err();
        assert!(
            matches!(err, TaintError::ReceiptExpired { .. }),
            "long-expired receipt must be rejected, got {err:?}"
        );
    }

    // =========================================================================
    // BLOCKER: Duplicate boundary/rule ID rejection tests
    // =========================================================================

    #[test]
    fn duplicate_boundary_id_rejected() {
        let b1 = BoundaryPolicy::new(
            "same-id",
            TaintLevel::LowTaint,
            ConfidentialityLevel::Internal,
            3,
        )
        .unwrap();
        let b2 = BoundaryPolicy::new(
            "same-id",
            TaintLevel::MediumTaint,
            ConfidentialityLevel::Confidential,
            4,
        )
        .unwrap();

        let err = DualLatticePolicy::new(vec![b1, b2], vec![]).unwrap_err();
        assert!(
            matches!(err, TaintError::DuplicateBoundaryId { .. }),
            "duplicate boundary ID must be rejected, got {err:?}"
        );
        assert!(
            err.to_string().contains("same-id"),
            "error should contain the duplicate ID, got: {err}"
        );
    }

    #[test]
    fn duplicate_rule_id_rejected() {
        let r1 = DeclassificationPolicy::new(
            "SAME-RULE",
            ConfidentialityLevel::Secret,
            ConfidentialityLevel::Internal,
        )
        .unwrap();
        let r2 = DeclassificationPolicy::new(
            "SAME-RULE",
            ConfidentialityLevel::Confidential,
            ConfidentialityLevel::Public,
        )
        .unwrap();

        let err = DualLatticePolicy::new(vec![], vec![r1, r2]).unwrap_err();
        assert!(
            matches!(err, TaintError::DuplicateRuleId { .. }),
            "duplicate rule ID must be rejected, got {err:?}"
        );
        assert!(
            err.to_string().contains("SAME-RULE"),
            "error should contain the duplicate ID, got: {err}"
        );
    }

    #[test]
    fn unique_boundary_and_rule_ids_accepted() {
        let b1 = BoundaryPolicy::new(
            "boundary-a",
            TaintLevel::LowTaint,
            ConfidentialityLevel::Internal,
            3,
        )
        .unwrap();
        let b2 = BoundaryPolicy::new(
            "boundary-b",
            TaintLevel::Untainted,
            ConfidentialityLevel::Public,
            4,
        )
        .unwrap();
        let r1 = DeclassificationPolicy::new(
            "RULE-1",
            ConfidentialityLevel::Secret,
            ConfidentialityLevel::Internal,
        )
        .unwrap();
        let r2 = DeclassificationPolicy::new(
            "RULE-2",
            ConfidentialityLevel::Internal,
            ConfidentialityLevel::Public,
        )
        .unwrap();

        assert!(
            DualLatticePolicy::new(vec![b1, b2], vec![r1, r2]).is_ok(),
            "unique IDs should be accepted"
        );
    }

    // =========================================================================
    // MAJOR: Oversized signature rejection tests
    // =========================================================================

    #[test]
    fn oversized_signature_rejected_at_creation() {
        let policy = test_policy();
        let oversized_sig = vec![0xAA; MAX_SIGNATURE_SIZE + 1];
        let err = policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Internal,
                &unique_receipt_id(),
                "DECLASS-SECRET-TO-INTERNAL",
                "valid justification",
                "security-officer-1",
                "external-api",
                TEST_PAYLOAD_HASH,
                TEST_ENVELOPE_HASH,
                &oversized_sig,
                TEST_ISSUED_AT_MS,
                TEST_EXPIRES_AT_MS,
            )
            .unwrap_err();
        assert!(
            matches!(err, TaintError::ReceiptFieldSizeExceeded { .. }),
            "oversized signature must be rejected at creation, got {err:?}"
        );
    }

    #[test]
    fn oversized_signature_rejected_at_deserialization() {
        // With bounded deserialization, an oversized signature is rejected
        // during deserialization itself -- before the receipt object is
        // even fully constructed. This prevents memory allocation of
        // oversized payloads.
        let oversized_sig: Vec<u8> = vec![0xAA; MAX_SIGNATURE_SIZE + 1];
        let forged_json = serde_json::json!({
            "from_level": "Secret",
            "to_level": "Internal",
            "receipt_id": unique_receipt_id(),
            "policy_ref": "DECLASS-SECRET-TO-INTERNAL",
            "justification": "valid",
            "authority_id": "authority-1",
            "boundary_id": "external-api",
            "payload_hash": TEST_PAYLOAD_HASH,
            "envelope_hash": TEST_ENVELOPE_HASH,
            "issued_at_ms": TEST_ISSUED_AT_MS,
            "expires_at_ms": TEST_EXPIRES_AT_MS,
            "content_hash": vec![0u8; 32],
            "authority_signature": oversized_sig,
        });
        let result: Result<DeclassificationReceipt, _> = serde_json::from_value(forged_json);
        assert!(
            result.is_err(),
            "oversized signature must be rejected at deserialization, got {result:?}"
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("exceeds maximum"),
            "error should mention size limit, got: {err_msg}"
        );
    }

    #[test]
    fn max_size_signature_accepted() {
        let policy = test_policy();
        // Signature at exactly MAX_SIGNATURE_SIZE should be accepted.
        let mut max_sig = vec![0xAA; MAX_SIGNATURE_SIZE];
        max_sig[0] = 0xAA; // ensure first byte is the "valid" marker
        let result = policy.declassify(
            ConfidentialityLevel::Secret,
            ConfidentialityLevel::Internal,
            &unique_receipt_id(),
            "DECLASS-SECRET-TO-INTERNAL",
            "valid justification",
            "security-officer-1",
            "external-api",
            TEST_PAYLOAD_HASH,
            TEST_ENVELOPE_HASH,
            &max_sig,
            TEST_ISSUED_AT_MS,
            TEST_EXPIRES_AT_MS,
        );
        assert!(
            result.is_ok(),
            "signature at exactly MAX_SIGNATURE_SIZE should be accepted"
        );
    }

    // =========================================================================
    // BLOCKER: Anti-replay (one-time consumption) tests
    // =========================================================================

    #[test]
    fn replayed_receipt_rejected() {
        // A receipt consumed once must be rejected on second use.
        let mut policy = test_policy();
        let label = DataLabel::new(TaintLevel::Untainted, ConfidentialityLevel::Secret);

        let receipt = policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Internal,
                &unique_receipt_id(),
                "DECLASS-SECRET-TO-INTERNAL",
                "approved release",
                "security-officer-1",
                "external-api",
                TEST_PAYLOAD_HASH,
                TEST_ENVELOPE_HASH,
                VALID_TEST_SIG,
                TEST_ISSUED_AT_MS,
                TEST_EXPIRES_AT_MS,
            )
            .unwrap();

        // First use: should succeed.
        let result = policy
            .propagate_with_declassification(
                "external-api",
                &label,
                &receipt,
                Some(&TestVerifier),
                TEST_NOW_MS,
                TEST_PAYLOAD_HASH,
                TEST_ENVELOPE_HASH,
            )
            .unwrap();
        assert_eq!(result.confidentiality, ConfidentialityLevel::Internal);

        // Second use of the SAME receipt: must be rejected (anti-replay).
        let err = policy
            .propagate_with_declassification(
                "external-api",
                &label,
                &receipt,
                Some(&TestVerifier),
                TEST_NOW_MS,
                TEST_PAYLOAD_HASH,
                TEST_ENVELOPE_HASH,
            )
            .unwrap_err();
        assert!(
            matches!(err, TaintError::ReceiptAlreadyConsumed { .. }),
            "replayed receipt must be rejected, got {err:?}"
        );
        assert!(
            err.to_string().contains(receipt.receipt_id()),
            "error should contain the receipt ID, got: {err}"
        );
    }

    #[test]
    fn consumed_receipt_count_tracks_usage() {
        let mut policy = test_policy();
        let label = DataLabel::new(TaintLevel::Untainted, ConfidentialityLevel::Secret);

        assert_eq!(policy.consumed_receipt_count(), 0);

        let receipt = policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Internal,
                &unique_receipt_id(),
                "DECLASS-SECRET-TO-INTERNAL",
                "first",
                "security-officer-1",
                "external-api",
                TEST_PAYLOAD_HASH,
                TEST_ENVELOPE_HASH,
                VALID_TEST_SIG,
                TEST_ISSUED_AT_MS,
                TEST_EXPIRES_AT_MS,
            )
            .unwrap();

        let _ = policy
            .propagate_with_declassification(
                "external-api",
                &label,
                &receipt,
                Some(&TestVerifier),
                TEST_NOW_MS,
                TEST_PAYLOAD_HASH,
                TEST_ENVELOPE_HASH,
            )
            .unwrap();

        assert_eq!(policy.consumed_receipt_count(), 1);
    }

    // =========================================================================
    // BLOCKER: Effect-binding verification tests
    // =========================================================================

    #[test]
    fn receipt_payload_hash_mismatch_rejected() {
        let mut policy = test_policy();
        let label = DataLabel::new(TaintLevel::Untainted, ConfidentialityLevel::Secret);

        let receipt = policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Internal,
                &unique_receipt_id(),
                "DECLASS-SECRET-TO-INTERNAL",
                "approved",
                "security-officer-1",
                "external-api",
                TEST_PAYLOAD_HASH,
                TEST_ENVELOPE_HASH,
                VALID_TEST_SIG,
                TEST_ISSUED_AT_MS,
                TEST_EXPIRES_AT_MS,
            )
            .unwrap();

        // Present a different payload hash at consumption time.
        let wrong_payload = b"wrong-payload-hash-32bytes-padXX";
        let err = policy
            .propagate_with_declassification(
                "external-api",
                &label,
                &receipt,
                Some(&TestVerifier),
                TEST_NOW_MS,
                wrong_payload,
                TEST_ENVELOPE_HASH,
            )
            .unwrap_err();
        assert!(
            matches!(err, TaintError::EffectBindingMismatch { .. }),
            "payload hash mismatch must be rejected, got {err:?}"
        );
        assert!(
            err.to_string().contains("payload_hash"),
            "error should mention payload_hash, got: {err}"
        );
    }

    #[test]
    fn receipt_envelope_hash_mismatch_rejected() {
        let mut policy = test_policy();
        let label = DataLabel::new(TaintLevel::Untainted, ConfidentialityLevel::Secret);

        let receipt = policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Internal,
                &unique_receipt_id(),
                "DECLASS-SECRET-TO-INTERNAL",
                "approved",
                "security-officer-1",
                "external-api",
                TEST_PAYLOAD_HASH,
                TEST_ENVELOPE_HASH,
                VALID_TEST_SIG,
                TEST_ISSUED_AT_MS,
                TEST_EXPIRES_AT_MS,
            )
            .unwrap();

        // Present a different envelope hash at consumption time.
        let wrong_envelope = b"wrong-envelope-hash-32bytes-padX";
        let err = policy
            .propagate_with_declassification(
                "external-api",
                &label,
                &receipt,
                Some(&TestVerifier),
                TEST_NOW_MS,
                TEST_PAYLOAD_HASH,
                wrong_envelope,
            )
            .unwrap_err();
        assert!(
            matches!(err, TaintError::EffectBindingMismatch { .. }),
            "envelope hash mismatch must be rejected, got {err:?}"
        );
        assert!(
            err.to_string().contains("envelope_hash"),
            "error should mention envelope_hash, got: {err}"
        );
    }

    // =========================================================================
    // CQ BLOCKER: MAX_RECEIPT_LIFETIME_MS enforced at consumption
    // =========================================================================

    #[test]
    fn over_long_lifetime_receipt_rejected_at_consumption() {
        // An externally-constructed receipt with lifetime exceeding
        // MAX_RECEIPT_LIFETIME_MS must be rejected at consumption time,
        // even though it bypassed the issuance-time check.
        let mut policy = test_policy();
        let label = DataLabel::new(TaintLevel::Untainted, ConfidentialityLevel::Secret);

        // Manually construct a receipt with an over-long lifetime via
        // deserialization (bypassing the issuance-time check in declassify).
        let over_long_expires = TEST_ISSUED_AT_MS + MAX_RECEIPT_LIFETIME_MS + 1;
        let rid = unique_receipt_id();

        // Compute the correct hash for this over-long receipt.
        let hash = DualLatticePolicy::compute_receipt_hash(
            ConfidentialityLevel::Secret,
            ConfidentialityLevel::Internal,
            &rid,
            "DECLASS-SECRET-TO-INTERNAL",
            "over-long lifetime",
            "security-officer-1",
            "external-api",
            TEST_PAYLOAD_HASH,
            TEST_ENVELOPE_HASH,
            TEST_ISSUED_AT_MS,
            over_long_expires,
        );

        let forged_json = serde_json::json!({
            "from_level": "Secret",
            "to_level": "Internal",
            "receipt_id": rid,
            "policy_ref": "DECLASS-SECRET-TO-INTERNAL",
            "justification": "over-long lifetime",
            "authority_id": "security-officer-1",
            "boundary_id": "external-api",
            "payload_hash": TEST_PAYLOAD_HASH,
            "envelope_hash": TEST_ENVELOPE_HASH,
            "issued_at_ms": TEST_ISSUED_AT_MS,
            "expires_at_ms": over_long_expires,
            "content_hash": hash,
            "authority_signature": VALID_TEST_SIG,
        });
        let forged: DeclassificationReceipt = serde_json::from_value(forged_json).unwrap();

        let err = policy
            .propagate_with_declassification(
                "external-api",
                &label,
                &forged,
                Some(&TestVerifier),
                TEST_NOW_MS,
                TEST_PAYLOAD_HASH,
                TEST_ENVELOPE_HASH,
            )
            .unwrap_err();
        assert!(
            matches!(err, TaintError::ReceiptExpired { .. }),
            "over-long lifetime must be rejected at consumption, got {err:?}"
        );
        assert!(
            err.to_string().contains("exceeds maximum"),
            "error should mention exceeding maximum, got: {err}"
        );
        assert!(
            err.to_string().contains("at consumption"),
            "error should indicate this is a consumption-time check, got: {err}"
        );
    }

    // =========================================================================
    // MAJOR: Bounded deserialization tests
    // =========================================================================

    #[test]
    fn oversized_string_field_rejected_at_deserialization() {
        // A string field exceeding MAX_DESERIALIZE_STRING_LEN must be
        // rejected during deserialization itself, before the receipt
        // object is fully constructed.
        let oversized_justification = "X".repeat(MAX_DESERIALIZE_STRING_LEN + 1);
        let forged_json = serde_json::json!({
            "from_level": "Secret",
            "to_level": "Internal",
            "receipt_id": unique_receipt_id(),
            "policy_ref": "DECLASS-SECRET-TO-INTERNAL",
            "justification": oversized_justification,
            "authority_id": "authority-1",
            "boundary_id": "external-api",
            "payload_hash": TEST_PAYLOAD_HASH,
            "envelope_hash": TEST_ENVELOPE_HASH,
            "issued_at_ms": TEST_ISSUED_AT_MS,
            "expires_at_ms": TEST_EXPIRES_AT_MS,
            "content_hash": vec![0u8; 32],
        });
        let result: Result<DeclassificationReceipt, _> = serde_json::from_value(forged_json);
        assert!(
            result.is_err(),
            "oversized string field must be rejected at deserialization, got {result:?}"
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("exceeds maximum"),
            "error should mention size limit, got: {err_msg}"
        );
    }

    #[test]
    fn oversized_bytes_field_rejected_at_deserialization() {
        // A bytes field (payload_hash) exceeding MAX_EFFECT_HASH_LEN must
        // be rejected during deserialization.
        let oversized_hash = vec![0u8; MAX_EFFECT_HASH_LEN + 1];
        let forged_json = serde_json::json!({
            "from_level": "Secret",
            "to_level": "Internal",
            "receipt_id": unique_receipt_id(),
            "policy_ref": "DECLASS-SECRET-TO-INTERNAL",
            "justification": "valid",
            "authority_id": "authority-1",
            "boundary_id": "external-api",
            "payload_hash": oversized_hash,
            "envelope_hash": TEST_ENVELOPE_HASH,
            "issued_at_ms": TEST_ISSUED_AT_MS,
            "expires_at_ms": TEST_EXPIRES_AT_MS,
            "content_hash": vec![0u8; 32],
        });
        let result: Result<DeclassificationReceipt, _> = serde_json::from_value(forged_json);
        assert!(
            result.is_err(),
            "oversized bytes field must be rejected at deserialization, got {result:?}"
        );
    }

    // =========================================================================
    // Receipt hash includes effect-binding fields
    // =========================================================================

    #[test]
    fn receipt_hash_varies_with_payload_hash() {
        let policy = test_policy();
        let r1 = policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Internal,
                "rid-ph-1",
                "DECLASS-SECRET-TO-INTERNAL",
                "same",
                "authority-1",
                "external-api",
                b"payload-A-padded-to-32-bytes-pad",
                TEST_ENVELOPE_HASH,
                VALID_TEST_SIG,
                TEST_ISSUED_AT_MS,
                TEST_EXPIRES_AT_MS,
            )
            .unwrap();
        let r2 = policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Internal,
                "rid-ph-2",
                "DECLASS-SECRET-TO-INTERNAL",
                "same",
                "authority-1",
                "external-api",
                b"payload-B-padded-to-32-bytes-pad",
                TEST_ENVELOPE_HASH,
                VALID_TEST_SIG,
                TEST_ISSUED_AT_MS,
                TEST_EXPIRES_AT_MS,
            )
            .unwrap();
        assert_ne!(
            r1.content_hash(),
            r2.content_hash(),
            "different payload hashes must produce different receipt hashes"
        );
    }

    #[test]
    fn receipt_hash_varies_with_envelope_hash() {
        let policy = test_policy();
        let r1 = policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Internal,
                "rid-eh-1",
                "DECLASS-SECRET-TO-INTERNAL",
                "same",
                "authority-1",
                "external-api",
                TEST_PAYLOAD_HASH,
                b"envelope-A-padded-to-32bytes-pad",
                VALID_TEST_SIG,
                TEST_ISSUED_AT_MS,
                TEST_EXPIRES_AT_MS,
            )
            .unwrap();
        let r2 = policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Internal,
                "rid-eh-2",
                "DECLASS-SECRET-TO-INTERNAL",
                "same",
                "authority-1",
                "external-api",
                TEST_PAYLOAD_HASH,
                b"envelope-B-padded-to-32bytes-pad",
                VALID_TEST_SIG,
                TEST_ISSUED_AT_MS,
                TEST_EXPIRES_AT_MS,
            )
            .unwrap();
        assert_ne!(
            r1.content_hash(),
            r2.content_hash(),
            "different envelope hashes must produce different receipt hashes"
        );
    }

    #[test]
    fn receipt_hash_varies_with_receipt_id() {
        let policy = test_policy();
        let r1 = policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Internal,
                "receipt-id-A",
                "DECLASS-SECRET-TO-INTERNAL",
                "same",
                "authority-1",
                "external-api",
                TEST_PAYLOAD_HASH,
                TEST_ENVELOPE_HASH,
                VALID_TEST_SIG,
                TEST_ISSUED_AT_MS,
                TEST_EXPIRES_AT_MS,
            )
            .unwrap();
        let r2 = policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Internal,
                "receipt-id-B",
                "DECLASS-SECRET-TO-INTERNAL",
                "same",
                "authority-1",
                "external-api",
                TEST_PAYLOAD_HASH,
                TEST_ENVELOPE_HASH,
                VALID_TEST_SIG,
                TEST_ISSUED_AT_MS,
                TEST_EXPIRES_AT_MS,
            )
            .unwrap();
        assert_ne!(
            r1.content_hash(),
            r2.content_hash(),
            "different receipt_ids must produce different receipt hashes"
        );
    }

    // =========================================================================
    // BLOCKER: Mandatory 32-byte effect hash enforcement tests
    // =========================================================================

    #[test]
    fn empty_payload_hash_rejected_at_issuance() {
        let policy = test_policy();
        let err = policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Internal,
                &unique_receipt_id(),
                "DECLASS-SECRET-TO-INTERNAL",
                "empty payload hash",
                "authority-1",
                "external-api",
                &[], // empty payload hash
                TEST_ENVELOPE_HASH,
                VALID_TEST_SIG,
                TEST_ISSUED_AT_MS,
                TEST_EXPIRES_AT_MS,
            )
            .unwrap_err();
        assert!(
            matches!(err, TaintError::InvalidEffectHash { .. }),
            "empty payload_hash must be rejected, got {err:?}"
        );
        assert!(
            err.to_string().contains("payload_hash"),
            "error should mention payload_hash, got: {err}"
        );
        assert!(
            err.to_string().contains("32"),
            "error should mention required 32-byte length, got: {err}"
        );
    }

    #[test]
    fn empty_envelope_hash_rejected_at_issuance() {
        let policy = test_policy();
        let err = policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Internal,
                &unique_receipt_id(),
                "DECLASS-SECRET-TO-INTERNAL",
                "empty envelope hash",
                "authority-1",
                "external-api",
                TEST_PAYLOAD_HASH,
                &[], // empty envelope hash
                VALID_TEST_SIG,
                TEST_ISSUED_AT_MS,
                TEST_EXPIRES_AT_MS,
            )
            .unwrap_err();
        assert!(
            matches!(err, TaintError::InvalidEffectHash { .. }),
            "empty envelope_hash must be rejected, got {err:?}"
        );
        assert!(
            err.to_string().contains("envelope_hash"),
            "error should mention envelope_hash, got: {err}"
        );
    }

    #[test]
    fn short_payload_hash_rejected_at_issuance() {
        let policy = test_policy();
        // 16 bytes is too short (need exactly 32).
        let short_hash = vec![0xAB; 16];
        let err = policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Internal,
                &unique_receipt_id(),
                "DECLASS-SECRET-TO-INTERNAL",
                "short payload hash",
                "authority-1",
                "external-api",
                &short_hash,
                TEST_ENVELOPE_HASH,
                VALID_TEST_SIG,
                TEST_ISSUED_AT_MS,
                TEST_EXPIRES_AT_MS,
            )
            .unwrap_err();
        assert!(
            matches!(err, TaintError::InvalidEffectHash { .. }),
            "short payload_hash must be rejected, got {err:?}"
        );
    }

    #[test]
    fn long_payload_hash_rejected_at_issuance() {
        let policy = test_policy();
        // 33 bytes is too long (need exactly 32).
        let long_hash = vec![0xAB; 33];
        let err = policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Internal,
                &unique_receipt_id(),
                "DECLASS-SECRET-TO-INTERNAL",
                "long payload hash",
                "authority-1",
                "external-api",
                &long_hash,
                TEST_ENVELOPE_HASH,
                VALID_TEST_SIG,
                TEST_ISSUED_AT_MS,
                TEST_EXPIRES_AT_MS,
            )
            .unwrap_err();
        assert!(
            matches!(err, TaintError::InvalidEffectHash { .. }),
            "oversized payload_hash must be rejected, got {err:?}"
        );
    }

    #[test]
    fn exact_32_byte_hashes_accepted_at_issuance() {
        let policy = test_policy();
        let hash_32 = vec![0xCD; 32];
        let result = policy.declassify(
            ConfidentialityLevel::Secret,
            ConfidentialityLevel::Internal,
            &unique_receipt_id(),
            "DECLASS-SECRET-TO-INTERNAL",
            "exact 32-byte hashes",
            "authority-1",
            "external-api",
            &hash_32,
            &hash_32,
            VALID_TEST_SIG,
            TEST_ISSUED_AT_MS,
            TEST_EXPIRES_AT_MS,
        );
        assert!(
            result.is_ok(),
            "exactly 32-byte hashes should be accepted, got {result:?}"
        );
    }

    #[test]
    fn empty_expected_hashes_rejected_at_consumption() {
        // Even if the receipt has valid 32-byte hashes, the caller-supplied
        // expected hashes must also be exactly 32 bytes.
        let mut policy = test_policy();
        let label = DataLabel::new(TaintLevel::Untainted, ConfidentialityLevel::Secret);

        let receipt = policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Internal,
                &unique_receipt_id(),
                "DECLASS-SECRET-TO-INTERNAL",
                "valid",
                "security-officer-1",
                "external-api",
                TEST_PAYLOAD_HASH,
                TEST_ENVELOPE_HASH,
                VALID_TEST_SIG,
                TEST_ISSUED_AT_MS,
                TEST_EXPIRES_AT_MS,
            )
            .unwrap();

        // Empty expected payload hash at consumption.
        let err = policy
            .propagate_with_declassification(
                "external-api",
                &label,
                &receipt,
                Some(&TestVerifier),
                TEST_NOW_MS,
                &[], // empty expected payload hash
                TEST_ENVELOPE_HASH,
            )
            .unwrap_err();
        assert!(
            matches!(err, TaintError::InvalidEffectHash { .. }),
            "empty expected payload_hash must be rejected at consumption, got {err:?}"
        );
    }

    // =========================================================================
    // MAJOR: Anti-replay eviction tests
    // =========================================================================

    #[test]
    fn anti_replay_evicts_expired_entries_before_capacity_check() {
        // Fill the anti-replay map near capacity with receipts that will
        // expire before the next consumption attempt, then verify that
        // a new receipt can still be consumed after eviction.

        // Use a small policy with matching boundary/rules.
        let boundaries = vec![
            BoundaryPolicy::new("b", TaintLevel::Toxic, ConfidentialityLevel::Secret, 0).unwrap(),
        ];
        let rules = vec![
            DeclassificationPolicy::new(
                "R",
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Public,
            )
            .unwrap(),
        ];
        let mut policy = DualLatticePolicy::new(boundaries, rules).unwrap();
        let label = DataLabel::new(TaintLevel::Untainted, ConfidentialityLevel::Secret);

        // Insert (MAX_CONSUMED_RECEIPTS - 1) entries manually with an
        // expiry in the past relative to our next consumption timestamp.
        let past_expiry_ms = 1_000_000u64;
        for i in 0..MAX_CONSUMED_RECEIPTS - 1 {
            policy
                .consumed_receipts
                .insert(format!("old-receipt-{i}"), past_expiry_ms);
        }
        assert_eq!(policy.consumed_receipt_count(), MAX_CONSUMED_RECEIPTS - 1);

        // Create a fresh receipt with a future expiry.
        let fresh_issued = 2_000_000u64;
        let fresh_expires = fresh_issued + 3_600_000;
        let fresh_now = fresh_issued + 1_800_000;
        let receipt = policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Public,
                &unique_receipt_id(),
                "R",
                "after eviction",
                "auth-1",
                "b",
                TEST_PAYLOAD_HASH,
                TEST_ENVELOPE_HASH,
                VALID_TEST_SIG,
                fresh_issued,
                fresh_expires,
            )
            .unwrap();

        // Consume at a time past the old entries' expiry but within the
        // new receipt's validity window. Eviction should clear old entries.
        let result = policy.propagate_with_declassification(
            "b",
            &label,
            &receipt,
            Some(&TestVerifier),
            fresh_now,
            TEST_PAYLOAD_HASH,
            TEST_ENVELOPE_HASH,
        );
        assert!(
            result.is_ok(),
            "consumption must succeed after evicting expired entries, got {result:?}"
        );
        // Old entries should be evicted; only the fresh one remains.
        assert_eq!(
            policy.consumed_receipt_count(),
            1,
            "expired entries should have been evicted"
        );
    }

    #[test]
    fn anti_replay_saturation_still_works_with_expiry_eviction() {
        // Demonstrate that even after MAX_CONSUMED_RECEIPTS receipts have
        // been consumed, the system continues to operate as long as old
        // receipts have expired and been evicted.
        let boundaries = vec![
            BoundaryPolicy::new("b", TaintLevel::Toxic, ConfidentialityLevel::Secret, 0).unwrap(),
        ];
        let rules = vec![
            DeclassificationPolicy::new(
                "R",
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Public,
            )
            .unwrap(),
        ];
        let mut policy = DualLatticePolicy::new(boundaries, rules).unwrap();
        let label = DataLabel::new(TaintLevel::Untainted, ConfidentialityLevel::Secret);

        // Fill the map to exactly MAX_CONSUMED_RECEIPTS with expired entries.
        let past_expiry_ms = 500_000u64;
        for i in 0..MAX_CONSUMED_RECEIPTS {
            policy
                .consumed_receipts
                .insert(format!("saturated-{i}"), past_expiry_ms);
        }
        assert_eq!(policy.consumed_receipt_count(), MAX_CONSUMED_RECEIPTS);

        // Now try to consume a fresh receipt at a time past the old expiry.
        let fresh_issued = 1_000_000u64;
        let fresh_expires = fresh_issued + 3_600_000;
        let fresh_now = fresh_issued + 1_800_000;
        let receipt = policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Public,
                &unique_receipt_id(),
                "R",
                "post-saturation",
                "auth-1",
                "b",
                TEST_PAYLOAD_HASH,
                TEST_ENVELOPE_HASH,
                VALID_TEST_SIG,
                fresh_issued,
                fresh_expires,
            )
            .unwrap();

        let result = policy.propagate_with_declassification(
            "b",
            &label,
            &receipt,
            Some(&TestVerifier),
            fresh_now,
            TEST_PAYLOAD_HASH,
            TEST_ENVELOPE_HASH,
        );
        assert!(
            result.is_ok(),
            "system must continue operating after evicting expired entries from \
             a saturated anti-replay set, got {result:?}"
        );
        assert_eq!(
            policy.consumed_receipt_count(),
            1,
            "all expired entries should have been evicted, leaving only the fresh one"
        );
    }

    #[test]
    fn anti_replay_capacity_exceeded_without_evictable_entries_fails() {
        // If the anti-replay map is full and no entries are expired,
        // the capacity check must still fail-closed.
        let boundaries = vec![
            BoundaryPolicy::new("b", TaintLevel::Toxic, ConfidentialityLevel::Secret, 0).unwrap(),
        ];
        let rules = vec![
            DeclassificationPolicy::new(
                "R",
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Public,
            )
            .unwrap(),
        ];
        let mut policy = DualLatticePolicy::new(boundaries, rules).unwrap();
        let label = DataLabel::new(TaintLevel::Untainted, ConfidentialityLevel::Secret);

        // Fill with entries that expire FAR in the future (not evictable).
        let future_expiry_ms = u64::MAX;
        for i in 0..MAX_CONSUMED_RECEIPTS {
            policy
                .consumed_receipts
                .insert(format!("nonevictable-{i}"), future_expiry_ms);
        }

        let fresh_issued = 1_000_000u64;
        let fresh_expires = fresh_issued + 3_600_000;
        let fresh_now = fresh_issued + 1_800_000;
        let receipt = policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Public,
                &unique_receipt_id(),
                "R",
                "should fail",
                "auth-1",
                "b",
                TEST_PAYLOAD_HASH,
                TEST_ENVELOPE_HASH,
                VALID_TEST_SIG,
                fresh_issued,
                fresh_expires,
            )
            .unwrap();

        let err = policy
            .propagate_with_declassification(
                "b",
                &label,
                &receipt,
                Some(&TestVerifier),
                fresh_now,
                TEST_PAYLOAD_HASH,
                TEST_ENVELOPE_HASH,
            )
            .unwrap_err();
        assert!(
            matches!(err, TaintError::ConsumedReceiptSetFull { .. }),
            "capacity must still be enforced when no entries are evictable, got {err:?}"
        );
    }
}

// =============================================================================
// Proptest lattice law invariants
// =============================================================================

#[cfg(test)]
mod proptests {
    use proptest::prelude::*;

    use super::*;

    fn arb_taint_level() -> impl Strategy<Value = TaintLevel> {
        (0u8..=4).prop_map(|v| TaintLevel::from_ordinal(v).unwrap())
    }

    fn arb_conf_level() -> impl Strategy<Value = ConfidentialityLevel> {
        (0u8..=4).prop_map(|v| ConfidentialityLevel::from_ordinal(v).unwrap())
    }

    proptest! {
        // =================================================================
        // TaintLevel join lattice laws
        // =================================================================

        #[test]
        fn taint_join_commutative(a in arb_taint_level(), b in arb_taint_level()) {
            prop_assert_eq!(a.join(b), b.join(a));
        }

        #[test]
        fn taint_join_associative(
            a in arb_taint_level(),
            b in arb_taint_level(),
            c in arb_taint_level(),
        ) {
            prop_assert_eq!(a.join(b).join(c), a.join(b.join(c)));
        }

        #[test]
        fn taint_join_idempotent(a in arb_taint_level()) {
            prop_assert_eq!(a.join(a), a);
        }

        #[test]
        fn taint_join_identity(a in arb_taint_level()) {
            // Untainted is the identity for join.
            prop_assert_eq!(a.join(TaintLevel::Untainted), a);
            prop_assert_eq!(TaintLevel::Untainted.join(a), a);
        }

        #[test]
        fn taint_join_absorbing(a in arb_taint_level()) {
            // Toxic is the absorbing element for join.
            prop_assert_eq!(a.join(TaintLevel::Toxic), TaintLevel::Toxic);
        }

        #[test]
        fn taint_join_monotone(a in arb_taint_level(), b in arb_taint_level()) {
            // join(a, b) >= a and join(a, b) >= b
            prop_assert!(a.join(b) >= a);
            prop_assert!(a.join(b) >= b);
        }

        // =================================================================
        // ConfidentialityLevel join lattice laws
        // =================================================================

        #[test]
        fn conf_join_commutative(a in arb_conf_level(), b in arb_conf_level()) {
            prop_assert_eq!(a.join(b), b.join(a));
        }

        #[test]
        fn conf_join_associative(
            a in arb_conf_level(),
            b in arb_conf_level(),
            c in arb_conf_level(),
        ) {
            prop_assert_eq!(a.join(b).join(c), a.join(b.join(c)));
        }

        #[test]
        fn conf_join_idempotent(a in arb_conf_level()) {
            prop_assert_eq!(a.join(a), a);
        }

        #[test]
        fn conf_join_identity(a in arb_conf_level()) {
            prop_assert_eq!(a.join(ConfidentialityLevel::Public), a);
            prop_assert_eq!(ConfidentialityLevel::Public.join(a), a);
        }

        #[test]
        fn conf_join_absorbing(a in arb_conf_level()) {
            prop_assert_eq!(a.join(ConfidentialityLevel::TopSecret), ConfidentialityLevel::TopSecret);
        }

        #[test]
        fn conf_join_monotone(a in arb_conf_level(), b in arb_conf_level()) {
            prop_assert!(a.join(b) >= a);
            prop_assert!(a.join(b) >= b);
        }

        // =================================================================
        // ConfidentialityLevel meet lattice laws
        // =================================================================

        #[test]
        fn conf_meet_commutative(a in arb_conf_level(), b in arb_conf_level()) {
            prop_assert_eq!(a.meet(b), b.meet(a));
        }

        #[test]
        fn conf_meet_associative(
            a in arb_conf_level(),
            b in arb_conf_level(),
            c in arb_conf_level(),
        ) {
            prop_assert_eq!(a.meet(b).meet(c), a.meet(b.meet(c)));
        }

        #[test]
        fn conf_meet_idempotent(a in arb_conf_level()) {
            prop_assert_eq!(a.meet(a), a);
        }

        #[test]
        fn conf_meet_identity(a in arb_conf_level()) {
            prop_assert_eq!(a.meet(ConfidentialityLevel::TopSecret), a);
            prop_assert_eq!(ConfidentialityLevel::TopSecret.meet(a), a);
        }

        #[test]
        fn conf_meet_absorbing(a in arb_conf_level()) {
            prop_assert_eq!(a.meet(ConfidentialityLevel::Public), ConfidentialityLevel::Public);
        }

        #[test]
        fn conf_meet_monotone(a in arb_conf_level(), b in arb_conf_level()) {
            prop_assert!(a.meet(b) <= a);
            prop_assert!(a.meet(b) <= b);
        }

        // =================================================================
        // Absorption law: join and meet interact correctly
        // =================================================================

        #[test]
        fn conf_absorption_law(a in arb_conf_level(), b in arb_conf_level()) {
            // a join (a meet b) == a
            prop_assert_eq!(a.join(a.meet(b)), a);
            // a meet (a join b) == a
            prop_assert_eq!(a.meet(a.join(b)), a);
        }

        // =================================================================
        // DataLabel join lattice laws
        // =================================================================

        #[test]
        fn data_label_join_commutative(
            ta in arb_taint_level(), ca in arb_conf_level(),
            tb in arb_taint_level(), cb in arb_conf_level(),
        ) {
            let a = DataLabel::new(ta, ca);
            let b = DataLabel::new(tb, cb);
            prop_assert_eq!(a.join(b), b.join(a));
        }

        #[test]
        fn data_label_join_associative(
            ta in arb_taint_level(), ca in arb_conf_level(),
            tb in arb_taint_level(), cb in arb_conf_level(),
            tc in arb_taint_level(), cc in arb_conf_level(),
        ) {
            let a = DataLabel::new(ta, ca);
            let b = DataLabel::new(tb, cb);
            let c = DataLabel::new(tc, cc);
            prop_assert_eq!(a.join(b).join(c), a.join(b.join(c)));
        }

        #[test]
        fn data_label_join_idempotent(t in arb_taint_level(), c in arb_conf_level()) {
            let a = DataLabel::new(t, c);
            prop_assert_eq!(a.join(a), a);
        }

        // =================================================================
        // Propagation function correctness
        // =================================================================

        #[test]
        fn propagate_taint_matches_fold(
            a in arb_taint_level(),
            b in arb_taint_level(),
            c in arb_taint_level(),
        ) {
            let inputs = [a, b, c];
            let expected = a.join(b).join(c);
            prop_assert_eq!(propagate_taint(&inputs), expected);
        }

        #[test]
        fn propagate_classification_matches_fold(
            a in arb_conf_level(),
            b in arb_conf_level(),
            c in arb_conf_level(),
        ) {
            let inputs = [a, b, c];
            let expected = a.join(b).join(c);
            prop_assert_eq!(propagate_classification(&inputs), expected);
        }

        // =================================================================
        // Taint monotonicity: propagation never decreases
        // =================================================================

        #[test]
        fn propagate_taint_never_decreases(
            a in arb_taint_level(),
            b in arb_taint_level(),
        ) {
            let result = propagate_taint(&[a, b]);
            prop_assert!(result >= a);
            prop_assert!(result >= b);
        }

        #[test]
        fn propagate_classification_never_decreases(
            a in arb_conf_level(),
            b in arb_conf_level(),
        ) {
            let result = propagate_classification(&[a, b]);
            prop_assert!(result >= a);
            prop_assert!(result >= b);
        }
    }
}
