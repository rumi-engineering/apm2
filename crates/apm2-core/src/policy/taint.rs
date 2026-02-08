// AGENT-AUTHORED
//! Dual lattice taint/classification propagation and declassification receipts
//! (TCK-00378).
//!
//! This module enforces RFC-0020 Section 5 dual-lattice security:
//!
//! - **Taint lattice**: Tracks data provenance integrity. Taint propagates
//!   upward via `join` (least upper bound). Higher taint = less trusted input.
//! - **Confidentiality lattice**: Tracks information classification level.
//!   Confidentiality propagates downward via `meet` (greatest lower bound) at
//!   boundary crossings to enforce need-to-know.
//! - **Declassification receipts**: Explicit, policy-gated downgrades of
//!   confidentiality level that produce auditable receipts.
//! - **Boundary crossing hooks**: Dual-lattice policy enforcement at trust
//!   boundary transitions and actuator entry points.
//!
//! # Security Model
//!
//! - **Fail-closed**: Any lattice violation rejects the request.
//! - **No implicit declassification**: Confidentiality can only be lowered via
//!   an explicit [`DeclassificationReceipt`] referencing a policy rule.
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
//! **Architecture note**: This module is the *policy primitive library*. It
//! provides types, lattice operations, declassification receipt issuance, and
//! boundary-crossing enforcement as pure functions / methods with no I/O.
//!
//! Runtime integration -- injecting labels into work-object flows, wiring
//! boundary checks into protocol dispatch, persisting receipts to the ledger,
//! and plugging in concrete [`SignatureVerifier`] implementations backed by
//! the daemon's key material -- is handled by the daemon-layer wiring tickets:
//!
//! - `TCK-00420`: Wire taint labels into work-object instruction flow
//! - `TCK-00421`: Boundary check hooks in protocol dispatch
//! - `TCK-00422`: Ledger persistence for declassification receipts
//!
//! Until those tickets land, the API is library-only and must be called
//! explicitly by consumers.

use std::fmt;

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
/// more sensitive data. At boundary crossings, confidentiality propagates
/// via [`ConfidentialityLevel::meet`] (greatest lower bound) to enforce
/// the principle that outbound data cannot exceed the boundary's clearance.
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
// TODO(TCK-00422): Wire concrete Ed25519/HSM SignatureVerifier into daemon
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
    /// Reference to the policy rule that authorized this declassification.
    policy_ref: String,
    /// Human-readable justification for audit trail.
    justification: String,
    /// Identifier of the authority (principal) that authorized the
    /// declassification.
    authority_id: String,
    /// Identifier of the boundary this receipt is scoped to. The receipt is
    /// only valid when crossing this specific boundary.
    boundary_id: String,
    /// BLAKE3 hash of the receipt content for tamper evidence.
    content_hash: [u8; 32],
    /// Cryptographic signature by the authority over the content hash.
    ///
    /// Verified at consumption time via a caller-supplied
    /// [`SignatureVerifier`]. Receipts without a valid signature are
    /// rejected (fail-closed).
    #[serde(default)]
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
}

impl DualLatticePolicy {
    /// Create a new dual-lattice policy with the given boundaries and
    /// declassification rules.
    #[must_use]
    pub const fn new(
        boundaries: Vec<BoundaryPolicy>,
        declassification_rules: Vec<DeclassificationPolicy>,
    ) -> Self {
        Self {
            boundaries,
            declassification_rules,
        }
    }

    /// Create an empty (deny-all) policy. No boundaries are configured,
    /// so all crossings are denied.
    #[must_use]
    pub const fn deny_all() -> Self {
        Self {
            boundaries: Vec::new(),
            declassification_rules: Vec::new(),
        }
    }

    /// Check a data label against a named boundary.
    ///
    /// # Errors
    ///
    /// Returns [`TaintError::BoundaryCrossingDenied`] if no boundary with
    /// the given ID is configured (fail-closed), or the specific taint/
    /// confidentiality violation error if the label fails the check.
    // TODO(TCK-00421): Wire into daemon protocol dispatch boundary hooks
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
    // TODO(TCK-00421): Wire into daemon actuator dispatch path
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

    /// Request a declassification, producing a receipt if authorized.
    ///
    /// The caller must specify which policy rule authorizes the downgrade,
    /// the `authority_id` of the principal requesting the declassification,
    /// the `boundary_id` that the receipt will be scoped to, and the
    /// `authority_signature` (the authority's cryptographic signature over
    /// the receipt's content hash).
    ///
    /// The signature is stored opaquely and verified at consumption time
    /// via a caller-supplied [`SignatureVerifier`].
    ///
    /// # Errors
    ///
    /// Returns [`TaintError::DeclassificationDenied`] if no matching rule
    /// is found or the requested range is not covered.
    /// Returns [`TaintError::InvalidPolicyRef`] if the justification,
    /// authority, or boundary identifiers are invalid.
    // TODO(TCK-00422): Wire into daemon actuation path
    #[allow(clippy::too_many_arguments)] // All params are semantically distinct security inputs
    pub fn declassify(
        &self,
        from: ConfidentialityLevel,
        to: ConfidentialityLevel,
        policy_ref: &str,
        justification: &str,
        authority_id: &str,
        boundary_id: &str,
        authority_signature: &[u8],
    ) -> Result<DeclassificationReceipt, TaintError> {
        // Validate inputs.
        if from.ordinal() <= to.ordinal() {
            return Err(TaintError::DeclassificationDenied {
                from,
                to,
                reason: "declassification requires from > to".to_string(),
            });
        }

        if justification.len() > MAX_JUSTIFICATION_LEN {
            return Err(TaintError::InvalidPolicyRef {
                reason: format!("justification exceeds maximum length of {MAX_JUSTIFICATION_LEN}"),
            });
        }

        if policy_ref.is_empty() {
            return Err(TaintError::InvalidPolicyRef {
                reason: "policy reference must be non-empty".to_string(),
            });
        }

        if policy_ref.len() > MAX_POLICY_REF_LEN {
            return Err(TaintError::InvalidPolicyRef {
                reason: format!("policy reference exceeds maximum length of {MAX_POLICY_REF_LEN}"),
            });
        }

        if authority_id.is_empty() {
            return Err(TaintError::InvalidPolicyRef {
                reason: "authority_id must be non-empty".to_string(),
            });
        }

        if authority_id.len() > MAX_AUTHORITY_ID_LEN {
            return Err(TaintError::InvalidPolicyRef {
                reason: format!("authority_id exceeds maximum length of {MAX_AUTHORITY_ID_LEN}"),
            });
        }

        if boundary_id.is_empty() {
            return Err(TaintError::InvalidPolicyRef {
                reason: "boundary_id must be non-empty".to_string(),
            });
        }

        if boundary_id.len() > MAX_BOUNDARY_ID_LEN {
            return Err(TaintError::InvalidPolicyRef {
                reason: format!("boundary_id exceeds maximum length of {MAX_BOUNDARY_ID_LEN}"),
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

        // Compute content hash over ALL receipt fields using length-prefixed
        // canonical hashing. Each variable-length field is preceded by its
        // length as a little-endian u64, preventing delimiter-boundary
        // collision attacks where different field tuples share identical
        // concatenated preimage bytes.
        let content_hash = Self::compute_receipt_hash(
            from,
            to,
            rule.rule_id(),
            justification,
            authority_id,
            boundary_id,
        );

        Ok(DeclassificationReceipt {
            from_level: from,
            to_level: to,
            policy_ref: policy_ref.to_string(),
            justification: justification.to_string(),
            authority_id: authority_id.to_string(),
            boundary_id: boundary_id.to_string(),
            content_hash,
            authority_signature: authority_signature.to_vec(),
        })
    }

    /// Compute the canonical content hash for a declassification receipt.
    ///
    /// Uses domain-separated, length-prefixed hashing to prevent
    /// delimiter-boundary collision attacks. Each variable-length field
    /// is preceded by its byte length as a little-endian `u64`.
    fn compute_receipt_hash(
        from: ConfidentialityLevel,
        to: ConfidentialityLevel,
        rule_id: &str,
        justification: &str,
        authority_id: &str,
        boundary_id: &str,
    ) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        // Domain separation tag to bind this hash to receipt semantics.
        hasher.update(b"apm2.declassification-receipt.v1");
        // Fixed-length fields: from and to ordinals.
        hasher.update(&[from.ordinal()]);
        hasher.update(&[to.ordinal()]);
        // Length-prefixed variable-length fields.
        Self::hash_length_prefixed(&mut hasher, rule_id.as_bytes());
        Self::hash_length_prefixed(&mut hasher, justification.as_bytes());
        Self::hash_length_prefixed(&mut hasher, authority_id.as_bytes());
        Self::hash_length_prefixed(&mut hasher, boundary_id.as_bytes());
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
            receipt.policy_ref(),
            receipt.justification(),
            receipt.authority_id(),
            receipt.boundary_id(),
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
    // TODO(TCK-00420): Wire into work-object instruction flow
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

    /// Propagate a label through a boundary crossing with an explicit
    /// declassification receipt.
    ///
    /// The receipt must:
    /// 1. Have field sizes within the configured `MAX_*` limits (re-validated
    ///    at consumption time to reject oversized deserialized receipts).
    /// 2. Have a valid content hash (recomputed and verified against the
    ///    receipt's claimed hash to detect forged/tampered receipts).
    /// 3. Have a valid authority signature verified via the supplied
    ///    [`SignatureVerifier`]. If `verifier` is `None`, the receipt is
    ///    **rejected** (fail-closed).
    /// 4. Reference a `policy_ref` that maps to an active declassification rule
    ///    authorizing the `from_level -> to_level` transition.
    /// 5. Be scoped to the same `boundary_id` being crossed.
    /// 6. Declassify from at least `label.confidentiality` down to at most
    ///    `boundary.max_confidentiality`.
    ///
    /// If the label already fits within the boundary clearance the receipt
    /// is still fully validated (size limits, hash, signature, `policy_ref`,
    /// boundary binding) but the label passes through unchanged.
    ///
    /// # Errors
    ///
    /// - [`TaintError::ReceiptFieldSizeExceeded`] if any receipt field exceeds
    ///   its maximum allowed size.
    /// - [`TaintError::BoundaryCrossingDenied`] if the boundary is unknown
    ///   (fail-closed), the receipt content hash is invalid, the receipt's
    ///   `policy_ref` does not map to an active rule authorizing the
    ///   transition, the receipt is not scoped to this boundary, or the receipt
    ///   does not cover the required downgrade range.
    /// - [`TaintError::SignatureVerificationFailed`] if the authority signature
    ///   is invalid or no verifier is provided (fail-closed).
    /// - [`TaintError::TaintCeilingExceeded`] if taint exceeds the boundary
    ///   ceiling.
    // TODO(TCK-00422): Wire into daemon actuation path
    pub fn propagate_with_declassification(
        &self,
        boundary_id: &str,
        label: &DataLabel,
        receipt: &DeclassificationReceipt,
        verifier: Option<&dyn SignatureVerifier>,
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

        // ---- Receipt integrity verification ----
        // 1. Recompute the content hash and verify it matches the receipt's claimed
        //    hash. This rejects forged or deserialized receipts whose fields have been
        //    tampered with.
        if !Self::verify_receipt_hash(receipt) {
            return Err(TaintError::BoundaryCrossingDenied {
                boundary: boundary_id.to_string(),
                reason: "receipt content hash verification failed (forged or tampered receipt)"
                    .to_string(),
            });
        }

        // ---- Authority signature verification (BLOCKER fix) ----
        // Verify the receipt's authority signature using the caller-supplied
        // verifier. If no verifier is provided, fail-closed.
        Self::verify_authority_signature(receipt, verifier)?;

        // 2. Verify that the receipt's policy_ref maps to an active declassification
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
        if label
            .confidentiality
            .within_clearance(boundary.max_confidentiality())
        {
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

        DualLatticePolicy::new(boundaries, declass_rules)
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
        let policy = DualLatticePolicy::new(vec![], vec![]);
        let label = DataLabel::TRUSTED_PUBLIC;
        assert!(policy.check_actuator_tier(3, &label).is_err());
    }

    #[test]
    fn actuator_tier_below_3_passes_without_boundary() {
        // Tiers below 3 do not require boundary policies.
        let policy = DualLatticePolicy::new(vec![], vec![]);
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
                "DECLASS-SECRET-TO-INTERNAL",
                "Approved by security review SR-2026-042",
                "security-officer-1",
                "external-api",
                VALID_TEST_SIG,
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
        let r1 = policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Internal,
                "DECLASS-SECRET-TO-INTERNAL",
                "same justification",
                "authority-1",
                "external-api",
                VALID_TEST_SIG,
            )
            .unwrap();
        let r2 = policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Internal,
                "DECLASS-SECRET-TO-INTERNAL",
                "same justification",
                "authority-1",
                "external-api",
                VALID_TEST_SIG,
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
                "DECLASS-SECRET-TO-INTERNAL",
                "justification A",
                "authority-1",
                "external-api",
                VALID_TEST_SIG,
            )
            .unwrap();
        let r2 = policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Internal,
                "DECLASS-SECRET-TO-INTERNAL",
                "justification B",
                "authority-1",
                "external-api",
                VALID_TEST_SIG,
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
                "DECLASS-SECRET-TO-INTERNAL",
                "same justification",
                "authority-A",
                "external-api",
                VALID_TEST_SIG,
            )
            .unwrap();
        let r2 = policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Internal,
                "DECLASS-SECRET-TO-INTERNAL",
                "same justification",
                "authority-B",
                "external-api",
                VALID_TEST_SIG,
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
                "DECLASS-SECRET-TO-INTERNAL",
                "same justification",
                "authority-1",
                "external-api",
                VALID_TEST_SIG,
            )
            .unwrap();
        let r2 = policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Internal,
                "DECLASS-SECRET-TO-INTERNAL",
                "same justification",
                "authority-1",
                "tier3-actuator",
                VALID_TEST_SIG,
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
                "DECLASS-SECRET-TO-INTERNAL",
                "trying to leak",
                "authority-1",
                "external-api",
                VALID_TEST_SIG,
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
                "NONEXISTENT-RULE",
                "no such rule",
                "authority-1",
                "external-api",
                VALID_TEST_SIG,
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
                "DECLASS-SECRET-TO-INTERNAL",
                "upgrade attempt",
                "authority-1",
                "external-api",
                VALID_TEST_SIG,
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
                "DECLASS-SECRET-TO-INTERNAL",
                "no-op attempt",
                "authority-1",
                "external-api",
                VALID_TEST_SIG,
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
                "",
                "missing ref",
                "authority-1",
                "external-api",
                VALID_TEST_SIG,
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
                "DECLASS-SECRET-TO-INTERNAL",
                &long_just,
                "authority-1",
                "external-api",
                VALID_TEST_SIG,
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
                "DECLASS-SECRET-TO-INTERNAL",
                "valid justification",
                "",
                "external-api",
                VALID_TEST_SIG,
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
                "DECLASS-SECRET-TO-INTERNAL",
                "valid justification",
                "authority-1",
                "",
                VALID_TEST_SIG,
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
                "DECLASS-SECRET-TO-INTERNAL",
                "valid justification",
                &long_auth,
                "external-api",
                VALID_TEST_SIG,
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
                "DECLASS-SECRET-TO-INTERNAL",
                "valid justification",
                "authority-1",
                &long_bnd,
                VALID_TEST_SIG,
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
                "DECLASS-SECRET-TO-INTERNAL",
                "step 1",
                "authority-1",
                "external-api",
                VALID_TEST_SIG,
            )
            .unwrap();
        assert_eq!(r1.to_level(), ConfidentialityLevel::Internal);

        let r2 = policy
            .declassify(
                ConfidentialityLevel::Internal,
                ConfidentialityLevel::Public,
                "DECLASS-INTERNAL-TO-PUBLIC",
                "step 2",
                "authority-1",
                "tier4-actuator",
                VALID_TEST_SIG,
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
        let policy = test_policy();
        let label = DataLabel::new(TaintLevel::Untainted, ConfidentialityLevel::Secret);

        let receipt = policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Internal,
                "DECLASS-SECRET-TO-INTERNAL",
                "Approved for external release",
                "security-officer-1",
                "external-api",
                VALID_TEST_SIG,
            )
            .unwrap();

        let result = policy
            .propagate_with_declassification("external-api", &label, &receipt, Some(&TestVerifier))
            .unwrap();
        assert_eq!(result.taint, TaintLevel::Untainted);
        assert_eq!(result.confidentiality, ConfidentialityLevel::Internal);
    }

    #[test]
    fn propagation_with_receipt_rejects_wrong_boundary() {
        // A receipt scoped to a different boundary must be rejected.
        let policy = test_policy();
        let label = DataLabel::new(TaintLevel::Untainted, ConfidentialityLevel::Secret);

        // Receipt scoped to "tier3-actuator", not "external-api".
        let receipt = policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Internal,
                "DECLASS-SECRET-TO-INTERNAL",
                "wrong boundary",
                "security-officer-1",
                "tier3-actuator",
                VALID_TEST_SIG,
            )
            .unwrap();

        let err = policy
            .propagate_with_declassification("external-api", &label, &receipt, Some(&TestVerifier))
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
        let policy = test_policy();
        let label = DataLabel::new(TaintLevel::Untainted, ConfidentialityLevel::Public);

        let receipt = policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Internal,
                "DECLASS-SECRET-TO-INTERNAL",
                "not needed but valid",
                "security-officer-1",
                "external-api",
                VALID_TEST_SIG,
            )
            .unwrap();

        let result = policy
            .propagate_with_declassification("external-api", &label, &receipt, Some(&TestVerifier))
            .unwrap();
        assert_eq!(result, label);
    }

    #[test]
    fn propagation_with_receipt_rejects_insufficient_downgrade() {
        // Receipt's to_level is still above the boundary's max_confidentiality.
        let policy = test_policy();
        // tier4-actuator max_confidentiality = Public
        let label = DataLabel::new(TaintLevel::Untainted, ConfidentialityLevel::Secret);

        // Receipt only goes down to Internal, but tier4 requires Public.
        let receipt = policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Internal,
                "DECLASS-SECRET-TO-INTERNAL",
                "insufficient downgrade",
                "security-officer-1",
                "tier4-actuator",
                VALID_TEST_SIG,
            )
            .unwrap();

        let err = policy
            .propagate_with_declassification(
                "tier4-actuator",
                &label,
                &receipt,
                Some(&TestVerifier),
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
                "DECLASS-SECRET-TO-INTERNAL",
                "trying to skip levels",
                "authority-1",
                "external-api",
                VALID_TEST_SIG,
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
                "DECLASS-SECRET-TO-INTERNAL",
                "reverse declassification attempt",
                "authority-1",
                "external-api",
                VALID_TEST_SIG,
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
        let policy = DualLatticePolicy::new(vec![], vec![]);
        let err = policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Public,
                "ANY-RULE",
                "no rules exist",
                "authority-1",
                "some-boundary",
                VALID_TEST_SIG,
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
        let policy = test_policy();
        let label = DataLabel::new(TaintLevel::Untainted, ConfidentialityLevel::Secret);

        // Create a legitimate receipt first, then forge the hash.
        let legit = policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Internal,
                "DECLASS-SECRET-TO-INTERNAL",
                "legitimate",
                "security-officer-1",
                "external-api",
                VALID_TEST_SIG,
            )
            .unwrap();

        // Forge: construct via serde with a zeroed hash.
        let forged_json = serde_json::json!({
            "from_level": "Secret",
            "to_level": "Internal",
            "policy_ref": legit.policy_ref(),
            "justification": "FORGED justification",
            "authority_id": legit.authority_id(),
            "boundary_id": legit.boundary_id(),
            "content_hash": vec![0u8; 32],
        });
        let forged: DeclassificationReceipt = serde_json::from_value(forged_json).unwrap();

        let err = policy
            .propagate_with_declassification("external-api", &label, &forged, Some(&TestVerifier))
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
        let policy = test_policy();
        let label = DataLabel::new(TaintLevel::Untainted, ConfidentialityLevel::Secret);

        let legit = policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Internal,
                "DECLASS-SECRET-TO-INTERNAL",
                "legitimate",
                "security-officer-1",
                "external-api",
                VALID_TEST_SIG,
            )
            .unwrap();

        // Tamper: change to_level to Public but keep the old hash.
        let tampered_json = serde_json::json!({
            "from_level": "Secret",
            "to_level": "Public",
            "policy_ref": legit.policy_ref(),
            "justification": legit.justification(),
            "authority_id": legit.authority_id(),
            "boundary_id": legit.boundary_id(),
            "content_hash": legit.content_hash(),
        });
        let tampered: DeclassificationReceipt = serde_json::from_value(tampered_json).unwrap();

        let err = policy
            .propagate_with_declassification("external-api", &label, &tampered, Some(&TestVerifier))
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
        let policy = test_policy();
        let label = DataLabel::new(TaintLevel::Untainted, ConfidentialityLevel::Secret);

        // Compute a valid hash for a nonexistent rule.
        let hash = DualLatticePolicy::compute_receipt_hash(
            ConfidentialityLevel::Secret,
            ConfidentialityLevel::Internal,
            "NONEXISTENT-RULE",
            "trying to bypass",
            "attacker",
            "external-api",
        );

        let forged_json = serde_json::json!({
            "from_level": "Secret",
            "to_level": "Internal",
            "policy_ref": "NONEXISTENT-RULE",
            "justification": "trying to bypass",
            "authority_id": "attacker",
            "boundary_id": "external-api",
            "content_hash": hash,
            "authority_signature": VALID_TEST_SIG,
        });
        let forged: DeclassificationReceipt = serde_json::from_value(forged_json).unwrap();

        let err = policy
            .propagate_with_declassification("external-api", &label, &forged, Some(&TestVerifier))
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
        let policy = test_policy();
        let label = DataLabel::new(TaintLevel::Untainted, ConfidentialityLevel::TopSecret);

        let hash = DualLatticePolicy::compute_receipt_hash(
            ConfidentialityLevel::TopSecret,
            ConfidentialityLevel::Public,
            "DECLASS-SECRET-TO-INTERNAL",
            "level skip",
            "attacker",
            "external-api",
        );

        let forged_json = serde_json::json!({
            "from_level": "TopSecret",
            "to_level": "Public",
            "policy_ref": "DECLASS-SECRET-TO-INTERNAL",
            "justification": "level skip",
            "authority_id": "attacker",
            "boundary_id": "external-api",
            "content_hash": hash,
            "authority_signature": VALID_TEST_SIG,
        });
        let forged: DeclassificationReceipt = serde_json::from_value(forged_json).unwrap();

        let err = policy
            .propagate_with_declassification("external-api", &label, &forged, Some(&TestVerifier))
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
        let policy = test_policy();
        let label = DataLabel::new(TaintLevel::Untainted, ConfidentialityLevel::Secret);
        let receipt = policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Internal,
                "DECLASS-SECRET-TO-INTERNAL",
                "valid request",
                "security-officer-1",
                "external-api",
                VALID_TEST_SIG,
            )
            .unwrap();

        let err = policy
            .propagate_with_declassification("external-api", &label, &receipt, None)
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
        let policy = test_policy();
        let label = DataLabel::new(TaintLevel::Untainted, ConfidentialityLevel::Secret);
        let receipt = policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Internal,
                "DECLASS-SECRET-TO-INTERNAL",
                "valid request",
                "security-officer-1",
                "external-api",
                &[], // empty signature
            )
            .unwrap();

        let err = policy
            .propagate_with_declassification("external-api", &label, &receipt, Some(&TestVerifier))
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
        let policy = test_policy();
        let label = DataLabel::new(TaintLevel::Untainted, ConfidentialityLevel::Secret);
        let receipt = policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Internal,
                "DECLASS-SECRET-TO-INTERNAL",
                "valid request",
                "security-officer-1",
                "external-api",
                INVALID_TEST_SIG,
            )
            .unwrap();

        let err = policy
            .propagate_with_declassification("external-api", &label, &receipt, Some(&TestVerifier))
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
        let policy = test_policy();
        let label = DataLabel::new(TaintLevel::Untainted, ConfidentialityLevel::Secret);
        let receipt = policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Internal,
                "DECLASS-SECRET-TO-INTERNAL",
                "approved release",
                "security-officer-1",
                "external-api",
                VALID_TEST_SIG,
            )
            .unwrap();

        let result = policy
            .propagate_with_declassification("external-api", &label, &receipt, Some(&TestVerifier))
            .unwrap();
        assert_eq!(result.confidentiality, ConfidentialityLevel::Internal);
    }

    // =========================================================================
    // MAJOR: Receipt field size validation at consumption time tests
    // =========================================================================

    #[test]
    fn oversized_policy_ref_rejected_at_consumption() {
        let policy = test_policy();
        let label = DataLabel::new(TaintLevel::Untainted, ConfidentialityLevel::Secret);

        // Create a receipt with an oversized policy_ref via deserialization.
        let legit = policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Internal,
                "DECLASS-SECRET-TO-INTERNAL",
                "valid",
                "authority-1",
                "external-api",
                VALID_TEST_SIG,
            )
            .unwrap();

        let oversized_ref = "X".repeat(MAX_POLICY_REF_LEN + 1);
        let forged_json = serde_json::json!({
            "from_level": "Secret",
            "to_level": "Internal",
            "policy_ref": oversized_ref,
            "justification": legit.justification(),
            "authority_id": legit.authority_id(),
            "boundary_id": legit.boundary_id(),
            "content_hash": legit.content_hash(),
            "authority_signature": VALID_TEST_SIG,
        });
        let forged: DeclassificationReceipt = serde_json::from_value(forged_json).unwrap();

        let err = policy
            .propagate_with_declassification("external-api", &label, &forged, Some(&TestVerifier))
            .unwrap_err();
        assert!(
            matches!(err, TaintError::ReceiptFieldSizeExceeded { .. }),
            "oversized policy_ref must be rejected, got {err:?}"
        );
    }

    #[test]
    fn oversized_justification_rejected_at_consumption() {
        let policy = test_policy();
        let label = DataLabel::new(TaintLevel::Untainted, ConfidentialityLevel::Secret);

        let legit = policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Internal,
                "DECLASS-SECRET-TO-INTERNAL",
                "valid",
                "authority-1",
                "external-api",
                VALID_TEST_SIG,
            )
            .unwrap();

        let oversized_just = "Y".repeat(MAX_JUSTIFICATION_LEN + 1);
        let forged_json = serde_json::json!({
            "from_level": "Secret",
            "to_level": "Internal",
            "policy_ref": legit.policy_ref(),
            "justification": oversized_just,
            "authority_id": legit.authority_id(),
            "boundary_id": legit.boundary_id(),
            "content_hash": legit.content_hash(),
            "authority_signature": VALID_TEST_SIG,
        });
        let forged: DeclassificationReceipt = serde_json::from_value(forged_json).unwrap();

        let err = policy
            .propagate_with_declassification("external-api", &label, &forged, Some(&TestVerifier))
            .unwrap_err();
        assert!(
            matches!(err, TaintError::ReceiptFieldSizeExceeded { .. }),
            "oversized justification must be rejected, got {err:?}"
        );
    }

    #[test]
    fn oversized_authority_id_rejected_at_consumption() {
        let policy = test_policy();
        let label = DataLabel::new(TaintLevel::Untainted, ConfidentialityLevel::Secret);

        let legit = policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Internal,
                "DECLASS-SECRET-TO-INTERNAL",
                "valid",
                "authority-1",
                "external-api",
                VALID_TEST_SIG,
            )
            .unwrap();

        let oversized_auth = "Z".repeat(MAX_AUTHORITY_ID_LEN + 1);
        let forged_json = serde_json::json!({
            "from_level": "Secret",
            "to_level": "Internal",
            "policy_ref": legit.policy_ref(),
            "justification": legit.justification(),
            "authority_id": oversized_auth,
            "boundary_id": legit.boundary_id(),
            "content_hash": legit.content_hash(),
            "authority_signature": VALID_TEST_SIG,
        });
        let forged: DeclassificationReceipt = serde_json::from_value(forged_json).unwrap();

        let err = policy
            .propagate_with_declassification("external-api", &label, &forged, Some(&TestVerifier))
            .unwrap_err();
        assert!(
            matches!(err, TaintError::ReceiptFieldSizeExceeded { .. }),
            "oversized authority_id must be rejected, got {err:?}"
        );
    }

    #[test]
    fn oversized_boundary_id_rejected_at_consumption() {
        let policy = test_policy();
        let label = DataLabel::new(TaintLevel::Untainted, ConfidentialityLevel::Secret);

        let legit = policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Internal,
                "DECLASS-SECRET-TO-INTERNAL",
                "valid",
                "authority-1",
                "external-api",
                VALID_TEST_SIG,
            )
            .unwrap();

        let oversized_bnd = "W".repeat(MAX_BOUNDARY_ID_LEN + 1);
        let forged_json = serde_json::json!({
            "from_level": "Secret",
            "to_level": "Internal",
            "policy_ref": legit.policy_ref(),
            "justification": legit.justification(),
            "authority_id": legit.authority_id(),
            "boundary_id": oversized_bnd,
            "content_hash": legit.content_hash(),
            "authority_signature": VALID_TEST_SIG,
        });
        let forged: DeclassificationReceipt = serde_json::from_value(forged_json).unwrap();

        let err = policy
            .propagate_with_declassification("external-api", &label, &forged, Some(&TestVerifier))
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
        let extended_policy = DualLatticePolicy::new(boundaries, declass_rules);

        let r1 = extended_policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Internal,
                "DECLASS-SECRET-TO-INTERNAL",
                "same-justification",
                "ab",
                "cd",
                VALID_TEST_SIG,
            )
            .unwrap();

        let r2 = extended_policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Internal,
                "DECLASS-SECRET-TO-INTERNAL",
                "same-justification",
                "abc",
                "d",
                VALID_TEST_SIG,
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
        let policy = DualLatticePolicy::new(boundaries, declass_rules);

        let r1 = policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Internal,
                "RULE",
                "JUST",
                "auth",
                "boundary",
                VALID_TEST_SIG,
            )
            .unwrap();
        let r2 = policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Internal,
                "RULEJ",
                "UST",
                "auth",
                "boundary",
                VALID_TEST_SIG,
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
