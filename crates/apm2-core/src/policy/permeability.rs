// AGENT-AUTHORED
//! Permeability authority lattice meet algorithm enforcement (TCK-00373,
//! REQ-0027).
//!
//! This module implements the permeability delegation meet algorithm that
//! enforces the strict-subset rule: delegated authority D MUST equal
//! `meet(A, O)` (greatest lower bound) across all [`PermeabilityFacet`]
//! dimensions.
//!
//! # Authority Vector Dimensions
//!
//! Each [`AuthorityVector`] carries a level for every facet:
//!
//! - **Risk**: Risk tier classification (High > Med > Low)
//! - **Capability**: Capability scope (Full > `ReadWrite` > `ReadOnly` > None)
//! - **Budget**: Budget allowance (Unlimited > Capped(n) > Zero)
//! - **`StopPredicate`**: Stop predicate authority (Override > Extend > Inherit
//!   > Deny)
//! - **Taint**: Taint propagation ceiling (Adversarial > Untrusted > Attested >
//!   Trusted)
//! - **Classification**: Data classification (TopSecret > Secret > Confidential
//!   > Public)
//!
//! # Lattice Meet (Greatest Lower Bound)
//!
//! `lattice_meet(A, O)` computes D where for each facet, `D[f] = min(A[f],
//! O[f])`. This guarantees that delegation never widens authority: `D <= A` and
//! `D <= O`.
//!
//! # Permeability Receipt
//!
//! [`PermeabilityReceipt`] binds a delegation to its computed authority
//! vector, the parent authority hash, the overlay hash, and the resulting
//! delegation hash. Receipt admission verifies `D == meet(A, O)` and
//! rejects unverifiable overlays.
//!
//! # Security Properties
//!
//! - **Fail-closed**: Missing, unverifiable, expired, or revoked delegation
//!   receipts deny actuation
//! - **Strict-subset**: Widening attempts are deterministically denied
//! - **Deterministic**: Meet algorithm produces identical results across
//!   implementations
//! - **Recursion-depth resistant**: Multi-level delegation chains (depth >= 4)
//!   cannot launder additional authority
//!
//! # Example
//!
//! ```rust
//! use apm2_core::policy::permeability::{
//!     AuthorityVector, BudgetLevel, CapabilityLevel, ClassificationLevel, PermeabilityReceipt,
//!     RiskLevel, StopPredicateLevel, TaintCeiling, lattice_meet,
//! };
//!
//! let parent = AuthorityVector::new(
//!     RiskLevel::High,
//!     CapabilityLevel::ReadWrite,
//!     BudgetLevel::Capped(5000),
//!     StopPredicateLevel::Extend,
//!     TaintCeiling::Untrusted,
//!     ClassificationLevel::Secret,
//! );
//!
//! let overlay = AuthorityVector::new(
//!     RiskLevel::Med,
//!     CapabilityLevel::Full,
//!     BudgetLevel::Capped(10000),
//!     StopPredicateLevel::Override,
//!     TaintCeiling::Attested,
//!     ClassificationLevel::Confidential,
//! );
//!
//! let delegated = lattice_meet(&parent, &overlay);
//!
//! // Each facet takes the minimum of parent and overlay
//! assert_eq!(delegated.risk, RiskLevel::Med);
//! assert_eq!(delegated.capability, CapabilityLevel::ReadWrite);
//! assert_eq!(delegated.budget, BudgetLevel::Capped(5000));
//! assert_eq!(delegated.stop_predicate, StopPredicateLevel::Extend);
//! assert_eq!(delegated.taint, TaintCeiling::Attested);
//! assert_eq!(delegated.classification, ClassificationLevel::Confidential);
//! ```
//!
//! # Contract References
//!
//! - TCK-00373: Permeability authority lattice meet algorithm enforcement
//! - REQ-0027: Permeability authority lattice meet enforcement
//! - `HOLONIC_SUBSTRATE_INTERFACE.md` Section 8.3.1 - 8.3.3

use serde::{Deserialize, Serialize};
use thiserror::Error;

// =============================================================================
// Constants
// =============================================================================

/// Maximum recursion depth for delegation chains.
///
/// Chains deeper than this are rejected to prevent authority laundering
/// through multi-level re-delegation.
pub const MAX_DELEGATION_DEPTH: u32 = 16;

/// Maximum length for actor ID strings in receipts.
pub const MAX_ACTOR_ID_LENGTH: usize = 256;

/// Maximum length for receipt ID strings.
pub const MAX_RECEIPT_ID_LENGTH: usize = 256;

// =============================================================================
// PermeabilityFacet
// =============================================================================

/// Enumeration of authority vector dimensions.
///
/// Each facet represents an independent axis of authority that is subject
/// to the lattice meet (greatest lower bound) during delegation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum PermeabilityFacet {
    /// Risk tier authority ceiling.
    Risk,
    /// Capability scope (tool access breadth).
    Capability,
    /// Budget allowance (token / operation caps).
    Budget,
    /// Stop predicate authority (ability to override / extend stop conditions).
    StopPredicate,
    /// Taint propagation ceiling.
    Taint,
    /// Data classification ceiling.
    Classification,
}

impl PermeabilityFacet {
    /// Returns an iterator over all facets in canonical order.
    pub fn all() -> impl Iterator<Item = Self> {
        [
            Self::Risk,
            Self::Capability,
            Self::Budget,
            Self::StopPredicate,
            Self::Taint,
            Self::Classification,
        ]
        .into_iter()
    }
}

// =============================================================================
// Per-Facet Level Types
// =============================================================================

/// Risk tier authority level.
///
/// Ordered: `High > Med > Low`. The meet of two risk levels is the minimum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[repr(u8)]
pub enum RiskLevel {
    /// Lowest risk authority.
    Low  = 0,
    /// Medium risk authority.
    Med  = 1,
    /// Highest risk authority.
    High = 2,
}

impl RiskLevel {
    /// Returns the numeric rank (higher = more authority).
    #[must_use]
    pub const fn rank(self) -> u8 {
        self as u8
    }
}

impl PartialOrd for RiskLevel {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for RiskLevel {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.rank().cmp(&other.rank())
    }
}

/// Capability scope authority level.
///
/// Ordered: `Full > ReadWrite > ReadOnly > None`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[repr(u8)]
pub enum CapabilityLevel {
    /// No capabilities granted.
    None      = 0,
    /// Read-only access.
    ReadOnly  = 1,
    /// Read and write access.
    ReadWrite = 2,
    /// Full capabilities.
    Full      = 3,
}

impl CapabilityLevel {
    /// Returns the numeric rank (higher = more authority).
    #[must_use]
    pub const fn rank(self) -> u8 {
        self as u8
    }
}

impl PartialOrd for CapabilityLevel {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for CapabilityLevel {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.rank().cmp(&other.rank())
    }
}

/// Budget allowance authority level.
///
/// Ordered: `Unlimited > Capped(n) > Zero`. For two `Capped` values,
/// the one with the higher cap has more authority. The meet of two
/// `Capped` values takes the minimum cap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BudgetLevel {
    /// Zero budget (no operations allowed).
    Zero,
    /// Capped budget with a specific limit.
    Capped(u64),
    /// Unlimited budget.
    Unlimited,
}

impl BudgetLevel {
    /// Returns a rank for ordering. Capped values use rank 1 with
    /// the cap value distinguishing them.
    #[must_use]
    pub const fn coarse_rank(self) -> u8 {
        match self {
            Self::Zero => 0,
            Self::Capped(_) => 1,
            Self::Unlimited => 2,
        }
    }
}

impl PartialOrd for BudgetLevel {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for BudgetLevel {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match (self, other) {
            (Self::Zero, Self::Zero) | (Self::Unlimited, Self::Unlimited) => {
                std::cmp::Ordering::Equal
            },
            (Self::Zero, _) | (_, Self::Unlimited) => std::cmp::Ordering::Less,
            (_, Self::Zero) | (Self::Unlimited, _) => std::cmp::Ordering::Greater,
            (Self::Capped(a), Self::Capped(b)) => a.cmp(b),
        }
    }
}

/// Stop predicate authority level.
///
/// Ordered: `Override > Extend > Inherit > Deny`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[repr(u8)]
pub enum StopPredicateLevel {
    /// Cannot use stop predicates.
    Deny     = 0,
    /// Inherit stop predicates from parent.
    Inherit  = 1,
    /// Can extend stop predicates with additional conditions.
    Extend   = 2,
    /// Can override stop predicates entirely.
    Override = 3,
}

impl StopPredicateLevel {
    /// Returns the numeric rank (higher = more authority).
    #[must_use]
    pub const fn rank(self) -> u8 {
        self as u8
    }
}

impl PartialOrd for StopPredicateLevel {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for StopPredicateLevel {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.rank().cmp(&other.rank())
    }
}

/// Taint propagation ceiling.
///
/// Ordered: `Adversarial > Untrusted > Attested > Trusted`.
/// The meet of two taint ceilings takes the minimum (most restrictive).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[repr(u8)]
pub enum TaintCeiling {
    /// Only trusted content.
    Trusted     = 0,
    /// Up to attested content.
    Attested    = 1,
    /// Up to untrusted content.
    Untrusted   = 2,
    /// Up to adversarial content.
    Adversarial = 3,
}

impl TaintCeiling {
    /// Returns the numeric rank (higher = more permissive).
    #[must_use]
    pub const fn rank(self) -> u8 {
        self as u8
    }
}

impl PartialOrd for TaintCeiling {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for TaintCeiling {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.rank().cmp(&other.rank())
    }
}

/// Data classification ceiling.
///
/// Ordered: `TopSecret > Secret > Confidential > Public`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[repr(u8)]
pub enum ClassificationLevel {
    /// Public data.
    Public       = 0,
    /// Confidential data.
    Confidential = 1,
    /// Secret data.
    Secret       = 2,
    /// Top-secret data.
    TopSecret    = 3,
}

impl ClassificationLevel {
    /// Returns the numeric rank (higher = more authority).
    #[must_use]
    pub const fn rank(self) -> u8 {
        self as u8
    }
}

impl PartialOrd for ClassificationLevel {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ClassificationLevel {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.rank().cmp(&other.rank())
    }
}

// =============================================================================
// AuthorityVector
// =============================================================================

/// A complete authority vector across all permeability facets.
///
/// Each field represents the authority level for one facet. The lattice
/// meet of two vectors computes the componentwise minimum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub struct AuthorityVector {
    /// Risk tier authority.
    pub risk: RiskLevel,
    /// Capability scope authority.
    pub capability: CapabilityLevel,
    /// Budget allowance.
    pub budget: BudgetLevel,
    /// Stop predicate authority.
    pub stop_predicate: StopPredicateLevel,
    /// Taint propagation ceiling.
    pub taint: TaintCeiling,
    /// Data classification ceiling.
    pub classification: ClassificationLevel,
}

impl AuthorityVector {
    /// Creates a new authority vector with explicit levels for all facets.
    #[must_use]
    pub const fn new(
        risk: RiskLevel,
        capability: CapabilityLevel,
        budget: BudgetLevel,
        stop_predicate: StopPredicateLevel,
        taint: TaintCeiling,
        classification: ClassificationLevel,
    ) -> Self {
        Self {
            risk,
            capability,
            budget,
            stop_predicate,
            taint,
            classification,
        }
    }

    /// Creates the maximum authority vector (top element of the lattice).
    #[must_use]
    pub const fn top() -> Self {
        Self {
            risk: RiskLevel::High,
            capability: CapabilityLevel::Full,
            budget: BudgetLevel::Unlimited,
            stop_predicate: StopPredicateLevel::Override,
            taint: TaintCeiling::Adversarial,
            classification: ClassificationLevel::TopSecret,
        }
    }

    /// Creates the minimum authority vector (bottom element of the lattice).
    #[must_use]
    pub const fn bottom() -> Self {
        Self {
            risk: RiskLevel::Low,
            capability: CapabilityLevel::None,
            budget: BudgetLevel::Zero,
            stop_predicate: StopPredicateLevel::Deny,
            taint: TaintCeiling::Trusted,
            classification: ClassificationLevel::Public,
        }
    }

    /// Returns true if `self` is a subset of (less than or equal to) `other`
    /// across all facets.
    #[must_use]
    pub fn is_subset_of(&self, other: &Self) -> bool {
        self.risk <= other.risk
            && self.capability <= other.capability
            && self.budget <= other.budget
            && self.stop_predicate <= other.stop_predicate
            && self.taint <= other.taint
            && self.classification <= other.classification
    }

    /// Returns true if `self` is strictly less than `other` in at least one
    /// facet and no greater in any facet.
    #[must_use]
    pub fn is_strict_subset_of(&self, other: &Self) -> bool {
        self.is_subset_of(other) && self != other
    }

    /// Computes the BLAKE3 hash of this authority vector in canonical form.
    ///
    /// The canonical form serializes each facet as a big-endian byte in
    /// a fixed order to ensure deterministic hashing across implementations.
    #[must_use]
    pub fn content_hash(&self) -> [u8; 32] {
        let canonical = self.canonical_bytes();
        blake3::hash(&canonical).into()
    }

    /// Returns the canonical byte representation for hashing.
    ///
    /// Format: `[risk_rank, capability_rank, budget_coarse_rank,
    /// budget_cap_be_8bytes, stop_rank, taint_rank, classification_rank]`
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(15);
        buf.push(self.risk.rank());
        buf.push(self.capability.rank());
        buf.push(self.budget.coarse_rank());
        // Encode budget cap value for Capped variant, 0 otherwise
        let cap_value = match self.budget {
            BudgetLevel::Capped(n) => n,
            _ => 0,
        };
        buf.extend_from_slice(&cap_value.to_be_bytes());
        buf.push(self.stop_predicate.rank());
        buf.push(self.taint.rank());
        buf.push(self.classification.rank());
        buf
    }
}

// =============================================================================
// Lattice Meet
// =============================================================================

/// Computes the lattice meet (greatest lower bound) of two authority vectors.
///
/// For each facet, the result is `min(a[facet], b[facet])`. This guarantees
/// the delegation invariant: the resulting authority is a subset of both
/// inputs.
///
/// # Determinism
///
/// This function is pure and deterministic: given the same inputs, it
/// always produces the same output regardless of platform or implementation.
#[must_use]
pub fn lattice_meet(a: &AuthorityVector, b: &AuthorityVector) -> AuthorityVector {
    AuthorityVector {
        risk: std::cmp::min(a.risk, b.risk),
        capability: std::cmp::min(a.capability, b.capability),
        budget: std::cmp::min(a.budget, b.budget),
        stop_predicate: std::cmp::min(a.stop_predicate, b.stop_predicate),
        taint: std::cmp::min(a.taint, b.taint),
        classification: std::cmp::min(a.classification, b.classification),
    }
}

// =============================================================================
// Error Types
// =============================================================================

/// Errors from permeability delegation operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PermeabilityError {
    /// Delegation would widen authority beyond parent.
    #[error("delegation widens authority: delegated vector is not a subset of parent")]
    DelegationWidening,

    /// Delegation would widen authority beyond overlay.
    #[error("delegation widens authority: delegated vector is not a subset of overlay")]
    OverlayWidening,

    /// Delegated authority does not match computed meet.
    #[error("delegated authority does not equal meet(parent, overlay)")]
    MeetMismatch,

    /// Delegation chain exceeds maximum depth.
    #[error("delegation chain depth {depth} exceeds maximum {max}")]
    DepthExceeded {
        /// Actual chain depth.
        depth: u32,
        /// Maximum allowed depth.
        max: u32,
    },

    /// Receipt hash does not match computed value.
    #[error("receipt hash mismatch: expected {expected}, got {actual}")]
    HashMismatch {
        /// Expected hash (hex).
        expected: String,
        /// Actual hash (hex).
        actual: String,
    },

    /// Receipt has been revoked.
    #[error("permeability receipt has been revoked")]
    Revoked,

    /// Receipt has expired.
    #[error("permeability receipt has expired")]
    Expired,

    /// Missing required binding.
    #[error("missing required binding: {field}")]
    MissingBinding {
        /// Name of the missing field.
        field: String,
    },

    /// Receipt ID is empty or exceeds maximum length.
    #[error("invalid receipt ID length: {actual}, max {max}")]
    InvalidReceiptId {
        /// Actual length.
        actual: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Actor ID exceeds maximum length.
    #[error("actor ID length {actual} exceeds max {max}")]
    ActorIdTooLong {
        /// Actual length.
        actual: usize,
        /// Maximum allowed.
        max: usize,
    },
}

// =============================================================================
// PermeabilityReceipt
// =============================================================================

/// A receipt binding a delegation to its computed authority vector.
///
/// The receipt is the proof artifact that delegation was properly computed
/// via the lattice meet algorithm. Downstream consumers MUST bind
/// `permeability_receipt_hash` in their envelopes to prove they operate
/// under a valid delegation.
///
/// # Admission Rule
///
/// A receipt is only valid if:
/// 1. `delegated == meet(parent_authority, overlay)`
/// 2. `delegated.is_subset_of(parent_authority)`
/// 3. `delegated.is_subset_of(overlay)`
/// 4. `delegation_depth <= MAX_DELEGATION_DEPTH`
/// 5. The receipt is not revoked or expired
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct PermeabilityReceipt {
    /// Unique identifier for this receipt.
    pub receipt_id: String,

    /// The parent authority vector (delegator's authority).
    pub parent_authority: AuthorityVector,

    /// The authority overlay (requested authority scope).
    pub overlay: AuthorityVector,

    /// The computed delegated authority vector: `meet(parent, overlay)`.
    pub delegated: AuthorityVector,

    /// BLAKE3 hash of the parent authority vector.
    pub parent_authority_hash: [u8; 32],

    /// BLAKE3 hash of the overlay authority vector.
    pub overlay_hash: [u8; 32],

    /// BLAKE3 hash of the delegated authority vector.
    pub delegated_hash: [u8; 32],

    /// Depth of this delegation in the chain (0 = root, 1 = first delegation,
    /// etc.).
    pub delegation_depth: u32,

    /// Hash of the parent receipt (if this is a chained delegation).
    /// `None` for root-level delegations.
    pub parent_receipt_hash: Option<[u8; 32]>,

    /// Actor ID of the delegator.
    pub delegator_actor_id: String,

    /// Actor ID of the delegate (recipient of authority).
    pub delegate_actor_id: String,

    /// Timestamp (millis since epoch) when this receipt was issued.
    pub issued_at_ms: u64,

    /// Timestamp (millis since epoch) when this receipt expires.
    /// `0` means no expiry.
    pub expires_at_ms: u64,

    /// Whether this receipt has been revoked.
    pub revoked: bool,
}

impl PermeabilityReceipt {
    /// Computes the BLAKE3 hash of this receipt for binding in downstream
    /// envelopes.
    ///
    /// The hash covers all receipt fields: ID, authority hashes, depth,
    /// parent receipt hash, actor IDs, and timestamps.
    #[must_use]
    pub fn content_hash(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(self.receipt_id.as_bytes());
        hasher.update(&self.parent_authority_hash);
        hasher.update(&self.overlay_hash);
        hasher.update(&self.delegated_hash);
        hasher.update(&self.delegation_depth.to_be_bytes());
        if let Some(ref parent_hash) = self.parent_receipt_hash {
            hasher.update(&[1u8]); // presence marker
            hasher.update(parent_hash);
        } else {
            hasher.update(&[0u8]); // absence marker
        }
        hasher.update(self.delegator_actor_id.as_bytes());
        hasher.update(self.delegate_actor_id.as_bytes());
        hasher.update(&self.issued_at_ms.to_be_bytes());
        hasher.update(&self.expires_at_ms.to_be_bytes());
        hasher.finalize().into()
    }

    /// Validates this receipt for admission.
    ///
    /// Checks:
    /// 1. Receipt ID is non-empty and within length limits
    /// 2. Actor IDs are within length limits
    /// 3. `delegated == meet(parent_authority, overlay)`
    /// 4. `delegated` is a subset of `parent_authority`
    /// 5. `delegated` is a subset of `overlay`
    /// 6. Authority hashes match computed values
    /// 7. Delegation depth is within limits
    /// 8. Receipt is not revoked
    /// 9. Receipt is not expired (if `now_ms > 0`)
    ///
    /// # Arguments
    ///
    /// * `now_ms` - Current time in milliseconds since epoch. Pass `0` to skip
    ///   expiry checks.
    ///
    /// # Errors
    ///
    /// Returns [`PermeabilityError`] if any admission check fails.
    pub fn validate_admission(&self, now_ms: u64) -> Result<(), PermeabilityError> {
        // Check receipt ID length
        if self.receipt_id.is_empty() || self.receipt_id.len() > MAX_RECEIPT_ID_LENGTH {
            return Err(PermeabilityError::InvalidReceiptId {
                actual: self.receipt_id.len(),
                max: MAX_RECEIPT_ID_LENGTH,
            });
        }

        // Check actor ID lengths
        if self.delegator_actor_id.len() > MAX_ACTOR_ID_LENGTH {
            return Err(PermeabilityError::ActorIdTooLong {
                actual: self.delegator_actor_id.len(),
                max: MAX_ACTOR_ID_LENGTH,
            });
        }
        if self.delegate_actor_id.len() > MAX_ACTOR_ID_LENGTH {
            return Err(PermeabilityError::ActorIdTooLong {
                actual: self.delegate_actor_id.len(),
                max: MAX_ACTOR_ID_LENGTH,
            });
        }

        // Check revocation
        if self.revoked {
            return Err(PermeabilityError::Revoked);
        }

        // Check expiry
        if self.expires_at_ms > 0 && now_ms > 0 && now_ms > self.expires_at_ms {
            return Err(PermeabilityError::Expired);
        }

        // Check delegation depth
        if self.delegation_depth > MAX_DELEGATION_DEPTH {
            return Err(PermeabilityError::DepthExceeded {
                depth: self.delegation_depth,
                max: MAX_DELEGATION_DEPTH,
            });
        }

        // Compute expected meet
        let expected_meet = lattice_meet(&self.parent_authority, &self.overlay);
        if self.delegated != expected_meet {
            return Err(PermeabilityError::MeetMismatch);
        }

        // Verify subset relationships (redundant with meet check but
        // defense-in-depth)
        if !self.delegated.is_subset_of(&self.parent_authority) {
            return Err(PermeabilityError::DelegationWidening);
        }
        if !self.delegated.is_subset_of(&self.overlay) {
            return Err(PermeabilityError::OverlayWidening);
        }

        // Verify authority hashes
        let parent_hash = self.parent_authority.content_hash();
        if parent_hash != self.parent_authority_hash {
            return Err(PermeabilityError::HashMismatch {
                expected: hex::encode(parent_hash),
                actual: hex::encode(self.parent_authority_hash),
            });
        }

        let overlay_hash = self.overlay.content_hash();
        if overlay_hash != self.overlay_hash {
            return Err(PermeabilityError::HashMismatch {
                expected: hex::encode(overlay_hash),
                actual: hex::encode(self.overlay_hash),
            });
        }

        let delegated_hash = self.delegated.content_hash();
        if delegated_hash != self.delegated_hash {
            return Err(PermeabilityError::HashMismatch {
                expected: hex::encode(delegated_hash),
                actual: hex::encode(self.delegated_hash),
            });
        }

        Ok(())
    }
}

// =============================================================================
// PermeabilityReceiptBuilder
// =============================================================================

/// Builder for constructing [`PermeabilityReceipt`] instances.
///
/// The builder computes the lattice meet and all hashes automatically,
/// ensuring correctness by construction.
pub struct PermeabilityReceiptBuilder {
    receipt_id: String,
    parent_authority: AuthorityVector,
    overlay: AuthorityVector,
    delegation_depth: u32,
    parent_receipt_hash: Option<[u8; 32]>,
    delegator_actor_id: String,
    delegate_actor_id: String,
    issued_at_ms: u64,
    expires_at_ms: u64,
}

impl PermeabilityReceiptBuilder {
    /// Creates a new builder with the required fields.
    #[must_use]
    pub fn new(
        receipt_id: impl Into<String>,
        parent_authority: AuthorityVector,
        overlay: AuthorityVector,
    ) -> Self {
        Self {
            receipt_id: receipt_id.into(),
            parent_authority,
            overlay,
            delegation_depth: 0,
            parent_receipt_hash: None,
            delegator_actor_id: String::new(),
            delegate_actor_id: String::new(),
            issued_at_ms: 0,
            expires_at_ms: 0,
        }
    }

    /// Sets the delegation depth.
    #[must_use]
    pub const fn delegation_depth(mut self, depth: u32) -> Self {
        self.delegation_depth = depth;
        self
    }

    /// Sets the parent receipt hash (for chained delegations).
    #[must_use]
    pub const fn parent_receipt_hash(mut self, hash: [u8; 32]) -> Self {
        self.parent_receipt_hash = Some(hash);
        self
    }

    /// Sets the delegator actor ID.
    #[must_use]
    pub fn delegator_actor_id(mut self, id: impl Into<String>) -> Self {
        self.delegator_actor_id = id.into();
        self
    }

    /// Sets the delegate actor ID.
    #[must_use]
    pub fn delegate_actor_id(mut self, id: impl Into<String>) -> Self {
        self.delegate_actor_id = id.into();
        self
    }

    /// Sets the issued-at timestamp.
    #[must_use]
    pub const fn issued_at_ms(mut self, ms: u64) -> Self {
        self.issued_at_ms = ms;
        self
    }

    /// Sets the expires-at timestamp.
    #[must_use]
    pub const fn expires_at_ms(mut self, ms: u64) -> Self {
        self.expires_at_ms = ms;
        self
    }

    /// Builds the receipt, computing the meet and all hashes.
    ///
    /// # Errors
    ///
    /// Returns `PermeabilityError::DepthExceeded` if the delegation depth
    /// exceeds `MAX_DELEGATION_DEPTH`.
    pub fn build(self) -> Result<PermeabilityReceipt, PermeabilityError> {
        if self.delegation_depth > MAX_DELEGATION_DEPTH {
            return Err(PermeabilityError::DepthExceeded {
                depth: self.delegation_depth,
                max: MAX_DELEGATION_DEPTH,
            });
        }

        let delegated = lattice_meet(&self.parent_authority, &self.overlay);

        Ok(PermeabilityReceipt {
            receipt_id: self.receipt_id,
            parent_authority_hash: self.parent_authority.content_hash(),
            overlay_hash: self.overlay.content_hash(),
            delegated_hash: delegated.content_hash(),
            parent_authority: self.parent_authority,
            overlay: self.overlay,
            delegated,
            delegation_depth: self.delegation_depth,
            parent_receipt_hash: self.parent_receipt_hash,
            delegator_actor_id: self.delegator_actor_id,
            delegate_actor_id: self.delegate_actor_id,
            issued_at_ms: self.issued_at_ms,
            expires_at_ms: self.expires_at_ms,
            revoked: false,
        })
    }
}

// =============================================================================
// Delegation Chain Validation
// =============================================================================

/// Validates a chain of permeability receipts for authority laundering.
///
/// Verifies that each receipt in the chain:
/// 1. Properly computes `meet(parent, overlay)`
/// 2. Links to its predecessor via `parent_receipt_hash`
/// 3. Has monotonically non-increasing authority (no widening at any level)
/// 4. Does not exceed `MAX_DELEGATION_DEPTH`
///
/// # Arguments
///
/// * `chain` - Delegation receipts in order from root (index 0) to leaf.
/// * `now_ms` - Current time for expiry checks. Pass `0` to skip.
///
/// # Errors
///
/// Returns the first error encountered during chain validation.
pub fn validate_delegation_chain(
    chain: &[PermeabilityReceipt],
    now_ms: u64,
) -> Result<(), PermeabilityError> {
    if chain.is_empty() {
        return Err(PermeabilityError::MissingBinding {
            field: "delegation chain is empty".to_string(),
        });
    }

    // Validate depth constraint for the entire chain
    let chain_depth = u32::try_from(chain.len().saturating_sub(1)).unwrap_or(u32::MAX);
    if chain_depth > MAX_DELEGATION_DEPTH {
        return Err(PermeabilityError::DepthExceeded {
            depth: chain_depth,
            max: MAX_DELEGATION_DEPTH,
        });
    }

    // Validate each receipt individually
    for receipt in chain {
        receipt.validate_admission(now_ms)?;
    }

    // Validate chain linkage and monotonic non-widening
    for i in 1..chain.len() {
        let parent = &chain[i - 1];
        let child = &chain[i];

        // Verify parent receipt hash binding
        let parent_hash = parent.content_hash();
        match child.parent_receipt_hash {
            Some(ref linked_hash) if *linked_hash == parent_hash => {},
            Some(ref linked_hash) => {
                return Err(PermeabilityError::HashMismatch {
                    expected: hex::encode(parent_hash),
                    actual: hex::encode(linked_hash),
                });
            },
            None => {
                return Err(PermeabilityError::MissingBinding {
                    field: format!("parent_receipt_hash at chain index {i}"),
                });
            },
        }

        // Verify monotonic non-widening: child's delegated authority must be
        // a subset of parent's delegated authority
        if !child.delegated.is_subset_of(&parent.delegated) {
            return Err(PermeabilityError::DelegationWidening);
        }

        // Verify delegation depth is monotonically increasing
        if child.delegation_depth != parent.delegation_depth + 1 {
            return Err(PermeabilityError::MissingBinding {
                field: format!(
                    "delegation_depth at chain index {i}: expected {}, got {}",
                    parent.delegation_depth + 1,
                    child.delegation_depth
                ),
            });
        }
    }

    Ok(())
}

// =============================================================================
// Consumption Binding
// =============================================================================

/// Validates that an envelope or receipt properly binds a permeability
/// receipt hash and that the bound authority is sufficient for the
/// requested action.
///
/// # Arguments
///
/// * `receipt` - The permeability receipt to validate against.
/// * `bound_hash` - The `permeability_receipt_hash` from the envelope.
/// * `required_authority` - The minimum authority needed for the action.
/// * `now_ms` - Current time for expiry checks. Pass `0` to skip.
///
/// # Errors
///
/// Returns an error if the binding is invalid, the receipt has expired or
/// been revoked, or the delegated authority is insufficient.
pub fn validate_consumption_binding(
    receipt: &PermeabilityReceipt,
    bound_hash: &[u8; 32],
    required_authority: &AuthorityVector,
    now_ms: u64,
) -> Result<(), PermeabilityError> {
    // Validate the receipt itself
    receipt.validate_admission(now_ms)?;

    // Verify the bound hash matches
    let receipt_hash = receipt.content_hash();
    if receipt_hash != *bound_hash {
        return Err(PermeabilityError::HashMismatch {
            expected: hex::encode(receipt_hash),
            actual: hex::encode(bound_hash),
        });
    }

    // Verify the delegated authority is sufficient for the action
    if !required_authority.is_subset_of(&receipt.delegated) {
        return Err(PermeabilityError::DelegationWidening);
    }

    Ok(())
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
#[allow(missing_docs)]
mod tests {
    use super::*;

    // =========================================================================
    // Facet Ordering Tests
    // =========================================================================

    #[test]
    fn test_risk_level_ordering() {
        assert!(RiskLevel::Low < RiskLevel::Med);
        assert!(RiskLevel::Med < RiskLevel::High);
        assert!(RiskLevel::Low < RiskLevel::High);
    }

    #[test]
    fn test_capability_level_ordering() {
        assert!(CapabilityLevel::None < CapabilityLevel::ReadOnly);
        assert!(CapabilityLevel::ReadOnly < CapabilityLevel::ReadWrite);
        assert!(CapabilityLevel::ReadWrite < CapabilityLevel::Full);
    }

    #[test]
    fn test_budget_level_ordering() {
        assert!(BudgetLevel::Zero < BudgetLevel::Capped(1));
        assert!(BudgetLevel::Capped(1) < BudgetLevel::Capped(100));
        assert!(BudgetLevel::Capped(100) < BudgetLevel::Unlimited);
        assert!(BudgetLevel::Zero < BudgetLevel::Unlimited);
    }

    #[test]
    fn test_stop_predicate_level_ordering() {
        assert!(StopPredicateLevel::Deny < StopPredicateLevel::Inherit);
        assert!(StopPredicateLevel::Inherit < StopPredicateLevel::Extend);
        assert!(StopPredicateLevel::Extend < StopPredicateLevel::Override);
    }

    #[test]
    fn test_taint_ceiling_ordering() {
        assert!(TaintCeiling::Trusted < TaintCeiling::Attested);
        assert!(TaintCeiling::Attested < TaintCeiling::Untrusted);
        assert!(TaintCeiling::Untrusted < TaintCeiling::Adversarial);
    }

    #[test]
    fn test_classification_level_ordering() {
        assert!(ClassificationLevel::Public < ClassificationLevel::Confidential);
        assert!(ClassificationLevel::Confidential < ClassificationLevel::Secret);
        assert!(ClassificationLevel::Secret < ClassificationLevel::TopSecret);
    }

    // =========================================================================
    // Authority Vector Tests
    // =========================================================================

    #[test]
    fn test_authority_vector_top_is_maximum() {
        let top = AuthorityVector::top();
        assert_eq!(top.risk, RiskLevel::High);
        assert_eq!(top.capability, CapabilityLevel::Full);
        assert_eq!(top.budget, BudgetLevel::Unlimited);
        assert_eq!(top.stop_predicate, StopPredicateLevel::Override);
        assert_eq!(top.taint, TaintCeiling::Adversarial);
        assert_eq!(top.classification, ClassificationLevel::TopSecret);
    }

    #[test]
    fn test_authority_vector_bottom_is_minimum() {
        let bottom = AuthorityVector::bottom();
        assert_eq!(bottom.risk, RiskLevel::Low);
        assert_eq!(bottom.capability, CapabilityLevel::None);
        assert_eq!(bottom.budget, BudgetLevel::Zero);
        assert_eq!(bottom.stop_predicate, StopPredicateLevel::Deny);
        assert_eq!(bottom.taint, TaintCeiling::Trusted);
        assert_eq!(bottom.classification, ClassificationLevel::Public);
    }

    #[test]
    fn test_bottom_is_subset_of_top() {
        assert!(AuthorityVector::bottom().is_subset_of(&AuthorityVector::top()));
    }

    #[test]
    fn test_top_is_not_subset_of_bottom() {
        assert!(!AuthorityVector::top().is_subset_of(&AuthorityVector::bottom()));
    }

    #[test]
    fn test_vector_is_subset_of_itself() {
        let v = AuthorityVector::new(
            RiskLevel::Med,
            CapabilityLevel::ReadWrite,
            BudgetLevel::Capped(5000),
            StopPredicateLevel::Extend,
            TaintCeiling::Untrusted,
            ClassificationLevel::Secret,
        );
        assert!(v.is_subset_of(&v));
        assert!(!v.is_strict_subset_of(&v));
    }

    #[test]
    fn test_content_hash_deterministic() {
        let v = AuthorityVector::new(
            RiskLevel::High,
            CapabilityLevel::Full,
            BudgetLevel::Capped(42),
            StopPredicateLevel::Override,
            TaintCeiling::Adversarial,
            ClassificationLevel::TopSecret,
        );
        let h1 = v.content_hash();
        let h2 = v.content_hash();
        assert_eq!(h1, h2, "content hash must be deterministic");
    }

    #[test]
    fn test_different_vectors_different_hashes() {
        let a = AuthorityVector::top();
        let b = AuthorityVector::bottom();
        assert_ne!(a.content_hash(), b.content_hash());
    }

    // =========================================================================
    // Lattice Meet Tests
    // =========================================================================

    #[test]
    fn test_meet_identity_with_self() {
        let v = AuthorityVector::new(
            RiskLevel::Med,
            CapabilityLevel::ReadWrite,
            BudgetLevel::Capped(5000),
            StopPredicateLevel::Extend,
            TaintCeiling::Untrusted,
            ClassificationLevel::Secret,
        );
        assert_eq!(lattice_meet(&v, &v), v, "meet(v, v) == v");
    }

    #[test]
    fn test_meet_with_top_is_identity() {
        let v = AuthorityVector::new(
            RiskLevel::Med,
            CapabilityLevel::ReadOnly,
            BudgetLevel::Capped(100),
            StopPredicateLevel::Inherit,
            TaintCeiling::Attested,
            ClassificationLevel::Confidential,
        );
        assert_eq!(lattice_meet(&v, &AuthorityVector::top()), v);
        assert_eq!(lattice_meet(&AuthorityVector::top(), &v), v);
    }

    #[test]
    fn test_meet_with_bottom_is_bottom() {
        let v = AuthorityVector::new(
            RiskLevel::High,
            CapabilityLevel::Full,
            BudgetLevel::Unlimited,
            StopPredicateLevel::Override,
            TaintCeiling::Adversarial,
            ClassificationLevel::TopSecret,
        );
        assert_eq!(
            lattice_meet(&v, &AuthorityVector::bottom()),
            AuthorityVector::bottom()
        );
        assert_eq!(
            lattice_meet(&AuthorityVector::bottom(), &v),
            AuthorityVector::bottom()
        );
    }

    #[test]
    fn test_meet_commutativity() {
        let a = AuthorityVector::new(
            RiskLevel::High,
            CapabilityLevel::ReadWrite,
            BudgetLevel::Capped(5000),
            StopPredicateLevel::Extend,
            TaintCeiling::Untrusted,
            ClassificationLevel::Secret,
        );
        let b = AuthorityVector::new(
            RiskLevel::Med,
            CapabilityLevel::Full,
            BudgetLevel::Capped(10000),
            StopPredicateLevel::Override,
            TaintCeiling::Attested,
            ClassificationLevel::Confidential,
        );
        assert_eq!(
            lattice_meet(&a, &b),
            lattice_meet(&b, &a),
            "meet must be commutative"
        );
    }

    #[test]
    fn test_meet_associativity() {
        let a = AuthorityVector::new(
            RiskLevel::High,
            CapabilityLevel::Full,
            BudgetLevel::Capped(10000),
            StopPredicateLevel::Override,
            TaintCeiling::Adversarial,
            ClassificationLevel::TopSecret,
        );
        let b = AuthorityVector::new(
            RiskLevel::Med,
            CapabilityLevel::ReadWrite,
            BudgetLevel::Capped(5000),
            StopPredicateLevel::Extend,
            TaintCeiling::Untrusted,
            ClassificationLevel::Secret,
        );
        let c = AuthorityVector::new(
            RiskLevel::Low,
            CapabilityLevel::ReadOnly,
            BudgetLevel::Capped(1000),
            StopPredicateLevel::Inherit,
            TaintCeiling::Attested,
            ClassificationLevel::Confidential,
        );
        let ab_c = lattice_meet(&lattice_meet(&a, &b), &c);
        let a_bc = lattice_meet(&a, &lattice_meet(&b, &c));
        assert_eq!(ab_c, a_bc, "meet must be associative");
    }

    #[test]
    fn test_meet_result_is_subset_of_both() {
        let a = AuthorityVector::new(
            RiskLevel::High,
            CapabilityLevel::ReadWrite,
            BudgetLevel::Capped(5000),
            StopPredicateLevel::Extend,
            TaintCeiling::Untrusted,
            ClassificationLevel::Secret,
        );
        let b = AuthorityVector::new(
            RiskLevel::Med,
            CapabilityLevel::Full,
            BudgetLevel::Capped(10000),
            StopPredicateLevel::Override,
            TaintCeiling::Attested,
            ClassificationLevel::Confidential,
        );
        let m = lattice_meet(&a, &b);
        assert!(
            m.is_subset_of(&a),
            "meet result must be subset of first input"
        );
        assert!(
            m.is_subset_of(&b),
            "meet result must be subset of second input"
        );
    }

    #[test]
    fn test_meet_componentwise_minimum() {
        let a = AuthorityVector::new(
            RiskLevel::High,
            CapabilityLevel::ReadWrite,
            BudgetLevel::Capped(5000),
            StopPredicateLevel::Extend,
            TaintCeiling::Untrusted,
            ClassificationLevel::Secret,
        );
        let b = AuthorityVector::new(
            RiskLevel::Med,
            CapabilityLevel::Full,
            BudgetLevel::Capped(10000),
            StopPredicateLevel::Override,
            TaintCeiling::Attested,
            ClassificationLevel::Confidential,
        );
        let m = lattice_meet(&a, &b);
        assert_eq!(m.risk, RiskLevel::Med);
        assert_eq!(m.capability, CapabilityLevel::ReadWrite);
        assert_eq!(m.budget, BudgetLevel::Capped(5000));
        assert_eq!(m.stop_predicate, StopPredicateLevel::Extend);
        assert_eq!(m.taint, TaintCeiling::Attested);
        assert_eq!(m.classification, ClassificationLevel::Confidential);
    }

    #[test]
    fn test_meet_budget_zero_dominates() {
        let a = AuthorityVector::new(
            RiskLevel::High,
            CapabilityLevel::Full,
            BudgetLevel::Capped(10000),
            StopPredicateLevel::Override,
            TaintCeiling::Adversarial,
            ClassificationLevel::TopSecret,
        );
        let b = AuthorityVector::new(
            RiskLevel::High,
            CapabilityLevel::Full,
            BudgetLevel::Zero,
            StopPredicateLevel::Override,
            TaintCeiling::Adversarial,
            ClassificationLevel::TopSecret,
        );
        let m = lattice_meet(&a, &b);
        assert_eq!(m.budget, BudgetLevel::Zero);
    }

    // =========================================================================
    // Delegation Widening Rejection Tests
    // =========================================================================

    #[test]
    fn test_widening_risk_rejected() {
        let parent = AuthorityVector::new(
            RiskLevel::Med,
            CapabilityLevel::Full,
            BudgetLevel::Unlimited,
            StopPredicateLevel::Override,
            TaintCeiling::Adversarial,
            ClassificationLevel::TopSecret,
        );
        // Overlay tries to grant High risk (wider than parent)
        let overlay = AuthorityVector::new(
            RiskLevel::High,
            CapabilityLevel::Full,
            BudgetLevel::Unlimited,
            StopPredicateLevel::Override,
            TaintCeiling::Adversarial,
            ClassificationLevel::TopSecret,
        );
        let m = lattice_meet(&parent, &overlay);
        // Meet clamps to Med (parent's level)
        assert_eq!(m.risk, RiskLevel::Med);
        assert!(m.is_subset_of(&parent));
    }

    #[test]
    fn test_manually_widened_receipt_rejected() {
        let parent = AuthorityVector::new(
            RiskLevel::Med,
            CapabilityLevel::ReadWrite,
            BudgetLevel::Capped(5000),
            StopPredicateLevel::Extend,
            TaintCeiling::Untrusted,
            ClassificationLevel::Secret,
        );
        let overlay = AuthorityVector::new(
            RiskLevel::Low,
            CapabilityLevel::ReadOnly,
            BudgetLevel::Capped(1000),
            StopPredicateLevel::Inherit,
            TaintCeiling::Attested,
            ClassificationLevel::Confidential,
        );
        // Construct a receipt with manually widened authority
        let widened = AuthorityVector::new(
            RiskLevel::High, // wider than parent!
            CapabilityLevel::Full,
            BudgetLevel::Unlimited,
            StopPredicateLevel::Override,
            TaintCeiling::Adversarial,
            ClassificationLevel::TopSecret,
        );
        let receipt = PermeabilityReceipt {
            receipt_id: "widened-receipt".to_string(),
            parent_authority: parent,
            overlay,
            delegated: widened,
            parent_authority_hash: parent.content_hash(),
            overlay_hash: overlay.content_hash(),
            delegated_hash: widened.content_hash(),
            delegation_depth: 0,
            parent_receipt_hash: None,
            delegator_actor_id: "delegator".to_string(),
            delegate_actor_id: "delegate".to_string(),
            issued_at_ms: 1_000_000,
            expires_at_ms: 2_000_000,
            revoked: false,
        };
        let result = receipt.validate_admission(1_500_000);
        assert!(result.is_err());
        assert!(
            matches!(result, Err(PermeabilityError::MeetMismatch)),
            "manually widened delegation must be rejected"
        );
    }

    // =========================================================================
    // Receipt Validation Tests
    // =========================================================================

    #[test]
    fn test_valid_receipt_passes_admission() {
        let parent = AuthorityVector::new(
            RiskLevel::High,
            CapabilityLevel::Full,
            BudgetLevel::Capped(10000),
            StopPredicateLevel::Override,
            TaintCeiling::Adversarial,
            ClassificationLevel::TopSecret,
        );
        let overlay = AuthorityVector::new(
            RiskLevel::Med,
            CapabilityLevel::ReadWrite,
            BudgetLevel::Capped(5000),
            StopPredicateLevel::Extend,
            TaintCeiling::Untrusted,
            ClassificationLevel::Secret,
        );
        let receipt = PermeabilityReceiptBuilder::new("receipt-001", parent, overlay)
            .delegator_actor_id("alice")
            .delegate_actor_id("bob")
            .issued_at_ms(1_000_000)
            .expires_at_ms(2_000_000)
            .build()
            .unwrap();

        assert!(receipt.validate_admission(1_500_000).is_ok());
    }

    #[test]
    fn test_expired_receipt_rejected() {
        let parent = AuthorityVector::top();
        let overlay = AuthorityVector::top();
        let receipt = PermeabilityReceiptBuilder::new("receipt-expired", parent, overlay)
            .delegator_actor_id("alice")
            .delegate_actor_id("bob")
            .issued_at_ms(1_000_000)
            .expires_at_ms(2_000_000)
            .build()
            .unwrap();

        let result = receipt.validate_admission(3_000_000);
        assert!(matches!(result, Err(PermeabilityError::Expired)));
    }

    #[test]
    fn test_revoked_receipt_rejected() {
        let parent = AuthorityVector::top();
        let overlay = AuthorityVector::top();
        let mut receipt = PermeabilityReceiptBuilder::new("receipt-revoked", parent, overlay)
            .delegator_actor_id("alice")
            .delegate_actor_id("bob")
            .issued_at_ms(1_000_000)
            .expires_at_ms(2_000_000)
            .build()
            .unwrap();
        receipt.revoked = true;

        let result = receipt.validate_admission(1_500_000);
        assert!(matches!(result, Err(PermeabilityError::Revoked)));
    }

    #[test]
    fn test_tampered_hash_rejected() {
        let parent = AuthorityVector::top();
        let overlay = AuthorityVector::bottom();
        let mut receipt = PermeabilityReceiptBuilder::new("receipt-tampered", parent, overlay)
            .delegator_actor_id("alice")
            .delegate_actor_id("bob")
            .issued_at_ms(1_000_000)
            .build()
            .unwrap();
        // Tamper with the parent authority hash
        receipt.parent_authority_hash = [0xFF; 32];

        let result = receipt.validate_admission(0);
        assert!(matches!(
            result,
            Err(PermeabilityError::HashMismatch { .. })
        ));
    }

    #[test]
    fn test_empty_receipt_id_rejected() {
        let parent = AuthorityVector::top();
        let overlay = AuthorityVector::top();
        let receipt = PermeabilityReceipt {
            receipt_id: String::new(),
            parent_authority: parent,
            overlay,
            delegated: lattice_meet(&parent, &overlay),
            parent_authority_hash: parent.content_hash(),
            overlay_hash: overlay.content_hash(),
            delegated_hash: lattice_meet(&parent, &overlay).content_hash(),
            delegation_depth: 0,
            parent_receipt_hash: None,
            delegator_actor_id: "alice".to_string(),
            delegate_actor_id: "bob".to_string(),
            issued_at_ms: 1_000_000,
            expires_at_ms: 0,
            revoked: false,
        };
        let result = receipt.validate_admission(0);
        assert!(matches!(
            result,
            Err(PermeabilityError::InvalidReceiptId { .. })
        ));
    }

    // =========================================================================
    // Consumption Binding Tests
    // =========================================================================

    #[test]
    fn test_valid_consumption_binding() {
        let parent = AuthorityVector::top();
        let overlay = AuthorityVector::new(
            RiskLevel::Med,
            CapabilityLevel::ReadWrite,
            BudgetLevel::Capped(5000),
            StopPredicateLevel::Extend,
            TaintCeiling::Untrusted,
            ClassificationLevel::Secret,
        );
        let receipt = PermeabilityReceiptBuilder::new("receipt-consume", parent, overlay)
            .delegator_actor_id("alice")
            .delegate_actor_id("bob")
            .issued_at_ms(1_000_000)
            .build()
            .unwrap();

        let bound_hash = receipt.content_hash();
        let required = AuthorityVector::new(
            RiskLevel::Low,
            CapabilityLevel::ReadOnly,
            BudgetLevel::Capped(100),
            StopPredicateLevel::Inherit,
            TaintCeiling::Attested,
            ClassificationLevel::Public,
        );
        assert!(validate_consumption_binding(&receipt, &bound_hash, &required, 0).is_ok());
    }

    #[test]
    fn test_consumption_binding_wrong_hash_rejected() {
        let parent = AuthorityVector::top();
        let overlay = AuthorityVector::bottom();
        let receipt = PermeabilityReceiptBuilder::new("receipt-wrong-hash", parent, overlay)
            .delegator_actor_id("alice")
            .delegate_actor_id("bob")
            .issued_at_ms(1_000_000)
            .build()
            .unwrap();

        let wrong_hash = [0xAB; 32];
        let required = AuthorityVector::bottom();
        let result = validate_consumption_binding(&receipt, &wrong_hash, &required, 0);
        assert!(matches!(
            result,
            Err(PermeabilityError::HashMismatch { .. })
        ));
    }

    #[test]
    fn test_consumption_binding_insufficient_authority_rejected() {
        let parent = AuthorityVector::new(
            RiskLevel::Med,
            CapabilityLevel::ReadWrite,
            BudgetLevel::Capped(5000),
            StopPredicateLevel::Extend,
            TaintCeiling::Untrusted,
            ClassificationLevel::Secret,
        );
        let overlay = AuthorityVector::new(
            RiskLevel::Low,
            CapabilityLevel::ReadOnly,
            BudgetLevel::Capped(1000),
            StopPredicateLevel::Inherit,
            TaintCeiling::Attested,
            ClassificationLevel::Confidential,
        );
        let receipt = PermeabilityReceiptBuilder::new("receipt-insuff", parent, overlay)
            .delegator_actor_id("alice")
            .delegate_actor_id("bob")
            .issued_at_ms(1_000_000)
            .build()
            .unwrap();

        let bound_hash = receipt.content_hash();
        // Required authority exceeds what was delegated
        let required = AuthorityVector::top();
        let result = validate_consumption_binding(&receipt, &bound_hash, &required, 0);
        assert!(matches!(result, Err(PermeabilityError::DelegationWidening)));
    }

    // =========================================================================
    // Delegation Chain Tests
    // =========================================================================

    #[test]
    fn test_valid_two_level_delegation_chain() {
        let root_parent = AuthorityVector::top();
        let root_overlay = AuthorityVector::new(
            RiskLevel::High,
            CapabilityLevel::ReadWrite,
            BudgetLevel::Capped(10000),
            StopPredicateLevel::Extend,
            TaintCeiling::Untrusted,
            ClassificationLevel::Secret,
        );
        let root = PermeabilityReceiptBuilder::new("root", root_parent, root_overlay)
            .delegation_depth(0)
            .delegator_actor_id("root-admin")
            .delegate_actor_id("manager")
            .issued_at_ms(1_000_000)
            .build()
            .unwrap();

        let child_overlay = AuthorityVector::new(
            RiskLevel::Med,
            CapabilityLevel::ReadOnly,
            BudgetLevel::Capped(1000),
            StopPredicateLevel::Inherit,
            TaintCeiling::Attested,
            ClassificationLevel::Confidential,
        );
        let child = PermeabilityReceiptBuilder::new("child", root.delegated, child_overlay)
            .delegation_depth(1)
            .parent_receipt_hash(root.content_hash())
            .delegator_actor_id("manager")
            .delegate_actor_id("worker")
            .issued_at_ms(1_000_000)
            .build()
            .unwrap();

        assert!(validate_delegation_chain(&[root, child], 0).is_ok());
    }

    // =========================================================================
    // Recursion Depth >= 4 Laundering Tests
    // =========================================================================

    /// Helper: builds a delegation chain of the given depth, each level
    /// narrowing authority by one notch.
    fn build_chain(depth: usize) -> Vec<PermeabilityReceipt> {
        let levels = [
            AuthorityVector::new(
                RiskLevel::High,
                CapabilityLevel::Full,
                BudgetLevel::Capped(100_000),
                StopPredicateLevel::Override,
                TaintCeiling::Adversarial,
                ClassificationLevel::TopSecret,
            ),
            AuthorityVector::new(
                RiskLevel::High,
                CapabilityLevel::ReadWrite,
                BudgetLevel::Capped(50_000),
                StopPredicateLevel::Extend,
                TaintCeiling::Untrusted,
                ClassificationLevel::Secret,
            ),
            AuthorityVector::new(
                RiskLevel::Med,
                CapabilityLevel::ReadOnly,
                BudgetLevel::Capped(10_000),
                StopPredicateLevel::Inherit,
                TaintCeiling::Attested,
                ClassificationLevel::Confidential,
            ),
            AuthorityVector::new(
                RiskLevel::Low,
                CapabilityLevel::ReadOnly,
                BudgetLevel::Capped(1_000),
                StopPredicateLevel::Deny,
                TaintCeiling::Trusted,
                ClassificationLevel::Public,
            ),
        ];

        let mut chain = Vec::with_capacity(depth);

        // Root delegation
        let root = PermeabilityReceiptBuilder::new(
            format!("receipt-{}", 0),
            AuthorityVector::top(),
            levels[0],
        )
        .delegation_depth(0)
        .delegator_actor_id("root")
        .delegate_actor_id("level-1")
        .issued_at_ms(1_000_000)
        .build()
        .unwrap();
        chain.push(root);

        for i in 1..depth {
            let overlay_idx = std::cmp::min(i, levels.len() - 1);
            let prev = &chain[i - 1];
            let receipt = PermeabilityReceiptBuilder::new(
                format!("receipt-{i}"),
                prev.delegated,
                levels[overlay_idx],
            )
            .delegation_depth(u32::try_from(i).unwrap())
            .parent_receipt_hash(prev.content_hash())
            .delegator_actor_id(format!("level-{i}"))
            .delegate_actor_id(format!("level-{}", i + 1))
            .issued_at_ms(1_000_000)
            .build()
            .unwrap();
            chain.push(receipt);
        }

        chain
    }

    #[test]
    fn test_depth_4_chain_valid_when_narrowing() {
        let chain = build_chain(4);
        assert!(validate_delegation_chain(&chain, 0).is_ok());

        // Verify authority monotonically decreases
        for i in 1..chain.len() {
            assert!(
                chain[i].delegated.is_subset_of(&chain[i - 1].delegated),
                "authority must not increase at depth {i}"
            );
        }
    }

    #[test]
    fn test_depth_5_chain_valid_when_narrowing() {
        let chain = build_chain(5);
        assert!(validate_delegation_chain(&chain, 0).is_ok());
    }

    #[test]
    fn test_depth_4_laundering_attempt_rejected() {
        // Build a valid 3-level chain, then try to launder authority at level 4
        let mut chain = build_chain(3);

        // At depth 3, try to construct a receipt that widens authority
        let prev = &chain[2];
        let widened = AuthorityVector::new(
            RiskLevel::High, // higher than parent's delegated (which is at most Med at this depth)
            CapabilityLevel::Full,
            BudgetLevel::Unlimited,
            StopPredicateLevel::Override,
            TaintCeiling::Adversarial,
            ClassificationLevel::TopSecret,
        );

        // Build a fraudulent receipt manually
        let overlay = widened; // overlay grants max authority
        let fraud_delegated = widened; // pretend meet gave us everything
        let receipt = PermeabilityReceipt {
            receipt_id: "fraud-receipt-3".to_string(),
            parent_authority: prev.delegated,
            overlay,
            delegated: fraud_delegated,
            parent_authority_hash: prev.delegated.content_hash(),
            overlay_hash: overlay.content_hash(),
            delegated_hash: fraud_delegated.content_hash(),
            delegation_depth: 3,
            parent_receipt_hash: Some(prev.content_hash()),
            delegator_actor_id: "level-3".to_string(),
            delegate_actor_id: "level-4".to_string(),
            issued_at_ms: 1_000_000,
            expires_at_ms: 0,
            revoked: false,
        };
        chain.push(receipt);

        let result = validate_delegation_chain(&chain, 0);
        assert!(
            result.is_err(),
            "depth-4 laundering attempt must be rejected"
        );
    }

    #[test]
    fn test_depth_6_laundering_escalation_rejected() {
        // Build a valid 5-level chain, then try to escalate at level 6
        let mut chain = build_chain(5);

        let prev = &chain[4];
        // Try to escalate a single facet
        let mut escalated = prev.delegated;
        escalated.risk = RiskLevel::High;

        let receipt = PermeabilityReceipt {
            receipt_id: "fraud-receipt-5".to_string(),
            parent_authority: prev.delegated,
            overlay: AuthorityVector::top(),
            delegated: escalated,
            parent_authority_hash: prev.delegated.content_hash(),
            overlay_hash: AuthorityVector::top().content_hash(),
            delegated_hash: escalated.content_hash(),
            delegation_depth: 5,
            parent_receipt_hash: Some(prev.content_hash()),
            delegator_actor_id: "level-5".to_string(),
            delegate_actor_id: "level-6".to_string(),
            issued_at_ms: 1_000_000,
            expires_at_ms: 0,
            revoked: false,
        };
        chain.push(receipt);

        let result = validate_delegation_chain(&chain, 0);
        assert!(
            result.is_err(),
            "single-facet escalation at depth 6 must be rejected"
        );
    }

    #[test]
    fn test_depth_exceeds_max_rejected() {
        let result = PermeabilityReceiptBuilder::new(
            "deep-receipt",
            AuthorityVector::top(),
            AuthorityVector::top(),
        )
        .delegation_depth(MAX_DELEGATION_DEPTH + 1)
        .build();
        assert!(matches!(
            result,
            Err(PermeabilityError::DepthExceeded { .. })
        ));
    }

    #[test]
    fn test_chain_missing_parent_hash_rejected() {
        let root =
            PermeabilityReceiptBuilder::new("root", AuthorityVector::top(), AuthorityVector::top())
                .delegation_depth(0)
                .delegator_actor_id("root")
                .delegate_actor_id("child")
                .issued_at_ms(1_000_000)
                .build()
                .unwrap();

        let child_overlay = AuthorityVector::new(
            RiskLevel::Med,
            CapabilityLevel::ReadOnly,
            BudgetLevel::Capped(1000),
            StopPredicateLevel::Inherit,
            TaintCeiling::Attested,
            ClassificationLevel::Confidential,
        );
        let child = PermeabilityReceiptBuilder::new("child", root.delegated, child_overlay)
            .delegation_depth(1)
            // deliberately omitting parent_receipt_hash
            .delegator_actor_id("child")
            .delegate_actor_id("grandchild")
            .issued_at_ms(1_000_000)
            .build()
            .unwrap();

        let result = validate_delegation_chain(&[root, child], 0);
        assert!(
            matches!(result, Err(PermeabilityError::MissingBinding { .. })),
            "chain with missing parent hash binding must be rejected"
        );
    }

    #[test]
    fn test_chain_wrong_parent_hash_rejected() {
        let root =
            PermeabilityReceiptBuilder::new("root", AuthorityVector::top(), AuthorityVector::top())
                .delegation_depth(0)
                .delegator_actor_id("root")
                .delegate_actor_id("child")
                .issued_at_ms(1_000_000)
                .build()
                .unwrap();

        let child_overlay = AuthorityVector::new(
            RiskLevel::Med,
            CapabilityLevel::ReadOnly,
            BudgetLevel::Capped(1000),
            StopPredicateLevel::Inherit,
            TaintCeiling::Attested,
            ClassificationLevel::Confidential,
        );
        let child = PermeabilityReceiptBuilder::new("child", root.delegated, child_overlay)
            .delegation_depth(1)
            .parent_receipt_hash([0xDE; 32]) // wrong hash
            .delegator_actor_id("child")
            .delegate_actor_id("grandchild")
            .issued_at_ms(1_000_000)
            .build()
            .unwrap();

        let result = validate_delegation_chain(&[root, child], 0);
        assert!(
            matches!(result, Err(PermeabilityError::HashMismatch { .. })),
            "chain with incorrect parent hash must be rejected"
        );
    }

    // =========================================================================
    // Determinism Tests
    // =========================================================================

    #[test]
    fn test_meet_determinism_across_orderings() {
        let vectors: Vec<AuthorityVector> = vec![
            AuthorityVector::top(),
            AuthorityVector::bottom(),
            AuthorityVector::new(
                RiskLevel::Med,
                CapabilityLevel::ReadWrite,
                BudgetLevel::Capped(5000),
                StopPredicateLevel::Extend,
                TaintCeiling::Untrusted,
                ClassificationLevel::Secret,
            ),
            AuthorityVector::new(
                RiskLevel::Low,
                CapabilityLevel::ReadOnly,
                BudgetLevel::Capped(100),
                StopPredicateLevel::Inherit,
                TaintCeiling::Attested,
                ClassificationLevel::Confidential,
            ),
        ];

        // Verify that meet produces identical results regardless of
        // argument order and repeated applications.
        for i in 0..vectors.len() {
            for j in 0..vectors.len() {
                let m1 = lattice_meet(&vectors[i], &vectors[j]);
                let m2 = lattice_meet(&vectors[j], &vectors[i]);
                assert_eq!(m1, m2, "meet must be commutative for ({i}, {j})");

                // Repeated application must be idempotent
                let m3 = lattice_meet(&m1, &vectors[i]);
                let m4 = lattice_meet(&m1, &vectors[j]);
                assert_eq!(m3, m1, "meet(meet(a,b), a) == meet(a,b)");
                assert_eq!(m4, m1, "meet(meet(a,b), b) == meet(a,b)");
            }
        }
    }

    #[test]
    fn test_receipt_hash_determinism() {
        let parent = AuthorityVector::top();
        let overlay = AuthorityVector::new(
            RiskLevel::Med,
            CapabilityLevel::ReadWrite,
            BudgetLevel::Capped(5000),
            StopPredicateLevel::Extend,
            TaintCeiling::Untrusted,
            ClassificationLevel::Secret,
        );
        let r1 = PermeabilityReceiptBuilder::new("det-test", parent, overlay)
            .delegator_actor_id("alice")
            .delegate_actor_id("bob")
            .issued_at_ms(1_000_000)
            .expires_at_ms(2_000_000)
            .build()
            .unwrap();
        let r2 = PermeabilityReceiptBuilder::new("det-test", parent, overlay)
            .delegator_actor_id("alice")
            .delegate_actor_id("bob")
            .issued_at_ms(1_000_000)
            .expires_at_ms(2_000_000)
            .build()
            .unwrap();
        assert_eq!(
            r1.content_hash(),
            r2.content_hash(),
            "identical receipts must have identical hashes"
        );
    }

    // =========================================================================
    // Serde Roundtrip Tests
    // =========================================================================

    #[test]
    fn test_authority_vector_serde_roundtrip() {
        let v = AuthorityVector::new(
            RiskLevel::Med,
            CapabilityLevel::ReadWrite,
            BudgetLevel::Capped(42),
            StopPredicateLevel::Extend,
            TaintCeiling::Untrusted,
            ClassificationLevel::Secret,
        );
        let json = serde_json::to_string(&v).unwrap();
        let deserialized: AuthorityVector = serde_json::from_str(&json).unwrap();
        assert_eq!(v, deserialized);
    }

    #[test]
    fn test_receipt_serde_roundtrip() {
        let parent = AuthorityVector::top();
        let overlay = AuthorityVector::bottom();
        let receipt = PermeabilityReceiptBuilder::new("serde-test", parent, overlay)
            .delegator_actor_id("alice")
            .delegate_actor_id("bob")
            .issued_at_ms(1_000_000)
            .build()
            .unwrap();
        let json = serde_json::to_string(&receipt).unwrap();
        let deserialized: PermeabilityReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(receipt, deserialized);
    }

    // =========================================================================
    // PermeabilityFacet Tests
    // =========================================================================

    #[test]
    fn test_facet_all_returns_six_facets() {
        let facets: Vec<_> = PermeabilityFacet::all().collect();
        assert_eq!(facets.len(), 6);
        assert_eq!(facets[0], PermeabilityFacet::Risk);
        assert_eq!(facets[5], PermeabilityFacet::Classification);
    }

    // =========================================================================
    // Edge Case Tests
    // =========================================================================

    #[test]
    fn test_empty_chain_rejected() {
        let result = validate_delegation_chain(&[], 0);
        assert!(matches!(
            result,
            Err(PermeabilityError::MissingBinding { .. })
        ));
    }

    #[test]
    fn test_single_receipt_chain_valid() {
        let receipt = PermeabilityReceiptBuilder::new(
            "single",
            AuthorityVector::top(),
            AuthorityVector::bottom(),
        )
        .delegation_depth(0)
        .delegator_actor_id("root")
        .delegate_actor_id("worker")
        .issued_at_ms(1_000_000)
        .build()
        .unwrap();

        assert!(validate_delegation_chain(&[receipt], 0).is_ok());
    }

    #[test]
    fn test_budget_capped_meet_takes_minimum() {
        let a = AuthorityVector::new(
            RiskLevel::High,
            CapabilityLevel::Full,
            BudgetLevel::Capped(300),
            StopPredicateLevel::Override,
            TaintCeiling::Adversarial,
            ClassificationLevel::TopSecret,
        );
        let b = AuthorityVector::new(
            RiskLevel::High,
            CapabilityLevel::Full,
            BudgetLevel::Capped(700),
            StopPredicateLevel::Override,
            TaintCeiling::Adversarial,
            ClassificationLevel::TopSecret,
        );
        let m = lattice_meet(&a, &b);
        assert_eq!(m.budget, BudgetLevel::Capped(300));
    }

    #[test]
    fn test_meet_capped_with_unlimited_takes_capped() {
        let a = AuthorityVector::new(
            RiskLevel::High,
            CapabilityLevel::Full,
            BudgetLevel::Capped(5000),
            StopPredicateLevel::Override,
            TaintCeiling::Adversarial,
            ClassificationLevel::TopSecret,
        );
        let b = AuthorityVector::new(
            RiskLevel::High,
            CapabilityLevel::Full,
            BudgetLevel::Unlimited,
            StopPredicateLevel::Override,
            TaintCeiling::Adversarial,
            ClassificationLevel::TopSecret,
        );
        let m = lattice_meet(&a, &b);
        assert_eq!(m.budget, BudgetLevel::Capped(5000));
    }

    // =========================================================================
    // Proptest: Lattice Law Invariants
    // =========================================================================

    mod proptest_lattice {
        use proptest::prelude::*;

        use super::*;

        fn arb_risk() -> impl Strategy<Value = RiskLevel> {
            prop_oneof![
                Just(RiskLevel::Low),
                Just(RiskLevel::Med),
                Just(RiskLevel::High),
            ]
        }

        fn arb_capability() -> impl Strategy<Value = CapabilityLevel> {
            prop_oneof![
                Just(CapabilityLevel::None),
                Just(CapabilityLevel::ReadOnly),
                Just(CapabilityLevel::ReadWrite),
                Just(CapabilityLevel::Full),
            ]
        }

        fn arb_budget() -> impl Strategy<Value = BudgetLevel> {
            prop_oneof![
                Just(BudgetLevel::Zero),
                (0..=100_000u64).prop_map(BudgetLevel::Capped),
                Just(BudgetLevel::Unlimited),
            ]
        }

        fn arb_stop() -> impl Strategy<Value = StopPredicateLevel> {
            prop_oneof![
                Just(StopPredicateLevel::Deny),
                Just(StopPredicateLevel::Inherit),
                Just(StopPredicateLevel::Extend),
                Just(StopPredicateLevel::Override),
            ]
        }

        fn arb_taint() -> impl Strategy<Value = TaintCeiling> {
            prop_oneof![
                Just(TaintCeiling::Trusted),
                Just(TaintCeiling::Attested),
                Just(TaintCeiling::Untrusted),
                Just(TaintCeiling::Adversarial),
            ]
        }

        fn arb_classification() -> impl Strategy<Value = ClassificationLevel> {
            prop_oneof![
                Just(ClassificationLevel::Public),
                Just(ClassificationLevel::Confidential),
                Just(ClassificationLevel::Secret),
                Just(ClassificationLevel::TopSecret),
            ]
        }

        fn arb_authority_vector() -> impl Strategy<Value = AuthorityVector> {
            (
                arb_risk(),
                arb_capability(),
                arb_budget(),
                arb_stop(),
                arb_taint(),
                arb_classification(),
            )
                .prop_map(|(r, c, b, s, t, cl)| AuthorityVector::new(r, c, b, s, t, cl))
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(512))]

            #[test]
            fn prop_meet_commutative(a in arb_authority_vector(), b in arb_authority_vector()) {
                prop_assert_eq!(lattice_meet(&a, &b), lattice_meet(&b, &a));
            }

            #[test]
            fn prop_meet_associative(
                a in arb_authority_vector(),
                b in arb_authority_vector(),
                c in arb_authority_vector(),
            ) {
                let ab_c = lattice_meet(&lattice_meet(&a, &b), &c);
                let a_bc = lattice_meet(&a, &lattice_meet(&b, &c));
                prop_assert_eq!(ab_c, a_bc);
            }

            #[test]
            fn prop_meet_idempotent(a in arb_authority_vector()) {
                prop_assert_eq!(lattice_meet(&a, &a), a);
            }

            #[test]
            fn prop_meet_result_subset_of_both(
                a in arb_authority_vector(),
                b in arb_authority_vector(),
            ) {
                let m = lattice_meet(&a, &b);
                prop_assert!(m.is_subset_of(&a), "meet must be <= a");
                prop_assert!(m.is_subset_of(&b), "meet must be <= b");
            }

            #[test]
            fn prop_meet_with_top_identity(a in arb_authority_vector()) {
                prop_assert_eq!(lattice_meet(&a, &AuthorityVector::top()), a);
                prop_assert_eq!(lattice_meet(&AuthorityVector::top(), &a), a);
            }

            #[test]
            fn prop_meet_with_bottom_annihilates(a in arb_authority_vector()) {
                prop_assert_eq!(
                    lattice_meet(&a, &AuthorityVector::bottom()),
                    AuthorityVector::bottom()
                );
            }

            #[test]
            fn prop_content_hash_deterministic(a in arb_authority_vector()) {
                prop_assert_eq!(a.content_hash(), a.content_hash());
            }

            #[test]
            fn prop_delegation_never_widens(
                parent in arb_authority_vector(),
                overlay in arb_authority_vector(),
            ) {
                let delegated = lattice_meet(&parent, &overlay);
                prop_assert!(
                    delegated.is_subset_of(&parent),
                    "delegation must never exceed parent"
                );
            }
        }
    }
}
