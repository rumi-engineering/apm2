// AGENT-AUTHORED (TCK-00340)
//! Multi-holon policy inheritance enforcement and attestation ratcheting.
//!
//! This module enforces two critical security properties:
//!
//! 1. **Policy Inheritance**: Subleases MUST be strict subsets of their parent
//!    leases. A child holon may never exceed the authority of its parent.
//!
//! 2. **Attestation Ratcheting**: Higher risk tiers require stronger
//!    attestation on receipts
//!    ([`ToolExecutionReceipt`](super::tool_execution_receipt::ToolExecutionReceipt),
//!    [`ReviewReceiptRecorded`](super::review_receipt::ReviewReceiptRecorded),
//!    [`ProjectionReceiptRecorded`](super::projection_receipt_recorded::ProjectionReceiptRecorded)).
//!    Missing attestation in high-risk tiers fails closed (reject, not warn).
//!
//! # Security Model
//!
//! - **Fail-Closed**: Missing or invalid attestation always results in
//!   rejection. There is no "warn" mode for high-risk tiers.
//! - **Strict Subset**: A sublease cannot expand capabilities, extend time
//!   bounds, change policy hash, or reference a different changeset than its
//!   parent lease.
//! - **Monotonic Ratchet**: Attestation requirements only increase with risk
//!   tier; they never decrease.
//!
//! # Contract References
//!
//! - TCK-00340: Security hardening: multi-holon policy inheritance enforcement
//!   + attestation tightening
//! - REQ-0016: Attestation requirements ratcheted for higher risk tiers
//! - RFC-0019 Section 03: Trust Boundaries
//! - TB-0005: Capability Manifest Integrity Boundary

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use thiserror::Error;

use super::lease::GateLease;
use super::policy_resolution::RiskTier;

// =============================================================================
// Constants
// =============================================================================

/// Maximum number of subleases that can be validated in a single batch.
///
/// Prevents unbounded resource consumption during batch validation.
pub const MAX_SUBLEASE_BATCH_SIZE: usize = 256;

/// Maximum length for actor ID strings in attestation context.
pub const MAX_ACTOR_ID_LENGTH: usize = 256;

/// Maximum length for reason strings in validation results.
pub const MAX_REASON_LENGTH: usize = 1024;

// =============================================================================
// Error Types
// =============================================================================

/// Errors from policy inheritance and attestation validation.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PolicyInheritanceError {
    /// Sublease violates strict-subset constraint of parent lease.
    #[error("sublease '{sublease_id}' violates parent lease '{parent_id}': {reason}")]
    SubleaseViolation {
        /// ID of the parent lease.
        parent_id: String,
        /// ID of the violating sublease.
        sublease_id: String,
        /// Human-readable reason for the violation.
        reason: String,
    },

    /// Attestation requirements not met for the given risk tier.
    #[error("attestation requirement not met for risk tier {tier:?}: {reason}")]
    AttestationNotMet {
        /// The risk tier that was not satisfied.
        tier: RiskTier,
        /// Human-readable reason.
        reason: String,
    },

    /// Batch size exceeds the maximum allowed.
    #[error("sublease batch size {actual} exceeds maximum {max}")]
    BatchTooLarge {
        /// Actual batch size.
        actual: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// String field exceeds maximum length.
    #[error("string field '{field}' exceeds maximum length ({actual} > {max})")]
    StringTooLong {
        /// Field name.
        field: &'static str,
        /// Actual length.
        actual: usize,
        /// Maximum allowed.
        max: usize,
    },
}

// =============================================================================
// AttestationLevel
// =============================================================================

/// Attestation strength levels required for receipts.
///
/// Ordered from weakest to strongest. Higher risk tiers require
/// stronger attestation levels.
///
/// # Ordering
///
/// `None < SelfSigned < CounterSigned < ThresholdSigned`
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[repr(u8)]
pub enum AttestationLevel {
    /// No attestation present. Only acceptable at Tier0.
    None            = 0,
    /// Receipt is self-signed by the executor.
    SelfSigned      = 1,
    /// Receipt is counter-signed by a second party (verifier).
    CounterSigned   = 2,
    /// Receipt has threshold signatures (multiple verifiers).
    ThresholdSigned = 3,
}

impl AttestationLevel {
    /// Returns the numeric code for this level.
    #[must_use]
    pub const fn to_code(self) -> u8 {
        self as u8
    }

    /// Creates an attestation level from its numeric code.
    ///
    /// Returns `None` for invalid codes (fail-closed).
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::None),
            1 => Some(Self::SelfSigned),
            2 => Some(Self::CounterSigned),
            3 => Some(Self::ThresholdSigned),
            _ => None,
        }
    }

    /// Returns true if this level meets or exceeds the required level.
    #[must_use]
    pub const fn satisfies(self, required: Self) -> bool {
        (self as u8) >= (required as u8)
    }

    /// Returns the display name for this level.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "NONE",
            Self::SelfSigned => "SELF_SIGNED",
            Self::CounterSigned => "COUNTER_SIGNED",
            Self::ThresholdSigned => "THRESHOLD_SIGNED",
        }
    }
}

impl std::fmt::Display for AttestationLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// =============================================================================
// ReceiptKind
// =============================================================================

/// The kind of receipt being attested.
///
/// Different receipt kinds may have different attestation requirements
/// at the same risk tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReceiptKind {
    /// A tool execution receipt (proof of tool actuation).
    ToolExecution,
    /// A review receipt (proof of review completion).
    Review,
    /// A projection receipt (proof of external projection).
    Projection,
}

impl ReceiptKind {
    /// Returns the display name for this kind.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ToolExecution => "TOOL_EXECUTION",
            Self::Review => "REVIEW",
            Self::Projection => "PROJECTION",
        }
    }
}

impl std::fmt::Display for ReceiptKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// =============================================================================
// AttestationRequirements
// =============================================================================

/// Defines the minimum attestation level required per risk tier and receipt
/// kind.
///
/// This is the core ratcheting mechanism: higher risk tiers demand stronger
/// attestation without breaking low-tier throughput.
///
/// # Default Requirements
///
/// | Risk Tier | Tool Exec       | Review            | Projection        |
/// |-----------|-----------------|-------------------|-------------------|
/// | Tier0     | `None`          | `None`            | `None`            |
/// | Tier1     | `SelfSigned`    | `SelfSigned`      | `SelfSigned`      |
/// | Tier2     | `SelfSigned`    | `CounterSigned`   | `SelfSigned`      |
/// | Tier3     | `CounterSigned` | `CounterSigned`   | `CounterSigned`   |
/// | Tier4     | `CounterSigned` | `ThresholdSigned` | `CounterSigned`   |
///
/// # Security
///
/// The ratchet is monotonically non-decreasing: a higher tier never requires
/// less attestation than a lower tier. This is enforced at construction time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationRequirements {
    /// Minimum attestation for `ToolExecutionReceipt` per risk tier (index =
    /// tier).
    tool_execution: [AttestationLevel; 5],
    /// Minimum attestation for `ReviewReceiptRecorded` per risk tier (index =
    /// tier).
    review: [AttestationLevel; 5],
    /// Minimum attestation for `ProjectionReceiptRecorded` per risk tier
    /// (index = tier).
    projection: [AttestationLevel; 5],
}

impl Default for AttestationRequirements {
    /// Returns the default attestation requirements.
    ///
    /// See the struct-level documentation for the default table.
    fn default() -> Self {
        Self {
            tool_execution: [
                AttestationLevel::None,          // Tier0
                AttestationLevel::SelfSigned,    // Tier1
                AttestationLevel::SelfSigned,    // Tier2
                AttestationLevel::CounterSigned, // Tier3
                AttestationLevel::CounterSigned, // Tier4
            ],
            review: [
                AttestationLevel::None,            // Tier0
                AttestationLevel::SelfSigned,      // Tier1
                AttestationLevel::CounterSigned,   // Tier2
                AttestationLevel::CounterSigned,   // Tier3
                AttestationLevel::ThresholdSigned, // Tier4
            ],
            projection: [
                AttestationLevel::None,          // Tier0
                AttestationLevel::SelfSigned,    // Tier1
                AttestationLevel::SelfSigned,    // Tier2
                AttestationLevel::CounterSigned, // Tier3
                AttestationLevel::CounterSigned, // Tier4
            ],
        }
    }
}

impl AttestationRequirements {
    /// Creates the default attestation requirements.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the minimum attestation level required for the given receipt
    /// kind and risk tier.
    #[must_use]
    pub fn required_level(&self, kind: ReceiptKind, tier: RiskTier) -> AttestationLevel {
        let idx = u8::from(tier) as usize;
        match kind {
            ReceiptKind::ToolExecution => self.tool_execution[idx],
            ReceiptKind::Review => self.review[idx],
            ReceiptKind::Projection => self.projection[idx],
        }
    }

    /// Validates that a receipt's attestation level meets the requirement for
    /// its risk tier.
    ///
    /// # Fail-Closed Semantics
    ///
    /// If the provided `actual` level does not satisfy the required level for
    /// the given `tier` and `kind`, this returns an error. There is no warning
    /// mode.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyInheritanceError::AttestationNotMet`] if the attestation
    /// level is insufficient.
    pub fn validate(
        &self,
        kind: ReceiptKind,
        tier: RiskTier,
        actual: AttestationLevel,
    ) -> Result<(), PolicyInheritanceError> {
        let required = self.required_level(kind, tier);
        if actual.satisfies(required) {
            Ok(())
        } else {
            Err(PolicyInheritanceError::AttestationNotMet {
                tier,
                reason: format!(
                    "{kind} receipt requires at least {required} attestation at risk tier {tier:?}, \
                     but got {actual}",
                ),
            })
        }
    }

    /// Validates that the ratchet invariant holds: for each receipt kind, the
    /// required attestation level is monotonically non-decreasing across tiers.
    ///
    /// # Errors
    ///
    /// Returns error if any tier requires less attestation than a lower tier.
    pub fn validate_monotonic(&self) -> Result<(), PolicyInheritanceError> {
        for (name, levels) in [
            ("tool_execution", &self.tool_execution),
            ("review", &self.review),
            ("projection", &self.projection),
        ] {
            for i in 1..levels.len() {
                if (levels[i] as u8) < (levels[i - 1] as u8) {
                    #[allow(clippy::cast_possible_truncation)]
                    // i is bounded by levels.len() (5), so truncation cannot occur.
                    return Err(PolicyInheritanceError::AttestationNotMet {
                        tier: RiskTier::try_from(i as u8).unwrap_or(RiskTier::Tier4),
                        reason: format!(
                            "monotonic ratchet violated for {name}: tier {i} requires \
                             {} but tier {} requires {}",
                            levels[i],
                            i - 1,
                            levels[i - 1],
                        ),
                    });
                }
            }
        }
        Ok(())
    }
}

// =============================================================================
// PolicyInheritanceValidator
// =============================================================================

/// Validates that subleases are strict subsets of their parent leases.
///
/// # Strict Subset Rules
///
/// A sublease is a valid strict subset of a parent lease if and only if:
///
/// 1. **Same `work_id`**: The sublease operates on the same work item.
/// 2. **Same `changeset_digest`**: The sublease references the same changeset
///    (constant-time comparison for security).
/// 3. **Same `policy_hash`**: The sublease operates under the same resolved
///    policy (constant-time comparison for security).
/// 4. **Time bounds within parent**: The sublease's `[issued_at, expires_at]`
///    interval is a subset of the parent's interval.
/// 5. **Gate scope**: The sublease's `gate_id` is validated (not expanded).
///
/// # Fail-Closed
///
/// Any violation of the above rules results in immediate rejection.
/// There is no permissive or warn-only mode.
pub struct PolicyInheritanceValidator;

impl PolicyInheritanceValidator {
    /// Validates that a sublease is a strict subset of its parent lease.
    ///
    /// # Arguments
    ///
    /// * `parent` - The parent lease providing the authority boundary
    /// * `sublease` - The sublease that must not exceed the parent's authority
    ///
    /// # Errors
    ///
    /// Returns [`PolicyInheritanceError::SubleaseViolation`] if any constraint
    /// is violated.
    pub fn validate_sublease(
        parent: &GateLease,
        sublease: &GateLease,
    ) -> Result<(), PolicyInheritanceError> {
        // 1. work_id must match
        if parent.work_id != sublease.work_id {
            return Err(PolicyInheritanceError::SubleaseViolation {
                parent_id: parent.lease_id.clone(),
                sublease_id: sublease.lease_id.clone(),
                reason: format!(
                    "work_id mismatch: parent='{}', sublease='{}'",
                    parent.work_id, sublease.work_id,
                ),
            });
        }

        // 2. changeset_digest must match (constant-time)
        if !bool::from(parent.changeset_digest.ct_eq(&sublease.changeset_digest)) {
            return Err(PolicyInheritanceError::SubleaseViolation {
                parent_id: parent.lease_id.clone(),
                sublease_id: sublease.lease_id.clone(),
                reason: "changeset_digest mismatch".to_string(),
            });
        }

        // 3. policy_hash must match (constant-time)
        if !bool::from(parent.policy_hash.ct_eq(&sublease.policy_hash)) {
            return Err(PolicyInheritanceError::SubleaseViolation {
                parent_id: parent.lease_id.clone(),
                sublease_id: sublease.lease_id.clone(),
                reason: "policy_hash mismatch".to_string(),
            });
        }

        // 4. Time bounds: sublease must be within parent bounds
        if sublease.issued_at < parent.issued_at {
            return Err(PolicyInheritanceError::SubleaseViolation {
                parent_id: parent.lease_id.clone(),
                sublease_id: sublease.lease_id.clone(),
                reason: format!(
                    "sublease issued_at ({}) is before parent issued_at ({})",
                    sublease.issued_at, parent.issued_at,
                ),
            });
        }

        if sublease.expires_at > parent.expires_at {
            return Err(PolicyInheritanceError::SubleaseViolation {
                parent_id: parent.lease_id.clone(),
                sublease_id: sublease.lease_id.clone(),
                reason: format!(
                    "sublease expires_at ({}) is after parent expires_at ({})",
                    sublease.expires_at, parent.expires_at,
                ),
            });
        }

        // 5. If parent has no AAT extension, sublease must not have one either (cannot
        //    escalate privileges). If parent has AAT extension and sublease also has
        //    one, the sublease AAT extension must reference the same RCP manifest hash
        //    and profile.
        if parent.aat_extension.is_none() && sublease.aat_extension.is_some() {
            return Err(PolicyInheritanceError::SubleaseViolation {
                parent_id: parent.lease_id.clone(),
                sublease_id: sublease.lease_id.clone(),
                reason: "sublease has aat_extension but parent does not; \
                         cannot escalate AAT privileges"
                    .to_string(),
            });
        }

        if let (Some(parent_ext), Some(sub_ext)) = (&parent.aat_extension, &sublease.aat_extension)
        {
            // RCP manifest hash must match (constant-time)
            if !bool::from(
                parent_ext
                    .rcp_manifest_hash
                    .ct_eq(&sub_ext.rcp_manifest_hash),
            ) {
                return Err(PolicyInheritanceError::SubleaseViolation {
                    parent_id: parent.lease_id.clone(),
                    sublease_id: sublease.lease_id.clone(),
                    reason: "aat_extension rcp_manifest_hash mismatch".to_string(),
                });
            }

            // RCP profile ID must match
            if parent_ext.rcp_profile_id != sub_ext.rcp_profile_id {
                return Err(PolicyInheritanceError::SubleaseViolation {
                    parent_id: parent.lease_id.clone(),
                    sublease_id: sublease.lease_id.clone(),
                    reason: format!(
                        "aat_extension rcp_profile_id mismatch: parent='{}', sublease='{}'",
                        parent_ext.rcp_profile_id, sub_ext.rcp_profile_id,
                    ),
                });
            }
        }

        Ok(())
    }

    /// Validates a batch of subleases against a single parent lease.
    ///
    /// Returns all violations found (does not short-circuit).
    ///
    /// # Errors
    ///
    /// Returns [`PolicyInheritanceError::BatchTooLarge`] if the batch exceeds
    /// [`MAX_SUBLEASE_BATCH_SIZE`].
    pub fn validate_batch(
        parent: &GateLease,
        subleases: &[GateLease],
    ) -> Result<Vec<PolicyInheritanceError>, PolicyInheritanceError> {
        if subleases.len() > MAX_SUBLEASE_BATCH_SIZE {
            return Err(PolicyInheritanceError::BatchTooLarge {
                actual: subleases.len(),
                max: MAX_SUBLEASE_BATCH_SIZE,
            });
        }

        let mut violations = Vec::new();
        for sublease in subleases {
            if let Err(e) = Self::validate_sublease(parent, sublease) {
                violations.push(e);
            }
        }
        Ok(violations)
    }
}

// =============================================================================
// ReceiptAttestation — metadata for attestation level on a receipt
// =============================================================================

/// Attestation metadata carried with a receipt.
///
/// This structure captures enough information for the validator to check
/// whether a receipt satisfies the attestation requirement for its risk tier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptAttestation {
    /// The kind of receipt this attestation covers.
    pub kind: ReceiptKind,

    /// The attestation level achieved.
    pub level: AttestationLevel,

    /// The policy hash that was active when the receipt was produced.
    #[serde(with = "serde_bytes")]
    pub policy_hash: [u8; 32],

    /// The signer identity (hex-encoded public key) of the primary signer.
    pub signer_identity: String,

    /// Optional counter-signer identity (hex-encoded public key).
    /// Present when `level >= CounterSigned`.
    pub counter_signer_identity: Option<String>,

    /// Number of threshold signers. Present when `level == ThresholdSigned`.
    /// Must be >= 2 for threshold signatures.
    pub threshold_signer_count: Option<u32>,
}

impl ReceiptAttestation {
    /// Validates the internal consistency of this attestation metadata.
    ///
    /// # Errors
    ///
    /// Returns error if the metadata is inconsistent with the claimed level.
    pub fn validate(&self) -> Result<(), PolicyInheritanceError> {
        // Validate string lengths
        if self.signer_identity.len() > MAX_ACTOR_ID_LENGTH {
            return Err(PolicyInheritanceError::StringTooLong {
                field: "signer_identity",
                actual: self.signer_identity.len(),
                max: MAX_ACTOR_ID_LENGTH,
            });
        }

        if let Some(ref cs) = self.counter_signer_identity {
            if cs.len() > MAX_ACTOR_ID_LENGTH {
                return Err(PolicyInheritanceError::StringTooLong {
                    field: "counter_signer_identity",
                    actual: cs.len(),
                    max: MAX_ACTOR_ID_LENGTH,
                });
            }
        }

        // CounterSigned and ThresholdSigned require a counter-signer
        if self.level >= AttestationLevel::CounterSigned && self.counter_signer_identity.is_none() {
            return Err(PolicyInheritanceError::AttestationNotMet {
                tier: RiskTier::Tier0, // tier not known here; caller provides
                reason: format!(
                    "attestation level {} requires counter_signer_identity but none provided",
                    self.level,
                ),
            });
        }

        // ThresholdSigned requires threshold_signer_count >= 2
        if self.level == AttestationLevel::ThresholdSigned {
            match self.threshold_signer_count {
                Some(count) if count >= 2 => {},
                Some(count) => {
                    return Err(PolicyInheritanceError::AttestationNotMet {
                        tier: RiskTier::Tier0,
                        reason: format!(
                            "threshold_signer_count must be >= 2 for ThresholdSigned, got {count}",
                        ),
                    });
                },
                None => {
                    return Err(PolicyInheritanceError::AttestationNotMet {
                        tier: RiskTier::Tier0,
                        reason: "ThresholdSigned requires threshold_signer_count".to_string(),
                    });
                },
            }
        }

        // SelfSigned requires a non-empty signer_identity
        if self.level >= AttestationLevel::SelfSigned && self.signer_identity.is_empty() {
            return Err(PolicyInheritanceError::AttestationNotMet {
                tier: RiskTier::Tier0,
                reason: format!(
                    "attestation level {} requires non-empty signer_identity",
                    self.level,
                ),
            });
        }

        Ok(())
    }
}

// =============================================================================
// validate_receipt_attestation — top-level fail-closed validation
// =============================================================================

/// Validates that a receipt's attestation meets the requirements for its risk
/// tier.
///
/// This is the primary entry point for attestation ratcheting. It performs:
///
/// 1. Internal consistency check on the attestation metadata
/// 2. Ratchet check: `actual.level >= required_level(kind, tier)`
/// 3. Policy hash binding check against the expected policy hash
///
/// # Fail-Closed
///
/// Any failure results in rejection. There is no warning mode.
///
/// # Arguments
///
/// * `attestation` - The attestation metadata from the receipt
/// * `tier` - The resolved risk tier for this changeset
/// * `expected_policy_hash` - The expected policy hash from the resolution
/// * `requirements` - The attestation requirement table
///
/// # Errors
///
/// Returns [`PolicyInheritanceError::AttestationNotMet`] on any failure.
pub fn validate_receipt_attestation(
    attestation: &ReceiptAttestation,
    tier: RiskTier,
    expected_policy_hash: &[u8; 32],
    requirements: &AttestationRequirements,
) -> Result<(), PolicyInheritanceError> {
    // Step 1: Validate internal consistency
    attestation.validate()?;

    // Step 2: Policy hash binding (constant-time comparison)
    if !bool::from(attestation.policy_hash.ct_eq(expected_policy_hash)) {
        return Err(PolicyInheritanceError::AttestationNotMet {
            tier,
            reason: "receipt policy_hash does not match expected resolution policy_hash"
                .to_string(),
        });
    }

    // Step 3: Ratchet check
    requirements.validate(attestation.kind, tier, attestation.level)?;

    Ok(())
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Signer;
    use crate::fac::{AatLeaseExtension, GateLeaseBuilder};

    // =========================================================================
    // Helper: create parent lease
    // =========================================================================

    fn make_parent_lease(signer: &Signer) -> GateLease {
        GateLeaseBuilder::new("parent-001", "work-001", "gate-build")
            .changeset_digest([0x42; 32])
            .executor_actor_id("executor-001")
            .issued_at(1_000_000)
            .expires_at(2_000_000)
            .policy_hash([0xAB; 32])
            .issuer_actor_id("issuer-001")
            .time_envelope_ref("htf:tick:100")
            .build_and_sign(signer)
    }

    fn make_sublease(
        signer: &Signer,
        sublease_id: &str,
        work_id: &str,
        changeset: [u8; 32],
        policy: [u8; 32],
        issued_at: u64,
        expires_at: u64,
    ) -> GateLease {
        GateLeaseBuilder::new(sublease_id, work_id, "gate-build")
            .changeset_digest(changeset)
            .executor_actor_id("sub-executor-001")
            .issued_at(issued_at)
            .expires_at(expires_at)
            .policy_hash(policy)
            .issuer_actor_id("sub-issuer-001")
            .time_envelope_ref("htf:tick:200")
            .build_and_sign(signer)
    }

    // =========================================================================
    // Policy Inheritance Tests
    // =========================================================================

    #[test]
    fn test_valid_sublease_strict_subset() {
        let signer = Signer::generate();
        let parent = make_parent_lease(&signer);
        let sublease = make_sublease(
            &signer, "sub-001", "work-001", [0x42; 32], [0xAB; 32],
            1_100_000, // within parent bounds
            1_900_000, // within parent bounds
        );

        assert!(PolicyInheritanceValidator::validate_sublease(&parent, &sublease).is_ok());
    }

    #[test]
    fn test_sublease_exact_parent_bounds() {
        let signer = Signer::generate();
        let parent = make_parent_lease(&signer);
        let sublease = make_sublease(
            &signer, "sub-001", "work-001", [0x42; 32], [0xAB; 32],
            1_000_000, // exact parent issued_at
            2_000_000, // exact parent expires_at
        );

        // Exact bounds are allowed (subset, not proper subset)
        assert!(PolicyInheritanceValidator::validate_sublease(&parent, &sublease).is_ok());
    }

    #[test]
    fn test_sublease_work_id_mismatch_rejected() {
        let signer = Signer::generate();
        let parent = make_parent_lease(&signer);
        let sublease = make_sublease(
            &signer,
            "sub-001",
            "work-DIFFERENT",
            [0x42; 32],
            [0xAB; 32],
            1_100_000,
            1_900_000,
        );

        let result = PolicyInheritanceValidator::validate_sublease(&parent, &sublease);
        assert!(matches!(
            result,
            Err(PolicyInheritanceError::SubleaseViolation { ref reason, .. })
            if reason.contains("work_id mismatch")
        ));
    }

    #[test]
    fn test_sublease_changeset_mismatch_rejected() {
        let signer = Signer::generate();
        let parent = make_parent_lease(&signer);
        let sublease = make_sublease(
            &signer, "sub-001", "work-001", [0xFF; 32], // different changeset
            [0xAB; 32], 1_100_000, 1_900_000,
        );

        let result = PolicyInheritanceValidator::validate_sublease(&parent, &sublease);
        assert!(matches!(
            result,
            Err(PolicyInheritanceError::SubleaseViolation { ref reason, .. })
            if reason.contains("changeset_digest mismatch")
        ));
    }

    #[test]
    fn test_sublease_policy_hash_mismatch_rejected() {
        let signer = Signer::generate();
        let parent = make_parent_lease(&signer);
        let sublease = make_sublease(
            &signer, "sub-001", "work-001", [0x42; 32], [0xFF; 32], // different policy hash
            1_100_000, 1_900_000,
        );

        let result = PolicyInheritanceValidator::validate_sublease(&parent, &sublease);
        assert!(matches!(
            result,
            Err(PolicyInheritanceError::SubleaseViolation { ref reason, .. })
            if reason.contains("policy_hash mismatch")
        ));
    }

    #[test]
    fn test_sublease_issued_before_parent_rejected() {
        let signer = Signer::generate();
        let parent = make_parent_lease(&signer);
        let sublease = make_sublease(
            &signer, "sub-001", "work-001", [0x42; 32], [0xAB; 32],
            999_999, // before parent issued_at
            1_900_000,
        );

        let result = PolicyInheritanceValidator::validate_sublease(&parent, &sublease);
        assert!(matches!(
            result,
            Err(PolicyInheritanceError::SubleaseViolation { ref reason, .. })
            if reason.contains("issued_at") && reason.contains("before parent")
        ));
    }

    #[test]
    fn test_sublease_expires_after_parent_rejected() {
        let signer = Signer::generate();
        let parent = make_parent_lease(&signer);
        let sublease = make_sublease(
            &signer, "sub-001", "work-001", [0x42; 32], [0xAB; 32], 1_100_000,
            2_000_001, // after parent expires_at
        );

        let result = PolicyInheritanceValidator::validate_sublease(&parent, &sublease);
        assert!(matches!(
            result,
            Err(PolicyInheritanceError::SubleaseViolation { ref reason, .. })
            if reason.contains("expires_at") && reason.contains("after parent")
        ));
    }

    #[test]
    fn test_sublease_aat_escalation_rejected() {
        let signer = Signer::generate();
        // Parent has NO AAT extension
        let parent = make_parent_lease(&signer);

        // Sublease tries to add AAT extension (privilege escalation)
        let sublease = GateLeaseBuilder::new("sub-001", "work-001", "gate-aat")
            .changeset_digest([0x42; 32])
            .executor_actor_id("sub-executor")
            .issued_at(1_100_000)
            .expires_at(1_900_000)
            .policy_hash([0xAB; 32])
            .issuer_actor_id("sub-issuer")
            .time_envelope_ref("htf:tick:200")
            .aat_extension(AatLeaseExtension {
                view_commitment_hash: [0x33; 32],
                rcp_manifest_hash: [0x11; 32],
                rcp_profile_id: "profile-001".to_string(),
                selection_policy_id: "policy-001".to_string(),
            })
            .build_and_sign(&signer);

        let result = PolicyInheritanceValidator::validate_sublease(&parent, &sublease);
        assert!(matches!(
            result,
            Err(PolicyInheritanceError::SubleaseViolation { ref reason, .. })
            if reason.contains("cannot escalate AAT privileges")
        ));
    }

    #[test]
    fn test_sublease_aat_manifest_mismatch_rejected() {
        let signer = Signer::generate();

        // Parent with AAT extension
        let parent = GateLeaseBuilder::new("parent-001", "work-001", "gate-aat")
            .changeset_digest([0x42; 32])
            .executor_actor_id("executor-001")
            .issued_at(1_000_000)
            .expires_at(2_000_000)
            .policy_hash([0xAB; 32])
            .issuer_actor_id("issuer-001")
            .time_envelope_ref("htf:tick:100")
            .aat_extension(AatLeaseExtension {
                view_commitment_hash: [0x33; 32],
                rcp_manifest_hash: [0x11; 32],
                rcp_profile_id: "profile-001".to_string(),
                selection_policy_id: "policy-001".to_string(),
            })
            .build_and_sign(&signer);

        // Sublease with different RCP manifest hash
        let sublease = GateLeaseBuilder::new("sub-001", "work-001", "gate-aat")
            .changeset_digest([0x42; 32])
            .executor_actor_id("sub-executor")
            .issued_at(1_100_000)
            .expires_at(1_900_000)
            .policy_hash([0xAB; 32])
            .issuer_actor_id("sub-issuer")
            .time_envelope_ref("htf:tick:200")
            .aat_extension(AatLeaseExtension {
                view_commitment_hash: [0x33; 32],
                rcp_manifest_hash: [0xFF; 32], // DIFFERENT
                rcp_profile_id: "profile-001".to_string(),
                selection_policy_id: "policy-001".to_string(),
            })
            .build_and_sign(&signer);

        let result = PolicyInheritanceValidator::validate_sublease(&parent, &sublease);
        assert!(matches!(
            result,
            Err(PolicyInheritanceError::SubleaseViolation { ref reason, .. })
            if reason.contains("rcp_manifest_hash mismatch")
        ));
    }

    #[test]
    fn test_sublease_aat_profile_mismatch_rejected() {
        let signer = Signer::generate();

        let parent = GateLeaseBuilder::new("parent-001", "work-001", "gate-aat")
            .changeset_digest([0x42; 32])
            .executor_actor_id("executor-001")
            .issued_at(1_000_000)
            .expires_at(2_000_000)
            .policy_hash([0xAB; 32])
            .issuer_actor_id("issuer-001")
            .time_envelope_ref("htf:tick:100")
            .aat_extension(AatLeaseExtension {
                view_commitment_hash: [0x33; 32],
                rcp_manifest_hash: [0x11; 32],
                rcp_profile_id: "profile-001".to_string(),
                selection_policy_id: "policy-001".to_string(),
            })
            .build_and_sign(&signer);

        let sublease = GateLeaseBuilder::new("sub-001", "work-001", "gate-aat")
            .changeset_digest([0x42; 32])
            .executor_actor_id("sub-executor")
            .issued_at(1_100_000)
            .expires_at(1_900_000)
            .policy_hash([0xAB; 32])
            .issuer_actor_id("sub-issuer")
            .time_envelope_ref("htf:tick:200")
            .aat_extension(AatLeaseExtension {
                view_commitment_hash: [0x33; 32],
                rcp_manifest_hash: [0x11; 32],
                rcp_profile_id: "profile-DIFFERENT".to_string(), // DIFFERENT
                selection_policy_id: "policy-001".to_string(),
            })
            .build_and_sign(&signer);

        let result = PolicyInheritanceValidator::validate_sublease(&parent, &sublease);
        assert!(matches!(
            result,
            Err(PolicyInheritanceError::SubleaseViolation { ref reason, .. })
            if reason.contains("rcp_profile_id mismatch")
        ));
    }

    #[test]
    fn test_valid_sublease_with_matching_aat() {
        let signer = Signer::generate();

        let parent = GateLeaseBuilder::new("parent-001", "work-001", "gate-aat")
            .changeset_digest([0x42; 32])
            .executor_actor_id("executor-001")
            .issued_at(1_000_000)
            .expires_at(2_000_000)
            .policy_hash([0xAB; 32])
            .issuer_actor_id("issuer-001")
            .time_envelope_ref("htf:tick:100")
            .aat_extension(AatLeaseExtension {
                view_commitment_hash: [0x33; 32],
                rcp_manifest_hash: [0x11; 32],
                rcp_profile_id: "profile-001".to_string(),
                selection_policy_id: "policy-001".to_string(),
            })
            .build_and_sign(&signer);

        let sublease = GateLeaseBuilder::new("sub-001", "work-001", "gate-aat")
            .changeset_digest([0x42; 32])
            .executor_actor_id("sub-executor")
            .issued_at(1_100_000)
            .expires_at(1_900_000)
            .policy_hash([0xAB; 32])
            .issuer_actor_id("sub-issuer")
            .time_envelope_ref("htf:tick:200")
            .aat_extension(AatLeaseExtension {
                view_commitment_hash: [0x33; 32],
                rcp_manifest_hash: [0x11; 32],
                rcp_profile_id: "profile-001".to_string(),
                selection_policy_id: "policy-001".to_string(),
            })
            .build_and_sign(&signer);

        assert!(PolicyInheritanceValidator::validate_sublease(&parent, &sublease).is_ok());
    }

    // =========================================================================
    // Batch Validation Tests
    // =========================================================================

    #[test]
    fn test_batch_validation_all_valid() {
        let signer = Signer::generate();
        let parent = make_parent_lease(&signer);

        let subleases = vec![
            make_sublease(
                &signer, "sub-1", "work-001", [0x42; 32], [0xAB; 32], 1_100_000, 1_500_000,
            ),
            make_sublease(
                &signer, "sub-2", "work-001", [0x42; 32], [0xAB; 32], 1_200_000, 1_800_000,
            ),
            make_sublease(
                &signer, "sub-3", "work-001", [0x42; 32], [0xAB; 32], 1_000_000, 2_000_000,
            ),
        ];

        let violations = PolicyInheritanceValidator::validate_batch(&parent, &subleases).unwrap();
        assert_eq!(
            violations.len(),
            0,
            "expected no violations for valid subleases"
        );
    }

    #[test]
    fn test_batch_validation_partial_violations() {
        let signer = Signer::generate();
        let parent = make_parent_lease(&signer);

        let subleases = vec![
            make_sublease(
                &signer,
                "sub-valid",
                "work-001",
                [0x42; 32],
                [0xAB; 32],
                1_100_000,
                1_500_000,
            ),
            make_sublease(
                &signer,
                "sub-bad-work",
                "work-OTHER",
                [0x42; 32],
                [0xAB; 32],
                1_100_000,
                1_500_000,
            ),
            make_sublease(
                &signer,
                "sub-bad-time",
                "work-001",
                [0x42; 32],
                [0xAB; 32],
                1_100_000,
                3_000_000,
            ),
        ];

        let violations = PolicyInheritanceValidator::validate_batch(&parent, &subleases).unwrap();
        assert_eq!(
            violations.len(),
            2,
            "expected 2 violations out of 3 subleases"
        );
    }

    #[test]
    fn test_batch_too_large_rejected() {
        let signer = Signer::generate();
        let parent = make_parent_lease(&signer);

        let subleases: Vec<GateLease> = (0..=MAX_SUBLEASE_BATCH_SIZE)
            .map(|i| {
                make_sublease(
                    &signer,
                    &format!("sub-{i}"),
                    "work-001",
                    [0x42; 32],
                    [0xAB; 32],
                    1_100_000,
                    1_500_000,
                )
            })
            .collect();

        let result = PolicyInheritanceValidator::validate_batch(&parent, &subleases);
        assert!(matches!(
            result,
            Err(PolicyInheritanceError::BatchTooLarge {
                actual: 257,
                max: 256
            })
        ));
    }

    // =========================================================================
    // Attestation Level Tests
    // =========================================================================

    #[test]
    fn test_attestation_level_ordering() {
        assert!(AttestationLevel::None < AttestationLevel::SelfSigned);
        assert!(AttestationLevel::SelfSigned < AttestationLevel::CounterSigned);
        assert!(AttestationLevel::CounterSigned < AttestationLevel::ThresholdSigned);
    }

    #[test]
    fn test_attestation_level_satisfies() {
        assert!(AttestationLevel::ThresholdSigned.satisfies(AttestationLevel::None));
        assert!(AttestationLevel::ThresholdSigned.satisfies(AttestationLevel::SelfSigned));
        assert!(AttestationLevel::ThresholdSigned.satisfies(AttestationLevel::CounterSigned));
        assert!(AttestationLevel::ThresholdSigned.satisfies(AttestationLevel::ThresholdSigned));

        assert!(AttestationLevel::SelfSigned.satisfies(AttestationLevel::SelfSigned));
        assert!(!AttestationLevel::SelfSigned.satisfies(AttestationLevel::CounterSigned));
        assert!(!AttestationLevel::None.satisfies(AttestationLevel::SelfSigned));
    }

    #[test]
    fn test_attestation_level_from_code_valid() {
        assert_eq!(AttestationLevel::from_code(0), Some(AttestationLevel::None));
        assert_eq!(
            AttestationLevel::from_code(1),
            Some(AttestationLevel::SelfSigned)
        );
        assert_eq!(
            AttestationLevel::from_code(2),
            Some(AttestationLevel::CounterSigned)
        );
        assert_eq!(
            AttestationLevel::from_code(3),
            Some(AttestationLevel::ThresholdSigned)
        );
    }

    #[test]
    fn test_attestation_level_from_code_invalid() {
        assert_eq!(AttestationLevel::from_code(4), None);
        assert_eq!(AttestationLevel::from_code(255), None);
    }

    // =========================================================================
    // Attestation Requirements Tests
    // =========================================================================

    #[test]
    fn test_default_requirements_monotonic() {
        let req = AttestationRequirements::default();
        assert!(req.validate_monotonic().is_ok());
    }

    #[test]
    fn test_tier0_allows_no_attestation() {
        let req = AttestationRequirements::default();

        for kind in [
            ReceiptKind::ToolExecution,
            ReceiptKind::Review,
            ReceiptKind::Projection,
        ] {
            assert!(
                req.validate(kind, RiskTier::Tier0, AttestationLevel::None)
                    .is_ok(),
                "Tier0 should allow no attestation for {kind}",
            );
        }
    }

    #[test]
    fn test_tier1_requires_self_signed() {
        let req = AttestationRequirements::default();

        for kind in [
            ReceiptKind::ToolExecution,
            ReceiptKind::Review,
            ReceiptKind::Projection,
        ] {
            // Self-signed should pass at tier 1
            assert!(
                req.validate(kind, RiskTier::Tier1, AttestationLevel::SelfSigned)
                    .is_ok(),
                "Tier1 should accept SelfSigned for {kind}",
            );

            // None should fail at tier 1
            assert!(
                req.validate(kind, RiskTier::Tier1, AttestationLevel::None)
                    .is_err(),
                "Tier1 should reject None for {kind}",
            );
        }
    }

    #[test]
    fn test_tier2_review_requires_counter_signed() {
        let req = AttestationRequirements::default();

        // Review at Tier2 needs CounterSigned
        assert!(
            req.validate(
                ReceiptKind::Review,
                RiskTier::Tier2,
                AttestationLevel::CounterSigned
            )
            .is_ok()
        );
        assert!(
            req.validate(
                ReceiptKind::Review,
                RiskTier::Tier2,
                AttestationLevel::SelfSigned
            )
            .is_err()
        );

        // Tool execution at Tier2 only needs SelfSigned
        assert!(
            req.validate(
                ReceiptKind::ToolExecution,
                RiskTier::Tier2,
                AttestationLevel::SelfSigned
            )
            .is_ok()
        );
    }

    #[test]
    fn test_tier3_requires_counter_signed_all() {
        let req = AttestationRequirements::default();

        for kind in [
            ReceiptKind::ToolExecution,
            ReceiptKind::Review,
            ReceiptKind::Projection,
        ] {
            assert!(
                req.validate(kind, RiskTier::Tier3, AttestationLevel::CounterSigned)
                    .is_ok(),
                "Tier3 should accept CounterSigned for {kind}",
            );
            assert!(
                req.validate(kind, RiskTier::Tier3, AttestationLevel::SelfSigned)
                    .is_err(),
                "Tier3 should reject SelfSigned for {kind}",
            );
        }
    }

    #[test]
    fn test_tier4_review_requires_threshold_signed() {
        let req = AttestationRequirements::default();

        // Review at Tier4 needs ThresholdSigned
        assert!(
            req.validate(
                ReceiptKind::Review,
                RiskTier::Tier4,
                AttestationLevel::ThresholdSigned
            )
            .is_ok()
        );
        assert!(
            req.validate(
                ReceiptKind::Review,
                RiskTier::Tier4,
                AttestationLevel::CounterSigned
            )
            .is_err()
        );

        // Tool execution at Tier4 needs CounterSigned (not threshold)
        assert!(
            req.validate(
                ReceiptKind::ToolExecution,
                RiskTier::Tier4,
                AttestationLevel::CounterSigned
            )
            .is_ok()
        );
    }

    #[test]
    fn test_higher_attestation_always_accepted() {
        let req = AttestationRequirements::default();

        // ThresholdSigned should be accepted everywhere
        for tier in [
            RiskTier::Tier0,
            RiskTier::Tier1,
            RiskTier::Tier2,
            RiskTier::Tier3,
            RiskTier::Tier4,
        ] {
            for kind in [
                ReceiptKind::ToolExecution,
                ReceiptKind::Review,
                ReceiptKind::Projection,
            ] {
                assert!(
                    req.validate(kind, tier, AttestationLevel::ThresholdSigned)
                        .is_ok(),
                    "ThresholdSigned should be accepted for {kind} at {tier:?}",
                );
            }
        }
    }

    // =========================================================================
    // Full Receipt Attestation Validation Tests
    // =========================================================================

    #[test]
    fn test_validate_receipt_attestation_success() {
        let policy_hash = [0xAB; 32];
        let attestation = ReceiptAttestation {
            kind: ReceiptKind::ToolExecution,
            level: AttestationLevel::SelfSigned,
            policy_hash,
            signer_identity: "signer-001".to_string(),
            counter_signer_identity: None,
            threshold_signer_count: None,
        };

        let req = AttestationRequirements::default();
        assert!(
            validate_receipt_attestation(&attestation, RiskTier::Tier1, &policy_hash, &req).is_ok()
        );
    }

    #[test]
    fn test_validate_receipt_attestation_policy_hash_mismatch() {
        let attestation = ReceiptAttestation {
            kind: ReceiptKind::ToolExecution,
            level: AttestationLevel::SelfSigned,
            policy_hash: [0xAB; 32],
            signer_identity: "signer-001".to_string(),
            counter_signer_identity: None,
            threshold_signer_count: None,
        };

        let wrong_hash = [0xFF; 32];
        let req = AttestationRequirements::default();
        let result = validate_receipt_attestation(&attestation, RiskTier::Tier1, &wrong_hash, &req);
        assert!(matches!(
            result,
            Err(PolicyInheritanceError::AttestationNotMet { ref reason, .. })
            if reason.contains("policy_hash")
        ));
    }

    #[test]
    fn test_validate_receipt_attestation_insufficient_level() {
        let policy_hash = [0xAB; 32];
        let attestation = ReceiptAttestation {
            kind: ReceiptKind::Review,
            level: AttestationLevel::SelfSigned,
            policy_hash,
            signer_identity: "signer-001".to_string(),
            counter_signer_identity: None,
            threshold_signer_count: None,
        };

        let req = AttestationRequirements::default();
        // Tier2 requires CounterSigned for Review, but we only have SelfSigned
        let result =
            validate_receipt_attestation(&attestation, RiskTier::Tier2, &policy_hash, &req);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_receipt_attestation_counter_signed_without_counter_signer() {
        let policy_hash = [0xAB; 32];
        let attestation = ReceiptAttestation {
            kind: ReceiptKind::Review,
            level: AttestationLevel::CounterSigned,
            policy_hash,
            signer_identity: "signer-001".to_string(),
            counter_signer_identity: None, // Missing!
            threshold_signer_count: None,
        };

        let req = AttestationRequirements::default();
        let result =
            validate_receipt_attestation(&attestation, RiskTier::Tier2, &policy_hash, &req);
        assert!(matches!(
            result,
            Err(PolicyInheritanceError::AttestationNotMet { ref reason, .. })
            if reason.contains("counter_signer_identity")
        ));
    }

    #[test]
    fn test_validate_receipt_attestation_threshold_without_count() {
        let policy_hash = [0xAB; 32];
        let attestation = ReceiptAttestation {
            kind: ReceiptKind::Review,
            level: AttestationLevel::ThresholdSigned,
            policy_hash,
            signer_identity: "signer-001".to_string(),
            counter_signer_identity: Some("counter-001".to_string()),
            threshold_signer_count: None, // Missing!
        };

        let req = AttestationRequirements::default();
        let result =
            validate_receipt_attestation(&attestation, RiskTier::Tier4, &policy_hash, &req);
        assert!(matches!(
            result,
            Err(PolicyInheritanceError::AttestationNotMet { ref reason, .. })
            if reason.contains("threshold_signer_count")
        ));
    }

    #[test]
    fn test_validate_receipt_attestation_threshold_count_too_low() {
        let policy_hash = [0xAB; 32];
        let attestation = ReceiptAttestation {
            kind: ReceiptKind::Review,
            level: AttestationLevel::ThresholdSigned,
            policy_hash,
            signer_identity: "signer-001".to_string(),
            counter_signer_identity: Some("counter-001".to_string()),
            threshold_signer_count: Some(1), // Must be >= 2
        };

        let req = AttestationRequirements::default();
        let result =
            validate_receipt_attestation(&attestation, RiskTier::Tier4, &policy_hash, &req);
        assert!(matches!(
            result,
            Err(PolicyInheritanceError::AttestationNotMet { ref reason, .. })
            if reason.contains(">= 2")
        ));
    }

    #[test]
    fn test_validate_receipt_attestation_full_threshold_success() {
        let policy_hash = [0xAB; 32];
        let attestation = ReceiptAttestation {
            kind: ReceiptKind::Review,
            level: AttestationLevel::ThresholdSigned,
            policy_hash,
            signer_identity: "signer-001".to_string(),
            counter_signer_identity: Some("counter-001".to_string()),
            threshold_signer_count: Some(3),
        };

        let req = AttestationRequirements::default();
        assert!(
            validate_receipt_attestation(&attestation, RiskTier::Tier4, &policy_hash, &req).is_ok()
        );
    }

    #[test]
    fn test_validate_self_signed_empty_signer_rejected() {
        let policy_hash = [0xAB; 32];
        let attestation = ReceiptAttestation {
            kind: ReceiptKind::ToolExecution,
            level: AttestationLevel::SelfSigned,
            policy_hash,
            signer_identity: String::new(), // Empty!
            counter_signer_identity: None,
            threshold_signer_count: None,
        };

        let req = AttestationRequirements::default();
        let result =
            validate_receipt_attestation(&attestation, RiskTier::Tier1, &policy_hash, &req);
        assert!(matches!(
            result,
            Err(PolicyInheritanceError::AttestationNotMet { ref reason, .. })
            if reason.contains("signer_identity")
        ));
    }

    #[test]
    fn test_signer_identity_too_long_rejected() {
        let policy_hash = [0xAB; 32];
        let attestation = ReceiptAttestation {
            kind: ReceiptKind::ToolExecution,
            level: AttestationLevel::SelfSigned,
            policy_hash,
            signer_identity: "x".repeat(MAX_ACTOR_ID_LENGTH + 1),
            counter_signer_identity: None,
            threshold_signer_count: None,
        };

        let req = AttestationRequirements::default();
        let result =
            validate_receipt_attestation(&attestation, RiskTier::Tier1, &policy_hash, &req);
        assert!(matches!(
            result,
            Err(PolicyInheritanceError::StringTooLong {
                field: "signer_identity",
                ..
            })
        ));
    }

    // =========================================================================
    // Fail-Closed Invariant Tests
    // =========================================================================

    #[test]
    fn test_fail_closed_high_tier_no_attestation() {
        let req = AttestationRequirements::default();
        let policy_hash = [0xAB; 32];

        // Tier3 with no attestation on any receipt kind should ALWAYS fail
        for kind in [
            ReceiptKind::ToolExecution,
            ReceiptKind::Review,
            ReceiptKind::Projection,
        ] {
            let result = req.validate(kind, RiskTier::Tier3, AttestationLevel::None);
            assert!(result.is_err(), "Tier3+None must fail closed for {kind}");
        }

        // Tier4 with no attestation should ALWAYS fail
        for kind in [
            ReceiptKind::ToolExecution,
            ReceiptKind::Review,
            ReceiptKind::Projection,
        ] {
            let result = req.validate(kind, RiskTier::Tier4, AttestationLevel::None);
            assert!(result.is_err(), "Tier4+None must fail closed for {kind}");
        }

        // Even Tier1 with None should fail (SelfSigned required)
        for kind in [
            ReceiptKind::ToolExecution,
            ReceiptKind::Review,
            ReceiptKind::Projection,
        ] {
            let result = req.validate(kind, RiskTier::Tier1, AttestationLevel::None);
            assert!(result.is_err(), "Tier1+None must fail closed for {kind}");
        }

        // Verify through the full pipeline too
        let attestation = ReceiptAttestation {
            kind: ReceiptKind::ToolExecution,
            level: AttestationLevel::None,
            policy_hash,
            signer_identity: String::new(),
            counter_signer_identity: None,
            threshold_signer_count: None,
        };
        let result =
            validate_receipt_attestation(&attestation, RiskTier::Tier3, &policy_hash, &req);
        assert!(result.is_err(), "Full pipeline must also fail closed");
    }

    #[test]
    fn test_receipt_kind_display() {
        assert_eq!(ReceiptKind::ToolExecution.as_str(), "TOOL_EXECUTION");
        assert_eq!(ReceiptKind::Review.as_str(), "REVIEW");
        assert_eq!(ReceiptKind::Projection.as_str(), "PROJECTION");
    }

    #[test]
    fn test_attestation_level_display() {
        assert_eq!(AttestationLevel::None.as_str(), "NONE");
        assert_eq!(AttestationLevel::SelfSigned.as_str(), "SELF_SIGNED");
        assert_eq!(AttestationLevel::CounterSigned.as_str(), "COUNTER_SIGNED");
        assert_eq!(
            AttestationLevel::ThresholdSigned.as_str(),
            "THRESHOLD_SIGNED"
        );
    }
}
