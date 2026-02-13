// AGENT-AUTHORED
//! AAT reuse provenance validation.
//!
//! This module implements the logic for determining whether a previous AAT
//! result can be reused for a new admission attempt. Reuse is strictly
//! controlled based on the risk tier of the change.
//!
//! # Reuse Policy (FAC-REQ-0013)
//!
//! - **High Risk (Tier 2-4)**: AAT results are NEVER reused. High-risk changes
//!   require fresh execution to ensure no environment drift or ephemeral
//!   factors affect the outcome.
//! - **Medium Risk (Tier 1)**: Reuse is allowed only with an explicit waiver.
//! - **Low Risk (Tier 0)**: Reuse is allowed if the provenance tuple matches
//!   exactly.
//!
//! # Provenance Tuple
//!
//! The provenance tuple identifies the execution context:
//! - `changeset_digest`: The code being tested.
//! - `view_commitment_hash`: The view of the world (dependencies, etc.).
//! - `rcp_profile_id`: The resource profile used.
//! - `verifier_policy_hash`: The verification logic applied.
//! - `determinism_class`: The required determinism level.
//!
//! All fields must match exactly for reuse to be permitted.
//!
//! # Security
//!
//! Hash comparisons use constant-time operations via the `subtle` crate to
//! prevent timing side-channel attacks.

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use thiserror::Error;

use super::policy_resolution::{DeterminismClass, MAX_STRING_LENGTH, RiskTier};
// Re-export proto types
pub use crate::events::{
    AatProvenanceTuple as AatProvenanceTupleProto, AatResultReused as AATResultReusedProto,
};

// =============================================================================
// Error Types
// =============================================================================

/// Errors that can occur during AAT reuse validation.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ReuseError {
    /// High risk tier does not allow reuse.
    #[error("HIGH risk tier ({tier:?}) does not allow AAT result reuse")]
    HighTierNoReuse {
        /// The risk tier that blocked reuse.
        tier: RiskTier,
    },

    /// Medium risk tier requires a waiver for reuse.
    #[error("MED risk tier ({tier:?}) requires waiver for AAT result reuse")]
    MedTierRequiresWaiver {
        /// The risk tier.
        tier: RiskTier,
    },

    /// Provenance tuple mismatch.
    #[error("provenance mismatch: {field} differs (original={original}, current={current})")]
    ProvenanceMismatch {
        /// The field that mismatched.
        field: &'static str,
        /// Value in the original receipt.
        original: String,
        /// Value in the current context.
        current: String,
    },

    /// Invalid data in conversion.
    #[error("invalid data: {0}")]
    InvalidData(String),

    /// Missing required field.
    #[error("missing required field: {0}")]
    MissingField(&'static str),

    /// String field exceeds maximum length.
    #[error("string field '{field}' exceeds maximum length ({len} > {max})")]
    StringTooLong {
        /// The field name.
        field: &'static str,
        /// Actual length.
        len: usize,
        /// Maximum allowed length.
        max: usize,
    },
}

// =============================================================================
// Domain Types
// =============================================================================

/// Provenance tuple identifying the context of an AAT execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AatProvenanceTuple {
    /// Hash binding to specific changeset.
    #[serde(with = "serde_bytes")]
    pub changeset_digest: [u8; 32],

    /// Hash binding to view commitment.
    #[serde(with = "serde_bytes")]
    pub view_commitment_hash: [u8; 32],

    /// RCP profile identifier.
    pub rcp_profile_id: String,

    /// Hash of the verifier policy.
    #[serde(with = "serde_bytes")]
    pub verifier_policy_hash: [u8; 32],

    /// Determinism class.
    pub determinism_class: DeterminismClass,
}

impl AatProvenanceTuple {
    /// Checks if this tuple matches another tuple exactly.
    ///
    /// # Security
    ///
    /// Hash comparisons use constant-time operations to prevent timing
    /// side-channel attacks.
    ///
    /// # Returns
    ///
    /// `Ok(())` if they match, `Err(ReuseError::ProvenanceMismatch)` otherwise.
    ///
    /// # Errors
    ///
    /// Returns `ReuseError::ProvenanceMismatch` if any field differs between
    /// the tuples.
    pub fn verify_match(&self, other: &Self) -> Result<(), ReuseError> {
        // Use constant-time comparison for hash fields to prevent timing attacks
        if self.changeset_digest.ct_eq(&other.changeset_digest).into() {
            // Match - continue
        } else {
            return Err(ReuseError::ProvenanceMismatch {
                field: "changeset_digest",
                original: hex::encode(self.changeset_digest),
                current: hex::encode(other.changeset_digest),
            });
        }

        if self
            .view_commitment_hash
            .ct_eq(&other.view_commitment_hash)
            .into()
        {
            // Match - continue
        } else {
            return Err(ReuseError::ProvenanceMismatch {
                field: "view_commitment_hash",
                original: hex::encode(self.view_commitment_hash),
                current: hex::encode(other.view_commitment_hash),
            });
        }

        if self.rcp_profile_id != other.rcp_profile_id {
            return Err(ReuseError::ProvenanceMismatch {
                field: "rcp_profile_id",
                original: self.rcp_profile_id.clone(),
                current: other.rcp_profile_id.clone(),
            });
        }

        if self
            .verifier_policy_hash
            .ct_eq(&other.verifier_policy_hash)
            .into()
        {
            // Match - continue
        } else {
            return Err(ReuseError::ProvenanceMismatch {
                field: "verifier_policy_hash",
                original: hex::encode(self.verifier_policy_hash),
                current: hex::encode(other.verifier_policy_hash),
            });
        }

        if self.determinism_class != other.determinism_class {
            return Err(ReuseError::ProvenanceMismatch {
                field: "determinism_class",
                original: format!("{:?}", self.determinism_class),
                current: format!("{:?}", other.determinism_class),
            });
        }
        Ok(())
    }
}

/// Event payload for reused AAT results.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AATResultReused {
    /// Hash of the original `AatGateReceipt` being reused.
    #[serde(with = "serde_bytes")]
    pub from_receipt_hash: [u8; 32],

    /// Provenance tuple of the current context.
    pub provenance: AatProvenanceTuple,

    /// Policy hash for the current admission attempt.
    #[serde(with = "serde_bytes")]
    pub policy_hash: [u8; 32],

    /// Human-readable justification for reuse.
    pub justification: String,

    /// Gate signature proving authorization.
    ///
    /// # TODO: Signature Verification
    ///
    /// This field stores the raw signature bytes. Full signature verification
    /// requires:
    /// 1. `canonical_bytes()` method to produce the signed message
    /// 2. `validate_signature()` method to verify against the gate's public key
    ///
    /// These are deferred pending integration with the gate key registry.
    #[serde(with = "serde_bytes")]
    pub gate_signature: [u8; 64],
}

// =============================================================================
// Validation Logic
// =============================================================================

/// Validates whether an AAT result can be reused based on risk tier and
/// provenance.
///
/// # Arguments
///
/// * `risk_tier` - The risk tier of the current change.
/// * `original` - The provenance of the original result.
/// * `current` - The provenance of the current context.
///
/// # Returns
///
/// `Ok(())` if reuse is allowed.
/// `Err` if reuse is prohibited by policy or provenance mismatch.
///
/// # Errors
///
/// Returns:
/// - `ReuseError::HighTierNoReuse` for Tier2-4 risk levels
/// - `ReuseError::MedTierRequiresWaiver` for Tier1 risk level
/// - `ReuseError::ProvenanceMismatch` if provenance tuples do not match exactly
pub fn can_reuse_aat_result(
    risk_tier: RiskTier,
    original: &AatProvenanceTuple,
    current: &AatProvenanceTuple,
) -> Result<(), ReuseError> {
    match risk_tier {
        // High Risk: Never reuse
        RiskTier::Tier2 | RiskTier::Tier3 | RiskTier::Tier4 => {
            Err(ReuseError::HighTierNoReuse { tier: risk_tier })
        },

        // Medium Risk: Requires waiver (not implemented here, effectively blocks reuse)
        RiskTier::Tier1 => Err(ReuseError::MedTierRequiresWaiver { tier: risk_tier }),

        // Low Risk: Allowed if provenance matches
        RiskTier::Tier0 => original.verify_match(current),
    }
}

// =============================================================================
// Proto Conversions
// =============================================================================

impl TryFrom<AatProvenanceTupleProto> for AatProvenanceTuple {
    type Error = ReuseError;

    fn try_from(proto: AatProvenanceTupleProto) -> Result<Self, Self::Error> {
        // Validate string field lengths
        if proto.rcp_profile_id.len() > MAX_STRING_LENGTH {
            return Err(ReuseError::StringTooLong {
                field: "rcp_profile_id",
                len: proto.rcp_profile_id.len(),
                max: MAX_STRING_LENGTH,
            });
        }

        let changeset_digest = proto
            .changeset_digest
            .try_into()
            .map_err(|_| ReuseError::InvalidData("changeset_digest must be 32 bytes".into()))?;
        let view_commitment_hash = proto
            .view_commitment_hash
            .try_into()
            .map_err(|_| ReuseError::InvalidData("view_commitment_hash must be 32 bytes".into()))?;
        let verifier_policy_hash = proto
            .verifier_policy_hash
            .try_into()
            .map_err(|_| ReuseError::InvalidData("verifier_policy_hash must be 32 bytes".into()))?;

        let determinism_class = DeterminismClass::try_from(
            u8::try_from(proto.determinism_class)
                .map_err(|_| ReuseError::InvalidData("determinism_class too large".into()))?,
        )
        .map_err(|_| ReuseError::InvalidData("invalid determinism_class".into()))?;

        Ok(Self {
            changeset_digest,
            view_commitment_hash,
            rcp_profile_id: proto.rcp_profile_id,
            verifier_policy_hash,
            determinism_class,
        })
    }
}

impl From<AatProvenanceTuple> for AatProvenanceTupleProto {
    fn from(domain: AatProvenanceTuple) -> Self {
        Self {
            changeset_digest: domain.changeset_digest.to_vec(),
            view_commitment_hash: domain.view_commitment_hash.to_vec(),
            rcp_profile_id: domain.rcp_profile_id,
            verifier_policy_hash: domain.verifier_policy_hash.to_vec(),
            determinism_class: u32::from(u8::from(domain.determinism_class)),
        }
    }
}

impl TryFrom<AATResultReusedProto> for AATResultReused {
    type Error = ReuseError;

    fn try_from(proto: AATResultReusedProto) -> Result<Self, Self::Error> {
        // Validate string field lengths
        if proto.justification.len() > MAX_STRING_LENGTH {
            return Err(ReuseError::StringTooLong {
                field: "justification",
                len: proto.justification.len(),
                max: MAX_STRING_LENGTH,
            });
        }

        let from_receipt_hash = proto
            .from_receipt_hash
            .try_into()
            .map_err(|_| ReuseError::InvalidData("from_receipt_hash must be 32 bytes".into()))?;
        let policy_hash = proto
            .policy_hash
            .try_into()
            .map_err(|_| ReuseError::InvalidData("policy_hash must be 32 bytes".into()))?;
        let gate_signature = proto
            .gate_signature
            .try_into()
            .map_err(|_| ReuseError::InvalidData("gate_signature must be 64 bytes".into()))?;

        let provenance = proto
            .provenance
            .ok_or(ReuseError::MissingField("provenance"))?
            .try_into()?;

        Ok(Self {
            from_receipt_hash,
            provenance,
            policy_hash,
            justification: proto.justification,
            gate_signature,
        })
    }
}

impl From<AATResultReused> for AATResultReusedProto {
    fn from(domain: AATResultReused) -> Self {
        Self {
            from_receipt_hash: domain.from_receipt_hash.to_vec(),
            provenance: Some(domain.provenance.into()),
            policy_hash: domain.policy_hash.to_vec(),
            justification: domain.justification,
            gate_signature: domain.gate_signature.to_vec(),
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn create_tuple(id: u8) -> AatProvenanceTuple {
        AatProvenanceTuple {
            changeset_digest: [id; 32],
            view_commitment_hash: [id; 32],
            rcp_profile_id: format!("profile-{id}"),
            verifier_policy_hash: [id; 32],
            determinism_class: DeterminismClass::FullyDeterministic,
        }
    }

    #[test]
    fn test_high_tier_never_reuses() {
        let t1 = create_tuple(1);
        // Even if tuples match perfectly
        for tier in [RiskTier::Tier2, RiskTier::Tier3, RiskTier::Tier4] {
            let result = can_reuse_aat_result(tier, &t1, &t1);
            assert!(matches!(result, Err(ReuseError::HighTierNoReuse { .. })));
        }
    }

    #[test]
    fn test_med_tier_requires_waiver() {
        let t1 = create_tuple(1);
        // Even if tuples match
        let result = can_reuse_aat_result(RiskTier::Tier1, &t1, &t1);
        assert!(matches!(
            result,
            Err(ReuseError::MedTierRequiresWaiver { .. })
        ));
    }

    #[test]
    fn test_low_tier_reuse_success() {
        let t1 = create_tuple(1);
        // Exact match allows reuse
        assert!(can_reuse_aat_result(RiskTier::Tier0, &t1, &t1).is_ok());
    }

    #[test]
    fn test_low_tier_provenance_mismatch() {
        let t1 = create_tuple(1);
        let t2 = create_tuple(2);

        // Mismatch rejects reuse
        let result = can_reuse_aat_result(RiskTier::Tier0, &t1, &t2);
        assert!(matches!(result, Err(ReuseError::ProvenanceMismatch { .. })));
    }

    #[test]
    fn test_tuple_verify_match_field_check() {
        let base = create_tuple(1);

        // Changeset mismatch
        let mut t = base.clone();
        t.changeset_digest = [0x99; 32];
        let err = base.verify_match(&t).unwrap_err();
        match err {
            ReuseError::ProvenanceMismatch { field, .. } => assert_eq!(field, "changeset_digest"),
            _ => panic!("wrong error"),
        }

        // Determinism class mismatch
        let mut t = base.clone();
        t.determinism_class = DeterminismClass::NonDeterministic;
        let err = base.verify_match(&t).unwrap_err();
        match err {
            ReuseError::ProvenanceMismatch { field, .. } => assert_eq!(field, "determinism_class"),
            _ => panic!("wrong error"),
        }
    }

    #[test]
    fn test_proto_roundtrip() {
        let original = AATResultReused {
            from_receipt_hash: [0x11; 32],
            provenance: create_tuple(1),
            policy_hash: [0x22; 32],
            justification: "test".to_string(),
            gate_signature: [0x33; 64],
        };

        let proto: AATResultReusedProto = original.clone().into();
        let recovered: AATResultReused = proto.try_into().unwrap();

        assert_eq!(original, recovered);
    }

    #[test]
    fn test_rcp_profile_id_too_long() {
        let long_string = "x".repeat(MAX_STRING_LENGTH + 1);
        let proto = AatProvenanceTupleProto {
            changeset_digest: vec![0; 32],
            view_commitment_hash: vec![0; 32],
            rcp_profile_id: long_string,
            verifier_policy_hash: vec![0; 32],
            determinism_class: 0,
        };

        let result: Result<AatProvenanceTuple, _> = proto.try_into();
        assert!(matches!(
            result,
            Err(ReuseError::StringTooLong {
                field: "rcp_profile_id",
                ..
            })
        ));
    }

    #[test]
    fn test_justification_too_long() {
        let long_string = "x".repeat(MAX_STRING_LENGTH + 1);
        let proto = AATResultReusedProto {
            from_receipt_hash: vec![0; 32],
            provenance: Some(AatProvenanceTupleProto {
                changeset_digest: vec![0; 32],
                view_commitment_hash: vec![0; 32],
                rcp_profile_id: "valid".to_string(),
                verifier_policy_hash: vec![0; 32],
                determinism_class: 0,
            }),
            policy_hash: vec![0; 32],
            justification: long_string,
            gate_signature: vec![0; 64],
        };

        let result: Result<AATResultReused, _> = proto.try_into();
        assert!(matches!(
            result,
            Err(ReuseError::StringTooLong {
                field: "justification",
                ..
            })
        ));
    }

    #[test]
    fn test_constant_time_comparison_behavior() {
        // This test verifies the constant-time comparison is used correctly.
        // We can't directly test timing, but we can verify the logic works.
        let t1 = create_tuple(1);
        let mut t2 = create_tuple(1);

        // Same values should match
        assert!(t1.verify_match(&t2).is_ok());

        // Different first byte should fail
        t2.changeset_digest[0] = 0xFF;
        assert!(t1.verify_match(&t2).is_err());

        // Different last byte should fail
        t2.changeset_digest[0] = 1;
        t2.changeset_digest[31] = 0xFF;
        assert!(t1.verify_match(&t2).is_err());
    }
}
