// AGENT-AUTHORED
//! Anti-downgrade enforcement for the Forge Admission Cycle.
//!
//! This module implements anti-downgrade checks that prevent attackers from
//! lowering security requirements after policy resolution. All checks must
//! pass for a receipt to be admitted.
//!
//! # Security Model
//!
//! Anti-downgrade enforcement is SECURITY-CRITICAL code that:
//!
//! - **Prevents policy substitution**: Ensures `receipt.policy_hash` matches
//!   the resolved policy hash
//! - **Prevents risk tier downgrade**: Ensures the receipt's risk tier is not
//!   lower than the resolved risk tier
//! - **Validates verifier policy**: Ensures the receipt's verifier policy hash
//!   is in the resolved list
//! - **Validates RCP profile**: Ensures the receipt's RCP profile ID is in the
//!   resolved list
//!
//! # Fail-Closed Design
//!
//! This module uses a FAIL-CLOSED approach: if any check cannot be verified,
//! the receipt is rejected. This ensures that partial or corrupted data cannot
//! bypass security controls.
//!
//! # Example
//!
//! ```rust
//! use apm2_core::crypto::Signer;
//! use apm2_core::fac::anti_downgrade::verify_no_downgrade;
//! use apm2_core::fac::{
//!     AatAttestation, AatGateReceipt, AatGateReceiptBuilder, AatVerdict, DeterminismClass,
//!     DeterminismStatus, FlakeClass, PolicyResolvedForChangeSet,
//!     PolicyResolvedForChangeSetBuilder, RiskTier, TerminalVerifierOutput,
//! };
//!
//! // Create a policy resolution
//! let resolver = Signer::generate();
//! let resolution = PolicyResolvedForChangeSetBuilder::new("work-001", [0x42; 32])
//!     .resolved_risk_tier(2)
//!     .resolved_determinism_class(0)
//!     .add_rcp_profile_id("profile-001")
//!     .add_rcp_manifest_hash([0x11; 32])
//!     .add_verifier_policy_hash([0x22; 32])
//!     .resolver_actor_id("resolver-001")
//!     .resolver_version("1.0.0")
//!     .build_and_sign(&resolver);
//!
//! // Create a matching receipt
//! let terminal_evidence_digest = [0x77; 32];
//! let terminal_verifier_outputs_digest = [0x99; 32];
//! let stability_digest = AatGateReceipt::compute_stability_digest(
//!     AatVerdict::Pass,
//!     &terminal_evidence_digest,
//!     &terminal_verifier_outputs_digest,
//! );
//!
//! let receipt = AatGateReceiptBuilder::new()
//!     .view_commitment_hash([0x11; 32])
//!     .rcp_manifest_hash([0x11; 32])
//!     .rcp_profile_id("profile-001")
//!     .policy_hash(resolution.resolved_policy_hash())
//!     .determinism_class(DeterminismClass::FullyDeterministic)
//!     .determinism_status(DeterminismStatus::Stable)
//!     .flake_class(FlakeClass::DeterministicFail)
//!     .run_count(1)
//!     .run_receipt_hashes(vec![[0x44; 32]])
//!     .terminal_evidence_digest(terminal_evidence_digest)
//!     .observational_evidence_digest([0x88; 32])
//!     .terminal_verifier_outputs_digest(terminal_verifier_outputs_digest)
//!     .stability_digest(stability_digest)
//!     .verdict(AatVerdict::Pass)
//!     .transcript_chain_root_hash([0xBB; 32])
//!     .transcript_bundle_hash([0xCC; 32])
//!     .artifact_manifest_hash([0xDD; 32])
//!     .terminal_verifier_outputs(vec![TerminalVerifierOutput {
//!         verifier_kind: "exit_code".to_string(),
//!         output_digest: [0xEE; 32],
//!         predicate_satisfied: true,
//!     }])
//!     .verifier_policy_hash([0x22; 32])
//!     .selection_policy_id("policy-001")
//!     .risk_tier(RiskTier::Tier2)
//!     .attestation(AatAttestation {
//!         container_image_digest: [0x01; 32],
//!         toolchain_digests: vec![[0x02; 32]],
//!         runner_identity_key_id: "runner-001".to_string(),
//!         network_policy_profile_hash: [0x03; 32],
//!     })
//!     .build()
//!     .expect("valid receipt");
//!
//! // Verify no downgrade
//! assert!(verify_no_downgrade(&resolution, &receipt).is_ok());
//! ```

use subtle::ConstantTimeEq;
use thiserror::Error;

use super::aat_receipt::AatGateReceipt;
use super::policy_resolution::{PolicyResolvedForChangeSet, RiskTier};

// =============================================================================
// Error Types
// =============================================================================

/// Errors that indicate a potential security downgrade attempt.
///
/// These errors are SECURITY-CRITICAL and should be logged and monitored.
/// Any occurrence may indicate an attack or system compromise.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DowngradeError {
    /// The receipt's policy hash does not match the resolved policy hash.
    ///
    /// This indicates that the receipt was created under a different policy
    /// configuration than what was resolved for this changeset. This could
    /// indicate an attempt to substitute a weaker policy.
    #[error("policy hash mismatch: receipt policy hash does not match resolved policy hash")]
    PolicyHashMismatch,

    /// The receipt's risk tier is lower than the resolved risk tier.
    ///
    /// This indicates an attempt to lower the security requirements after
    /// policy resolution. Higher risk tiers require more scrutiny.
    #[error(
        "risk tier downgrade: receipt risk tier ({receipt_tier:?}) is lower than resolved ({resolved_tier:?})"
    )]
    RiskTierDowngrade {
        /// The risk tier from the receipt.
        receipt_tier: RiskTier,
        /// The risk tier from the policy resolution.
        resolved_tier: RiskTier,
    },

    /// The receipt's verifier policy hash is not in the resolved list.
    ///
    /// This indicates that the receipt uses a verifier policy that was not
    /// approved during policy resolution. This could allow unapproved
    /// verification logic.
    #[error(
        "verifier policy not resolved: receipt verifier policy hash is not in the resolved list"
    )]
    VerifierPolicyNotResolved,

    /// The receipt's RCP profile ID is not in the resolved list.
    ///
    /// This indicates that the receipt uses an RCP profile that was not
    /// approved during policy resolution. This could allow unapproved
    /// runtime configuration.
    #[error(
        "RCP profile not resolved: receipt RCP profile ID '{profile_id}' is not in the resolved list"
    )]
    RcpProfileNotResolved {
        /// The RCP profile ID from the receipt that was not found.
        profile_id: String,
    },

    /// The resolved risk tier value is invalid (not in range 0-4).
    ///
    /// This indicates data corruption or a malformed policy resolution.
    /// The check fails closed to prevent bypassing security controls.
    #[error("invalid risk tier: resolved risk tier value {tier_value} is not valid (expected 0-4)")]
    InvalidRiskTier {
        /// The invalid tier value that was encountered.
        tier_value: u8,
    },
}

// =============================================================================
// Anti-Downgrade Verification
// =============================================================================

/// Verifies that a receipt does not represent a security downgrade from the
/// resolved policy.
///
/// This function performs four critical security checks:
///
/// 1. **Policy Hash Match**: The receipt's `policy_hash` must exactly match the
///    resolution's `resolved_policy_hash`. This prevents policy substitution
///    attacks.
///
/// 2. **Risk Tier Non-Downgrade**: The receipt's `risk_tier` must be greater
///    than or equal to the resolution's `resolved_risk_tier`. This prevents
///    attackers from lowering the required scrutiny level.
///
/// 3. **Verifier Policy Resolved**: The receipt's `verifier_policy_hash` must
///    be present in the resolution's `resolved_verifier_policy_hashes`. This
///    ensures only approved verification logic is used.
///
/// 4. **RCP Profile Resolved**: The receipt's `rcp_profile_id` must be present
///    in the resolution's `resolved_rcp_profile_ids`. This ensures only
///    approved runtime configurations are used.
///
/// # Security
///
/// - Uses constant-time comparison for hash checks to prevent timing attacks
/// - Uses FAIL-CLOSED approach: any verification failure results in rejection
/// - All checks are performed; partial success is not possible
///
/// # Arguments
///
/// * `resolved` - The policy resolution anchor for this changeset
/// * `receipt` - The AAT gate receipt to verify
///
/// # Returns
///
/// `Ok(())` if all anti-downgrade checks pass, or an appropriate
/// [`DowngradeError`] if any check fails.
///
/// # Errors
///
/// Returns [`DowngradeError::PolicyHashMismatch`] if the policy hashes don't
/// match.
/// Returns [`DowngradeError::RiskTierDowngrade`] if the receipt's risk tier is
/// lower than resolved.
/// Returns [`DowngradeError::VerifierPolicyNotResolved`] if the verifier policy
/// hash is not in the resolved list.
/// Returns [`DowngradeError::RcpProfileNotResolved`] if the RCP profile ID is
/// not in the resolved list.
/// Returns [`DowngradeError::InvalidRiskTier`] if the resolved risk tier value
/// is not valid (0-4). This indicates data corruption and fails closed.
pub fn verify_no_downgrade(
    resolved: &PolicyResolvedForChangeSet,
    receipt: &AatGateReceipt,
) -> Result<(), DowngradeError> {
    // Check 1: Policy hash must match (constant-time comparison)
    if !bool::from(resolved.resolved_policy_hash().ct_eq(&receipt.policy_hash)) {
        return Err(DowngradeError::PolicyHashMismatch);
    }

    // Check 2: Risk tier must not be lower than resolved
    // Convert u8 to RiskTier for comparison (fail-closed on invalid tier)
    let resolved_tier = RiskTier::try_from(resolved.resolved_risk_tier).map_err(|_| {
        DowngradeError::InvalidRiskTier {
            tier_value: resolved.resolved_risk_tier,
        }
    })?;
    let receipt_tier = receipt.risk_tier;

    // RiskTier comparison: higher numeric value = higher risk = more scrutiny
    // A downgrade is when receipt_tier < resolved_tier
    // Compare using u8 representation since RiskTier doesn't implement Ord
    let receipt_tier_val = u8::from(receipt_tier);
    let resolved_tier_val = u8::from(resolved_tier);
    if receipt_tier_val < resolved_tier_val {
        return Err(DowngradeError::RiskTierDowngrade {
            receipt_tier,
            resolved_tier,
        });
    }

    // Check 3: Verifier policy hash must be in resolved list
    // Use constant-time comparison for each hash in the list
    let verifier_policy_found = resolved
        .resolved_verifier_policy_hashes
        .iter()
        .any(|resolved_hash| bool::from(resolved_hash.ct_eq(&receipt.verifier_policy_hash)));

    if !verifier_policy_found {
        return Err(DowngradeError::VerifierPolicyNotResolved);
    }

    // Check 4: RCP profile ID must be in resolved list
    // String comparison is not timing-sensitive as profile IDs are not secrets
    let rcp_profile_found = resolved
        .resolved_rcp_profile_ids
        .iter()
        .any(|id| id == &receipt.rcp_profile_id);

    if !rcp_profile_found {
        return Err(DowngradeError::RcpProfileNotResolved {
            profile_id: receipt.rcp_profile_id.clone(),
        });
    }

    Ok(())
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
#[allow(missing_docs)]
pub mod tests {
    use super::*;
    use crate::crypto::Signer;
    use crate::fac::{
        AatAttestation, AatGateReceiptBuilder, AatVerdict, DeterminismClass, DeterminismStatus,
        FlakeClass, PolicyResolvedForChangeSetBuilder, TerminalVerifierOutput,
    };

    /// Helper to create a valid policy resolution for testing.
    fn create_test_resolution(signer: &Signer) -> PolicyResolvedForChangeSet {
        PolicyResolvedForChangeSetBuilder::new("work-001", [0x42; 32])
            .resolved_risk_tier(2) // Tier2
            .resolved_determinism_class(0)
            .add_rcp_profile_id("profile-001")
            .add_rcp_manifest_hash([0x11; 32])
            .add_verifier_policy_hash([0x22; 32])
            .resolver_actor_id("resolver-001")
            .resolver_version("1.0.0")
            .build_and_sign(signer)
    }

    /// Helper to create a valid AAT receipt that matches the test resolution.
    fn create_matching_receipt(
        policy_hash: [u8; 32],
        risk_tier: RiskTier,
        verifier_policy_hash: [u8; 32],
        rcp_profile_id: &str,
    ) -> AatGateReceipt {
        let terminal_evidence_digest = [0x77; 32];
        let terminal_verifier_outputs_digest = [0x99; 32];
        let stability_digest = AatGateReceipt::compute_stability_digest(
            AatVerdict::Pass,
            &terminal_evidence_digest,
            &terminal_verifier_outputs_digest,
        );

        AatGateReceiptBuilder::new()
            .view_commitment_hash([0x11; 32])
            .rcp_manifest_hash([0x11; 32])
            .rcp_profile_id(rcp_profile_id)
            .policy_hash(policy_hash)
            .determinism_class(DeterminismClass::FullyDeterministic)
            .determinism_status(DeterminismStatus::Stable)
            .flake_class(FlakeClass::DeterministicFail)
            .run_count(1)
            .run_receipt_hashes(vec![[0x44; 32]])
            .terminal_evidence_digest(terminal_evidence_digest)
            .observational_evidence_digest([0x88; 32])
            .terminal_verifier_outputs_digest(terminal_verifier_outputs_digest)
            .stability_digest(stability_digest)
            .verdict(AatVerdict::Pass)
            .transcript_chain_root_hash([0xBB; 32])
            .transcript_bundle_hash([0xCC; 32])
            .artifact_manifest_hash([0xDD; 32])
            .terminal_verifier_outputs(vec![TerminalVerifierOutput {
                verifier_kind: "exit_code".to_string(),
                output_digest: [0xEE; 32],
                predicate_satisfied: true,
            }])
            .verifier_policy_hash(verifier_policy_hash)
            .selection_policy_id("policy-001")
            .risk_tier(risk_tier)
            .attestation(AatAttestation {
                container_image_digest: [0x01; 32],
                toolchain_digests: vec![[0x02; 32]],
                runner_identity_key_id: "runner-001".to_string(),
                network_policy_profile_hash: [0x03; 32],
            })
            .build()
            .expect("valid receipt")
    }

    // =========================================================================
    // Success Cases
    // =========================================================================

    #[test]
    fn test_verify_no_downgrade_success() {
        let signer = Signer::generate();
        let resolution = create_test_resolution(&signer);

        let receipt = create_matching_receipt(
            resolution.resolved_policy_hash(),
            RiskTier::Tier2, // Same as resolved
            [0x22; 32],      // Matches resolved verifier policy hash
            "profile-001",   // Matches resolved RCP profile
        );

        assert!(verify_no_downgrade(&resolution, &receipt).is_ok());
    }

    #[test]
    fn test_verify_no_downgrade_higher_risk_tier_ok() {
        let signer = Signer::generate();
        let resolution = create_test_resolution(&signer);

        // Receipt with HIGHER risk tier than resolved is OK (not a downgrade)
        let receipt = create_matching_receipt(
            resolution.resolved_policy_hash(),
            RiskTier::Tier3, // Higher than resolved Tier2
            [0x22; 32],
            "profile-001",
        );

        assert!(verify_no_downgrade(&resolution, &receipt).is_ok());
    }

    #[test]
    fn test_verify_no_downgrade_highest_risk_tier_ok() {
        let signer = Signer::generate();
        let resolution = create_test_resolution(&signer);

        // Receipt with maximum risk tier is always OK
        let receipt = create_matching_receipt(
            resolution.resolved_policy_hash(),
            RiskTier::Tier4, // Maximum risk tier
            [0x22; 32],
            "profile-001",
        );

        assert!(verify_no_downgrade(&resolution, &receipt).is_ok());
    }

    // =========================================================================
    // Policy Hash Mismatch Tests
    // =========================================================================

    #[test]
    fn test_policy_hash_mismatch_rejected() {
        let signer = Signer::generate();
        let resolution = create_test_resolution(&signer);

        // Receipt with different policy hash
        let receipt = create_matching_receipt(
            [0xFF; 32], // Wrong policy hash
            RiskTier::Tier2,
            [0x22; 32],
            "profile-001",
        );

        let result = verify_no_downgrade(&resolution, &receipt);
        assert!(matches!(result, Err(DowngradeError::PolicyHashMismatch)));
    }

    #[test]
    fn test_policy_hash_mismatch_single_bit_difference() {
        let signer = Signer::generate();
        let resolution = create_test_resolution(&signer);

        // Create a policy hash that differs by only one bit
        let mut wrong_hash = resolution.resolved_policy_hash();
        wrong_hash[0] ^= 0x01; // Flip one bit

        let receipt =
            create_matching_receipt(wrong_hash, RiskTier::Tier2, [0x22; 32], "profile-001");

        let result = verify_no_downgrade(&resolution, &receipt);
        assert!(matches!(result, Err(DowngradeError::PolicyHashMismatch)));
    }

    // =========================================================================
    // Risk Tier Downgrade Tests
    // =========================================================================

    #[test]
    fn test_risk_tier_downgrade_rejected() {
        let signer = Signer::generate();
        let resolution = create_test_resolution(&signer); // Tier2

        // Receipt with LOWER risk tier than resolved is a downgrade
        let receipt = create_matching_receipt(
            resolution.resolved_policy_hash(),
            RiskTier::Tier1, // Lower than resolved Tier2
            [0x22; 32],
            "profile-001",
        );

        let result = verify_no_downgrade(&resolution, &receipt);
        assert!(matches!(
            result,
            Err(DowngradeError::RiskTierDowngrade {
                receipt_tier: RiskTier::Tier1,
                resolved_tier: RiskTier::Tier2,
            })
        ));
    }

    #[test]
    fn test_risk_tier_downgrade_to_tier0_rejected() {
        let signer = Signer::generate();
        let resolution = create_test_resolution(&signer); // Tier2

        // Downgrade to minimum risk tier
        let receipt = create_matching_receipt(
            resolution.resolved_policy_hash(),
            RiskTier::Tier0, // Minimum risk tier
            [0x22; 32],
            "profile-001",
        );

        let result = verify_no_downgrade(&resolution, &receipt);
        assert!(matches!(
            result,
            Err(DowngradeError::RiskTierDowngrade {
                receipt_tier: RiskTier::Tier0,
                resolved_tier: RiskTier::Tier2,
            })
        ));
    }

    #[test]
    fn test_all_risk_tier_downgrades_detected() {
        // Test all possible downgrade combinations
        let signer = Signer::generate();

        for resolved_tier_val in 1u8..=4 {
            // Create resolution with this tier
            let resolution = PolicyResolvedForChangeSetBuilder::new("work-001", [0x42; 32])
                .resolved_risk_tier(resolved_tier_val)
                .resolved_determinism_class(0)
                .add_rcp_profile_id("profile-001")
                .add_rcp_manifest_hash([0x11; 32])
                .add_verifier_policy_hash([0x22; 32])
                .resolver_actor_id("resolver-001")
                .resolver_version("1.0.0")
                .build_and_sign(&signer);

            let resolved_tier = RiskTier::try_from(resolved_tier_val).unwrap();

            // Test all lower tiers
            for lower_tier_val in 0..resolved_tier_val {
                let lower_tier = RiskTier::try_from(lower_tier_val).unwrap();

                let receipt = create_matching_receipt(
                    resolution.resolved_policy_hash(),
                    lower_tier,
                    [0x22; 32],
                    "profile-001",
                );

                let result = verify_no_downgrade(&resolution, &receipt);
                assert!(
                    matches!(
                        result,
                        Err(DowngradeError::RiskTierDowngrade {
                            receipt_tier,
                            resolved_tier: res_tier,
                        }) if receipt_tier == lower_tier && res_tier == resolved_tier
                    ),
                    "Downgrade from {resolved_tier:?} to {lower_tier:?} should be rejected"
                );
            }
        }
    }

    // =========================================================================
    // Verifier Policy Not Resolved Tests
    // =========================================================================

    #[test]
    fn test_verifier_policy_not_resolved_rejected() {
        let signer = Signer::generate();
        let resolution = create_test_resolution(&signer);

        // Receipt with verifier policy hash not in resolved list
        let receipt = create_matching_receipt(
            resolution.resolved_policy_hash(),
            RiskTier::Tier2,
            [0xFF; 32], // Not in resolved list
            "profile-001",
        );

        let result = verify_no_downgrade(&resolution, &receipt);
        assert!(matches!(
            result,
            Err(DowngradeError::VerifierPolicyNotResolved)
        ));
    }

    #[test]
    fn test_verifier_policy_single_bit_difference_rejected() {
        let signer = Signer::generate();
        let resolution = create_test_resolution(&signer);

        // Verifier policy hash that differs by one bit
        let mut wrong_hash = [0x22; 32];
        wrong_hash[31] ^= 0x01;

        let receipt = create_matching_receipt(
            resolution.resolved_policy_hash(),
            RiskTier::Tier2,
            wrong_hash,
            "profile-001",
        );

        let result = verify_no_downgrade(&resolution, &receipt);
        assert!(matches!(
            result,
            Err(DowngradeError::VerifierPolicyNotResolved)
        ));
    }

    #[test]
    fn test_verifier_policy_multiple_resolved_policies() {
        let signer = Signer::generate();

        // Create resolution with multiple verifier policy hashes
        let resolution = PolicyResolvedForChangeSetBuilder::new("work-001", [0x42; 32])
            .resolved_risk_tier(2)
            .resolved_determinism_class(0)
            .add_rcp_profile_id("profile-001")
            .add_rcp_manifest_hash([0x11; 32])
            .add_verifier_policy_hash([0x22; 32])
            .add_verifier_policy_hash([0x33; 32])
            .add_verifier_policy_hash([0x44; 32])
            .resolver_actor_id("resolver-001")
            .resolver_version("1.0.0")
            .build_and_sign(&signer);

        // Any of the resolved verifier policy hashes should work
        for verifier_hash in [[0x22; 32], [0x33; 32], [0x44; 32]] {
            let receipt = create_matching_receipt(
                resolution.resolved_policy_hash(),
                RiskTier::Tier2,
                verifier_hash,
                "profile-001",
            );

            assert!(
                verify_no_downgrade(&resolution, &receipt).is_ok(),
                "Verifier policy hash {verifier_hash:?} should be accepted"
            );
        }

        // But a different hash should fail
        let receipt = create_matching_receipt(
            resolution.resolved_policy_hash(),
            RiskTier::Tier2,
            [0x55; 32], // Not in resolved list
            "profile-001",
        );

        assert!(matches!(
            verify_no_downgrade(&resolution, &receipt),
            Err(DowngradeError::VerifierPolicyNotResolved)
        ));
    }

    // =========================================================================
    // RCP Profile Not Resolved Tests
    // =========================================================================

    #[test]
    fn test_rcp_profile_not_resolved_rejected() {
        let signer = Signer::generate();
        let resolution = create_test_resolution(&signer);

        // Receipt with RCP profile not in resolved list
        let receipt = create_matching_receipt(
            resolution.resolved_policy_hash(),
            RiskTier::Tier2,
            [0x22; 32],
            "unknown-profile", // Not in resolved list
        );

        let result = verify_no_downgrade(&resolution, &receipt);
        assert!(matches!(
            result,
            Err(DowngradeError::RcpProfileNotResolved { ref profile_id })
            if profile_id == "unknown-profile"
        ));
    }

    #[test]
    fn test_rcp_profile_empty_string_rejected() {
        let signer = Signer::generate();
        let resolution = create_test_resolution(&signer);

        // Receipt with empty RCP profile ID
        let receipt = create_matching_receipt(
            resolution.resolved_policy_hash(),
            RiskTier::Tier2,
            [0x22; 32],
            "", // Empty string
        );

        let result = verify_no_downgrade(&resolution, &receipt);
        assert!(matches!(
            result,
            Err(DowngradeError::RcpProfileNotResolved { ref profile_id })
            if profile_id.is_empty()
        ));
    }

    #[test]
    fn test_rcp_profile_multiple_resolved_profiles() {
        let signer = Signer::generate();

        // Create resolution with multiple RCP profile IDs
        let resolution = PolicyResolvedForChangeSetBuilder::new("work-001", [0x42; 32])
            .resolved_risk_tier(2)
            .resolved_determinism_class(0)
            .add_rcp_profile_id("profile-a")
            .add_rcp_manifest_hash([0x11; 32])
            .add_rcp_profile_id("profile-b")
            .add_rcp_manifest_hash([0x22; 32])
            .add_rcp_profile_id("profile-c")
            .add_rcp_manifest_hash([0x33; 32])
            .add_verifier_policy_hash([0x44; 32])
            .resolver_actor_id("resolver-001")
            .resolver_version("1.0.0")
            .build_and_sign(&signer);

        // Any of the resolved RCP profiles should work
        for profile_id in ["profile-a", "profile-b", "profile-c"] {
            let receipt = create_matching_receipt(
                resolution.resolved_policy_hash(),
                RiskTier::Tier2,
                [0x44; 32],
                profile_id,
            );

            assert!(
                verify_no_downgrade(&resolution, &receipt).is_ok(),
                "RCP profile '{profile_id}' should be accepted"
            );
        }

        // But a different profile should fail
        let receipt = create_matching_receipt(
            resolution.resolved_policy_hash(),
            RiskTier::Tier2,
            [0x44; 32],
            "profile-d", // Not in resolved list
        );

        assert!(matches!(
            verify_no_downgrade(&resolution, &receipt),
            Err(DowngradeError::RcpProfileNotResolved { ref profile_id })
            if profile_id == "profile-d"
        ));
    }

    #[test]
    fn test_rcp_profile_case_sensitive() {
        let signer = Signer::generate();
        let resolution = create_test_resolution(&signer); // Has "profile-001"

        // Attempt with different case
        let receipt = create_matching_receipt(
            resolution.resolved_policy_hash(),
            RiskTier::Tier2,
            [0x22; 32],
            "Profile-001", // Different case
        );

        let result = verify_no_downgrade(&resolution, &receipt);
        assert!(matches!(
            result,
            Err(DowngradeError::RcpProfileNotResolved { ref profile_id })
            if profile_id == "Profile-001"
        ));
    }

    // =========================================================================
    // Error Priority Tests
    // =========================================================================

    #[test]
    fn test_policy_hash_mismatch_checked_first() {
        let signer = Signer::generate();
        let resolution = create_test_resolution(&signer);

        // Receipt with MULTIPLE issues: wrong policy hash, lower risk tier,
        // wrong verifier policy, wrong RCP profile
        let receipt = create_matching_receipt(
            [0xFF; 32],      // Wrong
            RiskTier::Tier0, // Lower than Tier2
            [0xFF; 32],      // Wrong
            "unknown",       // Wrong
        );

        // Policy hash mismatch should be reported first
        let result = verify_no_downgrade(&resolution, &receipt);
        assert!(matches!(result, Err(DowngradeError::PolicyHashMismatch)));
    }

    #[test]
    fn test_risk_tier_checked_second() {
        let signer = Signer::generate();
        let resolution = create_test_resolution(&signer);

        // Receipt with correct policy hash but other issues
        let receipt = create_matching_receipt(
            resolution.resolved_policy_hash(),
            RiskTier::Tier0, // Lower than Tier2
            [0xFF; 32],      // Wrong
            "unknown",       // Wrong
        );

        // Risk tier downgrade should be reported (after policy hash passes)
        let result = verify_no_downgrade(&resolution, &receipt);
        assert!(matches!(
            result,
            Err(DowngradeError::RiskTierDowngrade { .. })
        ));
    }

    #[test]
    fn test_verifier_policy_checked_third() {
        let signer = Signer::generate();
        let resolution = create_test_resolution(&signer);

        // Receipt with correct policy hash and risk tier but wrong verifier policy
        let receipt = create_matching_receipt(
            resolution.resolved_policy_hash(),
            RiskTier::Tier2, // Correct
            [0xFF; 32],      // Wrong
            "unknown",       // Wrong
        );

        // Verifier policy not resolved should be reported
        let result = verify_no_downgrade(&resolution, &receipt);
        assert!(matches!(
            result,
            Err(DowngradeError::VerifierPolicyNotResolved)
        ));
    }

    #[test]
    fn test_rcp_profile_checked_last() {
        let signer = Signer::generate();
        let resolution = create_test_resolution(&signer);

        // Receipt with only wrong RCP profile
        let receipt = create_matching_receipt(
            resolution.resolved_policy_hash(),
            RiskTier::Tier2,
            [0x22; 32], // Correct
            "unknown",  // Wrong
        );

        // RCP profile not resolved should be reported
        let result = verify_no_downgrade(&resolution, &receipt);
        assert!(matches!(
            result,
            Err(DowngradeError::RcpProfileNotResolved { .. })
        ));
    }

    // =========================================================================
    // Edge Cases
    // =========================================================================

    #[test]
    fn test_empty_resolved_verifier_policies() {
        let signer = Signer::generate();

        // Create resolution with NO verifier policy hashes
        let resolution = PolicyResolvedForChangeSetBuilder::new("work-001", [0x42; 32])
            .resolved_risk_tier(2)
            .resolved_determinism_class(0)
            .add_rcp_profile_id("profile-001")
            .add_rcp_manifest_hash([0x11; 32])
            // No verifier policy hashes added
            .resolver_actor_id("resolver-001")
            .resolver_version("1.0.0")
            .build_and_sign(&signer);

        // Any receipt should fail verifier policy check
        let receipt = create_matching_receipt(
            resolution.resolved_policy_hash(),
            RiskTier::Tier2,
            [0x22; 32], // Any hash
            "profile-001",
        );

        let result = verify_no_downgrade(&resolution, &receipt);
        assert!(matches!(
            result,
            Err(DowngradeError::VerifierPolicyNotResolved)
        ));
    }

    #[test]
    fn test_empty_resolved_rcp_profiles() {
        let signer = Signer::generate();

        // Create resolution with NO RCP profile IDs
        let resolution = PolicyResolvedForChangeSetBuilder::new("work-001", [0x42; 32])
            .resolved_risk_tier(2)
            .resolved_determinism_class(0)
            // No RCP profile IDs added
            .add_verifier_policy_hash([0x22; 32])
            .resolver_actor_id("resolver-001")
            .resolver_version("1.0.0")
            .build_and_sign(&signer);

        // Any receipt should fail RCP profile check
        let receipt = create_matching_receipt(
            resolution.resolved_policy_hash(),
            RiskTier::Tier2,
            [0x22; 32],
            "profile-001", // Any profile
        );

        let result = verify_no_downgrade(&resolution, &receipt);
        assert!(matches!(
            result,
            Err(DowngradeError::RcpProfileNotResolved { .. })
        ));
    }

    #[test]
    fn test_tier0_resolved_allows_all_tiers() {
        let signer = Signer::generate();

        // Create resolution with Tier0 (minimum risk)
        let resolution = PolicyResolvedForChangeSetBuilder::new("work-001", [0x42; 32])
            .resolved_risk_tier(0) // Tier0
            .resolved_determinism_class(0)
            .add_rcp_profile_id("profile-001")
            .add_rcp_manifest_hash([0x11; 32])
            .add_verifier_policy_hash([0x22; 32])
            .resolver_actor_id("resolver-001")
            .resolver_version("1.0.0")
            .build_and_sign(&signer);

        // All tiers should be accepted (none can be lower than Tier0)
        for tier in [
            RiskTier::Tier0,
            RiskTier::Tier1,
            RiskTier::Tier2,
            RiskTier::Tier3,
            RiskTier::Tier4,
        ] {
            let receipt = create_matching_receipt(
                resolution.resolved_policy_hash(),
                tier,
                [0x22; 32],
                "profile-001",
            );

            assert!(
                verify_no_downgrade(&resolution, &receipt).is_ok(),
                "Tier {tier:?} should be accepted when resolved is Tier0"
            );
        }
    }

    #[test]
    fn test_tier4_resolved_only_allows_tier4() {
        let signer = Signer::generate();

        // Create resolution with Tier4 (maximum risk)
        let resolution = PolicyResolvedForChangeSetBuilder::new("work-001", [0x42; 32])
            .resolved_risk_tier(4) // Tier4
            .resolved_determinism_class(0)
            .add_rcp_profile_id("profile-001")
            .add_rcp_manifest_hash([0x11; 32])
            .add_verifier_policy_hash([0x22; 32])
            .resolver_actor_id("resolver-001")
            .resolver_version("1.0.0")
            .build_and_sign(&signer);

        // Only Tier4 should be accepted
        let receipt = create_matching_receipt(
            resolution.resolved_policy_hash(),
            RiskTier::Tier4,
            [0x22; 32],
            "profile-001",
        );
        assert!(verify_no_downgrade(&resolution, &receipt).is_ok());

        // All other tiers should be rejected
        for tier in [
            RiskTier::Tier0,
            RiskTier::Tier1,
            RiskTier::Tier2,
            RiskTier::Tier3,
        ] {
            let receipt = create_matching_receipt(
                resolution.resolved_policy_hash(),
                tier,
                [0x22; 32],
                "profile-001",
            );

            assert!(
                matches!(
                    verify_no_downgrade(&resolution, &receipt),
                    Err(DowngradeError::RiskTierDowngrade { .. })
                ),
                "Tier {tier:?} should be rejected when resolved is Tier4"
            );
        }
    }

    // =========================================================================
    // Error Message Tests
    // =========================================================================

    #[test]
    fn test_error_display_messages() {
        // PolicyHashMismatch
        let err = DowngradeError::PolicyHashMismatch;
        assert!(err.to_string().contains("policy hash mismatch"));

        // RiskTierDowngrade
        let err = DowngradeError::RiskTierDowngrade {
            receipt_tier: RiskTier::Tier1,
            resolved_tier: RiskTier::Tier3,
        };
        let msg = err.to_string();
        assert!(msg.contains("risk tier downgrade"));
        assert!(msg.contains("Tier1"));
        assert!(msg.contains("Tier3"));

        // VerifierPolicyNotResolved
        let err = DowngradeError::VerifierPolicyNotResolved;
        assert!(err.to_string().contains("verifier policy not resolved"));

        // RcpProfileNotResolved
        let err = DowngradeError::RcpProfileNotResolved {
            profile_id: "my-profile".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("RCP profile not resolved"));
        assert!(msg.contains("my-profile"));

        // InvalidRiskTier
        let err = DowngradeError::InvalidRiskTier { tier_value: 99 };
        let msg = err.to_string();
        assert!(msg.contains("invalid risk tier"));
        assert!(msg.contains("99"));
    }

    // =========================================================================
    // Invalid Risk Tier Tests (Fail-Closed)
    // =========================================================================

    #[test]
    fn test_invalid_resolved_risk_tier_fails_closed() {
        // This test verifies that an invalid resolved_risk_tier value
        // causes a fail-closed error instead of panicking.
        //
        // We need to manually construct a PolicyResolvedForChangeSet with
        // an invalid risk tier to test this path.
        use crate::crypto::Signer;

        let signer = Signer::generate();

        // Create a valid resolution first
        let mut resolution = PolicyResolvedForChangeSetBuilder::new("work-001", [0x42; 32])
            .resolved_risk_tier(2)
            .resolved_determinism_class(0)
            .add_rcp_profile_id("profile-001")
            .add_rcp_manifest_hash([0x11; 32])
            .add_verifier_policy_hash([0x22; 32])
            .resolver_actor_id("resolver-001")
            .resolver_version("1.0.0")
            .build_and_sign(&signer);

        // Directly mutate the risk tier to an invalid value (simulating corruption)
        resolution.resolved_risk_tier = 99; // Invalid: not 0-4

        let receipt = create_matching_receipt(
            resolution.resolved_policy_hash(),
            RiskTier::Tier2,
            [0x22; 32],
            "profile-001",
        );

        // Should return InvalidRiskTier error, NOT panic
        let result = verify_no_downgrade(&resolution, &receipt);
        assert!(
            matches!(
                result,
                Err(DowngradeError::InvalidRiskTier { tier_value: 99 })
            ),
            "Expected InvalidRiskTier error for tier value 99, got {result:?}"
        );
    }

    #[test]
    fn test_invalid_risk_tier_values_all_fail_closed() {
        // Test that all invalid tier values (5-255) result in InvalidRiskTier error
        use crate::crypto::Signer;

        let signer = Signer::generate();

        for invalid_tier in [5u8, 10, 50, 100, 200, 255] {
            let mut resolution = PolicyResolvedForChangeSetBuilder::new("work-001", [0x42; 32])
                .resolved_risk_tier(2)
                .resolved_determinism_class(0)
                .add_rcp_profile_id("profile-001")
                .add_rcp_manifest_hash([0x11; 32])
                .add_verifier_policy_hash([0x22; 32])
                .resolver_actor_id("resolver-001")
                .resolver_version("1.0.0")
                .build_and_sign(&signer);

            // Directly set invalid tier (simulating data corruption)
            resolution.resolved_risk_tier = invalid_tier;

            let receipt = create_matching_receipt(
                resolution.resolved_policy_hash(),
                RiskTier::Tier2,
                [0x22; 32],
                "profile-001",
            );

            let result = verify_no_downgrade(&resolution, &receipt);
            assert!(
                matches!(
                    result,
                    Err(DowngradeError::InvalidRiskTier { tier_value }) if tier_value == invalid_tier
                ),
                "Expected InvalidRiskTier error for tier value {invalid_tier}, got {result:?}"
            );
        }
    }
}
