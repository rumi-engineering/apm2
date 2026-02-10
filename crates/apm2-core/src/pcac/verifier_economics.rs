// AGENT-AUTHORED
//! Verifier economics profile and enforcement checks for PCAC (RFC-0027 §8).
//!
//! Tier2+ operations fail closed when declared verifier-economics bounds are
//! exceeded. Tier0/1 operations are monitor-only.

use serde::{Deserialize, Serialize};

use super::{AuthorityDenyClass, RiskTier};

/// Per-operation timing bounds for PCAC verifier checks.
///
/// Each field is the p95 upper bound in microseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifierEconomicsProfile {
    /// p95 upper bound for the `join` lifecycle stage (microseconds).
    pub p95_join_us: u64,
    /// p95 upper bound for `verify_receipt_authentication` (microseconds).
    pub p95_verify_receipt_us: u64,
    /// p95 upper bound for `validate_authoritative_bindings` (microseconds).
    pub p95_validate_bindings_us: u64,
    /// p95 upper bound for `classify_fact` (microseconds).
    pub p95_classify_fact_us: u64,
    /// p95 upper bound for `validate_replay_lifecycle_order` (microseconds).
    pub p95_replay_lifecycle_us: u64,
    /// p95 upper bound for anti-entropy verification operations (microseconds).
    pub p95_anti_entropy_us: u64,
    /// p95 upper bound for the entire `revalidate` stage (microseconds).
    pub p95_revalidate_us: u64,
    /// p95 upper bound for the entire `consume` stage (microseconds).
    pub p95_consume_us: u64,
    /// Maximum allowed cryptographic proof checks per verification operation.
    ///
    /// This bound applies only to cryptographic verification work
    /// (for example Merkle-proof verification and digest comparisons), not to
    /// throughput counters such as anti-entropy event batch size.
    pub max_proof_checks: u64,
}

impl Default for VerifierEconomicsProfile {
    fn default() -> Self {
        // Conservative finite defaults.
        Self {
            p95_join_us: 10_000,
            p95_verify_receipt_us: 10_000,
            p95_validate_bindings_us: 10_000,
            p95_classify_fact_us: 10_000,
            p95_replay_lifecycle_us: 10_000,
            // Anti-entropy verification may include digest + transfer checks.
            p95_anti_entropy_us: 50_000,
            // Stage-level envelopes include sub-check operations.
            p95_revalidate_us: 30_000,
            p95_consume_us: 30_000,
            // Conservative cryptographic-check budget per verifier call.
            max_proof_checks: 256,
        }
    }
}

/// Identifies the verifier operation being measured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifierOperation {
    /// Timing sample for the `join` lifecycle stage (certificate issuance).
    Join,
    /// Timing sample for `verify_receipt_authentication`.
    VerifyReceiptAuthentication,
    /// Timing sample for `validate_authoritative_bindings`.
    ValidateAuthoritativeBindings,
    /// Timing sample for `classify_fact`.
    ClassifyFact,
    /// Timing sample for `validate_replay_lifecycle_order`.
    ValidateReplayLifecycleOrder,
    /// Timing sample for anti-entropy verification.
    AntiEntropy,
    /// Wall-clock timing for the entire `revalidate` stage.
    Revalidate,
    /// Wall-clock timing for the entire `consume` stage.
    Consume,
}

impl std::fmt::Display for VerifierOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Join => write!(f, "join"),
            Self::VerifyReceiptAuthentication => write!(f, "verify_receipt_authentication"),
            Self::ValidateAuthoritativeBindings => write!(f, "validate_authoritative_bindings"),
            Self::ClassifyFact => write!(f, "classify_fact"),
            Self::ValidateReplayLifecycleOrder => write!(f, "validate_replay_lifecycle_order"),
            Self::AntiEntropy => write!(f, "anti_entropy_verification"),
            Self::Revalidate => write!(f, "revalidate"),
            Self::Consume => write!(f, "consume"),
        }
    }
}

/// Verifier economics bound checker for PCAC authority lifecycle operations.
pub struct VerifierEconomicsChecker {
    profile: VerifierEconomicsProfile,
}

impl VerifierEconomicsChecker {
    /// Creates a checker from a concrete economics profile.
    #[must_use]
    pub const fn new(profile: VerifierEconomicsProfile) -> Self {
        Self { profile }
    }

    const fn bound_for(&self, operation: VerifierOperation) -> u64 {
        match operation {
            VerifierOperation::Join => self.profile.p95_join_us,
            VerifierOperation::VerifyReceiptAuthentication => self.profile.p95_verify_receipt_us,
            VerifierOperation::ValidateAuthoritativeBindings => {
                self.profile.p95_validate_bindings_us
            },
            VerifierOperation::ClassifyFact => self.profile.p95_classify_fact_us,
            VerifierOperation::ValidateReplayLifecycleOrder => self.profile.p95_replay_lifecycle_us,
            VerifierOperation::AntiEntropy => self.profile.p95_anti_entropy_us,
            VerifierOperation::Revalidate => self.profile.p95_revalidate_us,
            VerifierOperation::Consume => self.profile.p95_consume_us,
        }
    }

    /// Checks elapsed verifier time against profile bounds for a risk tier.
    ///
    /// Tier2+ is fail-closed on bound exceedance. Tier0/1 is monitor-only.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityDenyClass::VerifierEconomicsBoundsExceeded`] when
    /// elapsed time exceeds bounds for Tier2+ operations.
    pub fn check_timing(
        &self,
        operation: VerifierOperation,
        elapsed_us: u64,
        risk_tier: RiskTier,
    ) -> Result<(), AuthorityDenyClass> {
        let bound_us = self.bound_for(operation);
        if elapsed_us <= bound_us {
            return Ok(());
        }

        match risk_tier {
            RiskTier::Tier0 | RiskTier::Tier1 => Ok(()),
            RiskTier::Tier2Plus => Err(AuthorityDenyClass::VerifierEconomicsBoundsExceeded {
                operation: operation.to_string(),
                risk_tier,
            }),
        }
    }

    /// Checks verifier proof-check count against profile bounds for a risk
    /// tier.
    ///
    /// Tier2+ is fail-closed on bound exceedance. Tier0/1 is monitor-only.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityDenyClass::VerifierEconomicsBoundsExceeded`] when
    /// proof count exceeds bounds for Tier2+ operations.
    pub fn check_proof_count(
        &self,
        operation: VerifierOperation,
        proof_check_count: u64,
        risk_tier: RiskTier,
    ) -> Result<(), AuthorityDenyClass> {
        if proof_check_count <= self.profile.max_proof_checks {
            return Ok(());
        }

        match risk_tier {
            RiskTier::Tier0 | RiskTier::Tier1 => Ok(()),
            RiskTier::Tier2Plus => Err(AuthorityDenyClass::VerifierEconomicsBoundsExceeded {
                operation: operation.to_string(),
                risk_tier,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tight_profile() -> VerifierEconomicsProfile {
        VerifierEconomicsProfile {
            p95_join_us: 5,
            p95_verify_receipt_us: 10,
            p95_validate_bindings_us: 20,
            p95_classify_fact_us: 30,
            p95_replay_lifecycle_us: 40,
            p95_anti_entropy_us: 50,
            p95_revalidate_us: 60,
            p95_consume_us: 70,
            max_proof_checks: 3,
        }
    }

    #[test]
    fn tier2plus_exceedance_denies() {
        let checker = VerifierEconomicsChecker::new(tight_profile());
        let err = checker
            .check_timing(
                VerifierOperation::VerifyReceiptAuthentication,
                11,
                RiskTier::Tier2Plus,
            )
            .unwrap_err();
        assert!(matches!(
            err,
            AuthorityDenyClass::VerifierEconomicsBoundsExceeded { ref operation, risk_tier }
                if operation == "verify_receipt_authentication" && risk_tier == RiskTier::Tier2Plus
        ));
    }

    #[test]
    fn tier0_tier1_exceedance_is_monitor_only() {
        let checker = VerifierEconomicsChecker::new(tight_profile());
        let tier0 = checker.check_timing(
            VerifierOperation::ValidateAuthoritativeBindings,
            21,
            RiskTier::Tier0,
        );
        let tier1 = checker.check_timing(
            VerifierOperation::ValidateAuthoritativeBindings,
            21,
            RiskTier::Tier1,
        );
        assert!(tier0.is_ok());
        assert!(tier1.is_ok());
    }

    #[test]
    fn all_operation_variants_are_covered() {
        let checker = VerifierEconomicsChecker::new(tight_profile());
        let cases = [
            (VerifierOperation::Join, 6, "join"),
            (
                VerifierOperation::VerifyReceiptAuthentication,
                11,
                "verify_receipt_authentication",
            ),
            (
                VerifierOperation::ValidateAuthoritativeBindings,
                21,
                "validate_authoritative_bindings",
            ),
            (VerifierOperation::ClassifyFact, 31, "classify_fact"),
            (
                VerifierOperation::ValidateReplayLifecycleOrder,
                41,
                "validate_replay_lifecycle_order",
            ),
            (
                VerifierOperation::AntiEntropy,
                51,
                "anti_entropy_verification",
            ),
            (VerifierOperation::Revalidate, 61, "revalidate"),
            (VerifierOperation::Consume, 71, "consume"),
        ];

        for (operation, elapsed, expected_name) in cases {
            let err = checker
                .check_timing(operation, elapsed, RiskTier::Tier2Plus)
                .unwrap_err();
            assert!(matches!(
                err,
                AuthorityDenyClass::VerifierEconomicsBoundsExceeded { ref operation, risk_tier }
                    if operation == expected_name && risk_tier == RiskTier::Tier2Plus
            ));
        }
    }

    #[test]
    fn default_profile_is_non_zero() {
        let profile = VerifierEconomicsProfile::default();
        assert_eq!(profile.p95_join_us, 10_000);
        assert_eq!(profile.p95_verify_receipt_us, 10_000);
        assert_eq!(profile.p95_validate_bindings_us, 10_000);
        assert_eq!(profile.p95_classify_fact_us, 10_000);
        assert_eq!(profile.p95_replay_lifecycle_us, 10_000);
        assert_eq!(profile.p95_anti_entropy_us, 50_000);
        assert_eq!(profile.p95_revalidate_us, 30_000);
        assert_eq!(profile.p95_consume_us, 30_000);
        assert_eq!(profile.max_proof_checks, 256);
    }

    #[test]
    fn profile_serialization_round_trip() {
        let profile = VerifierEconomicsProfile {
            p95_join_us: 100,
            p95_verify_receipt_us: 111,
            p95_validate_bindings_us: 222,
            p95_classify_fact_us: 333,
            p95_replay_lifecycle_us: 444,
            p95_anti_entropy_us: 555,
            p95_revalidate_us: 666,
            p95_consume_us: 777,
            max_proof_checks: 666,
        };
        let json = serde_json::to_string(&profile).unwrap();
        let decoded: VerifierEconomicsProfile = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.p95_join_us, 100);
        assert_eq!(decoded.p95_verify_receipt_us, 111);
        assert_eq!(decoded.p95_validate_bindings_us, 222);
        assert_eq!(decoded.p95_classify_fact_us, 333);
        assert_eq!(decoded.p95_replay_lifecycle_us, 444);
        assert_eq!(decoded.p95_anti_entropy_us, 555);
        assert_eq!(decoded.p95_revalidate_us, 666);
        assert_eq!(decoded.p95_consume_us, 777);
        assert_eq!(decoded.max_proof_checks, 666);
    }

    #[test]
    fn zero_bounds_deny_non_zero_tier2plus_elapsed() {
        let checker = VerifierEconomicsChecker::new(VerifierEconomicsProfile {
            p95_join_us: 0,
            p95_verify_receipt_us: 0,
            p95_validate_bindings_us: 0,
            p95_classify_fact_us: 0,
            p95_replay_lifecycle_us: 0,
            p95_anti_entropy_us: 0,
            p95_revalidate_us: 0,
            p95_consume_us: 0,
            max_proof_checks: 0,
        });
        let err = checker
            .check_timing(VerifierOperation::ClassifyFact, 1, RiskTier::Tier2Plus)
            .unwrap_err();
        assert!(matches!(
            err,
            AuthorityDenyClass::VerifierEconomicsBoundsExceeded { ref operation, risk_tier }
                if operation == "classify_fact" && risk_tier == RiskTier::Tier2Plus
        ));
    }

    #[test]
    fn boundary_exact_is_allowed_and_plus_one_denies() {
        let checker = VerifierEconomicsChecker::new(tight_profile());
        let exact = checker.check_timing(
            VerifierOperation::ValidateReplayLifecycleOrder,
            40,
            RiskTier::Tier2Plus,
        );
        assert!(exact.is_ok());

        let over = checker
            .check_timing(
                VerifierOperation::ValidateReplayLifecycleOrder,
                41,
                RiskTier::Tier2Plus,
            )
            .unwrap_err();
        assert!(matches!(
            over,
            AuthorityDenyClass::VerifierEconomicsBoundsExceeded { ref operation, risk_tier }
                if operation == "validate_replay_lifecycle_order" && risk_tier == RiskTier::Tier2Plus
        ));
    }

    #[test]
    fn proof_count_tier2plus_exceedance_denies() {
        let checker = VerifierEconomicsChecker::new(tight_profile());
        let err = checker
            .check_proof_count(
                VerifierOperation::ValidateReplayLifecycleOrder,
                4,
                RiskTier::Tier2Plus,
            )
            .unwrap_err();
        assert!(matches!(
            err,
            AuthorityDenyClass::VerifierEconomicsBoundsExceeded { ref operation, risk_tier }
                if operation == "validate_replay_lifecycle_order" && risk_tier == RiskTier::Tier2Plus
        ));
    }

    #[test]
    fn proof_count_tier0_tier1_exceedance_is_monitor_only() {
        let checker = VerifierEconomicsChecker::new(tight_profile());
        assert!(
            checker
                .check_proof_count(VerifierOperation::ClassifyFact, 4, RiskTier::Tier0)
                .is_ok()
        );
        assert!(
            checker
                .check_proof_count(VerifierOperation::ClassifyFact, 4, RiskTier::Tier1)
                .is_ok()
        );
    }
}
