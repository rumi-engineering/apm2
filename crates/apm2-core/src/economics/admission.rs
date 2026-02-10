//! Deterministic economics admission evaluator.
//!
//! Admission resolves a canonical economics profile by hash and evaluates
//! observed usage against per-cell budget limits keyed by
//! `(RiskTier, BoundaryIntentClass)`.
//!
//! All unknown, missing, stale, or unresolved profile states deny by default.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::profile::{
    BudgetEntry, EconomicsProfile, EconomicsProfileError, EconomicsProfileInputState,
};
use crate::crypto::Hash;
use crate::determinism::canonicalize_json;
use crate::evidence::{CasError, ContentAddressedStore};
use crate::pcac::{BoundaryIntentClass, RiskTier};

/// Stable deny reason for a zero/null profile hash.
pub const DENY_REASON_PROFILE_HASH_ZERO: &str = "economics_profile_hash_zero";
/// Stable deny reason when profile hash is not present in CAS.
pub const DENY_REASON_PROFILE_MISSING: &str = "economics_profile_missing";
/// Stable deny reason when profile retrieval is unresolved.
pub const DENY_REASON_PROFILE_UNRESOLVED: &str = "economics_profile_unresolved";
/// Stable deny reason when profile bytes are invalid/corrupt.
pub const DENY_REASON_PROFILE_INVALID: &str = "economics_profile_invalid";
/// Stable deny reason when profile inputs are stale.
pub const DENY_REASON_PROFILE_STALE: &str = "economics_profile_stale";
/// Stable deny reason when profile inputs are unresolved.
pub const DENY_REASON_PROFILE_INPUTS_UNRESOLVED: &str = "economics_profile_inputs_unresolved";
/// Stable deny reason when no budget cell exists for the `(tier, class)` key.
pub const DENY_REASON_BUDGET_ENTRY_MISSING: &str = "economics_budget_entry_missing";
/// Stable deny reason for token budget exceedance.
pub const DENY_REASON_TOKENS_EXCEEDED: &str = "economics_budget_tokens_exceeded";
/// Stable deny reason for tool-call budget exceedance.
pub const DENY_REASON_TOOL_CALLS_EXCEEDED: &str = "economics_budget_tool_calls_exceeded";
/// Stable deny reason for time budget exceedance.
pub const DENY_REASON_TIME_MS_EXCEEDED: &str = "economics_budget_time_ms_exceeded";
/// Stable deny reason for I/O byte budget exceedance.
pub const DENY_REASON_IO_BYTES_EXCEEDED: &str = "economics_budget_io_bytes_exceeded";

const ZERO_HASH: Hash = [0u8; 32];

/// Observed resource usage snapshot for admission evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedUsage {
    /// Tokens consumed so far.
    pub tokens_used: u64,
    /// Tool calls consumed so far.
    pub tool_calls_used: u32,
    /// Execution time consumed in milliseconds.
    pub time_ms_used: u64,
    /// I/O bytes consumed so far.
    pub io_bytes_used: u64,
}

/// Admission verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum BudgetAdmissionVerdict {
    /// Request is admissible under the active budget cell.
    Allow,
    /// Request is denied under fail-closed semantics.
    Deny,
    /// Request is frozen pending adjudication.
    Freeze,
    /// Request requires escalation.
    Escalate,
}

/// Deterministic admission trace payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetAdmissionTrace {
    /// Profile hash used for evaluation.
    pub profile_hash: Hash,
    /// Risk tier key used for budget lookup.
    pub tier: RiskTier,
    /// Boundary intent class key used for budget lookup.
    pub intent_class: BoundaryIntentClass,
    /// Observed usage snapshot.
    pub observed: ObservedUsage,
    /// Limits selected for the `(tier, intent_class)` key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limits: Option<BudgetEntry>,
    /// Evaluation verdict.
    pub verdict: BudgetAdmissionVerdict,
    /// Stable deny reason when verdict is deny/freeze/escalate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deny_reason: Option<String>,
}

impl BudgetAdmissionTrace {
    /// Returns deterministic canonical JSON bytes for replay verification.
    ///
    /// # Errors
    ///
    /// Returns an error when serialization or canonicalization fails.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, BudgetAdmissionError> {
        let json =
            serde_json::to_string(self).map_err(|error| BudgetAdmissionError::Serialization {
                message: error.to_string(),
            })?;
        let canonical_json =
            canonicalize_json(&json).map_err(|error| BudgetAdmissionError::Serialization {
                message: error.to_string(),
            })?;
        Ok(canonical_json.into_bytes())
    }
}

/// Admission decision with replay-verifiable trace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetAdmissionDecision {
    /// Verdict for the evaluated request.
    pub verdict: BudgetAdmissionVerdict,
    /// Stable deny reason when verdict is deny/freeze/escalate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deny_reason: Option<String>,
    /// Deterministic trace payload.
    pub trace: BudgetAdmissionTrace,
}

/// Errors for admission trace canonicalization.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum BudgetAdmissionError {
    /// Serialization or canonicalization failed.
    #[error("budget admission serialization failed: {message}")]
    Serialization {
        /// Error message.
        message: String,
    },
}

/// Evaluates budget admission against a hash-addressed economics profile.
pub struct BudgetAdmissionEvaluator<'a> {
    cas: &'a dyn ContentAddressedStore,
    profile_hash: Hash,
}

impl<'a> BudgetAdmissionEvaluator<'a> {
    /// Creates a new admission evaluator bound to a CAS and profile hash.
    #[must_use]
    pub fn new(cas: &'a dyn ContentAddressedStore, profile_hash: Hash) -> Self {
        Self { cas, profile_hash }
    }

    /// Evaluates budget admission for `(tier, intent_class)` and usage.
    ///
    /// Unknown profile state is fail-closed: missing hash, missing CAS entry,
    /// corrupt profile bytes, stale profile inputs, unresolved profile inputs,
    /// and missing budget cell all return deterministic denies.
    #[must_use]
    pub fn evaluate(
        &self,
        tier: RiskTier,
        intent_class: BoundaryIntentClass,
        observed_usage: &ObservedUsage,
    ) -> BudgetAdmissionDecision {
        let profile = match self.resolve_profile() {
            Ok(profile) => profile,
            Err(deny_reason) => {
                return self.deny(tier, intent_class, *observed_usage, None, deny_reason);
            },
        };

        let Some(limits) = profile.budget_entry(tier, intent_class).copied() else {
            return self.deny(
                tier,
                intent_class,
                *observed_usage,
                None,
                DENY_REASON_BUDGET_ENTRY_MISSING,
            );
        };

        let Some(deny_reason) = Self::first_exceedance_reason(observed_usage, &limits) else {
            return self.allow(tier, intent_class, *observed_usage, limits);
        };

        self.deny(
            tier,
            intent_class,
            *observed_usage,
            Some(limits),
            deny_reason,
        )
    }

    fn resolve_profile(&self) -> Result<EconomicsProfile, &'static str> {
        if self.profile_hash == ZERO_HASH {
            return Err(DENY_REASON_PROFILE_HASH_ZERO);
        }

        let profile =
            EconomicsProfile::load_from_cas(self.cas, &self.profile_hash).map_err(|error| {
                match error {
                    EconomicsProfileError::Cas(CasError::NotFound { .. }) => {
                        DENY_REASON_PROFILE_MISSING
                    },
                    EconomicsProfileError::HashMismatch { .. }
                    | EconomicsProfileError::InvalidFrame
                    | EconomicsProfileError::InvalidSchema { .. }
                    | EconomicsProfileError::InvalidSchemaVersion { .. }
                    | EconomicsProfileError::DuplicateBudgetEntry { .. }
                    | EconomicsProfileError::BudgetEntriesTooLarge { .. }
                    | EconomicsProfileError::Serialization { .. } => DENY_REASON_PROFILE_INVALID,
                    EconomicsProfileError::Cas(_) => DENY_REASON_PROFILE_UNRESOLVED,
                }
            })?;

        match profile.input_state {
            EconomicsProfileInputState::Current => Ok(profile),
            EconomicsProfileInputState::Stale => Err(DENY_REASON_PROFILE_STALE),
            EconomicsProfileInputState::Unresolved => Err(DENY_REASON_PROFILE_INPUTS_UNRESOLVED),
        }
    }

    const fn first_exceedance_reason(
        observed_usage: &ObservedUsage,
        limits: &BudgetEntry,
    ) -> Option<&'static str> {
        if observed_usage.tokens_used > limits.max_tokens {
            return Some(DENY_REASON_TOKENS_EXCEEDED);
        }
        if observed_usage.tool_calls_used > limits.max_tool_calls {
            return Some(DENY_REASON_TOOL_CALLS_EXCEEDED);
        }
        if observed_usage.time_ms_used > limits.max_time_ms {
            return Some(DENY_REASON_TIME_MS_EXCEEDED);
        }
        if observed_usage.io_bytes_used > limits.max_io_bytes {
            return Some(DENY_REASON_IO_BYTES_EXCEEDED);
        }
        None
    }

    const fn allow(
        &self,
        tier: RiskTier,
        intent_class: BoundaryIntentClass,
        observed: ObservedUsage,
        limits: BudgetEntry,
    ) -> BudgetAdmissionDecision {
        let trace = BudgetAdmissionTrace {
            profile_hash: self.profile_hash,
            tier,
            intent_class,
            observed,
            limits: Some(limits),
            verdict: BudgetAdmissionVerdict::Allow,
            deny_reason: None,
        };

        BudgetAdmissionDecision {
            verdict: BudgetAdmissionVerdict::Allow,
            deny_reason: None,
            trace,
        }
    }

    fn deny(
        &self,
        tier: RiskTier,
        intent_class: BoundaryIntentClass,
        observed: ObservedUsage,
        limits: Option<BudgetEntry>,
        deny_reason: &str,
    ) -> BudgetAdmissionDecision {
        let deny_reason_owned = deny_reason.to_string();
        let trace = BudgetAdmissionTrace {
            profile_hash: self.profile_hash,
            tier,
            intent_class,
            observed,
            limits,
            verdict: BudgetAdmissionVerdict::Deny,
            deny_reason: Some(deny_reason_owned.clone()),
        };

        BudgetAdmissionDecision {
            verdict: BudgetAdmissionVerdict::Deny,
            deny_reason: Some(deny_reason_owned),
            trace,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{
        BudgetAdmissionEvaluator, BudgetAdmissionVerdict, DENY_REASON_BUDGET_ENTRY_MISSING,
        DENY_REASON_IO_BYTES_EXCEEDED, DENY_REASON_PROFILE_HASH_ZERO,
        DENY_REASON_PROFILE_INPUTS_UNRESOLVED, DENY_REASON_PROFILE_INVALID,
        DENY_REASON_PROFILE_MISSING, DENY_REASON_PROFILE_STALE, DENY_REASON_TIME_MS_EXCEEDED,
        DENY_REASON_TOKENS_EXCEEDED, DENY_REASON_TOOL_CALLS_EXCEEDED, ObservedUsage,
    };
    use crate::economics::profile::{
        BudgetEntry, ECONOMICS_PROFILE_HASH_DOMAIN, EconomicsProfile, EconomicsProfileInputState,
        LifecycleCostVector,
    };
    use crate::evidence::{ContentAddressedStore, MemoryCas};
    use crate::pcac::{BoundaryIntentClass, RiskTier};

    const ALL_RISK_TIERS: [RiskTier; 3] = [RiskTier::Tier0, RiskTier::Tier1, RiskTier::Tier2Plus];
    const ALL_INTENT_CLASSES: [BoundaryIntentClass; 5] = [
        BoundaryIntentClass::Observe,
        BoundaryIntentClass::Assert,
        BoundaryIntentClass::Delegate,
        BoundaryIntentClass::Actuate,
        BoundaryIntentClass::Govern,
    ];

    fn lifecycle_costs() -> LifecycleCostVector {
        LifecycleCostVector {
            c_join: 1,
            c_revalidate: 2,
            c_consume: 3,
            c_effect: 4,
            c_replay: 5,
            c_recovery: 6,
        }
    }

    fn limits() -> BudgetEntry {
        BudgetEntry {
            max_tokens: 100,
            max_tool_calls: 10,
            max_time_ms: 1_000,
            max_io_bytes: 10_000,
        }
    }

    fn observed_within_limits() -> ObservedUsage {
        ObservedUsage {
            tokens_used: 50,
            tool_calls_used: 5,
            time_ms_used: 500,
            io_bytes_used: 5_000,
        }
    }

    fn full_matrix() -> BTreeMap<(RiskTier, BoundaryIntentClass), BudgetEntry> {
        let mut matrix = BTreeMap::new();
        for tier in ALL_RISK_TIERS {
            for intent_class in ALL_INTENT_CLASSES {
                matrix.insert((tier, intent_class), limits());
            }
        }
        matrix
    }

    fn build_profile(state: EconomicsProfileInputState) -> EconomicsProfile {
        EconomicsProfile::new(lifecycle_costs(), state, full_matrix())
            .expect("profile should be valid")
    }

    #[test]
    fn zero_profile_hash_denies_fail_closed() {
        let cas = MemoryCas::new();
        let evaluator = BudgetAdmissionEvaluator::new(&cas, [0u8; 32]);

        let decision = evaluator.evaluate(
            RiskTier::Tier0,
            BoundaryIntentClass::Observe,
            &observed_within_limits(),
        );

        assert_eq!(decision.verdict, BudgetAdmissionVerdict::Deny);
        assert_eq!(
            decision.deny_reason.as_deref(),
            Some(DENY_REASON_PROFILE_HASH_ZERO)
        );
    }

    #[test]
    fn missing_cas_entry_denies_fail_closed() {
        let cas = MemoryCas::new();
        let evaluator = BudgetAdmissionEvaluator::new(&cas, [0xAA; 32]);

        let decision = evaluator.evaluate(
            RiskTier::Tier0,
            BoundaryIntentClass::Observe,
            &observed_within_limits(),
        );

        assert_eq!(decision.verdict, BudgetAdmissionVerdict::Deny);
        assert_eq!(
            decision.deny_reason.as_deref(),
            Some(DENY_REASON_PROFILE_MISSING)
        );
    }

    #[test]
    fn invalid_profile_bytes_denies_fail_closed() {
        let cas = MemoryCas::new();
        let mut invalid = Vec::from(ECONOMICS_PROFILE_HASH_DOMAIN);
        invalid.extend_from_slice(br#"{"schema":"broken""#);
        let profile_hash = cas
            .store(&invalid)
            .expect("invalid payload should store")
            .hash;

        let evaluator = BudgetAdmissionEvaluator::new(&cas, profile_hash);
        let decision = evaluator.evaluate(
            RiskTier::Tier0,
            BoundaryIntentClass::Observe,
            &observed_within_limits(),
        );

        assert_eq!(decision.verdict, BudgetAdmissionVerdict::Deny);
        assert_eq!(
            decision.deny_reason.as_deref(),
            Some(DENY_REASON_PROFILE_INVALID)
        );
    }

    #[test]
    fn noncanonical_profile_payload_hash_mismatch_denies_fail_closed() {
        let cas = MemoryCas::new();
        let profile = build_profile(EconomicsProfileInputState::Current);
        let canonical_json = profile
            .canonical_bytes()
            .expect("canonical profile bytes should serialize");
        let canonical_value: serde_json::Value =
            serde_json::from_slice(&canonical_json).expect("canonical profile bytes should parse");
        let noncanonical_json = serde_json::to_vec_pretty(&canonical_value)
            .expect("non-canonical profile payload should serialize");
        assert_ne!(noncanonical_json, canonical_json);

        let mut framed = Vec::from(ECONOMICS_PROFILE_HASH_DOMAIN);
        framed.extend_from_slice(&noncanonical_json);
        let profile_hash = cas
            .store(&framed)
            .expect("non-canonical profile payload should store")
            .hash;

        let evaluator = BudgetAdmissionEvaluator::new(&cas, profile_hash);
        let decision = evaluator.evaluate(
            RiskTier::Tier0,
            BoundaryIntentClass::Observe,
            &observed_within_limits(),
        );

        assert_eq!(decision.verdict, BudgetAdmissionVerdict::Deny);
        assert_eq!(
            decision.deny_reason.as_deref(),
            Some(DENY_REASON_PROFILE_INVALID)
        );
    }

    #[test]
    fn stale_profile_inputs_deny_fail_closed() {
        let cas = MemoryCas::new();
        let profile_hash = build_profile(EconomicsProfileInputState::Stale)
            .store_in_cas(&cas)
            .expect("stale profile should store");
        let evaluator = BudgetAdmissionEvaluator::new(&cas, profile_hash);

        let decision = evaluator.evaluate(
            RiskTier::Tier0,
            BoundaryIntentClass::Observe,
            &observed_within_limits(),
        );

        assert_eq!(decision.verdict, BudgetAdmissionVerdict::Deny);
        assert_eq!(
            decision.deny_reason.as_deref(),
            Some(DENY_REASON_PROFILE_STALE)
        );
    }

    #[test]
    fn unresolved_profile_inputs_deny_fail_closed() {
        let cas = MemoryCas::new();
        let profile_hash = build_profile(EconomicsProfileInputState::Unresolved)
            .store_in_cas(&cas)
            .expect("unresolved profile should store");
        let evaluator = BudgetAdmissionEvaluator::new(&cas, profile_hash);

        let decision = evaluator.evaluate(
            RiskTier::Tier0,
            BoundaryIntentClass::Observe,
            &observed_within_limits(),
        );

        assert_eq!(decision.verdict, BudgetAdmissionVerdict::Deny);
        assert_eq!(
            decision.deny_reason.as_deref(),
            Some(DENY_REASON_PROFILE_INPUTS_UNRESOLVED)
        );
    }

    #[test]
    fn missing_budget_entry_denies_unprofiled_path() {
        let mut partial_matrix = BTreeMap::new();
        partial_matrix.insert((RiskTier::Tier0, BoundaryIntentClass::Observe), limits());

        let profile = EconomicsProfile::new(
            lifecycle_costs(),
            EconomicsProfileInputState::Current,
            partial_matrix,
        )
        .expect("partial profile should be valid");
        let cas = MemoryCas::new();
        let profile_hash = profile
            .store_in_cas(&cas)
            .expect("partial profile should store");

        let evaluator = BudgetAdmissionEvaluator::new(&cas, profile_hash);
        let decision = evaluator.evaluate(
            RiskTier::Tier2Plus,
            BoundaryIntentClass::Actuate,
            &observed_within_limits(),
        );

        assert_eq!(decision.verdict, BudgetAdmissionVerdict::Deny);
        assert_eq!(
            decision.deny_reason.as_deref(),
            Some(DENY_REASON_BUDGET_ENTRY_MISSING)
        );
    }

    #[test]
    fn usage_within_limits_allows() {
        let cas = MemoryCas::new();
        let profile_hash = build_profile(EconomicsProfileInputState::Current)
            .store_in_cas(&cas)
            .expect("profile should store");
        let evaluator = BudgetAdmissionEvaluator::new(&cas, profile_hash);

        let decision = evaluator.evaluate(
            RiskTier::Tier1,
            BoundaryIntentClass::Assert,
            &observed_within_limits(),
        );

        assert_eq!(decision.verdict, BudgetAdmissionVerdict::Allow);
        assert_eq!(decision.deny_reason, None);
        assert_eq!(decision.trace.limits, Some(limits()));
    }

    #[test]
    fn token_exceedance_denies_with_specific_reason() {
        let cas = MemoryCas::new();
        let profile_hash = build_profile(EconomicsProfileInputState::Current)
            .store_in_cas(&cas)
            .expect("profile should store");
        let evaluator = BudgetAdmissionEvaluator::new(&cas, profile_hash);

        let mut observed = observed_within_limits();
        observed.tokens_used = 101;

        let decision = evaluator.evaluate(RiskTier::Tier0, BoundaryIntentClass::Observe, &observed);

        assert_eq!(decision.verdict, BudgetAdmissionVerdict::Deny);
        assert_eq!(
            decision.deny_reason.as_deref(),
            Some(DENY_REASON_TOKENS_EXCEEDED)
        );
    }

    #[test]
    fn tool_calls_exceedance_denies_with_specific_reason() {
        let cas = MemoryCas::new();
        let profile_hash = build_profile(EconomicsProfileInputState::Current)
            .store_in_cas(&cas)
            .expect("profile should store");
        let evaluator = BudgetAdmissionEvaluator::new(&cas, profile_hash);

        let mut observed = observed_within_limits();
        observed.tool_calls_used = 11;

        let decision = evaluator.evaluate(RiskTier::Tier0, BoundaryIntentClass::Observe, &observed);

        assert_eq!(decision.verdict, BudgetAdmissionVerdict::Deny);
        assert_eq!(
            decision.deny_reason.as_deref(),
            Some(DENY_REASON_TOOL_CALLS_EXCEEDED)
        );
    }

    #[test]
    fn time_exceedance_denies_with_specific_reason() {
        let cas = MemoryCas::new();
        let profile_hash = build_profile(EconomicsProfileInputState::Current)
            .store_in_cas(&cas)
            .expect("profile should store");
        let evaluator = BudgetAdmissionEvaluator::new(&cas, profile_hash);

        let mut observed = observed_within_limits();
        observed.time_ms_used = 1_001;

        let decision = evaluator.evaluate(RiskTier::Tier0, BoundaryIntentClass::Observe, &observed);

        assert_eq!(decision.verdict, BudgetAdmissionVerdict::Deny);
        assert_eq!(
            decision.deny_reason.as_deref(),
            Some(DENY_REASON_TIME_MS_EXCEEDED)
        );
    }

    #[test]
    fn io_exceedance_denies_with_specific_reason() {
        let cas = MemoryCas::new();
        let profile_hash = build_profile(EconomicsProfileInputState::Current)
            .store_in_cas(&cas)
            .expect("profile should store");
        let evaluator = BudgetAdmissionEvaluator::new(&cas, profile_hash);

        let mut observed = observed_within_limits();
        observed.io_bytes_used = 10_001;

        let decision = evaluator.evaluate(RiskTier::Tier0, BoundaryIntentClass::Observe, &observed);

        assert_eq!(decision.verdict, BudgetAdmissionVerdict::Deny);
        assert_eq!(
            decision.deny_reason.as_deref(),
            Some(DENY_REASON_IO_BYTES_EXCEEDED)
        );
    }

    #[test]
    fn multiple_exceedances_return_first_deny_reason() {
        let cas = MemoryCas::new();
        let profile_hash = build_profile(EconomicsProfileInputState::Current)
            .store_in_cas(&cas)
            .expect("profile should store");
        let evaluator = BudgetAdmissionEvaluator::new(&cas, profile_hash);

        let observed = ObservedUsage {
            tokens_used: 1_000,
            tool_calls_used: 1_000,
            time_ms_used: 1_000_000,
            io_bytes_used: 1_000_000,
        };

        let decision = evaluator.evaluate(RiskTier::Tier0, BoundaryIntentClass::Observe, &observed);

        assert_eq!(decision.verdict, BudgetAdmissionVerdict::Deny);
        assert_eq!(
            decision.deny_reason.as_deref(),
            Some(DENY_REASON_TOKENS_EXCEEDED)
        );
    }

    #[test]
    fn trace_is_deterministic_for_identical_inputs() {
        let cas = MemoryCas::new();
        let profile_hash = build_profile(EconomicsProfileInputState::Current)
            .store_in_cas(&cas)
            .expect("profile should store");
        let evaluator = BudgetAdmissionEvaluator::new(&cas, profile_hash);
        let observed = observed_within_limits();

        let decision_a =
            evaluator.evaluate(RiskTier::Tier1, BoundaryIntentClass::Assert, &observed);
        let decision_b =
            evaluator.evaluate(RiskTier::Tier1, BoundaryIntentClass::Assert, &observed);

        let trace_a = decision_a
            .trace
            .canonical_bytes()
            .expect("trace A canonical bytes should serialize");
        let trace_b = decision_b
            .trace
            .canonical_bytes()
            .expect("trace B canonical bytes should serialize");

        assert_eq!(trace_a, trace_b);
    }

    #[test]
    fn all_risk_tier_and_intent_class_combinations_are_exercised() {
        let cas = MemoryCas::new();
        let profile_hash = build_profile(EconomicsProfileInputState::Current)
            .store_in_cas(&cas)
            .expect("profile should store");
        let evaluator = BudgetAdmissionEvaluator::new(&cas, profile_hash);
        let observed = observed_within_limits();

        let mut checked = 0usize;
        for tier in ALL_RISK_TIERS {
            for intent_class in ALL_INTENT_CLASSES {
                let decision = evaluator.evaluate(tier, intent_class, &observed);
                assert_eq!(
                    decision.verdict,
                    BudgetAdmissionVerdict::Allow,
                    "combination should allow: tier={tier}, class={intent_class}"
                );
                checked += 1;
            }
        }

        let expected = ALL_RISK_TIERS.len() * ALL_INTENT_CLASSES.len();
        assert_eq!(checked, expected);
        assert!(checked > 1);
    }
}
