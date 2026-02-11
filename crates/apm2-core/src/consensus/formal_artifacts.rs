//! Formal artifact aggregation gate for promotion decisions.
//!
//! RFC-0020 requires promotion surfaces that tighten enforcement or add
//! federation behavior to maintain a complete formal-artifact bundle:
//! - session model convergence
//! - anti-entropy posture checks
//! - bisimulation proof (depth <= 12)
//! - functor-law proof

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::{
    AdmittedRewriteCatalog, AntiEntropyDefect, ConvergenceError, ConvergenceReport,
    ConvergenceSimulator, ObservableSemantics, PromotionGate, PromotionGateResult,
    RewriteGateResult, RewritePromotionGate,
};

/// Maximum bisimulation depth for formal artifact promotion checks.
pub const FORMAL_BISIMULATION_MAX_DEPTH: usize = 12;

/// Classification of formal-artifact checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FormalGateClass {
    /// Bisimulation equivalence gate.
    Bisimulation,
    /// Functor-law rewrite gate.
    FunctorLaw,
    /// Anti-entropy posture gate.
    AntiEntropy,
    /// Session-model convergence gate.
    Convergence,
    /// Model-checked invariant hook gate.
    InvariantHooks,
}

/// Structured formal-artifact defect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FormalArtifactDefect {
    /// Gate class that produced the defect.
    pub gate: FormalGateClass,
    /// Machine-oriented defect code.
    pub code: String,
    /// Human-readable defect detail.
    pub detail: String,
}

/// Anti-entropy artifact posture summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AntiEntropyArtifactStatus {
    /// Pull-only protocol enforcement result.
    pub pull_only_enforced: bool,
    /// Relay budget enforcement result.
    pub relay_budget_enforced: bool,
    /// Whether byzantine relay behavior was detected.
    pub byzantine_relay_detected: bool,
    /// Optional anti-entropy defects from admission/enforcement surfaces.
    #[serde(default)]
    pub defects: Vec<AntiEntropyDefect>,
}

impl AntiEntropyArtifactStatus {
    /// Returns `true` when anti-entropy posture passes promotion criteria.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.pull_only_enforced
            && self.relay_budget_enforced
            && !self.byzantine_relay_detected
            && self.defects.is_empty()
    }
}

/// Model-checked invariant verification hooks required by RFC-0020.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelCheckedInvariantReport {
    /// `true` iff no actuation can occur without verified stop state.
    pub no_actuation_without_verified_stop_state: bool,
    /// `true` iff delegation scope cannot widen.
    pub no_delegation_widening: bool,
    /// `true` iff unsigned facts are rejected from admission.
    pub no_unsigned_facts_admitted: bool,
}

impl ModelCheckedInvariantReport {
    /// Returns `true` when all required invariants are satisfied.
    #[must_use]
    pub const fn passed(&self) -> bool {
        self.no_actuation_without_verified_stop_state
            && self.no_delegation_widening
            && self.no_unsigned_facts_admitted
    }
}

/// Captured formal artifact outputs for one promotion evaluation.
#[derive(Debug, Clone)]
pub struct FormalGateArtifactSet {
    /// Bisimulation gate output.
    pub bisimulation: PromotionGateResult,
    /// Functor-law gate output.
    pub functor: RewriteGateResult,
    /// Anti-entropy posture summary.
    pub anti_entropy: AntiEntropyArtifactStatus,
    /// Session-model convergence report.
    pub convergence: ConvergenceReport,
    /// Invariant-hook report.
    pub invariants: ModelCheckedInvariantReport,
}

/// Composite formal-gate result with pass/fail breakdown and blocking defects.
#[derive(Debug, Clone)]
pub struct FormalGateArtifactResult {
    /// Formal artifact outputs used for this decision.
    pub artifacts: FormalGateArtifactSet,
    /// `true` if promotion is allowed.
    pub allowed: bool,
    /// Per-gate blocking defects.
    pub blocking_defects: Vec<FormalArtifactDefect>,
}

/// Errors produced during formal-gate artifact evaluation.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum FormalGateArtifactError {
    /// Bisimulation gate construction/evaluation failed.
    #[error("bisimulation evaluation failed: {reason}")]
    Bisimulation {
        /// Failure reason.
        reason: String,
    },
    /// Convergence simulation failed.
    #[error("convergence simulation failed: {0}")]
    Convergence(#[from] ConvergenceError),
}

impl FormalGateArtifactSet {
    /// Evaluates all required formal artifacts and returns a composite result.
    ///
    /// This method runs:
    /// - bisimulation gate (depth <= 12)
    /// - functor-law gate
    /// - anti-entropy posture gate
    /// - convergence simulation gate
    /// - model-checked invariant hooks
    ///
    /// # Errors
    ///
    /// Returns [`FormalGateArtifactError`] when bisimulation or convergence
    /// evaluation fails unexpectedly.
    pub fn evaluate_all(
        compositions: &[ObservableSemantics],
        catalog: &AdmittedRewriteCatalog,
        anti_entropy: AntiEntropyArtifactStatus,
        convergence_simulator: &mut ConvergenceSimulator,
        max_convergence_rounds: usize,
        invariants: ModelCheckedInvariantReport,
    ) -> Result<FormalGateArtifactResult, FormalGateArtifactError> {
        let bisimulation_gate =
            PromotionGate::new(FORMAL_BISIMULATION_MAX_DEPTH).map_err(|error| {
                FormalGateArtifactError::Bisimulation {
                    reason: error.to_string(),
                }
            })?;
        let bisimulation = bisimulation_gate.evaluate(compositions).map_err(|error| {
            FormalGateArtifactError::Bisimulation {
                reason: error.to_string(),
            }
        })?;

        let functor = RewritePromotionGate::new().evaluate(catalog);
        let convergence = convergence_simulator.converge(max_convergence_rounds)?;

        let artifacts = Self {
            bisimulation,
            functor,
            anti_entropy,
            convergence,
            invariants,
        };

        Ok(FormalGateArtifactResult {
            allowed: artifacts.passed(),
            blocking_defects: artifacts.collect_defects(),
            artifacts,
        })
    }

    /// Returns `true` when every required artifact gate passes.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.bisimulation.allowed()
            && self.functor.allowed()
            && self.anti_entropy.passed()
            && self.convergence.converged
            && self.invariants.passed()
    }

    /// Returns per-gate defect records.
    #[must_use]
    pub fn collect_defects(&self) -> Vec<FormalArtifactDefect> {
        let mut defects = Vec::new();

        if !self.bisimulation.allowed() {
            defects.push(FormalArtifactDefect {
                gate: FormalGateClass::Bisimulation,
                code: "BISIMULATION_BLOCKING_DEFECTS".to_string(),
                detail: format!(
                    "{} blocking defect(s)",
                    self.bisimulation.blocking_defects().len()
                ),
            });
        }
        if !self.functor.allowed() {
            defects.push(FormalArtifactDefect {
                gate: FormalGateClass::FunctorLaw,
                code: "FUNCTOR_LAW_BLOCKING_DEFECTS".to_string(),
                detail: format!(
                    "{} blocking defect(s)",
                    self.functor.blocking_defects().len()
                ),
            });
        }
        if !self.anti_entropy.passed() {
            defects.push(FormalArtifactDefect {
                gate: FormalGateClass::AntiEntropy,
                code: "ANTI_ENTROPY_POSTURE_FAILED".to_string(),
                detail: format!(
                    "pull_only_enforced={}, relay_budget_enforced={}, byzantine_relay_detected={}, defects={}",
                    self.anti_entropy.pull_only_enforced,
                    self.anti_entropy.relay_budget_enforced,
                    self.anti_entropy.byzantine_relay_detected,
                    self.anti_entropy.defects.len()
                ),
            });
        }
        if !self.convergence.converged {
            defects.push(FormalArtifactDefect {
                gate: FormalGateClass::Convergence,
                code: "CONVERGENCE_NOT_REACHED".to_string(),
                detail: format!(
                    "convergence not reached within {} round(s)",
                    self.convergence.rounds_executed
                ),
            });
        }
        if !self.invariants.no_actuation_without_verified_stop_state {
            defects.push(FormalArtifactDefect {
                gate: FormalGateClass::InvariantHooks,
                code: "NO_ACTUATION_WITHOUT_VERIFIED_STOP_STATE_FAILED".to_string(),
                detail: "actuation path without verified stop state".to_string(),
            });
        }
        if !self.invariants.no_delegation_widening {
            defects.push(FormalArtifactDefect {
                gate: FormalGateClass::InvariantHooks,
                code: "NO_DELEGATION_WIDENING_FAILED".to_string(),
                detail: "delegation widening detected".to_string(),
            });
        }
        if !self.invariants.no_unsigned_facts_admitted {
            defects.push(FormalArtifactDefect {
                gate: FormalGateClass::InvariantHooks,
                code: "NO_UNSIGNED_FACTS_ADMITTED_FAILED".to_string(),
                detail: "unsigned fact admission detected".to_string(),
            });
        }

        defects
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::{Hlc, MAX_CONVERGENCE_ROUNDS, RewriteRule, build_linear_composition};

    #[test]
    fn formal_artifact_set_passes_when_all_components_pass() {
        let compositions = vec![build_linear_composition(0).expect("composition should build")];

        let mut catalog = AdmittedRewriteCatalog::new().expect("catalog should construct");
        let lts = build_linear_composition(0).expect("composition should build");
        let rule = RewriteRule::new("R001".to_string(), "identity".to_string(), lts.clone(), lts)
            .expect("rule should construct");
        catalog.register_rule(rule).expect("rule should register");
        catalog
            .submit_proof("R001", "cas://proof/r001")
            .expect("proof should verify");

        let anti_entropy = AntiEntropyArtifactStatus {
            pull_only_enforced: true,
            relay_budget_enforced: true,
            byzantine_relay_detected: false,
            defects: Vec::new(),
        };

        let mut convergence =
            ConvergenceSimulator::new(vec!["cell-a".to_string(), "cell-b".to_string()], 8)
                .expect("simulator should construct");
        convergence
            .admit("cell-a", "subject-1", "value", Hlc::new(1, 0))
            .expect("admit should succeed");

        let invariants = ModelCheckedInvariantReport {
            no_actuation_without_verified_stop_state: true,
            no_delegation_widening: true,
            no_unsigned_facts_admitted: true,
        };

        let result = FormalGateArtifactSet::evaluate_all(
            &compositions,
            &catalog,
            anti_entropy,
            &mut convergence,
            MAX_CONVERGENCE_ROUNDS,
            invariants,
        )
        .expect("formal artifacts should evaluate");
        assert!(result.allowed);
        assert_eq!(result.blocking_defects.len(), 0);
    }

    #[test]
    fn formal_artifact_set_blocks_when_invariant_hook_fails() {
        let compositions = vec![build_linear_composition(0).expect("composition should build")];

        let mut catalog = AdmittedRewriteCatalog::new().expect("catalog should construct");
        let lts = build_linear_composition(0).expect("composition should build");
        let rule = RewriteRule::new("R001".to_string(), "identity".to_string(), lts.clone(), lts)
            .expect("rule should construct");
        catalog.register_rule(rule).expect("rule should register");
        catalog
            .submit_proof("R001", "cas://proof/r001")
            .expect("proof should verify");

        let anti_entropy = AntiEntropyArtifactStatus {
            pull_only_enforced: true,
            relay_budget_enforced: true,
            byzantine_relay_detected: false,
            defects: Vec::new(),
        };

        let mut convergence =
            ConvergenceSimulator::new(vec!["cell-a".to_string(), "cell-b".to_string()], 8)
                .expect("simulator should construct");
        convergence
            .admit("cell-a", "subject-1", "value", Hlc::new(1, 0))
            .expect("admit should succeed");

        let invariants = ModelCheckedInvariantReport {
            no_actuation_without_verified_stop_state: false,
            no_delegation_widening: true,
            no_unsigned_facts_admitted: true,
        };

        let result = FormalGateArtifactSet::evaluate_all(
            &compositions,
            &catalog,
            anti_entropy,
            &mut convergence,
            MAX_CONVERGENCE_ROUNDS,
            invariants,
        )
        .expect("formal artifacts should evaluate");

        assert!(!result.allowed);
        assert_eq!(result.blocking_defects.len(), 1);
        assert_eq!(
            result.blocking_defects[0].code,
            "NO_ACTUATION_WITHOUT_VERIFIED_STOP_STATE_FAILED"
        );
    }
}
