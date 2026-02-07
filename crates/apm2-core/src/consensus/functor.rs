// AGENT-AUTHORED
//! Functorial observation law checks for admitted rewrites (TCK-00368).
//!
//! This module encodes functorial law constraints for optimization rewrites
//! over HSI observable semantics. A rewrite is admitted only when observation
//! preservation is proven: the functor law `observe(rewrite(x)) ==
//! rewrite(observe(x))` must hold for every admitted rewrite rule.
//!
//! # Overview
//!
//! Optimization rewrites transform holon composition structures (e.g.,
//! collapsing redundant spawn chains, eliding no-op escalations). These
//! rewrites must not alter observable HSI truth semantics. This module
//! provides:
//!
//! - [`RewriteRule`]: A named rewrite with source/target patterns and an
//!   observation-preservation proof obligation
//! - [`FunctorLawChecker`]: Verifies the functorial law `map-then-observe ==
//!   observe-then-map` for a rewrite rule
//! - [`AdmittedRewriteCatalog`]: Tracks proof obligations and admits only
//!   proven rewrites
//! - [`RewritePromotionGate`]: Integrates with the formal artifact review gate
//!   to block non-proven rewrites from release pipelines
//!
//! # Security Properties
//!
//! - **Fail-closed**: Non-proven rewrites are blocked by default
//! - **Explicit authority**: Each rewrite must carry a proof obligation
//!   artifact reference
//! - **Observation preservation**: The functorial law ensures optimizations
//!   cannot silently alter observable behavior
//!
//! # References
//!
//! - RFC-0020: Holonic Composition and Recursive Structure
//! - REQ-0022: Functorial observation law for admitted rewrites
//! - Mac Lane, S. "Categories for the Working Mathematician" (1971)

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::bisimulation::{BisimulationChecker, BisimulationError, ObservableSemantics};

// ============================================================================
// Constants
// ============================================================================

/// Maximum number of rewrite rules in a catalog.
///
/// Bounds the catalog size to prevent unbounded memory consumption.
pub const MAX_CATALOG_RULES: usize = 256;

/// Maximum length of a rewrite rule identifier.
pub const MAX_RULE_ID_LEN: usize = 128;

/// Maximum length of a proof obligation reference.
pub const MAX_PROOF_REF_LEN: usize = 256;

/// Maximum number of observation points to check per rewrite rule.
///
/// Each observation point is an HSI operation whose output is compared
/// before and after the rewrite.
pub const MAX_OBSERVATION_POINTS: usize = 64;

// ============================================================================
// Errors
// ============================================================================

/// Errors that can occur during functorial law checking.
#[derive(Debug, Error)]
pub enum FunctorError {
    /// The rewrite rule identifier exceeds the maximum length.
    #[error("rule id length {len} exceeds maximum {max}")]
    RuleIdTooLong {
        /// The actual length.
        len: usize,
        /// The maximum allowed length.
        max: usize,
    },

    /// The proof obligation reference exceeds the maximum length.
    #[error("proof reference length {len} exceeds maximum {max}")]
    ProofRefTooLong {
        /// The actual length.
        len: usize,
        /// The maximum allowed length.
        max: usize,
    },

    /// The catalog has reached its maximum capacity.
    #[error("catalog full: {count} rules (max {max})")]
    CatalogFull {
        /// The current count.
        count: usize,
        /// The maximum allowed.
        max: usize,
    },

    /// A rewrite rule with this ID already exists.
    #[error("duplicate rule id: {0}")]
    DuplicateRule(String),

    /// The referenced rule was not found.
    #[error("rule not found: {0}")]
    RuleNotFound(String),

    /// The functorial law check failed.
    #[error("functorial law violation: {description}")]
    LawViolation {
        /// The rule that violated the law.
        rule_id: String,
        /// Description of the violation.
        description: String,
    },

    /// Too many observation points.
    #[error("too many observation points: {count} (max {max})")]
    TooManyObservationPoints {
        /// The actual count.
        count: usize,
        /// The maximum allowed.
        max: usize,
    },

    /// An underlying bisimulation error.
    #[error("bisimulation error: {0}")]
    Bisimulation(#[from] BisimulationError),

    /// The rule has no proof obligation.
    #[error("rule {rule_id} has no proof obligation")]
    NoProofObligation {
        /// The rule missing a proof.
        rule_id: String,
    },
}

// ============================================================================
// Rewrite Rule
// ============================================================================

/// The status of a proof obligation for a rewrite rule.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProofStatus {
    /// No proof has been submitted.
    Pending,
    /// A proof has been submitted and verified.
    Verified {
        /// Reference to the proof artifact (e.g., EVID-0022).
        artifact_ref: String,
    },
    /// A proof was submitted but verification failed.
    Rejected {
        /// The reason the proof was rejected.
        reason: String,
    },
}

impl fmt::Display for ProofStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pending => write!(f, "PENDING"),
            Self::Verified { artifact_ref } => write!(f, "VERIFIED({artifact_ref})"),
            Self::Rejected { reason } => write!(f, "REJECTED({reason})"),
        }
    }
}

/// A rewrite rule that transforms HSI composition structures.
///
/// Each rule defines a source pattern (the structure before rewriting)
/// and a target pattern (the structure after rewriting). The rule is
/// admitted only when the observation-preservation proof obligation is
/// verified.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RewriteRule {
    /// Unique identifier for this rewrite rule.
    id: String,

    /// Human-readable description of what this rewrite does.
    description: String,

    /// The source pattern (pre-rewrite observable semantics).
    source_pattern: ObservableSemantics,

    /// The target pattern (post-rewrite observable semantics).
    target_pattern: ObservableSemantics,

    /// The status of the observation-preservation proof obligation.
    proof_status: ProofStatus,
}

impl RewriteRule {
    /// Creates a new rewrite rule with pending proof status.
    ///
    /// # Errors
    ///
    /// Returns an error if the rule ID exceeds `MAX_RULE_ID_LEN`.
    pub fn new(
        id: String,
        description: String,
        source_pattern: ObservableSemantics,
        target_pattern: ObservableSemantics,
    ) -> Result<Self, FunctorError> {
        if id.len() > MAX_RULE_ID_LEN {
            return Err(FunctorError::RuleIdTooLong {
                len: id.len(),
                max: MAX_RULE_ID_LEN,
            });
        }

        Ok(Self {
            id,
            description,
            source_pattern,
            target_pattern,
            proof_status: ProofStatus::Pending,
        })
    }

    /// Returns the rule identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the rule description.
    #[must_use]
    pub fn description(&self) -> &str {
        &self.description
    }

    /// Returns the source pattern.
    #[must_use]
    pub const fn source_pattern(&self) -> &ObservableSemantics {
        &self.source_pattern
    }

    /// Returns the target pattern.
    #[must_use]
    pub const fn target_pattern(&self) -> &ObservableSemantics {
        &self.target_pattern
    }

    /// Returns the current proof status.
    #[must_use]
    pub const fn proof_status(&self) -> &ProofStatus {
        &self.proof_status
    }

    /// Returns whether this rule has been verified.
    #[must_use]
    pub const fn is_verified(&self) -> bool {
        matches!(self.proof_status, ProofStatus::Verified { .. })
    }
}

impl fmt::Display for RewriteRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RewriteRule({}: {} [{}])",
            self.id, self.description, self.proof_status
        )
    }
}

// ============================================================================
// Functor Law Checker
// ============================================================================

/// Result of a functorial law check for a single rewrite rule.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctorLawResult {
    /// The rule that was checked.
    rule_id: String,

    /// Whether the law holds.
    passed: bool,

    /// Description of the violation, if any.
    violation: Option<String>,
}

impl FunctorLawResult {
    /// Returns the rule ID.
    #[must_use]
    pub fn rule_id(&self) -> &str {
        &self.rule_id
    }

    /// Returns whether the law check passed.
    #[must_use]
    pub const fn passed(&self) -> bool {
        self.passed
    }

    /// Returns the violation description, if any.
    #[must_use]
    pub fn violation(&self) -> Option<&str> {
        self.violation.as_deref()
    }
}

impl fmt::Display for FunctorLawResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.passed {
            write!(f, "PASS: rule {} preserves observations", self.rule_id)
        } else {
            write!(
                f,
                "FAIL: rule {} violates functorial law: {}",
                self.rule_id,
                self.violation.as_deref().unwrap_or("unknown")
            )
        }
    }
}

/// Verifies the functorial observation law for rewrite rules.
///
/// The functorial law states that for any rewrite rule R and observation
/// function O:
///
/// ```text
///   O(R(x)) == R'(O(x))
/// ```
///
/// In practice, this means that applying the rewrite to a composition
/// and then observing the result must be equivalent (bisimilar) to
/// observing the original composition and then applying the
/// corresponding rewrite to the observations.
///
/// Since HSI observations are captured as labeled transition systems,
/// the checker uses bisimulation to verify this equivalence.
#[derive(Clone, Debug)]
pub struct FunctorLawChecker {
    /// The bisimulation checker used for equivalence verification.
    bisim_checker: BisimulationChecker,
}

impl FunctorLawChecker {
    /// Creates a new functor law checker.
    ///
    /// # Errors
    ///
    /// Returns an error if the bisimulation checker cannot be created.
    pub fn new() -> Result<Self, FunctorError> {
        let bisim_checker = BisimulationChecker::new(super::bisimulation::MAX_RECURSION_DEPTH)?;
        Ok(Self { bisim_checker })
    }

    /// Checks the functorial law for a rewrite rule.
    ///
    /// Verifies that `observe(rewrite(source)) == observe(target)` by
    /// checking bisimulation equivalence between the source and target
    /// patterns. If the source and target are bisimilar, the rewrite
    /// preserves observations.
    ///
    /// # Errors
    ///
    /// Returns an error if the bisimulation check encounters an internal
    /// error.
    pub fn check_rule(&self, rule: &RewriteRule) -> Result<FunctorLawResult, FunctorError> {
        // The functorial law: observe(rewrite(x)) == rewrite(observe(x))
        //
        // In our setting, the "observation" is the observable semantics
        // (the LTS). The rewrite transforms source_pattern into
        // target_pattern. For the law to hold, the source and target
        // must be observationally equivalent (bisimilar).
        let bisim_result = self
            .bisim_checker
            .check(rule.source_pattern(), rule.target_pattern())?;

        if bisim_result.passed() {
            Ok(FunctorLawResult {
                rule_id: rule.id().to_string(),
                passed: true,
                violation: None,
            })
        } else {
            let counterexample = bisim_result.counterexample();
            let violation_desc = if counterexample.is_empty() {
                "source and target patterns are not bisimilar".to_string()
            } else {
                format!("source and target patterns diverge: {}", counterexample[0])
            };

            Ok(FunctorLawResult {
                rule_id: rule.id().to_string(),
                passed: false,
                violation: Some(violation_desc),
            })
        }
    }

    /// Checks the functorial law for multiple rewrite rules.
    ///
    /// Returns results for each rule. All rules must pass for the batch
    /// to be considered valid.
    ///
    /// # Errors
    ///
    /// Returns an error if any bisimulation check encounters an internal
    /// error.
    pub fn check_rules(
        &self,
        rules: &[RewriteRule],
    ) -> Result<Vec<FunctorLawResult>, FunctorError> {
        let mut results = Vec::with_capacity(rules.len());
        for rule in rules {
            results.push(self.check_rule(rule)?);
        }
        Ok(results)
    }
}

// ============================================================================
// Admitted Rewrite Catalog
// ============================================================================

/// A catalog of rewrite rules with proof obligation tracking.
///
/// The catalog maintains the set of known rewrite rules and their proof
/// status. Only rules with verified proofs are admitted for use in
/// optimization pipelines.
///
/// # Fail-closed behavior
///
/// By default, all rules start with `ProofStatus::Pending` and are not
/// admitted. A rule must pass the functorial law check and have its
/// proof obligation verified before it can be admitted.
#[derive(Clone, Debug)]
pub struct AdmittedRewriteCatalog {
    /// The set of rewrite rules, keyed by rule ID.
    rules: BTreeMap<String, RewriteRule>,

    /// The functor law checker used for verification.
    checker: FunctorLawChecker,
}

impl AdmittedRewriteCatalog {
    /// Creates a new empty catalog.
    ///
    /// # Errors
    ///
    /// Returns an error if the functor law checker cannot be created.
    pub fn new() -> Result<Self, FunctorError> {
        let checker = FunctorLawChecker::new()?;
        Ok(Self {
            rules: BTreeMap::new(),
            checker,
        })
    }

    /// Returns the number of rules in the catalog.
    #[must_use]
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Returns the number of admitted (verified) rules.
    #[must_use]
    pub fn admitted_count(&self) -> usize {
        self.rules.values().filter(|r| r.is_verified()).count()
    }

    /// Returns the number of pending (unverified) rules.
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.rules
            .values()
            .filter(|r| matches!(r.proof_status(), ProofStatus::Pending))
            .count()
    }

    /// Returns a rule by ID, if it exists.
    #[must_use]
    pub fn get_rule(&self, id: &str) -> Option<&RewriteRule> {
        self.rules.get(id)
    }

    /// Returns all admitted (verified) rules.
    #[must_use]
    pub fn admitted_rules(&self) -> Vec<&RewriteRule> {
        self.rules.values().filter(|r| r.is_verified()).collect()
    }

    /// Returns all rules regardless of status.
    #[must_use]
    pub fn all_rules(&self) -> Vec<&RewriteRule> {
        self.rules.values().collect()
    }

    /// Registers a new rewrite rule with pending proof status.
    ///
    /// The rule is not admitted until its proof obligation is verified
    /// via [`submit_proof`](Self::submit_proof).
    ///
    /// # Errors
    ///
    /// Returns an error if the catalog is full or the rule ID already exists.
    pub fn register_rule(&mut self, rule: RewriteRule) -> Result<(), FunctorError> {
        if self.rules.len() >= MAX_CATALOG_RULES {
            return Err(FunctorError::CatalogFull {
                count: self.rules.len(),
                max: MAX_CATALOG_RULES,
            });
        }

        if self.rules.contains_key(rule.id()) {
            return Err(FunctorError::DuplicateRule(rule.id().to_string()));
        }

        self.rules.insert(rule.id().to_string(), rule);
        Ok(())
    }

    /// Submits a proof for a rewrite rule and verifies it.
    ///
    /// This method:
    /// 1. Looks up the rule by ID
    /// 2. Runs the functorial law check (bisimulation equivalence)
    /// 3. If the law holds, marks the rule as verified with the given artifact
    ///    reference
    /// 4. If the law does not hold, marks the rule as rejected
    ///
    /// # Errors
    ///
    /// Returns an error if the rule is not found, the proof reference
    /// is too long, or the bisimulation check encounters an internal error.
    pub fn submit_proof(
        &mut self,
        rule_id: &str,
        artifact_ref: &str,
    ) -> Result<FunctorLawResult, FunctorError> {
        if artifact_ref.len() > MAX_PROOF_REF_LEN {
            return Err(FunctorError::ProofRefTooLong {
                len: artifact_ref.len(),
                max: MAX_PROOF_REF_LEN,
            });
        }

        let rule = self
            .rules
            .get(rule_id)
            .ok_or_else(|| FunctorError::RuleNotFound(rule_id.to_string()))?
            .clone();

        let result = self.checker.check_rule(&rule)?;

        let rule_mut = self
            .rules
            .get_mut(rule_id)
            .ok_or_else(|| FunctorError::RuleNotFound(rule_id.to_string()))?;

        if result.passed() {
            rule_mut.proof_status = ProofStatus::Verified {
                artifact_ref: artifact_ref.to_string(),
            };
        } else {
            rule_mut.proof_status = ProofStatus::Rejected {
                reason: result
                    .violation()
                    .unwrap_or("functorial law violation")
                    .to_string(),
            };
        }

        Ok(result)
    }

    /// Removes a rule from the catalog.
    ///
    /// # Errors
    ///
    /// Returns an error if the rule is not found.
    pub fn remove_rule(&mut self, rule_id: &str) -> Result<RewriteRule, FunctorError> {
        self.rules
            .remove(rule_id)
            .ok_or_else(|| FunctorError::RuleNotFound(rule_id.to_string()))
    }
}

// ============================================================================
// Promotion Gate Integration
// ============================================================================

/// Result of a rewrite promotion gate evaluation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RewriteGateResult {
    /// Whether promotion is allowed.
    allowed: bool,

    /// Rules that passed the gate.
    passed_rules: Vec<String>,

    /// Blocking defects (rules that failed).
    blocking_defects: Vec<RewriteBlockingDefect>,
}

/// A blocking defect emitted when a rewrite rule fails the promotion gate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RewriteBlockingDefect {
    /// The rule that caused the defect.
    pub rule_id: String,
    /// The kind of defect.
    pub kind: RewriteDefectKind,
    /// Human-readable description.
    pub description: String,
}

/// The kind of rewrite promotion defect.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RewriteDefectKind {
    /// The rule has no proof obligation (still pending).
    NoProof,
    /// The proof was submitted but rejected.
    ProofRejected,
    /// The functorial law check failed.
    LawViolation,
}

impl fmt::Display for RewriteBlockingDefect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "BLOCKING DEFECT for rule {}: {:?} - {}",
            self.rule_id, self.kind, self.description
        )
    }
}

impl RewriteGateResult {
    /// Returns whether promotion is allowed.
    #[must_use]
    pub const fn allowed(&self) -> bool {
        self.allowed
    }

    /// Returns the rules that passed.
    #[must_use]
    pub fn passed_rules(&self) -> &[String] {
        &self.passed_rules
    }

    /// Returns the blocking defects.
    #[must_use]
    pub fn blocking_defects(&self) -> &[RewriteBlockingDefect] {
        &self.blocking_defects
    }
}

impl fmt::Display for RewriteGateResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.allowed {
            write!(
                f,
                "PASS: all {} rewrite rule(s) admitted",
                self.passed_rules.len()
            )
        } else {
            write!(
                f,
                "FAIL: {} blocking defect(s) in rewrite rules",
                self.blocking_defects.len()
            )
        }
    }
}

/// Promotion gate that blocks non-proven rewrites from release pipelines.
///
/// The gate evaluates all rewrite rules in a catalog and blocks promotion
/// if any rule lacks a verified proof obligation. This ensures that
/// optimization rewrites cannot be released without formal verification
/// that they preserve observable HSI truth semantics.
///
/// # Fail-closed behavior
///
/// - Rules with `ProofStatus::Pending` are blocked (no proof submitted)
/// - Rules with `ProofStatus::Rejected` are blocked (proof failed)
/// - Only rules with `ProofStatus::Verified` pass the gate
#[derive(Clone, Debug)]
pub struct RewritePromotionGate {
    /// Whether to require all rules to be verified (strict mode).
    /// When false, only rules that are explicitly rejected are blocked.
    strict: bool,
}

impl Default for RewritePromotionGate {
    fn default() -> Self {
        Self::new()
    }
}

impl RewritePromotionGate {
    /// Creates a new promotion gate in strict mode.
    ///
    /// In strict mode, all rules must have verified proofs. Pending
    /// rules are treated as blocking defects.
    #[must_use]
    pub const fn new() -> Self {
        Self { strict: true }
    }

    /// Creates a new promotion gate with the specified strictness.
    ///
    /// In non-strict mode, only explicitly rejected rules block
    /// promotion. Pending rules are allowed through.
    #[must_use]
    pub const fn with_strictness(strict: bool) -> Self {
        Self { strict }
    }

    /// Returns whether the gate is in strict mode.
    #[must_use]
    pub const fn is_strict(&self) -> bool {
        self.strict
    }

    /// Evaluates the promotion gate for a catalog of rewrite rules.
    ///
    /// Checks every rule in the catalog. A rule blocks promotion if:
    /// - It has `ProofStatus::Rejected` (always blocks)
    /// - It has `ProofStatus::Pending` and the gate is in strict mode
    #[must_use]
    pub fn evaluate(&self, catalog: &AdmittedRewriteCatalog) -> RewriteGateResult {
        let mut passed_rules = Vec::new();
        let mut blocking_defects = Vec::new();

        for rule in catalog.all_rules() {
            match rule.proof_status() {
                ProofStatus::Verified { .. } => {
                    passed_rules.push(rule.id().to_string());
                },
                ProofStatus::Pending => {
                    if self.strict {
                        blocking_defects.push(RewriteBlockingDefect {
                            rule_id: rule.id().to_string(),
                            kind: RewriteDefectKind::NoProof,
                            description: format!(
                                "Rule {} has no proof obligation; \
                                 submit proof before promotion",
                                rule.id()
                            ),
                        });
                    } else {
                        passed_rules.push(rule.id().to_string());
                    }
                },
                ProofStatus::Rejected { reason } => {
                    blocking_defects.push(RewriteBlockingDefect {
                        rule_id: rule.id().to_string(),
                        kind: RewriteDefectKind::ProofRejected,
                        description: format!("Rule {} proof was rejected: {}", rule.id(), reason),
                    });
                },
            }
        }

        let allowed = blocking_defects.is_empty();

        RewriteGateResult {
            allowed,
            passed_rules,
            blocking_defects,
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::bisimulation::{HsiOperation, ObservableSemantics, StopKind};

    // ====================================================================
    // Helper: build a simple two-state LTS
    // ====================================================================

    fn build_simple_lts(op: HsiOperation) -> ObservableSemantics {
        let mut lts = ObservableSemantics::new(0);
        let s1 = lts.add_state().unwrap();
        lts.add_transition(0, op, s1).unwrap();
        lts
    }

    fn build_spawn_execute_stop() -> ObservableSemantics {
        let mut lts = ObservableSemantics::new(0);
        let s1 = lts.add_state().unwrap();
        let s2 = lts.add_state().unwrap();
        let s3 = lts.add_state().unwrap();
        lts.add_transition(0, HsiOperation::Spawn { depth: 0 }, s1)
            .unwrap();
        lts.add_transition(
            s1,
            HsiOperation::Execute {
                output_tag: "result".to_string(),
            },
            s2,
        )
        .unwrap();
        lts.add_transition(
            s2,
            HsiOperation::Stop {
                kind: StopKind::GoalSatisfied,
            },
            s3,
        )
        .unwrap();
        lts
    }

    // ====================================================================
    // RewriteRule tests
    // ====================================================================

    #[test]
    fn test_rewrite_rule_creation() {
        let source = build_simple_lts(HsiOperation::Spawn { depth: 0 });
        let target = build_simple_lts(HsiOperation::Spawn { depth: 0 });

        let rule = RewriteRule::new(
            "R001".to_string(),
            "identity rewrite".to_string(),
            source,
            target,
        )
        .unwrap();

        assert_eq!(rule.id(), "R001");
        assert_eq!(rule.description(), "identity rewrite");
        assert_eq!(*rule.proof_status(), ProofStatus::Pending);
        assert!(!rule.is_verified());
    }

    #[test]
    fn test_rewrite_rule_id_too_long() {
        let source = ObservableSemantics::new(0);
        let target = ObservableSemantics::new(0);
        let long_id = "x".repeat(MAX_RULE_ID_LEN + 1);

        let result = RewriteRule::new(long_id, "test".to_string(), source, target);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            FunctorError::RuleIdTooLong { .. }
        ));
    }

    #[test]
    fn test_rewrite_rule_display() {
        let source = ObservableSemantics::new(0);
        let target = ObservableSemantics::new(0);

        let rule =
            RewriteRule::new("R001".to_string(), "test".to_string(), source, target).unwrap();

        let display = rule.to_string();
        assert!(display.contains("R001"));
        assert!(display.contains("test"));
        assert!(display.contains("PENDING"));
    }

    // ====================================================================
    // ProofStatus tests
    // ====================================================================

    #[test]
    fn test_proof_status_display() {
        let pending = ProofStatus::Pending;
        assert_eq!(pending.to_string(), "PENDING");

        let verified = ProofStatus::Verified {
            artifact_ref: "EVID-0022".to_string(),
        };
        assert_eq!(verified.to_string(), "VERIFIED(EVID-0022)");

        let rejected = ProofStatus::Rejected {
            reason: "law violated".to_string(),
        };
        assert_eq!(rejected.to_string(), "REJECTED(law violated)");
    }

    // ====================================================================
    // FunctorLawChecker tests
    // ====================================================================

    #[test]
    fn test_functor_law_checker_creation() {
        let checker = FunctorLawChecker::new().unwrap();
        assert!(checker.bisim_checker.max_depth() > 0);
    }

    #[test]
    fn test_functor_law_identity_rewrite_passes() {
        let checker = FunctorLawChecker::new().unwrap();

        // Identity rewrite: source == target (bisimilar by definition)
        let lts = build_spawn_execute_stop();
        let rule = RewriteRule::new(
            "identity".to_string(),
            "no-op rewrite".to_string(),
            lts.clone(),
            lts,
        )
        .unwrap();

        let result = checker.check_rule(&rule).unwrap();
        assert!(result.passed());
        assert!(result.violation().is_none());
        assert!(result.to_string().contains("PASS"));
    }

    #[test]
    fn test_functor_law_observing_rewrite_fails() {
        let checker = FunctorLawChecker::new().unwrap();

        // Rewrite that changes observable behavior: spawn -> execute
        let source = build_simple_lts(HsiOperation::Spawn { depth: 0 });
        let target = build_simple_lts(HsiOperation::Execute {
            output_tag: "changed".to_string(),
        });

        let rule = RewriteRule::new(
            "bad-rewrite".to_string(),
            "changes observables".to_string(),
            source,
            target,
        )
        .unwrap();

        let result = checker.check_rule(&rule).unwrap();
        assert!(!result.passed());
        assert!(result.violation().is_some());
        assert!(result.to_string().contains("FAIL"));
    }

    #[test]
    fn test_functor_law_structurally_different_fails() {
        let checker = FunctorLawChecker::new().unwrap();

        // Source has two transitions, target has one
        let mut source = ObservableSemantics::new(0);
        let s1 = source.add_state().unwrap();
        let s2 = source.add_state().unwrap();
        source
            .add_transition(0, HsiOperation::Spawn { depth: 0 }, s1)
            .unwrap();
        source
            .add_transition(
                0,
                HsiOperation::Execute {
                    output_tag: "extra".to_string(),
                },
                s2,
            )
            .unwrap();

        let target = build_simple_lts(HsiOperation::Spawn { depth: 0 });

        let rule = RewriteRule::new(
            "lossy-rewrite".to_string(),
            "drops an observable transition".to_string(),
            source,
            target,
        )
        .unwrap();

        let result = checker.check_rule(&rule).unwrap();
        assert!(!result.passed());
    }

    #[test]
    fn test_functor_law_check_rules_batch() {
        let checker = FunctorLawChecker::new().unwrap();

        let lts = build_spawn_execute_stop();
        let good_rule =
            RewriteRule::new("good".to_string(), "identity".to_string(), lts.clone(), lts).unwrap();

        let source = build_simple_lts(HsiOperation::Spawn { depth: 0 });
        let target = build_simple_lts(HsiOperation::Execute {
            output_tag: "changed".to_string(),
        });
        let bad_rule = RewriteRule::new(
            "bad".to_string(),
            "changes semantics".to_string(),
            source,
            target,
        )
        .unwrap();

        let results = checker.check_rules(&[good_rule, bad_rule]).unwrap();
        assert_eq!(results.len(), 2);
        assert!(results[0].passed());
        assert!(!results[1].passed());
    }

    #[test]
    fn test_functor_law_empty_lts_equivalent() {
        let checker = FunctorLawChecker::new().unwrap();

        let source = ObservableSemantics::new(0);
        let target = ObservableSemantics::new(0);

        let rule = RewriteRule::new(
            "empty".to_string(),
            "empty compositions".to_string(),
            source,
            target,
        )
        .unwrap();

        let result = checker.check_rule(&rule).unwrap();
        assert!(result.passed());
    }

    // ====================================================================
    // FunctorLawResult tests
    // ====================================================================

    #[test]
    fn test_functor_law_result_accessors() {
        let result = FunctorLawResult {
            rule_id: "R001".to_string(),
            passed: true,
            violation: None,
        };
        assert_eq!(result.rule_id(), "R001");
        assert!(result.passed());
        assert!(result.violation().is_none());

        let fail_result = FunctorLawResult {
            rule_id: "R002".to_string(),
            passed: false,
            violation: Some("divergence".to_string()),
        };
        assert!(!fail_result.passed());
        assert_eq!(fail_result.violation(), Some("divergence"));
    }

    // ====================================================================
    // AdmittedRewriteCatalog tests
    // ====================================================================

    #[test]
    fn test_catalog_creation() {
        let catalog = AdmittedRewriteCatalog::new().unwrap();
        assert_eq!(catalog.rule_count(), 0);
        assert_eq!(catalog.admitted_count(), 0);
        assert_eq!(catalog.pending_count(), 0);
    }

    #[test]
    fn test_catalog_register_rule() {
        let mut catalog = AdmittedRewriteCatalog::new().unwrap();

        let source = ObservableSemantics::new(0);
        let target = ObservableSemantics::new(0);
        let rule =
            RewriteRule::new("R001".to_string(), "test".to_string(), source, target).unwrap();

        catalog.register_rule(rule).unwrap();
        assert_eq!(catalog.rule_count(), 1);
        assert_eq!(catalog.pending_count(), 1);
        assert_eq!(catalog.admitted_count(), 0);
    }

    #[test]
    fn test_catalog_duplicate_rule_rejected() {
        let mut catalog = AdmittedRewriteCatalog::new().unwrap();

        let source = ObservableSemantics::new(0);
        let target = ObservableSemantics::new(0);
        let rule1 = RewriteRule::new(
            "R001".to_string(),
            "first".to_string(),
            source.clone(),
            target.clone(),
        )
        .unwrap();
        let rule2 =
            RewriteRule::new("R001".to_string(), "duplicate".to_string(), source, target).unwrap();

        catalog.register_rule(rule1).unwrap();
        let result = catalog.register_rule(rule2);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            FunctorError::DuplicateRule(_)
        ));
    }

    #[test]
    fn test_catalog_get_rule() {
        let mut catalog = AdmittedRewriteCatalog::new().unwrap();

        let source = ObservableSemantics::new(0);
        let target = ObservableSemantics::new(0);
        let rule =
            RewriteRule::new("R001".to_string(), "test".to_string(), source, target).unwrap();

        catalog.register_rule(rule).unwrap();

        let fetched = catalog.get_rule("R001");
        assert!(fetched.is_some());
        assert_eq!(fetched.unwrap().id(), "R001");

        assert!(catalog.get_rule("nonexistent").is_none());
    }

    #[test]
    fn test_catalog_submit_proof_verified() {
        let mut catalog = AdmittedRewriteCatalog::new().unwrap();

        // Register an identity rewrite (source == target, will pass law check)
        let lts = build_spawn_execute_stop();
        let rule =
            RewriteRule::new("R001".to_string(), "identity".to_string(), lts.clone(), lts).unwrap();

        catalog.register_rule(rule).unwrap();

        let result = catalog.submit_proof("R001", "EVID-0022").unwrap();
        assert!(result.passed());

        // Rule should now be verified
        let rule = catalog.get_rule("R001").unwrap();
        assert!(rule.is_verified());
        assert!(matches!(
            rule.proof_status(),
            ProofStatus::Verified { artifact_ref } if artifact_ref == "EVID-0022"
        ));

        assert_eq!(catalog.admitted_count(), 1);
        assert_eq!(catalog.pending_count(), 0);
    }

    #[test]
    fn test_catalog_submit_proof_rejected() {
        let mut catalog = AdmittedRewriteCatalog::new().unwrap();

        // Register a bad rewrite (changes observables, will fail law check)
        let source = build_simple_lts(HsiOperation::Spawn { depth: 0 });
        let target = build_simple_lts(HsiOperation::Execute {
            output_tag: "changed".to_string(),
        });
        let rule = RewriteRule::new(
            "R-bad".to_string(),
            "bad rewrite".to_string(),
            source,
            target,
        )
        .unwrap();

        catalog.register_rule(rule).unwrap();

        let result = catalog.submit_proof("R-bad", "EVID-fake").unwrap();
        assert!(!result.passed());

        // Rule should now be rejected
        let rule = catalog.get_rule("R-bad").unwrap();
        assert!(!rule.is_verified());
        assert!(matches!(rule.proof_status(), ProofStatus::Rejected { .. }));

        assert_eq!(catalog.admitted_count(), 0);
    }

    #[test]
    fn test_catalog_submit_proof_rule_not_found() {
        let mut catalog = AdmittedRewriteCatalog::new().unwrap();
        let result = catalog.submit_proof("nonexistent", "EVID-0022");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), FunctorError::RuleNotFound(_)));
    }

    #[test]
    fn test_catalog_submit_proof_ref_too_long() {
        let mut catalog = AdmittedRewriteCatalog::new().unwrap();

        let source = ObservableSemantics::new(0);
        let target = ObservableSemantics::new(0);
        let rule =
            RewriteRule::new("R001".to_string(), "test".to_string(), source, target).unwrap();
        catalog.register_rule(rule).unwrap();

        let long_ref = "x".repeat(MAX_PROOF_REF_LEN + 1);
        let result = catalog.submit_proof("R001", &long_ref);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            FunctorError::ProofRefTooLong { .. }
        ));
    }

    #[test]
    fn test_catalog_remove_rule() {
        let mut catalog = AdmittedRewriteCatalog::new().unwrap();

        let source = ObservableSemantics::new(0);
        let target = ObservableSemantics::new(0);
        let rule =
            RewriteRule::new("R001".to_string(), "test".to_string(), source, target).unwrap();

        catalog.register_rule(rule).unwrap();
        assert_eq!(catalog.rule_count(), 1);

        let removed = catalog.remove_rule("R001").unwrap();
        assert_eq!(removed.id(), "R001");
        assert_eq!(catalog.rule_count(), 0);
    }

    #[test]
    fn test_catalog_remove_rule_not_found() {
        let mut catalog = AdmittedRewriteCatalog::new().unwrap();
        let result = catalog.remove_rule("nonexistent");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), FunctorError::RuleNotFound(_)));
    }

    #[test]
    fn test_catalog_admitted_rules() {
        let mut catalog = AdmittedRewriteCatalog::new().unwrap();

        // Register two identity rewrites
        let lts = build_spawn_execute_stop();
        let rule1 = RewriteRule::new(
            "R001".to_string(),
            "first".to_string(),
            lts.clone(),
            lts.clone(),
        )
        .unwrap();
        let rule2 =
            RewriteRule::new("R002".to_string(), "second".to_string(), lts.clone(), lts).unwrap();

        catalog.register_rule(rule1).unwrap();
        catalog.register_rule(rule2).unwrap();

        // Verify only R001
        catalog.submit_proof("R001", "EVID-0022").unwrap();

        let admitted = catalog.admitted_rules();
        assert_eq!(admitted.len(), 1);
        assert_eq!(admitted[0].id(), "R001");
    }

    #[test]
    fn test_catalog_all_rules() {
        let mut catalog = AdmittedRewriteCatalog::new().unwrap();

        let source = ObservableSemantics::new(0);
        let target = ObservableSemantics::new(0);

        let rule1 = RewriteRule::new(
            "R001".to_string(),
            "first".to_string(),
            source.clone(),
            target.clone(),
        )
        .unwrap();
        let rule2 =
            RewriteRule::new("R002".to_string(), "second".to_string(), source, target).unwrap();

        catalog.register_rule(rule1).unwrap();
        catalog.register_rule(rule2).unwrap();

        let all = catalog.all_rules();
        assert_eq!(all.len(), 2);
    }

    // ====================================================================
    // RewritePromotionGate tests
    // ====================================================================

    #[test]
    fn test_promotion_gate_strict_creation() {
        let gate = RewritePromotionGate::new();
        assert!(gate.is_strict());
    }

    #[test]
    fn test_promotion_gate_non_strict() {
        let gate = RewritePromotionGate::with_strictness(false);
        assert!(!gate.is_strict());
    }

    #[test]
    fn test_promotion_gate_empty_catalog_passes() {
        let gate = RewritePromotionGate::new();
        let catalog = AdmittedRewriteCatalog::new().unwrap();

        let result = gate.evaluate(&catalog);
        assert!(result.allowed());
        assert!(result.blocking_defects().is_empty());
        assert!(result.passed_rules().is_empty());
    }

    #[test]
    fn test_promotion_gate_all_verified_passes() {
        let gate = RewritePromotionGate::new();
        let mut catalog = AdmittedRewriteCatalog::new().unwrap();

        let lts = build_spawn_execute_stop();
        let rule =
            RewriteRule::new("R001".to_string(), "identity".to_string(), lts.clone(), lts).unwrap();
        catalog.register_rule(rule).unwrap();
        catalog.submit_proof("R001", "EVID-0022").unwrap();

        let result = gate.evaluate(&catalog);
        assert!(result.allowed());
        assert_eq!(result.passed_rules().len(), 1);
        assert!(result.blocking_defects().is_empty());
        assert!(result.to_string().contains("PASS"));
    }

    #[test]
    fn test_promotion_gate_strict_blocks_pending() {
        let gate = RewritePromotionGate::new();
        let mut catalog = AdmittedRewriteCatalog::new().unwrap();

        let source = ObservableSemantics::new(0);
        let target = ObservableSemantics::new(0);
        let rule =
            RewriteRule::new("R001".to_string(), "pending".to_string(), source, target).unwrap();
        catalog.register_rule(rule).unwrap();

        let result = gate.evaluate(&catalog);
        assert!(!result.allowed());
        assert_eq!(result.blocking_defects().len(), 1);
        assert_eq!(
            result.blocking_defects()[0].kind,
            RewriteDefectKind::NoProof
        );
        assert!(result.to_string().contains("FAIL"));
    }

    #[test]
    fn test_promotion_gate_non_strict_allows_pending() {
        let gate = RewritePromotionGate::with_strictness(false);
        let mut catalog = AdmittedRewriteCatalog::new().unwrap();

        let source = ObservableSemantics::new(0);
        let target = ObservableSemantics::new(0);
        let rule =
            RewriteRule::new("R001".to_string(), "pending".to_string(), source, target).unwrap();
        catalog.register_rule(rule).unwrap();

        let result = gate.evaluate(&catalog);
        assert!(result.allowed());
        assert_eq!(result.passed_rules().len(), 1);
    }

    #[test]
    fn test_promotion_gate_blocks_rejected() {
        let gate = RewritePromotionGate::new();
        let mut catalog = AdmittedRewriteCatalog::new().unwrap();

        // Register a bad rewrite that will be rejected
        let source = build_simple_lts(HsiOperation::Spawn { depth: 0 });
        let target = build_simple_lts(HsiOperation::Execute {
            output_tag: "changed".to_string(),
        });
        let rule = RewriteRule::new(
            "R-bad".to_string(),
            "bad rewrite".to_string(),
            source,
            target,
        )
        .unwrap();
        catalog.register_rule(rule).unwrap();
        catalog.submit_proof("R-bad", "EVID-fake").unwrap();

        let result = gate.evaluate(&catalog);
        assert!(!result.allowed());
        assert_eq!(result.blocking_defects().len(), 1);
        assert_eq!(
            result.blocking_defects()[0].kind,
            RewriteDefectKind::ProofRejected
        );
    }

    #[test]
    fn test_promotion_gate_non_strict_also_blocks_rejected() {
        let gate = RewritePromotionGate::with_strictness(false);
        let mut catalog = AdmittedRewriteCatalog::new().unwrap();

        let source = build_simple_lts(HsiOperation::Spawn { depth: 0 });
        let target = build_simple_lts(HsiOperation::Execute {
            output_tag: "changed".to_string(),
        });
        let rule = RewriteRule::new(
            "R-bad".to_string(),
            "bad rewrite".to_string(),
            source,
            target,
        )
        .unwrap();
        catalog.register_rule(rule).unwrap();
        catalog.submit_proof("R-bad", "EVID-fake").unwrap();

        let result = gate.evaluate(&catalog);
        assert!(
            !result.allowed(),
            "Even non-strict mode must block rejected proofs"
        );
    }

    #[test]
    fn test_promotion_gate_mixed_rules() {
        let gate = RewritePromotionGate::new();
        let mut catalog = AdmittedRewriteCatalog::new().unwrap();

        // Good rule (will be verified)
        let lts = build_spawn_execute_stop();
        let good_rule = RewriteRule::new(
            "R-good".to_string(),
            "identity".to_string(),
            lts.clone(),
            lts,
        )
        .unwrap();
        catalog.register_rule(good_rule).unwrap();
        catalog.submit_proof("R-good", "EVID-0022").unwrap();

        // Pending rule (will block in strict mode)
        let source = ObservableSemantics::new(0);
        let target = ObservableSemantics::new(0);
        let pending_rule = RewriteRule::new(
            "R-pending".to_string(),
            "pending".to_string(),
            source,
            target,
        )
        .unwrap();
        catalog.register_rule(pending_rule).unwrap();

        let result = gate.evaluate(&catalog);
        assert!(!result.allowed());
        assert_eq!(result.passed_rules().len(), 1);
        assert_eq!(result.blocking_defects().len(), 1);
    }

    // ====================================================================
    // DoD: Admitted rewrite catalog references proof obligations
    // ====================================================================

    #[test]
    fn test_dod_catalog_references_proof_obligations() {
        let mut catalog = AdmittedRewriteCatalog::new().unwrap();

        let lts = build_spawn_execute_stop();
        let rule =
            RewriteRule::new("R001".to_string(), "identity".to_string(), lts.clone(), lts).unwrap();
        catalog.register_rule(rule).unwrap();

        // Submit proof with artifact reference
        catalog.submit_proof("R001", "EVID-0022").unwrap();

        // Verify the catalog references the proof obligation
        let rule = catalog.get_rule("R001").unwrap();
        match rule.proof_status() {
            ProofStatus::Verified { artifact_ref } => {
                assert_eq!(artifact_ref, "EVID-0022");
            },
            other => panic!("expected Verified, got {other}"),
        }
    }

    // ====================================================================
    // DoD: Non-proven rewrites blocked from release pipelines
    // ====================================================================

    #[test]
    fn test_dod_non_proven_rewrites_blocked() {
        let gate = RewritePromotionGate::new();
        let mut catalog = AdmittedRewriteCatalog::new().unwrap();

        // Register a rule without submitting proof
        let source = ObservableSemantics::new(0);
        let target = ObservableSemantics::new(0);
        let rule = RewriteRule::new(
            "R-unproven".to_string(),
            "unproven rewrite".to_string(),
            source,
            target,
        )
        .unwrap();
        catalog.register_rule(rule).unwrap();

        // Strict gate must block
        let result = gate.evaluate(&catalog);
        assert!(
            !result.allowed(),
            "Non-proven rewrites must be blocked from release pipelines"
        );
        assert!(
            !result.blocking_defects().is_empty(),
            "Blocking defects must be emitted for non-proven rewrites"
        );
    }

    // ====================================================================
    // DoD: Optimization does not change observable HSI truth semantics
    // ====================================================================

    #[test]
    fn test_dod_optimization_preserves_hsi_truth_semantics() {
        let checker = FunctorLawChecker::new().unwrap();

        // An optimization that preserves observable behavior
        let lts = build_spawn_execute_stop();
        let preserving_rule = RewriteRule::new(
            "R-preserving".to_string(),
            "preserves observations".to_string(),
            lts.clone(),
            lts,
        )
        .unwrap();

        let result = checker.check_rule(&preserving_rule).unwrap();
        assert!(
            result.passed(),
            "Observation-preserving rewrites must pass the functorial law"
        );

        // An optimization that changes observable behavior
        let source = build_spawn_execute_stop();
        let mut bad_target = ObservableSemantics::new(0);
        let s1 = bad_target.add_state().unwrap();
        bad_target
            .add_transition(0, HsiOperation::Spawn { depth: 0 }, s1)
            .unwrap();
        // Missing execute and stop transitions -- observation changed

        let violating_rule = RewriteRule::new(
            "R-violating".to_string(),
            "changes observations".to_string(),
            source,
            bad_target,
        )
        .unwrap();

        let result = checker.check_rule(&violating_rule).unwrap();
        assert!(
            !result.passed(),
            "Observation-changing rewrites must fail the functorial law"
        );
    }

    // ====================================================================
    // Error variant tests
    // ====================================================================

    #[test]
    fn test_error_display() {
        let err = FunctorError::RuleIdTooLong { len: 200, max: 128 };
        assert!(err.to_string().contains("200"));
        assert!(err.to_string().contains("128"));

        let err = FunctorError::ProofRefTooLong { len: 300, max: 256 };
        assert!(err.to_string().contains("300"));

        let err = FunctorError::CatalogFull {
            count: 256,
            max: 256,
        };
        assert!(err.to_string().contains("256"));

        let err = FunctorError::DuplicateRule("R001".to_string());
        assert!(err.to_string().contains("R001"));

        let err = FunctorError::RuleNotFound("R999".to_string());
        assert!(err.to_string().contains("R999"));

        let err = FunctorError::LawViolation {
            rule_id: "R001".to_string(),
            description: "divergence".to_string(),
        };
        assert!(err.to_string().contains("divergence"));

        let err = FunctorError::TooManyObservationPoints {
            count: 100,
            max: 64,
        };
        assert!(err.to_string().contains("100"));

        let err = FunctorError::NoProofObligation {
            rule_id: "R001".to_string(),
        };
        assert!(err.to_string().contains("R001"));
    }

    // ====================================================================
    // RewriteBlockingDefect display test
    // ====================================================================

    #[test]
    fn test_rewrite_blocking_defect_display() {
        let defect = RewriteBlockingDefect {
            rule_id: "R001".to_string(),
            kind: RewriteDefectKind::NoProof,
            description: "missing proof".to_string(),
        };
        let display = defect.to_string();
        assert!(display.contains("BLOCKING DEFECT"));
        assert!(display.contains("R001"));
        assert!(display.contains("missing proof"));
    }

    // ====================================================================
    // RewriteGateResult display and accessor tests
    // ====================================================================

    #[test]
    fn test_rewrite_gate_result_accessors() {
        let result = RewriteGateResult {
            allowed: true,
            passed_rules: vec!["R001".to_string()],
            blocking_defects: vec![],
        };

        assert!(result.allowed());
        assert_eq!(result.passed_rules().len(), 1);
        assert!(result.blocking_defects().is_empty());
    }

    // ====================================================================
    // Catalog capacity test
    // ====================================================================

    #[test]
    fn test_catalog_capacity_limit() {
        let mut catalog = AdmittedRewriteCatalog::new().unwrap();

        for i in 0..MAX_CATALOG_RULES {
            let source = ObservableSemantics::new(0);
            let target = ObservableSemantics::new(0);
            let rule =
                RewriteRule::new(format!("R{i:04}"), format!("rule {i}"), source, target).unwrap();
            catalog.register_rule(rule).unwrap();
        }

        assert_eq!(catalog.rule_count(), MAX_CATALOG_RULES);

        // One more should fail
        let source = ObservableSemantics::new(0);
        let target = ObservableSemantics::new(0);
        let overflow_rule = RewriteRule::new(
            "R-overflow".to_string(),
            "overflow".to_string(),
            source,
            target,
        )
        .unwrap();

        let result = catalog.register_rule(overflow_rule);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            FunctorError::CatalogFull { .. }
        ));
    }
}
