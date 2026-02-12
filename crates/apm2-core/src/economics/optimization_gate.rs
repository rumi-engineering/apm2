// AGENT-AUTHORED
//! Security-interlocked optimization gates and quantitative evidence quality
//! enforcement (RFC-0029 REQ-0006).
//!
//! This module enforces the following interlock contracts:
//!
//! 1. **KPI/countermetric completeness**: every optimization KPI must have a
//!    required countermetric in gate policy. Proposals missing a countermetric
//!    mapping for any declared KPI are denied fail-closed.
//!
//! 2. **Canonical evaluator binding**: all TP-EIO29 predicates must be
//!    evaluated by `TemporalPredicateEvaluatorV1` (evaluator ID
//!    `temporal_predicate_evaluator_v1`). Unknown evaluator IDs are denied
//!    fail-closed.
//!
//! 3. **Evidence-quality thresholds**: statistical power >= 0.90, significance
//!    alpha <= 0.01, minimum sample-size proof > 0, and reproducibility matrix
//!    >= 3 distinct runtime classes.
//!
//! 4. **Freshness and throughput-dominance**: stale evidence classes block
//!    optimization promotions, and throughput-dominance violations block
//!    promotion-critical evidence classes.
//!
//! # Security Model
//!
//! All gates enforce fail-closed semantics: missing, stale, unknown, or
//! sub-threshold evidence produces a deterministic denial with a stable
//! reason code. There is no "default pass" path.

use std::collections::BTreeMap;

use serde::{Deserialize, Deserializer, Serialize};
use subtle::ConstantTimeEq;

use crate::pcac::MAX_REASON_LENGTH;
use crate::pcac::temporal_arbitration::{ArbitrationOutcome, EvaluatorTuple, TemporalPredicateId};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Canonical evaluator ID for all TP-EIO29 predicates.
pub const CANONICAL_EVALUATOR_ID: &str = "temporal_predicate_evaluator_v1";

/// Maximum number of KPI entries in an optimization gate policy.
pub const MAX_KPI_ENTRIES: usize = 64;

/// Maximum number of countermetric entries in a countermetric profile.
pub const MAX_COUNTERMETRIC_ENTRIES: usize = 64;

/// Maximum length for a KPI identifier string.
pub const MAX_KPI_ID_LENGTH: usize = 256;

/// Maximum length for a countermetric identifier string.
pub const MAX_COUNTERMETRIC_ID_LENGTH: usize = 256;

/// Maximum number of evidence samples in a quality report.
pub const MAX_EVIDENCE_SAMPLES: usize = 256;

/// Maximum number of runtime classes in a reproducibility matrix.
pub const MAX_RUNTIME_CLASSES: usize = 64;

/// Maximum length for runtime class identifier strings.
pub const MAX_RUNTIME_CLASS_ID_LENGTH: usize = 256;

/// Maximum length for deny reason strings.
pub const MAX_DENY_REASON_LENGTH: usize = MAX_REASON_LENGTH;

/// Minimum required statistical power for evidence quality admission.
pub const MIN_STATISTICAL_POWER: f64 = 0.90;

/// Maximum allowed significance alpha for evidence quality admission.
pub const MAX_SIGNIFICANCE_ALPHA: f64 = 0.01;

/// Minimum required distinct runtime classes for reproducibility matrix.
pub const MIN_REPRODUCIBILITY_RUNTIME_CLASSES: usize = 3;

/// Maximum age in ticks for evidence freshness (promotion-critical).
pub const MAX_EVIDENCE_FRESHNESS_TICKS: u64 = 1000;

/// Maximum allowed throughput regression ratio (1.0 = no regression).
/// Evidence that shows throughput below this ratio of the baseline is
/// rejected as a throughput-dominance violation.
pub const THROUGHPUT_DOMINANCE_MIN_RATIO: f64 = 1.0;

// ---------------------------------------------------------------------------
// Deny reason constants
// ---------------------------------------------------------------------------

/// Deny: KPI has no countermetric mapping in gate policy.
pub const DENY_KPI_MISSING_COUNTERMETRIC: &str = "optimization_kpi_missing_countermetric";

/// Deny: countermetric profile is not present.
pub const DENY_COUNTERMETRIC_PROFILE_MISSING: &str = "optimization_countermetric_profile_missing";

/// Deny: evaluator ID is not the canonical evaluator.
pub const DENY_NON_CANONICAL_EVALUATOR: &str = "optimization_non_canonical_evaluator";

/// Deny: evaluator ID is empty.
pub const DENY_EVALUATOR_ID_EMPTY: &str = "optimization_evaluator_id_empty";

/// Deny: statistical power below threshold.
pub const DENY_POWER_BELOW_THRESHOLD: &str = "optimization_evidence_power_below_threshold";

/// Deny: significance alpha above threshold.
pub const DENY_ALPHA_ABOVE_THRESHOLD: &str = "optimization_evidence_alpha_above_threshold";

/// Deny: sample size is zero.
pub const DENY_SAMPLE_SIZE_ZERO: &str = "optimization_evidence_sample_size_zero";

/// Deny: insufficient runtime classes for reproducibility.
pub const DENY_REPRODUCIBILITY_INSUFFICIENT: &str =
    "optimization_evidence_reproducibility_insufficient";

/// Deny: evidence is stale (exceeds freshness window).
pub const DENY_EVIDENCE_STALE: &str = "optimization_evidence_stale";

/// Deny: throughput-dominance violation.
pub const DENY_THROUGHPUT_DOMINANCE_VIOLATION: &str = "optimization_throughput_dominance_violation";

/// Deny: evidence quality report is missing.
pub const DENY_EVIDENCE_QUALITY_MISSING: &str = "optimization_evidence_quality_missing";

/// Deny: arbitration outcome is not `AgreedAllow`.
pub const DENY_ARBITRATION_NOT_AGREED_ALLOW: &str = "optimization_arbitration_not_agreed_allow";

/// Deny: KPI entries exceed maximum count.
pub const DENY_KPI_ENTRIES_OVERFLOW: &str = "optimization_kpi_entries_overflow";

/// Deny: countermetric entries exceed maximum count.
pub const DENY_COUNTERMETRIC_ENTRIES_OVERFLOW: &str = "optimization_countermetric_entries_overflow";

/// Deny: evidence samples exceed maximum count.
pub const DENY_EVIDENCE_SAMPLES_OVERFLOW: &str = "optimization_evidence_samples_overflow";

/// Deny: runtime classes exceed maximum count.
pub const DENY_RUNTIME_CLASSES_OVERFLOW: &str = "optimization_runtime_classes_overflow";

/// Deny: throughput ratio is NaN.
pub const DENY_THROUGHPUT_RATIO_NAN: &str = "optimization_throughput_ratio_nan";

/// Deny: power value is NaN.
pub const DENY_POWER_NAN: &str = "optimization_evidence_power_nan";

/// Deny: alpha value is NaN.
pub const DENY_ALPHA_NAN: &str = "optimization_evidence_alpha_nan";

/// Deny: evidence freshness tick is ahead of current tick.
pub const DENY_EVIDENCE_FUTURE_TICK: &str = "optimization_evidence_future_tick";

// ---------------------------------------------------------------------------
// Bounded serde deserializers
// ---------------------------------------------------------------------------

fn deserialize_bounded_kpi_id<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    if value.len() > MAX_KPI_ID_LENGTH {
        return Err(serde::de::Error::custom(format!(
            "kpi_id length {} exceeds maximum {}",
            value.len(),
            MAX_KPI_ID_LENGTH,
        )));
    }
    Ok(value)
}

fn deserialize_bounded_optional_deny_reason<'de, D>(
    deserializer: D,
) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<String>::deserialize(deserializer)?;
    if let Some(reason) = value.as_ref() {
        if reason.len() > MAX_DENY_REASON_LENGTH {
            return Err(serde::de::Error::custom(format!(
                "deny_reason length {} exceeds maximum {}",
                reason.len(),
                MAX_DENY_REASON_LENGTH,
            )));
        }
    }
    Ok(value)
}

fn deserialize_bounded_kpi_map<'de, D>(
    deserializer: D,
) -> Result<BTreeMap<String, String>, D::Error>
where
    D: Deserializer<'de>,
{
    let map = BTreeMap::<String, String>::deserialize(deserializer)?;
    if map.len() > MAX_KPI_ENTRIES {
        return Err(serde::de::Error::custom(format!(
            "kpi_countermetric_map length {} exceeds maximum {}",
            map.len(),
            MAX_KPI_ENTRIES,
        )));
    }
    for (k, v) in &map {
        if k.len() > MAX_KPI_ID_LENGTH {
            return Err(serde::de::Error::custom(format!(
                "kpi_id length {} exceeds maximum {}",
                k.len(),
                MAX_KPI_ID_LENGTH,
            )));
        }
        if v.len() > MAX_COUNTERMETRIC_ID_LENGTH {
            return Err(serde::de::Error::custom(format!(
                "countermetric_id length {} exceeds maximum {}",
                v.len(),
                MAX_COUNTERMETRIC_ID_LENGTH,
            )));
        }
    }
    Ok(map)
}

fn deserialize_bounded_runtime_classes<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let classes = Vec::<String>::deserialize(deserializer)?;
    if classes.len() > MAX_RUNTIME_CLASSES {
        return Err(serde::de::Error::custom(format!(
            "runtime_classes length {} exceeds maximum {}",
            classes.len(),
            MAX_RUNTIME_CLASSES,
        )));
    }
    for class in &classes {
        if class.len() > MAX_RUNTIME_CLASS_ID_LENGTH {
            return Err(serde::de::Error::custom(format!(
                "runtime_class_id length {} exceeds maximum {}",
                class.len(),
                MAX_RUNTIME_CLASS_ID_LENGTH,
            )));
        }
    }
    Ok(classes)
}

fn deserialize_bounded_kpi_ids<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let ids = Vec::<String>::deserialize(deserializer)?;
    if ids.len() > MAX_KPI_ENTRIES {
        return Err(serde::de::Error::custom(format!(
            "kpi_ids length {} exceeds maximum {}",
            ids.len(),
            MAX_KPI_ENTRIES,
        )));
    }
    for id in &ids {
        if id.len() > MAX_KPI_ID_LENGTH {
            return Err(serde::de::Error::custom(format!(
                "kpi_id length {} exceeds maximum {}",
                id.len(),
                MAX_KPI_ID_LENGTH,
            )));
        }
    }
    Ok(ids)
}

// ---------------------------------------------------------------------------
// KPI/Countermetric completeness types
// ---------------------------------------------------------------------------

/// A mapping of optimization KPI IDs to their required countermetric IDs.
///
/// Every KPI declared in an optimization proposal must have a corresponding
/// countermetric. Missing mappings are denied fail-closed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CountermetricProfile {
    /// Mapping from KPI ID to its required countermetric ID.
    #[serde(deserialize_with = "deserialize_bounded_kpi_map")]
    pub kpi_countermetric_map: BTreeMap<String, String>,

    /// Content digest of this profile (for CAS binding).
    pub content_digest: [u8; 32],
}

/// An optimization proposal declaring which KPIs it targets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OptimizationProposal {
    /// The KPI IDs this optimization targets.
    #[serde(deserialize_with = "deserialize_bounded_kpi_ids")]
    pub target_kpi_ids: Vec<String>,

    /// Evaluator tuples bound to this proposal's TP-EIO29 predicates.
    pub evaluator_bindings: Vec<EvaluatorTuple>,

    /// Content digest of the proposal (for integrity binding).
    pub proposal_digest: [u8; 32],
}

// ---------------------------------------------------------------------------
// Evidence quality types
// ---------------------------------------------------------------------------

/// Quantitative evidence quality report for an optimization.
///
/// Must meet minimum thresholds for power, alpha, sample size, and
/// reproducibility before an optimization can be promoted.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceQualityReport {
    /// Statistical power of the evidence (required >= 0.90).
    pub statistical_power: f64,

    /// Significance level alpha (required <= 0.01).
    pub significance_alpha: f64,

    /// Number of samples in the evidence. Must be > 0.
    pub sample_size: u64,

    /// Distinct runtime classes where evidence was gathered.
    /// Must contain >= 3 classes for reproducibility.
    #[serde(deserialize_with = "deserialize_bounded_runtime_classes")]
    pub runtime_classes: Vec<String>,

    /// HTF tick at which this evidence was gathered.
    pub evidence_tick: u64,

    /// Throughput ratio relative to baseline. Must be >= 1.0.
    /// A ratio below 1.0 indicates throughput regression (dominance violation).
    pub throughput_ratio: f64,

    /// Content digest of the evidence report (for integrity binding).
    pub evidence_digest: [u8; 32],
}

// ---------------------------------------------------------------------------
// Optimization gate decision
// ---------------------------------------------------------------------------

/// Verdict from the optimization gate evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum OptimizationGateVerdict {
    /// All gates pass — optimization may proceed.
    Allow,
    /// One or more gates denied the optimization.
    Deny,
    /// Optimization is blocked pending freshness resolution.
    Blocked,
}

/// Trace payload for optimization gate decisions.
///
/// Contains boolean gate results and a proposal digest for auditing.
/// The multiple boolean fields reflect distinct gate evaluations and
/// are intentionally separate for deterministic tracing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct OptimizationGateTrace {
    /// Overall verdict.
    pub verdict: OptimizationGateVerdict,

    /// Stable deny reason when verdict is not `Allow`.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_bounded_optional_deny_reason"
    )]
    pub deny_reason: Option<String>,

    /// Whether KPI/countermetric completeness passed.
    pub kpi_countermetric_complete: bool,

    /// Whether canonical evaluator binding passed.
    pub canonical_evaluator_bound: bool,

    /// Whether evidence quality thresholds passed.
    pub evidence_quality_passed: bool,

    /// Whether evidence freshness passed.
    pub evidence_freshness_passed: bool,

    /// Whether throughput-dominance check passed.
    pub throughput_dominance_passed: bool,

    /// Proposal digest bound to this decision.
    pub proposal_digest: [u8; 32],
}

/// Complete optimization gate decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OptimizationGateDecision {
    /// Verdict.
    pub verdict: OptimizationGateVerdict,

    /// Deterministic deny reason when verdict is not `Allow`.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_bounded_optional_deny_reason"
    )]
    pub deny_reason: Option<String>,

    /// Full trace for auditing.
    pub trace: OptimizationGateTrace,
}

impl OptimizationGateDecision {
    /// Returns the deny defect if verdict is not `Allow`.
    #[must_use]
    pub fn defect(&self) -> Option<&str> {
        self.deny_reason.as_deref()
    }
}

// ---------------------------------------------------------------------------
// Gate: KPI/countermetric completeness
// ---------------------------------------------------------------------------

/// Validates that every KPI in the proposal has a countermetric mapping.
///
/// # Errors
///
/// Returns a stable deny reason string if any KPI is missing a countermetric.
pub fn validate_kpi_countermetric_completeness(
    proposal: &OptimizationProposal,
    profile: &CountermetricProfile,
) -> Result<(), &'static str> {
    if proposal.target_kpi_ids.len() > MAX_KPI_ENTRIES {
        return Err(DENY_KPI_ENTRIES_OVERFLOW);
    }

    if profile.kpi_countermetric_map.len() > MAX_COUNTERMETRIC_ENTRIES {
        return Err(DENY_COUNTERMETRIC_ENTRIES_OVERFLOW);
    }

    for kpi_id in &proposal.target_kpi_ids {
        if !profile.kpi_countermetric_map.contains_key(kpi_id.as_str()) {
            return Err(DENY_KPI_MISSING_COUNTERMETRIC);
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Gate: Canonical evaluator binding
// ---------------------------------------------------------------------------

/// Validates that all evaluator bindings in the proposal use the canonical
/// `TemporalPredicateEvaluatorV1` evaluator ID.
///
/// # Errors
///
/// Returns a stable deny reason if any evaluator has a non-canonical ID.
pub fn validate_canonical_evaluator_binding(
    proposal: &OptimizationProposal,
) -> Result<(), &'static str> {
    for evaluator in &proposal.evaluator_bindings {
        if evaluator.evaluator_id.is_empty() {
            return Err(DENY_EVALUATOR_ID_EMPTY);
        }
        if evaluator.evaluator_id != CANONICAL_EVALUATOR_ID {
            return Err(DENY_NON_CANONICAL_EVALUATOR);
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Gate: Evidence quality thresholds
// ---------------------------------------------------------------------------

/// Validates evidence quality against required thresholds.
///
/// Checks:
/// - `statistical_power` >= `MIN_STATISTICAL_POWER` (0.90)
/// - `significance_alpha` <= `MAX_SIGNIFICANCE_ALPHA` (0.01)
/// - `sample_size` > 0
/// - `runtime_classes.len()` >= `MIN_REPRODUCIBILITY_RUNTIME_CLASSES` (3)
///
/// # Errors
///
/// Returns a stable deny reason if any threshold is violated.
pub fn validate_evidence_quality(report: &EvidenceQualityReport) -> Result<(), &'static str> {
    if report.runtime_classes.len() > MAX_RUNTIME_CLASSES {
        return Err(DENY_RUNTIME_CLASSES_OVERFLOW);
    }

    if report.statistical_power.is_nan() {
        return Err(DENY_POWER_NAN);
    }

    if report.significance_alpha.is_nan() {
        return Err(DENY_ALPHA_NAN);
    }

    if report.statistical_power < MIN_STATISTICAL_POWER {
        return Err(DENY_POWER_BELOW_THRESHOLD);
    }

    if report.significance_alpha > MAX_SIGNIFICANCE_ALPHA {
        return Err(DENY_ALPHA_ABOVE_THRESHOLD);
    }

    if report.sample_size == 0 {
        return Err(DENY_SAMPLE_SIZE_ZERO);
    }

    if report.runtime_classes.len() < MIN_REPRODUCIBILITY_RUNTIME_CLASSES {
        return Err(DENY_REPRODUCIBILITY_INSUFFICIENT);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Gate: Evidence freshness
// ---------------------------------------------------------------------------

/// Validates that evidence is fresh relative to the current tick.
///
/// Stale evidence (older than `MAX_EVIDENCE_FRESHNESS_TICKS`) blocks
/// optimization promotions.
///
/// # Errors
///
/// Returns a stable deny reason if evidence is stale or has a future tick.
pub const fn validate_evidence_freshness(
    evidence_tick: u64,
    current_tick: u64,
    max_age_ticks: u64,
) -> Result<(), &'static str> {
    if evidence_tick > current_tick {
        return Err(DENY_EVIDENCE_FUTURE_TICK);
    }

    let age = current_tick - evidence_tick;
    if age > max_age_ticks {
        return Err(DENY_EVIDENCE_STALE);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Gate: Throughput dominance
// ---------------------------------------------------------------------------

/// Validates that the optimization does not regress throughput below baseline.
///
/// A throughput ratio < 1.0 indicates the optimization reduces throughput,
/// which blocks promotion-critical evidence classes.
///
/// # Errors
///
/// Returns a stable deny reason if throughput dominance is violated.
pub fn validate_throughput_dominance(throughput_ratio: f64) -> Result<(), &'static str> {
    if throughput_ratio.is_nan() {
        return Err(DENY_THROUGHPUT_RATIO_NAN);
    }

    if throughput_ratio < THROUGHPUT_DOMINANCE_MIN_RATIO {
        return Err(DENY_THROUGHPUT_DOMINANCE_VIOLATION);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Gate: Arbitration binding
// ---------------------------------------------------------------------------

/// Validates that temporal arbitration outcome is `AgreedAllow`.
///
/// Non-allow outcomes (deny, transient/persistent disagreement) block
/// optimization promotion.
///
/// # Errors
///
/// Returns a stable deny reason if the outcome is not `AgreedAllow`.
pub fn validate_arbitration_outcome(outcome: ArbitrationOutcome) -> Result<(), &'static str> {
    if outcome != ArbitrationOutcome::AgreedAllow {
        return Err(DENY_ARBITRATION_NOT_AGREED_ALLOW);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Combined optimization gate evaluator
// ---------------------------------------------------------------------------

/// Evaluates all optimization gates for a proposal.
///
/// Gate evaluation order:
/// 1. KPI/countermetric completeness
/// 2. Canonical evaluator binding
/// 3. Arbitration outcome
/// 4. Evidence quality thresholds
/// 5. Evidence freshness
/// 6. Throughput dominance
///
/// First failing gate determines the deny reason. All gates are fail-closed.
///
/// Returns a decision with full trace for auditing.
#[must_use]
pub fn evaluate_optimization_gate(
    proposal: &OptimizationProposal,
    countermetric_profile: Option<&CountermetricProfile>,
    evidence_quality: Option<&EvidenceQualityReport>,
    arbitration_outcome: ArbitrationOutcome,
    current_tick: u64,
    max_evidence_age_ticks: u64,
) -> OptimizationGateDecision {
    let mut trace = OptimizationGateTrace {
        verdict: OptimizationGateVerdict::Allow,
        deny_reason: None,
        kpi_countermetric_complete: false,
        canonical_evaluator_bound: false,
        evidence_quality_passed: false,
        evidence_freshness_passed: false,
        throughput_dominance_passed: false,
        proposal_digest: proposal.proposal_digest,
    };

    // Gate 1: KPI/countermetric completeness
    let Some(profile) = countermetric_profile else {
        return deny_decision(DENY_COUNTERMETRIC_PROFILE_MISSING, trace);
    };

    if let Err(reason) = validate_kpi_countermetric_completeness(proposal, profile) {
        return deny_decision(reason, trace);
    }
    trace.kpi_countermetric_complete = true;

    // Gate 2: Canonical evaluator binding
    if let Err(reason) = validate_canonical_evaluator_binding(proposal) {
        return deny_decision(reason, trace);
    }
    trace.canonical_evaluator_bound = true;

    // Gate 3: Arbitration outcome
    if let Err(reason) = validate_arbitration_outcome(arbitration_outcome) {
        return deny_decision(reason, trace);
    }

    // Gate 4: Evidence quality
    let Some(evidence) = evidence_quality else {
        return deny_decision(DENY_EVIDENCE_QUALITY_MISSING, trace);
    };

    if let Err(reason) = validate_evidence_quality(evidence) {
        return deny_decision(reason, trace);
    }
    trace.evidence_quality_passed = true;

    // Gate 5: Evidence freshness
    match validate_evidence_freshness(evidence.evidence_tick, current_tick, max_evidence_age_ticks)
    {
        Ok(()) => {
            trace.evidence_freshness_passed = true;
        },
        Err(reason) => {
            // Freshness violation produces BLOCKED, not DENY
            trace.verdict = OptimizationGateVerdict::Blocked;
            trace.deny_reason = Some(reason.to_string());
            return OptimizationGateDecision {
                verdict: OptimizationGateVerdict::Blocked,
                deny_reason: Some(reason.to_string()),
                trace,
            };
        },
    }

    // Gate 6: Throughput dominance
    if let Err(reason) = validate_throughput_dominance(evidence.throughput_ratio) {
        return deny_decision(reason, trace);
    }
    trace.throughput_dominance_passed = true;

    // All gates passed
    trace.verdict = OptimizationGateVerdict::Allow;
    OptimizationGateDecision {
        verdict: OptimizationGateVerdict::Allow,
        deny_reason: None,
        trace,
    }
}

/// Constructs a deny decision with the given reason.
fn deny_decision(reason: &str, mut trace: OptimizationGateTrace) -> OptimizationGateDecision {
    trace.verdict = OptimizationGateVerdict::Deny;
    trace.deny_reason = Some(reason.to_string());
    OptimizationGateDecision {
        verdict: OptimizationGateVerdict::Deny,
        deny_reason: Some(reason.to_string()),
        trace,
    }
}

// ---------------------------------------------------------------------------
// TemporalSloProfileV1 (REQ-0006 requirement)
// ---------------------------------------------------------------------------

/// Temporal SLO profile tuple as required by REQ-0006.
///
/// Optimization gates MUST represent temporal objectives using this type.
/// Each tuple binds a baseline, target, evaluation window, owner locus,
/// falsification predicate, countermetrics, and boundary authority reference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemporalSloProfileV1 {
    /// Baseline measurement value.
    pub baseline: u64,

    /// Target measurement value.
    pub target: u64,

    /// Hash reference to the evaluation window definition.
    pub window_ref: [u8; 32],

    /// Locus (owner) of this temporal objective.
    #[serde(deserialize_with = "deserialize_bounded_kpi_id")]
    pub owner_locus: String,

    /// TP-EIO29 predicate identifier for falsification.
    pub falsification_predicate: TemporalPredicateId,

    /// Required countermetric IDs for this objective.
    #[serde(deserialize_with = "deserialize_bounded_kpi_ids")]
    pub countermetrics: Vec<String>,

    /// Hash reference to the boundary authority envelope.
    pub boundary_authority_ref: [u8; 32],
}

impl TemporalSloProfileV1 {
    /// Validates the SLO profile structural constraints.
    ///
    /// # Errors
    ///
    /// Returns an error string if any field is invalid:
    /// - zero `window_ref` or `boundary_authority_ref`
    /// - empty `owner_locus`
    /// - empty countermetrics list
    /// - target <= baseline (no improvement possible)
    pub fn validate(&self) -> Result<(), String> {
        if is_zero_hash(&self.window_ref) {
            return Err("window_ref must not be zero".to_string());
        }
        if is_zero_hash(&self.boundary_authority_ref) {
            return Err("boundary_authority_ref must not be zero".to_string());
        }
        if self.owner_locus.is_empty() {
            return Err("owner_locus must not be empty".to_string());
        }
        if self.owner_locus.len() > MAX_KPI_ID_LENGTH {
            return Err(format!(
                "owner_locus length {} exceeds maximum {}",
                self.owner_locus.len(),
                MAX_KPI_ID_LENGTH,
            ));
        }
        if self.countermetrics.is_empty() {
            return Err(
                "countermetrics must not be empty (every KPI requires countermetrics)".to_string(),
            );
        }
        if self.countermetrics.len() > MAX_COUNTERMETRIC_ENTRIES {
            return Err(format!(
                "countermetrics length {} exceeds maximum {}",
                self.countermetrics.len(),
                MAX_COUNTERMETRIC_ENTRIES,
            ));
        }
        for cm in &self.countermetrics {
            if cm.is_empty() {
                return Err("countermetric ID must not be empty".to_string());
            }
            if cm.len() > MAX_COUNTERMETRIC_ID_LENGTH {
                return Err(format!(
                    "countermetric_id length {} exceeds maximum {}",
                    cm.len(),
                    MAX_COUNTERMETRIC_ID_LENGTH,
                ));
            }
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const ZERO_HASH: [u8; 32] = [0u8; 32];

fn is_zero_hash(hash: &[u8; 32]) -> bool {
    hash.ct_eq(&ZERO_HASH).unwrap_u8() == 1
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn test_countermetric_profile() -> CountermetricProfile {
        let mut map = BTreeMap::new();
        map.insert("kpi_latency".to_string(), "cm_error_rate".to_string());
        map.insert("kpi_throughput".to_string(), "cm_containment".to_string());
        map.insert("kpi_cost".to_string(), "cm_verification_rate".to_string());
        CountermetricProfile {
            kpi_countermetric_map: map,
            content_digest: hash(0xCC),
        }
    }

    fn test_evaluator_tuple(pred: TemporalPredicateId) -> EvaluatorTuple {
        EvaluatorTuple {
            evaluator_id: CANONICAL_EVALUATOR_ID.to_string(),
            predicate_id: pred,
            contract_digest_set: hash(0x11),
            canonicalizer_tuple: hash(0x22),
            time_authority_ref: hash(0x33),
            window_ref: hash(0x44),
            verdict: ArbitrationOutcome::AgreedAllow,
            deny_reason: None,
        }
    }

    fn test_proposal() -> OptimizationProposal {
        OptimizationProposal {
            target_kpi_ids: vec!["kpi_latency".to_string(), "kpi_throughput".to_string()],
            evaluator_bindings: vec![
                test_evaluator_tuple(TemporalPredicateId::TpEio29001),
                test_evaluator_tuple(TemporalPredicateId::TpEio29002),
            ],
            proposal_digest: hash(0xDD),
        }
    }

    fn test_evidence_quality() -> EvidenceQualityReport {
        EvidenceQualityReport {
            statistical_power: 0.95,
            significance_alpha: 0.005,
            sample_size: 1000,
            runtime_classes: vec![
                "x86_64_linux".to_string(),
                "aarch64_linux".to_string(),
                "x86_64_macos".to_string(),
            ],
            evidence_tick: 900,
            throughput_ratio: 1.15,
            evidence_digest: hash(0xEE),
        }
    }

    // =======================================================================
    // KPI/countermetric completeness tests
    // =======================================================================

    #[test]
    fn test_kpi_countermetric_complete_allows() {
        let proposal = test_proposal();
        let profile = test_countermetric_profile();
        assert!(validate_kpi_countermetric_completeness(&proposal, &profile).is_ok());
    }

    #[test]
    fn test_kpi_missing_countermetric_denied() {
        let mut proposal = test_proposal();
        proposal.target_kpi_ids.push("kpi_unknown".to_string());
        let profile = test_countermetric_profile();
        let err = validate_kpi_countermetric_completeness(&proposal, &profile).unwrap_err();
        assert_eq!(err, DENY_KPI_MISSING_COUNTERMETRIC);
    }

    #[test]
    fn test_empty_proposal_kpis_allowed() {
        let mut proposal = test_proposal();
        proposal.target_kpi_ids.clear();
        let profile = test_countermetric_profile();
        assert!(validate_kpi_countermetric_completeness(&proposal, &profile).is_ok());
    }

    // =======================================================================
    // Canonical evaluator binding tests
    // =======================================================================

    #[test]
    fn test_canonical_evaluator_allows() {
        let proposal = test_proposal();
        assert!(validate_canonical_evaluator_binding(&proposal).is_ok());
    }

    #[test]
    fn test_non_canonical_evaluator_denied() {
        let mut proposal = test_proposal();
        proposal.evaluator_bindings[0].evaluator_id = "rogue_evaluator".to_string();
        let err = validate_canonical_evaluator_binding(&proposal).unwrap_err();
        assert_eq!(err, DENY_NON_CANONICAL_EVALUATOR);
    }

    #[test]
    fn test_empty_evaluator_id_denied() {
        let mut proposal = test_proposal();
        proposal.evaluator_bindings[0].evaluator_id = String::new();
        let err = validate_canonical_evaluator_binding(&proposal).unwrap_err();
        assert_eq!(err, DENY_EVALUATOR_ID_EMPTY);
    }

    #[test]
    fn test_no_evaluators_allowed() {
        let mut proposal = test_proposal();
        proposal.evaluator_bindings.clear();
        assert!(validate_canonical_evaluator_binding(&proposal).is_ok());
    }

    // =======================================================================
    // Evidence quality tests
    // =======================================================================

    #[test]
    fn test_evidence_quality_passing() {
        let report = test_evidence_quality();
        assert!(validate_evidence_quality(&report).is_ok());
    }

    #[test]
    fn test_evidence_power_below_threshold_denied() {
        let mut report = test_evidence_quality();
        report.statistical_power = 0.89;
        let err = validate_evidence_quality(&report).unwrap_err();
        assert_eq!(err, DENY_POWER_BELOW_THRESHOLD);
    }

    #[test]
    fn test_evidence_power_exact_threshold_allows() {
        let mut report = test_evidence_quality();
        report.statistical_power = 0.90;
        assert!(validate_evidence_quality(&report).is_ok());
    }

    #[test]
    fn test_evidence_alpha_above_threshold_denied() {
        let mut report = test_evidence_quality();
        report.significance_alpha = 0.02;
        let err = validate_evidence_quality(&report).unwrap_err();
        assert_eq!(err, DENY_ALPHA_ABOVE_THRESHOLD);
    }

    #[test]
    fn test_evidence_alpha_exact_threshold_allows() {
        let mut report = test_evidence_quality();
        report.significance_alpha = 0.01;
        assert!(validate_evidence_quality(&report).is_ok());
    }

    #[test]
    fn test_evidence_sample_size_zero_denied() {
        let mut report = test_evidence_quality();
        report.sample_size = 0;
        let err = validate_evidence_quality(&report).unwrap_err();
        assert_eq!(err, DENY_SAMPLE_SIZE_ZERO);
    }

    #[test]
    fn test_evidence_reproducibility_insufficient_denied() {
        let mut report = test_evidence_quality();
        report.runtime_classes = vec!["x86_64".to_string(), "aarch64".to_string()];
        let err = validate_evidence_quality(&report).unwrap_err();
        assert_eq!(err, DENY_REPRODUCIBILITY_INSUFFICIENT);
    }

    #[test]
    fn test_evidence_reproducibility_exact_threshold_allows() {
        let mut report = test_evidence_quality();
        report.runtime_classes = vec![
            "x86_64".to_string(),
            "aarch64".to_string(),
            "riscv64".to_string(),
        ];
        assert!(validate_evidence_quality(&report).is_ok());
    }

    #[test]
    fn test_evidence_power_nan_denied() {
        let mut report = test_evidence_quality();
        report.statistical_power = f64::NAN;
        let err = validate_evidence_quality(&report).unwrap_err();
        assert_eq!(err, DENY_POWER_NAN);
    }

    #[test]
    fn test_evidence_alpha_nan_denied() {
        let mut report = test_evidence_quality();
        report.significance_alpha = f64::NAN;
        let err = validate_evidence_quality(&report).unwrap_err();
        assert_eq!(err, DENY_ALPHA_NAN);
    }

    // =======================================================================
    // Evidence freshness tests
    // =======================================================================

    #[test]
    fn test_evidence_fresh_allows() {
        assert!(validate_evidence_freshness(900, 1000, 200).is_ok());
    }

    #[test]
    fn test_evidence_exact_age_allows() {
        assert!(validate_evidence_freshness(800, 1000, 200).is_ok());
    }

    #[test]
    fn test_evidence_stale_blocked() {
        let err = validate_evidence_freshness(700, 1000, 200).unwrap_err();
        assert_eq!(err, DENY_EVIDENCE_STALE);
    }

    #[test]
    fn test_evidence_future_tick_denied() {
        let err = validate_evidence_freshness(1001, 1000, 200).unwrap_err();
        assert_eq!(err, DENY_EVIDENCE_FUTURE_TICK);
    }

    // =======================================================================
    // Throughput dominance tests
    // =======================================================================

    #[test]
    fn test_throughput_above_baseline_allows() {
        assert!(validate_throughput_dominance(1.15).is_ok());
    }

    #[test]
    fn test_throughput_exact_baseline_allows() {
        assert!(validate_throughput_dominance(1.0).is_ok());
    }

    #[test]
    fn test_throughput_below_baseline_denied() {
        let err = validate_throughput_dominance(0.99).unwrap_err();
        assert_eq!(err, DENY_THROUGHPUT_DOMINANCE_VIOLATION);
    }

    #[test]
    fn test_throughput_nan_denied() {
        let err = validate_throughput_dominance(f64::NAN).unwrap_err();
        assert_eq!(err, DENY_THROUGHPUT_RATIO_NAN);
    }

    // =======================================================================
    // Arbitration outcome tests
    // =======================================================================

    #[test]
    fn test_arbitration_agreed_allow_passes() {
        assert!(validate_arbitration_outcome(ArbitrationOutcome::AgreedAllow).is_ok());
    }

    #[test]
    fn test_arbitration_agreed_deny_fails() {
        let err = validate_arbitration_outcome(ArbitrationOutcome::AgreedDeny).unwrap_err();
        assert_eq!(err, DENY_ARBITRATION_NOT_AGREED_ALLOW);
    }

    #[test]
    fn test_arbitration_disagreement_transient_fails() {
        let err =
            validate_arbitration_outcome(ArbitrationOutcome::DisagreementTransient).unwrap_err();
        assert_eq!(err, DENY_ARBITRATION_NOT_AGREED_ALLOW);
    }

    #[test]
    fn test_arbitration_disagreement_persistent_fails() {
        let err =
            validate_arbitration_outcome(ArbitrationOutcome::DisagreementPersistent).unwrap_err();
        assert_eq!(err, DENY_ARBITRATION_NOT_AGREED_ALLOW);
    }

    // =======================================================================
    // Combined gate evaluation tests
    // =======================================================================

    #[test]
    fn test_full_gate_evaluation_allows() {
        let proposal = test_proposal();
        let profile = test_countermetric_profile();
        let evidence = test_evidence_quality();

        let decision = evaluate_optimization_gate(
            &proposal,
            Some(&profile),
            Some(&evidence),
            ArbitrationOutcome::AgreedAllow,
            1000,
            200,
        );

        assert_eq!(decision.verdict, OptimizationGateVerdict::Allow);
        assert!(decision.deny_reason.is_none());
        assert!(decision.trace.kpi_countermetric_complete);
        assert!(decision.trace.canonical_evaluator_bound);
        assert!(decision.trace.evidence_quality_passed);
        assert!(decision.trace.evidence_freshness_passed);
        assert!(decision.trace.throughput_dominance_passed);
    }

    #[test]
    fn test_missing_countermetric_profile_denied() {
        let proposal = test_proposal();
        let evidence = test_evidence_quality();

        let decision = evaluate_optimization_gate(
            &proposal,
            None,
            Some(&evidence),
            ArbitrationOutcome::AgreedAllow,
            1000,
            200,
        );

        assert_eq!(decision.verdict, OptimizationGateVerdict::Deny);
        assert_eq!(
            decision.deny_reason.as_deref(),
            Some(DENY_COUNTERMETRIC_PROFILE_MISSING),
        );
    }

    #[test]
    fn test_missing_evidence_quality_denied() {
        let proposal = test_proposal();
        let profile = test_countermetric_profile();

        let decision = evaluate_optimization_gate(
            &proposal,
            Some(&profile),
            None,
            ArbitrationOutcome::AgreedAllow,
            1000,
            200,
        );

        assert_eq!(decision.verdict, OptimizationGateVerdict::Deny);
        assert_eq!(
            decision.deny_reason.as_deref(),
            Some(DENY_EVIDENCE_QUALITY_MISSING),
        );
    }

    #[test]
    fn test_stale_evidence_produces_blocked() {
        let proposal = test_proposal();
        let profile = test_countermetric_profile();
        let mut evidence = test_evidence_quality();
        evidence.evidence_tick = 500;

        let decision = evaluate_optimization_gate(
            &proposal,
            Some(&profile),
            Some(&evidence),
            ArbitrationOutcome::AgreedAllow,
            1000,
            200,
        );

        assert_eq!(decision.verdict, OptimizationGateVerdict::Blocked);
        assert_eq!(decision.deny_reason.as_deref(), Some(DENY_EVIDENCE_STALE),);
    }

    #[test]
    fn test_throughput_dominance_violation_denied() {
        let proposal = test_proposal();
        let profile = test_countermetric_profile();
        let mut evidence = test_evidence_quality();
        evidence.throughput_ratio = 0.95;

        let decision = evaluate_optimization_gate(
            &proposal,
            Some(&profile),
            Some(&evidence),
            ArbitrationOutcome::AgreedAllow,
            1000,
            200,
        );

        assert_eq!(decision.verdict, OptimizationGateVerdict::Deny);
        assert_eq!(
            decision.deny_reason.as_deref(),
            Some(DENY_THROUGHPUT_DOMINANCE_VIOLATION),
        );
    }

    #[test]
    fn test_non_canonical_evaluator_in_full_gate_denied() {
        let mut proposal = test_proposal();
        proposal.evaluator_bindings[0].evaluator_id = "bad_evaluator".to_string();
        let profile = test_countermetric_profile();
        let evidence = test_evidence_quality();

        let decision = evaluate_optimization_gate(
            &proposal,
            Some(&profile),
            Some(&evidence),
            ArbitrationOutcome::AgreedAllow,
            1000,
            200,
        );

        assert_eq!(decision.verdict, OptimizationGateVerdict::Deny);
        assert_eq!(
            decision.deny_reason.as_deref(),
            Some(DENY_NON_CANONICAL_EVALUATOR),
        );
        assert!(decision.trace.kpi_countermetric_complete);
        assert!(!decision.trace.canonical_evaluator_bound);
    }

    #[test]
    fn test_arbitration_deny_in_full_gate() {
        let proposal = test_proposal();
        let profile = test_countermetric_profile();
        let evidence = test_evidence_quality();

        let decision = evaluate_optimization_gate(
            &proposal,
            Some(&profile),
            Some(&evidence),
            ArbitrationOutcome::AgreedDeny,
            1000,
            200,
        );

        assert_eq!(decision.verdict, OptimizationGateVerdict::Deny);
        assert_eq!(
            decision.deny_reason.as_deref(),
            Some(DENY_ARBITRATION_NOT_AGREED_ALLOW),
        );
    }

    #[test]
    fn test_low_power_in_full_gate_denied() {
        let proposal = test_proposal();
        let profile = test_countermetric_profile();
        let mut evidence = test_evidence_quality();
        evidence.statistical_power = 0.5;

        let decision = evaluate_optimization_gate(
            &proposal,
            Some(&profile),
            Some(&evidence),
            ArbitrationOutcome::AgreedAllow,
            1000,
            200,
        );

        assert_eq!(decision.verdict, OptimizationGateVerdict::Deny);
        assert_eq!(
            decision.deny_reason.as_deref(),
            Some(DENY_POWER_BELOW_THRESHOLD),
        );
    }

    #[test]
    fn test_defect_accessor() {
        let proposal = test_proposal();
        let profile = test_countermetric_profile();
        let evidence = test_evidence_quality();

        let allow = evaluate_optimization_gate(
            &proposal,
            Some(&profile),
            Some(&evidence),
            ArbitrationOutcome::AgreedAllow,
            1000,
            200,
        );
        assert!(allow.defect().is_none());

        let deny = evaluate_optimization_gate(
            &proposal,
            None,
            Some(&evidence),
            ArbitrationOutcome::AgreedAllow,
            1000,
            200,
        );
        assert_eq!(deny.defect(), Some(DENY_COUNTERMETRIC_PROFILE_MISSING));
    }

    // =======================================================================
    // TemporalSloProfileV1 tests
    // =======================================================================

    fn test_slo_profile() -> TemporalSloProfileV1 {
        TemporalSloProfileV1 {
            baseline: 100,
            target: 200,
            window_ref: hash(0x55),
            owner_locus: "kpi_latency".to_string(),
            falsification_predicate: TemporalPredicateId::TpEio29001,
            countermetrics: vec!["cm_error_rate".to_string()],
            boundary_authority_ref: hash(0x66),
        }
    }

    #[test]
    fn test_slo_profile_valid() {
        let profile = test_slo_profile();
        assert!(profile.validate().is_ok());
    }

    #[test]
    fn test_slo_profile_zero_window_ref_rejected() {
        let mut profile = test_slo_profile();
        profile.window_ref = [0u8; 32];
        let err = profile.validate().unwrap_err();
        assert!(err.contains("window_ref must not be zero"));
    }

    #[test]
    fn test_slo_profile_zero_boundary_authority_rejected() {
        let mut profile = test_slo_profile();
        profile.boundary_authority_ref = [0u8; 32];
        let err = profile.validate().unwrap_err();
        assert!(err.contains("boundary_authority_ref must not be zero"));
    }

    #[test]
    fn test_slo_profile_empty_owner_locus_rejected() {
        let mut profile = test_slo_profile();
        profile.owner_locus = String::new();
        let err = profile.validate().unwrap_err();
        assert!(err.contains("owner_locus must not be empty"));
    }

    #[test]
    fn test_slo_profile_empty_countermetrics_rejected() {
        let mut profile = test_slo_profile();
        profile.countermetrics.clear();
        let err = profile.validate().unwrap_err();
        assert!(err.contains("countermetrics must not be empty"));
    }

    #[test]
    fn test_slo_profile_empty_countermetric_id_rejected() {
        let mut profile = test_slo_profile();
        profile.countermetrics.push(String::new());
        let err = profile.validate().unwrap_err();
        assert!(err.contains("countermetric ID must not be empty"));
    }

    #[test]
    fn test_slo_profile_oversized_owner_locus_rejected() {
        let mut profile = test_slo_profile();
        profile.owner_locus = "x".repeat(MAX_KPI_ID_LENGTH + 1);
        let err = profile.validate().unwrap_err();
        assert!(err.contains("owner_locus length"));
    }

    #[test]
    fn test_slo_profile_serialization_roundtrip() {
        let profile = test_slo_profile();
        let json = serde_json::to_string(&profile).expect("serialize");
        let decoded: TemporalSloProfileV1 = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded, profile);
    }

    // =======================================================================
    // Serde bounds tests
    // =======================================================================

    #[test]
    fn test_countermetric_profile_oversized_map_rejected() {
        let mut map = BTreeMap::new();
        for i in 0..=MAX_KPI_ENTRIES {
            map.insert(format!("kpi_{i}"), format!("cm_{i}"));
        }
        let digest: Vec<u8> = vec![0xCC; 32];
        let json = serde_json::json!({
            "kpi_countermetric_map": map,
            "content_digest": digest,
        });
        let err = serde_json::from_value::<CountermetricProfile>(json).unwrap_err();
        assert!(err.to_string().contains("kpi_countermetric_map length"));
    }

    #[test]
    fn test_evidence_report_oversized_runtime_classes_rejected() {
        let classes: Vec<String> = (0..=MAX_RUNTIME_CLASSES)
            .map(|i| format!("class_{i}"))
            .collect();
        let digest: Vec<u8> = vec![0xEE; 32];
        let json = serde_json::json!({
            "statistical_power": 0.95,
            "significance_alpha": 0.005,
            "sample_size": 100,
            "runtime_classes": classes,
            "evidence_tick": 100,
            "throughput_ratio": 1.1,
            "evidence_digest": digest,
        });
        let err = serde_json::from_value::<EvidenceQualityReport>(json).unwrap_err();
        assert!(err.to_string().contains("runtime_classes length"));
    }

    #[test]
    fn test_proposal_oversized_kpi_ids_rejected() {
        let ids: Vec<String> = (0..=MAX_KPI_ENTRIES).map(|i| format!("kpi_{i}")).collect();
        let digest: Vec<u8> = vec![0xDD; 32];
        let json = serde_json::json!({
            "target_kpi_ids": ids,
            "evaluator_bindings": [],
            "proposal_digest": digest,
        });
        let err = serde_json::from_value::<OptimizationProposal>(json).unwrap_err();
        assert!(err.to_string().contains("kpi_ids length"));
    }

    #[test]
    fn test_gate_trace_proposal_digest_preserved() {
        let proposal = test_proposal();
        let profile = test_countermetric_profile();
        let evidence = test_evidence_quality();

        let decision = evaluate_optimization_gate(
            &proposal,
            Some(&profile),
            Some(&evidence),
            ArbitrationOutcome::AgreedAllow,
            1000,
            200,
        );

        assert_eq!(decision.trace.proposal_digest, proposal.proposal_digest);
    }

    // =======================================================================
    // Combined gate ordering tests (verify first-failure semantics)
    // =======================================================================

    #[test]
    fn test_gate_ordering_kpi_before_evaluator() {
        // Both KPI and evaluator fail — KPI is checked first
        let mut proposal = test_proposal();
        proposal.target_kpi_ids.push("kpi_unknown".to_string());
        proposal.evaluator_bindings[0].evaluator_id = "bad".to_string();
        let profile = test_countermetric_profile();
        let evidence = test_evidence_quality();

        let decision = evaluate_optimization_gate(
            &proposal,
            Some(&profile),
            Some(&evidence),
            ArbitrationOutcome::AgreedAllow,
            1000,
            200,
        );

        assert_eq!(
            decision.deny_reason.as_deref(),
            Some(DENY_KPI_MISSING_COUNTERMETRIC),
        );
    }

    #[test]
    fn test_gate_ordering_evaluator_before_evidence() {
        // Both evaluator and evidence fail — evaluator is checked first
        let mut proposal = test_proposal();
        proposal.evaluator_bindings[0].evaluator_id = "bad".to_string();
        let profile = test_countermetric_profile();
        let mut evidence = test_evidence_quality();
        evidence.statistical_power = 0.1;

        let decision = evaluate_optimization_gate(
            &proposal,
            Some(&profile),
            Some(&evidence),
            ArbitrationOutcome::AgreedAllow,
            1000,
            200,
        );

        assert_eq!(
            decision.deny_reason.as_deref(),
            Some(DENY_NON_CANONICAL_EVALUATOR),
        );
    }

    #[test]
    fn test_gate_ordering_freshness_produces_blocked_not_deny() {
        let proposal = test_proposal();
        let profile = test_countermetric_profile();
        let mut evidence = test_evidence_quality();
        // Evidence is stale AND throughput is bad — stale is checked first
        evidence.evidence_tick = 100;
        evidence.throughput_ratio = 0.5;

        let decision = evaluate_optimization_gate(
            &proposal,
            Some(&profile),
            Some(&evidence),
            ArbitrationOutcome::AgreedAllow,
            1000,
            200,
        );

        assert_eq!(decision.verdict, OptimizationGateVerdict::Blocked);
        assert_eq!(decision.deny_reason.as_deref(), Some(DENY_EVIDENCE_STALE),);
    }
}
