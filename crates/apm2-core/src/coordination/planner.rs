//! Advisory bounded expected free energy (EFE) planner types.
//!
//! This module implements the REQ-0023 advisory planning surface for
//! coordination. Planner objectives may guide prioritization but do not grant
//! authority to act.

use std::cmp::Ordering;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::crypto::{EventHasher, Hash};

/// Maximum length of a work ID in planner types.
pub const MAX_PLANNER_WORK_ID_LEN: usize = 256;

/// Maximum length of a coordination ID in planner types.
pub const MAX_PLANNER_COORDINATION_ID_LEN: usize = 256;

/// Maximum number of objectives that can be tracked simultaneously.
pub const MAX_TRACKED_OBJECTIVES: usize = 1000;

/// Threshold for Tier3+ escalation receipt emission.
pub const TIER3_ESCALATION_THRESHOLD: u32 = 3;

/// Stable schema version for [`CoordinationObjectiveReceiptV1`].
pub const OBJECTIVE_RECEIPT_SCHEMA_VERSION: &str = "1.0.0";

/// Weight configuration for expected free energy components.
///
/// All weights are clamped to `[0.0, 1.0]` on construction.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EfeWeights {
    /// Weight for expected policy violation component.
    #[serde(rename = "lambda_risk")]
    risk: f64,

    /// Weight for expected evidence ambiguity component.
    #[serde(rename = "lambda_uncertainty")]
    uncertainty: f64,

    /// Weight for expected resource cost component.
    #[serde(rename = "lambda_cost")]
    cost: f64,
}

impl EfeWeights {
    /// Creates bounded EFE weights.
    ///
    /// Returns an error for NaN or infinite values. Finite values are clamped
    /// to `[0.0, 1.0]`.
    ///
    /// # Errors
    ///
    /// Returns [`PlannerError::InvalidFloat`] if any input is NaN or infinite.
    pub fn new(
        lambda_risk: f64,
        lambda_uncertainty: f64,
        lambda_cost: f64,
    ) -> Result<Self, PlannerError> {
        Ok(Self {
            risk: clamp_weight("lambda_risk", lambda_risk)?,
            uncertainty: clamp_weight("lambda_uncertainty", lambda_uncertainty)?,
            cost: clamp_weight("lambda_cost", lambda_cost)?,
        })
    }

    /// Returns the policy-violation component weight.
    #[must_use]
    pub const fn lambda_risk(&self) -> f64 {
        self.risk
    }

    /// Returns the evidence-ambiguity component weight.
    #[must_use]
    pub const fn lambda_uncertainty(&self) -> f64 {
        self.uncertainty
    }

    /// Returns the resource-cost component weight.
    #[must_use]
    pub const fn lambda_cost(&self) -> f64 {
        self.cost
    }

    fn validate_bounded(&self) -> Result<(), PlannerError> {
        validate_weight_in_unit_interval("lambda_risk", self.risk)?;
        validate_weight_in_unit_interval("lambda_uncertainty", self.uncertainty)?;
        validate_weight_in_unit_interval("lambda_cost", self.cost)?;
        Ok(())
    }
}

impl Default for EfeWeights {
    fn default() -> Self {
        Self {
            risk: 1.0,
            uncertainty: 1.0,
            cost: 1.0,
        }
    }
}

/// Component scores for expected free energy calculation.
///
/// Each component is in `[0.0, 1.0]`, where `0.0` is best.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EfeComponents {
    /// Estimated policy violation score from capability/stop/freshness
    /// constraints.
    #[serde(rename = "expected_policy_violation")]
    policy_violation: f64,

    /// Evidence ambiguity score (reduced by context/evidence acquisition).
    #[serde(rename = "expected_evidence_ambiguity")]
    evidence_ambiguity: f64,

    /// Resource cost score (bounded by episode/channel budgets).
    #[serde(rename = "expected_resource_cost")]
    resource_cost: f64,
}

impl EfeComponents {
    /// Creates bounded EFE component scores.
    ///
    /// Returns an error for NaN/infinite values and for finite values outside
    /// `[0.0, 1.0]`.
    ///
    /// # Errors
    ///
    /// Returns [`PlannerError::InvalidFloat`] for NaN/infinite values and
    /// [`PlannerError::OutOfRange`] for finite values outside `[0.0, 1.0]`.
    pub fn new(
        expected_policy_violation: f64,
        expected_evidence_ambiguity: f64,
        expected_resource_cost: f64,
    ) -> Result<Self, PlannerError> {
        Ok(Self {
            policy_violation: validate_component_in_unit_interval(
                "expected_policy_violation",
                expected_policy_violation,
            )?,
            evidence_ambiguity: validate_component_in_unit_interval(
                "expected_evidence_ambiguity",
                expected_evidence_ambiguity,
            )?,
            resource_cost: validate_component_in_unit_interval(
                "expected_resource_cost",
                expected_resource_cost,
            )?,
        })
    }

    /// Returns the expected policy-violation component.
    #[must_use]
    pub const fn expected_policy_violation(&self) -> f64 {
        self.policy_violation
    }

    /// Returns the expected evidence-ambiguity component.
    #[must_use]
    pub const fn expected_evidence_ambiguity(&self) -> f64 {
        self.evidence_ambiguity
    }

    /// Returns the expected resource-cost component.
    #[must_use]
    pub const fn expected_resource_cost(&self) -> f64 {
        self.resource_cost
    }

    /// Computes EFE as a weighted sum of bounded components.
    #[must_use]
    pub fn compute_efe(&self, weights: &EfeWeights) -> f64 {
        weights.lambda_cost().mul_add(
            self.expected_resource_cost(),
            weights.lambda_risk().mul_add(
                self.expected_policy_violation(),
                weights.lambda_uncertainty() * self.expected_evidence_ambiguity(),
            ),
        )
    }

    fn validate_bounded(&self) -> Result<(), PlannerError> {
        validate_component_in_unit_interval("expected_policy_violation", self.policy_violation)?;
        validate_component_in_unit_interval(
            "expected_evidence_ambiguity",
            self.evidence_ambiguity,
        )?;
        validate_component_in_unit_interval("expected_resource_cost", self.resource_cost)?;
        Ok(())
    }
}

/// A bounded EFE objective that is strictly advisory.
///
/// This type enforces hard separation between planner objective and authority
/// checks. It can suggest priority but cannot authorize actuation or bypass
/// gates.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EfeObjective {
    /// The work item this objective applies to.
    #[serde(rename = "work_id")]
    work_id: String,

    /// Component scores used to compute the objective.
    #[serde(rename = "components")]
    components: EfeComponents,

    /// Weights used for objective computation.
    #[serde(rename = "weights")]
    weights: EfeWeights,

    /// Computed EFE score (lower is better). Advisory only.
    #[serde(rename = "efe_score")]
    efe_score: f64,

    /// Monotonic tick at which this objective was computed.
    #[serde(rename = "computed_at_tick")]
    computed_at_tick: u64,
}

impl EfeObjective {
    /// Creates a new advisory EFE objective.
    ///
    /// # Errors
    ///
    /// Returns [`PlannerError::FieldTooLong`] if `work_id` exceeds
    /// [`MAX_PLANNER_WORK_ID_LEN`].
    pub fn new(
        work_id: impl Into<String>,
        components: EfeComponents,
        weights: EfeWeights,
        computed_at_tick: u64,
    ) -> Result<Self, PlannerError> {
        let work_id = work_id.into();
        validate_field_len("work_id", &work_id, MAX_PLANNER_WORK_ID_LEN)?;

        let efe_score = components.compute_efe(&weights);
        let objective = Self {
            work_id,
            components,
            weights,
            efe_score,
            computed_at_tick,
        };
        objective.validate_components_and_weights()?;
        validate_finite("efe_score", objective.efe_score)?;
        Ok(objective)
    }

    /// Returns the work item this objective applies to.
    #[must_use]
    pub fn work_id(&self) -> &str {
        &self.work_id
    }

    /// Returns the EFE components used for scoring.
    #[must_use]
    pub const fn components(&self) -> &EfeComponents {
        &self.components
    }

    /// Returns the EFE weights used for scoring.
    #[must_use]
    pub const fn weights(&self) -> &EfeWeights {
        &self.weights
    }

    /// Returns the advisory EFE score.
    #[must_use]
    pub const fn efe_score(&self) -> f64 {
        self.efe_score
    }

    /// Returns the monotonic tick at objective computation time.
    #[must_use]
    pub const fn computed_at_tick(&self) -> u64 {
        self.computed_at_tick
    }

    fn validate_components_and_weights(&self) -> Result<(), PlannerError> {
        self.components.validate_bounded()?;
        self.weights.validate_bounded()?;
        Ok(())
    }

    #[must_use]
    const fn inputs_are_finite(&self) -> bool {
        self.components.expected_policy_violation().is_finite()
            && self.components.expected_evidence_ambiguity().is_finite()
            && self.components.expected_resource_cost().is_finite()
            && self.weights.lambda_risk().is_finite()
            && self.weights.lambda_uncertainty().is_finite()
            && self.weights.lambda_cost().is_finite()
    }

    /// Returns a BLAKE3 hash over canonical JSON objective inputs
    /// (`components` + `weights`).
    #[must_use]
    pub fn objective_inputs_hash(&self) -> Hash {
        #[derive(Serialize)]
        #[serde(deny_unknown_fields)]
        struct ObjectiveInputs<'a> {
            #[serde(rename = "components")]
            components: &'a EfeComponents,
            #[serde(rename = "weights")]
            weights: &'a EfeWeights,
        }

        debug_assert!(
            self.inputs_are_finite(),
            "objective inputs must be finite before hashing"
        );

        let inputs = ObjectiveInputs {
            components: &self.components,
            weights: &self.weights,
        };
        let canonical = canonical_json_bytes(&inputs);
        EventHasher::hash_content(&canonical)
    }
}

/// Receipt emitted for Tier3+ repeated escalation loops.
///
/// This receipt binds objective inputs by hash and provides auditability
/// without granting actuation authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoordinationObjectiveReceiptV1 {
    /// Schema version for forward compatibility.
    #[serde(rename = "schema_version")]
    pub schema_version: String,

    /// Coordination ID for this receipt.
    #[serde(rename = "coordination_id")]
    pub coordination_id: String,

    /// Work item ID.
    #[serde(rename = "work_id")]
    pub work_id: String,

    /// BLAKE3 hash of objective inputs (`components` + `weights`).
    #[serde(rename = "objective_inputs_hash")]
    pub objective_inputs_hash: [u8; 32],

    /// Computed EFE score at emission time (string representation for stable
    /// artifact signing).
    #[serde(rename = "efe_score_repr")]
    pub efe_score_repr: String,

    /// Escalation count (number of repeated attempts).
    #[serde(rename = "escalation_count")]
    pub escalation_count: u32,

    /// Monotonic tick when the objective was computed.
    #[serde(rename = "computed_at_tick")]
    pub computed_at_tick: u64,

    /// Monotonic tick when the receipt was emitted.
    #[serde(rename = "emitted_at_tick")]
    pub emitted_at_tick: u64,
}

impl CoordinationObjectiveReceiptV1 {
    /// Creates a new objective receipt.
    ///
    /// # Errors
    ///
    /// Returns [`PlannerError::FieldTooLong`] when bounded string fields exceed
    /// limits.
    pub fn new(
        coordination_id: impl Into<String>,
        objective: &EfeObjective,
        escalation_count: u32,
        emitted_at_tick: u64,
    ) -> Result<Self, PlannerError> {
        let coordination_id = coordination_id.into();
        validate_field_len(
            "coordination_id",
            &coordination_id,
            MAX_PLANNER_COORDINATION_ID_LEN,
        )?;
        validate_field_len("work_id", objective.work_id(), MAX_PLANNER_WORK_ID_LEN)?;

        Ok(Self {
            schema_version: OBJECTIVE_RECEIPT_SCHEMA_VERSION.to_string(),
            coordination_id,
            work_id: objective.work_id().to_string(),
            objective_inputs_hash: objective.objective_inputs_hash(),
            efe_score_repr: format!("{:.17}", objective.efe_score()),
            escalation_count,
            computed_at_tick: objective.computed_at_tick(),
            emitted_at_tick,
        })
    }

    /// Returns canonical bytes used for receipt hash computation.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(192);

        buf.extend_from_slice(b"CORv1");
        write_length_prefixed_string(&mut buf, &self.schema_version);
        write_length_prefixed_string(&mut buf, &self.coordination_id);
        write_length_prefixed_string(&mut buf, &self.work_id);
        buf.extend_from_slice(&self.objective_inputs_hash);
        write_length_prefixed_string(&mut buf, &self.efe_score_repr);
        write_u32(&mut buf, self.escalation_count);
        write_u64(&mut buf, self.computed_at_tick);
        write_u64(&mut buf, self.emitted_at_tick);

        buf
    }

    /// Computes the BLAKE3 hash of this objective receipt.
    #[must_use]
    pub fn compute_hash(&self) -> Hash {
        let canonical = self.canonical_bytes();
        EventHasher::hash_content(&canonical)
    }

    /// Verifies this receipt against an expected hash.
    #[must_use]
    pub fn verify(&self, expected_hash: &Hash) -> bool {
        self.compute_hash() == *expected_hash
    }
}

/// An advisory planner score that explicitly cannot grant authority.
///
/// This public API type exposes read-only objective information for planning
/// and auditability. It has no authority or gate mutation methods.
#[derive(Debug, Clone)]
pub struct AdvisoryPlannerScore {
    objective: EfeObjective,
}

impl AdvisoryPlannerScore {
    /// Wraps an objective as advisory planner score.
    ///
    /// # Errors
    ///
    /// Returns a [`PlannerError`] if components/weights are non-finite or
    /// out of bounds.
    pub fn new(objective: EfeObjective) -> Result<Self, PlannerError> {
        objective.validate_components_and_weights()?;
        validate_finite("efe_score", objective.efe_score())?;
        Ok(Self { objective })
    }

    /// Returns the advisory EFE score (lower is better).
    #[must_use]
    pub const fn efe_score(&self) -> f64 {
        self.objective.efe_score()
    }

    /// Returns the work item ID this score applies to.
    #[must_use]
    pub fn work_id(&self) -> &str {
        self.objective.work_id()
    }

    /// Returns EFE component scores.
    #[must_use]
    pub const fn components(&self) -> &EfeComponents {
        self.objective.components()
    }

    /// Returns EFE component weights.
    #[must_use]
    pub const fn weights(&self) -> &EfeWeights {
        self.objective.weights()
    }

    /// Returns hash of objective inputs (`components` + `weights`).
    #[must_use]
    pub fn objective_inputs_hash(&self) -> Hash {
        self.objective.objective_inputs_hash()
    }

    /// Returns the objective compute tick.
    #[must_use]
    pub(crate) const fn computed_at_tick(&self) -> u64 {
        self.objective.computed_at_tick()
    }

    /// Returns the underlying objective for internal receipt generation.
    #[must_use]
    pub(crate) const fn objective(&self) -> &EfeObjective {
        &self.objective
    }
}

impl PartialEq for AdvisoryPlannerScore {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for AdvisoryPlannerScore {}

impl PartialOrd for AdvisoryPlannerScore {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for AdvisoryPlannerScore {
    /// Advisory priority ordering.
    ///
    /// Lower EFE scores sort first (higher priority). This ordering is
    /// informational and MUST NOT be treated as authorization.
    fn cmp(&self, other: &Self) -> Ordering {
        self.efe_score()
            .total_cmp(&other.efe_score())
            .then_with(|| self.work_id().cmp(other.work_id()))
            .then_with(|| self.computed_at_tick().cmp(&other.computed_at_tick()))
    }
}

/// Planner-specific error variants.
#[derive(Debug, Clone, PartialEq)]
pub enum PlannerError {
    /// A weight or component value was NaN or infinite.
    InvalidFloat {
        /// Field name.
        field: &'static str,
        /// Invalid value.
        value: f64,
    },

    /// A bounded value was outside an allowed inclusive range.
    OutOfRange {
        /// Field name.
        field: &'static str,
        /// Actual value.
        value: f64,
        /// Inclusive minimum.
        min: f64,
        /// Inclusive maximum.
        max: f64,
    },

    /// A bounded string exceeded the maximum length.
    FieldTooLong {
        /// Field name.
        field: &'static str,
        /// Actual length in bytes.
        actual: usize,
        /// Maximum allowed length in bytes.
        max: usize,
    },

    /// Too many objectives were tracked.
    ObjectiveLimitExceeded {
        /// Actual tracked size.
        actual: usize,
        /// Maximum allowed.
        max: usize,
    },
}

impl fmt::Display for PlannerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFloat { field, value } => {
                write!(f, "invalid float in field '{field}': {value}")
            },
            Self::OutOfRange {
                field,
                value,
                min,
                max,
            } => {
                write!(
                    f,
                    "out-of-range value for field '{field}': {value} (expected {min}..={max})"
                )
            },
            Self::FieldTooLong { field, actual, max } => {
                write!(
                    f,
                    "field '{field}' exceeds max length: {actual} > {max} bytes"
                )
            },
            Self::ObjectiveLimitExceeded { actual, max } => {
                write!(f, "objective limit exceeded: {actual} > {max}")
            },
        }
    }
}

impl std::error::Error for PlannerError {}

const fn validate_finite(field: &'static str, value: f64) -> Result<f64, PlannerError> {
    if !value.is_finite() {
        return Err(PlannerError::InvalidFloat { field, value });
    }
    Ok(value)
}

fn validate_component_in_unit_interval(
    field: &'static str,
    value: f64,
) -> Result<f64, PlannerError> {
    validate_finite(field, value)?;
    if !(0.0..=1.0).contains(&value) {
        return Err(PlannerError::OutOfRange {
            field,
            value,
            min: 0.0,
            max: 1.0,
        });
    }
    Ok(value)
}

fn validate_weight_in_unit_interval(field: &'static str, value: f64) -> Result<f64, PlannerError> {
    validate_finite(field, value)?;
    if !(0.0..=1.0).contains(&value) {
        return Err(PlannerError::OutOfRange {
            field,
            value,
            min: 0.0,
            max: 1.0,
        });
    }
    Ok(value)
}

fn clamp_weight(field: &'static str, value: f64) -> Result<f64, PlannerError> {
    validate_finite(field, value)?;
    Ok(value.clamp(0.0, 1.0))
}

const fn validate_field_len(
    field: &'static str,
    value: &str,
    max: usize,
) -> Result<(), PlannerError> {
    let actual = value.len();
    if actual > max {
        return Err(PlannerError::FieldTooLong { field, actual, max });
    }
    Ok(())
}

fn canonical_json_bytes<T: Serialize>(value: &T) -> Vec<u8> {
    let canonical_value = serde_json::to_value(value)
        .expect("planner canonicalization should serialize to JSON value");
    serde_json::to_vec(&canonical_value)
        .expect("planner canonicalization should serialize to bytes")
}

fn write_length_prefixed_string(buf: &mut Vec<u8>, value: &str) {
    let bytes = value.as_bytes();
    #[allow(clippy::cast_possible_truncation)]
    let len = bytes.len().min(u32::MAX as usize) as u32;
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(&bytes[..len as usize]);
}

fn write_u32(buf: &mut Vec<u8>, value: u32) {
    buf.extend_from_slice(&value.to_le_bytes());
}

fn write_u64(buf: &mut Vec<u8>, value: u64) {
    buf.extend_from_slice(&value.to_le_bytes());
}
