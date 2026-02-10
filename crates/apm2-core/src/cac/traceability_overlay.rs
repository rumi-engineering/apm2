//! CAC traceability overlay enforcement for RFC-0019 chapter 18.
//!
//! Validates that promotion-critical claims carry required CAC schema,
//! digest-set, canonicalizer, and Tier2+ fail-closed trigger fields.

#![allow(clippy::module_name_repetitions)]

use std::collections::HashMap;

use serde::de::{self, Deserializer};
use serde::{Deserialize, Serialize};

use super::contract_registry::{CacCompatibilityState, CacDefectClass, CacValidationResult};

const MAX_STRING_LENGTH: usize = 4_096;
const MAX_REQUIRED_SCHEMA_IDS: usize = 16;

const TRC_FAC_10_SCHEMA_IDS: [&str; 6] = [
    "cac.holon_contract.v1",
    "cac.context_pack_spec.v1",
    "cac.context_pack_manifest.v1",
    "cac.reasoning_selector.v1",
    "cac.budget_profile.v1",
    "cac.run_receipt.v1",
];

const TRC_FAC_10_DIGEST_BINDING_SCHEMA_IDS: [&str; 4] = [
    "cac.holon_contract.v1",
    "cac.context_pack_manifest.v1",
    "cac.reasoning_selector.v1",
    "cac.run_receipt.v1",
];

const TRC_FAC_10_SELECTOR_CLOSURE_SCHEMA_IDS: [&str; 2] =
    ["cac.reasoning_selector.v1", "cac.run_receipt.v1"];

/// TRC-FAC claim identifiers for promotion-critical traceability rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TrcFacClaim {
    /// Authority continuity before effect.
    #[serde(rename = "TRC-FAC-01")]
    TrcFac01,
    /// Revocation/freshness dominance.
    #[serde(rename = "TRC-FAC-02")]
    TrcFac02,
    /// Queue and control-path stability.
    #[serde(rename = "TRC-FAC-07")]
    TrcFac07,
    /// `RoleSpec` speciation with non-regression.
    #[serde(rename = "TRC-FAC-10")]
    TrcFac10,
    /// Projection authority isolation.
    #[serde(rename = "TRC-FAC-12")]
    TrcFac12,
    /// Projection sink independence and outage continuity.
    #[serde(rename = "TRC-FAC-14")]
    TrcFac14,
    /// Erasure+BFT reconstruction admissibility.
    #[serde(rename = "TRC-FAC-15")]
    TrcFac15,
    /// Temporal monotonicity and ambiguity deny.
    #[serde(rename = "TRC-FAC-16")]
    TrcFac16,
}

impl TrcFacClaim {
    const fn as_str(self) -> &'static str {
        match self {
            Self::TrcFac01 => "TRC-FAC-01",
            Self::TrcFac02 => "TRC-FAC-02",
            Self::TrcFac07 => "TRC-FAC-07",
            Self::TrcFac10 => "TRC-FAC-10",
            Self::TrcFac12 => "TRC-FAC-12",
            Self::TrcFac14 => "TRC-FAC-14",
            Self::TrcFac15 => "TRC-FAC-15",
            Self::TrcFac16 => "TRC-FAC-16",
        }
    }
}

/// CAC overlay requirement for a promotion-critical TRC-FAC claim.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CacOverlayRequirement {
    /// The TRC-FAC claim this requirement applies to.
    pub claim: TrcFacClaim,
    /// Required schema IDs that must be present and valid.
    #[serde(deserialize_with = "deserialize_required_schema_ids")]
    pub required_schema_ids: Vec<String>,
    /// Whether digest-set completeness is required.
    pub digest_set_required: bool,
    /// Whether canonicalizer binding is required.
    pub canonicalizer_binding_required: bool,
    /// Whether signature/freshness binding is required.
    pub signature_freshness_required: bool,
    /// Tier2+ escalation behavior for unresolved defects.
    pub tier2_escalation: Tier2FailClosedBehavior,
}

/// Tier2+ fail-closed behavior for unresolved CAC ambiguity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Tier2FailClosedBehavior {
    /// Deny immediately on any unresolved defect.
    DenyImmediate,
    /// Deny + freeze promotion paths.
    DenyAndFreeze,
    /// Deny + freeze -> halt escalation if unresolved by deadline.
    DenyFreezeHalt,
}

/// Overlay validation defect for a promotion-critical claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OverlayDefect {
    /// Claim that failed overlay validation.
    pub claim: TrcFacClaim,
    /// Defect class emitted during overlay validation.
    pub defect_class: OverlayDefectClass,
    /// Human-readable detail.
    #[serde(deserialize_with = "deserialize_bounded_string")]
    pub detail: String,
}

/// Defect classes emitted by traceability-overlay checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OverlayDefectClass {
    /// Required schema not present in validation results.
    MissingRequiredSchema,
    /// Schema validation result is not Compatible.
    SchemaValidationFailed,
    /// Digest-set is incomplete for a required schema.
    IncompleteDigestSet,
    /// Canonicalizer binding mismatch.
    CanonicalizerBindingMismatch,
    /// Signature/freshness validation failed for required schema.
    SignatureFreshnessFailed,
    /// Tier2+ escalation triggered.
    Tier2EscalationTriggered,
}

impl OverlayDefect {
    const fn new(claim: TrcFacClaim, defect_class: OverlayDefectClass, detail: String) -> Self {
        Self {
            claim,
            defect_class,
            detail,
        }
    }
}

fn deserialize_bounded_string<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    if value.len() > MAX_STRING_LENGTH {
        return Err(de::Error::custom(format!(
            "string exceeds maximum length ({} > {MAX_STRING_LENGTH})",
            value.len()
        )));
    }
    Ok(value)
}

fn deserialize_required_schema_ids<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let values = Vec::<String>::deserialize(deserializer)?;
    if values.is_empty() {
        return Err(de::Error::custom(
            "required_schema_ids must contain at least one schema_id",
        ));
    }
    if values.len() > MAX_REQUIRED_SCHEMA_IDS {
        return Err(de::Error::custom(format!(
            "required_schema_ids exceeds maximum size ({} > {MAX_REQUIRED_SCHEMA_IDS})",
            values.len()
        )));
    }

    for schema_id in &values {
        if schema_id.is_empty() {
            return Err(de::Error::custom(
                "required_schema_ids cannot contain empty schema_id values",
            ));
        }
        if schema_id.len() > MAX_STRING_LENGTH {
            return Err(de::Error::custom(format!(
                "schema_id exceeds maximum length ({} > {MAX_STRING_LENGTH})",
                schema_id.len()
            )));
        }
    }
    Ok(values)
}

/// Returns the RFC-0019 chapter 18 promotion-critical CAC overlay matrix.
#[must_use]
pub fn default_overlay_requirements() -> Vec<CacOverlayRequirement> {
    vec![
        CacOverlayRequirement {
            claim: TrcFacClaim::TrcFac01,
            required_schema_ids: vec![
                "apm2.pcac_snapshot_report.v1".to_string(),
                "apm2.authority_kernel_decision.v1".to_string(),
            ],
            digest_set_required: true,
            canonicalizer_binding_required: true,
            signature_freshness_required: true,
            tier2_escalation: Tier2FailClosedBehavior::DenyAndFreeze,
        },
        CacOverlayRequirement {
            claim: TrcFacClaim::TrcFac02,
            required_schema_ids: vec![
                "apm2.time_authority_envelope.v1".to_string(),
                "apm2.revocation_frontier_snapshot.v1".to_string(),
            ],
            digest_set_required: true,
            canonicalizer_binding_required: true,
            signature_freshness_required: true,
            tier2_escalation: Tier2FailClosedBehavior::DenyAndFreeze,
        },
        CacOverlayRequirement {
            claim: TrcFacClaim::TrcFac07,
            required_schema_ids: vec![
                "apm2.temporal_slo_profile.v1".to_string(),
                "apm2.projection_continuity_window.v1".to_string(),
                "apm2.time_authority_envelope.v1".to_string(),
            ],
            digest_set_required: true,
            canonicalizer_binding_required: true,
            signature_freshness_required: true,
            tier2_escalation: Tier2FailClosedBehavior::DenyAndFreeze,
        },
        CacOverlayRequirement {
            claim: TrcFacClaim::TrcFac10,
            required_schema_ids: TRC_FAC_10_SCHEMA_IDS
                .iter()
                .map(|schema| (*schema).to_string())
                .collect(),
            digest_set_required: true,
            canonicalizer_binding_required: true,
            signature_freshness_required: true,
            tier2_escalation: Tier2FailClosedBehavior::DenyAndFreeze,
        },
        CacOverlayRequirement {
            claim: TrcFacClaim::TrcFac12,
            required_schema_ids: vec![
                "apm2.projection_isolation_policy.v1".to_string(),
                "apm2.sink_identity_snapshot.v1".to_string(),
            ],
            digest_set_required: true,
            canonicalizer_binding_required: true,
            signature_freshness_required: true,
            tier2_escalation: Tier2FailClosedBehavior::DenyAndFreeze,
        },
        CacOverlayRequirement {
            claim: TrcFacClaim::TrcFac14,
            required_schema_ids: vec![
                "apm2.projection_sink_continuity_profile.v1".to_string(),
                "apm2.projection_continuity_window.v1".to_string(),
                "apm2.time_authority_envelope.v1".to_string(),
            ],
            digest_set_required: true,
            canonicalizer_binding_required: true,
            signature_freshness_required: true,
            tier2_escalation: Tier2FailClosedBehavior::DenyAndFreeze,
        },
        CacOverlayRequirement {
            claim: TrcFacClaim::TrcFac15,
            required_schema_ids: vec![
                "apm2.erasure_recovery_receipt.v1".to_string(),
                "apm2.bft_recovery_quorum_certificate.v1".to_string(),
                "apm2.recovery_admissibility_receipt.v1".to_string(),
                "apm2.source_trust_snapshot.v1".to_string(),
            ],
            digest_set_required: true,
            canonicalizer_binding_required: true,
            signature_freshness_required: true,
            tier2_escalation: Tier2FailClosedBehavior::DenyAndFreeze,
        },
        CacOverlayRequirement {
            claim: TrcFacClaim::TrcFac16,
            required_schema_ids: vec![
                "apm2.revocation_frontier_snapshot.v1".to_string(),
                "apm2.replay_convergence_receipt.v1".to_string(),
                "apm2.temporal_disagreement_receipt.v1".to_string(),
                "apm2.temporal_arbitration_receipt.v1".to_string(),
                "apm2.temporal_predicate_evaluator.v1".to_string(),
            ],
            digest_set_required: true,
            canonicalizer_binding_required: true,
            signature_freshness_required: true,
            tier2_escalation: Tier2FailClosedBehavior::DenyFreezeHalt,
        },
    ]
}

fn push_defect_if_absent(defects: &mut Vec<OverlayDefect>, defect: OverlayDefect) {
    if !defects.contains(&defect) {
        defects.push(defect);
    }
}

fn has_defect_class(result: &CacValidationResult, classes: &[CacDefectClass]) -> bool {
    result
        .defects
        .iter()
        .any(|defect| classes.contains(&defect.class))
}

fn claim_has_non_tier2_defect(defects: &[OverlayDefect], claim: TrcFacClaim) -> bool {
    defects.iter().any(|defect| {
        defect.claim == claim && defect.defect_class != OverlayDefectClass::Tier2EscalationTriggered
    })
}

fn claim_has_tier2_defect(defects: &[OverlayDefect], claim: TrcFacClaim) -> bool {
    defects.iter().any(|defect| {
        defect.claim == claim && defect.defect_class == OverlayDefectClass::Tier2EscalationTriggered
    })
}

const fn tier2_escalation_detail(behavior: Tier2FailClosedBehavior) -> &'static str {
    match behavior {
        Tier2FailClosedBehavior::DenyImmediate => {
            "Tier2+ fail-closed: deny immediately on unresolved CAC defect"
        },
        Tier2FailClosedBehavior::DenyAndFreeze => {
            "Tier2+ fail-closed: deny + freeze promotion paths"
        },
        Tier2FailClosedBehavior::DenyFreezeHalt => {
            "Tier2+ fail-closed: deny + freeze then halt escalation if unresolved by deadline"
        },
    }
}

fn sorted_unique_claims(claims: &[TrcFacClaim]) -> Vec<TrcFacClaim> {
    let mut ordered = claims.to_vec();
    ordered.sort_unstable();
    ordered.dedup();
    ordered
}

fn trc_fac_10_effective_schema_ids(
    requirement: &CacOverlayRequirement,
    defects: &mut Vec<OverlayDefect>,
) -> Vec<String> {
    let mut schema_ids = requirement.required_schema_ids.clone();
    for required_schema_id in TRC_FAC_10_SCHEMA_IDS {
        if !schema_ids
            .iter()
            .any(|schema_id| schema_id == required_schema_id)
        {
            push_defect_if_absent(
                defects,
                OverlayDefect::new(
                    TrcFacClaim::TrcFac10,
                    OverlayDefectClass::Tier2EscalationTriggered,
                    format!(
                        "{} overlay row is missing mandatory schema_id '{}' (fail-closed)",
                        TrcFacClaim::TrcFac10.as_str(),
                        required_schema_id
                    ),
                ),
            );
            schema_ids.push(required_schema_id.to_string());
        }
    }
    schema_ids
}

fn validate_schema_requirement(
    claim: TrcFacClaim,
    requirement: &CacOverlayRequirement,
    schema_id: &str,
    validation_results: &HashMap<String, CacValidationResult>,
    defects: &mut Vec<OverlayDefect>,
) {
    let Some(result) = validation_results.get(schema_id) else {
        push_defect_if_absent(
            defects,
            OverlayDefect::new(
                claim,
                OverlayDefectClass::MissingRequiredSchema,
                format!(
                    "{} is missing required schema_id '{}'",
                    claim.as_str(),
                    schema_id
                ),
            ),
        );
        return;
    };

    validate_schema_compatibility(claim, schema_id, result, defects);
    validate_digest_binding(
        claim,
        schema_id,
        requirement.digest_set_required,
        result,
        defects,
    );
    validate_canonicalizer_binding(
        claim,
        schema_id,
        requirement.canonicalizer_binding_required,
        result,
        defects,
    );
    validate_signature_freshness(
        claim,
        schema_id,
        requirement.signature_freshness_required,
        result,
        defects,
    );
}

fn validate_schema_compatibility(
    claim: TrcFacClaim,
    schema_id: &str,
    result: &CacValidationResult,
    defects: &mut Vec<OverlayDefect>,
) {
    if result.recompute_compatibility_state() == CacCompatibilityState::Compatible {
        return;
    }

    push_defect_if_absent(
        defects,
        OverlayDefect::new(
            claim,
            OverlayDefectClass::SchemaValidationFailed,
            format!(
                "{} schema_id '{}' is not compatible",
                claim.as_str(),
                schema_id
            ),
        ),
    );
}

fn validate_digest_binding(
    claim: TrcFacClaim,
    schema_id: &str,
    digest_set_required: bool,
    result: &CacValidationResult,
    defects: &mut Vec<OverlayDefect>,
) {
    if !digest_set_required
        || !has_defect_class(
            result,
            &[
                CacDefectClass::DigestIncomplete,
                CacDefectClass::DigestMismatch,
            ],
        )
    {
        return;
    }

    let detail = if claim == TrcFacClaim::TrcFac10
        && TRC_FAC_10_DIGEST_BINDING_SCHEMA_IDS.contains(&schema_id)
    {
        format!(
            "{} RoleSpec/context-selector digest set is incomplete or mismatched at schema_id '{}'",
            claim.as_str(),
            schema_id
        )
    } else {
        format!(
            "{} digest-set binding is incomplete or mismatched at schema_id '{}'",
            claim.as_str(),
            schema_id
        )
    };
    push_defect_if_absent(
        defects,
        OverlayDefect::new(claim, OverlayDefectClass::IncompleteDigestSet, detail),
    );
}

fn validate_canonicalizer_binding(
    claim: TrcFacClaim,
    schema_id: &str,
    canonicalizer_binding_required: bool,
    result: &CacValidationResult,
    defects: &mut Vec<OverlayDefect>,
) {
    if !canonicalizer_binding_required
        || !has_defect_class(
            result,
            &[
                CacDefectClass::CanonicalizerUnresolved,
                CacDefectClass::CanonicalizerVectorMismatch,
            ],
        )
    {
        return;
    }

    let detail = if claim == TrcFacClaim::TrcFac10 {
        format!(
            "{} canonicalizer vectors must match active snapshot tuple (schema_id '{}')",
            claim.as_str(),
            schema_id
        )
    } else {
        format!(
            "{} canonicalizer binding mismatch at schema_id '{}'",
            claim.as_str(),
            schema_id
        )
    };
    push_defect_if_absent(
        defects,
        OverlayDefect::new(
            claim,
            OverlayDefectClass::CanonicalizerBindingMismatch,
            detail,
        ),
    );
}

fn validate_signature_freshness(
    claim: TrcFacClaim,
    schema_id: &str,
    signature_freshness_required: bool,
    result: &CacValidationResult,
    defects: &mut Vec<OverlayDefect>,
) {
    if !signature_freshness_required
        || !has_defect_class(
            result,
            &[
                CacDefectClass::SignatureFreshnessFailed,
                CacDefectClass::StaleInputDetected,
            ],
        )
    {
        return;
    }

    push_defect_if_absent(
        defects,
        OverlayDefect::new(
            claim,
            OverlayDefectClass::SignatureFreshnessFailed,
            format!(
                "{} signature/freshness check failed at schema_id '{}'",
                claim.as_str(),
                schema_id
            ),
        ),
    );
}

fn validate_trc_fac_10_selector_closure(
    validation_results: &HashMap<String, CacValidationResult>,
    defects: &mut Vec<OverlayDefect>,
) {
    let selector_closure_failed = TRC_FAC_10_SELECTOR_CLOSURE_SCHEMA_IDS
        .iter()
        .any(|schema_id| {
            validation_results.get(*schema_id).is_some_and(|result| {
                has_defect_class(result, &[CacDefectClass::PredicateExecutionFailed])
            })
        });

    if selector_closure_failed {
        push_defect_if_absent(
            defects,
            OverlayDefect::new(
                TrcFacClaim::TrcFac10,
                OverlayDefectClass::Tier2EscalationTriggered,
                "selector closure mismatch or ambient context read evidence -> deny GATE-EIO29-BOUNDS + freeze".to_string(),
            ),
        );
    }
}

/// Validate that a set of `CacValidationResult` values satisfies the overlay
/// requirements for the specified TRC-FAC claims.
#[must_use]
#[allow(clippy::implicit_hasher)]
pub fn validate_overlay_requirements(
    claims: &[TrcFacClaim],
    validation_results: &HashMap<String, CacValidationResult>,
    overlay: &[CacOverlayRequirement],
) -> Vec<OverlayDefect> {
    let mut defects = Vec::new();

    for claim in sorted_unique_claims(claims) {
        let matching_rows: Vec<&CacOverlayRequirement> =
            overlay.iter().filter(|row| row.claim == claim).collect();

        let requirement = match matching_rows.as_slice() {
            [] => {
                push_defect_if_absent(
                    &mut defects,
                    OverlayDefect::new(
                        claim,
                        OverlayDefectClass::Tier2EscalationTriggered,
                        format!("{} overlay row missing; fail-closed deny", claim.as_str()),
                    ),
                );
                continue;
            },
            [requirement] => *requirement,
            _ => {
                push_defect_if_absent(
                    &mut defects,
                    OverlayDefect::new(
                        claim,
                        OverlayDefectClass::Tier2EscalationTriggered,
                        format!(
                            "{} overlay row ambiguous ({} entries); fail-closed deny",
                            claim.as_str(),
                            matching_rows.len()
                        ),
                    ),
                );
                continue;
            },
        };

        let schema_ids = if claim == TrcFacClaim::TrcFac10 {
            trc_fac_10_effective_schema_ids(requirement, &mut defects)
        } else {
            requirement.required_schema_ids.clone()
        };

        if schema_ids.is_empty() {
            push_defect_if_absent(
                &mut defects,
                OverlayDefect::new(
                    claim,
                    OverlayDefectClass::Tier2EscalationTriggered,
                    format!(
                        "{} overlay row has no schema requirements; fail-closed deny",
                        claim.as_str()
                    ),
                ),
            );
            continue;
        }

        let mut unique_schema_ids = Vec::with_capacity(schema_ids.len());
        for schema_id in schema_ids {
            if !unique_schema_ids.contains(&schema_id) {
                unique_schema_ids.push(schema_id);
            }
        }

        for schema_id in &unique_schema_ids {
            validate_schema_requirement(
                claim,
                requirement,
                schema_id,
                validation_results,
                &mut defects,
            );
        }

        if claim == TrcFacClaim::TrcFac10 {
            validate_trc_fac_10_selector_closure(validation_results, &mut defects);
        }

        if claim_has_non_tier2_defect(&defects, claim) && !claim_has_tier2_defect(&defects, claim) {
            push_defect_if_absent(
                &mut defects,
                OverlayDefect::new(
                    claim,
                    OverlayDefectClass::Tier2EscalationTriggered,
                    tier2_escalation_detail(requirement.tier2_escalation).to_string(),
                ),
            );
        }
    }

    defects
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cac::{CacDefect, CacValidationStep};

    fn compatible_result() -> CacValidationResult {
        CacValidationResult {
            compatibility_state: CacCompatibilityState::Compatible,
            defects: Vec::new(),
            executed_steps: Vec::new(),
            short_circuited: false,
        }
    }

    fn blocked_result_with_defect(
        class: CacDefectClass,
        step: CacValidationStep,
    ) -> CacValidationResult {
        CacValidationResult {
            compatibility_state: CacCompatibilityState::Blocked,
            defects: vec![CacDefect::new(class, step, "test defect")],
            executed_steps: vec![step],
            short_circuited: true,
        }
    }

    fn all_promotion_critical_claims() -> [TrcFacClaim; 8] {
        [
            TrcFacClaim::TrcFac01,
            TrcFacClaim::TrcFac02,
            TrcFacClaim::TrcFac07,
            TrcFacClaim::TrcFac10,
            TrcFacClaim::TrcFac12,
            TrcFacClaim::TrcFac14,
            TrcFacClaim::TrcFac15,
            TrcFacClaim::TrcFac16,
        ]
    }

    fn validation_results_for_overlay(
        overlay: &[CacOverlayRequirement],
    ) -> HashMap<String, CacValidationResult> {
        let mut results = HashMap::new();
        for requirement in overlay {
            for schema_id in &requirement.required_schema_ids {
                results
                    .entry(schema_id.clone())
                    .or_insert_with(compatible_result);
            }
        }
        results
    }

    #[test]
    fn test_default_overlay_covers_all_claims() {
        let overlay = default_overlay_requirements();
        let mut claims: Vec<TrcFacClaim> = overlay.iter().map(|row| row.claim).collect();
        claims.sort_unstable();
        claims.dedup();
        assert_eq!(claims, all_promotion_critical_claims());
    }

    #[test]
    fn test_overlay_validation_all_schemas_pass() {
        let overlay = default_overlay_requirements();
        let claims = all_promotion_critical_claims();
        let validation_results = validation_results_for_overlay(&overlay);
        let defects = validate_overlay_requirements(&claims, &validation_results, &overlay);
        assert!(defects.is_empty(), "unexpected defects: {defects:?}");
    }

    #[test]
    fn test_overlay_missing_required_schema_defect() {
        let overlay = default_overlay_requirements();
        let mut validation_results = HashMap::new();
        validation_results.insert(
            "apm2.authority_kernel_decision.v1".to_string(),
            compatible_result(),
        );

        let defects =
            validate_overlay_requirements(&[TrcFacClaim::TrcFac01], &validation_results, &overlay);

        assert!(defects.iter().any(|defect| {
            defect.claim == TrcFacClaim::TrcFac01
                && defect.defect_class == OverlayDefectClass::MissingRequiredSchema
        }));
    }

    #[test]
    fn test_overlay_failed_schema_defect() {
        let overlay = default_overlay_requirements();
        let mut validation_results = HashMap::new();
        validation_results.insert(
            "apm2.time_authority_envelope.v1".to_string(),
            blocked_result_with_defect(
                CacDefectClass::SchemaUnresolved,
                CacValidationStep::SchemaResolution,
            ),
        );
        validation_results.insert(
            "apm2.revocation_frontier_snapshot.v1".to_string(),
            compatible_result(),
        );

        let defects =
            validate_overlay_requirements(&[TrcFacClaim::TrcFac02], &validation_results, &overlay);

        assert!(defects.iter().any(|defect| {
            defect.claim == TrcFacClaim::TrcFac02
                && defect.defect_class == OverlayDefectClass::SchemaValidationFailed
                && defect.detail.contains("apm2.time_authority_envelope.v1")
        }));
    }

    #[test]
    fn test_trc_fac_10_rolespec_binding_required() {
        let mut overlay = default_overlay_requirements();
        let trc_fac_10 = overlay
            .iter_mut()
            .find(|row| row.claim == TrcFacClaim::TrcFac10)
            .expect("TRC-FAC-10 row should exist");
        trc_fac_10.required_schema_ids = vec![
            "cac.reasoning_selector.v1".to_string(),
            "cac.run_receipt.v1".to_string(),
        ];

        let mut validation_results = HashMap::new();
        validation_results.insert("cac.reasoning_selector.v1".to_string(), compatible_result());
        validation_results.insert("cac.run_receipt.v1".to_string(), compatible_result());

        let defects =
            validate_overlay_requirements(&[TrcFacClaim::TrcFac10], &validation_results, &overlay);

        for schema_id in [
            "cac.holon_contract.v1",
            "cac.context_pack_spec.v1",
            "cac.context_pack_manifest.v1",
        ] {
            assert!(defects.iter().any(|defect| {
                defect.claim == TrcFacClaim::TrcFac10
                    && defect.defect_class == OverlayDefectClass::MissingRequiredSchema
                    && defect.detail.contains(schema_id)
            }));
        }
    }

    #[test]
    fn test_tier2_escalation_behavior() {
        let overlay = default_overlay_requirements();
        for row in &overlay {
            if row.claim == TrcFacClaim::TrcFac16 {
                assert_eq!(
                    row.tier2_escalation,
                    Tier2FailClosedBehavior::DenyFreezeHalt
                );
            } else {
                assert_eq!(row.tier2_escalation, Tier2FailClosedBehavior::DenyAndFreeze);
            }
        }
    }

    #[test]
    fn test_overlay_defect_serialization() {
        let defect = OverlayDefect {
            claim: TrcFacClaim::TrcFac12,
            defect_class: OverlayDefectClass::CanonicalizerBindingMismatch,
            detail: "canonicalizer mismatch for test".to_string(),
        };

        let encoded = serde_json::to_string(&defect).expect("defect should serialize");
        let decoded: OverlayDefect =
            serde_json::from_str(&encoded).expect("defect should deserialize");

        assert_eq!(decoded, defect);
    }
}
