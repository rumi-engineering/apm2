//! CAC snapshot contract registry and deterministic validation policy.
//!
//! This module implements the RFC-0019 chapter 17
//! `contract_object_registry[]` contract for CAC snapshot objects:
//! schema-qualified rows, deterministic validation order, defect taxonomy,
//! compatibility-state refinement, and Tier2+ escalation behavior.

#![allow(clippy::module_name_repetitions)]

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::determinism::{CANONICALIZER_ID, CANONICALIZER_VERSION};

/// Maximum number of contract rows allowed in a registry.
pub const MAX_CONTRACT_REGISTRY_ENTRIES: usize = 128;

/// Maximum number of defects retained in validation outputs.
pub const MAX_CAC_DEFECTS: usize = 128;

/// Digest algorithm used by CAC snapshot contract rows.
pub const CAC_DIGEST_ALGORITHM_BLAKE3: &str = "blake3";

/// Digest field name required for snapshot object bindings.
pub const CAC_DIGEST_FIELD_OBJECT: &str = "object_digest";

/// Canonicalizer vectors reference bound to snapshot rows.
pub const CAC_CANONICALIZER_VECTORS_REF: &str = "dcp://apm2.cac/canonicalizer/vectors@v1";

/// Signature binding reference for objects that require signature material.
pub const SIGNATURE_SET_REQUIRED_REF: &str = "signature_set.required";

/// Signature binding reference for objects that do not require signature
/// material.
pub const SIGNATURE_SET_NOT_REQUIRED_REF: &str = "signature_set.not_required";

/// Freshness/window binding reference for objects that require time-window
/// validation.
pub const WINDOW_OR_TTL_REQUIRED_REF: &str = "window_or_ttl.required";

/// Freshness/window binding reference for objects that do not require
/// time-window validation.
pub const WINDOW_OR_TTL_NOT_REQUIRED_REF: &str = "window_or_ttl.not_required";

/// Registry-level defects emitted while verifying contract completeness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum RegistryDefect {
    /// A required schema was not present in the registry.
    MissingRequiredSchema {
        /// Missing schema identifier.
        schema_id: String,
    },
    /// Multiple entries claim the same schema identifier.
    DuplicateSchemaId {
        /// Duplicated schema identifier.
        schema_id: String,
    },
    /// Multiple entries claim the same schema stable identifier.
    DuplicateStableId {
        /// Duplicated schema stable identifier.
        schema_stable_id: String,
    },
    /// Registry exceeds the configured maximum row count.
    EntryLimitExceeded {
        /// Actual entry count.
        count: usize,
        /// Allowed maximum entry count.
        max: usize,
    },
}

/// Schema-qualified contract object registry entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContractObjectRegistryEntry {
    /// Stable object identifier in the snapshot contract row.
    pub object_id: String,
    /// Semantic object kind (`snapshot.report`, `time.envelope`, etc.).
    pub kind: String,
    /// Schema identifier (`apm2.*.v1`, `cac.*.v1`).
    pub schema_id: String,
    /// Schema major version used for compatibility checks.
    pub schema_major: u32,
    /// Stable schema identifier across versions.
    pub schema_stable_id: String,
    /// Required digest algorithm for this object.
    pub digest_algorithm: String,
    /// Field name used to bind object digest values.
    pub digest_field: String,
    /// Whether digest presence is mandatory for this object.
    pub digest_required: bool,
    /// Required canonicalizer identifier.
    pub canonicalizer_id: String,
    /// Required canonicalizer semantic version.
    pub canonicalizer_version: String,
    /// Reference to canonicalizer vectors required for compatibility.
    pub canonicalizer_vectors_ref: String,
    /// Signature set binding requirement reference.
    pub signature_set_ref: String,
    /// Window/TTL freshness binding requirement reference.
    pub window_or_ttl_ref: String,
}

/// Contract object registry containing schema-qualified snapshot rows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContractObjectRegistry {
    entries: Vec<ContractObjectRegistryEntry>,
}

impl ContractObjectRegistry {
    /// Creates a registry and validates completeness constraints.
    ///
    /// # Errors
    ///
    /// Returns a bounded list of [`RegistryDefect`] values when the registry is
    /// incomplete or structurally invalid.
    pub fn new(entries: Vec<ContractObjectRegistryEntry>) -> Result<Self, Vec<RegistryDefect>> {
        let registry = Self { entries };
        registry.validate_completeness().map(|()| registry)
    }

    /// Returns the canonical default snapshot contract registry.
    #[must_use]
    pub fn default_registry() -> Self {
        let registry = Self {
            entries: default_contract_registry_entries(),
        };
        debug_assert!(registry.validate_completeness().is_ok());
        registry
    }

    /// Returns immutable access to all registry rows.
    #[must_use]
    pub fn entries(&self) -> &[ContractObjectRegistryEntry] {
        &self.entries
    }

    /// Looks up a registry row by `schema_id`.
    #[must_use]
    pub fn lookup_by_schema_id(&self, id: &str) -> Option<&ContractObjectRegistryEntry> {
        self.entries.iter().find(|entry| entry.schema_id == id)
    }

    /// Looks up a registry row by `schema_stable_id`.
    #[must_use]
    pub fn lookup_by_stable_id(&self, stable_id: &str) -> Option<&ContractObjectRegistryEntry> {
        self.entries
            .iter()
            .find(|entry| entry.schema_stable_id == stable_id)
    }

    /// Validates that all required rows are present and structurally unique.
    ///
    /// # Errors
    ///
    /// Returns a bounded defect list when the registry is incomplete or
    /// contains duplicate schema/stable identifiers.
    pub fn validate_completeness(&self) -> Result<(), Vec<RegistryDefect>> {
        let mut defects = Vec::new();

        if self.entries.len() > MAX_CONTRACT_REGISTRY_ENTRIES {
            push_registry_defect(
                &mut defects,
                RegistryDefect::EntryLimitExceeded {
                    count: self.entries.len(),
                    max: MAX_CONTRACT_REGISTRY_ENTRIES,
                },
            );
        }

        let mut schema_ids = BTreeSet::new();
        let mut stable_ids = BTreeSet::new();

        for entry in &self.entries {
            if !schema_ids.insert(entry.schema_id.clone()) {
                push_registry_defect(
                    &mut defects,
                    RegistryDefect::DuplicateSchemaId {
                        schema_id: entry.schema_id.clone(),
                    },
                );
            }

            if !stable_ids.insert(entry.schema_stable_id.clone()) {
                push_registry_defect(
                    &mut defects,
                    RegistryDefect::DuplicateStableId {
                        schema_stable_id: entry.schema_stable_id.clone(),
                    },
                );
            }
        }

        for schema_id in REQUIRED_CONTRACT_SCHEMA_IDS {
            if self.lookup_by_schema_id(schema_id).is_none() {
                push_registry_defect(
                    &mut defects,
                    RegistryDefect::MissingRequiredSchema {
                        schema_id: (*schema_id).to_string(),
                    },
                );
            }
        }

        if defects.is_empty() {
            Ok(())
        } else {
            Err(defects)
        }
    }
}

/// Deterministic CAC validation steps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CacValidationStep {
    /// Resolve schema identity and major-compatibility bindings.
    SchemaResolution,
    /// Validate canonicalizer tuple compatibility.
    CanonicalizerCompatibility,
    /// Verify signature and freshness validity.
    SignatureFreshness,
    /// Verify digest completeness and equality constraints.
    DigestCompleteness,
    /// Execute predicate-level semantic checks.
    PredicateExecution,
}

/// Mandatory deterministic step order for CAC validation.
pub const CAC_VALIDATION_ORDER: [CacValidationStep; 5] = [
    CacValidationStep::SchemaResolution,
    CacValidationStep::CanonicalizerCompatibility,
    CacValidationStep::SignatureFreshness,
    CacValidationStep::DigestCompleteness,
    CacValidationStep::PredicateExecution,
];

/// CAC defect classes for snapshot contract validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum CacDefectClass {
    /// `schema_id` did not resolve in registry.
    SchemaUnresolved,
    /// `schema_major` is incompatible with registry row.
    SchemaVersionIncompatible,
    /// Registry stable-id drift requires adjudication.
    SchemaRegistryDriftAmbiguous,
    /// Canonicalizer identifier did not resolve.
    CanonicalizerUnresolved,
    /// Canonicalizer vectors/version mismatch.
    CanonicalizerVectorMismatch,
    /// Required digest is absent or incomplete.
    DigestIncomplete,
    /// Recomputed or declared digest binding mismatch.
    DigestMismatch,
    /// Signature verification failed.
    SignatureFreshnessFailed,
    /// Input failed freshness checks.
    StaleInputDetected,
    /// Validation did not execute in deterministic order.
    ValidationOrderViolation,
    /// Predicate execution failed.
    PredicateExecutionFailed,
    /// Object kind was not recognized for resolved schema.
    UnknownObjectKind,
}

impl CacDefectClass {
    const fn compatibility_state(self) -> CacCompatibilityState {
        match self {
            Self::SchemaUnresolved
            | Self::SchemaVersionIncompatible
            | Self::SchemaRegistryDriftAmbiguous
            | Self::CanonicalizerUnresolved
            | Self::CanonicalizerVectorMismatch
            | Self::DigestIncomplete
            | Self::DigestMismatch
            | Self::SignatureFreshnessFailed
            | Self::StaleInputDetected
            | Self::ValidationOrderViolation
            | Self::PredicateExecutionFailed
            | Self::UnknownObjectKind => CacCompatibilityState::Blocked,
        }
    }
}

/// CAC compatibility-state refinement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(u8)]
#[serde(rename_all = "snake_case")]
pub enum CacCompatibilityState {
    /// All checks pass and no defects are emitted.
    Compatible = 0,
    /// Inputs are semantically valid but drift requires adjudication.
    Suspect    = 1,
    /// Critical defect class present or checks are unevaluable.
    Blocked    = 2,
}

impl CacCompatibilityState {
    /// Returns `true` when admission is allowed.
    #[must_use]
    pub const fn is_admissible(self) -> bool {
        matches!(self, Self::Compatible)
    }
}

/// CAC defect emitted by deterministic validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CacDefect {
    /// Defect classification.
    pub class: CacDefectClass,
    /// Validation step that emitted this defect.
    pub step: CacValidationStep,
    /// Compatibility-state impact for this defect.
    pub compatibility_state: CacCompatibilityState,
    /// Human-readable defect detail.
    pub detail: String,
}

impl CacDefect {
    /// Creates a new defect with compatibility-state inferred from its class.
    #[must_use]
    pub fn new(class: CacDefectClass, step: CacValidationStep, detail: impl Into<String>) -> Self {
        Self {
            class,
            step,
            compatibility_state: class.compatibility_state(),
            detail: detail.into(),
        }
    }
}

/// Signature verification status for a CAC object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CacSignatureStatus {
    /// Signature checks passed.
    Valid,
    /// Signature checks failed.
    Invalid,
}

/// Freshness status for a CAC object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CacFreshnessStatus {
    /// Input is fresh enough for validation.
    Fresh,
    /// Input is stale/out-of-window.
    Stale,
}

/// Predicate execution status for a CAC object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CacPredicateStatus {
    /// Predicate checks passed.
    Passed,
    /// Predicate checks failed.
    Failed,
}

/// `RoleSpec` context-injection binding for deterministic CAC gates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleSpecContextBinding {
    /// Hash of `RoleSpec` contract bytes.
    pub role_spec_hash: [u8; 32],
    /// Hash of `ContextPackSpec` contract bytes.
    pub context_pack_spec_hash: [u8; 32],
    /// Hash of `ContextPackManifest` contract bytes.
    pub context_pack_manifest_hash: [u8; 32],
    /// Optional hash of reasoning selector closure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reasoning_selector_hash: Option<[u8; 32]>,
    /// Optional hash of budget profile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget_profile_hash: Option<[u8; 32]>,
}

/// Errors for deterministic `RoleSpec` context binding validation.
#[derive(Debug, Clone, PartialEq, Eq, Error, Serialize, Deserialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum RoleSpecContextBindingError {
    /// A required or present optional hash was all-zero.
    #[error("hash field '{field}' must be non-zero")]
    ZeroHash {
        /// Name of the zero hash field.
        field: String,
    },
}

impl RoleSpecContextBinding {
    /// Validates that all required hash bindings are non-zero and
    /// deterministic.
    ///
    /// # Errors
    ///
    /// Returns [`RoleSpecContextBindingError::ZeroHash`] for any zero hash.
    pub fn validate(&self) -> Result<(), RoleSpecContextBindingError> {
        ensure_non_zero_hash("role_spec_hash", &self.role_spec_hash)?;
        ensure_non_zero_hash("context_pack_spec_hash", &self.context_pack_spec_hash)?;
        ensure_non_zero_hash(
            "context_pack_manifest_hash",
            &self.context_pack_manifest_hash,
        )?;

        if let Some(hash) = self.reasoning_selector_hash {
            ensure_non_zero_hash("reasoning_selector_hash", &hash)?;
        }

        if let Some(hash) = self.budget_profile_hash {
            ensure_non_zero_hash("budget_profile_hash", &hash)?;
        }

        Ok(())
    }
}

/// Validation input for a single CAC object row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CacObject {
    /// Snapshot object identifier.
    pub object_id: String,
    /// Snapshot object kind.
    pub kind: String,
    /// Object schema identifier.
    pub schema_id: String,
    /// Object schema major version.
    pub schema_major: u32,
    /// Object schema stable identifier.
    pub schema_stable_id: String,
    /// Object digest value when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_digest: Option<[u8; 32]>,
    /// Expected digest for digest-equality constraints.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_digest: Option<[u8; 32]>,
    /// Digest algorithm used for this object.
    pub digest_algorithm: String,
    /// Canonicalizer identifier used by object encoding.
    pub canonicalizer_id: String,
    /// Canonicalizer version used by object encoding.
    pub canonicalizer_version: String,
    /// Canonicalizer vectors reference for object encoding.
    pub canonicalizer_vectors_ref: String,
    /// Signature verification status.
    pub signature_status: CacSignatureStatus,
    /// Freshness evaluation status.
    pub freshness_status: CacFreshnessStatus,
    /// Predicate execution status.
    pub predicate_status: CacPredicateStatus,
    /// Optional declared order emitted by caller for order-integrity checks.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub declared_validation_order: Vec<CacValidationStep>,
    /// Optional deterministic `RoleSpec` context injection binding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role_spec_context_binding: Option<RoleSpecContextBinding>,
}

impl CacObject {
    /// Builds a validation input seeded from a registry row.
    #[must_use]
    pub fn from_registry_entry(entry: &ContractObjectRegistryEntry) -> Self {
        let digest = [0xA5; 32];
        Self {
            object_id: entry.object_id.clone(),
            kind: entry.kind.clone(),
            schema_id: entry.schema_id.clone(),
            schema_major: entry.schema_major,
            schema_stable_id: entry.schema_stable_id.clone(),
            object_digest: Some(digest),
            expected_digest: Some(digest),
            digest_algorithm: entry.digest_algorithm.clone(),
            canonicalizer_id: entry.canonicalizer_id.clone(),
            canonicalizer_version: entry.canonicalizer_version.clone(),
            canonicalizer_vectors_ref: entry.canonicalizer_vectors_ref.clone(),
            signature_status: CacSignatureStatus::Valid,
            freshness_status: CacFreshnessStatus::Fresh,
            predicate_status: CacPredicateStatus::Passed,
            declared_validation_order: Vec::new(),
            role_spec_context_binding: None,
        }
    }
}

/// Result from deterministic CAC contract validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CacValidationResult {
    /// Aggregate compatibility state after all executed checks.
    pub compatibility_state: CacCompatibilityState,
    /// Bounded defect list emitted during validation.
    pub defects: Vec<CacDefect>,
    /// Steps executed before completion or short-circuit.
    pub executed_steps: Vec<CacValidationStep>,
    /// Whether validation short-circuited on a blocked defect.
    pub short_circuited: bool,
}

impl CacValidationResult {
    /// Returns `true` only when the object is fully compatible.
    #[must_use]
    pub const fn is_admissible(&self) -> bool {
        self.compatibility_state.is_admissible()
    }
}

/// Escalation action for Tier2+ unresolved CAC defects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EscalationAction {
    /// Continue processing without freeze/halt transition.
    Continue,
    /// Freeze promotion-critical progression until adjudication.
    FreezePromotionPaths,
    /// Escalate to emergency halt.
    Halt,
}

/// Tier2+ freeze/halt escalation policy for unresolved CAC defects.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tier2EscalationPolicy {
    /// Freeze promotion-critical paths when any non-compatible defects are
    /// present.
    pub freeze_on_blocked: bool,
    /// Halt when unresolved defects remain unresolved past deadline.
    pub halt_on_unresolved_deadline: bool,
    /// Maximum allowed unresolved duration before halt escalation.
    pub adjudication_deadline_secs: u64,
}

impl Default for Tier2EscalationPolicy {
    fn default() -> Self {
        Self::default_strict()
    }
}

impl Tier2EscalationPolicy {
    /// Strict Tier2+ defaults.
    #[must_use]
    pub const fn default_strict() -> Self {
        Self {
            freeze_on_blocked: true,
            halt_on_unresolved_deadline: true,
            adjudication_deadline_secs: 3_600,
        }
    }

    /// Returns escalation policy by risk tier (`>= 2` is strict Tier2+).
    #[must_use]
    pub const fn for_risk_tier(risk_tier: u8) -> Self {
        if risk_tier >= 2 {
            Self::default_strict()
        } else {
            Self {
                freeze_on_blocked: false,
                halt_on_unresolved_deadline: false,
                adjudication_deadline_secs: 3_600,
            }
        }
    }

    /// Evaluates escalation action from current defects and unresolved age.
    #[must_use]
    pub fn evaluate(&self, defects: &[CacDefect], unresolved_for_secs: u64) -> EscalationAction {
        let compatibility_state = defects
            .iter()
            .map(|defect| defect.compatibility_state)
            .max()
            .unwrap_or(CacCompatibilityState::Compatible);

        if compatibility_state == CacCompatibilityState::Compatible || !self.freeze_on_blocked {
            return EscalationAction::Continue;
        }

        if self.halt_on_unresolved_deadline
            && unresolved_for_secs >= self.adjudication_deadline_secs
        {
            EscalationAction::Halt
        } else {
            EscalationAction::FreezePromotionPaths
        }
    }
}

/// Validates a CAC object against deterministic contract checks.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn validate_cac_contract(
    registry: &ContractObjectRegistry,
    object: &CacObject,
) -> CacValidationResult {
    let mut defects = Vec::new();
    let mut executed_steps = Vec::with_capacity(CAC_VALIDATION_ORDER.len());
    let mut compatibility_state = CacCompatibilityState::Compatible;
    let mut resolved_entry: Option<&ContractObjectRegistryEntry> = None;
    let mut short_circuited = false;

    for step in CAC_VALIDATION_ORDER {
        executed_steps.push(step);

        match step {
            CacValidationStep::SchemaResolution => {
                if !object.declared_validation_order.is_empty()
                    && object.declared_validation_order.as_slice() != CAC_VALIDATION_ORDER
                {
                    update_with_defect(
                        &mut defects,
                        &mut compatibility_state,
                        CacDefect::new(
                            CacDefectClass::ValidationOrderViolation,
                            step,
                            "declared validation order does not match CAC_VALIDATION_ORDER",
                        ),
                    );
                }

                if let Some(entry) = registry.lookup_by_schema_id(&object.schema_id) {
                    resolved_entry = Some(entry);

                    if entry.kind != object.kind {
                        update_with_defect(
                            &mut defects,
                            &mut compatibility_state,
                            CacDefect::new(
                                CacDefectClass::UnknownObjectKind,
                                step,
                                format!(
                                    "kind mismatch: expected '{}', got '{}'",
                                    entry.kind, object.kind
                                ),
                            ),
                        );
                    }

                    if entry.schema_major != object.schema_major {
                        update_with_defect(
                            &mut defects,
                            &mut compatibility_state,
                            CacDefect::new(
                                CacDefectClass::SchemaVersionIncompatible,
                                step,
                                format!(
                                    "schema_major mismatch: expected {}, got {}",
                                    entry.schema_major, object.schema_major
                                ),
                            ),
                        );
                    }

                    if entry.schema_stable_id != object.schema_stable_id {
                        update_with_defect(
                            &mut defects,
                            &mut compatibility_state,
                            CacDefect::new(
                                CacDefectClass::SchemaRegistryDriftAmbiguous,
                                step,
                                format!(
                                    "schema_stable_id drift: expected '{}', got '{}'",
                                    entry.schema_stable_id, object.schema_stable_id
                                ),
                            ),
                        );
                    }
                } else {
                    update_with_defect(
                        &mut defects,
                        &mut compatibility_state,
                        CacDefect::new(
                            CacDefectClass::SchemaUnresolved,
                            step,
                            format!(
                                "schema_id '{}' is not in contract registry",
                                object.schema_id
                            ),
                        ),
                    );
                }
            },
            CacValidationStep::CanonicalizerCompatibility => {
                if let Some(entry) = resolved_entry {
                    if object.canonicalizer_id != entry.canonicalizer_id {
                        update_with_defect(
                            &mut defects,
                            &mut compatibility_state,
                            CacDefect::new(
                                CacDefectClass::CanonicalizerUnresolved,
                                step,
                                format!(
                                    "canonicalizer_id mismatch: expected '{}', got '{}'",
                                    entry.canonicalizer_id, object.canonicalizer_id
                                ),
                            ),
                        );
                    }

                    if object.canonicalizer_version != entry.canonicalizer_version
                        || object.canonicalizer_vectors_ref != entry.canonicalizer_vectors_ref
                    {
                        update_with_defect(
                            &mut defects,
                            &mut compatibility_state,
                            CacDefect::new(
                                CacDefectClass::CanonicalizerVectorMismatch,
                                step,
                                "canonicalizer version/vectors mismatch against registry tuple",
                            ),
                        );
                    }
                } else {
                    update_with_defect(
                        &mut defects,
                        &mut compatibility_state,
                        CacDefect::new(
                            CacDefectClass::SchemaUnresolved,
                            step,
                            "schema must resolve before canonicalizer checks",
                        ),
                    );
                }
            },
            CacValidationStep::SignatureFreshness => {
                if object.signature_status == CacSignatureStatus::Invalid {
                    update_with_defect(
                        &mut defects,
                        &mut compatibility_state,
                        CacDefect::new(
                            CacDefectClass::SignatureFreshnessFailed,
                            step,
                            "signature verification failed",
                        ),
                    );
                }

                if object.freshness_status == CacFreshnessStatus::Stale {
                    update_with_defect(
                        &mut defects,
                        &mut compatibility_state,
                        CacDefect::new(
                            CacDefectClass::StaleInputDetected,
                            step,
                            "object input is stale for required window/ttl",
                        ),
                    );
                }
            },
            CacValidationStep::DigestCompleteness => {
                if let Some(entry) = resolved_entry {
                    if entry.digest_required
                        && object.object_digest.as_ref().is_none_or(is_zero_hash)
                    {
                        update_with_defect(
                            &mut defects,
                            &mut compatibility_state,
                            CacDefect::new(
                                CacDefectClass::DigestIncomplete,
                                step,
                                "required object_digest is missing or zero",
                            ),
                        );
                    }

                    if object.digest_algorithm != entry.digest_algorithm {
                        update_with_defect(
                            &mut defects,
                            &mut compatibility_state,
                            CacDefect::new(
                                CacDefectClass::DigestMismatch,
                                step,
                                format!(
                                    "digest algorithm mismatch: expected '{}', got '{}'",
                                    entry.digest_algorithm, object.digest_algorithm
                                ),
                            ),
                        );
                    }

                    if let Some(expected_digest) = object.expected_digest {
                        if object.object_digest != Some(expected_digest) {
                            update_with_defect(
                                &mut defects,
                                &mut compatibility_state,
                                CacDefect::new(
                                    CacDefectClass::DigestMismatch,
                                    step,
                                    "object_digest does not match expected digest",
                                ),
                            );
                        }
                    }
                } else {
                    update_with_defect(
                        &mut defects,
                        &mut compatibility_state,
                        CacDefect::new(
                            CacDefectClass::SchemaUnresolved,
                            step,
                            "schema must resolve before digest checks",
                        ),
                    );
                }
            },
            CacValidationStep::PredicateExecution => {
                if let Some(binding) = &object.role_spec_context_binding {
                    if let Err(error) = binding.validate() {
                        update_with_defect(
                            &mut defects,
                            &mut compatibility_state,
                            CacDefect::new(
                                CacDefectClass::PredicateExecutionFailed,
                                step,
                                format!("RoleSpec context binding invalid: {error}"),
                            ),
                        );
                    }
                }

                if object.predicate_status == CacPredicateStatus::Failed {
                    update_with_defect(
                        &mut defects,
                        &mut compatibility_state,
                        CacDefect::new(
                            CacDefectClass::PredicateExecutionFailed,
                            step,
                            "predicate execution failed",
                        ),
                    );
                }
            },
        }

        if compatibility_state == CacCompatibilityState::Blocked {
            short_circuited = true;
            break;
        }
    }

    CacValidationResult {
        compatibility_state,
        defects,
        executed_steps,
        short_circuited,
    }
}

fn update_with_defect(
    defects: &mut Vec<CacDefect>,
    compatibility_state: &mut CacCompatibilityState,
    defect: CacDefect,
) {
    *compatibility_state = (*compatibility_state).max(defect.compatibility_state);
    if defects.len() < MAX_CAC_DEFECTS {
        defects.push(defect);
    }
}

fn push_registry_defect(defects: &mut Vec<RegistryDefect>, defect: RegistryDefect) {
    if defects.len() < MAX_CAC_DEFECTS {
        defects.push(defect);
    }
}

fn ensure_non_zero_hash(field: &str, hash: &[u8; 32]) -> Result<(), RoleSpecContextBindingError> {
    if is_zero_hash(hash) {
        return Err(RoleSpecContextBindingError::ZeroHash {
            field: field.to_string(),
        });
    }
    Ok(())
}

fn is_zero_hash(hash: &[u8; 32]) -> bool {
    hash.iter().all(|byte| *byte == 0)
}

fn default_registry_entry(
    object_id: &str,
    kind: &str,
    schema_id: &str,
    signature_set_ref: &str,
    window_or_ttl_ref: &str,
) -> ContractObjectRegistryEntry {
    ContractObjectRegistryEntry {
        object_id: object_id.to_string(),
        kind: kind.to_string(),
        schema_id: schema_id.to_string(),
        schema_major: 1,
        schema_stable_id: format!("dcp://apm2.local/schemas/{schema_id}@v1"),
        digest_algorithm: CAC_DIGEST_ALGORITHM_BLAKE3.to_string(),
        digest_field: CAC_DIGEST_FIELD_OBJECT.to_string(),
        digest_required: true,
        canonicalizer_id: CANONICALIZER_ID.to_string(),
        canonicalizer_version: CANONICALIZER_VERSION.to_string(),
        canonicalizer_vectors_ref: CAC_CANONICALIZER_VECTORS_REF.to_string(),
        signature_set_ref: signature_set_ref.to_string(),
        window_or_ttl_ref: window_or_ttl_ref.to_string(),
    }
}

#[allow(clippy::too_many_lines)]
fn default_contract_registry_entries() -> Vec<ContractObjectRegistryEntry> {
    vec![
        default_registry_entry(
            "PCACSnapshotReportV1",
            "snapshot.report",
            "apm2.pcac_snapshot_report.v1",
            SIGNATURE_SET_REQUIRED_REF,
            WINDOW_OR_TTL_NOT_REQUIRED_REF,
        ),
        default_registry_entry(
            "AuthorityKernelDecisionV1",
            "authority.kernel.decision",
            "apm2.authority_kernel_decision.v1",
            SIGNATURE_SET_REQUIRED_REF,
            WINDOW_OR_TTL_NOT_REQUIRED_REF,
        ),
        default_registry_entry(
            "AuthorityChainEntryV1",
            "authority.chain.entry",
            "apm2.authority_chain_entry.v1",
            SIGNATURE_SET_REQUIRED_REF,
            WINDOW_OR_TTL_NOT_REQUIRED_REF,
        ),
        default_registry_entry(
            "EpochSealV1",
            "epoch.seal",
            "apm2.epoch_seal.v1",
            SIGNATURE_SET_REQUIRED_REF,
            WINDOW_OR_TTL_REQUIRED_REF,
        ),
        default_registry_entry(
            "BoundaryFlowPolicyV1",
            "boundary.flow.policy",
            "apm2.boundary_flow_policy.v1",
            SIGNATURE_SET_REQUIRED_REF,
            WINDOW_OR_TTL_NOT_REQUIRED_REF,
        ),
        default_registry_entry(
            "ProjectionDiffProofV1",
            "projection.diff.proof",
            "apm2.projection_diff_proof.v1",
            SIGNATURE_SET_REQUIRED_REF,
            WINDOW_OR_TTL_NOT_REQUIRED_REF,
        ),
        default_registry_entry(
            "DelegationMeetComputationReceiptV1",
            "delegation.meet.receipt",
            "apm2.delegation_meet_computation_receipt.v1",
            SIGNATURE_SET_REQUIRED_REF,
            WINDOW_OR_TTL_NOT_REQUIRED_REF,
        ),
        default_registry_entry(
            "DelegationSatisfiabilityReceiptV1",
            "delegation.satisfiability.receipt",
            "apm2.delegation_satisfiability_receipt.v1",
            SIGNATURE_SET_REQUIRED_REF,
            WINDOW_OR_TTL_NOT_REQUIRED_REF,
        ),
        default_registry_entry(
            "EconomicsConstraintProfileV1",
            "economics.constraint.profile",
            "apm2.economics_constraint_profile.v1",
            SIGNATURE_SET_REQUIRED_REF,
            WINDOW_OR_TTL_NOT_REQUIRED_REF,
        ),
        default_registry_entry(
            "RecoverabilityProfileV1",
            "recoverability.profile",
            "apm2.recoverability_profile.v1",
            SIGNATURE_SET_REQUIRED_REF,
            WINDOW_OR_TTL_NOT_REQUIRED_REF,
        ),
        default_registry_entry(
            "AutonomicRemediationContractV1",
            "autonomic.remediation.contract",
            "apm2.autonomic_remediation_contract.v1",
            SIGNATURE_SET_REQUIRED_REF,
            WINDOW_OR_TTL_NOT_REQUIRED_REF,
        ),
        default_registry_entry(
            "RoleSpecContractV1",
            "role.spec.contract",
            "cac.holon_contract.v1",
            SIGNATURE_SET_REQUIRED_REF,
            WINDOW_OR_TTL_NOT_REQUIRED_REF,
        ),
        default_registry_entry(
            "RoleContextPackSpecV1",
            "context_pack.spec",
            "cac.context_pack_spec.v1",
            SIGNATURE_SET_REQUIRED_REF,
            WINDOW_OR_TTL_NOT_REQUIRED_REF,
        ),
        default_registry_entry(
            "RoleContextPackManifestV1",
            "context_pack.manifest",
            "cac.context_pack_manifest.v1",
            SIGNATURE_SET_REQUIRED_REF,
            WINDOW_OR_TTL_NOT_REQUIRED_REF,
        ),
        default_registry_entry(
            "RoleReasoningSelectorV1",
            "reasoning.selector",
            "cac.reasoning_selector.v1",
            SIGNATURE_SET_REQUIRED_REF,
            WINDOW_OR_TTL_NOT_REQUIRED_REF,
        ),
        default_registry_entry(
            "RoleBudgetProfileV1",
            "budget.profile",
            "cac.budget_profile.v1",
            SIGNATURE_SET_REQUIRED_REF,
            WINDOW_OR_TTL_NOT_REQUIRED_REF,
        ),
        default_registry_entry(
            "RoleRunReceiptV1",
            "receipt.run",
            "cac.run_receipt.v1",
            SIGNATURE_SET_REQUIRED_REF,
            WINDOW_OR_TTL_REQUIRED_REF,
        ),
        default_registry_entry(
            "CacDefectRecordV1",
            "defect.record",
            "cac.defect_record.v1",
            SIGNATURE_SET_REQUIRED_REF,
            WINDOW_OR_TTL_NOT_REQUIRED_REF,
        ),
        default_registry_entry(
            "ProjectionSinkContinuityProfileV1",
            "projection.sink.continuity.profile",
            "apm2.projection_sink_continuity_profile.v1",
            SIGNATURE_SET_REQUIRED_REF,
            WINDOW_OR_TTL_REQUIRED_REF,
        ),
        default_registry_entry(
            "TimeAuthorityEnvelopeV1",
            "time.envelope",
            "apm2.time_authority_envelope.v1",
            SIGNATURE_SET_REQUIRED_REF,
            WINDOW_OR_TTL_REQUIRED_REF,
        ),
        default_registry_entry(
            "TemporalSloProfileV1",
            "temporal.slo.profile",
            "apm2.temporal_slo_profile.v1",
            SIGNATURE_SET_REQUIRED_REF,
            WINDOW_OR_TTL_REQUIRED_REF,
        ),
        default_registry_entry(
            "ProjectionContinuityWindowV1",
            "projection.continuity.window",
            "apm2.projection_continuity_window.v1",
            SIGNATURE_SET_REQUIRED_REF,
            WINDOW_OR_TTL_REQUIRED_REF,
        ),
        default_registry_entry(
            "ProjectionCompromiseSignalV1",
            "projection.compromise.signal",
            "apm2.projection_compromise_signal.v1",
            SIGNATURE_SET_REQUIRED_REF,
            WINDOW_OR_TTL_REQUIRED_REF,
        ),
        default_registry_entry(
            "SourceTrustSnapshotV1",
            "source.trust.snapshot",
            "apm2.source_trust_snapshot.v1",
            SIGNATURE_SET_REQUIRED_REF,
            WINDOW_OR_TTL_NOT_REQUIRED_REF,
        ),
        default_registry_entry(
            "CodebaseRecoveryProfileV1",
            "codebase.recovery.profile",
            "apm2.codebase_recovery_profile.v1",
            SIGNATURE_SET_REQUIRED_REF,
            WINDOW_OR_TTL_NOT_REQUIRED_REF,
        ),
        default_registry_entry(
            "ErasureRecoveryReceiptV1",
            "erasure.recovery.receipt",
            "apm2.erasure_recovery_receipt.v1",
            SIGNATURE_SET_REQUIRED_REF,
            WINDOW_OR_TTL_REQUIRED_REF,
        ),
        default_registry_entry(
            "BftRecoveryQuorumCertificateV1",
            "bft.recovery.quorum.certificate",
            "apm2.bft_recovery_quorum_certificate.v1",
            SIGNATURE_SET_REQUIRED_REF,
            WINDOW_OR_TTL_REQUIRED_REF,
        ),
        default_registry_entry(
            "ReplayConvergenceReceiptV1",
            "replay.convergence.receipt",
            "apm2.replay_convergence_receipt.v1",
            SIGNATURE_SET_REQUIRED_REF,
            WINDOW_OR_TTL_REQUIRED_REF,
        ),
        default_registry_entry(
            "RecoveryAdmissibilityReceiptV1",
            "recovery.admissibility.receipt",
            "apm2.recovery_admissibility_receipt.v1",
            SIGNATURE_SET_REQUIRED_REF,
            WINDOW_OR_TTL_REQUIRED_REF,
        ),
        default_registry_entry(
            "TemporalPredicateEvaluatorV1",
            "temporal.evaluator",
            "apm2.temporal_predicate_evaluator.v1",
            SIGNATURE_SET_REQUIRED_REF,
            WINDOW_OR_TTL_REQUIRED_REF,
        ),
        default_registry_entry(
            "RevocationFrontierSnapshotV1",
            "revocation.frontier.snapshot",
            "apm2.revocation_frontier_snapshot.v1",
            SIGNATURE_SET_REQUIRED_REF,
            WINDOW_OR_TTL_REQUIRED_REF,
        ),
        default_registry_entry(
            "LocalMonotonicEmergencyTimeReceiptV1",
            "local.time.emergency.receipt",
            "apm2.local_monotonic_emergency_time_receipt.v1",
            SIGNATURE_SET_REQUIRED_REF,
            WINDOW_OR_TTL_REQUIRED_REF,
        ),
        default_registry_entry(
            "SemanticDiffReportV1",
            "semantic.diff.report",
            "apm2.semantic_diff_report.v1",
            SIGNATURE_SET_REQUIRED_REF,
            WINDOW_OR_TTL_NOT_REQUIRED_REF,
        ),
        default_registry_entry(
            "CryptoAgilityPolicyV1",
            "crypto.agility.policy",
            "apm2.crypto_agility_policy.v1",
            SIGNATURE_SET_REQUIRED_REF,
            WINDOW_OR_TTL_REQUIRED_REF,
        ),
        default_registry_entry(
            "SinkIdentitySnapshotV1",
            "sink.identity.snapshot",
            "apm2.sink_identity_snapshot.v1",
            SIGNATURE_SET_REQUIRED_REF,
            WINDOW_OR_TTL_NOT_REQUIRED_REF,
        ),
        default_registry_entry(
            "ProjectionIsolationPolicyV1",
            "projection.isolation.policy",
            "apm2.projection_isolation_policy.v1",
            SIGNATURE_SET_REQUIRED_REF,
            WINDOW_OR_TTL_NOT_REQUIRED_REF,
        ),
        default_registry_entry(
            "TradeSecretPolicyProfileV1",
            "trade.secret.policy",
            "apm2.trade_secret_policy_profile.v1",
            SIGNATURE_SET_REQUIRED_REF,
            WINDOW_OR_TTL_NOT_REQUIRED_REF,
        ),
        default_registry_entry(
            "VerifierIndependenceProfileV1",
            "verifier.independence.profile",
            "apm2.verifier_independence_profile.v1",
            SIGNATURE_SET_REQUIRED_REF,
            WINDOW_OR_TTL_NOT_REQUIRED_REF,
        ),
        default_registry_entry(
            "EvidenceQualityProfileV1",
            "evidence.quality.profile",
            "apm2.evidence_quality_profile.v1",
            SIGNATURE_SET_REQUIRED_REF,
            WINDOW_OR_TTL_NOT_REQUIRED_REF,
        ),
        default_registry_entry(
            "EvidenceFreshnessSlaV1",
            "evidence.freshness.sla",
            "apm2.evidence_freshness_sla.v1",
            SIGNATURE_SET_REQUIRED_REF,
            WINDOW_OR_TTL_REQUIRED_REF,
        ),
        default_registry_entry(
            "CountermetricProfileV1",
            "countermetric.profile",
            "apm2.countermetric_profile.v1",
            SIGNATURE_SET_REQUIRED_REF,
            WINDOW_OR_TTL_NOT_REQUIRED_REF,
        ),
        default_registry_entry(
            "HardwareTierEnvelopeV1",
            "hardware.tier.envelope",
            "apm2.hardware_tier_envelope.v1",
            SIGNATURE_SET_REQUIRED_REF,
            WINDOW_OR_TTL_NOT_REQUIRED_REF,
        ),
        default_registry_entry(
            "TemporalDisagreementReceiptV1",
            "temporal.disagreement.receipt",
            "apm2.temporal_disagreement_receipt.v1",
            SIGNATURE_SET_REQUIRED_REF,
            WINDOW_OR_TTL_REQUIRED_REF,
        ),
        default_registry_entry(
            "TemporalArbitrationReceiptV1",
            "temporal.arbitration.receipt",
            "apm2.temporal_arbitration_receipt.v1",
            SIGNATURE_SET_REQUIRED_REF,
            WINDOW_OR_TTL_REQUIRED_REF,
        ),
        default_registry_entry(
            "HaltStateReceiptV1",
            "halt.state.receipt",
            "apm2.halt_state_receipt.v1",
            SIGNATURE_SET_REQUIRED_REF,
            WINDOW_OR_TTL_REQUIRED_REF,
        ),
        default_registry_entry(
            "PostCompromiseRecoveryReceiptV1",
            "post_compromise.recovery.receipt",
            "apm2.post_compromise_recovery_receipt.v1",
            SIGNATURE_SET_REQUIRED_REF,
            WINDOW_OR_TTL_REQUIRED_REF,
        ),
        default_registry_entry(
            "OperatorSafetyGuardProfileV1",
            "operator.safety.guard",
            "apm2.operator_safety_guard_profile.v1",
            SIGNATURE_SET_REQUIRED_REF,
            WINDOW_OR_TTL_NOT_REQUIRED_REF,
        ),
        default_registry_entry(
            "AntiEntropyConvergenceReceiptV1",
            "anti_entropy.convergence.receipt",
            "apm2.anti_entropy_convergence_receipt.v1",
            SIGNATURE_SET_REQUIRED_REF,
            WINDOW_OR_TTL_REQUIRED_REF,
        ),
    ]
}

const REQUIRED_CONTRACT_SCHEMA_IDS: &[&str] = &[
    "apm2.pcac_snapshot_report.v1",
    "apm2.authority_kernel_decision.v1",
    "apm2.authority_chain_entry.v1",
    "apm2.epoch_seal.v1",
    "apm2.boundary_flow_policy.v1",
    "apm2.projection_diff_proof.v1",
    "apm2.delegation_meet_computation_receipt.v1",
    "apm2.delegation_satisfiability_receipt.v1",
    "apm2.economics_constraint_profile.v1",
    "apm2.recoverability_profile.v1",
    "apm2.autonomic_remediation_contract.v1",
    "cac.holon_contract.v1",
    "cac.context_pack_spec.v1",
    "cac.context_pack_manifest.v1",
    "cac.reasoning_selector.v1",
    "cac.budget_profile.v1",
    "cac.run_receipt.v1",
    "cac.defect_record.v1",
    "apm2.projection_sink_continuity_profile.v1",
    "apm2.time_authority_envelope.v1",
    "apm2.temporal_slo_profile.v1",
    "apm2.projection_continuity_window.v1",
    "apm2.projection_compromise_signal.v1",
    "apm2.source_trust_snapshot.v1",
    "apm2.codebase_recovery_profile.v1",
    "apm2.erasure_recovery_receipt.v1",
    "apm2.bft_recovery_quorum_certificate.v1",
    "apm2.replay_convergence_receipt.v1",
    "apm2.recovery_admissibility_receipt.v1",
    "apm2.temporal_predicate_evaluator.v1",
    "apm2.revocation_frontier_snapshot.v1",
    "apm2.local_monotonic_emergency_time_receipt.v1",
    "apm2.semantic_diff_report.v1",
    "apm2.crypto_agility_policy.v1",
    "apm2.sink_identity_snapshot.v1",
    "apm2.projection_isolation_policy.v1",
    "apm2.trade_secret_policy_profile.v1",
    "apm2.verifier_independence_profile.v1",
    "apm2.evidence_quality_profile.v1",
    "apm2.evidence_freshness_sla.v1",
    "apm2.countermetric_profile.v1",
    "apm2.hardware_tier_envelope.v1",
    "apm2.temporal_disagreement_receipt.v1",
    "apm2.temporal_arbitration_receipt.v1",
    "apm2.halt_state_receipt.v1",
    "apm2.post_compromise_recovery_receipt.v1",
    "apm2.operator_safety_guard_profile.v1",
    "apm2.anti_entropy_convergence_receipt.v1",
];

#[cfg(test)]
#[allow(missing_docs)]
mod tests {
    use super::*;

    fn sample_blocked_defect() -> CacDefect {
        CacDefect::new(
            CacDefectClass::SchemaUnresolved,
            CacValidationStep::SchemaResolution,
            "test blocked defect",
        )
    }

    fn sample_suspect_defect() -> CacDefect {
        CacDefect {
            class: CacDefectClass::SchemaRegistryDriftAmbiguous,
            step: CacValidationStep::SchemaResolution,
            compatibility_state: CacCompatibilityState::Suspect,
            detail: "test suspect defect".to_string(),
        }
    }

    #[test]
    fn test_default_registry_complete() {
        let registry = ContractObjectRegistry::default_registry();
        assert!(registry.validate_completeness().is_ok());
        assert!(registry.entries().len() >= REQUIRED_CONTRACT_SCHEMA_IDS.len());
    }

    #[test]
    fn test_registry_lookup_by_schema_id() {
        let registry = ContractObjectRegistry::default_registry();
        let entry = registry
            .lookup_by_schema_id("apm2.pcac_snapshot_report.v1")
            .expect("schema_id should resolve from default registry");

        assert_eq!(entry.object_id, "PCACSnapshotReportV1");
        assert_eq!(entry.schema_major, 1);
    }

    #[test]
    fn test_registry_lookup_by_stable_id() {
        let registry = ContractObjectRegistry::default_registry();
        let stable_id = "dcp://apm2.local/schemas/apm2.pcac_snapshot_report.v1@v1";
        let entry = registry
            .lookup_by_stable_id(stable_id)
            .expect("stable_id should resolve from default registry");

        assert_eq!(entry.schema_id, "apm2.pcac_snapshot_report.v1");
    }

    #[test]
    fn test_defect_class_serialization() {
        let all_classes = [
            CacDefectClass::SchemaUnresolved,
            CacDefectClass::SchemaVersionIncompatible,
            CacDefectClass::SchemaRegistryDriftAmbiguous,
            CacDefectClass::CanonicalizerUnresolved,
            CacDefectClass::CanonicalizerVectorMismatch,
            CacDefectClass::DigestIncomplete,
            CacDefectClass::DigestMismatch,
            CacDefectClass::SignatureFreshnessFailed,
            CacDefectClass::StaleInputDetected,
            CacDefectClass::ValidationOrderViolation,
            CacDefectClass::PredicateExecutionFailed,
            CacDefectClass::UnknownObjectKind,
        ];

        assert!(!all_classes.is_empty());

        for class in all_classes {
            let encoded = serde_json::to_string(&class).expect("class should serialize");
            let decoded: CacDefectClass =
                serde_json::from_str(&encoded).expect("class should deserialize");
            assert_eq!(class, decoded);
        }
    }

    #[test]
    fn test_compatibility_state_transitions() {
        assert!(CacCompatibilityState::Compatible < CacCompatibilityState::Suspect);
        assert!(CacCompatibilityState::Suspect < CacCompatibilityState::Blocked);
    }

    #[test]
    fn test_schema_registry_drift_compatibility_is_blocked() {
        let defect = CacDefect::new(
            CacDefectClass::SchemaRegistryDriftAmbiguous,
            CacValidationStep::SchemaResolution,
            "schema_stable_id drift detected",
        );

        assert_eq!(defect.compatibility_state, CacCompatibilityState::Blocked);
    }

    #[test]
    fn test_canonicalizer_vector_mismatch_compatibility_is_blocked() {
        let defect = CacDefect::new(
            CacDefectClass::CanonicalizerVectorMismatch,
            CacValidationStep::CanonicalizerCompatibility,
            "canonicalizer tuple mismatch detected",
        );

        assert_eq!(defect.compatibility_state, CacCompatibilityState::Blocked);
    }

    #[test]
    fn test_validation_order_deterministic() {
        let registry = ContractObjectRegistry::default_registry();
        let entry = registry
            .lookup_by_schema_id("apm2.pcac_snapshot_report.v1")
            .expect("schema should resolve for deterministic test");

        let mut object = CacObject::from_registry_entry(entry);
        object.declared_validation_order = CAC_VALIDATION_ORDER.to_vec();

        let result = validate_cac_contract(&registry, &object);

        assert_eq!(
            result.compatibility_state,
            CacCompatibilityState::Compatible
        );
        assert_eq!(result.executed_steps, CAC_VALIDATION_ORDER.to_vec());
        assert!(!result.short_circuited);
        assert!(result.defects.is_empty());
    }

    #[test]
    fn test_tier2_freeze_on_blocked() {
        let policy = Tier2EscalationPolicy::default_strict();
        let defects = vec![sample_blocked_defect()];

        let action = policy.evaluate(&defects, 10);
        assert_eq!(action, EscalationAction::FreezePromotionPaths);
    }

    #[test]
    fn test_tier2_halt_on_deadline() {
        let policy = Tier2EscalationPolicy::default_strict();
        let defects = vec![sample_blocked_defect()];

        let action = policy.evaluate(&defects, policy.adjudication_deadline_secs + 1);
        assert_eq!(action, EscalationAction::Halt);
    }

    #[test]
    fn test_tier2_freeze_on_suspect_before_deadline() {
        let policy = Tier2EscalationPolicy::default_strict();
        let defects = vec![sample_suspect_defect()];

        let action = policy.evaluate(&defects, policy.adjudication_deadline_secs - 1);
        assert_eq!(action, EscalationAction::FreezePromotionPaths);
    }

    #[test]
    fn test_tier2_halt_on_suspect_after_deadline() {
        let policy = Tier2EscalationPolicy::default_strict();
        let defects = vec![sample_suspect_defect()];

        let action = policy.evaluate(&defects, policy.adjudication_deadline_secs);
        assert_eq!(action, EscalationAction::Halt);
    }

    #[test]
    fn test_role_context_object_ids_match_rfc_0019_chapter_17() {
        let registry = ContractObjectRegistry::default_registry();
        let expected_rows = [
            ("cac.context_pack_spec.v1", "RoleContextPackSpecV1"),
            ("cac.context_pack_manifest.v1", "RoleContextPackManifestV1"),
            ("cac.reasoning_selector.v1", "RoleReasoningSelectorV1"),
            ("cac.budget_profile.v1", "RoleBudgetProfileV1"),
        ];

        for (schema_id, expected_object_id) in expected_rows {
            let entry = registry.lookup_by_schema_id(schema_id).unwrap_or_else(|| {
                panic!("schema_id '{schema_id}' should exist in default registry")
            });
            assert_eq!(entry.object_id, expected_object_id);
            assert_eq!(
                entry.schema_stable_id,
                format!("dcp://apm2.local/schemas/{schema_id}@v1")
            );
        }
    }

    #[test]
    fn test_rolespec_context_binding_validation() {
        let binding = RoleSpecContextBinding {
            role_spec_hash: [0; 32],
            context_pack_spec_hash: [0x11; 32],
            context_pack_manifest_hash: [0x22; 32],
            reasoning_selector_hash: Some([0x33; 32]),
            budget_profile_hash: Some([0x44; 32]),
        };

        let error = binding
            .validate()
            .expect_err("zero role_spec_hash should fail validation");

        assert!(matches!(
            error,
            RoleSpecContextBindingError::ZeroHash { ref field } if field == "role_spec_hash"
        ));
    }

    #[test]
    fn test_cac_validation_short_circuits_on_blocked() {
        let registry = ContractObjectRegistry::default_registry();
        let entry = registry
            .lookup_by_schema_id("apm2.pcac_snapshot_report.v1")
            .expect("schema should resolve for baseline object");
        let mut object = CacObject::from_registry_entry(entry);
        object.schema_id = "apm2.unknown_schema.v1".to_string();

        let result = validate_cac_contract(&registry, &object);

        assert_eq!(result.compatibility_state, CacCompatibilityState::Blocked);
        assert_eq!(
            result.executed_steps,
            vec![CacValidationStep::SchemaResolution]
        );
        assert!(result.short_circuited);
        assert!(
            result
                .defects
                .iter()
                .any(|defect| defect.class == CacDefectClass::SchemaUnresolved)
        );
    }
}
