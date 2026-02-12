//! CAC snapshot contract registry and deterministic validation policy.
//!
//! This module implements the RFC-0019 chapter 17
//! `contract_object_registry[]` contract for CAC snapshot objects:
//! schema-qualified rows, deterministic validation order, defect taxonomy,
//! compatibility-state refinement, and Tier2+ escalation behavior.

#![allow(clippy::module_name_repetitions)]

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::marker::PhantomData;

use serde::de::{self, Deserializer, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use thiserror::Error;

use super::traceability_overlay::{
    OverlayDefect, OverlayDefectClass, TrcFacClaim, default_overlay_requirements,
    validate_overlay_requirements,
};
use crate::determinism::{CANONICALIZER_ID, CANONICALIZER_VERSION};

/// Maximum number of contract rows allowed in a registry.
pub const MAX_CONTRACT_REGISTRY_ENTRIES: usize = 128;

/// Maximum number of defects retained in validation outputs.
pub const MAX_CAC_DEFECTS: usize = 128;

const MAX_STRING_LENGTH: usize = 4_096;

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
        #[serde(deserialize_with = "deserialize_bounded_string")]
        schema_id: String,
    },
    /// A required schema row attempted to relax mandatory security semantics.
    RequiredSchemaSecurityDowngrade {
        /// Required schema identifier.
        #[serde(deserialize_with = "deserialize_bounded_string")]
        schema_id: String,
        /// Downgraded field name.
        #[serde(deserialize_with = "deserialize_bounded_string")]
        field_name: String,
    },
    /// Multiple entries claim the same schema identifier.
    DuplicateSchemaId {
        /// Duplicated schema identifier.
        #[serde(deserialize_with = "deserialize_bounded_string")]
        schema_id: String,
    },
    /// Multiple entries claim the same schema stable identifier.
    DuplicateStableId {
        /// Duplicated schema stable identifier.
        #[serde(deserialize_with = "deserialize_bounded_string")]
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
    #[serde(deserialize_with = "deserialize_bounded_string")]
    pub object_id: String,
    /// Semantic object kind (`snapshot.report`, `time.envelope`, etc.).
    #[serde(deserialize_with = "deserialize_bounded_string")]
    pub kind: String,
    /// Schema identifier (`apm2.*.v1`, `cac.*.v1`).
    #[serde(deserialize_with = "deserialize_bounded_string")]
    pub schema_id: String,
    /// Schema major version used for compatibility checks.
    pub schema_major: u32,
    /// Stable schema identifier across versions.
    #[serde(deserialize_with = "deserialize_bounded_string")]
    pub schema_stable_id: String,
    /// Required digest algorithm for this object.
    #[serde(deserialize_with = "deserialize_bounded_string")]
    pub digest_algorithm: String,
    /// Field name used to bind object digest values.
    #[serde(deserialize_with = "deserialize_bounded_string")]
    pub digest_field: String,
    /// Whether digest presence is mandatory for this object.
    pub digest_required: bool,
    /// Required canonicalizer identifier.
    #[serde(deserialize_with = "deserialize_bounded_string")]
    pub canonicalizer_id: String,
    /// Required canonicalizer semantic version.
    #[serde(deserialize_with = "deserialize_bounded_string")]
    pub canonicalizer_version: String,
    /// Reference to canonicalizer vectors required for compatibility.
    #[serde(deserialize_with = "deserialize_bounded_string")]
    pub canonicalizer_vectors_ref: String,
    /// Signature set binding requirement reference.
    ///
    /// `None` means no signature requirement is declared for this row.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_bounded_string"
    )]
    pub signature_set_ref: Option<String>,
    /// Window/TTL freshness binding requirement reference.
    ///
    /// `None` means no freshness requirement is declared for this row.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_bounded_string"
    )]
    pub window_or_ttl_ref: Option<String>,
}

/// Contract object registry containing schema-qualified snapshot rows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContractObjectRegistry {
    #[serde(deserialize_with = "deserialize_registry_entries")]
    entries: Vec<ContractObjectRegistryEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ContractObjectRegistryRaw {
    #[serde(deserialize_with = "deserialize_registry_entries")]
    entries: Vec<ContractObjectRegistryEntry>,
}

impl<'de> Deserialize<'de> for ContractObjectRegistry {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = ContractObjectRegistryRaw::deserialize(deserializer)?;
        Self::new(raw.entries).map_err(|defects| {
            de::Error::custom(format!(
                "contract object registry invariant validation failed: {defects:?}"
            ))
        })
    }
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
    /// Returns a bounded defect list when the registry is incomplete, contains
    /// duplicate schema/stable identifiers, or downgrades required-row security
    /// semantics.
    pub fn validate_completeness(&self) -> Result<(), Vec<RegistryDefect>> {
        let mut defects = Vec::new();
        let expected_required_rows = expected_required_row_bindings();

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
            match self.lookup_by_schema_id(schema_id) {
                Some(entry) => {
                    if let Some(expected) = expected_required_rows.get(*schema_id) {
                        check_required_row_security_bindings(
                            &mut defects,
                            schema_id,
                            entry,
                            expected,
                        );
                    } else {
                        push_registry_defect(
                            &mut defects,
                            RegistryDefect::RequiredSchemaSecurityDowngrade {
                                schema_id: (*schema_id).to_string(),
                                field_name: "schema_id".to_string(),
                            },
                        );
                    }
                },
                None => {
                    push_registry_defect(
                        &mut defects,
                        RegistryDefect::MissingRequiredSchema {
                            schema_id: (*schema_id).to_string(),
                        },
                    );
                },
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
const MAX_VALIDATION_STEPS: usize = CAC_VALIDATION_ORDER.len();

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
    /// Registry requirement reference is unknown or malformed.
    RequirementRefUnresolved,
    /// Validation did not execute in deterministic order.
    ValidationOrderViolation,
    /// Predicate execution failed.
    PredicateExecutionFailed,
    /// Object kind was not recognized for resolved schema.
    UnknownObjectKind,
    /// Resolved registry row and object identity do not match.
    ObjectIdentityMismatch,
}

impl CacDefectClass {
    /// Derives deterministic compatibility-state impact from defect class.
    #[must_use]
    pub const fn compatibility_state(&self) -> CacCompatibilityState {
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
            | Self::RequirementRefUnresolved
            | Self::ValidationOrderViolation
            | Self::PredicateExecutionFailed
            | Self::UnknownObjectKind
            | Self::ObjectIdentityMismatch => CacCompatibilityState::Blocked,
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CacDefect {
    /// Defect classification.
    pub class: CacDefectClass,
    /// Validation step that emitted this defect.
    pub step: CacValidationStep,
    /// Compatibility-state impact for this defect, derived from `class`.
    compatibility_state: CacCompatibilityState,
    /// Human-readable defect detail.
    #[serde(deserialize_with = "deserialize_bounded_string")]
    pub detail: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CacDefectRaw {
    class: CacDefectClass,
    step: CacValidationStep,
    #[serde(default, rename = "compatibility_state")]
    _compatibility_state: Option<de::IgnoredAny>,
    #[serde(deserialize_with = "deserialize_bounded_string")]
    detail: String,
}

impl<'de> Deserialize<'de> for CacDefect {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = CacDefectRaw::deserialize(deserializer)?;
        Ok(Self {
            class: raw.class,
            step: raw.step,
            compatibility_state: raw.class.compatibility_state(),
            detail: raw.detail,
        })
    }
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

    /// Returns compatibility-state impact derived from the defect class.
    #[must_use]
    pub const fn compatibility_state(&self) -> CacCompatibilityState {
        self.compatibility_state
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
        #[serde(deserialize_with = "deserialize_bounded_string")]
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
    #[serde(deserialize_with = "deserialize_bounded_string")]
    pub object_id: String,
    /// Snapshot object kind.
    #[serde(deserialize_with = "deserialize_bounded_string")]
    pub kind: String,
    /// Object schema identifier.
    #[serde(deserialize_with = "deserialize_bounded_string")]
    pub schema_id: String,
    /// Object schema major version.
    pub schema_major: u32,
    /// Object schema stable identifier.
    #[serde(deserialize_with = "deserialize_bounded_string")]
    pub schema_stable_id: String,
    /// Object digest value when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_digest: Option<[u8; 32]>,
    /// Expected digest for digest-equality constraints.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_digest: Option<[u8; 32]>,
    /// Digest algorithm used for this object.
    #[serde(deserialize_with = "deserialize_bounded_string")]
    pub digest_algorithm: String,
    /// Canonicalizer identifier used by object encoding.
    #[serde(deserialize_with = "deserialize_bounded_string")]
    pub canonicalizer_id: String,
    /// Canonicalizer version used by object encoding.
    #[serde(deserialize_with = "deserialize_bounded_string")]
    pub canonicalizer_version: String,
    /// Canonicalizer vectors reference for object encoding.
    #[serde(deserialize_with = "deserialize_bounded_string")]
    pub canonicalizer_vectors_ref: String,
    /// Signature verification status.
    pub signature_status: CacSignatureStatus,
    /// Freshness evaluation status.
    pub freshness_status: CacFreshnessStatus,
    /// Predicate execution status.
    pub predicate_status: CacPredicateStatus,
    /// Optional declared order emitted by caller for order-integrity checks.
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "deserialize_declared_validation_order"
    )]
    pub declared_validation_order: Vec<CacValidationStep>,
    /// Optional deterministic `RoleSpec` context injection binding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role_spec_context_binding: Option<RoleSpecContextBinding>,
}

impl CacObject {
    /// Builds a validation input seeded from a registry row.
    #[must_use]
    pub fn from_registry_entry(entry: &ContractObjectRegistryEntry) -> Self {
        Self {
            object_id: entry.object_id.clone(),
            kind: entry.kind.clone(),
            schema_id: entry.schema_id.clone(),
            schema_major: entry.schema_major,
            schema_stable_id: entry.schema_stable_id.clone(),
            object_digest: None,
            expected_digest: None,
            digest_algorithm: entry.digest_algorithm.clone(),
            canonicalizer_id: entry.canonicalizer_id.clone(),
            canonicalizer_version: entry.canonicalizer_version.clone(),
            canonicalizer_vectors_ref: entry.canonicalizer_vectors_ref.clone(),
            signature_status: CacSignatureStatus::Invalid,
            freshness_status: CacFreshnessStatus::Stale,
            predicate_status: CacPredicateStatus::Failed,
            declared_validation_order: Vec::new(),
            role_spec_context_binding: None,
        }
    }
}

/// Result from deterministic CAC contract validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CacValidationResult {
    /// Aggregate compatibility state after all executed checks.
    pub compatibility_state: CacCompatibilityState,
    /// Bounded defect list emitted during validation.
    #[serde(deserialize_with = "deserialize_cac_defects")]
    pub defects: Vec<CacDefect>,
    /// Steps executed before completion or short-circuit.
    #[serde(deserialize_with = "deserialize_executed_steps")]
    pub executed_steps: Vec<CacValidationStep>,
    /// Whether validation short-circuited on a blocked defect.
    pub short_circuited: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CacValidationResultRaw {
    compatibility_state: CacCompatibilityState,
    #[serde(deserialize_with = "deserialize_cac_defects")]
    defects: Vec<CacDefect>,
    #[serde(deserialize_with = "deserialize_executed_steps")]
    executed_steps: Vec<CacValidationStep>,
    short_circuited: bool,
}

impl<'de> Deserialize<'de> for CacValidationResult {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = CacValidationResultRaw::deserialize(deserializer)?;
        let recomputed_state = recompute_compatibility_state_from_defects(&raw.defects);
        if raw.compatibility_state != recomputed_state {
            return Err(de::Error::custom(format!(
                "compatibility_state {:?} does not match recomputed state {:?}",
                raw.compatibility_state, recomputed_state
            )));
        }

        Ok(Self {
            compatibility_state: recomputed_state,
            defects: raw.defects,
            executed_steps: raw.executed_steps,
            short_circuited: raw.short_circuited,
        })
    }
}

impl CacValidationResult {
    /// Recomputes compatibility-state refinement from defects.
    #[must_use]
    pub fn recompute_compatibility_state(&self) -> CacCompatibilityState {
        recompute_compatibility_state_from_defects(&self.defects)
    }

    /// Returns `true` only when the object is fully compatible.
    #[must_use]
    pub fn is_admissible(&self) -> bool {
        self.recompute_compatibility_state().is_admissible()
    }
}

/// Aggregate result from validating a CAC snapshot payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacSnapshotValidationResult {
    /// Aggregate compatibility state across per-schema and overlay checks.
    pub compatibility_state: CacCompatibilityState,
    /// Consolidated defect list, including overlay-derived defects.
    pub defects: Vec<CacDefect>,
    /// Per-schema validation results keyed by `schema_id`.
    pub validation_results: BTreeMap<String, CacValidationResult>,
}

impl CacSnapshotValidationResult {
    /// Recomputes compatibility-state refinement from defects.
    #[must_use]
    pub fn recompute_compatibility_state(&self) -> CacCompatibilityState {
        recompute_compatibility_state_from_defects(&self.defects)
    }

    /// Returns `true` only when the full snapshot is fully compatible.
    #[must_use]
    pub fn is_admissible(&self) -> bool {
        self.recompute_compatibility_state().is_admissible()
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
            .map(|defect| defect.class.compatibility_state())
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

fn deserialize_optional_bounded_string<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<String>::deserialize(deserializer)?;
    if let Some(value) = value {
        if value.len() > MAX_STRING_LENGTH {
            return Err(de::Error::custom(format!(
                "string exceeds maximum length ({} > {MAX_STRING_LENGTH})",
                value.len()
            )));
        }
        Ok(Some(value))
    } else {
        Ok(None)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequirementBinding {
    Required,
    NotRequired,
}

fn resolve_requirement_binding(
    requirement_ref: Option<&str>,
    field_name: &str,
    required_ref: &str,
    not_required_ref: &str,
) -> Result<Option<RequirementBinding>, String> {
    let Some(raw_ref) = requirement_ref else {
        return Ok(None);
    };

    let ref_value = raw_ref.trim();
    if ref_value.is_empty() {
        return Err(format!(
            "{field_name} is empty; expected '{required_ref}' or '{not_required_ref}'"
        ));
    }

    if ref_value == required_ref {
        Ok(Some(RequirementBinding::Required))
    } else if ref_value == not_required_ref {
        Ok(Some(RequirementBinding::NotRequired))
    } else {
        Err(format!(
            "unknown {field_name} '{ref_value}'; expected '{required_ref}' or '{not_required_ref}'"
        ))
    }
}

fn deserialize_bounded_vec<'de, D, T>(
    deserializer: D,
    max: usize,
    field_name: &'static str,
) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct BoundedVecVisitor<T> {
        max: usize,
        field_name: &'static str,
        _phantom: PhantomData<T>,
    }

    impl<'de, T> Visitor<'de> for BoundedVecVisitor<T>
    where
        T: Deserialize<'de>,
    {
        type Value = Vec<T>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(
                formatter,
                "a sequence for '{}' with at most {} entries",
                self.field_name, self.max
            )
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut values = Vec::with_capacity(seq.size_hint().unwrap_or(0).min(self.max));
            while values.len() < self.max {
                match seq.next_element::<T>()? {
                    Some(value) => values.push(value),
                    None => return Ok(values),
                }
            }

            if seq.next_element::<de::IgnoredAny>()?.is_some() {
                return Err(de::Error::custom(format!(
                    "{} exceeds maximum size ({})",
                    self.field_name, self.max
                )));
            }

            Ok(values)
        }
    }

    deserializer.deserialize_seq(BoundedVecVisitor {
        max,
        field_name,
        _phantom: PhantomData,
    })
}

fn deserialize_registry_entries<'de, D>(
    deserializer: D,
) -> Result<Vec<ContractObjectRegistryEntry>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_vec(deserializer, MAX_CONTRACT_REGISTRY_ENTRIES, "entries")
}

fn deserialize_declared_validation_order<'de, D>(
    deserializer: D,
) -> Result<Vec<CacValidationStep>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_vec(
        deserializer,
        MAX_VALIDATION_STEPS,
        "declared_validation_order",
    )
}

fn deserialize_cac_defects<'de, D>(deserializer: D) -> Result<Vec<CacDefect>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_vec(deserializer, MAX_CAC_DEFECTS, "defects")
}

fn deserialize_executed_steps<'de, D>(deserializer: D) -> Result<Vec<CacValidationStep>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_vec(deserializer, MAX_VALIDATION_STEPS, "executed_steps")
}

fn recompute_compatibility_state_from_defects(defects: &[CacDefect]) -> CacCompatibilityState {
    defects
        .iter()
        .map(|defect| defect.class.compatibility_state())
        .max()
        .unwrap_or(CacCompatibilityState::Compatible)
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

                    if entry.object_id != object.object_id {
                        update_with_defect(
                            &mut defects,
                            &mut compatibility_state,
                            CacDefect::new(
                                CacDefectClass::ObjectIdentityMismatch,
                                step,
                                format!(
                                    "object_id mismatch: expected '{}', got '{}'",
                                    entry.object_id, object.object_id
                                ),
                            ),
                        );
                    }

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
                if let Some(entry) = resolved_entry {
                    let required_schema = is_required_contract_schema(entry.schema_id.as_str());

                    let signature_requirement = resolve_requirement_binding(
                        entry.signature_set_ref.as_deref(),
                        "signature_set_ref",
                        SIGNATURE_SET_REQUIRED_REF,
                        SIGNATURE_SET_NOT_REQUIRED_REF,
                    );
                    if required_schema {
                        if entry.signature_set_ref.is_none() {
                            update_with_defect(
                                &mut defects,
                                &mut compatibility_state,
                                CacDefect::new(
                                    CacDefectClass::RequirementRefUnresolved,
                                    step,
                                    format!(
                                        "required schema '{}' is missing signature_set_ref",
                                        entry.schema_id
                                    ),
                                ),
                            );
                        } else if let Err(detail) = &signature_requirement {
                            update_with_defect(
                                &mut defects,
                                &mut compatibility_state,
                                CacDefect::new(
                                    CacDefectClass::RequirementRefUnresolved,
                                    step,
                                    detail.clone(),
                                ),
                            );
                        }

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
                    } else {
                        match signature_requirement {
                            Ok(Some(RequirementBinding::Required)) => {
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
                            },
                            Ok(Some(RequirementBinding::NotRequired) | None) => {},
                            Err(detail) => {
                                update_with_defect(
                                    &mut defects,
                                    &mut compatibility_state,
                                    CacDefect::new(
                                        CacDefectClass::RequirementRefUnresolved,
                                        step,
                                        detail,
                                    ),
                                );
                            },
                        }
                    }

                    let freshness_requirement = resolve_requirement_binding(
                        entry.window_or_ttl_ref.as_deref(),
                        "window_or_ttl_ref",
                        WINDOW_OR_TTL_REQUIRED_REF,
                        WINDOW_OR_TTL_NOT_REQUIRED_REF,
                    );
                    if required_schema {
                        if entry.window_or_ttl_ref.is_none() {
                            update_with_defect(
                                &mut defects,
                                &mut compatibility_state,
                                CacDefect::new(
                                    CacDefectClass::RequirementRefUnresolved,
                                    step,
                                    format!(
                                        "required schema '{}' is missing window_or_ttl_ref",
                                        entry.schema_id
                                    ),
                                ),
                            );
                        } else if let Err(detail) = &freshness_requirement {
                            update_with_defect(
                                &mut defects,
                                &mut compatibility_state,
                                CacDefect::new(
                                    CacDefectClass::RequirementRefUnresolved,
                                    step,
                                    detail.clone(),
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
                    } else {
                        match freshness_requirement {
                            Ok(Some(RequirementBinding::Required)) => {
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
                            Ok(Some(RequirementBinding::NotRequired) | None) => {},
                            Err(detail) => {
                                update_with_defect(
                                    &mut defects,
                                    &mut compatibility_state,
                                    CacDefect::new(
                                        CacDefectClass::RequirementRefUnresolved,
                                        step,
                                        detail,
                                    ),
                                );
                            },
                        }
                    }
                } else {
                    update_with_defect(
                        &mut defects,
                        &mut compatibility_state,
                        CacDefect::new(
                            CacDefectClass::SchemaUnresolved,
                            step,
                            "schema must resolve before signature/freshness checks",
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
                        let digest_mismatch = object.object_digest.is_none_or(|object_digest| {
                            bool::from(object_digest.ct_ne(&expected_digest))
                        });
                        if digest_mismatch {
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
                if let Some(entry) = resolved_entry {
                    if requires_role_spec_context_binding(entry.schema_id.as_str())
                        && object.role_spec_context_binding.is_none()
                    {
                        update_with_defect(
                            &mut defects,
                            &mut compatibility_state,
                            CacDefect::new(
                                CacDefectClass::PredicateExecutionFailed,
                                step,
                                format!(
                                    "required schema '{}' is missing role_spec_context_binding",
                                    entry.schema_id
                                ),
                            ),
                        );
                    }
                }

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
        compatibility_state: recompute_compatibility_state_from_defects(&defects),
        defects,
        executed_steps,
        short_circuited,
    }
}

const fn map_overlay_defect_class(defect_class: OverlayDefectClass) -> CacDefectClass {
    match defect_class {
        OverlayDefectClass::MissingRequiredSchema => CacDefectClass::SchemaUnresolved,
        OverlayDefectClass::SchemaValidationFailed
        | OverlayDefectClass::Tier2EscalationTriggered => CacDefectClass::PredicateExecutionFailed,
        OverlayDefectClass::IncompleteDigestSet => CacDefectClass::DigestIncomplete,
        OverlayDefectClass::CanonicalizerBindingMismatch => {
            CacDefectClass::CanonicalizerVectorMismatch
        },
        OverlayDefectClass::SignatureFreshnessFailed => CacDefectClass::SignatureFreshnessFailed,
    }
}

fn overlay_defect_to_cac_defect(defect: &OverlayDefect) -> CacDefect {
    CacDefect::new(
        map_overlay_defect_class(defect.defect_class),
        CacValidationStep::PredicateExecution,
        format!(
            "overlay {:?} {:?}: {}",
            defect.claim, defect.defect_class, defect.detail
        ),
    )
}

/// Validates a CAC snapshot payload and enforces promotion-critical overlay
/// requirements for active TRC-FAC claims.
#[must_use]
#[allow(clippy::implicit_hasher)]
pub fn validate_cac_snapshot(
    registry: &ContractObjectRegistry,
    objects: &[CacObject],
    active_claims: &[TrcFacClaim],
) -> CacSnapshotValidationResult {
    let mut defects = Vec::new();
    let mut compatibility_state = CacCompatibilityState::Compatible;
    let mut validation_results = HashMap::with_capacity(objects.len());

    for object in objects {
        let result = validate_cac_contract(registry, object);
        for defect in &result.defects {
            update_with_defect(&mut defects, &mut compatibility_state, defect.clone());
        }

        if validation_results
            .insert(object.schema_id.clone(), result)
            .is_some()
        {
            update_with_defect(
                &mut defects,
                &mut compatibility_state,
                CacDefect::new(
                    CacDefectClass::SchemaRegistryDriftAmbiguous,
                    CacValidationStep::SchemaResolution,
                    format!(
                        "duplicate validation result for schema_id '{}' in snapshot payload",
                        object.schema_id
                    ),
                ),
            );
        }
    }

    let overlay = default_overlay_requirements();
    let overlay_defects =
        validate_overlay_requirements(active_claims, &validation_results, &overlay);
    for overlay_defect in overlay_defects {
        update_with_defect(
            &mut defects,
            &mut compatibility_state,
            overlay_defect_to_cac_defect(&overlay_defect),
        );
    }

    CacSnapshotValidationResult {
        compatibility_state: recompute_compatibility_state_from_defects(&defects),
        defects,
        validation_results: validation_results.into_iter().collect(),
    }
}

fn update_with_defect(
    defects: &mut Vec<CacDefect>,
    compatibility_state: &mut CacCompatibilityState,
    defect: CacDefect,
) {
    *compatibility_state = (*compatibility_state).max(defect.compatibility_state());
    if defects.len() < MAX_CAC_DEFECTS {
        defects.push(defect);
    }
}

fn push_registry_defect(defects: &mut Vec<RegistryDefect>, defect: RegistryDefect) {
    if defects.len() < MAX_CAC_DEFECTS {
        defects.push(defect);
    }
}

fn check_required_schema_field(
    defects: &mut Vec<RegistryDefect>,
    schema_id: &str,
    field_name: &str,
    matches_expected: bool,
) {
    if !matches_expected {
        push_registry_defect(
            defects,
            RegistryDefect::RequiredSchemaSecurityDowngrade {
                schema_id: schema_id.to_string(),
                field_name: field_name.to_string(),
            },
        );
    }
}

fn check_required_row_security_bindings(
    defects: &mut Vec<RegistryDefect>,
    schema_id: &str,
    entry: &ContractObjectRegistryEntry,
    expected: &ContractObjectRegistryEntry,
) {
    check_required_schema_field(
        defects,
        schema_id,
        "object_id",
        entry.object_id == expected.object_id,
    );
    check_required_schema_field(
        defects,
        schema_id,
        "schema_major",
        entry.schema_major == expected.schema_major,
    );
    check_required_schema_field(
        defects,
        schema_id,
        "schema_stable_id",
        entry.schema_stable_id == expected.schema_stable_id,
    );
    check_required_schema_field(
        defects,
        schema_id,
        "digest_required",
        entry.digest_required == expected.digest_required,
    );
    check_required_schema_field(
        defects,
        schema_id,
        "digest_algorithm",
        entry.digest_algorithm == expected.digest_algorithm,
    );
    check_required_schema_field(
        defects,
        schema_id,
        "digest_field_name",
        entry.digest_field == expected.digest_field,
    );
    check_required_schema_field(
        defects,
        schema_id,
        "canonicalizer_kind",
        entry.canonicalizer_id == expected.canonicalizer_id,
    );
    check_required_schema_field(
        defects,
        schema_id,
        "canonicalizer_version",
        entry.canonicalizer_version == expected.canonicalizer_version,
    );
    check_required_schema_field(
        defects,
        schema_id,
        "canonicalizer_vectors_ref",
        entry.canonicalizer_vectors_ref == expected.canonicalizer_vectors_ref,
    );
    check_required_schema_field(
        defects,
        schema_id,
        "signature_set_ref",
        entry.signature_set_ref == expected.signature_set_ref,
    );
    check_required_schema_field(
        defects,
        schema_id,
        "window_or_ttl_ref",
        entry.window_or_ttl_ref == expected.window_or_ttl_ref,
    );
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
    bool::from(hash.ct_eq(&[0; 32]))
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
        signature_set_ref: Some(signature_set_ref.to_string()),
        window_or_ttl_ref: Some(window_or_ttl_ref.to_string()),
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
        default_registry_entry(
            "OptimizationGateDecisionV1",
            "optimization.gate.decision",
            "apm2.optimization_gate_decision.v1",
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
    "apm2.optimization_gate_decision.v1",
];

fn expected_required_row_bindings() -> HashMap<String, ContractObjectRegistryEntry> {
    let expected: HashMap<String, ContractObjectRegistryEntry> =
        default_contract_registry_entries()
            .into_iter()
            .filter(|entry| is_required_contract_schema(entry.schema_id.as_str()))
            .map(|entry| (entry.schema_id.clone(), entry))
            .collect();
    debug_assert_eq!(expected.len(), REQUIRED_CONTRACT_SCHEMA_IDS.len());
    expected
}

fn is_required_contract_schema(schema_id: &str) -> bool {
    REQUIRED_CONTRACT_SCHEMA_IDS.contains(&schema_id)
}

fn requires_role_spec_context_binding(schema_id: &str) -> bool {
    is_required_contract_schema(schema_id) && schema_id.starts_with("cac.")
}

#[cfg(test)]
#[allow(missing_docs)]
mod tests {
    use super::*;

    const NON_REQUIRED_TEST_SCHEMA_ID: &str = "apm2.contract_registry_optional_test.v1";

    fn sample_blocked_defect() -> CacDefect {
        CacDefect::new(
            CacDefectClass::SchemaUnresolved,
            CacValidationStep::SchemaResolution,
            "test blocked defect",
        )
    }

    fn registry_with_non_required_entry_mutation(
        mutate: impl FnOnce(&mut ContractObjectRegistryEntry),
    ) -> ContractObjectRegistry {
        let mut entries = ContractObjectRegistry::default_registry()
            .entries()
            .to_vec();
        let mut optional_entry = default_registry_entry(
            "ContractRegistryOptionalTestV1",
            "test.optional.contract.object",
            NON_REQUIRED_TEST_SCHEMA_ID,
            SIGNATURE_SET_REQUIRED_REF,
            WINDOW_OR_TTL_REQUIRED_REF,
        );
        mutate(&mut optional_entry);
        entries.push(optional_entry);
        ContractObjectRegistry::new(entries)
            .expect("mutated non-required registry should satisfy completeness constraints")
    }

    fn sample_admissible_object(entry: &ContractObjectRegistryEntry) -> CacObject {
        let mut object = CacObject::from_registry_entry(entry);
        object.object_digest = Some([0xA5; 32]);
        object.expected_digest = Some([0xA5; 32]);
        object.signature_status = CacSignatureStatus::Valid;
        object.freshness_status = CacFreshnessStatus::Fresh;
        object.predicate_status = CacPredicateStatus::Passed;
        object
    }

    fn sample_admissible_object_for_schema(
        registry: &ContractObjectRegistry,
        schema_id: &str,
    ) -> CacObject {
        let entry = registry.lookup_by_schema_id(schema_id).unwrap_or_else(|| {
            panic!("schema_id '{schema_id}' should resolve in default registry")
        });
        sample_admissible_object(entry)
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
            CacDefectClass::RequirementRefUnresolved,
            CacDefectClass::ValidationOrderViolation,
            CacDefectClass::PredicateExecutionFailed,
            CacDefectClass::UnknownObjectKind,
            CacDefectClass::ObjectIdentityMismatch,
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

        assert_eq!(defect.compatibility_state(), CacCompatibilityState::Blocked);
    }

    #[test]
    fn test_canonicalizer_vector_mismatch_compatibility_is_blocked() {
        let defect = CacDefect::new(
            CacDefectClass::CanonicalizerVectorMismatch,
            CacValidationStep::CanonicalizerCompatibility,
            "canonicalizer tuple mismatch detected",
        );

        assert_eq!(defect.compatibility_state(), CacCompatibilityState::Blocked);
    }

    #[test]
    fn test_validation_order_deterministic() {
        let registry = ContractObjectRegistry::default_registry();
        let entry = registry
            .lookup_by_schema_id("apm2.pcac_snapshot_report.v1")
            .expect("schema should resolve for deterministic test");

        let mut object = sample_admissible_object(entry);
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
    fn test_from_registry_entry_defaults_fail_closed() {
        let registry = ContractObjectRegistry::default_registry();
        let entry = registry
            .lookup_by_schema_id("apm2.pcac_snapshot_report.v1")
            .expect("schema should resolve for default fail-closed test");
        let object = CacObject::from_registry_entry(entry);

        let result = validate_cac_contract(&registry, &object);

        assert_eq!(result.compatibility_state, CacCompatibilityState::Blocked);
        assert!(!result.is_admissible());
        assert!(result.short_circuited);
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
    fn test_escalation_ignores_forged_compatibility_state() {
        let policy = Tier2EscalationPolicy::default_strict();
        let defects = vec![CacDefect {
            class: CacDefectClass::SchemaUnresolved,
            step: CacValidationStep::SchemaResolution,
            compatibility_state: CacCompatibilityState::Compatible,
            detail: "forged compatible state".to_string(),
        }];

        let action = policy.evaluate(&defects, policy.adjudication_deadline_secs - 1);
        assert_eq!(action, EscalationAction::FreezePromotionPaths);
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

    #[test]
    fn test_overlay_enforcement_blocks_promotion_on_missing_schema() {
        let registry = ContractObjectRegistry::default_registry();
        let objects = vec![sample_admissible_object_for_schema(
            &registry,
            "apm2.authority_kernel_decision.v1",
        )];

        let result = validate_cac_snapshot(&registry, &objects, &[TrcFacClaim::TrcFac01]);

        assert_eq!(result.compatibility_state, CacCompatibilityState::Blocked);
        assert!(result.defects.iter().any(|defect| {
            defect.class == CacDefectClass::SchemaUnresolved
                && defect.detail.contains("overlay")
                && defect.detail.contains("MissingRequiredSchema")
                && defect.detail.contains("apm2.pcac_snapshot_report.v1")
        }));
    }

    #[test]
    fn test_overlay_enforcement_passes_when_all_schemas_compatible() {
        let registry = ContractObjectRegistry::default_registry();
        let objects = vec![
            sample_admissible_object_for_schema(&registry, "apm2.pcac_snapshot_report.v1"),
            sample_admissible_object_for_schema(&registry, "apm2.authority_kernel_decision.v1"),
        ];

        let result = validate_cac_snapshot(&registry, &objects, &[TrcFacClaim::TrcFac01]);

        assert_eq!(
            result.compatibility_state,
            CacCompatibilityState::Compatible
        );
        assert!(
            result.defects.is_empty(),
            "unexpected defects: {:?}",
            result.defects
        );
    }

    #[test]
    fn test_overlay_tier2_escalation_blocks_validation() {
        let registry = ContractObjectRegistry::default_registry();
        let objects = vec![sample_admissible_object_for_schema(
            &registry,
            "apm2.revocation_frontier_snapshot.v1",
        )];

        let result = validate_cac_snapshot(&registry, &objects, &[TrcFacClaim::TrcFac16]);

        assert!(
            result
                .validation_results
                .values()
                .all(CacValidationResult::is_admissible),
            "object-level defects should not drive this failure: {:?}",
            result.validation_results
        );
        assert_eq!(result.compatibility_state, CacCompatibilityState::Blocked);
        assert!(result.defects.iter().any(|defect| {
            defect.class == CacDefectClass::PredicateExecutionFailed
                && defect.detail.contains("overlay")
                && defect.detail.contains("Tier2EscalationTriggered")
        }));
    }

    #[test]
    fn test_unsigned_object_skips_signature_check() {
        let schema_id = NON_REQUIRED_TEST_SCHEMA_ID;
        let registry = registry_with_non_required_entry_mutation(|entry| {
            entry.signature_set_ref = None;
        });
        let entry = registry
            .lookup_by_schema_id(schema_id)
            .expect("optional schema should resolve for signature bypass test");
        let mut object = sample_admissible_object(entry);
        object.signature_status = CacSignatureStatus::Invalid;

        let result = validate_cac_contract(&registry, &object);

        assert_eq!(
            result.compatibility_state,
            CacCompatibilityState::Compatible
        );
        assert!(
            !result
                .defects
                .iter()
                .any(|defect| defect.class == CacDefectClass::SignatureFreshnessFailed)
        );
    }

    #[test]
    fn test_non_window_bound_skips_freshness_check() {
        let schema_id = NON_REQUIRED_TEST_SCHEMA_ID;
        let registry = registry_with_non_required_entry_mutation(|entry| {
            entry.window_or_ttl_ref = None;
        });
        let entry = registry
            .lookup_by_schema_id(schema_id)
            .expect("optional schema should resolve for freshness bypass test");
        let mut object = sample_admissible_object(entry);
        object.freshness_status = CacFreshnessStatus::Stale;

        let result = validate_cac_contract(&registry, &object);

        assert_eq!(
            result.compatibility_state,
            CacCompatibilityState::Compatible
        );
        assert!(
            !result
                .defects
                .iter()
                .any(|defect| defect.class == CacDefectClass::StaleInputDetected)
        );
    }

    #[test]
    fn test_unknown_ref_value_is_explicit_defect() {
        let schema_id = NON_REQUIRED_TEST_SCHEMA_ID;
        let registry = registry_with_non_required_entry_mutation(|entry| {
            entry.signature_set_ref = Some("signature_set.unknown".to_string());
        });
        let entry = registry
            .lookup_by_schema_id(schema_id)
            .expect("schema should resolve for unknown-ref test");
        let object = sample_admissible_object(entry);

        let result = validate_cac_contract(&registry, &object);

        assert_eq!(result.compatibility_state, CacCompatibilityState::Blocked);
        assert!(
            result
                .defects
                .iter()
                .any(|defect| defect.class == CacDefectClass::RequirementRefUnresolved)
        );
    }

    #[test]
    fn test_required_schema_missing_signature_ref_rejected() {
        let required_schema_id = "apm2.pcac_snapshot_report.v1";
        let mut entries = ContractObjectRegistry::default_registry()
            .entries()
            .to_vec();
        let entry = entries
            .iter_mut()
            .find(|entry| entry.schema_id == required_schema_id)
            .expect("required schema should exist in default registry");
        entry.signature_set_ref = None;

        let defects = ContractObjectRegistry::new(entries)
            .expect_err("required schema missing signature_set_ref must be rejected");

        assert!(defects.iter().any(|defect| {
            matches!(
                defect,
                RegistryDefect::RequiredSchemaSecurityDowngrade {
                    schema_id,
                    field_name,
                } if schema_id == required_schema_id && field_name == "signature_set_ref"
            )
        }));
    }

    #[test]
    fn test_required_schema_missing_window_ref_rejected() {
        let required_schema_id = "apm2.pcac_snapshot_report.v1";
        let mut entries = ContractObjectRegistry::default_registry()
            .entries()
            .to_vec();
        let entry = entries
            .iter_mut()
            .find(|entry| entry.schema_id == required_schema_id)
            .expect("required schema should exist in default registry");
        entry.window_or_ttl_ref = None;

        let defects = ContractObjectRegistry::new(entries)
            .expect_err("required schema missing window_or_ttl_ref must be rejected");

        assert!(defects.iter().any(|defect| {
            matches!(
                defect,
                RegistryDefect::RequiredSchemaSecurityDowngrade {
                    schema_id,
                    field_name,
                } if schema_id == required_schema_id && field_name == "window_or_ttl_ref"
            )
        }));
    }

    #[test]
    fn test_required_schema_digest_downgrade_rejected() {
        let required_schema_id = "apm2.pcac_snapshot_report.v1";
        let mut entries = ContractObjectRegistry::default_registry()
            .entries()
            .to_vec();
        let entry = entries
            .iter_mut()
            .find(|entry| entry.schema_id == required_schema_id)
            .expect("required schema should exist in default registry");
        entry.digest_required = false;

        let defects = ContractObjectRegistry::new(entries)
            .expect_err("required schema digest_required downgrade must be rejected");

        assert!(defects.iter().any(|defect| {
            matches!(
                defect,
                RegistryDefect::RequiredSchemaSecurityDowngrade {
                    schema_id,
                    field_name,
                } if schema_id == required_schema_id && field_name == "digest_required"
            )
        }));
    }

    #[test]
    fn test_required_schema_canonicalizer_downgrade_rejected() {
        let required_schema_id = "apm2.pcac_snapshot_report.v1";
        let mut entries = ContractObjectRegistry::default_registry()
            .entries()
            .to_vec();
        let entry = entries
            .iter_mut()
            .find(|entry| entry.schema_id == required_schema_id)
            .expect("required schema should exist in default registry");
        entry.canonicalizer_id = "canonicalizer.tampered".to_string();

        let defects = ContractObjectRegistry::new(entries)
            .expect_err("required schema canonicalizer downgrade must be rejected");

        assert!(defects.iter().any(|defect| {
            matches!(
                defect,
                RegistryDefect::RequiredSchemaSecurityDowngrade {
                    schema_id,
                    field_name,
                } if schema_id == required_schema_id && field_name == "canonicalizer_kind"
            )
        }));
    }

    #[test]
    fn test_required_schema_algorithm_downgrade_rejected() {
        let required_schema_id = "apm2.pcac_snapshot_report.v1";
        let mut entries = ContractObjectRegistry::default_registry()
            .entries()
            .to_vec();
        let entry = entries
            .iter_mut()
            .find(|entry| entry.schema_id == required_schema_id)
            .expect("required schema should exist in default registry");
        entry.digest_algorithm = "sha256".to_string();

        let defects = ContractObjectRegistry::new(entries)
            .expect_err("required schema digest algorithm downgrade must be rejected");

        assert!(defects.iter().any(|defect| {
            matches!(
                defect,
                RegistryDefect::RequiredSchemaSecurityDowngrade {
                    schema_id,
                    field_name,
                } if schema_id == required_schema_id && field_name == "digest_algorithm"
            )
        }));
    }

    #[test]
    fn test_required_schema_downgrade_blocked() {
        let required_schema_id = "apm2.pcac_snapshot_report.v1";
        let mut entries = ContractObjectRegistry::default_registry()
            .entries()
            .to_vec();
        let entry = entries
            .iter_mut()
            .find(|entry| entry.schema_id == required_schema_id)
            .expect("required schema should exist in default registry");
        entry.signature_set_ref = None;
        entry.window_or_ttl_ref = None;

        // Construct directly to emulate a tampered in-memory registry that bypassed
        // constructor checks.
        let registry = ContractObjectRegistry { entries };
        let entry = registry
            .lookup_by_schema_id(required_schema_id)
            .expect("required schema should resolve for downgrade test");
        let object = sample_admissible_object(entry);

        let result = validate_cac_contract(&registry, &object);

        assert_ne!(
            result.compatibility_state,
            CacCompatibilityState::Compatible
        );
        assert!(!result.is_admissible());
        assert!(
            result
                .defects
                .iter()
                .any(|defect| defect.class == CacDefectClass::RequirementRefUnresolved)
        );
    }

    #[test]
    fn test_required_cac_schema_missing_binding_defect() {
        let registry = ContractObjectRegistry::default_registry();
        let entry = registry
            .lookup_by_schema_id("cac.context_pack_spec.v1")
            .expect("required cac schema should resolve");
        let object = sample_admissible_object(entry);

        let result = validate_cac_contract(&registry, &object);

        assert_eq!(result.compatibility_state, CacCompatibilityState::Blocked);
        assert!(result.defects.iter().any(|defect| {
            defect.class == CacDefectClass::PredicateExecutionFailed
                && defect.detail.contains("missing role_spec_context_binding")
        }));
    }

    #[test]
    fn test_object_id_mismatch_rejected() {
        let registry = ContractObjectRegistry::default_registry();
        let entry = registry
            .lookup_by_schema_id("apm2.pcac_snapshot_report.v1")
            .expect("schema should resolve for object_id mismatch test");
        let mut object = sample_admissible_object(entry);
        object.object_id = "DifferentObjectIdV1".to_string();

        let result = validate_cac_contract(&registry, &object);

        assert_eq!(result.compatibility_state, CacCompatibilityState::Blocked);
        assert_eq!(
            result.executed_steps,
            vec![CacValidationStep::SchemaResolution]
        );
        assert!(
            result
                .defects
                .iter()
                .any(|defect| defect.class == CacDefectClass::ObjectIdentityMismatch)
        );
    }

    #[test]
    fn test_object_id_match_accepted() {
        let registry = ContractObjectRegistry::default_registry();
        let entry = registry
            .lookup_by_schema_id("apm2.pcac_snapshot_report.v1")
            .expect("schema should resolve for object_id match test");
        let object = sample_admissible_object(entry);

        let result = validate_cac_contract(&registry, &object);

        assert_eq!(
            result.compatibility_state,
            CacCompatibilityState::Compatible
        );
        assert!(
            !result
                .defects
                .iter()
                .any(|defect| defect.class == CacDefectClass::ObjectIdentityMismatch)
        );
    }

    #[test]
    fn test_registry_defect_deserialize_rejects_oversized_string() {
        let value = serde_json::json!({
            "kind": "missing_required_schema",
            "schema_id": "x".repeat(MAX_STRING_LENGTH + 1),
        });

        let error = serde_json::from_value::<RegistryDefect>(value)
            .expect_err("oversized schema_id should fail during deserialization");

        assert!(error.to_string().contains("string exceeds maximum length"));
    }

    #[test]
    fn test_contract_object_registry_entry_deserialize_rejects_oversized_string() {
        let value = serde_json::json!({
            "object_id": "x".repeat(MAX_STRING_LENGTH + 1),
            "kind": "snapshot.report",
            "schema_id": "apm2.pcac_snapshot_report.v1",
            "schema_major": 1,
            "schema_stable_id": "dcp://apm2.local/schemas/apm2.pcac_snapshot_report.v1@v1",
            "digest_algorithm": "blake3",
            "digest_field": "object_digest",
            "digest_required": true,
            "canonicalizer_id": CANONICALIZER_ID,
            "canonicalizer_version": CANONICALIZER_VERSION,
            "canonicalizer_vectors_ref": CAC_CANONICALIZER_VECTORS_REF,
            "signature_set_ref": SIGNATURE_SET_REQUIRED_REF,
            "window_or_ttl_ref": WINDOW_OR_TTL_NOT_REQUIRED_REF,
        });

        let error = serde_json::from_value::<ContractObjectRegistryEntry>(value)
            .expect_err("oversized object_id should fail during deserialization");

        assert!(error.to_string().contains("string exceeds maximum length"));
    }

    #[test]
    fn test_contract_object_registry_deserialize_rejects_oversized_entries() {
        let baseline_entry = ContractObjectRegistry::default_registry()
            .entries()
            .first()
            .cloned()
            .expect("default registry should contain at least one entry");
        let entry_value =
            serde_json::to_value(baseline_entry).expect("registry entry should serialize");
        let oversized_entries = vec![entry_value; MAX_CONTRACT_REGISTRY_ENTRIES + 1];
        let value = serde_json::json!({
            "entries": oversized_entries,
        });

        let error = serde_json::from_value::<ContractObjectRegistry>(value)
            .expect_err("oversized entries should fail during deserialization");

        assert!(error.to_string().contains("entries exceeds maximum size"));
    }

    #[test]
    fn test_deserialize_invalid_registry_rejected() {
        let mut value = serde_json::to_value(ContractObjectRegistry::default_registry())
            .expect("default registry should serialize");
        let entries = value["entries"]
            .as_array_mut()
            .expect("entries should be an array");
        let duplicate_entry = entries
            .first()
            .cloned()
            .expect("default registry should contain at least one entry");
        entries.push(duplicate_entry);

        let error = serde_json::from_value::<ContractObjectRegistry>(value)
            .expect_err("duplicate schema_id should fail invariant validation");
        assert!(error.to_string().contains("DuplicateSchemaId"));
    }

    #[test]
    fn test_cac_object_deserialize_rejects_oversized_declared_validation_order() {
        let registry = ContractObjectRegistry::default_registry();
        let entry = registry
            .entries()
            .first()
            .expect("default registry should contain at least one entry");
        let object = CacObject::from_registry_entry(entry);
        let mut value = serde_json::to_value(object).expect("object should serialize");
        value["declared_validation_order"] = serde_json::Value::Array(
            std::iter::repeat_n(
                serde_json::Value::String("schema_resolution".to_string()),
                MAX_VALIDATION_STEPS + 1,
            )
            .collect(),
        );

        let error = serde_json::from_value::<CacObject>(value)
            .expect_err("oversized declared_validation_order should fail during deserialization");

        assert!(
            error
                .to_string()
                .contains("declared_validation_order exceeds maximum size")
        );
    }

    #[test]
    fn test_cac_validation_result_deserialize_rejects_oversized_defects() {
        let defect = serde_json::json!({
            "class": "digest_mismatch",
            "step": "digest_completeness",
            "compatibility_state": "blocked",
            "detail": "digest mismatch",
        });
        let value = serde_json::json!({
            "compatibility_state": "blocked",
            "defects": vec![defect; MAX_CAC_DEFECTS + 1],
            "executed_steps": ["schema_resolution"],
            "short_circuited": true,
        });

        let error = serde_json::from_value::<CacValidationResult>(value)
            .expect_err("oversized defects should fail during deserialization");

        assert!(error.to_string().contains("defects exceeds maximum size"));
    }

    #[test]
    fn test_forged_compatible_state_with_blocked_defects_rejected() {
        let forged_result = CacValidationResult {
            compatibility_state: CacCompatibilityState::Compatible,
            defects: vec![sample_blocked_defect()],
            executed_steps: vec![CacValidationStep::SchemaResolution],
            short_circuited: false,
        };

        assert_eq!(
            forged_result.recompute_compatibility_state(),
            CacCompatibilityState::Blocked
        );
        assert!(!forged_result.is_admissible());
    }

    #[test]
    fn test_forged_defect_compatibility_state_rejected() {
        let value = serde_json::json!({
            "class": "schema_unresolved",
            "step": "schema_resolution",
            "compatibility_state": "compatible",
            "detail": "forged compatible compatibility state",
        });

        let defect: CacDefect =
            serde_json::from_value(value).expect("defect should deserialize with derived state");

        assert_eq!(defect.compatibility_state(), CacCompatibilityState::Blocked);
        assert_eq!(
            defect.compatibility_state(),
            defect.class.compatibility_state()
        );
    }

    #[test]
    fn test_cac_validation_result_deserialize_rejects_incoherent_compatibility_state() {
        let value = serde_json::json!({
            "compatibility_state": "compatible",
            "defects": [{
                "class": "schema_unresolved",
                "step": "schema_resolution",
                "compatibility_state": "blocked",
                "detail": "forged blocked defect",
            }],
            "executed_steps": ["schema_resolution"],
            "short_circuited": true,
        });

        let error = serde_json::from_value::<CacValidationResult>(value)
            .expect_err("incoherent compatibility_state should fail during deserialization");

        assert!(
            error
                .to_string()
                .contains("does not match recomputed state")
        );
    }

    #[test]
    fn test_cac_validation_reports_digest_mismatch() {
        let registry = ContractObjectRegistry::default_registry();
        let entry = registry
            .lookup_by_schema_id("apm2.pcac_snapshot_report.v1")
            .expect("schema should resolve for digest mismatch test");
        let mut object = sample_admissible_object(entry);
        object.object_digest = Some([0x11; 32]);
        object.expected_digest = Some([0x22; 32]);
        object.declared_validation_order = CAC_VALIDATION_ORDER.to_vec();

        let result = validate_cac_contract(&registry, &object);
        assert_eq!(result.compatibility_state, CacCompatibilityState::Blocked);
        assert!(
            result
                .defects
                .iter()
                .any(|defect| defect.class == CacDefectClass::DigestMismatch)
        );
    }
}
