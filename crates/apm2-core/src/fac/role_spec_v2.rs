// AGENT-AUTHORED
//! `RoleSpec` v2 contract types for FAC `WorkObject` implementor policy.
//!
//! This module introduces `RoleSpecV2`, the hash-addressed contract artifact
//! for `fac_workobject_implementor_v2`. Compared to `RoleSpecV1`, v2 adds
//! mandatory security policy fields:
//!
//! - `tool_allowlists`: explicit per-tool allowlist
//! - `tool_budgets`: explicit per-tool token/invocation budgets
//! - `output_schema`: structured output field contract
//! - `deny_taxonomy`: explicit deny-condition -> deny-reason mapping
//!
//! Fail-closed semantics are mandatory: missing, stale, ambiguous, unknown, or
//! unverifiable policy state must deny.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;

use super::role_spec::{
    MAX_CAPABILITY_ID_LENGTH, MAX_DESCRIPTION_LENGTH, MAX_OUTPUT_SCHEMA_LENGTH, MAX_ROLE_ID_LENGTH,
    MAX_ROLE_NAME_LENGTH, MAX_TOOL_CLASS_LENGTH, RoleType,
};
use crate::evidence::{CasError, ContentAddressedStore};
use crate::htf::Canonicalizable;

/// `RoleSpec` v2 schema identifier.
pub const ROLE_SPEC_V2_SCHEMA: &str = "apm2.role_spec.v2";

/// Canonical role id for `WorkObject` implementor contract.
pub const FAC_WORKOBJECT_IMPLEMENTOR_V2_ROLE_ID: &str = "fac_workobject_implementor_v2";

/// Maximum number of tools in `tool_allowlists`.
pub const MAX_V2_TOOLS_IN_ALLOWLISTS: usize = 256;

/// Maximum number of per-tool budget entries.
pub const MAX_V2_TOOL_BUDGETS: usize = 256;

/// Maximum number of output schema fields.
pub const MAX_V2_OUTPUT_SCHEMA_FIELDS: usize = 128;

/// Maximum length of a field name in `output_schema.fields`.
pub const MAX_V2_OUTPUT_FIELD_NAME_LENGTH: usize = 128;

/// Maximum number of deny taxonomy entries.
pub const MAX_V2_DENY_TAXONOMY_ENTRIES: usize = 8;

/// Maximum length of a deny reason message.
pub const MAX_V2_DENY_REASON_MESSAGE_LENGTH: usize = 512;

/// Maximum number of required capabilities.
pub const MAX_V2_REQUIRED_CAPABILITIES: usize = 128;

/// Errors that can occur during role spec v2 operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum RoleSpecV2Error {
    /// Missing required field.
    #[error("missing required field: {0}")]
    MissingField(&'static str),

    /// Invalid schema identifier.
    #[error("invalid schema: expected {expected}, got {actual}")]
    InvalidSchema {
        /// Expected schema identifier.
        expected: String,
        /// Actual schema identifier.
        actual: String,
    },

    /// Unsupported role spec version.
    #[error("unsupported role spec version: {0}")]
    UnsupportedRoleSpecVersion(String),

    /// String field exceeds maximum length.
    #[error("string field '{field}' exceeds maximum length ({len} > {max})")]
    StringTooLong {
        /// Field name.
        field: &'static str,
        /// Actual length.
        len: usize,
        /// Maximum length.
        max: usize,
    },

    /// Collection field exceeds maximum count.
    #[error("collection field '{field}' exceeds maximum count ({count} > {max})")]
    CollectionTooLarge {
        /// Field name.
        field: &'static str,
        /// Actual count.
        count: usize,
        /// Maximum count.
        max: usize,
    },

    /// Invalid tool class in allowlist or budget map.
    #[error("invalid tool class: {0}")]
    InvalidToolClass(String),

    /// Required tool budget entry missing for an allowlisted tool.
    #[error("missing tool budget for allowlisted tool: {tool}")]
    MissingToolBudgetForAllowlistedTool {
        /// Tool class name.
        tool: String,
    },

    /// Tool budget exists for a tool not in allowlist.
    #[error("tool budget for '{tool}' not in allowlist")]
    ToolBudgetNotInAllowlist {
        /// Tool class name.
        tool: String,
    },

    /// Invalid tool budget configuration.
    #[error("invalid tool budget for '{tool}': {reason}")]
    InvalidToolBudget {
        /// Tool class name.
        tool: String,
        /// Failure reason.
        reason: String,
    },

    /// Deny taxonomy is missing a required condition mapping.
    #[error("deny taxonomy missing required condition: {condition}")]
    MissingDenyTaxonomyMapping {
        /// Missing condition.
        condition: DenyCondition,
    },

    /// Deny taxonomy code does not match the required mapping.
    #[error("deny taxonomy mismatch for {condition}: expected {expected}, got {actual}")]
    DenyTaxonomyMismatch {
        /// Deny condition.
        condition: DenyCondition,
        /// Expected deny reason code.
        expected: DenyReasonCode,
        /// Actual deny reason code.
        actual: DenyReasonCode,
    },

    /// Serialization failed.
    #[error("serialization error: {0}")]
    SerializationError(String),

    /// Deserialization failed.
    #[error("deserialization error: {0}")]
    DeserializationError(String),

    /// CAS error.
    #[error("CAS error: {0}")]
    CasError(String),
}

impl From<CasError> for RoleSpecV2Error {
    fn from(value: CasError) -> Self {
        Self::CasError(value.to_string())
    }
}

/// Deny conditions required by `RoleSpec` v2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DenyCondition {
    /// Missing authority context for evaluation.
    MissingAuthorityContext,
    /// Authority context is stale.
    StaleAuthorityContext,
    /// Role profile is unknown or unregistered.
    UnknownRoleProfile,
    /// Context hash cannot be verified.
    UnverifiableContextHash,
}

impl DenyCondition {
    /// Returns the required deny reason code for this condition.
    #[must_use]
    pub const fn required_code(self) -> DenyReasonCode {
        match self {
            Self::MissingAuthorityContext => DenyReasonCode::MissingAuthority,
            Self::StaleAuthorityContext => DenyReasonCode::StaleAuthority,
            Self::UnknownRoleProfile => DenyReasonCode::UnknownRole,
            Self::UnverifiableContextHash => DenyReasonCode::UnverifiableContext,
        }
    }

    /// Ordered list of required deny conditions.
    #[must_use]
    pub const fn required_conditions() -> [Self; 4] {
        [
            Self::MissingAuthorityContext,
            Self::StaleAuthorityContext,
            Self::UnknownRoleProfile,
            Self::UnverifiableContextHash,
        ]
    }
}

impl std::fmt::Display for DenyCondition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = match self {
            Self::MissingAuthorityContext => "missing_authority_context",
            Self::StaleAuthorityContext => "stale_authority_context",
            Self::UnknownRoleProfile => "unknown_role_profile",
            Self::UnverifiableContextHash => "unverifiable_context_hash",
        };
        write!(f, "{value}")
    }
}

/// Machine-readable deny reason code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DenyReasonCode {
    /// Deny due to missing authority context.
    MissingAuthority,
    /// Deny due to stale authority context.
    StaleAuthority,
    /// Deny due to unknown role profile.
    UnknownRole,
    /// Deny due to context hash not being verifiable.
    UnverifiableContext,
}

impl DenyReasonCode {
    #[must_use]
    const fn as_str(self) -> &'static str {
        match self {
            Self::MissingAuthority => "MISSING_AUTHORITY",
            Self::StaleAuthority => "STALE_AUTHORITY",
            Self::UnknownRole => "UNKNOWN_ROLE",
            Self::UnverifiableContext => "UNVERIFIABLE_CONTEXT",
        }
    }

    #[must_use]
    fn from_wire_or_restrictive(value: &str) -> Self {
        match value {
            "MISSING_AUTHORITY" => Self::MissingAuthority,
            "STALE_AUTHORITY" => Self::StaleAuthority,
            "UNKNOWN_ROLE" => Self::UnknownRole,
            // Unknown values default to the most restrictive class.
            _ => Self::UnverifiableContext,
        }
    }
}

impl std::fmt::Display for DenyReasonCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl Serialize for DenyReasonCode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for DenyReasonCode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Ok(Self::from_wire_or_restrictive(&raw))
    }
}

/// Structured deny reason object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DenyReason {
    /// Machine-readable deny code.
    pub code: DenyReasonCode,
    /// Human-readable reason text.
    pub message: String,
}

impl DenyReason {
    /// Creates a deny reason.
    #[must_use]
    pub fn new(code: DenyReasonCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

/// Per-tool token/invocation budget for `RoleSpec` v2.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolBudgetV2 {
    /// Maximum invocations per episode for this tool.
    pub max_invocations: u32,
    /// Maximum total tokens consumed by this tool per episode.
    pub max_tokens: u64,
}

impl ToolBudgetV2 {
    /// Creates a tool budget.
    #[must_use]
    pub const fn new(max_invocations: u32, max_tokens: u64) -> Self {
        Self {
            max_invocations,
            max_tokens,
        }
    }
}

/// Output schema field type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputFieldType {
    /// UTF-8 string value.
    String,
    /// Signed integer value.
    Integer,
    /// Floating-point or decimal number.
    Number,
    /// Boolean value.
    Boolean,
    /// Array/list value.
    Array,
    /// Object value.
    Object,
}

/// Single output field requirement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutputSchemaField {
    /// Expected field type.
    pub field_type: OutputFieldType,
    /// Whether this field is mandatory in output payloads.
    pub required: bool,
}

impl OutputSchemaField {
    /// Creates a required field.
    #[must_use]
    pub const fn required(field_type: OutputFieldType) -> Self {
        Self {
            field_type,
            required: true,
        }
    }

    /// Creates an optional field.
    #[must_use]
    pub const fn optional(field_type: OutputFieldType) -> Self {
        Self {
            field_type,
            required: false,
        }
    }
}

/// Structured output schema contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutputSchemaV2 {
    /// Schema identifier for output payload.
    pub schema_id: String,
    /// Field-level constraints keyed by field name.
    pub fields: BTreeMap<String, OutputSchemaField>,
}

impl OutputSchemaV2 {
    /// Creates an output schema with no fields.
    #[must_use]
    pub fn new(schema_id: impl Into<String>) -> Self {
        Self {
            schema_id: schema_id.into(),
            fields: BTreeMap::new(),
        }
    }

    /// Adds/overrides a field definition.
    #[must_use]
    pub fn with_field(mut self, name: impl Into<String>, field: OutputSchemaField) -> Self {
        self.fields.insert(name.into(), field);
        self
    }

    /// Validates output schema constraints.
    fn validate(&self) -> Result<(), RoleSpecV2Error> {
        if self.schema_id.is_empty() {
            return Err(RoleSpecV2Error::MissingField("output_schema.schema_id"));
        }
        if self.schema_id.len() > MAX_OUTPUT_SCHEMA_LENGTH {
            return Err(RoleSpecV2Error::StringTooLong {
                field: "output_schema.schema_id",
                len: self.schema_id.len(),
                max: MAX_OUTPUT_SCHEMA_LENGTH,
            });
        }
        if self.fields.is_empty() {
            return Err(RoleSpecV2Error::MissingField("output_schema.fields"));
        }
        if self.fields.len() > MAX_V2_OUTPUT_SCHEMA_FIELDS {
            return Err(RoleSpecV2Error::CollectionTooLarge {
                field: "output_schema.fields",
                count: self.fields.len(),
                max: MAX_V2_OUTPUT_SCHEMA_FIELDS,
            });
        }

        for name in self.fields.keys() {
            if name.is_empty() {
                return Err(RoleSpecV2Error::MissingField("output_schema.fields.name"));
            }
            if name.len() > MAX_V2_OUTPUT_FIELD_NAME_LENGTH {
                return Err(RoleSpecV2Error::StringTooLong {
                    field: "output_schema.fields.name",
                    len: name.len(),
                    max: MAX_V2_OUTPUT_FIELD_NAME_LENGTH,
                });
            }
        }

        Ok(())
    }
}

/// Role specification v2 contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleSpecV2 {
    /// Schema identifier (must be `apm2.role_spec.v2`).
    pub schema: String,
    /// Stable role id.
    pub role_id: String,
    /// Human-readable role name.
    pub role_name: String,
    /// Role type.
    pub role_type: RoleType,
    /// Role description.
    pub description: String,
    /// Explicit allowlist of permitted tool names.
    pub tool_allowlists: BTreeSet<String>,
    /// Explicit per-tool token/invocation budgets.
    pub tool_budgets: BTreeMap<String, ToolBudgetV2>,
    /// Expected structured output schema.
    pub output_schema: OutputSchemaV2,
    /// Explicit deny-condition -> deny-reason mapping.
    pub deny_taxonomy: BTreeMap<DenyCondition, DenyReason>,
    /// Required capabilities by id and minimum level.
    pub required_capabilities: BTreeMap<String, u8>,
}

impl RoleSpecV2 {
    /// Validates this role contract.
    ///
    /// Missing/unknown/ambiguous state is treated as deny (fail-closed).
    ///
    /// # Errors
    ///
    /// Returns [`RoleSpecV2Error`] if any required field is missing, malformed,
    /// ambiguous, or violates bounded-policy constraints.
    #[allow(clippy::too_many_lines)]
    pub fn validate(&self) -> Result<(), RoleSpecV2Error> {
        if self.schema != ROLE_SPEC_V2_SCHEMA {
            if self.schema.starts_with("apm2.role_spec.") {
                return Err(RoleSpecV2Error::UnsupportedRoleSpecVersion(
                    self.schema.clone(),
                ));
            }
            return Err(RoleSpecV2Error::InvalidSchema {
                expected: ROLE_SPEC_V2_SCHEMA.to_string(),
                actual: self.schema.clone(),
            });
        }

        if self.role_id.is_empty() {
            return Err(RoleSpecV2Error::MissingField("role_id"));
        }
        if self.role_id.len() > MAX_ROLE_ID_LENGTH {
            return Err(RoleSpecV2Error::StringTooLong {
                field: "role_id",
                len: self.role_id.len(),
                max: MAX_ROLE_ID_LENGTH,
            });
        }

        if self.role_name.is_empty() {
            return Err(RoleSpecV2Error::MissingField("role_name"));
        }
        if self.role_name.len() > MAX_ROLE_NAME_LENGTH {
            return Err(RoleSpecV2Error::StringTooLong {
                field: "role_name",
                len: self.role_name.len(),
                max: MAX_ROLE_NAME_LENGTH,
            });
        }

        if self.description.len() > MAX_DESCRIPTION_LENGTH {
            return Err(RoleSpecV2Error::StringTooLong {
                field: "description",
                len: self.description.len(),
                max: MAX_DESCRIPTION_LENGTH,
            });
        }

        if self.tool_allowlists.is_empty() {
            return Err(RoleSpecV2Error::MissingField("tool_allowlists"));
        }
        if self.tool_allowlists.len() > MAX_V2_TOOLS_IN_ALLOWLISTS {
            return Err(RoleSpecV2Error::CollectionTooLarge {
                field: "tool_allowlists",
                count: self.tool_allowlists.len(),
                max: MAX_V2_TOOLS_IN_ALLOWLISTS,
            });
        }
        for tool in &self.tool_allowlists {
            Self::validate_tool_name(tool)?;
        }

        if self.tool_budgets.is_empty() {
            return Err(RoleSpecV2Error::MissingField("tool_budgets"));
        }
        if self.tool_budgets.len() > MAX_V2_TOOL_BUDGETS {
            return Err(RoleSpecV2Error::CollectionTooLarge {
                field: "tool_budgets",
                count: self.tool_budgets.len(),
                max: MAX_V2_TOOL_BUDGETS,
            });
        }
        for tool in &self.tool_allowlists {
            if !self.tool_budgets.contains_key(tool) {
                return Err(RoleSpecV2Error::MissingToolBudgetForAllowlistedTool {
                    tool: tool.clone(),
                });
            }
        }
        for (tool, budget) in &self.tool_budgets {
            Self::validate_tool_name(tool)?;
            if !self.tool_allowlists.contains(tool) {
                return Err(RoleSpecV2Error::ToolBudgetNotInAllowlist { tool: tool.clone() });
            }
            if budget.max_invocations == 0 {
                return Err(RoleSpecV2Error::InvalidToolBudget {
                    tool: tool.clone(),
                    reason: "max_invocations must be > 0".to_string(),
                });
            }
            if budget.max_tokens == 0 {
                return Err(RoleSpecV2Error::InvalidToolBudget {
                    tool: tool.clone(),
                    reason: "max_tokens must be > 0".to_string(),
                });
            }
        }

        self.output_schema.validate()?;

        if self.deny_taxonomy.is_empty() {
            return Err(RoleSpecV2Error::MissingField("deny_taxonomy"));
        }
        if self.deny_taxonomy.len() > MAX_V2_DENY_TAXONOMY_ENTRIES {
            return Err(RoleSpecV2Error::CollectionTooLarge {
                field: "deny_taxonomy",
                count: self.deny_taxonomy.len(),
                max: MAX_V2_DENY_TAXONOMY_ENTRIES,
            });
        }
        for condition in DenyCondition::required_conditions() {
            let Some(reason) = self.deny_taxonomy.get(&condition) else {
                return Err(RoleSpecV2Error::MissingDenyTaxonomyMapping { condition });
            };
            let expected = condition.required_code();
            if reason.code != expected {
                return Err(RoleSpecV2Error::DenyTaxonomyMismatch {
                    condition,
                    expected,
                    actual: reason.code,
                });
            }
            if reason.message.is_empty() {
                return Err(RoleSpecV2Error::MissingField("deny_taxonomy.message"));
            }
            if reason.message.len() > MAX_V2_DENY_REASON_MESSAGE_LENGTH {
                return Err(RoleSpecV2Error::StringTooLong {
                    field: "deny_taxonomy.message",
                    len: reason.message.len(),
                    max: MAX_V2_DENY_REASON_MESSAGE_LENGTH,
                });
            }
        }

        if self.required_capabilities.len() > MAX_V2_REQUIRED_CAPABILITIES {
            return Err(RoleSpecV2Error::CollectionTooLarge {
                field: "required_capabilities",
                count: self.required_capabilities.len(),
                max: MAX_V2_REQUIRED_CAPABILITIES,
            });
        }
        for cap_id in self.required_capabilities.keys() {
            if cap_id.is_empty() {
                return Err(RoleSpecV2Error::MissingField(
                    "required_capabilities.capability_id",
                ));
            }
            if cap_id.len() > MAX_CAPABILITY_ID_LENGTH {
                return Err(RoleSpecV2Error::StringTooLong {
                    field: "required_capabilities.capability_id",
                    len: cap_id.len(),
                    max: MAX_CAPABILITY_ID_LENGTH,
                });
            }
        }

        Ok(())
    }

    /// Returns deny reason for a condition. If taxonomy is incomplete, this
    /// defaults to most restrictive deny class.
    #[must_use]
    pub fn deny_reason_for(&self, condition: DenyCondition) -> DenyReason {
        self.deny_taxonomy
            .get(&condition)
            .cloned()
            .unwrap_or_else(|| {
                DenyReason::new(
                    DenyReasonCode::UnverifiableContext,
                    "deny taxonomy incomplete; fail-closed",
                )
            })
    }

    /// Computes deterministic CAS hash.
    ///
    /// # Errors
    ///
    /// Returns [`RoleSpecV2Error::SerializationError`] if canonicalization
    /// fails.
    pub fn compute_cas_hash(&self) -> Result<[u8; 32], RoleSpecV2Error> {
        self.canonical_bytes()
            .map(|bytes| *blake3::hash(&bytes).as_bytes())
            .map_err(|e| {
                RoleSpecV2Error::SerializationError(format!("canonicalization failed: {e}"))
            })
    }

    /// Stores this role contract in CAS and returns hash.
    ///
    /// # Errors
    ///
    /// Returns [`RoleSpecV2Error`] if validation fails, canonicalization fails,
    /// or CAS storage fails.
    pub fn store_in_cas(
        &self,
        cas: &dyn ContentAddressedStore,
    ) -> Result<[u8; 32], RoleSpecV2Error> {
        self.validate()?;
        let bytes = self.canonical_bytes().map_err(|e| {
            RoleSpecV2Error::SerializationError(format!("canonicalization failed: {e}"))
        })?;
        let result = cas.store(&bytes)?;
        Ok(result.hash)
    }

    /// Loads a role contract from CAS by hash.
    ///
    /// # Errors
    ///
    /// Returns [`RoleSpecV2Error`] if CAS retrieval fails, deserialization
    /// fails, validation fails, or hash verification fails.
    pub fn load_from_cas(
        cas: &dyn ContentAddressedStore,
        hash: &[u8; 32],
    ) -> Result<Self, RoleSpecV2Error> {
        let bytes = cas.retrieve(hash)?;
        let spec: Self = serde_json::from_slice(&bytes)
            .map_err(|e| RoleSpecV2Error::DeserializationError(e.to_string()))?;
        spec.validate()?;

        let computed_hash = spec.compute_cas_hash()?;
        if computed_hash != *hash {
            return Err(RoleSpecV2Error::CasError(format!(
                "hash mismatch: expected {}, got {}",
                hex::encode(hash),
                hex::encode(computed_hash)
            )));
        }
        Ok(spec)
    }

    fn validate_tool_name(tool: &str) -> Result<(), RoleSpecV2Error> {
        if tool.is_empty() {
            return Err(RoleSpecV2Error::InvalidToolClass(
                "tool class cannot be empty".to_string(),
            ));
        }
        if tool.len() > MAX_TOOL_CLASS_LENGTH {
            return Err(RoleSpecV2Error::StringTooLong {
                field: "tool_class",
                len: tool.len(),
                max: MAX_TOOL_CLASS_LENGTH,
            });
        }
        if !tool.starts_with("kernel.") {
            return Err(RoleSpecV2Error::InvalidToolClass(format!(
                "tool class '{tool}' must start with 'kernel.'"
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::MemoryCas;

    fn valid_role_spec_v2() -> RoleSpecV2 {
        let mut tool_allowlists = BTreeSet::new();
        tool_allowlists.insert("kernel.fs.read".to_string());
        tool_allowlists.insert("kernel.fs.write".to_string());
        tool_allowlists.insert("kernel.shell.exec".to_string());

        let mut tool_budgets = BTreeMap::new();
        tool_budgets.insert("kernel.fs.read".to_string(), ToolBudgetV2::new(80, 240_000));
        tool_budgets.insert(
            "kernel.fs.write".to_string(),
            ToolBudgetV2::new(40, 160_000),
        );
        tool_budgets.insert(
            "kernel.shell.exec".to_string(),
            ToolBudgetV2::new(20, 320_000),
        );

        let output_schema = OutputSchemaV2::new("apm2.fac_workobject_implementor_output.v2")
            .with_field(
                "status",
                OutputSchemaField::required(OutputFieldType::String),
            )
            .with_field(
                "work_id",
                OutputSchemaField::required(OutputFieldType::String),
            )
            .with_field(
                "changeset_bundle_hash",
                OutputSchemaField::required(OutputFieldType::String),
            )
            .with_field(
                "evidence_refs",
                OutputSchemaField::optional(OutputFieldType::Array),
            );

        let mut deny_taxonomy = BTreeMap::new();
        deny_taxonomy.insert(
            DenyCondition::MissingAuthorityContext,
            DenyReason::new(
                DenyReasonCode::MissingAuthority,
                "authority context missing at evaluation boundary",
            ),
        );
        deny_taxonomy.insert(
            DenyCondition::StaleAuthorityContext,
            DenyReason::new(
                DenyReasonCode::StaleAuthority,
                "authority context is stale for current gate window",
            ),
        );
        deny_taxonomy.insert(
            DenyCondition::UnknownRoleProfile,
            DenyReason::new(
                DenyReasonCode::UnknownRole,
                "role profile is not registered in deterministic registry",
            ),
        );
        deny_taxonomy.insert(
            DenyCondition::UnverifiableContextHash,
            DenyReason::new(
                DenyReasonCode::UnverifiableContext,
                "context hash cannot be verified against authority source",
            ),
        );

        let mut required_capabilities = BTreeMap::new();
        required_capabilities.insert("fs.read".to_string(), 0);
        required_capabilities.insert("fs.write".to_string(), 1);
        required_capabilities.insert("shell.exec".to_string(), 1);

        RoleSpecV2 {
            schema: ROLE_SPEC_V2_SCHEMA.to_string(),
            role_id: FAC_WORKOBJECT_IMPLEMENTOR_V2_ROLE_ID.to_string(),
            role_name: "FAC WorkObject Implementor".to_string(),
            role_type: RoleType::Implementer,
            description: "Implements WorkObject tasks under strict deny taxonomy.".to_string(),
            tool_allowlists,
            tool_budgets,
            output_schema,
            deny_taxonomy,
            required_capabilities,
        }
    }

    #[test]
    fn role_spec_v2_validates() {
        let spec = valid_role_spec_v2();
        assert!(spec.validate().is_ok());
    }

    #[test]
    fn role_spec_v2_hash_is_deterministic() {
        let a = valid_role_spec_v2();
        let b = valid_role_spec_v2();

        assert_eq!(a.compute_cas_hash().unwrap(), b.compute_cas_hash().unwrap());
    }

    #[test]
    fn role_spec_v2_hash_stable_across_serialization_roundtrip() {
        let spec = valid_role_spec_v2();
        let original_hash = spec.compute_cas_hash().unwrap();

        let json = serde_json::to_string(&spec).unwrap();
        let loaded: RoleSpecV2 = serde_json::from_str(&json).unwrap();
        let roundtrip_hash = loaded.compute_cas_hash().unwrap();

        assert_eq!(original_hash, roundtrip_hash);
    }

    #[test]
    fn role_spec_v2_cas_roundtrip() {
        let cas = MemoryCas::new();
        let spec = valid_role_spec_v2();

        let hash = spec.store_in_cas(&cas).unwrap();
        let loaded = RoleSpecV2::load_from_cas(&cas, &hash).unwrap();

        assert_eq!(spec, loaded);
    }

    #[test]
    fn missing_tool_budgets_field_is_rejected() {
        let mut value = serde_json::to_value(valid_role_spec_v2()).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .remove("tool_budgets")
            .expect("tool_budgets should exist");

        let parsed: Result<RoleSpecV2, _> = serde_json::from_value(value);
        assert!(parsed.is_err());
    }

    #[test]
    fn missing_output_schema_field_is_rejected() {
        let mut value = serde_json::to_value(valid_role_spec_v2()).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .remove("output_schema")
            .expect("output_schema should exist");

        let parsed: Result<RoleSpecV2, _> = serde_json::from_value(value);
        assert!(parsed.is_err());
    }

    #[test]
    fn missing_deny_taxonomy_field_is_rejected() {
        let mut value = serde_json::to_value(valid_role_spec_v2()).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .remove("deny_taxonomy")
            .expect("deny_taxonomy should exist");

        let parsed: Result<RoleSpecV2, _> = serde_json::from_value(value);
        assert!(parsed.is_err());
    }

    #[test]
    fn empty_tool_allowlists_is_rejected_fail_closed() {
        let mut spec = valid_role_spec_v2();
        spec.tool_allowlists.clear();
        let err = spec.validate().unwrap_err();
        assert!(matches!(
            err,
            RoleSpecV2Error::MissingField("tool_allowlists")
        ));
    }

    #[test]
    fn empty_output_schema_fields_is_rejected_fail_closed() {
        let mut spec = valid_role_spec_v2();
        spec.output_schema.fields.clear();
        let err = spec.validate().unwrap_err();
        assert!(matches!(
            err,
            RoleSpecV2Error::MissingField("output_schema.fields")
        ));
    }

    #[test]
    fn empty_deny_taxonomy_is_rejected_fail_closed() {
        let mut spec = valid_role_spec_v2();
        spec.deny_taxonomy.clear();
        let err = spec.validate().unwrap_err();
        assert!(matches!(
            err,
            RoleSpecV2Error::MissingField("deny_taxonomy")
        ));
    }

    #[test]
    fn unsupported_role_version_is_rejected() {
        let mut spec = valid_role_spec_v2();
        spec.schema = "apm2.role_spec.v9".to_string();

        let err = spec.validate().unwrap_err();
        assert!(matches!(
            err,
            RoleSpecV2Error::UnsupportedRoleSpecVersion(_)
        ));
    }

    #[test]
    fn null_security_critical_field_is_rejected() {
        let mut value = serde_json::to_value(valid_role_spec_v2()).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("deny_taxonomy".to_string(), serde_json::Value::Null);

        let parsed: Result<RoleSpecV2, _> = serde_json::from_value(value);
        assert!(parsed.is_err());
    }

    #[test]
    fn security_enum_field_missing_code_does_not_default() {
        let mut value = serde_json::to_value(valid_role_spec_v2()).unwrap();
        value
            .get_mut("deny_taxonomy")
            .unwrap()
            .get_mut("missing_authority_context")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .remove("code")
            .expect("code should exist");

        let parsed: Result<RoleSpecV2, _> = serde_json::from_value(value);
        assert!(
            parsed.is_err(),
            "missing enum field must not default for security-critical deny reason code"
        );
    }

    #[test]
    fn unknown_deny_reason_code_defaults_restrictive_and_fails_mapping() {
        let mut value = serde_json::to_value(valid_role_spec_v2()).unwrap();
        value
            .get_mut("deny_taxonomy")
            .unwrap()
            .get_mut("missing_authority_context")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert(
                "code".to_string(),
                serde_json::Value::String("NOT_A_REAL_CODE".to_string()),
            );

        let parsed: RoleSpecV2 = serde_json::from_value(value).unwrap();
        let err = parsed.validate().unwrap_err();
        assert!(matches!(
            err,
            RoleSpecV2Error::DenyTaxonomyMismatch {
                condition: DenyCondition::MissingAuthorityContext,
                ..
            }
        ));
    }

    #[test]
    fn deny_reason_lookup_falls_back_to_unverifiable_context() {
        let mut spec = valid_role_spec_v2();
        spec.deny_taxonomy.clear();

        let reason = spec.deny_reason_for(DenyCondition::UnknownRoleProfile);
        assert_eq!(reason.code, DenyReasonCode::UnverifiableContext);
        assert_eq!(reason.message, "deny taxonomy incomplete; fail-closed");
    }
}
