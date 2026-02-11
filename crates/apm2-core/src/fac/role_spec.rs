// AGENT-AUTHORED
//! Role specification types for FAC v0 agent role definitions.
//!
//! This module implements the `RoleSpecV1` structure used to define agent roles
//! with their tool-call matrix (allowed tools + budgets) under holonic boundary
//! discipline.
//!
//! # Overview
//!
//! Per RFC-0019 Addendum (`10_fac_efficiency_and_role_specs.md`), each role
//! MUST have:
//! - A narrowly scoped `RoleSpecV1` (hash-addressed)
//! - Explicit tool allowlists and budgets
//! - Defined output schemas for conformance harness
//!
//! `RoleSpecV1` is a CAS-addressed artifact. Role selection is explicit by
//! hash; **ambient defaults are forbidden**.
//!
//! # Security Properties
//!
//! - **CAS Storage**: Role spec is stored in CAS and referenced by hash
//! - **No Ambient Defaults**: Roles must be explicitly selected by hash
//! - **Deny-by-Default**: Tool allowlists enforce deny-by-default for tools
//! - **Budget Enforcement**: Each role has explicit tool call and resource
//!   budgets
//!
//! # Built-in Roles
//!
//! Per RFC-0019, the minimum role specs are:
//! - `orchestrator`: Allocates work, enforces budgets/stop conditions
//! - `implementer`: Generates changesets addressing reviewer feedback
//! - `code_quality_reviewer`: Assesses correctness, style, maintainability
//! - `security_reviewer`: Detects unsafe patterns, policy violations
//!
//! # Example
//!
//! ```rust
//! use std::collections::BTreeSet;
//!
//! use apm2_core::fac::{RoleBudgets, RoleSpecV1, ToolAllowlist, ToolBudget};
//!
//! let mut allowed_tools = BTreeSet::new();
//! allowed_tools.insert("kernel.fs.read".to_string());
//! allowed_tools.insert("kernel.fs.search".to_string());
//!
//! let role_spec = RoleSpecV1::builder()
//!     .role_id("code_quality_reviewer")
//!     .role_name("Code Quality Reviewer")
//!     .description("Assesses code correctness, style, and maintainability")
//!     .tool_allowlist(ToolAllowlist::new(allowed_tools))
//!     .budgets(RoleBudgets::default())
//!     .build()
//!     .expect("valid role spec");
//!
//! assert!(role_spec.validate().is_ok());
//! let cas_hash = role_spec.compute_cas_hash().expect("hash computation");
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::evidence::{CasError, ContentAddressedStore};
use crate::htf::Canonicalizable;

// =============================================================================
// Schema Constants and Limits
// =============================================================================

/// Role Spec V1 schema identifier.
pub const ROLE_SPEC_V1_SCHEMA: &str = "apm2.role_spec.v1";

/// Maximum length for `role_id` field.
pub const MAX_ROLE_ID_LENGTH: usize = 128;

/// Maximum length for `role_name` field.
pub const MAX_ROLE_NAME_LENGTH: usize = 256;

/// Maximum length for `description` field.
pub const MAX_DESCRIPTION_LENGTH: usize = 4096;

/// Maximum number of tools in the allowlist.
pub const MAX_TOOLS_IN_ALLOWLIST: usize = 256;

/// Maximum length for a tool class name.
pub const MAX_TOOL_CLASS_LENGTH: usize = 128;

/// Maximum number of required output schemas.
pub const MAX_REQUIRED_OUTPUT_SCHEMAS: usize = 64;

/// Maximum length for an output schema identifier.
pub const MAX_OUTPUT_SCHEMA_LENGTH: usize = 256;

/// Maximum number of tool-specific budgets.
pub const MAX_TOOL_BUDGETS: usize = 256;

/// Maximum length for capability ID.
pub const MAX_CAPABILITY_ID_LENGTH: usize = 128;

/// Forbidden direct GitHub capability classes for production `agent_runtime`
/// projection isolation (RFC-0028 REQ-0008).
pub const FORBIDDEN_DIRECT_GITHUB_CAPABILITY_CLASSES: [&str; 4] = [
    "github_api",
    "gh_cli",
    "forge_org_admin",
    "forge_repo_admin",
];

/// Returns the forbidden direct GitHub capability class if `capability_id`
/// resolves to one, otherwise `None`.
#[must_use]
pub fn forbidden_direct_github_capability_class(capability_id: &str) -> Option<&'static str> {
    let normalized = capability_id.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return None;
    }

    let normalized = normalized
        .strip_prefix("kernel.")
        .unwrap_or(&normalized)
        .trim();

    let class = normalized
        .split(['.', ':', '/'])
        .find(|segment| !segment.is_empty())
        .unwrap_or(normalized);

    FORBIDDEN_DIRECT_GITHUB_CAPABILITY_CLASSES
        .iter()
        .copied()
        .find(|forbidden| class == *forbidden)
}

// =============================================================================
// Error Types
// =============================================================================

/// Errors that can occur during role spec operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum RoleSpecError {
    /// Missing required field.
    #[error("missing required field: {0}")]
    MissingField(&'static str),

    /// String field exceeds maximum length.
    #[error("string field '{field}' exceeds maximum length ({len} > {max})")]
    StringTooLong {
        /// The field name.
        field: &'static str,
        /// Actual length.
        len: usize,
        /// Maximum allowed length.
        max: usize,
    },

    /// Invalid schema identifier.
    #[error("invalid schema: expected {expected}, got {actual}")]
    InvalidSchema {
        /// Expected schema.
        expected: String,
        /// Actual schema.
        actual: String,
    },

    /// Collection field exceeds maximum count.
    #[error("collection field '{field}' exceeds maximum count ({count} > {max})")]
    CollectionTooLarge {
        /// The field name.
        field: &'static str,
        /// Actual count.
        count: usize,
        /// Maximum allowed count.
        max: usize,
    },

    /// Invalid tool class in allowlist.
    #[error("invalid tool class: {0}")]
    InvalidToolClass(String),

    /// Forbidden direct GitHub capability class for production agent runtime.
    #[error("forbidden direct GitHub capability class: {0}")]
    ForbiddenCapabilityClass(String),

    /// Tool budget specified for tool not in allowlist.
    #[error("tool budget for '{tool}' not in allowlist")]
    ToolBudgetNotInAllowlist {
        /// The tool class.
        tool: String,
    },

    /// Invalid role type.
    #[error("invalid role type: {0}")]
    InvalidRoleType(String),

    /// CAS error.
    #[error("CAS error: {0}")]
    CasError(String),

    /// Serialization error.
    #[error("serialization error: {0}")]
    SerializationError(String),

    /// Output schema inconsistency.
    #[error("output schema inconsistency: {0}")]
    OutputSchemaInconsistency(String),

    /// Tool allowlist inconsistency.
    #[error("tool allowlist inconsistency: {0}")]
    ToolAllowlistInconsistency(String),
}

impl From<CasError> for RoleSpecError {
    fn from(e: CasError) -> Self {
        Self::CasError(e.to_string())
    }
}

// =============================================================================
// RoleType
// =============================================================================

/// The type of agent role.
///
/// Per RFC-0019 Addendum, there are four minimum role types:
/// - `Orchestrator`: Allocates work, enforces budgets
/// - `Implementer`: Generates changesets
/// - `CodeQualityReviewer`: Reviews code quality
/// - `SecurityReviewer`: Reviews security aspects
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoleType {
    /// Orchestrator role: allocates work, enforces budgets/stop conditions.
    Orchestrator,
    /// Implementer role: generates changesets addressing feedback.
    Implementer,
    /// Code quality reviewer role: assesses correctness, style,
    /// maintainability.
    CodeQualityReviewer,
    /// Security reviewer role: detects unsafe patterns, policy violations.
    SecurityReviewer,
    /// Test flake fixer: fixes test failures.
    TestFlakeFixer,
    /// Rust compile error fixer: fixes compilation errors.
    RustCompileErrorFixer,
    /// Dependency updater: updates dependencies.
    DependencyUpdater,
    /// Custom role: user-defined role with explicit specification.
    Custom,
}

impl std::fmt::Display for RoleType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Orchestrator => write!(f, "orchestrator"),
            Self::Implementer => write!(f, "implementer"),
            Self::CodeQualityReviewer => write!(f, "code_quality_reviewer"),
            Self::SecurityReviewer => write!(f, "security_reviewer"),
            Self::TestFlakeFixer => write!(f, "test_flake_fixer"),
            Self::RustCompileErrorFixer => write!(f, "rust_compile_error_fixer"),
            Self::DependencyUpdater => write!(f, "dependency_updater"),
            Self::Custom => write!(f, "custom"),
        }
    }
}

impl FromStr for RoleType {
    type Err = RoleSpecError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "orchestrator" => Ok(Self::Orchestrator),
            "implementer" => Ok(Self::Implementer),
            "code_quality_reviewer" => Ok(Self::CodeQualityReviewer),
            "security_reviewer" => Ok(Self::SecurityReviewer),
            "test_flake_fixer" => Ok(Self::TestFlakeFixer),
            "rust_compile_error_fixer" => Ok(Self::RustCompileErrorFixer),
            "dependency_updater" => Ok(Self::DependencyUpdater),
            "custom" => Ok(Self::Custom),
            _ => Err(RoleSpecError::InvalidRoleType(s.to_string())),
        }
    }
}

// =============================================================================
// ToolBudget
// =============================================================================

/// Budget limits for a specific tool class.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolBudget {
    /// Maximum number of calls to this tool per episode.
    pub max_calls_per_episode: u32,
    /// Maximum total bytes of arguments per episode.
    pub max_args_bytes_per_episode: u64,
    /// Maximum total bytes of results per episode.
    pub max_result_bytes_per_episode: u64,
    /// Timeout per call in milliseconds.
    pub timeout_ms_per_call: u64,
}

impl Default for ToolBudget {
    fn default() -> Self {
        Self {
            max_calls_per_episode: 100,
            max_args_bytes_per_episode: 10 * 1024 * 1024, // 10 MB
            max_result_bytes_per_episode: 10 * 1024 * 1024, // 10 MB
            timeout_ms_per_call: 60_000,                  // 60 seconds
        }
    }
}

impl ToolBudget {
    /// Creates a new tool budget with the given limits.
    #[must_use]
    pub const fn new(
        max_calls_per_episode: u32,
        max_args_bytes_per_episode: u64,
        max_result_bytes_per_episode: u64,
        timeout_ms_per_call: u64,
    ) -> Self {
        Self {
            max_calls_per_episode,
            max_args_bytes_per_episode,
            max_result_bytes_per_episode,
            timeout_ms_per_call,
        }
    }

    /// Creates a restrictive budget for read-only operations.
    #[must_use]
    pub const fn read_only() -> Self {
        Self {
            max_calls_per_episode: 50,
            max_args_bytes_per_episode: 1024 * 1024, // 1 MB
            max_result_bytes_per_episode: 10 * 1024 * 1024, // 10 MB
            timeout_ms_per_call: 30_000,             // 30 seconds
        }
    }

    /// Creates a budget for write operations.
    #[must_use]
    pub const fn write() -> Self {
        Self {
            max_calls_per_episode: 50,
            max_args_bytes_per_episode: 5 * 1024 * 1024, // 5 MB
            max_result_bytes_per_episode: 1024 * 1024,   // 1 MB
            timeout_ms_per_call: 60_000,                 // 60 seconds
        }
    }

    /// Creates a budget for shell execution operations.
    #[must_use]
    pub const fn shell_exec() -> Self {
        Self {
            max_calls_per_episode: 20,
            max_args_bytes_per_episode: 1024 * 1024, // 1 MB
            max_result_bytes_per_episode: 5 * 1024 * 1024, // 5 MB
            timeout_ms_per_call: 300_000,            // 5 minutes
        }
    }
}

// =============================================================================
// ToolAllowlist
// =============================================================================

/// Allowlist of tool classes that a role may use.
///
/// This implements the deny-by-default principle: only tools explicitly listed
/// are allowed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolAllowlist {
    /// Set of allowed tool class identifiers (e.g., "kernel.fs.read").
    pub allowed_tools: BTreeSet<String>,
    /// Per-tool budget overrides (tool class -> budget).
    /// Tools not in this map use `RoleBudgets::default_tool_budget`.
    pub tool_budgets: BTreeMap<String, ToolBudget>,
}

impl ToolAllowlist {
    /// Creates a new tool allowlist with the given tools.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // BTreeSet doesn't have const constructors
    pub fn new(allowed_tools: BTreeSet<String>) -> Self {
        Self {
            allowed_tools,
            tool_budgets: BTreeMap::new(),
        }
    }

    /// Creates an empty tool allowlist.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Adds a tool to the allowlist.
    #[must_use]
    pub fn with_tool(mut self, tool_class: impl Into<String>) -> Self {
        self.allowed_tools.insert(tool_class.into());
        self
    }

    /// Adds a tool with a specific budget.
    #[must_use]
    pub fn with_tool_and_budget(
        mut self,
        tool_class: impl Into<String>,
        budget: ToolBudget,
    ) -> Self {
        let tool_class = tool_class.into();
        self.allowed_tools.insert(tool_class.clone());
        self.tool_budgets.insert(tool_class, budget);
        self
    }

    /// Returns true if the tool is allowed.
    #[must_use]
    pub fn is_allowed(&self, tool_class: &str) -> bool {
        self.allowed_tools.contains(tool_class)
    }

    /// Returns the budget for a tool, if it has a specific budget.
    #[must_use]
    pub fn get_budget(&self, tool_class: &str) -> Option<&ToolBudget> {
        self.tool_budgets.get(tool_class)
    }

    /// Validates the tool allowlist.
    ///
    /// # Errors
    ///
    /// Returns error if validation fails.
    pub fn validate(&self) -> Result<(), RoleSpecError> {
        // Check allowlist size
        if self.allowed_tools.len() > MAX_TOOLS_IN_ALLOWLIST {
            return Err(RoleSpecError::CollectionTooLarge {
                field: "allowed_tools",
                count: self.allowed_tools.len(),
                max: MAX_TOOLS_IN_ALLOWLIST,
            });
        }

        // Validate tool class names
        for tool_class in &self.allowed_tools {
            if tool_class.is_empty() {
                return Err(RoleSpecError::InvalidToolClass(
                    "tool class cannot be empty".to_string(),
                ));
            }
            if tool_class.len() > MAX_TOOL_CLASS_LENGTH {
                return Err(RoleSpecError::StringTooLong {
                    field: "tool_class",
                    len: tool_class.len(),
                    max: MAX_TOOL_CLASS_LENGTH,
                });
            }
            // Tool classes should follow kernel namespace convention
            if !tool_class.starts_with("kernel.") {
                return Err(RoleSpecError::InvalidToolClass(format!(
                    "tool class '{tool_class}' must start with 'kernel.'"
                )));
            }
        }

        // Check tool budgets size
        if self.tool_budgets.len() > MAX_TOOL_BUDGETS {
            return Err(RoleSpecError::CollectionTooLarge {
                field: "tool_budgets",
                count: self.tool_budgets.len(),
                max: MAX_TOOL_BUDGETS,
            });
        }

        // Validate that all tools with budgets are in the allowlist
        for tool_class in self.tool_budgets.keys() {
            if !self.allowed_tools.contains(tool_class) {
                return Err(RoleSpecError::ToolBudgetNotInAllowlist {
                    tool: tool_class.clone(),
                });
            }
        }

        Ok(())
    }
}

// =============================================================================
// RoleBudgets
// =============================================================================

/// Overall budget limits for a role.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleBudgets {
    /// Maximum number of tool calls per episode (across all tools).
    pub max_total_tool_calls: u32,
    /// Maximum tokens (input + output) per episode.
    pub max_tokens: u64,
    /// Maximum wall clock time per episode in milliseconds.
    pub max_wall_clock_ms: u64,
    /// Maximum evidence size per episode in bytes.
    pub max_evidence_bytes: u64,
    /// Default budget for tools without specific budget overrides.
    pub default_tool_budget: ToolBudget,
}

impl Default for RoleBudgets {
    fn default() -> Self {
        Self {
            max_total_tool_calls: 100,
            max_tokens: 1_000_000,
            max_wall_clock_ms: 3_600_000,          // 1 hour
            max_evidence_bytes: 100 * 1024 * 1024, // 100 MB
            default_tool_budget: ToolBudget::default(),
        }
    }
}

#[allow(clippy::missing_const_for_fn)] // Cannot be const due to ToolBudget::read_only()
impl RoleBudgets {
    /// Creates budgets suitable for orchestrator role.
    #[must_use]
    pub fn orchestrator() -> Self {
        Self {
            max_total_tool_calls: 50,
            max_tokens: 500_000,
            max_wall_clock_ms: 1_800_000, // 30 minutes
            max_evidence_bytes: 50 * 1024 * 1024,
            default_tool_budget: ToolBudget::read_only(),
        }
    }

    /// Creates budgets suitable for implementer role.
    #[must_use]
    pub fn implementer() -> Self {
        Self {
            max_total_tool_calls: 200,
            max_tokens: 2_000_000,
            max_wall_clock_ms: 7_200_000, // 2 hours
            max_evidence_bytes: 200 * 1024 * 1024,
            default_tool_budget: ToolBudget::default(),
        }
    }

    /// Creates budgets suitable for reviewer roles.
    #[must_use]
    pub fn reviewer() -> Self {
        Self {
            max_total_tool_calls: 100,
            max_tokens: 1_000_000,
            max_wall_clock_ms: 3_600_000, // 1 hour
            max_evidence_bytes: 100 * 1024 * 1024,
            default_tool_budget: ToolBudget::read_only(),
        }
    }

    /// Creates budgets suitable for specialist roles.
    ///
    /// Specialists have narrower budgets than generalist implementers because
    /// they are focused on specific, well-scoped tasks (e.g., fixing a single
    /// compile error or test flake).
    #[must_use]
    pub fn specialist() -> Self {
        Self {
            max_total_tool_calls: 50,
            max_tokens: 500_000,
            max_wall_clock_ms: 1_800_000, // 30 minutes
            max_evidence_bytes: 50 * 1024 * 1024,
            default_tool_budget: ToolBudget::default(),
        }
    }
}

// =============================================================================
// RequiredOutputSchema
// =============================================================================

/// A required output schema that the role must produce.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequiredOutputSchema {
    /// Schema identifier (e.g., `apm2.review_receipt_recorded.v1`).
    pub schema_id: String,
    /// Whether this output is required (vs optional).
    pub required: bool,
    /// Description of when this output is expected.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

impl RequiredOutputSchema {
    /// Creates a new required output schema.
    #[must_use]
    pub fn new(schema_id: impl Into<String>, required: bool) -> Self {
        Self {
            schema_id: schema_id.into(),
            required,
            description: None,
        }
    }

    /// Sets the description.
    #[must_use]
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }
}

// =============================================================================
// RoleSpecV1
// =============================================================================

/// Role Specification V1.
///
/// Defines an agent role with its tool-call matrix (allowed tools + budgets)
/// under holonic boundary discipline. This spec is stored in CAS and selected
/// by hash; ambient defaults are forbidden.
///
/// # Security Properties
///
/// - **Deny-by-Default**: Only explicitly listed tools are allowed
/// - **Budget Enforcement**: Each role has explicit resource limits
/// - **CAS Binding**: Spec is content-addressed for integrity
/// - **No Ambient Defaults**: Must be explicitly selected by hash
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleSpecV1 {
    /// Schema identifier (always `apm2.role_spec.v1`).
    pub schema: String,

    /// Stable role identifier (e.g., "code_quality_reviewer-v1").
    pub role_id: String,

    /// Human-readable role name.
    pub role_name: String,

    /// Role type classification.
    pub role_type: RoleType,

    /// Description of the role's responsibilities.
    pub description: String,

    /// Tool allowlist with per-tool budgets.
    pub tool_allowlist: ToolAllowlist,

    /// Overall budget limits for this role.
    pub budgets: RoleBudgets,

    /// Required output schemas that conformance harness checks.
    pub required_output_schemas: Vec<RequiredOutputSchema>,

    /// System prompt template for this role.
    /// Uses placeholders like `{work_id}`, `{context}` for injection.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system_prompt_template: Option<String>,

    /// Capabilities required by this role.
    /// Maps capability ID to minimum required level (0 = read, 1 = write, etc.)
    pub required_capabilities: BTreeMap<String, u8>,
}

impl RoleSpecV1 {
    /// Creates a new builder for `RoleSpecV1`.
    #[must_use]
    pub fn builder() -> RoleSpecV1Builder {
        RoleSpecV1Builder::default()
    }

    /// Validates the role specification.
    ///
    /// # Errors
    ///
    /// Returns error if validation fails:
    /// - Schema identifier is invalid
    /// - Required fields are empty
    /// - String fields exceed maximum length
    /// - Collection fields exceed maximum count
    /// - Tool allowlist is invalid
    #[allow(clippy::too_many_lines)]
    pub fn validate(&self) -> Result<(), RoleSpecError> {
        // Validate schema
        if self.schema != ROLE_SPEC_V1_SCHEMA {
            return Err(RoleSpecError::InvalidSchema {
                expected: ROLE_SPEC_V1_SCHEMA.to_string(),
                actual: self.schema.clone(),
            });
        }

        // Validate role_id
        if self.role_id.is_empty() {
            return Err(RoleSpecError::MissingField("role_id"));
        }
        if self.role_id.len() > MAX_ROLE_ID_LENGTH {
            return Err(RoleSpecError::StringTooLong {
                field: "role_id",
                len: self.role_id.len(),
                max: MAX_ROLE_ID_LENGTH,
            });
        }

        // Validate role_name
        if self.role_name.is_empty() {
            return Err(RoleSpecError::MissingField("role_name"));
        }
        if self.role_name.len() > MAX_ROLE_NAME_LENGTH {
            return Err(RoleSpecError::StringTooLong {
                field: "role_name",
                len: self.role_name.len(),
                max: MAX_ROLE_NAME_LENGTH,
            });
        }

        // Validate description
        if self.description.len() > MAX_DESCRIPTION_LENGTH {
            return Err(RoleSpecError::StringTooLong {
                field: "description",
                len: self.description.len(),
                max: MAX_DESCRIPTION_LENGTH,
            });
        }

        // Validate tool allowlist
        self.tool_allowlist.validate()?;

        // Validate required output schemas
        if self.required_output_schemas.len() > MAX_REQUIRED_OUTPUT_SCHEMAS {
            return Err(RoleSpecError::CollectionTooLarge {
                field: "required_output_schemas",
                count: self.required_output_schemas.len(),
                max: MAX_REQUIRED_OUTPUT_SCHEMAS,
            });
        }
        for schema in &self.required_output_schemas {
            if schema.schema_id.is_empty() {
                return Err(RoleSpecError::MissingField("schema_id"));
            }
            if schema.schema_id.len() > MAX_OUTPUT_SCHEMA_LENGTH {
                return Err(RoleSpecError::StringTooLong {
                    field: "schema_id",
                    len: schema.schema_id.len(),
                    max: MAX_OUTPUT_SCHEMA_LENGTH,
                });
            }
        }

        // Validate required capabilities
        for cap_id in self.required_capabilities.keys() {
            if cap_id.is_empty() {
                return Err(RoleSpecError::MissingField("capability_id"));
            }
            if cap_id.len() > MAX_CAPABILITY_ID_LENGTH {
                return Err(RoleSpecError::StringTooLong {
                    field: "capability_id",
                    len: cap_id.len(),
                    max: MAX_CAPABILITY_ID_LENGTH,
                });
            }
            if let Some(forbidden_class) = forbidden_direct_github_capability_class(cap_id) {
                return Err(RoleSpecError::ForbiddenCapabilityClass(format!(
                    "{cap_id} (class: {forbidden_class})"
                )));
            }
        }

        Ok(())
    }

    /// Computes the CAS hash of this role spec.
    ///
    /// Uses RFC 8785 canonical JSON serialization via the `Canonicalizable`
    /// trait to ensure deterministic hashing.
    ///
    /// # Errors
    ///
    /// Returns error if canonicalization fails.
    pub fn compute_cas_hash(&self) -> Result<[u8; 32], RoleSpecError> {
        self.canonical_bytes()
            .map(|bytes| *blake3::hash(&bytes).as_bytes())
            .map_err(|e| RoleSpecError::SerializationError(format!("canonicalization failed: {e}")))
    }

    /// Stores this role spec in CAS and returns its hash.
    ///
    /// # Errors
    ///
    /// Returns error if validation fails or CAS storage fails.
    pub fn store_in_cas(&self, cas: &dyn ContentAddressedStore) -> Result<[u8; 32], RoleSpecError> {
        // Validate before storing
        self.validate()?;

        // Canonicalize
        let bytes = self.canonical_bytes().map_err(|e| {
            RoleSpecError::SerializationError(format!("canonicalization failed: {e}"))
        })?;

        // Store in CAS
        let result = cas.store(&bytes)?;

        Ok(result.hash)
    }

    /// Loads a role spec from CAS by hash.
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Content is not found in CAS
    /// - Content cannot be deserialized
    /// - Loaded spec fails validation
    pub fn load_from_cas(
        cas: &dyn ContentAddressedStore,
        hash: &[u8; 32],
    ) -> Result<Self, RoleSpecError> {
        // Retrieve from CAS
        let bytes = cas.retrieve(hash)?;

        // Deserialize
        let spec: Self = serde_json::from_slice(&bytes).map_err(|e| {
            RoleSpecError::SerializationError(format!("deserialization failed: {e}"))
        })?;

        // Validate loaded spec
        spec.validate()?;

        // Verify hash matches
        let computed_hash = spec.compute_cas_hash()?;
        if computed_hash != *hash {
            return Err(RoleSpecError::CasError(format!(
                "hash mismatch: expected {}, got {}",
                hex::encode(hash),
                hex::encode(computed_hash)
            )));
        }

        Ok(spec)
    }

    /// Checks if a tool is allowed for this role.
    #[must_use]
    pub fn is_tool_allowed(&self, tool_class: &str) -> bool {
        self.tool_allowlist.is_allowed(tool_class)
    }

    /// Gets the budget for a specific tool.
    ///
    /// Returns the tool-specific budget if set, otherwise the default budget.
    #[must_use]
    pub fn get_tool_budget(&self, tool_class: &str) -> &ToolBudget {
        self.tool_allowlist
            .get_budget(tool_class)
            .unwrap_or(&self.budgets.default_tool_budget)
    }
}

// =============================================================================
// RoleSpecV1Builder
// =============================================================================

/// Builder for constructing a `RoleSpecV1`.
#[derive(Debug, Default)]
pub struct RoleSpecV1Builder {
    role_id: Option<String>,
    role_name: Option<String>,
    role_type: Option<RoleType>,
    description: Option<String>,
    tool_allowlist: Option<ToolAllowlist>,
    budgets: Option<RoleBudgets>,
    required_output_schemas: Vec<RequiredOutputSchema>,
    system_prompt_template: Option<String>,
    required_capabilities: BTreeMap<String, u8>,
}

#[allow(clippy::missing_const_for_fn)]
impl RoleSpecV1Builder {
    /// Sets the role ID.
    #[must_use]
    pub fn role_id(mut self, id: impl Into<String>) -> Self {
        self.role_id = Some(id.into());
        self
    }

    /// Sets the role name.
    #[must_use]
    pub fn role_name(mut self, name: impl Into<String>) -> Self {
        self.role_name = Some(name.into());
        self
    }

    /// Sets the role type.
    #[must_use]
    pub fn role_type(mut self, role_type: RoleType) -> Self {
        self.role_type = Some(role_type);
        self
    }

    /// Sets the description.
    #[must_use]
    pub fn description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    /// Sets the tool allowlist.
    #[must_use]
    pub fn tool_allowlist(mut self, allowlist: ToolAllowlist) -> Self {
        self.tool_allowlist = Some(allowlist);
        self
    }

    /// Sets the budgets.
    #[must_use]
    pub fn budgets(mut self, budgets: RoleBudgets) -> Self {
        self.budgets = Some(budgets);
        self
    }

    /// Adds a required output schema.
    #[must_use]
    pub fn required_output_schema(mut self, schema: RequiredOutputSchema) -> Self {
        self.required_output_schemas.push(schema);
        self
    }

    /// Sets the system prompt template.
    #[must_use]
    pub fn system_prompt_template(mut self, template: impl Into<String>) -> Self {
        self.system_prompt_template = Some(template.into());
        self
    }

    /// Adds a required capability.
    #[must_use]
    pub fn required_capability(mut self, cap_id: impl Into<String>, level: u8) -> Self {
        self.required_capabilities.insert(cap_id.into(), level);
        self
    }

    /// Builds the `RoleSpecV1`.
    ///
    /// # Errors
    ///
    /// Returns error if required fields are missing or validation fails.
    pub fn build(self) -> Result<RoleSpecV1, RoleSpecError> {
        let spec = RoleSpecV1 {
            schema: ROLE_SPEC_V1_SCHEMA.to_string(),
            role_id: self.role_id.ok_or(RoleSpecError::MissingField("role_id"))?,
            role_name: self
                .role_name
                .ok_or(RoleSpecError::MissingField("role_name"))?,
            role_type: self.role_type.unwrap_or(RoleType::Custom),
            description: self.description.unwrap_or_default(),
            tool_allowlist: self.tool_allowlist.unwrap_or_default(),
            budgets: self.budgets.unwrap_or_default(),
            required_output_schemas: self.required_output_schemas,
            system_prompt_template: self.system_prompt_template,
            required_capabilities: self.required_capabilities,
        };

        spec.validate()?;
        Ok(spec)
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::MemoryCas;

    fn create_valid_role_spec() -> RoleSpecV1 {
        let allowlist = ToolAllowlist::empty()
            .with_tool("kernel.fs.read")
            .with_tool("kernel.fs.search")
            .with_tool_and_budget("kernel.shell.exec", ToolBudget::shell_exec());

        RoleSpecV1::builder()
            .role_id("code_quality_reviewer-v1")
            .role_name("Code Quality Reviewer")
            .role_type(RoleType::CodeQualityReviewer)
            .description("Assesses code correctness, style, and maintainability")
            .tool_allowlist(allowlist)
            .budgets(RoleBudgets::reviewer())
            .required_output_schema(RequiredOutputSchema::new(
                "apm2.review_receipt_recorded.v1",
                true,
            ))
            .build()
            .expect("valid role spec")
    }

    #[test]
    fn test_role_spec_builder_valid() {
        let spec = create_valid_role_spec();
        assert_eq!(spec.schema, ROLE_SPEC_V1_SCHEMA);
        assert_eq!(spec.role_id, "code_quality_reviewer-v1");
        assert_eq!(spec.role_type, RoleType::CodeQualityReviewer);
        assert!(spec.validate().is_ok());
    }

    #[test]
    fn test_role_spec_builder_missing_fields() {
        // Missing role_id
        let result = RoleSpecV1::builder().role_name("Test").build();
        assert!(matches!(
            result,
            Err(RoleSpecError::MissingField("role_id"))
        ));

        // Missing role_name
        let result = RoleSpecV1::builder().role_id("test").build();
        assert!(matches!(
            result,
            Err(RoleSpecError::MissingField("role_name"))
        ));
    }

    #[test]
    fn test_role_spec_validation_string_too_long() {
        let long_id = "x".repeat(MAX_ROLE_ID_LENGTH + 1);
        let result = RoleSpecV1::builder()
            .role_id(long_id)
            .role_name("Test")
            .build();
        assert!(matches!(
            result,
            Err(RoleSpecError::StringTooLong {
                field: "role_id",
                ..
            })
        ));
    }

    #[test]
    fn test_role_spec_cas_hash_deterministic() {
        let spec1 = create_valid_role_spec();
        let spec2 = create_valid_role_spec();

        assert_eq!(
            spec1.compute_cas_hash().unwrap(),
            spec2.compute_cas_hash().unwrap()
        );
    }

    #[test]
    fn test_role_spec_cas_hash_differs_on_change() {
        let spec1 = create_valid_role_spec();
        let spec2 = RoleSpecV1::builder()
            .role_id("different-role-v1")
            .role_name("Different Role")
            .role_type(RoleType::SecurityReviewer)
            .description("Different description")
            .tool_allowlist(ToolAllowlist::empty().with_tool("kernel.fs.read"))
            .budgets(RoleBudgets::reviewer())
            .build()
            .expect("valid role spec");

        assert_ne!(
            spec1.compute_cas_hash().unwrap(),
            spec2.compute_cas_hash().unwrap()
        );
    }

    #[test]
    fn test_role_spec_cas_roundtrip() {
        let cas = MemoryCas::new();
        let spec = create_valid_role_spec();

        // Store
        let hash = spec.store_in_cas(&cas).expect("store should succeed");

        // Load
        let loaded = RoleSpecV1::load_from_cas(&cas, &hash).expect("load should succeed");

        assert_eq!(spec, loaded);
    }

    #[test]
    fn test_role_spec_cas_not_found() {
        let cas = MemoryCas::new();
        let fake_hash = [0x42u8; 32];

        let result = RoleSpecV1::load_from_cas(&cas, &fake_hash);
        assert!(matches!(result, Err(RoleSpecError::CasError(_))));
    }

    #[test]
    fn test_role_type_display() {
        assert_eq!(RoleType::Orchestrator.to_string(), "orchestrator");
        assert_eq!(RoleType::Implementer.to_string(), "implementer");
        assert_eq!(
            RoleType::CodeQualityReviewer.to_string(),
            "code_quality_reviewer"
        );
        assert_eq!(RoleType::SecurityReviewer.to_string(), "security_reviewer");
        assert_eq!(RoleType::Custom.to_string(), "custom");
    }

    #[test]
    fn test_role_type_from_str() {
        assert_eq!(
            "orchestrator".parse::<RoleType>().unwrap(),
            RoleType::Orchestrator
        );
        assert_eq!(
            "implementer".parse::<RoleType>().unwrap(),
            RoleType::Implementer
        );
        assert_eq!(
            "code_quality_reviewer".parse::<RoleType>().unwrap(),
            RoleType::CodeQualityReviewer
        );
        assert_eq!(
            "security_reviewer".parse::<RoleType>().unwrap(),
            RoleType::SecurityReviewer
        );
        assert_eq!("custom".parse::<RoleType>().unwrap(), RoleType::Custom);
        assert!("invalid".parse::<RoleType>().is_err());
    }

    #[test]
    fn test_tool_allowlist_validation() {
        // Valid
        let allowlist = ToolAllowlist::empty()
            .with_tool("kernel.fs.read")
            .with_tool("kernel.fs.write");
        assert!(allowlist.validate().is_ok());

        // Empty tool class
        let mut invalid = ToolAllowlist::empty();
        invalid.allowed_tools.insert(String::new());
        assert!(matches!(
            invalid.validate(),
            Err(RoleSpecError::InvalidToolClass(_))
        ));

        // Tool class without kernel prefix
        let mut invalid = ToolAllowlist::empty();
        invalid.allowed_tools.insert("custom.tool".to_string());
        assert!(matches!(
            invalid.validate(),
            Err(RoleSpecError::InvalidToolClass(_))
        ));
    }

    #[test]
    fn test_tool_allowlist_budget_not_in_allowlist() {
        let mut allowlist = ToolAllowlist::empty().with_tool("kernel.fs.read");
        // Add budget for tool not in allowlist
        allowlist
            .tool_budgets
            .insert("kernel.fs.write".to_string(), ToolBudget::default());

        assert!(matches!(
            allowlist.validate(),
            Err(RoleSpecError::ToolBudgetNotInAllowlist { tool }) if tool == "kernel.fs.write"
        ));
    }

    #[test]
    fn test_role_spec_rejects_forbidden_direct_github_capability_classes() {
        for forbidden in FORBIDDEN_DIRECT_GITHUB_CAPABILITY_CLASSES {
            let result = RoleSpecV1::builder()
                .role_id("forbidden-cap-role")
                .role_name("Forbidden Capability Role")
                .tool_allowlist(ToolAllowlist::empty().with_tool("kernel.fs.read"))
                .required_capability(format!("{forbidden}.write"), 1)
                .build();

            assert!(
                matches!(result, Err(RoleSpecError::ForbiddenCapabilityClass(_))),
                "expected forbidden capability class rejection for {forbidden}, got: {result:?}"
            );
        }
    }

    #[test]
    fn test_is_tool_allowed() {
        let spec = create_valid_role_spec();
        assert!(spec.is_tool_allowed("kernel.fs.read"));
        assert!(spec.is_tool_allowed("kernel.fs.search"));
        assert!(spec.is_tool_allowed("kernel.shell.exec"));
        assert!(!spec.is_tool_allowed("kernel.fs.write"));
        assert!(!spec.is_tool_allowed("kernel.net.browse"));
    }

    #[test]
    fn test_get_tool_budget() {
        let spec = create_valid_role_spec();

        // Tool with specific budget
        let shell_budget = spec.get_tool_budget("kernel.shell.exec");
        assert_eq!(shell_budget.max_calls_per_episode, 20);

        // Tool without specific budget (uses default)
        let read_budget = spec.get_tool_budget("kernel.fs.read");
        assert_eq!(
            read_budget.max_calls_per_episode,
            spec.budgets.default_tool_budget.max_calls_per_episode
        );
    }

    #[test]
    fn test_role_budgets_presets() {
        let orchestrator = RoleBudgets::orchestrator();
        assert_eq!(orchestrator.max_total_tool_calls, 50);

        let implementer = RoleBudgets::implementer();
        assert_eq!(implementer.max_total_tool_calls, 200);

        let reviewer = RoleBudgets::reviewer();
        assert_eq!(reviewer.max_total_tool_calls, 100);

        let specialist = RoleBudgets::specialist();
        assert_eq!(specialist.max_total_tool_calls, 50);
        assert_eq!(specialist.max_tokens, 500_000);
    }

    #[test]
    fn test_tool_budget_presets() {
        let read_only = ToolBudget::read_only();
        assert_eq!(read_only.max_calls_per_episode, 50);

        let write = ToolBudget::write();
        assert_eq!(write.max_calls_per_episode, 50);

        let shell = ToolBudget::shell_exec();
        assert_eq!(shell.max_calls_per_episode, 20);
        assert_eq!(shell.timeout_ms_per_call, 300_000);
    }

    #[test]
    fn test_required_output_schema() {
        let schema = RequiredOutputSchema::new("apm2.review_receipt_recorded.v1", true)
            .with_description("Review receipt for successful reviews");

        assert_eq!(schema.schema_id, "apm2.review_receipt_recorded.v1");
        assert!(schema.required);
        assert_eq!(
            schema.description,
            Some("Review receipt for successful reviews".to_string())
        );
    }

    #[test]
    fn test_role_spec_serialization() {
        let spec = create_valid_role_spec();

        // Serialize to JSON
        let json = serde_json::to_string_pretty(&spec).expect("serialize should succeed");

        // Deserialize back
        let deserialized: RoleSpecV1 =
            serde_json::from_str(&json).expect("deserialize should succeed");

        assert_eq!(spec, deserialized);
    }

    #[test]
    fn test_deny_unknown_fields() {
        let json = r#"{
            "schema": "apm2.role_spec.v1",
            "role_id": "test",
            "role_name": "Test",
            "role_type": "custom",
            "description": "",
            "tool_allowlist": { "allowed_tools": [], "tool_budgets": {} },
            "budgets": {
                "max_total_tool_calls": 100,
                "max_tokens": 1000000,
                "max_wall_clock_ms": 3600000,
                "max_evidence_bytes": 104857600,
                "default_tool_budget": {
                    "max_calls_per_episode": 100,
                    "max_args_bytes_per_episode": 10485760,
                    "max_result_bytes_per_episode": 10485760,
                    "timeout_ms_per_call": 60000
                }
            },
            "required_output_schemas": [],
            "required_capabilities": {},
            "extra_field": "fail"
        }"#;

        let result: Result<RoleSpecV1, _> = serde_json::from_str(json);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("unknown field `extra_field`"));
    }
}
