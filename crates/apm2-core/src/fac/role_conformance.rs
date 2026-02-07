// AGENT-AUTHORED
//! `RoleSpec` conformance harness for validating role specifications.
//!
//! This module implements the conformance harness for `RoleSpecV1` validation
//! as specified in RFC-0019 Addendum (`10_fac_efficiency_and_role_specs.md`).
//!
//! # Conformance Harness Principles
//!
//! Per RFC-0019:
//! - Schema validation of role outputs (receipt kinds, required fields)
//! - Deny-by-default tool allowlists and budgets enforced by `RoleSpec`
//! - Replay tests: run the same `RoleSpec` against toy tasks and verify:
//!   - Deterministic tool-call envelope behavior
//!   - No forbidden tools used
//!   - Terminal receipt produced or structured failure emitted
//!
//! # Validation Types
//!
//! The harness performs three types of validation:
//!
//! 1. **Schema Validation**: Ensures the `RoleSpecV1` structure is valid
//! 2. **Tool Allowlist Consistency**: Verifies tool budgets are consistent
//! 3. **Output Schema Completeness**: Checks required outputs are defined
//!
//! # Example
//!
//! ```rust
//! use apm2_core::fac::{ConformanceResult, RoleConformanceHarness, builtin_roles};
//!
//! let role = builtin_roles::code_quality_reviewer_role();
//! let harness = RoleConformanceHarness::new();
//!
//! let result = harness.validate(&role);
//! assert!(result.is_conformant());
//! ```

use std::collections::BTreeSet;

use thiserror::Error;

use super::role_spec::{ROLE_SPEC_V1_SCHEMA, RoleSpecError, RoleSpecV1};

// =============================================================================
// Error Types
// =============================================================================

/// Errors that can occur during conformance validation.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ConformanceError {
    /// Schema validation failed.
    #[error("schema validation failed: {0}")]
    SchemaValidation(String),

    /// Tool allowlist is inconsistent.
    #[error("tool allowlist inconsistent: {0}")]
    ToolAllowlistInconsistent(String),

    /// Output schema is missing.
    #[error("required output schema missing: {0}")]
    MissingOutputSchema(String),

    /// Role spec validation failed.
    #[error("role spec validation failed: {0}")]
    RoleSpecInvalid(#[from] RoleSpecError),

    /// Tool is forbidden by policy.
    #[error("forbidden tool used: {0}")]
    ForbiddenTool(String),

    /// Budget exceeded.
    #[error("budget exceeded: {resource} ({used} > {limit})")]
    BudgetExceeded {
        /// The resource that exceeded budget.
        resource: String,
        /// Amount used.
        used: u64,
        /// Budget limit.
        limit: u64,
    },

    /// Terminal receipt not produced.
    #[error("terminal receipt not produced: {expected}")]
    NoTerminalReceipt {
        /// The expected receipt type.
        expected: String,
    },
}

// =============================================================================
// ConformanceViolation
// =============================================================================

/// A specific conformance violation found during validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConformanceViolation {
    /// The type of violation.
    pub violation_type: ViolationType,
    /// Human-readable description of the violation.
    pub description: String,
    /// The field or context where the violation occurred.
    pub context: Option<String>,
}

impl ConformanceViolation {
    /// Creates a new conformance violation.
    #[must_use]
    pub fn new(violation_type: ViolationType, description: impl Into<String>) -> Self {
        Self {
            violation_type,
            description: description.into(),
            context: None,
        }
    }

    /// Adds context to the violation.
    #[must_use]
    pub fn with_context(mut self, context: impl Into<String>) -> Self {
        self.context = Some(context.into());
        self
    }
}

impl std::fmt::Display for ConformanceViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{:?}] {}", self.violation_type, self.description)?;
        if let Some(ref ctx) = self.context {
            write!(f, " (context: {ctx})")?;
        }
        Ok(())
    }
}

/// Types of conformance violations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ViolationType {
    /// Schema validation failure.
    SchemaInvalid,
    /// Tool not in allowlist.
    ToolNotAllowed,
    /// Tool budget not defined for allowed tool.
    MissingToolBudget,
    /// Required output schema not defined.
    MissingOutputSchema,
    /// Output schema is invalid.
    InvalidOutputSchema,
    /// Tool budget inconsistent with allowlist.
    ToolBudgetInconsistent,
    /// Required capability not defined.
    MissingCapability,
}

// =============================================================================
// ConformanceResult
// =============================================================================

/// Result of a conformance validation.
#[derive(Debug, Clone, Default)]
pub struct ConformanceResult {
    /// Whether the role spec is conformant.
    conformant: bool,
    /// List of violations found (empty if conformant).
    violations: Vec<ConformanceViolation>,
    /// Warnings (non-blocking issues).
    warnings: Vec<String>,
}

impl ConformanceResult {
    /// Creates a new conformant result.
    #[must_use]
    pub const fn conformant() -> Self {
        Self {
            conformant: true,
            violations: Vec::new(),
            warnings: Vec::new(),
        }
    }

    /// Creates a new non-conformant result with violations.
    #[must_use]
    pub const fn non_conformant(violations: Vec<ConformanceViolation>) -> Self {
        Self {
            conformant: false,
            violations,
            warnings: Vec::new(),
        }
    }

    /// Returns true if the role spec is conformant.
    #[must_use]
    pub const fn is_conformant(&self) -> bool {
        self.conformant
    }

    /// Returns the violations found.
    #[must_use]
    pub fn violations(&self) -> &[ConformanceViolation] {
        &self.violations
    }

    /// Returns the warnings.
    #[must_use]
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    /// Adds a violation.
    pub fn add_violation(&mut self, violation: ConformanceViolation) {
        self.violations.push(violation);
        self.conformant = false;
    }

    /// Adds a warning.
    pub fn add_warning(&mut self, warning: impl Into<String>) {
        self.warnings.push(warning.into());
    }

    /// Merges another result into this one.
    pub fn merge(&mut self, other: Self) {
        if !other.conformant {
            self.conformant = false;
        }
        self.violations.extend(other.violations);
        self.warnings.extend(other.warnings);
    }
}

// =============================================================================
// RoleConformanceHarness
// =============================================================================

/// Conformance harness for validating role specifications.
///
/// This harness performs comprehensive validation of `RoleSpecV1` artifacts
/// to ensure they meet the requirements specified in RFC-0019.
///
/// # Validation Phases
///
/// 1. **Schema Validation**: Basic structural validation
/// 2. **Tool Allowlist Consistency**: Verify all tool budgets are valid
/// 3. **Output Schema Completeness**: Check required outputs are defined
/// 4. **Capability Validation**: Verify required capabilities are reasonable
///
/// # Example
///
/// ```rust
/// use apm2_core::fac::{RoleConformanceHarness, builtin_roles};
///
/// let harness = RoleConformanceHarness::new();
/// let role = builtin_roles::implementer_role();
///
/// let result = harness.validate(&role);
/// if result.is_conformant() {
///     println!("Role spec is valid");
/// } else {
///     for violation in result.violations() {
///         eprintln!("Violation: {}", violation);
///     }
/// }
/// ```
#[derive(Debug, Default)]
pub struct RoleConformanceHarness {
    /// Required tool classes that all roles should have access to (if any).
    required_tools: BTreeSet<String>,
    /// Required output schemas by role type.
    required_output_schemas: BTreeSet<String>,
    /// Forbidden tool classes (for security).
    forbidden_tools: BTreeSet<String>,
}

impl RoleConformanceHarness {
    /// Creates a new conformance harness with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a harness with required tools.
    #[must_use]
    pub fn with_required_tools(mut self, tools: BTreeSet<String>) -> Self {
        self.required_tools = tools;
        self
    }

    /// Creates a harness with required output schemas.
    #[must_use]
    pub fn with_required_output_schemas(mut self, schemas: BTreeSet<String>) -> Self {
        self.required_output_schemas = schemas;
        self
    }

    /// Creates a harness with forbidden tools.
    #[must_use]
    pub fn with_forbidden_tools(mut self, tools: BTreeSet<String>) -> Self {
        self.forbidden_tools = tools;
        self
    }

    /// Validates a role specification against conformance requirements.
    ///
    /// # Returns
    ///
    /// A `ConformanceResult` indicating whether the role spec is conformant
    /// and listing any violations found.
    #[must_use]
    pub fn validate(&self, role_spec: &RoleSpecV1) -> ConformanceResult {
        let mut result = ConformanceResult::conformant();

        // Phase 1: Schema validation
        Self::validate_schema(role_spec, &mut result);

        // Phase 2: Tool allowlist consistency
        self.validate_tool_allowlist(role_spec, &mut result);

        // Phase 3: Output schema completeness
        self.validate_output_schemas(role_spec, &mut result);

        // Phase 4: Capability validation
        Self::validate_capabilities(role_spec, &mut result);

        // Phase 5: Forbidden tools check
        self.validate_forbidden_tools(role_spec, &mut result);

        result
    }

    /// Validates basic schema requirements.
    fn validate_schema(role_spec: &RoleSpecV1, result: &mut ConformanceResult) {
        // Check schema identifier
        if role_spec.schema != ROLE_SPEC_V1_SCHEMA {
            result.add_violation(
                ConformanceViolation::new(
                    ViolationType::SchemaInvalid,
                    format!(
                        "invalid schema: expected '{}', got '{}'",
                        ROLE_SPEC_V1_SCHEMA, role_spec.schema
                    ),
                )
                .with_context("schema"),
            );
        }

        // Run built-in validation
        if let Err(e) = role_spec.validate() {
            result.add_violation(
                ConformanceViolation::new(
                    ViolationType::SchemaInvalid,
                    format!("role spec validation failed: {e}"),
                )
                .with_context("validate()"),
            );
        }
    }

    /// Validates tool allowlist consistency.
    fn validate_tool_allowlist(&self, role_spec: &RoleSpecV1, result: &mut ConformanceResult) {
        let allowlist = &role_spec.tool_allowlist;

        // Check all tool budgets are for allowed tools
        for tool_class in allowlist.tool_budgets.keys() {
            if !allowlist.allowed_tools.contains(tool_class) {
                result.add_violation(
                    ConformanceViolation::new(
                        ViolationType::ToolBudgetInconsistent,
                        format!("tool budget for '{tool_class}' but tool is not in allowlist"),
                    )
                    .with_context("tool_budgets"),
                );
            }
        }

        // Check required tools are in allowlist
        for required_tool in &self.required_tools {
            if !allowlist.allowed_tools.contains(required_tool) {
                result.add_violation(
                    ConformanceViolation::new(
                        ViolationType::ToolNotAllowed,
                        format!("required tool '{required_tool}' not in allowlist"),
                    )
                    .with_context("required_tools"),
                );
            }
        }

        // Warn if allowlist is empty (may be intentional for orchestrator)
        if allowlist.allowed_tools.is_empty() {
            result.add_warning("tool allowlist is empty - role cannot use any tools");
        }
    }

    /// Validates output schema completeness.
    fn validate_output_schemas(&self, role_spec: &RoleSpecV1, result: &mut ConformanceResult) {
        // Check required output schemas are defined
        for required_schema in &self.required_output_schemas {
            let has_schema = role_spec
                .required_output_schemas
                .iter()
                .any(|s| &s.schema_id == required_schema);

            if !has_schema {
                result.add_violation(
                    ConformanceViolation::new(
                        ViolationType::MissingOutputSchema,
                        format!("required output schema '{required_schema}' not defined"),
                    )
                    .with_context("required_output_schemas"),
                );
            }
        }

        // Check output schema IDs are non-empty
        for schema in &role_spec.required_output_schemas {
            if schema.schema_id.is_empty() {
                result.add_violation(
                    ConformanceViolation::new(
                        ViolationType::InvalidOutputSchema,
                        "output schema has empty schema_id",
                    )
                    .with_context("required_output_schemas"),
                );
            }
        }

        // Warn if no required output schemas
        if role_spec.required_output_schemas.is_empty() {
            result.add_warning(
                "no required output schemas defined - conformance cannot verify outputs",
            );
        }

        // Warn if no schema is marked as required
        let has_required = role_spec.required_output_schemas.iter().any(|s| s.required);
        if !role_spec.required_output_schemas.is_empty() && !has_required {
            result.add_warning("no output schema is marked as required");
        }
    }

    /// Validates required capabilities.
    fn validate_capabilities(role_spec: &RoleSpecV1, result: &mut ConformanceResult) {
        // Warn if no required capabilities
        if role_spec.required_capabilities.is_empty() {
            result.add_warning("no required capabilities defined");
        }

        // Check capability IDs are valid
        for cap_id in role_spec.required_capabilities.keys() {
            if cap_id.is_empty() {
                result.add_violation(
                    ConformanceViolation::new(
                        ViolationType::MissingCapability,
                        "capability has empty ID",
                    )
                    .with_context("required_capabilities"),
                );
            }
        }
    }

    /// Validates no forbidden tools are in allowlist.
    fn validate_forbidden_tools(&self, role_spec: &RoleSpecV1, result: &mut ConformanceResult) {
        for forbidden_tool in &self.forbidden_tools {
            if role_spec
                .tool_allowlist
                .allowed_tools
                .contains(forbidden_tool)
            {
                result.add_violation(
                    ConformanceViolation::new(
                        ViolationType::ToolNotAllowed,
                        format!("forbidden tool '{forbidden_tool}' is in allowlist"),
                    )
                    .with_context("forbidden_tools"),
                );
            }
        }
    }

    /// Validates a tool call against the role spec.
    ///
    /// This is used during execution to verify tool calls comply with the role.
    ///
    /// # Arguments
    ///
    /// * `role_spec` - The role specification
    /// * `tool_class` - The tool class being called
    /// * `args_bytes` - Size of arguments in bytes
    ///
    /// # Errors
    ///
    /// Returns `ConformanceError` if the tool call is not allowed.
    pub fn validate_tool_call(
        &self,
        role_spec: &RoleSpecV1,
        tool_class: &str,
        args_bytes: u64,
    ) -> Result<(), ConformanceError> {
        // Check tool is allowed
        if !role_spec.is_tool_allowed(tool_class) {
            return Err(ConformanceError::ForbiddenTool(tool_class.to_string()));
        }

        // Check forbidden tools
        if self.forbidden_tools.contains(tool_class) {
            return Err(ConformanceError::ForbiddenTool(format!(
                "{tool_class} (forbidden by policy)"
            )));
        }

        // Check args size budget
        let budget = role_spec.get_tool_budget(tool_class);
        if args_bytes > budget.max_args_bytes_per_episode {
            return Err(ConformanceError::BudgetExceeded {
                resource: format!("{tool_class}.args_bytes"),
                used: args_bytes,
                limit: budget.max_args_bytes_per_episode,
            });
        }

        Ok(())
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fac::builtin_roles;
    use crate::fac::role_spec::{RoleBudgets, RoleType, ToolAllowlist, ToolBudget};

    #[test]
    fn test_conformance_harness_creation() {
        let harness = RoleConformanceHarness::new();
        assert!(harness.required_tools.is_empty());
        assert!(harness.required_output_schemas.is_empty());
        assert!(harness.forbidden_tools.is_empty());
    }

    #[test]
    fn test_builtin_roles_are_conformant() {
        let harness = RoleConformanceHarness::new();

        for role in builtin_roles::all_builtin_roles() {
            let result = harness.validate(&role);
            assert!(
                result.is_conformant(),
                "Role '{}' should be conformant. Violations: {:?}",
                role.role_id,
                result.violations()
            );
        }
    }

    #[test]
    fn test_invalid_schema_detected() {
        let mut role = builtin_roles::orchestrator_role();
        role.schema = "invalid.schema.v1".to_string();

        let harness = RoleConformanceHarness::new();
        let result = harness.validate(&role);

        assert!(!result.is_conformant());
        assert!(
            result
                .violations()
                .iter()
                .any(|v| v.violation_type == ViolationType::SchemaInvalid)
        );
    }

    #[test]
    fn test_tool_budget_not_in_allowlist_detected() {
        let mut allowlist = ToolAllowlist::empty().with_tool("kernel.fs.read");

        // Add budget for tool not in allowlist
        allowlist
            .tool_budgets
            .insert("kernel.fs.write".to_string(), ToolBudget::default());

        let role = RoleSpecV1::builder()
            .role_id("test-role")
            .role_name("Test Role")
            .role_type(RoleType::Custom)
            .tool_allowlist(allowlist)
            .build();

        // Should fail validation
        assert!(role.is_err());
    }

    #[test]
    fn test_required_tools_validation() {
        let mut required = BTreeSet::new();
        required.insert("kernel.required.tool".to_string());

        let harness = RoleConformanceHarness::new().with_required_tools(required);

        let role = builtin_roles::orchestrator_role();
        let result = harness.validate(&role);

        // Orchestrator doesn't have kernel.required.tool
        assert!(!result.is_conformant());
        assert!(
            result
                .violations()
                .iter()
                .any(|v| v.violation_type == ViolationType::ToolNotAllowed)
        );
    }

    #[test]
    fn test_required_output_schemas_validation() {
        let mut required = BTreeSet::new();
        required.insert("apm2.required.output.v1".to_string());

        let harness = RoleConformanceHarness::new().with_required_output_schemas(required);

        let role = builtin_roles::orchestrator_role();
        let result = harness.validate(&role);

        // Orchestrator doesn't have apm2.required.output.v1
        assert!(!result.is_conformant());
        assert!(
            result
                .violations()
                .iter()
                .any(|v| v.violation_type == ViolationType::MissingOutputSchema)
        );
    }

    #[test]
    fn test_forbidden_tools_validation() {
        let mut forbidden = BTreeSet::new();
        forbidden.insert("kernel.shell.exec".to_string());

        let harness = RoleConformanceHarness::new().with_forbidden_tools(forbidden);

        // Implementer has shell.exec
        let role = builtin_roles::implementer_role();
        let result = harness.validate(&role);

        assert!(!result.is_conformant());
        assert!(
            result
                .violations()
                .iter()
                .any(|v| v.violation_type == ViolationType::ToolNotAllowed)
        );
    }

    #[test]
    fn test_validate_tool_call_allowed() {
        let harness = RoleConformanceHarness::new();
        let role = builtin_roles::implementer_role();

        // Allowed tool with reasonable args
        let result = harness.validate_tool_call(&role, "kernel.fs.read", 1024);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_tool_call_not_allowed() {
        let harness = RoleConformanceHarness::new();
        let role = builtin_roles::code_quality_reviewer_role();

        // Reviewer can't write files
        let result = harness.validate_tool_call(&role, "kernel.fs.write", 1024);
        assert!(matches!(result, Err(ConformanceError::ForbiddenTool(_))));
    }

    #[test]
    fn test_validate_tool_call_budget_exceeded() {
        let harness = RoleConformanceHarness::new();
        let role = builtin_roles::implementer_role();

        // Exceed args budget
        let result = harness.validate_tool_call(&role, "kernel.fs.read", 100 * 1024 * 1024);
        assert!(matches!(
            result,
            Err(ConformanceError::BudgetExceeded { .. })
        ));
    }

    #[test]
    fn test_validate_tool_call_forbidden_by_policy() {
        let mut forbidden = BTreeSet::new();
        forbidden.insert("kernel.fs.read".to_string());

        let harness = RoleConformanceHarness::new().with_forbidden_tools(forbidden);
        let role = builtin_roles::implementer_role();

        // Even though implementer allows fs.read, it's forbidden by policy
        let result = harness.validate_tool_call(&role, "kernel.fs.read", 1024);
        assert!(matches!(result, Err(ConformanceError::ForbiddenTool(_))));
    }

    #[test]
    fn test_conformance_result_merge() {
        let mut result1 = ConformanceResult::conformant();
        result1.add_warning("warning1");

        let mut result2 = ConformanceResult::conformant();
        result2.add_violation(ConformanceViolation::new(
            ViolationType::SchemaInvalid,
            "test violation",
        ));

        result1.merge(result2);

        assert!(!result1.is_conformant());
        assert_eq!(result1.violations().len(), 1);
        assert_eq!(result1.warnings().len(), 1);
    }

    #[test]
    fn test_violation_display() {
        let violation = ConformanceViolation::new(ViolationType::ToolNotAllowed, "test tool")
            .with_context("allowlist");

        let display = violation.to_string();
        assert!(display.contains("ToolNotAllowed"));
        assert!(display.contains("test tool"));
        assert!(display.contains("allowlist"));
    }

    #[test]
    fn test_empty_allowlist_warning() {
        let role = RoleSpecV1::builder()
            .role_id("empty-allowlist-role")
            .role_name("Empty Allowlist Role")
            .role_type(RoleType::Custom)
            .tool_allowlist(ToolAllowlist::empty())
            .budgets(RoleBudgets::default())
            .build()
            .expect("valid role");

        let harness = RoleConformanceHarness::new();
        let result = harness.validate(&role);

        // Should be conformant but with warnings
        assert!(result.is_conformant());
        assert!(!result.warnings().is_empty());
        assert!(
            result
                .warnings()
                .iter()
                .any(|w| w.contains("tool allowlist is empty"))
        );
    }

    #[test]
    fn test_no_output_schemas_warning() {
        let role = RoleSpecV1::builder()
            .role_id("no-output-role")
            .role_name("No Output Role")
            .role_type(RoleType::Custom)
            .tool_allowlist(ToolAllowlist::empty().with_tool("kernel.fs.read"))
            .budgets(RoleBudgets::default())
            .build()
            .expect("valid role");

        let harness = RoleConformanceHarness::new();
        let result = harness.validate(&role);

        // Should be conformant but with warnings
        assert!(result.is_conformant());
        assert!(
            result
                .warnings()
                .iter()
                .any(|w| w.contains("no required output schemas"))
        );
    }
}
