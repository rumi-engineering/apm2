// AGENT-AUTHORED
//! Built-in role specifications for FAC v0 agent roles.
//!
//! This module provides pre-configured `RoleSpecV1` instances for the minimum
//! required roles per RFC-0019:
//!
//! - **Orchestrator**: Allocates work, enforces budgets/stop conditions
//! - **Implementer**: Generates changesets addressing reviewer feedback
//! - **Code Quality Reviewer**: Assesses correctness, style, maintainability
//! - **Security Reviewer**: Detects unsafe patterns, policy violations
//!
//! # Overview
//!
//! Per RFC-0019 Addendum (`10_fac_efficiency_and_role_specs.md`), each role
//! has:
//! - A narrowly scoped `RoleSpecV1` (hash-addressed)
//! - A small tool allowlist
//! - Explicit tool budgets
//!
//! All role specs:
//! - Are stored in CAS and selected by hash
//! - Enforce deny-by-default tool allowlists
//! - Have explicit budget limits per role type
//!
//! # Security Model
//!
//! The kernel enforces role boundaries:
//! - Tool calls are validated against the role's allowlist
//! - Budget consumption is tracked against role limits
//! - Output schemas are validated by the conformance harness
//!
//! # Example
//!
//! ```rust
//! use apm2_core::evidence::MemoryCas;
//! use apm2_core::fac::builtin_roles;
//!
//! // Get the code quality reviewer role spec
//! let role_spec = builtin_roles::code_quality_reviewer_role();
//! assert!(role_spec.validate().is_ok());
//!
//! // Store in CAS for hash-addressed selection
//! let cas = MemoryCas::new();
//! let hash = role_spec.store_in_cas(&cas).expect("store should succeed");
//!
//! // Role specs are selected by hash, not by name
//! println!("Code Quality Reviewer role hash: {}", hex::encode(hash));
//! ```

use std::collections::{BTreeMap, BTreeSet};

use super::role_spec::{
    RequiredOutputSchema, RoleBudgets, RoleSpecV1, RoleType, ToolAllowlist, ToolBudget,
};
pub use super::role_spec_v2::FAC_WORKOBJECT_IMPLEMENTOR_V2_ROLE_ID;
use super::role_spec_v2::{
    DenyCondition, DenyReason, DenyReasonCode, OutputFieldType, OutputSchemaField, OutputSchemaV2,
    ROLE_SPEC_V2_SCHEMA, RoleSpecV2, RoleSpecV2Error, ToolBudgetV2,
};
use crate::evidence::ContentAddressedStore;

// =============================================================================
// Role Spec Constants
// =============================================================================

/// Role ID for orchestrator.
pub const ORCHESTRATOR_ROLE_ID: &str = "orchestrator-v1";

/// Role ID for implementer.
pub const IMPLEMENTER_ROLE_ID: &str = "implementer-v1";

/// Role ID for code quality reviewer.
pub const CODE_QUALITY_REVIEWER_ROLE_ID: &str = "code_quality_reviewer-v1";

/// Role ID for security reviewer.
pub const SECURITY_REVIEWER_ROLE_ID: &str = "security_reviewer-v1";

/// Role ID for test flake fixer.
pub const TEST_FLAKE_FIXER_ROLE_ID: &str = "test_flake_fixer-v1";

/// Role ID for rust compile error fixer.
pub const RUST_COMPILE_ERROR_FIXER_ROLE_ID: &str = "rust_compile_error_fixer-v1";

/// Role ID for dependency updater.
pub const DEPENDENCY_UPDATER_ROLE_ID: &str = "dependency_updater-v1";

// =============================================================================
// Orchestrator Role
// =============================================================================

/// Creates a `RoleSpecV1` for the orchestrator role.
///
/// # Role Responsibilities
///
/// Per RFC-0019 Addendum, the orchestrator:
/// - Allocates work to other roles
/// - Enforces budgets and stop conditions
/// - Drives iteration loops
///
/// # Typical Kernel Operations
///
/// - `kernel.artifact.fetch`: Pull `ChangeSetBundleV1`, prior receipts, context
///   packs
/// - `kernel.evidence.publish`: Store context packs, plans, summaries in CAS
/// - `kernel.event.emit`: Record `WorkTransitioned`, iteration boundaries
/// - `kernel.git.read`: Fetch PR refs and compute diffs
///
/// # Panics
///
/// Panics if the role spec fails validation (should never happen for valid
/// constants).
#[must_use]
pub fn orchestrator_role() -> RoleSpecV1 {
    let tool_allowlist = ToolAllowlist::empty()
        .with_tool_and_budget("kernel.artifact.fetch", ToolBudget::read_only())
        .with_tool_and_budget("kernel.evidence.publish", ToolBudget::write())
        .with_tool_and_budget("kernel.event.emit", ToolBudget::write())
        .with_tool_and_budget("kernel.git.read", ToolBudget::read_only());

    RoleSpecV1::builder()
        .role_id(ORCHESTRATOR_ROLE_ID)
        .role_name("Orchestrator")
        .role_type(RoleType::Orchestrator)
        .description(
            "Allocates work to other roles, enforces budgets and stop conditions, \
             drives iteration loops until PASS/BLOCKED/BUDGET_EXHAUSTED.",
        )
        .tool_allowlist(tool_allowlist)
        .budgets(RoleBudgets::orchestrator())
        .required_output_schema(RequiredOutputSchema::new("apm2.work_transitioned.v1", true))
        .required_output_schema(
            RequiredOutputSchema::new("apm2.context_pack.v1", false)
                .with_description("Context pack for delegated work"),
        )
        .system_prompt_template(
            "You are an orchestrator agent responsible for coordinating work \
             across multiple specialized agents. Your role is to:\n\n\
             1. Analyze the work request and determine the appropriate delegation strategy\n\
             2. Allocate tasks to implementer and reviewer agents\n\
             3. Monitor progress and enforce budgets\n\
             4. Drive iteration loops until completion or failure\n\n\
             Stage-2 (TCK-00419): Default lifecycle path uses projection-request/receipt \
             mode. Direct write side-effects require explicit override.\n\n\
             Work ID: {work_id}\n\
             Context: {context}",
        )
        .required_capability("work.orchestrate", 1)
        .required_capability("evidence.publish", 1)
        .build()
        .expect("orchestrator_role should be valid")
}

// =============================================================================
// Implementer Role
// =============================================================================

/// Creates a `RoleSpecV1` for the implementer role.
///
/// # Role Responsibilities
///
/// Per RFC-0019 Addendum, the implementer:
/// - Generates new `ChangeSetBundleV1` addressing reviewer feedback
/// - Applies changes deterministically in workspace
/// - Runs tests/linters as terminal verifiers
///
/// # Typical Kernel Operations
///
/// - `kernel.fs.list`: Discover relevant code paths
/// - `kernel.fs.search`: Search for patterns in code
/// - `kernel.fs.read`: Read file contents
/// - `kernel.fs.write`: Apply changes
/// - `kernel.fs.edit`: Apply edits to files
/// - `kernel.shell.exec`: Run tests/linters
/// - `kernel.evidence.publish`: Publish new changeset bundle
/// - `kernel.event.emit`: `ChangeSetPublished` + iteration metadata
///
/// # CAS Operations
///
/// Reads:
/// - Context pack (selectors), prior diffs, prior test outputs, reviewer
///   findings
///
/// Writes:
/// - Patch bundle, tool receipts, test outputs, summary receipts
///
/// # Panics
///
/// Panics if the role spec fails validation (should never happen for valid
/// constants).
#[must_use]
pub fn implementer_role() -> RoleSpecV1 {
    let tool_allowlist = ToolAllowlist::empty()
        // File system operations
        .with_tool_and_budget("kernel.fs.list", ToolBudget::read_only())
        .with_tool_and_budget("kernel.fs.search", ToolBudget::read_only())
        .with_tool_and_budget("kernel.fs.read", ToolBudget::read_only())
        .with_tool_and_budget("kernel.fs.write", ToolBudget::write())
        .with_tool_and_budget("kernel.fs.edit", ToolBudget::write())
        // Shell execution for tests/linters
        .with_tool_and_budget("kernel.shell.exec", ToolBudget::shell_exec())
        // Evidence and events
        .with_tool_and_budget("kernel.evidence.publish", ToolBudget::write())
        .with_tool_and_budget("kernel.event.emit", ToolBudget::write())
        // Artifact fetch for context
        .with_tool_and_budget("kernel.artifact.fetch", ToolBudget::read_only());

    RoleSpecV1::builder()
        .role_id(IMPLEMENTER_ROLE_ID)
        .role_name("Implementer")
        .role_type(RoleType::Implementer)
        .description(
            "Generates new ChangeSetBundleV1 addressing reviewer feedback. \
             Applies changes deterministically in workspace and runs tests/linters \
             as terminal verifiers.",
        )
        .tool_allowlist(tool_allowlist)
        .budgets(RoleBudgets::implementer())
        .required_output_schema(RequiredOutputSchema::new(
            "apm2.changeset_published.v1",
            true,
        ))
        .required_output_schema(
            RequiredOutputSchema::new("apm2.tool_execution_receipt.v1", false)
                .with_description("Tool execution receipts for audit"),
        )
        .required_output_schema(
            RequiredOutputSchema::new("apm2.summary_receipt.v1", false)
                .with_description("Summary of implementation work"),
        )
        .system_prompt_template(
            "You are an implementer agent responsible for writing and modifying code \
             to address reviewer feedback and implement new features. Your role is to:\n\n\
             1. Analyze the requirements and reviewer feedback\n\
             2. Read and understand the existing codebase\n\
             3. Make targeted changes to address the requirements\n\
             4. Run tests to verify your changes\n\
             5. Produce a clean changeset for review\n\n\
             Stage-2 (TCK-00419): Default lifecycle path uses projection-request/receipt \
             mode. Direct write side-effects require explicit override.\n\n\
             Work ID: {work_id}\n\
             Context: {context}",
        )
        .required_capability("fs.read", 0)
        .required_capability("fs.write", 1)
        .required_capability("shell.exec", 1)
        .required_capability("evidence.publish", 1)
        .build()
        .expect("implementer_role should be valid")
}

// =============================================================================
// Code Quality Reviewer Role
// =============================================================================

/// Creates a `RoleSpecV1` for the code quality reviewer role.
///
/// # Role Responsibilities
///
/// Per RFC-0019 Addendum, the code quality reviewer:
/// - Assesses correctness, style, maintainability
/// - Runs targeted tests or linters (avoids full CI)
/// - Produces review artifact bundles with findings
///
/// # Typical Kernel Operations
///
/// - `kernel.artifact.fetch`: Retrieve `ChangeSetBundleV1` + tool indices
/// - `kernel.fs.read`: Inspect touched files and surrounding context
/// - `kernel.fs.search`: Search for related code
/// - `kernel.shell.exec`: Run targeted tests or linters
/// - `kernel.evidence.publish`: Review artifact bundle
/// - `kernel.event.emit`: `ReviewReceiptRecorded`
///
/// # Panics
///
/// Panics if the role spec fails validation (should never happen for valid
/// constants).
#[must_use]
pub fn code_quality_reviewer_role() -> RoleSpecV1 {
    let tool_allowlist = ToolAllowlist::empty()
        // Artifact fetch for changeset
        .with_tool_and_budget("kernel.artifact.fetch", ToolBudget::read_only())
        // File reading for code inspection
        .with_tool_and_budget("kernel.fs.read", ToolBudget::read_only())
        .with_tool_and_budget("kernel.fs.search", ToolBudget::read_only())
        .with_tool_and_budget("kernel.fs.list", ToolBudget::read_only())
        // Shell execution for targeted tests (limited)
        .with_tool_and_budget(
            "kernel.shell.exec",
            ToolBudget {
                max_calls_per_episode: 10,
                max_args_bytes_per_episode: 512 * 1024,      // 512 KB
                max_result_bytes_per_episode: 2 * 1024 * 1024, // 2 MB
                timeout_ms_per_call: 180_000,                 // 3 minutes
            },
        )
        // Evidence and events
        .with_tool_and_budget("kernel.evidence.publish", ToolBudget::write())
        .with_tool_and_budget("kernel.event.emit", ToolBudget::write());

    RoleSpecV1::builder()
        .role_id(CODE_QUALITY_REVIEWER_ROLE_ID)
        .role_name("Code Quality Reviewer")
        .role_type(RoleType::CodeQualityReviewer)
        .description(
            "Assesses code correctness, style, and maintainability. \
             Runs targeted tests or linters and produces structured review findings.",
        )
        .tool_allowlist(tool_allowlist)
        .budgets(RoleBudgets::reviewer())
        .required_output_schema(RequiredOutputSchema::new(
            "apm2.review_receipt_recorded.v1",
            true,
        ))
        .required_output_schema(
            RequiredOutputSchema::new("apm2.review_artifact_bundle.v1", true)
                .with_description("Review artifacts stored in CAS"),
        )
        .system_prompt_template(
            "You are a code quality reviewer responsible for assessing code changes \
             for correctness, style, and maintainability. Your role is to:\n\n\
             1. Review the changeset for logical correctness\n\
             2. Check code style and consistency\n\
             3. Assess maintainability and readability\n\
             4. Run targeted tests to verify behavior\n\
             5. Provide specific, actionable feedback\n\
             6. Prefer `apm2 fac review` commands for lifecycle/status/retrigger \
                operations when needed\n\
             7. Use direct `gh` commands only for PR comment-body interactions \
                that FAC does not yet expose\n\n\
             Produce a structured review with:\n\
             - APPROVE if the code meets quality standards\n\
             - REQUEST_CHANGES if improvements are needed\n\
             - COMMENT for observations without blocking\n\n\
             Work ID: {work_id}\n\
             Context: {context}",
        )
        .required_capability("fs.read", 0)
        .required_capability("shell.exec", 1)
        .required_capability("evidence.publish", 1)
        .build()
        .expect("code_quality_reviewer_role should be valid")
}

// =============================================================================
// Security Reviewer Role
// =============================================================================

/// Creates a `RoleSpecV1` for the security reviewer role.
///
/// # Role Responsibilities
///
/// Per RFC-0019 Addendum, the security reviewer:
/// - Detects unsafe patterns, dangerous APIs, policy violations
/// - Focuses on security-sensitive code paths
/// - Produces structured security findings
///
/// # Typical Kernel Operations
///
/// - `kernel.artifact.fetch`: Retrieve `ChangeSetBundleV1`
/// - `kernel.fs.read`: Focus on security-sensitive code paths
/// - `kernel.fs.search`: Search for security patterns
/// - `kernel.shell.exec`: Run security checks (where available)
/// - `kernel.evidence.publish`: Review artifact bundle with security findings
/// - `kernel.event.emit`: `ReviewReceiptRecorded`
///
/// # Panics
///
/// Panics if the role spec fails validation (should never happen for valid
/// constants).
#[must_use]
pub fn security_reviewer_role() -> RoleSpecV1 {
    let tool_allowlist = ToolAllowlist::empty()
        // Artifact fetch for changeset
        .with_tool_and_budget("kernel.artifact.fetch", ToolBudget::read_only())
        // File reading for security inspection
        .with_tool_and_budget("kernel.fs.read", ToolBudget::read_only())
        .with_tool_and_budget("kernel.fs.search", ToolBudget::read_only())
        .with_tool_and_budget("kernel.fs.list", ToolBudget::read_only())
        // Shell execution for security checks (limited)
        .with_tool_and_budget(
            "kernel.shell.exec",
            ToolBudget {
                max_calls_per_episode: 10,
                max_args_bytes_per_episode: 512 * 1024,      // 512 KB
                max_result_bytes_per_episode: 2 * 1024 * 1024, // 2 MB
                timeout_ms_per_call: 180_000,                 // 3 minutes
            },
        )
        // Evidence and events
        .with_tool_and_budget("kernel.evidence.publish", ToolBudget::write())
        .with_tool_and_budget("kernel.event.emit", ToolBudget::write());

    RoleSpecV1::builder()
        .role_id(SECURITY_REVIEWER_ROLE_ID)
        .role_name("Security Reviewer")
        .role_type(RoleType::SecurityReviewer)
        .description(
            "Detects unsafe patterns, dangerous APIs, and policy violations. \
             Focuses on security-sensitive code paths and produces structured \
             security findings.",
        )
        .tool_allowlist(tool_allowlist)
        .budgets(RoleBudgets::reviewer())
        .required_output_schema(RequiredOutputSchema::new(
            "apm2.review_receipt_recorded.v1",
            true,
        ))
        .required_output_schema(
            RequiredOutputSchema::new("apm2.review_artifact_bundle.v1", true)
                .with_description("Review artifacts with security findings"),
        )
        .system_prompt_template(
            "You are a security reviewer responsible for detecting security issues \
             in code changes. Your role is to:\n\n\
             1. Identify unsafe patterns and dangerous API usage\n\
             2. Check for common vulnerabilities (injection, auth bypass, etc.)\n\
             3. Verify secrets/credentials are not exposed\n\
             4. Assess policy compliance\n\
             5. Run security scanning tools where available\n\
             6. Prefer `apm2 fac review` commands for lifecycle/status/retrigger \
                operations when needed\n\
             7. Use direct `gh` commands only for PR comment-body interactions \
                that FAC does not yet expose\n\n\
             Produce a structured security review with:\n\
             - APPROVE if no security issues found\n\
             - REQUEST_CHANGES if security issues must be addressed\n\
             - COMMENT for observations or minor suggestions\n\n\
             Work ID: {work_id}\n\
             Context: {context}",
        )
        .required_capability("fs.read", 0)
        .required_capability("shell.exec", 1)
        .required_capability("evidence.publish", 1)
        .build()
        .expect("security_reviewer_role should be valid")
}

// =============================================================================
// Specialist Roles
// =============================================================================

/// Creates a `RoleSpecV1` for the test flake fixer role.
///
/// # Role Responsibilities
///
/// - Diagnoses and fixes test flakes (non-deterministic failures)
/// - Runs tests in isolation or loop to reproduce
/// - Applies fixes to test code or logic
///
/// # Typical Kernel Operations
///
/// - `kernel.fs.read`: Read test files
/// - `kernel.fs.edit`: Modify test logic
/// - `kernel.shell.exec`: Run `cargo test`
/// - `kernel.evidence.publish`: Publish fix
///
/// # Panics
///
/// Panics if the role spec fails to build due to invalid configuration.
/// This should never happen with the hardcoded values.
#[must_use]
pub fn test_flake_fixer_role() -> RoleSpecV1 {
    let tool_allowlist = ToolAllowlist::empty()
        .with_tool_and_budget("kernel.artifact.fetch", ToolBudget::read_only())
        .with_tool_and_budget("kernel.fs.list", ToolBudget::read_only())
        .with_tool_and_budget("kernel.fs.search", ToolBudget::read_only())
        .with_tool_and_budget("kernel.fs.read", ToolBudget::read_only())
        .with_tool_and_budget("kernel.fs.edit", ToolBudget::write())
        .with_tool_and_budget("kernel.fs.write", ToolBudget::write())
        .with_tool_and_budget("kernel.shell.exec", ToolBudget::shell_exec())
        .with_tool_and_budget("kernel.evidence.publish", ToolBudget::write())
        .with_tool_and_budget("kernel.event.emit", ToolBudget::write());

    RoleSpecV1::builder()
        .role_id(TEST_FLAKE_FIXER_ROLE_ID)
        .role_name("Test Flake Fixer")
        .role_type(RoleType::TestFlakeFixer)
        .description(
            "Specialist role for diagnosing and fixing non-deterministic test \
             failures (flakes).",
        )
        .tool_allowlist(tool_allowlist)
        .budgets(RoleBudgets::specialist())
        .required_output_schema(RequiredOutputSchema::new(
            "apm2.changeset_published.v1",
            true,
        ))
        .required_output_schema(
            RequiredOutputSchema::new("apm2.tool_execution_receipt.v1", false)
                .with_description("Tool execution receipts for audit"),
        )
        .required_output_schema(
            RequiredOutputSchema::new("apm2.summary_receipt.v1", false)
                .with_description("Summary of implementation work"),
        )
        .system_prompt_template(
            "You are a test flake fixer specialist. Your goal is to fix flaky tests.\n\n\
             1. Analyze the test failure log\n\
             2. Reproduce the flake (if possible)\n\
             3. Modify the test or code to fix the race/indeterminism\n\
             4. Verify the fix\n\n\
             Work ID: {work_id}\n\
             Context: {context}",
        )
        .required_capability("fs.write", 1)
        .required_capability("shell.exec", 1)
        .build()
        .expect("test_flake_fixer_role should be valid")
}

/// Creates a `RoleSpecV1` for the Rust compile error fixer role.
///
/// # Role Responsibilities
///
/// - Fixes Rust compilation errors
/// - Interprets `cargo check` output
/// - Applies syntax/type fixes
///
/// # Panics
///
/// Panics if the role spec fails to build due to invalid configuration.
/// This should never happen with the hardcoded values.
#[must_use]
pub fn rust_compile_error_fixer_role() -> RoleSpecV1 {
    let tool_allowlist = ToolAllowlist::empty()
        .with_tool_and_budget("kernel.artifact.fetch", ToolBudget::read_only())
        .with_tool_and_budget("kernel.fs.list", ToolBudget::read_only())
        .with_tool_and_budget("kernel.fs.search", ToolBudget::read_only())
        .with_tool_and_budget("kernel.fs.read", ToolBudget::read_only())
        .with_tool_and_budget("kernel.fs.edit", ToolBudget::write())
        .with_tool_and_budget("kernel.fs.write", ToolBudget::write())
        .with_tool_and_budget("kernel.shell.exec", ToolBudget::shell_exec())
        .with_tool_and_budget("kernel.evidence.publish", ToolBudget::write())
        .with_tool_and_budget("kernel.event.emit", ToolBudget::write());

    RoleSpecV1::builder()
        .role_id(RUST_COMPILE_ERROR_FIXER_ROLE_ID)
        .role_name("Rust Compile Error Fixer")
        .role_type(RoleType::RustCompileErrorFixer)
        .description("Specialist role for fixing Rust compilation errors.")
        .tool_allowlist(tool_allowlist)
        .budgets(RoleBudgets::specialist())
        .required_output_schema(RequiredOutputSchema::new(
            "apm2.changeset_published.v1",
            true,
        ))
        .required_output_schema(
            RequiredOutputSchema::new("apm2.tool_execution_receipt.v1", false)
                .with_description("Tool execution receipts for audit"),
        )
        .required_output_schema(
            RequiredOutputSchema::new("apm2.summary_receipt.v1", false)
                .with_description("Summary of implementation work"),
        )
        .system_prompt_template(
            "You are a Rust compile error fixer specialist. Your goal is to make the code compile.\n\n\
             1. Analyze the cargo check output\n\
             2. Apply fixes to the code\n\
             3. Verify compilation\n\n\
             Work ID: {work_id}\n\
             Context: {context}",
        )
        .required_capability("fs.write", 1)
        .required_capability("shell.exec", 1)
        .build()
        .expect("rust_compile_error_fixer_role should be valid")
}

/// Creates a `RoleSpecV1` for the dependency updater role.
///
/// # Role Responsibilities
///
/// - Updates dependencies in `Cargo.toml`
/// - Resolves version conflicts
///
/// # Panics
///
/// Panics if the role spec fails to build due to invalid configuration.
/// This should never happen with the hardcoded values.
#[must_use]
pub fn dependency_updater_role() -> RoleSpecV1 {
    let tool_allowlist = ToolAllowlist::empty()
        .with_tool_and_budget("kernel.artifact.fetch", ToolBudget::read_only())
        .with_tool_and_budget("kernel.fs.list", ToolBudget::read_only())
        .with_tool_and_budget("kernel.fs.search", ToolBudget::read_only())
        .with_tool_and_budget("kernel.fs.read", ToolBudget::read_only())
        .with_tool_and_budget("kernel.fs.write", ToolBudget::write())
        .with_tool_and_budget("kernel.fs.edit", ToolBudget::write())
        .with_tool_and_budget("kernel.shell.exec", ToolBudget::shell_exec())
        .with_tool_and_budget("kernel.evidence.publish", ToolBudget::write())
        .with_tool_and_budget("kernel.event.emit", ToolBudget::write());

    RoleSpecV1::builder()
        .role_id(DEPENDENCY_UPDATER_ROLE_ID)
        .role_name("Dependency Updater")
        .role_type(RoleType::DependencyUpdater)
        .description("Specialist role for updating project dependencies.")
        .tool_allowlist(tool_allowlist)
        .budgets(RoleBudgets::specialist())
        .required_output_schema(RequiredOutputSchema::new(
            "apm2.changeset_published.v1",
            true,
        ))
        .required_output_schema(
            RequiredOutputSchema::new("apm2.tool_execution_receipt.v1", false)
                .with_description("Tool execution receipts for audit"),
        )
        .required_output_schema(
            RequiredOutputSchema::new("apm2.summary_receipt.v1", false)
                .with_description("Summary of implementation work"),
        )
        .system_prompt_template(
            "You are a dependency updater specialist. Your goal is to update dependencies safely.\n\n\
             1. Check for outdated dependencies\n\
             2. Update Cargo.toml/Cargo.lock\n\
             3. Verify build passes\n\n\
             Work ID: {work_id}\n\
             Context: {context}",
        )
        .required_capability("fs.write", 1)
        .required_capability("shell.exec", 1)
        .build()
        .expect("dependency_updater_role should be valid")
}

// =============================================================================
// RoleSpec v2 WorkObject Implementor Contract
// =============================================================================

fn workobject_implementor_tool_allowlists() -> BTreeSet<String> {
    let mut tool_allowlists = BTreeSet::new();
    tool_allowlists.insert("kernel.artifact.fetch".to_string());
    tool_allowlists.insert("kernel.fs.list".to_string());
    tool_allowlists.insert("kernel.fs.search".to_string());
    tool_allowlists.insert("kernel.fs.read".to_string());
    tool_allowlists.insert("kernel.fs.write".to_string());
    tool_allowlists.insert("kernel.fs.edit".to_string());
    tool_allowlists.insert("kernel.shell.exec".to_string());
    tool_allowlists.insert("kernel.evidence.publish".to_string());
    tool_allowlists.insert("kernel.event.emit".to_string());
    tool_allowlists
}

fn workobject_implementor_tool_budgets() -> BTreeMap<String, ToolBudgetV2> {
    let mut tool_budgets = BTreeMap::new();
    tool_budgets.insert(
        "kernel.artifact.fetch".to_string(),
        ToolBudgetV2::new(64, 180_000),
    );
    tool_budgets.insert(
        "kernel.fs.list".to_string(),
        ToolBudgetV2::new(120, 120_000),
    );
    tool_budgets.insert(
        "kernel.fs.search".to_string(),
        ToolBudgetV2::new(120, 220_000),
    );
    tool_budgets.insert(
        "kernel.fs.read".to_string(),
        ToolBudgetV2::new(160, 300_000),
    );
    tool_budgets.insert(
        "kernel.fs.write".to_string(),
        ToolBudgetV2::new(64, 180_000),
    );
    tool_budgets.insert("kernel.fs.edit".to_string(), ToolBudgetV2::new(80, 220_000));
    tool_budgets.insert(
        "kernel.shell.exec".to_string(),
        ToolBudgetV2::new(32, 480_000),
    );
    tool_budgets.insert(
        "kernel.evidence.publish".to_string(),
        ToolBudgetV2::new(48, 120_000),
    );
    tool_budgets.insert(
        "kernel.event.emit".to_string(),
        ToolBudgetV2::new(64, 80_000),
    );
    tool_budgets
}

fn workobject_implementor_output_schema() -> OutputSchemaV2 {
    OutputSchemaV2::new("apm2.fac_workobject_implementor_output.v2")
        .with_field(
            "status",
            OutputSchemaField::required(OutputFieldType::String),
        )
        .with_field(
            "work_id",
            OutputSchemaField::required(OutputFieldType::String),
        )
        .with_field(
            "role_spec_hash",
            OutputSchemaField::required(OutputFieldType::String),
        )
        .with_field(
            "changeset_bundle_hash",
            OutputSchemaField::required(OutputFieldType::String),
        )
        .with_field(
            "evidence_refs",
            OutputSchemaField::optional(OutputFieldType::Array),
        )
        .with_field(
            "summary",
            OutputSchemaField::optional(OutputFieldType::String),
        )
}

fn workobject_implementor_deny_taxonomy() -> BTreeMap<DenyCondition, DenyReason> {
    let mut deny_taxonomy = BTreeMap::new();
    deny_taxonomy.insert(
        DenyCondition::MissingAuthorityContext,
        DenyReason::new(
            DenyReasonCode::MissingAuthority,
            "authority context missing for WorkObject execution",
        ),
    );
    deny_taxonomy.insert(
        DenyCondition::StaleAuthorityContext,
        DenyReason::new(
            DenyReasonCode::StaleAuthority,
            "authority context stale relative to active gate window",
        ),
    );
    deny_taxonomy.insert(
        DenyCondition::UnknownRoleProfile,
        DenyReason::new(
            DenyReasonCode::UnknownRole,
            "role profile hash does not resolve to registered RoleSpec contract",
        ),
    );
    deny_taxonomy.insert(
        DenyCondition::UnverifiableContextHash,
        DenyReason::new(
            DenyReasonCode::UnverifiableContext,
            "context hash cannot be verified against authoritative source",
        ),
    );
    deny_taxonomy
}

fn workobject_implementor_required_capabilities() -> BTreeMap<String, u8> {
    let mut required_capabilities = BTreeMap::new();
    required_capabilities.insert("artifact.fetch".to_string(), 0);
    required_capabilities.insert("fs.read".to_string(), 0);
    required_capabilities.insert("fs.write".to_string(), 1);
    required_capabilities.insert("shell.exec".to_string(), 1);
    required_capabilities.insert("evidence.publish".to_string(), 1);
    required_capabilities
}

/// Creates the `fac_workobject_implementor_v2` `RoleSpec` contract artifact.
///
/// This contract is the v2 foundation for `WorkObject` implementor execution
/// and encodes explicit tool budgets, allowlists, output schema fields, and
/// deny taxonomy bindings.
///
/// # Panics
///
/// Panics if internal contract constants are malformed and fail validation.
#[must_use]
pub fn fac_workobject_implementor_v2_role_contract() -> RoleSpecV2 {
    let contract = RoleSpecV2 {
        schema: ROLE_SPEC_V2_SCHEMA.to_string(),
        role_id: FAC_WORKOBJECT_IMPLEMENTOR_V2_ROLE_ID.to_string(),
        role_name: "FAC WorkObject Implementor".to_string(),
        role_type: RoleType::Implementer,
        description: "WorkObject-focused implementor contract with explicit deny taxonomy and per-tool budgets.".to_string(),
        tool_allowlists: workobject_implementor_tool_allowlists(),
        tool_budgets: workobject_implementor_tool_budgets(),
        output_schema: workobject_implementor_output_schema(),
        deny_taxonomy: workobject_implementor_deny_taxonomy(),
        required_capabilities: workobject_implementor_required_capabilities(),
    };
    contract
        .validate()
        .expect("fac_workobject_implementor_v2 contract should be valid");
    contract
}

/// Returns all built-in `RoleSpec` v2 contracts.
#[must_use]
pub fn all_builtin_role_contracts_v2() -> Vec<RoleSpecV2> {
    vec![fac_workobject_implementor_v2_role_contract()]
}

/// Looks up a built-in `RoleSpec` v2 contract by role id.
#[must_use]
pub fn get_builtin_role_contract_v2(role_id: &str) -> Option<RoleSpecV2> {
    match role_id {
        FAC_WORKOBJECT_IMPLEMENTOR_V2_ROLE_ID => {
            Some(fac_workobject_implementor_v2_role_contract())
        },
        _ => None,
    }
}

/// Computes deterministic hash registry for built-in `RoleSpec` v2 contracts.
///
/// The map key is `role_id` and value is canonical CAS hash.
///
/// # Errors
///
/// Returns [`RoleSpecV2Error`] if canonicalization or hash computation fails.
pub fn builtin_role_contract_hash_registry_v2()
-> Result<BTreeMap<String, [u8; 32]>, RoleSpecV2Error> {
    let mut registry = BTreeMap::new();
    for contract in all_builtin_role_contracts_v2() {
        let hash = contract.compute_cas_hash()?;
        registry.insert(contract.role_id.clone(), hash);
    }
    Ok(registry)
}

/// Stores built-in `RoleSpec` v2 contracts in CAS and returns role->hash map.
///
/// # Errors
///
/// Returns [`RoleSpecV2Error`] if contract validation, canonicalization, or CAS
/// persistence fails.
pub fn seed_builtin_role_contracts_v2_in_cas(
    cas: &dyn ContentAddressedStore,
) -> Result<BTreeMap<String, [u8; 32]>, RoleSpecV2Error> {
    let mut registry = BTreeMap::new();
    for contract in all_builtin_role_contracts_v2() {
        let hash = contract.store_in_cas(cas)?;
        registry.insert(contract.role_id.clone(), hash);
    }
    Ok(registry)
}

// =============================================================================
// Registry Functions
// =============================================================================

/// Returns all built-in role specs.
///
/// # Returns
///
/// A vector containing all pre-configured role specifications.
#[must_use]
pub fn all_builtin_roles() -> Vec<RoleSpecV1> {
    vec![
        orchestrator_role(),
        implementer_role(),
        code_quality_reviewer_role(),
        security_reviewer_role(),
        test_flake_fixer_role(),
        rust_compile_error_fixer_role(),
        dependency_updater_role(),
    ]
}

/// Looks up a built-in role spec by its role ID.
///
/// # Arguments
///
/// * `role_id` - The role identifier (e.g., "code_quality_reviewer-v1")
///
/// # Returns
///
/// The matching role spec if found, `None` otherwise.
#[must_use]
pub fn get_builtin_role(role_id: &str) -> Option<RoleSpecV1> {
    match role_id {
        ORCHESTRATOR_ROLE_ID => Some(orchestrator_role()),
        IMPLEMENTER_ROLE_ID => Some(implementer_role()),
        CODE_QUALITY_REVIEWER_ROLE_ID => Some(code_quality_reviewer_role()),
        SECURITY_REVIEWER_ROLE_ID => Some(security_reviewer_role()),
        TEST_FLAKE_FIXER_ROLE_ID => Some(test_flake_fixer_role()),
        RUST_COMPILE_ERROR_FIXER_ROLE_ID => Some(rust_compile_error_fixer_role()),
        DEPENDENCY_UPDATER_ROLE_ID => Some(dependency_updater_role()),
        _ => None,
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::MemoryCas;
    use crate::fac::{
        FORBIDDEN_DIRECT_GITHUB_CAPABILITY_CLASSES, ROLE_SPEC_V1_SCHEMA,
        forbidden_direct_github_capability_class,
    };

    #[test]
    fn test_orchestrator_role_valid() {
        let role = orchestrator_role();
        assert!(role.validate().is_ok());
        assert_eq!(role.role_id, ORCHESTRATOR_ROLE_ID);
        assert_eq!(role.role_type, RoleType::Orchestrator);
    }

    #[test]
    fn test_orchestrator_role_tool_allowlist() {
        let role = orchestrator_role();
        assert!(role.is_tool_allowed("kernel.artifact.fetch"));
        assert!(role.is_tool_allowed("kernel.evidence.publish"));
        assert!(role.is_tool_allowed("kernel.event.emit"));
        assert!(role.is_tool_allowed("kernel.git.read"));
        // Should not have write access
        assert!(!role.is_tool_allowed("kernel.fs.write"));
        assert!(!role.is_tool_allowed("kernel.shell.exec"));
    }

    #[test]
    fn test_orchestrator_role_cas_roundtrip() {
        let cas = MemoryCas::new();
        let role = orchestrator_role();

        let hash = role.store_in_cas(&cas).expect("store should succeed");
        let loaded = RoleSpecV1::load_from_cas(&cas, &hash).expect("load should succeed");

        assert_eq!(role, loaded);
    }

    #[test]
    fn test_implementer_role_valid() {
        let role = implementer_role();
        assert!(role.validate().is_ok());
        assert_eq!(role.role_id, IMPLEMENTER_ROLE_ID);
        assert_eq!(role.role_type, RoleType::Implementer);
    }

    #[test]
    fn test_implementer_role_tool_allowlist() {
        let role = implementer_role();
        // Read operations
        assert!(role.is_tool_allowed("kernel.fs.list"));
        assert!(role.is_tool_allowed("kernel.fs.search"));
        assert!(role.is_tool_allowed("kernel.fs.read"));
        // Write operations
        assert!(role.is_tool_allowed("kernel.fs.write"));
        assert!(role.is_tool_allowed("kernel.fs.edit"));
        // Shell execution
        assert!(role.is_tool_allowed("kernel.shell.exec"));
    }

    #[test]
    fn test_implementer_role_has_higher_budgets() {
        let implementer = implementer_role();
        let reviewer = code_quality_reviewer_role();

        assert!(
            implementer.budgets.max_total_tool_calls > reviewer.budgets.max_total_tool_calls,
            "Implementer should have higher tool call budget"
        );
        assert!(
            implementer.budgets.max_tokens > reviewer.budgets.max_tokens,
            "Implementer should have higher token budget"
        );
    }

    #[test]
    fn test_specialist_roles_have_narrower_budgets_than_implementer() {
        let implementer = implementer_role();
        let specialists = [
            test_flake_fixer_role(),
            rust_compile_error_fixer_role(),
            dependency_updater_role(),
        ];

        for specialist in specialists {
            assert!(
                specialist.budgets.max_total_tool_calls < implementer.budgets.max_total_tool_calls,
                "{} should have fewer tool calls than implementer",
                specialist.role_id
            );
            assert!(
                specialist.budgets.max_tokens < implementer.budgets.max_tokens,
                "{} should have lower token budget than implementer",
                specialist.role_id
            );
        }
    }

    #[test]
    fn test_implementer_role_cas_roundtrip() {
        let cas = MemoryCas::new();
        let role = implementer_role();

        let hash = role.store_in_cas(&cas).expect("store should succeed");
        let loaded = RoleSpecV1::load_from_cas(&cas, &hash).expect("load should succeed");

        assert_eq!(role, loaded);
    }

    #[test]
    fn test_code_quality_reviewer_role_valid() {
        let role = code_quality_reviewer_role();
        assert!(role.validate().is_ok());
        assert_eq!(role.role_id, CODE_QUALITY_REVIEWER_ROLE_ID);
        assert_eq!(role.role_type, RoleType::CodeQualityReviewer);
    }

    #[test]
    fn test_code_quality_reviewer_tool_allowlist() {
        let role = code_quality_reviewer_role();
        // Read operations
        assert!(role.is_tool_allowed("kernel.artifact.fetch"));
        assert!(role.is_tool_allowed("kernel.fs.read"));
        assert!(role.is_tool_allowed("kernel.fs.search"));
        // Limited shell execution
        assert!(role.is_tool_allowed("kernel.shell.exec"));
        // Should NOT have write access
        assert!(!role.is_tool_allowed("kernel.fs.write"));
        assert!(!role.is_tool_allowed("kernel.fs.edit"));
    }

    #[test]
    fn test_code_quality_reviewer_limited_shell_budget() {
        let role = code_quality_reviewer_role();
        let shell_budget = role.get_tool_budget("kernel.shell.exec");

        // Reviewers should have limited shell execution
        assert_eq!(shell_budget.max_calls_per_episode, 10);
    }

    #[test]
    fn test_code_quality_reviewer_cas_roundtrip() {
        let cas = MemoryCas::new();
        let role = code_quality_reviewer_role();

        let hash = role.store_in_cas(&cas).expect("store should succeed");
        let loaded = RoleSpecV1::load_from_cas(&cas, &hash).expect("load should succeed");

        assert_eq!(role, loaded);
    }

    #[test]
    fn test_security_reviewer_role_valid() {
        let role = security_reviewer_role();
        assert!(role.validate().is_ok());
        assert_eq!(role.role_id, SECURITY_REVIEWER_ROLE_ID);
        assert_eq!(role.role_type, RoleType::SecurityReviewer);
    }

    #[test]
    fn test_security_reviewer_tool_allowlist() {
        let role = security_reviewer_role();
        // Similar to code quality but focused on security
        assert!(role.is_tool_allowed("kernel.artifact.fetch"));
        assert!(role.is_tool_allowed("kernel.fs.read"));
        assert!(role.is_tool_allowed("kernel.fs.search"));
        assert!(role.is_tool_allowed("kernel.shell.exec"));
        // Should NOT have write access
        assert!(!role.is_tool_allowed("kernel.fs.write"));
        assert!(!role.is_tool_allowed("kernel.fs.edit"));
    }

    #[test]
    fn test_security_reviewer_cas_roundtrip() {
        let cas = MemoryCas::new();
        let role = security_reviewer_role();

        let hash = role.store_in_cas(&cas).expect("store should succeed");
        let loaded = RoleSpecV1::load_from_cas(&cas, &hash).expect("load should succeed");

        assert_eq!(role, loaded);
    }

    #[test]
    fn test_all_builtin_roles() {
        let roles = all_builtin_roles();
        assert_eq!(roles.len(), 7);

        for role in &roles {
            assert!(
                role.validate().is_ok(),
                "Role {} failed validation",
                role.role_id
            );
            assert_eq!(role.schema, ROLE_SPEC_V1_SCHEMA);
        }
    }

    #[test]
    fn test_get_builtin_role() {
        assert!(get_builtin_role(ORCHESTRATOR_ROLE_ID).is_some());
        assert!(get_builtin_role(IMPLEMENTER_ROLE_ID).is_some());
        assert!(get_builtin_role(CODE_QUALITY_REVIEWER_ROLE_ID).is_some());
        assert!(get_builtin_role(SECURITY_REVIEWER_ROLE_ID).is_some());
        assert!(get_builtin_role("nonexistent").is_none());
    }

    #[test]
    fn test_fac_workobject_implementor_v2_contract_valid() {
        let contract = fac_workobject_implementor_v2_role_contract();
        assert!(contract.validate().is_ok());
        assert_eq!(contract.schema, ROLE_SPEC_V2_SCHEMA);
        assert_eq!(contract.role_id, FAC_WORKOBJECT_IMPLEMENTOR_V2_ROLE_ID);
        assert_eq!(contract.role_type, RoleType::Implementer);
        assert!(!contract.tool_allowlists.is_empty());
        assert!(!contract.tool_budgets.is_empty());
        assert!(!contract.output_schema.fields.is_empty());
        assert!(!contract.deny_taxonomy.is_empty());
    }

    #[test]
    fn test_all_builtin_role_contracts_v2_registered() {
        let contracts = all_builtin_role_contracts_v2();
        assert_eq!(contracts.len(), 1);
        assert_eq!(contracts[0].role_id, FAC_WORKOBJECT_IMPLEMENTOR_V2_ROLE_ID);
    }

    #[test]
    fn test_get_builtin_role_contract_v2() {
        assert!(get_builtin_role_contract_v2(FAC_WORKOBJECT_IMPLEMENTOR_V2_ROLE_ID).is_some());
        assert!(get_builtin_role_contract_v2("not_registered").is_none());
    }

    #[test]
    fn test_builtin_role_contract_hash_registry_v2_deterministic() {
        let registry_a = builtin_role_contract_hash_registry_v2().unwrap();
        let registry_b = builtin_role_contract_hash_registry_v2().unwrap();
        assert_eq!(registry_a, registry_b);

        let contract = fac_workobject_implementor_v2_role_contract();
        let expected_hash = contract.compute_cas_hash().unwrap();
        assert_eq!(
            registry_a
                .get(FAC_WORKOBJECT_IMPLEMENTOR_V2_ROLE_ID)
                .copied(),
            Some(expected_hash)
        );
    }

    #[test]
    fn test_seed_builtin_role_contracts_v2_in_cas_roundtrip() {
        let cas = MemoryCas::new();
        let registry = seed_builtin_role_contracts_v2_in_cas(&cas).unwrap();
        let hash = registry
            .get(FAC_WORKOBJECT_IMPLEMENTOR_V2_ROLE_ID)
            .copied()
            .expect("role contract hash must be seeded");

        let loaded = RoleSpecV2::load_from_cas(&cas, &hash).unwrap();
        assert_eq!(loaded.role_id, FAC_WORKOBJECT_IMPLEMENTOR_V2_ROLE_ID);
        assert_eq!(loaded.compute_cas_hash().unwrap(), hash);
    }

    #[test]
    fn test_role_hashes_are_deterministic() {
        let role1 = orchestrator_role();
        let role2 = orchestrator_role();
        assert_eq!(
            role1.compute_cas_hash().unwrap(),
            role2.compute_cas_hash().unwrap()
        );

        let role3 = implementer_role();
        let role4 = implementer_role();
        assert_eq!(
            role3.compute_cas_hash().unwrap(),
            role4.compute_cas_hash().unwrap()
        );
    }

    #[test]
    fn test_role_hashes_differ_between_roles() {
        let orchestrator_hash = orchestrator_role().compute_cas_hash().unwrap();
        let implementer_hash = implementer_role().compute_cas_hash().unwrap();
        let code_quality_hash = code_quality_reviewer_role().compute_cas_hash().unwrap();
        let security_hash = security_reviewer_role().compute_cas_hash().unwrap();

        // All hashes should be unique
        assert_ne!(orchestrator_hash, implementer_hash);
        assert_ne!(orchestrator_hash, code_quality_hash);
        assert_ne!(orchestrator_hash, security_hash);
        assert_ne!(implementer_hash, code_quality_hash);
        assert_ne!(implementer_hash, security_hash);
        assert_ne!(code_quality_hash, security_hash);
    }

    #[test]
    fn test_all_roles_have_required_output_schemas() {
        for role in all_builtin_roles() {
            assert!(
                !role.required_output_schemas.is_empty(),
                "{} should have required output schemas",
                role.role_id
            );

            // At least one schema should be required
            let has_required = role.required_output_schemas.iter().any(|s| s.required);
            assert!(
                has_required,
                "{} should have at least one required output schema",
                role.role_id
            );
        }
    }

    #[test]
    fn test_all_roles_have_system_prompt_template() {
        for role in all_builtin_roles() {
            assert!(
                role.system_prompt_template.is_some(),
                "{} should have a system prompt template",
                role.role_id
            );

            let template = role.system_prompt_template.as_ref().unwrap();
            // Template should have placeholders
            assert!(
                template.contains("{work_id}"),
                "{} template should contain {{work_id}} placeholder",
                role.role_id
            );
            assert!(
                template.contains("{context}"),
                "{} template should contain {{context}} placeholder",
                role.role_id
            );
        }
    }

    #[test]
    fn test_all_roles_have_required_capabilities() {
        for role in all_builtin_roles() {
            assert!(
                !role.required_capabilities.is_empty(),
                "{} should have required capabilities",
                role.role_id
            );
        }
    }

    #[test]
    fn test_builtin_roles_exclude_direct_github_capability_classes() {
        for role in all_builtin_roles() {
            for capability in role.required_capabilities.keys() {
                assert!(
                    forbidden_direct_github_capability_class(capability).is_none(),
                    "role {} must not include forbidden direct GitHub capability class in {}",
                    role.role_id,
                    capability
                );
            }
        }
    }

    #[test]
    fn test_builtin_role_contract_v2_excludes_direct_github_capability_classes() {
        let contract = fac_workobject_implementor_v2_role_contract();
        for capability in contract.required_capabilities.keys() {
            assert!(
                forbidden_direct_github_capability_class(capability).is_none(),
                "v2 contract must not include forbidden direct GitHub capability class in {capability}",
            );
        }

        // Sanity: test explicitly exercises all forbidden classes.
        assert_eq!(FORBIDDEN_DIRECT_GITHUB_CAPABILITY_CLASSES.len(), 4);
    }

    #[test]
    fn test_reviewer_roles_have_same_budgets() {
        let code_quality = code_quality_reviewer_role();
        let security = security_reviewer_role();

        assert_eq!(
            code_quality.budgets.max_total_tool_calls,
            security.budgets.max_total_tool_calls
        );
        assert_eq!(code_quality.budgets.max_tokens, security.budgets.max_tokens);
    }

    #[test]
    fn test_reviewer_roles_cannot_write_files() {
        for role in [code_quality_reviewer_role(), security_reviewer_role()] {
            assert!(
                !role.is_tool_allowed("kernel.fs.write"),
                "{} should not be able to write files",
                role.role_id
            );
            assert!(
                !role.is_tool_allowed("kernel.fs.edit"),
                "{} should not be able to edit files",
                role.role_id
            );
        }
    }

    // =========================================================================
    // Conformance Tests for RoleSpecV1
    // =========================================================================

    mod conformance {
        use super::*;

        /// Conformance test: All roles have unique CAS hashes.
        #[test]
        fn conformance_all_roles_unique_hashes() {
            let roles = all_builtin_roles();
            let mut hashes: Vec<[u8; 32]> = Vec::new();

            for role in &roles {
                let hash = role
                    .compute_cas_hash()
                    .expect("CAS hash should be computable");
                assert!(
                    !hashes.contains(&hash),
                    "Role '{}' has duplicate CAS hash",
                    role.role_id
                );
                hashes.push(hash);
            }
        }

        /// Conformance test: All roles pass full validation.
        #[test]
        fn conformance_all_roles_valid() {
            for role in all_builtin_roles() {
                assert!(
                    role.validate().is_ok(),
                    "Role '{}' should pass validation",
                    role.role_id
                );
            }
        }

        /// Conformance test: All tool classes follow kernel namespace.
        #[test]
        fn conformance_all_tools_follow_namespace() {
            for role in all_builtin_roles() {
                for tool_class in &role.tool_allowlist.allowed_tools {
                    assert!(
                        tool_class.starts_with("kernel."),
                        "Tool '{}' in role '{}' should follow kernel namespace",
                        tool_class,
                        role.role_id
                    );
                }
            }
        }

        /// Conformance test: CAS roundtrip preserves all fields.
        #[test]
        fn conformance_cas_roundtrip_field_preservation() {
            let cas = MemoryCas::new();

            for role in all_builtin_roles() {
                let hash = role
                    .store_in_cas(&cas)
                    .unwrap_or_else(|_| panic!("Store '{}' should succeed", role.role_id));

                let loaded = RoleSpecV1::load_from_cas(&cas, &hash)
                    .unwrap_or_else(|_| panic!("Load '{}' should succeed", role.role_id));

                // Field-by-field comparison
                assert_eq!(role.role_id, loaded.role_id);
                assert_eq!(role.role_name, loaded.role_name);
                assert_eq!(role.role_type, loaded.role_type);
                assert_eq!(role.description, loaded.description);
                assert_eq!(role.tool_allowlist, loaded.tool_allowlist);
                assert_eq!(role.budgets, loaded.budgets);
                assert_eq!(role.required_output_schemas, loaded.required_output_schemas);
                assert_eq!(role.system_prompt_template, loaded.system_prompt_template);
                assert_eq!(role.required_capabilities, loaded.required_capabilities);

                // Full equality check
                assert_eq!(role, loaded, "Full role mismatch for '{}'", role.role_id);
            }
        }
    }
}
