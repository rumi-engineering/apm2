//! Role routing and classification logic for FAC.
//!
//! This module implements the heuristics for routing work to specialist roles
//! based on diff analysis and issue labels, per TCK-00334.
//!
//! # Integration Point
//!
//! This module is designed to be called by the Orchestrator or daemon when
//! allocating work. The `classify_changeset` function analyzes issue metadata
//! and changed files to determine the best role for the task.
//!
//! # Context Pack Scoping
//!
//! Each `RoutingDecision` includes suggested file patterns for building a
//! scoped context pack. This allows specialists to receive only relevant
//! files, reducing noise and token usage.

use crate::fac::builtin_roles::{
    dependency_updater_role, implementer_role, rust_compile_error_fixer_role, test_flake_fixer_role,
};
use crate::fac::role_spec::{RoleSpecV1, RoleType};

/// File patterns for test-related files.
const TEST_FILE_PATTERNS: &[&str] = &["**/tests/**", "**/test_*.rs", "**/*_test.rs"];

/// File patterns for Rust source files.
const RUST_SOURCE_PATTERNS: &[&str] = &["**/*.rs", "Cargo.toml", "Cargo.lock"];

/// File patterns for dependency-related files.
const DEPENDENCY_PATTERNS: &[&str] = &[
    "Cargo.toml",
    "Cargo.lock",
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
];

/// The decision made by the router.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoutingDecision {
    /// Route to a specialist role with narrowed scope.
    Specialist(RoleSpecV1),
    /// Route to the generalist implementer role.
    Generalist(RoleSpecV1),
}

impl RoutingDecision {
    /// Returns the selected role spec.
    #[must_use]
    pub const fn role_spec(&self) -> &RoleSpecV1 {
        match self {
            Self::Specialist(role) | Self::Generalist(role) => role,
        }
    }

    /// Returns suggested file patterns for building a scoped context pack.
    ///
    /// Specialists receive narrowed file patterns to reduce noise and token
    /// usage. Generalists receive `None`, indicating full context should be
    /// provided.
    ///
    /// # Returns
    ///
    /// - `Some(&[&str])` - File glob patterns to include in the context pack
    /// - `None` - Full context should be provided (for generalists)
    ///
    /// # Example
    ///
    /// ```rust
    /// use apm2_core::fac::role_routing::{RoutingDecision, classify_changeset};
    ///
    /// let decision = classify_changeset(&[], &["flaky-test".to_string()], "Fix flake");
    ///
    /// if let Some(patterns) = decision.context_file_patterns() {
    ///     for pattern in patterns {
    ///         println!("Include files matching: {}", pattern);
    ///     }
    /// }
    /// ```
    #[must_use]
    pub const fn context_file_patterns(&self) -> Option<&'static [&'static str]> {
        match self {
            Self::Generalist(_) => None, // Full context for generalists
            Self::Specialist(role) => match role.role_type {
                RoleType::TestFlakeFixer => Some(TEST_FILE_PATTERNS),
                RoleType::RustCompileErrorFixer => Some(RUST_SOURCE_PATTERNS),
                RoleType::DependencyUpdater => Some(DEPENDENCY_PATTERNS),
                // Other specialists get full context by default
                _ => None,
            },
        }
    }

    /// Returns whether this decision routes to a specialist role.
    #[must_use]
    pub const fn is_specialist(&self) -> bool {
        matches!(self, Self::Specialist(_))
    }

    /// Returns whether this decision routes to a generalist role.
    #[must_use]
    pub const fn is_generalist(&self) -> bool {
        matches!(self, Self::Generalist(_))
    }
}

/// Classifies a changeset to determine the best role.
///
/// # Arguments
///
/// * `diff_stats` - List of file paths changed (simplified diff analysis).
/// * `issue_labels` - Labels associated with the work item.
/// * `issue_title` - Title of the work item.
#[must_use]
pub fn classify_changeset(
    changed_files: &[String],
    issue_labels: &[String],
    issue_title: &str,
) -> RoutingDecision {
    // 1. Check explicit labels first (strongest signal)
    for label in issue_labels {
        match label.as_str() {
            "flaky-test" | "test-failure" => {
                return RoutingDecision::Specialist(test_flake_fixer_role());
            },
            "compile-error" | "build-failure" => {
                return RoutingDecision::Specialist(rust_compile_error_fixer_role());
            },
            "dependencies" | "deps" => {
                return RoutingDecision::Specialist(dependency_updater_role());
            },
            _ => {},
        }
    }

    // 2. Check title keywords (medium signal)
    let title_lower = issue_title.to_lowercase();
    if title_lower.contains("flake") || title_lower.contains("test fail") {
        return RoutingDecision::Specialist(test_flake_fixer_role());
    }
    if title_lower.contains("compile error") || title_lower.contains("build fail") {
        return RoutingDecision::Specialist(rust_compile_error_fixer_role());
    }
    if title_lower.contains("bump ")
        || title_lower.contains("dependency")
        || title_lower.contains("update crate")
    {
        return RoutingDecision::Specialist(dependency_updater_role());
    }

    // 3. Analyze changed files (heuristic signal)
    if !changed_files.is_empty()
        && changed_files.iter().all(|f| {
            f.ends_with("Cargo.toml")
                || f.ends_with("Cargo.lock")
                || f.ends_with(".cargo/config.toml")
        })
    {
        return RoutingDecision::Specialist(dependency_updater_role());
        // If all changes are in test files, suggest test fixer?
        // Maybe, but implementer is also valid. Let's be conservative.
    }

    // Default to generalist implementer
    RoutingDecision::Generalist(implementer_role())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fac::builtin_roles::{
        DEPENDENCY_UPDATER_ROLE_ID, IMPLEMENTER_ROLE_ID, RUST_COMPILE_ERROR_FIXER_ROLE_ID,
        TEST_FLAKE_FIXER_ROLE_ID,
    };

    #[test]
    fn test_classify_by_label() {
        let decision = classify_changeset(&[], &["flaky-test".to_string()], "Some issue");
        assert_eq!(decision.role_spec().role_id, TEST_FLAKE_FIXER_ROLE_ID);
        assert!(matches!(decision, RoutingDecision::Specialist(_)));

        let decision = classify_changeset(&[], &["compile-error".to_string()], "Some issue");
        assert_eq!(
            decision.role_spec().role_id,
            RUST_COMPILE_ERROR_FIXER_ROLE_ID
        );

        let decision = classify_changeset(&[], &["dependencies".to_string()], "Some issue");
        assert_eq!(decision.role_spec().role_id, DEPENDENCY_UPDATER_ROLE_ID);
    }

    #[test]
    fn test_classify_by_title() {
        let decision = classify_changeset(&[], &[], "Fix CI flake in test_foo");
        assert_eq!(decision.role_spec().role_id, TEST_FLAKE_FIXER_ROLE_ID);

        let decision = classify_changeset(&[], &[], "Bump serde to 1.0.200");
        assert_eq!(decision.role_spec().role_id, DEPENDENCY_UPDATER_ROLE_ID);
    }

    #[test]
    fn test_classify_by_files() {
        let files = vec!["Cargo.toml".to_string(), "Cargo.lock".to_string()];
        let decision = classify_changeset(&files, &[], "Maintenance");
        assert_eq!(decision.role_spec().role_id, DEPENDENCY_UPDATER_ROLE_ID);
    }

    #[test]
    fn test_classify_generalist_fallback() {
        let files = vec!["src/main.rs".to_string()];
        let decision = classify_changeset(&files, &[], "Implement new feature");
        assert_eq!(decision.role_spec().role_id, IMPLEMENTER_ROLE_ID);
        assert!(matches!(decision, RoutingDecision::Generalist(_)));
    }

    #[test]
    fn test_context_file_patterns_test_flake_fixer() {
        let decision = classify_changeset(&[], &["flaky-test".to_string()], "Fix flake");
        let patterns = decision.context_file_patterns();
        assert!(patterns.is_some());
        let patterns = patterns.unwrap();
        assert!(patterns.contains(&"**/tests/**"));
        assert!(patterns.contains(&"**/test_*.rs"));
    }

    #[test]
    fn test_context_file_patterns_rust_compile_error_fixer() {
        let decision = classify_changeset(&[], &["compile-error".to_string()], "Fix error");
        let patterns = decision.context_file_patterns();
        assert!(patterns.is_some());
        let patterns = patterns.unwrap();
        assert!(patterns.contains(&"**/*.rs"));
        assert!(patterns.contains(&"Cargo.toml"));
    }

    #[test]
    fn test_context_file_patterns_dependency_updater() {
        let decision = classify_changeset(&[], &["dependencies".to_string()], "Update deps");
        let patterns = decision.context_file_patterns();
        assert!(patterns.is_some());
        let patterns = patterns.unwrap();
        assert!(patterns.contains(&"Cargo.toml"));
        assert!(patterns.contains(&"Cargo.lock"));
        assert!(patterns.contains(&"package.json"));
    }

    #[test]
    fn test_context_file_patterns_generalist_is_none() {
        let decision = classify_changeset(&["src/main.rs".to_string()], &[], "New feature");
        assert!(decision.is_generalist());
        assert!(decision.context_file_patterns().is_none());
    }

    #[test]
    fn test_is_specialist_and_is_generalist() {
        let specialist = classify_changeset(&[], &["flaky-test".to_string()], "Fix flake");
        assert!(specialist.is_specialist());
        assert!(!specialist.is_generalist());

        let generalist = classify_changeset(&["src/main.rs".to_string()], &[], "New feature");
        assert!(generalist.is_generalist());
        assert!(!generalist.is_specialist());
    }
}
