//! Lease scope types for authority boundaries.
//!
//! This module defines [`LeaseScope`] which specifies what operations a lease
//! authorizes. Scopes form a lattice where derived leases must have a scope
//! that is a subset of their parent's scope.
//!
//! # Authority Model
//!
//! Lease scopes implement bounded authority (Axiom III from Principia
//! Holonica). Each scope defines:
//!
//! - **Work IDs**: Which work items the lease grants access to
//! - **Tool Names**: Which tools the lease holder can invoke
//! - **Namespaces**: Which namespace prefixes are accessible
//!
//! # Example
//!
//! ```rust
//! use apm2_holon::resource::LeaseScope;
//!
//! // Create a scope with specific permissions
//! let scope = LeaseScope::builder()
//!     .work_ids(["work-001", "work-002"])
//!     .tools(["read_file", "write_file"])
//!     .namespaces(["project/src"])
//!     .build();
//!
//! assert!(scope.allows_work_id("work-001"));
//! assert!(scope.allows_tool("read_file"));
//! assert!(scope.allows_namespace("project/src/main.rs"));
//! ```

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::error::ResourceError;

/// A lease scope defining authority boundaries.
///
/// Scopes constrain what operations a lease holder can perform:
/// - Which work items can be accessed
/// - Which tools can be invoked
/// - Which namespaces are accessible
///
/// An empty set for any dimension means "no access" (not "unlimited").
/// Use `LeaseScope::unlimited()` for unrestricted access.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseScope {
    /// Work IDs this scope grants access to.
    /// Empty means no work access.
    work_ids: BTreeSet<String>,

    /// Tool names this scope allows invocation of.
    /// Empty means no tool access.
    tools: BTreeSet<String>,

    /// Namespace prefixes this scope allows access to.
    /// Empty means no namespace access.
    namespaces: BTreeSet<String>,

    /// Whether this is an unlimited scope (bypass all checks).
    #[serde(default)]
    unlimited: bool,
}

impl LeaseScope {
    /// Creates an empty scope with no permissions.
    ///
    /// An empty scope denies all operations.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // BTreeSet::new() is not const
    pub fn empty() -> Self {
        Self {
            work_ids: BTreeSet::new(),
            tools: BTreeSet::new(),
            namespaces: BTreeSet::new(),
            unlimited: false,
        }
    }

    /// Creates an unlimited scope that allows all operations.
    ///
    /// # Warning
    ///
    /// Unlimited scopes should only be used for root-level holons
    /// with explicit authorization. They bypass all permission checks.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // BTreeSet::new() is not const
    pub fn unlimited() -> Self {
        Self {
            work_ids: BTreeSet::new(),
            tools: BTreeSet::new(),
            namespaces: BTreeSet::new(),
            unlimited: true,
        }
    }

    /// Returns a builder for constructing a `LeaseScope`.
    #[must_use]
    pub fn builder() -> LeaseScopeBuilder {
        LeaseScopeBuilder::default()
    }

    /// Returns `true` if this is an unlimited scope.
    #[must_use]
    pub const fn is_unlimited(&self) -> bool {
        self.unlimited
    }

    /// Returns `true` if this scope has no permissions.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        !self.unlimited
            && self.work_ids.is_empty()
            && self.tools.is_empty()
            && self.namespaces.is_empty()
    }

    /// Returns the work IDs in this scope.
    #[must_use]
    pub const fn work_ids(&self) -> &BTreeSet<String> {
        &self.work_ids
    }

    /// Returns the tools in this scope.
    #[must_use]
    pub const fn tools(&self) -> &BTreeSet<String> {
        &self.tools
    }

    /// Returns the namespaces in this scope.
    #[must_use]
    pub const fn namespaces(&self) -> &BTreeSet<String> {
        &self.namespaces
    }

    /// Returns `true` if this scope allows access to the given work ID.
    #[must_use]
    pub fn allows_work_id(&self, work_id: &str) -> bool {
        self.unlimited || self.work_ids.contains(work_id)
    }

    /// Returns `true` if this scope allows invocation of the given tool.
    #[must_use]
    pub fn allows_tool(&self, tool: &str) -> bool {
        self.unlimited || self.tools.contains(tool)
    }

    /// Returns `true` if this scope allows access to the given namespace path.
    ///
    /// Namespace matching uses path-aware prefix semantics: a scope with
    /// namespace "project/src" allows access to "project/src" and
    /// "project/src/main.rs", but NOT "project/src\_backup" or
    /// "project/srcfile".
    ///
    /// # Security
    ///
    /// Paths containing traversal sequences (`..`) are rejected to prevent
    /// scope escape attacks. A scope allowing "project" will NOT authorize
    /// "project/../secret" even though it starts with the allowed prefix.
    ///
    /// The path separator is `/`.
    #[must_use]
    pub fn allows_namespace(&self, path: &str) -> bool {
        // SECURITY: Always reject paths with traversal sequences first,
        // even for unlimited scopes (defense in depth)
        if Self::contains_path_traversal(path) {
            return false;
        }
        if self.unlimited {
            return true;
        }
        self.namespaces
            .iter()
            .any(|ns| Self::is_namespace_prefix(ns, path))
    }

    /// Checks if a path contains traversal sequences (`..`).
    ///
    /// Returns true if the path contains:
    /// - `..` at the start (e.g., `../foo`)
    /// - `..` at the end (e.g., `foo/..`)
    /// - `..` in the middle (e.g., `foo/../bar`)
    /// - Just `..`
    fn contains_path_traversal(path: &str) -> bool {
        // Check for exact ".." or paths starting/ending/containing "/.." or "../"
        path == ".." || path.starts_with("../") || path.ends_with("/..") || path.contains("/../")
    }

    /// Checks if `prefix` is a valid namespace prefix of `path`.
    ///
    /// Returns true if:
    /// - `path` equals `prefix`, or
    /// - `path` starts with `prefix` followed by `/`
    fn is_namespace_prefix(prefix: &str, path: &str) -> bool {
        if path == prefix {
            return true;
        }
        // Check if path starts with prefix followed by a path separator
        path.starts_with(prefix) && path.as_bytes().get(prefix.len()) == Some(&b'/')
    }

    /// Checks if this scope is a superset of another scope.
    ///
    /// A scope A is a superset of scope B if every permission in B
    /// is also present in A.
    #[must_use]
    pub fn is_superset_of(&self, other: &Self) -> bool {
        if self.unlimited {
            return true;
        }
        if other.unlimited {
            return false;
        }

        // Check work_ids subset
        for id in &other.work_ids {
            if !self.work_ids.contains(id) {
                return false;
            }
        }

        // Check tools subset
        for tool in &other.tools {
            if !self.tools.contains(tool) {
                return false;
            }
        }

        // Check namespaces subset (prefix matching)
        for ns in &other.namespaces {
            if !self.allows_namespace(ns) {
                return false;
            }
        }

        true
    }

    /// Checks if this scope is a subset of another scope.
    #[must_use]
    pub fn is_subset_of(&self, other: &Self) -> bool {
        other.is_superset_of(self)
    }

    /// Creates an intersection of this scope with another.
    ///
    /// The resulting scope contains only permissions present in both scopes.
    #[must_use]
    pub fn intersect(&self, other: &Self) -> Self {
        if other.unlimited {
            return self.clone();
        }
        if self.unlimited {
            return other.clone();
        }

        Self {
            work_ids: self
                .work_ids
                .intersection(&other.work_ids)
                .cloned()
                .collect(),
            tools: self.tools.intersection(&other.tools).cloned().collect(),
            namespaces: self.intersect_namespaces(&other.namespaces),
            unlimited: false,
        }
    }

    /// Intersects namespace sets using path-aware prefix matching.
    fn intersect_namespaces(&self, other: &BTreeSet<String>) -> BTreeSet<String> {
        let mut result = BTreeSet::new();

        // For each namespace in self, check if it's allowed by other
        for ns in &self.namespaces {
            if other.iter().any(|o| Self::is_namespace_prefix(o, ns)) {
                result.insert(ns.clone());
            }
        }

        // For each namespace in other, check if it's allowed by self
        for ns in other {
            if self
                .namespaces
                .iter()
                .any(|s| Self::is_namespace_prefix(s, ns))
            {
                result.insert(ns.clone());
            }
        }

        result
    }

    /// Validates that a requested scope can be derived from this parent scope.
    ///
    /// # Errors
    ///
    /// Returns `ResourceError::InvalidDerivation` if the requested scope
    /// exceeds this scope's permissions.
    pub fn validate_derivation(&self, requested: &Self) -> Result<(), ResourceError> {
        if !self.is_superset_of(requested) {
            return Err(ResourceError::invalid_derivation(
                "derived scope exceeds parent scope",
            ));
        }
        Ok(())
    }

    /// Derives a sub-scope bounded by this scope.
    ///
    /// The returned scope is the intersection of the requested scope
    /// and this scope, ensuring the derived scope never exceeds the parent.
    #[must_use]
    pub fn derive_sub_scope(&self, requested: &Self) -> Self {
        self.intersect(requested)
    }
}

impl Default for LeaseScope {
    fn default() -> Self {
        Self::empty()
    }
}

/// Builder for constructing [`LeaseScope`] instances.
#[derive(Debug, Default)]
pub struct LeaseScopeBuilder {
    work_ids: BTreeSet<String>,
    tools: BTreeSet<String>,
    namespaces: BTreeSet<String>,
}

impl LeaseScopeBuilder {
    /// Adds work IDs to the scope.
    #[must_use]
    pub fn work_ids<I, S>(mut self, ids: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.work_ids.extend(ids.into_iter().map(Into::into));
        self
    }

    /// Adds a single work ID to the scope.
    #[must_use]
    pub fn work_id(mut self, id: impl Into<String>) -> Self {
        self.work_ids.insert(id.into());
        self
    }

    /// Adds tools to the scope.
    #[must_use]
    pub fn tools<I, S>(mut self, tools: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.tools.extend(tools.into_iter().map(Into::into));
        self
    }

    /// Adds a single tool to the scope.
    #[must_use]
    pub fn tool(mut self, tool: impl Into<String>) -> Self {
        self.tools.insert(tool.into());
        self
    }

    /// Adds namespaces to the scope.
    #[must_use]
    pub fn namespaces<I, S>(mut self, namespaces: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.namespaces
            .extend(namespaces.into_iter().map(Into::into));
        self
    }

    /// Adds a single namespace to the scope.
    #[must_use]
    pub fn namespace(mut self, namespace: impl Into<String>) -> Self {
        self.namespaces.insert(namespace.into());
        self
    }

    /// Builds the `LeaseScope`.
    #[must_use]
    pub fn build(self) -> LeaseScope {
        LeaseScope {
            work_ids: self.work_ids,
            tools: self.tools,
            namespaces: self.namespaces,
            unlimited: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_scope() {
        let scope = LeaseScope::empty();

        assert!(scope.is_empty());
        assert!(!scope.is_unlimited());
        assert!(!scope.allows_work_id("work-001"));
        assert!(!scope.allows_tool("read_file"));
        assert!(!scope.allows_namespace("project/src"));
    }

    #[test]
    fn test_unlimited_scope() {
        let scope = LeaseScope::unlimited();

        assert!(!scope.is_empty());
        assert!(scope.is_unlimited());
        assert!(scope.allows_work_id("any-work"));
        assert!(scope.allows_tool("any-tool"));
        assert!(scope.allows_namespace("any/path"));
    }

    #[test]
    fn test_builder() {
        let scope = LeaseScope::builder()
            .work_ids(["work-001", "work-002"])
            .tools(["read_file", "write_file"])
            .namespaces(["project/src", "project/tests"])
            .build();

        assert!(!scope.is_empty());
        assert!(!scope.is_unlimited());
        assert!(scope.allows_work_id("work-001"));
        assert!(scope.allows_work_id("work-002"));
        assert!(!scope.allows_work_id("work-003"));
        assert!(scope.allows_tool("read_file"));
        assert!(!scope.allows_tool("delete_file"));
    }

    #[test]
    fn test_builder_single_items() {
        let scope = LeaseScope::builder()
            .work_id("work-001")
            .tool("read_file")
            .namespace("project/src")
            .build();

        assert!(scope.allows_work_id("work-001"));
        assert!(scope.allows_tool("read_file"));
        assert!(scope.allows_namespace("project/src"));
    }

    #[test]
    fn test_namespace_prefix_matching() {
        let scope = LeaseScope::builder().namespace("project/src").build();

        // Exact match
        assert!(scope.allows_namespace("project/src"));
        // Valid subpaths
        assert!(scope.allows_namespace("project/src/main.rs"));
        assert!(scope.allows_namespace("project/src/lib/mod.rs"));
        // Different directories
        assert!(!scope.allows_namespace("project/tests"));
        assert!(!scope.allows_namespace("other/src"));
        // SECURITY: Must NOT match sibling paths that share a prefix
        assert!(!scope.allows_namespace("project/src_backup"));
        assert!(!scope.allows_namespace("project/srcfile"));
    }

    #[test]
    fn test_namespace_prefix_security() {
        // Verify fix for scope prefix vulnerability
        // A scope for "data" must NOT allow access to "database"
        let scope = LeaseScope::builder().namespace("data").build();

        assert!(scope.allows_namespace("data"));
        assert!(scope.allows_namespace("data/file.txt"));
        assert!(!scope.allows_namespace("database"));
        assert!(!scope.allows_namespace("database/users"));
        assert!(!scope.allows_namespace("data_backup"));

        // Another test case: "auth" vs "authority"
        let auth_scope = LeaseScope::builder().namespace("auth").build();

        assert!(auth_scope.allows_namespace("auth"));
        assert!(auth_scope.allows_namespace("auth/tokens"));
        assert!(!auth_scope.allows_namespace("authority"));
        assert!(!auth_scope.allows_namespace("authorize"));
    }

    #[test]
    fn test_path_traversal_rejection() {
        // SECURITY: Verify that paths containing ".." traversal sequences
        // are rejected to prevent scope escape attacks
        let scope = LeaseScope::builder().namespace("project").build();

        // Normal paths should work
        assert!(scope.allows_namespace("project"));
        assert!(scope.allows_namespace("project/src"));
        assert!(scope.allows_namespace("project/src/main.rs"));

        // Path traversal attempts must be rejected
        assert!(!scope.allows_namespace("project/../secret"));
        assert!(!scope.allows_namespace("project/src/../../../etc/passwd"));
        assert!(!scope.allows_namespace("../project"));
        assert!(!scope.allows_namespace("project/.."));
        assert!(!scope.allows_namespace(".."));

        // Paths that look similar but don't have traversal should work
        // (e.g., a file literally named "..." or "..x")
        assert!(scope.allows_namespace("project/.../file"));
        assert!(scope.allows_namespace("project/..hidden"));

        // Even unlimited scopes must reject traversal (defense in depth)
        let unlimited = LeaseScope::unlimited();
        assert!(!unlimited.allows_namespace("anything/../secret"));
        // But normal paths still work
        assert!(unlimited.allows_namespace("anything/normal/path"));
    }

    #[test]
    fn test_is_superset_of() {
        let parent = LeaseScope::builder()
            .work_ids(["work-001", "work-002", "work-003"])
            .tools(["read", "write", "delete"])
            .namespaces(["project"])
            .build();

        let child = LeaseScope::builder()
            .work_ids(["work-001", "work-002"])
            .tools(["read", "write"])
            .namespaces(["project/src"])
            .build();

        assert!(parent.is_superset_of(&child));
        assert!(!child.is_superset_of(&parent));
    }

    #[test]
    fn test_unlimited_is_superset_of_all() {
        let unlimited = LeaseScope::unlimited();
        let any_scope = LeaseScope::builder()
            .work_ids(["work-001"])
            .tools(["anything"])
            .namespaces(["anywhere"])
            .build();

        assert!(unlimited.is_superset_of(&any_scope));
        assert!(!any_scope.is_superset_of(&unlimited));
    }

    #[test]
    fn test_is_subset_of() {
        let parent = LeaseScope::builder()
            .work_ids(["work-001", "work-002"])
            .build();

        let child = LeaseScope::builder().work_ids(["work-001"]).build();

        assert!(child.is_subset_of(&parent));
        assert!(!parent.is_subset_of(&child));
    }

    #[test]
    fn test_intersect() {
        let scope1 = LeaseScope::builder()
            .work_ids(["work-001", "work-002", "work-003"])
            .tools(["read", "write"])
            .build();

        let scope2 = LeaseScope::builder()
            .work_ids(["work-002", "work-003", "work-004"])
            .tools(["write", "delete"])
            .build();

        let intersection = scope1.intersect(&scope2);

        assert_eq!(intersection.work_ids().len(), 2);
        assert!(intersection.allows_work_id("work-002"));
        assert!(intersection.allows_work_id("work-003"));
        assert!(!intersection.allows_work_id("work-001"));
        assert!(!intersection.allows_work_id("work-004"));

        assert_eq!(intersection.tools().len(), 1);
        assert!(intersection.allows_tool("write"));
        assert!(!intersection.allows_tool("read"));
        assert!(!intersection.allows_tool("delete"));
    }

    #[test]
    fn test_intersect_with_unlimited() {
        let limited = LeaseScope::builder().work_ids(["work-001"]).build();

        let unlimited = LeaseScope::unlimited();

        // Intersection with unlimited returns the limited scope
        let result = limited.intersect(&unlimited);
        assert_eq!(result, limited);

        let result = unlimited.intersect(&limited);
        assert_eq!(result, limited);
    }

    #[test]
    fn test_validate_derivation_success() {
        let parent = LeaseScope::builder()
            .work_ids(["work-001", "work-002"])
            .tools(["read", "write"])
            .build();

        let child = LeaseScope::builder()
            .work_ids(["work-001"])
            .tools(["read"])
            .build();

        assert!(parent.validate_derivation(&child).is_ok());
    }

    #[test]
    fn test_validate_derivation_failure() {
        let parent = LeaseScope::builder()
            .work_ids(["work-001"])
            .tools(["read"])
            .build();

        let child = LeaseScope::builder()
            .work_ids(["work-001", "work-002"]) // exceeds parent
            .tools(["read"])
            .build();

        let result = parent.validate_derivation(&child);
        assert!(result.is_err());
        match result {
            Err(ResourceError::InvalidDerivation { reason }) => {
                assert!(reason.contains("exceeds parent scope"));
            },
            _ => panic!("Expected InvalidDerivation error"),
        }
    }

    #[test]
    fn test_derive_sub_scope() {
        let parent = LeaseScope::builder()
            .work_ids(["work-001", "work-002", "work-003"])
            .tools(["read", "write", "delete"])
            .build();

        let requested = LeaseScope::builder()
            .work_ids(["work-001", "work-004"]) // work-004 not in parent
            .tools(["read", "execute"]) // execute not in parent
            .build();

        let derived = parent.derive_sub_scope(&requested);

        // Should only include what's in both
        assert!(derived.allows_work_id("work-001"));
        assert!(!derived.allows_work_id("work-004"));
        assert!(derived.allows_tool("read"));
        assert!(!derived.allows_tool("execute"));
    }

    #[test]
    fn test_default_is_empty() {
        let scope = LeaseScope::default();
        assert!(scope.is_empty());
    }

    #[test]
    fn test_serialization() {
        let scope = LeaseScope::builder()
            .work_ids(["work-001"])
            .tools(["read"])
            .namespaces(["project"])
            .build();

        let json = serde_json::to_string(&scope).unwrap();
        let deserialized: LeaseScope = serde_json::from_str(&json).unwrap();

        assert_eq!(scope, deserialized);
    }

    #[test]
    fn test_unlimited_serialization() {
        let scope = LeaseScope::unlimited();

        let json = serde_json::to_string(&scope).unwrap();
        let deserialized: LeaseScope = serde_json::from_str(&json).unwrap();

        assert!(deserialized.is_unlimited());
    }

    #[test]
    fn test_intersect_namespaces() {
        let scope1 = LeaseScope::builder()
            .namespaces(["project", "other"])
            .build();

        let scope2 = LeaseScope::builder()
            .namespaces(["project/src", "different"])
            .build();

        let intersection = scope1.intersect(&scope2);

        // project/src is under project, so it should be included
        assert!(intersection.allows_namespace("project/src"));
        assert!(!intersection.allows_namespace("other"));
        assert!(!intersection.allows_namespace("different"));
    }
}
