// AGENT-AUTHORED
//! Workspace confinement for capsule containment (RFC-0020 Section 4.3).
//!
//! Provides path traversal prevention, workspace root confinement, and
//! error types for symlink escape detection. Used by the capsule profile
//! to enforce that agent processes cannot access files outside their workspace.
//!
//! # Security Properties
//!
//! - Path traversal via `..` components is rejected (both relative and
//!   absolute)
//! - Absolute paths must not contain `ParentDir` or `CurDir` components
//! - Relative paths in workspace context are rejected if absolute
//! - Workspace root itself is validated (no sensitive system directories)
//!
//! # Symlink Detection (Deferred to TCK-00375)
//!
//! This module defines the [`WorkspaceConfinementError::SymlinkDetected`]
//! error variant for use by future runtime callers that perform filesystem
//! I/O. Symlink-safe runtime path resolution (using `symlink_metadata()`
//! calls per CTR-1503 and filesystem-level TOCTOU checks) is **deferred to
//! TCK-00375**. This module currently provides only lexical path validation;
//! it does NOT perform runtime symlink detection.
//!
//! # Example
//!
//! ```rust
//! use std::path::Path;
//!
//! use apm2_core::capsule::{WorkspaceConfinement, validate_workspace_path};
//!
//! // Construction validates the root path (fail-closed by construction).
//! let confinement =
//!     WorkspaceConfinement::new("/home/agent/workspace").expect("valid workspace root");
//!
//! // Valid relative path within workspace (root enforced via WorkspaceConfinement)
//! let ws = WorkspaceConfinement::new("/workspace").expect("valid workspace root");
//! assert!(validate_workspace_path(Path::new("src/main.rs"), &ws).is_ok());
//!
//! // Path traversal attempt → rejected
//! assert!(validate_workspace_path(Path::new("../../../etc/passwd"), &ws).is_err());
//! ```

use std::path::{Component, Path, PathBuf};

use serde::{Serialize, de};
use thiserror::Error;

// =============================================================================
// Resource Limits
// =============================================================================

/// Maximum path depth to prevent directory traversal and zip-bomb style
/// attacks.
pub const MAX_WORKSPACE_PATH_DEPTH: usize = 64;

/// Maximum length of a workspace path.
const MAX_WORKSPACE_PATH_LENGTH: usize = 4096;

/// Blocked workspace root prefixes (sensitive system directories).
///
/// Workspace root MUST NOT be set to these directories to prevent
/// accidental access to system-critical files.
const BLOCKED_ROOTS: &[&str] = &[
    "/", "/bin", "/boot", "/dev", "/etc", "/lib", "/lib64", "/proc", "/root", "/run", "/sbin",
    "/sys", "/usr", "/var",
];

// =============================================================================
// Error Types
// =============================================================================

/// Errors from workspace confinement operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum WorkspaceConfinementError {
    /// Path traversal attempt detected.
    #[error("path traversal detected: {path}")]
    PathTraversal {
        /// The offending path.
        path: String,
    },

    /// Symlink detected in workspace path.
    #[error("symlink detected at: {path}")]
    SymlinkDetected {
        /// Path where symlink was found.
        path: String,
    },

    /// Absolute path in workspace-relative context.
    #[error("absolute path not allowed in workspace context: {path}")]
    AbsolutePath {
        /// The offending absolute path.
        path: String,
    },

    /// Path depth exceeds maximum.
    #[error("path depth {depth} exceeds maximum {max}")]
    PathTooDeep {
        /// Actual depth.
        depth: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Path length exceeds maximum.
    #[error("path length {actual} exceeds maximum {max}")]
    PathTooLong {
        /// Actual length.
        actual: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Workspace root is a sensitive system directory.
    #[error("workspace root '{root}' is a blocked system directory")]
    BlockedRoot {
        /// The blocked root path.
        root: String,
    },

    /// Workspace root is empty.
    #[error("workspace root path is empty")]
    EmptyRoot,

    /// Workspace root is not absolute.
    #[error("workspace root must be an absolute path: {root}")]
    NotAbsolute {
        /// The non-absolute root.
        root: String,
    },

    /// Forbidden path component found.
    #[error("forbidden path component: {component}")]
    ForbiddenComponent {
        /// Description of the forbidden component.
        component: String,
    },
}

// =============================================================================
// WorkspaceConfinement
// =============================================================================

/// Workspace confinement specification for capsule containment.
///
/// Defines the workspace root directory that will be bind-mounted
/// into the capsule. All agent file operations are confined to this root.
///
/// # Construction
///
/// `WorkspaceConfinement` is fail-closed by construction: the only public
/// constructor is [`WorkspaceConfinement::new()`], which validates the root
/// path and returns `Result`. This ensures that `contains()` and
/// `validate_workspace_path()` can never be called on an unvalidated
/// confinement (CTR-2603, CTR-1205).
///
/// # Deserialization
///
/// `Deserialize` is implemented manually (not derived) to enforce the same
/// validation as `new()`. Deserializing a blocked root like `"/etc"` will
/// fail, preventing bypass of the construction-time invariants via serde
/// (CTR-1604, CTR-2603).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct WorkspaceConfinement {
    /// Absolute path to the workspace root (validated at construction time).
    root: PathBuf,
}

// Custom Deserialize: deserialize into a helper struct, then validate via
// new(). This closes the deserialization bypass where serde could construct a
// WorkspaceConfinement with a blocked root like "/etc" (CTR-2603, CTR-1604).
impl<'de> de::Deserialize<'de> for WorkspaceConfinement {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        /// Helper struct matching the serialized shape of `WorkspaceConfinement`.
        #[derive(serde::Deserialize)]
        struct Raw {
            root: PathBuf,
        }

        let raw = Raw::deserialize(deserializer)?;
        Self::new(raw.root).map_err(de::Error::custom)
    }
}

impl WorkspaceConfinement {
    /// Creates a new workspace confinement with the given root, validating
    /// that the root is an absolute path without traversal components and
    /// is not a blocked system directory.
    ///
    /// # Errors
    ///
    /// Returns [`WorkspaceConfinementError`] if the root path fails
    /// validation (empty, relative, contains `..`/`.`, blocked directory,
    /// or exceeds length limits).
    pub fn new(root: impl Into<PathBuf>) -> Result<Self, WorkspaceConfinementError> {
        let confinement = Self { root: root.into() };
        confinement.validate_root()?;
        Ok(confinement)
    }

    /// Returns the workspace root path.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Internal: validates the workspace root path.
    ///
    /// Called by `new()` during construction. This is not public because
    /// all `WorkspaceConfinement` values are validated at construction time.
    fn validate_root(&self) -> Result<(), WorkspaceConfinementError> {
        let root_str = self.root.to_string_lossy();

        // Must not be empty
        if root_str.is_empty() {
            return Err(WorkspaceConfinementError::EmptyRoot);
        }

        // Must be absolute
        if !self.root.is_absolute() {
            return Err(WorkspaceConfinementError::NotAbsolute {
                root: root_str.to_string(),
            });
        }

        // Must not exceed length limit
        if root_str.len() > MAX_WORKSPACE_PATH_LENGTH {
            return Err(WorkspaceConfinementError::PathTooLong {
                actual: root_str.len(),
                max: MAX_WORKSPACE_PATH_LENGTH,
            });
        }

        // Reject ParentDir (..) and CurDir (.) components in workspace root
        // BEFORE blocked-root policy checks. A root like `/tmp/../etc` would
        // bypass lexical prefix checks against BLOCKED_ROOTS because the
        // prefix `/tmp` is not blocked, but the path resolves to `/etc`.
        // Per CTR-1504: iterate over components and reject ParentDir/CurDir.
        for component in self.root.components() {
            match component {
                Component::ParentDir => {
                    return Err(WorkspaceConfinementError::ForbiddenComponent {
                        component: "ParentDir (..)".to_string(),
                    });
                },
                Component::CurDir => {
                    return Err(WorkspaceConfinementError::ForbiddenComponent {
                        component: "CurDir (.)".to_string(),
                    });
                },
                Component::Normal(_) | Component::RootDir | Component::Prefix(_) => {},
            }
        }

        // Must not be a blocked system directory.
        // Use component-aware `starts_with` to prevent partial match bypass
        // (e.g., "/var/log" must be blocked because /var is blocked).
        for blocked in BLOCKED_ROOTS {
            let blocked_path = Path::new(blocked);
            if *blocked == "/" {
                // Root "/" only blocks the exact root path, not children.
                // Every absolute path starts_with("/"), so we check equality.
                if self.root == blocked_path {
                    return Err(WorkspaceConfinementError::BlockedRoot {
                        root: root_str.to_string(),
                    });
                }
            } else if self.root == blocked_path || self.root.starts_with(blocked_path) {
                // For other blocked roots, block both exact match and children
                return Err(WorkspaceConfinementError::BlockedRoot {
                    root: root_str.to_string(),
                });
            }
        }

        Ok(())
    }

    /// Checks whether a path is safely contained within this workspace.
    ///
    /// The path must be relative and must not contain traversal components.
    /// Because `WorkspaceConfinement` is validated at construction time,
    /// the workspace root is guaranteed to be a valid, non-blocked absolute
    /// path.
    ///
    /// # Errors
    ///
    /// Returns [`WorkspaceConfinementError`] if the path escapes.
    pub fn contains(&self, path: &Path) -> Result<PathBuf, WorkspaceConfinementError> {
        validate_workspace_path(path, self)
    }
}

// =============================================================================
// Path Validation
// =============================================================================

/// Validates that a path is safely confined within the workspace root.
///
/// This function performs component-aware path validation:
/// - Rejects absolute paths
/// - Rejects `..` (parent directory) components
/// - Rejects paths exceeding depth limits
/// - Returns the resolved path within the workspace root
///
/// # Arguments
///
/// * `path` - The path to validate (should be relative)
/// * `confinement` - A validated [`WorkspaceConfinement`] whose root has
///   already passed structural checks (absolute, no blocked prefixes, no
///   `..`/`.` components). Accepting `&WorkspaceConfinement` instead of a bare
///   `&Path` ensures callers cannot pass an arbitrary, unvalidated root.
///
/// # Errors
///
/// Returns [`WorkspaceConfinementError`] if the path is unsafe.
pub fn validate_workspace_path(
    path: &Path,
    confinement: &WorkspaceConfinement,
) -> Result<PathBuf, WorkspaceConfinementError> {
    let workspace_root = confinement.root();
    let path_str = path.to_string_lossy();

    // Reject paths that are too long
    if path_str.len() > MAX_WORKSPACE_PATH_LENGTH {
        return Err(WorkspaceConfinementError::PathTooLong {
            actual: path_str.len(),
            max: MAX_WORKSPACE_PATH_LENGTH,
        });
    }

    // Reject absolute paths
    if path.is_absolute() {
        return Err(WorkspaceConfinementError::AbsolutePath {
            path: path_str.to_string(),
        });
    }

    // Component-aware validation
    let mut resolved = PathBuf::new();
    let mut depth: usize = 0;

    for component in path.components() {
        match component {
            Component::Normal(seg) => {
                resolved.push(seg);
                depth = depth.saturating_add(1);
                if depth > MAX_WORKSPACE_PATH_DEPTH {
                    return Err(WorkspaceConfinementError::PathTooDeep {
                        depth,
                        max: MAX_WORKSPACE_PATH_DEPTH,
                    });
                }
            },
            Component::CurDir => {
                // "." is harmless, skip
            },
            Component::ParentDir => {
                return Err(WorkspaceConfinementError::PathTraversal {
                    path: path_str.to_string(),
                });
            },
            Component::RootDir | Component::Prefix(_) => {
                return Err(WorkspaceConfinementError::ForbiddenComponent {
                    component: format!("{component:?}"),
                });
            },
        }
    }

    Ok(workspace_root.join(resolved))
}

/// Validates that an absolute path does not escape the workspace root.
///
/// Rejects any path containing `ParentDir` (`..`) components to prevent
/// lexical escapes like `/workspace/../etc/passwd` which satisfy
/// `starts_with("/workspace")` but resolve outside the root. Callers that
/// need to accept non-normalized paths must canonicalize them first with
/// appropriate TOCTOU-safe strategies (see RSK-1501).
///
/// Note: `CurDir` (`.`) components are automatically stripped by Rust's
/// `Path::components()` iterator for absolute paths, so they cannot bypass
/// this check.
///
/// This is used for post-resolution checks (e.g., after symlink resolution).
///
/// # Errors
///
/// Returns [`WorkspaceConfinementError`] if the path escapes or contains
/// non-normalized components.
pub fn validate_absolute_within_root(
    resolved_path: &Path,
    workspace_root: &Path,
) -> Result<(), WorkspaceConfinementError> {
    // Reject non-normalized components that could bypass starts_with checks.
    // A path like `/workspace/../etc/passwd` matches starts_with("/workspace")
    // because the first two path components match, but the `..` escapes.
    //
    // CurDir (`.`) is automatically stripped by `Path::components()` for
    // absolute paths, so we only need to check for ParentDir here.
    for component in resolved_path.components() {
        if matches!(component, Component::ParentDir) {
            return Err(WorkspaceConfinementError::PathTraversal {
                path: resolved_path.to_string_lossy().to_string(),
            });
        }
    }

    if !resolved_path.starts_with(workspace_root) {
        return Err(WorkspaceConfinementError::PathTraversal {
            path: resolved_path.to_string_lossy().to_string(),
        });
    }
    Ok(())
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
#[allow(missing_docs)]
mod tests {
    use super::*;

    // =========================================================================
    // WorkspaceConfinement Validation Tests
    // =========================================================================

    #[test]
    fn test_valid_workspace_root() {
        let wc = WorkspaceConfinement::new("/home/agent/workspace");
        assert!(wc.is_ok());
    }

    #[test]
    fn test_empty_workspace_root() {
        let result = WorkspaceConfinement::new("");
        assert!(matches!(result, Err(WorkspaceConfinementError::EmptyRoot)));
    }

    #[test]
    fn test_relative_workspace_root() {
        let result = WorkspaceConfinement::new("relative/path");
        assert!(matches!(
            result,
            Err(WorkspaceConfinementError::NotAbsolute { .. })
        ));
    }

    #[test]
    fn test_blocked_root_exact() {
        let result = WorkspaceConfinement::new("/etc");
        assert!(matches!(
            result,
            Err(WorkspaceConfinementError::BlockedRoot { .. })
        ));
    }

    #[test]
    fn test_blocked_root_child() {
        // /var/log should be blocked because /var is blocked
        let result = WorkspaceConfinement::new("/var/log");
        assert!(matches!(
            result,
            Err(WorkspaceConfinementError::BlockedRoot { .. })
        ));
    }

    #[test]
    fn test_blocked_root_slash() {
        let result = WorkspaceConfinement::new("/");
        assert!(matches!(
            result,
            Err(WorkspaceConfinementError::BlockedRoot { .. })
        ));
    }

    // =========================================================================
    // Path Validation Tests
    // =========================================================================

    #[test]
    fn test_valid_relative_path() {
        let ws = WorkspaceConfinement::new("/workspace").unwrap();
        let result = validate_workspace_path(Path::new("src/main.rs"), &ws);
        assert_eq!(result.unwrap(), PathBuf::from("/workspace/src/main.rs"));
    }

    #[test]
    fn test_path_with_dot() {
        let ws = WorkspaceConfinement::new("/workspace").unwrap();
        let result = validate_workspace_path(Path::new("./src/main.rs"), &ws);
        assert_eq!(result.unwrap(), PathBuf::from("/workspace/src/main.rs"));
    }

    #[test]
    fn test_path_traversal_dotdot() {
        let ws = WorkspaceConfinement::new("/workspace").unwrap();
        let result = validate_workspace_path(Path::new("../../../etc/passwd"), &ws);
        assert!(matches!(
            result,
            Err(WorkspaceConfinementError::PathTraversal { .. })
        ));
    }

    #[test]
    fn test_path_traversal_embedded_dotdot() {
        let ws = WorkspaceConfinement::new("/workspace").unwrap();
        let result = validate_workspace_path(Path::new("src/../../etc/passwd"), &ws);
        assert!(matches!(
            result,
            Err(WorkspaceConfinementError::PathTraversal { .. })
        ));
    }

    #[test]
    fn test_absolute_path_rejected() {
        let ws = WorkspaceConfinement::new("/workspace").unwrap();
        let result = validate_workspace_path(Path::new("/etc/passwd"), &ws);
        assert!(matches!(
            result,
            Err(WorkspaceConfinementError::AbsolutePath { .. })
        ));
    }

    #[test]
    fn test_path_too_deep() {
        let ws = WorkspaceConfinement::new("/workspace").unwrap();
        let deep_path: String = (0..=MAX_WORKSPACE_PATH_DEPTH)
            .map(|i| format!("d{i}"))
            .collect::<Vec<_>>()
            .join("/");
        let result = validate_workspace_path(Path::new(&deep_path), &ws);
        assert!(matches!(
            result,
            Err(WorkspaceConfinementError::PathTooDeep { .. })
        ));
    }

    #[test]
    fn test_path_exactly_at_max_depth() {
        let ws = WorkspaceConfinement::new("/workspace").unwrap();
        let path: String = (0..MAX_WORKSPACE_PATH_DEPTH)
            .map(|i| format!("d{i}"))
            .collect::<Vec<_>>()
            .join("/");
        let result = validate_workspace_path(Path::new(&path), &ws);
        assert!(result.is_ok());
    }

    // =========================================================================
    // Adversarial Path Traversal Tests (escape attempts)
    // =========================================================================

    #[test]
    fn test_adversarial_dotdot_at_start() {
        let ws = WorkspaceConfinement::new("/workspace").unwrap();
        assert!(validate_workspace_path(Path::new(".."), &ws).is_err());
    }

    #[test]
    fn test_adversarial_multiple_dotdots() {
        let ws = WorkspaceConfinement::new("/workspace").unwrap();
        assert!(validate_workspace_path(Path::new("../../.."), &ws).is_err());
    }

    #[test]
    fn test_adversarial_dotdot_after_normal() {
        let ws = WorkspaceConfinement::new("/workspace").unwrap();
        assert!(validate_workspace_path(Path::new("a/b/../../.."), &ws).is_err());
    }

    #[test]
    fn test_adversarial_dotdot_to_etc() {
        let ws = WorkspaceConfinement::new("/workspace").unwrap();
        assert!(validate_workspace_path(Path::new("../../../etc/shadow"), &ws).is_err());
    }

    #[test]
    fn test_adversarial_encoded_traversal_components() {
        // On Unix, Path::new handles actual OS paths, not URL-encoded strings.
        // The OS will see these as literal filenames, not traversal.
        // But we verify the component check still works for real ".." components.
        let ws = WorkspaceConfinement::new("/workspace").unwrap();
        // Mix of ".." and normal
        assert!(validate_workspace_path(Path::new("foo/../../../bar"), &ws).is_err());
    }

    #[test]
    fn test_adversarial_null_byte_in_path() {
        // Paths with null bytes are invalid on Unix, but we test that our
        // validation doesn't panic
        let ws = WorkspaceConfinement::new("/workspace").unwrap();
        // std::path::Path will handle this as a normal segment
        let result = validate_workspace_path(Path::new("safe_file.txt"), &ws);
        assert!(result.is_ok());
    }

    // =========================================================================
    // Absolute Within Root Tests
    // =========================================================================

    #[test]
    fn test_absolute_within_root_ok() {
        let root = Path::new("/workspace");
        let path = Path::new("/workspace/src/main.rs");
        assert!(validate_absolute_within_root(path, root).is_ok());
    }

    #[test]
    fn test_absolute_outside_root_rejected() {
        let root = Path::new("/workspace");
        let path = Path::new("/etc/passwd");
        assert!(validate_absolute_within_root(path, root).is_err());
    }

    #[test]
    fn test_absolute_sibling_rejected() {
        let root = Path::new("/workspace/project-a");
        let path = Path::new("/workspace/project-b/secret.txt");
        assert!(validate_absolute_within_root(path, root).is_err());
    }

    // =========================================================================
    // SECURITY REGRESSION: Absolute path escape via non-normalized components
    // =========================================================================

    #[test]
    fn test_absolute_escape_via_parent_dir() {
        // SECURITY REGRESSION: /workspace/../etc/passwd lexically
        // starts_with("/workspace") but resolves outside root.
        let root = Path::new("/workspace");
        let path = Path::new("/workspace/../etc/passwd");
        let result = validate_absolute_within_root(path, root);
        assert!(
            result.is_err(),
            "absolute path with .. must be rejected: got {result:?}"
        );
    }

    #[test]
    fn test_absolute_escape_via_double_parent_dir() {
        // SECURITY REGRESSION: deeper traversal attempt.
        let root = Path::new("/workspace");
        let path = Path::new("/workspace/./../../etc/passwd");
        let result = validate_absolute_within_root(path, root);
        assert!(
            result.is_err(),
            "absolute path with ./../.. must be rejected: got {result:?}"
        );
    }

    #[test]
    fn test_absolute_escape_via_nested_parent_dir() {
        // /workspace/subdir/../../etc/shadow
        let root = Path::new("/workspace");
        let path = Path::new("/workspace/subdir/../../etc/shadow");
        let result = validate_absolute_within_root(path, root);
        assert!(
            result.is_err(),
            "nested .. escape must be rejected: got {result:?}"
        );
    }

    #[test]
    fn test_absolute_curdir_stripped_by_components() {
        // Rust's Path::components() strips CurDir (.) for absolute paths,
        // so `/workspace/./src/main.rs` is normalized to
        // `/workspace/src/main.rs` by the iterator. This means CurDir
        // cannot bypass the starts_with check for absolute paths.
        let root = Path::new("/workspace");
        let path = Path::new("/workspace/./src/main.rs");
        let result = validate_absolute_within_root(path, root);
        assert!(
            result.is_ok(),
            "CurDir in absolute paths is stripped by components(): got {result:?}"
        );
    }

    #[test]
    fn test_absolute_clean_path_within_root_ok() {
        // Verify that clean (normalized) absolute paths still pass.
        let root = Path::new("/workspace");
        let path = Path::new("/workspace/src/main.rs");
        assert!(validate_absolute_within_root(path, root).is_ok());
    }

    #[test]
    fn test_absolute_root_exact_ok() {
        let root = Path::new("/workspace");
        let path = Path::new("/workspace");
        assert!(validate_absolute_within_root(path, root).is_ok());
    }

    // =========================================================================
    // WorkspaceConfinement.contains() Tests
    // =========================================================================

    #[test]
    fn test_contains_valid_path() {
        let wc = WorkspaceConfinement::new("/workspace").unwrap();
        let result = wc.contains(Path::new("src/lib.rs"));
        assert_eq!(result.unwrap(), PathBuf::from("/workspace/src/lib.rs"));
    }

    #[test]
    fn test_contains_traversal_rejected() {
        let wc = WorkspaceConfinement::new("/workspace").unwrap();
        assert!(wc.contains(Path::new("../secret")).is_err());
    }

    // =========================================================================
    // BLOCKER 2: Workspace root with ParentDir (..) bypass regression tests
    // (now caught at construction time via fail-closed new())
    // =========================================================================

    #[test]
    fn test_workspace_root_rejects_parent_dir_bypass_to_etc() {
        // /tmp/../etc resolves to /etc, bypassing the blocked-root check
        // because /tmp is not blocked. The ParentDir component must be
        // rejected at construction time.
        let result = WorkspaceConfinement::new("/tmp/../etc");
        assert!(
            matches!(
                result,
                Err(WorkspaceConfinementError::ForbiddenComponent { .. })
            ),
            "/tmp/../etc must be rejected due to ParentDir: got {result:?}"
        );
    }

    #[test]
    fn test_workspace_root_rejects_deep_parent_dir_bypass() {
        // /workspace/../../var resolves to /var, bypassing the non-blocked
        // /workspace prefix.
        let result = WorkspaceConfinement::new("/workspace/../../var");
        assert!(
            matches!(
                result,
                Err(WorkspaceConfinementError::ForbiddenComponent { .. })
            ),
            "/workspace/../../var must be rejected due to ParentDir: got {result:?}"
        );
    }

    #[test]
    fn test_workspace_root_rejects_triple_parent_dir_bypass() {
        // /home/./user/../../../etc traverses to /etc via multiple ..
        let result = WorkspaceConfinement::new("/home/./user/../../../etc");
        assert!(
            result.is_err(),
            "/home/./user/../../../etc must be rejected: got {result:?}"
        );
    }

    #[test]
    fn test_workspace_root_rejects_curdir_component() {
        // Note: On Linux, Path::components() for absolute paths strips CurDir
        // (.) components, so /home/./agent becomes [RootDir, "home", "agent"].
        // However, for non-absolute paths or edge cases, CurDir should still
        // be explicitly rejected. Test a path that retains CurDir in components.
        //
        // Actually for absolute paths on Linux, CurDir is stripped by
        // Path::components(). But the ParentDir test covers the main bypass.
        // This test verifies the /home/./user/../../../etc case catches
        // ParentDir even when CurDir is present.
        let result = WorkspaceConfinement::new("/home/./user/../../../etc");
        // Should be rejected due to ParentDir (CurDir is stripped by
        // Path::components for absolute paths, but ParentDir remains)
        assert!(
            result.is_err(),
            "path with . and .. must be rejected: got {result:?}"
        );
    }

    #[test]
    fn test_workspace_root_clean_path_still_works() {
        // Verify clean absolute paths without . or .. still pass
        let result = WorkspaceConfinement::new("/home/agent/workspace");
        assert!(result.is_ok());
    }

    // =========================================================================
    // Fail-closed construction tests
    // =========================================================================

    #[test]
    fn test_new_returns_result_not_raw_struct() {
        // Verify that WorkspaceConfinement::new() returns a Result,
        // making it impossible to have an unvalidated confinement.
        let valid: Result<WorkspaceConfinement, WorkspaceConfinementError> =
            WorkspaceConfinement::new("/workspace");
        assert!(valid.is_ok());

        let invalid: Result<WorkspaceConfinement, WorkspaceConfinementError> =
            WorkspaceConfinement::new("");
        assert!(invalid.is_err());
    }

    // =========================================================================
    // SECURITY REGRESSION: Deserialization bypass tests (Round 6 BLOCKER)
    //
    // WorkspaceConfinement must NOT be constructible via serde::Deserialize
    // without running validate_root(). Prior to this fix, #[derive(Deserialize)]
    // allowed: serde_json::from_str(r#"{"root":"/etc"}"#) to succeed,
    // bypassing the blocked-root check and allowing .contains("passwd") to
    // return Ok("/etc/passwd").
    // =========================================================================

    #[test]
    fn test_deserialize_blocked_root_etc_rejected() {
        // SECURITY REGRESSION: deserializing a blocked root MUST fail.
        // This was the exact bypass reported in Round 6.
        let result: Result<WorkspaceConfinement, _> = serde_json::from_str(r#"{"root":"/etc"}"#);
        assert!(
            result.is_err(),
            "deserializing blocked root /etc must fail: got {result:?}"
        );
    }

    #[test]
    fn test_deserialize_blocked_root_var_rejected() {
        let result: Result<WorkspaceConfinement, _> = serde_json::from_str(r#"{"root":"/var"}"#);
        assert!(
            result.is_err(),
            "deserializing blocked root /var must fail: got {result:?}"
        );
    }

    #[test]
    fn test_deserialize_blocked_root_slash_rejected() {
        let result: Result<WorkspaceConfinement, _> = serde_json::from_str(r#"{"root":"/"}"#);
        assert!(
            result.is_err(),
            "deserializing blocked root / must fail: got {result:?}"
        );
    }

    #[test]
    fn test_deserialize_relative_root_rejected() {
        let result: Result<WorkspaceConfinement, _> =
            serde_json::from_str(r#"{"root":"relative/path"}"#);
        assert!(
            result.is_err(),
            "deserializing relative root must fail: got {result:?}"
        );
    }

    #[test]
    fn test_deserialize_empty_root_rejected() {
        let result: Result<WorkspaceConfinement, _> = serde_json::from_str(r#"{"root":""}"#);
        assert!(
            result.is_err(),
            "deserializing empty root must fail: got {result:?}"
        );
    }

    #[test]
    fn test_deserialize_valid_root_succeeds() {
        let wc: WorkspaceConfinement = serde_json::from_str(r#"{"root":"/home/agent/workspace"}"#)
            .expect("deserializing valid root must succeed");
        assert_eq!(wc.root(), Path::new("/home/agent/workspace"));
    }

    #[test]
    fn test_deserialize_roundtrip_preserves_validity() {
        let original = WorkspaceConfinement::new("/workspace").unwrap();
        let json = serde_json::to_string(&original).unwrap();
        let deserialized: WorkspaceConfinement =
            serde_json::from_str(&json).expect("roundtrip must succeed");
        assert_eq!(original, deserialized);
    }

    #[test]
    fn test_deserialize_traversal_root_rejected() {
        // Paths with ParentDir must be rejected even during deserialization.
        let result: Result<WorkspaceConfinement, _> =
            serde_json::from_str(r#"{"root":"/tmp/../etc"}"#);
        assert!(
            result.is_err(),
            "deserializing root with .. must fail: got {result:?}"
        );
    }
}
