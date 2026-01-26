//! File path validation for ticket emission.
//!
//! This module provides:
//! - Path validation against the CCP file inventory
//! - Filesystem-based path existence checking
//! - Path normalization and traversal protection
//!
//! # Path Validation
//!
//! All file paths referenced in tickets are validated:
//! - `files_to_modify` must exist in CCP or on filesystem
//! - `files_to_create` must NOT exist (unless marked as extension point)
//! - Invalid paths cause validation failure (fail-closed)
//!
//! # Invariants
//!
//! - [INV-VALID-001] Path validation is deterministic
//! - [INV-VALID-002] Traversal attempts are rejected
//! - [INV-VALID-003] Validation errors are aggregated, not early-returned

use std::collections::HashSet;
use std::fs::{self, File};
use std::io::Read;
use std::path::Path;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, warn};

/// Maximum file size for CCP index (10 MB).
const MAX_CCP_INDEX_SIZE: u64 = 10 * 1024 * 1024;

/// Errors that can occur during ticket validation.
#[derive(Debug, Clone, Error)]
#[non_exhaustive]
pub enum TicketValidationError {
    /// A file that should exist does not.
    #[error("file does not exist: {path}")]
    FileNotFound {
        /// The missing file path.
        path: String,
        /// Ticket ID that references this path.
        ticket_id: String,
    },

    /// A file that should not exist already exists.
    #[error("file already exists (use extension point): {path}")]
    FileAlreadyExists {
        /// The existing file path.
        path: String,
        /// Ticket ID that references this path.
        ticket_id: String,
    },

    /// Path contains traversal attempt.
    #[error("path traversal detected: {path}")]
    PathTraversal {
        /// The offending path.
        path: String,
        /// Ticket ID that references this path.
        ticket_id: String,
    },

    /// Path is absolute (must be relative to repo root).
    #[error("absolute path not allowed: {path}")]
    AbsolutePath {
        /// The offending path.
        path: String,
        /// Ticket ID that references this path.
        ticket_id: String,
    },

    /// CCP index not found.
    #[error("CCP index not found: {path}")]
    CcpIndexNotFound {
        /// The missing path.
        path: String,
    },

    /// CCP index parse error.
    #[error("failed to parse CCP index: {reason}")]
    CcpIndexParseError {
        /// Reason for the failure.
        reason: String,
    },

    /// Multiple validation errors occurred.
    #[error("multiple validation errors: {}", format_errors(.errors))]
    Multiple {
        /// All validation errors.
        errors: Vec<Self>,
    },
}

/// Formats a list of errors for display.
fn format_errors(errors: &[TicketValidationError]) -> String {
    errors
        .iter()
        .map(std::string::ToString::to_string)
        .collect::<Vec<_>>()
        .join("; ")
}

/// A file reference from a ticket.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileReference {
    /// The file path.
    pub path: String,
    /// The ticket ID that references this file.
    pub ticket_id: String,
    /// Whether this is a file to create (true) or modify (false).
    pub is_create: bool,
}

/// Path validation result for ticket emission.
#[derive(Debug, Clone)]
pub struct TicketValidationResult {
    /// Files that were validated as existing.
    pub validated_existing: Vec<FileReference>,
    /// Files that were validated as new.
    pub validated_new: Vec<FileReference>,
    /// Validation errors (empty if all paths valid).
    pub errors: Vec<TicketValidationError>,
}

impl TicketValidationResult {
    /// Creates a new empty validation result.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            validated_existing: Vec::new(),
            validated_new: Vec::new(),
            errors: Vec::new(),
        }
    }

    /// Returns true if all paths validated successfully.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.errors.is_empty()
    }

    /// Converts validation errors into a single error.
    ///
    /// # Errors
    ///
    /// Returns `TicketValidationError::Multiple` if there are multiple errors,
    /// or the single error if there's only one.
    ///
    /// # Panics
    ///
    /// This function will not panic. The `expect` is safe because we verify
    /// `self.errors.len() == 1` before calling it.
    pub fn into_result(self) -> Result<(), TicketValidationError> {
        if self.errors.is_empty() {
            Ok(())
        } else if self.errors.len() == 1 {
            Err(self.errors.into_iter().next().expect("checked len == 1"))
        } else {
            Err(TicketValidationError::Multiple {
                errors: self.errors,
            })
        }
    }

    /// Merges another validation result into this one.
    pub fn merge(&mut self, other: Self) {
        self.validated_existing.extend(other.validated_existing);
        self.validated_new.extend(other.validated_new);
        self.errors.extend(other.errors);
    }
}

impl Default for TicketValidationResult {
    fn default() -> Self {
        Self::new()
    }
}

/// Validates a PRD ID against the strict project pattern.
///
/// PRD IDs must match the pattern `PRD-NNNN` (where N is a digit, minimum 4
/// digits). This prevents path traversal attacks (e.g., `PRD-../../../etc`).
fn validate_prd_id(prd_id: &str) -> Result<(), TicketValidationError> {
    // Strict pattern: PRD- followed by at least 4 digits
    let is_valid = prd_id.len() >= 8
        && prd_id.starts_with("PRD-")
        && prd_id[4..].chars().all(|c| c.is_ascii_digit())
        && prd_id.len() <= 12; // Reasonable upper bound: PRD-99999999

    if !is_valid {
        return Err(TicketValidationError::CcpIndexParseError {
            reason: format!("PRD ID must match pattern PRD-NNNN (e.g., PRD-0001), got: {prd_id}"),
        });
    }
    Ok(())
}

/// Loads the CCP file inventory.
fn load_ccp_inventory(
    repo_root: &Path,
    prd_id: &str,
) -> Result<HashSet<String>, TicketValidationError> {
    // Validate PRD ID to prevent path traversal
    validate_prd_id(prd_id)?;

    let ccp_index_path = repo_root
        .join("evidence")
        .join("prd")
        .join(prd_id)
        .join("ccp")
        .join("ccp_index.json");

    if !ccp_index_path.exists() {
        return Err(TicketValidationError::CcpIndexNotFound {
            path: ccp_index_path.display().to_string(),
        });
    }

    // Read with size limit
    let metadata =
        fs::metadata(&ccp_index_path).map_err(|e| TicketValidationError::CcpIndexParseError {
            reason: format!("Failed to read metadata: {e}"),
        })?;

    if metadata.len() > MAX_CCP_INDEX_SIZE {
        return Err(TicketValidationError::CcpIndexParseError {
            reason: format!(
                "CCP index too large: {} bytes (max {} bytes)",
                metadata.len(),
                MAX_CCP_INDEX_SIZE
            ),
        });
    }

    let file =
        File::open(&ccp_index_path).map_err(|e| TicketValidationError::CcpIndexParseError {
            reason: format!("Failed to open: {e}"),
        })?;

    let mut content = String::new();
    file.take(MAX_CCP_INDEX_SIZE)
        .read_to_string(&mut content)
        .map_err(|e| TicketValidationError::CcpIndexParseError {
            reason: format!("Failed to read: {e}"),
        })?;

    let ccp_index: serde_json::Value =
        serde_json::from_str(&content).map_err(|e| TicketValidationError::CcpIndexParseError {
            reason: format!("JSON parse error: {e}"),
        })?;

    // Extract file paths from inventory
    let mut paths = HashSet::new();

    if let Some(inventory) = ccp_index.get("file_inventory") {
        if let Some(files) = inventory.get("files") {
            if let Some(file_array) = files.as_array() {
                for file in file_array {
                    if let Some(path) = file.get("path").and_then(|v| v.as_str()) {
                        paths.insert(path.to_string());
                    }
                }
            }
        }
    }

    debug!(
        file_count = paths.len(),
        "Loaded CCP file inventory for validation"
    );

    Ok(paths)
}

/// Normalizes a path for comparison.
fn normalize_path(path: &str) -> String {
    path.trim_start_matches('/').replace('\\', "/")
}

/// Checks if a path contains traversal attempts.
fn contains_traversal(path: &str) -> bool {
    path.contains("..")
}

/// Checks if a path is absolute (not allowed in ticket file references).
fn is_absolute_path(path: &str) -> bool {
    Path::new(path).is_absolute()
}

/// Checks if a path exists in the repository.
fn path_exists_in_repo(repo_root: &Path, relative_path: &str) -> bool {
    if contains_traversal(relative_path) {
        return false;
    }

    let full_path = repo_root.join(relative_path);

    // Verify the resolved path is still within repo_root
    if let (Ok(canonical_root), Ok(canonical_path)) =
        (repo_root.canonicalize(), full_path.canonicalize())
    {
        canonical_path.starts_with(&canonical_root)
    } else {
        // If canonicalization fails, check if file exists
        full_path.exists()
    }
}

/// Validates file paths for a single ticket.
///
/// # Arguments
///
/// * `repo_root` - Path to the repository root
/// * `ticket_id` - The ticket being validated
/// * `files_to_modify` - Paths that must exist
/// * `files_to_create` - Paths that must NOT exist
/// * `ccp_inventory` - Set of paths in CCP (optional)
fn validate_ticket_file_paths(
    repo_root: &Path,
    ticket_id: &str,
    files_to_modify: &[String],
    files_to_create: &[String],
    ccp_inventory: Option<&HashSet<String>>,
) -> TicketValidationResult {
    let mut result = TicketValidationResult::new();

    // Validate files_to_modify (must exist)
    for path in files_to_modify {
        // Check for traversal
        if contains_traversal(path) {
            result.errors.push(TicketValidationError::PathTraversal {
                path: path.clone(),
                ticket_id: ticket_id.to_string(),
            });
            continue;
        }

        // Check for absolute path
        if is_absolute_path(path) {
            result.errors.push(TicketValidationError::AbsolutePath {
                path: path.clone(),
                ticket_id: ticket_id.to_string(),
            });
            continue;
        }

        let normalized = normalize_path(path);
        let exists_in_ccp = ccp_inventory.is_some_and(|inv| inv.contains(&normalized));
        let exists_in_repo = path_exists_in_repo(repo_root, &normalized);

        if exists_in_ccp || exists_in_repo {
            result.validated_existing.push(FileReference {
                path: path.clone(),
                ticket_id: ticket_id.to_string(),
                is_create: false,
            });
        } else {
            result.errors.push(TicketValidationError::FileNotFound {
                path: path.clone(),
                ticket_id: ticket_id.to_string(),
            });
        }
    }

    // Validate files_to_create (must NOT exist)
    for path in files_to_create {
        // Check for traversal
        if contains_traversal(path) {
            result.errors.push(TicketValidationError::PathTraversal {
                path: path.clone(),
                ticket_id: ticket_id.to_string(),
            });
            continue;
        }

        // Check for absolute path
        if is_absolute_path(path) {
            result.errors.push(TicketValidationError::AbsolutePath {
                path: path.clone(),
                ticket_id: ticket_id.to_string(),
            });
            continue;
        }

        let normalized = normalize_path(path);
        let exists_in_ccp = ccp_inventory.is_some_and(|inv| inv.contains(&normalized));
        let exists_in_repo = path_exists_in_repo(repo_root, &normalized);

        if exists_in_ccp || exists_in_repo {
            result
                .errors
                .push(TicketValidationError::FileAlreadyExists {
                    path: path.clone(),
                    ticket_id: ticket_id.to_string(),
                });
        } else {
            result.validated_new.push(FileReference {
                path: path.clone(),
                ticket_id: ticket_id.to_string(),
                is_create: true,
            });
        }
    }

    result
}

/// Validates all file paths across multiple tickets.
///
/// # Arguments
///
/// * `repo_root` - Path to the repository root
/// * `prd_id` - PRD identifier for CCP location (optional)
/// * `tickets` - List of (`ticket_id`, `files_to_modify`, `files_to_create`)
///   tuples
///
/// # Returns
///
/// A validation result containing any errors found.
///
/// # Errors
///
/// Returns a `TicketValidationError` if CCP cannot be loaded when `prd_id` is
/// provided.
pub fn validate_ticket_paths(
    repo_root: &Path,
    prd_id: Option<&str>,
    tickets: &[(&str, Vec<String>, Vec<String>)],
) -> Result<TicketValidationResult, TicketValidationError> {
    // Load CCP inventory if PRD ID provided
    let ccp_inventory = if let Some(prd_id) = prd_id {
        match load_ccp_inventory(repo_root, prd_id) {
            Ok(inv) => Some(inv),
            Err(TicketValidationError::CcpIndexNotFound { .. }) => {
                warn!(prd_id = %prd_id, "CCP index not found, falling back to filesystem validation");
                None
            },
            Err(e) => return Err(e),
        }
    } else {
        None
    };

    let mut combined_result = TicketValidationResult::new();

    for (ticket_id, files_to_modify, files_to_create) in tickets {
        let result = validate_ticket_file_paths(
            repo_root,
            ticket_id,
            files_to_modify,
            files_to_create,
            ccp_inventory.as_ref(),
        );
        combined_result.merge(result);
    }

    Ok(combined_result)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::*;

    /// Creates test CCP index.
    fn create_test_ccp_index(root: &Path) {
        let ccp_dir = root.join("evidence/prd/PRD-0001/ccp");
        fs::create_dir_all(&ccp_dir).unwrap();

        fs::write(
            ccp_dir.join("ccp_index.json"),
            r#"{
                "schema_version": "2026-01-26",
                "index_hash": "abc1234567890",
                "file_inventory": {
                    "file_count": 3,
                    "files": [
                        {"path": "crates/apm2-core/src/lib.rs", "hash": "aaa", "size": 100},
                        {"path": "crates/apm2-cli/src/main.rs", "hash": "bbb", "size": 200},
                        {"path": "crates/apm2-core/src/ccp/mod.rs", "hash": "ccc", "size": 150}
                    ]
                }
            }"#,
        )
        .unwrap();
    }

    /// UT-116-03: Test file path validation against CCP.
    #[test]
    fn test_validation_existing_file() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();
        create_test_ccp_index(root);

        let tickets = vec![(
            "TCK-00001",
            vec!["crates/apm2-core/src/lib.rs".to_string()],
            vec![],
        )];

        let result = validate_ticket_paths(root, Some("PRD-0001"), &tickets).unwrap();

        assert!(result.is_valid(), "Should validate existing file");
        assert_eq!(result.validated_existing.len(), 1);
    }

    /// UT-116-03: Test validation of missing file.
    #[test]
    fn test_validation_missing_file() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();
        create_test_ccp_index(root);

        let tickets = vec![(
            "TCK-00001",
            vec!["crates/nonexistent/file.rs".to_string()],
            vec![],
        )];

        let result = validate_ticket_paths(root, Some("PRD-0001"), &tickets).unwrap();

        assert!(!result.is_valid(), "Should fail for missing file");
        assert!(matches!(
            &result.errors[0],
            TicketValidationError::FileNotFound { path, ticket_id }
            if path.contains("nonexistent") && ticket_id == "TCK-00001"
        ));
    }

    /// UT-116-03: Test validation of file already exists.
    #[test]
    fn test_validation_file_already_exists() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();
        create_test_ccp_index(root);

        let tickets = vec![(
            "TCK-00001",
            vec![],
            vec!["crates/apm2-core/src/lib.rs".to_string()],
        )];

        let result = validate_ticket_paths(root, Some("PRD-0001"), &tickets).unwrap();

        assert!(!result.is_valid(), "Should fail for existing file");
        assert!(matches!(
            &result.errors[0],
            TicketValidationError::FileAlreadyExists { .. }
        ));
    }

    /// UT-116-03: Test validation of new files.
    #[test]
    fn test_validation_new_files() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();
        create_test_ccp_index(root);

        let tickets = vec![(
            "TCK-00001",
            vec![],
            vec!["crates/apm2-core/src/ticket_emitter/mod.rs".to_string()],
        )];

        let result = validate_ticket_paths(root, Some("PRD-0001"), &tickets).unwrap();

        assert!(result.is_valid(), "Should validate new file path");
        assert_eq!(result.validated_new.len(), 1);
    }

    /// Test path traversal rejection.
    #[test]
    fn test_validation_rejects_traversal() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();
        create_test_ccp_index(root);

        let tickets = vec![("TCK-00001", vec!["../../../etc/passwd".to_string()], vec![])];

        let result = validate_ticket_paths(root, Some("PRD-0001"), &tickets).unwrap();

        assert!(!result.is_valid());
        assert!(matches!(
            &result.errors[0],
            TicketValidationError::PathTraversal { .. }
        ));
    }

    /// Test absolute path rejection in `files_to_modify`.
    #[test]
    fn test_validation_rejects_absolute_path_modify() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();
        create_test_ccp_index(root);

        let tickets = vec![("TCK-00001", vec!["/etc/passwd".to_string()], vec![])];

        let result = validate_ticket_paths(root, Some("PRD-0001"), &tickets).unwrap();

        assert!(!result.is_valid());
        assert!(matches!(
            &result.errors[0],
            TicketValidationError::AbsolutePath { path, ticket_id }
            if path == "/etc/passwd" && ticket_id == "TCK-00001"
        ));
    }

    /// Test absolute path rejection in `files_to_create`.
    #[test]
    fn test_validation_rejects_absolute_path_create() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();
        create_test_ccp_index(root);

        let tickets = vec![("TCK-00001", vec![], vec!["/tmp/malicious.rs".to_string()])];

        let result = validate_ticket_paths(root, Some("PRD-0001"), &tickets).unwrap();

        assert!(!result.is_valid());
        assert!(matches!(
            &result.errors[0],
            TicketValidationError::AbsolutePath { path, ticket_id }
            if path == "/tmp/malicious.rs" && ticket_id == "TCK-00001"
        ));
    }

    /// Test multiple tickets validation.
    #[test]
    fn test_validation_multiple_tickets() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();
        create_test_ccp_index(root);

        let tickets = vec![
            (
                "TCK-00001",
                vec!["crates/apm2-core/src/lib.rs".to_string()],
                vec!["crates/apm2-core/src/new_module/mod.rs".to_string()],
            ),
            (
                "TCK-00002",
                vec!["crates/apm2-cli/src/main.rs".to_string()],
                vec!["crates/apm2-cli/src/commands/factory/tickets.rs".to_string()],
            ),
        ];

        let result = validate_ticket_paths(root, Some("PRD-0001"), &tickets).unwrap();

        assert!(result.is_valid());
        assert_eq!(result.validated_existing.len(), 2);
        assert_eq!(result.validated_new.len(), 2);
    }

    /// Test validation without CCP (filesystem only).
    #[test]
    fn test_validation_without_ccp() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();

        // Create actual files on filesystem
        let src_dir = root.join("crates/apm2-core/src");
        fs::create_dir_all(&src_dir).unwrap();
        fs::write(src_dir.join("lib.rs"), "// lib").unwrap();

        let tickets = vec![(
            "TCK-00001",
            vec!["crates/apm2-core/src/lib.rs".to_string()],
            vec!["crates/apm2-core/src/new_module/mod.rs".to_string()],
        )];

        // No PRD ID means no CCP lookup
        let result = validate_ticket_paths(root, None, &tickets).unwrap();

        assert!(result.is_valid());
        assert_eq!(result.validated_existing.len(), 1);
        assert_eq!(result.validated_new.len(), 1);
    }

    /// Test multiple validation errors.
    #[test]
    fn test_multiple_validation_errors() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();
        create_test_ccp_index(root);

        let tickets = vec![(
            "TCK-00001",
            vec!["missing1.rs".to_string(), "missing2.rs".to_string()],
            vec![],
        )];

        let result = validate_ticket_paths(root, Some("PRD-0001"), &tickets).unwrap();

        assert!(!result.is_valid());
        assert_eq!(result.errors.len(), 2);

        let err = result.into_result().unwrap_err();
        assert!(matches!(
            err,
            TicketValidationError::Multiple { errors } if errors.len() == 2
        ));
    }

    /// Test `ValidationResult` merge.
    #[test]
    fn test_validation_result_merge() {
        let mut result1 = TicketValidationResult::new();
        result1.validated_existing.push(FileReference {
            path: "file1.rs".to_string(),
            ticket_id: "TCK-00001".to_string(),
            is_create: false,
        });

        let mut result2 = TicketValidationResult::new();
        result2.validated_new.push(FileReference {
            path: "file2.rs".to_string(),
            ticket_id: "TCK-00002".to_string(),
            is_create: true,
        });

        result1.merge(result2);

        assert_eq!(result1.validated_existing.len(), 1);
        assert_eq!(result1.validated_new.len(), 1);
    }

    /// Test PRD ID validation rejects path traversal.
    ///
    /// This prevents an attacker from reading arbitrary `ccp_index.json` files
    /// via malicious PRD IDs like `PRD-../../../etc`.
    #[test]
    fn test_prd_id_validation_rejects_traversal() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();

        let tickets = vec![("TCK-00001", vec!["some/file.rs".to_string()], vec![])];

        // Path traversal attempt
        let result = validate_ticket_paths(root, Some("PRD-../../../etc"), &tickets);
        assert!(result.is_err(), "Should reject PRD ID with path traversal");
        assert!(
            matches!(result, Err(TicketValidationError::CcpIndexParseError { reason }) if reason.contains("PRD ID must match pattern")),
            "Error should indicate invalid PRD ID pattern"
        );

        // Shell injection
        let result = validate_ticket_paths(root, Some("PRD-0001;ls"), &tickets);
        assert!(
            result.is_err(),
            "Should reject PRD ID with shell metacharacter"
        );

        // Too few digits
        let result = validate_ticket_paths(root, Some("PRD-001"), &tickets);
        assert!(
            result.is_err(),
            "Should reject PRD ID with fewer than 4 digits"
        );

        // Invalid format (letters)
        let result = validate_ticket_paths(root, Some("PRD-TEST"), &tickets);
        assert!(result.is_err(), "Should reject PRD ID with letters");
    }

    /// Test that valid PRD IDs are accepted (though CCP may not exist).
    #[test]
    fn test_prd_id_validation_accepts_valid() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();

        let tickets = vec![("TCK-00001", vec![], vec!["new/file.rs".to_string()])];

        // Valid PRD ID - should not fail on ID validation
        // (may fail on CCP not found, but that's a different error)
        let result = validate_ticket_paths(root, Some("PRD-0001"), &tickets);
        // If it fails, it should be CcpIndexNotFound, not a parse error
        if let Err(e) = &result {
            assert!(
                matches!(e, TicketValidationError::CcpIndexNotFound { .. }),
                "Valid PRD ID should not cause parse error, got: {e:?}"
            );
        }

        // Valid PRD ID with more digits
        let result = validate_ticket_paths(root, Some("PRD-99999999"), &tickets);
        if let Err(e) = &result {
            assert!(
                matches!(e, TicketValidationError::CcpIndexNotFound { .. }),
                "Valid PRD ID should not cause parse error, got: {e:?}"
            );
        }
    }
}
