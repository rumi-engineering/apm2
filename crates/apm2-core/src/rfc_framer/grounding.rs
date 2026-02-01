#![allow(clippy::disallowed_methods)] // Metadata/observability usage or adapter.
//! CCP grounding section generation and path validation.
//!
//! This module provides:
//! - CCP grounding data structure for RFC metadata
//! - Path validation against the CCP file inventory
//! - Component reference extraction from Impact Map
//!
//! # Path Validation
//!
//! All file paths referenced in an RFC are validated against the CCP:
//! - `files_to_modify` must exist in CCP file inventory
//! - `files_to_create` must NOT exist (unless marked as extending)
//! - Invalid paths fail the compilation (fail-closed)
//!
//! # Invariants
//!
//! - [INV-GROUND-001] CCP index hash is computed from the index file content
//! - [INV-GROUND-002] Path validation is deterministic
//! - [INV-GROUND-003] Component references are sorted for reproducibility

use std::collections::HashSet;
use std::fs::{self, File};
use std::io::Read;
use std::path::Path;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, warn};

/// Maximum file size for CCP index (10 MB).
const MAX_CCP_INDEX_SIZE: u64 = 10 * 1024 * 1024;

/// Errors that can occur during grounding operations.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum GroundingError {
    /// Failed to read a file.
    #[error("failed to read file {path}: {reason}")]
    ReadError {
        /// Path to the file that failed to read.
        path: String,
        /// Reason for the failure.
        reason: String,
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

    /// Impact map not found.
    #[error("impact map not found: {path}")]
    ImpactMapNotFound {
        /// The missing path.
        path: String,
    },

    /// Impact map parse error.
    #[error("failed to parse impact map: {reason}")]
    ImpactMapParseError {
        /// Reason for the failure.
        reason: String,
    },

    /// Path validation failed.
    #[error("path validation failed: {0}")]
    PathValidation(#[from] PathValidationError),

    /// Path traversal attempt detected.
    #[error("path traversal detected: {path} - {reason}")]
    PathTraversalError {
        /// The path that attempted traversal.
        path: String,
        /// Reason for the failure.
        reason: String,
    },

    /// File is too large to read.
    #[error("file {path} is too large ({size} bytes, max {max_size} bytes)")]
    FileTooLarge {
        /// Path to the file.
        path: String,
        /// Actual file size.
        size: u64,
        /// Maximum allowed size.
        max_size: u64,
    },
}

/// Errors that can occur during path validation.
#[derive(Debug, Clone, Error)]
#[non_exhaustive]
pub enum PathValidationError {
    /// A file that should exist does not.
    #[error("file does not exist in CCP: {path}")]
    FileNotFound {
        /// The missing file path.
        path: String,
    },

    /// A file that should not exist already exists.
    #[error("file already exists in CCP (use extension point): {path}")]
    FileAlreadyExists {
        /// The existing file path.
        path: String,
    },

    /// Multiple validation errors occurred.
    #[error("multiple path validation errors: {}", .errors.iter().map(std::string::ToString::to_string).collect::<Vec<_>>().join("; "))]
    Multiple {
        /// All validation errors.
        errors: Vec<Self>,
    },
}

/// A reference to a CCP component in the grounding section.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentReference {
    /// Component ID (e.g., "COMP-CORE").
    pub id: String,
    /// Reference path in the component atlas.
    pub r#ref: String,
    /// Rationale for why this component is affected.
    pub rationale: String,
}

/// CCP grounding section for RFC metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CcpGrounding {
    /// Path to the CCP index file.
    pub ccp_index_ref: String,
    /// BLAKE3 hash of the CCP index (first 7 hex chars for brevity).
    pub ccp_index_hash: String,
    /// Path to the impact map file.
    pub impact_map_ref: String,
    /// Rationale for the grounding.
    pub rationale: String,
    /// Component references extracted from Impact Map.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub component_references: Vec<ComponentReference>,
    /// Timestamp when grounding was computed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grounded_at: Option<DateTime<Utc>>,
}

impl CcpGrounding {
    /// Creates a new CCP grounding from the CCP index and Impact Map.
    ///
    /// # Arguments
    ///
    /// * `repo_root` - Path to the repository root
    /// * `prd_id` - PRD identifier
    ///
    /// # Errors
    ///
    /// Returns an error if the CCP index or Impact Map cannot be read.
    pub fn from_artifacts(repo_root: &Path, prd_id: &str) -> Result<Self, GroundingError> {
        // Validate PRD ID
        validate_id(prd_id)?;

        let ccp_index_path = repo_root
            .join("evidence")
            .join("prd")
            .join(prd_id)
            .join("ccp")
            .join("ccp_index.json");

        let impact_map_path = repo_root
            .join("evidence")
            .join("prd")
            .join(prd_id)
            .join("impact_map")
            .join("impact_map.yaml");

        // Read and hash CCP index
        if !ccp_index_path.exists() {
            return Err(GroundingError::CcpIndexNotFound {
                path: ccp_index_path.display().to_string(),
            });
        }

        let ccp_content = read_file_bounded(&ccp_index_path, MAX_CCP_INDEX_SIZE)?;
        let ccp_hash = blake3::hash(ccp_content.as_bytes());
        let ccp_index_hash = ccp_hash.to_hex()[..7].to_string();

        // Check impact map exists
        if !impact_map_path.exists() {
            return Err(GroundingError::ImpactMapNotFound {
                path: impact_map_path.display().to_string(),
            });
        }

        // Extract component references from impact map
        let component_references = extract_component_references(repo_root, prd_id)?;

        // Build relative paths for output
        let ccp_index_ref = format!("evidence/prd/{prd_id}/ccp/ccp_index.json");
        let impact_map_ref = format!("evidence/prd/{prd_id}/impact_map/impact_map.yaml");

        Ok(Self {
            ccp_index_ref,
            ccp_index_hash,
            impact_map_ref,
            rationale: format!("RFC is grounded in CCP artifacts generated for {prd_id}"),
            component_references,
            grounded_at: Some(Utc::now()),
        })
    }
}

/// Validates an ID (PRD, RFC, etc.) for path traversal attacks.
fn validate_id(id: &str) -> Result<(), GroundingError> {
    if id.contains('/') || id.contains('\\') || id.contains("..") {
        return Err(GroundingError::PathTraversalError {
            path: id.to_string(),
            reason: "ID contains invalid characters".to_string(),
        });
    }
    Ok(())
}

/// Reads a file with size limits.
fn read_file_bounded(path: &Path, max_size: u64) -> Result<String, GroundingError> {
    let metadata = fs::metadata(path).map_err(|e| GroundingError::ReadError {
        path: path.display().to_string(),
        reason: e.to_string(),
    })?;

    let size = metadata.len();
    if size > max_size {
        return Err(GroundingError::FileTooLarge {
            path: path.display().to_string(),
            size,
            max_size,
        });
    }

    let file = File::open(path).map_err(|e| GroundingError::ReadError {
        path: path.display().to_string(),
        reason: e.to_string(),
    })?;

    let mut content = String::new();
    file.take(max_size)
        .read_to_string(&mut content)
        .map_err(|e| GroundingError::ReadError {
            path: path.display().to_string(),
            reason: e.to_string(),
        })?;

    Ok(content)
}

/// Extracts component references from the Impact Map.
fn extract_component_references(
    repo_root: &Path,
    prd_id: &str,
) -> Result<Vec<ComponentReference>, GroundingError> {
    let impact_map_path = repo_root
        .join("evidence")
        .join("prd")
        .join(prd_id)
        .join("impact_map")
        .join("impact_map.yaml");

    let content = read_file_bounded(&impact_map_path, MAX_CCP_INDEX_SIZE)?;

    let impact_map: serde_yaml::Value =
        serde_yaml::from_str(&content).map_err(|e| GroundingError::ImpactMapParseError {
            reason: e.to_string(),
        })?;

    let mut seen_components: HashSet<String> = HashSet::new();
    let mut references = Vec::new();

    // Extract unique components from requirement mappings
    if let Some(mappings) = impact_map.get("requirement_mappings") {
        if let Some(mapping_array) = mappings.as_sequence() {
            for mapping in mapping_array {
                if let Some(candidates) = mapping.get("candidates") {
                    if let Some(candidate_array) = candidates.as_sequence() {
                        for candidate in candidate_array {
                            let component_id = candidate
                                .get("component_id")
                                .and_then(|v| v.as_str())
                                .unwrap_or("");

                            if !component_id.is_empty() && !seen_components.contains(component_id) {
                                seen_components.insert(component_id.to_string());

                                let component_name = candidate
                                    .get("component_name")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or(component_id);

                                let rationale = candidate
                                    .get("rationale")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("Matched via impact map");

                                references.push(ComponentReference {
                                    id: component_id.to_string(),
                                    r#ref: format!(
                                        "evidence/prd/{prd_id}/ccp/component_atlas.yaml#component_atlas.components[id={component_id}]"
                                    ),
                                    rationale: format!("{component_name} ({rationale})"),
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    // Sort for determinism
    references.sort_by(|a, b| a.id.cmp(&b.id));

    if references.is_empty() {
        warn!("No component references extracted from impact map");
    }

    Ok(references)
}

/// Path validation result for RFC framing.
#[derive(Debug, Clone)]
pub struct PathValidationResult {
    /// Files that were validated as existing.
    pub validated_existing: Vec<String>,
    /// Files that were validated as new.
    pub validated_new: Vec<String>,
    /// Validation errors (empty if all paths valid).
    pub errors: Vec<PathValidationError>,
}

impl PathValidationResult {
    /// Returns true if all paths validated successfully.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.errors.is_empty()
    }

    /// Converts validation errors into a single error.
    ///
    /// # Errors
    ///
    /// Returns `PathValidationError::Multiple` if there are any errors.
    ///
    /// # Panics
    ///
    /// This function will not panic. The `unwrap` is safe because we check
    /// `self.errors.len() == 1` before calling it.
    pub fn into_result(self) -> Result<(), PathValidationError> {
        if self.errors.is_empty() {
            Ok(())
        } else if self.errors.len() == 1 {
            // SAFETY: We just checked that there is exactly one error
            Err(self.errors.into_iter().next().expect("checked len == 1"))
        } else {
            Err(PathValidationError::Multiple {
                errors: self.errors,
            })
        }
    }
}

/// Validates file paths against the CCP file inventory.
///
/// # Arguments
///
/// * `repo_root` - Path to the repository root
/// * `prd_id` - PRD identifier for CCP location
/// * `files_to_modify` - Paths that must exist in CCP
/// * `files_to_create` - Paths that must NOT exist in CCP
///
/// # Returns
///
/// A validation result containing any errors found.
///
/// # Errors
///
/// Returns a `GroundingError` if the CCP index cannot be read.
pub fn validate_paths(
    repo_root: &Path,
    prd_id: &str,
    files_to_modify: &[String],
    files_to_create: &[String],
) -> Result<PathValidationResult, GroundingError> {
    // Validate PRD ID
    validate_id(prd_id)?;

    // Load CCP file inventory
    let ccp_index_path = repo_root
        .join("evidence")
        .join("prd")
        .join(prd_id)
        .join("ccp")
        .join("ccp_index.json");

    if !ccp_index_path.exists() {
        return Err(GroundingError::CcpIndexNotFound {
            path: ccp_index_path.display().to_string(),
        });
    }

    let ccp_content = read_file_bounded(&ccp_index_path, MAX_CCP_INDEX_SIZE)?;

    let ccp_index: serde_json::Value =
        serde_json::from_str(&ccp_content).map_err(|e| GroundingError::CcpIndexParseError {
            reason: e.to_string(),
        })?;

    // Build set of existing paths from file_inventory
    let mut existing_paths: HashSet<String> = HashSet::new();

    if let Some(inventory) = ccp_index.get("file_inventory") {
        if let Some(files) = inventory.get("files") {
            if let Some(file_array) = files.as_array() {
                for file in file_array {
                    if let Some(path) = file.get("path").and_then(|v| v.as_str()) {
                        existing_paths.insert(path.to_string());
                    }
                }
            }
        }
    }

    debug!(
        file_count = existing_paths.len(),
        "Loaded CCP file inventory"
    );

    let mut result = PathValidationResult {
        validated_existing: Vec::new(),
        validated_new: Vec::new(),
        errors: Vec::new(),
    };

    // Validate files_to_modify (must exist)
    for path in files_to_modify {
        // Normalize path for comparison
        let normalized = normalize_path(path);

        if existing_paths.contains(&normalized) || path_exists_in_repo(repo_root, &normalized) {
            result.validated_existing.push(path.clone());
        } else {
            result
                .errors
                .push(PathValidationError::FileNotFound { path: path.clone() });
        }
    }

    // Validate files_to_create (must NOT exist)
    for path in files_to_create {
        let normalized = normalize_path(path);

        if existing_paths.contains(&normalized) || path_exists_in_repo(repo_root, &normalized) {
            result
                .errors
                .push(PathValidationError::FileAlreadyExists { path: path.clone() });
        } else {
            result.validated_new.push(path.clone());
        }
    }

    Ok(result)
}

/// Normalizes a path for comparison.
fn normalize_path(path: &str) -> String {
    // Remove leading slashes and normalize separators
    path.trim_start_matches('/').replace('\\', "/")
}

/// Checks if a path exists in the repository.
fn path_exists_in_repo(repo_root: &Path, relative_path: &str) -> bool {
    // Prevent path traversal
    if relative_path.contains("..") {
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

/// Builds a set of files from RFC ticket decomposition.
///
/// Extracts `files_to_create` and `files_to_modify` from RFC data.
#[derive(Debug, Clone, Default)]
pub struct RfcFileReferences {
    /// Files that will be created.
    pub files_to_create: Vec<String>,
    /// Files that will be modified.
    pub files_to_modify: Vec<String>,
}

impl RfcFileReferences {
    /// Extracts file references from RFC ticket decomposition YAML.
    #[must_use]
    pub fn from_yaml(yaml: &serde_yaml::Value) -> Self {
        let mut refs = Self::default();

        // Look for tickets array
        if let Some(tickets) = yaml.get("tickets") {
            if let Some(ticket_array) = tickets.as_sequence() {
                for ticket in ticket_array {
                    // Extract files_to_create
                    if let Some(files) = ticket.get("files_to_create") {
                        if let Some(file_array) = files.as_sequence() {
                            for file in file_array {
                                if let Some(path) = file.as_str() {
                                    refs.files_to_create.push(path.to_string());
                                } else if let Some(path) = file.get("path").and_then(|v| v.as_str())
                                {
                                    refs.files_to_create.push(path.to_string());
                                }
                            }
                        }
                    }

                    // Extract files_to_modify
                    if let Some(files) = ticket.get("files_to_modify") {
                        if let Some(file_array) = files.as_sequence() {
                            for file in file_array {
                                if let Some(path) = file.as_str() {
                                    refs.files_to_modify.push(path.to_string());
                                } else if let Some(path) = file.get("path").and_then(|v| v.as_str())
                                {
                                    refs.files_to_modify.push(path.to_string());
                                }
                            }
                        }
                    }
                }
            }
        }

        // Deduplicate
        refs.files_to_create.sort();
        refs.files_to_create.dedup();
        refs.files_to_modify.sort();
        refs.files_to_modify.dedup();

        refs
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::*;

    /// Creates test CCP index and impact map.
    fn create_test_artifacts(root: &Path) {
        let ccp_dir = root.join("evidence/prd/PRD-TEST/ccp");
        fs::create_dir_all(&ccp_dir).unwrap();

        let impact_map_dir = root.join("evidence/prd/PRD-TEST/impact_map");
        fs::create_dir_all(&impact_map_dir).unwrap();

        // Create CCP index
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

        // Create impact map
        fs::write(
            impact_map_dir.join("impact_map.yaml"),
            r#"schema_version: "2026-01-26"
prd_id: PRD-TEST
requirement_mappings:
  - requirement_id: REQ-0001
    candidates:
      - component_id: COMP-CLI
        component_name: apm2-cli
        rationale: "CLI entrypoint"
      - component_id: COMP-CORE
        component_name: apm2-core
        rationale: "Core library"
  - requirement_id: REQ-0002
    candidates:
      - component_id: COMP-CORE
        component_name: apm2-core
        rationale: "CCP module"
"#,
        )
        .unwrap();
    }

    /// UT-115-03: Test CCP grounding section generation.
    #[test]
    fn test_ccp_grounding_from_artifacts() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();
        create_test_artifacts(root);

        let grounding = CcpGrounding::from_artifacts(root, "PRD-TEST").unwrap();

        // Verify structure
        assert_eq!(
            grounding.ccp_index_ref,
            "evidence/prd/PRD-TEST/ccp/ccp_index.json"
        );
        assert_eq!(
            grounding.impact_map_ref,
            "evidence/prd/PRD-TEST/impact_map/impact_map.yaml"
        );
        assert!(!grounding.ccp_index_hash.is_empty());
        assert_eq!(grounding.ccp_index_hash.len(), 7); // First 7 hex chars

        // Verify component references extracted
        assert!(!grounding.component_references.is_empty());
        let comp_ids: Vec<_> = grounding
            .component_references
            .iter()
            .map(|c| c.id.as_str())
            .collect();
        assert!(comp_ids.contains(&"COMP-CLI"));
        assert!(comp_ids.contains(&"COMP-CORE"));

        // Components should be sorted
        let mut sorted_ids = comp_ids.clone();
        sorted_ids.sort_unstable();
        assert_eq!(
            comp_ids, sorted_ids,
            "Component references should be sorted"
        );
    }

    /// UT-115-04: Test path validation against CCP.
    #[test]
    fn test_path_validation_existing() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();
        create_test_artifacts(root);

        let files_to_modify = vec!["crates/apm2-core/src/lib.rs".to_string()];
        let files_to_create: Vec<String> = vec![];

        let result = validate_paths(root, "PRD-TEST", &files_to_modify, &files_to_create).unwrap();

        assert!(result.is_valid(), "Should validate existing file");
        assert_eq!(result.validated_existing.len(), 1);
    }

    /// UT-115-05: Test invalid path rejection.
    #[test]
    fn test_path_validation_missing_file() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();
        create_test_artifacts(root);

        let files_to_modify = vec!["crates/nonexistent/file.rs".to_string()];
        let files_to_create: Vec<String> = vec![];

        let result = validate_paths(root, "PRD-TEST", &files_to_modify, &files_to_create).unwrap();

        assert!(!result.is_valid(), "Should fail for missing file");
        assert_eq!(result.errors.len(), 1);
        assert!(matches!(
            &result.errors[0],
            PathValidationError::FileNotFound { path } if path.contains("nonexistent")
        ));
    }

    /// UT-115-05: Test file already exists rejection.
    #[test]
    fn test_path_validation_file_exists() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();
        create_test_artifacts(root);

        let files_to_modify: Vec<String> = vec![];
        let files_to_create = vec!["crates/apm2-core/src/lib.rs".to_string()];

        let result = validate_paths(root, "PRD-TEST", &files_to_modify, &files_to_create).unwrap();

        assert!(
            !result.is_valid(),
            "Should fail for existing file in files_to_create"
        );
        assert!(matches!(
            &result.errors[0],
            PathValidationError::FileAlreadyExists { .. }
        ));
    }

    /// Test path validation with new files.
    #[test]
    fn test_path_validation_new_files() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();
        create_test_artifacts(root);

        let files_to_modify: Vec<String> = vec![];
        let files_to_create = vec!["crates/apm2-core/src/rfc_framer/mod.rs".to_string()];

        let result = validate_paths(root, "PRD-TEST", &files_to_modify, &files_to_create).unwrap();

        assert!(result.is_valid(), "Should validate new file path");
        assert_eq!(result.validated_new.len(), 1);
    }

    /// Test CCP index not found error.
    #[test]
    fn test_grounding_ccp_not_found() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();

        let result = CcpGrounding::from_artifacts(root, "PRD-NONEXISTENT");
        assert!(matches!(
            result,
            Err(GroundingError::CcpIndexNotFound { .. })
        ));
    }

    /// Test impact map not found error.
    #[test]
    fn test_grounding_impact_map_not_found() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();

        // Create only CCP index, not impact map
        let ccp_dir = root.join("evidence/prd/PRD-TEST/ccp");
        fs::create_dir_all(&ccp_dir).unwrap();
        fs::write(ccp_dir.join("ccp_index.json"), r#"{"index_hash": "test"}"#).unwrap();

        let result = CcpGrounding::from_artifacts(root, "PRD-TEST");
        assert!(matches!(
            result,
            Err(GroundingError::ImpactMapNotFound { .. })
        ));
    }

    /// Test path traversal rejection.
    #[test]
    fn test_validate_id_rejects_traversal() {
        assert!(matches!(
            validate_id("PRD-../../../etc/passwd"),
            Err(GroundingError::PathTraversalError { .. })
        ));
        assert!(matches!(
            validate_id("PRD/test"),
            Err(GroundingError::PathTraversalError { .. })
        ));
        assert!(matches!(
            validate_id("PRD\\test"),
            Err(GroundingError::PathTraversalError { .. })
        ));
        assert!(validate_id("PRD-0001").is_ok());
    }

    /// Test `RfcFileReferences` extraction.
    #[test]
    fn test_rfc_file_references() {
        let yaml: serde_yaml::Value = serde_yaml::from_str(
            r#"
tickets:
  - ticket_id: TCK-00001
    files_to_create:
      - "crates/apm2-core/src/new_module/mod.rs"
      - path: "crates/apm2-core/src/new_module/impl.rs"
    files_to_modify:
      - "crates/apm2-core/src/lib.rs"
  - ticket_id: TCK-00002
    files_to_modify:
      - "crates/apm2-cli/src/main.rs"
"#,
        )
        .unwrap();

        let refs = RfcFileReferences::from_yaml(&yaml);

        assert_eq!(refs.files_to_create.len(), 2);
        assert_eq!(refs.files_to_modify.len(), 2);
        assert!(
            refs.files_to_create
                .contains(&"crates/apm2-core/src/new_module/mod.rs".to_string())
        );
        assert!(
            refs.files_to_modify
                .contains(&"crates/apm2-core/src/lib.rs".to_string())
        );
    }

    /// Test multiple validation errors.
    #[test]
    fn test_multiple_validation_errors() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();
        create_test_artifacts(root);

        let files_to_modify = vec![
            "crates/missing1.rs".to_string(),
            "crates/missing2.rs".to_string(),
        ];
        let files_to_create: Vec<String> = vec![];

        let result = validate_paths(root, "PRD-TEST", &files_to_modify, &files_to_create).unwrap();

        assert!(!result.is_valid());
        assert_eq!(result.errors.len(), 2);

        let err = result.into_result().unwrap_err();
        assert!(matches!(err, PathValidationError::Multiple { errors } if errors.len() == 2));
    }
}
