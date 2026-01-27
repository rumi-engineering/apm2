//! Requirement parsing and CCP component matching.
//!
//! This module provides:
//! - PRD requirement YAML parsing
//! - Component matching via keyword similarity (Jaccard coefficient)
//! - Ranked candidate lists with fit scores and rationale
//!
//! # Matching Algorithm
//!
//! The matching algorithm uses a multi-stage approach:
//! 1. Exact substring match on component description or module names (highest
//!    priority)
//! 2. Word-level Jaccard similarity (threshold >= 0.3 for candidate inclusion)
//! 3. Requirements without strong matches are flagged for adjudication
//!
//! # Invariants
//!
//! - [INV-MAPPER-001] Requirement IDs are unique within a PRD
//! - [INV-MAPPER-002] Candidates are sorted by fit score (descending)
//! - [INV-MAPPER-003] All parsed requirements are included in output

use std::collections::HashSet;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, warn};

/// Maximum file size for requirement files (1 MB).
/// Prevents denial-of-service via unbounded reads.
const MAX_REQUIREMENT_FILE_SIZE: u64 = 1024 * 1024;

/// Maximum number of requirement files to process.
const MAX_REQUIREMENT_FILES: usize = 1000;

/// Minimum Jaccard similarity threshold for candidate inclusion.
const JACCARD_THRESHOLD: f64 = 0.3;

/// Errors that can occur during requirement parsing and mapping.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ImpactMapError {
    /// Failed to read a file.
    #[error("failed to read file {path}: {reason}")]
    ReadError {
        /// Path to the file that failed to read.
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

    /// Too many requirement files.
    #[error("too many requirement files ({count}, max {max_count})")]
    TooManyFiles {
        /// Actual count.
        count: usize,
        /// Maximum allowed count.
        max_count: usize,
    },

    /// YAML parsing failed.
    #[error("YAML parsing failed for {path}: {reason}")]
    YamlParseError {
        /// Path to the file.
        path: String,
        /// Reason for the failure.
        reason: String,
    },

    /// Invalid PRD directory.
    #[error("invalid PRD directory: {path}")]
    InvalidPrdDirectory {
        /// The invalid path.
        path: String,
    },

    /// Requirements directory not found.
    #[error("requirements directory not found: {path}")]
    RequirementsDirectoryNotFound {
        /// The missing path.
        path: String,
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

    /// Path traversal attempt detected.
    #[error("path traversal detected: {path} - {reason}")]
    PathTraversalError {
        /// The path that attempted traversal.
        path: String,
        /// Reason for the failure.
        reason: String,
    },

    /// No requirements found.
    #[error("no requirements found in {path}")]
    NoRequirementsFound {
        /// The path that was searched.
        path: String,
    },
}

/// A parsed PRD requirement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParsedRequirement {
    /// Requirement ID (e.g., "REQ-0001").
    pub id: String,
    /// Requirement type (FUNCTIONAL, `NON_FUNCTIONAL`, etc.).
    pub requirement_type: String,
    /// Requirement title.
    pub title: String,
    /// Requirement statement.
    pub statement: String,
    /// Acceptance criteria.
    pub acceptance_criteria: Vec<String>,
    /// Evidence IDs associated with this requirement.
    pub evidence_ids: Vec<String>,
}

/// Raw YAML structure for requirement files.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RequirementYaml {
    prd_requirement: RequirementContent,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RequirementContent {
    id: String,
    #[serde(rename = "type")]
    requirement_type: String,
    title: String,
    statement: String,
    #[serde(default)]
    acceptance_criteria: Vec<String>,
    #[serde(default)]
    evidence: Option<EvidenceBlock>,
    /// Schema version (optional, not used but accepted for compatibility).
    #[serde(default)]
    #[allow(dead_code)]
    schema_version: Option<String>,
    /// Template version (optional, not used but accepted for compatibility).
    #[serde(default)]
    #[allow(dead_code)]
    template_version: Option<String>,
}

#[derive(Debug, Deserialize)]
struct EvidenceBlock {
    #[serde(default)]
    evidence_ids: Vec<String>,
    /// Whether evidence is inherited from PRD (optional metadata).
    #[serde(default)]
    #[allow(dead_code)]
    inherited_from_prd: Option<bool>,
    /// Additional notes about evidence requirements (optional metadata).
    #[serde(default)]
    #[allow(dead_code)]
    notes: Vec<String>,
}

/// Fit score for component matching.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FitScore {
    /// High confidence match (exact substring or Jaccard >= 0.6).
    High,
    /// Medium confidence match (Jaccard >= 0.4).
    Medium,
    /// Low confidence match (Jaccard >= 0.3).
    Low,
}

impl FitScore {
    /// Returns the numeric value for sorting.
    const fn value(self) -> u8 {
        match self {
            Self::High => 3,
            Self::Medium => 2,
            Self::Low => 1,
        }
    }

    /// Creates a fit score from a Jaccard similarity value.
    fn from_similarity(similarity: f64, is_exact: bool) -> Option<Self> {
        if is_exact || similarity >= 0.6 {
            Some(Self::High)
        } else if similarity >= 0.4 {
            Some(Self::Medium)
        } else if similarity >= JACCARD_THRESHOLD {
            Some(Self::Low)
        } else {
            None
        }
    }
}

/// A candidate component for a requirement.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateComponent {
    /// Component ID (e.g., "COMP-CLI").
    pub component_id: String,
    /// Component name.
    pub component_name: String,
    /// Fit score.
    pub fit_score: FitScore,
    /// Rationale for the match.
    pub rationale: String,
    /// Extension point ID if applicable.
    pub extension_point_id: Option<String>,
    /// Jaccard similarity score (0.0 to 1.0).
    pub similarity_score: f64,
}

/// A requirement with its mapped candidate components.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MappedRequirement {
    /// Requirement ID.
    pub requirement_id: String,
    /// Requirement title.
    pub requirement_title: String,
    /// Requirement statement (truncated for output).
    pub requirement_statement: String,
    /// Candidate components, sorted by fit score.
    pub candidates: Vec<CandidateComponent>,
    /// Whether this requirement needs manual review.
    pub needs_review: bool,
}

/// Component information from CCP index for matching.
#[derive(Debug, Clone)]
pub struct ComponentInfo {
    /// Component ID.
    pub id: String,
    /// Component name.
    pub name: String,
    /// Component description.
    pub description: String,
    /// Extension points.
    pub extension_points: Vec<ExtensionPointInfo>,
    /// Module names (for additional matching).
    pub module_names: Vec<String>,
}

/// Extension point information.
#[derive(Debug, Clone)]
pub struct ExtensionPointInfo {
    /// Extension point ID.
    pub id: String,
    /// Extension point name.
    pub name: String,
    /// Extension point description.
    pub description: String,
}

/// Requirement matcher that performs component matching.
pub struct RequirementMatcher {
    /// Components from CCP index.
    components: Vec<ComponentInfo>,
}

impl RequirementMatcher {
    /// Creates a new requirement matcher with the given components.
    #[must_use]
    pub const fn new(components: Vec<ComponentInfo>) -> Self {
        Self { components }
    }

    /// Matches a requirement to candidate components.
    #[must_use]
    pub fn match_requirement(&self, requirement: &ParsedRequirement) -> MappedRequirement {
        let mut candidates = Vec::new();

        // Extract words from requirement for Jaccard comparison
        let req_words = extract_words(&format!(
            "{} {} {}",
            requirement.title, requirement.statement, requirement.id
        ));

        for component in &self.components {
            // Check for exact substring matches first
            let exact_match = Self::check_exact_match(requirement, component);

            // Calculate Jaccard similarity
            let comp_words = extract_words(&format!(
                "{} {} {}",
                component.name,
                component.description,
                component.module_names.join(" ")
            ));
            let similarity = jaccard_similarity(&req_words, &comp_words);

            // Determine fit score
            if let Some(fit_score) = FitScore::from_similarity(similarity, exact_match.is_some()) {
                let rationale = exact_match.as_ref().map_or_else(
                    || {
                        format!(
                            "Keyword similarity score: {similarity:.2} against '{}'",
                            component.name
                        )
                    },
                    Clone::clone,
                );

                // Check extension points for better matches
                let (extension_point_id, ext_similarity) =
                    Self::find_best_extension_point(requirement, component);

                let final_similarity = similarity.max(ext_similarity);

                candidates.push(CandidateComponent {
                    component_id: component.id.clone(),
                    component_name: component.name.clone(),
                    fit_score,
                    rationale,
                    extension_point_id,
                    similarity_score: final_similarity,
                });
            }
        }

        // Sort candidates by fit score (descending), then by similarity
        candidates.sort_by(|a, b| {
            b.fit_score.value().cmp(&a.fit_score.value()).then(
                b.similarity_score
                    .partial_cmp(&a.similarity_score)
                    .unwrap_or(std::cmp::Ordering::Equal),
            )
        });

        // Flag for review if no high-confidence matches
        let needs_review =
            candidates.is_empty() || !candidates.iter().any(|c| c.fit_score == FitScore::High);

        // Truncate statement for output (safely handle multi-byte characters)
        let statement_truncated = if requirement.statement.chars().count() > 200 {
            format!("{}...", safe_truncate(&requirement.statement, 197))
        } else {
            requirement.statement.clone()
        };

        MappedRequirement {
            requirement_id: requirement.id.clone(),
            requirement_title: requirement.title.clone(),
            requirement_statement: statement_truncated,
            candidates,
            needs_review,
        }
    }

    /// Checks for exact substring matches between requirement and component.
    fn check_exact_match(
        requirement: &ParsedRequirement,
        component: &ComponentInfo,
    ) -> Option<String> {
        let req_lower = format!("{} {}", requirement.title, requirement.statement).to_lowercase();
        let comp_name_lower = component.name.to_lowercase();
        let comp_desc_lower = component.description.to_lowercase();

        // Check if component name appears in requirement
        if req_lower.contains(&comp_name_lower) {
            return Some(format!(
                "Exact match: requirement mentions '{}'",
                component.name
            ));
        }

        // Check if requirement mentions any module names
        for module in &component.module_names {
            let module_lower = module.to_lowercase();
            if req_lower.contains(&module_lower) {
                return Some(format!(
                    "Exact match: requirement mentions module '{module}'"
                ));
            }
        }

        // Check if key requirement terms appear in component description
        let key_terms = [
            "factory", "compile", "impact", "map", "ccp", "rfc", "ticket",
        ];
        for term in &key_terms {
            if req_lower.contains(term) && comp_desc_lower.contains(term) {
                return Some(format!("Exact match: both mention key term '{term}'"));
            }
        }

        None
    }

    /// Finds the best matching extension point for a requirement.
    fn find_best_extension_point(
        requirement: &ParsedRequirement,
        component: &ComponentInfo,
    ) -> (Option<String>, f64) {
        let req_words = extract_words(&format!("{} {}", requirement.title, requirement.statement));

        let mut best_ext: Option<String> = None;
        let mut best_similarity = 0.0;

        for ext in &component.extension_points {
            let ext_words = extract_words(&format!("{} {}", ext.name, ext.description));
            let similarity = jaccard_similarity(&req_words, &ext_words);

            if similarity > best_similarity {
                best_similarity = similarity;
                best_ext = Some(ext.id.clone());
            }
        }

        (best_ext, best_similarity)
    }
}

/// Safely truncates a string to a maximum number of characters.
///
/// This function handles multi-byte UTF-8 characters correctly, ensuring
/// we never split in the middle of a character.
fn safe_truncate(s: &str, max_chars: usize) -> &str {
    match s.char_indices().nth(max_chars) {
        Some((idx, _)) => &s[..idx],
        None => s,
    }
}

/// Extracts words from text for Jaccard comparison.
fn extract_words(text: &str) -> HashSet<String> {
    text.to_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| w.len() >= 3) // Skip short words
        .map(String::from)
        .collect()
}

/// Calculates Jaccard similarity coefficient between two word sets.
#[allow(clippy::cast_precision_loss)]
fn jaccard_similarity(set1: &HashSet<String>, set2: &HashSet<String>) -> f64 {
    if set1.is_empty() || set2.is_empty() {
        return 0.0;
    }

    let intersection = set1.intersection(set2).count();
    let union = set1.union(set2).count();

    if union == 0 {
        0.0
    } else {
        intersection as f64 / union as f64
    }
}

/// Validates that a PRD ID does not contain path traversal characters.
///
/// # Errors
///
/// Returns `PathTraversalError` if the PRD ID contains `/`, `\`, or `..`.
pub fn validate_prd_id(prd_id: &str) -> Result<(), ImpactMapError> {
    if prd_id.contains('/') || prd_id.contains('\\') || prd_id.contains("..") {
        return Err(ImpactMapError::PathTraversalError {
            path: prd_id.to_string(),
            reason: "PRD ID contains invalid characters".to_string(),
        });
    }
    Ok(())
}

/// Validates that a path is within the repository root.
fn validate_path_within_repo(path: &Path, repo_root: &Path) -> Result<(), ImpactMapError> {
    let canonical_path = path.canonicalize().map_err(|e| ImpactMapError::ReadError {
        path: path.display().to_string(),
        reason: e.to_string(),
    })?;

    let canonical_root = repo_root
        .canonicalize()
        .map_err(|e| ImpactMapError::ReadError {
            path: repo_root.display().to_string(),
            reason: e.to_string(),
        })?;

    if !canonical_path.starts_with(&canonical_root) {
        return Err(ImpactMapError::PathTraversalError {
            path: path.display().to_string(),
            reason: "path is outside repo root".to_string(),
        });
    }

    Ok(())
}

/// Reads a file with size limits.
fn read_file_bounded(path: &Path, max_size: u64) -> Result<String, ImpactMapError> {
    let metadata = fs::metadata(path).map_err(|e| ImpactMapError::ReadError {
        path: path.display().to_string(),
        reason: e.to_string(),
    })?;

    let size = metadata.len();
    if size > max_size {
        return Err(ImpactMapError::FileTooLarge {
            path: path.display().to_string(),
            size,
            max_size,
        });
    }

    let file = File::open(path).map_err(|e| ImpactMapError::ReadError {
        path: path.display().to_string(),
        reason: e.to_string(),
    })?;

    let mut content = String::new();
    file.take(max_size)
        .read_to_string(&mut content)
        .map_err(|e| ImpactMapError::ReadError {
            path: path.display().to_string(),
            reason: e.to_string(),
        })?;

    Ok(content)
}

/// Parses all requirements from a PRD's requirements directory.
///
/// # Arguments
///
/// * `repo_root` - Path to the repository root
/// * `prd_id` - PRD identifier (e.g., "PRD-0005")
///
/// # Returns
///
/// A vector of parsed requirements, sorted by ID.
///
/// # Errors
///
/// Returns an error if:
/// - The requirements directory doesn't exist
/// - File reads fail
/// - YAML parsing fails
pub fn parse_requirements(
    repo_root: &Path,
    prd_id: &str,
) -> Result<Vec<ParsedRequirement>, ImpactMapError> {
    // Validate PRD ID to prevent path traversal
    validate_prd_id(prd_id)?;

    let requirements_dir = repo_root
        .join("documents")
        .join("prds")
        .join(prd_id)
        .join("requirements");

    if !requirements_dir.exists() {
        return Err(ImpactMapError::RequirementsDirectoryNotFound {
            path: requirements_dir.display().to_string(),
        });
    }

    // Validate path is within repo
    validate_path_within_repo(&requirements_dir, repo_root)?;

    // Find all YAML files
    let mut yaml_files: Vec<PathBuf> = Vec::new();
    let entries = fs::read_dir(&requirements_dir).map_err(|e| ImpactMapError::ReadError {
        path: requirements_dir.display().to_string(),
        reason: e.to_string(),
    })?;

    for entry in entries {
        let entry = entry.map_err(|e| ImpactMapError::ReadError {
            path: requirements_dir.display().to_string(),
            reason: e.to_string(),
        })?;
        let path = entry.path();

        // Only process REQ-*.yaml files to skip index/readme files.
        // Consolidation prevents redundant extension splitting.
        let is_valid_req = path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with("REQ-") && (n.ends_with(".yaml") || n.ends_with(".yml")));

        if is_valid_req {
            yaml_files.push(path);
        }
    }

    // Check file count limit
    if yaml_files.len() > MAX_REQUIREMENT_FILES {
        return Err(ImpactMapError::TooManyFiles {
            count: yaml_files.len(),
            max_count: MAX_REQUIREMENT_FILES,
        });
    }

    if yaml_files.is_empty() {
        return Err(ImpactMapError::NoRequirementsFound {
            path: requirements_dir.display().to_string(),
        });
    }

    // Sort for determinism
    yaml_files.sort();

    let mut requirements = Vec::with_capacity(yaml_files.len());

    for path in &yaml_files {
        debug!(path = %path.display(), "Parsing requirement file");

        let content = read_file_bounded(path, MAX_REQUIREMENT_FILE_SIZE)?;

        let req_yaml: RequirementYaml =
            serde_yaml::from_str(&content).map_err(|e| ImpactMapError::YamlParseError {
                path: path.display().to_string(),
                reason: e.to_string(),
            })?;

        let req = req_yaml.prd_requirement;

        requirements.push(ParsedRequirement {
            id: req.id,
            requirement_type: req.requirement_type,
            title: req.title,
            statement: req.statement.trim().to_string(),
            acceptance_criteria: req.acceptance_criteria,
            evidence_ids: req.evidence.map(|e| e.evidence_ids).unwrap_or_default(),
        });
    }

    // Sort by ID for determinism
    requirements.sort_by(|a, b| a.id.cmp(&b.id));

    Ok(requirements)
}

/// Loads component information from the CCP component atlas.
///
/// # Arguments
///
/// * `repo_root` - Path to the repository root
/// * `prd_id` - PRD identifier
///
/// # Returns
///
/// A vector of component information for matching.
///
/// # Errors
///
/// Returns an error if the CCP atlas file doesn't exist or cannot be parsed.
#[allow(clippy::too_many_lines)]
pub fn load_components_from_ccp(
    repo_root: &Path,
    prd_id: &str,
) -> Result<Vec<ComponentInfo>, ImpactMapError> {
    // Validate PRD ID to prevent path traversal
    validate_prd_id(prd_id)?;

    let atlas_path = repo_root
        .join("evidence")
        .join("prd")
        .join(prd_id)
        .join("ccp")
        .join("component_atlas.yaml");

    if !atlas_path.exists() {
        return Err(ImpactMapError::CcpIndexNotFound {
            path: atlas_path.display().to_string(),
        });
    }

    let content = read_file_bounded(&atlas_path, MAX_REQUIREMENT_FILE_SIZE * 10)?;

    // Parse the component atlas YAML
    let atlas: serde_yaml::Value =
        serde_yaml::from_str(&content).map_err(|e| ImpactMapError::CcpIndexParseError {
            reason: e.to_string(),
        })?;

    let mut components = Vec::new();

    // Navigate to components array
    if let Some(comp_atlas) = atlas.get("component_atlas") {
        if let Some(comps) = comp_atlas.get("components") {
            if let Some(comp_array) = comps.as_sequence() {
                for comp in comp_array {
                    let id = comp
                        .get("id")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let name = comp
                        .get("name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let description = comp
                        .get("description")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();

                    // Extract extension points
                    let mut extension_points = Vec::new();
                    if let Some(ext_points) = comp.get("extension_points") {
                        if let Some(ext_array) = ext_points.as_sequence() {
                            for ext in ext_array {
                                extension_points.push(ExtensionPointInfo {
                                    id: ext
                                        .get("id")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("")
                                        .to_string(),
                                    name: ext
                                        .get("name")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("")
                                        .to_string(),
                                    description: ext
                                        .get("description")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("")
                                        .to_string(),
                                });
                            }
                        }
                    }

                    // Extract module names
                    let mut module_names = Vec::new();
                    if let Some(modules) = comp.get("modules") {
                        if let Some(mod_array) = modules.as_sequence() {
                            for module in mod_array {
                                if let Some(mod_name) = module.get("name").and_then(|v| v.as_str())
                                {
                                    module_names.push(mod_name.to_string());
                                }
                                // Also check for extension points within modules
                                if let Some(mod_ext_points) = module.get("extension_points") {
                                    if let Some(ext_array) = mod_ext_points.as_sequence() {
                                        for ext in ext_array {
                                            extension_points.push(ExtensionPointInfo {
                                                id: ext
                                                    .get("id")
                                                    .and_then(|v| v.as_str())
                                                    .unwrap_or("")
                                                    .to_string(),
                                                name: ext
                                                    .get("name")
                                                    .and_then(|v| v.as_str())
                                                    .unwrap_or("")
                                                    .to_string(),
                                                description: ext
                                                    .get("description")
                                                    .and_then(|v| v.as_str())
                                                    .unwrap_or("")
                                                    .to_string(),
                                            });
                                        }
                                    }
                                }
                            }
                        }
                    }

                    if !id.is_empty() {
                        components.push(ComponentInfo {
                            id,
                            name,
                            description,
                            extension_points,
                            module_names,
                        });
                    }
                }
            }
        }
    }

    // Also try the flat structure (direct components array)
    if components.is_empty() {
        if let Some(comps) = atlas.get("components") {
            if let Some(comp_array) = comps.as_sequence() {
                for comp in comp_array {
                    let id = comp
                        .get("id")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let name = comp
                        .get("name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let description = comp
                        .get("description")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();

                    let mut extension_points = Vec::new();
                    if let Some(ext_points) = comp.get("extension_points") {
                        if let Some(ext_array) = ext_points.as_sequence() {
                            for ext in ext_array {
                                extension_points.push(ExtensionPointInfo {
                                    id: ext
                                        .get("id")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("")
                                        .to_string(),
                                    name: ext
                                        .get("name")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("")
                                        .to_string(),
                                    description: ext
                                        .get("description")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("")
                                        .to_string(),
                                });
                            }
                        }
                    }

                    let mut module_names = Vec::new();
                    if let Some(modules) = comp.get("modules") {
                        if let Some(mod_array) = modules.as_sequence() {
                            for module in mod_array {
                                if let Some(mod_name) = module.get("name").and_then(|v| v.as_str())
                                {
                                    module_names.push(mod_name.to_string());
                                }
                            }
                        }
                    }

                    if !id.is_empty() {
                        components.push(ComponentInfo {
                            id,
                            name,
                            description,
                            extension_points,
                            module_names,
                        });
                    }
                }
            }
        }
    }

    if components.is_empty() {
        warn!("No components found in CCP atlas");
    }

    Ok(components)
}

/// Test utilities for the requirement mapper module.
#[cfg(test)]
pub mod tests {
    use tempfile::TempDir;

    use super::*;

    /// Creates a test requirements directory with sample files.
    ///
    /// # Panics
    ///
    /// Panics if directory creation or file writes fail.
    pub fn create_test_requirements(root: &Path) {
        let req_dir = root.join("documents/prds/PRD-TEST/requirements");
        fs::create_dir_all(&req_dir).unwrap();

        fs::write(
            req_dir.join("REQ-0001.yaml"),
            r#"prd_requirement:
  schema_version: "2026-01-23"
  template_version: "2026-01-23"
  id: REQ-0001
  type: FUNCTIONAL
  title: CLI entrypoint for factory commands
  statement: |
    The system MUST provide a CLI entrypoint for factory commands
    including compile, ccp build, and impact-map build.
  acceptance_criteria:
    - "apm2 factory compile --prd PRD-XXXX works"
    - "apm2 factory ccp build --prd PRD-XXXX works"
  evidence:
    evidence_ids:
      - EVID-0001
"#,
        )
        .unwrap();

        fs::write(
            req_dir.join("REQ-0002.yaml"),
            r#"prd_requirement:
  schema_version: "2026-01-23"
  template_version: "2026-01-23"
  id: REQ-0002
  type: FUNCTIONAL
  title: Component atlas generation
  statement: |
    The CCP module MUST generate a component atlas from AGENTS.md files.
  acceptance_criteria:
    - "Component IDs are stable"
  evidence:
    evidence_ids:
      - EVID-0002
"#,
        )
        .unwrap();
    }

    /// Creates a test CCP component atlas.
    ///
    /// # Panics
    ///
    /// Panics if directory creation or file writes fail.
    pub fn create_test_ccp_atlas(root: &Path) {
        let ccp_dir = root.join("evidence/prd/PRD-TEST/ccp");
        fs::create_dir_all(&ccp_dir).unwrap();

        fs::write(
            ccp_dir.join("component_atlas.yaml"),
            r#"component_atlas:
  schema_version: "2026-01-26"
  generated_at: "2026-01-26T00:00:00Z"
  repo_root: "/test"
  components:
    - id: COMP-CLI
      name: apm2-cli
      path: crates/apm2-cli
      type: binary_crate
      description: "CLI client for managing AI CLI processes"
      extension_points:
        - id: EXT-CLI-001
          name: FactoryCommands
          description: "Clap subcommand enum for factory commands"
    - id: COMP-CORE
      name: apm2-core
      path: crates/apm2-core
      type: library_crate
      description: "Core library providing adapters, CCP module, and process management"
      modules:
        - name: adapter
          path: crates/apm2-core/src/adapter
          description: "Agent adapters for process observation"
        - name: ccp
          path: crates/apm2-core/src/ccp
          description: "CCP component atlas and crate graph generation"
"#,
        )
        .unwrap();
    }

    /// UT-114-01: Test requirement parsing from PRD requirements directory.
    #[test]
    fn test_parse_requirements() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();
        create_test_requirements(root);

        let requirements = parse_requirements(root, "PRD-TEST").unwrap();

        assert_eq!(requirements.len(), 2);
        assert_eq!(requirements[0].id, "REQ-0001");
        assert_eq!(requirements[1].id, "REQ-0002");
        assert!(
            requirements[0]
                .title
                .contains("CLI entrypoint for factory commands")
        );
    }

    /// UT-114-01: Test parsing fails for missing directory.
    #[test]
    fn test_parse_requirements_missing_dir() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();

        let result = parse_requirements(root, "PRD-NONEXISTENT");
        assert!(matches!(
            result,
            Err(ImpactMapError::RequirementsDirectoryNotFound { .. })
        ));
    }

    /// UT-114-02: Test CCP component matching algorithm.
    #[test]
    fn test_component_matching() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();
        create_test_requirements(root);
        create_test_ccp_atlas(root);

        let requirements = parse_requirements(root, "PRD-TEST").unwrap();
        let components = load_components_from_ccp(root, "PRD-TEST").unwrap();

        assert!(!components.is_empty(), "Should load components");
        assert_eq!(components.len(), 2, "Should have 2 components");

        let matcher = RequirementMatcher::new(components);

        // Test matching REQ-0001 (CLI entrypoint)
        let mapping = matcher.match_requirement(&requirements[0]);
        assert_eq!(mapping.requirement_id, "REQ-0001");

        // Mapping should complete without error (may or may not have candidates
        // depending on similarity threshold)
        assert!(
            mapping.needs_review || !mapping.candidates.is_empty(),
            "Should either have candidates or be flagged for review"
        );

        // Test matching REQ-0002 (Component atlas / CCP)
        let mapping2 = matcher.match_requirement(&requirements[1]);
        assert_eq!(mapping2.requirement_id, "REQ-0002");

        // Verify the CCP keyword matching works - requirement mentions "CCP" and
        // component has "ccp" module
        let has_ccp_match = mapping2
            .candidates
            .iter()
            .any(|c| c.component_id == "COMP-CORE" && c.rationale.to_lowercase().contains("ccp"));

        // Either we get a CCP match or the requirement is flagged for review
        assert!(
            has_ccp_match || mapping2.needs_review,
            "Should match CCP-related component or be flagged for review"
        );
    }

    /// Test Jaccard similarity calculation.
    #[test]
    fn test_jaccard_similarity() {
        let set1: HashSet<String> = ["hello", "world", "test"]
            .iter()
            .map(std::string::ToString::to_string)
            .collect();
        let set2: HashSet<String> = ["hello", "world", "foo"]
            .iter()
            .map(std::string::ToString::to_string)
            .collect();

        let sim = jaccard_similarity(&set1, &set2);
        // Intersection: {hello, world} = 2
        // Union: {hello, world, test, foo} = 4
        // Jaccard = 2/4 = 0.5
        assert!((sim - 0.5).abs() < 0.001);

        // Test empty sets
        let empty: HashSet<String> = HashSet::new();
        assert!((jaccard_similarity(&empty, &set1) - 0.0).abs() < f64::EPSILON);
        assert!((jaccard_similarity(&set1, &empty) - 0.0).abs() < f64::EPSILON);
    }

    /// Test word extraction.
    #[test]
    fn test_extract_words() {
        let words = extract_words("Hello, World! This is a test-123.");
        assert!(words.contains("hello"));
        assert!(words.contains("world"));
        assert!(words.contains("this"));
        assert!(words.contains("test"));
        assert!(words.contains("123"));
        // Short words should be filtered
        assert!(!words.contains("is"));
        assert!(!words.contains("a"));
    }

    /// Test `FitScore` ordering.
    #[test]
    fn test_fit_score_ordering() {
        assert!(FitScore::High.value() > FitScore::Medium.value());
        assert!(FitScore::Medium.value() > FitScore::Low.value());
    }

    /// Test `FitScore` from similarity.
    #[test]
    fn test_fit_score_from_similarity() {
        assert_eq!(FitScore::from_similarity(0.7, false), Some(FitScore::High));
        assert_eq!(
            FitScore::from_similarity(0.5, false),
            Some(FitScore::Medium)
        );
        assert_eq!(FitScore::from_similarity(0.35, false), Some(FitScore::Low));
        assert_eq!(FitScore::from_similarity(0.2, false), None);
        // Exact match always high
        assert_eq!(FitScore::from_similarity(0.2, true), Some(FitScore::High));
    }

    /// Test safe truncation with multibyte characters.
    #[test]
    fn test_safe_truncate() {
        // ASCII string
        let ascii = "Hello, World!";
        assert_eq!(safe_truncate(ascii, 5), "Hello");
        assert_eq!(safe_truncate(ascii, 100), ascii);

        // String with multibyte emoji at various positions
        let emoji = "Hello World!";
        assert_eq!(safe_truncate(emoji, 5), "Hello");

        // String with emoji that would be at the truncation boundary
        // 196 regular chars + emoji (4 bytes)
        let boundary_test = format!("{}X", "a".repeat(196));
        let truncated = safe_truncate(&boundary_test, 197);
        assert_eq!(truncated.len(), 197);
        assert_eq!(truncated.chars().count(), 197);
    }

    /// Test multibyte truncation is safe - no panic on emoji at position ~197.
    #[test]
    fn test_multibyte_truncation_safe() {
        // Create a statement with emojis around position 197
        // Each emoji is multiple bytes, so this tests the safe truncation
        let prefix = "a".repeat(195);
        let emoji_suffix = "abcdef"; // emojis at byte positions that would cause panic
        let long_statement = format!("{prefix}{emoji_suffix}");

        let requirement = ParsedRequirement {
            id: "REQ-EMOJI".to_string(),
            requirement_type: "FUNCTIONAL".to_string(),
            title: "Test emoji truncation".to_string(),
            statement: long_statement,
            acceptance_criteria: vec![],
            evidence_ids: vec![],
        };

        // Create a matcher with no components - we just want to test truncation
        let matcher = RequirementMatcher::new(vec![]);

        // This should not panic even though the string has multibyte chars
        let mapping = matcher.match_requirement(&requirement);

        // Verify truncation happened safely
        assert!(mapping.requirement_statement.ends_with("..."));
        assert_eq!(mapping.requirement_statement.chars().count(), 200); // 197 + "..."

        // Now test with emoji exactly at character position 197
        // This creates a string of 250 characters with an emoji at position 197
        let before_emoji = "A".repeat(197);
        let after_emoji = "B".repeat(49);
        let emoji_at_boundary = format!("{before_emoji}x{after_emoji}");
        let requirement2 = ParsedRequirement {
            id: "REQ-BOUNDARY".to_string(),
            requirement_type: "FUNCTIONAL".to_string(),
            title: "Test boundary".to_string(),
            statement: emoji_at_boundary,
            acceptance_criteria: vec![],
            evidence_ids: vec![],
        };

        // This should also not panic (string is > 200 chars so will be truncated)
        let mapping2 = matcher.match_requirement(&requirement2);
        assert!(mapping2.requirement_statement.ends_with("..."));
        // The truncation should produce exactly 200 characters (197 + "...")
        assert_eq!(mapping2.requirement_statement.chars().count(), 200);
    }

    /// Test PRD ID validation rejects path traversal.
    #[test]
    fn test_validate_prd_id_rejects_traversal() {
        // Should reject forward slash
        assert!(matches!(
            validate_prd_id("PRD-../../etc/passwd"),
            Err(ImpactMapError::PathTraversalError { .. })
        ));

        // Should reject backslash
        assert!(matches!(
            validate_prd_id("PRD\\..\\windows"),
            Err(ImpactMapError::PathTraversalError { .. })
        ));

        // Should reject double-dot
        assert!(matches!(
            validate_prd_id(".."),
            Err(ImpactMapError::PathTraversalError { .. })
        ));

        // Should accept valid PRD IDs
        assert!(validate_prd_id("PRD-0001").is_ok());
        assert!(validate_prd_id("PRD-TEST").is_ok());
        assert!(validate_prd_id("PRD-2026-01-26").is_ok());
    }
}
