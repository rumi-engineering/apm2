//! Deterministic YAML output generation for impact maps.
//!
//! This module provides:
//! - Impact map data structure for output
//! - Deterministic YAML serialization with sorted keys
//! - Atomic file writes to prevent corruption
//! - Content hashing for cache invalidation
//!
//! # Output Format
//!
//! The impact map is written to:
//! `evidence/prd/<PRD-ID>/impact_map/impact_map.yaml`
//!
//! # Determinism
//!
//! Output is deterministic via:
//! - Sorted keys in YAML (alphabetical)
//! - 2-space indentation
//! - Sorted arrays by identifier
//! - Content hash computed from canonical YAML

use std::fs;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

use super::adjudication::{AdjudicationResult, adjudicate_mappings};
use super::mapper::{
    ImpactMapError, MappedRequirement, RequirementMatcher, load_components_from_ccp,
    parse_requirements,
};
use crate::determinism::{CanonicalizeError, canonicalize_yaml, write_atomic};

/// Summary of the impact map generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImpactMapSummary {
    /// Total requirements processed.
    pub total_requirements: usize,
    /// Requirements with high-confidence matches.
    pub high_confidence_matches: usize,
    /// Requirements needing review.
    pub needs_review: usize,
    /// Duplication risks identified.
    pub duplication_risks: usize,
    /// Net-new requirements.
    pub net_new_count: usize,
}

/// The complete impact map structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImpactMap {
    /// Schema version for this impact map format.
    pub schema_version: String,
    /// Timestamp when the impact map was generated.
    pub generated_at: DateTime<Utc>,
    /// PRD identifier.
    pub prd_id: String,
    /// CCP index hash used for this impact map.
    pub ccp_index_hash: String,
    /// BLAKE3 hash of this impact map content.
    pub content_hash: String,
    /// Summary statistics.
    pub summary: ImpactMapSummary,
    /// Requirement mappings.
    pub requirement_mappings: Vec<MappedRequirement>,
    /// Adjudication result.
    pub adjudication: AdjudicationResult,
}

impl ImpactMap {
    /// Current schema version.
    pub const SCHEMA_VERSION: &'static str = "2026-01-26";
}

/// Options for building the impact map.
#[derive(Debug, Clone, Default)]
pub struct ImpactMapBuildOptions {
    /// Force rebuild even if inputs haven't changed.
    pub force: bool,
    /// Dry run mode - compute but don't write output.
    pub dry_run: bool,
}

/// Result of an impact map build operation.
#[derive(Debug, Clone)]
pub struct ImpactMapBuildResult {
    /// The built impact map.
    pub impact_map: ImpactMap,
    /// Whether the build was skipped due to unchanged inputs.
    pub skipped: bool,
    /// Path to the output directory.
    pub output_dir: PathBuf,
}

/// Errors specific to output generation.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum OutputError {
    /// Impact map error.
    #[error("{0}")]
    ImpactMapError(#[from] ImpactMapError),

    /// Failed to create output directory.
    #[error("failed to create output directory {path}: {reason}")]
    DirectoryCreationError {
        /// Path to the directory.
        path: String,
        /// Reason for the failure.
        reason: String,
    },

    /// Failed to write output file.
    #[error("failed to write output file {path}: {reason}")]
    WriteError {
        /// Path to the file.
        path: String,
        /// Reason for the failure.
        reason: String,
    },

    /// YAML canonicalization failed.
    #[error("YAML canonicalization failed: {0}")]
    CanonicalizeError(#[from] CanonicalizeError),

    /// Atomic write failed.
    #[error("atomic write failed: {0}")]
    AtomicWriteError(#[from] crate::determinism::AtomicWriteError),

    /// YAML serialization failed.
    #[error("YAML serialization failed: {reason}")]
    YamlSerializationError {
        /// Reason for the failure.
        reason: String,
    },

    /// JSON parsing failed.
    #[error("JSON parsing failed: {reason}")]
    JsonParseError {
        /// Reason for the failure.
        reason: String,
    },
}

/// Reads the CCP index hash from the CCP index file.
fn read_ccp_index_hash(repo_root: &Path, prd_id: &str) -> Result<String, OutputError> {
    let index_path = repo_root
        .join("evidence")
        .join("prd")
        .join(prd_id)
        .join("ccp")
        .join("ccp_index.json");

    if !index_path.exists() {
        return Err(ImpactMapError::CcpIndexNotFound {
            path: index_path.display().to_string(),
        }
        .into());
    }

    let content = fs::read_to_string(&index_path).map_err(|e| ImpactMapError::ReadError {
        path: index_path.display().to_string(),
        reason: e.to_string(),
    })?;

    // Parse JSON to extract index_hash
    let json: serde_json::Value =
        serde_json::from_str(&content).map_err(|e| OutputError::JsonParseError {
            reason: e.to_string(),
        })?;

    // Try different possible structures
    let hash = json
        .get("index_hash")
        .or_else(|| json.get("ccp_index").and_then(|i| i.get("git_commit")))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    Ok(hash.to_string())
}

/// Computes the content hash for the impact map.
fn compute_content_hash(
    mappings: &[MappedRequirement],
    adjudication: &AdjudicationResult,
) -> Result<String, OutputError> {
    // Create a hashable structure excluding timestamps
    #[derive(Serialize)]
    struct HashableContent<'a> {
        mappings: &'a [MappedRequirement],
        adjudication: &'a AdjudicationResult,
    }

    let content = HashableContent {
        mappings,
        adjudication,
    };

    let yaml_value =
        serde_yaml::to_value(&content).map_err(|e| OutputError::YamlSerializationError {
            reason: e.to_string(),
        })?;

    let canonical = canonicalize_yaml(&yaml_value)?;
    let hash = blake3::hash(canonical.as_bytes());

    Ok(hash.to_hex().to_string())
}

/// Writes the impact map to the output directory.
///
/// Uses atomic writes to prevent partial/corrupt files on crash.
///
/// # Errors
///
/// Returns an error if the output directory cannot be created or the file
/// cannot be written.
pub fn write_impact_map(output_dir: &Path, impact_map: &ImpactMap) -> Result<(), OutputError> {
    // Create output directory
    fs::create_dir_all(output_dir).map_err(|e| OutputError::DirectoryCreationError {
        path: output_dir.display().to_string(),
        reason: e.to_string(),
    })?;

    // Serialize to YAML value for canonicalization
    let yaml_value =
        serde_yaml::to_value(impact_map).map_err(|e| OutputError::YamlSerializationError {
            reason: e.to_string(),
        })?;

    // Canonicalize for deterministic output
    let canonical_yaml = canonicalize_yaml(&yaml_value)?;

    // Write atomically
    let output_path = output_dir.join("impact_map.yaml");
    write_atomic(&output_path, canonical_yaml.as_bytes())?;

    info!(
        output_path = %output_path.display(),
        content_hash = %impact_map.content_hash,
        "Impact map written"
    );

    Ok(())
}

/// Builds the impact map for a PRD.
///
/// This function:
/// 1. Parses PRD requirements
/// 2. Loads CCP components
/// 3. Matches requirements to components
/// 4. Adjudicates mappings for risks
/// 5. Writes deterministic YAML output
///
/// # Arguments
///
/// * `repo_root` - Path to the repository root
/// * `prd_id` - PRD identifier (e.g., "PRD-0005")
/// * `options` - Build options (force, `dry_run`)
///
/// # Errors
///
/// Returns an error if:
/// - CCP index doesn't exist
/// - Requirements directory doesn't exist
/// - File operations fail
///
/// # Example
///
/// ```rust,no_run
/// use std::path::Path;
///
/// use apm2_core::impact_map::{ImpactMapBuildOptions, build_impact_map};
///
/// let result = build_impact_map(
///     Path::new("/repo/root"),
///     "PRD-0005",
///     &ImpactMapBuildOptions::default(),
/// )
/// .unwrap();
///
/// println!(
///     "Generated impact map with {} mappings",
///     result.impact_map.requirement_mappings.len()
/// );
/// ```
pub fn build_impact_map(
    repo_root: &Path,
    prd_id: &str,
    options: &ImpactMapBuildOptions,
) -> Result<ImpactMapBuildResult, OutputError> {
    info!(
        repo_root = %repo_root.display(),
        prd_id = %prd_id,
        force = options.force,
        dry_run = options.dry_run,
        "Building impact map"
    );

    // Read CCP index hash
    debug!("Reading CCP index hash");
    let ccp_index_hash = read_ccp_index_hash(repo_root, prd_id)?;
    debug!(ccp_index_hash = %ccp_index_hash, "CCP index hash read");

    // Parse requirements
    debug!("Parsing requirements");
    let requirements = parse_requirements(repo_root, prd_id)?;
    debug!(
        requirement_count = requirements.len(),
        "Requirements parsed"
    );

    // Load CCP components
    debug!("Loading CCP components");
    let components = load_components_from_ccp(repo_root, prd_id)?;
    debug!(component_count = components.len(), "Components loaded");

    // Match requirements to components
    debug!("Matching requirements to components");
    let matcher = RequirementMatcher::new(components);
    let mut mappings: Vec<MappedRequirement> = requirements
        .iter()
        .map(|req| matcher.match_requirement(req))
        .collect();

    // Sort mappings by requirement ID for determinism
    mappings.sort_by(|a, b| a.requirement_id.cmp(&b.requirement_id));

    debug!(mapping_count = mappings.len(), "Mappings generated");

    // Adjudicate mappings
    debug!("Adjudicating mappings");
    let adjudication = adjudicate_mappings(&mappings);
    debug!(
        duplication_risks = adjudication.duplication_risks.len(),
        net_new = adjudication.net_new_requirements.len(),
        "Adjudication complete"
    );

    // Compute content hash
    let content_hash = compute_content_hash(&mappings, &adjudication)?;

    // Build summary
    let summary = ImpactMapSummary {
        total_requirements: mappings.len(),
        high_confidence_matches: adjudication.high_confidence_count,
        needs_review: adjudication.needs_review_count,
        duplication_risks: adjudication.duplication_risks.len(),
        net_new_count: adjudication.net_new_requirements.len(),
    };

    // Create impact map
    let impact_map = ImpactMap {
        schema_version: ImpactMap::SCHEMA_VERSION.to_string(),
        generated_at: Utc::now(),
        prd_id: prd_id.to_string(),
        ccp_index_hash,
        content_hash,
        summary,
        requirement_mappings: mappings,
        adjudication,
    };

    // Determine output directory
    let output_dir = repo_root
        .join("evidence")
        .join("prd")
        .join(prd_id)
        .join("impact_map");

    // Write output (unless dry run)
    if options.dry_run {
        info!(
            content_hash = %impact_map.content_hash,
            "Dry run - skipping file writes"
        );
    } else {
        write_impact_map(&output_dir, &impact_map)?;
    }

    Ok(ImpactMapBuildResult {
        impact_map,
        skipped: false,
        output_dir,
    })
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::*;
    use crate::impact_map::mapper::tests::{create_test_ccp_atlas, create_test_requirements};

    /// UT-114-04: Test deterministic YAML output.
    #[test]
    fn test_deterministic_output() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();
        create_test_requirements(root);
        create_test_ccp_atlas(root);

        // Create CCP index file
        let ccp_dir = root.join("evidence/prd/PRD-TEST/ccp");
        fs::write(
            ccp_dir.join("ccp_index.json"),
            r#"{"index_hash": "abc123"}"#,
        )
        .unwrap();

        // Build twice and compare
        let result1 =
            build_impact_map(root, "PRD-TEST", &ImpactMapBuildOptions::default()).unwrap();
        let result2 = build_impact_map(
            root,
            "PRD-TEST",
            &ImpactMapBuildOptions {
                force: true,
                dry_run: false,
            },
        )
        .unwrap();

        // Content hashes should be identical (excluding timestamp)
        assert_eq!(
            result1.impact_map.content_hash, result2.impact_map.content_hash,
            "Content hash should be deterministic"
        );

        // Read the output file
        let output_path = result1.output_dir.join("impact_map.yaml");
        assert!(output_path.exists(), "Output file should exist");

        // Parse and verify structure
        let content = fs::read_to_string(&output_path).unwrap();
        let parsed: ImpactMap = serde_yaml::from_str(&content).unwrap();

        assert_eq!(parsed.prd_id, "PRD-TEST");
        assert!(!parsed.requirement_mappings.is_empty());
    }

    /// UT-114-04: Test dry run mode.
    #[test]
    fn test_dry_run_no_output() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();
        create_test_requirements(root);
        create_test_ccp_atlas(root);

        // Create CCP index file
        let ccp_dir = root.join("evidence/prd/PRD-TEST/ccp");
        fs::write(
            ccp_dir.join("ccp_index.json"),
            r#"{"index_hash": "abc123"}"#,
        )
        .unwrap();

        let result = build_impact_map(
            root,
            "PRD-TEST",
            &ImpactMapBuildOptions {
                force: false,
                dry_run: true,
            },
        )
        .unwrap();

        // Impact map should be computed
        assert!(!result.impact_map.content_hash.is_empty());

        // But output file should not exist
        let output_path = result.output_dir.join("impact_map.yaml");
        assert!(
            !output_path.exists(),
            "Output file should not exist in dry run"
        );
    }

    /// Test CCP index not found error.
    #[test]
    fn test_ccp_index_not_found() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();
        create_test_requirements(root);
        // Don't create CCP atlas

        let result = build_impact_map(root, "PRD-TEST", &ImpactMapBuildOptions::default());
        assert!(result.is_err());
    }

    /// Test content hash computation.
    #[test]
    fn test_content_hash_determinism() {
        use super::super::adjudication::AdjudicationResult;
        use super::super::mapper::{CandidateComponent, FitScore, MappedRequirement};

        let mappings = vec![MappedRequirement {
            requirement_id: "REQ-0001".to_string(),
            requirement_title: "Test".to_string(),
            requirement_statement: "Test statement".to_string(),
            candidates: vec![CandidateComponent {
                component_id: "COMP-A".to_string(),
                component_name: "comp-a".to_string(),
                fit_score: FitScore::High,
                rationale: "Test".to_string(),
                extension_point_id: None,
                similarity_score: 0.8,
            }],
            needs_review: false,
        }];

        let adjudication = AdjudicationResult {
            duplication_risks: vec![],
            net_new_requirements: vec![],
            total_requirements: 1,
            high_confidence_count: 1,
            needs_review_count: 0,
        };

        let hash1 = compute_content_hash(&mappings, &adjudication).unwrap();
        let hash2 = compute_content_hash(&mappings, &adjudication).unwrap();

        assert_eq!(hash1, hash2, "Content hash should be deterministic");
    }
}
