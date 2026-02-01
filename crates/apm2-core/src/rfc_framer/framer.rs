#![allow(clippy::disallowed_methods)] // Metadata/observability usage or adapter.
//! Core RFC generation logic from Impact Map and CCP.
//!
//! This module provides:
//! - RFC skeleton generation from Impact Map + CCP
//! - RFC section generation following template structure
//! - Deterministic YAML output with atomic writes
//!
//! # RFC Structure
//!
//! Generated RFCs follow the standard template:
//! - `00_meta.yaml`: RFC metadata with CCP grounding
//! - `01_problem_and_imports.yaml`: Problem statement from PRD
//! - `02_design_decisions.yaml`: Populated from Impact Map
//! - `03_trust_boundaries.yaml`: Security model (skeleton)
//! - `04_contracts_and_versioning.yaml`: API contracts (skeleton)
//! - `05_rollout_and_ops.yaml`: Deployment considerations (skeleton)
//! - `06_ticket_decomposition.yaml`: Generated from mapped requirements
//! - `07_test_and_evidence.yaml`: Test strategy (skeleton)
//! - `08_risks_and_open_questions.yaml`: Risk assessment (skeleton)
//! - `09_governance_and_gates.yaml`: Approval gates (skeleton)

use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, info};

use super::grounding::{CcpGrounding, GroundingError, PathValidationError, validate_paths};
use crate::determinism::{CanonicalizeError, canonicalize_yaml, write_atomic};

/// Maximum file size for input files (10 MB).
const MAX_INPUT_FILE_SIZE: u64 = 10 * 1024 * 1024;

/// Current schema version for generated RFCs.
const SCHEMA_VERSION: &str = "2026-01-26";

/// Errors that can occur during RFC framing.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum RfcFrameError {
    /// Grounding error.
    #[error("{0}")]
    Grounding(#[from] GroundingError),

    /// Path validation failed.
    #[error("path validation failed: {0}")]
    PathValidation(#[from] PathValidationError),

    /// Failed to read a file.
    #[error("failed to read file {path}: {reason}")]
    ReadError {
        /// Path to the file.
        path: String,
        /// Reason for the failure.
        reason: String,
    },

    /// Failed to write a file.
    #[error("failed to write file {path}: {reason}")]
    WriteError {
        /// Path to the file.
        path: String,
        /// Reason for the failure.
        reason: String,
    },

    /// Failed to create directory.
    #[error("failed to create directory {path}: {reason}")]
    DirectoryCreationError {
        /// Path to the directory.
        path: String,
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

    /// PRD not found.
    #[error("PRD not found: {path}")]
    PrdNotFound {
        /// The missing path.
        path: String,
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

    /// RFC already exists.
    #[error("RFC already exists: {path} (use --force to overwrite)")]
    RfcAlreadyExists {
        /// The existing path.
        path: String,
    },
}

/// RFC section types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RfcSectionType {
    /// `00_meta.yaml`
    Meta,
    /// `01_problem_and_imports.yaml`
    ProblemAndImports,
    /// `02_design_decisions.yaml`
    DesignDecisions,
    /// `03_trust_boundaries.yaml`
    TrustBoundaries,
    /// `04_contracts_and_versioning.yaml`
    ContractsAndVersioning,
    /// `05_rollout_and_ops.yaml`
    RolloutAndOps,
    /// `06_ticket_decomposition.yaml`
    TicketDecomposition,
    /// `07_test_and_evidence.yaml`
    TestAndEvidence,
    /// `08_risks_and_open_questions.yaml`
    RisksAndOpenQuestions,
    /// `09_governance_and_gates.yaml`
    GovernanceAndGates,
}

impl RfcSectionType {
    /// Returns the filename for this section.
    #[must_use]
    pub const fn filename(&self) -> &'static str {
        match self {
            Self::Meta => "00_meta.yaml",
            Self::ProblemAndImports => "01_problem_and_imports.yaml",
            Self::DesignDecisions => "02_design_decisions.yaml",
            Self::TrustBoundaries => "03_trust_boundaries.yaml",
            Self::ContractsAndVersioning => "04_contracts_and_versioning.yaml",
            Self::RolloutAndOps => "05_rollout_and_ops.yaml",
            Self::TicketDecomposition => "06_ticket_decomposition.yaml",
            Self::TestAndEvidence => "07_test_and_evidence.yaml",
            Self::RisksAndOpenQuestions => "08_risks_and_open_questions.yaml",
            Self::GovernanceAndGates => "09_governance_and_gates.yaml",
        }
    }

    /// Returns all section types in order.
    #[must_use]
    pub const fn all() -> [Self; 10] {
        [
            Self::Meta,
            Self::ProblemAndImports,
            Self::DesignDecisions,
            Self::TrustBoundaries,
            Self::ContractsAndVersioning,
            Self::RolloutAndOps,
            Self::TicketDecomposition,
            Self::TestAndEvidence,
            Self::RisksAndOpenQuestions,
            Self::GovernanceAndGates,
        ]
    }
}

/// A generated RFC section.
#[derive(Debug, Clone)]
pub struct RfcSection {
    /// Section type.
    pub section_type: RfcSectionType,
    /// YAML content.
    pub content: String,
}

/// Options for RFC framing.
#[derive(Debug, Clone, Default)]
pub struct RfcFrameOptions {
    /// Force overwrite if RFC already exists.
    pub force: bool,
    /// Dry run mode - compute but don't write output.
    pub dry_run: bool,
    /// Skip path validation (not recommended).
    pub skip_validation: bool,
}

/// A complete RFC frame ready for output.
#[derive(Debug, Clone)]
pub struct RfcFrame {
    /// RFC identifier.
    pub rfc_id: String,
    /// PRD identifier.
    pub prd_id: String,
    /// RFC title.
    pub title: String,
    /// CCP grounding information.
    pub ccp_grounding: CcpGrounding,
    /// Generated sections.
    pub sections: Vec<RfcSection>,
    /// Timestamp when the frame was generated.
    pub generated_at: DateTime<Utc>,
}

/// Result of an RFC frame operation.
#[derive(Debug, Clone)]
pub struct RfcFrameResult {
    /// The generated RFC frame.
    pub frame: RfcFrame,
    /// CCP grounding information.
    pub ccp_grounding: CcpGrounding,
    /// Path to the output directory.
    pub output_dir: PathBuf,
    /// Whether dry run mode was used.
    pub dry_run: bool,
}

/// Validates an ID (PRD, RFC) for path traversal attacks.
fn validate_id(id: &str) -> Result<(), RfcFrameError> {
    if id.contains('/') || id.contains('\\') || id.contains("..") {
        return Err(RfcFrameError::PathTraversalError {
            path: id.to_string(),
            reason: "ID contains invalid characters".to_string(),
        });
    }
    Ok(())
}

/// Reads a file with size limits.
fn read_file_bounded(path: &Path, max_size: u64) -> Result<String, RfcFrameError> {
    let metadata = fs::metadata(path).map_err(|e| RfcFrameError::ReadError {
        path: path.display().to_string(),
        reason: e.to_string(),
    })?;

    let size = metadata.len();
    if size > max_size {
        return Err(RfcFrameError::FileTooLarge {
            path: path.display().to_string(),
            size,
            max_size,
        });
    }

    let file = File::open(path).map_err(|e| RfcFrameError::ReadError {
        path: path.display().to_string(),
        reason: e.to_string(),
    })?;

    let mut content = String::new();
    file.take(max_size)
        .read_to_string(&mut content)
        .map_err(|e| RfcFrameError::ReadError {
            path: path.display().to_string(),
            reason: e.to_string(),
        })?;

    Ok(content)
}

/// Loads the Impact Map for a PRD.
fn load_impact_map(repo_root: &Path, prd_id: &str) -> Result<serde_yaml::Value, RfcFrameError> {
    let impact_map_path = repo_root
        .join("evidence")
        .join("prd")
        .join(prd_id)
        .join("impact_map")
        .join("impact_map.yaml");

    if !impact_map_path.exists() {
        return Err(RfcFrameError::ImpactMapNotFound {
            path: impact_map_path.display().to_string(),
        });
    }

    let content = read_file_bounded(&impact_map_path, MAX_INPUT_FILE_SIZE)?;

    serde_yaml::from_str(&content).map_err(|e| RfcFrameError::ImpactMapParseError {
        reason: e.to_string(),
    })
}

/// Loads the PRD meta information.
fn load_prd_meta(repo_root: &Path, prd_id: &str) -> Result<serde_yaml::Value, RfcFrameError> {
    let prd_meta_path = repo_root
        .join("documents")
        .join("prds")
        .join(prd_id)
        .join("00_meta.yaml");

    if !prd_meta_path.exists() {
        return Err(RfcFrameError::PrdNotFound {
            path: prd_meta_path.display().to_string(),
        });
    }

    let content = read_file_bounded(&prd_meta_path, MAX_INPUT_FILE_SIZE)?;

    serde_yaml::from_str(&content).map_err(|e| RfcFrameError::ImpactMapParseError {
        reason: format!("PRD meta parse error: {e}"),
    })
}

/// Generates the `00_meta.yaml` section.
fn generate_meta_section(
    rfc_id: &str,
    prd_id: &str,
    title: &str,
    ccp_grounding: &CcpGrounding,
) -> Result<String, RfcFrameError> {
    let meta = serde_yaml::to_value(serde_json::json!({
        "rfc_meta": {
            "schema_version": SCHEMA_VERSION,
            "template_version": SCHEMA_VERSION,
            "rfc": {
                "id": rfc_id,
                "title": title,
                "status": "DRAFT",
                "created_date": Utc::now().format("%Y-%m-%d").to_string(),
                "last_updated_date": Utc::now().format("%Y-%m-%d").to_string()
            },
            "binds_to_prd": {
                "prd_id": prd_id,
                "prd_base_path": format!("documents/prds/{prd_id}"),
                "requirement_registry_ref": format!("documents/prds/{prd_id}/requirements/"),
                "evidence_bundle_ref": format!("documents/prds/{prd_id}/12_evidence_bundle.yaml"),
                "prd_meta_ref": format!("documents/prds/{prd_id}/00_meta.yaml"),
                "rationale": format!("Implements {prd_id} requirements")
            },
            "protocol_profile": {
                "id": "NONE",
                "applies": false,
                "inherited_from_prd": true,
                "profile_ref": ""
            },
            "ccp_grounding": {
                "ccp_index_ref": &ccp_grounding.ccp_index_ref,
                "ccp_index_hash": &ccp_grounding.ccp_index_hash,
                "impact_map_ref": &ccp_grounding.impact_map_ref,
                "rationale": &ccp_grounding.rationale
            },
            "custody": {
                "producing_agent_roles": ["AGENT_AUTHOR", "AGENT_ARCHITECT"],
                "responsible_domains": ["DOMAIN_BUILD_RELEASE", "DOMAIN_RUNTIME"],
                "authority_signoffs_required": ["AUTH_ARCHITECTURE", "AUTH_PRODUCT"]
            }
        }
    }))
    .map_err(|e| RfcFrameError::YamlSerializationError {
        reason: e.to_string(),
    })?;

    canonicalize_yaml(&meta).map_err(Into::into)
}

/// Generates the `01_problem_and_imports.yaml` section.
fn generate_problem_section(
    prd_id: &str,
    impact_map: &serde_yaml::Value,
    ccp_grounding: &CcpGrounding,
) -> Result<String, RfcFrameError> {
    // Extract requirement IDs from impact map
    let mut requirement_refs = Vec::new();
    if let Some(mappings) = impact_map.get("requirement_mappings") {
        if let Some(mapping_array) = mappings.as_sequence() {
            for mapping in mapping_array {
                if let Some(req_id) = mapping.get("requirement_id").and_then(|v| v.as_str()) {
                    let title = mapping
                        .get("requirement_title")
                        .and_then(|v| v.as_str())
                        .unwrap_or("Untitled");
                    requirement_refs.push(serde_json::json!({
                        "id": req_id,
                        "title": title,
                        "ref": format!("documents/prds/{prd_id}/requirements/{req_id}.yaml#prd_requirement")
                    }));
                }
            }
        }
    }

    // Build component dependencies
    let component_deps: Vec<serde_json::Value> = ccp_grounding
        .component_references
        .iter()
        .map(|c| {
            serde_json::json!({
                "id": c.id,
                "ref": c.r#ref,
                "rationale": c.rationale
            })
        })
        .collect();

    let problem = serde_yaml::to_value(serde_json::json!({
        "rfc_problem_and_imports": {
            "schema_version": SCHEMA_VERSION,
            "template_version": SCHEMA_VERSION,
            "problem_statement": {
                "summary": "TODO: Add problem summary from PRD",
                "prd_ref": format!("documents/prds/{prd_id}/02_problem.yaml#prd_problem")
            },
            "imported_requirements": requirement_refs,
            "ccp_grounding": {
                "ccp_index_ref": &ccp_grounding.ccp_index_ref,
                "component_dependencies": component_deps
            }
        }
    }))
    .map_err(|e| RfcFrameError::YamlSerializationError {
        reason: e.to_string(),
    })?;

    canonicalize_yaml(&problem).map_err(Into::into)
}

/// Generates the `02_design_decisions.yaml` section.
fn generate_design_section(_impact_map: &serde_yaml::Value) -> Result<String, RfcFrameError> {
    // Note: Future enhancement could extract net-new modules from impact_map
    // for populating the design decisions section with actual data.

    let design = serde_yaml::to_value(serde_json::json!({
        "rfc_design_decisions": {
            "schema_version": SCHEMA_VERSION,
            "template_version": SCHEMA_VERSION,
            "design_space_exploration": {
                "prd_ref": "TODO: Add PRD solution reference",
                "options": [
                    {
                        "option_id": "OPT-A",
                        "name": "TODO: Option A name",
                        "description": "TODO: Describe option A",
                        "evaluation": {
                            "strengths": ["TODO: List strengths"],
                            "weaknesses": ["TODO: List weaknesses"]
                        }
                    }
                ],
                "selected_approach": {
                    "choice": "OPT-A",
                    "rationale": "TODO: Explain selection rationale"
                }
            },
            "architecture_decisions": [
                {
                    "decision_id": "AD-001",
                    "title": "TODO: Decision title",
                    "description": "TODO: Describe the architectural decision",
                    "rationale": "TODO: Explain why this decision was made",
                    "impact_map_ref": "TODO: Reference to impact map"
                }
            ]
        }
    }))
    .map_err(|e| RfcFrameError::YamlSerializationError {
        reason: e.to_string(),
    })?;

    canonicalize_yaml(&design).map_err(Into::into)
}

/// Generates a skeleton section with standard structure.
fn generate_skeleton_section(section_type: RfcSectionType) -> Result<String, RfcFrameError> {
    let section_name = match section_type {
        RfcSectionType::TrustBoundaries => "rfc_trust_boundaries",
        RfcSectionType::ContractsAndVersioning => "rfc_contracts_and_versioning",
        RfcSectionType::RolloutAndOps => "rfc_rollout_and_ops",
        RfcSectionType::TestAndEvidence => "rfc_test_and_evidence",
        RfcSectionType::RisksAndOpenQuestions => "rfc_risks_and_open_questions",
        RfcSectionType::GovernanceAndGates => "rfc_governance_and_gates",
        _ => {
            return Err(RfcFrameError::YamlSerializationError {
                reason: "Invalid section type for skeleton".to_string(),
            });
        },
    };

    let content = match section_type {
        RfcSectionType::TrustBoundaries => serde_json::json!({
            section_name: {
                "schema_version": SCHEMA_VERSION,
                "template_version": SCHEMA_VERSION,
                "trust_model": {
                    "overview": "TODO: Describe trust model",
                    "boundaries": []
                },
                "threat_model": [],
                "security_contacts": []
            }
        }),
        RfcSectionType::ContractsAndVersioning => serde_json::json!({
            section_name: {
                "schema_version": SCHEMA_VERSION,
                "template_version": SCHEMA_VERSION,
                "api_contracts": [],
                "versioning_strategy": {
                    "schema_versioning": "TODO: Describe schema versioning",
                    "artifact_versioning": "TODO: Describe artifact versioning",
                    "backwards_compatibility": "TODO: Describe compatibility"
                }
            }
        }),
        RfcSectionType::RolloutAndOps => serde_json::json!({
            section_name: {
                "schema_version": SCHEMA_VERSION,
                "template_version": SCHEMA_VERSION,
                "rollout_phases": [],
                "operational_considerations": {
                    "monitoring": "TODO: Describe monitoring",
                    "alerting": "TODO: Describe alerting",
                    "runbooks": []
                }
            }
        }),
        RfcSectionType::TestAndEvidence => serde_json::json!({
            section_name: {
                "schema_version": SCHEMA_VERSION,
                "template_version": SCHEMA_VERSION,
                "test_strategy": {
                    "unit_tests": "TODO: Describe unit test strategy",
                    "integration_tests": "TODO: Describe integration test strategy",
                    "property_tests": "TODO: Describe property test strategy"
                },
                "evidence_requirements": [],
                "acceptance_criteria": []
            }
        }),
        RfcSectionType::RisksAndOpenQuestions => serde_json::json!({
            section_name: {
                "schema_version": SCHEMA_VERSION,
                "template_version": SCHEMA_VERSION,
                "risks": [],
                "open_questions": [],
                "dependencies": []
            }
        }),
        RfcSectionType::GovernanceAndGates => serde_json::json!({
            section_name: {
                "schema_version": SCHEMA_VERSION,
                "template_version": SCHEMA_VERSION,
                "approval_gates": [],
                "review_requirements": {
                    "required_reviewers": [],
                    "review_criteria": []
                },
                "sign_off_status": {
                    "architecture": "PENDING",
                    "security": "PENDING",
                    "product": "PENDING"
                }
            }
        }),
        _ => {
            return Err(RfcFrameError::YamlSerializationError {
                reason: "Invalid section type".to_string(),
            });
        },
    };

    let yaml_value =
        serde_yaml::to_value(content).map_err(|e| RfcFrameError::YamlSerializationError {
            reason: e.to_string(),
        })?;

    canonicalize_yaml(&yaml_value).map_err(Into::into)
}

/// Generates the `06_ticket_decomposition.yaml` section.
fn generate_ticket_section(
    impact_map: &serde_yaml::Value,
    _ccp_grounding: &CcpGrounding,
) -> Result<String, RfcFrameError> {
    // Extract requirements and build tickets
    let mut tickets = Vec::new();
    let mut ticket_counter = 1;

    if let Some(mappings) = impact_map.get("requirement_mappings") {
        if let Some(mapping_array) = mappings.as_sequence() {
            for mapping in mapping_array {
                let req_id = mapping
                    .get("requirement_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("REQ-XXXX");
                let req_title = mapping
                    .get("requirement_title")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Untitled");

                // Get primary component from candidates
                let component_id = mapping
                    .get("candidates")
                    .and_then(|c| c.as_sequence())
                    .and_then(|arr| arr.first())
                    .and_then(|c| c.get("component_id"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("COMP-UNKNOWN");

                tickets.push(serde_json::json!({
                    "ticket_id": format!("TCK-{ticket_counter:05}"),
                    "title": req_title,
                    "phase": "PHASE-1",
                    "requirement_ids": [req_id],
                    "description": format!("Implement {} as specified in {}", req_title, req_id),
                    "ccp_component": component_id,
                    "files_to_create": [],
                    "files_to_modify": [],
                    "verification_commands": ["cargo test", "cargo clippy -D warnings"],
                    "acceptance_criteria": ["TODO: Define acceptance criteria"],
                    "blocked_by": []
                }));

                ticket_counter += 1;
            }
        }
    }

    let decomposition = serde_yaml::to_value(serde_json::json!({
        "rfc_ticket_decomposition": {
            "schema_version": SCHEMA_VERSION,
            "template_version": SCHEMA_VERSION,
            "decomposition_strategy": "Tickets are organized by requirement mapping from Impact Map.",
            "tickets": tickets,
            "dependency_graph": "TODO: Generate dependency graph",
            "summary": {
                "total_tickets": tickets.len(),
                "by_phase": {
                    "PHASE-1": tickets.len()
                }
            }
        }
    }))
    .map_err(|e| RfcFrameError::YamlSerializationError {
        reason: e.to_string(),
    })?;

    canonicalize_yaml(&decomposition).map_err(Into::into)
}

/// Writes RFC sections to the output directory.
fn write_rfc_sections(output_dir: &Path, sections: &[RfcSection]) -> Result<(), RfcFrameError> {
    // Create output directory
    fs::create_dir_all(output_dir).map_err(|e| RfcFrameError::DirectoryCreationError {
        path: output_dir.display().to_string(),
        reason: e.to_string(),
    })?;

    // Write each section atomically
    for section in sections {
        let section_path = output_dir.join(section.section_type.filename());
        write_atomic(&section_path, section.content.as_bytes())?;
        debug!(path = %section_path.display(), "Wrote RFC section");
    }

    Ok(())
}

/// Frames an RFC from Impact Map and CCP artifacts.
///
/// This function:
/// 1. Loads the Impact Map for the PRD
/// 2. Creates CCP grounding section with index hash
/// 3. Optionally validates file paths against CCP
/// 4. Generates all RFC sections
/// 5. Writes sections atomically to output directory
///
/// # Arguments
///
/// * `repo_root` - Path to the repository root
/// * `prd_id` - PRD identifier (e.g., "PRD-0005")
/// * `rfc_id` - RFC identifier (e.g., "RFC-0011")
/// * `options` - Frame options (force, `dry_run`, `skip_validation`)
///
/// # Errors
///
/// Returns an error if:
/// - Impact Map or CCP index doesn't exist
/// - Path validation fails (unless skipped)
/// - File operations fail
///
/// # Example
///
/// ```rust,no_run
/// use std::path::Path;
///
/// use apm2_core::rfc_framer::{RfcFrameOptions, frame_rfc};
///
/// let result = frame_rfc(
///     Path::new("/repo/root"),
///     "PRD-0005",
///     "RFC-0011",
///     &RfcFrameOptions::default(),
/// )
/// .unwrap();
///
/// println!("RFC framed with {} sections", result.frame.sections.len());
/// ```
#[allow(clippy::too_many_lines)]
pub fn frame_rfc(
    repo_root: &Path,
    prd_id: &str,
    rfc_id: &str,
    options: &RfcFrameOptions,
) -> Result<RfcFrameResult, RfcFrameError> {
    // Validate IDs
    validate_id(prd_id)?;
    validate_id(rfc_id)?;

    info!(
        repo_root = %repo_root.display(),
        prd_id = %prd_id,
        rfc_id = %rfc_id,
        force = options.force,
        dry_run = options.dry_run,
        "Framing RFC"
    );

    // Check if RFC already exists
    let output_dir = repo_root.join("documents").join("rfcs").join(rfc_id);
    if output_dir.exists() && !options.force {
        return Err(RfcFrameError::RfcAlreadyExists {
            path: output_dir.display().to_string(),
        });
    }

    // Create CCP grounding
    debug!("Creating CCP grounding");
    let ccp_grounding = CcpGrounding::from_artifacts(repo_root, prd_id)?;
    debug!(
        ccp_index_hash = %ccp_grounding.ccp_index_hash,
        component_count = ccp_grounding.component_references.len(),
        "CCP grounding created"
    );

    // Load Impact Map
    debug!("Loading Impact Map");
    let impact_map = load_impact_map(repo_root, prd_id)?;

    // Load PRD meta for title
    let prd_meta = load_prd_meta(repo_root, prd_id).ok();
    let rfc_title = prd_meta
        .as_ref()
        .and_then(|m| m.get("prd_meta"))
        .and_then(|m| m.get("prd"))
        .and_then(|p| p.get("title"))
        .and_then(|t| t.as_str())
        .unwrap_or("Untitled RFC")
        .to_string();

    // Path validation (optional but recommended)
    if !options.skip_validation {
        debug!("Validating paths against CCP");
        // For now, we don't have specific files to validate yet
        // This will be populated when ticket decomposition is refined
        let validation_result = validate_paths(repo_root, prd_id, &[], &[])?;
        validation_result.into_result()?;
    }

    // Generate all sections
    debug!("Generating RFC sections");
    let mut sections = Vec::new();

    // 00_meta.yaml
    sections.push(RfcSection {
        section_type: RfcSectionType::Meta,
        content: generate_meta_section(rfc_id, prd_id, &rfc_title, &ccp_grounding)?,
    });

    // 01_problem_and_imports.yaml
    sections.push(RfcSection {
        section_type: RfcSectionType::ProblemAndImports,
        content: generate_problem_section(prd_id, &impact_map, &ccp_grounding)?,
    });

    // 02_design_decisions.yaml
    sections.push(RfcSection {
        section_type: RfcSectionType::DesignDecisions,
        content: generate_design_section(&impact_map)?,
    });

    // 03-05, 07-09: Skeleton sections
    for section_type in [
        RfcSectionType::TrustBoundaries,
        RfcSectionType::ContractsAndVersioning,
        RfcSectionType::RolloutAndOps,
    ] {
        sections.push(RfcSection {
            section_type,
            content: generate_skeleton_section(section_type)?,
        });
    }

    // 06_ticket_decomposition.yaml
    sections.push(RfcSection {
        section_type: RfcSectionType::TicketDecomposition,
        content: generate_ticket_section(&impact_map, &ccp_grounding)?,
    });

    // 07-09: More skeleton sections
    for section_type in [
        RfcSectionType::TestAndEvidence,
        RfcSectionType::RisksAndOpenQuestions,
        RfcSectionType::GovernanceAndGates,
    ] {
        sections.push(RfcSection {
            section_type,
            content: generate_skeleton_section(section_type)?,
        });
    }

    // Sort sections by type for determinism
    sections.sort_by_key(|s| s.section_type.filename());

    // Create RFC frame
    let frame = RfcFrame {
        rfc_id: rfc_id.to_string(),
        prd_id: prd_id.to_string(),
        title: rfc_title,
        ccp_grounding: ccp_grounding.clone(),
        sections: sections.clone(),
        generated_at: Utc::now(),
    };

    // Write output (unless dry run)
    if options.dry_run {
        info!(
            section_count = frame.sections.len(),
            "Dry run - skipping file writes"
        );
    } else {
        write_rfc_sections(&output_dir, &sections)?;
        info!(
            output_dir = %output_dir.display(),
            section_count = sections.len(),
            "RFC framed successfully"
        );
    }

    Ok(RfcFrameResult {
        frame,
        ccp_grounding,
        output_dir,
        dry_run: options.dry_run,
    })
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::*;

    /// Creates test artifacts for RFC framing.
    fn create_test_artifacts(root: &Path) {
        // Create CCP index
        let ccp_dir = root.join("evidence/prd/PRD-TEST/ccp");
        fs::create_dir_all(&ccp_dir).unwrap();
        fs::write(
            ccp_dir.join("ccp_index.json"),
            r#"{
                "schema_version": "2026-01-26",
                "index_hash": "abc1234567890",
                "file_inventory": {
                    "file_count": 2,
                    "files": [
                        {"path": "crates/apm2-core/src/lib.rs", "hash": "aaa", "size": 100},
                        {"path": "crates/apm2-cli/src/main.rs", "hash": "bbb", "size": 200}
                    ]
                }
            }"#,
        )
        .unwrap();

        // Create Impact Map
        let impact_map_dir = root.join("evidence/prd/PRD-TEST/impact_map");
        fs::create_dir_all(&impact_map_dir).unwrap();
        fs::write(
            impact_map_dir.join("impact_map.yaml"),
            r#"schema_version: "2026-01-26"
prd_id: PRD-TEST
ccp_index_hash: abc1234
content_hash: def5678
summary:
  total_requirements: 2
  high_confidence_matches: 1
  needs_review: 1
requirement_mappings:
  - requirement_id: REQ-0001
    requirement_title: "CLI entrypoint"
    requirement_statement: "Provide CLI commands"
    candidates:
      - component_id: COMP-CLI
        component_name: apm2-cli
        fit_score: high
        rationale: "CLI entrypoint"
        similarity_score: 0.8
    needs_review: false
  - requirement_id: REQ-0002
    requirement_title: "Core library"
    requirement_statement: "Provide core functionality"
    candidates:
      - component_id: COMP-CORE
        component_name: apm2-core
        fit_score: medium
        rationale: "Core library"
        similarity_score: 0.6
    needs_review: true
adjudication:
  duplication_risks: []
  net_new_requirements: []
  total_requirements: 2
  high_confidence_count: 1
  needs_review_count: 1
"#,
        )
        .unwrap();

        // Create PRD meta
        let prd_dir = root.join("documents/prds/PRD-TEST");
        fs::create_dir_all(&prd_dir).unwrap();
        fs::write(
            prd_dir.join("00_meta.yaml"),
            r#"prd_meta:
  schema_version: "2026-01-26"
  prd:
    id: PRD-TEST
    title: "Test PRD for RFC Framing"
    status: APPROVED
"#,
        )
        .unwrap();
    }

    /// UT-115-01: Test RFC template loading and section generation.
    #[test]
    fn test_rfc_section_generation() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();
        create_test_artifacts(root);

        let result = frame_rfc(
            root,
            "PRD-TEST",
            "RFC-TEST",
            &RfcFrameOptions {
                force: false,
                dry_run: true,
                skip_validation: true,
            },
        )
        .unwrap();

        // Verify all 10 sections generated
        assert_eq!(result.frame.sections.len(), 10);

        // Verify section types
        let section_types: Vec<_> = result
            .frame
            .sections
            .iter()
            .map(|s| s.section_type)
            .collect();
        assert!(section_types.contains(&RfcSectionType::Meta));
        assert!(section_types.contains(&RfcSectionType::ProblemAndImports));
        assert!(section_types.contains(&RfcSectionType::TicketDecomposition));
    }

    /// UT-115-02: Test Impact Map consumption.
    #[test]
    fn test_impact_map_consumption() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();
        create_test_artifacts(root);

        let result = frame_rfc(
            root,
            "PRD-TEST",
            "RFC-TEST",
            &RfcFrameOptions {
                force: false,
                dry_run: true,
                skip_validation: true,
            },
        )
        .unwrap();

        // Check that CCP grounding includes component references
        assert!(!result.ccp_grounding.component_references.is_empty());

        // Check ticket decomposition includes requirements
        let ticket_section = result
            .frame
            .sections
            .iter()
            .find(|s| s.section_type == RfcSectionType::TicketDecomposition)
            .unwrap();

        assert!(
            ticket_section.content.contains("REQ-0001") || ticket_section.content.contains("TCK-")
        );
    }

    /// UT-115-03: Test CCP grounding section in meta.
    #[test]
    fn test_ccp_grounding_in_meta() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();
        create_test_artifacts(root);

        let result = frame_rfc(
            root,
            "PRD-TEST",
            "RFC-TEST",
            &RfcFrameOptions {
                force: false,
                dry_run: true,
                skip_validation: true,
            },
        )
        .unwrap();

        let meta_section = result
            .frame
            .sections
            .iter()
            .find(|s| s.section_type == RfcSectionType::Meta)
            .unwrap();

        // Verify CCP grounding is present
        assert!(meta_section.content.contains("ccp_grounding"));
        assert!(meta_section.content.contains("ccp_index_hash"));
        assert!(
            meta_section
                .content
                .contains(&result.ccp_grounding.ccp_index_hash)
        );
    }

    /// Test RFC already exists error.
    #[test]
    fn test_rfc_already_exists() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();
        create_test_artifacts(root);

        // Create existing RFC directory
        let rfc_dir = root.join("documents/rfcs/RFC-EXISTING");
        fs::create_dir_all(&rfc_dir).unwrap();

        let result = frame_rfc(
            root,
            "PRD-TEST",
            "RFC-EXISTING",
            &RfcFrameOptions::default(),
        );

        assert!(matches!(
            result,
            Err(RfcFrameError::RfcAlreadyExists { .. })
        ));
    }

    /// Test force overwrite.
    #[test]
    fn test_force_overwrite() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();
        create_test_artifacts(root);

        // Create existing RFC directory
        let rfc_dir = root.join("documents/rfcs/RFC-FORCE");
        fs::create_dir_all(&rfc_dir).unwrap();

        let result = frame_rfc(
            root,
            "PRD-TEST",
            "RFC-FORCE",
            &RfcFrameOptions {
                force: true,
                dry_run: false,
                skip_validation: true,
            },
        );

        assert!(result.is_ok(), "Force should allow overwrite");
    }

    /// Test ID validation rejects traversal.
    #[test]
    fn test_id_validation() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();

        let result = frame_rfc(
            root,
            "PRD-../../../etc",
            "RFC-TEST",
            &RfcFrameOptions::default(),
        );
        assert!(matches!(
            result,
            Err(RfcFrameError::PathTraversalError { .. })
        ));

        let result = frame_rfc(root, "PRD-TEST", "RFC/../hack", &RfcFrameOptions::default());
        assert!(matches!(
            result,
            Err(RfcFrameError::PathTraversalError { .. })
        ));
    }

    /// Test section type filenames.
    #[test]
    fn test_section_type_filenames() {
        assert_eq!(RfcSectionType::Meta.filename(), "00_meta.yaml");
        assert_eq!(
            RfcSectionType::ProblemAndImports.filename(),
            "01_problem_and_imports.yaml"
        );
        assert_eq!(
            RfcSectionType::TicketDecomposition.filename(),
            "06_ticket_decomposition.yaml"
        );
        assert_eq!(
            RfcSectionType::GovernanceAndGates.filename(),
            "09_governance_and_gates.yaml"
        );
    }

    /// IT-115-01: Full integration test - RFC generation.
    #[test]
    fn test_full_rfc_generation() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();
        create_test_artifacts(root);

        let result = frame_rfc(
            root,
            "PRD-TEST",
            "RFC-FULL",
            &RfcFrameOptions {
                force: false,
                dry_run: false,
                skip_validation: true,
            },
        )
        .unwrap();

        // Verify output directory exists
        assert!(result.output_dir.exists());

        // Verify all section files exist
        for section_type in RfcSectionType::all() {
            let section_path = result.output_dir.join(section_type.filename());
            assert!(
                section_path.exists(),
                "Section file should exist: {}",
                section_type.filename()
            );

            // Verify file is valid YAML
            let content = fs::read_to_string(&section_path).unwrap();
            let _: serde_yaml::Value = serde_yaml::from_str(&content)
                .unwrap_or_else(|e| panic!("Invalid YAML in {}: {}", section_type.filename(), e));
        }
    }
}
