#![allow(clippy::disallowed_methods)] // Metadata/observability usage or adapter.
//! Core ticket emission logic from RFC decomposition.
//!
//! This module provides:
//! - RFC decomposition parsing from `06_ticket_decomposition.yaml`
//! - Stable ticket ID generation
//! - Verification command generation from acceptance criteria
//! - Atomic ticket YAML output following the ticket schema
//!
//! # Ticket Structure
//!
//! Generated tickets follow the schema:
//! - `schema_version`: Schema version for compatibility
//! - `template_version`: Template version for consistency
//! - `ticket`: Core metadata (id, title, status, `rfc_id`, `requirement_ids`,
//!   `depends_on`)
//! - `implementation`: Summary, `files_to_create`, `files_to_modify`,
//!   `implementation_steps`
//! - `acceptance_criteria`: Verification criteria
//! - `test_requirements`: Test definitions with verification commands
//! - `notes`: Additional context

use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use chrono::Utc;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, info, warn};

use super::validation::{TicketValidationError, validate_ticket_paths};
use crate::determinism::{AtomicWriteError, CanonicalizeError, canonicalize_yaml, write_atomic};

/// Maximum file size for input files (10 MB).
const MAX_INPUT_FILE_SIZE: u64 = 10 * 1024 * 1024;

/// Current schema version for generated tickets.
const SCHEMA_VERSION: &str = "2026-01-26";

/// Errors that can occur during ticket emission.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum TicketEmitError {
    /// RFC decomposition not found.
    #[error("RFC ticket decomposition not found: {path}")]
    DecompositionNotFound {
        /// The missing path.
        path: String,
    },

    /// RFC decomposition parse error.
    #[error("failed to parse RFC decomposition: {reason}")]
    DecompositionParseError {
        /// Reason for the failure.
        reason: String,
    },

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

    /// Path validation failed.
    #[error("path validation failed: {0}")]
    PathValidation(#[from] TicketValidationError),

    /// YAML canonicalization failed.
    #[error("YAML canonicalization failed: {0}")]
    CanonicalizeError(#[from] CanonicalizeError),

    /// Atomic write failed.
    #[error("atomic write failed: {0}")]
    AtomicWriteError(#[from] AtomicWriteError),

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

    /// RFC not found.
    #[error("RFC not found: {path}")]
    RfcNotFound {
        /// The missing path.
        path: String,
    },

    /// No tickets to emit.
    #[error("no tickets found in RFC decomposition")]
    NoTickets,

    /// Ticket ID conflict.
    #[error("ticket ID conflict: {id} already exists")]
    TicketIdConflict {
        /// The conflicting ID.
        id: String,
    },
}

/// Options for ticket emission.
#[derive(Debug, Clone, Default)]
pub struct TicketEmitOptions {
    /// Force overwrite if tickets already exist.
    pub force: bool,
    /// Dry run mode - compute but don't write output.
    pub dry_run: bool,
    /// Skip path validation (not recommended).
    pub skip_validation: bool,
    /// PRD ID for CCP validation (optional).
    pub prd_id: Option<String>,
}

/// A file reference in a ticket.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TicketFile {
    /// The file path.
    pub path: String,
    /// The purpose of this file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    /// Changes to be made (for `files_to_modify`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub changes: Option<String>,
}

/// An implementation step in a ticket.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImplementationStep {
    /// Step number.
    pub step: u32,
    /// Action to take.
    pub action: String,
    /// Detailed description.
    pub details: String,
}

/// An acceptance criterion for a ticket.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptanceCriterion {
    /// The criterion description.
    pub criterion: String,
    /// How to verify this criterion.
    pub verification: String,
}

/// A test requirement for a ticket.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestRequirement {
    /// Test identifier.
    pub test_id: String,
    /// Test description.
    pub description: String,
    /// Command to verify this test.
    pub verification_command: String,
}

/// A generated ticket ready for output.
#[derive(Debug, Clone)]
pub struct EmittedTicket {
    /// Ticket identifier.
    pub id: String,
    /// Ticket title.
    pub title: String,
    /// Ticket status.
    pub status: String,
    /// RFC identifier.
    pub rfc_id: String,
    /// Requirement IDs.
    pub requirement_ids: Vec<String>,
    /// Dependencies.
    pub depends_on: Vec<String>,
    /// Implementation summary.
    pub summary: String,
    /// Files to create.
    pub files_to_create: Vec<TicketFile>,
    /// Files to modify.
    pub files_to_modify: Vec<TicketFile>,
    /// Implementation steps.
    pub implementation_steps: Vec<ImplementationStep>,
    /// Acceptance criteria.
    pub acceptance_criteria: Vec<AcceptanceCriterion>,
    /// Test requirements.
    pub test_requirements: Vec<TestRequirement>,
    /// Additional notes.
    pub notes: String,
    /// Generated YAML content.
    pub yaml_content: String,
}

/// Result of a ticket emission operation.
#[derive(Debug, Clone)]
pub struct TicketEmitResult {
    /// The emitted tickets.
    pub tickets: Vec<EmittedTicket>,
    /// RFC identifier.
    pub rfc_id: String,
    /// Path to the output directory.
    pub output_dir: PathBuf,
    /// Whether dry run mode was used.
    pub dry_run: bool,
    /// Warnings encountered during emission.
    pub warnings: Vec<String>,
}

/// Validates an RFC ID against the strict project pattern.
///
/// RFC IDs must match the pattern `RFC-NNNN` (where N is a digit, minimum 4
/// digits). This prevents:
/// - Path traversal attacks (e.g., `RFC-../../../etc`)
/// - Shell injection (e.g., `RFC-0010;ls`, `RFC-0010|evil`)
///
/// # Errors
///
/// Returns `TicketEmitError::PathTraversalError` if the ID is invalid.
fn validate_rfc_id(id: &str) -> Result<(), TicketEmitError> {
    // Strict pattern: RFC- followed by at least 4 digits
    let is_valid = id.len() >= 8
        && id.starts_with("RFC-")
        && id[4..].chars().all(|c| c.is_ascii_digit())
        && id.len() <= 12; // Reasonable upper bound: RFC-99999999

    if !is_valid {
        return Err(TicketEmitError::PathTraversalError {
            path: id.to_string(),
            reason: "RFC ID must match pattern RFC-NNNN (e.g., RFC-0010)".to_string(),
        });
    }
    Ok(())
}

/// Validates a ticket ID against the strict project standard pattern.
///
/// Ticket IDs must match the pattern `TCK-NNNNN` (where N is a digit).
/// This prevents:
/// - Path traversal attacks (e.g., `../evil`, `TCK/../../etc`)
/// - Shell injection (e.g., `TCK;rm -rf /`, `TCK|evil`, `TCK$(cmd)`)
///
/// # Errors
///
/// Returns `TicketEmitError::PathTraversalError` if the ID is invalid.
fn validate_ticket_id(id: &str) -> Result<(), TicketEmitError> {
    // Strict pattern: TCK- followed by exactly 5 digits
    let is_valid =
        id.len() == 9 && id.starts_with("TCK-") && id[4..].chars().all(|c| c.is_ascii_digit());

    if !is_valid {
        return Err(TicketEmitError::PathTraversalError {
            path: id.to_string(),
            reason: "Ticket ID must match pattern TCK-NNNNN (e.g., TCK-00001)".to_string(),
        });
    }

    Ok(())
}

/// Reads a file with size limits.
fn read_file_bounded(path: &Path, max_size: u64) -> Result<String, TicketEmitError> {
    let metadata = fs::metadata(path).map_err(|e| TicketEmitError::ReadError {
        path: path.display().to_string(),
        reason: e.to_string(),
    })?;

    let size = metadata.len();
    if size > max_size {
        return Err(TicketEmitError::FileTooLarge {
            path: path.display().to_string(),
            size,
            max_size,
        });
    }

    let file = File::open(path).map_err(|e| TicketEmitError::ReadError {
        path: path.display().to_string(),
        reason: e.to_string(),
    })?;

    let mut content = String::new();
    file.take(max_size)
        .read_to_string(&mut content)
        .map_err(|e| TicketEmitError::ReadError {
            path: path.display().to_string(),
            reason: e.to_string(),
        })?;

    Ok(content)
}

/// Loads the RFC ticket decomposition.
fn load_decomposition(
    repo_root: &Path,
    rfc_id: &str,
) -> Result<serde_yaml::Value, TicketEmitError> {
    let decomposition_path = repo_root
        .join("documents")
        .join("rfcs")
        .join(rfc_id)
        .join("06_ticket_decomposition.yaml");

    if !decomposition_path.exists() {
        return Err(TicketEmitError::DecompositionNotFound {
            path: decomposition_path.display().to_string(),
        });
    }

    let content = read_file_bounded(&decomposition_path, MAX_INPUT_FILE_SIZE)?;

    serde_yaml::from_str(&content).map_err(|e| TicketEmitError::DecompositionParseError {
        reason: e.to_string(),
    })
}

/// Gets existing ticket IDs from the tickets directory.
fn get_existing_ticket_ids(repo_root: &Path) -> HashSet<String> {
    let tickets_dir = repo_root.join("documents").join("work").join("tickets");
    let mut ids = HashSet::new();

    if let Ok(entries) = fs::read_dir(&tickets_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "yaml") {
                if let Some(stem) = path.file_stem() {
                    if let Some(name) = stem.to_str() {
                        if name.starts_with("TCK-") {
                            ids.insert(name.to_string());
                        }
                    }
                }
            }
        }
    }

    ids
}

/// Extracts files from a YAML array.
fn extract_files(yaml: &serde_yaml::Value) -> Vec<TicketFile> {
    let mut files = Vec::new();

    if let Some(file_array) = yaml.as_sequence() {
        for file in file_array {
            let path = if let Some(p) = file.as_str() {
                p.to_string()
            } else if let Some(p) = file.get("path").and_then(|v| v.as_str()) {
                p.to_string()
            } else {
                continue;
            };

            let purpose = file
                .get("purpose")
                .and_then(|v| v.as_str())
                .map(String::from);
            let changes = file
                .get("changes")
                .and_then(|v| v.as_str())
                .map(String::from);

            files.push(TicketFile {
                path,
                purpose,
                changes,
            });
        }
    }

    files
}

/// Extracts string array from YAML.
fn extract_string_array(yaml: &serde_yaml::Value) -> Vec<String> {
    yaml.as_sequence()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

/// Generates default verification commands for a ticket.
fn generate_verification_commands(rfc_id: &str, ticket_id: &str) -> Vec<TestRequirement> {
    vec![
        TestRequirement {
            test_id: format!("UT-{}-01", &ticket_id[4..]),
            description: "Unit tests pass".to_string(),
            verification_command: format!(
                "cargo test -p apm2-core {}",
                ticket_id.to_lowercase().replace('-', "_")
            ),
        },
        TestRequirement {
            test_id: format!("IT-{}-01", &ticket_id[4..]),
            description: "Integration test".to_string(),
            verification_command: format!(
                "cargo run --bin apm2 -- factory tickets emit --rfc {rfc_id}"
            ),
        },
    ]
}

/// Generates ticket YAML content.
fn generate_ticket_yaml(ticket: &EmittedTicket) -> Result<String, TicketEmitError> {
    // Build files_to_create array
    let files_to_create: Vec<serde_json::Value> = ticket
        .files_to_create
        .iter()
        .map(|f| {
            let mut obj = serde_json::json!({
                "path": f.path
            });
            if let Some(ref purpose) = f.purpose {
                obj["purpose"] = serde_json::json!(purpose);
            }
            obj
        })
        .collect();

    // Build files_to_modify array
    let files_to_modify: Vec<serde_json::Value> = ticket
        .files_to_modify
        .iter()
        .map(|f| {
            let mut obj = serde_json::json!({
                "path": f.path
            });
            if let Some(ref changes) = f.changes {
                obj["changes"] = serde_json::json!(changes);
            }
            obj
        })
        .collect();

    // Build implementation_steps array
    let implementation_steps: Vec<serde_json::Value> = ticket
        .implementation_steps
        .iter()
        .map(|s| {
            serde_json::json!({
                "step": s.step,
                "action": s.action,
                "details": s.details
            })
        })
        .collect();

    // Build acceptance_criteria array
    let acceptance_criteria: Vec<serde_json::Value> = ticket
        .acceptance_criteria
        .iter()
        .map(|c| {
            serde_json::json!({
                "criterion": c.criterion,
                "verification": c.verification
            })
        })
        .collect();

    // Build test_requirements array
    let test_requirements: Vec<serde_json::Value> = ticket
        .test_requirements
        .iter()
        .map(|t| {
            serde_json::json!({
                "test_id": t.test_id,
                "description": t.description,
                "verification_command": t.verification_command
            })
        })
        .collect();

    let yaml_value = serde_yaml::to_value(serde_json::json!({
        "schema_version": SCHEMA_VERSION,
        "template_version": SCHEMA_VERSION,
        "ticket": {
            "id": ticket.id,
            "title": ticket.title,
            "status": ticket.status,
            "rfc_id": ticket.rfc_id,
            "requirement_ids": ticket.requirement_ids,
            "depends_on": ticket.depends_on
        },
        "implementation": {
            "summary": ticket.summary,
            "files_to_create": files_to_create,
            "files_to_modify": files_to_modify,
            "implementation_steps": implementation_steps,
            "code_examples": []
        },
        "acceptance_criteria": acceptance_criteria,
        "test_requirements": test_requirements,
        "notes": ticket.notes
    }))
    .map_err(|e| TicketEmitError::YamlSerializationError {
        reason: e.to_string(),
    })?;

    canonicalize_yaml(&yaml_value).map_err(Into::into)
}

/// Parses tickets from RFC decomposition.
#[allow(clippy::too_many_lines)]
fn parse_tickets_from_decomposition(
    decomposition: &serde_yaml::Value,
    rfc_id: &str,
    _existing_ids: &HashSet<String>,
) -> Result<Vec<EmittedTicket>, TicketEmitError> {
    // Try both possible root keys
    let tickets_yaml = decomposition
        .get("rfc_ticket_decomposition")
        .and_then(|d| d.get("tickets"))
        .or_else(|| decomposition.get("tickets"));

    let tickets_array = tickets_yaml.and_then(|t| t.as_sequence()).ok_or_else(|| {
        TicketEmitError::DecompositionParseError {
            reason: "No 'tickets' array found in decomposition".to_string(),
        }
    })?;

    if tickets_array.is_empty() {
        return Err(TicketEmitError::NoTickets);
    }

    let mut emitted_tickets = Vec::new();
    let mut id_mapping: HashMap<String, String> = HashMap::new();

    for ticket_yaml in tickets_array {
        // Get ticket ID from decomposition
        let original_id = ticket_yaml
            .get("ticket_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| TicketEmitError::DecompositionParseError {
                reason: "Ticket missing 'ticket_id' field".to_string(),
            })?;

        // Validate ticket ID to prevent path traversal and shell injection
        validate_ticket_id(original_id)?;

        // Use stable ID mapping - always use the original ID for idempotency
        let ticket_id = original_id.to_string();

        // Store mapping for dependency resolution
        id_mapping.insert(original_id.to_string(), ticket_id.clone());

        let title = ticket_yaml
            .get("title")
            .and_then(|v| v.as_str())
            .unwrap_or("Untitled")
            .to_string();

        let requirement_ids = extract_string_array(
            ticket_yaml
                .get("requirement_ids")
                .unwrap_or(&serde_yaml::Value::Null),
        );

        let depends_on = extract_string_array(
            ticket_yaml
                .get("blocked_by")
                .unwrap_or(&serde_yaml::Value::Null),
        );

        let description = ticket_yaml
            .get("description")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let files_to_create = extract_files(
            ticket_yaml
                .get("files_to_create")
                .unwrap_or(&serde_yaml::Value::Null),
        );

        let files_to_modify = extract_files(
            ticket_yaml
                .get("files_to_modify")
                .unwrap_or(&serde_yaml::Value::Null),
        );

        // Extract verification commands from decomposition
        let verification_commands = ticket_yaml
            .get("verification_commands")
            .and_then(|v| v.as_sequence())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        // Extract acceptance criteria from decomposition
        let acceptance_criteria = ticket_yaml
            .get("acceptance_criteria")
            .and_then(|v| v.as_sequence())
            .map(|arr| {
                arr.iter()
                    .enumerate()
                    .filter_map(|(i, v)| {
                        let criterion = if let Some(s) = v.as_str() {
                            s.to_string()
                        } else if let Some(c) = v.get("criterion").and_then(|x| x.as_str()) {
                            c.to_string()
                        } else {
                            return None;
                        };

                        let verification =
                            v.get("verification").and_then(|x| x.as_str()).map_or_else(
                                || {
                                    verification_commands.get(i).cloned().unwrap_or_else(|| {
                                        "Manual verification required".to_string()
                                    })
                                },
                                String::from,
                            );

                        Some(AcceptanceCriterion {
                            criterion,
                            verification,
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();

        // Generate test requirements from verification commands
        let test_requirements = if verification_commands.is_empty() {
            generate_verification_commands(rfc_id, &ticket_id)
        } else {
            verification_commands
                .iter()
                .enumerate()
                .map(|(i, cmd)| TestRequirement {
                    test_id: format!("VR-{}-{:02}", &ticket_id[4..], i + 1),
                    description: format!("Verification command {}", i + 1),
                    verification_command: cmd.clone(),
                })
                .collect()
        };

        let phase = ticket_yaml
            .get("phase")
            .and_then(|v| v.as_str())
            .unwrap_or("PHASE-1");

        let notes = format!(
            "Phase: {}\nGenerated from RFC {} ticket decomposition on {}.",
            phase,
            rfc_id,
            Utc::now().format("%Y-%m-%d")
        );

        let mut ticket = EmittedTicket {
            id: ticket_id,
            title,
            status: "READY".to_string(),
            rfc_id: rfc_id.to_string(),
            requirement_ids,
            depends_on,
            summary: description,
            files_to_create,
            files_to_modify,
            implementation_steps: Vec::new(), // Will be populated if available
            acceptance_criteria,
            test_requirements,
            notes,
            yaml_content: String::new(),
        };

        // Generate YAML content
        ticket.yaml_content = generate_ticket_yaml(&ticket)?;

        emitted_tickets.push(ticket);
    }

    // Resolve dependency IDs
    for ticket in &mut emitted_tickets {
        ticket.depends_on = ticket
            .depends_on
            .iter()
            .map(|dep| id_mapping.get(dep).cloned().unwrap_or_else(|| dep.clone()))
            .collect();
        // Regenerate YAML after dependency resolution
        ticket.yaml_content = generate_ticket_yaml(ticket)?;
    }

    Ok(emitted_tickets)
}

/// Writes tickets to the output directory.
fn write_tickets(output_dir: &Path, tickets: &[EmittedTicket]) -> Result<(), TicketEmitError> {
    // Create output directory
    fs::create_dir_all(output_dir).map_err(|e| TicketEmitError::DirectoryCreationError {
        path: output_dir.display().to_string(),
        reason: e.to_string(),
    })?;

    // Write each ticket atomically
    for ticket in tickets {
        let ticket_path = output_dir.join(format!("{}.yaml", ticket.id));
        write_atomic(&ticket_path, ticket.yaml_content.as_bytes())?;
        debug!(path = %ticket_path.display(), id = %ticket.id, "Wrote ticket");
    }

    Ok(())
}

/// Emits tickets from an RFC's ticket decomposition.
///
/// This function:
/// 1. Loads the RFC's `06_ticket_decomposition.yaml`
/// 2. Generates stable ticket IDs (idempotent)
/// 3. Optionally validates file paths against CCP
/// 4. Generates verification commands
/// 5. Writes tickets atomically to output directory
///
/// # Arguments
///
/// * `repo_root` - Path to the repository root
/// * `rfc_id` - RFC identifier (e.g., "RFC-0010")
/// * `options` - Emit options (force, `dry_run`, `skip_validation`)
///
/// # Errors
///
/// Returns an error if:
/// - RFC decomposition doesn't exist
/// - Path validation fails (unless skipped)
/// - File operations fail
///
/// # Example
///
/// ```rust,no_run
/// use std::path::Path;
///
/// use apm2_core::ticket_emitter::{TicketEmitOptions, emit_tickets};
///
/// let result = emit_tickets(
///     Path::new("/repo/root"),
///     "RFC-0010",
///     &TicketEmitOptions::default(),
/// )
/// .unwrap();
///
/// println!("Emitted {} tickets", result.tickets.len());
/// ```
pub fn emit_tickets(
    repo_root: &Path,
    rfc_id: &str,
    options: &TicketEmitOptions,
) -> Result<TicketEmitResult, TicketEmitError> {
    // Validate RFC ID
    validate_rfc_id(rfc_id)?;

    info!(
        repo_root = %repo_root.display(),
        rfc_id = %rfc_id,
        force = options.force,
        dry_run = options.dry_run,
        "Emitting tickets from RFC decomposition"
    );

    // Check RFC exists
    let rfc_dir = repo_root.join("documents").join("rfcs").join(rfc_id);
    if !rfc_dir.exists() {
        return Err(TicketEmitError::RfcNotFound {
            path: rfc_dir.display().to_string(),
        });
    }

    // Load RFC decomposition
    debug!("Loading RFC ticket decomposition");
    let decomposition = load_decomposition(repo_root, rfc_id)?;

    // Get existing ticket IDs for stable ID generation
    let existing_ids = get_existing_ticket_ids(repo_root);
    debug!(
        existing_count = existing_ids.len(),
        "Found existing ticket IDs"
    );

    // Parse tickets from decomposition
    let mut tickets = parse_tickets_from_decomposition(&decomposition, rfc_id, &existing_ids)?;

    // Path validation (required unless explicitly skipped)
    if !options.skip_validation {
        debug!("Validating ticket paths");

        let validation_input: Vec<(&str, Vec<String>, Vec<String>)> = tickets
            .iter()
            .map(|t| {
                (
                    t.id.as_str(),
                    t.files_to_modify.iter().map(|f| f.path.clone()).collect(),
                    t.files_to_create.iter().map(|f| f.path.clone()).collect(),
                )
            })
            .collect();

        let validation_result =
            validate_ticket_paths(repo_root, options.prd_id.as_deref(), &validation_input)?;

        if !validation_result.is_valid() {
            // Fail-closed: return error if any validation errors
            // SEC-EMITTER-002: Never allow invalid paths through
            let error_count = validation_result.errors.len();
            warn!(
                error_count = error_count,
                "Path validation failed - aborting emission"
            );
            return Err(validation_result.into_result().unwrap_err().into());
        }
    }

    // Check for existing tickets if not forcing
    let output_dir = repo_root.join("documents").join("work").join("tickets");
    if !options.force {
        for ticket in &tickets {
            let ticket_path = output_dir.join(format!("{}.yaml", ticket.id));
            if ticket_path.exists() && !existing_ids.contains(&ticket.id) {
                return Err(TicketEmitError::TicketIdConflict {
                    id: ticket.id.clone(),
                });
            }
        }
    }

    // Ensure all tickets have verification commands
    for ticket in &mut tickets {
        if ticket.test_requirements.is_empty() {
            ticket.test_requirements = generate_verification_commands(rfc_id, &ticket.id);
            ticket.yaml_content = generate_ticket_yaml(ticket)?;
        }
    }

    // Write output (unless dry run)
    if options.dry_run {
        info!(
            ticket_count = tickets.len(),
            "Dry run - skipping file writes"
        );
    } else {
        write_tickets(&output_dir, &tickets)?;
        info!(
            output_dir = %output_dir.display(),
            ticket_count = tickets.len(),
            "Tickets emitted successfully"
        );
    }

    Ok(TicketEmitResult {
        tickets,
        rfc_id: rfc_id.to_string(),
        output_dir,
        dry_run: options.dry_run,
        warnings: Vec::new(), // No warnings - we now fail-closed on validation errors
    })
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::*;

    /// Creates test RFC with ticket decomposition.
    fn create_test_rfc(root: &Path) {
        let rfc_dir = root.join("documents/rfcs/RFC-0000");
        fs::create_dir_all(&rfc_dir).unwrap();

        fs::write(
            rfc_dir.join("06_ticket_decomposition.yaml"),
            r#"rfc_ticket_decomposition:
  schema_version: "2026-01-26"
  template_version: "2026-01-26"
  decomposition_strategy: "Test decomposition"
  tickets:
    - ticket_id: TCK-00001
      title: "First test ticket"
      phase: PHASE-1
      requirement_ids:
        - REQ-0001
      description: "Test ticket description"
      files_to_create:
        - crates/test/src/new_module/mod.rs
      files_to_modify:
        - crates/test/src/lib.rs
      verification_commands:
        - "cargo test"
        - "cargo clippy -D warnings"
      acceptance_criteria:
        - "Tests pass"
        - "No clippy warnings"
      blocked_by: []
    - ticket_id: TCK-00002
      title: "Second test ticket"
      phase: PHASE-1
      requirement_ids:
        - REQ-0002
      description: "Second ticket depends on first"
      files_to_create:
        - crates/test/src/another/mod.rs
      files_to_modify: []
      verification_commands:
        - "cargo test another"
      acceptance_criteria:
        - "Another module works"
      blocked_by:
        - TCK-00001
  summary:
    total_tickets: 2
    by_phase:
      PHASE-1: 2
"#,
        )
        .unwrap();
    }

    /// Creates test filesystem structure.
    fn create_test_files(root: &Path) {
        let src_dir = root.join("crates/test/src");
        fs::create_dir_all(&src_dir).unwrap();
        fs::write(src_dir.join("lib.rs"), "// lib.rs").unwrap();

        let tickets_dir = root.join("documents/work/tickets");
        fs::create_dir_all(&tickets_dir).unwrap();
    }

    /// UT-116-01: Test RFC decomposition parsing.
    #[test]
    fn test_parse_decomposition() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();
        create_test_rfc(root);
        create_test_files(root);

        let result = emit_tickets(
            root,
            "RFC-0000",
            &TicketEmitOptions {
                dry_run: true,
                skip_validation: true,
                ..Default::default()
            },
        )
        .unwrap();

        assert_eq!(result.tickets.len(), 2);
        assert_eq!(result.tickets[0].id, "TCK-00001");
        assert_eq!(result.tickets[0].title, "First test ticket");
        assert_eq!(result.tickets[1].id, "TCK-00002");
    }

    /// UT-116-02: Test stable ticket ID generation.
    #[test]
    fn test_stable_ids() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();
        create_test_rfc(root);
        create_test_files(root);

        // First run
        let result1 = emit_tickets(
            root,
            "RFC-0000",
            &TicketEmitOptions {
                dry_run: true,
                skip_validation: true,
                ..Default::default()
            },
        )
        .unwrap();

        // Second run (should produce identical IDs)
        let result2 = emit_tickets(
            root,
            "RFC-0000",
            &TicketEmitOptions {
                dry_run: true,
                skip_validation: true,
                ..Default::default()
            },
        )
        .unwrap();

        assert_eq!(result1.tickets[0].id, result2.tickets[0].id);
        assert_eq!(result1.tickets[1].id, result2.tickets[1].id);
    }

    /// UT-116-04: Test verification command generation.
    #[test]
    fn test_verification_commands() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();
        create_test_rfc(root);
        create_test_files(root);

        let result = emit_tickets(
            root,
            "RFC-0000",
            &TicketEmitOptions {
                dry_run: true,
                skip_validation: true,
                ..Default::default()
            },
        )
        .unwrap();

        // All tickets should have verification commands
        for ticket in &result.tickets {
            assert!(
                !ticket.test_requirements.is_empty(),
                "Ticket {} should have verification commands",
                ticket.id
            );
        }

        // First ticket should have the commands from decomposition
        assert_eq!(result.tickets[0].test_requirements.len(), 2);
        assert!(
            result.tickets[0].test_requirements[0]
                .verification_command
                .contains("cargo test")
        );
    }

    /// UT-116-05: Test ticket YAML schema compliance.
    #[test]
    fn test_schema_compliance() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();
        create_test_rfc(root);
        create_test_files(root);

        let result = emit_tickets(
            root,
            "RFC-0000",
            &TicketEmitOptions {
                dry_run: true,
                skip_validation: true,
                ..Default::default()
            },
        )
        .unwrap();

        for ticket in &result.tickets {
            // Parse the YAML content to verify it's valid
            let yaml: serde_yaml::Value =
                serde_yaml::from_str(&ticket.yaml_content).expect("Generated YAML should be valid");

            // Check required fields
            assert!(yaml.get("schema_version").is_some());
            assert!(yaml.get("ticket").is_some());
            assert!(yaml.get("implementation").is_some());
            assert!(yaml.get("acceptance_criteria").is_some());
            assert!(yaml.get("test_requirements").is_some());

            // Check ticket section
            let ticket_section = yaml.get("ticket").unwrap();
            assert!(ticket_section.get("id").is_some());
            assert!(ticket_section.get("title").is_some());
            assert!(ticket_section.get("status").is_some());
            assert!(ticket_section.get("rfc_id").is_some());
        }
    }

    /// Test RFC not found error.
    #[test]
    fn test_rfc_not_found() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();

        let result = emit_tickets(root, "RFC-0099", &TicketEmitOptions::default());

        assert!(matches!(result, Err(TicketEmitError::RfcNotFound { .. })));
    }

    /// Test RFC ID validation rejects traversal and shell injection.
    ///
    /// SEC-EMITTER-002: Strict validation for RFC IDs prevents:
    /// - Path traversal attacks (e.g., `RFC-../../../etc`)
    /// - Shell injection (e.g., `RFC-0010;ls`, `RFC-0010|evil`)
    #[test]
    fn test_rfc_id_validation() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();

        // Path traversal
        let result = emit_tickets(root, "RFC-../../../etc", &TicketEmitOptions::default());
        assert!(matches!(
            result,
            Err(TicketEmitError::PathTraversalError { .. })
        ));

        // Shell injection - semicolon
        let result = emit_tickets(root, "RFC-0010;ls", &TicketEmitOptions::default());
        assert!(
            matches!(result, Err(TicketEmitError::PathTraversalError { .. })),
            "Should reject RFC ID with semicolon (shell injection)"
        );

        // Shell injection - pipe
        let result = emit_tickets(root, "RFC-0010|evil", &TicketEmitOptions::default());
        assert!(
            matches!(result, Err(TicketEmitError::PathTraversalError { .. })),
            "Should reject RFC ID with pipe (shell injection)"
        );

        // Shell injection - ampersand
        let result = emit_tickets(root, "RFC-0010&evil", &TicketEmitOptions::default());
        assert!(
            matches!(result, Err(TicketEmitError::PathTraversalError { .. })),
            "Should reject RFC ID with ampersand (shell injection)"
        );

        // Too few digits
        let result = emit_tickets(root, "RFC-001", &TicketEmitOptions::default());
        assert!(
            matches!(result, Err(TicketEmitError::PathTraversalError { .. })),
            "Should reject RFC ID with fewer than 4 digits"
        );

        // Valid RFC IDs (should fail for other reasons, not ID validation)
        let result = emit_tickets(root, "RFC-0010", &TicketEmitOptions::default());
        assert!(
            !matches!(result, Err(TicketEmitError::PathTraversalError { .. })),
            "Should accept valid RFC ID RFC-0010"
        );

        let result = emit_tickets(root, "RFC-99999999", &TicketEmitOptions::default());
        assert!(
            !matches!(result, Err(TicketEmitError::PathTraversalError { .. })),
            "Should accept valid RFC ID with more digits"
        );
    }

    /// Test ticket ID validation rejects path traversal and shell injection.
    ///
    /// This is a security test ensuring malicious ticket IDs in YAML
    /// cannot cause path traversal or shell injection attacks.
    #[test]
    fn test_invalid_ticket_id_rejection() {
        // Test cases for various attack vectors
        let invalid_ids = [
            ("../test", "path traversal with .."),
            ("TCK/../evil", "path traversal embedded"),
            ("TCK/test", "forward slash"),
            ("TCK\\test", "backslash"),
            ("TCK;rm", "shell semicolon"),
            ("TCK-001|evil", "shell pipe"),
            ("TCK&evil", "shell ampersand"),
            ("TCK$(cmd)", "shell command substitution"),
            ("TCK`cmd`", "shell backtick"),
            ("TCK$VAR", "shell variable"),
            ("TCK-0001", "too few digits"),
            ("TCK-000001", "too many digits"),
            ("TCK00001", "missing hyphen"),
            ("tck-00001", "lowercase prefix"),
            ("XYZ-00001", "wrong prefix"),
            ("", "empty string"),
            ("TCK-ABCDE", "letters instead of digits"),
        ];

        for (invalid_id, description) in invalid_ids {
            let result = validate_ticket_id(invalid_id);
            assert!(
                result.is_err(),
                "Should reject '{invalid_id}' ({description})"
            );
            assert!(
                matches!(result, Err(TicketEmitError::PathTraversalError { .. })),
                "Should return PathTraversalError for '{invalid_id}' ({description})"
            );
        }

        // Verify valid IDs are accepted
        let valid_ids = ["TCK-00001", "TCK-00100", "TCK-99999", "TCK-12345"];
        for valid_id in valid_ids {
            let result = validate_ticket_id(valid_id);
            assert!(result.is_ok(), "Should accept valid ticket ID '{valid_id}'");
        }
    }

    /// Test that malicious ticket IDs in decomposition YAML are rejected.
    #[test]
    fn test_malicious_ticket_id_in_decomposition() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();

        // Create RFC with malicious ticket ID (using valid RFC ID)
        let rfc_dir = root.join("documents/rfcs/RFC-9999");
        fs::create_dir_all(&rfc_dir).unwrap();

        fs::write(
            rfc_dir.join("06_ticket_decomposition.yaml"),
            r#"rfc_ticket_decomposition:
  tickets:
    - ticket_id: "../../../etc/passwd"
      title: "Malicious ticket"
      description: "Attempting path traversal"
"#,
        )
        .unwrap();

        // Create minimal directory structure
        let tickets_dir = root.join("documents/work/tickets");
        fs::create_dir_all(&tickets_dir).unwrap();

        let result = emit_tickets(
            root,
            "RFC-9999",
            &TicketEmitOptions {
                dry_run: true,
                skip_validation: true,
                ..Default::default()
            },
        );

        assert!(
            matches!(result, Err(TicketEmitError::PathTraversalError { .. })),
            "Should reject decomposition with malicious ticket ID"
        );
    }

    /// Test dry run mode.
    #[test]
    fn test_dry_run() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();
        create_test_rfc(root);
        create_test_files(root);

        let result = emit_tickets(
            root,
            "RFC-0000",
            &TicketEmitOptions {
                dry_run: true,
                skip_validation: true,
                ..Default::default()
            },
        )
        .unwrap();

        assert!(result.dry_run);
        assert_eq!(result.tickets.len(), 2);

        // Verify no files were written
        let ticket_path = result.output_dir.join("TCK-00001.yaml");
        assert!(!ticket_path.exists());
    }

    /// Test full ticket emission.
    #[test]
    fn test_full_emission() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();
        create_test_rfc(root);
        create_test_files(root);

        let result = emit_tickets(
            root,
            "RFC-0000",
            &TicketEmitOptions {
                dry_run: false,
                skip_validation: true,
                force: true,
                ..Default::default()
            },
        )
        .unwrap();

        assert!(!result.dry_run);
        assert_eq!(result.tickets.len(), 2);

        // Verify files were written
        for ticket in &result.tickets {
            let ticket_path = result.output_dir.join(format!("{}.yaml", ticket.id));
            assert!(
                ticket_path.exists(),
                "Ticket file should exist: {}",
                ticket.id
            );

            // Verify content is valid YAML
            let content = fs::read_to_string(&ticket_path).unwrap();
            let _: serde_yaml::Value =
                serde_yaml::from_str(&content).expect("Written file should be valid YAML");
        }
    }

    /// Test dependency resolution.
    #[test]
    fn test_dependency_resolution() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();
        create_test_rfc(root);
        create_test_files(root);

        let result = emit_tickets(
            root,
            "RFC-0000",
            &TicketEmitOptions {
                dry_run: true,
                skip_validation: true,
                ..Default::default()
            },
        )
        .unwrap();

        // Second ticket should depend on first
        let second_ticket = &result.tickets[1];
        assert!(
            second_ticket.depends_on.contains(&"TCK-00001".to_string()),
            "Second ticket should depend on first"
        );
    }

    /// SEC-EMITTER-002: Test fail-closed validation.
    ///
    /// When path validation fails, `emit_tickets` must return an error,
    /// not just log warnings and continue.
    #[test]
    fn test_fail_closed_validation() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();

        // Create RFC with valid structure but invalid file paths
        let rfc_dir = root.join("documents/rfcs/RFC-8888");
        fs::create_dir_all(&rfc_dir).unwrap();

        fs::write(
            rfc_dir.join("06_ticket_decomposition.yaml"),
            r#"rfc_ticket_decomposition:
  tickets:
    - ticket_id: TCK-00001
      title: "Ticket with invalid path"
      description: "References a file that does not exist"
      files_to_modify:
        - crates/nonexistent/file_that_does_not_exist.rs
      files_to_create: []
"#,
        )
        .unwrap();

        // Create tickets directory but NOT the file referenced
        let tickets_dir = root.join("documents/work/tickets");
        fs::create_dir_all(&tickets_dir).unwrap();

        // Without skip_validation, this should fail because the file doesn't exist
        let result = emit_tickets(
            root,
            "RFC-8888",
            &TicketEmitOptions {
                dry_run: true,
                skip_validation: false, // Enable validation
                ..Default::default()
            },
        );

        // Must be an error, not a success with warnings
        assert!(
            result.is_err(),
            "emit_tickets must return Err when validation fails (fail-closed)"
        );
        assert!(
            matches!(result, Err(TicketEmitError::PathValidation(_))),
            "Error should be PathValidation, got: {result:?}"
        );
    }
}
