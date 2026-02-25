//! CAC (Context-as-Code) CLI commands.
//!
//! This module provides CLI commands for CAC operations including
//! patch application with replay protection via the admission pipeline.

use std::io::{self, Read as IoRead};
use std::path::{Path, PathBuf};

/// Maximum file size for input files (10MB).
///
/// This limit prevents denial-of-service attacks via memory exhaustion from
/// large file inputs.
const MAX_INPUT_FILE_SIZE: u64 = 10 * 1024 * 1024;

use anyhow::{Context, Result, bail};
use apm2_core::cac::admission::{
    AdmissionError, AdmissionGate, AdmissionReceipt, AdmissionRequest, ArtifactKind,
};
use apm2_core::cac::patch_engine::PatchEngineError;
use apm2_core::evidence::MemoryCas;
use clap::{Args, Subcommand, ValueEnum};
use serde_json::Value;

/// Exit codes for CAC commands per RFC-0011::REQ-0002.
pub mod exit_codes {
    /// Success exit code.
    pub const SUCCESS: u8 = 0;
    /// Validation error exit code (schema validation failed, invalid input,
    /// etc.).
    pub const VALIDATION_ERROR: u8 = 1;
    /// Replay violation exit code (expected base hash mismatch).
    pub const REPLAY_VIOLATION: u8 = 2;
}

/// CAC command group.
#[derive(Debug, Args)]
pub struct CacCommand {
    #[command(subcommand)]
    pub subcommand: CacSubcommand,
}

/// CAC subcommands.
#[derive(Debug, Subcommand)]
pub enum CacSubcommand {
    /// Apply a patch to a CAC artifact with replay protection.
    ///
    /// Reads a patch document (JSON Patch RFC 6902 or Merge Patch RFC 7396)
    /// and applies it to a base document. Requires --expected-base for replay
    /// protection to prevent stale overwrites.
    ///
    /// NOTE: This command validates the patch and computes an admission receipt
    /// but does NOT persist the resulting artifact. The in-memory CAS is used
    /// for validation only - artifacts are discarded when the command exits.
    /// This is useful for:
    ///   - Verifying patches are valid before committing to a workflow
    ///   - Testing schema compliance of patched documents
    ///   - Computing artifact hashes for planning purposes
    ///
    /// Future versions will support persistence options via --store flags.
    ApplyPatch(ApplyPatchArgs),
}

/// Patch type for apply-patch command.
#[derive(Debug, Clone, Copy, Default, ValueEnum)]
pub enum PatchTypeArg {
    /// JSON Patch (RFC 6902) - array of operations.
    #[default]
    JsonPatch,
    /// Merge Patch (RFC 7396) - document-level merge.
    MergePatch,
}

impl std::fmt::Display for PatchTypeArg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::JsonPatch => write!(f, "json-patch"),
            Self::MergePatch => write!(f, "merge-patch"),
        }
    }
}

/// Output format for receipts.
#[derive(Debug, Clone, Copy, Default, ValueEnum)]
pub enum OutputFormat {
    /// JSON output format.
    #[default]
    Json,
    /// YAML output format.
    Yaml,
}

/// Arguments for the `cac apply-patch` command.
#[derive(Debug, Args)]
pub struct ApplyPatchArgs {
    /// Expected BLAKE3 hash of the base document (required for replay
    /// protection).
    ///
    /// This must match the hash of the current base document. If it doesn't,
    /// the command fails with exit code 2 (replay violation).
    #[arg(long, required = true)]
    pub expected_base: String,

    /// Path to the patch file. Use "-" or omit to read from stdin.
    #[arg(long)]
    pub patch: Option<PathBuf>,

    /// Path to the base document file.
    #[arg(long, required = true)]
    pub base: PathBuf,

    /// Path to the JSON Schema file for validation.
    #[arg(long, required = true)]
    pub schema: PathBuf,

    /// DCP ID for the artifact being patched.
    #[arg(long, required = true)]
    pub dcp_id: String,

    /// Artifact kind being patched.
    #[arg(long, default_value = "generic")]
    pub artifact_kind: String,

    /// Patch type (json-patch or merge-patch).
    #[arg(long, value_enum, default_value = "json-patch")]
    pub patch_type: PatchTypeArg,

    /// Dry run mode - validate without committing to CAS.
    #[arg(long, default_value = "false")]
    pub dry_run: bool,

    /// Output format for the admission receipt.
    #[arg(long, value_enum, default_value = "json")]
    pub format: OutputFormat,
}

/// Runs the CAC command, returning an appropriate exit code as u8.
///
/// # Exit Codes
///
/// - 0: Success
/// - 1: Validation error (schema validation failed, invalid input, etc.)
/// - 2: Replay violation (expected base hash mismatch)
pub fn run_cac(cmd: &CacCommand) -> u8 {
    match &cmd.subcommand {
        CacSubcommand::ApplyPatch(args) => run_apply_patch(args),
    }
}

/// Runs the `cac apply-patch` command.
fn run_apply_patch(args: &ApplyPatchArgs) -> u8 {
    match run_apply_patch_inner(args) {
        Ok(receipt) => {
            // Output the receipt in the requested format
            let output = match args.format {
                OutputFormat::Json => serde_json::to_string_pretty(&receipt)
                    .unwrap_or_else(|e| format!("{{\"error\": \"serialization failed: {e}\"}}",)),
                OutputFormat::Yaml => serde_yaml::to_string(&receipt)
                    .unwrap_or_else(|e| format!("error: serialization failed: {e}")),
            };
            println!("{output}");
            exit_codes::SUCCESS
        },
        Err(CacCliError::ReplayViolation { expected, actual }) => {
            eprintln!(
                "Error: Replay violation - expected base hash '{expected}' but document has hash '{actual}'"
            );
            exit_codes::REPLAY_VIOLATION
        },
        Err(CacCliError::ValidationError(msg)) => {
            eprintln!("Error: Validation failed - {msg}");
            exit_codes::VALIDATION_ERROR
        },
        Err(CacCliError::Other(msg)) => {
            eprintln!("Error: {msg}");
            exit_codes::VALIDATION_ERROR
        },
    }
}

/// Internal error type for CLI error handling.
#[derive(Debug)]
enum CacCliError {
    ReplayViolation { expected: String, actual: String },
    ValidationError(String),
    Other(String),
}

impl From<anyhow::Error> for CacCliError {
    fn from(err: anyhow::Error) -> Self {
        Self::Other(err.to_string())
    }
}

/// Inner implementation that returns Result for easier error handling.
fn run_apply_patch_inner(args: &ApplyPatchArgs) -> Result<AdmissionReceipt, CacCliError> {
    // Read the patch document
    let patch_content = read_patch_input(args.patch.as_ref())
        .map_err(|e| CacCliError::Other(format!("failed to read patch: {e}")))?;

    // Parse patch as JSON
    let patch: Value = serde_json::from_str(&patch_content)
        .map_err(|e| CacCliError::ValidationError(format!("invalid patch JSON: {e}")))?;

    // Read the base document with size limit
    let base_content = read_bounded_file(&args.base)
        .map_err(|e| CacCliError::Other(format!("failed to read base document: {e}")))?;

    // Parse base document as JSON
    let base: Value = serde_json::from_str(&base_content)
        .map_err(|e| CacCliError::ValidationError(format!("invalid base document JSON: {e}")))?;

    // Read the schema with size limit
    let schema_content = read_bounded_file(&args.schema)
        .map_err(|e| CacCliError::Other(format!("failed to read schema: {e}")))?;

    // Parse schema as JSON
    let schema: Value = serde_json::from_str(&schema_content)
        .map_err(|e| CacCliError::ValidationError(format!("invalid schema JSON: {e}")))?;

    // Parse artifact kind
    let artifact_kind = parse_artifact_kind(&args.artifact_kind)
        .map_err(|e| CacCliError::ValidationError(e.to_string()))?;

    // Create the admission request based on patch type
    let request = match args.patch_type {
        PatchTypeArg::JsonPatch => AdmissionRequest::new_json_patch(
            &args.dcp_id,
            artifact_kind,
            base,
            patch,
            &args.expected_base,
            &schema,
        ),
        PatchTypeArg::MergePatch => AdmissionRequest::new_merge_patch(
            &args.dcp_id,
            artifact_kind,
            base,
            patch,
            &args.expected_base,
            &schema,
        ),
    };

    // Create the admission gate with in-memory CAS
    // In dry-run mode, we still use CAS but don't persist anywhere
    let cas = MemoryCas::new();
    let gate = AdmissionGate::new(cas);

    // Admit the artifact
    let result = gate.admit(request).map_err(|e| match e {
        AdmissionError::PatchFailed(PatchEngineError::ReplayViolation { expected, actual }) => {
            CacCliError::ReplayViolation { expected, actual }
        },
        AdmissionError::ValidationFailed(ve) => CacCliError::ValidationError(ve.to_string()),
        AdmissionError::CanonicalizationFailed(ce) => {
            CacCliError::ValidationError(format!("canonicalization failed: {ce}"))
        },
        AdmissionError::PatchFailed(pe) => {
            CacCliError::ValidationError(format!("patch failed: {pe}"))
        },
        AdmissionError::InvalidDcpId { reason } => {
            CacCliError::ValidationError(format!("invalid DCP ID: {reason}"))
        },
        AdmissionError::InputComplexityExceeded { message } => {
            CacCliError::ValidationError(format!("input complexity exceeded: {message}"))
        },
        other => CacCliError::Other(other.to_string()),
    })?;

    // In dry-run mode, we still return the receipt but note it wasn't persisted
    if args.dry_run {
        // The receipt is already computed, just return it
        // The caller can inspect it without any persistent side effects
    }

    Ok(result.receipt)
}

/// Reads a file with size limit to prevent denial-of-service via memory
/// exhaustion.
///
/// Uses a bounded reader to avoid TOCTOU (time-of-check to time-of-use) race
/// conditions. Instead of checking file size then reading, we read up to
/// `MAX_INPUT_FILE_SIZE + 1` bytes and reject if we hit the limit.
///
/// # Errors
///
/// Returns an error if:
/// - The file cannot be read
/// - The file content exceeds `MAX_INPUT_FILE_SIZE` (10MB)
fn read_bounded_file(path: &Path) -> Result<String> {
    use std::fs::File;
    use std::io::Read;

    let file =
        File::open(path).with_context(|| format!("failed to open file: {}", path.display()))?;

    let mut content = String::new();
    let mut bounded_reader = file.take(MAX_INPUT_FILE_SIZE + 1);

    bounded_reader
        .read_to_string(&mut content)
        .with_context(|| format!("failed to read file: {}", path.display()))?;

    if content.len() as u64 > MAX_INPUT_FILE_SIZE {
        bail!(
            "file '{}' exceeds maximum size limit of {} bytes",
            path.display(),
            MAX_INPUT_FILE_SIZE
        );
    }

    Ok(content)
}

/// Reads from stdin with size limit to prevent denial-of-service via memory
/// exhaustion.
///
/// # Errors
///
/// Returns an error if:
/// - Reading from stdin fails
/// - The input exceeds `MAX_INPUT_FILE_SIZE` (10MB)
fn read_bounded_stdin() -> Result<String> {
    let mut content = String::new();
    let mut handle = io::stdin().take(MAX_INPUT_FILE_SIZE + 1);

    handle
        .read_to_string(&mut content)
        .context("failed to read from stdin")?;

    if content.len() as u64 > MAX_INPUT_FILE_SIZE {
        bail!("stdin input exceeds maximum size limit of {MAX_INPUT_FILE_SIZE} bytes");
    }

    Ok(content)
}

/// Reads patch input from file or stdin.
fn read_patch_input(patch_path: Option<&PathBuf>) -> Result<String> {
    match patch_path {
        Some(path) if path.as_os_str() != "-" => read_bounded_file(path),
        _ => read_bounded_stdin(),
    }
}

/// Parses artifact kind from string.
fn parse_artifact_kind(kind: &str) -> Result<ArtifactKind> {
    match kind.to_lowercase().as_str() {
        "ticket" => Ok(ArtifactKind::Ticket),
        "rfc" => Ok(ArtifactKind::Rfc),
        "prd" => Ok(ArtifactKind::Prd),
        "policy" => Ok(ArtifactKind::Policy),
        "context_pack" | "contextpack" => Ok(ArtifactKind::ContextPack),
        "target_profile" | "targetprofile" => Ok(ArtifactKind::TargetProfile),
        "schema" => Ok(ArtifactKind::Schema),
        "bootstrap" => Ok(ArtifactKind::Bootstrap),
        "run_manifest" | "runmanifest" => Ok(ArtifactKind::RunManifest),
        "generic" => Ok(ArtifactKind::Generic),
        _ => bail!(
            "unknown artifact kind '{kind}'. Valid kinds: ticket, rfc, prd, policy, \
             context_pack, target_profile, schema, bootstrap, run_manifest, generic"
        ),
    }
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    fn sample_schema() -> Value {
        serde_json::json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "properties": {
                "id": { "type": "string" },
                "version": { "type": "integer" }
            },
            "required": ["id"],
            "unevaluatedProperties": false
        })
    }

    fn compute_base_hash(doc: &Value) -> String {
        use apm2_core::cac::PatchEngine;
        let engine = PatchEngine::new();
        engine.compute_hash(doc).unwrap()
    }

    // =========================================================================
    // CLI Argument Parsing Tests
    // =========================================================================

    #[test]
    fn test_parse_artifact_kind_valid() {
        assert!(matches!(
            parse_artifact_kind("ticket").unwrap(),
            ArtifactKind::Ticket
        ));
        assert!(matches!(
            parse_artifact_kind("rfc").unwrap(),
            ArtifactKind::Rfc
        ));
        assert!(matches!(
            parse_artifact_kind("prd").unwrap(),
            ArtifactKind::Prd
        ));
        assert!(matches!(
            parse_artifact_kind("generic").unwrap(),
            ArtifactKind::Generic
        ));
        // Case insensitive
        assert!(matches!(
            parse_artifact_kind("TICKET").unwrap(),
            ArtifactKind::Ticket
        ));
    }

    #[test]
    fn test_parse_artifact_kind_invalid() {
        let result = parse_artifact_kind("invalid_kind");
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("unknown artifact kind")
        );
    }

    #[test]
    fn test_patch_type_display() {
        assert_eq!(PatchTypeArg::JsonPatch.to_string(), "json-patch");
        assert_eq!(PatchTypeArg::MergePatch.to_string(), "merge-patch");
    }

    // =========================================================================
    // Apply Patch Integration Tests
    // =========================================================================

    #[test]
    fn cli_cac_apply_patch_json_patch_success() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path().join("base.json");
        let patch_path = temp_dir.path().join("patch.json");
        let schema_path = temp_dir.path().join("schema.json");

        // Create base document
        let base = serde_json::json!({"id": "RFC-0011::REQ-0002", "version": 1});
        let base_hash = compute_base_hash(&base);
        std::fs::write(&base_path, serde_json::to_string(&base).unwrap()).unwrap();

        // Create patch
        let patch = serde_json::json!([{"op": "replace", "path": "/version", "value": 2}]);
        std::fs::write(&patch_path, serde_json::to_string(&patch).unwrap()).unwrap();

        // Create schema
        std::fs::write(
            &schema_path,
            serde_json::to_string(&sample_schema()).unwrap(),
        )
        .unwrap();

        let args = ApplyPatchArgs {
            expected_base: base_hash,
            patch: Some(patch_path),
            base: base_path,
            schema: schema_path,
            dcp_id: "dcp://test/ticket/RFC-0011::REQ-0002".to_string(),
            artifact_kind: "ticket".to_string(),
            patch_type: PatchTypeArg::JsonPatch,
            dry_run: false,
            format: OutputFormat::Json,
        };

        let result = run_apply_patch_inner(&args);
        assert!(result.is_ok(), "Expected success, got: {result:?}");

        let receipt = result.unwrap();
        assert_eq!(receipt.dcp_id, "dcp://test/ticket/RFC-0011::REQ-0002");
        assert!(receipt.patch_hash.is_some());
        assert!(receipt.base_hash.is_some());
    }

    #[test]
    fn cli_cac_apply_patch_merge_patch_success() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path().join("base.json");
        let patch_path = temp_dir.path().join("patch.json");
        let schema_path = temp_dir.path().join("schema.json");

        // Create base document
        let base = serde_json::json!({"id": "RFC-0011::REQ-0002", "version": 1});
        let base_hash = compute_base_hash(&base);
        std::fs::write(&base_path, serde_json::to_string(&base).unwrap()).unwrap();

        // Create merge patch
        let patch = serde_json::json!({"version": 2});
        std::fs::write(&patch_path, serde_json::to_string(&patch).unwrap()).unwrap();

        // Create schema
        std::fs::write(
            &schema_path,
            serde_json::to_string(&sample_schema()).unwrap(),
        )
        .unwrap();

        let args = ApplyPatchArgs {
            expected_base: base_hash,
            patch: Some(patch_path),
            base: base_path,
            schema: schema_path,
            dcp_id: "dcp://test/ticket/RFC-0011::REQ-0002".to_string(),
            artifact_kind: "ticket".to_string(),
            patch_type: PatchTypeArg::MergePatch,
            dry_run: false,
            format: OutputFormat::Json,
        };

        let result = run_apply_patch_inner(&args);
        assert!(result.is_ok(), "Expected success, got: {result:?}");

        let receipt = result.unwrap();
        assert_eq!(
            receipt.patch_type,
            Some("Merge Patch (RFC 7396)".to_string())
        );
    }

    #[test]
    fn cli_cac_apply_patch_replay_violation() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path().join("base.json");
        let patch_path = temp_dir.path().join("patch.json");
        let schema_path = temp_dir.path().join("schema.json");

        // Create base document
        let base = serde_json::json!({"id": "RFC-0011::REQ-0002", "version": 1});
        std::fs::write(&base_path, serde_json::to_string(&base).unwrap()).unwrap();

        // Create patch
        let patch = serde_json::json!([{"op": "replace", "path": "/version", "value": 2}]);
        std::fs::write(&patch_path, serde_json::to_string(&patch).unwrap()).unwrap();

        // Create schema
        std::fs::write(
            &schema_path,
            serde_json::to_string(&sample_schema()).unwrap(),
        )
        .unwrap();

        // Use wrong expected base hash
        let wrong_hash = "0000000000000000000000000000000000000000000000000000000000000000";

        let args = ApplyPatchArgs {
            expected_base: wrong_hash.to_string(),
            patch: Some(patch_path),
            base: base_path,
            schema: schema_path,
            dcp_id: "dcp://test/ticket/RFC-0011::REQ-0002".to_string(),
            artifact_kind: "ticket".to_string(),
            patch_type: PatchTypeArg::JsonPatch,
            dry_run: false,
            format: OutputFormat::Json,
        };

        let result = run_apply_patch_inner(&args);
        assert!(
            matches!(result, Err(CacCliError::ReplayViolation { .. })),
            "Expected ReplayViolation, got: {result:?}"
        );
    }

    #[test]
    fn cli_cac_apply_patch_validation_error() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path().join("base.json");
        let patch_path = temp_dir.path().join("patch.json");
        let schema_path = temp_dir.path().join("schema.json");

        // Create base document
        let base = serde_json::json!({"id": "RFC-0011::REQ-0002", "version": 1});
        let base_hash = compute_base_hash(&base);
        std::fs::write(&base_path, serde_json::to_string(&base).unwrap()).unwrap();

        // Create patch that adds an unknown field (violates schema)
        let patch = serde_json::json!([{"op": "add", "path": "/unknown", "value": "bad"}]);
        std::fs::write(&patch_path, serde_json::to_string(&patch).unwrap()).unwrap();

        // Create strict schema
        std::fs::write(
            &schema_path,
            serde_json::to_string(&sample_schema()).unwrap(),
        )
        .unwrap();

        let args = ApplyPatchArgs {
            expected_base: base_hash,
            patch: Some(patch_path),
            base: base_path,
            schema: schema_path,
            dcp_id: "dcp://test/ticket/RFC-0011::REQ-0002".to_string(),
            artifact_kind: "ticket".to_string(),
            patch_type: PatchTypeArg::JsonPatch,
            dry_run: false,
            format: OutputFormat::Json,
        };

        let result = run_apply_patch_inner(&args);
        assert!(
            matches!(result, Err(CacCliError::ValidationError(_))),
            "Expected ValidationError, got: {result:?}"
        );
    }

    #[test]
    fn cli_cac_apply_patch_dry_run() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path().join("base.json");
        let patch_path = temp_dir.path().join("patch.json");
        let schema_path = temp_dir.path().join("schema.json");

        // Create base document
        let base = serde_json::json!({"id": "RFC-0011::REQ-0002", "version": 1});
        let base_hash = compute_base_hash(&base);
        std::fs::write(&base_path, serde_json::to_string(&base).unwrap()).unwrap();

        // Create patch
        let patch = serde_json::json!([{"op": "replace", "path": "/version", "value": 2}]);
        std::fs::write(&patch_path, serde_json::to_string(&patch).unwrap()).unwrap();

        // Create schema
        std::fs::write(
            &schema_path,
            serde_json::to_string(&sample_schema()).unwrap(),
        )
        .unwrap();

        let args = ApplyPatchArgs {
            expected_base: base_hash,
            patch: Some(patch_path),
            base: base_path,
            schema: schema_path,
            dcp_id: "dcp://test/ticket/RFC-0011::REQ-0002".to_string(),
            artifact_kind: "ticket".to_string(),
            patch_type: PatchTypeArg::JsonPatch,
            dry_run: true, // Dry run mode
            format: OutputFormat::Json,
        };

        let result = run_apply_patch_inner(&args);
        assert!(result.is_ok(), "Dry run should succeed: {result:?}");

        // Receipt should still be returned in dry-run mode
        let receipt = result.unwrap();
        assert!(!receipt.new_hash.is_empty());
    }

    #[test]
    fn cli_cac_apply_patch_yaml_output() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path().join("base.json");
        let patch_path = temp_dir.path().join("patch.json");
        let schema_path = temp_dir.path().join("schema.json");

        // Create base document
        let base = serde_json::json!({"id": "RFC-0011::REQ-0002", "version": 1});
        let base_hash = compute_base_hash(&base);
        std::fs::write(&base_path, serde_json::to_string(&base).unwrap()).unwrap();

        // Create patch
        let patch = serde_json::json!([{"op": "replace", "path": "/version", "value": 2}]);
        std::fs::write(&patch_path, serde_json::to_string(&patch).unwrap()).unwrap();

        // Create schema
        std::fs::write(
            &schema_path,
            serde_json::to_string(&sample_schema()).unwrap(),
        )
        .unwrap();

        let args = ApplyPatchArgs {
            expected_base: base_hash,
            patch: Some(patch_path),
            base: base_path,
            schema: schema_path,
            dcp_id: "dcp://test/ticket/RFC-0011::REQ-0002".to_string(),
            artifact_kind: "ticket".to_string(),
            patch_type: PatchTypeArg::JsonPatch,
            dry_run: false,
            format: OutputFormat::Yaml, // YAML output
        };

        let result = run_apply_patch_inner(&args);
        assert!(result.is_ok(), "Expected success, got: {result:?}");

        // Verify we can serialize to YAML
        let receipt = result.unwrap();
        let yaml_output = serde_yaml::to_string(&receipt);
        assert!(yaml_output.is_ok());
    }

    #[test]
    fn cli_cac_apply_patch_invalid_json() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path().join("base.json");
        let patch_path = temp_dir.path().join("patch.json");
        let schema_path = temp_dir.path().join("schema.json");

        // Create invalid base document
        std::fs::write(&base_path, "{ invalid json }").unwrap();

        // Create patch
        let patch = serde_json::json!([{"op": "replace", "path": "/version", "value": 2}]);
        std::fs::write(&patch_path, serde_json::to_string(&patch).unwrap()).unwrap();

        // Create schema
        std::fs::write(
            &schema_path,
            serde_json::to_string(&sample_schema()).unwrap(),
        )
        .unwrap();

        let args = ApplyPatchArgs {
            expected_base: "somehash".to_string(),
            patch: Some(patch_path),
            base: base_path,
            schema: schema_path,
            dcp_id: "dcp://test/ticket/RFC-0011::REQ-0002".to_string(),
            artifact_kind: "ticket".to_string(),
            patch_type: PatchTypeArg::JsonPatch,
            dry_run: false,
            format: OutputFormat::Json,
        };

        let result = run_apply_patch_inner(&args);
        assert!(
            matches!(result, Err(CacCliError::ValidationError(_))),
            "Expected ValidationError for invalid JSON, got: {result:?}"
        );
    }

    #[test]
    fn cli_cac_apply_patch_missing_file() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path().join("nonexistent.json");
        let patch_path = temp_dir.path().join("patch.json");
        let schema_path = temp_dir.path().join("schema.json");

        // Create patch
        let patch = serde_json::json!([{"op": "replace", "path": "/version", "value": 2}]);
        std::fs::write(&patch_path, serde_json::to_string(&patch).unwrap()).unwrap();

        // Create schema
        std::fs::write(
            &schema_path,
            serde_json::to_string(&sample_schema()).unwrap(),
        )
        .unwrap();

        let args = ApplyPatchArgs {
            expected_base: "somehash".to_string(),
            patch: Some(patch_path),
            base: base_path, // Doesn't exist
            schema: schema_path,
            dcp_id: "dcp://test/ticket/RFC-0011::REQ-0002".to_string(),
            artifact_kind: "ticket".to_string(),
            patch_type: PatchTypeArg::JsonPatch,
            dry_run: false,
            format: OutputFormat::Json,
        };

        let result = run_apply_patch_inner(&args);
        assert!(
            matches!(result, Err(CacCliError::Other(_))),
            "Expected Other error for missing file, got: {result:?}"
        );
    }

    // =========================================================================
    // File Size Limit Tests
    // =========================================================================

    #[test]
    fn test_apply_patch_file_too_large() {
        use std::io::Write;

        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path().join("base.json");
        let schema_path = temp_dir.path().join("schema.json");

        // Create base document
        let base = serde_json::json!({"id": "RFC-0011::REQ-0002", "version": 1});
        let base_hash = compute_base_hash(&base);
        std::fs::write(&base_path, serde_json::to_string(&base).unwrap()).unwrap();

        // Create a patch file that exceeds MAX_INPUT_FILE_SIZE (10MB)
        // We create a file slightly larger than 10MB
        let oversized_path = temp_dir.path().join("oversized_patch.json");
        {
            let mut file = std::fs::File::create(&oversized_path).unwrap();
            // Write opening bracket for JSON array
            file.write_all(b"[").unwrap();
            // Write enough data to exceed 10MB
            let chunk = r#"{"op":"test","path":"/id","value":"RFC-0011::REQ-0002"},"#;
            #[allow(clippy::cast_possible_truncation)]
            let chunk_count = (super::MAX_INPUT_FILE_SIZE as usize / chunk.len()) + 100;
            for _ in 0..chunk_count {
                file.write_all(chunk.as_bytes()).unwrap();
            }
            // Write closing operation and bracket
            file.write_all(b"{\"op\":\"test\",\"path\":\"/id\",\"value\":\"RFC-0011::REQ-0002\"}]")
                .unwrap();
        }

        // Verify the file is actually larger than the limit
        let metadata = std::fs::metadata(&oversized_path).unwrap();
        assert!(
            metadata.len() > super::MAX_INPUT_FILE_SIZE,
            "Test file should exceed MAX_INPUT_FILE_SIZE"
        );

        // Create schema
        std::fs::write(
            &schema_path,
            serde_json::to_string(&sample_schema()).unwrap(),
        )
        .unwrap();

        let args = ApplyPatchArgs {
            expected_base: base_hash,
            patch: Some(oversized_path),
            base: base_path,
            schema: schema_path,
            dcp_id: "dcp://test/ticket/RFC-0011::REQ-0002".to_string(),
            artifact_kind: "ticket".to_string(),
            patch_type: PatchTypeArg::JsonPatch,
            dry_run: false,
            format: OutputFormat::Json,
        };

        let result = run_apply_patch_inner(&args);
        assert!(
            matches!(result, Err(CacCliError::Other(ref msg)) if msg.contains("exceeds maximum size limit")),
            "Expected error about file size limit, got: {result:?}"
        );
    }

    #[test]
    fn test_read_bounded_file_rejects_oversized() {
        use std::io::Write;

        let temp_dir = TempDir::new().unwrap();
        let oversized_path = temp_dir.path().join("oversized.txt");

        // Create a file that exceeds MAX_INPUT_FILE_SIZE
        {
            let mut file = std::fs::File::create(&oversized_path).unwrap();
            let chunk = vec![b'x'; 1024 * 1024]; // 1MB chunk
            for _ in 0..11 {
                // Write 11MB total
                file.write_all(&chunk).unwrap();
            }
        }

        let result = super::read_bounded_file(&oversized_path);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("exceeds maximum size limit"),
            "Error message should mention size limit: {err_msg}"
        );
        assert!(
            err_msg.contains("10485760"),
            "Error message should include the limit in bytes: {err_msg}"
        );
    }
}
