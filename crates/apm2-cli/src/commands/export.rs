//! Export CLI command for exporting CAC artifacts to vendor-specific layouts.
//!
//! This module provides the CLI command for exporting a compiled `ContextPack`
//! to a target profile's output format with optional conformance verification.
//!
//! # Exit Codes
//!
//! - 0: Success
//! - 1: Error (I/O, validation, or other failures)
//! - 2: Conformance failure (when `--verify` is used)

use std::fs::File;
use std::io::{Read as IoRead, Write as IoWrite};
use std::path::PathBuf;

use apm2_core::cac::{
    CompiledContextPack, ConformanceError, ConformanceSuiteConfig, ContextPackCompiler,
    ContextPackSpec, DcpIndex, ExportError, ExportManifest, ExportPipeline, ExportReceipt,
    MemoryContentResolver, run_conformance_suite,
};
use chrono::Utc;
use clap::{Args, ValueEnum};

/// Maximum file size for input files (10MB).
///
/// This limit prevents denial-of-service attacks via memory exhaustion from
/// large file inputs (per CTR-1603).
const MAX_INPUT_FILE_SIZE: u64 = 10 * 1024 * 1024;

/// Exit codes for export commands per TCK-00143.
pub mod exit_codes {
    /// Success exit code.
    pub const SUCCESS: u8 = 0;
    /// General error exit code (I/O, validation, etc.).
    pub const ERROR: u8 = 1;
    /// Conformance failure exit code (tests failed).
    pub const CONFORMANCE_FAILURE: u8 = 2;
}

/// Output format for manifest/receipt.
#[derive(Debug, Clone, Copy, Default, ValueEnum)]
pub enum OutputFormat {
    /// JSON output format (default).
    #[default]
    Json,
    /// YAML output format.
    Yaml,
}

/// Export command arguments.
#[derive(Debug, Args)]
pub struct ExportArgs {
    /// Path to the target profile file (YAML or JSON).
    ///
    /// The target profile defines output format, budget policies, and
    /// delivery constraints for the export operation.
    #[arg(long, required = true)]
    pub profile: PathBuf,

    /// Path to the context pack file (YAML or JSON), or "-" for stdin.
    ///
    /// The context pack specifies which artifacts to export and their
    /// budget constraints.
    #[arg(long)]
    pub pack: Option<PathBuf>,

    /// Output directory for exported files.
    ///
    /// The directory must exist. Files will be written to subdirectories
    /// based on artifact stable IDs.
    #[arg(long, required = true)]
    pub output_dir: PathBuf,

    /// Run conformance tests after export.
    ///
    /// When enabled, runs determinism, provenance, and schema verification
    /// tests and outputs an `ExportReceipt` instead of just an
    /// `ExportManifest`.
    #[arg(long, default_value = "false")]
    pub verify: bool,

    /// Output format for manifest/receipt (json or yaml).
    #[arg(long, value_enum, default_value = "json")]
    pub format: OutputFormat,

    /// Path to a DCP index file (JSON).
    ///
    /// The index file contains artifact metadata mapping stable IDs to
    /// content hashes. Required for export operations.
    #[arg(long, required = true)]
    pub index: PathBuf,
}

/// Runs the export command, returning an appropriate exit code as u8.
///
/// # Exit Codes
///
/// - 0: Success
/// - 1: Error (I/O, validation, etc.)
/// - 2: Conformance failure (when `--verify` is used and tests fail)
pub fn run_export(args: &ExportArgs) -> u8 {
    match run_export_inner(args) {
        Ok(ExportResult::Manifest(manifest)) => {
            output_result(&manifest, args.format, "manifest");
            exit_codes::SUCCESS
        },
        Ok(ExportResult::Receipt(receipt)) => {
            output_result(&receipt, args.format, "receipt");
            if receipt.overall_passed {
                exit_codes::SUCCESS
            } else {
                eprintln!("\nConformance verification failed: {}", receipt.summary());
                exit_codes::CONFORMANCE_FAILURE
            }
        },
        Err(ExportCliError::Io(msg)) => {
            eprintln!("Error: {msg}");
            exit_codes::ERROR
        },
        Err(ExportCliError::Validation(msg)) => {
            eprintln!("Error: Validation failed - {msg}");
            exit_codes::ERROR
        },
        Err(ExportCliError::Export(msg)) => {
            eprintln!("Error: Export failed - {msg}");
            exit_codes::ERROR
        },
        Err(ExportCliError::Conformance(msg)) => {
            eprintln!("Error: Conformance test error - {msg}");
            exit_codes::CONFORMANCE_FAILURE
        },
    }
}

/// Outputs a serializable result to stdout.
fn output_result<T: serde::Serialize>(result: &T, format: OutputFormat, name: &str) {
    let output = match format {
        OutputFormat::Json => serde_json::to_string_pretty(result)
            .unwrap_or_else(|e| format!("{{\"error\": \"{name} serialization failed: {e}\"}}")),
        OutputFormat::Yaml => serde_yaml::to_string(result)
            .unwrap_or_else(|e| format!("error: {name} serialization failed: {e}")),
    };
    println!("{output}");
}

/// Result of export operation.
#[derive(Debug)]
enum ExportResult {
    /// Export completed, manifest returned (no verification).
    Manifest(ExportManifest),
    /// Export completed with verification, receipt returned.
    Receipt(ExportReceipt),
}

/// Internal error type for CLI error handling.
#[derive(Debug)]
enum ExportCliError {
    Io(String),
    Validation(String),
    Export(String),
    Conformance(String),
}

impl From<std::io::Error> for ExportCliError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err.to_string())
    }
}

impl From<ExportError> for ExportCliError {
    fn from(err: ExportError) -> Self {
        Self::Export(err.to_string())
    }
}

impl From<ConformanceError> for ExportCliError {
    fn from(err: ConformanceError) -> Self {
        Self::Conformance(err.to_string())
    }
}

/// Inner implementation that returns Result for easier error handling.
fn run_export_inner(args: &ExportArgs) -> Result<ExportResult, ExportCliError> {
    // Validate output directory exists
    if !args.output_dir.exists() {
        return Err(ExportCliError::Io(format!(
            "output directory does not exist: {}",
            args.output_dir.display()
        )));
    }
    if !args.output_dir.is_dir() {
        return Err(ExportCliError::Io(format!(
            "output path is not a directory: {}",
            args.output_dir.display()
        )));
    }

    // Load target profile
    let profile_content = read_bounded_file(&args.profile)?;
    let profile = parse_target_profile(&profile_content, &args.profile)?;

    // Load context pack (from file, stdin, or create minimal)
    let pack_spec = load_pack_spec(args.pack.as_ref())?;

    // Load DCP index
    let index = load_dcp_index(&args.index)?;

    // Compile the pack
    let compiler = ContextPackCompiler::new(&index);
    let compilation_result = compiler
        .compile(&pack_spec)
        .map_err(|e| ExportCliError::Validation(format!("pack compilation failed: {e}")))?;

    // Create content resolver from index
    // For now, we use an empty resolver since actual content loading
    // requires CAS integration which is out of scope for this ticket
    let resolver = create_content_resolver(&index, &compilation_result.pack);

    // Get current timestamp (CTR-2501: Time Is an External Input)
    let timestamp = Utc::now();

    // Create export pipeline
    let pipeline = ExportPipeline::builder()
        .profile(profile.clone())
        .output_dir(&args.output_dir)
        .timestamp(timestamp)
        .build()?;

    // Export
    let manifest = pipeline.export(&compilation_result.pack, &resolver)?;

    // Output summary to stderr
    eprintln!("Export summary:");
    eprintln!("  profile: {}", manifest.export_profile);
    eprintln!("  outputs: {}", manifest.outputs.len());
    eprintln!("  total_bytes: {}", manifest.total_bytes);
    eprintln!("  timestamp: {}", manifest.export_timestamp);

    // If verify is requested, run conformance tests
    if args.verify {
        let config = ConformanceSuiteConfig::default();
        let receipt = run_conformance_suite(
            &compilation_result.pack,
            &resolver,
            &profile,
            timestamp,
            &manifest.exporter_version,
            &[],
            &config,
        )?;

        eprintln!("Conformance: {}", receipt.summary());
        Ok(ExportResult::Receipt(receipt))
    } else {
        Ok(ExportResult::Manifest(manifest))
    }
}

/// Reads a file with size limit to prevent denial-of-service via memory
/// exhaustion.
///
/// Uses a bounded reader to avoid TOCTOU (time-of-check to time-of-use) race
/// conditions.
fn read_bounded_file(path: &std::path::Path) -> Result<String, ExportCliError> {
    let file = File::open(path).map_err(|e| {
        ExportCliError::Io(format!("failed to open file '{}': {e}", path.display()))
    })?;

    let mut content = String::new();
    let mut bounded_reader = file.take(MAX_INPUT_FILE_SIZE + 1);

    bounded_reader.read_to_string(&mut content).map_err(|e| {
        ExportCliError::Io(format!("failed to read file '{}': {e}", path.display()))
    })?;

    if content.len() as u64 > MAX_INPUT_FILE_SIZE {
        return Err(ExportCliError::Validation(format!(
            "file '{}' exceeds maximum size limit of {} bytes",
            path.display(),
            MAX_INPUT_FILE_SIZE
        )));
    }

    Ok(content)
}

/// Reads from stdin with size limit.
fn read_bounded_stdin() -> Result<String, ExportCliError> {
    use std::io;

    let mut content = String::new();
    let mut handle = io::stdin().take(MAX_INPUT_FILE_SIZE + 1);

    handle
        .read_to_string(&mut content)
        .map_err(|e| ExportCliError::Io(format!("failed to read from stdin: {e}")))?;

    if content.len() as u64 > MAX_INPUT_FILE_SIZE {
        return Err(ExportCliError::Validation(format!(
            "stdin input exceeds maximum size limit of {MAX_INPUT_FILE_SIZE} bytes"
        )));
    }

    Ok(content)
}

/// Parses a `TargetProfile` from content, detecting format from file extension.
fn parse_target_profile(
    content: &str,
    path: &std::path::Path,
) -> Result<apm2_core::cac::TargetProfile, ExportCliError> {
    let extension = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    let profile = match extension.as_str() {
        "yaml" | "yml" => serde_yaml::from_str(content).map_err(|e| {
            ExportCliError::Validation(format!("invalid YAML in profile file: {e}"))
        })?,
        _ => serde_json::from_str(content).map_err(|e| {
            ExportCliError::Validation(format!("invalid JSON in profile file: {e}"))
        })?,
    };

    Ok(profile)
}

/// Loads a `ContextPackSpec` from file, stdin, or creates a minimal spec.
fn load_pack_spec(pack_path: Option<&PathBuf>) -> Result<ContextPackSpec, ExportCliError> {
    let content = match pack_path {
        Some(path) if path.as_os_str() == "-" => read_bounded_stdin()?,
        Some(path) => read_bounded_file(path)?,
        None => {
            // No pack specified - this is an error
            return Err(ExportCliError::Validation(
                "no context pack specified. Use --pack <path> or --pack - for stdin".to_string(),
            ));
        },
    };

    let path = pack_path.map_or_else(|| std::path::Path::new("stdin"), PathBuf::as_path);
    parse_pack_spec(&content, path)
}

/// Parses a `ContextPackSpec` from content.
fn parse_pack_spec(
    content: &str,
    path: &std::path::Path,
) -> Result<ContextPackSpec, ExportCliError> {
    let extension = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    let spec: ContextPackSpec = match extension.as_str() {
        "yaml" | "yml" => serde_yaml::from_str(content)
            .map_err(|e| ExportCliError::Validation(format!("invalid YAML in pack file: {e}")))?,
        _ => serde_json::from_str(content)
            .map_err(|e| ExportCliError::Validation(format!("invalid JSON in pack file: {e}")))?,
    };

    // Validate the spec
    spec.validate()
        .map_err(|e| ExportCliError::Validation(e.to_string()))?;

    Ok(spec)
}

/// Loads a `DcpIndex` from a file path.
fn load_dcp_index(index_path: &std::path::Path) -> Result<DcpIndex, ExportCliError> {
    let content = read_bounded_file(index_path)?;
    let index: DcpIndex = serde_json::from_str(&content).map_err(|e| {
        ExportCliError::Validation(format!(
            "failed to parse index file '{}': {e}",
            index_path.display()
        ))
    })?;
    Ok(index)
}

/// Creates a content resolver from the DCP index and compiled pack.
///
/// For testing purposes, this creates a memory resolver with placeholder
/// content. In production, this would integrate with the CAS.
fn create_content_resolver(_index: &DcpIndex, pack: &CompiledContextPack) -> MemoryContentResolver {
    // SECURITY: Warn users that placeholder content is being used
    eprintln!(
        "WARNING: Exporting using placeholder content. Real content requires daemon connection."
    );

    let mut resolver = MemoryContentResolver::new();

    // For each entry in the pack, we need to provide content
    // In production, this would fetch from CAS using content_hash
    // For now, we create placeholder content for testing
    for entry in &pack.manifest.entries {
        // Create minimal placeholder content
        // In a real implementation, we would fetch actual content from CAS
        let placeholder = format!(
            "# {}\n\nThis is placeholder content for stable_id: {}\n",
            entry.stable_id, entry.stable_id
        );
        resolver.insert(&entry.stable_id, placeholder.as_bytes().to_vec());
    }

    resolver
}

/// Writes output to a file or stdout.
#[allow(dead_code)]
fn write_output(content: &str, output: Option<&PathBuf>) -> Result<(), ExportCliError> {
    match output {
        Some(path) => {
            let mut file = File::create(path).map_err(|e| {
                ExportCliError::Io(format!(
                    "failed to create output file '{}': {e}",
                    path.display()
                ))
            })?;
            file.write_all(content.as_bytes()).map_err(|e| {
                ExportCliError::Io(format!("failed to write to '{}': {e}", path.display()))
            })?;
            eprintln!("Output written to: {}", path.display());
        },
        None => {
            println!("{content}");
        },
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use apm2_core::cac::compiler::{BudgetUsed, CompiledManifest, ManifestEntry};
    use apm2_core::cac::{ContentResolver, DcpEntry, TypedQuantity};
    use tempfile::TempDir;

    use super::*;

    /// Creates a minimal valid target profile JSON for testing.
    fn minimal_profile_json() -> String {
        r#"{
            "profile_id": "test-profile",
            "version": "2026-01-27",
            "delivery_constraints": {
                "output_format": "markdown",
                "provenance_embed": "inline"
            }
        }"#
        .to_string()
    }

    /// Creates a minimal valid target profile YAML for testing.
    fn minimal_profile_yaml() -> String {
        r#"profile_id: "test-profile"
version: "2026-01-27"
delivery_constraints:
  output_format: "markdown"
  provenance_embed: "inline"
"#
        .to_string()
    }

    /// Creates a minimal valid pack spec JSON for testing.
    fn minimal_pack_json() -> String {
        r#"{
            "schema": "bootstrap:context_pack_spec.v1",
            "schema_version": "v1",
            "spec_id": "test-pack",
            "roots": ["org:doc:readme"],
            "budget": {},
            "target_profile": "org:profile:test"
        }"#
        .to_string()
    }

    /// Creates a DCP index with the test artifact.
    fn test_index_json() -> String {
        r#"{
            "entries": {
                "org:doc:readme": {
                    "stable_id": "org:doc:readme",
                    "content_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "schema_id": "org:schema:doc"
                },
                "org:schema:doc": {
                    "stable_id": "org:schema:doc",
                    "content_hash": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "schema_id": "org:schema:doc"
                }
            },
            "content_to_stable": {},
            "dependents": {},
            "last_seq_id": 0,
            "enforce_reserved": true
        }"#
        .to_string()
    }

    // =========================================================================
    // Profile Parsing Tests
    // =========================================================================

    #[test]
    fn test_export_parse_profile_json() {
        let temp_dir = TempDir::new().unwrap();
        let profile_path = temp_dir.path().join("profile.json");
        std::fs::write(&profile_path, minimal_profile_json()).unwrap();

        let content = read_bounded_file(&profile_path).unwrap();
        let profile = parse_target_profile(&content, &profile_path).unwrap();

        assert_eq!(profile.profile_id, "test-profile");
    }

    #[test]
    fn test_export_parse_profile_yaml() {
        let temp_dir = TempDir::new().unwrap();
        let profile_path = temp_dir.path().join("profile.yaml");
        std::fs::write(&profile_path, minimal_profile_yaml()).unwrap();

        let content = read_bounded_file(&profile_path).unwrap();
        let profile = parse_target_profile(&content, &profile_path).unwrap();

        assert_eq!(profile.profile_id, "test-profile");
    }

    #[test]
    fn test_export_parse_profile_invalid() {
        let temp_dir = TempDir::new().unwrap();
        let profile_path = temp_dir.path().join("profile.json");
        std::fs::write(&profile_path, "{ invalid json }").unwrap();

        let content = read_bounded_file(&profile_path).unwrap();
        let result = parse_target_profile(&content, &profile_path);

        assert!(matches!(result, Err(ExportCliError::Validation(_))));
    }

    // =========================================================================
    // Pack Spec Parsing Tests
    // =========================================================================

    #[test]
    fn test_export_parse_pack_spec() {
        let temp_dir = TempDir::new().unwrap();
        let pack_path = temp_dir.path().join("pack.json");
        std::fs::write(&pack_path, minimal_pack_json()).unwrap();

        let content = read_bounded_file(&pack_path).unwrap();
        let spec = parse_pack_spec(&content, &pack_path).unwrap();

        assert_eq!(spec.spec_id, "test-pack");
        assert_eq!(spec.roots, vec!["org:doc:readme"]);
    }

    #[test]
    fn test_export_no_pack_returns_error() {
        let result = load_pack_spec(None);
        assert!(matches!(result, Err(ExportCliError::Validation(_))));
    }

    // =========================================================================
    // Index Loading Tests
    // =========================================================================

    #[test]
    fn test_export_load_index() {
        let temp_dir = TempDir::new().unwrap();
        let index_path = temp_dir.path().join("index.json");
        std::fs::write(&index_path, test_index_json()).unwrap();

        let index = load_dcp_index(&index_path).unwrap();
        assert!(!index.is_empty());
    }

    // Note: test_export_no_index_returns_error removed because --index is now
    // required by Clap at argument parsing time

    // =========================================================================
    // File Size Limit Tests
    // =========================================================================

    #[test]
    fn test_export_file_too_large() {
        use std::io::Write;

        let temp_dir = TempDir::new().unwrap();
        let oversized_path = temp_dir.path().join("oversized.json");

        // Create a file that exceeds MAX_INPUT_FILE_SIZE
        {
            let mut file = std::fs::File::create(&oversized_path).unwrap();
            let chunk = vec![b'x'; 1024 * 1024]; // 1MB chunk
            for _ in 0..11 {
                // Write 11MB total
                file.write_all(&chunk).unwrap();
            }
        }

        let result = read_bounded_file(&oversized_path);
        assert!(
            matches!(result, Err(ExportCliError::Validation(msg)) if msg.contains("exceeds maximum size limit"))
        );
    }

    // =========================================================================
    // Content Resolver Tests
    // =========================================================================

    #[test]
    fn test_export_create_content_resolver() {
        let mut index = DcpIndex::new();
        // Register schema first
        let schema = DcpEntry::new(
            "org:schema:doc",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "org:schema:doc",
        );
        index.register(schema).unwrap();

        let entry = DcpEntry::new(
            "org:doc:readme",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "org:schema:doc",
        );
        index.register(entry).unwrap();

        let mut content_hashes = BTreeMap::new();
        content_hashes.insert(
            "org:doc:readme".to_string(),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
        );

        let pack = CompiledContextPack {
            manifest: CompiledManifest {
                schema: CompiledManifest::SCHEMA.to_string(),
                schema_version: CompiledManifest::SCHEMA_VERSION.to_string(),
                spec_id: "test-pack".to_string(),
                target_profile: "test-profile".to_string(),
                entries: vec![ManifestEntry {
                    stable_id: "org:doc:readme".to_string(),
                    content_hash:
                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                            .to_string(),
                    schema_id: "org:schema:doc".to_string(),
                    dependencies: vec![],
                }],
                canonicalizer_id: CompiledManifest::CANONICALIZER_ID.to_string(),
                canonicalizer_version: CompiledManifest::CANONICALIZER_VERSION.to_string(),
            },
            content_hashes,
            budget_used: BudgetUsed {
                artifact_count: TypedQuantity::artifacts(1),
                total_bytes: None,
            },
        };

        let resolver = create_content_resolver(&index, &pack);
        // Verify content is available
        let content = resolver.resolve("org:doc:readme", "").unwrap();
        assert!(!content.is_empty());
    }

    // =========================================================================
    // Integration Tests
    // =========================================================================

    #[test]
    fn test_export_integration_success() {
        let temp_dir = TempDir::new().unwrap();

        // Create profile file
        let profile_path = temp_dir.path().join("profile.json");
        std::fs::write(&profile_path, minimal_profile_json()).unwrap();

        // Create pack file
        let pack_path = temp_dir.path().join("pack.json");
        std::fs::write(&pack_path, minimal_pack_json()).unwrap();

        // Create index file
        let index_path = temp_dir.path().join("index.json");
        std::fs::write(&index_path, test_index_json()).unwrap();

        // Create output directory
        let output_dir = temp_dir.path().join("output");
        std::fs::create_dir(&output_dir).unwrap();

        let args = ExportArgs {
            profile: profile_path,
            pack: Some(pack_path),
            output_dir: output_dir.clone(),
            verify: false,
            format: OutputFormat::Json,
            index: index_path,
        };

        let exit_code = run_export(&args);
        assert_eq!(exit_code, exit_codes::SUCCESS);

        // Verify output file was created
        let output_file = output_dir.join("org/doc/readme.md");
        assert!(output_file.exists(), "Output file should be created");
    }

    #[test]
    fn test_export_integration_with_verify() {
        let temp_dir = TempDir::new().unwrap();

        // Create profile file
        let profile_path = temp_dir.path().join("profile.json");
        std::fs::write(&profile_path, minimal_profile_json()).unwrap();

        // Create pack file
        let pack_path = temp_dir.path().join("pack.json");
        std::fs::write(&pack_path, minimal_pack_json()).unwrap();

        // Create index file
        let index_path = temp_dir.path().join("index.json");
        std::fs::write(&index_path, test_index_json()).unwrap();

        // Create output directory
        let output_dir = temp_dir.path().join("output");
        std::fs::create_dir(&output_dir).unwrap();

        let args = ExportArgs {
            profile: profile_path,
            pack: Some(pack_path),
            output_dir,
            verify: true, // Enable verification
            format: OutputFormat::Yaml,
            index: index_path,
        };

        let exit_code = run_export(&args);
        assert_eq!(exit_code, exit_codes::SUCCESS);
    }

    #[test]
    fn test_export_output_dir_not_exists() {
        let temp_dir = TempDir::new().unwrap();

        let profile_path = temp_dir.path().join("profile.json");
        std::fs::write(&profile_path, minimal_profile_json()).unwrap();

        let pack_path = temp_dir.path().join("pack.json");
        std::fs::write(&pack_path, minimal_pack_json()).unwrap();

        // Create a dummy index file for testing (--index is required by Clap)
        let index_path = temp_dir.path().join("index.json");
        std::fs::write(&index_path, test_index_json()).unwrap();

        let args = ExportArgs {
            profile: profile_path,
            pack: Some(pack_path),
            output_dir: PathBuf::from("/nonexistent/path/12345"),
            verify: false,
            format: OutputFormat::Json,
            index: index_path,
        };

        let exit_code = run_export(&args);
        assert_eq!(exit_code, exit_codes::ERROR);
    }

    // Note: test_export_missing_index removed because --index is now required by
    // Clap The error handling is done by Clap at argument parsing time, not in
    // our code

    // =========================================================================
    // Output Format Tests
    // =========================================================================

    #[test]
    fn test_output_format_default_is_json() {
        assert!(matches!(OutputFormat::default(), OutputFormat::Json));
    }

    // =========================================================================
    // Error Type Tests
    // =========================================================================

    #[test]
    fn test_export_cli_error_from_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let cli_err: ExportCliError = io_err.into();
        assert!(matches!(cli_err, ExportCliError::Io(_)));
    }
}
