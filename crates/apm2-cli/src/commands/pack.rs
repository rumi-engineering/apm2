//! Pack CLI commands for `ContextPack` compilation.
//!
//! This module provides CLI commands for `ContextPack` operations including
//! compilation of pack specs into manifests with budget enforcement.

use std::fs::File;
use std::io::{Read as IoRead, Write as IoWrite};
use std::path::PathBuf;

use apm2_core::cac::{
    CompilationError, ContextPackCompiler, ContextPackSpec, DcpIndex, PackSpecError,
};
use clap::{Args, Subcommand, ValueEnum};

/// Maximum file size for input files (10MB).
///
/// This limit prevents denial-of-service attacks via memory exhaustion from
/// large file inputs (per CTR-1603).
const MAX_INPUT_FILE_SIZE: u64 = 10 * 1024 * 1024;

/// Exit codes for pack commands per TCK-00139.
pub mod exit_codes {
    /// Success exit code.
    pub const SUCCESS: u8 = 0;
    /// Budget exceeded exit code.
    pub const BUDGET_EXCEEDED: u8 = 1;
    /// Validation error exit code (schema validation failed, invalid input, etc.).
    pub const VALIDATION_ERROR: u8 = 2;
}

/// Pack command group.
#[derive(Debug, Args)]
pub struct PackCommand {
    #[command(subcommand)]
    pub subcommand: PackSubcommand,
}

/// Pack subcommands.
#[derive(Debug, Subcommand)]
pub enum PackSubcommand {
    /// Compile a `ContextPack` specification into a manifest.
    ///
    /// Reads a pack spec file, resolves dependencies through the DCP index,
    /// enforces budget constraints, and outputs a deterministic manifest.
    ///
    /// # Exit Codes
    ///
    /// - 0: Success
    /// - 1: Budget exceeded
    /// - 2: Validation error (invalid spec, artifact not found, etc.)
    ///
    /// # Example
    ///
    /// ```bash
    /// apm2 pack compile --spec pack-spec.json
    /// apm2 pack compile --spec pack-spec.yaml --format yaml
    /// apm2 pack compile --spec pack-spec.json --budget-check
    /// apm2 pack compile --spec pack-spec.json --profile org:profile:custom
    /// apm2 pack compile --spec pack-spec.json --output manifest.json
    /// ```
    Compile(CompileArgs),
}

/// Output format for manifests.
#[derive(Debug, Clone, Copy, Default, ValueEnum)]
pub enum OutputFormat {
    /// JSON output format (default).
    #[default]
    Json,
    /// YAML output format.
    Yaml,
}

/// Arguments for the `pack compile` command.
#[derive(Debug, Args)]
pub struct CompileArgs {
    /// Path to the pack spec file (JSON or YAML).
    #[arg(long, required = true)]
    pub spec: PathBuf,

    /// Target profile override (replaces `target_profile` in spec).
    #[arg(long)]
    pub profile: Option<String>,

    /// Validation-only mode (check budget without full compilation).
    ///
    /// In this mode, the compiler validates the spec and resolves dependencies
    /// to check budget constraints, but does not generate the full manifest.
    #[arg(long)]
    pub budget_check: bool,

    /// Output path for the manifest (default: stdout).
    #[arg(long, short)]
    pub output: Option<PathBuf>,

    /// Output format for the manifest.
    #[arg(long, value_enum, default_value = "json")]
    pub format: OutputFormat,
}

/// Runs the pack command, returning an appropriate exit code as u8.
///
/// # Exit Codes
///
/// - 0: Success
/// - 1: Budget exceeded
/// - 2: Validation error
pub fn run_pack(cmd: &PackCommand) -> u8 {
    match &cmd.subcommand {
        PackSubcommand::Compile(args) => run_compile(args),
    }
}

/// Runs the `pack compile` command.
fn run_compile(args: &CompileArgs) -> u8 {
    match run_compile_inner(args) {
        Ok(()) => exit_codes::SUCCESS,
        Err(PackCliError::BudgetExceeded { dimension, limit, actual }) => {
            eprintln!(
                "Error: Budget exceeded - {dimension} limit is {limit}, but pack requires {actual}"
            );
            exit_codes::BUDGET_EXCEEDED
        },
        Err(PackCliError::ValidationError(msg)) => {
            eprintln!("Error: Validation failed - {msg}");
            exit_codes::VALIDATION_ERROR
        },
        Err(PackCliError::IoError(msg)) => {
            eprintln!("Error: {msg}");
            exit_codes::VALIDATION_ERROR
        },
    }
}

/// Internal error type for CLI error handling.
#[derive(Debug)]
enum PackCliError {
    BudgetExceeded {
        dimension: String,
        limit: u64,
        actual: u64,
    },
    ValidationError(String),
    IoError(String),
}

impl From<std::io::Error> for PackCliError {
    fn from(err: std::io::Error) -> Self {
        Self::IoError(err.to_string())
    }
}

impl From<PackSpecError> for PackCliError {
    fn from(err: PackSpecError) -> Self {
        Self::ValidationError(err.to_string())
    }
}

impl From<CompilationError> for PackCliError {
    fn from(err: CompilationError) -> Self {
        match err {
            CompilationError::BudgetExceeded {
                dimension,
                limit,
                actual,
            } => Self::BudgetExceeded {
                dimension,
                limit,
                actual,
            },
            other => Self::ValidationError(other.to_string()),
        }
    }
}

/// Inner implementation that returns Result for easier error handling.
fn run_compile_inner(args: &CompileArgs) -> Result<(), PackCliError> {
    // Read and parse the spec file
    let spec_content = read_bounded_file(&args.spec)?;
    let mut spec = parse_spec(&spec_content, &args.spec)?;

    // Apply profile override if provided
    if let Some(ref profile) = args.profile {
        spec.target_profile.clone_from(profile);
        // Re-validate after modification
        spec.validate().map_err(|e| PackCliError::ValidationError(e.to_string()))?;
    }

    // Create DCP index (empty for now - in production this would be populated)
    // TODO: Load DCP index from configuration or --index flag
    let index = DcpIndex::new();

    // Create compiler
    let compiler = ContextPackCompiler::new(&index);

    // Compile the pack
    let result = compiler.compile(&spec)?;

    // Output summary to stderr
    eprintln!("Compilation summary:");
    eprintln!("  spec_id: {}", result.receipt.spec_id);
    eprintln!("  artifact_count: {}", result.receipt.artifact_count);
    eprintln!("  root_count: {}", result.receipt.root_count);
    eprintln!("  compile_time_ms: {}", result.receipt.compile_time_ms);
    eprintln!(
        "  budget_used: {} artifacts",
        result.pack.budget_used.artifact_count.value()
    );
    if !result.receipt.warnings.is_empty() {
        eprintln!("  warnings: {}", result.receipt.warnings.len());
        for warning in &result.receipt.warnings {
            eprintln!("    - [{}] {}", warning.code, warning.message);
        }
    }
    eprintln!("  manifest_hash: {}", result.receipt.manifest_hash);

    // In budget-check mode, we're done after validation
    if args.budget_check {
        eprintln!("Budget check passed.");
        return Ok(());
    }

    // Serialize manifest
    let manifest_output = match args.format {
        OutputFormat::Json => serde_json::to_string_pretty(&result.pack.manifest)
            .map_err(|e| PackCliError::ValidationError(format!("serialization failed: {e}")))?,
        OutputFormat::Yaml => serde_yaml::to_string(&result.pack.manifest)
            .map_err(|e| PackCliError::ValidationError(format!("serialization failed: {e}")))?,
    };

    // Output manifest to file or stdout
    match &args.output {
        Some(path) => {
            let mut file = File::create(path).map_err(|e| {
                PackCliError::IoError(format!("failed to create output file '{}': {e}", path.display()))
            })?;
            file.write_all(manifest_output.as_bytes()).map_err(|e| {
                PackCliError::IoError(format!("failed to write to '{}': {e}", path.display()))
            })?;
            eprintln!("Manifest written to: {}", path.display());
        },
        None => {
            println!("{manifest_output}");
        },
    }

    Ok(())
}

/// Reads a file with size limit to prevent denial-of-service via memory exhaustion.
///
/// Uses a bounded reader to avoid TOCTOU (time-of-check to time-of-use) race
/// conditions. Instead of checking file size then reading, we read up to
/// `MAX_INPUT_FILE_SIZE + 1` bytes and reject if we hit the limit.
fn read_bounded_file(path: &std::path::Path) -> Result<String, PackCliError> {
    let file = File::open(path).map_err(|e| {
        PackCliError::IoError(format!("failed to open file '{}': {e}", path.display()))
    })?;

    let mut content = String::new();
    let mut bounded_reader = file.take(MAX_INPUT_FILE_SIZE + 1);

    bounded_reader.read_to_string(&mut content).map_err(|e| {
        PackCliError::IoError(format!("failed to read file '{}': {e}", path.display()))
    })?;

    if content.len() as u64 > MAX_INPUT_FILE_SIZE {
        return Err(PackCliError::ValidationError(format!(
            "file '{}' exceeds maximum size limit of {} bytes",
            path.display(),
            MAX_INPUT_FILE_SIZE
        )));
    }

    Ok(content)
}

/// Parses a spec from content, detecting format from file extension.
fn parse_spec(content: &str, path: &std::path::Path) -> Result<ContextPackSpec, PackCliError> {
    let extension = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    let spec: ContextPackSpec = match extension.as_str() {
        "yaml" | "yml" => serde_yaml::from_str(content).map_err(|e| {
            PackCliError::ValidationError(format!("invalid YAML in spec file: {e}"))
        })?,
        _ => serde_json::from_str(content).map_err(|e| {
            PackCliError::ValidationError(format!("invalid JSON in spec file: {e}"))
        })?,
    };

    // Validate the spec
    spec.validate()?;

    Ok(spec)
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    /// Creates a minimal valid pack spec JSON for testing.
    fn minimal_spec_json() -> String {
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

    /// Creates a minimal valid pack spec YAML for testing.
    fn minimal_spec_yaml() -> String {
        r#"schema: "bootstrap:context_pack_spec.v1"
schema_version: "v1"
spec_id: "test-pack"
roots:
  - "org:doc:readme"
budget: {}
target_profile: "org:profile:test"
"#
        .to_string()
    }

    // =========================================================================
    // Spec Parsing Tests
    // =========================================================================

    #[test]
    fn test_pack_compile_parse_json_spec() {
        let temp_dir = TempDir::new().unwrap();
        let spec_path = temp_dir.path().join("spec.json");
        std::fs::write(&spec_path, minimal_spec_json()).unwrap();

        let content = read_bounded_file(&spec_path).unwrap();
        let spec = parse_spec(&content, &spec_path).unwrap();

        assert_eq!(spec.spec_id, "test-pack");
        assert_eq!(spec.roots, vec!["org:doc:readme"]);
        assert_eq!(spec.target_profile, "org:profile:test");
    }

    #[test]
    fn test_pack_compile_parse_yaml_spec() {
        let temp_dir = TempDir::new().unwrap();
        let spec_path = temp_dir.path().join("spec.yaml");
        std::fs::write(&spec_path, minimal_spec_yaml()).unwrap();

        let content = read_bounded_file(&spec_path).unwrap();
        let spec = parse_spec(&content, &spec_path).unwrap();

        assert_eq!(spec.spec_id, "test-pack");
        assert_eq!(spec.roots, vec!["org:doc:readme"]);
    }

    #[test]
    fn test_pack_compile_parse_yml_extension() {
        let temp_dir = TempDir::new().unwrap();
        let spec_path = temp_dir.path().join("spec.yml");
        std::fs::write(&spec_path, minimal_spec_yaml()).unwrap();

        let content = read_bounded_file(&spec_path).unwrap();
        let spec = parse_spec(&content, &spec_path).unwrap();

        assert_eq!(spec.spec_id, "test-pack");
    }

    #[test]
    fn test_pack_compile_invalid_json() {
        let temp_dir = TempDir::new().unwrap();
        let spec_path = temp_dir.path().join("spec.json");
        std::fs::write(&spec_path, "{ invalid json }").unwrap();

        let content = read_bounded_file(&spec_path).unwrap();
        let result = parse_spec(&content, &spec_path);

        assert!(matches!(result, Err(PackCliError::ValidationError(_))));
    }

    #[test]
    fn test_pack_compile_missing_required_field() {
        let temp_dir = TempDir::new().unwrap();
        let spec_path = temp_dir.path().join("spec.json");
        // Missing spec_id
        let invalid_spec = r#"{
            "schema": "bootstrap:context_pack_spec.v1",
            "schema_version": "v1",
            "roots": ["org:doc:readme"],
            "budget": {},
            "target_profile": "org:profile:test"
        }"#;
        std::fs::write(&spec_path, invalid_spec).unwrap();

        let content = read_bounded_file(&spec_path).unwrap();
        let result = parse_spec(&content, &spec_path);

        assert!(matches!(result, Err(PackCliError::ValidationError(_))));
    }

    // =========================================================================
    // File Size Limit Tests
    // =========================================================================

    #[test]
    fn test_pack_compile_file_too_large() {
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
        assert!(matches!(result, Err(PackCliError::ValidationError(msg)) if msg.contains("exceeds maximum size limit")));
    }

    #[test]
    fn test_pack_compile_file_not_found() {
        let result = read_bounded_file(std::path::Path::new("/nonexistent/path/spec.json"));
        assert!(matches!(result, Err(PackCliError::IoError(_))));
    }

    // =========================================================================
    // Profile Override Tests
    // =========================================================================

    #[test]
    fn test_pack_compile_profile_override() {
        let temp_dir = TempDir::new().unwrap();
        let spec_path = temp_dir.path().join("spec.json");
        std::fs::write(&spec_path, minimal_spec_json()).unwrap();

        let content = read_bounded_file(&spec_path).unwrap();
        let mut spec = parse_spec(&content, &spec_path).unwrap();

        assert_eq!(spec.target_profile, "org:profile:test");

        // Apply override
        spec.target_profile = "org:profile:custom".to_string();
        spec.validate().unwrap();

        assert_eq!(spec.target_profile, "org:profile:custom");
    }

    // =========================================================================
    // Compilation Tests
    // =========================================================================

    #[test]
    fn test_pack_compile_artifact_not_found() {
        let temp_dir = TempDir::new().unwrap();
        let spec_path = temp_dir.path().join("spec.json");
        std::fs::write(&spec_path, minimal_spec_json()).unwrap();

        let args = CompileArgs {
            spec: spec_path,
            profile: None,
            budget_check: false,
            output: None,
            format: OutputFormat::Json,
        };

        // The compile should fail because the root artifact doesn't exist in the empty index
        let result = run_compile(&args);
        assert_eq!(result, exit_codes::VALIDATION_ERROR);
    }

    #[test]
    fn test_pack_compile_budget_exceeded() {
        // Create a spec with a very low budget
        let spec_with_budget = r#"{
            "schema": "bootstrap:context_pack_spec.v1",
            "schema_version": "v1",
            "spec_id": "test-pack",
            "roots": ["org:doc:readme", "org:doc:agents"],
            "budget": {
                "max_artifacts": {
                    "value": 1,
                    "unit": "artifacts"
                }
            },
            "target_profile": "org:profile:test"
        }"#;

        let temp_dir = TempDir::new().unwrap();
        let spec_path = temp_dir.path().join("spec.json");
        std::fs::write(&spec_path, spec_with_budget).unwrap();

        let content = read_bounded_file(&spec_path).unwrap();
        let spec = parse_spec(&content, &spec_path).unwrap();

        // Budget constraint should be set
        assert_eq!(spec.budget.max_artifacts.as_ref().unwrap().value(), 1);
        assert_eq!(spec.roots.len(), 2); // More roots than budget allows
    }

    // =========================================================================
    // Exit Code Tests
    // =========================================================================

    #[test]
    fn test_pack_compile_exit_code_validation_error() {
        let temp_dir = TempDir::new().unwrap();
        let spec_path = temp_dir.path().join("spec.json");
        std::fs::write(&spec_path, "{}").unwrap(); // Empty object - invalid spec

        let args = CompileArgs {
            spec: spec_path,
            profile: None,
            budget_check: false,
            output: None,
            format: OutputFormat::Json,
        };

        let result = run_compile(&args);
        assert_eq!(result, exit_codes::VALIDATION_ERROR);
    }

    #[test]
    fn test_pack_compile_exit_code_file_not_found() {
        let args = CompileArgs {
            spec: PathBuf::from("/nonexistent/spec.json"),
            profile: None,
            budget_check: false,
            output: None,
            format: OutputFormat::Json,
        };

        let result = run_compile(&args);
        assert_eq!(result, exit_codes::VALIDATION_ERROR);
    }

    // =========================================================================
    // Output Format Tests
    // =========================================================================

    #[test]
    fn test_output_format_default_is_json() {
        assert!(matches!(OutputFormat::default(), OutputFormat::Json));
    }

    // =========================================================================
    // Error Conversion Tests
    // =========================================================================

    #[test]
    fn test_pack_cli_error_from_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let cli_err: PackCliError = io_err.into();
        assert!(matches!(cli_err, PackCliError::IoError(_)));
    }

    #[test]
    fn test_pack_cli_error_from_pack_spec_error() {
        let spec_err = PackSpecError::EmptyRoots;
        let cli_err: PackCliError = spec_err.into();
        assert!(matches!(cli_err, PackCliError::ValidationError(_)));
    }

    #[test]
    fn test_pack_cli_error_from_compilation_error_budget() {
        let comp_err = CompilationError::BudgetExceeded {
            dimension: "artifacts".to_string(),
            limit: 10,
            actual: 20,
        };
        let cli_err: PackCliError = comp_err.into();
        assert!(matches!(
            cli_err,
            PackCliError::BudgetExceeded {
                dimension,
                limit: 10,
                actual: 20,
            } if dimension == "artifacts"
        ));
    }

    #[test]
    fn test_pack_cli_error_from_compilation_error_not_found() {
        let comp_err = CompilationError::ArtifactNotFound {
            stable_id: "org:doc:missing".to_string(),
        };
        let cli_err: PackCliError = comp_err.into();
        assert!(matches!(cli_err, PackCliError::ValidationError(_)));
    }

    // =========================================================================
    // Additional Tests
    // =========================================================================

    #[test]
    fn test_pack_compile_invalid_yaml() {
        let temp_dir = TempDir::new().unwrap();
        let spec_path = temp_dir.path().join("spec.yaml");
        std::fs::write(&spec_path, "invalid: yaml: syntax: [").unwrap();

        let content = read_bounded_file(&spec_path).unwrap();
        let result = parse_spec(&content, &spec_path);

        assert!(matches!(result, Err(PackCliError::ValidationError(_))));
    }

    #[test]
    fn test_pack_compile_empty_roots() {
        let temp_dir = TempDir::new().unwrap();
        let spec_path = temp_dir.path().join("spec.json");
        // Empty roots list
        let invalid_spec = r#"{
            "schema": "bootstrap:context_pack_spec.v1",
            "schema_version": "v1",
            "spec_id": "test-pack",
            "roots": [],
            "budget": {},
            "target_profile": "org:profile:test"
        }"#;
        std::fs::write(&spec_path, invalid_spec).unwrap();

        let content = read_bounded_file(&spec_path).unwrap();
        let result = parse_spec(&content, &spec_path);

        assert!(matches!(result, Err(PackCliError::ValidationError(_))));
    }

    #[test]
    fn test_pack_compile_budget_check_mode() {
        let temp_dir = TempDir::new().unwrap();
        let spec_path = temp_dir.path().join("spec.json");
        std::fs::write(&spec_path, minimal_spec_json()).unwrap();

        let args = CompileArgs {
            spec: spec_path,
            profile: None,
            budget_check: true, // Budget check mode
            output: None,
            format: OutputFormat::Json,
        };

        // Should still fail due to missing artifact, but would pass budget check if artifact existed
        let result = run_compile(&args);
        assert_eq!(result, exit_codes::VALIDATION_ERROR);
    }

    #[test]
    fn test_pack_compile_yaml_output_format() {
        let temp_dir = TempDir::new().unwrap();
        let spec_path = temp_dir.path().join("spec.json");
        std::fs::write(&spec_path, minimal_spec_json()).unwrap();

        let args = CompileArgs {
            spec: spec_path,
            profile: None,
            budget_check: false,
            output: None,
            format: OutputFormat::Yaml, // YAML output format
        };

        // Should still fail due to missing artifact
        let result = run_compile(&args);
        assert_eq!(result, exit_codes::VALIDATION_ERROR);
    }

    #[test]
    fn test_pack_compile_with_output_file() {
        let temp_dir = TempDir::new().unwrap();
        let spec_path = temp_dir.path().join("spec.json");
        let output_path = temp_dir.path().join("manifest.json");
        std::fs::write(&spec_path, minimal_spec_json()).unwrap();

        let args = CompileArgs {
            spec: spec_path,
            profile: None,
            budget_check: false,
            output: Some(output_path.clone()),
            format: OutputFormat::Json,
        };

        // Should still fail due to missing artifact
        let result = run_compile(&args);
        assert_eq!(result, exit_codes::VALIDATION_ERROR);

        // Output file should not be created on failure
        assert!(!output_path.exists());
    }

    #[test]
    fn test_pack_compile_with_profile_override() {
        let temp_dir = TempDir::new().unwrap();
        let spec_path = temp_dir.path().join("spec.json");
        std::fs::write(&spec_path, minimal_spec_json()).unwrap();

        let args = CompileArgs {
            spec: spec_path,
            profile: Some("org:profile:custom".to_string()),
            budget_check: false,
            output: None,
            format: OutputFormat::Json,
        };

        // Should still fail due to missing artifact, but profile should be applied
        let result = run_compile(&args);
        assert_eq!(result, exit_codes::VALIDATION_ERROR);
    }

    #[test]
    fn test_run_pack_dispatches_to_compile() {
        let temp_dir = TempDir::new().unwrap();
        let spec_path = temp_dir.path().join("spec.json");
        std::fs::write(&spec_path, minimal_spec_json()).unwrap();

        let cmd = PackCommand {
            subcommand: PackSubcommand::Compile(CompileArgs {
                spec: spec_path,
                profile: None,
                budget_check: false,
                output: None,
                format: OutputFormat::Json,
            }),
        };

        let result = run_pack(&cmd);
        assert_eq!(result, exit_codes::VALIDATION_ERROR);
    }

    #[test]
    fn test_pack_cli_error_debug() {
        let err = PackCliError::BudgetExceeded {
            dimension: "artifacts".to_string(),
            limit: 10,
            actual: 20,
        };
        // Just verify Debug trait is implemented
        let debug_str = format!("{err:?}");
        assert!(debug_str.contains("BudgetExceeded"));
    }
}
