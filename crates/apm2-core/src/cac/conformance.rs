//! Export conformance testing module.
//!
//! This module provides conformance tests to verify that export operations
//! produce deterministic, well-formed outputs with proper provenance.
//!
//! # Design Principles
//!
//! - **Determinism Verification**: Re-exporting the same pack produces
//!   byte-identical output (DD-0005)
//! - **Provenance Validation**: Exported files contain valid, parseable
//!   provenance metadata
//! - **Schema Compliance**: Output structure matches expected format
//! - **Auditable Results**: All tests produce receipts for audit trails
//!
//! # Architecture
//!
//! ```text
//! ConformanceTest (specification)
//!        |
//!        v
//! run_conformance_suite()
//!        |
//!        ├──> verify_determinism() - export twice, compare bytes
//!        ├──> verify_provenance() - parse frontmatter, validate fields
//!        └──> verify_schema() - validate output structure
//!        |
//!        v
//! ExportReceipt (auditable result)
//! ```
//!
//! # Example
//!
//! ```ignore
//! use apm2_core::cac::conformance::{ConformanceTest, ExportReceipt, run_conformance_suite};
//!
//! let tests = vec![
//!     ConformanceTest::new("determinism", "sha256:...", "pack-ref"),
//! ];
//!
//! let receipt = run_conformance_suite(
//!     &pack,
//!     &resolver,
//!     &pipeline,
//!     "claude-code-v1",
//!     timestamp,
//!     &tests,
//! )?;
//!
//! assert!(receipt.overall_passed);
//! ```

use std::fmt::Write;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::compiler::CompiledContextPack;
use super::export::{
    ContentResolver, ExportConfig, ExportError, ExportManifest, ExportPipeline, Provenance,
};
use super::target_profile::TargetProfile;

// ============================================================================
// Constants
// ============================================================================

/// Conformance test module version for schema evolution tracking.
pub const CONFORMANCE_VERSION: &str = "v1";

/// Schema identifier for export receipts.
pub const EXPORT_RECEIPT_SCHEMA: &str = "bootstrap:export_receipt.v1";

/// Maximum number of conformance tests in a single suite (`DoS` prevention).
pub const MAX_CONFORMANCE_TESTS: usize = 1000;

/// Required provenance fields that must be present in frontmatter.
const REQUIRED_PROVENANCE_FIELDS: &[&str] = &[
    "source_pack_hash",
    "export_profile",
    "export_timestamp",
    "exporter_version",
];

/// YAML frontmatter delimiter.
const YAML_FRONTMATTER_DELIMITER: &str = "---";

// ============================================================================
// Errors
// ============================================================================

/// Errors that can occur during conformance testing.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ConformanceError {
    /// Determinism verification failed - two exports produced different bytes.
    #[error(
        "determinism verification failed: export 1 hash {hash1} != export 2 hash {hash2} for path {path}"
    )]
    DeterminismFailure {
        /// Hash of first export.
        hash1: String,
        /// Hash of second export.
        hash2: String,
        /// Path that differed.
        path: String,
    },

    /// Provenance parsing failed - frontmatter could not be extracted.
    #[error("provenance parsing failed for '{path}': {reason}")]
    ProvenanceParsingFailed {
        /// Path with invalid provenance.
        path: String,
        /// Reason for failure.
        reason: String,
    },

    /// Required provenance field is missing.
    #[error("provenance field '{field}' is missing in '{path}'")]
    ProvenanceMissingField {
        /// The missing field name.
        field: String,
        /// Path with missing field.
        path: String,
    },

    /// Provenance field has invalid value.
    #[error("provenance field '{field}' has invalid value in '{path}': {reason}")]
    ProvenanceInvalidField {
        /// The field with invalid value.
        field: String,
        /// Path containing the field.
        path: String,
        /// Reason for invalidity.
        reason: String,
    },

    /// Schema validation failed for export output.
    #[error("schema validation failed for '{path}': {reason}")]
    SchemaValidationFailed {
        /// Path that failed validation.
        path: String,
        /// Reason for failure.
        reason: String,
    },

    /// Export operation failed during conformance test.
    #[error("export operation failed: {0}")]
    ExportFailed(#[from] ExportError),

    /// Too many conformance tests specified (`DoS` prevention).
    #[error("too many conformance tests: {count} exceeds maximum of {max}")]
    TooManyTests {
        /// Number of tests requested.
        count: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Invalid test specification.
    #[error("invalid conformance test specification: {reason}")]
    InvalidTestSpec {
        /// Reason for invalidity.
        reason: String,
    },

    /// Content not valid UTF-8 for text-based verification.
    #[error("content at '{path}' is not valid UTF-8")]
    InvalidUtf8 {
        /// Path with invalid content.
        path: String,
    },
}

// ============================================================================
// ConformanceTest
// ============================================================================

/// A conformance test specification.
///
/// Each test specifies what to verify about an export operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConformanceTest {
    /// Unique identifier for this test.
    pub test_id: String,

    /// Expected hash of the export output (sha256 or blake3).
    /// If provided, the export output hash will be compared against this.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_hash: Option<String>,

    /// Reference to the pack being tested.
    pub pack_ref: String,
}

impl ConformanceTest {
    /// Creates a new conformance test.
    #[must_use]
    pub fn new(
        test_id: impl Into<String>,
        expected_hash: Option<String>,
        pack_ref: impl Into<String>,
    ) -> Self {
        Self {
            test_id: test_id.into(),
            expected_hash,
            pack_ref: pack_ref.into(),
        }
    }

    /// Creates a determinism test (no expected hash, just verifies
    /// repeatability).
    #[must_use]
    pub fn determinism(test_id: impl Into<String>, pack_ref: impl Into<String>) -> Self {
        Self::new(test_id, None, pack_ref)
    }

    /// Creates a golden test with expected hash.
    #[must_use]
    pub fn golden(
        test_id: impl Into<String>,
        expected_hash: impl Into<String>,
        pack_ref: impl Into<String>,
    ) -> Self {
        Self::new(test_id, Some(expected_hash.into()), pack_ref)
    }
}

// ============================================================================
// ConformanceTestResult
// ============================================================================

/// Result of a single conformance test.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConformanceTestResult {
    /// The test identifier.
    pub test_id: String,

    /// Whether the test passed.
    pub passed: bool,

    /// Error message if the test failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,

    /// Duration of the test in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
}

impl ConformanceTestResult {
    /// Creates a passing test result.
    #[must_use]
    pub fn pass(test_id: impl Into<String>, duration_ms: Option<u64>) -> Self {
        Self {
            test_id: test_id.into(),
            passed: true,
            error: None,
            duration_ms,
        }
    }

    /// Creates a failing test result.
    #[must_use]
    pub fn fail(
        test_id: impl Into<String>,
        error: impl Into<String>,
        duration_ms: Option<u64>,
    ) -> Self {
        Self {
            test_id: test_id.into(),
            passed: false,
            error: Some(error.into()),
            duration_ms,
        }
    }
}

// ============================================================================
// ExportReceipt
// ============================================================================

/// Receipt documenting the results of export conformance testing.
///
/// This struct provides auditable evidence that an export operation
/// passed conformance tests. It follows the schema defined in TCK-00142.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportReceipt {
    /// Schema identifier for this receipt format.
    pub schema: String,

    /// Schema version.
    pub schema_version: String,

    /// BLAKE3 hash of the exported pack manifest.
    pub pack_hash: String,

    /// Profile ID used for export.
    pub profile_id: String,

    /// Results of individual conformance tests.
    pub conformance_tests: Vec<ConformanceTestResult>,

    /// Whether all conformance tests passed.
    pub overall_passed: bool,

    /// Timestamp when the receipt was generated (ISO 8601).
    pub timestamp: String,

    /// Total duration of all tests in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_duration_ms: Option<u64>,
}

impl ExportReceipt {
    /// Creates a new export receipt.
    #[must_use]
    pub fn new(
        pack_hash: impl Into<String>,
        profile_id: impl Into<String>,
        conformance_tests: Vec<ConformanceTestResult>,
        timestamp: DateTime<Utc>,
    ) -> Self {
        let overall_passed = conformance_tests.iter().all(|t| t.passed);
        let total_duration_ms: Option<u64> = {
            let sum: u64 = conformance_tests.iter().filter_map(|t| t.duration_ms).sum();
            if sum > 0 { Some(sum) } else { None }
        };

        Self {
            schema: EXPORT_RECEIPT_SCHEMA.to_string(),
            schema_version: CONFORMANCE_VERSION.to_string(),
            pack_hash: pack_hash.into(),
            profile_id: profile_id.into(),
            conformance_tests,
            overall_passed,
            timestamp: timestamp.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            total_duration_ms,
        }
    }

    /// Returns the number of passed tests.
    #[must_use]
    pub fn passed_count(&self) -> usize {
        self.conformance_tests.iter().filter(|t| t.passed).count()
    }

    /// Returns the number of failed tests.
    #[must_use]
    pub fn failed_count(&self) -> usize {
        self.conformance_tests.iter().filter(|t| !t.passed).count()
    }

    /// Returns a summary string for display.
    #[must_use]
    pub fn summary(&self) -> String {
        let total = self.conformance_tests.len();
        let passed = self.passed_count();
        let failed = self.failed_count();

        let mut summary = String::new();
        let _ = write!(summary, "Export conformance: {passed}/{total} tests passed");

        if failed > 0 {
            let _ = write!(summary, " ({failed} failed)");
        }

        if let Some(duration) = self.total_duration_ms {
            let _ = write!(summary, " in {duration}ms");
        }

        summary
    }
}

// ============================================================================
// Verification Functions
// ============================================================================

/// Verifies export determinism by exporting twice and comparing bytes.
///
/// This is the primary determinism test: given the same inputs, exports
/// must produce byte-identical outputs.
///
/// # Arguments
///
/// * `pack` - The compiled context pack to export
/// * `resolver` - Content resolver for artifact content
/// * `profile` - Target profile for export
/// * `timestamp` - Fixed timestamp for determinism
/// * `output_dir1` - First output directory (temporary)
/// * `output_dir2` - Second output directory (temporary)
///
/// # Returns
///
/// `Ok(())` if both exports are byte-identical, or an error describing
/// the difference.
///
/// # Errors
///
/// Returns [`ConformanceError::DeterminismFailure`] if outputs differ.
/// Returns [`ConformanceError::ExportFailed`] if export operations fail.
pub fn verify_determinism<R: ContentResolver>(
    pack: &CompiledContextPack,
    resolver: &R,
    profile: &TargetProfile,
    timestamp: DateTime<Utc>,
    exporter_version: &str,
    output_dir1: &std::path::Path,
    output_dir2: &std::path::Path,
) -> Result<(), ConformanceError> {
    // Create pipelines with identical configuration
    let config1 = ExportConfig {
        profile: profile.clone(),
        output_dir: output_dir1.to_path_buf(),
        timestamp,
        exporter_version: exporter_version.to_string(),
    };

    let config2 = ExportConfig {
        profile: profile.clone(),
        output_dir: output_dir2.to_path_buf(),
        timestamp,
        exporter_version: exporter_version.to_string(),
    };

    let pipeline1 = ExportPipeline::new(config1)?;
    let pipeline2 = ExportPipeline::new(config2)?;

    // Export twice
    let manifest1 = pipeline1.export(pack, resolver)?;
    let manifest2 = pipeline2.export(pack, resolver)?;

    // Compare manifests (excluding paths which are relative to different dirs)
    if manifest1.outputs.len() != manifest2.outputs.len() {
        return Err(ConformanceError::DeterminismFailure {
            hash1: format!("{} outputs", manifest1.outputs.len()),
            hash2: format!("{} outputs", manifest2.outputs.len()),
            path: "manifest.outputs".to_string(),
        });
    }

    // Compare each output's content hash
    for (o1, o2) in manifest1.outputs.iter().zip(manifest2.outputs.iter()) {
        if o1.content_hash != o2.content_hash {
            return Err(ConformanceError::DeterminismFailure {
                hash1: o1.content_hash.clone(),
                hash2: o2.content_hash.clone(),
                path: o1.path.to_string_lossy().to_string(),
            });
        }
    }

    // Compare actual file contents
    for output in &manifest1.outputs {
        let path1 = output_dir1.join(&output.path);
        let path2 = output_dir2.join(&output.path);

        let content1 = std::fs::read(&path1).map_err(|e| {
            ConformanceError::ExportFailed(ExportError::AtomicWriteFailed {
                path: path1.clone(),
                source: crate::determinism::AtomicWriteError::TempFileCreation(e),
            })
        })?;

        let content2 = std::fs::read(&path2).map_err(|e| {
            ConformanceError::ExportFailed(ExportError::AtomicWriteFailed {
                path: path2.clone(),
                source: crate::determinism::AtomicWriteError::TempFileCreation(e),
            })
        })?;

        if content1 != content2 {
            let hash1 = hex::encode(blake3::hash(&content1).as_bytes());
            let hash2 = hex::encode(blake3::hash(&content2).as_bytes());

            return Err(ConformanceError::DeterminismFailure {
                hash1,
                hash2,
                path: output.path.to_string_lossy().to_string(),
            });
        }
    }

    Ok(())
}

/// Verifies provenance metadata in exported content.
///
/// Parses the YAML frontmatter and validates that all required fields
/// are present and have valid values.
///
/// # Arguments
///
/// * `content` - The exported file content (UTF-8)
/// * `path` - Path to the file (for error reporting)
/// * `expected_profile` - Expected profile ID in provenance
///
/// # Returns
///
/// `Ok(Provenance)` if valid, or an error describing the issue.
///
/// # Errors
///
/// Returns [`ConformanceError::ProvenanceParsingFailed`] if frontmatter cannot
/// be parsed. Returns [`ConformanceError::ProvenanceMissingField`] if required
/// fields are missing. Returns [`ConformanceError::ProvenanceInvalidField`] if
/// field values are invalid.
pub fn verify_provenance(
    content: &str,
    path: &std::path::Path,
    expected_profile: Option<&str>,
) -> Result<Provenance, ConformanceError> {
    let path_str = path.to_string_lossy().to_string();

    // Extract frontmatter
    let frontmatter =
        extract_frontmatter(content).ok_or_else(|| ConformanceError::ProvenanceParsingFailed {
            path: path_str.clone(),
            reason: "no YAML frontmatter found (expected to start with '---')".to_string(),
        })?;

    // Parse as YAML
    let yaml: serde_yaml::Value = serde_yaml::from_str(&frontmatter).map_err(|e| {
        ConformanceError::ProvenanceParsingFailed {
            path: path_str.clone(),
            reason: format!("invalid YAML: {e}"),
        }
    })?;

    // Get provenance section
    let provenance_section =
        yaml.get("provenance")
            .ok_or_else(|| ConformanceError::ProvenanceParsingFailed {
                path: path_str.clone(),
                reason: "no 'provenance' section in frontmatter".to_string(),
            })?;

    // Validate required fields
    for field in REQUIRED_PROVENANCE_FIELDS {
        if provenance_section.get(*field).is_none() {
            return Err(ConformanceError::ProvenanceMissingField {
                field: (*field).to_string(),
                path: path_str.clone(),
            });
        }
    }

    // Extract and validate field values
    let source_pack_hash = provenance_section
        .get("source_pack_hash")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ConformanceError::ProvenanceInvalidField {
            field: "source_pack_hash".to_string(),
            path: path_str.clone(),
            reason: "must be a string".to_string(),
        })?;

    // Validate source_pack_hash format (should start with "sha256:" or "blake3:")
    if !source_pack_hash.starts_with("sha256:") && !source_pack_hash.starts_with("blake3:") {
        return Err(ConformanceError::ProvenanceInvalidField {
            field: "source_pack_hash".to_string(),
            path: path_str.clone(),
            reason: format!("must start with 'sha256:' or 'blake3:', got '{source_pack_hash}'"),
        });
    }

    let export_profile = provenance_section
        .get("export_profile")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ConformanceError::ProvenanceInvalidField {
            field: "export_profile".to_string(),
            path: path_str.clone(),
            reason: "must be a string".to_string(),
        })?;

    // Validate profile ID if expected
    if let Some(expected) = expected_profile {
        if export_profile != expected {
            return Err(ConformanceError::ProvenanceInvalidField {
                field: "export_profile".to_string(),
                path: path_str.clone(),
                reason: format!("expected '{expected}', got '{export_profile}'"),
            });
        }
    }

    let export_timestamp = provenance_section
        .get("export_timestamp")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ConformanceError::ProvenanceInvalidField {
            field: "export_timestamp".to_string(),
            path: path_str.clone(),
            reason: "must be a string".to_string(),
        })?;

    // Validate timestamp format (ISO 8601)
    if !is_valid_iso8601_timestamp(export_timestamp) {
        return Err(ConformanceError::ProvenanceInvalidField {
            field: "export_timestamp".to_string(),
            path: path_str.clone(),
            reason: format!(
                "must be ISO 8601 format (YYYY-MM-DDTHH:MM:SSZ), got '{export_timestamp}'"
            ),
        });
    }

    let exporter_version = provenance_section
        .get("exporter_version")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ConformanceError::ProvenanceInvalidField {
            field: "exporter_version".to_string(),
            path: path_str.clone(),
            reason: "must be a string".to_string(),
        })?;

    // Construct provenance (use a dummy timestamp since we've validated the string)
    Ok(Provenance {
        source_pack_hash: source_pack_hash.to_string(),
        export_profile: export_profile.to_string(),
        export_timestamp: export_timestamp.to_string(),
        exporter_version: exporter_version.to_string(),
    })
}

/// Verifies that export output matches expected schema.
///
/// For Markdown exports, validates:
/// - Frontmatter structure
/// - Provenance fields
/// - Content after frontmatter
///
/// For JSON exports, validates:
/// - Valid JSON structure
/// - `_provenance` field if using Metadata embed mode
///
/// # Arguments
///
/// * `content` - The exported file content
/// * `path` - Path to the file (for error reporting)
/// * `expected_format` - Expected output format
///
/// # Returns
///
/// `Ok(())` if schema is valid, or an error describing the issue.
///
/// # Errors
///
/// Returns [`ConformanceError::SchemaValidationFailed`] if output doesn't match
/// expected schema.
pub fn verify_schema(
    content: &[u8],
    path: &std::path::Path,
    expected_format: OutputFormat,
) -> Result<(), ConformanceError> {
    let path_str = path.to_string_lossy().to_string();

    match expected_format {
        OutputFormat::Markdown | OutputFormat::PlainText => {
            // Validate UTF-8
            let content_str =
                std::str::from_utf8(content).map_err(|_| ConformanceError::InvalidUtf8 {
                    path: path_str.clone(),
                })?;

            // For text formats with frontmatter, validate structure
            if content_str.starts_with(YAML_FRONTMATTER_DELIMITER) {
                // Ensure frontmatter is properly closed
                let after_first = &content_str[3..]; // Skip first "---"
                if !after_first.contains(YAML_FRONTMATTER_DELIMITER) {
                    return Err(ConformanceError::SchemaValidationFailed {
                        path: path_str,
                        reason: "YAML frontmatter is not properly closed".to_string(),
                    });
                }
            }

            Ok(())
        },
        OutputFormat::Json => {
            // Validate UTF-8
            let content_str =
                std::str::from_utf8(content).map_err(|_| ConformanceError::InvalidUtf8 {
                    path: path_str.clone(),
                })?;

            // Validate JSON structure
            let _: serde_json::Value = serde_json::from_str(content_str).map_err(|e| {
                ConformanceError::SchemaValidationFailed {
                    path: path_str.clone(),
                    reason: format!("invalid JSON: {e}"),
                }
            })?;

            Ok(())
        },
        OutputFormat::Xml => {
            // XML validation is out of scope for this ticket
            // Just verify it's not empty
            if content.is_empty() {
                return Err(ConformanceError::SchemaValidationFailed {
                    path: path_str,
                    reason: "XML content is empty".to_string(),
                });
            }
            Ok(())
        },
    }
}

/// Output format for schema verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    /// Markdown format (.md)
    Markdown,
    /// Plain text format (.txt)
    PlainText,
    /// JSON format (.json)
    Json,
    /// XML format (.xml)
    Xml,
}

impl From<super::target_profile::OutputFormat> for OutputFormat {
    fn from(format: super::target_profile::OutputFormat) -> Self {
        match format {
            super::target_profile::OutputFormat::Markdown => Self::Markdown,
            super::target_profile::OutputFormat::PlainText => Self::PlainText,
            super::target_profile::OutputFormat::Json => Self::Json,
            super::target_profile::OutputFormat::Xml => Self::Xml,
        }
    }
}

// ============================================================================
// Conformance Suite Runner
// ============================================================================

/// Configuration for running the conformance suite.
#[derive(Debug, Clone)]
pub struct ConformanceSuiteConfig {
    /// Enable determinism verification (export twice and compare).
    pub verify_determinism: bool,

    /// Enable provenance verification (parse and validate frontmatter).
    pub verify_provenance: bool,

    /// Enable schema verification (validate output structure).
    pub verify_schema: bool,
}

impl Default for ConformanceSuiteConfig {
    fn default() -> Self {
        Self {
            verify_determinism: true,
            verify_provenance: true,
            verify_schema: true,
        }
    }
}

/// Runs the conformance test suite for an export operation.
///
/// This is the main entry point for export conformance testing.
/// It runs determinism, provenance, and schema verification tests
/// and produces an auditable receipt.
///
/// # Arguments
///
/// * `pack` - The compiled context pack to test
/// * `resolver` - Content resolver for artifact content
/// * `profile` - Target profile for export
/// * `timestamp` - Timestamp for export (injected for determinism)
/// * `exporter_version` - Version of the exporter
/// * `tests` - List of conformance tests to run
/// * `config` - Suite configuration
///
/// # Returns
///
/// An [`ExportReceipt`] documenting the test results.
///
/// # Errors
///
/// Returns [`ConformanceError::TooManyTests`] if too many tests are specified.
/// Individual test failures are captured in the receipt, not returned as
/// errors.
pub fn run_conformance_suite<R: ContentResolver>(
    pack: &CompiledContextPack,
    resolver: &R,
    profile: &TargetProfile,
    timestamp: DateTime<Utc>,
    exporter_version: &str,
    tests: &[ConformanceTest],
    config: &ConformanceSuiteConfig,
) -> Result<ExportReceipt, ConformanceError> {
    // Validate test count
    if tests.len() > MAX_CONFORMANCE_TESTS {
        return Err(ConformanceError::TooManyTests {
            count: tests.len(),
            max: MAX_CONFORMANCE_TESTS,
        });
    }

    let _start = std::time::Instant::now();
    let mut results = Vec::with_capacity(tests.len() + 3); // +3 for built-in tests

    // Run built-in determinism test if enabled
    if config.verify_determinism {
        let test_start = std::time::Instant::now();
        let result = run_determinism_test(pack, resolver, profile, timestamp, exporter_version);
        // Saturate at u64::MAX for durations exceeding ~584 million years
        #[allow(clippy::cast_possible_truncation)]
        let duration_ms = Some(test_start.elapsed().as_millis().min(u128::from(u64::MAX)) as u64);

        match result {
            Ok(()) => results.push(ConformanceTestResult::pass("determinism", duration_ms)),
            Err(e) => results.push(ConformanceTestResult::fail(
                "determinism",
                e.to_string(),
                duration_ms,
            )),
        }
    }

    // Run provenance and schema tests by exporting once
    if config.verify_provenance || config.verify_schema {
        let temp_dir = tempfile::TempDir::new().map_err(|e| {
            ConformanceError::ExportFailed(ExportError::ConfigurationError {
                message: format!("failed to create temp directory: {e}"),
            })
        })?;

        let export_config = ExportConfig {
            profile: profile.clone(),
            output_dir: temp_dir.path().to_path_buf(),
            timestamp,
            exporter_version: exporter_version.to_string(),
        };

        let pipeline = ExportPipeline::new(export_config)?;
        let manifest = pipeline.export(pack, resolver)?;

        // Run provenance test if enabled
        if config.verify_provenance {
            let test_start = std::time::Instant::now();
            let result = run_provenance_test(&manifest, temp_dir.path(), &profile.profile_id);
            // Saturate at u64::MAX for durations exceeding ~584 million years
            #[allow(clippy::cast_possible_truncation)]
            let duration_ms =
                Some(test_start.elapsed().as_millis().min(u128::from(u64::MAX)) as u64);

            match result {
                Ok(()) => results.push(ConformanceTestResult::pass("provenance", duration_ms)),
                Err(e) => results.push(ConformanceTestResult::fail(
                    "provenance",
                    e.to_string(),
                    duration_ms,
                )),
            }
        }

        // Run schema test if enabled
        if config.verify_schema {
            let test_start = std::time::Instant::now();
            let result = run_schema_test(&manifest, temp_dir.path(), profile);
            // Saturate at u64::MAX for durations exceeding ~584 million years
            #[allow(clippy::cast_possible_truncation)]
            let duration_ms =
                Some(test_start.elapsed().as_millis().min(u128::from(u64::MAX)) as u64);

            match result {
                Ok(()) => results.push(ConformanceTestResult::pass("schema", duration_ms)),
                Err(e) => results.push(ConformanceTestResult::fail(
                    "schema",
                    e.to_string(),
                    duration_ms,
                )),
            }
        }
    }

    // Run custom tests
    for test in tests {
        let test_start = std::time::Instant::now();
        let result = run_custom_test(test, pack);
        // Saturate at u64::MAX for durations exceeding ~584 million years
        #[allow(clippy::cast_possible_truncation)]
        let duration_ms = Some(test_start.elapsed().as_millis().min(u128::from(u64::MAX)) as u64);

        match result {
            Ok(()) => results.push(ConformanceTestResult::pass(&test.test_id, duration_ms)),
            Err(e) => results.push(ConformanceTestResult::fail(
                &test.test_id,
                e.to_string(),
                duration_ms,
            )),
        }
    }

    // Compute pack hash
    let manifest_json = serde_json::to_string(&pack.manifest).unwrap_or_default();
    let pack_hash = hex::encode(blake3::hash(manifest_json.as_bytes()).as_bytes());

    Ok(ExportReceipt::new(
        format!("blake3:{pack_hash}"),
        &profile.profile_id,
        results,
        timestamp,
    ))
}

/// Runs the determinism test.
fn run_determinism_test<R: ContentResolver>(
    pack: &CompiledContextPack,
    resolver: &R,
    profile: &TargetProfile,
    timestamp: DateTime<Utc>,
    exporter_version: &str,
) -> Result<(), ConformanceError> {
    let temp_dir1 = tempfile::TempDir::new().map_err(|e| {
        ConformanceError::ExportFailed(ExportError::ConfigurationError {
            message: format!("failed to create temp directory 1: {e}"),
        })
    })?;

    let temp_dir2 = tempfile::TempDir::new().map_err(|e| {
        ConformanceError::ExportFailed(ExportError::ConfigurationError {
            message: format!("failed to create temp directory 2: {e}"),
        })
    })?;

    verify_determinism(
        pack,
        resolver,
        profile,
        timestamp,
        exporter_version,
        temp_dir1.path(),
        temp_dir2.path(),
    )
}

/// Runs the provenance test.
fn run_provenance_test(
    manifest: &ExportManifest,
    output_dir: &std::path::Path,
    expected_profile: &str,
) -> Result<(), ConformanceError> {
    for output in &manifest.outputs {
        let path = output_dir.join(&output.path);

        // Read content
        let content = std::fs::read(&path).map_err(|e| {
            ConformanceError::ExportFailed(ExportError::AtomicWriteFailed {
                path: path.clone(),
                source: crate::determinism::AtomicWriteError::TempFileCreation(e),
            })
        })?;

        // Convert to string for text-based formats
        if let Ok(content_str) = std::str::from_utf8(&content) {
            // Only verify provenance for files with frontmatter
            if content_str.starts_with(YAML_FRONTMATTER_DELIMITER) {
                verify_provenance(content_str, &path, Some(expected_profile))?;
            }
        }
    }

    Ok(())
}

/// Runs the schema test.
fn run_schema_test(
    manifest: &ExportManifest,
    output_dir: &std::path::Path,
    profile: &TargetProfile,
) -> Result<(), ConformanceError> {
    let format = OutputFormat::from(profile.delivery_constraints.output_format);

    for output in &manifest.outputs {
        let path = output_dir.join(&output.path);

        // Read content
        let content = std::fs::read(&path).map_err(|e| {
            ConformanceError::ExportFailed(ExportError::AtomicWriteFailed {
                path: path.clone(),
                source: crate::determinism::AtomicWriteError::TempFileCreation(e),
            })
        })?;

        verify_schema(&content, &path, format)?;
    }

    Ok(())
}

/// Runs a custom conformance test.
fn run_custom_test(
    test: &ConformanceTest,
    pack: &CompiledContextPack,
) -> Result<(), ConformanceError> {
    // Verify pack reference matches
    if test.pack_ref != pack.manifest.spec_id && !test.pack_ref.is_empty() {
        return Err(ConformanceError::InvalidTestSpec {
            reason: format!(
                "test '{}' references pack '{}' but current pack is '{}'",
                test.test_id, test.pack_ref, pack.manifest.spec_id
            ),
        });
    }

    // If expected hash is provided, compute and compare
    if let Some(ref expected_hash) = test.expected_hash {
        let manifest_json = serde_json::to_string(&pack.manifest).map_err(|e| {
            ConformanceError::InvalidTestSpec {
                reason: format!("failed to serialize manifest: {e}"),
            }
        })?;

        let actual_hash = hex::encode(blake3::hash(manifest_json.as_bytes()).as_bytes());

        // Compare (strip prefix if present)
        let expected_clean = expected_hash
            .strip_prefix("sha256:")
            .or_else(|| expected_hash.strip_prefix("blake3:"))
            .unwrap_or(expected_hash);

        if actual_hash != expected_clean {
            return Err(ConformanceError::DeterminismFailure {
                hash1: expected_clean.to_string(),
                hash2: actual_hash,
                path: "manifest".to_string(),
            });
        }
    }

    Ok(())
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Extracts YAML frontmatter from content.
///
/// Returns the frontmatter content (excluding delimiters) if found.
fn extract_frontmatter(content: &str) -> Option<String> {
    if !content.starts_with(YAML_FRONTMATTER_DELIMITER) {
        return None;
    }

    // Skip the first delimiter
    let after_first = &content[3..];

    // Skip the newline after first delimiter
    let after_first = after_first.strip_prefix('\n').unwrap_or(after_first);

    // Find the closing delimiter
    let end_pos = after_first.find(YAML_FRONTMATTER_DELIMITER)?;

    Some(after_first[..end_pos].to_string())
}

/// Validates ISO 8601 timestamp format.
fn is_valid_iso8601_timestamp(s: &str) -> bool {
    // Simple validation: YYYY-MM-DDTHH:MM:SSZ
    if s.len() != 20 {
        return false;
    }

    // Check basic structure
    let chars: Vec<char> = s.chars().collect();
    if chars.len() != 20 {
        return false;
    }

    // Check format: YYYY-MM-DDTHH:MM:SSZ
    chars[4] == '-'
        && chars[7] == '-'
        && chars[10] == 'T'
        && chars[13] == ':'
        && chars[16] == ':'
        && chars[19] == 'Z'
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use chrono::TimeZone;
    use tempfile::TempDir;

    use super::*;
    use crate::cac::compiler::{BudgetUsed, CompiledContextPack, CompiledManifest, ManifestEntry};
    use crate::cac::export::MemoryContentResolver;
    use crate::cac::target_profile::{
        DeliveryConstraints, OutputFormat as ProfileOutputFormat, ProvenanceEmbed, TargetProfile,
        TypedQuantity,
    };

    /// Creates a test timestamp for deterministic testing.
    fn test_timestamp() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 1, 27, 12, 0, 0).unwrap()
    }

    /// Creates a minimal test profile.
    fn test_profile() -> TargetProfile {
        TargetProfile::builder()
            .profile_id("test-profile")
            .version("2026-01-27")
            .delivery_constraints(
                DeliveryConstraints::builder()
                    .output_format(ProfileOutputFormat::Markdown)
                    .provenance_embed(ProvenanceEmbed::Inline)
                    .build(),
            )
            .build()
            .unwrap()
    }

    /// Creates a minimal compiled context pack for testing.
    fn test_pack() -> CompiledContextPack {
        let entry = ManifestEntry {
            stable_id: "org:doc:readme".to_string(),
            content_hash: "a".repeat(64),
            schema_id: "org:schema:doc".to_string(),
            dependencies: vec![],
        };

        let mut content_hashes = BTreeMap::new();
        content_hashes.insert("org:doc:readme".to_string(), "a".repeat(64));

        CompiledContextPack {
            manifest: CompiledManifest {
                schema: CompiledManifest::SCHEMA.to_string(),
                schema_version: CompiledManifest::SCHEMA_VERSION.to_string(),
                spec_id: "test-pack".to_string(),
                target_profile: "test-profile".to_string(),
                entries: vec![entry],
                canonicalizer_id: CompiledManifest::CANONICALIZER_ID.to_string(),
                canonicalizer_version: CompiledManifest::CANONICALIZER_VERSION.to_string(),
            },
            content_hashes,
            budget_used: BudgetUsed {
                artifact_count: TypedQuantity::artifacts(1),
                total_bytes: None,
            },
        }
    }

    // =========================================================================
    // ConformanceTest Tests
    // =========================================================================

    #[test]
    fn test_conformance_test_new() {
        let test = ConformanceTest::new("test-001", Some("sha256:abc".to_string()), "pack-001");

        assert_eq!(test.test_id, "test-001");
        assert_eq!(test.expected_hash, Some("sha256:abc".to_string()));
        assert_eq!(test.pack_ref, "pack-001");
    }

    #[test]
    fn test_conformance_test_determinism() {
        let test = ConformanceTest::determinism("det-001", "pack-001");

        assert_eq!(test.test_id, "det-001");
        assert_eq!(test.expected_hash, None);
        assert_eq!(test.pack_ref, "pack-001");
    }

    #[test]
    fn test_conformance_test_golden() {
        let test = ConformanceTest::golden("golden-001", "blake3:xyz", "pack-001");

        assert_eq!(test.test_id, "golden-001");
        assert_eq!(test.expected_hash, Some("blake3:xyz".to_string()));
        assert_eq!(test.pack_ref, "pack-001");
    }

    // =========================================================================
    // ConformanceTestResult Tests
    // =========================================================================

    #[test]
    fn test_conformance_test_result_pass() {
        let result = ConformanceTestResult::pass("test-001", Some(100));

        assert_eq!(result.test_id, "test-001");
        assert!(result.passed);
        assert!(result.error.is_none());
        assert_eq!(result.duration_ms, Some(100));
    }

    #[test]
    fn test_conformance_test_result_fail() {
        let result = ConformanceTestResult::fail("test-001", "something went wrong", Some(50));

        assert_eq!(result.test_id, "test-001");
        assert!(!result.passed);
        assert_eq!(result.error, Some("something went wrong".to_string()));
        assert_eq!(result.duration_ms, Some(50));
    }

    // =========================================================================
    // ExportReceipt Tests
    // =========================================================================

    #[test]
    fn test_export_receipt_new() {
        let results = vec![
            ConformanceTestResult::pass("test-1", Some(10)),
            ConformanceTestResult::pass("test-2", Some(20)),
        ];

        let receipt =
            ExportReceipt::new("sha256:abc123", "claude-code-v1", results, test_timestamp());

        assert_eq!(receipt.pack_hash, "sha256:abc123");
        assert_eq!(receipt.profile_id, "claude-code-v1");
        assert!(receipt.overall_passed);
        assert_eq!(receipt.passed_count(), 2);
        assert_eq!(receipt.failed_count(), 0);
        assert_eq!(receipt.timestamp, "2026-01-27T12:00:00Z");
        assert_eq!(receipt.total_duration_ms, Some(30));
    }

    #[test]
    fn test_export_receipt_with_failures() {
        let results = vec![
            ConformanceTestResult::pass("test-1", Some(10)),
            ConformanceTestResult::fail("test-2", "failed", Some(20)),
            ConformanceTestResult::fail("test-3", "also failed", Some(15)),
        ];

        let receipt =
            ExportReceipt::new("sha256:abc123", "claude-code-v1", results, test_timestamp());

        assert!(!receipt.overall_passed);
        assert_eq!(receipt.passed_count(), 1);
        assert_eq!(receipt.failed_count(), 2);
    }

    #[test]
    fn test_export_receipt_summary() {
        let results = vec![
            ConformanceTestResult::pass("test-1", Some(10)),
            ConformanceTestResult::fail("test-2", "failed", Some(20)),
        ];

        let receipt =
            ExportReceipt::new("sha256:abc123", "claude-code-v1", results, test_timestamp());

        let summary = receipt.summary();
        assert!(summary.contains("1/2 tests passed"));
        assert!(summary.contains("1 failed"));
        assert!(summary.contains("30ms"));
    }

    // =========================================================================
    // Provenance Verification Tests
    // =========================================================================

    #[test]
    fn test_verify_provenance_valid() {
        let content = r#"---
provenance:
  export_profile: "test-profile"
  export_timestamp: "2026-01-27T12:00:00Z"
  exporter_version: "0.1.0"
  source_pack_hash: "sha256:abc123"
---

# Content here
"#;

        let result = verify_provenance(content, std::path::Path::new("test.md"), None);
        assert!(result.is_ok());

        let provenance = result.unwrap();
        assert_eq!(provenance.source_pack_hash, "sha256:abc123");
        assert_eq!(provenance.export_profile, "test-profile");
    }

    #[test]
    fn test_verify_provenance_missing_frontmatter() {
        let content = "# No frontmatter here";

        let result = verify_provenance(content, std::path::Path::new("test.md"), None);
        assert!(matches!(
            result,
            Err(ConformanceError::ProvenanceParsingFailed { .. })
        ));
    }

    #[test]
    fn test_verify_provenance_missing_field() {
        let content = r#"---
provenance:
  export_profile: "test-profile"
  export_timestamp: "2026-01-27T12:00:00Z"
  exporter_version: "0.1.0"
---
"#;
        // Missing source_pack_hash

        let result = verify_provenance(content, std::path::Path::new("test.md"), None);
        assert!(matches!(
            result,
            Err(ConformanceError::ProvenanceMissingField { field, .. })
            if field == "source_pack_hash"
        ));
    }

    #[test]
    fn test_verify_provenance_invalid_hash_format() {
        let content = r#"---
provenance:
  export_profile: "test-profile"
  export_timestamp: "2026-01-27T12:00:00Z"
  exporter_version: "0.1.0"
  source_pack_hash: "invalid-format"
---
"#;

        let result = verify_provenance(content, std::path::Path::new("test.md"), None);
        assert!(matches!(
            result,
            Err(ConformanceError::ProvenanceInvalidField { field, .. })
            if field == "source_pack_hash"
        ));
    }

    #[test]
    fn test_verify_provenance_profile_mismatch() {
        let content = r#"---
provenance:
  export_profile: "wrong-profile"
  export_timestamp: "2026-01-27T12:00:00Z"
  exporter_version: "0.1.0"
  source_pack_hash: "sha256:abc123"
---
"#;

        let result = verify_provenance(
            content,
            std::path::Path::new("test.md"),
            Some("expected-profile"),
        );
        assert!(matches!(
            result,
            Err(ConformanceError::ProvenanceInvalidField { field, .. })
            if field == "export_profile"
        ));
    }

    // =========================================================================
    // Schema Verification Tests
    // =========================================================================

    #[test]
    fn test_verify_schema_markdown_valid() {
        let content = b"---\nprovenance:\n  key: value\n---\n\n# Content";

        let result = verify_schema(
            content,
            std::path::Path::new("test.md"),
            OutputFormat::Markdown,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_schema_markdown_unclosed_frontmatter() {
        let content = b"---\nprovenance:\n  key: value\n# No closing delimiter";

        let result = verify_schema(
            content,
            std::path::Path::new("test.md"),
            OutputFormat::Markdown,
        );
        assert!(matches!(
            result,
            Err(ConformanceError::SchemaValidationFailed { .. })
        ));
    }

    #[test]
    fn test_verify_schema_json_valid() {
        let content = br#"{"key": "value", "nested": {"a": 1}}"#;

        let result = verify_schema(
            content,
            std::path::Path::new("test.json"),
            OutputFormat::Json,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_schema_json_invalid() {
        let content = b"not valid json {{{";

        let result = verify_schema(
            content,
            std::path::Path::new("test.json"),
            OutputFormat::Json,
        );
        assert!(matches!(
            result,
            Err(ConformanceError::SchemaValidationFailed { .. })
        ));
    }

    // =========================================================================
    // Determinism Verification Tests
    // =========================================================================

    #[test]
    fn test_verify_determinism_success() {
        let temp_dir1 = TempDir::new().unwrap();
        let temp_dir2 = TempDir::new().unwrap();

        let pack = test_pack();
        let mut resolver = MemoryContentResolver::new();
        resolver.insert("org:doc:readme", b"# Test Content");

        let result = verify_determinism(
            &pack,
            &resolver,
            &test_profile(),
            test_timestamp(),
            "0.1.0",
            temp_dir1.path(),
            temp_dir2.path(),
        );

        assert!(result.is_ok());
    }

    // =========================================================================
    // Conformance Suite Tests
    // =========================================================================

    #[test]
    fn test_run_conformance_suite_all_pass() {
        let pack = test_pack();
        let mut resolver = MemoryContentResolver::new();
        resolver.insert("org:doc:readme", b"# Test Content");

        let config = ConformanceSuiteConfig::default();

        let receipt = run_conformance_suite(
            &pack,
            &resolver,
            &test_profile(),
            test_timestamp(),
            "0.1.0",
            &[],
            &config,
        )
        .unwrap();

        assert!(receipt.overall_passed);
        assert_eq!(receipt.passed_count(), 3); // determinism, provenance, schema
    }

    #[test]
    fn test_run_conformance_suite_with_custom_tests() {
        let pack = test_pack();
        let mut resolver = MemoryContentResolver::new();
        resolver.insert("org:doc:readme", b"# Test Content");

        let custom_tests = vec![ConformanceTest::determinism("custom-det", "test-pack")];

        let config = ConformanceSuiteConfig::default();

        let receipt = run_conformance_suite(
            &pack,
            &resolver,
            &test_profile(),
            test_timestamp(),
            "0.1.0",
            &custom_tests,
            &config,
        )
        .unwrap();

        assert!(receipt.overall_passed);
        assert_eq!(receipt.passed_count(), 4); // 3 built-in + 1 custom
    }

    #[test]
    fn test_run_conformance_suite_too_many_tests() {
        let pack = test_pack();
        let resolver = MemoryContentResolver::new();

        let tests: Vec<ConformanceTest> = (0..=MAX_CONFORMANCE_TESTS)
            .map(|i| ConformanceTest::determinism(format!("test-{i}"), "pack"))
            .collect();

        let config = ConformanceSuiteConfig::default();

        let result = run_conformance_suite(
            &pack,
            &resolver,
            &test_profile(),
            test_timestamp(),
            "0.1.0",
            &tests,
            &config,
        );

        assert!(matches!(result, Err(ConformanceError::TooManyTests { .. })));
    }

    #[test]
    fn test_run_conformance_suite_selective_tests() {
        let pack = test_pack();
        let mut resolver = MemoryContentResolver::new();
        resolver.insert("org:doc:readme", b"# Test Content");

        // Only run determinism test
        let config = ConformanceSuiteConfig {
            verify_determinism: true,
            verify_provenance: false,
            verify_schema: false,
        };

        let receipt = run_conformance_suite(
            &pack,
            &resolver,
            &test_profile(),
            test_timestamp(),
            "0.1.0",
            &[],
            &config,
        )
        .unwrap();

        assert!(receipt.overall_passed);
        assert_eq!(receipt.passed_count(), 1); // Only determinism
    }

    // =========================================================================
    // Helper Function Tests
    // =========================================================================

    #[test]
    fn test_extract_frontmatter() {
        let content = "---\nkey: value\n---\n\nContent";
        let fm = extract_frontmatter(content);
        assert_eq!(fm, Some("key: value\n".to_string()));
    }

    #[test]
    fn test_extract_frontmatter_no_delimiter() {
        let content = "No frontmatter here";
        let fm = extract_frontmatter(content);
        assert_eq!(fm, None);
    }

    #[test]
    fn test_is_valid_iso8601_timestamp() {
        assert!(is_valid_iso8601_timestamp("2026-01-27T12:00:00Z"));
        assert!(!is_valid_iso8601_timestamp("2026-01-27"));
        assert!(!is_valid_iso8601_timestamp("invalid"));
        assert!(!is_valid_iso8601_timestamp("2026/01/27T12:00:00Z"));
    }

    // =========================================================================
    // Golden Test Vector Tests
    // =========================================================================

    #[test]
    fn test_golden_vector_empty_pack() {
        // Test with a pack that has no artifacts
        let mut content_hashes = BTreeMap::new();
        content_hashes.insert("org:schema:empty".to_string(), "b".repeat(64));

        let pack = CompiledContextPack {
            manifest: CompiledManifest {
                schema: CompiledManifest::SCHEMA.to_string(),
                schema_version: CompiledManifest::SCHEMA_VERSION.to_string(),
                spec_id: "empty-pack".to_string(),
                target_profile: "test-profile".to_string(),
                entries: vec![],
                canonicalizer_id: CompiledManifest::CANONICALIZER_ID.to_string(),
                canonicalizer_version: CompiledManifest::CANONICALIZER_VERSION.to_string(),
            },
            content_hashes,
            budget_used: BudgetUsed {
                artifact_count: TypedQuantity::artifacts(0),
                total_bytes: None,
            },
        };

        let resolver = MemoryContentResolver::new();

        // Empty pack should still pass conformance (no outputs to verify)
        let config = ConformanceSuiteConfig {
            verify_determinism: true,
            verify_provenance: false, // No outputs to check provenance
            verify_schema: false,
        };

        let receipt = run_conformance_suite(
            &pack,
            &resolver,
            &test_profile(),
            test_timestamp(),
            "0.1.0",
            &[],
            &config,
        )
        .unwrap();

        assert!(receipt.overall_passed);
    }

    #[test]
    fn test_golden_vector_single_artifact() {
        let pack = test_pack();
        let mut resolver = MemoryContentResolver::new();
        resolver.insert(
            "org:doc:readme",
            b"# Single Artifact Test\n\nThis is a test document.",
        );

        let config = ConformanceSuiteConfig::default();

        let receipt = run_conformance_suite(
            &pack,
            &resolver,
            &test_profile(),
            test_timestamp(),
            "0.1.0",
            &[],
            &config,
        )
        .unwrap();

        assert!(receipt.overall_passed);
        assert_eq!(receipt.profile_id, "test-profile");
    }

    #[test]
    fn test_golden_vector_nested_dependencies() {
        // Create a pack with nested dependencies
        let entries = vec![
            ManifestEntry {
                stable_id: "org:doc:root".to_string(),
                content_hash: "a".repeat(64),
                schema_id: "org:schema:doc".to_string(),
                dependencies: vec!["org:doc:child1".to_string()],
            },
            ManifestEntry {
                stable_id: "org:doc:child1".to_string(),
                content_hash: "b".repeat(64),
                schema_id: "org:schema:doc".to_string(),
                dependencies: vec!["org:doc:child2".to_string()],
            },
            ManifestEntry {
                stable_id: "org:doc:child2".to_string(),
                content_hash: "c".repeat(64),
                schema_id: "org:schema:doc".to_string(),
                dependencies: vec![],
            },
        ];

        let mut content_hashes = BTreeMap::new();
        content_hashes.insert("org:doc:root".to_string(), "a".repeat(64));
        content_hashes.insert("org:doc:child1".to_string(), "b".repeat(64));
        content_hashes.insert("org:doc:child2".to_string(), "c".repeat(64));

        let pack = CompiledContextPack {
            manifest: CompiledManifest {
                schema: CompiledManifest::SCHEMA.to_string(),
                schema_version: CompiledManifest::SCHEMA_VERSION.to_string(),
                spec_id: "nested-pack".to_string(),
                target_profile: "test-profile".to_string(),
                entries,
                canonicalizer_id: CompiledManifest::CANONICALIZER_ID.to_string(),
                canonicalizer_version: CompiledManifest::CANONICALIZER_VERSION.to_string(),
            },
            content_hashes,
            budget_used: BudgetUsed {
                artifact_count: TypedQuantity::artifacts(3),
                total_bytes: None,
            },
        };

        let mut resolver = MemoryContentResolver::new();
        resolver.insert("org:doc:root", b"# Root Document");
        resolver.insert("org:doc:child1", b"# Child 1");
        resolver.insert("org:doc:child2", b"# Child 2");

        let config = ConformanceSuiteConfig::default();

        let receipt = run_conformance_suite(
            &pack,
            &resolver,
            &test_profile(),
            test_timestamp(),
            "0.1.0",
            &[],
            &config,
        )
        .unwrap();

        assert!(receipt.overall_passed);
        assert_eq!(receipt.conformance_tests.len(), 3);
    }

    // =========================================================================
    // Serialization Tests
    // =========================================================================

    #[test]
    fn test_export_receipt_serialization() {
        let results = vec![
            ConformanceTestResult::pass("determinism", Some(100)),
            ConformanceTestResult::pass("provenance", Some(50)),
            ConformanceTestResult::pass("schema", Some(30)),
        ];

        let receipt =
            ExportReceipt::new("sha256:abc123", "claude-code-v1", results, test_timestamp());

        // Serialize to YAML
        let yaml = serde_yaml::to_string(&receipt).unwrap();

        // Verify expected structure (YAML may or may not quote string values)
        assert!(yaml.contains("pack_hash:"));
        assert!(yaml.contains("sha256:abc123"));
        assert!(yaml.contains("profile_id:"));
        assert!(yaml.contains("claude-code-v1"));
        assert!(yaml.contains("overall_passed: true"));
        assert!(yaml.contains("2026-01-27T12:00:00Z"));

        // Deserialize back
        let deserialized: ExportReceipt = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(deserialized.pack_hash, receipt.pack_hash);
        assert_eq!(deserialized.profile_id, receipt.profile_id);
        assert_eq!(deserialized.overall_passed, receipt.overall_passed);
    }

    #[test]
    fn test_conformance_test_serialization() {
        let test = ConformanceTest::golden("golden-001", "sha256:expected", "pack-001");

        // Serialize to JSON
        let json = serde_json::to_string(&test).unwrap();

        // Deserialize back
        let deserialized: ConformanceTest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.test_id, test.test_id);
        assert_eq!(deserialized.expected_hash, test.expected_hash);
        assert_eq!(deserialized.pack_ref, test.pack_ref);
    }
}
