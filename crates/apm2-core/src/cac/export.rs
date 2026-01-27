//! Deterministic export pipeline for CAC artifacts.
//!
//! This module transforms a [`CompiledContextPack`] into vendor-specific
//! output layouts (e.g., Markdown files with YAML frontmatter) following a
//! [`TargetProfile`] specification.
//!
//! # Design Principles
//!
//! - **Determinism**: Re-exporting the same pack with the same profile
//!   produces byte-identical output. This is achieved by:
//!   - Sorting all keys lexicographically in YAML frontmatter
//!   - Using consistent formatting (2-space indentation, no trailing whitespace)
//!   - Injecting timestamps externally (CTR-2501: Time Is an External Input)
//!
//! - **Provenance**: All Markdown outputs include YAML frontmatter with
//!   provenance metadata (source pack hash, profile, timestamp, version)
//!
//! - **Crash Safety**: Uses atomic file writes to ensure outputs are either
//!   fully written or not modified (INV-1601)
//!
//! # Example
//!
//! ```ignore
//! use apm2_core::cac::export::{ExportConfig, ExportPipeline};
//! use chrono::Utc;
//! use std::path::Path;
//!
//! let pipeline = ExportPipeline::builder()
//!     .profile(target_profile)
//!     .output_dir(Path::new("/output"))
//!     .timestamp(Utc::now())
//!     .exporter_version("0.1.0")
//!     .build()
//!     .unwrap();
//!
//! let manifest = pipeline.export(&compiled_pack, &content_resolver)?;
//! ```

use std::collections::BTreeMap;
use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::compiler::CompiledContextPack;
use super::target_profile::{OutputFormat, ProvenanceEmbed, TargetProfile};
use crate::determinism::{AtomicWriteError, write_atomic};

// ============================================================================
// Constants
// ============================================================================

/// Default exporter version if not specified.
pub const DEFAULT_EXPORTER_VERSION: &str = "0.1.0";

/// Maximum length for rendered content (denial-of-service prevention).
pub const MAX_RENDERED_CONTENT_BYTES: usize = 100 * 1024 * 1024; // 100 MiB

/// Provenance frontmatter delimiter.
const YAML_FRONTMATTER_DELIMITER: &str = "---";

// ============================================================================
// Errors
// ============================================================================

/// Errors that can occur during export operations.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ExportError {
    /// The output directory doesn't exist.
    #[error("output directory does not exist: {path}")]
    OutputDirNotFound {
        /// Path that doesn't exist.
        path: PathBuf,
    },

    /// The output directory is not a directory.
    #[error("output path is not a directory: {path}")]
    NotADirectory {
        /// Path that isn't a directory.
        path: PathBuf,
    },

    /// Budget policy violation during export.
    #[error("budget policy violation: {dimension} exceeds limit of {limit} (actual: {actual})")]
    BudgetViolation {
        /// The dimension that was violated.
        dimension: String,
        /// The budget limit.
        limit: u64,
        /// The actual value.
        actual: u64,
    },

    /// Content exceeded maximum size.
    #[error("content exceeds maximum size: {actual} bytes > {max} bytes")]
    ContentTooLarge {
        /// Actual content size.
        actual: usize,
        /// Maximum allowed size.
        max: usize,
    },

    /// Content resolver failed to retrieve content.
    #[error("content resolution failed for '{stable_id}': {message}")]
    ContentResolutionFailed {
        /// The `stable_id` that failed.
        stable_id: String,
        /// Error message.
        message: String,
    },

    /// Atomic write failed.
    #[error("atomic write failed for '{path}': {source}")]
    AtomicWriteFailed {
        /// Target path.
        path: PathBuf,
        /// Underlying error.
        #[source]
        source: AtomicWriteError,
    },

    /// Manifest serialization failed.
    #[error("manifest serialization failed: {message}")]
    ManifestSerializationFailed {
        /// Error message.
        message: String,
    },

    /// Configuration error.
    #[error("configuration error: {message}")]
    ConfigurationError {
        /// Error message.
        message: String,
    },
}

// ============================================================================
// Provenance
// ============================================================================

/// Provenance metadata embedded in exported outputs.
///
/// This struct is serialized as YAML frontmatter in Markdown outputs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Provenance {
    /// BLAKE3 hash of the source context pack manifest.
    pub source_pack_hash: String,

    /// Profile ID used for export.
    pub export_profile: String,

    /// Timestamp when export was performed (ISO 8601).
    pub export_timestamp: String,

    /// Version of the exporter.
    pub exporter_version: String,
}

impl Provenance {
    /// Creates a new provenance record.
    #[must_use]
    pub fn new(
        source_pack_hash: impl Into<String>,
        export_profile: impl Into<String>,
        export_timestamp: DateTime<Utc>,
        exporter_version: impl Into<String>,
    ) -> Self {
        Self {
            source_pack_hash: format!("sha256:{}", source_pack_hash.into()),
            export_profile: export_profile.into(),
            export_timestamp: export_timestamp.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            exporter_version: exporter_version.into(),
        }
    }

    /// Renders provenance as YAML frontmatter.
    ///
    /// Format:
    /// ```yaml
    /// ---
    /// provenance:
    ///   export_profile: "claude-code-v1"
    ///   export_timestamp: "2026-01-27T12:00:00Z"
    ///   exporter_version: "0.1.0"
    ///   source_pack_hash: "sha256:..."
    /// ---
    /// ```
    #[must_use]
    pub fn to_frontmatter(&self) -> String {
        use std::fmt::Write;
        // Use BTreeMap for deterministic key ordering
        let mut frontmatter = String::new();
        frontmatter.push_str(YAML_FRONTMATTER_DELIMITER);
        frontmatter.push('\n');
        frontmatter.push_str("provenance:\n");
        // Keys in alphabetical order for determinism
        let _ = writeln!(frontmatter, "  export_profile: \"{}\"", self.export_profile);
        let _ = writeln!(frontmatter, "  export_timestamp: \"{}\"", self.export_timestamp);
        let _ = writeln!(frontmatter, "  exporter_version: \"{}\"", self.exporter_version);
        let _ = writeln!(frontmatter, "  source_pack_hash: \"{}\"", self.source_pack_hash);
        frontmatter.push_str(YAML_FRONTMATTER_DELIMITER);
        frontmatter.push('\n');
        frontmatter
    }
}

// ============================================================================
// Export Output
// ============================================================================

/// A single exported output file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportOutput {
    /// Relative path from output directory.
    pub path: PathBuf,

    /// BLAKE3 hash of the output content.
    pub content_hash: String,

    /// Provenance metadata for this output.
    pub provenance: Provenance,

    /// Size in bytes.
    pub size_bytes: u64,
}

// ============================================================================
// Export Manifest
// ============================================================================

/// Manifest of all exported outputs.
///
/// The manifest provides an inventory of all files produced by an export
/// operation, including content hashes for verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportManifest {
    /// Schema identifier for this manifest.
    pub schema: String,

    /// Schema version.
    pub schema_version: String,

    /// Source pack manifest hash.
    pub source_pack_hash: String,

    /// Profile used for export.
    pub export_profile: String,

    /// Export timestamp (ISO 8601).
    pub export_timestamp: String,

    /// Exporter version.
    pub exporter_version: String,

    /// List of exported outputs in deterministic order.
    pub outputs: Vec<ExportOutput>,

    /// Total bytes written.
    pub total_bytes: u64,
}

impl ExportManifest {
    /// Schema identifier for export manifests.
    pub const SCHEMA: &'static str = "bootstrap:export_manifest.v1";

    /// Schema version.
    pub const SCHEMA_VERSION: &'static str = "v1";
}

// ============================================================================
// Content Resolver Trait
// ============================================================================

/// Trait for resolving artifact content from stable IDs.
///
/// Implementations may fetch content from CAS, filesystem, or other sources.
pub trait ContentResolver {
    /// Resolves content for the given `stable_id`.
    ///
    /// # Errors
    ///
    /// Returns an error if the content cannot be retrieved.
    fn resolve(&self, stable_id: &str, content_hash: &str) -> Result<Vec<u8>, String>;
}

/// A simple in-memory content resolver for testing.
#[derive(Debug, Clone, Default)]
pub struct MemoryContentResolver {
    /// Content keyed by `stable_id`.
    content: BTreeMap<String, Vec<u8>>,
}

impl MemoryContentResolver {
    /// Creates a new empty resolver.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds content for a `stable_id`.
    pub fn insert(&mut self, stable_id: impl Into<String>, content: impl Into<Vec<u8>>) {
        self.content.insert(stable_id.into(), content.into());
    }
}

impl ContentResolver for MemoryContentResolver {
    fn resolve(&self, stable_id: &str, _content_hash: &str) -> Result<Vec<u8>, String> {
        self.content
            .get(stable_id)
            .cloned()
            .ok_or_else(|| format!("content not found for '{stable_id}'"))
    }
}

// ============================================================================
// Export Config
// ============================================================================

/// Configuration for export operations.
#[derive(Debug, Clone)]
pub struct ExportConfig {
    /// Target profile for export.
    pub profile: TargetProfile,

    /// Output directory.
    pub output_dir: PathBuf,

    /// Export timestamp (injected for determinism, per CTR-2501).
    pub timestamp: DateTime<Utc>,

    /// Exporter version string.
    pub exporter_version: String,
}

// ============================================================================
// Export Pipeline
// ============================================================================

/// Deterministic export pipeline for CAC artifacts.
///
/// The pipeline transforms a [`CompiledContextPack`] into vendor-specific
/// output files following the constraints defined in a [`TargetProfile`].
#[derive(Debug)]
pub struct ExportPipeline {
    config: ExportConfig,
}

impl ExportPipeline {
    /// Creates a new export pipeline builder.
    #[must_use]
    pub fn builder() -> ExportPipelineBuilder {
        ExportPipelineBuilder::default()
    }

    /// Creates a new export pipeline with the given configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration is invalid.
    pub fn new(config: ExportConfig) -> Result<Self, ExportError> {
        // Validate output directory exists
        if !config.output_dir.exists() {
            return Err(ExportError::OutputDirNotFound {
                path: config.output_dir,
            });
        }
        if !config.output_dir.is_dir() {
            return Err(ExportError::NotADirectory {
                path: config.output_dir,
            });
        }
        Ok(Self { config })
    }

    /// Exports a compiled context pack to the output directory.
    ///
    /// # Arguments
    ///
    /// * `pack` - The compiled context pack to export
    /// * `resolver` - Content resolver for retrieving artifact content
    ///
    /// # Returns
    ///
    /// An export manifest describing all written files.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Budget policy is violated
    /// - Content resolution fails
    /// - Atomic writes fail
    pub fn export<R: ContentResolver>(
        &self,
        pack: &CompiledContextPack,
        resolver: &R,
    ) -> Result<ExportManifest, ExportError> {
        // Step 1: Validate budget constraints
        self.validate_budget(pack)?;

        // Step 2: Render content for each artifact
        let rendered_outputs = self.render_context_pack(pack, resolver)?;

        // Step 3: Write outputs atomically
        let outputs = self.write_outputs(&rendered_outputs)?;

        // Step 4: Generate manifest
        Ok(self.generate_manifest(pack, outputs))
    }

    /// Validates budget constraints against the pack.
    fn validate_budget(&self, pack: &CompiledContextPack) -> Result<(), ExportError> {
        let budget = &self.config.profile.budget_policy;

        // Check artifact count
        if let Some(ref max_artifacts) = budget.max_artifacts {
            let actual = pack.budget_used.artifact_count.value();
            if actual > max_artifacts.value() {
                return Err(ExportError::BudgetViolation {
                    dimension: "artifacts".to_string(),
                    limit: max_artifacts.value(),
                    actual,
                });
            }
        }

        Ok(())
    }

    /// Renders all artifacts in the pack according to the profile.
    fn render_context_pack<R: ContentResolver>(
        &self,
        pack: &CompiledContextPack,
        resolver: &R,
    ) -> Result<Vec<RenderedOutput>, ExportError> {
        let mut outputs = Vec::new();
        let provenance = self.create_provenance(pack);

        for entry in &pack.manifest.entries {
            // Resolve content
            let content = resolver
                .resolve(&entry.stable_id, &entry.content_hash)
                .map_err(|e| ExportError::ContentResolutionFailed {
                    stable_id: entry.stable_id.clone(),
                    message: e,
                })?;

            // Check content size
            if content.len() > MAX_RENDERED_CONTENT_BYTES {
                return Err(ExportError::ContentTooLarge {
                    actual: content.len(),
                    max: MAX_RENDERED_CONTENT_BYTES,
                });
            }

            // Render based on output format
            let rendered = self.render_artifact(&entry.stable_id, &content, &provenance)?;
            outputs.push(rendered);
        }

        // Sort outputs by path for determinism
        outputs.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(outputs)
    }

    /// Renders a single artifact with provenance.
    fn render_artifact(
        &self,
        stable_id: &str,
        content: &[u8],
        provenance: &Provenance,
    ) -> Result<RenderedOutput, ExportError> {
        let format = self.config.profile.delivery_constraints.output_format;
        let embed_mode = self.config.profile.delivery_constraints.provenance_embed;

        // Convert content to string (assuming UTF-8 for text formats)
        let content_str = String::from_utf8_lossy(content);

        // Generate output content based on format
        let (output_content, extension) = match format {
            OutputFormat::Markdown => {
                let rendered = Self::embed_provenance(&content_str, provenance, embed_mode);
                (rendered.into_bytes(), "md")
            },
            OutputFormat::PlainText => {
                let rendered = Self::embed_provenance(&content_str, provenance, embed_mode);
                (rendered.into_bytes(), "txt")
            },
            OutputFormat::Json => {
                // For JSON, provenance is embedded as metadata object
                let rendered = Self::embed_provenance_json(&content_str, provenance, embed_mode)?;
                (rendered.into_bytes(), "json")
            },
            OutputFormat::Xml => {
                // XML support is out of scope for this ticket
                (content.to_vec(), "xml")
            },
        };

        // Generate deterministic path from stable_id
        let path = Self::stable_id_to_path(stable_id, extension);

        Ok(RenderedOutput {
            path,
            content: output_content,
            provenance: provenance.clone(),
        })
    }

    /// Embeds provenance metadata into content.
    fn embed_provenance(
        content: &str,
        provenance: &Provenance,
        embed_mode: ProvenanceEmbed,
    ) -> String {
        match embed_mode {
            ProvenanceEmbed::Inline => {
                // YAML frontmatter at the top
                let mut result = provenance.to_frontmatter();
                result.push('\n');
                result.push_str(content);
                result
            },
            ProvenanceEmbed::Footer => {
                // Provenance as footer comment
                let mut result = content.to_string();
                if !result.ends_with('\n') {
                    result.push('\n');
                }
                result.push_str("\n<!-- Provenance -->\n");
                result.push_str(&provenance.to_frontmatter());
                result
            },
            ProvenanceEmbed::Metadata | ProvenanceEmbed::None => {
                // No inline embedding
                content.to_string()
            },
        }
    }

    /// Embeds provenance into JSON content.
    fn embed_provenance_json(
        content: &str,
        provenance: &Provenance,
        embed_mode: ProvenanceEmbed,
    ) -> Result<String, ExportError> {
        match embed_mode {
            ProvenanceEmbed::Metadata => {
                // Parse original JSON and add provenance field
                let mut json: serde_json::Value =
                    serde_json::from_str(content).map_err(|e| ExportError::ConfigurationError {
                        message: format!("invalid JSON content: {e}"),
                    })?;

                if let serde_json::Value::Object(ref mut map) = json {
                    map.insert(
                        "_provenance".to_string(),
                        serde_json::to_value(provenance).map_err(|e| {
                            ExportError::ManifestSerializationFailed { message: e.to_string() }
                        })?,
                    );
                }

                serde_json::to_string_pretty(&json)
                    .map_err(|e| ExportError::ManifestSerializationFailed { message: e.to_string() })
            },
            ProvenanceEmbed::Inline | ProvenanceEmbed::Footer | ProvenanceEmbed::None => {
                Ok(content.to_string())
            },
        }
    }

    /// Converts a `stable_id` to a filesystem path.
    ///
    /// Replaces colons with directory separators for hierarchical layout.
    fn stable_id_to_path(stable_id: &str, extension: &str) -> PathBuf {
        // Replace colons with path separators for hierarchical structure
        let parts: Vec<&str> = stable_id.split(':').collect();
        let mut path = PathBuf::new();

        // All but last part become directories
        for part in parts.iter().take(parts.len().saturating_sub(1)) {
            path.push(part);
        }

        // Last part is the filename
        if let Some(filename) = parts.last() {
            path.push(format!("{filename}.{extension}"));
        }

        path
    }

    /// Creates provenance metadata for the export.
    fn create_provenance(&self, pack: &CompiledContextPack) -> Provenance {
        // Use the manifest hash as source pack hash
        let manifest_json =
            serde_json::to_string(&pack.manifest).unwrap_or_else(|_| String::new());
        let hash = blake3::hash(manifest_json.as_bytes());
        let hash_hex = hex::encode(hash.as_bytes());

        Provenance::new(
            hash_hex,
            &self.config.profile.profile_id,
            self.config.timestamp,
            &self.config.exporter_version,
        )
    }

    /// Writes rendered outputs atomically to the output directory.
    fn write_outputs(
        &self,
        rendered: &[RenderedOutput],
    ) -> Result<Vec<ExportOutput>, ExportError> {
        let mut outputs = Vec::with_capacity(rendered.len());

        for output in rendered {
            let full_path = self.config.output_dir.join(&output.path);

            // Ensure parent directory exists
            if let Some(parent) = full_path.parent() {
                std::fs::create_dir_all(parent).map_err(|e| ExportError::AtomicWriteFailed {
                    path: full_path.clone(),
                    source: AtomicWriteError::TempFileCreation(e),
                })?;
            }

            // Compute content hash
            let hash = blake3::hash(&output.content);
            let hash_hex = hex::encode(hash.as_bytes());

            // Write atomically
            write_atomic(&full_path, &output.content).map_err(|e| {
                ExportError::AtomicWriteFailed {
                    path: full_path.clone(),
                    source: e,
                }
            })?;

            #[allow(clippy::cast_possible_truncation)]
            outputs.push(ExportOutput {
                path: output.path.clone(),
                content_hash: hash_hex,
                provenance: output.provenance.clone(),
                size_bytes: output.content.len() as u64,
            });
        }

        Ok(outputs)
    }

    /// Generates the export manifest.
    fn generate_manifest(
        &self,
        pack: &CompiledContextPack,
        outputs: Vec<ExportOutput>,
    ) -> ExportManifest {
        let provenance = self.create_provenance(pack);
        let total_bytes: u64 = outputs.iter().map(|o| o.size_bytes).sum();

        ExportManifest {
            schema: ExportManifest::SCHEMA.to_string(),
            schema_version: ExportManifest::SCHEMA_VERSION.to_string(),
            source_pack_hash: provenance.source_pack_hash,
            export_profile: provenance.export_profile,
            export_timestamp: provenance.export_timestamp,
            exporter_version: provenance.exporter_version,
            outputs,
            total_bytes,
        }
    }

    /// Returns a reference to the export configuration.
    #[must_use]
    pub const fn config(&self) -> &ExportConfig {
        &self.config
    }
}

// ============================================================================
// Rendered Output (internal)
// ============================================================================

/// Internal representation of rendered output before writing.
#[derive(Debug)]
struct RenderedOutput {
    path: PathBuf,
    content: Vec<u8>,
    provenance: Provenance,
}

// ============================================================================
// Export Pipeline Builder
// ============================================================================

/// Builder for [`ExportPipeline`].
#[derive(Debug, Default)]
pub struct ExportPipelineBuilder {
    profile: Option<TargetProfile>,
    output_dir: Option<PathBuf>,
    timestamp: Option<DateTime<Utc>>,
    exporter_version: Option<String>,
}

impl ExportPipelineBuilder {
    /// Sets the target profile.
    #[must_use]
    pub fn profile(mut self, profile: TargetProfile) -> Self {
        self.profile = Some(profile);
        self
    }

    /// Sets the output directory.
    #[must_use]
    pub fn output_dir(mut self, path: impl Into<PathBuf>) -> Self {
        self.output_dir = Some(path.into());
        self
    }

    /// Sets the export timestamp (for determinism, per CTR-2501).
    #[must_use]
    pub const fn timestamp(mut self, timestamp: DateTime<Utc>) -> Self {
        self.timestamp = Some(timestamp);
        self
    }

    /// Sets the exporter version.
    #[must_use]
    pub fn exporter_version(mut self, version: impl Into<String>) -> Self {
        self.exporter_version = Some(version.into());
        self
    }

    /// Builds the export pipeline.
    ///
    /// # Errors
    ///
    /// Returns an error if required fields are missing or the configuration
    /// is invalid.
    pub fn build(self) -> Result<ExportPipeline, ExportError> {
        let profile = self.profile.ok_or_else(|| ExportError::ConfigurationError {
            message: "profile is required".to_string(),
        })?;

        let output_dir = self
            .output_dir
            .ok_or_else(|| ExportError::ConfigurationError {
                message: "output_dir is required".to_string(),
            })?;

        let timestamp = self
            .timestamp
            .ok_or_else(|| ExportError::ConfigurationError {
                message: "timestamp is required (CTR-2501: Time Is an External Input)".to_string(),
            })?;

        let exporter_version = self
            .exporter_version
            .unwrap_or_else(|| DEFAULT_EXPORTER_VERSION.to_string());

        let config = ExportConfig {
            profile,
            output_dir,
            timestamp,
            exporter_version,
        };

        ExportPipeline::new(config)
    }
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
    use crate::cac::target_profile::{
        BudgetPolicy, DeliveryConstraints, OutputFormat, ProvenanceEmbed, TargetProfile,
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
                    .output_format(OutputFormat::Markdown)
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
    // Provenance Tests
    // =========================================================================

    #[test]
    fn test_provenance_new() {
        let provenance = Provenance::new(
            "abc123",
            "claude-code-v1",
            test_timestamp(),
            "0.1.0",
        );

        assert_eq!(provenance.source_pack_hash, "sha256:abc123");
        assert_eq!(provenance.export_profile, "claude-code-v1");
        assert_eq!(provenance.export_timestamp, "2026-01-27T12:00:00Z");
        assert_eq!(provenance.exporter_version, "0.1.0");
    }

    #[test]
    fn test_provenance_frontmatter_format() {
        let provenance = Provenance::new(
            "abc123",
            "claude-code-v1",
            test_timestamp(),
            "0.1.0",
        );

        let frontmatter = provenance.to_frontmatter();

        // Check structure
        assert!(frontmatter.starts_with("---\n"));
        assert!(frontmatter.contains("provenance:\n"));
        assert!(frontmatter.ends_with("---\n"));

        // Check all fields are present
        assert!(frontmatter.contains("source_pack_hash: \"sha256:abc123\""));
        assert!(frontmatter.contains("export_profile: \"claude-code-v1\""));
        assert!(frontmatter.contains("export_timestamp: \"2026-01-27T12:00:00Z\""));
        assert!(frontmatter.contains("exporter_version: \"0.1.0\""));
    }

    #[test]
    fn test_provenance_frontmatter_deterministic_ordering() {
        let provenance = Provenance::new(
            "abc123",
            "claude-code-v1",
            test_timestamp(),
            "0.1.0",
        );

        let frontmatter = provenance.to_frontmatter();

        // Keys should be in alphabetical order
        let export_profile_pos = frontmatter.find("export_profile").unwrap();
        let export_timestamp_pos = frontmatter.find("export_timestamp").unwrap();
        let exporter_version_pos = frontmatter.find("exporter_version").unwrap();
        let source_pack_hash_pos = frontmatter.find("source_pack_hash").unwrap();

        assert!(
            export_profile_pos < export_timestamp_pos,
            "export_profile should come before export_timestamp"
        );
        assert!(
            export_timestamp_pos < exporter_version_pos,
            "export_timestamp should come before exporter_version"
        );
        assert!(
            exporter_version_pos < source_pack_hash_pos,
            "exporter_version should come before source_pack_hash"
        );
    }

    // =========================================================================
    // Export Pipeline Builder Tests
    // =========================================================================

    #[test]
    fn test_builder_missing_profile() {
        let temp_dir = TempDir::new().unwrap();
        let result = ExportPipeline::builder()
            .output_dir(temp_dir.path())
            .timestamp(test_timestamp())
            .build();

        assert!(matches!(
            result,
            Err(ExportError::ConfigurationError { message }) if message.contains("profile")
        ));
    }

    #[test]
    fn test_builder_missing_output_dir() {
        let result = ExportPipeline::builder()
            .profile(test_profile())
            .timestamp(test_timestamp())
            .build();

        assert!(matches!(
            result,
            Err(ExportError::ConfigurationError { message }) if message.contains("output_dir")
        ));
    }

    #[test]
    fn test_builder_missing_timestamp() {
        let temp_dir = TempDir::new().unwrap();
        let result = ExportPipeline::builder()
            .profile(test_profile())
            .output_dir(temp_dir.path())
            .build();

        assert!(matches!(
            result,
            Err(ExportError::ConfigurationError { message }) if message.contains("timestamp")
        ));
    }

    #[test]
    fn test_builder_output_dir_not_found() {
        let result = ExportPipeline::builder()
            .profile(test_profile())
            .output_dir("/nonexistent/path/12345")
            .timestamp(test_timestamp())
            .build();

        assert!(matches!(result, Err(ExportError::OutputDirNotFound { .. })));
    }

    #[test]
    fn test_builder_success() {
        let temp_dir = TempDir::new().unwrap();
        let result = ExportPipeline::builder()
            .profile(test_profile())
            .output_dir(temp_dir.path())
            .timestamp(test_timestamp())
            .exporter_version("1.0.0")
            .build();

        assert!(result.is_ok());
        let pipeline = result.unwrap();
        assert_eq!(pipeline.config().exporter_version, "1.0.0");
    }

    #[test]
    fn test_builder_default_exporter_version() {
        let temp_dir = TempDir::new().unwrap();
        let pipeline = ExportPipeline::builder()
            .profile(test_profile())
            .output_dir(temp_dir.path())
            .timestamp(test_timestamp())
            .build()
            .unwrap();

        assert_eq!(pipeline.config().exporter_version, DEFAULT_EXPORTER_VERSION);
    }

    // =========================================================================
    // Export Tests
    // =========================================================================

    #[test]
    fn test_export_creates_output_file() {
        let temp_dir = TempDir::new().unwrap();
        let pipeline = ExportPipeline::builder()
            .profile(test_profile())
            .output_dir(temp_dir.path())
            .timestamp(test_timestamp())
            .build()
            .unwrap();

        let pack = test_pack();
        let mut resolver = MemoryContentResolver::new();
        resolver.insert("org:doc:readme", b"# Hello World\n\nThis is a test.");

        let manifest = pipeline.export(&pack, &resolver).unwrap();

        // Check manifest
        assert_eq!(manifest.outputs.len(), 1);
        assert_eq!(manifest.export_profile, "test-profile");
        assert_eq!(manifest.export_timestamp, "2026-01-27T12:00:00Z");

        // Check output file exists
        let output_path = temp_dir.path().join("org/doc/readme.md");
        assert!(output_path.exists(), "Output file should exist");

        // Check content has provenance frontmatter
        let content = std::fs::read_to_string(&output_path).unwrap();
        assert!(content.starts_with("---\n"));
        assert!(content.contains("provenance:"));
        assert!(content.contains("# Hello World"));
    }

    #[test]
    fn test_export_determinism() {
        let temp_dir1 = TempDir::new().unwrap();
        let temp_dir2 = TempDir::new().unwrap();

        let pack = test_pack();
        let mut resolver = MemoryContentResolver::new();
        resolver.insert("org:doc:readme", b"# Determinism Test");

        // Export twice with same parameters
        let pipeline1 = ExportPipeline::builder()
            .profile(test_profile())
            .output_dir(temp_dir1.path())
            .timestamp(test_timestamp())
            .exporter_version("1.0.0")
            .build()
            .unwrap();

        let pipeline2 = ExportPipeline::builder()
            .profile(test_profile())
            .output_dir(temp_dir2.path())
            .timestamp(test_timestamp())
            .exporter_version("1.0.0")
            .build()
            .unwrap();

        let manifest1 = pipeline1.export(&pack, &resolver).unwrap();
        let manifest2 = pipeline2.export(&pack, &resolver).unwrap();

        // Manifests should be identical (except paths which are relative)
        assert_eq!(manifest1.source_pack_hash, manifest2.source_pack_hash);
        assert_eq!(manifest1.export_profile, manifest2.export_profile);
        assert_eq!(manifest1.export_timestamp, manifest2.export_timestamp);
        assert_eq!(manifest1.outputs.len(), manifest2.outputs.len());

        // Content hashes should be identical
        for (o1, o2) in manifest1.outputs.iter().zip(manifest2.outputs.iter()) {
            assert_eq!(o1.content_hash, o2.content_hash);
            assert_eq!(o1.path, o2.path);
        }

        // File contents should be byte-identical
        let content1 = std::fs::read(temp_dir1.path().join("org/doc/readme.md")).unwrap();
        let content2 = std::fs::read(temp_dir2.path().join("org/doc/readme.md")).unwrap();
        assert_eq!(content1, content2);
    }

    #[test]
    fn test_export_with_footer_provenance() {
        let temp_dir = TempDir::new().unwrap();
        let profile = TargetProfile::builder()
            .profile_id("footer-profile")
            .version("2026-01-27")
            .delivery_constraints(
                DeliveryConstraints::builder()
                    .output_format(OutputFormat::Markdown)
                    .provenance_embed(ProvenanceEmbed::Footer)
                    .build(),
            )
            .build()
            .unwrap();

        let pipeline = ExportPipeline::builder()
            .profile(profile)
            .output_dir(temp_dir.path())
            .timestamp(test_timestamp())
            .build()
            .unwrap();

        let pack = test_pack();
        let mut resolver = MemoryContentResolver::new();
        resolver.insert("org:doc:readme", b"# Content First");

        pipeline.export(&pack, &resolver).unwrap();

        let content = std::fs::read_to_string(temp_dir.path().join("org/doc/readme.md")).unwrap();
        assert!(content.starts_with("# Content First"));
        assert!(content.contains("<!-- Provenance -->"));
    }

    #[test]
    fn test_export_with_no_provenance() {
        let temp_dir = TempDir::new().unwrap();
        let profile = TargetProfile::builder()
            .profile_id("no-provenance-profile")
            .version("2026-01-27")
            .delivery_constraints(
                DeliveryConstraints::builder()
                    .output_format(OutputFormat::Markdown)
                    .provenance_embed(ProvenanceEmbed::None)
                    .build(),
            )
            .build()
            .unwrap();

        let pipeline = ExportPipeline::builder()
            .profile(profile)
            .output_dir(temp_dir.path())
            .timestamp(test_timestamp())
            .build()
            .unwrap();

        let pack = test_pack();
        let mut resolver = MemoryContentResolver::new();
        resolver.insert("org:doc:readme", b"# No Provenance");

        pipeline.export(&pack, &resolver).unwrap();

        let content = std::fs::read_to_string(temp_dir.path().join("org/doc/readme.md")).unwrap();
        assert_eq!(content, "# No Provenance");
        assert!(!content.contains("provenance:"));
    }

    // =========================================================================
    // Budget Validation Tests
    // =========================================================================

    #[test]
    fn test_budget_violation_artifacts() {
        let temp_dir = TempDir::new().unwrap();
        let profile = TargetProfile::builder()
            .profile_id("limited-profile")
            .version("2026-01-27")
            .budget_policy(
                BudgetPolicy::builder()
                    .max_artifacts(TypedQuantity::artifacts(0)) // No artifacts allowed
                    .build(),
            )
            .build()
            .unwrap();

        let pipeline = ExportPipeline::builder()
            .profile(profile)
            .output_dir(temp_dir.path())
            .timestamp(test_timestamp())
            .build()
            .unwrap();

        let pack = test_pack(); // Has 1 artifact
        let resolver = MemoryContentResolver::new();

        let result = pipeline.export(&pack, &resolver);
        assert!(matches!(
            result,
            Err(ExportError::BudgetViolation { dimension, limit: 0, actual: 1 })
            if dimension == "artifacts"
        ));
    }

    // =========================================================================
    // Content Resolution Tests
    // =========================================================================

    #[test]
    fn test_content_resolution_failure() {
        let temp_dir = TempDir::new().unwrap();
        let pipeline = ExportPipeline::builder()
            .profile(test_profile())
            .output_dir(temp_dir.path())
            .timestamp(test_timestamp())
            .build()
            .unwrap();

        let pack = test_pack();
        let resolver = MemoryContentResolver::new(); // Empty - no content

        let result = pipeline.export(&pack, &resolver);
        assert!(matches!(
            result,
            Err(ExportError::ContentResolutionFailed { stable_id, .. })
            if stable_id == "org:doc:readme"
        ));
    }

    // =========================================================================
    // Path Generation Tests
    // =========================================================================

    #[test]
    fn test_stable_id_to_path() {
        assert_eq!(
            ExportPipeline::stable_id_to_path("org:doc:readme", "md"),
            PathBuf::from("org/doc/readme.md")
        );

        assert_eq!(
            ExportPipeline::stable_id_to_path("simple", "txt"),
            PathBuf::from("simple.txt")
        );

        assert_eq!(
            ExportPipeline::stable_id_to_path("a:b:c:d", "json"),
            PathBuf::from("a/b/c/d.json")
        );
    }

    // =========================================================================
    // Export Manifest Tests
    // =========================================================================

    #[test]
    fn test_export_manifest_fields() {
        let temp_dir = TempDir::new().unwrap();
        let pipeline = ExportPipeline::builder()
            .profile(test_profile())
            .output_dir(temp_dir.path())
            .timestamp(test_timestamp())
            .exporter_version("2.0.0")
            .build()
            .unwrap();

        let pack = test_pack();
        let mut resolver = MemoryContentResolver::new();
        resolver.insert("org:doc:readme", b"test content");

        let manifest = pipeline.export(&pack, &resolver).unwrap();

        assert_eq!(manifest.schema, ExportManifest::SCHEMA);
        assert_eq!(manifest.schema_version, ExportManifest::SCHEMA_VERSION);
        assert_eq!(manifest.export_profile, "test-profile");
        assert_eq!(manifest.exporter_version, "2.0.0");
        assert_eq!(manifest.export_timestamp, "2026-01-27T12:00:00Z");
        assert!(manifest.total_bytes > 0);
    }

    // =========================================================================
    // Memory Content Resolver Tests
    // =========================================================================

    #[test]
    fn test_memory_content_resolver() {
        let mut resolver = MemoryContentResolver::new();
        resolver.insert("key1", b"value1".to_vec());
        resolver.insert("key2", b"value2".to_vec());

        assert_eq!(resolver.resolve("key1", "").unwrap(), b"value1");
        assert_eq!(resolver.resolve("key2", "").unwrap(), b"value2");
        assert!(resolver.resolve("key3", "").is_err());
    }
}
