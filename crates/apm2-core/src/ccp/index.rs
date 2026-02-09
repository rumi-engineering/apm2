#![allow(clippy::disallowed_methods)] // Metadata/observability usage or adapter.
//! CCP Index generation for unified, content-addressed codebase artifacts.
//!
//! This module combines the component atlas and crate graph into a unified
//! CCP index with BLAKE3 content hashing for incremental rebuild detection.
//! The index provides a complete semantic inventory of the codebase that
//! grounds all RFC file path references.
//!
//! # Invariants
//!
//! - [INV-0001] Index hash is deterministic: same inputs produce identical hash
//! - [INV-0002] File inventory is sorted by path for reproducible output
//! - [INV-0003] All source files are captured with content hashes
//! - [INV-0004] Output files use canonical YAML formatting
//!
//! # Contracts
//!
//! - [CTR-0001] `build_ccp_index` requires a valid repository root
//! - [CTR-0002] Output directory is created if it doesn't exist
//! - [CTR-0003] Atomic writes ensure no partial/corrupt files on crash
//! - [CTR-0004] Incremental rebuild detection uses stored hash comparison
//!
//! # Security
//!
//! - [SEC-0001] File reads are bounded to prevent denial-of-service
//! - [SEC-0002] Path traversal is prevented by canonicalization
//! - [SEC-0003] Only files within repo root are processed

use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, info};

use super::{
    CcpError, ComponentAtlas, CrateGraph, CrateGraphError, build_component_atlas, build_crate_graph,
};
use crate::determinism::{canonicalize_yaml, write_atomic};

/// Maximum file size for source files (10 MB).
/// Prevents denial-of-service via unbounded reads.
const MAX_SOURCE_FILE_SIZE: u64 = 10 * 1024 * 1024;

/// Maximum number of source files to process.
/// Prevents denial-of-service via excessive file enumeration.
const MAX_SOURCE_FILES: usize = 50_000;

/// Errors that can occur during CCP index generation.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CcpIndexError {
    /// Component atlas build failed.
    #[error("failed to build component atlas: {0}")]
    ComponentAtlasError(#[from] CcpError),

    /// Crate graph build failed.
    #[error("failed to build crate graph: {0}")]
    CrateGraphError(#[from] CrateGraphError),

    /// Failed to read a file.
    #[error("failed to read file {path}: {reason}")]
    ReadError {
        /// Path to the file that failed to read.
        path: String,
        /// Reason for the failure.
        reason: String,
    },

    /// Failed to write output file.
    #[error("failed to write output file {path}: {reason}")]
    WriteError {
        /// Path to the file that failed to write.
        path: String,
        /// Reason for the failure.
        reason: String,
    },

    /// Invalid repository root.
    #[error("invalid repository root: {path}")]
    InvalidRepoRoot {
        /// The invalid path.
        path: String,
    },

    /// Failed to create output directory.
    #[error("failed to create output directory {path}: {reason}")]
    DirectoryCreationError {
        /// Path to the directory.
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

    /// Too many source files.
    #[error("too many source files ({count}, max {max_count})")]
    TooManyFiles {
        /// Actual count.
        count: usize,
        /// Maximum allowed count.
        max_count: usize,
    },

    /// YAML serialization failed.
    #[error("YAML serialization failed: {reason}")]
    YamlSerializationError {
        /// Reason for the failure.
        reason: String,
    },

    /// Path traversal attempt detected.
    #[error("path traversal detected: {path} is outside repo root")]
    PathTraversalError {
        /// The path that attempted traversal.
        path: String,
    },

    /// YAML canonicalization failed.
    #[error("YAML canonicalization failed: {0}")]
    CanonicalizeError(#[from] crate::determinism::CanonicalizeError),

    /// Atomic write failed.
    #[error("atomic write failed: {0}")]
    AtomicWriteError(#[from] crate::determinism::AtomicWriteError),
}

/// A source file in the file inventory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceFile {
    /// Path to the file, relative to repo root.
    pub path: PathBuf,
    /// BLAKE3 hash of the file content (hex-encoded).
    pub hash: String,
    /// File size in bytes.
    pub size: u64,
}

/// File inventory for the repository.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileInventory {
    /// Total number of source files.
    pub file_count: usize,
    /// Total size of all source files in bytes.
    pub total_size: u64,
    /// All source files, sorted by path.
    pub files: Vec<SourceFile>,
}

/// The complete CCP index for a repository.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CcpIndex {
    /// Schema version for this index format.
    pub schema_version: String,
    /// Timestamp when the index was generated.
    pub generated_at: DateTime<Utc>,
    /// Repository root path.
    pub repo_root: PathBuf,
    /// PRD identifier this index is associated with.
    pub prd_id: String,
    /// BLAKE3 hash of the entire index content (hex-encoded).
    /// This is computed from the canonical form of atlas + graph + inventory.
    pub index_hash: String,
    /// Component atlas summary (component count).
    pub component_count: usize,
    /// Crate graph summary (crate count, edge count).
    pub crate_count: usize,
    /// Edge count in the crate graph.
    pub edge_count: usize,
    /// File inventory summary.
    pub file_inventory: FileInventory,
}

impl CcpIndex {
    /// Current schema version.
    pub const SCHEMA_VERSION: &'static str = "2026-01-26";
}

/// Options for building the CCP index.
#[derive(Debug, Clone, Default)]
pub struct CcpBuildOptions {
    /// Force rebuild even if index hash hasn't changed.
    pub force: bool,
    /// Dry run mode - compute but don't write output.
    pub dry_run: bool,
}

/// Result of a CCP index build operation.
#[derive(Debug, Clone)]
pub struct CcpBuildResult {
    /// The built CCP index.
    pub index: CcpIndex,
    /// The component atlas.
    pub atlas: ComponentAtlas,
    /// The crate graph.
    pub graph: CrateGraph,
    /// Whether the build was skipped due to unchanged hash.
    pub skipped: bool,
    /// Path to the output directory.
    pub output_dir: PathBuf,
}

/// Escapes a path for use in glob patterns to prevent glob injection.
fn escape_path_for_glob(path: &Path) -> String {
    glob::Pattern::escape(&path.to_string_lossy())
}

/// Discovers all source files in the repository.
///
/// Searches for `*.rs`, `*.yaml`, `*.yml`, and `*.md` files in the `crates/`
/// directory, and `*.rs` files in the `fuzz/` directory.
/// Returns paths sorted alphabetically for determinism.
fn discover_source_files(repo_root: &Path) -> Result<Vec<PathBuf>, CcpIndexError> {
    let mut paths = Vec::new();
    let escaped_root = escape_path_for_glob(repo_root);

    // File extensions to scan in crates/
    let extensions = ["rs", "yaml", "yml", "md"];
    let directories = ["crates"];

    for dir in &directories {
        for ext in &extensions {
            let pattern = format!("{escaped_root}/{dir}/**/*.{ext}");
            if let Ok(entries) = glob::glob(&pattern) {
                for entry in entries.flatten() {
                    paths.push(entry);
                }
            }
        }
    }

    // fuzz/ directory only contains Rust files
    let fuzz_pattern = format!("{escaped_root}/fuzz/**/*.rs");
    if let Ok(entries) = glob::glob(&fuzz_pattern) {
        for entry in entries.flatten() {
            paths.push(entry);
        }
    }

    // Check file count limit
    if paths.len() > MAX_SOURCE_FILES {
        return Err(CcpIndexError::TooManyFiles {
            count: paths.len(),
            max_count: MAX_SOURCE_FILES,
        });
    }

    // Sort for determinism
    paths.sort();
    Ok(paths)
}

/// Computes the BLAKE3 hash of a file's content.
///
/// # Security
///
/// Uses bounded reads to prevent denial-of-service via large files.
fn hash_file(path: &Path) -> Result<(String, u64), CcpIndexError> {
    let metadata = fs::metadata(path).map_err(|e| CcpIndexError::ReadError {
        path: path.display().to_string(),
        reason: e.to_string(),
    })?;

    let size = metadata.len();

    if size > MAX_SOURCE_FILE_SIZE {
        return Err(CcpIndexError::FileTooLarge {
            path: path.display().to_string(),
            size,
            max_size: MAX_SOURCE_FILE_SIZE,
        });
    }

    let file = File::open(path).map_err(|e| CcpIndexError::ReadError {
        path: path.display().to_string(),
        reason: e.to_string(),
    })?;

    // Use take() to enforce the size limit
    let mut content = Vec::new();
    file.take(MAX_SOURCE_FILE_SIZE)
        .read_to_end(&mut content)
        .map_err(|e| CcpIndexError::ReadError {
            path: path.display().to_string(),
            reason: e.to_string(),
        })?;

    let hash = blake3::hash(&content);
    Ok((hash.to_hex().to_string(), size))
}

/// Validates that a path is within the repository root.
///
/// # Security
///
/// Prevents path traversal attacks by ensuring all paths are within the repo.
fn validate_path_within_repo(path: &Path, repo_root: &Path) -> Result<(), CcpIndexError> {
    let canonical_path = path.canonicalize().map_err(|e| CcpIndexError::ReadError {
        path: path.display().to_string(),
        reason: e.to_string(),
    })?;

    let canonical_root = repo_root
        .canonicalize()
        .map_err(|e| CcpIndexError::ReadError {
            path: repo_root.display().to_string(),
            reason: e.to_string(),
        })?;

    if !canonical_path.starts_with(&canonical_root) {
        return Err(CcpIndexError::PathTraversalError {
            path: path.display().to_string(),
        });
    }

    Ok(())
}

/// Builds a file inventory from discovered source files.
fn build_file_inventory(
    repo_root: &Path,
    source_files: &[PathBuf],
) -> Result<FileInventory, CcpIndexError> {
    let mut files = Vec::with_capacity(source_files.len());
    let mut total_size = 0u64;

    for path in source_files {
        // Validate path is within repo
        validate_path_within_repo(path, repo_root)?;

        let (hash, size) = hash_file(path)?;
        total_size = total_size.saturating_add(size);

        // Make path relative to repo root
        let relative_path = path.strip_prefix(repo_root).unwrap_or(path).to_path_buf();

        files.push(SourceFile {
            path: relative_path,
            hash,
            size,
        });
    }

    // Sort by path for determinism
    files.sort_by(|a, b| a.path.cmp(&b.path));

    Ok(FileInventory {
        file_count: files.len(),
        total_size,
        files,
    })
}

/// A hashable view of the component atlas without timestamps.
///
/// This excludes `generated_at` and `repo_root` which vary between runs
/// but don't represent meaningful content changes.
#[derive(Serialize)]
struct HashableAtlas<'a> {
    schema_version: &'a str,
    components: &'a [super::Component],
}

/// A hashable view of the crate graph without timestamps.
///
/// This excludes `generated_at` and `workspace_root` which vary between runs
/// but don't represent meaningful content changes.
#[derive(Serialize)]
struct HashableGraph<'a> {
    schema_version: &'a str,
    crates: &'a [super::CrateNode],
    edges: &'a [super::DependencyEdge],
}

/// Computes the index hash from atlas, graph, and inventory.
///
/// The hash is computed from the content-relevant fields only, excluding
/// timestamps and absolute paths which vary between runs but don't represent
/// meaningful content changes.
fn compute_index_hash(
    atlas: &ComponentAtlas,
    graph: &CrateGraph,
    inventory: &FileInventory,
) -> Result<String, CcpIndexError> {
    let mut hasher = blake3::Hasher::new();

    // Hash content-relevant atlas fields only (exclude generated_at, repo_root)
    let hashable_atlas = HashableAtlas {
        schema_version: &atlas.schema_version,
        components: &atlas.components,
    };
    let atlas_yaml = serde_yaml::to_value(&hashable_atlas).map_err(|e| {
        CcpIndexError::YamlSerializationError {
            reason: e.to_string(),
        }
    })?;
    let atlas_canonical = canonicalize_yaml(&atlas_yaml)?;
    hasher.update(atlas_canonical.as_bytes());

    // Hash content-relevant graph fields only (exclude generated_at,
    // workspace_root)
    let hashable_graph = HashableGraph {
        schema_version: &graph.schema_version,
        crates: &graph.crates,
        edges: &graph.edges,
    };
    let graph_yaml = serde_yaml::to_value(&hashable_graph).map_err(|e| {
        CcpIndexError::YamlSerializationError {
            reason: e.to_string(),
        }
    })?;
    let graph_canonical = canonicalize_yaml(&graph_yaml)?;
    hasher.update(graph_canonical.as_bytes());

    // Hash canonical inventory YAML (no timestamps to exclude)
    let inventory_yaml =
        serde_yaml::to_value(inventory).map_err(|e| CcpIndexError::YamlSerializationError {
            reason: e.to_string(),
        })?;
    let inventory_canonical = canonicalize_yaml(&inventory_yaml)?;
    hasher.update(inventory_canonical.as_bytes());

    Ok(hasher.finalize().to_hex().to_string())
}

/// Reads the existing CCP index from the output directory.
fn read_existing_index(output_dir: &Path) -> Option<CcpIndex> {
    let index_path = output_dir.join("ccp_index.json");
    if !index_path.exists() {
        return None;
    }

    let content = fs::read_to_string(&index_path).ok()?;
    serde_json::from_str(&content).ok()
}

/// Writes the CCP output files atomically.
fn write_output_files(
    output_dir: &Path,
    index: &CcpIndex,
    atlas: &ComponentAtlas,
    graph: &CrateGraph,
    index_hash: &str,
) -> Result<(), CcpIndexError> {
    // Create output directory
    fs::create_dir_all(output_dir).map_err(|e| CcpIndexError::DirectoryCreationError {
        path: output_dir.display().to_string(),
        reason: e.to_string(),
    })?;

    // Write ccp_index.json
    let index_json =
        serde_json::to_string_pretty(index).map_err(|e| CcpIndexError::WriteError {
            path: output_dir.join("ccp_index.json").display().to_string(),
            reason: e.to_string(),
        })?;
    write_atomic(&output_dir.join("ccp_index.json"), index_json.as_bytes())?;

    // Write component_atlas.yaml (standard YAML format for readable output)
    // Note: We use standard serde_yaml here instead of canonical to preserve
    // field ordering which aids readability. The hash computation uses canonical
    // YAML internally for determinism.
    let atlas_yaml_str =
        serde_yaml::to_string(atlas).map_err(|e| CcpIndexError::YamlSerializationError {
            reason: e.to_string(),
        })?;
    write_atomic(
        &output_dir.join("component_atlas.yaml"),
        atlas_yaml_str.as_bytes(),
    )?;

    // Write crate_graph.yaml (standard YAML format for readable output)
    let graph_yaml_str =
        serde_yaml::to_string(graph).map_err(|e| CcpIndexError::YamlSerializationError {
            reason: e.to_string(),
        })?;
    write_atomic(
        &output_dir.join("crate_graph.yaml"),
        graph_yaml_str.as_bytes(),
    )?;

    info!(
        output_dir = %output_dir.display(),
        index_hash = %index_hash,
        "CCP index written"
    );

    Ok(())
}

/// Builds the CCP index for the given repository.
///
/// This function:
/// 1. Builds the component atlas from AGENTS.md files
/// 2. Builds the crate graph from cargo metadata
/// 3. Discovers and hashes all source files
/// 4. Computes a deterministic index hash
/// 5. Writes output files atomically
///
/// # Arguments
///
/// * `repo_root` - Path to the repository root
/// * `prd_id` - PRD identifier for the output directory
/// * `options` - Build options (force, `dry_run`)
///
/// # Errors
///
/// Returns an error if:
/// - The repository root doesn't exist
/// - Component atlas or crate graph build fails
/// - File operations fail
///
/// # Example
///
/// ```rust,no_run
/// use std::path::Path;
///
/// use apm2_core::ccp::index::{CcpBuildOptions, build_ccp_index};
///
/// let result = build_ccp_index(
///     Path::new("/repo/root"),
///     "PRD-0001",
///     &CcpBuildOptions::default(),
/// )
/// .unwrap();
///
/// println!("Index hash: {}", result.index.index_hash);
/// println!("Components: {}", result.index.component_count);
/// println!("Crates: {}", result.index.crate_count);
/// ```
pub fn build_ccp_index(
    repo_root: &Path,
    prd_id: &str,
    options: &CcpBuildOptions,
) -> Result<CcpBuildResult, CcpIndexError> {
    // Validate repo root
    if !repo_root.exists() {
        return Err(CcpIndexError::InvalidRepoRoot {
            path: repo_root.display().to_string(),
        });
    }

    let repo_root = repo_root
        .canonicalize()
        .map_err(|e| CcpIndexError::InvalidRepoRoot {
            path: format!("{}: {}", repo_root.display(), e),
        })?;

    info!(
        repo_root = %repo_root.display(),
        prd_id = %prd_id,
        force = options.force,
        dry_run = options.dry_run,
        "Building CCP index"
    );

    // Build component atlas
    debug!("Building component atlas");
    let atlas = build_component_atlas(&repo_root)?;
    debug!(
        component_count = atlas.components.len(),
        "Component atlas built"
    );

    // Build crate graph
    debug!("Building crate graph");
    let graph = build_crate_graph(&repo_root)?;
    debug!(
        crate_count = graph.crates.len(),
        edge_count = graph.edges.len(),
        "Crate graph built"
    );

    // Discover and hash source files
    debug!("Discovering source files");
    let source_files = discover_source_files(&repo_root)?;
    debug!(file_count = source_files.len(), "Source files discovered");

    // Build file inventory
    debug!("Building file inventory");
    let file_inventory = build_file_inventory(&repo_root, &source_files)?;
    debug!(
        file_count = file_inventory.file_count,
        total_size = file_inventory.total_size,
        "File inventory built"
    );

    // Compute index hash
    debug!("Computing index hash");
    let index_hash = compute_index_hash(&atlas, &graph, &file_inventory)?;
    debug!(index_hash = %index_hash, "Index hash computed");

    // Determine output directory
    let output_dir = repo_root
        .join("evidence")
        .join("prd")
        .join(prd_id)
        .join("ccp");

    // Check for existing index and compare hash
    if !options.force {
        if let Some(existing_index) = read_existing_index(&output_dir) {
            if existing_index.index_hash == index_hash {
                info!(
                    index_hash = %index_hash,
                    "Index hash unchanged, skipping rebuild"
                );
                return Ok(CcpBuildResult {
                    index: existing_index,
                    atlas,
                    graph,
                    skipped: true,
                    output_dir,
                });
            }
        }
    }

    // Create the CCP index
    let index = CcpIndex {
        schema_version: CcpIndex::SCHEMA_VERSION.to_string(),
        generated_at: Utc::now(),
        repo_root,
        prd_id: prd_id.to_string(),
        index_hash: index_hash.clone(),
        component_count: atlas.components.len(),
        crate_count: graph.crates.len(),
        edge_count: graph.edges.len(),
        file_inventory,
    };

    // Write output files (unless dry run)
    if options.dry_run {
        info!(
            index_hash = %index_hash,
            "Dry run - skipping file writes"
        );
    } else {
        write_output_files(&output_dir, &index, &atlas, &graph, &index_hash)?;
    }

    Ok(CcpBuildResult {
        index,
        atlas,
        graph,
        skipped: false,
        output_dir,
    })
}

/// Checks if a rebuild is needed by comparing the stored hash with a fresh
/// computation.
///
/// This is useful for quick incremental checks without performing the full
/// build.
///
/// # Arguments
///
/// * `repo_root` - Path to the repository root
/// * `prd_id` - PRD identifier
///
/// # Returns
///
/// Returns `true` if a rebuild is needed, `false` if the index is up to date.
///
/// # Errors
///
/// Returns an error if:
/// - The component atlas cannot be built
/// - The crate graph cannot be built
/// - Source file discovery or hashing fails
pub fn needs_rebuild(repo_root: &Path, prd_id: &str) -> Result<bool, CcpIndexError> {
    let output_dir = repo_root
        .join("evidence")
        .join("prd")
        .join(prd_id)
        .join("ccp");

    // If no existing index, rebuild is needed
    let Some(existing_index) = read_existing_index(&output_dir) else {
        return Ok(true);
    };

    // Build fresh components to compute hash
    let atlas = build_component_atlas(repo_root)?;
    let graph = build_crate_graph(repo_root)?;
    let source_files = discover_source_files(repo_root)?;
    let file_inventory = build_file_inventory(repo_root, &source_files)?;
    let fresh_hash = compute_index_hash(&atlas, &graph, &file_inventory)?;

    Ok(existing_index.index_hash != fresh_hash)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::*;

    /// Creates a minimal test workspace structure.
    fn create_test_workspace(root: &Path) {
        // Create workspace Cargo.toml
        fs::write(
            root.join("Cargo.toml"),
            r#"[workspace]
members = ["crates/test-crate"]
resolver = "2"
"#,
        )
        .unwrap();

        // Create test crate
        fs::create_dir_all(root.join("crates/test-crate/src")).unwrap();
        fs::write(
            root.join("crates/test-crate/Cargo.toml"),
            r#"[package]
name = "test-crate"
version = "0.1.0"
edition = "2021"
"#,
        )
        .unwrap();
        fs::write(
            root.join("crates/test-crate/src/lib.rs"),
            "//! Test crate\npub fn hello() -> &'static str { \"hello\" }\n",
        )
        .unwrap();

        // Create AGENTS.md
        fs::write(
            root.join("crates/test-crate/AGENTS.md"),
            r"# Test Crate

> A test crate for testing.

## Invariants

- [INV-0001] Test invariant
",
        )
        .unwrap();
    }

    /// UT-113-01: Test index hash is deterministic.
    #[test]
    fn test_index_hash_deterministic() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();
        create_test_workspace(root);

        // Build twice and compare hashes
        let result1 = build_ccp_index(
            root,
            "PRD-TEST",
            &CcpBuildOptions {
                force: true,
                dry_run: true,
            },
        )
        .unwrap();
        let result2 = build_ccp_index(
            root,
            "PRD-TEST",
            &CcpBuildOptions {
                force: true,
                dry_run: true,
            },
        )
        .unwrap();

        assert_eq!(
            result1.index.index_hash, result2.index.index_hash,
            "Index hash should be deterministic"
        );
    }

    /// UT-113-02: Test file inventory captures all source files.
    #[test]
    fn test_file_inventory_captures_all() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();
        create_test_workspace(root);

        // Add more source files
        fs::write(
            root.join("crates/test-crate/src/utils.rs"),
            "//! Utils module\n",
        )
        .unwrap();
        fs::create_dir_all(root.join("crates/test-crate/src/submod")).unwrap();
        fs::write(
            root.join("crates/test-crate/src/submod/mod.rs"),
            "//! Submodule\n",
        )
        .unwrap();

        let result = build_ccp_index(
            root,
            "PRD-TEST",
            &CcpBuildOptions {
                force: true,
                dry_run: true,
            },
        )
        .unwrap();

        // Should capture all 3 .rs files + 1 AGENTS.md file = 4 files
        assert_eq!(
            result.index.file_inventory.file_count, 4,
            "Should capture all source files (3 .rs + 1 .md)"
        );

        // Verify paths are sorted
        let paths: Vec<_> = result
            .index
            .file_inventory
            .files
            .iter()
            .map(|f| f.path.to_string_lossy().to_string())
            .collect();
        let mut sorted_paths = paths.clone();
        sorted_paths.sort();
        assert_eq!(paths, sorted_paths, "File paths should be sorted");
    }

    /// UT-113-03: Test incremental rebuild detection.
    #[test]
    fn test_incremental_rebuild_detection() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();
        create_test_workspace(root);

        // First build
        let result1 = build_ccp_index(root, "PRD-TEST", &CcpBuildOptions::default()).unwrap();
        assert!(!result1.skipped, "First build should not be skipped");

        // Second build without changes should be skipped
        let result2 = build_ccp_index(root, "PRD-TEST", &CcpBuildOptions::default()).unwrap();
        assert!(result2.skipped, "Second build should be skipped");
        assert_eq!(result1.index.index_hash, result2.index.index_hash);

        // Modify a source file
        fs::write(
            root.join("crates/test-crate/src/lib.rs"),
            "//! Modified test crate\npub fn hello() -> &'static str { \"world\" }\n",
        )
        .unwrap();

        // Third build should not be skipped
        let result3 = build_ccp_index(root, "PRD-TEST", &CcpBuildOptions::default()).unwrap();
        assert!(
            !result3.skipped,
            "Build after modification should not be skipped"
        );
        assert_ne!(
            result1.index.index_hash, result3.index.index_hash,
            "Hash should change after modification"
        );
    }

    /// UT-113-04: Test force rebuild ignores cache.
    #[test]
    fn test_force_rebuild_ignores_cache() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();
        create_test_workspace(root);

        // First build
        let result1 = build_ccp_index(root, "PRD-TEST", &CcpBuildOptions::default()).unwrap();
        assert!(!result1.skipped);

        // Force rebuild should not be skipped even without changes
        let result2 = build_ccp_index(
            root,
            "PRD-TEST",
            &CcpBuildOptions {
                force: true,
                dry_run: false,
            },
        )
        .unwrap();
        assert!(!result2.skipped, "Force rebuild should not be skipped");
    }

    /// IT-113-01: Full integration test.
    #[test]
    fn test_full_integration() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();
        create_test_workspace(root);

        // Build the index
        let result = build_ccp_index(root, "PRD-0001", &CcpBuildOptions::default()).unwrap();

        // Verify index structure
        assert_eq!(result.index.schema_version, CcpIndex::SCHEMA_VERSION);
        assert_eq!(result.index.prd_id, "PRD-0001");
        assert!(!result.index.index_hash.is_empty());
        assert_eq!(result.index.component_count, result.atlas.components.len());
        assert_eq!(result.index.crate_count, result.graph.crates.len());
        assert_eq!(result.index.edge_count, result.graph.edges.len());

        // Verify output files exist
        let output_dir = root.join("evidence/prd/PRD-0001/ccp");
        assert!(output_dir.join("ccp_index.json").exists());
        assert!(output_dir.join("component_atlas.yaml").exists());
        assert!(output_dir.join("crate_graph.yaml").exists());

        // Verify output files are valid
        let index_content = fs::read_to_string(output_dir.join("ccp_index.json")).unwrap();
        let _: CcpIndex = serde_json::from_str(&index_content).unwrap();

        let atlas_content = fs::read_to_string(output_dir.join("component_atlas.yaml")).unwrap();
        let _: ComponentAtlas = serde_yaml::from_str(&atlas_content).unwrap();

        let graph_content = fs::read_to_string(output_dir.join("crate_graph.yaml")).unwrap();
        let _: CrateGraph = serde_yaml::from_str(&graph_content).unwrap();
    }

    #[test]
    fn test_dry_run_no_output() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();
        create_test_workspace(root);

        // Build with dry run
        let result = build_ccp_index(
            root,
            "PRD-TEST",
            &CcpBuildOptions {
                force: false,
                dry_run: true,
            },
        )
        .unwrap();

        // Index should be computed
        assert!(!result.index.index_hash.is_empty());

        // But no output files should exist
        let output_dir = root.join("evidence/prd/PRD-TEST/ccp");
        assert!(
            !output_dir.exists(),
            "Output directory should not exist in dry run"
        );
    }

    #[test]
    fn test_invalid_repo_root() {
        let result = build_ccp_index(
            Path::new("/nonexistent/path"),
            "PRD-TEST",
            &CcpBuildOptions::default(),
        );
        assert!(matches!(result, Err(CcpIndexError::InvalidRepoRoot { .. })));
    }

    #[test]
    fn test_needs_rebuild() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();
        create_test_workspace(root);

        // No existing index - needs rebuild
        assert!(needs_rebuild(root, "PRD-TEST").unwrap());

        // Build the index
        build_ccp_index(root, "PRD-TEST", &CcpBuildOptions::default()).unwrap();

        // Now it doesn't need rebuild
        assert!(!needs_rebuild(root, "PRD-TEST").unwrap());

        // Modify a file
        fs::write(
            root.join("crates/test-crate/src/lib.rs"),
            "//! Modified content\n",
        )
        .unwrap();

        // Now it needs rebuild again
        assert!(needs_rebuild(root, "PRD-TEST").unwrap());
    }

    #[test]
    fn test_file_hash_correctness() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();

        // Create a test file with known content
        let content = b"Hello, World!";
        let test_file = root.join("test.rs");
        fs::write(&test_file, content).unwrap();

        let (hash, size) = hash_file(&test_file).unwrap();

        // Verify size
        assert_eq!(size, content.len() as u64);

        // Verify hash is correct BLAKE3 hash
        let expected_hash = blake3::hash(content).to_hex().to_string();
        assert_eq!(hash, expected_hash);

        // Verify hash is deterministic
        let (hash2, _) = hash_file(&test_file).unwrap();
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_path_traversal_prevention() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();

        // Create a file outside the repo
        let outside_dir = TempDir::new().unwrap();
        let outside_file = outside_dir.path().join("secret.txt");
        fs::write(&outside_file, "secret").unwrap();

        // Validate should fail for path outside repo
        let result = validate_path_within_repo(&outside_file, root);
        assert!(matches!(
            result,
            Err(CcpIndexError::PathTraversalError { .. })
        ));
    }

    #[test]
    fn test_source_files_sorted() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();

        // Create files in non-alphabetical order
        fs::create_dir_all(root.join("crates/z-crate/src")).unwrap();
        fs::create_dir_all(root.join("crates/a-crate/src")).unwrap();
        fs::write(root.join("crates/z-crate/src/lib.rs"), "").unwrap();
        fs::write(root.join("crates/a-crate/src/lib.rs"), "").unwrap();

        let files = discover_source_files(root).unwrap();

        // Verify sorted
        let paths: Vec<_> = files
            .iter()
            .map(|p| p.to_string_lossy().to_string())
            .collect();
        let mut sorted = paths.clone();
        sorted.sort();
        assert_eq!(paths, sorted, "Source files should be sorted");
    }
}
