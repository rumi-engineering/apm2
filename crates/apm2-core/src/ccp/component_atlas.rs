#![allow(clippy::disallowed_methods)] // Metadata/observability usage or adapter.
//! Component atlas generation for CCP.
//!
//! This module discovers AGENTS.md files in crate directories, parses
//! invariants/contracts/extension points, and generates stable component IDs.
//! The atlas provides the semantic inventory of the codebase that grounds
//! all RFC file path references.
//!
//! # Invariants
//!
//! - [INV-0001] Component IDs are deterministic: same crate name always
//!   produces same ID
//! - [INV-0002] Component list is sorted by ID for deterministic output
//! - [INV-0003] AGENTS.md discovery is sorted alphabetically for determinism
//!
//! # Contracts
//!
//! - [CTR-0001] Parser tolerates format variations in AGENTS.md files
//! - [CTR-0002] Crates without AGENTS.md get placeholder entries with empty
//!   `invariants`/`contracts`/`extension_points`
//! - [CTR-0003] Generated YAML output uses canonical format from determinism
//!   module

use std::collections::HashSet;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use chrono::{DateTime, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::warn;

/// Maximum file size for AGENTS.md files (10 MB).
/// Prevents denial-of-service via unbounded reads.
const MAX_AGENTS_MD_SIZE: u64 = 10 * 1024 * 1024;

/// Maximum file size for Cargo.toml files (1 MB).
/// Prevents denial-of-service via unbounded reads.
const MAX_CARGO_TOML_SIZE: u64 = 1024 * 1024;

/// Errors that can occur during CCP operations.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CcpError {
    /// Failed to read a file.
    #[error("failed to read file {path}: {reason}")]
    ReadError {
        /// Path to the file that failed to read.
        path: String,
        /// Reason for the failure.
        reason: String,
    },

    /// Failed to parse AGENTS.md content.
    #[error("failed to parse AGENTS.md at {path}: {reason}")]
    ParseError {
        /// Path to the file that failed to parse.
        path: String,
        /// Reason for the failure.
        reason: String,
    },

    /// Failed to discover crates.
    #[error("failed to discover crates in {path}: {reason}")]
    DiscoveryError {
        /// Path where discovery failed.
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
}

/// Stability level for extension points.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Stability {
    /// Unstable API, may change without notice.
    #[default]
    Unstable,
    /// Stable API with backward compatibility guarantees.
    Stable,
    /// Deprecated API, will be removed in future versions.
    Deprecated,
}

/// Type of component (derived from crate structure).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ComponentType {
    /// A library crate.
    #[default]
    Library,
    /// A binary crate.
    Binary,
    /// An xtask crate (development tooling).
    XTask,
    /// A skill (agent capability).
    Skill,
}

/// An invariant extracted from AGENTS.md.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Invariant {
    /// Unique identifier (e.g., "INV-0001").
    pub id: String,
    /// Human-readable description.
    pub description: String,
}

/// A contract extracted from AGENTS.md.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Contract {
    /// Unique identifier (e.g., "CTR-0001").
    pub id: String,
    /// Human-readable description.
    pub description: String,
}

/// An extension point extracted from AGENTS.md.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtensionPoint {
    /// Unique identifier (e.g., "EXT-0001").
    pub id: String,
    /// Human-readable description.
    pub description: String,
    /// Stability level of this extension point.
    pub stability: Stability,
}

/// A component in the codebase (typically a crate).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Component {
    /// Stable component identifier (e.g., "COMP-APM2_CORE").
    pub id: String,
    /// Human-readable name (the crate name).
    pub name: String,
    /// Path to the crate directory, relative to repo root.
    pub crate_path: PathBuf,
    /// Type of component.
    pub component_type: ComponentType,
    /// Description from AGENTS.md or generated placeholder.
    pub description: String,
    /// Path to AGENTS.md if it exists.
    pub agents_md_path: Option<PathBuf>,
    /// Invariants extracted from AGENTS.md.
    pub invariants: Vec<Invariant>,
    /// Contracts extracted from AGENTS.md.
    pub contracts: Vec<Contract>,
    /// Extension points extracted from AGENTS.md.
    pub extension_points: Vec<ExtensionPoint>,
}

/// The complete component atlas for a repository.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentAtlas {
    /// Schema version for this atlas format.
    pub schema_version: String,
    /// Timestamp when the atlas was generated.
    pub generated_at: DateTime<Utc>,
    /// Repository root path.
    pub repo_root: PathBuf,
    /// All discovered components, sorted by ID.
    pub components: Vec<Component>,
}

impl ComponentAtlas {
    /// Current schema version.
    pub const SCHEMA_VERSION: &'static str = "2026-01-26";
}

/// Generates a stable component ID from a crate name.
///
/// The ID format is `COMP-{UPPER_SNAKE_CASE}` where the crate name is
/// converted to uppercase with hyphens replaced by underscores.
///
/// # Examples
///
/// ```
/// use apm2_core::ccp::generate_component_id;
///
/// assert_eq!(generate_component_id("apm2-core"), "COMP-APM2_CORE");
/// assert_eq!(generate_component_id("my_crate"), "COMP-MY_CRATE");
/// ```
#[must_use]
pub fn generate_component_id(crate_name: &str) -> String {
    let upper_snake = crate_name.to_uppercase().replace('-', "_");
    format!("COMP-{upper_snake}")
}

/// Reads a file with a size limit to prevent denial-of-service via unbounded
/// reads.
///
/// # Errors
///
/// Returns an error if the file is too large or cannot be read.
fn read_file_bounded(path: &Path, max_size: u64) -> Result<String, CcpError> {
    let metadata = fs::metadata(path).map_err(|e| CcpError::ReadError {
        path: path.display().to_string(),
        reason: e.to_string(),
    })?;

    if metadata.len() > max_size {
        return Err(CcpError::FileTooLarge {
            path: path.display().to_string(),
            size: metadata.len(),
            max_size,
        });
    }

    let file = File::open(path).map_err(|e| CcpError::ReadError {
        path: path.display().to_string(),
        reason: e.to_string(),
    })?;

    // Use take() to enforce the size limit even if metadata was wrong
    let mut content = String::new();
    file.take(max_size)
        .read_to_string(&mut content)
        .map_err(|e| CcpError::ReadError {
            path: path.display().to_string(),
            reason: e.to_string(),
        })?;

    Ok(content)
}

/// Escapes a path for use in glob patterns to prevent glob injection.
fn escape_path_for_glob(path: &Path) -> String {
    glob::Pattern::escape(&path.to_string_lossy())
}

/// Discovers all AGENTS.md files in the repository.
///
/// Searches for:
/// - `crates/*/AGENTS.md` (top-level crate AGENTS.md)
/// - `crates/*/*/AGENTS.md` (nested module AGENTS.md - for future use)
///
/// Returns paths sorted alphabetically for determinism.
fn discover_agents_md(repo_root: &Path) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    let escaped_root = escape_path_for_glob(repo_root);

    // Pattern 1: crates/*/AGENTS.md
    let pattern1 = format!("{escaped_root}/crates/*/AGENTS.md");
    if let Ok(entries) = glob::glob(&pattern1) {
        for entry in entries.flatten() {
            paths.push(entry);
        }
    }

    // Pattern 2: crates/*/*/AGENTS.md (for nested modules like
    // src/adapter/AGENTS.md)
    let pattern2 = format!("{escaped_root}/crates/*/*/AGENTS.md");
    if let Ok(entries) = glob::glob(&pattern2) {
        for entry in entries.flatten() {
            paths.push(entry);
        }
    }

    // Pattern 3: crates/*/*/*/AGENTS.md (for deeper nesting like
    // src/adapter/foo/AGENTS.md)
    let pattern3 = format!("{escaped_root}/crates/*/*/*/AGENTS.md");
    if let Ok(entries) = glob::glob(&pattern3) {
        for entry in entries.flatten() {
            paths.push(entry);
        }
    }

    // Sort for determinism
    paths.sort();
    paths
}

/// Discovers all crate directories in the repository.
///
/// Returns crate directories (containing Cargo.toml) sorted alphabetically.
fn discover_crates(repo_root: &Path) -> Result<Vec<PathBuf>, CcpError> {
    let mut crates = Vec::new();
    let escaped_root = escape_path_for_glob(repo_root);

    // Pattern: crates/*/Cargo.toml
    let pattern = format!("{escaped_root}/crates/*/Cargo.toml");
    let entries = glob::glob(&pattern).map_err(|e| CcpError::DiscoveryError {
        path: pattern.clone(),
        reason: e.to_string(),
    })?;

    for entry in entries.flatten() {
        // Get the crate directory (parent of Cargo.toml)
        if let Some(crate_dir) = entry.parent() {
            crates.push(crate_dir.to_path_buf());
        }
    }

    // Also check for xtask
    let xtask_cargo = repo_root.join("xtask/Cargo.toml");
    if xtask_cargo.exists() {
        crates.push(repo_root.join("xtask"));
    }

    // Sort for determinism
    crates.sort();
    Ok(crates)
}

/// Parsed content from an AGENTS.md file.
#[derive(Debug, Default)]
struct ParsedAgentsMd {
    /// Module description (first paragraph or quote block).
    description: String,
    /// Extracted invariants.
    invariants: Vec<Invariant>,
    /// Extracted contracts.
    contracts: Vec<Contract>,
    /// Extracted extension points.
    extension_points: Vec<ExtensionPoint>,
}

// Regex patterns for parsing AGENTS.md
// Format 1 (List): `- INV-001: statement here`
// Format 2 (Definition): `INV-001: statement here`
// Format 3 (Header): `### INV-001: Title`
// Format 4 (Table): `| INV-001 | statement |`
static LIST_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^-\s*\[(INV|CTR|EXT)-(\d+)\]\s*(.+)$").unwrap());

static DEF_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\[(INV|CTR|EXT)-(\d+)\]\s*(.+)$").unwrap());

static HEADER_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^#{1,4}\s*\[(INV|CTR|EXT)-(\d+)\]:\s*(.+)$").unwrap());

static TABLE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\|\s*\[(INV|CTR|EXT)-(\d+)\]\s*\|\s*(.+?)\s*\|").unwrap());

// Also support formats without brackets (as shown in ticket)
static LIST_NOBRACKET_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^-\s*(INV|CTR|EXT)-(\d+):\s*(.+)$").unwrap());

static DEF_NOBRACKET_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(INV|CTR|EXT)-(\d+):\s*(.+)$").unwrap());

static HEADER_NOBRACKET_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^#{1,4}\s*(INV|CTR|EXT)-(\d+):\s*(.+)$").unwrap());

static TABLE_NOBRACKET_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\|\s*(INV|CTR|EXT)-(\d+)\s*\|\s*(.+?)\s*\|").unwrap());

/// Parses an AGENTS.md file and extracts invariants, contracts, and extension
/// points.
///
/// This parser is tolerant of format variations:
/// 1. List format: `- [INV-001] statement here` or `- INV-001: statement here`
/// 2. Definition format: `[INV-001] statement here` or `INV-001: statement
///    here`
/// 3. Header-prefixed: `### [INV-001]: Title` or `### INV-001: Title`
/// 4. Table format: `| [INV-001] | statement |` or `| INV-001 | statement |`
fn parse_agents_md(content: &str) -> ParsedAgentsMd {
    let mut result = ParsedAgentsMd::default();
    let mut seen_ids: HashSet<String> = HashSet::new();

    // Extract description from first paragraph or quote block
    let lines: Vec<&str> = content.lines().collect();
    let mut description_lines = Vec::new();
    let mut in_description = false;

    for line in &lines {
        let trimmed = line.trim();

        // Skip title line
        if trimmed.starts_with("# ") && !in_description {
            continue;
        }

        // Quote block is description
        if trimmed.starts_with("> ") {
            description_lines.push(trimmed.trim_start_matches("> ").trim());
            in_description = true;
            continue;
        }

        // Empty line after description ends it
        if in_description && trimmed.is_empty() {
            break;
        }

        // First non-empty, non-title, non-quote line starts description
        if !in_description && !trimmed.is_empty() && !trimmed.starts_with('#') {
            description_lines.push(trimmed);
            in_description = true;
        } else if in_description {
            description_lines.push(trimmed);
        }
    }

    result.description = description_lines.join(" ").trim().to_string();

    // Parse invariants, contracts, and extension points
    for line in &lines {
        let trimmed = line.trim();

        // Try each regex pattern
        let captures = LIST_RE
            .captures(trimmed)
            .or_else(|| DEF_RE.captures(trimmed))
            .or_else(|| HEADER_RE.captures(trimmed))
            .or_else(|| TABLE_RE.captures(trimmed))
            .or_else(|| LIST_NOBRACKET_RE.captures(trimmed))
            .or_else(|| DEF_NOBRACKET_RE.captures(trimmed))
            .or_else(|| HEADER_NOBRACKET_RE.captures(trimmed))
            .or_else(|| TABLE_NOBRACKET_RE.captures(trimmed));

        if let Some(caps) = captures {
            let prefix = caps.get(1).map_or("", |m| m.as_str());
            let num = caps.get(2).map_or("", |m| m.as_str());
            let desc = caps.get(3).map_or("", |m| m.as_str().trim()).to_string();

            let id = format!("{prefix}-{num}");

            // Skip duplicates
            if seen_ids.contains(&id) {
                continue;
            }
            seen_ids.insert(id.clone());

            match prefix {
                "INV" => {
                    result.invariants.push(Invariant {
                        id,
                        description: desc,
                    });
                },
                "CTR" => {
                    result.contracts.push(Contract {
                        id,
                        description: desc,
                    });
                },
                "EXT" => {
                    result.extension_points.push(ExtensionPoint {
                        id,
                        description: desc,
                        stability: Stability::default(),
                    });
                },
                _ => {},
            }
        }
    }

    // Sort for determinism
    result.invariants.sort_by(|a, b| a.id.cmp(&b.id));
    result.contracts.sort_by(|a, b| a.id.cmp(&b.id));
    result.extension_points.sort_by(|a, b| a.id.cmp(&b.id));

    result
}

/// Determines the component type from the crate path and Cargo.toml.
fn determine_component_type(crate_path: &Path) -> ComponentType {
    // Check if it's xtask
    if crate_path.file_name().is_some_and(|n| n == "xtask") {
        return ComponentType::XTask;
    }

    // Check Cargo.toml for binary targets
    let cargo_toml = crate_path.join("Cargo.toml");
    match read_file_bounded(&cargo_toml, MAX_CARGO_TOML_SIZE) {
        Ok(content) => {
            // Simple heuristic: if it has [[bin]] section, it's a binary
            if content.contains("[[bin]]") {
                return ComponentType::Binary;
            }
            // If it's a daemon or CLI crate, it's binary
            if let Some(name) = crate_path.file_name() {
                let name_str = name.to_string_lossy();
                if name_str.contains("daemon") || name_str.contains("cli") {
                    return ComponentType::Binary;
                }
            }
        },
        Err(e) => {
            warn!(
                path = %cargo_toml.display(),
                error = %e,
                "Failed to read Cargo.toml for component type detection, defaulting to Library"
            );
        },
    }

    ComponentType::Library
}

/// Extracts the crate name from a crate path.
fn extract_crate_name(crate_path: &Path) -> String {
    crate_path.file_name().map_or_else(
        || "unknown".to_string(),
        |n| n.to_string_lossy().to_string(),
    )
}

/// Builds a component atlas for the given repository.
///
/// This function:
/// 1. Discovers all crate directories in `crates/` and `xtask/`
/// 2. For each crate, checks for AGENTS.md
/// 3. If AGENTS.md exists, parses it for invariants/contracts/extension points
/// 4. If AGENTS.md doesn't exist, creates a placeholder entry
/// 5. Generates stable component IDs from crate names
/// 6. Returns the atlas sorted by component ID for determinism
///
/// # Errors
///
/// Returns an error if:
/// - The repository root doesn't exist
/// - Crate discovery fails
///
/// # Example
///
/// ```rust,no_run
/// use std::path::Path;
///
/// use apm2_core::ccp::build_component_atlas;
///
/// let atlas = build_component_atlas(Path::new("/repo/root")).unwrap();
/// for component in &atlas.components {
///     println!(
///         "{}: {} invariants",
///         component.id,
///         component.invariants.len()
///     );
/// }
/// ```
pub fn build_component_atlas(repo_root: &Path) -> Result<ComponentAtlas, CcpError> {
    // Validate repo root
    if !repo_root.exists() {
        return Err(CcpError::InvalidRepoRoot {
            path: repo_root.display().to_string(),
        });
    }

    // Discover all crates
    let crates = discover_crates(repo_root)?;

    // Build a map of crate paths to their AGENTS.md files
    let agents_md_files = discover_agents_md(repo_root);
    let mut agents_md_map: std::collections::HashMap<PathBuf, PathBuf> =
        std::collections::HashMap::new();

    for agents_path in agents_md_files {
        // Find the crate directory for this AGENTS.md
        // It could be at crate root or in a subdirectory
        for crate_dir in &crates {
            if agents_path.starts_with(crate_dir) {
                // Use the top-level AGENTS.md for the crate if it exists
                let top_level = crate_dir.join("AGENTS.md");
                if agents_path == top_level {
                    agents_md_map.insert(crate_dir.clone(), agents_path.clone());
                }
                break;
            }
        }
    }

    // Build components
    let mut components = Vec::new();

    for crate_path in crates {
        let crate_name = extract_crate_name(&crate_path);
        let component_id = generate_component_id(&crate_name);
        let component_type = determine_component_type(&crate_path);

        // Make path relative to repo root
        let relative_path = crate_path
            .strip_prefix(repo_root)
            .unwrap_or(&crate_path)
            .to_path_buf();

        let (description, invariants, contracts, extension_points, agents_md_path) =
            if let Some(agents_path) = agents_md_map.get(&crate_path) {
                // Parse AGENTS.md with bounded read to prevent DoS
                let content = read_file_bounded(agents_path, MAX_AGENTS_MD_SIZE)?;

                let parsed = parse_agents_md(&content);

                let relative_agents_path = agents_path
                    .strip_prefix(repo_root)
                    .unwrap_or(agents_path)
                    .to_path_buf();

                (
                    parsed.description,
                    parsed.invariants,
                    parsed.contracts,
                    parsed.extension_points,
                    Some(relative_agents_path),
                )
            } else {
                // Placeholder entry
                (
                    format!("Component for {crate_name} (no AGENTS.md)"),
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                    None,
                )
            };

        components.push(Component {
            id: component_id,
            name: crate_name,
            crate_path: relative_path,
            component_type,
            description,
            agents_md_path,
            invariants,
            contracts,
            extension_points,
        });
    }

    // Sort by component ID for determinism
    components.sort_by(|a, b| a.id.cmp(&b.id));

    Ok(ComponentAtlas {
        schema_version: ComponentAtlas::SCHEMA_VERSION.to_string(),
        generated_at: Utc::now(),
        repo_root: repo_root.to_path_buf(),
        components,
    })
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::*;

    /// UT-111-01: Test component ID generation is deterministic.
    #[test]
    fn test_component_id_deterministic() {
        // Same input should always produce same output
        for _ in 0..10 {
            assert_eq!(generate_component_id("apm2-core"), "COMP-APM2_CORE");
            assert_eq!(generate_component_id("apm2-daemon"), "COMP-APM2_DAEMON");
            assert_eq!(generate_component_id("my_crate"), "COMP-MY_CRATE");
        }

        // Different inputs produce different outputs
        assert_ne!(
            generate_component_id("apm2-core"),
            generate_component_id("apm2-daemon")
        );
    }

    #[test]
    fn test_component_id_variations() {
        assert_eq!(generate_component_id("foo"), "COMP-FOO");
        assert_eq!(generate_component_id("foo-bar"), "COMP-FOO_BAR");
        assert_eq!(generate_component_id("foo_bar"), "COMP-FOO_BAR");
        assert_eq!(generate_component_id("foo-bar-baz"), "COMP-FOO_BAR_BAZ");
        assert_eq!(generate_component_id("FooBar"), "COMP-FOOBAR");
    }

    /// UT-111-02: Test AGENTS.md discovery finds all files.
    #[test]
    fn test_agents_md_discovery() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();

        // Create directory structure
        fs::create_dir_all(root.join("crates/foo")).unwrap();
        fs::create_dir_all(root.join("crates/bar")).unwrap();
        fs::create_dir_all(root.join("crates/baz/src")).unwrap();

        // Create AGENTS.md files
        fs::write(root.join("crates/foo/AGENTS.md"), "# Foo").unwrap();
        fs::write(root.join("crates/bar/AGENTS.md"), "# Bar").unwrap();
        fs::write(root.join("crates/baz/AGENTS.md"), "# Baz").unwrap();

        let discovered = discover_agents_md(root);

        assert_eq!(discovered.len(), 3);
        // Should be sorted
        assert!(discovered[0].ends_with("crates/bar/AGENTS.md"));
        assert!(discovered[1].ends_with("crates/baz/AGENTS.md"));
        assert!(discovered[2].ends_with("crates/foo/AGENTS.md"));
    }

    #[test]
    fn test_agents_md_discovery_empty() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();

        // No crates directory
        let discovered = discover_agents_md(root);
        assert!(discovered.is_empty());
    }

    /// UT-111-03: Test AGENTS.md parsing extracts invariants (all 4 formats).
    #[test]
    fn test_parse_invariants() {
        let content = r"# Test Module

> This is the description.

## Invariants

- [INV-0001] All operations must be atomic
[INV-0002] State is always consistent after operation

### [INV-0003]: Thread Safety
All public methods are thread-safe.

| ID | Description |
|----|-------------|
| [INV-0004] | Memory usage bounded by config |
";

        let parsed = parse_agents_md(content);

        assert_eq!(parsed.invariants.len(), 4);
        assert_eq!(parsed.invariants[0].id, "INV-0001");
        assert_eq!(
            parsed.invariants[0].description,
            "All operations must be atomic"
        );
        assert_eq!(parsed.invariants[1].id, "INV-0002");
        assert_eq!(
            parsed.invariants[1].description,
            "State is always consistent after operation"
        );
        assert_eq!(parsed.invariants[2].id, "INV-0003");
        assert_eq!(parsed.invariants[2].description, "Thread Safety");
        assert_eq!(parsed.invariants[3].id, "INV-0004");
        assert_eq!(
            parsed.invariants[3].description,
            "Memory usage bounded by config"
        );
    }

    #[test]
    fn test_parse_invariants_nobracket_format() {
        // Test the format without brackets (as shown in ticket)
        let content = r"# Test Module

## Invariants

- INV-001: All operations must be atomic
INV-002: State is always consistent after operation

### INV-003: Thread Safety
All public methods are thread-safe.

| ID | Description |
|----|-------------|
| INV-004 | Memory usage bounded by config |
";

        let parsed = parse_agents_md(content);

        assert_eq!(parsed.invariants.len(), 4);
        assert_eq!(parsed.invariants[0].id, "INV-001");
        assert_eq!(parsed.invariants[1].id, "INV-002");
        assert_eq!(parsed.invariants[2].id, "INV-003");
        assert_eq!(parsed.invariants[3].id, "INV-004");
    }

    #[test]
    fn test_parse_contracts() {
        let content = r"# Test Module

## Contracts

- [CTR-0001] Caller must validate input before calling
[CTR-0002] Return values are always non-null

### [CTR-0003]: Error Handling
Errors are returned, not thrown.
";

        let parsed = parse_agents_md(content);

        assert_eq!(parsed.contracts.len(), 3);
        assert_eq!(parsed.contracts[0].id, "CTR-0001");
        assert_eq!(
            parsed.contracts[0].description,
            "Caller must validate input before calling"
        );
        assert_eq!(parsed.contracts[1].id, "CTR-0002");
        assert_eq!(parsed.contracts[2].id, "CTR-0003");
    }

    /// UT-111-04: Test AGENTS.md parsing extracts extension points.
    #[test]
    fn test_parse_extension_points() {
        let content = r"# Test Module

## Extension Points

- [EXT-0001] Custom handlers can be registered via trait
[EXT-0002] Plugins can be loaded at runtime
";

        let parsed = parse_agents_md(content);

        assert_eq!(parsed.extension_points.len(), 2);
        assert_eq!(parsed.extension_points[0].id, "EXT-0001");
        assert_eq!(
            parsed.extension_points[0].description,
            "Custom handlers can be registered via trait"
        );
        assert_eq!(parsed.extension_points[1].id, "EXT-0002");
        assert_eq!(parsed.extension_points[0].stability, Stability::Unstable);
    }

    #[test]
    fn test_parse_description() {
        let content = r"# Test Module

> This is a module that does important things.

## Invariants
";

        let parsed = parse_agents_md(content);
        assert_eq!(
            parsed.description,
            "This is a module that does important things."
        );
    }

    #[test]
    fn test_parse_description_multiline_quote() {
        let content = r"# Test Module

> This is a module that does
> important things across
> multiple lines.

## Invariants
";

        let parsed = parse_agents_md(content);
        assert_eq!(
            parsed.description,
            "This is a module that does important things across multiple lines."
        );
    }

    #[test]
    fn test_parse_duplicate_ids() {
        // Duplicates should be skipped
        let content = r"# Test Module

- [INV-0001] First definition
- [INV-0001] Duplicate (should be ignored)
- [INV-0002] Second invariant
";

        let parsed = parse_agents_md(content);

        assert_eq!(parsed.invariants.len(), 2);
        assert_eq!(parsed.invariants[0].id, "INV-0001");
        assert_eq!(parsed.invariants[0].description, "First definition");
    }

    /// UT-111-05: Test placeholder components for crates without AGENTS.md.
    #[test]
    fn test_placeholder_components() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();

        // Create crates with and without AGENTS.md
        fs::create_dir_all(root.join("crates/with-agents")).unwrap();
        fs::create_dir_all(root.join("crates/without-agents")).unwrap();

        fs::write(
            root.join("crates/with-agents/Cargo.toml"),
            "[package]\nname = \"with-agents\"",
        )
        .unwrap();
        fs::write(
            root.join("crates/without-agents/Cargo.toml"),
            "[package]\nname = \"without-agents\"",
        )
        .unwrap();

        fs::write(
            root.join("crates/with-agents/AGENTS.md"),
            "# With Agents\n\n> Has documentation.\n\n- [INV-0001] Test invariant",
        )
        .unwrap();

        let atlas = build_component_atlas(root).unwrap();

        assert_eq!(atlas.components.len(), 2);

        // Find the component without AGENTS.md
        let without = atlas
            .components
            .iter()
            .find(|c| c.name == "without-agents")
            .unwrap();
        assert!(without.agents_md_path.is_none());
        assert!(without.invariants.is_empty());
        assert!(without.contracts.is_empty());
        assert!(without.extension_points.is_empty());
        assert!(without.description.contains("no AGENTS.md"));

        // Find the component with AGENTS.md
        let with = atlas
            .components
            .iter()
            .find(|c| c.name == "with-agents")
            .unwrap();
        assert!(with.agents_md_path.is_some());
        assert_eq!(with.invariants.len(), 1);
    }

    /// IT-111-01: Integration test: full component atlas build.
    #[test]
    fn test_full_component_atlas_build() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();

        // Create a realistic directory structure
        fs::create_dir_all(root.join("crates/apm2-core/src")).unwrap();
        fs::create_dir_all(root.join("crates/apm2-daemon")).unwrap();
        fs::create_dir_all(root.join("crates/apm2-cli")).unwrap();
        fs::create_dir_all(root.join("xtask")).unwrap();

        // Create Cargo.toml files
        fs::write(
            root.join("crates/apm2-core/Cargo.toml"),
            "[package]\nname = \"apm2-core\"",
        )
        .unwrap();
        fs::write(
            root.join("crates/apm2-daemon/Cargo.toml"),
            "[package]\nname = \"apm2-daemon\"\n[[bin]]\nname = \"apm2-daemon\"",
        )
        .unwrap();
        fs::write(
            root.join("crates/apm2-cli/Cargo.toml"),
            "[package]\nname = \"apm2-cli\"\n[[bin]]\nname = \"apm2\"",
        )
        .unwrap();
        fs::write(root.join("xtask/Cargo.toml"), "[package]\nname = \"xtask\"").unwrap();

        // Create AGENTS.md files
        fs::write(
            root.join("crates/apm2-core/AGENTS.md"),
            r"# APM2 Core

> Core library for apm2.

## Invariants

- [INV-0001] All operations are thread-safe
- [INV-0002] State transitions are atomic

## Contracts

- [CTR-0001] Caller validates input

## Extension Points

- [EXT-0001] Custom adapters via trait
",
        )
        .unwrap();

        fs::write(
            root.join("crates/apm2-daemon/AGENTS.md"),
            r"# APM2 Daemon

> Background daemon process.

## Invariants

- [INV-0001] Single instance per machine
",
        )
        .unwrap();

        // Build the atlas
        let atlas = build_component_atlas(root).unwrap();

        // Verify schema version
        assert_eq!(atlas.schema_version, ComponentAtlas::SCHEMA_VERSION);

        // Verify all components discovered
        assert_eq!(atlas.components.len(), 4);

        // Verify components are sorted by ID
        let ids: Vec<_> = atlas.components.iter().map(|c| &c.id).collect();
        let mut sorted_ids = ids.clone();
        sorted_ids.sort();
        assert_eq!(ids, sorted_ids);

        // Verify specific components
        let core = atlas
            .components
            .iter()
            .find(|c| c.name == "apm2-core")
            .unwrap();
        assert_eq!(core.id, "COMP-APM2_CORE");
        assert_eq!(core.component_type, ComponentType::Library);
        assert_eq!(core.invariants.len(), 2);
        assert_eq!(core.contracts.len(), 1);
        assert_eq!(core.extension_points.len(), 1);

        let daemon = atlas
            .components
            .iter()
            .find(|c| c.name == "apm2-daemon")
            .unwrap();
        assert_eq!(daemon.id, "COMP-APM2_DAEMON");
        assert_eq!(daemon.component_type, ComponentType::Binary);
        assert_eq!(daemon.invariants.len(), 1);

        let xtask = atlas.components.iter().find(|c| c.name == "xtask").unwrap();
        assert_eq!(xtask.id, "COMP-XTASK");
        assert_eq!(xtask.component_type, ComponentType::XTask);

        let cli = atlas
            .components
            .iter()
            .find(|c| c.name == "apm2-cli")
            .unwrap();
        assert_eq!(cli.id, "COMP-APM2_CLI");
        assert_eq!(cli.component_type, ComponentType::Binary);
        // No AGENTS.md, should be placeholder
        assert!(cli.agents_md_path.is_none());
    }

    #[test]
    fn test_atlas_determinism() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();

        // Create minimal structure
        fs::create_dir_all(root.join("crates/alpha")).unwrap();
        fs::create_dir_all(root.join("crates/beta")).unwrap();
        fs::create_dir_all(root.join("crates/gamma")).unwrap();

        fs::write(
            root.join("crates/alpha/Cargo.toml"),
            "[package]\nname = \"alpha\"",
        )
        .unwrap();
        fs::write(
            root.join("crates/beta/Cargo.toml"),
            "[package]\nname = \"beta\"",
        )
        .unwrap();
        fs::write(
            root.join("crates/gamma/Cargo.toml"),
            "[package]\nname = \"gamma\"",
        )
        .unwrap();

        fs::write(
            root.join("crates/alpha/AGENTS.md"),
            "# Alpha\n- [INV-0001] Test",
        )
        .unwrap();
        fs::write(
            root.join("crates/beta/AGENTS.md"),
            "# Beta\n- [INV-0001] Test",
        )
        .unwrap();

        // Build atlas twice
        let atlas1 = build_component_atlas(root).unwrap();
        let atlas2 = build_component_atlas(root).unwrap();

        // Component IDs and order should match
        assert_eq!(atlas1.components.len(), atlas2.components.len());
        for (c1, c2) in atlas1.components.iter().zip(atlas2.components.iter()) {
            assert_eq!(c1.id, c2.id);
            assert_eq!(c1.name, c2.name);
            assert_eq!(c1.crate_path, c2.crate_path);
            assert_eq!(c1.invariants, c2.invariants);
            assert_eq!(c1.contracts, c2.contracts);
            assert_eq!(c1.extension_points, c2.extension_points);
        }
    }

    #[test]
    fn test_invalid_repo_root() {
        let result = build_component_atlas(Path::new("/nonexistent/path"));
        assert!(matches!(result, Err(CcpError::InvalidRepoRoot { .. })));
    }

    #[test]
    fn test_empty_agents_md() {
        let content = "";
        let parsed = parse_agents_md(content);
        assert!(parsed.invariants.is_empty());
        assert!(parsed.contracts.is_empty());
        assert!(parsed.extension_points.is_empty());
    }

    #[test]
    fn test_agents_md_with_only_prose() {
        let content = r"# Module Name

This module does things. It's very useful.

## Overview

More description here without any invariants or contracts.
";

        let parsed = parse_agents_md(content);
        assert!(parsed.invariants.is_empty());
        assert!(parsed.contracts.is_empty());
        assert!(parsed.extension_points.is_empty());
    }

    #[test]
    fn test_parse_real_world_format() {
        // Test the actual format used in the codebase (with square brackets)
        let content = r"# Adapter Module

> Normalizes heterogeneous agent runtimes into a common event contract.

**Invariants:**
- [INV-0101] `sequence` is strictly monotonically increasing
- [INV-0102] First event is always `ProcessStarted`

**Contracts:**
- [CTR-0101] All adapters emit normalized `AdapterEvent` instances
- [CTR-0102] Events are ordered by `sequence` within a session
";

        let parsed = parse_agents_md(content);

        assert_eq!(parsed.invariants.len(), 2);
        assert_eq!(parsed.invariants[0].id, "INV-0101");
        assert_eq!(parsed.invariants[1].id, "INV-0102");

        assert_eq!(parsed.contracts.len(), 2);
        assert_eq!(parsed.contracts[0].id, "CTR-0101");
        assert_eq!(parsed.contracts[1].id, "CTR-0102");
    }

    #[test]
    fn test_read_file_bounded() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();

        // Create a small file (should succeed)
        let small_file = root.join("small.md");
        fs::write(&small_file, "# Small file\n").unwrap();
        let result = read_file_bounded(&small_file, MAX_AGENTS_MD_SIZE);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "# Small file\n");

        // Test with a small max size (should fail for same file)
        let result = read_file_bounded(&small_file, 5);
        assert!(matches!(result, Err(CcpError::FileTooLarge { .. })));

        // Test with nonexistent file (should fail)
        let nonexistent = root.join("nonexistent.md");
        let result = read_file_bounded(&nonexistent, MAX_AGENTS_MD_SIZE);
        assert!(matches!(result, Err(CcpError::ReadError { .. })));
    }

    #[test]
    fn test_escape_path_for_glob() {
        // Normal path should remain unchanged
        assert_eq!(escape_path_for_glob(Path::new("/foo/bar")), "/foo/bar");

        // Path with glob special characters should be escaped
        assert_eq!(
            escape_path_for_glob(Path::new("/foo/[bar]")),
            "/foo/[[]bar[]]"
        );
        assert_eq!(escape_path_for_glob(Path::new("/foo/*")), "/foo/[*]");
        assert_eq!(escape_path_for_glob(Path::new("/foo/?")), "/foo/[?]");
    }
}
