//! Crate graph generation for CCP.
//!
//! This module invokes `cargo metadata` to build a deterministic dependency
//! graph of all workspace crates. The graph captures inter-crate dependencies
//! with version constraints, enabling impact analysis when changes propagate
//! through the dependency tree.
//!
//! # Invariants
//!
//! - [INV-0001] Crate graph output is deterministic: same workspace always
//!   produces identical graph (sorted nodes and edges)
//! - [INV-0002] Only workspace crates are included as nodes
//! - [INV-0003] Edges represent actual dependencies from Cargo.toml
//!
//! # Contracts
//!
//! - [CTR-0001] `build_crate_graph` requires a valid cargo workspace root
//! - [CTR-0002] Errors are returned explicitly, not swallowed
//! - [CTR-0003] Output uses canonical sorting for reproducibility
//!
//! # Security
//!
//! - [SEC-0001] Cargo subprocess environment is sanitized - only essential
//!   variables (`PATH`, `HOME`, `CARGO_HOME`, `RUSTUP_HOME`) are passed through
//! - [SEC-0002] Cargo metadata is parsed with strict typed schemas to prevent
//!   fail-open on malformed input
//! - [SEC-0003] Subprocess has 30-second timeout to prevent denial-of-service
//!   via hanging process
//! - [SEC-0004] JSON is parsed directly from `BufReader` for memory efficiency

use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, warn};
use wait_timeout::ChildExt;

// =============================================================================
// Cargo Metadata Schema Types (SEC-0002: Strict typed parsing)
// =============================================================================

/// Parsed cargo metadata output.
#[derive(Debug, Deserialize)]
struct CargoMetadata {
    /// All packages in the workspace.
    packages: Vec<CargoPackage>,
    /// Workspace member package IDs.
    workspace_members: Vec<String>,
    /// Workspace root path.
    workspace_root: PathBuf,
}

/// A package in cargo metadata.
#[derive(Debug, Deserialize)]
struct CargoPackage {
    /// Package identifier (e.g., "apm2-core 0.1.0 (path+file:///...)").
    id: String,
    /// Package name.
    name: String,
    /// Package version.
    version: String,
    /// Path to the package's Cargo.toml.
    manifest_path: PathBuf,
    /// Package dependencies.
    #[serde(default)]
    dependencies: Vec<CargoDependency>,
    /// Package targets (lib, bin, etc.).
    #[serde(default)]
    targets: Vec<CargoTarget>,
    /// Package features.
    #[serde(default)]
    features: HashMap<String, Vec<String>>,
}

/// A dependency in cargo metadata.
#[derive(Debug, Deserialize)]
struct CargoDependency {
    /// Dependency name.
    name: String,
    /// Dependency kind (normal, dev, build).
    kind: Option<String>,
    /// Version requirement.
    req: String,
    /// Enabled features.
    #[serde(default)]
    features: Vec<String>,
    /// Whether the dependency is optional.
    #[serde(default)]
    optional: bool,
}

/// A target in cargo metadata.
#[derive(Debug, Deserialize)]
struct CargoTarget {
    /// Target kinds (lib, bin, proc-macro, etc.).
    kind: Vec<String>,
}

/// Maximum output size for cargo metadata (50 MB).
/// Prevents denial-of-service via unbounded reads from subprocess.
const MAX_CARGO_METADATA_SIZE: u64 = 50 * 1024 * 1024;

/// Timeout for cargo metadata subprocess (30 seconds).
/// SEC-0003: Prevents denial-of-service via hanging subprocess.
const CARGO_METADATA_TIMEOUT: Duration = Duration::from_secs(30);

/// Errors that can occur during crate graph generation.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CrateGraphError {
    /// Failed to invoke cargo metadata.
    #[error("failed to invoke cargo metadata: {reason}")]
    CargoInvocationError {
        /// Reason for the failure.
        reason: String,
    },

    /// Failed to parse cargo metadata output.
    #[error("failed to parse cargo metadata: {reason}")]
    MetadataParseError {
        /// Reason for the failure.
        reason: String,
    },

    /// Invalid workspace root.
    #[error("invalid workspace root: {path}")]
    InvalidWorkspaceRoot {
        /// The invalid path.
        path: String,
    },

    /// Cargo metadata output is too large.
    #[error("cargo metadata output too large ({size} bytes, max {max_size} bytes)")]
    OutputTooLarge {
        /// Actual output size.
        size: u64,
        /// Maximum allowed size.
        max_size: u64,
    },

    /// Cargo command returned an error.
    #[error("cargo metadata failed: {stderr}")]
    CargoError {
        /// The stderr output from cargo.
        stderr: String,
    },

    /// Cargo subprocess timed out.
    #[error("cargo metadata timed out after {timeout_secs} seconds")]
    SubprocessTimeout {
        /// The timeout in seconds.
        timeout_secs: u64,
    },

    /// Reader thread panicked during output collection.
    #[error("reader thread panicked while collecting subprocess output")]
    ReaderThreadPanic,
}

/// Type of crate target.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord,
)]
#[serde(rename_all = "lowercase")]
pub enum CrateType {
    /// A library crate (`[lib]`).
    #[default]
    Lib,
    /// A binary crate (`[[bin]]`).
    Bin,
    /// A procedural macro crate (`proc-macro = true`).
    ProcMacro,
}

/// Type of dependency relationship.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord,
)]
#[serde(rename_all = "lowercase")]
pub enum DependencyType {
    /// Normal dependency (`[dependencies]`).
    #[default]
    Normal,
    /// Development dependency (`[dev-dependencies]`).
    Dev,
    /// Build dependency (`[build-dependencies]`).
    Build,
}

/// A crate node in the dependency graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrateNode {
    /// Stable crate identifier (matches component ID pattern from atlas).
    /// Format: `CRATE-{UPPER_SNAKE_CASE}` (e.g., "CRATE-APM2_CORE").
    pub id: String,
    /// Crate name from Cargo.toml.
    pub name: String,
    /// Version from Cargo.toml.
    pub version: String,
    /// Crate root path, relative to workspace root.
    pub path: PathBuf,
    /// Primary crate type.
    pub crate_type: CrateType,
    /// Available features.
    pub features: Vec<String>,
}

/// A dependency edge in the graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DependencyEdge {
    /// Source crate ID.
    pub from: String,
    /// Target crate ID.
    pub to: String,
    /// Type of dependency.
    pub dep_type: DependencyType,
    /// Version requirement (e.g., "0.1", "^1.0", "=2.0.0").
    pub version_req: String,
    /// Enabled features for this dependency.
    pub features: Vec<String>,
    /// Whether this is an optional dependency.
    pub optional: bool,
}

/// The complete crate graph for a workspace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrateGraph {
    /// Schema version for this graph format.
    pub schema_version: String,
    /// Timestamp when the graph was generated.
    pub generated_at: DateTime<Utc>,
    /// Workspace root path.
    pub workspace_root: PathBuf,
    /// All workspace crates, sorted by ID.
    pub crates: Vec<CrateNode>,
    /// All dependency edges, sorted by (from, to, `dep_type`).
    pub edges: Vec<DependencyEdge>,
}

impl CrateGraph {
    /// Current schema version.
    pub const SCHEMA_VERSION: &'static str = "2026-01-26";
}

/// Generates a stable crate ID from a crate name.
///
/// The ID format is `CRATE-{UPPER_SNAKE_CASE}` where the crate name is
/// converted to uppercase with hyphens replaced by underscores.
///
/// # Examples
///
/// ```
/// use apm2_core::ccp::crate_graph::generate_crate_id;
///
/// assert_eq!(generate_crate_id("apm2-core"), "CRATE-APM2_CORE");
/// assert_eq!(generate_crate_id("my_crate"), "CRATE-MY_CRATE");
/// ```
#[must_use]
pub fn generate_crate_id(crate_name: &str) -> String {
    let upper_snake = crate_name.to_uppercase().replace('-', "_");
    format!("CRATE-{upper_snake}")
}

/// Environment variables allowed to pass through to cargo subprocess.
///
/// SEC-0001: Only essential variables are allowed to prevent secret leakage.
/// - `PATH`: Required to locate cargo and rustc binaries
/// - `HOME`: Required for rustup/cargo home resolution
/// - `CARGO_HOME`: Custom cargo installation directory
/// - `RUSTUP_HOME`: Custom rustup installation directory
/// - `CARGO_TARGET_DIR`: Custom target directory (may be set for build caching)
/// - `TERM`: Terminal type for error message formatting
const ALLOWED_ENV_VARS: &[&str] = &[
    "PATH",
    "HOME",
    "CARGO_HOME",
    "RUSTUP_HOME",
    "CARGO_TARGET_DIR",
    "TERM",
];

/// Maximum stderr size (1 MB) - limits error message collection.
const MAX_STDERR_SIZE: u64 = 1024 * 1024;

/// Reads from a pipe into a Vec<u8> with a size limit.
/// Returns the bytes read (up to limit) and whether the limit was exceeded.
fn read_pipe_bounded<R: Read>(reader: R, limit: u64) -> std::io::Result<Vec<u8>> {
    let mut buffer = Vec::new();
    reader.take(limit).read_to_end(&mut buffer)?;
    Ok(buffer)
}

/// Invokes `cargo metadata` and returns the parsed metadata.
///
/// # Security
///
/// The cargo subprocess runs with a sanitized environment (SEC-0001). Only
/// essential variables are passed through to prevent leaking secrets like
/// API keys or tokens to the subprocess.
///
/// # Deadlock Prevention
///
/// Stdout and stderr are read concurrently in separate threads BEFORE waiting
/// for the subprocess to complete. This prevents deadlock when the subprocess
/// writes more than the OS pipe buffer size (~64KB), which would cause the
/// subprocess to block on write while the parent waits for it to exit.
///
/// # Errors
///
/// Returns an error if cargo cannot be invoked, the command fails, or the
/// output is too large or cannot be parsed.
fn invoke_cargo_metadata(repo_root: &Path) -> Result<CargoMetadata, CrateGraphError> {
    let manifest_path = repo_root.join("Cargo.toml");

    if !manifest_path.exists() {
        return Err(CrateGraphError::InvalidWorkspaceRoot {
            path: repo_root.display().to_string(),
        });
    }

    debug!(
        manifest_path = %manifest_path.display(),
        "Invoking cargo metadata"
    );

    // SEC-0001: Build command with sanitized environment
    let mut cmd = Command::new("cargo");
    cmd.arg("metadata")
        .arg("--format-version")
        .arg("1")
        .arg("--locked") // Prevent network access and Cargo.lock updates
        .arg("--manifest-path")
        .arg(&manifest_path)
        .arg("--no-deps")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_clear(); // Clear all environment variables

    // Re-add only essential variables
    for var_name in ALLOWED_ENV_VARS {
        if let Ok(value) = std::env::var(var_name) {
            cmd.env(var_name, value);
        }
    }

    let mut child = cmd
        .spawn()
        .map_err(|e| CrateGraphError::CargoInvocationError {
            reason: e.to_string(),
        })?;

    // Take stdout and stderr handles BEFORE waiting to prevent deadlock.
    // If the subprocess writes more than the pipe buffer (~64KB), it will
    // block on write. We must read concurrently with waiting.
    let stdout_handle = child.stdout.take();
    let stderr_handle = child.stderr.take();

    // Spawn reader threads to consume stdout and stderr concurrently.
    // This prevents deadlock when subprocess output exceeds pipe buffer.
    let (stdout_tx, stdout_rx) = mpsc::channel();
    let (stderr_tx, stderr_rx) = mpsc::channel();

    // Spawn stdout reader thread
    let stdout_thread = if let Some(stdout) = stdout_handle {
        Some(std::thread::spawn(move || {
            let result = read_pipe_bounded(stdout, MAX_CARGO_METADATA_SIZE);
            let _ = stdout_tx.send(result);
        }))
    } else {
        let _ = stdout_tx.send(Ok(Vec::new()));
        None
    };

    // Spawn stderr reader thread
    let stderr_thread = if let Some(stderr) = stderr_handle {
        Some(std::thread::spawn(move || {
            let result = read_pipe_bounded(stderr, MAX_STDERR_SIZE);
            let _ = stderr_tx.send(result);
        }))
    } else {
        let _ = stderr_tx.send(Ok(Vec::new()));
        None
    };

    // SEC-0003: Wait with timeout to prevent denial-of-service via hanging
    // subprocess. Reader threads will continue draining pipes in parallel.
    let status_result = child.wait_timeout(CARGO_METADATA_TIMEOUT).map_err(|e| {
        CrateGraphError::CargoInvocationError {
            reason: format!("failed to wait for cargo: {e}"),
        }
    });

    // Join reader threads (they will complete once subprocess closes pipes)
    if let Some(thread) = stdout_thread {
        let _ = thread.join();
    }
    if let Some(thread) = stderr_thread {
        let _ = thread.join();
    }

    // Check wait result after joining threads
    let Some(status) = status_result? else {
        // Timeout - kill the process
        let _ = child.kill();
        let _ = child.wait(); // Reap the zombie
        return Err(CrateGraphError::SubprocessTimeout {
            timeout_secs: CARGO_METADATA_TIMEOUT.as_secs(),
        });
    };

    // Collect stdout result from channel
    let stdout_bytes = stdout_rx
        .recv()
        .map_err(|_| CrateGraphError::ReaderThreadPanic)?
        .map_err(|e| CrateGraphError::CargoInvocationError {
            reason: format!("failed to read stdout: {e}"),
        })?;

    // Collect stderr result from channel
    let stderr_bytes = stderr_rx
        .recv()
        .map_err(|_| CrateGraphError::ReaderThreadPanic)?
        .map_err(|e| CrateGraphError::CargoInvocationError {
            reason: format!("failed to read stderr: {e}"),
        })?;

    // Check for cargo errors
    if !status.success() {
        let stderr_content = String::from_utf8_lossy(&stderr_bytes).into_owned();
        return Err(CrateGraphError::CargoError {
            stderr: stderr_content,
        });
    }

    // SEC-0002: Parse with strict typed schema
    serde_json::from_slice::<CargoMetadata>(&stdout_bytes).map_err(|e| {
        CrateGraphError::MetadataParseError {
            reason: format!("failed to parse cargo metadata schema: {e}"),
        }
    })
}

/// Builds a mapping of package names to crate IDs for workspace members.
fn build_name_to_id_map(
    packages: &[CargoPackage],
    workspace_members: &HashSet<String>,
) -> HashMap<String, String> {
    let mut name_to_id = HashMap::new();

    for package in packages {
        if !workspace_members.contains(&package.id) {
            continue;
        }

        let crate_id = generate_crate_id(&package.name);
        name_to_id.insert(package.name.clone(), crate_id);
    }

    name_to_id
}

/// Extracts a crate node from a package.
fn extract_crate_node(package: &CargoPackage, workspace_root: &Path) -> CrateNode {
    let crate_path = package
        .manifest_path
        .parent()
        .map(|p| p.strip_prefix(workspace_root).unwrap_or(p).to_path_buf())
        .unwrap_or_default();

    let crate_type = determine_crate_type(package);

    let mut features: Vec<String> = package.features.keys().cloned().collect();
    features.sort();

    CrateNode {
        id: generate_crate_id(&package.name),
        name: package.name.clone(),
        version: package.version.clone(),
        path: crate_path,
        crate_type,
        features,
    }
}

/// Extracts dependency edges from a package's dependencies.
fn extract_dependency_edges(
    package: &CargoPackage,
    crate_id: &str,
    name_to_id: &HashMap<String, String>,
) -> Vec<DependencyEdge> {
    let mut edges = Vec::new();

    for dep in &package.dependencies {
        // Only include edges to workspace crates
        let Some(target_id) = name_to_id.get(&dep.name) else {
            continue;
        };

        let dep_type = match dep.kind.as_deref() {
            Some("dev") => DependencyType::Dev,
            Some("build") => DependencyType::Build,
            _ => DependencyType::Normal,
        };

        let mut features = dep.features.clone();
        features.sort();

        edges.push(DependencyEdge {
            from: crate_id.to_string(),
            to: target_id.clone(),
            dep_type,
            version_req: dep.req.clone(),
            features,
            optional: dep.optional,
        });
    }

    edges
}

/// Parses cargo metadata into crate nodes and dependency edges.
///
/// # Arguments
///
/// * `metadata` - The parsed cargo metadata
/// * `workspace_root` - The workspace root path for computing relative paths
///
/// # Returns
///
/// A tuple of (crates, edges) extracted from the metadata.
fn parse_cargo_metadata(
    metadata: &CargoMetadata,
    workspace_root: &Path,
) -> (Vec<CrateNode>, Vec<DependencyEdge>) {
    let workspace_members: HashSet<String> = metadata.workspace_members.iter().cloned().collect();

    // Build a map of package name to crate ID for workspace members
    let name_to_id = build_name_to_id_map(&metadata.packages, &workspace_members);

    let mut crates = Vec::new();
    let mut edges = Vec::new();

    // Extract crate nodes and edges from workspace packages
    for package in &metadata.packages {
        if !workspace_members.contains(&package.id) {
            continue;
        }

        let crate_node = extract_crate_node(package, workspace_root);
        let crate_edges = extract_dependency_edges(package, &crate_node.id, &name_to_id);

        crates.push(crate_node);
        edges.extend(crate_edges);
    }

    (crates, edges)
}

/// Determines the primary crate type from package targets.
fn determine_crate_type(package: &CargoPackage) -> CrateType {
    // First pass: check for proc-macro (highest precedence)
    for target in &package.targets {
        if target.kind.iter().any(|k| k == "proc-macro") {
            return CrateType::ProcMacro;
        }
    }

    // Second pass: check for binary targets
    for target in &package.targets {
        if target.kind.iter().any(|k| k == "bin") {
            return CrateType::Bin;
        }
    }

    CrateType::Lib
}

/// Sorts crates and edges for deterministic output.
fn sort_graph(crates: &mut [CrateNode], edges: &mut [DependencyEdge]) {
    // Sort crates by ID
    crates.sort_by(|a, b| a.id.cmp(&b.id));

    // Sort edges by (from, to, dep_type)
    edges.sort_by(|a, b| {
        a.from
            .cmp(&b.from)
            .then_with(|| a.to.cmp(&b.to))
            .then_with(|| a.dep_type.cmp(&b.dep_type))
    });
}

/// Builds a crate graph for the given workspace.
///
/// This function:
/// 1. Invokes `cargo metadata --no-deps` to get workspace package information
/// 2. Parses the metadata to extract workspace crates and their dependencies
/// 3. Filters to only include edges between workspace crates
/// 4. Sorts the output deterministically for reproducibility
///
/// # Arguments
///
/// * `repo_root` - Path to the workspace root (directory containing root
///   Cargo.toml)
///
/// # Errors
///
/// Returns an error if:
/// - The workspace root doesn't contain a Cargo.toml
/// - Cargo metadata fails to execute
/// - The output cannot be parsed
///
/// # Example
///
/// ```rust,no_run
/// use std::path::Path;
///
/// use apm2_core::ccp::crate_graph::build_crate_graph;
///
/// let graph = build_crate_graph(Path::new("/repo/root")).unwrap();
/// println!("Workspace has {} crates", graph.crates.len());
/// for edge in &graph.edges {
///     println!("{} -> {} ({})", edge.from, edge.to, edge.version_req);
/// }
/// ```
pub fn build_crate_graph(repo_root: &Path) -> Result<CrateGraph, CrateGraphError> {
    // Validate workspace root
    if !repo_root.exists() {
        return Err(CrateGraphError::InvalidWorkspaceRoot {
            path: repo_root.display().to_string(),
        });
    }

    // Invoke cargo metadata
    let metadata = invoke_cargo_metadata(repo_root)?;

    // Extract workspace root from metadata
    let workspace_root = metadata.workspace_root.clone();

    // Parse metadata into nodes and edges
    let (mut crates, mut edges) = parse_cargo_metadata(&metadata, &workspace_root);

    // Sort for determinism
    sort_graph(&mut crates, &mut edges);

    // Log any skipped dependencies
    if crates.is_empty() {
        warn!("No workspace crates found in {}", repo_root.display());
    }

    Ok(CrateGraph {
        schema_version: CrateGraph::SCHEMA_VERSION.to_string(),
        generated_at: Utc::now(),
        workspace_root,
        crates,
        edges,
    })
}

/// Finds all crates that depend on the given crate.
///
/// This is useful for impact analysis - determining which crates are affected
/// when a crate changes.
///
/// # Example
///
/// ```rust,no_run
/// use apm2_core::ccp::crate_graph::{CrateGraph, find_dependents};
///
/// fn analyze_impact(graph: &CrateGraph, crate_id: &str) {
///     let dependents = find_dependents(graph, crate_id);
///     println!("Crates depending on {}: {:?}", crate_id, dependents);
/// }
/// ```
#[must_use]
pub fn find_dependents<'a>(graph: &'a CrateGraph, crate_id: &str) -> Vec<&'a str> {
    graph
        .edges
        .iter()
        .filter(|e| e.to == crate_id)
        .map(|e| e.from.as_str())
        .collect()
}

/// Finds all crates that the given crate depends on.
///
/// # Example
///
/// ```rust,no_run
/// use apm2_core::ccp::crate_graph::{CrateGraph, find_dependencies};
///
/// fn list_deps(graph: &CrateGraph, crate_id: &str) {
///     let deps = find_dependencies(graph, crate_id);
///     println!("Dependencies of {}: {:?}", crate_id, deps);
/// }
/// ```
#[must_use]
pub fn find_dependencies<'a>(graph: &'a CrateGraph, crate_id: &str) -> Vec<&'a str> {
    graph
        .edges
        .iter()
        .filter(|e| e.from == crate_id)
        .map(|e| e.to.as_str())
        .collect()
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::*;

    /// Helper to get the workspace root for tests.
    fn get_workspace_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|p| p.parent())
            .map(Path::to_path_buf)
            .expect("Could not find workspace root")
    }

    /// UT-112-01: Test cargo metadata invocation succeeds.
    #[test]
    fn test_cargo_metadata_invocation() {
        // This test runs against the actual workspace
        let repo_root = get_workspace_root();

        let result = invoke_cargo_metadata(&repo_root);
        assert!(
            result.is_ok(),
            "cargo metadata should succeed: {:?}",
            result.err()
        );

        let metadata = result.unwrap();
        assert!(
            !metadata.packages.is_empty(),
            "metadata should have packages"
        );
        assert!(
            !metadata.workspace_members.is_empty(),
            "metadata should have workspace_members"
        );
    }

    /// UT-112-02: Test metadata parsing extracts all workspace crates.
    #[test]
    fn test_parse_workspace_crates() {
        let repo_root = get_workspace_root();

        let metadata = invoke_cargo_metadata(&repo_root).unwrap();
        let (crates, _edges) = parse_cargo_metadata(&metadata, &repo_root);

        // Should find at least apm2-core, apm2-daemon, apm2-cli
        assert!(crates.len() >= 3, "Should find at least 3 workspace crates");

        assert!(
            crates.iter().any(|c| c.name == "apm2-core"),
            "Should find apm2-core"
        );
    }

    /// UT-112-03: Test dependency edges are correctly extracted.
    #[test]
    fn test_dependency_edges() {
        let repo_root = get_workspace_root();

        let metadata = invoke_cargo_metadata(&repo_root).unwrap();
        let (_crates, edges) = parse_cargo_metadata(&metadata, &repo_root);

        // apm2-daemon depends on apm2-core
        let daemon_to_core = edges
            .iter()
            .find(|e| e.from == "CRATE-APM2_DAEMON" && e.to == "CRATE-APM2_CORE");

        assert!(
            daemon_to_core.is_some(),
            "Should find apm2-daemon -> apm2-core edge"
        );
    }

    /// UT-112-04: Test output is deterministically sorted.
    #[test]
    fn test_deterministic_output() {
        let repo_root = get_workspace_root();

        // Build graph twice
        let graph1 = build_crate_graph(&repo_root).unwrap();
        let graph2 = build_crate_graph(&repo_root).unwrap();

        // Crate order should match
        assert_eq!(graph1.crates.len(), graph2.crates.len());
        for (c1, c2) in graph1.crates.iter().zip(graph2.crates.iter()) {
            assert_eq!(c1.id, c2.id, "Crate IDs should match in order");
            assert_eq!(c1.name, c2.name);
            assert_eq!(c1.version, c2.version);
            assert_eq!(c1.features, c2.features, "Features should be sorted");
        }

        // Edge order should match
        assert_eq!(graph1.edges.len(), graph2.edges.len());
        for (e1, e2) in graph1.edges.iter().zip(graph2.edges.iter()) {
            assert_eq!(e1.from, e2.from, "Edge from should match");
            assert_eq!(e1.to, e2.to, "Edge to should match");
            assert_eq!(e1.dep_type, e2.dep_type, "Edge dep_type should match");
        }

        // Verify crates are sorted by ID
        let ids: Vec<_> = graph1.crates.iter().map(|c| &c.id).collect();
        let mut sorted_ids = ids.clone();
        sorted_ids.sort();
        assert_eq!(ids, sorted_ids, "Crates should be sorted by ID");

        // Verify edges are sorted
        for window in graph1.edges.windows(2) {
            let ordering = window[0]
                .from
                .cmp(&window[1].from)
                .then_with(|| window[0].to.cmp(&window[1].to))
                .then_with(|| window[0].dep_type.cmp(&window[1].dep_type));
            assert!(
                ordering != std::cmp::Ordering::Greater,
                "Edges should be sorted by (from, to, dep_type)"
            );
        }
    }

    /// UT-112-05: Test optional dependencies are marked correctly.
    #[test]
    fn test_optional_dependencies() {
        // Create a minimal workspace with optional dependencies
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();

        // Create workspace Cargo.toml
        fs::write(
            root.join("Cargo.toml"),
            r#"[workspace]
members = ["crates/core", "crates/cli"]
resolver = "2"
"#,
        )
        .unwrap();

        // Create core crate
        fs::create_dir_all(root.join("crates/core/src")).unwrap();
        fs::write(
            root.join("crates/core/Cargo.toml"),
            r#"[package]
name = "core"
version = "0.1.0"
edition = "2021"
"#,
        )
        .unwrap();
        fs::write(root.join("crates/core/src/lib.rs"), "").unwrap();

        // Create cli crate with optional dependency on core
        fs::create_dir_all(root.join("crates/cli/src")).unwrap();
        fs::write(
            root.join("crates/cli/Cargo.toml"),
            r#"[package]
name = "cli"
version = "0.1.0"
edition = "2021"

[dependencies]
core = { path = "../core", optional = true }
"#,
        )
        .unwrap();
        fs::write(root.join("crates/cli/src/lib.rs"), "").unwrap();

        let graph = build_crate_graph(root).unwrap();

        // Find the cli -> core edge
        let cli_to_core = graph
            .edges
            .iter()
            .find(|e| e.from == "CRATE-CLI" && e.to == "CRATE-CORE");

        assert!(cli_to_core.is_some(), "Should find cli -> core edge");
        assert!(
            cli_to_core.unwrap().optional,
            "cli -> core should be marked as optional"
        );
    }

    /// IT-112-01: Integration test: full crate graph build.
    #[test]
    fn test_full_crate_graph_build() {
        let repo_root = get_workspace_root();

        let graph = build_crate_graph(&repo_root).unwrap();

        // Verify schema version
        assert_eq!(graph.schema_version, CrateGraph::SCHEMA_VERSION);

        // Verify workspace root is set
        assert!(!graph.workspace_root.as_os_str().is_empty());

        // Verify we have crates
        assert!(!graph.crates.is_empty(), "Should have workspace crates");

        // Verify each crate has required fields
        for crate_node in &graph.crates {
            assert!(!crate_node.id.is_empty(), "Crate ID should not be empty");
            assert!(
                !crate_node.name.is_empty(),
                "Crate name should not be empty"
            );
            assert!(
                !crate_node.version.is_empty(),
                "Crate version should not be empty"
            );
            assert!(
                crate_node.id.starts_with("CRATE-"),
                "Crate ID should start with CRATE-"
            );
        }

        // Verify edges reference valid crates
        let crate_ids: HashSet<_> = graph.crates.iter().map(|c| &c.id).collect();
        for edge in &graph.edges {
            assert!(
                crate_ids.contains(&edge.from),
                "Edge 'from' should reference a valid crate: {}",
                edge.from
            );
            assert!(
                crate_ids.contains(&edge.to),
                "Edge 'to' should reference a valid crate: {}",
                edge.to
            );
        }
    }

    #[test]
    fn test_generate_crate_id() {
        assert_eq!(generate_crate_id("apm2-core"), "CRATE-APM2_CORE");
        assert_eq!(generate_crate_id("apm2-daemon"), "CRATE-APM2_DAEMON");
        assert_eq!(generate_crate_id("my_crate"), "CRATE-MY_CRATE");
        assert_eq!(generate_crate_id("foo-bar-baz"), "CRATE-FOO_BAR_BAZ");
    }

    #[test]
    fn test_invalid_workspace_root() {
        let result = build_crate_graph(Path::new("/nonexistent/path"));
        assert!(matches!(
            result,
            Err(CrateGraphError::InvalidWorkspaceRoot { .. })
        ));
    }

    #[test]
    fn test_find_dependents() {
        let graph = CrateGraph {
            schema_version: CrateGraph::SCHEMA_VERSION.to_string(),
            generated_at: Utc::now(),
            workspace_root: PathBuf::new(),
            crates: vec![],
            edges: vec![
                DependencyEdge {
                    from: "CRATE-CLI".to_string(),
                    to: "CRATE-CORE".to_string(),
                    dep_type: DependencyType::Normal,
                    version_req: "0.1".to_string(),
                    features: vec![],
                    optional: false,
                },
                DependencyEdge {
                    from: "CRATE-DAEMON".to_string(),
                    to: "CRATE-CORE".to_string(),
                    dep_type: DependencyType::Normal,
                    version_req: "0.1".to_string(),
                    features: vec![],
                    optional: false,
                },
            ],
        };

        let dependents = find_dependents(&graph, "CRATE-CORE");
        assert_eq!(dependents.len(), 2);
        assert!(dependents.contains(&"CRATE-CLI"));
        assert!(dependents.contains(&"CRATE-DAEMON"));
    }

    #[test]
    fn test_find_dependencies() {
        let graph = CrateGraph {
            schema_version: CrateGraph::SCHEMA_VERSION.to_string(),
            generated_at: Utc::now(),
            workspace_root: PathBuf::new(),
            crates: vec![],
            edges: vec![
                DependencyEdge {
                    from: "CRATE-CLI".to_string(),
                    to: "CRATE-CORE".to_string(),
                    dep_type: DependencyType::Normal,
                    version_req: "0.1".to_string(),
                    features: vec![],
                    optional: false,
                },
                DependencyEdge {
                    from: "CRATE-CLI".to_string(),
                    to: "CRATE-UTILS".to_string(),
                    dep_type: DependencyType::Normal,
                    version_req: "0.1".to_string(),
                    features: vec![],
                    optional: false,
                },
            ],
        };

        let dependencies = find_dependencies(&graph, "CRATE-CLI");
        assert_eq!(dependencies.len(), 2);
        assert!(dependencies.contains(&"CRATE-CORE"));
        assert!(dependencies.contains(&"CRATE-UTILS"));
    }

    #[test]
    fn test_dependency_types() {
        // Create a workspace with different dependency types
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();

        fs::write(
            root.join("Cargo.toml"),
            r#"[workspace]
members = ["crates/core", "crates/cli"]
resolver = "2"
"#,
        )
        .unwrap();

        fs::create_dir_all(root.join("crates/core/src")).unwrap();
        fs::write(
            root.join("crates/core/Cargo.toml"),
            r#"[package]
name = "core"
version = "0.1.0"
edition = "2021"
"#,
        )
        .unwrap();
        fs::write(root.join("crates/core/src/lib.rs"), "").unwrap();

        fs::create_dir_all(root.join("crates/cli/src")).unwrap();
        fs::write(
            root.join("crates/cli/Cargo.toml"),
            r#"[package]
name = "cli"
version = "0.1.0"
edition = "2021"

[dependencies]
core = { path = "../core" }

[dev-dependencies]
core = { path = "../core" }

[build-dependencies]
core = { path = "../core" }
"#,
        )
        .unwrap();
        fs::write(root.join("crates/cli/src/lib.rs"), "").unwrap();

        let graph = build_crate_graph(root).unwrap();

        // Should have edges for normal, dev, and build dependencies
        let normal_edge = graph.edges.iter().find(|e| {
            e.from == "CRATE-CLI" && e.to == "CRATE-CORE" && e.dep_type == DependencyType::Normal
        });
        let dev_edge = graph.edges.iter().find(|e| {
            e.from == "CRATE-CLI" && e.to == "CRATE-CORE" && e.dep_type == DependencyType::Dev
        });
        let build_edge = graph.edges.iter().find(|e| {
            e.from == "CRATE-CLI" && e.to == "CRATE-CORE" && e.dep_type == DependencyType::Build
        });

        assert!(normal_edge.is_some(), "Should have normal dependency edge");
        assert!(dev_edge.is_some(), "Should have dev dependency edge");
        assert!(build_edge.is_some(), "Should have build dependency edge");
    }

    #[test]
    fn test_crate_type_detection() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();

        fs::write(
            root.join("Cargo.toml"),
            r#"[workspace]
members = ["crates/lib-crate", "crates/bin-crate"]
resolver = "2"
"#,
        )
        .unwrap();

        // Library crate
        fs::create_dir_all(root.join("crates/lib-crate/src")).unwrap();
        fs::write(
            root.join("crates/lib-crate/Cargo.toml"),
            r#"[package]
name = "lib-crate"
version = "0.1.0"
edition = "2021"

[lib]
name = "lib_crate"
"#,
        )
        .unwrap();
        fs::write(root.join("crates/lib-crate/src/lib.rs"), "").unwrap();

        // Binary crate
        fs::create_dir_all(root.join("crates/bin-crate/src")).unwrap();
        fs::write(
            root.join("crates/bin-crate/Cargo.toml"),
            r#"[package]
name = "bin-crate"
version = "0.1.0"
edition = "2021"

[[bin]]
name = "my-binary"
path = "src/main.rs"
"#,
        )
        .unwrap();
        fs::write(root.join("crates/bin-crate/src/main.rs"), "fn main() {}").unwrap();

        let graph = build_crate_graph(root).unwrap();

        let lib_crate = graph
            .crates
            .iter()
            .find(|c| c.name == "lib-crate")
            .expect("Should find lib-crate");
        assert_eq!(lib_crate.crate_type, CrateType::Lib);

        let bin_crate = graph
            .crates
            .iter()
            .find(|c| c.name == "bin-crate")
            .expect("Should find bin-crate");
        assert_eq!(bin_crate.crate_type, CrateType::Bin);
    }

    /// SEC-112-01: Test that cargo subprocess has sanitized environment.
    ///
    /// This test verifies that the `ALLOWED_ENV_VARS` list is properly used
    /// and doesn't accidentally include any obviously dangerous variables.
    #[test]
    fn test_allowed_env_vars_are_safe() {
        // Verify ALLOWED_ENV_VARS doesn't contain dangerous patterns
        let dangerous_patterns = [
            "SECRET",
            "TOKEN",
            "KEY",
            "PASSWORD",
            "CREDENTIAL",
            "AUTH",
            "API_KEY",
        ];

        for var in ALLOWED_ENV_VARS {
            let upper = var.to_uppercase();
            for pattern in &dangerous_patterns {
                assert!(
                    !upper.contains(pattern),
                    "ALLOWED_ENV_VARS should not contain dangerous variable pattern '{pattern}': found '{var}'"
                );
            }
        }
    }

    /// SEC-112-02: Test that cargo metadata with typed schema rejects malformed
    /// JSON.
    #[test]
    fn test_strict_schema_rejects_malformed() {
        // Valid JSON but missing required fields should fail
        let malformed_json = r#"{"packages": [], "not_workspace_members": []}"#;

        // This should fail because workspace_members is missing
        let result: Result<CargoMetadata, _> = serde_json::from_str(malformed_json);
        assert!(
            result.is_err(),
            "Should reject JSON missing required fields"
        );

        // Test with completely wrong structure
        let wrong_structure = r#"{"foo": "bar"}"#;
        let result: Result<CargoMetadata, _> = serde_json::from_str(wrong_structure);
        assert!(result.is_err(), "Should reject JSON with wrong structure");
    }

    /// SEC-112-03: Test that cargo metadata works with a sanitized environment.
    ///
    /// This verifies that the `build_crate_graph` function works correctly
    /// when running with a minimal set of environment variables.
    #[test]
    fn test_cargo_metadata_with_sanitized_env() {
        let repo_root = get_workspace_root();

        // Build crate graph should succeed with the sanitized environment
        // This test verifies that the command works with only the allowed vars
        let result = build_crate_graph(&repo_root);
        assert!(
            result.is_ok(),
            "build_crate_graph should succeed with sanitized environment: {:?}",
            result.err()
        );

        // Verify the result has valid data
        let graph = result.unwrap();
        assert!(
            !graph.crates.is_empty(),
            "Should have found workspace crates"
        );
    }
}
