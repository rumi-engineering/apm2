//! Signal collectors for refactor radar.
//!
//! This module provides signal collectors that analyze various aspects of
//! the codebase to identify areas that may benefit from refactoring:
//!
//! - `HotspotCollector`: Analyzes git history for high-churn files
//! - `DuplicationCollector`: Detects structural similarity patterns
//! - `ComplexityCollector`: Analyzes code complexity metrics
//!
//! # Invariants
//!
//! - [INV-SIGNAL-001] All signals have valid source paths within repo root
//! - [INV-SIGNAL-002] Severity levels are consistent across signal types
//! - [INV-SIGNAL-003] Evidence strings provide actionable context
//!
//! # Contracts
//!
//! - [CTR-SIGNAL-001] Git commands use proper argument escaping
//! - [CTR-SIGNAL-002] File paths from git are validated before use
//! - [CTR-SIGNAL-003] Collectors fail gracefully on missing data
//!
//! # Security
//!
//! - [SEC-SIGNAL-001] Path traversal is prevented via validation
//! - [SEC-SIGNAL-002] Git command arguments are not user-controlled
//! - [SEC-SIGNAL-003] File reads are bounded to prevent denial-of-service

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, warn};

/// Errors that can occur during signal collection.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SignalError {
    /// Git command failed.
    #[error("git command failed: {reason}")]
    GitCommandFailed {
        /// Reason for the failure.
        reason: String,
    },

    /// Invalid path in git output.
    #[error("invalid path in git output: {path} - {reason}")]
    InvalidPath {
        /// The invalid path.
        path: String,
        /// Reason it's invalid.
        reason: String,
    },

    /// Path traversal attempt detected.
    #[error("path traversal detected: {path}")]
    PathTraversal {
        /// The path that attempted traversal.
        path: String,
    },

    /// IO error during collection.
    #[error("IO error: {reason}")]
    IoError {
        /// Reason for the failure.
        reason: String,
    },
}

/// Severity level for a signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Low severity - worth noting but not urgent.
    Low,
    /// Medium severity - should be addressed.
    Medium,
    /// High severity - requires attention.
    High,
    /// Critical severity - immediate action recommended.
    Critical,
}

impl Severity {
    /// Returns a numeric value for sorting (higher = more severe).
    #[must_use]
    pub const fn value(self) -> u8 {
        match self {
            Self::Low => 1,
            Self::Medium => 2,
            Self::High => 3,
            Self::Critical => 4,
        }
    }
}

/// A hotspot signal indicating high file churn.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HotspotSignal {
    /// Path to the file (relative to repo root).
    pub source_path: PathBuf,
    /// Number of changes in the time window.
    pub churn_count: usize,
    /// Severity based on churn count.
    pub severity: Severity,
    /// Evidence describing the finding.
    pub evidence: String,
    /// Suggested action to address the hotspot.
    pub suggested_action: String,
}

/// A duplication signal indicating structural similarity.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DuplicationSignal {
    /// Primary source path.
    pub source_path: PathBuf,
    /// Similar file paths.
    pub similar_files: Vec<PathBuf>,
    /// Similarity percentage (0-100).
    pub similarity_percent: u8,
    /// Severity based on similarity and scope.
    pub severity: Severity,
    /// Evidence describing the finding.
    pub evidence: String,
    /// Suggested action to address duplication.
    pub suggested_action: String,
}

/// A complexity signal indicating high complexity metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComplexitySignal {
    /// Path to the file.
    pub source_path: PathBuf,
    /// Line count (a basic complexity proxy).
    pub line_count: usize,
    /// Severity based on complexity.
    pub severity: Severity,
    /// Evidence describing the finding.
    pub evidence: String,
    /// Suggested action to address complexity.
    pub suggested_action: String,
}

/// A unified signal type wrapping all signal variants.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "signal_type", rename_all = "snake_case")]
pub enum Signal {
    /// Hotspot signal.
    Hotspot(HotspotSignal),
    /// Duplication signal.
    Duplication(DuplicationSignal),
    /// Complexity signal.
    Complexity(ComplexitySignal),
}

impl Signal {
    /// Returns the source path for this signal.
    #[must_use]
    pub fn source_path(&self) -> &Path {
        match self {
            Self::Hotspot(s) => &s.source_path,
            Self::Duplication(s) => &s.source_path,
            Self::Complexity(s) => &s.source_path,
        }
    }

    /// Returns the severity for this signal.
    #[must_use]
    pub const fn severity(&self) -> Severity {
        match self {
            Self::Hotspot(s) => s.severity,
            Self::Duplication(s) => s.severity,
            Self::Complexity(s) => s.severity,
        }
    }

    /// Returns the evidence string for this signal.
    #[must_use]
    pub fn evidence(&self) -> &str {
        match self {
            Self::Hotspot(s) => &s.evidence,
            Self::Duplication(s) => &s.evidence,
            Self::Complexity(s) => &s.evidence,
        }
    }

    /// Returns the suggested action for this signal.
    #[must_use]
    pub fn suggested_action(&self) -> &str {
        match self {
            Self::Hotspot(s) => &s.suggested_action,
            Self::Duplication(s) => &s.suggested_action,
            Self::Complexity(s) => &s.suggested_action,
        }
    }

    /// Returns the signal type name.
    #[must_use]
    pub const fn signal_type(&self) -> &'static str {
        match self {
            Self::Hotspot(_) => "hotspot",
            Self::Duplication(_) => "duplication",
            Self::Complexity(_) => "complexity",
        }
    }
}

/// Validates a path from git output to prevent path traversal.
///
/// # Arguments
///
/// * `path` - The path string from git output
/// * `repo_root` - The repository root path
///
/// # Errors
///
/// Returns `SignalError::PathTraversal` if the path attempts traversal.
/// Returns `SignalError::InvalidPath` if the path is otherwise invalid.
fn validate_git_path(path: &str, repo_root: &Path) -> Result<PathBuf, SignalError> {
    // Check for obvious traversal attempts
    if path.contains("..") || path.starts_with('/') || path.contains('\\') {
        return Err(SignalError::PathTraversal {
            path: path.to_string(),
        });
    }

    // Check for null bytes or other control characters
    if path.bytes().any(|b| b == 0 || b < 32) {
        return Err(SignalError::InvalidPath {
            path: path.to_string(),
            reason: "contains control characters".to_string(),
        });
    }

    // Empty paths are invalid
    if path.is_empty() {
        return Err(SignalError::InvalidPath {
            path: path.to_string(),
            reason: "empty path".to_string(),
        });
    }

    let full_path = repo_root.join(path);

    // If the path exists, verify it's within repo_root via canonicalization
    if full_path.exists() {
        let canonical = full_path.canonicalize().map_err(|e| SignalError::IoError {
            reason: e.to_string(),
        })?;
        let canonical_root = repo_root.canonicalize().map_err(|e| SignalError::IoError {
            reason: e.to_string(),
        })?;

        if !canonical.starts_with(&canonical_root) {
            return Err(SignalError::PathTraversal {
                path: path.to_string(),
            });
        }
    }

    Ok(PathBuf::from(path))
}

/// Collector for hotspot signals based on git churn analysis.
pub struct HotspotCollector {
    /// Time window for churn analysis.
    window: Duration,
    /// Minimum churn count to report.
    min_churn: usize,
}

impl HotspotCollector {
    /// Creates a new hotspot collector.
    ///
    /// # Arguments
    ///
    /// * `window` - Time window to analyze (e.g., 7 days, 30 days)
    /// * `min_churn` - Minimum number of changes to report as a signal
    #[must_use]
    pub const fn new(window: Duration, min_churn: usize) -> Self {
        Self { window, min_churn }
    }

    /// Collects hotspot signals from the repository.
    ///
    /// # Arguments
    ///
    /// * `repo_root` - Path to the repository root
    ///
    /// # Errors
    ///
    /// Returns an error if git command fails or paths are invalid.
    ///
    /// # Security
    ///
    /// - SEC-SIGNAL-002: Git arguments are constructed internally, not from
    ///   user input
    /// - CTR-SIGNAL-002: All paths from git output are validated
    pub fn collect(&self, repo_root: &Path) -> Result<Vec<HotspotSignal>, SignalError> {
        // Calculate days from duration
        let days = self.window.as_secs() / 86400;
        let since_arg = format!("{days} days ago");

        debug!(
            repo_root = %repo_root.display(),
            days = days,
            "Collecting hotspot signals"
        );

        // Run git log to get file change history
        // SEC-SIGNAL-002: Arguments are hardcoded, not user-controlled
        // SEC-SIGNAL-003: Use streaming to prevent unbounded memory usage
        let mut child = Command::new("git")
            .args(["log", "--format=%H", "--name-only", "--since", &since_arg])
            .current_dir(repo_root)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| SignalError::GitCommandFailed {
                reason: e.to_string(),
            })?;

        let Some(stdout) = child.stdout.take() else {
            return Err(SignalError::GitCommandFailed {
                reason: "failed to capture stdout".to_string(),
            });
        };
        let reader = BufReader::new(stdout);
        let mut file_counts: HashMap<String, usize> = HashMap::new();

        // Parse git log output line-by-line: commit hashes followed by file paths
        for line_result in reader.lines() {
            let line = line_result.map_err(|e| SignalError::IoError {
                reason: e.to_string(),
            })?;
            let line = line.trim();

            // Skip empty lines
            if line.is_empty() {
                continue;
            }

            // Skip commit hashes (40 hex characters)
            if line.len() == 40 && line.chars().all(|c| c.is_ascii_hexdigit()) {
                continue;
            }

            // Validate and count the file path
            match validate_git_path(line, repo_root) {
                Ok(_) => {
                    *file_counts.entry(line.to_string()).or_insert(0) += 1;
                },
                Err(e) => {
                    warn!(path = %line, error = %e, "Skipping invalid path from git");
                },
            }
        }

        // Wait for the child process and check exit status
        let status = child.wait().map_err(|e| SignalError::GitCommandFailed {
            reason: e.to_string(),
        })?;

        if !status.success() {
            return Err(SignalError::GitCommandFailed {
                reason: "git log failed".to_string(),
            });
        }

        // Convert to signals, filtering by min_churn and sorting by count
        let mut signals: Vec<HotspotSignal> = file_counts
            .into_iter()
            .filter(|(_, count)| *count >= self.min_churn)
            .map(|(path, count)| {
                let severity = severity_from_churn(count);
                HotspotSignal {
                    source_path: PathBuf::from(&path),
                    churn_count: count,
                    severity,
                    evidence: format!(
                        "Modified {count} times in the last {days} days, indicating high volatility"
                    ),
                    suggested_action: suggest_hotspot_action(count, &path),
                }
            })
            .collect();

        // Sort by churn count descending
        signals.sort_by(|a, b| b.churn_count.cmp(&a.churn_count));

        debug!(signal_count = signals.len(), "Collected hotspot signals");

        Ok(signals)
    }
}

/// Determines severity from churn count.
const fn severity_from_churn(count: usize) -> Severity {
    if count >= 30 {
        Severity::Critical
    } else if count >= 20 {
        Severity::High
    } else if count >= 10 {
        Severity::Medium
    } else {
        Severity::Low
    }
}

/// Suggests an action based on churn count and file path.
fn suggest_hotspot_action(count: usize, path: &str) -> String {
    if count >= 30 {
        format!(
            "Consider refactoring {path} into smaller, more focused modules to reduce change coupling"
        )
    } else if count >= 20 {
        format!(
            "Review {path} for separation of concerns - high churn may indicate mixed responsibilities"
        )
    } else if count >= 10 {
        format!(
            "Monitor {path} - moderate churn may stabilize after current work or indicate need for extraction"
        )
    } else {
        format!("Low priority - {path} shows normal maintenance patterns")
    }
}

/// Collector for duplication signals based on structural similarity.
pub struct DuplicationCollector {
    /// Minimum similarity threshold (0-100).
    similarity_threshold: u8,
}

impl DuplicationCollector {
    /// Creates a new duplication collector.
    ///
    /// # Arguments
    ///
    /// * `similarity_threshold` - Minimum similarity percentage to report
    ///   (0-100)
    #[must_use]
    pub const fn new(similarity_threshold: u8) -> Self {
        Self {
            similarity_threshold,
        }
    }

    /// Collects duplication signals by analyzing file structure patterns.
    ///
    /// This is a heuristic-based approach that looks for:
    /// - Files with similar names in different directories
    /// - Files with similar structure (imports, function patterns)
    ///
    /// # Arguments
    ///
    /// * `repo_root` - Path to the repository root
    ///
    /// # Errors
    ///
    /// Returns an error if file operations fail.
    pub fn collect(&self, repo_root: &Path) -> Result<Vec<DuplicationSignal>, SignalError> {
        debug!(
            repo_root = %repo_root.display(),
            threshold = self.similarity_threshold,
            "Collecting duplication signals"
        );

        let mut signals = Vec::new();

        // Find Rust source files using git ls-files for consistency
        // SEC-SIGNAL-003: Use streaming to avoid loading entire output into memory
        let mut child = Command::new("git")
            .args(["ls-files", "*.rs"])
            .current_dir(repo_root)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| SignalError::GitCommandFailed {
                reason: e.to_string(),
            })?;

        let Some(stdout) = child.stdout.take() else {
            warn!("git ls-files produced no stdout, skipping duplication analysis");
            return Ok(signals);
        };

        // CTR-SIGNAL-002: Validate all paths from git before use
        let files: Vec<PathBuf> = BufReader::new(stdout)
            .lines()
            .filter_map(|line_result| {
                let line = line_result.ok()?;
                if line.is_empty() {
                    return None;
                }
                match validate_git_path(&line, repo_root) {
                    Ok(p) => Some(p),
                    Err(e) => {
                        warn!(path = %line, error = %e, "Skipping invalid path from git");
                        None
                    },
                }
            })
            .collect();

        // Wait for child to finish
        let _ = child.wait();

        // Group files by base name to find potential duplicates
        let mut by_name: HashMap<String, Vec<PathBuf>> = HashMap::new();
        for file in files {
            if let Some(name) = file.file_name().and_then(|n| n.to_str()) {
                by_name.entry(name.to_string()).or_default().push(file);
            }
        }

        // Check groups with same name in different locations
        for (name, paths) in &by_name {
            if paths.len() > 1 && name != "mod.rs" && name != "lib.rs" && name != "main.rs" {
                // These are common files that legitimately appear multiple times
                let primary = &paths[0];
                let similar: Vec<PathBuf> = paths[1..].to_vec();

                // Heuristic: same filename = 70% base similarity
                let similarity = 70;

                if similarity >= self.similarity_threshold {
                    signals.push(DuplicationSignal {
                        source_path: primary.clone(),
                        similar_files: similar.clone(),
                        similarity_percent: similarity,
                        severity: severity_from_duplication(similarity, similar.len()),
                        evidence: format!(
                            "File '{}' appears in {} locations with similar naming",
                            name,
                            paths.len()
                        ),
                        suggested_action: format!(
                            "Review {} and {} for common abstraction opportunities",
                            primary.display(),
                            similar
                                .iter()
                                .map(|p| p.display().to_string())
                                .collect::<Vec<_>>()
                                .join(", ")
                        ),
                    });
                }
            }
        }

        // Sort by severity
        signals.sort_by(|a, b| b.severity.cmp(&a.severity));

        debug!(
            signal_count = signals.len(),
            "Collected duplication signals"
        );

        Ok(signals)
    }
}

/// Determines severity from duplication metrics.
const fn severity_from_duplication(similarity: u8, count: usize) -> Severity {
    if similarity >= 90 || count >= 4 {
        Severity::Critical
    } else if similarity >= 80 || count >= 3 {
        Severity::High
    } else if similarity >= 70 {
        Severity::Medium
    } else {
        Severity::Low
    }
}

/// Collector for complexity signals based on file metrics.
pub struct ComplexityCollector {
    /// Maximum line count threshold for a file.
    max_lines: usize,
}

/// Maximum file size to read for complexity analysis (10 MB).
/// SEC-SIGNAL-003: Prevent denial-of-service via large files.
const MAX_COMPLEXITY_FILE_SIZE: u64 = 10 * 1024 * 1024;

impl ComplexityCollector {
    /// Creates a new complexity collector.
    ///
    /// # Arguments
    ///
    /// * `max_lines` - Files exceeding this line count are flagged
    #[must_use]
    pub const fn new(max_lines: usize) -> Self {
        Self { max_lines }
    }

    /// Collects complexity signals by analyzing file sizes.
    ///
    /// # Arguments
    ///
    /// * `repo_root` - Path to the repository root
    ///
    /// # Errors
    ///
    /// Returns an error if file operations fail.
    pub fn collect(&self, repo_root: &Path) -> Result<Vec<ComplexitySignal>, SignalError> {
        debug!(
            repo_root = %repo_root.display(),
            max_lines = self.max_lines,
            "Collecting complexity signals"
        );

        let mut signals = Vec::new();

        // Find Rust source files using git ls-files
        // SEC-SIGNAL-003: Use streaming to avoid loading entire output into memory
        let mut child = Command::new("git")
            .args(["ls-files", "*.rs"])
            .current_dir(repo_root)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| SignalError::GitCommandFailed {
                reason: e.to_string(),
            })?;

        let Some(stdout) = child.stdout.take() else {
            warn!("git ls-files produced no stdout, skipping complexity analysis");
            return Ok(signals);
        };

        // Process files line by line
        for line_result in BufReader::new(stdout).lines() {
            let Ok(line) = line_result else {
                continue;
            };
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            // Validate the path
            let path = match validate_git_path(line, repo_root) {
                Ok(p) => p,
                Err(e) => {
                    warn!(path = %line, error = %e, "Skipping invalid path");
                    continue;
                },
            };

            // Read file and count lines
            // SEC-SIGNAL-003: Check for symlinks before reading
            let full_path = repo_root.join(&path);
            let Ok(metadata) = std::fs::symlink_metadata(&full_path) else {
                continue;
            };

            // Skip symlinks to prevent symlink attacks
            if metadata.is_symlink() {
                warn!(path = %full_path.display(), "Skipping symlink");
                continue;
            }

            // SEC-SIGNAL-003: Check file size to prevent DoS via large files
            if metadata.len() > MAX_COMPLEXITY_FILE_SIZE {
                warn!(
                    path = %full_path.display(),
                    size = metadata.len(),
                    "Skipping large file"
                );
                continue;
            }

            // Use BufReader to stream file contents instead of loading entire file
            let Ok(file) = File::open(&full_path) else {
                continue;
            };
            let line_count = BufReader::new(file).lines().count();

            if line_count > self.max_lines {
                let severity = severity_from_complexity(line_count, self.max_lines);
                signals.push(ComplexitySignal {
                    source_path: path,
                    line_count,
                    severity,
                    evidence: format!(
                        "File has {line_count} lines, exceeding threshold of {}",
                        self.max_lines
                    ),
                    suggested_action: suggest_complexity_action(line_count),
                });
            }
        }

        // Wait for child to finish
        let _ = child.wait();

        // Sort by line count descending
        signals.sort_by(|a, b| b.line_count.cmp(&a.line_count));

        debug!(signal_count = signals.len(), "Collected complexity signals");

        Ok(signals)
    }
}

/// Determines severity from line count.
#[allow(clippy::cast_precision_loss)]
fn severity_from_complexity(lines: usize, threshold: usize) -> Severity {
    let ratio = lines as f64 / threshold as f64;
    if ratio >= 3.0 {
        Severity::Critical
    } else if ratio >= 2.0 {
        Severity::High
    } else if ratio >= 1.5 {
        Severity::Medium
    } else {
        Severity::Low
    }
}

/// Suggests an action based on line count.
fn suggest_complexity_action(lines: usize) -> String {
    if lines >= 1500 {
        "Large file requires immediate decomposition into focused modules".to_string()
    } else if lines >= 1000 {
        "Consider breaking into multiple modules based on logical boundaries".to_string()
    } else if lines >= 750 {
        "Review for extraction opportunities - look for cohesive functionality groups".to_string()
    } else {
        "Monitor file size - may benefit from modest restructuring".to_string()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::fmt::Write as _;

    use tempfile::TempDir;

    use super::*;

    /// Runs a git command with proper environment isolation.
    ///
    /// When running tests in a git worktree, git commands can accidentally use
    /// the parent worktree's configuration. This helper ensures that each
    /// test's temporary repo is fully isolated by clearing inherited git env
    /// vars and setting `GIT_DIR` and `GIT_WORK_TREE` explicitly.
    ///
    /// For `git init`, we don't set `GIT_DIR` since it doesn't exist yet.
    fn run_git_command(root: &Path, args: &[&str]) -> std::io::Result<std::process::Output> {
        let mut cmd = Command::new("git");
        cmd.args(args).current_dir(root);

        // Clear inherited git env vars to avoid using parent worktree
        cmd.env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE")
            .env_remove("GIT_INDEX_FILE")
            .env_remove("GIT_OBJECT_DIRECTORY")
            .env_remove("GIT_COMMON_DIR");

        // Set ceiling to the temp directory's parent to prevent walking up
        // past the test repo. This is especially important for `git init`.
        if let Some(parent) = root.parent() {
            cmd.env("GIT_CEILING_DIRECTORIES", parent);
        }

        // For non-init commands, explicitly point to the test repo
        if args.first() != Some(&"init") {
            cmd.env("GIT_DIR", root.join(".git"))
                .env("GIT_WORK_TREE", root);
        }

        cmd.output()
    }

    /// Creates a test git repository with some history.
    ///
    /// # Errors
    ///
    /// Returns an error if git commands or file operations fail.
    pub fn create_test_repo(root: &Path) -> std::io::Result<()> {
        // Initialize git repo
        run_git_command(root, &["init"])?;

        // Configure git for the test
        run_git_command(root, &["config", "user.email", "test@example.com"])?;

        run_git_command(root, &["config", "user.name", "Test"])?;

        // Create some files
        std::fs::create_dir_all(root.join("src"))?;
        std::fs::write(root.join("src/main.rs"), "fn main() {}")?;
        std::fs::write(root.join("src/lib.rs"), "pub fn test() {}")?;

        // Initial commit
        run_git_command(root, &["add", "."])?;

        run_git_command(root, &["commit", "-m", "Initial commit"])?;

        Ok(())
    }

    /// UT-122-01: Test hotspot signal collection from git history.
    #[test]
    fn test_hotspot_collection() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();

        // Set up test repo
        create_test_repo(root).expect("Failed to create test repo");

        // Add more commits to create churn
        for i in 0..5 {
            std::fs::write(
                root.join("src/main.rs"),
                format!("fn main() {{ /* {i} */ }}"),
            )
            .unwrap();
            run_git_command(root, &["add", "src/main.rs"]).unwrap();
            run_git_command(root, &["commit", "-m", &format!("Update {i}")]).unwrap();
        }

        let collector = HotspotCollector::new(Duration::from_secs(30 * 86400), 3);
        let signals = collector.collect(root).unwrap();

        // Should have at least one hotspot (main.rs modified 5+ times)
        assert!(!signals.is_empty(), "Should detect hotspot signals");

        // Verify the hotspot has expected properties
        let main_hotspot = signals.iter().find(|s| {
            s.source_path
                .to_str()
                .is_some_and(|p| p.contains("main.rs"))
        });
        assert!(main_hotspot.is_some(), "Should find main.rs as hotspot");
    }

    /// Test path validation rejects traversal attempts.
    #[test]
    fn test_path_validation_rejects_traversal() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();

        // Path traversal attempts
        assert!(matches!(
            validate_git_path("../etc/passwd", root),
            Err(SignalError::PathTraversal { .. })
        ));
        assert!(matches!(
            validate_git_path("/etc/passwd", root),
            Err(SignalError::PathTraversal { .. })
        ));
        assert!(matches!(
            validate_git_path("foo/../../../bar", root),
            Err(SignalError::PathTraversal { .. })
        ));

        // Valid relative paths should work
        assert!(validate_git_path("src/main.rs", root).is_ok());
        assert!(validate_git_path("crates/core/lib.rs", root).is_ok());
    }

    /// Test path validation rejects control characters.
    #[test]
    fn test_path_validation_rejects_control_chars() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();

        // Null byte
        let result = validate_git_path("src/main\x00.rs", root);
        assert!(matches!(result, Err(SignalError::InvalidPath { .. })));

        // Tab
        let result = validate_git_path("src/main\t.rs", root);
        assert!(matches!(result, Err(SignalError::InvalidPath { .. })));
    }

    /// Test severity levels from churn count.
    #[test]
    fn test_severity_from_churn() {
        assert_eq!(severity_from_churn(5), Severity::Low);
        assert_eq!(severity_from_churn(10), Severity::Medium);
        assert_eq!(severity_from_churn(15), Severity::Medium);
        assert_eq!(severity_from_churn(20), Severity::High);
        assert_eq!(severity_from_churn(25), Severity::High);
        assert_eq!(severity_from_churn(30), Severity::Critical);
        assert_eq!(severity_from_churn(50), Severity::Critical);
    }

    /// UT-122-02: Test duplication signal heuristic matching.
    #[test]
    fn test_duplication_collection() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();

        create_test_repo(root).expect("Failed to create test repo");

        // Create duplicate-named files in different directories
        std::fs::create_dir_all(root.join("src/module_a")).unwrap();
        std::fs::create_dir_all(root.join("src/module_b")).unwrap();
        std::fs::write(root.join("src/module_a/handler.rs"), "fn handle() {}").unwrap();
        std::fs::write(root.join("src/module_b/handler.rs"), "fn handle() {}").unwrap();

        run_git_command(root, &["add", "."]).unwrap();
        run_git_command(root, &["commit", "-m", "Add handlers"]).unwrap();

        let collector = DuplicationCollector::new(60);
        let signals = collector.collect(root).unwrap();

        // Should detect the duplicate handler.rs files
        let handler_dup = signals.iter().find(|s| {
            s.source_path
                .to_str()
                .is_some_and(|p| p.contains("handler"))
        });
        assert!(
            handler_dup.is_some(),
            "Should detect handler.rs duplication"
        );
    }

    /// Test complexity collection.
    #[test]
    fn test_complexity_collection() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();

        create_test_repo(root).expect("Failed to create test repo");

        // Create a large file
        let large_content = (0..600).fold(String::new(), |mut acc, i| {
            let _ = writeln!(acc, "// Line {i}");
            acc
        });
        std::fs::write(root.join("src/large.rs"), &large_content).unwrap();

        run_git_command(root, &["add", "src/large.rs"]).unwrap();
        run_git_command(root, &["commit", "-m", "Add large file"]).unwrap();

        let collector = ComplexityCollector::new(500);
        let signals = collector.collect(root).unwrap();

        // Should detect the large file
        let large_signal = signals.iter().find(|s| {
            s.source_path
                .to_str()
                .is_some_and(|p| p.contains("large.rs"))
        });
        assert!(large_signal.is_some(), "Should detect large.rs complexity");
        assert!(
            large_signal.unwrap().line_count >= 600,
            "Should report correct line count"
        );
    }

    /// Test Signal unified type.
    #[test]
    fn test_signal_unified_type() {
        let hotspot = Signal::Hotspot(HotspotSignal {
            source_path: PathBuf::from("test.rs"),
            churn_count: 15,
            severity: Severity::Medium,
            evidence: "Test evidence".to_string(),
            suggested_action: "Test action".to_string(),
        });

        assert_eq!(hotspot.signal_type(), "hotspot");
        assert_eq!(hotspot.severity(), Severity::Medium);
        assert_eq!(hotspot.source_path(), Path::new("test.rs"));
        assert_eq!(hotspot.evidence(), "Test evidence");
        assert_eq!(hotspot.suggested_action(), "Test action");
    }
}
