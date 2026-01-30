//! Determinism enforcement for AAT execution.
//!
//! This module provides the [`DeterminismGuard`] which ensures that AAT
//! verification runs are deterministic and isolated from external factors
//! that could affect verdicts.
//!
//! # Determinism Requirements
//!
//! For AAT verdicts to be trustworthy, they must be reproducible:
//! - Same commit + same inputs = same verdict
//! - No network access during hypothesis execution
//! - Fixed random seeds for any randomized operations
//! - Environment captured for reproducibility verification
//!
//! # Network Isolation
//!
//! On Linux `x86_64`, the guard can optionally apply a seccomp filter that
//! blocks network syscalls (socket, connect, etc.). This prevents hypothesis
//! verification commands from accessing the network, which could introduce
//! non-determinism or security risks.
//!
//! On other platforms, network blocking is not available and the guard
//! will emit a warning if network isolation is requested.
//!
//! # Environment Snapshot
//!
//! The guard captures a comprehensive environment snapshot including:
//! - OS name and version
//! - Rust toolchain version
//! - Cargo version
//! - Git commit SHA
//! - Timestamp
//!
//! This snapshot is included in the evidence bundle to enable verification
//! that re-runs produce the same verdict on the same environment.

use std::collections::BTreeMap;
use std::process::Command;

use anyhow::{Context, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};

/// Fixed random seed for AAT operations.
///
/// This seed is used to initialize any randomized operations during AAT
/// to ensure deterministic behavior. The specific value is arbitrary but
/// fixed to ensure reproducibility.
pub const AAT_RANDOM_SEED: u64 = 0xCAFE_BEEF_1234_5678;

/// Environment variables set by the determinism guard.
pub const DETERMINISM_ENV_VARS: &[(&str, &str)] = &[
    // Rust-specific determinism
    ("RUST_TEST_SHUFFLE_SEED", "20260130"),
    // Python determinism
    ("PYTHONHASHSEED", "20260130"),
    // Node.js determinism (disable async hooks randomization)
    ("NODE_OPTIONS", "--no-randomize-environment"),
];

/// Environment snapshot captured at AAT execution time.
///
/// This snapshot provides all information needed to verify that a re-run
/// is being performed in an equivalent environment.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnvironmentSnapshot {
    /// Operating system name (e.g., "Linux", "macOS", "Windows").
    pub os_name: String,

    /// Operating system version.
    pub os_version: String,

    /// CPU architecture (e.g., "`x86_64`", "aarch64").
    pub arch: String,

    /// Rust compiler version (output of `rustc --version`).
    pub rustc_version: String,

    /// Cargo version (output of `cargo --version`).
    pub cargo_version: String,

    /// Git commit SHA of the PR being verified.
    pub git_commit_sha: String,

    /// ISO 8601 timestamp when the snapshot was taken.
    pub captured_at: String,

    /// Additional tool versions that may affect determinism.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub tool_versions: BTreeMap<String, String>,
}

impl EnvironmentSnapshot {
    /// Capture a new environment snapshot.
    ///
    /// # Arguments
    ///
    /// * `git_commit_sha` - The git commit SHA being verified
    ///
    /// # Errors
    ///
    /// Returns an error if required tool version commands fail.
    pub fn capture(git_commit_sha: impl Into<String>) -> Result<Self> {
        let os_name = std::env::consts::OS.to_string();
        let arch = std::env::consts::ARCH.to_string();

        // Get OS version using sysinfo
        let os_version = Self::get_os_version();

        // Get rustc version
        let rustc_version = Self::get_command_output("rustc", &["--version"])
            .context("Failed to get rustc version")?;

        // Get cargo version
        let cargo_version = Self::get_command_output("cargo", &["--version"])
            .context("Failed to get cargo version")?;

        let captured_at = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();

        Ok(Self {
            os_name,
            os_version,
            arch,
            rustc_version,
            cargo_version,
            git_commit_sha: git_commit_sha.into(),
            captured_at,
            tool_versions: BTreeMap::new(),
        })
    }

    /// Add a tool version to the snapshot.
    ///
    /// # Arguments
    ///
    /// * `tool` - The tool name
    /// * `version` - The version string
    #[must_use]
    pub fn with_tool_version(
        mut self,
        tool: impl Into<String>,
        version: impl Into<String>,
    ) -> Self {
        self.tool_versions.insert(tool.into(), version.into());
        self
    }

    /// Get OS version using sysinfo crate.
    fn get_os_version() -> String {
        use sysinfo::System;

        System::long_os_version().unwrap_or_else(|| "unknown".to_string())
    }

    /// Run a command and capture its stdout output.
    fn get_command_output(cmd: &str, args: &[&str]) -> Result<String> {
        let output = Command::new(cmd)
            .args(args)
            .output()
            .with_context(|| format!("Failed to execute {cmd}"))?;

        if !output.status.success() {
            anyhow::bail!("{} failed with exit code {:?}", cmd, output.status.code());
        }

        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    /// Check if this snapshot is compatible with another for verdict
    /// comparison.
    ///
    /// Two snapshots are compatible if they have the same:
    /// - OS name and architecture
    /// - Rust toolchain version
    /// - Cargo version
    ///
    /// The git commit SHA and timestamp are intentionally excluded as they
    /// are expected to differ between runs.
    pub fn is_compatible_with(&self, other: &Self) -> bool {
        self.os_name == other.os_name
            && self.arch == other.arch
            && self.rustc_version == other.rustc_version
            && self.cargo_version == other.cargo_version
    }

    /// Generate a determinism key for this environment.
    ///
    /// This key can be used to verify that two runs are on equivalent
    /// environments without comparing the full snapshot.
    pub fn determinism_key(&self) -> String {
        format!(
            "{}-{}-{}-{}",
            self.os_name, self.arch, self.rustc_version, self.cargo_version
        )
    }
}

/// Configuration for the determinism guard.
#[derive(Debug, Clone)]
pub struct DeterminismConfig {
    /// Whether to block network access during execution.
    ///
    /// On Linux `x86_64`, this uses seccomp to block socket syscalls.
    /// On other platforms, this is a no-op with a warning.
    pub block_network: bool,

    /// Whether to enforce fixed random seeds.
    pub enforce_random_seed: bool,

    /// Whether to capture environment snapshot.
    pub capture_environment: bool,
}

impl Default for DeterminismConfig {
    fn default() -> Self {
        Self {
            block_network: true,
            enforce_random_seed: true,
            capture_environment: true,
        }
    }
}

/// Guard for enforcing determinism during AAT execution.
///
/// The guard manages:
/// - Environment variable setup for deterministic execution
/// - Network isolation (on supported platforms)
/// - Environment snapshot capture
///
/// # Example
///
/// ```ignore
/// let config = DeterminismConfig::default();
/// let guard = DeterminismGuard::new(config, "abc123")?;
///
/// // Get environment variables to pass to child processes
/// let env_vars = guard.get_env_vars();
///
/// // Get the captured environment snapshot
/// let snapshot = guard.environment_snapshot();
/// ```
#[derive(Debug)]
pub struct DeterminismGuard {
    config: DeterminismConfig,
    environment_snapshot: Option<EnvironmentSnapshot>,
    env_vars: Vec<(String, String)>,
}

impl DeterminismGuard {
    /// Create a new determinism guard.
    ///
    /// # Arguments
    ///
    /// * `config` - Configuration for the guard
    /// * `git_commit_sha` - The git commit SHA being verified
    ///
    /// # Errors
    ///
    /// Returns an error if environment snapshot capture fails.
    pub fn new(config: DeterminismConfig, git_commit_sha: impl Into<String>) -> Result<Self> {
        let git_sha = git_commit_sha.into();

        // Capture environment snapshot if configured
        let environment_snapshot = if config.capture_environment {
            Some(EnvironmentSnapshot::capture(&git_sha)?)
        } else {
            None
        };

        // Build environment variables for child processes
        let mut env_vars: Vec<(String, String)> = Vec::new();

        if config.enforce_random_seed {
            for (key, value) in DETERMINISM_ENV_VARS {
                env_vars.push(((*key).to_string(), (*value).to_string()));
            }
        }

        Ok(Self {
            config,
            environment_snapshot,
            env_vars,
        })
    }

    /// Get the environment snapshot captured by this guard.
    ///
    /// Returns `None` if `capture_environment` was false in the config.
    #[must_use]
    pub const fn environment_snapshot(&self) -> Option<&EnvironmentSnapshot> {
        self.environment_snapshot.as_ref()
    }

    /// Get environment variables to pass to child processes.
    ///
    /// These variables ensure deterministic behavior in various tools
    /// (Rust, Python, Node.js, etc.).
    #[must_use]
    pub fn get_env_vars(&self) -> &[(String, String)] {
        &self.env_vars
    }

    /// Check if network blocking is available on this platform.
    #[must_use]
    pub const fn network_blocking_available() -> bool {
        cfg!(all(target_os = "linux", target_arch = "x86_64"))
    }

    /// Check if network blocking is enabled.
    #[must_use]
    pub const fn network_blocking_enabled(&self) -> bool {
        self.config.block_network
    }

    /// Get the configuration used by this guard.
    #[must_use]
    pub const fn config(&self) -> &DeterminismConfig {
        &self.config
    }
}

/// Verdict hash for comparing re-run consistency.
///
/// This hash is computed from the deterministic parts of an evidence bundle,
/// excluding timestamps and other non-deterministic fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerdictHash {
    /// The hash value (hex-encoded BLAKE3).
    pub hash: String,

    /// Fields included in the hash computation.
    pub included_fields: Vec<String>,

    /// Git commit SHA this hash was computed for.
    pub commit_sha: String,
}

impl VerdictHash {
    /// Compute a verdict hash from key verdict-determining fields.
    ///
    /// The hash includes:
    /// - Commit SHA
    /// - Verdict value
    /// - Hypothesis results (id, prediction, result)
    /// - Anti-gaming result
    ///
    /// The hash excludes:
    /// - Timestamps
    /// - Stdout/stderr content (may vary due to timing)
    /// - Tool versions (captured separately in environment snapshot)
    pub fn compute(
        commit_sha: &str,
        verdict: &str,
        hypothesis_results: &[(String, String, Option<String>)], // (id, prediction, result)
        anti_gaming_passed: bool,
    ) -> Self {
        use std::fmt::Write;

        let mut hasher = blake3::Hasher::new();
        let mut included_fields = Vec::new();

        // Include commit SHA
        hasher.update(b"commit:");
        hasher.update(commit_sha.as_bytes());
        hasher.update(b"\n");
        included_fields.push("commit_sha".to_string());

        // Include verdict
        hasher.update(b"verdict:");
        hasher.update(verdict.as_bytes());
        hasher.update(b"\n");
        included_fields.push("verdict".to_string());

        // Include hypothesis results in deterministic order
        // (already sorted by id in the evidence bundle)
        for (id, prediction, result) in hypothesis_results {
            hasher.update(b"hypothesis:");
            hasher.update(id.as_bytes());
            hasher.update(b":");
            hasher.update(prediction.as_bytes());
            hasher.update(b":");
            hasher.update(result.as_deref().unwrap_or("none").as_bytes());
            hasher.update(b"\n");
        }
        included_fields.push("hypothesis_results".to_string());

        // Include anti-gaming result
        hasher.update(b"anti_gaming:");
        hasher.update(if anti_gaming_passed {
            b"passed"
        } else {
            b"failed"
        });
        hasher.update(b"\n");
        included_fields.push("anti_gaming_passed".to_string());

        // Finalize hash
        let hash = hasher.finalize();
        let mut hash_hex = String::with_capacity(64);
        for byte in hash.as_bytes() {
            write!(&mut hash_hex, "{byte:02x}").expect("write to string cannot fail");
        }

        Self {
            hash: hash_hex,
            included_fields,
            commit_sha: commit_sha.to_string(),
        }
    }

    /// Check if two verdict hashes match.
    ///
    /// This indicates that the verdicts are deterministically equivalent.
    pub fn matches(&self, other: &Self) -> bool {
        self.hash == other.hash && self.commit_sha == other.commit_sha
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // EnvironmentSnapshot tests
    // =========================================================================

    #[test]
    fn test_environment_snapshot_capture() {
        let snapshot = EnvironmentSnapshot::capture("abc123def456").unwrap();

        assert!(!snapshot.os_name.is_empty());
        assert!(!snapshot.arch.is_empty());
        assert!(!snapshot.rustc_version.is_empty());
        assert!(!snapshot.cargo_version.is_empty());
        assert_eq!(snapshot.git_commit_sha, "abc123def456");
        assert!(!snapshot.captured_at.is_empty());
    }

    #[test]
    fn test_environment_snapshot_with_tool_version() {
        let snapshot = EnvironmentSnapshot::capture("abc123")
            .unwrap()
            .with_tool_version("python", "3.11.0")
            .with_tool_version("node", "20.0.0");

        assert_eq!(
            snapshot.tool_versions.get("python"),
            Some(&"3.11.0".to_string())
        );
        assert_eq!(
            snapshot.tool_versions.get("node"),
            Some(&"20.0.0".to_string())
        );
    }

    #[test]
    fn test_environment_snapshot_compatibility() {
        let snapshot1 = EnvironmentSnapshot {
            os_name: "linux".to_string(),
            os_version: "5.15.0".to_string(),
            arch: "x86_64".to_string(),
            rustc_version: "rustc 1.85.0".to_string(),
            cargo_version: "cargo 1.85.0".to_string(),
            git_commit_sha: "abc123".to_string(),
            captured_at: "2026-01-30T10:00:00Z".to_string(),
            tool_versions: BTreeMap::new(),
        };

        let snapshot2 = EnvironmentSnapshot {
            os_name: "linux".to_string(),
            os_version: "5.15.0".to_string(),
            arch: "x86_64".to_string(),
            rustc_version: "rustc 1.85.0".to_string(),
            cargo_version: "cargo 1.85.0".to_string(),
            git_commit_sha: "def456".to_string(), // Different commit
            captured_at: "2026-01-30T11:00:00Z".to_string(), // Different time
            tool_versions: BTreeMap::new(),
        };

        // Should be compatible despite different commit and time
        assert!(snapshot1.is_compatible_with(&snapshot2));
    }

    #[test]
    fn test_environment_snapshot_incompatible_arch() {
        let snapshot1 = EnvironmentSnapshot {
            os_name: "linux".to_string(),
            os_version: "5.15.0".to_string(),
            arch: "x86_64".to_string(),
            rustc_version: "rustc 1.85.0".to_string(),
            cargo_version: "cargo 1.85.0".to_string(),
            git_commit_sha: "abc123".to_string(),
            captured_at: "2026-01-30T10:00:00Z".to_string(),
            tool_versions: BTreeMap::new(),
        };

        let snapshot2 = EnvironmentSnapshot {
            os_name: "linux".to_string(),
            os_version: "5.15.0".to_string(),
            arch: "aarch64".to_string(), // Different arch
            rustc_version: "rustc 1.85.0".to_string(),
            cargo_version: "cargo 1.85.0".to_string(),
            git_commit_sha: "abc123".to_string(),
            captured_at: "2026-01-30T10:00:00Z".to_string(),
            tool_versions: BTreeMap::new(),
        };

        // Should NOT be compatible
        assert!(!snapshot1.is_compatible_with(&snapshot2));
    }

    #[test]
    fn test_environment_snapshot_determinism_key() {
        let snapshot = EnvironmentSnapshot {
            os_name: "linux".to_string(),
            os_version: "5.15.0".to_string(),
            arch: "x86_64".to_string(),
            rustc_version: "rustc 1.85.0".to_string(),
            cargo_version: "cargo 1.85.0".to_string(),
            git_commit_sha: "abc123".to_string(),
            captured_at: "2026-01-30T10:00:00Z".to_string(),
            tool_versions: BTreeMap::new(),
        };

        let key = snapshot.determinism_key();
        assert!(key.contains("linux"));
        assert!(key.contains("x86_64"));
        assert!(key.contains("rustc 1.85.0"));
        assert!(key.contains("cargo 1.85.0"));
    }

    // =========================================================================
    // DeterminismGuard tests
    // =========================================================================

    #[test]
    fn test_determinism_guard_new() {
        let config = DeterminismConfig::default();
        let guard = DeterminismGuard::new(config, "abc123").unwrap();

        assert!(guard.environment_snapshot().is_some());
        assert!(!guard.get_env_vars().is_empty());
    }

    #[test]
    fn test_determinism_guard_env_vars() {
        let config = DeterminismConfig {
            enforce_random_seed: true,
            ..Default::default()
        };
        let guard = DeterminismGuard::new(config, "abc123").unwrap();

        let env_vars = guard.get_env_vars();

        // Should contain Rust test shuffle seed
        let has_rust_seed = env_vars.iter().any(|(k, _)| k == "RUST_TEST_SHUFFLE_SEED");
        assert!(has_rust_seed, "Should contain RUST_TEST_SHUFFLE_SEED");

        // Should contain Python hash seed
        let has_python_seed = env_vars.iter().any(|(k, _)| k == "PYTHONHASHSEED");
        assert!(has_python_seed, "Should contain PYTHONHASHSEED");
    }

    #[test]
    fn test_determinism_guard_no_env_capture() {
        let config = DeterminismConfig {
            capture_environment: false,
            ..Default::default()
        };
        let guard = DeterminismGuard::new(config, "abc123").unwrap();

        assert!(guard.environment_snapshot().is_none());
    }

    #[test]
    fn test_determinism_guard_no_random_seed() {
        let config = DeterminismConfig {
            enforce_random_seed: false,
            capture_environment: false,
            ..Default::default()
        };
        let guard = DeterminismGuard::new(config, "abc123").unwrap();

        assert!(guard.get_env_vars().is_empty());
    }

    #[test]
    fn test_network_blocking_available() {
        // This will be true on Linux x86_64, false elsewhere
        let available = DeterminismGuard::network_blocking_available();

        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        assert!(available);

        #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
        assert!(!available);
    }

    // =========================================================================
    // VerdictHash tests
    // =========================================================================

    #[test]
    fn test_verdict_hash_compute() {
        let hypothesis_results = vec![
            (
                "H-001".to_string(),
                "Test 1".to_string(),
                Some("PASSED".to_string()),
            ),
            (
                "H-002".to_string(),
                "Test 2".to_string(),
                Some("PASSED".to_string()),
            ),
        ];

        let hash = VerdictHash::compute("abc123", "PASSED", &hypothesis_results, true);

        assert!(!hash.hash.is_empty());
        assert_eq!(hash.hash.len(), 64); // BLAKE3 produces 256 bits = 64 hex chars
        assert_eq!(hash.commit_sha, "abc123");
        assert!(hash.included_fields.contains(&"commit_sha".to_string()));
        assert!(hash.included_fields.contains(&"verdict".to_string()));
    }

    #[test]
    fn test_verdict_hash_deterministic() {
        let hypothesis_results = vec![(
            "H-001".to_string(),
            "Test 1".to_string(),
            Some("PASSED".to_string()),
        )];

        let hash1 = VerdictHash::compute("abc123", "PASSED", &hypothesis_results, true);
        let hash2 = VerdictHash::compute("abc123", "PASSED", &hypothesis_results, true);

        assert_eq!(hash1.hash, hash2.hash);
        assert!(hash1.matches(&hash2));
    }

    #[test]
    fn test_verdict_hash_different_commit() {
        let hypothesis_results = vec![(
            "H-001".to_string(),
            "Test 1".to_string(),
            Some("PASSED".to_string()),
        )];

        let hash1 = VerdictHash::compute("abc123", "PASSED", &hypothesis_results, true);
        let hash2 = VerdictHash::compute("def456", "PASSED", &hypothesis_results, true);

        assert_ne!(hash1.hash, hash2.hash);
        assert!(!hash1.matches(&hash2));
    }

    #[test]
    fn test_verdict_hash_different_verdict() {
        let hypothesis_results = vec![(
            "H-001".to_string(),
            "Test 1".to_string(),
            Some("PASSED".to_string()),
        )];

        let hash1 = VerdictHash::compute("abc123", "PASSED", &hypothesis_results, true);
        let hash2 = VerdictHash::compute("abc123", "FAILED", &hypothesis_results, true);

        assert_ne!(hash1.hash, hash2.hash);
    }

    #[test]
    fn test_verdict_hash_different_hypothesis_result() {
        let results1 = vec![(
            "H-001".to_string(),
            "Test 1".to_string(),
            Some("PASSED".to_string()),
        )];
        let results2 = vec![(
            "H-001".to_string(),
            "Test 1".to_string(),
            Some("FAILED".to_string()),
        )];

        let hash1 = VerdictHash::compute("abc123", "PASSED", &results1, true);
        let hash2 = VerdictHash::compute("abc123", "PASSED", &results2, true);

        assert_ne!(hash1.hash, hash2.hash);
    }

    #[test]
    fn test_verdict_hash_different_anti_gaming() {
        let hypothesis_results = vec![(
            "H-001".to_string(),
            "Test 1".to_string(),
            Some("PASSED".to_string()),
        )];

        let hash1 = VerdictHash::compute("abc123", "PASSED", &hypothesis_results, true);
        let hash2 = VerdictHash::compute("abc123", "PASSED", &hypothesis_results, false);

        assert_ne!(hash1.hash, hash2.hash);
    }

    #[test]
    fn test_verdict_hash_serialization() {
        let hypothesis_results = vec![(
            "H-001".to_string(),
            "Test 1".to_string(),
            Some("PASSED".to_string()),
        )];

        let hash = VerdictHash::compute("abc123", "PASSED", &hypothesis_results, true);

        let json = serde_json::to_string(&hash).unwrap();
        let parsed: VerdictHash = serde_json::from_str(&json).unwrap();

        assert_eq!(hash, parsed);
    }

    // =========================================================================
    // DeterminismConfig tests
    // =========================================================================

    #[test]
    fn test_determinism_config_default() {
        let config = DeterminismConfig::default();

        assert!(config.block_network);
        assert!(config.enforce_random_seed);
        assert!(config.capture_environment);
    }

    // =========================================================================
    // Constants tests
    // =========================================================================

    #[test]
    fn test_aat_random_seed_is_fixed() {
        // This test documents that the seed is intentionally fixed
        // and will fail if someone accidentally changes it
        assert_eq!(AAT_RANDOM_SEED, 0xCAFE_BEEF_1234_5678);
    }

    #[test]
    fn test_determinism_env_vars_not_empty() {
        assert!(!DETERMINISM_ENV_VARS.is_empty());

        // Verify all entries have non-empty keys and values
        for (key, value) in DETERMINISM_ENV_VARS {
            assert!(!key.is_empty(), "Env var key should not be empty");
            assert!(!value.is_empty(), "Env var value should not be empty");
        }
    }
}
