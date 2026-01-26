//! Routing profile parsing and validation.
//!
//! This module provides:
//! - Routing profile YAML parsing
//! - Profile validation against schema constraints
//! - Stage-to-provider configuration mapping
//!
//! # Invariants
//!
//! - [INV-PROFILE-001] Profile IDs are unique within a profile set
//! - [INV-PROFILE-002] All stage configurations have a valid provider
//! - [INV-PROFILE-003] Timeout values are within acceptable bounds
//! - [INV-PROFILE-004] Parsed profiles are immutable after loading

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Read;
use std::path::Path;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::debug;

/// Maximum file size for routing profile files (1 MB).
const MAX_PROFILE_FILE_SIZE: u64 = 1024 * 1024;

/// Minimum timeout in milliseconds.
const MIN_TIMEOUT_MS: u64 = 1000;

/// Maximum timeout in milliseconds (10 minutes).
const MAX_TIMEOUT_MS: u64 = 600_000;

/// Default timeout in milliseconds (30 seconds).
const DEFAULT_TIMEOUT_MS: u64 = 30_000;

/// Default maximum retries.
const DEFAULT_MAX_RETRIES: u32 = 3;

/// Default initial retry delay in milliseconds.
const DEFAULT_INITIAL_DELAY_MS: u64 = 1000;

/// Default backoff multiplier.
const DEFAULT_BACKOFF_MULTIPLIER: f64 = 2.0;

/// Errors that can occur during profile parsing.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ProfileError {
    /// Failed to read profile file.
    #[error("failed to read profile file {path}: {reason}")]
    ReadError {
        /// Path to the file.
        path: String,
        /// Reason for the failure.
        reason: String,
    },

    /// Profile file is too large.
    #[error("profile file {path} is too large ({size} bytes, max {max_size} bytes)")]
    FileTooLarge {
        /// Path to the file.
        path: String,
        /// Actual file size.
        size: u64,
        /// Maximum allowed size.
        max_size: u64,
    },

    /// YAML parsing failed.
    #[error("YAML parsing failed for {path}: {reason}")]
    YamlParseError {
        /// Path to the file.
        path: String,
        /// Reason for the failure.
        reason: String,
    },

    /// Profile not found.
    #[error("routing profile not found: {path}")]
    ProfileNotFound {
        /// The missing path.
        path: String,
    },

    /// Invalid profile ID format.
    #[error("invalid profile ID format: {id} (must match ^[a-z][a-z0-9_-]*$)")]
    InvalidProfileId {
        /// The invalid ID.
        id: String,
    },

    /// Invalid timeout value.
    #[error("invalid timeout for stage {stage}: {value}ms (must be {min}-{max}ms)")]
    InvalidTimeout {
        /// Stage name.
        stage: String,
        /// The invalid value.
        value: u64,
        /// Minimum allowed value.
        min: u64,
        /// Maximum allowed value.
        max: u64,
    },

    /// No stages defined.
    #[error("routing profile {profile_id} has no stages defined")]
    NoStagesDefined {
        /// Profile ID.
        profile_id: String,
    },

    /// Stage not found in profile.
    #[error("stage '{stage}' not found in profile '{profile_id}'")]
    StageNotFound {
        /// Profile ID.
        profile_id: String,
        /// Stage name.
        stage: String,
    },

    /// Path traversal attempt detected.
    #[error("path traversal detected: {path} - {reason}")]
    PathTraversalError {
        /// The path that attempted traversal.
        path: String,
        /// Reason for the failure.
        reason: String,
    },
}

/// Retry policy configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetryPolicy {
    /// Maximum number of retry attempts.
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,

    /// Initial delay before first retry in milliseconds.
    #[serde(default = "default_initial_delay_ms")]
    pub initial_delay_ms: u64,

    /// Multiplier for exponential backoff.
    #[serde(default = "default_backoff_multiplier")]
    pub backoff_multiplier: f64,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: DEFAULT_MAX_RETRIES,
            initial_delay_ms: DEFAULT_INITIAL_DELAY_MS,
            backoff_multiplier: DEFAULT_BACKOFF_MULTIPLIER,
        }
    }
}

const fn default_max_retries() -> u32 {
    DEFAULT_MAX_RETRIES
}

const fn default_initial_delay_ms() -> u64 {
    DEFAULT_INITIAL_DELAY_MS
}

const fn default_backoff_multiplier() -> f64 {
    DEFAULT_BACKOFF_MULTIPLIER
}

/// Provider configuration for a pipeline stage.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderConfig {
    /// Provider identifier (e.g., "local", "anthropic", "openai").
    pub provider: String,

    /// Model identifier (e.g., "claude-3-5-sonnet").
    #[serde(default)]
    pub model: Option<String>,

    /// Custom endpoint URL.
    #[serde(default)]
    pub endpoint: Option<String>,

    /// Request timeout in milliseconds.
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,

    /// Retry policy configuration.
    #[serde(default)]
    pub retry_policy: RetryPolicy,

    /// Stage-specific fallback.
    #[serde(default)]
    pub stage_fallback: Option<StageFallback>,
}

impl Default for ProviderConfig {
    fn default() -> Self {
        Self {
            provider: String::new(),
            model: None,
            endpoint: None,
            timeout_ms: DEFAULT_TIMEOUT_MS,
            retry_policy: RetryPolicy::default(),
            stage_fallback: None,
        }
    }
}

const fn default_timeout_ms() -> u64 {
    DEFAULT_TIMEOUT_MS
}

/// Stage-specific fallback configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StageFallback {
    /// Fallback provider identifier.
    pub provider: String,

    /// Fallback model identifier.
    #[serde(default)]
    pub model: Option<String>,

    /// Fallback timeout in milliseconds.
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
}

/// Global fallback configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GlobalFallback {
    /// Fallback provider identifier.
    pub provider: String,

    /// Fallback model identifier.
    #[serde(default)]
    pub model: Option<String>,

    /// Fallback timeout in milliseconds.
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,

    /// Human-readable reason for fallback usage.
    #[serde(default)]
    pub reason: Option<String>,
}

/// Canary comparison configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanaryConfig {
    /// Whether canary comparison is enabled.
    #[serde(default)]
    pub enabled: bool,

    /// Profile ID of the comparison routing profile.
    #[serde(default)]
    pub comparison_profile: Option<String>,

    /// List of stage names to include in canary comparison.
    #[serde(default)]
    pub stages: Vec<String>,

    /// Whether to generate detailed output diffs.
    #[serde(default = "default_output_diffs")]
    pub output_diffs: bool,
}

impl Default for CanaryConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            comparison_profile: None,
            stages: Vec::new(),
            output_diffs: true,
        }
    }
}

const fn default_output_diffs() -> bool {
    true
}

/// A routing profile defining stage-to-provider mappings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutingProfile {
    /// Unique identifier for this profile.
    pub profile_id: String,

    /// Human-readable description.
    pub description: String,

    /// Profile version (ISO date format).
    #[serde(default = "default_version")]
    pub version: String,

    /// Stage-to-provider mappings.
    pub stages: HashMap<String, ProviderConfig>,

    /// Global fallback configuration.
    #[serde(default)]
    pub fallback: Option<GlobalFallback>,

    /// Canary comparison configuration.
    #[serde(default)]
    pub canary: Option<CanaryConfig>,
}

fn default_version() -> String {
    "2026-01-26".to_string()
}

/// Raw YAML structure for routing profile files.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RoutingProfileYaml {
    routing_profile: RoutingProfile,
}

impl RoutingProfile {
    /// Gets the provider configuration for a stage.
    ///
    /// # Arguments
    ///
    /// * `stage` - The stage name to look up.
    ///
    /// # Returns
    ///
    /// The provider configuration for the stage, or `None` if not found.
    #[must_use]
    pub fn get_stage_config(&self, stage: &str) -> Option<&ProviderConfig> {
        self.stages.get(stage)
    }

    /// Gets all defined stage names.
    #[must_use]
    pub fn stage_names(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.stages.keys().map(String::as_str).collect();
        names.sort_unstable();
        names
    }

    /// Checks if a stage is defined in this profile.
    #[must_use]
    pub fn has_stage(&self, stage: &str) -> bool {
        self.stages.contains_key(stage)
    }

    /// Gets the global fallback configuration, if defined.
    #[must_use]
    pub const fn global_fallback(&self) -> Option<&GlobalFallback> {
        self.fallback.as_ref()
    }

    /// Gets the canary configuration, if defined.
    #[must_use]
    pub const fn canary_config(&self) -> Option<&CanaryConfig> {
        self.canary.as_ref()
    }

    /// Validates the profile against schema constraints.
    ///
    /// # Errors
    ///
    /// Returns an error if validation fails.
    pub fn validate(&self) -> Result<(), ProfileError> {
        // Validate profile ID format
        if !is_valid_profile_id(&self.profile_id) {
            return Err(ProfileError::InvalidProfileId {
                id: self.profile_id.clone(),
            });
        }

        // Validate that stages are defined
        if self.stages.is_empty() {
            return Err(ProfileError::NoStagesDefined {
                profile_id: self.profile_id.clone(),
            });
        }

        // Validate timeout values for all stages
        for (stage_name, config) in &self.stages {
            if config.timeout_ms < MIN_TIMEOUT_MS || config.timeout_ms > MAX_TIMEOUT_MS {
                return Err(ProfileError::InvalidTimeout {
                    stage: stage_name.clone(),
                    value: config.timeout_ms,
                    min: MIN_TIMEOUT_MS,
                    max: MAX_TIMEOUT_MS,
                });
            }

            // Validate stage fallback timeout if present
            if let Some(fallback) = &config.stage_fallback {
                if fallback.timeout_ms < MIN_TIMEOUT_MS || fallback.timeout_ms > MAX_TIMEOUT_MS {
                    return Err(ProfileError::InvalidTimeout {
                        stage: format!("{stage_name}.fallback"),
                        value: fallback.timeout_ms,
                        min: MIN_TIMEOUT_MS,
                        max: MAX_TIMEOUT_MS,
                    });
                }
            }
        }

        // Validate global fallback timeout if present
        if let Some(fallback) = &self.fallback {
            if fallback.timeout_ms < MIN_TIMEOUT_MS || fallback.timeout_ms > MAX_TIMEOUT_MS {
                return Err(ProfileError::InvalidTimeout {
                    stage: "fallback".to_string(),
                    value: fallback.timeout_ms,
                    min: MIN_TIMEOUT_MS,
                    max: MAX_TIMEOUT_MS,
                });
            }
        }

        Ok(())
    }
}

/// Validates that a profile ID matches the expected format.
fn is_valid_profile_id(id: &str) -> bool {
    if id.is_empty() || id.len() > 64 {
        return false;
    }

    let mut chars = id.chars();
    match chars.next() {
        Some(c) if c.is_ascii_lowercase() => {},
        _ => return false,
    }

    chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
}

/// Validates that a path doesn't contain traversal characters.
fn validate_profile_path(path: &str) -> Result<(), ProfileError> {
    if path.contains("..") || path.contains('\0') {
        return Err(ProfileError::PathTraversalError {
            path: path.to_string(),
            reason: "path contains invalid characters".to_string(),
        });
    }
    Ok(())
}

/// Reads a file with size limits.
fn read_file_bounded(path: &Path, max_size: u64) -> Result<String, ProfileError> {
    let metadata = fs::metadata(path).map_err(|e| ProfileError::ReadError {
        path: path.display().to_string(),
        reason: e.to_string(),
    })?;

    let size = metadata.len();
    if size > max_size {
        return Err(ProfileError::FileTooLarge {
            path: path.display().to_string(),
            size,
            max_size,
        });
    }

    let file = File::open(path).map_err(|e| ProfileError::ReadError {
        path: path.display().to_string(),
        reason: e.to_string(),
    })?;

    let mut content = String::new();
    file.take(max_size)
        .read_to_string(&mut content)
        .map_err(|e| ProfileError::ReadError {
            path: path.display().to_string(),
            reason: e.to_string(),
        })?;

    Ok(content)
}

/// Loads a routing profile from a YAML file.
///
/// # Arguments
///
/// * `path` - Path to the routing profile YAML file.
///
/// # Returns
///
/// The parsed and validated routing profile.
///
/// # Errors
///
/// Returns an error if:
/// - The file doesn't exist
/// - The file is too large
/// - YAML parsing fails
/// - Validation fails
pub fn load_profile(path: &Path) -> Result<RoutingProfile, ProfileError> {
    validate_profile_path(&path.display().to_string())?;

    if !path.exists() {
        return Err(ProfileError::ProfileNotFound {
            path: path.display().to_string(),
        });
    }

    debug!(path = %path.display(), "Loading routing profile");

    let content = read_file_bounded(path, MAX_PROFILE_FILE_SIZE)?;

    let profile_yaml: RoutingProfileYaml =
        serde_yaml::from_str(&content).map_err(|e| ProfileError::YamlParseError {
            path: path.display().to_string(),
            reason: e.to_string(),
        })?;

    let profile = profile_yaml.routing_profile;
    profile.validate()?;

    debug!(profile_id = %profile.profile_id, "Routing profile loaded successfully");

    Ok(profile)
}

/// Loads a routing profile by ID from the standard profiles directory.
///
/// # Arguments
///
/// * `repo_root` - Path to the repository root.
/// * `profile_id` - The profile ID to load.
///
/// # Returns
///
/// The parsed and validated routing profile.
///
/// # Errors
///
/// Returns an error if the profile doesn't exist or fails validation.
pub fn load_profile_by_id(
    repo_root: &Path,
    profile_id: &str,
) -> Result<RoutingProfile, ProfileError> {
    // Validate profile ID format first
    if !is_valid_profile_id(profile_id) {
        return Err(ProfileError::InvalidProfileId {
            id: profile_id.to_string(),
        });
    }

    let profile_path = repo_root
        .join("documents")
        .join("standards")
        .join("routing_profiles")
        .join(format!("{profile_id}.yaml"));

    load_profile(&profile_path)
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    /// Creates a test routing profile file.
    fn create_test_profile(dir: &Path, content: &str) -> std::path::PathBuf {
        let path = dir.join("test.yaml");
        fs::write(&path, content).unwrap();
        path
    }

    /// UT-118-01: Test valid routing profile parsing.
    #[test]
    fn test_load_valid_profile() {
        let temp_dir = TempDir::new().unwrap();
        let content = r#"
routing_profile:
  profile_id: test-local
  description: Test routing profile for local development.
  version: "2026-01-26"
  stages:
    ccp_build:
      provider: local
      timeout_ms: 30000
    impact_map:
      provider: anthropic
      model: claude-3-5-sonnet
      timeout_ms: 60000
  fallback:
    provider: local
    timeout_ms: 30000
    reason: Fallback to local when remote unavailable.
"#;
        let path = create_test_profile(temp_dir.path(), content);
        let profile = load_profile(&path).unwrap();

        assert_eq!(profile.profile_id, "test-local");
        assert_eq!(profile.stages.len(), 2);
        assert!(profile.has_stage("ccp_build"));
        assert!(profile.has_stage("impact_map"));

        let ccp_config = profile.get_stage_config("ccp_build").unwrap();
        assert_eq!(ccp_config.provider, "local");
        assert_eq!(ccp_config.timeout_ms, 30000);

        let impact_config = profile.get_stage_config("impact_map").unwrap();
        assert_eq!(impact_config.provider, "anthropic");
        assert_eq!(impact_config.model, Some("claude-3-5-sonnet".to_string()));
    }

    /// UT-118-01: Test profile with retry policy.
    #[test]
    fn test_profile_with_retry_policy() {
        let temp_dir = TempDir::new().unwrap();
        let content = r"
routing_profile:
  profile_id: retry-test
  description: Profile with custom retry policy.
  stages:
    test_stage:
      provider: anthropic
      model: claude-3-5-sonnet
      timeout_ms: 60000
      retry_policy:
        max_retries: 5
        initial_delay_ms: 2000
        backoff_multiplier: 3.0
";
        let path = create_test_profile(temp_dir.path(), content);
        let profile = load_profile(&path).unwrap();

        let config = profile.get_stage_config("test_stage").unwrap();
        assert_eq!(config.retry_policy.max_retries, 5);
        assert_eq!(config.retry_policy.initial_delay_ms, 2000);
        assert!((config.retry_policy.backoff_multiplier - 3.0).abs() < f64::EPSILON);
    }

    /// UT-118-01: Test profile with stage fallback.
    #[test]
    fn test_profile_with_stage_fallback() {
        let temp_dir = TempDir::new().unwrap();
        let content = r"
routing_profile:
  profile_id: fallback-test
  description: Profile with stage-specific fallback.
  stages:
    test_stage:
      provider: anthropic
      model: claude-3-5-sonnet
      timeout_ms: 60000
      stage_fallback:
        provider: local
        timeout_ms: 30000
";
        let path = create_test_profile(temp_dir.path(), content);
        let profile = load_profile(&path).unwrap();

        let config = profile.get_stage_config("test_stage").unwrap();
        let fallback = config.stage_fallback.as_ref().unwrap();
        assert_eq!(fallback.provider, "local");
        assert_eq!(fallback.timeout_ms, 30000);
    }

    /// UT-118-01: Test profile with canary configuration.
    #[test]
    fn test_profile_with_canary() {
        let temp_dir = TempDir::new().unwrap();
        let content = r"
routing_profile:
  profile_id: canary-test
  description: Profile with canary configuration.
  stages:
    test_stage:
      provider: anthropic
      model: claude-3-5-sonnet
      timeout_ms: 60000
  canary:
    enabled: true
    comparison_profile: production
    stages:
      - test_stage
    output_diffs: true
";
        let path = create_test_profile(temp_dir.path(), content);
        let profile = load_profile(&path).unwrap();

        let canary = profile.canary_config().unwrap();
        assert!(canary.enabled);
        assert_eq!(canary.comparison_profile, Some("production".to_string()));
        assert_eq!(canary.stages, vec!["test_stage"]);
        assert!(canary.output_diffs);
    }

    /// UT-118-02: Test invalid profile ID format.
    #[test]
    fn test_invalid_profile_id() {
        let temp_dir = TempDir::new().unwrap();
        let content = r"
routing_profile:
  profile_id: INVALID_ID
  description: Profile with invalid ID format.
  stages:
    test:
      provider: local
      timeout_ms: 30000
";
        let path = create_test_profile(temp_dir.path(), content);
        let result = load_profile(&path);

        assert!(matches!(result, Err(ProfileError::InvalidProfileId { .. })));
    }

    /// UT-118-02: Test profile with no stages.
    #[test]
    fn test_no_stages_defined() {
        let temp_dir = TempDir::new().unwrap();
        let content = r"
routing_profile:
  profile_id: empty-profile
  description: Profile with no stages.
  stages: {}
";
        let path = create_test_profile(temp_dir.path(), content);
        let result = load_profile(&path);

        assert!(matches!(result, Err(ProfileError::NoStagesDefined { .. })));
    }

    /// UT-118-02: Test invalid timeout value.
    #[test]
    fn test_invalid_timeout() {
        let temp_dir = TempDir::new().unwrap();
        let content = r"
routing_profile:
  profile_id: timeout-test
  description: Profile with invalid timeout.
  stages:
    test:
      provider: local
      timeout_ms: 100
";
        let path = create_test_profile(temp_dir.path(), content);
        let result = load_profile(&path);

        assert!(matches!(result, Err(ProfileError::InvalidTimeout { .. })));
    }

    /// UT-118-02: Test profile not found.
    #[test]
    fn test_profile_not_found() {
        let result = load_profile(Path::new("/nonexistent/profile.yaml"));
        assert!(matches!(result, Err(ProfileError::ProfileNotFound { .. })));
    }

    /// Test valid profile ID formats.
    #[test]
    fn test_valid_profile_ids() {
        assert!(is_valid_profile_id("local"));
        assert!(is_valid_profile_id("local-dev"));
        assert!(is_valid_profile_id("local_dev"));
        assert!(is_valid_profile_id("local123"));
        assert!(is_valid_profile_id("a"));
        // Invalid cases
        assert!(!is_valid_profile_id(""));
        assert!(!is_valid_profile_id("Local")); // uppercase
        assert!(!is_valid_profile_id("123local")); // starts with number
        assert!(!is_valid_profile_id("-local")); // starts with hyphen
        assert!(!is_valid_profile_id("local.dev")); // contains dot
    }

    /// Test `stage_names` returns sorted list.
    #[test]
    fn test_stage_names_sorted() {
        let temp_dir = TempDir::new().unwrap();
        let content = r"
routing_profile:
  profile_id: sorted-test
  description: Test stage name sorting.
  stages:
    zebra:
      provider: local
      timeout_ms: 30000
    alpha:
      provider: local
      timeout_ms: 30000
    middle:
      provider: local
      timeout_ms: 30000
";
        let path = create_test_profile(temp_dir.path(), content);
        let profile = load_profile(&path).unwrap();

        let names = profile.stage_names();
        assert_eq!(names, vec!["alpha", "middle", "zebra"]);
    }

    /// Test default values are applied.
    #[test]
    fn test_default_values() {
        let temp_dir = TempDir::new().unwrap();
        let content = r"
routing_profile:
  profile_id: defaults-test
  description: Test default value application.
  stages:
    minimal:
      provider: local
";
        let path = create_test_profile(temp_dir.path(), content);
        let profile = load_profile(&path).unwrap();

        let config = profile.get_stage_config("minimal").unwrap();
        assert_eq!(config.timeout_ms, DEFAULT_TIMEOUT_MS);
        assert_eq!(config.retry_policy.max_retries, DEFAULT_MAX_RETRIES);
        assert_eq!(
            config.retry_policy.initial_delay_ms,
            DEFAULT_INITIAL_DELAY_MS
        );
        assert!(
            (config.retry_policy.backoff_multiplier - DEFAULT_BACKOFF_MULTIPLIER).abs()
                < f64::EPSILON
        );
    }
}
