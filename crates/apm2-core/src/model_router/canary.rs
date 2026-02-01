#![allow(clippy::disallowed_methods)] // Metadata/observability usage or adapter.
//! Canary comparison mode for A/B testing routing configurations.
//!
//! This module provides:
//! - `CanaryRunner` that executes same input through two routes
//! - Diff generation between outputs
//! - Structured canary reports with timing and differences
//!
//! # Design Philosophy
//!
//! Canary mode is opt-in and runs both routes sequentially. This allows
//! comparison of outputs between two routing configurations (e.g., comparing
//! a new model against the current production model) without affecting
//! production traffic.
//!
//! # Invariants
//!
//! - [INV-CANARY-001] Both routes are executed sequentially (not parallel)
//! - [INV-CANARY-002] Timing is captured independently for each route
//! - [INV-CANARY-003] Diffs are generated only if `output_diffs` is enabled
//! - [INV-CANARY-004] Canary reports include all metadata for reproducibility

use std::collections::HashMap;
use std::path::Path;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{info, warn};

use super::profile::{
    CanaryConfig, ProfileError, ProviderConfig, RoutingProfile, load_profile_by_id,
};
use super::router::{DefaultProviderAvailability, ModelRouter, RouterError};

/// Errors that can occur during canary comparison.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CanaryError {
    /// Router error.
    #[error("{0}")]
    Router(#[from] RouterError),

    /// Profile error.
    #[error("{0}")]
    Profile(#[from] ProfileError),

    /// Canary not configured.
    #[error("canary mode not configured in profile '{profile_id}'")]
    NotConfigured {
        /// Profile ID.
        profile_id: String,
    },

    /// Comparison profile not found.
    #[error("comparison profile '{comparison_id}' not found")]
    ComparisonProfileNotFound {
        /// Comparison profile ID.
        comparison_id: String,
    },

    /// Stage not in canary configuration.
    #[error("stage '{stage}' not in canary configuration")]
    StageNotInCanary {
        /// Stage name.
        stage: String,
    },

    /// Execution error from primary route.
    #[error("primary route execution failed for stage '{stage}': {reason}")]
    PrimaryExecutionFailed {
        /// Stage name.
        stage: String,
        /// Reason for failure.
        reason: String,
    },

    /// Execution error from comparison route.
    #[error("comparison route execution failed for stage '{stage}': {reason}")]
    ComparisonExecutionFailed {
        /// Stage name.
        stage: String,
        /// Reason for failure.
        reason: String,
    },
}

/// Execution timing information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionTiming {
    /// Duration of the execution.
    #[serde(with = "humantime_serde")]
    pub duration: Duration,

    /// Start timestamp.
    pub started_at: DateTime<Utc>,

    /// End timestamp.
    pub ended_at: DateTime<Utc>,
}

/// Result of executing a single route.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteExecution {
    /// The provider configuration used.
    pub config: ProviderConfig,

    /// Whether fallback was used.
    pub used_fallback: bool,

    /// The output from the execution (serialized).
    pub output: String,

    /// Execution timing.
    pub timing: ExecutionTiming,

    /// Whether execution succeeded.
    pub success: bool,

    /// Error message if execution failed.
    pub error: Option<String>,
}

/// Diff entry between two outputs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffEntry {
    /// Line number (1-indexed).
    pub line: usize,

    /// Type of difference.
    pub diff_type: DiffType,

    /// Content from primary route.
    pub primary_content: Option<String>,

    /// Content from comparison route.
    pub comparison_content: Option<String>,
}

/// Type of difference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DiffType {
    /// Line added in comparison.
    Added,
    /// Line removed from comparison.
    Removed,
    /// Line modified between routes.
    Modified,
}

/// Summary of differences between routes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffSummary {
    /// Number of lines added.
    pub lines_added: usize,

    /// Number of lines removed.
    pub lines_removed: usize,

    /// Number of lines modified.
    pub lines_modified: usize,

    /// Whether outputs are identical.
    pub identical: bool,

    /// Detailed diff entries (if `output_diffs` enabled).
    #[serde(default)]
    pub entries: Vec<DiffEntry>,
}

/// Result of a canary comparison for a single stage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StageCanaryResult {
    /// Stage name.
    pub stage: String,

    /// Primary route execution result.
    pub primary: RouteExecution,

    /// Comparison route execution result.
    pub comparison: RouteExecution,

    /// Diff summary.
    pub diff: DiffSummary,
}

/// Complete canary comparison report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanaryReport {
    /// Report ID (UUID or timestamp-based).
    pub report_id: String,

    /// Primary profile ID.
    pub primary_profile_id: String,

    /// Comparison profile ID.
    pub comparison_profile_id: String,

    /// Report generation timestamp.
    pub generated_at: DateTime<Utc>,

    /// Stage results.
    pub stages: Vec<StageCanaryResult>,

    /// Overall summary.
    pub summary: CanarySummary,
}

/// Overall canary comparison summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanarySummary {
    /// Total stages compared.
    pub total_stages: usize,

    /// Stages with identical output.
    pub identical_stages: usize,

    /// Stages with differences.
    pub different_stages: usize,

    /// Stages where primary failed.
    pub primary_failures: usize,

    /// Stages where comparison failed.
    pub comparison_failures: usize,

    /// Average timing difference (comparison - primary).
    #[serde(with = "humantime_serde")]
    pub avg_timing_diff: Duration,
}

/// Trait for stage execution.
///
/// This trait allows mocking stage execution in tests.
pub trait StageExecutor: Send + Sync {
    /// Executes a stage with the given configuration.
    ///
    /// # Arguments
    ///
    /// * `stage` - The stage name.
    /// * `config` - The provider configuration.
    /// * `input` - The input data.
    ///
    /// # Returns
    ///
    /// The execution output as a string, or an error.
    ///
    /// # Errors
    ///
    /// Returns an error string if execution fails.
    fn execute(&self, stage: &str, config: &ProviderConfig, input: &str) -> Result<String, String>;
}

/// Mock executor for testing that returns the input with provider info.
#[derive(Debug, Clone, Default)]
pub struct MockStageExecutor;

impl StageExecutor for MockStageExecutor {
    fn execute(&self, stage: &str, config: &ProviderConfig, input: &str) -> Result<String, String> {
        Ok(format!(
            "Stage: {}\nProvider: {}\nModel: {}\nInput: {}",
            stage,
            config.provider,
            config.model.as_deref().unwrap_or("none"),
            input
        ))
    }
}

/// Canary runner that executes comparisons between routing configurations.
pub struct CanaryRunner<E: StageExecutor> {
    /// Primary router.
    primary_router: ModelRouter<DefaultProviderAvailability>,

    /// Comparison router.
    comparison_router: ModelRouter<DefaultProviderAvailability>,

    /// Canary configuration.
    canary_config: CanaryConfig,

    /// Stage executor.
    executor: E,
}

impl<E: StageExecutor> CanaryRunner<E> {
    /// Creates a new canary runner.
    ///
    /// # Arguments
    ///
    /// * `primary_profile` - The primary routing profile.
    /// * `comparison_profile` - The comparison routing profile.
    /// * `canary_config` - The canary configuration.
    /// * `executor` - The stage executor.
    pub fn new(
        primary_profile: RoutingProfile,
        comparison_profile: RoutingProfile,
        canary_config: CanaryConfig,
        executor: E,
    ) -> Self {
        let primary_router = ModelRouter::from_profile(primary_profile);
        let comparison_router = ModelRouter::from_profile(comparison_profile);

        Self {
            primary_router,
            comparison_router,
            canary_config,
            executor,
        }
    }

    /// Runs canary comparison for a single stage.
    ///
    /// # Arguments
    ///
    /// * `stage` - The stage name.
    /// * `input` - The input data.
    ///
    /// # Returns
    ///
    /// The stage canary result.
    ///
    /// # Errors
    ///
    /// Returns an error if routing fails for either route.
    pub fn run_stage(&self, stage: &str, input: &str) -> Result<StageCanaryResult, CanaryError> {
        // Check if stage is in canary configuration
        if !self.canary_config.stages.is_empty()
            && !self.canary_config.stages.contains(&stage.to_string())
        {
            return Err(CanaryError::StageNotInCanary {
                stage: stage.to_string(),
            });
        }

        info!(stage = %stage, "Running canary comparison");

        // Execute primary route
        let primary_result = self.execute_route(&self.primary_router, stage, input, true)?;

        // Execute comparison route
        let comparison_result = self.execute_route(&self.comparison_router, stage, input, false)?;

        // Generate diff
        let diff = self.generate_diff(&primary_result.output, &comparison_result.output);

        Ok(StageCanaryResult {
            stage: stage.to_string(),
            primary: primary_result,
            comparison: comparison_result,
            diff,
        })
    }

    /// Executes a single route.
    fn execute_route(
        &self,
        router: &ModelRouter<DefaultProviderAvailability>,
        stage: &str,
        input: &str,
        is_primary: bool,
    ) -> Result<RouteExecution, CanaryError> {
        let route_result = router.route_stage(stage)?;

        let start = Instant::now();
        let started_at = Utc::now();

        let execution_result = self.executor.execute(stage, &route_result.config, input);

        let duration = start.elapsed();
        let ended_at = Utc::now();

        let timing = ExecutionTiming {
            duration,
            started_at,
            ended_at,
        };

        match execution_result {
            Ok(output) => Ok(RouteExecution {
                config: route_result.config,
                used_fallback: route_result.is_fallback,
                output,
                timing,
                success: true,
                error: None,
            }),
            Err(error) => {
                if is_primary {
                    warn!(stage = %stage, error = %error, "Primary route execution failed");
                } else {
                    warn!(stage = %stage, error = %error, "Comparison route execution failed");
                }
                Ok(RouteExecution {
                    config: route_result.config,
                    used_fallback: route_result.is_fallback,
                    output: String::new(),
                    timing,
                    success: false,
                    error: Some(error),
                })
            },
        }
    }

    /// Generates a diff between two outputs.
    fn generate_diff(&self, primary: &str, comparison: &str) -> DiffSummary {
        if primary == comparison {
            return DiffSummary {
                lines_added: 0,
                lines_removed: 0,
                lines_modified: 0,
                identical: true,
                entries: Vec::new(),
            };
        }

        let primary_lines: Vec<&str> = primary.lines().collect();
        let comparison_lines: Vec<&str> = comparison.lines().collect();

        let mut entries = Vec::new();
        let mut lines_added = 0;
        let mut lines_removed = 0;
        let mut lines_modified = 0;

        let max_lines = primary_lines.len().max(comparison_lines.len());

        for i in 0..max_lines {
            let primary_line = primary_lines.get(i);
            let comparison_line = comparison_lines.get(i);

            match (primary_line, comparison_line) {
                (Some(p), Some(c)) if p != c => {
                    lines_modified += 1;
                    if self.canary_config.output_diffs {
                        entries.push(DiffEntry {
                            line: i + 1,
                            diff_type: DiffType::Modified,
                            primary_content: Some((*p).to_string()),
                            comparison_content: Some((*c).to_string()),
                        });
                    }
                },
                (Some(p), None) => {
                    lines_removed += 1;
                    if self.canary_config.output_diffs {
                        entries.push(DiffEntry {
                            line: i + 1,
                            diff_type: DiffType::Removed,
                            primary_content: Some((*p).to_string()),
                            comparison_content: None,
                        });
                    }
                },
                (None, Some(c)) => {
                    lines_added += 1;
                    if self.canary_config.output_diffs {
                        entries.push(DiffEntry {
                            line: i + 1,
                            diff_type: DiffType::Added,
                            primary_content: None,
                            comparison_content: Some((*c).to_string()),
                        });
                    }
                },
                _ => {},
            }
        }

        DiffSummary {
            lines_added,
            lines_removed,
            lines_modified,
            identical: false,
            entries,
        }
    }

    /// Runs canary comparison for all configured stages.
    ///
    /// # Arguments
    ///
    /// * `inputs` - Map of stage name to input data.
    ///
    /// # Returns
    ///
    /// The complete canary report.
    pub fn run_all(&self, inputs: &HashMap<String, String>) -> CanaryReport {
        let report_id = format!(
            "canary-{}-{}",
            self.primary_router.profile_id(),
            Utc::now().format("%Y%m%d-%H%M%S")
        );

        let stages_to_run: Vec<&str> = if self.canary_config.stages.is_empty() {
            // Run all stages from primary profile
            self.primary_router.stage_names()
        } else {
            self.canary_config
                .stages
                .iter()
                .map(String::as_str)
                .collect()
        };

        let mut stage_results = Vec::new();
        let mut total_primary_duration = Duration::ZERO;
        let mut total_comparison_duration = Duration::ZERO;
        let mut primary_failures = 0;
        let mut comparison_failures = 0;
        let mut identical_stages = 0;

        for stage in stages_to_run {
            let input = inputs.get(stage).map_or("", String::as_str);

            match self.run_stage(stage, input) {
                Ok(result) => {
                    total_primary_duration += result.primary.timing.duration;
                    total_comparison_duration += result.comparison.timing.duration;

                    if !result.primary.success {
                        primary_failures += 1;
                    }
                    if !result.comparison.success {
                        comparison_failures += 1;
                    }
                    if result.diff.identical {
                        identical_stages += 1;
                    }

                    stage_results.push(result);
                },
                Err(e) => {
                    warn!(stage = %stage, error = %e, "Failed to run canary for stage");
                },
            }
        }

        let total_stages = stage_results.len();
        let different_stages = total_stages - identical_stages;

        // Calculate average timing difference
        #[allow(clippy::cast_possible_truncation)]
        let avg_timing_diff = if total_stages > 0 {
            let stages_count = total_stages as u32;
            let primary_avg = total_primary_duration / stages_count;
            let comparison_avg = total_comparison_duration / stages_count;
            primary_avg.abs_diff(comparison_avg)
        } else {
            Duration::ZERO
        };

        CanaryReport {
            report_id,
            primary_profile_id: self.primary_router.profile_id().to_string(),
            comparison_profile_id: self.comparison_router.profile_id().to_string(),
            generated_at: Utc::now(),
            stages: stage_results,
            summary: CanarySummary {
                total_stages,
                identical_stages,
                different_stages,
                primary_failures,
                comparison_failures,
                avg_timing_diff,
            },
        }
    }
}

/// Creates a canary runner from profile IDs.
///
/// # Arguments
///
/// * `repo_root` - Path to the repository root.
/// * `primary_profile_id` - The primary profile ID.
/// * `comparison_profile_id` - The comparison profile ID.
/// * `executor` - The stage executor.
///
/// # Returns
///
/// A canary runner configured for the two profiles.
///
/// # Errors
///
/// Returns an error if either profile cannot be loaded.
pub fn create_canary_runner<E: StageExecutor>(
    repo_root: &Path,
    primary_profile_id: &str,
    comparison_profile_id: &str,
    executor: E,
) -> Result<CanaryRunner<E>, CanaryError> {
    let primary_profile = load_profile_by_id(repo_root, primary_profile_id)?;
    let comparison_profile = load_profile_by_id(repo_root, comparison_profile_id)?;

    // Get canary config from primary profile, or create default
    let canary_config = primary_profile
        .canary
        .clone()
        .unwrap_or_else(|| CanaryConfig {
            enabled: true,
            comparison_profile: Some(comparison_profile_id.to_string()),
            stages: Vec::new(),
            output_diffs: true,
        });

    Ok(CanaryRunner::new(
        primary_profile,
        comparison_profile,
        canary_config,
        executor,
    ))
}

// Provide humantime_serde for Duration serialization
mod humantime_serde {
    use std::time::Duration;

    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let s = humantime::format_duration(*duration).to_string();
        serializer.serialize_str(&s)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        humantime::parse_duration(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::*;
    use crate::model_router::profile::load_profile;

    /// Creates test routing profiles.
    fn create_test_profiles(dir: &Path) -> (RoutingProfile, RoutingProfile) {
        let primary_content = r"
routing_profile:
  profile_id: primary-test
  description: Primary test profile.
  stages:
    test_stage:
      provider: anthropic
      model: claude-3-5-sonnet
      timeout_ms: 60000
    another_stage:
      provider: openai
      model: gpt-4
      timeout_ms: 30000
  canary:
    enabled: true
    comparison_profile: comparison-test
    stages:
      - test_stage
    output_diffs: true
";
        let comparison_content = r"
routing_profile:
  profile_id: comparison-test
  description: Comparison test profile.
  stages:
    test_stage:
      provider: openai
      model: gpt-4
      timeout_ms: 60000
    another_stage:
      provider: anthropic
      model: claude-3-5-sonnet
      timeout_ms: 30000
";

        let primary_path = dir.join("primary.yaml");
        let comparison_path = dir.join("comparison.yaml");

        fs::write(&primary_path, primary_content).unwrap();
        fs::write(&comparison_path, comparison_content).unwrap();

        let primary = load_profile(&primary_path).unwrap();
        let comparison = load_profile(&comparison_path).unwrap();

        (primary, comparison)
    }

    /// UT-118-05: Test canary runner creation.
    #[test]
    fn test_canary_runner_creation() {
        let temp_dir = TempDir::new().unwrap();
        let (primary, comparison) = create_test_profiles(temp_dir.path());

        let canary_config = primary.canary.clone().unwrap();

        let runner = CanaryRunner::new(primary, comparison, canary_config, MockStageExecutor);

        assert_eq!(runner.primary_router.profile_id(), "primary-test");
        assert_eq!(runner.comparison_router.profile_id(), "comparison-test");
    }

    /// UT-118-05: Test single stage canary comparison.
    #[test]
    fn test_run_stage() {
        let temp_dir = TempDir::new().unwrap();
        let (primary, comparison) = create_test_profiles(temp_dir.path());

        let canary_config = primary.canary.clone().unwrap();

        let runner = CanaryRunner::new(primary, comparison, canary_config, MockStageExecutor);

        let result = runner.run_stage("test_stage", "test input").unwrap();

        assert_eq!(result.stage, "test_stage");
        assert!(result.primary.success);
        assert!(result.comparison.success);
        // Outputs should differ because providers are different
        assert!(!result.diff.identical);
    }

    /// UT-118-05: Test stage not in canary config.
    #[test]
    fn test_stage_not_in_canary() {
        let temp_dir = TempDir::new().unwrap();
        let (primary, comparison) = create_test_profiles(temp_dir.path());

        let canary_config = primary.canary.clone().unwrap();

        let runner = CanaryRunner::new(primary, comparison, canary_config, MockStageExecutor);

        let result = runner.run_stage("another_stage", "test input");
        assert!(matches!(result, Err(CanaryError::StageNotInCanary { .. })));
    }

    /// UT-118-06: Test diff generation with identical outputs.
    #[test]
    fn test_diff_identical() {
        let temp_dir = TempDir::new().unwrap();
        let (primary, comparison) = create_test_profiles(temp_dir.path());

        let canary_config = CanaryConfig {
            enabled: true,
            comparison_profile: Some("comparison-test".to_string()),
            stages: Vec::new(), // Empty means all stages
            output_diffs: true,
        };

        let runner = CanaryRunner::new(primary, comparison, canary_config, MockStageExecutor);

        // Both outputs are the same string
        let diff = runner.generate_diff("line1\nline2", "line1\nline2");
        assert!(diff.identical);
        assert_eq!(diff.lines_added, 0);
        assert_eq!(diff.lines_removed, 0);
        assert_eq!(diff.lines_modified, 0);
    }

    /// UT-118-06: Test diff generation with different outputs.
    #[test]
    fn test_diff_different() {
        let temp_dir = TempDir::new().unwrap();
        let (primary, comparison) = create_test_profiles(temp_dir.path());

        let canary_config = CanaryConfig {
            enabled: true,
            comparison_profile: Some("comparison-test".to_string()),
            stages: Vec::new(),
            output_diffs: true,
        };

        let runner = CanaryRunner::new(primary, comparison, canary_config, MockStageExecutor);

        let diff = runner.generate_diff("line1\nline2\nline3", "line1\nmodified\nline3\nextra");

        assert!(!diff.identical);
        assert_eq!(diff.lines_added, 1); // "extra"
        assert_eq!(diff.lines_modified, 1); // "line2" -> "modified"
        assert_eq!(diff.entries.len(), 2);
    }

    /// UT-118-06: Test `run_all` generates complete report.
    #[test]
    fn test_run_all() {
        let temp_dir = TempDir::new().unwrap();
        let (primary, comparison) = create_test_profiles(temp_dir.path());

        let canary_config = CanaryConfig {
            enabled: true,
            comparison_profile: Some("comparison-test".to_string()),
            stages: vec!["test_stage".to_string()],
            output_diffs: true,
        };

        let runner = CanaryRunner::new(primary, comparison, canary_config, MockStageExecutor);

        let mut inputs = HashMap::new();
        inputs.insert("test_stage".to_string(), "test input".to_string());

        let report = runner.run_all(&inputs);

        assert!(report.report_id.starts_with("canary-primary-test-"));
        assert_eq!(report.primary_profile_id, "primary-test");
        assert_eq!(report.comparison_profile_id, "comparison-test");
        assert_eq!(report.summary.total_stages, 1);
        assert_eq!(report.stages.len(), 1);
    }

    /// Test `ExecutionTiming` serialization.
    #[test]
    fn test_execution_timing_serialization() {
        let timing = ExecutionTiming {
            duration: Duration::from_millis(1500),
            started_at: Utc::now(),
            ended_at: Utc::now(),
        };

        let json = serde_json::to_string(&timing).unwrap();
        assert!(json.contains("1s 500ms") || json.contains("1.5s"));
    }
}
