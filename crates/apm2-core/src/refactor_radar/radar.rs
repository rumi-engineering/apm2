//! Core radar aggregation and prioritization logic.
//!
//! This module provides:
//! - Signal aggregation from all collectors
//! - Prioritization based on severity and signal type
//! - Bounded output with configurable limits
//! - Circuit breaker to prevent recommendation overload
//!
//! # Invariants
//!
//! - [INV-RADAR-001] Output never exceeds `max_recommendations` setting
//! - [INV-RADAR-002] Recommendations are sorted by priority
//! - [INV-RADAR-003] Circuit breaker status is always included in output
//!
//! # Contracts
//!
//! - [CTR-RADAR-001] `run` requires valid repository root
//! - [CTR-RADAR-002] All signals are validated before aggregation
//! - [CTR-RADAR-003] Bounded output is enforced regardless of input size
//!
//! # Example
//!
//! ```rust,no_run
//! use std::path::Path;
//! use std::time::Duration;
//!
//! use apm2_core::refactor_radar::{Radar, RadarConfig};
//!
//! let config = RadarConfig {
//!     window: Duration::from_secs(7 * 86400), // 7 days
//!     max_recommendations: 10,
//!     backlog_threshold: 20,
//!     ..Default::default()
//! };
//!
//! let radar = Radar::new(config);
//! let result = radar.run(Path::new("/repo/root")).unwrap();
//!
//! println!("Circuit breaker: {:?}", result.circuit_breaker);
//! for rec in &result.recommendations {
//!     println!(
//!         "  #{}: {} - {}",
//!         rec.priority,
//!         rec.source_path.display(),
//!         rec.rationale
//!     );
//! }
//! ```

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, info, warn};

use super::signals::{
    ComplexityCollector, DuplicationCollector, HotspotCollector, Severity, Signal, SignalError,
};

/// Default maximum recommendations to output.
pub const DEFAULT_MAX_RECOMMENDATIONS: usize = 10;

/// Default backlog threshold for circuit breaker.
pub const DEFAULT_BACKLOG_THRESHOLD: usize = 20;

/// Default minimum churn for hotspot detection.
const DEFAULT_MIN_CHURN: usize = 5;

/// Default similarity threshold for duplication detection.
const DEFAULT_SIMILARITY_THRESHOLD: u8 = 70;

/// Default max lines for complexity detection.
const DEFAULT_MAX_LINES: usize = 500;

/// Errors that can occur during radar operation.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum RadarError {
    /// Repository root not found.
    #[error("repository root not found: {path}")]
    RepoNotFound {
        /// The missing path.
        path: String,
    },

    /// Signal collection failed.
    #[error("signal collection failed: {0}")]
    SignalError(#[from] SignalError),

    /// IO error.
    #[error("IO error: {reason}")]
    IoError {
        /// Reason for the failure.
        reason: String,
    },
}

/// Circuit breaker status.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CircuitBreakerStatus {
    /// Circuit breaker is not tripped, normal operation.
    Ok,
    /// Circuit breaker is tripped due to high backlog.
    Tripped,
}

/// Circuit breaker information.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CircuitBreaker {
    /// Current status.
    pub status: CircuitBreakerStatus,
    /// Current backlog count (open maintenance tickets).
    pub current_backlog: usize,
    /// Configured threshold.
    pub threshold: usize,
    /// Whether the breaker was ignored via flag.
    pub ignored: bool,
}

impl CircuitBreaker {
    /// Returns true if the circuit breaker is tripped and not ignored.
    #[must_use]
    pub const fn is_blocking(&self) -> bool {
        matches!(self.status, CircuitBreakerStatus::Tripped) && !self.ignored
    }
}

/// A prioritized recommendation from the radar.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Recommendation {
    /// Priority rank (1 = highest priority).
    pub priority: usize,
    /// Signal type that generated this recommendation.
    pub signal_type: String,
    /// Source file path.
    pub source_path: PathBuf,
    /// Severity level.
    pub severity: Severity,
    /// Rationale for the recommendation.
    pub rationale: String,
    /// Suggested action.
    pub suggested_action: String,
    /// Suggested ticket for tracking.
    pub suggested_ticket: SuggestedTicket,
}

/// A suggested ticket for a recommendation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SuggestedTicket {
    /// Suggested ticket title.
    pub title: String,
    /// Ticket type.
    pub ticket_type: String,
}

/// Configuration for the refactor radar.
#[derive(Debug, Clone)]
pub struct RadarConfig {
    /// Time window for analysis.
    pub window: Duration,
    /// Maximum recommendations to output.
    pub max_recommendations: usize,
    /// Backlog threshold for circuit breaker.
    pub backlog_threshold: usize,
    /// Whether to ignore the circuit breaker.
    pub ignore_breaker: bool,
    /// Minimum churn count for hotspot detection.
    pub min_churn: usize,
    /// Similarity threshold for duplication detection.
    pub similarity_threshold: u8,
    /// Max lines threshold for complexity detection.
    pub max_lines: usize,
}

impl Default for RadarConfig {
    fn default() -> Self {
        Self {
            window: Duration::from_secs(7 * 86400), // 7 days
            max_recommendations: DEFAULT_MAX_RECOMMENDATIONS,
            backlog_threshold: DEFAULT_BACKLOG_THRESHOLD,
            ignore_breaker: false,
            min_churn: DEFAULT_MIN_CHURN,
            similarity_threshold: DEFAULT_SIMILARITY_THRESHOLD,
            max_lines: DEFAULT_MAX_LINES,
        }
    }
}

/// Result from a radar run.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RadarResult {
    /// Circuit breaker status.
    pub circuit_breaker: CircuitBreaker,
    /// Recommendations (empty if circuit breaker is blocking).
    pub recommendations: Vec<Recommendation>,
    /// Total signals collected before filtering.
    pub total_signals: usize,
    /// Configuration used.
    pub config_summary: ConfigSummary,
}

/// Summary of the configuration used.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigSummary {
    /// Window in days.
    pub window_days: u64,
    /// Max recommendations.
    pub max_recommendations: usize,
    /// Backlog threshold.
    pub backlog_threshold: usize,
}

/// The refactor radar aggregator.
pub struct Radar {
    config: RadarConfig,
}

impl Radar {
    /// Creates a new radar with the given configuration.
    #[must_use]
    pub const fn new(config: RadarConfig) -> Self {
        Self { config }
    }

    /// Runs the radar analysis on the repository.
    ///
    /// # Arguments
    ///
    /// * `repo_root` - Path to the repository root
    ///
    /// # Returns
    ///
    /// A `RadarResult` containing recommendations and circuit breaker status.
    ///
    /// # Errors
    ///
    /// Returns an error if the repository doesn't exist or signal collection
    /// fails.
    ///
    /// # Invariants
    ///
    /// - INV-RADAR-001: Output never exceeds `max_recommendations`
    /// - INV-RADAR-002: Recommendations are sorted by priority
    pub fn run(&self, repo_root: &Path) -> Result<RadarResult, RadarError> {
        // Validate repo root exists
        if !repo_root.exists() {
            return Err(RadarError::RepoNotFound {
                path: repo_root.display().to_string(),
            });
        }

        let window_days = self.config.window.as_secs() / 86400;
        info!(
            repo_root = %repo_root.display(),
            window_days = window_days,
            max_recommendations = self.config.max_recommendations,
            "Running refactor radar"
        );

        // Check circuit breaker first
        let backlog_count = count_maintenance_tickets(repo_root);
        let circuit_breaker = CircuitBreaker {
            status: if backlog_count > self.config.backlog_threshold {
                CircuitBreakerStatus::Tripped
            } else {
                CircuitBreakerStatus::Ok
            },
            current_backlog: backlog_count,
            threshold: self.config.backlog_threshold,
            ignored: self.config.ignore_breaker,
        };

        // If circuit breaker is tripped and not ignored, return early
        if circuit_breaker.is_blocking() {
            warn!(
                backlog = backlog_count,
                threshold = self.config.backlog_threshold,
                "Circuit breaker tripped - suspending recommendations"
            );
            return Ok(RadarResult {
                circuit_breaker,
                recommendations: Vec::new(),
                total_signals: 0,
                config_summary: ConfigSummary {
                    window_days,
                    max_recommendations: self.config.max_recommendations,
                    backlog_threshold: self.config.backlog_threshold,
                },
            });
        }

        // Collect signals from all collectors
        let mut all_signals = Vec::new();

        // Hotspot signals
        let hotspot_collector = HotspotCollector::new(self.config.window, self.config.min_churn);
        match hotspot_collector.collect(repo_root) {
            Ok(signals) => {
                debug!(count = signals.len(), "Collected hotspot signals");
                all_signals.extend(signals.into_iter().map(Signal::Hotspot));
            },
            Err(e) => {
                warn!(error = %e, "Hotspot collection failed, continuing with other signals");
            },
        }

        // Duplication signals
        let dup_collector = DuplicationCollector::new(self.config.similarity_threshold);
        match dup_collector.collect(repo_root) {
            Ok(signals) => {
                debug!(count = signals.len(), "Collected duplication signals");
                all_signals.extend(signals.into_iter().map(Signal::Duplication));
            },
            Err(e) => {
                warn!(error = %e, "Duplication collection failed, continuing with other signals");
            },
        }

        // Complexity signals
        let complexity_collector = ComplexityCollector::new(self.config.max_lines);
        match complexity_collector.collect(repo_root) {
            Ok(signals) => {
                debug!(count = signals.len(), "Collected complexity signals");
                all_signals.extend(signals.into_iter().map(Signal::Complexity));
            },
            Err(e) => {
                warn!(error = %e, "Complexity collection failed");
            },
        }

        let total_signals = all_signals.len();
        debug!(total = total_signals, "Total signals collected");

        // Aggregate and prioritize signals
        let recommendations = self.aggregate_signals(all_signals);

        info!(
            recommendations = recommendations.len(),
            total_signals = total_signals,
            "Radar analysis complete"
        );

        Ok(RadarResult {
            circuit_breaker,
            recommendations,
            total_signals,
            config_summary: ConfigSummary {
                window_days,
                max_recommendations: self.config.max_recommendations,
                backlog_threshold: self.config.backlog_threshold,
            },
        })
    }

    /// Aggregates signals into prioritized recommendations.
    ///
    /// # Invariants
    ///
    /// - INV-RADAR-001: Output never exceeds `max_recommendations`
    fn aggregate_signals(&self, signals: Vec<Signal>) -> Vec<Recommendation> {
        // Sort signals by severity (descending)
        let mut sorted_signals: Vec<_> = signals.into_iter().collect();
        sorted_signals.sort_by_key(|s| std::cmp::Reverse(s.severity().value()));

        // Convert to recommendations, respecting the max limit
        // INV-RADAR-001: Bounded output
        let recommendations: Vec<Recommendation> = sorted_signals
            .into_iter()
            .take(self.config.max_recommendations)
            .enumerate()
            .map(|(idx, signal)| {
                let priority = idx + 1;
                let title = generate_ticket_title(&signal);

                Recommendation {
                    priority,
                    signal_type: signal.signal_type().to_string(),
                    source_path: signal.source_path().to_path_buf(),
                    severity: signal.severity(),
                    rationale: signal.evidence().to_string(),
                    suggested_action: signal.suggested_action().to_string(),
                    suggested_ticket: SuggestedTicket {
                        title,
                        ticket_type: "maintenance".to_string(),
                    },
                }
            })
            .collect();

        recommendations
    }
}

/// Generates a ticket title from a signal.
fn generate_ticket_title(signal: &Signal) -> String {
    let path = signal.source_path().display();
    match signal {
        Signal::Hotspot(h) => {
            format!(
                "Refactor {} to reduce churn ({} changes)",
                path, h.churn_count
            )
        },
        Signal::Duplication(d) => {
            format!(
                "Extract common abstraction from {} ({}% similarity)",
                path, d.similarity_percent
            )
        },
        Signal::Complexity(c) => {
            format!(
                "Decompose {} to reduce complexity ({} lines)",
                path, c.line_count
            )
        },
    }
}

/// Maximum file size to read for ticket content (1MB).
const MAX_TICKET_FILE_SIZE: u64 = 1_000_000;

/// Counts open maintenance tickets in the repository.
fn count_maintenance_tickets(repo_root: &Path) -> usize {
    let tickets_dir = repo_root.join("documents").join("work").join("tickets");

    if !tickets_dir.exists() {
        return 0;
    }

    // SEC: Validate tickets_dir is within repo_root via canonicalization
    let Ok(canonical_tickets) = tickets_dir.canonicalize() else {
        warn!(path = %tickets_dir.display(), "Failed to canonicalize tickets directory");
        return 0;
    };
    let Ok(canonical_repo) = repo_root.canonicalize() else {
        warn!(path = %repo_root.display(), "Failed to canonicalize repo root");
        return 0;
    };
    if !canonical_tickets.starts_with(&canonical_repo) {
        warn!(
            tickets_dir = %canonical_tickets.display(),
            repo_root = %canonical_repo.display(),
            "tickets_dir escapes repo_root"
        );
        return 0;
    }

    let count = fs::read_dir(&tickets_dir)
        .map(|entries| {
            entries
                .flatten()
                .filter(|e| {
                    let path = e.path();
                    if path.extension().is_some_and(|ext| ext == "yaml") {
                        // SEC: Check for symlinks before reading
                        let Ok(metadata) = fs::symlink_metadata(&path) else {
                            return false;
                        };

                        // Skip symlinks to prevent symlink attacks
                        if metadata.is_symlink() {
                            warn!(path = %path.display(), "Skipping symlink in tickets dir");
                            return false;
                        }

                        // SEC: Check file size to prevent DoS via large files
                        if metadata.len() > MAX_TICKET_FILE_SIZE {
                            warn!(
                                path = %path.display(),
                                size = metadata.len(),
                                "Skipping large ticket file"
                            );
                            return false;
                        }

                        // Check if it's a maintenance ticket and not completed
                        if let Ok(content) = fs::read_to_string(&path) {
                            // Quick heuristic: check for maintenance-related keywords
                            // and not COMPLETED status
                            let is_maintenance = content.contains("maintenance")
                                || content.contains("refactor")
                                || content.contains("Refactor");
                            let is_open = !content.contains("status: COMPLETED")
                                && !content.contains("status: DONE");
                            return is_maintenance && is_open;
                        }
                    }
                    false
                })
                .count()
        })
        .unwrap_or(0);

    debug!(count = count, "Counted maintenance tickets");
    count
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;

    use tempfile::TempDir;

    use super::*;
    use crate::refactor_radar::signals::tests::create_test_repo;

    /// UT-122-03: Test radar aggregation respects `max_recommendations` bound.
    #[test]
    fn test_bounded_output() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();

        create_test_repo(root).expect("Failed to create test repo");

        // Create multiple files to generate many signals
        for i in 0..20 {
            let content = (0..600).fold(String::new(), |mut acc, j| {
                let _ = writeln!(acc, "// Line {j}");
                acc
            });
            std::fs::write(root.join(format!("src/file_{i}.rs")), &content).unwrap();

            std::process::Command::new("git")
                .args(["add", &format!("src/file_{i}.rs")])
                .current_dir(root)
                .output()
                .unwrap();
        }

        std::process::Command::new("git")
            .args(["commit", "-m", "Add many files"])
            .current_dir(root)
            .output()
            .unwrap();

        let config = RadarConfig {
            window: Duration::from_secs(30 * 86400),
            max_recommendations: 5,
            backlog_threshold: 100, // High to avoid tripping
            max_lines: 100,         // Low to trigger complexity signals
            ..Default::default()
        };

        let radar = Radar::new(config);
        let result = radar.run(root).unwrap();

        // INV-RADAR-001: Output must not exceed max_recommendations
        assert!(
            result.recommendations.len() <= 5,
            "Bounded output: got {} recommendations, expected <= 5",
            result.recommendations.len()
        );

        // Verify priorities are sequential
        for (i, rec) in result.recommendations.iter().enumerate() {
            assert_eq!(
                rec.priority,
                i + 1,
                "Priority should be sequential starting at 1"
            );
        }
    }

    /// UT-122-04: Test circuit breaker trips when backlog exceeds threshold.
    #[test]
    fn test_circuit_breaker_trip() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();

        create_test_repo(root).expect("Failed to create test repo");

        // Create maintenance tickets to trigger circuit breaker
        let tickets_dir = root.join("documents/work/tickets");
        std::fs::create_dir_all(&tickets_dir).unwrap();

        for i in 0..25 {
            let content = format!(
                "ticket:\n  id: TCK-{i:05}\n  title: Maintenance ticket {i}\n  status: READY\n  type: maintenance\n"
            );
            std::fs::write(tickets_dir.join(format!("TCK-{i:05}.yaml")), content).unwrap();
        }

        let config = RadarConfig {
            window: Duration::from_secs(30 * 86400),
            max_recommendations: 10,
            backlog_threshold: 20, // Lower than the 25 tickets we created
            ignore_breaker: false,
            ..Default::default()
        };

        let radar = Radar::new(config);
        let result = radar.run(root).unwrap();

        // Circuit breaker should be tripped
        assert!(
            matches!(result.circuit_breaker.status, CircuitBreakerStatus::Tripped),
            "Circuit breaker should be tripped"
        );
        assert!(
            result.circuit_breaker.is_blocking(),
            "Circuit breaker should be blocking"
        );
        assert!(
            result.recommendations.is_empty(),
            "No recommendations when circuit breaker is tripped"
        );
    }

    /// Test circuit breaker can be ignored.
    #[test]
    fn test_circuit_breaker_ignore() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();

        create_test_repo(root).expect("Failed to create test repo");

        // Create maintenance tickets
        let tickets_dir = root.join("documents/work/tickets");
        std::fs::create_dir_all(&tickets_dir).unwrap();

        for i in 0..25 {
            let content = format!(
                "ticket:\n  id: TCK-{i:05}\n  title: Maintenance refactor ticket {i}\n  status: READY\n"
            );
            std::fs::write(tickets_dir.join(format!("TCK-{i:05}.yaml")), content).unwrap();
        }

        let config = RadarConfig {
            window: Duration::from_secs(30 * 86400),
            max_recommendations: 10,
            backlog_threshold: 20,
            ignore_breaker: true, // Ignore the circuit breaker
            ..Default::default()
        };

        let radar = Radar::new(config);
        let result = radar.run(root).unwrap();

        // Circuit breaker status should still be tripped
        assert!(
            matches!(result.circuit_breaker.status, CircuitBreakerStatus::Tripped),
            "Circuit breaker status should still be tripped"
        );
        // But it should not be blocking
        assert!(
            !result.circuit_breaker.is_blocking(),
            "Circuit breaker should not be blocking when ignored"
        );
        assert!(result.circuit_breaker.ignored, "Ignored flag should be set");
    }

    /// Test radar with no signals.
    #[test]
    fn test_radar_no_signals() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();

        create_test_repo(root).expect("Failed to create test repo");

        let config = RadarConfig {
            window: Duration::from_secs(1), // Very short window
            max_recommendations: 10,
            min_churn: 100,     // Very high threshold
            max_lines: 100_000, // Very high threshold
            ..Default::default()
        };

        let radar = Radar::new(config);
        let result = radar.run(root).unwrap();

        // Should have no recommendations but no error
        assert!(result.recommendations.is_empty());
        assert!(matches!(
            result.circuit_breaker.status,
            CircuitBreakerStatus::Ok
        ));
    }

    /// Test repo not found error.
    #[test]
    fn test_repo_not_found() {
        let config = RadarConfig::default();
        let radar = Radar::new(config);

        let result = radar.run(Path::new("/nonexistent/path"));

        assert!(matches!(result, Err(RadarError::RepoNotFound { .. })));
    }

    /// Test default configuration values.
    #[test]
    fn test_default_config() {
        let config = RadarConfig::default();

        assert_eq!(config.max_recommendations, DEFAULT_MAX_RECOMMENDATIONS);
        assert_eq!(config.backlog_threshold, DEFAULT_BACKLOG_THRESHOLD);
        assert!(!config.ignore_breaker);
        assert_eq!(config.window.as_secs(), 7 * 86400);
    }

    /// Test recommendation sorting by severity.
    #[test]
    fn test_recommendation_sorting() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();

        create_test_repo(root).expect("Failed to create test repo");

        // Create files with different complexity levels
        let small_content = (0..50).fold(String::new(), |mut acc, i| {
            let _ = writeln!(acc, "// Line {i}");
            acc
        });
        let large_content = (0..2000).fold(String::new(), |mut acc, i| {
            let _ = writeln!(acc, "// Line {i}");
            acc
        });

        std::fs::write(root.join("src/small.rs"), &small_content).unwrap();
        std::fs::write(root.join("src/large.rs"), &large_content).unwrap();

        std::process::Command::new("git")
            .args(["add", "."])
            .current_dir(root)
            .output()
            .unwrap();
        std::process::Command::new("git")
            .args(["commit", "-m", "Add files"])
            .current_dir(root)
            .output()
            .unwrap();

        let config = RadarConfig {
            max_lines: 100,
            max_recommendations: 10,
            ..Default::default()
        };

        let radar = Radar::new(config);
        let result = radar.run(root).unwrap();

        // Verify recommendations are sorted by severity (highest first)
        for window in result.recommendations.windows(2) {
            assert!(
                window[0].severity.value() >= window[1].severity.value(),
                "Recommendations should be sorted by severity descending"
            );
        }
    }
}
