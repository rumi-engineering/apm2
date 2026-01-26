//! Refactor Radar module for maintenance recommendations.
//!
//! This module provides the Refactor Radar, which aggregates CCP signals
//! (hotspots, duplication heuristics, complexity metrics) into bounded,
//! prioritized maintenance recommendations.
//!
//! # Overview
//!
//! The Refactor Radar analyzes a codebase to identify areas that may benefit
//! from refactoring:
//!
//! - **Hotspots**: Files with high churn rate in git history
//! - **Duplication**: Structural similarity patterns suggesting abstraction
//!   opportunities
//! - **Complexity**: Files exceeding size/complexity thresholds
//!
//! # Design Principles
//!
//! - **Bounded Output**: Recommendations are capped at a configurable maximum
//!   to prevent overwhelming developers
//! - **Circuit Breaker**: When the maintenance backlog is high, new
//!   recommendations are suspended to avoid "recommendation fatigue"
//! - **Prioritization**: Recommendations are ranked by severity for actionable
//!   triage
//!
//! # Invariants
//!
//! - [INV-0001] Radar output never exceeds `max_recommendations` setting
//! - [INV-0002] Circuit breaker suspends output when backlog > threshold
//! - [INV-0003] All file paths are validated to prevent traversal attacks
//! - [INV-0004] Git command arguments are not user-controlled
//!
//! # Contracts
//!
//! - [CTR-0001] `Radar::run` requires valid repository root path
//! - [CTR-0002] Configuration values are validated at construction
//! - [CTR-0003] Signal collectors fail gracefully without crashing radar
//!
//! # Security
//!
//! - [SEC-0001] Path traversal is prevented via validation
//! - [SEC-0002] Git commands use hardcoded arguments, not user input
//! - [SEC-0003] File reads are bounded to prevent denial-of-service
//!
//! # Example
//!
//! ```rust,no_run
//! use std::path::Path;
//! use std::time::Duration;
//!
//! use apm2_core::refactor_radar::{Radar, RadarConfig};
//!
//! // Configure the radar
//! let config = RadarConfig {
//!     window: Duration::from_secs(7 * 86400), // Analyze last 7 days
//!     max_recommendations: 10,                // Cap at 10 recommendations
//!     backlog_threshold: 20,                  // Trip if > 20 open tickets
//!     ..Default::default()
//! };
//!
//! // Run the analysis
//! let radar = Radar::new(config);
//! let result = radar.run(Path::new("/repo/root")).unwrap();
//!
//! // Check circuit breaker status
//! if result.circuit_breaker.is_blocking() {
//!     println!(
//!         "Recommendations suspended: {} open tickets (threshold: {})",
//!         result.circuit_breaker.current_backlog,
//!         result.circuit_breaker.threshold
//!     );
//! } else {
//!     // Process recommendations
//!     for rec in &result.recommendations {
//!         println!(
//!             "#{} [{:?}] {}: {}",
//!             rec.priority,
//!             rec.severity,
//!             rec.source_path.display(),
//!             rec.rationale
//!         );
//!     }
//! }
//! ```

pub mod radar;
pub mod signals;

// Re-export primary API
pub use radar::{
    CircuitBreaker, CircuitBreakerStatus, ConfigSummary, DEFAULT_BACKLOG_THRESHOLD,
    DEFAULT_MAX_RECOMMENDATIONS, Radar, RadarConfig, RadarError, RadarResult, Recommendation,
    SuggestedTicket,
};
pub use signals::{
    ComplexitySignal, DuplicationSignal, HotspotSignal, Severity, Signal, SignalError,
};
