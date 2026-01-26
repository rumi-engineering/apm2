//! Model router for multi-model orchestration with configurable routing
//! profiles.
//!
//! This module provides the foundation for routing pipeline stages to
//! appropriate AI providers based on configurable routing profiles. It
//! supports:
//!
//! - Routing profile YAML parsing and validation
//! - Stage-to-provider routing with fail-closed semantics
//! - Provider availability checking with fallback support
//! - Canary comparison mode for A/B testing routes
//!
//! # Overview
//!
//! The model router enables flexible multi-model orchestration by separating
//! routing logic from execution logic. Routing profiles are version-controlled
//! YAML files that define how each pipeline stage should be routed to
//! providers.
//!
//! # Design Philosophy
//!
//! 1. **Fail-closed semantics**: If a provider is unavailable and no fallback
//!    is explicitly configured, the router returns an error rather than
//!    silently degrading. This prevents unexpected behavior in production.
//!
//! 2. **Canary mode is opt-in**: Runs both routes sequentially to compare
//!    outputs between two routing configurations.
//!
//! 3. **Routing profiles are version-controlled**: YAML files enable
//!    reproducible routing configurations across environments.
//!
//! # Invariants
//!
//! - [INV-ROUTER-001] Router is immutable after construction
//! - [INV-ROUTER-002] Fail-closed: no implicit fallbacks
//! - [INV-ROUTER-003] Provider availability is checked before routing
//! - [INV-ROUTER-004] All routing decisions are logged for auditability
//! - [INV-PROFILE-001] Profile IDs are unique within a profile set
//! - [INV-PROFILE-002] All stage configurations have a valid provider
//! - [INV-CANARY-001] Both routes are executed sequentially (not parallel)
//!
//! # Contracts
//!
//! - [CTR-ROUTER-001] `route_stage` requires a valid stage name from the
//!   profile
//! - [CTR-ROUTER-002] Provider unavailability triggers fallback chain
//! - [CTR-ROUTER-003] Fallback chain exhaustion returns explicit error
//! - [CTR-PROFILE-001] Profile loading validates against schema constraints
//!
//! # Security
//!
//! - [SEC-ROUTER-001] Profile file reads are bounded to prevent `DoS`
//! - [SEC-ROUTER-002] Path traversal is prevented in profile paths
//! - [SEC-ROUTER-003] Profile IDs are validated against safe patterns
//!
//! # Example
//!
//! ```rust,no_run
//! use std::path::Path;
//!
//! use apm2_core::model_router::{ModelRouter, load_profile};
//!
//! // Load a routing profile
//! let profile = load_profile(Path::new(
//!     "/repo/documents/standards/routing_profiles/local.yaml",
//! ))
//! .unwrap();
//!
//! // Create a router from the profile
//! let router = ModelRouter::from_profile(profile);
//!
//! // Route a pipeline stage
//! let result = router.route_stage("impact_map").unwrap();
//! println!("Routing to provider: {}", result.config.provider);
//! if result.is_fallback {
//!     println!("Using fallback: {:?}", result.fallback_reason);
//! }
//! ```
//!
//! # Canary Mode Example
//!
//! ```rust,no_run
//! use std::collections::HashMap;
//! use std::path::Path;
//!
//! use apm2_core::model_router::{MockStageExecutor, create_canary_runner};
//!
//! // Create a canary runner comparing two profiles
//! let runner = create_canary_runner(
//!     Path::new("/repo"),
//!     "local",
//!     "production",
//!     MockStageExecutor,
//! )
//! .unwrap();
//!
//! // Run canary comparison
//! let mut inputs = HashMap::new();
//! inputs.insert("impact_map".to_string(), "input data".to_string());
//!
//! let report = runner.run_all(&inputs);
//! println!(
//!     "Canary report: {} stages compared",
//!     report.summary.total_stages
//! );
//! println!(
//!     "Identical: {}, Different: {}",
//!     report.summary.identical_stages, report.summary.different_stages
//! );
//! ```

pub mod canary;
pub mod profile;
pub mod router;

// Re-export primary API from profile module
// Re-export primary API from canary module
pub use canary::{
    CanaryError, CanaryReport, CanaryRunner, CanarySummary, DiffEntry, DiffSummary, DiffType,
    ExecutionTiming, MockStageExecutor, RouteExecution, StageCanaryResult, StageExecutor,
    create_canary_runner,
};
pub use profile::{
    CanaryConfig, GlobalFallback, ProfileError, ProviderConfig, RetryPolicy, RoutingProfile,
    StageFallback, load_profile, load_profile_by_id,
};
// Re-export primary API from router module
pub use router::{
    DefaultProviderAvailability, ModelRouter, ProviderAvailability, ProviderStatus, RouteResult,
    RouterError,
};
