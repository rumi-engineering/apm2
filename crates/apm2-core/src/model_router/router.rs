//! Core routing logic for multi-model orchestration.
//!
//! This module provides:
//! - Router struct that holds loaded routing profile
//! - Stage-to-provider routing with fail-closed semantics
//! - Provider availability checking
//!
//! # Design Philosophy
//!
//! The router uses fail-closed semantics: if a provider is unavailable and
//! no fallback is explicitly configured, the router returns an error rather
//! than silently degrading. This ensures predictable behavior and prevents
//! silent failures in production pipelines.
//!
//! # Invariants
//!
//! - [INV-ROUTER-001] Router is immutable after construction
//! - [INV-ROUTER-002] Fail-closed: no implicit fallbacks
//! - [INV-ROUTER-003] Provider availability is checked before routing
//! - [INV-ROUTER-004] All routing decisions are logged for auditability

use std::collections::HashSet;
use std::path::Path;

use thiserror::Error;
use tracing::{debug, info, warn};

use super::profile::{
    GlobalFallback, ProfileError, ProviderConfig, RetryPolicy, RoutingProfile, StageFallback,
    load_profile, load_profile_by_id,
};

/// Errors that can occur during routing.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum RouterError {
    /// Profile error.
    #[error("{0}")]
    Profile(#[from] ProfileError),

    /// Stage not found in profile.
    #[error("stage '{stage}' not found in profile '{profile_id}'")]
    StageNotFound {
        /// Profile ID.
        profile_id: String,
        /// Stage name.
        stage: String,
    },

    /// Provider unavailable.
    #[error("provider '{provider}' is unavailable for stage '{stage}': {reason}")]
    ProviderUnavailable {
        /// Provider identifier.
        provider: String,
        /// Stage name.
        stage: String,
        /// Reason for unavailability.
        reason: String,
    },

    /// No fallback configured.
    #[error("provider '{provider}' unavailable for stage '{stage}' and no fallback configured")]
    NoFallbackConfigured {
        /// Provider identifier.
        provider: String,
        /// Stage name.
        stage: String,
    },

    /// Fallback also unavailable.
    #[error("fallback provider '{fallback}' also unavailable for stage '{stage}': {reason}")]
    FallbackUnavailable {
        /// Stage name.
        stage: String,
        /// Fallback provider identifier.
        fallback: String,
        /// Reason for unavailability.
        reason: String,
    },
}

/// Provider availability status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderStatus {
    /// Provider is available and ready.
    Available,
    /// Provider is unavailable with a reason.
    Unavailable(String),
    /// Provider status is unknown (not checked).
    Unknown,
}

/// Trait for checking provider availability.
///
/// This trait allows different implementations for testing vs production.
pub trait ProviderAvailability: Send + Sync {
    /// Checks if a provider is available.
    ///
    /// # Arguments
    ///
    /// * `provider` - The provider identifier to check.
    /// * `endpoint` - Optional custom endpoint URL.
    ///
    /// # Returns
    ///
    /// The availability status of the provider.
    fn check_availability(&self, provider: &str, endpoint: Option<&str>) -> ProviderStatus;
}

/// Default provider availability checker that assumes all providers are
/// available.
///
/// In production, this would be replaced with an implementation that actually
/// checks provider endpoints.
#[derive(Debug, Clone, Default)]
pub struct DefaultProviderAvailability {
    /// Set of providers marked as unavailable for testing.
    unavailable_providers: HashSet<String>,
}

impl DefaultProviderAvailability {
    /// Creates a new default availability checker.
    #[must_use]
    pub fn new() -> Self {
        Self {
            unavailable_providers: HashSet::new(),
        }
    }

    /// Marks a provider as unavailable (for testing).
    pub fn mark_unavailable(&mut self, provider: &str) {
        self.unavailable_providers.insert(provider.to_string());
    }

    /// Marks a provider as available (for testing).
    pub fn mark_available(&mut self, provider: &str) {
        self.unavailable_providers.remove(provider);
    }
}

impl ProviderAvailability for DefaultProviderAvailability {
    fn check_availability(&self, provider: &str, _endpoint: Option<&str>) -> ProviderStatus {
        if self.unavailable_providers.contains(provider) {
            ProviderStatus::Unavailable("provider marked as unavailable".to_string())
        } else {
            // All providers are available if not explicitly marked unavailable.
            // In production, we'd check endpoints for remote providers.
            ProviderStatus::Available
        }
    }
}

/// Result of a routing decision.
#[derive(Debug, Clone)]
pub struct RouteResult {
    /// The provider configuration to use.
    pub config: ProviderConfig,

    /// Whether this is a fallback route.
    pub is_fallback: bool,

    /// Fallback reason if using fallback.
    pub fallback_reason: Option<String>,
}

/// Model router that routes pipeline stages to providers.
#[derive(Debug)]
pub struct ModelRouter<A: ProviderAvailability = DefaultProviderAvailability> {
    /// The loaded routing profile.
    profile: RoutingProfile,

    /// Provider availability checker.
    availability: A,
}

impl ModelRouter<DefaultProviderAvailability> {
    /// Creates a new model router from a profile path.
    ///
    /// # Arguments
    ///
    /// * `profile_path` - Path to the routing profile YAML file.
    ///
    /// # Errors
    ///
    /// Returns an error if the profile cannot be loaded or validated.
    pub fn from_file(profile_path: &Path) -> Result<Self, RouterError> {
        let profile = load_profile(profile_path)?;
        Ok(Self {
            profile,
            availability: DefaultProviderAvailability::new(),
        })
    }

    /// Creates a new model router from a profile ID.
    ///
    /// # Arguments
    ///
    /// * `repo_root` - Path to the repository root.
    /// * `profile_id` - The profile ID to load.
    ///
    /// # Errors
    ///
    /// Returns an error if the profile cannot be loaded or validated.
    pub fn from_profile_id(repo_root: &Path, profile_id: &str) -> Result<Self, RouterError> {
        let profile = load_profile_by_id(repo_root, profile_id)?;
        Ok(Self {
            profile,
            availability: DefaultProviderAvailability::new(),
        })
    }

    /// Creates a new model router from an existing profile.
    ///
    /// # Arguments
    ///
    /// * `profile` - The routing profile to use.
    #[must_use]
    pub fn from_profile(profile: RoutingProfile) -> Self {
        Self {
            profile,
            availability: DefaultProviderAvailability::new(),
        }
    }
}

impl<A: ProviderAvailability> ModelRouter<A> {
    /// Creates a new model router with a custom availability checker.
    ///
    /// # Arguments
    ///
    /// * `profile` - The routing profile to use.
    /// * `availability` - The provider availability checker.
    #[must_use]
    pub const fn with_availability(profile: RoutingProfile, availability: A) -> Self {
        Self {
            profile,
            availability,
        }
    }

    /// Gets the loaded routing profile.
    #[must_use]
    pub const fn profile(&self) -> &RoutingProfile {
        &self.profile
    }

    /// Gets the profile ID.
    #[must_use]
    pub fn profile_id(&self) -> &str {
        &self.profile.profile_id
    }

    /// Routes a stage to the appropriate provider.
    ///
    /// This method implements fail-closed semantics:
    /// 1. Look up the stage configuration
    /// 2. Check if the primary provider is available
    /// 3. If unavailable, try stage-specific fallback
    /// 4. If still unavailable, try global fallback
    /// 5. If no fallback works, return an error
    ///
    /// # Arguments
    ///
    /// * `stage` - The stage name to route.
    ///
    /// # Returns
    ///
    /// The routing result with provider configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The stage is not found in the profile
    /// - The provider is unavailable and no fallback is configured
    /// - All fallbacks are also unavailable
    pub fn route_stage(&self, stage: &str) -> Result<RouteResult, RouterError> {
        debug!(stage = %stage, profile_id = %self.profile.profile_id, "Routing stage");

        // Look up stage configuration
        let stage_config =
            self.profile
                .get_stage_config(stage)
                .ok_or_else(|| RouterError::StageNotFound {
                    profile_id: self.profile.profile_id.clone(),
                    stage: stage.to_string(),
                })?;

        // Check primary provider availability
        let primary_status = self
            .availability
            .check_availability(&stage_config.provider, stage_config.endpoint.as_deref());

        match primary_status {
            ProviderStatus::Available => {
                info!(
                    stage = %stage,
                    provider = %stage_config.provider,
                    "Routed stage to primary provider"
                );
                Ok(RouteResult {
                    config: stage_config.clone(),
                    is_fallback: false,
                    fallback_reason: None,
                })
            },
            ProviderStatus::Unavailable(reason) => {
                warn!(
                    stage = %stage,
                    provider = %stage_config.provider,
                    reason = %reason,
                    "Primary provider unavailable, attempting fallback"
                );
                self.try_fallback(stage, stage_config, &reason)
            },
            ProviderStatus::Unknown => {
                // Treat unknown as available (optimistic)
                debug!(
                    stage = %stage,
                    provider = %stage_config.provider,
                    "Provider status unknown, assuming available"
                );
                Ok(RouteResult {
                    config: stage_config.clone(),
                    is_fallback: false,
                    fallback_reason: None,
                })
            },
        }
    }

    /// Attempts to use a fallback provider.
    fn try_fallback(
        &self,
        stage: &str,
        stage_config: &ProviderConfig,
        primary_reason: &str,
    ) -> Result<RouteResult, RouterError> {
        // Try stage-specific fallback first
        if let Some(stage_fallback) = &stage_config.stage_fallback {
            let fallback_status = self
                .availability
                .check_availability(&stage_fallback.provider, None);

            match fallback_status {
                ProviderStatus::Available | ProviderStatus::Unknown => {
                    info!(
                        stage = %stage,
                        fallback_provider = %stage_fallback.provider,
                        "Using stage-specific fallback"
                    );
                    return Ok(RouteResult {
                        config: Self::fallback_to_provider_config(stage_fallback),
                        is_fallback: true,
                        fallback_reason: Some(format!(
                            "Primary provider '{}' unavailable: {}",
                            stage_config.provider, primary_reason
                        )),
                    });
                },
                ProviderStatus::Unavailable(reason) => {
                    warn!(
                        stage = %stage,
                        fallback_provider = %stage_fallback.provider,
                        reason = %reason,
                        "Stage fallback also unavailable"
                    );
                },
            }
        }

        // Try global fallback
        if let Some(global_fallback) = &self.profile.fallback {
            let fallback_status = self
                .availability
                .check_availability(&global_fallback.provider, None);

            match fallback_status {
                ProviderStatus::Available | ProviderStatus::Unknown => {
                    info!(
                        stage = %stage,
                        fallback_provider = %global_fallback.provider,
                        "Using global fallback"
                    );
                    return Ok(RouteResult {
                        config: Self::global_fallback_to_provider_config(global_fallback),
                        is_fallback: true,
                        fallback_reason: Some(global_fallback.reason.clone().unwrap_or_else(
                            || {
                                format!(
                                    "Primary provider '{}' unavailable: {}",
                                    stage_config.provider, primary_reason
                                )
                            },
                        )),
                    });
                },
                ProviderStatus::Unavailable(reason) => {
                    return Err(RouterError::FallbackUnavailable {
                        stage: stage.to_string(),
                        fallback: global_fallback.provider.clone(),
                        reason,
                    });
                },
            }
        }

        // No fallback configured
        Err(RouterError::NoFallbackConfigured {
            provider: stage_config.provider.clone(),
            stage: stage.to_string(),
        })
    }

    /// Converts a stage fallback to a provider config.
    fn fallback_to_provider_config(fallback: &StageFallback) -> ProviderConfig {
        ProviderConfig {
            provider: fallback.provider.clone(),
            model: fallback.model.clone(),
            endpoint: None,
            timeout_ms: fallback.timeout_ms,
            retry_policy: RetryPolicy::default(),
            stage_fallback: None,
        }
    }

    /// Converts a global fallback to a provider config.
    fn global_fallback_to_provider_config(fallback: &GlobalFallback) -> ProviderConfig {
        ProviderConfig {
            provider: fallback.provider.clone(),
            model: fallback.model.clone(),
            endpoint: None,
            timeout_ms: fallback.timeout_ms,
            retry_policy: RetryPolicy::default(),
            stage_fallback: None,
        }
    }

    /// Checks if a stage is defined in the profile.
    #[must_use]
    pub fn has_stage(&self, stage: &str) -> bool {
        self.profile.has_stage(stage)
    }

    /// Gets all stage names defined in the profile.
    #[must_use]
    pub fn stage_names(&self) -> Vec<&str> {
        self.profile.stage_names()
    }

    /// Routes multiple stages at once, returning all results.
    ///
    /// # Arguments
    ///
    /// * `stages` - The stage names to route.
    ///
    /// # Returns
    ///
    /// A vector of tuples (`stage_name`, result) for each stage.
    pub fn route_stages<'a>(
        &self,
        stages: &[&'a str],
    ) -> Vec<(&'a str, Result<RouteResult, RouterError>)> {
        stages
            .iter()
            .map(|&stage| (stage, self.route_stage(stage)))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::*;

    /// Creates a test routing profile.
    fn create_test_router() -> ModelRouter<DefaultProviderAvailability> {
        let temp_dir = TempDir::new().unwrap();
        let content = r"
routing_profile:
  profile_id: test-router
  description: Test routing profile.
  stages:
    ccp_build:
      provider: local
      timeout_ms: 30000
    impact_map:
      provider: anthropic
      model: claude-3-5-sonnet
      timeout_ms: 60000
      stage_fallback:
        provider: openai
        model: gpt-4
        timeout_ms: 60000
    rfc_frame:
      provider: anthropic
      model: claude-3-5-sonnet
      timeout_ms: 120000
  fallback:
    provider: local
    timeout_ms: 30000
    reason: Global fallback to local provider.
";
        let path = temp_dir.path().join("test.yaml");
        fs::write(&path, content).unwrap();
        ModelRouter::from_file(&path).unwrap()
    }

    /// UT-118-03: Test successful stage routing.
    #[test]
    fn test_route_stage_success() {
        let router = create_test_router();

        let result = router.route_stage("ccp_build").unwrap();
        assert_eq!(result.config.provider, "local");
        assert!(!result.is_fallback);
        assert!(result.fallback_reason.is_none());

        let result = router.route_stage("impact_map").unwrap();
        assert_eq!(result.config.provider, "anthropic");
        assert_eq!(result.config.model, Some("claude-3-5-sonnet".to_string()));
        assert!(!result.is_fallback);
    }

    /// UT-118-03: Test stage not found error.
    #[test]
    fn test_route_stage_not_found() {
        let router = create_test_router();

        let result = router.route_stage("nonexistent");
        assert!(matches!(result, Err(RouterError::StageNotFound { .. })));
    }

    /// UT-118-04: Test fail-closed semantics - no fallback configured.
    #[test]
    fn test_fail_closed_no_fallback() {
        let temp_dir = TempDir::new().unwrap();
        let content = r"
routing_profile:
  profile_id: no-fallback
  description: Profile without fallback.
  stages:
    test_stage:
      provider: remote
      timeout_ms: 30000
";
        let path = temp_dir.path().join("test.yaml");
        fs::write(&path, content).unwrap();

        let profile = super::super::profile::load_profile(&path).unwrap();
        let mut availability = DefaultProviderAvailability::new();
        availability.mark_unavailable("remote");

        let router = ModelRouter::with_availability(profile, availability);
        let result = router.route_stage("test_stage");

        assert!(matches!(
            result,
            Err(RouterError::NoFallbackConfigured { .. })
        ));
    }

    /// UT-118-04: Test stage-specific fallback.
    #[test]
    fn test_stage_specific_fallback() {
        let router = create_test_router();

        // Create a router with anthropic marked as unavailable
        let profile = router.profile().clone();
        let mut availability = DefaultProviderAvailability::new();
        availability.mark_unavailable("anthropic");

        let router = ModelRouter::with_availability(profile, availability);
        let result = router.route_stage("impact_map").unwrap();

        assert_eq!(result.config.provider, "openai");
        assert!(result.is_fallback);
        assert!(result.fallback_reason.is_some());
    }

    /// UT-118-04: Test global fallback.
    #[test]
    fn test_global_fallback() {
        let router = create_test_router();

        // Mark anthropic as unavailable for rfc_frame (which has no stage fallback)
        let profile = router.profile().clone();
        let mut availability = DefaultProviderAvailability::new();
        availability.mark_unavailable("anthropic");

        let router = ModelRouter::with_availability(profile, availability);
        let result = router.route_stage("rfc_frame").unwrap();

        assert_eq!(result.config.provider, "local");
        assert!(result.is_fallback);
        assert_eq!(
            result.fallback_reason,
            Some("Global fallback to local provider.".to_string())
        );
    }

    /// UT-118-04: Test fallback chain exhaustion.
    #[test]
    fn test_fallback_chain_exhausted() {
        let router = create_test_router();

        // Mark all providers as unavailable
        let profile = router.profile().clone();
        let mut availability = DefaultProviderAvailability::new();
        availability.mark_unavailable("anthropic");
        availability.mark_unavailable("openai");
        availability.mark_unavailable("local");

        let router = ModelRouter::with_availability(profile, availability);
        let result = router.route_stage("impact_map");

        assert!(matches!(
            result,
            Err(RouterError::FallbackUnavailable { .. })
        ));
    }

    /// Test router helper methods.
    #[test]
    fn test_router_helpers() {
        let router = create_test_router();

        assert!(router.has_stage("ccp_build"));
        assert!(router.has_stage("impact_map"));
        assert!(!router.has_stage("nonexistent"));

        let stages = router.stage_names();
        assert!(stages.contains(&"ccp_build"));
        assert!(stages.contains(&"impact_map"));
        assert!(stages.contains(&"rfc_frame"));
    }

    /// Test `route_stages` batch routing.
    #[test]
    fn test_route_stages_batch() {
        let router = create_test_router();

        let results = router.route_stages(&["ccp_build", "impact_map", "nonexistent"]);

        assert_eq!(results.len(), 3);
        assert!(results[0].1.is_ok());
        assert!(results[1].1.is_ok());
        assert!(results[2].1.is_err());
    }

    /// Test `profile_id` accessor.
    #[test]
    fn test_profile_id() {
        let router = create_test_router();
        assert_eq!(router.profile_id(), "test-router");
    }
}
