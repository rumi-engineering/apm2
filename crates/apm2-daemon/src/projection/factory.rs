//! Projection adapter factory and provider-neutral target descriptors.
//!
//! This module is intentionally small and fail-closed:
//! - Only explicitly supported surfaces can be constructed.
//! - Surface selection and target identity are typed inputs.
//! - Token material stays in `SecretString` until adapter construction.

use std::path::PathBuf;

use apm2_core::crypto::Signer;
use secrecy::{ExposeSecret, SecretString};

use super::github_sync::{
    GitHubAdapterConfig, GitHubProjectionAdapter, ProjectionAdapter, ProjectionError,
};

/// Supported projection surface kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectionSurface {
    /// GitHub projection surface.
    GitHub,
}

impl ProjectionSurface {
    /// Returns the canonical lowercase surface name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GitHub => "github",
        }
    }
}

/// Provider-neutral projection target descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectionTarget {
    /// Surface family.
    pub surface: ProjectionSurface,
    /// API base URL.
    pub api_base_url: String,
    /// Namespace (e.g., owner/workspace/group).
    pub namespace: String,
    /// Project identifier (e.g., repo/slug).
    pub project: String,
}

impl ProjectionTarget {
    /// Creates a GitHub target descriptor.
    #[must_use]
    pub fn github(
        api_base_url: impl Into<String>,
        namespace: impl Into<String>,
        project: impl Into<String>,
    ) -> Self {
        Self {
            surface: ProjectionSurface::GitHub,
            api_base_url: api_base_url.into(),
            namespace: namespace.into(),
            project: project.into(),
        }
    }

    /// Returns a stable human-readable target identifier.
    #[must_use]
    pub fn target_id(&self) -> String {
        format!("{}/{}", self.namespace, self.project)
    }
}

/// Build input for constructing a projection adapter.
#[derive(Debug, Clone)]
pub struct ProjectionAdapterBuildSpec {
    /// Target descriptor.
    pub target: ProjectionTarget,
    /// Surface-scoped auth token.
    pub token: SecretString,
    /// Persistent idempotency cache path.
    pub cache_path: PathBuf,
}

/// Factory for projection adapters.
pub trait ProjectionAdapterFactory: Send + Sync {
    /// Builds a projection adapter for the requested target.
    ///
    /// # Errors
    ///
    /// Returns an error when target configuration is invalid or adapter
    /// construction fails.
    fn build(
        &self,
        signer: Signer,
        spec: ProjectionAdapterBuildSpec,
    ) -> Result<Box<dyn ProjectionAdapter>, ProjectionError>;
}

/// Default fail-closed adapter factory.
#[derive(Debug, Default, Clone, Copy)]
pub struct DefaultProjectionAdapterFactory;

impl ProjectionAdapterFactory for DefaultProjectionAdapterFactory {
    fn build(
        &self,
        signer: Signer,
        spec: ProjectionAdapterBuildSpec,
    ) -> Result<Box<dyn ProjectionAdapter>, ProjectionError> {
        match spec.target.surface {
            ProjectionSurface::GitHub => {
                let github_config = GitHubAdapterConfig::new(
                    &spec.target.api_base_url,
                    &spec.target.namespace,
                    &spec.target.project,
                )?
                .with_api_token(spec.token.expose_secret())?;
                let adapter =
                    GitHubProjectionAdapter::new(signer, github_config, &spec.cache_path)?;
                Ok(Box::new(adapter))
            },
        }
    }
}
