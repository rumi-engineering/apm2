//! GitHub App access control for holonic agents.
//!
//! This module implements a tiered GitHub App architecture that maps to the
//! APM2 risk tier system (LOW/MED/HIGH per RFC-0015), providing
//! capability-bound, auditable GitHub access for AI agents.
//!
//! # Architecture
//!
//! Three GitHub Apps are mapped to risk tiers:
//!
//! | App | Risk Tier | Permissions | Token TTL |
//! |-----|-----------|-------------|-----------|
//! | `apm2-reader` | LOW | `contents:read`, `metadata:read` | 1 hour |
//! | `apm2-developer` | MED | + `pull_requests:write`, `checks:write` | 15 min |
//! | `apm2-operator` | HIGH | + `contents:write`, `admin:read` | 2 min |
//!
//! # Security Properties
//!
//! - Raw tokens are **never** stored in the ledger (only hashes)
//! - Token TTLs are proportional to risk tier (shorter for higher tiers)
//! - Scope attenuation only (cannot escalate permissions)
//! - All operations are audited for non-repudiation
//!
//! # Key Concepts
//!
//! - **`GitHubApp`**: Enum representing the three apps (Reader, Developer,
//!   Operator)
//! - **`GitHubScope`**: Permission scopes granted by each app
//! - **`GitHubLease`**: A time-bounded grant to use a GitHub installation token
//! - **`TokenProvider`**: Mints installation access tokens for a given
//!   app/installation
//!
//! # Example
//!
//! ```rust
//! use apm2_core::github::{GitHubApp, GitHubScope, RiskTier};
//!
//! // Determine which app a tier can use
//! let tier = RiskTier::Med;
//! let apps = tier.allowed_apps();
//! assert!(apps.contains(&GitHubApp::Reader));
//! assert!(apps.contains(&GitHubApp::Developer));
//! assert!(!apps.contains(&GitHubApp::Operator));
//!
//! // Check if a scope is allowed for an app
//! let app = GitHubApp::Developer;
//! assert!(app.allows_scope(GitHubScope::ContentsRead));
//! assert!(app.allows_scope(GitHubScope::PullRequestsWrite));
//! assert!(!app.allows_scope(GitHubScope::AdminRead));
//! ```

mod error;
mod lease;
mod scope;
mod token_provider;

pub use error::GitHubError;
pub use lease::{GitHubLease, GitHubLeaseState, RevocationReason};
pub use scope::{GitHubApp, GitHubScope, RiskTier};
pub use token_provider::{
    GitHubAppTokenProvider, MockTokenProvider, RateLimitedTokenProvider, TokenProvider,
    TokenRequest, TokenResponse,
};

/// Maximum length for GitHub App IDs.
pub const MAX_APP_ID_LEN: usize = 64;

/// Maximum length for installation IDs.
pub const MAX_INSTALLATION_ID_LEN: usize = 64;

/// Maximum length for lease IDs.
pub const MAX_LEASE_ID_LEN: usize = 128;

/// Maximum length for episode IDs.
pub const MAX_EPISODE_ID_LEN: usize = 128;

/// Maximum length for actor IDs.
pub const MAX_ACTOR_ID_LEN: usize = 128;

/// Maximum length for repository identifiers (owner/repo).
pub const MAX_REPOSITORY_LEN: usize = 256;

/// Maximum length for API endpoint strings.
pub const MAX_API_ENDPOINT_LEN: usize = 512;

/// Maximum number of scopes that can be requested in a single lease.
pub const MAX_SCOPES_PER_LEASE: usize = 16;

/// Validates an API endpoint string for audit events.
///
/// An API endpoint must:
/// - Start with `/`
/// - Not contain path traversal sequences (`..`)
/// - Not contain control characters (ASCII < 32 or DEL)
/// - Not exceed `MAX_API_ENDPOINT_LEN`
///
/// # Examples
///
/// ```
/// use apm2_core::github::validate_api_endpoint;
///
/// assert!(validate_api_endpoint("/repos/owner/repo/pulls").is_ok());
/// assert!(validate_api_endpoint("repos/owner/repo").is_err()); // missing leading /
/// assert!(validate_api_endpoint("/repos/../etc/passwd").is_err()); // path traversal
/// ```
///
/// # Errors
///
/// Returns `GitHubError::InvalidApiEndpoint` if the endpoint is invalid.
pub fn validate_api_endpoint(endpoint: &str) -> Result<(), GitHubError> {
    // Check length
    if endpoint.len() > MAX_API_ENDPOINT_LEN {
        return Err(GitHubError::InvalidApiEndpoint {
            reason: format!(
                "length {} exceeds maximum {}",
                endpoint.len(),
                MAX_API_ENDPOINT_LEN
            ),
        });
    }

    // Must start with /
    if !endpoint.starts_with('/') {
        return Err(GitHubError::InvalidApiEndpoint {
            reason: "must start with '/'".to_string(),
        });
    }

    // Check for path traversal sequences
    if endpoint.contains("..") {
        return Err(GitHubError::InvalidApiEndpoint {
            reason: "contains path traversal sequence '..'".to_string(),
        });
    }

    // Check for control characters (ASCII 0-31 and 127 DEL)
    if endpoint.chars().any(|c| c.is_ascii_control()) {
        return Err(GitHubError::InvalidApiEndpoint {
            reason: "contains control characters".to_string(),
        });
    }

    Ok(())
}

/// Validates a repository identifier for audit events.
///
/// A repository must:
/// - Be in the format `owner/repo`
/// - Owner and repo names contain only alphanumeric characters, hyphens,
///   underscores, and dots
/// - Owner and repo names must not be empty
/// - Owner and repo names must start with an alphanumeric character
/// - Not exceed `MAX_REPOSITORY_LEN`
///
/// # Examples
///
/// ```
/// use apm2_core::github::validate_repository;
///
/// assert!(validate_repository("anthropics/apm2").is_ok());
/// assert!(validate_repository("my-org/my_repo.rs").is_ok());
/// assert!(validate_repository("owner").is_err()); // missing /repo
/// assert!(validate_repository("owner/repo/extra").is_err()); // too many segments
/// assert!(validate_repository("-owner/repo").is_err()); // starts with hyphen
/// ```
///
/// # Errors
///
/// Returns `GitHubError::InvalidRepository` if the repository is invalid.
pub fn validate_repository(repository: &str) -> Result<(), GitHubError> {
    // Check length
    if repository.len() > MAX_REPOSITORY_LEN {
        return Err(GitHubError::InvalidRepository {
            reason: format!(
                "length {} exceeds maximum {}",
                repository.len(),
                MAX_REPOSITORY_LEN
            ),
        });
    }

    // Split into owner and repo
    let parts: Vec<&str> = repository.split('/').collect();
    if parts.len() != 2 {
        return Err(GitHubError::InvalidRepository {
            reason: "must be in 'owner/repo' format".to_string(),
        });
    }

    let owner = parts[0];
    let repo = parts[1];

    // Validate owner
    validate_repository_segment(owner, "owner")?;

    // Validate repo
    validate_repository_segment(repo, "repo")?;

    Ok(())
}

/// Validates a single segment (owner or repo) of a repository identifier.
fn validate_repository_segment(segment: &str, name: &str) -> Result<(), GitHubError> {
    if segment.is_empty() {
        return Err(GitHubError::InvalidRepository {
            reason: format!("{name} cannot be empty"),
        });
    }

    // Must start with alphanumeric
    let first_char = segment.chars().next().unwrap();
    if !first_char.is_ascii_alphanumeric() {
        return Err(GitHubError::InvalidRepository {
            reason: format!("{name} must start with an alphanumeric character"),
        });
    }

    // All characters must be alphanumeric, hyphen, underscore, or dot
    for c in segment.chars() {
        if !c.is_ascii_alphanumeric() && c != '-' && c != '_' && c != '.' {
            return Err(GitHubError::InvalidRepository {
                reason: format!(
                    "{name} contains invalid character '{c}' (allowed: alphanumeric, -, _, .)"
                ),
            });
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests;
