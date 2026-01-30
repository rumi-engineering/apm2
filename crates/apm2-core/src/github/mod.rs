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
pub use token_provider::{MockTokenProvider, TokenProvider, TokenRequest, TokenResponse};

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

#[cfg(test)]
mod tests;
