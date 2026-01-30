//! GitHub permission scope and risk tier definitions.
//!
//! This module defines the mapping between APM2 risk tiers and GitHub App
//! permissions. The design follows the principle of least privilege with
//! tiered escalation.

use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Risk tier for an agent (HIGH, MED, LOW).
///
/// Aligned with RFC-0015 risk-tiered AAT selection policy.
/// Higher risk tiers have more permissions but shorter TTLs for containment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum RiskTier {
    /// Low risk: Read-only access. Longest TTL, sampled AAT.
    Low  = 0,
    /// Medium risk: Can create PRs and update checks. Conditional AAT.
    Med  = 1,
    /// High risk: Full operator access. Always requires AAT, shortest TTL.
    High = 2,
}

impl RiskTier {
    /// Returns all GitHub Apps this tier is allowed to use.
    ///
    /// Tiers can use apps at or below their permission level.
    #[must_use]
    pub fn allowed_apps(&self) -> Vec<GitHubApp> {
        match self {
            Self::Low => vec![GitHubApp::Reader],
            Self::Med => vec![GitHubApp::Reader, GitHubApp::Developer],
            Self::High => {
                vec![GitHubApp::Reader, GitHubApp::Developer, GitHubApp::Operator]
            },
        }
    }

    /// Returns the maximum GitHub App tier this risk tier can use.
    #[must_use]
    pub const fn max_app(&self) -> GitHubApp {
        match self {
            Self::Low => GitHubApp::Reader,
            Self::Med => GitHubApp::Developer,
            Self::High => GitHubApp::Operator,
        }
    }

    /// Returns the default token TTL for this tier.
    ///
    /// Higher risk tiers get shorter TTLs for containment.
    #[must_use]
    pub const fn default_ttl(&self) -> Duration {
        match self {
            Self::Low => Duration::from_secs(3600), // 1 hour
            Self::Med => Duration::from_secs(900),  // 15 minutes
            Self::High => Duration::from_secs(120), // 2 minutes
        }
    }

    /// Returns the maximum token TTL for this tier.
    ///
    /// Token TTLs cannot exceed this value even if requested.
    #[must_use]
    pub const fn max_ttl(&self) -> Duration {
        match self {
            Self::Low => Duration::from_secs(3600), // 1 hour
            Self::Med => Duration::from_secs(1800), // 30 minutes
            Self::High => Duration::from_secs(300), // 5 minutes
        }
    }

    /// Returns this tier as a string.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Low => "LOW",
            Self::Med => "MED",
            Self::High => "HIGH",
        }
    }
}

impl std::str::FromStr for RiskTier {
    type Err = InvalidRiskTier;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_uppercase().as_str() {
            "LOW" => Ok(Self::Low),
            "MED" | "MEDIUM" => Ok(Self::Med),
            "HIGH" => Ok(Self::High),
            _ => Err(InvalidRiskTier {
                value: value.to_string(),
            }),
        }
    }
}

impl std::fmt::Display for RiskTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Error returned when parsing an invalid risk tier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidRiskTier {
    /// The invalid value.
    pub value: String,
}

impl std::fmt::Display for InvalidRiskTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "invalid risk tier: '{}' (must be LOW, MED, or HIGH)",
            self.value
        )
    }
}

impl std::error::Error for InvalidRiskTier {}

/// GitHub App types with tiered permissions.
///
/// Each app corresponds to a set of GitHub permissions and is intended
/// for use by agents at specific risk tiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum GitHubApp {
    /// Read-only app for LOW risk agents.
    /// Permissions: `contents:read`, `metadata:read`
    Reader,

    /// Developer app for MED risk agents.
    /// Permissions: Reader + `pull_requests:write`, `checks:write`,
    /// `statuses:write`
    Developer,

    /// Operator app for HIGH risk agents.
    /// Permissions: Developer + `contents:write`, `admin:read`,
    /// `releases:write`
    Operator,
}

impl GitHubApp {
    /// Returns the set of scopes granted by this app.
    #[must_use]
    pub fn scopes(&self) -> Vec<GitHubScope> {
        match self {
            Self::Reader => vec![GitHubScope::ContentsRead, GitHubScope::MetadataRead],
            Self::Developer => vec![
                GitHubScope::ContentsRead,
                GitHubScope::MetadataRead,
                GitHubScope::PullRequestsWrite,
                GitHubScope::ChecksWrite,
                GitHubScope::StatusesWrite,
            ],
            Self::Operator => vec![
                GitHubScope::ContentsRead,
                GitHubScope::MetadataRead,
                GitHubScope::PullRequestsWrite,
                GitHubScope::ChecksWrite,
                GitHubScope::StatusesWrite,
                GitHubScope::ContentsWrite,
                GitHubScope::AdminRead,
                GitHubScope::ReleasesWrite,
            ],
        }
    }

    /// Returns true if this app grants the given scope.
    #[must_use]
    pub fn allows_scope(self, scope: GitHubScope) -> bool {
        self.scopes().contains(&scope)
    }

    /// Returns the minimum risk tier required to use this app.
    #[must_use]
    pub const fn min_tier(&self) -> RiskTier {
        match self {
            Self::Reader => RiskTier::Low,
            Self::Developer => RiskTier::Med,
            Self::Operator => RiskTier::High,
        }
    }

    /// Returns the canonical app name.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Reader => "apm2-reader",
            Self::Developer => "apm2-developer",
            Self::Operator => "apm2-operator",
        }
    }

    /// Parses a GitHub app from its canonical name.
    ///
    /// # Errors
    ///
    /// Returns an error if the name is not recognized.
    pub fn from_name(name: &str) -> Result<Self, InvalidAppName> {
        match name {
            "apm2-reader" | "reader" => Ok(Self::Reader),
            "apm2-developer" | "developer" => Ok(Self::Developer),
            "apm2-operator" | "operator" => Ok(Self::Operator),
            _ => Err(InvalidAppName {
                name: name.to_string(),
            }),
        }
    }
}

impl std::fmt::Display for GitHubApp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Error returned when parsing an invalid app name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidAppName {
    /// The invalid name.
    pub name: String,
}

impl std::fmt::Display for InvalidAppName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "invalid GitHub app name: '{}' (expected: apm2-reader, apm2-developer, apm2-operator)",
            self.name
        )
    }
}

impl std::error::Error for InvalidAppName {}

/// GitHub permission scopes.
///
/// These correspond to GitHub App permissions and are used to determine
/// what operations an agent can perform.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum GitHubScope {
    /// Read repository contents (files, commits).
    ContentsRead,
    /// Read repository metadata (stars, forks, settings).
    MetadataRead,
    /// Create and update pull requests.
    PullRequestsWrite,
    /// Create and update check runs.
    ChecksWrite,
    /// Create and update commit statuses.
    StatusesWrite,
    /// Write to repository contents (push commits).
    ContentsWrite,
    /// Read repository admin settings.
    AdminRead,
    /// Create and manage releases.
    ReleasesWrite,
}

impl GitHubScope {
    /// Returns the canonical scope name as used in GitHub API.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::ContentsRead => "contents:read",
            Self::MetadataRead => "metadata:read",
            Self::PullRequestsWrite => "pull_requests:write",
            Self::ChecksWrite => "checks:write",
            Self::StatusesWrite => "statuses:write",
            Self::ContentsWrite => "contents:write",
            Self::AdminRead => "admin:read",
            Self::ReleasesWrite => "releases:write",
        }
    }

    /// Parses a scope from its canonical string representation.
    ///
    /// # Errors
    ///
    /// Returns an error if the string is not a recognized scope.
    pub fn parse(s: &str) -> Result<Self, InvalidScope> {
        match s {
            "contents:read" => Ok(Self::ContentsRead),
            "metadata:read" => Ok(Self::MetadataRead),
            "pull_requests:write" => Ok(Self::PullRequestsWrite),
            "checks:write" => Ok(Self::ChecksWrite),
            "statuses:write" => Ok(Self::StatusesWrite),
            "contents:write" => Ok(Self::ContentsWrite),
            "admin:read" => Ok(Self::AdminRead),
            "releases:write" => Ok(Self::ReleasesWrite),
            _ => Err(InvalidScope {
                scope: s.to_string(),
            }),
        }
    }

    /// Returns true if this is a write scope.
    #[must_use]
    pub const fn is_write(&self) -> bool {
        matches!(
            self,
            Self::PullRequestsWrite
                | Self::ChecksWrite
                | Self::StatusesWrite
                | Self::ContentsWrite
                | Self::ReleasesWrite
        )
    }
}

impl std::fmt::Display for GitHubScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Error returned when parsing an invalid scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidScope {
    /// The invalid scope string.
    pub scope: String,
}

impl std::fmt::Display for InvalidScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid GitHub scope: '{}'", self.scope)
    }
}

impl std::error::Error for InvalidScope {}

/// Validates that a risk tier can use a GitHub app.
///
/// # Errors
///
/// Returns an error if the tier is not allowed to use the app.
#[allow(dead_code)] // Used in tests; will be used by reducers when integrated
pub fn validate_tier_app(tier: RiskTier, app: GitHubApp) -> Result<(), TierAppMismatch> {
    if tier.allowed_apps().contains(&app) {
        Ok(())
    } else {
        Err(TierAppMismatch { tier, app })
    }
}

/// Error returned when a tier cannot use an app.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // Used in tests; will be used by reducers when integrated
pub struct TierAppMismatch {
    /// The risk tier.
    pub tier: RiskTier,
    /// The app that was requested.
    pub app: GitHubApp,
}

impl std::fmt::Display for TierAppMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "risk tier {} cannot use app {} (requires {}+)",
            self.tier,
            self.app,
            self.app.min_tier()
        )
    }
}

impl std::error::Error for TierAppMismatch {}

/// Validates that an app allows a set of scopes.
///
/// # Errors
///
/// Returns an error listing the first disallowed scope.
#[allow(dead_code)] // Used in tests; will be used by reducers when integrated
pub fn validate_app_scopes(app: GitHubApp, scopes: &[GitHubScope]) -> Result<(), ScopeNotAllowed> {
    for scope in scopes {
        if !app.allows_scope(*scope) {
            return Err(ScopeNotAllowed { app, scope: *scope });
        }
    }
    Ok(())
}

/// Error returned when a scope is not allowed for an app.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // Used in tests; will be used by reducers when integrated
pub struct ScopeNotAllowed {
    /// The app.
    pub app: GitHubApp,
    /// The scope that is not allowed.
    pub scope: GitHubScope,
}

impl std::fmt::Display for ScopeNotAllowed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "app {} does not allow scope {} (requires {}+)",
            self.app,
            self.scope,
            self.scope_min_app()
        )
    }
}

impl ScopeNotAllowed {
    /// Returns the minimum app required for this scope.
    #[allow(dead_code)] // Used in Display impl
    const fn scope_min_app(self) -> GitHubApp {
        match self.scope {
            GitHubScope::ContentsRead | GitHubScope::MetadataRead => GitHubApp::Reader,
            GitHubScope::PullRequestsWrite
            | GitHubScope::ChecksWrite
            | GitHubScope::StatusesWrite => GitHubApp::Developer,
            GitHubScope::ContentsWrite | GitHubScope::AdminRead | GitHubScope::ReleasesWrite => {
                GitHubApp::Operator
            },
        }
    }
}

impl std::error::Error for ScopeNotAllowed {}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn test_risk_tier_allowed_apps() {
        assert_eq!(RiskTier::Low.allowed_apps(), vec![GitHubApp::Reader]);
        assert_eq!(
            RiskTier::Med.allowed_apps(),
            vec![GitHubApp::Reader, GitHubApp::Developer]
        );
        assert_eq!(
            RiskTier::High.allowed_apps(),
            vec![GitHubApp::Reader, GitHubApp::Developer, GitHubApp::Operator]
        );
    }

    #[test]
    fn test_risk_tier_max_app() {
        assert_eq!(RiskTier::Low.max_app(), GitHubApp::Reader);
        assert_eq!(RiskTier::Med.max_app(), GitHubApp::Developer);
        assert_eq!(RiskTier::High.max_app(), GitHubApp::Operator);
    }

    #[test]
    fn test_risk_tier_ttl() {
        // Higher risk tiers should have shorter TTLs
        assert!(RiskTier::Low.default_ttl() > RiskTier::Med.default_ttl());
        assert!(RiskTier::Med.default_ttl() > RiskTier::High.default_ttl());
    }

    #[test]
    fn test_risk_tier_from_str() {
        assert_eq!("LOW".parse::<RiskTier>().unwrap(), RiskTier::Low);
        assert_eq!("low".parse::<RiskTier>().unwrap(), RiskTier::Low);
        assert_eq!("MED".parse::<RiskTier>().unwrap(), RiskTier::Med);
        assert_eq!("MEDIUM".parse::<RiskTier>().unwrap(), RiskTier::Med);
        assert_eq!("HIGH".parse::<RiskTier>().unwrap(), RiskTier::High);
        assert!("INVALID".parse::<RiskTier>().is_err());
    }

    #[test]
    fn test_github_app_scopes() {
        let reader_scopes = GitHubApp::Reader.scopes();
        assert!(reader_scopes.contains(&GitHubScope::ContentsRead));
        assert!(reader_scopes.contains(&GitHubScope::MetadataRead));
        assert!(!reader_scopes.contains(&GitHubScope::PullRequestsWrite));

        let developer_scopes = GitHubApp::Developer.scopes();
        assert!(developer_scopes.contains(&GitHubScope::ContentsRead));
        assert!(developer_scopes.contains(&GitHubScope::PullRequestsWrite));
        assert!(!developer_scopes.contains(&GitHubScope::ContentsWrite));

        let operator_scopes = GitHubApp::Operator.scopes();
        assert!(operator_scopes.contains(&GitHubScope::ContentsRead));
        assert!(operator_scopes.contains(&GitHubScope::ContentsWrite));
        assert!(operator_scopes.contains(&GitHubScope::AdminRead));
    }

    #[test]
    fn test_github_app_allows_scope() {
        assert!(GitHubApp::Reader.allows_scope(GitHubScope::ContentsRead));
        assert!(!GitHubApp::Reader.allows_scope(GitHubScope::PullRequestsWrite));

        assert!(GitHubApp::Developer.allows_scope(GitHubScope::PullRequestsWrite));
        assert!(!GitHubApp::Developer.allows_scope(GitHubScope::ContentsWrite));

        assert!(GitHubApp::Operator.allows_scope(GitHubScope::ContentsWrite));
    }

    #[test]
    fn test_github_app_from_name() {
        assert_eq!(
            GitHubApp::from_name("apm2-reader").unwrap(),
            GitHubApp::Reader
        );
        assert_eq!(GitHubApp::from_name("reader").unwrap(), GitHubApp::Reader);
        assert_eq!(
            GitHubApp::from_name("apm2-developer").unwrap(),
            GitHubApp::Developer
        );
        assert_eq!(
            GitHubApp::from_name("apm2-operator").unwrap(),
            GitHubApp::Operator
        );
        assert!(GitHubApp::from_name("unknown").is_err());
    }

    #[test]
    fn test_github_scope_parse() {
        assert_eq!(
            GitHubScope::parse("contents:read").unwrap(),
            GitHubScope::ContentsRead
        );
        assert_eq!(
            GitHubScope::parse("pull_requests:write").unwrap(),
            GitHubScope::PullRequestsWrite
        );
        assert!(GitHubScope::parse("unknown:scope").is_err());
    }

    #[test]
    fn test_github_scope_is_write() {
        assert!(!GitHubScope::ContentsRead.is_write());
        assert!(!GitHubScope::MetadataRead.is_write());
        assert!(GitHubScope::PullRequestsWrite.is_write());
        assert!(GitHubScope::ContentsWrite.is_write());
    }

    #[test]
    fn test_validate_tier_app() {
        // Low can only use Reader
        assert!(validate_tier_app(RiskTier::Low, GitHubApp::Reader).is_ok());
        assert!(validate_tier_app(RiskTier::Low, GitHubApp::Developer).is_err());
        assert!(validate_tier_app(RiskTier::Low, GitHubApp::Operator).is_err());

        // Med can use Reader and Developer
        assert!(validate_tier_app(RiskTier::Med, GitHubApp::Reader).is_ok());
        assert!(validate_tier_app(RiskTier::Med, GitHubApp::Developer).is_ok());
        assert!(validate_tier_app(RiskTier::Med, GitHubApp::Operator).is_err());

        // High can use all
        assert!(validate_tier_app(RiskTier::High, GitHubApp::Reader).is_ok());
        assert!(validate_tier_app(RiskTier::High, GitHubApp::Developer).is_ok());
        assert!(validate_tier_app(RiskTier::High, GitHubApp::Operator).is_ok());
    }

    #[test]
    fn test_validate_app_scopes() {
        // Reader can only read
        assert!(
            validate_app_scopes(
                GitHubApp::Reader,
                &[GitHubScope::ContentsRead, GitHubScope::MetadataRead]
            )
            .is_ok()
        );
        assert!(validate_app_scopes(GitHubApp::Reader, &[GitHubScope::PullRequestsWrite]).is_err());

        // Developer can write PRs but not contents
        assert!(
            validate_app_scopes(
                GitHubApp::Developer,
                &[GitHubScope::ContentsRead, GitHubScope::PullRequestsWrite]
            )
            .is_ok()
        );
        assert!(validate_app_scopes(GitHubApp::Developer, &[GitHubScope::ContentsWrite]).is_err());

        // Operator can do everything
        assert!(
            validate_app_scopes(
                GitHubApp::Operator,
                &[
                    GitHubScope::ContentsRead,
                    GitHubScope::ContentsWrite,
                    GitHubScope::AdminRead
                ]
            )
            .is_ok()
        );
    }
}
