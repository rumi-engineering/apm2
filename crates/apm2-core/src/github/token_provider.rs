//! Token provider for GitHub App authentication.
//!
//! This module provides the infrastructure for minting GitHub installation
//! access tokens. The actual GitHub API calls are abstracted behind traits
//! to enable testing and future extensions.
//!
//! # Architecture
//!
//! ```text
//! TokenProvider (trait)
//!     |
//!     +-- MockTokenProvider (for testing)
//!     |
//!     +-- GitHubTokenProvider (TODO: real implementation)
//!         Requires GitHub App credentials infrastructure.
//!         See: https://docs.github.com/en/apps/creating-github-apps
//! ```
//!
//! # Security Notes
//!
//! - Raw tokens are NEVER stored in the ledger
//! - Tokens are hashed with SHA-256 before storage
//! - Token storage in OS keyring is recommended (not implemented here)
//! - Short TTLs are enforced based on risk tier

use std::time::Duration;

use secrecy::SecretString;

use super::error::GitHubError;
use super::scope::{GitHubApp, GitHubScope, RiskTier};

/// Request for minting a new installation access token.
#[derive(Debug, Clone)]
pub struct TokenRequest {
    /// GitHub App to use for this request.
    pub app: GitHubApp,
    /// GitHub installation ID.
    pub installation_id: String,
    /// Risk tier of the requesting agent.
    pub risk_tier: RiskTier,
    /// Requested scopes (must be subset of app's scopes).
    pub scopes: Vec<GitHubScope>,
    /// Requested TTL (will be capped to tier's max).
    pub requested_ttl: Option<Duration>,
    /// Episode ID this token is bound to.
    pub episode_id: String,
}

impl TokenRequest {
    /// Creates a new token request.
    #[must_use]
    pub fn new(
        app: GitHubApp,
        installation_id: String,
        risk_tier: RiskTier,
        episode_id: String,
    ) -> Self {
        Self {
            app,
            installation_id,
            risk_tier,
            scopes: app.scopes(),
            requested_ttl: None,
            episode_id,
        }
    }

    /// Sets the requested scopes.
    #[must_use]
    pub fn with_scopes(mut self, scopes: Vec<GitHubScope>) -> Self {
        self.scopes = scopes;
        self
    }

    /// Sets the requested TTL.
    #[must_use]
    pub const fn with_ttl(mut self, ttl: Duration) -> Self {
        self.requested_ttl = Some(ttl);
        self
    }

    /// Validates this request.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Risk tier cannot use the requested app
    /// - App does not allow the requested scopes
    /// - Requested TTL exceeds tier's maximum
    pub fn validate(&self) -> Result<(), GitHubError> {
        // Validate tier can use app
        if !self.risk_tier.allowed_apps().contains(&self.app) {
            return Err(GitHubError::TierAppMismatch {
                tier: self.risk_tier,
                app: self.app,
            });
        }

        // Validate app allows all scopes
        for scope in &self.scopes {
            if !self.app.allows_scope(*scope) {
                return Err(GitHubError::ScopeNotAllowed {
                    app: self.app,
                    scope: *scope,
                });
            }
        }

        // Validate TTL
        if let Some(ttl) = self.requested_ttl {
            let max_ttl = self.risk_tier.max_ttl();
            if ttl > max_ttl {
                return Err(GitHubError::TtlExceedsMaximum {
                    requested_secs: ttl.as_secs(),
                    max_secs: max_ttl.as_secs(),
                    tier: self.risk_tier,
                });
            }
        }

        Ok(())
    }

    /// Returns the effective TTL for this request.
    ///
    /// Uses the requested TTL if provided and valid, otherwise the default
    /// TTL for the risk tier.
    #[must_use]
    pub fn effective_ttl(&self) -> Duration {
        self.requested_ttl.map_or_else(
            || self.risk_tier.default_ttl(),
            |ttl| ttl.min(self.risk_tier.max_ttl()),
        )
    }
}

/// Response from minting an installation access token.
#[derive(Clone)]
pub struct TokenResponse {
    /// The installation access token.
    /// Wrapped in `SecretString` to prevent accidental logging (CTR-2604).
    pub token: SecretString,

    /// SHA-256 hash of the token (safe to store in ledger).
    pub token_hash: Vec<u8>,

    /// When the token expires (Unix timestamp in seconds).
    pub expires_at: u64,

    /// Scopes granted to this token.
    pub scopes: Vec<GitHubScope>,

    /// GitHub App ID.
    pub app_id: String,

    /// Installation ID.
    pub installation_id: String,
}

impl TokenResponse {
    /// Computes the SHA-256 hash of a token.
    #[must_use]
    pub fn hash_token(token: &str) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        hasher.finalize().to_vec()
    }
}

/// Trait for token providers.
///
/// Implementations mint GitHub installation access tokens for a given
/// app and installation.
pub trait TokenProvider: Send + Sync {
    /// Mints a new installation access token.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Request validation fails
    /// - GitHub API call fails
    /// - Rate limit exceeded
    fn mint_token(&self, request: &TokenRequest) -> Result<TokenResponse, GitHubError>;

    /// Returns the provider name for logging.
    fn name(&self) -> &'static str;
}

/// Mock token provider for testing.
///
/// This provider generates predictable tokens without making GitHub API calls.
#[derive(Debug, Default)]
pub struct MockTokenProvider {
    /// Counter for generating unique tokens.
    counter: std::sync::atomic::AtomicU64,
}

impl MockTokenProvider {
    /// Creates a new mock token provider.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl TokenProvider for MockTokenProvider {
    fn mint_token(&self, request: &TokenRequest) -> Result<TokenResponse, GitHubError> {
        // Validate request first
        request.validate()?;

        // Generate a predictable token
        let counter = self
            .counter
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let token_str = format!(
            "ghs_mock_{}_{}_{}",
            request.app.name(),
            request.installation_id,
            counter
        );
        let token_hash = TokenResponse::hash_token(&token_str);
        let token = SecretString::from(token_str);

        // Calculate expiration
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let ttl = request.effective_ttl();
        let expires_at = now + ttl.as_secs();

        Ok(TokenResponse {
            token,
            token_hash,
            expires_at,
            scopes: request.scopes.clone(),
            app_id: format!("mock-{}", request.app.name()),
            installation_id: request.installation_id.clone(),
        })
    }

    fn name(&self) -> &'static str {
        "mock"
    }
}

#[cfg(test)]
mod unit_tests {
    use secrecy::ExposeSecret;

    use super::*;

    #[test]
    fn test_token_request_new() {
        let request = TokenRequest::new(
            GitHubApp::Developer,
            "12345".to_string(),
            RiskTier::Med,
            "episode-001".to_string(),
        );

        assert_eq!(request.app, GitHubApp::Developer);
        assert_eq!(request.installation_id, "12345");
        assert_eq!(request.risk_tier, RiskTier::Med);
        assert!(request.requested_ttl.is_none());
    }

    #[test]
    fn test_token_request_with_scopes() {
        let request = TokenRequest::new(
            GitHubApp::Developer,
            "12345".to_string(),
            RiskTier::Med,
            "episode-001".to_string(),
        )
        .with_scopes(vec![GitHubScope::ContentsRead]);

        assert_eq!(request.scopes, vec![GitHubScope::ContentsRead]);
    }

    #[test]
    fn test_token_request_with_ttl() {
        let request = TokenRequest::new(
            GitHubApp::Developer,
            "12345".to_string(),
            RiskTier::Med,
            "episode-001".to_string(),
        )
        .with_ttl(Duration::from_secs(600));

        assert_eq!(request.requested_ttl, Some(Duration::from_secs(600)));
    }

    #[test]
    fn test_token_request_validate_success() {
        let request = TokenRequest::new(
            GitHubApp::Developer,
            "12345".to_string(),
            RiskTier::Med,
            "episode-001".to_string(),
        );

        assert!(request.validate().is_ok());
    }

    #[test]
    fn test_token_request_validate_tier_mismatch() {
        let request = TokenRequest::new(
            GitHubApp::Developer,
            "12345".to_string(),
            RiskTier::Low, // Low tier cannot use Developer
            "episode-001".to_string(),
        );

        assert!(matches!(
            request.validate(),
            Err(GitHubError::TierAppMismatch { .. })
        ));
    }

    #[test]
    fn test_token_request_validate_scope_not_allowed() {
        let request = TokenRequest::new(
            GitHubApp::Reader,
            "12345".to_string(),
            RiskTier::Low,
            "episode-001".to_string(),
        )
        .with_scopes(vec![GitHubScope::PullRequestsWrite]);

        assert!(matches!(
            request.validate(),
            Err(GitHubError::ScopeNotAllowed { .. })
        ));
    }

    #[test]
    fn test_token_request_validate_ttl_exceeded() {
        let request = TokenRequest::new(
            GitHubApp::Developer,
            "12345".to_string(),
            RiskTier::Med,
            "episode-001".to_string(),
        )
        .with_ttl(Duration::from_secs(7200)); // 2 hours, exceeds Med tier max

        assert!(matches!(
            request.validate(),
            Err(GitHubError::TtlExceedsMaximum { .. })
        ));
    }

    #[test]
    fn test_token_request_effective_ttl_default() {
        let request = TokenRequest::new(
            GitHubApp::Developer,
            "12345".to_string(),
            RiskTier::Med,
            "episode-001".to_string(),
        );

        assert_eq!(request.effective_ttl(), RiskTier::Med.default_ttl());
    }

    #[test]
    fn test_token_request_effective_ttl_capped() {
        let request = TokenRequest::new(
            GitHubApp::Developer,
            "12345".to_string(),
            RiskTier::Med,
            "episode-001".to_string(),
        )
        .with_ttl(Duration::from_secs(7200)); // Request 2 hours

        // Should be capped to Med tier max (30 minutes)
        assert_eq!(request.effective_ttl(), RiskTier::Med.max_ttl());
    }

    #[test]
    fn test_token_response_hash_token() {
        let hash1 = TokenResponse::hash_token("token1");
        let hash2 = TokenResponse::hash_token("token1");
        let hash3 = TokenResponse::hash_token("token2");

        // Same token should produce same hash
        assert_eq!(hash1, hash2);
        // Different tokens should produce different hashes
        assert_ne!(hash1, hash3);
        // SHA-256 produces 32 bytes
        assert_eq!(hash1.len(), 32);
    }

    #[test]
    fn test_mock_token_provider() {
        let provider = MockTokenProvider::new();
        let request = TokenRequest::new(
            GitHubApp::Developer,
            "12345".to_string(),
            RiskTier::Med,
            "episode-001".to_string(),
        );

        let response = provider.mint_token(&request).unwrap();

        assert!(response.token.expose_secret().starts_with("ghs_mock_"));
        assert_eq!(response.token_hash.len(), 32);
        assert_eq!(response.installation_id, "12345");
        assert!(!response.scopes.is_empty());
    }

    #[test]
    fn test_mock_token_provider_unique_tokens() {
        let provider = MockTokenProvider::new();
        let request = TokenRequest::new(
            GitHubApp::Developer,
            "12345".to_string(),
            RiskTier::Med,
            "episode-001".to_string(),
        );

        let response1 = provider.mint_token(&request).unwrap();
        let response2 = provider.mint_token(&request).unwrap();

        // Each call should produce a unique token
        assert_ne!(
            response1.token.expose_secret(),
            response2.token.expose_secret()
        );
        assert_ne!(response1.token_hash, response2.token_hash);
    }

    #[test]
    fn test_mock_token_provider_validates_request() {
        let provider = MockTokenProvider::new();
        let request = TokenRequest::new(
            GitHubApp::Developer,
            "12345".to_string(),
            RiskTier::Low, // Invalid: T0 cannot use Developer
            "episode-001".to_string(),
        );

        let result = provider.mint_token(&request);
        assert!(matches!(result, Err(GitHubError::TierAppMismatch { .. })));
    }
}
