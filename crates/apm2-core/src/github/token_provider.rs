#![allow(clippy::disallowed_methods)] // Metadata/observability usage or adapter.
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
//!     +-- RateLimitedTokenProvider (production wrapper)
//!     |       |
//!     |       +-- wraps any TokenProvider
//!     |
//!     +-- MockTokenProvider (for testing)
//!     |
//!     +-- GitHubAppTokenProvider
//!         Mints installation tokens using GitHub App JWT exchange.
//!         See: https://docs.github.com/en/apps/creating-github-apps
//! ```
//!
//! # Security Notes
//!
//! - Raw tokens are NEVER stored in the ledger
//! - Tokens are hashed with SHA-256 before storage
//! - App private keys load from keyring or runtime env
//! - Short TTLs are enforced based on risk tier
//! - Per-episode rate limits prevent token churn attacks (LAW-06)

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chrono::{DateTime, Utc};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use super::MAX_SCOPES_PER_LEASE;
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
    /// - Too many scopes requested (exceeds `MAX_SCOPES_PER_LEASE`)
    /// - Requested TTL exceeds tier's maximum
    pub fn validate(&self) -> Result<(), GitHubError> {
        // Validate tier can use app
        if !self.risk_tier.allowed_apps().contains(&self.app) {
            return Err(GitHubError::TierAppMismatch {
                tier: self.risk_tier,
                app: self.app,
            });
        }

        // Validate scope count
        if self.scopes.len() > MAX_SCOPES_PER_LEASE {
            return Err(GitHubError::TooManyScopes {
                count: self.scopes.len(),
                max: MAX_SCOPES_PER_LEASE,
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

const DEFAULT_GITHUB_API_BASE_URL: &str = "https://api.github.com";
const DEFAULT_GITHUB_APP_KEYRING_SERVICE: &str = "apm2.github.app";

/// Production token provider using GitHub App JWT exchange.
pub struct GitHubAppTokenProvider {
    app_id: String,
    private_key: SecretString,
    api_base_url: String,
    http_client: reqwest::blocking::Client,
}

impl GitHubAppTokenProvider {
    /// Creates a provider with the default GitHub API base URL.
    ///
    /// # Errors
    ///
    /// Returns an error when the app id or private key is empty, or the
    /// HTTP client cannot be initialized.
    pub fn new(app_id: impl Into<String>, private_key: SecretString) -> Result<Self, GitHubError> {
        Self::new_with_api_base_url(app_id, private_key, DEFAULT_GITHUB_API_BASE_URL)
    }

    /// Creates a provider with an explicit API base URL.
    ///
    /// # Errors
    ///
    /// Returns an error when required values are missing or the HTTP client
    /// cannot be initialized.
    pub fn new_with_api_base_url(
        app_id: impl Into<String>,
        private_key: SecretString,
        api_base_url: impl Into<String>,
    ) -> Result<Self, GitHubError> {
        let app_id = app_id.into();
        if app_id.trim().is_empty() {
            return Err(GitHubError::InvalidInput {
                field: "app_id".to_string(),
                reason: "must not be empty".to_string(),
            });
        }

        if private_key.expose_secret().trim().is_empty() {
            return Err(GitHubError::InvalidInput {
                field: "private_key".to_string(),
                reason: "must not be empty".to_string(),
            });
        }

        let api_base_url = api_base_url.into();
        if api_base_url.trim().is_empty() {
            return Err(GitHubError::InvalidInput {
                field: "api_base_url".to_string(),
                reason: "must not be empty".to_string(),
            });
        }

        let http_client = reqwest::blocking::Client::builder()
            .connect_timeout(Duration::from_secs(15))
            .timeout(Duration::from_secs(60))
            .build()
            .map_err(|error| GitHubError::HttpError {
                status: None,
                message: error.to_string(),
            })?;

        Ok(Self {
            app_id,
            private_key,
            api_base_url,
            http_client,
        })
    }

    /// Loads a private key from keyring storage.
    ///
    /// # Errors
    ///
    /// Returns an error if keyring access fails or the key is missing.
    pub fn load_private_key_from_keyring(
        service: &str,
        account: &str,
    ) -> Result<SecretString, GitHubError> {
        let entry =
            keyring::Entry::new(service, account).map_err(|error| GitHubError::Keyring {
                message: error.to_string(),
            })?;
        let private_key = entry.get_password().map_err(|error| GitHubError::Keyring {
            message: error.to_string(),
        })?;
        if private_key.trim().is_empty() {
            return Err(GitHubError::Keyring {
                message: "private key entry is empty".to_string(),
            });
        }
        Ok(SecretString::from(private_key))
    }

    /// Resolves a private key from environment first, then keyring.
    ///
    /// # Errors
    ///
    /// Returns an error if neither source is available.
    pub fn load_private_key_from_env_or_keyring(
        app_id: &str,
        env_var: &str,
        keyring_service: Option<&str>,
        keyring_account: Option<&str>,
    ) -> Result<SecretString, GitHubError> {
        if let Ok(private_key) = std::env::var(env_var) {
            if !private_key.trim().is_empty() {
                return Ok(SecretString::from(private_key));
            }
        }

        let service = keyring_service.unwrap_or(DEFAULT_GITHUB_APP_KEYRING_SERVICE);
        let default_account = format!("app-{app_id}");
        let account = keyring_account.unwrap_or(default_account.as_str());
        Self::load_private_key_from_keyring(service, account)
    }

    fn permissions_for_scopes(scopes: &[GitHubScope]) -> BTreeMap<String, String> {
        let mut permissions = BTreeMap::new();
        for scope in scopes {
            match scope {
                GitHubScope::ContentsRead => {
                    Self::set_permission(&mut permissions, "contents", "read");
                },
                GitHubScope::MetadataRead => {
                    Self::set_permission(&mut permissions, "metadata", "read");
                },
                GitHubScope::PullRequestsWrite => {
                    Self::set_permission(&mut permissions, "pull_requests", "write");
                },
                GitHubScope::ChecksWrite => {
                    Self::set_permission(&mut permissions, "checks", "write");
                },
                GitHubScope::StatusesWrite => {
                    Self::set_permission(&mut permissions, "statuses", "write");
                },
                GitHubScope::ContentsWrite => {
                    Self::set_permission(&mut permissions, "contents", "write");
                },
                GitHubScope::AdminRead => {
                    Self::set_permission(&mut permissions, "administration", "read");
                },
                GitHubScope::ReleasesWrite => {
                    // GitHub release operations are covered by `contents:write`.
                    Self::set_permission(&mut permissions, "contents", "write");
                },
            }
        }
        permissions
    }

    fn set_permission(permissions: &mut BTreeMap<String, String>, name: &str, level: &str) {
        let current = permissions.get(name).map_or("none", String::as_str);
        let next = if current == "write" || level == "write" {
            "write"
        } else {
            "read"
        };
        permissions.insert(name.to_string(), next.to_string());
    }

    fn generate_jwt(&self, now: u64) -> Result<String, GitHubError> {
        #[derive(Debug, Serialize)]
        struct Claims {
            iat: u64,
            exp: u64,
            iss: String,
        }

        let claims = Claims {
            iat: now.saturating_sub(60),
            exp: now + 600,
            iss: self.app_id.clone(),
        };
        let key = EncodingKey::from_rsa_pem(self.private_key.expose_secret().as_bytes()).map_err(
            |error| GitHubError::Jwt {
                message: error.to_string(),
            },
        )?;

        jsonwebtoken::encode(&Header::new(Algorithm::RS256), &claims, &key).map_err(|error| {
            GitHubError::Jwt {
                message: error.to_string(),
            }
        })
    }
}

impl TokenProvider for GitHubAppTokenProvider {
    fn mint_token(&self, request: &TokenRequest) -> Result<TokenResponse, GitHubError> {
        #[derive(Debug, Serialize)]
        struct InstallationTokenRequest {
            permissions: BTreeMap<String, String>,
        }

        #[derive(Debug, Deserialize)]
        struct InstallationTokenResponse {
            token: String,
            expires_at: String,
        }

        request.validate()?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| GitHubError::TokenProviderError {
                message: error.to_string(),
            })?
            .as_secs();
        let jwt = self.generate_jwt(now)?;
        let permissions = Self::permissions_for_scopes(&request.scopes);
        let payload = InstallationTokenRequest { permissions };
        let endpoint = format!(
            "{}/app/installations/{}/access_tokens",
            self.api_base_url.trim_end_matches('/'),
            request.installation_id
        );

        let response = self
            .http_client
            .post(endpoint)
            .header("Accept", "application/vnd.github+json")
            .header("User-Agent", "apm2-core/github-app-token-provider")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .bearer_auth(jwt)
            .json(&payload)
            .send()
            .map_err(|error| GitHubError::HttpError {
                status: None,
                message: error.to_string(),
            })?;

        let status = response.status();
        if !status.is_success() {
            let message = response
                .text()
                .unwrap_or_else(|_| "unable to read token response body".to_string());
            return Err(GitHubError::HttpError {
                status: Some(status.as_u16()),
                message,
            });
        }

        let payload: InstallationTokenResponse =
            response
                .json()
                .map_err(|error| GitHubError::TokenProviderError {
                    message: error.to_string(),
                })?;

        let expires_at = DateTime::parse_from_rfc3339(&payload.expires_at)
            .map_err(|error| GitHubError::TimeParse {
                value: payload.expires_at.clone(),
                message: error.to_string(),
            })?
            .with_timezone(&Utc)
            .timestamp();
        let expires_at = u64::try_from(expires_at).map_err(|_| GitHubError::TimeParse {
            value: payload.expires_at.clone(),
            message: "timestamp is before unix epoch".to_string(),
        })?;

        let effective_expiry = expires_at.min(now + request.effective_ttl().as_secs());
        let token_hash = TokenResponse::hash_token(&payload.token);

        Ok(TokenResponse {
            token: SecretString::from(payload.token),
            token_hash,
            expires_at: effective_expiry,
            scopes: request.scopes.clone(),
            app_id: self.app_id.clone(),
            installation_id: request.installation_id.clone(),
        })
    }

    fn name(&self) -> &'static str {
        "github-app"
    }
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

/// Rate-limited token provider wrapper.
///
/// Enforces per-episode token issuance limits to prevent token churn attacks.
/// This ensures that short TTLs provide meaningful containment by preventing
/// a compromised agent from maintaining indefinite access through rapid
/// token renewal (LAW-06: MDL as a Gated Budget).
///
/// # Rate Limits by Tier
///
/// - **Low**: 10 tokens per episode (read-only, long TTL)
/// - **Med**: 5 tokens per episode (limited writes, medium TTL)
/// - **High**: 3 tokens per episode (privileged ops, short TTL)
///
/// The inverse relationship between privilege and token budget ensures that
/// higher-risk operations have stricter containment.
pub struct RateLimitedTokenProvider<P: TokenProvider> {
    /// The underlying token provider.
    inner: P,
    /// Per-episode issuance counts.
    /// Key: `episode_id`, Value: tokens issued.
    issuance_counts: Arc<Mutex<HashMap<String, u32>>>,
}

impl<P: TokenProvider> RateLimitedTokenProvider<P> {
    /// Creates a new rate-limited token provider wrapping the given provider.
    #[must_use]
    pub fn new(inner: P) -> Self {
        Self {
            inner,
            issuance_counts: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Returns the maximum tokens allowed per episode for a given tier.
    ///
    /// Higher risk tiers get fewer tokens to ensure containment through
    /// short TTLs cannot be bypassed by token churn.
    #[must_use]
    pub const fn max_tokens_for_tier(tier: RiskTier) -> u32 {
        match tier {
            RiskTier::Low => 10, // Read-only, 1hr TTL, low risk
            RiskTier::Med => 5,  // Limited writes, 30min TTL
            RiskTier::High => 3, // Privileged, 5min TTL, strict limit
        }
    }

    /// Resets the issuance count for an episode.
    ///
    /// This should be called when an episode completes to free memory.
    pub fn reset_episode(&self, episode_id: &str) {
        if let Ok(mut counts) = self.issuance_counts.lock() {
            counts.remove(episode_id);
        }
    }

    /// Returns the current issuance count for an episode.
    #[must_use]
    pub fn get_issuance_count(&self, episode_id: &str) -> u32 {
        self.issuance_counts
            .lock()
            .ok()
            .and_then(|counts| counts.get(episode_id).copied())
            .unwrap_or(0)
    }
}

impl<P: TokenProvider> TokenProvider for RateLimitedTokenProvider<P> {
    fn mint_token(&self, request: &TokenRequest) -> Result<TokenResponse, GitHubError> {
        // Check rate limit before delegating
        let max_tokens = Self::max_tokens_for_tier(request.risk_tier);

        {
            let mut counts =
                self.issuance_counts
                    .lock()
                    .map_err(|_| GitHubError::TokenProviderError {
                        message: "rate limiter lock poisoned".to_string(),
                    })?;

            let count = counts.entry(request.episode_id.clone()).or_insert(0);

            if *count >= max_tokens {
                return Err(GitHubError::RateLimitExceeded {
                    episode_id: request.episode_id.clone(),
                    issued: *count,
                    max: max_tokens,
                    tier: request.risk_tier,
                });
            }

            // Increment before minting to prevent race conditions
            *count += 1;
        }

        // Delegate to inner provider
        match self.inner.mint_token(request) {
            Ok(response) => Ok(response),
            Err(e) => {
                // Rollback count on failure
                if let Ok(mut counts) = self.issuance_counts.lock() {
                    if let Some(count) = counts.get_mut(&request.episode_id) {
                        *count = count.saturating_sub(1);
                    }
                }
                Err(e)
            },
        }
    }

    fn name(&self) -> &'static str {
        "rate-limited"
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

    #[test]
    fn test_rate_limited_provider_allows_within_limit() {
        let inner = MockTokenProvider::new();
        let provider = RateLimitedTokenProvider::new(inner);

        let request = TokenRequest::new(
            GitHubApp::Operator,
            "12345".to_string(),
            RiskTier::High,
            "episode-001".to_string(),
        );

        // High tier allows 3 tokens
        assert!(provider.mint_token(&request).is_ok());
        assert!(provider.mint_token(&request).is_ok());
        assert!(provider.mint_token(&request).is_ok());

        assert_eq!(provider.get_issuance_count("episode-001"), 3);
    }

    #[test]
    fn test_rate_limited_provider_blocks_at_limit() {
        let inner = MockTokenProvider::new();
        let provider = RateLimitedTokenProvider::new(inner);

        let request = TokenRequest::new(
            GitHubApp::Operator,
            "12345".to_string(),
            RiskTier::High,
            "episode-001".to_string(),
        );

        // Exhaust the limit (3 for High tier)
        for _ in 0..3 {
            provider.mint_token(&request).unwrap();
        }

        // Fourth request should fail
        let result = provider.mint_token(&request);
        assert!(matches!(
            result,
            Err(GitHubError::RateLimitExceeded {
                issued: 3,
                max: 3,
                tier: RiskTier::High,
                ..
            })
        ));
    }

    #[test]
    fn test_rate_limited_provider_separate_episodes() {
        let inner = MockTokenProvider::new();
        let provider = RateLimitedTokenProvider::new(inner);

        let request1 = TokenRequest::new(
            GitHubApp::Operator,
            "12345".to_string(),
            RiskTier::High,
            "episode-001".to_string(),
        );

        let request2 = TokenRequest::new(
            GitHubApp::Operator,
            "12345".to_string(),
            RiskTier::High,
            "episode-002".to_string(),
        );

        // Exhaust episode-001's limit
        for _ in 0..3 {
            provider.mint_token(&request1).unwrap();
        }

        // episode-002 should still work
        assert!(provider.mint_token(&request2).is_ok());
        assert_eq!(provider.get_issuance_count("episode-002"), 1);
    }

    #[test]
    fn test_rate_limited_provider_reset_episode() {
        let inner = MockTokenProvider::new();
        let provider = RateLimitedTokenProvider::new(inner);

        let request = TokenRequest::new(
            GitHubApp::Operator,
            "12345".to_string(),
            RiskTier::High,
            "episode-001".to_string(),
        );

        // Use some tokens
        provider.mint_token(&request).unwrap();
        provider.mint_token(&request).unwrap();
        assert_eq!(provider.get_issuance_count("episode-001"), 2);

        // Reset the episode
        provider.reset_episode("episode-001");
        assert_eq!(provider.get_issuance_count("episode-001"), 0);

        // Should be able to mint again
        assert!(provider.mint_token(&request).is_ok());
    }

    #[test]
    fn test_rate_limits_inversely_proportional_to_risk() {
        // Higher risk = fewer tokens (stricter containment)
        let low_limit =
            RateLimitedTokenProvider::<MockTokenProvider>::max_tokens_for_tier(RiskTier::Low);
        let med_limit =
            RateLimitedTokenProvider::<MockTokenProvider>::max_tokens_for_tier(RiskTier::Med);
        let high_limit =
            RateLimitedTokenProvider::<MockTokenProvider>::max_tokens_for_tier(RiskTier::High);

        assert!(
            low_limit > med_limit,
            "Low risk should allow more tokens than Med"
        );
        assert!(
            med_limit > high_limit,
            "Med risk should allow more tokens than High"
        );
    }

    #[test]
    fn test_token_request_validate_too_many_scopes() {
        // Create a request with more scopes than MAX_SCOPES_PER_LEASE (16)
        let scopes = vec![GitHubScope::ContentsRead; MAX_SCOPES_PER_LEASE + 1];
        let request = TokenRequest::new(
            GitHubApp::Reader,
            "12345".to_string(),
            RiskTier::Low,
            "episode-001".to_string(),
        )
        .with_scopes(scopes);

        let result = request.validate();
        assert!(matches!(
            result,
            Err(GitHubError::TooManyScopes {
                count,
                max,
            }) if count == MAX_SCOPES_PER_LEASE + 1 && max == MAX_SCOPES_PER_LEASE
        ));
    }

    #[test]
    fn test_token_request_validate_exactly_max_scopes() {
        // Create a request with exactly MAX_SCOPES_PER_LEASE scopes - should pass
        let scopes = vec![GitHubScope::ContentsRead; MAX_SCOPES_PER_LEASE];
        let request = TokenRequest::new(
            GitHubApp::Reader,
            "12345".to_string(),
            RiskTier::Low,
            "episode-001".to_string(),
        )
        .with_scopes(scopes);

        // Should not fail on scope count
        let result = request.validate();
        assert!(result.is_ok());
    }

    #[test]
    fn test_github_app_token_provider_rejects_empty_values() {
        let provider = GitHubAppTokenProvider::new("", SecretString::from("key"));
        assert!(matches!(
            provider,
            Err(GitHubError::InvalidInput { field, .. }) if field == "app_id"
        ));

        let provider = GitHubAppTokenProvider::new("2715660", SecretString::from(" "));
        assert!(matches!(
            provider,
            Err(GitHubError::InvalidInput { field, .. }) if field == "private_key"
        ));
    }

    #[test]
    fn test_github_app_permissions_scope_write_wins() {
        let permissions = GitHubAppTokenProvider::permissions_for_scopes(&[
            GitHubScope::ContentsRead,
            GitHubScope::ContentsWrite,
            GitHubScope::MetadataRead,
        ]);
        assert_eq!(
            permissions.get("contents").map(String::as_str),
            Some("write")
        );
        assert_eq!(
            permissions.get("metadata").map(String::as_str),
            Some("read")
        );
    }

    #[test]
    fn test_github_app_generate_jwt_invalid_pem() {
        let provider =
            GitHubAppTokenProvider::new("2715660", SecretString::from("not-a-valid-pem"))
                .expect("provider should construct with non-empty values");
        let result = provider.generate_jwt(1_700_000_000);
        assert!(matches!(result, Err(GitHubError::Jwt { .. })));
    }
}
