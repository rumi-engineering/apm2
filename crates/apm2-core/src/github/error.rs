//! GitHub-specific error types.

use thiserror::Error;

use super::scope::{
    GitHubApp, GitHubScope, InvalidAppName, InvalidRiskTier, InvalidScope, RiskTier,
};

/// Errors that can occur during GitHub operations.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum GitHubError {
    /// A lease with this ID already exists.
    #[error("GitHub lease already exists: {lease_id}")]
    LeaseAlreadyExists {
        /// The duplicate lease ID.
        lease_id: String,
    },

    /// The lease was not found.
    #[error("GitHub lease not found: {lease_id}")]
    LeaseNotFound {
        /// The lease ID that was not found.
        lease_id: String,
    },

    /// Attempted to operate on a lease in a terminal state.
    #[error("GitHub lease {lease_id} is already in terminal state: {current_state}")]
    LeaseAlreadyTerminal {
        /// The lease ID.
        lease_id: String,
        /// The current terminal state.
        current_state: String,
    },

    /// The lease has expired.
    #[error("GitHub lease {lease_id} has expired at {expired_at}")]
    LeaseExpired {
        /// The lease ID.
        lease_id: String,
        /// When the lease expired (Unix nanos).
        expired_at: u64,
    },

    /// Risk tier cannot use the requested app.
    #[error("risk tier {tier} cannot use GitHub app {app}")]
    TierAppMismatch {
        /// The risk tier.
        tier: RiskTier,
        /// The app that was requested.
        app: GitHubApp,
    },

    /// App does not allow the requested scope.
    #[error("GitHub app {app} does not allow scope {scope}")]
    ScopeNotAllowed {
        /// The app.
        app: GitHubApp,
        /// The scope that is not allowed.
        scope: GitHubScope,
    },

    /// Invalid risk tier value.
    #[error("invalid risk tier: {0}")]
    InvalidRiskTier(#[from] InvalidRiskTier),

    /// Invalid app name.
    #[error("invalid app name: {0}")]
    InvalidAppName(#[from] InvalidAppName),

    /// Invalid scope string.
    #[error("invalid scope: {0}")]
    InvalidScope(#[from] InvalidScope),

    /// Invalid input field.
    #[error("invalid input for field {field}: {reason}")]
    InvalidInput {
        /// The field name.
        field: String,
        /// The reason it is invalid.
        reason: String,
    },

    /// Missing required signature.
    #[error("signature is required for GitHub lease operation on {lease_id}")]
    MissingSignature {
        /// The lease ID missing a signature.
        lease_id: String,
    },

    /// Token provider error.
    #[error("token provider error: {message}")]
    TokenProviderError {
        /// Error message from the provider.
        message: String,
    },

    /// Keyring interaction failed.
    #[error("keyring error: {message}")]
    Keyring {
        /// Error message from keyring backend.
        message: String,
    },

    /// JWT signing/encoding failed.
    #[error("JWT error: {message}")]
    Jwt {
        /// Error message from JWT library.
        message: String,
    },

    /// HTTP request/response error from GitHub API calls.
    #[error("HTTP error (status={status:?}): {message}")]
    HttpError {
        /// Optional HTTP status code.
        status: Option<u16>,
        /// Error payload or transport message.
        message: String,
    },

    /// Failed to parse a time value.
    #[error("time parse error for '{value}': {message}")]
    TimeParse {
        /// Original unparsed value.
        value: String,
        /// Parsing error detail.
        message: String,
    },

    /// Too many scopes requested.
    #[error("too many scopes requested: {count} (max: {max})")]
    TooManyScopes {
        /// Number of scopes requested.
        count: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Token TTL exceeds maximum for tier.
    #[error("token TTL {requested_secs}s exceeds maximum {max_secs}s for tier {tier}")]
    TtlExceedsMaximum {
        /// Requested TTL in seconds.
        requested_secs: u64,
        /// Maximum allowed in seconds.
        max_secs: u64,
        /// The tier.
        tier: RiskTier,
    },

    /// Invalid revocation reason.
    #[error("invalid revocation reason: {value}")]
    InvalidRevocationReason {
        /// The invalid value provided.
        value: String,
    },

    /// Failed to decode the event payload.
    #[error("failed to decode GitHub lease event: {0}")]
    DecodeError(#[from] prost::DecodeError),

    /// Invalid API endpoint format.
    #[error("invalid api_endpoint: {reason}")]
    InvalidApiEndpoint {
        /// The reason the endpoint is invalid.
        reason: String,
    },

    /// Invalid repository format.
    #[error("invalid repository format: {reason}")]
    InvalidRepository {
        /// The reason the repository is invalid.
        reason: String,
    },

    /// Rate limit exceeded for token issuance.
    #[error(
        "token issuance rate limit exceeded for episode {episode_id}: {issued} tokens issued, max {max} for tier {tier}"
    )]
    RateLimitExceeded {
        /// The episode that exceeded its limit.
        episode_id: String,
        /// Number of tokens already issued.
        issued: u32,
        /// Maximum allowed for the tier.
        max: u32,
        /// The risk tier.
        tier: RiskTier,
    },
}
