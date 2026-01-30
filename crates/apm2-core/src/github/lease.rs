//! GitHub lease types for capability-bound token access.
//!
//! A `GitHubLease` represents a time-bounded grant to use a GitHub installation
//! access token. Leases are bound to episodes and enforce risk tier
//! constraints.

use serde::{Deserialize, Serialize};

use super::error::GitHubError;
use super::scope::{GitHubApp, GitHubScope, RiskTier};
use super::{
    MAX_ACTOR_ID_LEN, MAX_APP_ID_LEN, MAX_EPISODE_ID_LEN, MAX_INSTALLATION_ID_LEN,
    MAX_LEASE_ID_LEN, MAX_SCOPES_PER_LEASE,
};

/// The lifecycle state of a GitHub lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum GitHubLeaseState {
    /// Lease is active and the token can be used.
    Active,
    /// Lease has been revoked (voluntary or forced).
    Revoked,
    /// Lease has expired due to timeout.
    Expired,
}

impl GitHubLeaseState {
    /// Returns the string representation of this state.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "ACTIVE",
            Self::Revoked => "REVOKED",
            Self::Expired => "EXPIRED",
        }
    }

    /// Parses a lease state from a string.
    ///
    /// # Errors
    ///
    /// Returns `GitHubError::InvalidInput` if the string is not recognized.
    pub fn parse(s: &str) -> Result<Self, GitHubError> {
        match s.to_uppercase().as_str() {
            "ACTIVE" => Ok(Self::Active),
            "REVOKED" => Ok(Self::Revoked),
            "EXPIRED" => Ok(Self::Expired),
            _ => Err(GitHubError::InvalidInput {
                field: "state".to_string(),
                reason: format!("unknown state: {s}"),
            }),
        }
    }

    /// Returns true if this is a terminal state.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(self, Self::Revoked | Self::Expired)
    }

    /// Returns true if this is an active (non-terminal) state.
    #[must_use]
    pub const fn is_active(&self) -> bool {
        matches!(self, Self::Active)
    }
}

impl std::fmt::Display for GitHubLeaseState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// The reason a GitHub lease was revoked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum RevocationReason {
    /// Lease holder voluntarily released the lease.
    Voluntary,
    /// Lease expired naturally.
    Expired,
    /// Lease was revoked due to policy violation.
    PolicyViolation,
    /// Lease was revoked due to suspected key compromise.
    KeyCompromise,
}

impl RevocationReason {
    /// Returns the string representation of this reason.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Voluntary => "VOLUNTARY",
            Self::Expired => "EXPIRED",
            Self::PolicyViolation => "POLICY_VIOLATION",
            Self::KeyCompromise => "KEY_COMPROMISE",
        }
    }

    /// Parses a revocation reason from a string.
    ///
    /// # Errors
    ///
    /// Returns `GitHubError::InvalidRevocationReason` if not recognized.
    pub fn parse(s: &str) -> Result<Self, GitHubError> {
        match s.to_uppercase().as_str() {
            "VOLUNTARY" => Ok(Self::Voluntary),
            "EXPIRED" => Ok(Self::Expired),
            "POLICY_VIOLATION" => Ok(Self::PolicyViolation),
            "KEY_COMPROMISE" => Ok(Self::KeyCompromise),
            _ => Err(GitHubError::InvalidRevocationReason {
                value: s.to_string(),
            }),
        }
    }
}

impl std::fmt::Display for RevocationReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// A GitHub lease granting access to a GitHub installation token.
///
/// # Security Properties
///
/// - The raw token is **never** stored in this struct (only `token_hash`)
/// - Leases are bound to episodes and cannot be transferred
/// - Risk tier determines which apps and scopes are allowed
/// - TTL is capped based on risk tier
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[non_exhaustive]
pub struct GitHubLease {
    /// Unique identifier for this lease.
    pub lease_id: String,

    /// Episode this lease is bound to.
    pub episode_id: String,

    /// GitHub App ID (determines permission tier).
    pub github_app_id: String,

    /// GitHub installation ID for the target repository/organization.
    pub installation_id: String,

    /// The GitHub App type for this lease.
    pub app: GitHubApp,

    /// Risk tier of the requesting agent.
    pub risk_tier: RiskTier,

    /// Scopes granted by this lease.
    pub scopes: Vec<GitHubScope>,

    /// SHA-256 hash of the installation access token.
    /// The raw token is NEVER stored here.
    pub token_hash: Vec<u8>,

    /// Current lifecycle state.
    pub state: GitHubLeaseState,

    /// Timestamp when the lease was issued (Unix nanos).
    pub issued_at: u64,

    /// Timestamp when the lease expires (Unix nanos).
    pub expires_at: u64,

    /// Hash of the capability manifest that authorized this lease.
    pub capability_manifest_hash: Vec<u8>,

    /// Issuer signature over the lease issuance.
    pub issuer_signature: Vec<u8>,

    /// Revocation reason, if the lease was revoked.
    pub revocation_reason: Option<RevocationReason>,

    /// Actor who revoked the lease, if revoked.
    pub revoker_actor_id: Option<String>,

    /// Timestamp when the lease was terminated (revoked or expired).
    pub terminated_at: Option<u64>,
}

impl GitHubLease {
    /// Creates a new GitHub lease in the Active state.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Any input field exceeds maximum length
    /// - Risk tier cannot use the requested app
    /// - App does not allow the requested scopes
    /// - Too many scopes requested
    /// - Signature is empty
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lease_id: String,
        episode_id: String,
        github_app_id: String,
        installation_id: String,
        app: GitHubApp,
        risk_tier: RiskTier,
        scopes: Vec<GitHubScope>,
        token_hash: Vec<u8>,
        issued_at: u64,
        expires_at: u64,
        capability_manifest_hash: Vec<u8>,
        issuer_signature: Vec<u8>,
    ) -> Result<Self, GitHubError> {
        // Constants for cryptographic artifact lengths
        const SHA256_HASH_LEN: usize = 32;
        const ED25519_SIGNATURE_LEN: usize = 64;

        // Validate input lengths
        validate_length(&lease_id, "lease_id", MAX_LEASE_ID_LEN)?;
        validate_length(&episode_id, "episode_id", MAX_EPISODE_ID_LEN)?;
        validate_length(&github_app_id, "github_app_id", MAX_APP_ID_LEN)?;
        validate_length(&installation_id, "installation_id", MAX_INSTALLATION_ID_LEN)?;

        // Validate scope count
        if scopes.len() > MAX_SCOPES_PER_LEASE {
            return Err(GitHubError::TooManyScopes {
                count: scopes.len(),
                max: MAX_SCOPES_PER_LEASE,
            });
        }

        // Validate tier can use app
        if !risk_tier.allowed_apps().contains(&app) {
            return Err(GitHubError::TierAppMismatch {
                tier: risk_tier,
                app,
            });
        }

        // Validate app allows all scopes
        for scope in &scopes {
            if !app.allows_scope(*scope) {
                return Err(GitHubError::ScopeNotAllowed { app, scope: *scope });
            }
        }

        // Validate cryptographic artifact lengths
        if token_hash.len() != SHA256_HASH_LEN {
            return Err(GitHubError::InvalidInput {
                field: "token_hash".to_string(),
                reason: format!(
                    "token_hash must be exactly {} bytes (SHA-256), got {}",
                    SHA256_HASH_LEN,
                    token_hash.len()
                ),
            });
        }

        if capability_manifest_hash.len() != SHA256_HASH_LEN {
            return Err(GitHubError::InvalidInput {
                field: "capability_manifest_hash".to_string(),
                reason: format!(
                    "capability_manifest_hash must be exactly {} bytes (SHA-256), got {}",
                    SHA256_HASH_LEN,
                    capability_manifest_hash.len()
                ),
            });
        }

        if issuer_signature.len() != ED25519_SIGNATURE_LEN {
            return Err(GitHubError::InvalidInput {
                field: "issuer_signature".to_string(),
                reason: format!(
                    "issuer_signature must be exactly {} bytes (Ed25519), got {}",
                    ED25519_SIGNATURE_LEN,
                    issuer_signature.len()
                ),
            });
        }

        // Validate expires_at > issued_at
        if expires_at <= issued_at {
            return Err(GitHubError::InvalidInput {
                field: "expires_at".to_string(),
                reason: format!(
                    "expires_at ({expires_at}) must be greater than issued_at ({issued_at})"
                ),
            });
        }

        Ok(Self {
            lease_id,
            episode_id,
            github_app_id,
            installation_id,
            app,
            risk_tier,
            scopes,
            token_hash,
            state: GitHubLeaseState::Active,
            issued_at,
            expires_at,
            capability_manifest_hash,
            issuer_signature,
            revocation_reason: None,
            revoker_actor_id: None,
            terminated_at: None,
        })
    }

    /// Returns true if this lease is active.
    #[must_use]
    pub const fn is_active(&self) -> bool {
        self.state.is_active()
    }

    /// Returns true if this lease is in a terminal state.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        self.state.is_terminal()
    }

    /// Checks if the lease has expired based on the given current time.
    #[must_use]
    pub const fn is_expired_at(&self, current_time: u64) -> bool {
        self.state.is_active() && current_time >= self.expires_at
    }

    /// Returns the remaining time until expiration, or 0 if expired.
    #[must_use]
    pub const fn time_remaining(&self, current_time: u64) -> u64 {
        self.expires_at.saturating_sub(current_time)
    }

    /// Marks this lease as revoked.
    ///
    /// # Errors
    ///
    /// Returns an error if the lease is already in a terminal state.
    pub fn revoke(
        &mut self,
        reason: RevocationReason,
        revoker_actor_id: String,
        revoked_at: u64,
    ) -> Result<(), GitHubError> {
        if self.state.is_terminal() {
            return Err(GitHubError::LeaseAlreadyTerminal {
                lease_id: self.lease_id.clone(),
                current_state: self.state.to_string(),
            });
        }

        validate_length(&revoker_actor_id, "revoker_actor_id", MAX_ACTOR_ID_LEN)?;

        self.state = GitHubLeaseState::Revoked;
        self.revocation_reason = Some(reason);
        self.revoker_actor_id = Some(revoker_actor_id);
        self.terminated_at = Some(revoked_at);
        Ok(())
    }

    /// Marks this lease as expired.
    ///
    /// Uses the lease's `expires_at` for `terminated_at` to prevent
    /// pruning evasion attacks.
    ///
    /// # Errors
    ///
    /// Returns an error if the lease is already in a terminal state.
    pub fn expire(&mut self) -> Result<(), GitHubError> {
        if self.state.is_terminal() {
            return Err(GitHubError::LeaseAlreadyTerminal {
                lease_id: self.lease_id.clone(),
                current_state: self.state.to_string(),
            });
        }

        self.state = GitHubLeaseState::Expired;
        self.revocation_reason = Some(RevocationReason::Expired);
        // Use lease's expires_at, not event timestamp, to prevent pruning evasion
        self.terminated_at = Some(self.expires_at);
        Ok(())
    }

    /// Returns true if this lease allows the given scope.
    #[must_use]
    pub fn allows_scope(&self, scope: GitHubScope) -> bool {
        self.scopes.contains(&scope)
    }
}

/// Validates that a string does not exceed the maximum length.
fn validate_length(value: &str, field: &str, max: usize) -> Result<(), GitHubError> {
    if value.len() > max {
        return Err(GitHubError::InvalidInput {
            field: field.to_string(),
            reason: format!("length {} exceeds maximum {max}", value.len()),
        });
    }
    Ok(())
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    /// Valid 32-byte SHA-256 hash for tests.
    fn valid_token_hash() -> Vec<u8> {
        vec![0u8; 32]
    }

    /// Valid 32-byte SHA-256 hash for capability manifest.
    fn valid_capability_manifest_hash() -> Vec<u8> {
        vec![1u8; 32]
    }

    /// Valid 64-byte Ed25519 signature for tests.
    fn valid_issuer_signature() -> Vec<u8> {
        vec![2u8; 64]
    }

    fn test_lease() -> GitHubLease {
        GitHubLease::new(
            "lease-001".to_string(),
            "episode-001".to_string(),
            "12345".to_string(),
            "67890".to_string(),
            GitHubApp::Developer,
            RiskTier::Med,
            vec![GitHubScope::ContentsRead, GitHubScope::PullRequestsWrite],
            valid_token_hash(),
            1_000_000_000, // issued_at
            2_000_000_000, // expires_at
            valid_capability_manifest_hash(),
            valid_issuer_signature(),
        )
        .unwrap()
    }

    #[test]
    fn test_lease_creation() {
        let lease = test_lease();
        assert_eq!(lease.lease_id, "lease-001");
        assert_eq!(lease.state, GitHubLeaseState::Active);
        assert!(lease.is_active());
        assert!(!lease.is_terminal());
    }

    #[test]
    fn test_lease_tier_app_validation() {
        // Low risk tier cannot use Developer app
        let result = GitHubLease::new(
            "lease-001".to_string(),
            "episode-001".to_string(),
            "12345".to_string(),
            "67890".to_string(),
            GitHubApp::Developer,
            RiskTier::Low, // T0 cannot use Developer
            vec![GitHubScope::ContentsRead],
            valid_token_hash(),
            1_000_000_000,
            2_000_000_000,
            valid_capability_manifest_hash(),
            valid_issuer_signature(),
        );
        assert!(matches!(result, Err(GitHubError::TierAppMismatch { .. })));
    }

    #[test]
    fn test_lease_scope_validation() {
        // Reader cannot have PullRequestsWrite scope
        let result = GitHubLease::new(
            "lease-001".to_string(),
            "episode-001".to_string(),
            "12345".to_string(),
            "67890".to_string(),
            GitHubApp::Reader,
            RiskTier::Low,
            vec![GitHubScope::PullRequestsWrite], // Not allowed for Reader
            valid_token_hash(),
            1_000_000_000,
            2_000_000_000,
            valid_capability_manifest_hash(),
            valid_issuer_signature(),
        );
        assert!(matches!(result, Err(GitHubError::ScopeNotAllowed { .. })));
    }

    #[test]
    fn test_lease_invalid_signature_length() {
        // Empty signature
        let result = GitHubLease::new(
            "lease-001".to_string(),
            "episode-001".to_string(),
            "12345".to_string(),
            "67890".to_string(),
            GitHubApp::Reader,
            RiskTier::Low,
            vec![GitHubScope::ContentsRead],
            valid_token_hash(),
            1_000_000_000,
            2_000_000_000,
            valid_capability_manifest_hash(),
            vec![], // Empty signature - invalid
        );
        assert!(
            matches!(result, Err(GitHubError::InvalidInput { field, .. }) if field == "issuer_signature")
        );

        // Wrong length signature (not 64 bytes)
        let result = GitHubLease::new(
            "lease-001".to_string(),
            "episode-001".to_string(),
            "12345".to_string(),
            "67890".to_string(),
            GitHubApp::Reader,
            RiskTier::Low,
            vec![GitHubScope::ContentsRead],
            valid_token_hash(),
            1_000_000_000,
            2_000_000_000,
            valid_capability_manifest_hash(),
            vec![1, 2, 3], // Too short - invalid
        );
        assert!(
            matches!(result, Err(GitHubError::InvalidInput { field, .. }) if field == "issuer_signature")
        );
    }

    #[test]
    fn test_lease_invalid_expiration() {
        let result = GitHubLease::new(
            "lease-001".to_string(),
            "episode-001".to_string(),
            "12345".to_string(),
            "67890".to_string(),
            GitHubApp::Reader,
            RiskTier::Low,
            vec![GitHubScope::ContentsRead],
            valid_token_hash(),
            2_000_000_000, // issued_at
            1_000_000_000, // expires_at < issued_at
            valid_capability_manifest_hash(),
            valid_issuer_signature(),
        );
        assert!(matches!(result, Err(GitHubError::InvalidInput { .. })));
    }

    #[test]
    fn test_lease_is_expired_at() {
        let lease = test_lease();

        // Before expiration
        assert!(!lease.is_expired_at(1_500_000_000));

        // At expiration boundary
        assert!(lease.is_expired_at(2_000_000_000));

        // After expiration
        assert!(lease.is_expired_at(3_000_000_000));
    }

    #[test]
    fn test_lease_time_remaining() {
        let lease = test_lease();
        assert_eq!(lease.time_remaining(1_500_000_000), 500_000_000);
        assert_eq!(lease.time_remaining(2_000_000_000), 0);
        assert_eq!(lease.time_remaining(3_000_000_000), 0);
    }

    #[test]
    fn test_lease_revoke() {
        let mut lease = test_lease();

        lease
            .revoke(
                RevocationReason::Voluntary,
                "actor-001".to_string(),
                1_500_000_000,
            )
            .unwrap();

        assert_eq!(lease.state, GitHubLeaseState::Revoked);
        assert!(lease.is_terminal());
        assert_eq!(lease.revocation_reason, Some(RevocationReason::Voluntary));
        assert_eq!(lease.revoker_actor_id, Some("actor-001".to_string()));
        assert_eq!(lease.terminated_at, Some(1_500_000_000));
    }

    #[test]
    fn test_lease_revoke_already_terminal() {
        let mut lease = test_lease();
        lease
            .revoke(
                RevocationReason::Voluntary,
                "actor-001".to_string(),
                1_500_000_000,
            )
            .unwrap();

        // Cannot revoke again
        let result = lease.revoke(
            RevocationReason::PolicyViolation,
            "actor-002".to_string(),
            1_600_000_000,
        );
        assert!(matches!(
            result,
            Err(GitHubError::LeaseAlreadyTerminal { .. })
        ));
    }

    #[test]
    fn test_lease_expire() {
        let mut lease = test_lease();
        lease.expire().unwrap();

        assert_eq!(lease.state, GitHubLeaseState::Expired);
        assert!(lease.is_terminal());
        assert_eq!(lease.revocation_reason, Some(RevocationReason::Expired));
        // terminated_at should be the lease's expires_at, not event timestamp
        assert_eq!(lease.terminated_at, Some(2_000_000_000));
    }

    #[test]
    fn test_lease_allows_scope() {
        let lease = test_lease();
        assert!(lease.allows_scope(GitHubScope::ContentsRead));
        assert!(lease.allows_scope(GitHubScope::PullRequestsWrite));
        assert!(!lease.allows_scope(GitHubScope::ContentsWrite));
    }

    #[test]
    fn test_github_lease_state_parse() {
        assert_eq!(
            GitHubLeaseState::parse("ACTIVE").unwrap(),
            GitHubLeaseState::Active
        );
        assert_eq!(
            GitHubLeaseState::parse("active").unwrap(),
            GitHubLeaseState::Active
        );
        assert_eq!(
            GitHubLeaseState::parse("REVOKED").unwrap(),
            GitHubLeaseState::Revoked
        );
        assert_eq!(
            GitHubLeaseState::parse("EXPIRED").unwrap(),
            GitHubLeaseState::Expired
        );
        assert!(GitHubLeaseState::parse("UNKNOWN").is_err());
    }

    #[test]
    fn test_revocation_reason_parse() {
        assert_eq!(
            RevocationReason::parse("VOLUNTARY").unwrap(),
            RevocationReason::Voluntary
        );
        assert_eq!(
            RevocationReason::parse("POLICY_VIOLATION").unwrap(),
            RevocationReason::PolicyViolation
        );
        assert_eq!(
            RevocationReason::parse("KEY_COMPROMISE").unwrap(),
            RevocationReason::KeyCompromise
        );
        assert!(RevocationReason::parse("UNKNOWN").is_err());
    }

    #[test]
    fn test_lease_id_length_validation() {
        let long_id = "x".repeat(MAX_LEASE_ID_LEN + 1);
        let result = GitHubLease::new(
            long_id,
            "episode-001".to_string(),
            "12345".to_string(),
            "67890".to_string(),
            GitHubApp::Reader,
            RiskTier::Low,
            vec![GitHubScope::ContentsRead],
            valid_token_hash(),
            1_000_000_000,
            2_000_000_000,
            valid_capability_manifest_hash(),
            valid_issuer_signature(),
        );
        assert!(matches!(result, Err(GitHubError::InvalidInput { .. })));
    }

    #[test]
    fn test_too_many_scopes() {
        let scopes = vec![GitHubScope::ContentsRead; MAX_SCOPES_PER_LEASE + 1];
        let result = GitHubLease::new(
            "lease-001".to_string(),
            "episode-001".to_string(),
            "12345".to_string(),
            "67890".to_string(),
            GitHubApp::Reader,
            RiskTier::Low,
            scopes,
            valid_token_hash(),
            1_000_000_000,
            2_000_000_000,
            valid_capability_manifest_hash(),
            valid_issuer_signature(),
        );
        assert!(matches!(result, Err(GitHubError::TooManyScopes { .. })));
    }

    #[test]
    fn test_token_hash_must_be_32_bytes() {
        // Too short
        let result = GitHubLease::new(
            "lease-001".to_string(),
            "episode-001".to_string(),
            "12345".to_string(),
            "67890".to_string(),
            GitHubApp::Reader,
            RiskTier::Low,
            vec![GitHubScope::ContentsRead],
            vec![0u8; 31], // 31 bytes - too short
            1_000_000_000,
            2_000_000_000,
            valid_capability_manifest_hash(),
            valid_issuer_signature(),
        );
        assert!(
            matches!(result, Err(GitHubError::InvalidInput { field, reason }) if field == "token_hash" && reason.contains("32 bytes"))
        );

        // Too long
        let result = GitHubLease::new(
            "lease-001".to_string(),
            "episode-001".to_string(),
            "12345".to_string(),
            "67890".to_string(),
            GitHubApp::Reader,
            RiskTier::Low,
            vec![GitHubScope::ContentsRead],
            vec![0u8; 33], // 33 bytes - too long
            1_000_000_000,
            2_000_000_000,
            valid_capability_manifest_hash(),
            valid_issuer_signature(),
        );
        assert!(
            matches!(result, Err(GitHubError::InvalidInput { field, reason }) if field == "token_hash" && reason.contains("32 bytes"))
        );

        // Empty
        let result = GitHubLease::new(
            "lease-001".to_string(),
            "episode-001".to_string(),
            "12345".to_string(),
            "67890".to_string(),
            GitHubApp::Reader,
            RiskTier::Low,
            vec![GitHubScope::ContentsRead],
            vec![], // Empty
            1_000_000_000,
            2_000_000_000,
            valid_capability_manifest_hash(),
            valid_issuer_signature(),
        );
        assert!(
            matches!(result, Err(GitHubError::InvalidInput { field, .. }) if field == "token_hash")
        );
    }

    #[test]
    fn test_capability_manifest_hash_must_be_32_bytes() {
        // Too short
        let result = GitHubLease::new(
            "lease-001".to_string(),
            "episode-001".to_string(),
            "12345".to_string(),
            "67890".to_string(),
            GitHubApp::Reader,
            RiskTier::Low,
            vec![GitHubScope::ContentsRead],
            valid_token_hash(),
            1_000_000_000,
            2_000_000_000,
            vec![1u8; 31], // 31 bytes - too short
            valid_issuer_signature(),
        );
        assert!(
            matches!(result, Err(GitHubError::InvalidInput { field, reason }) if field == "capability_manifest_hash" && reason.contains("32 bytes"))
        );

        // Too long
        let result = GitHubLease::new(
            "lease-001".to_string(),
            "episode-001".to_string(),
            "12345".to_string(),
            "67890".to_string(),
            GitHubApp::Reader,
            RiskTier::Low,
            vec![GitHubScope::ContentsRead],
            valid_token_hash(),
            1_000_000_000,
            2_000_000_000,
            vec![1u8; 33], // 33 bytes - too long
            valid_issuer_signature(),
        );
        assert!(
            matches!(result, Err(GitHubError::InvalidInput { field, reason }) if field == "capability_manifest_hash" && reason.contains("32 bytes"))
        );
    }

    #[test]
    fn test_issuer_signature_must_be_64_bytes() {
        // Too short
        let result = GitHubLease::new(
            "lease-001".to_string(),
            "episode-001".to_string(),
            "12345".to_string(),
            "67890".to_string(),
            GitHubApp::Reader,
            RiskTier::Low,
            vec![GitHubScope::ContentsRead],
            valid_token_hash(),
            1_000_000_000,
            2_000_000_000,
            valid_capability_manifest_hash(),
            vec![2u8; 63], // 63 bytes - too short
        );
        assert!(
            matches!(result, Err(GitHubError::InvalidInput { field, reason }) if field == "issuer_signature" && reason.contains("64 bytes"))
        );

        // Too long
        let result = GitHubLease::new(
            "lease-001".to_string(),
            "episode-001".to_string(),
            "12345".to_string(),
            "67890".to_string(),
            GitHubApp::Reader,
            RiskTier::Low,
            vec![GitHubScope::ContentsRead],
            valid_token_hash(),
            1_000_000_000,
            2_000_000_000,
            valid_capability_manifest_hash(),
            vec![2u8; 65], // 65 bytes - too long
        );
        assert!(
            matches!(result, Err(GitHubError::InvalidInput { field, reason }) if field == "issuer_signature" && reason.contains("64 bytes"))
        );
    }
}
