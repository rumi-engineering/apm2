//! Integration tests for the GitHub module.

#[cfg(test)]
mod integration_tests {
    use crate::github::{
        GitHubApp, GitHubLease, GitHubLeaseState, GitHubScope, MockTokenProvider, RevocationReason,
        RiskTier, TokenProvider, TokenRequest, TokenResponse,
    };

    /// Tests the full flow of requesting a token and creating a lease.
    #[test]
    fn test_token_to_lease_flow() {
        // 1. Create a token request
        let provider = MockTokenProvider::new();
        let request = TokenRequest::new(
            GitHubApp::Developer,
            "installation-123".to_string(),
            RiskTier::Med,
            "episode-456".to_string(),
        )
        .with_scopes(vec![
            GitHubScope::ContentsRead,
            GitHubScope::PullRequestsWrite,
        ]);

        // 2. Validate the request
        assert!(request.validate().is_ok());

        // 3. Mint the token
        let response = provider.mint_token(&request).unwrap();
        assert_eq!(response.token_hash.len(), 32);

        // 4. Create a lease from the token response
        #[allow(clippy::cast_possible_truncation)]
        let now_nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);

        #[allow(clippy::cast_possible_truncation)]
        let expires_at_nanos = (u128::from(response.expires_at) * 1_000_000_000) as u64;

        let lease = GitHubLease::new(
            "lease-001".to_string(),
            request.episode_id.clone(),
            response.app_id.clone(),
            response.installation_id.clone(),
            request.app,
            request.risk_tier,
            response.scopes.clone(),
            response.token_hash,
            now_nanos,
            expires_at_nanos,
            vec![1, 2, 3], // capability_manifest_hash
            vec![4, 5, 6], // issuer_signature
        )
        .unwrap();

        // 5. Verify lease properties
        assert_eq!(lease.state, GitHubLeaseState::Active);
        assert!(lease.is_active());
        assert!(lease.allows_scope(GitHubScope::ContentsRead));
        assert!(lease.allows_scope(GitHubScope::PullRequestsWrite));
        assert!(!lease.allows_scope(GitHubScope::ContentsWrite));
    }

    /// Tests that tier escalation is prevented.
    #[test]
    fn test_tier_escalation_prevention() {
        // Low risk agent tries to use Developer app
        let request = TokenRequest::new(
            GitHubApp::Developer,
            "installation-123".to_string(),
            RiskTier::Low,
            "episode-456".to_string(),
        );

        // Request validation should fail
        let result = request.validate();
        assert!(result.is_err());

        // Provider should also reject
        let provider = MockTokenProvider::new();
        let result = provider.mint_token(&request);
        assert!(result.is_err());
    }

    /// Tests that scope escalation is prevented.
    #[test]
    fn test_scope_escalation_prevention() {
        // Developer app tries to get ContentsWrite scope
        let request = TokenRequest::new(
            GitHubApp::Developer,
            "installation-123".to_string(),
            RiskTier::Med,
            "episode-456".to_string(),
        )
        .with_scopes(vec![GitHubScope::ContentsWrite]);

        // Request validation should fail
        let result = request.validate();
        assert!(result.is_err());

        // Provider should also reject
        let provider = MockTokenProvider::new();
        let result = provider.mint_token(&request);
        assert!(result.is_err());
    }

    /// Tests lease revocation flow.
    #[test]
    fn test_lease_revocation_flow() {
        let mut lease = create_test_lease();

        // Verify active state
        assert!(lease.is_active());
        assert!(!lease.is_terminal());

        // Revoke the lease
        lease
            .revoke(
                RevocationReason::PolicyViolation,
                "admin-actor".to_string(),
                2_000_000_000,
            )
            .unwrap();

        // Verify revoked state
        assert!(!lease.is_active());
        assert!(lease.is_terminal());
        assert_eq!(lease.state, GitHubLeaseState::Revoked);
        assert_eq!(
            lease.revocation_reason,
            Some(RevocationReason::PolicyViolation)
        );
        assert_eq!(lease.revoker_actor_id, Some("admin-actor".to_string()));

        // Cannot revoke again
        let result = lease.revoke(
            RevocationReason::KeyCompromise,
            "another-actor".to_string(),
            3_000_000_000,
        );
        assert!(result.is_err());
    }

    /// Tests lease expiration flow.
    #[test]
    fn test_lease_expiration_flow() {
        let mut lease = create_test_lease();

        // Verify not expired yet at issued time
        assert!(!lease.is_expired_at(1_000_000_000));

        // Should be expired at expires_at time
        assert!(lease.is_expired_at(2_000_000_000));

        // Mark as expired
        lease.expire().unwrap();

        // Verify expired state
        assert!(!lease.is_active());
        assert!(lease.is_terminal());
        assert_eq!(lease.state, GitHubLeaseState::Expired);

        // terminated_at should be lease.expires_at (not event timestamp)
        // This prevents pruning evasion attacks
        assert_eq!(lease.terminated_at, Some(2_000_000_000));
    }

    /// Tests token hash computation.
    #[test]
    fn test_token_hash_security() {
        let token = "ghs_test_token_12345";
        let hash = TokenResponse::hash_token(token);

        // Hash should be 32 bytes (SHA-256)
        assert_eq!(hash.len(), 32);

        // Same token should produce same hash (deterministic)
        let hash2 = TokenResponse::hash_token(token);
        assert_eq!(hash, hash2);

        // Different token should produce different hash
        let different_hash = TokenResponse::hash_token("ghs_different_token");
        assert_ne!(hash, different_hash);

        // Hash should not contain the original token
        let hash_str = format!("{hash:?}");
        assert!(!hash_str.contains("test_token"));
    }

    /// Tests that all tier-app combinations are correct.
    #[test]
    fn test_all_tier_app_combinations() {
        struct TestCase {
            tier: RiskTier,
            app: GitHubApp,
            should_allow: bool,
        }

        let cases = vec![
            // Low can only use Reader
            TestCase {
                tier: RiskTier::Low,
                app: GitHubApp::Reader,
                should_allow: true,
            },
            TestCase {
                tier: RiskTier::Low,
                app: GitHubApp::Developer,
                should_allow: false,
            },
            TestCase {
                tier: RiskTier::Low,
                app: GitHubApp::Operator,
                should_allow: false,
            },
            // Med can use Reader and Developer
            TestCase {
                tier: RiskTier::Med,
                app: GitHubApp::Reader,
                should_allow: true,
            },
            TestCase {
                tier: RiskTier::Med,
                app: GitHubApp::Developer,
                should_allow: true,
            },
            TestCase {
                tier: RiskTier::Med,
                app: GitHubApp::Operator,
                should_allow: false,
            },
            // High can use all apps
            TestCase {
                tier: RiskTier::High,
                app: GitHubApp::Reader,
                should_allow: true,
            },
            TestCase {
                tier: RiskTier::High,
                app: GitHubApp::Developer,
                should_allow: true,
            },
            TestCase {
                tier: RiskTier::High,
                app: GitHubApp::Operator,
                should_allow: true,
            },
        ];

        for case in cases {
            let allowed = case.tier.allowed_apps().contains(&case.app);
            assert_eq!(
                allowed, case.should_allow,
                "Tier {:?} + App {:?}: expected {}, got {}",
                case.tier, case.app, case.should_allow, allowed
            );
        }
    }

    /// Tests that TTL decreases with increasing risk tier.
    #[test]
    fn test_ttl_proportional_to_risk() {
        let tiers = [RiskTier::Low, RiskTier::Med, RiskTier::High];

        for i in 0..tiers.len() - 1 {
            let current_ttl = tiers[i].default_ttl();
            let next_ttl = tiers[i + 1].default_ttl();
            assert!(
                current_ttl > next_ttl,
                "{} TTL ({:?}) should be > {} TTL ({:?})",
                tiers[i],
                current_ttl,
                tiers[i + 1],
                next_ttl
            );
        }
    }

    fn create_test_lease() -> GitHubLease {
        GitHubLease::new(
            "lease-001".to_string(),
            "episode-001".to_string(),
            "app-12345".to_string(),
            "installation-67890".to_string(),
            GitHubApp::Developer,
            RiskTier::Med,
            vec![GitHubScope::ContentsRead, GitHubScope::PullRequestsWrite],
            vec![1, 2, 3, 4, 5, 6, 7, 8],
            1_000_000_000, // issued_at
            2_000_000_000, // expires_at
            vec![10, 20, 30],
            vec![40, 50, 60],
        )
        .unwrap()
    }
}
