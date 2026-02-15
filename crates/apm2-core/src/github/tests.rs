//! Integration tests for the GitHub module.

#[cfg(test)]
mod remote_url_tests {
    use crate::github::parse_github_remote_url;

    #[test]
    fn parse_ssh_scp_url() {
        let result = parse_github_remote_url("git@github.com:guardian-intelligence/apm2.git");
        assert_eq!(
            result,
            Some(("guardian-intelligence".to_string(), "apm2".to_string()))
        );
    }

    #[test]
    fn parse_ssh_scp_no_suffix() {
        let result = parse_github_remote_url("git@github.com:owner/repo");
        assert_eq!(result, Some(("owner".to_string(), "repo".to_string())));
    }

    #[test]
    fn parse_https_url() {
        let result = parse_github_remote_url("https://github.com/guardian-intelligence/apm2.git");
        assert_eq!(
            result,
            Some(("guardian-intelligence".to_string(), "apm2".to_string()))
        );
    }

    #[test]
    fn parse_https_no_suffix() {
        let result = parse_github_remote_url("https://github.com/guardian-intelligence/apm2");
        assert_eq!(
            result,
            Some(("guardian-intelligence".to_string(), "apm2".to_string()))
        );
    }

    #[test]
    fn parse_ssh_protocol_url() {
        let result = parse_github_remote_url("ssh://git@github.com/guardian-intelligence/apm2.git");
        assert_eq!(
            result,
            Some(("guardian-intelligence".to_string(), "apm2".to_string()))
        );
    }

    #[test]
    fn parse_http_url() {
        let result = parse_github_remote_url("http://github.com/guardian-intelligence/apm2");
        assert_eq!(
            result,
            Some(("guardian-intelligence".to_string(), "apm2".to_string()))
        );
    }

    #[test]
    fn reject_invalid_url() {
        assert_eq!(parse_github_remote_url("not-a-url"), None);
    }

    #[test]
    fn reject_empty_url() {
        assert_eq!(parse_github_remote_url(""), None);
    }

    #[test]
    fn reject_empty_owner() {
        assert_eq!(parse_github_remote_url("git@github.com:/repo.git"), None);
    }

    #[test]
    fn reject_no_repo() {
        assert_eq!(parse_github_remote_url("git@github.com:owner"), None);
    }

    #[test]
    fn reject_oversized_url() {
        let long_url = format!("https://github.com/{}/repo", "a".repeat(3000));
        assert_eq!(parse_github_remote_url(&long_url), None);
    }

    #[test]
    fn reject_injection_characters() {
        assert_eq!(
            parse_github_remote_url("git@github.com:owner/../etc.git"),
            None
        );
    }

    #[test]
    fn parse_url_with_dots_and_underscores() {
        let result = parse_github_remote_url("https://github.com/my.org/my_repo.git");
        assert_eq!(result, Some(("my.org".to_string(), "my_repo".to_string())));
    }

    // --- Negative tests for extra path segments (MAJOR fix) ---

    #[test]
    fn reject_https_extra_path_segments() {
        // Must reject URLs with extra path beyond owner/repo
        assert_eq!(
            parse_github_remote_url("https://github.com/owner/repo/tree/main"),
            None
        );
    }

    #[test]
    fn reject_https_extra_path_blob() {
        assert_eq!(
            parse_github_remote_url("https://github.com/owner/repo/blob/main/README.md"),
            None
        );
    }

    #[test]
    fn reject_https_extra_path_pulls() {
        assert_eq!(
            parse_github_remote_url("https://github.com/owner/repo/pulls"),
            None
        );
    }

    #[test]
    fn reject_ssh_extra_path_segments() {
        assert_eq!(
            parse_github_remote_url("ssh://git@github.com/owner/repo/extra"),
            None
        );
    }

    #[test]
    fn reject_http_extra_path_segments() {
        assert_eq!(
            parse_github_remote_url("http://github.com/owner/repo/extra/path"),
            None
        );
    }

    #[test]
    fn accept_https_trailing_slash() {
        // Trailing slash should still parse correctly
        let result = parse_github_remote_url("https://github.com/owner/repo/");
        assert_eq!(result, Some(("owner".to_string(), "repo".to_string())));
    }

    #[test]
    fn accept_scp_trailing_slash() {
        let result = parse_github_remote_url("git@github.com:owner/repo/");
        assert_eq!(result, Some(("owner".to_string(), "repo".to_string())));
    }

    #[test]
    fn reject_https_extra_with_git_suffix() {
        // Must not accept extra segments even with .git at the end
        assert_eq!(
            parse_github_remote_url("https://github.com/owner/repo/extra.git"),
            None
        );
    }
}

#[cfg(test)]
mod validation_tests {
    use crate::github::{
        GitHubError, MAX_API_ENDPOINT_LEN, MAX_REPOSITORY_LEN, validate_api_endpoint,
        validate_repository,
    };

    // ========== API Endpoint Validation Tests ==========

    #[test]
    fn test_validate_api_endpoint_valid() {
        // Standard GitHub API endpoints
        assert!(validate_api_endpoint("/repos/owner/repo/pulls").is_ok());
        assert!(validate_api_endpoint("/repos/owner/repo/issues/123").is_ok());
        assert!(validate_api_endpoint("/repos/my-org/my_repo/contents/path/to/file.rs").is_ok());
        assert!(validate_api_endpoint("/user").is_ok());
        assert!(validate_api_endpoint("/").is_ok());
    }

    #[test]
    fn test_validate_api_endpoint_missing_leading_slash() {
        let result = validate_api_endpoint("repos/owner/repo");
        assert!(matches!(
            result,
            Err(GitHubError::InvalidApiEndpoint { reason }) if reason.contains("start with '/'")
        ));
    }

    #[test]
    fn test_validate_api_endpoint_path_traversal() {
        // Single traversal
        let result = validate_api_endpoint("/repos/../etc/passwd");
        assert!(matches!(
            result,
            Err(GitHubError::InvalidApiEndpoint { reason }) if reason.contains("..")
        ));

        // Double traversal
        let result = validate_api_endpoint("/repos/owner/..%2f../etc");
        assert!(matches!(
            result,
            Err(GitHubError::InvalidApiEndpoint { reason }) if reason.contains("..")
        ));

        // At the end
        let result = validate_api_endpoint("/repos/owner/..");
        assert!(matches!(
            result,
            Err(GitHubError::InvalidApiEndpoint { reason }) if reason.contains("..")
        ));

        // Multiple occurrences
        let result = validate_api_endpoint("/repos/../owner/../repo");
        assert!(matches!(
            result,
            Err(GitHubError::InvalidApiEndpoint { reason }) if reason.contains("..")
        ));
    }

    #[test]
    fn test_validate_api_endpoint_control_characters() {
        // Null byte
        let result = validate_api_endpoint("/repos/owner\x00/repo");
        assert!(matches!(
            result,
            Err(GitHubError::InvalidApiEndpoint { reason }) if reason.contains("control characters")
        ));

        // Newline
        let result = validate_api_endpoint("/repos/owner\n/repo");
        assert!(matches!(
            result,
            Err(GitHubError::InvalidApiEndpoint { reason }) if reason.contains("control characters")
        ));

        // Carriage return
        let result = validate_api_endpoint("/repos/owner\r/repo");
        assert!(matches!(
            result,
            Err(GitHubError::InvalidApiEndpoint { reason }) if reason.contains("control characters")
        ));

        // Tab
        let result = validate_api_endpoint("/repos/owner\t/repo");
        assert!(matches!(
            result,
            Err(GitHubError::InvalidApiEndpoint { reason }) if reason.contains("control characters")
        ));

        // DEL (0x7F)
        let result = validate_api_endpoint("/repos/owner\x7F/repo");
        assert!(matches!(
            result,
            Err(GitHubError::InvalidApiEndpoint { reason }) if reason.contains("control characters")
        ));
    }

    #[test]
    fn test_validate_api_endpoint_length_exceeded() {
        let long_endpoint = format!("/{}", "a".repeat(MAX_API_ENDPOINT_LEN));
        let result = validate_api_endpoint(&long_endpoint);
        assert!(matches!(
            result,
            Err(GitHubError::InvalidApiEndpoint { reason }) if reason.contains("exceeds maximum")
        ));
    }

    #[test]
    fn test_validate_api_endpoint_max_length_ok() {
        // Exactly at max length should be OK
        let endpoint = format!("/{}", "a".repeat(MAX_API_ENDPOINT_LEN - 1));
        assert!(validate_api_endpoint(&endpoint).is_ok());
    }

    #[test]
    fn test_validate_api_endpoint_empty() {
        let result = validate_api_endpoint("");
        assert!(matches!(
            result,
            Err(GitHubError::InvalidApiEndpoint { reason }) if reason.contains("start with '/'")
        ));
    }

    // ========== Repository Validation Tests ==========

    #[test]
    fn test_validate_repository_valid() {
        assert!(validate_repository("owner/repo").is_ok());
        assert!(validate_repository("my-org/my-repo").is_ok());
        assert!(validate_repository("My_Org/My_Repo").is_ok());
        assert!(validate_repository("org.name/repo.name").is_ok());
        assert!(validate_repository("a/b").is_ok());
        assert!(validate_repository("org123/repo456").is_ok());
        assert!(validate_repository("Org-Name_123/Repo.Name-456_test").is_ok());
    }

    #[test]
    fn test_validate_repository_missing_slash() {
        let result = validate_repository("ownerrepo");
        assert!(matches!(
            result,
            Err(GitHubError::InvalidRepository { reason }) if reason.contains("owner/repo")
        ));
    }

    #[test]
    fn test_validate_repository_too_many_slashes() {
        let result = validate_repository("owner/repo/extra");
        assert!(matches!(
            result,
            Err(GitHubError::InvalidRepository { reason }) if reason.contains("owner/repo")
        ));
    }

    #[test]
    fn test_validate_repository_empty_owner() {
        let result = validate_repository("/repo");
        assert!(matches!(
            result,
            Err(GitHubError::InvalidRepository { reason }) if reason.contains("owner cannot be empty")
        ));
    }

    #[test]
    fn test_validate_repository_empty_repo() {
        let result = validate_repository("owner/");
        assert!(matches!(
            result,
            Err(GitHubError::InvalidRepository { reason }) if reason.contains("repo cannot be empty")
        ));
    }

    #[test]
    fn test_validate_repository_starts_with_hyphen() {
        let result = validate_repository("-owner/repo");
        assert!(matches!(
            result,
            Err(GitHubError::InvalidRepository { reason }) if reason.contains("must start with an alphanumeric")
        ));

        let result = validate_repository("owner/-repo");
        assert!(matches!(
            result,
            Err(GitHubError::InvalidRepository { reason }) if reason.contains("must start with an alphanumeric")
        ));
    }

    #[test]
    fn test_validate_repository_starts_with_underscore() {
        let result = validate_repository("_owner/repo");
        assert!(matches!(
            result,
            Err(GitHubError::InvalidRepository { reason }) if reason.contains("must start with an alphanumeric")
        ));
    }

    #[test]
    fn test_validate_repository_starts_with_dot() {
        let result = validate_repository(".owner/repo");
        assert!(matches!(
            result,
            Err(GitHubError::InvalidRepository { reason }) if reason.contains("must start with an alphanumeric")
        ));
    }

    #[test]
    fn test_validate_repository_invalid_characters() {
        // Space
        let result = validate_repository("owner name/repo");
        assert!(matches!(
            result,
            Err(GitHubError::InvalidRepository { reason }) if reason.contains("invalid character")
        ));

        // Special characters
        let result = validate_repository("owner@name/repo");
        assert!(matches!(
            result,
            Err(GitHubError::InvalidRepository { reason }) if reason.contains("invalid character")
        ));

        let result = validate_repository("owner/repo#name");
        assert!(matches!(
            result,
            Err(GitHubError::InvalidRepository { reason }) if reason.contains("invalid character")
        ));

        let result = validate_repository("owner/repo$name");
        assert!(matches!(
            result,
            Err(GitHubError::InvalidRepository { reason }) if reason.contains("invalid character")
        ));
    }

    #[test]
    fn test_validate_repository_length_exceeded() {
        let long_owner = "a".repeat(MAX_REPOSITORY_LEN);
        let result = validate_repository(&format!("{long_owner}/repo"));
        assert!(matches!(
            result,
            Err(GitHubError::InvalidRepository { reason }) if reason.contains("exceeds maximum")
        ));
    }

    #[test]
    fn test_validate_repository_max_length_ok() {
        // Close to max length but still valid
        let half_len = (MAX_REPOSITORY_LEN - 2) / 2;
        let repo = format!("{}/{}", "a".repeat(half_len), "b".repeat(half_len));
        assert!(validate_repository(&repo).is_ok());
    }

    #[test]
    fn test_validate_repository_path_traversal_not_applicable() {
        // ".." is not a valid owner/repo format anyway (doesn't start with
        // alphanumeric) but let's ensure we catch it
        let result = validate_repository("../etc");
        assert!(matches!(
            result,
            Err(GitHubError::InvalidRepository { reason }) if reason.contains("must start with an alphanumeric")
        ));
    }

    #[test]
    fn test_validate_repository_control_characters() {
        // Control characters in owner
        let result = validate_repository("owner\x00name/repo");
        assert!(matches!(
            result,
            Err(GitHubError::InvalidRepository { reason }) if reason.contains("invalid character")
        ));

        // Control characters in repo
        let result = validate_repository("owner/repo\nname");
        assert!(matches!(
            result,
            Err(GitHubError::InvalidRepository { reason }) if reason.contains("invalid character")
        ));
    }
}

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
        // Use a fixed timestamp: 2026-01-15 12:00:00 UTC in nanoseconds since
        // UNIX_EPOCH 2026-01-15 12:00:00 UTC = 1768478400 seconds since epoch
        let now_nanos: u64 = 1_768_478_400_000_000_000;

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
            vec![1u8; 32], // capability_manifest_hash: 32 bytes for SHA-256
            vec![2u8; 64], // issuer_signature: 64 bytes for Ed25519
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
            vec![0u8; 32], // token_hash: 32 bytes for SHA-256
            1_000_000_000, // issued_at
            2_000_000_000, // expires_at
            vec![1u8; 32], // capability_manifest_hash: 32 bytes for SHA-256
            vec![2u8; 64], // issuer_signature: 64 bytes for Ed25519
        )
        .unwrap()
    }
}
