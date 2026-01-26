//! Integration tests for the webhook module.
//!
//! These tests verify the complete webhook handling flow, including:
//! - Signature validation
//! - Payload parsing
//! - Rate limiting
//! - Feature flag behavior

use secrecy::SecretString;

use super::*;

/// Helper to compute a valid signature.
fn compute_signature(secret: &str, payload: &[u8]) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;

    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(payload);
    let result = mac.finalize();
    let bytes = result.into_bytes();

    format!(
        "sha256={}",
        bytes.iter().fold(String::new(), |mut acc, b| {
            use std::fmt::Write;
            let _ = write!(acc, "{b:02x}");
            acc
        })
    )
}

mod signature_tests {
    use super::*;

    #[test]
    fn test_signature_validator_rejects_tampered_payload() {
        let validator = SignatureValidator::new(SecretString::from("my-secret"));

        let original = b"original payload";
        let signature = compute_signature("my-secret", original);

        // Valid signature for original
        assert!(validator.verify(original, &signature).is_ok());

        // Tampered payload should fail
        let tampered = b"tampered payload";
        assert!(matches!(
            validator.verify(tampered, &signature),
            Err(WebhookError::InvalidSignature)
        ));
    }

    #[test]
    fn test_signature_validator_rejects_wrong_secret() {
        let validator = SignatureValidator::new(SecretString::from("correct-secret"));

        let payload = b"test payload";
        let wrong_signature = compute_signature("wrong-secret", payload);

        assert!(matches!(
            validator.verify(payload, &wrong_signature),
            Err(WebhookError::InvalidSignature)
        ));
    }
}

mod payload_tests {
    use super::*;

    fn make_workflow_run_payload(action: &str, conclusion: Option<&str>) -> Vec<u8> {
        let conclusion_json = conclusion
            .map(|c| format!(r#""conclusion": "{c}","#))
            .unwrap_or_default();

        format!(
            r#"{{
                "action": "{action}",
                "workflow_run": {{
                    "id": 99999,
                    "head_sha": "fedcba9876543210",
                    "head_branch": "main",
                    {conclusion_json}
                    "pull_requests": [
                        {{"number": 100}},
                        {{"number": 101}}
                    ]
                }}
            }}"#
        )
        .into_bytes()
    }

    #[test]
    fn test_parse_success_workflow() {
        let payload = make_workflow_run_payload("completed", Some("success"));
        let parsed = WorkflowRunPayload::parse(&payload).unwrap();
        let completed = parsed.into_completed().unwrap();

        assert_eq!(completed.workflow_run_id, 99999);
        assert_eq!(completed.commit_sha, "fedcba9876543210");
        assert_eq!(completed.branch, "main");
        assert_eq!(completed.conclusion, WorkflowConclusion::Success);
        assert_eq!(completed.pull_request_numbers, vec![100, 101]);
    }

    #[test]
    fn test_parse_failure_workflow() {
        let payload = make_workflow_run_payload("completed", Some("failure"));
        let parsed = WorkflowRunPayload::parse(&payload).unwrap();
        let completed = parsed.into_completed().unwrap();

        assert_eq!(completed.conclusion, WorkflowConclusion::Failure);
    }

    #[test]
    fn test_reject_in_progress_workflow() {
        let payload = make_workflow_run_payload("in_progress", None);
        let parsed = WorkflowRunPayload::parse(&payload).unwrap();
        let result = parsed.into_completed();

        assert!(matches!(result, Err(WebhookError::UnsupportedEventType(_))));
    }
}

mod rate_limit_tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;

    #[test]
    fn test_rate_limit_allows_burst() {
        let config = RateLimitConfig {
            max_requests: 10,
            window_secs: 60,
            ..Default::default()
        };
        let limiter = RateLimiter::new(config);
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        // Should allow 10 requests
        for i in 0..10 {
            let result = limiter.check(ip);
            assert!(result.is_ok(), "Request {i} should be allowed");
        }

        // 11th request should be rejected
        assert!(matches!(
            limiter.check(ip),
            Err(WebhookError::RateLimitExceeded)
        ));
    }

    #[test]
    fn test_rate_limit_per_ip_isolation() {
        let config = RateLimitConfig {
            max_requests: 2,
            window_secs: 60,
            ..Default::default()
        };
        let limiter = RateLimiter::new(config);

        let ip1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        // IP1 uses its quota
        assert!(limiter.check(ip1).is_ok());
        assert!(limiter.check(ip1).is_ok());
        assert!(matches!(
            limiter.check(ip1),
            Err(WebhookError::RateLimitExceeded)
        ));

        // IP2 still has its own quota
        assert!(limiter.check(ip2).is_ok());
        assert!(limiter.check(ip2).is_ok());
        assert!(matches!(
            limiter.check(ip2),
            Err(WebhookError::RateLimitExceeded)
        ));
    }
}

mod config_tests {
    use super::*;

    #[test]
    fn test_config_requires_secret() {
        let result = WebhookConfig::builder().enabled(true).build();

        assert!(matches!(result, Err(WebhookConfigError::MissingSecret)));
    }

    #[test]
    fn test_config_requires_minimum_secret_length() {
        let result = WebhookConfig::builder()
            .secret(SecretString::from("short"))
            .enabled(true)
            .build();

        assert!(matches!(
            result,
            Err(WebhookConfigError::SecretTooShort { min_length: 32 })
        ));
    }

    #[test]
    fn test_config_accepts_valid_secret() {
        let result = WebhookConfig::builder()
            .secret(SecretString::from(
                "this-is-a-secret-that-is-at-least-32-bytes-long",
            ))
            .enabled(true)
            .build();

        assert!(result.is_ok());
        assert!(result.unwrap().is_enabled());
    }
}

mod error_tests {
    use axum::http::StatusCode;

    use super::*;

    #[test]
    fn test_error_status_code_mapping() {
        // Definition of Done requirements:
        // - Valid signatures return 200 or 202
        // - Invalid signatures return 401 Unauthorized
        // - Malformed payloads return 400 Bad Request
        // - Rate limit exceeded returns 429 Too Many Requests

        assert_eq!(
            WebhookError::InvalidSignature.status_code(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            WebhookError::MissingSignature.status_code(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            WebhookError::InvalidPayload("test".into()).status_code(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            WebhookError::UnsupportedEventType("test".into()).status_code(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            WebhookError::RateLimitExceeded.status_code(),
            StatusCode::TOO_MANY_REQUESTS
        );
    }

    #[test]
    fn test_disabled_returns_not_found() {
        // When disabled, the endpoint should return 404 to hide its existence
        assert_eq!(WebhookError::Disabled.status_code(), StatusCode::NOT_FOUND);
    }
}

mod event_emitter_tests {
    use super::*;

    #[test]
    fn test_event_emitter_idempotency() {
        let emitter = CIEventEmitter::new();
        let completed = WorkflowRunCompleted {
            workflow_run_id: 12345,
            commit_sha: "abc123".to_string(),
            branch: "main".to_string(),
            conclusion: WorkflowConclusion::Success,
            pull_request_numbers: vec![42],
        };

        // First emission succeeds
        let result1 = emitter.emit(&completed, true, "delivery-123").unwrap();
        assert!(matches!(result1, EmitResult::Emitted { .. }));

        // Same delivery ID is rejected as duplicate
        let result2 = emitter.emit(&completed, true, "delivery-123").unwrap();
        assert_eq!(result2, EmitResult::Duplicate);

        // Different delivery ID succeeds
        let result3 = emitter.emit(&completed, true, "delivery-456").unwrap();
        assert!(matches!(result3, EmitResult::Emitted { .. }));

        // Verify only 2 events stored
        assert_eq!(emitter.event_store().count(), 2);
    }

    #[test]
    fn test_event_emitter_persists_events() {
        use crate::events::ci::{CIConclusion, EventQuery};

        let emitter = CIEventEmitter::new();
        let completed = WorkflowRunCompleted {
            workflow_run_id: 12345,
            commit_sha: "abc123".to_string(),
            branch: "main".to_string(),
            conclusion: WorkflowConclusion::Failure,
            pull_request_numbers: vec![42, 43],
        };

        let result = emitter.emit(&completed, true, "delivery-123").unwrap();
        let EmitResult::Emitted { event_id } = result else {
            panic!("Expected Emitted")
        };

        // Query by PR number
        let query = EventQuery::new().with_pr_number(42);
        let events = emitter.event_store().query(&query);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_id, event_id);
        assert_eq!(events[0].payload.conclusion, CIConclusion::Failure);
    }

    #[test]
    fn test_duplicate_delivery_returns_ok() {
        // Per HTTP semantics, duplicate webhook delivery should return 200 OK
        // (idempotent operation)
        use axum::http::StatusCode;

        assert_eq!(WebhookError::DuplicateDelivery.status_code(), StatusCode::OK);
    }
}

/// Property-based tests for robustness.
#[cfg(test)]
mod proptest_tests {
    use proptest::prelude::*;

    use super::*;

    proptest! {
        /// Test that signature validation never panics on arbitrary input.
        #[test]
        fn signature_validation_never_panics(
            payload in prop::collection::vec(any::<u8>(), 0..10000),
            signature in ".*"
        ) {
            let validator = SignatureValidator::new(SecretString::from("test-secret"));
            // Should not panic, may return error
            let _ = validator.verify(&payload, &signature);
        }

        /// Test that payload parsing never panics on arbitrary input.
        #[test]
        fn payload_parsing_never_panics(
            payload in prop::collection::vec(any::<u8>(), 0..10000)
        ) {
            // Should not panic, may return error
            let _ = WorkflowRunPayload::parse(&payload);
        }

        /// Test that rate limiter handles arbitrary IPs.
        #[test]
        fn rate_limiter_handles_any_ip(
            a in 0u8..=255,
            b in 0u8..=255,
            c in 0u8..=255,
            d in 0u8..=255
        ) {
            use std::net::{IpAddr, Ipv4Addr};

            let config = RateLimitConfig {
                max_requests: 100,
                window_secs: 60,
                ..Default::default()
            };
            let limiter = RateLimiter::new(config);
            let ip = IpAddr::V4(Ipv4Addr::new(a, b, c, d));

            // Should not panic
            let _ = limiter.check(ip);
        }
    }
}
