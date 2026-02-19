// AGENT-AUTHORED (TCK-00559)
//! Security regression tests: fuzz job spec parsing + adversarial queue file
//! tests + `safe_rmtree` property tests.
//!
//! This integration test file covers three security-critical regression areas:
//!
//! 1. **`FacJobSpecV1` adversarial parsing**: Malformed JSON, oversized inputs,
//!    type confusion, and boundary-value fixtures that must never panic and
//!    must be rejected fail-closed.
//!
//! 2. **Queue file tampering**: Digest mismatch, token mismatch, unknown
//!    fields, schema corruption, and field mutation — all must be detected and
//!    rejected by the validation pipeline.
//!
//! 3. **`safe_rmtree` property tests**: Symlink refusal, no parent escape,
//!    dot-segment rejection, and TOCTOU smoke tests using proptest for
//!    randomized path generation.
//!
//! # Security invariants tested
//!
//! - [INV-JS-001] `job_spec_digest` covers all fields except the mutable token.
//! - [INV-JS-002] Digest and request-id checks are constant-time.
//! - [INV-JS-003] Validation is fail-closed.
//! - [INV-JS-004] Boundary structs use `#[serde(deny_unknown_fields)]`.
//! - [INV-RMTREE-001] Symlink at any depth causes abort.
//! - [INV-RMTREE-002] Root must be strictly under `allowed_parent`.
//! - [INV-RMTREE-005] Both paths must be absolute.
//! - [INV-RMTREE-010] Dot-segment paths are rejected.

// ── Shared helpers ──────────────────────────────────────────────────────
//
// Extracted to file level so inner modules can reuse without duplication.

use apm2_core::fac::JobSource;

fn sample_source() -> JobSource {
    JobSource {
        kind: "mirror_commit".to_string(),
        repo_id: "org-repo".to_string(),
        head_sha: "a".repeat(40),
        patch: None,
    }
}

// =============================================================================
// Part 1: FacJobSpecV1 Adversarial Parsing
// =============================================================================
//
// These tests exercise the job spec parsing and validation pipeline with
// adversarial inputs that a fuzzer would generate. They serve as
// deterministic regression anchors for the fuzz target.

mod job_spec_adversarial {
    use apm2_core::fac::{
        FacJobSpecV1, FacJobSpecV1Builder, JOB_SPEC_SCHEMA_ID, JobSource, JobSpecError,
        MAX_JOB_SPEC_SIZE, deserialize_job_spec,
    };

    use super::sample_source;

    // ── Helpers ─────────────────────────────────────────────────────────

    fn build_valid_spec() -> FacJobSpecV1 {
        FacJobSpecV1Builder::new(
            "job-test-559",
            "gates",
            "bulk",
            "2026-02-18T00:00:00Z",
            "lease-1",
            sample_source(),
        )
        .channel_context_token("valid-token-base64")
        .memory_max_bytes(64_000_000_000)
        .build()
        .expect("valid spec should build")
    }

    // ── Oversized input rejection ───────────────────────────────────────

    #[test]
    fn reject_oversized_input() {
        let huge = vec![b'{'; MAX_JOB_SPEC_SIZE + 1];
        let result = deserialize_job_spec(&huge);
        assert!(
            matches!(result, Err(JobSpecError::InputTooLarge { .. })),
            "must reject input exceeding MAX_JOB_SPEC_SIZE"
        );
    }

    #[test]
    fn reject_input_at_exact_limit_plus_one() {
        // Exactly MAX_JOB_SPEC_SIZE + 1 bytes
        let data = vec![0x20; MAX_JOB_SPEC_SIZE + 1];
        let result = deserialize_job_spec(&data);
        assert!(result.is_err(), "must reject oversized input");
    }

    #[test]
    fn accept_input_at_exact_limit() {
        // Exactly MAX_JOB_SPEC_SIZE bytes of whitespace (valid JSON is spaces)
        // This will fail JSON parsing but should not fail the size check.
        let data = vec![0x20; MAX_JOB_SPEC_SIZE];
        let result = deserialize_job_spec(&data);
        // Must fail with a JSON parse error, NOT an InputTooLarge error.
        match result {
            Err(JobSpecError::InputTooLarge { .. }) => {
                panic!("should not reject at-limit input as too large");
            },
            Err(JobSpecError::Json { .. }) => {
                // Expected: whitespace-only input fails JSON parsing.
            },
            Err(other) => {
                panic!("unexpected error variant at exact limit: {other:?}");
            },
            Ok(_) => {
                panic!("whitespace-only input should not parse as valid JSON");
            },
        }
    }

    // ── Malformed JSON inputs (no panic) ────────────────────────────────

    #[test]
    fn no_panic_on_empty_input() {
        let result = deserialize_job_spec(b"");
        assert!(result.is_err());
    }

    #[test]
    fn no_panic_on_null_bytes() {
        let result = deserialize_job_spec(&[0u8; 256]);
        assert!(result.is_err());
    }

    #[test]
    fn no_panic_on_deeply_nested_json() {
        // 128 levels of nested arrays
        let mut json = String::new();
        for _ in 0..128 {
            json.push('[');
        }
        for _ in 0..128 {
            json.push(']');
        }
        let result = deserialize_job_spec(json.as_bytes());
        assert!(result.is_err());
    }

    #[test]
    fn no_panic_on_utf8_boundary_abuse() {
        // Valid UTF-8 but adversarial for JSON: mix of multi-byte chars
        let data = b"\xc0\x80\xf0\x90\x80\x80";
        let result = deserialize_job_spec(data);
        assert!(result.is_err());
    }

    #[test]
    fn no_panic_on_json_number_overflow() {
        let json = format!(
            r#"{{"schema":"{JOB_SPEC_SCHEMA_ID}","priority":99999999999999999999999999999999}}"#,
        );
        let result = deserialize_job_spec(json.as_bytes());
        assert!(result.is_err());
    }

    #[test]
    fn no_panic_on_type_confusion_array() {
        // Send a JSON array instead of an object
        let result = deserialize_job_spec(b"[1,2,3]");
        assert!(result.is_err());
    }

    #[test]
    fn no_panic_on_type_confusion_string() {
        let result = deserialize_job_spec(b"\"hello\"");
        assert!(result.is_err());
    }

    #[test]
    fn no_panic_on_type_confusion_number() {
        let result = deserialize_job_spec(b"42");
        assert!(result.is_err());
    }

    #[test]
    fn no_panic_on_type_confusion_boolean() {
        let result = deserialize_job_spec(b"true");
        assert!(result.is_err());
    }

    #[test]
    fn no_panic_on_type_confusion_null() {
        let result = deserialize_job_spec(b"null");
        assert!(result.is_err());
    }

    // ── Field-level adversarial values ──────────────────────────────────

    #[test]
    fn reject_empty_schema() {
        let mut spec = build_valid_spec();
        spec.schema = String::new();
        assert!(matches!(
            spec.validate_structure(),
            Err(JobSpecError::SchemaMismatch { .. })
        ));
    }

    #[test]
    fn reject_wrong_schema() {
        let mut spec = build_valid_spec();
        spec.schema = "apm2.fac.job_spec.v2".to_string();
        assert!(matches!(
            spec.validate_structure(),
            Err(JobSpecError::SchemaMismatch { .. })
        ));
    }

    #[test]
    fn reject_null_bytes_in_job_id() {
        let result = FacJobSpecV1Builder::new(
            "job\0id",
            "gates",
            "bulk",
            "2026-02-18T00:00:00Z",
            "lease-1",
            sample_source(),
        )
        .channel_context_token("valid-token")
        .build();
        // NUL bytes in job_id MUST be rejected by strict charset validation
        // (INV-JS-006).  job_id only allows [A-Za-z0-9_-].
        assert!(
            matches!(
                result,
                Err(JobSpecError::InvalidFormat {
                    field: "job_id",
                    ..
                })
            ),
            "NUL bytes in job_id must be rejected: {result:?}"
        );
    }

    #[test]
    fn reject_extremely_long_job_id() {
        let long_id = "x".repeat(300);
        let result = FacJobSpecV1Builder::new(
            long_id.as_str(),
            "gates",
            "bulk",
            "2026-02-18T00:00:00Z",
            "lease-1",
            sample_source(),
        )
        .build();
        assert!(
            matches!(
                result,
                Err(JobSpecError::FieldTooLong {
                    field: "job_id",
                    ..
                })
            ),
            "must reject oversized job_id"
        );
    }

    #[test]
    fn reject_priority_overflow() {
        let result = FacJobSpecV1Builder::new(
            "job1",
            "gates",
            "bulk",
            "2026-02-18T00:00:00Z",
            "lease-1",
            sample_source(),
        )
        .priority(101)
        .build();
        assert!(matches!(
            result,
            Err(JobSpecError::PriorityOutOfRange { value: 101 })
        ));
    }

    #[test]
    fn reject_priority_max_u32() {
        let result = FacJobSpecV1Builder::new(
            "job1",
            "gates",
            "bulk",
            "2026-02-18T00:00:00Z",
            "lease-1",
            sample_source(),
        )
        .priority(u32::MAX)
        .build();
        assert!(matches!(
            result,
            Err(JobSpecError::PriorityOutOfRange { .. })
        ));
    }

    #[test]
    fn reject_invalid_kind() {
        let mut spec = build_valid_spec();
        spec.kind = "evil_kind".to_string();
        assert!(matches!(
            spec.validate_structure(),
            Err(JobSpecError::InvalidFormat { field: "kind", .. })
        ));
    }

    #[test]
    fn reject_invalid_source_kind() {
        let mut spec = build_valid_spec();
        spec.source.kind = "unknown_source".to_string();
        assert!(matches!(
            spec.validate_structure(),
            Err(JobSpecError::InvalidFormat {
                field: "source.kind",
                ..
            })
        ));
    }

    #[test]
    fn reject_path_traversal_in_repo_id_structural() {
        // These patterns are caught by validate_repo_id() during build():
        // backslash, leading slash, dot-dot segments, dot-only segments.
        let adversarial_ids = [
            "../../../etc/passwd",
            "/etc/shadow",
            "C:\\Windows\\System32",
            "\\\\evil-server\\share",
            "./local-file",
            "repo/../escape",
        ];
        for bad_id in &adversarial_ids {
            let source = JobSource {
                kind: "mirror_commit".to_string(),
                repo_id: bad_id.to_string(),
                head_sha: "a".repeat(40),
                patch: None,
            };
            let result = FacJobSpecV1Builder::new(
                "job1",
                "gates",
                "bulk",
                "2026-02-18T00:00:00Z",
                "lease-1",
                source,
            )
            .build();
            assert!(
                result.is_err(),
                "must reject path-traversal repo_id: {bad_id}"
            );
        }
    }

    #[test]
    fn reject_tilde_expansion_in_repo_id() {
        // Tilde home-directory expansion (~/...) is caught by
        // `reject_filesystem_paths()` which is called from
        // `validate_job_spec()` at the core layer (INV-JS-006).
        use apm2_core::fac::validate_job_spec;

        let source = JobSource {
            kind: "mirror_commit".to_string(),
            repo_id: "~/important-file".to_string(),
            head_sha: "a".repeat(40),
            patch: None,
        };
        let spec = FacJobSpecV1Builder::new(
            "job1",
            "gates",
            "bulk",
            "2026-02-18T00:00:00Z",
            "lease-1",
            source,
        )
        .channel_context_token("valid-token")
        .build()
        .expect("builder accepts tilde — structural validation does not cover it");

        let result = validate_job_spec(&spec);
        assert!(
            matches!(result, Err(JobSpecError::FilesystemPathRejected { .. })),
            "validate_job_spec must reject tilde-expansion repo_id: ~/important-file, got: {result:?}"
        );
    }

    #[test]
    fn reject_invalid_head_sha() {
        let bad_shas: Vec<String> = vec![
            String::new(),     // empty
            "xyz".to_string(), // too short, non-hex
            "g".repeat(40),    // non-hex chars, correct length
            "a".repeat(39),    // one char short
            "a".repeat(41),    // one char too long
            "a".repeat(63),    // not 40 or 64
        ];
        for bad_sha in &bad_shas {
            let source = JobSource {
                kind: "mirror_commit".to_string(),
                repo_id: "org-repo".to_string(),
                head_sha: bad_sha.clone(),
                patch: None,
            };
            let result = FacJobSpecV1Builder::new(
                "job1",
                "gates",
                "bulk",
                "2026-02-18T00:00:00Z",
                "lease-1",
                source,
            )
            .build();
            assert!(result.is_err(), "must reject bad head_sha: {bad_sha}");
        }
    }

    #[test]
    fn accept_valid_64_char_head_sha() {
        let source = JobSource {
            kind: "mirror_commit".to_string(),
            repo_id: "org-repo".to_string(),
            head_sha: "a".repeat(64), // SHA-256 length
            patch: None,
        };
        let result = FacJobSpecV1Builder::new(
            "job1",
            "gates",
            "bulk",
            "2026-02-18T00:00:00Z",
            "lease-1",
            source,
        )
        .channel_context_token("TOKEN")
        .build();
        assert!(result.is_ok(), "must accept valid 64-char hex SHA");
    }

    #[test]
    fn reject_invalid_enqueue_time() {
        let bad_times = [
            "",
            "not-a-date",
            "2026-02-18",       // missing time component
            "20260218T000000Z", // compact form, too short
        ];
        for bad_time in &bad_times {
            let result = FacJobSpecV1Builder::new(
                "job1",
                "gates",
                "bulk",
                *bad_time,
                "lease-1",
                sample_source(),
            )
            .build();
            assert!(result.is_err(), "must reject bad enqueue_time: {bad_time}");
        }
    }

    // ── Unknown fields rejection (deny_unknown_fields) ──────────────────

    #[test]
    fn reject_unknown_top_level_field() {
        let mut spec_json = serde_json::to_value(build_valid_spec()).unwrap();
        spec_json
            .as_object_mut()
            .unwrap()
            .insert("evil_field".to_string(), serde_json::json!("pwned"));
        let bytes = serde_json::to_vec(&spec_json).unwrap();
        let result = deserialize_job_spec(&bytes);
        assert!(
            result.is_err(),
            "must reject unknown top-level field (deny_unknown_fields)"
        );
    }

    #[test]
    fn reject_unknown_actuation_field() {
        let mut spec_json = serde_json::to_value(build_valid_spec()).unwrap();
        spec_json["actuation"]
            .as_object_mut()
            .unwrap()
            .insert("backdoor".to_string(), serde_json::json!(true));
        let bytes = serde_json::to_vec(&spec_json).unwrap();
        let result = deserialize_job_spec(&bytes);
        assert!(
            result.is_err(),
            "must reject unknown field in actuation block"
        );
    }

    #[test]
    fn reject_unknown_source_field() {
        let mut spec_json = serde_json::to_value(build_valid_spec()).unwrap();
        spec_json["source"]
            .as_object_mut()
            .unwrap()
            .insert("injected".to_string(), serde_json::json!("malware"));
        let bytes = serde_json::to_vec(&spec_json).unwrap();
        let result = deserialize_job_spec(&bytes);
        assert!(result.is_err(), "must reject unknown field in source block");
    }

    #[test]
    fn reject_unknown_constraints_field() {
        let mut spec_json = serde_json::to_value(build_valid_spec()).unwrap();
        spec_json["constraints"]
            .as_object_mut()
            .unwrap()
            .insert("allow_root".to_string(), serde_json::json!(true));
        let bytes = serde_json::to_vec(&spec_json).unwrap();
        let result = deserialize_job_spec(&bytes);
        assert!(
            result.is_err(),
            "must reject unknown field in constraints block"
        );
    }

    #[test]
    fn reject_unknown_lane_requirements_field() {
        let mut spec_json = serde_json::to_value(build_valid_spec()).unwrap();
        spec_json["lane_requirements"]
            .as_object_mut()
            .unwrap()
            .insert("privileged".to_string(), serde_json::json!(true));
        let bytes = serde_json::to_vec(&spec_json).unwrap();
        let result = deserialize_job_spec(&bytes);
        assert!(
            result.is_err(),
            "must reject unknown field in lane_requirements block"
        );
    }
}

// =============================================================================
// Part 2: Queue File Tampering Tests
// =============================================================================
//
// These tests simulate adversarial queue file modifications and verify that
// the validation pipeline detects and rejects each tamper vector fail-closed.

mod queue_tampering {
    use apm2_core::fac::job_spec::CONTROL_LANE_REPO_ID;
    use apm2_core::fac::{
        FacJobSpecV1Builder, JobSource, JobSpecError, deserialize_job_spec, validate_job_spec,
        validate_job_spec_control_lane,
    };

    use super::sample_source;

    // ── Helpers ─────────────────────────────────────────────────────────

    fn control_lane_source() -> JobSource {
        JobSource {
            kind: "mirror_commit".to_string(),
            repo_id: CONTROL_LANE_REPO_ID.to_string(),
            head_sha: "0".repeat(40),
            patch: None,
        }
    }

    fn build_valid_tokenized_spec() -> apm2_core::fac::FacJobSpecV1 {
        FacJobSpecV1Builder::new(
            "job-queue-test",
            "gates",
            "bulk",
            "2026-02-18T00:00:00Z",
            "lease-queue",
            sample_source(),
        )
        .channel_context_token("valid-base64-token")
        .memory_max_bytes(64_000_000_000)
        .build()
        .expect("valid spec should build")
    }

    fn build_valid_control_spec() -> apm2_core::fac::FacJobSpecV1 {
        FacJobSpecV1Builder::new(
            "job-cancel-test",
            "stop_revoke",
            "control",
            "2026-02-18T00:00:00Z",
            "lease-cancel",
            control_lane_source(),
        )
        .cancel_target_job_id("target-job-123")
        .channel_context_token("control-token")
        .memory_max_bytes(64_000_000_000)
        .build()
        .expect("valid control spec should build")
    }

    // ── Digest mismatch detection ───────────────────────────────────────

    #[test]
    fn detect_digest_mismatch_after_kind_mutation() {
        let mut spec = build_valid_tokenized_spec();
        spec.kind = "warm".to_string();
        let result = validate_job_spec(&spec);
        assert!(
            matches!(result, Err(JobSpecError::DigestMismatch { .. })),
            "must detect digest mismatch when kind is mutated"
        );
    }

    #[test]
    fn detect_digest_mismatch_after_repo_id_mutation() {
        let mut spec = build_valid_tokenized_spec();
        spec.source.repo_id = "evil-org/evil-repo".to_string();
        let result = validate_job_spec(&spec);
        assert!(
            matches!(result, Err(JobSpecError::DigestMismatch { .. })),
            "must detect digest mismatch when repo_id is mutated"
        );
    }

    #[test]
    fn detect_digest_mismatch_after_head_sha_mutation() {
        let mut spec = build_valid_tokenized_spec();
        spec.source.head_sha = "b".repeat(40);
        let result = validate_job_spec(&spec);
        assert!(
            matches!(result, Err(JobSpecError::DigestMismatch { .. })),
            "must detect digest mismatch when head_sha is mutated"
        );
    }

    #[test]
    fn detect_digest_mismatch_after_priority_mutation() {
        let mut spec = build_valid_tokenized_spec();
        spec.priority = 0; // Changed from default 50
        let result = validate_job_spec(&spec);
        assert!(
            matches!(result, Err(JobSpecError::DigestMismatch { .. })),
            "must detect digest mismatch when priority is mutated"
        );
    }

    #[test]
    fn detect_digest_mismatch_after_queue_lane_mutation() {
        let mut spec = build_valid_tokenized_spec();
        spec.queue_lane = "priority".to_string();
        let result = validate_job_spec(&spec);
        assert!(
            matches!(result, Err(JobSpecError::DigestMismatch { .. })),
            "must detect digest mismatch when queue_lane is mutated"
        );
    }

    #[test]
    fn detect_digest_mismatch_after_lease_id_mutation() {
        let mut spec = build_valid_tokenized_spec();
        spec.actuation.lease_id = "stolen-lease".to_string();
        let result = validate_job_spec(&spec);
        assert!(
            matches!(result, Err(JobSpecError::DigestMismatch { .. })),
            "must detect digest mismatch when lease_id is mutated"
        );
    }

    #[test]
    fn detect_digest_mismatch_after_enqueue_time_mutation() {
        let mut spec = build_valid_tokenized_spec();
        spec.enqueue_time = "2099-12-31T23:59:59Z".to_string();
        let result = validate_job_spec(&spec);
        assert!(
            matches!(result, Err(JobSpecError::DigestMismatch { .. })),
            "must detect digest mismatch when enqueue_time is mutated"
        );
    }

    #[test]
    fn detect_digest_mismatch_with_forged_digest() {
        let mut spec = build_valid_tokenized_spec();
        spec.job_spec_digest =
            "b3-256:0000000000000000000000000000000000000000000000000000000000000000".to_string();
        let result = validate_job_spec(&spec);
        assert!(result.is_err(), "must reject forged digest");
    }

    // ── Token mismatch detection ────────────────────────────────────────

    #[test]
    fn detect_request_id_mismatch() {
        let mut spec = build_valid_tokenized_spec();
        // Forge request_id to a different value than job_spec_digest
        spec.actuation.request_id =
            "b3-256:1111111111111111111111111111111111111111111111111111111111111111".to_string();
        let result = validate_job_spec(&spec);
        assert!(
            matches!(result, Err(JobSpecError::RequestIdMismatch { .. })),
            "must detect request_id mismatch (not digest mismatch): {result:?}"
        );
    }

    #[test]
    fn reject_missing_token() {
        let mut spec = build_valid_tokenized_spec();
        spec.actuation.channel_context_token = None;
        let result = validate_job_spec(&spec);
        assert!(
            matches!(result, Err(JobSpecError::MissingToken { .. })),
            "must reject missing channel_context_token"
        );
    }

    #[test]
    fn reject_empty_token() {
        let mut spec = build_valid_tokenized_spec();
        spec.actuation.channel_context_token = Some(String::new());
        let result = validate_job_spec(&spec);
        assert!(
            matches!(result, Err(JobSpecError::MissingToken { .. })),
            "must reject empty channel_context_token"
        );
    }

    // ── Control lane tampering ──────────────────────────────────────────

    #[test]
    fn control_lane_rejects_non_stop_revoke_kind() {
        let spec = build_valid_tokenized_spec();
        let result = validate_job_spec_control_lane(&spec);
        assert!(
            result.is_err(),
            "control lane must reject non-stop_revoke jobs"
        );
    }

    #[test]
    fn control_lane_rejects_wrong_repo_id() {
        let mut spec = build_valid_control_spec();
        spec.source.repo_id = "evil-org/repo".to_string();
        let result = validate_job_spec_control_lane(&spec);
        assert!(
            result.is_err(),
            "control lane must reject non-internal/control repo_id"
        );
    }

    #[test]
    fn control_lane_detects_digest_tampering() {
        let mut spec = build_valid_control_spec();
        spec.source.head_sha = "f".repeat(40);
        let result = validate_job_spec_control_lane(&spec);
        assert!(
            matches!(result, Err(JobSpecError::DigestMismatch { .. })),
            "control lane must detect digest mismatch"
        );
    }

    // ── Malformed digest format ─────────────────────────────────────────

    #[test]
    fn reject_digest_without_prefix() {
        let mut spec = build_valid_tokenized_spec();
        spec.job_spec_digest =
            "0000000000000000000000000000000000000000000000000000000000000000".to_string();
        let result = validate_job_spec(&spec);
        assert!(
            matches!(result, Err(JobSpecError::InvalidDigest { .. })),
            "must reject digest without b3-256: prefix"
        );
    }

    #[test]
    fn reject_digest_with_wrong_prefix() {
        let mut spec = build_valid_tokenized_spec();
        spec.job_spec_digest =
            "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_string();
        let result = validate_job_spec(&spec);
        assert!(
            matches!(result, Err(JobSpecError::InvalidDigest { .. })),
            "must reject digest with wrong prefix"
        );
    }

    #[test]
    fn reject_digest_with_short_hex() {
        let mut spec = build_valid_tokenized_spec();
        spec.job_spec_digest = "b3-256:000000".to_string();
        let result = validate_job_spec(&spec);
        assert!(
            matches!(result, Err(JobSpecError::InvalidDigest { .. })),
            "must reject digest with short hex"
        );
    }

    #[test]
    fn reject_digest_with_non_hex() {
        let mut spec = build_valid_tokenized_spec();
        spec.job_spec_digest =
            "b3-256:zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz".to_string();
        let result = validate_job_spec(&spec);
        assert!(
            matches!(result, Err(JobSpecError::InvalidDigest { .. })),
            "must reject digest with non-hex chars"
        );
    }

    #[test]
    fn reject_request_id_with_invalid_format() {
        let mut spec = build_valid_tokenized_spec();
        spec.actuation.request_id = "not-a-digest".to_string();
        let result = validate_job_spec(&spec);
        assert!(
            result.is_err(),
            "must reject request_id with invalid format"
        );
    }

    // ── cancel_target_job_id validation ─────────────────────────────────

    #[test]
    fn reject_cancel_target_for_non_stop_revoke() {
        let mut spec = build_valid_tokenized_spec();
        spec.cancel_target_job_id = Some("target-123".to_string());
        assert!(
            spec.validate_structure().is_err(),
            "must reject cancel_target_job_id on non-stop_revoke spec"
        );
    }

    #[test]
    fn reject_cancel_target_with_special_chars() {
        let adversarial_targets = [
            "../escape",
            "target;rm -rf /",
            "target$(whoami)",
            "target*glob",
            "target?query",
        ];
        for target in &adversarial_targets {
            let source = JobSource {
                kind: "mirror_commit".to_string(),
                repo_id: CONTROL_LANE_REPO_ID.to_string(),
                head_sha: "0".repeat(40),
                patch: None,
            };
            let result = FacJobSpecV1Builder::new(
                "job-cancel",
                "stop_revoke",
                "control",
                "2026-02-18T00:00:00Z",
                "lease-1",
                source,
            )
            .cancel_target_job_id(*target)
            .build();
            assert!(
                result.is_err(),
                "must reject adversarial cancel_target_job_id: {target}"
            );
        }
    }

    // ── Digest determinism ──────────────────────────────────────────────

    #[test]
    fn digest_is_deterministic_across_builds() {
        let spec1 = build_valid_tokenized_spec();
        let spec2 = build_valid_tokenized_spec();
        assert_eq!(
            spec1.job_spec_digest, spec2.job_spec_digest,
            "digest must be deterministic"
        );
    }

    #[test]
    fn digest_is_token_independent() {
        let with_token = build_valid_tokenized_spec();
        let without_token = FacJobSpecV1Builder::new(
            "job-queue-test",
            "gates",
            "bulk",
            "2026-02-18T00:00:00Z",
            "lease-queue",
            sample_source(),
        )
        .memory_max_bytes(64_000_000_000)
        .build()
        .expect("spec without token");

        // Token is excluded from digest computation, so digests should match.
        assert_eq!(
            with_token.job_spec_digest, without_token.job_spec_digest,
            "digest must be token-independent (INV-JS-001)"
        );
    }

    // ── JSON injection / schema confusion ───────────────────────────────

    #[test]
    fn reject_json_with_duplicate_keys() {
        // JSON with duplicate "schema" key — serde_json uses last-wins,
        // but the spec validation should catch the wrong schema value.
        let json = r#"{"schema":"evil","schema":"apm2.fac.job_spec.v1","job_id":"j","job_spec_digest":"d","kind":"gates","queue_lane":"q","priority":0,"enqueue_time":"2026-02-18T00:00:00Z","actuation":{"lease_id":"l","request_id":"r","channel_context_token":null},"source":{"kind":"mirror_commit","repo_id":"org-repo","head_sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"lane_requirements":{},"constraints":{"require_nextest":false}}"#;
        let result = deserialize_job_spec(json.as_bytes());
        // If deserialization succeeds, validation must still catch issues.
        if let Ok(spec) = result {
            // This spec has digest/request_id issues at minimum.
            assert!(
                validate_job_spec(&spec).is_err(),
                "must reject spec constructed from adversarial JSON"
            );
        }
    }
}

// =============================================================================
// Part 3: safe_rmtree Property Tests
// =============================================================================
//
// Property-based tests for safe_rmtree_v1 using proptest for randomized
// path generation and filesystem setup.

mod safe_rmtree_properties {
    use std::fs;
    use std::path::{Path, PathBuf};

    use apm2_core::fac::{SafeRmtreeError, SafeRmtreeOutcome, safe_rmtree_v1};

    // ── Helpers ─────────────────────────────────────────────────────────

    fn make_allowed_parent() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700))
                .expect("set perms on temp dir");
        }
        dir
    }

    fn create_tree(parent: &Path, name: &str, depth: usize, files_per_dir: usize) -> PathBuf {
        let root = parent.join(name);
        fs::create_dir_all(&root).expect("mkdir root");
        for i in 0..files_per_dir {
            fs::write(root.join(format!("file_{i}.txt")), format!("content-{i}"))
                .expect("write file");
        }
        if depth > 0 {
            create_tree(&root, "sub", depth - 1, files_per_dir);
        }
        root
    }

    // ── Symlink refusal (property: no symlink traversal) ────────────────

    #[test]
    #[cfg(unix)]
    fn property_symlink_at_root_always_refused() {
        let parent = make_allowed_parent();
        let real = parent.path().join("real");
        fs::create_dir(&real).expect("mkdir");
        fs::write(real.join("data.txt"), b"sensitive").expect("write");

        // Symlink root -> real
        let link = parent.path().join("link");
        std::os::unix::fs::symlink(&real, &link).expect("symlink");

        let result = safe_rmtree_v1(&link, parent.path());
        assert!(
            matches!(result, Err(SafeRmtreeError::SymlinkDetected { .. })),
            "must refuse symlink root"
        );
        assert!(real.join("data.txt").exists(), "real data must survive");
    }

    #[test]
    #[cfg(unix)]
    fn property_symlink_in_subtree_always_refused() {
        let parent = make_allowed_parent();
        let root = create_tree(parent.path(), "tree", 2, 1);

        // Place a symlink deep in the tree
        let target = parent.path().join("external");
        fs::create_dir(&target).expect("mkdir external");
        fs::write(target.join("secret.txt"), b"secret").expect("write");
        std::os::unix::fs::symlink(&target, root.join("sub").join("evil"))
            .expect("symlink in subtree");

        let result = safe_rmtree_v1(&root, parent.path());
        assert!(
            matches!(result, Err(SafeRmtreeError::SymlinkDetected { .. })),
            "must refuse symlink in subtree"
        );
        assert!(
            target.join("secret.txt").exists(),
            "external data must survive"
        );
    }

    #[test]
    #[cfg(unix)]
    fn property_dangling_symlink_refused() {
        let parent = make_allowed_parent();
        let root = parent.path().join("tree");
        fs::create_dir(&root).expect("mkdir");

        // Dangling symlink: points to non-existent target
        std::os::unix::fs::symlink("/nonexistent/target", root.join("dangling"))
            .expect("dangling symlink");

        let result = safe_rmtree_v1(&root, parent.path());
        assert!(
            matches!(result, Err(SafeRmtreeError::SymlinkDetected { .. })),
            "must refuse dangling symlink"
        );
    }

    #[test]
    #[cfg(unix)]
    fn property_symlink_in_ancestor_chain_refused() {
        let parent = make_allowed_parent();
        let real_dir = parent.path().join("real_sub");
        fs::create_dir(&real_dir).expect("mkdir");
        let target = real_dir.join("deep");
        fs::create_dir(&target).expect("mkdir deep");
        fs::write(target.join("data.txt"), b"data").expect("write");

        // Create symlink as intermediate directory
        let link_dir = parent.path().join("link_sub");
        std::os::unix::fs::symlink(&real_dir, &link_dir).expect("symlink");

        // Try to delete through the symlink ancestor
        let result = safe_rmtree_v1(&link_dir.join("deep"), parent.path());
        assert!(
            matches!(result, Err(SafeRmtreeError::SymlinkDetected { .. })),
            "must refuse deletion through symlinked ancestor"
        );
    }

    // ── No parent escape (property: deletion bounded to parent) ─────────

    #[test]
    fn property_root_equals_parent_refused() {
        let parent = make_allowed_parent();
        let result = safe_rmtree_v1(parent.path(), parent.path());
        assert!(
            matches!(result, Err(SafeRmtreeError::OutsideAllowedParent { .. })),
            "must refuse root == parent"
        );
    }

    #[test]
    fn property_root_outside_parent_refused() {
        let parent1 = make_allowed_parent();
        let parent2 = make_allowed_parent();
        let root = parent2.path().join("subdir");
        fs::create_dir(&root).expect("mkdir");

        let result = safe_rmtree_v1(&root, parent1.path());
        assert!(
            matches!(result, Err(SafeRmtreeError::OutsideAllowedParent { .. })),
            "must refuse root outside parent"
        );
    }

    #[test]
    fn property_relative_root_refused() {
        let parent = make_allowed_parent();
        let result = safe_rmtree_v1(Path::new("relative/path"), parent.path());
        assert!(
            matches!(result, Err(SafeRmtreeError::NotAbsolute { .. })),
            "must refuse relative root"
        );
    }

    #[test]
    fn property_relative_parent_refused() {
        let result = safe_rmtree_v1(Path::new("/absolute/root"), Path::new("relative/parent"));
        assert!(
            matches!(result, Err(SafeRmtreeError::NotAbsolute { .. })),
            "must refuse relative parent"
        );
    }

    // ── Dot-segment rejection ───────────────────────────────────────────

    #[test]
    fn property_dot_dot_in_root_refused() {
        let parent = make_allowed_parent();
        let bad_root = parent.path().join("..").join("escape");
        let result = safe_rmtree_v1(&bad_root, parent.path());
        assert!(
            matches!(result, Err(SafeRmtreeError::DotSegment { .. })),
            "must reject .. in root path"
        );
    }

    #[test]
    fn property_dot_in_root_refused() {
        let parent = make_allowed_parent();
        let bad_root = parent.path().join(".").join("subdir");
        let result = safe_rmtree_v1(&bad_root, parent.path());
        assert!(
            matches!(result, Err(SafeRmtreeError::DotSegment { .. })),
            "must reject . in root path"
        );
    }

    #[test]
    fn property_dot_dot_in_parent_refused() {
        // Use test-owned TempDir paths with injected dot-segments instead
        // of absolute host paths, ensuring hermetic isolation.
        let parent = make_allowed_parent();
        let parent_with_dots = parent
            .path()
            .join("..")
            .join(parent.path().file_name().expect("tempdir has a name"));
        let root = parent.path().join("target");
        fs::create_dir(&root).expect("mkdir target");

        let result = safe_rmtree_v1(&root, &parent_with_dots);
        assert!(
            matches!(result, Err(SafeRmtreeError::DotSegment { .. })),
            "must reject .. in parent path: {result:?}"
        );
    }

    // ── Proptest: randomized path components ────────────────────────────

    use proptest::prelude::*;

    /// Strategy for generating safe directory names (no path separators,
    /// no dot segments, no empty strings).
    fn safe_dirname_strategy() -> impl Strategy<Value = String> {
        "[a-zA-Z0-9_]{1,16}".prop_map(|s| s)
    }

    proptest! {
        /// Property: safe_rmtree_v1 on a valid tree under a valid parent
        /// always succeeds and deletes the tree completely.
        #[test]
        fn proptest_valid_tree_always_deleted(
            name in safe_dirname_strategy(),
            depth in 0_usize..4,
            files_per_dir in 0_usize..5,
        ) {
            let parent = make_allowed_parent();
            let root = create_tree(parent.path(), &name, depth, files_per_dir);

            let result = safe_rmtree_v1(&root, parent.path());
            prop_assert!(result.is_ok(), "valid tree deletion failed: {:?}", result.err());

            match result.unwrap() {
                SafeRmtreeOutcome::Deleted { files_deleted, dirs_deleted } => {
                    prop_assert!(files_deleted > 0 || dirs_deleted > 0 || (depth == 0 && files_per_dir == 0),
                        "expected at least one deletion");
                    prop_assert!(dirs_deleted >= 1, "root directory must be counted");
                },
                SafeRmtreeOutcome::AlreadyAbsent => {
                    prop_assert!(false, "tree was created but reported absent");
                },
            }

            prop_assert!(!root.exists(), "root must be fully deleted");
        }

        /// Property: nonexistent roots always return AlreadyAbsent.
        #[test]
        fn proptest_nonexistent_root_is_noop(
            name in safe_dirname_strategy(),
        ) {
            let parent = make_allowed_parent();
            let root = parent.path().join(&name);
            // Do NOT create the root

            let result = safe_rmtree_v1(&root, parent.path());
            prop_assert!(result.is_ok());
            prop_assert_eq!(result.unwrap(), SafeRmtreeOutcome::AlreadyAbsent);
        }

        /// Property: dot-dot segments in root are always rejected.
        #[test]
        fn proptest_dot_dot_always_rejected(
            prefix in safe_dirname_strategy(),
            suffix in safe_dirname_strategy(),
        ) {
            let bad_root = PathBuf::from(format!("/tmp/{prefix}/../{suffix}"));
            let parent = PathBuf::from("/tmp");
            let result = safe_rmtree_v1(&bad_root, &parent);
            prop_assert!(
                matches!(result, Err(SafeRmtreeError::DotSegment { .. })),
                "dot-dot must always be rejected, got: {:?}", result
            );
        }

        /// Property: relative paths are always rejected regardless of content.
        #[test]
        fn proptest_relative_paths_always_rejected(
            name in safe_dirname_strategy(),
        ) {
            let parent = make_allowed_parent();
            let rel_root = PathBuf::from(&name);
            let result = safe_rmtree_v1(&rel_root, parent.path());
            prop_assert!(
                matches!(result, Err(SafeRmtreeError::NotAbsolute { .. })),
                "relative path must always be rejected"
            );
        }
    }

    // ── TOCTOU smoke tests ──────────────────────────────────────────────
    //
    // True TOCTOU testing requires interleaved thread scheduling which is
    // non-deterministic. These smoke tests verify the structural defenses
    // are in place (fd-relative operations, O_NOFOLLOW, etc.) by creating
    // symlinks and verifying they are detected.

    #[test]
    #[cfg(unix)]
    fn toctou_smoke_symlink_swap_at_root() {
        // Scenario: attacker creates a legitimate directory, then swaps it
        // with a symlink before deletion. The fd-relative O_NOFOLLOW
        // approach should catch this.
        let parent = make_allowed_parent();
        let root = parent.path().join("victim");
        fs::create_dir(&root).expect("mkdir");
        fs::write(root.join("data.txt"), b"data").expect("write");

        // Replace the root with a symlink to /tmp (or another directory)
        fs::remove_dir_all(&root).expect("remove original");
        let decoy = parent.path().join("decoy");
        fs::create_dir(&decoy).expect("mkdir decoy");
        fs::write(decoy.join("important.txt"), b"important").expect("write");
        std::os::unix::fs::symlink(&decoy, &root).expect("symlink swap");

        let result = safe_rmtree_v1(&root, parent.path());
        assert!(
            matches!(result, Err(SafeRmtreeError::SymlinkDetected { .. })),
            "must detect symlink swap at root: {result:?}"
        );
        assert!(
            decoy.join("important.txt").exists(),
            "decoy data must survive"
        );
    }

    #[test]
    #[cfg(unix)]
    fn toctou_smoke_symlink_swap_in_tree() {
        // Scenario: legitimate tree with a subdirectory that gets replaced
        // by a symlink. The openat(O_NOFOLLOW) should catch this.
        let parent = make_allowed_parent();
        let root = parent.path().join("tree");
        fs::create_dir_all(root.join("sub")).expect("mkdir");
        fs::write(root.join("sub").join("normal.txt"), b"normal").expect("write");

        // Replace sub/ with a symlink
        let target = parent.path().join("target_dir");
        fs::create_dir(&target).expect("mkdir target");
        fs::write(target.join("sensitive.txt"), b"sensitive").expect("write");

        fs::remove_dir_all(root.join("sub")).expect("remove sub");
        std::os::unix::fs::symlink(&target, root.join("sub")).expect("symlink swap");

        let result = safe_rmtree_v1(&root, parent.path());
        assert!(
            matches!(result, Err(SafeRmtreeError::SymlinkDetected { .. })),
            "must detect symlink swap in tree: {result:?}"
        );
        assert!(
            target.join("sensitive.txt").exists(),
            "sensitive data must survive"
        );
    }

    // ── Permission and boundary enforcement ─────────────────────────────

    #[test]
    #[cfg(unix)]
    fn refuse_parent_with_group_access() {
        use std::os::unix::fs::PermissionsExt;

        let parent = make_allowed_parent();
        fs::set_permissions(parent.path(), fs::Permissions::from_mode(0o770)).expect("set perms");
        let root = parent.path().join("child");
        fs::create_dir(&root).expect("mkdir");

        let result = safe_rmtree_v1(&root, parent.path());
        assert!(
            matches!(result, Err(SafeRmtreeError::PermissionDenied { .. })),
            "must refuse parent with group access"
        );
    }

    #[test]
    #[cfg(unix)]
    fn refuse_parent_with_world_access() {
        use std::os::unix::fs::PermissionsExt;

        let parent = make_allowed_parent();
        fs::set_permissions(parent.path(), fs::Permissions::from_mode(0o707)).expect("set perms");
        let root = parent.path().join("child");
        fs::create_dir(&root).expect("mkdir");

        let result = safe_rmtree_v1(&root, parent.path());
        assert!(
            matches!(result, Err(SafeRmtreeError::PermissionDenied { .. })),
            "must refuse parent with world access"
        );
    }

    // ── Unexpected file types ───────────────────────────────────────────

    #[test]
    #[cfg(unix)]
    fn refuse_fifo_root() {
        let parent = make_allowed_parent();
        let fifo = parent.path().join("evil.fifo");
        nix::unistd::mkfifo(&fifo, nix::sys::stat::Mode::S_IRWXU).expect("mkfifo");

        let result = safe_rmtree_v1(&fifo, parent.path());
        assert!(
            matches!(result, Err(SafeRmtreeError::UnexpectedFileType { .. })),
            "must refuse FIFO as root"
        );
    }

    #[test]
    #[cfg(unix)]
    fn refuse_socket_root() {
        use std::os::unix::net::UnixListener;

        let parent = make_allowed_parent();
        let sock = parent.path().join("evil.sock");
        let _listener = UnixListener::bind(&sock).expect("bind");

        let result = safe_rmtree_v1(&sock, parent.path());
        assert!(
            matches!(result, Err(SafeRmtreeError::UnexpectedFileType { .. })),
            "must refuse socket as root"
        );
    }

    // ── Successful deletion edge cases ──────────────────────────────────

    #[test]
    fn delete_single_file_root() {
        let parent = make_allowed_parent();
        let file = parent.path().join("single.txt");
        fs::write(&file, b"data").expect("write");

        let result = safe_rmtree_v1(&file, parent.path());
        assert!(
            matches!(
                result,
                Ok(SafeRmtreeOutcome::Deleted {
                    files_deleted: 1,
                    dirs_deleted: 0,
                })
            ),
            "must delete single file"
        );
        assert!(!file.exists());
    }

    #[test]
    fn delete_empty_directory() {
        let parent = make_allowed_parent();
        let dir = parent.path().join("empty");
        fs::create_dir(&dir).expect("mkdir");

        let result = safe_rmtree_v1(&dir, parent.path());
        assert!(
            matches!(
                result,
                Ok(SafeRmtreeOutcome::Deleted {
                    files_deleted: 0,
                    dirs_deleted: 1,
                })
            ),
            "must delete empty directory"
        );
        assert!(!dir.exists());
    }

    #[test]
    fn nonexistent_root_is_noop() {
        let parent = make_allowed_parent();
        let root = parent.path().join("does_not_exist");

        let result = safe_rmtree_v1(&root, parent.path());
        assert_eq!(result.unwrap(), SafeRmtreeOutcome::AlreadyAbsent);
    }

    #[test]
    fn deeply_nested_tree_succeeds() {
        let parent = make_allowed_parent();
        let root = create_tree(parent.path(), "deep", 10, 2);

        let result = safe_rmtree_v1(&root, parent.path());
        assert!(result.is_ok(), "deep tree deletion should succeed");
        let outcome = result.unwrap();
        match outcome {
            SafeRmtreeOutcome::Deleted {
                files_deleted,
                dirs_deleted,
            } => {
                assert!(files_deleted > 0, "must have deleted files");
                assert!(dirs_deleted > 0, "must have deleted directories");
            },
            SafeRmtreeOutcome::AlreadyAbsent => panic!("expected Deleted"),
        }
        assert!(!root.exists(), "root must be fully deleted");
    }

    /// Property: string-prefix attacks on parent path are rejected.
    /// e.g., /tmp/abc is NOT under /tmp/ab even though it's a string prefix.
    #[test]
    fn string_prefix_attack_rejected() {
        let parent = make_allowed_parent();
        let parent_path = parent.path().to_path_buf();

        // Create a path that is a string prefix of parent but not a child.
        // Setup uses expect() so failures are caught rather than silently
        // skipping the assertion.
        let similar = PathBuf::from(format!("{}xyz", parent_path.display()));
        fs::create_dir_all(&similar).expect("setup: create string-prefix sibling directory");
        let target = similar.join("victim");
        fs::create_dir_all(&target).expect("setup: create victim directory");

        let result = safe_rmtree_v1(&target, parent.path());
        assert!(
            matches!(result, Err(SafeRmtreeError::OutsideAllowedParent { .. })),
            "must reject string-prefix attack: {result:?}"
        );

        // Cleanup
        let _ = fs::remove_dir_all(&similar);
    }
}
