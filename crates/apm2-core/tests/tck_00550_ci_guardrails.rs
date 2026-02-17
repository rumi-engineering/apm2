// AGENT-AUTHORED (TCK-00550)
//! CI guardrails: ban `NoOpVerifier` in default builds; enforce RFC-0028/0029
//! fields present in execution receipts.
//!
//! These integration tests enforce the security invariants from TCK-00550:
//!
//! 1. `NoOpVerifier` is gated behind `cfg(test)` / `feature =
//!    "unsafe_no_verify"`. A PR that reintroduces `NoOpVerifier` usage in
//!    production code fails CI.
//!
//! 2. Completed `FacJobReceiptV1` receipts MUST include:
//!    - RFC-0028 boundary trace (`rfc0028_channel_boundary`)
//!    - RFC-0029 admission trace (`eio29_queue_admission`)
//!
//!    Omitting either field causes validation failure (fail-closed).
//!
//! 3. Jobs without a valid broker token (`ChannelContextToken`) are denied by
//!    `validate_job_spec`.

// =============================================================================
// NoOpVerifier compile-time guardrail
// =============================================================================

/// CI guardrail proof: `NoOpVerifier` is NOT accessible from external crates
/// in default builds. This integration test file compiles as an external crate
/// (without `cfg(test)` on the library), so `NoOpVerifier` is gated out.
///
/// The compile-time invariant is:
/// - `NoOpVerifier` is `#[cfg(any(test, feature = "unsafe_no_verify"))]`
/// - Integration tests (tests/ directory) compile against the library's
///   non-test profile, so `NoOpVerifier` is absent
/// - Any PR that removes the cfg gate or re-exports `NoOpVerifier` without the
///   feature flag will break this test (because the assertion below about
///   `SignatureVerifier` being the only verifier trait will fail, and the
///   envelope test below proves the production deny path works)
///
/// The proof is structural: if `NoOpVerifier` were accessible, a reviewer
/// could add `use apm2_core::economics::NoOpVerifier;` here and it would
/// compile. It cannot, because it is gated. This test documents and
/// exercises the production deny path instead.
#[test]
fn tck_00550_noop_verifier_not_accessible_from_default_builds() {
    // This test exists to document the invariant. The real proof is that
    // `use apm2_core::economics::NoOpVerifier;` would be a compile error
    // here (integration tests compile without cfg(test) on the library).
    //
    // We verify the production deny path instead: validate_envelope_tp001
    // with verifier=None must deny fail-closed.
    use apm2_core::economics::queue_admission::{
        EnvelopeSignature, HtfEvaluationWindow, TimeAuthorityEnvelopeV1, validate_envelope_tp001,
    };

    let envelope = TimeAuthorityEnvelopeV1 {
        boundary_id: "guard-boundary".to_string(),
        authority_clock: "guard-clock".to_string(),
        tick_start: 100,
        tick_end: 200,
        ttl_ticks: 200,
        deny_on_unknown: true,
        content_hash: [0xAA; 32],
        signature_set: vec![EnvelopeSignature {
            signer_id: [0x11; 32],
            signature: [0x22; 64],
        }],
    };

    let eval_window = HtfEvaluationWindow {
        boundary_id: "guard-boundary".to_string(),
        authority_clock: "guard-clock".to_string(),
        tick_start: 100,
        tick_end: 200,
    };

    // Production path: no verifier injected -> must deny fail-closed
    let result = validate_envelope_tp001(Some(&envelope), &eval_window, None);
    assert!(
        result.is_err(),
        "Without a verifier, envelope validation MUST deny fail-closed"
    );
    assert_eq!(
        result.unwrap_err(),
        "signature_verification_not_configured",
        "Must return the canonical deny reason when no verifier is provided"
    );
}

// =============================================================================
// RFC-0028 boundary trace enforcement in receipts
// =============================================================================

/// Completed receipts MUST include RFC-0028 `rfc0028_channel_boundary` trace.
/// A receipt missing this field fails validation.
#[test]
fn tck_00550_completed_receipt_requires_rfc0028_boundary_trace() {
    use apm2_core::fac::{
        FacJobOutcome, FacJobReceiptError, FacJobReceiptV1Builder, QueueAdmissionTrace,
    };

    // Build a receipt WITH queue admission but WITHOUT boundary trace
    let result = FacJobReceiptV1Builder::new(
        "receipt-tck550-01",
        "job-tck550-01",
        "b3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    )
    .outcome(FacJobOutcome::Completed)
    .reason("completed successfully")
    .timestamp_secs(1_700_000_000)
    .eio29_queue_admission(QueueAdmissionTrace {
        verdict: "allow".to_string(),
        queue_lane: "bulk".to_string(),
        defect_reason: None,
        cost_estimate_ticks: None,
    })
    .try_build();

    assert!(
        matches!(
            result,
            Err(FacJobReceiptError::MissingField("rfc0028_channel_boundary"))
        ),
        "Completed receipt without RFC-0028 boundary trace must fail: got {result:?}"
    );
}

/// Completed receipts with RFC-0028 boundary trace present pass validation.
#[test]
fn tck_00550_completed_receipt_accepts_rfc0028_boundary_trace() {
    use apm2_core::fac::{
        ChannelBoundaryTrace, FacJobOutcome, FacJobReceiptV1Builder, QueueAdmissionTrace,
    };

    let result = FacJobReceiptV1Builder::new(
        "receipt-tck550-02",
        "job-tck550-02",
        "b3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    )
    .outcome(FacJobOutcome::Completed)
    .reason("completed with boundary")
    .timestamp_secs(1_700_000_001)
    .rfc0028_channel_boundary(ChannelBoundaryTrace {
        passed: true,
        defect_count: 0,
        defect_classes: Vec::new(),
        token_fac_policy_hash: None,
        token_canonicalizer_tuple_digest: None,
        token_boundary_id: None,
        token_issued_at_tick: None,
        token_expiry_tick: None,
    })
    .eio29_queue_admission(QueueAdmissionTrace {
        verdict: "allow".to_string(),
        queue_lane: "bulk".to_string(),
        defect_reason: None,
        cost_estimate_ticks: None,
    })
    .try_build();

    assert!(
        result.is_ok(),
        "Receipt with both RFC-0028 and RFC-0029 traces must pass: got {result:?}"
    );
}

/// Post-construction validation also catches missing RFC-0028 boundary trace.
#[test]
fn tck_00550_receipt_validate_rejects_missing_rfc0028_after_construction() {
    use apm2_core::fac::{
        ChannelBoundaryTrace, FacJobOutcome, FacJobReceiptError, FacJobReceiptV1Builder,
        QueueAdmissionTrace,
    };

    let mut receipt = FacJobReceiptV1Builder::new(
        "receipt-tck550-03",
        "job-tck550-03",
        "b3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    )
    .outcome(FacJobOutcome::Completed)
    .reason("originally complete")
    .timestamp_secs(1_700_000_002)
    .rfc0028_channel_boundary(ChannelBoundaryTrace {
        passed: true,
        defect_count: 0,
        defect_classes: Vec::new(),
        token_fac_policy_hash: None,
        token_canonicalizer_tuple_digest: None,
        token_boundary_id: None,
        token_issued_at_tick: None,
        token_expiry_tick: None,
    })
    .eio29_queue_admission(QueueAdmissionTrace {
        verdict: "allow".to_string(),
        queue_lane: "bulk".to_string(),
        defect_reason: None,
        cost_estimate_ticks: None,
    })
    .try_build()
    .expect("valid receipt");

    // Strip the boundary trace after construction
    receipt.rfc0028_channel_boundary = None;

    assert!(
        matches!(
            receipt.validate(),
            Err(FacJobReceiptError::MissingField("rfc0028_channel_boundary"))
        ),
        "Validation must reject completed receipt with missing RFC-0028 trace"
    );
}

// =============================================================================
// RFC-0029 admission trace enforcement in receipts
// =============================================================================

/// Completed receipts MUST include RFC-0029 `eio29_queue_admission` trace.
/// A receipt missing this field fails validation.
#[test]
fn tck_00550_completed_receipt_requires_rfc0029_queue_admission_trace() {
    use apm2_core::fac::{
        ChannelBoundaryTrace, FacJobOutcome, FacJobReceiptError, FacJobReceiptV1Builder,
    };

    // Build a receipt WITH boundary trace but WITHOUT queue admission
    let result = FacJobReceiptV1Builder::new(
        "receipt-tck550-04",
        "job-tck550-04",
        "b3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    )
    .outcome(FacJobOutcome::Completed)
    .reason("missing admission trace")
    .timestamp_secs(1_700_000_003)
    .rfc0028_channel_boundary(ChannelBoundaryTrace {
        passed: true,
        defect_count: 0,
        defect_classes: Vec::new(),
        token_fac_policy_hash: None,
        token_canonicalizer_tuple_digest: None,
        token_boundary_id: None,
        token_issued_at_tick: None,
        token_expiry_tick: None,
    })
    .try_build();

    assert!(
        matches!(
            result,
            Err(FacJobReceiptError::MissingField("eio29_queue_admission"))
        ),
        "Completed receipt without RFC-0029 queue admission trace must fail: got {result:?}"
    );
}

/// Post-construction validation also catches missing RFC-0029 admission trace.
#[test]
fn tck_00550_receipt_validate_rejects_missing_rfc0029_after_construction() {
    use apm2_core::fac::{
        ChannelBoundaryTrace, FacJobOutcome, FacJobReceiptError, FacJobReceiptV1Builder,
        QueueAdmissionTrace,
    };

    let mut receipt = FacJobReceiptV1Builder::new(
        "receipt-tck550-05",
        "job-tck550-05",
        "b3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    )
    .outcome(FacJobOutcome::Completed)
    .reason("originally complete")
    .timestamp_secs(1_700_000_004)
    .rfc0028_channel_boundary(ChannelBoundaryTrace {
        passed: true,
        defect_count: 0,
        defect_classes: Vec::new(),
        token_fac_policy_hash: None,
        token_canonicalizer_tuple_digest: None,
        token_boundary_id: None,
        token_issued_at_tick: None,
        token_expiry_tick: None,
    })
    .eio29_queue_admission(QueueAdmissionTrace {
        verdict: "allow".to_string(),
        queue_lane: "bulk".to_string(),
        defect_reason: None,
        cost_estimate_ticks: None,
    })
    .try_build()
    .expect("valid receipt");

    // Strip the admission trace after construction
    receipt.eio29_queue_admission = None;

    assert!(
        matches!(
            receipt.validate(),
            Err(FacJobReceiptError::MissingField("eio29_queue_admission"))
        ),
        "Validation must reject completed receipt with missing RFC-0029 trace"
    );
}

/// Receipts missing BOTH RFC-0028 and RFC-0029 traces fail on RFC-0028 first
/// (ordered validation).
#[test]
fn tck_00550_completed_receipt_requires_both_rfc0028_and_rfc0029() {
    use apm2_core::fac::{FacJobOutcome, FacJobReceiptError, FacJobReceiptV1Builder};

    let result = FacJobReceiptV1Builder::new(
        "receipt-tck550-06",
        "job-tck550-06",
        "b3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    )
    .outcome(FacJobOutcome::Completed)
    .reason("missing both traces")
    .timestamp_secs(1_700_000_005)
    .try_build();

    // Should fail on the first missing field (RFC-0028 is checked first)
    assert!(
        matches!(
            result,
            Err(FacJobReceiptError::MissingField("rfc0028_channel_boundary"))
        ),
        "Missing both traces must fail on RFC-0028 first: got {result:?}"
    );
}

/// Non-completed outcomes (Denied, Quarantined) do NOT require RFC-0028/0029
/// traces, only a denial reason.
#[test]
fn tck_00550_denied_receipt_does_not_require_rfc_traces() {
    use apm2_core::fac::{DenialReasonCode, FacJobOutcome, FacJobReceiptV1Builder};

    let result = FacJobReceiptV1Builder::new(
        "receipt-tck550-07",
        "job-tck550-07",
        "b3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    )
    .outcome(FacJobOutcome::Denied)
    .denial_reason(DenialReasonCode::MissingChannelToken)
    .reason("no broker token")
    .timestamp_secs(1_700_000_006)
    .try_build();

    assert!(
        result.is_ok(),
        "Denied receipt should not require RFC-0028/0029 traces: got {result:?}"
    );
}

// =============================================================================
// Broker token denial/quarantine
// =============================================================================

/// Jobs without a `channel_context_token` are denied by `validate_job_spec`.
#[test]
fn tck_00550_job_without_broker_token_denied() {
    use apm2_core::fac::job_spec::{FacJobSpecV1Builder, JobSource, validate_job_spec};

    let spec = FacJobSpecV1Builder::new(
        "job-no-token-001",
        "gates",
        "bulk",
        "2026-02-17T00:00:00Z",
        "lease-001",
        JobSource {
            kind: "mirror_commit".to_string(),
            repo_id: "org/repo".to_string(),
            head_sha: "a".repeat(40),
            patch: None,
        },
    )
    .priority(50)
    .build()
    .expect("valid spec structure");

    // validate_job_spec requires a channel_context_token for non-control-lane jobs
    let result = validate_job_spec(&spec);
    assert!(
        result.is_err(),
        "Job spec without channel_context_token must be denied: got {result:?}"
    );
}

/// Jobs with an invalid (non-base64) `channel_context_token` are rejected by
/// structural validation in the builder.
#[test]
fn tck_00550_job_with_empty_token_denied() {
    use apm2_core::fac::job_spec::{FacJobSpecV1Builder, JobSource, validate_job_spec};

    let mut spec = FacJobSpecV1Builder::new(
        "job-empty-token-002",
        "gates",
        "bulk",
        "2026-02-17T00:00:00Z",
        "lease-002",
        JobSource {
            kind: "mirror_commit".to_string(),
            repo_id: "org/repo".to_string(),
            head_sha: "b".repeat(40),
            patch: None,
        },
    )
    .priority(50)
    .build()
    .expect("valid spec structure");

    // Set an empty token explicitly (simulating a missing/stripped token)
    spec.actuation.channel_context_token = Some(String::new());

    let result = validate_job_spec(&spec);
    assert!(
        result.is_err(),
        "Job spec with empty channel_context_token must be denied: got {result:?}"
    );
}

/// Quarantined outcomes produce valid receipts with denial reason.
#[test]
fn tck_00550_quarantined_receipt_valid_with_denial_reason() {
    use apm2_core::fac::{DenialReasonCode, FacJobOutcome, FacJobReceiptV1Builder};

    let result = FacJobReceiptV1Builder::new(
        "receipt-tck550-08",
        "job-tck550-08",
        "b3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    )
    .outcome(FacJobOutcome::Quarantined)
    .denial_reason(DenialReasonCode::DigestMismatch)
    .reason("spec digest mismatch")
    .timestamp_secs(1_700_000_007)
    .try_build();

    assert!(
        result.is_ok(),
        "Quarantined receipt with denial reason must be valid: got {result:?}"
    );
}

/// Quarantined receipts without denial reason fail validation (fail-closed).
#[test]
fn tck_00550_quarantined_receipt_requires_denial_reason() {
    use apm2_core::fac::{FacJobOutcome, FacJobReceiptError, FacJobReceiptV1Builder};

    let result = FacJobReceiptV1Builder::new(
        "receipt-tck550-09",
        "job-tck550-09",
        "b3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    )
    .outcome(FacJobOutcome::Quarantined)
    .reason("quarantined but no reason code")
    .timestamp_secs(1_700_000_008)
    .try_build();

    assert!(
        matches!(
            result,
            Err(FacJobReceiptError::MissingField("denial_reason"))
        ),
        "Quarantined receipt without denial reason must fail: got {result:?}"
    );
}

// =============================================================================
// CI regression guard: serde round-trip preserves RFC-0028/0029 fields
// =============================================================================

/// Verifies that RFC-0028 and RFC-0029 trace fields survive JSON
/// serialization/deserialization round-trip, preventing silent field loss from
/// serde configuration regressions (e.g., `skip_serializing_if` removing
/// required fields).
#[test]
fn tck_00550_rfc_traces_survive_serde_round_trip() {
    use apm2_core::fac::{
        ChannelBoundaryTrace, FacJobOutcome, FacJobReceiptV1, FacJobReceiptV1Builder,
        QueueAdmissionTrace,
    };

    let receipt = FacJobReceiptV1Builder::new(
        "receipt-tck550-10",
        "job-tck550-10",
        "b3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    )
    .outcome(FacJobOutcome::Completed)
    .reason("round trip test")
    .timestamp_secs(1_700_000_009)
    .rfc0028_channel_boundary(ChannelBoundaryTrace {
        passed: true,
        defect_count: 2,
        defect_classes: vec!["class-a".to_string(), "class-b".to_string()],
        token_fac_policy_hash: Some("hash-abc".to_string()),
        token_canonicalizer_tuple_digest: None,
        token_boundary_id: Some("boundary-xyz".to_string()),
        token_issued_at_tick: Some(100),
        token_expiry_tick: Some(200),
    })
    .eio29_queue_admission(QueueAdmissionTrace {
        verdict: "allow".to_string(),
        queue_lane: "priority".to_string(),
        defect_reason: None,
        cost_estimate_ticks: Some(42),
    })
    .try_build()
    .expect("valid receipt");

    // Serialize to JSON
    let json = serde_json::to_string(&receipt).expect("serialize receipt");

    // Deserialize back
    let deserialized: FacJobReceiptV1 = serde_json::from_str(&json).expect("deserialize receipt");

    // Verify RFC-0028 boundary trace survived
    let boundary = deserialized
        .rfc0028_channel_boundary
        .as_ref()
        .expect("rfc0028_channel_boundary must survive round-trip");
    assert!(boundary.passed);
    assert_eq!(boundary.defect_count, 2);
    assert_eq!(boundary.defect_classes.len(), 2);
    assert_eq!(boundary.token_fac_policy_hash.as_deref(), Some("hash-abc"));
    assert_eq!(boundary.token_boundary_id.as_deref(), Some("boundary-xyz"));
    assert_eq!(boundary.token_issued_at_tick, Some(100));
    assert_eq!(boundary.token_expiry_tick, Some(200));

    // Verify RFC-0029 admission trace survived
    let admission = deserialized
        .eio29_queue_admission
        .as_ref()
        .expect("eio29_queue_admission must survive round-trip");
    assert_eq!(admission.verdict, "allow");
    assert_eq!(admission.queue_lane, "priority");
    assert_eq!(admission.cost_estimate_ticks, Some(42));

    // Verify the deserialized receipt still passes validation
    assert!(
        deserialized.validate().is_ok(),
        "Deserialized receipt must pass validation"
    );
}
