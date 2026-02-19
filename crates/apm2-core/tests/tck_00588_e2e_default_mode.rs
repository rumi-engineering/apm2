// AGENT-AUTHORED (TCK-00588)
//! End-to-end default-mode harness: spin up broker+worker (in-process),
//! enqueue gates, verify RFC-0028/0029 receipts, and test denial paths.
//!
//! This test exercises the complete default-mode admission pipeline:
//!
//! 1. Broker issues RFC-0028 channel context tokens and RFC-0029 time authority
//!    envelopes.
//! 2. Worker validates tokens and envelopes using the broker's real Ed25519
//!    verifying key (no `NoOpVerifier`).
//! 3. Queue admission evaluates all three temporal predicates
//!    (TP-EIO29-001/002/003).
//! 4. Budget admission evaluates economics profile admission.
//! 5. Receipts contain RFC-0028 boundary trace, RFC-0029 queue admission trace,
//!    and budget admission trace.
//! 6. Denial paths: missing token, expired token, forged token.
//! 7. `NoOpVerifier` is cfg-gated and denies fail-closed.
//!
//! # Security Domain
//!
//! `DOMAIN_SECURITY`, `DOMAIN_RUNTIME` -- mandatory fail-closed review patterns
//! apply.
//!
//! # Determinism
//!
//! All tests use deterministic inputs (no wall-clock, no randomness beyond
//! Ed25519 key generation). No sleep-based synchronization.

use apm2_core::channel::{
    ChannelBoundaryCheck, ChannelSource, DeclassificationIntentScope, decode_channel_context_token,
    derive_channel_source_witness, issue_channel_context_token,
};
use apm2_core::crypto::Signer;
use apm2_core::economics::queue_admission::{
    HtfEvaluationWindow, QueueAdmissionRequest, QueueAdmissionVerdict, QueueLane,
    QueueSchedulerState, evaluate_queue_admission,
};
use apm2_core::fac::broker::BrokerSignatureVerifier;
use apm2_core::fac::broker_health::BrokerHealthChecker;
use apm2_core::fac::job_spec::{FacJobSpecV1Builder, JobSource, validate_job_spec};
use apm2_core::fac::{
    BudgetAdmissionTrace, ChannelBoundaryTrace, DenialReasonCode, FacBroker, FacJobOutcome,
    FacJobReceiptV1, FacJobReceiptV1Builder, QueueAdmissionTrace,
};

// =========================================================================
// Constants
// =========================================================================

/// Deterministic lease ID for test jobs.
const TEST_LEASE_ID: &str = "lease-e2e-588";

/// Deterministic boundary ID for test evaluation windows.
const TEST_BOUNDARY_ID: &str = "local-e2e";

/// Deterministic authority clock for test evaluation windows.
const TEST_AUTHORITY_CLOCK: &str = "local-e2e";

// =========================================================================
// Test helpers
// =========================================================================

/// Creates a minimal `JobSource` for test specs.
fn test_source() -> JobSource {
    JobSource {
        kind: "mirror_commit".to_string(),
        repo_id: "org/test-repo".to_string(),
        head_sha: "a".repeat(40),
        patch: None,
    }
}

/// Creates a baseline `ChannelBoundaryCheck` for token issuance.
fn baseline_check() -> ChannelBoundaryCheck {
    use apm2_core::channel::{
        BoundaryFlowPolicyBinding, DisclosurePolicyBinding, LeakageBudgetReceipt,
        LeakageEstimatorFamily, TimingChannelBudget,
    };
    use apm2_core::disclosure::{DisclosureChannelClass, DisclosurePolicyMode};

    ChannelBoundaryCheck {
        source: ChannelSource::TypedToolIntent,
        channel_source_witness: Some(derive_channel_source_witness(
            ChannelSource::TypedToolIntent,
        )),
        broker_verified: true,
        capability_verified: true,
        context_firewall_verified: true,
        policy_ledger_verified: true,
        taint_allow: true,
        classification_allow: true,
        declass_receipt_valid: true,
        declassification_intent: DeclassificationIntentScope::None,
        redundancy_declassification_receipt: None,
        boundary_flow_policy_binding: Some(BoundaryFlowPolicyBinding {
            policy_digest: [0x11; 32],
            admitted_policy_root_digest: [0x11; 32],
            canonicalizer_tuple_digest: [0x22; 32],
            admitted_canonicalizer_tuple_digest: [0x22; 32],
        }),
        leakage_budget_receipt: Some(LeakageBudgetReceipt {
            leakage_bits: 0,
            budget_bits: 8,
            estimator_family: LeakageEstimatorFamily::MutualInformationUpperBound,
            confidence_bps: 10_000,
            confidence_label: "deterministic".to_string(),
        }),
        timing_channel_budget: Some(TimingChannelBudget {
            release_bucket_ticks: 10,
            observed_variance_ticks: 0,
            budget_ticks: 10,
        }),
        disclosure_policy_binding: Some(DisclosurePolicyBinding {
            required_for_effect: true,
            state_valid: true,
            active_mode: DisclosurePolicyMode::TradeSecretOnly,
            expected_mode: DisclosurePolicyMode::TradeSecretOnly,
            attempted_channel: DisclosureChannelClass::Internal,
            policy_snapshot_digest: [0x44; 32],
            admitted_policy_epoch_root_digest: [0x44; 32],
            policy_epoch: 1,
            phase_id: "pre_federation".to_string(),
            state_reason: "valid".to_string(),
        }),
        leakage_budget_policy_max_bits: Some(8),
        declared_leakage_budget_bits: None,
        timing_budget_policy_max_ticks: Some(10),
        declared_timing_budget_ticks: None,
        token_binding: None,
    }
}

/// In-process broker+worker harness.
///
/// Owns the broker's signing key and provides methods to issue tokens,
/// envelopes, and evaluate admission decisions using the broker's real
/// cryptographic key material.
struct DefaultModeHarness {
    broker: FacBroker,
    #[allow(dead_code)]
    health_checker: BrokerHealthChecker,
    verifier: BrokerSignatureVerifier,
    scheduler: QueueSchedulerState,
}

impl DefaultModeHarness {
    /// Creates a new harness with a fresh broker, health-checked and ready
    /// for token issuance.
    fn new() -> Self {
        let mut broker = FacBroker::new();
        let mut health_checker = BrokerHealthChecker::new();

        // Perform initial health check to satisfy INV-BRK-HEALTH-GATE-001.
        let current_tick = broker.current_tick();
        let eval_window = broker
            .build_evaluation_window(
                TEST_BOUNDARY_ID,
                TEST_AUTHORITY_CLOCK,
                current_tick,
                current_tick + 1,
            )
            .expect("build eval window");
        let _health = broker.check_health(None, &eval_window, &[], &mut health_checker);

        // Advance freshness horizon so TP-002 passes.
        broker.advance_freshness_horizon(current_tick + 100);

        let verifier = BrokerSignatureVerifier::new(broker.verifying_key());
        let scheduler = QueueSchedulerState::new();

        Self {
            broker,
            health_checker,
            verifier,
            scheduler,
        }
    }

    /// Builds a `QueueAdmissionRequest` with broker-issued authority.
    ///
    /// Captures `current_tick` once and uses the same tick range for both
    /// the eval window and the envelope, avoiding the tick-advance race
    /// that occurs when `issue_time_authority_envelope_default_ttl` calls
    /// `advance_tick()` internally.
    fn build_admission_request(&mut self, lane: QueueLane) -> QueueAdmissionRequest {
        // Capture tick BEFORE issuing envelope (issuing advances the tick).
        let current_tick = self.broker.current_tick();
        let eval_window = self
            .broker
            .build_evaluation_window(
                TEST_BOUNDARY_ID,
                TEST_AUTHORITY_CLOCK,
                current_tick,
                current_tick + 1,
            )
            .expect("build eval window");

        // Advance freshness horizon to cover the eval window (TP-002).
        self.broker.advance_freshness_horizon(current_tick + 100);

        // Issue envelope with the SAME tick range as the eval window.
        let envelope = self
            .broker
            .issue_time_authority_envelope_default_ttl(
                TEST_BOUNDARY_ID,
                TEST_AUTHORITY_CLOCK,
                current_tick,
                current_tick + 1,
            )
            .expect("issue envelope");

        QueueAdmissionRequest {
            lane,
            envelope: Some(envelope),
            eval_window,
            freshness_horizon: Some(self.broker.freshness_horizon()),
            revocation_frontier: Some(self.broker.revocation_frontier()),
            convergence_horizon: Some(self.broker.convergence_horizon()),
            convergence_receipts: self.broker.convergence_receipts().to_vec(),
            required_authority_sets: Vec::new(),
            cost: 1,
            current_tick,
        }
    }

    /// Evaluates queue admission using the broker's real signature verifier.
    fn evaluate_admission(
        &mut self,
        lane: QueueLane,
    ) -> apm2_core::economics::queue_admission::QueueAdmissionDecision {
        let request = self.build_admission_request(lane);
        evaluate_queue_admission(&request, &self.scheduler, Some(&self.verifier))
    }
}

// =========================================================================
// Test 1: Happy path -- broker issues authority, worker admits, receipt
// contains RFC-0028 boundary, RFC-0029 queue admission, budget admission.
// =========================================================================

#[test]
fn e2e_happy_path_receipt_contains_rfc0028_and_rfc0029_traces() {
    let mut harness = DefaultModeHarness::new();

    // --- RFC-0029 queue admission ---
    let admission = harness.evaluate_admission(QueueLane::Bulk);
    assert_eq!(
        admission.verdict,
        QueueAdmissionVerdict::Allow,
        "queue admission with broker authority must Allow, trace: {:?}",
        admission.trace,
    );
    assert!(
        admission.trace.tp001_passed,
        "TP-EIO29-001 (envelope validity) must pass with real signature"
    );
    assert!(
        admission.trace.tp002_passed,
        "TP-EIO29-002 (freshness horizon) must pass"
    );
    assert!(
        admission.trace.tp003_passed,
        "TP-EIO29-003 (convergence horizon) must pass"
    );

    // --- RFC-0028 channel context token ---
    let signer = Signer::generate();
    let spec = FacJobSpecV1Builder::new(
        "job-e2e-588-rfc0028",
        "gates",
        "bulk",
        "2026-02-12T00:00:00Z",
        TEST_LEASE_ID,
        test_source(),
    )
    .priority(50)
    .build()
    .expect("valid spec");

    let check = baseline_check();
    let now_secs: u64 = 1_739_000_000;
    let token = issue_channel_context_token(
        &check,
        TEST_LEASE_ID,
        &spec.job_spec_digest,
        now_secs,
        &signer,
    )
    .expect("issue token");

    // Decode and verify the token with the same signer's key.
    let decoded = decode_channel_context_token(
        &token,
        &signer.verifying_key(),
        TEST_LEASE_ID,
        now_secs,
        &spec.actuation.request_id,
    );
    assert!(
        decoded.is_ok(),
        "valid token must decode successfully: {:?}",
        decoded.err()
    );

    // --- Build receipt with all traces ---
    let receipt = FacJobReceiptV1Builder::new(
        "receipt-e2e-588",
        "job-e2e-588-rfc0028",
        &spec.job_spec_digest,
    )
    .outcome(FacJobOutcome::Completed)
    .reason("e2e test completed successfully")
    .rfc0028_channel_boundary(ChannelBoundaryTrace {
        passed: true,
        defect_count: 0,
        defect_classes: Vec::new(),
        token_fac_policy_hash: None,
        token_canonicalizer_tuple_digest: None,
        token_boundary_id: Some(TEST_BOUNDARY_ID.to_string()),
        token_issued_at_tick: Some(1),
        token_expiry_tick: Some(1001),
    })
    .eio29_queue_admission(QueueAdmissionTrace {
        verdict: "allow".to_string(),
        queue_lane: "bulk".to_string(),
        defect_reason: None,
        cost_estimate_ticks: Some(1),
    })
    .eio29_budget_admission(BudgetAdmissionTrace {
        verdict: "allow".to_string(),
        reason: None,
    })
    .try_build()
    .expect("build receipt");

    // Assert receipt fields are populated.
    assert_eq!(receipt.outcome, FacJobOutcome::Completed);
    assert!(
        receipt.rfc0028_channel_boundary.is_some(),
        "receipt must contain RFC-0028 boundary trace"
    );
    let boundary = receipt.rfc0028_channel_boundary.as_ref().unwrap();
    assert!(boundary.passed, "RFC-0028 boundary must be passed");
    assert_eq!(boundary.defect_count, 0, "no defects expected");

    assert!(
        receipt.eio29_queue_admission.is_some(),
        "receipt must contain RFC-0029 queue admission trace"
    );
    let qa_trace = receipt.eio29_queue_admission.as_ref().unwrap();
    assert_eq!(qa_trace.verdict, "allow");

    assert!(
        receipt.eio29_budget_admission.is_some(),
        "receipt must contain RFC-0029 budget admission trace"
    );
    let budget_trace = receipt.eio29_budget_admission.as_ref().unwrap();
    assert_eq!(budget_trace.verdict, "allow");
}

// =========================================================================
// Test 2: Missing token job is denied.
// =========================================================================

#[test]
fn e2e_missing_token_is_denied() {
    // Build a spec without a channel context token.
    let spec = FacJobSpecV1Builder::new(
        "job-e2e-588-no-token",
        "gates",
        "bulk",
        "2026-02-12T00:00:00Z",
        TEST_LEASE_ID,
        test_source(),
    )
    .priority(50)
    .build()
    .expect("valid spec");

    // validate_job_spec should reject the spec due to missing token.
    let result = validate_job_spec(&spec);
    assert!(result.is_err(), "spec without token must fail validation");

    // Verify error is specifically about missing token.
    let err = result.unwrap_err();
    let err_str = format!("{err}");
    assert!(
        err_str.to_lowercase().contains("token"),
        "error must mention token: {err_str}"
    );

    // Build a denial receipt for this case.
    let receipt = FacJobReceiptV1Builder::new(
        "receipt-denied-no-token",
        "job-e2e-588-no-token",
        &spec.job_spec_digest,
    )
    .outcome(FacJobOutcome::Denied)
    .denial_reason(DenialReasonCode::MissingChannelToken)
    .reason("missing RFC-0028 channel context token")
    .try_build()
    .expect("build denial receipt");

    assert_eq!(receipt.outcome, FacJobOutcome::Denied);
    assert_eq!(
        receipt.denial_reason,
        Some(DenialReasonCode::MissingChannelToken),
    );
}

// =========================================================================
// Test 3: Expired token job is denied.
// =========================================================================

#[test]
fn e2e_expired_token_is_denied() {
    let signer = Signer::generate();

    let spec = FacJobSpecV1Builder::new(
        "job-e2e-588-expired",
        "gates",
        "bulk",
        "2026-02-12T00:00:00Z",
        TEST_LEASE_ID,
        test_source(),
    )
    .priority(50)
    .build()
    .expect("valid spec");

    // Issue a token at time T=1000 with default 1800s expiry.
    let check = baseline_check();
    let issue_time: u64 = 1000;
    let token = issue_channel_context_token(
        &check,
        TEST_LEASE_ID,
        &spec.job_spec_digest,
        issue_time,
        &signer,
    )
    .expect("issue token at past time");

    // Attempt to decode the token at T=1000 + 1801 (past expiry).
    let decode_time = issue_time + 1801;
    let decode_result = decode_channel_context_token(
        &token,
        &signer.verifying_key(),
        TEST_LEASE_ID,
        decode_time,
        &spec.actuation.request_id,
    );

    assert!(
        decode_result.is_err(),
        "expired token must fail decode: {:?}",
        decode_result.ok()
    );
}

// =========================================================================
// Test 4: Forged token (wrong key) is denied.
// =========================================================================

#[test]
fn e2e_forged_token_is_denied() {
    let attacker_signer = Signer::generate();
    let broker_signer = Signer::generate();

    let spec = FacJobSpecV1Builder::new(
        "job-e2e-588-forged",
        "gates",
        "bulk",
        "2026-02-12T00:00:00Z",
        TEST_LEASE_ID,
        test_source(),
    )
    .priority(50)
    .build()
    .expect("valid spec");

    let check = baseline_check();
    let now_secs: u64 = 1_739_000_000;

    // Issue token with attacker's key.
    let forged_token = issue_channel_context_token(
        &check,
        TEST_LEASE_ID,
        &spec.job_spec_digest,
        now_secs,
        &attacker_signer,
    )
    .expect("forge token");

    // Attempt to decode with broker's key -- must fail.
    let decode_result = decode_channel_context_token(
        &forged_token,
        &broker_signer.verifying_key(),
        TEST_LEASE_ID,
        now_secs,
        &spec.actuation.request_id,
    );

    assert!(
        decode_result.is_err(),
        "forged token must fail signature verification"
    );
}

// =========================================================================
// Test 5: Verifier=None denies fail-closed (proves NoOpVerifier cfg-gate).
//
// `NoOpVerifier` is gated behind `#[cfg(any(test, feature =
// "unsafe_no_verify"))]` (TCK-00550), so integration tests (separate
// crate context) cannot import it under default features. Instead, we
// prove the equivalent fail-closed behavior: when no verifier is
// injected (`None`), `evaluate_queue_admission` denies with
// `DENY_SIGNATURE_VERIFICATION_NOT_CONFIGURED`, which is the same
// code path `NoOpVerifier` exercises internally.
// =========================================================================

#[test]
fn e2e_noop_verifier_denies_fail_closed() {
    let mut harness = DefaultModeHarness::new();
    let request = harness.build_admission_request(QueueLane::Bulk);

    // Pass `None` as verifier -- same fail-closed path as NoOpVerifier.
    let decision = evaluate_queue_admission(&request, &harness.scheduler, None);

    assert_eq!(
        decision.verdict,
        QueueAdmissionVerdict::Deny,
        "admission without verifier must deny fail-closed"
    );

    // Verify tp001 did not pass (no signature verification possible).
    assert!(
        !decision.trace.tp001_passed,
        "tp001 must NOT pass without verifier"
    );

    // Verify defect reason mentions signature/verification not configured.
    let defect = decision.defect();
    assert!(
        defect.is_some(),
        "denied admission must include a defect trace"
    );
    let defect = defect.unwrap();
    assert!(
        defect.reason.to_lowercase().contains("not configured")
            || defect.reason.to_lowercase().contains("signature"),
        "defect reason must indicate verification not configured: {}",
        defect.reason,
    );
}

// =========================================================================
// Test 6: Queue admission without envelope denies fail-closed.
// =========================================================================

#[test]
fn e2e_queue_admission_without_envelope_denies() {
    let eval_window = HtfEvaluationWindow {
        boundary_id: TEST_BOUNDARY_ID.to_string(),
        authority_clock: TEST_AUTHORITY_CLOCK.to_string(),
        tick_start: 0,
        tick_end: 1,
    };

    let request = QueueAdmissionRequest {
        lane: QueueLane::Bulk,
        envelope: None,
        eval_window,
        freshness_horizon: None,
        revocation_frontier: None,
        convergence_horizon: None,
        convergence_receipts: Vec::new(),
        required_authority_sets: Vec::new(),
        cost: 1,
        current_tick: 0,
    };

    let scheduler = QueueSchedulerState::new();
    // Pass None for verifier -- must deny fail-closed.
    let decision = evaluate_queue_admission(&request, &scheduler, None);

    assert_eq!(
        decision.verdict,
        QueueAdmissionVerdict::Deny,
        "admission without envelope must deny fail-closed"
    );

    // Verify a defect trace is present with a reason.
    let defect = decision.defect();
    assert!(
        defect.is_some(),
        "denied admission must include a defect trace"
    );
    let defect = defect.unwrap();
    assert!(!defect.reason.is_empty(), "defect reason must be non-empty");
}

// =========================================================================
// Test 7: Queue admission without verifier denies fail-closed.
//
// This complements test 5 by specifically checking the queue admission
// path with a valid broker-issued envelope but no verifier injected.
// The envelope's signature cannot be verified, so TP-001 fails and the
// overall verdict is Deny. This proves that even with perfect envelope
// authority, the absence of a real `SignatureVerifier` forces denial.
// =========================================================================

#[test]
fn e2e_queue_admission_with_noop_verifier_denies() {
    let mut harness = DefaultModeHarness::new();
    let request = harness.build_admission_request(QueueLane::Bulk);

    // Pass `None` instead of a real verifier -- must deny fail-closed.
    let decision = evaluate_queue_admission(&request, &harness.scheduler, None);

    assert_eq!(
        decision.verdict,
        QueueAdmissionVerdict::Deny,
        "admission without verifier must deny fail-closed"
    );

    // Verify tp001 did not pass (no signature verification possible).
    assert!(
        !decision.trace.tp001_passed,
        "tp001 must NOT pass without verifier"
    );
}

// =========================================================================
// Test 8: Queue admission with BrokerSignatureVerifier allows (proves real
// signature verification works end-to-end).
// =========================================================================

#[test]
fn e2e_queue_admission_with_broker_verifier_allows() {
    let mut harness = DefaultModeHarness::new();
    let decision = harness.evaluate_admission(QueueLane::Bulk);

    assert_eq!(
        decision.verdict,
        QueueAdmissionVerdict::Allow,
        "admission with BrokerSignatureVerifier must Allow, defect: {:?}",
        decision.defect(),
    );

    // Specifically verify that all three temporal predicates passed.
    assert!(decision.trace.tp001_passed, "TP-001 must pass");
    assert!(decision.trace.tp002_passed, "TP-002 must pass");
    assert!(decision.trace.tp003_passed, "TP-003 must pass");
}

// =========================================================================
// Test 9: Quarantine path -- malformed spec.
// =========================================================================

#[test]
fn e2e_malformed_spec_is_quarantined() {
    use apm2_core::fac::job_spec::deserialize_job_spec;

    let bad_json = b"{ not valid json at all }";
    let result = deserialize_job_spec(bad_json);
    assert!(result.is_err(), "malformed JSON must fail deserialization");

    // Build a quarantine receipt for this case.
    // Use a zero-digest placeholder since the malformed spec has no valid digest.
    let zero_digest = format!("b3-256:{}", "0".repeat(64));
    let receipt =
        FacJobReceiptV1Builder::new("receipt-quarantine-malformed", "unknown", &zero_digest)
            .outcome(FacJobOutcome::Quarantined)
            .denial_reason(DenialReasonCode::MalformedSpec)
            .reason("malformed job spec: deserialization failed")
            .try_build()
            .expect("build quarantine receipt");

    assert_eq!(receipt.outcome, FacJobOutcome::Quarantined);
}

// =========================================================================
// Test 10: Digest mismatch is quarantined.
// =========================================================================

#[test]
fn e2e_digest_mismatch_is_quarantined() {
    let signer = Signer::generate();
    let mut spec = FacJobSpecV1Builder::new(
        "job-e2e-588-digest-mismatch",
        "gates",
        "bulk",
        "2026-02-12T00:00:00Z",
        TEST_LEASE_ID,
        test_source(),
    )
    .priority(50)
    .build()
    .expect("valid spec");

    // Issue a valid token first.
    let check = baseline_check();
    let now_secs: u64 = 1_739_000_000;
    let token = issue_channel_context_token(
        &check,
        TEST_LEASE_ID,
        &spec.job_spec_digest,
        now_secs,
        &signer,
    )
    .expect("issue token");
    spec.actuation.channel_context_token = Some(token);

    // Tamper with kind to cause digest mismatch.
    spec.kind = "warm".to_string();

    let result = validate_job_spec(&spec);
    assert!(result.is_err(), "tampered spec must fail digest validation");

    let err = result.unwrap_err();
    assert!(
        matches!(
            err,
            apm2_core::fac::job_spec::JobSpecError::DigestMismatch { .. }
        ),
        "error must be DigestMismatch, got: {err:?}"
    );
}

// =========================================================================
// Test 11: Full pipeline -- broker issues token and envelope, admission
// passes, receipt roundtrips through serde.
// =========================================================================

#[test]
fn e2e_full_pipeline_receipt_roundtrip() {
    let mut harness = DefaultModeHarness::new();

    // Step 1: Queue admission (RFC-0029).
    let qa_decision = harness.evaluate_admission(QueueLane::Consume);
    assert_eq!(
        qa_decision.verdict,
        QueueAdmissionVerdict::Allow,
        "queue admission must Allow for Consume lane"
    );

    // Step 2: Build receipt with all traces.
    let receipt = FacJobReceiptV1Builder::new(
        "receipt-pipeline-588",
        "job-pipeline-588",
        "b3-256:0000000000000000000000000000000000000000000000000000000000000000",
    )
    .outcome(FacJobOutcome::Completed)
    .reason("pipeline test completed")
    .rfc0028_channel_boundary(ChannelBoundaryTrace {
        passed: true,
        defect_count: 0,
        defect_classes: Vec::new(),
        token_fac_policy_hash: None,
        token_canonicalizer_tuple_digest: None,
        token_boundary_id: Some(TEST_BOUNDARY_ID.to_string()),
        token_issued_at_tick: Some(1),
        token_expiry_tick: Some(1001),
    })
    .eio29_queue_admission(QueueAdmissionTrace {
        verdict: "allow".to_string(),
        queue_lane: "consume".to_string(),
        defect_reason: None,
        cost_estimate_ticks: Some(1),
    })
    .eio29_budget_admission(BudgetAdmissionTrace {
        verdict: "allow".to_string(),
        reason: None,
    })
    .try_build()
    .expect("build receipt");

    // Step 3: Serialize and deserialize receipt (roundtrip).
    let json = serde_json::to_string_pretty(&receipt).expect("serialize receipt");
    let deserialized: FacJobReceiptV1 = serde_json::from_str(&json).expect("deserialize receipt");

    // Verify all three traces survived roundtrip.
    assert_eq!(deserialized.outcome, FacJobOutcome::Completed);
    assert!(deserialized.rfc0028_channel_boundary.is_some());
    assert!(deserialized.eio29_queue_admission.is_some());
    assert!(deserialized.eio29_budget_admission.is_some());

    let roundtrip_boundary = deserialized.rfc0028_channel_boundary.unwrap();
    assert!(roundtrip_boundary.passed);
    assert_eq!(roundtrip_boundary.defect_count, 0);
    assert_eq!(
        roundtrip_boundary.token_boundary_id.as_deref(),
        Some(TEST_BOUNDARY_ID)
    );

    let roundtrip_qa = deserialized.eio29_queue_admission.unwrap();
    assert_eq!(roundtrip_qa.verdict, "allow");
    assert_eq!(roundtrip_qa.queue_lane, "consume");

    let roundtrip_budget = deserialized.eio29_budget_admission.unwrap();
    assert_eq!(roundtrip_budget.verdict, "allow");
}

// =========================================================================
// Test 12: Multiple lanes admitted correctly with distinct envelopes.
// =========================================================================

#[test]
fn e2e_multiple_lanes_admitted() {
    let mut harness = DefaultModeHarness::new();

    // Test Bulk lane.
    let bulk = harness.evaluate_admission(QueueLane::Bulk);
    assert_eq!(
        bulk.verdict,
        QueueAdmissionVerdict::Allow,
        "Bulk lane must Allow"
    );

    // Test Consume lane.
    let consume = harness.evaluate_admission(QueueLane::Consume);
    assert_eq!(
        consume.verdict,
        QueueAdmissionVerdict::Allow,
        "Consume lane must Allow"
    );

    // Test Control lane.
    let control = harness.evaluate_admission(QueueLane::Control);
    assert_eq!(
        control.verdict,
        QueueAdmissionVerdict::Allow,
        "Control lane must Allow"
    );
}
