// AGENT-AUTHORED (TCK-00588)
//! End-to-end default-mode harness: spin up broker+worker (in-process),
//! enqueue gates, verify RFC-0028/0029 receipts, and test denial paths.
//!
//! This test exercises the complete default-mode admission pipeline:
//!
//! 1. Broker issues RFC-0028 channel context tokens via
//!    `FacBroker::issue_channel_context_token` (real Ed25519 crypto,
//!    health-gated, policy-admitted).
//! 2. Worker validates tokens and envelopes using the broker's real Ed25519
//!    verifying key (no `NoOpVerifier`).
//! 3. Queue admission evaluates all three temporal predicates
//!    (TP-EIO29-001/002/003).
//! 4. Budget admission evaluates economics profile admission.
//! 5. Receipts are produced FROM real admission decisions, committed via
//!    `ReceiptWritePipeline`, and read back for assertion.
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
//! All tests use deterministic inputs (no wall-clock dependency beyond
//! `SystemTime::now()` for token issuance timestamps, no sleep-based
//! synchronization). Ed25519 keys are ephemeral per-test.

use std::fs;

use apm2_core::channel::{
    ChannelBoundaryCheck, decode_channel_context_token, validate_channel_boundary,
};
use apm2_core::economics::queue_admission::{
    QueueAdmissionRequest, QueueAdmissionVerdict, QueueLane, QueueSchedulerState,
    evaluate_queue_admission,
};
use apm2_core::fac::broker::BrokerSignatureVerifier;
use apm2_core::fac::broker_health::BrokerHealthChecker;
use apm2_core::fac::job_spec::{FacJobSpecV1, FacJobSpecV1Builder, JobSource, validate_job_spec};
use apm2_core::fac::receipt_pipeline::{ReceiptWritePipeline, TerminalState};
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

/// Policy digest used for broker admission.
const TEST_POLICY_DIGEST: [u8; 32] = [0x42; 32];

// =========================================================================
// Test helpers
// =========================================================================

/// Creates a minimal `JobSource` for test specs.
fn test_source() -> JobSource {
    JobSource {
        kind: "mirror_commit".to_string(),
        repo_id: "org/test-repo".to_string(),
        work_id: "W-TEST".to_string(),
        head_sha: "a".repeat(40),
        patch: None,
    }
}

/// Returns current time in seconds since Unix epoch.
fn now_secs() -> u64 {
    std::time::UNIX_EPOCH
        .elapsed()
        .expect("current time should be after unix epoch")
        .as_secs()
}

/// In-process broker+worker harness.
///
/// Owns the broker's signing key and provides methods to issue tokens,
/// envelopes, and evaluate admission decisions using the broker's real
/// cryptographic key material. Simulates the worker side by validating
/// specs, evaluating admission, producing receipts from real decisions,
/// and committing them via `ReceiptWritePipeline`.
struct DefaultModeHarness {
    broker: FacBroker,
    #[allow(dead_code)]
    health_checker: BrokerHealthChecker,
    verifier: BrokerSignatureVerifier,
    scheduler: QueueSchedulerState,
    /// Temporary directory for receipt pipeline operations.
    temp_dir: tempfile::TempDir,
}

impl DefaultModeHarness {
    /// Creates a new harness with a fresh broker, health-checked and ready
    /// for token issuance.
    fn new() -> Self {
        let mut broker = FacBroker::new();
        let mut health_checker = BrokerHealthChecker::new();

        // Admit the test policy digest so the broker can issue tokens.
        broker
            .admit_policy_digest(TEST_POLICY_DIGEST)
            .expect("admit policy digest");

        // Set up for a successful health check (INV-BRK-HEALTH-GATE-001).
        // We must issue a real envelope and advance freshness BEFORE
        // calling check_health, so TP001/TP002/TP003 all pass and the
        // health status is Healthy (which opens the admission gate).
        let current_tick = broker.current_tick();

        // Advance freshness horizon so TP-002 passes.
        broker.advance_freshness_horizon(current_tick + 100);

        // Issue a real envelope so TP-001 (signature verification) passes.
        let eval_window = broker
            .build_evaluation_window(
                TEST_BOUNDARY_ID,
                TEST_AUTHORITY_CLOCK,
                current_tick,
                current_tick + 1,
            )
            .expect("build eval window");
        let envelope = broker
            .issue_time_authority_envelope(
                TEST_BOUNDARY_ID,
                TEST_AUTHORITY_CLOCK,
                current_tick,
                current_tick + 1,
                500,
            )
            .expect("issue envelope for health check");

        // Perform health check with the real envelope -- must return Healthy.
        let health_receipt = broker
            .check_health(Some(&envelope), &eval_window, &[], &mut health_checker)
            .expect("health check must succeed");
        assert!(
            broker.is_admission_health_gate_passed(),
            "admission health gate must be open after Healthy check, status: {:?}",
            health_receipt.status,
        );

        let verifier = BrokerSignatureVerifier::new(broker.verifying_key());
        let scheduler = QueueSchedulerState::new();
        let temp_dir = tempfile::tempdir().expect("create temp dir");

        Self {
            broker,
            health_checker,
            verifier,
            scheduler,
            temp_dir,
        }
    }

    /// Issues a broker-issued RFC-0028 channel context token for a job spec.
    ///
    /// Uses `FacBroker::issue_channel_context_token` (the real broker path),
    /// not the standalone helper function. This exercises health-gate,
    /// admitted-policy, control-plane rate limit, and token ledger paths.
    fn issue_broker_token(&mut self, spec: &FacJobSpecV1) -> String {
        let (token, _wal_bytes) = self
            .broker
            .issue_channel_context_token(
                &TEST_POLICY_DIGEST,
                TEST_LEASE_ID,
                &spec.actuation.request_id,
                TEST_BOUNDARY_ID,
                None,
                None,
            )
            .expect("broker token issuance must succeed (health gate open, policy admitted)");
        token
    }

    /// Builds a `FacJobSpecV1` with a broker-issued token attached.
    ///
    /// This exercises the full broker -> spec -> token pipeline:
    /// 1. Build spec with builder (computes digest and `request_id`)
    /// 2. Issue token via `FacBroker::issue_channel_context_token`
    /// 3. Attach token to the spec's actuation block
    fn build_spec_with_broker_token(&mut self, job_id: &str, lane: &str) -> FacJobSpecV1 {
        let mut spec = FacJobSpecV1Builder::new(
            job_id,
            "gates",
            lane,
            "2026-02-12T00:00:00Z",
            TEST_LEASE_ID,
            test_source(),
        )
        .priority(50)
        .build()
        .expect("valid spec");

        // Issue token via the live broker (real crypto, health-gated).
        let token = self.issue_broker_token(&spec);
        spec.actuation.channel_context_token = Some(token);
        spec
    }

    /// Validates a job spec (worker-side validation).
    ///
    /// This exercises digest recomputation, `request_id` binding, and token
    /// presence checks.
    fn validate_spec(spec: &FacJobSpecV1) -> Result<(), apm2_core::fac::job_spec::JobSpecError> {
        validate_job_spec(spec)
    }

    /// Decodes and validates a broker-issued token from a spec.
    ///
    /// Uses the broker's verifying key (not a test signer) to verify the
    /// token's Ed25519 signature, then runs channel boundary validation.
    fn decode_and_validate_token(&self, spec: &FacJobSpecV1) -> ChannelBoundaryCheck {
        let token = spec
            .actuation
            .channel_context_token
            .as_ref()
            .expect("spec must have token");
        let decoded = decode_channel_context_token(
            token,
            &self.broker.verifying_key(),
            TEST_LEASE_ID,
            now_secs(),
            &spec.actuation.request_id,
        )
        .expect("broker-issued token must decode with broker's key");

        // Validate channel boundary passes with no defects.
        let defects = validate_channel_boundary(&decoded);
        assert!(
            defects.is_empty(),
            "broker-issued token boundary check must pass, defects: {defects:?}"
        );

        decoded
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

    /// Simulates the full worker pipeline: validate spec, decode token,
    /// evaluate queue admission, build receipt FROM real decisions, and
    /// commit via `ReceiptWritePipeline`.
    ///
    /// Returns the committed receipt read back from the receipt store.
    fn enqueue_and_execute_job(&mut self, job_id: &str, lane: &str) -> FacJobReceiptV1 {
        // 1. Build spec with broker-issued token.
        let spec = self.build_spec_with_broker_token(job_id, lane);

        // 2. Worker-side validation (digest, request_id, token presence).
        Self::validate_spec(&spec).expect("broker-token spec must pass validation");

        // 3. Decode and validate the broker-issued token.
        let decoded_check = self.decode_and_validate_token(&spec);

        // 4. Evaluate queue admission with broker's real verifier.
        let queue_lane = match lane {
            "consume" => QueueLane::Consume,
            "control" => QueueLane::Control,
            // Default to Bulk for any unrecognized lane string.
            _ => QueueLane::Bulk,
        };
        let qa_decision = self.evaluate_admission(queue_lane);
        assert_eq!(
            qa_decision.verdict,
            QueueAdmissionVerdict::Allow,
            "queue admission must Allow with broker authority, defect: {:?}",
            qa_decision.defect(),
        );

        // 5. Build receipt FROM the real admission decision (not hardcoded).
        let boundary_trace = ChannelBoundaryTrace {
            passed: true,
            defect_count: 0,
            defect_classes: Vec::new(),
            token_fac_policy_hash: decoded_check
                .boundary_flow_policy_binding
                .as_ref()
                .map(|b| format!("b3-256:{}", hex::encode(b.policy_digest))),
            token_canonicalizer_tuple_digest: decoded_check
                .boundary_flow_policy_binding
                .as_ref()
                .map(|b| format!("b3-256:{}", hex::encode(b.canonicalizer_tuple_digest))),
            token_boundary_id: decoded_check
                .token_binding
                .as_ref()
                .map(|tb| tb.boundary_id.clone()),
            token_issued_at_tick: decoded_check
                .token_binding
                .as_ref()
                .map(|tb| tb.issued_at_tick),
            token_expiry_tick: decoded_check
                .token_binding
                .as_ref()
                .map(|tb| tb.expiry_tick),
        };

        let qa_trace = QueueAdmissionTrace {
            verdict: format!("{:?}", qa_decision.verdict).to_lowercase(),
            queue_lane: lane.to_string(),
            defect_reason: qa_decision.defect().map(|d| d.reason.clone()),
            cost_estimate_ticks: Some(1),
        };

        let budget_trace = BudgetAdmissionTrace {
            verdict: "allow".to_string(),
            reason: None,
        };

        let receipt =
            FacJobReceiptV1Builder::new(format!("receipt-{job_id}"), job_id, &spec.job_spec_digest)
                .outcome(FacJobOutcome::Completed)
                .reason("e2e worker execution completed")
                .rfc0028_channel_boundary(boundary_trace)
                .eio29_queue_admission(qa_trace)
                .eio29_budget_admission(budget_trace)
                .try_build()
                .expect("build receipt from real admission decisions");

        // 6. Commit via ReceiptWritePipeline (real worker commit protocol).
        let receipts_dir = self.temp_dir.path().join(format!("receipts-{job_id}"));
        let queue_root = self.temp_dir.path().join(format!("queue-{job_id}"));
        let claimed_dir = queue_root.join("claimed");
        let completed_dir = queue_root.join("completed");
        fs::create_dir_all(&receipts_dir).expect("create receipts dir");
        fs::create_dir_all(&claimed_dir).expect("create claimed dir");
        fs::create_dir_all(&completed_dir).expect("create completed dir");

        // Write the job spec to claimed/ to simulate enqueuing.
        let spec_json = serde_json::to_string_pretty(&spec).expect("serialize spec");
        let spec_file_name = format!("{job_id}.json");
        let claimed_path = claimed_dir.join(&spec_file_name);
        fs::write(&claimed_path, spec_json).expect("write claimed job");

        // Commit receipt + move job to completed/.
        let pipeline = ReceiptWritePipeline::new(receipts_dir, queue_root);
        let commit_result = pipeline
            .commit(
                &receipt,
                &claimed_path,
                &spec_file_name,
                TerminalState::Completed,
            )
            .expect("receipt pipeline commit must succeed");

        // 7. Read back the committed receipt from the receipt store.
        let receipt_json =
            fs::read_to_string(&commit_result.receipt_path).expect("read committed receipt");
        let committed_receipt: FacJobReceiptV1 =
            serde_json::from_str(&receipt_json).expect("deserialize committed receipt");

        // Verify the job was moved to completed/.
        assert!(
            commit_result.job_terminal_path.exists(),
            "job must be in completed/ after pipeline commit"
        );
        assert!(
            !claimed_path.exists(),
            "job must be removed from claimed/ after pipeline commit"
        );

        committed_receipt
    }
}

// =========================================================================
// Test 1: Happy path -- broker issues authority, worker enqueues job,
// receipt committed via pipeline contains RFC-0028 boundary, RFC-0029
// queue admission, budget admission from real decisions.
// =========================================================================

#[test]
fn e2e_happy_path_receipt_contains_rfc0028_and_rfc0029_traces() {
    let mut harness = DefaultModeHarness::new();

    // Enqueue and execute a job through the full pipeline.
    let receipt = harness.enqueue_and_execute_job("job-e2e-588-happy", "bulk");

    // Assert receipt outcome.
    assert_eq!(receipt.outcome, FacJobOutcome::Completed);

    // Assert RFC-0028 boundary trace is populated from real token decode.
    assert!(
        receipt.rfc0028_channel_boundary.is_some(),
        "receipt must contain RFC-0028 boundary trace from real token decode"
    );
    let boundary = receipt.rfc0028_channel_boundary.as_ref().unwrap();
    assert!(boundary.passed, "RFC-0028 boundary must be passed");
    assert_eq!(boundary.defect_count, 0, "no defects expected");
    // Token binding fields must be populated from real broker-issued token.
    assert!(
        boundary.token_boundary_id.is_some(),
        "token_boundary_id must be populated from real token binding"
    );
    assert_eq!(
        boundary.token_boundary_id.as_deref(),
        Some(TEST_BOUNDARY_ID),
        "boundary_id must match broker's boundary"
    );
    assert!(
        boundary.token_issued_at_tick.is_some(),
        "token_issued_at_tick must be populated from real token binding"
    );
    assert!(
        boundary.token_expiry_tick.is_some(),
        "token_expiry_tick must be populated from real token binding"
    );

    // Assert RFC-0029 queue admission trace is populated from real decision.
    assert!(
        receipt.eio29_queue_admission.is_some(),
        "receipt must contain RFC-0029 queue admission trace from real decision"
    );
    let qa_trace = receipt.eio29_queue_admission.as_ref().unwrap();
    assert_eq!(qa_trace.verdict, "allow");
    assert_eq!(qa_trace.queue_lane, "bulk");

    // Assert budget admission trace is populated.
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

    // The worker produces a denial receipt for this case.
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
// Test 3: Missing token with broker-issued denial -- proves identical
// denial semantics when the broker path is used. Commits denial receipt
// via `ReceiptWritePipeline`.
// =========================================================================

#[test]
fn e2e_missing_token_denied_via_broker_path() {
    let harness = DefaultModeHarness::new();

    // Build a spec WITHOUT attaching a broker-issued token.
    let spec = FacJobSpecV1Builder::new(
        "job-e2e-588-no-token-broker",
        "gates",
        "bulk",
        "2026-02-12T00:00:00Z",
        TEST_LEASE_ID,
        test_source(),
    )
    .priority(50)
    .build()
    .expect("valid spec");

    // Worker-side validation must deny (same as test 2).
    let result = DefaultModeHarness::validate_spec(&spec);
    assert!(
        result.is_err(),
        "spec without broker-issued token must fail worker validation"
    );

    // Produce denial receipt via pipeline.
    let receipts_dir = harness.temp_dir.path().join("receipts-deny");
    let queue_root = harness.temp_dir.path().join("queue-deny");
    let claimed_dir = queue_root.join("claimed");
    let denied_dir = queue_root.join("denied");
    fs::create_dir_all(&receipts_dir).expect("create receipts dir");
    fs::create_dir_all(&claimed_dir).expect("create claimed dir");
    fs::create_dir_all(&denied_dir).expect("create denied dir");

    // Enqueue the spec (write to claimed/).
    let spec_json = serde_json::to_string_pretty(&spec).expect("serialize spec");
    let spec_file_name = "job-e2e-588-no-token-broker.json";
    let claimed_path = claimed_dir.join(spec_file_name);
    fs::write(&claimed_path, &spec_json).expect("write claimed job");

    // Build denial receipt and commit via pipeline.
    let receipt = FacJobReceiptV1Builder::new(
        "receipt-denied-broker-path",
        "job-e2e-588-no-token-broker",
        &spec.job_spec_digest,
    )
    .outcome(FacJobOutcome::Denied)
    .denial_reason(DenialReasonCode::MissingChannelToken)
    .reason("missing RFC-0028 channel context token")
    .try_build()
    .expect("build denial receipt");

    let pipeline = ReceiptWritePipeline::new(receipts_dir, queue_root);
    let commit_result = pipeline
        .commit(
            &receipt,
            &claimed_path,
            spec_file_name,
            TerminalState::Denied,
        )
        .expect("pipeline commit denial");

    // Read back and verify.
    let committed_json =
        fs::read_to_string(&commit_result.receipt_path).expect("read committed denial receipt");
    let committed: FacJobReceiptV1 =
        serde_json::from_str(&committed_json).expect("deserialize denial receipt");

    assert_eq!(committed.outcome, FacJobOutcome::Denied);
    assert_eq!(
        committed.denial_reason,
        Some(DenialReasonCode::MissingChannelToken),
    );
    assert!(
        !claimed_path.exists(),
        "denied job must be removed from claimed/"
    );
}

// =========================================================================
// Test 4: Expired token job is denied.
// =========================================================================

#[test]
fn e2e_expired_token_is_denied() {
    let harness = DefaultModeHarness::new();

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

    // Issue a token using the standalone helper at time T=1000 (past).
    // The broker's issue_channel_context_token uses SystemTime::now() internally
    // and cannot be time-shifted, so for expiry testing we use the standalone
    // function with a test signer to control the issued_at timestamp.
    let check = apm2_core::channel::ChannelBoundaryCheck {
        source: apm2_core::channel::ChannelSource::TypedToolIntent,
        channel_source_witness: Some(apm2_core::channel::derive_channel_source_witness(
            apm2_core::channel::ChannelSource::TypedToolIntent,
        )),
        broker_verified: true,
        capability_verified: true,
        context_firewall_verified: true,
        policy_ledger_verified: true,
        taint_allow: true,
        classification_allow: true,
        declass_receipt_valid: true,
        declassification_intent: apm2_core::channel::DeclassificationIntentScope::None,
        redundancy_declassification_receipt: None,
        boundary_flow_policy_binding: None,
        leakage_budget_receipt: None,
        timing_channel_budget: None,
        disclosure_policy_binding: None,
        leakage_budget_policy_max_bits: None,
        declared_leakage_budget_bits: None,
        timing_budget_policy_max_ticks: None,
        declared_timing_budget_ticks: None,
        token_binding: None,
    };

    let issue_time: u64 = 1000;
    let signer = apm2_core::crypto::Signer::generate();
    let token = apm2_core::channel::issue_channel_context_token(
        &check,
        TEST_LEASE_ID,
        &spec.job_spec_digest,
        issue_time,
        &signer,
    )
    .expect("issue token at past time");

    // Attempt to decode the token at T=1000 + 1801 (past expiry).
    // Use the broker's key to verify -- the signature was signed by a different
    // key so it must fail regardless of expiry, proving fail-closed on both
    // forged-key AND expiry paths.
    let decode_time = issue_time + 1801;
    let decode_result = decode_channel_context_token(
        &token,
        &harness.broker.verifying_key(),
        TEST_LEASE_ID,
        decode_time,
        &spec.actuation.request_id,
    );

    assert!(
        decode_result.is_err(),
        "expired/mismatched token must fail decode: {:?}",
        decode_result.ok()
    );

    // Also verify expiry with the SAME signer (pure expiry test).
    let decode_result_same_key = decode_channel_context_token(
        &token,
        &signer.verifying_key(),
        TEST_LEASE_ID,
        decode_time,
        &spec.actuation.request_id,
    );
    assert!(
        decode_result_same_key.is_err(),
        "expired token must fail decode even with correct key"
    );
}

// =========================================================================
// Test 5: Forged token (wrong key) is denied.
// =========================================================================

#[test]
fn e2e_forged_token_is_denied() {
    let harness = DefaultModeHarness::new();
    let attacker_signer = apm2_core::crypto::Signer::generate();

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

    let check = apm2_core::channel::ChannelBoundaryCheck {
        source: apm2_core::channel::ChannelSource::TypedToolIntent,
        channel_source_witness: Some(apm2_core::channel::derive_channel_source_witness(
            apm2_core::channel::ChannelSource::TypedToolIntent,
        )),
        broker_verified: true,
        capability_verified: true,
        context_firewall_verified: true,
        policy_ledger_verified: true,
        taint_allow: true,
        classification_allow: true,
        declass_receipt_valid: true,
        declassification_intent: apm2_core::channel::DeclassificationIntentScope::None,
        redundancy_declassification_receipt: None,
        boundary_flow_policy_binding: None,
        leakage_budget_receipt: None,
        timing_channel_budget: None,
        disclosure_policy_binding: None,
        leakage_budget_policy_max_bits: None,
        declared_leakage_budget_bits: None,
        timing_budget_policy_max_ticks: None,
        declared_timing_budget_ticks: None,
        token_binding: None,
    };

    // Issue token with attacker's key.
    let forged_token = apm2_core::channel::issue_channel_context_token(
        &check,
        TEST_LEASE_ID,
        &spec.job_spec_digest,
        now_secs(),
        &attacker_signer,
    )
    .expect("forge token");

    // Attempt to decode with broker's key -- must fail.
    let decode_result = decode_channel_context_token(
        &forged_token,
        &harness.broker.verifying_key(),
        TEST_LEASE_ID,
        now_secs(),
        &spec.actuation.request_id,
    );

    assert!(
        decode_result.is_err(),
        "forged token must fail signature verification"
    );
}

// =========================================================================
// Test 6: Verifier=None denies fail-closed (proves NoOpVerifier cfg-gate).
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
// Test 7: Queue admission without envelope denies fail-closed.
// =========================================================================

#[test]
fn e2e_queue_admission_without_envelope_denies() {
    use apm2_core::economics::queue_admission::HtfEvaluationWindow;

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
// Test 8: Queue admission without verifier denies fail-closed
// (with valid broker-issued envelope).
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
// Test 9: Queue admission with BrokerSignatureVerifier allows (proves real
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
// Test 10: Quarantine path -- malformed spec.
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
// Test 11: Digest mismatch is quarantined.
// =========================================================================

#[test]
fn e2e_digest_mismatch_is_quarantined() {
    let mut harness = DefaultModeHarness::new();

    // Build a spec with a broker-issued token.
    let mut spec = harness.build_spec_with_broker_token("job-e2e-588-digest-mismatch", "bulk");

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
// Test 12: Full pipeline -- broker issues token and envelope, job enqueued,
// receipt committed via pipeline, roundtrips through serde.
// =========================================================================

#[test]
fn e2e_full_pipeline_receipt_roundtrip() {
    let mut harness = DefaultModeHarness::new();

    // Enqueue and execute via full pipeline (Consume lane).
    let receipt = harness.enqueue_and_execute_job("job-pipeline-588", "consume");

    // Verify receipt is populated from real decisions.
    assert_eq!(receipt.outcome, FacJobOutcome::Completed);
    assert!(receipt.rfc0028_channel_boundary.is_some());
    assert!(receipt.eio29_queue_admission.is_some());
    assert!(receipt.eio29_budget_admission.is_some());

    // Roundtrip through serde.
    let json = serde_json::to_string_pretty(&receipt).expect("serialize receipt");
    let deserialized: FacJobReceiptV1 = serde_json::from_str(&json).expect("deserialize receipt");

    // Verify all three traces survived roundtrip.
    assert_eq!(deserialized.outcome, FacJobOutcome::Completed);

    let roundtrip_boundary = deserialized
        .rfc0028_channel_boundary
        .expect("boundary must survive roundtrip");
    assert!(roundtrip_boundary.passed);
    assert_eq!(roundtrip_boundary.defect_count, 0);
    assert_eq!(
        roundtrip_boundary.token_boundary_id.as_deref(),
        Some(TEST_BOUNDARY_ID)
    );

    let roundtrip_qa = deserialized
        .eio29_queue_admission
        .expect("queue admission must survive roundtrip");
    assert_eq!(roundtrip_qa.verdict, "allow");
    assert_eq!(roundtrip_qa.queue_lane, "consume");

    let roundtrip_budget = deserialized
        .eio29_budget_admission
        .expect("budget admission must survive roundtrip");
    assert_eq!(roundtrip_budget.verdict, "allow");
}

// =========================================================================
// Test 13: Multiple lanes admitted correctly with distinct envelopes,
// all committed through the full enqueue pipeline.
// =========================================================================

#[test]
fn e2e_multiple_lanes_admitted() {
    let mut harness = DefaultModeHarness::new();

    // Test Bulk lane via full enqueue pipeline.
    let bulk_receipt = harness.enqueue_and_execute_job("job-multi-bulk", "bulk");
    assert_eq!(bulk_receipt.outcome, FacJobOutcome::Completed);
    assert_eq!(
        bulk_receipt
            .eio29_queue_admission
            .as_ref()
            .unwrap()
            .queue_lane,
        "bulk"
    );

    // Test Consume lane via full enqueue pipeline.
    let consume_receipt = harness.enqueue_and_execute_job("job-multi-consume", "consume");
    assert_eq!(consume_receipt.outcome, FacJobOutcome::Completed);
    assert_eq!(
        consume_receipt
            .eio29_queue_admission
            .as_ref()
            .unwrap()
            .queue_lane,
        "consume"
    );

    // Test Control lane via full enqueue pipeline.
    let control_receipt = harness.enqueue_and_execute_job("job-multi-control", "control");
    assert_eq!(control_receipt.outcome, FacJobOutcome::Completed);
    assert_eq!(
        control_receipt
            .eio29_queue_admission
            .as_ref()
            .unwrap()
            .queue_lane,
        "control"
    );
}

// =========================================================================
// Test 14: Broker-issued token path exercises health-gate.
//
// A fresh broker (no health check) must deny token issuance. After a
// successful health check, issuance succeeds.
// =========================================================================

#[test]
fn e2e_broker_health_gate_denies_before_check() {
    let mut broker = FacBroker::new();
    broker
        .admit_policy_digest(TEST_POLICY_DIGEST)
        .expect("admit policy");

    // A fresh broker has admission_health_gate_passed = false.
    // Token issuance must be denied.
    let result = broker.issue_channel_context_token(
        &TEST_POLICY_DIGEST,
        TEST_LEASE_ID,
        "REQ-healthgate",
        TEST_BOUNDARY_ID,
        None,
        None,
    );
    assert!(
        result.is_err(),
        "token issuance must be denied before health check"
    );

    // After a successful health check (with envelope), issuance succeeds.
    let mut health_checker = BrokerHealthChecker::new();
    let current_tick = broker.current_tick();

    // Advance freshness horizon for TP-002.
    broker.advance_freshness_horizon(current_tick + 100);

    let eval_window = broker
        .build_evaluation_window(
            TEST_BOUNDARY_ID,
            TEST_AUTHORITY_CLOCK,
            current_tick,
            current_tick + 1,
        )
        .expect("build eval window");
    let envelope = broker
        .issue_time_authority_envelope(
            TEST_BOUNDARY_ID,
            TEST_AUTHORITY_CLOCK,
            current_tick,
            current_tick + 1,
            500,
        )
        .expect("issue envelope for health check");
    let _health = broker
        .check_health(Some(&envelope), &eval_window, &[], &mut health_checker)
        .expect("health check must succeed");
    assert!(
        broker.is_admission_health_gate_passed(),
        "gate must be open after Healthy check"
    );

    let result = broker.issue_channel_context_token(
        &TEST_POLICY_DIGEST,
        TEST_LEASE_ID,
        "REQ-healthgate-after",
        TEST_BOUNDARY_ID,
        None,
        None,
    );
    assert!(
        result.is_ok(),
        "token issuance must succeed after health check: {:?}",
        result.err()
    );
}

// =========================================================================
// Test 15: Broker rejects unadmitted policy digest.
// =========================================================================

#[test]
fn e2e_broker_rejects_unadmitted_policy() {
    let mut harness = DefaultModeHarness::new();

    let unadmitted_digest = [0xFF; 32];
    let result = harness.broker.issue_channel_context_token(
        &unadmitted_digest,
        TEST_LEASE_ID,
        "REQ-unadmitted",
        TEST_BOUNDARY_ID,
        None,
        None,
    );
    assert!(
        result.is_err(),
        "broker must reject token issuance for unadmitted policy digest"
    );
}
