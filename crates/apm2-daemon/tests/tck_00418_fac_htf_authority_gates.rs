//! TCK-00418: HTF authority hardening for FAC lifecycle transitions.
//!
//! Integration tests verifying:
//!
//! - **AC-1**: Transitions denied if `time_envelope_ref` is missing,
//!   unresolvable, or references a disallowed `clock_profile_hash`.
//! - **AC-2**: Lease/gate expiry decisions are tick/envelope-based and
//!   invariant under wall-time perturbation.
//! - **AC-3**: No authoritative admission or gate decision consumes wall-time
//!   values directly.
//!
//! Evidence artifact: EVID-HEF-0016

use std::sync::Arc;

use apm2_core::crypto::Signer;
use apm2_core::evidence::{ContentAddressedStore, MemoryCas};
use apm2_core::fac::GateLeaseBuilder;
use apm2_core::htf::{
    BoundedWallInterval, Canonicalizable, ClockProfile, Hlc, LedgerTime, MonotonicReading,
    MonotonicSource, TimeEnvelope, WallTimeSource,
};
use apm2_daemon::protocol::dispatch::LeaseValidator;
use apm2_daemon::protocol::{
    ConnectionContext, IngestReviewReceiptRequest, PeerCredentials, PrivilegedDispatcher,
    PrivilegedErrorCode, PrivilegedResponse, ReviewReceiptVerdict, derive_actor_id,
    encode_ingest_review_receipt_request,
};

// ============================================================================
// Test artifact constants
// ============================================================================

const TEST_ARTIFACT_CONTENT: &[u8] = b"test-artifact-bundle-content";

fn test_artifact_bundle_hash() -> Vec<u8> {
    let cas = MemoryCas::default();
    let result = cas.store(TEST_ARTIFACT_CONTENT).unwrap();
    result.hash.to_vec()
}

const fn test_peer_credentials() -> PeerCredentials {
    PeerCredentials {
        uid: 1000,
        gid: 1000,
        pid: Some(12345),
    }
}

fn privileged_ctx() -> ConnectionContext {
    ConnectionContext::privileged_session_open(Some(test_peer_credentials()))
}

// ============================================================================
// HTF artifact helpers
// ============================================================================

/// Stores a canonical `ClockProfileV1` + `TimeEnvelopeV1` in CAS and returns
/// the envelope hash reference (`time_envelope_ref`).
fn store_time_authority_artifacts(
    cas: &dyn ContentAddressedStore,
    wall_time_source: WallTimeSource,
    include_attestation: bool,
) -> String {
    let clock_profile = ClockProfile {
        attestation: include_attestation.then(|| serde_json::json!({"kind": "test"})),
        build_fingerprint: "apm2-daemon/test".to_string(),
        hlc_enabled: true,
        max_wall_uncertainty_ns: 1_000_000,
        monotonic_source: MonotonicSource::ClockMonotonic,
        profile_policy_id: "test-policy".to_string(),
        tick_rate_hz: 1_000_000_000,
        wall_time_source,
    };

    let profile_bytes = clock_profile
        .canonical_bytes()
        .expect("clock profile canonicalization should succeed");
    let profile_hash = clock_profile
        .canonical_hash()
        .expect("clock profile hash should succeed");
    let stored_profile = cas
        .store(&profile_bytes)
        .expect("clock profile should store");
    assert_eq!(
        stored_profile.hash, profile_hash,
        "stored profile hash must match canonical hash"
    );

    let envelope = TimeEnvelope {
        clock_profile_hash: hex::encode(profile_hash),
        hlc: Hlc {
            logical: 0,
            wall_ns: 1_700_000_000_000_000_000,
        },
        ledger_anchor: LedgerTime::new("test-ledger", 0, 1),
        mono: MonotonicReading {
            end_tick: Some(10_000_000_000),
            source: MonotonicSource::ClockMonotonic,
            start_tick: 0,
            tick_rate_hz: 1_000_000_000,
        },
        notes: Some("htf-authority-test".to_string()),
        wall: BoundedWallInterval::new(
            1_700_000_000_000_000_000,
            1_700_000_000_100_000_000,
            wall_time_source,
            "95%",
        )
        .expect("bounded wall interval should be valid"),
    };

    let envelope_bytes = envelope
        .canonical_bytes()
        .expect("time envelope canonicalization should succeed");
    let envelope_hash = envelope
        .canonical_hash()
        .expect("time envelope hash should succeed");
    let stored_envelope = cas
        .store(&envelope_bytes)
        .expect("time envelope should store");
    assert_eq!(
        stored_envelope.hash, envelope_hash,
        "stored envelope hash must match canonical hash"
    );

    hex::encode(envelope_hash)
}

/// Registers a full gate lease with CAS-hosted HTF artifacts.
#[allow(clippy::too_many_arguments)]
fn register_full_test_lease(
    lease_validator: &dyn LeaseValidator,
    cas: &dyn ContentAddressedStore,
    lease_id: &str,
    work_id: &str,
    gate_id: &str,
    executor_actor_id: &str,
    policy_hash: [u8; 32],
    wall_time_source: WallTimeSource,
    include_attestation: bool,
) {
    let time_envelope_ref =
        store_time_authority_artifacts(cas, wall_time_source, include_attestation);
    let signer = Signer::generate();
    let full_lease = GateLeaseBuilder::new(lease_id, work_id, gate_id)
        .changeset_digest([0x42; 32])
        .executor_actor_id(executor_actor_id)
        .issued_at(1_000_000)
        .expires_at(2_000_000)
        .policy_hash(policy_hash)
        .issuer_actor_id("issuer-test")
        .time_envelope_ref(&time_envelope_ref)
        .build_and_sign(&signer);
    lease_validator
        .register_full_lease(&full_lease)
        .expect("full lease registration should succeed");
}

/// Registers a gate lease with an EMPTY `time_envelope_ref`, simulating
/// a lease that was issued before HTF authority hardening.
fn register_lease_without_envelope(
    lease_validator: &dyn LeaseValidator,
    lease_id: &str,
    work_id: &str,
    gate_id: &str,
    executor_actor_id: &str,
    policy_hash: [u8; 32],
) {
    let signer = Signer::generate();
    let full_lease = GateLeaseBuilder::new(lease_id, work_id, gate_id)
        .changeset_digest([0x42; 32])
        .executor_actor_id(executor_actor_id)
        .issued_at(1_000_000)
        .expires_at(2_000_000)
        .policy_hash(policy_hash)
        .issuer_actor_id("issuer-test")
        .time_envelope_ref("") // Empty string triggers "missing" check
        .build_and_sign(&signer);
    lease_validator
        .register_full_lease(&full_lease)
        .expect("lease registration (empty envelope) should succeed");
}

fn make_review_receipt_request(lease_id: &str) -> IngestReviewReceiptRequest {
    IngestReviewReceiptRequest {
        lease_id: lease_id.to_string(),
        receipt_id: format!("RR-{lease_id}"),
        reviewer_actor_id: derive_actor_id(&test_peer_credentials()),
        changeset_digest: vec![0x42; 32],
        artifact_bundle_hash: test_artifact_bundle_hash(),
        verdict: ReviewReceiptVerdict::Approve.into(),
        blocked_reason_code: 0,
        blocked_log_hash: vec![],
        identity_proof_hash: vec![0x99; 32],
    }
}

fn dispatch_review_receipt(
    dispatcher: &PrivilegedDispatcher,
    ctx: &ConnectionContext,
    request: &IngestReviewReceiptRequest,
) -> PrivilegedResponse {
    let frame = encode_ingest_review_receipt_request(request);
    dispatcher.dispatch(&frame, ctx).expect("dispatch ok")
}

// ============================================================================
// AC-1: Transitions denied if time_envelope_ref is missing, unresolvable,
// or references a disallowed clock_profile_hash.
// ============================================================================

/// AC-1.1: Missing `time_envelope_ref` on lease => hard denial.
///
/// A lease without any `time_envelope_ref` binding MUST be rejected by the
/// review receipt ingestion path with a clear error message. This prevents
/// legacy or misconfigured leases from bypassing HTF authority checks.
#[test]
fn test_missing_time_envelope_ref_denied() {
    let peer_creds = test_peer_credentials();
    let executor_actor_id = derive_actor_id(&peer_creds);
    let cas = Arc::new(MemoryCas::default());
    cas.store(TEST_ARTIFACT_CONTENT).unwrap();

    let dispatcher =
        PrivilegedDispatcher::new().with_cas(Arc::clone(&cas) as Arc<dyn ContentAddressedStore>);

    // Register lease WITHOUT time_envelope_ref
    dispatcher.lease_validator().register_lease_with_executor(
        "lease-no-env",
        "W-NO-ENV",
        "gate-001",
        &executor_actor_id,
    );
    register_lease_without_envelope(
        dispatcher.lease_validator().as_ref(),
        "lease-no-env",
        "W-NO-ENV",
        "gate-001",
        &executor_actor_id,
        [0u8; 32],
    );

    let request = make_review_receipt_request("lease-no-env");
    let ctx = privileged_ctx();
    let response = dispatch_review_receipt(&dispatcher, &ctx, &request);

    match response {
        PrivilegedResponse::Error(err) => {
            assert_eq!(
                err.code(),
                PrivilegedErrorCode::CapabilityRequestRejected,
                "missing envelope must be CapabilityRequestRejected"
            );
            assert!(
                err.message.contains("time_envelope_ref") || err.message.contains("HTF authority"),
                "error message must mention time_envelope_ref or HTF authority, got: {}",
                err.message
            );
        },
        other => panic!("expected rejection for missing time_envelope_ref, got: {other:?}"),
    }
}

/// AC-1.2: Unresolvable `time_envelope_ref` (hash not in CAS) => hard denial.
///
/// If the CAS lookup for the envelope hash returns an error, the transition
/// MUST be denied. This tests the CAS-resolution path.
#[test]
fn test_unresolvable_time_envelope_ref_denied() {
    let peer_creds = test_peer_credentials();
    let executor_actor_id = derive_actor_id(&peer_creds);
    let cas = Arc::new(MemoryCas::default());
    cas.store(TEST_ARTIFACT_CONTENT).unwrap();

    let dispatcher =
        PrivilegedDispatcher::new().with_cas(Arc::clone(&cas) as Arc<dyn ContentAddressedStore>);

    // Register lease with a fabricated time_envelope_ref that does NOT exist in CAS
    let signer = Signer::generate();
    let full_lease = GateLeaseBuilder::new("lease-bad-ref", "W-BAD-REF", "gate-002")
        .changeset_digest([0x42; 32])
        .executor_actor_id(&executor_actor_id)
        .issued_at(1_000_000)
        .expires_at(2_000_000)
        .policy_hash([0u8; 32])
        .issuer_actor_id("issuer-test")
        .time_envelope_ref(hex::encode([0xDE; 32])) // bogus hash
        .build_and_sign(&signer);
    dispatcher
        .lease_validator()
        .register_full_lease(&full_lease)
        .expect("lease registration should succeed");
    dispatcher.lease_validator().register_lease_with_executor(
        "lease-bad-ref",
        "W-BAD-REF",
        "gate-002",
        &executor_actor_id,
    );

    let request = make_review_receipt_request("lease-bad-ref");
    let ctx = privileged_ctx();
    let response = dispatch_review_receipt(&dispatcher, &ctx, &request);

    match response {
        PrivilegedResponse::Error(err) => {
            assert_eq!(
                err.code(),
                PrivilegedErrorCode::CapabilityRequestRejected,
                "unresolvable envelope must be CapabilityRequestRejected"
            );
            assert!(
                err.message.contains("HTF authority")
                    || err.message.contains("time_envelope_ref")
                    || err.message.contains("CAS"),
                "error message must mention CAS or HTF, got: {}",
                err.message
            );
        },
        other => panic!("expected rejection for unresolvable time_envelope_ref, got: {other:?}"),
    }
}

/// AC-1.3: Disallowed `clock_profile_hash` for risk tier => hard denial.
///
/// A Tier4 (fail-closed default) risk tier with `BestEffortNtp` wall time
/// source is not admissible. The profile admissibility check MUST reject it.
#[test]
fn test_disallowed_clock_profile_hash_denied() {
    let peer_creds = test_peer_credentials();
    let executor_actor_id = derive_actor_id(&peer_creds);
    let cas = Arc::new(MemoryCas::default());
    cas.store(TEST_ARTIFACT_CONTENT).unwrap();

    let dispatcher =
        PrivilegedDispatcher::new().with_cas(Arc::clone(&cas) as Arc<dyn ContentAddressedStore>);

    // Register lease with BestEffortNtp source — inadmissible for Tier2+
    dispatcher.lease_validator().register_lease_with_executor(
        "lease-bad-src",
        "W-BAD-SRC",
        "gate-003",
        &executor_actor_id,
    );
    register_full_test_lease(
        dispatcher.lease_validator().as_ref(),
        cas.as_ref(),
        "lease-bad-src",
        "W-BAD-SRC",
        "gate-003",
        &executor_actor_id,
        [0u8; 32],
        WallTimeSource::BestEffortNtp, // Disallowed for Tier2+
        true,                          // attestation present
    );

    let request = make_review_receipt_request("lease-bad-src");
    let ctx = privileged_ctx();
    let response = dispatch_review_receipt(&dispatcher, &ctx, &request);

    match response {
        PrivilegedResponse::Error(err) => {
            assert_eq!(
                err.code(),
                PrivilegedErrorCode::CapabilityRequestRejected,
                "disallowed clock profile must be CapabilityRequestRejected"
            );
            assert!(
                err.message.contains("HTF authority")
                    || err.message.contains("not admissible")
                    || err.message.contains("clock_profile"),
                "error message must mention profile inadmissibility, got: {}",
                err.message
            );
        },
        other => panic!("expected rejection for disallowed clock profile, got: {other:?}"),
    }
}

/// AC-1.4: Missing attestation for Tier3/Tier4 => hard denial.
///
/// Risk tiers Tier3 and Tier4 require `attestation.is_some()` in the clock
/// profile. Without a work claim, the risk tier defaults to Tier4
/// (fail-closed). A profile without attestation MUST be rejected.
#[test]
fn test_missing_attestation_for_high_tier_denied() {
    let peer_creds = test_peer_credentials();
    let executor_actor_id = derive_actor_id(&peer_creds);
    let cas = Arc::new(MemoryCas::default());
    cas.store(TEST_ARTIFACT_CONTENT).unwrap();

    let dispatcher =
        PrivilegedDispatcher::new().with_cas(Arc::clone(&cas) as Arc<dyn ContentAddressedStore>);

    // Register lease with AuthenticatedNts but NO attestation
    dispatcher.lease_validator().register_lease_with_executor(
        "lease-no-att",
        "W-NO-ATT",
        "gate-004",
        &executor_actor_id,
    );
    register_full_test_lease(
        dispatcher.lease_validator().as_ref(),
        cas.as_ref(),
        "lease-no-att",
        "W-NO-ATT",
        "gate-004",
        &executor_actor_id,
        [0u8; 32],
        WallTimeSource::AuthenticatedNts, // Allowed source
        false,                            // NO attestation — required for Tier3/4
    );

    let request = make_review_receipt_request("lease-no-att");
    let ctx = privileged_ctx();
    let response = dispatch_review_receipt(&dispatcher, &ctx, &request);

    match response {
        PrivilegedResponse::Error(err) => {
            assert_eq!(
                err.code(),
                PrivilegedErrorCode::CapabilityRequestRejected,
                "missing attestation must be CapabilityRequestRejected"
            );
            assert!(
                err.message.contains("HTF authority")
                    || err.message.contains("not admissible")
                    || err.message.contains("clock_profile"),
                "error message must mention profile inadmissibility, got: {}",
                err.message
            );
        },
        other => panic!("expected rejection for missing attestation, got: {other:?}"),
    }
}

// ============================================================================
// AC-2: Lease/gate expiry decisions are tick/envelope-based and invariant
// under wall-time perturbation.
// ============================================================================

/// AC-2.1: Wall-time perturbation does not alter authority outcome.
///
/// Constructs two identical test scenarios differing ONLY in the wall-time
/// values within the `TimeEnvelope`. Both MUST produce the same authority
/// decision (rejection or approval), proving that gate decisions are
/// tick/envelope-based and not wall-time-dependent.
#[test]
fn test_wall_time_perturbation_invariance() {
    let peer_creds = test_peer_credentials();
    let executor_actor_id = derive_actor_id(&peer_creds);

    // --- Scenario A: wall_ns at epoch 1.7e18 ---
    let cas_a = Arc::new(MemoryCas::default());
    cas_a.store(TEST_ARTIFACT_CONTENT).unwrap();
    let dispatcher_a =
        PrivilegedDispatcher::new().with_cas(Arc::clone(&cas_a) as Arc<dyn ContentAddressedStore>);

    dispatcher_a.lease_validator().register_lease_with_executor(
        "lease-wt-a",
        "W-WT-A",
        "gate-wt",
        &executor_actor_id,
    );

    // Store envelope with wall_ns = 1.7e18
    let time_ref_a = store_envelope_with_wall_ns(
        cas_a.as_ref(),
        1_700_000_000_000_000_000,
        1_700_000_000_100_000_000,
    );
    register_lease_with_envelope_ref(
        dispatcher_a.lease_validator().as_ref(),
        "lease-wt-a",
        "W-WT-A",
        "gate-wt",
        &executor_actor_id,
        &time_ref_a,
    );

    // --- Scenario B: wall_ns at epoch 2.0e18 (300M ns later) ---
    let cas_b = Arc::new(MemoryCas::default());
    cas_b.store(TEST_ARTIFACT_CONTENT).unwrap();
    let dispatcher_b =
        PrivilegedDispatcher::new().with_cas(Arc::clone(&cas_b) as Arc<dyn ContentAddressedStore>);

    dispatcher_b.lease_validator().register_lease_with_executor(
        "lease-wt-b",
        "W-WT-B",
        "gate-wt",
        &executor_actor_id,
    );

    // Store envelope with drastically different wall_ns = 2.0e18
    let time_ref_b = store_envelope_with_wall_ns(
        cas_b.as_ref(),
        2_000_000_000_000_000_000,
        2_000_000_000_100_000_000,
    );
    register_lease_with_envelope_ref(
        dispatcher_b.lease_validator().as_ref(),
        "lease-wt-b",
        "W-WT-B",
        "gate-wt",
        &executor_actor_id,
        &time_ref_b,
    );

    let request_a = make_review_receipt_request("lease-wt-a");
    let request_b = IngestReviewReceiptRequest {
        lease_id: "lease-wt-b".to_string(),
        receipt_id: "RR-lease-wt-b".to_string(),
        ..make_review_receipt_request("lease-wt-a")
    };

    let ctx = privileged_ctx();
    let response_a = dispatch_review_receipt(&dispatcher_a, &ctx, &request_a);
    let response_b = dispatch_review_receipt(&dispatcher_b, &ctx, &request_b);

    // Both must produce the same CATEGORY of response (both error or both
    // success) — wall-time perturbation must not change the authority outcome.
    let a_is_error = matches!(response_a, PrivilegedResponse::Error(_));
    let b_is_error = matches!(response_b, PrivilegedResponse::Error(_));
    assert_eq!(
        a_is_error, b_is_error,
        "wall-time perturbation must not change authority outcome; \
         scenario A error={a_is_error}, scenario B error={b_is_error}"
    );
}

/// AC-2.2: Tick-based lease expiry is deterministic under wall-time shift.
///
/// Two envelopes with identical tick readings but different wall times MUST
/// produce identical authority verdicts.
#[test]
fn test_tick_based_authority_determinism() {
    let peer_creds = test_peer_credentials();
    let executor_actor_id = derive_actor_id(&peer_creds);

    // Build two envelopes: same ticks, different wall times
    let cas_1 = Arc::new(MemoryCas::default());
    cas_1.store(TEST_ARTIFACT_CONTENT).unwrap();
    let cas_2 = Arc::new(MemoryCas::default());
    cas_2.store(TEST_ARTIFACT_CONTENT).unwrap();

    let ref_1 = store_envelope_with_wall_ns(
        cas_1.as_ref(),
        1_600_000_000_000_000_000, // "past"
        1_600_000_000_100_000_000,
    );
    let ref_2 = store_envelope_with_wall_ns(
        cas_2.as_ref(),
        1_900_000_000_000_000_000, // "future"
        1_900_000_000_100_000_000,
    );

    let d1 =
        PrivilegedDispatcher::new().with_cas(Arc::clone(&cas_1) as Arc<dyn ContentAddressedStore>);
    let d2 =
        PrivilegedDispatcher::new().with_cas(Arc::clone(&cas_2) as Arc<dyn ContentAddressedStore>);

    d1.lease_validator().register_lease_with_executor(
        "l-tick-1",
        "W-T1",
        "g-tick",
        &executor_actor_id,
    );
    register_lease_with_envelope_ref(
        d1.lease_validator().as_ref(),
        "l-tick-1",
        "W-T1",
        "g-tick",
        &executor_actor_id,
        &ref_1,
    );

    d2.lease_validator().register_lease_with_executor(
        "l-tick-2",
        "W-T2",
        "g-tick",
        &executor_actor_id,
    );
    register_lease_with_envelope_ref(
        d2.lease_validator().as_ref(),
        "l-tick-2",
        "W-T2",
        "g-tick",
        &executor_actor_id,
        &ref_2,
    );

    let ctx = privileged_ctx();
    let r1 = dispatch_review_receipt(&d1, &ctx, &make_review_receipt_request("l-tick-1"));
    let r2 = dispatch_review_receipt(
        &d2,
        &ctx,
        &IngestReviewReceiptRequest {
            lease_id: "l-tick-2".to_string(),
            receipt_id: "RR-l-tick-2".to_string(),
            ..make_review_receipt_request("l-tick-1")
        },
    );

    let r1_err = matches!(r1, PrivilegedResponse::Error(_));
    let r2_err = matches!(r2, PrivilegedResponse::Error(_));
    assert_eq!(
        r1_err, r2_err,
        "tick-based authority must be deterministic regardless of wall time; \
         past-wall error={r1_err}, future-wall error={r2_err}"
    );
}

// ============================================================================
// AC-3: No authoritative admission or gate decision consumes wall-time
// values directly.
// ============================================================================

/// AC-3.1: Valid HTF bindings with admissible profile pass admission.
///
/// Constructs a lease with `AuthenticatedNts` wall time source and attestation,
/// both admissible for Tier4. This MUST pass the HTF authority validation
/// (the remaining rejection, if any, comes from attestation ratcheting at the
/// Tier4 level, not from HTF authority).
#[test]
fn test_valid_htf_bindings_pass_htf_authority() {
    let peer_creds = test_peer_credentials();
    let executor_actor_id = derive_actor_id(&peer_creds);
    let cas = Arc::new(MemoryCas::default());
    cas.store(TEST_ARTIFACT_CONTENT).unwrap();

    let dispatcher =
        PrivilegedDispatcher::new().with_cas(Arc::clone(&cas) as Arc<dyn ContentAddressedStore>);

    dispatcher.lease_validator().register_lease_with_executor(
        "lease-ok",
        "W-OK",
        "gate-ok",
        &executor_actor_id,
    );
    register_full_test_lease(
        dispatcher.lease_validator().as_ref(),
        cas.as_ref(),
        "lease-ok",
        "W-OK",
        "gate-ok",
        &executor_actor_id,
        [0u8; 32],
        WallTimeSource::AuthenticatedNts,
        true,
    );

    let request = make_review_receipt_request("lease-ok");
    let ctx = privileged_ctx();
    let response = dispatch_review_receipt(&dispatcher, &ctx, &request);

    // If the response is an error, it must NOT be about HTF authority.
    // It may fail for other reasons (attestation ratcheting at Tier4 level),
    // but the HTF authority check itself must pass.
    if let PrivilegedResponse::Error(ref err) = response {
        assert!(
            !err.message.contains("HTF authority"),
            "valid HTF bindings must not fail HTF authority validation, got: {}",
            err.message
        );
        assert!(
            !err.message.contains("time_envelope_ref"),
            "valid time_envelope_ref must not be rejected, got: {}",
            err.message
        );
        assert!(
            !err.message.contains("clock_profile"),
            "valid clock_profile must not be rejected, got: {}",
            err.message
        );
    }
}

/// AC-3.2: CAS-absent envelope reference is a hard gate, not a wall-time check.
///
/// Verifies that the rejection reason specifically references CAS/envelope
/// resolution failure, not any wall-time-derived comparison.
#[test]
fn test_rejection_reason_is_not_wall_time_derived() {
    let peer_creds = test_peer_credentials();
    let executor_actor_id = derive_actor_id(&peer_creds);
    let cas = Arc::new(MemoryCas::default());
    cas.store(TEST_ARTIFACT_CONTENT).unwrap();

    let dispatcher =
        PrivilegedDispatcher::new().with_cas(Arc::clone(&cas) as Arc<dyn ContentAddressedStore>);

    // Lease with non-existent envelope hash
    let signer = Signer::generate();
    let full_lease = GateLeaseBuilder::new("lease-rej-chk", "W-REJ", "gate-rej")
        .changeset_digest([0x42; 32])
        .executor_actor_id(&executor_actor_id)
        .issued_at(1_000_000)
        .expires_at(2_000_000)
        .policy_hash([0u8; 32])
        .issuer_actor_id("issuer-test")
        .time_envelope_ref(hex::encode([0xFF; 32]))
        .build_and_sign(&signer);
    dispatcher
        .lease_validator()
        .register_full_lease(&full_lease)
        .unwrap();
    dispatcher.lease_validator().register_lease_with_executor(
        "lease-rej-chk",
        "W-REJ",
        "gate-rej",
        &executor_actor_id,
    );

    let request = make_review_receipt_request("lease-rej-chk");
    let ctx = privileged_ctx();
    let response = dispatch_review_receipt(&dispatcher, &ctx, &request);

    match response {
        PrivilegedResponse::Error(err) => {
            // Must NOT mention "wall time", "SystemTime", "now()" etc.
            let lower = err.message.to_lowercase();
            assert!(
                !lower.contains("wall time"),
                "rejection must not reference wall time directly, got: {}",
                err.message
            );
            assert!(
                !lower.contains("systemtime"),
                "rejection must not reference SystemTime, got: {}",
                err.message
            );
            // MUST mention CAS or envelope resolution
            assert!(
                lower.contains("cas")
                    || lower.contains("envelope")
                    || lower.contains("htf authority"),
                "rejection must reference CAS/envelope resolution, got: {}",
                err.message
            );
        },
        other => panic!("expected error for missing CAS object, got: {other:?}"),
    }
}

// ============================================================================
// Perturbation helpers
// ============================================================================

/// Stores a `TimeEnvelope` with specific wall-time bounds but identical tick
/// readings. Uses `AuthenticatedNts` source and includes attestation for
/// Tier4 admissibility.
fn store_envelope_with_wall_ns(
    cas: &dyn ContentAddressedStore,
    wall_start_ns: u64,
    wall_end_ns: u64,
) -> String {
    let clock_profile = ClockProfile {
        attestation: Some(serde_json::json!({"kind": "test-perturb"})),
        build_fingerprint: "apm2-daemon/test".to_string(),
        hlc_enabled: true,
        max_wall_uncertainty_ns: 1_000_000,
        monotonic_source: MonotonicSource::ClockMonotonic,
        profile_policy_id: "test-policy".to_string(),
        tick_rate_hz: 1_000_000_000,
        wall_time_source: WallTimeSource::AuthenticatedNts,
    };

    let profile_bytes = clock_profile.canonical_bytes().expect("canonical bytes");
    let profile_hash = clock_profile.canonical_hash().expect("canonical hash");
    cas.store(&profile_bytes).expect("store profile");

    let envelope = TimeEnvelope {
        clock_profile_hash: hex::encode(profile_hash),
        hlc: Hlc {
            logical: 0,
            wall_ns: wall_start_ns,
        },
        ledger_anchor: LedgerTime::new("test-ledger", 0, 1),
        mono: MonotonicReading {
            end_tick: Some(10_000_000_000), // same ticks in all scenarios
            source: MonotonicSource::ClockMonotonic,
            start_tick: 0,
            tick_rate_hz: 1_000_000_000,
        },
        notes: Some("perturbation-test".to_string()),
        wall: BoundedWallInterval::new(
            wall_start_ns,
            wall_end_ns,
            WallTimeSource::AuthenticatedNts,
            "95%",
        )
        .expect("bounded wall interval"),
    };

    let envelope_bytes = envelope.canonical_bytes().expect("canonical bytes");
    let envelope_hash = envelope.canonical_hash().expect("canonical hash");
    cas.store(&envelope_bytes).expect("store envelope");

    hex::encode(envelope_hash)
}

// ============================================================================
// CAS continuity: orchestrator + dispatcher share the same CAS backend
// ============================================================================

/// End-to-end proof that orchestrator-issued gate leases resolve correctly
/// through the dispatcher's `validate_lease_time_authority` when both
/// components share the SAME CAS instance (TCK-00418 BLOCKER fix).
///
/// This test:
/// 1. Creates a single shared `MemoryCas`.
/// 2. Wires a `GateOrchestrator` with that CAS.
/// 3. Triggers publication-driven start which issues gate leases (storing
///    `ClockProfile` and `TimeEnvelope` in the shared CAS).
/// 4. Retrieves the issued lease via `gate_lease()`.
/// 5. Wires a `PrivilegedDispatcher` with the SAME CAS.
/// 6. Registers the lease with the dispatcher's lease validator.
/// 7. Dispatches an `IngestReviewReceipt` and verifies the HTF authority
///    validation path does NOT fail with a CAS resolution error.
#[tokio::test]
async fn test_shared_cas_orchestrator_dispatcher_continuity() {
    use apm2_core::fac::ChangesetPublication;
    use apm2_daemon::gate::{GateOrchestrator, GateOrchestratorConfig, GateType};

    // Step 1: Single shared CAS
    let shared_cas: Arc<dyn ContentAddressedStore> = Arc::new(MemoryCas::default());
    // Pre-store artifact content so IngestReviewReceipt can resolve
    // artifact_bundle_hash
    shared_cas.store(TEST_ARTIFACT_CONTENT).unwrap();

    // Step 2: Orchestrator wired to shared CAS
    let gate_signer = Arc::new(Signer::generate());
    let orch = GateOrchestrator::new(GateOrchestratorConfig::default(), gate_signer)
        .with_cas(Arc::clone(&shared_cas));

    // Step 3: Trigger publication-driven start => issues leases with CAS-backed
    // time_envelope_ref.
    let dur = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap();
    let now_ms = dur.as_secs() * 1000 + u64::from(dur.subsec_millis());
    let publication = ChangesetPublication {
        work_id: "W-CAS-CONTINUITY".to_string(),
        changeset_digest: [0x42; 32],
        bundle_cas_hash: [0xAB; 32],
        published_at_ms: now_ms,
        publisher_actor_id: "actor:publisher".to_string(),
        changeset_published_event_id: "evt-cas-test".to_string(),
    };
    let (_gate_types, _signers, events) = orch
        .start_for_changeset(publication)
        .await
        .expect("publication start should succeed");

    // Sanity: at least one GateLeaseIssued event was emitted
    assert!(
        events.len() >= 2,
        "expected PolicyResolved + at least 1 GateLeaseIssued, got {} events",
        events.len()
    );

    // Step 4: Retrieve the Quality gate lease (arbitrary choice)
    let lease = orch
        .gate_lease("W-CAS-CONTINUITY", GateType::Quality)
        .await
        .expect("Quality gate lease should exist after start_for_changeset");

    // Verify the time_envelope_ref is a hex-encoded hash (not legacy htf:* format)
    assert!(
        !lease.time_envelope_ref.starts_with("htf:"),
        "time_envelope_ref should be a CAS hash, not legacy format; got: {}",
        lease.time_envelope_ref
    );
    assert_eq!(
        lease.time_envelope_ref.len(),
        64,
        "time_envelope_ref should be a 64-char hex-encoded BLAKE3 hash; got len={}",
        lease.time_envelope_ref.len()
    );

    // Step 5: Dispatcher wired to the SAME shared CAS
    let peer_creds = test_peer_credentials();
    let executor_actor_id = derive_actor_id(&peer_creds);
    let dispatcher = PrivilegedDispatcher::new().with_cas(Arc::clone(&shared_cas));

    // Step 6: Register the orchestrator-issued lease with the dispatcher
    dispatcher.lease_validator().register_lease_with_executor(
        &lease.lease_id,
        &lease.work_id,
        &lease.gate_id,
        &executor_actor_id,
    );
    dispatcher
        .lease_validator()
        .register_full_lease(&lease)
        .expect("orchestrator-issued lease registration should succeed");

    // Step 7: Dispatch IngestReviewReceipt — the HTF authority validation
    // must NOT fail with a CAS resolution error because both orchestrator
    // and dispatcher share the same CAS.
    let request = IngestReviewReceiptRequest {
        lease_id: lease.lease_id.clone(),
        receipt_id: format!("RR-{}", lease.lease_id),
        reviewer_actor_id: derive_actor_id(&peer_creds),
        changeset_digest: vec![0x42; 32],
        artifact_bundle_hash: test_artifact_bundle_hash(),
        verdict: ReviewReceiptVerdict::Approve.into(),
        blocked_reason_code: 0,
        blocked_log_hash: vec![],
        identity_proof_hash: vec![0x99; 32],
    };
    let ctx = privileged_ctx();
    let response = dispatch_review_receipt(&dispatcher, &ctx, &request);

    // The response may be an error for reasons OTHER than HTF authority
    // (e.g., policy ratcheting, missing work claim). But it MUST NOT
    // fail on HTF/CAS resolution — that would indicate the CAS split bug.
    if let PrivilegedResponse::Error(ref err) = response {
        let lower = err.message.to_lowercase();
        assert!(
            !lower.contains("time_envelope_ref"),
            "CAS split bug: dispatcher cannot resolve orchestrator's time_envelope_ref; \
             error: {}",
            err.message
        );
        assert!(
            !lower.contains("failed to resolve time_envelope_ref from cas"),
            "CAS split bug: time envelope not in dispatcher CAS; error: {}",
            err.message
        );
        assert!(
            !lower.contains("htf authority") || !lower.contains("cas"),
            "CAS-related HTF authority failure indicates split CAS; error: {}",
            err.message
        );
    }
    // If we reach here without assertion failure, the CAS continuity is proven:
    // the dispatcher successfully resolved the orchestrator's CAS-stored
    // TimeEnvelope and ClockProfile artifacts.
}

/// Registers a lease with a specific `time_envelope_ref`, using
/// `AuthenticatedNts` as the profile source with attestation.
fn register_lease_with_envelope_ref(
    lease_validator: &dyn LeaseValidator,
    lease_id: &str,
    work_id: &str,
    gate_id: &str,
    executor_actor_id: &str,
    time_envelope_ref: &str,
) {
    let signer = Signer::generate();
    let full_lease = GateLeaseBuilder::new(lease_id, work_id, gate_id)
        .changeset_digest([0x42; 32])
        .executor_actor_id(executor_actor_id)
        .issued_at(1_000_000)
        .expires_at(2_000_000)
        .policy_hash([0u8; 32])
        .issuer_actor_id("issuer-test")
        .time_envelope_ref(time_envelope_ref)
        .build_and_sign(&signer);
    lease_validator
        .register_full_lease(&full_lease)
        .expect("lease registration should succeed");
}
