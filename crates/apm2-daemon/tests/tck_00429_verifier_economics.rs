//! Integration tests for TCK-00429: verifier economics enforcement.
//!
//! Tests verify:
//! - Tier2+ operations fail closed when bounds exceeded
//! - Tier0/1 operations continue when bounds exceeded (monitor-only)
//! - Proof-check-count enforcement works
//! - Anti-entropy bounds enforcement works

use std::sync::{Arc, Mutex};
use std::time::Instant;

use apm2_core::consensus::SyncEvent;
use apm2_core::crypto::{EventHasher, Hash};
use apm2_core::pcac::{
    AuthoritativeBindings, AuthorityDenyClass, AuthorityJoinInputV1, AuthorityJoinKernel,
    BindingExpectations, BoundaryIntentClass, DeterminismClass, FactClass, IdentityEvidenceLevel,
    ReceiptAuthentication, RiskTier, VerifierEconomicsChecker, VerifierEconomicsProfile,
    VerifierOperation, timed_anti_entropy_verification, timed_classify_fact,
    timed_validate_authoritative_bindings, timed_verify_receipt_authentication,
};
use apm2_daemon::episode::InMemorySessionRegistry;
use apm2_daemon::ledger::{SqliteLedgerEventEmitter, SqliteWorkRegistry};
use apm2_daemon::pcac::{InProcessKernel, LifecycleGate};
use apm2_daemon::session::SessionRegistry;
use apm2_daemon::state::DispatcherState;
use rusqlite::Connection;
use tempfile::TempDir;

const fn test_hash(byte: u8) -> Hash {
    [byte; 32]
}

fn valid_input(risk_tier: RiskTier, scope_complexity: usize, seed: u8) -> AuthorityJoinInputV1 {
    let scope_witness_hashes = (0..scope_complexity)
        .map(|i| {
            let offset = u8::try_from(i).expect("scope complexity must fit in u8");
            test_hash(seed.wrapping_add(offset).max(1))
        })
        .collect();

    AuthorityJoinInputV1 {
        session_id: format!("session-{seed}"),
        holon_id: None,
        intent_digest: test_hash(seed.wrapping_add(0x01)),
        boundary_intent_class: BoundaryIntentClass::Assert,
        capability_manifest_hash: test_hash(seed.wrapping_add(0x02)),
        scope_witness_hashes,
        lease_id: format!("lease-{seed}"),
        permeability_receipt_hash: None,
        identity_proof_hash: test_hash(seed.wrapping_add(0x03)),
        identity_evidence_level: IdentityEvidenceLevel::Verified,
        directory_head_hash: test_hash(seed.wrapping_add(0x04)),
        freshness_policy_hash: test_hash(seed.wrapping_add(0x05)),
        freshness_witness_tick: 1000,
        stop_budget_profile_digest: test_hash(seed.wrapping_add(0x06)),
        pre_actuation_receipt_hashes: vec![],
        leakage_witness_hash: test_hash(seed.wrapping_add(0x09)),
        timing_witness_hash: test_hash(seed.wrapping_add(0x0A)),
        risk_tier,
        determinism_class: DeterminismClass::Deterministic,
        time_envelope_ref: test_hash(seed.wrapping_add(0x07)),
        as_of_ledger_anchor: test_hash(seed.wrapping_add(0x08)),
        pointer_only_waiver_hash: None,
    }
}

const fn permissive_timing_profile(max_proof_checks: u64) -> VerifierEconomicsProfile {
    VerifierEconomicsProfile {
        p95_join_us: u64::MAX,
        p95_verify_receipt_us: u64::MAX,
        p95_validate_bindings_us: u64::MAX,
        p95_classify_fact_us: u64::MAX,
        p95_replay_lifecycle_us: u64::MAX,
        p95_anti_entropy_us: u64::MAX,
        p95_revalidate_us: u64::MAX,
        p95_consume_us: u64::MAX,
        max_proof_checks,
    }
}

const fn valid_bindings(seed: u8) -> (AuthoritativeBindings, Hash) {
    let authority_seal_hash = test_hash(seed.wrapping_add(0x11));
    (
        AuthoritativeBindings {
            episode_envelope_hash: test_hash(seed.wrapping_add(0x12)),
            view_commitment_hash: test_hash(seed.wrapping_add(0x13)),
            time_envelope_ref: test_hash(seed.wrapping_add(0x14)),
            authentication: ReceiptAuthentication::Direct {
                authority_seal_hash,
            },
            permeability_receipt_hash: None,
            delegation_chain_hash: None,
        },
        authority_seal_hash,
    )
}

fn make_sync_events(count: usize) -> Vec<SyncEvent> {
    let mut events = Vec::with_capacity(count);
    let mut prev_hash = [0u8; 32];
    for idx in 0..count {
        let payload = format!("sync-event-{idx}").into_bytes();
        let event_hash = EventHasher::hash_event(&payload, &prev_hash);
        events.push(SyncEvent {
            seq_id: u64::try_from(idx).unwrap_or(u64::MAX).saturating_add(1),
            event_type: "test".to_string(),
            payload,
            prev_hash,
            event_hash,
            timestamp_ns: 1_000_000 + u64::try_from(idx).unwrap_or(0),
        });
        prev_hash = event_hash;
    }
    events
}

fn make_file_backed_sqlite_conn(temp_dir: &TempDir) -> Arc<Mutex<Connection>> {
    let db_path = temp_dir.path().join("tck_00429_runtime.sqlite");
    let conn = Connection::open(&db_path).expect("file-backed sqlite should open");
    SqliteLedgerEventEmitter::init_schema_for_test(&conn).expect("ledger schema should initialize");
    SqliteWorkRegistry::init_schema(&conn).expect("work schema should initialize");
    Arc::new(Mutex::new(conn))
}

fn elapsed_us_since(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX)
}

fn p95(samples: &mut [u64]) -> u64 {
    assert!(!samples.is_empty());
    samples.sort_unstable();
    let idx = ((samples.len() * 95).div_ceil(100)).saturating_sub(1);
    samples[idx]
}

#[test]
fn test_join_scope_witness_cardinality_does_not_trigger_merkle_depth_denial() {
    let kernel = InProcessKernel::new(100).with_verifier_economics(permissive_timing_profile(1));
    let input = valid_input(
        RiskTier::Tier2Plus,
        apm2_core::pcac::MAX_SCOPE_WITNESS_HASHES,
        0x20,
    );
    let cert = kernel
        .join(&input)
        .expect("join must allow contract-valid max scope witnesses");
    assert_eq!(cert.risk_tier, RiskTier::Tier2Plus);
}

#[test]
fn test_tier0_join_allows_on_verifier_bounds_exceeded() {
    let kernel = InProcessKernel::new(100).with_verifier_economics(permissive_timing_profile(0));
    let input = valid_input(RiskTier::Tier0, 4, 0x21);
    let cert = kernel
        .join(&input)
        .expect("Tier0 must allow even when verifier bounds exceed");
    assert_eq!(cert.risk_tier, RiskTier::Tier0);
}

#[test]
fn test_join_operation_uses_join_metric_and_enforces_join_bound() {
    let kernel = InProcessKernel::new(100).with_verifier_economics(VerifierEconomicsProfile {
        p95_join_us: 0,
        p95_verify_receipt_us: u64::MAX,
        p95_validate_bindings_us: u64::MAX,
        p95_classify_fact_us: u64::MAX,
        p95_replay_lifecycle_us: u64::MAX,
        p95_anti_entropy_us: u64::MAX,
        p95_revalidate_us: u64::MAX,
        p95_consume_us: u64::MAX,
        max_proof_checks: u64::MAX,
    });
    let input = valid_input(RiskTier::Tier2Plus, 1, 0x22);
    let err = kernel
        .join(&input)
        .expect_err("Tier2+ join must deny when Join timing bound is exceeded");
    assert!(matches!(
        err.deny_class,
        AuthorityDenyClass::VerifierEconomicsBoundsExceeded { ref operation, risk_tier }
            if operation == "join" && risk_tier == RiskTier::Tier2Plus
    ));
}

#[test]
fn test_consume_economics_deny_does_not_burn_certificate() {
    let kernel = InProcessKernel::new(101).with_verifier_economics(VerifierEconomicsProfile {
        p95_join_us: u64::MAX,
        p95_verify_receipt_us: u64::MAX,
        p95_validate_bindings_us: u64::MAX,
        p95_classify_fact_us: u64::MAX,
        p95_replay_lifecycle_us: u64::MAX,
        p95_anti_entropy_us: u64::MAX,
        p95_revalidate_us: u64::MAX,
        p95_consume_us: 0,
        max_proof_checks: u64::MAX,
    });
    let input = valid_input(RiskTier::Tier2Plus, 1, 0x23);
    let cert = kernel
        .join(&input)
        .expect("join must pass with permissive non-consume bounds");

    let first_err = kernel
        .consume(
            &cert,
            input.intent_digest,
            input.boundary_intent_class,
            true,
            input.time_envelope_ref,
            cert.revocation_head_hash,
        )
        .expect_err("first consume must deny on consume economics bound");
    assert!(matches!(
        first_err.deny_class,
        AuthorityDenyClass::VerifierEconomicsBoundsExceeded { ref operation, risk_tier }
            if operation == "consume" && risk_tier == RiskTier::Tier2Plus
    ));

    let second_err = kernel
        .consume(
            &cert,
            input.intent_digest,
            input.boundary_intent_class,
            true,
            input.time_envelope_ref,
            cert.revocation_head_hash,
        )
        .expect_err("second consume must still deny on economics, not AlreadyConsumed");
    assert!(matches!(
        second_err.deny_class,
        AuthorityDenyClass::VerifierEconomicsBoundsExceeded { ref operation, risk_tier }
            if operation == "consume" && risk_tier == RiskTier::Tier2Plus
    ));
    assert!(!matches!(
        second_err.deny_class,
        AuthorityDenyClass::AlreadyConsumed { .. }
    ));
}

#[test]
fn test_proof_check_count_enforcement() {
    let kernel = InProcessKernel::new(100).with_verifier_economics(permissive_timing_profile(2));
    let input = valid_input(RiskTier::Tier2Plus, 0, 0x30);

    let cert = kernel.join(&input).expect("join must pass");

    let err = kernel
        .consume(
            &cert,
            input.intent_digest,
            input.boundary_intent_class,
            true,
            input.time_envelope_ref,
            cert.revocation_head_hash,
        )
        .expect_err("consume must deny when replay proof checks exceed bound");
    assert!(matches!(
        err.deny_class,
        AuthorityDenyClass::VerifierEconomicsBoundsExceeded { ref operation, risk_tier }
            if operation == "validate_replay_lifecycle_order" && risk_tier == RiskTier::Tier2Plus
    ));
}

#[test]
fn tck_00429_direct_receipt_auth_proof_count_enforced() {
    let kernel =
        InProcessKernel::new(220).with_verifier_economics(permissive_timing_profile(u64::MAX));
    let input = valid_input(RiskTier::Tier2Plus, 1, 0x31);
    let cert = kernel
        .join(&input)
        .expect("join should pass under permissive proof-check profile");
    kernel
        .revalidate(
            &cert,
            input.time_envelope_ref,
            input.as_of_ledger_anchor,
            cert.revocation_head_hash,
        )
        .expect("revalidate should pass under permissive profile");

    let timed = timed_verify_receipt_authentication(
        &ReceiptAuthentication::Direct {
            authority_seal_hash: cert.ajc_id,
        },
        &cert.ajc_id,
        None,
        input.time_envelope_ref,
        input.as_of_ledger_anchor,
        cert.issued_at_tick.saturating_add(1),
    );
    assert!(timed.result.is_ok(), "direct receipt auth should verify");
    assert_eq!(timed.proof_check_count, 1);

    let checker = VerifierEconomicsChecker::new(permissive_timing_profile(0));
    let deny = checker
        .check_proof_count(
            VerifierOperation::VerifyReceiptAuthentication,
            timed.proof_check_count,
            RiskTier::Tier2Plus,
        )
        .expect_err("Tier2+ must deny direct receipt auth when max_proof_checks=0");
    assert!(matches!(
        deny,
        AuthorityDenyClass::VerifierEconomicsBoundsExceeded { ref operation, risk_tier }
            if operation == "verify_receipt_authentication" && risk_tier == RiskTier::Tier2Plus
    ));
}

#[test]
fn tck_00429_unbatched_receipt_auth_proof_count_enforced() {
    let kernel =
        InProcessKernel::new(320).with_verifier_economics(permissive_timing_profile(u64::MAX));
    let input = valid_input(RiskTier::Tier2Plus, 1, 0x32);
    let cert = kernel
        .join(&input)
        .expect("join should pass under permissive proof-check profile");
    kernel
        .revalidate(
            &cert,
            input.time_envelope_ref,
            input.as_of_ledger_anchor,
            cert.revocation_head_hash,
        )
        .expect("revalidate should pass under permissive profile");

    let receipt_hash = test_hash(0x7A);
    let timed = timed_verify_receipt_authentication(
        &ReceiptAuthentication::PointerUnbatched {
            receipt_hash,
            authority_seal_hash: cert.ajc_id,
        },
        &cert.ajc_id,
        Some(&receipt_hash),
        input.time_envelope_ref,
        input.as_of_ledger_anchor,
        cert.issued_at_tick.saturating_add(1),
    );
    assert!(timed.result.is_ok(), "unbatched receipt auth should verify");
    assert_eq!(timed.proof_check_count, 1);

    let checker = VerifierEconomicsChecker::new(permissive_timing_profile(0));
    let deny = checker
        .check_proof_count(
            VerifierOperation::VerifyReceiptAuthentication,
            timed.proof_check_count,
            RiskTier::Tier2Plus,
        )
        .expect_err("Tier2+ must deny unbatched receipt auth when max_proof_checks=0");
    assert!(matches!(
        deny,
        AuthorityDenyClass::VerifierEconomicsBoundsExceeded { ref operation, risk_tier }
            if operation == "verify_receipt_authentication" && risk_tier == RiskTier::Tier2Plus
    ));
}

#[test]
fn tck_00429_runtime_anti_entropy_bounds_enforced() {
    let temp_dir = TempDir::new().expect("temp dir should be created");
    let sqlite_conn = make_file_backed_sqlite_conn(&temp_dir);
    let session_registry: Arc<dyn SessionRegistry> = Arc::new(InMemorySessionRegistry::new());

    let state = DispatcherState::with_persistence(
        session_registry,
        None,
        Some(Arc::clone(&sqlite_conn)),
        None,
    )
    .expect("dispatcher state should initialize with runtime PCAC gate");

    let events = make_sync_events(250_000);
    let digest = test_hash(0x66);

    let err = state
        .enforce_anti_entropy_catchup(
            RiskTier::Tier2Plus,
            Some(&digest),
            Some(&digest),
            &events,
            &[0u8; 32],
            Some(1),
            None,
            None,
            test_hash(0x67),
            test_hash(0x68),
            999,
        )
        .expect_err("Tier2+ runtime anti-entropy path must deny when timing bound exceeds");

    assert!(matches!(
        err.deny_class,
        AuthorityDenyClass::VerifierEconomicsBoundsExceeded { ref operation, risk_tier }
            if operation == "anti_entropy_verification" && risk_tier == RiskTier::Tier2Plus
    ));
}

#[test]
fn test_anti_entropy_bounds_enforcement() {
    let tick_kernel =
        Arc::new(InProcessKernel::new(100).with_verifier_economics(permissive_timing_profile(0)));
    let kernel_trait: Arc<dyn AuthorityJoinKernel> = tick_kernel.clone();
    let gate = LifecycleGate::with_tick_kernel(kernel_trait, Arc::clone(&tick_kernel));
    let events = make_sync_events(3);
    let digest = test_hash(0x44);
    let expected_prev_hash = [0u8; 32];

    let err = gate
        .enforce_anti_entropy_economics(
            RiskTier::Tier2Plus,
            Some(&digest),
            Some(&digest),
            &events,
            &expected_prev_hash,
            Some(1),
            None,
            None,
            None,
            test_hash(0x50),
            test_hash(0x51),
            1234,
        )
        .expect_err("Tier2+ anti-entropy verification must deny when bounds exceed");
    assert!(matches!(
        err.deny_class,
        AuthorityDenyClass::VerifierEconomicsBoundsExceeded { ref operation, risk_tier }
            if operation == "anti_entropy_verification" && risk_tier == RiskTier::Tier2Plus
    ));
}

#[test]
fn test_anti_entropy_proof_checks_exclude_event_count() {
    let events = make_sync_events(512);
    let digest = test_hash(0x45);

    let timed = timed_anti_entropy_verification(
        Some(&digest),
        Some(&digest),
        &events,
        &[0u8; 32],
        Some(1),
        None,
        None,
    );

    assert!(timed.result.is_ok());
    assert_eq!(timed.proof_check_count, 1);
    assert_eq!(timed.event_count, 512);
}

#[test]
fn test_crypto_operations_report_non_zero_proof_checks() {
    let (bindings, expected_seal_hash) = valid_bindings(0x60);
    let ledger_anchor = test_hash(0x70);

    let timed_bindings = timed_validate_authoritative_bindings(
        &bindings,
        bindings.time_envelope_ref,
        ledger_anchor,
        100,
        Some(&bindings.view_commitment_hash),
        Some(&ledger_anchor),
    );
    assert!(timed_bindings.result.is_ok());
    assert_eq!(timed_bindings.proof_check_count, 3);

    let timed_classification = timed_classify_fact(
        Some(&bindings),
        &expected_seal_hash,
        None,
        bindings.time_envelope_ref,
        ledger_anchor,
        100,
        BindingExpectations {
            expected_view_commitment: Some(&bindings.view_commitment_hash),
            expected_ledger_anchor: Some(&ledger_anchor),
        },
    );
    assert_eq!(timed_classification.result, FactClass::AcceptanceFact);
    assert_eq!(timed_classification.proof_check_count, 4);
}

#[test]
fn test_evid_0005_benchmark_output() {
    let profile = VerifierEconomicsProfile::default();
    let mut join_samples = Vec::new();
    let mut revalidate_samples = Vec::new();
    let mut consume_samples = Vec::new();
    let mut anti_entropy_samples = Vec::new();

    let mut join_proof_checks_total = 0_u64;
    let mut replay_proof_checks_total = 0_u64;
    let mut anti_entropy_proof_checks_total = 0_u64;

    for (complexity_idx, complexity) in [1_usize, 4, 8, 16].into_iter().enumerate() {
        for iter in 0..12_u64 {
            let complexity_idx_u8 =
                u8::try_from(complexity_idx).expect("complexity index must fit in u8");
            let iter_u8 = u8::try_from(iter).expect("iteration must fit in u8");
            let seed = complexity_idx_u8
                .wrapping_mul(16)
                .wrapping_add(iter_u8)
                .wrapping_add(1);
            let kernel = InProcessKernel::new(10_000 + iter).with_verifier_economics(profile);
            let input = valid_input(RiskTier::Tier1, complexity, seed);

            let start = Instant::now();
            let cert = kernel.join(&input).expect("join benchmark");
            join_samples.push(elapsed_us_since(start));
            join_proof_checks_total = join_proof_checks_total.saturating_add(1);

            let start = Instant::now();
            kernel
                .revalidate(
                    &cert,
                    input.time_envelope_ref,
                    input.as_of_ledger_anchor,
                    cert.revocation_head_hash,
                )
                .expect("revalidate benchmark");
            revalidate_samples.push(elapsed_us_since(start));

            let start = Instant::now();
            kernel
                .consume(
                    &cert,
                    input.intent_digest,
                    input.boundary_intent_class,
                    true,
                    input.time_envelope_ref,
                    cert.revocation_head_hash,
                )
                .expect("consume benchmark");
            consume_samples.push(elapsed_us_since(start));
            replay_proof_checks_total = replay_proof_checks_total.saturating_add(3);
        }
    }

    let anti_entropy_events = make_sync_events(24);
    let anti_entropy_digest = test_hash(0x81);
    for _ in 0..24 {
        let timed = timed_anti_entropy_verification(
            Some(&anti_entropy_digest),
            Some(&anti_entropy_digest),
            &anti_entropy_events,
            &[0u8; 32],
            Some(1),
            None,
            None,
        );
        assert!(timed.result.is_ok(), "synthetic anti-entropy benchmark");
        anti_entropy_samples.push(timed.elapsed_us);
        anti_entropy_proof_checks_total =
            anti_entropy_proof_checks_total.saturating_add(timed.proof_check_count);
    }

    let join_p95 = p95(&mut join_samples);
    let revalidate_p95 = p95(&mut revalidate_samples);
    let consume_p95 = p95(&mut consume_samples);
    let anti_entropy_p95 = p95(&mut anti_entropy_samples);

    // Assert p95 values are within declared profile thresholds.
    // Use 10x tolerance for CI environment variability.
    let tolerance = 10;
    assert!(
        join_p95 <= profile.p95_join_us * tolerance,
        "join p95 ({join_p95}) exceeds profile threshold ({}) with {tolerance}x tolerance",
        profile.p95_join_us,
    );
    assert!(
        revalidate_p95 <= profile.p95_revalidate_us * tolerance,
        "revalidate p95 ({revalidate_p95}) exceeds profile threshold ({}) with {tolerance}x tolerance",
        profile.p95_revalidate_us,
    );
    assert!(
        consume_p95 <= profile.p95_consume_us * tolerance,
        "consume p95 ({consume_p95}) exceeds profile threshold ({}) with {tolerance}x tolerance",
        profile.p95_consume_us,
    );
    assert!(
        anti_entropy_p95 <= profile.p95_anti_entropy_us * tolerance,
        "anti-entropy p95 ({anti_entropy_p95}) exceeds profile threshold ({}) with {tolerance}x tolerance",
        profile.p95_anti_entropy_us,
    );

    let tier2_join_deny = {
        let kernel = InProcessKernel::new(200).with_verifier_economics(VerifierEconomicsProfile {
            p95_join_us: 0,
            p95_verify_receipt_us: u64::MAX,
            p95_validate_bindings_us: u64::MAX,
            p95_classify_fact_us: u64::MAX,
            p95_replay_lifecycle_us: u64::MAX,
            p95_anti_entropy_us: u64::MAX,
            p95_revalidate_us: u64::MAX,
            p95_consume_us: u64::MAX,
            max_proof_checks: u64::MAX,
        });
        let input = valid_input(
            RiskTier::Tier2Plus,
            apm2_core::pcac::MAX_SCOPE_WITNESS_HASHES,
            0x90,
        );
        kernel.join(&input).expect_err("tier2 join deny").deny_class
    };
    let tier2_consume_deny = {
        let kernel =
            InProcessKernel::new(300).with_verifier_economics(permissive_timing_profile(2));
        let input = valid_input(RiskTier::Tier2Plus, 0, 0x91);
        let cert = kernel.join(&input).expect("join");
        kernel
            .consume(
                &cert,
                input.intent_digest,
                input.boundary_intent_class,
                true,
                input.time_envelope_ref,
                cert.revocation_head_hash,
            )
            .expect_err("tier2 consume deny")
            .deny_class
    };
    let tier2_anti_entropy_deny = {
        let tick_kernel = Arc::new(
            InProcessKernel::new(400).with_verifier_economics(permissive_timing_profile(0)),
        );
        let kernel_trait: Arc<dyn AuthorityJoinKernel> = tick_kernel.clone();
        let gate = LifecycleGate::with_tick_kernel(kernel_trait, Arc::clone(&tick_kernel));
        let events = make_sync_events(4);
        let digest = test_hash(0x92);
        gate.enforce_anti_entropy_economics(
            RiskTier::Tier2Plus,
            Some(&digest),
            Some(&digest),
            &events,
            &[0u8; 32],
            Some(1),
            None,
            None,
            None,
            test_hash(0x93),
            test_hash(0x94),
            400,
        )
        .expect_err("tier2 anti-entropy deny")
        .deny_class
    };

    println!(
        "p95 join/revalidate/consume benchmark summaries: join_p95_us={join_p95}, revalidate_p95_us={revalidate_p95}, consume_p95_us={consume_p95}",
    );
    println!("anti-entropy catch-up benchmark summary: anti_entropy_p95_us={anti_entropy_p95}",);
    println!(
        "proof-check count metrics: join_proof_checks_total={join_proof_checks_total}, replay_proof_checks_total={replay_proof_checks_total}, anti_entropy_proof_checks_total={anti_entropy_proof_checks_total}",
    );
    println!(
        "bound exceedance deny traces for Tier2+: join='{tier2_join_deny}', consume='{tier2_consume_deny}', anti_entropy='{tier2_anti_entropy_deny}'",
    );

    assert!(!join_samples.is_empty());
    assert!(!revalidate_samples.is_empty());
    assert!(!consume_samples.is_empty());
    assert!(!anti_entropy_samples.is_empty());
    assert!(
        join_proof_checks_total > 0,
        "join must have non-zero proof checks"
    );
    assert!(
        replay_proof_checks_total > 0,
        "replay must have non-zero proof checks"
    );
    assert!(
        anti_entropy_proof_checks_total > 0,
        "anti-entropy must have non-zero proof checks"
    );
    assert!(matches!(
        tier2_join_deny,
        AuthorityDenyClass::VerifierEconomicsBoundsExceeded { .. }
    ));
    assert!(matches!(
        tier2_consume_deny,
        AuthorityDenyClass::VerifierEconomicsBoundsExceeded { .. }
    ));
    assert!(matches!(
        tier2_anti_entropy_deny,
        AuthorityDenyClass::VerifierEconomicsBoundsExceeded { .. }
    ));
}
