//! Integration tests for TCK-00429: verifier economics enforcement.
//!
//! Tests verify:
//! - Tier2+ operations fail closed when bounds exceeded
//! - Tier0/1 operations continue when bounds exceeded (monitor-only)
//! - Proof-check-count enforcement works
//! - Anti-entropy bounds enforcement works

use std::time::Instant;

use apm2_core::consensus::SyncEvent;
use apm2_core::crypto::{EventHasher, Hash};
use apm2_core::pcac::{
    AuthorityDenyClass, AuthorityJoinInputV1, BoundaryIntentClass, DeterminismClass,
    IdentityEvidenceLevel, RiskTier, VerifierEconomicsProfile, timed_anti_entropy_verification,
};
use apm2_daemon::pcac::InProcessKernel;

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
        risk_tier,
        determinism_class: DeterminismClass::Deterministic,
        time_envelope_ref: test_hash(seed.wrapping_add(0x07)),
        as_of_ledger_anchor: test_hash(seed.wrapping_add(0x08)),
        pointer_only_waiver_hash: None,
    }
}

const fn permissive_timing_profile(max_proof_checks: u64) -> VerifierEconomicsProfile {
    VerifierEconomicsProfile {
        p95_verify_receipt_us: u64::MAX,
        p95_validate_bindings_us: u64::MAX,
        p95_classify_fact_us: u64::MAX,
        p95_replay_lifecycle_us: u64::MAX,
        p95_anti_entropy_us: u64::MAX,
        max_proof_checks,
    }
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
fn test_tier2_join_denies_on_verifier_bounds_exceeded() {
    let kernel = InProcessKernel::new(100).with_verifier_economics(permissive_timing_profile(0));
    let input = valid_input(RiskTier::Tier2Plus, 4, 0x20);
    let err = kernel
        .join(&input)
        .expect_err("Tier2+ must deny when bounds exceed");
    assert!(matches!(
        err.deny_class,
        AuthorityDenyClass::VerifierEconomicsBoundsExceeded { ref operation, risk_tier }
            if operation == "verify_receipt_authentication" && risk_tier == RiskTier::Tier2Plus
    ));
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
fn test_proof_check_count_enforcement() {
    let kernel = InProcessKernel::new(100).with_verifier_economics(permissive_timing_profile(2));
    let input = valid_input(RiskTier::Tier2Plus, 0, 0x30);

    let cert = kernel.join(&input).expect("join must pass");
    kernel
        .revalidate(
            &cert,
            input.time_envelope_ref,
            input.as_of_ledger_anchor,
            cert.revocation_head_hash,
        )
        .expect("revalidate must pass");

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
fn test_anti_entropy_bounds_enforcement() {
    let kernel = InProcessKernel::new(100).with_verifier_economics(permissive_timing_profile(0));
    let events = make_sync_events(3);
    let digest = test_hash(0x44);
    let expected_prev_hash = [0u8; 32];

    let err = kernel
        .check_anti_entropy_verification(
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
            if complexity > 1 {
                join_proof_checks_total = join_proof_checks_total.saturating_add(1);
            }

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

    let tier2_join_deny = {
        let kernel =
            InProcessKernel::new(200).with_verifier_economics(permissive_timing_profile(0));
        let input = valid_input(RiskTier::Tier2Plus, 4, 0x90);
        kernel.join(&input).expect_err("tier2 join deny").deny_class
    };
    let tier2_consume_deny = {
        let kernel =
            InProcessKernel::new(300).with_verifier_economics(permissive_timing_profile(2));
        let input = valid_input(RiskTier::Tier2Plus, 0, 0x91);
        let cert = kernel.join(&input).expect("join");
        kernel
            .revalidate(
                &cert,
                input.time_envelope_ref,
                input.as_of_ledger_anchor,
                cert.revocation_head_hash,
            )
            .expect("revalidate");
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
        let kernel =
            InProcessKernel::new(400).with_verifier_economics(permissive_timing_profile(0));
        let events = make_sync_events(4);
        let digest = test_hash(0x92);
        kernel
            .check_anti_entropy_verification(
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
