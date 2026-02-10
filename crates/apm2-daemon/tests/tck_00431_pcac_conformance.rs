//! TCK-00431: PCAC conformance and falsification suite (RFC-0027 §16).
//!
//! Coverage focus:
//! - Section 16 falsification criteria hit mapping to non-admissible outcomes
//! - Crash-replay fault injection (missing durable consume record)
//! - Duplicate consume denial guarantees
//! - Tier2+ stale/ambiguous freshness denial probes
//! - Tier2+ sovereignty uncertainty denial probes
//!
//! Evidence artifact: EVID-0010

use apm2_core::crypto::Hash;
use apm2_core::pcac::{
    AuthorityDenyClass, AuthorityJoinInputV1, AuthorityJoinKernel, AutonomyCeiling,
    BoundaryIntentClass, DeterminismClass, FreezeAction, IdentityEvidenceLevel, LifecycleStage,
    PcacPolicyKnobs, ReplayLifecycleEntry, RiskTier, validate_replay_lifecycle_order,
};
use apm2_daemon::pcac::{
    DurableKernel, FileBackedConsumeIndex, InProcessKernel, SovereigntyChecker, SovereigntyState,
};
use tempfile::TempDir;

const fn test_hash(byte: u8) -> Hash {
    [byte; 32]
}

fn authoritative_input(seed: u8, risk_tier: RiskTier) -> AuthorityJoinInputV1 {
    AuthorityJoinInputV1 {
        session_id: format!("session-{seed}"),
        holon_id: None,
        intent_digest: test_hash(seed.wrapping_add(1)),
        boundary_intent_class: BoundaryIntentClass::Assert,
        capability_manifest_hash: test_hash(seed.wrapping_add(2)),
        scope_witness_hashes: vec![test_hash(seed.wrapping_add(3))],
        lease_id: format!("lease-{seed}"),
        permeability_receipt_hash: None,
        identity_proof_hash: test_hash(seed.wrapping_add(4)),
        identity_evidence_level: IdentityEvidenceLevel::Verified,
        directory_head_hash: test_hash(seed.wrapping_add(5)),
        freshness_policy_hash: test_hash(seed.wrapping_add(6)),
        freshness_witness_tick: 1_000,
        stop_budget_profile_digest: test_hash(seed.wrapping_add(7)),
        pre_actuation_receipt_hashes: vec![],
        risk_tier,
        determinism_class: DeterminismClass::Deterministic,
        time_envelope_ref: test_hash(seed.wrapping_add(8)),
        as_of_ledger_anchor: test_hash(seed.wrapping_add(9)),
        pointer_only_waiver_hash: None,
    }
}

fn strict_policy() -> PcacPolicyKnobs {
    PcacPolicyKnobs::default()
}

fn is_full_coverage(value: f64) -> bool {
    (value - 1.0).abs() <= f64::EPSILON
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AdmissionOutcome {
    Admissible,
    NonAdmissible,
}

#[derive(Debug, Clone, Copy)]
struct PcacEvidenceSummary {
    missing_lifecycle_stage_count: u64,
    ordered_receipt_chain_pass: bool,
    duplicate_consume_accept_count: u64,
    durable_consume_record_coverage: f64,
    tier2plus_stale_allow_count: u64,
    freshness_unknown_state_count: u64,
    authoritative_outcomes_with_full_replay_contract: f64,
    missing_selector_count: u64,
    verifier_economics_regression_count: u64,
    crash_replay_missing_durable_record_accept_count: u64,
    unknown_state_count: u64,
}

impl PcacEvidenceSummary {
    const fn admissible_baseline() -> Self {
        Self {
            missing_lifecycle_stage_count: 0,
            ordered_receipt_chain_pass: true,
            duplicate_consume_accept_count: 0,
            durable_consume_record_coverage: 1.0,
            tier2plus_stale_allow_count: 0,
            freshness_unknown_state_count: 0,
            authoritative_outcomes_with_full_replay_contract: 1.0,
            missing_selector_count: 0,
            verifier_economics_regression_count: 0,
            crash_replay_missing_durable_record_accept_count: 0,
            unknown_state_count: 0,
        }
    }

    fn objective_outcome(self) -> AdmissionOutcome {
        let admissible = self.missing_lifecycle_stage_count == 0
            && self.ordered_receipt_chain_pass
            && self.duplicate_consume_accept_count == 0
            && is_full_coverage(self.durable_consume_record_coverage)
            && self.tier2plus_stale_allow_count == 0
            && self.freshness_unknown_state_count == 0
            && is_full_coverage(self.authoritative_outcomes_with_full_replay_contract)
            && self.missing_selector_count == 0
            && self.verifier_economics_regression_count == 0
            && self.crash_replay_missing_durable_record_accept_count == 0
            && self.unknown_state_count == 0;

        if admissible {
            AdmissionOutcome::Admissible
        } else {
            AdmissionOutcome::NonAdmissible
        }
    }

    fn gate_outcome(self) -> AdmissionOutcome {
        let lifecycle_gate_passes =
            self.missing_lifecycle_stage_count == 0 && self.unknown_state_count == 0;
        let single_consume_gate_passes = self.duplicate_consume_accept_count == 0
            && is_full_coverage(self.durable_consume_record_coverage)
            && self.unknown_state_count == 0;
        let freshness_gate_passes = self.tier2plus_stale_allow_count == 0
            && self.freshness_unknown_state_count == 0
            && self.unknown_state_count == 0;
        let replay_gate_passes =
            is_full_coverage(self.authoritative_outcomes_with_full_replay_contract)
                && self.missing_selector_count == 0
                && self.unknown_state_count == 0;
        let no_falsification_specific_hits = self.verifier_economics_regression_count == 0
            && self.crash_replay_missing_durable_record_accept_count == 0;

        if lifecycle_gate_passes
            && single_consume_gate_passes
            && freshness_gate_passes
            && replay_gate_passes
            && no_falsification_specific_hits
        {
            AdmissionOutcome::Admissible
        } else {
            AdmissionOutcome::NonAdmissible
        }
    }
}

const fn verifier_economics_regressed(
    baseline_p95_us: u64,
    candidate_p95_us: u64,
    baseline_threat_checks: u64,
    candidate_threat_checks: u64,
) -> bool {
    candidate_p95_us > baseline_p95_us && candidate_threat_checks == baseline_threat_checks
}

#[derive(Debug, Clone, Copy)]
enum Section16Criterion {
    MissingReplayResolvableLifecycleReceipts,
    DuplicateConsumeSucceeded,
    Tier2FreshnessAllow,
    VerifierEconomicsRegressed,
    CrashReplayAcceptedWithoutDurableRecord,
}

impl Section16Criterion {
    const fn all() -> [Self; 5] {
        [
            Self::MissingReplayResolvableLifecycleReceipts,
            Self::DuplicateConsumeSucceeded,
            Self::Tier2FreshnessAllow,
            Self::VerifierEconomicsRegressed,
            Self::CrashReplayAcceptedWithoutDurableRecord,
        ]
    }

    fn summary_with_hit(self) -> PcacEvidenceSummary {
        let mut summary = PcacEvidenceSummary::admissible_baseline();
        match self {
            Self::MissingReplayResolvableLifecycleReceipts => {
                summary.missing_selector_count = 1;
                summary.authoritative_outcomes_with_full_replay_contract = 0.0;
            },
            Self::DuplicateConsumeSucceeded => {
                summary.duplicate_consume_accept_count = 1;
            },
            Self::Tier2FreshnessAllow => {
                summary.tier2plus_stale_allow_count = 1;
                summary.freshness_unknown_state_count = 1;
            },
            Self::VerifierEconomicsRegressed => {
                let hit = verifier_economics_regressed(120, 260, 32, 32);
                summary.verifier_economics_regression_count = u64::from(hit);
            },
            Self::CrashReplayAcceptedWithoutDurableRecord => {
                summary.crash_replay_missing_durable_record_accept_count = 1;
                summary.durable_consume_record_coverage = 0.0;
            },
        }
        summary
    }
}

fn sovereignty_state_missing_epoch() -> SovereigntyState {
    SovereigntyState {
        epoch: None,
        principal_id: "principal-tck-00431".to_string(),
        revocation_head_known: true,
        autonomy_ceiling: Some(AutonomyCeiling {
            max_risk_tier: RiskTier::Tier2Plus,
            policy_binding_hash: test_hash(0x91),
        }),
        active_freeze: FreezeAction::NoAction,
    }
}

#[test]
fn section16_falsification_hits_are_non_admissible_for_objectives_and_gates() {
    for criterion in Section16Criterion::all() {
        let summary = criterion.summary_with_hit();
        assert_eq!(
            summary.objective_outcome(),
            AdmissionOutcome::NonAdmissible,
            "objective outcome must be non-admissible when falsification criterion {criterion:?} is hit"
        );
        assert_eq!(
            summary.gate_outcome(),
            AdmissionOutcome::NonAdmissible,
            "gate outcome must be non-admissible when falsification criterion {criterion:?} is hit"
        );

        // Determinism check: same summary yields same outcomes on repeated
        // evaluation.
        assert_eq!(summary.objective_outcome(), summary.objective_outcome());
        assert_eq!(summary.gate_outcome(), summary.gate_outcome());
    }
}

#[test]
fn replay_selector_gap_probe_is_non_admissible() {
    let lifecycle_entries = vec![
        ReplayLifecycleEntry {
            stage: LifecycleStage::Join,
            tick: 100,
            requires_pre_actuation: false,
            pre_actuation_selector_hash: None,
        },
        ReplayLifecycleEntry {
            stage: LifecycleStage::Revalidate,
            tick: 101,
            requires_pre_actuation: false,
            pre_actuation_selector_hash: None,
        },
        ReplayLifecycleEntry {
            stage: LifecycleStage::Consume,
            tick: 102,
            requires_pre_actuation: true,
            pre_actuation_selector_hash: None,
        },
    ];

    let deny = validate_replay_lifecycle_order(
        &lifecycle_entries,
        Some(103),
        &[],
        test_hash(0xA1),
        test_hash(0xA2),
        103,
    )
    .expect_err("missing pre-actuation selector must deny replay lifecycle validation");

    assert!(matches!(
        deny.deny_class,
        AuthorityDenyClass::MissingPreActuationReceipt
    ));

    let mut summary = PcacEvidenceSummary::admissible_baseline();
    summary.missing_selector_count = 1;
    summary.authoritative_outcomes_with_full_replay_contract = 0.0;

    assert!(summary.missing_selector_count > 0);
    assert_eq!(summary.objective_outcome(), AdmissionOutcome::NonAdmissible);
    assert_eq!(summary.gate_outcome(), AdmissionOutcome::NonAdmissible);
}

#[test]
fn crash_replay_without_durable_record_probe_is_non_admissible() {
    let input = authoritative_input(0x31, RiskTier::Tier2Plus);
    let policy = strict_policy();

    let initial_kernel = InProcessKernel::new(5_000);
    let initial_cert = AuthorityJoinKernel::join(&initial_kernel, &input, &policy)
        .expect("first join should produce a certificate");

    let (_first_witness, first_record) = AuthorityJoinKernel::consume(
        &initial_kernel,
        &initial_cert,
        input.intent_digest,
        input.boundary_intent_class,
        input.boundary_intent_class.is_authoritative(),
        input.time_envelope_ref,
        initial_cert.revocation_head_hash,
        &policy,
    )
    .expect("first consume should succeed");
    assert_eq!(first_record.ajc_id, initial_cert.ajc_id);

    // Fault injection: restart with no durable consume state; same AJC can be
    // consumed again. This is a falsification hit and must be non-admissible.
    let restarted_kernel = InProcessKernel::new(5_000);
    let replayed_cert = AuthorityJoinKernel::join(&restarted_kernel, &input, &policy)
        .expect("restart join should reproduce deterministic certificate");
    assert_eq!(replayed_cert.ajc_id, initial_cert.ajc_id);

    let (_replayed_witness, replayed_record) = AuthorityJoinKernel::consume(
        &restarted_kernel,
        &replayed_cert,
        input.intent_digest,
        input.boundary_intent_class,
        input.boundary_intent_class.is_authoritative(),
        input.time_envelope_ref,
        replayed_cert.revocation_head_hash,
        &policy,
    )
    .expect("missing durable consume record fault injection should reproduce replay acceptance");
    assert_eq!(replayed_record.ajc_id, replayed_cert.ajc_id);

    let mut summary = PcacEvidenceSummary::admissible_baseline();
    summary.duplicate_consume_accept_count = 1;
    summary.durable_consume_record_coverage = 0.0;
    summary.crash_replay_missing_durable_record_accept_count = 1;

    assert!(summary.duplicate_consume_accept_count > 0);
    assert!(summary.crash_replay_missing_durable_record_accept_count > 0);
    assert_eq!(summary.objective_outcome(), AdmissionOutcome::NonAdmissible);
    assert_eq!(summary.gate_outcome(), AdmissionOutcome::NonAdmissible);
}

#[test]
fn durable_duplicate_consume_attempts_are_denied_including_restart_replay() {
    let temp_dir = TempDir::new().expect("tempdir should be created");
    let consume_log_path = temp_dir.path().join("consume.log");

    let input = authoritative_input(0x41, RiskTier::Tier2Plus);
    let policy = strict_policy();

    let cert_ajc_id;
    {
        let durable_index =
            FileBackedConsumeIndex::open(&consume_log_path, None).expect("open durable index");
        let durable_kernel =
            DurableKernel::new(InProcessKernel::new(7_000), Box::new(durable_index));

        let cert = AuthorityJoinKernel::join(&durable_kernel, &input, &policy)
            .expect("join should succeed with durable kernel");
        cert_ajc_id = cert.ajc_id;

        AuthorityJoinKernel::consume(
            &durable_kernel,
            &cert,
            input.intent_digest,
            input.boundary_intent_class,
            input.boundary_intent_class.is_authoritative(),
            input.time_envelope_ref,
            cert.revocation_head_hash,
            &policy,
        )
        .expect("first durable consume should succeed");

        let duplicate_err = AuthorityJoinKernel::consume(
            &durable_kernel,
            &cert,
            input.intent_digest,
            input.boundary_intent_class,
            input.boundary_intent_class.is_authoritative(),
            input.time_envelope_ref,
            cert.revocation_head_hash,
            &policy,
        )
        .expect_err("duplicate consume in same process must deny");

        assert!(matches!(
            duplicate_err.deny_class,
            AuthorityDenyClass::AlreadyConsumed { ajc_id } if ajc_id == cert.ajc_id
        ));
    }

    {
        let replay_index =
            FileBackedConsumeIndex::open(&consume_log_path, None).expect("reopen durable index");
        let replay_kernel = DurableKernel::new(InProcessKernel::new(7_000), Box::new(replay_index));
        let replay_cert = AuthorityJoinKernel::join(&replay_kernel, &input, &policy)
            .expect("restart join should reproduce deterministic certificate");
        assert_eq!(replay_cert.ajc_id, cert_ajc_id);

        let replay_err = AuthorityJoinKernel::consume(
            &replay_kernel,
            &replay_cert,
            input.intent_digest,
            input.boundary_intent_class,
            input.boundary_intent_class.is_authoritative(),
            input.time_envelope_ref,
            replay_cert.revocation_head_hash,
            &policy,
        )
        .expect_err("duplicate consume after restart must deny");

        assert!(matches!(
            replay_err.deny_class,
            AuthorityDenyClass::AlreadyConsumed { ajc_id } if ajc_id == replay_cert.ajc_id
        ));
    }

    let log_contents = std::fs::read_to_string(&consume_log_path)
        .expect("consume log should be readable after durable consume");
    assert!(log_contents.contains(&hex::encode(cert_ajc_id)));
}

#[test]
fn tier2_freshness_and_sovereignty_uncertainty_probes_deny() {
    // Stale freshness denial probe.
    let stale_kernel = InProcessKernel::new(9_000);
    let stale_input = authoritative_input(0x51, RiskTier::Tier2Plus);
    let stale_policy = PcacPolicyKnobs {
        freshness_max_age_ticks: 2,
        ..strict_policy()
    };
    let stale_cert = AuthorityJoinKernel::join(&stale_kernel, &stale_input, &stale_policy)
        .expect("stale probe join should succeed");
    stale_kernel.advance_tick(stale_cert.issued_at_tick + stale_policy.freshness_max_age_ticks + 1);

    let stale_err = AuthorityJoinKernel::revalidate(
        &stale_kernel,
        &stale_cert,
        stale_input.time_envelope_ref,
        stale_input.as_of_ledger_anchor,
        stale_cert.revocation_head_hash,
        &stale_policy,
    )
    .expect_err("Tier2+ stale freshness probe must deny");
    assert!(
        matches!(
            stale_err.deny_class,
            AuthorityDenyClass::FreshnessExceeded { .. }
                | AuthorityDenyClass::CertificateExpired { .. }
        ),
        "expected stale freshness denial class, got: {:?}",
        stale_err.deny_class
    );

    // Ambiguous freshness policy denial probe.
    let ambiguous_kernel = InProcessKernel::new(9_500);
    let ambiguous_input = authoritative_input(0x52, RiskTier::Tier2Plus);
    let ambiguous_policy = PcacPolicyKnobs {
        freshness_max_age_ticks: 0,
        ..strict_policy()
    };
    let ambiguous_err =
        AuthorityJoinKernel::join(&ambiguous_kernel, &ambiguous_input, &ambiguous_policy)
            .expect_err("Tier2+ ambiguous freshness policy must deny");
    assert!(
        matches!(
            ambiguous_err.deny_class,
            AuthorityDenyClass::UnknownState { ref description }
                if description.contains("freshness_max_age_ticks")
        ),
        "expected ambiguous freshness denial class, got: {:?}",
        ambiguous_err.deny_class
    );

    // Sovereignty uncertainty denial probe.
    let sovereignty_kernel = InProcessKernel::new(10_000);
    let sovereignty_checker = SovereigntyChecker::new(test_hash(0x99));
    let sovereignty_input = authoritative_input(0x53, RiskTier::Tier2Plus);
    let sovereignty_cert =
        AuthorityJoinKernel::join(&sovereignty_kernel, &sovereignty_input, &strict_policy())
            .expect("Tier2+ sovereignty probe join should succeed");
    let sovereignty_err = sovereignty_checker
        .check_revalidate(
            &sovereignty_cert,
            &sovereignty_state_missing_epoch(),
            10_000,
            sovereignty_input.time_envelope_ref,
            sovereignty_input.as_of_ledger_anchor,
        )
        .expect_err("Tier2+ sovereignty uncertainty must deny");
    assert!(
        matches!(
            sovereignty_err.deny_class,
            AuthorityDenyClass::SovereigntyUncertainty { .. }
                | AuthorityDenyClass::UnknownState { .. }
        ),
        "expected sovereignty uncertainty/unknown-state denial class, got: {:?}",
        sovereignty_err.deny_class
    );
}
