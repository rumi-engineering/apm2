//! TCK-00382: Business continuity, formal gates, and federation stop/rotation
//! governance.
//!
//! Evidence artifacts:
//! - EVID-0036
//! - EVID-0401
//! - EVID-0402

use std::sync::Arc;

use apm2_core::consensus::{
    AdmittedRewriteCatalog, AntiEntropyArtifactStatus, ConvergenceSimulator,
    FormalGateArtifactResult, FormalGateArtifactSet, Hlc, MAX_CONVERGENCE_ROUNDS,
    ModelCheckedInvariantReport, RewriteRule, build_linear_composition,
};
use apm2_core::continuity::{ContinuityError, DrillReceiptV1, MAX_DRILL_EVIDENCE_REFS};
use apm2_core::crypto::{EventHasher, Hash, Signer};
use apm2_core::fac::PolicyResolvedForChangeSetBuilder;
use apm2_core::governance::{
    GovernanceRatchetUpdateV1, GovernanceRotationAnnouncementV1, GovernanceStopClass,
    GovernanceStopOrderV1, OverlapValidityWindowV1,
};
use apm2_core::ledger::EventRecord;
use apm2_core::reducer::{Reducer, ReducerContext};
use apm2_core::work::{WorkReducer, WorkReducerState, helpers};
use apm2_daemon::episode::registry::InMemorySessionRegistry;
use apm2_daemon::gate::{
    GateOutcome, GateType, GitHubMergeAdapter, MergeExecutor, MergeExecutorError, MergeInput,
    MergeResult,
};
use apm2_daemon::governance_channel::{
    BreakglassAuthorization, GovernanceActionKind, GovernanceChannelError,
    GovernanceChannelHandler, GovernanceEnforcementLevel,
};
use apm2_daemon::hmp::{BodyRef, ChannelClass, HmpMessageV1};
use apm2_daemon::session::SessionRegistry;
use apm2_daemon::state::DispatcherState;

const fn test_hash(byte: u8) -> Hash {
    [byte; 32]
}

struct SuccessAdapter {
    result_sha: String,
}

impl GitHubMergeAdapter for SuccessAdapter {
    fn squash_merge(
        &self,
        _pr_number: u64,
        _commit_title: &str,
        target_branch: &str,
    ) -> Result<MergeResult, MergeExecutorError> {
        Ok(MergeResult {
            result_sha: self.result_sha.clone(),
            target_branch: target_branch.to_string(),
        })
    }
}

fn make_valid_work_events(work_id: &str) -> (Vec<EventRecord>, WorkReducerState) {
    let opened_payload =
        helpers::work_opened_payload(work_id, "TICKET", vec![1, 2, 3], vec![], vec![]);
    let events = vec![
        EventRecord::with_timestamp("work.opened", work_id, "actor:test", opened_payload, 1_000)
            .with_seq_id(1),
    ];
    let mut reducer = WorkReducer::new();
    reducer
        .apply(&events[0], &ReducerContext::new(1))
        .expect("reducer should apply work.opened");
    (events, reducer.state().clone())
}

fn make_merge_input(signer: &Signer) -> MergeInput {
    let work_id = "work-00382-merge";
    let (work_events, expected_reducer_state) = make_valid_work_events(work_id);
    let policy_resolution = PolicyResolvedForChangeSetBuilder::new(work_id, test_hash(0x42))
        .resolved_risk_tier(1)
        .resolved_determinism_class(0)
        .resolver_actor_id("resolver-00382")
        .resolver_version("1.0.0")
        .build_and_sign(signer);

    MergeInput {
        work_id: work_id.to_string(),
        changeset_digest: test_hash(0x42),
        pr_number: 382,
        target_branch: "main".to_string(),
        gate_outcomes: vec![
            GateOutcome {
                gate_type: GateType::Aat,
                passed: true,
                receipt_id: Some("receipt-aat-00382".to_string()),
                timed_out: false,
            },
            GateOutcome {
                gate_type: GateType::Quality,
                passed: true,
                receipt_id: Some("receipt-quality-00382".to_string()),
                timed_out: false,
            },
            GateOutcome {
                gate_type: GateType::Security,
                passed: true,
                receipt_id: Some("receipt-security-00382".to_string()),
                timed_out: false,
            },
        ],
        policy_resolution,
        actor_id: "merge-executor-00382".to_string(),
        work_events,
        expected_reducer_state: Some(expected_reducer_state),
        promotion_stage: None,
        formal_artifacts: None,
        stop_path_slo_allows_promotion: None,
        rpo_rto_within_targets: None,
    }
}

fn make_passing_formal_artifact_result() -> FormalGateArtifactResult {
    let compositions = vec![build_linear_composition(0).expect("composition should build")];

    let mut catalog = AdmittedRewriteCatalog::new().expect("catalog should construct");
    let lts = build_linear_composition(0).expect("composition should build");
    let rule = RewriteRule::new(
        "R00382".to_string(),
        "identity".to_string(),
        lts.clone(),
        lts,
    )
    .expect("rule should construct");
    catalog.register_rule(rule).expect("rule should register");
    catalog
        .submit_proof("R00382", "cas://proof/r00382")
        .expect("proof should verify");

    let anti_entropy = AntiEntropyArtifactStatus {
        pull_only_enforced: true,
        relay_budget_enforced: true,
        byzantine_relay_detected: false,
        defects: Vec::new(),
    };

    let mut convergence =
        ConvergenceSimulator::new(vec!["cell-a".to_string(), "cell-b".to_string()], 8)
            .expect("simulator should construct");
    convergence
        .admit("cell-a", "subject-1", "value", Hlc::new(1, 0))
        .expect("admit should succeed");

    let invariants = ModelCheckedInvariantReport {
        no_actuation_without_verified_stop_state: true,
        no_delegation_widening: true,
        no_unsigned_facts_admitted: true,
    };

    FormalGateArtifactSet::evaluate_all(
        &compositions,
        &catalog,
        anti_entropy,
        &mut convergence,
        MAX_CONVERGENCE_ROUNDS,
        invariants,
    )
    .expect("formal artifacts should pass")
}

fn governance_envelope(message_class: &str, body_hash: Hash) -> HmpMessageV1 {
    HmpMessageV1 {
        protocol_id: "hsi:v1".to_string(),
        message_class: message_class.to_string(),
        message_id: test_hash(0x91),
        idempotency_key: "idem-00382".to_string(),
        hlc_timestamp: 1_000,
        parents: Vec::new(),
        sender_holon_id: "holon-a".to_string(),
        sender_actor_id: "actor-a".to_string(),
        channel_class: ChannelClass::Governance,
        sender_cell_id: "cell-a".to_string(),
        receiver_cell_id: "cell-local".to_string(),
        sender_policy_root_key_id: "pkid-a".to_string(),
        body_ref: BodyRef::new(body_hash, "application/json".to_string())
            .expect("body ref should construct"),
        ledger_head_hash: test_hash(0x22),
        context_pack_hash: None,
        manifest_hash: None,
        view_commitment_hash: None,
        permeability_receipt_hash: Some(test_hash(0x23)),
    }
}

fn production_wired_handler() -> (DispatcherState, GovernanceChannelHandler) {
    let session_registry: Arc<dyn SessionRegistry> = Arc::new(InMemorySessionRegistry::new());
    let state = DispatcherState::with_persistence(session_registry, None, None, None)
        .expect("dispatcher state should initialize");
    let stop_authority = Arc::clone(
        state
            .stop_authority()
            .expect("with_persistence should wire stop authority"),
    );
    let handler = GovernanceChannelHandler::new("cell-local".to_string(), stop_authority);
    (state, handler)
}

// IT-00382-01: S1+ promotion blocks when formal artifacts are missing.
#[test]
fn tck_00382_it_01_s1_blocks_without_formal_artifacts() {
    let signer = Arc::new(Signer::generate());
    let executor = MergeExecutor::new(Arc::clone(&signer), "merge-executor");
    let mut input = make_merge_input(&signer);

    input.promotion_stage = Some("S1".to_string());
    input.stop_path_slo_allows_promotion = Some(true);
    input.rpo_rto_within_targets = Some(true);

    let adapter = SuccessAdapter {
        result_sha: "sha-00382-01".to_string(),
    };
    let err = executor.execute_merge(&input, &adapter).unwrap_err();
    match err {
        MergeExecutorError::PromotionGateBlocked { reason, .. } => {
            assert!(reason.contains("formal artifacts missing"));
        },
        other => panic!("expected PromotionGateBlocked, got {other:?}"),
    }
}

// IT-00382-02: Stop-path SLO failures block S1+ promotion.
#[test]
fn tck_00382_it_02_s1_blocks_on_stop_path_slo_failure() {
    let signer = Arc::new(Signer::generate());
    let executor = MergeExecutor::new(Arc::clone(&signer), "merge-executor");
    let mut input = make_merge_input(&signer);

    input.promotion_stage = Some("S1".to_string());
    input.formal_artifacts = Some(make_passing_formal_artifact_result());
    input.stop_path_slo_allows_promotion = Some(false);
    input.rpo_rto_within_targets = Some(true);

    let adapter = SuccessAdapter {
        result_sha: "sha-00382-02".to_string(),
    };
    let err = executor.execute_merge(&input, &adapter).unwrap_err();
    match err {
        MergeExecutorError::PromotionGateBlocked { reason, .. } => {
            assert!(reason.contains("stop-path SLO signal"));
        },
        other => panic!("expected PromotionGateBlocked, got {other:?}"),
    }
}

// IT-00382-03: RPO/RTO failures block S1+ promotion.
#[test]
fn tck_00382_it_03_s1_blocks_on_rpo_rto_failure() {
    let signer = Arc::new(Signer::generate());
    let executor = MergeExecutor::new(Arc::clone(&signer), "merge-executor");
    let mut input = make_merge_input(&signer);

    input.promotion_stage = Some("S1".to_string());
    input.formal_artifacts = Some(make_passing_formal_artifact_result());
    input.stop_path_slo_allows_promotion = Some(true);
    input.rpo_rto_within_targets = Some(false);

    let adapter = SuccessAdapter {
        result_sha: "sha-00382-03".to_string(),
    };
    let err = executor.execute_merge(&input, &adapter).unwrap_err();
    match err {
        MergeExecutorError::PromotionGateBlocked { reason, .. } => {
            assert!(reason.contains("RPO/RTO signal"));
        },
        other => panic!("expected PromotionGateBlocked, got {other:?}"),
    }
}

// IT-00382-04: Signed cross-cell stop is authenticated and auditable.
#[test]
fn tck_00382_it_04_governance_stop_is_authenticated_and_audited() {
    let signer = Signer::generate();
    let (state, mut handler) = production_wired_handler();

    let mut message = GovernanceStopOrderV1 {
        issuer_cell_id: "cell-a".to_string(),
        target_cell_id: "cell-local".to_string(),
        stop_class: GovernanceStopClass::GovernanceStop,
        reason: "federated stop".to_string(),
        timestamp_ms: 1_000,
        signature: Vec::new(),
    };
    message.sign(&signer).expect("stop order should sign");
    let payload = serde_json::to_vec(&message).expect("payload should serialize");
    let envelope = governance_envelope(
        "HSI.GOVERNANCE.STOP_ORDER.V1",
        EventHasher::hash_content(&payload),
    );

    let receipt = handler
        .process_message(
            &envelope,
            &payload,
            &signer.verifying_key(),
            test_hash(0x33),
            1_000,
            None,
        )
        .expect("governance stop should process");

    assert_eq!(receipt.action_kind, GovernanceActionKind::StopOrder);
    assert!(receipt.authenticated);
    assert_eq!(handler.action_receipts().len(), 1);
    assert!(
        state
            .stop_authority()
            .expect("stop authority should remain wired")
            .governance_stop_active()
    );
}

// IT-00382-05: G2 ratchet-tightening requires signed breakglass authorization.
#[test]
fn tck_00382_it_05_g2_requires_breakglass_for_ratchet_tightening() {
    let signer = Signer::generate();
    let operator_signer = Signer::generate();
    let (_state, mut handler) = production_wired_handler();
    handler.set_enforcement_level(GovernanceEnforcementLevel::G2);

    let mut message = GovernanceRatchetUpdateV1 {
        cell_id: "cell-a".to_string(),
        previous_gate_level: "G1".to_string(),
        next_gate_level: "G2".to_string(),
        justification: "incident mitigation".to_string(),
        timestamp_ms: 2_000,
        signature: Vec::new(),
    };
    message.sign(&signer).expect("ratchet update should sign");
    let payload = serde_json::to_vec(&message).expect("payload should serialize");
    let envelope = governance_envelope(
        "HSI.GOVERNANCE.RATCHET_UPDATE.V1",
        EventHasher::hash_content(&payload),
    );

    let denied = handler.process_message(
        &envelope,
        &payload,
        &signer.verifying_key(),
        test_hash(0x34),
        2_000,
        None,
    );
    assert!(matches!(
        denied,
        Err(GovernanceChannelError::BreakglassDenied { .. })
    ));

    let mut authorization = BreakglassAuthorization {
        operator_id: "operator-00382".to_string(),
        reason: "incident mitigation".to_string(),
        valid_from_ms: 1_900,
        valid_until_ms: 2_500,
        sequence_number: 1,
        signature: Vec::new(),
    };
    authorization
        .sign(&operator_signer)
        .expect("breakglass authorization should sign");
    handler
        .authorize_breakglass(authorization, &operator_signer.verifying_key())
        .expect("breakglass authorization should register");

    let receipt = handler
        .process_message(
            &envelope,
            &payload,
            &signer.verifying_key(),
            test_hash(0x35),
            2_000,
            Some("operator-00382"),
        )
        .expect("ratchet update should pass with breakglass");

    assert_eq!(receipt.action_kind, GovernanceActionKind::RatchetUpdate);
    assert!(receipt.breakglass_receipt.is_some());
    assert_eq!(handler.action_receipts().len(), 1);
    assert_eq!(handler.breakglass_receipts().len(), 1);
}

// IT-00382-06: DrillReceiptV1 enforces bounded evidence references fail-closed.
#[test]
fn tck_00382_it_06_drill_receipt_rejects_oversized_evidence_reference_set() {
    let receipt = DrillReceiptV1 {
        scenario_id: "scenario-00382".to_string(),
        scenario_version: "v1".to_string(),
        observed_failure_modes: vec!["partition".to_string()],
        recovery_time_ms: 123,
        stop_order_failure_count: 0,
        evidence_references: vec![test_hash(0x44); MAX_DRILL_EVIDENCE_REFS + 1],
    };

    let err = receipt
        .validate()
        .expect_err("oversized evidence set must fail");
    assert!(matches!(
        err,
        ContinuityError::TooManyEntries {
            field: "evidence_references",
            actual,
            max
        } if actual == MAX_DRILL_EVIDENCE_REFS + 1 && max == MAX_DRILL_EVIDENCE_REFS
    ));
}

// IT-00382-07: Rotation announcements are authenticated and routed.
#[test]
fn tck_00382_it_07_rotation_announcement_is_authenticated_and_routed() {
    let signer = Signer::generate();
    let (_state, mut handler) = production_wired_handler();

    let mut message = GovernanceRotationAnnouncementV1 {
        cell_id: "cell-a".to_string(),
        old_key_id: "old-key".to_string(),
        new_key_id: "new-key".to_string(),
        overlap_validity_window: OverlapValidityWindowV1 {
            not_before_ms: 1_000,
            not_after_ms: 2_000,
        },
        timestamp_ms: 1_500,
        signature: Vec::new(),
    };
    message
        .sign(&signer)
        .expect("rotation announcement should sign");

    let payload = serde_json::to_vec(&message).expect("payload should serialize");
    let envelope = governance_envelope(
        "HSI.GOVERNANCE.ROTATION_ANNOUNCEMENT.V1",
        EventHasher::hash_content(&payload),
    );
    let receipt = handler
        .process_message(
            &envelope,
            &payload,
            &signer.verifying_key(),
            test_hash(0x36),
            1_500,
            None,
        )
        .expect("rotation announcement should process");

    assert_eq!(
        receipt.action_kind,
        GovernanceActionKind::RotationAnnouncement
    );
    assert!(receipt.authenticated);
    assert_eq!(handler.action_receipts().len(), 1);
}

// IT-00382-08: Stale governance messages are rejected by freshness checks.
#[test]
fn tck_00382_it_08_stale_governance_message_rejected() {
    let signer = Signer::generate();
    let (state, mut handler) = production_wired_handler();

    let mut message = GovernanceStopOrderV1 {
        issuer_cell_id: "cell-a".to_string(),
        target_cell_id: "cell-local".to_string(),
        stop_class: GovernanceStopClass::GovernanceStop,
        reason: "stale replay attempt".to_string(),
        timestamp_ms: 1_000,
        signature: Vec::new(),
    };
    message.sign(&signer).expect("stop order should sign");
    let payload = serde_json::to_vec(&message).expect("payload should serialize");
    let envelope = governance_envelope(
        "HSI.GOVERNANCE.STOP_ORDER.V1",
        EventHasher::hash_content(&payload),
    );

    let result = handler.process_message(
        &envelope,
        &payload,
        &signer.verifying_key(),
        test_hash(0x37),
        1_000_000,
        None,
    );
    assert!(matches!(
        result,
        Err(GovernanceChannelError::MessageTimestampFreshness { .. })
    ));
    assert!(
        !state
            .stop_authority()
            .expect("stop authority should remain wired")
            .governance_stop_active()
    );
}

// IT-00382-09: Future governance messages beyond tolerance are rejected.
#[test]
fn tck_00382_it_09_future_governance_message_rejected() {
    let signer = Signer::generate();
    let (_state, mut handler) = production_wired_handler();

    let mut message = GovernanceStopOrderV1 {
        issuer_cell_id: "cell-a".to_string(),
        target_cell_id: "cell-local".to_string(),
        stop_class: GovernanceStopClass::GovernanceStop,
        reason: "future replay attempt".to_string(),
        timestamp_ms: 100_000,
        signature: Vec::new(),
    };
    message.sign(&signer).expect("stop order should sign");
    let payload = serde_json::to_vec(&message).expect("payload should serialize");
    let envelope = governance_envelope(
        "HSI.GOVERNANCE.STOP_ORDER.V1",
        EventHasher::hash_content(&payload),
    );

    let result = handler.process_message(
        &envelope,
        &payload,
        &signer.verifying_key(),
        test_hash(0x38),
        1_000,
        None,
    );
    assert!(matches!(
        result,
        Err(GovernanceChannelError::MessageTimestampFreshness { .. })
    ));
}

// IT-00382-10: Fresh governance messages inside window are accepted.
#[test]
fn tck_00382_it_10_fresh_governance_message_within_window_accepted() {
    let signer = Signer::generate();
    let (_state, mut handler) = production_wired_handler();

    let mut message = GovernanceStopOrderV1 {
        issuer_cell_id: "cell-a".to_string(),
        target_cell_id: "cell-local".to_string(),
        stop_class: GovernanceStopClass::GovernanceStop,
        reason: "fresh stop request".to_string(),
        timestamp_ms: 1_000,
        signature: Vec::new(),
    };
    message.sign(&signer).expect("stop order should sign");
    let payload = serde_json::to_vec(&message).expect("payload should serialize");
    let envelope = governance_envelope(
        "HSI.GOVERNANCE.STOP_ORDER.V1",
        EventHasher::hash_content(&payload),
    );

    let receipt = handler
        .process_message(
            &envelope,
            &payload,
            &signer.verifying_key(),
            test_hash(0x39),
            1_000,
            None,
        )
        .expect("fresh governance stop should process");
    assert_eq!(receipt.action_kind, GovernanceActionKind::StopOrder);
}

// IT-00382-11: Replayed breakglass authorization with same sequence is
// rejected.
#[test]
fn tck_00382_it_11_breakglass_replay_with_stale_sequence_rejected() {
    let operator_signer = Signer::generate();
    let (_state, mut handler) = production_wired_handler();

    let mut initial = BreakglassAuthorization {
        operator_id: "op-001".to_string(),
        reason: "initial authorization".to_string(),
        valid_from_ms: 1_000,
        valid_until_ms: 5_000,
        sequence_number: 1,
        signature: Vec::new(),
    };
    initial
        .sign(&operator_signer)
        .expect("initial authorization should sign");
    handler
        .authorize_breakglass(initial, &operator_signer.verifying_key())
        .expect("initial authorization should register");

    let mut replay = BreakglassAuthorization {
        operator_id: "op-001".to_string(),
        reason: "replay authorization".to_string(),
        valid_from_ms: 1_000,
        valid_until_ms: 5_000,
        sequence_number: 1,
        signature: Vec::new(),
    };
    replay
        .sign(&operator_signer)
        .expect("replay authorization should sign");

    let result = handler.authorize_breakglass(replay, &operator_signer.verifying_key());
    assert!(matches!(
        result,
        Err(GovernanceChannelError::BreakglassDenied { .. })
    ));
}

// IT-00382-12: Replayed breakglass authorization with lower sequence is
// rejected.
#[test]
fn tck_00382_it_12_breakglass_replay_with_lower_sequence_rejected() {
    let operator_signer = Signer::generate();
    let (_state, mut handler) = production_wired_handler();

    let mut higher = BreakglassAuthorization {
        operator_id: "op-001".to_string(),
        reason: "higher sequence authorization".to_string(),
        valid_from_ms: 1_000,
        valid_until_ms: 5_000,
        sequence_number: 5,
        signature: Vec::new(),
    };
    higher
        .sign(&operator_signer)
        .expect("higher authorization should sign");
    handler
        .authorize_breakglass(higher, &operator_signer.verifying_key())
        .expect("higher authorization should register");

    let mut lower = BreakglassAuthorization {
        operator_id: "op-001".to_string(),
        reason: "lower sequence authorization".to_string(),
        valid_from_ms: 1_000,
        valid_until_ms: 5_000,
        sequence_number: 3,
        signature: Vec::new(),
    };
    lower
        .sign(&operator_signer)
        .expect("lower authorization should sign");

    let result = handler.authorize_breakglass(lower, &operator_signer.verifying_key());
    assert!(matches!(
        result,
        Err(GovernanceChannelError::BreakglassDenied { .. })
    ));
}

// IT-00382-13: Strictly increasing breakglass sequence is accepted.
#[test]
fn tck_00382_it_13_breakglass_monotonic_sequence_accepted() {
    let signer = Signer::generate();
    let operator_signer = Signer::generate();
    let (_state, mut handler) = production_wired_handler();
    handler.set_enforcement_level(GovernanceEnforcementLevel::G2);

    let mut first = BreakglassAuthorization {
        operator_id: "op-001".to_string(),
        reason: "first authorization".to_string(),
        valid_from_ms: 1_000,
        valid_until_ms: 5_000,
        sequence_number: 1,
        signature: Vec::new(),
    };
    first
        .sign(&operator_signer)
        .expect("first authorization should sign");
    handler
        .authorize_breakglass(first, &operator_signer.verifying_key())
        .expect("first authorization should register");

    let mut second = BreakglassAuthorization {
        operator_id: "op-001".to_string(),
        reason: "second authorization".to_string(),
        valid_from_ms: 1_000,
        valid_until_ms: 5_000,
        sequence_number: 2,
        signature: Vec::new(),
    };
    second
        .sign(&operator_signer)
        .expect("second authorization should sign");
    handler
        .authorize_breakglass(second, &operator_signer.verifying_key())
        .expect("second authorization should replace first");

    let mut message = GovernanceRatchetUpdateV1 {
        cell_id: "cell-a".to_string(),
        previous_gate_level: "G1".to_string(),
        next_gate_level: "G2".to_string(),
        justification: "confirm replacement".to_string(),
        timestamp_ms: 2_000,
        signature: Vec::new(),
    };
    message.sign(&signer).expect("ratchet update should sign");
    let payload = serde_json::to_vec(&message).expect("payload should serialize");
    let envelope = governance_envelope(
        "HSI.GOVERNANCE.RATCHET_UPDATE.V1",
        EventHasher::hash_content(&payload),
    );

    let receipt = handler
        .process_message(
            &envelope,
            &payload,
            &signer.verifying_key(),
            test_hash(0x3a),
            2_000,
            Some("op-001"),
        )
        .expect("ratchet update should pass with newer breakglass authorization");

    let breakglass_receipt = receipt
        .breakglass_receipt
        .expect("breakglass receipt should be present");
    assert_eq!(breakglass_receipt.reason, "second authorization");
}
