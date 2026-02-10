//! Tests for advisory EFE planner integration.

#![allow(clippy::float_cmp)]

use super::ControllerError;
use super::controller::{CoordinationConfig, CoordinationController};
use super::planner::{
    AdvisoryPlannerScore, CoordinationObjectiveReceiptV1, EfeComponents, EfeObjective, EfeWeights,
    MAX_PLANNER_COORDINATION_ID_LEN, MAX_PLANNER_WORK_ID_LEN, MAX_TRACKED_OBJECTIVES,
    OBJECTIVE_RECEIPT_SCHEMA_VERSION, PlannerError, TIER3_ESCALATION_THRESHOLD,
};
use super::state::{
    AbortReason, BudgetType, CoordinationBudget, CoordinationStatus, SessionOutcome, StopCondition,
    WorkItemOutcome,
};
use crate::crypto::Hash;
use crate::htf::HtfTick;

/// Default tick rate for tests: 1MHz (1 tick = 1 microsecond).
const TEST_TICK_RATE_HZ: u64 = 1_000_000;

fn tick(value: u64) -> HtfTick {
    HtfTick::new(value, TEST_TICK_RATE_HZ)
}

fn test_budget() -> CoordinationBudget {
    CoordinationBudget::new(10, 60_000_000, TEST_TICK_RATE_HZ, Some(100_000)).unwrap()
}

fn test_controller(work_ids: Vec<String>, max_attempts: u32) -> CoordinationController {
    let config = CoordinationConfig::new(work_ids, test_budget(), max_attempts).unwrap();
    CoordinationController::new(config)
}

fn planner_score(
    work_id: &str,
    components: EfeComponents,
    tick_value: u64,
) -> AdvisoryPlannerScore {
    let objective = EfeObjective::new(
        work_id.to_string(),
        components,
        EfeWeights::default(),
        tick_value,
    )
    .unwrap();
    AdvisoryPlannerScore::new(objective).unwrap()
}

fn best_possible_score(work_id: &str, tick_value: u64) -> AdvisoryPlannerScore {
    planner_score(
        work_id,
        EfeComponents::new(0.0, 0.0, 0.0).unwrap(),
        tick_value,
    )
}

fn tracking_snapshot(
    controller: &CoordinationController,
) -> Vec<(String, u32, Vec<String>, Option<WorkItemOutcome>)> {
    controller
        .work_tracking()
        .iter()
        .map(|item| {
            (
                item.work_id.clone(),
                item.attempt_count,
                item.session_ids.clone(),
                item.final_outcome,
            )
        })
        .collect()
}

#[test]
fn test_efe_computation_weighted_sum() {
    let components = EfeComponents::new(0.2, 0.3, 0.4).unwrap();
    let weights = EfeWeights::new(0.5, 0.25, 1.0).unwrap();

    let efe = components.compute_efe(&weights);
    let expected = 0.575_f64;

    assert!((efe - expected).abs() < f64::EPSILON);
}

#[test]
fn test_efe_weights_clamp() {
    let weights = EfeWeights::new(-2.0, 0.5, 9.0).unwrap();

    assert_eq!(weights.lambda_risk(), 0.0);
    assert_eq!(weights.lambda_uncertainty(), 0.5);
    assert_eq!(weights.lambda_cost(), 1.0);
}

#[test]
fn test_efe_reject_nan_inf() {
    let weight_err = EfeWeights::new(f64::NAN, 0.4, 0.5).unwrap_err();
    assert!(matches!(
        weight_err,
        PlannerError::InvalidFloat {
            field: "lambda_risk",
            ..
        }
    ));

    let component_err = EfeComponents::new(0.4, f64::INFINITY, 0.1).unwrap_err();
    assert!(matches!(
        component_err,
        PlannerError::InvalidFloat {
            field: "expected_evidence_ambiguity",
            ..
        }
    ));
}

#[test]
fn test_efe_components_bounds() {
    let err = EfeComponents::new(1.2, 0.1, 0.1).unwrap_err();
    assert!(matches!(
        err,
        PlannerError::OutOfRange {
            field: "expected_policy_violation",
            ..
        }
    ));
}

#[test]
fn test_efe_default_weights() {
    let weights = EfeWeights::default();

    assert_eq!(weights.lambda_risk(), 1.0);
    assert_eq!(weights.lambda_uncertainty(), 1.0);
    assert_eq!(weights.lambda_cost(), 1.0);
}

#[test]
fn test_advisory_score_cannot_bypass_budget_exhausted() {
    let budget = CoordinationBudget::new(1, 60_000_000, TEST_TICK_RATE_HZ, Some(100_000)).unwrap();
    let config = CoordinationConfig::new(vec!["work-1".to_string()], budget, 3).unwrap();
    let mut controller = CoordinationController::new(config);

    controller.start(tick(1_000), 1_000_000_000).unwrap();
    let spawn = controller
        .prepare_session_spawn("work-1", 100, 2_000_000_000)
        .unwrap();
    controller
        .record_session_termination(
            &spawn.session_id,
            "work-1",
            SessionOutcome::Success,
            10,
            tick(2_000),
            3_000_000_000,
        )
        .unwrap();

    assert_eq!(
        controller.check_stop_condition(),
        Some(StopCondition::BudgetExhausted(BudgetType::Episodes))
    );

    let receipt = controller
        .record_advisory_objective(0, best_possible_score("work-1", 2_500), 2_550)
        .unwrap();
    assert!(receipt.is_none());

    assert_eq!(
        controller.check_stop_condition(),
        Some(StopCondition::BudgetExhausted(BudgetType::Episodes))
    );
}

#[test]
fn test_advisory_score_cannot_bypass_circuit_breaker() {
    let mut controller = test_controller(
        vec![
            "work-1".to_string(),
            "work-2".to_string(),
            "work-3".to_string(),
        ],
        1,
    );
    controller.start(tick(1_000), 1_000_000_000).unwrap();

    for (index, work_id) in ["work-1", "work-2", "work-3"].into_iter().enumerate() {
        let spawn = controller
            .prepare_session_spawn(work_id, 100 + index as u64, 2_000_000_000 + index as u64)
            .unwrap();
        controller
            .record_session_termination(
                &spawn.session_id,
                work_id,
                SessionOutcome::Failure,
                10,
                tick(2_000 + index as u64),
                3_000_000_000 + index as u64,
            )
            .unwrap();
    }

    assert_eq!(
        controller.check_stop_condition(),
        Some(StopCondition::CircuitBreakerTriggered {
            consecutive_failures: TIER3_ESCALATION_THRESHOLD,
        })
    );

    let receipt = controller
        .record_advisory_objective(2, best_possible_score("work-3", 3_000), 3_050)
        .unwrap();
    assert!(receipt.is_none());

    assert_eq!(
        controller.check_stop_condition(),
        Some(StopCondition::CircuitBreakerTriggered {
            consecutive_failures: TIER3_ESCALATION_THRESHOLD,
        })
    );
}

#[test]
fn test_advisory_score_cannot_bypass_freshness_check() {
    let mut controller = test_controller(vec!["work-1".to_string()], 3);
    controller.start(tick(1_000), 1_000_000_000).unwrap();

    let before = controller.check_work_freshness("work-1", 100, false);
    assert!(!before.is_eligible);

    let receipt = controller
        .record_advisory_objective(0, best_possible_score("work-1", 1_500), 1_550)
        .unwrap();
    assert!(receipt.is_none());

    let after = controller.check_work_freshness("work-1", 100, false);
    assert!(!after.is_eligible);
    assert_eq!(before.skip_reason, after.skip_reason);
}

#[test]
fn test_advisory_score_cannot_bypass_work_completed() {
    let mut controller = test_controller(vec!["work-1".to_string()], 3);
    controller.start(tick(1_000), 1_000_000_000).unwrap();
    controller.skip_work_item("work-1").unwrap();

    assert_eq!(
        controller.check_stop_condition(),
        Some(StopCondition::WorkCompleted)
    );

    let receipt = controller
        .record_advisory_objective(0, best_possible_score("work-1", 2_000), 2_050)
        .unwrap();
    assert!(receipt.is_none());

    assert_eq!(
        controller.check_stop_condition(),
        Some(StopCondition::WorkCompleted)
    );
}

#[test]
fn test_advisory_score_cannot_authorize_spawn() {
    let mut controller = test_controller(vec!["work-1".to_string()], 3);
    controller.start(tick(1_000), 1_000_000_000).unwrap();
    controller.skip_work_item("work-1").unwrap();
    controller
        .complete(StopCondition::WorkCompleted, tick(2_000), 2_000_000_000)
        .unwrap();

    assert!(matches!(
        controller.status(),
        CoordinationStatus::Completed(StopCondition::WorkCompleted)
    ));

    let receipt = controller
        .record_advisory_objective(0, best_possible_score("work-1", 2_100), 2_150)
        .unwrap();
    assert!(receipt.is_none());

    let spawn = controller.prepare_session_spawn("work-1", 101, 3_000_000_000);
    assert!(matches!(
        spawn,
        Err(ControllerError::CoordinationTerminal { .. })
    ));
}

#[test]
fn test_advisory_score_no_gate_mutation() {
    let mut controller = test_controller(vec!["work-1".to_string(), "work-2".to_string()], 3);
    controller.start(tick(1_000), 1_000_000_000).unwrap();

    let before_failures = controller.consecutive_failures();
    let before_budget = controller.budget_usage().clone();
    let before_tracking = tracking_snapshot(&controller);
    let before_stop = controller.check_stop_condition();

    let receipt = controller
        .record_advisory_objective(0, best_possible_score("work-1", 1_200), 1_250)
        .unwrap();
    assert!(receipt.is_none());

    let after_failures = controller.consecutive_failures();
    let after_budget = controller.budget_usage().clone();
    let after_tracking = tracking_snapshot(&controller);
    let after_stop = controller.check_stop_condition();

    assert_eq!(before_failures, after_failures);
    assert_eq!(before_budget, after_budget);
    assert_eq!(before_tracking, after_tracking);
    assert_eq!(before_stop, after_stop);
}

#[test]
fn test_advisory_score_type_has_no_auth_methods() {
    let score = best_possible_score("work-1", 1_000);

    let _: f64 = score.efe_score();
    let _: &str = score.work_id();
    let _: &EfeComponents = score.components();
    let _: &EfeWeights = score.weights();
    let _: Hash = score.objective_inputs_hash();
}

#[test]
fn test_receipt_emitted_at_tier3_threshold() {
    let mut controller = test_controller(vec!["work-1".to_string()], 5);
    controller.start(tick(1_000), 1_000_000_000).unwrap();

    for attempt in 0..TIER3_ESCALATION_THRESHOLD {
        let spawn = controller
            .prepare_session_spawn("work-1", 100 + u64::from(attempt), 2_000_000_000)
            .unwrap();
        controller
            .record_session_termination(
                &spawn.session_id,
                "work-1",
                SessionOutcome::Failure,
                5,
                tick(2_000 + u64::from(attempt)),
                3_000_000_000,
            )
            .unwrap();
    }

    let receipt = controller
        .record_advisory_objective(0, best_possible_score("work-1", 4_000), 4_444)
        .unwrap()
        .expect("receipt should be emitted at tier3 threshold");

    assert_eq!(receipt.schema_version, OBJECTIVE_RECEIPT_SCHEMA_VERSION);
    assert_eq!(receipt.escalation_count, TIER3_ESCALATION_THRESHOLD);
    assert_eq!(receipt.work_id, "work-1");
    assert_eq!(receipt.computed_at_tick, 4_000);
    assert_eq!(receipt.emitted_at_tick, 4_444);
    assert_eq!(
        receipt.coordination_id,
        controller.coordination_id().unwrap()
    );
}

#[test]
fn test_receipt_not_emitted_below_threshold() {
    let mut controller = test_controller(vec!["work-1".to_string()], 5);
    controller.start(tick(1_000), 1_000_000_000).unwrap();

    for attempt in 0..(TIER3_ESCALATION_THRESHOLD - 1) {
        let spawn = controller
            .prepare_session_spawn("work-1", 100 + u64::from(attempt), 2_000_000_000)
            .unwrap();
        controller
            .record_session_termination(
                &spawn.session_id,
                "work-1",
                SessionOutcome::Failure,
                5,
                tick(2_000 + u64::from(attempt)),
                3_000_000_000,
            )
            .unwrap();
    }

    let receipt = controller
        .record_advisory_objective(0, best_possible_score("work-1", 4_000), 4_111)
        .unwrap();
    assert!(receipt.is_none());
}

#[test]
fn test_receipt_hash_deterministic() {
    let objective = EfeObjective::new(
        "work-1".to_string(),
        EfeComponents::new(0.2, 0.3, 0.4).unwrap(),
        EfeWeights::new(0.8, 0.6, 0.4).unwrap(),
        42,
    )
    .unwrap();

    let receipt_a = CoordinationObjectiveReceiptV1::new("coord-1", &objective, 3, 43).unwrap();
    let receipt_b = CoordinationObjectiveReceiptV1::new("coord-1", &objective, 3, 43).unwrap();

    assert_eq!(receipt_a.compute_hash(), receipt_b.compute_hash());
}

#[test]
fn test_receipt_hash_changes_on_input_change() {
    let objective = EfeObjective::new(
        "work-1".to_string(),
        EfeComponents::new(0.2, 0.3, 0.4).unwrap(),
        EfeWeights::new(0.8, 0.6, 0.4).unwrap(),
        42,
    )
    .unwrap();

    let receipt_a = CoordinationObjectiveReceiptV1::new("coord-1", &objective, 3, 43).unwrap();
    let receipt_b = CoordinationObjectiveReceiptV1::new("coord-1", &objective, 4, 43).unwrap();

    assert_ne!(receipt_a.compute_hash(), receipt_b.compute_hash());
}

#[test]
fn test_receipt_contains_objective_inputs_hash() {
    let objective = EfeObjective::new(
        "work-1".to_string(),
        EfeComponents::new(0.2, 0.3, 0.4).unwrap(),
        EfeWeights::new(0.8, 0.6, 0.4).unwrap(),
        42,
    )
    .unwrap();

    let receipt = CoordinationObjectiveReceiptV1::new("coord-1", &objective, 3, 43).unwrap();
    assert_eq!(
        receipt.objective_inputs_hash,
        objective.objective_inputs_hash()
    );
}

#[test]
fn test_receipt_verify_roundtrip() {
    let objective = EfeObjective::new(
        "work-1".to_string(),
        EfeComponents::new(0.2, 0.3, 0.4).unwrap(),
        EfeWeights::new(0.8, 0.6, 0.4).unwrap(),
        42,
    )
    .unwrap();

    let receipt = CoordinationObjectiveReceiptV1::new("coord-1", &objective, 3, 43).unwrap();
    let hash = receipt.compute_hash();
    assert!(receipt.verify(&hash));
}

#[test]
fn test_receipt_verify_tamper_detection() {
    let objective = EfeObjective::new(
        "work-1".to_string(),
        EfeComponents::new(0.2, 0.3, 0.4).unwrap(),
        EfeWeights::new(0.8, 0.6, 0.4).unwrap(),
        42,
    )
    .unwrap();

    let receipt = CoordinationObjectiveReceiptV1::new("coord-1", &objective, 3, 43).unwrap();
    let hash = receipt.compute_hash();

    let mut tampered = receipt;
    tampered.escalation_count = tampered.escalation_count.saturating_add(1);

    assert!(!tampered.verify(&hash));
}

#[test]
fn test_work_id_too_long_rejected() {
    let work_id = "w".repeat(MAX_PLANNER_WORK_ID_LEN + 1);
    let result = EfeObjective::new(
        work_id,
        EfeComponents::new(0.1, 0.2, 0.3).unwrap(),
        EfeWeights::default(),
        10,
    );

    assert!(matches!(
        result,
        Err(PlannerError::FieldTooLong {
            field: "work_id",
            ..
        })
    ));
}

#[test]
fn test_coordination_id_too_long_rejected() {
    let objective = EfeObjective::new(
        "work-1".to_string(),
        EfeComponents::new(0.1, 0.2, 0.3).unwrap(),
        EfeWeights::default(),
        10,
    )
    .unwrap();

    let coordination_id = "c".repeat(MAX_PLANNER_COORDINATION_ID_LEN + 1);
    let result = CoordinationObjectiveReceiptV1::new(coordination_id, &objective, 3, 11);

    assert!(matches!(
        result,
        Err(PlannerError::FieldTooLong {
            field: "coordination_id",
            ..
        })
    ));
}

#[test]
fn test_max_objectives_limit() {
    let work_ids: Vec<String> = (0..=MAX_TRACKED_OBJECTIVES)
        .map(|index| format!("work-{index}"))
        .collect();

    let config = CoordinationConfig::with_max_queue_size(
        work_ids,
        test_budget(),
        3,
        MAX_TRACKED_OBJECTIVES + 1,
    )
    .unwrap();
    let mut controller = CoordinationController::new(config);

    for index in 0..MAX_TRACKED_OBJECTIVES {
        let score = best_possible_score(&format!("work-{index}"), index as u64);
        let result = controller
            .record_advisory_objective(index, score, index as u64)
            .unwrap();
        assert!(result.is_none());
    }

    let overflow = best_possible_score(&format!("work-{MAX_TRACKED_OBJECTIVES}"), 9_999);
    let err = controller
        .record_advisory_objective(MAX_TRACKED_OBJECTIVES, overflow, 10_000)
        .unwrap_err();
    assert!(matches!(err, ControllerError::Internal { .. }));
    if let ControllerError::Internal { message } = err {
        assert!(message.contains("objective limit exceeded"));
    }
}

#[test]
fn test_efe_objective_serde_roundtrip() {
    let objective = EfeObjective::new(
        "work-1".to_string(),
        EfeComponents::new(0.1, 0.2, 0.3).unwrap(),
        EfeWeights::new(0.3, 0.5, 0.7).unwrap(),
        42,
    )
    .unwrap();

    let encoded = serde_json::to_vec(&objective).unwrap();
    let decoded: EfeObjective = serde_json::from_slice(&encoded).unwrap();
    assert_eq!(decoded, objective);
}

#[test]
fn test_receipt_serde_roundtrip() {
    let objective = EfeObjective::new(
        "work-1".to_string(),
        EfeComponents::new(0.1, 0.2, 0.3).unwrap(),
        EfeWeights::new(0.3, 0.5, 0.7).unwrap(),
        42,
    )
    .unwrap();

    let receipt = CoordinationObjectiveReceiptV1::new("coord-1", &objective, 3, 43).unwrap();
    let encoded = serde_json::to_vec(&receipt).unwrap();
    let decoded: CoordinationObjectiveReceiptV1 = serde_json::from_slice(&encoded).unwrap();
    assert_eq!(decoded, receipt);
}

#[test]
fn test_advisory_score_ordering() {
    let low = planner_score("work-low", EfeComponents::new(0.1, 0.1, 0.1).unwrap(), 10);
    let high = planner_score("work-high", EfeComponents::new(0.9, 0.9, 0.9).unwrap(), 10);
    let medium = planner_score(
        "work-medium",
        EfeComponents::new(0.4, 0.4, 0.4).unwrap(),
        10,
    );

    let mut scores = [high, medium, low];
    scores.sort();

    assert_eq!(scores[0].work_id(), "work-low");
    assert_eq!(scores[1].work_id(), "work-medium");
    assert_eq!(scores[2].work_id(), "work-high");
}

#[test]
fn test_advisory_score_lookup_returns_latest_score() {
    let mut controller = test_controller(vec!["work-1".to_string()], 3);
    controller.start(tick(1_000), 1_000_000_000).unwrap();

    let first = planner_score("work-1", EfeComponents::new(0.7, 0.7, 0.7).unwrap(), 1_100);
    controller
        .record_advisory_objective(0, first, 1_150)
        .unwrap();

    let second = planner_score("work-1", EfeComponents::new(0.2, 0.2, 0.2).unwrap(), 1_200);
    controller
        .record_advisory_objective(0, second.clone(), 1_250)
        .unwrap();

    let latest = controller.advisory_score_for(0).unwrap();
    assert_eq!(latest.efe_score(), second.efe_score());
}

#[test]
fn test_advisory_score_lookup_is_index_scoped_for_duplicate_work_ids() {
    let mut controller = test_controller(vec!["dup".to_string(), "dup".to_string()], 3);
    controller.start(tick(1_000), 1_000_000_000).unwrap();

    let first = planner_score("dup", EfeComponents::new(0.8, 0.8, 0.8).unwrap(), 1_100);
    let second = planner_score("dup", EfeComponents::new(0.1, 0.1, 0.1).unwrap(), 1_200);

    controller
        .record_advisory_objective(0, first.clone(), 1_150)
        .unwrap();
    controller
        .record_advisory_objective(1, second.clone(), 1_250)
        .unwrap();

    let score_0 = controller.advisory_score_for(0).unwrap();
    let score_1 = controller.advisory_score_for(1).unwrap();
    assert_eq!(score_0.efe_score(), first.efe_score());
    assert_eq!(score_1.efe_score(), second.efe_score());
}

#[test]
fn test_advisory_record_rejects_out_of_bounds_work_index() {
    let mut controller = test_controller(vec!["work-1".to_string()], 3);

    let err = controller
        .record_advisory_objective(1, best_possible_score("work-1", 1_200), 1_250)
        .unwrap_err();
    assert!(matches!(err, ControllerError::Internal { .. }));
}

#[test]
fn test_advisory_record_requires_known_work_id() {
    let mut controller = test_controller(vec!["work-1".to_string()], 3);
    controller.start(tick(1_000), 1_000_000_000).unwrap();

    let unknown = best_possible_score("unknown-work", 1_200);
    let err = controller
        .record_advisory_objective(0, unknown, 1_250)
        .unwrap_err();

    assert!(matches!(err, ControllerError::WorkNotFound { .. }));
}

#[test]
fn test_advisory_score_revalidates_components_and_weights() {
    let objective_json = serde_json::json!({
        "work_id": "work-1",
        "components": {
            "expected_policy_violation": 2.0,
            "expected_evidence_ambiguity": 0.2,
            "expected_resource_cost": 0.3
        },
        "weights": {
            "lambda_risk": 0.1,
            "lambda_uncertainty": 0.2,
            "lambda_cost": 0.3
        },
        "efe_score": 0.4,
        "computed_at_tick": 42
    });
    let objective: EfeObjective = serde_json::from_value(objective_json).unwrap();

    let err = AdvisoryPlannerScore::new(objective).unwrap_err();
    assert!(matches!(
        err,
        PlannerError::OutOfRange {
            field: "expected_policy_violation",
            ..
        }
    ));
}

#[test]
fn test_terminal_abort_state_unaffected_by_advisory_score() {
    let mut controller = test_controller(vec!["work-1".to_string()], 3);
    controller.start(tick(1_000), 1_000_000_000).unwrap();
    controller
        .abort(
            AbortReason::Cancelled {
                reason: "test".to_string(),
            },
            tick(2_000),
            2_000_000_000,
        )
        .unwrap();

    assert!(matches!(
        controller.status(),
        CoordinationStatus::Aborted(AbortReason::Cancelled { .. })
    ));

    let receipt = controller
        .record_advisory_objective(0, best_possible_score("work-1", 2_100), 2_150)
        .unwrap();
    assert!(receipt.is_none());

    assert!(matches!(
        controller.status(),
        CoordinationStatus::Aborted(AbortReason::Cancelled { .. })
    ));
}
