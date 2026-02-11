//! TCK-00430: RFC-0027 objective and gate evidence exporters.
//!
//! Verifies:
//! - Objective/gate summaries export to declared RFC-0027 evidence paths
//! - Deterministic predicate evaluation hooks pass for complete summaries
//! - Missing/partial summary fields fail closed
//! - Unknown-state fields enforce non-admissible outcomes

use std::fs;

use apm2_core::pcac::{
    PcacEvidenceBundle, PcacEvidenceExportError, PcacGateId, PcacLifecycleEvidenceState,
    PcacObjectiveId, PcacPredicateSummary, PcacRuntimeExportOutcome, SummarySource,
    assert_exported_predicates, evaluate_exported_predicates, evaluate_gate_predicate_value,
    evaluate_objective_predicate_value, export_pcac_evidence_bundle, export_runtime_bundle_to_root,
};
use serde_json::Value;
use tempfile::TempDir;

#[test]
fn tck_00430_exports_declared_paths_and_predicates_pass() {
    let temp_dir = TempDir::new().expect("tempdir must be created");
    let bundle = PcacEvidenceBundle::with_uniform_summary(
        SummarySource::Observed,
        &PcacPredicateSummary::all_pass(),
    );

    export_pcac_evidence_bundle(temp_dir.path(), &bundle)
        .expect("summary export must succeed for all RFC-0027 objective and gate paths");

    for objective_id in PcacObjectiveId::ALL {
        let path = temp_dir.path().join(objective_id.summary_relative_path());
        assert!(
            path.is_file(),
            "objective summary must exist at declared path: {}",
            path.display()
        );
    }

    for gate_id in PcacGateId::ALL {
        let path = temp_dir.path().join(gate_id.summary_relative_path());
        assert!(
            path.is_file(),
            "gate summary must exist at declared path: {}",
            path.display()
        );
    }

    let report = assert_exported_predicates(temp_dir.path())
        .expect("all exported objective and gate predicates must evaluate deterministically");
    assert!(
        report.all_passed(),
        "all predicates must pass for all-pass summaries"
    );

    let sample_path = temp_dir
        .path()
        .join(PcacObjectiveId::ObjPcac01.summary_relative_path());
    let sample_summary = fs::read_to_string(&sample_path).expect("summary file must be readable");
    assert!(
        sample_summary.contains("\"summary_source\": \"observed\""),
        "exported summary must carry observed source classification"
    );

    let first = fs::read(&sample_path).expect("first read of objective summary must succeed");
    export_pcac_evidence_bundle(temp_dir.path(), &bundle)
        .expect("second deterministic export must succeed");
    let second = fs::read(&sample_path).expect("second read of objective summary must succeed");
    assert_eq!(
        first, second,
        "summary export bytes must be deterministic across repeated exports"
    );
}

#[test]
fn tck_00430_missing_field_fails_closed() {
    let temp_dir = TempDir::new().expect("tempdir must be created");
    let bundle = PcacEvidenceBundle::with_uniform_summary(
        SummarySource::Observed,
        &PcacPredicateSummary::all_pass(),
    );
    export_pcac_evidence_bundle(temp_dir.path(), &bundle).expect("initial export must succeed");

    let objective_path = temp_dir
        .path()
        .join(PcacObjectiveId::ObjPcac02.summary_relative_path());
    let raw = fs::read_to_string(&objective_path)
        .expect("objective summary must be readable before field removal");
    let mut summary_value: Value =
        serde_json::from_str(&raw).expect("objective summary must parse as JSON");

    if let Value::Object(ref mut map) = summary_value {
        map.remove("durable_consume_record_coverage");
    } else {
        panic!("expected objective summary JSON object");
    }

    let updated =
        serde_json::to_vec_pretty(&summary_value).expect("mutated summary must serialize");
    fs::write(&objective_path, updated).expect("mutated summary must be written");

    let report = evaluate_exported_predicates(temp_dir.path());
    let objective_result = report
        .objective_result(PcacObjectiveId::ObjPcac02)
        .expect("objective result must be present");

    assert!(
        !objective_result.passed,
        "missing required field must fail objective predicate closed"
    );
    assert!(
        objective_result
            .reason
            .contains("durable_consume_record_coverage"),
        "failure reason must identify missing required field"
    );
    assert!(
        !report.all_passed(),
        "aggregate predicate report must fail when any required field is missing"
    );
}

#[test]
fn tck_00430_partial_summary_fields_are_non_admissible() {
    let partial_gate_summary = serde_json::json!({
        "summary_source": "observed",
        "duplicate_consume_accept_count": 0u64,
        "unknown_state_count": 0u64
    });
    let gate_eval =
        evaluate_gate_predicate_value(PcacGateId::GatePcacSingleConsume, &partial_gate_summary);
    assert!(
        !gate_eval.passed,
        "partial gate summary must fail closed for missing required predicate fields"
    );
    assert!(
        gate_eval.reason.contains("durable_consume_record_coverage"),
        "failure reason must identify missing coverage field"
    );

    let partial_objective_summary = serde_json::json!({
        "summary_source": "observed",
        "missing_lifecycle_stage_count": 0u64
    });
    let objective_eval =
        evaluate_objective_predicate_value(PcacObjectiveId::ObjPcac01, &partial_objective_summary);
    assert!(
        !objective_eval.passed,
        "partial objective summary must fail closed for missing required predicate fields"
    );
    assert!(
        objective_eval.reason.contains("ordered_receipt_chain_pass"),
        "failure reason must identify missing ordered chain field"
    );
}

#[test]
fn tck_00430_unknown_state_field_enforces_fail_closed() {
    let mut summary_value =
        serde_json::to_value(PcacPredicateSummary::all_pass()).expect("summary must serialize");
    summary_value["summary_source"] = serde_json::json!("observed");
    summary_value["unknown_state_count"] = serde_json::json!(1u64);

    let objective_eval =
        evaluate_objective_predicate_value(PcacObjectiveId::ObjPcac06, &summary_value);
    assert!(
        !objective_eval.passed,
        "unknown_state_count > 0 must deny objective predicate"
    );

    let gate_eval = evaluate_gate_predicate_value(PcacGateId::GatePcacReplay, &summary_value);
    assert!(
        !gate_eval.passed,
        "unknown_state_count > 0 must deny gate predicate"
    );
}

#[test]
fn tck_00430_synthetic_source_is_non_admissible() {
    let temp_dir = TempDir::new().expect("tempdir must be created");
    let bundle = PcacEvidenceBundle::all_pass();
    export_pcac_evidence_bundle(temp_dir.path(), &bundle).expect("export must succeed");

    let report = evaluate_exported_predicates(temp_dir.path());
    assert!(
        !report.all_passed(),
        "synthetic summary source must fail machine predicates"
    );
    let reason = report
        .first_failure_reason()
        .expect("synthetic source failure reason must be present");
    assert!(
        reason.contains("summary_source"),
        "failure reason must mention summary_source gating"
    );
}

#[test]
fn tck_00430_near_one_coverage_values_fail_exact_equality() {
    for near_one in [0.999_999_999_5_f64, 1.000_000_000_1_f64] {
        let mut summary_value =
            serde_json::to_value(PcacPredicateSummary::all_pass()).expect("summary must serialize");
        summary_value["summary_source"] = serde_json::json!("observed");
        summary_value["durable_consume_record_coverage"] = serde_json::json!(near_one);

        let objective_eval =
            evaluate_objective_predicate_value(PcacObjectiveId::ObjPcac02, &summary_value);
        assert!(
            !objective_eval.passed,
            "OBJ-PCAC-02 must require exact 1.0 coverage value; got {near_one}"
        );
        let gate_eval =
            evaluate_gate_predicate_value(PcacGateId::GatePcacSingleConsume, &summary_value);
        assert!(
            !gate_eval.passed,
            "GATE-PCAC-SINGLE-CONSUME must require exact 1.0 coverage value; got {near_one}"
        );

        summary_value["durable_consume_record_coverage"] = serde_json::json!(1.0_f64);
        summary_value["authoritative_outcomes_with_full_replay_contract"] =
            serde_json::json!(near_one);

        let objective_eval =
            evaluate_objective_predicate_value(PcacObjectiveId::ObjPcac06, &summary_value);
        assert!(
            !objective_eval.passed,
            "OBJ-PCAC-06 must require exact 1.0 replay coverage value; got {near_one}"
        );
        let gate_eval = evaluate_gate_predicate_value(PcacGateId::GatePcacReplay, &summary_value);
        assert!(
            !gate_eval.passed,
            "GATE-PCAC-REPLAY must require exact 1.0 replay coverage value; got {near_one}"
        );
    }
}

#[test]
fn tck_00430_runtime_partial_lifecycle_export_is_non_admissible() {
    let temp_dir = TempDir::new().expect("tempdir must be created");
    let lifecycle_state = PcacLifecycleEvidenceState {
        summary_source: SummarySource::PartialLifecycle,
        missing_lifecycle_stage_count: 0,
        ordered_receipt_chain_pass: true,
        duplicate_consume_accept_count: Some(0),
        durable_consume_record_coverage: Some(1.0),
        tier2plus_stale_allow_count: None,
        freshness_unknown_state_count: None,
        delegation_narrowing_violations: None,
        intent_mismatch_allow_count: Some(0),
        authoritative_outcomes_with_full_replay_contract: None,
        missing_selector_count: None,
        unknown_state_count: 0,
    };

    let outcome = export_runtime_bundle_to_root(temp_dir.path(), &lifecycle_state)
        .expect("runtime export with partial lifecycle metrics must still emit bundle");
    let reason = match outcome {
        PcacRuntimeExportOutcome::NonAdmissible { reason } => reason,
        other => panic!("expected non-admissible runtime export outcome, got {other:?}"),
    };
    assert!(
        reason.contains("summary_source"),
        "non-admissible reason must explain summary_source classification"
    );

    let sample_path = temp_dir
        .path()
        .join(PcacObjectiveId::ObjPcac01.summary_relative_path());
    let sample_summary = fs::read_to_string(&sample_path).expect("summary file must be readable");
    assert!(
        sample_summary.contains("\"summary_source\": \"partial_lifecycle\""),
        "runtime lifecycle export must carry partial_lifecycle summary_source"
    );
}

#[test]
fn tck_00430_runtime_export_rejects_relative_root() {
    let lifecycle_state = PcacLifecycleEvidenceState {
        summary_source: SummarySource::PartialLifecycle,
        missing_lifecycle_stage_count: 0,
        ordered_receipt_chain_pass: true,
        duplicate_consume_accept_count: Some(0),
        durable_consume_record_coverage: Some(1.0),
        tier2plus_stale_allow_count: None,
        freshness_unknown_state_count: None,
        delegation_narrowing_violations: None,
        intent_mismatch_allow_count: Some(0),
        authoritative_outcomes_with_full_replay_contract: None,
        missing_selector_count: None,
        unknown_state_count: 0,
    };

    let err = export_runtime_bundle_to_root("relative-export-root", &lifecycle_state)
        .expect_err("relative export root must be rejected");
    assert!(
        matches!(err, PcacEvidenceExportError::InvalidExportRoot { .. }),
        "relative path must fail root confinement validation"
    );
}

#[cfg(unix)]
#[test]
fn tck_00430_runtime_export_rejects_symlink_root() {
    use std::os::unix::fs::symlink;

    let temp_dir = TempDir::new().expect("tempdir must be created");
    let target_root = temp_dir.path().join("root");
    fs::create_dir(&target_root).expect("target root must be created");
    let symlink_root = temp_dir.path().join("root-link");
    symlink(&target_root, &symlink_root).expect("symlink root must be created");

    let lifecycle_state = PcacLifecycleEvidenceState {
        summary_source: SummarySource::PartialLifecycle,
        missing_lifecycle_stage_count: 0,
        ordered_receipt_chain_pass: true,
        duplicate_consume_accept_count: Some(0),
        durable_consume_record_coverage: Some(1.0),
        tier2plus_stale_allow_count: None,
        freshness_unknown_state_count: None,
        delegation_narrowing_violations: None,
        intent_mismatch_allow_count: Some(0),
        authoritative_outcomes_with_full_replay_contract: None,
        missing_selector_count: None,
        unknown_state_count: 0,
    };

    let err = export_runtime_bundle_to_root(&symlink_root, &lifecycle_state)
        .expect_err("symlink export root must be rejected");
    let PcacEvidenceExportError::InvalidExportRoot { reason, .. } = err else {
        panic!("expected invalid export root error for symlink root");
    };
    assert!(
        reason.contains("symlink"),
        "symlink root rejection reason must mention symlink traversal"
    );
}
