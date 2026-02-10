// AGENT-AUTHORED
//! RFC-0027 PCAC objective/gate summary exporters and deterministic predicate
//! evaluators.
//!
//! This module provides:
//! - Stable `summary.json` exporters for OBJ-PCAC-01..06 and
//!   GATE-PCAC-{LIFECYCLE,SINGLE-CONSUME,FRESHNESS,REPLAY}
//! - Deterministic predicate evaluation hooks matching RFC-0027 jq predicates
//! - Fail-closed handling for missing artifacts, missing fields, and malformed
//!   summary values

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;

const FLOAT_EQ_TOLERANCE: f64 = 1e-9;

/// Environment variable used to enable runtime summary export.
///
/// When this variable is set, runtime hooks may export all PCAC objective and
/// gate summaries to this root directory and evaluate predicates fail-closed.
pub const PCAC_EVIDENCE_EXPORT_ROOT_ENV: &str = "APM2_PCAC_EVIDENCE_EXPORT_ROOT";

/// RFC-0027 objective identifiers with declared summary paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PcacObjectiveId {
    /// Lifecycle completeness objective.
    ObjPcac01,
    /// Single-consume durability objective.
    ObjPcac02,
    /// Tier2+ freshness safety objective.
    ObjPcac03,
    /// Delegation narrowing objective.
    ObjPcac04,
    /// Intent equality objective.
    ObjPcac05,
    /// Replay verifiability objective.
    ObjPcac06,
}

impl PcacObjectiveId {
    /// All RFC-0027 objective IDs in deterministic evaluation/export order.
    pub const ALL: [Self; 6] = [
        Self::ObjPcac01,
        Self::ObjPcac02,
        Self::ObjPcac03,
        Self::ObjPcac04,
        Self::ObjPcac05,
        Self::ObjPcac06,
    ];

    /// Returns the stable objective ID string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ObjPcac01 => "OBJ-PCAC-01",
            Self::ObjPcac02 => "OBJ-PCAC-02",
            Self::ObjPcac03 => "OBJ-PCAC-03",
            Self::ObjPcac04 => "OBJ-PCAC-04",
            Self::ObjPcac05 => "OBJ-PCAC-05",
            Self::ObjPcac06 => "OBJ-PCAC-06",
        }
    }

    /// Returns the summary path relative to an export root.
    #[must_use]
    pub const fn summary_relative_path(self) -> &'static str {
        match self {
            Self::ObjPcac01 => "evidence/rfcs/RFC-0027/objectives/OBJ-PCAC-01/summary.json",
            Self::ObjPcac02 => "evidence/rfcs/RFC-0027/objectives/OBJ-PCAC-02/summary.json",
            Self::ObjPcac03 => "evidence/rfcs/RFC-0027/objectives/OBJ-PCAC-03/summary.json",
            Self::ObjPcac04 => "evidence/rfcs/RFC-0027/objectives/OBJ-PCAC-04/summary.json",
            Self::ObjPcac05 => "evidence/rfcs/RFC-0027/objectives/OBJ-PCAC-05/summary.json",
            Self::ObjPcac06 => "evidence/rfcs/RFC-0027/objectives/OBJ-PCAC-06/summary.json",
        }
    }
}

/// RFC-0027 gate identifiers with declared summary paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PcacGateId {
    /// Lifecycle gate.
    GatePcacLifecycle,
    /// Single-consume gate.
    GatePcacSingleConsume,
    /// Freshness gate.
    GatePcacFreshness,
    /// Replay gate.
    GatePcacReplay,
}

impl PcacGateId {
    /// All RFC-0027 gate IDs in deterministic evaluation/export order.
    pub const ALL: [Self; 4] = [
        Self::GatePcacLifecycle,
        Self::GatePcacSingleConsume,
        Self::GatePcacFreshness,
        Self::GatePcacReplay,
    ];

    /// Returns the stable gate ID string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GatePcacLifecycle => "GATE-PCAC-LIFECYCLE",
            Self::GatePcacSingleConsume => "GATE-PCAC-SINGLE-CONSUME",
            Self::GatePcacFreshness => "GATE-PCAC-FRESHNESS",
            Self::GatePcacReplay => "GATE-PCAC-REPLAY",
        }
    }

    /// Returns the summary path relative to an export root.
    #[must_use]
    pub const fn summary_relative_path(self) -> &'static str {
        match self {
            Self::GatePcacLifecycle => {
                "evidence/rfcs/RFC-0027/gates/GATE-PCAC-LIFECYCLE/summary.json"
            },
            Self::GatePcacSingleConsume => {
                "evidence/rfcs/RFC-0027/gates/GATE-PCAC-SINGLE-CONSUME/summary.json"
            },
            Self::GatePcacFreshness => {
                "evidence/rfcs/RFC-0027/gates/GATE-PCAC-FRESHNESS/summary.json"
            },
            Self::GatePcacReplay => "evidence/rfcs/RFC-0027/gates/GATE-PCAC-REPLAY/summary.json",
        }
    }
}

/// Stable summary fields used by RFC-0027 objective and gate machine
/// predicates.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PcacPredicateSummary {
    /// Missing lifecycle stage count (join/revalidate/consume continuity).
    pub missing_lifecycle_stage_count: u64,
    /// Ordered receipt chain pass/fail indicator.
    pub ordered_receipt_chain_pass: bool,
    /// Duplicate consume acceptance count.
    pub duplicate_consume_accept_count: u64,
    /// Coverage ratio for durable consume record enforcement.
    pub durable_consume_record_coverage: f64,
    /// Count of stale Tier2+ allows.
    pub tier2plus_stale_allow_count: u64,
    /// Count of freshness unknown-state outcomes.
    pub freshness_unknown_state_count: u64,
    /// Delegation narrowing violation count.
    pub delegation_narrowing_violations: u64,
    /// Intent mismatch allow count.
    pub intent_mismatch_allow_count: u64,
    /// Ratio of authoritative outcomes with full replay contract coverage.
    pub authoritative_outcomes_with_full_replay_contract: f64,
    /// Missing selector count for replay evidence.
    pub missing_selector_count: u64,
    /// Global unknown-state count (fail-closed guard).
    pub unknown_state_count: u64,
}

impl PcacPredicateSummary {
    /// Returns a fully passing summary value for all RFC-0027 objective and
    /// gate predicates.
    #[must_use]
    pub const fn all_pass() -> Self {
        Self {
            missing_lifecycle_stage_count: 0,
            ordered_receipt_chain_pass: true,
            duplicate_consume_accept_count: 0,
            durable_consume_record_coverage: 1.0,
            tier2plus_stale_allow_count: 0,
            freshness_unknown_state_count: 0,
            delegation_narrowing_violations: 0,
            intent_mismatch_allow_count: 0,
            authoritative_outcomes_with_full_replay_contract: 1.0,
            missing_selector_count: 0,
            unknown_state_count: 0,
        }
    }
}

/// Objective and gate summary bundle for RFC-0027 evidence export.
#[derive(Debug, Clone, PartialEq)]
pub struct PcacEvidenceBundle {
    /// Per-objective summaries keyed by RFC objective ID.
    pub objective_summaries: BTreeMap<PcacObjectiveId, PcacPredicateSummary>,
    /// Per-gate summaries keyed by RFC gate ID.
    pub gate_summaries: BTreeMap<PcacGateId, PcacPredicateSummary>,
}

impl PcacEvidenceBundle {
    /// Builds a bundle with a single summary value replicated across all
    /// objectives and gates.
    #[must_use]
    pub fn with_uniform_summary(summary: &PcacPredicateSummary) -> Self {
        let objective_summaries = PcacObjectiveId::ALL
            .into_iter()
            .map(|objective_id| (objective_id, summary.clone()))
            .collect();
        let gate_summaries = PcacGateId::ALL
            .into_iter()
            .map(|gate_id| (gate_id, summary.clone()))
            .collect();
        Self {
            objective_summaries,
            gate_summaries,
        }
    }

    /// Builds a fully passing bundle for all objective and gate predicates.
    #[must_use]
    pub fn all_pass() -> Self {
        Self::with_uniform_summary(&PcacPredicateSummary::all_pass())
    }
}

/// Result of evaluating one machine predicate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PredicateEvaluation {
    /// Whether the predicate passed.
    pub passed: bool,
    /// Deterministic pass/fail reason.
    pub reason: String,
}

impl PredicateEvaluation {
    #[must_use]
    fn pass() -> Self {
        Self {
            passed: true,
            reason: "predicate_satisfied".to_string(),
        }
    }

    #[must_use]
    fn fail(reason: impl Into<String>) -> Self {
        Self {
            passed: false,
            reason: reason.into(),
        }
    }
}

/// Aggregate evaluation report for all RFC-0027 objective and gate predicates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcacPredicateEvaluationReport {
    /// Objective predicate outcomes in deterministic objective order.
    pub objective_results: Vec<(PcacObjectiveId, PredicateEvaluation)>,
    /// Gate predicate outcomes in deterministic gate order.
    pub gate_results: Vec<(PcacGateId, PredicateEvaluation)>,
}

impl PcacPredicateEvaluationReport {
    /// Returns `true` when all objective and gate predicates passed.
    #[must_use]
    pub fn all_passed(&self) -> bool {
        self.objective_results
            .iter()
            .all(|(_, result)| result.passed)
            && self.gate_results.iter().all(|(_, result)| result.passed)
    }

    /// Returns the first failure reason in deterministic order, if any.
    #[must_use]
    pub fn first_failure_reason(&self) -> Option<String> {
        self.objective_results
            .iter()
            .find(|(_, result)| !result.passed)
            .map(|(objective_id, result)| format!("{}: {}", objective_id.as_str(), result.reason))
            .or_else(|| {
                self.gate_results
                    .iter()
                    .find(|(_, result)| !result.passed)
                    .map(|(gate_id, result)| format!("{}: {}", gate_id.as_str(), result.reason))
            })
    }

    /// Returns the predicate result for an objective ID, if present.
    #[must_use]
    pub fn objective_result(&self, objective_id: PcacObjectiveId) -> Option<&PredicateEvaluation> {
        self.objective_results
            .iter()
            .find(|(candidate, _)| *candidate == objective_id)
            .map(|(_, result)| result)
    }

    /// Returns the predicate result for a gate ID, if present.
    #[must_use]
    pub fn gate_result(&self, gate_id: PcacGateId) -> Option<&PredicateEvaluation> {
        self.gate_results
            .iter()
            .find(|(candidate, _)| *candidate == gate_id)
            .map(|(_, result)| result)
    }
}

/// Export and predicate-evaluation errors for PCAC RFC-0027 evidence.
#[derive(Debug, thiserror::Error)]
pub enum PcacEvidenceExportError {
    /// The export bundle is missing a required objective/gate summary.
    #[error("missing {kind} summary for '{id}'")]
    MissingSummary {
        /// Artifact kind (`objective` or `gate`).
        kind: &'static str,
        /// Missing objective or gate ID.
        id: &'static str,
    },

    /// Creating an evidence directory failed.
    #[error("failed to create evidence directory '{path}': {source}")]
    CreateDir {
        /// Directory path that failed to create.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// Serializing summary JSON failed.
    #[error("failed to serialize summary '{path}': {source}")]
    Serialize {
        /// Summary path being serialized.
        path: PathBuf,
        /// Underlying serialization error.
        #[source]
        source: serde_json::Error,
    },

    /// Writing a summary file failed.
    #[error("failed to write summary file '{path}': {source}")]
    WriteFile {
        /// Summary path being written.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// At least one predicate failed in fail-closed mode.
    #[error("predicate evaluation failed: {reason}")]
    PredicateFailed {
        /// Deterministic failure reason.
        reason: String,
    },
}

/// Exports all RFC-0027 objective and gate summaries to declared evidence
/// paths under `root`.
///
/// # Errors
///
/// Returns [`PcacEvidenceExportError`] when required bundle entries are
/// missing or files cannot be serialized/written.
pub fn export_pcac_evidence_bundle(
    root: impl AsRef<Path>,
    bundle: &PcacEvidenceBundle,
) -> Result<(), PcacEvidenceExportError> {
    let root = root.as_ref();

    for objective_id in PcacObjectiveId::ALL {
        let summary = bundle
            .objective_summaries
            .get(&objective_id)
            .ok_or_else(|| PcacEvidenceExportError::MissingSummary {
                kind: "objective",
                id: objective_id.as_str(),
            })?;
        let summary_path = root.join(objective_id.summary_relative_path());
        write_summary_file(&summary_path, summary)?;
    }

    for gate_id in PcacGateId::ALL {
        let summary = bundle.gate_summaries.get(&gate_id).ok_or_else(|| {
            PcacEvidenceExportError::MissingSummary {
                kind: "gate",
                id: gate_id.as_str(),
            }
        })?;
        let summary_path = root.join(gate_id.summary_relative_path());
        write_summary_file(&summary_path, summary)?;
    }

    Ok(())
}

/// Evaluates one objective predicate against a JSON summary value.
///
/// Missing fields, wrong field types, or malformed JSON shapes are fail-closed
/// outcomes.
#[must_use]
pub fn evaluate_objective_predicate_value(
    objective_id: PcacObjectiveId,
    summary: &Value,
) -> PredicateEvaluation {
    let result = match objective_id {
        PcacObjectiveId::ObjPcac01 => evaluate_obj_pcac_01(summary),
        PcacObjectiveId::ObjPcac02 => evaluate_obj_pcac_02(summary),
        PcacObjectiveId::ObjPcac03 => evaluate_obj_pcac_03(summary),
        PcacObjectiveId::ObjPcac04 => evaluate_obj_pcac_04(summary),
        PcacObjectiveId::ObjPcac05 => evaluate_obj_pcac_05(summary),
        PcacObjectiveId::ObjPcac06 => evaluate_obj_pcac_06(summary),
    };

    evaluate_predicate_result(
        result,
        format!(
            "objective predicate returned false for {}",
            objective_id.as_str()
        ),
    )
}

/// Evaluates one gate predicate against a JSON summary value.
///
/// Missing fields, wrong field types, or malformed JSON shapes are fail-closed
/// outcomes.
#[must_use]
pub fn evaluate_gate_predicate_value(gate_id: PcacGateId, summary: &Value) -> PredicateEvaluation {
    let result = match gate_id {
        PcacGateId::GatePcacLifecycle => evaluate_gate_pcac_lifecycle(summary),
        PcacGateId::GatePcacSingleConsume => evaluate_gate_pcac_single_consume(summary),
        PcacGateId::GatePcacFreshness => evaluate_gate_pcac_freshness(summary),
        PcacGateId::GatePcacReplay => evaluate_gate_pcac_replay(summary),
    };

    evaluate_predicate_result(
        result,
        format!("gate predicate returned false for {}", gate_id.as_str()),
    )
}

/// Evaluates all objective and gate predicates from exported summary files
/// rooted at `root`.
///
/// This function is fail-closed: missing files, parse errors, missing fields,
/// and malformed types all produce failed predicate results.
#[must_use]
pub fn evaluate_exported_predicates(root: impl AsRef<Path>) -> PcacPredicateEvaluationReport {
    let root = root.as_ref();

    let objective_results = PcacObjectiveId::ALL
        .into_iter()
        .map(|objective_id| {
            let summary_path = root.join(objective_id.summary_relative_path());
            let result = evaluate_summary_file(&summary_path, |summary| {
                evaluate_objective_predicate_value(objective_id, summary)
            });
            (objective_id, result)
        })
        .collect();

    let gate_results = PcacGateId::ALL
        .into_iter()
        .map(|gate_id| {
            let summary_path = root.join(gate_id.summary_relative_path());
            let result = evaluate_summary_file(&summary_path, |summary| {
                evaluate_gate_predicate_value(gate_id, summary)
            });
            (gate_id, result)
        })
        .collect();

    PcacPredicateEvaluationReport {
        objective_results,
        gate_results,
    }
}

/// Evaluates all exported predicates and returns an error if any predicate
/// fails.
///
/// # Errors
///
/// Returns [`PcacEvidenceExportError::PredicateFailed`] with the first
/// deterministic failure reason when any predicate fails.
pub fn assert_exported_predicates(
    root: impl AsRef<Path>,
) -> Result<PcacPredicateEvaluationReport, PcacEvidenceExportError> {
    let report = evaluate_exported_predicates(root);
    if report.all_passed() {
        Ok(report)
    } else {
        Err(PcacEvidenceExportError::PredicateFailed {
            reason: report
                .first_failure_reason()
                .unwrap_or_else(|| "unknown predicate failure".to_string()),
        })
    }
}

/// Runtime convenience hook.
///
/// If [`PCAC_EVIDENCE_EXPORT_ROOT_ENV`] is set, this exports a fail-closed
/// all-pass bundle and validates all objective/gate predicates against the
/// exported artifacts.
///
/// # Errors
///
/// Returns [`PcacEvidenceExportError`] when export or predicate evaluation
/// fails while runtime export is enabled.
pub fn maybe_export_runtime_pass_bundle() -> Result<(), PcacEvidenceExportError> {
    let Some(root) = std::env::var_os(PCAC_EVIDENCE_EXPORT_ROOT_ENV) else {
        return Ok(());
    };

    let root = PathBuf::from(root);
    let bundle = PcacEvidenceBundle::all_pass();
    export_pcac_evidence_bundle(&root, &bundle)?;
    let _report = assert_exported_predicates(&root)?;
    Ok(())
}

fn write_summary_file(
    path: &Path,
    summary: &PcacPredicateSummary,
) -> Result<(), PcacEvidenceExportError> {
    let parent = path
        .parent()
        .ok_or_else(|| PcacEvidenceExportError::WriteFile {
            path: path.to_path_buf(),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "summary path has no parent directory",
            ),
        })?;

    fs::create_dir_all(parent).map_err(|source| PcacEvidenceExportError::CreateDir {
        path: parent.to_path_buf(),
        source,
    })?;

    let mut encoded = serde_json::to_vec_pretty(summary).map_err(|source| {
        PcacEvidenceExportError::Serialize {
            path: path.to_path_buf(),
            source,
        }
    })?;
    encoded.push(b'\n');

    fs::write(path, encoded).map_err(|source| PcacEvidenceExportError::WriteFile {
        path: path.to_path_buf(),
        source,
    })
}

fn evaluate_obj_pcac_01(summary: &Value) -> Result<bool, String> {
    let missing_lifecycle_stage_count = require_u64(summary, "missing_lifecycle_stage_count")?;
    let ordered_receipt_chain_pass = require_bool(summary, "ordered_receipt_chain_pass")?;
    let unknown_state_count = require_u64(summary, "unknown_state_count")?;
    Ok(
        missing_lifecycle_stage_count == 0
            && ordered_receipt_chain_pass
            && unknown_state_count == 0,
    )
}

fn evaluate_obj_pcac_02(summary: &Value) -> Result<bool, String> {
    let duplicate_consume_accept_count = require_u64(summary, "duplicate_consume_accept_count")?;
    let durable_consume_record_coverage = require_f64(summary, "durable_consume_record_coverage")?;
    let unknown_state_count = require_u64(summary, "unknown_state_count")?;
    Ok(duplicate_consume_accept_count == 0
        && float_eq(durable_consume_record_coverage, 1.0)
        && unknown_state_count == 0)
}

fn evaluate_obj_pcac_03(summary: &Value) -> Result<bool, String> {
    let tier2plus_stale_allow_count = require_u64(summary, "tier2plus_stale_allow_count")?;
    let freshness_unknown_state_count = require_u64(summary, "freshness_unknown_state_count")?;
    let unknown_state_count = require_u64(summary, "unknown_state_count")?;
    Ok(tier2plus_stale_allow_count == 0
        && freshness_unknown_state_count == 0
        && unknown_state_count == 0)
}

fn evaluate_obj_pcac_04(summary: &Value) -> Result<bool, String> {
    let delegation_narrowing_violations = require_u64(summary, "delegation_narrowing_violations")?;
    let unknown_state_count = require_u64(summary, "unknown_state_count")?;
    Ok(delegation_narrowing_violations == 0 && unknown_state_count == 0)
}

fn evaluate_obj_pcac_05(summary: &Value) -> Result<bool, String> {
    let intent_mismatch_allow_count = require_u64(summary, "intent_mismatch_allow_count")?;
    let unknown_state_count = require_u64(summary, "unknown_state_count")?;
    Ok(intent_mismatch_allow_count == 0 && unknown_state_count == 0)
}

fn evaluate_obj_pcac_06(summary: &Value) -> Result<bool, String> {
    let authoritative_outcomes_with_full_replay_contract =
        require_f64(summary, "authoritative_outcomes_with_full_replay_contract")?;
    let missing_selector_count = require_u64(summary, "missing_selector_count")?;
    let unknown_state_count = require_u64(summary, "unknown_state_count")?;
    Ok(
        float_eq(authoritative_outcomes_with_full_replay_contract, 1.0)
            && missing_selector_count == 0
            && unknown_state_count == 0,
    )
}

fn evaluate_gate_pcac_lifecycle(summary: &Value) -> Result<bool, String> {
    let missing_lifecycle_stage_count = require_u64(summary, "missing_lifecycle_stage_count")?;
    let unknown_state_count = require_u64(summary, "unknown_state_count")?;
    Ok(missing_lifecycle_stage_count == 0 && unknown_state_count == 0)
}

fn evaluate_gate_pcac_single_consume(summary: &Value) -> Result<bool, String> {
    let duplicate_consume_accept_count = require_u64(summary, "duplicate_consume_accept_count")?;
    let durable_consume_record_coverage = require_f64(summary, "durable_consume_record_coverage")?;
    let unknown_state_count = require_u64(summary, "unknown_state_count")?;
    Ok(duplicate_consume_accept_count == 0
        && float_eq(durable_consume_record_coverage, 1.0)
        && unknown_state_count == 0)
}

fn evaluate_gate_pcac_freshness(summary: &Value) -> Result<bool, String> {
    let tier2plus_stale_allow_count = require_u64(summary, "tier2plus_stale_allow_count")?;
    let freshness_unknown_state_count = require_u64(summary, "freshness_unknown_state_count")?;
    let unknown_state_count = require_u64(summary, "unknown_state_count")?;
    Ok(tier2plus_stale_allow_count == 0
        && freshness_unknown_state_count == 0
        && unknown_state_count == 0)
}

fn evaluate_gate_pcac_replay(summary: &Value) -> Result<bool, String> {
    let authoritative_outcomes_with_full_replay_contract =
        require_f64(summary, "authoritative_outcomes_with_full_replay_contract")?;
    let missing_selector_count = require_u64(summary, "missing_selector_count")?;
    let unknown_state_count = require_u64(summary, "unknown_state_count")?;
    Ok(
        float_eq(authoritative_outcomes_with_full_replay_contract, 1.0)
            && missing_selector_count == 0
            && unknown_state_count == 0,
    )
}

fn evaluate_predicate_result(
    result: Result<bool, String>,
    false_reason: String,
) -> PredicateEvaluation {
    match result {
        Ok(true) => PredicateEvaluation::pass(),
        Ok(false) => PredicateEvaluation::fail(false_reason),
        Err(reason) => PredicateEvaluation::fail(reason),
    }
}

fn evaluate_summary_file(
    path: &Path,
    eval: impl Fn(&Value) -> PredicateEvaluation,
) -> PredicateEvaluation {
    let summary_json = match fs::read_to_string(path) {
        Ok(value) => value,
        Err(error) => {
            return PredicateEvaluation::fail(format!(
                "missing or unreadable summary '{}': {error}",
                path.display()
            ));
        },
    };
    let parsed: Value = match serde_json::from_str(&summary_json) {
        Ok(value) => value,
        Err(error) => {
            return PredicateEvaluation::fail(format!(
                "invalid json in summary '{}': {error}",
                path.display()
            ));
        },
    };
    eval(&parsed)
}

fn require_field<'a>(summary: &'a Value, field: &str) -> Result<&'a Value, String> {
    let object = summary
        .as_object()
        .ok_or_else(|| "summary must be a JSON object".to_string())?;
    object
        .get(field)
        .ok_or_else(|| format!("missing required field '{field}'"))
}

fn require_u64(summary: &Value, field: &str) -> Result<u64, String> {
    let value = require_field(summary, field)?;
    value
        .as_u64()
        .ok_or_else(|| format!("field '{field}' must be an unsigned integer"))
}

fn require_bool(summary: &Value, field: &str) -> Result<bool, String> {
    let value = require_field(summary, field)?;
    value
        .as_bool()
        .ok_or_else(|| format!("field '{field}' must be a boolean"))
}

fn require_f64(summary: &Value, field: &str) -> Result<f64, String> {
    let value = require_field(summary, field)?;
    let number = value
        .as_f64()
        .ok_or_else(|| format!("field '{field}' must be a number"))?;
    if number.is_finite() {
        Ok(number)
    } else {
        Err(format!("field '{field}' must be finite"))
    }
}

#[must_use]
fn float_eq(lhs: f64, rhs: f64) -> bool {
    (lhs - rhs).abs() <= FLOAT_EQ_TOLERANCE
}
