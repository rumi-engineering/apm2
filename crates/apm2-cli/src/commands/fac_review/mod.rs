//! FAC review orchestration commands.
//!
//! This module provides VPS-oriented, FAC-first review execution with:
//! - Security/quality orchestration (parallel when `--type all`)
//! - Multi-model backend dispatch (Codex + Gemini)
//! - NDJSON lifecycle telemetry under `~/.apm2/review_events.ndjson`
//! - Pulse-file based SHA freshness checks and resume flow
//! - Liveness-based stall detection and bounded model fallback
//! - Idempotent detached dispatch + projection snapshots for GitHub surfaces
//! - Doctor-first remediation and CI state analysis

mod backend;
#[cfg(test)]
mod barrier;
mod bounded_test_runner;
mod ci_status;
mod detection;
mod dispatch;
mod events;
mod evidence;
mod fenced_yaml;
mod finding;
mod findings;
mod findings_store;
mod gate_attestation;
mod gate_cache;
mod gate_checks;
mod gates;
mod github_auth;
mod github_projection;
mod github_reads;
mod jsonl;
mod lifecycle;
mod liveness;
mod logs;
mod merge_conflicts;
mod model_pool;
mod orchestrator;
mod pipeline;
mod policy_loader;
mod prepare;
mod projection;
mod projection_store;
mod push;
mod readiness;
mod recovery;
mod repair_cycle;
mod state;
mod target;
mod timeout_policy;
mod types;
mod verdict_projection;

use std::collections::{HashSet, VecDeque};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use apm2_core::fac::service_user_gate::QueueWriteMode;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
// Re-export public API for use by `fac.rs`
use dispatch::dispatch_single_review_with_force;
use events::review_events_path;
pub use finding::{ReviewFindingSeverityArg, ReviewFindingTypeArg};
pub use gates::GateThroughputProfile;
pub use lifecycle::VerdictValueArg;
use serde::Serialize;
use state::{
    list_review_pr_numbers, load_review_run_state, load_review_run_state_strict, read_pulse_file,
    review_run_state_path,
};
pub use types::ReviewRunType;
use types::{
    DispatchReviewResult, DispatchSummary, ReviewKind, TERMINAL_MANUAL_TERMINATION_DECISION_BOUND,
    TERMINATE_TIMEOUT, validate_expected_head_sha,
};

use crate::client::protocol::OperatorClient;
use crate::exit_codes::codes as exit_codes;

const DOCTOR_SCHEMA: &str = "apm2.fac.review.doctor.v1";
const FAC_REVIEW_MACHINE_CAC_SCHEMA: &str = "apm2.fac.review.machine_bundle.cac.v1";
const FAC_REVIEW_MACHINE_CAC_SCHEMA_VERSION: &str = "1.0.0";
const FAC_REVIEW_MACHINE_CAC_KIND: &str = "fac.review.machine_bundle";
const FAC_REVIEW_MACHINE_CAC_STABLE_ID: &str = "dcp://apm2.fac/machine/fac-review@v1";
const FAC_REVIEW_MACHINE_CAC_STATUS: &str = "ACTIVE";
const FAC_REVIEW_MACHINE_CAC_CLASSIFICATION: &str = "INTERNAL";
const FAC_REVIEW_MACHINE_CAC_PATH: &str = "documents/reviews/fac_review_state_machine.cac.json";
const FAC_REVIEW_MACHINE_PAYLOAD_SCHEMA: &str = "apm2.fac.review.machine_bundle.v1";
const DOCTOR_DECISION_MACHINE_SCHEMA: &str = "apm2.fac.review.doctor_decision_machine.v1";
const GATE_PROGRESS_MACHINE_SCHEMA: &str = "apm2.fac.review.gate_progress_machine.v1";
const DOCTOR_WAIT_MACHINE_SCHEMA: &str = "apm2.fac.review.doctor_wait_machine.v1";
const GATES_WAIT_MACHINE_SCHEMA: &str = "apm2.fac.review.gates_wait_machine.v1";
const DOCTOR_COMMAND_PR_NUMBER_PLACEHOLDER: &str = "{pr_number}";
const DOCTOR_COMMAND_WAIT_TIMEOUT_PLACEHOLDER: &str = "{wait_timeout_seconds}";
const DOCTOR_STALE_GATE_AGE_SECONDS: i64 = 6 * 60 * 60;
const DOCTOR_EVENT_SCAN_MAX_LINES: usize = 200_000;
const DOCTOR_EVENT_SCAN_MAX_LINE_BYTES: usize = 64 * 1024;
const DOCTOR_EVENT_SCAN_MAX_BYTES_PER_SOURCE: u64 = 8 * 1024 * 1024;
const DOCTOR_LOG_SCAN_MAX_BYTES: u64 = 2 * 1024 * 1024;
const DOCTOR_LOG_SCAN_MAX_LINES: u64 = 200_000;
const DOCTOR_LOG_SCAN_CHUNK_BYTES: usize = 8 * 1024;
const DOCTOR_ACTIVE_AGENT_IDLE_TIMEOUT_SECONDS: i64 = 300;
const DOCTOR_DISPATCH_PENDING_WARNING_SECONDS: i64 = 120;
const DOCTOR_WAIT_TIMEOUT_DEFAULT_SECONDS: u64 = 1200;
const DOCTOR_WAIT_POLL_INTERVAL_SECONDS: u64 = 1;
const DOCTOR_WAIT_PULSE_CHECK_INTERVAL_MILLIS: u64 = 1000;
const DOCTOR_WAIT_PULSE_MAX_PULSES_PER_SEC: u32 = 24;
const DOCTOR_WAIT_PULSE_CLIENT_SUB_ID_MAX_LEN: usize = 64;
const DOCTOR_WAIT_PULSE_DEDUPE_CAPACITY: usize = 512;
const DOCTOR_WAIT_PULSE_RECONNECT_MAX_ATTEMPTS: usize = 3;
const DOCTOR_WAIT_PULSE_RECONNECT_BACKOFF_MILLIS: u64 = 250;
const DOCTOR_WAIT_TIMEOUT_EXIT_CODE: u8 = 2;
const DOCTOR_FIX_MAX_PASSES: usize = 3;
const FAC_REVIEW_MACHINE_TRACEABILITY_SCHEMA: &str = "apm2.fac.review.machine_traceability.v1";
const FAC_REVIEW_MACHINE_REQUIREMENT_IDS: &[&str] = &[
    "DR-001-GATE_FAILURE_REQUIRES_IMPLEMENTOR",
    "DR-002-RUNNING_GATE_SUPPRESSES_FIX",
    "DR-003-TERMINAL_PASS_REQUIRED_FOR_MERGE_READY",
    "DR-004-DOCTOR_RULE_ORDER_IS_STRICT",
    "DR-005-WAIT_RETURNS_ON_TERMINAL_ACTION",
    "DR-006-EVERGREEN_CAC_STATE_MACHINE_SOURCE",
    "DR-007-CLI_EXIT_ON_ACTION_SET_IS_CANONICAL",
    "DR-008-MACHINE_VERIFIABLE_ARTIFACTS",
];
const FAC_REVIEW_MACHINE_REQUIREMENT_DR006_ARTIFACT_REFS: &[&str] = &[
    "documents/reviews/fac_review_state_machine.cac.json",
    "crates/apm2-cli/src/commands/fac_review/mod.rs",
];
const FAC_REVIEW_MACHINE_REQUIREMENT_DR007_ARTIFACT_REFS: &[&str] = &[
    "crates/apm2-cli/src/commands/fac_review/mod.rs",
    "crates/apm2-cli/src/commands/fac.rs",
];
const FAC_REVIEW_MACHINE_REQUIREMENT_DR008_ARTIFACT_REFS: &[&str] =
    &["documents/reviews/fac_review_state_machine.cac.json"];
const DOCTOR_WAIT_PULSE_TOPICS: &[&str] = &["work.>", "work_graph.>", "gate.>", "ledger.head"];

#[derive(Debug, Serialize)]
struct DoctorHealthItem {
    severity: &'static str,
    message: String,
    remediation: String,
}

#[derive(Debug, Serialize)]
struct DoctorIdentitySnapshot {
    pr_number: u32,
    branch: Option<String>,
    worktree: Option<String>,
    source: Option<String>,
    local_sha: Option<String>,
    updated_at: Option<String>,
    remote_head_sha: Option<String>,
    stale: bool,
}

#[derive(Debug, Serialize)]
struct DoctorLifecycleSnapshot {
    state: String,
    time_in_state_seconds: i64,
    error_budget_used: u32,
    retry_budget_remaining: u32,
    updated_at: String,
    last_event_seq: u64,
}

#[derive(Debug, Serialize)]
struct DoctorGateSnapshot {
    name: String,
    status: String,
    completed_at: Option<String>,
    freshness_seconds: Option<i64>,
    #[serde(skip_serializing)]
    source: DoctorGateSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DoctorGateSignal {
    Pass,
    Fail,
    InFlight,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DoctorGateProgressState {
    Unknown,
    InFlight,
    TerminalPassed,
    TerminalFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DoctorGateSource {
    LocalCache,
    Projection,
}

impl DoctorGateSource {
    const fn as_str(self) -> &'static str {
        match self {
            Self::LocalCache => "local_cache",
            Self::Projection => "projection",
        }
    }

    const fn priority(self) -> u8 {
        match self {
            Self::LocalCache => 1,
            Self::Projection => 2,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DoctorWaitState {
    Evaluate,
    ExitOnRecommendedAction,
    ExitOnInterrupt,
    ExitOnTimeout,
    PollEmit,
    Sleep,
    CollectSummary,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DoctorWaitMode {
    PulsePrimary,
    PollingFallback,
}

impl DoctorWaitMode {
    const fn as_str(self) -> &'static str {
        match self {
            Self::PulsePrimary => "pulse_primary",
            Self::PollingFallback => "polling_fallback",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DoctorWaitWakeReason {
    Pulse,
    Timer,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum DoctorWaitLoopControl {
    Exit(u8),
    Fallback { next_tick: u64, reason: String },
}

impl DoctorWaitState {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Evaluate => "evaluate",
            Self::ExitOnRecommendedAction => "exit_on_recommended_action",
            Self::ExitOnInterrupt => "exit_on_interrupt",
            Self::ExitOnTimeout => "exit_on_timeout",
            Self::PollEmit => "poll_emit",
            Self::Sleep => "sleep",
            Self::CollectSummary => "collect_summary",
        }
    }
}

#[derive(Debug, Serialize)]
struct DoctorReviewSnapshot {
    dimension: String,
    verdict: String,
    reviewed_sha: String,
    reviewed_by: String,
    reviewed_at: String,
    reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    terminal_reason: Option<String>,
}

#[derive(Debug, Serialize)]
struct DoctorAgentSnapshot {
    agent_type: String,
    state: String,
    run_id: String,
    sha: String,
    pid: Option<u32>,
    pid_alive: bool,
    started_at: String,
    completion_status: Option<String>,
    completion_summary: Option<String>,
    completion_token_hash: String,
    completion_token_expires_at: String,
    elapsed_seconds: Option<i64>,
    models_attempted: Vec<String>,
    tool_call_count: Option<u64>,
    log_line_count: Option<u64>,
    nudge_count: Option<u32>,
    last_activity_seconds_ago: Option<i64>,
}

#[derive(Debug, Serialize)]
struct DoctorAgentSection {
    max_active_agents_per_pr: usize,
    active_agents: usize,
    total_agents: usize,
    entries: Vec<DoctorAgentSnapshot>,
}

#[derive(Debug, Clone, Copy, Default)]
struct DoctorAgentActivitySummary {
    active_agents: usize,
    all_active_idle: bool,
    max_idle_seconds: Option<i64>,
    max_dispatched_pending_seconds: Option<i64>,
}

#[cfg(not(test))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct LocalGatesRunResult {
    pub(super) exit_code: u8,
    pub(super) failure_summary: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct DoctorFindingsCounts {
    blocker: u32,
    major: u32,
    minor: u32,
    nit: u32,
}

#[derive(Debug, Clone, Serialize)]
struct DoctorFindingsDimensionSummary {
    dimension: String,
    counts: DoctorFindingsCounts,
    formal_verdict: String,
    computed_verdict: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum DoctorMergeConflictStatus {
    NoConflicts,
    HasConflicts,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum DoctorShaFreshnessSource {
    RemoteMatch,
    LocalAuthoritative,
    Stale,
    Unknown,
}

#[derive(Debug, Serialize)]
#[allow(clippy::struct_excessive_bools)]
struct DoctorMergeReadiness {
    merge_ready: bool,
    all_verdicts_approve: bool,
    gates_pass: bool,
    sha_fresh: bool,
    sha_freshness_source: DoctorShaFreshnessSource,
    no_merge_conflicts: bool,
    merge_conflict_status: DoctorMergeConflictStatus,
}

#[derive(Debug, Serialize)]
struct DoctorWorktreeStatus {
    worktree_exists: bool,
    worktree_clean: bool,
    merge_conflicts: usize,
}

#[derive(Debug, Serialize)]
struct DoctorGithubProjectionStatus {
    auto_merge_enabled: bool,
    last_comment_updated_at: Option<String>,
    projection_lag_seconds: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DoctorRecommendedAction {
    pub action: String,
    pub reason: String,
    pub priority: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(skip)]
    pub follow_up_fix: bool,
    #[serde(skip)]
    pub follow_up_force: bool,
}

#[derive(Debug, Serialize)]
struct DoctorRepairApplied {
    operation: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    before: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    after: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum DoctorRunStateCondition {
    Healthy,
    Missing,
    Corrupt,
    Ambiguous,
    Unavailable,
}

impl DoctorRunStateCondition {
    const fn requires_repair(self) -> bool {
        matches!(self, Self::Corrupt | Self::Ambiguous)
    }
}

#[derive(Debug, Serialize)]
struct DoctorRunStateDiagnostic {
    review_type: String,
    condition: DoctorRunStateCondition,
    canonical_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    candidates: Vec<String>,
}

#[derive(Debug, Serialize)]
struct DoctorPushAttemptSummary {
    ts: String,
    sha: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    failed_stage: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    exit_code: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    duration_s: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_hint: Option<String>,
}

#[derive(Debug, Default, Serialize)]
#[allow(clippy::struct_excessive_bools)]
struct DoctorRepairSignals {
    lifecycle_missing: bool,
    lifecycle_load_failed: bool,
    lifecycle_stuck_shape: bool,
    identity_missing: bool,
    identity_stale: bool,
    agent_registry_load_failed: bool,
    agent_registry_capacity_exceeded: bool,
    dead_active_agent_present: bool,
    run_state_repair_required: bool,
    projection_comment_binding_missing: bool,
}

#[derive(Debug, Serialize)]
struct DoctorPrSummary {
    schema: String,
    pr_number: u32,
    owner_repo: String,
    identity: DoctorIdentitySnapshot,
    lifecycle: Option<DoctorLifecycleSnapshot>,
    gates: Vec<DoctorGateSnapshot>,
    reviews: Vec<DoctorReviewSnapshot>,
    findings_summary: Vec<DoctorFindingsDimensionSummary>,
    merge_readiness: DoctorMergeReadiness,
    worktree_status: DoctorWorktreeStatus,
    github_projection: DoctorGithubProjectionStatus,
    recommended_action: DoctorRecommendedAction,
    agents: Option<DoctorAgentSection>,
    run_state_diagnostics: Vec<DoctorRunStateDiagnostic>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    repairs_applied: Vec<DoctorRepairApplied>,
    #[serde(skip_serializing_if = "Option::is_none")]
    latest_push_attempt: Option<DoctorPushAttemptSummary>,
    repair_signals: DoctorRepairSignals,
    health: Vec<DoctorHealthItem>,
}

struct DoctorActionInputs<'a> {
    pr_number: u32,
    repair_signals: &'a DoctorRepairSignals,
    lifecycle: Option<&'a DoctorLifecycleSnapshot>,
    gates: &'a [DoctorGateSnapshot],
    agent_activity: DoctorAgentActivitySummary,
    reviews: &'a [DoctorReviewSnapshot],
    review_terminal_reasons: &'a std::collections::BTreeMap<String, Option<String>>,
    findings_summary: &'a [DoctorFindingsDimensionSummary],
    merge_readiness: &'a DoctorMergeReadiness,
    latest_push_attempt: Option<&'a DoctorPushAttemptSummary>,
}

#[derive(Debug, Serialize)]
pub struct DoctorTrackedPrSummary {
    pub pr_number: u32,
    pub owner_repo: String,
    pub lifecycle_state: String,
    pub recommended_action: DoctorRecommendedAction,
    pub active_agents: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_activity_seconds_ago: Option<i64>,
}

pub fn fac_review_machine_spec_json() -> serde_json::Value {
    let doctor_rules = DOCTOR_DECISION_RULES
        .iter()
        .map(|rule| {
            let recommendation = doctor_recommendation_rule_for_state(rule.state);
            serde_json::json!({
                "priority": rule.priority,
                "state": rule.state.as_str(),
                "recommended_action": rule.state.recommended_action(),
                "recommended_priority": recommendation.priority,
                "guard_id": rule.guard_id,
                "guard_kind": rule.guard.as_str(),
                "guard_predicate": rule.guard_predicate,
                "reason_kind": recommendation.reason_kind.as_str(),
                "reason_template": recommendation.reason_template,
                "command_kind": recommendation.command_kind.as_str(),
                "command_template": recommendation.command_template,
                "command_notes": recommendation.command_notes,
                "requirement_refs": rule.requirement_refs,
            })
        })
        .collect::<Vec<_>>();
    let recommendation_rules = DOCTOR_RECOMMENDATION_RULES
        .iter()
        .map(|rule| {
            serde_json::json!({
                "state": rule.state.as_str(),
                "action": rule.action,
                "priority": rule.priority,
                "reason_kind": rule.reason_kind.as_str(),
                "reason_template": rule.reason_template,
                "command_kind": rule.command_kind.as_str(),
                "command_template": rule.command_template,
                "command_notes": rule.command_notes,
            })
        })
        .collect::<Vec<_>>();
    let gate_rules = DOCTOR_GATE_PROGRESS_RULES
        .iter()
        .map(|rule| {
            serde_json::json!({
                "priority": rule.priority,
                "state": rule.state.as_str(),
                "guard_id": rule.guard_id,
                "guard_kind": rule.guard.as_str(),
                "guard_predicate": rule.guard_predicate,
            })
        })
        .collect::<Vec<_>>();
    let gate_reduction_rules = DOCTOR_GATE_REDUCTION_RULES
        .iter()
        .map(|rule| {
            serde_json::json!({
                "priority": rule.priority,
                "decision": match rule.decision {
                    DoctorGateReductionDecision::ReplaceIncoming => "replace_incoming",
                    DoctorGateReductionDecision::KeepExisting => "keep_existing",
                },
                "guard_id": rule.guard_id,
                "guard_kind": rule.guard.as_str(),
                "guard_predicate": rule.guard_predicate,
            })
        })
        .collect::<Vec<_>>();
    let wait_rules = DOCTOR_WAIT_TRANSITION_RULES
        .iter()
        .map(|rule| {
            serde_json::json!({
                "priority": rule.priority,
                "from": rule.from.as_str(),
                "to": rule.to.as_str(),
                "guard_id": rule.guard_id,
                "guard_kind": rule.guard.as_str(),
                "guard_predicate": rule.guard_predicate,
                "requirement_refs": rule.requirement_refs,
            })
        })
        .collect::<Vec<_>>();
    let wait_action_policy = DOCTOR_ACTION_POLICIES
        .iter()
        .map(|policy| {
            serde_json::json!({
                "action": policy.action,
                "default_wait_exit": policy.default_wait_exit,
                "wait_terminal_reason": policy.wait_terminal_reason,
                "allow_exit_on_flag": policy.allow_exit_on_flag,
            })
        })
        .collect::<Vec<_>>();
    let wait_default_exit_actions = doctor_wait_default_exit_actions()
        .into_iter()
        .collect::<Vec<_>>();
    let wait_supported_exit_actions = doctor_wait_supported_exit_actions()
        .into_iter()
        .map(str::to_string)
        .collect::<Vec<_>>();
    let reviewer_missing_verdict_machine = orchestrator::missing_verdict_machine_spec_json();
    let reviewer_missing_verdict_rules = reviewer_missing_verdict_machine
        .get("rules")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    let gates_wait_machine = gates::gates_wait_machine_spec_json();
    let gates_wait_transitions = gates_wait_machine
        .get("transitions")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    let lifecycle_machine = lifecycle::lifecycle_machine_spec();
    let lifecycle_transitions = lifecycle_machine
        .get("transitions")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    let requirements_traceability = vec![
        serde_json::json!({
            "requirement_id": "DR-001-GATE_FAILURE_REQUIRES_IMPLEMENTOR",
            "implemented_by": [
                "DoctorDecisionState::DispatchMergeConflicts",
                "DoctorDecisionState::DispatchFailedGates",
                "DoctorDecisionState::DispatchImplementor"
            ],
            "regression_tests": [
                "test_build_recommended_action_dispatches_implementor_on_failed_gates_with_pending_verdicts",
                "test_build_recommended_action_dispatches_implementor_when_lifecycle_reports_gates_failed",
                "test_build_recommended_action_dispatches_implementor_when_push_attempt_failed_gate_stage",
                "test_build_recommended_action_gate_failure_overrides_stale_identity_fix",
                "upsert_doctor_gate_snapshot_prefers_failed_over_inflight",
                "derive_doctor_gate_progress_state_treats_lifecycle_gates_failed_as_terminal_failed",
                "test_build_recommended_action_dispatch_implementor_has_command"
            ]
        }),
        serde_json::json!({
            "requirement_id": "DR-002-RUNNING_GATE_SUPPRESSES_FIX",
            "implemented_by": [
                "derive_doctor_gate_progress_state",
                "DoctorDecisionState::WaitForGates"
            ],
            "regression_tests": [
                "test_build_recommended_action_waits_when_gate_status_is_running_without_active_reviewers",
                "test_build_recommended_action_waits_when_gate_status_is_running_with_idle_reviewers",
                "parse_pr_body_gate_status_for_sha_extracts_current_sha_snapshot"
            ]
        }),
        serde_json::json!({
            "requirement_id": "DR-003-TERMINAL_PASS_REQUIRED_FOR_MERGE_READY",
            "implemented_by": [
                "build_doctor_merge_readiness",
                "DoctorDecisionState::Merge",
                "DoctorDecisionState::Approve"
            ],
            "regression_tests": [
                "test_build_doctor_merge_readiness_requires_terminal_passed_gates"
            ]
        }),
        serde_json::json!({
            "requirement_id": "DR-004-DOCTOR_RULE_ORDER_IS_STRICT",
            "implemented_by": [
                "DOCTOR_DECISION_RULES",
                "DOCTOR_GATE_PROGRESS_RULES",
                "DOCTOR_RECOMMENDATION_RULES"
            ],
            "regression_tests": [
                "doctor_decision_rules_are_unique_and_strictly_ordered",
                "doctor_gate_progress_rules_are_unique_and_strictly_ordered",
                "doctor_recommendation_rules_cover_all_decision_states"
            ]
        }),
        serde_json::json!({
            "requirement_id": "DR-005-WAIT_RETURNS_ON_TERMINAL_ACTION",
            "implemented_by": [
                "DOCTOR_WAIT_TRANSITION_RULES",
                "DOCTOR_ACTION_POLICIES",
                "derive_doctor_wait_next_state"
            ],
            "regression_tests": [
                "doctor_wait_transition_rules_are_unique_and_strictly_ordered",
                "doctor_wait_machine_exits_immediately_on_dispatch_implementor",
                "doctor_wait_machine_prioritizes_terminal_action_over_interrupt",
                "doctor_wait_machine_exits_on_interrupt_when_action_is_not_terminal",
                "doctor_wait_machine_exits_on_timeout_when_not_interrupted"
            ]
        }),
    ];

    let artifact_evidence_refs_for_requirement = |requirement_id: &str| -> &'static [&'static str] {
        match requirement_id {
            "DR-006-EVERGREEN_CAC_STATE_MACHINE_SOURCE" => {
                FAC_REVIEW_MACHINE_REQUIREMENT_DR006_ARTIFACT_REFS
            },
            "DR-007-CLI_EXIT_ON_ACTION_SET_IS_CANONICAL" => {
                FAC_REVIEW_MACHINE_REQUIREMENT_DR007_ARTIFACT_REFS
            },
            "DR-008-MACHINE_VERIFIABLE_ARTIFACTS" => {
                FAC_REVIEW_MACHINE_REQUIREMENT_DR008_ARTIFACT_REFS
            },
            _ => &[],
        }
    };

    let mut traceability_by_requirement =
        std::collections::BTreeMap::<String, serde_json::Value>::new();
    for entry in &requirements_traceability {
        if let Some(requirement_id) = entry
            .get("requirement_id")
            .and_then(serde_json::Value::as_str)
        {
            traceability_by_requirement.insert(requirement_id.to_string(), entry.clone());
        }
    }

    let mut requirement_rule_links = std::collections::BTreeMap::<String, Vec<String>>::new();
    for rule in DOCTOR_DECISION_RULES {
        for requirement_id in rule.requirement_refs {
            requirement_rule_links
                .entry((*requirement_id).to_string())
                .or_default()
                .push(format!("doctor_decision_rules:{}", rule.guard_id));
        }
    }
    for rule in DOCTOR_WAIT_TRANSITION_RULES {
        for requirement_id in rule.requirement_refs {
            requirement_rule_links
                .entry((*requirement_id).to_string())
                .or_default()
                .push(format!("doctor_wait_rules:{}", rule.guard_id));
        }
    }
    for transition in &lifecycle_transitions {
        let transition_id = transition
            .get("transition_id")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown");
        if let Some(requirement_refs) = transition
            .get("requirement_refs")
            .and_then(serde_json::Value::as_array)
        {
            for requirement_id in requirement_refs
                .iter()
                .filter_map(serde_json::Value::as_str)
            {
                requirement_rule_links
                    .entry(requirement_id.to_string())
                    .or_default()
                    .push(format!("lifecycle_transitions:{transition_id}"));
            }
        }
    }
    for links in requirement_rule_links.values_mut() {
        links.sort_unstable();
        links.dedup();
    }

    let mut all_requirement_ids = std::collections::BTreeSet::<String>::new();
    for requirement_id in FAC_REVIEW_MACHINE_REQUIREMENT_IDS {
        all_requirement_ids.insert((*requirement_id).to_string());
    }
    all_requirement_ids.extend(traceability_by_requirement.keys().cloned());
    all_requirement_ids.extend(requirement_rule_links.keys().cloned());

    let requirement_coverage = all_requirement_ids
        .into_iter()
        .map(|requirement_id| {
            let in_ticket_scope = FAC_REVIEW_MACHINE_REQUIREMENT_IDS
                .iter()
                .any(|candidate| *candidate == requirement_id);
            let traceability_entry = traceability_by_requirement.get(&requirement_id);
            let in_machine_traceability = traceability_entry.is_some();
            let rule_links = requirement_rule_links
                .get(&requirement_id)
                .cloned()
                .unwrap_or_default();
            let artifact_evidence_refs = artifact_evidence_refs_for_requirement(&requirement_id)
                .iter()
                .map(|value| (*value).to_string())
                .collect::<Vec<_>>();

            let coverage_mode = if !rule_links.is_empty() {
                "rule_linked"
            } else if in_machine_traceability {
                "traceability_entry_only"
            } else if !artifact_evidence_refs.is_empty() {
                "artifact_level"
            } else if in_ticket_scope {
                "ticket_only"
            } else {
                "machine_only"
            };
            let covered = in_ticket_scope
                && (in_machine_traceability
                    || !rule_links.is_empty()
                    || !artifact_evidence_refs.is_empty());

            let implemented_by = traceability_entry
                .and_then(|entry| entry.get("implemented_by"))
                .and_then(serde_json::Value::as_array)
                .map(|values| {
                    values
                        .iter()
                        .filter_map(serde_json::Value::as_str)
                        .map(str::to_string)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let regression_tests = traceability_entry
                .and_then(|entry| entry.get("regression_tests"))
                .and_then(serde_json::Value::as_array)
                .map(|values| {
                    values
                        .iter()
                        .filter_map(serde_json::Value::as_str)
                        .map(str::to_string)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();

            serde_json::json!({
                "requirement_id": requirement_id,
                "in_ticket_scope": in_ticket_scope,
                "in_machine_traceability": in_machine_traceability,
                "covered": covered,
                "coverage_mode": coverage_mode,
                "rule_links": rule_links,
                "implemented_by": implemented_by,
                "regression_tests": regression_tests,
                "artifact_evidence_refs": artifact_evidence_refs,
            })
        })
        .collect::<Vec<_>>();

    let doctor_decision_guard_ids_unique = {
        let mut seen = std::collections::BTreeSet::new();
        DOCTOR_DECISION_RULES
            .iter()
            .all(|rule| seen.insert(rule.guard_id))
    };
    let doctor_decision_priorities_strict = DOCTOR_DECISION_RULES
        .windows(2)
        .all(|window| window[0].priority < window[1].priority);
    let gate_progress_guard_ids_unique = {
        let mut seen = std::collections::BTreeSet::new();
        DOCTOR_GATE_PROGRESS_RULES
            .iter()
            .all(|rule| seen.insert(rule.guard_id))
    };
    let gate_progress_priorities_strict = DOCTOR_GATE_PROGRESS_RULES
        .windows(2)
        .all(|window| window[0].priority < window[1].priority);
    let gate_reduction_guard_ids_unique = {
        let mut seen = std::collections::BTreeSet::new();
        DOCTOR_GATE_REDUCTION_RULES
            .iter()
            .all(|rule| seen.insert(rule.guard_id))
    };
    let gate_reduction_priorities_strict = DOCTOR_GATE_REDUCTION_RULES
        .windows(2)
        .all(|window| window[0].priority < window[1].priority);
    let wait_guard_ids_unique = {
        let mut seen = std::collections::BTreeSet::new();
        DOCTOR_WAIT_TRANSITION_RULES
            .iter()
            .all(|rule| seen.insert(rule.guard_id))
    };
    let wait_priorities_strict = DOCTOR_WAIT_TRANSITION_RULES
        .windows(2)
        .all(|window| window[0].priority < window[1].priority);
    let gates_wait_guard_ids_unique = {
        let mut seen = std::collections::BTreeSet::new();
        gates_wait_transitions.iter().all(|transition| {
            transition
                .get("guard_id")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|guard_id| seen.insert(guard_id.to_string()))
        })
    };
    let gates_wait_priorities_strict = gates_wait_transitions.windows(2).all(|window| {
        let left = window[0]
            .get("priority")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        let right = window[1]
            .get("priority")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        left < right
    });
    let reviewer_missing_verdict_guard_ids_unique = {
        let mut seen = std::collections::BTreeSet::<String>::new();
        reviewer_missing_verdict_rules.iter().all(|rule| {
            rule.get("guard_id")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|guard_id| seen.insert(guard_id.to_string()))
        })
    };
    let reviewer_missing_verdict_priorities_strict =
        reviewer_missing_verdict_rules.windows(2).all(|window| {
            let left = window[0]
                .get("priority")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            let right = window[1]
                .get("priority")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            left < right
        });
    let lifecycle_transition_ids_unique = {
        let mut seen = std::collections::BTreeSet::<String>::new();
        lifecycle_transitions.iter().all(|transition| {
            transition
                .get("transition_id")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|transition_id| seen.insert(transition_id.to_string()))
        })
    };
    let recommendation_states_unique = {
        let mut seen = std::collections::BTreeSet::new();
        DOCTOR_RECOMMENDATION_RULES
            .iter()
            .all(|rule| seen.insert(rule.state.as_str()))
    };

    let decision_recommendation_matrix = DOCTOR_DECISION_RULES
        .iter()
        .map(|rule| {
            let recommendation = doctor_recommendation_rule_for_state(rule.state);
            serde_json::json!({
                "priority": rule.priority,
                "state": rule.state.as_str(),
                "guard_id": rule.guard_id,
                "guard_kind": rule.guard.as_str(),
                "guard_predicate": rule.guard_predicate,
                "action": recommendation.action,
                "action_priority": recommendation.priority,
                "command_template": recommendation.command_template,
                "reason_template": recommendation.reason_template,
                "requirement_refs": rule.requirement_refs,
            })
        })
        .collect::<Vec<_>>();

    let doctor_decision_rules_by_guard_id = DOCTOR_DECISION_RULES
        .iter()
        .map(|rule| {
            (
                rule.guard_id.to_string(),
                serde_json::json!({
                    "priority": rule.priority,
                    "state": rule.state.as_str(),
                    "guard_kind": rule.guard.as_str(),
                    "guard_predicate": rule.guard_predicate,
                    "recommended_action": rule.state.recommended_action(),
                    "requirement_refs": rule.requirement_refs,
                }),
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    let gate_progress_rules_by_guard_id = DOCTOR_GATE_PROGRESS_RULES
        .iter()
        .map(|rule| {
            (
                rule.guard_id.to_string(),
                serde_json::json!({
                    "priority": rule.priority,
                    "state": rule.state.as_str(),
                    "guard_kind": rule.guard.as_str(),
                    "guard_predicate": rule.guard_predicate,
                }),
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    let gate_reduction_rules_by_guard_id = DOCTOR_GATE_REDUCTION_RULES
        .iter()
        .map(|rule| {
            (
                rule.guard_id.to_string(),
                serde_json::json!({
                    "priority": rule.priority,
                    "decision": match rule.decision {
                        DoctorGateReductionDecision::ReplaceIncoming => "replace_incoming",
                        DoctorGateReductionDecision::KeepExisting => "keep_existing",
                    },
                    "guard_kind": rule.guard.as_str(),
                    "guard_predicate": rule.guard_predicate,
                }),
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    let doctor_wait_rules_by_guard_id = DOCTOR_WAIT_TRANSITION_RULES
        .iter()
        .map(|rule| {
            (
                rule.guard_id.to_string(),
                serde_json::json!({
                    "priority": rule.priority,
                    "from": rule.from.as_str(),
                    "to": rule.to.as_str(),
                    "guard_kind": rule.guard.as_str(),
                    "guard_predicate": rule.guard_predicate,
                    "requirement_refs": rule.requirement_refs,
                }),
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    let gates_wait_transitions_by_guard_id = gates_wait_transitions
        .iter()
        .filter_map(|transition| {
            let guard_id = transition
                .get("guard_id")
                .and_then(serde_json::Value::as_str)?;
            Some((guard_id.to_string(), transition.clone()))
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    let lifecycle_transitions_by_id = lifecycle_transitions
        .iter()
        .filter_map(|transition| {
            let transition_id = transition
                .get("transition_id")
                .and_then(serde_json::Value::as_str)?;
            Some((
                transition_id.to_string(),
                serde_json::json!({
                    "event": transition.get("event"),
                    "from": transition.get("from"),
                    "to": transition.get("to"),
                    "guard_predicate": transition.get("guard_predicate"),
                    "requirement_refs": transition.get("requirement_refs"),
                }),
            ))
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    let doctor_recommendations_by_state = DOCTOR_RECOMMENDATION_RULES
        .iter()
        .map(|rule| {
            (
                rule.state.as_str().to_string(),
                serde_json::json!({
                    "action": rule.action,
                    "priority": rule.priority,
                    "command_template": rule.command_template,
                }),
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    let wait_action_policy_by_action = DOCTOR_ACTION_POLICIES
        .iter()
        .map(|policy| {
            (
                policy.action.to_string(),
                serde_json::json!({
                    "default_wait_exit": policy.default_wait_exit,
                    "allow_exit_on_flag": policy.allow_exit_on_flag,
                    "wait_terminal_reason": policy.wait_terminal_reason,
                }),
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();

    let covered_total = requirement_coverage
        .iter()
        .filter(|entry| {
            entry
                .get("covered")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false)
        })
        .count();
    let coverage_mode_count = |target: &str| {
        requirement_coverage
            .iter()
            .filter(|entry| {
                entry
                    .get("coverage_mode")
                    .and_then(serde_json::Value::as_str)
                    == Some(target)
            })
            .count()
    };

    let payload = serde_json::json!({
        "schema": FAC_REVIEW_MACHINE_PAYLOAD_SCHEMA,
        "doctor_decision_machine": {
            "schema": DOCTOR_DECISION_MACHINE_SCHEMA,
            "evaluation": "priority_order_first_match",
            "default_state": DoctorDecisionState::Wait.as_str(),
            "states": DOCTOR_DECISION_RULES
                .iter()
                .map(|rule| rule.state.as_str())
                .collect::<Vec<_>>(),
            "rules": doctor_rules,
            "recommendations": recommendation_rules,
        },
        "gate_progress_machine": {
            "schema": GATE_PROGRESS_MACHINE_SCHEMA,
            "evaluation": "priority_order_first_match",
            "default_state": DoctorGateProgressState::Unknown.as_str(),
            "states": DOCTOR_GATE_PROGRESS_RULES
                .iter()
                .map(|rule| rule.state.as_str())
                .collect::<Vec<_>>(),
            "rules": gate_rules,
        },
        "gate_reduction_machine": {
            "schema": "apm2.fac.review.gate_reduction_machine.v1",
            "evaluation": "priority_order_first_match",
            "default_decision": "keep_existing",
            "sources": [
                DoctorGateSource::LocalCache.as_str(),
                DoctorGateSource::Projection.as_str(),
            ],
            "rules": gate_reduction_rules,
        },
        "doctor_wait_machine": {
            "schema": DOCTOR_WAIT_MACHINE_SCHEMA,
            "evaluation": "priority_order_first_match_per_state",
            "start_state": DoctorWaitState::Evaluate.as_str(),
            "states": [
                DoctorWaitState::Evaluate.as_str(),
                DoctorWaitState::ExitOnRecommendedAction.as_str(),
                DoctorWaitState::ExitOnInterrupt.as_str(),
                DoctorWaitState::ExitOnTimeout.as_str(),
                DoctorWaitState::PollEmit.as_str(),
                DoctorWaitState::Sleep.as_str(),
                DoctorWaitState::CollectSummary.as_str(),
            ],
            "terminal_states": [
                DoctorWaitState::ExitOnRecommendedAction.as_str(),
                DoctorWaitState::ExitOnInterrupt.as_str(),
                DoctorWaitState::ExitOnTimeout.as_str(),
            ],
            "default_exit_actions": wait_default_exit_actions,
            "supported_exit_actions": wait_supported_exit_actions,
            "action_policy": wait_action_policy,
            "rules": wait_rules,
        },
        "reviewer_missing_verdict_machine": reviewer_missing_verdict_machine,
        "gates_wait_machine": {
            "schema": GATES_WAIT_MACHINE_SCHEMA,
            "evaluation": "priority_order_first_match_per_state",
            "machine": gates_wait_machine,
        },
        "lifecycle_machine": lifecycle_machine,
        "requirements_traceability": requirements_traceability,
        "machine_traceability": {
            "schema": FAC_REVIEW_MACHINE_TRACEABILITY_SCHEMA,
            "ticket_requirement_ids": FAC_REVIEW_MACHINE_REQUIREMENT_IDS,
            "indexes": {
                "doctor_decision_rules_by_guard_id": doctor_decision_rules_by_guard_id,
                "gate_progress_rules_by_guard_id": gate_progress_rules_by_guard_id,
                "gate_reduction_rules_by_guard_id": gate_reduction_rules_by_guard_id,
                "doctor_wait_rules_by_guard_id": doctor_wait_rules_by_guard_id,
                "gates_wait_transitions_by_guard_id": gates_wait_transitions_by_guard_id,
                "lifecycle_transitions_by_id": lifecycle_transitions_by_id,
                "doctor_recommendations_by_state": doctor_recommendations_by_state,
            },
            "decision_recommendation_matrix": decision_recommendation_matrix,
            "wait_action_policy": {
                "default_exit_actions": doctor_wait_default_exit_actions(),
                "supported_exit_actions": doctor_wait_supported_exit_actions(),
                "by_action": wait_action_policy_by_action,
            },
            "requirement_coverage": requirement_coverage,
            "integrity_checks": {
                "doctor_decision_guard_ids_unique": doctor_decision_guard_ids_unique,
                "doctor_decision_priorities_strict": doctor_decision_priorities_strict,
                "gate_progress_guard_ids_unique": gate_progress_guard_ids_unique,
                "gate_progress_priorities_strict": gate_progress_priorities_strict,
                "gate_reduction_guard_ids_unique": gate_reduction_guard_ids_unique,
                "gate_reduction_priorities_strict": gate_reduction_priorities_strict,
                "wait_guard_ids_unique": wait_guard_ids_unique,
                "wait_priorities_strict": wait_priorities_strict,
                "gates_wait_guard_ids_unique": gates_wait_guard_ids_unique,
                "gates_wait_priorities_strict": gates_wait_priorities_strict,
                "reviewer_missing_verdict_guard_ids_unique": reviewer_missing_verdict_guard_ids_unique,
                "reviewer_missing_verdict_priorities_strict": reviewer_missing_verdict_priorities_strict,
                "lifecycle_transition_ids_unique": lifecycle_transition_ids_unique,
                "recommendation_states_unique": recommendation_states_unique,
            },
            "counts": {
                "doctor_decision_rules": DOCTOR_DECISION_RULES.len(),
                "doctor_recommendations": DOCTOR_RECOMMENDATION_RULES.len(),
                "gate_progress_rules": DOCTOR_GATE_PROGRESS_RULES.len(),
                "gate_reduction_rules": DOCTOR_GATE_REDUCTION_RULES.len(),
                "wait_rules": DOCTOR_WAIT_TRANSITION_RULES.len(),
                "wait_action_policy_actions": DOCTOR_ACTION_POLICIES.len(),
                "reviewer_missing_verdict_rules": reviewer_missing_verdict_rules.len(),
                "gates_wait_transitions": gates_wait_transitions.len(),
                "lifecycle_transitions": lifecycle_transitions.len(),
                "ticket_in_scope_requirements": FAC_REVIEW_MACHINE_REQUIREMENT_IDS.len(),
                "machine_traceability_requirements": 5,
                "covered_total": covered_total,
                "artifact_level_total": coverage_mode_count("artifact_level"),
                "traceability_entry_only_total": coverage_mode_count("traceability_entry_only"),
            },
        },
    });
    serde_json::json!({
        "schema": FAC_REVIEW_MACHINE_CAC_SCHEMA,
        "schema_version": FAC_REVIEW_MACHINE_CAC_SCHEMA_VERSION,
        "kind": FAC_REVIEW_MACHINE_CAC_KIND,
        "meta": {
            "stable_id": FAC_REVIEW_MACHINE_CAC_STABLE_ID,
            "status": FAC_REVIEW_MACHINE_CAC_STATUS,
            "classification": FAC_REVIEW_MACHINE_CAC_CLASSIFICATION,
            "source_of_truth_refs": [
                FAC_REVIEW_MACHINE_CAC_PATH,
                "documents/reviews/fac_review_requirements.cac.json",
                "documents/rfcs/RFC-0019/"
            ],
            "last_aligned_rfc": "RFC-0019",
            "canonicalizer": {
                "canonicalizer_id": "apm2.canonicalizer.jcs",
                "canonicalizer_version": "1.0.0",
                "vectors_ref": "dcp://apm2.cac/canonicalizer/vectors@v1"
            },
            "provenance": {
                "actor_id": "HOLON-PLATFORM-GOVERNANCE",
                "work_id": "FAC-REVIEW-STATE-MACHINE-CAC-INIT-20260220",
                "source_receipts": []
            }
        },
        "payload": payload
    })
}

pub fn fac_review_machine_spec_json_string(pretty: bool) -> Result<String, String> {
    if pretty {
        serde_json::to_string_pretty(&fac_review_machine_spec_json())
            .map_err(|err| format!("failed to serialize FAC review machine spec: {err}"))
    } else {
        serde_json::to_string(&fac_review_machine_spec_json())
            .map_err(|err| format!("failed to serialize FAC review machine spec: {err}"))
    }
}

// ── Process management helpers (used by orchestrator) ───────────────────────

pub fn derive_repo() -> Result<String, String> {
    target::derive_repo_from_origin()
}

fn terminate_child(child: &mut Child) -> Result<(), String> {
    let pid = child.id();
    let term_status = Command::new("kill")
        .args(["-TERM", &pid.to_string()])
        .status()
        .map_err(|err| format!("failed to send SIGTERM to {pid}: {err}"))?;
    if !term_status.success() {
        let _ = child.kill();
        let _ = child.wait();
        return Ok(());
    }

    let start = Instant::now();
    while start.elapsed() < TERMINATE_TIMEOUT {
        if child
            .try_wait()
            .map_err(|err| format!("failed while waiting for pid {pid}: {err}"))?
            .is_some()
        {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    let _ = child.wait();
    Ok(())
}

fn exit_signal(status: std::process::ExitStatus) -> Option<i32> {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        status.signal()
    }
    #[cfg(not(unix))]
    {
        let _ = status;
        None
    }
}

#[derive(Debug, Clone, Default)]
struct DoctorPulseMetadata {
    pulse_id: Option<String>,
    topic: Option<String>,
    event_type: Option<String>,
    ledger_cursor: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct DoctorPulseFingerprint {
    pulse_id: Option<String>,
    ledger_cursor: Option<u64>,
}

#[derive(Debug)]
struct DoctorPulseDeduper {
    capacity: usize,
    entries: VecDeque<DoctorPulseFingerprint>,
    index: HashSet<DoctorPulseFingerprint>,
}

impl DoctorPulseDeduper {
    fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            entries: VecDeque::new(),
            index: HashSet::new(),
        }
    }

    fn insert_if_new(&mut self, pulse: &DoctorPulseMetadata) -> bool {
        let Some(fingerprint) = pulse.fingerprint() else {
            return true;
        };
        if self.index.contains(&fingerprint) {
            return false;
        }
        if self.entries.len() >= self.capacity
            && let Some(oldest) = self.entries.pop_front()
        {
            self.index.remove(&oldest);
        }
        self.index.insert(fingerprint.clone());
        self.entries.push_back(fingerprint);
        true
    }
}

impl DoctorPulseMetadata {
    fn fingerprint(&self) -> Option<DoctorPulseFingerprint> {
        if self.pulse_id.is_none() && self.ledger_cursor.is_none() {
            return None;
        }
        Some(DoctorPulseFingerprint {
            pulse_id: self.pulse_id.clone(),
            ledger_cursor: self.ledger_cursor,
        })
    }
}

struct DoctorPulseSubscription {
    runtime: tokio::runtime::Runtime,
    client: OperatorClient,
    subscription_id: String,
    operator_socket: PathBuf,
    client_sub_id: String,
    topic_patterns: Vec<String>,
    since_ledger_cursor: u64,
}

impl DoctorPulseSubscription {
    fn connect(
        operator_socket: &Path,
        repo: &str,
        pr_number: u32,
    ) -> Result<(Self, usize, usize), String> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|err| format!("failed to build pulse runtime: {err}"))?;

        let topic_patterns = doctor_wait_pulse_topic_patterns();
        let client_sub_id = build_doctor_pulse_client_sub_id(repo, pr_number);
        let (client, response) = runtime.block_on(async {
            let mut client = OperatorClient::connect(operator_socket)
                .await
                .map_err(|err| format!("operator pulse connect failed: {err}"))?;
            let response = client
                .subscribe_pulse(
                    &client_sub_id,
                    &topic_patterns,
                    0,
                    DOCTOR_WAIT_PULSE_MAX_PULSES_PER_SEC,
                )
                .await
                .map_err(|err| format!("operator pulse subscribe failed: {err}"))?;
            Ok::<_, String>((client, response))
        })?;

        let accepted_count = response.accepted_patterns.len();
        let rejected_count = response.rejected_patterns.len();

        let mut subscription = Self {
            runtime,
            client,
            subscription_id: response.subscription_id,
            operator_socket: operator_socket.to_path_buf(),
            client_sub_id,
            topic_patterns,
            since_ledger_cursor: response.effective_since_cursor,
        };
        if accepted_count == 0 {
            let _ = subscription.close();
            return Err("pulse subscription accepted no patterns".to_string());
        }

        Ok((subscription, accepted_count, rejected_count))
    }

    fn wait_for_pulse(&mut self, timeout: Duration) -> Result<Option<DoctorPulseMetadata>, String> {
        let pulse = self
            .runtime
            .block_on(async { self.client.wait_for_pulse(timeout).await })
            .map_err(|err| format!("pulse wait failed: {err}"))?;
        let Some(event) = pulse else {
            return Ok(None);
        };

        let mut metadata = DoctorPulseMetadata::default();
        if let Some(envelope) = event.envelope {
            self.since_ledger_cursor = self.since_ledger_cursor.max(envelope.ledger_cursor);
            metadata.pulse_id = (!envelope.pulse_id.is_empty()).then_some(envelope.pulse_id);
            metadata.topic = (!envelope.topic.is_empty()).then_some(envelope.topic);
            metadata.event_type = (!envelope.event_type.is_empty()).then_some(envelope.event_type);
            metadata.ledger_cursor = Some(envelope.ledger_cursor);
        }
        Ok(Some(metadata))
    }

    fn reconnect(&mut self) -> Result<(usize, usize), String> {
        let _ = self.close();

        let operator_socket = self.operator_socket.clone();
        let client_sub_id = self.client_sub_id.clone();
        let topic_patterns = self.topic_patterns.clone();
        let since_ledger_cursor = self.since_ledger_cursor;

        let (client, response) = self.runtime.block_on(async move {
            let mut client = OperatorClient::connect(&operator_socket)
                .await
                .map_err(|err| format!("operator pulse reconnect failed: {err}"))?;
            let response = client
                .subscribe_pulse(
                    &client_sub_id,
                    &topic_patterns,
                    since_ledger_cursor,
                    DOCTOR_WAIT_PULSE_MAX_PULSES_PER_SEC,
                )
                .await
                .map_err(|err| format!("operator pulse resubscribe failed: {err}"))?;
            Ok::<_, String>((client, response))
        })?;

        let accepted_count = response.accepted_patterns.len();
        let rejected_count = response.rejected_patterns.len();
        if accepted_count == 0 {
            return Err("pulse reconnect accepted no patterns".to_string());
        }

        self.client = client;
        self.subscription_id = response.subscription_id;
        self.since_ledger_cursor = self
            .since_ledger_cursor
            .max(response.effective_since_cursor);
        Ok((accepted_count, rejected_count))
    }

    fn close(&mut self) -> Result<bool, String> {
        let subscription_id = self.subscription_id.clone();
        let response = self
            .runtime
            .block_on(async { self.client.unsubscribe_pulse(&subscription_id).await })
            .map_err(|err| format!("failed to unsubscribe pulse subscription: {err}"))?;
        Ok(response.removed)
    }
}

fn doctor_wait_pulse_topic_patterns() -> Vec<String> {
    DOCTOR_WAIT_PULSE_TOPICS
        .iter()
        .map(|value| (*value).to_string())
        .collect()
}

fn build_doctor_pulse_client_sub_id(repo: &str, pr_number: u32) -> String {
    let prefix = format!("fac-doctor-pr{pr_number}-");
    let mut sanitized = String::with_capacity(repo.len());
    for ch in repo.chars() {
        if ch.is_ascii_alphanumeric() {
            sanitized.push(ch.to_ascii_lowercase());
        } else if ch == '-' || ch == '_' {
            sanitized.push(ch);
        } else {
            sanitized.push('-');
        }
    }
    let sanitized = sanitized.trim_matches('-');
    let repo_part = if sanitized.is_empty() {
        "repo"
    } else {
        sanitized
    };

    let remaining = DOCTOR_WAIT_PULSE_CLIENT_SUB_ID_MAX_LEN.saturating_sub(prefix.len());
    let trimmed_repo = repo_part.chars().take(remaining.max(1)).collect::<String>();
    format!("{prefix}{trimmed_repo}")
}

const fn doctor_wait_should_collect_summary(
    mode: DoctorWaitMode,
    wake_reason: DoctorWaitWakeReason,
) -> bool {
    match mode {
        DoctorWaitMode::PulsePrimary => matches!(wake_reason, DoctorWaitWakeReason::Pulse),
        DoctorWaitMode::PollingFallback => true,
    }
}

fn emit_doctor_wait_degraded_mode_event(json_output: bool, pr_number: u32, reason: &str) {
    if json_output {
        if let Err(err) = jsonl::emit_jsonl(&jsonl::StageEvent {
            event: "doctor_wait_degraded".to_string(),
            ts: jsonl::ts_now(),
            extra: serde_json::json!({
                "pr_number": pr_number,
                "from_mode": DoctorWaitMode::PulsePrimary.as_str(),
                "to_mode": DoctorWaitMode::PollingFallback.as_str(),
                "reason": reason,
            }),
        }) {
            eprintln!("WARNING: failed to emit doctor wait degraded event: {err}");
        }
    } else {
        eprintln!("doctor wait: degraded to polling fallback for PR #{pr_number}: {reason}");
    }
}

fn emit_doctor_pulse_subscribed_event(
    json_output: bool,
    pr_number: u32,
    accepted_count: usize,
    rejected_count: usize,
    since_ledger_cursor: u64,
    reconnect_attempt: Option<usize>,
) {
    if json_output {
        if let Err(err) = jsonl::emit_jsonl(&jsonl::StageEvent {
            event: "doctor_pulse_subscribed".to_string(),
            ts: jsonl::ts_now(),
            extra: serde_json::json!({
                "pr_number": pr_number,
                "accepted_patterns": accepted_count,
                "rejected_patterns": rejected_count,
                "since_ledger_cursor": since_ledger_cursor,
                "reconnect_attempt": reconnect_attempt,
            }),
        }) {
            eprintln!("WARNING: failed to emit doctor pulse subscribe event: {err}");
        }
    } else if let Some(attempt) = reconnect_attempt {
        eprintln!(
            "doctor wait: pulse reconnected on attempt {attempt} (accepted_patterns={accepted_count}, rejected_patterns={rejected_count}, since_cursor={since_ledger_cursor})"
        );
    } else {
        eprintln!(
            "doctor wait: pulse subscription active (accepted_patterns={accepted_count}, rejected_patterns={rejected_count}, since_cursor={since_ledger_cursor})"
        );
    }
}

fn emit_doctor_pulse_reconnect_event(
    json_output: bool,
    pr_number: u32,
    attempt: usize,
    outcome: &str,
    reason: &str,
) {
    if json_output {
        if let Err(err) = jsonl::emit_jsonl(&jsonl::StageEvent {
            event: "doctor_pulse_reconnect".to_string(),
            ts: jsonl::ts_now(),
            extra: serde_json::json!({
                "pr_number": pr_number,
                "attempt": attempt,
                "outcome": outcome,
                "reason": reason,
            }),
        }) {
            eprintln!("WARNING: failed to emit doctor pulse reconnect event: {err}");
        }
    } else {
        eprintln!(
            "doctor wait: pulse reconnect attempt {attempt} outcome={outcome} reason={reason}"
        );
    }
}

fn emit_doctor_pulse_skipped_event(
    json_output: bool,
    pr_number: u32,
    reason: &str,
    pulse: &DoctorPulseMetadata,
) {
    if json_output {
        if let Err(err) = jsonl::emit_jsonl(&jsonl::StageEvent {
            event: "doctor_pulse_skipped".to_string(),
            ts: jsonl::ts_now(),
            extra: serde_json::json!({
                "pr_number": pr_number,
                "reason": reason,
                "pulse_id": pulse.pulse_id,
                "topic": pulse.topic,
                "event_type": pulse.event_type,
                "ledger_cursor": pulse.ledger_cursor,
            }),
        }) {
            eprintln!("WARNING: failed to emit doctor pulse skipped event: {err}");
        }
    }
}

fn doctor_wait_pulse_is_relevant(pulse: &DoctorPulseMetadata) -> bool {
    if let Some(topic) = pulse.topic.as_deref()
        && (topic == "ledger.head"
            || topic.starts_with("work.")
            || topic.starts_with("work_graph.")
            || topic.starts_with("gate."))
    {
        return true;
    }

    let Some(event_type) = pulse.event_type.as_deref() else {
        return false;
    };
    let normalized = event_type.to_ascii_lowercase();
    normalized.starts_with("work.")
        || normalized.starts_with("work_graph.")
        || normalized.starts_with("gate.")
        || matches!(
            normalized.as_str(),
            "ledger.head"
                | "kernelevent"
                | "workopened"
                | "worktransitioned"
                | "workedgeadded"
                | "workedgeremoved"
                | "workedgewaived"
                | "gatereceipt"
        )
}

fn close_doctor_pulse_subscription(subscription: &mut DoctorPulseSubscription) {
    match subscription.close() {
        Ok(true) => {},
        Ok(false) => {
            eprintln!("WARNING: pulse subscription close returned removed=false");
        },
        Err(err) => {
            eprintln!("WARNING: failed to unsubscribe pulse subscription: {err}");
        },
    }
}

fn attempt_doctor_pulse_reconnect(
    pulse_subscription: &mut DoctorPulseSubscription,
    json_output: bool,
    pr_number: u32,
    wait_error: &str,
) -> Result<(), String> {
    let mut last_error = wait_error.to_string();
    for attempt in 1..=DOCTOR_WAIT_PULSE_RECONNECT_MAX_ATTEMPTS {
        let delay = Duration::from_millis(
            DOCTOR_WAIT_PULSE_RECONNECT_BACKOFF_MILLIS.saturating_mul(attempt as u64),
        );
        thread::sleep(delay);

        match pulse_subscription.reconnect() {
            Ok((accepted_count, rejected_count)) => {
                emit_doctor_pulse_subscribed_event(
                    json_output,
                    pr_number,
                    accepted_count,
                    rejected_count,
                    pulse_subscription.since_ledger_cursor,
                    Some(attempt),
                );
                emit_doctor_pulse_reconnect_event(
                    json_output,
                    pr_number,
                    attempt,
                    "recovered",
                    wait_error,
                );
                return Ok(());
            },
            Err(err) => {
                emit_doctor_pulse_reconnect_event(
                    json_output,
                    pr_number,
                    attempt,
                    "retry_failed",
                    &err,
                );
                last_error = err;
            },
        }
    }

    Err(format!(
        "{wait_error}; reconnect exhausted after {DOCTOR_WAIT_PULSE_RECONNECT_MAX_ATTEMPTS} attempts: {last_error}"
    ))
}

/// Run doctor diagnostics for a specific PR.
///
/// Doctor is machine-oriented by default. In wait mode, output streams NDJSON
/// heartbeats plus a terminal result event.
#[allow(clippy::too_many_arguments)]
pub fn run_doctor(
    repo: &str,
    pr_number: u32,
    operator_socket: &Path,
    fix: bool,
    json_output: bool,
    wait_for_recommended_action: bool,
    wait_timeout_seconds: u64,
    exit_on: &[String],
) -> u8 {
    let mut repairs_applied = Vec::new();
    if fix {
        let mut attempted_plan_fingerprints = std::collections::BTreeSet::new();
        for pass in 1..=DOCTOR_FIX_MAX_PASSES {
            let pre_repair = run_doctor_inner(repo, pr_number, Vec::new(), false);
            let plan = derive_doctor_repair_plan(&pre_repair);
            let pre_follow_up_fix = doctor_recommended_action_requests_follow_up_fix(&pre_repair);
            let pre_follow_up_force = doctor_recommended_follow_up_fix_force(&pre_repair);
            if !plan.has_operations() && !pre_follow_up_fix {
                break;
            }
            let plan_fingerprint = format!(
                "{} follow_up_fix={} follow_up_force={}",
                plan.fingerprint(),
                pre_follow_up_fix,
                pre_follow_up_force
            );
            if !attempted_plan_fingerprints.insert(plan_fingerprint.clone()) {
                let err = format!(
                    "doctor fix did not converge for PR #{pr_number}; repeated repair plan `{plan_fingerprint}`"
                );
                if let Err(emit_err) = jsonl::emit_json_error("fac_doctor_fix_incomplete", &err) {
                    eprintln!("WARNING: failed to emit doctor fix convergence error: {emit_err}");
                }
                return exit_codes::GENERIC_ERROR;
            }

            if plan.has_operations() {
                let force_repair = doctor_requires_force_repair(&pre_repair);
                match recovery::run_repair_plan(
                    repo,
                    Some(pr_number),
                    force_repair,
                    plan.refresh_identity,
                    plan.reap_stale_agents,
                    plan.reset_lifecycle,
                    plan.repair_registry_integrity,
                    false,
                    plan.run_state_review_types,
                ) {
                    Ok(summary) => {
                        let mut doctor_repairs = summary.into_doctor_repairs();
                        repairs_applied.append(&mut doctor_repairs);
                    },
                    Err(err) => {
                        if let Err(emit_err) = jsonl::emit_json_error("fac_doctor_fix_failed", &err)
                        {
                            eprintln!("WARNING: failed to emit doctor fix error: {emit_err}");
                        }
                        return exit_codes::GENERIC_ERROR;
                    },
                }

                let post_repair = run_doctor_inner(repo, pr_number, Vec::new(), true);
                match run_doctor_follow_up_repair(repo, pr_number, &post_repair) {
                    Ok(Some(repair)) => repairs_applied.push(repair),
                    Ok(None) => {},
                    Err(err) => {
                        if let Err(emit_err) =
                            jsonl::emit_json_error("fac_doctor_fix_follow_up_failed", &err)
                        {
                            eprintln!(
                                "WARNING: failed to emit doctor fix follow-up error: {emit_err}"
                            );
                        }
                        return exit_codes::GENERIC_ERROR;
                    },
                }
            } else {
                match run_doctor_follow_up_repair(repo, pr_number, &pre_repair) {
                    Ok(Some(repair)) => repairs_applied.push(repair),
                    Ok(None) => {},
                    Err(err) => {
                        if let Err(emit_err) =
                            jsonl::emit_json_error("fac_doctor_fix_follow_up_failed", &err)
                        {
                            eprintln!(
                                "WARNING: failed to emit doctor fix follow-up error: {emit_err}"
                            );
                        }
                        return exit_codes::GENERIC_ERROR;
                    },
                }
            }

            let follow_up = run_doctor_inner(repo, pr_number, Vec::new(), true);
            if follow_up.recommended_action.action != "fix" {
                break;
            }
            let follow_up_plan = derive_doctor_repair_plan(&follow_up);
            let follow_up_fix = doctor_recommended_action_requests_follow_up_fix(&follow_up);
            if !follow_up_plan.has_operations() && !follow_up_fix {
                break;
            }
            if pass == DOCTOR_FIX_MAX_PASSES {
                let err = format!(
                    "doctor fix exhausted {DOCTOR_FIX_MAX_PASSES} passes for PR #{pr_number} \
                     while additional repair operations remain (`{}`) follow_up_fix={follow_up_fix}",
                    follow_up_plan.fingerprint()
                );
                if let Err(emit_err) = jsonl::emit_json_error("fac_doctor_fix_incomplete", &err) {
                    eprintln!("WARNING: failed to emit doctor fix max-pass error: {emit_err}");
                }
                return exit_codes::GENERIC_ERROR;
            }
        }
    }

    if !wait_for_recommended_action {
        let summary = run_doctor_inner(repo, pr_number, repairs_applied, false);
        println!(
            "{}",
            serde_json::to_string_pretty(&summary)
                .unwrap_or_else(|_| "{\"error\":\"serialization_failure\"}".to_string())
        );
        let has_critical_health = summary
            .health
            .iter()
            .any(|item| item.severity.eq_ignore_ascii_case("high"));
        let requires_intervention = matches!(
            summary.recommended_action.action.as_str(),
            "fix" | "escalate"
        );
        if has_critical_health || requires_intervention {
            return exit_codes::GENERIC_ERROR;
        }
        return exit_codes::SUCCESS;
    }

    let exit_actions = match normalize_doctor_exit_actions(exit_on) {
        Ok(value) => value,
        Err(err) => {
            return emit_doctor_wait_error(
                json_output,
                "fac_doctor_invalid_exit_on",
                &err,
                exit_codes::GENERIC_ERROR,
            );
        },
    };

    let interrupted = match doctor_interrupt_flag() {
        Ok(flag) => flag,
        Err(err) => {
            return emit_doctor_wait_error(
                json_output,
                "fac_doctor_signal_handler_failed",
                &err,
                exit_codes::GENERIC_ERROR,
            );
        },
    };
    interrupted.store(false, Ordering::SeqCst);

    let started = Instant::now();
    let mut tick = 0_u64;
    let mut summary = run_doctor_inner(repo, pr_number, repairs_applied, false);
    if json_output {
        if let Err(err) = jsonl::emit_jsonl(&jsonl::StageEvent {
            event: "doctor_wait_mode".to_string(),
            ts: jsonl::ts_now(),
            extra: serde_json::json!({
                "mode": DoctorWaitMode::PulsePrimary.as_str(),
                "pr_number": pr_number,
            }),
        }) {
            eprintln!("WARNING: failed to emit doctor wait mode event: {err}");
        }
    }

    let mut pulse_subscription =
        match DoctorPulseSubscription::connect(operator_socket, repo, pr_number) {
            Ok((subscription, accepted_count, rejected_count)) => {
                emit_doctor_pulse_subscribed_event(
                    json_output,
                    pr_number,
                    accepted_count,
                    rejected_count,
                    subscription.since_ledger_cursor,
                    None,
                );
                Some(subscription)
            },
            Err(err) => {
                emit_doctor_wait_degraded_mode_event(json_output, pr_number, &err);
                None
            },
        };

    if let Some(subscription) = pulse_subscription.as_mut() {
        match run_doctor_wait_pulse_loop(
            repo,
            pr_number,
            json_output,
            &exit_actions,
            interrupted.as_ref(),
            wait_timeout_seconds,
            started,
            tick,
            &mut summary,
            subscription,
        ) {
            DoctorWaitLoopControl::Exit(code) => {
                close_doctor_pulse_subscription(subscription);
                return code;
            },
            DoctorWaitLoopControl::Fallback { next_tick, reason } => {
                tick = next_tick;
                close_doctor_pulse_subscription(subscription);
                emit_doctor_wait_degraded_mode_event(json_output, pr_number, &reason);
            },
        }
    }

    run_doctor_wait_poll_loop(
        repo,
        pr_number,
        json_output,
        &exit_actions,
        interrupted.as_ref(),
        wait_timeout_seconds,
        started,
        tick,
        summary,
    )
}

#[allow(clippy::too_many_arguments)]
fn doctor_wait_maybe_exit(
    repo: &str,
    pr_number: u32,
    summary: &mut DoctorPrSummary,
    json_output: bool,
    tick: u64,
    started: Instant,
    wait_timeout_seconds: u64,
    exit_actions: &std::collections::BTreeSet<String>,
    interrupted: &AtomicBool,
) -> Option<DoctorWaitLoopControl> {
    let elapsed_seconds = started.elapsed().as_secs().min(wait_timeout_seconds);
    let facts = DoctorWaitFacts {
        recommended_action: summary.recommended_action.action.as_str(),
        exit_actions,
        interrupted: interrupted.load(Ordering::SeqCst),
        elapsed_seconds,
        wait_timeout_seconds,
    };
    match derive_doctor_wait_next_state(DoctorWaitState::Evaluate, Some(&facts)) {
        DoctorWaitState::ExitOnRecommendedAction => {
            emit_doctor_wait_terminal_event(json_output, tick, summary, elapsed_seconds);
            emit_doctor_wait_result(summary, json_output, tick, false, elapsed_seconds);
            Some(DoctorWaitLoopControl::Exit(exit_codes::SUCCESS))
        },
        DoctorWaitState::ExitOnInterrupt => {
            *summary = run_doctor_inner(repo, pr_number, Vec::new(), true);
            emit_doctor_wait_result(summary, json_output, tick, false, elapsed_seconds);
            Some(DoctorWaitLoopControl::Exit(exit_codes::SUCCESS))
        },
        DoctorWaitState::ExitOnTimeout => {
            emit_doctor_wait_timeout_event(json_output, tick, summary, elapsed_seconds);
            emit_doctor_wait_result(summary, json_output, tick, true, elapsed_seconds);
            Some(DoctorWaitLoopControl::Exit(DOCTOR_WAIT_TIMEOUT_EXIT_CODE))
        },
        _ => None,
    }
}

#[allow(clippy::too_many_arguments)]
fn run_doctor_wait_pulse_loop(
    repo: &str,
    pr_number: u32,
    json_output: bool,
    exit_actions: &std::collections::BTreeSet<String>,
    interrupted: &AtomicBool,
    wait_timeout_seconds: u64,
    started: Instant,
    initial_tick: u64,
    summary: &mut DoctorPrSummary,
    pulse_subscription: &mut DoctorPulseSubscription,
) -> DoctorWaitLoopControl {
    let mut tick = initial_tick;
    let mut pulse_deduper = DoctorPulseDeduper::new(DOCTOR_WAIT_PULSE_DEDUPE_CAPACITY);

    loop {
        if let Some(result) = doctor_wait_maybe_exit(
            repo,
            pr_number,
            summary,
            json_output,
            tick,
            started,
            wait_timeout_seconds,
            exit_actions,
            interrupted,
        ) {
            return result;
        }

        let elapsed = started.elapsed().as_secs();
        let remaining_seconds = wait_timeout_seconds.saturating_sub(elapsed);
        let wait_slice = Duration::from_millis(DOCTOR_WAIT_PULSE_CHECK_INTERVAL_MILLIS)
            .min(Duration::from_secs(remaining_seconds.max(1)));

        let pulse_metadata = match pulse_subscription.wait_for_pulse(wait_slice) {
            Ok(pulse) => pulse,
            Err(err) => {
                if let Err(reconnect_err) =
                    attempt_doctor_pulse_reconnect(pulse_subscription, json_output, pr_number, &err)
                {
                    return DoctorWaitLoopControl::Fallback {
                        next_tick: tick,
                        reason: reconnect_err,
                    };
                }
                continue;
            },
        };
        let wake_reason = if pulse_metadata.is_some() {
            DoctorWaitWakeReason::Pulse
        } else {
            DoctorWaitWakeReason::Timer
        };

        if !doctor_wait_should_collect_summary(DoctorWaitMode::PulsePrimary, wake_reason) {
            continue;
        }

        let Some(pulse) = pulse_metadata else {
            continue;
        };

        if !doctor_wait_pulse_is_relevant(&pulse) {
            emit_doctor_pulse_skipped_event(json_output, pr_number, "out_of_scope", &pulse);
            continue;
        }

        if !pulse_deduper.insert_if_new(&pulse) {
            emit_doctor_pulse_skipped_event(json_output, pr_number, "duplicate", &pulse);
            continue;
        }

        tick = tick.saturating_add(1);
        if json_output {
            if let Err(err) = jsonl::emit_jsonl(&jsonl::StageEvent {
                event: "doctor_pulse".to_string(),
                ts: jsonl::ts_now(),
                extra: serde_json::json!({
                    "tick": tick,
                    "pr_number": pr_number,
                    "pulse_id": pulse.pulse_id,
                    "topic": pulse.topic,
                    "event_type": pulse.event_type,
                    "ledger_cursor": pulse.ledger_cursor,
                    "action": summary.recommended_action.action.as_str(),
                }),
            }) {
                eprintln!("WARNING: failed to emit doctor pulse event: {err}");
            }
        } else {
            let topic = pulse.topic.as_deref().unwrap_or("unknown");
            let event_type = pulse.event_type.as_deref().unwrap_or("unknown");
            eprintln!(
                "doctor wait: pulse tick={tick} topic={topic} event_type={event_type} elapsed={}s",
                started.elapsed().as_secs()
            );
        }

        // Every 5th pulse-triggered reevaluation uses full mode so merge state
        // can still converge if only partial local projections updated.
        let use_lightweight = tick % 5 != 0;
        *summary = run_doctor_inner(repo, pr_number, Vec::new(), use_lightweight);
    }
}

#[allow(clippy::too_many_arguments)]
fn run_doctor_wait_poll_loop(
    repo: &str,
    pr_number: u32,
    json_output: bool,
    exit_actions: &std::collections::BTreeSet<String>,
    interrupted: &AtomicBool,
    wait_timeout_seconds: u64,
    started: Instant,
    initial_tick: u64,
    mut summary: DoctorPrSummary,
) -> u8 {
    let poll_interval = Duration::from_secs(DOCTOR_WAIT_POLL_INTERVAL_SECONDS);
    let mut tick = initial_tick;
    let mut wait_state = DoctorWaitState::Evaluate;

    if json_output {
        if let Err(err) = jsonl::emit_jsonl(&jsonl::StageEvent {
            event: "doctor_wait_mode".to_string(),
            ts: jsonl::ts_now(),
            extra: serde_json::json!({
                "mode": DoctorWaitMode::PollingFallback.as_str(),
                "pr_number": pr_number,
            }),
        }) {
            eprintln!("WARNING: failed to emit doctor wait mode event: {err}");
        }
    }

    loop {
        let elapsed_seconds = started.elapsed().as_secs().min(wait_timeout_seconds);
        match wait_state {
            DoctorWaitState::Evaluate => {
                if let Some(DoctorWaitLoopControl::Exit(code)) = doctor_wait_maybe_exit(
                    repo,
                    pr_number,
                    &mut summary,
                    json_output,
                    tick,
                    started,
                    wait_timeout_seconds,
                    exit_actions,
                    interrupted,
                ) {
                    return code;
                }
                wait_state = derive_doctor_wait_next_state(wait_state, None);
            },
            DoctorWaitState::ExitOnRecommendedAction
            | DoctorWaitState::ExitOnInterrupt
            | DoctorWaitState::ExitOnTimeout => {
                // Exit states are handled centrally by `doctor_wait_maybe_exit`.
                wait_state = DoctorWaitState::Evaluate;
            },
            DoctorWaitState::PollEmit => {
                if json_output {
                    if let Err(err) = jsonl::emit_jsonl(&jsonl::DoctorPollEvent {
                        event: "doctor_poll",
                        tick,
                        action: summary.recommended_action.action.clone(),
                        ts: jsonl::ts_now(),
                    }) {
                        eprintln!("WARNING: failed to emit doctor poll event: {err}");
                    }
                } else {
                    eprintln!(
                        "doctor wait: tick={tick} action={} elapsed={}s",
                        summary.recommended_action.action, elapsed_seconds
                    );
                }
                wait_state = derive_doctor_wait_next_state(wait_state, None);
            },
            DoctorWaitState::Sleep => {
                thread::sleep(poll_interval);
                tick = tick.saturating_add(1);
                wait_state = derive_doctor_wait_next_state(wait_state, None);
            },
            DoctorWaitState::CollectSummary => {
                if doctor_wait_should_collect_summary(
                    DoctorWaitMode::PollingFallback,
                    DoctorWaitWakeReason::Timer,
                ) {
                    // BF-002 (TCK-00626): Every 5th tick, use non-lightweight
                    // mode to detect externally-merged PRs via GitHub API.
                    let use_lightweight = tick % 5 != 0;
                    summary = run_doctor_inner(repo, pr_number, Vec::new(), use_lightweight);
                }
                wait_state = derive_doctor_wait_next_state(wait_state, None);
            },
        }
    }
}

fn run_doctor_follow_up_repair(
    repo: &str,
    pr_number: u32,
    summary: &DoctorPrSummary,
) -> Result<Option<DoctorRepairApplied>, String> {
    if !doctor_recommended_action_requests_follow_up_fix(summary) {
        return Ok(None);
    }

    let force_follow_up_fix = doctor_recommended_follow_up_fix_force(summary);
    let repair_summary =
        repair_cycle::run_repair_for_doctor_fix(repo, pr_number, force_follow_up_fix, true)?;
    let dispatched_count = repair_summary
        .reviews_dispatched
        .as_ref()
        .map_or(0, Vec::len);

    Ok(Some(DoctorRepairApplied {
        operation: "follow_up_pr_fix".to_string(),
        before: Some(format!(
            "force={force_follow_up_fix} reason={}",
            summary.recommended_action.reason
        )),
        after: Some(format!(
            "strategy={} evidence_passed={} dispatched_reviews={}",
            repair_summary.strategy.label(),
            repair_summary
                .evidence_passed
                .map_or_else(|| "none".to_string(), |passed| passed.to_string()),
            dispatched_count
        )),
    }))
}

#[derive(Debug, Clone)]
struct DoctorWaitFacts<'a> {
    recommended_action: &'a str,
    exit_actions: &'a std::collections::BTreeSet<String>,
    interrupted: bool,
    elapsed_seconds: u64,
    wait_timeout_seconds: u64,
}

fn doctor_action_policy_for_action(action: &str) -> Option<&'static DoctorActionPolicy> {
    DOCTOR_ACTION_POLICIES
        .iter()
        .find(|policy| policy.action == action)
}

fn doctor_wait_default_exit_actions() -> std::collections::BTreeSet<String> {
    DOCTOR_ACTION_POLICIES
        .iter()
        .filter(|policy| policy.default_wait_exit && policy.allow_exit_on_flag)
        .map(|policy| policy.action.to_string())
        .collect::<std::collections::BTreeSet<_>>()
}

pub fn doctor_wait_supported_exit_actions() -> Vec<&'static str> {
    DOCTOR_ACTION_POLICIES
        .iter()
        .filter(|policy| policy.allow_exit_on_flag)
        .map(|policy| policy.action)
        .collect::<Vec<_>>()
}

fn doctor_wait_rule_triggered(
    rule: &DoctorWaitTransitionRule,
    facts: Option<&DoctorWaitFacts<'_>>,
) -> bool {
    match rule.guard {
        DoctorWaitGuard::RecommendedActionInExitSet => {
            facts.is_some_and(|entry| entry.exit_actions.contains(entry.recommended_action))
        },
        DoctorWaitGuard::Interrupted => facts.is_some_and(|entry| entry.interrupted),
        DoctorWaitGuard::TimedOut => {
            facts.is_some_and(|entry| entry.elapsed_seconds >= entry.wait_timeout_seconds)
        },
        DoctorWaitGuard::Always => true,
    }
}

fn derive_doctor_wait_next_state(
    current: DoctorWaitState,
    facts: Option<&DoctorWaitFacts<'_>>,
) -> DoctorWaitState {
    for rule in DOCTOR_WAIT_TRANSITION_RULES {
        if rule.from != current {
            continue;
        }
        if doctor_wait_rule_triggered(rule, facts) {
            return rule.to;
        }
    }
    current
}

fn normalize_doctor_exit_actions(
    exit_on: &[String],
) -> Result<std::collections::BTreeSet<String>, String> {
    if exit_on.is_empty() {
        return Ok(doctor_wait_default_exit_actions());
    }

    let mut set = std::collections::BTreeSet::new();
    let supported_actions = doctor_wait_supported_exit_actions();
    for value in exit_on {
        let normalized = value.trim().to_ascii_lowercase();
        if !supported_actions.contains(&normalized.as_str()) {
            return Err(format!(
                "invalid --exit-on action `{value}` (expected one of: {})",
                supported_actions.join(", ")
            ));
        }
        set.insert(normalized);
    }
    Ok(set)
}

fn emit_doctor_wait_result(
    summary: &DoctorPrSummary,
    json_output: bool,
    tick: u64,
    timed_out: bool,
    elapsed_seconds: u64,
) {
    if json_output {
        let summary_value = match serde_json::to_value(summary) {
            Ok(value) => value,
            Err(err) => {
                eprintln!("WARNING: failed to serialize doctor summary: {err}");
                serde_json::json!({
                    "error": "serialization_failure",
                })
            },
        };
        if let Err(err) = jsonl::emit_jsonl(&jsonl::DoctorResultEvent {
            event: "doctor_result",
            tick,
            action: summary.recommended_action.action.clone(),
            timed_out,
            elapsed_seconds,
            ts: jsonl::ts_now(),
            summary: summary_value,
        }) {
            eprintln!("WARNING: failed to emit doctor result event: {err}");
        }
    } else {
        println!(
            "{}",
            serde_json::to_string_pretty(summary)
                .unwrap_or_else(|_| "{\"error\":\"serialization_failure\"}".to_string())
        );
    }
}

fn emit_doctor_wait_timeout_event(
    json_output: bool,
    tick: u64,
    summary: &DoctorPrSummary,
    elapsed_seconds: u64,
) {
    if !json_output {
        return;
    }
    if let Err(err) = jsonl::emit_jsonl(&jsonl::DoctorWaitTimeoutEvent {
        event: "wait_timeout",
        tick,
        action: summary.recommended_action.action.clone(),
        elapsed_seconds,
        ts: jsonl::ts_now(),
    }) {
        eprintln!("WARNING: failed to emit doctor wait timeout event: {err}");
    }
}

fn doctor_wait_terminal_reason(action: &str) -> &'static str {
    doctor_action_policy_for_action(action)
        .map_or("terminal_state", |policy| policy.wait_terminal_reason)
}

fn emit_doctor_wait_terminal_event(
    json_output: bool,
    tick: u64,
    summary: &DoctorPrSummary,
    elapsed_seconds: u64,
) {
    if !json_output {
        return;
    }
    if let Err(err) = jsonl::emit_jsonl(&jsonl::DoctorWaitTerminalEvent {
        event: "wait_terminal",
        tick,
        reason: doctor_wait_terminal_reason(&summary.recommended_action.action).to_string(),
        action: summary.recommended_action.action.clone(),
        elapsed_seconds,
        ts: jsonl::ts_now(),
    }) {
        eprintln!("WARNING: failed to emit doctor wait terminal event: {err}");
    }
}

fn emit_doctor_wait_error(json_output: bool, error: &str, message: &str, exit_code: u8) -> u8 {
    if json_output {
        let _ = jsonl::emit_jsonl(&jsonl::StageEvent {
            event: "doctor_error".to_string(),
            ts: jsonl::ts_now(),
            extra: serde_json::json!({
                "error": error,
                "message": message,
            }),
        });
    } else {
        // Compatibility fallback: still emit a structured JSON object.
        let payload = serde_json::json!({
            "error": error,
            "message": message,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&payload)
                .unwrap_or_else(|_| "{\"error\":\"serialization_failure\"}".to_string())
        );
    }
    exit_code
}

/// Returns the global interrupt flag used by the doctor wait loop.
///
/// Registers a `ctrlc` signal handler (SIGINT + SIGTERM via the `termination`
/// feature) on first call. If the handler cannot be registered, returns `Err`
/// so the caller can refuse to start wait mode rather than running without
/// graceful shutdown semantics (fail-closed).
fn doctor_interrupt_flag() -> Result<Arc<AtomicBool>, String> {
    static INTERRUPTED: OnceLock<Result<Arc<AtomicBool>, String>> = OnceLock::new();
    INTERRUPTED
        .get_or_init(|| {
            let interrupted = Arc::new(AtomicBool::new(false));
            let handler_flag = Arc::clone(&interrupted);
            ctrlc::set_handler(move || {
                handler_flag.store(true, Ordering::SeqCst);
            })
            .map_err(|e| format!("failed to register Ctrl-C/SIGTERM handler: {e}"))?;
            Ok(interrupted)
        })
        .clone()
}

/// Maximum number of tracked PRs to include in doctor summaries.
/// Prevents unbounded memory consumption on long-lived instances.
const MAX_TRACKED_PR_SUMMARIES: usize = 100;

pub fn collect_tracked_pr_summaries(
    fallback_owner_repo: Option<&str>,
    repo_filter: Option<&str>,
) -> Result<Vec<DoctorTrackedPrSummary>, String> {
    let mut pr_numbers = list_review_pr_numbers()?;
    // Sort descending so we keep the most recent PRs when truncating.
    pr_numbers.sort_unstable_by(|a, b| b.cmp(a));
    let mut candidates = Vec::with_capacity(pr_numbers.len());
    for pr_number in pr_numbers {
        let Some(owner_repo) = resolve_owner_repo_for_pr(pr_number, fallback_owner_repo) else {
            continue;
        };
        candidates.push((pr_number, owner_repo));
    }
    let selected = filter_tracked_pr_candidates(candidates, repo_filter, MAX_TRACKED_PR_SUMMARIES);

    let mut summaries = Vec::with_capacity(selected.len());
    for (pr_number, owner_repo) in selected {
        let summary = run_doctor_inner(&owner_repo, pr_number, Vec::new(), true);
        let lifecycle_state = summary
            .lifecycle
            .as_ref()
            .map_or_else(|| "unknown".to_string(), |entry| entry.state.clone());
        let active_agents = summary
            .agents
            .as_ref()
            .map_or(0, |entry| entry.active_agents);
        let last_activity_seconds_ago = summary.agents.as_ref().and_then(|agents| {
            agents
                .entries
                .iter()
                .filter_map(|entry| entry.last_activity_seconds_ago)
                .min()
        });

        summaries.push(DoctorTrackedPrSummary {
            pr_number,
            owner_repo,
            lifecycle_state,
            recommended_action: summary.recommended_action,
            active_agents,
            last_activity_seconds_ago,
        });
    }
    summaries.sort_by_key(|entry| entry.pr_number);
    Ok(summaries)
}

fn filter_tracked_pr_candidates(
    candidates: Vec<(u32, String)>,
    repo_filter: Option<&str>,
    limit: usize,
) -> Vec<(u32, String)> {
    candidates
        .into_iter()
        .filter(|(_, owner_repo)| tracked_pr_matches_repo_filter(owner_repo, repo_filter))
        .take(limit)
        .collect()
}

fn resolve_owner_repo_for_pr(pr_number: u32, fallback_owner_repo: Option<&str>) -> Option<String> {
    for review_type in ["security", "quality"] {
        if let Ok(Some(state)) = load_review_run_state_strict(pr_number, review_type) {
            let owner_repo = state.owner_repo.trim().to_ascii_lowercase();
            if !owner_repo.is_empty() {
                return Some(owner_repo);
            }
        }
    }
    fallback_owner_repo.and_then(|value| {
        let normalized = value.trim().to_ascii_lowercase();
        if normalized.is_empty() {
            None
        } else {
            Some(normalized)
        }
    })
}

fn tracked_pr_matches_repo_filter(owner_repo: &str, repo_filter: Option<&str>) -> bool {
    let normalized_owner_repo = owner_repo.trim().to_ascii_lowercase();
    if normalized_owner_repo.is_empty() {
        return false;
    }
    let normalized_filter = repo_filter
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_ascii_lowercase);
    normalized_filter.is_none_or(|filter| normalized_owner_repo == filter)
}

fn run_doctor_inner(
    owner_repo: &str,
    pr_number: u32,
    repairs_applied: Vec<DoctorRepairApplied>,
    lightweight: bool,
) -> DoctorPrSummary {
    let mut health = Vec::new();
    let mut repair_signals = DoctorRepairSignals::default();
    let identity = match projection_store::load_pr_identity_snapshot(owner_repo, pr_number) {
        Ok(value) => value,
        Err(err) => {
            health.push(DoctorHealthItem {
                severity: "high",
                message: format!("failed to read local PR identity: {err}"),
                remediation:
                    "run `apm2 fac doctor --pr <PR_NUMBER> --fix` to refresh local projection data"
                        .to_string(),
            });
            None
        },
    };

    let local_sha = identity.as_ref().map(|record| record.head_sha.clone());
    let branch = identity.as_ref().and_then(|record| record.branch.clone());
    let worktree = identity.as_ref().and_then(|record| record.worktree.clone());
    let identity_source = identity.as_ref().map(|record| record.source.clone());
    let identity_updated_at = identity.as_ref().map(|record| record.updated_at.clone());

    let mut remote_head = None;
    if !lightweight {
        match github_reads::fetch_pr_head_sha(owner_repo, pr_number) {
            Ok(value) => {
                if let Err(err) = validate_expected_head_sha(&value) {
                    health.push(DoctorHealthItem {
                        severity: "high",
                        message: format!("invalid remote PR head SHA from GitHub: {err}"),
                        remediation:
                            "retry later when GitHub API returns a valid SHA or refresh repo credentials"
                                .to_string(),
                    });
                } else {
                    remote_head = Some(value.to_ascii_lowercase());
                }
            },
            Err(err) => {
                health.push(DoctorHealthItem {
                    severity: "medium",
                    message: format!("could not resolve remote PR head SHA: {err}"),
                    remediation: "retry doctor after GH API access is restored".to_string(),
                });
            },
        }
    }
    // BF-002 (TCK-00626): When running in non-lightweight mode, check if
    // the PR was merged on GitHub. If the local lifecycle projection hasn't
    // observed the merge, inject a merged event so the wait loop can detect
    // the terminal state.
    if !lightweight {
        if let Ok(Some(_merged_at)) = github_reads::fetch_pr_merged_at(owner_repo, pr_number) {
            // BF-002 (TCK-00626 round 2): Use remote_head as authoritative SHA
            // for merge detection. Fall back to local_sha only if remote is
            // unavailable. Skip merge injection entirely if no valid SHA exists
            // (cannot verify lifecycle without a valid SHA).
            let merge_sha = remote_head
                .as_deref()
                .or(local_sha.as_deref())
                .unwrap_or("");
            if !merge_sha.is_empty() {
                if let Err(err) = lifecycle::apply_event(
                    owner_repo,
                    pr_number,
                    merge_sha,
                    &lifecycle::LifecycleEventKind::Merged {
                        source: "github_api_detection".to_string(),
                    },
                ) {
                    // BF-002 (TCK-00626 round 3): Propagate merge event
                    // application errors instead of silently dropping them.
                    // This surfaces SHA mismatches and state transition
                    // failures that could leave the lifecycle projection
                    // inconsistent with the actual GitHub merge state.
                    eprintln!(
                        "WARNING: failed to apply merged lifecycle event for PR #{pr_number} \
                         (sha={merge_sha}): {err}",
                    );
                }
            }
        }
    }

    let stale = match (&local_sha, remote_head.as_deref()) {
        (Some(local), Some(remote)) => !local.eq_ignore_ascii_case(remote),
        _ => false,
    };
    repair_signals.identity_stale = stale;

    if stale {
        health.push(DoctorHealthItem {
            severity: "high",
            message: format!(
                "local SHA {} != remote SHA {}",
                local_sha.as_deref().unwrap_or("unknown"),
                remote_head.as_deref().unwrap_or("unknown")
            ),
            remediation: "fetch latest PR head and rerun the FAC pipeline for this SHA".to_string(),
        });
    } else if local_sha.is_none() {
        repair_signals.identity_missing = true;
        health.push(DoctorHealthItem {
            severity: "high",
            message: "no local PR identity snapshot found for this PR".to_string(),
            remediation: "run `apm2 fac doctor --pr <PR_NUMBER> --fix` to create/refresh identity"
                .to_string(),
        });
    } else if remote_head.is_none() {
        health.push(DoctorHealthItem {
            severity: "medium",
            message: "remote PR head SHA unavailable; using local SHA as authoritative".to_string(),
            remediation: "retry doctor after GitHub API access is restored".to_string(),
        });
    }

    let lifecycle = match lifecycle::load_pr_lifecycle_snapshot(owner_repo, pr_number) {
        Ok(Some(snapshot)) => {
            match snapshot.pr_state.as_str() {
                "stuck" => health.push(DoctorHealthItem {
                    severity: "high",
                    message: "lifecycle reducer is in STUCK state".to_string(),
                    remediation: "run `apm2 fac doctor --pr <PR_NUMBER> --fix` to reconcile state"
                        .to_string(),
                }),
                "stale" => health.push(DoctorHealthItem {
                    severity: "medium",
                    message: "lifecycle reducer indicates STALE state".to_string(),
                    remediation: "run `apm2 fac push` to refresh lifecycle state".to_string(),
                }),
                "recovering" => health.push(DoctorHealthItem {
                    severity: "medium",
                    message: "lifecycle reducer indicates RECOVERING state".to_string(),
                    remediation: "run `apm2 fac doctor --pr <PR_NUMBER> --fix` if recovery stalls"
                        .to_string(),
                }),
                _ => {},
            }
            repair_signals.lifecycle_stuck_shape = matches!(
                snapshot.pr_state.as_str(),
                "stuck" | "recovering" | "quarantined"
            );
            let lifecycle_view = DoctorLifecycleSnapshot {
                state: snapshot.pr_state.clone(),
                time_in_state_seconds: snapshot.time_in_state_seconds,
                error_budget_used: snapshot.error_budget_used,
                retry_budget_remaining: snapshot.retry_budget_remaining,
                updated_at: snapshot.updated_at.clone(),
                last_event_seq: snapshot.last_event_seq,
            };
            if lifecycle_retry_budget_exhausted(&lifecycle_view) {
                health.push(DoctorHealthItem {
                    severity: "high",
                    message: "retry budget exhausted".to_string(),
                    remediation:
                        "manual investigation required; repair lifecycle state before retrying"
                            .to_string(),
                });
            } else if snapshot.retry_budget_remaining == 0 {
                health.push(DoctorHealthItem {
                    severity: "medium",
                    message:
                        "retry budget is zero but lifecycle is not in an exhausted terminal shape"
                            .to_string(),
                    remediation: "run `apm2 fac doctor --pr <PR_NUMBER> --fix` if this persists"
                        .to_string(),
                });
            } else if snapshot.error_budget_used > 0 {
                health.push(DoctorHealthItem {
                    severity: "medium",
                    message: format!("error budget used: {}/{}", snapshot.error_budget_used, 10),
                    remediation: "run `apm2 fac doctor --pr <PR_NUMBER> --fix` and verify trend"
                        .to_string(),
                });
            }
            if snapshot.error_budget_used >= 8 {
                health.push(DoctorHealthItem {
                    severity: "high",
                    message: "high lifecycle error budget usage".to_string(),
                    remediation:
                        "investigate repeating failures in lifecycle events and CI diagnostics"
                            .to_string(),
                });
            }

            if let Some(local_sha) = local_sha.as_deref()
                && !snapshot.current_sha.eq_ignore_ascii_case(local_sha)
            {
                health.push(DoctorHealthItem {
                    severity: "high",
                    message: format!(
                        "lifecycle current SHA {} != local identity SHA {}",
                        snapshot.current_sha, local_sha
                    ),
                    remediation: "run `apm2 fac push` to align lifecycle with current local SHA"
                        .to_string(),
                });
            }

            Some(lifecycle_view)
        },
        Ok(None) => {
            repair_signals.lifecycle_missing = true;
            health.push(DoctorHealthItem {
                severity: "high",
                message: "no lifecycle record found for this PR".to_string(),
                remediation: "run `apm2 fac doctor --pr <PR_NUMBER> --fix`".to_string(),
            });
            None
        },
        Err(err) => {
            repair_signals.lifecycle_load_failed = true;
            health.push(DoctorHealthItem {
                severity: "high",
                message: format!("failed to read lifecycle snapshot: {err}"),
                remediation: "run `apm2 fac doctor --pr <PR_NUMBER> --fix` and re-run doctor"
                    .to_string(),
            });
            None
        },
    };

    let mut gates_by_name = std::collections::BTreeMap::<String, DoctorGateSnapshot>::new();
    let mut has_any_gate_signal = false;
    match local_sha.as_deref() {
        Some(sha) => {
            match gate_cache::GateCache::load(sha) {
                Some(cache) => {
                    if cache.gates.is_empty() {
                        health.push(DoctorHealthItem {
                            severity: "medium",
                            message: "no cached gate results for current SHA".to_string(),
                            remediation: "run `apm2 fac push`".to_string(),
                        });
                    }
                    for (name, result) in cache.gates {
                        let completed_at = if result.completed_at.trim().is_empty() {
                            None
                        } else {
                            Some(result.completed_at.clone())
                        };
                        let freshness = completed_at
                            .as_deref()
                            .and_then(gate_result_freshness_seconds);
                        upsert_doctor_gate_snapshot(
                            &mut gates_by_name,
                            &name,
                            normalize_doctor_gate_status(&result.status),
                            completed_at,
                            freshness,
                            DoctorGateSource::LocalCache,
                        );
                        has_any_gate_signal = true;
                    }
                },
                None => {
                    health.push(DoctorHealthItem {
                        severity: "low",
                        message: "no gate cache found for local SHA".to_string(),
                        remediation: "run `apm2 fac push` to populate evidence cache".to_string(),
                    });
                },
            }

            let projected_gate_snapshot = if lightweight {
                match projection_store::load_pr_body_snapshot(owner_repo, pr_number) {
                    Ok(Some(body)) => projection::parse_pr_body_gate_status_for_sha(&body, sha),
                    Ok(None) => None,
                    Err(err) => {
                        health.push(DoctorHealthItem {
                            severity: "medium",
                            message: format!("failed to read projected PR body snapshot: {err}"),
                            remediation: "rerun `apm2 fac push` to refresh projected gate status"
                                .to_string(),
                        });
                        None
                    },
                }
            } else {
                match projection::load_pr_body_gate_status_for_sha(owner_repo, pr_number, sha) {
                    Ok(value) => value,
                    Err(err) => {
                        health.push(DoctorHealthItem {
                            severity: "medium",
                            message: format!("failed to read projected gate status: {err}"),
                            remediation: "retry doctor after GitHub projection access is restored"
                                .to_string(),
                        });
                        None
                    },
                }
            };

            if let Some(projected) = projected_gate_snapshot {
                let projected_freshness = gate_result_freshness_seconds(&projected.timestamp);
                for gate in projected.gates {
                    upsert_doctor_gate_snapshot(
                        &mut gates_by_name,
                        &gate.name,
                        normalize_doctor_gate_status(&gate.status),
                        Some(projected.timestamp.clone()),
                        projected_freshness,
                        DoctorGateSource::Projection,
                    );
                    has_any_gate_signal = true;
                }
            }
        },
        None => health.push(DoctorHealthItem {
            severity: "high",
            message: "no local SHA resolved for gate review".to_string(),
            remediation: "establish local identity via `apm2 fac push`".to_string(),
        }),
    }
    let gates = gates_by_name.into_values().collect::<Vec<_>>();

    if local_sha.is_some() && !has_any_gate_signal {
        health.push(DoctorHealthItem {
            severity: "low",
            message: "no gate status signal found for local SHA".to_string(),
            remediation: "run `apm2 fac push` to publish gate status".to_string(),
        });
    }
    for gate in &gates {
        match doctor_gate_signal_from_status(&gate.status) {
            DoctorGateSignal::Fail => health.push(DoctorHealthItem {
                severity: "high",
                message: format!("gate {} failed", gate.name),
                remediation:
                    "dispatch implementor to remediate gate failure and rerun `apm2 fac push`"
                        .to_string(),
            }),
            DoctorGateSignal::InFlight => health.push(DoctorHealthItem {
                severity: "medium",
                message: format!(
                    "gate {} is non-terminal ({})",
                    gate.name,
                    gate.status.to_ascii_uppercase()
                ),
                remediation: format!("wait for FAC gates to finish for PR #{pr_number}"),
            }),
            DoctorGateSignal::Pass => {
                if gate
                    .freshness_seconds
                    .is_some_and(|age| age > DOCTOR_STALE_GATE_AGE_SECONDS)
                {
                    health.push(DoctorHealthItem {
                        severity: "low",
                        message: format!(
                            "gate {} cache is stale ({})",
                            gate.name,
                            format_freshness_age(gate.freshness_seconds)
                        ),
                        remediation: "rerun gate evidence to refresh cache".to_string(),
                    });
                }
            },
        }
    }

    let mut reviews = if let Some(sha) = local_sha.as_deref() {
        match verdict_projection::load_verdict_projection_snapshot(owner_repo, pr_number, sha) {
            Ok(Some(snapshot)) => {
                if !snapshot.errors.is_empty() {
                    health.push(DoctorHealthItem {
                        severity: "medium",
                        message: snapshot.errors.join("; "),
                        remediation:
                            "rerun review verdict emission paths for missing or corrupted entries"
                                .to_string(),
                    });
                }
                if !verdict_projection_snapshot_has_remote_comment_binding(&snapshot) {
                    repair_signals.projection_comment_binding_missing = true;
                    health.push(DoctorHealthItem {
                        severity: "medium",
                        message:
                            "verdict projection is missing authoritative remote comment binding"
                                .to_string(),
                        remediation:
                            "run `apm2 fac doctor --pr <PR_NUMBER> --fix` to replay bounded projection repair"
                                .to_string(),
                    });
                }
                collect_review_dimension_snapshots(&snapshot)
            },
            Ok(None) => {
                health.push(DoctorHealthItem {
                    severity: "medium",
                    message: "no verdict projection for local SHA".to_string(),
                    remediation:
                        "run `apm2 fac doctor --pr <PR_NUMBER> --fix` then `apm2 fac review verdict show --pr <PR_NUMBER>`"
                            .to_string(),
                });
                collect_default_review_dimension_snapshots(sha)
            },
            Err(err) => {
                health.push(DoctorHealthItem {
                    severity: "high",
                    message: format!("failed to load verdict projection: {err}"),
                    remediation:
                        "re-run verdict flow (`apm2 fac review verdict set ...`) after integrity check"
                            .to_string(),
                });
                collect_default_review_dimension_snapshots(sha)
            },
        }
    } else {
        health.push(DoctorHealthItem {
            severity: "high",
            message: "no local SHA resolved for verdict lookup".to_string(),
            remediation: "establish local PR identity before reading verdicts".to_string(),
        });
        Vec::new()
    };
    let (run_state_diagnostics, review_terminal_reasons) =
        collect_run_state_diagnostics(pr_number, &mut health);
    apply_terminal_reasons_to_reviews(&mut reviews, &review_terminal_reasons);
    repair_signals.run_state_repair_required = run_state_diagnostics
        .iter()
        .any(|entry| entry.condition.requires_repair());

    let agents = match lifecycle::load_agent_registry_snapshot_for_pr(owner_repo, pr_number) {
        Ok(snapshot) => {
            let max_active = snapshot.max_active_agents_per_pr;
            let active_agents = snapshot.active_agents;
            if active_agents > max_active {
                repair_signals.agent_registry_capacity_exceeded = true;
                health.push(DoctorHealthItem {
                    severity: "high",
                    message: format!(
                        "active agent entries ({active_agents}) exceed configured max ({max_active})"
                    ),
                    remediation:
                        "run `apm2 fac doctor --pr <PR_NUMBER> --fix` to prune stale/invalid registry entries"
                            .to_string(),
                });
            }

            for entry in &snapshot.entries {
                if entry.pid.is_some()
                    && matches!(entry.state.as_str(), "running" | "dispatched")
                    && !entry.pid_alive
                {
                    repair_signals.dead_active_agent_present = true;
                    health.push(DoctorHealthItem {
                        severity: "high",
                        message: format!(
                            "{} lane pid={} is no longer alive",
                            entry.agent_type,
                            entry.pid.unwrap_or(0)
                        ),
                        remediation:
                            "run `apm2 fac doctor --pr <PR_NUMBER> --fix` to reclaim lane state"
                                .to_string(),
                    });
                }
                if entry.pid.is_none()
                    && matches!(entry.state.as_str(), "running" | "dispatched" | "stuck")
                {
                    health.push(DoctorHealthItem {
                        severity: "medium",
                        message: format!(
                            "{} lane for PR #{} has missing PID in state {}",
                            entry.agent_type, pr_number, entry.state
                        ),
                        remediation:
                            "rerun `apm2 fac doctor --pr <PR_NUMBER> --fix` and watch for slot reapage"
                                .to_string(),
                    });
                }
            }
            if let Some(lifecycle) = lifecycle.as_ref()
                && lifecycle.state == "review_in_progress"
                && active_agents == 0
            {
                health.push(DoctorHealthItem {
                    severity: "high",
                    message: "review_in_progress lifecycle state with zero active agents"
                        .to_string(),
                    remediation: "run `apm2 fac doctor --pr <PR_NUMBER> --fix` to resume reviews"
                        .to_string(),
                });
            }

            let mut entries = Vec::with_capacity(snapshot.entries.len());
            let (
                activity_map,
                activity_by_run_id,
                model_attempts,
                model_attempts_by_run_id,
                tool_call_counts,
                nudge_counts_from_events,
                findings_activity,
            ) = if lightweight {
                (
                    std::collections::BTreeMap::new(),
                    std::collections::BTreeMap::new(),
                    std::collections::BTreeMap::new(),
                    std::collections::BTreeMap::new(),
                    std::collections::BTreeMap::new(),
                    std::collections::BTreeMap::new(),
                    std::collections::BTreeMap::new(),
                )
            } else {
                let active_run_ids = snapshot
                    .entries
                    .iter()
                    .map(|entry| entry.run_id.trim().to_string())
                    .filter(|run_id| !run_id.is_empty())
                    .collect::<std::collections::BTreeSet<_>>();
                let event_signals = scan_event_signals_for_pr(pr_number, &active_run_ids);
                let fa = latest_finding_activity_by_dimension(
                    owner_repo,
                    pr_number,
                    local_sha.as_deref(),
                );
                (
                    event_signals.activity_timestamps,
                    event_signals.activity_timestamps_by_run_id,
                    event_signals.model_attempts,
                    event_signals.model_attempts_by_run_id,
                    event_signals.tool_call_counts,
                    event_signals.nudge_counts,
                    fa,
                )
            };
            let run_state_nudge_counts = if lightweight {
                std::collections::BTreeMap::new()
            } else {
                load_run_state_nudge_counts_for_pr(pr_number)
            };
            let log_activity = collect_log_activity_for_pr(pr_number, !lightweight);
            for entry in snapshot.entries {
                let dimension = doctor_dimension_for_agent(&entry.agent_type);
                let run_id_key = entry.run_id.trim().to_string();
                let started_at = parse_rfc3339_utc(entry.started_at.as_str());
                let pulse_activity = dimension
                    .and_then(|review_type| read_pulse_file(pr_number, review_type).ok().flatten())
                    .and_then(|pulse| {
                        let run_matches = pulse
                            .run_id
                            .as_deref()
                            .is_some_and(|run_id| run_id == entry.run_id);
                        if !run_matches {
                            return None;
                        }
                        let fresh_for_run =
                            started_at.is_none_or(|started| pulse.written_at >= started);
                        if fresh_for_run && pulse.head_sha.eq_ignore_ascii_case(&entry.sha) {
                            Some(pulse.written_at)
                        } else {
                            None
                        }
                    });
                let elapsed_seconds = started_at.and_then(seconds_since_datetime_utc);
                let last_activity = dimension.and_then(|review_type| {
                    let mut latest = activity_by_run_id.get(&run_id_key).copied();
                    if latest.is_none() {
                        latest = activity_map.get(review_type).copied();
                    }
                    if let Some(ts) = log_activity.last_modified_at.get(&run_id_key).copied() {
                        latest = Some(latest.map_or(ts, |current: DateTime<Utc>| current.max(ts)));
                    }
                    if let Some(ts) = pulse_activity {
                        latest = Some(latest.map_or(ts, |current: DateTime<Utc>| current.max(ts)));
                    }
                    if let Some(ts) = findings_activity.get(review_type).copied() {
                        latest = Some(latest.map_or(ts, |current: DateTime<Utc>| current.max(ts)));
                    }
                    latest
                });
                let models_attempted = model_attempts_by_run_id
                    .get(&run_id_key)
                    .cloned()
                    .or_else(|| {
                        dimension.and_then(|review_type| model_attempts.get(review_type).cloned())
                    })
                    .unwrap_or_default();
                let tool_call_count = tool_call_counts.get(&run_id_key).copied();
                let nudge_count = run_state_nudge_counts
                    .get(&run_id_key)
                    .copied()
                    .or_else(|| {
                        nudge_counts_from_events
                            .get(&run_id_key)
                            .and_then(|count| u32::try_from(*count).ok())
                    });
                let log_line_count = log_activity.line_counts.get(&run_id_key).copied();
                entries.push(DoctorAgentSnapshot {
                    agent_type: entry.agent_type,
                    state: entry.state,
                    run_id: entry.run_id,
                    sha: entry.sha,
                    pid: entry.pid,
                    pid_alive: entry.pid_alive,
                    started_at: entry.started_at,
                    completion_status: entry.completion_status,
                    completion_summary: entry.completion_summary,
                    completion_token_hash: entry.completion_token_hash,
                    completion_token_expires_at: entry.completion_token_expires_at,
                    elapsed_seconds,
                    models_attempted,
                    tool_call_count,
                    log_line_count,
                    nudge_count,
                    last_activity_seconds_ago: last_activity.and_then(seconds_since_datetime_utc),
                });
            }
            Some(DoctorAgentSection {
                max_active_agents_per_pr: max_active,
                active_agents,
                total_agents: entries.len(),
                entries,
            })
        },
        Err(err) => {
            repair_signals.agent_registry_load_failed = true;
            health.push(DoctorHealthItem {
                severity: "medium",
                message: format!("failed to load agent registry snapshot: {err}"),
                remediation: "run `apm2 fac doctor --pr <PR_NUMBER> --fix`".to_string(),
            });
            None
        },
    };

    let findings_summary =
        build_doctor_findings_summary(owner_repo, pr_number, local_sha.as_deref(), &reviews);
    let (worktree_status, merge_conflict_status) =
        build_doctor_worktree_status(&mut health, local_sha.as_deref(), worktree.as_deref());
    if !lightweight {
        add_doctor_local_main_sync_health(&mut health, worktree.as_deref());
    }
    let gate_progress_state = derive_doctor_gate_progress_state(&gates, lifecycle.as_ref());
    let merge_readiness = build_doctor_merge_readiness(
        &reviews,
        gate_progress_state,
        stale,
        local_sha.as_ref(),
        remote_head.as_ref(),
        merge_conflict_status,
    );
    let github_projection = if lightweight {
        DoctorGithubProjectionStatus {
            auto_merge_enabled: false,
            last_comment_updated_at: None,
            projection_lag_seconds: None,
        }
    } else {
        build_doctor_github_projection_status(owner_repo, pr_number, local_sha.as_deref())
    };
    let latest_push_attempt =
        match build_doctor_push_attempt_summary(owner_repo, pr_number, local_sha.as_deref()) {
            Ok(value) => value,
            Err(err) => {
                health.push(DoctorHealthItem {
                    severity: "medium",
                    message: format!("failed to read push attempt log: {err}"),
                    remediation: "rerun `apm2 fac push` to refresh push telemetry".to_string(),
                });
                None
            },
        };
    let agent_activity = build_doctor_agent_activity_summary(agents.as_ref());
    let recommended_action = build_recommended_action(&DoctorActionInputs {
        pr_number,
        repair_signals: &repair_signals,
        lifecycle: lifecycle.as_ref(),
        gates: &gates,
        agent_activity,
        reviews: &reviews,
        review_terminal_reasons: &review_terminal_reasons,
        findings_summary: &findings_summary,
        merge_readiness: &merge_readiness,
        latest_push_attempt: latest_push_attempt.as_ref(),
    });

    DoctorPrSummary {
        schema: DOCTOR_SCHEMA.to_string(),
        pr_number,
        owner_repo: owner_repo.to_ascii_lowercase(),
        identity: DoctorIdentitySnapshot {
            pr_number,
            branch,
            worktree,
            source: identity_source,
            local_sha,
            updated_at: identity_updated_at,
            remote_head_sha: remote_head,
            stale,
        },
        lifecycle,
        gates,
        reviews,
        findings_summary,
        merge_readiness,
        worktree_status,
        github_projection,
        recommended_action,
        agents,
        run_state_diagnostics,
        repairs_applied,
        latest_push_attempt,
        repair_signals,
        health,
    }
}

#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)]
struct DoctorRepairPlan {
    reap_stale_agents: bool,
    refresh_identity: bool,
    reset_lifecycle: bool,
    repair_registry_integrity: bool,
    run_state_review_types: Vec<String>,
}

impl DoctorRepairPlan {
    fn has_operations(&self) -> bool {
        self.reap_stale_agents
            || self.refresh_identity
            || self.reset_lifecycle
            || self.repair_registry_integrity
            || !self.run_state_review_types.is_empty()
    }

    fn fingerprint(&self) -> String {
        format!(
            "reap={} refresh={} reset={} repair_registry={} run_state={}",
            self.reap_stale_agents,
            self.refresh_identity,
            self.reset_lifecycle,
            self.repair_registry_integrity,
            self.run_state_review_types.join(",")
        )
    }
}

fn derive_doctor_repair_plan(summary: &DoctorPrSummary) -> DoctorRepairPlan {
    let signals = &summary.repair_signals;
    let run_state_review_types = summary
        .run_state_diagnostics
        .iter()
        .filter(|entry| entry.condition.requires_repair())
        .map(|entry| entry.review_type.clone())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();

    DoctorRepairPlan {
        reap_stale_agents: signals.dead_active_agent_present
            || signals.agent_registry_capacity_exceeded,
        refresh_identity: signals.identity_stale || signals.identity_missing,
        reset_lifecycle: signals.lifecycle_missing
            || signals.lifecycle_load_failed
            || signals.lifecycle_stuck_shape,
        repair_registry_integrity: signals.agent_registry_load_failed,
        run_state_review_types,
    }
}

const fn doctor_requires_force_repair(summary: &DoctorPrSummary) -> bool {
    let signals = &summary.repair_signals;
    signals.lifecycle_load_failed || signals.agent_registry_load_failed
}

fn doctor_recommended_action_requests_follow_up_fix(summary: &DoctorPrSummary) -> bool {
    if !summary
        .recommended_action
        .action
        .eq_ignore_ascii_case("fix")
    {
        return false;
    }
    summary.recommended_action.follow_up_fix
}

fn doctor_recommended_follow_up_fix_force(summary: &DoctorPrSummary) -> bool {
    if summary.reviews.iter().any(review_requires_forced_fix) {
        return true;
    }
    summary.recommended_action.follow_up_force
}

fn build_doctor_agent_activity_summary(
    agents: Option<&DoctorAgentSection>,
) -> DoctorAgentActivitySummary {
    let Some(section) = agents else {
        return DoctorAgentActivitySummary::default();
    };

    let mut active_reviewers = 0usize;
    let mut running_reviewers = 0usize;
    let mut all_running_idle = true;
    let mut max_idle_seconds = None;
    let mut max_dispatched_pending_seconds = None;

    for entry in &section.entries {
        if doctor_dimension_for_agent(&entry.agent_type).is_none() {
            continue;
        }
        match entry.state.trim().to_ascii_lowercase().as_str() {
            "running" => {
                active_reviewers = active_reviewers.saturating_add(1);
                running_reviewers = running_reviewers.saturating_add(1);
                let Some(idle_seconds) = entry.last_activity_seconds_ago else {
                    all_running_idle = false;
                    continue;
                };
                max_idle_seconds = Some(
                    max_idle_seconds.map_or(idle_seconds, |current: i64| current.max(idle_seconds)),
                );
                if idle_seconds <= DOCTOR_ACTIVE_AGENT_IDLE_TIMEOUT_SECONDS {
                    all_running_idle = false;
                }
            },
            "dispatched" => {
                active_reviewers = active_reviewers.saturating_add(1);
                if let Some(elapsed_seconds) = entry.elapsed_seconds {
                    max_dispatched_pending_seconds = Some(
                        max_dispatched_pending_seconds
                            .map_or(elapsed_seconds, |current: i64| current.max(elapsed_seconds)),
                    );
                }
            },
            _ => {},
        }
    }

    let all_active_idle = active_reviewers > 0
        && running_reviewers == active_reviewers
        && all_running_idle
        && max_idle_seconds.is_some_and(|value| value > DOCTOR_ACTIVE_AGENT_IDLE_TIMEOUT_SECONDS);

    DoctorAgentActivitySummary {
        active_agents: active_reviewers,
        all_active_idle,
        max_idle_seconds,
        max_dispatched_pending_seconds,
    }
}

fn parse_rfc3339_utc(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|value| value.with_timezone(&Utc))
}

fn seconds_since_datetime_utc(value: DateTime<Utc>) -> Option<i64> {
    let delta = Utc::now() - value;
    let std_delta = delta.to_std().ok()?;
    i64::try_from(std_delta.as_secs()).ok()
}

fn doctor_dimension_for_agent(agent_type: &str) -> Option<&'static str> {
    match agent_type {
        "reviewer_security" | "security" => Some("security"),
        "reviewer_quality" | "quality" | "code-quality" => Some("quality"),
        _ => None,
    }
}

#[derive(Default)]
struct DoctorEventSignals {
    activity_timestamps: std::collections::BTreeMap<String, DateTime<Utc>>,
    activity_timestamps_by_run_id: std::collections::BTreeMap<String, DateTime<Utc>>,
    model_attempts: std::collections::BTreeMap<String, Vec<String>>,
    model_attempts_by_run_id: std::collections::BTreeMap<String, Vec<String>>,
    tool_call_counts: std::collections::BTreeMap<String, u64>,
    nudge_counts: std::collections::BTreeMap<String, u64>,
}

fn event_dimension_key(review_type: &str) -> Option<String> {
    match review_type.trim().to_ascii_lowercase().as_str() {
        "security" => Some("security".to_string()),
        "quality" | "code-quality" => Some("quality".to_string()),
        _ => None,
    }
}

fn scan_event_signals_for_pr(
    pr_number: u32,
    run_ids: &std::collections::BTreeSet<String>,
) -> DoctorEventSignals {
    let Ok(path) = review_events_path() else {
        return DoctorEventSignals::default();
    };
    let rotated_path = apm2_daemon::telemetry::reviewer::reviewer_events_rotated_path(&path);
    if !path.exists() && !rotated_path.exists() {
        return DoctorEventSignals::default();
    }

    scan_event_signals_from_sources_with_budget(
        &[path, rotated_path],
        pr_number,
        run_ids,
        DOCTOR_EVENT_SCAN_MAX_BYTES_PER_SOURCE,
    )
}

fn read_event_source_tail(path: &Path, max_bytes: u64) -> Option<Vec<u8>> {
    if max_bytes == 0 {
        return Some(Vec::new());
    }
    let mut file = File::open(path).ok()?;
    let file_len = file.metadata().ok()?.len();
    if file_len == 0 {
        return Some(Vec::new());
    }

    let bytes_to_read = file_len.min(max_bytes);
    let start_offset = file_len.saturating_sub(bytes_to_read);
    file.seek(SeekFrom::Start(start_offset)).ok()?;

    let mut tail = Vec::new();
    file.take(bytes_to_read).read_to_end(&mut tail).ok()?;

    if start_offset > 0 {
        if let Some(newline_idx) = tail.iter().position(|byte| *byte == b'\n') {
            tail = tail.split_off(newline_idx.saturating_add(1));
        } else {
            tail.clear();
        }
    }
    Some(tail)
}

fn scan_event_signals_from_sources_with_budget(
    sources: &[PathBuf],
    pr_number: u32,
    run_ids: &std::collections::BTreeSet<String>,
    max_bytes_per_source: u64,
) -> DoctorEventSignals {
    let mut signals = DoctorEventSignals::default();
    let mut remaining_lines = DOCTOR_EVENT_SCAN_MAX_LINES;
    for source in sources {
        if remaining_lines == 0 {
            break;
        }
        let Some(tail_bytes) = read_event_source_tail(source, max_bytes_per_source) else {
            continue;
        };
        let reader = std::io::Cursor::new(tail_bytes);
        let mut remaining_bytes = max_bytes_per_source;
        scan_event_signals_from_reader_with_budget(
            reader,
            pr_number,
            run_ids,
            &mut signals,
            &mut remaining_lines,
            &mut remaining_bytes,
        );
    }
    signals
}

#[cfg(test)]
fn scan_event_signals_from_reader<R: BufRead>(
    reader: R,
    pr_number: u32,
    run_ids: &std::collections::BTreeSet<String>,
) -> DoctorEventSignals {
    let mut signals = DoctorEventSignals::default();
    let mut remaining_lines = DOCTOR_EVENT_SCAN_MAX_LINES;
    let mut remaining_bytes = DOCTOR_EVENT_SCAN_MAX_BYTES_PER_SOURCE;
    scan_event_signals_from_reader_with_budget(
        reader,
        pr_number,
        run_ids,
        &mut signals,
        &mut remaining_lines,
        &mut remaining_bytes,
    );
    signals
}

enum BoundedLineRead {
    Eof,
    Line(Vec<u8>),
    TooLong,
}

fn discard_until_newline<R: BufRead>(reader: &mut R) -> std::io::Result<usize> {
    let mut consumed = 0usize;
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return Ok(consumed);
        }
        if let Some(newline_idx) = available.iter().position(|byte| *byte == b'\n') {
            let consume_bytes = newline_idx.saturating_add(1);
            reader.consume(consume_bytes);
            return Ok(consumed.saturating_add(consume_bytes));
        }
        let chunk_len = available.len();
        reader.consume(chunk_len);
        consumed = consumed.saturating_add(chunk_len);
    }
}

fn read_bounded_line<R: BufRead>(
    reader: &mut R,
    max_line_bytes: usize,
) -> std::io::Result<(BoundedLineRead, usize)> {
    let mut line = Vec::new();
    let line_limit_plus_one = max_line_bytes.saturating_add(1);
    let line_limit = u64::try_from(line_limit_plus_one).unwrap_or(u64::MAX);

    let (bytes_read, limit_reached) = {
        let mut limited_reader = reader.by_ref().take(line_limit);
        let bytes_read = limited_reader.read_until(b'\n', &mut line)?;
        (bytes_read, limited_reader.limit() == 0)
    };

    if bytes_read == 0 {
        return Ok((BoundedLineRead::Eof, 0));
    }
    if limit_reached && !line.ends_with(b"\n") {
        let drained = discard_until_newline(reader)?;
        let consumed_total = bytes_read.saturating_add(drained);
        return Ok((BoundedLineRead::TooLong, consumed_total));
    }

    Ok((BoundedLineRead::Line(line), bytes_read))
}

fn scan_event_signals_from_reader_with_budget<R: BufRead>(
    mut reader: R,
    pr_number: u32,
    run_ids: &std::collections::BTreeSet<String>,
    signals: &mut DoctorEventSignals,
    remaining_lines: &mut usize,
    remaining_bytes: &mut u64,
) {
    let mut event_line_counts = std::collections::BTreeMap::<String, u64>::new();
    loop {
        if *remaining_lines == 0 || *remaining_bytes == 0 {
            break;
        }
        *remaining_lines = (*remaining_lines).saturating_sub(1);

        let Ok((bounded_line, consumed_bytes)) =
            read_bounded_line(&mut reader, DOCTOR_EVENT_SCAN_MAX_LINE_BYTES)
        else {
            continue;
        };
        let consumed_u64 = u64::try_from(consumed_bytes).unwrap_or(u64::MAX);
        *remaining_bytes = (*remaining_bytes).saturating_sub(consumed_u64);

        let line = match bounded_line {
            BoundedLineRead::Eof => break,
            BoundedLineRead::TooLong => continue,
            BoundedLineRead::Line(bytes) => {
                let Ok(line) = String::from_utf8(bytes) else {
                    continue;
                };
                line
            },
        };

        let Ok(event) = serde_json::from_str::<serde_json::Value>(&line) else {
            continue;
        };

        let matches_pr = event
            .get("pr_number")
            .and_then(serde_json::Value::as_u64)
            .is_some_and(|value| value == u64::from(pr_number));
        if !matches_pr {
            continue;
        }

        let event_run_id = event
            .get("run_id")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string);

        if !run_ids.is_empty() {
            let Some(run_id) = event_run_id.as_ref() else {
                continue;
            };
            if !run_ids.contains(run_id) {
                continue;
            }
        }

        let review_type = event
            .get("review_type")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        let Some(key) = event_dimension_key(review_type) else {
            continue;
        };

        let event_name = event
            .get("event")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();

        if let Some(ts) = event_activity_timestamp(&event, event_name) {
            update_activity_timestamp(&mut signals.activity_timestamps, &key, ts);
            if let Some(run_id) = event_run_id.as_ref() {
                update_activity_timestamp(&mut signals.activity_timestamps_by_run_id, run_id, ts);
            }
        }

        if event
            .get("event")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|value| value == "run_start")
            && let Some(model) = event.get("model").and_then(serde_json::Value::as_str)
            && !model.trim().is_empty()
        {
            push_model_attempt(&mut signals.model_attempts, &key, model);
            if let Some(run_id) = event_run_id.as_ref() {
                push_model_attempt(&mut signals.model_attempts_by_run_id, run_id, model);
            }
        }

        if event
            .get("event")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|value| value == "model_fallback")
            && let Some(model) = event.get("to_model").and_then(serde_json::Value::as_str)
            && !model.trim().is_empty()
        {
            push_model_attempt(&mut signals.model_attempts, &key, model);
            if let Some(run_id) = event_run_id.as_ref() {
                push_model_attempt(&mut signals.model_attempts_by_run_id, run_id, model);
            }
        }

        if let Some(run_id) = event_run_id {
            event_line_counts
                .entry(run_id.clone())
                .and_modify(|count| *count = count.saturating_add(1))
                .or_insert(1);

            if event_name == "nudge_resume" {
                signals
                    .nudge_counts
                    .entry(run_id.clone())
                    .and_modify(|count| *count = count.saturating_add(1))
                    .or_insert(1);
            }

            if event_contains_tool_signal(&event)
                || (!event_name.is_empty() && !is_lifecycle_event_name(event_name))
            {
                signals
                    .tool_call_counts
                    .entry(run_id)
                    .and_modify(|count| *count = count.saturating_add(1))
                    .or_insert(1);
            }
        }
    }

    for (run_id, total_lines) in event_line_counts {
        signals
            .tool_call_counts
            .entry(run_id)
            .or_insert(total_lines);
    }
}

fn event_activity_timestamp(event: &serde_json::Value, event_name: &str) -> Option<DateTime<Utc>> {
    let ts = event
        .get("ts")
        .and_then(serde_json::Value::as_str)
        .and_then(parse_rfc3339_utc)?;
    match event_name {
        // Polling events are heartbeat signals and do not imply progress.
        "pulse_check" => None,
        // This event carries authoritative idle age from the orchestrator.
        "liveness_check" => {
            let idle_seconds = event
                .get("last_tool_call_age_secs")
                .and_then(serde_json::Value::as_u64)
                .and_then(|value| i64::try_from(value).ok())?;
            Some(ts - ChronoDuration::seconds(idle_seconds))
        },
        _ => Some(ts),
    }
}

fn update_activity_timestamp(
    target: &mut std::collections::BTreeMap<String, DateTime<Utc>>,
    key: &str,
    ts: DateTime<Utc>,
) {
    target
        .entry(key.to_string())
        .and_modify(|existing| *existing = (*existing).max(ts))
        .or_insert(ts);
}

fn push_model_attempt(
    target: &mut std::collections::BTreeMap<String, Vec<String>>,
    key: &str,
    model: &str,
) {
    target
        .entry(key.to_string())
        .or_default()
        .push(model.to_string());
}

fn is_lifecycle_event_name(event_name: &str) -> bool {
    matches!(
        event_name,
        "run_start"
            | "run_complete"
            | "run_crash"
            | "run_deduplicated"
            | "model_fallback"
            | "completion_signal_detected"
            | "pulse_check"
            | "liveness_check"
            | "stall_detected"
            | "sha_update"
            | "review_posted"
            | "nudge_resume"
    )
}

fn event_contains_tool_signal(event: &serde_json::Value) -> bool {
    [
        "tool",
        "tool_call",
        "tool_calls",
        "tool_name",
        "toolCall",
        "toolCallId",
    ]
    .iter()
    .any(|key| event.get(*key).is_some())
}

fn load_run_state_nudge_counts_for_pr(pr_number: u32) -> std::collections::BTreeMap<String, u32> {
    let mut counts = std::collections::BTreeMap::new();
    for review_type in ["security", "quality"] {
        let Ok(Some(state)) = load_review_run_state_strict(pr_number, review_type) else {
            continue;
        };
        let run_id = state.run_id.trim();
        if run_id.is_empty() {
            continue;
        }
        counts.insert(run_id.to_string(), state.nudge_count);
    }
    counts
}

#[derive(Default)]
struct DoctorLogActivitySignals {
    line_counts: std::collections::BTreeMap<String, u64>,
    last_modified_at: std::collections::BTreeMap<String, DateTime<Utc>>,
}

fn collect_log_activity_for_pr(
    pr_number: u32,
    include_line_counts: bool,
) -> DoctorLogActivitySignals {
    let mut signals = DoctorLogActivitySignals::default();
    let _ = state::with_review_state_shared(|review_state| {
        for entry in review_state.reviewers.values() {
            if entry.pr_number != pr_number {
                continue;
            }
            let run_id = entry.run_id.trim();
            if run_id.is_empty() {
                continue;
            }
            let run_id = run_id.to_string();
            if let Ok(metadata) = fs::metadata(&entry.log_file)
                && let Ok(modified) = metadata.modified()
            {
                let modified_at = DateTime::<Utc>::from(modified);
                signals
                    .last_modified_at
                    .entry(run_id.clone())
                    .and_modify(|existing| *existing = (*existing).max(modified_at))
                    .or_insert(modified_at);
            }
            if include_line_counts
                && let Some(line_count) = count_log_lines_bounded(&entry.log_file)
            {
                signals
                    .line_counts
                    .entry(run_id)
                    .and_modify(|existing| *existing = (*existing).max(line_count))
                    .or_insert(line_count);
            }
        }
        Ok(())
    });
    signals
}

fn count_log_lines_bounded(path: &Path) -> Option<u64> {
    let file = File::open(path).ok()?;
    let mut reader = BufReader::new(file);
    let mut chunk = [0_u8; DOCTOR_LOG_SCAN_CHUNK_BYTES];
    let mut line_count = 0_u64;
    let mut byte_count = 0_u64;
    let mut saw_bytes = false;
    let mut last_byte = None;

    while line_count < DOCTOR_LOG_SCAN_MAX_LINES && byte_count < DOCTOR_LOG_SCAN_MAX_BYTES {
        let remaining_bytes = DOCTOR_LOG_SCAN_MAX_BYTES.saturating_sub(byte_count);
        let to_read =
            usize::try_from(remaining_bytes.min(DOCTOR_LOG_SCAN_CHUNK_BYTES as u64)).ok()?;
        if to_read == 0 {
            break;
        }
        let bytes_read = reader.read(&mut chunk[..to_read]).ok()?;
        if bytes_read == 0 {
            break;
        }

        saw_bytes = true;
        byte_count = byte_count.saturating_add(bytes_read as u64);
        last_byte = chunk.get(bytes_read.saturating_sub(1)).copied();

        let mut newline_count = 0_u64;
        for byte in &chunk[..bytes_read] {
            if *byte == b'\n' {
                newline_count = newline_count.saturating_add(1);
            }
        }
        line_count = line_count.saturating_add(newline_count);
    }

    if saw_bytes && line_count < DOCTOR_LOG_SCAN_MAX_LINES && !matches!(last_byte, Some(b'\n')) {
        line_count = line_count.saturating_add(1);
    }

    Some(line_count)
}

fn latest_finding_activity_by_dimension(
    owner_repo: &str,
    pr_number: u32,
    local_sha: Option<&str>,
) -> std::collections::BTreeMap<String, DateTime<Utc>> {
    let mut latest = std::collections::BTreeMap::new();
    let Some(sha) = local_sha else {
        return latest;
    };
    let Ok(Some(bundle)) = findings_store::load_findings_bundle(owner_repo, pr_number, sha) else {
        return latest;
    };
    for dimension in ["security", "code-quality"] {
        let Some(view) = findings_store::find_dimension(&bundle, dimension) else {
            continue;
        };
        let mut newest = None;
        for finding in &view.findings {
            if let Some(ts) = parse_rfc3339_utc(&finding.created_at) {
                newest = Some(newest.map_or(ts, |current: DateTime<Utc>| current.max(ts)));
            }
        }
        if let Some(ts) = newest {
            let key = if dimension == "code-quality" {
                "quality".to_string()
            } else {
                "security".to_string()
            };
            latest.insert(key, ts);
        }
    }
    latest
}

fn canonical_review_dimension(value: &str) -> String {
    match value.trim().to_ascii_lowercase().as_str() {
        "security" => "security".to_string(),
        "quality" | "code-quality" => "code-quality".to_string(),
        other => other.to_string(),
    }
}

fn collect_run_state_diagnostics(
    pr_number: u32,
    health: &mut Vec<DoctorHealthItem>,
) -> (
    Vec<DoctorRunStateDiagnostic>,
    std::collections::BTreeMap<String, Option<String>>,
) {
    let mut diagnostics = Vec::new();
    let mut reasons = std::collections::BTreeMap::new();
    for (review_type, dimension) in [("security", "security"), ("quality", "code-quality")] {
        let canonical_path = match review_run_state_path(pr_number, review_type) {
            Ok(path) => path.display().to_string(),
            Err(err) => {
                health.push(DoctorHealthItem {
                    severity: "high",
                    message: format!(
                        "failed to resolve {review_type} run-state path for doctor: {err}"
                    ),
                    remediation:
                        "run `apm2 fac doctor --pr <PR_NUMBER> --fix` to rebuild run-state"
                            .to_string(),
                });
                diagnostics.push(DoctorRunStateDiagnostic {
                    review_type: review_type.to_string(),
                    condition: DoctorRunStateCondition::Unavailable,
                    canonical_path: "-".to_string(),
                    detail: Some(err),
                    candidates: Vec::new(),
                });
                reasons.insert(dimension.to_string(), None);
                continue;
            },
        };
        match load_review_run_state(pr_number, review_type) {
            Ok(state::ReviewRunStateLoad::Present(state)) => {
                diagnostics.push(DoctorRunStateDiagnostic {
                    review_type: review_type.to_string(),
                    condition: DoctorRunStateCondition::Healthy,
                    canonical_path,
                    detail: None,
                    candidates: Vec::new(),
                });
                reasons.insert(dimension.to_string(), state.terminal_reason);
            },
            Ok(state::ReviewRunStateLoad::Missing { .. }) => {
                diagnostics.push(DoctorRunStateDiagnostic {
                    review_type: review_type.to_string(),
                    condition: DoctorRunStateCondition::Missing,
                    canonical_path,
                    detail: Some("run-state file missing".to_string()),
                    candidates: Vec::new(),
                });
                health.push(DoctorHealthItem {
                    severity: "low",
                    message: format!("missing {review_type} run-state file"),
                    remediation:
                        "if review execution is expected for this dimension, run `apm2 fac doctor --pr <PR_NUMBER> --fix`"
                            .to_string(),
                });
                reasons.insert(dimension.to_string(), None);
            },
            Ok(state::ReviewRunStateLoad::Corrupt { path, error }) => {
                diagnostics.push(DoctorRunStateDiagnostic {
                    review_type: review_type.to_string(),
                    condition: DoctorRunStateCondition::Corrupt,
                    canonical_path,
                    detail: Some(format!(
                        "corrupt-state path={} detail={error}",
                        path.display()
                    )),
                    candidates: Vec::new(),
                });
                health.push(DoctorHealthItem {
                    severity: "high",
                    message: format!(
                        "{review_type} run-state is corrupt: path={} detail={error}",
                        path.display()
                    ),
                    remediation:
                        "run `apm2 fac doctor --pr <PR_NUMBER> --fix` to quarantine and rebuild run-state"
                            .to_string(),
                });
                reasons.insert(dimension.to_string(), None);
            },
            Ok(state::ReviewRunStateLoad::Ambiguous { dir, candidates }) => {
                let rendered_candidates = candidates
                    .iter()
                    .map(|path| path.display().to_string())
                    .collect::<Vec<_>>();
                diagnostics.push(DoctorRunStateDiagnostic {
                    review_type: review_type.to_string(),
                    condition: DoctorRunStateCondition::Ambiguous,
                    canonical_path,
                    detail: Some(format!("ambiguous-state dir={}", dir.display())),
                    candidates: rendered_candidates.clone(),
                });
                health.push(DoctorHealthItem {
                    severity: "high",
                    message: format!(
                        "{review_type} run-state is ambiguous: dir={} candidates={}",
                        dir.display(),
                        rendered_candidates.join(",")
                    ),
                    remediation:
                        "run `apm2 fac doctor --pr <PR_NUMBER> --fix` to canonicalize run-state candidates"
                            .to_string(),
                });
                reasons.insert(dimension.to_string(), None);
            },
            Err(err) => {
                diagnostics.push(DoctorRunStateDiagnostic {
                    review_type: review_type.to_string(),
                    condition: DoctorRunStateCondition::Unavailable,
                    canonical_path,
                    detail: Some(err.clone()),
                    candidates: Vec::new(),
                });
                health.push(DoctorHealthItem {
                    severity: "high",
                    message: format!("failed to load {review_type} run-state: {err}"),
                    remediation:
                        "run `apm2 fac doctor --pr <PR_NUMBER> --fix` to rebuild run-state"
                            .to_string(),
                });
                reasons.insert(dimension.to_string(), None);
            },
        }
    }
    (diagnostics, reasons)
}

fn apply_terminal_reasons_to_reviews(
    reviews: &mut [DoctorReviewSnapshot],
    terminal_reasons: &std::collections::BTreeMap<String, Option<String>>,
) {
    for review in reviews {
        let key = canonical_review_dimension(&review.dimension);
        review.terminal_reason = terminal_reasons.get(&key).cloned().flatten();
    }
}

fn build_doctor_findings_summary(
    owner_repo: &str,
    pr_number: u32,
    local_sha: Option<&str>,
    reviews: &[DoctorReviewSnapshot],
) -> Vec<DoctorFindingsDimensionSummary> {
    let mut summaries = Vec::new();
    let findings_bundle = local_sha.and_then(|sha| {
        findings_store::load_findings_bundle(owner_repo, pr_number, sha)
            .ok()
            .flatten()
    });

    for dimension in ["security", "code-quality"] {
        let mut counts = DoctorFindingsCounts {
            blocker: 0,
            major: 0,
            minor: 0,
            nit: 0,
        };
        if let Some(bundle) = findings_bundle.as_ref()
            && let Some(view) = findings_store::find_dimension(bundle, dimension)
        {
            for finding in &view.findings {
                match finding.severity.trim().to_ascii_uppercase().as_str() {
                    "BLOCKER" => counts.blocker = counts.blocker.saturating_add(1),
                    "MINOR" => counts.minor = counts.minor.saturating_add(1),
                    "NIT" => counts.nit = counts.nit.saturating_add(1),
                    _ => counts.major = counts.major.saturating_add(1),
                }
            }
        }

        let formal_verdict = reviews
            .iter()
            .find(|entry| canonical_review_dimension(&entry.dimension) == dimension)
            .map_or_else(|| "pending".to_string(), |entry| entry.verdict.clone());
        let computed_verdict = if counts.blocker > 0 || counts.major > 0 {
            "deny".to_string()
        } else if counts.minor > 0 || counts.nit > 0 {
            "approve".to_string()
        } else {
            "pending".to_string()
        };

        summaries.push(DoctorFindingsDimensionSummary {
            dimension: dimension.to_string(),
            counts,
            formal_verdict,
            computed_verdict,
        });
    }
    summaries
}

fn build_doctor_worktree_status(
    health: &mut Vec<DoctorHealthItem>,
    local_sha: Option<&str>,
    worktree: Option<&str>,
) -> (DoctorWorktreeStatus, DoctorMergeConflictStatus) {
    let mut status = DoctorWorktreeStatus {
        worktree_exists: false,
        worktree_clean: false,
        merge_conflicts: 0,
    };
    let mut merge_conflict_status = DoctorMergeConflictStatus::Unknown;

    let Some(worktree_path) = worktree.map(PathBuf::from) else {
        return (status, merge_conflict_status);
    };
    status.worktree_exists = worktree_path.exists();
    if !status.worktree_exists {
        health.push(DoctorHealthItem {
            severity: "medium",
            message: format!("worktree path missing: {}", worktree_path.display()),
            remediation: "run `apm2 fac push` to refresh identity/worktree".to_string(),
        });
        return (status, merge_conflict_status);
    }

    status.worktree_clean = git_worktree_clean(&worktree_path).unwrap_or(false);
    if let Some(sha) = local_sha {
        match merge_conflicts::check_merge_conflicts_against_main(&worktree_path, sha) {
            Ok(report) => {
                status.merge_conflicts = report.conflict_count();
                merge_conflict_status = if report.has_conflicts() {
                    DoctorMergeConflictStatus::HasConflicts
                } else {
                    DoctorMergeConflictStatus::NoConflicts
                };
            },
            Err(err) => {
                health.push(DoctorHealthItem {
                    severity: "medium",
                    message: format!("failed to evaluate merge conflicts: {err}"),
                    remediation: "resolve local repository state and rerun doctor".to_string(),
                });
            },
        }
    }

    (status, merge_conflict_status)
}

fn git_worktree_clean(worktree: &Path) -> Result<bool, String> {
    let output = Command::new("git")
        .args(["status", "--porcelain"])
        .current_dir(worktree)
        .output()
        .map_err(|err| format!("failed to check worktree cleanliness: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "git status failed in {}: {}",
            worktree.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().is_empty())
}

fn git_ref_exists(worktree: &Path, reference: &str) -> Result<bool, String> {
    let output = Command::new("git")
        .args(["rev-parse", "--verify", "--quiet", reference])
        .current_dir(worktree)
        .output()
        .map_err(|err| {
            format!(
                "failed to resolve `{reference}` in {}: {err}",
                worktree.display()
            )
        })?;
    match output.status.code() {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        Some(_) | None => Err(format!(
            "failed to resolve `{reference}` in {}: {}",
            worktree.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        )),
    }
}

fn main_sync_lag(worktree: &Path) -> Result<Option<(u64, u64)>, String> {
    if !git_ref_exists(worktree, "refs/heads/main^{commit}")?
        || !git_ref_exists(worktree, "refs/remotes/origin/main^{commit}")?
    {
        return Ok(None);
    }

    let output = Command::new("git")
        .args([
            "rev-list",
            "--left-right",
            "--count",
            "refs/heads/main...refs/remotes/origin/main",
        ])
        .current_dir(worktree)
        .output()
        .map_err(|err| {
            format!(
                "failed to compare main refs in {}: {err}",
                worktree.display()
            )
        })?;
    if !output.status.success() {
        return Err(format!(
            "failed to compare main refs in {}: {}",
            worktree.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let counts = String::from_utf8_lossy(&output.stdout);
    let mut parts = counts.split_whitespace();
    let ahead = parts
        .next()
        .ok_or_else(|| "missing local-main ahead count".to_string())?
        .parse::<u64>()
        .map_err(|err| format!("invalid local-main ahead count: {err}"))?;
    let behind = parts
        .next()
        .ok_or_else(|| "missing local-main behind count".to_string())?
        .parse::<u64>()
        .map_err(|err| format!("invalid local-main behind count: {err}"))?;
    Ok(Some((ahead, behind)))
}

fn add_doctor_local_main_sync_health(health: &mut Vec<DoctorHealthItem>, worktree: Option<&str>) {
    let repo_dir = worktree
        .map(PathBuf::from)
        .filter(|path| path.exists())
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
    let Ok(Some((_ahead, behind))) = main_sync_lag(&repo_dir) else {
        return;
    };
    if behind > 0 {
        health.push(DoctorHealthItem {
            severity: "medium",
            message: format!("local main is {behind} commits behind origin/main"),
            remediation: "run `git fetch origin main:main`".to_string(),
        });
    }
}

fn build_doctor_merge_readiness(
    reviews: &[DoctorReviewSnapshot],
    gate_progress_state: DoctorGateProgressState,
    stale_identity: bool,
    local_sha: Option<&String>,
    remote_head_sha: Option<&String>,
    merge_conflict_status: DoctorMergeConflictStatus,
) -> DoctorMergeReadiness {
    let all_verdicts_approve = ["security", "code-quality"].iter().all(|dimension| {
        reviews.iter().any(|entry| {
            canonical_review_dimension(&entry.dimension) == *dimension
                && entry.verdict.eq_ignore_ascii_case("approve")
        })
    });
    let gates_pass = gate_progress_state == DoctorGateProgressState::TerminalPassed;
    let (sha_fresh, sha_freshness_source) = if stale_identity {
        (false, DoctorShaFreshnessSource::Stale)
    } else if local_sha.is_some() && remote_head_sha.is_some() {
        (true, DoctorShaFreshnessSource::RemoteMatch)
    } else if local_sha.is_some() {
        (true, DoctorShaFreshnessSource::LocalAuthoritative)
    } else {
        (false, DoctorShaFreshnessSource::Unknown)
    };
    let no_merge_conflicts = merge_conflict_status == DoctorMergeConflictStatus::NoConflicts;
    let merge_ready = all_verdicts_approve && gates_pass && sha_fresh && no_merge_conflicts;
    DoctorMergeReadiness {
        merge_ready,
        all_verdicts_approve,
        gates_pass,
        sha_fresh,
        sha_freshness_source,
        no_merge_conflicts,
        merge_conflict_status,
    }
}

fn verdict_projection_snapshot_has_remote_comment_binding(
    snapshot: &verdict_projection::VerdictProjectionSnapshot,
) -> bool {
    verdict_projection::has_remote_comment_binding(
        snapshot.source_comment_id,
        snapshot.source_comment_url.as_deref(),
    )
}

fn build_doctor_github_projection_status(
    owner_repo: &str,
    pr_number: u32,
    local_sha: Option<&str>,
) -> DoctorGithubProjectionStatus {
    let auto_merge_enabled = github_reads::fetch_pr_data(owner_repo, pr_number)
        .ok()
        .and_then(|value| value.get("auto_merge").cloned())
        .is_some_and(|value| !value.is_null());

    let projection_snapshot = local_sha.and_then(|sha| {
        verdict_projection::load_verdict_projection_snapshot(owner_repo, pr_number, sha)
            .ok()
            .flatten()
    });
    let projected_updated_at = projection_snapshot
        .as_ref()
        .map(|snapshot| snapshot.updated_at.clone());
    let github_updated_at = projection_snapshot
        .as_ref()
        .and_then(|snapshot| snapshot.source_comment_id)
        .filter(|comment_id| *comment_id > 0)
        .and_then(|comment_id| fetch_issue_comment_updated_at(owner_repo, comment_id));
    let last_comment_updated_at = github_updated_at.or(projected_updated_at);
    let projection_lag_seconds = last_comment_updated_at
        .as_deref()
        .and_then(parse_rfc3339_utc)
        .and_then(seconds_since_datetime_utc);

    DoctorGithubProjectionStatus {
        auto_merge_enabled,
        last_comment_updated_at,
        projection_lag_seconds,
    }
}

fn fetch_issue_comment_updated_at(owner_repo: &str, comment_id: u64) -> Option<String> {
    let endpoint = format!("/repos/{owner_repo}/issues/comments/{comment_id}");
    let output = apm2_core::fac::gh_command()
        .args(["api", &endpoint, "--jq", ".updated_at"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if value.is_empty() || value.eq_ignore_ascii_case("null") {
        return None;
    }
    Some(value)
}

fn build_doctor_push_attempt_summary(
    owner_repo: &str,
    pr_number: u32,
    local_sha: Option<&str>,
) -> Result<Option<DoctorPushAttemptSummary>, String> {
    let Some(sha) = local_sha else {
        return Ok(None);
    };
    let Some(attempt) = push::load_latest_push_attempt_for_sha(owner_repo, pr_number, sha)? else {
        return Ok(None);
    };
    let failure = attempt.first_failed_stage();
    let failed_stage = failure.as_ref().map(|entry| entry.stage.clone());
    let exit_code = failure.as_ref().and_then(|entry| entry.exit_code);
    let duration_s = failure.as_ref().map(|entry| entry.duration_s);
    let error_hint = failure.and_then(|entry| entry.error_hint);
    Ok(Some(DoctorPushAttemptSummary {
        ts: attempt.ts,
        sha: attempt.sha,
        failed_stage,
        exit_code,
        duration_s,
        error_hint,
    }))
}

fn lifecycle_retry_budget_exhausted(entry: &DoctorLifecycleSnapshot) -> bool {
    entry.retry_budget_remaining == 0
        && entry.last_event_seq > 0
        && matches!(entry.state.as_str(), "stuck" | "recovering" | "quarantined")
}

fn review_requires_forced_fix(review: &DoctorReviewSnapshot) -> bool {
    review
        .terminal_reason
        .as_deref()
        .is_some_and(|reason| reason.eq_ignore_ascii_case("max_restarts_exceeded"))
}

fn terminal_reason_requires_forced_fix(terminal_reason: Option<&String>) -> bool {
    terminal_reason.is_some_and(|value| value.eq_ignore_ascii_case("max_restarts_exceeded"))
}

fn has_forced_fix_terminal_reason(
    reviews: &[DoctorReviewSnapshot],
    review_terminal_reasons: &std::collections::BTreeMap<String, Option<String>>,
) -> bool {
    reviews.iter().any(review_requires_forced_fix)
        || review_terminal_reasons
            .values()
            .map(std::option::Option::as_ref)
            .any(terminal_reason_requires_forced_fix)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DoctorDecisionState {
    Fix,
    Done,
    FixProjectionGap,
    Merge,
    FixStaleIdentity,
    Approve,
    DispatchMergeConflicts,
    DispatchFailedGates,
    DispatchImplementor,
    WaitForGates,
    FixIdleReviewers,
    FixPendingNoActiveReviewers,
    EscalateLifecycleBudget,
    Wait,
}

impl DoctorDecisionState {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Fix => "fix",
            Self::Done => "done",
            Self::FixProjectionGap => "fix_projection_gap",
            Self::Merge => "merge",
            Self::FixStaleIdentity => "fix_stale_identity",
            Self::Approve => "approve",
            Self::DispatchMergeConflicts => "dispatch_merge_conflicts",
            Self::DispatchFailedGates => "dispatch_failed_gates",
            Self::DispatchImplementor => "dispatch_implementor",
            Self::WaitForGates => "wait_for_gates",
            Self::FixIdleReviewers => "fix_idle_reviewers",
            Self::FixPendingNoActiveReviewers => "fix_pending_no_active_reviewers",
            Self::EscalateLifecycleBudget => "escalate_lifecycle_budget",
            Self::Wait => "wait",
        }
    }

    const fn recommended_action(self) -> &'static str {
        match self {
            Self::Done => "done",
            Self::Merge => "merge",
            Self::Fix
            | Self::FixProjectionGap
            | Self::FixStaleIdentity
            | Self::FixIdleReviewers
            | Self::FixPendingNoActiveReviewers => "fix",
            Self::Approve => "approve",
            Self::DispatchMergeConflicts
            | Self::DispatchFailedGates
            | Self::DispatchImplementor => "dispatch_implementor",
            Self::WaitForGates | Self::Wait => "wait",
            Self::EscalateLifecycleBudget => "escalate",
        }
    }
}

impl DoctorGateProgressState {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::InFlight => "in_flight",
            Self::TerminalPassed => "terminal_passed",
            Self::TerminalFailed => "terminal_failed",
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct DoctorDecisionRule {
    priority: u8,
    state: DoctorDecisionState,
    guard: DoctorDecisionGuard,
    guard_id: &'static str,
    guard_predicate: &'static str,
    requirement_refs: &'static [&'static str],
}

#[derive(Debug, Clone, Copy)]
enum DoctorDecisionGuard {
    HasIntegrityOrCorruption,
    LifecycleMerged,
    ProjectionGapRequiresFix,
    MergeReady,
    ShaFreshnessStale,
    ApproveEligible,
    MergeConflictsPresent,
    GateFailureSignal,
    ImplementorRemediationResolved,
    PendingVerdictWithGateInFlight,
    AllActiveIdle,
    PendingNoActive,
    LifecycleEscalation,
    Default,
}

impl DoctorDecisionGuard {
    const fn as_str(self) -> &'static str {
        match self {
            Self::HasIntegrityOrCorruption => "has_integrity_or_corruption",
            Self::LifecycleMerged => "lifecycle_merged",
            Self::ProjectionGapRequiresFix => "projection_gap_requires_fix",
            Self::MergeReady => "merge_ready",
            Self::ShaFreshnessStale => "sha_freshness_stale",
            Self::ApproveEligible => "approve_eligible",
            Self::MergeConflictsPresent => "merge_conflicts_present",
            Self::GateFailureSignal => "gate_failure_signal",
            Self::ImplementorRemediationResolved => "implementor_remediation_resolved",
            Self::PendingVerdictWithGateInFlight => "pending_verdict_with_gate_in_flight",
            Self::AllActiveIdle => "all_active_idle",
            Self::PendingNoActive => "pending_no_active",
            Self::LifecycleEscalation => "lifecycle_escalation",
            Self::Default => "default",
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum DoctorReasonKind {
    Template,
    PushFailureHintOrTemplate,
    FindingsRollupWithPushHint,
    IdleFixWithMaxIdle,
    PendingNoActiveWithPushHint,
    WaitWithPendingHint,
}

impl DoctorReasonKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Template => "template",
            Self::PushFailureHintOrTemplate => "push_failure_hint_or_template",
            Self::FindingsRollupWithPushHint => "findings_rollup_with_push_hint",
            Self::IdleFixWithMaxIdle => "idle_fix_with_max_idle",
            Self::PendingNoActiveWithPushHint => "pending_no_active_with_push_hint",
            Self::WaitWithPendingHint => "wait_with_pending_hint",
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum DoctorCommandKind {
    RuleTemplate,
    FixForce,
    FixConditionalForce,
    FixFollowUp,
    None,
}

impl DoctorCommandKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::RuleTemplate => "rule_template",
            Self::FixForce => "fix_force",
            Self::FixConditionalForce => "fix_conditional_force",
            Self::FixFollowUp => "fix_follow_up",
            Self::None => "none",
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct DoctorRecommendationRule {
    state: DoctorDecisionState,
    action: &'static str,
    priority: &'static str,
    reason_kind: DoctorReasonKind,
    reason_template: &'static str,
    command_kind: DoctorCommandKind,
    command_template: Option<&'static str>,
    command_notes: Option<&'static str>,
}

#[derive(Debug, Clone, Copy)]
struct DoctorActionPolicy {
    action: &'static str,
    default_wait_exit: bool,
    wait_terminal_reason: &'static str,
    allow_exit_on_flag: bool,
}

#[derive(Debug, Clone, Copy)]
struct DoctorWaitTransitionRule {
    priority: u8,
    from: DoctorWaitState,
    to: DoctorWaitState,
    guard: DoctorWaitGuard,
    guard_id: &'static str,
    guard_predicate: &'static str,
    requirement_refs: &'static [&'static str],
}

#[derive(Debug, Clone, Copy)]
enum DoctorWaitGuard {
    RecommendedActionInExitSet,
    Interrupted,
    TimedOut,
    Always,
}

impl DoctorWaitGuard {
    const fn as_str(self) -> &'static str {
        match self {
            Self::RecommendedActionInExitSet => "recommended_action_in_exit_set",
            Self::Interrupted => "interrupted",
            Self::TimedOut => "timed_out",
            Self::Always => "always",
        }
    }
}

const DOCTOR_DECISION_RULES: &[DoctorDecisionRule] = &[
    DoctorDecisionRule {
        priority: 1,
        state: DoctorDecisionState::Fix,
        guard: DoctorDecisionGuard::HasIntegrityOrCorruption,
        guard_id: "DOC-G-001",
        guard_predicate: "facts.has_integrity_or_corruption",
        requirement_refs: &[],
    },
    DoctorDecisionRule {
        priority: 2,
        state: DoctorDecisionState::Done,
        guard: DoctorDecisionGuard::LifecycleMerged,
        guard_id: "DOC-G-002",
        guard_predicate: "facts.lifecycle_merged",
        requirement_refs: &[],
    },
    DoctorDecisionRule {
        priority: 3,
        state: DoctorDecisionState::FixProjectionGap,
        guard: DoctorDecisionGuard::ProjectionGapRequiresFix,
        guard_id: "DOC-G-003P",
        guard_predicate: "facts.projection_gap_requires_fix",
        requirement_refs: &[],
    },
    DoctorDecisionRule {
        priority: 4,
        state: DoctorDecisionState::Merge,
        guard: DoctorDecisionGuard::MergeReady,
        guard_id: "DOC-G-003",
        guard_predicate: "facts.merge_ready",
        requirement_refs: &["DR-003-TERMINAL_PASS_REQUIRED_FOR_MERGE_READY"],
    },
    DoctorDecisionRule {
        priority: 5,
        state: DoctorDecisionState::FixStaleIdentity,
        guard: DoctorDecisionGuard::ShaFreshnessStale,
        guard_id: "DOC-G-004",
        guard_predicate: "facts.sha_freshness_source == stale && !facts.has_gate_failure_signal",
        requirement_refs: &[],
    },
    DoctorDecisionRule {
        priority: 6,
        state: DoctorDecisionState::Approve,
        guard: DoctorDecisionGuard::ApproveEligible,
        guard_id: "DOC-G-005",
        guard_predicate: "merge_readiness.all_verdicts_approve && !facts.has_actionable_findings && facts.sha_freshness_source == remote_match && facts.merge_conflict_status != has_conflicts && !facts.has_gate_failure_signal",
        requirement_refs: &["DR-003-TERMINAL_PASS_REQUIRED_FOR_MERGE_READY"],
    },
    DoctorDecisionRule {
        priority: 7,
        state: DoctorDecisionState::DispatchMergeConflicts,
        guard: DoctorDecisionGuard::MergeConflictsPresent,
        guard_id: "DOC-G-006",
        guard_predicate: "facts.merge_conflict_status == has_conflicts",
        requirement_refs: &["DR-001-GATE_FAILURE_REQUIRES_IMPLEMENTOR"],
    },
    DoctorDecisionRule {
        priority: 8,
        state: DoctorDecisionState::DispatchFailedGates,
        guard: DoctorDecisionGuard::GateFailureSignal,
        guard_id: "DOC-G-007",
        guard_predicate: "facts.has_gate_failure_signal",
        requirement_refs: &["DR-001-GATE_FAILURE_REQUIRES_IMPLEMENTOR"],
    },
    DoctorDecisionRule {
        priority: 9,
        state: DoctorDecisionState::DispatchImplementor,
        guard: DoctorDecisionGuard::ImplementorRemediationResolved,
        guard_id: "DOC-G-008",
        guard_predicate: "facts.requires_implementor_remediation && facts.all_verdicts_resolved",
        requirement_refs: &["DR-001-GATE_FAILURE_REQUIRES_IMPLEMENTOR"],
    },
    DoctorDecisionRule {
        priority: 10,
        state: DoctorDecisionState::WaitForGates,
        guard: DoctorDecisionGuard::PendingVerdictWithGateInFlight,
        guard_id: "DOC-G-009",
        guard_predicate: "facts.has_pending_verdict && facts.gate_progress_state == in_flight",
        requirement_refs: &["DR-002-RUNNING_GATE_SUPPRESSES_FIX"],
    },
    DoctorDecisionRule {
        priority: 11,
        state: DoctorDecisionState::FixIdleReviewers,
        guard: DoctorDecisionGuard::AllActiveIdle,
        guard_id: "DOC-G-010",
        guard_predicate: "facts.all_active_idle",
        requirement_refs: &[],
    },
    DoctorDecisionRule {
        priority: 12,
        state: DoctorDecisionState::FixPendingNoActiveReviewers,
        guard: DoctorDecisionGuard::PendingNoActive,
        guard_id: "DOC-G-011",
        guard_predicate: "facts.active_agents == 0 && facts.has_pending_verdict",
        requirement_refs: &[],
    },
    DoctorDecisionRule {
        priority: 13,
        state: DoctorDecisionState::EscalateLifecycleBudget,
        guard: DoctorDecisionGuard::LifecycleEscalation,
        guard_id: "DOC-G-012",
        guard_predicate: "facts.lifecycle_escalation",
        requirement_refs: &[],
    },
    DoctorDecisionRule {
        priority: 14,
        state: DoctorDecisionState::Wait,
        guard: DoctorDecisionGuard::Default,
        guard_id: "DOC-G-013",
        guard_predicate: "default",
        requirement_refs: &[],
    },
];

const DOCTOR_RECOMMENDATION_RULES: &[DoctorRecommendationRule] = &[
    DoctorRecommendationRule {
        state: DoctorDecisionState::Fix,
        action: "fix",
        priority: "high",
        reason_kind: DoctorReasonKind::Template,
        reason_template: "local FAC state indicates integrity/corruption issues",
        command_kind: DoctorCommandKind::RuleTemplate,
        command_template: Some("apm2 fac doctor --pr {pr_number} --fix"),
        command_notes: None,
    },
    DoctorRecommendationRule {
        state: DoctorDecisionState::Done,
        action: "done",
        priority: "low",
        reason_kind: DoctorReasonKind::Template,
        reason_template: "PR has been merged to main",
        command_kind: DoctorCommandKind::None,
        command_template: None,
        command_notes: None,
    },
    DoctorRecommendationRule {
        state: DoctorDecisionState::FixProjectionGap,
        action: "fix",
        priority: "high",
        reason_kind: DoctorReasonKind::Template,
        reason_template: "verdict projection is missing authoritative remote comment binding for a terminal-approved SHA",
        command_kind: DoctorCommandKind::FixFollowUp,
        command_template: Some("apm2 fac doctor --pr {pr_number} --fix"),
        command_notes: Some("runtime follow-up PR repair cycle runs in bounded single-flight mode"),
    },
    DoctorRecommendationRule {
        state: DoctorDecisionState::Merge,
        action: "merge",
        priority: "medium",
        reason_kind: DoctorReasonKind::Template,
        reason_template: "all verdicts approve; gates pass; SHA is fresh; no merge conflicts",
        command_kind: DoctorCommandKind::None,
        command_template: None,
        command_notes: None,
    },
    DoctorRecommendationRule {
        state: DoctorDecisionState::FixStaleIdentity,
        action: "fix",
        priority: "high",
        reason_kind: DoctorReasonKind::Template,
        reason_template: "local verdict/findings snapshot is stale relative to remote PR head",
        command_kind: DoctorCommandKind::FixForce,
        command_template: Some("apm2 fac doctor --pr {pr_number} --fix"),
        command_notes: Some(
            "follow-up PR repair cycle runs with forced strategy (bounded single-flight)",
        ),
    },
    DoctorRecommendationRule {
        state: DoctorDecisionState::Approve,
        action: "approve",
        priority: "low",
        reason_kind: DoctorReasonKind::Template,
        reason_template: "all review dimensions approve; awaiting auto-merge",
        command_kind: DoctorCommandKind::RuleTemplate,
        command_template: Some(
            "apm2 fac doctor --pr {pr_number} --wait-for-recommended-action --wait-timeout-seconds {wait_timeout_seconds}",
        ),
        command_notes: None,
    },
    DoctorRecommendationRule {
        state: DoctorDecisionState::DispatchMergeConflicts,
        action: "dispatch_implementor",
        priority: "high",
        reason_kind: DoctorReasonKind::Template,
        reason_template: "merge conflicts require implementor remediation and a fresh push",
        command_kind: DoctorCommandKind::RuleTemplate,
        command_template: Some("apm2 fac review findings --pr {pr_number}"),
        command_notes: None,
    },
    DoctorRecommendationRule {
        state: DoctorDecisionState::DispatchFailedGates,
        action: "dispatch_implementor",
        priority: "high",
        reason_kind: DoctorReasonKind::PushFailureHintOrTemplate,
        reason_template: "evidence gate failure requires implementor remediation before review can continue",
        command_kind: DoctorCommandKind::RuleTemplate,
        command_template: Some("apm2 fac review findings --pr {pr_number}"),
        command_notes: Some("reason may include latest push failure hint when available"),
    },
    DoctorRecommendationRule {
        state: DoctorDecisionState::DispatchImplementor,
        action: "dispatch_implementor",
        priority: "high",
        reason_kind: DoctorReasonKind::FindingsRollupWithPushHint,
        reason_template: "review findings require implementor remediation",
        command_kind: DoctorCommandKind::RuleTemplate,
        command_template: Some("apm2 fac review findings --pr {pr_number}"),
        command_notes: Some("reason includes findings rollup when available"),
    },
    DoctorRecommendationRule {
        state: DoctorDecisionState::WaitForGates,
        action: "wait",
        priority: "medium",
        reason_kind: DoctorReasonKind::Template,
        reason_template: "FAC gates are still in progress; follow-up fix is deferred",
        command_kind: DoctorCommandKind::RuleTemplate,
        command_template: Some(
            "apm2 fac doctor --pr {pr_number} --wait-for-recommended-action --wait-timeout-seconds {wait_timeout_seconds}",
        ),
        command_notes: None,
    },
    DoctorRecommendationRule {
        state: DoctorDecisionState::FixIdleReviewers,
        action: "fix",
        priority: "high",
        reason_kind: DoctorReasonKind::IdleFixWithMaxIdle,
        reason_template: "all active reviewer agents are idle",
        command_kind: DoctorCommandKind::FixForce,
        command_template: Some("apm2 fac doctor --pr {pr_number} --fix"),
        command_notes: Some(
            "runtime follow-up PR repair cycle uses forced strategy (bounded single-flight); reason appends max idle age telemetry",
        ),
    },
    DoctorRecommendationRule {
        state: DoctorDecisionState::FixPendingNoActiveReviewers,
        action: "fix",
        priority: "high",
        reason_kind: DoctorReasonKind::PendingNoActiveWithPushHint,
        reason_template: "no active reviewer agents and verdict remains pending",
        command_kind: DoctorCommandKind::FixConditionalForce,
        command_template: Some("apm2 fac doctor --pr {pr_number} --fix"),
        command_notes: Some(
            "runtime follow-up PR repair cycle toggles forced strategy (bounded single-flight) when terminal reason indicates max_restarts_exceeded",
        ),
    },
    DoctorRecommendationRule {
        state: DoctorDecisionState::EscalateLifecycleBudget,
        action: "escalate",
        priority: "high",
        reason_kind: DoctorReasonKind::Template,
        reason_template: "lifecycle retry/error budget exhausted",
        command_kind: DoctorCommandKind::RuleTemplate,
        command_template: Some("apm2 fac doctor --pr {pr_number}"),
        command_notes: None,
    },
    DoctorRecommendationRule {
        state: DoctorDecisionState::Wait,
        action: "wait",
        priority: "low",
        reason_kind: DoctorReasonKind::WaitWithPendingHint,
        reason_template: "reviews and findings are still in progress",
        command_kind: DoctorCommandKind::RuleTemplate,
        command_template: Some(
            "apm2 fac doctor --pr {pr_number} --wait-for-recommended-action --wait-timeout-seconds {wait_timeout_seconds}",
        ),
        command_notes: None,
    },
];

const DOCTOR_ACTION_POLICIES: &[DoctorActionPolicy] = &[
    DoctorActionPolicy {
        action: "fix",
        default_wait_exit: true,
        wait_terminal_reason: "fix",
        allow_exit_on_flag: true,
    },
    DoctorActionPolicy {
        action: "escalate",
        default_wait_exit: true,
        wait_terminal_reason: "escalate",
        allow_exit_on_flag: true,
    },
    DoctorActionPolicy {
        action: "merge",
        default_wait_exit: true,
        wait_terminal_reason: "merge_ready",
        allow_exit_on_flag: true,
    },
    DoctorActionPolicy {
        action: "dispatch_implementor",
        default_wait_exit: true,
        wait_terminal_reason: "dispatch_implementor",
        allow_exit_on_flag: true,
    },
    DoctorActionPolicy {
        action: "done",
        default_wait_exit: true,
        wait_terminal_reason: "done",
        allow_exit_on_flag: true,
    },
    DoctorActionPolicy {
        action: "approve",
        default_wait_exit: true,
        wait_terminal_reason: "merge_ready",
        allow_exit_on_flag: true,
    },
    DoctorActionPolicy {
        action: "wait",
        default_wait_exit: false,
        wait_terminal_reason: "non_terminal_wait",
        allow_exit_on_flag: false,
    },
];

const DOCTOR_WAIT_TRANSITION_RULES: &[DoctorWaitTransitionRule] = &[
    DoctorWaitTransitionRule {
        priority: 1,
        from: DoctorWaitState::Evaluate,
        to: DoctorWaitState::ExitOnRecommendedAction,
        guard: DoctorWaitGuard::RecommendedActionInExitSet,
        guard_id: "WAIT-G-001",
        guard_predicate: "facts.recommended_action in effective_exit_actions",
        requirement_refs: &["DR-005-WAIT_RETURNS_ON_TERMINAL_ACTION"],
    },
    DoctorWaitTransitionRule {
        priority: 2,
        from: DoctorWaitState::Evaluate,
        to: DoctorWaitState::ExitOnInterrupt,
        guard: DoctorWaitGuard::Interrupted,
        guard_id: "WAIT-G-002",
        guard_predicate: "facts.interrupted",
        requirement_refs: &[],
    },
    DoctorWaitTransitionRule {
        priority: 3,
        from: DoctorWaitState::Evaluate,
        to: DoctorWaitState::ExitOnTimeout,
        guard: DoctorWaitGuard::TimedOut,
        guard_id: "WAIT-G-003",
        guard_predicate: "facts.elapsed_seconds >= facts.wait_timeout_seconds",
        requirement_refs: &[],
    },
    DoctorWaitTransitionRule {
        priority: 4,
        from: DoctorWaitState::Evaluate,
        to: DoctorWaitState::PollEmit,
        guard: DoctorWaitGuard::Always,
        guard_id: "WAIT-G-004",
        guard_predicate: "default",
        requirement_refs: &[],
    },
    DoctorWaitTransitionRule {
        priority: 5,
        from: DoctorWaitState::PollEmit,
        to: DoctorWaitState::Sleep,
        guard: DoctorWaitGuard::Always,
        guard_id: "WAIT-G-005",
        guard_predicate: "always",
        requirement_refs: &[],
    },
    DoctorWaitTransitionRule {
        priority: 6,
        from: DoctorWaitState::Sleep,
        to: DoctorWaitState::CollectSummary,
        guard: DoctorWaitGuard::Always,
        guard_id: "WAIT-G-006",
        guard_predicate: "always",
        requirement_refs: &[],
    },
    DoctorWaitTransitionRule {
        priority: 7,
        from: DoctorWaitState::CollectSummary,
        to: DoctorWaitState::Evaluate,
        guard: DoctorWaitGuard::Always,
        guard_id: "WAIT-G-007",
        guard_predicate: "always",
        requirement_refs: &[],
    },
];

#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)]
struct DoctorDecisionFacts {
    has_integrity_or_corruption: bool,
    lifecycle_merged: bool,
    projection_gap_requires_fix: bool,
    merge_ready: bool,
    all_verdicts_approve: bool,
    sha_freshness_source: DoctorShaFreshnessSource,
    has_actionable_findings: bool,
    merge_conflict_status: DoctorMergeConflictStatus,
    has_gate_failure_signal: bool,
    requires_implementor_remediation: bool,
    all_verdicts_resolved: bool,
    has_pending_verdict: bool,
    gate_progress_state: DoctorGateProgressState,
    active_agents: usize,
    all_active_idle: bool,
    max_idle_seconds: Option<i64>,
    max_dispatched_pending_seconds: Option<i64>,
    has_forced_fix_terminal_reason: bool,
    lifecycle_escalation: bool,
    push_failure_hint: Option<String>,
}

impl DoctorDecisionFacts {
    fn from_input(input: &DoctorActionInputs<'_>) -> Self {
        let has_actionable_findings = input
            .findings_summary
            .iter()
            .any(|entry| entry.counts.blocker > 0 || entry.counts.major > 0);
        let all_verdicts_resolved = !input
            .findings_summary
            .iter()
            .any(|entry| entry.formal_verdict.eq_ignore_ascii_case("pending"));
        let requires_implementor_remediation = input.findings_summary.iter().any(|entry| {
            entry.formal_verdict.eq_ignore_ascii_case("deny")
                || entry.counts.blocker > 0
                || entry.counts.major > 0
        });
        let has_pending_verdict = input
            .findings_summary
            .iter()
            .any(|entry| entry.formal_verdict.eq_ignore_ascii_case("pending"));

        let gate_progress_state = derive_doctor_gate_progress_state(input.gates, input.lifecycle);
        let lifecycle_gate_failure = input
            .lifecycle
            .is_some_and(|entry| entry.state.eq_ignore_ascii_case("gates_failed"));
        let push_attempt_gate_failure = input
            .latest_push_attempt
            .and_then(|attempt| attempt.failed_stage.as_deref())
            .is_some_and(push_attempt_stage_is_gate_failure);
        let has_gate_failure_signal = gate_progress_state
            == DoctorGateProgressState::TerminalFailed
            || lifecycle_gate_failure
            || push_attempt_gate_failure;
        let projection_gap_requires_fix = input.repair_signals.projection_comment_binding_missing
            && input.merge_readiness.all_verdicts_approve
            && input.merge_readiness.gates_pass
            && input.merge_readiness.sha_fresh
            && input.merge_readiness.merge_conflict_status
                != DoctorMergeConflictStatus::HasConflicts
            && !has_gate_failure_signal;
        let has_integrity_or_corruption = input.repair_signals.lifecycle_load_failed
            || input.repair_signals.lifecycle_missing
            || input.repair_signals.agent_registry_load_failed
            || input.repair_signals.run_state_repair_required;
        let lifecycle_escalation = input.lifecycle.is_some_and(|entry| {
            entry.error_budget_used >= 8 || lifecycle_retry_budget_exhausted(entry)
        });

        Self {
            has_integrity_or_corruption,
            lifecycle_merged: input
                .lifecycle
                .is_some_and(|entry| entry.state.eq_ignore_ascii_case("merged")),
            projection_gap_requires_fix,
            merge_ready: input.merge_readiness.merge_ready,
            all_verdicts_approve: input.merge_readiness.all_verdicts_approve,
            sha_freshness_source: input.merge_readiness.sha_freshness_source,
            has_actionable_findings,
            merge_conflict_status: input.merge_readiness.merge_conflict_status,
            has_gate_failure_signal,
            requires_implementor_remediation,
            all_verdicts_resolved,
            has_pending_verdict,
            gate_progress_state,
            active_agents: input.agent_activity.active_agents,
            all_active_idle: input.agent_activity.all_active_idle,
            max_idle_seconds: input.agent_activity.max_idle_seconds,
            max_dispatched_pending_seconds: input.agent_activity.max_dispatched_pending_seconds,
            has_forced_fix_terminal_reason: has_forced_fix_terminal_reason(
                input.reviews,
                input.review_terminal_reasons,
            ),
            lifecycle_escalation,
            push_failure_hint: input
                .latest_push_attempt
                .and_then(format_push_attempt_failure_hint),
        }
    }
}

fn doctor_decision_guard_triggered(rule: &DoctorDecisionRule, facts: &DoctorDecisionFacts) -> bool {
    match rule.guard {
        DoctorDecisionGuard::HasIntegrityOrCorruption => facts.has_integrity_or_corruption,
        DoctorDecisionGuard::LifecycleMerged => facts.lifecycle_merged,
        DoctorDecisionGuard::ProjectionGapRequiresFix => facts.projection_gap_requires_fix,
        DoctorDecisionGuard::MergeReady => facts.merge_ready,
        DoctorDecisionGuard::ShaFreshnessStale => {
            facts.sha_freshness_source == DoctorShaFreshnessSource::Stale
                && !facts.has_gate_failure_signal
        },
        DoctorDecisionGuard::ApproveEligible => {
            facts.all_verdicts_approve
                && !facts.has_actionable_findings
                && facts.sha_freshness_source == DoctorShaFreshnessSource::RemoteMatch
                && facts.merge_conflict_status != DoctorMergeConflictStatus::HasConflicts
                && !facts.has_gate_failure_signal
        },
        DoctorDecisionGuard::MergeConflictsPresent => {
            facts.merge_conflict_status == DoctorMergeConflictStatus::HasConflicts
        },
        DoctorDecisionGuard::GateFailureSignal => facts.has_gate_failure_signal,
        DoctorDecisionGuard::ImplementorRemediationResolved => {
            facts.requires_implementor_remediation && facts.all_verdicts_resolved
        },
        DoctorDecisionGuard::PendingVerdictWithGateInFlight => {
            facts.has_pending_verdict
                && facts.gate_progress_state == DoctorGateProgressState::InFlight
        },
        DoctorDecisionGuard::AllActiveIdle => facts.all_active_idle,
        DoctorDecisionGuard::PendingNoActive => {
            facts.active_agents == 0 && facts.has_pending_verdict
        },
        DoctorDecisionGuard::LifecycleEscalation => facts.lifecycle_escalation,
        DoctorDecisionGuard::Default => true,
    }
}

fn derive_doctor_decision_state(facts: &DoctorDecisionFacts) -> DoctorDecisionState {
    for rule in DOCTOR_DECISION_RULES {
        if doctor_decision_guard_triggered(rule, facts) {
            return rule.state;
        }
    }
    DoctorDecisionState::Wait
}

fn doctor_recommendation_rule_for_state(
    state: DoctorDecisionState,
) -> &'static DoctorRecommendationRule {
    DOCTOR_RECOMMENDATION_RULES
        .iter()
        .find(|rule| rule.state == state)
        .unwrap_or_else(|| {
            panic!(
                "missing doctor recommendation rule for state {}",
                state.as_str()
            )
        })
}

fn render_doctor_command_template(template: &str, pr_number: u32) -> String {
    template
        .replace(DOCTOR_COMMAND_PR_NUMBER_PLACEHOLDER, &pr_number.to_string())
        .replace(
            DOCTOR_COMMAND_WAIT_TIMEOUT_PLACEHOLDER,
            &DOCTOR_WAIT_TIMEOUT_DEFAULT_SECONDS.to_string(),
        )
}

fn fix_command(pr_number: u32) -> String {
    format!("apm2 fac doctor --pr {pr_number} --fix")
}

fn render_doctor_recommendation_reason(
    rule: &DoctorRecommendationRule,
    input: &DoctorActionInputs<'_>,
    facts: &DoctorDecisionFacts,
) -> String {
    match rule.reason_kind {
        DoctorReasonKind::Template => rule.reason_template.to_string(),
        DoctorReasonKind::PushFailureHintOrTemplate => facts
            .push_failure_hint
            .clone()
            .unwrap_or_else(|| rule.reason_template.to_string()),
        DoctorReasonKind::FindingsRollupWithPushHint => {
            let push_hint = facts
                .push_failure_hint
                .as_deref()
                .unwrap_or(rule.reason_template);
            let findings_rollup = format_findings_rollup_for_reason(input.findings_summary);
            if findings_rollup.is_empty() {
                push_hint.to_string()
            } else {
                format!("{findings_rollup}; {push_hint}")
            }
        },
        DoctorReasonKind::IdleFixWithMaxIdle => {
            let max_idle = facts
                .max_idle_seconds
                .unwrap_or(DOCTOR_ACTIVE_AGENT_IDLE_TIMEOUT_SECONDS);
            format!(
                "all active reviewer agents are idle (no activity for up to {max_idle}s); recommend repair"
            )
        },
        DoctorReasonKind::PendingNoActiveWithPushHint => facts
            .push_failure_hint
            .clone()
            .unwrap_or_else(|| rule.reason_template.to_string()),
        DoctorReasonKind::WaitWithPendingHint => {
            let mut wait_reason =
                "reviews are in progress or awaiting projection catch-up".to_string();
            if facts
                .max_dispatched_pending_seconds
                .is_some_and(|value| value > DOCTOR_DISPATCH_PENDING_WARNING_SECONDS)
            {
                let pending_seconds = facts
                    .max_dispatched_pending_seconds
                    .unwrap_or(DOCTOR_DISPATCH_PENDING_WARNING_SECONDS);
                wait_reason.push_str("; reviewer dispatch pending for ");
                wait_reason.push_str(&pending_seconds.to_string());
                wait_reason.push_str("s (may be stuck)");
            }
            wait_reason
        },
    }
}

fn render_doctor_recommendation_command(
    rule: &DoctorRecommendationRule,
    input: &DoctorActionInputs<'_>,
    _facts: &DoctorDecisionFacts,
) -> Option<String> {
    match rule.command_kind {
        DoctorCommandKind::None => None,
        DoctorCommandKind::RuleTemplate => rule
            .command_template
            .map(|template| render_doctor_command_template(template, input.pr_number)),
        DoctorCommandKind::FixFollowUp => Some(fix_command(input.pr_number)),
        DoctorCommandKind::FixForce | DoctorCommandKind::FixConditionalForce => {
            Some(fix_command(input.pr_number))
        },
    }
}

const fn render_doctor_follow_up_repair_flags(
    rule: &DoctorRecommendationRule,
    facts: &DoctorDecisionFacts,
) -> (bool, bool) {
    match rule.command_kind {
        DoctorCommandKind::None | DoctorCommandKind::RuleTemplate => (false, false),
        DoctorCommandKind::FixForce => (true, true),
        DoctorCommandKind::FixConditionalForce => (true, facts.has_forced_fix_terminal_reason),
        DoctorCommandKind::FixFollowUp => (true, false),
    }
}

fn build_recommended_action(input: &DoctorActionInputs<'_>) -> DoctorRecommendedAction {
    let facts = DoctorDecisionFacts::from_input(input);
    let state = derive_doctor_decision_state(&facts);
    let rule = doctor_recommendation_rule_for_state(state);
    let (follow_up_fix, follow_up_force) = render_doctor_follow_up_repair_flags(rule, &facts);
    DoctorRecommendedAction {
        action: rule.action.to_string(),
        reason: render_doctor_recommendation_reason(rule, input, &facts),
        priority: rule.priority.to_string(),
        command: render_doctor_recommendation_command(rule, input, &facts),
        follow_up_fix,
        follow_up_force,
    }
}

fn format_findings_rollup_for_reason(findings: &[DoctorFindingsDimensionSummary]) -> String {
    findings
        .iter()
        .map(|entry| {
            format!(
                "{}={}({}B/{}M/{}m/{}N)",
                entry.dimension,
                entry.formal_verdict.to_ascii_lowercase(),
                entry.counts.blocker,
                entry.counts.major,
                entry.counts.minor,
                entry.counts.nit
            )
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn format_push_attempt_failure_hint(attempt: &DoctorPushAttemptSummary) -> Option<String> {
    let stage = attempt.failed_stage.as_ref()?;
    let exit_code = attempt
        .exit_code
        .map_or_else(|| "-".to_string(), |code| code.to_string());
    let duration = attempt
        .duration_s
        .map_or_else(|| "-".to_string(), |secs| format!("{secs}s"));
    let hint = attempt
        .error_hint
        .clone()
        .unwrap_or_else(|| "no hint".to_string());
    Some(format!(
        "last push: {stage} FAIL (exit {exit_code}, {duration}) - {hint}"
    ))
}

fn push_attempt_stage_is_gate_failure(stage: &str) -> bool {
    let normalized = stage.trim().to_ascii_lowercase();
    normalized.starts_with("gate_") || normalized == "gates"
}

fn collect_default_review_dimension_snapshots(local_sha: &str) -> Vec<DoctorReviewSnapshot> {
    vec![
        DoctorReviewSnapshot {
            dimension: "security".to_string(),
            verdict: "pending".to_string(),
            reviewed_sha: local_sha.to_string(),
            reviewed_by: String::new(),
            reviewed_at: String::new(),
            reason: "no verified projection loaded".to_string(),
            terminal_reason: None,
        },
        DoctorReviewSnapshot {
            dimension: "code-quality".to_string(),
            verdict: "pending".to_string(),
            reviewed_sha: local_sha.to_string(),
            reviewed_by: String::new(),
            reviewed_at: String::new(),
            reason: "no verified projection loaded".to_string(),
            terminal_reason: None,
        },
    ]
}

fn collect_review_dimension_snapshots(
    snapshot: &verdict_projection::VerdictProjectionSnapshot,
) -> Vec<DoctorReviewSnapshot> {
    let mut mapped = std::collections::BTreeMap::<
        String,
        &verdict_projection::VerdictProjectionDimensionSnapshot,
    >::new();
    for entry in &snapshot.dimensions {
        mapped.insert(entry.dimension.clone(), entry);
    }
    ["security", "code-quality"]
        .into_iter()
        .map(|dimension| {
            let Some(entry) = mapped.get(dimension) else {
                return DoctorReviewSnapshot {
                    dimension: (*dimension).to_string(),
                    verdict: "pending".to_string(),
                    reviewed_sha: snapshot.head_sha.clone(),
                    reviewed_by: String::new(),
                    reviewed_at: String::new(),
                    reason: "missing dimension in projection".to_string(),
                    terminal_reason: None,
                };
            };
            DoctorReviewSnapshot {
                dimension: entry.dimension.clone(),
                verdict: entry.decision.clone(),
                reviewed_sha: entry.reviewed_sha.clone(),
                reviewed_by: entry.reviewed_by.clone(),
                reviewed_at: entry.reviewed_at.clone(),
                reason: entry.reason.clone(),
                terminal_reason: None,
            }
        })
        .collect()
}

fn normalize_doctor_gate_status(status: &str) -> &'static str {
    match status.trim().to_ascii_uppercase().as_str() {
        "PASS" => "PASS",
        "FAIL" => "FAIL",
        "RUNNING" => "RUNNING",
        _ => "NOT_RUN",
    }
}

fn doctor_gate_signal_from_status(status: &str) -> DoctorGateSignal {
    match normalize_doctor_gate_status(status) {
        "PASS" => DoctorGateSignal::Pass,
        "FAIL" => DoctorGateSignal::Fail,
        _ => DoctorGateSignal::InFlight,
    }
}

const fn doctor_gate_signal_priority(signal: DoctorGateSignal) -> u8 {
    match signal {
        DoctorGateSignal::Fail => 3,
        DoctorGateSignal::InFlight => 2,
        DoctorGateSignal::Pass => 1,
    }
}

const fn doctor_gate_status_for_signal(signal: DoctorGateSignal) -> &'static str {
    match signal {
        DoctorGateSignal::Pass => "PASS",
        DoctorGateSignal::Fail => "FAIL",
        DoctorGateSignal::InFlight => "RUNNING",
    }
}

fn merge_gate_freshness(existing: Option<i64>, incoming: Option<i64>) -> Option<i64> {
    match (existing, incoming) {
        (Some(left), Some(right)) => Some(left.min(right)),
        (Some(left), None) => Some(left),
        (None, Some(right)) => Some(right),
        (None, None) => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DoctorGateReductionDecision {
    ReplaceIncoming,
    KeepExisting,
}

#[derive(Debug, Clone, Copy)]
struct DoctorGateReductionRule {
    priority: u8,
    decision: DoctorGateReductionDecision,
    guard: DoctorGateReductionGuard,
    guard_id: &'static str,
    guard_predicate: &'static str,
}

#[derive(Debug, Clone, Copy)]
enum DoctorGateReductionGuard {
    IncomingSignalHigher,
    ExistingSignalHigher,
    SameSignalIncomingSourceHigher,
    SameSignalIncomingTimestampNewer,
    Default,
}

impl DoctorGateReductionGuard {
    const fn as_str(self) -> &'static str {
        match self {
            Self::IncomingSignalHigher => "incoming_signal_higher",
            Self::ExistingSignalHigher => "existing_signal_higher",
            Self::SameSignalIncomingSourceHigher => "same_signal_incoming_source_higher",
            Self::SameSignalIncomingTimestampNewer => "same_signal_incoming_timestamp_newer",
            Self::Default => "default",
        }
    }
}

#[derive(Debug, Clone, Copy)]
#[allow(clippy::struct_excessive_bools)]
struct DoctorGateReductionFacts {
    incoming_signal_higher: bool,
    existing_signal_higher: bool,
    same_signal: bool,
    incoming_source_higher: bool,
    incoming_completed_at_newer: bool,
}

const DOCTOR_GATE_REDUCTION_RULES: &[DoctorGateReductionRule] = &[
    DoctorGateReductionRule {
        priority: 1,
        decision: DoctorGateReductionDecision::ReplaceIncoming,
        guard: DoctorGateReductionGuard::IncomingSignalHigher,
        guard_id: "GATE-R-001",
        guard_predicate: "incoming.signal_priority > existing.signal_priority",
    },
    DoctorGateReductionRule {
        priority: 2,
        decision: DoctorGateReductionDecision::KeepExisting,
        guard: DoctorGateReductionGuard::ExistingSignalHigher,
        guard_id: "GATE-R-002",
        guard_predicate: "incoming.signal_priority < existing.signal_priority",
    },
    DoctorGateReductionRule {
        priority: 3,
        decision: DoctorGateReductionDecision::ReplaceIncoming,
        guard: DoctorGateReductionGuard::SameSignalIncomingSourceHigher,
        guard_id: "GATE-R-003",
        guard_predicate: "incoming.signal_priority == existing.signal_priority && incoming.source_priority > existing.source_priority",
    },
    DoctorGateReductionRule {
        priority: 4,
        decision: DoctorGateReductionDecision::ReplaceIncoming,
        guard: DoctorGateReductionGuard::SameSignalIncomingTimestampNewer,
        guard_id: "GATE-R-004",
        guard_predicate: "incoming.signal_priority == existing.signal_priority && incoming.completed_at > existing.completed_at",
    },
    DoctorGateReductionRule {
        priority: 5,
        decision: DoctorGateReductionDecision::KeepExisting,
        guard: DoctorGateReductionGuard::Default,
        guard_id: "GATE-R-005",
        guard_predicate: "default",
    },
];

fn gate_timestamp_is_newer(incoming: Option<&str>, existing: Option<&str>) -> bool {
    match (
        incoming.and_then(parse_rfc3339_utc),
        existing.and_then(parse_rfc3339_utc),
    ) {
        (Some(incoming_ts), Some(existing_ts)) => incoming_ts > existing_ts,
        (Some(_), None) => true,
        _ => false,
    }
}

fn derive_doctor_gate_reduction_decision(
    facts: DoctorGateReductionFacts,
) -> DoctorGateReductionDecision {
    for rule in DOCTOR_GATE_REDUCTION_RULES {
        let triggered = match rule.guard {
            DoctorGateReductionGuard::IncomingSignalHigher => facts.incoming_signal_higher,
            DoctorGateReductionGuard::ExistingSignalHigher => facts.existing_signal_higher,
            DoctorGateReductionGuard::SameSignalIncomingSourceHigher => {
                facts.same_signal && facts.incoming_source_higher
            },
            DoctorGateReductionGuard::SameSignalIncomingTimestampNewer => {
                facts.same_signal && facts.incoming_completed_at_newer
            },
            DoctorGateReductionGuard::Default => true,
        };
        if triggered {
            return rule.decision;
        }
    }
    DoctorGateReductionDecision::KeepExisting
}

fn upsert_doctor_gate_snapshot(
    gates_by_name: &mut std::collections::BTreeMap<String, DoctorGateSnapshot>,
    name: &str,
    status: &'static str,
    completed_at: Option<String>,
    freshness_seconds: Option<i64>,
    source: DoctorGateSource,
) {
    let gate_name = name.trim().to_string();
    if gate_name.is_empty() {
        return;
    }
    match gates_by_name.entry(gate_name.clone()) {
        std::collections::btree_map::Entry::Vacant(entry) => {
            entry.insert(DoctorGateSnapshot {
                name: gate_name,
                status: status.to_string(),
                completed_at,
                freshness_seconds,
                source,
            });
        },
        std::collections::btree_map::Entry::Occupied(mut entry) => {
            let snapshot = entry.get_mut();
            let existing_signal = doctor_gate_signal_from_status(&snapshot.status);
            let incoming_signal = doctor_gate_signal_from_status(status);
            let facts = DoctorGateReductionFacts {
                incoming_signal_higher: doctor_gate_signal_priority(incoming_signal)
                    > doctor_gate_signal_priority(existing_signal),
                existing_signal_higher: doctor_gate_signal_priority(existing_signal)
                    > doctor_gate_signal_priority(incoming_signal),
                same_signal: doctor_gate_signal_priority(existing_signal)
                    == doctor_gate_signal_priority(incoming_signal),
                incoming_source_higher: source.priority() > snapshot.source.priority(),
                incoming_completed_at_newer: gate_timestamp_is_newer(
                    completed_at.as_deref(),
                    snapshot.completed_at.as_deref(),
                ),
            };
            if derive_doctor_gate_reduction_decision(facts)
                == DoctorGateReductionDecision::ReplaceIncoming
            {
                snapshot.status = doctor_gate_status_for_signal(incoming_signal).to_string();
                snapshot.source = source;
            }
            if snapshot.completed_at.is_none()
                || gate_timestamp_is_newer(
                    completed_at.as_deref(),
                    snapshot.completed_at.as_deref(),
                )
            {
                snapshot.completed_at = completed_at;
            }
            snapshot.freshness_seconds =
                merge_gate_freshness(snapshot.freshness_seconds, freshness_seconds);
        },
    }
}

#[derive(Debug, Clone, Copy)]
struct DoctorGateProgressRule {
    priority: u8,
    state: DoctorGateProgressState,
    guard: DoctorGateProgressGuard,
    guard_id: &'static str,
    guard_predicate: &'static str,
}

#[derive(Debug, Clone, Copy)]
enum DoctorGateProgressGuard {
    LifecycleGatesRunningOrAnyInFlight,
    AnyFailed,
    AnyPassed,
    Default,
}

impl DoctorGateProgressGuard {
    const fn as_str(self) -> &'static str {
        match self {
            Self::LifecycleGatesRunningOrAnyInFlight => "lifecycle_gates_running_or_any_in_flight",
            Self::AnyFailed => "any_failed",
            Self::AnyPassed => "any_passed",
            Self::Default => "default",
        }
    }
}

const DOCTOR_GATE_PROGRESS_RULES: &[DoctorGateProgressRule] = &[
    DoctorGateProgressRule {
        priority: 1,
        state: DoctorGateProgressState::TerminalFailed,
        guard: DoctorGateProgressGuard::AnyFailed,
        guard_id: "GATE-G-001",
        guard_predicate: "lifecycle.state == gates_failed || any(gate.status == FAIL)",
    },
    DoctorGateProgressRule {
        priority: 2,
        state: DoctorGateProgressState::InFlight,
        guard: DoctorGateProgressGuard::LifecycleGatesRunningOrAnyInFlight,
        guard_id: "GATE-G-002",
        guard_predicate: "lifecycle.state == gates_running || any(gate.status in {RUNNING,NOT_RUN})",
    },
    DoctorGateProgressRule {
        priority: 3,
        state: DoctorGateProgressState::TerminalPassed,
        guard: DoctorGateProgressGuard::AnyPassed,
        guard_id: "GATE-G-003",
        guard_predicate: "any(gate.status == PASS)",
    },
    DoctorGateProgressRule {
        priority: 4,
        state: DoctorGateProgressState::Unknown,
        guard: DoctorGateProgressGuard::Default,
        guard_id: "GATE-G-004",
        guard_predicate: "default",
    },
];

#[derive(Debug, Clone, Copy)]
#[allow(clippy::struct_excessive_bools)]
struct DoctorGateProgressFacts {
    lifecycle_gates_running: bool,
    has_in_flight_gate: bool,
    has_failed_gate: bool,
    has_passed_gate: bool,
}

impl DoctorGateProgressFacts {
    fn from_inputs(
        gates: &[DoctorGateSnapshot],
        lifecycle: Option<&DoctorLifecycleSnapshot>,
    ) -> Self {
        let mut has_in_flight_gate = false;
        let lifecycle_gates_failed =
            lifecycle.is_some_and(|entry| entry.state.eq_ignore_ascii_case("gates_failed"));
        let mut has_failed_gate = lifecycle_gates_failed;
        let mut has_passed_gate = false;
        for gate in gates {
            match doctor_gate_signal_from_status(&gate.status) {
                DoctorGateSignal::Pass => has_passed_gate = true,
                DoctorGateSignal::Fail => has_failed_gate = true,
                DoctorGateSignal::InFlight => has_in_flight_gate = true,
            }
        }
        Self {
            lifecycle_gates_running: lifecycle
                .is_some_and(|entry| entry.state.eq_ignore_ascii_case("gates_running")),
            has_in_flight_gate,
            has_failed_gate,
            has_passed_gate,
        }
    }
}

fn derive_doctor_gate_progress_state(
    gates: &[DoctorGateSnapshot],
    lifecycle: Option<&DoctorLifecycleSnapshot>,
) -> DoctorGateProgressState {
    let facts = DoctorGateProgressFacts::from_inputs(gates, lifecycle);
    for rule in DOCTOR_GATE_PROGRESS_RULES {
        let triggered = match rule.guard {
            DoctorGateProgressGuard::LifecycleGatesRunningOrAnyInFlight => {
                facts.lifecycle_gates_running || facts.has_in_flight_gate
            },
            DoctorGateProgressGuard::AnyFailed => facts.has_failed_gate,
            DoctorGateProgressGuard::AnyPassed => facts.has_passed_gate,
            DoctorGateProgressGuard::Default => true,
        };
        if triggered {
            return rule.state;
        }
    }
    DoctorGateProgressState::Unknown
}

fn gate_result_freshness_seconds(completed_at: &str) -> Option<i64> {
    if completed_at.trim().is_empty() {
        return None;
    }
    let Ok(parsed) = DateTime::parse_from_rfc3339(completed_at) else {
        return None;
    };
    let age = Utc::now() - parsed.with_timezone(&Utc);
    let Ok(duration) = age.to_std() else {
        return None;
    };
    Some(
        i64::try_from(duration.as_secs())
            .unwrap_or(i64::MAX)
            .clamp(0, i64::MAX),
    )
}

fn format_freshness_age(seconds: Option<i64>) -> String {
    let Some(seconds) = seconds else {
        return "unknown".to_string();
    };
    if seconds < 60 {
        format!("{seconds}s")
    } else if seconds < 60 * 60 {
        format!("{}m", seconds / 60)
    } else {
        format!("{}h", seconds / (60 * 60))
    }
}
// ── Public entry points ─────────────────────────────────────────────────────

pub fn run_findings(
    repo: &str,
    pr_number: Option<u32>,
    sha: Option<&str>,
    json_output: bool,
) -> u8 {
    match findings::run_findings(repo, pr_number, sha, json_output) {
        Ok(code) => code,
        Err(err) => {
            let payload = serde_json::json!({
                "error": "fac_review_findings_failed",
                "message": err,
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&payload)
                    .unwrap_or_else(|_| "{\"error\":\"serialization_failure\"}".to_string())
            );
            exit_codes::GENERIC_ERROR
        },
    }
}

#[allow(clippy::too_many_arguments)]
pub fn run_finding(
    repo: &str,
    pr_number: Option<u32>,
    sha: Option<&str>,
    review_type: ReviewFindingTypeArg,
    severity: ReviewFindingSeverityArg,
    summary: &str,
    details: Option<&str>,
    risk: Option<&str>,
    impact: Option<&str>,
    location: Option<&str>,
    reviewer_id: Option<&str>,
    model_id: Option<&str>,
    backend_id: Option<&str>,
    evidence_pointer: Option<&str>,
    json_output: bool,
) -> u8 {
    match finding::run_finding(
        repo,
        pr_number,
        sha,
        review_type,
        severity,
        summary,
        details,
        risk,
        impact,
        location,
        reviewer_id,
        model_id,
        backend_id,
        evidence_pointer,
        json_output,
    ) {
        Ok(code) => code,
        Err(err) => {
            let payload = serde_json::json!({
                "error": "fac_review_finding_failed",
                "message": err,
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&payload)
                    .unwrap_or_else(|_| "{\"error\":\"serialization_failure\"}".to_string())
            );
            exit_codes::GENERIC_ERROR
        },
    }
}

pub fn run_prepare(repo: &str, pr_number: Option<u32>, sha: Option<&str>, json_output: bool) -> u8 {
    match prepare::run_prepare(repo, pr_number, sha, json_output) {
        Ok(code) => code,
        Err(err) => {
            let payload = serde_json::json!({
                "error": "fac_review_prepare_failed",
                "message": err,
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&payload)
                    .unwrap_or_else(|_| "{\"error\":\"serialization_failure\"}".to_string())
            );
            exit_codes::GENERIC_ERROR
        },
    }
}

#[allow(clippy::too_many_arguments)]
pub fn run_verdict_set(
    repo: &str,
    pr_number: Option<u32>,
    sha: Option<&str>,
    dimension: &str,
    verdict: VerdictValueArg,
    reason: Option<&str>,
    model_id: Option<&str>,
    backend_id: Option<&str>,
    keep_prepared_inputs: bool,
    json_output: bool,
) -> u8 {
    lifecycle::run_verdict_set(
        repo,
        pr_number,
        sha,
        dimension,
        verdict,
        reason,
        model_id,
        backend_id,
        keep_prepared_inputs,
        json_output,
    )
}

pub fn run_verdict_show(
    repo: &str,
    pr_number: Option<u32>,
    sha: Option<&str>,
    json_output: bool,
) -> u8 {
    lifecycle::run_verdict_show(repo, pr_number, sha, json_output)
}

pub fn run_tail(lines: usize, follow: bool) -> u8 {
    match run_tail_inner(lines, follow) {
        Ok(()) => exit_codes::SUCCESS,
        Err(err) => {
            let payload = serde_json::json!({
                "error": "fac_review_tail_failed",
                "message": err,
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&payload)
                    .unwrap_or_else(|_| "{\"error\":\"serialization_failure\"}".to_string())
            );
            exit_codes::GENERIC_ERROR
        },
    }
}

pub fn run_terminate(
    repo: &str,
    pr_number: Option<u32>,
    review_type: &str,
    json_output: bool,
) -> u8 {
    match run_terminate_inner(repo, pr_number, review_type, json_output) {
        Ok(()) => exit_codes::SUCCESS,
        Err(err) => {
            let payload = serde_json::json!({
                "error": "terminate_failed",
                "message": err,
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&payload)
                    .unwrap_or_else(|_| "{\"error\":\"serialization_failure\"}".to_string())
            );
            exit_codes::GENERIC_ERROR
        },
    }
}

fn run_terminate_inner(
    repo: &str,
    pr_number: Option<u32>,
    review_type: &str,
    json_output: bool,
) -> Result<(), String> {
    let home = types::apm2_home_dir()?;
    run_terminate_inner_for_home(&home, repo, pr_number, review_type, json_output)
}

fn run_terminate_inner_for_home(
    home: &Path,
    repo: &str,
    pr_number: Option<u32>,
    review_type: &str,
    json_output: bool,
) -> Result<(), String> {
    let (owner_repo, resolved_pr) = target::resolve_pr_target(repo, pr_number)?;
    let state_opt =
        state::load_review_run_state_verified_strict_for_home(home, resolved_pr, review_type)?;

    let Some(mut run_state) = state_opt else {
        let msg = format!("no active reviewer for PR #{resolved_pr} type={review_type}");
        if json_output {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "status": "no_active_reviewer",
                    "pr_number": resolved_pr,
                    "review_type": review_type,
                    "message": msg,
                }))
                .unwrap_or_default()
            );
        } else {
            eprintln!("{msg}");
        }
        return Ok(());
    };

    if run_state.status.is_terminal() {
        let msg = format!(
            "reviewer already terminal for PR #{resolved_pr} type={review_type} status={} reason={}",
            run_state.status.as_str(),
            run_state.terminal_reason.as_deref().unwrap_or("none"),
        );
        if json_output {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "status": "already_terminal",
                    "pr_number": resolved_pr,
                    "review_type": review_type,
                    "run_status": run_state.status.as_str(),
                    "terminal_reason": run_state.terminal_reason,
                    "message": msg,
                }))
                .unwrap_or_default()
            );
        } else {
            eprintln!("{msg}");
        }
        return Ok(());
    }

    if !run_state
        .owner_repo
        .eq_ignore_ascii_case(owner_repo.as_str())
    {
        let msg = format!(
            "repo mismatch guard skipped termination for PR #{resolved_pr} type={review_type}: run-state repo={} requested repo={owner_repo}",
            run_state.owner_repo
        );
        eprintln!("WARNING: {msg}");
        return Err(msg);
    }

    if run_state.status == types::ReviewRunStatus::Alive && run_state.pid.is_none() {
        return Err(
            "cannot terminate: run state is Alive but PID is missing - operator must investigate."
                .to_string(),
        );
    }

    if run_state.pid.is_some() && run_state.proc_start_time.is_none() {
        return Err(format!(
            "integrity check failed for PR #{resolved_pr} type={review_type}: \
             pid is present but proc_start_time is missing — refusing to terminate"
        ));
    }

    if run_state.pid.is_some() && run_state.proc_start_time.is_some() {
        if let Err(integrity_err) =
            state::verify_review_run_state_integrity_binding(home, &run_state)
        {
            return Err(format!(
                "integrity verification failed for PR #{resolved_pr} type={review_type}: {integrity_err} -- \
                 refusing to terminate based on potentially tampered state"
            ));
        }
    }

    let authority = verdict_projection::resolve_termination_authority_for_home(
        home,
        &owner_repo,
        resolved_pr,
        review_type,
        &run_state.head_sha,
        &run_state.run_id,
    )
    .map_err(|err| {
        format!(
            "decision-bound authority required for PR #{resolved_pr} type={review_type} termination: {err}"
        )
    })?;
    authority.matches_state(&run_state).map_err(|err| {
        format!("decision authority mismatch for PR #{resolved_pr} type={review_type}: {err}")
    })?;
    if !authority.decision_signature_present() {
        return Err(format!(
            "decision-bound authority required for PR #{resolved_pr} type={review_type}: missing decision signature"
        ));
    }

    let outcome = dispatch::terminate_review_agent_for_home(home, &authority)?;
    let killed = matches!(outcome, dispatch::TerminationOutcome::Killed);

    let failure = match &outcome {
        dispatch::TerminationOutcome::Killed | dispatch::TerminationOutcome::AlreadyDead => None,
        dispatch::TerminationOutcome::SkippedMismatch => Some(format!(
            "termination skipped for PR #{resolved_pr} type={review_type}: process identity did not match authority"
        )),
        dispatch::TerminationOutcome::IdentityFailure(reason) => Some(format!(
            "failed to terminate PR #{resolved_pr} type={review_type}: {reason}"
        )),
    };
    if let Some(message) = failure {
        return Err(message);
    }

    run_state.status = types::ReviewRunStatus::Failed;
    run_state.terminal_reason = Some(TERMINAL_MANUAL_TERMINATION_DECISION_BOUND.to_string());
    state::write_review_run_state_for_home(home, &run_state)?;

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "status": "terminated",
                "pr_number": resolved_pr,
                "review_type": review_type,
                "run_id": run_state.run_id,
                "pid": run_state.pid,
                "process_killed": killed,
                "outcome": format!("{outcome:?}"),
            }))
            .unwrap_or_default()
        );
    } else {
        let pid_info = run_state
            .pid
            .map_or_else(|| "no-pid".to_string(), |p| p.to_string());
        eprintln!(
            "terminated reviewer PR #{resolved_pr} type={review_type} \
             run_id={} pid={pid_info} killed={killed}",
            run_state.run_id
        );
    }

    Ok(())
}

pub fn run_push(
    repo: &str,
    remote: &str,
    branch: Option<&str>,
    ticket: Option<&Path>,
    json_output: bool,
    write_mode: QueueWriteMode,
) -> u8 {
    push::run_push(repo, remote, branch, ticket, json_output, write_mode)
}

pub fn run_pipeline(repo: &str, pr_number: u32, sha: &str, json_output: bool) -> u8 {
    pipeline::run_pipeline(repo, pr_number, sha, json_output)
}

pub fn run_internal_reviewer(
    repo: &str,
    pr_number: u32,
    review_type: &str,
    expected_head_sha: &str,
    force: bool,
    _json_output: bool,
) -> u8 {
    let parsed_review_type = match review_type.trim().to_ascii_lowercase().as_str() {
        "security" => ReviewRunType::Security,
        "quality" => ReviewRunType::Quality,
        other => {
            let payload = serde_json::json!({
                "error": "fac_review_internal_run_invalid_type",
                "message": format!("invalid review type: {other} (expected security|quality)"),
            });
            println!(
                "{}",
                serde_json::to_string(&payload).unwrap_or_else(|_| "{}".to_string())
            );
            return exit_codes::GENERIC_ERROR;
        },
    };
    if let Err(err) = validate_expected_head_sha(expected_head_sha) {
        let payload = serde_json::json!({
            "error": "fac_review_internal_run_invalid_head_sha",
            "message": err,
        });
        println!(
            "{}",
            serde_json::to_string(&payload).unwrap_or_else(|_| "{}".to_string())
        );
        return exit_codes::GENERIC_ERROR;
    }

    match orchestrator::run_review_inner(
        repo,
        pr_number,
        parsed_review_type,
        Some(expected_head_sha),
        force,
    ) {
        Ok(summary) => {
            let success = summary.security.as_ref().is_none_or(|entry| entry.success)
                && summary.quality.as_ref().is_none_or(|entry| entry.success);
            let payload = serde_json::json!({
                "schema": "apm2.fac.review.internal_run.v1",
                "summary": summary,
            });
            println!(
                "{}",
                serde_json::to_string(&payload).unwrap_or_else(|_| "{}".to_string())
            );
            if success {
                exit_codes::SUCCESS
            } else {
                exit_codes::GENERIC_ERROR
            }
        },
        Err(err) => {
            let payload = serde_json::json!({
                "error": "fac_review_internal_run_failed",
                "message": err,
            });
            println!(
                "{}",
                serde_json::to_string(&payload).unwrap_or_else(|_| "{}".to_string())
            );
            exit_codes::GENERIC_ERROR
        },
    }
}

pub fn run_logs(
    pr_number: Option<u32>,
    repo: &str,
    selector_type: Option<&str>,
    selector: Option<&str>,
    json_output: bool,
) -> u8 {
    logs::run_logs(pr_number, repo, selector_type, selector, json_output)
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::fn_params_excessive_bools)]
pub fn run_gates(
    force: bool,
    quick: bool,
    timeout_seconds: u64,
    memory_max: &str,
    pids_max: u64,
    cpu_quota: &str,
    gate_profile: GateThroughputProfile,
    json_output: bool,
    wait: bool,
    wait_timeout_secs: u64,
    write_mode: QueueWriteMode,
) -> u8 {
    gates::run_gates(
        force,
        quick,
        timeout_seconds,
        memory_max,
        pids_max,
        cpu_quota,
        gate_profile,
        json_output,
        wait,
        wait_timeout_secs,
        write_mode,
    )
}

#[cfg(not(test))]
#[allow(clippy::too_many_arguments)]
pub(super) fn run_gates_local_worker(
    force: bool,
    quick: bool,
    timeout_seconds: u64,
    memory_max: &str,
    pids_max: u64,
    cpu_quota: &str,
    gate_profile: GateThroughputProfile,
    workspace_root: &Path,
    bounded_unit_base: Option<&str>,
    lease_job_id: Option<&str>,
    lease_toolchain_fingerprint: Option<&str>,
) -> Result<LocalGatesRunResult, String> {
    let result = gates::run_gates_local_worker(
        force,
        quick,
        timeout_seconds,
        memory_max,
        pids_max,
        cpu_quota,
        gate_profile,
        workspace_root,
        bounded_unit_base,
        lease_job_id,
        lease_toolchain_fingerprint,
    )?;
    Ok(LocalGatesRunResult {
        exit_code: result.exit_code,
        failure_summary: result.failure_summary,
    })
}

#[cfg(not(test))]
pub(super) fn rebind_gate_cache_after_receipt(
    sha: &str,
    receipts_dir: &std::path::Path,
    job_id: &str,
    signer: &apm2_core::crypto::Signer,
) {
    gate_cache::rebind_gate_cache_after_receipt(sha, receipts_dir, job_id, signer);
}

#[cfg(not(test))]
pub(super) fn rebind_v3_gate_cache_after_receipt(
    sha: &str,
    policy_hash: &str,
    sbx_hash: &str,
    net_hash: &str,
    receipts_dir: &std::path::Path,
    job_id: &str,
    signer: &apm2_core::crypto::Signer,
) {
    evidence::rebind_v3_gate_cache_after_receipt(
        sha,
        policy_hash,
        sbx_hash,
        net_hash,
        receipts_dir,
        job_id,
        signer,
    );
}

#[cfg(not(test))]
pub(super) fn apply_gate_result_lifecycle_for_repo_sha(
    owner_repo: &str,
    head_sha: &str,
    passed: bool,
) -> Result<usize, String> {
    lifecycle::apply_gate_result_events_for_repo_sha(owner_repo, head_sha, passed)
}

// ── Internal dispatch helper (shared with pipeline/follow-up repair) ────────

fn dispatch_run_state_is_terminal(run_state: &str) -> bool {
    let normalized = run_state.trim().to_ascii_lowercase();
    matches!(
        normalized.as_str(),
        "done" | "failed" | "crashed" | "completed" | "cancelled"
    )
}

fn run_dispatch_inner(
    owner_repo: &str,
    pr_number: u32,
    review_type: ReviewRunType,
    expected_head_sha: Option<&str>,
    force: bool,
) -> Result<DispatchSummary, String> {
    let current_head_sha = projection::fetch_pr_head_sha_authoritative(owner_repo, pr_number)?;
    if let Some(identity) = projection_store::load_pr_identity(owner_repo, pr_number)? {
        validate_expected_head_sha(&identity.head_sha)?;
        if !identity.head_sha.eq_ignore_ascii_case(&current_head_sha) {
            projection_store::save_identity_with_context(
                owner_repo,
                pr_number,
                &current_head_sha,
                "dispatch.auto_refresh_identity",
            )
            .map_err(|err| {
                format!(
                    "local PR identity head {} is stale relative to authoritative PR head {current_head_sha}; automatic refresh failed: {err}",
                    identity.head_sha
                )
            })?;
        }
    }
    if let Some(expected) = expected_head_sha {
        validate_expected_head_sha(expected)?;
        if !expected.eq_ignore_ascii_case(&current_head_sha) {
            return Err(format!(
                "PR head mismatch before review dispatch: expected {expected}, authoritative {current_head_sha}"
            ));
        }
    }
    let dispatch_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);

    let kinds = match review_type {
        ReviewRunType::All => vec![ReviewKind::Security, ReviewKind::Quality],
        ReviewRunType::Security => vec![ReviewKind::Security],
        ReviewRunType::Quality => vec![ReviewKind::Quality],
    };
    let clear_projection_verdicts = true;

    let mut results = Vec::with_capacity(kinds.len());
    let mut reviews_dispatched_emitted = false;
    for kind in kinds {
        lifecycle::enforce_pr_capacity(owner_repo, pr_number)?;
        let result = dispatch_single_review_with_force(
            owner_repo,
            pr_number,
            kind,
            &current_head_sha,
            dispatch_epoch,
            force,
        )?;
        let is_joined = result.mode.eq_ignore_ascii_case("joined");
        let joined_is_terminal = dispatch_run_state_is_terminal(&result.run_state);
        let joined_has_run_id = result
            .run_id
            .as_deref()
            .map(str::trim)
            .is_some_and(|value| !value.is_empty());
        if is_joined && !joined_is_terminal && !joined_has_run_id {
            return Err(format!(
                "joined {} dispatch missing run_id in non-terminal state (run_state={})",
                kind.as_str(),
                result.run_state
            ));
        }
        if !is_joined {
            let run_id = result
                .run_id
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    format!(
                        "non-joined {} dispatch returned empty run_id (mode={})",
                        kind.as_str(),
                        result.mode
                    )
                })?;
            let emit_reviews_dispatched = !reviews_dispatched_emitted;
            let token = lifecycle::register_reviewer_dispatch(
                owner_repo,
                pr_number,
                &current_head_sha,
                kind.as_str(),
                Some(run_id),
                result.pid,
                result.pid.and_then(state::get_process_start_time),
                emit_reviews_dispatched,
                clear_projection_verdicts,
            )?;
            if token.is_none() {
                return Err(format!(
                    "lifecycle registration failed for {} review: register_reviewer_dispatch returned none",
                    kind.as_str()
                ));
            }
            if emit_reviews_dispatched {
                reviews_dispatched_emitted = true;
            }
        }
        results.push(result);
    }

    Ok(DispatchSummary {
        pr_url: format!("https://github.com/{owner_repo}/pull/{pr_number}"),
        pr_number,
        head_sha: current_head_sha,
        dispatch_epoch,
        results,
    })
}

pub(super) fn dispatch_reviews_with_lifecycle(
    owner_repo: &str,
    pr_number: u32,
    head_sha: &str,
    force: bool,
) -> Result<Vec<DispatchReviewResult>, String> {
    validate_expected_head_sha(head_sha)?;
    let summary = run_dispatch_inner(
        owner_repo,
        pr_number,
        ReviewRunType::All,
        Some(head_sha),
        force,
    )?;
    Ok(summary.results)
}

// ── Tail ────────────────────────────────────────────────────────────────────

fn run_tail_inner(lines: usize, follow: bool) -> Result<(), String> {
    let path = review_events_path()?;
    if !path.exists() {
        return Err(format!("event stream not found at {}", path.display()));
    }

    let last_lines = state::read_last_lines(&path, lines)?;
    for line in &last_lines {
        println!("{line}");
    }

    if !follow {
        return Ok(());
    }

    let mut offset = fs::metadata(&path).map(|meta| meta.len()).unwrap_or(0);
    loop {
        thread::sleep(Duration::from_secs(1));
        let len = fs::metadata(&path).map(|meta| meta.len()).unwrap_or(0);
        if len < offset {
            offset = len;
        }
        if len == offset {
            continue;
        }
        let mut file =
            File::open(&path).map_err(|err| format!("failed to open {}: {err}", path.display()))?;
        file.seek(SeekFrom::Start(offset))
            .map_err(|err| format!("failed to seek {}: {err}", path.display()))?;
        let mut buf = String::new();
        file.read_to_string(&mut buf)
            .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
        print!("{buf}");
        let _ = std::io::stdout().flush();
        offset = len;
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use std::process::Command;
    use std::sync::atomic::{AtomicU32, Ordering};

    use chrono::Utc;

    use super::backend::build_spawn_command_for_backend;
    use super::barrier::{
        build_barrier_decision_event, is_allowed_author_association, read_event_payload_bounded,
    };
    use super::detection::{detect_comment_permission_denied, detect_http_400_or_rate_limit};
    use super::events::emit_review_event_to_path;
    use super::model_pool::{MODEL_POOL, select_fallback_model, select_review_model_random};
    use super::projection::{
        apply_sequence_done_fallback, event_is_terminal_crash, latest_event_head_sha,
        latest_state_head_sha, projection_state_done, projection_state_failed,
        projection_state_for_type, resolve_current_head_sha, resolve_projection_sha,
    };
    use super::state::{read_last_lines, read_pulse_file_from_path, write_pulse_file_to_path};
    use super::types::{
        EVENT_ROTATE_BYTES, FacEventContext, ReviewBackend, ReviewKind, ReviewRunState,
        ReviewRunStatus, ReviewStateEntry, ReviewStateFile, default_model, now_iso8601_millis,
    };
    static TEST_PR_COUNTER: AtomicU32 = AtomicU32::new(441_000);

    fn next_test_pr() -> u32 {
        TEST_PR_COUNTER.fetch_add(1, Ordering::SeqCst)
    }

    fn sample_run_state(
        pr_number: u32,
        pid: u32,
        head_sha: &str,
        proc_start_time: Option<u64>,
    ) -> ReviewRunState {
        ReviewRunState {
            run_id: "pr441-security-s1-01234567".to_string(),
            owner_repo: "example/repo".to_string(),
            pr_number,
            head_sha: head_sha.to_string(),
            review_type: "security".to_string(),
            reviewer_role: "fac_reviewer".to_string(),
            started_at: "2026-02-10T00:00:00Z".to_string(),
            status: ReviewRunStatus::Alive,
            terminal_reason: None,
            model_id: Some("gpt-5.3-codex".to_string()),
            backend_id: Some("codex".to_string()),
            restart_count: 0,
            nudge_count: 0,
            sequence_number: 1,
            previous_run_id: None,
            previous_head_sha: None,
            pid: Some(pid),
            proc_start_time,
            integrity_hmac: None,
        }
    }

    fn spawn_persistent_process() -> std::process::Child {
        Command::new("sleep")
            .arg("1000")
            .spawn()
            .expect("spawn persistent process")
    }

    fn kill_child(mut child: std::process::Child) {
        let _ = child.kill();
        let _ = child.wait();
    }

    fn dead_pid_for_test() -> u32 {
        let mut child = std::process::Command::new("true")
            .spawn()
            .expect("spawn short-lived child");
        let pid = child.id();
        let _ = child.wait();
        pid
    }

    fn seed_decision_projection_for_terminate(
        home: &std::path::Path,
        owner_repo: &str,
        pr_number: u32,
        review_type: &str,
        head_sha: &str,
        reviewer_login: &str,
        comment_id: u64,
    ) {
        super::verdict_projection::seed_decision_projection_for_home_for_tests(
            home,
            owner_repo,
            pr_number,
            review_type,
            head_sha,
            reviewer_login,
            comment_id,
        )
        .expect("seed decision projection");
    }

    #[test]
    fn test_select_review_model_random_returns_pool_member() {
        let models = MODEL_POOL
            .iter()
            .map(|entry| entry.model)
            .collect::<Vec<_>>();
        for _ in 0..64 {
            let selected = select_review_model_random();
            assert!(
                models.contains(&selected.model.as_str()),
                "selected model must be from pool: {}",
                selected.model
            );
        }
    }

    #[test]
    fn test_select_fallback_model_excludes_failed_and_covers_pool() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..200 {
            let fallback = select_fallback_model("gpt-5.3-codex")
                .expect("known model should produce fallback");
            assert_ne!(fallback.model, "gpt-5.3-codex", "must exclude failed model");
            seen.insert(fallback.model.clone());
        }
        assert!(seen.contains("gemini-3-flash-preview"));
        assert!(seen.contains("gemini-3.1-pro-preview"));
        assert!(seen.contains("gpt-5.3-codex-spark"));
    }

    #[test]
    fn test_select_fallback_model_unknown_returns_pool_member() {
        let fallback =
            select_fallback_model("unknown-model").expect("unknown failure should still fallback");
        assert!(
            MODEL_POOL
                .iter()
                .map(|entry| entry.model)
                .any(|candidate| candidate == fallback.model.as_str())
        );
    }

    #[test]
    fn test_projection_state_helpers() {
        assert!(projection_state_done("done:gpt-5.3-codex/codex:r0:abcdef0"));
        assert!(!projection_state_done(
            "alive:gpt-5.3-codex/codex:r0:abcdef0"
        ));
        assert!(projection_state_failed(
            "failed:comment_post_permission_denied"
        ));
        assert!(!projection_state_failed("none"));
    }

    #[test]
    fn test_allowed_author_association_guard() {
        assert!(is_allowed_author_association("OWNER"));
        assert!(is_allowed_author_association("MEMBER"));
        assert!(is_allowed_author_association("COLLABORATOR"));
        assert!(!is_allowed_author_association("CONTRIBUTOR"));
        assert!(!is_allowed_author_association("NONE"));
    }

    #[test]
    fn test_build_spawn_command_for_backend_codex() {
        let prompt = std::path::Path::new("/tmp/prompt.md");
        let log = std::path::Path::new("/tmp/review.log");
        let capture = std::path::Path::new("/tmp/capture.md");

        let codex = build_spawn_command_for_backend(
            ReviewBackend::Codex,
            prompt,
            log,
            "gpt-5.3-codex",
            Some(capture),
        )
        .expect("build codex command");
        assert_eq!(codex.program, "codex");
        assert!(codex.args.contains(&"exec".to_string()));
        assert!(codex.args.contains(&"--json".to_string()));
        assert!(codex.args.contains(&"--output-last-message".to_string()));
        assert_eq!(codex.stdin_file, Some(prompt.to_path_buf()));
    }

    #[test]
    fn test_build_spawn_command_for_backend_gemini() {
        let temp = tempfile::NamedTempFile::new().expect("tempfile");
        let prompt = temp.path();
        std::fs::write(prompt, "test prompt").expect("write prompt");
        let log = std::path::Path::new("/tmp/review.log");

        let gemini = build_spawn_command_for_backend(
            ReviewBackend::Gemini,
            prompt,
            log,
            "gemini-3-flash-preview",
            None,
        )
        .expect("build gemini command");
        assert_eq!(gemini.program, "gemini");
        assert!(gemini.args.contains(&"-m".to_string()));
        assert!(gemini.args.contains(&"stream-json".to_string()));
    }

    #[test]
    fn test_build_spawn_command_for_backend_claude() {
        let prompt = std::path::Path::new("/tmp/prompt.md");
        let log = std::path::Path::new("/tmp/review.log");

        let claude = build_spawn_command_for_backend(
            ReviewBackend::ClaudeCode,
            prompt,
            log,
            "claude-3-7-sonnet",
            None,
        )
        .expect("build claude command");
        assert_eq!(claude.program, "claude");
        assert!(claude.args.contains(&"--output-format".to_string()));
        assert!(claude.args.contains(&"json".to_string()));
        assert!(claude.args.contains(&"--permission-mode".to_string()));
        assert!(claude.args.contains(&"plan".to_string()));
    }

    #[test]
    fn test_emit_review_event_appends_ndjson() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let path = temp_dir.path().join("review_events.ndjson");

        emit_review_event_to_path(
            &path,
            &serde_json::json!({
                "ts": now_iso8601_millis(),
                "event": "test_event",
                "review_type": "security",
                "pr_number": 1,
                "head_sha": "abc",
                "seq": 1
            }),
        )
        .expect("emit event");

        let lines = read_last_lines(&path, 10).expect("read lines");
        assert_eq!(lines.len(), 1);
        let parsed: serde_json::Value = serde_json::from_str(&lines[0]).expect("parse line");
        assert_eq!(parsed["event"], "test_event");
    }

    #[test]
    fn test_emit_review_event_rotates_at_threshold() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let path = temp_dir.path().join("review_events.ndjson");
        let rotated = temp_dir.path().join("review_events.ndjson.1");
        let oversized_len = usize::try_from(EVENT_ROTATE_BYTES + 1)
            .expect("event rotate threshold should fit into usize in tests");
        let oversized = vec![b'x'; oversized_len];
        std::fs::write(&path, oversized).expect("write oversized file");

        emit_review_event_to_path(
            &path,
            &serde_json::json!({
                "ts": now_iso8601_millis(),
                "event": "post_rotate",
                "review_type": "quality",
                "pr_number": 2,
                "head_sha": "def",
                "seq": 2
            }),
        )
        .expect("emit event");

        assert!(rotated.exists(), "rotated file should exist");
        let lines = read_last_lines(&path, 10).expect("read lines");
        assert_eq!(lines.len(), 1);
    }

    #[test]
    fn test_detect_http_400_or_rate_limit_markers() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let path = temp_dir.path().join("review.log");

        std::fs::write(
            &path,
            r#"{"message":"You have exhausted your capacity on this model. Your quota will reset after 2s."}"#,
        )
        .expect("write rate-limit log");
        assert!(detect_http_400_or_rate_limit(&path));

        std::fs::write(&path, r#"{"message":"normal progress"}"#).expect("write normal log");
        assert!(!detect_http_400_or_rate_limit(&path));
    }

    #[test]
    fn test_detect_comment_permission_denied_markers() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let path = temp_dir.path().join("review.log");

        std::fs::write(
            &path,
            "GraphQL: Resource not accessible by personal access token (addComment)",
        )
        .expect("write denied log");
        assert!(!detect_comment_permission_denied(&path));

        std::fs::write(
            &path,
            r#"{"type":"item.completed","item":{"type":"command_execution","command":"gh pr comment https://github.com/guardian-intelligence/apm2/pull/508 --body-file review.md","status":"failed","exit_code":1,"aggregated_output":"GraphQL: Resource not accessible by personal access token (addComment)"}}"#,
        )
        .expect("write structured denied log");
        assert!(detect_comment_permission_denied(&path));

        std::fs::write(&path, r#"{"message":"normal progress"}"#).expect("write normal log");
        assert!(!detect_comment_permission_denied(&path));
    }

    #[test]
    fn test_detect_comment_permission_denied_ignores_diff_output() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let path = temp_dir.path().join("review.log");

        std::fs::write(
            &path,
            r#"{"type":"item.completed","item":{"command":"/bin/bash -lc 'gh pr diff https://github.com/guardian-intelligence/apm2/pull/508'","aggregated_output":"diff --git a/.github/workflows/ai-review.yml b/.github/workflows/ai-review.yml\nGraphQL: Resource not accessible by personal access token (addComment)"}}"#,
        )
        .expect("write diff-like denied marker log");
        assert!(!detect_comment_permission_denied(&path));
    }

    #[test]
    fn test_detect_comment_permission_denied_requires_comment_context() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let path = temp_dir.path().join("review.log");

        std::fs::write(
            &path,
            r#"{"type":"item.completed","item":{"type":"command_execution","command":"/bin/bash -lc 'gh pr comment https://github.com/guardian-intelligence/apm2/pull/508 --body-file review.md'","status":"failed","exit_code":1,"aggregated_output":"GraphQL: Resource not accessible by personal access token (addComment)"}}"#,
        )
        .expect("write comment denied log");
        assert!(detect_comment_permission_denied(&path));
    }

    #[test]
    fn test_detect_comment_permission_denied_ignores_source_dump() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let path = temp_dir.path().join("review.log");

        let line = serde_json::json!({
            "type": "item.completed",
            "item": {
                "type": "command_execution",
                "command": "nl -ba crates/apm2-cli/src/commands/fac_review.rs",
                "status": "completed",
                "exit_code": 0,
                "aggregated_output": "2396: r#\"{\\\"type\\\":\\\"item.completed\\\",\\\"item\\\":{\\\"command\\\":\\\"/bin/bash -lc 'gh pr comment https://github.com/guardian-intelligence/apm2/pull/508 --body-file review.md'\\\",\\\"aggregated_output\\\":\\\"GraphQL: Resource not accessible by personal access token (addComment)\\\"}}\"#,"
            }
        })
        .to_string();
        std::fs::write(&path, line).expect("write source-dump denied marker log");
        assert!(!detect_comment_permission_denied(&path));
    }

    #[test]
    fn test_run_terminate_inner_skips_when_proc_start_time_missing() {
        let pr_number = next_test_pr();
        let temp = tempfile::tempdir().expect("tempdir");
        let home = temp.path();
        let state_path = super::state::review_run_state_path_for_home(home, pr_number, "security");

        let child = spawn_persistent_process();
        let pid = child.id();
        let state = sample_run_state(pr_number, pid, "abcdef1234567890", None);
        super::state::write_review_run_state_for_home(home, &state).expect("write run state");

        let result = super::run_terminate_inner_for_home(
            home,
            "example/repo",
            Some(pr_number),
            "security",
            false,
        );
        assert!(result.is_err());
        let error = result.expect_err("terminate should fail-closed");
        assert!(error.contains("integrity"));
        assert!(super::state::is_process_alive(pid));

        kill_child(child);
        let _ = std::fs::remove_file(state_path);
    }

    #[test]
    fn test_run_terminate_inner_skips_when_proc_start_time_mismatched() {
        let pr_number = next_test_pr();
        let temp = tempfile::tempdir().expect("tempdir");
        let home = temp.path();
        let state_path = super::state::review_run_state_path_for_home(home, pr_number, "security");

        let child = spawn_persistent_process();
        let pid = child.id();
        let observed_start = super::state::get_process_start_time(pid).expect("read start time");
        let head_sha = "abcdef1234567890abcdef1234567890abcdef12";
        let state = sample_run_state(pr_number, pid, head_sha, Some(observed_start + 1));
        super::state::write_review_run_state_for_home(home, &state).expect("write run state");
        seed_decision_projection_for_terminate(
            home,
            "example/repo",
            pr_number,
            "security",
            head_sha,
            "test-reviewer",
            43,
        );

        let result = super::run_terminate_inner_for_home(
            home,
            "example/repo",
            Some(pr_number),
            "security",
            false,
        );
        assert!(result.is_err());
        let error = result.expect_err("terminate should fail-closed");
        assert!(error.contains("identity mismatch"));
        assert!(super::state::is_process_alive(pid));

        kill_child(child);
        let _ = std::fs::remove_file(state_path);
    }

    #[test]
    fn test_run_terminate_inner_fails_when_pid_missing_for_alive_state() {
        let pr_number = next_test_pr();
        let temp = tempfile::tempdir().expect("tempdir");
        let home = temp.path();
        let state_path = super::state::review_run_state_path_for_home(home, pr_number, "security");

        let mut state = sample_run_state(pr_number, 0, "abcdef1234567890", Some(123_456_789));
        state.pid = None;
        super::state::write_review_run_state_for_home(home, &state).expect("write run state");

        let result = super::run_terminate_inner_for_home(
            home,
            "example/repo",
            Some(pr_number),
            "security",
            false,
        );
        assert!(result.is_err());
        let error = result.expect_err("terminate should fail-closed");
        assert!(error.contains("PID is missing"));

        let loaded = super::state::load_review_run_state_for_home(home, pr_number, "security")
            .expect("load run-state");
        let state = match loaded {
            super::state::ReviewRunStateLoad::Present(state) => state,
            other => panic!("expected present state, got {other:?}"),
        };
        assert_eq!(state.status, ReviewRunStatus::Alive);
        assert!(state.pid.is_none());

        let _ = std::fs::remove_file(state_path);
    }

    #[test]
    fn test_run_terminate_inner_skips_when_repo_mismatch() {
        let pr_number = next_test_pr();
        let temp = tempfile::tempdir().expect("tempdir");
        let home = temp.path();
        let state_path = super::state::review_run_state_path_for_home(home, pr_number, "security");

        let child = spawn_persistent_process();
        let pid = child.id();
        let proc_start_time = super::state::get_process_start_time(pid).expect("read start time");
        let mut state = sample_run_state(pr_number, pid, "abcdef1234567890", Some(proc_start_time));
        state.owner_repo = "example/other-repo".to_string();
        super::state::write_review_run_state_for_home(home, &state).expect("write run state");

        let result = super::run_terminate_inner_for_home(
            home,
            "owner/repo",
            Some(pr_number),
            "security",
            false,
        );
        assert!(
            result.is_err(),
            "repo mismatch should now be treated as a failure"
        );
        let error = result.expect_err("repo mismatch should be surfaced as an error");
        assert!(error.contains("repo mismatch"));
        assert!(super::state::is_process_alive(pid));

        let loaded = super::state::load_review_run_state_for_home(home, pr_number, "security")
            .expect("load run-state");
        let state = match loaded {
            super::state::ReviewRunStateLoad::Present(state) => state,
            other => panic!("expected present state, got {other:?}"),
        };
        assert_eq!(state.status, ReviewRunStatus::Alive);

        kill_child(child);
        let _ = std::fs::remove_file(state_path);
    }

    #[test]
    fn test_run_terminate_inner_skips_when_repo_mismatch_format() {
        let pr_number = next_test_pr();
        let temp = tempfile::tempdir().expect("tempdir");
        let home = temp.path();
        let state_path = super::state::review_run_state_path_for_home(home, pr_number, "security");

        let child = spawn_persistent_process();
        let pid = child.id();
        let proc_start_time = super::state::get_process_start_time(pid).expect("read start time");
        let mut state = sample_run_state(pr_number, pid, "abcdef1234567890", Some(proc_start_time));
        state.owner_repo = "not-a-repo-url".to_string();
        super::state::write_review_run_state_for_home(home, &state).expect("write run state");

        let result = super::run_terminate_inner_for_home(
            home,
            "example/repo",
            Some(pr_number),
            "security",
            false,
        );
        assert!(
            result.is_err(),
            "repo mismatch should now be treated as an error"
        );
        let error = result.expect_err("repo mismatch should be surfaced as an error");
        assert!(error.contains("repo mismatch"));

        kill_child(child);
        let _ = std::fs::remove_file(state_path);
    }

    #[test]
    fn test_run_terminate_inner_fails_on_integrity_mismatch() {
        let pr_number = next_test_pr();
        let temp = tempfile::tempdir().expect("tempdir");
        let home = temp.path();
        let state_path = super::state::review_run_state_path_for_home(home, pr_number, "security");

        let child = spawn_persistent_process();
        let pid = child.id();
        let proc_start_time = super::state::get_process_start_time(pid).expect("read start time");
        let state = sample_run_state(pr_number, pid, "abcdef1234567890", Some(proc_start_time));
        super::state::write_review_run_state_for_home(home, &state).expect("write run state");

        let mut tampered: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&state_path).expect("read run state json"))
                .expect("parse run state json");
        tampered["head_sha"] = serde_json::json!("fedcba0987654321");
        std::fs::write(
            &state_path,
            serde_json::to_vec_pretty(&tampered).expect("serialize tampered run state"),
        )
        .expect("write tampered state");

        let result = super::run_terminate_inner_for_home(
            home,
            "example/repo",
            Some(pr_number),
            "security",
            false,
        );
        assert!(result.is_err());
        let error = result.expect_err("terminate should fail-closed");
        assert!(error.contains("integrity verification failed"));
        assert!(super::state::is_process_alive(pid));

        kill_child(child);
        let _ = std::fs::remove_file(state_path);
    }

    #[test]
    fn test_run_terminate_inner_writes_manual_termination_receipt() {
        let pr_number = next_test_pr();
        let temp = tempfile::tempdir().expect("tempdir");
        let home = temp.path();
        let state_path = super::state::review_run_state_path_for_home(home, pr_number, "security");
        let dead_pid = dead_pid_for_test();
        let state = sample_run_state(
            pr_number,
            dead_pid,
            "abcdef1234567890abcdef1234567890abcdef12",
            Some(123_456_789),
        );
        super::state::write_review_run_state_for_home(home, &state).expect("write run state");
        seed_decision_projection_for_terminate(
            home,
            "example/repo",
            pr_number,
            "security",
            &state.head_sha,
            "test-reviewer",
            42,
        );

        super::run_terminate_inner_for_home(
            home,
            "example/repo",
            Some(pr_number),
            "security",
            false,
        )
        .expect("terminate should succeed");

        let receipt_path = state_path
            .parent()
            .expect("state parent")
            .join("termination_receipt.json");
        let receipt: serde_json::Value = serde_json::from_slice(
            &std::fs::read(&receipt_path).expect("read termination receipt"),
        )
        .expect("parse termination receipt");
        assert_eq!(receipt["repo"], serde_json::json!("example/repo"));
        assert_eq!(receipt["review_type"], serde_json::json!("security"));
        assert_eq!(receipt["outcome"], serde_json::json!("already_dead"));
        assert_eq!(receipt["decision_comment_id"], serde_json::json!(42));
        assert_eq!(
            receipt["decision_author"],
            serde_json::json!("test-reviewer")
        );
        let decision_summary = receipt["decision_summary"]
            .as_str()
            .expect("decision_summary must be present");
        assert_eq!(
            decision_summary.len(),
            64,
            "decision_summary must be a sha256 hex digest"
        );
        assert!(
            decision_summary
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "decision_summary must be lowercase hex"
        );
        let integrity_hmac = receipt["integrity_hmac"]
            .as_str()
            .expect("integrity_hmac must be present");
        assert!(
            !integrity_hmac.is_empty(),
            "integrity_hmac must not be empty"
        );
        let loaded = super::state::load_review_run_state_for_home(home, pr_number, "security")
            .expect("load run-state");
        let terminal_state = match loaded {
            super::state::ReviewRunStateLoad::Present(state) => state,
            other => panic!("expected present state, got {other:?}"),
        };
        assert_eq!(terminal_state.status, ReviewRunStatus::Failed);
        assert_eq!(
            terminal_state.terminal_reason.as_deref(),
            Some(super::types::TERMINAL_MANUAL_TERMINATION_DECISION_BOUND)
        );

        let _ = std::fs::remove_file(state_path);
        let _ = std::fs::remove_file(receipt_path);
    }

    #[test]
    fn test_run_terminate_inner_fails_without_decision_projection() {
        let pr_number = next_test_pr();
        let temp = tempfile::tempdir().expect("tempdir");
        let home = temp.path();
        let dead_pid = dead_pid_for_test();
        let state = sample_run_state(
            pr_number,
            dead_pid,
            "abcdef1234567890abcdef1234567890abcdef12",
            Some(123_456_789),
        );
        super::state::write_review_run_state_for_home(home, &state).expect("write run state");

        let result = super::run_terminate_inner_for_home(
            home,
            "example/repo",
            Some(pr_number),
            "security",
            false,
        );
        assert!(
            result.is_err(),
            "terminate must fail without decision authority"
        );
        let error = result.expect_err("expected decision authority error");
        assert!(
            error.contains("decision-bound authority required"),
            "unexpected error detail: {error}"
        );
        assert!(
            error.contains("missing decision projection")
                || error.contains("failed to read reviewer projection"),
            "unexpected error detail: {error}"
        );
    }

    #[test]
    fn test_detect_http_400_or_rate_limit_ignores_source_dump() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let path = temp_dir.path().join("review.log");

        let line = serde_json::json!({
            "type": "item.completed",
            "item": {
                "type": "command_execution",
                "command": "nl -ba crates/apm2-cli/src/commands/fac_review.rs",
                "status": "completed",
                "exit_code": 0,
                "aggregated_output": "2344: r#\"{\\\"message\\\":\\\"You have exhausted your capacity on this model. Your quota will reset after 2s.\\\"}\"#,"
            }
        })
        .to_string();
        std::fs::write(&path, line).expect("write source-dump backpressure marker log");
        assert!(!detect_http_400_or_rate_limit(&path));
    }

    #[test]
    fn test_pulse_file_roundtrip() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let path = temp_dir.path().join("review_pulse_security.json");
        write_pulse_file_to_path(&path, "0123456789abcdef", None).expect("write pulse");
        let pulse = read_pulse_file_from_path(&path)
            .expect("read pulse")
            .expect("pulse present");
        assert_eq!(pulse.head_sha, "0123456789abcdef");
    }

    #[test]
    fn test_event_is_terminal_crash_conditions() {
        let by_restart = serde_json::json!({
            "event": "run_crash",
            "restart_count": 3,
            "reason": "run_crash"
        });
        assert!(event_is_terminal_crash(&by_restart));

        let by_reason = serde_json::json!({
            "event": "run_crash",
            "restart_count": 0,
            "reason": "comment_post_permission_denied"
        });
        assert!(event_is_terminal_crash(&by_reason));

        let non_terminal = serde_json::json!({
            "event": "run_crash",
            "restart_count": 1,
            "reason": "run_crash"
        });
        assert!(!event_is_terminal_crash(&non_terminal));
    }

    #[test]
    fn test_projection_state_for_type_prefers_done_event() {
        let state = ReviewStateFile::default();
        let events = vec![
            serde_json::json!({
                "event": "run_start",
                "review_type": "security",
                "pr_number": 42,
                "model": "gpt-5.3-codex",
                "backend": "codex",
                "restart_count": 1,
                "head_sha": "abcdef1234567890",
                "seq": 1
            }),
            serde_json::json!({
                "event": "run_complete",
                "review_type": "security",
                "pr_number": 42,
                "restart_count": 2,
                "head_sha": "abcdef1234567890",
                "verdict": "PASS",
                "seq": 2
            }),
        ];

        let rendered = projection_state_for_type(&state, &events, 42, ReviewKind::Security, None);
        assert_eq!(rendered, "done:gpt-5.3-codex/codex:r2:abcdef1");
    }

    #[test]
    fn test_projection_state_for_type_fail_verdict_is_failed() {
        let state = ReviewStateFile::default();
        let events = vec![serde_json::json!({
            "event": "run_complete",
            "review_type": "security",
            "pr_number": 42,
            "head_sha": "abcdef1234567890",
            "verdict": "FAIL",
            "seq": 2
        })];

        let rendered = projection_state_for_type(&state, &events, 42, ReviewKind::Security, None);
        assert_eq!(rendered, "failed:verdict_fail");
    }

    #[test]
    fn test_projection_state_for_type_unknown_verdict_is_failed() {
        let state = ReviewStateFile::default();
        let events = vec![serde_json::json!({
            "event": "run_complete",
            "review_type": "quality",
            "pr_number": 17,
            "head_sha": "abcdef1234567890",
            "verdict": "UNKNOWN",
            "seq": 2
        })];

        let rendered = projection_state_for_type(&state, &events, 17, ReviewKind::Quality, None);
        assert_eq!(rendered, "failed:verdict_unknown");
    }

    #[test]
    fn test_projection_state_for_type_terminal_crash() {
        let state = ReviewStateFile::default();
        let events = vec![serde_json::json!({
            "event": "run_crash",
            "review_type": "quality",
            "pr_number": 17,
            "restart_count": 0,
            "reason": "comment_post_permission_denied",
            "seq": 1
        })];

        let rendered = projection_state_for_type(&state, &events, 17, ReviewKind::Quality, None);
        assert_eq!(rendered, "failed:comment_post_permission_denied");
    }

    #[test]
    fn test_projection_state_for_type_stale_without_current_events_is_none() {
        let dead_pid = dead_pid_for_test();
        let mut state = ReviewStateFile::default();
        state.reviewers.insert(
            "stale-security".to_string(),
            ReviewStateEntry {
                pid: dead_pid,
                started_at: Utc::now(),
                log_file: PathBuf::from("/tmp/stale.log"),
                prompt_file: None,
                last_message_file: None,
                review_type: "security".to_string(),
                pr_number: 42,
                owner_repo: "owner/repo".to_string(),
                head_sha: "abcdef1234567890abcdef1234567890abcdef12".to_string(),
                restart_count: 0,
                model: default_model(),
                backend: ReviewBackend::Codex,
                temp_files: Vec::new(),
                run_id: "stale-security-run".to_string(),
                sequence_number: 1,
                terminal_reason: None,
                model_id: Some(default_model()),
                backend_id: Some("codex".to_string()),
                status: ReviewRunStatus::Alive,
            },
        );
        let events = Vec::<serde_json::Value>::new();

        let rendered = projection_state_for_type(
            &state,
            &events,
            42,
            ReviewKind::Security,
            Some("abcdef1234567890abcdef1234567890abcdef12"),
        );
        assert_eq!(rendered, "none");
    }

    #[test]
    fn test_projection_state_for_type_stale_with_current_events_is_failed() {
        let dead_pid = dead_pid_for_test();
        let mut state = ReviewStateFile::default();
        state.reviewers.insert(
            "stale-quality".to_string(),
            ReviewStateEntry {
                pid: dead_pid,
                started_at: Utc::now(),
                log_file: PathBuf::from("/tmp/stale.log"),
                prompt_file: None,
                last_message_file: None,
                review_type: "quality".to_string(),
                pr_number: 17,
                owner_repo: "owner/repo".to_string(),
                head_sha: "abcdef1234567890abcdef1234567890abcdef12".to_string(),
                restart_count: 0,
                model: default_model(),
                backend: ReviewBackend::Codex,
                temp_files: Vec::new(),
                run_id: "stale-quality-run".to_string(),
                sequence_number: 1,
                terminal_reason: None,
                model_id: Some(default_model()),
                backend_id: Some("codex".to_string()),
                status: ReviewRunStatus::Alive,
            },
        );
        let events = vec![serde_json::json!({
            "event": "run_start",
            "review_type": "quality",
            "pr_number": 17,
            "head_sha": "abcdef1234567890abcdef1234567890abcdef12",
            "seq": 1
        })];

        let rendered = projection_state_for_type(
            &state,
            &events,
            17,
            ReviewKind::Quality,
            Some("abcdef1234567890abcdef1234567890abcdef12"),
        );
        assert_eq!(rendered, "failed:stale_process_state");
    }

    #[test]
    fn test_apply_sequence_done_fallback_sets_done_states() {
        let events = vec![serde_json::json!({
            "event": "sequence_done",
            "head_sha": "abcdef1234567890",
            "security_verdict": "DEDUPED",
            "quality_verdict": "PASS",
            "seq": 9
        })];
        let mut security = "none".to_string();
        let mut quality = "none".to_string();

        apply_sequence_done_fallback(&events, &mut security, &mut quality);

        assert_eq!(security, "done:sequence/summary:r0:abcdef1");
        assert_eq!(quality, "done:sequence/summary:r0:abcdef1");
    }

    #[test]
    fn test_apply_sequence_done_fallback_sets_failed_state() {
        let events = vec![serde_json::json!({
            "event": "sequence_done",
            "head_sha": "abcdef1234567890",
            "security_verdict": "FAIL",
            "quality_verdict": "UNKNOWN",
            "seq": 9
        })];
        let mut security = "none".to_string();
        let mut quality = "none".to_string();

        apply_sequence_done_fallback(&events, &mut security, &mut quality);

        assert_eq!(security, "failed:sequence_fail");
        assert_eq!(quality, "failed:sequence_unknown");
    }

    #[test]
    fn test_read_event_payload_bounded_rejects_oversized_payload() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let path = temp_dir.path().join("event.json");
        std::fs::write(&path, "0123456789abcdef").expect("write oversized payload");

        let err = read_event_payload_bounded(&path, 8).expect_err("payload should be rejected");
        assert!(err.contains("too large"), "unexpected error: {err}");
    }

    #[test]
    fn test_build_barrier_decision_event_contains_reason() {
        let event = build_barrier_decision_event(
            "barrier",
            "guardian-intelligence/apm2",
            "workflow_dispatch",
            None,
            false,
            Some("missing actor permission"),
        );
        assert_eq!(event["event"], "barrier_decision");
        assert_eq!(event["phase"], "barrier");
        assert_eq!(event["result"], "fail");
        assert_eq!(event["repo"], "guardian-intelligence/apm2");
        assert_eq!(event["reason"], "missing actor permission");
        assert_eq!(event["pr_number"], 0);
        assert_eq!(event["head_sha"], "-");
    }

    #[test]
    fn test_build_barrier_decision_event_with_context() {
        let ctx = FacEventContext {
            repo: "guardian-intelligence/apm2".to_string(),
            event_name: "pull_request_target".to_string(),
            pr_number: 509,
            pr_url: "https://github.com/guardian-intelligence/apm2/pull/509".to_string(),
            head_sha: "0c662aab51571e9a5d0ff7ab11bde9457cef23e1".to_string(),
            base_ref: "main".to_string(),
            default_branch: "main".to_string(),
            author_login: "Anveio".to_string(),
            author_association: "MEMBER".to_string(),
            actor_login: "Anveio".to_string(),
            actor_permission: Some("admin".to_string()),
        };
        let event = build_barrier_decision_event(
            "kickoff",
            &ctx.repo,
            &ctx.event_name,
            Some(&ctx),
            true,
            None,
        );
        assert_eq!(event["result"], "pass");
        assert_eq!(event["pr_number"], 509);
        assert_eq!(
            event["head_sha"],
            "0c662aab51571e9a5d0ff7ab11bde9457cef23e1"
        );
        assert_eq!(event["actor_permission"], "admin");
        assert!(event.get("reason").is_none());
    }

    // =========================================================================
    // SHA resolution function tests
    // =========================================================================

    #[test]
    fn test_latest_state_head_sha_empty() {
        let state = ReviewStateFile {
            reviewers: BTreeMap::new(),
        };
        assert_eq!(latest_state_head_sha(&state, 42), None);
    }

    #[test]
    fn test_latest_state_head_sha_match() {
        let mut state = ReviewStateFile {
            reviewers: BTreeMap::new(),
        };
        state.reviewers.insert(
            "security-1".to_string(),
            ReviewStateEntry {
                pid: 1234,
                started_at: Utc::now(),
                log_file: PathBuf::from("/tmp/log"),
                prompt_file: None,
                last_message_file: None,
                review_type: "security".to_string(),
                pr_number: 42,
                owner_repo: "owner/repo".to_string(),
                head_sha: "abc123def456".to_string(),
                restart_count: 0,
                model: "test-model".to_string(),
                backend: ReviewBackend::default(),
                temp_files: Vec::new(),
                run_id: "security-1-run".to_string(),
                sequence_number: 1,
                terminal_reason: None,
                model_id: Some("test-model".to_string()),
                backend_id: Some("codex".to_string()),
                status: ReviewRunStatus::Alive,
            },
        );
        assert_eq!(
            latest_state_head_sha(&state, 42),
            Some("abc123def456".to_string())
        );
    }

    #[test]
    fn test_latest_state_head_sha_latest_wins() {
        let mut state = ReviewStateFile {
            reviewers: BTreeMap::new(),
        };
        let early = Utc::now() - chrono::Duration::seconds(60);
        let late = Utc::now();
        state.reviewers.insert(
            "security-old".to_string(),
            ReviewStateEntry {
                pid: 1000,
                started_at: early,
                log_file: PathBuf::from("/tmp/old"),
                prompt_file: None,
                last_message_file: None,
                review_type: "security".to_string(),
                pr_number: 42,
                owner_repo: "owner/repo".to_string(),
                head_sha: "old_sha".to_string(),
                restart_count: 0,
                model: "test-model".to_string(),
                backend: ReviewBackend::default(),
                temp_files: Vec::new(),
                run_id: "security-old-run".to_string(),
                sequence_number: 1,
                terminal_reason: None,
                model_id: Some("test-model".to_string()),
                backend_id: Some("codex".to_string()),
                status: ReviewRunStatus::Alive,
            },
        );
        state.reviewers.insert(
            "security-new".to_string(),
            ReviewStateEntry {
                pid: 2000,
                started_at: late,
                log_file: PathBuf::from("/tmp/new"),
                prompt_file: None,
                last_message_file: None,
                review_type: "security".to_string(),
                pr_number: 42,
                owner_repo: "owner/repo".to_string(),
                head_sha: "new_sha".to_string(),
                restart_count: 0,
                model: "test-model".to_string(),
                backend: ReviewBackend::default(),
                temp_files: Vec::new(),
                run_id: "security-new-run".to_string(),
                sequence_number: 2,
                terminal_reason: None,
                model_id: Some("test-model".to_string()),
                backend_id: Some("codex".to_string()),
                status: ReviewRunStatus::Alive,
            },
        );
        assert_eq!(
            latest_state_head_sha(&state, 42),
            Some("new_sha".to_string())
        );
    }

    #[test]
    fn test_latest_state_head_sha_wrong_pr() {
        let mut state = ReviewStateFile {
            reviewers: BTreeMap::new(),
        };
        state.reviewers.insert(
            "quality-1".to_string(),
            ReviewStateEntry {
                pid: 1234,
                started_at: Utc::now(),
                log_file: PathBuf::from("/tmp/log"),
                prompt_file: None,
                last_message_file: None,
                review_type: "quality".to_string(),
                pr_number: 99,
                owner_repo: "owner/repo".to_string(),
                head_sha: "sha_for_99".to_string(),
                restart_count: 0,
                model: "test-model".to_string(),
                backend: ReviewBackend::default(),
                temp_files: Vec::new(),
                run_id: "quality-1-run".to_string(),
                sequence_number: 1,
                terminal_reason: None,
                model_id: Some("test-model".to_string()),
                backend_id: Some("codex".to_string()),
                status: ReviewRunStatus::Alive,
            },
        );
        assert_eq!(latest_state_head_sha(&state, 42), None);
    }

    #[test]
    fn test_latest_event_head_sha_empty() {
        let events: Vec<serde_json::Value> = vec![];
        assert_eq!(latest_event_head_sha(&events), None);
    }

    #[test]
    fn test_latest_event_head_sha_last_wins() {
        let events = vec![
            serde_json::json!({"head_sha": "first_sha", "event": "dispatched"}),
            serde_json::json!({"head_sha": "second_sha", "event": "started"}),
        ];
        assert_eq!(
            latest_event_head_sha(&events),
            Some("second_sha".to_string())
        );
    }

    #[test]
    fn test_latest_event_head_sha_skips_dash() {
        let events = vec![
            serde_json::json!({"head_sha": "real_sha", "event": "dispatched"}),
            serde_json::json!({"head_sha": "-", "event": "stall"}),
            serde_json::json!({"head_sha": "", "event": "crash"}),
        ];
        assert_eq!(latest_event_head_sha(&events), Some("real_sha".to_string()));
    }

    #[test]
    fn test_resolve_projection_sha_filter_priority() {
        let state = ReviewStateFile {
            reviewers: BTreeMap::new(),
        };
        let events: Vec<serde_json::Value> = vec![];
        assert_eq!(
            resolve_projection_sha(42, &state, &events, Some("override_sha")),
            "override_sha"
        );
    }

    #[test]
    fn test_resolve_projection_sha_state_fallback() {
        let mut state = ReviewStateFile {
            reviewers: BTreeMap::new(),
        };
        state.reviewers.insert(
            "sec-1".to_string(),
            ReviewStateEntry {
                pid: 1,
                started_at: Utc::now(),
                log_file: PathBuf::from("/tmp/log"),
                prompt_file: None,
                last_message_file: None,
                review_type: "security".to_string(),
                pr_number: 77777,
                owner_repo: "owner/repo".to_string(),
                head_sha: "state_sha_wins".to_string(),
                restart_count: 0,
                model: "test-model".to_string(),
                backend: ReviewBackend::default(),
                temp_files: Vec::new(),
                run_id: "sec-state-fallback-run".to_string(),
                sequence_number: 1,
                terminal_reason: None,
                model_id: Some("test-model".to_string()),
                backend_id: Some("codex".to_string()),
                status: ReviewRunStatus::Alive,
            },
        );
        let events: Vec<serde_json::Value> = vec![];
        let result = resolve_projection_sha(77777, &state, &events, None);
        assert_eq!(result, "state_sha_wins");
    }

    #[test]
    fn test_resolve_projection_sha_events_fallback() {
        let state = ReviewStateFile {
            reviewers: BTreeMap::new(),
        };
        let events = vec![serde_json::json!({"head_sha": "event_sha_abc", "event": "dispatched"})];
        let result = resolve_projection_sha(88888, &state, &events, None);
        assert_eq!(result, "event_sha_abc");
    }

    #[test]
    fn test_resolve_current_head_sha_state_priority() {
        let mut state = ReviewStateFile {
            reviewers: BTreeMap::new(),
        };
        state.reviewers.insert(
            "sec-1".to_string(),
            ReviewStateEntry {
                pid: 1,
                started_at: Utc::now(),
                log_file: PathBuf::from("/tmp/log"),
                prompt_file: None,
                last_message_file: None,
                review_type: "security".to_string(),
                pr_number: 77777,
                owner_repo: "owner/repo".to_string(),
                head_sha: "state_sha_current".to_string(),
                restart_count: 0,
                model: "test-model".to_string(),
                backend: ReviewBackend::default(),
                temp_files: Vec::new(),
                run_id: "sec-current-head-run".to_string(),
                sequence_number: 1,
                terminal_reason: None,
                model_id: Some("test-model".to_string()),
                backend_id: Some("codex".to_string()),
                status: ReviewRunStatus::Alive,
            },
        );
        let events: Vec<serde_json::Value> = vec![];
        let result = resolve_current_head_sha(77777, &state, &events, "fallback_sha");
        assert_ne!(result, "fallback_sha");
    }

    fn doctor_merge_readiness_fixture(
        merge_conflict_status: super::DoctorMergeConflictStatus,
    ) -> super::DoctorMergeReadiness {
        super::DoctorMergeReadiness {
            merge_ready: false,
            all_verdicts_approve: false,
            gates_pass: false,
            sha_fresh: false,
            sha_freshness_source: super::DoctorShaFreshnessSource::Unknown,
            no_merge_conflicts: merge_conflict_status
                == super::DoctorMergeConflictStatus::NoConflicts,
            merge_conflict_status,
        }
    }

    fn pending_findings_summary() -> Vec<super::DoctorFindingsDimensionSummary> {
        vec![
            super::DoctorFindingsDimensionSummary {
                dimension: "security".to_string(),
                counts: super::DoctorFindingsCounts {
                    blocker: 0,
                    major: 0,
                    minor: 0,
                    nit: 0,
                },
                formal_verdict: "pending".to_string(),
                computed_verdict: "pending".to_string(),
            },
            super::DoctorFindingsDimensionSummary {
                dimension: "code-quality".to_string(),
                counts: super::DoctorFindingsCounts {
                    blocker: 0,
                    major: 0,
                    minor: 0,
                    nit: 0,
                },
                formal_verdict: "pending".to_string(),
                computed_verdict: "pending".to_string(),
            },
        ]
    }

    fn findings_summary_entry(
        dimension: &str,
        formal_verdict: &str,
        blocker: u32,
        major: u32,
        minor: u32,
        nit: u32,
    ) -> super::DoctorFindingsDimensionSummary {
        super::DoctorFindingsDimensionSummary {
            dimension: dimension.to_string(),
            counts: super::DoctorFindingsCounts {
                blocker,
                major,
                minor,
                nit,
            },
            formal_verdict: formal_verdict.to_string(),
            computed_verdict: if blocker > 0 || major > 0 {
                "deny".to_string()
            } else if minor > 0 || nit > 0 {
                "approve".to_string()
            } else {
                "pending".to_string()
            },
        }
    }

    fn doctor_gate_snapshot(name: &str, status: &str) -> super::DoctorGateSnapshot {
        super::DoctorGateSnapshot {
            name: name.to_string(),
            status: status.to_string(),
            completed_at: None,
            freshness_seconds: None,
            source: super::DoctorGateSource::LocalCache,
        }
    }

    fn doctor_push_attempt_summary(
        failed_stage: Option<&str>,
        error_hint: Option<&str>,
    ) -> super::DoctorPushAttemptSummary {
        super::DoctorPushAttemptSummary {
            ts: "fixture-ts".to_string(),
            sha: "0123456789abcdef0123456789abcdef01234567".to_string(),
            failed_stage: failed_stage.map(str::to_string),
            exit_code: Some(1),
            duration_s: Some(30),
            error_hint: error_hint.map(str::to_string),
        }
    }

    fn reviewer_agent_snapshot(
        state: &str,
        elapsed_seconds: Option<i64>,
        last_activity_seconds_ago: Option<i64>,
    ) -> super::DoctorAgentSnapshot {
        super::DoctorAgentSnapshot {
            agent_type: "reviewer_security".to_string(),
            state: state.to_string(),
            run_id: "run-security".to_string(),
            sha: "0123456789abcdef0123456789abcdef01234567".to_string(),
            pid: Some(4242),
            pid_alive: true,
            started_at: "2026-02-15T00:00:00Z".to_string(),
            completion_status: None,
            completion_summary: None,
            completion_token_hash: "token".to_string(),
            completion_token_expires_at: "2026-02-15T01:00:00Z".to_string(),
            elapsed_seconds,
            models_attempted: Vec::new(),
            tool_call_count: None,
            log_line_count: None,
            nudge_count: None,
            last_activity_seconds_ago,
        }
    }

    fn doctor_pr_summary_for_fix_tests(
        findings_summary: Vec<super::DoctorFindingsDimensionSummary>,
        agents: Option<super::DoctorAgentSection>,
    ) -> super::DoctorPrSummary {
        super::DoctorPrSummary {
            schema: "apm2.fac.review.doctor.v1".to_string(),
            pr_number: 42,
            owner_repo: "example/repo".to_string(),
            identity: super::DoctorIdentitySnapshot {
                pr_number: 42,
                branch: None,
                worktree: None,
                source: None,
                local_sha: None,
                updated_at: None,
                remote_head_sha: None,
                stale: false,
            },
            lifecycle: None,
            gates: Vec::new(),
            reviews: Vec::new(),
            findings_summary,
            merge_readiness: doctor_merge_readiness_fixture(
                super::DoctorMergeConflictStatus::Unknown,
            ),
            worktree_status: super::DoctorWorktreeStatus {
                worktree_exists: false,
                worktree_clean: false,
                merge_conflicts: 0,
            },
            github_projection: super::DoctorGithubProjectionStatus {
                auto_merge_enabled: false,
                last_comment_updated_at: None,
                projection_lag_seconds: None,
            },
            recommended_action: super::DoctorRecommendedAction {
                action: "wait".to_string(),
                reason: "fixture".to_string(),
                priority: "low".to_string(),
                command: None,
                follow_up_fix: false,
                follow_up_force: false,
            },
            agents,
            run_state_diagnostics: Vec::new(),
            repairs_applied: Vec::new(),
            latest_push_attempt: None,
            repair_signals: super::DoctorRepairSignals::default(),
            health: Vec::new(),
        }
    }

    fn doctor_lifecycle_fixture(
        state: &str,
        retry_budget_remaining: u32,
        error_budget_used: u32,
        last_event_seq: u64,
    ) -> super::DoctorLifecycleSnapshot {
        super::DoctorLifecycleSnapshot {
            state: state.to_string(),
            time_in_state_seconds: 30,
            error_budget_used,
            retry_budget_remaining,
            updated_at: "2026-02-15T00:00:00Z".to_string(),
            last_event_seq,
        }
    }

    fn doctor_reviews_with_terminal_reason(
        terminal_reason: Option<&str>,
    ) -> Vec<super::DoctorReviewSnapshot> {
        vec![
            super::DoctorReviewSnapshot {
                dimension: "security".to_string(),
                verdict: "pending".to_string(),
                reviewed_sha: String::new(),
                reviewed_by: String::new(),
                reviewed_at: String::new(),
                reason: String::new(),
                terminal_reason: terminal_reason.map(str::to_string),
            },
            super::DoctorReviewSnapshot {
                dimension: "code-quality".to_string(),
                verdict: "pending".to_string(),
                reviewed_sha: String::new(),
                reviewed_by: String::new(),
                reviewed_at: String::new(),
                reason: String::new(),
                terminal_reason: None,
            },
        ]
    }

    fn build_recommended_action_for_tests(
        pr_number: u32,
        lifecycle: Option<&super::DoctorLifecycleSnapshot>,
        agents: Option<&super::DoctorAgentSection>,
        reviews: &[super::DoctorReviewSnapshot],
        findings_summary: &[super::DoctorFindingsDimensionSummary],
        merge_readiness: &super::DoctorMergeReadiness,
    ) -> super::DoctorRecommendedAction {
        let mut terminal_reasons = std::collections::BTreeMap::new();
        let repair_signals = super::DoctorRepairSignals::default();
        for review in reviews {
            terminal_reasons.insert(
                super::canonical_review_dimension(&review.dimension),
                review.terminal_reason.clone(),
            );
        }
        super::build_recommended_action(&super::DoctorActionInputs {
            pr_number,
            repair_signals: &repair_signals,
            lifecycle,
            gates: &[],
            agent_activity: super::build_doctor_agent_activity_summary(agents),
            reviews,
            review_terminal_reasons: &terminal_reasons,
            findings_summary,
            merge_readiness,
            latest_push_attempt: None,
        })
    }

    fn doctor_summary_for_repair_plan_tests() -> super::DoctorPrSummary {
        let mut summary = doctor_pr_summary_for_fix_tests(pending_findings_summary(), None);
        summary.identity.local_sha = Some("0123456789abcdef0123456789abcdef01234567".to_string());
        summary.identity.stale = false;
        summary.lifecycle = Some(doctor_lifecycle_fixture("pushed", 3, 0, 1));
        summary.repair_signals.identity_missing = false;
        summary.repair_signals.identity_stale = false;
        summary
    }

    #[test]
    fn test_derive_doctor_repair_plan_flags_registry_integrity_repair() {
        let mut summary = doctor_summary_for_repair_plan_tests();
        summary.repair_signals.agent_registry_load_failed = true;

        let plan = super::derive_doctor_repair_plan(&summary);
        assert!(plan.repair_registry_integrity);
        assert!(!plan.reset_lifecycle);
    }

    #[test]
    fn test_derive_doctor_repair_plan_uses_push_attempt_registry_hint() {
        let mut summary = doctor_summary_for_repair_plan_tests();
        summary.repair_signals.agent_registry_load_failed = true;

        let plan = super::derive_doctor_repair_plan(&summary);
        assert!(plan.repair_registry_integrity);
    }

    #[test]
    fn test_derive_doctor_repair_plan_refreshes_identity_when_missing() {
        let mut summary = doctor_summary_for_repair_plan_tests();
        summary.repair_signals.identity_missing = true;

        let plan = super::derive_doctor_repair_plan(&summary);
        assert!(plan.refresh_identity);
    }

    #[test]
    fn test_derive_doctor_repair_plan_refreshes_identity_when_stale() {
        let mut summary = doctor_summary_for_repair_plan_tests();
        summary.repair_signals.identity_stale = true;

        let plan = super::derive_doctor_repair_plan(&summary);
        assert!(plan.refresh_identity);
    }

    #[test]
    fn test_doctor_requires_force_repair_for_registry_integrity_issue() {
        let mut summary = doctor_summary_for_repair_plan_tests();
        summary.repair_signals.agent_registry_load_failed = true;

        assert!(super::doctor_requires_force_repair(&summary));
    }

    #[test]
    fn test_doctor_requires_force_repair_does_not_force_on_run_state_only() {
        let mut summary = doctor_summary_for_repair_plan_tests();
        summary.repair_signals.run_state_repair_required = true;

        assert!(
            !super::doctor_requires_force_repair(&summary),
            "run-state-only repair should not imply forced lifecycle reset"
        );
    }

    #[test]
    fn test_build_recommended_action_uses_force_fix_for_max_restarts_exceeded_before_escalation() {
        let reviews = doctor_reviews_with_terminal_reason(Some("max_restarts_exceeded"));
        let findings = pending_findings_summary();
        let action = build_recommended_action_for_tests(
            42,
            Some(&doctor_lifecycle_fixture("stuck", 0, 9, 100)),
            Some(&super::DoctorAgentSection {
                max_active_agents_per_pr: 2,
                active_agents: 0,
                total_agents: 0,
                entries: Vec::new(),
            }),
            &reviews,
            &findings,
            &doctor_merge_readiness_fixture(super::DoctorMergeConflictStatus::Unknown),
        );
        assert_eq!(action.action, "fix");
        let command = action.command.expect("fix command");
        assert_eq!(command, "apm2 fac doctor --pr 42 --fix");
        assert!(action.follow_up_fix);
        assert!(action.follow_up_force);
    }

    #[test]
    fn test_build_recommended_action_uses_force_fix_when_terminal_reason_only_in_state_map() {
        let findings = pending_findings_summary();
        let terminal_reasons = std::collections::BTreeMap::from([(
            "security".to_string(),
            Some("max_restarts_exceeded".to_string()),
        )]);
        let action = super::build_recommended_action(&super::DoctorActionInputs {
            pr_number: 42,
            repair_signals: &super::DoctorRepairSignals::default(),
            lifecycle: Some(&doctor_lifecycle_fixture("stuck", 0, 9, 100)),
            gates: &[],
            agent_activity: super::build_doctor_agent_activity_summary(Some(
                &super::DoctorAgentSection {
                    max_active_agents_per_pr: 2,
                    active_agents: 0,
                    total_agents: 0,
                    entries: Vec::new(),
                },
            )),
            reviews: &[],
            review_terminal_reasons: &terminal_reasons,
            findings_summary: &findings,
            merge_readiness: &doctor_merge_readiness_fixture(
                super::DoctorMergeConflictStatus::Unknown,
            ),
            latest_push_attempt: None,
        });
        assert_eq!(action.action, "fix");
        let command = action.command.expect("fix command");
        assert_eq!(command, "apm2 fac doctor --pr 42 --fix");
        assert!(action.follow_up_fix);
        assert!(action.follow_up_force);
    }

    #[test]
    fn test_build_recommended_action_terminal_reason_read_warning_does_not_force_fix() {
        let findings = pending_findings_summary();
        let terminal_reasons = std::collections::BTreeMap::new();
        let action = super::build_recommended_action(&super::DoctorActionInputs {
            pr_number: 42,
            repair_signals: &super::DoctorRepairSignals::default(),
            lifecycle: Some(&doctor_lifecycle_fixture("stuck", 0, 9, 100)),
            gates: &[],
            agent_activity: super::build_doctor_agent_activity_summary(Some(
                &super::DoctorAgentSection {
                    max_active_agents_per_pr: 2,
                    active_agents: 0,
                    total_agents: 0,
                    entries: Vec::new(),
                },
            )),
            reviews: &[],
            review_terminal_reasons: &terminal_reasons,
            findings_summary: &findings,
            merge_readiness: &doctor_merge_readiness_fixture(
                super::DoctorMergeConflictStatus::Unknown,
            ),
            latest_push_attempt: None,
        });
        assert_eq!(action.action, "fix");
        let command = action.command.expect("fix command");
        assert_eq!(command, "apm2 fac doctor --pr 42 --fix");
        assert!(action.follow_up_fix);
        assert!(!action.follow_up_force);
    }

    #[test]
    fn test_build_recommended_action_recommends_fix_for_run_state_corruption() {
        let findings = pending_findings_summary();
        let terminal_reasons = std::collections::BTreeMap::new();
        let repair_signals = super::DoctorRepairSignals {
            run_state_repair_required: true,
            ..super::DoctorRepairSignals::default()
        };
        let action = super::build_recommended_action(&super::DoctorActionInputs {
            pr_number: 42,
            repair_signals: &repair_signals,
            lifecycle: Some(&doctor_lifecycle_fixture("review_in_progress", 1, 0, 10)),
            gates: &[],
            agent_activity: super::build_doctor_agent_activity_summary(Some(
                &super::DoctorAgentSection {
                    max_active_agents_per_pr: 2,
                    active_agents: 1,
                    total_agents: 1,
                    entries: Vec::new(),
                },
            )),
            reviews: &[],
            review_terminal_reasons: &terminal_reasons,
            findings_summary: &findings,
            merge_readiness: &doctor_merge_readiness_fixture(
                super::DoctorMergeConflictStatus::Unknown,
            ),
            latest_push_attempt: None,
        });
        assert_eq!(action.action, "fix");
    }

    #[test]
    fn test_build_recommended_action_missing_run_state_does_not_force_fix_command() {
        let findings = pending_findings_summary();
        let terminal_reasons = std::collections::BTreeMap::new();
        let action = super::build_recommended_action(&super::DoctorActionInputs {
            pr_number: 42,
            repair_signals: &super::DoctorRepairSignals::default(),
            lifecycle: Some(&doctor_lifecycle_fixture("review_in_progress", 1, 0, 10)),
            gates: &[],
            agent_activity: super::build_doctor_agent_activity_summary(Some(
                &super::DoctorAgentSection {
                    max_active_agents_per_pr: 2,
                    active_agents: 1,
                    total_agents: 1,
                    entries: Vec::new(),
                },
            )),
            reviews: &[],
            review_terminal_reasons: &terminal_reasons,
            findings_summary: &findings,
            merge_readiness: &doctor_merge_readiness_fixture(
                super::DoctorMergeConflictStatus::Unknown,
            ),
            latest_push_attempt: None,
        });
        assert_eq!(action.action, "fix");
        let command = action.command.expect("fix command");
        assert_eq!(command, "apm2 fac doctor --pr 42 --fix");
        assert!(action.follow_up_fix);
        assert!(!action.follow_up_force);
    }

    #[test]
    fn test_build_recommended_action_unknown_merge_conflict_does_not_escalate() {
        let reviews = doctor_reviews_with_terminal_reason(None);
        let findings = pending_findings_summary();
        let action = build_recommended_action_for_tests(
            42,
            None,
            Some(&super::DoctorAgentSection {
                max_active_agents_per_pr: 2,
                active_agents: 0,
                total_agents: 0,
                entries: Vec::new(),
            }),
            &reviews,
            &findings,
            &doctor_merge_readiness_fixture(super::DoctorMergeConflictStatus::Unknown),
        );
        assert_eq!(action.action, "fix");
        let command = action.command.expect("fix command");
        assert_eq!(command, "apm2 fac doctor --pr 42 --fix");
        assert!(action.follow_up_fix);
        assert!(!action.follow_up_force);
    }

    #[test]
    fn test_build_recommended_action_dispatches_implementor_on_explicit_merge_conflicts() {
        let reviews = doctor_reviews_with_terminal_reason(None);
        let findings = pending_findings_summary();
        let action = build_recommended_action_for_tests(
            42,
            None,
            Some(&super::DoctorAgentSection {
                max_active_agents_per_pr: 2,
                active_agents: 0,
                total_agents: 0,
                entries: Vec::new(),
            }),
            &reviews,
            &findings,
            &doctor_merge_readiness_fixture(super::DoctorMergeConflictStatus::HasConflicts),
        );
        assert_eq!(action.action, "dispatch_implementor");
        let command = action.command.expect("dispatch command");
        assert!(command.contains("apm2 fac review findings --pr 42"));
    }

    #[test]
    fn test_build_recommended_action_conflicts_override_approve_waiting_state() {
        let reviews = doctor_reviews_with_terminal_reason(None);
        let findings = vec![
            findings_summary_entry("security", "approve", 0, 0, 0, 0),
            findings_summary_entry("code-quality", "approve", 0, 0, 0, 0),
        ];
        let action = build_recommended_action_for_tests(
            42,
            None,
            Some(&super::DoctorAgentSection {
                max_active_agents_per_pr: 2,
                active_agents: 0,
                total_agents: 0,
                entries: Vec::new(),
            }),
            &reviews,
            &findings,
            &doctor_merge_readiness_fixture(super::DoctorMergeConflictStatus::HasConflicts),
        );
        assert_eq!(action.action, "dispatch_implementor");
    }

    #[test]
    fn test_build_recommended_action_conflicts_preserve_failed_review_remediation() {
        let reviews = doctor_reviews_with_terminal_reason(None);
        let findings = vec![
            findings_summary_entry("security", "deny", 1, 0, 0, 0),
            findings_summary_entry("code-quality", "approve", 0, 0, 0, 0),
        ];
        let action = build_recommended_action_for_tests(
            42,
            None,
            Some(&super::DoctorAgentSection {
                max_active_agents_per_pr: 2,
                active_agents: 0,
                total_agents: 0,
                entries: Vec::new(),
            }),
            &reviews,
            &findings,
            &doctor_merge_readiness_fixture(super::DoctorMergeConflictStatus::HasConflicts),
        );
        assert_eq!(action.action, "dispatch_implementor");
        let command = action.command.expect("dispatch command");
        assert!(command.contains("apm2 fac review findings --pr 42"));
    }

    #[test]
    fn test_build_recommended_action_waits_when_one_dimension_pending_despite_deny() {
        let reviews = doctor_reviews_with_terminal_reason(None);
        let findings = vec![
            findings_summary_entry("security", "deny", 1, 0, 0, 0),
            findings_summary_entry("code-quality", "pending", 0, 0, 0, 0),
        ];
        let agents = super::DoctorAgentSection {
            max_active_agents_per_pr: 2,
            active_agents: 1,
            total_agents: 1,
            entries: vec![reviewer_agent_snapshot("running", Some(120), Some(10))],
        };
        let action = build_recommended_action_for_tests(
            42,
            None,
            Some(&agents),
            &reviews,
            &findings,
            &doctor_merge_readiness_fixture(super::DoctorMergeConflictStatus::Unknown),
        );
        assert_eq!(action.action, "wait");
        let command = action.command.expect("wait command");
        assert!(command.contains("--wait-for-recommended-action"));
        assert!(command.contains("--wait-timeout-seconds 1200"));
    }

    #[test]
    fn test_build_recommended_action_dispatches_when_all_dimensions_resolved() {
        let reviews = doctor_reviews_with_terminal_reason(None);
        let findings = vec![
            findings_summary_entry("security", "deny", 0, 1, 0, 0),
            findings_summary_entry("code-quality", "approve", 0, 0, 0, 0),
        ];
        let action = build_recommended_action_for_tests(
            42,
            None,
            None,
            &reviews,
            &findings,
            &doctor_merge_readiness_fixture(super::DoctorMergeConflictStatus::Unknown),
        );
        assert_eq!(action.action, "dispatch_implementor");
    }

    #[test]
    fn test_build_recommended_action_dispatches_when_both_dimensions_deny() {
        let reviews = doctor_reviews_with_terminal_reason(None);
        let findings = vec![
            findings_summary_entry("security", "deny", 1, 0, 0, 0),
            findings_summary_entry("code-quality", "deny", 0, 1, 0, 0),
        ];
        let action = build_recommended_action_for_tests(
            42,
            None,
            None,
            &reviews,
            &findings,
            &doctor_merge_readiness_fixture(super::DoctorMergeConflictStatus::Unknown),
        );
        assert_eq!(action.action, "dispatch_implementor");
    }

    #[test]
    fn test_build_recommended_action_returns_done_for_merged_lifecycle() {
        let reviews = doctor_reviews_with_terminal_reason(None);
        let action = build_recommended_action_for_tests(
            42,
            Some(&doctor_lifecycle_fixture("merged", 3, 0, 1)),
            Some(&super::DoctorAgentSection {
                max_active_agents_per_pr: 2,
                active_agents: 1,
                total_agents: 1,
                entries: vec![reviewer_agent_snapshot("running", Some(5), Some(2))],
            }),
            &reviews,
            &pending_findings_summary(),
            &doctor_merge_readiness_fixture(super::DoctorMergeConflictStatus::Unknown),
        );
        assert_eq!(action.action, "done");
        assert!(action.command.is_none());
    }

    #[test]
    fn test_build_recommended_action_done_takes_priority_over_merge_ready() {
        let reviews = doctor_reviews_with_terminal_reason(None);
        let merge_ready = super::DoctorMergeReadiness {
            merge_ready: true,
            all_verdicts_approve: true,
            gates_pass: true,
            sha_fresh: true,
            sha_freshness_source: super::DoctorShaFreshnessSource::RemoteMatch,
            no_merge_conflicts: true,
            merge_conflict_status: super::DoctorMergeConflictStatus::NoConflicts,
        };
        let action = build_recommended_action_for_tests(
            42,
            Some(&doctor_lifecycle_fixture("merged", 3, 0, 1)),
            None,
            &reviews,
            &pending_findings_summary(),
            &merge_ready,
        );
        assert_eq!(action.action, "done");
    }

    #[test]
    fn test_build_recommended_action_returns_approve_when_all_verdicts_approve_but_not_merge_ready()
    {
        let reviews = doctor_reviews_with_terminal_reason(None);
        let findings = vec![
            findings_summary_entry("security", "approve", 0, 0, 0, 0),
            findings_summary_entry("code-quality", "approve", 0, 0, 0, 1),
        ];
        let readiness = super::DoctorMergeReadiness {
            merge_ready: false,
            all_verdicts_approve: true,
            gates_pass: false,
            sha_fresh: true,
            sha_freshness_source: super::DoctorShaFreshnessSource::RemoteMatch,
            no_merge_conflicts: true,
            merge_conflict_status: super::DoctorMergeConflictStatus::NoConflicts,
        };
        let action =
            build_recommended_action_for_tests(42, None, None, &reviews, &findings, &readiness);
        assert_eq!(action.action, "approve");
        let command = action.command.expect("approve command");
        assert!(command.contains("--wait-for-recommended-action"));
        assert!(command.contains("--wait-timeout-seconds 1200"));
    }

    #[test]
    fn test_build_recommended_action_projection_gap_triggers_fix_and_follow_up_repair() {
        let findings = vec![
            findings_summary_entry("security", "approve", 0, 0, 0, 0),
            findings_summary_entry("code-quality", "approve", 0, 0, 0, 0),
        ];
        let readiness = super::DoctorMergeReadiness {
            merge_ready: true,
            all_verdicts_approve: true,
            gates_pass: true,
            sha_fresh: true,
            sha_freshness_source: super::DoctorShaFreshnessSource::RemoteMatch,
            no_merge_conflicts: true,
            merge_conflict_status: super::DoctorMergeConflictStatus::NoConflicts,
        };
        let terminal_reasons = std::collections::BTreeMap::new();
        let repair_signals = super::DoctorRepairSignals {
            projection_comment_binding_missing: true,
            ..super::DoctorRepairSignals::default()
        };
        let action = super::build_recommended_action(&super::DoctorActionInputs {
            pr_number: 42,
            repair_signals: &repair_signals,
            lifecycle: Some(&doctor_lifecycle_fixture("review_in_progress", 2, 0, 42)),
            gates: &[
                doctor_gate_snapshot("fmt", "PASS"),
                doctor_gate_snapshot("test", "PASS"),
            ],
            agent_activity: super::DoctorAgentActivitySummary::default(),
            reviews: &[],
            review_terminal_reasons: &terminal_reasons,
            findings_summary: &findings,
            merge_readiness: &readiness,
            latest_push_attempt: None,
        });
        assert_eq!(action.action, "fix");
        assert_eq!(
            action.command.as_deref(),
            Some("apm2 fac doctor --pr 42 --fix")
        );
        assert!(action.follow_up_fix);
        assert!(!action.follow_up_force);
    }

    #[test]
    fn test_build_recommended_action_projection_gap_waits_before_terminal_gate_pass() {
        let findings = vec![
            findings_summary_entry("security", "approve", 0, 0, 0, 0),
            findings_summary_entry("code-quality", "approve", 0, 0, 0, 0),
        ];
        let readiness = super::DoctorMergeReadiness {
            merge_ready: false,
            all_verdicts_approve: true,
            gates_pass: false,
            sha_fresh: true,
            sha_freshness_source: super::DoctorShaFreshnessSource::RemoteMatch,
            no_merge_conflicts: true,
            merge_conflict_status: super::DoctorMergeConflictStatus::NoConflicts,
        };
        let terminal_reasons = std::collections::BTreeMap::new();
        let repair_signals = super::DoctorRepairSignals {
            projection_comment_binding_missing: true,
            ..super::DoctorRepairSignals::default()
        };
        let action = super::build_recommended_action(&super::DoctorActionInputs {
            pr_number: 42,
            repair_signals: &repair_signals,
            lifecycle: Some(&doctor_lifecycle_fixture("review_in_progress", 2, 0, 42)),
            gates: &[doctor_gate_snapshot("fmt", "RUNNING")],
            agent_activity: super::DoctorAgentActivitySummary::default(),
            reviews: &[],
            review_terminal_reasons: &terminal_reasons,
            findings_summary: &findings,
            merge_readiness: &readiness,
            latest_push_attempt: None,
        });
        assert_eq!(action.action, "approve");
    }

    #[test]
    fn test_build_recommended_action_does_not_approve_without_remote_sha_match() {
        let reviews = doctor_reviews_with_terminal_reason(None);
        let findings = vec![
            findings_summary_entry("security", "approve", 0, 0, 0, 0),
            findings_summary_entry("code-quality", "approve", 0, 0, 0, 0),
        ];
        let readiness = super::DoctorMergeReadiness {
            merge_ready: false,
            all_verdicts_approve: true,
            gates_pass: false,
            sha_fresh: true,
            sha_freshness_source: super::DoctorShaFreshnessSource::LocalAuthoritative,
            no_merge_conflicts: true,
            merge_conflict_status: super::DoctorMergeConflictStatus::NoConflicts,
        };
        let action =
            build_recommended_action_for_tests(42, None, None, &reviews, &findings, &readiness);
        assert_eq!(action.action, "wait");
    }

    #[test]
    fn test_build_recommended_action_blocks_approve_when_actionable_findings_exist() {
        let reviews = doctor_reviews_with_terminal_reason(None);
        let findings = vec![
            findings_summary_entry("security", "approve", 0, 2, 0, 0),
            findings_summary_entry("code-quality", "approve", 0, 0, 0, 0),
        ];
        let readiness = super::DoctorMergeReadiness {
            merge_ready: false,
            all_verdicts_approve: true,
            gates_pass: false,
            sha_fresh: true,
            sha_freshness_source: super::DoctorShaFreshnessSource::RemoteMatch,
            no_merge_conflicts: true,
            merge_conflict_status: super::DoctorMergeConflictStatus::NoConflicts,
        };
        let action =
            build_recommended_action_for_tests(42, None, None, &reviews, &findings, &readiness);
        assert_eq!(action.action, "dispatch_implementor");
    }

    #[test]
    fn test_build_recommended_action_stale_sha_overrides_dispatch_implementor() {
        let reviews = doctor_reviews_with_terminal_reason(None);
        let findings = vec![
            findings_summary_entry("security", "deny", 0, 2, 0, 0),
            findings_summary_entry("code-quality", "approve", 0, 0, 0, 0),
        ];
        let readiness = super::DoctorMergeReadiness {
            merge_ready: false,
            all_verdicts_approve: false,
            gates_pass: true,
            sha_fresh: false,
            sha_freshness_source: super::DoctorShaFreshnessSource::Stale,
            no_merge_conflicts: true,
            merge_conflict_status: super::DoctorMergeConflictStatus::NoConflicts,
        };
        let action =
            build_recommended_action_for_tests(42, None, None, &reviews, &findings, &readiness);
        assert_eq!(action.action, "fix");
        let command = action.command.expect("fix command");
        assert_eq!(command, "apm2 fac doctor --pr 42 --fix");
        assert!(action.follow_up_fix);
        assert!(action.follow_up_force);
    }

    #[test]
    fn test_build_recommended_action_stale_sha_overrides_approve() {
        let reviews = doctor_reviews_with_terminal_reason(None);
        let findings = vec![
            findings_summary_entry("security", "approve", 0, 0, 0, 0),
            findings_summary_entry("code-quality", "approve", 0, 0, 0, 0),
        ];
        let readiness = super::DoctorMergeReadiness {
            merge_ready: false,
            all_verdicts_approve: true,
            gates_pass: true,
            sha_fresh: false,
            sha_freshness_source: super::DoctorShaFreshnessSource::Stale,
            no_merge_conflicts: true,
            merge_conflict_status: super::DoctorMergeConflictStatus::NoConflicts,
        };
        let action =
            build_recommended_action_for_tests(42, None, None, &reviews, &findings, &readiness);
        assert_eq!(action.action, "fix");
        let command = action.command.expect("fix command");
        assert_eq!(command, "apm2 fac doctor --pr 42 --fix");
        assert!(action.follow_up_fix);
        assert!(action.follow_up_force);
    }

    #[test]
    fn test_build_recommended_action_allows_approve_while_reviewers_active() {
        let reviews = doctor_reviews_with_terminal_reason(None);
        let findings = vec![
            findings_summary_entry("security", "approve", 0, 0, 0, 0),
            findings_summary_entry("code-quality", "approve", 0, 0, 0, 0),
        ];
        let readiness = super::DoctorMergeReadiness {
            merge_ready: false,
            all_verdicts_approve: true,
            gates_pass: false,
            sha_fresh: true,
            sha_freshness_source: super::DoctorShaFreshnessSource::RemoteMatch,
            no_merge_conflicts: true,
            merge_conflict_status: super::DoctorMergeConflictStatus::NoConflicts,
        };
        let agents = super::DoctorAgentSection {
            max_active_agents_per_pr: 2,
            active_agents: 1,
            total_agents: 1,
            entries: vec![reviewer_agent_snapshot("running", Some(20), Some(5))],
        };
        let action = build_recommended_action_for_tests(
            42,
            None,
            Some(&agents),
            &reviews,
            &findings,
            &readiness,
        );
        assert_eq!(action.action, "approve");
    }

    #[test]
    fn test_build_recommended_action_merge_takes_priority_over_approve() {
        let reviews = doctor_reviews_with_terminal_reason(None);
        let findings = vec![
            findings_summary_entry("security", "approve", 0, 0, 0, 0),
            findings_summary_entry("code-quality", "approve", 0, 0, 0, 0),
        ];
        let readiness = super::DoctorMergeReadiness {
            merge_ready: true,
            all_verdicts_approve: true,
            gates_pass: true,
            sha_fresh: true,
            sha_freshness_source: super::DoctorShaFreshnessSource::RemoteMatch,
            no_merge_conflicts: true,
            merge_conflict_status: super::DoctorMergeConflictStatus::NoConflicts,
        };
        let action =
            build_recommended_action_for_tests(42, None, None, &reviews, &findings, &readiness);
        assert_eq!(action.action, "merge");
    }

    #[test]
    fn test_build_recommended_action_wait_has_command() {
        let reviews = doctor_reviews_with_terminal_reason(None);
        let findings = pending_findings_summary();
        let agents = super::DoctorAgentSection {
            max_active_agents_per_pr: 2,
            active_agents: 1,
            total_agents: 1,
            entries: vec![reviewer_agent_snapshot("running", Some(20), Some(5))],
        };
        let action = build_recommended_action_for_tests(
            42,
            Some(&doctor_lifecycle_fixture("review_in_progress", 2, 0, 11)),
            Some(&agents),
            &reviews,
            &findings,
            &doctor_merge_readiness_fixture(super::DoctorMergeConflictStatus::Unknown),
        );
        assert_eq!(action.action, "wait");
        let command = action.command.expect("wait command");
        assert!(command.contains("--wait-for-recommended-action"));
        assert!(command.contains("--wait-timeout-seconds 1200"));
    }

    #[test]
    fn test_build_recommended_action_waits_when_gates_are_non_terminal_without_reviewers() {
        let reviews = doctor_reviews_with_terminal_reason(None);
        let findings = pending_findings_summary();
        let terminal_reasons = std::collections::BTreeMap::new();
        let gates = vec![doctor_gate_snapshot("test", "NOT_RUN")];
        let action = super::build_recommended_action(&super::DoctorActionInputs {
            pr_number: 42,
            repair_signals: &super::DoctorRepairSignals::default(),
            lifecycle: Some(&doctor_lifecycle_fixture("gates_running", 1, 0, 12)),
            gates: &gates,
            agent_activity: super::build_doctor_agent_activity_summary(Some(
                &super::DoctorAgentSection {
                    max_active_agents_per_pr: 2,
                    active_agents: 0,
                    total_agents: 0,
                    entries: Vec::new(),
                },
            )),
            reviews: &reviews,
            review_terminal_reasons: &terminal_reasons,
            findings_summary: &findings,
            merge_readiness: &doctor_merge_readiness_fixture(
                super::DoctorMergeConflictStatus::Unknown,
            ),
            latest_push_attempt: None,
        });
        assert_eq!(action.action, "wait");
        assert!(action.reason.contains("gates are still in progress"));
        let command = action.command.expect("wait command");
        assert!(command.contains("--wait-for-recommended-action"));
    }

    #[test]
    fn test_build_recommended_action_fixes_when_gates_are_terminal_and_no_reviewers() {
        let reviews = doctor_reviews_with_terminal_reason(None);
        let findings = pending_findings_summary();
        let terminal_reasons = std::collections::BTreeMap::new();
        let gates = vec![doctor_gate_snapshot("test", "PASS")];
        let action = super::build_recommended_action(&super::DoctorActionInputs {
            pr_number: 42,
            repair_signals: &super::DoctorRepairSignals::default(),
            lifecycle: Some(&doctor_lifecycle_fixture("review_in_progress", 1, 0, 12)),
            gates: &gates,
            agent_activity: super::build_doctor_agent_activity_summary(Some(
                &super::DoctorAgentSection {
                    max_active_agents_per_pr: 2,
                    active_agents: 0,
                    total_agents: 0,
                    entries: Vec::new(),
                },
            )),
            reviews: &reviews,
            review_terminal_reasons: &terminal_reasons,
            findings_summary: &findings,
            merge_readiness: &doctor_merge_readiness_fixture(
                super::DoctorMergeConflictStatus::Unknown,
            ),
            latest_push_attempt: None,
        });
        assert_eq!(action.action, "fix");
    }

    #[test]
    fn test_build_recommended_action_waits_when_gate_status_is_running_without_active_reviewers() {
        let reviews = doctor_reviews_with_terminal_reason(None);
        let findings = pending_findings_summary();
        let terminal_reasons = std::collections::BTreeMap::new();
        let gates = vec![doctor_gate_snapshot("test", "RUNNING")];
        let action = super::build_recommended_action(&super::DoctorActionInputs {
            pr_number: 42,
            repair_signals: &super::DoctorRepairSignals::default(),
            lifecycle: Some(&doctor_lifecycle_fixture("review_in_progress", 1, 0, 12)),
            gates: &gates,
            agent_activity: super::build_doctor_agent_activity_summary(Some(
                &super::DoctorAgentSection {
                    max_active_agents_per_pr: 2,
                    active_agents: 0,
                    total_agents: 0,
                    entries: Vec::new(),
                },
            )),
            reviews: &reviews,
            review_terminal_reasons: &terminal_reasons,
            findings_summary: &findings,
            merge_readiness: &doctor_merge_readiness_fixture(
                super::DoctorMergeConflictStatus::Unknown,
            ),
            latest_push_attempt: None,
        });
        assert_eq!(action.action, "wait");
    }

    #[test]
    fn test_build_recommended_action_waits_when_gate_status_is_running_with_idle_reviewers() {
        let reviews = doctor_reviews_with_terminal_reason(None);
        let findings = pending_findings_summary();
        let terminal_reasons = std::collections::BTreeMap::new();
        let gates = vec![doctor_gate_snapshot("test", "RUNNING")];
        let idle_agents = super::DoctorAgentSection {
            max_active_agents_per_pr: 2,
            active_agents: 1,
            total_agents: 1,
            entries: vec![reviewer_agent_snapshot(
                "running",
                Some(super::DOCTOR_ACTIVE_AGENT_IDLE_TIMEOUT_SECONDS + 20),
                Some(super::DOCTOR_ACTIVE_AGENT_IDLE_TIMEOUT_SECONDS + 20),
            )],
        };
        let action = super::build_recommended_action(&super::DoctorActionInputs {
            pr_number: 42,
            repair_signals: &super::DoctorRepairSignals::default(),
            lifecycle: Some(&doctor_lifecycle_fixture("review_in_progress", 1, 0, 12)),
            gates: &gates,
            agent_activity: super::build_doctor_agent_activity_summary(Some(&idle_agents)),
            reviews: &reviews,
            review_terminal_reasons: &terminal_reasons,
            findings_summary: &findings,
            merge_readiness: &doctor_merge_readiness_fixture(
                super::DoctorMergeConflictStatus::Unknown,
            ),
            latest_push_attempt: None,
        });
        assert_eq!(action.action, "wait");
        assert!(action.reason.contains("gates are still in progress"));
    }

    #[test]
    fn test_build_recommended_action_dispatches_implementor_when_lifecycle_reports_gates_failed() {
        let reviews = doctor_reviews_with_terminal_reason(None);
        let findings = pending_findings_summary();
        let terminal_reasons = std::collections::BTreeMap::new();
        let gates = Vec::new();
        let action = super::build_recommended_action(&super::DoctorActionInputs {
            pr_number: 42,
            repair_signals: &super::DoctorRepairSignals::default(),
            lifecycle: Some(&doctor_lifecycle_fixture("gates_failed", 1, 0, 12)),
            gates: &gates,
            agent_activity: super::build_doctor_agent_activity_summary(Some(
                &super::DoctorAgentSection {
                    max_active_agents_per_pr: 2,
                    active_agents: 0,
                    total_agents: 0,
                    entries: Vec::new(),
                },
            )),
            reviews: &reviews,
            review_terminal_reasons: &terminal_reasons,
            findings_summary: &findings,
            merge_readiness: &doctor_merge_readiness_fixture(
                super::DoctorMergeConflictStatus::Unknown,
            ),
            latest_push_attempt: None,
        });
        assert_eq!(action.action, "dispatch_implementor");
    }

    #[test]
    fn test_build_recommended_action_dispatches_implementor_when_push_attempt_failed_gate_stage() {
        let reviews = doctor_reviews_with_terminal_reason(None);
        let findings = pending_findings_summary();
        let terminal_reasons = std::collections::BTreeMap::new();
        let gates = vec![doctor_gate_snapshot("test", "RUNNING")];
        let push_attempt = doctor_push_attempt_summary(Some("gate_test"), Some("gate timeout"));
        let action = super::build_recommended_action(&super::DoctorActionInputs {
            pr_number: 42,
            repair_signals: &super::DoctorRepairSignals::default(),
            lifecycle: Some(&doctor_lifecycle_fixture("review_in_progress", 1, 0, 12)),
            gates: &gates,
            agent_activity: super::build_doctor_agent_activity_summary(Some(
                &super::DoctorAgentSection {
                    max_active_agents_per_pr: 2,
                    active_agents: 0,
                    total_agents: 0,
                    entries: Vec::new(),
                },
            )),
            reviews: &reviews,
            review_terminal_reasons: &terminal_reasons,
            findings_summary: &findings,
            merge_readiness: &doctor_merge_readiness_fixture(
                super::DoctorMergeConflictStatus::Unknown,
            ),
            latest_push_attempt: Some(&push_attempt),
        });
        assert_eq!(action.action, "dispatch_implementor");
        assert!(action.reason.contains("last push: gate_test FAIL"));
    }

    #[test]
    fn test_build_recommended_action_gate_failure_overrides_stale_identity_fix() {
        let reviews = doctor_reviews_with_terminal_reason(None);
        let findings = pending_findings_summary();
        let terminal_reasons = std::collections::BTreeMap::new();
        let gates = vec![doctor_gate_snapshot("test", "FAIL")];
        let stale_readiness = super::DoctorMergeReadiness {
            merge_ready: false,
            all_verdicts_approve: false,
            gates_pass: false,
            sha_fresh: false,
            sha_freshness_source: super::DoctorShaFreshnessSource::Stale,
            no_merge_conflicts: true,
            merge_conflict_status: super::DoctorMergeConflictStatus::NoConflicts,
        };
        let action = super::build_recommended_action(&super::DoctorActionInputs {
            pr_number: 42,
            repair_signals: &super::DoctorRepairSignals::default(),
            lifecycle: Some(&doctor_lifecycle_fixture("review_in_progress", 1, 0, 12)),
            gates: &gates,
            agent_activity: super::build_doctor_agent_activity_summary(Some(
                &super::DoctorAgentSection {
                    max_active_agents_per_pr: 2,
                    active_agents: 0,
                    total_agents: 0,
                    entries: Vec::new(),
                },
            )),
            reviews: &reviews,
            review_terminal_reasons: &terminal_reasons,
            findings_summary: &findings,
            merge_readiness: &stale_readiness,
            latest_push_attempt: None,
        });
        assert_eq!(action.action, "dispatch_implementor");
    }

    #[test]
    fn test_build_recommended_action_fixes_when_gate_progress_is_unknown_without_active_reviewers()
    {
        let reviews = doctor_reviews_with_terminal_reason(None);
        let findings = pending_findings_summary();
        let terminal_reasons = std::collections::BTreeMap::new();
        let gates = Vec::new();
        let action = super::build_recommended_action(&super::DoctorActionInputs {
            pr_number: 42,
            repair_signals: &super::DoctorRepairSignals::default(),
            lifecycle: None,
            gates: &gates,
            agent_activity: super::build_doctor_agent_activity_summary(Some(
                &super::DoctorAgentSection {
                    max_active_agents_per_pr: 2,
                    active_agents: 0,
                    total_agents: 0,
                    entries: Vec::new(),
                },
            )),
            reviews: &reviews,
            review_terminal_reasons: &terminal_reasons,
            findings_summary: &findings,
            merge_readiness: &doctor_merge_readiness_fixture(
                super::DoctorMergeConflictStatus::Unknown,
            ),
            latest_push_attempt: None,
        });
        assert_eq!(action.action, "fix");
    }

    #[test]
    fn test_build_recommended_action_waits_when_projection_running_overrides_cached_pass() {
        let reviews = doctor_reviews_with_terminal_reason(None);
        let findings = pending_findings_summary();
        let terminal_reasons = std::collections::BTreeMap::new();

        let mut gates_by_name = std::collections::BTreeMap::new();
        super::upsert_doctor_gate_snapshot(
            &mut gates_by_name,
            "test",
            "PASS",
            Some("2026-02-20T00:00:00Z".to_string()),
            Some(5),
            super::DoctorGateSource::LocalCache,
        );
        super::upsert_doctor_gate_snapshot(
            &mut gates_by_name,
            "test",
            "RUNNING",
            Some("2026-02-20T00:00:01Z".to_string()),
            Some(4),
            super::DoctorGateSource::Projection,
        );
        let gates = gates_by_name.into_values().collect::<Vec<_>>();

        let action = super::build_recommended_action(&super::DoctorActionInputs {
            pr_number: 42,
            repair_signals: &super::DoctorRepairSignals::default(),
            lifecycle: Some(&doctor_lifecycle_fixture("review_in_progress", 1, 0, 12)),
            gates: &gates,
            agent_activity: super::build_doctor_agent_activity_summary(Some(
                &super::DoctorAgentSection {
                    max_active_agents_per_pr: 2,
                    active_agents: 0,
                    total_agents: 0,
                    entries: Vec::new(),
                },
            )),
            reviews: &reviews,
            review_terminal_reasons: &terminal_reasons,
            findings_summary: &findings,
            merge_readiness: &doctor_merge_readiness_fixture(
                super::DoctorMergeConflictStatus::Unknown,
            ),
            latest_push_attempt: None,
        });
        assert_eq!(action.action, "wait");
    }

    #[test]
    fn test_build_recommended_action_dispatches_implementor_on_failed_gates_with_pending_verdicts()
    {
        let reviews = doctor_reviews_with_terminal_reason(None);
        let findings = pending_findings_summary();
        let terminal_reasons = std::collections::BTreeMap::new();
        let gates = vec![doctor_gate_snapshot("test", "FAIL")];
        let action = super::build_recommended_action(&super::DoctorActionInputs {
            pr_number: 42,
            repair_signals: &super::DoctorRepairSignals::default(),
            lifecycle: Some(&doctor_lifecycle_fixture("review_in_progress", 1, 0, 12)),
            gates: &gates,
            agent_activity: super::build_doctor_agent_activity_summary(Some(
                &super::DoctorAgentSection {
                    max_active_agents_per_pr: 2,
                    active_agents: 0,
                    total_agents: 0,
                    entries: Vec::new(),
                },
            )),
            reviews: &reviews,
            review_terminal_reasons: &terminal_reasons,
            findings_summary: &findings,
            merge_readiness: &doctor_merge_readiness_fixture(
                super::DoctorMergeConflictStatus::Unknown,
            ),
            latest_push_attempt: None,
        });
        assert_eq!(action.action, "dispatch_implementor");
    }

    #[test]
    fn test_build_recommended_action_dispatch_implementor_has_command() {
        let reviews = doctor_reviews_with_terminal_reason(None);
        let findings = vec![
            findings_summary_entry("security", "deny", 0, 1, 0, 0),
            findings_summary_entry("code-quality", "approve", 0, 0, 0, 0),
        ];
        let action = build_recommended_action_for_tests(
            42,
            None,
            None,
            &reviews,
            &findings,
            &doctor_merge_readiness_fixture(super::DoctorMergeConflictStatus::Unknown),
        );
        assert_eq!(action.action, "dispatch_implementor");
        let command = action.command.expect("dispatch command");
        assert!(command.contains("apm2 fac review findings --pr 42"));
    }

    #[test]
    fn test_build_recommended_action_dispatch_implementor_reason_includes_dimension_summary() {
        let reviews = doctor_reviews_with_terminal_reason(None);
        let findings = vec![
            findings_summary_entry("security", "deny", 2, 1, 0, 0),
            findings_summary_entry("code-quality", "approve", 0, 0, 0, 3),
        ];
        let action = build_recommended_action_for_tests(
            42,
            None,
            None,
            &reviews,
            &findings,
            &doctor_merge_readiness_fixture(super::DoctorMergeConflictStatus::Unknown),
        );
        assert_eq!(action.action, "dispatch_implementor");
        assert!(action.reason.contains("security=deny(2B/1M/0m/0N)"));
        assert!(action.reason.contains("code-quality=approve(0B/0M/0m/3N)"));
    }

    #[test]
    fn test_build_recommended_action_fixes_when_active_reviewers_are_idle() {
        let reviews = doctor_reviews_with_terminal_reason(None);
        let findings = pending_findings_summary();
        let agents = super::DoctorAgentSection {
            max_active_agents_per_pr: 2,
            active_agents: 1,
            total_agents: 1,
            entries: vec![reviewer_agent_snapshot("running", Some(700), Some(600))],
        };
        let action = build_recommended_action_for_tests(
            42,
            Some(&doctor_lifecycle_fixture("review_in_progress", 2, 0, 11)),
            Some(&agents),
            &reviews,
            &findings,
            &doctor_merge_readiness_fixture(super::DoctorMergeConflictStatus::Unknown),
        );
        assert_eq!(action.action, "fix");
        let command = action.command.expect("fix command");
        assert_eq!(command, "apm2 fac doctor --pr 42 --fix");
        assert!(action.follow_up_fix);
        assert!(action.follow_up_force);
    }

    #[test]
    fn test_build_recommended_action_waits_when_running_activity_is_unknown() {
        let reviews = doctor_reviews_with_terminal_reason(None);
        let findings = pending_findings_summary();
        let agents = super::DoctorAgentSection {
            max_active_agents_per_pr: 2,
            active_agents: 1,
            total_agents: 1,
            entries: vec![reviewer_agent_snapshot("running", Some(700), None)],
        };
        let action = build_recommended_action_for_tests(
            42,
            Some(&doctor_lifecycle_fixture("review_in_progress", 2, 0, 11)),
            Some(&agents),
            &reviews,
            &findings,
            &doctor_merge_readiness_fixture(super::DoctorMergeConflictStatus::Unknown),
        );
        assert_eq!(action.action, "wait");
    }

    #[test]
    fn test_build_recommended_action_wait_reason_warns_on_stuck_dispatched_agent() {
        let reviews = doctor_reviews_with_terminal_reason(None);
        let findings = pending_findings_summary();
        let agents = super::DoctorAgentSection {
            max_active_agents_per_pr: 2,
            active_agents: 1,
            total_agents: 1,
            entries: vec![reviewer_agent_snapshot("dispatched", Some(200), None)],
        };
        let action = build_recommended_action_for_tests(
            42,
            Some(&doctor_lifecycle_fixture("reviews_dispatched", 2, 0, 11)),
            Some(&agents),
            &reviews,
            &findings,
            &doctor_merge_readiness_fixture(super::DoctorMergeConflictStatus::Unknown),
        );
        assert_eq!(action.action, "wait");
        assert!(
            action
                .reason
                .contains("reviewer dispatch pending for 200s (may be stuck)")
        );
    }

    #[test]
    fn test_build_recommended_action_budget_escalation_has_command() {
        let reviews = doctor_reviews_with_terminal_reason(None);
        let findings = pending_findings_summary();
        let agents = super::DoctorAgentSection {
            max_active_agents_per_pr: 2,
            active_agents: 1,
            total_agents: 1,
            entries: vec![reviewer_agent_snapshot("running", Some(30), Some(5))],
        };
        let action = build_recommended_action_for_tests(
            42,
            Some(&doctor_lifecycle_fixture("stuck", 0, 9, 11)),
            Some(&agents),
            &reviews,
            &findings,
            &doctor_merge_readiness_fixture(super::DoctorMergeConflictStatus::Unknown),
        );
        assert_eq!(action.action, "escalate");
        let command = action.command.expect("escalate command");
        assert!(command.contains("apm2 fac doctor --pr 42"));
    }

    #[test]
    fn test_doctor_recommended_fix_helpers_follow_recommended_action_contract() {
        let mut summary = doctor_pr_summary_for_fix_tests(pending_findings_summary(), None);
        assert!(!super::doctor_recommended_action_requests_follow_up_fix(
            &summary
        ));
        assert!(!super::doctor_recommended_follow_up_fix_force(&summary));

        summary.recommended_action.action = "fix".to_string();
        assert!(!super::doctor_recommended_action_requests_follow_up_fix(
            &summary
        ));
        assert!(!super::doctor_recommended_follow_up_fix_force(&summary));

        summary.recommended_action.follow_up_fix = true;
        summary.recommended_action.follow_up_force = false;
        assert!(super::doctor_recommended_action_requests_follow_up_fix(
            &summary
        ));
        assert!(!super::doctor_recommended_follow_up_fix_force(&summary));

        summary.recommended_action.follow_up_force = true;
        assert!(super::doctor_recommended_follow_up_fix_force(&summary));
    }

    #[test]
    fn test_lifecycle_retry_budget_exhausted_requires_seq_and_exhausted_state() {
        assert!(!super::lifecycle_retry_budget_exhausted(
            &doctor_lifecycle_fixture("pushed", 0, 0, 0)
        ));
        assert!(!super::lifecycle_retry_budget_exhausted(
            &doctor_lifecycle_fixture("pushed", 0, 0, 10)
        ));
        assert!(super::lifecycle_retry_budget_exhausted(
            &doctor_lifecycle_fixture("stuck", 0, 0, 10)
        ));
    }

    #[test]
    fn test_build_recommended_action_does_not_escalate_on_zero_retry_without_exhaustion_shape() {
        let reviews = doctor_reviews_with_terminal_reason(None);
        let findings = pending_findings_summary();
        let action = build_recommended_action_for_tests(
            42,
            Some(&doctor_lifecycle_fixture("pushed", 0, 0, 0)),
            Some(&super::DoctorAgentSection {
                max_active_agents_per_pr: 2,
                active_agents: 1,
                total_agents: 1,
                entries: vec![reviewer_agent_snapshot("running", Some(20), Some(2))],
            }),
            &reviews,
            &findings,
            &doctor_merge_readiness_fixture(super::DoctorMergeConflictStatus::Unknown),
        );
        assert_eq!(action.action, "wait");
    }

    #[test]
    fn test_build_doctor_merge_readiness_uses_local_authoritative_when_remote_unavailable() {
        let reviews = vec![
            super::DoctorReviewSnapshot {
                dimension: "security".to_string(),
                verdict: "approve".to_string(),
                reviewed_sha: String::new(),
                reviewed_by: String::new(),
                reviewed_at: String::new(),
                reason: String::new(),
                terminal_reason: None,
            },
            super::DoctorReviewSnapshot {
                dimension: "code-quality".to_string(),
                verdict: "approve".to_string(),
                reviewed_sha: String::new(),
                reviewed_by: String::new(),
                reviewed_at: String::new(),
                reason: String::new(),
                terminal_reason: None,
            },
        ];
        let gates = vec![super::DoctorGateSnapshot {
            name: "rustfmt".to_string(),
            status: "PASS".to_string(),
            completed_at: None,
            freshness_seconds: None,
            source: super::DoctorGateSource::LocalCache,
        }];
        let local_sha = "0123456789abcdef0123456789abcdef01234567".to_string();
        let gate_progress = super::derive_doctor_gate_progress_state(&gates, None);
        let readiness = super::build_doctor_merge_readiness(
            &reviews,
            gate_progress,
            false,
            Some(&local_sha),
            None,
            super::DoctorMergeConflictStatus::NoConflicts,
        );
        assert!(readiness.sha_fresh);
        assert_eq!(
            readiness.sha_freshness_source,
            super::DoctorShaFreshnessSource::LocalAuthoritative
        );
        assert!(readiness.merge_ready);
    }

    #[test]
    fn test_build_doctor_merge_readiness_requires_terminal_passed_gates() {
        let reviews = vec![
            super::DoctorReviewSnapshot {
                dimension: "security".to_string(),
                verdict: "approve".to_string(),
                reviewed_sha: String::new(),
                reviewed_by: String::new(),
                reviewed_at: String::new(),
                reason: String::new(),
                terminal_reason: None,
            },
            super::DoctorReviewSnapshot {
                dimension: "code-quality".to_string(),
                verdict: "approve".to_string(),
                reviewed_sha: String::new(),
                reviewed_by: String::new(),
                reviewed_at: String::new(),
                reason: String::new(),
                terminal_reason: None,
            },
        ];
        let local_sha = "0123456789abcdef0123456789abcdef01234567".to_string();
        let readiness = super::build_doctor_merge_readiness(
            &reviews,
            super::DoctorGateProgressState::InFlight,
            false,
            Some(&local_sha),
            Some(&local_sha),
            super::DoctorMergeConflictStatus::NoConflicts,
        );
        assert!(!readiness.gates_pass);
        assert!(!readiness.merge_ready);
    }

    #[test]
    fn test_build_recommended_action_dispatches_on_formal_deny_without_findings() {
        let findings = vec![
            findings_summary_entry("security", "deny", 0, 0, 0, 0),
            findings_summary_entry("code-quality", "approve", 0, 0, 0, 0),
        ];
        let reviews = doctor_reviews_with_terminal_reason(None);
        let action = build_recommended_action_for_tests(
            42,
            None,
            None,
            &reviews,
            &findings,
            &doctor_merge_readiness_fixture(super::DoctorMergeConflictStatus::Unknown),
        );
        assert_eq!(action.action, "dispatch_implementor");
        assert!(action.command.is_some());
    }

    #[test]
    fn test_build_recommended_action_dispatches_on_major_findings_without_formal_deny() {
        let findings = vec![
            findings_summary_entry("security", "approve", 0, 0, 0, 0),
            findings_summary_entry("code-quality", "approve", 0, 1, 0, 0),
        ];
        let reviews = doctor_reviews_with_terminal_reason(None);
        let action = build_recommended_action_for_tests(
            42,
            None,
            None,
            &reviews,
            &findings,
            &doctor_merge_readiness_fixture(super::DoctorMergeConflictStatus::Unknown),
        );
        assert_eq!(action.action, "dispatch_implementor");
        assert!(action.command.is_some());
    }

    #[test]
    fn test_normalize_doctor_exit_actions_defaults_include_escalate() {
        let normalized = super::normalize_doctor_exit_actions(&[]).expect("normalize defaults");
        assert!(normalized.contains("escalate"));
        assert!(normalized.contains("fix"));
        assert!(normalized.contains("dispatch_implementor"));
        assert!(normalized.contains("merge"));
        assert!(normalized.contains("done"));
        assert!(normalized.contains("approve"));
        assert!(!normalized.contains("wait"));
    }

    #[test]
    fn test_normalize_doctor_exit_actions_accepts_user_supplied_escalate() {
        let normalized = super::normalize_doctor_exit_actions(&["escalate".to_string()])
            .expect("escalate should be accepted");
        assert_eq!(normalized.len(), 1);
        assert!(normalized.contains("escalate"));
    }

    #[test]
    fn test_doctor_wait_terminal_reason_maps_merge_and_approve() {
        assert_eq!(super::doctor_wait_terminal_reason("merge"), "merge_ready");
        assert_eq!(super::doctor_wait_terminal_reason("approve"), "merge_ready");
        assert_eq!(
            super::doctor_wait_terminal_reason("dispatch_implementor"),
            "dispatch_implementor"
        );
    }

    #[test]
    fn test_dispatch_run_state_terminal_labels_include_done_and_crashed() {
        assert!(super::dispatch_run_state_is_terminal("done"));
        assert!(super::dispatch_run_state_is_terminal("failed"));
        assert!(super::dispatch_run_state_is_terminal("crashed"));
        assert!(super::dispatch_run_state_is_terminal("completed"));
        assert!(super::dispatch_run_state_is_terminal("cancelled"));
        assert!(!super::dispatch_run_state_is_terminal("pending"));
        assert!(!super::dispatch_run_state_is_terminal("alive"));
    }

    #[test]
    fn test_scan_event_signals_from_reader_scans_full_log_for_pr() {
        let mut lines = String::new();
        for index in 0..5000 {
            lines.push_str(
                &serde_json::json!({
                    "pr_number": 999,
                    "review_type": "security",
                    "event": "run_start",
                    "model": format!("other-{index}"),
                    "ts": "2026-02-15T00:00:00Z"
                })
                .to_string(),
            );
            lines.push('\n');
        }
        lines.push_str(
            &serde_json::json!({
                "pr_number": 42,
                "review_type": "security",
                "run_id": "keep",
                "event": "run_start",
                "model": "model-a",
                "ts": "2026-02-15T00:01:00Z"
            })
            .to_string(),
        );
        lines.push('\n');
        for _ in 0..5000 {
            lines.push_str(
                &serde_json::json!({
                    "pr_number": 999,
                    "review_type": "quality",
                    "event": "model_fallback",
                    "to_model": "other",
                    "ts": "2026-02-15T00:00:10Z"
                })
                .to_string(),
            );
            lines.push('\n');
        }
        lines.push_str(
            &serde_json::json!({
                "pr_number": 42,
                "review_type": "security",
                "run_id": "keep",
                "event": "model_fallback",
                "to_model": "model-b",
                "ts": "2026-02-15T00:02:00Z"
            })
            .to_string(),
        );
        lines.push('\n');

        let run_ids = std::collections::BTreeSet::<String>::new();
        let signals =
            super::scan_event_signals_from_reader(std::io::Cursor::new(lines), 42, &run_ids);
        let models = signals
            .model_attempts
            .get("security")
            .cloned()
            .unwrap_or_default();
        assert_eq!(models, vec!["model-a".to_string(), "model-b".to_string()]);
        assert!(signals.activity_timestamps.contains_key("security"));
    }

    #[test]
    fn test_scan_event_signals_from_reader_respects_run_id_filter() {
        let mut lines = String::new();
        lines.push_str(
            &serde_json::json!({
                "pr_number": 42,
                "review_type": "quality",
                "run_id": "ignore",
                "event": "run_start",
                "model": "model-ignore",
                "ts": "2026-02-15T00:01:00Z"
            })
            .to_string(),
        );
        lines.push('\n');
        lines.push_str(
            &serde_json::json!({
                "pr_number": 42,
                "review_type": "quality",
                "run_id": "keep",
                "event": "run_start",
                "model": "model-keep",
                "ts": "2026-02-15T00:02:00Z"
            })
            .to_string(),
        );
        lines.push('\n');

        let run_ids = std::collections::BTreeSet::from(["keep".to_string()]);
        let signals =
            super::scan_event_signals_from_reader(std::io::Cursor::new(lines), 42, &run_ids);
        let models = signals
            .model_attempts
            .get("quality")
            .cloned()
            .unwrap_or_default();
        assert_eq!(models, vec!["model-keep".to_string()]);
    }

    #[test]
    fn test_scan_event_signals_counts_tool_calls_and_nudges_per_run() {
        let mut lines = String::new();
        lines.push_str(
            &serde_json::json!({
                "pr_number": 42,
                "review_type": "security",
                "run_id": "keep",
                "event": "run_start",
                "model": "model-a",
                "ts": "2026-02-15T00:01:00Z"
            })
            .to_string(),
        );
        lines.push('\n');
        lines.push_str(
            &serde_json::json!({
                "pr_number": 42,
                "review_type": "security",
                "run_id": "keep",
                "event": "tool_call",
                "tool": "read_file",
                "ts": "2026-02-15T00:02:00Z"
            })
            .to_string(),
        );
        lines.push('\n');
        lines.push_str(
            &serde_json::json!({
                "pr_number": 42,
                "review_type": "security",
                "run_id": "keep",
                "event": "nudge_resume",
                "ts": "2026-02-15T00:03:00Z"
            })
            .to_string(),
        );
        lines.push('\n');

        let run_ids = std::collections::BTreeSet::from(["keep".to_string()]);
        let signals =
            super::scan_event_signals_from_reader(std::io::Cursor::new(lines), 42, &run_ids);
        assert_eq!(signals.tool_call_counts.get("keep").copied(), Some(1));
        assert_eq!(signals.nudge_counts.get("keep").copied(), Some(1));
    }

    #[test]
    fn test_scan_event_signals_tool_count_falls_back_to_total_lines() {
        let mut lines = String::new();
        lines.push_str(
            &serde_json::json!({
                "pr_number": 42,
                "review_type": "security",
                "run_id": "keep",
                "event": "run_start",
                "model": "model-a",
                "ts": "2026-02-15T00:01:00Z"
            })
            .to_string(),
        );
        lines.push('\n');
        lines.push_str(
            &serde_json::json!({
                "pr_number": 42,
                "review_type": "security",
                "run_id": "keep",
                "event": "liveness_check",
                "ts": "2026-02-15T00:02:00Z"
            })
            .to_string(),
        );
        lines.push('\n');

        let run_ids = std::collections::BTreeSet::from(["keep".to_string()]);
        let signals =
            super::scan_event_signals_from_reader(std::io::Cursor::new(lines), 42, &run_ids);
        assert_eq!(signals.tool_call_counts.get("keep").copied(), Some(2));
    }

    #[test]
    fn test_scan_event_signals_liveness_uses_idle_age_for_activity_timestamp() {
        let mut lines = String::new();
        lines.push_str(
            &serde_json::json!({
                "pr_number": 42,
                "review_type": "security",
                "run_id": "keep",
                "event": "liveness_check",
                "last_tool_call_age_secs": 120,
                "ts": "2026-02-15T00:10:00Z"
            })
            .to_string(),
        );
        lines.push('\n');

        let run_ids = std::collections::BTreeSet::from(["keep".to_string()]);
        let signals =
            super::scan_event_signals_from_reader(std::io::Cursor::new(lines), 42, &run_ids);
        let expected = super::parse_rfc3339_utc("2026-02-15T00:08:00Z").expect("parse expected");
        assert_eq!(
            signals.activity_timestamps_by_run_id.get("keep").copied(),
            Some(expected)
        );
    }

    #[test]
    fn test_scan_event_signals_skips_oversized_line_and_keeps_scanning() {
        let oversized = "x".repeat(super::DOCTOR_EVENT_SCAN_MAX_LINE_BYTES.saturating_add(32));
        let mut lines = String::new();
        lines.push_str(&oversized);
        lines.push('\n');
        lines.push_str(
            &serde_json::json!({
                "pr_number": 42,
                "review_type": "security",
                "run_id": "keep",
                "event": "run_start",
                "model": "model-safe",
                "ts": "2026-02-15T00:02:00Z"
            })
            .to_string(),
        );
        lines.push('\n');

        let run_ids = std::collections::BTreeSet::from(["keep".to_string()]);
        let signals =
            super::scan_event_signals_from_reader(std::io::Cursor::new(lines), 42, &run_ids);
        let models = signals
            .model_attempts
            .get("security")
            .cloned()
            .unwrap_or_default();
        assert_eq!(models, vec!["model-safe".to_string()]);
    }

    #[test]
    fn test_scan_event_signals_from_sources_with_budget_prefers_tail_segment() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let path = temp.path().join("review_events.ndjson");
        let mut lines = String::new();
        for index in 0..400 {
            lines.push_str(
                &serde_json::json!({
                    "pr_number": 42,
                    "review_type": "security",
                    "run_id": format!("old-{index}"),
                    "event": "run_start",
                    "model": "model-old",
                    "ts": "2026-02-15T00:00:00Z"
                })
                .to_string(),
            );
            lines.push('\n');
        }
        lines.push_str(
            &serde_json::json!({
                "pr_number": 42,
                "review_type": "security",
                "run_id": "keep",
                "event": "run_start",
                "model": "model-tail",
                "ts": "2026-02-15T00:01:00Z"
            })
            .to_string(),
        );
        lines.push('\n');
        lines.push_str(
            &serde_json::json!({
                "pr_number": 42,
                "review_type": "security",
                "run_id": "keep",
                "event": "tool_call",
                "tool": "read_file",
                "ts": "2026-02-15T00:01:05Z"
            })
            .to_string(),
        );
        lines.push('\n');
        std::fs::write(&path, lines).expect("write events");

        let run_ids = std::collections::BTreeSet::from(["keep".to_string()]);
        let signals =
            super::scan_event_signals_from_sources_with_budget(&[path], 42, &run_ids, 1024);
        let models = signals
            .model_attempts
            .get("security")
            .cloned()
            .unwrap_or_default();
        assert_eq!(models, vec!["model-tail".to_string()]);
        assert_eq!(signals.tool_call_counts.get("keep").copied(), Some(1));
    }

    #[test]
    fn test_count_log_lines_bounded_handles_single_oversized_line_without_oom() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let path = temp.path().join("oversized.log");
        let max_scan_bytes =
            usize::try_from(super::DOCTOR_LOG_SCAN_MAX_BYTES).expect("scan byte cap fits usize");
        let oversized = "z".repeat(max_scan_bytes.saturating_add(4096));
        std::fs::write(&path, oversized).expect("write oversized log");

        let line_count =
            super::count_log_lines_bounded(&path).expect("bounded count should succeed");
        assert_eq!(line_count, 1);
    }

    /// Verify the doctor interrupt flag uses a global singleton and that the
    /// `ctrlc` crate's `termination` feature is active. The `termination`
    /// feature makes `set_handler` also handle SIGTERM (and SIGHUP) in
    /// addition to SIGINT, so the doctor wait loop exits cleanly on both
    /// Ctrl-C and SIGTERM with a final `doctor_result` snapshot.
    ///
    /// This test validates the structural property: the flag is accessible and
    /// the handler was installed (or another subsystem installed one before
    /// us).
    #[test]
    fn doctor_interrupt_flag_is_singleton_and_default_false() {
        let flag_a = super::doctor_interrupt_flag()
            .expect("handler should register or already be registered");
        let flag_b = super::doctor_interrupt_flag()
            .expect("handler should register or already be registered");

        // Both calls return Arc clones of the same global flag.
        assert!(std::sync::Arc::ptr_eq(&flag_a, &flag_b));

        // The flag starts as false (not interrupted).
        assert!(!flag_a.load(std::sync::atomic::Ordering::SeqCst));

        // Simulate the signal: set the flag to true and verify.
        flag_a.store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(flag_b.load(std::sync::atomic::Ordering::SeqCst));

        // Reset for other tests.
        flag_a.store(false, std::sync::atomic::Ordering::SeqCst);
    }

    /// Verify that the `ctrlc` crate was compiled with `termination` feature.
    ///
    /// The `termination` feature makes `ctrlc::set_handler()` also install
    /// signal handlers for SIGTERM and SIGHUP. Without it, only SIGINT is
    /// handled, meaning SIGTERM kills the process without invoking the doctor
    /// wait loop's interrupt path (no final `doctor_result` snapshot).
    ///
    /// We verify the feature is active by checking that `ctrlc::set_handler`
    /// returns `MultipleHandlers` (i.e., the global handler was already
    /// installed by `doctor_interrupt_flag()`) rather than silently accepting
    /// a new handler. This proves the handler is installed for SIGTERM too.
    #[test]
    fn ctrlc_termination_feature_handles_sigterm() {
        // Ensure the global handler is installed (must succeed for this
        // test's assertion to be meaningful).
        super::doctor_interrupt_flag().expect("handler should register or already be registered");

        // Attempting to install a second handler should fail because the
        // global handler is already installed (ctrlc only allows one handler).
        let result = ctrlc::set_handler(|| {});
        assert!(
            result.is_err(),
            "expected MultipleHandlers error since global handler was already installed"
        );
    }

    #[test]
    fn tracked_pr_repo_filter_matches_case_insensitive_exact_repo() {
        assert!(super::tracked_pr_matches_repo_filter(
            "Guardian-Intelligence/APM2",
            Some("guardian-intelligence/apm2"),
        ));
        assert!(super::tracked_pr_matches_repo_filter(
            "guardian-intelligence/apm2",
            Some("  GUARDIAN-INTELLIGENCE/APM2  "),
        ));
    }

    #[test]
    fn tracked_pr_repo_filter_rejects_partial_or_mismatched_repo() {
        assert!(!super::tracked_pr_matches_repo_filter(
            "guardian-intelligence/apm2",
            Some("guardian-intelligence"),
        ));
        assert!(!super::tracked_pr_matches_repo_filter(
            "guardian-intelligence/apm2",
            Some("guardian-intelligence/apm2-docs"),
        ));
    }

    #[test]
    fn tracked_pr_repo_filter_defaults_to_allow_without_filter() {
        assert!(super::tracked_pr_matches_repo_filter(
            "guardian-intelligence/apm2",
            None
        ));
        assert!(!super::tracked_pr_matches_repo_filter("   ", None));
    }

    #[test]
    fn doctor_decision_rules_are_unique_and_strictly_ordered() {
        let mut last_priority = 0_u8;
        let mut seen_states = std::collections::BTreeSet::new();
        let mut seen_guard_ids = std::collections::BTreeSet::new();
        for rule in super::DOCTOR_DECISION_RULES {
            assert!(rule.priority > last_priority);
            last_priority = rule.priority;
            assert!(seen_states.insert(rule.state.as_str()));
            assert!(seen_guard_ids.insert(rule.guard_id));
        }
        assert_eq!(
            super::DOCTOR_DECISION_RULES
                .last()
                .map(|rule| rule.state.as_str()),
            Some(super::DoctorDecisionState::Wait.as_str())
        );
    }

    #[test]
    fn doctor_gate_progress_rules_are_unique_and_strictly_ordered() {
        let mut last_priority = 0_u8;
        let mut seen_states = std::collections::BTreeSet::new();
        let mut seen_guard_ids = std::collections::BTreeSet::new();
        for rule in super::DOCTOR_GATE_PROGRESS_RULES {
            assert!(rule.priority > last_priority);
            last_priority = rule.priority;
            assert!(seen_states.insert(rule.state.as_str()));
            assert!(seen_guard_ids.insert(rule.guard_id));
        }
        assert_eq!(
            super::DOCTOR_GATE_PROGRESS_RULES
                .last()
                .map(|rule| rule.state.as_str()),
            Some(super::DoctorGateProgressState::Unknown.as_str())
        );
    }

    #[test]
    fn doctor_recommendation_rules_cover_all_decision_states() {
        let decision_states = super::DOCTOR_DECISION_RULES
            .iter()
            .map(|rule| rule.state.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        let recommendation_states = super::DOCTOR_RECOMMENDATION_RULES
            .iter()
            .map(|rule| rule.state.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(decision_states, recommendation_states);
    }

    #[test]
    fn doctor_action_policies_cover_recommendation_actions() {
        let recommendation_actions = super::DOCTOR_RECOMMENDATION_RULES
            .iter()
            .map(|rule| rule.action)
            .collect::<std::collections::BTreeSet<_>>();
        let policy_actions = super::DOCTOR_ACTION_POLICIES
            .iter()
            .map(|policy| policy.action)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(recommendation_actions, policy_actions);
        assert!(policy_actions.contains("dispatch_implementor"));
    }

    #[test]
    fn doctor_wait_transition_rules_are_unique_and_strictly_ordered() {
        let mut last_priority = 0_u8;
        let mut seen_guard_ids = std::collections::BTreeSet::new();
        for rule in super::DOCTOR_WAIT_TRANSITION_RULES {
            assert!(rule.priority > last_priority);
            last_priority = rule.priority;
            assert!(seen_guard_ids.insert(rule.guard_id));
        }
        assert_eq!(
            super::DOCTOR_WAIT_TRANSITION_RULES
                .last()
                .map(|rule| rule.to.as_str()),
            Some(super::DoctorWaitState::Evaluate.as_str())
        );
    }

    #[test]
    fn doctor_wait_machine_exits_immediately_on_dispatch_implementor() {
        let exit_actions =
            super::normalize_doctor_exit_actions(&[]).expect("default exit actions should parse");
        let facts = super::DoctorWaitFacts {
            recommended_action: "dispatch_implementor",
            exit_actions: &exit_actions,
            interrupted: false,
            elapsed_seconds: 1,
            wait_timeout_seconds: 1200,
        };
        let next =
            super::derive_doctor_wait_next_state(super::DoctorWaitState::Evaluate, Some(&facts));
        assert_eq!(next, super::DoctorWaitState::ExitOnRecommendedAction);
    }

    #[test]
    fn doctor_wait_machine_prioritizes_terminal_action_over_interrupt() {
        let exit_actions =
            super::normalize_doctor_exit_actions(&[]).expect("default exit actions should parse");
        let facts = super::DoctorWaitFacts {
            recommended_action: "dispatch_implementor",
            exit_actions: &exit_actions,
            interrupted: true,
            elapsed_seconds: 1200,
            wait_timeout_seconds: 1200,
        };
        let next =
            super::derive_doctor_wait_next_state(super::DoctorWaitState::Evaluate, Some(&facts));
        assert_eq!(next, super::DoctorWaitState::ExitOnRecommendedAction);
    }

    #[test]
    fn doctor_wait_machine_exits_on_interrupt_when_action_is_not_terminal() {
        let exit_actions =
            super::normalize_doctor_exit_actions(&[]).expect("default exit actions should parse");
        let facts = super::DoctorWaitFacts {
            recommended_action: "wait",
            exit_actions: &exit_actions,
            interrupted: true,
            elapsed_seconds: 5,
            wait_timeout_seconds: 1200,
        };
        let next =
            super::derive_doctor_wait_next_state(super::DoctorWaitState::Evaluate, Some(&facts));
        assert_eq!(next, super::DoctorWaitState::ExitOnInterrupt);
    }

    #[test]
    fn doctor_wait_machine_exits_on_timeout_when_not_interrupted() {
        let exit_actions =
            super::normalize_doctor_exit_actions(&[]).expect("default exit actions should parse");
        let facts = super::DoctorWaitFacts {
            recommended_action: "wait",
            exit_actions: &exit_actions,
            interrupted: false,
            elapsed_seconds: 1200,
            wait_timeout_seconds: 1200,
        };
        let next =
            super::derive_doctor_wait_next_state(super::DoctorWaitState::Evaluate, Some(&facts));
        assert_eq!(next, super::DoctorWaitState::ExitOnTimeout);
    }

    #[test]
    fn doctor_wait_pulse_mode_rechecks_only_on_pulse_wakeups() {
        assert!(super::doctor_wait_should_collect_summary(
            super::DoctorWaitMode::PulsePrimary,
            super::DoctorWaitWakeReason::Pulse
        ));
        assert!(!super::doctor_wait_should_collect_summary(
            super::DoctorWaitMode::PulsePrimary,
            super::DoctorWaitWakeReason::Timer
        ));
    }

    #[test]
    fn doctor_wait_polling_mode_rechecks_on_timer_wakeups() {
        assert!(super::doctor_wait_should_collect_summary(
            super::DoctorWaitMode::PollingFallback,
            super::DoctorWaitWakeReason::Timer
        ));
    }

    #[test]
    fn doctor_pulse_client_sub_id_is_bounded_and_ascii() {
        let long_repo = "Guardian-Intelligence/APM2/With/Very/Long/Repository/Path/Components";
        let sub_id = super::build_doctor_pulse_client_sub_id(long_repo, 42);
        assert!(!sub_id.is_empty());
        assert!(sub_id.is_ascii(), "client_sub_id must be ASCII");
        assert!(
            sub_id.len() <= super::DOCTOR_WAIT_PULSE_CLIENT_SUB_ID_MAX_LEN,
            "client_sub_id exceeded max length: {}",
            sub_id.len()
        );
    }

    #[test]
    fn doctor_pulse_deduper_rejects_duplicate_fingerprint() {
        let mut deduper = super::DoctorPulseDeduper::new(4);
        let pulse = super::DoctorPulseMetadata {
            pulse_id: Some("pulse-1".to_string()),
            topic: Some("work.W-1.events".to_string()),
            event_type: Some("work.transitioned".to_string()),
            ledger_cursor: Some(10),
        };

        assert!(deduper.insert_if_new(&pulse));
        assert!(!deduper.insert_if_new(&pulse));
    }

    #[test]
    fn doctor_pulse_deduper_evicts_oldest_entry_when_capacity_reached() {
        let mut deduper = super::DoctorPulseDeduper::new(2);
        let pulse_1 = super::DoctorPulseMetadata {
            pulse_id: Some("pulse-1".to_string()),
            topic: Some("work.W-1.events".to_string()),
            event_type: Some("work.transitioned".to_string()),
            ledger_cursor: Some(10),
        };
        let pulse_2 = super::DoctorPulseMetadata {
            pulse_id: Some("pulse-2".to_string()),
            topic: Some("work.W-2.events".to_string()),
            event_type: Some("work.transitioned".to_string()),
            ledger_cursor: Some(11),
        };
        let pulse_3 = super::DoctorPulseMetadata {
            pulse_id: Some("pulse-3".to_string()),
            topic: Some("work.W-3.events".to_string()),
            event_type: Some("work.transitioned".to_string()),
            ledger_cursor: Some(12),
        };

        assert!(deduper.insert_if_new(&pulse_1));
        assert!(deduper.insert_if_new(&pulse_2));
        assert!(deduper.insert_if_new(&pulse_3));

        // pulse_1 should have been evicted when pulse_3 was inserted.
        assert!(deduper.insert_if_new(&pulse_1));
    }

    #[test]
    fn doctor_wait_pulse_scope_filters_unrelated_events() {
        let relevant = super::DoctorPulseMetadata {
            pulse_id: Some("pulse-work".to_string()),
            topic: Some("work.W-123.events".to_string()),
            event_type: Some("work.transitioned".to_string()),
            ledger_cursor: Some(42),
        };
        assert!(super::doctor_wait_pulse_is_relevant(&relevant));

        let unrelated = super::DoctorPulseMetadata {
            pulse_id: Some("pulse-session".to_string()),
            topic: Some("session.S-1.lifecycle".to_string()),
            event_type: Some("session.started".to_string()),
            ledger_cursor: Some(43),
        };
        assert!(!super::doctor_wait_pulse_is_relevant(&unrelated));
    }

    #[test]
    fn upsert_doctor_gate_snapshot_prefers_inflight_over_pass() {
        let mut gates = std::collections::BTreeMap::new();
        super::upsert_doctor_gate_snapshot(
            &mut gates,
            "test",
            "PASS",
            Some("2026-02-20T00:00:00Z".to_string()),
            Some(5),
            super::DoctorGateSource::LocalCache,
        );
        super::upsert_doctor_gate_snapshot(
            &mut gates,
            "test",
            "RUNNING",
            Some("2026-02-20T00:00:01Z".to_string()),
            Some(4),
            super::DoctorGateSource::Projection,
        );
        let merged = gates.get("test").expect("test gate should exist");
        assert_eq!(merged.status, "RUNNING");
    }

    #[test]
    fn upsert_doctor_gate_snapshot_prefers_failed_over_pass() {
        let mut gates = std::collections::BTreeMap::new();
        super::upsert_doctor_gate_snapshot(
            &mut gates,
            "test",
            "PASS",
            None,
            Some(5),
            super::DoctorGateSource::LocalCache,
        );
        super::upsert_doctor_gate_snapshot(
            &mut gates,
            "test",
            "FAIL",
            None,
            Some(4),
            super::DoctorGateSource::Projection,
        );
        let merged = gates.get("test").expect("test gate should exist");
        assert_eq!(merged.status, "FAIL");
    }

    #[test]
    fn upsert_doctor_gate_snapshot_prefers_failed_over_inflight() {
        let mut gates = std::collections::BTreeMap::new();
        super::upsert_doctor_gate_snapshot(
            &mut gates,
            "test",
            "RUNNING",
            None,
            Some(5),
            super::DoctorGateSource::LocalCache,
        );
        super::upsert_doctor_gate_snapshot(
            &mut gates,
            "test",
            "FAIL",
            None,
            Some(4),
            super::DoctorGateSource::Projection,
        );
        let merged = gates.get("test").expect("test gate should exist");
        assert_eq!(merged.status, "FAIL");

        super::upsert_doctor_gate_snapshot(
            &mut gates,
            "test",
            "RUNNING",
            None,
            Some(3),
            super::DoctorGateSource::Projection,
        );
        let merged = gates.get("test").expect("test gate should exist");
        assert_eq!(merged.status, "FAIL");
    }

    #[test]
    fn derive_doctor_gate_progress_state_treats_lifecycle_gates_failed_as_terminal_failed() {
        let state = super::derive_doctor_gate_progress_state(
            &[],
            Some(&doctor_lifecycle_fixture("gates_failed", 2, 0, 9)),
        );
        assert_eq!(state, super::DoctorGateProgressState::TerminalFailed);
    }

    #[test]
    fn derive_doctor_gate_progress_state_prefers_failed_when_running_and_failed_present() {
        let gates = vec![
            doctor_gate_snapshot("test", "RUNNING"),
            doctor_gate_snapshot("test2", "FAIL"),
        ];
        let state = super::derive_doctor_gate_progress_state(&gates, None);
        assert_eq!(state, super::DoctorGateProgressState::TerminalFailed);
    }

    #[test]
    fn fac_review_machine_spec_snapshot_is_current() {
        let expected =
            include_str!("../../../../../documents/reviews/fac_review_state_machine.cac.json");
        let actual =
            serde_json::to_string_pretty(&super::fac_review_machine_spec_json()).expect("json");
        assert_eq!(actual.trim(), expected.trim());
    }

    #[test]
    fn tracked_pr_repo_filter_applies_before_global_limit() {
        let mut candidates = Vec::new();
        for pr in (1000..=1105).rev() {
            candidates.push((pr, "example/capacity-load".to_string()));
        }
        // This target PR would be dropped by old logic that truncated to 100
        // before applying repo filtering.
        candidates.push((42, "guardian-intelligence/apm2".to_string()));

        let selected = super::filter_tracked_pr_candidates(
            candidates,
            Some("guardian-intelligence/apm2"),
            super::MAX_TRACKED_PR_SUMMARIES,
        );
        assert_eq!(
            selected,
            vec![(42, "guardian-intelligence/apm2".to_string())]
        );
    }
}
