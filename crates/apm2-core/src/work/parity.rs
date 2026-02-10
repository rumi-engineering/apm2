//! Event-family parity validation and replay-equivalence gates for work
//! lifecycle transitions.
//!
//! Implements REQ-HEF-0014 by validating semantic equivalence across:
//! - daemon underscore events (`work_claimed`, `work_transitioned`)
//! - reducer dotted events (`work.*`)
//! - protobuf-typed work variants (`WorkTransitioned`, companions)

use std::collections::{BTreeMap, HashMap, HashSet};

use prost::Message;
use serde::{Deserialize, Serialize};

use super::{WorkError, WorkReducer, WorkReducerState};
use crate::events::{
    DefectRecorded, DefectSource, WorkAborted, WorkCompleted, WorkEvent, WorkOpened,
    WorkPrAssociated, WorkTransitioned, work_event,
};
use crate::ledger::EventRecord;
use crate::reducer::{Reducer, ReducerContext};

/// The three active event families for work lifecycle transitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EventFamily {
    /// Daemon underscore events (for example, `work_claimed`).
    DaemonUnderscore,
    /// Reducer dotted events (for example, `work.transitioned`).
    ReducerDotted,
    /// Protobuf typed variants (for example, `WorkTransitioned`).
    ProtobufTyped,
}

/// Canonical lifecycle classes used for parity comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TransitionClass {
    /// `WorkOpened` / `work.opened`.
    WorkOpened,
    /// Open -> Claimed.
    WorkClaimed,
    /// Claimed -> `InProgress`.
    WorkStarted,
    /// Generic transition not covered by a specialized class.
    WorkTransitioned,
    /// `WorkCompleted` / `work.completed`.
    WorkCompleted,
    /// `WorkAborted` / `work.aborted`.
    WorkAborted,
    /// `WorkPrAssociated` / `work.pr_associated`.
    WorkPrAssociated,
    /// CI-gated transitions.
    WorkCiTransition,
}

/// Fields that must remain equivalent across families.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ParityField {
    /// Work identity.
    WorkId,
    /// Transition state descriptor.
    State,
    /// Rationale code.
    Rationale,
    /// Replay sequence (`previous_transition_count`).
    Sequence,
    /// Event actor identity.
    Actor,
    /// Event timestamp.
    Timestamp,
}

/// Canonical mapping entry between event families.
#[derive(Debug, Clone)]
pub struct EventFamilyMapping {
    /// Lifecycle transition class covered by this mapping.
    pub transition_class: TransitionClass,
    /// Daemon event name, if daemon emits this class.
    pub daemon_event: Option<&'static str>,
    /// Reducer dotted event type.
    pub reducer_event_type: &'static str,
    /// Protobuf variant name.
    pub protobuf_variant: &'static str,
    /// Fields that must match across families.
    pub parity_fields: &'static [ParityField],
}

const WORK_ID_FIELDS: &[ParityField] = &[ParityField::WorkId];
const TRANSITION_FIELDS: &[ParityField] = &[
    ParityField::WorkId,
    ParityField::State,
    ParityField::Rationale,
    ParityField::Sequence,
    ParityField::Actor,
];
const COMPLETION_FIELDS: &[ParityField] = &[ParityField::WorkId, ParityField::Actor];
const ABORT_FIELDS: &[ParityField] = &[
    ParityField::WorkId,
    ParityField::Rationale,
    ParityField::Actor,
];
const PR_ASSOCIATED_FIELDS: &[ParityField] = &[ParityField::WorkId, ParityField::Actor];

/// Canonical mapping matrix for parity validation.
pub const MAPPING_MATRIX: &[EventFamilyMapping] = &[
    EventFamilyMapping {
        transition_class: TransitionClass::WorkOpened,
        daemon_event: None,
        reducer_event_type: "work.opened",
        protobuf_variant: "WorkOpened",
        parity_fields: WORK_ID_FIELDS,
    },
    EventFamilyMapping {
        transition_class: TransitionClass::WorkClaimed,
        daemon_event: Some("work_claimed"),
        reducer_event_type: "work.transitioned",
        protobuf_variant: "WorkTransitioned",
        parity_fields: TRANSITION_FIELDS,
    },
    EventFamilyMapping {
        transition_class: TransitionClass::WorkStarted,
        daemon_event: Some("work_transitioned"),
        reducer_event_type: "work.transitioned",
        protobuf_variant: "WorkTransitioned",
        parity_fields: TRANSITION_FIELDS,
    },
    EventFamilyMapping {
        transition_class: TransitionClass::WorkTransitioned,
        daemon_event: Some("work_transitioned"),
        reducer_event_type: "work.transitioned",
        protobuf_variant: "WorkTransitioned",
        parity_fields: TRANSITION_FIELDS,
    },
    EventFamilyMapping {
        transition_class: TransitionClass::WorkCompleted,
        daemon_event: None,
        reducer_event_type: "work.completed",
        protobuf_variant: "WorkCompleted",
        parity_fields: COMPLETION_FIELDS,
    },
    EventFamilyMapping {
        transition_class: TransitionClass::WorkAborted,
        daemon_event: None,
        reducer_event_type: "work.aborted",
        protobuf_variant: "WorkAborted",
        parity_fields: ABORT_FIELDS,
    },
    EventFamilyMapping {
        transition_class: TransitionClass::WorkPrAssociated,
        daemon_event: None,
        reducer_event_type: "work.pr_associated",
        protobuf_variant: "WorkPrAssociated",
        parity_fields: PR_ASSOCIATED_FIELDS,
    },
    EventFamilyMapping {
        transition_class: TransitionClass::WorkCiTransition,
        daemon_event: Some("work_transitioned"),
        reducer_event_type: "work.transitioned",
        protobuf_variant: "WorkTransitioned",
        parity_fields: TRANSITION_FIELDS,
    },
];

/// Structured parity defect for promotion-gate blocking and defect emission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParityDefect {
    /// Work identifier associated with the defect.
    pub work_id: String,
    /// Event IDs involved in the mismatch.
    pub event_ids: Vec<String>,
    /// Mapping class that failed.
    pub mapping_class: TransitionClass,
    /// Field that failed equivalence.
    pub field: ParityField,
    /// Expected value from source family.
    pub expected: String,
    /// Actual value from target family.
    pub actual: String,
    /// Source family for comparison.
    pub source_family: EventFamily,
    /// Target family for comparison.
    pub target_family: EventFamily,
}

/// Result of a parity check for one mapping class.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParityCheckResult {
    /// Mapping class evaluated.
    pub transition_class: TransitionClass,
    /// Whether all checks passed.
    pub passed: bool,
    /// Defects produced by this class.
    pub defects: Vec<ParityDefect>,
}

/// Canonical parity validator.
pub struct ParityValidator;

impl ParityValidator {
    /// Validates all mapped work lifecycle classes across active event
    /// families.
    #[must_use]
    pub fn validate_all(events: &[EventRecord]) -> Vec<ParityCheckResult> {
        let (mut canonical_events, parse_defects) = parse_events(events);
        infer_claimed_fields_from_daemon_transition(&mut canonical_events);
        evaluate_parity(&canonical_events, parse_defects)
    }
}

/// Replay-equivalence result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayResult {
    /// Whether replay projection matches expected state.
    pub matches: bool,
    /// Actual replayed state.
    pub actual_state: WorkReducerState,
    /// Expected state.
    pub expected_state: WorkReducerState,
    /// Number of duplicate events deduplicated before reducer application.
    pub deduplicated_event_count: usize,
    /// Number of work events that mutated reducer state.
    pub applied_event_count: usize,
    /// Duplicate side effects observed during replay.
    pub duplicate_side_effects: usize,
}

/// Replay-equivalence checker for work lifecycle projection.
#[derive(Debug, Default)]
pub struct ReplayEquivalenceChecker {
    reducer: WorkReducer,
}

impl ReplayEquivalenceChecker {
    /// Creates a replay-equivalence checker.
    #[must_use]
    pub fn new() -> Self {
        Self {
            reducer: WorkReducer::new(),
        }
    }

    /// Replays events and compares final reducer state to `expected_state`.
    ///
    /// Duplicate events are deduplicated by deterministic event fingerprint
    /// before reducer application to model idempotent delivery semantics.
    ///
    /// # Errors
    ///
    /// Returns [`WorkError`] when reducer application fails for a non-duplicate
    /// event.
    pub fn verify_replay_equivalence(
        &mut self,
        events: &[EventRecord],
        expected_state: &WorkReducerState,
    ) -> Result<ReplayResult, WorkError> {
        self.reducer.reset();

        let mut seen_fingerprints = HashSet::new();
        let mut deduplicated_event_count = 0usize;
        let mut applied_event_count = 0usize;
        let mut duplicate_side_effects = 0usize;

        for event in events {
            let fingerprint = event_fingerprint(event);
            if !seen_fingerprints.insert(fingerprint) {
                deduplicated_event_count += 1;
                continue;
            }

            let state_before = self.reducer.state().clone();
            let ctx = ReducerContext::new(event.seq_id.unwrap_or(0));
            self.reducer.apply(event, &ctx)?;

            if event.event_type.starts_with("work.") {
                if self.reducer.state() == &state_before {
                    // Event has a unique fingerprint but did not mutate state.
                    // This indicates a duplicate side effect - the same logical
                    // transition was already applied from a different event source.
                    duplicate_side_effects += 1;
                } else {
                    applied_event_count += 1;
                }
            }
        }

        let actual_state = self.reducer.state().clone();
        let matches = &actual_state == expected_state;

        Ok(ReplayResult {
            matches,
            actual_state,
            expected_state: expected_state.clone(),
            deduplicated_event_count,
            applied_event_count,
            duplicate_side_effects,
        })
    }
}

/// Event-family promotion gate output.
#[derive(Debug, Clone)]
pub struct PromotionGateResult {
    /// Whether promotion is allowed.
    pub allowed: bool,
    /// Per-class parity check results.
    pub parity_results: Vec<ParityCheckResult>,
    /// Flattened parity defects.
    pub parity_defects: Vec<ParityDefect>,
    /// Replay pass flag.
    pub replay_passed: bool,
    /// Replay result, if replay executed without reducer error.
    pub replay_result: Option<ReplayResult>,
    /// Replay error, if replay failed closed.
    pub replay_error: Option<String>,
    /// Structured `DefectRecorded` payloads derived from failures.
    pub defect_records: Vec<DefectRecorded>,
}

/// Promotion gate that blocks on parity or replay-equivalence failures.
pub struct EventFamilyPromotionGate;

impl EventFamilyPromotionGate {
    /// Evaluates parity and replay-equivalence for promotion.
    ///
    /// # Errors
    ///
    /// Returns [`WorkError`] only when replay reducer application fails
    /// unrecoverably before a result can be produced.
    pub fn evaluate(
        events: &[EventRecord],
        expected_state: &WorkReducerState,
    ) -> Result<PromotionGateResult, WorkError> {
        let parity_results = ParityValidator::validate_all(events);
        let parity_defects: Vec<ParityDefect> = parity_results
            .iter()
            .flat_map(|result| result.defects.clone())
            .collect();

        let detected_at = latest_timestamp(events);
        let mut defect_records: Vec<DefectRecorded> = parity_defects
            .iter()
            .map(|defect| parity_defect_to_record(defect, detected_at))
            .collect();

        let mut replay_checker = ReplayEquivalenceChecker::new();
        let replay_result = replay_checker.verify_replay_equivalence(events, expected_state)?;
        let replay_passed = replay_result.matches && replay_result.duplicate_side_effects == 0;

        let replay_error = if replay_passed {
            None
        } else {
            let error_message = if replay_result.matches {
                format!(
                    "replay duplicate side effects detected: {}",
                    replay_result.duplicate_side_effects
                )
            } else {
                "replay projection mismatch".to_string()
            };
            defect_records.push(replay_failure_record(
                &error_message,
                detected_at,
                &primary_work_id(events),
            ));
            Some(error_message)
        };

        let allowed = parity_defects.is_empty() && replay_passed;

        Ok(PromotionGateResult {
            allowed,
            parity_results,
            parity_defects,
            replay_passed,
            replay_result: Some(replay_result),
            replay_error,
            defect_records,
        })
    }
}

#[derive(Debug, Clone)]
struct CanonicalParityEvent {
    event_id: String,
    family: EventFamily,
    transition_class: TransitionClass,
    daemon_event: Option<String>,
    reducer_event_type: Option<String>,
    protobuf_variant: Option<String>,
    work_id: String,
    from_state: Option<String>,
    to_state: Option<String>,
    rationale_code: Option<String>,
    previous_transition_count: Option<u32>,
    actor_id: Option<String>,
    timestamp_ns: u64,
}

impl CanonicalParityEvent {
    fn matches_mapping(&self, mapping: &EventFamilyMapping) -> bool {
        if self.transition_class != mapping.transition_class {
            return false;
        }

        match self.family {
            EventFamily::DaemonUnderscore => self.daemon_event.as_deref() == mapping.daemon_event,
            EventFamily::ReducerDotted => {
                self.reducer_event_type.as_deref() == Some(mapping.reducer_event_type)
            },
            EventFamily::ProtobufTyped => {
                self.protobuf_variant.as_deref() == Some(mapping.protobuf_variant)
            },
        }
    }

    fn mapping_key(&self) -> String {
        match self.transition_class {
            TransitionClass::WorkClaimed
            | TransitionClass::WorkStarted
            | TransitionClass::WorkTransitioned
            | TransitionClass::WorkCiTransition => {
                let seq = self
                    .previous_transition_count
                    .map_or_else(|| "missing".to_string(), |value| value.to_string());
                format!("{}|{seq}", self.work_id)
            },
            TransitionClass::WorkOpened
            | TransitionClass::WorkCompleted
            | TransitionClass::WorkAborted
            | TransitionClass::WorkPrAssociated => self.work_id.clone(),
        }
    }

    fn field_value(&self, field: ParityField) -> Option<String> {
        match field {
            ParityField::WorkId => Some(self.work_id.clone()),
            ParityField::State => self.state_descriptor(),
            ParityField::Rationale => self.rationale_code.clone(),
            ParityField::Sequence => self
                .previous_transition_count
                .map(|value| value.to_string()),
            ParityField::Actor => self.actor_id.clone(),
            ParityField::Timestamp => Some(self.timestamp_ns.to_string()),
        }
    }

    fn state_descriptor(&self) -> Option<String> {
        match (&self.from_state, &self.to_state) {
            (Some(from_state), Some(to_state)) => Some(format!("{from_state}->{to_state}")),
            (None, Some(to_state)) => Some(to_state.clone()),
            _ => None,
        }
    }
}

fn parse_events(events: &[EventRecord]) -> (Vec<CanonicalParityEvent>, Vec<ParityDefect>) {
    let mut canonical_events = Vec::new();
    let mut defects = Vec::new();

    for (index, event) in events.iter().enumerate() {
        let event_id = event_id_for(event, index);
        match event.event_type.as_str() {
            "work_claimed" => parse_work_claimed(
                event,
                &event_id,
                &mut canonical_events,
                &mut defects,
                EventFamily::DaemonUnderscore,
            ),
            "work_transitioned" => parse_daemon_work_transitioned(
                event,
                &event_id,
                &mut canonical_events,
                &mut defects,
            ),
            "work.opened" | "work.transitioned" | "work.completed" | "work.aborted"
            | "work.pr_associated" => {
                parse_dotted_work_event(event, &event_id, &mut canonical_events, &mut defects);
            },
            "WorkOpened" | "WorkTransitioned" | "WorkCompleted" | "WorkAborted"
            | "WorkPrAssociated" => parse_direct_protobuf_work_event(
                event,
                &event_id,
                &mut canonical_events,
                &mut defects,
            ),
            other if other.starts_with("work.") || other.starts_with("work_") => {
                defects.push(ParityDefect {
                    work_id: event.session_id.clone(),
                    event_ids: vec![event_id.clone()],
                    mapping_class: TransitionClass::WorkTransitioned,
                    field: ParityField::WorkId,
                    expected: "known work lifecycle event type".to_string(),
                    actual: other.to_string(),
                    source_family: EventFamily::ReducerDotted,
                    target_family: EventFamily::ReducerDotted,
                });
            },
            _ => {},
        }
    }

    (canonical_events, defects)
}

fn parse_work_claimed(
    event: &EventRecord,
    event_id: &str,
    canonical_events: &mut Vec<CanonicalParityEvent>,
    defects: &mut Vec<ParityDefect>,
    family: EventFamily,
) {
    let payload: serde_json::Value = match serde_json::from_slice(&event.payload) {
        Ok(value) => value,
        Err(error) => {
            defects.push(ParityDefect {
                work_id: event.session_id.clone(),
                event_ids: vec![event_id.to_string()],
                mapping_class: TransitionClass::WorkClaimed,
                field: ParityField::WorkId,
                expected: "valid JSON payload".to_string(),
                actual: error.to_string(),
                source_family: family,
                target_family: family,
            });
            return;
        },
    };

    let work_id = payload
        .get("work_id")
        .and_then(serde_json::Value::as_str)
        .map_or_else(|| event.session_id.clone(), ToString::to_string);

    let actor_id = payload
        .get("actor_id")
        .and_then(serde_json::Value::as_str)
        .map_or_else(|| event.actor_id.clone(), ToString::to_string);

    let previous_transition_count = payload
        .get("previous_transition_count")
        .and_then(serde_json::Value::as_u64)
        .and_then(|value| parse_u32(value, event_id, &work_id, defects, family));

    canonical_events.push(CanonicalParityEvent {
        event_id: event_id.to_string(),
        family,
        transition_class: TransitionClass::WorkClaimed,
        daemon_event: Some("work_claimed".to_string()),
        reducer_event_type: None,
        protobuf_variant: None,
        work_id,
        from_state: Some("OPEN".to_string()),
        to_state: Some("CLAIMED".to_string()),
        rationale_code: payload
            .get("rationale_code")
            .and_then(serde_json::Value::as_str)
            .map(ToString::to_string),
        previous_transition_count,
        actor_id: Some(actor_id),
        timestamp_ns: event.timestamp_ns,
    });
}

fn parse_daemon_work_transitioned(
    event: &EventRecord,
    event_id: &str,
    canonical_events: &mut Vec<CanonicalParityEvent>,
    defects: &mut Vec<ParityDefect>,
) {
    let payload: serde_json::Value = match serde_json::from_slice(&event.payload) {
        Ok(value) => value,
        Err(error) => {
            defects.push(ParityDefect {
                work_id: event.session_id.clone(),
                event_ids: vec![event_id.to_string()],
                mapping_class: TransitionClass::WorkTransitioned,
                field: ParityField::WorkId,
                expected: "valid JSON payload".to_string(),
                actual: error.to_string(),
                source_family: EventFamily::DaemonUnderscore,
                target_family: EventFamily::DaemonUnderscore,
            });
            return;
        },
    };

    let work_id = payload
        .get("work_id")
        .and_then(serde_json::Value::as_str)
        .map_or_else(|| event.session_id.clone(), ToString::to_string);

    let from_raw = payload
        .get("from_state")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    let to_raw = payload
        .get("to_state")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();

    let from_state = normalize_state(from_raw);
    let to_state = normalize_state(to_raw);

    if from_state.is_none() || to_state.is_none() {
        defects.push(ParityDefect {
            work_id,
            event_ids: vec![event_id.to_string()],
            mapping_class: TransitionClass::WorkTransitioned,
            field: ParityField::State,
            expected: "known transition states".to_string(),
            actual: format!("{from_raw}->{to_raw}"),
            source_family: EventFamily::DaemonUnderscore,
            target_family: EventFamily::DaemonUnderscore,
        });
        return;
    }

    let from_state = from_state.expect("checked above");
    let to_state = to_state.expect("checked above");
    let transition_class = classify_transition(&from_state, &to_state);
    let previous_transition_count = payload
        .get("previous_transition_count")
        .and_then(serde_json::Value::as_u64)
        .and_then(|value| {
            parse_u32(
                value,
                event_id,
                &work_id,
                defects,
                EventFamily::DaemonUnderscore,
            )
        });

    canonical_events.push(CanonicalParityEvent {
        event_id: event_id.to_string(),
        family: EventFamily::DaemonUnderscore,
        transition_class,
        daemon_event: Some("work_transitioned".to_string()),
        reducer_event_type: None,
        protobuf_variant: None,
        work_id,
        from_state: Some(from_state),
        to_state: Some(to_state),
        rationale_code: payload
            .get("rationale_code")
            .and_then(serde_json::Value::as_str)
            .map(ToString::to_string),
        previous_transition_count,
        actor_id: payload
            .get("actor_id")
            .and_then(serde_json::Value::as_str)
            .map(ToString::to_string)
            .or_else(|| Some(event.actor_id.clone())),
        timestamp_ns: event.timestamp_ns,
    });
}

fn parse_dotted_work_event(
    event: &EventRecord,
    event_id: &str,
    canonical_events: &mut Vec<CanonicalParityEvent>,
    defects: &mut Vec<ParityDefect>,
) {
    let decoded = match WorkEvent::decode(&event.payload[..]) {
        Ok(value) => value,
        Err(error) => {
            defects.push(ParityDefect {
                work_id: event.session_id.clone(),
                event_ids: vec![event_id.to_string()],
                mapping_class: TransitionClass::WorkTransitioned,
                field: ParityField::WorkId,
                expected: "valid WorkEvent payload".to_string(),
                actual: error.to_string(),
                source_family: EventFamily::ReducerDotted,
                target_family: EventFamily::ReducerDotted,
            });
            return;
        },
    };

    let Some(event_variant) = decoded.event else {
        defects.push(ParityDefect {
            work_id: event.session_id.clone(),
            event_ids: vec![event_id.to_string()],
            mapping_class: TransitionClass::WorkTransitioned,
            field: ParityField::WorkId,
            expected: "populated WorkEvent oneof".to_string(),
            actual: "empty WorkEvent oneof".to_string(),
            source_family: EventFamily::ReducerDotted,
            target_family: EventFamily::ReducerDotted,
        });
        return;
    };

    match event_variant {
        work_event::Event::Opened(opened) => push_opened_events(
            event,
            event_id,
            opened,
            "WorkOpened",
            TransitionClass::WorkOpened,
            "work.opened",
            canonical_events,
            defects,
        ),
        work_event::Event::Transitioned(transitioned) => push_transitioned_events(
            event,
            event_id,
            transitioned,
            "WorkTransitioned",
            "work.transitioned",
            canonical_events,
            defects,
        ),
        work_event::Event::Completed(completed) => push_completed_events(
            event,
            event_id,
            completed,
            "WorkCompleted",
            TransitionClass::WorkCompleted,
            "work.completed",
            canonical_events,
            defects,
        ),
        work_event::Event::Aborted(aborted) => push_aborted_events(
            event,
            event_id,
            aborted,
            "WorkAborted",
            TransitionClass::WorkAborted,
            "work.aborted",
            canonical_events,
            defects,
        ),
        work_event::Event::PrAssociated(pr_associated) => push_pr_associated_events(
            event,
            event_id,
            pr_associated,
            "WorkPrAssociated",
            TransitionClass::WorkPrAssociated,
            "work.pr_associated",
            canonical_events,
            defects,
        ),
    }
}

#[allow(clippy::too_many_lines)]
fn parse_direct_protobuf_work_event(
    event: &EventRecord,
    event_id: &str,
    canonical_events: &mut Vec<CanonicalParityEvent>,
    defects: &mut Vec<ParityDefect>,
) {
    match event.event_type.as_str() {
        "WorkOpened" => match decode_opened(&event.payload) {
            Ok(opened) => push_proto_only_opened(
                event,
                event_id,
                opened,
                "WorkOpened",
                TransitionClass::WorkOpened,
                canonical_events,
            ),
            Err(error) => defects.push(ParityDefect {
                work_id: event.session_id.clone(),
                event_ids: vec![event_id.to_string()],
                mapping_class: TransitionClass::WorkOpened,
                field: ParityField::WorkId,
                expected: "decodable WorkOpened payload".to_string(),
                actual: error,
                source_family: EventFamily::ProtobufTyped,
                target_family: EventFamily::ProtobufTyped,
            }),
        },
        "WorkTransitioned" => match decode_transitioned(&event.payload) {
            Ok(transitioned) => push_proto_only_transitioned(
                event,
                event_id,
                transitioned,
                "WorkTransitioned",
                canonical_events,
                defects,
            ),
            Err(error) => defects.push(ParityDefect {
                work_id: event.session_id.clone(),
                event_ids: vec![event_id.to_string()],
                mapping_class: TransitionClass::WorkTransitioned,
                field: ParityField::WorkId,
                expected: "decodable WorkTransitioned payload".to_string(),
                actual: error,
                source_family: EventFamily::ProtobufTyped,
                target_family: EventFamily::ProtobufTyped,
            }),
        },
        "WorkCompleted" => match decode_completed(&event.payload) {
            Ok(completed) => push_proto_only_completed(
                event,
                event_id,
                completed,
                "WorkCompleted",
                TransitionClass::WorkCompleted,
                canonical_events,
            ),
            Err(error) => defects.push(ParityDefect {
                work_id: event.session_id.clone(),
                event_ids: vec![event_id.to_string()],
                mapping_class: TransitionClass::WorkCompleted,
                field: ParityField::WorkId,
                expected: "decodable WorkCompleted payload".to_string(),
                actual: error,
                source_family: EventFamily::ProtobufTyped,
                target_family: EventFamily::ProtobufTyped,
            }),
        },
        "WorkAborted" => match decode_aborted(&event.payload) {
            Ok(aborted) => push_proto_only_aborted(
                event,
                event_id,
                aborted,
                "WorkAborted",
                TransitionClass::WorkAborted,
                canonical_events,
            ),
            Err(error) => defects.push(ParityDefect {
                work_id: event.session_id.clone(),
                event_ids: vec![event_id.to_string()],
                mapping_class: TransitionClass::WorkAborted,
                field: ParityField::WorkId,
                expected: "decodable WorkAborted payload".to_string(),
                actual: error,
                source_family: EventFamily::ProtobufTyped,
                target_family: EventFamily::ProtobufTyped,
            }),
        },
        "WorkPrAssociated" => match decode_pr_associated(&event.payload) {
            Ok(pr_associated) => push_proto_only_pr_associated(
                event,
                event_id,
                pr_associated,
                "WorkPrAssociated",
                TransitionClass::WorkPrAssociated,
                canonical_events,
            ),
            Err(error) => defects.push(ParityDefect {
                work_id: event.session_id.clone(),
                event_ids: vec![event_id.to_string()],
                mapping_class: TransitionClass::WorkPrAssociated,
                field: ParityField::WorkId,
                expected: "decodable WorkPrAssociated payload".to_string(),
                actual: error,
                source_family: EventFamily::ProtobufTyped,
                target_family: EventFamily::ProtobufTyped,
            }),
        },
        _ => {},
    }
}

#[allow(clippy::too_many_arguments)]
fn push_opened_events(
    event: &EventRecord,
    event_id: &str,
    opened: WorkOpened,
    protobuf_variant: &str,
    transition_class: TransitionClass,
    expected_event_type: &str,
    canonical_events: &mut Vec<CanonicalParityEvent>,
    defects: &mut Vec<ParityDefect>,
) {
    if event.event_type != expected_event_type {
        defects.push(ParityDefect {
            work_id: opened.work_id.clone(),
            event_ids: vec![event_id.to_string()],
            mapping_class: transition_class,
            field: ParityField::WorkId,
            expected: expected_event_type.to_string(),
            actual: event.event_type.clone(),
            source_family: EventFamily::ReducerDotted,
            target_family: EventFamily::ReducerDotted,
        });
    }

    canonical_events.push(CanonicalParityEvent {
        event_id: format!("{event_id}@dotted"),
        family: EventFamily::ReducerDotted,
        transition_class,
        daemon_event: None,
        reducer_event_type: Some(event.event_type.clone()),
        protobuf_variant: Some(protobuf_variant.to_string()),
        work_id: opened.work_id.clone(),
        from_state: None,
        to_state: Some("OPEN".to_string()),
        rationale_code: None,
        previous_transition_count: None,
        actor_id: Some(event.actor_id.clone()),
        timestamp_ns: event.timestamp_ns,
    });

    canonical_events.push(CanonicalParityEvent {
        event_id: format!("{event_id}@proto"),
        family: EventFamily::ProtobufTyped,
        transition_class,
        daemon_event: None,
        reducer_event_type: Some(event.event_type.clone()),
        protobuf_variant: Some(protobuf_variant.to_string()),
        work_id: opened.work_id,
        from_state: None,
        to_state: Some("OPEN".to_string()),
        rationale_code: None,
        previous_transition_count: None,
        actor_id: Some(event.actor_id.clone()),
        timestamp_ns: event.timestamp_ns,
    });
}

fn push_transitioned_events(
    event: &EventRecord,
    event_id: &str,
    transitioned: WorkTransitioned,
    protobuf_variant: &str,
    expected_event_type: &str,
    canonical_events: &mut Vec<CanonicalParityEvent>,
    defects: &mut Vec<ParityDefect>,
) {
    if event.event_type != expected_event_type {
        defects.push(ParityDefect {
            work_id: transitioned.work_id.clone(),
            event_ids: vec![event_id.to_string()],
            mapping_class: TransitionClass::WorkTransitioned,
            field: ParityField::WorkId,
            expected: expected_event_type.to_string(),
            actual: event.event_type.clone(),
            source_family: EventFamily::ReducerDotted,
            target_family: EventFamily::ReducerDotted,
        });
    }

    let from_state = normalize_state(&transitioned.from_state);
    let to_state = normalize_state(&transitioned.to_state);

    if from_state.is_none() || to_state.is_none() {
        defects.push(ParityDefect {
            work_id: transitioned.work_id,
            event_ids: vec![event_id.to_string()],
            mapping_class: TransitionClass::WorkTransitioned,
            field: ParityField::State,
            expected: "known transition states".to_string(),
            actual: format!("{}->{}", transitioned.from_state, transitioned.to_state),
            source_family: EventFamily::ReducerDotted,
            target_family: EventFamily::ReducerDotted,
        });
        return;
    }

    let from_state = from_state.expect("checked above");
    let to_state = to_state.expect("checked above");
    let transition_class = classify_transition(&from_state, &to_state);

    canonical_events.push(CanonicalParityEvent {
        event_id: format!("{event_id}@dotted"),
        family: EventFamily::ReducerDotted,
        transition_class,
        daemon_event: None,
        reducer_event_type: Some(event.event_type.clone()),
        protobuf_variant: Some(protobuf_variant.to_string()),
        work_id: transitioned.work_id.clone(),
        from_state: Some(from_state.clone()),
        to_state: Some(to_state.clone()),
        rationale_code: Some(transitioned.rationale_code.clone()),
        previous_transition_count: Some(transitioned.previous_transition_count),
        actor_id: Some(event.actor_id.clone()),
        timestamp_ns: event.timestamp_ns,
    });

    canonical_events.push(CanonicalParityEvent {
        event_id: format!("{event_id}@proto"),
        family: EventFamily::ProtobufTyped,
        transition_class,
        daemon_event: None,
        reducer_event_type: Some(event.event_type.clone()),
        protobuf_variant: Some(protobuf_variant.to_string()),
        work_id: transitioned.work_id,
        from_state: Some(from_state),
        to_state: Some(to_state),
        rationale_code: Some(transitioned.rationale_code),
        previous_transition_count: Some(transitioned.previous_transition_count),
        actor_id: Some(event.actor_id.clone()),
        timestamp_ns: event.timestamp_ns,
    });
}

#[allow(clippy::too_many_arguments)]
fn push_completed_events(
    event: &EventRecord,
    event_id: &str,
    completed: WorkCompleted,
    protobuf_variant: &str,
    transition_class: TransitionClass,
    expected_event_type: &str,
    canonical_events: &mut Vec<CanonicalParityEvent>,
    defects: &mut Vec<ParityDefect>,
) {
    if event.event_type != expected_event_type {
        defects.push(ParityDefect {
            work_id: completed.work_id.clone(),
            event_ids: vec![event_id.to_string()],
            mapping_class: transition_class,
            field: ParityField::WorkId,
            expected: expected_event_type.to_string(),
            actual: event.event_type.clone(),
            source_family: EventFamily::ReducerDotted,
            target_family: EventFamily::ReducerDotted,
        });
    }

    canonical_events.push(CanonicalParityEvent {
        event_id: format!("{event_id}@dotted"),
        family: EventFamily::ReducerDotted,
        transition_class,
        daemon_event: None,
        reducer_event_type: Some(event.event_type.clone()),
        protobuf_variant: Some(protobuf_variant.to_string()),
        work_id: completed.work_id.clone(),
        from_state: None,
        to_state: Some("COMPLETED".to_string()),
        rationale_code: None,
        previous_transition_count: None,
        actor_id: Some(event.actor_id.clone()),
        timestamp_ns: event.timestamp_ns,
    });

    canonical_events.push(CanonicalParityEvent {
        event_id: format!("{event_id}@proto"),
        family: EventFamily::ProtobufTyped,
        transition_class,
        daemon_event: None,
        reducer_event_type: Some(event.event_type.clone()),
        protobuf_variant: Some(protobuf_variant.to_string()),
        work_id: completed.work_id,
        from_state: None,
        to_state: Some("COMPLETED".to_string()),
        rationale_code: None,
        previous_transition_count: None,
        actor_id: Some(event.actor_id.clone()),
        timestamp_ns: event.timestamp_ns,
    });
}

#[allow(clippy::too_many_arguments)]
fn push_aborted_events(
    event: &EventRecord,
    event_id: &str,
    aborted: WorkAborted,
    protobuf_variant: &str,
    transition_class: TransitionClass,
    expected_event_type: &str,
    canonical_events: &mut Vec<CanonicalParityEvent>,
    defects: &mut Vec<ParityDefect>,
) {
    if event.event_type != expected_event_type {
        defects.push(ParityDefect {
            work_id: aborted.work_id.clone(),
            event_ids: vec![event_id.to_string()],
            mapping_class: transition_class,
            field: ParityField::WorkId,
            expected: expected_event_type.to_string(),
            actual: event.event_type.clone(),
            source_family: EventFamily::ReducerDotted,
            target_family: EventFamily::ReducerDotted,
        });
    }

    canonical_events.push(CanonicalParityEvent {
        event_id: format!("{event_id}@dotted"),
        family: EventFamily::ReducerDotted,
        transition_class,
        daemon_event: None,
        reducer_event_type: Some(event.event_type.clone()),
        protobuf_variant: Some(protobuf_variant.to_string()),
        work_id: aborted.work_id.clone(),
        from_state: None,
        to_state: Some("ABORTED".to_string()),
        rationale_code: Some(aborted.rationale_code.clone()),
        previous_transition_count: None,
        actor_id: Some(event.actor_id.clone()),
        timestamp_ns: event.timestamp_ns,
    });

    canonical_events.push(CanonicalParityEvent {
        event_id: format!("{event_id}@proto"),
        family: EventFamily::ProtobufTyped,
        transition_class,
        daemon_event: None,
        reducer_event_type: Some(event.event_type.clone()),
        protobuf_variant: Some(protobuf_variant.to_string()),
        work_id: aborted.work_id,
        from_state: None,
        to_state: Some("ABORTED".to_string()),
        rationale_code: Some(aborted.rationale_code),
        previous_transition_count: None,
        actor_id: Some(event.actor_id.clone()),
        timestamp_ns: event.timestamp_ns,
    });
}

#[allow(clippy::too_many_arguments)]
fn push_pr_associated_events(
    event: &EventRecord,
    event_id: &str,
    pr_associated: WorkPrAssociated,
    protobuf_variant: &str,
    transition_class: TransitionClass,
    expected_event_type: &str,
    canonical_events: &mut Vec<CanonicalParityEvent>,
    defects: &mut Vec<ParityDefect>,
) {
    if event.event_type != expected_event_type {
        defects.push(ParityDefect {
            work_id: pr_associated.work_id.clone(),
            event_ids: vec![event_id.to_string()],
            mapping_class: transition_class,
            field: ParityField::WorkId,
            expected: expected_event_type.to_string(),
            actual: event.event_type.clone(),
            source_family: EventFamily::ReducerDotted,
            target_family: EventFamily::ReducerDotted,
        });
    }

    canonical_events.push(CanonicalParityEvent {
        event_id: format!("{event_id}@dotted"),
        family: EventFamily::ReducerDotted,
        transition_class,
        daemon_event: None,
        reducer_event_type: Some(event.event_type.clone()),
        protobuf_variant: Some(protobuf_variant.to_string()),
        work_id: pr_associated.work_id.clone(),
        from_state: None,
        to_state: None,
        rationale_code: None,
        previous_transition_count: None,
        actor_id: Some(event.actor_id.clone()),
        timestamp_ns: event.timestamp_ns,
    });

    canonical_events.push(CanonicalParityEvent {
        event_id: format!("{event_id}@proto"),
        family: EventFamily::ProtobufTyped,
        transition_class,
        daemon_event: None,
        reducer_event_type: Some(event.event_type.clone()),
        protobuf_variant: Some(protobuf_variant.to_string()),
        work_id: pr_associated.work_id,
        from_state: None,
        to_state: None,
        rationale_code: None,
        previous_transition_count: None,
        actor_id: Some(event.actor_id.clone()),
        timestamp_ns: event.timestamp_ns,
    });
}

fn push_proto_only_opened(
    event: &EventRecord,
    event_id: &str,
    opened: WorkOpened,
    protobuf_variant: &str,
    transition_class: TransitionClass,
    canonical_events: &mut Vec<CanonicalParityEvent>,
) {
    canonical_events.push(CanonicalParityEvent {
        event_id: format!("{event_id}@proto"),
        family: EventFamily::ProtobufTyped,
        transition_class,
        daemon_event: None,
        reducer_event_type: None,
        protobuf_variant: Some(protobuf_variant.to_string()),
        work_id: opened.work_id,
        from_state: None,
        to_state: Some("OPEN".to_string()),
        rationale_code: None,
        previous_transition_count: None,
        actor_id: Some(event.actor_id.clone()),
        timestamp_ns: event.timestamp_ns,
    });
}

fn push_proto_only_transitioned(
    event: &EventRecord,
    event_id: &str,
    transitioned: WorkTransitioned,
    protobuf_variant: &str,
    canonical_events: &mut Vec<CanonicalParityEvent>,
    defects: &mut Vec<ParityDefect>,
) {
    let from_state = normalize_state(&transitioned.from_state);
    let to_state = normalize_state(&transitioned.to_state);

    if from_state.is_none() || to_state.is_none() {
        defects.push(ParityDefect {
            work_id: transitioned.work_id,
            event_ids: vec![event_id.to_string()],
            mapping_class: TransitionClass::WorkTransitioned,
            field: ParityField::State,
            expected: "known transition states".to_string(),
            actual: format!("{}->{}", transitioned.from_state, transitioned.to_state),
            source_family: EventFamily::ProtobufTyped,
            target_family: EventFamily::ProtobufTyped,
        });
        return;
    }

    let from_state = from_state.expect("checked above");
    let to_state = to_state.expect("checked above");
    let transition_class = classify_transition(&from_state, &to_state);

    canonical_events.push(CanonicalParityEvent {
        event_id: format!("{event_id}@proto"),
        family: EventFamily::ProtobufTyped,
        transition_class,
        daemon_event: None,
        reducer_event_type: None,
        protobuf_variant: Some(protobuf_variant.to_string()),
        work_id: transitioned.work_id,
        from_state: Some(from_state),
        to_state: Some(to_state),
        rationale_code: Some(transitioned.rationale_code),
        previous_transition_count: Some(transitioned.previous_transition_count),
        actor_id: Some(event.actor_id.clone()),
        timestamp_ns: event.timestamp_ns,
    });
}

fn push_proto_only_completed(
    event: &EventRecord,
    event_id: &str,
    completed: WorkCompleted,
    protobuf_variant: &str,
    transition_class: TransitionClass,
    canonical_events: &mut Vec<CanonicalParityEvent>,
) {
    canonical_events.push(CanonicalParityEvent {
        event_id: format!("{event_id}@proto"),
        family: EventFamily::ProtobufTyped,
        transition_class,
        daemon_event: None,
        reducer_event_type: None,
        protobuf_variant: Some(protobuf_variant.to_string()),
        work_id: completed.work_id,
        from_state: None,
        to_state: Some("COMPLETED".to_string()),
        rationale_code: None,
        previous_transition_count: None,
        actor_id: Some(event.actor_id.clone()),
        timestamp_ns: event.timestamp_ns,
    });
}

fn push_proto_only_aborted(
    event: &EventRecord,
    event_id: &str,
    aborted: WorkAborted,
    protobuf_variant: &str,
    transition_class: TransitionClass,
    canonical_events: &mut Vec<CanonicalParityEvent>,
) {
    canonical_events.push(CanonicalParityEvent {
        event_id: format!("{event_id}@proto"),
        family: EventFamily::ProtobufTyped,
        transition_class,
        daemon_event: None,
        reducer_event_type: None,
        protobuf_variant: Some(protobuf_variant.to_string()),
        work_id: aborted.work_id,
        from_state: None,
        to_state: Some("ABORTED".to_string()),
        rationale_code: Some(aborted.rationale_code),
        previous_transition_count: None,
        actor_id: Some(event.actor_id.clone()),
        timestamp_ns: event.timestamp_ns,
    });
}

fn push_proto_only_pr_associated(
    event: &EventRecord,
    event_id: &str,
    pr_associated: WorkPrAssociated,
    protobuf_variant: &str,
    transition_class: TransitionClass,
    canonical_events: &mut Vec<CanonicalParityEvent>,
) {
    canonical_events.push(CanonicalParityEvent {
        event_id: format!("{event_id}@proto"),
        family: EventFamily::ProtobufTyped,
        transition_class,
        daemon_event: None,
        reducer_event_type: None,
        protobuf_variant: Some(protobuf_variant.to_string()),
        work_id: pr_associated.work_id,
        from_state: None,
        to_state: None,
        rationale_code: None,
        previous_transition_count: None,
        actor_id: Some(event.actor_id.clone()),
        timestamp_ns: event.timestamp_ns,
    });
}

fn decode_opened(payload: &[u8]) -> Result<WorkOpened, String> {
    WorkOpened::decode(payload).or_else(|_| decode_wrapped_variant(payload, "WorkOpened"))
}

fn decode_transitioned(payload: &[u8]) -> Result<WorkTransitioned, String> {
    WorkTransitioned::decode(payload)
        .or_else(|_| decode_wrapped_variant(payload, "WorkTransitioned"))
}

fn decode_completed(payload: &[u8]) -> Result<WorkCompleted, String> {
    WorkCompleted::decode(payload).or_else(|_| decode_wrapped_variant(payload, "WorkCompleted"))
}

fn decode_aborted(payload: &[u8]) -> Result<WorkAborted, String> {
    WorkAborted::decode(payload).or_else(|_| decode_wrapped_variant(payload, "WorkAborted"))
}

fn decode_pr_associated(payload: &[u8]) -> Result<WorkPrAssociated, String> {
    WorkPrAssociated::decode(payload)
        .or_else(|_| decode_wrapped_variant(payload, "WorkPrAssociated"))
}

fn decode_wrapped_variant<T>(payload: &[u8], variant_name: &str) -> Result<T, String>
where
    T: Message + Default,
{
    let wrapped = WorkEvent::decode(payload).map_err(|error| error.to_string())?;
    let event_variant = wrapped
        .event
        .ok_or_else(|| "empty WorkEvent oneof".to_string())?;

    match (variant_name, event_variant) {
        ("WorkOpened", work_event::Event::Opened(event)) => {
            T::decode(event.encode_to_vec().as_slice()).map_err(|error| error.to_string())
        },
        ("WorkTransitioned", work_event::Event::Transitioned(event)) => {
            T::decode(event.encode_to_vec().as_slice()).map_err(|error| error.to_string())
        },
        ("WorkCompleted", work_event::Event::Completed(event)) => {
            T::decode(event.encode_to_vec().as_slice()).map_err(|error| error.to_string())
        },
        ("WorkAborted", work_event::Event::Aborted(event)) => {
            T::decode(event.encode_to_vec().as_slice()).map_err(|error| error.to_string())
        },
        ("WorkPrAssociated", work_event::Event::PrAssociated(event)) => {
            T::decode(event.encode_to_vec().as_slice()).map_err(|error| error.to_string())
        },
        _ => Err(format!(
            "payload does not contain expected variant {variant_name}"
        )),
    }
}

fn parse_u32(
    value: u64,
    event_id: &str,
    work_id: &str,
    defects: &mut Vec<ParityDefect>,
    family: EventFamily,
) -> Option<u32> {
    u32::try_from(value).map_or_else(
        |_| {
            defects.push(ParityDefect {
                work_id: work_id.to_string(),
                event_ids: vec![event_id.to_string()],
                mapping_class: TransitionClass::WorkTransitioned,
                field: ParityField::Sequence,
                expected: "u32 sequence value".to_string(),
                actual: value.to_string(),
                source_family: family,
                target_family: family,
            });
            None
        },
        Some,
    )
}

fn normalize_state(raw_state: &str) -> Option<String> {
    let compact = raw_state
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .collect::<String>()
        .to_ascii_uppercase();

    let normalized = match compact.as_str() {
        "OPEN" => "OPEN",
        "CLAIMED" => "CLAIMED",
        "INPROGRESS" => "IN_PROGRESS",
        "REVIEW" => "REVIEW",
        "NEEDSINPUT" => "NEEDS_INPUT",
        "NEEDSADJUDICATION" => "NEEDS_ADJUDICATION",
        "COMPLETED" => "COMPLETED",
        "ABORTED" => "ABORTED",
        "CIPENDING" => "CI_PENDING",
        "READYFORREVIEW" => "READY_FOR_REVIEW",
        "BLOCKED" => "BLOCKED",
        _ => return None,
    };

    Some(normalized.to_string())
}

fn classify_transition(from_state: &str, to_state: &str) -> TransitionClass {
    match (from_state, to_state) {
        ("OPEN", "CLAIMED") => TransitionClass::WorkClaimed,
        ("CLAIMED", "IN_PROGRESS") => TransitionClass::WorkStarted,
        ("CI_PENDING", "READY_FOR_REVIEW" | "BLOCKED") | ("BLOCKED", "CI_PENDING") => {
            TransitionClass::WorkCiTransition
        },
        _ => TransitionClass::WorkTransitioned,
    }
}

fn infer_claimed_fields_from_daemon_transition(events: &mut [CanonicalParityEvent]) {
    let mut companion_map: HashMap<String, (String, u32)> = HashMap::new();

    for event in events.iter() {
        if event.family == EventFamily::DaemonUnderscore
            && event.daemon_event.as_deref() == Some("work_transitioned")
            && event.transition_class == TransitionClass::WorkClaimed
            && event.rationale_code.is_some()
            && event.previous_transition_count.is_some()
        {
            let key = format!(
                "{}|{}|{}",
                event.work_id,
                event.actor_id.clone().unwrap_or_default(),
                event.timestamp_ns
            );
            let rationale = event.rationale_code.clone().unwrap_or_default();
            let sequence = event.previous_transition_count.unwrap_or(0);
            companion_map.insert(key, (rationale, sequence));
        }
    }

    for event in events.iter_mut() {
        if event.family == EventFamily::DaemonUnderscore
            && event.daemon_event.as_deref() == Some("work_claimed")
            && (event.rationale_code.is_none() || event.previous_transition_count.is_none())
        {
            let key = format!(
                "{}|{}|{}",
                event.work_id,
                event.actor_id.clone().unwrap_or_default(),
                event.timestamp_ns
            );
            if let Some((rationale, sequence)) = companion_map.get(&key) {
                if event.rationale_code.is_none() {
                    event.rationale_code = Some(rationale.clone());
                }
                if event.previous_transition_count.is_none() {
                    event.previous_transition_count = Some(*sequence);
                }
            }
        }
    }
}

fn evaluate_parity(
    canonical_events: &[CanonicalParityEvent],
    parse_defects: Vec<ParityDefect>,
) -> Vec<ParityCheckResult> {
    let mut parse_defects_by_class: HashMap<TransitionClass, Vec<ParityDefect>> = HashMap::new();
    for defect in parse_defects {
        parse_defects_by_class
            .entry(defect.mapping_class)
            .or_default()
            .push(defect);
    }

    MAPPING_MATRIX
        .iter()
        .map(|mapping| {
            let mut defects = parse_defects_by_class
                .remove(&mapping.transition_class)
                .unwrap_or_default();

            let mut groups: BTreeMap<String, HashMap<EventFamily, Vec<&CanonicalParityEvent>>> =
                BTreeMap::new();

            for event in canonical_events
                .iter()
                .filter(|event| event.matches_mapping(mapping))
            {
                groups
                    .entry(event.mapping_key())
                    .or_default()
                    .entry(event.family)
                    .or_default()
                    .push(event);
            }

            for family_groups in groups.values() {
                let required_families = required_families(mapping);

                for required_family in &required_families {
                    match family_groups.get(required_family) {
                        Some(events) if !events.is_empty() => {
                            if events.len() > 1 {
                                defects.push(ParityDefect {
                                    work_id: events[0].work_id.clone(),
                                    event_ids: events
                                        .iter()
                                        .map(|entry| entry.event_id.clone())
                                        .collect(),
                                    mapping_class: mapping.transition_class,
                                    field: ParityField::Sequence,
                                    expected: "single event per family/key".to_string(),
                                    actual: events.len().to_string(),
                                    source_family: *required_family,
                                    target_family: *required_family,
                                });
                            }
                        },
                        _ => {
                            let source_family = EventFamily::ReducerDotted;
                            let work_id = first_work_id(family_groups)
                                .unwrap_or_else(|| "unknown".to_string());
                            defects.push(ParityDefect {
                                work_id,
                                event_ids: first_event_ids(family_groups),
                                mapping_class: mapping.transition_class,
                                field: ParityField::WorkId,
                                expected: "event present".to_string(),
                                actual: "missing".to_string(),
                                source_family,
                                target_family: *required_family,
                            });
                        },
                    }
                }

                let baseline = select_baseline(family_groups);
                let Some(baseline_event) = baseline else {
                    continue;
                };

                for target_family in required_families {
                    if target_family == baseline_event.family {
                        continue;
                    }

                    let Some(target_event) = family_groups
                        .get(&target_family)
                        .and_then(|events| events.first().copied())
                    else {
                        continue;
                    };

                    for field in mapping.parity_fields {
                        compare_field(
                            baseline_event,
                            target_event,
                            *field,
                            mapping.transition_class,
                            &mut defects,
                        );
                    }
                }
            }

            ParityCheckResult {
                transition_class: mapping.transition_class,
                passed: defects.is_empty(),
                defects,
            }
        })
        .collect()
}

fn required_families(mapping: &EventFamilyMapping) -> Vec<EventFamily> {
    let mut families = vec![EventFamily::ReducerDotted, EventFamily::ProtobufTyped];
    if mapping.daemon_event.is_some() {
        families.push(EventFamily::DaemonUnderscore);
    }
    families
}

fn select_baseline<'a>(
    family_groups: &'a HashMap<EventFamily, Vec<&'a CanonicalParityEvent>>,
) -> Option<&'a CanonicalParityEvent> {
    family_groups
        .get(&EventFamily::ReducerDotted)
        .and_then(|events| events.first().copied())
        .or_else(|| {
            family_groups
                .get(&EventFamily::ProtobufTyped)
                .and_then(|events| events.first().copied())
        })
        .or_else(|| {
            family_groups
                .get(&EventFamily::DaemonUnderscore)
                .and_then(|events| events.first().copied())
        })
}

fn compare_field(
    baseline_event: &CanonicalParityEvent,
    target_event: &CanonicalParityEvent,
    field: ParityField,
    transition_class: TransitionClass,
    defects: &mut Vec<ParityDefect>,
) {
    let expected = baseline_event
        .field_value(field)
        .unwrap_or_else(|| "<missing>".to_string());
    let actual = target_event
        .field_value(field)
        .unwrap_or_else(|| "<missing>".to_string());

    if expected != actual {
        defects.push(ParityDefect {
            work_id: baseline_event.work_id.clone(),
            event_ids: vec![
                baseline_event.event_id.clone(),
                target_event.event_id.clone(),
            ],
            mapping_class: transition_class,
            field,
            expected,
            actual,
            source_family: baseline_event.family,
            target_family: target_event.family,
        });
    }
}

fn event_fingerprint(event: &EventRecord) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(event.event_type.as_bytes());
    hasher.update(event.session_id.as_bytes());
    hasher.update(event.actor_id.as_bytes());
    hasher.update(&event.payload);
    hasher.update(&event.timestamp_ns.to_le_bytes());
    *hasher.finalize().as_bytes()
}

fn parity_defect_to_record(defect: &ParityDefect, detected_at: u64) -> DefectRecorded {
    let payload = serde_json::to_vec(defect).unwrap_or_default();
    let cas_hash = blake3::hash(&payload);

    DefectRecorded {
        defect_id: format!("DEF-PARITY-{}", uuid::Uuid::new_v4()),
        defect_type: "WORK_EVENT_PARITY_MISMATCH".to_string(),
        cas_hash: cas_hash.as_bytes().to_vec(),
        source: DefectSource::SchemaReject as i32,
        work_id: defect.work_id.clone(),
        severity: "S1".to_string(),
        detected_at,
        time_envelope_ref: None,
    }
}

fn replay_failure_record(message: &str, detected_at: u64, work_id: &str) -> DefectRecorded {
    let payload = serde_json::json!({
        "kind": "WORK_REPLAY_EQUIVALENCE_FAILURE",
        "message": message,
        "work_id": work_id,
    });
    let payload_bytes = payload.to_string().into_bytes();
    let cas_hash = blake3::hash(&payload_bytes);

    DefectRecorded {
        defect_id: format!("DEF-REPLAY-{}", uuid::Uuid::new_v4()),
        defect_type: "WORK_REPLAY_EQUIVALENCE_FAILURE".to_string(),
        cas_hash: cas_hash.as_bytes().to_vec(),
        source: DefectSource::SchemaReject as i32,
        work_id: work_id.to_string(),
        severity: "S1".to_string(),
        detected_at,
        time_envelope_ref: None,
    }
}

fn latest_timestamp(events: &[EventRecord]) -> u64 {
    events
        .iter()
        .map(|event| event.timestamp_ns)
        .max()
        .unwrap_or(0)
}

fn primary_work_id(events: &[EventRecord]) -> String {
    for event in events {
        if event.event_type.starts_with("work.") || event.event_type.starts_with("work_") {
            return event.session_id.clone();
        }
    }
    "work.lifecycle".to_string()
}

fn event_id_for(event: &EventRecord, index: usize) -> String {
    event
        .seq_id
        .map_or_else(|| format!("idx:{index}"), |seq_id| format!("seq:{seq_id}"))
}

fn first_event_ids(
    family_groups: &HashMap<EventFamily, Vec<&CanonicalParityEvent>>,
) -> Vec<String> {
    family_groups
        .values()
        .filter_map(|events| events.first().map(|event| event.event_id.clone()))
        .collect()
}

fn first_work_id(
    family_groups: &HashMap<EventFamily, Vec<&CanonicalParityEvent>>,
) -> Option<String> {
    family_groups
        .values()
        .find_map(|events| events.first().map(|event| event.work_id.clone()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::work::helpers;

    fn build_event(
        event_type: &str,
        session_id: &str,
        actor_id: &str,
        payload: Vec<u8>,
        timestamp_ns: u64,
        seq_id: u64,
    ) -> EventRecord {
        EventRecord::with_timestamp(event_type, session_id, actor_id, payload, timestamp_ns)
            .with_seq_id(seq_id)
    }

    #[test]
    fn mapping_matrix_covers_five_work_variants() {
        let variants: HashSet<&'static str> = MAPPING_MATRIX
            .iter()
            .map(|mapping| mapping.protobuf_variant)
            .collect();
        assert_eq!(variants.len(), 5);
        assert!(variants.contains("WorkOpened"));
        assert!(variants.contains("WorkTransitioned"));
        assert!(variants.contains("WorkCompleted"));
        assert!(variants.contains("WorkAborted"));
        assert!(variants.contains("WorkPrAssociated"));
    }

    #[test]
    fn parity_validator_detects_mismatch() {
        let work_id = "W-PARITY-UNIT-001";
        let claim_payload = serde_json::json!({
            "event_type": "work_claimed",
            "work_id": work_id,
            "actor_id": "actor-a",
            "rationale_code": "daemon_claim",
            "previous_transition_count": 0,
        })
        .to_string()
        .into_bytes();

        let reducer_payload = helpers::work_transitioned_payload_with_sequence(
            work_id,
            "OPEN",
            "CLAIMED",
            "different_rationale",
            0,
        );

        let events = vec![
            build_event("work_claimed", work_id, "actor-a", claim_payload, 1_000, 1),
            build_event(
                "work.transitioned",
                work_id,
                "actor-a",
                reducer_payload,
                1_001,
                2,
            ),
        ];

        let results = ParityValidator::validate_all(&events);
        let defect_count: usize = results.iter().map(|result| result.defects.len()).sum();
        assert_eq!(defect_count, 1);
    }
}
