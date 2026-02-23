use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use apm2_core::events::{
    WorkEdgeAdded, WorkEdgeRemoved, WorkEdgeType, WorkEdgeWaived, WorkEvent, WorkGraphEvent,
    work_event, work_graph_event,
};
use apm2_core::ledger::EventRecord;
use apm2_core::reducer::{Reducer, ReducerContext};
use apm2_core::work::{Work, WorkError, WorkReducer, WorkState, helpers};
use ed25519_dalek::Verifier;
use prost::Message;
use serde::Deserialize;
use thiserror::Error;

use crate::protocol::dispatch::{
    LedgerEventEmitter, SignedLedgerEvent, WORK_CLAIMED_DOMAIN_PREFIX,
    WORK_TRANSITIONED_DOMAIN_PREFIX,
};

const DEFAULT_SYNTHETIC_WORK_TYPE: &str = "TICKET";
const MAX_CANONICAL_WORK_EVENT_JSON_BYTES: usize = 64 * 1024;
const MAX_CANONICAL_WORK_EVENT_DECODED_BYTES: usize = 64 * 1024;
const MAX_CANONICAL_WORK_EVENT_HEX_CHARS: usize = MAX_CANONICAL_WORK_EVENT_DECODED_BYTES * 2;
const MAX_WORK_GRAPH_EVENT_BYTES: usize = 64 * 1024;
const MAX_WORK_GRAPH_JSON_DEPTH: usize = 2;
const GRAPH_EDGE_ID_DOMAIN_PREFIX: &[u8] = b"apm2.work_graph.edge.v1";

/// Stable machine-readable reason code for an unsatisfied incoming BLOCKS edge.
pub const WORK_DIAGNOSTIC_REASON_BLOCKS_UNSATISFIED: &str = "work.blocks.unsatisfied_prerequisite";
/// Stable machine-readable reason code for an active waiver.
pub const WORK_DIAGNOSTIC_REASON_BLOCKS_WAIVER_ACTIVE: &str = "work.blocks.waiver_active";
/// Stable machine-readable reason code for late edge detection.
pub const WORK_DIAGNOSTIC_REASON_BLOCKS_LATE_EDGE: &str = "work.blocks.late_edge_added";

/// Severity for dependency diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkDependencySeverity {
    /// Informational only.
    Info,
    /// Warning-level diagnostic.
    Warning,
    /// Error-level diagnostic.
    Error,
}

/// Machine-readable dependency diagnostic emitted by work authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkDependencyDiagnostic {
    /// Stable reason code for programmatic handling.
    pub reason_code: String,
    /// Severity level.
    pub severity: WorkDependencySeverity,
    /// Human-readable detail.
    pub message: String,
    /// Deterministic edge identifier.
    pub edge_id: String,
    /// Source work item ID.
    pub from_work_id: String,
    /// Target work item ID.
    pub to_work_id: String,
    /// Current state of prerequisite work, when known.
    pub from_work_state: Option<WorkState>,
    /// Whether a waiver is active for this edge.
    pub waived: bool,
    /// Waiver identifier when available.
    pub waiver_id: Option<String>,
    /// Waiver expiry timestamp (ns) when available.
    pub waiver_expires_at_ns: Option<u64>,
    /// Remaining waiver lifetime in ns when available.
    pub waiver_remaining_ns: Option<u64>,
    /// Whether this edge was added after dependent work had already started.
    pub late_edge: bool,
}

/// Result of dependency evaluation for a target work item.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WorkDependencyEvaluation {
    /// Whether implementer claim should be blocked.
    pub implementer_claim_blocked: bool,
    /// Structured diagnostics for doctor/work status consumers.
    pub diagnostics: Vec<WorkDependencyDiagnostic>,
}

/// Projection errors for work lifecycle reconstruction.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum WorkProjectionError {
    /// Reducer rejected an event.
    #[error("work reducer error: {0}")]
    Reducer(#[from] WorkError),

    /// Event payload was malformed.
    #[error("invalid {event_type} payload: {reason}")]
    InvalidPayload {
        /// Event type associated with the payload.
        event_type: String,
        /// Why payload parsing failed.
        reason: String,
    },

    /// Transition count exceeded `u32` bounds.
    #[error("invalid previous_transition_count in {event_type}: {value}")]
    InvalidTransitionCount {
        /// Event type associated with the invalid value.
        event_type: String,
        /// Value that could not be represented as `u32`.
        value: u64,
    },

    /// Signature verification failed (fail-closed).
    #[error("signature verification failed for event {event_id}: {reason}")]
    SignatureVerificationFailed {
        /// Event ID that failed verification.
        event_id: String,
        /// Why verification failed.
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct WorkEdgeKey {
    from_work_id: String,
    to_work_id: String,
    edge_type: WorkEdgeType,
}

#[derive(Debug, Clone)]
struct ActiveWorkEdge {
    key: WorkEdgeKey,
    edge_id: String,
    late_edge: bool,
    late_edge_state: Option<WorkState>,
}

#[derive(Debug, Clone)]
struct ActiveWorkEdgeWaiver {
    waiver_id: Option<String>,
    expires_at_ns: Option<u64>,
}

impl ActiveWorkEdgeWaiver {
    fn is_active(&self, now_ns: u64) -> bool {
        self.expires_at_ns.is_none_or(|expiry| now_ns <= expiry)
    }
}

#[derive(Debug, Clone)]
struct ParsedWorkEdgeAdded {
    from_work_id: String,
    to_work_id: String,
    edge_type: WorkEdgeType,
    edge_id: Option<String>,
}

#[derive(Debug, Clone)]
struct ParsedWorkEdgeRemoved {
    from_work_id: String,
    to_work_id: String,
    edge_type: Option<WorkEdgeType>,
    edge_id: Option<String>,
}

#[derive(Debug, Clone)]
struct ParsedWorkEdgeWaived {
    from_work_id: String,
    to_work_id: String,
    edge_type: Option<WorkEdgeType>,
    waiver_id: Option<String>,
    expires_at_ns: Option<u64>,
}

#[derive(Debug, Clone)]
enum ParsedWorkGraphEvent {
    Added(ParsedWorkEdgeAdded),
    Removed(ParsedWorkEdgeRemoved),
    Waived(ParsedWorkEdgeWaived),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WorkGraphEventKind {
    Added,
    Removed,
    Waived,
}

/// Ledger-backed `WorkObject` projection rebuilt through `WorkReducer`.
#[derive(Debug, Default)]
pub struct WorkObjectProjection {
    reducer: WorkReducer,
    ordered_work: BTreeMap<String, Work>,
    active_edges: BTreeMap<WorkEdgeKey, ActiveWorkEdge>,
    active_waivers: BTreeMap<WorkEdgeKey, ActiveWorkEdgeWaiver>,
}

impl WorkObjectProjection {
    /// Creates an empty projection.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Rebuilds projection state from a full event history.
    ///
    /// Events are replayed deterministically by `(timestamp_ns, seq_id,
    /// original_index)`.
    pub fn rebuild_from_events(
        &mut self,
        events: &[EventRecord],
    ) -> Result<(), WorkProjectionError> {
        self.reducer.reset();
        self.active_edges.clear();
        self.active_waivers.clear();

        let mut ordered_indices: Vec<usize> = (0..events.len()).collect();
        ordered_indices.sort_by_key(|idx| {
            (
                events[*idx].timestamp_ns,
                events[*idx].seq_id.unwrap_or(u64::MAX),
                *idx as u64,
            )
        });

        for idx in ordered_indices {
            self.apply_reducer_event(&events[idx])?;
        }

        self.reindex();
        Ok(())
    }

    /// Applies a single event incrementally.
    pub fn apply_event(&mut self, event: &EventRecord) -> Result<(), WorkProjectionError> {
        self.apply_reducer_event(event)?;
        self.reindex();
        Ok(())
    }

    /// Rebuilds projection from daemon signed-ledger events.
    pub fn rebuild_from_signed_events(
        &mut self,
        events: &[SignedLedgerEvent],
    ) -> Result<(), WorkProjectionError> {
        self.reducer.reset();
        self.active_edges.clear();
        self.active_waivers.clear();

        let mut ordered: Vec<(usize, &SignedLedgerEvent)> = events.iter().enumerate().collect();
        ordered.sort_by_key(|(idx, event)| (event.timestamp_ns, *idx as u64));

        let mut opened_work_ids = BTreeSet::new();
        let mut next_seq_id = 1u64;

        for (_, event) in ordered {
            let reducer_events =
                translate_signed_event(event, &mut opened_work_ids, &mut next_seq_id)?;
            for reducer_event in &reducer_events {
                self.apply_reducer_event(reducer_event)?;
            }

            if let Some(graph_event) = decode_work_graph_event(event)? {
                self.apply_work_graph_event(graph_event, event.timestamp_ns);
            }
        }

        self.reindex();
        Ok(())
    }

    /// Returns a work item by ID.
    #[must_use]
    pub fn get_work(&self, work_id: &str) -> Option<&Work> {
        self.ordered_work.get(work_id)
    }

    /// Returns all known work items in deterministic ID order.
    #[must_use]
    pub fn list_work(&self) -> Vec<&Work> {
        self.ordered_work.values().collect()
    }

    /// Returns an iterator over all known work items in deterministic ID
    /// order.
    pub fn iter_work(&self) -> impl Iterator<Item = &Work> + '_ {
        self.ordered_work.values()
    }

    /// Returns the number of work items currently materialized in projection
    /// state.
    #[must_use]
    pub fn work_count(&self) -> usize {
        self.ordered_work.len()
    }

    /// Returns claimable work items in deterministic ID order.
    #[must_use]
    pub fn claimable_work(&self) -> Vec<&Work> {
        self.ordered_work
            .values()
            .filter(|work| work.state.is_claimable())
            .collect()
    }

    /// Evaluates incoming dependency edges for a target work item.
    #[must_use]
    pub fn evaluate_work_dependencies(
        &self,
        work_id: &str,
        evaluation_time_ns: u64,
    ) -> WorkDependencyEvaluation {
        let mut diagnostics = Vec::new();

        let mut incoming_blocks: Vec<&ActiveWorkEdge> = self
            .active_edges
            .values()
            .filter(|edge| {
                edge.key.edge_type == WorkEdgeType::Blocks && edge.key.to_work_id == work_id
            })
            .collect();
        incoming_blocks.sort_by(|left, right| left.edge_id.cmp(&right.edge_id));

        for edge in incoming_blocks {
            let prerequisite_state = self
                .ordered_work
                .get(&edge.key.from_work_id)
                .map(|work| work.state);
            let active_waiver = self
                .active_waivers
                .get(&edge.key)
                .filter(|waiver| waiver.is_active(evaluation_time_ns));

            if let Some(waiver) = active_waiver {
                diagnostics.push(WorkDependencyDiagnostic {
                    reason_code: WORK_DIAGNOSTIC_REASON_BLOCKS_WAIVER_ACTIVE.to_string(),
                    severity: WorkDependencySeverity::Info,
                    message: format!(
                        "incoming BLOCKS edge waived for prerequisite '{}' -> '{}'",
                        edge.key.from_work_id, edge.key.to_work_id
                    ),
                    edge_id: edge.edge_id.clone(),
                    from_work_id: edge.key.from_work_id.clone(),
                    to_work_id: edge.key.to_work_id.clone(),
                    from_work_state: prerequisite_state,
                    waived: true,
                    waiver_id: waiver.waiver_id.clone(),
                    waiver_expires_at_ns: waiver.expires_at_ns,
                    waiver_remaining_ns: waiver
                        .expires_at_ns
                        .map(|expiry| expiry.saturating_sub(evaluation_time_ns)),
                    late_edge: edge.late_edge,
                });
            } else if prerequisite_state != Some(WorkState::Completed) {
                let prerequisite_label = prerequisite_state
                    .map_or_else(|| "UNKNOWN".to_string(), |state| state.as_str().to_string());
                diagnostics.push(WorkDependencyDiagnostic {
                    reason_code: WORK_DIAGNOSTIC_REASON_BLOCKS_UNSATISFIED.to_string(),
                    severity: WorkDependencySeverity::Error,
                    message: format!(
                        "incoming BLOCKS edge unsatisfied: prerequisite '{}' is '{}' (must be COMPLETED or waived)",
                        edge.key.from_work_id, prerequisite_label
                    ),
                    edge_id: edge.edge_id.clone(),
                    from_work_id: edge.key.from_work_id.clone(),
                    to_work_id: edge.key.to_work_id.clone(),
                    from_work_state: prerequisite_state,
                    waived: false,
                    waiver_id: None,
                    waiver_expires_at_ns: None,
                    waiver_remaining_ns: None,
                    late_edge: edge.late_edge,
                });
            }

            if edge.late_edge {
                let added_state = edge
                    .late_edge_state
                    .map_or_else(|| "UNKNOWN".to_string(), |state| state.as_str().to_string());
                diagnostics.push(WorkDependencyDiagnostic {
                    reason_code: WORK_DIAGNOSTIC_REASON_BLOCKS_LATE_EDGE.to_string(),
                    severity: WorkDependencySeverity::Warning,
                    message: format!(
                        "late BLOCKS edge detected: '{}' -> '{}' was added after dependent reached '{}'",
                        edge.key.from_work_id, edge.key.to_work_id, added_state
                    ),
                    edge_id: edge.edge_id.clone(),
                    from_work_id: edge.key.from_work_id.clone(),
                    to_work_id: edge.key.to_work_id.clone(),
                    from_work_state: prerequisite_state,
                    waived: active_waiver.is_some(),
                    waiver_id: active_waiver.and_then(|waiver| waiver.waiver_id.clone()),
                    waiver_expires_at_ns: active_waiver.and_then(|waiver| waiver.expires_at_ns),
                    waiver_remaining_ns: active_waiver
                        .and_then(|waiver| waiver.expires_at_ns)
                        .map(|expiry| expiry.saturating_sub(evaluation_time_ns)),
                    late_edge: true,
                });
            }
        }

        let implementer_claim_blocked = diagnostics
            .iter()
            .any(|diagnostic| diagnostic.reason_code == WORK_DIAGNOSTIC_REASON_BLOCKS_UNSATISFIED);

        WorkDependencyEvaluation {
            implementer_claim_blocked,
            diagnostics,
        }
    }

    fn apply_reducer_event(&mut self, event: &EventRecord) -> Result<(), WorkProjectionError> {
        let seq_id = event.seq_id.unwrap_or(0);
        let ctx = ReducerContext::new(seq_id);
        self.reducer.apply(event, &ctx)?;
        Ok(())
    }

    fn apply_work_graph_event(&mut self, event: ParsedWorkGraphEvent, _timestamp_ns: u64) {
        match event {
            ParsedWorkGraphEvent::Added(added) => {
                let key = WorkEdgeKey {
                    from_work_id: added.from_work_id,
                    to_work_id: added.to_work_id,
                    edge_type: added.edge_type,
                };
                let edge_id = added.edge_id.unwrap_or_else(|| derive_edge_id(&key));

                let dependent_state = self
                    .reducer
                    .state()
                    .work_items
                    .get(&key.to_work_id)
                    .map(|work| work.state);
                let late_edge = dependent_state.is_some_and(|state| {
                    matches!(
                        state,
                        WorkState::Claimed | WorkState::InProgress | WorkState::CiPending
                    )
                });

                // A fresh edge add supersedes prior waivers for the same key.
                self.active_waivers.remove(&key);

                self.active_edges.insert(
                    key.clone(),
                    ActiveWorkEdge {
                        key,
                        edge_id,
                        late_edge,
                        late_edge_state: dependent_state,
                    },
                );
            },
            ParsedWorkGraphEvent::Removed(removed) => {
                let keys_to_remove: Vec<WorkEdgeKey> = self
                    .active_edges
                    .keys()
                    .filter(|key| {
                        key.from_work_id == removed.from_work_id
                            && key.to_work_id == removed.to_work_id
                            && removed
                                .edge_type
                                .is_none_or(|edge_type| key.edge_type == edge_type)
                    })
                    .cloned()
                    .collect();
                for key in keys_to_remove {
                    self.active_edges.remove(&key);
                    self.active_waivers.remove(&key);
                }

                if let Some(edge_id) = removed.edge_id {
                    let key_by_edge_id = self
                        .active_edges
                        .iter()
                        .find_map(|(key, edge)| (edge.edge_id == edge_id).then(|| key.clone()));
                    if let Some(key) = key_by_edge_id {
                        self.active_edges.remove(&key);
                        self.active_waivers.remove(&key);
                    }
                }
            },
            ParsedWorkGraphEvent::Waived(waived) => {
                let matching_keys: Vec<WorkEdgeKey> = self
                    .active_edges
                    .keys()
                    .filter(|key| {
                        key.from_work_id == waived.from_work_id
                            && key.to_work_id == waived.to_work_id
                            && waived
                                .edge_type
                                .is_none_or(|edge_type| key.edge_type == edge_type)
                    })
                    .cloned()
                    .collect();

                for key in matching_keys {
                    self.active_waivers.insert(
                        key,
                        ActiveWorkEdgeWaiver {
                            waiver_id: waived.waiver_id.clone(),
                            expires_at_ns: waived.expires_at_ns,
                        },
                    );
                }
            },
        }
    }

    fn reindex(&mut self) {
        self.ordered_work = self
            .reducer
            .state()
            .work_items
            .iter()
            .map(|(work_id, work)| (work_id.clone(), work.clone()))
            .collect();
    }
}

/// Converts daemon signed events into canonical `work.*` reducer events.
///
/// Non-work events are ignored. Transitional daemon legacy events
/// (`work_claimed`, `work_transitioned`) are normalized into `work.*` protobuf
/// payloads consumed by `WorkReducer`.
pub fn translate_signed_events(
    events: &[SignedLedgerEvent],
) -> Result<Vec<EventRecord>, WorkProjectionError> {
    let mut ordered: Vec<(usize, &SignedLedgerEvent)> = events.iter().enumerate().collect();
    ordered.sort_by_key(|(idx, event)| (event.timestamp_ns, *idx as u64));

    let mut reducer_events = Vec::new();
    let mut opened_work_ids = BTreeSet::new();
    let mut next_seq_id = 1u64;

    for (_, event) in ordered {
        let translated = translate_signed_event(event, &mut opened_work_ids, &mut next_seq_id)?;
        reducer_events.extend(translated);
    }

    Ok(reducer_events)
}

fn translate_signed_event(
    event: &SignedLedgerEvent,
    opened_work_ids: &mut BTreeSet<String>,
    next_seq_id: &mut u64,
) -> Result<Vec<EventRecord>, WorkProjectionError> {
    let mut translated = Vec::new();
    let mut push_event =
        |event_type: &str, work_id: &str, actor_id: &str, payload: Vec<u8>, timestamp_ns: u64| {
            translated.push(build_event_record(
                event_type,
                work_id,
                actor_id,
                payload,
                timestamp_ns,
                *next_seq_id,
            ));
            *next_seq_id = next_seq_id.saturating_add(1);
        };

    match event.event_type.as_str() {
        // Native reducer event family (already canonical names).
        "work.opened" | "work.transitioned" | "work.completed" | "work.aborted"
        | "work.pr_associated" => {
            let reducer_payload =
                decode_canonical_work_event_payload(&event.payload, &event.event_type)?;
            if let Some(work_id) = extract_work_id_from_work_event(&reducer_payload) {
                opened_work_ids.insert(work_id);
            }
            push_event(
                &event.event_type,
                &event.work_id,
                &event.actor_id,
                reducer_payload,
                event.timestamp_ns,
            );
        },

        // Transitional daemon event: claim anchor. We synthesize only
        // work.opened; the authoritative claim state comes from
        // work_transitioned(Open->Claimed).
        "work_claimed" => {
            let work_id = extract_work_id_from_json_payload(
                &event.payload,
                "work_claimed",
                "work_id",
                &event.work_id,
            )?;

            if opened_work_ids.insert(work_id.clone()) {
                push_event(
                    "work.opened",
                    &work_id,
                    &event.actor_id,
                    helpers::work_opened_payload(
                        &work_id,
                        DEFAULT_SYNTHETIC_WORK_TYPE,
                        Vec::new(),
                        Vec::new(),
                        Vec::new(),
                    ),
                    event.timestamp_ns,
                );
            }
        },

        // Transitional daemon event: JSON transition payload.
        "work_transitioned" => {
            let transition = parse_work_transitioned_payload(&event.payload)?;

            if transition.from_state == "OPEN" && opened_work_ids.insert(transition.work_id.clone())
            {
                push_event(
                    "work.opened",
                    &transition.work_id,
                    &event.actor_id,
                    helpers::work_opened_payload(
                        &transition.work_id,
                        DEFAULT_SYNTHETIC_WORK_TYPE,
                        Vec::new(),
                        Vec::new(),
                        Vec::new(),
                    ),
                    event.timestamp_ns,
                );
            }

            push_event(
                "work.transitioned",
                &transition.work_id,
                &event.actor_id,
                helpers::work_transitioned_payload_with_sequence(
                    &transition.work_id,
                    &transition.from_state,
                    &transition.to_state,
                    &transition.rationale_code,
                    transition.previous_transition_count,
                ),
                event.timestamp_ns,
            );
        },

        _ => {},
    }

    Ok(translated)
}

#[derive(Debug, Deserialize)]
struct WorkEventEnvelopeJson {
    event_type: String,
    session_id: String,
    actor_id: String,
    payload: String,
    #[serde(flatten)]
    _extra_fields: BTreeMap<String, serde_json::Value>,
}

fn decode_canonical_work_event_payload(
    payload: &[u8],
    event_type: &str,
) -> Result<Vec<u8>, WorkProjectionError> {
    if payload.len() > MAX_CANONICAL_WORK_EVENT_JSON_BYTES {
        return Err(WorkProjectionError::InvalidPayload {
            event_type: event_type.to_string(),
            reason: format!(
                "payload exceeds maximum {MAX_CANONICAL_WORK_EVENT_JSON_BYTES} bytes for JSON \
                 envelope decode"
            ),
        });
    }

    if payload.first() != Some(&b'{') {
        return Err(WorkProjectionError::InvalidPayload {
            event_type: event_type.to_string(),
            reason: "work.* payload must use JSON session envelope; legacy raw protobuf payloads are no longer supported".to_string(),
        });
    }

    let session_envelope =
        serde_json::from_slice::<WorkEventEnvelopeJson>(payload).map_err(|e| {
            WorkProjectionError::InvalidPayload {
                event_type: event_type.to_string(),
                reason: format!("work.* payload is not a valid JSON session envelope: {e}"),
            }
        })?;
    if session_envelope.event_type != event_type {
        return Err(WorkProjectionError::InvalidPayload {
            event_type: event_type.to_string(),
            reason: format!(
                "session envelope event_type '{}' does not match ledger event_type '{}'",
                session_envelope.event_type, event_type
            ),
        });
    }
    if session_envelope.session_id.is_empty() || session_envelope.actor_id.is_empty() {
        return Err(WorkProjectionError::InvalidPayload {
            event_type: event_type.to_string(),
            reason: "session envelope missing required identity fields".to_string(),
        });
    }
    let wrapped_payload = session_envelope.payload;

    if wrapped_payload.len() > MAX_CANONICAL_WORK_EVENT_HEX_CHARS {
        return Err(WorkProjectionError::InvalidPayload {
            event_type: event_type.to_string(),
            reason: format!(
                "wrapped work.* payload hex exceeds maximum {MAX_CANONICAL_WORK_EVENT_HEX_CHARS} \
                 characters"
            ),
        });
    }

    let decoded =
        hex::decode(&wrapped_payload).map_err(|error| WorkProjectionError::InvalidPayload {
            event_type: event_type.to_string(),
            reason: format!("wrapped work.* payload hex decode failed: {error}"),
        })?;

    if decoded.len() > MAX_CANONICAL_WORK_EVENT_DECODED_BYTES {
        return Err(WorkProjectionError::InvalidPayload {
            event_type: event_type.to_string(),
            reason: format!(
                "wrapped work.* payload exceeds maximum {MAX_CANONICAL_WORK_EVENT_DECODED_BYTES} \
                 bytes after hex decode"
            ),
        });
    }

    WorkEvent::decode(decoded.as_slice()).map_err(|error| WorkProjectionError::InvalidPayload {
        event_type: event_type.to_string(),
        reason: format!("wrapped work.* payload does not decode as WorkEvent: {error}"),
    })?;

    Ok(decoded)
}

fn decode_work_graph_event(
    event: &SignedLedgerEvent,
) -> Result<Option<ParsedWorkGraphEvent>, WorkProjectionError> {
    let Some(kind) = canonical_work_graph_event_kind(&event.event_type) else {
        return Ok(None);
    };

    if event.payload.len() > MAX_WORK_GRAPH_EVENT_BYTES {
        return Err(WorkProjectionError::InvalidPayload {
            event_type: event.event_type.clone(),
            reason: format!(
                "payload exceeds maximum {MAX_WORK_GRAPH_EVENT_BYTES} bytes for work graph decode"
            ),
        });
    }

    decode_work_graph_payload(kind, &event.payload, &event.event_type, 0).map(Some)
}

fn decode_work_graph_payload(
    kind: WorkGraphEventKind,
    payload: &[u8],
    event_type: &str,
    depth: usize,
) -> Result<ParsedWorkGraphEvent, WorkProjectionError> {
    if depth > MAX_WORK_GRAPH_JSON_DEPTH {
        return Err(WorkProjectionError::InvalidPayload {
            event_type: event_type.to_string(),
            reason: "nested payload wrappers exceed maximum depth".to_string(),
        });
    }

    if let Ok(envelope) = WorkGraphEvent::decode(payload) {
        if let Some(parsed) = parse_work_graph_envelope(kind, envelope, event_type)? {
            return Ok(parsed);
        }
    }

    match kind {
        WorkGraphEventKind::Added => {
            if let Ok(added) = WorkEdgeAdded::decode(payload) {
                return Ok(ParsedWorkGraphEvent::Added(ParsedWorkEdgeAdded {
                    from_work_id: added.from_work_id,
                    to_work_id: added.to_work_id,
                    edge_type: parse_required_work_edge_type_raw(
                        added.edge_type,
                        event_type,
                        "edge_type",
                    )?,
                    edge_id: None,
                }));
            }
        },
        WorkGraphEventKind::Removed => {
            if let Ok(removed) = WorkEdgeRemoved::decode(payload) {
                return Ok(ParsedWorkGraphEvent::Removed(ParsedWorkEdgeRemoved {
                    from_work_id: removed.from_work_id,
                    to_work_id: removed.to_work_id,
                    edge_type: None,
                    edge_id: None,
                }));
            }
        },
        WorkGraphEventKind::Waived => {
            if let Ok(waived) = WorkEdgeWaived::decode(payload) {
                return Ok(ParsedWorkGraphEvent::Waived(ParsedWorkEdgeWaived {
                    from_work_id: waived.from_work_id,
                    to_work_id: waived.to_work_id,
                    edge_type: Some(parse_required_work_edge_type_raw(
                        waived.original_edge_type,
                        event_type,
                        "original_edge_type",
                    )?),
                    waiver_id: None,
                    expires_at_ns: None,
                }));
            }
        },
    }

    let value: serde_json::Value =
        serde_json::from_slice(payload).map_err(|error| WorkProjectionError::InvalidPayload {
            event_type: event_type.to_string(),
            reason: format!("protobuf and JSON decode failed: {error}"),
        })?;

    if let Some(inner_payload) = value
        .get("payload")
        .and_then(serde_json::Value::as_str)
        .filter(|_| value.get("from_work_id").is_none() && value.get("to_work_id").is_none())
    {
        let decoded =
            hex::decode(inner_payload).map_err(|error| WorkProjectionError::InvalidPayload {
                event_type: event_type.to_string(),
                reason: format!("hex decode of wrapped payload failed: {error}"),
            })?;
        return decode_work_graph_payload(kind, &decoded, event_type, depth + 1);
    }

    match kind {
        WorkGraphEventKind::Added => {
            parse_added_from_json(&value, event_type).map(ParsedWorkGraphEvent::Added)
        },
        WorkGraphEventKind::Removed => {
            parse_removed_from_json(&value, event_type).map(ParsedWorkGraphEvent::Removed)
        },
        WorkGraphEventKind::Waived => {
            parse_waived_from_json(&value, event_type).map(ParsedWorkGraphEvent::Waived)
        },
    }
}

fn parse_work_graph_envelope(
    expected_kind: WorkGraphEventKind,
    envelope: WorkGraphEvent,
    event_type: &str,
) -> Result<Option<ParsedWorkGraphEvent>, WorkProjectionError> {
    let Some(event) = envelope.event else {
        return Ok(None);
    };

    match (expected_kind, event) {
        (WorkGraphEventKind::Added, work_graph_event::Event::Added(added)) => {
            Ok(Some(ParsedWorkGraphEvent::Added(ParsedWorkEdgeAdded {
                from_work_id: added.from_work_id,
                to_work_id: added.to_work_id,
                edge_type: parse_required_work_edge_type_raw(
                    added.edge_type,
                    event_type,
                    "edge_type",
                )?,
                edge_id: None,
            })))
        },
        (WorkGraphEventKind::Removed, work_graph_event::Event::Removed(removed)) => {
            Ok(Some(ParsedWorkGraphEvent::Removed(ParsedWorkEdgeRemoved {
                from_work_id: removed.from_work_id,
                to_work_id: removed.to_work_id,
                edge_type: None,
                edge_id: None,
            })))
        },
        (WorkGraphEventKind::Waived, work_graph_event::Event::Waived(waived)) => {
            Ok(Some(ParsedWorkGraphEvent::Waived(ParsedWorkEdgeWaived {
                from_work_id: waived.from_work_id,
                to_work_id: waived.to_work_id,
                edge_type: Some(parse_required_work_edge_type_raw(
                    waived.original_edge_type,
                    event_type,
                    "original_edge_type",
                )?),
                waiver_id: None,
                expires_at_ns: None,
            })))
        },
        _ => Err(WorkProjectionError::InvalidPayload {
            event_type: event_type.to_string(),
            reason: "work graph envelope variant does not match event_type".to_string(),
        }),
    }
}

fn parse_added_from_json(
    value: &serde_json::Value,
    event_type: &str,
) -> Result<ParsedWorkEdgeAdded, WorkProjectionError> {
    let from_work_id = json_required_string(value, "from_work_id", event_type)?;
    let to_work_id = json_required_string(value, "to_work_id", event_type)?;
    let edge_type = parse_required_work_edge_type_json(value, "edge_type", event_type)?;
    let edge_id = json_optional_string(value, "edge_id");

    Ok(ParsedWorkEdgeAdded {
        from_work_id,
        to_work_id,
        edge_type,
        edge_id,
    })
}

fn parse_removed_from_json(
    value: &serde_json::Value,
    event_type: &str,
) -> Result<ParsedWorkEdgeRemoved, WorkProjectionError> {
    let from_work_id = json_required_string(value, "from_work_id", event_type)?;
    let to_work_id = json_required_string(value, "to_work_id", event_type)?;
    let edge_type = parse_optional_work_edge_type_json(value, "edge_type", event_type)?;
    let edge_id = json_optional_string(value, "edge_id");

    Ok(ParsedWorkEdgeRemoved {
        from_work_id,
        to_work_id,
        edge_type,
        edge_id,
    })
}

fn parse_waived_from_json(
    value: &serde_json::Value,
    event_type: &str,
) -> Result<ParsedWorkEdgeWaived, WorkProjectionError> {
    let from_work_id = json_required_string(value, "from_work_id", event_type)?;
    let to_work_id = json_required_string(value, "to_work_id", event_type)?;
    let edge_type = parse_optional_work_edge_type_json(value, "original_edge_type", event_type)?
        .or(parse_optional_work_edge_type_json(
            value,
            "edge_type",
            event_type,
        )?)
        .ok_or_else(|| WorkProjectionError::InvalidPayload {
            event_type: event_type.to_string(),
            reason: "missing or invalid original_edge_type".to_string(),
        })?;
    let waiver_id = json_optional_string(value, "waiver_id");
    let expires_at_ns = value
        .get("expires_at_ns")
        .and_then(parse_u64_json)
        .or_else(|| value.get("waiver_expires_at_ns").and_then(parse_u64_json));

    Ok(ParsedWorkEdgeWaived {
        from_work_id,
        to_work_id,
        edge_type: Some(edge_type),
        waiver_id,
        expires_at_ns,
    })
}

fn parse_required_work_edge_type_raw(
    raw: i32,
    event_type: &str,
    field: &str,
) -> Result<WorkEdgeType, WorkProjectionError> {
    let parsed = WorkEdgeType::try_from(raw).map_err(|_| WorkProjectionError::InvalidPayload {
        event_type: event_type.to_string(),
        reason: format!("invalid {field}: unknown edge_type value {raw}"),
    })?;
    if parsed == WorkEdgeType::Unspecified {
        return Err(WorkProjectionError::InvalidPayload {
            event_type: event_type.to_string(),
            reason: format!("invalid {field}: WORK_EDGE_TYPE_UNSPECIFIED is not allowed"),
        });
    }
    Ok(parsed)
}

fn parse_required_work_edge_type_json(
    value: &serde_json::Value,
    field: &str,
    event_type: &str,
) -> Result<WorkEdgeType, WorkProjectionError> {
    parse_optional_work_edge_type_json(value, field, event_type)?.ok_or_else(|| {
        WorkProjectionError::InvalidPayload {
            event_type: event_type.to_string(),
            reason: format!("missing or invalid {field}"),
        }
    })
}

fn parse_optional_work_edge_type_json(
    value: &serde_json::Value,
    field: &str,
    event_type: &str,
) -> Result<Option<WorkEdgeType>, WorkProjectionError> {
    let Some(raw) = value.get(field) else {
        return Ok(None);
    };

    let parsed =
        parse_work_edge_type_json(raw).ok_or_else(|| WorkProjectionError::InvalidPayload {
            event_type: event_type.to_string(),
            reason: format!("missing or invalid {field}"),
        })?;
    if parsed == WorkEdgeType::Unspecified {
        return Err(WorkProjectionError::InvalidPayload {
            event_type: event_type.to_string(),
            reason: format!("invalid {field}: WORK_EDGE_TYPE_UNSPECIFIED is not allowed"),
        });
    }

    Ok(Some(parsed))
}

fn parse_work_edge_type_json(value: &serde_json::Value) -> Option<WorkEdgeType> {
    if let Some(raw) = value.as_i64() {
        return i32::try_from(raw)
            .ok()
            .and_then(|numeric| WorkEdgeType::try_from(numeric).ok());
    }

    let text = value.as_str()?;
    let normalized = text
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .collect::<String>()
        .to_ascii_uppercase();
    match normalized.as_str() {
        "WORKEDGETYPEUNSPECIFIED" | "UNSPECIFIED" => Some(WorkEdgeType::Unspecified),
        "WORKEDGETYPEDEPENDENCY" | "DEPENDENCY" => Some(WorkEdgeType::Dependency),
        "WORKEDGETYPEBLOCKS" | "BLOCKS" => Some(WorkEdgeType::Blocks),
        "WORKEDGETYPEENABLES" | "ENABLES" => Some(WorkEdgeType::Enables),
        "WORKEDGETYPESEQUENCE" | "SEQUENCE" => Some(WorkEdgeType::Sequence),
        _ => None,
    }
}

fn parse_u64_json(value: &serde_json::Value) -> Option<u64> {
    value
        .as_u64()
        .or_else(|| value.as_str().and_then(|raw| raw.parse::<u64>().ok()))
}

fn json_required_string(
    value: &serde_json::Value,
    field: &str,
    event_type: &str,
) -> Result<String, WorkProjectionError> {
    json_optional_string(value, field).ok_or_else(|| WorkProjectionError::InvalidPayload {
        event_type: event_type.to_string(),
        reason: format!("missing or invalid {field}"),
    })
}

fn json_optional_string(value: &serde_json::Value, field: &str) -> Option<String> {
    value
        .get(field)
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(str::to_string)
}

fn canonical_work_graph_event_kind(event_type: &str) -> Option<WorkGraphEventKind> {
    let normalized = event_type
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .collect::<String>()
        .to_ascii_lowercase();
    match normalized.as_str() {
        "workgraphedgeadded" => Some(WorkGraphEventKind::Added),
        "workgraphedgeremoved" => Some(WorkGraphEventKind::Removed),
        "workgraphedgewaived" => Some(WorkGraphEventKind::Waived),
        _ => None,
    }
}

fn derive_edge_id(key: &WorkEdgeKey) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(GRAPH_EDGE_ID_DOMAIN_PREFIX);
    hasher.update(key.from_work_id.as_bytes());
    hasher.update(&[0]);
    hasher.update(key.to_work_id.as_bytes());
    hasher.update(&[0]);
    hasher.update(key.edge_type.as_str_name().as_bytes());
    format!("EDGE-{}", hex::encode(hasher.finalize().as_bytes()))
}

#[derive(Debug)]
struct ParsedTransition {
    work_id: String,
    from_state: String,
    to_state: String,
    rationale_code: String,
    previous_transition_count: u32,
}

fn parse_work_transitioned_payload(
    payload: &[u8],
) -> Result<ParsedTransition, WorkProjectionError> {
    let value: serde_json::Value =
        serde_json::from_slice(payload).map_err(|err| WorkProjectionError::InvalidPayload {
            event_type: "work_transitioned".to_string(),
            reason: err.to_string(),
        })?;

    let work_id = value
        .get("work_id")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| WorkProjectionError::InvalidPayload {
            event_type: "work_transitioned".to_string(),
            reason: "missing work_id".to_string(),
        })?
        .to_string();

    let from_raw = value
        .get("from_state")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| WorkProjectionError::InvalidPayload {
            event_type: "work_transitioned".to_string(),
            reason: "missing from_state".to_string(),
        })?;

    let to_raw = value
        .get("to_state")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| WorkProjectionError::InvalidPayload {
            event_type: "work_transitioned".to_string(),
            reason: "missing to_state".to_string(),
        })?;

    let from_state =
        normalize_work_state(from_raw).ok_or_else(|| WorkProjectionError::InvalidPayload {
            event_type: "work_transitioned".to_string(),
            reason: format!("unsupported from_state: {from_raw}"),
        })?;

    let to_state =
        normalize_work_state(to_raw).ok_or_else(|| WorkProjectionError::InvalidPayload {
            event_type: "work_transitioned".to_string(),
            reason: format!("unsupported to_state: {to_raw}"),
        })?;

    let rationale_code = value
        .get("rationale_code")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("runtime_transition")
        .to_string();

    let previous_transition_count = value
        .get("previous_transition_count")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| WorkProjectionError::InvalidPayload {
            event_type: "work_transitioned".to_string(),
            reason: "missing previous_transition_count".to_string(),
        })?;

    let previous_transition_count = u32::try_from(previous_transition_count).map_err(|_| {
        WorkProjectionError::InvalidTransitionCount {
            event_type: "work_transitioned".to_string(),
            value: previous_transition_count,
        }
    })?;

    Ok(ParsedTransition {
        work_id,
        from_state,
        to_state,
        rationale_code,
        previous_transition_count,
    })
}

fn extract_work_id_from_json_payload(
    payload: &[u8],
    event_type: &str,
    field: &str,
    fallback: &str,
) -> Result<String, WorkProjectionError> {
    let value: serde_json::Value =
        serde_json::from_slice(payload).map_err(|err| WorkProjectionError::InvalidPayload {
            event_type: event_type.to_string(),
            reason: err.to_string(),
        })?;

    if let Some(work_id) = value.get(field).and_then(serde_json::Value::as_str) {
        return Ok(work_id.to_string());
    }

    if !fallback.is_empty() {
        return Ok(fallback.to_string());
    }

    Err(WorkProjectionError::InvalidPayload {
        event_type: event_type.to_string(),
        reason: format!("missing {field}"),
    })
}

fn normalize_work_state(raw_state: &str) -> Option<String> {
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

fn extract_work_id_from_work_event(payload: &[u8]) -> Option<String> {
    let decoded = WorkEvent::decode(payload).ok()?;
    match decoded.event {
        Some(work_event::Event::Opened(evt)) => Some(evt.work_id),
        Some(work_event::Event::Transitioned(evt)) => Some(evt.work_id),
        Some(work_event::Event::Completed(evt)) => Some(evt.work_id),
        Some(work_event::Event::Aborted(evt)) => Some(evt.work_id),
        Some(work_event::Event::PrAssociated(evt)) => Some(evt.work_id),
        None => None,
    }
}

fn build_event_record(
    event_type: &str,
    session_id: &str,
    actor_id: &str,
    payload: Vec<u8>,
    timestamp_ns: u64,
    seq_id: u64,
) -> EventRecord {
    let mut event = EventRecord::with_timestamp(
        event_type.to_string(),
        session_id.to_string(),
        actor_id.to_string(),
        payload,
        timestamp_ns,
    );
    event.seq_id = Some(seq_id);
    event
}

/// Resolves the domain-separation prefix for signature verification.
///
/// Returns `None` for event types that are not work-relevant (these are
/// skipped during projection rebuild anyway).
fn domain_prefix_for_event_type(event_type: &str) -> Option<&'static [u8]> {
    match event_type {
        "work_claimed" => Some(WORK_CLAIMED_DOMAIN_PREFIX),
        "work_transitioned" => Some(WORK_TRANSITIONED_DOMAIN_PREFIX),
        // Native protobuf work events do not carry JCS signatures; they
        // are verified structurally by the reducer.
        _ => None,
    }
}

/// Verifies Ed25519 signatures on signed ledger events.
///
/// Returns the input events unchanged on success, or fails closed with
/// `WorkProjectionError::SignatureVerificationFailed`. Only events with
/// domain-bound signatures (`work_claimed`, `work_transitioned`) are
/// verified. Events without a known domain prefix are passed through
/// (they are filtered by `translate_signed_events` anyway).
pub fn verify_signed_events(
    events: &[SignedLedgerEvent],
    emitter: &Arc<dyn LedgerEventEmitter>,
) -> Result<Vec<SignedLedgerEvent>, WorkProjectionError> {
    let vk = emitter.verifying_key();
    let mut verified = Vec::with_capacity(events.len());

    for event in events {
        if let Some(prefix) = domain_prefix_for_event_type(&event.event_type) {
            // Reconstruct canonical bytes: domain prefix + payload.
            let mut canonical_bytes = Vec::with_capacity(prefix.len() + event.payload.len());
            canonical_bytes.extend_from_slice(prefix);
            canonical_bytes.extend_from_slice(&event.payload);

            // Parse signature bytes into Ed25519 signature.
            let sig_bytes: [u8; 64] = event.signature.as_slice().try_into().map_err(|_| {
                WorkProjectionError::SignatureVerificationFailed {
                    event_id: event.event_id.clone(),
                    reason: format!(
                        "invalid signature length: expected 64, got {}",
                        event.signature.len()
                    ),
                }
            })?;
            let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);

            // Fail-closed: reject events with invalid signatures.
            vk.verify(&canonical_bytes, &signature).map_err(|e| {
                WorkProjectionError::SignatureVerificationFailed {
                    event_id: event.event_id.clone(),
                    reason: format!("Ed25519 verification failed: {e}"),
                }
            })?;
        }

        verified.push(event.clone());
    }

    Ok(verified)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signed_event(
        event_type: &str,
        work_id: &str,
        payload: Vec<u8>,
        timestamp_ns: u64,
    ) -> SignedLedgerEvent {
        SignedLedgerEvent {
            event_id: format!("EVT-{event_type}-{work_id}-{timestamp_ns}"),
            event_type: event_type.to_string(),
            work_id: work_id.to_string(),
            actor_id: "actor:test".to_string(),
            payload,
            signature: vec![0u8; 64],
            timestamp_ns,
        }
    }

    fn work_opened_event(work_id: &str, timestamp_ns: u64) -> SignedLedgerEvent {
        signed_event(
            "work.opened",
            work_id,
            helpers::work_opened_payload(work_id, "TICKET", vec![0x11; 32], vec![], vec![]),
            timestamp_ns,
        )
    }

    fn work_transitioned_event(
        work_id: &str,
        from_state: &str,
        to_state: &str,
        previous_transition_count: u32,
        timestamp_ns: u64,
    ) -> SignedLedgerEvent {
        let payload = serde_json::json!({
            "work_id": work_id,
            "from_state": from_state,
            "to_state": to_state,
            "rationale_code": "test_transition",
            "previous_transition_count": previous_transition_count,
        });
        signed_event(
            "work_transitioned",
            work_id,
            serde_json::to_vec(&payload).expect("work_transitioned payload should encode"),
            timestamp_ns,
        )
    }

    fn work_graph_added_event(
        from_work_id: &str,
        to_work_id: &str,
        edge_type: WorkEdgeType,
        timestamp_ns: u64,
    ) -> SignedLedgerEvent {
        let mut payload = Vec::new();
        WorkEdgeAdded {
            from_work_id: from_work_id.to_string(),
            to_work_id: to_work_id.to_string(),
            edge_type: edge_type as i32,
            rationale: "test-edge".to_string(),
        }
        .encode(&mut payload)
        .expect("WorkEdgeAdded protobuf should encode");

        signed_event("work_graph.edge.added", to_work_id, payload, timestamp_ns)
    }

    fn work_graph_added_raw_event(
        from_work_id: &str,
        to_work_id: &str,
        edge_type_raw: i32,
        timestamp_ns: u64,
    ) -> SignedLedgerEvent {
        let mut payload = Vec::new();
        WorkEdgeAdded {
            from_work_id: from_work_id.to_string(),
            to_work_id: to_work_id.to_string(),
            edge_type: edge_type_raw,
            rationale: "test-edge-raw".to_string(),
        }
        .encode(&mut payload)
        .expect("WorkEdgeAdded protobuf should encode");

        signed_event("work_graph.edge.added", to_work_id, payload, timestamp_ns)
    }

    fn work_graph_waived_json_event(
        from_work_id: &str,
        to_work_id: &str,
        waiver_id: &str,
        expires_at_ns: u64,
        timestamp_ns: u64,
    ) -> SignedLedgerEvent {
        let payload = serde_json::json!({
            "from_work_id": from_work_id,
            "to_work_id": to_work_id,
            "original_edge_type": "BLOCKS",
            "waiver_id": waiver_id,
            "expires_at_ns": expires_at_ns,
            "waiver_justification": "test-waiver",
        });
        signed_event(
            "work_graph.edge.waived",
            to_work_id,
            serde_json::to_vec(&payload).expect("WorkEdgeWaived JSON payload should encode"),
            timestamp_ns,
        )
    }

    fn work_graph_waived_raw_event(
        from_work_id: &str,
        to_work_id: &str,
        original_edge_type_raw: i32,
        timestamp_ns: u64,
    ) -> SignedLedgerEvent {
        let mut payload = Vec::new();
        WorkEdgeWaived {
            from_work_id: from_work_id.to_string(),
            to_work_id: to_work_id.to_string(),
            original_edge_type: original_edge_type_raw,
            waiver_justification: "test-waiver-raw".to_string(),
            waiver_actor_id: "actor:test".to_string(),
        }
        .encode(&mut payload)
        .expect("WorkEdgeWaived protobuf should encode");

        signed_event("work_graph.edge.waived", to_work_id, payload, timestamp_ns)
    }

    #[test]
    fn decode_canonical_work_event_payload_rejects_oversized_json_envelope() {
        let oversized = vec![b'x'; MAX_CANONICAL_WORK_EVENT_JSON_BYTES + 1];
        let result = decode_canonical_work_event_payload(&oversized, "work.opened");

        assert!(
            matches!(
                result,
                Err(WorkProjectionError::InvalidPayload { event_type, reason })
                    if event_type == "work.opened"
                        && reason.contains("payload exceeds maximum")
            ),
            "oversized JSON envelopes must be rejected before deserialization"
        );
    }

    #[test]
    fn decode_canonical_work_event_payload_rejects_oversized_protobuf_before_decode() {
        let payload = helpers::work_opened_payload(
            "W-projection-oversized-protobuf",
            "TICKET",
            vec![0x11; 32],
            vec!["R".repeat(MAX_CANONICAL_WORK_EVENT_JSON_BYTES)],
            vec![],
        );
        assert!(
            payload.len() > MAX_CANONICAL_WORK_EVENT_JSON_BYTES,
            "test fixture must exceed the canonical payload bound"
        );

        let result = decode_canonical_work_event_payload(&payload, "work.opened");
        assert!(
            matches!(
                result,
                Err(WorkProjectionError::InvalidPayload { event_type, reason })
                    if event_type == "work.opened"
                        && reason.contains("payload exceeds maximum")
            ),
            "oversized protobuf payloads must be rejected before decode attempts"
        );
    }

    #[test]
    fn decode_canonical_work_event_payload_rejects_raw_protobuf_when_not_json_prefixed() {
        let payload = helpers::work_opened_payload(
            "W-projection-raw-protobuf",
            "TICKET",
            vec![0x22; 32],
            vec![],
            vec![],
        );

        let result = decode_canonical_work_event_payload(&payload, "work.opened");
        assert!(
            matches!(
                result,
                Err(WorkProjectionError::InvalidPayload { event_type, reason })
                    if event_type == "work.opened"
                        && reason.contains("must use JSON session envelope")
            ),
            "legacy raw protobuf work payloads must be rejected after envelope cutover"
        );
    }

    #[test]
    fn decode_canonical_work_event_payload_decodes_json_envelope_when_prefixed_with_brace() {
        let opened_payload = helpers::work_opened_payload(
            "W-projection-json-envelope",
            "TICKET",
            vec![0x33; 32],
            vec![],
            vec![],
        );
        let envelope = serde_json::to_vec(&serde_json::json!({
            "event_type": "work.opened",
            "session_id": "W-projection-json-envelope",
            "actor_id": "actor:test-projection",
            "payload": hex::encode(&opened_payload),
            "ajc_id": "f".repeat(64),
        }))
        .expect("JSON envelope should encode");
        assert_eq!(
            envelope.first(),
            Some(&b'{'),
            "fixture must start with '{{' to exercise JSON-first format detection"
        );

        let decoded = decode_canonical_work_event_payload(&envelope, "work.opened")
            .expect("JSON envelope should decode");
        assert_eq!(
            decoded, opened_payload,
            "JSON envelopes must be unwrapped instead of treated as raw protobuf"
        );
    }

    #[test]
    fn decode_canonical_work_event_payload_rejects_payload_only_envelope() {
        let opened_payload = helpers::work_opened_payload(
            "W-projection-payload-only-envelope",
            "TICKET",
            vec![0x44; 32],
            vec![],
            vec![],
        );
        let envelope = serde_json::to_vec(&serde_json::json!({
            "payload": hex::encode(&opened_payload),
        }))
        .expect("payload-only envelope should encode");

        let result = decode_canonical_work_event_payload(&envelope, "work.opened");
        assert!(
            matches!(
                result,
                Err(WorkProjectionError::InvalidPayload { event_type, reason })
                    if event_type == "work.opened"
                        && reason.contains("valid JSON session envelope")
            ),
            "payload-only envelope must be rejected after envelope cutover"
        );
    }

    #[test]
    fn decode_canonical_work_event_payload_rejects_non_json_non_protobuf_payload() {
        let payload = b"not-a-valid-work-event".to_vec();
        let result = decode_canonical_work_event_payload(&payload, "work.opened");

        assert!(
            matches!(
                result,
                Err(WorkProjectionError::InvalidPayload { event_type, reason })
                    if event_type == "work.opened"
                        && reason.contains("must use JSON session envelope")
            ),
            "non-JSON-prefixed payloads must fail closed under envelope-only decoding"
        );
    }

    #[test]
    fn unsatisfied_blocks_edge_blocks_implementer_claim() {
        let prerequisite = "W-pre-001";
        let target = "W-target-001";
        let mut projection = WorkObjectProjection::new();

        let events = vec![
            work_opened_event(prerequisite, 1_000),
            work_opened_event(target, 1_001),
            work_graph_added_event(prerequisite, target, WorkEdgeType::Blocks, 1_002),
        ];

        projection
            .rebuild_from_signed_events(&events)
            .expect("projection rebuild should succeed");

        let evaluation = projection.evaluate_work_dependencies(target, 2_000);
        assert!(
            evaluation.implementer_claim_blocked,
            "unsatisfied incoming BLOCKS dependency must block implementer claimability"
        );
        assert!(
            evaluation
                .diagnostics
                .iter()
                .any(|item| item.reason_code == WORK_DIAGNOSTIC_REASON_BLOCKS_UNSATISFIED),
            "unsatisfied dependency diagnostic should be present"
        );
    }

    #[test]
    fn active_waiver_allows_implementer_claimability() {
        let prerequisite = "W-pre-002";
        let target = "W-target-002";
        let mut projection = WorkObjectProjection::new();

        let events = vec![
            work_opened_event(prerequisite, 1_000),
            work_opened_event(target, 1_001),
            work_graph_added_event(prerequisite, target, WorkEdgeType::Blocks, 1_002),
            work_graph_waived_json_event(prerequisite, target, "WVR-001", 5_000, 1_003),
        ];

        projection
            .rebuild_from_signed_events(&events)
            .expect("projection rebuild should succeed");

        let evaluation = projection.evaluate_work_dependencies(target, 2_000);
        assert!(
            !evaluation.implementer_claim_blocked,
            "active waiver must allow implementer claimability despite unsatisfied prerequisite"
        );

        let waiver = evaluation
            .diagnostics
            .iter()
            .find(|item| item.reason_code == WORK_DIAGNOSTIC_REASON_BLOCKS_WAIVER_ACTIVE)
            .expect("waiver diagnostic should be present");
        assert_eq!(waiver.waiver_id.as_deref(), Some("WVR-001"));
        assert_eq!(waiver.waiver_expires_at_ns, Some(5_000));
        assert_eq!(waiver.waiver_remaining_ns, Some(3_000));
    }

    #[test]
    fn late_edge_diagnostic_does_not_mutate_work_state() {
        let prerequisite = "W-pre-003";
        let target = "W-target-003";
        let mut projection = WorkObjectProjection::new();

        let events = vec![
            work_opened_event(prerequisite, 1_000),
            work_opened_event(target, 1_001),
            work_transitioned_event(target, "OPEN", "CLAIMED", 0, 1_002),
            work_transitioned_event(target, "CLAIMED", "IN_PROGRESS", 1, 1_003),
            work_graph_added_event(prerequisite, target, WorkEdgeType::Blocks, 1_004),
        ];

        projection
            .rebuild_from_signed_events(&events)
            .expect("projection rebuild should succeed");

        let work = projection
            .get_work(target)
            .expect("target work should exist in projection");
        assert_eq!(
            work.state,
            WorkState::InProgress,
            "late edge diagnostics must not mutate lifecycle state"
        );

        let evaluation = projection.evaluate_work_dependencies(target, 2_000);
        let late_edge = evaluation
            .diagnostics
            .iter()
            .find(|item| item.reason_code == WORK_DIAGNOSTIC_REASON_BLOCKS_LATE_EDGE)
            .expect("late edge diagnostic should be present");
        assert_eq!(late_edge.severity, WorkDependencySeverity::Warning);
        assert!(
            late_edge.late_edge,
            "late edge diagnostic must explicitly indicate late edge"
        );
    }

    #[test]
    fn malformed_added_edge_type_fails_closed() {
        let prerequisite = "W-pre-004";
        let target = "W-target-004";
        let mut projection = WorkObjectProjection::new();

        let events = vec![
            work_opened_event(prerequisite, 1_000),
            work_opened_event(target, 1_001),
            work_graph_added_raw_event(prerequisite, target, 99, 1_002),
        ];

        let result = projection.rebuild_from_signed_events(&events);
        assert!(
            matches!(result, Err(WorkProjectionError::InvalidPayload { .. })),
            "unknown edge_type values must fail-closed"
        );
    }

    #[test]
    fn malformed_waiver_edge_type_fails_closed() {
        let prerequisite = "W-pre-005";
        let target = "W-target-005";
        let mut projection = WorkObjectProjection::new();

        let events = vec![
            work_opened_event(prerequisite, 1_000),
            work_opened_event(target, 1_001),
            work_graph_added_event(prerequisite, target, WorkEdgeType::Blocks, 1_002),
            work_graph_waived_raw_event(prerequisite, target, 77, 1_003),
        ];

        let result = projection.rebuild_from_signed_events(&events);
        assert!(
            matches!(result, Err(WorkProjectionError::InvalidPayload { .. })),
            "unknown waiver edge_type values must fail-closed"
        );
    }

    #[test]
    fn unspecified_edge_type_fails_closed() {
        let prerequisite = "W-pre-006";
        let target = "W-target-006";
        let mut projection = WorkObjectProjection::new();

        let events = vec![
            work_opened_event(prerequisite, 1_000),
            work_opened_event(target, 1_001),
            work_graph_added_raw_event(
                prerequisite,
                target,
                WorkEdgeType::Unspecified as i32,
                1_002,
            ),
        ];

        let result = projection.rebuild_from_signed_events(&events);
        assert!(
            matches!(result, Err(WorkProjectionError::InvalidPayload { .. })),
            "WORK_EDGE_TYPE_UNSPECIFIED must fail-closed"
        );
    }
}
