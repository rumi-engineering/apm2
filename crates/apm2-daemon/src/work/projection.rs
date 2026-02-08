use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use apm2_core::events::{WorkEvent, work_event};
use apm2_core::ledger::EventRecord;
use apm2_core::reducer::{Reducer, ReducerContext};
use apm2_core::work::{Work, WorkError, WorkReducer, helpers};
use ed25519_dalek::Verifier;
use prost::Message;
use thiserror::Error;

use crate::protocol::dispatch::{
    LedgerEventEmitter, SignedLedgerEvent, WORK_CLAIMED_DOMAIN_PREFIX,
    WORK_TRANSITIONED_DOMAIN_PREFIX,
};

const DEFAULT_SYNTHETIC_WORK_TYPE: &str = "TICKET";

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

/// Ledger-backed `WorkObject` projection rebuilt through `WorkReducer`.
#[derive(Debug, Default)]
pub struct WorkObjectProjection {
    reducer: WorkReducer,
    ordered_work: BTreeMap<String, Work>,
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
        let reducer_events = translate_signed_events(events)?;
        self.rebuild_from_events(&reducer_events)
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

    /// Returns claimable work items in deterministic ID order.
    #[must_use]
    pub fn claimable_work(&self) -> Vec<&Work> {
        self.ordered_work
            .values()
            .filter(|work| work.state.is_claimable())
            .collect()
    }

    fn apply_reducer_event(&mut self, event: &EventRecord) -> Result<(), WorkProjectionError> {
        let seq_id = event.seq_id.unwrap_or(0);
        let ctx = ReducerContext::new(seq_id);
        self.reducer.apply(event, &ctx)?;
        Ok(())
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

    for (_, event) in ordered {
        match event.event_type.as_str() {
            // Native reducer event family (already canonical names).
            "work.opened" | "work.transitioned" | "work.completed" | "work.aborted"
            | "work.pr_associated" => {
                if let Some(work_id) = extract_work_id_from_work_event(&event.payload) {
                    opened_work_ids.insert(work_id);
                }
                reducer_events.push(build_event_record(
                    &event.event_type,
                    &event.work_id,
                    &event.actor_id,
                    event.payload.clone(),
                    event.timestamp_ns,
                    next_seq_id(&reducer_events),
                ));
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
                    reducer_events.push(build_event_record(
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
                        next_seq_id(&reducer_events),
                    ));
                }
            },

            // Transitional daemon event: JSON transition payload.
            "work_transitioned" => {
                let transition = parse_work_transitioned_payload(&event.payload)?;

                if transition.from_state == "OPEN"
                    && opened_work_ids.insert(transition.work_id.clone())
                {
                    reducer_events.push(build_event_record(
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
                        next_seq_id(&reducer_events),
                    ));
                }

                reducer_events.push(build_event_record(
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
                    next_seq_id(&reducer_events),
                ));
            },

            _ => {},
        }
    }

    Ok(reducer_events)
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

fn next_seq_id(events: &[EventRecord]) -> u64 {
    events.last().and_then(|event| event.seq_id).unwrap_or(0) + 1
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
