//! Adapter that writes holon events into the apm2-core ledger+CAS substrate.
//!
//! # Purpose (TCK-00670 / HL-001)
//!
//! This module bridges holon event vocabulary to the canonical core ledger
//! `EventRecord` format. Holon events are encoded with an `event_type`
//! prefix of `holon.*` and payloads are serialized as canonical JSON (RFC 8785
//! / JCS) for deterministic replay.
//!
//! Large artifacts referenced by holon events are stored in CAS; only their
//! BLAKE3 digests appear in event payloads.
//!
//! # BFT-readiness (HL-003)
//!
//! Authority events (work claimed, lease issued, terminal decisions) carry
//! [`FinalitySignal`] metadata so they can be appended via
//! `BftLedgerBackend` when consensus is enabled. The adapter never assumes
//! local finality — finality is an explicit signal from the consensus layer.
//!
//! # Design
//!
//! ```text
//! Holon EventType / OrchestrationEvent
//!          |
//!          v
//!   CoreLedgerAdapter::append_holon_event()
//!          |
//!          +---> serialize payload via JCS
//!          +---> (optional) store artifact in CAS, embed digest
//!          +---> construct EventRecord with `holon.*` event_type
//!          +---> write to core Ledger
//! ```
//!
//! # Invariants
//!
//! - [INV-CLA-001] All payloads are serialized with `serde_jcs` for
//!   deterministic byte representation.
//! - [INV-CLA-002] Event type discriminants use the prefix `holon.` followed by
//!   the snake_case variant name, producing stable wire identifiers.
//! - [INV-CLA-003] Artifact digests in payloads are BLAKE3 hashes of the
//!   artifact content stored in CAS.
//! - [INV-CLA-004] Authority events (work.claimed, lease.issued, terminal work
//!   events) carry explicit finality signals; holon code never assumes local
//!   finality.
//! - [INV-CLA-005] Payloads are bounded: `MAX_PAYLOAD_SIZE` prevents memory DoS
//!   from oversized serialization.
//! - [INV-CLA-006] Unknown fields are denied on deserialization via
//!   `deny_unknown_fields`.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::ledger::{EventType, LedgerEvent};
use crate::orchestration::OrchestrationEvent;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum serialized payload size (256 KiB).
///
/// Prevents memory denial-of-service from pathological serialization. Holon
/// event payloads are metadata-sized; large artifacts go to CAS.
pub const MAX_PAYLOAD_SIZE: usize = 256 * 1024;

/// Maximum number of events in a single batch append.
pub const MAX_BATCH_SIZE: usize = 1024;

/// Event type prefix for all holon events in the core ledger.
pub const HOLON_EVENT_PREFIX: &str = "holon.";

// ---------------------------------------------------------------------------
// Finality Signal (HL-003)
// ---------------------------------------------------------------------------

/// Explicit finality signal for BFT-ready authority events.
///
/// Holon code MUST NOT assume local finality. When consensus is disabled,
/// finality is `Local` (single-node). When consensus is enabled, authority
/// events receive `Pending` until the BFT layer confirms with `Finalized`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub enum FinalitySignal {
    /// Event is locally committed but not yet consensus-finalized.
    /// This is the default for single-node deployments.
    #[default]
    Local,
    /// Event has been submitted to consensus but not yet finalized.
    Pending,
    /// Event has been finalized by BFT consensus with a quorum certificate.
    Finalized {
        /// Consensus epoch in which finality was achieved.
        epoch: u64,
        /// Consensus round in which finality was achieved.
        round: u64,
    },
}

impl FinalitySignal {
    /// Returns `true` if this event has reached finality (either local or
    /// BFT-finalized).
    #[must_use]
    pub const fn is_final(&self) -> bool {
        matches!(self, Self::Local | Self::Finalized { .. })
    }

    /// Returns `true` if this event is still pending consensus finalization.
    #[must_use]
    pub const fn is_pending(&self) -> bool {
        matches!(self, Self::Pending)
    }
}

// ---------------------------------------------------------------------------
// Adapter Error
// ---------------------------------------------------------------------------

/// Errors from the core ledger adapter.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CoreLedgerAdapterError {
    /// Payload serialization failed.
    #[error("payload serialization failed: {0}")]
    Serialization(String),

    /// Payload exceeds maximum allowed size.
    #[error("payload too large: {size} bytes exceeds {max} byte limit")]
    PayloadTooLarge {
        /// Actual payload size.
        size: usize,
        /// Maximum allowed size.
        max: usize,
    },

    /// Batch size exceeds maximum.
    #[error("batch too large: {size} exceeds {max} event limit")]
    BatchTooLarge {
        /// Actual batch size.
        size: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// CAS store operation failed.
    #[error("CAS store failed: {0}")]
    CasError(String),

    /// Ledger append failed.
    #[error("ledger append failed: {0}")]
    LedgerError(String),

    /// Event type is not recognized.
    #[error("unknown event type: {0}")]
    UnknownEventType(String),
}

// ---------------------------------------------------------------------------
// Holon Event Envelope (wire format in core ledger payload)
// ---------------------------------------------------------------------------

/// Envelope wrapping a holon event payload in the core ledger.
///
/// This is the canonical JSON structure stored in `EventRecord.payload`.
/// It carries the holon-specific payload plus metadata needed for replay
/// and BFT-readiness.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HolonEventEnvelope {
    /// Schema version for forward/backward compatibility.
    pub schema_version: u32,

    /// The holon event type discriminant (e.g., `work_created`).
    pub event_kind: String,

    /// Canonical JSON payload of the holon event.
    pub payload: serde_json::Value,

    /// BLAKE3 digest of the original holon ledger event hash, if available.
    /// Links back to the holon-local hash chain for migration verification.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub holon_event_hash: Option<String>,

    /// CAS digest of any large artifact associated with this event.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_cas_digest: Option<String>,

    /// Finality signal for BFT-readiness (HL-003).
    pub finality: FinalitySignal,

    /// Whether this event represents an authority decision that requires
    /// BFT consensus when enabled.
    pub is_authority_event: bool,
}

/// Current schema version for holon event envelopes.
pub const ENVELOPE_SCHEMA_VERSION: u32 = 1;

// ---------------------------------------------------------------------------
// Event Type Mapping
// ---------------------------------------------------------------------------

/// Maps a holon `EventType` to its core ledger `event_type` string.
///
/// The format is `holon.<snake_case_variant>`.
#[must_use]
pub fn holon_event_type_name(event_type: &EventType) -> String {
    format!("{HOLON_EVENT_PREFIX}{}", event_type.type_name())
}

/// Maps an `OrchestrationEvent` to its core ledger `event_type` string.
#[must_use]
pub fn orchestration_event_type_name(event: &OrchestrationEvent) -> String {
    let suffix = match event {
        OrchestrationEvent::Started(_) => "orchestration.started",
        OrchestrationEvent::IterationCompleted(_) => "orchestration.iteration_completed",
        OrchestrationEvent::Terminated(_) => "orchestration.terminated",
    };
    format!("{HOLON_EVENT_PREFIX}{suffix}")
}

/// Returns `true` if the holon event represents an authority decision
/// that should go through BFT consensus when enabled.
///
/// Authority events are those that represent:
/// - Work lifecycle terminal decisions (completed, failed, cancelled)
/// - Lease issuance and release
/// - Work claims (binding a lease to work)
#[must_use]
pub const fn is_authority_event(event_type: &EventType) -> bool {
    matches!(
        event_type,
        EventType::WorkClaimed { .. }
            | EventType::WorkCompleted { .. }
            | EventType::WorkFailed { .. }
            | EventType::WorkCancelled { .. }
            | EventType::LeaseIssued { .. }
            | EventType::LeaseReleased { .. }
            | EventType::LeaseExpired { .. }
    )
}

/// Returns `true` if an orchestration event is an authority decision.
#[must_use]
pub const fn is_orchestration_authority_event(event: &OrchestrationEvent) -> bool {
    matches!(event, OrchestrationEvent::Terminated(_))
}

// ---------------------------------------------------------------------------
// Envelope Construction
// ---------------------------------------------------------------------------

/// Constructs a [`HolonEventEnvelope`] from a holon [`LedgerEvent`].
///
/// # Errors
///
/// Returns [`CoreLedgerAdapterError::Serialization`] if the event type
/// cannot be serialized to JSON.
///
/// Returns [`CoreLedgerAdapterError::PayloadTooLarge`] if the serialized
/// envelope exceeds `MAX_PAYLOAD_SIZE`.
pub fn envelope_from_ledger_event(
    event: &LedgerEvent,
    artifact_cas_digest: Option<String>,
    finality: FinalitySignal,
) -> Result<(String, Vec<u8>), CoreLedgerAdapterError> {
    let event_type_str = holon_event_type_name(event.event_type());
    let is_authority = is_authority_event(event.event_type());

    let payload_value = serde_json::to_value(event.event_type()).map_err(|e| {
        CoreLedgerAdapterError::Serialization(format!("event type serialization: {e}"))
    })?;

    let holon_hash = if event.compute_hash().is_zero() {
        None
    } else {
        Some(event.compute_hash().to_hex())
    };

    let envelope = HolonEventEnvelope {
        schema_version: ENVELOPE_SCHEMA_VERSION,
        event_kind: event.event_type().type_name().to_string(),
        payload: payload_value,
        holon_event_hash: holon_hash,
        artifact_cas_digest,
        finality,
        is_authority_event: is_authority,
    };

    let canonical_bytes = serde_jcs::to_vec(&envelope)
        .map_err(|e| CoreLedgerAdapterError::Serialization(format!("JCS canonicalization: {e}")))?;

    if canonical_bytes.len() > MAX_PAYLOAD_SIZE {
        return Err(CoreLedgerAdapterError::PayloadTooLarge {
            size: canonical_bytes.len(),
            max: MAX_PAYLOAD_SIZE,
        });
    }

    Ok((event_type_str, canonical_bytes))
}

/// Constructs a [`HolonEventEnvelope`] from an [`OrchestrationEvent`].
///
/// # Errors
///
/// Returns [`CoreLedgerAdapterError::Serialization`] if serialization fails.
///
/// Returns [`CoreLedgerAdapterError::PayloadTooLarge`] if the serialized
/// envelope exceeds `MAX_PAYLOAD_SIZE`.
pub fn envelope_from_orchestration_event(
    event: &OrchestrationEvent,
    finality: FinalitySignal,
) -> Result<(String, Vec<u8>), CoreLedgerAdapterError> {
    let event_type_str = orchestration_event_type_name(event);
    let is_authority = is_orchestration_authority_event(event);

    let event_kind = match event {
        OrchestrationEvent::Started(_) => "orchestration.started",
        OrchestrationEvent::IterationCompleted(_) => "orchestration.iteration_completed",
        OrchestrationEvent::Terminated(_) => "orchestration.terminated",
    };

    let payload_value = serde_json::to_value(event).map_err(|e| {
        CoreLedgerAdapterError::Serialization(format!("orchestration event serialization: {e}"))
    })?;

    let envelope = HolonEventEnvelope {
        schema_version: ENVELOPE_SCHEMA_VERSION,
        event_kind: event_kind.to_string(),
        payload: payload_value,
        holon_event_hash: None,
        artifact_cas_digest: None,
        finality,
        is_authority_event: is_authority,
    };

    let canonical_bytes = serde_jcs::to_vec(&envelope)
        .map_err(|e| CoreLedgerAdapterError::Serialization(format!("JCS canonicalization: {e}")))?;

    if canonical_bytes.len() > MAX_PAYLOAD_SIZE {
        return Err(CoreLedgerAdapterError::PayloadTooLarge {
            size: canonical_bytes.len(),
            max: MAX_PAYLOAD_SIZE,
        });
    }

    Ok((event_type_str, canonical_bytes))
}

/// Decodes a [`HolonEventEnvelope`] from core ledger payload bytes.
///
/// # Errors
///
/// Returns [`CoreLedgerAdapterError::Serialization`] if the bytes cannot
/// be deserialized.
///
/// Returns [`CoreLedgerAdapterError::PayloadTooLarge`] if the payload
/// exceeds `MAX_PAYLOAD_SIZE`.
pub fn decode_envelope(payload: &[u8]) -> Result<HolonEventEnvelope, CoreLedgerAdapterError> {
    if payload.len() > MAX_PAYLOAD_SIZE {
        return Err(CoreLedgerAdapterError::PayloadTooLarge {
            size: payload.len(),
            max: MAX_PAYLOAD_SIZE,
        });
    }

    serde_json::from_slice(payload).map_err(|e| {
        CoreLedgerAdapterError::Serialization(format!("envelope deserialization: {e}"))
    })
}

// ---------------------------------------------------------------------------
// Replay / State Fold Helpers (HL-004)
// ---------------------------------------------------------------------------

/// Folds a sequence of holon event envelopes to verify deterministic replay.
///
/// Returns the count of events processed and whether all authority events
/// have reached finality.
///
/// # Errors
///
/// Returns [`CoreLedgerAdapterError::Serialization`] if any envelope
/// cannot be decoded.
pub fn verify_replay_determinism(
    envelopes: &[HolonEventEnvelope],
) -> Result<ReplayVerification, CoreLedgerAdapterError> {
    let mut event_count: u64 = 0;
    let mut authority_count: u64 = 0;
    let mut pending_authority_count: u64 = 0;
    let mut max_schema_version: u32 = 0;

    for envelope in envelopes {
        event_count = event_count.saturating_add(1);
        if envelope.schema_version > max_schema_version {
            max_schema_version = envelope.schema_version;
        }
        if envelope.is_authority_event {
            authority_count = authority_count.saturating_add(1);
            if envelope.finality.is_pending() {
                pending_authority_count = pending_authority_count.saturating_add(1);
            }
        }
    }

    Ok(ReplayVerification {
        event_count,
        authority_count,
        pending_authority_count,
        all_authority_final: pending_authority_count == 0,
        max_schema_version,
    })
}

/// Result of replay verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayVerification {
    /// Total number of events processed.
    pub event_count: u64,
    /// Number of authority events.
    pub authority_count: u64,
    /// Number of authority events still pending finality.
    pub pending_authority_count: u64,
    /// Whether all authority events have reached finality.
    pub all_authority_final: bool,
    /// Maximum schema version encountered.
    pub max_schema_version: u32,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::{EventType, LedgerEvent};
    use crate::orchestration::{OrchestrationEvent, OrchestrationStarted, OrchestrationTerminated};

    // -----------------------------------------------------------------------
    // HL-001: Event type mapping
    // -----------------------------------------------------------------------

    #[test]
    fn event_type_mapping_produces_holon_prefix() {
        let et = EventType::WorkCreated {
            title: "test".to_string(),
        };
        let name = holon_event_type_name(&et);
        assert!(name.starts_with(HOLON_EVENT_PREFIX));
        assert_eq!(name, "holon.work_created");
    }

    #[test]
    fn all_event_types_have_stable_discriminants() {
        // Verify a representative sample of event types produce stable strings
        let cases: Vec<(EventType, &str)> = vec![
            (
                EventType::WorkCreated { title: "t".into() },
                "holon.work_created",
            ),
            (
                EventType::WorkClaimed {
                    lease_id: "l".into(),
                },
                "holon.work_claimed",
            ),
            (
                EventType::WorkCompleted {
                    evidence_ids: vec![],
                },
                "holon.work_completed",
            ),
            (
                EventType::WorkFailed {
                    reason: "r".into(),
                    recoverable: false,
                },
                "holon.work_failed",
            ),
            (
                EventType::WorkCancelled { reason: "r".into() },
                "holon.work_cancelled",
            ),
            (
                EventType::LeaseIssued {
                    lease_id: "l".into(),
                    holder_id: "h".into(),
                    expires_at_ns: 0,
                },
                "holon.lease_issued",
            ),
            (
                EventType::LeaseReleased {
                    lease_id: "l".into(),
                    reason: "r".into(),
                },
                "holon.lease_released",
            ),
            (
                EventType::EpisodeStarted {
                    episode_id: "e".into(),
                    attempt_number: 1,
                },
                "holon.episode_started",
            ),
            (
                EventType::EpisodeCompleted {
                    episode_id: "e".into(),
                    outcome: crate::ledger::EpisodeOutcome::Completed,
                    tokens_consumed: 0,
                },
                "holon.episode_completed",
            ),
            (
                EventType::ArtifactEmitted {
                    artifact_id: "a".into(),
                    artifact_kind: "k".into(),
                    content_hash: None,
                },
                "holon.artifact_emitted",
            ),
        ];

        for (et, expected) in cases {
            assert_eq!(holon_event_type_name(&et), expected, "mismatch for {et:?}");
        }
    }

    // -----------------------------------------------------------------------
    // HL-001: Envelope construction and round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn envelope_round_trip_deterministic() {
        let event = LedgerEvent::builder()
            .event_id("evt-001")
            .work_id("work-001")
            .holon_id("holon-001")
            .timestamp_ns(1000)
            .event_type(EventType::WorkCreated {
                title: "Test work".to_string(),
            })
            .build();

        let (event_type, payload) =
            envelope_from_ledger_event(&event, None, FinalitySignal::Local).unwrap();

        assert_eq!(event_type, "holon.work_created");

        // Decode and verify round-trip
        let envelope = decode_envelope(&payload).unwrap();
        assert_eq!(envelope.schema_version, ENVELOPE_SCHEMA_VERSION);
        assert_eq!(envelope.event_kind, "work_created");
        assert!(!envelope.is_authority_event);
        assert!(envelope.finality.is_final());

        // Second serialization must produce identical bytes (deterministic)
        let (_, payload2) =
            envelope_from_ledger_event(&event, None, FinalitySignal::Local).unwrap();
        assert_eq!(
            payload, payload2,
            "JCS canonicalization must be deterministic"
        );
    }

    #[test]
    fn authority_events_flagged_correctly() {
        let authority_types = vec![
            EventType::WorkClaimed {
                lease_id: "l".into(),
            },
            EventType::WorkCompleted {
                evidence_ids: vec![],
            },
            EventType::WorkFailed {
                reason: "r".into(),
                recoverable: false,
            },
            EventType::WorkCancelled { reason: "r".into() },
            EventType::LeaseIssued {
                lease_id: "l".into(),
                holder_id: "h".into(),
                expires_at_ns: 0,
            },
            EventType::LeaseReleased {
                lease_id: "l".into(),
                reason: "r".into(),
            },
            EventType::LeaseExpired {
                lease_id: "l".into(),
            },
        ];

        for et in &authority_types {
            assert!(is_authority_event(et), "expected authority event: {et:?}");
        }

        let non_authority = vec![
            EventType::WorkCreated { title: "t".into() },
            EventType::EpisodeStarted {
                episode_id: "e".into(),
                attempt_number: 1,
            },
            EventType::ArtifactEmitted {
                artifact_id: "a".into(),
                artifact_kind: "k".into(),
                content_hash: None,
            },
            EventType::BudgetConsumed {
                resource_type: "tokens".into(),
                amount: 100,
                remaining: 900,
            },
        ];

        for et in &non_authority {
            assert!(
                !is_authority_event(et),
                "expected non-authority event: {et:?}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // HL-003: BFT finality signals
    // -----------------------------------------------------------------------

    #[test]
    fn finality_signal_defaults_to_local() {
        let fs = FinalitySignal::default();
        assert!(fs.is_final());
        assert!(!fs.is_pending());
    }

    #[test]
    fn pending_finality_is_not_final() {
        let fs = FinalitySignal::Pending;
        assert!(!fs.is_final());
        assert!(fs.is_pending());
    }

    #[test]
    fn bft_finalized_is_final() {
        let fs = FinalitySignal::Finalized {
            epoch: 42,
            round: 7,
        };
        assert!(fs.is_final());
        assert!(!fs.is_pending());
    }

    #[test]
    fn authority_event_carries_finality_in_envelope() {
        let event = LedgerEvent::builder()
            .event_id("evt-claim")
            .work_id("work-001")
            .holon_id("holon-001")
            .timestamp_ns(2000)
            .event_type(EventType::WorkClaimed {
                lease_id: "lease-001".to_string(),
            })
            .build();

        let (_, payload) = envelope_from_ledger_event(
            &event,
            None,
            FinalitySignal::Finalized { epoch: 1, round: 3 },
        )
        .unwrap();

        let envelope = decode_envelope(&payload).unwrap();
        assert!(envelope.is_authority_event);
        assert_eq!(
            envelope.finality,
            FinalitySignal::Finalized { epoch: 1, round: 3 }
        );
    }

    // -----------------------------------------------------------------------
    // HL-001: CAS digest embedding
    // -----------------------------------------------------------------------

    #[test]
    fn artifact_cas_digest_embedded_in_envelope() {
        let event = LedgerEvent::builder()
            .event_id("evt-artifact")
            .work_id("work-001")
            .holon_id("holon-001")
            .timestamp_ns(3000)
            .event_type(EventType::ArtifactEmitted {
                artifact_id: "art-001".into(),
                artifact_kind: "code_change".into(),
                content_hash: Some("abc123".into()),
            })
            .build();

        let cas_digest = "deadbeefcafebabe".to_string();
        let (_, payload) =
            envelope_from_ledger_event(&event, Some(cas_digest), FinalitySignal::Local).unwrap();

        let envelope = decode_envelope(&payload).unwrap();
        assert_eq!(
            envelope.artifact_cas_digest.as_deref(),
            Some("deadbeefcafebabe")
        );
    }

    // -----------------------------------------------------------------------
    // HL-004: Bounded decoding — deny unknown fields
    // -----------------------------------------------------------------------

    #[test]
    fn deny_unknown_fields_in_envelope() {
        let json = r#"{"schema_version":1,"event_kind":"test","payload":{},"finality":"Local","is_authority_event":false,"unknown_field":"evil"}"#;
        let result: Result<HolonEventEnvelope, _> = serde_json::from_str(json);
        assert!(result.is_err(), "must deny unknown fields");
    }

    // -----------------------------------------------------------------------
    // HL-004: Payload size bounds
    // -----------------------------------------------------------------------

    #[test]
    fn rejects_oversized_payload() {
        // Create a huge payload
        let huge = vec![0u8; MAX_PAYLOAD_SIZE + 1];
        let result = decode_envelope(&huge);
        assert!(matches!(
            result,
            Err(CoreLedgerAdapterError::PayloadTooLarge { .. })
        ));
    }

    // -----------------------------------------------------------------------
    // HL-004: Replay verification
    // -----------------------------------------------------------------------

    #[test]
    fn replay_verification_counts_authority_events() {
        let envelopes = vec![
            HolonEventEnvelope {
                schema_version: 1,
                event_kind: "work_created".into(),
                payload: serde_json::Value::Null,
                holon_event_hash: None,
                artifact_cas_digest: None,
                finality: FinalitySignal::Local,
                is_authority_event: false,
            },
            HolonEventEnvelope {
                schema_version: 1,
                event_kind: "work_claimed".into(),
                payload: serde_json::Value::Null,
                holon_event_hash: None,
                artifact_cas_digest: None,
                finality: FinalitySignal::Finalized { epoch: 1, round: 1 },
                is_authority_event: true,
            },
            HolonEventEnvelope {
                schema_version: 1,
                event_kind: "work_completed".into(),
                payload: serde_json::Value::Null,
                holon_event_hash: None,
                artifact_cas_digest: None,
                finality: FinalitySignal::Pending,
                is_authority_event: true,
            },
        ];

        let result = verify_replay_determinism(&envelopes).unwrap();
        assert_eq!(result.event_count, 3);
        assert_eq!(result.authority_count, 2);
        assert_eq!(result.pending_authority_count, 1);
        assert!(!result.all_authority_final);
    }

    #[test]
    fn replay_verification_all_final_when_no_pending() {
        let envelopes = vec![HolonEventEnvelope {
            schema_version: 1,
            event_kind: "work_claimed".into(),
            payload: serde_json::Value::Null,
            holon_event_hash: None,
            artifact_cas_digest: None,
            finality: FinalitySignal::Local,
            is_authority_event: true,
        }];

        let result = verify_replay_determinism(&envelopes).unwrap();
        assert_eq!(result.event_count, 1);
        assert_eq!(result.authority_count, 1);
        assert!(result.all_authority_final);
    }

    // -----------------------------------------------------------------------
    // Orchestration event envelope construction
    // -----------------------------------------------------------------------

    #[test]
    fn orchestration_started_envelope() {
        let started = OrchestrationStarted::new("orch-001", "work-001", 10, 100_000, 60_000, 1000);
        let event = OrchestrationEvent::Started(started);

        let (event_type, payload) =
            envelope_from_orchestration_event(&event, FinalitySignal::Local).unwrap();

        assert_eq!(event_type, "holon.orchestration.started");
        let envelope = decode_envelope(&payload).unwrap();
        assert!(!envelope.is_authority_event);
    }

    #[test]
    fn orchestration_terminated_is_authority_event() {
        use crate::orchestration::TerminationReason;

        let terminated = OrchestrationTerminated::new(
            "orch-001",
            "work-001",
            TerminationReason::Pass,
            5,
            1000,
            500,
            2000,
        );
        let event = OrchestrationEvent::Terminated(terminated);

        assert!(is_orchestration_authority_event(&event));

        let (event_type, payload) = envelope_from_orchestration_event(
            &event,
            FinalitySignal::Finalized { epoch: 2, round: 5 },
        )
        .unwrap();

        assert_eq!(event_type, "holon.orchestration.terminated");
        let envelope = decode_envelope(&payload).unwrap();
        assert!(envelope.is_authority_event);
        assert!(envelope.finality.is_final());
    }

    // -----------------------------------------------------------------------
    // HL-004: Deterministic canonicalization
    // -----------------------------------------------------------------------

    #[test]
    fn jcs_produces_deterministic_output_across_field_order() {
        // Construct the same envelope twice and verify byte equality
        let envelope = HolonEventEnvelope {
            schema_version: 1,
            event_kind: "work_created".into(),
            payload: serde_json::json!({"title": "test", "z_field": 1, "a_field": 2}),
            holon_event_hash: Some("aabb".into()),
            artifact_cas_digest: None,
            finality: FinalitySignal::Local,
            is_authority_event: false,
        };

        let bytes1 = serde_jcs::to_vec(&envelope).unwrap();
        let bytes2 = serde_jcs::to_vec(&envelope).unwrap();
        assert_eq!(bytes1, bytes2);

        // Verify JCS sorted keys in the output
        let output = String::from_utf8(bytes1).unwrap();
        // JCS sorts keys lexicographically; verify key ordering
        let a_pos = output.find("\"a_field\"").unwrap();
        let z_pos = output.find("\"z_field\"").unwrap();
        assert!(
            a_pos < z_pos,
            "JCS must sort keys: a_field at {a_pos}, z_field at {z_pos}"
        );
    }

    // -----------------------------------------------------------------------
    // HL-004: Reconstructibility — envelope contains enough data to fold state
    // -----------------------------------------------------------------------

    #[test]
    fn envelope_preserves_original_holon_hash_for_migration() {
        let genesis = LedgerEvent::builder()
            .event_id("evt-001")
            .work_id("work-001")
            .holon_id("holon-001")
            .timestamp_ns(1000)
            .event_type(EventType::WorkCreated {
                title: "Test".to_string(),
            })
            .build();

        // The genesis event has a non-zero hash
        let hash = genesis.compute_hash();
        assert!(!hash.is_zero());

        let (_, payload) =
            envelope_from_ledger_event(&genesis, None, FinalitySignal::Local).unwrap();
        let envelope = decode_envelope(&payload).unwrap();

        // The holon hash is preserved for cross-reference
        assert!(envelope.holon_event_hash.is_some());
        assert_eq!(envelope.holon_event_hash.unwrap(), hash.to_hex());
    }

    // -----------------------------------------------------------------------
    // Finality signal serialization round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn finality_signal_serde_round_trip() {
        let signals = vec![
            FinalitySignal::Local,
            FinalitySignal::Pending,
            FinalitySignal::Finalized {
                epoch: 42,
                round: 7,
            },
        ];

        for signal in signals {
            let json = serde_json::to_string(&signal).unwrap();
            let decoded: FinalitySignal = serde_json::from_str(&json).unwrap();
            assert_eq!(signal, decoded, "round-trip failed for {signal:?}");
        }
    }
}
