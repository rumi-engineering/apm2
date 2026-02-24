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

use std::fmt;
// Core ledger types are available when the `core-ledger` feature is enabled.
#[cfg(feature = "core-ledger")]
use std::sync::Arc;

#[cfg(feature = "core-ledger")]
use apm2_core::ledger::{EventRecord, LedgerBackend, LedgerError};
use serde::{Deserialize, Serialize, de};
use thiserror::Error;

#[cfg(feature = "legacy_holon_ledger")]
use crate::ledger::{EventType, LedgerEvent};
use crate::orchestration::OrchestrationEvent;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum serialized payload size (8 MiB).
///
/// Derivation: `WorkCompleted` events can carry up to 1000 evidence IDs,
/// each approximately 4 KiB when serialized (~4 MiB total). With envelope
/// overhead the maximum valid payload can approach ~4.5 MiB. We set the
/// limit to 8 MiB to accommodate growth while still bounding memory usage
/// against denial-of-service. Large artifacts should still go to CAS; this
/// limit covers metadata-heavy events.
pub const MAX_PAYLOAD_SIZE: usize = 8 * 1024 * 1024;

/// Expected length of a hex-encoded BLAKE3 digest (64 lowercase hex chars).
pub const HEX_DIGEST_LENGTH: usize = 64;

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
    ///
    /// **Fail-closed**: This is a strict allowlist. Only explicitly enumerated
    /// variants return `true`. Because `FinalitySignal` is `#[non_exhaustive]`,
    /// any future variant will land in the catch-all arm and return `false`
    /// (i.e., treat unknown states as not-final), preventing state machine
    /// advancement on unconfirmed authority decisions.
    ///
    /// The `match_same_arms` lint is deliberately suppressed: we keep
    /// `Pending` explicit (rather than merging it into the wildcard) so
    /// that adding a new variant forces a conscious decision about
    /// whether it counts as final.
    #[must_use]
    #[allow(clippy::match_same_arms)]
    pub const fn is_final(&self) -> bool {
        match self {
            Self::Local | Self::Finalized { .. } => true,
            Self::Pending => false,
            // Fail-closed: any future variant added to the non-exhaustive enum
            // is treated as not-final until explicitly allow-listed here.
            #[allow(unreachable_patterns)]
            _ => false,
        }
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

    /// CAS store operation failed.
    #[error("CAS store failed: {0}")]
    CasError(String),

    /// Ledger append failed.
    #[error("ledger append failed: {0}")]
    LedgerError(String),

    /// Event type is not recognized.
    #[error("unknown event type: {0}")]
    UnknownEventType(String),

    /// A digest string failed format validation.
    #[error("invalid digest: {field}: {reason}")]
    InvalidDigest {
        /// Which field contained the invalid digest.
        field: &'static str,
        /// What was wrong.
        reason: String,
    },
}

// ---------------------------------------------------------------------------
// Validated Hex Digest (BLAKE3 format)
// ---------------------------------------------------------------------------

/// A validated hex-encoded BLAKE3 digest string.
///
/// Enforces that the inner value is exactly 64 lowercase hexadecimal
/// characters, preventing path traversal sequences or pathological characters
/// from propagating through the system if digests are used downstream as
/// filesystem paths or database keys.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HexDigest(String);

impl HexDigest {
    /// Validates and wraps a hex digest string.
    ///
    /// # Errors
    ///
    /// Returns `CoreLedgerAdapterError::InvalidDigest` if the string is not
    /// exactly 64 lowercase hex characters.
    pub fn try_new(value: String, field: &'static str) -> Result<Self, CoreLedgerAdapterError> {
        if value.len() != HEX_DIGEST_LENGTH {
            return Err(CoreLedgerAdapterError::InvalidDigest {
                field,
                reason: format!(
                    "expected {HEX_DIGEST_LENGTH} hex chars, got {}",
                    value.len()
                ),
            });
        }
        if !value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(CoreLedgerAdapterError::InvalidDigest {
                field,
                reason: "must be lowercase hex characters [0-9a-f]".to_string(),
            });
        }
        Ok(Self(value))
    }

    /// Returns the inner hex string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consumes the wrapper, returning the inner string.
    #[must_use]
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl fmt::Display for HexDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for HexDigest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for HexDigest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        // Validate format during deserialization (parse, don't validate).
        Self::try_new(s, "hex_digest").map_err(|e| de::Error::custom(e.to_string()))
    }
}

// ---------------------------------------------------------------------------
// Holon Event Envelope (wire format in core ledger payload)
// ---------------------------------------------------------------------------

/// Envelope wrapping a holon event payload in the core ledger.
///
/// This is the canonical JSON structure stored in `EventRecord.payload`.
/// It carries the holon-specific payload plus metadata needed for replay
/// and BFT-readiness.
///
/// **Security**: The `is_authority_event` status is NOT part of the wire
/// format. It is computed dynamically from `event_kind` via
/// [`HolonEventEnvelope::is_authority_event`] to prevent an attacker from
/// crafting a payload that falsifies authority status and bypasses BFT
/// finality checks.
///
/// **Parse, don't validate**: Digest fields use [`HexDigest`] which
/// enforces format (64 lowercase hex chars) during deserialization.
/// Downstream consumers can rely on the type system to guarantee digest
/// format without additional runtime checks.
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
    pub holon_event_hash: Option<HexDigest>,

    /// CAS digest of any large artifact associated with this event.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_cas_digest: Option<HexDigest>,

    /// Finality signal for BFT-readiness (HL-003).
    pub finality: FinalitySignal,
}

impl HolonEventEnvelope {
    /// Returns `true` if this event represents an authority decision that
    /// requires BFT consensus when enabled.
    ///
    /// **Security**: This is computed dynamically from `event_kind`, NOT
    /// deserialized from the wire payload, to prevent attackers from
    /// falsifying authority status and bypassing BFT finality checks.
    #[must_use]
    pub fn is_authority_event(&self) -> bool {
        is_authority_event_kind(&self.event_kind)
    }
}

/// Current schema version for holon event envelopes.
pub const ENVELOPE_SCHEMA_VERSION: u32 = 1;

/// Known authority event kind strings.
///
/// An event kind is an authority event if it carries state that influences
/// deterministic output or resource consumption. This includes:
/// - Work lifecycle terminals (completed, failed, cancelled)
/// - Work claims and escalation (binding leases to work)
/// - Lease lifecycle (issuance, renewal, release, expiry)
/// - Episode completion (execution outcomes and token usage)
/// - Artifact emission (content hashes affecting replay)
/// - Orchestration start and termination (budget allocation, terminal
///   decisions)
const AUTHORITY_EVENT_KINDS: &[&str] = &[
    "work_claimed",
    "work_completed",
    "work_failed",
    "work_cancelled",
    "work_escalated",
    "episode_completed",
    "artifact_emitted",
    "lease_issued",
    "lease_renewed",
    "lease_released",
    "lease_expired",
    "orchestration.started",
    "orchestration.terminated",
];

/// Returns `true` if the given `event_kind` string represents an authority
/// event that should go through BFT consensus when enabled.
///
/// **Fail-closed**: Only explicitly listed kinds return `true`. Any
/// unknown or unrecognized kind returns `false`, preventing unknown event
/// types from bypassing finality checks by claiming authority status.
#[must_use]
pub fn is_authority_event_kind(event_kind: &str) -> bool {
    AUTHORITY_EVENT_KINDS.contains(&event_kind)
}

// ---------------------------------------------------------------------------
// Event Type Mapping
// ---------------------------------------------------------------------------

/// Maps a holon `EventType` to its core ledger `event_type` string.
///
/// The format is `holon.<snake_case_variant>`.
#[cfg(feature = "legacy_holon_ledger")]
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
/// Authority events are those that carry state influencing deterministic
/// output or resource consumption:
/// - Work lifecycle terminal decisions (completed, failed, cancelled)
/// - Work claims (binding a lease to work) and escalation (delegating local
///   authority)
/// - Lease lifecycle (issuance, renewal, release, expiry)
/// - Episode completion (execution outcomes and token usage)
/// - Artifact emission (content hashes that affect deterministic replay)
#[cfg(feature = "legacy_holon_ledger")]
#[must_use]
pub const fn is_authority_event(event_type: &EventType) -> bool {
    matches!(
        event_type,
        EventType::WorkClaimed { .. }
            | EventType::WorkCompleted { .. }
            | EventType::WorkFailed { .. }
            | EventType::WorkCancelled { .. }
            | EventType::WorkEscalated { .. }
            | EventType::EpisodeCompleted { .. }
            | EventType::ArtifactEmitted { .. }
            | EventType::LeaseIssued { .. }
            | EventType::LeaseRenewed { .. }
            | EventType::LeaseReleased { .. }
            | EventType::LeaseExpired { .. }
    )
}

/// Returns `true` if an orchestration event is an authority decision.
///
/// Both `Started` (budget allocation) and `Terminated` (terminal decision)
/// carry state that must be consensus-finalized.
#[must_use]
pub const fn is_orchestration_authority_event(event: &OrchestrationEvent) -> bool {
    matches!(
        event,
        OrchestrationEvent::Started(_) | OrchestrationEvent::Terminated(_)
    )
}

// ---------------------------------------------------------------------------
// Envelope Construction
// ---------------------------------------------------------------------------

/// Constructs a [`HolonEventEnvelope`] from a holon [`LedgerEvent`].
///
/// Only available when the `legacy_holon_ledger` feature is enabled,
/// since it depends on the legacy `LedgerEvent` / `EventType` types.
///
/// # Errors
///
/// Returns [`CoreLedgerAdapterError::Serialization`] if the event type
/// cannot be serialized to JSON.
///
/// Returns [`CoreLedgerAdapterError::PayloadTooLarge`] if the serialized
/// envelope exceeds `MAX_PAYLOAD_SIZE`.
#[cfg(feature = "legacy_holon_ledger")]
pub fn envelope_from_ledger_event(
    event: &LedgerEvent,
    artifact_cas_digest: Option<HexDigest>,
    finality: FinalitySignal,
) -> Result<(String, Vec<u8>), CoreLedgerAdapterError> {
    let event_type_str = holon_event_type_name(event.event_type());

    let payload_value = serde_json::to_value(event.event_type()).map_err(|e| {
        CoreLedgerAdapterError::Serialization(format!("event type serialization: {e}"))
    })?;

    let holon_hash = if event.compute_hash().is_zero() {
        None
    } else {
        let hex = event.compute_hash().to_hex();
        Some(HexDigest::try_new(hex, "holon_event_hash")?)
    };

    let envelope = HolonEventEnvelope {
        schema_version: ENVELOPE_SCHEMA_VERSION,
        event_kind: event.event_type().type_name().to_string(),
        payload: payload_value,
        holon_event_hash: holon_hash,
        artifact_cas_digest,
        finality,
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
/// Digest fields (`holon_event_hash`, `artifact_cas_digest`) are
/// validated intrinsically during deserialization because they use
/// [`HexDigest`] which enforces the 64-lowercase-hex format in its
/// `Deserialize` implementation. No separate validation step is needed.
///
/// # Errors
///
/// Returns [`CoreLedgerAdapterError::Serialization`] if the bytes cannot
/// be deserialized (including malformed digest fields).
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

    let envelope: HolonEventEnvelope = serde_json::from_slice(payload).map_err(|e| {
        CoreLedgerAdapterError::Serialization(format!("envelope deserialization: {e}"))
    })?;

    Ok(envelope)
}

// ---------------------------------------------------------------------------
// Replay / State Fold Helpers (HL-004)
// ---------------------------------------------------------------------------

/// Inspects a sequence of holon event envelopes and collects replay
/// statistics: total event count, authority event count, and how many
/// authority events have not yet reached finality.
///
/// **Note**: This function collects statistics only. It does not re-fold
/// state or compare hashes; deterministic replay verification requires a
/// full state fold with hash comparison.
///
/// Finality is checked via the strict-allowlist [`FinalitySignal::is_final`]
/// method (fail-closed: unknown future variants are treated as not-final).
#[must_use]
pub fn inspect_replay_stats(envelopes: &[HolonEventEnvelope]) -> ReplayStats {
    let mut event_count: u64 = 0;
    let mut authority_count: u64 = 0;
    let mut non_final_authority_count: u64 = 0;
    let mut max_schema_version: u32 = 0;

    for envelope in envelopes {
        event_count = event_count.saturating_add(1);
        if envelope.schema_version > max_schema_version {
            max_schema_version = envelope.schema_version;
        }
        // SECURITY: Authority status is computed from event_kind, not
        // trusted from the wire payload. See HolonEventEnvelope docs.
        if envelope.is_authority_event() {
            authority_count = authority_count.saturating_add(1);
            // Fail-closed: use is_final() (strict allowlist) rather than
            // !is_pending() which would pass unknown future variants.
            if !envelope.finality.is_final() {
                non_final_authority_count = non_final_authority_count.saturating_add(1);
            }
        }
    }

    ReplayStats {
        event_count,
        authority_count,
        non_final_authority_count,
        all_authority_final: non_final_authority_count == 0,
        max_schema_version,
    }
}

/// Statistics collected by [`inspect_replay_stats`] over a sequence of
/// holon event envelopes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayStats {
    /// Total number of events inspected.
    pub event_count: u64,
    /// Number of authority events.
    pub authority_count: u64,
    /// Number of authority events that have NOT reached finality (checked
    /// via the strict-allowlist `is_final()` method, which treats unknown
    /// future `FinalitySignal` variants as not-final).
    pub non_final_authority_count: u64,
    /// Whether all authority events have reached finality.
    pub all_authority_final: bool,
    /// Maximum schema version encountered.
    pub max_schema_version: u32,
}

// ---------------------------------------------------------------------------
// CoreLedgerWriter (HL-001 / HL-003)
// ---------------------------------------------------------------------------

/// Writes holon events into the apm2-core ledger+CAS substrate.
///
/// This is the concrete event sink required by HL-001. It serializes
/// events into [`HolonEventEnvelope`]s, encodes them as JCS bytes, and
/// appends them as [`EventRecord`]s to the core ledger.
///
/// # BFT-readiness (HL-003)
///
/// Authority events carry an explicit [`FinalitySignal`]. The writer
/// passes consensus metadata through to the `EventRecord` so that
/// `BftLedgerBackend` can route authority events through consensus.
/// The holon runtime MUST NOT assume local finality is permanent; it
/// passes the signal explicitly, allowing the BFT layer to upgrade
/// `Local` to `Finalized` later.
///
/// # Synchronization protocol
///
/// `CoreLedgerWriter` holds an `Arc<dyn LedgerBackend>` which is
/// internally synchronized. The writer itself is `Send + Sync` and
/// can be shared across tasks via `Arc`.
#[cfg(feature = "core-ledger")]
pub struct CoreLedgerWriter {
    /// Core ledger backend for appending events.
    backend: Arc<dyn LedgerBackend>,
    /// Namespace for holon events in the core ledger (e.g., `"holon"`).
    namespace: String,
    /// Session ID for all events written by this writer.
    session_id: String,
    /// Actor ID (signer identity) for all events written by this writer.
    actor_id: String,
}

#[cfg(feature = "core-ledger")]
impl fmt::Debug for CoreLedgerWriter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CoreLedgerWriter")
            .field("namespace", &self.namespace)
            .field("session_id", &self.session_id)
            .field("actor_id", &self.actor_id)
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "core-ledger")]
impl CoreLedgerWriter {
    /// Creates a new writer bound to the given ledger backend.
    ///
    /// # Arguments
    ///
    /// * `backend` - The core ledger backend (e.g., `SqliteLedgerBackend` or
    ///   `BftLedgerBackend`).
    /// * `namespace` - Namespace prefix for holon events (e.g., `"holon"`).
    /// * `session_id` - Session ID for attribution.
    /// * `actor_id` - Actor/signer identity for attribution.
    #[must_use]
    pub fn new(
        backend: Arc<dyn LedgerBackend>,
        namespace: impl Into<String>,
        session_id: impl Into<String>,
        actor_id: impl Into<String>,
    ) -> Self {
        Self {
            backend,
            namespace: namespace.into(),
            session_id: session_id.into(),
            actor_id: actor_id.into(),
        }
    }

    /// Writes an orchestration event to the core ledger.
    ///
    /// The event is serialized into a [`HolonEventEnvelope`], encoded
    /// as JCS bytes, and appended as an [`EventRecord`]. The
    /// [`FinalitySignal`] is threaded through so that BFT-enabled
    /// deployments can route authority events through consensus.
    ///
    /// # Errors
    ///
    /// Returns [`CoreLedgerAdapterError::Serialization`] if serialization
    /// fails, [`CoreLedgerAdapterError::PayloadTooLarge`] if the envelope
    /// exceeds the size limit, or [`CoreLedgerAdapterError::LedgerError`]
    /// if the ledger append fails.
    pub async fn write_orchestration_event(
        &self,
        event: &OrchestrationEvent,
        finality: FinalitySignal,
        timestamp_ns: u64,
    ) -> Result<u64, CoreLedgerAdapterError> {
        let (event_type_str, canonical_bytes) = envelope_from_orchestration_event(event, finality)?;

        let mut record = EventRecord::new(
            &event_type_str,
            &self.session_id,
            &self.actor_id,
            canonical_bytes,
        );
        record.timestamp_ns = timestamp_ns;

        // Thread consensus metadata from FinalitySignal into EventRecord.
        if let FinalitySignal::Finalized { epoch, round } = finality {
            record.consensus_epoch = Some(epoch);
            record.consensus_round = Some(round);
        }
        record.canonicalizer_id = Some("jcs".to_string());
        record.canonicalizer_version = Some("rfc8785".to_string());

        let seq_id = self
            .backend
            .append(&self.namespace, &record)
            .await
            .map_err(|e: LedgerError| CoreLedgerAdapterError::LedgerError(e.to_string()))?;

        Ok(seq_id)
    }

    /// Writes a holon event (from legacy `LedgerEvent`) to the core ledger.
    ///
    /// Only available when both `core-ledger` and `legacy_holon_ledger`
    /// features are enabled, since it bridges the legacy event types.
    ///
    /// # Errors
    ///
    /// Returns [`CoreLedgerAdapterError`] on serialization, size, or
    /// ledger append failure.
    #[cfg(feature = "legacy_holon_ledger")]
    pub async fn write_holon_event(
        &self,
        event: &LedgerEvent,
        artifact_cas_digest: Option<HexDigest>,
        finality: FinalitySignal,
        timestamp_ns: u64,
    ) -> Result<u64, CoreLedgerAdapterError> {
        let (event_type_str, canonical_bytes) =
            envelope_from_ledger_event(event, artifact_cas_digest, finality)?;

        let mut record = EventRecord::new(
            &event_type_str,
            &self.session_id,
            &self.actor_id,
            canonical_bytes,
        );
        record.timestamp_ns = timestamp_ns;

        if let FinalitySignal::Finalized { epoch, round } = finality {
            record.consensus_epoch = Some(epoch);
            record.consensus_round = Some(round);
        }
        record.canonicalizer_id = Some("jcs".to_string());
        record.canonicalizer_version = Some("rfc8785".to_string());

        let seq_id = self
            .backend
            .append(&self.namespace, &record)
            .await
            .map_err(|e: LedgerError| CoreLedgerAdapterError::LedgerError(e.to_string()))?;

        Ok(seq_id)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "legacy_holon_ledger")]
    use crate::ledger::{EventType, LedgerEvent};
    use crate::orchestration::{OrchestrationEvent, OrchestrationStarted, OrchestrationTerminated};

    // -----------------------------------------------------------------------
    // HL-001: Event type mapping (legacy bridge)
    // These tests use `holon_event_type_name` which requires the legacy
    // feature.
    // -----------------------------------------------------------------------

    #[cfg(feature = "legacy_holon_ledger")]
    #[test]
    fn event_type_mapping_produces_holon_prefix() {
        let et = EventType::WorkCreated {
            title: "test".to_string(),
        };
        let name = holon_event_type_name(&et);
        assert!(name.starts_with(HOLON_EVENT_PREFIX));
        assert_eq!(name, "holon.work_created");
    }

    #[cfg(feature = "legacy_holon_ledger")]
    #[test]
    fn all_event_types_have_stable_discriminants() {
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
    // HL-001: Envelope construction and round-trip (legacy bridge)
    // -----------------------------------------------------------------------

    #[cfg(feature = "legacy_holon_ledger")]
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
        // Authority status is computed dynamically from event_kind.
        assert!(
            !envelope.is_authority_event(),
            "work_created is not an authority event"
        );
        assert!(envelope.finality.is_final());

        // Second serialization must produce identical bytes (deterministic)
        let (_, payload2) =
            envelope_from_ledger_event(&event, None, FinalitySignal::Local).unwrap();
        assert_eq!(
            payload, payload2,
            "JCS canonicalization must be deterministic"
        );
    }

    #[cfg(feature = "legacy_holon_ledger")]
    #[test]
    fn authority_events_flagged_correctly_via_legacy_event_type() {
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
            EventType::WorkEscalated {
                to_holon_id: "h".into(),
                reason: "r".into(),
            },
            EventType::EpisodeCompleted {
                episode_id: "e".into(),
                outcome: crate::ledger::EpisodeOutcome::Completed,
                tokens_consumed: 0,
            },
            EventType::ArtifactEmitted {
                artifact_id: "a".into(),
                artifact_kind: "k".into(),
                content_hash: None,
            },
            EventType::LeaseIssued {
                lease_id: "l".into(),
                holder_id: "h".into(),
                expires_at_ns: 0,
            },
            EventType::LeaseRenewed {
                lease_id: "l".into(),
                new_expires_at_ns: 1000,
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
            EventType::WorkProgressed {
                description: "d".into(),
                new_state: crate::work::WorkLifecycle::InProgress,
            },
            EventType::EpisodeStarted {
                episode_id: "e".into(),
                attempt_number: 1,
            },
            EventType::EvidencePublished {
                evidence_id: "e".into(),
                requirement_id: "r".into(),
                content_hash: "h".into(),
            },
            EventType::BudgetConsumed {
                resource_type: "tokens".into(),
                amount: 100,
                remaining: 900,
            },
            EventType::BudgetExhausted {
                resource_type: "tokens".into(),
                total_used: 1000,
                limit: 1000,
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
    // Authority event kind computation (dynamic, not from wire)
    // -----------------------------------------------------------------------

    #[test]
    fn authority_event_kind_computed_dynamically() {
        // Authority kinds
        assert!(is_authority_event_kind("work_claimed"));
        assert!(is_authority_event_kind("work_completed"));
        assert!(is_authority_event_kind("work_failed"));
        assert!(is_authority_event_kind("work_cancelled"));
        assert!(is_authority_event_kind("work_escalated"));
        assert!(is_authority_event_kind("episode_completed"));
        assert!(is_authority_event_kind("artifact_emitted"));
        assert!(is_authority_event_kind("lease_issued"));
        assert!(is_authority_event_kind("lease_renewed"));
        assert!(is_authority_event_kind("lease_released"));
        assert!(is_authority_event_kind("lease_expired"));
        assert!(is_authority_event_kind("orchestration.started"));
        assert!(is_authority_event_kind("orchestration.terminated"));

        // Non-authority kinds
        assert!(!is_authority_event_kind("work_created"));
        assert!(!is_authority_event_kind("work_progressed"));
        assert!(!is_authority_event_kind("episode_started"));
        assert!(!is_authority_event_kind("evidence_published"));
        assert!(!is_authority_event_kind("budget_consumed"));
        assert!(!is_authority_event_kind(
            "orchestration.iteration_completed"
        ));

        // Fail-closed: unknown kinds are not authority
        assert!(!is_authority_event_kind(""));
        assert!(!is_authority_event_kind("malicious_fake_event"));
    }

    #[test]
    fn envelope_computes_authority_from_event_kind_not_wire() {
        // Construct an envelope with an authority event_kind
        let envelope = HolonEventEnvelope {
            schema_version: 1,
            event_kind: "work_claimed".into(),
            payload: serde_json::Value::Null,
            holon_event_hash: None,
            artifact_cas_digest: None,
            finality: FinalitySignal::Local,
        };
        assert!(
            envelope.is_authority_event(),
            "work_claimed must be authority"
        );

        // Construct an envelope with a non-authority event_kind
        let envelope2 = HolonEventEnvelope {
            schema_version: 1,
            event_kind: "work_created".into(),
            payload: serde_json::Value::Null,
            holon_event_hash: None,
            artifact_cas_digest: None,
            finality: FinalitySignal::Local,
        };
        assert!(
            !envelope2.is_authority_event(),
            "work_created must not be authority"
        );
    }

    // -----------------------------------------------------------------------
    // SECURITY: attacker cannot bypass BFT finality via wire payload
    // -----------------------------------------------------------------------

    #[test]
    fn attacker_cannot_falsify_authority_status_via_wire() {
        // Previously, is_authority_event was a wire field. Now it's
        // computed. Verify that an envelope deserialized from bytes
        // correctly identifies authority regardless of what was in the
        // wire payload (the field no longer exists).
        let json =
            r#"{"schema_version":1,"event_kind":"work_completed","payload":{},"finality":"Local"}"#;
        let envelope = decode_envelope(json.as_bytes()).unwrap();
        assert!(
            envelope.is_authority_event(),
            "work_completed must always be authority, regardless of wire"
        );

        // Non-authority event kind
        let json2 =
            r#"{"schema_version":1,"event_kind":"work_created","payload":{},"finality":"Local"}"#;
        let envelope2 = decode_envelope(json2.as_bytes()).unwrap();
        assert!(
            !envelope2.is_authority_event(),
            "work_created is not authority"
        );
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

    #[cfg(feature = "legacy_holon_ledger")]
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
        assert!(envelope.is_authority_event());
        assert_eq!(
            envelope.finality,
            FinalitySignal::Finalized { epoch: 1, round: 3 }
        );
    }

    // -----------------------------------------------------------------------
    // HL-001: CAS digest embedding (legacy bridge)
    // -----------------------------------------------------------------------

    #[cfg(feature = "legacy_holon_ledger")]
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

        let cas_digest_str =
            "deadbeefcafebabedeadbeefcafebabedeadbeefcafebabedeadbeefcafebabe".to_string();
        let cas_digest = HexDigest::try_new(cas_digest_str.clone(), "test").unwrap();
        let (_, payload) =
            envelope_from_ledger_event(&event, Some(cas_digest), FinalitySignal::Local).unwrap();

        let envelope = decode_envelope(&payload).unwrap();
        assert_eq!(
            envelope.artifact_cas_digest.as_ref().map(HexDigest::as_str),
            Some(cas_digest_str.as_str()),
        );
    }

    // -----------------------------------------------------------------------
    // HL-004: Bounded decoding — deny unknown fields
    // -----------------------------------------------------------------------

    #[test]
    fn deny_unknown_fields_in_envelope() {
        // `is_authority_event` was removed from the wire format and is now
        // treated as an unknown field, which must be denied.
        let json = r#"{"schema_version":1,"event_kind":"test","payload":{},"finality":"Local","is_authority_event":false,"unknown_field":"evil"}"#;
        let result: Result<HolonEventEnvelope, _> = serde_json::from_str(json);
        assert!(result.is_err(), "must deny unknown fields");
    }

    #[test]
    fn deny_legacy_is_authority_event_field() {
        // The old wire field `is_authority_event` must be rejected.
        let json = r#"{"schema_version":1,"event_kind":"test","payload":{},"finality":"Local","is_authority_event":true}"#;
        let result: Result<HolonEventEnvelope, _> = serde_json::from_str(json);
        assert!(
            result.is_err(),
            "must reject legacy is_authority_event field"
        );
    }

    // -----------------------------------------------------------------------
    // HL-004: Payload size bounds
    // -----------------------------------------------------------------------

    #[test]
    fn rejects_oversized_payload() {
        let huge = vec![0u8; MAX_PAYLOAD_SIZE + 1];
        let result = decode_envelope(&huge);
        assert!(matches!(
            result,
            Err(CoreLedgerAdapterError::PayloadTooLarge { .. })
        ));
    }

    // -----------------------------------------------------------------------
    // Digest validation (HexDigest type enforcement)
    // -----------------------------------------------------------------------

    #[test]
    fn hex_digest_accepts_valid_blake3_hex() {
        let valid = "a".repeat(64);
        let result = HexDigest::try_new(valid, "test");
        assert!(result.is_ok());
    }

    #[test]
    fn hex_digest_rejects_wrong_length() {
        let short = "abcdef".to_string();
        let result = HexDigest::try_new(short, "test");
        assert!(
            matches!(result, Err(CoreLedgerAdapterError::InvalidDigest { .. })),
            "should reject wrong-length digest"
        );
    }

    #[test]
    fn hex_digest_rejects_uppercase() {
        let upper = "A".repeat(64);
        let result = HexDigest::try_new(upper, "test");
        assert!(
            matches!(result, Err(CoreLedgerAdapterError::InvalidDigest { .. })),
            "should reject uppercase hex"
        );
    }

    #[test]
    fn hex_digest_rejects_non_hex_characters() {
        let mut bad = "a".repeat(60);
        bad.push_str("/../");
        let result = HexDigest::try_new(bad, "test");
        assert!(
            matches!(result, Err(CoreLedgerAdapterError::InvalidDigest { .. })),
            "should reject path traversal characters"
        );
    }

    #[test]
    fn hex_digest_serde_round_trip() {
        let digest = HexDigest::try_new("a".repeat(64), "test").unwrap();
        let json = serde_json::to_string(&digest).unwrap();
        let decoded: HexDigest = serde_json::from_str(&json).unwrap();
        assert_eq!(digest, decoded);
    }

    #[test]
    fn hex_digest_deserialize_rejects_invalid() {
        let json = r#""BADCAFE""#;
        let result: Result<HexDigest, _> = serde_json::from_str(json);
        assert!(result.is_err(), "serde must reject invalid hex digests");
    }

    #[test]
    fn decode_envelope_rejects_malformed_holon_event_hash() {
        let json = r#"{"schema_version":1,"event_kind":"test","payload":{},"holon_event_hash":"BADCAFE","finality":"Local"}"#;
        let result = decode_envelope(json.as_bytes());
        assert!(
            result.is_err(),
            "should reject malformed holon_event_hash: {result:?}"
        );
    }

    #[test]
    fn decode_envelope_rejects_malformed_artifact_cas_digest() {
        let json = r#"{"schema_version":1,"event_kind":"test","payload":{},"artifact_cas_digest":"../../etc/passwd","finality":"Local"}"#;
        let result = decode_envelope(json.as_bytes());
        assert!(
            result.is_err(),
            "should reject path-traversal in artifact_cas_digest: {result:?}"
        );
    }

    #[test]
    fn decode_envelope_accepts_valid_digests() {
        let valid_hash = "a".repeat(64);
        let json = format!(
            r#"{{"schema_version":1,"event_kind":"test","payload":{{}},"holon_event_hash":"{valid_hash}","artifact_cas_digest":"{valid_hash}","finality":"Local"}}"#,
        );
        let result = decode_envelope(json.as_bytes());
        assert!(result.is_ok(), "should accept valid 64-char hex digests");
    }

    // -----------------------------------------------------------------------
    // Replay statistics
    // -----------------------------------------------------------------------

    #[test]
    fn replay_stats_counts_authority_events() {
        let envelopes = vec![
            HolonEventEnvelope {
                schema_version: 1,
                event_kind: "work_created".into(),
                payload: serde_json::Value::Null,
                holon_event_hash: None,
                artifact_cas_digest: None,
                finality: FinalitySignal::Local,
            },
            HolonEventEnvelope {
                schema_version: 1,
                event_kind: "work_claimed".into(),
                payload: serde_json::Value::Null,
                holon_event_hash: None,
                artifact_cas_digest: None,
                finality: FinalitySignal::Finalized { epoch: 1, round: 1 },
            },
            HolonEventEnvelope {
                schema_version: 1,
                event_kind: "work_completed".into(),
                payload: serde_json::Value::Null,
                holon_event_hash: None,
                artifact_cas_digest: None,
                finality: FinalitySignal::Pending,
            },
        ];

        let result = inspect_replay_stats(&envelopes);
        assert_eq!(result.event_count, 3);
        assert_eq!(result.authority_count, 2);
        assert_eq!(result.non_final_authority_count, 1);
        assert!(!result.all_authority_final);
    }

    #[test]
    fn replay_stats_all_final_when_no_pending() {
        let envelopes = vec![HolonEventEnvelope {
            schema_version: 1,
            event_kind: "work_claimed".into(),
            payload: serde_json::Value::Null,
            holon_event_hash: None,
            artifact_cas_digest: None,
            finality: FinalitySignal::Local,
        }];

        let result = inspect_replay_stats(&envelopes);
        assert_eq!(result.event_count, 1);
        assert_eq!(result.authority_count, 1);
        assert!(result.all_authority_final);
    }

    // -----------------------------------------------------------------------
    // Orchestration event envelope construction
    // -----------------------------------------------------------------------

    #[test]
    fn orchestration_started_is_authority_event() {
        let started = OrchestrationStarted::new("orch-001", "work-001", 10, 100_000, 60_000, 1000);
        let event = OrchestrationEvent::Started(started);

        assert!(is_orchestration_authority_event(&event));

        let (event_type, payload) =
            envelope_from_orchestration_event(&event, FinalitySignal::Local).unwrap();

        assert_eq!(event_type, "holon.orchestration.started");
        let envelope = decode_envelope(&payload).unwrap();
        assert!(
            envelope.is_authority_event(),
            "OrchestrationStarted carries budget allocation and must be authority"
        );
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
        assert!(envelope.is_authority_event());
        assert!(envelope.finality.is_final());
    }

    // -----------------------------------------------------------------------
    // HL-004: Deterministic canonicalization
    // -----------------------------------------------------------------------

    #[test]
    fn jcs_produces_deterministic_output_across_field_order() {
        let digest = HexDigest::try_new("a".repeat(64), "test").unwrap();
        let envelope = HolonEventEnvelope {
            schema_version: 1,
            event_kind: "work_created".into(),
            payload: serde_json::json!({"title": "test", "z_field": 1, "a_field": 2}),
            holon_event_hash: Some(digest),
            artifact_cas_digest: None,
            finality: FinalitySignal::Local,
        };

        let bytes1 = serde_jcs::to_vec(&envelope).unwrap();
        let bytes2 = serde_jcs::to_vec(&envelope).unwrap();
        assert_eq!(bytes1, bytes2);

        // Verify JCS sorted keys in the output
        let output = String::from_utf8(bytes1).unwrap();
        let a_pos = output.find("\"a_field\"").unwrap();
        let z_pos = output.find("\"z_field\"").unwrap();
        assert!(
            a_pos < z_pos,
            "JCS must sort keys: a_field at {a_pos}, z_field at {z_pos}"
        );
    }

    // -----------------------------------------------------------------------
    // HL-004: Round-trip determinism (encode -> decode -> re-encode)
    // -----------------------------------------------------------------------

    #[test]
    fn round_trip_encode_decode_reencode_is_deterministic() {
        // Encode a sequence of events, decode back, and re-encode.
        // Verify the re-encoded bytes match the original (deterministic
        // round-trip).
        let events = vec![
            OrchestrationEvent::Started(OrchestrationStarted::new(
                "orch-001", "work-001", 10, 100_000, 60_000, 1000,
            )),
            OrchestrationEvent::Terminated(OrchestrationTerminated::new(
                "orch-001",
                "work-001",
                crate::orchestration::TerminationReason::Pass,
                5,
                1000,
                500,
                2000,
            )),
        ];

        for event in &events {
            let (event_type, original_bytes) =
                envelope_from_orchestration_event(event, FinalitySignal::Local).unwrap();

            // Decode
            let decoded = decode_envelope(&original_bytes).unwrap();

            // Re-encode from decoded envelope
            let re_encoded = serde_jcs::to_vec(&decoded).unwrap();

            assert_eq!(
                original_bytes, re_encoded,
                "round-trip must be deterministic for {event_type}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // HL-004: Reconstructibility — decode from serialized envelope only
    // -----------------------------------------------------------------------

    #[test]
    fn cache_loss_reconstructibility() {
        // Simulate "cache loss" by decoding from serialized bytes and
        // verifying reconstruction produces the same envelope.
        let event = OrchestrationEvent::Started(OrchestrationStarted::new(
            "orch-001", "work-001", 10, 100_000, 60_000, 1000,
        ));

        let (_, bytes) = envelope_from_orchestration_event(&event, FinalitySignal::Local).unwrap();

        // "Cache loss": decode from raw bytes only
        let reconstructed = decode_envelope(&bytes).unwrap();

        // Verify reconstruction is faithful
        assert_eq!(reconstructed.schema_version, ENVELOPE_SCHEMA_VERSION);
        assert_eq!(reconstructed.event_kind, "orchestration.started");
        assert!(reconstructed.is_authority_event());
        assert_eq!(reconstructed.finality, FinalitySignal::Local);

        // Verify the reconstructed envelope re-serializes identically
        let re_bytes = serde_jcs::to_vec(&reconstructed).unwrap();
        assert_eq!(bytes, re_bytes);
    }

    #[test]
    fn multi_event_sequence_round_trip_reconstructibility() {
        // Create a sequence of events, encode them all, then reconstruct
        // from just the serialized bytes and verify equivalence.
        let digest = HexDigest::try_new("b".repeat(64), "test").unwrap();
        let envelopes = vec![
            HolonEventEnvelope {
                schema_version: 1,
                event_kind: "work_created".into(),
                payload: serde_json::json!({"title": "Test work"}),
                holon_event_hash: None,
                artifact_cas_digest: None,
                finality: FinalitySignal::Local,
            },
            HolonEventEnvelope {
                schema_version: 1,
                event_kind: "lease_issued".into(),
                payload: serde_json::json!({"lease_id": "L-001", "holder_id": "H-001"}),
                holon_event_hash: None,
                artifact_cas_digest: Some(digest),
                finality: FinalitySignal::Local,
            },
            HolonEventEnvelope {
                schema_version: 1,
                event_kind: "work_completed".into(),
                payload: serde_json::json!({"evidence_ids": ["ev-001"]}),
                holon_event_hash: None,
                artifact_cas_digest: None,
                finality: FinalitySignal::Finalized { epoch: 1, round: 3 },
            },
        ];

        // Encode all envelopes
        let serialized: Vec<Vec<u8>> = envelopes
            .iter()
            .map(|env| serde_jcs::to_vec(env).unwrap())
            .collect();

        // Reconstruct all from serialized bytes only (simulating cache loss)
        let reconstructed: Vec<HolonEventEnvelope> = serialized
            .iter()
            .map(|bytes| decode_envelope(bytes).unwrap())
            .collect();

        // Verify each reconstructed envelope matches the original
        assert_eq!(envelopes.len(), reconstructed.len());
        for (original, restored) in envelopes.iter().zip(reconstructed.iter()) {
            assert_eq!(original.schema_version, restored.schema_version);
            assert_eq!(original.event_kind, restored.event_kind);
            assert_eq!(original.holon_event_hash, restored.holon_event_hash);
            assert_eq!(original.artifact_cas_digest, restored.artifact_cas_digest);
            assert_eq!(original.finality, restored.finality);

            // Re-encode and verify byte equality
            let orig_bytes = serde_jcs::to_vec(original).unwrap();
            let restored_bytes = serde_jcs::to_vec(restored).unwrap();
            assert_eq!(orig_bytes, restored_bytes);
        }

        // Verify replay stats match
        let original_stats = inspect_replay_stats(&envelopes);
        let restored_stats = inspect_replay_stats(&reconstructed);
        assert_eq!(original_stats, restored_stats);
        assert_eq!(original_stats.event_count, 3);
        assert_eq!(original_stats.authority_count, 2); // lease_issued + work_completed
    }

    // -----------------------------------------------------------------------
    // HL-004: Reconstructibility — legacy bridge
    // -----------------------------------------------------------------------

    #[cfg(feature = "legacy_holon_ledger")]
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

        let hash = genesis.compute_hash();
        assert!(!hash.is_zero());

        let (_, payload) =
            envelope_from_ledger_event(&genesis, None, FinalitySignal::Local).unwrap();
        let envelope = decode_envelope(&payload).unwrap();

        assert!(envelope.holon_event_hash.is_some());
        assert_eq!(
            envelope.holon_event_hash.as_ref().unwrap().as_str(),
            hash.to_hex()
        );
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

    // -----------------------------------------------------------------------
    // CoreLedgerWriter integration test
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn core_ledger_writer_writes_orchestration_event() {
        use std::sync::Arc;

        use apm2_core::ledger::{LedgerBackend, SqliteLedgerBackend};

        let backend: Arc<dyn LedgerBackend> = Arc::new(SqliteLedgerBackend::in_memory().unwrap());

        let writer =
            CoreLedgerWriter::new(backend.clone(), "holon-test", "session-001", "actor-001");

        let event = OrchestrationEvent::Started(OrchestrationStarted::new(
            "orch-001", "work-001", 10, 100_000, 60_000, 1000,
        ));

        let seq_id = writer
            .write_orchestration_event(
                &event,
                FinalitySignal::Finalized { epoch: 1, round: 2 },
                5_000_000,
            )
            .await
            .unwrap();

        assert!(seq_id > 0, "event must be assigned a sequence ID");

        // Read back and verify
        let events: Vec<apm2_core::ledger::EventRecord> =
            backend.read_from("holon-test", 0, 10).await.unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "holon.orchestration.started");
        assert_eq!(events[0].session_id, "session-001");
        assert_eq!(events[0].actor_id, "actor-001");
        assert_eq!(events[0].consensus_epoch, Some(1));
        assert_eq!(events[0].consensus_round, Some(2));

        // Decode the payload and verify content
        let envelope = decode_envelope(&events[0].payload).unwrap();
        assert_eq!(envelope.event_kind, "orchestration.started");
        assert!(envelope.is_authority_event());
        assert_eq!(
            envelope.finality,
            FinalitySignal::Finalized { epoch: 1, round: 2 }
        );
    }
}
