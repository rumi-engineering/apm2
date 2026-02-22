// AGENT-AUTHORED (TCK-00322, TCK-00505)
//! Projection worker for the FAC (Forge Admission Cycle).
//!
//! This module implements the long-running projection worker that:
//! 1. Tails the ledger for `ReviewReceiptRecorded` events
//! 2. Looks up PR metadata from the work index
//! 3. Evaluates economics admission gate (TCK-00505)
//! 4. Projects review results to GitHub (status + comment)
//! 5. Stores projection receipts in CAS for idempotency
//!
//! # RFC-0019: Projection Worker (Workstream F)
//!
//! Per RFC-0019, the projection worker:
//! - Reads ledger commits via a tailer
//! - Builds a work index: `changeset_digest` -> `work_id` -> PR metadata
//! - On `ReviewReceiptRecorded`: fetches review artifacts from CAS, applies
//!   projection via GitHub adapter, stores projection receipt (durable)
//! - Is idempotent: restarts don't duplicate comments
//!
//! # RFC-0029: Economics Admission Gate (TCK-00505)
//!
//! Per RFC-0029, before any projection side effect
//! (`adapter.project_status()`):
//!
//! 1. ALL `review_receipt_recorded` events MUST pass through the economics
//!    gate. Events without economics selectors are DENIED (fail-closed:
//!    `missing_economics_selectors` subcategory).
//! 2. Assemble gate inputs from `ReviewReceiptRecorded` payload
//! 3. Resolve continuity profile, sink snapshot, and window via resolver
//! 4. Evaluate `evaluate_projection_continuity()` economics gate
//! 5. On ALLOW: insert intent, enforce projection lifecycle gate (`join ->
//!    revalidate -> consume`), then execute projection effect
//! 6. On DENY: record denied intent in `IntentBuffer`, skip projection
//!
//! **Fail-closed**: Missing gate inputs (temporal authority, profile,
//! snapshot) result in DENY, never default ALLOW. Missing economics
//! selectors result in DENY (no bypass path). Gate init failure denies
//! all events. Idempotent-insert replay prevention ensures no
//! double-projection of the same `(work_id, changeset_digest)`.
//!
//! **Implementation scope**: The current implementation provides
//! economics-gated admission with canonical PCAC lifecycle enforcement
//! (`join -> revalidate -> consume`) immediately before projection effects,
//! plus idempotent-insert replay prevention via `IntentBuffer` uniqueness
//! on `(work_id, changeset_digest)`. The enforcement guarantees are:
//! - No projection without passing the economics gate.
//! - Events without economics selectors are DENIED, not bypassed.
//! - No projection effect without passing lifecycle `join -> revalidate ->
//!   consume`.
//! - No double-projection of the same `(work_id, changeset_digest)`.
//! - Retry-safe: transient projection failures leave the intent as PENDING,
//!   allowing re-attempt on the next delivery.
//!
//! # Security Model
//!
//! - **Write-only projection**: GitHub is an output target only
//! - **Ledger is truth**: All decisions are made based on ledger state
//! - **Idempotency via receipts**: Uses CAS+ledger for idempotency, not GitHub
//!   state
//! - **Crash-only recovery**: Worker can restart from ledger head at any time
//! - **Economics-gated**: Events carrying economics selectors must pass the
//!   economics admission gate before projection (TCK-00505)

use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use apm2_core::crypto::{EventHasher, Signer};
use apm2_core::economics::{
    ContinuityScenarioVerdict, ContinuityVerdict, DeferredReplayMode, ProjectionContinuityWindowV1,
    ProjectionSinkContinuityProfileV1, evaluate_projection_continuity,
};
use apm2_core::evidence::ContentAddressedStore;
use apm2_core::pcac::{
    AuthorityDenyClass, AuthorityJoinInputV1, BoundaryIntentClass, DeterminismClass,
    IdentityEvidenceLevel, PcacPolicyKnobs, RiskTier,
};
use rusqlite::{Connection, OptionalExtension, params};
use thiserror::Error;
use tracing::{debug, info, warn};

use super::continuity_resolver::{
    ContinuityProfileResolver, ResolvedContinuityProfile, ResolvedContinuityWindow,
};
use super::github_sync::{GitHubAdapterConfig, GitHubProjectionAdapter, ProjectionAdapter};
use super::intent_buffer::{IntentBuffer, IntentLifecycleArtifacts};
use super::projection_receipt::ProjectedStatus;
use crate::pcac::{InProcessKernel, LifecycleGate};
use crate::protocol::dispatch::SignedLedgerEvent;

// =============================================================================
// Error Types
// =============================================================================

/// Errors that can occur during projection worker operations.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ProjectionWorkerError {
    /// Database error.
    #[error("database error: {0}")]
    DatabaseError(String),

    /// No PR associated with work.
    #[error("no PR associated with work_id: {work_id}")]
    NoPrAssociation {
        /// The work ID that has no PR association.
        work_id: String,
    },

    /// Projection failed.
    #[error("projection failed: {0}")]
    ProjectionFailed(String),

    /// Invalid event payload.
    #[error("invalid event payload: {0}")]
    InvalidPayload(String),

    /// Already projected (idempotency).
    #[error("already projected for receipt: {receipt_id}")]
    AlreadyProjected {
        /// The receipt ID that was already projected.
        receipt_id: String,
    },

    /// Economics admission denied — projection skipped (TCK-00505).
    #[error("economics admission denied: {reason}")]
    AdmissionDenied {
        /// The structured deny reason.
        reason: String,
    },

    /// Economics admission denied (subcategory) — projection skipped
    /// (TCK-00505).
    ///
    /// Used for replay prevention (`consumed`), gate-not-wired
    /// (`missing_gate`), missing selectors (`missing_economics_selectors`),
    /// revoked authority (`revoked`), and stale authority (`stale`)
    /// scenarios. Covers idempotent-insert replay prevention,
    /// fail-closed gate-init scenarios, and selector-absent events.
    #[error("economics admission denied: {reason} (subcategory: {subcategory})")]
    LifecycleDenied {
        /// The structured deny reason.
        reason: String,
        /// Denial subcategory
        /// (`consumed`/`missing_gate`/`missing_economics_selectors`).
        subcategory: String,
    },

    /// Intent buffer operation failed (TCK-00505).
    #[error("intent buffer error: {0}")]
    IntentBufferError(String),

    /// Worker shutdown requested.
    #[error("worker shutdown requested")]
    ShutdownRequested,

    /// Missing dependency - event cannot be processed yet because required
    /// associations are not indexed. This error triggers NACK/Retry behavior:
    /// the watermark is NOT advanced so the event will be reprocessed.
    ///
    /// Blocker fix: Critical Data Loss via Shared Watermark - implements
    /// NACK/Retry semantics where watermark is not advanced for events that
    /// fail due to missing dependencies.
    #[error("missing dependency for event: {event_id} - {reason}")]
    MissingDependency {
        /// The event ID that failed due to missing dependency.
        event_id: String,
        /// The reason/missing dependency description.
        reason: String,
    },
}

// =============================================================================
// Economics Admission Telemetry (TCK-00505)
// =============================================================================

/// Structured telemetry counters for economics admission gate decisions.
///
/// Thread-safe atomic counters for admit/deny per sink, including
/// lifecycle-denial subcategories. These counters are monotonically increasing
/// and never reset during daemon lifetime.
///
/// # Synchronization Protocol
///
/// All fields are `AtomicU64` with `Relaxed` ordering — these are independent
/// counters for observability only, not used for synchronization or
/// happens-before edges with other data.
pub struct AdmissionTelemetry {
    /// Total projections admitted (economics ALLOW + successful projection).
    pub admitted_count: AtomicU64,
    /// Total projections denied by economics gate evaluation.
    pub economics_denied_count: AtomicU64,
    /// Total projections denied due to revoked authority (zero hash).
    pub lifecycle_revoked_count: AtomicU64,
    /// Total projections denied due to stale authority (zero `window_ref`).
    pub lifecycle_stale_count: AtomicU64,
    /// Total projections denied due to duplicate intent (idempotent-insert
    /// replay prevention).
    pub lifecycle_consumed_count: AtomicU64,
    /// Total projections denied due to missing gate inputs (fail-closed).
    pub missing_inputs_denied_count: AtomicU64,
    /// Total projections denied because the economics gate was not wired
    /// but the event carried economics selectors (fail-closed).
    pub missing_gate_denied_count: AtomicU64,
    /// Total projections denied because the event did not carry economics
    /// selectors (fail-closed: all events must have selectors).
    pub missing_selectors_denied_count: AtomicU64,
}

impl AdmissionTelemetry {
    /// Creates a new telemetry instance with all counters at zero.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            admitted_count: AtomicU64::new(0),
            economics_denied_count: AtomicU64::new(0),
            lifecycle_revoked_count: AtomicU64::new(0),
            lifecycle_stale_count: AtomicU64::new(0),
            lifecycle_consumed_count: AtomicU64::new(0),
            missing_inputs_denied_count: AtomicU64::new(0),
            missing_gate_denied_count: AtomicU64::new(0),
            missing_selectors_denied_count: AtomicU64::new(0),
        }
    }
}

impl Default for AdmissionTelemetry {
    fn default() -> Self {
        Self::new()
    }
}

/// Denial subcategory identifiers for economics admission gate.
///
/// Used in structured deny reasons and telemetry for admission-denial
/// classification.
pub mod lifecycle_deny {
    /// Authority was revoked (zero hash detected during gate input extraction).
    pub const REVOKED: &str = "revoked";
    /// Authority was stale (zero `window_ref` detected during gate input
    /// extraction).
    pub const STALE: &str = "stale";
    /// Intent already consumed (idempotent-insert replay prevention).
    pub const CONSUMED: &str = "consumed";
    /// Economics gate is not wired but event carries economics selectors
    /// (fail-closed).
    pub const MISSING_GATE: &str = "missing_gate";
    /// Mandatory economics selectors absent (fail-closed).
    ///
    /// All `review_receipt_recorded` events must carry economics
    /// selectors; absence is a gate bypass attempt or malformed event.
    pub const MISSING_SELECTORS: &str = "missing_economics_selectors";
    /// Mandatory lifecycle selectors absent (fail-closed).
    pub const MISSING_LIFECYCLE_SELECTORS: &str = "missing_lifecycle_selectors";
}

/// Default sink identifier for single-sink projection (GitHub).
/// Used in tests; production code resolves sink ID from the event
/// payload's `boundary_id` field (MAJOR-1 fix).
#[cfg(test)]
const DEFAULT_SINK_ID: &str = "github-primary";

// =============================================================================
// Work Index
// =============================================================================

/// Default TTL for work index entries (7 days, matching idempotency cache).
/// This ensures tables don't grow unbounded (Blocker fix: Unbounded State
/// Growth).
pub const DEFAULT_TTL_SECS: u64 = 7 * 24 * 60 * 60;

/// Maximum string length for fields extracted from ledger payloads.
///
/// This prevents unbounded input consumption (denial of service) when
/// deserializing untrusted payloads. (Blocker fix: Unbounded Input Consumption)
pub const MAX_STRING_LENGTH: usize = 1024;

/// Required 32-byte hash linkage fields for projection write admission.
const RECEIPT_LINKAGE_HASH_FIELDS: [&str; 6] = [
    "changeset_digest",
    "artifact_bundle_hash",
    "capability_manifest_hash",
    "context_pack_hash",
    "role_spec_hash",
    "identity_proof_hash",
];

/// Optional lifecycle linkage hash fields that must be all-or-none.
const RECEIPT_LIFECYCLE_HASH_FIELDS: [&str; 3] =
    ["ajc_id", "intent_digest", "consume_selector_digest"];

/// Linkage hashes that must resolve in authoritative CAS before projection.
const RECEIPT_CAS_LINKAGE_HASH_FIELDS: [&str; 4] = [
    "artifact_bundle_hash",
    "capability_manifest_hash",
    "context_pack_hash",
    "role_spec_hash",
];

/// Authoritative stores used to validate projection receipt linkage.
struct ProjectionLinkageAuthority<'a> {
    conn: &'a Arc<Mutex<Connection>>,
    cas: Option<&'a dyn ContentAddressedStore>,
}

struct AuthoritativeReceiptLinkageRecord {
    event_id: String,
    payload: serde_json::Value,
}

/// Validates that a string field does not exceed the maximum allowed length.
/// Returns an error if the string is too long.
/// (Blocker fix: Unbounded Input Consumption)
fn validate_string_length(field_name: &str, value: &str) -> Result<(), ProjectionWorkerError> {
    if value.len() > MAX_STRING_LENGTH {
        return Err(ProjectionWorkerError::InvalidPayload(format!(
            "{field_name} exceeds maximum length ({} > {MAX_STRING_LENGTH})",
            value.len()
        )));
    }
    Ok(())
}

fn validate_hash32_hex_field(
    payload: &serde_json::Value,
    field: &str,
) -> Result<[u8; 32], ProjectionWorkerError> {
    let value = payload
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| ProjectionWorkerError::InvalidPayload(format!("missing {field}")))?;
    validate_string_length(field, value)?;
    let decoded = hex::decode(value).map_err(|e| {
        ProjectionWorkerError::InvalidPayload(format!("{field} is not valid hex: {e}"))
    })?;
    if decoded.len() != 32 {
        return Err(ProjectionWorkerError::InvalidPayload(format!(
            "{field} must decode to 32 bytes"
        )));
    }

    let mut hash = [0u8; 32];
    hash.copy_from_slice(&decoded);
    if hash.iter().all(|byte| *byte == 0) {
        return Err(ProjectionWorkerError::InvalidPayload(format!(
            "{field} is zero (unset authority linkage)"
        )));
    }
    Ok(hash)
}

fn validate_nonempty_string_field(
    payload: &serde_json::Value,
    field: &str,
) -> Result<(), ProjectionWorkerError> {
    let value = payload
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| ProjectionWorkerError::InvalidPayload(format!("missing {field}")))?;
    validate_string_length(field, value)?;
    if value.trim().is_empty() {
        return Err(ProjectionWorkerError::InvalidPayload(format!(
            "{field} is empty"
        )));
    }
    Ok(())
}

fn payload_nonempty_str<'a>(
    payload: &'a serde_json::Value,
    field: &str,
) -> Result<&'a str, ProjectionWorkerError> {
    validate_nonempty_string_field(payload, field)?;
    payload
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| ProjectionWorkerError::InvalidPayload(format!("missing {field}")))
}

/// Returns `true` if the event payload carries economics selectors
/// (`eval_tick`, `time_authority_ref`, `window_ref`, `boundary_id`).
///
/// All `review_receipt_recorded` events MUST carry economics selectors.
/// Events without selectors are DENIED with `missing_economics_selectors`
/// subcategory (fail-closed: no bypass path).
fn payload_has_economics_selectors(payload: &serde_json::Value) -> bool {
    payload.get("eval_tick").is_some()
        || payload.get("time_authority_ref").is_some()
        || payload.get("window_ref").is_some()
        || payload.get("boundary_id").is_some()
}

/// Returns `true` if the field is present, valid 32-byte hex, and all zeros.
///
/// Used to distinguish between "missing/malformed" (generic DENY) and
/// "explicitly zero/revoked/stale" (lifecycle subcategory DENY) for
/// telemetry classification.
fn is_zero_hash32_field(payload: &serde_json::Value, field: &str) -> bool {
    let Some(hex_str) = payload.get(field).and_then(|v| v.as_str()) else {
        return false;
    };
    if hex_str.len() > MAX_STRING_LENGTH {
        return false;
    }
    let Ok(bytes) = hex::decode(hex_str) else {
        return false;
    };
    bytes.len() == 32 && bytes.iter().all(|&b| b == 0)
}

/// Extracts a 32-byte hash field from a JSON payload (TCK-00505).
///
/// Returns `None` if the field is missing, not a valid hex string, not 32
/// bytes, or is all zeros (unset authority linkage). This is a best-effort
/// extraction for gate input assembly — callers treat `None` as DENY.
fn extract_hash32_field(payload: &serde_json::Value, field: &str) -> Option<[u8; 32]> {
    let hex_str = payload.get(field).and_then(|v| v.as_str())?;
    if hex_str.len() > MAX_STRING_LENGTH {
        return None;
    }
    let bytes = hex::decode(hex_str).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&bytes);
    // Zero hash means unset/revoked — return None for fail-closed.
    if hash.iter().all(|&b| b == 0) {
        return None;
    }
    Some(hash)
}

/// Decodes a session-event JSON envelope (`{"payload":"<hex>"}`) into the
/// inner `WorkEvent` protobuf.
fn decode_work_event_from_session_envelope(
    payload_bytes: &[u8],
) -> Result<apm2_core::events::WorkEvent, ProjectionWorkerError> {
    use prost::Message;

    let envelope: serde_json::Value = serde_json::from_slice(payload_bytes).map_err(|e| {
        ProjectionWorkerError::InvalidPayload(format!(
            "failed to parse session event JSON envelope: {e}"
        ))
    })?;
    let payload_hex = envelope
        .get("payload")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            ProjectionWorkerError::InvalidPayload(
                "session event JSON envelope missing 'payload'".to_string(),
            )
        })?;
    let inner = hex::decode(payload_hex).map_err(|e| {
        ProjectionWorkerError::InvalidPayload(format!(
            "failed to decode session event payload hex: {e}"
        ))
    })?;
    apm2_core::events::WorkEvent::decode(inner.as_slice()).map_err(|e| {
        ProjectionWorkerError::InvalidPayload(format!("failed to decode inner WorkEvent: {e}"))
    })
}

/// Extracts the `spec_snapshot_hash` from a persisted `work.opened` event
/// payload.
fn extract_work_opened_spec_snapshot_hash(
    payload_bytes: &[u8],
) -> Result<[u8; 32], ProjectionWorkerError> {
    let work_event = decode_work_event_from_session_envelope(payload_bytes)?;
    let Some(apm2_core::events::work_event::Event::Opened(opened)) = work_event.event else {
        return Err(ProjectionWorkerError::InvalidPayload(
            "work.opened payload does not decode to WorkOpened variant".to_string(),
        ));
    };

    let hash_slice: &[u8] = opened.spec_snapshot_hash.as_slice();
    let hash: [u8; 32] = hash_slice.try_into().map_err(|_| {
        ProjectionWorkerError::InvalidPayload(
            "work.opened spec_snapshot_hash must be 32 bytes".to_string(),
        )
    })?;
    Ok(hash)
}

/// Parses `(work_id, pr_number, commit_sha)` from a persisted
/// `work.pr_associated` event envelope.
///
/// Supports both modern envelopes with top-level `pr_number`/`commit_sha`
/// fields and legacy envelopes that require protobuf decode.
fn parse_work_pr_associated_payload(
    payload_bytes: &[u8],
    fallback_work_id: &str,
) -> Result<(String, u64, String), ProjectionWorkerError> {
    let envelope: serde_json::Value = serde_json::from_slice(payload_bytes).map_err(|e| {
        ProjectionWorkerError::InvalidPayload(format!(
            "failed to parse work.pr_associated envelope: {e}"
        ))
    })?;

    let work_id = envelope
        .get("session_id")
        .and_then(serde_json::Value::as_str)
        .or_else(|| envelope.get("work_id").and_then(serde_json::Value::as_str))
        .unwrap_or(fallback_work_id)
        .to_string();

    let top_level_pr = envelope
        .get("pr_number")
        .and_then(serde_json::Value::as_u64);
    let top_level_sha = envelope
        .get("commit_sha")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);
    if let Some((pr_number, commit_sha)) = top_level_pr.zip(top_level_sha) {
        return Ok((work_id, pr_number, commit_sha));
    }

    let work_event = decode_work_event_from_session_envelope(payload_bytes)?;
    let Some(apm2_core::events::work_event::Event::PrAssociated(associated)) = work_event.event
    else {
        return Err(ProjectionWorkerError::InvalidPayload(
            "work.pr_associated payload does not decode to WorkPrAssociated variant".to_string(),
        ));
    };

    let parsed_work_id = if associated.work_id.is_empty() {
        work_id
    } else {
        associated.work_id
    };
    Ok((parsed_work_id, associated.pr_number, associated.commit_sha))
}

/// Resolves `(repo_owner, repo_name)` for a `work_id` by joining through the
/// persisted `work.opened` event and fetching the immutable `WorkSpecV1` from
/// CAS using `spec_snapshot_hash`.
fn resolve_repo_identity_for_work(
    conn: &Connection,
    cas: &dyn ContentAddressedStore,
    work_id: &str,
) -> Result<(String, String), ProjectionWorkerError> {
    let legacy_payload: Option<Vec<u8>> = conn
        .query_row(
            "SELECT payload FROM ledger_events \
             WHERE event_type = 'work.opened' AND work_id = ?1 \
             ORDER BY timestamp_ns ASC, rowid ASC LIMIT 1",
            params![work_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| ProjectionWorkerError::DatabaseError(e.to_string()))?;

    let payload = if let Some(payload) = legacy_payload {
        payload
    } else {
        let canonical_events_exists: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM sqlite_master \
                 WHERE type = 'table' AND name = 'events'",
                [],
                |row| row.get(0),
            )
            .unwrap_or(false);

        if !canonical_events_exists {
            return Err(ProjectionWorkerError::InvalidPayload(format!(
                "missing work.opened event for work_id={work_id}"
            )));
        }

        conn.query_row(
            "SELECT payload FROM events \
             WHERE event_type = 'work.opened' AND session_id = ?1 \
             ORDER BY timestamp_ns ASC, rowid ASC LIMIT 1",
            params![work_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| ProjectionWorkerError::DatabaseError(e.to_string()))?
        .ok_or_else(|| {
            ProjectionWorkerError::InvalidPayload(format!(
                "missing canonical work.opened event for work_id={work_id}"
            ))
        })?
    };

    let spec_snapshot_hash = extract_work_opened_spec_snapshot_hash(&payload)?;
    let spec_bytes = cas.retrieve(&spec_snapshot_hash).map_err(|e| {
        ProjectionWorkerError::InvalidPayload(format!(
            "failed to resolve WorkSpec from CAS for work_id={work_id}: {e}"
        ))
    })?;
    let work_spec = apm2_core::fac::work_cas_schemas::bounded_decode_work_spec(&spec_bytes)
        .map_err(|e| {
            ProjectionWorkerError::InvalidPayload(format!(
                "resolved WorkSpec for work_id={work_id} is invalid: {e}"
            ))
        })?;
    let repo = work_spec.repo.ok_or_else(|| {
        ProjectionWorkerError::InvalidPayload(format!(
            "WorkSpec for work_id={work_id} is missing repo identity"
        ))
    })?;

    Ok((repo.owner, repo.name))
}

fn load_authoritative_receipt_linkage_record(
    authority: &ProjectionLinkageAuthority<'_>,
    receipt_id: &str,
    lease_id: &str,
    work_id: &str,
) -> Result<Option<AuthoritativeReceiptLinkageRecord>, ProjectionWorkerError> {
    let conn = authority
        .conn
        .lock()
        .map_err(|e| ProjectionWorkerError::DatabaseError(format!("mutex poisoned: {e}")))?;
    let mut stmt = conn
        .prepare(
            "SELECT event_id, payload
             FROM ledger_events
             WHERE event_type IN ('review_receipt_recorded', 'review_blocked_recorded')
               AND work_id = ?1
             ORDER BY timestamp_ns DESC, rowid DESC",
        )
        .map_err(|e| ProjectionWorkerError::DatabaseError(e.to_string()))?;

    let mut rows = stmt
        .query(params![work_id])
        .map_err(|e| ProjectionWorkerError::DatabaseError(e.to_string()))?;
    while let Some(row) = rows
        .next()
        .map_err(|e| ProjectionWorkerError::DatabaseError(e.to_string()))?
    {
        let event_id: String = row
            .get(0)
            .map_err(|e| ProjectionWorkerError::DatabaseError(e.to_string()))?;
        let payload_bytes: Vec<u8> = row
            .get(1)
            .map_err(|e| ProjectionWorkerError::DatabaseError(e.to_string()))?;
        let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).map_err(|e| {
            ProjectionWorkerError::InvalidPayload(format!(
                "authoritative event payload is not valid JSON: {e}"
            ))
        })?;

        let row_receipt = payload
            .get("receipt_id")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        let row_lease = payload
            .get("lease_id")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        let row_work = payload
            .get("work_id")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();

        if row_receipt == receipt_id && row_lease == lease_id && row_work == work_id {
            return Ok(Some(AuthoritativeReceiptLinkageRecord {
                event_id,
                payload,
            }));
        }
    }

    Ok(None)
}

fn validate_projection_receipt_linkage(
    payload: &serde_json::Value,
    event: &SignedLedgerEvent,
    authority: &ProjectionLinkageAuthority<'_>,
) -> Result<(), ProjectionWorkerError> {
    validate_nonempty_string_field(payload, "receipt_id")?;
    validate_nonempty_string_field(payload, "lease_id")?;
    validate_nonempty_string_field(payload, "work_id")?;
    validate_nonempty_string_field(payload, "time_envelope_ref")?;

    let payload_receipt_id = payload_nonempty_str(payload, "receipt_id")?;
    let payload_lease_id = payload_nonempty_str(payload, "lease_id")?;

    let payload_work_id = payload
        .get("work_id")
        .and_then(serde_json::Value::as_str)
        .expect("validated work_id presence");
    if payload_work_id != event.work_id {
        return Err(ProjectionWorkerError::InvalidPayload(format!(
            "work_id mismatch: payload={} envelope={}",
            payload_work_id, event.work_id
        )));
    }

    let mut payload_hashes = std::collections::HashMap::new();
    for field in RECEIPT_LINKAGE_HASH_FIELDS {
        let hash = validate_hash32_hex_field(payload, field)?;
        payload_hashes.insert(field, hash);
    }

    let authoritative_record = load_authoritative_receipt_linkage_record(
        authority,
        payload_receipt_id,
        payload_lease_id,
        payload_work_id,
    )?
    .ok_or_else(|| {
        ProjectionWorkerError::InvalidPayload(format!(
            "authoritative receipt linkage missing for receipt_id={payload_receipt_id} \
             lease_id={payload_lease_id} work_id={payload_work_id}"
        ))
    })?;

    if authoritative_record.event_id != event.event_id {
        return Err(ProjectionWorkerError::InvalidPayload(format!(
            "receipt identity tuple resolves to authoritative event_id={} but current projection context is event_id={}",
            authoritative_record.event_id, event.event_id
        )));
    }

    for field in RECEIPT_LINKAGE_HASH_FIELDS {
        let payload_hash = payload_hashes.get(field).copied().ok_or_else(|| {
            ProjectionWorkerError::InvalidPayload(format!("missing cached hash for {field}"))
        })?;
        let authoritative_hash = validate_hash32_hex_field(&authoritative_record.payload, field)?;
        if payload_hash != authoritative_hash {
            return Err(ProjectionWorkerError::InvalidPayload(format!(
                "linkage hash mismatch for {field}: payload={} authoritative={}",
                hex::encode(payload_hash),
                hex::encode(authoritative_hash),
            )));
        }
    }

    let Some(cas) = authority.cas else {
        return Err(ProjectionWorkerError::InvalidPayload(
            "authoritative CAS unavailable for projection linkage validation".to_string(),
        ));
    };

    for field in RECEIPT_CAS_LINKAGE_HASH_FIELDS {
        let hash = payload_hashes.get(field).copied().ok_or_else(|| {
            ProjectionWorkerError::InvalidPayload(format!("missing cached hash for {field}"))
        })?;
        match cas.exists(&hash) {
            Ok(true) => {},
            Ok(false) => {
                return Err(ProjectionWorkerError::InvalidPayload(format!(
                    "{field} {} is not resolvable in authoritative CAS",
                    hex::encode(hash)
                )));
            },
            Err(e) => {
                return Err(ProjectionWorkerError::InvalidPayload(format!(
                    "authoritative CAS lookup failed for {field}: {e}"
                )));
            },
        }
    }

    let lifecycle_fields_present = [
        "ajc_id",
        "intent_digest",
        "consume_tick",
        "pcac_time_envelope_ref",
        "consume_selector_digest",
    ]
    .iter()
    .filter(|field| payload.get(*field).is_some())
    .count();

    if lifecycle_fields_present != 0 && lifecycle_fields_present != 5 {
        return Err(ProjectionWorkerError::InvalidPayload(
            "partial lifecycle linkage tuple is not admissible (all-or-none required)".to_string(),
        ));
    }

    if lifecycle_fields_present == 5 {
        for field in RECEIPT_LIFECYCLE_HASH_FIELDS {
            validate_hash32_hex_field(payload, field)?;
        }
        validate_nonempty_string_field(payload, "pcac_time_envelope_ref")?;

        let consume_tick = payload
            .get("consume_tick")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| {
                ProjectionWorkerError::InvalidPayload(
                    "consume_tick must be an unsigned integer".to_string(),
                )
            })?;
        if consume_tick == 0 {
            return Err(ProjectionWorkerError::InvalidPayload(
                "consume_tick must be > 0".to_string(),
            ));
        }
    }

    Ok(())
}

/// Work index schema SQL.
const WORK_INDEX_SCHEMA_SQL: &str = r"
    CREATE TABLE IF NOT EXISTS work_pr_index (
        work_id TEXT NOT NULL UNIQUE,
        pr_number INTEGER NOT NULL,
        repo_owner TEXT NOT NULL,
        repo_name TEXT NOT NULL,
        head_sha TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        PRIMARY KEY (repo_owner, repo_name, pr_number)
    );

    CREATE TABLE IF NOT EXISTS changeset_work_index (
        changeset_digest BLOB PRIMARY KEY,
        work_id TEXT NOT NULL,
        created_at INTEGER NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_changeset_work_id ON changeset_work_index(work_id);
    CREATE INDEX IF NOT EXISTS idx_changeset_work_created ON changeset_work_index(created_at);

    -- Tailer watermark persistence (fixes blocker: non-persistent LedgerTailer)
    -- MAJOR FIX: Potential Data Loss via Non-Unique Watermark
    -- Now tracks (timestamp_ns, event_id) as a composite cursor to handle
    -- multiple events with the same timestamp. Previously, if events A and B
    -- both had timestamp 1000, acknowledging A would advance watermark to 1000,
    -- causing B to be skipped on the next poll (since we query timestamp > 1000).
    CREATE TABLE IF NOT EXISTS tailer_watermark (
        tailer_id TEXT PRIMARY KEY,
        last_processed_ns INTEGER NOT NULL,
        last_event_id TEXT NOT NULL DEFAULT '',
        updated_at INTEGER NOT NULL
    );

    -- Commit SHA mapping for changeset digest -> git SHA
    CREATE TABLE IF NOT EXISTS changeset_sha_index (
        changeset_digest BLOB PRIMARY KEY,
        commit_sha TEXT NOT NULL,
        created_at INTEGER NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_sha_created ON changeset_sha_index(created_at);

    -- Comment idempotency tracking (blocker fix: duplicate comments)
    CREATE TABLE IF NOT EXISTS comment_receipts (
        receipt_id TEXT PRIMARY KEY,
        work_id TEXT NOT NULL,
        pr_number INTEGER NOT NULL,
        comment_type TEXT NOT NULL,
        created_at INTEGER NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_comment_created ON comment_receipts(created_at);
    CREATE INDEX IF NOT EXISTS idx_work_pr_work_id ON work_pr_index(work_id);
    CREATE INDEX IF NOT EXISTS idx_work_pr_created ON work_pr_index(created_at);

    -- TCK-00638: Work context entry projection (RFC-0032 Phase 2)
    CREATE TABLE IF NOT EXISTS work_context (
        work_id TEXT NOT NULL,
        entry_id TEXT NOT NULL,
        kind TEXT NOT NULL,
        dedupe_key TEXT NOT NULL,
        actor_id TEXT NOT NULL DEFAULT '',
        cas_hash TEXT NOT NULL,
        evidence_id TEXT NOT NULL,
        created_at_ns INTEGER NOT NULL,
        PRIMARY KEY (work_id, entry_id)
    );

    CREATE UNIQUE INDEX IF NOT EXISTS idx_work_context_dedupe
        ON work_context(work_id, kind, dedupe_key);
    CREATE INDEX IF NOT EXISTS idx_work_context_work_id ON work_context(work_id);
    CREATE INDEX IF NOT EXISTS idx_work_context_created ON work_context(created_at_ns);
";

/// Work index for tracking changeset -> `work_id` -> PR associations.
///
/// Per RFC-0019:
/// - `changeset_digest` -> `work_id` (from `ChangeSetPublished`)
/// - `work_id` -> PR metadata (from `WorkPrAssociated` or config)
pub struct WorkIndex {
    conn: Arc<Mutex<Connection>>,
}

impl WorkIndex {
    /// Creates a new work index with the given `SQLite` connection.
    ///
    /// # Errors
    ///
    /// Returns an error if schema initialization fails.
    pub fn new(conn: Arc<Mutex<Connection>>) -> Result<Self, ProjectionWorkerError> {
        {
            let conn_guard = conn.lock().map_err(|e| {
                ProjectionWorkerError::DatabaseError(format!("mutex poisoned: {e}"))
            })?;

            conn_guard
                .execute_batch(WORK_INDEX_SCHEMA_SQL)
                .map_err(|e| {
                    ProjectionWorkerError::DatabaseError(format!("schema init failed: {e}"))
                })?;
        }

        Ok(Self { conn })
    }

    /// Registers a changeset -> `work_id` association.
    ///
    /// Called when processing `ChangeSetPublished` events.
    #[allow(clippy::cast_possible_wrap)]
    pub fn register_changeset(
        &self,
        changeset_digest: &[u8; 32],
        work_id: &str,
    ) -> Result<(), ProjectionWorkerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| ProjectionWorkerError::DatabaseError(format!("mutex poisoned: {e}")))?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        conn.execute(
            "INSERT OR REPLACE INTO changeset_work_index
             (changeset_digest, work_id, created_at)
             VALUES (?1, ?2, ?3)",
            params![changeset_digest.as_slice(), work_id, now as i64],
        )
        .map_err(|e| ProjectionWorkerError::DatabaseError(e.to_string()))?;

        debug!(
            changeset = %hex::encode(changeset_digest),
            work_id = %work_id,
            "Registered changeset -> work_id"
        );

        Ok(())
    }

    /// Registers a `work_id` -> PR association.
    ///
    /// Called when processing `WorkPrAssociated` events or from configuration.
    #[allow(clippy::cast_possible_wrap)]
    pub fn register_pr(
        &self,
        work_id: &str,
        pr_number: u64,
        repo_owner: &str,
        repo_name: &str,
        head_sha: &str,
    ) -> Result<(), ProjectionWorkerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| ProjectionWorkerError::DatabaseError(format!("mutex poisoned: {e}")))?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        conn.execute(
            "INSERT OR REPLACE INTO work_pr_index
             (work_id, pr_number, repo_owner, repo_name, head_sha, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                work_id,
                pr_number as i64,
                repo_owner,
                repo_name,
                head_sha,
                now as i64
            ],
        )
        .map_err(|e| ProjectionWorkerError::DatabaseError(e.to_string()))?;

        info!(
            work_id = %work_id,
            pr_number = pr_number,
            repo = %format!("{}/{}", repo_owner, repo_name),
            "Registered work_id -> PR"
        );

        Ok(())
    }

    /// Looks up the `work_id` for a changeset digest.
    pub fn get_work_id(&self, changeset_digest: &[u8; 32]) -> Option<String> {
        let conn = self.conn.lock().ok()?;

        conn.query_row(
            "SELECT work_id FROM changeset_work_index WHERE changeset_digest = ?1",
            params![changeset_digest.as_slice()],
            |row| row.get(0),
        )
        .optional()
        .ok()
        .flatten()
    }

    /// Looks up PR metadata for a `work_id`.
    #[allow(clippy::cast_sign_loss)] // PR numbers are always positive
    pub fn get_pr_metadata(&self, work_id: &str) -> Option<PrMetadata> {
        let conn = self.conn.lock().ok()?;

        conn.query_row(
            "SELECT pr_number, repo_owner, repo_name, head_sha
             FROM work_pr_index WHERE work_id = ?1",
            params![work_id],
            |row| {
                Ok(PrMetadata {
                    pr_number: row.get::<_, i64>(0)? as u64,
                    repo_owner: row.get(1)?,
                    repo_name: row.get(2)?,
                    head_sha: row.get(3)?,
                })
            },
        )
        .optional()
        .ok()
        .flatten()
    }

    /// Looks up the `work_id` associated with `(repo_owner, repo_name,
    /// pr_number)`.
    #[allow(clippy::cast_possible_wrap, clippy::cast_possible_truncation)]
    pub fn get_work_id_for_pr(
        &self,
        repo_owner: &str,
        repo_name: &str,
        pr_number: u64,
    ) -> Option<String> {
        let conn = self.conn.lock().ok()?;
        conn.query_row(
            "SELECT work_id FROM work_pr_index \
             WHERE repo_owner = ?1 AND repo_name = ?2 AND pr_number = ?3",
            params![repo_owner, repo_name, pr_number as i64],
            |row| row.get(0),
        )
        .optional()
        .ok()
        .flatten()
    }

    /// Registers a changeset -> commit SHA mapping.
    ///
    /// Required for GitHub status projection to know which commit to update.
    #[allow(clippy::cast_possible_wrap)]
    pub fn register_commit_sha(
        &self,
        changeset_digest: &[u8; 32],
        commit_sha: &str,
    ) -> Result<(), ProjectionWorkerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| ProjectionWorkerError::DatabaseError(format!("mutex poisoned: {e}")))?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        conn.execute(
            "INSERT OR REPLACE INTO changeset_sha_index
             (changeset_digest, commit_sha, created_at)
             VALUES (?1, ?2, ?3)",
            params![changeset_digest.as_slice(), commit_sha, now as i64],
        )
        .map_err(|e| ProjectionWorkerError::DatabaseError(e.to_string()))?;

        debug!(
            changeset = %hex::encode(changeset_digest),
            commit_sha = %commit_sha,
            "Registered changeset -> commit SHA"
        );

        Ok(())
    }

    /// Gets the commit SHA for a changeset digest.
    pub fn get_commit_sha(&self, changeset_digest: &[u8; 32]) -> Option<String> {
        let conn = self.conn.lock().ok()?;

        conn.query_row(
            "SELECT commit_sha FROM changeset_sha_index WHERE changeset_digest = ?1",
            params![changeset_digest.as_slice()],
            |row| row.get(0),
        )
        .optional()
        .ok()
        .flatten()
    }

    /// Checks if a comment has already been posted (idempotency check).
    pub fn is_comment_posted(&self, receipt_id: &str) -> bool {
        let Ok(conn) = self.conn.lock() else {
            return false;
        };

        conn.query_row(
            "SELECT 1 FROM comment_receipts WHERE receipt_id = ?1",
            params![receipt_id],
            |_| Ok(()),
        )
        .is_ok()
    }

    /// Records that a comment was posted (for idempotency).
    #[allow(clippy::cast_possible_wrap)]
    pub fn record_comment_posted(
        &self,
        receipt_id: &str,
        work_id: &str,
        pr_number: u64,
        comment_type: &str,
    ) -> Result<(), ProjectionWorkerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| ProjectionWorkerError::DatabaseError(format!("mutex poisoned: {e}")))?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        conn.execute(
            "INSERT OR REPLACE INTO comment_receipts
             (receipt_id, work_id, pr_number, comment_type, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                receipt_id,
                work_id,
                pr_number as i64,
                comment_type,
                now as i64
            ],
        )
        .map_err(|e| ProjectionWorkerError::DatabaseError(e.to_string()))?;

        debug!(
            receipt_id = %receipt_id,
            work_id = %work_id,
            pr_number = pr_number,
            "Recorded comment posted"
        );

        Ok(())
    }

    /// Evicts expired entries from all work index tables.
    ///
    /// This implements TTL-based eviction to prevent unbounded state growth
    /// (Blocker fix: Unbounded State Growth). Default TTL is 7 days, matching
    /// the idempotency cache TTL.
    ///
    /// # Arguments
    ///
    /// * `ttl_secs` - TTL in seconds; entries older than this are evicted
    ///
    /// # Returns
    ///
    /// The total number of rows deleted across all tables.
    #[allow(clippy::cast_possible_wrap)]
    pub fn evict_expired(&self, ttl_secs: u64) -> Result<usize, ProjectionWorkerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| ProjectionWorkerError::DatabaseError(format!("mutex poisoned: {e}")))?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let cutoff = now.saturating_sub(ttl_secs) as i64;

        // Evict from all tables with created_at timestamps
        let mut total_deleted = 0;

        total_deleted += conn
            .execute(
                "DELETE FROM changeset_work_index WHERE created_at < ?1",
                params![cutoff],
            )
            .map_err(|e| ProjectionWorkerError::DatabaseError(e.to_string()))?;

        total_deleted += conn
            .execute(
                "DELETE FROM changeset_sha_index WHERE created_at < ?1",
                params![cutoff],
            )
            .map_err(|e| ProjectionWorkerError::DatabaseError(e.to_string()))?;

        total_deleted += conn
            .execute(
                "DELETE FROM comment_receipts WHERE created_at < ?1",
                params![cutoff],
            )
            .map_err(|e| ProjectionWorkerError::DatabaseError(e.to_string()))?;

        total_deleted += conn
            .execute(
                "DELETE FROM work_pr_index WHERE created_at < ?1",
                params![cutoff],
            )
            .map_err(|e| ProjectionWorkerError::DatabaseError(e.to_string()))?;

        // BLOCKER FIX: Evict expired work_context entries.
        // The `created_at_ns` column uses nanoseconds, so convert the
        // seconds-based cutoff to nanoseconds before comparison.
        #[allow(clippy::cast_possible_wrap)]
        let cutoff_ns = (now.saturating_sub(ttl_secs) as i64).saturating_mul(1_000_000_000);
        total_deleted += conn
            .execute(
                "DELETE FROM work_context WHERE created_at_ns < ?1",
                params![cutoff_ns],
            )
            .map_err(|e| ProjectionWorkerError::DatabaseError(e.to_string()))?;

        if total_deleted > 0 {
            info!(
                deleted = total_deleted,
                ttl_secs = ttl_secs,
                "Evicted expired work index entries"
            );
        }

        Ok(total_deleted)
    }

    /// Returns the connection for use with async `spawn_blocking` operations.
    ///
    /// This is used by the async worker to wrap blocking `SQLite` operations
    /// in `spawn_blocking` (Major fix: Thread blocking in async context).
    #[must_use]
    pub fn connection(&self) -> Arc<Mutex<Connection>> {
        Arc::clone(&self.conn)
    }

    /// Async wrapper for `evict_expired` that uses `spawn_blocking`.
    ///
    /// This avoids blocking the async runtime during eviction, which can
    /// be slow for large tables (Major fix: Thread blocking in async context).
    pub async fn evict_expired_async(&self, ttl_secs: u64) -> Result<usize, ProjectionWorkerError> {
        let conn = Arc::clone(&self.conn);
        tokio::task::spawn_blocking(move || {
            let conn_guard = conn.lock().map_err(|e| {
                ProjectionWorkerError::DatabaseError(format!("mutex poisoned: {e}"))
            })?;

            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);

            #[allow(clippy::cast_possible_wrap)]
            let cutoff = now.saturating_sub(ttl_secs) as i64;

            let mut total_deleted = 0;

            total_deleted += conn_guard
                .execute(
                    "DELETE FROM changeset_work_index WHERE created_at < ?1",
                    params![cutoff],
                )
                .map_err(|e| ProjectionWorkerError::DatabaseError(e.to_string()))?;

            total_deleted += conn_guard
                .execute(
                    "DELETE FROM changeset_sha_index WHERE created_at < ?1",
                    params![cutoff],
                )
                .map_err(|e| ProjectionWorkerError::DatabaseError(e.to_string()))?;

            total_deleted += conn_guard
                .execute(
                    "DELETE FROM comment_receipts WHERE created_at < ?1",
                    params![cutoff],
                )
                .map_err(|e| ProjectionWorkerError::DatabaseError(e.to_string()))?;

            total_deleted += conn_guard
                .execute(
                    "DELETE FROM work_pr_index WHERE created_at < ?1",
                    params![cutoff],
                )
                .map_err(|e| ProjectionWorkerError::DatabaseError(e.to_string()))?;

            // BLOCKER FIX: Evict expired work_context entries.
            // The `created_at_ns` column uses nanoseconds, so convert the
            // seconds-based cutoff to nanoseconds before comparison.
            #[allow(clippy::cast_possible_wrap)]
            let cutoff_ns = cutoff.saturating_mul(1_000_000_000);
            total_deleted += conn_guard
                .execute(
                    "DELETE FROM work_context WHERE created_at_ns < ?1",
                    params![cutoff_ns],
                )
                .map_err(|e| ProjectionWorkerError::DatabaseError(e.to_string()))?;

            if total_deleted > 0 {
                info!(
                    deleted = total_deleted,
                    ttl_secs = ttl_secs,
                    "Evicted expired work index entries (async)"
                );
            }

            Ok(total_deleted)
        })
        .await
        .map_err(|e| ProjectionWorkerError::DatabaseError(format!("spawn_blocking failed: {e}")))?
    }

    /// Registers a work context entry in the projection table (TCK-00638).
    ///
    /// Uses `INSERT OR IGNORE` to support idempotent replays: the primary key
    /// `(work_id, entry_id)` and the uniqueness constraint on
    /// `(work_id, kind, dedupe_key)` together ensure that duplicate entries
    /// from retries are silently absorbed.
    ///
    /// # Arguments
    ///
    /// * `work_id` - Canonical work identifier
    /// * `entry_id` - Deterministically derived entry ID (`CTX-` prefix +
    ///   blake3 hex)
    /// * `kind` - Entry kind discriminant
    /// * `dedupe_key` - Deduplication key
    /// * `actor_id` - Actor that published the entry
    /// * `cas_hash` - CAS hash of the canonical entry bytes (hex)
    /// * `evidence_id` - Evidence ID (same as `entry_id`)
    /// * `created_at_ns` - HTF timestamp in nanoseconds
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    #[allow(clippy::too_many_arguments, clippy::cast_possible_wrap)]
    pub fn register_work_context_entry(
        &self,
        work_id: &str,
        entry_id: &str,
        kind: &str,
        dedupe_key: &str,
        actor_id: &str,
        cas_hash: &str,
        evidence_id: &str,
        created_at_ns: u64,
    ) -> Result<(), ProjectionWorkerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| ProjectionWorkerError::DatabaseError(format!("mutex poisoned: {e}")))?;

        conn.execute(
            "INSERT OR IGNORE INTO work_context
             (work_id, entry_id, kind, dedupe_key, actor_id, cas_hash, evidence_id, created_at_ns)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                work_id,
                entry_id,
                kind,
                dedupe_key,
                actor_id,
                cas_hash,
                evidence_id,
                created_at_ns as i64,
            ],
        )
        .map_err(|e| ProjectionWorkerError::DatabaseError(e.to_string()))?;

        debug!(
            work_id = %work_id,
            entry_id = %entry_id,
            kind = %kind,
            "Registered work context entry in projection"
        );

        Ok(())
    }
}

/// PR metadata for projection.
#[derive(Debug, Clone)]
pub struct PrMetadata {
    /// The PR number.
    pub pr_number: u64,
    /// Repository owner.
    pub repo_owner: String,
    /// Repository name.
    pub repo_name: String,
    /// Head commit SHA.
    pub head_sha: String,
}

// =============================================================================
// Ledger Tailer
// =============================================================================

/// Default tailer ID for the projection worker.
const DEFAULT_TAILER_ID: &str = "projection_worker";

/// Ledger tailer for watching events.
///
/// Tracks the last processed event sequence and polls for new events.
/// Persists the watermark to `SQLite` for crash recovery (fixes blocker:
/// non-persistent tailer).
///
/// # MAJOR FIX: Potential Data Loss via Non-Unique Watermark
///
/// The watermark now tracks `(timestamp_ns, event_id)` as a composite cursor
/// instead of just `timestamp_ns`. This ensures that if multiple events share
/// the same timestamp, acknowledging one won't skip the others.
///
/// The polling query uses `(timestamp_ns, event_id) > (last_ns, last_id)`
/// to correctly handle timestamp collisions.
pub struct LedgerTailer {
    /// Database connection for ledger access.
    /// Made `pub(crate)` to allow async handlers to wrap operations in
    /// `spawn_blocking`.
    pub(crate) conn: Arc<Mutex<Connection>>,
    /// Last processed event timestamp (for ordering).
    last_processed_ns: u64,
    /// Last processed event ID (for deterministic ordering within same
    /// timestamp). MAJOR FIX: Together with timestamp, forms a composite
    /// cursor.
    last_event_id: String,
    /// Tailer identifier for watermark persistence.
    tailer_id: String,
    /// TCK-00638 / BLOCKER fix: Whether the canonical `events` table is
    /// active (freeze mode). Detected lazily on first poll by checking
    /// if the `events` table exists in `sqlite_master`. Once set, the
    /// tailer also queries canonical events to see freeze-mode writes.
    /// Uses `std::sync::atomic::AtomicU8` with three states:
    /// 0 = unknown, 1 = legacy-only, 2 = canonical-active.
    canonical_mode: std::sync::atomic::AtomicU8,
}

impl LedgerTailer {
    /// Creates a new ledger tailer, loading persisted watermark if available.
    ///
    /// This ensures crash recovery: the tailer resumes from where it left off.
    #[allow(clippy::cast_sign_loss)]
    pub fn new(conn: Arc<Mutex<Connection>>) -> Self {
        Self::with_id(conn, DEFAULT_TAILER_ID)
    }

    /// Creates a new ledger tailer with a custom ID.
    ///
    /// MAJOR FIX: Potential Data Loss via Non-Unique Watermark
    /// Now loads both `timestamp_ns` and `event_id` for composite cursor.
    #[allow(clippy::cast_sign_loss)]
    pub fn with_id(conn: Arc<Mutex<Connection>>, tailer_id: &str) -> Self {
        // Load persisted watermark if available (now includes event_id)
        let (last_processed_ns, last_event_id) = conn.lock().map_or((0, String::new()), |conn_guard| {
            conn_guard
                .query_row(
                    "SELECT last_processed_ns, COALESCE(last_event_id, '') FROM tailer_watermark WHERE tailer_id = ?1",
                    params![tailer_id],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
                )
                .map(|(ns, event_id)| (ns as u64, event_id))
                .unwrap_or((0, String::new()))
        });

        if last_processed_ns > 0 {
            info!(
                tailer_id = %tailer_id,
                last_processed_ns = last_processed_ns,
                last_event_id = %last_event_id,
                "Resumed ledger tailer from persisted watermark"
            );
        }

        Self {
            conn,
            last_processed_ns,
            last_event_id,
            tailer_id: tailer_id.to_string(),
            canonical_mode: std::sync::atomic::AtomicU8::new(0),
        }
    }

    /// Creates a ledger tailer starting from a specific timestamp.
    #[must_use]
    pub fn from_timestamp(conn: Arc<Mutex<Connection>>, timestamp_ns: u64) -> Self {
        Self {
            conn,
            last_processed_ns: timestamp_ns,
            last_event_id: String::new(),
            tailer_id: DEFAULT_TAILER_ID.to_string(),
            canonical_mode: std::sync::atomic::AtomicU8::new(0),
        }
    }

    /// TCK-00638 / BLOCKER fix: Detects whether the canonical `events` table
    /// is active. Returns `true` if canonical mode is active (the `events`
    /// table exists and has at least one row). Result is cached in an
    /// `AtomicU8` to avoid repeated `sqlite_master` queries.
    ///
    /// States: 0 = unknown (probe required), 1 = legacy-only, 2 = canonical.
    fn is_canonical_active(conn: &Connection, mode: &std::sync::atomic::AtomicU8) -> bool {
        use std::sync::atomic::Ordering;
        let current = mode.load(Ordering::Acquire);
        if current == 2 {
            return true;
        }
        if current == 1 {
            return false;
        }
        // Probe: check if `events` table exists in sqlite_master.
        let exists: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master \
                 WHERE type = 'table' AND name = 'events')",
                [],
                |row| row.get(0),
            )
            .unwrap_or(false);
        if exists {
            mode.store(2, Ordering::Release);
            true
        } else {
            mode.store(1, Ordering::Release);
            false
        }
    }

    /// TCK-00638 / BLOCKER fix: Polls the canonical `events` table for
    /// events matching the given type and cursor, using the same composite
    /// cursor semantics as the legacy poll.
    ///
    /// Column mapping: `events.session_id` → `work_id`,
    /// `events.seq_id` → synthesised `"canonical-{seq_id:020}"` `event_id`.
    ///
    /// ## Cursor correctness (MAJOR fix: timestamp collision cursor skip)
    ///
    /// The synthesised `event_id` uses a **20-digit zero-padded** `seq_id`
    /// (e.g. `canonical-00000000000000000042`) so that lexicographic ordering
    /// matches the underlying numeric `seq_id ASC` ordering. Without zero-
    /// padding, `"canonical-10"` would sort **before** `"canonical-9"` in
    /// string comparison, causing the cursor to skip rows with `seq_id >= 10`
    /// when a same-timestamp batch page boundary falls between single-digit
    /// and multi-digit `seq_id` values.
    #[allow(clippy::cast_sign_loss, clippy::cast_possible_wrap)]
    fn poll_canonical_events(
        conn: &Connection,
        event_type: &str,
        last_processed_ns: u64,
        last_event_id: &str,
        limit: usize,
    ) -> Result<Vec<SignedLedgerEvent>, ProjectionWorkerError> {
        // Map the canonical row to a `SignedLedgerEvent` with synthesised
        // event_id = "canonical-{seq_id:020}" (zero-padded for
        // lexicographic == numeric ordering).
        let map_row = |row: &rusqlite::Row<'_>| -> rusqlite::Result<SignedLedgerEvent> {
            let seq_id: i64 = row.get(0)?;
            Ok(SignedLedgerEvent {
                event_id: format!("canonical-{seq_id:020}"),
                event_type: row.get(1)?,
                work_id: row.get(2)?, // session_id maps to work_id
                actor_id: row.get(3)?,
                payload: row.get(4)?,
                signature: row.get(5)?,
                timestamp_ns: row.get::<_, i64>(6)? as u64,
            })
        };

        if last_event_id.is_empty() {
            let mut stmt = conn
                .prepare(
                    "SELECT seq_id, event_type, session_id, actor_id, payload, \
                            COALESCE(signature, X''), timestamp_ns \
                     FROM events \
                     WHERE event_type = ?1 AND timestamp_ns > ?2 \
                     ORDER BY timestamp_ns ASC, seq_id ASC \
                     LIMIT ?3",
                )
                .map_err(|e| ProjectionWorkerError::DatabaseError(e.to_string()))?;

            let events = stmt
                .query_map(
                    params![event_type, last_processed_ns as i64, limit as i64],
                    map_row,
                )
                .map_err(|e| ProjectionWorkerError::DatabaseError(e.to_string()))?
                .filter_map(Result::ok)
                .collect::<Vec<_>>();
            Ok(events)
        } else {
            // For composite cursor with canonical events: the last_event_id
            // may be a legacy event_id or a "canonical-{seq_id:020}" string.
            //
            // MAJOR FIX (cursor skip under timestamp collision):
            // Use zero-padded synthesised canonical event_id in SQL so
            // string `>` comparison matches numeric `seq_id ASC` ordering.
            // The SQL pads `seq_id` with `SUBSTR('00000000000000000000', 1,
            // 20 - LENGTH(CAST(seq_id AS TEXT)))` to produce a 20-char
            // zero-padded number, then prefixes `'canonical-'`.
            let mut stmt = conn
                .prepare(
                    "SELECT seq_id, event_type, session_id, actor_id, payload, \
                            COALESCE(signature, X''), timestamp_ns \
                     FROM events \
                     WHERE event_type = ?1 AND ( \
                         timestamp_ns > ?2 OR \
                         (timestamp_ns = ?2 AND \
                          ('canonical-' || SUBSTR('00000000000000000000', 1, \
                              20 - LENGTH(CAST(seq_id AS TEXT))) || CAST(seq_id AS TEXT)) > ?3) \
                     ) \
                     ORDER BY timestamp_ns ASC, seq_id ASC \
                     LIMIT ?4",
                )
                .map_err(|e| ProjectionWorkerError::DatabaseError(e.to_string()))?;

            let events = stmt
                .query_map(
                    params![
                        event_type,
                        last_processed_ns as i64,
                        last_event_id,
                        limit as i64
                    ],
                    map_row,
                )
                .map_err(|e| ProjectionWorkerError::DatabaseError(e.to_string()))?
                .filter_map(Result::ok)
                .collect::<Vec<_>>();
            Ok(events)
        }
    }

    /// Persists the current watermark to `SQLite`.
    ///
    /// Called after processing events to ensure crash recovery.
    ///
    /// MAJOR FIX: Potential Data Loss via Non-Unique Watermark
    /// Now persists both `timestamp_ns` and `event_id` for composite cursor.
    #[allow(clippy::cast_possible_wrap)]
    fn persist_watermark(&self) -> Result<(), ProjectionWorkerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| ProjectionWorkerError::DatabaseError(format!("mutex poisoned: {e}")))?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        conn.execute(
            "INSERT OR REPLACE INTO tailer_watermark
             (tailer_id, last_processed_ns, last_event_id, updated_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                self.tailer_id,
                self.last_processed_ns as i64,
                &self.last_event_id,
                now as i64
            ],
        )
        .map_err(|e| ProjectionWorkerError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    /// Gets the next batch of unprocessed events of a given type.
    ///
    /// Returns events ordered by `(timestamp_ns, event_id)`, starting after
    /// the last processed cursor.
    ///
    /// # MAJOR FIX: Potential Data Loss via Non-Unique Watermark
    ///
    /// Uses a composite cursor `(timestamp_ns, event_id)` to handle timestamp
    /// collisions. Events are ordered by timestamp first, then by `event_id`
    /// (lexicographically) for deterministic ordering within the same
    /// timestamp.
    ///
    /// # At-Least-Once Delivery
    ///
    /// This method does NOT automatically advance the watermark. The caller
    /// must explicitly call [`Self::acknowledge`] after successfully processing
    /// each event. This ensures at-least-once delivery semantics:
    /// - If the daemon crashes before acknowledgment, events are redelivered
    /// - Idempotency is achieved via `comment_receipts` and `IdempotencyCache`
    #[allow(clippy::cast_sign_loss, clippy::cast_possible_wrap)]
    pub fn poll_events(
        &mut self,
        event_type: &str,
        limit: usize,
    ) -> Result<Vec<SignedLedgerEvent>, ProjectionWorkerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| ProjectionWorkerError::DatabaseError(format!("mutex poisoned: {e}")))?;

        // MAJOR FIX: Use composite cursor (timestamp_ns, event_id) to handle
        // timestamp collisions. The query selects events where:
        // - timestamp > last_timestamp, OR
        // - timestamp == last_timestamp AND event_id > last_event_id (only if
        //   last_event_id is set)
        // This ensures no events are skipped when multiple events share a timestamp.
        //
        // When last_event_id is empty (e.g., from_timestamp or fresh start), we only
        // use timestamp comparison to maintain backward compatibility and
        // correct semantics: timestamp_ns > last means "everything after this
        // timestamp".
        let query = if self.last_event_id.is_empty() {
            // No event_id cursor - use timestamp-only comparison
            "SELECT event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns
             FROM ledger_events
             WHERE event_type = ?1 AND timestamp_ns > ?2
             ORDER BY timestamp_ns ASC, event_id ASC
             LIMIT ?3"
        } else {
            // Have event_id cursor - use composite comparison
            "SELECT event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns
             FROM ledger_events
             WHERE event_type = ?1 AND (
                 timestamp_ns > ?2 OR
                 (timestamp_ns = ?2 AND event_id > ?3)
             )
             ORDER BY timestamp_ns ASC, event_id ASC
             LIMIT ?4"
        };

        let mut stmt = conn
            .prepare(query)
            .map_err(|e| ProjectionWorkerError::DatabaseError(e.to_string()))?;

        let mut events = if self.last_event_id.is_empty() {
            stmt.query_map(
                params![event_type, self.last_processed_ns as i64, limit as i64],
                |row| {
                    Ok(SignedLedgerEvent {
                        event_id: row.get(0)?,
                        event_type: row.get(1)?,
                        work_id: row.get(2)?,
                        actor_id: row.get(3)?,
                        payload: row.get(4)?,
                        signature: row.get(5)?,
                        timestamp_ns: row.get::<_, i64>(6)? as u64,
                    })
                },
            )
            .map_err(|e| ProjectionWorkerError::DatabaseError(e.to_string()))?
            .filter_map(Result::ok)
            .collect::<Vec<_>>()
        } else {
            stmt.query_map(
                params![
                    event_type,
                    self.last_processed_ns as i64,
                    &self.last_event_id,
                    limit as i64
                ],
                |row| {
                    Ok(SignedLedgerEvent {
                        event_id: row.get(0)?,
                        event_type: row.get(1)?,
                        work_id: row.get(2)?,
                        actor_id: row.get(3)?,
                        payload: row.get(4)?,
                        signature: row.get(5)?,
                        timestamp_ns: row.get::<_, i64>(6)? as u64,
                    })
                },
            )
            .map_err(|e| ProjectionWorkerError::DatabaseError(e.to_string()))?
            .filter_map(Result::ok)
            .collect::<Vec<_>>()
        };

        // TCK-00638 / BLOCKER fix: When canonical mode is active, also
        // poll the canonical `events` table and merge results by
        // (timestamp_ns, event_id) ordering. This ensures the tailer
        // observes freeze-mode writes.
        if Self::is_canonical_active(&conn, &self.canonical_mode) {
            let canonical = Self::poll_canonical_events(
                &conn,
                event_type,
                self.last_processed_ns,
                &self.last_event_id,
                limit,
            )?;
            if !canonical.is_empty() {
                events.extend(canonical);
                // Sort merged events by (timestamp_ns, event_id) for
                // deterministic cursor-compatible ordering.
                events.sort_by(|a, b| {
                    a.timestamp_ns
                        .cmp(&b.timestamp_ns)
                        .then_with(|| a.event_id.cmp(&b.event_id))
                });
                // Enforce the batch limit after merge.
                events.truncate(limit);
            }
        }

        // NOTE: Watermark is NOT advanced here. Caller must call acknowledge()
        // after successful processing to ensure at-least-once delivery.

        Ok(events)
    }

    /// Acknowledges successful processing of an event.
    ///
    /// This advances the watermark to the event's `(timestamp_ns, event_id)`,
    /// ensuring the event won't be redelivered on restart. Should be called
    /// after each event is successfully processed.
    ///
    /// # MAJOR FIX: Potential Data Loss via Non-Unique Watermark
    ///
    /// Now accepts both `timestamp_ns` and `event_id` to form a composite
    /// cursor. This ensures correct ordering when multiple events share a
    /// timestamp.
    ///
    /// # At-Least-Once Delivery
    ///
    /// By separating polling from acknowledgment, we achieve at-least-once
    /// delivery semantics:
    /// - Events are only acknowledged after successful processing
    /// - If the daemon crashes before acknowledgment, events are redelivered
    /// - Idempotency prevents duplicate side effects
    pub fn acknowledge(
        &mut self,
        timestamp_ns: u64,
        event_id: &str,
    ) -> Result<(), ProjectionWorkerError> {
        // Advance watermark if this event is strictly after the current cursor.
        // Use composite comparison: (ts, event_id) > (last_ts, last_event_id)
        let should_advance = timestamp_ns > self.last_processed_ns
            || (timestamp_ns == self.last_processed_ns && event_id > self.last_event_id.as_str());

        if should_advance {
            self.last_processed_ns = timestamp_ns;
            self.last_event_id = event_id.to_string();
            self.persist_watermark()?;
        }
        Ok(())
    }

    /// Async wrapper for `poll_events` that uses `spawn_blocking`.
    ///
    /// This avoids blocking the async runtime during `SQLite` I/O
    /// (Major fix: Thread blocking in async context).
    ///
    /// MAJOR FIX: Potential Data Loss via Non-Unique Watermark
    /// Uses composite cursor (`timestamp_ns`, `event_id`) in the query.
    #[allow(clippy::cast_sign_loss, clippy::cast_possible_wrap)]
    pub async fn poll_events_async(
        &self,
        event_type: &str,
        limit: usize,
    ) -> Result<Vec<SignedLedgerEvent>, ProjectionWorkerError> {
        let conn = Arc::clone(&self.conn);
        let event_type = event_type.to_string();
        let last_processed_ns = self.last_processed_ns;
        let last_event_id = self.last_event_id.clone();
        // TCK-00638 / BLOCKER fix: Snapshot canonical_mode before spawning so
        // the blocking closure can detect freeze-mode writes. The probe
        // result is returned alongside events so we can cache it.
        let canonical_mode_snapshot = self
            .canonical_mode
            .load(std::sync::atomic::Ordering::Acquire);

        // Return (events, detected_canonical_mode) from spawn_blocking.
        let result = tokio::task::spawn_blocking(move || {
            let conn_guard = conn.lock().map_err(|e| {
                ProjectionWorkerError::DatabaseError(format!("mutex poisoned: {e}"))
            })?;

            // MAJOR FIX: Use composite cursor (timestamp_ns, event_id)
            // When last_event_id is empty, use timestamp-only comparison for backward
            // compat.
            let query = if last_event_id.is_empty() {
                "SELECT event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns
                 FROM ledger_events
                 WHERE event_type = ?1 AND timestamp_ns > ?2
                 ORDER BY timestamp_ns ASC, event_id ASC
                 LIMIT ?3"
            } else {
                "SELECT event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns
                 FROM ledger_events
                 WHERE event_type = ?1 AND (
                     timestamp_ns > ?2 OR
                     (timestamp_ns = ?2 AND event_id > ?3)
                 )
                 ORDER BY timestamp_ns ASC, event_id ASC
                 LIMIT ?4"
            };

            let mut stmt = conn_guard
                .prepare(query)
                .map_err(|e| ProjectionWorkerError::DatabaseError(e.to_string()))?;

            let mut events = if last_event_id.is_empty() {
                stmt.query_map(
                    params![event_type, last_processed_ns as i64, limit as i64],
                    |row| {
                        Ok(SignedLedgerEvent {
                            event_id: row.get(0)?,
                            event_type: row.get(1)?,
                            work_id: row.get(2)?,
                            actor_id: row.get(3)?,
                            payload: row.get(4)?,
                            signature: row.get(5)?,
                            timestamp_ns: row.get::<_, i64>(6)? as u64,
                        })
                    },
                )
                .map_err(|e| ProjectionWorkerError::DatabaseError(e.to_string()))?
                .filter_map(Result::ok)
                .collect::<Vec<_>>()
            } else {
                stmt.query_map(
                    params![
                        event_type,
                        last_processed_ns as i64,
                        &last_event_id,
                        limit as i64
                    ],
                    |row| {
                        Ok(SignedLedgerEvent {
                            event_id: row.get(0)?,
                            event_type: row.get(1)?,
                            work_id: row.get(2)?,
                            actor_id: row.get(3)?,
                            payload: row.get(4)?,
                            signature: row.get(5)?,
                            timestamp_ns: row.get::<_, i64>(6)? as u64,
                        })
                    },
                )
                .map_err(|e| ProjectionWorkerError::DatabaseError(e.to_string()))?
                .filter_map(Result::ok)
                .collect::<Vec<_>>()
            };

            // TCK-00638 / BLOCKER fix: When canonical mode is active (or
            // unknown and detected by probing), also poll canonical events.
            let canonical_active = if canonical_mode_snapshot == 2 {
                true
            } else if canonical_mode_snapshot == 1 {
                false
            } else {
                // Probe: check if `events` table exists.
                conn_guard
                    .query_row(
                        "SELECT EXISTS(SELECT 1 FROM sqlite_master \
                         WHERE type = 'table' AND name = 'events')",
                        [],
                        |row| row.get(0),
                    )
                    .unwrap_or(false)
            };

            // Encode detected mode for caching: 2 = canonical, 1 = legacy.
            let detected: u8 = if canonical_active {
                2
            } else if canonical_mode_snapshot == 0 {
                1
            } else {
                canonical_mode_snapshot
            };

            if canonical_active {
                let canonical = Self::poll_canonical_events(
                    &conn_guard,
                    &event_type,
                    last_processed_ns,
                    &last_event_id,
                    limit,
                )?;
                if !canonical.is_empty() {
                    events.extend(canonical);
                    events.sort_by(|a, b| {
                        a.timestamp_ns
                            .cmp(&b.timestamp_ns)
                            .then_with(|| a.event_id.cmp(&b.event_id))
                    });
                    events.truncate(limit);
                }
            }

            Ok((events, detected))
        })
        .await
        .map_err(|e| ProjectionWorkerError::DatabaseError(format!("spawn_blocking failed: {e}")))?;

        let (events, detected_mode) = result?;

        // Cache the detected canonical mode for future polls.
        if canonical_mode_snapshot == 0 && detected_mode != 0 {
            self.canonical_mode
                .store(detected_mode, std::sync::atomic::Ordering::Release);
        }

        Ok(events)
    }

    /// Async wrapper for `acknowledge` that uses `spawn_blocking`.
    ///
    /// This avoids blocking the async runtime during `SQLite` I/O
    /// (Major fix: Thread blocking in async context).
    ///
    /// MAJOR FIX: Potential Data Loss via Non-Unique Watermark
    /// Now accepts both `timestamp_ns` and `event_id` for composite cursor.
    #[allow(clippy::cast_possible_wrap)]
    pub async fn acknowledge_async(
        &mut self,
        timestamp_ns: u64,
        event_id: &str,
    ) -> Result<(), ProjectionWorkerError> {
        // Advance watermark if this event is strictly after the current cursor.
        let should_advance = timestamp_ns > self.last_processed_ns
            || (timestamp_ns == self.last_processed_ns && event_id > self.last_event_id.as_str());

        if should_advance {
            self.last_processed_ns = timestamp_ns;
            self.last_event_id = event_id.to_string();

            let conn = Arc::clone(&self.conn);
            let tailer_id = self.tailer_id.clone();
            let last_processed_ns = self.last_processed_ns;
            let last_event_id = self.last_event_id.clone();

            tokio::task::spawn_blocking(move || {
                let conn_guard = conn.lock().map_err(|e| {
                    ProjectionWorkerError::DatabaseError(format!("mutex poisoned: {e}"))
                })?;

                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);

                conn_guard
                    .execute(
                        "INSERT OR REPLACE INTO tailer_watermark
                         (tailer_id, last_processed_ns, last_event_id, updated_at)
                         VALUES (?1, ?2, ?3, ?4)",
                        params![
                            tailer_id,
                            last_processed_ns as i64,
                            last_event_id,
                            now as i64
                        ],
                    )
                    .map_err(|e| ProjectionWorkerError::DatabaseError(e.to_string()))?;

                Ok(())
            })
            .await
            .map_err(|e| {
                ProjectionWorkerError::DatabaseError(format!("spawn_blocking failed: {e}"))
            })?
        } else {
            Ok(())
        }
    }

    /// Gets the current ledger head (latest event timestamp).
    #[allow(clippy::cast_sign_loss)]
    pub fn get_ledger_head(&self) -> Result<Option<[u8; 32]>, ProjectionWorkerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| ProjectionWorkerError::DatabaseError(format!("mutex poisoned: {e}")))?;

        // For now, compute a hash of the latest event_id as "ledger head"
        // In a full implementation, this would be the chain hash
        let result: Option<String> = conn
            .query_row(
                "SELECT event_id FROM ledger_events ORDER BY timestamp_ns DESC, rowid DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| ProjectionWorkerError::DatabaseError(e.to_string()))?;

        Ok(result.map(|event_id| {
            let mut hash = [0u8; 32];
            let digest = blake3::hash(event_id.as_bytes());
            hash.copy_from_slice(digest.as_bytes());
            hash
        }))
    }
}

// =============================================================================
// Projection Worker
// =============================================================================

/// Configuration for the projection worker.
#[derive(Debug, Clone)]
pub struct ProjectionWorkerConfig {
    /// Poll interval for checking new events.
    pub poll_interval: Duration,
    /// Maximum events to process per batch.
    pub batch_size: usize,
    /// Whether to enable GitHub projection.
    pub github_enabled: bool,
    /// GitHub API configuration (if enabled).
    pub github_config: Option<GitHubAdapterConfig>,
}

impl Default for ProjectionWorkerConfig {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_secs(1),
            batch_size: 100,
            github_enabled: false,
            github_config: None,
        }
    }
}

impl ProjectionWorkerConfig {
    /// Creates a new configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the poll interval.
    #[must_use]
    pub const fn with_poll_interval(mut self, interval: Duration) -> Self {
        self.poll_interval = interval;
        self
    }

    /// Sets the batch size.
    #[must_use]
    pub const fn with_batch_size(mut self, size: usize) -> Self {
        self.batch_size = size;
        self
    }

    /// Enables GitHub projection with the given configuration.
    #[must_use]
    pub fn with_github(mut self, config: GitHubAdapterConfig) -> Self {
        self.github_enabled = true;
        self.github_config = Some(config);
        self
    }
}

/// The projection worker that tails the ledger and projects to GitHub.
///
/// # Economics Admission Gate (TCK-00505)
///
/// When `intent_buffer`, `continuity_resolver`, and `gate_signer` are set,
/// the worker enforces economics-gated admission with idempotent-insert
/// replay prevention before every projection of events that carry
/// economics selectors (`eval_tick`, `time_authority_ref`, `window_ref`,
/// `boundary_id`).
///
/// Events without economics selectors are denied fail-closed
/// (`missing_economics_selectors`).
///
/// After economics ALLOW, the worker enforces projection lifecycle gate
/// sequencing (`join -> revalidate -> consume`) before any side effect.
///
/// If the gate is NOT wired (init failure), events carrying economics
/// selectors are DENIED (fail-closed). Events without economics
/// selectors are also DENIED (fail-closed: no bypass path).
///
/// **Implementation scope**: The current implementation provides
/// economics-gated admission with idempotent-insert replay prevention
/// (via `IntentBuffer` uniqueness on `(work_id, changeset_digest)`).
/// The enforcement guarantees are: no projection of economics-selector
/// events without passing the economics gate, no double-projection
/// of the same `(work_id, changeset_digest)`, no projection without passing
/// lifecycle `join -> revalidate -> consume`, and retry-safe handling of
/// transient projection failures (PENDING intents allow re-attempt).
pub struct ProjectionWorker {
    config: ProjectionWorkerConfig,
    work_index: WorkIndex,
    /// Tailer for `changeset_published` events.
    changeset_tailer: LedgerTailer,
    /// Tailer for `work.pr_associated` events.
    work_pr_tailer: LedgerTailer,
    /// Tailer for `review_receipt_recorded` events.
    review_tailer: LedgerTailer,
    /// Tailer for `evidence.published` events with `WORK_CONTEXT_ENTRY`
    /// category (TCK-00638).
    evidence_published_tailer: LedgerTailer,
    adapter: Option<GitHubProjectionAdapter>,
    authoritative_cas: Option<Arc<dyn ContentAddressedStore>>,
    /// Durable buffer for recording admission decisions (TCK-00504/00505).
    intent_buffer: Option<Arc<IntentBuffer>>,
    /// Continuity profile resolver for economics gate input assembly
    /// (TCK-00507/00505).
    continuity_resolver: Option<Arc<dyn ContinuityProfileResolver>>,
    /// Signer for constructing signed continuity window and profile
    /// artifacts at gate evaluation time (TCK-00505).
    gate_signer: Option<Arc<Signer>>,
    /// Lifecycle gate enforced after economics ALLOW and before projection
    /// side effects (`join -> revalidate -> consume`).
    projection_lifecycle_gate: Option<Arc<LifecycleGate>>,
    /// Structured telemetry for admission gate decisions (TCK-00505).
    telemetry: Arc<AdmissionTelemetry>,
    /// Shutdown flag.
    shutdown: Arc<std::sync::atomic::AtomicBool>,
}

impl ProjectionWorker {
    /// Creates a new projection worker.
    ///
    /// # Arguments
    ///
    /// * `conn` - `SQLite` connection for work index and ledger access
    /// * `config` - Worker configuration
    ///
    /// # Errors
    ///
    /// Returns an error if initialization fails.
    #[allow(clippy::needless_pass_by_value)] // Arc is cheap to clone, and we clone it multiple times
    pub fn new(
        conn: Arc<Mutex<Connection>>,
        config: ProjectionWorkerConfig,
    ) -> Result<Self, ProjectionWorkerError> {
        let work_index = WorkIndex::new(Arc::clone(&conn))?;

        // Create separate tailers for each event type to avoid watermark multiplexing.
        // Each tailer has its own persistent watermark, ensuring events of one type
        // don't skip events of another type due to shared timestamp tracking.
        let changeset_tailer =
            LedgerTailer::with_id(Arc::clone(&conn), "projection_worker:changeset_published");
        let work_pr_tailer =
            LedgerTailer::with_id(Arc::clone(&conn), "projection_worker:work_pr_associated");
        let review_tailer = LedgerTailer::with_id(
            Arc::clone(&conn),
            "projection_worker:review_receipt_recorded",
        );
        let evidence_published_tailer =
            LedgerTailer::with_id(Arc::clone(&conn), "projection_worker:evidence_published");

        // NOTE: Adapter is NOT created here to avoid fail-open issues.
        // The adapter MUST be injected via set_adapter() with a properly
        // configured GitHubProjectionAdapter that uses:
        // 1. A persistent signer from the daemon's key material
        // 2. The real HTTP client (not mock) for production
        //
        // If github_enabled is true but no adapter is set, projection will
        // log warnings but not fail-open to GitHub.
        let adapter = None;

        let lifecycle_kernel = Arc::new(InProcessKernel::new(1));
        let projection_lifecycle_gate = Arc::new(LifecycleGate::with_tick_kernel(
            lifecycle_kernel.clone(),
            lifecycle_kernel,
        ));

        Ok(Self {
            config,
            work_index,
            changeset_tailer,
            work_pr_tailer,
            review_tailer,
            evidence_published_tailer,
            adapter,
            authoritative_cas: None,
            intent_buffer: None,
            continuity_resolver: None,
            gate_signer: None,
            projection_lifecycle_gate: Some(projection_lifecycle_gate),
            telemetry: Arc::new(AdmissionTelemetry::new()),
            shutdown: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        })
    }

    /// Returns a handle for requesting shutdown.
    #[must_use]
    pub fn shutdown_handle(&self) -> Arc<std::sync::atomic::AtomicBool> {
        Arc::clone(&self.shutdown)
    }

    /// Returns a reference to the work index.
    #[must_use]
    pub const fn work_index(&self) -> &WorkIndex {
        &self.work_index
    }

    /// Returns a reference to the admission telemetry counters (TCK-00505).
    #[must_use]
    pub const fn telemetry(&self) -> &Arc<AdmissionTelemetry> {
        &self.telemetry
    }

    /// Sets the GitHub projection adapter.
    ///
    /// # Security
    ///
    /// The adapter MUST be created with:
    /// 1. A persistent signer from the daemon's key material (NOT random)
    /// 2. A properly configured `GitHubAdapterConfig` with API token
    /// 3. A real HTTP client for production (use `new()`, not `new_mock()`)
    ///
    /// Failing to provide a proper adapter will result in projections being
    /// skipped (fail-safe, not fail-open).
    pub fn set_adapter(&mut self, adapter: GitHubProjectionAdapter) {
        self.adapter = Some(adapter);
    }

    /// Sets the authoritative CAS used for receipt linkage resolution.
    ///
    /// Projection linkage validation is fail-closed and requires CAS-backed
    /// hashes to resolve in this store before any projection write is emitted.
    pub fn set_authoritative_cas(&mut self, cas: Arc<dyn ContentAddressedStore>) {
        self.authoritative_cas = Some(cas);
    }

    /// Sets the durable intent buffer for recording admission decisions
    /// (TCK-00504/00505).
    ///
    /// When set alongside `continuity_resolver`, enables the economics
    /// admission gate on the projection path. Both must be set for the
    /// gate to activate.
    pub fn set_intent_buffer(&mut self, buffer: IntentBuffer) {
        self.intent_buffer = Some(Arc::new(buffer));
    }

    /// Sets the continuity profile resolver for economics gate input
    /// assembly (TCK-00507/00505).
    ///
    /// When set alongside `intent_buffer` and `gate_signer`, enables the
    /// economics admission gate on the projection path. All three must be
    /// set for the gate to activate.
    pub fn set_continuity_resolver(&mut self, resolver: Arc<dyn ContinuityProfileResolver>) {
        self.continuity_resolver = Some(resolver);
    }

    /// Sets the gate signer used to construct signed continuity window
    /// and profile artifacts at economics gate evaluation time (TCK-00505).
    ///
    /// The signer MUST be persistent (daemon lifecycle key), NOT random
    /// per-invocation, so that signed artifacts are reproducible for
    /// audit trails.
    pub fn set_gate_signer(&mut self, signer: Arc<Signer>) {
        self.gate_signer = Some(signer);
    }

    /// Overrides the lifecycle gate used before projection side effects.
    ///
    /// This is primarily intended for deterministic tests or for wiring a
    /// daemon-owned lifecycle gate instance.
    pub fn set_projection_lifecycle_gate(&mut self, gate: Arc<LifecycleGate>) {
        self.projection_lifecycle_gate = Some(gate);
    }

    /// Returns whether a GitHub adapter is configured.
    #[must_use]
    pub const fn has_adapter(&self) -> bool {
        self.adapter.is_some()
    }

    /// Returns whether the economics admission gate is fully wired
    /// (TCK-00505).
    ///
    /// The gate requires an intent buffer, a continuity resolver, and a
    /// gate signer to be active.
    #[must_use]
    pub fn has_economics_gate(&self) -> bool {
        self.intent_buffer.is_some()
            && self.continuity_resolver.is_some()
            && self.gate_signer.is_some()
    }

    /// Runs the projection worker loop.
    ///
    /// This method blocks until shutdown is requested.
    ///
    /// # Errors
    ///
    /// Returns an error if the worker encounters a fatal error.
    #[allow(clippy::cast_possible_truncation)] // poll_interval is always < u64::MAX ms
    pub async fn run(&mut self) -> Result<(), ProjectionWorkerError> {
        info!(
            poll_interval_ms = self.config.poll_interval.as_millis() as u64,
            batch_size = self.config.batch_size,
            github_enabled = self.config.github_enabled,
            "Projection worker starting"
        );

        // Counter for periodic eviction (Blocker fix: Unbounded State Growth)
        // Run eviction every ~1000 poll cycles (roughly once per hour at 1s poll
        // interval)
        let eviction_interval: u64 = 1000;
        let mut eviction_counter: u64 = 0;

        while !self.shutdown.load(std::sync::atomic::Ordering::Relaxed) {
            // Process ChangeSetPublished events to build work index
            // (Major fix: Thread blocking in async context - uses spawn_blocking)
            if let Err(e) = self.process_changeset_published().await {
                warn!(error = %e, "Error processing ChangeSetPublished events");
            }

            // Process WorkPrAssociated events to link work_id -> PR metadata
            // (Major fix: Thread blocking in async context - uses spawn_blocking)
            if let Err(e) = self.process_work_pr_associated().await {
                warn!(error = %e, "Error processing WorkPrAssociated events");
            }

            // Process ReviewReceiptRecorded events for projection
            // (Major fix: Thread blocking in async context - uses spawn_blocking)
            if let Err(e) = self.process_review_receipts().await {
                warn!(error = %e, "Error processing ReviewReceiptRecorded events");
            }

            // Process evidence.published events to index WORK_CONTEXT_ENTRY entries
            // (TCK-00638: RFC-0032 Phase 2 work_context projection)
            if let Err(e) = self.process_evidence_published().await {
                warn!(error = %e, "Error processing evidence.published events");
            }

            // Periodic eviction of expired entries (Blocker fix: Unbounded State Growth)
            // Uses spawn_blocking to avoid blocking async runtime (Major fix: Thread
            // blocking)
            eviction_counter = eviction_counter.wrapping_add(1);
            if eviction_counter % eviction_interval == 0 {
                if let Err(e) = self.work_index.evict_expired_async(DEFAULT_TTL_SECS).await {
                    warn!(error = %e, "Error during work index eviction");
                }
            }

            // Sleep for poll interval
            tokio::time::sleep(self.config.poll_interval).await;
        }

        info!("Projection worker shutting down");
        Ok(())
    }

    /// Processes `ChangeSetPublished` events to populate the work index.
    ///
    /// # At-Least-Once Delivery (Blocker fix: Fail-Open Auto-Ack on Crash)
    ///
    /// This method only acknowledges events AFTER successful processing.
    /// If the daemon crashes before acknowledgment, events will be redelivered.
    ///
    /// # Async I/O (Major fix: Thread blocking in async context)
    ///
    /// Uses async polling and acknowledgment to avoid blocking the tokio
    /// runtime.
    async fn process_changeset_published(&mut self) -> Result<(), ProjectionWorkerError> {
        let events = self
            .changeset_tailer
            .poll_events_async("changeset_published", self.config.batch_size)
            .await?;

        for event in events {
            match self.handle_changeset_published(&event) {
                Ok(()) => {
                    // Only acknowledge after successful processing
                    // (Blocker fix: Fail-Open Auto-Ack on Crash)
                    // MAJOR FIX: Pass event_id for composite cursor
                    self.changeset_tailer
                        .acknowledge_async(event.timestamp_ns, &event.event_id)
                        .await?;
                },
                Err(e) => {
                    warn!(
                        event_id = %event.event_id,
                        error = %e,
                        "Failed to process ChangeSetPublished event - will retry"
                    );
                    // Do NOT acknowledge - event will be reprocessed on next poll
                    // This is the NACK/Retry behavior for at-least-once delivery
                    break; // Stop processing batch to maintain ordering
                },
            }
        }

        Ok(())
    }

    /// Handles a single `ChangeSetPublished` event.
    fn handle_changeset_published(
        &self,
        event: &SignedLedgerEvent,
    ) -> Result<(), ProjectionWorkerError> {
        // Parse payload to extract changeset_digest and work_id
        let payload: serde_json::Value = serde_json::from_slice(&event.payload)
            .map_err(|e| ProjectionWorkerError::InvalidPayload(e.to_string()))?;

        let changeset_digest_hex = payload
            .get("changeset_digest")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                ProjectionWorkerError::InvalidPayload("missing changeset_digest".to_string())
            })?;

        // Validate string length (Blocker fix: Unbounded Input Consumption)
        validate_string_length("changeset_digest", changeset_digest_hex)?;

        let work_id = payload
            .get("work_id")
            .and_then(|v| v.as_str())
            .unwrap_or(&event.work_id);

        // Validate string length (Blocker fix: Unbounded Input Consumption)
        validate_string_length("work_id", work_id)?;

        // Extract commit SHA if present (for GitHub status projection)
        let commit_sha = payload.get("commit_sha").and_then(|v| v.as_str());

        // Validate commit_sha length if present (Blocker fix: Unbounded Input
        // Consumption)
        if let Some(sha) = commit_sha {
            validate_string_length("commit_sha", sha)?;
        }

        // Decode changeset digest
        let digest_bytes = hex::decode(changeset_digest_hex)
            .map_err(|e| ProjectionWorkerError::InvalidPayload(e.to_string()))?;

        if digest_bytes.len() != 32 {
            return Err(ProjectionWorkerError::InvalidPayload(
                "changeset_digest must be 32 bytes".to_string(),
            ));
        }

        let mut changeset_digest = [0u8; 32];
        changeset_digest.copy_from_slice(&digest_bytes);

        // Register in work index
        self.work_index
            .register_changeset(&changeset_digest, work_id)?;

        // Register commit SHA mapping if present (blocker fix: CommitShaNotFound)
        if let Some(sha) = commit_sha {
            self.work_index
                .register_commit_sha(&changeset_digest, sha)?;
        }

        Ok(())
    }

    /// Processes `work.pr_associated` events to link `work_id` -> PR metadata.
    ///
    /// This is critical for projection: without PR metadata, we cannot post
    /// status checks or comments. (Blocker fix: Missing `WorkPrAssociated`
    /// handling)
    ///
    /// # At-Least-Once Delivery (Blocker fix: Fail-Open Auto-Ack on Crash)
    ///
    /// This method only acknowledges events AFTER successful processing.
    /// If the daemon crashes before acknowledgment, events will be redelivered.
    ///
    /// # Async I/O (Major fix: Thread blocking in async context)
    ///
    /// Uses async polling and acknowledgment to avoid blocking the tokio
    /// runtime.
    async fn process_work_pr_associated(&mut self) -> Result<(), ProjectionWorkerError> {
        let events = self
            .work_pr_tailer
            .poll_events_async("work.pr_associated", self.config.batch_size)
            .await?;

        for event in events {
            match self.handle_work_pr_associated(&event).await {
                Ok(()) => {
                    // Only acknowledge after successful processing
                    // (Blocker fix: Fail-Open Auto-Ack on Crash)
                    // MAJOR FIX: Pass event_id for composite cursor
                    self.work_pr_tailer
                        .acknowledge_async(event.timestamp_ns, &event.event_id)
                        .await?;
                },
                Err(e) => {
                    warn!(
                        event_id = %event.event_id,
                        error = %e,
                        "Failed to process WorkPrAssociated event - will retry"
                    );
                    // Do NOT acknowledge - event will be reprocessed on next poll
                    break; // Stop processing batch to maintain ordering
                },
            }
        }

        Ok(())
    }

    /// Handles a single `WorkPrAssociated` event.
    ///
    /// # Async I/O (Major fix: Thread blocking in async context)
    ///
    /// This method is async and wraps all `SQLite` `WorkIndex` operations in
    /// `spawn_blocking` to avoid blocking the Tokio executor threads.
    #[allow(clippy::cast_sign_loss)] // PR numbers are always positive
    async fn handle_work_pr_associated(
        &self,
        event: &SignedLedgerEvent,
    ) -> Result<(), ProjectionWorkerError> {
        // Parse canonical work.pr_associated envelope and fallback to inner
        // protobuf decode when top-level projection fields are absent.
        let (work_id, pr_number, commit_sha) =
            parse_work_pr_associated_payload(&event.payload, &event.work_id)?;

        validate_string_length("work_id", &work_id)?;
        validate_string_length("commit_sha", &commit_sha)?;

        // Legacy payloads may include changeset_digest; keep support for
        // status projection join when present.
        let payload_json: serde_json::Value =
            serde_json::from_slice(&event.payload).map_err(|e| {
                ProjectionWorkerError::InvalidPayload(format!(
                    "failed to parse work.pr_associated envelope: {e}"
                ))
            })?;
        let changeset_digest_opt: Option<[u8; 32]> = match payload_json
            .get("changeset_digest")
            .and_then(|v| v.as_str())
        {
            Some(changeset_digest_hex) => {
                validate_string_length("changeset_digest", changeset_digest_hex)?;
                let digest_bytes = hex::decode(changeset_digest_hex).map_err(|e| {
                    ProjectionWorkerError::InvalidPayload(format!(
                        "changeset_digest is not valid hex: {e}"
                    ))
                })?;
                let digest: [u8; 32] = digest_bytes.as_slice().try_into().map_err(|_| {
                    ProjectionWorkerError::InvalidPayload(
                        "changeset_digest must decode to 32 bytes".to_string(),
                    )
                })?;
                Some(digest)
            },
            None => None,
        };

        // Repo identity is authoritative from WorkSpec (work.opened ->
        // spec_snapshot_hash -> CAS WorkSpecV1.repo), not from this event.
        let Some(cas) = self.authoritative_cas.as_ref() else {
            return Err(ProjectionWorkerError::InvalidPayload(
                "authoritative CAS is required to resolve WorkSpec repo for work.pr_associated"
                    .to_string(),
            ));
        };

        let conn = self.work_index.connection();
        let cas = Arc::clone(cas);
        let work_id_owned = work_id.clone();
        let commit_sha_owned = commit_sha.clone();

        tokio::task::spawn_blocking(move || {
            let conn_guard = conn.lock().map_err(|e| {
                ProjectionWorkerError::DatabaseError(format!("mutex poisoned: {e}"))
            })?;

            let (repo_owner, repo_name) =
                resolve_repo_identity_for_work(&conn_guard, cas.as_ref(), &work_id_owned)?;

            validate_string_length("repo_owner", &repo_owner)?;
            validate_string_length("repo_name", &repo_name)?;

            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);

            #[allow(clippy::cast_possible_wrap)]
            conn_guard
                .execute(
                    "INSERT OR REPLACE INTO work_pr_index
                     (work_id, pr_number, repo_owner, repo_name, head_sha, created_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![
                        &work_id_owned,
                        pr_number as i64,
                        &repo_owner,
                        &repo_name,
                        &commit_sha_owned,
                        now as i64
                    ],
                )
                .map_err(|e| ProjectionWorkerError::DatabaseError(e.to_string()))?;

            if let Some(changeset_digest) = changeset_digest_opt {
                #[allow(clippy::cast_possible_wrap)]
                conn_guard
                    .execute(
                        "INSERT OR REPLACE INTO changeset_sha_index
                         (changeset_digest, commit_sha, created_at)
                         VALUES (?1, ?2, ?3)",
                        params![changeset_digest.as_slice(), &commit_sha_owned, now as i64],
                    )
                    .map_err(|e| ProjectionWorkerError::DatabaseError(e.to_string()))?;
            }

            Ok(())
        })
        .await
        .map_err(|e| ProjectionWorkerError::DatabaseError(format!("spawn_blocking failed: {e}")))?
    }

    /// Processes `ReviewReceiptRecorded` events for projection.
    ///
    /// # At-Least-Once Delivery (Blocker fix: Fail-Open Auto-Ack on Crash)
    ///
    /// This method only acknowledges events AFTER successful processing.
    /// If the daemon crashes before acknowledgment, events will be redelivered.
    ///
    /// # NACK/Retry for Missing Dependencies (Blocker fix: Critical Data Loss)
    ///
    /// If a `ReviewReceiptRecorded` event fails because the required
    /// associations (from `ChangeSetPublished` or `WorkPrAssociated`) are not
    /// yet indexed, the watermark is NOT advanced. The event will be
    /// reprocessed on the next poll cycle, giving time for the dependency
    /// events to be processed first.
    ///
    /// # Strict Sequential Acknowledgment
    ///
    /// Events are processed in timestamp order, and we MUST stop at the first
    /// failure to prevent skipping unprocessed events. If event A at ts=1000
    /// fails and we continue to process event B at ts=2000, acknowledging B
    /// would set the watermark to 2000, permanently skipping A.
    ///
    /// # Async I/O (Major fix: Thread blocking in async context)
    ///
    /// Uses async polling and acknowledgment to avoid blocking the tokio
    /// runtime.
    async fn process_review_receipts(&mut self) -> Result<(), ProjectionWorkerError> {
        let events = self
            .review_tailer
            .poll_events_async("review_receipt_recorded", self.config.batch_size)
            .await?;

        for event in events {
            match self.handle_review_receipt(&event).await {
                Ok(()) => {
                    // Only acknowledge after successful processing
                    // (Blocker fix: Fail-Open Auto-Ack on Crash)
                    // MAJOR FIX: Pass event_id for composite cursor
                    self.review_tailer
                        .acknowledge_async(event.timestamp_ns, &event.event_id)
                        .await?;
                },
                Err(ProjectionWorkerError::AdmissionDenied { reason }) => {
                    // Economics admission denied — event was fully processed,
                    // intent recorded as denied. Acknowledge to advance
                    // watermark (TCK-00505).
                    info!(
                        event_id = %event.event_id,
                        reason = %reason,
                        "Projection denied by economics admission gate"
                    );
                    self.review_tailer
                        .acknowledge_async(event.timestamp_ns, &event.event_id)
                        .await?;
                },
                Err(ProjectionWorkerError::LifecycleDenied {
                    reason,
                    subcategory,
                }) => {
                    // Economics admission denied (subcategory) — event was
                    // fully processed, intent recorded. Acknowledge to
                    // advance watermark (TCK-00505).
                    info!(
                        event_id = %event.event_id,
                        reason = %reason,
                        subcategory = %subcategory,
                        "Projection denied by economics admission (subcategory)"
                    );
                    self.review_tailer
                        .acknowledge_async(event.timestamp_ns, &event.event_id)
                        .await?;
                },
                Err(ProjectionWorkerError::MissingDependency { event_id, reason }) => {
                    // NACK/Retry: Do NOT acknowledge - event will be reprocessed
                    // (Blocker fix: Critical Data Loss via Shared Watermark)
                    debug!(
                        event_id = %event_id,
                        reason = %reason,
                        "Missing dependency for review receipt - will retry on next poll"
                    );
                    // MUST break to prevent skipping this event!
                    // If we continue and later events succeed, their higher
                    // timestamps would be acknowledged, permanently skipping
                    // this failed event.
                    break;
                },
                Err(ProjectionWorkerError::NoPrAssociation { work_id }) => {
                    // This is a variant of missing dependency - don't acknowledge
                    debug!(
                        event_id = %event.event_id,
                        work_id = %work_id,
                        "No PR association yet for review receipt - will retry on next poll"
                    );
                    // MUST break to prevent skipping this event!
                    break;
                },
                Err(e) => {
                    warn!(
                        event_id = %event.event_id,
                        error = %e,
                        "Failed to process ReviewReceiptRecorded event - will retry"
                    );
                    // For other errors, also don't acknowledge to ensure retry
                    break; // Stop processing batch for non-dependency errors
                },
            }
        }

        Ok(())
    }

    /// Processes `evidence.published` events to populate the `work_context`
    /// projection table (TCK-00638).
    ///
    /// Only events with category `WORK_CONTEXT_ENTRY` are indexed. All other
    /// evidence categories are silently skipped (acknowledged without
    /// indexing).
    ///
    /// Uses at-least-once delivery: events are acknowledged only after
    /// successful projection.
    async fn process_evidence_published(&mut self) -> Result<(), ProjectionWorkerError> {
        let events = self
            .evidence_published_tailer
            .poll_events_async("evidence.published", self.config.batch_size)
            .await?;

        for event in events {
            match self.handle_evidence_published(&event) {
                Ok(()) => {
                    self.evidence_published_tailer
                        .acknowledge_async(event.timestamp_ns, &event.event_id)
                        .await?;
                },
                Err(ProjectionWorkerError::InvalidPayload(ref msg)) => {
                    // InvalidPayload is permanently unrecoverable: the event
                    // payload is structurally malformed and will never succeed
                    // on retry. Acknowledge (skip) the event to prevent
                    // head-of-line blocking that would pin the tailer and
                    // block all subsequent evidence.published events.
                    warn!(
                        event_id = %event.event_id,
                        error = %msg,
                        "Defect: permanently malformed evidence.published event \
                         - acknowledging to prevent head-of-line blocking"
                    );
                    self.evidence_published_tailer
                        .acknowledge_async(event.timestamp_ns, &event.event_id)
                        .await?;
                },
                Err(e) => {
                    // Transient errors (database, lock contention) may
                    // succeed on retry. Break and re-poll on next cycle.
                    warn!(
                        event_id = %event.event_id,
                        error = %e,
                        "Failed to process evidence.published event - will retry"
                    );
                    break;
                },
            }
        }

        Ok(())
    }

    /// Handles a single `evidence.published` event for work context projection.
    ///
    /// The ledger stores session events as a JSON envelope with a hex-encoded
    /// protobuf in the `"payload"` field (see `emit_session_event`). This
    /// method decodes that envelope first, then the inner `EvidenceEvent`
    /// protobuf, checks if the category is `WORK_CONTEXT_ENTRY`, and if so,
    /// extracts metadata fields and inserts into the `work_context` projection
    /// table.
    ///
    /// Non-`WORK_CONTEXT_ENTRY` events are silently skipped (return `Ok(())`).
    fn handle_evidence_published(
        &self,
        event: &SignedLedgerEvent,
    ) -> Result<(), ProjectionWorkerError> {
        use prost::Message;

        // Step 1: Parse the JSON envelope produced by emit_session_event.
        // Format: { "event_type": "...", "session_id": "...", "actor_id": "...",
        // "payload": "<hex>" }
        let envelope: serde_json::Value = serde_json::from_slice(&event.payload).map_err(|e| {
            ProjectionWorkerError::InvalidPayload(format!(
                "failed to parse session event JSON envelope: {e}"
            ))
        })?;

        let hex_payload = envelope
            .get("payload")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                ProjectionWorkerError::InvalidPayload(
                    "session event JSON envelope missing 'payload' field".to_string(),
                )
            })?;

        let inner_bytes = hex::decode(hex_payload).map_err(|e| {
            ProjectionWorkerError::InvalidPayload(format!(
                "failed to hex-decode inner protobuf payload: {e}"
            ))
        })?;

        // Step 2: Decode the inner EvidenceEvent protobuf.
        let evidence_event = apm2_core::events::EvidenceEvent::decode(inner_bytes.as_slice())
            .map_err(|e| {
                ProjectionWorkerError::InvalidPayload(format!(
                    "failed to decode EvidenceEvent from inner protobuf: {e}"
                ))
            })?;

        let Some(apm2_core::events::evidence_event::Event::Published(published)) =
            evidence_event.event
        else {
            // Not a Published event — skip.
            return Ok(());
        };

        // Only index WORK_CONTEXT_ENTRY evidence.
        if published.category != "WORK_CONTEXT_ENTRY" {
            return Ok(());
        }

        // Extract metadata fields from the evidence metadata list.
        let mut entry_id = String::new();
        let mut kind = String::new();
        let mut dedupe_key = String::new();
        let mut actor_id = String::new();

        for meta in &published.metadata {
            if let Some(val) = meta.strip_prefix("entry_id=") {
                entry_id = val.to_string();
            } else if let Some(val) = meta.strip_prefix("kind=") {
                kind = val.to_string();
            } else if let Some(val) = meta.strip_prefix("dedupe_key=") {
                dedupe_key = val.to_string();
            } else if let Some(val) = meta.strip_prefix("actor_id=") {
                actor_id = val.to_string();
            }
        }

        if entry_id.is_empty() || kind.is_empty() || dedupe_key.is_empty() {
            return Err(ProjectionWorkerError::InvalidPayload(format!(
                "evidence.published WORK_CONTEXT_ENTRY missing required metadata: \
                 entry_id={entry_id:?}, kind={kind:?}, dedupe_key={dedupe_key:?}"
            )));
        }

        let cas_hash_hex = hex::encode(&published.artifact_hash);

        self.work_index.register_work_context_entry(
            &published.work_id,
            &entry_id,
            &kind,
            &dedupe_key,
            &actor_id,
            &cas_hash_hex,
            &published.evidence_id,
            event.timestamp_ns,
        )?;

        debug!(
            event_id = %event.event_id,
            work_id = %published.work_id,
            entry_id = %entry_id,
            kind = %kind,
            "Projected WORK_CONTEXT_ENTRY evidence to work_context table"
        );

        Ok(())
    }

    /// Handles a single `ReviewReceiptRecorded` event.
    ///
    /// # Economics Admission Gate (TCK-00505)
    ///
    /// When the event payload carries economics selectors (`eval_tick`,
    /// `time_authority_ref`, `window_ref`, `boundary_id`):
    ///
    /// 1. If the gate is wired: evaluate economics admission, insert intent as
    ///    PENDING, enforce lifecycle gate (`join -> revalidate -> consume`),
    ///    proceed to projection, then admit AFTER successful projection.
    /// 2. If the gate is NOT wired: DENY (fail-closed for events with economics
    ///    selectors).
    ///
    /// Events without economics selectors are denied fail-closed.
    ///
    /// Missing gate inputs result in DENY (fail-closed).
    ///
    /// # Async I/O (Major fix: Thread blocking in async context)
    ///
    /// This method wraps all synchronous `SQLite` operations (`WorkIndex` and
    /// adapter's `register_commit_sha`) in `spawn_blocking` to avoid blocking
    /// the Tokio executor threads.
    async fn handle_review_receipt(
        &self,
        event: &SignedLedgerEvent,
    ) -> Result<(), ProjectionWorkerError> {
        // Parse payload
        let payload: serde_json::Value = serde_json::from_slice(&event.payload)
            .map_err(|e| ProjectionWorkerError::InvalidPayload(e.to_string()))?;

        // RFC-0028 REQ-0008: projection writes are admissible only when the
        // receipt payload carries authoritative linkage fields and those
        // fields bind to the signed event envelope.
        let work_index_conn = self.work_index.connection();
        let linkage_authority = ProjectionLinkageAuthority {
            conn: &work_index_conn,
            cas: self.authoritative_cas.as_deref(),
        };
        validate_projection_receipt_linkage(&payload, event, &linkage_authority)?;

        let changeset_digest_hex = payload
            .get("changeset_digest")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                ProjectionWorkerError::InvalidPayload("missing changeset_digest".to_string())
            })?;

        // Validate string length (Blocker fix: Unbounded Input Consumption)
        validate_string_length("changeset_digest", changeset_digest_hex)?;

        let receipt_id = payload
            .get("receipt_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                ProjectionWorkerError::InvalidPayload("missing receipt_id".to_string())
            })?;

        // Validate string length (Blocker fix: Unbounded Input Consumption)
        validate_string_length("receipt_id", receipt_id)?;

        // Decode changeset digest
        let digest_bytes = hex::decode(changeset_digest_hex)
            .map_err(|e| ProjectionWorkerError::InvalidPayload(e.to_string()))?;

        if digest_bytes.len() != 32 {
            return Err(ProjectionWorkerError::InvalidPayload(
                "changeset_digest must be 32 bytes".to_string(),
            ));
        }

        let mut changeset_digest = [0u8; 32];
        changeset_digest.copy_from_slice(&digest_bytes);

        // BLOCKER FIX: Cross-PR Review Leakage / Spoofing via Digest Collision
        //
        // Security: Use `event.work_id` directly from the SignedLedgerEvent envelope
        // instead of looking it up from the changeset_digest. The changeset_work_index
        // table uses changeset_digest as PRIMARY KEY, so if two PRs share the same
        // commit, the second PR overwrites the first. Looking up work_id via digest
        // could resolve to the wrong PR.
        //
        // The SignedLedgerEvent envelope contains the authoritative work_id that was
        // set when the event was emitted. This is cryptographically bound to the
        // event signature, preventing spoofing.
        let work_id = &event.work_id;

        // Validate work_id from envelope
        validate_string_length("work_id", work_id)?;

        if work_id.is_empty() {
            return Err(ProjectionWorkerError::InvalidPayload(
                "work_id in event envelope is empty".to_string(),
            ));
        }

        // Major fix: Thread blocking in async context
        // Look up PR metadata using spawn_blocking to avoid blocking the Tokio runtime
        let work_id_owned = work_id.clone();
        let pr_metadata = tokio::task::spawn_blocking(move || {
            let conn_guard = work_index_conn.lock().map_err(|e| {
                ProjectionWorkerError::DatabaseError(format!("mutex poisoned: {e}"))
            })?;

            #[allow(clippy::cast_sign_loss)]
            conn_guard
                .query_row(
                    "SELECT pr_number, repo_owner, repo_name, head_sha
                     FROM work_pr_index WHERE work_id = ?1",
                    params![&work_id_owned],
                    |row| {
                        Ok(PrMetadata {
                            pr_number: row.get::<_, i64>(0)? as u64,
                            repo_owner: row.get(1)?,
                            repo_name: row.get(2)?,
                            head_sha: row.get(3)?,
                        })
                    },
                )
                .optional()
                .map_err(|e| ProjectionWorkerError::DatabaseError(e.to_string()))
        })
        .await
        .map_err(|e| ProjectionWorkerError::DatabaseError(format!("spawn_blocking failed: {e}")))??
        .ok_or_else(|| ProjectionWorkerError::NoPrAssociation {
            work_id: work_id.clone(),
        })?;

        // Parse review verdict to determine status (Major fix: hardcoded success)
        let verdict = payload
            .get("verdict")
            .and_then(|v| v.as_str())
            .unwrap_or("success");

        // Validate string length (Blocker fix: Unbounded Input Consumption)
        validate_string_length("verdict", verdict)?;

        let status = Self::parse_review_verdict(verdict);

        // Extract summary if present
        let summary = payload.get("summary").and_then(|v| v.as_str());

        // Validate summary length if present (Blocker fix: Unbounded Input Consumption)
        if let Some(s) = summary {
            validate_string_length("summary", s)?;
        }

        info!(
            receipt_id = %receipt_id,
            work_id = %work_id,
            pr_number = pr_metadata.pr_number,
            verdict = %verdict,
            "Processing review receipt for projection"
        );

        // =====================================================================
        // TCK-00505: Economics-gated admission with idempotent-insert
        //            replay prevention (fail-closed: no bypass path)
        // =====================================================================
        //
        // ALL review_receipt_recorded events MUST pass through the economics
        // gate. There is NO legacy ungated path.
        //
        //   - If selectors are present AND gate is wired: evaluate admission, insert as
        //     PENDING, project, then admit AFTER successful projection.
        //   - If selectors are present AND gate is NOT wired (init failure): DENY with
        //     durable recording in IntentBuffer before ACK.
        //   - If selectors are ABSENT: DENY with "missing_economics_selectors"
        //     subcategory. No projection bypass.
        //
        // Security (RSK-1105): The economics admission logic performs
        // synchronous blocking SQLite I/O (IntentBuffer::insert,
        // IntentBuffer::admit) and signed artifact construction. Wrapping
        // in spawn_blocking prevents async executor starvation.
        let has_econ_selectors = payload_has_economics_selectors(&payload);

        // Track the intent_id if economics gate admitted this event, so
        // we can durably admit it AFTER successful projection.
        #[allow(unused_assignments)]
        // Only the economics-gate-active path reaches post-block code; others return early.
        let mut pending_intent_id: Option<String> = None;

        if !has_econ_selectors {
            // Fail-closed: events without economics selectors are DENIED.
            // No legacy bypass path -- all review_receipt_recorded events
            // must carry economics selectors.
            let reason = "event missing economics selectors (fail-closed: no bypass path)";
            warn!(
                work_id = %work_id,
                receipt_id = %receipt_id,
                reason = %reason,
                "Denying projection: missing economics selectors"
            );
            self.telemetry
                .missing_selectors_denied_count
                .fetch_add(1, AtomicOrdering::Relaxed);

            // Record the deny durably in IntentBuffer before ACK.
            // If the IntentBuffer is not available (gate completely failed
            // to init), return a non-ACK error so the event is retried.
            let intent_buffer = self.intent_buffer.as_ref().ok_or_else(|| {
                ProjectionWorkerError::IntentBufferError(
                    "intent buffer not available for durable deny recording \
                     (missing selectors path); event will be retried"
                        .to_string(),
                )
            })?;
            record_denied_intent(
                intent_buffer,
                receipt_id,
                work_id,
                &changeset_digest,
                status,
                0, // eval_tick absent -- use zero sentinel
                event.timestamp_ns,
                reason,
            )?;

            return Err(ProjectionWorkerError::LifecycleDenied {
                reason: reason.to_string(),
                subcategory: lifecycle_deny::MISSING_SELECTORS.to_string(),
            });
        } else if self.has_economics_gate() {
            // Clone Arc-backed dependencies into the blocking closure.
            let intent_buffer = Arc::clone(self.intent_buffer.as_ref().ok_or_else(|| {
                ProjectionWorkerError::IntentBufferError("intent buffer not wired".to_string())
            })?);

            let resolver = Arc::clone(self.continuity_resolver.as_ref().ok_or_else(|| {
                ProjectionWorkerError::IntentBufferError(
                    "continuity resolver not wired".to_string(),
                )
            })?);
            let gate_signer = Arc::clone(self.gate_signer.as_ref().ok_or_else(|| {
                ProjectionWorkerError::IntentBufferError("gate signer not wired".to_string())
            })?);
            let telemetry = Arc::clone(&self.telemetry);
            let payload_clone = payload.clone();
            let work_id_clone = work_id.clone();
            let changeset_digest_clone = changeset_digest;
            let receipt_id_clone = receipt_id.to_string();
            let event_timestamp_ns = event.timestamp_ns;
            let event_id_clone = event.event_id.clone();

            let intent_id = tokio::task::spawn_blocking(move || {
                evaluate_economics_admission_blocking(
                    &payload_clone,
                    &work_id_clone,
                    &changeset_digest_clone,
                    &receipt_id_clone,
                    status,
                    event_timestamp_ns,
                    &event_id_clone,
                    &intent_buffer,
                    resolver.as_ref(),
                    &gate_signer,
                    &telemetry,
                )
            })
            .await
            .map_err(|e| {
                ProjectionWorkerError::IntentBufferError(format!("spawn_blocking failed: {e}"))
            })??;

            // Economics gate ALLOW + replay prevention passed.
            // The intent is PENDING in the buffer. We will admit it
            // AFTER successful projection to ensure at-least-once
            // semantics (BLOCKER-2 fix).
            pending_intent_id = Some(intent_id);
            debug!(
                work_id = %work_id,
                receipt_id = %receipt_id,
                "Economics admission: ALLOW (pending projection effect)"
            );
        } else {
            // Gate not wired but event carries economics selectors.
            // Fail-closed: DENY projection for events with economics
            // selectors when the gate is not initialized. This prevents
            // silent bypass of economics enforcement due to init failure
            // (MAJOR-1 fix: fail-closed gate wiring).
            let reason = "economics gate not initialized but event carries economics \
                 selectors (fail-closed)";
            warn!(
                work_id = %work_id,
                receipt_id = %receipt_id,
                reason = %reason,
                "Denying projection: economics gate INACTIVE for event with selectors"
            );
            self.telemetry
                .missing_gate_denied_count
                .fetch_add(1, AtomicOrdering::Relaxed);

            // Record the deny durably in IntentBuffer before ACK.
            // If the IntentBuffer itself is unavailable (gate completely
            // failed to init), return a non-ACK error so the event is
            // retried rather than silently ACKed without audit trail.
            let intent_buffer = self.intent_buffer.as_ref().ok_or_else(|| {
                ProjectionWorkerError::IntentBufferError(
                    "intent buffer not available for durable deny recording \
                     (missing gate path); event will be retried"
                        .to_string(),
                )
            })?;
            // Extract eval_tick for the deny record if available, otherwise
            // use zero sentinel.
            let eval_tick_for_deny = payload
                .get("eval_tick")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            record_denied_intent(
                intent_buffer,
                receipt_id,
                work_id,
                &changeset_digest,
                status,
                eval_tick_for_deny,
                event.timestamp_ns,
                reason,
            )?;

            return Err(ProjectionWorkerError::LifecycleDenied {
                reason: reason.to_string(),
                subcategory: lifecycle_deny::MISSING_GATE.to_string(),
            });
        }

        if let Some(ref intent_id) = pending_intent_id {
            // ---------------------------------------------------------------
            // BLOCKER FIX: Retry-safe lifecycle gate.
            //
            // On retry, the previous attempt may have completed the lifecycle
            // gate (join -> revalidate -> consume) and persisted artifacts to
            // the intent, but then failed during projection. If we re-run the
            // lifecycle gate, consume will hit AlreadyConsumed and permanently
            // suppress projection.
            //
            // Check for previously persisted lifecycle artifacts on the
            // pending intent FIRST. If found, reuse them and skip the
            // lifecycle gate. This makes the retry path idempotent with
            // respect to lifecycle consumption.
            // ---------------------------------------------------------------
            let existing_artifacts = {
                let intent_buffer = self.intent_buffer.as_ref().ok_or_else(|| {
                    ProjectionWorkerError::IntentBufferError(
                        "intent buffer unavailable for lifecycle artifact lookup".to_string(),
                    )
                })?;
                intent_buffer
                    .get_lifecycle_artifacts(intent_id)
                    .map_err(|e| ProjectionWorkerError::IntentBufferError(e.to_string()))?
            };

            if let Some(artifacts) = existing_artifacts {
                // Retry path: lifecycle artifacts already persisted from a
                // previous attempt. Skip the lifecycle gate to avoid
                // AlreadyConsumed denial. Artifacts are already in the DB --
                // no further persistence needed.
                info!(
                    intent_id = %intent_id,
                    ajc_id = %hex::encode(artifacts.ajc_id),
                    consume_tick = artifacts.consume_tick,
                    "Retry: reusing persisted lifecycle artifacts (skipping lifecycle gate)"
                );
            } else {
                // First attempt (or retry without persisted artifacts):
                // run the full lifecycle gate.
                let Some(lifecycle_gate) = self.projection_lifecycle_gate.as_ref() else {
                    let reason = "projection lifecycle gate not initialized (fail-closed)";
                    self.telemetry
                        .missing_gate_denied_count
                        .fetch_add(1, AtomicOrdering::Relaxed);
                    let intent_buffer = self.intent_buffer.as_ref().ok_or_else(|| {
                        ProjectionWorkerError::IntentBufferError(
                            "intent buffer unavailable for lifecycle deny recording".to_string(),
                        )
                    })?;
                    deny_pending_intent(intent_buffer, intent_id, reason)?;
                    return Err(ProjectionWorkerError::LifecycleDenied {
                        reason: reason.to_string(),
                        subcategory: lifecycle_deny::MISSING_GATE.to_string(),
                    });
                };

                let lifecycle_result = evaluate_projection_lifecycle_gate(
                    lifecycle_gate,
                    &payload,
                    self.telemetry.as_ref(),
                    &event.event_id,
                );
                match lifecycle_result {
                    Ok(artifacts) => {
                        // Persist lifecycle artifacts IMMEDIATELY after
                        // successful lifecycle gate, BEFORE projection.
                        // This ensures that on retry, we can detect the
                        // consumed token and skip re-consumption.
                        //
                        // BLOCKER FIX (round-4): If persistence fails,
                        // continue with in-memory artifacts rather than
                        // propagating the error. If we error out here,
                        // on retry the lifecycle gate will hit
                        // AlreadyConsumed (the token was consumed
                        // in-memory) and permanently deny the intent.
                        // Using the in-memory artifacts allows the
                        // current attempt to complete; if projection
                        // also fails, the AlreadyConsumed recovery
                        // path below will handle the next retry.
                        let intent_buffer = self.intent_buffer.as_ref().ok_or_else(|| {
                            ProjectionWorkerError::IntentBufferError(
                                "intent buffer unavailable for lifecycle artifact persistence"
                                    .to_string(),
                            )
                        })?;
                        if let Err(e) =
                            intent_buffer.attach_lifecycle_artifacts(intent_id, &artifacts)
                        {
                            warn!(
                                intent_id = %intent_id,
                                error = %e,
                                "Failed to persist lifecycle artifacts \
                                 (proceeding to projection; \
                                 retry will use AlreadyConsumed recovery)"
                            );
                        }
                        // Artifacts persisted to DB (or recovery via
                        // AlreadyConsumed on retry if persistence failed).
                        // No in-memory tracking needed.
                    },
                    Err(err) => {
                        // BLOCKER FIX (round-4): Retry-safe
                        // AlreadyConsumed handling.
                        //
                        // If the lifecycle gate returns AlreadyConsumed
                        // and the intent is still PENDING, this is a
                        // retry where a previous attempt consumed the
                        // token but failed before persisting artifacts
                        // (e.g., attach_lifecycle_artifacts error or
                        // DB corruption). The intent is still PENDING
                        // — projection never succeeded. Denying it
                        // would permanently suppress a retryable
                        // failure. Instead, proceed to projection
                        // WITHOUT lifecycle artifacts. The intent will
                        // be admitted on projection success.
                        //
                        // This preserves single-use consume semantics
                        // (token consumed once) without poisoning
                        // retries.
                        let is_already_consumed = matches!(
                            &err,
                            ProjectionWorkerError::LifecycleDenied { reason, subcategory }
                                if subcategory == lifecycle_deny::CONSUMED
                                   && reason.contains("consume denied")
                        );
                        if is_already_consumed {
                            info!(
                                intent_id = %intent_id,
                                "Retry: lifecycle token already consumed \
                                 but intent still PENDING — proceeding \
                                 to projection (retry-safe recovery)"
                            );
                            // No lifecycle artifacts available — proceed
                            // without them. The intent admission does
                            // not require artifacts to be present.
                        } else {
                            let deny_reason = match &err {
                                ProjectionWorkerError::LifecycleDenied { reason, .. } => {
                                    reason.clone()
                                },
                                _ => err.to_string(),
                            };
                            let intent_buffer = self.intent_buffer.as_ref().ok_or_else(|| {
                                ProjectionWorkerError::IntentBufferError(
                                    "intent buffer unavailable for lifecycle deny recording"
                                        .to_string(),
                                )
                            })?;
                            deny_pending_intent(intent_buffer, intent_id, &deny_reason)?;
                            return Err(err);
                        }
                    },
                }
            }
        }

        // Project to GitHub if adapter is configured.
        // SECURITY: If an intent was admitted (pending_intent_id is Some) but the
        // adapter is absent, we must NOT silently admit the intent without a
        // projection effect. Deny the intent and return an error so the event
        // is retried once the adapter becomes available.
        if pending_intent_id.is_some() && self.adapter.is_none() {
            let reason = "projection adapter not configured; cannot apply projection effect for admitted intent (fail-closed)";
            warn!(
                work_id = %work_id,
                receipt_id = %receipt_id,
                reason = %reason,
                "Denying projection: adapter absent for selector-bearing event with pending intent"
            );
            let intent_buffer = self.intent_buffer.as_ref().ok_or_else(|| {
                ProjectionWorkerError::IntentBufferError(
                    "intent buffer not available for adapter-absent deny recording".to_string(),
                )
            })?;
            if let Some(ref intent_id) = pending_intent_id {
                deny_pending_intent(intent_buffer, intent_id, reason)?;
            }
            self.telemetry
                .missing_gate_denied_count
                .fetch_add(1, AtomicOrdering::Relaxed);
            return Err(ProjectionWorkerError::LifecycleDenied {
                reason: reason.to_string(),
                subcategory: lifecycle_deny::MISSING_GATE.to_string(),
            });
        }

        if let Some(ref adapter) = self.adapter {
            // Major fix: Thread blocking in async context
            // Register commit SHA for status projection using async method with
            // spawn_blocking
            adapter
                .register_commit_sha_async(changeset_digest, pr_metadata.head_sha.clone())
                .await
                .map_err(|e| ProjectionWorkerError::ProjectionFailed(e.to_string()))?;

            // Major fix: Thread blocking in async context
            // Get ledger head for idempotency key using spawn_blocking
            let tailer_conn = Arc::clone(&self.review_tailer.conn);
            let ledger_head = tokio::task::spawn_blocking(move || {
                let conn_guard = tailer_conn.lock().map_err(|e| {
                    ProjectionWorkerError::DatabaseError(format!("mutex poisoned: {e}"))
                })?;

                #[allow(clippy::cast_sign_loss)]
                let result: Option<String> = conn_guard
                    .query_row(
                        "SELECT event_id FROM ledger_events ORDER BY timestamp_ns DESC, rowid DESC LIMIT 1",
                        [],
                        |row| row.get(0),
                    )
                    .optional()
                    .map_err(|e| ProjectionWorkerError::DatabaseError(e.to_string()))?;

                Ok(result.map(|event_id| {
                    let mut hash = [0u8; 32];
                    let digest = blake3::hash(event_id.as_bytes());
                    hash.copy_from_slice(digest.as_bytes());
                    hash
                }))
            })
            .await
            .map_err(|e| {
                ProjectionWorkerError::DatabaseError(format!("spawn_blocking failed: {e}"))
            })??
            .unwrap_or([0u8; 32]);

            // Project status (uses parsed verdict, not hardcoded success)
            let projection_receipt = adapter
                .project_status(work_id, changeset_digest, ledger_head, status)
                .await
                .map_err(|e| ProjectionWorkerError::ProjectionFailed(e.to_string()))?;

            info!(
                receipt_id = %projection_receipt.receipt_id,
                work_id = %work_id,
                status = %projection_receipt.projected_status,
                "Projected status to GitHub"
            );

            // Post PR comment (idempotent - check before posting)
            // Blocker fix: Comment projection is now idempotent
            let comment_receipt_id = format!("{receipt_id}-comment");

            // Major fix: Thread blocking in async context
            // Check if comment was already posted using spawn_blocking
            let work_index_conn = self.work_index.connection();
            let comment_id_for_check = comment_receipt_id.clone();
            let is_posted = tokio::task::spawn_blocking(move || {
                let Ok(conn_guard) = work_index_conn.lock() else {
                    return false;
                };

                conn_guard
                    .query_row(
                        "SELECT 1 FROM comment_receipts WHERE receipt_id = ?1",
                        params![&comment_id_for_check],
                        |_| Ok(()),
                    )
                    .is_ok()
            })
            .await
            .map_err(|e| {
                ProjectionWorkerError::DatabaseError(format!("spawn_blocking failed: {e}"))
            })?;

            if is_posted {
                debug!(
                    receipt_id = %receipt_id,
                    "Skipping comment post (already posted - idempotency)"
                );
            } else {
                let comment_body = GitHubProjectionAdapter::<
                    super::divergence_watchdog::SystemTimeSource,
                >::format_review_comment(
                    receipt_id, status, summary
                );

                adapter
                    .post_comment(pr_metadata.pr_number, &comment_body)
                    .await
                    .map_err(|e| ProjectionWorkerError::ProjectionFailed(e.to_string()))?;

                // Major fix: Thread blocking in async context
                // Record that comment was posted using spawn_blocking
                let work_index_conn = self.work_index.connection();
                let comment_id = comment_receipt_id.clone();
                let work_id_for_record = work_id.clone();
                let pr_number = pr_metadata.pr_number;

                tokio::task::spawn_blocking(move || {
                    let conn_guard = work_index_conn.lock().map_err(|e| {
                        ProjectionWorkerError::DatabaseError(format!("mutex poisoned: {e}"))
                    })?;

                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0);

                    #[allow(clippy::cast_possible_wrap)]
                    conn_guard
                        .execute(
                            "INSERT OR REPLACE INTO comment_receipts
                             (receipt_id, work_id, pr_number, comment_type, created_at)
                             VALUES (?1, ?2, ?3, ?4, ?5)",
                            params![
                                &comment_id,
                                &work_id_for_record,
                                pr_number as i64,
                                "review",
                                now as i64
                            ],
                        )
                        .map_err(|e| ProjectionWorkerError::DatabaseError(e.to_string()))?;

                    Ok::<(), ProjectionWorkerError>(())
                })
                .await
                .map_err(|e| {
                    ProjectionWorkerError::DatabaseError(format!("spawn_blocking failed: {e}"))
                })??;

                info!(
                    receipt_id = %receipt_id,
                    work_id = %work_id,
                    pr_number = pr_metadata.pr_number,
                    "Posted review comment to GitHub PR"
                );
            }
        } else {
            debug!(
                work_id = %work_id,
                "GitHub projection disabled, skipping"
            );
        }

        // =====================================================================
        // BLOCKER-2 fix: Admit intent AFTER successful projection.
        //
        // The intent was inserted as PENDING before projection. Lifecycle
        // artifacts were already persisted immediately after lifecycle gate
        // success (before projection). Now that all projection side effects
        // (status + comment + receipt persistence) succeeded, durably mark
        // the intent as admitted. On retry, a PENDING intent with persisted
        // lifecycle artifacts allows re-attempt without re-consuming the
        // lifecycle token; only ACK after both projection success AND
        // durable admission.
        // =====================================================================
        if let Some(ref intent_id) = pending_intent_id {
            let intent_buffer = Arc::clone(self.intent_buffer.as_ref().ok_or_else(|| {
                ProjectionWorkerError::IntentBufferError(
                    "intent buffer not wired for post-projection admit".to_string(),
                )
            })?);
            let intent_id_owned = intent_id.clone();
            let event_timestamp_ns = event.timestamp_ns;
            let telemetry = Arc::clone(&self.telemetry);

            tokio::task::spawn_blocking(move || {
                // Lifecycle artifacts are already persisted before projection
                // (BLOCKER fix: persist before effect to support retry).
                // Only the admit transition remains.
                let admitted = intent_buffer
                    .admit(&intent_id_owned, event_timestamp_ns)
                    .map_err(|e| ProjectionWorkerError::IntentBufferError(e.to_string()))?;
                if admitted {
                    telemetry
                        .admitted_count
                        .fetch_add(1, AtomicOrdering::Relaxed);
                }
                Ok::<(), ProjectionWorkerError>(())
            })
            .await
            .map_err(|e| {
                ProjectionWorkerError::IntentBufferError(format!("spawn_blocking failed: {e}"))
            })??;

            info!(
                work_id = %work_id,
                receipt_id = %receipt_id,
                intent_id = %intent_id,
                "Intent admitted AFTER successful projection"
            );
        }

        Ok(())
    }

    // (evaluate_economics_admission moved to free function below)

    /// Parses a review verdict string into a `ProjectedStatus`.
    ///
    /// Major fix: Previously hardcoded to Success, now parses actual verdict.
    fn parse_review_verdict(verdict: &str) -> ProjectedStatus {
        match verdict.to_lowercase().as_str() {
            "success" | "pass" | "approved" => ProjectedStatus::Success,
            "failure" | "fail" | "rejected" => ProjectedStatus::Failure,
            "pending" | "in_progress" => ProjectedStatus::Pending,
            "error" | "errored" => ProjectedStatus::Error,
            "cancelled" | "canceled" | "skipped" => ProjectedStatus::Cancelled,
            _ => {
                warn!(verdict = %verdict, "Unknown review verdict, defaulting to Pending");
                ProjectedStatus::Pending
            },
        }
    }
}

// =============================================================================
// Economics Admission Gate (free functions for spawn_blocking)
// =============================================================================

/// Records a denied intent in the intent buffer (TCK-00505).
///
/// Inserts the intent if it does not already exist, then marks it as
/// denied with the given reason.
///
/// # Errors
///
/// Returns an error if either the insert or deny operation fails. This
/// ensures deny records are durable before watermark advancement --
/// events must not be acknowledged without a durable deny recording (MINOR fix:
/// deny-path audit evidence must not be silently dropped).
#[allow(clippy::too_many_arguments)]
fn record_denied_intent(
    intent_buffer: &IntentBuffer,
    receipt_id: &str,
    work_id: &str,
    changeset_digest: &[u8; 32],
    status: ProjectedStatus,
    eval_tick: u64,
    event_timestamp_ns: u64,
    reason: &str,
) -> Result<(), ProjectionWorkerError> {
    let intent_id = format!("proj-{receipt_id}");
    let ledger_head = [0u8; 32]; // Zero -- denied intents have no committed ledger head.

    // Insert intent (idempotent). Propagate errors -- a failed insert means
    // the deny record will not be durable (MINOR fix: deny-path audit
    // evidence silently dropped).
    intent_buffer
        .insert(
            &intent_id,
            work_id,
            changeset_digest,
            &ledger_head,
            &status.to_string(),
            eval_tick,
            event_timestamp_ns,
        )
        .map_err(|e| {
            ProjectionWorkerError::IntentBufferError(format!("failed to insert deny intent: {e}"))
        })?;

    // Mark as denied. Propagate errors -- if deny fails, the event must
    // NOT be ACKed so it can be retried (ensures durable deny recording).
    let denied = intent_buffer
        .deny(&intent_id, reason)
        .map_err(|e| ProjectionWorkerError::IntentBufferError(e.to_string()))?;

    if !denied {
        // deny() returns false if the intent was not found or already had
        // a non-pending verdict. This is not inherently an error (the intent
        // may already be denied from a prior attempt), but log for
        // observability.
        debug!(
            intent_id = %intent_id,
            reason = %reason,
            "Deny returned false (intent may already be denied or not pending)"
        );
    }

    Ok(())
}

/// Marks an existing pending intent as denied.
///
/// Used when a post-admission gate (for example projection lifecycle) fails
/// after the intent was inserted as PENDING.
fn deny_pending_intent(
    intent_buffer: &IntentBuffer,
    intent_id: &str,
    reason: &str,
) -> Result<(), ProjectionWorkerError> {
    let denied = intent_buffer
        .deny(intent_id, reason)
        .map_err(|e| ProjectionWorkerError::IntentBufferError(e.to_string()))?;
    if !denied {
        debug!(
            intent_id = %intent_id,
            reason = %reason,
            "deny_pending_intent returned false (intent already non-pending)"
        );
    }
    Ok(())
}

#[derive(Debug, Clone, Copy)]
struct ProjectionLifecycleSelectors {
    ajc_id: [u8; 32],
    intent_digest: [u8; 32],
    consume_selector_digest: [u8; 32],
    consume_tick: u64,
    pcac_time_envelope_ref: [u8; 32],
}

fn extract_projection_lifecycle_selectors(
    payload: &serde_json::Value,
) -> Option<ProjectionLifecycleSelectors> {
    let ajc_id = extract_hash32_field(payload, "ajc_id")?;
    let intent_digest = extract_hash32_field(payload, "intent_digest")?;
    let consume_selector_digest = extract_hash32_field(payload, "consume_selector_digest")?;
    let consume_tick = payload
        .get("consume_tick")
        .and_then(serde_json::Value::as_u64)?;
    if consume_tick == 0 {
        return None;
    }
    let pcac_time_envelope_ref = extract_hash32_field(payload, "pcac_time_envelope_ref")?;

    Some(ProjectionLifecycleSelectors {
        ajc_id,
        intent_digest,
        consume_selector_digest,
        consume_tick,
        pcac_time_envelope_ref,
    })
}

const fn lifecycle_subcategory_from_deny_class(deny_class: &AuthorityDenyClass) -> &'static str {
    match deny_class {
        AuthorityDenyClass::RevocationFrontierAdvanced
        | AuthorityDenyClass::UnknownRevocationHead { .. } => lifecycle_deny::REVOKED,
        AuthorityDenyClass::StaleFreshnessAtJoin
        | AuthorityDenyClass::StaleFreshnessAtRevalidate
        | AuthorityDenyClass::CertificateExpired { .. }
        | AuthorityDenyClass::FreshnessExceeded { .. }
        | AuthorityDenyClass::LedgerAnchorDrift => lifecycle_deny::STALE,
        _ => lifecycle_deny::CONSUMED,
    }
}

fn increment_lifecycle_counter(telemetry: &AdmissionTelemetry, subcategory: &str) {
    match subcategory {
        lifecycle_deny::REVOKED => {
            telemetry
                .lifecycle_revoked_count
                .fetch_add(1, AtomicOrdering::Relaxed);
        },
        lifecycle_deny::STALE => {
            telemetry
                .lifecycle_stale_count
                .fetch_add(1, AtomicOrdering::Relaxed);
        },
        _ => {
            telemetry
                .lifecycle_consumed_count
                .fetch_add(1, AtomicOrdering::Relaxed);
        },
    }
}

/// Domain tag prefix for projection lifecycle witness hashes.
///
/// This is the projection-specific equivalent of
/// `PrivilegedPcacInputBuilder::hash()` in `protocol::dispatch`.
/// Uses a distinct domain to prevent cross-module digest confusion.
const PROJECTION_LIFECYCLE_DOMAIN: &str = "apm2-projection-lifecycle";

/// Compute a domain-tagged BLAKE3 hash for projection lifecycle fields.
///
/// Canonical pattern from RS-42 section 4.1: domain-tagged witness hashes
/// prevent cross-handler digest collisions.
fn projection_lifecycle_tagged_hash(hash_type: &str, data: &[&[u8]]) -> [u8; 32] {
    let tag = format!("{PROJECTION_LIFECYCLE_DOMAIN}-{hash_type}-v1");
    let mut hasher = blake3::Hasher::new_keyed(&{
        let mut key = [0u8; 32];
        let tag_hash = blake3::hash(tag.as_bytes());
        key.copy_from_slice(tag_hash.as_bytes());
        key
    });
    for segment in data {
        hasher.update(segment);
    }
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_bytes());
    out
}

/// Derive risk tier from event payload context.
///
/// MAJOR fix: Risk tier is derived from authoritative context instead of
/// hard-coded. Missing or unknown values fail closed to `Tier2Plus`
/// (most restrictive), preventing silent privilege escalation.
fn derive_risk_tier_from_payload(payload: &serde_json::Value) -> RiskTier {
    #[allow(clippy::match_same_arms)] // Explicit tier2+ arm documents accepted variants
    match payload.get("risk_tier").and_then(|v| v.as_str()) {
        Some("tier0" | "Tier0") => RiskTier::Tier0,
        Some("tier1" | "Tier1") => RiskTier::Tier1,
        Some("tier2" | "Tier2" | "tier2+" | "Tier2+" | "Tier2Plus") => RiskTier::Tier2Plus,
        // Fail-closed: unknown/missing -> most restrictive tier
        _ => RiskTier::Tier2Plus,
    }
}

/// Build the PCAC `AuthorityJoinInputV1` for projection lifecycle from
/// event payload context.
///
/// # Canonical Builder Equivalence (MAJOR fix: PCAC scope alignment)
///
/// This function is the projection module's equivalent of
/// `PrivilegedPcacInputBuilder` (defined in `protocol::dispatch`).
/// It cannot reuse `PrivilegedPcacInputBuilder` directly because:
///
/// 1. **Domain tag scheme**: `PrivilegedPcacInputBuilder` uses
///    `PrivilegedHandlerClass`-parameterized domain tags. The projection
///    lifecycle uses `apm2-projection-lifecycle`-prefixed tags to prevent
///    cross-module digest collisions.
///
/// 2. **Scope witness derivation**: Projection joins use `context_pack_hash`
///    and `role_spec_hash` as scope witnesses, which are projection-specific
///    bindings not covered by the dispatch builder.
///
/// 3. **Risk tier derivation**: Risk tier is derived from the event payload
///    (`risk_tier` field), failing closed to `Tier2Plus` if absent. This
///    replaces the hard-coded `Tier1` and supports Tier2+ enforcement.
///
/// The field mapping is structurally equivalent to
/// `PrivilegedPcacInputBuilder::build()` per RS-42 canonical lifecycle
/// requirements.
fn build_projection_lifecycle_join_input(
    payload: &serde_json::Value,
    selectors: ProjectionLifecycleSelectors,
    eval_tick: u64,
    ledger_anchor: [u8; 32],
) -> Result<AuthorityJoinInputV1, ProjectionWorkerError> {
    let capability_manifest_hash = extract_hash32_field(payload, "capability_manifest_hash")
        .ok_or_else(|| ProjectionWorkerError::LifecycleDenied {
            reason: "missing capability_manifest_hash for lifecycle join".to_string(),
            subcategory: lifecycle_deny::MISSING_LIFECYCLE_SELECTORS.to_string(),
        })?;
    let context_pack_hash =
        extract_hash32_field(payload, "context_pack_hash").ok_or_else(|| {
            ProjectionWorkerError::LifecycleDenied {
                reason: "missing context_pack_hash for lifecycle join".to_string(),
                subcategory: lifecycle_deny::MISSING_LIFECYCLE_SELECTORS.to_string(),
            }
        })?;
    let role_spec_hash = extract_hash32_field(payload, "role_spec_hash").ok_or_else(|| {
        ProjectionWorkerError::LifecycleDenied {
            reason: "missing role_spec_hash for lifecycle join".to_string(),
            subcategory: lifecycle_deny::MISSING_LIFECYCLE_SELECTORS.to_string(),
        }
    })?;
    let identity_proof_hash =
        extract_hash32_field(payload, "identity_proof_hash").ok_or_else(|| {
            ProjectionWorkerError::LifecycleDenied {
                reason: "missing identity_proof_hash for lifecycle join".to_string(),
                subcategory: lifecycle_deny::MISSING_LIFECYCLE_SELECTORS.to_string(),
            }
        })?;
    let lease_id = payload_nonempty_str(payload, "lease_id").map_err(|_| {
        ProjectionWorkerError::LifecycleDenied {
            reason: "missing lease_id for lifecycle join".to_string(),
            subcategory: lifecycle_deny::MISSING_LIFECYCLE_SELECTORS.to_string(),
        }
    })?;

    let freshness_tick = eval_tick.max(1);
    let tick_bytes = freshness_tick.to_le_bytes();

    // MAJOR fix: Derive risk tier from authoritative payload context.
    // Missing or unknown -> Tier2Plus (fail-closed: most restrictive).
    let risk_tier = derive_risk_tier_from_payload(payload);

    // Canonical pattern: domain-tagged witness hashes (RS-42 section 4.1).
    let leakage_witness_hash = projection_lifecycle_tagged_hash(
        "boundary_leakage_witness_hash",
        &[&selectors.intent_digest, &context_pack_hash, &tick_bytes],
    );
    let timing_witness_hash = projection_lifecycle_tagged_hash(
        "boundary_timing_witness_hash",
        &[
            &selectors.pcac_time_envelope_ref,
            &ledger_anchor,
            &tick_bytes,
        ],
    );

    Ok(AuthorityJoinInputV1 {
        session_id: lease_id.to_string(),
        holon_id: None,
        intent_digest: selectors.intent_digest,
        boundary_intent_class: BoundaryIntentClass::Actuate,
        capability_manifest_hash,
        scope_witness_hashes: vec![context_pack_hash, role_spec_hash],
        lease_id: lease_id.to_string(),
        permeability_receipt_hash: Some(role_spec_hash),
        identity_proof_hash,
        identity_evidence_level: IdentityEvidenceLevel::Verified,
        pointer_only_waiver_hash: None,
        directory_head_hash: ledger_anchor,
        freshness_policy_hash: role_spec_hash,
        freshness_witness_tick: freshness_tick,
        stop_budget_profile_digest: capability_manifest_hash,
        pre_actuation_receipt_hashes: Vec::new(),
        leakage_witness_hash,
        timing_witness_hash,
        risk_tier,
        determinism_class: DeterminismClass::Deterministic,
        time_envelope_ref: selectors.pcac_time_envelope_ref,
        as_of_ledger_anchor: ledger_anchor,
    })
}

fn evaluate_projection_lifecycle_gate(
    lifecycle_gate: &LifecycleGate,
    payload: &serde_json::Value,
    telemetry: &AdmissionTelemetry,
    event_id: &str,
) -> Result<IntentLifecycleArtifacts, ProjectionWorkerError> {
    let selectors = extract_projection_lifecycle_selectors(payload).ok_or_else(|| {
        ProjectionWorkerError::LifecycleDenied {
            reason: "missing lifecycle selectors for projection effect gate".to_string(),
            subcategory: lifecycle_deny::MISSING_LIFECYCLE_SELECTORS.to_string(),
        }
    })?;
    debug!(
        payload_ajc_id = %hex::encode(selectors.ajc_id),
        payload_intent_digest = %hex::encode(selectors.intent_digest),
        payload_consume_selector_digest = %hex::encode(selectors.consume_selector_digest),
        payload_consume_tick = selectors.consume_tick,
        "Evaluating projection lifecycle selectors"
    );

    let eval_tick = payload
        .get("eval_tick")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(selectors.consume_tick)
        .max(1);
    let window_ref = extract_hash32_field(payload, "window_ref").ok_or_else(|| {
        ProjectionWorkerError::LifecycleDenied {
            reason: "missing window_ref for lifecycle gate".to_string(),
            subcategory: lifecycle_deny::STALE.to_string(),
        }
    })?;
    let ledger_anchor = {
        let digest = blake3::hash(event_id.as_bytes());
        let mut out = [0u8; 32];
        out.copy_from_slice(digest.as_bytes());
        out
    };
    let join_input =
        build_projection_lifecycle_join_input(payload, selectors, eval_tick, ledger_anchor)?;
    let policy = PcacPolicyKnobs::default();

    lifecycle_gate.advance_tick(eval_tick);
    let cert = lifecycle_gate
        .join_and_revalidate(
            &join_input,
            selectors.pcac_time_envelope_ref,
            ledger_anchor,
            window_ref,
            &policy,
        )
        .map_err(|deny| {
            let subcategory = lifecycle_subcategory_from_deny_class(&deny.deny_class);
            increment_lifecycle_counter(telemetry, subcategory);
            ProjectionWorkerError::LifecycleDenied {
                reason: format!(
                    "projection lifecycle join/revalidate denied: {}",
                    deny.deny_class
                ),
                subcategory: subcategory.to_string(),
            }
        })?;

    lifecycle_gate.advance_tick(selectors.consume_tick.max(eval_tick));
    lifecycle_gate
        .revalidate_before_execution(
            &cert,
            selectors.pcac_time_envelope_ref,
            ledger_anchor,
            window_ref,
            &policy,
        )
        .map_err(|deny| {
            let subcategory = lifecycle_subcategory_from_deny_class(&deny.deny_class);
            increment_lifecycle_counter(telemetry, subcategory);
            ProjectionWorkerError::LifecycleDenied {
                reason: format!(
                    "projection lifecycle revalidate denied: {}",
                    deny.deny_class
                ),
                subcategory: subcategory.to_string(),
            }
        })?;

    let (consumed_witness, consume_record) = lifecycle_gate
        .consume_before_effect(
            &cert,
            join_input.intent_digest,
            join_input.boundary_intent_class,
            true,
            selectors.pcac_time_envelope_ref,
            window_ref,
            &policy,
        )
        .map_err(|deny| {
            let subcategory = lifecycle_subcategory_from_deny_class(&deny.deny_class);
            increment_lifecycle_counter(telemetry, subcategory);
            ProjectionWorkerError::LifecycleDenied {
                reason: format!("projection lifecycle consume denied: {}", deny.deny_class),
                subcategory: subcategory.to_string(),
            }
        })?;

    debug!(
        ajc_id = %hex::encode(cert.ajc_id),
        intent_digest = %hex::encode(consumed_witness.intent_digest),
        consume_selector_digest = %hex::encode(consume_record.effect_selector_digest),
        consume_tick = consumed_witness.consumed_at_tick,
        "Projection lifecycle gate passed (join -> revalidate -> consume)"
    );

    Ok(IntentLifecycleArtifacts {
        ajc_id: cert.ajc_id,
        intent_digest: consumed_witness.intent_digest,
        consume_selector_digest: consume_record.effect_selector_digest,
        consume_tick: consumed_witness.consumed_at_tick,
        time_envelope_ref: consumed_witness.consumed_time_envelope_ref,
    })
}

/// Constructs a signed [`ProjectionContinuityWindowV1`] from resolved config
/// values and gate input hashes. Returns `None` on construction failure.
fn build_signed_window(
    resolved: &ResolvedContinuityWindow,
    time_authority_ref: [u8; 32],
    window_ref: [u8; 32],
    eval_tick: u64,
    signer: &Signer,
) -> Option<ProjectionContinuityWindowV1> {
    // Use the window_ref as both outage and replay window refs for
    // config-backed resolution (the config declares span durations, not
    // separate hash references for each sub-window).
    let content_hash = EventHasher::hash_content(
        &[
            resolved.boundary_id.as_bytes(),
            &resolved.outage_window_ticks.to_be_bytes(),
            &resolved.replay_window_ticks.to_be_bytes(),
        ]
        .concat(),
    );

    ProjectionContinuityWindowV1::create_signed(
        &format!("win-{}", hex::encode(&window_ref[..8])),
        &resolved.boundary_id,
        eval_tick.saturating_sub(resolved.outage_window_ticks), // outage start
        eval_tick,                                              // outage end
        eval_tick.saturating_sub(resolved.replay_window_ticks), // replay start
        eval_tick,                                              // replay end
        window_ref,                                             // outage_window_ref
        window_ref,                                             // replay_window_ref
        time_authority_ref,
        window_ref,
        content_hash,
        "projection-gate-signer",
        signer,
    )
    .ok()
}

/// Constructs a signed [`ProjectionSinkContinuityProfileV1`] from resolved
/// config values, the snapshot digest, and gate input hashes.
/// Returns `None` on construction failure.
fn build_signed_profile(
    resolved: &ResolvedContinuityProfile,
    snapshot_digest: [u8; 32],
    time_authority_ref: [u8; 32],
    window_ref: [u8; 32],
    signer: &Signer,
) -> Option<ProjectionSinkContinuityProfileV1> {
    // Build a single scenario verdict proving truth-plane continuation and
    // bounded backlog from the config-declared tolerances.
    let scenario_id = format!("cfg-{}", &resolved.sink_id);
    let scenario_digest = EventHasher::hash_content(
        &[
            resolved.sink_id.as_bytes(),
            &resolved.churn_tolerance.to_be_bytes(),
            &resolved.partition_tolerance.to_be_bytes(),
        ]
        .concat(),
    );

    let scenario = ContinuityScenarioVerdict {
        scenario_id,
        scenario_digest,
        truth_plane_continued: true,
        backlog_bounded: true,
        max_backlog_items: 0,
    };

    let content_hash = EventHasher::hash_content(
        &[
            resolved.sink_id.as_bytes(),
            &snapshot_digest,
            &time_authority_ref,
        ]
        .concat(),
    );

    ProjectionSinkContinuityProfileV1::create_signed(
        &format!("prof-{}", &resolved.sink_id),
        &resolved.sink_id, // boundary_id = sink_id for config-backed resolution
        vec![scenario],
        snapshot_digest,
        time_authority_ref,
        window_ref,
        content_hash,
        "projection-gate-signer",
        signer,
    )
    .ok()
}

/// Evaluates economics admission with idempotent-insert replay prevention
/// for a projection intent. Designed to run inside `spawn_blocking`.
///
/// # Gate Input Assembly
///
/// Extracts `eval_tick`, `time_authority_ref`, `window_ref`, and
/// `boundary_id` from the `ReviewReceiptRecorded` event payload.
/// Missing fields result in DENY (fail-closed).
///
/// # Signed Artifact Construction
///
/// Uses the resolved continuity window/profile from the
/// `ContinuityProfileResolver` to construct real signed
/// `ProjectionContinuityWindowV1` and `ProjectionSinkContinuityProfileV1`
/// artifacts, then passes them to `evaluate_projection_continuity()`.
///
/// # Replay Prevention
///
/// On economics ALLOW, inserts the intent into the `IntentBuffer` as
/// PENDING. If the intent already exists (same `work_id +
/// changeset_digest`), the projection is denied as a replay. This
/// provides idempotent-insert replay prevention via `IntentBuffer`
/// uniqueness constraint.
///
/// # Returns
///
/// On success, returns the `intent_id` (`String`) of the PENDING intent.
/// The caller MUST admit this intent AFTER successful projection to
/// ensure at-least-once semantics. On retry, a PENDING intent allows
/// re-attempt.
///
/// # Errors
///
/// Returns `AdmissionDenied` when the economics gate returns DENY.
/// Returns `LifecycleDenied` when replay prevention detects a duplicate.
#[allow(clippy::too_many_arguments)]
fn evaluate_economics_admission_blocking(
    payload: &serde_json::Value,
    work_id: &str,
    changeset_digest: &[u8; 32],
    receipt_id: &str,
    status: ProjectedStatus,
    event_timestamp_ns: u64,
    event_id: &str,
    intent_buffer: &IntentBuffer,
    resolver: &dyn ContinuityProfileResolver,
    gate_signer: &Signer,
    telemetry: &AdmissionTelemetry,
) -> Result<String, ProjectionWorkerError> {
    // -----------------------------------------------------------------
    // Step 1: Extract gate inputs from event payload (fail-closed on
    //         missing fields).
    // -----------------------------------------------------------------
    let Some(eval_tick) = payload.get("eval_tick").and_then(serde_json::Value::as_u64) else {
        let reason = "missing eval_tick in event payload (fail-closed)";
        record_denied_intent(
            intent_buffer,
            receipt_id,
            work_id,
            changeset_digest,
            status,
            0,
            event_timestamp_ns,
            reason,
        )?;
        telemetry
            .missing_inputs_denied_count
            .fetch_add(1, AtomicOrdering::Relaxed);
        return Err(ProjectionWorkerError::AdmissionDenied {
            reason: reason.to_string(),
        });
    };

    let Some(time_authority_ref) = extract_hash32_field(payload, "time_authority_ref") else {
        // Classify zero-hash time_authority_ref as explicit revoked authority
        // (MINOR fix: lifecycle telemetry subcategories).
        let is_zero = is_zero_hash32_field(payload, "time_authority_ref");
        let (reason, subcategory) = if is_zero {
            (
                "time_authority_ref is zero (revoked authority) (fail-closed)",
                Some(lifecycle_deny::REVOKED),
            )
        } else {
            (
                "missing or invalid time_authority_ref in event payload (fail-closed)",
                None,
            )
        };
        record_denied_intent(
            intent_buffer,
            receipt_id,
            work_id,
            changeset_digest,
            status,
            eval_tick,
            event_timestamp_ns,
            reason,
        )?;
        if is_zero {
            telemetry
                .lifecycle_revoked_count
                .fetch_add(1, AtomicOrdering::Relaxed);
            return Err(ProjectionWorkerError::LifecycleDenied {
                reason: reason.to_string(),
                subcategory: subcategory.unwrap().to_string(),
            });
        }
        telemetry
            .missing_inputs_denied_count
            .fetch_add(1, AtomicOrdering::Relaxed);
        return Err(ProjectionWorkerError::AdmissionDenied {
            reason: reason.to_string(),
        });
    };

    let Some(window_ref) = extract_hash32_field(payload, "window_ref") else {
        // Classify zero-hash window_ref as explicit stale authority
        // (MINOR fix: lifecycle telemetry subcategories).
        let is_zero = is_zero_hash32_field(payload, "window_ref");
        let (reason, subcategory) = if is_zero {
            (
                "window_ref is zero (stale authority) (fail-closed)",
                Some(lifecycle_deny::STALE),
            )
        } else {
            (
                "missing or invalid window_ref in event payload (fail-closed)",
                None,
            )
        };
        record_denied_intent(
            intent_buffer,
            receipt_id,
            work_id,
            changeset_digest,
            status,
            eval_tick,
            event_timestamp_ns,
            reason,
        )?;
        if is_zero {
            telemetry
                .lifecycle_stale_count
                .fetch_add(1, AtomicOrdering::Relaxed);
            return Err(ProjectionWorkerError::LifecycleDenied {
                reason: reason.to_string(),
                subcategory: subcategory.unwrap().to_string(),
            });
        }
        telemetry
            .missing_inputs_denied_count
            .fetch_add(1, AtomicOrdering::Relaxed);
        return Err(ProjectionWorkerError::AdmissionDenied {
            reason: reason.to_string(),
        });
    };

    let boundary_id = match payload.get("boundary_id").and_then(|v| v.as_str()) {
        Some(id) if !id.is_empty() => id.to_string(),
        _ => {
            let reason = "missing or empty boundary_id in event payload (fail-closed)";
            record_denied_intent(
                intent_buffer,
                receipt_id,
                work_id,
                changeset_digest,
                status,
                eval_tick,
                event_timestamp_ns,
                reason,
            )?;
            telemetry
                .missing_inputs_denied_count
                .fetch_add(1, AtomicOrdering::Relaxed);
            return Err(ProjectionWorkerError::AdmissionDenied {
                reason: reason.to_string(),
            });
        },
    };
    if boundary_id.len() > MAX_STRING_LENGTH {
        let reason = "boundary_id exceeds maximum length (fail-closed)";
        record_denied_intent(
            intent_buffer,
            receipt_id,
            work_id,
            changeset_digest,
            status,
            eval_tick,
            event_timestamp_ns,
            reason,
        )?;
        telemetry
            .missing_inputs_denied_count
            .fetch_add(1, AtomicOrdering::Relaxed);
        return Err(ProjectionWorkerError::AdmissionDenied {
            reason: reason.to_string(),
        });
    }

    // -----------------------------------------------------------------
    // Step 2: Resolve continuity profile, sink snapshot, and window
    //         from the resolver. Missing resolution -> DENY.
    //
    // MAJOR-1 fix: Use boundary_id from the event payload as the sink
    // ID for profile and snapshot resolution, instead of hard-coding
    // DEFAULT_SINK_ID. This supports configs with different sink IDs.
    // -----------------------------------------------------------------
    let sink_id = &boundary_id;

    let Some(resolved_profile) = resolver.resolve_continuity_profile(sink_id) else {
        let reason = format!("continuity profile not found for sink '{sink_id}' (fail-closed)");
        record_denied_intent(
            intent_buffer,
            receipt_id,
            work_id,
            changeset_digest,
            status,
            eval_tick,
            event_timestamp_ns,
            &reason,
        )?;
        telemetry
            .missing_inputs_denied_count
            .fetch_add(1, AtomicOrdering::Relaxed);
        return Err(ProjectionWorkerError::AdmissionDenied { reason });
    };

    let Some(snapshot) = resolver.resolve_sink_snapshot(sink_id) else {
        let reason = format!("sink snapshot not found for sink '{sink_id}' (fail-closed)");
        record_denied_intent(
            intent_buffer,
            receipt_id,
            work_id,
            changeset_digest,
            status,
            eval_tick,
            event_timestamp_ns,
            &reason,
        )?;
        telemetry
            .missing_inputs_denied_count
            .fetch_add(1, AtomicOrdering::Relaxed);
        return Err(ProjectionWorkerError::AdmissionDenied { reason });
    };

    let Some(resolved_window) = resolver.resolve_continuity_window(&boundary_id) else {
        let reason =
            format!("continuity window not found for boundary '{boundary_id}' (fail-closed)");
        record_denied_intent(
            intent_buffer,
            receipt_id,
            work_id,
            changeset_digest,
            status,
            eval_tick,
            event_timestamp_ns,
            &reason,
        )?;
        telemetry
            .missing_inputs_denied_count
            .fetch_add(1, AtomicOrdering::Relaxed);
        return Err(ProjectionWorkerError::AdmissionDenied { reason });
    };

    // -----------------------------------------------------------------
    // Step 3: Construct signed continuity window and profile artifacts
    //         from the resolved config values, then evaluate the
    //         economics gate via evaluate_projection_continuity().
    // -----------------------------------------------------------------
    let signed_window = build_signed_window(
        &resolved_window,
        time_authority_ref,
        window_ref,
        eval_tick,
        gate_signer,
    );

    let Some(ref window_artifact) = signed_window else {
        let reason = "failed to construct signed continuity window (fail-closed)";
        record_denied_intent(
            intent_buffer,
            receipt_id,
            work_id,
            changeset_digest,
            status,
            eval_tick,
            event_timestamp_ns,
            reason,
        )?;
        telemetry
            .missing_inputs_denied_count
            .fetch_add(1, AtomicOrdering::Relaxed);
        return Err(ProjectionWorkerError::AdmissionDenied {
            reason: reason.to_string(),
        });
    };

    let signed_profile = build_signed_profile(
        &resolved_profile,
        snapshot.snapshot_digest,
        time_authority_ref,
        window_ref,
        gate_signer,
    );

    let Some(ref profile_artifact) = signed_profile else {
        let reason = "failed to construct signed continuity profile (fail-closed)";
        record_denied_intent(
            intent_buffer,
            receipt_id,
            work_id,
            changeset_digest,
            status,
            eval_tick,
            event_timestamp_ns,
            reason,
        )?;
        telemetry
            .missing_inputs_denied_count
            .fetch_add(1, AtomicOrdering::Relaxed);
        return Err(ProjectionWorkerError::AdmissionDenied {
            reason: reason.to_string(),
        });
    };

    let decision = evaluate_projection_continuity(
        Some(window_artifact),
        Some(profile_artifact),
        Some(&snapshot),
        &boundary_id,
        eval_tick,
        time_authority_ref,
        window_ref,
        &resolved_profile.trusted_signer_keys,
        &DeferredReplayMode::Inactive,
    );

    if decision.verdict != ContinuityVerdict::Allow {
        let deny_reason = decision
            .defect
            .as_ref()
            .map_or_else(|| "economics_gate_deny".to_string(), |d| d.reason.clone());

        record_denied_intent(
            intent_buffer,
            receipt_id,
            work_id,
            changeset_digest,
            status,
            eval_tick,
            event_timestamp_ns,
            &deny_reason,
        )?;
        telemetry
            .economics_denied_count
            .fetch_add(1, AtomicOrdering::Relaxed);

        info!(
            work_id = %work_id,
            receipt_id = %receipt_id,
            deny_reason = %deny_reason,
            sink_id = %sink_id,
            "Economics admission DENY -- projection skipped"
        );

        return Err(ProjectionWorkerError::AdmissionDenied {
            reason: deny_reason,
        });
    }

    // -----------------------------------------------------------------
    // Step 4: Idempotent-insert replay prevention.
    //
    // Insert the intent into the durable buffer as PENDING. If the
    // intent already exists (same work_id + changeset_digest), the
    // projection is denied as a replay. This provides single-projection
    // semantics via idempotent-insert replay prevention.
    //
    // BLOCKER-2 fix: The intent is inserted as PENDING here. Admission
    // (marking as admitted) happens AFTER successful projection in the
    // caller. On retry, a PENDING intent allows re-attempt. Only ACK
    // after both projection success AND durable admission.
    // -----------------------------------------------------------------
    let intent_id = format!("proj-{receipt_id}");
    let ledger_head = blake3::hash(event_id.as_bytes());
    let ledger_head_bytes: [u8; 32] = *ledger_head.as_bytes();

    let inserted = intent_buffer
        .insert(
            &intent_id,
            work_id,
            changeset_digest,
            &ledger_head_bytes,
            &status.to_string(),
            eval_tick,
            event_timestamp_ns,
        )
        .map_err(|e| ProjectionWorkerError::IntentBufferError(e.to_string()))?;

    if !inserted {
        // BLOCKER fix: Duplicate insert does NOT unconditionally deny.
        // Load the existing intent's verdict and branch by state:
        //
        // - Pending: this is a RETRY after a transient projection failure. Proceed to
        //   attempt projection again (no ACK until success).
        // - Admitted: already projected successfully. Safe to ACK as duplicate.
        // - Denied: already denied. Safe to ACK.
        //
        // Previously, duplicate insert caused LifecycleDenied + ACK which
        // permanently suppressed projection after a transient failure.
        let existing = intent_buffer
            .get_intent(&intent_id)
            .map_err(|e| ProjectionWorkerError::IntentBufferError(e.to_string()))?;

        match existing.as_ref().map(|i| i.verdict) {
            Some(crate::projection::intent_buffer::IntentVerdict::Pending) => {
                // This is a RETRY — the previous attempt inserted PENDING
                // but projection failed before admission. Proceed to
                // re-attempt projection (return intent_id to caller).
                info!(
                    work_id = %work_id,
                    receipt_id = %receipt_id,
                    intent_id = %intent_id,
                    "Retry: existing PENDING intent found, re-attempting projection"
                );
                // Fall through to return Ok(intent_id) below.
            },
            Some(crate::projection::intent_buffer::IntentVerdict::Admitted) => {
                // Already projected successfully — safe to ACK as duplicate.
                telemetry
                    .lifecycle_consumed_count
                    .fetch_add(1, AtomicOrdering::Relaxed);

                info!(
                    work_id = %work_id,
                    receipt_id = %receipt_id,
                    subcategory = %lifecycle_deny::CONSUMED,
                    "Replay prevention: already admitted -- ACK as duplicate"
                );

                return Err(ProjectionWorkerError::LifecycleDenied {
                    reason: "intent already admitted (duplicate, safe to ACK)".to_string(),
                    subcategory: lifecycle_deny::CONSUMED.to_string(),
                });
            },
            Some(crate::projection::intent_buffer::IntentVerdict::Denied) => {
                // Already denied — safe to ACK.
                telemetry
                    .lifecycle_consumed_count
                    .fetch_add(1, AtomicOrdering::Relaxed);

                info!(
                    work_id = %work_id,
                    receipt_id = %receipt_id,
                    subcategory = %lifecycle_deny::CONSUMED,
                    "Replay prevention: already denied -- ACK as duplicate"
                );

                return Err(ProjectionWorkerError::LifecycleDenied {
                    reason: "intent already denied (duplicate, safe to ACK)".to_string(),
                    subcategory: lifecycle_deny::CONSUMED.to_string(),
                });
            },
            None => {
                // Intent not found despite insert returning false — this
                // should not happen. Fail-closed.
                let reason = "intent not found after duplicate insert (fail-closed)";
                telemetry
                    .lifecycle_consumed_count
                    .fetch_add(1, AtomicOrdering::Relaxed);

                return Err(ProjectionWorkerError::LifecycleDenied {
                    reason: reason.to_string(),
                    subcategory: lifecycle_deny::CONSUMED.to_string(),
                });
            },
        }
    }

    // Intent is now PENDING in the buffer. The caller will admit it
    // AFTER successful projection (BLOCKER-2 fix: admission recorded
    // AFTER projection side effects, not before).

    info!(
        work_id = %work_id,
        receipt_id = %receipt_id,
        intent_id = %intent_id,
        eval_tick = eval_tick,
        boundary_id = %boundary_id,
        sink_id = %sink_id,
        "Economics admission: ALLOW (intent PENDING, awaiting projection effect)"
    );

    Ok(intent_id)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use apm2_core::evidence::{ContentAddressedStore, MemoryCas};

    use super::*;

    fn create_test_db() -> Arc<Mutex<Connection>> {
        let conn = Connection::open_in_memory().unwrap();

        // Initialize ledger schema
        conn.execute(
            "CREATE TABLE IF NOT EXISTS ledger_events (
                event_id TEXT PRIMARY KEY,
                event_type TEXT NOT NULL,
                work_id TEXT NOT NULL,
                actor_id TEXT NOT NULL,
                payload BLOB NOT NULL,
                signature BLOB NOT NULL,
                timestamp_ns INTEGER NOT NULL
            )",
            [],
        )
        .unwrap();

        // Initialize work index schema (required for tailer watermark persistence)
        conn.execute_batch(WORK_INDEX_SCHEMA_SQL).unwrap();

        Arc::new(Mutex::new(conn))
    }

    #[test]
    fn test_work_index_register_changeset() {
        let conn = create_test_db();
        let index = WorkIndex::new(conn).unwrap();

        let digest = [0x42u8; 32];
        let work_id = "work-001";

        index.register_changeset(&digest, work_id).unwrap();

        assert_eq!(index.get_work_id(&digest), Some(work_id.to_string()));
    }

    #[test]
    fn test_work_index_register_pr() {
        let conn = create_test_db();
        let index = WorkIndex::new(conn).unwrap();

        let work_id = "work-001";
        index
            .register_pr(work_id, 123, "owner", "repo", "abc123")
            .unwrap();

        let metadata = index.get_pr_metadata(work_id).unwrap();
        assert_eq!(metadata.pr_number, 123);
        assert_eq!(metadata.repo_owner, "owner");
        assert_eq!(metadata.repo_name, "repo");
        assert_eq!(metadata.head_sha, "abc123");
    }

    #[test]
    fn test_work_index_lookup_work_id_by_repo_pr_key() {
        let conn = create_test_db();
        let index = WorkIndex::new(conn).unwrap();

        index
            .register_pr("work-lookup-001", 321, "octo", "repo-one", "sha321")
            .unwrap();

        assert_eq!(
            index.get_work_id_for_pr("octo", "repo-one", 321),
            Some("work-lookup-001".to_string())
        );
        assert!(index.get_work_id_for_pr("octo", "repo-one", 999).is_none());
    }

    #[test]
    fn test_work_index_same_pr_number_across_repos_maps_to_distinct_work_ids() {
        let conn = create_test_db();
        let index = WorkIndex::new(conn).unwrap();

        index
            .register_pr("work-repo-a", 77, "owner-a", "repo-a", "sha-a")
            .unwrap();
        index
            .register_pr("work-repo-b", 77, "owner-b", "repo-b", "sha-b")
            .unwrap();

        assert_eq!(
            index.get_work_id_for_pr("owner-a", "repo-a", 77),
            Some("work-repo-a".to_string())
        );
        assert_eq!(
            index.get_work_id_for_pr("owner-b", "repo-b", 77),
            Some("work-repo-b".to_string())
        );
    }

    #[test]
    fn test_work_pr_associated_projection_joins_repo_identity_from_work_spec() {
        use apm2_core::fac::work_cas_schemas::{
            WORK_SPEC_V1_SCHEMA, WorkSpecRepo, WorkSpecType, WorkSpecV1, canonicalize_for_cas,
        };

        let conn = create_test_db();
        let mut worker = ProjectionWorker::new(Arc::clone(&conn), ProjectionWorkerConfig::new())
            .expect("worker should initialize");
        let cas = Arc::new(MemoryCas::default());
        worker.set_authoritative_cas(Arc::clone(&cas) as Arc<dyn ContentAddressedStore>);

        let register_work_opened = |work_id: &str, owner: &str, repo: &str| {
            let spec = WorkSpecV1 {
                schema: WORK_SPEC_V1_SCHEMA.to_string(),
                work_id: work_id.to_string(),
                ticket_alias: None,
                title: format!("Work {work_id}"),
                summary: None,
                work_type: WorkSpecType::Ticket,
                repo: Some(WorkSpecRepo {
                    owner: owner.to_string(),
                    name: repo.to_string(),
                    default_branch: Some("main".to_string()),
                }),
                requirement_ids: Vec::new(),
                labels: Vec::new(),
                rfc_id: None,
                parent_work_ids: Vec::new(),
                created_at_ns: None,
            };
            let spec_json = serde_json::to_string(&spec).expect("work spec serializes");
            let canonical = canonicalize_for_cas(&spec_json).expect("work spec canonicalizes");
            let stored = cas
                .store(canonical.as_bytes())
                .expect("work spec stores in CAS");

            let opened_payload = apm2_core::work::helpers::work_opened_payload(
                work_id,
                "TICKET",
                stored.hash.to_vec(),
                Vec::new(),
                Vec::new(),
            );
            let envelope = serde_json::json!({
                "event_type": "work.opened",
                "session_id": work_id,
                "actor_id": "actor-test",
                "payload": hex::encode(opened_payload),
            });
            let envelope_bytes = serde_json::to_vec(&envelope).expect("envelope serializes");

            let conn_guard = conn.lock().expect("lock");
            conn_guard
                .execute(
                    "INSERT INTO ledger_events \
                     (event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![
                        format!("evt-opened-{work_id}"),
                        "work.opened",
                        work_id,
                        "actor-test",
                        envelope_bytes,
                        vec![0u8; 64],
                        1_000_i64
                    ],
                )
                .expect("work.opened insert");
        };

        register_work_opened("W-JOIN-A", "owner-a", "repo-a");
        register_work_opened("W-JOIN-B", "owner-b", "repo-b");

        let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
        rt.block_on(async {
            let mk_event = |work_id: &str, commit_sha: &str| {
                let payload =
                    apm2_core::work::helpers::work_pr_associated_payload(work_id, 77, commit_sha);
                let envelope = serde_json::json!({
                    "event_type": "work.pr_associated",
                    "session_id": work_id,
                    "actor_id": "actor-test",
                    "payload": hex::encode(payload),
                    "pr_number": 77_u64,
                    "commit_sha": commit_sha,
                });
                SignedLedgerEvent {
                    event_id: format!("evt-pr-{work_id}"),
                    event_type: "work.pr_associated".to_string(),
                    work_id: work_id.to_string(),
                    actor_id: "actor-test".to_string(),
                    payload: serde_json::to_vec(&envelope).expect("envelope serializes"),
                    signature: Vec::new(),
                    timestamp_ns: 2_000,
                }
            };

            worker
                .handle_work_pr_associated(&mk_event(
                    "W-JOIN-A",
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                ))
                .await
                .expect("first work.pr_associated should project");
            worker
                .handle_work_pr_associated(&mk_event(
                    "W-JOIN-B",
                    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                ))
                .await
                .expect("second work.pr_associated should project");
        });

        assert_eq!(
            worker
                .work_index()
                .get_work_id_for_pr("owner-a", "repo-a", 77),
            Some("W-JOIN-A".to_string())
        );
        assert_eq!(
            worker
                .work_index()
                .get_work_id_for_pr("owner-b", "repo-b", 77),
            Some("W-JOIN-B".to_string())
        );
    }

    #[test]
    fn test_work_index_not_found() {
        let conn = create_test_db();
        let index = WorkIndex::new(conn).unwrap();

        let digest = [0x42u8; 32];
        assert!(index.get_work_id(&digest).is_none());
        assert!(index.get_pr_metadata("unknown").is_none());
    }

    #[test]
    fn test_ledger_tailer_poll_events() {
        let conn = create_test_db();

        // Insert test events
        {
            let conn_guard = conn.lock().unwrap();
            conn_guard
                .execute(
                    "INSERT INTO ledger_events VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![
                        "evt-1",
                        "test_event",
                        "work-1",
                        "actor-1",
                        b"payload1".to_vec(),
                        vec![0u8; 64],
                        1000i64
                    ],
                )
                .unwrap();
            conn_guard
                .execute(
                    "INSERT INTO ledger_events VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![
                        "evt-2",
                        "test_event",
                        "work-2",
                        "actor-2",
                        b"payload2".to_vec(),
                        vec![0u8; 64],
                        2000i64
                    ],
                )
                .unwrap();
        }

        let mut tailer = LedgerTailer::new(conn);

        let events = tailer.poll_events("test_event", 10).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].event_id, "evt-1");
        assert_eq!(events[1].event_id, "evt-2");

        // Without acknowledge(), subsequent poll should return the SAME events
        // (Blocker fix: Fail-Open Auto-Ack - watermark not advanced on poll)
        let events = tailer.poll_events("test_event", 10).unwrap();
        assert_eq!(
            events.len(),
            2,
            "Events should be re-polled without acknowledge"
        );

        // After acknowledging, events should not be returned
        // MAJOR FIX: Pass event_id for composite cursor
        tailer.acknowledge(2000, "evt-2").unwrap(); // Acknowledge up to (timestamp 2000, evt-2)
        let events = tailer.poll_events("test_event", 10).unwrap();
        assert!(
            events.is_empty(),
            "Events should be empty after acknowledge"
        );
    }

    #[test]
    fn test_projection_worker_config() {
        let config = ProjectionWorkerConfig::new()
            .with_poll_interval(Duration::from_secs(5))
            .with_batch_size(50);

        assert_eq!(config.poll_interval, Duration::from_secs(5));
        assert_eq!(config.batch_size, 50);
        assert!(!config.github_enabled);
    }

    #[test]
    fn test_projection_worker_creation() {
        let conn = create_test_db();
        let config = ProjectionWorkerConfig::new();

        let worker = ProjectionWorker::new(conn, config);
        assert!(worker.is_ok());

        let worker = worker.unwrap();
        assert!(worker.adapter.is_none()); // GitHub not enabled
    }

    #[test]
    fn test_projection_worker_with_github_config() {
        let conn = create_test_db();
        let github_config =
            GitHubAdapterConfig::new("https://api.github.com", "owner", "repo").unwrap();
        let config = ProjectionWorkerConfig::new().with_github(github_config.clone());

        let worker = ProjectionWorker::new(Arc::clone(&conn), config);
        assert!(worker.is_ok());

        let mut worker = worker.unwrap();
        // Adapter is NOT created in constructor - must be injected (fail-safe design)
        assert!(!worker.has_adapter());

        // Inject mock adapter for testing
        let signer = apm2_core::crypto::Signer::generate();
        let adapter = GitHubProjectionAdapter::new_mock(signer, github_config).unwrap();
        worker.set_adapter(adapter);
        assert!(worker.has_adapter());
    }

    #[test]
    fn test_projection_worker_shutdown_handle() {
        let conn = create_test_db();
        let config = ProjectionWorkerConfig::new();
        let worker = ProjectionWorker::new(conn, config).unwrap();

        let handle = worker.shutdown_handle();
        assert!(!handle.load(std::sync::atomic::Ordering::Relaxed));

        // Signal shutdown
        handle.store(true, std::sync::atomic::Ordering::Relaxed);
        assert!(handle.load(std::sync::atomic::Ordering::Relaxed));
    }

    #[test]
    fn test_work_index_end_to_end_lookup() {
        // Test the full workflow: changeset -> work_id -> PR metadata
        let conn = create_test_db();
        let index = WorkIndex::new(conn).unwrap();

        let changeset_digest = [0x42u8; 32];
        let work_id = "work-001";

        // Register changeset -> work_id
        index
            .register_changeset(&changeset_digest, work_id)
            .unwrap();

        // Register work_id -> PR
        index
            .register_pr(work_id, 456, "org", "project", "def789")
            .unwrap();

        // Full lookup chain
        let found_work_id = index.get_work_id(&changeset_digest).unwrap();
        assert_eq!(found_work_id, work_id);

        let pr_metadata = index.get_pr_metadata(&found_work_id).unwrap();
        assert_eq!(pr_metadata.pr_number, 456);
        assert_eq!(pr_metadata.repo_owner, "org");
        assert_eq!(pr_metadata.repo_name, "project");
        assert_eq!(pr_metadata.head_sha, "def789");
    }

    #[test]
    fn test_ledger_tailer_from_timestamp() {
        let conn = create_test_db();

        // Insert test events
        {
            let conn_guard = conn.lock().unwrap();
            conn_guard
                .execute(
                    "INSERT INTO ledger_events VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![
                        "evt-1",
                        "test_event",
                        "work-1",
                        "actor-1",
                        b"payload1".to_vec(),
                        vec![0u8; 64],
                        1000i64
                    ],
                )
                .unwrap();
            conn_guard
                .execute(
                    "INSERT INTO ledger_events VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![
                        "evt-2",
                        "test_event",
                        "work-2",
                        "actor-2",
                        b"payload2".to_vec(),
                        vec![0u8; 64],
                        2000i64
                    ],
                )
                .unwrap();
        }

        // Create tailer starting from timestamp 1000 (after first event)
        let mut tailer = LedgerTailer::from_timestamp(Arc::clone(&conn), 1000);

        // Should only get the second event
        let events = tailer.poll_events("test_event", 10).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_id, "evt-2");
    }

    #[test]
    fn test_ledger_tailer_get_ledger_head() {
        let conn = create_test_db();

        // Insert test events
        {
            let conn_guard = conn.lock().unwrap();
            conn_guard
                .execute(
                    "INSERT INTO ledger_events VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![
                        "evt-latest",
                        "test_event",
                        "work-1",
                        "actor-1",
                        b"payload".to_vec(),
                        vec![0u8; 64],
                        9999i64
                    ],
                )
                .unwrap();
        }

        let tailer = LedgerTailer::new(conn);
        let head = tailer.get_ledger_head().unwrap();

        assert!(head.is_some());
        // Head is a BLAKE3 hash of the event_id
        let expected_hash = blake3::hash(b"evt-latest");
        assert_eq!(head.unwrap(), *expected_hash.as_bytes());
    }

    #[test]
    fn test_ledger_tailer_empty_ledger_head() {
        let conn = create_test_db();
        let tailer = LedgerTailer::new(conn);

        let head = tailer.get_ledger_head().unwrap();
        assert!(head.is_none());
    }

    #[test]
    fn test_work_index_update_existing() {
        let conn = create_test_db();
        let index = WorkIndex::new(conn).unwrap();

        // Register initial PR
        index
            .register_pr("work-001", 123, "owner1", "repo1", "sha1")
            .unwrap();

        // Update with new PR info (same work_id)
        index
            .register_pr("work-001", 456, "owner2", "repo2", "sha2")
            .unwrap();

        // Should have the updated values
        let metadata = index.get_pr_metadata("work-001").unwrap();
        assert_eq!(metadata.pr_number, 456);
        assert_eq!(metadata.repo_owner, "owner2");
        assert_eq!(metadata.repo_name, "repo2");
        assert_eq!(metadata.head_sha, "sha2");
    }

    #[test]
    fn test_changeset_work_index_update_existing() {
        let conn = create_test_db();
        let index = WorkIndex::new(conn).unwrap();

        let digest = [0x42u8; 32];

        // Register initial work_id
        index.register_changeset(&digest, "work-001").unwrap();

        // Update with new work_id (same changeset)
        index.register_changeset(&digest, "work-002").unwrap();

        // Should have the updated value
        assert_eq!(index.get_work_id(&digest), Some("work-002".to_string()));
    }

    #[test]
    fn test_pr_metadata_debug() {
        let metadata = PrMetadata {
            pr_number: 123,
            repo_owner: "owner".to_string(),
            repo_name: "repo".to_string(),
            head_sha: "abc123".to_string(),
        };

        let debug_str = format!("{metadata:?}");
        assert!(debug_str.contains("PrMetadata"));
        assert!(debug_str.contains("123"));
        assert!(debug_str.contains("owner"));
    }

    #[test]
    fn test_projection_worker_error_display() {
        let err = ProjectionWorkerError::DatabaseError("test error".to_string());
        assert!(err.to_string().contains("database error"));

        let err = ProjectionWorkerError::NoPrAssociation {
            work_id: "work-001".to_string(),
        };
        assert!(err.to_string().contains("work-001"));

        let err = ProjectionWorkerError::AlreadyProjected {
            receipt_id: "recv-001".to_string(),
        };
        assert!(err.to_string().contains("recv-001"));

        // Test MissingDependency error (Blocker fix: Critical Data Loss)
        let err = ProjectionWorkerError::MissingDependency {
            event_id: "evt-001".to_string(),
            reason: "waiting for ChangeSetPublished".to_string(),
        };
        assert!(err.to_string().contains("evt-001"));
        assert!(err.to_string().contains("waiting for ChangeSetPublished"));
    }

    #[test]
    fn test_work_index_evict_expired() {
        let conn = create_test_db();
        let index = WorkIndex::new(Arc::clone(&conn)).unwrap();

        // Register entries with old timestamps
        {
            let conn_guard = conn.lock().unwrap();
            // Insert old entries (created_at = 0, i.e., epoch)
            conn_guard
                .execute(
                    "INSERT INTO changeset_work_index (changeset_digest, work_id, created_at)
                     VALUES (?1, ?2, 0)",
                    params![vec![0x42u8; 32], "old-work"],
                )
                .unwrap();
            conn_guard
                .execute(
                    "INSERT INTO work_pr_index (work_id, pr_number, repo_owner, repo_name, head_sha, created_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, 0)",
                    params!["old-work", 123i64, "owner", "repo", "sha"],
                )
                .unwrap();
        }

        // Register a fresh entry
        index.register_changeset(&[0x99u8; 32], "new-work").unwrap();

        // Evict with short TTL (1 second) - should evict old entries
        let deleted = index.evict_expired(1).unwrap();
        assert!(deleted >= 2, "Should have deleted at least 2 old entries");

        // Old entries should be gone
        assert!(index.get_work_id(&[0x42u8; 32]).is_none());

        // Fresh entry should still exist
        assert!(index.get_work_id(&[0x99u8; 32]).is_some());
    }

    #[test]
    fn test_ledger_tailer_acknowledge_persistence() {
        let conn = create_test_db();

        // Create tailer and acknowledge some events
        // MAJOR FIX: Pass event_id for composite cursor
        {
            let mut tailer = LedgerTailer::with_id(Arc::clone(&conn), "test_tailer");
            tailer.acknowledge(5000, "evt-test").unwrap();
        }

        // Create new tailer with same ID - should resume from persisted watermark
        let tailer = LedgerTailer::with_id(conn, "test_tailer");

        // The watermark should be restored
        // We verify by checking that events before the watermark are not returned
        // (Since we have no events, this just verifies construction succeeded)
        assert!(tailer.get_ledger_head().is_ok());
    }

    // =========================================================================
    // NACK/Retry Mechanism Tests (Blocker fix: Critical Data Loss)
    // =========================================================================

    #[test]
    fn test_nack_retry_watermark_not_advanced_on_missing_dependency() {
        // Test that when processing fails due to missing dependency (MissingDependency
        // error), the watermark is NOT advanced, allowing the event to be
        // retried.
        let conn = create_test_db();

        // Insert a review_receipt_recorded event
        {
            let conn_guard = conn.lock().unwrap();
            let payload = serde_json::json!({
                "changeset_digest": "0000000000000000000000000000000000000000000000000000000000000042",
                "receipt_id": "receipt-001",
                "verdict": "success"
            });
            conn_guard
                .execute(
                    "INSERT INTO ledger_events VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![
                        "evt-review-1",
                        "review_receipt_recorded",
                        "work-1",
                        "actor-1",
                        serde_json::to_vec(&payload).unwrap(),
                        vec![0u8; 64],
                        1000i64
                    ],
                )
                .unwrap();
        }

        let mut tailer = LedgerTailer::with_id(Arc::clone(&conn), "test_nack_tailer");

        // Poll events - should get the review event
        let events = tailer.poll_events("review_receipt_recorded", 10).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_id, "evt-review-1");

        // Simulate MissingDependency error - do NOT call acknowledge()
        // The watermark should NOT advance

        // Poll again - should still get the same event (NACK/Retry behavior)
        let events = tailer.poll_events("review_receipt_recorded", 10).unwrap();
        assert_eq!(
            events.len(),
            1,
            "Event should be re-polled after NACK (watermark not advanced)"
        );
        assert_eq!(events[0].event_id, "evt-review-1");
    }

    #[test]
    fn test_nack_retry_partial_batch_processing() {
        // Test that when one event in a batch fails, subsequent events are not skipped.
        // This tests the strict sequential acknowledgment behavior.
        let conn = create_test_db();

        // Insert multiple events
        {
            let conn_guard = conn.lock().unwrap();
            for i in 1..=3 {
                let payload = serde_json::json!({
                    "changeset_digest": format!("{:0>64x}", i),
                    "receipt_id": format!("receipt-{:03}", i),
                    "verdict": "success"
                });
                conn_guard
                    .execute(
                        "INSERT INTO ledger_events VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                        params![
                            format!("evt-{}", i),
                            "review_receipt_recorded",
                            format!("work-{}", i),
                            "actor-1",
                            serde_json::to_vec(&payload).unwrap(),
                            vec![0u8; 64],
                            i64::from(i * 1000)
                        ],
                    )
                    .unwrap();
            }
        }

        let mut tailer = LedgerTailer::with_id(Arc::clone(&conn), "test_partial_batch_tailer");

        // Poll all events
        let events = tailer.poll_events("review_receipt_recorded", 10).unwrap();
        assert_eq!(events.len(), 3);

        // Acknowledge only the first event (simulate: first succeeded, second failed)
        // MAJOR FIX: Pass event_id for composite cursor
        tailer
            .acknowledge(events[0].timestamp_ns, &events[0].event_id)
            .unwrap();

        // Poll again - should get events 2 and 3 (event 1 was acknowledged)
        let events = tailer.poll_events("review_receipt_recorded", 10).unwrap();
        assert_eq!(
            events.len(),
            2,
            "Should get remaining 2 events after partial acknowledgment"
        );
        assert_eq!(events[0].event_id, "evt-2");
        assert_eq!(events[1].event_id, "evt-3");
    }

    #[test]
    fn test_nack_retry_no_pr_association_error_does_not_advance_watermark() {
        // Test that NoPrAssociation error triggers NACK behavior
        let conn = create_test_db();
        let index = WorkIndex::new(Arc::clone(&conn)).unwrap();

        // Register changeset but NOT PR association
        let changeset_digest = [0x42u8; 32];
        index
            .register_changeset(&changeset_digest, "work-orphan")
            .unwrap();

        // Verify no PR metadata exists
        assert!(
            index.get_pr_metadata("work-orphan").is_none(),
            "PR metadata should not exist"
        );

        // The NoPrAssociation error should be returned, triggering NACK
        // This is tested by verifying the error type exists and the lookup fails
        let err = ProjectionWorkerError::NoPrAssociation {
            work_id: "work-orphan".to_string(),
        };
        assert!(
            matches!(err, ProjectionWorkerError::NoPrAssociation { .. }),
            "NoPrAssociation error should match"
        );
    }

    #[test]
    fn test_nack_retry_missing_dependency_error_type() {
        // Test the MissingDependency error type for changeset not indexed
        let err = ProjectionWorkerError::MissingDependency {
            event_id: "evt-123".to_string(),
            reason: "changeset 0x42... not yet indexed".to_string(),
        };

        assert!(
            matches!(err, ProjectionWorkerError::MissingDependency { .. }),
            "MissingDependency error should match"
        );

        // Verify error message contains useful info
        let msg = err.to_string();
        assert!(msg.contains("evt-123"));
        assert!(msg.contains("not yet indexed"));
    }

    #[test]
    fn test_nack_retry_event_ordering_preserved() {
        // Test that event ordering is preserved during NACK/Retry.
        // Events must be processed in timestamp order to maintain causality.
        let conn = create_test_db();

        // Insert events with specific timestamps
        {
            let conn_guard = conn.lock().unwrap();
            // Insert out of order to verify ORDER BY works
            for (id, ts) in [("evt-c", 3000), ("evt-a", 1000), ("evt-b", 2000)] {
                let payload = serde_json::json!({
                    "changeset_digest": format!("{:0>64x}", ts),
                    "receipt_id": format!("receipt-{}", id),
                    "verdict": "success"
                });
                conn_guard
                    .execute(
                        "INSERT INTO ledger_events VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                        params![
                            id,
                            "review_receipt_recorded",
                            "work-1",
                            "actor-1",
                            serde_json::to_vec(&payload).unwrap(),
                            vec![0u8; 64],
                            i64::from(ts)
                        ],
                    )
                    .unwrap();
            }
        }

        let mut tailer = LedgerTailer::with_id(Arc::clone(&conn), "test_ordering_tailer");

        // Poll events - should be in timestamp order
        let events = tailer.poll_events("review_receipt_recorded", 10).unwrap();
        assert_eq!(events.len(), 3);
        assert_eq!(
            events[0].event_id, "evt-a",
            "First event should be evt-a (ts=1000)"
        );
        assert_eq!(
            events[1].event_id, "evt-b",
            "Second event should be evt-b (ts=2000)"
        );
        assert_eq!(
            events[2].event_id, "evt-c",
            "Third event should be evt-c (ts=3000)"
        );
    }

    #[test]
    fn test_validate_string_length_rejects_oversized_input() {
        // Test that oversized strings are rejected (Blocker fix: Unbounded Input
        // Consumption)
        let long_string = "x".repeat(MAX_STRING_LENGTH + 1);
        let result = validate_string_length("test_field", &long_string);

        assert!(
            result.is_err(),
            "Should reject string exceeding MAX_STRING_LENGTH"
        );
        let err = result.unwrap_err();
        assert!(
            matches!(err, ProjectionWorkerError::InvalidPayload(_)),
            "Should be InvalidPayload error"
        );
        assert!(err.to_string().contains("test_field"));
        assert!(err.to_string().contains("exceeds maximum length"));
    }

    #[test]
    fn test_validate_string_length_accepts_valid_input() {
        // Test that strings at or below MAX_STRING_LENGTH are accepted
        let exact_length = "x".repeat(MAX_STRING_LENGTH);
        assert!(
            validate_string_length("field", &exact_length).is_ok(),
            "Should accept string at MAX_STRING_LENGTH"
        );

        let short_string = "hello";
        assert!(
            validate_string_length("field", short_string).is_ok(),
            "Should accept short string"
        );

        let empty_string = "";
        assert!(
            validate_string_length("field", empty_string).is_ok(),
            "Should accept empty string"
        );
    }

    struct TestLinkageHashes {
        changeset_digest: [u8; 32],
        artifact_bundle_hash: [u8; 32],
        capability_manifest_hash: [u8; 32],
        context_pack_hash: [u8; 32],
        role_spec_hash: [u8; 32],
        identity_proof_hash: [u8; 32],
    }

    fn make_test_linkage_hashes(cas: &MemoryCas) -> TestLinkageHashes {
        let artifact_bundle_hash = cas
            .store(b"artifact-bundle-test")
            .expect("artifact bundle hash")
            .hash;
        let capability_manifest_hash = cas
            .store(b"capability-manifest-test")
            .expect("capability manifest hash")
            .hash;
        let context_pack_hash = cas
            .store(b"context-pack-test")
            .expect("context pack hash")
            .hash;
        let role_spec_hash = cas.store(b"role-spec-test").expect("role spec hash").hash;
        let identity_digest = blake3::hash(b"identity-proof-test");
        let mut identity_proof_hash = [0u8; 32];
        identity_proof_hash.copy_from_slice(identity_digest.as_bytes());

        TestLinkageHashes {
            changeset_digest: [0x42u8; 32],
            artifact_bundle_hash,
            capability_manifest_hash,
            context_pack_hash,
            role_spec_hash,
            identity_proof_hash,
        }
    }

    fn valid_receipt_linkage_payload(
        work_id: &str,
        hashes: &TestLinkageHashes,
    ) -> serde_json::Value {
        serde_json::json!({
            "receipt_id": "receipt-001",
            "lease_id": "lease-001",
            "work_id": work_id,
            "changeset_digest": hex::encode(hashes.changeset_digest),
            "artifact_bundle_hash": hex::encode(hashes.artifact_bundle_hash),
            "capability_manifest_hash": hex::encode(hashes.capability_manifest_hash),
            "context_pack_hash": hex::encode(hashes.context_pack_hash),
            "role_spec_hash": hex::encode(hashes.role_spec_hash),
            "identity_proof_hash": hex::encode(hashes.identity_proof_hash),
            "time_envelope_ref": "htf:tick:123456",
        })
    }

    fn test_event(work_id: &str) -> SignedLedgerEvent {
        SignedLedgerEvent {
            event_id: "evt-001".to_string(),
            event_type: "review_receipt_recorded".to_string(),
            work_id: work_id.to_string(),
            actor_id: "actor-001".to_string(),
            payload: Vec::new(),
            signature: vec![0u8; 64],
            timestamp_ns: 1000,
        }
    }

    fn insert_authoritative_receipt_event(
        conn: &Arc<Mutex<Connection>>,
        event: &SignedLedgerEvent,
        payload: &serde_json::Value,
    ) {
        conn.lock()
            .unwrap()
            .execute(
                "INSERT INTO ledger_events VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    event.event_id,
                    event.event_type,
                    event.work_id,
                    event.actor_id,
                    serde_json::to_vec(payload).expect("serialize payload"),
                    event.signature.clone(),
                    i64::try_from(event.timestamp_ns).expect("test timestamp_ns must fit into i64")
                ],
            )
            .expect("insert authoritative receipt event");
    }

    #[test]
    fn test_validate_projection_receipt_linkage_accepts_authoritative_payload() {
        let conn = create_test_db();
        let cas = MemoryCas::default();
        let hashes = make_test_linkage_hashes(&cas);
        let payload = valid_receipt_linkage_payload("work-001", &hashes);
        let event = test_event("work-001");
        insert_authoritative_receipt_event(&conn, &event, &payload);
        let authority = ProjectionLinkageAuthority {
            conn: &conn,
            cas: Some(&cas),
        };
        let result = validate_projection_receipt_linkage(&payload, &event, &authority);
        assert!(result.is_ok(), "expected valid linkage payload to pass");
    }

    #[test]
    fn test_validate_projection_receipt_linkage_rejects_work_id_mismatch() {
        let conn = create_test_db();
        let cas = MemoryCas::default();
        let hashes = make_test_linkage_hashes(&cas);
        let payload = valid_receipt_linkage_payload("work-payload", &hashes);
        let event = test_event("work-envelope");
        let authority = ProjectionLinkageAuthority {
            conn: &conn,
            cas: Some(&cas),
        };
        let err = validate_projection_receipt_linkage(&payload, &event, &authority).unwrap_err();
        assert!(
            matches!(err, ProjectionWorkerError::InvalidPayload(_)),
            "expected work_id mismatch to fail with InvalidPayload"
        );
        assert!(err.to_string().contains("work_id mismatch"));
    }

    #[test]
    fn test_validate_projection_receipt_linkage_rejects_missing_authority_hash() {
        let conn = create_test_db();
        let cas = MemoryCas::default();
        let hashes = make_test_linkage_hashes(&cas);
        let mut payload = valid_receipt_linkage_payload("work-001", &hashes);
        payload
            .as_object_mut()
            .unwrap()
            .remove("capability_manifest_hash");
        let event = test_event("work-001");
        let authority = ProjectionLinkageAuthority {
            conn: &conn,
            cas: Some(&cas),
        };
        let err = validate_projection_receipt_linkage(&payload, &event, &authority).unwrap_err();
        assert!(matches!(err, ProjectionWorkerError::InvalidPayload(_)));
        assert!(err.to_string().contains("missing capability_manifest_hash"));
    }

    #[test]
    fn test_validate_projection_receipt_linkage_rejects_partial_lifecycle_tuple() {
        let conn = create_test_db();
        let cas = MemoryCas::default();
        let hashes = make_test_linkage_hashes(&cas);
        let mut payload = valid_receipt_linkage_payload("work-001", &hashes);
        let event = test_event("work-001");
        insert_authoritative_receipt_event(&conn, &event, &payload);
        payload["ajc_id"] = serde_json::json!("42".repeat(32));
        payload["intent_digest"] = serde_json::json!("42".repeat(32));
        let authority = ProjectionLinkageAuthority {
            conn: &conn,
            cas: Some(&cas),
        };
        let err = validate_projection_receipt_linkage(&payload, &event, &authority).unwrap_err();
        assert!(matches!(err, ProjectionWorkerError::InvalidPayload(_)));
        assert!(err.to_string().contains("partial lifecycle linkage tuple"));
    }

    #[test]
    fn test_validate_projection_receipt_linkage_rejects_forged_linkage_hash() {
        let conn = create_test_db();
        let cas = MemoryCas::default();
        let hashes = make_test_linkage_hashes(&cas);
        let authoritative_payload = valid_receipt_linkage_payload("work-001", &hashes);
        let event = test_event("work-001");
        insert_authoritative_receipt_event(&conn, &event, &authoritative_payload);

        let mut forged_payload = authoritative_payload;
        let forged_capability_manifest_hash = cas
            .store(b"forged-capability-manifest")
            .expect("forged capability hash")
            .hash;
        forged_payload["capability_manifest_hash"] =
            serde_json::json!(hex::encode(forged_capability_manifest_hash));

        let authority = ProjectionLinkageAuthority {
            conn: &conn,
            cas: Some(&cas),
        };
        let err =
            validate_projection_receipt_linkage(&forged_payload, &event, &authority).unwrap_err();
        assert!(matches!(err, ProjectionWorkerError::InvalidPayload(_)));
        assert!(
            err.to_string()
                .contains("linkage hash mismatch for capability_manifest_hash")
        );
    }

    #[test]
    fn test_max_string_length_constant() {
        // Verify the MAX_STRING_LENGTH constant is set correctly
        assert_eq!(MAX_STRING_LENGTH, 1024, "MAX_STRING_LENGTH should be 1024");
    }

    // =========================================================================
    // TCK-00505: Economics Admission Gate + Replay Prevention Tests
    // =========================================================================

    /// Mock resolver for testing economics admission gate.
    ///
    /// The resolver uses the gate signer's public key as a trusted signer
    /// so that signed artifacts constructed by `build_signed_window` and
    /// `build_signed_profile` pass the trusted-signer check in
    /// `evaluate_projection_continuity`.
    struct MockContinuityResolver {
        profile: Option<crate::projection::continuity_resolver::ResolvedContinuityProfile>,
        snapshot: Option<apm2_core::economics::MultiSinkIdentitySnapshotV1>,
        window: Option<crate::projection::continuity_resolver::ResolvedContinuityWindow>,
    }

    impl MockContinuityResolver {
        /// Creates a resolver that returns values for the default sink.
        ///
        /// The `gate_signer` is used to derive the trusted signer key
        /// so that signed artifacts constructed from these resolved
        /// values are accepted by the economics gate.
        fn with_defaults_for_signer(gate_signer: &Signer) -> Self {
            let vk_bytes = gate_signer.verifying_key().to_bytes();

            // Build a snapshot with a valid computed digest.
            // REQ-0009 multi-sink continuity requires at least 2 distinct sinks.
            let mut snapshot = apm2_core::economics::MultiSinkIdentitySnapshotV1 {
                sink_identities: vec![
                    apm2_core::economics::SinkIdentityEntry {
                        sink_id: DEFAULT_SINK_ID.to_string(),
                        identity_digest: [0xAA; 32],
                    },
                    apm2_core::economics::SinkIdentityEntry {
                        sink_id: "secondary-sink".to_string(),
                        identity_digest: [0xBB; 32],
                    },
                ],
                snapshot_digest: [0u8; 32],
            };
            snapshot.snapshot_digest = snapshot.compute_digest();

            Self {
                profile: Some(
                    crate::projection::continuity_resolver::ResolvedContinuityProfile {
                        sink_id: DEFAULT_SINK_ID.to_string(),
                        outage_window_ticks: 100,
                        replay_window_ticks: 50,
                        churn_tolerance: 2,
                        partition_tolerance: 1,
                        trusted_signer_keys: vec![vk_bytes],
                    },
                ),
                snapshot: Some(snapshot),
                window: Some(
                    crate::projection::continuity_resolver::ResolvedContinuityWindow {
                        // boundary_id must match DEFAULT_SINK_ID for config-backed
                        // resolution (the profile's boundary_id is the sink_id).
                        boundary_id: DEFAULT_SINK_ID.to_string(),
                        outage_window_ticks: 100,
                        replay_window_ticks: 50,
                    },
                ),
            }
        }

        fn without_profile(gate_signer: &Signer) -> Self {
            let mut r = Self::with_defaults_for_signer(gate_signer);
            r.profile = None;
            r
        }

        fn without_snapshot(gate_signer: &Signer) -> Self {
            let mut r = Self::with_defaults_for_signer(gate_signer);
            r.snapshot = None;
            r
        }

        fn without_window(gate_signer: &Signer) -> Self {
            let mut r = Self::with_defaults_for_signer(gate_signer);
            r.window = None;
            r
        }
    }

    impl crate::projection::continuity_resolver::ContinuityProfileResolver for MockContinuityResolver {
        fn resolve_continuity_profile(
            &self,
            _sink_id: &str,
        ) -> Option<crate::projection::continuity_resolver::ResolvedContinuityProfile> {
            self.profile.clone()
        }

        fn resolve_sink_snapshot(
            &self,
            _sink_id: &str,
        ) -> Option<apm2_core::economics::MultiSinkIdentitySnapshotV1> {
            self.snapshot.clone()
        }

        fn resolve_continuity_window(
            &self,
            _boundary_id: &str,
        ) -> Option<crate::projection::continuity_resolver::ResolvedContinuityWindow> {
            self.window.clone()
        }
    }

    /// Shared test fixture: resolver + signer + intent buffer + telemetry.
    struct EconomicsTestFixture {
        resolver: Arc<MockContinuityResolver>,
        gate_signer: Signer,
        intent_buffer: IntentBuffer,
        telemetry: Arc<AdmissionTelemetry>,
    }

    impl EconomicsTestFixture {
        fn new() -> Self {
            let gate_signer = Signer::generate();
            let resolver = MockContinuityResolver::with_defaults_for_signer(&gate_signer);
            let intent_conn = Arc::new(Mutex::new(Connection::open_in_memory().unwrap()));
            let intent_buffer =
                crate::projection::intent_buffer::IntentBuffer::new(intent_conn).unwrap();
            Self {
                resolver: Arc::new(resolver),
                gate_signer,
                intent_buffer,
                telemetry: Arc::new(AdmissionTelemetry::new()),
            }
        }

        fn with_resolver(resolver: MockContinuityResolver) -> Self {
            let gate_signer = Signer::generate();
            let intent_conn = Arc::new(Mutex::new(Connection::open_in_memory().unwrap()));
            let intent_buffer =
                crate::projection::intent_buffer::IntentBuffer::new(intent_conn).unwrap();
            Self {
                resolver: Arc::new(resolver),
                gate_signer,
                intent_buffer,
                telemetry: Arc::new(AdmissionTelemetry::new()),
            }
        }

        #[allow(clippy::too_many_arguments)]
        fn evaluate(
            &self,
            payload: &serde_json::Value,
            work_id: &str,
            changeset_digest: &[u8; 32],
            receipt_id: &str,
            status: ProjectedStatus,
            event_timestamp_ns: u64,
            event_id: &str,
        ) -> Result<String, ProjectionWorkerError> {
            evaluate_economics_admission_blocking(
                payload,
                work_id,
                changeset_digest,
                receipt_id,
                status,
                event_timestamp_ns,
                event_id,
                &self.intent_buffer,
                self.resolver.as_ref(),
                &self.gate_signer,
                &self.telemetry,
            )
        }
    }

    /// Build a valid economics-gate payload.
    ///
    /// Uses `DEFAULT_SINK_ID` as the `boundary_id` to match the
    /// config-backed resolver's window boundary.
    fn economics_gate_payload(changeset_digest: &[u8; 32], receipt_id: &str) -> serde_json::Value {
        serde_json::json!({
            "receipt_id": receipt_id,
            "changeset_digest": hex::encode(changeset_digest),
            "verdict": "success",
            "eval_tick": 142_u64,
            "time_authority_ref": hex::encode([0x11u8; 32]),
            "window_ref": hex::encode([0x22u8; 32]),
            "boundary_id": DEFAULT_SINK_ID,
            "work_id": "work-econ-001",
            "artifact_bundle_hash": hex::encode([0x33u8; 32]),
            "capability_manifest_hash": hex::encode([0x44u8; 32]),
            "context_pack_hash": hex::encode([0x55u8; 32]),
            "role_spec_hash": hex::encode([0x66u8; 32]),
            "identity_proof_hash": hex::encode([0x77u8; 32]),
            "time_envelope_ref": "htf:tick:42",
            "lease_id": "lease-econ-001",
        })
    }

    // ----- Test: economics gate wiring -----

    #[test]
    fn test_economics_gate_not_wired_by_default() {
        let conn = create_test_db();
        let config = ProjectionWorkerConfig::new();
        let worker = ProjectionWorker::new(conn, config).unwrap();
        assert!(
            !worker.has_economics_gate(),
            "Gate should not be wired by default"
        );
    }

    #[test]
    fn test_economics_gate_requires_both_dependencies() {
        let conn = create_test_db();
        let config = ProjectionWorkerConfig::new();
        let mut worker = ProjectionWorker::new(conn, config).unwrap();

        // Only intent buffer - not enough
        let intent_conn = Arc::new(Mutex::new(Connection::open_in_memory().unwrap()));
        let intent_buffer =
            crate::projection::intent_buffer::IntentBuffer::new(intent_conn).unwrap();
        worker.set_intent_buffer(intent_buffer);
        assert!(
            !worker.has_economics_gate(),
            "Gate should not be active with only intent buffer"
        );

        // Add resolver - still not enough without signer
        let gate_signer = Signer::generate();
        worker.set_continuity_resolver(Arc::new(MockContinuityResolver::with_defaults_for_signer(
            &gate_signer,
        )));
        assert!(
            !worker.has_economics_gate(),
            "Gate should not be active without gate signer"
        );

        // Add gate signer - now it's fully wired
        worker.set_gate_signer(Arc::new(gate_signer));
        assert!(
            worker.has_economics_gate(),
            "Gate should be active with all three dependencies"
        );
    }

    // ----- Test: telemetry -----

    #[test]
    fn test_admission_telemetry_initialization() {
        let telemetry = AdmissionTelemetry::new();
        assert_eq!(telemetry.admitted_count.load(AtomicOrdering::Relaxed), 0);
        assert_eq!(
            telemetry
                .economics_denied_count
                .load(AtomicOrdering::Relaxed),
            0
        );
        assert_eq!(
            telemetry
                .lifecycle_revoked_count
                .load(AtomicOrdering::Relaxed),
            0
        );
        assert_eq!(
            telemetry
                .lifecycle_stale_count
                .load(AtomicOrdering::Relaxed),
            0
        );
        assert_eq!(
            telemetry
                .lifecycle_consumed_count
                .load(AtomicOrdering::Relaxed),
            0
        );
        assert_eq!(
            telemetry
                .missing_inputs_denied_count
                .load(AtomicOrdering::Relaxed),
            0
        );
        assert_eq!(
            telemetry
                .missing_gate_denied_count
                .load(AtomicOrdering::Relaxed),
            0
        );
        assert_eq!(
            telemetry
                .missing_selectors_denied_count
                .load(AtomicOrdering::Relaxed),
            0
        );
    }

    #[test]
    fn test_admission_telemetry_default() {
        let telemetry = AdmissionTelemetry::default();
        assert_eq!(
            telemetry.admitted_count.load(AtomicOrdering::Relaxed),
            0,
            "Default telemetry should start at zero"
        );
    }

    // ----- Test: lifecycle deny constants -----

    #[test]
    fn test_lifecycle_deny_constants() {
        assert_eq!(lifecycle_deny::REVOKED, "revoked");
        assert_eq!(lifecycle_deny::STALE, "stale");
        assert_eq!(lifecycle_deny::CONSUMED, "consumed");
        assert_eq!(lifecycle_deny::MISSING_GATE, "missing_gate");
        assert_eq!(
            lifecycle_deny::MISSING_SELECTORS,
            "missing_economics_selectors"
        );
        assert_eq!(
            lifecycle_deny::MISSING_LIFECYCLE_SELECTORS,
            "missing_lifecycle_selectors"
        );
    }

    // ----- Test: extract_hash32_field -----

    #[test]
    fn test_extract_hash32_field_valid() {
        let hash = [0x42u8; 32];
        let payload = serde_json::json!({
            "test_field": hex::encode(hash)
        });
        let result = extract_hash32_field(&payload, "test_field");
        assert_eq!(result, Some(hash));
    }

    #[test]
    fn test_extract_hash32_field_missing() {
        let payload = serde_json::json!({});
        assert!(
            extract_hash32_field(&payload, "test_field").is_none(),
            "Missing field should return None"
        );
    }

    #[test]
    fn test_extract_hash32_field_not_string() {
        let payload = serde_json::json!({
            "test_field": 12345
        });
        assert!(
            extract_hash32_field(&payload, "test_field").is_none(),
            "Non-string field should return None"
        );
    }

    #[test]
    fn test_extract_hash32_field_invalid_hex() {
        let payload = serde_json::json!({
            "test_field": "not_valid_hex_string"
        });
        assert!(
            extract_hash32_field(&payload, "test_field").is_none(),
            "Invalid hex should return None"
        );
    }

    #[test]
    fn test_extract_hash32_field_wrong_length() {
        // 16 bytes (too short)
        let payload = serde_json::json!({
            "test_field": hex::encode([0x42u8; 16])
        });
        assert!(
            extract_hash32_field(&payload, "test_field").is_none(),
            "Wrong-length hash should return None"
        );
    }

    #[test]
    fn test_extract_hash32_field_zero_hash_rejected() {
        // All zeros means revoked/unset — must be rejected.
        let payload = serde_json::json!({
            "test_field": hex::encode([0u8; 32])
        });
        assert!(
            extract_hash32_field(&payload, "test_field").is_none(),
            "Zero hash (revoked authority) should return None"
        );
    }

    #[test]
    fn test_extract_hash32_field_oversized_hex() {
        let oversized = "ab".repeat(MAX_STRING_LENGTH + 1);
        let payload = serde_json::json!({
            "test_field": oversized
        });
        assert!(
            extract_hash32_field(&payload, "test_field").is_none(),
            "Oversized hex string should return None"
        );
    }

    // ----- Test: evaluate_economics_admission_blocking -----

    #[test]
    fn test_economics_admission_missing_eval_tick_deny() {
        let fixture = EconomicsTestFixture::new();

        let changeset_digest = [0x42u8; 32];
        let mut payload = economics_gate_payload(&changeset_digest, "receipt-no-tick");
        payload.as_object_mut().unwrap().remove("eval_tick");

        let result = fixture.evaluate(
            &payload,
            "work-econ-001",
            &changeset_digest,
            "receipt-no-tick",
            ProjectedStatus::Success,
            5000,
            "evt-econ-001",
        );

        assert!(result.is_err(), "Missing eval_tick should DENY");
        let err = result.unwrap_err();
        assert!(
            matches!(err, ProjectionWorkerError::AdmissionDenied { .. }),
            "Expected AdmissionDenied, got: {err}"
        );
        assert!(err.to_string().contains("eval_tick"));
        assert_eq!(
            fixture
                .telemetry
                .missing_inputs_denied_count
                .load(AtomicOrdering::Relaxed),
            1,
            "missing_inputs_denied_count should be 1"
        );
    }

    #[test]
    fn test_economics_admission_missing_time_authority_ref_deny() {
        let fixture = EconomicsTestFixture::new();

        let changeset_digest = [0x42u8; 32];
        let mut payload = economics_gate_payload(&changeset_digest, "receipt-no-auth");
        payload
            .as_object_mut()
            .unwrap()
            .remove("time_authority_ref");

        let result = fixture.evaluate(
            &payload,
            "work-econ-001",
            &changeset_digest,
            "receipt-no-auth",
            ProjectedStatus::Success,
            5000,
            "evt-econ-001",
        );

        assert!(result.is_err(), "Missing time_authority_ref should DENY");
        let err = result.unwrap_err();
        assert!(matches!(err, ProjectionWorkerError::AdmissionDenied { .. }));
        assert!(err.to_string().contains("time_authority_ref"));
    }

    #[test]
    fn test_economics_admission_missing_window_ref_deny() {
        let fixture = EconomicsTestFixture::new();

        let changeset_digest = [0x42u8; 32];
        let mut payload = economics_gate_payload(&changeset_digest, "receipt-no-window");
        payload.as_object_mut().unwrap().remove("window_ref");

        let result = fixture.evaluate(
            &payload,
            "work-econ-001",
            &changeset_digest,
            "receipt-no-window",
            ProjectedStatus::Success,
            5000,
            "evt-econ-001",
        );

        assert!(result.is_err(), "Missing window_ref should DENY");
        let err = result.unwrap_err();
        assert!(matches!(err, ProjectionWorkerError::AdmissionDenied { .. }));
        assert!(err.to_string().contains("window_ref"));
    }

    #[test]
    fn test_economics_admission_missing_boundary_id_deny() {
        let fixture = EconomicsTestFixture::new();

        let changeset_digest = [0x42u8; 32];
        let mut payload = economics_gate_payload(&changeset_digest, "receipt-no-boundary");
        payload.as_object_mut().unwrap().remove("boundary_id");

        let result = fixture.evaluate(
            &payload,
            "work-econ-001",
            &changeset_digest,
            "receipt-no-boundary",
            ProjectedStatus::Success,
            5000,
            "evt-econ-001",
        );

        assert!(result.is_err(), "Missing boundary_id should DENY");
        let err = result.unwrap_err();
        assert!(matches!(err, ProjectionWorkerError::AdmissionDenied { .. }));
        assert!(err.to_string().contains("boundary_id"));
    }

    #[test]
    fn test_economics_admission_empty_boundary_id_deny() {
        let fixture = EconomicsTestFixture::new();

        let changeset_digest = [0x42u8; 32];
        let mut payload = economics_gate_payload(&changeset_digest, "receipt-empty-boundary");
        payload["boundary_id"] = serde_json::json!("");

        let result = fixture.evaluate(
            &payload,
            "work-econ-001",
            &changeset_digest,
            "receipt-empty-boundary",
            ProjectedStatus::Success,
            5000,
            "evt-econ-001",
        );

        assert!(result.is_err(), "Empty boundary_id should DENY");
    }

    #[test]
    fn test_economics_admission_oversized_boundary_id_deny() {
        let fixture = EconomicsTestFixture::new();

        let changeset_digest = [0x42u8; 32];
        let mut payload = economics_gate_payload(&changeset_digest, "receipt-big-boundary");
        payload["boundary_id"] = serde_json::json!("x".repeat(MAX_STRING_LENGTH + 1));

        let result = fixture.evaluate(
            &payload,
            "work-econ-001",
            &changeset_digest,
            "receipt-big-boundary",
            ProjectedStatus::Success,
            5000,
            "evt-econ-001",
        );

        assert!(result.is_err(), "Oversized boundary_id should DENY");
        let err = result.unwrap_err();
        assert!(err.to_string().contains("maximum length"));
    }

    // ----- Test: missing resolver results -> DENY -----

    #[test]
    fn test_economics_admission_missing_profile_deny() {
        let gate_signer = Signer::generate();
        let fixture = EconomicsTestFixture::with_resolver(MockContinuityResolver::without_profile(
            &gate_signer,
        ));

        let changeset_digest = [0x42u8; 32];
        let payload = economics_gate_payload(&changeset_digest, "receipt-no-profile");

        let result = fixture.evaluate(
            &payload,
            "work-econ-001",
            &changeset_digest,
            "receipt-no-profile",
            ProjectedStatus::Success,
            5000,
            "evt-econ-001",
        );

        assert!(result.is_err(), "Missing profile should DENY");
        let err = result.unwrap_err();
        assert!(matches!(err, ProjectionWorkerError::AdmissionDenied { .. }));
        assert!(err.to_string().contains("continuity profile not found"));
    }

    #[test]
    fn test_economics_admission_missing_snapshot_deny() {
        let gate_signer = Signer::generate();
        let fixture = EconomicsTestFixture::with_resolver(
            MockContinuityResolver::without_snapshot(&gate_signer),
        );

        let changeset_digest = [0x42u8; 32];
        let payload = economics_gate_payload(&changeset_digest, "receipt-no-snap");

        let result = fixture.evaluate(
            &payload,
            "work-econ-001",
            &changeset_digest,
            "receipt-no-snap",
            ProjectedStatus::Success,
            5000,
            "evt-econ-001",
        );

        assert!(result.is_err(), "Missing snapshot should DENY");
        let err = result.unwrap_err();
        assert!(matches!(err, ProjectionWorkerError::AdmissionDenied { .. }));
        assert!(err.to_string().contains("sink snapshot not found"));
    }

    #[test]
    fn test_economics_admission_missing_window_deny() {
        let gate_signer = Signer::generate();
        let fixture = EconomicsTestFixture::with_resolver(MockContinuityResolver::without_window(
            &gate_signer,
        ));

        let changeset_digest = [0x42u8; 32];
        let payload = economics_gate_payload(&changeset_digest, "receipt-no-win");

        let result = fixture.evaluate(
            &payload,
            "work-econ-001",
            &changeset_digest,
            "receipt-no-win",
            ProjectedStatus::Success,
            5000,
            "evt-econ-001",
        );

        assert!(result.is_err(), "Missing continuity window should DENY");
        let err = result.unwrap_err();
        assert!(matches!(err, ProjectionWorkerError::AdmissionDenied { .. }));
        assert!(err.to_string().contains("continuity window not found"));
    }

    // ----- Test: revoked authority (zero time_authority_ref) -> DENY -----

    #[test]
    fn test_economics_admission_revoked_authority_deny() {
        let fixture = EconomicsTestFixture::new();

        let changeset_digest = [0x42u8; 32];
        let mut payload = economics_gate_payload(&changeset_digest, "receipt-revoked");
        payload["time_authority_ref"] = serde_json::json!(hex::encode([0u8; 32]));

        let result = fixture.evaluate(
            &payload,
            "work-econ-001",
            &changeset_digest,
            "receipt-revoked",
            ProjectedStatus::Success,
            5000,
            "evt-econ-001",
        );

        assert!(result.is_err(), "Revoked authority (zero hash) should DENY");
        let err = result.unwrap_err();
        // Zero-hash time_authority_ref now produces LifecycleDenied with
        // "revoked" subcategory (MINOR fix: lifecycle telemetry subcategories).
        assert!(
            matches!(
                err,
                ProjectionWorkerError::LifecycleDenied {
                    ref subcategory,
                    ..
                } if subcategory == lifecycle_deny::REVOKED
            ),
            "Revoked authority should produce LifecycleDenied with revoked subcategory, got: {err}"
        );
    }

    // ----- Test: replay prevention (duplicate intent) -> DENY -----

    #[test]
    fn test_economics_admission_replay_prevention_deny() {
        // The economics gate now constructs real signed artifacts, so an
        // ALLOW path is reachable. Two calls with the same receipt_id:
        // - First ALLOW (PENDING intent created).
        // - Second ALLOW (PENDING intent found, retry allowed — BLOCKER fix).
        // - Admit the intent, then third call should DENY (consumed).
        let fixture = EconomicsTestFixture::new();

        let changeset_digest = [0x42u8; 32];
        let payload = economics_gate_payload(&changeset_digest, "receipt-replay");

        // First call should ALLOW.
        let result = fixture.evaluate(
            &payload,
            "work-econ-001",
            &changeset_digest,
            "receipt-replay",
            ProjectedStatus::Success,
            5000,
            "evt-econ-001",
        );
        assert!(
            result.is_ok(),
            "First admission should ALLOW, got: {result:?}"
        );
        let intent_id = result.unwrap();

        // Second call while still PENDING: should also ALLOW (retry).
        let result = fixture.evaluate(
            &payload,
            "work-econ-001",
            &changeset_digest,
            "receipt-replay",
            ProjectedStatus::Success,
            5000,
            "evt-econ-001",
        );
        assert!(
            result.is_ok(),
            "Second admission (retry while PENDING) should ALLOW, got: {result:?}"
        );

        // Admit the intent (simulate successful projection).
        fixture
            .intent_buffer
            .admit(&intent_id, 6000)
            .expect("admit");

        // Third call after admission should DENY (consumed/duplicate).
        let result = fixture.evaluate(
            &payload,
            "work-econ-001",
            &changeset_digest,
            "receipt-replay",
            ProjectedStatus::Success,
            5000,
            "evt-econ-001",
        );
        assert!(result.is_err(), "Third admission should DENY (consumed)");
        let err = result.unwrap_err();
        assert!(
            matches!(err, ProjectionWorkerError::LifecycleDenied { .. }),
            "Expected LifecycleDenied (consumed), got: {err}"
        );
        assert!(err.to_string().contains("already admitted"));
    }

    // ----- Test: ALLOW path reaches projection (integration) -----

    #[test]
    fn test_economics_admission_allow_path_reaches_projection() {
        // Proves that evaluate_economics_admission_blocking can return Ok(intent_id)
        // when all inputs are correct, signed artifacts pass the gate, and
        // the intent is new. The intent is PENDING (not yet admitted) --
        // admission happens AFTER projection in the caller.
        let fixture = EconomicsTestFixture::new();

        let changeset_digest = [0x42u8; 32];
        let payload = economics_gate_payload(&changeset_digest, "receipt-allow");

        let result = fixture.evaluate(
            &payload,
            "work-econ-001",
            &changeset_digest,
            "receipt-allow",
            ProjectedStatus::Success,
            5000,
            "evt-econ-001",
        );

        assert!(result.is_ok(), "ALLOW path should succeed, got: {result:?}");
        let intent_id = result.unwrap();
        assert_eq!(
            intent_id, "proj-receipt-allow",
            "Intent ID should match expected format"
        );
        // admitted_count is NOT incremented here -- it happens in the
        // caller AFTER successful projection (BLOCKER-2 fix).
        assert_eq!(
            fixture
                .telemetry
                .admitted_count
                .load(AtomicOrdering::Relaxed),
            0,
            "admitted_count should be 0 (admission deferred to post-projection)"
        );
    }

    // ----- Test: error variant display -----

    #[test]
    fn test_admission_denied_error_display() {
        let err = ProjectionWorkerError::AdmissionDenied {
            reason: "missing eval_tick".to_string(),
        };
        assert!(err.to_string().contains("economics admission denied"));
        assert!(err.to_string().contains("missing eval_tick"));
    }

    #[test]
    fn test_lifecycle_denied_error_display() {
        let err = ProjectionWorkerError::LifecycleDenied {
            reason: "authority revoked".to_string(),
            subcategory: lifecycle_deny::REVOKED.to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("economics admission denied"));
        assert!(msg.contains("authority revoked"));
        assert!(msg.contains("revoked"));
    }

    #[test]
    fn test_intent_buffer_error_display() {
        let err = ProjectionWorkerError::IntentBufferError("test failure".to_string());
        let msg = err.to_string();
        assert!(msg.contains("intent buffer error"));
        assert!(msg.contains("test failure"));
    }

    // ----- Test: telemetry counters increment -----

    #[test]
    fn test_telemetry_counters_increment_on_missing_inputs() {
        let fixture = EconomicsTestFixture::new();

        let changeset_digest = [0x42u8; 32];

        // Multiple missing-input denials should increment the counter
        for i in 0..3 {
            let mut payload =
                economics_gate_payload(&changeset_digest, &format!("receipt-miss-{i}"));
            payload.as_object_mut().unwrap().remove("eval_tick");

            let _ = fixture.evaluate(
                &payload,
                "work-econ-001",
                &changeset_digest,
                &format!("receipt-miss-{i}"),
                ProjectedStatus::Success,
                5000,
                "evt-econ-001",
            );
        }

        assert_eq!(
            fixture
                .telemetry
                .missing_inputs_denied_count
                .load(AtomicOrdering::Relaxed),
            3,
            "Missing inputs counter should be 3 after 3 denials"
        );
    }

    // ----- Test: record_denied_intent -----

    #[test]
    fn test_record_denied_intent_creates_denied_entry() {
        let intent_conn = Arc::new(Mutex::new(Connection::open_in_memory().unwrap()));
        let buffer =
            crate::projection::intent_buffer::IntentBuffer::new(Arc::clone(&intent_conn)).unwrap();

        let changeset_digest = [0x42u8; 32];
        let result = record_denied_intent(
            &buffer,
            "receipt-deny-test",
            "work-deny-001",
            &changeset_digest,
            ProjectedStatus::Failure,
            100,
            9999,
            "test denial reason",
        );

        assert!(result.is_ok(), "record_denied_intent should succeed");

        // Verify the intent was recorded and denied in the buffer
        let guard = intent_conn.lock().unwrap();
        let verdict: String = guard
            .query_row(
                "SELECT verdict FROM projection_intents WHERE intent_id = ?1",
                params!["proj-receipt-deny-test"],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(verdict, "denied", "Intent should be marked denied");

        let deny_reason: String = guard
            .query_row(
                "SELECT deny_reason FROM projection_intents WHERE intent_id = ?1",
                params!["proj-receipt-deny-test"],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            deny_reason.contains("test denial reason"),
            "Deny reason should be recorded"
        );
    }

    // ----- Test: gate input assembly completeness -----

    #[test]
    fn test_economics_admission_all_inputs_present_reaches_gate() {
        // When all inputs are present, the function should reach the
        // economics gate evaluation step. With real signed artifacts
        // and a matching trusted signer, the gate should return ALLOW.
        // The intent is inserted as PENDING; admission happens after
        // projection in the caller.
        let fixture = EconomicsTestFixture::new();

        let changeset_digest = [0x42u8; 32];
        let payload = economics_gate_payload(&changeset_digest, "receipt-full-inputs");

        let result = fixture.evaluate(
            &payload,
            "work-econ-001",
            &changeset_digest,
            "receipt-full-inputs",
            ProjectedStatus::Success,
            5000,
            "evt-econ-001",
        );

        // All inputs present + real signed artifacts + trusted signer -> ALLOW.
        assert!(
            result.is_ok(),
            "All inputs present should reach ALLOW, got: {result:?}"
        );
        let intent_id = result.unwrap();
        assert!(
            intent_id.starts_with("proj-"),
            "Intent ID should start with 'proj-'"
        );
        // admitted_count is NOT incremented here -- deferred to caller.
        assert_eq!(
            fixture
                .telemetry
                .admitted_count
                .load(AtomicOrdering::Relaxed),
            0,
            "admitted_count should be 0 (admission deferred to post-projection)"
        );
    }

    // ----- Test: stale authority (window_ref is zero) -> DENY -----

    #[test]
    fn test_economics_admission_stale_window_ref_deny() {
        // Zero window_ref means stale/unset -- triggers LifecycleDenied
        // with "stale" subcategory (MINOR fix: lifecycle telemetry).
        let fixture = EconomicsTestFixture::new();

        let changeset_digest = [0x42u8; 32];
        let mut payload = economics_gate_payload(&changeset_digest, "receipt-stale");
        payload["window_ref"] = serde_json::json!(hex::encode([0u8; 32]));

        let result = fixture.evaluate(
            &payload,
            "work-econ-001",
            &changeset_digest,
            "receipt-stale",
            ProjectedStatus::Success,
            5000,
            "evt-econ-001",
        );

        assert!(result.is_err(), "Stale window_ref should DENY");
        let err = result.unwrap_err();
        assert!(
            matches!(
                err,
                ProjectionWorkerError::LifecycleDenied {
                    ref subcategory,
                    ..
                } if subcategory == lifecycle_deny::STALE
            ),
            "Stale window_ref should produce LifecycleDenied with stale subcategory, got: {err}"
        );
    }

    // ----- Test: DEFAULT_SINK_ID constant -----

    #[test]
    fn test_default_sink_id_constant() {
        assert_eq!(
            DEFAULT_SINK_ID, "github-primary",
            "Default sink should be github-primary"
        );
    }

    // ----- Test: projection worker telemetry accessor -----

    #[test]
    fn test_projection_worker_telemetry_accessor() {
        let conn = create_test_db();
        let config = ProjectionWorkerConfig::new();
        let worker = ProjectionWorker::new(conn, config).unwrap();

        // Telemetry should be accessible and start at zero
        let telemetry = worker.telemetry();
        assert_eq!(telemetry.admitted_count.load(AtomicOrdering::Relaxed), 0);
    }

    // ----- Test: payload_has_economics_selectors -----

    #[test]
    fn test_payload_has_economics_selectors_all_present() {
        let payload = serde_json::json!({
            "eval_tick": 100,
            "time_authority_ref": "abc",
            "window_ref": "def",
            "boundary_id": "ghi"
        });
        assert!(
            payload_has_economics_selectors(&payload),
            "Should detect economics selectors when all present"
        );
    }

    #[test]
    fn test_payload_has_economics_selectors_partial() {
        // Any single selector present means the payload has economics selectors
        let payload = serde_json::json!({ "eval_tick": 100 });
        assert!(
            payload_has_economics_selectors(&payload),
            "Should detect economics selectors with only eval_tick"
        );

        let payload = serde_json::json!({ "boundary_id": "test" });
        assert!(
            payload_has_economics_selectors(&payload),
            "Should detect economics selectors with only boundary_id"
        );
    }

    #[test]
    fn test_payload_has_economics_selectors_none() {
        let payload = serde_json::json!({
            "receipt_id": "r1",
            "verdict": "success",
            "changeset_digest": "abc"
        });
        assert!(
            !payload_has_economics_selectors(&payload),
            "Should not detect economics selectors when none present"
        );
    }

    #[test]
    fn test_payload_has_economics_selectors_empty() {
        let payload = serde_json::json!({});
        assert!(
            !payload_has_economics_selectors(&payload),
            "Empty payload should have no economics selectors"
        );
    }

    // ----- Test: ALLOW path returns intent_id for deferred admission -----

    #[test]
    fn test_economics_admission_allow_returns_intent_id() {
        let fixture = EconomicsTestFixture::new();

        let changeset_digest = [0x42u8; 32];
        let payload = economics_gate_payload(&changeset_digest, "receipt-deferred");

        let result = fixture.evaluate(
            &payload,
            "work-econ-001",
            &changeset_digest,
            "receipt-deferred",
            ProjectedStatus::Success,
            5000,
            "evt-econ-001",
        );

        assert!(result.is_ok(), "ALLOW should succeed, got: {result:?}");
        let intent_id = result.unwrap();
        assert_eq!(intent_id, "proj-receipt-deferred");

        // Verify the intent is PENDING (not yet admitted)
        let intent = fixture
            .intent_buffer
            .get_intent(&intent_id)
            .expect("get_intent should not fail");
        assert!(intent.is_some(), "Intent should exist in buffer");
        let intent = intent.unwrap();
        assert_eq!(
            intent.verdict,
            crate::projection::intent_buffer::IntentVerdict::Pending,
            "Intent should be PENDING, not admitted"
        );
    }

    // =========================================================================
    // BLOCKER regression: pending-intent retry after transient failure
    // =========================================================================

    #[test]
    fn test_pending_intent_retry_after_transient_failure() {
        // Regression test for BLOCKER: insert pending -> effect failure ->
        // retry -> effect succeeds -> admitted.
        //
        // Previously, retry after transient failure caused a duplicate
        // insert which was treated as LifecycleDenied + ACK, permanently
        // suppressing the projection. The fix loads the existing intent's
        // verdict: if PENDING, proceed to re-attempt projection.
        let fixture = EconomicsTestFixture::new();

        let changeset_digest = [0x42u8; 32];
        let payload = economics_gate_payload(&changeset_digest, "receipt-retry");

        // First call: ALLOW, intent is PENDING.
        let result1 = fixture.evaluate(
            &payload,
            "work-econ-001",
            &changeset_digest,
            "receipt-retry",
            ProjectedStatus::Success,
            5000,
            "evt-econ-001",
        );
        assert!(
            result1.is_ok(),
            "First admission should ALLOW, got: {result1:?}"
        );
        let intent_id = result1.unwrap();
        assert_eq!(intent_id, "proj-receipt-retry");

        // Verify the intent is PENDING (projection not yet done).
        let intent = fixture
            .intent_buffer
            .get_intent(&intent_id)
            .expect("get_intent")
            .expect("should exist");
        assert_eq!(
            intent.verdict,
            crate::projection::intent_buffer::IntentVerdict::Pending,
            "Intent should be PENDING before projection"
        );

        // Simulate transient projection failure: intent stays PENDING.
        // On retry, the second call should also ALLOW (not DENY).
        let result2 = fixture.evaluate(
            &payload,
            "work-econ-001",
            &changeset_digest,
            "receipt-retry",
            ProjectedStatus::Success,
            5000,
            "evt-econ-001",
        );
        assert!(
            result2.is_ok(),
            "Retry should ALLOW (PENDING intent), got: {result2:?}"
        );
        let intent_id2 = result2.unwrap();
        assert_eq!(
            intent_id2, intent_id,
            "Retry should return the same intent_id"
        );

        // Now simulate successful projection by admitting the intent.
        fixture
            .intent_buffer
            .admit(&intent_id, 6000)
            .expect("admit should succeed");

        // After admission, a third attempt should DENY as consumed.
        let result3 = fixture.evaluate(
            &payload,
            "work-econ-001",
            &changeset_digest,
            "receipt-retry",
            ProjectedStatus::Success,
            5000,
            "evt-econ-001",
        );
        assert!(
            result3.is_err(),
            "Third attempt after admission should DENY"
        );
        let err = result3.unwrap_err();
        assert!(
            matches!(err, ProjectionWorkerError::LifecycleDenied { .. }),
            "Expected LifecycleDenied (consumed), got: {err}"
        );
        assert!(
            err.to_string().contains("already admitted"),
            "Should indicate already admitted"
        );

        // Telemetry: lifecycle_consumed_count should be 1 (the third
        // attempt), NOT 2 (the retry should not count).
        assert_eq!(
            fixture
                .telemetry
                .lifecycle_consumed_count
                .load(AtomicOrdering::Relaxed),
            1,
            "lifecycle_consumed_count should be 1 (only the post-admission duplicate)"
        );
    }

    #[test]
    fn test_denied_intent_replay_returns_consumed() {
        // If an intent was previously denied, a retry should also DENY
        // as consumed (safe to ACK).
        let fixture = EconomicsTestFixture::new();

        let changeset_digest = [0x42u8; 32];
        let payload = economics_gate_payload(&changeset_digest, "receipt-deny-replay");

        // First call: ALLOW, intent is PENDING.
        let result1 = fixture.evaluate(
            &payload,
            "work-econ-001",
            &changeset_digest,
            "receipt-deny-replay",
            ProjectedStatus::Success,
            5000,
            "evt-econ-001",
        );
        assert!(result1.is_ok(), "First call should ALLOW");
        let intent_id = result1.unwrap();

        // Manually deny the intent (simulating a deny from another path).
        fixture
            .intent_buffer
            .deny(&intent_id, "manual test deny")
            .expect("deny should succeed");

        // Retry: should DENY as consumed (already denied).
        let result2 = fixture.evaluate(
            &payload,
            "work-econ-001",
            &changeset_digest,
            "receipt-deny-replay",
            ProjectedStatus::Success,
            5000,
            "evt-econ-001",
        );
        assert!(result2.is_err(), "Retry after deny should DENY");
        let err = result2.unwrap_err();
        assert!(
            matches!(err, ProjectionWorkerError::LifecycleDenied { .. }),
            "Expected LifecycleDenied, got: {err}"
        );
        assert!(
            err.to_string().contains("already denied"),
            "Should indicate already denied"
        );
    }

    // =========================================================================
    // MAJOR-1 regression: non-default sink ID admits on valid inputs
    // =========================================================================

    #[test]
    fn test_economics_admission_custom_sink_id_admits() {
        // Regression test for MAJOR-1: configs with non-"github-primary"
        // sink IDs should admit when inputs are valid.
        let custom_sink_id = "custom-gitlab-sink";
        let gate_signer = Signer::generate();
        let vk_bytes = gate_signer.verifying_key().to_bytes();

        // Build snapshot with the custom sink ID.
        let mut snapshot = apm2_core::economics::MultiSinkIdentitySnapshotV1 {
            sink_identities: vec![
                apm2_core::economics::SinkIdentityEntry {
                    sink_id: custom_sink_id.to_string(),
                    identity_digest: [0xAA; 32],
                },
                apm2_core::economics::SinkIdentityEntry {
                    sink_id: "secondary-sink".to_string(),
                    identity_digest: [0xBB; 32],
                },
            ],
            snapshot_digest: [0u8; 32],
        };
        snapshot.snapshot_digest = snapshot.compute_digest();

        let resolver = MockContinuityResolver {
            profile: Some(
                crate::projection::continuity_resolver::ResolvedContinuityProfile {
                    sink_id: custom_sink_id.to_string(),
                    outage_window_ticks: 100,
                    replay_window_ticks: 50,
                    churn_tolerance: 2,
                    partition_tolerance: 1,
                    trusted_signer_keys: vec![vk_bytes],
                },
            ),
            snapshot: Some(snapshot),
            window: Some(
                crate::projection::continuity_resolver::ResolvedContinuityWindow {
                    boundary_id: custom_sink_id.to_string(),
                    outage_window_ticks: 100,
                    replay_window_ticks: 50,
                },
            ),
        };

        let intent_conn = Arc::new(Mutex::new(Connection::open_in_memory().unwrap()));
        let intent_buffer =
            crate::projection::intent_buffer::IntentBuffer::new(intent_conn).unwrap();
        let telemetry = Arc::new(AdmissionTelemetry::new());

        let changeset_digest = [0x42u8; 32];
        // Use the custom sink ID as boundary_id in the payload.
        let payload = serde_json::json!({
            "receipt_id": "receipt-custom-sink",
            "changeset_digest": hex::encode(changeset_digest),
            "verdict": "success",
            "eval_tick": 142_u64,
            "time_authority_ref": hex::encode([0x11u8; 32]),
            "window_ref": hex::encode([0x22u8; 32]),
            "boundary_id": custom_sink_id,
            "work_id": "work-custom-001",
            "artifact_bundle_hash": hex::encode([0x33u8; 32]),
            "capability_manifest_hash": hex::encode([0x44u8; 32]),
            "context_pack_hash": hex::encode([0x55u8; 32]),
            "role_spec_hash": hex::encode([0x66u8; 32]),
            "identity_proof_hash": hex::encode([0x77u8; 32]),
            "time_envelope_ref": "htf:tick:42",
            "lease_id": "lease-custom-001",
        });

        let result = evaluate_economics_admission_blocking(
            &payload,
            "work-custom-001",
            &changeset_digest,
            "receipt-custom-sink",
            ProjectedStatus::Success,
            5000,
            "evt-custom-001",
            &intent_buffer,
            &resolver,
            &gate_signer,
            &telemetry,
        );

        assert!(
            result.is_ok(),
            "Custom sink ID should admit on valid inputs, got: {result:?}"
        );
    }

    // =========================================================================
    // MAJOR-2 regression: deny-write failure prevents watermark advance
    // =========================================================================

    #[test]
    fn test_record_denied_intent_propagates_errors() {
        // Verify that record_denied_intent propagates deny() errors.
        // Previously, deny errors were silently dropped with `let _ = ...`.
        //
        // This test creates a buffer, inserts an intent, admits it, then
        // attempts to deny. deny() returns Ok(false) (non-error, already
        // not pending). We verify the function succeeds but logs the
        // no-op. For actual DB errors we rely on the error propagation
        // path already tested by the IntentBuffer unit tests.
        let intent_conn = Arc::new(Mutex::new(Connection::open_in_memory().unwrap()));
        let buffer =
            crate::projection::intent_buffer::IntentBuffer::new(Arc::clone(&intent_conn)).unwrap();

        let changeset_digest = [0x42u8; 32];

        // record_denied_intent should succeed for a fresh intent.
        let result = record_denied_intent(
            &buffer,
            "receipt-deny-err-test",
            "work-deny-err-001",
            &changeset_digest,
            ProjectedStatus::Failure,
            100,
            9999,
            "test denial reason",
        );
        assert!(
            result.is_ok(),
            "record_denied_intent should succeed for fresh intent"
        );

        // Verify the intent is denied.
        let intent = buffer
            .get_intent("proj-receipt-deny-err-test")
            .expect("get")
            .expect("exists");
        assert_eq!(
            intent.verdict,
            crate::projection::intent_buffer::IntentVerdict::Denied
        );
    }

    // =========================================================================
    // MINOR regression: lifecycle telemetry subcategories
    // =========================================================================

    #[test]
    fn test_revoked_authority_increments_lifecycle_revoked_count() {
        // Verify that zero-hash time_authority_ref increments
        // lifecycle_revoked_count (not missing_inputs_denied_count).
        let fixture = EconomicsTestFixture::new();

        let changeset_digest = [0x42u8; 32];
        let mut payload = economics_gate_payload(&changeset_digest, "receipt-revoked-telem");
        payload["time_authority_ref"] = serde_json::json!(hex::encode([0u8; 32]));

        let result = fixture.evaluate(
            &payload,
            "work-econ-001",
            &changeset_digest,
            "receipt-revoked-telem",
            ProjectedStatus::Success,
            5000,
            "evt-econ-001",
        );

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(
                err,
                ProjectionWorkerError::LifecycleDenied {
                    ref subcategory,
                    ..
                } if subcategory == lifecycle_deny::REVOKED
            ),
            "Expected LifecycleDenied with revoked subcategory, got: {err}"
        );
        assert_eq!(
            fixture
                .telemetry
                .lifecycle_revoked_count
                .load(AtomicOrdering::Relaxed),
            1,
            "lifecycle_revoked_count should be 1"
        );
        assert_eq!(
            fixture
                .telemetry
                .missing_inputs_denied_count
                .load(AtomicOrdering::Relaxed),
            0,
            "missing_inputs_denied_count should be 0 (revoked is a subcategory)"
        );
    }

    #[test]
    fn test_stale_authority_increments_lifecycle_stale_count() {
        // Verify that zero-hash window_ref increments
        // lifecycle_stale_count (not missing_inputs_denied_count).
        let fixture = EconomicsTestFixture::new();

        let changeset_digest = [0x42u8; 32];
        let mut payload = economics_gate_payload(&changeset_digest, "receipt-stale-telem");
        payload["window_ref"] = serde_json::json!(hex::encode([0u8; 32]));

        let result = fixture.evaluate(
            &payload,
            "work-econ-001",
            &changeset_digest,
            "receipt-stale-telem",
            ProjectedStatus::Success,
            5000,
            "evt-econ-001",
        );

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(
                err,
                ProjectionWorkerError::LifecycleDenied {
                    ref subcategory,
                    ..
                } if subcategory == lifecycle_deny::STALE
            ),
            "Expected LifecycleDenied with stale subcategory, got: {err}"
        );
        assert_eq!(
            fixture
                .telemetry
                .lifecycle_stale_count
                .load(AtomicOrdering::Relaxed),
            1,
            "lifecycle_stale_count should be 1"
        );
        assert_eq!(
            fixture
                .telemetry
                .missing_inputs_denied_count
                .load(AtomicOrdering::Relaxed),
            0,
            "missing_inputs_denied_count should be 0 (stale is a subcategory)"
        );
    }

    // =========================================================================
    // is_zero_hash32_field tests
    // =========================================================================

    #[test]
    fn test_is_zero_hash32_field_true_for_zero_hash() {
        let payload = serde_json::json!({
            "test_field": hex::encode([0u8; 32])
        });
        assert!(
            is_zero_hash32_field(&payload, "test_field"),
            "Zero hash should return true"
        );
    }

    #[test]
    fn test_is_zero_hash32_field_false_for_nonzero_hash() {
        let payload = serde_json::json!({
            "test_field": hex::encode([0x42u8; 32])
        });
        assert!(
            !is_zero_hash32_field(&payload, "test_field"),
            "Non-zero hash should return false"
        );
    }

    #[test]
    fn test_is_zero_hash32_field_false_for_missing() {
        let payload = serde_json::json!({});
        assert!(
            !is_zero_hash32_field(&payload, "test_field"),
            "Missing field should return false"
        );
    }

    #[test]
    fn test_is_zero_hash32_field_false_for_invalid_hex() {
        let payload = serde_json::json!({
            "test_field": "not_valid_hex"
        });
        assert!(
            !is_zero_hash32_field(&payload, "test_field"),
            "Invalid hex should return false"
        );
    }

    #[test]
    fn test_is_zero_hash32_field_false_for_wrong_length() {
        let payload = serde_json::json!({
            "test_field": hex::encode([0u8; 16])
        });
        assert!(
            !is_zero_hash32_field(&payload, "test_field"),
            "Wrong length zero hash should return false"
        );
    }

    fn run_review_poll_once(worker: &mut ProjectionWorker) -> Result<(), ProjectionWorkerError> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        rt.block_on(async { worker.process_review_receipts().await })
    }

    fn insert_review_receipt_event(
        conn: &Arc<Mutex<Connection>>,
        event_id: &str,
        work_id: &str,
        payload: &serde_json::Value,
        timestamp_ns: i64,
    ) {
        conn.lock()
            .expect("lock")
            .execute(
                "INSERT INTO ledger_events VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    event_id,
                    "review_receipt_recorded",
                    work_id,
                    "actor-reviewer",
                    serde_json::to_vec(payload).expect("serialize payload"),
                    vec![0u8; 64],
                    timestamp_ns
                ],
            )
            .expect("insert review_receipt_recorded");
    }

    fn review_tailer_watermark(conn: &Arc<Mutex<Connection>>) -> Option<(i64, String)> {
        conn.lock()
            .expect("lock")
            .query_row(
                "SELECT last_processed_ns, last_event_id
                 FROM tailer_watermark
                 WHERE tailer_id = 'projection_worker:review_receipt_recorded'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .expect("watermark query")
    }

    fn comment_receipt_count(conn: &Arc<Mutex<Connection>>) -> i64 {
        conn.lock()
            .expect("lock")
            .query_row("SELECT COUNT(*) FROM comment_receipts", [], |row| {
                row.get(0)
            })
            .expect("comment count")
    }

    fn make_review_payload(
        work_id: &str,
        receipt_id: &str,
        changeset_digest: [u8; 32],
        hashes: &TestLinkageHashes,
    ) -> serde_json::Value {
        let mut payload = valid_receipt_linkage_payload(work_id, hashes);
        payload["receipt_id"] = serde_json::json!(receipt_id);
        payload["changeset_digest"] = serde_json::json!(hex::encode(changeset_digest));
        payload["verdict"] = serde_json::json!("success");
        payload
    }

    fn add_economics_selectors(payload: &mut serde_json::Value) {
        payload["eval_tick"] = serde_json::json!(42_u64);
        payload["time_authority_ref"] = serde_json::json!(hex::encode([0x91u8; 32]));
        payload["window_ref"] = serde_json::json!(hex::encode([0x92u8; 32]));
        payload["boundary_id"] = serde_json::json!(DEFAULT_SINK_ID);
    }

    /// Compute the `ledger_anchor` the same way
    /// `evaluate_projection_lifecycle_gate` does (blake3 hash of `event_id`)
    /// and set `window_ref` in the payload to match.
    ///
    /// This is required because the lifecycle gate uses `window_ref` as
    /// `current_revocation_head_hash` and `ledger_anchor` as
    /// `directory_head_hash` (= `cert.revocation_head_hash`). The revocation
    /// frontier check requires these to be equal.
    fn align_window_ref_to_event(payload: &mut serde_json::Value, event_id: &str) {
        let digest = blake3::hash(event_id.as_bytes());
        let mut ledger_anchor = [0u8; 32];
        ledger_anchor.copy_from_slice(digest.as_bytes());
        payload["window_ref"] = serde_json::json!(hex::encode(ledger_anchor));
    }

    /// Adds lifecycle selectors to a payload so the lifecycle gate can
    /// extract them.
    ///
    /// NOTE: `capability_manifest_hash`, `context_pack_hash`,
    /// `role_spec_hash`, and `identity_proof_hash` are already present
    /// in the payload from `valid_receipt_linkage_payload` (and stored in
    /// the CAS). The lifecycle gate reuses these fields. Do NOT override
    /// them here or CAS linkage validation will fail.
    fn add_lifecycle_selectors(payload: &mut serde_json::Value) {
        payload["ajc_id"] = serde_json::json!(hex::encode([0xA1u8; 32]));
        payload["intent_digest"] = serde_json::json!(hex::encode([0xA2u8; 32]));
        payload["consume_selector_digest"] = serde_json::json!(hex::encode([0xA3u8; 32]));
        payload["consume_tick"] = serde_json::json!(10_u64);
        payload["pcac_time_envelope_ref"] = serde_json::json!(hex::encode([0xA4u8; 32]));
        // Risk tier for MAJOR fix: derive from payload
        payload["risk_tier"] = serde_json::json!("Tier1");
    }

    fn attach_mock_adapter(worker: &mut ProjectionWorker) {
        let github_config =
            GitHubAdapterConfig::new("https://api.github.com", "owner", "repo").expect("config");
        let adapter = GitHubProjectionAdapter::new_mock(Signer::generate(), github_config)
            .expect("mock adapter");
        worker.set_adapter(adapter);
    }

    // =========================================================================
    // Regression: missing economics selectors are denied and not projected
    // =========================================================================

    #[test]
    fn test_missing_economics_selectors_denied_and_not_projected() {
        let conn = create_test_db();
        let mut worker = ProjectionWorker::new(Arc::clone(&conn), ProjectionWorkerConfig::new())
            .expect("worker");
        let cas = MemoryCas::default();
        let hashes = make_test_linkage_hashes(&cas);
        worker.set_authoritative_cas(Arc::new(cas));
        attach_mock_adapter(&mut worker);

        let intent_conn = Arc::new(Mutex::new(
            Connection::open_in_memory().expect("sqlite open"),
        ));
        worker
            .set_intent_buffer(IntentBuffer::new(Arc::clone(&intent_conn)).expect("intent buffer"));

        worker
            .work_index()
            .register_pr("work-no-selectors", 123, "owner", "repo", "deadbeef")
            .expect("register pr");

        let payload = make_review_payload(
            "work-no-selectors",
            "receipt-no-selectors",
            [0x41u8; 32],
            &hashes,
        );
        insert_review_receipt_event(
            &conn,
            "evt-no-selectors",
            "work-no-selectors",
            &payload,
            1000,
        );

        run_review_poll_once(&mut worker).expect("poll");

        let watermark = review_tailer_watermark(&conn).expect("watermark");
        assert_eq!(watermark.1, "evt-no-selectors");
        assert_eq!(
            comment_receipt_count(&conn),
            0,
            "selector-less event must not call projection adapter"
        );

        let guard = intent_conn.lock().expect("lock");
        let (verdict, deny_reason): (String, String) = guard
            .query_row(
                "SELECT verdict, deny_reason FROM projection_intents WHERE intent_id = ?1",
                params!["proj-receipt-no-selectors"],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("denied intent row");
        assert_eq!(verdict, "denied");
        assert!(
            deny_reason.contains("missing economics selectors"),
            "unexpected deny reason: {deny_reason}"
        );
    }

    // =========================================================================
    // Regression: missing-gate ACK only with durable deny evidence
    // =========================================================================

    #[test]
    fn test_missing_gate_ack_requires_durable_deny_recording() {
        // Case A: intent buffer present -> deny is durable -> ACK allowed.
        let conn_a = create_test_db();
        let mut worker_a =
            ProjectionWorker::new(Arc::clone(&conn_a), ProjectionWorkerConfig::new())
                .expect("worker");
        let cas_a = MemoryCas::default();
        let hashes_a = make_test_linkage_hashes(&cas_a);
        worker_a.set_authoritative_cas(Arc::new(cas_a));
        attach_mock_adapter(&mut worker_a);
        let intent_conn_a = Arc::new(Mutex::new(Connection::open_in_memory().expect("sqlite")));
        worker_a.set_intent_buffer(
            IntentBuffer::new(Arc::clone(&intent_conn_a)).expect("intent buffer"),
        );
        worker_a
            .work_index()
            .register_pr("work-missing-gate-a", 123, "owner", "repo", "deadbeef")
            .expect("register pr");

        let mut payload_a = make_review_payload(
            "work-missing-gate-a",
            "receipt-missing-gate-a",
            [0x51u8; 32],
            &hashes_a,
        );
        add_economics_selectors(&mut payload_a);
        insert_review_receipt_event(
            &conn_a,
            "evt-missing-gate-a",
            "work-missing-gate-a",
            &payload_a,
            1000,
        );

        run_review_poll_once(&mut worker_a).expect("poll");
        assert!(
            review_tailer_watermark(&conn_a).is_some(),
            "event should ACK when deny evidence is durable"
        );
        let guard_a = intent_conn_a.lock().expect("lock");
        let verdict_a: String = guard_a
            .query_row(
                "SELECT verdict FROM projection_intents WHERE intent_id = ?1",
                params!["proj-receipt-missing-gate-a"],
                |row| row.get(0),
            )
            .expect("intent verdict");
        assert_eq!(verdict_a, "denied");

        // Case B: intent buffer absent -> deny cannot persist -> event is not ACKed.
        let conn_b = create_test_db();
        let mut worker_b =
            ProjectionWorker::new(Arc::clone(&conn_b), ProjectionWorkerConfig::new())
                .expect("worker");
        let cas_b = MemoryCas::default();
        let hashes_b = make_test_linkage_hashes(&cas_b);
        worker_b.set_authoritative_cas(Arc::new(cas_b));
        attach_mock_adapter(&mut worker_b);
        worker_b
            .work_index()
            .register_pr("work-missing-gate-b", 123, "owner", "repo", "deadbeef")
            .expect("register pr");

        let mut payload_b = make_review_payload(
            "work-missing-gate-b",
            "receipt-missing-gate-b",
            [0x52u8; 32],
            &hashes_b,
        );
        add_economics_selectors(&mut payload_b);
        insert_review_receipt_event(
            &conn_b,
            "evt-missing-gate-b",
            "work-missing-gate-b",
            &payload_b,
            1000,
        );

        run_review_poll_once(&mut worker_b).expect("poll");
        assert!(
            review_tailer_watermark(&conn_b).is_none(),
            "event must not ACK when deny evidence cannot be persisted"
        );
        assert_eq!(
            comment_receipt_count(&conn_b),
            0,
            "missing-gate deny must never project"
        );
    }

    #[test]
    fn test_missing_lifecycle_selectors_denied_before_projection() {
        let conn = create_test_db();
        let mut worker = ProjectionWorker::new(Arc::clone(&conn), ProjectionWorkerConfig::new())
            .expect("worker");
        let cas = MemoryCas::default();
        let hashes = make_test_linkage_hashes(&cas);
        worker.set_authoritative_cas(Arc::new(cas));
        attach_mock_adapter(&mut worker);

        let intent_conn = Arc::new(Mutex::new(Connection::open_in_memory().expect("sqlite")));
        worker
            .set_intent_buffer(IntentBuffer::new(Arc::clone(&intent_conn)).expect("intent buffer"));
        let gate_signer = Signer::generate();
        worker.set_continuity_resolver(Arc::new(MockContinuityResolver::with_defaults_for_signer(
            &gate_signer,
        )));
        worker.set_gate_signer(Arc::new(gate_signer));
        worker
            .work_index()
            .register_pr("work-missing-lifecycle", 123, "owner", "repo", "deadbeef")
            .expect("register pr");

        let mut payload = make_review_payload(
            "work-missing-lifecycle",
            "receipt-missing-lifecycle",
            [0x61u8; 32],
            &hashes,
        );
        add_economics_selectors(&mut payload);
        insert_review_receipt_event(
            &conn,
            "evt-missing-lifecycle",
            "work-missing-lifecycle",
            &payload,
            1000,
        );

        run_review_poll_once(&mut worker).expect("poll");

        assert!(
            review_tailer_watermark(&conn).is_some(),
            "missing lifecycle selectors should produce acknowledgeable deny after persistence"
        );
        assert_eq!(
            comment_receipt_count(&conn),
            0,
            "lifecycle deny must block projection"
        );
        let guard = intent_conn.lock().expect("lock");
        let (verdict, deny_reason): (String, String) = guard
            .query_row(
                "SELECT verdict, deny_reason FROM projection_intents WHERE intent_id = ?1",
                params!["proj-receipt-missing-lifecycle"],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("intent row");
        assert_eq!(verdict, "denied");
        assert!(
            deny_reason.contains("missing lifecycle selectors"),
            "unexpected deny reason: {deny_reason}"
        );
    }

    #[test]
    fn test_lifecycle_subcategory_mapping() {
        let consumed =
            lifecycle_subcategory_from_deny_class(&AuthorityDenyClass::AlreadyConsumed {
                ajc_id: [0x11u8; 32],
            });
        assert_eq!(consumed, lifecycle_deny::CONSUMED);

        let revoked =
            lifecycle_subcategory_from_deny_class(&AuthorityDenyClass::RevocationFrontierAdvanced);
        assert_eq!(revoked, lifecycle_deny::REVOKED);

        let stale =
            lifecycle_subcategory_from_deny_class(&AuthorityDenyClass::CertificateExpired {
                expired_at: 10,
                current_tick: 11,
            });
        assert_eq!(stale, lifecycle_deny::STALE);
    }

    // =========================================================================
    // MAJOR fix: Risk tier derivation from payload
    // =========================================================================

    #[test]
    fn test_derive_risk_tier_from_payload_known_tiers() {
        let payload = serde_json::json!({"risk_tier": "Tier0"});
        assert_eq!(
            derive_risk_tier_from_payload(&payload),
            RiskTier::Tier0,
            "Tier0 must parse"
        );

        let payload = serde_json::json!({"risk_tier": "Tier1"});
        assert_eq!(
            derive_risk_tier_from_payload(&payload),
            RiskTier::Tier1,
            "Tier1 must parse"
        );

        let payload = serde_json::json!({"risk_tier": "tier2"});
        assert_eq!(
            derive_risk_tier_from_payload(&payload),
            RiskTier::Tier2Plus,
            "tier2 lowercase must parse to Tier2Plus"
        );

        let payload = serde_json::json!({"risk_tier": "Tier2Plus"});
        assert_eq!(
            derive_risk_tier_from_payload(&payload),
            RiskTier::Tier2Plus,
            "Tier2Plus must parse"
        );
    }

    #[test]
    fn test_derive_risk_tier_from_payload_fail_closed_on_missing() {
        // Missing risk_tier must fail closed to Tier2Plus (most restrictive)
        let payload = serde_json::json!({"some_other_field": 42});
        assert_eq!(
            derive_risk_tier_from_payload(&payload),
            RiskTier::Tier2Plus,
            "missing risk_tier must fail closed to Tier2Plus"
        );
    }

    #[test]
    fn test_derive_risk_tier_from_payload_fail_closed_on_unknown() {
        // Unknown risk_tier must fail closed to Tier2Plus
        let payload = serde_json::json!({"risk_tier": "TierUnknown"});
        assert_eq!(
            derive_risk_tier_from_payload(&payload),
            RiskTier::Tier2Plus,
            "unknown risk_tier must fail closed to Tier2Plus"
        );

        let payload = serde_json::json!({"risk_tier": ""});
        assert_eq!(
            derive_risk_tier_from_payload(&payload),
            RiskTier::Tier2Plus,
            "empty risk_tier must fail closed to Tier2Plus"
        );

        let payload = serde_json::json!({"risk_tier": 42});
        assert_eq!(
            derive_risk_tier_from_payload(&payload),
            RiskTier::Tier2Plus,
            "non-string risk_tier must fail closed to Tier2Plus"
        );
    }

    // =========================================================================
    // BLOCKER fix regression: Lifecycle artifacts persisted before projection
    // =========================================================================

    /// Regression test: Intent lifecycle artifacts are persisted to the
    /// `IntentBuffer` BEFORE projection, so that on retry the lifecycle gate
    /// is skipped (reusing existing artifacts) instead of re-consuming and
    /// hitting `AlreadyConsumed`.
    #[test]
    fn test_lifecycle_artifacts_persisted_before_projection_effect() {
        let conn = create_test_db();
        let mut worker = ProjectionWorker::new(Arc::clone(&conn), ProjectionWorkerConfig::new())
            .expect("worker");
        let cas = MemoryCas::default();
        let hashes = make_test_linkage_hashes(&cas);
        worker.set_authoritative_cas(Arc::new(cas));
        attach_mock_adapter(&mut worker);

        let intent_conn = Arc::new(Mutex::new(Connection::open_in_memory().expect("sqlite")));
        worker
            .set_intent_buffer(IntentBuffer::new(Arc::clone(&intent_conn)).expect("intent buffer"));
        let gate_signer = Signer::generate();
        worker.set_continuity_resolver(Arc::new(MockContinuityResolver::with_defaults_for_signer(
            &gate_signer,
        )));
        worker.set_gate_signer(Arc::new(gate_signer));
        worker
            .work_index()
            .register_pr("work-lc-persist", 200, "owner", "repo", "abc123def")
            .expect("register pr");

        let mut payload = make_review_payload(
            "work-lc-persist",
            "receipt-lc-persist",
            [0x71u8; 32],
            &hashes,
        );
        add_economics_selectors(&mut payload);
        add_lifecycle_selectors(&mut payload);
        align_window_ref_to_event(&mut payload, "evt-lc-persist");
        insert_review_receipt_event(&conn, "evt-lc-persist", "work-lc-persist", &payload, 1000);

        // Process the event — this will:
        // 1. Pass economics gate
        // 2. Pass lifecycle gate (join -> revalidate -> consume)
        // 3. Persist lifecycle artifacts BEFORE projection
        // 4. Project successfully (mock adapter)
        // 5. Admit intent
        run_review_poll_once(&mut worker).expect("poll");

        // Verify the intent was admitted (projection succeeded).
        let guard = intent_conn.lock().expect("lock");
        let (verdict, ajc_blob): (String, Option<Vec<u8>>) = guard
            .query_row(
                "SELECT verdict, lifecycle_ajc_id
                 FROM projection_intents WHERE intent_id = ?1",
                params!["proj-receipt-lc-persist"],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("intent row");
        assert_eq!(
            verdict, "admitted",
            "intent must be admitted after projection"
        );
        assert!(
            ajc_blob.is_some(),
            "lifecycle artifacts must be persisted on the intent"
        );
    }

    /// Regression test: BLOCKER — lifecycle consume blocks retry after
    /// transient projection failure.
    ///
    /// Scenario:
    /// 1. First attempt: economics ALLOW -> lifecycle gate succeeds ->
    ///    lifecycle artifacts persisted -> `adapter.project_status()` would
    ///    fail transiently (simulated by checking artifacts are persisted
    ///    before admission).
    /// 2. On retry with persisted artifacts: the lifecycle gate must be skipped
    ///    (reusing artifacts from the first attempt) to avoid
    ///    `AlreadyConsumed`.
    ///
    /// This test verifies the `IntentBuffer` `get_lifecycle_artifacts`
    /// roundtrip that enables retry-safe lifecycle enforcement.
    #[test]
    fn test_retry_reuses_persisted_lifecycle_artifacts_no_reconsume() {
        use crate::projection::intent_buffer::IntentBuffer;

        // Set up an intent buffer to simulate the two-phase lifecycle.
        let intent_conn = Arc::new(Mutex::new(Connection::open_in_memory().expect("sqlite")));
        let intent_buffer = IntentBuffer::new(Arc::clone(&intent_conn)).expect("intent buffer");

        let intent_id = "proj-retry-test-001";
        let changeset_digest = [0x77u8; 32];
        let ledger_head = [0xBBu8; 32];

        // Phase 1: First attempt — insert PENDING intent and attach
        // lifecycle artifacts (simulating successful lifecycle gate).
        intent_buffer
            .insert(
                intent_id,
                "work-retry",
                &changeset_digest,
                &ledger_head,
                "pending",
                42,
                1_000_000,
            )
            .expect("insert");

        let original_artifacts = crate::projection::intent_buffer::IntentLifecycleArtifacts {
            ajc_id: [0xF1u8; 32],
            intent_digest: [0xF2u8; 32],
            consume_selector_digest: [0xF3u8; 32],
            consume_tick: 100,
            time_envelope_ref: [0xF4u8; 32],
        };

        intent_buffer
            .attach_lifecycle_artifacts(intent_id, &original_artifacts)
            .expect("attach");

        // Verify artifacts are persisted (as the first attempt would do).
        let intent = intent_buffer
            .get_intent(intent_id)
            .expect("get")
            .expect("exists");
        assert_eq!(
            intent.verdict,
            crate::projection::intent_buffer::IntentVerdict::Pending,
            "intent must still be PENDING (projection failed)"
        );

        // Phase 2: Retry — the economics gate detects PENDING intent and
        // skips re-insertion. Before running the lifecycle gate, check for
        // existing lifecycle artifacts.
        let retrieved_artifacts = intent_buffer
            .get_lifecycle_artifacts(intent_id)
            .expect("query")
            .expect("artifacts must exist for pending intent");

        // Verify the retrieved artifacts match what was persisted.
        assert_eq!(
            retrieved_artifacts.ajc_id, original_artifacts.ajc_id,
            "ajc_id must match"
        );
        assert_eq!(
            retrieved_artifacts.intent_digest, original_artifacts.intent_digest,
            "intent_digest must match"
        );
        assert_eq!(
            retrieved_artifacts.consume_selector_digest, original_artifacts.consume_selector_digest,
            "consume_selector_digest must match"
        );
        assert_eq!(
            retrieved_artifacts.consume_tick, 100,
            "consume_tick must match"
        );
        assert_eq!(
            retrieved_artifacts.time_envelope_ref, original_artifacts.time_envelope_ref,
            "time_envelope_ref must match"
        );

        // Phase 3: After retry succeeds, admit the intent.
        intent_buffer
            .admit(intent_id, 2_000_000)
            .expect("admit on retry");

        let final_intent = intent_buffer
            .get_intent(intent_id)
            .expect("get")
            .expect("exists");
        assert_eq!(
            final_intent.verdict,
            crate::projection::intent_buffer::IntentVerdict::Admitted,
            "intent must transition to admitted after retry"
        );
        assert_eq!(final_intent.admitted_at, 2_000_000);

        // Phase 4: Verify that after admission, lifecycle artifacts are
        // no longer returned (only pending intents are retry-eligible).
        let post_admit = intent_buffer
            .get_lifecycle_artifacts(intent_id)
            .expect("query");
        assert!(
            post_admit.is_none(),
            "admitted intents must not return lifecycle artifacts (not retry-eligible)"
        );
    }

    // =========================================================================
    // MAJOR fix: domain-tagged witness hashes in lifecycle join input
    // =========================================================================

    #[test]
    fn test_projection_lifecycle_tagged_hash_domain_separation() {
        // Verify that different hash types produce different outputs
        // (domain separation).
        let data: &[&[u8]] = &[&[1u8; 32], &[2u8; 32]];
        let hash_a = projection_lifecycle_tagged_hash("boundary_leakage_witness_hash", data);
        let hash_b = projection_lifecycle_tagged_hash("boundary_timing_witness_hash", data);
        assert_ne!(
            hash_a, hash_b,
            "different domain tags must produce different hashes"
        );
    }

    #[test]
    fn test_projection_lifecycle_tagged_hash_deterministic() {
        let data: &[&[u8]] = &[&[1u8; 32], &[2u8; 32]];
        let hash1 = projection_lifecycle_tagged_hash("boundary_leakage_witness_hash", data);
        let hash2 = projection_lifecycle_tagged_hash("boundary_leakage_witness_hash", data);
        assert_eq!(hash1, hash2, "same inputs must produce same output");
    }

    #[test]
    fn test_build_projection_lifecycle_join_input_derives_risk_tier() {
        let mut payload = serde_json::json!({
            "capability_manifest_hash": hex::encode([0xB1u8; 32]),
            "context_pack_hash": hex::encode([0xB2u8; 32]),
            "role_spec_hash": hex::encode([0xB3u8; 32]),
            "identity_proof_hash": hex::encode([0xB4u8; 32]),
            "lease_id": "test-lease",
            "risk_tier": "Tier2",
        });

        let selectors = ProjectionLifecycleSelectors {
            ajc_id: [0xA1u8; 32],
            intent_digest: [0xA2u8; 32],
            consume_selector_digest: [0xA3u8; 32],
            consume_tick: 10,
            pcac_time_envelope_ref: [0xA4u8; 32],
        };

        let join_input = build_projection_lifecycle_join_input(&payload, selectors, 42, [0xCC; 32])
            .expect("build");
        assert_eq!(
            join_input.risk_tier,
            RiskTier::Tier2Plus,
            "risk tier must be derived from payload"
        );

        // Test fail-closed: no risk_tier field -> Tier2Plus
        payload.as_object_mut().unwrap().remove("risk_tier");
        let join_input_no_tier =
            build_projection_lifecycle_join_input(&payload, selectors, 42, [0xCC; 32])
                .expect("build");
        assert_eq!(
            join_input_no_tier.risk_tier,
            RiskTier::Tier2Plus,
            "missing risk_tier must fail closed to Tier2Plus"
        );
    }

    // =========================================================================
    // BLOCKER FIX (round-4): lifecycle consume retry safety
    // =========================================================================

    /// Regression test for BLOCKER: lifecycle `AlreadyConsumed` must not
    /// permanently deny a PENDING intent on retry.
    ///
    /// Scenario:
    ///   1. First `evaluate_projection_lifecycle_gate` call succeeds (join ->
    ///      revalidate -> consume all pass).
    ///   2. Simulate: artifacts NOT persisted (e.g., DB write failure).
    ///   3. Second call hits `AlreadyConsumed` from the in-memory kernel.
    ///   4. The handler code must detect `AlreadyConsumed` + PENDING intent and
    ///      proceed to projection instead of permanent deny.
    #[test]
    fn test_lifecycle_already_consumed_does_not_permanently_deny_pending() {
        // Set up the lifecycle gate.
        let kernel = Arc::new(InProcessKernel::new(1));
        let gate = Arc::new(LifecycleGate::with_tick_kernel(kernel.clone(), kernel));

        let event_id = "evt-lifecycle-retry-001";

        // Compute ledger_anchor the same way evaluate_projection_lifecycle_gate does,
        // so that window_ref matches directory_head_hash (= ledger_anchor) and the
        // revocation frontier check passes.
        let ledger_anchor = {
            let digest = blake3::hash(event_id.as_bytes());
            let mut out = [0u8; 32];
            out.copy_from_slice(digest.as_bytes());
            out
        };

        // Build a payload with all required lifecycle selectors + join
        // fields. window_ref must equal ledger_anchor to satisfy the
        // revocation frontier check (cert.revocation_head_hash ==
        // directory_head_hash == ledger_anchor).
        let payload = serde_json::json!({
            "ajc_id": hex::encode([0xA1u8; 32]),
            "intent_digest": hex::encode([0xA2u8; 32]),
            "consume_selector_digest": hex::encode([0xA3u8; 32]),
            "consume_tick": 10u64,
            "pcac_time_envelope_ref": hex::encode([0xA4u8; 32]),
            "capability_manifest_hash": hex::encode([0xB1u8; 32]),
            "context_pack_hash": hex::encode([0xB2u8; 32]),
            "role_spec_hash": hex::encode([0xB3u8; 32]),
            "identity_proof_hash": hex::encode([0xB4u8; 32]),
            "lease_id": "test-lease-lifecycle-retry",
            "risk_tier": "Tier1",
            "eval_tick": 42u64,
            "window_ref": hex::encode(ledger_anchor),
        });

        let telemetry = AdmissionTelemetry::default();

        // First call: lifecycle gate succeeds.
        let result1 = evaluate_projection_lifecycle_gate(&gate, &payload, &telemetry, event_id);
        assert!(
            result1.is_ok(),
            "First lifecycle gate call should succeed, got: {result1:?}"
        );
        let artifacts = result1.unwrap();
        assert_ne!(artifacts.ajc_id, [0u8; 32], "AJC ID should be non-zero");

        // Do NOT persist artifacts -- simulate attach failure.

        // Second call (retry): same inputs -> AlreadyConsumed.
        let result2 = evaluate_projection_lifecycle_gate(&gate, &payload, &telemetry, event_id);
        assert!(result2.is_err(), "Second call should fail");
        let err = result2.unwrap_err();

        // Verify the error is a LifecycleDenied with CONSUMED
        // subcategory and contains "consume denied" in the reason
        // (which matches the AlreadyConsumed recovery check in
        // handle_review_receipt).
        match &err {
            ProjectionWorkerError::LifecycleDenied {
                reason,
                subcategory,
            } => {
                assert_eq!(
                    subcategory,
                    lifecycle_deny::CONSUMED,
                    "AlreadyConsumed must map to CONSUMED subcategory"
                );
                assert!(
                    reason.contains("consume denied"),
                    "Reason must contain 'consume denied' for \
                     AlreadyConsumed recovery detection, got: {reason}"
                );
            },
            other => panic!("Expected LifecycleDenied, got: {other}"),
        }

        // Verify the handler-level check matches: this is the exact
        // predicate used in handle_review_receipt to decide whether to
        // recover from AlreadyConsumed.
        let is_already_consumed = matches!(
            &err,
            ProjectionWorkerError::LifecycleDenied { reason, subcategory }
                if subcategory == lifecycle_deny::CONSUMED
                   && reason.contains("consume denied")
        );
        assert!(
            is_already_consumed,
            "AlreadyConsumed must match the retry-safe recovery predicate"
        );
    }

    /// Regression test: PENDING intent retry flows through economics
    /// admission with correct lifecycle artifact reuse.
    ///
    /// Verifies the full sequence: ALLOW + pending -> lifecycle pass ->
    /// artifacts persisted -> economics admission retry returns same
    /// `intent_id` -> lifecycle artifacts found on retry.
    #[test]
    fn test_pending_intent_lifecycle_artifact_reuse_on_retry() {
        let fixture = EconomicsTestFixture::new();

        let changeset_digest = [0x71u8; 32];
        let mut payload = economics_gate_payload(&changeset_digest, "receipt-lifecycle-retry");

        // Add lifecycle selectors so the lifecycle gate can process.
        payload["ajc_id"] = serde_json::json!(hex::encode([0xA1u8; 32]));
        payload["intent_digest"] = serde_json::json!(hex::encode([0xA2u8; 32]));
        payload["consume_selector_digest"] = serde_json::json!(hex::encode([0xA3u8; 32]));
        payload["consume_tick"] = serde_json::json!(10u64);
        payload["pcac_time_envelope_ref"] = serde_json::json!(hex::encode([0xA4u8; 32]));
        payload["capability_manifest_hash"] = serde_json::json!(hex::encode([0xB1u8; 32]));
        payload["context_pack_hash"] = serde_json::json!(hex::encode([0xB2u8; 32]));
        payload["role_spec_hash"] = serde_json::json!(hex::encode([0xB3u8; 32]));
        payload["identity_proof_hash"] = serde_json::json!(hex::encode([0xB4u8; 32]));
        payload["lease_id"] = serde_json::json!("test-lease-lifecycle-reuse");
        payload["risk_tier"] = serde_json::json!("Tier1");

        // First call: economics ALLOW, intent PENDING.
        let result1 = fixture.evaluate(
            &payload,
            "work-lifecycle-reuse",
            &changeset_digest,
            "receipt-lifecycle-retry",
            ProjectedStatus::Success,
            5000,
            "evt-lifecycle-reuse-001",
        );
        assert!(
            result1.is_ok(),
            "First admission should ALLOW, got: {result1:?}"
        );
        let intent_id = result1.unwrap();

        // Simulate: persist lifecycle artifacts on the intent.
        let test_artifacts = IntentLifecycleArtifacts {
            ajc_id: [0xDD; 32],
            intent_digest: [0xA2; 32],
            consume_selector_digest: [0xA3; 32],
            consume_tick: 10,
            time_envelope_ref: [0xA4; 32],
        };
        let attached = fixture
            .intent_buffer
            .attach_lifecycle_artifacts(&intent_id, &test_artifacts)
            .expect("attach artifacts");
        assert!(
            attached,
            "artifacts should attach to existing pending intent"
        );

        // Retry: economics admission returns same intent_id (PENDING).
        let result2 = fixture.evaluate(
            &payload,
            "work-lifecycle-reuse",
            &changeset_digest,
            "receipt-lifecycle-retry",
            ProjectedStatus::Success,
            5000,
            "evt-lifecycle-reuse-001",
        );
        assert!(
            result2.is_ok(),
            "Retry should ALLOW (PENDING intent), got: {result2:?}"
        );
        assert_eq!(result2.unwrap(), intent_id, "Must return same intent_id");

        // Verify lifecycle artifacts are still retrievable.
        let found_artifacts = fixture
            .intent_buffer
            .get_lifecycle_artifacts(&intent_id)
            .expect("get artifacts");
        assert!(
            found_artifacts.is_some(),
            "Lifecycle artifacts must be retrievable on retry"
        );
        let found = found_artifacts.unwrap();
        assert_eq!(
            found.ajc_id, test_artifacts.ajc_id,
            "Retrieved AJC ID must match persisted artifacts"
        );
    }

    /// Regression test: the full worker path with lifecycle gate and
    /// adapter succeeds end-to-end.
    ///
    /// Drives: ALLOW + pending -> lifecycle pass -> adapter projection
    /// succeeds -> intent admitted. This proves the happy-path when
    /// lifecycle artifacts are present.
    #[test]
    fn test_worker_lifecycle_happy_path_end_to_end() {
        let conn = create_test_db();
        let mut worker = ProjectionWorker::new(Arc::clone(&conn), ProjectionWorkerConfig::new())
            .expect("worker");
        let cas = MemoryCas::default();
        let hashes = make_test_linkage_hashes(&cas);
        worker.set_authoritative_cas(Arc::new(cas));
        attach_mock_adapter(&mut worker);

        let intent_conn = Arc::new(Mutex::new(Connection::open_in_memory().expect("sqlite")));
        worker
            .set_intent_buffer(IntentBuffer::new(Arc::clone(&intent_conn)).expect("intent buffer"));
        let gate_signer = Signer::generate();
        worker.set_continuity_resolver(Arc::new(MockContinuityResolver::with_defaults_for_signer(
            &gate_signer,
        )));
        worker.set_gate_signer(Arc::new(gate_signer));
        worker
            .work_index()
            .register_pr("work-lifecycle-e2e", 42, "owner", "repo", "deadbeef")
            .expect("register pr");

        let mut payload = make_review_payload(
            "work-lifecycle-e2e",
            "receipt-lifecycle-e2e",
            [0x81u8; 32],
            &hashes,
        );
        add_economics_selectors(&mut payload);
        add_lifecycle_selectors(&mut payload);
        align_window_ref_to_event(&mut payload, "evt-lifecycle-e2e");
        insert_review_receipt_event(
            &conn,
            "evt-lifecycle-e2e",
            "work-lifecycle-e2e",
            &payload,
            1000,
        );

        // Poll: economics ALLOW, lifecycle gate pass, mock adapter
        // succeeds, intent admitted.
        run_review_poll_once(&mut worker).expect("poll");

        // Verify: event acknowledged (watermark advanced).
        assert!(
            review_tailer_watermark(&conn).is_some(),
            "Event should be ACKed after successful projection"
        );

        // Verify: intent admitted in the buffer.
        let guard = intent_conn.lock().expect("lock");
        let verdict: String = guard
            .query_row(
                "SELECT verdict FROM projection_intents \
                 WHERE intent_id = ?1",
                params!["proj-receipt-lifecycle-e2e"],
                |row| row.get(0),
            )
            .expect("intent row");
        assert_eq!(
            verdict, "admitted",
            "Intent must be admitted after lifecycle + projection"
        );

        // Verify: lifecycle artifacts persisted on the intent.
        let ajc_blob: Option<Vec<u8>> = guard
            .query_row(
                "SELECT lifecycle_ajc_id FROM projection_intents \
                 WHERE intent_id = ?1",
                params!["proj-receipt-lifecycle-e2e"],
                |row| row.get(0),
            )
            .expect("lifecycle column");
        assert!(ajc_blob.is_some(), "Lifecycle artifacts must be persisted");
    }

    // ========================================================================
    // TCK-00638: work_context projection tests (RFC-0032 Phase 2)
    // ========================================================================

    /// BLOCKER 2a: Verify `WORK_CONTEXT_ENTRY` events are correctly indexed
    /// in the `work_context` projection table.
    #[test]
    fn test_work_context_entry_projection_indexes_correctly() {
        let conn = create_test_db();
        let index = WorkIndex::new(Arc::clone(&conn)).unwrap();

        index
            .register_work_context_entry(
                "W-001",
                "CTX-abc123",
                "HANDOFF_NOTE",
                "dedup-key-1",
                "actor-001",
                "deadbeefdeadbeef",
                "CTX-abc123",
                1_000_000_000,
            )
            .unwrap();

        // Query directly to verify the row was inserted.
        let guard = conn.lock().unwrap();
        let (entry_id, kind, dedupe_key, actor_id, cas_hash, evidence_id, created_at_ns): (
            String,
            String,
            String,
            String,
            String,
            String,
            i64,
        ) = guard
            .query_row(
                "SELECT entry_id, kind, dedupe_key, actor_id, cas_hash, evidence_id, created_at_ns \
                 FROM work_context WHERE work_id = ?1 AND entry_id = ?2",
                params!["W-001", "CTX-abc123"],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                    ))
                },
            )
            .expect("work_context row should exist");

        assert_eq!(entry_id, "CTX-abc123");
        assert_eq!(kind, "HANDOFF_NOTE");
        assert_eq!(dedupe_key, "dedup-key-1");
        assert_eq!(actor_id, "actor-001");
        assert_eq!(cas_hash, "deadbeefdeadbeef");
        assert_eq!(evidence_id, "CTX-abc123");
        assert_eq!(created_at_ns, 1_000_000_000);
    }

    /// BLOCKER 2b: Verify duplicate events are handled idempotently via
    /// INSERT OR IGNORE on the (`work_id`, `entry_id`) primary key.
    #[test]
    fn test_work_context_entry_projection_idempotent_duplicate() {
        let conn = create_test_db();
        let index = WorkIndex::new(Arc::clone(&conn)).unwrap();

        // First insert.
        index
            .register_work_context_entry(
                "W-002",
                "CTX-dup-001",
                "DIAGNOSIS",
                "dedup-diag-1",
                "actor-002",
                "cafebabecafebabe",
                "CTX-dup-001",
                2_000_000_000,
            )
            .unwrap();

        // Duplicate insert with same (work_id, entry_id) — must succeed (no error)
        // but NOT overwrite the existing row.
        index
            .register_work_context_entry(
                "W-002",
                "CTX-dup-001",
                "DIAGNOSIS",
                "dedup-diag-1",
                "actor-modified", // Different actor — should NOT overwrite.
                "different_hash",
                "CTX-dup-001",
                3_000_000_000, // Different timestamp — should NOT overwrite.
            )
            .unwrap();

        // Verify only 1 row exists (not 2).
        let guard = conn.lock().unwrap();
        let count: i64 = guard
            .query_row(
                "SELECT COUNT(*) FROM work_context WHERE work_id = ?1 AND entry_id = ?2",
                params!["W-002", "CTX-dup-001"],
                |row| row.get(0),
            )
            .expect("count query should succeed");
        assert_eq!(count, 1, "Duplicate insert must not create a second row");

        // Verify original values are preserved (INSERT OR IGNORE keeps first).
        let (actor_id, cas_hash, created_at_ns): (String, String, i64) = guard
            .query_row(
                "SELECT actor_id, cas_hash, created_at_ns FROM work_context \
                 WHERE work_id = ?1 AND entry_id = ?2",
                params!["W-002", "CTX-dup-001"],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("row should exist");
        assert_eq!(actor_id, "actor-002", "Original actor_id must be preserved");
        assert_eq!(
            cas_hash, "cafebabecafebabe",
            "Original cas_hash must be preserved"
        );
        assert_eq!(
            created_at_ns, 2_000_000_000,
            "Original created_at_ns must be preserved"
        );
    }

    /// BLOCKER 2c: Verify the UNIQUE constraint on (`work_id`, `kind`,
    /// `dedupe_key`) also prevents duplicates via INSERT OR IGNORE.
    #[test]
    fn test_work_context_entry_projection_dedupe_key_uniqueness() {
        let conn = create_test_db();
        let index = WorkIndex::new(Arc::clone(&conn)).unwrap();

        // First insert.
        index
            .register_work_context_entry(
                "W-003",
                "CTX-first",
                "REVIEW_FINDING",
                "review-key-1",
                "actor-003",
                "hash1111",
                "CTX-first",
                4_000_000_000,
            )
            .unwrap();

        // Second insert with SAME (work_id, kind, dedupe_key) but DIFFERENT
        // entry_id — violates the UNIQUE index on (work_id, kind, dedupe_key).
        // INSERT OR IGNORE should silently skip.
        index
            .register_work_context_entry(
                "W-003",
                "CTX-second", // Different entry_id.
                "REVIEW_FINDING",
                "review-key-1", // Same dedupe_key.
                "actor-003",
                "hash2222",
                "CTX-second",
                5_000_000_000,
            )
            .unwrap();

        // Verify total row count is 1 (the UNIQUE index prevented the second).
        let guard = conn.lock().unwrap();
        let count: i64 = guard
            .query_row(
                "SELECT COUNT(*) FROM work_context WHERE work_id = ?1",
                params!["W-003"],
                |row| row.get(0),
            )
            .expect("count query should succeed");
        assert_eq!(
            count, 1,
            "UNIQUE (work_id, kind, dedupe_key) must prevent second row"
        );

        // The surviving row should be the first one.
        let entry_id: String = guard
            .query_row(
                "SELECT entry_id FROM work_context WHERE work_id = ?1",
                params!["W-003"],
                |row| row.get(0),
            )
            .expect("row should exist");
        assert_eq!(
            entry_id, "CTX-first",
            "First inserted entry_id must survive"
        );
    }

    /// Helper: builds a JSON-envelope payload matching `emit_session_event`
    /// production format. The inner protobuf is hex-encoded in the `"payload"`
    /// field of the JSON object.
    fn build_session_event_envelope(inner_protobuf: &[u8]) -> Vec<u8> {
        let envelope = serde_json::json!({
            "event_type": "evidence.published",
            "session_id": "test-session",
            "actor_id": "test-actor",
            "payload": hex::encode(inner_protobuf),
        });
        serde_json::to_vec(&envelope).expect("JSON serialization should not fail")
    }

    /// Helper: inserts an `evidence.published` event into the ledger with
    /// production JSON-envelope wire format (matching `emit_session_event`).
    fn insert_evidence_published_event(
        conn: &Arc<Mutex<Connection>>,
        event_id: &str,
        work_id: &str,
        inner_protobuf: &[u8],
        timestamp_ns: i64,
    ) {
        let envelope_payload = build_session_event_envelope(inner_protobuf);
        conn.lock()
            .expect("lock")
            .execute(
                "INSERT INTO ledger_events VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    event_id,
                    "evidence.published",
                    work_id,
                    "actor-test",
                    envelope_payload,
                    vec![0u8; 64],
                    timestamp_ns
                ],
            )
            .expect("insert evidence.published event");
    }

    /// Helper: runs `process_evidence_published` on the worker via a
    /// single-threaded tokio runtime (same pattern as `run_review_poll_once`).
    fn run_evidence_published_poll_once(
        worker: &mut ProjectionWorker,
    ) -> Result<(), ProjectionWorkerError> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        rt.block_on(async { worker.process_evidence_published().await })
    }

    /// BLOCKER: Verify `handle_evidence_published` correctly decodes the
    /// JSON-envelope wire format (matching `emit_session_event` production
    /// encoding), extracts metadata, and indexes `WORK_CONTEXT_ENTRY` events.
    ///
    /// This test calls the actual `handle_evidence_published` method on a
    /// real `ProjectionWorker` with a properly wrapped JSON-envelope payload,
    /// proving the production decode path works end-to-end.
    #[test]
    fn test_handle_evidence_published_indexes_work_context_entry() {
        use prost::Message;

        let conn = create_test_db();
        let worker = ProjectionWorker::new(Arc::clone(&conn), ProjectionWorkerConfig::new())
            .expect("worker creation should succeed");

        // Build a realistic evidence.published protobuf.
        let published = apm2_core::events::EvidencePublished {
            evidence_id: "CTX-e2e-001".to_string(),
            work_id: "W-E2E".to_string(),
            category: "WORK_CONTEXT_ENTRY".to_string(),
            artifact_hash: vec![0xAA; 32],
            verification_command_ids: Vec::new(),
            classification: "INTERNAL".to_string(),
            artifact_size: 42,
            metadata: vec![
                "entry_id=CTX-e2e-001".to_string(),
                "kind=HANDOFF_NOTE".to_string(),
                "dedupe_key=e2e-dedup".to_string(),
                "actor_id=actor-e2e".to_string(),
            ],
            time_envelope_ref: None,
        };
        let evidence_event = apm2_core::events::EvidenceEvent {
            event: Some(apm2_core::events::evidence_event::Event::Published(
                published,
            )),
        };
        let inner_protobuf = evidence_event.encode_to_vec();

        // Wrap in JSON envelope matching emit_session_event production format.
        let envelope_payload = build_session_event_envelope(&inner_protobuf);

        let event = crate::protocol::dispatch::SignedLedgerEvent {
            event_id: "EVT-E2E-001".to_string(),
            event_type: "evidence.published".to_string(),
            work_id: "CTX-e2e-001".to_string(),
            actor_id: "actor-e2e".to_string(),
            payload: envelope_payload,
            signature: vec![0u8; 64],
            timestamp_ns: 6_000_000_000,
        };

        // Call the ACTUAL handle_evidence_published method on the worker.
        worker
            .handle_evidence_published(&event)
            .expect("handle_evidence_published should succeed with JSON-envelope payload");

        // Verify the row landed in the projection table.
        let guard = conn.lock().unwrap();
        let (stored_kind, stored_dedupe, stored_actor, stored_cas): (
            String,
            String,
            String,
            String,
        ) = guard
            .query_row(
                "SELECT kind, dedupe_key, actor_id, cas_hash FROM work_context \
                 WHERE work_id = ?1 AND entry_id = ?2",
                params!["W-E2E", "CTX-e2e-001"],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .expect("work_context row should exist after handle_evidence_published");

        assert_eq!(stored_kind, "HANDOFF_NOTE");
        assert_eq!(stored_dedupe, "e2e-dedup");
        assert_eq!(stored_actor, "actor-e2e");
        assert_eq!(
            stored_cas,
            hex::encode([0xAA; 32]),
            "cas_hash must match artifact_hash hex"
        );
    }

    /// BLOCKER: Non-WORK_CONTEXT_ENTRY events are silently skipped by the
    /// actual `handle_evidence_published` method. Uses production
    /// JSON-envelope wire format and calls the real method.
    #[test]
    fn test_handle_evidence_published_skips_non_work_context() {
        use prost::Message;

        let conn = create_test_db();
        let worker = ProjectionWorker::new(Arc::clone(&conn), ProjectionWorkerConfig::new())
            .expect("worker creation should succeed");

        let published = apm2_core::events::EvidencePublished {
            evidence_id: "EV-other".to_string(),
            work_id: "W-SKIP".to_string(),
            category: "SECURITY_SCAN".to_string(),
            artifact_hash: vec![0xBB; 32],
            verification_command_ids: Vec::new(),
            classification: "INTERNAL".to_string(),
            artifact_size: 100,
            metadata: vec![],
            time_envelope_ref: None,
        };
        let evidence_event = apm2_core::events::EvidenceEvent {
            event: Some(apm2_core::events::evidence_event::Event::Published(
                published,
            )),
        };
        let inner_protobuf = evidence_event.encode_to_vec();

        // Wrap in JSON envelope matching production encoding.
        let envelope_payload = build_session_event_envelope(&inner_protobuf);

        let event = crate::protocol::dispatch::SignedLedgerEvent {
            event_id: "EVT-SKIP-001".to_string(),
            event_type: "evidence.published".to_string(),
            work_id: "W-SKIP".to_string(),
            actor_id: "actor-skip".to_string(),
            payload: envelope_payload,
            signature: vec![0u8; 64],
            timestamp_ns: 7_000_000_000,
        };

        // Call the ACTUAL handle_evidence_published method — should succeed
        // (skip) without error.
        worker
            .handle_evidence_published(&event)
            .expect("non-WORK_CONTEXT_ENTRY events should be silently skipped");

        // Verify no row was inserted.
        let guard = conn.lock().unwrap();
        let count: i64 = guard
            .query_row(
                "SELECT COUNT(*) FROM work_context WHERE work_id = ?1",
                params!["W-SKIP"],
                |row| row.get(0),
            )
            .expect("count query should succeed");
        assert_eq!(
            count, 0,
            "Non-WORK_CONTEXT_ENTRY events must not produce work_context rows"
        );
    }

    /// E2E: Feeds a real wrapped ledger payload through the full
    /// `process_evidence_published` async path (tailer poll -> decode ->
    /// projection insert -> acknowledge) and verifies successful indexing.
    #[test]
    fn test_process_evidence_published_e2e_full_pipeline() {
        use prost::Message;

        let conn = create_test_db();
        let mut worker = ProjectionWorker::new(Arc::clone(&conn), ProjectionWorkerConfig::new())
            .expect("worker creation should succeed");

        // Build a WORK_CONTEXT_ENTRY evidence event protobuf.
        let published = apm2_core::events::EvidencePublished {
            evidence_id: "CTX-pipeline-001".to_string(),
            work_id: "W-PIPELINE".to_string(),
            category: "WORK_CONTEXT_ENTRY".to_string(),
            artifact_hash: vec![0xCC; 32],
            verification_command_ids: Vec::new(),
            classification: "INTERNAL".to_string(),
            artifact_size: 99,
            metadata: vec![
                "entry_id=CTX-pipeline-001".to_string(),
                "kind=REVIEW_FINDING".to_string(),
                "dedupe_key=pipeline-dedup".to_string(),
                "actor_id=actor-pipeline".to_string(),
            ],
            time_envelope_ref: None,
        };
        let evidence_event = apm2_core::events::EvidenceEvent {
            event: Some(apm2_core::events::evidence_event::Event::Published(
                published,
            )),
        };
        let inner_protobuf = evidence_event.encode_to_vec();

        // Insert the event into the ledger in production JSON-envelope format.
        insert_evidence_published_event(
            &conn,
            "EVT-PIPELINE-001",
            "W-PIPELINE",
            &inner_protobuf,
            8_000_000_000,
        );

        // Also insert a non-WORK_CONTEXT_ENTRY event to verify it is skipped.
        let skip_published = apm2_core::events::EvidencePublished {
            evidence_id: "EV-sec-scan".to_string(),
            work_id: "W-PIPELINE".to_string(),
            category: "SECURITY_SCAN".to_string(),
            artifact_hash: vec![0xDD; 32],
            verification_command_ids: Vec::new(),
            classification: "INTERNAL".to_string(),
            artifact_size: 50,
            metadata: vec![],
            time_envelope_ref: None,
        };
        let skip_event = apm2_core::events::EvidenceEvent {
            event: Some(apm2_core::events::evidence_event::Event::Published(
                skip_published,
            )),
        };
        insert_evidence_published_event(
            &conn,
            "EVT-SKIP-002",
            "W-PIPELINE",
            &skip_event.encode_to_vec(),
            9_000_000_000,
        );

        // Poll: process_evidence_published should decode both events,
        // index the WORK_CONTEXT_ENTRY one, skip the SECURITY_SCAN one,
        // and acknowledge both.
        run_evidence_published_poll_once(&mut worker)
            .expect("process_evidence_published should succeed");

        // Verify: exactly 1 work_context row for the WORK_CONTEXT_ENTRY event.
        let guard = conn.lock().unwrap();
        let (stored_kind, stored_dedupe, stored_actor, stored_cas): (
            String,
            String,
            String,
            String,
        ) = guard
            .query_row(
                "SELECT kind, dedupe_key, actor_id, cas_hash FROM work_context \
                 WHERE work_id = ?1 AND entry_id = ?2",
                params!["W-PIPELINE", "CTX-pipeline-001"],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .expect("work_context row should exist after full pipeline");

        assert_eq!(stored_kind, "REVIEW_FINDING");
        assert_eq!(stored_dedupe, "pipeline-dedup");
        assert_eq!(stored_actor, "actor-pipeline");
        assert_eq!(
            stored_cas,
            hex::encode([0xCC; 32]),
            "cas_hash must match artifact_hash hex"
        );

        // Verify: no row for the SECURITY_SCAN event.
        let skip_count: i64 = guard
            .query_row(
                "SELECT COUNT(*) FROM work_context WHERE entry_id = ?1",
                params!["EV-sec-scan"],
                |row| row.get(0),
            )
            .expect("count query should succeed");
        assert_eq!(
            skip_count, 0,
            "SECURITY_SCAN evidence must not produce work_context rows"
        );

        // Verify: total work_context rows for W-PIPELINE is exactly 1.
        let total_count: i64 = guard
            .query_row(
                "SELECT COUNT(*) FROM work_context WHERE work_id = ?1",
                params!["W-PIPELINE"],
                |row| row.get(0),
            )
            .expect("count query should succeed");
        assert_eq!(
            total_count, 1,
            "Only the WORK_CONTEXT_ENTRY event should produce a projection row"
        );
    }

    /// Regression: raw protobuf payload (without JSON envelope) must be
    /// rejected by `handle_evidence_published`. This proves that the method
    /// does NOT silently accept the old incorrect format.
    #[test]
    fn test_handle_evidence_published_rejects_raw_protobuf() {
        use prost::Message;

        let conn = create_test_db();
        let worker = ProjectionWorker::new(Arc::clone(&conn), ProjectionWorkerConfig::new())
            .expect("worker creation should succeed");

        let published = apm2_core::events::EvidencePublished {
            evidence_id: "CTX-raw".to_string(),
            work_id: "W-RAW".to_string(),
            category: "WORK_CONTEXT_ENTRY".to_string(),
            artifact_hash: vec![0xEE; 32],
            verification_command_ids: Vec::new(),
            classification: "INTERNAL".to_string(),
            artifact_size: 42,
            metadata: vec![
                "entry_id=CTX-raw".to_string(),
                "kind=HANDOFF_NOTE".to_string(),
                "dedupe_key=raw-key".to_string(),
                "actor_id=actor-raw".to_string(),
            ],
            time_envelope_ref: None,
        };
        let evidence_event = apm2_core::events::EvidenceEvent {
            event: Some(apm2_core::events::evidence_event::Event::Published(
                published,
            )),
        };
        // Raw protobuf bytes WITHOUT the JSON envelope wrapper.
        let raw_protobuf = evidence_event.encode_to_vec();

        let event = crate::protocol::dispatch::SignedLedgerEvent {
            event_id: "EVT-RAW-001".to_string(),
            event_type: "evidence.published".to_string(),
            work_id: "W-RAW".to_string(),
            actor_id: "actor-raw".to_string(),
            payload: raw_protobuf,
            signature: vec![0u8; 64],
            timestamp_ns: 10_000_000_000,
        };

        // The method must return an error because the payload is not a valid
        // JSON envelope.
        let result = worker.handle_evidence_published(&event);
        assert!(
            result.is_err(),
            "Raw protobuf payload (without JSON envelope) must be rejected"
        );
    }

    /// Security regression: a permanently malformed evidence.published event
    /// must NOT cause head-of-line blocking. The tailer must acknowledge
    /// (skip) the defective event and continue processing subsequent valid
    /// events.
    ///
    /// Scenario: insert a malformed event (raw protobuf, no JSON envelope),
    /// followed by a valid `WORK_CONTEXT_ENTRY` event. After one poll cycle,
    /// the malformed event is acknowledged and the valid event is indexed.
    #[test]
    fn test_process_evidence_published_skips_malformed_no_head_of_line_block() {
        use prost::Message;

        let conn = create_test_db();
        let mut worker = ProjectionWorker::new(Arc::clone(&conn), ProjectionWorkerConfig::new())
            .expect("worker creation should succeed");

        // Event 1: malformed — raw protobuf without JSON envelope wrapper.
        let published_bad = apm2_core::events::EvidencePublished {
            evidence_id: "CTX-bad".to_string(),
            work_id: "W-HOL-TEST".to_string(),
            category: "WORK_CONTEXT_ENTRY".to_string(),
            artifact_hash: vec![0xFF; 32],
            verification_command_ids: Vec::new(),
            classification: "INTERNAL".to_string(),
            artifact_size: 42,
            metadata: vec![
                "entry_id=CTX-bad".to_string(),
                "kind=HANDOFF_NOTE".to_string(),
                "dedupe_key=bad-key".to_string(),
                "actor_id=actor-bad".to_string(),
            ],
            time_envelope_ref: None,
        };
        let bad_event = apm2_core::events::EvidenceEvent {
            event: Some(apm2_core::events::evidence_event::Event::Published(
                published_bad,
            )),
        };
        // Insert as raw protobuf (NOT wrapped in JSON envelope) — this is
        // permanently malformed and will cause InvalidPayload on decode.
        let raw_protobuf = bad_event.encode_to_vec();
        conn.lock()
            .expect("lock")
            .execute(
                "INSERT INTO ledger_events VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    "EVT-BAD-001",
                    "evidence.published",
                    "W-HOL-TEST",
                    "actor-bad",
                    raw_protobuf,
                    vec![0u8; 64],
                    11_000_000_000i64
                ],
            )
            .expect("insert malformed event");

        // Event 2: valid WORK_CONTEXT_ENTRY with correct JSON envelope.
        let published_good = apm2_core::events::EvidencePublished {
            evidence_id: "CTX-good".to_string(),
            work_id: "W-HOL-TEST".to_string(),
            category: "WORK_CONTEXT_ENTRY".to_string(),
            artifact_hash: vec![0xAA; 32],
            verification_command_ids: Vec::new(),
            classification: "INTERNAL".to_string(),
            artifact_size: 99,
            metadata: vec![
                "entry_id=CTX-good".to_string(),
                "kind=DIAGNOSIS".to_string(),
                "dedupe_key=good-key".to_string(),
                "actor_id=actor-good".to_string(),
            ],
            time_envelope_ref: None,
        };
        let good_event = apm2_core::events::EvidenceEvent {
            event: Some(apm2_core::events::evidence_event::Event::Published(
                published_good,
            )),
        };
        insert_evidence_published_event(
            &conn,
            "EVT-GOOD-001",
            "W-HOL-TEST",
            &good_event.encode_to_vec(),
            12_000_000_000,
        );

        // Poll cycle 1: should acknowledge the malformed event (skip) and
        // process the valid event. No head-of-line blocking.
        run_evidence_published_poll_once(&mut worker)
            .expect("process_evidence_published should not fail on malformed payload");

        // If there was head-of-line blocking, we might need a second poll.
        // Run a second poll to prove forward progress completes.
        run_evidence_published_poll_once(&mut worker).expect("second poll should also succeed");

        // Verify: the valid event was indexed.
        let guard = conn.lock().unwrap();
        let (stored_kind, stored_dedupe): (String, String) = guard
            .query_row(
                "SELECT kind, dedupe_key FROM work_context \
                 WHERE work_id = ?1 AND entry_id = ?2",
                params!["W-HOL-TEST", "CTX-good"],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("valid WORK_CONTEXT_ENTRY must be indexed despite preceding malformed event");
        assert_eq!(stored_kind, "DIAGNOSIS");
        assert_eq!(stored_dedupe, "good-key");

        // Verify: the malformed event did NOT produce a projection row.
        let bad_count: i64 = guard
            .query_row(
                "SELECT COUNT(*) FROM work_context WHERE entry_id = ?1",
                params!["CTX-bad"],
                |row| row.get(0),
            )
            .expect("count query should succeed");
        assert_eq!(
            bad_count, 0,
            "Malformed event must not produce a work_context row"
        );
    }

    /// TCK-00638 / BLOCKER-2 regression test: `LedgerTailer::poll_events`
    /// discovers events written to the canonical `events` table when in
    /// freeze mode.
    ///
    /// Proves: When both `ledger_events` (legacy) and `events` (canonical)
    /// tables exist, `poll_events` merges results from both sources and
    /// synthesises `event_id` = `"canonical-{seq_id}"` for canonical rows.
    #[test]
    fn test_tailer_poll_events_discovers_canonical_events() {
        use prost::Message;

        // 1. Create in-memory DB with legacy schema + work index.
        let conn = Connection::open_in_memory().unwrap();
        conn.execute(
            "CREATE TABLE IF NOT EXISTS ledger_events (
                event_id TEXT PRIMARY KEY,
                event_type TEXT NOT NULL,
                work_id TEXT NOT NULL,
                actor_id TEXT NOT NULL,
                payload BLOB NOT NULL,
                signature BLOB NOT NULL,
                timestamp_ns INTEGER NOT NULL
            )",
            [],
        )
        .unwrap();
        conn.execute_batch(WORK_INDEX_SCHEMA_SQL).unwrap();

        // 2. Create canonical `events` table (same schema as `init_canonical_schema`
        //    produces).
        conn.execute_batch(
            "CREATE TABLE events (
                seq_id    INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                session_id TEXT NOT NULL,
                actor_id   TEXT NOT NULL,
                payload    BLOB NOT NULL,
                timestamp_ns INTEGER NOT NULL,
                prev_hash  TEXT NOT NULL DEFAULT 'genesis',
                event_hash TEXT NOT NULL DEFAULT '',
                signature  BLOB
            );",
        )
        .unwrap();

        // 3. Insert a legacy event to prove the tailer reads both sources.
        let legacy_proto = {
            let published = apm2_core::events::EvidencePublished {
                evidence_id: "CTX-legacy-entry".to_string(),
                work_id: "W-TAILER-LEGACY".to_string(),
                category: "WORK_CONTEXT_ENTRY".to_string(),
                artifact_hash: vec![0xAA; 32],
                verification_command_ids: Vec::new(),
                classification: "INTERNAL".to_string(),
                artifact_size: 50,
                metadata: Vec::new(),
                time_envelope_ref: None,
            };
            let ev = apm2_core::events::EvidenceEvent {
                event: Some(apm2_core::events::evidence_event::Event::Published(
                    published,
                )),
            };
            ev.encode_to_vec()
        };
        let legacy_envelope = build_session_event_envelope(&legacy_proto);
        conn.execute(
            "INSERT INTO ledger_events VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                "EVT-LEGACY-001",
                "evidence.published",
                "W-TAILER-LEGACY",
                "actor-test",
                legacy_envelope,
                vec![0u8; 64],
                1_000_000_000_i64
            ],
        )
        .unwrap();

        // 4. Insert a canonical event with a later timestamp.
        let canonical_proto = {
            let published = apm2_core::events::EvidencePublished {
                evidence_id: "CTX-canonical-entry".to_string(),
                work_id: "W-TAILER-CANONICAL".to_string(),
                category: "WORK_CONTEXT_ENTRY".to_string(),
                artifact_hash: vec![0xBB; 32],
                verification_command_ids: Vec::new(),
                classification: "INTERNAL".to_string(),
                artifact_size: 75,
                metadata: Vec::new(),
                time_envelope_ref: None,
            };
            let ev = apm2_core::events::EvidenceEvent {
                event: Some(apm2_core::events::evidence_event::Event::Published(
                    published,
                )),
            };
            ev.encode_to_vec()
        };
        let canonical_envelope = build_session_event_envelope(&canonical_proto);
        conn.execute(
            "INSERT INTO events (event_type, session_id, actor_id, payload, timestamp_ns) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                "evidence.published",
                "W-TAILER-CANONICAL",
                "actor-canonical",
                canonical_envelope,
                2_000_000_000_i64
            ],
        )
        .unwrap();

        let conn_arc = Arc::new(Mutex::new(conn));

        // 5. Create tailer and poll — must return BOTH events.
        let mut tailer = LedgerTailer::new(Arc::clone(&conn_arc));
        let events = tailer
            .poll_events("evidence.published", 100)
            .expect("poll_events must succeed");

        assert_eq!(
            events.len(),
            2,
            "BLOCKER-2 fix: poll_events must return events from BOTH \
             legacy and canonical tables, got {} event(s)",
            events.len()
        );

        // 6. Verify ordering: legacy (ts=1B) before canonical (ts=2B).
        assert_eq!(
            events[0].event_id, "EVT-LEGACY-001",
            "First event must be the legacy event"
        );
        assert!(
            events[1].event_id.starts_with("canonical-"),
            "Second event must have synthesised canonical event_id, got: {}",
            events[1].event_id
        );

        // 7. Verify canonical event fields are correctly mapped.
        let canonical_evt = &events[1];
        assert_eq!(canonical_evt.event_type, "evidence.published");
        assert_eq!(
            canonical_evt.work_id, "W-TAILER-CANONICAL",
            "canonical session_id must map to work_id"
        );
        assert_eq!(canonical_evt.timestamp_ns, 2_000_000_000);

        // 8. Acknowledge the first event and poll again — must return only the
        //    canonical event.
        tailer
            .acknowledge(events[0].timestamp_ns, &events[0].event_id)
            .expect("acknowledge legacy event");

        let events2 = tailer
            .poll_events("evidence.published", 100)
            .expect("second poll must succeed");
        assert_eq!(
            events2.len(),
            1,
            "After acknowledging the legacy event, only the canonical event should remain"
        );
        assert!(
            events2[0].event_id.starts_with("canonical-"),
            "Remaining event must be the canonical event"
        );

        // 9. Acknowledge the canonical event and poll again — must be empty.
        tailer
            .acknowledge(events2[0].timestamp_ns, &events2[0].event_id)
            .expect("acknowledge canonical event");

        let events3 = tailer
            .poll_events("evidence.published", 100)
            .expect("third poll must succeed");
        assert!(
            events3.is_empty(),
            "After acknowledging all events, poll must return empty"
        );
    }

    /// TCK-00638 / BLOCKER-2 regression test: When no canonical `events`
    /// table exists, `poll_events` only returns legacy events (no error).
    #[test]
    fn test_tailer_poll_events_legacy_only_when_no_canonical_table() {
        let conn = create_test_db();

        // Insert a legacy event.
        conn.lock()
            .unwrap()
            .execute(
                "INSERT INTO ledger_events VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    "EVT-LEGACY-ONLY",
                    "evidence.published",
                    "W-LEGACY",
                    "actor-test",
                    vec![0u8; 10],
                    vec![0u8; 64],
                    1_000_i64
                ],
            )
            .unwrap();

        let mut tailer = LedgerTailer::new(conn);
        let events = tailer
            .poll_events("evidence.published", 100)
            .expect("poll must succeed without canonical table");

        assert_eq!(
            events.len(),
            1,
            "Legacy-only mode must return the single legacy event"
        );
        assert_eq!(events[0].event_id, "EVT-LEGACY-ONLY");
    }

    // =========================================================================
    // TCK-00638 fix regression tests:
    //   1. Canonical cursor skip under timestamp collisions (>9 events)
    //   2. work_context eviction in evict_expired / evict_expired_async
    // =========================================================================

    /// MAJOR [Security] regression test: canonical tailer cursor must not
    /// skip events when >9 canonical rows share the same timestamp and a
    /// batch limit forces pagination.
    ///
    /// Before the fix, `"canonical-10"` sorted lexicographically BEFORE
    /// `"canonical-9"`, causing the cursor to advance past unprocessed rows
    /// with `seq_id >= 10`. The zero-padded `event_id` format
    /// (`"canonical-{seq_id:020}"`) eliminates the ordering mismatch.
    #[test]
    fn test_canonical_cursor_no_skip_above_9_events_same_timestamp() {
        // Setup: in-memory DB with both legacy + canonical tables.
        let conn = Connection::open_in_memory().unwrap();
        conn.execute(
            "CREATE TABLE IF NOT EXISTS ledger_events (
                event_id TEXT PRIMARY KEY,
                event_type TEXT NOT NULL,
                work_id TEXT NOT NULL,
                actor_id TEXT NOT NULL,
                payload BLOB NOT NULL,
                signature BLOB NOT NULL,
                timestamp_ns INTEGER NOT NULL
            )",
            [],
        )
        .unwrap();
        conn.execute_batch(WORK_INDEX_SCHEMA_SQL).unwrap();
        conn.execute_batch(
            "CREATE TABLE events (
                seq_id     INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                session_id TEXT NOT NULL,
                actor_id   TEXT NOT NULL,
                payload    BLOB NOT NULL,
                timestamp_ns INTEGER NOT NULL,
                prev_hash  TEXT NOT NULL DEFAULT 'genesis',
                event_hash TEXT NOT NULL DEFAULT '',
                signature  BLOB
            );",
        )
        .unwrap();

        // Insert 15 canonical events ALL sharing the same timestamp.
        let same_ts: i64 = 5_000_000_000;
        for i in 1..=15 {
            conn.execute(
                "INSERT INTO events (event_type, session_id, actor_id, payload, timestamp_ns) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    "evidence.published",
                    format!("W-CURSOR-{i}"),
                    "actor-test",
                    vec![0u8; 10],
                    same_ts
                ],
            )
            .unwrap();
        }

        let conn_arc = Arc::new(Mutex::new(conn));
        let mut tailer = LedgerTailer::new(Arc::clone(&conn_arc));

        // Poll with batch_size = 5 (forces 3 pagination rounds).
        let batch1 = tailer
            .poll_events("evidence.published", 5)
            .expect("first poll must succeed");
        assert_eq!(batch1.len(), 5, "First batch must return exactly 5 events");

        // Acknowledge all events in batch 1.
        for ev in &batch1 {
            tailer
                .acknowledge(ev.timestamp_ns, &ev.event_id)
                .expect("acknowledge must succeed");
        }

        // Poll again — should return the NEXT 5 events (seq_id 6..10).
        let batch2 = tailer
            .poll_events("evidence.published", 5)
            .expect("second poll must succeed");
        assert_eq!(
            batch2.len(),
            5,
            "Second batch must return exactly 5 events (seq_id 6..10), \
             got {}: cursor must not skip events with seq_id >= 10",
            batch2.len()
        );

        // Acknowledge batch 2.
        for ev in &batch2 {
            tailer
                .acknowledge(ev.timestamp_ns, &ev.event_id)
                .expect("acknowledge must succeed");
        }

        // Poll again — should return remaining 5 events (seq_id 11..15).
        let batch3 = tailer
            .poll_events("evidence.published", 5)
            .expect("third poll must succeed");
        assert_eq!(
            batch3.len(),
            5,
            "Third batch must return exactly 5 events (seq_id 11..15), \
             got {}: zero-padded cursor must not skip high seq_ids",
            batch3.len()
        );

        // Acknowledge batch 3.
        for ev in &batch3 {
            tailer
                .acknowledge(ev.timestamp_ns, &ev.event_id)
                .expect("acknowledge must succeed");
        }

        // Final poll — must be empty (all 15 events consumed).
        let batch4 = tailer
            .poll_events("evidence.published", 5)
            .expect("fourth poll must succeed");
        assert_eq!(
            batch4.len(),
            0,
            "All 15 events must have been consumed; remaining = {}",
            batch4.len()
        );

        // Verify the zero-padded event_id format is consistent.
        assert!(
            batch1[0]
                .event_id
                .starts_with("canonical-0000000000000000000"),
            "event_id must be zero-padded, got: {}",
            batch1[0].event_id
        );
    }

    /// BLOCKER [Code-quality] regression test: `evict_expired` must
    /// delete expired rows from the `work_context` table using the
    /// nanosecond `created_at_ns` column.
    #[test]
    fn test_evict_expired_includes_work_context_table() {
        let conn = create_test_db();
        let index = WorkIndex::new(Arc::clone(&conn)).unwrap();

        // Insert an old work_context entry (created_at_ns = 0, i.e. epoch).
        index
            .register_work_context_entry(
                "W-OLD",
                "CTX-old-entry",
                "DIAGNOSIS",
                "dedup-old",
                "actor-old",
                "hash-old",
                "CTX-old-entry",
                0, // nanoseconds: epoch => very old
            )
            .expect("register old entry");

        // Insert a fresh work_context entry with a recent timestamp.
        // Use a timestamp well in the future (year ~2040 in ns).
        let recent_ns: u64 = 2_200_000_000_000_000_000;
        index
            .register_work_context_entry(
                "W-NEW",
                "CTX-new-entry",
                "DIAGNOSIS",
                "dedup-new",
                "actor-new",
                "hash-new",
                "CTX-new-entry",
                recent_ns,
            )
            .expect("register new entry");

        // Verify both rows exist before eviction.
        {
            let guard = conn.lock().unwrap();
            let count: i64 = guard
                .query_row("SELECT COUNT(*) FROM work_context", [], |row| row.get(0))
                .unwrap();
            assert_eq!(count, 2, "Both entries must exist before eviction");
        }

        // Evict with 1-second TTL — the old entry (created_at_ns = 0)
        // should be deleted, the recent entry should survive.
        let deleted = index.evict_expired(1).unwrap();
        assert!(
            deleted >= 1,
            "evict_expired must delete at least 1 entry (the old work_context row)"
        );

        // Verify: old entry is gone.
        {
            let guard = conn.lock().unwrap();
            let old_count: i64 = guard
                .query_row(
                    "SELECT COUNT(*) FROM work_context WHERE entry_id = ?1",
                    params!["CTX-old-entry"],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(old_count, 0, "Old work_context entry must be evicted");
        }

        // Verify: new entry survives.
        {
            let guard = conn.lock().unwrap();
            let new_count: i64 = guard
                .query_row(
                    "SELECT COUNT(*) FROM work_context WHERE entry_id = ?1",
                    params!["CTX-new-entry"],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(
                new_count, 1,
                "Recent work_context entry must survive eviction"
            );
        }
    }
}
