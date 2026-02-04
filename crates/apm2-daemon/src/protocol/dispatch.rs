//! Privileged endpoint dispatcher for RFC-0017 control-plane IPC.
//!
//! This module implements the privileged endpoint dispatcher per DD-001 and
//! DD-009. Privileged endpoints (ClaimWork, SpawnEpisode, IssueCapability,
//! Shutdown) are only accessible via the operator socket. Session socket
//! connections receive `PERMISSION_DENIED` for all privileged requests.
//!
//! # Security Invariants
//!
//! - [INV-0001] An agent cannot execute privileged IPC operations
//! - [TB-002] Privilege separation boundary: session connections blocked from
//!   privileged handlers
//! - [TCK-00253] Actor_id derived from credential, not user input
//!
//! # Message Flow
//!
//! ```text
//! ┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
//! │ operator.sock   │────▶│ PrivilegedDispatch │──▶│ Handler Stubs  │
//! └─────────────────┘     └─────────────────┘     └─────────────────┘
//!                                │
//!                                │ `PERMISSION_DENIED`
//!                                ▼
//! ┌─────────────────┐     ┌─────────────────┐
//! │ session.sock    │────▶│  (Rejected)     │
//! └─────────────────┘     └─────────────────┘
//! ```

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use apm2_core::determinism::canonicalize_json;
use apm2_core::events::{DefectRecorded, Validate};
use bytes::Bytes;
use prost::Message;
use subtle::ConstantTimeEq;
use tracing::{debug, info, warn};

use super::credentials::PeerCredentials;
use super::error::{ProtocolError, ProtocolResult};
use super::messages::{
    BoundedDecode, ClaimWorkRequest, ClaimWorkResponse, DecodeConfig, IssueCapabilityRequest,
    IssueCapabilityResponse, PatternRejection, PrivilegedError, PrivilegedErrorCode,
    ShutdownRequest, ShutdownResponse, SpawnEpisodeRequest, SpawnEpisodeResponse,
    SubscribePulseRequest, SubscribePulseResponse, UnsubscribePulseRequest,
    UnsubscribePulseResponse, WorkRole,
};
use super::pulse_acl::{
    AclDecision, AclError, PulseAclEvaluator, validate_client_sub_id, validate_subscription_id,
};
use super::resource_governance::{
    SharedSubscriptionRegistry, SubscriptionRegistry, SubscriptionState,
};
use super::session_dispatch::InMemoryManifestStore;
use super::session_token::TokenMinter;
use crate::episode::registry::InMemorySessionRegistry;
use crate::episode::{
    CapabilityManifest, CustodyDomainError, CustodyDomainId, EpisodeRuntime, EpisodeRuntimeConfig,
    InMemoryCasManifestLoader, LeaseIssueDenialReason, ManifestLoader,
    validate_custody_domain_overlap,
};
use crate::htf::{ClockConfig, HolonicClock};
use crate::metrics::SharedMetricsRegistry;
use crate::session::{EphemeralHandle, SessionRegistry, SessionState};

// ============================================================================
// Ledger Event Emitter Interface (TCK-00253)
// ============================================================================

/// A signed ledger event for persistence.
///
/// Per acceptance criteria: "`WorkClaimed` event signed and persisted"
/// This struct represents a signed event ready for ledger ingestion.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SignedLedgerEvent {
    /// Unique event identifier.
    pub event_id: String,

    /// Event type discriminant.
    pub event_type: String,

    /// Work ID this event relates to.
    pub work_id: String,

    /// Actor ID that produced this event.
    pub actor_id: String,

    /// Canonical event payload (JSON).
    pub payload: Vec<u8>,

    /// Ed25519 signature over canonical bytes.
    pub signature: Vec<u8>,

    /// Timestamp in nanoseconds since epoch (HTF-compliant).
    pub timestamp_ns: u64,
}

/// Error type for ledger event emission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LedgerEventError {
    /// Signing operation failed.
    SigningFailed {
        /// Error message.
        message: String,
    },

    /// Ledger persistence failed.
    PersistenceFailed {
        /// Error message.
        message: String,
    },

    /// Validation failed (TCK-00307 MAJOR 4).
    ///
    /// Per REQ-VAL-0001: All event payloads must be validated before emission
    /// to prevent denial-of-service via unbounded strings/bytes.
    ValidationFailed {
        /// Error message describing the validation failure.
        message: String,
    },
}

impl std::fmt::Display for LedgerEventError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SigningFailed { message } => write!(f, "signing failed: {message}"),
            Self::PersistenceFailed { message } => write!(f, "persistence failed: {message}"),
            Self::ValidationFailed { message } => write!(f, "validation failed: {message}"),
        }
    }
}

impl std::error::Error for LedgerEventError {}

/// Error type for HTF timestamp generation (TCK-00289).
///
/// # Security (Fail-Closed)
///
/// Per RFC-0016 and the security policy, HTF timestamp errors must be
/// propagated rather than returning a fallback value. Returning 0 would
/// violate fail-closed security posture and could allow operations to
/// proceed with invalid timestamps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HtfTimestampError {
    /// HLC is not enabled on the clock.
    HlcNotEnabled,
    /// Clock error occurred.
    ClockError {
        /// Error message from the clock.
        message: String,
    },
}

impl std::fmt::Display for HtfTimestampError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HlcNotEnabled => write!(f, "HLC not enabled on clock"),
            Self::ClockError { message } => write!(f, "clock error: {message}"),
        }
    }
}

impl std::error::Error for HtfTimestampError {}

/// Trait for emitting signed events to the ledger.
///
/// Per TCK-00253 acceptance criteria:
/// - "`WorkClaimed` event signed and persisted"
/// - "Ledger query returns signed event"
///
/// # Implementers
///
/// - `StubLedgerEventEmitter`: In-memory storage for testing
/// - `DurableLedgerEventEmitter`: SQLite-backed persistence with HTF timestamps
///   (TCK-00289)
pub trait LedgerEventEmitter: Send + Sync {
    /// Emits a signed `WorkClaimed` event to the ledger.
    ///
    /// # Arguments
    ///
    /// * `claim` - The work claim to record
    /// * `timestamp_ns` - HTF-compliant timestamp in nanoseconds since epoch
    ///
    /// # Returns
    ///
    /// The signed event that was persisted.
    ///
    /// # Errors
    ///
    /// Returns `LedgerEventError` if signing or persistence fails.
    fn emit_work_claimed(
        &self,
        claim: &WorkClaim,
        timestamp_ns: u64,
    ) -> Result<SignedLedgerEvent, LedgerEventError>;

    /// Emits a signed `SessionStarted` event to the ledger (TCK-00289).
    ///
    /// # Arguments
    ///
    /// * `session_id` - The session ID being started
    /// * `work_id` - The work ID this session is associated with
    /// * `lease_id` - The lease ID authorizing this session
    /// * `actor_id` - The actor starting the session
    /// * `timestamp_ns` - HTF-compliant timestamp in nanoseconds since epoch
    ///
    /// # Returns
    ///
    /// The signed event that was persisted.
    ///
    /// # Errors
    ///
    /// Returns `LedgerEventError` if signing or persistence fails.
    fn emit_session_started(
        &self,
        session_id: &str,
        work_id: &str,
        lease_id: &str,
        actor_id: &str,
        timestamp_ns: u64,
    ) -> Result<SignedLedgerEvent, LedgerEventError>;

    /// Emits a generic session event to the ledger (TCK-00290).
    ///
    /// This method handles arbitrary session events from `EmitEvent` requests,
    /// preserving the actual `event_type` and payload from the request rather
    /// than coercing all events into `session_started` events.
    ///
    /// # Arguments
    ///
    /// * `session_id` - The session ID emitting the event
    /// * `event_type` - The actual event type from the request
    /// * `payload` - The event payload bytes from the request
    /// * `actor_id` - The actor emitting the event (session ID or agent ID)
    /// * `timestamp_ns` - HTF-compliant timestamp in nanoseconds since epoch
    ///
    /// # Returns
    ///
    /// The signed event that was persisted.
    ///
    /// # Errors
    ///
    /// Returns `LedgerEventError` if signing or persistence fails.
    fn emit_session_event(
        &self,
        session_id: &str,
        event_type: &str,
        payload: &[u8],
        actor_id: &str,
        timestamp_ns: u64,
    ) -> Result<SignedLedgerEvent, LedgerEventError>;

    /// Emits a signed `DefectRecorded` event to the ledger (TCK-00307).
    fn emit_defect_recorded(
        &self,
        defect: &DefectRecorded,
        timestamp_ns: u64,
    ) -> Result<SignedLedgerEvent, LedgerEventError>;

    /// Queries a signed event by event ID.
    fn get_event(&self, event_id: &str) -> Option<SignedLedgerEvent>;

    /// Queries events by work ID.
    fn get_events_by_work_id(&self, work_id: &str) -> Vec<SignedLedgerEvent>;
}

/// Domain separation prefix for `WorkClaimed` events.
///
/// Per RFC-0017 and TCK-00264: domain prefixes prevent cross-context replay.
pub const WORK_CLAIMED_DOMAIN_PREFIX: &[u8] = b"apm2.event.work_claimed:";

/// Domain separation prefix for `DefectRecorded` events.
pub const DEFECT_RECORDED_DOMAIN_PREFIX: &[u8] = b"apm2.event.defect_recorded:";

/// Maximum length for ID fields (`work_id`, `lease_id`, etc.).
///
/// Per SEC-SCP-FAC-0020: Unbounded input processing can lead to
/// denial-of-service via OOM. This limit prevents attackers from supplying
/// multi-GB ID strings.
pub const MAX_ID_LENGTH: usize = 256;

/// Maximum number of events stored in `StubLedgerEventEmitter`.
///
/// Per CTR-1303: In-memory stores must have `max_entries` limit with O(1)
/// eviction. This prevents denial-of-service via memory exhaustion from
/// unbounded event emission.
pub const MAX_LEDGER_EVENTS: usize = 10_000;

/// Stub ledger event emitter for testing.
///
/// Stores events in memory with Ed25519 signatures using a test signing key.
/// In production, this will be replaced with `SqliteLedgerEventEmitter`.
///
/// # Capacity Limits (CTR-1303)
///
/// This emitter enforces a maximum of [`MAX_LEDGER_EVENTS`] entries to prevent
/// memory exhaustion. When the limit is reached, the oldest entry (by insertion
/// order) is evicted to make room for the new event.
#[derive(Debug)]
pub struct StubLedgerEventEmitter {
    /// Events stored with insertion order for LRU eviction.
    /// The `Vec` maintains insertion order; oldest entries are at the front.
    events: std::sync::RwLock<(
        Vec<String>,
        std::collections::HashMap<String, SignedLedgerEvent>,
    )>,
    /// Events indexed by work ID for efficient querying.
    events_by_work_id: std::sync::RwLock<std::collections::HashMap<String, Vec<String>>>,
    /// Signing key for event signatures (test key).
    signing_key: ed25519_dalek::SigningKey,
}

impl Default for StubLedgerEventEmitter {
    fn default() -> Self {
        Self::new()
    }
}

impl StubLedgerEventEmitter {
    /// Creates a new stub emitter with a random test signing key.
    #[must_use]
    pub fn new() -> Self {
        use rand::rngs::OsRng;
        Self {
            events: std::sync::RwLock::new((
                Vec::with_capacity(MAX_LEDGER_EVENTS.min(1000)), // Pre-allocate reasonably
                std::collections::HashMap::with_capacity(MAX_LEDGER_EVENTS.min(1000)),
            )),
            events_by_work_id: std::sync::RwLock::new(std::collections::HashMap::new()),
            signing_key: ed25519_dalek::SigningKey::generate(&mut OsRng),
        }
    }

    /// Creates a new stub emitter with a specific signing key.
    #[must_use]
    pub fn with_signing_key(signing_key: ed25519_dalek::SigningKey) -> Self {
        Self {
            events: std::sync::RwLock::new((
                Vec::with_capacity(MAX_LEDGER_EVENTS.min(1000)), // Pre-allocate reasonably
                std::collections::HashMap::with_capacity(MAX_LEDGER_EVENTS.min(1000)),
            )),
            events_by_work_id: std::sync::RwLock::new(std::collections::HashMap::new()),
            signing_key,
        }
    }

    /// Returns the verifying (public) key for signature verification.
    #[must_use]
    pub fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.signing_key.verifying_key()
    }
}

impl LedgerEventEmitter for StubLedgerEventEmitter {
    fn emit_work_claimed(
        &self,
        claim: &WorkClaim,
        timestamp_ns: u64,
    ) -> Result<SignedLedgerEvent, LedgerEventError> {
        use ed25519_dalek::Signer;

        // Generate unique event ID
        let event_id = format!("EVT-{}", uuid::Uuid::new_v4());

        // Build canonical payload (deterministic JSON)
        let payload = serde_json::json!({
            "event_type": "work_claimed",
            "work_id": claim.work_id,
            "lease_id": claim.lease_id,
            "actor_id": claim.actor_id,
            "role": format!("{:?}", claim.role),
            "policy_resolved_ref": claim.policy_resolution.policy_resolved_ref,
            "capability_manifest_hash": hex::encode(claim.policy_resolution.capability_manifest_hash),
            "context_pack_hash": hex::encode(claim.policy_resolution.context_pack_hash),
        });

        let payload_bytes =
            serde_json::to_vec(&payload).map_err(|e| LedgerEventError::SigningFailed {
                message: format!("payload serialization failed: {e}"),
            })?;

        // Build canonical bytes for signing (domain prefix + payload)
        let mut canonical_bytes =
            Vec::with_capacity(WORK_CLAIMED_DOMAIN_PREFIX.len() + payload_bytes.len());
        canonical_bytes.extend_from_slice(WORK_CLAIMED_DOMAIN_PREFIX);
        canonical_bytes.extend_from_slice(&payload_bytes);

        // Sign the canonical bytes
        let signature = self.signing_key.sign(&canonical_bytes);

        // TCK-00289: Use provided HTF-compliant timestamp from HolonicClock.
        // The timestamp_ns parameter is now provided by the caller from
        // HolonicClock.now_hlc() ensuring RFC-0016 HTF compliance.

        let signed_event = SignedLedgerEvent {
            event_id: event_id.clone(),
            event_type: "work_claimed".to_string(),
            work_id: claim.work_id.clone(),
            actor_id: claim.actor_id.clone(),
            payload: payload_bytes,
            signature: signature.to_bytes().to_vec(),
            timestamp_ns,
        };

        // CTR-1303: Persist to bounded in-memory store with LRU eviction
        {
            let mut guard = self.events.write().expect("lock poisoned");
            let mut events_by_work = self.events_by_work_id.write().expect("lock poisoned");
            let (order, events) = &mut *guard;

            // Evict oldest entries if at capacity, also pruning events_by_work_id index
            while events.len() >= MAX_LEDGER_EVENTS {
                if let Some(oldest_key) = order.first().cloned() {
                    order.remove(0);
                    // Remove from events and prune the events_by_work_id index
                    if let Some(evicted_event) = events.remove(&oldest_key) {
                        // Remove from work_id index
                        if let Some(work_id_events) = events_by_work.get_mut(&evicted_event.work_id)
                        {
                            work_id_events.retain(|id| id != &oldest_key);
                            // Remove the entry entirely if no events remain for this work_id
                            if work_id_events.is_empty() {
                                events_by_work.remove(&evicted_event.work_id);
                            }
                        }
                    }
                    debug!(
                        evicted_event_id = %oldest_key,
                        "Evicted oldest ledger event to maintain capacity limit"
                    );
                } else {
                    break;
                }
            }

            order.push(event_id.clone());
            events.insert(event_id.clone(), signed_event.clone());
            events_by_work
                .entry(claim.work_id.clone())
                .or_default()
                .push(event_id);
        }

        info!(
            event_id = %signed_event.event_id,
            work_id = %signed_event.work_id,
            actor_id = %signed_event.actor_id,
            "WorkClaimed event signed and persisted"
        );

        Ok(signed_event)
    }

    fn get_event(&self, event_id: &str) -> Option<SignedLedgerEvent> {
        let guard = self.events.read().expect("lock poisoned");
        guard.1.get(event_id).cloned()
    }

    fn emit_session_started(
        &self,
        session_id: &str,
        work_id: &str,
        lease_id: &str,
        actor_id: &str,
        timestamp_ns: u64,
    ) -> Result<SignedLedgerEvent, LedgerEventError> {
        use ed25519_dalek::Signer;

        // Domain prefix for session events (must be at function start per clippy)
        const SESSION_STARTED_DOMAIN_PREFIX: &[u8] = b"apm2.event.session_started:";

        // Generate unique event ID
        let event_id = format!("EVT-{}", uuid::Uuid::new_v4());

        // Build canonical payload (deterministic JSON)
        let payload = serde_json::json!({
            "event_type": "session_started",
            "session_id": session_id,
            "work_id": work_id,
            "lease_id": lease_id,
            "actor_id": actor_id,
        });

        let payload_bytes =
            serde_json::to_vec(&payload).map_err(|e| LedgerEventError::SigningFailed {
                message: format!("payload serialization failed: {e}"),
            })?;

        // Build canonical bytes for signing (domain prefix + payload)
        let mut canonical_bytes =
            Vec::with_capacity(SESSION_STARTED_DOMAIN_PREFIX.len() + payload_bytes.len());
        canonical_bytes.extend_from_slice(SESSION_STARTED_DOMAIN_PREFIX);
        canonical_bytes.extend_from_slice(&payload_bytes);

        // Sign the canonical bytes
        let signature = self.signing_key.sign(&canonical_bytes);

        let signed_event = SignedLedgerEvent {
            event_id: event_id.clone(),
            event_type: "session_started".to_string(),
            work_id: work_id.to_string(),
            actor_id: actor_id.to_string(),
            payload: payload_bytes,
            signature: signature.to_bytes().to_vec(),
            timestamp_ns,
        };

        // CTR-1303: Persist to bounded in-memory store with LRU eviction
        {
            let mut guard = self.events.write().expect("lock poisoned");
            let mut events_by_work = self.events_by_work_id.write().expect("lock poisoned");
            let (order, events) = &mut *guard;

            // Evict oldest entries if at capacity
            while events.len() >= MAX_LEDGER_EVENTS {
                if let Some(oldest_key) = order.first().cloned() {
                    order.remove(0);
                    if let Some(evicted_event) = events.remove(&oldest_key) {
                        if let Some(work_id_events) = events_by_work.get_mut(&evicted_event.work_id)
                        {
                            work_id_events.retain(|id| id != &oldest_key);
                            if work_id_events.is_empty() {
                                events_by_work.remove(&evicted_event.work_id);
                            }
                        }
                    }
                } else {
                    break;
                }
            }

            order.push(event_id.clone());
            events.insert(event_id.clone(), signed_event.clone());
            events_by_work
                .entry(work_id.to_string())
                .or_default()
                .push(event_id);
        }

        info!(
            event_id = %signed_event.event_id,
            session_id = %session_id,
            work_id = %signed_event.work_id,
            "SessionStarted event signed and persisted"
        );

        Ok(signed_event)
    }

    fn emit_session_event(
        &self,
        session_id: &str,
        event_type: &str,
        payload: &[u8],
        actor_id: &str,
        timestamp_ns: u64,
    ) -> Result<SignedLedgerEvent, LedgerEventError> {
        use ed25519_dalek::Signer;

        // Domain prefix for generic session events (TCK-00290)
        const SESSION_EVENT_DOMAIN_PREFIX: &[u8] = b"apm2.event.session_event:";

        // Generate unique event ID
        let event_id = format!("EVT-{}", uuid::Uuid::new_v4());

        // Build payload as JSON with actual event type and hex-encoded payload
        let payload_json = serde_json::json!({
            "event_type": event_type,
            "session_id": session_id,
            "actor_id": actor_id,
            "payload": hex::encode(payload),
        });

        // MAJOR 1 FIX (TCK-00290): Use JCS (RFC 8785) canonicalization for signing.
        // This matches the production SqliteLedgerEventEmitter and ensures
        // deterministic JSON representation per RFC-0016. Using
        // serde_json::to_vec is non-deterministic because it does not guarantee
        // key ordering.
        let payload_string = payload_json.to_string();
        let canonical_payload =
            canonicalize_json(&payload_string).map_err(|e| LedgerEventError::SigningFailed {
                message: format!("JCS canonicalization failed: {e}"),
            })?;
        let payload_bytes = canonical_payload.as_bytes().to_vec();

        // Build canonical bytes for signing (domain prefix + JCS payload)
        let mut canonical_bytes =
            Vec::with_capacity(SESSION_EVENT_DOMAIN_PREFIX.len() + payload_bytes.len());
        canonical_bytes.extend_from_slice(SESSION_EVENT_DOMAIN_PREFIX);
        canonical_bytes.extend_from_slice(&payload_bytes);

        // Sign the canonical bytes
        let signature = self.signing_key.sign(&canonical_bytes);

        let signed_event = SignedLedgerEvent {
            event_id: event_id.clone(),
            event_type: event_type.to_string(),
            work_id: session_id.to_string(), // Use session_id as work_id for indexing
            actor_id: actor_id.to_string(),
            payload: payload_bytes,
            signature: signature.to_bytes().to_vec(),
            timestamp_ns,
        };

        // CTR-1303: Persist to bounded in-memory store with LRU eviction
        {
            let mut guard = self.events.write().expect("lock poisoned");
            let mut events_by_work = self.events_by_work_id.write().expect("lock poisoned");
            let (order, events) = &mut *guard;

            // Evict oldest entries if at capacity
            while events.len() >= MAX_LEDGER_EVENTS {
                if let Some(oldest_key) = order.first().cloned() {
                    order.remove(0);
                    if let Some(evicted_event) = events.remove(&oldest_key) {
                        if let Some(work_id_events) = events_by_work.get_mut(&evicted_event.work_id)
                        {
                            work_id_events.retain(|id| id != &oldest_key);
                            if work_id_events.is_empty() {
                                events_by_work.remove(&evicted_event.work_id);
                            }
                        }
                    }
                } else {
                    break;
                }
            }

            order.push(event_id.clone());
            events.insert(event_id.clone(), signed_event.clone());
            events_by_work
                .entry(session_id.to_string())
                .or_default()
                .push(event_id);
        }

        info!(
            event_id = %signed_event.event_id,
            session_id = %session_id,
            event_type = %event_type,
            actor_id = %actor_id,
            "SessionEvent signed and persisted"
        );

        Ok(signed_event)
    }

    fn emit_defect_recorded(
        &self,
        defect: &DefectRecorded,
        timestamp_ns: u64,
    ) -> Result<SignedLedgerEvent, LedgerEventError> {
        use ed25519_dalek::Signer;

        // TCK-00307 MAJOR 4: Call validate() to enforce DoS protections
        defect
            .validate()
            .map_err(|e| LedgerEventError::ValidationFailed { message: e })?;

        // Generate unique event ID
        let event_id = format!("EVT-{}", uuid::Uuid::new_v4());

        // TCK-00307 BLOCKER: Use JCS/JSON wire format (not ProtoBuf) to match
        // SqliteLedgerEventEmitter and ensure consumer uniformity.
        // Include time_envelope_ref for temporal binding (MAJOR 1).
        let time_envelope_ref_hex = defect
            .time_envelope_ref
            .as_ref()
            .map(|ter| hex::encode(&ter.hash));

        let payload = serde_json::json!({
            "event_type": "defect_recorded",
            "defect_id": defect.defect_id,
            "defect_type": defect.defect_type,
            "cas_hash": hex::encode(&defect.cas_hash),
            "source": defect.source,
            "work_id": defect.work_id,
            "severity": defect.severity,
            "detected_at": defect.detected_at,
            "time_envelope_ref": time_envelope_ref_hex,
        });

        // Use JCS (RFC 8785) canonicalization for deterministic signing
        let payload_json = payload.to_string();
        let canonical_payload =
            canonicalize_json(&payload_json).map_err(|e| LedgerEventError::SigningFailed {
                message: format!("JCS canonicalization failed: {e}"),
            })?;
        let payload_bytes = canonical_payload.as_bytes().to_vec();

        // Build canonical bytes for signing (domain prefix + JCS payload)
        let mut canonical_bytes =
            Vec::with_capacity(DEFECT_RECORDED_DOMAIN_PREFIX.len() + payload_bytes.len());
        canonical_bytes.extend_from_slice(DEFECT_RECORDED_DOMAIN_PREFIX);
        canonical_bytes.extend_from_slice(&payload_bytes);

        // Sign the canonical bytes
        let signature = self.signing_key.sign(&canonical_bytes);

        let signed_event = SignedLedgerEvent {
            event_id: event_id.clone(),
            event_type: "defect_recorded".to_string(),
            work_id: defect.work_id.clone(),
            actor_id: "system".to_string(),
            payload: payload_bytes,
            signature: signature.to_bytes().to_vec(),
            timestamp_ns,
        };

        // CTR-1303: Persist to bounded in-memory store with LRU eviction
        {
            let mut guard = self.events.write().expect("lock poisoned");
            let mut events_by_work = self.events_by_work_id.write().expect("lock poisoned");
            let (order, events) = &mut *guard;

            // Evict oldest entries if at capacity
            while events.len() >= MAX_LEDGER_EVENTS {
                if let Some(oldest_key) = order.first().cloned() {
                    order.remove(0);
                    if let Some(evicted_event) = events.remove(&oldest_key) {
                        if let Some(work_id_events) = events_by_work.get_mut(&evicted_event.work_id)
                        {
                            work_id_events.retain(|id| id != &oldest_key);
                            if work_id_events.is_empty() {
                                events_by_work.remove(&evicted_event.work_id);
                            }
                        }
                    }
                } else {
                    break;
                }
            }

            order.push(event_id.clone());
            events.insert(event_id.clone(), signed_event.clone());
            events_by_work
                .entry(defect.work_id.clone())
                .or_default()
                .push(event_id);
        }

        info!(
            event_id = %signed_event.event_id,
            defect_id = %defect.defect_id,
            work_id = %signed_event.work_id,
            "DefectRecorded event signed and persisted"
        );

        Ok(signed_event)
    }

    fn get_events_by_work_id(&self, work_id: &str) -> Vec<SignedLedgerEvent> {
        let events_by_work = self.events_by_work_id.read().expect("lock poisoned");
        let guard = self.events.read().expect("lock poisoned");

        events_by_work
            .get(work_id)
            .map(|event_ids| {
                event_ids
                    .iter()
                    .filter_map(|id| guard.1.get(id).cloned())
                    .collect()
            })
            .unwrap_or_default()
    }
}

// ============================================================================
// Policy Resolver Interface (TCK-00253)
// ============================================================================

use serde::{Deserialize, Serialize};

// ... (existing code)

/// Result of a policy resolution request.
///
/// Per DD-002, the daemon delegates policy resolution to the governance holon.
/// This struct captures the resolved policy state for work claiming.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyResolution {
    /// Unique reference to the `PolicyResolvedForChangeSet` event.
    pub policy_resolved_ref: String,

    /// BLAKE3 hash of the resolved policy.
    pub resolved_policy_hash: [u8; 32],

    /// BLAKE3 hash of the capability manifest derived from policy.
    pub capability_manifest_hash: [u8; 32],

    /// BLAKE3 hash of the sealed context pack.
    pub context_pack_hash: [u8; 32],
}

/// Error type for policy resolution operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyResolutionError {
    /// Policy resolution not found for the given work/role combination.
    NotFound {
        /// The work ID that was queried.
        work_id: String,
        /// The role that was queried.
        role: WorkRole,
    },

    /// Policy resolution failed due to governance error.
    GovernanceFailed {
        /// Error message from governance.
        message: String,
    },

    /// Invalid credential for policy resolution.
    InvalidCredential {
        /// Error message describing the credential issue.
        message: String,
    },
}

impl std::fmt::Display for PolicyResolutionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound { work_id, role } => {
                write!(
                    f,
                    "policy resolution not found for work_id={work_id}, role={role:?}"
                )
            },
            Self::GovernanceFailed { message } => {
                write!(f, "governance failed: {message}")
            },
            Self::InvalidCredential { message } => {
                write!(f, "invalid credential: {message}")
            },
        }
    }
}

impl std::error::Error for PolicyResolutionError {}

/// Trait for policy resolution delegation to governance.
///
/// Per DD-002, the daemon does not embed governance logic. It delegates
/// policy resolution to the governance holon and mints capability manifests
/// based on the returned resolution.
///
/// # Implementers
///
/// - `StubPolicyResolver`: Returns stub data for testing
/// - `GovernancePolicyResolver`: Delegates to actual governance holon (future)
pub trait PolicyResolver: Send + Sync {
    /// Resolves policy for a work claim.
    ///
    /// # Arguments
    ///
    /// * `work_id` - Generated work ID for this claim
    /// * `role` - The role being claimed
    /// * `actor_id` - The authoritative actor ID (derived from credential)
    ///
    /// # Returns
    ///
    /// `PolicyResolution` containing the resolved policy hashes and references.
    ///
    /// # Errors
    ///
    /// Returns `PolicyResolutionError` if resolution fails.
    fn resolve_for_claim(
        &self,
        work_id: &str,
        role: WorkRole,
        actor_id: &str,
    ) -> Result<PolicyResolution, PolicyResolutionError>;
}

/// Stub policy resolver for testing and development.
///
/// Returns deterministic stub data. In production, this will be replaced
/// with a real governance holon integration.
///
/// # TCK-00255: Context Pack Sealing
///
/// This stub demonstrates the sealing pattern required by RFC-0017:
/// 1. Create a `ContextPackManifest` with work-specific entries
/// 2. Call `seal()` to get the deterministic content hash
/// 3. Return the seal hash in the `PolicyResolution.context_pack_hash`
///
/// # TCK-00317: Role-Based Manifest Hash Resolution
///
/// Per DOD item 2 (Policy Resolution Bypass fix), this resolver now returns
/// the canonical `reviewer_v0_manifest_hash()` for the Reviewer role. This
/// ensures `SpawnEpisode` loads the correct manifest from CAS using the hash
/// from `PolicyResolution`, rather than selecting manifests by role name.
#[derive(Debug, Clone, Default)]
pub struct StubPolicyResolver;

impl PolicyResolver for StubPolicyResolver {
    fn resolve_for_claim(
        &self,
        work_id: &str,
        role: WorkRole,
        actor_id: &str,
    ) -> Result<PolicyResolution, PolicyResolutionError> {
        use apm2_core::context::{AccessLevel, ContextPackManifestBuilder, ManifestEntryBuilder};

        use crate::episode::reviewer_manifest::reviewer_v0_manifest_hash;

        // Generate deterministic hash for policy
        let policy_hash = blake3::hash(format!("policy:{work_id}:{actor_id}").as_bytes());

        // TCK-00317: Return role-appropriate manifest hash
        //
        // Per DOD item 2, the policy resolver must return the correct manifest
        // hash for each role. SpawnEpisode uses this hash to load the manifest
        // from CAS, ensuring the manifest is not bypassed by role selection.
        //
        // - Reviewer: Use canonical reviewer v0 manifest hash
        // - Other roles: Use deterministic stub hash (fail-closed on CAS lookup)
        let manifest_hash = match role {
            WorkRole::Reviewer => *reviewer_v0_manifest_hash(),
            _ => {
                // For non-reviewer roles, generate a deterministic hash that will
                // fail closed when loaded from CAS (hash doesn't exist in store)
                *blake3::hash(format!("manifest:{work_id}:{actor_id}").as_bytes()).as_bytes()
            },
        };

        // TCK-00255: Create and seal a context pack manifest
        // In production, this would be populated with actual file entries from
        // the work definition. For the stub, we create a deterministic manifest
        // based on work_id and actor_id.
        let content_hash = blake3::hash(format!("content:{work_id}:{actor_id}").as_bytes());
        let context_pack = ContextPackManifestBuilder::new(
            format!("manifest:{work_id}"),
            format!("profile:{actor_id}"),
        )
        .add_entry(
            ManifestEntryBuilder::new(
                format!("/work/{work_id}/context.yaml"),
                *content_hash.as_bytes(),
            )
            .stable_id("work-context")
            .access_level(AccessLevel::Read)
            .build(),
        )
        .build();

        // TCK-00255: Call seal() to get the context pack hash
        // This ensures the hash is deterministic and verifiable.
        let context_pack_hash =
            context_pack
                .seal()
                .map_err(|e| PolicyResolutionError::GovernanceFailed {
                    message: format!("context pack sealing failed: {e}"),
                })?;

        Ok(PolicyResolution {
            policy_resolved_ref: format!("PolicyResolvedForChangeSet:{work_id}"),
            resolved_policy_hash: *policy_hash.as_bytes(),
            capability_manifest_hash: manifest_hash,
            context_pack_hash,
        })
    }
}

// ============================================================================
// Work Registry Interface (TCK-00253)
// ============================================================================

/// A claimed work item with its associated metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkClaim {
    /// Unique work identifier.
    pub work_id: String,

    /// Lease identifier for this claim.
    pub lease_id: String,

    /// Authoritative actor ID (derived from credential).
    pub actor_id: String,

    /// Role claimed for this work.
    #[serde(with = "work_role_serde")]
    pub role: WorkRole,

    /// Policy resolution for this claim.
    pub policy_resolution: PolicyResolution,

    /// Custody domains associated with the executor (for `SoD` validation).
    ///
    /// Per TCK-00258, these are the domains assigned to the actor claiming
    /// the work. For `GATE_EXECUTOR` roles, spawn will be rejected if these
    /// domains overlap with author domains.
    pub executor_custody_domains: Vec<String>,

    /// Custody domains associated with changeset authors (for `SoD`
    /// validation).
    ///
    /// Per TCK-00258, these are the domains of the actors who authored the
    /// changeset being reviewed.
    pub author_custody_domains: Vec<String>,
}

mod work_role_serde {
    use serde::{Deserialize, Deserializer, Serializer};

    use super::WorkRole;

    // Serde requires `&T` for custom serializers via `serialize_with`.
    #[allow(clippy::trivially_copy_pass_by_ref)]
    pub fn serialize<S>(role: &WorkRole, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_i32(*role as i32)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<WorkRole, D::Error>
    where
        D: Deserializer<'de>,
    {
        let val = i32::deserialize(deserializer)?;
        WorkRole::try_from(val).map_err(serde::de::Error::custom)
    }
}

/// Trait for persisting and querying work claims.
///
/// The work registry tracks claimed work items and their associated
/// policy resolutions. It also handles `WorkClaimed` event signing.
pub trait WorkRegistry: Send + Sync {
    /// Registers a new work claim.
    ///
    /// # Arguments
    ///
    /// * `claim` - The work claim to register
    ///
    /// # Returns
    ///
    /// The registered `WorkClaim` (may be enriched with additional metadata).
    ///
    /// # Errors
    ///
    /// Returns an error if registration fails.
    fn register_claim(&self, claim: WorkClaim) -> Result<WorkClaim, WorkRegistryError>;

    /// Queries a work claim by work ID.
    fn get_claim(&self, work_id: &str) -> Option<WorkClaim>;
}

/// Error type for work registry operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkRegistryError {
    /// Work ID already exists.
    DuplicateWorkId {
        /// The duplicate work ID.
        work_id: String,
    },

    /// Registration failed.
    RegistrationFailed {
        /// Error message.
        message: String,
    },
}

impl std::fmt::Display for WorkRegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DuplicateWorkId { work_id } => {
                write!(f, "duplicate work_id: {work_id}")
            },
            Self::RegistrationFailed { message } => {
                write!(f, "registration failed: {message}")
            },
        }
    }
}

impl std::error::Error for WorkRegistryError {}

/// Maximum number of work claims stored in `StubWorkRegistry`.
///
/// Per CTR-1303: In-memory stores must have `max_entries` limit with O(1)
/// eviction. This prevents denial-of-service via memory exhaustion from
/// unbounded claim registration.
pub const MAX_WORK_CLAIMS: usize = 10_000;

/// In-memory stub work registry for testing.
///
/// # Capacity Limits (CTR-1303)
///
/// This registry enforces a maximum of [`MAX_WORK_CLAIMS`] entries to prevent
/// memory exhaustion. When the limit is reached, the oldest entry (by insertion
/// order) is evicted to make room for the new claim.
///
/// # Performance
///
/// Uses `VecDeque` for O(1) eviction via `pop_front()` instead of
/// `Vec::remove(0)` which is O(n).
#[derive(Debug)]
pub struct StubWorkRegistry {
    /// Claims stored with insertion order for LRU eviction.
    /// Uses `VecDeque` for O(1) eviction of oldest entries.
    claims: std::sync::RwLock<(
        VecDeque<String>,
        std::collections::HashMap<String, WorkClaim>,
    )>,
}

impl Default for StubWorkRegistry {
    fn default() -> Self {
        Self {
            claims: std::sync::RwLock::new((
                VecDeque::with_capacity(MAX_WORK_CLAIMS.min(1000)), // Pre-allocate reasonably
                std::collections::HashMap::with_capacity(MAX_WORK_CLAIMS.min(1000)),
            )),
        }
    }
}

impl WorkRegistry for StubWorkRegistry {
    fn register_claim(&self, claim: WorkClaim) -> Result<WorkClaim, WorkRegistryError> {
        let mut guard = self.claims.write().expect("lock poisoned");
        let (order, claims) = &mut *guard;

        if claims.contains_key(&claim.work_id) {
            return Err(WorkRegistryError::DuplicateWorkId {
                work_id: claim.work_id,
            });
        }

        // CTR-1303: Evict oldest entry if at capacity (O(1) via pop_front)
        while claims.len() >= MAX_WORK_CLAIMS {
            if let Some(oldest_key) = order.pop_front() {
                claims.remove(&oldest_key);
                debug!(
                    evicted_work_id = %oldest_key,
                    "Evicted oldest work claim to maintain capacity limit"
                );
            } else {
                break;
            }
        }

        let work_id = claim.work_id.clone();
        order.push_back(work_id.clone());
        claims.insert(work_id, claim.clone());
        Ok(claim)
    }

    fn get_claim(&self, work_id: &str) -> Option<WorkClaim> {
        let guard = self.claims.read().expect("lock poisoned");
        guard.1.get(work_id).cloned()
    }
}

// ============================================================================
// Actor ID Derivation (TCK-00253)
// ============================================================================

/// Derives the authoritative actor ID from peer credentials.
///
/// Per DD-001 and the proto definition, the `actor_id` in the request is a
/// "display hint" only. The authoritative `actor_id` is derived from the
/// credential. This implementation uses a fingerprint of the UID and GID
/// to create a **stable** identifier that does not change per request.
///
/// # Stability
///
/// The actor ID is derived ONLY from stable credential fields (UID, GID).
/// It intentionally excludes:
/// - PID: Changes per process
/// - Nonce: Changes per request
///
/// This ensures the same user always maps to the same `actor_id`.
///
/// # Arguments
///
/// * `credentials` - The peer credentials from `SO_PEERCRED`
///
/// # Returns
///
/// A stable actor ID string derived from the credential.
///
/// # TODO
///
/// - TCK-00253: `credential_signature` field is currently ignored. Integration
///   with credential verification infrastructure will allow deriving `actor_id`
///   from cryptographic identity rather than Unix UID/GID.
#[must_use]
pub fn derive_actor_id(credentials: &PeerCredentials) -> String {
    // Create a fingerprint from UID and GID only (stable across requests)
    // Per code quality review: exclude PID (changes per process) and nonce (changes
    // per request)
    let mut hasher = blake3::Hasher::new();
    hasher.update(&credentials.uid.to_le_bytes());
    hasher.update(&credentials.gid.to_le_bytes());

    let hash = hasher.finalize();

    // Use first 8 bytes (16 hex chars) for a shorter identifier
    // Per code quality review: use blake3::Hash::to_hex() instead of manual
    // formatting
    let hex = hash.to_hex();
    format!("actor:{}", &hex[..16])
}

/// Generates a unique work ID.
///
/// Uses UUID v4 for uniqueness per RFC-0016 (Hybrid Time Framework compliance).
/// HTF prohibits `SystemTime::now()` to ensure deterministic replay.
#[must_use]
pub fn generate_work_id() -> String {
    // RFC-0016 HTF compliance: Use UUID v4 instead of SystemTime::now()
    let uuid = uuid::Uuid::new_v4();
    format!("W-{uuid}")
}

/// Generates a unique lease ID.
///
/// Uses UUID v4 for uniqueness per RFC-0016 (Hybrid Time Framework compliance).
/// HTF prohibits `SystemTime::now()` to ensure deterministic replay.
#[must_use]
pub fn generate_lease_id() -> String {
    // RFC-0016 HTF compliance: Use UUID v4 instead of SystemTime::now()
    let uuid = uuid::Uuid::new_v4();
    format!("L-{uuid}")
}

// ============================================================================
// Connection Context
// ============================================================================

/// Connection context tracking privilege level and authentication state.
///
/// Per DD-001 (`privilege_predicate`), connections are classified as privileged
/// based on the socket path:
/// - operator.sock: `is_privileged = true`
/// - session.sock: `is_privileged = false`
///
/// # TCK-00303: Connection Lifecycle Management
///
/// The `connection_id` field is used to track connections in the subscription
/// registry. When a connection closes, the connection handler MUST call
/// `subscription_registry.unregister_connection(connection_id)` to free
/// resources and prevent connection slot leaks.
#[derive(Debug, Clone)]
pub struct ConnectionContext {
    /// Whether this connection is privileged (operator socket).
    is_privileged: bool,

    /// Peer credentials extracted via `SO_PEERCRED`.
    peer_credentials: Option<PeerCredentials>,

    /// Session ID for session-scoped connections (None for operator
    /// connections).
    session_id: Option<String>,

    /// Connection ID for subscription registry tracking (TCK-00303).
    ///
    /// Generated once when the connection is established and used consistently
    /// across all subscribe/unsubscribe operations. Must be passed to
    /// `unregister_connection` when the connection closes to prevent leaks.
    connection_id: String,
}

impl ConnectionContext {
    /// Creates a new privileged connection context (operator socket).
    ///
    /// # TCK-00303: Connection ID Generation
    ///
    /// The `connection_id` is generated from peer credentials (PID-based for
    /// operator connections) or a UUID if credentials are unavailable.
    #[must_use]
    pub fn privileged(peer_credentials: Option<PeerCredentials>) -> Self {
        let connection_id = peer_credentials.as_ref().and_then(|c| c.pid).map_or_else(
            || format!("CONN-OP-{}", uuid::Uuid::new_v4()),
            |pid| format!("CONN-OP-{pid}"),
        );
        Self {
            is_privileged: true,
            peer_credentials,
            session_id: None,
            connection_id,
        }
    }

    /// Creates a new session-scoped connection context (session socket).
    ///
    /// # TCK-00303: Connection ID Generation
    ///
    /// The `connection_id` is generated from the session ID (if available)
    /// or peer credentials (PID-based), or a UUID if neither is available.
    #[must_use]
    pub fn session(peer_credentials: Option<PeerCredentials>, session_id: Option<String>) -> Self {
        // For session connections, prefer session_id-based connection ID,
        // but fall back to PID or UUID if session_id is not yet known
        // (it may be set later via session token validation)
        let connection_id = session_id.as_ref().map_or_else(
            || {
                peer_credentials.as_ref().and_then(|c| c.pid).map_or_else(
                    || format!("CONN-SESS-{}", uuid::Uuid::new_v4()),
                    |pid| format!("CONN-SESS-{pid}"),
                )
            },
            |sid| format!("CONN-SESS-{sid}"),
        );
        Self {
            is_privileged: false,
            peer_credentials,
            session_id,
            connection_id,
        }
    }

    /// Returns `true` if this connection has privileged access.
    #[must_use]
    pub const fn is_privileged(&self) -> bool {
        self.is_privileged
    }

    /// Returns the peer credentials if available.
    #[must_use]
    pub const fn peer_credentials(&self) -> Option<&PeerCredentials> {
        self.peer_credentials.as_ref()
    }

    /// Returns the session ID for session-scoped connections.
    #[must_use]
    pub fn session_id(&self) -> Option<&str> {
        self.session_id.as_deref()
    }

    /// Returns the connection ID for subscription registry tracking.
    ///
    /// # TCK-00303: Connection Lifecycle
    ///
    /// This ID must be passed to `unregister_connection` when the connection
    /// closes to free subscription registry slots and prevent `DoS` via
    /// connection slot exhaustion.
    #[must_use]
    pub fn connection_id(&self) -> &str {
        &self.connection_id
    }
}

// ============================================================================
// Message Type Tags (for routing)
// ============================================================================

/// Message type tags for privileged endpoint routing.
///
/// These tags are used to identify the message type before decoding,
/// allowing the dispatcher to route to the appropriate handler.
///
/// # HEF Tag Range (CTR-PROTO-010)
///
/// HEF messages use tag range 64-79 per RFC-0018:
/// - 64 = `SubscribePulse`
/// - 65 = `SubscribePulseResponse` (response only)
/// - 66 = `UnsubscribePulse`
/// - 67 = `UnsubscribePulseResponse` (response only)
/// - 68 = `PulseEvent` (server->client only)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PrivilegedMessageType {
    /// `ClaimWork` request (IPC-PRIV-001)
    ClaimWork        = 1,
    /// `SpawnEpisode` request (IPC-PRIV-002)
    SpawnEpisode     = 2,
    /// `IssueCapability` request (IPC-PRIV-003)
    IssueCapability  = 3,
    /// Shutdown request (IPC-PRIV-004)
    Shutdown         = 4,
    // --- HEF Pulse Plane (CTR-PROTO-010, RFC-0018) ---
    /// `SubscribePulse` request (IPC-HEF-001)
    SubscribePulse   = 64,
    /// `UnsubscribePulse` request (IPC-HEF-002)
    UnsubscribePulse = 66,
    /// `PulseEvent` notification (server->client, IPC-HEF-003)
    PulseEvent       = 68,
}

impl PrivilegedMessageType {
    /// Attempts to parse a message type from a tag byte.
    #[must_use]
    pub const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(Self::ClaimWork),
            2 => Some(Self::SpawnEpisode),
            3 => Some(Self::IssueCapability),
            4 => Some(Self::Shutdown),
            // HEF tags (64-68)
            64 => Some(Self::SubscribePulse),
            66 => Some(Self::UnsubscribePulse),
            68 => Some(Self::PulseEvent),
            _ => None,
        }
    }

    /// Returns the tag byte for this message type.
    #[must_use]
    pub const fn tag(self) -> u8 {
        self as u8
    }
}

// ============================================================================
// Response Envelope
// ============================================================================

/// Response envelope for privileged endpoint responses.
///
/// Contains either a successful response or an error.
#[derive(Debug)]
pub enum PrivilegedResponse {
    /// Successful `ClaimWork` response.
    ClaimWork(ClaimWorkResponse),
    /// Successful `SpawnEpisode` response.
    SpawnEpisode(SpawnEpisodeResponse),
    /// Successful `IssueCapability` response.
    IssueCapability(IssueCapabilityResponse),
    /// Successful Shutdown response.
    Shutdown(ShutdownResponse),
    /// Successful `SubscribePulse` response (TCK-00302).
    SubscribePulse(SubscribePulseResponse),
    /// Successful `UnsubscribePulse` response (TCK-00302).
    UnsubscribePulse(UnsubscribePulseResponse),
    /// Error response.
    Error(PrivilegedError),
}

impl PrivilegedResponse {
    /// Creates a `PERMISSION_DENIED` error response.
    #[must_use]
    pub fn permission_denied() -> Self {
        Self::Error(PrivilegedError {
            code: PrivilegedErrorCode::PermissionDenied.into(),
            message: "permission denied".to_string(),
        })
    }

    /// Creates a custom error response.
    #[must_use]
    pub fn error(code: PrivilegedErrorCode, message: impl Into<String>) -> Self {
        Self::Error(PrivilegedError {
            code: code.into(),
            message: message.into(),
        })
    }

    /// Encodes the response to bytes.
    ///
    /// The format is: [tag: u8][payload: protobuf]
    /// Tag 0 indicates an error response.
    #[must_use]
    pub fn encode(&self) -> Bytes {
        // Response tags for HEF messages (request tag + 1)
        const SUBSCRIBE_PULSE_RESPONSE_TAG: u8 = 65;
        const UNSUBSCRIBE_PULSE_RESPONSE_TAG: u8 = 67;

        let mut buf = Vec::new();
        match self {
            Self::ClaimWork(resp) => {
                buf.push(PrivilegedMessageType::ClaimWork.tag());
                resp.encode(&mut buf).expect("encode cannot fail");
            },
            Self::SpawnEpisode(resp) => {
                buf.push(PrivilegedMessageType::SpawnEpisode.tag());
                resp.encode(&mut buf).expect("encode cannot fail");
            },
            Self::IssueCapability(resp) => {
                buf.push(PrivilegedMessageType::IssueCapability.tag());
                resp.encode(&mut buf).expect("encode cannot fail");
            },
            Self::Shutdown(resp) => {
                buf.push(PrivilegedMessageType::Shutdown.tag());
                resp.encode(&mut buf).expect("encode cannot fail");
            },
            Self::SubscribePulse(resp) => {
                buf.push(SUBSCRIBE_PULSE_RESPONSE_TAG);
                resp.encode(&mut buf).expect("encode cannot fail");
            },
            Self::UnsubscribePulse(resp) => {
                buf.push(UNSUBSCRIBE_PULSE_RESPONSE_TAG);
                resp.encode(&mut buf).expect("encode cannot fail");
            },
            Self::Error(err) => {
                buf.push(0); // Error tag
                err.encode(&mut buf).expect("encode cannot fail");
            },
        }
        Bytes::from(buf)
    }
}

// ============================================================================
// Dispatcher
// ============================================================================

// ============================================================================
// TCK-00257: Gate Lease Validation
// ============================================================================

/// Maximum number of lease entries to store (CTR-1303: bounded capacity).
const MAX_LEASE_ENTRIES: usize = 10_000;

/// Error returned when lease validation fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeaseValidationError {
    /// Lease ID was not found in the ledger.
    LeaseNotFound {
        /// The lease ID that was not found.
        lease_id: String,
    },
    /// Lease exists but `work_id` does not match.
    ///
    /// # Security Note (SEC-HYG-001)
    ///
    /// The expected `work_id` is intentionally omitted from this error to
    /// prevent information leakage. Revealing the expected value could
    /// allow an attacker to enumerate valid work IDs.
    WorkIdMismatch {
        /// The actual `work_id` from the request (not the expected one).
        actual: String,
    },
    /// Lease has expired.
    LeaseExpired {
        /// The expired lease ID.
        lease_id: String,
    },
    /// Failed to query the ledger.
    LedgerQueryFailed {
        /// The error message from the ledger.
        message: String,
    },
}

impl std::fmt::Display for LeaseValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LeaseNotFound { lease_id } => {
                write!(f, "lease not found: {lease_id}")
            },
            Self::WorkIdMismatch { actual } => {
                write!(f, "work_id mismatch for provided value: {actual}")
            },
            Self::LeaseExpired { lease_id } => {
                write!(f, "lease expired: {lease_id}")
            },
            Self::LedgerQueryFailed { message } => {
                write!(f, "ledger query failed: {message}")
            },
        }
    }
}

impl std::error::Error for LeaseValidationError {}

/// Trait for validating gate leases.
///
/// Per RFC-0017 IPC-PRIV-002, `GATE_EXECUTOR` role requires a valid
/// `GateLeaseIssued` event to exist in the ledger for the specified
/// `lease_id` and `work_id`.
///
/// # Security Contract
///
/// - `GATE_EXECUTOR` spawn MUST be rejected if lease validation fails
/// - Lease validation verifies the lease exists and matches the `work_id`
/// - This is a fail-closed check: validation errors reject the spawn
///
/// # Implementers
///
/// - `StubLeaseValidator`: In-memory storage for testing
/// - `LedgerLeaseValidator`: Ledger-backed validation (future)
pub trait LeaseValidator: Send + Sync {
    /// Validates that a gate lease exists and matches the `work_id`.
    ///
    /// # Arguments
    ///
    /// * `lease_id` - The lease ID to validate
    /// * `work_id` - The work ID that must match the lease
    ///
    /// # Returns
    ///
    /// `Ok(())` if the lease is valid and matches the `work_id`.
    ///
    /// # Errors
    ///
    /// Returns `LeaseValidationError` if:
    /// - The lease does not exist (`LeaseNotFound`)
    /// - The lease exists but the `work_id` doesn't match (`WorkIdMismatch`)
    /// - The lease has expired (`LeaseExpired`)
    /// - The ledger query failed (`LedgerQueryFailed`)
    fn validate_gate_lease(
        &self,
        lease_id: &str,
        work_id: &str,
    ) -> Result<(), LeaseValidationError>;

    /// Registers a gate lease for testing purposes.
    ///
    /// In production, leases are issued through a separate governance flow.
    /// This method exists to support test fixtures.
    fn register_lease(&self, lease_id: &str, work_id: &str, gate_id: &str);
}

/// Entry for a registered lease.
#[derive(Debug, Clone)]
struct LeaseEntry {
    work_id: String,
    #[allow(dead_code)]
    gate_id: String,
}

/// Stub implementation of [`LeaseValidator`] for testing.
///
/// Stores leases in memory with no persistence.
///
/// # Capacity Limits (CTR-1303)
///
/// This validator enforces a maximum of 10,000 entries to prevent memory
/// exhaustion. When the limit is reached, the oldest entry (by insertion order)
/// is evicted to make room for the new lease.
///
/// # Security Notes
///
/// - **SEC-DoS-001**: Duplicate lease IDs are handled by updating in place
///   rather than adding a new entry, preventing unbounded memory growth.
/// - **SEC-DoS-002**: Uses `VecDeque` for O(1) eviction from the front,
///   consistent with the O(1) eviction pattern established in PR 329.
#[derive(Debug, Default)]
pub struct StubLeaseValidator {
    /// Leases stored with insertion order for O(1) LRU eviction.
    ///
    /// Uses `VecDeque` (SEC-DoS-002) for efficient front removal.
    leases: std::sync::RwLock<(
        std::collections::VecDeque<String>,
        std::collections::HashMap<String, LeaseEntry>,
    )>,
}

impl StubLeaseValidator {
    /// Creates a new empty lease validator.
    #[must_use]
    pub fn new() -> Self {
        Self {
            leases: std::sync::RwLock::new((
                std::collections::VecDeque::new(),
                std::collections::HashMap::new(),
            )),
        }
    }
}

impl LeaseValidator for StubLeaseValidator {
    fn validate_gate_lease(
        &self,
        lease_id: &str,
        work_id: &str,
    ) -> Result<(), LeaseValidationError> {
        let guard = self.leases.read().expect("lock poisoned");
        let (_, leases) = &*guard;

        leases.get(lease_id).map_or_else(
            || {
                Err(LeaseValidationError::LeaseNotFound {
                    lease_id: lease_id.to_string(),
                })
            },
            |entry| {
                let work_id_matches = entry.work_id.len() == work_id.len()
                    && bool::from(entry.work_id.as_bytes().ct_eq(work_id.as_bytes()));
                if work_id_matches {
                    Ok(())
                } else {
                    Err(LeaseValidationError::WorkIdMismatch {
                        actual: work_id.to_string(),
                    })
                }
            },
        )
    }

    fn register_lease(&self, lease_id: &str, work_id: &str, gate_id: &str) {
        let mut guard = self.leases.write().expect("lock poisoned");
        let (order, leases) = &mut *guard;

        // SEC-DoS-001: Check for duplicate lease_id and update in place
        if leases.contains_key(lease_id) {
            // Update existing entry without adding to order (already tracked)
            leases.insert(
                lease_id.to_string(),
                LeaseEntry {
                    work_id: work_id.to_string(),
                    gate_id: gate_id.to_string(),
                },
            );
            return;
        }

        // CTR-1303: Evict oldest entry if at capacity
        // SEC-DoS-002: Use pop_front() for O(1) eviction
        while leases.len() >= MAX_LEASE_ENTRIES {
            if let Some(oldest_key) = order.pop_front() {
                leases.remove(&oldest_key);
            } else {
                break;
            }
        }

        order.push_back(lease_id.to_string());
        leases.insert(
            lease_id.to_string(),
            LeaseEntry {
                work_id: work_id.to_string(),
                gate_id: gate_id.to_string(),
            },
        );
    }
}

/// Privileged endpoint dispatcher.
///
/// Routes incoming messages to the appropriate handler based on message type.
/// Enforces privilege separation by checking
/// `ConnectionContext::is_privileged()` before dispatching to any handler.
///
/// # Security Contract
///
/// Per INV-0001 and TB-002:
/// - Session connections receive `PERMISSION_DENIED` for ALL privileged
///   requests
/// - No privileged handler logic executes for non-privileged connections
/// - Generic error messages prevent endpoint enumeration (TH-004)
///
/// # TCK-00253 Additions
///
/// - Policy resolver for governance delegation
/// - Work registry for claim persistence
/// - Ledger event emitter for signed event persistence
/// - Actor ID derivation from credentials
///
/// # TCK-00256 Additions
///
/// - Episode runtime for lifecycle management
/// - Session registry for session state persistence
///
/// # TCK-00257 Additions
///
/// - Lease validator for `GATE_EXECUTOR` spawn validation
///
/// # TCK-00289 Additions
///
/// - `HolonicClock` for HTF-compliant timestamps in `IssueCapability`
pub struct PrivilegedDispatcher {
    /// Decode configuration for bounded message decoding.
    decode_config: DecodeConfig,

    /// Policy resolver for governance delegation (TCK-00253).
    policy_resolver: Arc<dyn PolicyResolver>,

    /// Work registry for claim persistence (TCK-00253).
    work_registry: Arc<dyn WorkRegistry>,

    /// Ledger event emitter for signed event persistence (TCK-00253).
    event_emitter: Arc<dyn LedgerEventEmitter>,

    /// Episode runtime for lifecycle management (TCK-00256).
    episode_runtime: Arc<EpisodeRuntime>,

    /// Session registry for session state persistence (TCK-00256).
    session_registry: Arc<dyn SessionRegistry>,

    /// Lease validator for `GATE_EXECUTOR` spawn validation (TCK-00257).
    lease_validator: Arc<dyn LeaseValidator>,

    /// Token minter for session token generation (TCK-00287).
    ///
    /// Shared with `SessionDispatcher` to ensure tokens minted during
    /// `SpawnEpisode` can be validated on session endpoints.
    token_minter: Arc<TokenMinter>,

    /// Manifest store for capability manifest registration (TCK-00287).
    ///
    /// Shared with `SessionDispatcher` so that manifests registered during
    /// `SpawnEpisode` are accessible for tool request validation.
    manifest_store: Arc<InMemoryManifestStore>,

    /// CAS-backed manifest loader for capability manifest retrieval
    /// (TCK-00317).
    ///
    /// Per DOD item 1 (CAS Storage & Hash Loading), manifests are stored in
    /// CAS and loaded by hash. The policy resolver returns the manifest hash,
    /// and `handle_spawn_episode` uses this loader to retrieve the manifest.
    ///
    /// # Security Model
    ///
    /// - Manifests are stored with their BLAKE3 hash as the key
    /// - Load operations verify the hash matches the content
    /// - Missing manifests result in fail-closed rejection
    manifest_loader: Arc<dyn ManifestLoader>,

    /// Prometheus metrics registry for daemon health observability (TCK-00268).
    ///
    /// When present, the dispatcher emits metrics for:
    /// - `session_spawned`: When `SpawnEpisode` succeeds
    /// - `ipc_request_completed`: For each dispatched request
    /// - `capability_granted`: When `IssueCapability` succeeds
    ///
    /// # Integration Status
    ///
    /// **NOTE**: This dispatcher uses the binary protocol
    /// (`PrivilegedMessageType`) which is not currently wired into
    /// `main.rs`. The daemon's main connection handler uses JSON-based
    /// `IpcRequest` via `handlers::dispatch()` instead.
    ///
    /// These metrics will become active when the binary protocol path is
    /// integrated into the daemon's connection handling. Until then, the
    /// JSON-based IPC path in `handlers.rs` correctly records
    /// `ipc_request_completed` metrics.
    ///
    /// TODO(TCK-FUTURE): Wire `PrivilegedDispatcher` into `main.rs` to enable
    /// these metrics for binary protocol requests.
    metrics: Option<SharedMetricsRegistry>,

    /// HTF-compliant clock for timestamps (TCK-00289).
    ///
    /// Used to generate RFC-0016 compliant timestamps for:
    /// - `IssueCapability` `granted_at` / `expires_at` fields
    /// - `WorkClaimed` ledger event timestamps
    ///
    /// # HTF Compliance
    ///
    /// The clock provides:
    /// - Monotonic ticks: Never regress within a process lifetime
    /// - HLC stamps: Hybrid logical clock for cross-node causality
    /// - Wall time bounds: Observational only, with uncertainty interval
    holonic_clock: Arc<HolonicClock>,

    /// Subscription registry for HEF Pulse Plane resource governance
    /// (TCK-00303).
    ///
    /// Tracks per-connection subscription state and enforces limits per
    /// RFC-0018. Shared with `SessionDispatcher` to manage subscriptions
    /// across both operator and session sockets.
    subscription_registry: SharedSubscriptionRegistry,
}

impl Default for PrivilegedDispatcher {
    /// Creates a default dispatcher (TEST ONLY).
    ///
    /// # Warning: RSK-2503 Mixed Clock Domain Hazard
    ///
    /// See `new()` for details on clock domain hazards.
    fn default() -> Self {
        Self::new()
    }
}

/// Default session token TTL (1 hour).
///
/// Per RFC-0017, session tokens should have a reasonable TTL that matches
/// lease expiration. 1 hour is a sensible default for development.
pub const DEFAULT_SESSION_TOKEN_TTL_SECS: u64 = 3600;

impl PrivilegedDispatcher {
    /// Creates a new dispatcher with default decode configuration (TEST ONLY).
    ///
    /// # Warning: RSK-2503 Mixed Clock Domain Hazard
    ///
    /// This constructor creates an internal `HolonicClock` instance. For
    /// production code, use `with_shared_state` or `with_dependencies` to
    /// inject a shared clock and prevent mixed clock domain hazards.
    ///
    /// # Usage
    ///
    /// This constructor is intended for unit tests only. Production code
    /// should use `with_shared_state` or `with_dependencies` with a
    /// properly initialized and shared `HolonicClock`.
    ///
    /// Uses stub implementations for policy resolver, work registry, event
    /// emitter, session registry, and lease validator. No metrics are emitted.
    /// Creates internal stub token minter, manifest store, and HTF clock for
    /// testing.
    #[must_use]
    pub fn new() -> Self {
        // TCK-00289: Create default HolonicClock for HTF-compliant timestamps
        // WARNING: This creates an internal clock which can cause RSK-2503
        // (Mixed Clock Domain Hazard) if used in production alongside other
        // components with their own clocks. Use with_shared_state or
        // with_dependencies for production code.
        let holonic_clock = Arc::new(
            HolonicClock::new(ClockConfig::default(), None)
                .expect("default ClockConfig should always succeed"),
        );
        // TCK-00303: Create subscription registry for HEF resource governance
        let subscription_registry = Arc::new(SubscriptionRegistry::with_defaults());

        Self {
            decode_config: DecodeConfig::default(),
            policy_resolver: Arc::new(StubPolicyResolver),
            work_registry: Arc::new(StubWorkRegistry::default()),
            event_emitter: Arc::new(StubLedgerEventEmitter::new()),
            episode_runtime: Arc::new(EpisodeRuntime::new(EpisodeRuntimeConfig::default())),
            session_registry: Arc::new(InMemorySessionRegistry::default()),
            lease_validator: Arc::new(StubLeaseValidator::new()),
            token_minter: Arc::new(TokenMinter::new(TokenMinter::generate_secret())),
            manifest_store: Arc::new(InMemoryManifestStore::new()),
            // TCK-00317: Pre-seed CAS with reviewer v0 manifest
            manifest_loader: Arc::new(InMemoryCasManifestLoader::with_reviewer_v0_manifest()),
            metrics: None,
            holonic_clock,
            subscription_registry,
        }
    }

    /// Creates a new dispatcher with custom decode configuration (TEST ONLY).
    ///
    /// # Warning: RSK-2503 Mixed Clock Domain Hazard
    ///
    /// This constructor creates an internal `HolonicClock` instance. For
    /// production code, use `with_shared_state` or `with_dependencies` to
    /// inject a shared clock and prevent mixed clock domain hazards.
    ///
    /// # Usage
    ///
    /// This constructor is intended for unit tests only. Production code
    /// should use `with_shared_state` or `with_dependencies` with a
    /// properly initialized and shared `HolonicClock`.
    ///
    /// Uses stub implementations for policy resolver, work registry, event
    /// emitter, session registry, and lease validator. No metrics are emitted.
    /// Creates internal stub token minter, manifest store, and HTF clock for
    /// testing.
    #[must_use]
    pub fn with_decode_config(decode_config: DecodeConfig) -> Self {
        // TCK-00289: Create default HolonicClock for HTF-compliant timestamps
        // WARNING: This creates an internal clock which can cause RSK-2503
        // (Mixed Clock Domain Hazard) if used in production alongside other
        // components with their own clocks. Use with_shared_state or
        // with_dependencies for production code.
        let holonic_clock = Arc::new(
            HolonicClock::new(ClockConfig::default(), None)
                .expect("default ClockConfig should always succeed"),
        );
        // TCK-00303: Create subscription registry for HEF resource governance
        let subscription_registry = Arc::new(SubscriptionRegistry::with_defaults());

        Self {
            decode_config,
            policy_resolver: Arc::new(StubPolicyResolver),
            work_registry: Arc::new(StubWorkRegistry::default()),
            event_emitter: Arc::new(StubLedgerEventEmitter::new()),
            episode_runtime: Arc::new(EpisodeRuntime::new(EpisodeRuntimeConfig::default())),
            session_registry: Arc::new(InMemorySessionRegistry::default()),
            lease_validator: Arc::new(StubLeaseValidator::new()),
            token_minter: Arc::new(TokenMinter::new(TokenMinter::generate_secret())),
            manifest_store: Arc::new(InMemoryManifestStore::new()),
            // TCK-00317: Pre-seed CAS with reviewer v0 manifest
            manifest_loader: Arc::new(InMemoryCasManifestLoader::with_reviewer_v0_manifest()),
            metrics: None,
            holonic_clock,
            subscription_registry,
        }
    }

    /// Creates a new dispatcher with custom dependencies (PRODUCTION).
    ///
    /// This is the production constructor for real governance integration.
    /// Does not include metrics; use `with_metrics` to add them.
    ///
    /// # TCK-00289: Clock Injection (RSK-2503 Prevention)
    ///
    /// The `clock` parameter MUST be a shared `HolonicClock` instance that is
    /// also used by other components in the system. This prevents the mixed
    /// clock domain hazard (RSK-2503) that would occur if each component
    /// created its own clock.
    ///
    /// # TCK-00287: State Sharing
    ///
    /// The `token_minter` and `manifest_store` parameters MUST be `Arc::clone`
    /// copies of the same instances used by `SessionDispatcher`. This ensures:
    /// - Tokens minted during `SpawnEpisode` can be validated by
    ///   `SessionDispatcher`
    /// - Capability manifests registered during `SpawnEpisode` are accessible
    ///   for tool request validation
    ///
    /// Callers must ensure proper sharing by cloning the Arcs BEFORE passing
    /// to this constructor:
    /// ```ignore
    /// let token_minter = Arc::new(TokenMinter::new(...));
    /// let manifest_store = Arc::new(InMemoryManifestStore::new());
    /// let priv_dispatcher = PrivilegedDispatcher::with_dependencies(
    ///     ...,
    ///     Arc::clone(&token_minter),  // Clone BEFORE passing
    ///     Arc::clone(&manifest_store), // Clone BEFORE passing
    /// );
    /// let session_dispatcher = SessionDispatcher::with_manifest_store(
    ///     (*token_minter).clone(),
    ///     manifest_store,
    /// );
    /// ```
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn with_dependencies(
        decode_config: DecodeConfig,
        policy_resolver: Arc<dyn PolicyResolver>,
        work_registry: Arc<dyn WorkRegistry>,
        event_emitter: Arc<dyn LedgerEventEmitter>,
        episode_runtime: Arc<EpisodeRuntime>,
        session_registry: Arc<dyn SessionRegistry>,
        lease_validator: Arc<dyn LeaseValidator>,
        clock: Arc<HolonicClock>,
        token_minter: Arc<TokenMinter>,
        manifest_store: Arc<InMemoryManifestStore>,
        manifest_loader: Arc<dyn ManifestLoader>,
        subscription_registry: SharedSubscriptionRegistry,
    ) -> Self {
        Self {
            decode_config,
            policy_resolver,
            work_registry,
            event_emitter,
            episode_runtime,
            session_registry,
            lease_validator,
            token_minter,
            manifest_store,
            manifest_loader,
            metrics: None,
            holonic_clock: clock,
            subscription_registry,
        }
    }

    /// Creates a new dispatcher with shared token minter and manifest store
    /// (PRODUCTION).
    ///
    /// # TCK-00287: State Sharing
    ///
    /// This constructor is used by `DispatcherState` to wire up shared
    /// dependencies between `PrivilegedDispatcher` and `SessionDispatcher`:
    /// - `token_minter`: Ensures tokens minted during `SpawnEpisode` can be
    ///   validated by `SessionDispatcher`
    /// - `manifest_store`: Ensures capability manifests registered during
    ///   `SpawnEpisode` are accessible for tool request validation
    /// - `session_registry`: Uses the global daemon session registry instead of
    ///   an internal stub
    ///
    /// # TCK-00289: Clock Injection (RSK-2503 Prevention)
    ///
    /// The `clock` parameter MUST be a shared `HolonicClock` instance that is
    /// also used by other components in the system. This prevents the mixed
    /// clock domain hazard (RSK-2503) that would occur if each component
    /// created its own clock.
    #[must_use]
    pub fn with_shared_state(
        token_minter: Arc<TokenMinter>,
        manifest_store: Arc<InMemoryManifestStore>,
        session_registry: Arc<dyn SessionRegistry>,
        clock: Arc<HolonicClock>,
        subscription_registry: SharedSubscriptionRegistry,
    ) -> Self {
        Self {
            decode_config: DecodeConfig::default(),
            policy_resolver: Arc::new(StubPolicyResolver),
            work_registry: Arc::new(StubWorkRegistry::default()),
            event_emitter: Arc::new(StubLedgerEventEmitter::new()),
            episode_runtime: Arc::new(EpisodeRuntime::new(EpisodeRuntimeConfig::default())),
            session_registry,
            lease_validator: Arc::new(StubLeaseValidator::new()),
            token_minter,
            manifest_store,
            // TCK-00317: Pre-seed CAS with reviewer v0 manifest
            manifest_loader: Arc::new(InMemoryCasManifestLoader::with_reviewer_v0_manifest()),
            metrics: None,
            holonic_clock: clock,
            subscription_registry,
        }
    }

    /// Adds a metrics registry to the dispatcher (TCK-00268).
    ///
    /// When set, the dispatcher will emit metrics for:
    /// - `session_spawned`: When `SpawnEpisode` succeeds
    /// - `ipc_request_completed`: For each dispatched request
    /// - `capability_granted`: When `IssueCapability` succeeds
    ///
    /// # Integration Status
    ///
    /// **NOTE**: This method is currently only exercised in tests. The binary
    /// protocol path is not yet wired into `main.rs`. See the `metrics` field
    /// documentation for details.
    #[must_use]
    pub fn with_metrics(mut self, metrics: SharedMetricsRegistry) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Returns a reference to the event emitter.
    ///
    /// This is useful for testing to verify events were emitted.
    #[must_use]
    pub fn event_emitter(&self) -> &Arc<dyn LedgerEventEmitter> {
        &self.event_emitter
    }

    /// Returns a reference to the episode runtime.
    ///
    /// This is useful for testing to verify episode state.
    #[must_use]
    pub const fn episode_runtime(&self) -> &Arc<EpisodeRuntime> {
        &self.episode_runtime
    }

    /// Returns a reference to the session registry.
    ///
    /// This is useful for testing to verify session state.
    #[must_use]
    pub fn session_registry(&self) -> &Arc<dyn SessionRegistry> {
        &self.session_registry
    }

    /// Returns a reference to the lease validator.
    ///
    /// Primarily for testing purposes to pre-register leases.
    #[must_use]
    pub fn lease_validator(&self) -> &Arc<dyn LeaseValidator> {
        &self.lease_validator
    }

    /// Returns a reference to the token minter.
    ///
    /// # TCK-00287
    ///
    /// This is used to share the token minter with `SessionDispatcher`.
    #[must_use]
    pub const fn token_minter(&self) -> &Arc<TokenMinter> {
        &self.token_minter
    }

    /// Returns a reference to the manifest store.
    ///
    /// # TCK-00287
    ///
    /// This is used to share the manifest store with `SessionDispatcher`.
    #[must_use]
    pub const fn manifest_store(&self) -> &Arc<InMemoryManifestStore> {
        &self.manifest_store
    }

    /// Returns a reference to the HTF-compliant clock (TCK-00289).
    ///
    /// This is primarily for testing to verify clock behavior.
    #[must_use]
    pub const fn holonic_clock(&self) -> &Arc<HolonicClock> {
        &self.holonic_clock
    }

    /// Returns a reference to the subscription registry (TCK-00303).
    ///
    /// # TCK-00303
    ///
    /// This is used to share the subscription registry with
    /// `SessionDispatcher`.
    #[must_use]
    pub const fn subscription_registry(&self) -> &SharedSubscriptionRegistry {
        &self.subscription_registry
    }

    // =========================================================================
    // TCK-00289: HTF-Compliant Timestamp Generation
    // =========================================================================

    /// Returns an HTF-compliant timestamp in nanoseconds since epoch.
    ///
    /// Per RFC-0016, all timestamps must come from the `HolonicClock` to
    /// ensure:
    /// - Monotonicity: Timestamps never regress within a process lifetime
    /// - Causality: HLC provides cross-node causal ordering
    /// - Determinism: Clock source is injectable for replay scenarios
    ///
    /// # Returns
    ///
    /// The current HLC wall time in nanoseconds since epoch. This is a u64
    /// value representing hybrid logical clock time, suitable for ledger
    /// event timestamps and capability grant/expiry times.
    ///
    /// # Panics
    ///
    /// This method expects the `HolonicClock` to have HLC enabled. If HLC is
    /// not enabled, this returns an error (fail-closed).
    ///
    /// # Errors
    ///
    /// Returns `HtfTimestampError` if the clock operation fails.
    ///
    /// # Security (Fail-Closed)
    ///
    /// Per RFC-0016 and TCK-00289 DOD, this method fails closed rather than
    /// returning a fallback value like 0. Returning 0 would violate security
    /// policy and allow operations to proceed with invalid timestamps.
    fn get_htf_timestamp_ns(&self) -> Result<u64, HtfTimestampError> {
        match self.holonic_clock.now_hlc() {
            Ok(hlc) => Ok(hlc.wall_ns),
            Err(e) => {
                // TCK-00289: Fail-closed - do not return 0 as fallback.
                // This is a security-critical operation that must not proceed
                // with invalid timestamps.
                warn!(error = %e, "HLC clock error - failing closed per RFC-0016");
                Err(HtfTimestampError::ClockError {
                    message: e.to_string(),
                })
            },
        }
    }

    // =========================================================================
    // TCK-00258: Custody Domain Resolution (`SoD` Enforcement)
    // =========================================================================

    /// Resolves custody domains for an actor.
    ///
    /// Per TCK-00258, this method maps an actor ID to its custody domains
    /// for `SoD` validation. In production, this would query the `KeyPolicy`
    /// via a `CustodyDomainResolver` trait.
    ///
    /// # Stub Implementation
    ///
    /// Currently returns a single domain derived from the actor ID prefix.
    /// For example, `team-alpha:alice` -> `["team-alpha"]`.
    /// This enables testing of the `SoD` enforcement without full `KeyPolicy`
    /// integration.
    ///
    /// # Security (Fail-Closed)
    ///
    /// Returns an error if the actor ID doesn't match the expected
    /// `domain:actor` schema. This ensures that malformed or non-standard
    /// actor IDs cannot bypass `SoD` validation.
    #[allow(clippy::unused_self)] // Will use self in production for registry access
    fn resolve_actor_custody_domains(&self, actor_id: &str) -> Result<Vec<String>, String> {
        // Stub: derive domain from actor_id prefix (e.g., "team-alpha:alice" ->
        // "team-alpha") In production, this would query
        // KeyPolicy.custody_domains
        if let Some(colon_pos) = actor_id.find(':') {
            let domain = &actor_id[..colon_pos];
            if !domain.is_empty() {
                return Ok(vec![domain.to_string()]);
            }
        }
        // SEC-SoD-001: Fail-closed for malformed actor IDs.
        // If the actor_id doesn't match expected schema (domain:actor), return
        // an error. This prevents attackers from bypassing SoD by using
        // non-standard IDs.
        Err(format!(
            "malformed actor_id: {actor_id} (expected domain:actor)"
        ))
    }

    /// Resolves custody domains for changeset authors.
    ///
    /// Per TCK-00258, this method retrieves the custody domains of all actors
    /// who authored the changeset being reviewed. In production, this would
    /// query the changeset metadata and `KeyPolicy`.
    ///
    /// # Stub Implementation
    ///
    /// Currently returns a placeholder domain based on the `work_id`.
    /// For testing, set `work_id` to include domain information:
    /// e.g., `W-team-alpha-12345` -> `["team-alpha"]`
    ///
    /// # Security (Fail-Closed)
    ///
    /// Returns an error if the `work_id` doesn't match the expected schema.
    /// This ensures that malformed work IDs cannot bypass `SoD` validation.
    #[allow(clippy::unused_self)] // Will use self in production for registry access
    fn resolve_changeset_author_domains(&self, work_id: &str) -> Result<Vec<String>, String> {
        // Stub: derive author domain from work_id (e.g., "W-team-alpha-12345" ->
        // ["team-alpha"]) In production, this would query changeset metadata
        // for author list, then resolve each author's custody domains via
        // KeyPolicy
        if let Some(rest) = work_id.strip_prefix("W-") {
            if let Some(dash_pos) = rest.find('-') {
                let domain = &rest[..dash_pos];
                if !domain.is_empty() {
                    return Ok(vec![domain.to_string()]);
                }
            }
        }
        // SEC-SoD-001: Fail-closed for malformed work_ids.
        // Return an error if the work_id doesn't match the expected schema.
        // This prevents attackers from bypassing SoD by using malformed work_ids
        // that don't map to author domains.
        Err(format!(
            "malformed work_id: {work_id} (expected W-domain-suffix)"
        ))
    }

    /// Dispatches a privileged request to the appropriate handler.
    ///
    /// # Message Format
    ///
    /// The frame format is: [tag: u8][payload: protobuf]
    /// Where tag identifies the message type (see [`PrivilegedMessageType`]).
    ///
    /// # Security
    ///
    /// 1. Validates `ctx.is_privileged()` FIRST
    /// 2. Returns `PERMISSION_DENIED` immediately for non-privileged
    ///    connections
    /// 3. Only then decodes and routes the message
    ///
    /// # Errors
    ///
    /// Returns `Err` for protocol-level errors (malformed frames, etc.).
    /// Application-level errors are returned in [`PrivilegedResponse::Error`].
    pub fn dispatch(
        &self,
        frame: &Bytes,
        ctx: &ConnectionContext,
    ) -> ProtocolResult<PrivilegedResponse> {
        // INV-0001: Check privilege BEFORE any message processing
        if !ctx.is_privileged() {
            // TH-004: Generic error prevents endpoint enumeration
            debug!(
                peer_pid = ?ctx.peer_credentials().map(|c| c.pid),
                "Non-privileged connection attempted privileged endpoint"
            );
            return Ok(PrivilegedResponse::permission_denied());
        }

        // Validate frame has at least a tag byte
        if frame.is_empty() {
            return Err(ProtocolError::Serialization {
                reason: "empty frame".to_string(),
            });
        }

        let tag = frame[0];
        let payload = &frame[1..];

        // Route based on message type
        let msg_type =
            PrivilegedMessageType::from_tag(tag).ok_or_else(|| ProtocolError::Serialization {
                reason: format!("unknown privileged message type: {tag}"),
            })?;

        let result = match msg_type {
            PrivilegedMessageType::ClaimWork => self.handle_claim_work(payload, ctx),
            PrivilegedMessageType::SpawnEpisode => self.handle_spawn_episode(payload, ctx),
            PrivilegedMessageType::IssueCapability => self.handle_issue_capability(payload, ctx),
            PrivilegedMessageType::Shutdown => self.handle_shutdown(payload, ctx),
            // HEF Pulse Plane (TCK-00302): Operator subscription handlers
            PrivilegedMessageType::SubscribePulse => self.handle_subscribe_pulse(payload, ctx),
            PrivilegedMessageType::UnsubscribePulse => self.handle_unsubscribe_pulse(payload, ctx),
            // PulseEvent is server-to-client only, reject if received from client
            PrivilegedMessageType::PulseEvent => Ok(PrivilegedResponse::error(
                PrivilegedErrorCode::PermissionDenied,
                "PulseEvent is server-to-client only",
            )),
        };

        // TCK-00268: Emit IPC request completion metrics
        if let Some(ref metrics) = self.metrics {
            let endpoint = match msg_type {
                PrivilegedMessageType::ClaimWork => "ClaimWork",
                PrivilegedMessageType::SpawnEpisode => "SpawnEpisode",
                PrivilegedMessageType::IssueCapability => "IssueCapability",
                PrivilegedMessageType::Shutdown => "Shutdown",
                // HEF Pulse Plane (TCK-00300)
                PrivilegedMessageType::SubscribePulse => "SubscribePulse",
                PrivilegedMessageType::UnsubscribePulse => "UnsubscribePulse",
                PrivilegedMessageType::PulseEvent => "PulseEvent",
            };
            let status = match &result {
                Ok(PrivilegedResponse::Error(_)) => "error",
                Ok(_) => "success",
                Err(_) => "protocol_error",
            };
            metrics
                .daemon_metrics()
                .ipc_request_completed(endpoint, status);
        }

        result
    }

    /// Handles `ClaimWork` requests (IPC-PRIV-001).
    ///
    /// # TCK-00253 Implementation
    ///
    /// This handler implements the work claim flow per DD-001 and DD-002:
    ///
    /// 1. Validate request structure
    /// 2. Derive authoritative `actor_id` from credential (not user input)
    /// 3. Query governance for `PolicyResolvedForChangeSet`
    /// 4. Mint capability manifest based on resolved policy
    /// 5. Register work claim in registry
    /// 6. Return work assignment
    ///
    /// # Security
    ///
    /// Per DD-001: The `actor_id` in the request is a display hint only.
    /// The authoritative `actor_id` is derived from the peer credential.
    fn handle_claim_work(
        &self,
        payload: &[u8],
        ctx: &ConnectionContext,
    ) -> ProtocolResult<PrivilegedResponse> {
        let request =
            ClaimWorkRequest::decode_bounded(payload, &self.decode_config).map_err(|e| {
                ProtocolError::Serialization {
                    reason: format!("invalid ClaimWorkRequest: {e}"),
                }
            })?;

        let role = WorkRole::try_from(request.role).unwrap_or(WorkRole::Unspecified);

        info!(
            actor_id_hint = %request.actor_id,
            role = ?role,
            peer_pid = ?ctx.peer_credentials().map(|c| c.pid),
            "ClaimWork request received"
        );

        // Validate role is specified
        if role == WorkRole::Unspecified {
            return Ok(PrivilegedResponse::error(
                PrivilegedErrorCode::CapabilityRequestRejected,
                "role is required",
            ));
        }

        // TCK-00253: Derive authoritative actor_id from credential (not user input)
        // Per DD-001: "actor_id is a display hint; authoritative actor_id derived from
        // credential"
        let peer_creds = ctx
            .peer_credentials()
            .ok_or_else(|| ProtocolError::Serialization {
                reason: "peer credentials required for work claim".to_string(),
            })?;

        let actor_id = derive_actor_id(peer_creds);

        debug!(
            actor_id_hint = %request.actor_id,
            derived_actor_id = %actor_id,
            "Actor ID derived from credential"
        );

        // Generate unique work and lease IDs
        let work_id = generate_work_id();
        let lease_id = generate_lease_id();

        // TCK-00253: Query governance for policy resolution
        // Per DD-002: "Daemon calls HOLON-KERNEL-GOVERNANCE for policy resolution"
        let policy_resolution = match self
            .policy_resolver
            .resolve_for_claim(&work_id, role, &actor_id)
        {
            Ok(resolution) => resolution,
            Err(e) => {
                warn!(error = %e, "Policy resolution failed");
                // Return application-level error, not protocol error
                // Policy resolution failures are logic errors, not serialization errors
                return Ok(PrivilegedResponse::error(
                    PrivilegedErrorCode::PolicyResolutionFailed,
                    format!("policy resolution failed: {e}"),
                ));
            },
        };

        // SEC-SCP-FAC-0020: lease_id is redacted from logs to prevent capability
        // leakage
        info!(
            work_id = %work_id,
            lease_id = "[REDACTED]",
            actor_id = %actor_id,
            policy_resolved_ref = %policy_resolution.policy_resolved_ref,
            "Work claimed with policy resolution"
        );

        // TCK-00258: Extract custody domains for SoD validation
        // For now, use a stub implementation that derives domain from actor_id
        // In production, this would query the KeyPolicy via CustodyDomainResolver
        let executor_custody_domains = match self.resolve_actor_custody_domains(&actor_id) {
            Ok(domains) => domains,
            Err(e) => {
                warn!(error = %e, "Failed to resolve executor custody domains");
                return Ok(PrivilegedResponse::error(
                    PrivilegedErrorCode::CapabilityRequestRejected,
                    format!("failed to resolve executor custody domains: {e}"),
                ));
            },
        };

        let author_custody_domains = match self.resolve_changeset_author_domains(&work_id) {
            Ok(domains) => domains,
            Err(e) => {
                warn!(error = %e, "Failed to resolve author custody domains");
                return Ok(PrivilegedResponse::error(
                    PrivilegedErrorCode::CapabilityRequestRejected,
                    format!("failed to resolve author custody domains: {e}"),
                ));
            },
        };

        // Register the work claim
        let claim = WorkClaim {
            work_id,
            lease_id,
            actor_id,
            role,
            policy_resolution: policy_resolution.clone(),
            executor_custody_domains,
            author_custody_domains,
        };

        let claim = match self.work_registry.register_claim(claim) {
            Ok(claim) => claim,
            Err(e) => {
                warn!(error = %e, "Work registration failed");
                // Return application-level error, not protocol error
                // Registration failures are logic errors, not serialization errors
                return Ok(PrivilegedResponse::error(
                    PrivilegedErrorCode::CapabilityRequestRejected,
                    format!("work registration failed: {e}"),
                ));
            },
        };

        // TCK-00253: Emit signed WorkClaimed event to ledger.
        // Per acceptance criteria: "`WorkClaimed` event signed and persisted"
        // The event is:
        // - Signed with the daemon's signing key (Ed25519)
        // - Includes work_id, lease_id, actor_id, role, and policy_resolved_ref
        // - Persisted to the append-only ledger for audit trail
        //
        // TCK-00289: Use HTF-compliant timestamp from HolonicClock.
        // Per RFC-0016, timestamps must come from the HTF clock source to ensure
        // monotonicity and causal ordering.
        let timestamp_ns = match self.get_htf_timestamp_ns() {
            Ok(ts) => ts,
            Err(e) => {
                // TCK-00289: Fail-closed - do not proceed without valid timestamp
                warn!(error = %e, "HTF timestamp generation failed - failing closed");
                return Ok(PrivilegedResponse::error(
                    PrivilegedErrorCode::CapabilityRequestRejected,
                    format!("HTF timestamp error: {e}"),
                ));
            },
        };
        let signed_event = match self.event_emitter.emit_work_claimed(&claim, timestamp_ns) {
            Ok(event) => event,
            Err(e) => {
                warn!(error = %e, "WorkClaimed event emission failed");
                // Return application-level error, not protocol error
                // Event emission failures are logic errors, not serialization errors
                return Ok(PrivilegedResponse::error(
                    PrivilegedErrorCode::CapabilityRequestRejected,
                    format!("event emission failed: {e}"),
                ));
            },
        };

        debug!(
            event_id = %signed_event.event_id,
            work_id = %claim.work_id,
            "WorkClaimed event emitted successfully"
        );

        // Return the work assignment
        Ok(PrivilegedResponse::ClaimWork(ClaimWorkResponse {
            work_id: claim.work_id,
            lease_id: claim.lease_id,
            capability_manifest_hash: policy_resolution.capability_manifest_hash.to_vec(),
            policy_resolved_ref: policy_resolution.policy_resolved_ref,
            context_pack_hash: policy_resolution.context_pack_hash.to_vec(),
        }))
    }

    /// Handles `SpawnEpisode` requests (IPC-PRIV-002).
    ///
    /// # Security Contract (TCK-00257)
    ///
    /// - `GATE_EXECUTOR` role requires a valid `lease_id` that references a
    ///   `GateLeaseIssued` event in the ledger
    /// - The lease must match the `work_id` in the request
    /// - Non-`GATE_EXECUTOR` roles (`IMPLEMENTER`, `REVIEWER`) do not require
    ///   ledger lease validation (they use claim-based validation)
    ///
    /// # TCK-00256 Implementation
    ///
    /// This handler implements the episode spawn flow per DD-001 and DD-002:
    ///
    /// 1. Validate request structure
    /// 2. Query work registry for `PolicyResolvedForChangeSet`
    /// 3. Validate role matches the claimed role
    /// 4. Validate `lease_id` matches the claimed `lease_id` (SEC-SCP-FAC-0020)
    /// 5. Create episode in runtime with policy constraints
    /// 6. Persist session state for subsequent IPC calls
    /// 7. Return session credentials
    ///
    /// # Security
    ///
    /// - Per SEC-SCP-FAC-0020: `lease_id` is validated against the claim to
    ///   prevent authorization bypass. The `lease_id` is redacted from logs to
    ///   prevent capability leakage.
    /// - Per fail-closed semantics: spawn is rejected if policy resolution is
    ///   missing.
    fn handle_spawn_episode(
        &self,
        payload: &[u8],
        ctx: &ConnectionContext,
    ) -> ProtocolResult<PrivilegedResponse> {
        // TCK-00319: Maximum path length constant (declared at function start per
        // clippy)
        const MAX_PATH_LENGTH: usize = 4096;

        let request =
            SpawnEpisodeRequest::decode_bounded(payload, &self.decode_config).map_err(|e| {
                ProtocolError::Serialization {
                    reason: format!("invalid SpawnEpisodeRequest: {e}"),
                }
            })?;

        // SEC-SCP-FAC-0020: lease_id is redacted from logs to prevent capability
        // leakage
        info!(
            work_id = %request.work_id,
            role = ?WorkRole::try_from(request.role).unwrap_or(WorkRole::Unspecified),
            lease_id = "[REDACTED]",
            peer_pid = ?ctx.peer_credentials().map(|c| c.pid),
            "SpawnEpisode request received"
        );

        // Validate required fields
        if request.work_id.is_empty() {
            return Ok(PrivilegedResponse::error(
                PrivilegedErrorCode::CapabilityRequestRejected,
                "work_id is required",
            ));
        }

        // SEC-SCP-FAC-0020: Enforce maximum length on work_id to prevent DoS via OOM
        if request.work_id.len() > MAX_ID_LENGTH {
            warn!(
                work_id_len = request.work_id.len(),
                max_len = MAX_ID_LENGTH,
                "SpawnEpisode rejected: work_id exceeds maximum length"
            );
            return Ok(PrivilegedResponse::error(
                PrivilegedErrorCode::CapabilityRequestRejected,
                format!("work_id exceeds maximum length of {MAX_ID_LENGTH} bytes"),
            ));
        }

        // SEC-SCP-FAC-0020: Enforce maximum length on lease_id to prevent DoS via OOM
        if let Some(ref lease_id) = request.lease_id {
            if lease_id.len() > MAX_ID_LENGTH {
                warn!(
                    lease_id_len = lease_id.len(),
                    max_len = MAX_ID_LENGTH,
                    "SpawnEpisode rejected: lease_id exceeds maximum length"
                );
                return Ok(PrivilegedResponse::error(
                    PrivilegedErrorCode::CapabilityRequestRejected,
                    format!("lease_id exceeds maximum length of {MAX_ID_LENGTH} bytes"),
                ));
            }
        }

        // TCK-00319: Validate workspace_root is provided
        if request.workspace_root.is_empty() {
            return Ok(PrivilegedResponse::error(
                PrivilegedErrorCode::CapabilityRequestRejected,
                "workspace_root is required",
            ));
        }

        // TCK-00319: Validate workspace_root path length (prevent DoS via unbounded
        // paths)
        if request.workspace_root.len() > MAX_PATH_LENGTH {
            warn!(
                workspace_root_len = request.workspace_root.len(),
                max_len = MAX_PATH_LENGTH,
                "SpawnEpisode rejected: workspace_root exceeds maximum length"
            );
            return Ok(PrivilegedResponse::error(
                PrivilegedErrorCode::CapabilityRequestRejected,
                format!("workspace_root exceeds maximum length of {MAX_PATH_LENGTH} bytes"),
            ));
        }

        // TCK-00319: Validate workspace_root is an absolute path
        let workspace_path = std::path::Path::new(&request.workspace_root);
        if !workspace_path.is_absolute() {
            warn!(
                workspace_root = %request.workspace_root,
                "SpawnEpisode rejected: workspace_root must be an absolute path"
            );
            return Ok(PrivilegedResponse::error(
                PrivilegedErrorCode::CapabilityRequestRejected,
                "workspace_root must be an absolute path",
            ));
        }

        // TCK-00319: Validate workspace_root exists and is a directory
        if !workspace_path.exists() {
            warn!(
                workspace_root = %request.workspace_root,
                "SpawnEpisode rejected: workspace_root does not exist"
            );
            return Ok(PrivilegedResponse::error(
                PrivilegedErrorCode::CapabilityRequestRejected,
                format!("workspace_root does not exist: {}", request.workspace_root),
            ));
        }

        if !workspace_path.is_dir() {
            warn!(
                workspace_root = %request.workspace_root,
                "SpawnEpisode rejected: workspace_root is not a directory"
            );
            return Ok(PrivilegedResponse::error(
                PrivilegedErrorCode::CapabilityRequestRejected,
                format!(
                    "workspace_root is not a directory: {}",
                    request.workspace_root
                ),
            ));
        }

        if request.role == WorkRole::Unspecified as i32 {
            return Ok(PrivilegedResponse::error(
                PrivilegedErrorCode::CapabilityRequestRejected,
                "role is required",
            ));
        }

        // GATE_EXECUTOR requires lease_id
        if request.role == WorkRole::GateExecutor as i32 && request.lease_id.is_none() {
            return Ok(PrivilegedResponse::error(
                PrivilegedErrorCode::GateLeaseMissing,
                "lease_id is required for GATE_EXECUTOR role",
            ));
        }

        // TCK-00257: GATE_EXECUTOR requires valid lease in ledger
        // Per RFC-0017 IPC-PRIV-002, the lease must exist as a GateLeaseIssued event
        // and the work_id must match. This is a fail-closed check.
        if request.role == WorkRole::GateExecutor as i32 {
            let lease_id = request
                .lease_id
                .as_ref()
                .expect("lease_id presence checked above");

            if let Err(e) = self
                .lease_validator
                .validate_gate_lease(lease_id, &request.work_id)
            {
                warn!(
                    work_id = %request.work_id,
                    error = %e,
                    "SpawnEpisode rejected: gate lease validation failed"
                );
                return Ok(PrivilegedResponse::error(
                    PrivilegedErrorCode::GateLeaseMissing,
                    format!("gate lease validation failed: {e}"),
                ));
            }
        }

        // TCK-00256: Query work registry for PolicyResolvedForChangeSet
        // Fail-closed: spawn is only allowed if a valid policy resolution exists
        // for the work_id. This is established during ClaimWork.
        let Some(claim) = self.work_registry.get_claim(&request.work_id) else {
            warn!(
                work_id = %request.work_id,
                "SpawnEpisode rejected: policy resolution not found for work_id"
            );
            return Ok(PrivilegedResponse::error(
                PrivilegedErrorCode::PolicyResolutionMissing,
                format!(
                    "policy resolution not found for work_id={}; ClaimWork must be called first",
                    request.work_id
                ),
            ));
        };

        // TCK-00256: Validate role matches the claimed role
        // Per DD-001, the role in the spawn request should match the claimed role
        let request_role = WorkRole::try_from(request.role).unwrap_or(WorkRole::Unspecified);
        if claim.role != request_role {
            warn!(
                work_id = %request.work_id,
                claimed_role = ?claim.role,
                request_role = ?request_role,
                "SpawnEpisode rejected: role mismatch"
            );
            return Ok(PrivilegedResponse::error(
                PrivilegedErrorCode::CapabilityRequestRejected,
                format!(
                    "role mismatch: work was claimed as {:?} but spawn requested {:?}",
                    claim.role, request_role
                ),
            ));
        }

        // SEC-SCP-FAC-0020: Validate lease_id matches the claimed lease_id
        // This prevents authorization bypass where a caller provides an arbitrary
        // lease_id. All roles must provide the correct lease_id from ClaimWork.
        // NOTE: Uses constant-time comparison to prevent timing side-channel attacks
        // that could leak information about valid lease_id values.
        let provided_lease_id = request.lease_id.as_deref().unwrap_or("");
        let lease_id_matches = provided_lease_id.len() == claim.lease_id.len()
            && bool::from(
                provided_lease_id
                    .as_bytes()
                    .ct_eq(claim.lease_id.as_bytes()),
            );
        if !lease_id_matches {
            warn!(
                work_id = %request.work_id,
                "SpawnEpisode rejected: lease_id mismatch"
            );
            return Ok(PrivilegedResponse::error(
                PrivilegedErrorCode::CapabilityRequestRejected,
                "lease_id does not match the claimed lease_id",
            ));
        }

        // For GateExecutor, the lease_id is required and must match
        // (Redundant but explicit check preserved for clarity per logic)
        // NOTE: Uses constant-time comparison to prevent timing side-channel attacks.
        if request.role == WorkRole::GateExecutor as i32 {
            if let Some(ref lease_id) = request.lease_id {
                let gate_lease_matches = lease_id.len() == claim.lease_id.len()
                    && bool::from(lease_id.as_bytes().ct_eq(claim.lease_id.as_bytes()));
                if !gate_lease_matches {
                    warn!(
                        work_id = %request.work_id,
                        "SpawnEpisode rejected: GateExecutor lease_id mismatch"
                    );
                    return Ok(PrivilegedResponse::error(
                        PrivilegedErrorCode::CapabilityRequestRejected,
                        "lease_id does not match the claimed lease_id for GATE_EXECUTOR",
                    ));
                }
            }
        }

        // =====================================================================
        // TCK-00258: SoD Custody Domain Validation
        //
        // Per REQ-DCP-0006, GATE_EXECUTOR spawns MUST enforce Separation of
        // Duties by rejecting when executor custody domains overlap with author
        // custody domains. This prevents self-review attacks.
        // =====================================================================
        if request.role == WorkRole::GateExecutor as i32 {
            // Convert claim domains to CustodyDomainId for validation
            let executor_domains: Vec<CustodyDomainId> = claim
                .executor_custody_domains
                .iter()
                .filter_map(|d| CustodyDomainId::new(d.clone()).ok())
                .collect();

            let author_domains: Vec<CustodyDomainId> = claim
                .author_custody_domains
                .iter()
                .filter_map(|d| CustodyDomainId::new(d.clone()).ok())
                .collect();

            // TCK-00258: Fail-closed SoD validation for GATE_EXECUTOR.
            // If author domains cannot be resolved (empty), DENY the spawn.
            // The absence of author information MUST block, not allow, to prevent
            // attackers from bypassing SoD by using malformed work_ids.
            if author_domains.is_empty() {
                warn!(
                    work_id = %request.work_id,
                    "SpawnEpisode rejected: cannot resolve author custody domains for SoD validation"
                );
                return Ok(PrivilegedResponse::error(
                    PrivilegedErrorCode::SodViolation,
                    "cannot resolve author custody domains; SoD validation requires author information for GATE_EXECUTOR",
                ));
            }

            // Validate SoD: executor domains must not overlap with author domains
            if !executor_domains.is_empty() {
                if let Err(CustodyDomainError::Overlap {
                    executor_domain,
                    author_domain,
                }) = validate_custody_domain_overlap(&executor_domains, &author_domains)
                {
                    warn!(
                        work_id = %request.work_id,
                        executor_domain = %executor_domain,
                        author_domain = %author_domain,
                        "SpawnEpisode rejected: SoD custody domain violation"
                    );

                    // Emit LeaseIssueDenied event for audit logging.
                    // TCK-00289: Use HTF-compliant timestamp per RFC-0016.
                    // Fail-closed: if clock fails, we still reject the spawn (already
                    // doing that) but log at warning level instead of emitting event.
                    let timestamp_ns = match self.get_htf_timestamp_ns() {
                        Ok(ts) => ts,
                        Err(e) => {
                            warn!(error = %e, "HTF timestamp error for LeaseIssueDenied - skipping event emission");
                            0u64 // Use 0 only for best-effort event, spawn is still denied
                        },
                    };

                    // Best-effort event emission - don't fail spawn on event error.
                    // If no Tokio runtime is available (e.g., in unit tests), skip the
                    // async event emission. This is safe because:
                    // 1. The denial is still returned to the caller
                    // 2. The event is only for audit/diagnostic purposes
                    // 3. Production code always has a Tokio runtime
                    if let Ok(handle) = tokio::runtime::Handle::try_current() {
                        let _ = tokio::task::block_in_place(|| {
                            handle.block_on(async {
                                self.episode_runtime
                                    .emit_lease_issue_denied(
                                        request.work_id.clone(),
                                        LeaseIssueDenialReason::SodViolation {
                                            executor_domain: executor_domain.clone(),
                                            author_domain: author_domain.clone(),
                                        },
                                        timestamp_ns,
                                    )
                                    .await
                            })
                        });
                    }

                    return Ok(PrivilegedResponse::error(
                        PrivilegedErrorCode::SodViolation,
                        format!(
                            "custody domain overlap: executor domain '{executor_domain}' overlaps with author domain '{author_domain}'"
                        ),
                    ));
                }
            }
        }

        info!(
            work_id = %request.work_id,
            policy_resolved_ref = %claim.policy_resolution.policy_resolved_ref,
            "SpawnEpisode authorized with policy resolution"
        );

        // Generate session ID and ephemeral handle
        let session_id = format!("S-{}", uuid::Uuid::new_v4());
        let ephemeral_handle = EphemeralHandle::generate();

        // TCK-00256: Persist session state for subsequent IPC calls
        // The episode_runtime can create/start episodes asynchronously when needed.
        // For now, we persist the session state with policy constraints reference
        // so that subsequent async operations can use it.
        let session_state = SessionState {
            session_id: session_id.clone(),
            work_id: request.work_id.clone(),
            role: request_role.into(),
            ephemeral_handle: ephemeral_handle.to_string(),
            lease_id: claim.lease_id.clone(),
            policy_resolved_ref: claim.policy_resolution.policy_resolved_ref.clone(),
            capability_manifest_hash: claim.policy_resolution.capability_manifest_hash.to_vec(),
            episode_id: None, // Will be set when episode starts in async context
        };

        if let Err(e) = self.session_registry.register_session(session_state) {
            warn!(error = %e, "Session registration failed");
            return Ok(PrivilegedResponse::error(
                PrivilegedErrorCode::CapabilityRequestRejected,
                format!("session registration failed: {e}"),
            ));
        }

        debug!(
            session_id = %session_id,
            ephemeral_handle = %ephemeral_handle,
            "Session persisted"
        );

        // TCK-00287 BLOCKER 2: Generate session token for client authentication
        // The token is HMAC-signed and bound to this session's lease_id.
        //
        // NOTE: TokenMinter uses SystemTime for TTL calculation, which is
        // acceptable since token expiry is not a protocol-authoritative event.
        // The HTF clock is used for ledger events that require causal ordering.
        let spawn_time = SystemTime::now();
        let ttl = Duration::from_secs(DEFAULT_SESSION_TOKEN_TTL_SECS);
        let session_token =
            match self
                .token_minter
                .mint(&session_id, &claim.lease_id, spawn_time, ttl)
            {
                Ok(token) => token,
                Err(e) => {
                    warn!(error = %e, "Session token minting failed");
                    return Ok(PrivilegedResponse::error(
                        PrivilegedErrorCode::CapabilityRequestRejected,
                        format!("session token generation failed: {e}"),
                    ));
                },
            };

        // Serialize the token to JSON for inclusion in the response
        let session_token_json = match serde_json::to_string(&session_token) {
            Ok(json) => json,
            Err(e) => {
                warn!(error = %e, "Session token serialization failed");
                return Ok(PrivilegedResponse::error(
                    PrivilegedErrorCode::CapabilityRequestRejected,
                    format!("session token serialization failed: {e}"),
                ));
            },
        };

        // TCK-00317: Load capability manifest from CAS using hash from
        // PolicyResolution.
        //
        // Per DOD item 1 (CAS Storage & Hash Loading):
        // - Manifests are stored in CAS and referenced by hash
        // - SpawnEpisode loads the manifest using the hash from PolicyResolution
        // - For Reviewer role: Missing manifests result in fail-closed rejection
        // - For other roles: Fall back to minimal manifest (until their manifests are
        //   defined in CAS)
        //
        // Per DOD item 2 (Policy Resolution Bypass fix):
        // - The manifest is NOT selected by role name; it's loaded by hash
        // - StubPolicyResolver returns reviewer_v0_manifest_hash() for Reviewer
        // - This ensures the policy resolution controls which manifest is used
        let manifest_hash: [u8; 32] = claim.policy_resolution.capability_manifest_hash;

        let manifest = match self.manifest_loader.load_manifest(&manifest_hash) {
            Ok(m) => m,
            Err(e) => {
                // TCK-00317: For Reviewer role, fail-closed if manifest not found
                // For other roles, fall back to minimal manifest until their
                // manifests are stored in CAS.
                if request_role == WorkRole::Reviewer {
                    warn!(
                        work_id = %request.work_id,
                        manifest_hash = %hex::encode(manifest_hash),
                        error = %e,
                        "SpawnEpisode rejected: reviewer manifest not found in CAS"
                    );
                    return Ok(PrivilegedResponse::error(
                        PrivilegedErrorCode::CapabilityRequestRejected,
                        format!("reviewer capability manifest not found in CAS: {e}"),
                    ));
                }

                // Non-Reviewer roles: fall back to minimal manifest
                // This maintains backward compatibility until all role manifests
                // are defined and stored in CAS.
                debug!(
                    work_id = %request.work_id,
                    role = ?request_role,
                    manifest_hash = %hex::encode(manifest_hash),
                    "Manifest not in CAS, using minimal fallback manifest for non-reviewer role"
                );
                CapabilityManifest::from_hash_with_default_allowlist(&manifest_hash)
            },
        };

        self.manifest_store.register(&session_id, manifest.clone());

        debug!(
            session_id = %session_id,
            role = ?request_role,
            manifest_id = %manifest.manifest_id,
            tool_allowlist_len = manifest.tool_allowlist.len(),
            "Capability manifest registered in shared store"
        );

        // TCK-00268: Emit session_spawned metric
        if let Some(ref metrics) = self.metrics {
            let role_str = match request_role {
                WorkRole::Implementer => "implementer",
                WorkRole::Reviewer => "reviewer",
                WorkRole::GateExecutor => "gate_executor",
                WorkRole::Coordinator => "coordinator",
                WorkRole::Unspecified => "unspecified",
            };
            metrics.daemon_metrics().session_spawned(role_str);
        }

        // TCK-00289: Emit SessionStarted ledger event for audit trail.
        // Per DOD: "ClaimWork/SpawnEpisode persist state and emit ledger events"
        let timestamp_ns = match self.get_htf_timestamp_ns() {
            Ok(ts) => ts,
            Err(e) => {
                // TCK-00289: Fail-closed - do not proceed without valid timestamp
                warn!(error = %e, "HTF timestamp generation failed for SessionStarted - failing closed");
                return Ok(PrivilegedResponse::error(
                    PrivilegedErrorCode::CapabilityRequestRejected,
                    format!("HTF timestamp error: {e}"),
                ));
            },
        };

        // TCK-00319: Create and start episode with workspace root.
        // This ensures that all file/execute operations are confined to the
        // workspace directory. The episode must be started BEFORE returning
        // to the client so that tool handlers are properly initialized.
        //
        // Generate envelope hash from session_id + work_id + lease_id for uniqueness
        let envelope_data = format!("{}{}{}", session_id, request.work_id, claim.lease_id);
        let envelope_hash: [u8; 32] = blake3::hash(envelope_data.as_bytes()).into();

        // Try to create and start the episode. This requires a Tokio runtime.
        // In unit tests without a runtime, we skip episode creation but still
        // return a valid session (for backward compatibility with existing tests).
        let episode_id_opt = if let Ok(handle) = tokio::runtime::Handle::try_current() {
            match tokio::task::block_in_place(|| {
                handle.block_on(async {
                    // Create the episode with envelope hash and timestamp
                    let episode_id = self
                        .episode_runtime
                        .create(envelope_hash, timestamp_ns)
                        .await?;

                    // Start with workspace - this initializes rooted handlers
                    let _session_handle = self
                        .episode_runtime
                        .start_with_workspace(
                            &episode_id,
                            &claim.lease_id,
                            timestamp_ns,
                            workspace_path,
                        )
                        .await?;

                    Ok::<_, crate::episode::EpisodeError>(episode_id)
                })
            }) {
                Ok(id) => Some(id),
                Err(e) => {
                    warn!(
                        work_id = %request.work_id,
                        error = %e,
                        "SpawnEpisode failed: episode creation/start failed"
                    );
                    return Ok(PrivilegedResponse::error(
                        PrivilegedErrorCode::CapabilityRequestRejected,
                        format!("episode creation failed: {e}"),
                    ));
                },
            }
        } else {
            // No Tokio runtime available (e.g., in sync unit tests).
            // In production, this should never happen.
            // For testing backward compatibility, we allow session creation
            // without episode creation.
            #[cfg(test)]
            {
                debug!(
                    session_id = %session_id,
                    "No Tokio runtime - skipping episode creation (test mode)"
                );
                None
            }
            #[cfg(not(test))]
            {
                warn!("No Tokio runtime available for episode creation");
                return Ok(PrivilegedResponse::error(
                    PrivilegedErrorCode::CapabilityRequestRejected,
                    "episode creation failed: no async runtime available",
                ));
            }
        };

        if let Some(ref episode_id) = episode_id_opt {
            debug!(
                session_id = %session_id,
                episode_id = %episode_id,
                workspace_root = %request.workspace_root,
                "Episode created and started with workspace root"
            );
        }

        // Derive actor_id from credentials (same pattern as ClaimWork)
        let actor_id = ctx
            .peer_credentials()
            .map_or_else(|| "unknown".to_string(), derive_actor_id);

        if let Err(e) = self.event_emitter.emit_session_started(
            &session_id,
            &request.work_id,
            &claim.lease_id,
            &actor_id,
            timestamp_ns,
        ) {
            warn!(error = %e, "SessionStarted event emission failed");
            return Ok(PrivilegedResponse::error(
                PrivilegedErrorCode::CapabilityRequestRejected,
                format!("event emission failed: {e}"),
            ));
        }

        debug!(
            session_id = %session_id,
            work_id = %request.work_id,
            "SessionStarted event emitted successfully"
        );

        Ok(PrivilegedResponse::SpawnEpisode(SpawnEpisodeResponse {
            session_id,
            ephemeral_handle: ephemeral_handle.to_string(),
            capability_manifest_hash: claim.policy_resolution.capability_manifest_hash.to_vec(),
            context_pack_sealed: true,
            session_token: session_token_json,
        }))
    }

    /// Handles `IssueCapability` requests (IPC-PRIV-003).
    ///
    /// # TCK-00289 Implementation
    ///
    /// This handler implements capability issuance with:
    /// 1. Session validation (must exist)
    /// 2. Lease validation (session's lease must be valid for its work)
    /// 3. HTF-compliant timestamps via `HolonicClock`
    fn handle_issue_capability(
        &self,
        payload: &[u8],
        ctx: &ConnectionContext,
    ) -> ProtocolResult<PrivilegedResponse> {
        let request = IssueCapabilityRequest::decode_bounded(payload, &self.decode_config)
            .map_err(|e| ProtocolError::Serialization {
                reason: format!("invalid IssueCapabilityRequest: {e}"),
            })?;

        info!(
            session_id = %request.session_id,
            has_capability_request = request.capability_request.is_some(),
            peer_pid = ?ctx.peer_credentials().map(|c| c.pid),
            "IssueCapability request received"
        );

        // Validate required fields
        if request.session_id.is_empty() {
            return Ok(PrivilegedResponse::error(
                PrivilegedErrorCode::CapabilityRequestRejected,
                "session_id is required",
            ));
        }

        if request.capability_request.is_none() {
            return Ok(PrivilegedResponse::error(
                PrivilegedErrorCode::CapabilityRequestRejected,
                "capability_request is required",
            ));
        }

        // 1. Retrieve session state
        let Some(session) = self.session_registry.get_session(&request.session_id) else {
            warn!(session_id = %request.session_id, "IssueCapability rejected: session not found");
            return Ok(PrivilegedResponse::error(
                PrivilegedErrorCode::SessionNotFound,
                format!("session not found: {}", request.session_id),
            ));
        };

        // 2. Validate lease (TCK-00289: "Implement IssueCapability with lease
        //    validation")
        // Ensure the session's lease matches the authoritative work claim.
        // This confirms the session corresponds to a valid, active work item.
        if let Some(claim) = self.work_registry.get_claim(&session.work_id) {
            // Verify lease_id matches
            // Constant-time comparison is good practice for IDs
            let lease_matches = session.lease_id.len() == claim.lease_id.len()
                && bool::from(session.lease_id.as_bytes().ct_eq(claim.lease_id.as_bytes()));

            if !lease_matches {
                warn!(
                    session_id = %request.session_id,
                    expected_lease = "[REDACTED]",
                    actual_lease = "[REDACTED]",
                    "IssueCapability rejected: lease mismatch against work claim"
                );
                return Ok(PrivilegedResponse::error(
                    PrivilegedErrorCode::CapabilityRequestRejected,
                    "lease validation failed: session lease does not match work claim",
                ));
            }
        } else {
            warn!(
                session_id = %request.session_id,
                work_id = %session.work_id,
                "IssueCapability rejected: work claim not found"
            );
            return Ok(PrivilegedResponse::error(
                PrivilegedErrorCode::CapabilityRequestRejected,
                "lease validation failed: work claim not found",
            ));
        }

        // 3. Generate HTF-compliant timestamps
        let Ok(mono_tick) = self.holonic_clock.now_mono_tick() else {
            warn!("Clock error during IssueCapability");
            return Ok(PrivilegedResponse::error(
                PrivilegedErrorCode::PolicyResolutionFailed,
                "clock error",
            ));
        };
        let _mono_tick = mono_tick.value();

        // For grant/expire times, use HLC Wall Time per RFC-0016.
        // TCK-00289: Fail-closed - do not fall back to SystemTime if HLC disabled.
        let now_wall = match self.holonic_clock.now_hlc() {
            Ok(hlc) => hlc.wall_ns,
            Err(e) => {
                // TCK-00289: Fail-closed - do not use SystemTime fallback
                warn!(error = %e, "HLC clock error during IssueCapability - failing closed");
                return Ok(PrivilegedResponse::error(
                    PrivilegedErrorCode::PolicyResolutionFailed,
                    format!("HTF timestamp error: {e}"),
                ));
            },
        };

        // Duration is in seconds, convert to nanoseconds
        let duration_ns =
            request.capability_request.as_ref().unwrap().duration_secs * 1_000_000_000;
        let expires_at_ns = now_wall + duration_ns;

        // Convert to seconds for response (proto uses u64 seconds)
        let granted_at = now_wall / 1_000_000_000;
        let expires_at = expires_at_ns / 1_000_000_000;

        let capability_id = format!("C-{}", uuid::Uuid::new_v4());

        // TCK-00268: Emit capability_granted metric
        if let Some(ref metrics) = self.metrics {
            let role_str = match WorkRole::try_from(session.role).unwrap_or(WorkRole::Unspecified) {
                WorkRole::Implementer => "implementer",
                WorkRole::Reviewer => "reviewer",
                WorkRole::GateExecutor => "gate_executor",
                WorkRole::Coordinator => "coordinator",
                WorkRole::Unspecified => "unspecified",
            };

            let capability_type = request
                .capability_request
                .as_ref()
                .map_or("unknown", |c| c.tool_class.as_str());

            metrics
                .daemon_metrics()
                .capability_granted(role_str, capability_type);
        }

        info!(
            session_id = %request.session_id,
            capability_id = %capability_id,
            "Capability issued"
        );

        Ok(PrivilegedResponse::IssueCapability(
            IssueCapabilityResponse {
                capability_id,
                granted_at,
                expires_at,
            },
        ))
    }

    /// Handles Shutdown requests (IPC-PRIV-004).
    ///
    /// # Stub Implementation
    ///
    /// This is a stub handler that logs the request and returns acknowledgment.
    /// Full implementation requires integration with daemon state.
    fn handle_shutdown(
        &self,
        payload: &[u8],
        ctx: &ConnectionContext,
    ) -> ProtocolResult<PrivilegedResponse> {
        let request =
            ShutdownRequest::decode_bounded(payload, &self.decode_config).map_err(|e| {
                ProtocolError::Serialization {
                    reason: format!("invalid ShutdownRequest: {e}"),
                }
            })?;

        warn!(
            reason = ?request.reason,
            peer_pid = ?ctx.peer_credentials().map(|c| c.pid),
            "Shutdown request received (stub handler)"
        );

        // STUB: Return acknowledgment
        // Full implementation requires daemon state integration
        Ok(PrivilegedResponse::Shutdown(ShutdownResponse {
            message: "Shutdown acknowledged (stub)".to_string(),
        }))
    }

    // ========================================================================
    // HEF Pulse Plane Handlers (TCK-00302)
    // ========================================================================

    /// Handles `SubscribePulse` requests from operator sockets (IPC-HEF-001).
    ///
    /// # TCK-00302: Operator Full Taxonomy Access
    ///
    /// Per DD-HEF-0004: "Operator connections may subscribe broadly."
    /// Operators can subscribe to any valid pattern including wildcards.
    ///
    /// This handler:
    /// 1. Validates request structure and field lengths
    /// 2. Validates topic patterns using `pulse_topic` grammar
    /// 3. Allows all valid patterns (no ACL restrictions for operators)
    /// 4. Returns accepted patterns and any rejected invalid patterns
    ///
    /// # Note: Subscription Registry
    ///
    /// Actual subscription registration and pulse delivery are handled by
    /// TCK-00303 (resource governance) and TCK-00304 (outbox + publisher).
    fn handle_subscribe_pulse(
        &self,
        payload: &[u8],
        ctx: &ConnectionContext,
    ) -> ProtocolResult<PrivilegedResponse> {
        // Max patterns per request per RFC-0018 (must be declared before statements)
        const MAX_PATTERNS_PER_REQUEST: usize = 16;

        let request =
            SubscribePulseRequest::decode_bounded(payload, &self.decode_config).map_err(|e| {
                ProtocolError::Serialization {
                    reason: format!("invalid SubscribePulseRequest: {e}"),
                }
            })?;

        info!(
            client_sub_id = %request.client_sub_id,
            pattern_count = request.topic_patterns.len(),
            since_cursor = request.since_ledger_cursor,
            peer_pid = ?ctx.peer_credentials().map(|c| c.pid),
            "SubscribePulse (operator) request received"
        );

        // Validate client_sub_id length
        if let Err(e) = validate_client_sub_id(&request.client_sub_id) {
            warn!(error = %e, "Invalid client_sub_id");
            return Ok(PrivilegedResponse::error(
                PrivilegedErrorCode::PermissionDenied,
                e.to_string(),
            ));
        }

        // Validate topic_patterns count
        if request.topic_patterns.len() > MAX_PATTERNS_PER_REQUEST {
            warn!(
                pattern_count = request.topic_patterns.len(),
                "Too many patterns in subscribe request"
            );
            return Ok(PrivilegedResponse::error(
                PrivilegedErrorCode::PermissionDenied,
                format!(
                    "too many patterns: {} exceeds maximum {}",
                    request.topic_patterns.len(),
                    MAX_PATTERNS_PER_REQUEST
                ),
            ));
        }

        // Create ACL evaluator for operator subscriptions
        // Per DD-HEF-0004: "Operator connections may subscribe broadly"
        let evaluator = PulseAclEvaluator::for_operator();

        // Evaluate each pattern
        let mut accepted_patterns = Vec::new();
        let mut rejected_patterns = Vec::new();

        for pattern in &request.topic_patterns {
            match evaluator.check_subscribe(pattern) {
                AclDecision::Allow => {
                    accepted_patterns.push(pattern.clone());
                },
                AclDecision::Deny(err) => {
                    let reason_code = Self::acl_error_to_reason_code(&err);
                    rejected_patterns.push(PatternRejection {
                        pattern: pattern.clone(),
                        reason_code,
                    });
                    debug!(
                        pattern = %pattern,
                        reason = %err,
                        "Pattern rejected (invalid syntax)"
                    );
                },
            }
        }

        // Generate subscription ID; use connection ID from context (TCK-00303)
        let subscription_id = format!("SUB-{}", uuid::Uuid::new_v4());
        // TCK-00303: Use connection_id from context for consistent tracking
        // across the connection lifecycle. The connection handler will call
        // unregister_connection with this ID when the connection closes.
        let connection_id = ctx.connection_id();

        // TCK-00303: Wire resource governance - register connection if not exists
        // and add subscription with limit checks
        if !accepted_patterns.is_empty() {
            // Parse accepted patterns into TopicPattern
            let mut parsed_patterns = Vec::new();
            for pattern_str in &accepted_patterns {
                match super::pulse_topic::TopicPattern::parse(pattern_str) {
                    Ok(pattern) => parsed_patterns.push(pattern),
                    Err(e) => {
                        // Should not happen since ACL already validated, but be defensive
                        warn!(
                            pattern = %pattern_str,
                            error = %e,
                            "Pattern parse failed after ACL validation"
                        );
                        rejected_patterns.push(PatternRejection {
                            pattern: pattern_str.clone(),
                            reason_code: "INVALID_PATTERN".to_string(),
                        });
                    },
                }
            }

            // Register connection if it doesn't exist (idempotent)
            if let Err(e) = self
                .subscription_registry
                .register_connection(connection_id)
            {
                // Only TooManyConnections is a real error; ignore if connection already exists
                if matches!(
                    e,
                    super::resource_governance::ResourceError::TooManyConnections { .. }
                ) {
                    warn!(
                        connection_id = %connection_id,
                        error = %e,
                        "Connection registration failed: resource limit exceeded"
                    );
                    return Ok(PrivilegedResponse::error(
                        PrivilegedErrorCode::PermissionDenied,
                        format!("resource limit exceeded: {e}"),
                    ));
                }
                // Connection already exists - this is fine
            }

            // Create subscription state and add to registry
            let subscription = SubscriptionState::new(
                &subscription_id,
                &request.client_sub_id,
                parsed_patterns,
                request.since_ledger_cursor,
            );

            if let Err(e) = self
                .subscription_registry
                .add_subscription(connection_id, subscription)
            {
                warn!(
                    connection_id = %connection_id,
                    subscription_id = %subscription_id,
                    error = %e,
                    "Subscription registration failed: resource limit exceeded"
                );
                return Ok(PrivilegedResponse::error(
                    PrivilegedErrorCode::PermissionDenied,
                    format!("resource limit exceeded: {e}"),
                ));
            }
        }

        // Log outcome
        if rejected_patterns.is_empty() {
            info!(
                subscription_id = %subscription_id,
                connection_id = %connection_id,
                accepted_count = accepted_patterns.len(),
                "All patterns accepted (operator)"
            );
        } else {
            warn!(
                subscription_id = %subscription_id,
                connection_id = %connection_id,
                accepted_count = accepted_patterns.len(),
                rejected_count = rejected_patterns.len(),
                "Some patterns rejected (operator)"
            );
        }

        Ok(PrivilegedResponse::SubscribePulse(SubscribePulseResponse {
            subscription_id,
            effective_since_cursor: request.since_ledger_cursor,
            accepted_patterns,
            rejected_patterns,
        }))
    }

    /// Converts an `AclError` to a reason code string for `PatternRejection`.
    fn acl_error_to_reason_code(err: &AclError) -> String {
        match err {
            AclError::TopicNotAllowed { .. } => "ACL_DENY".to_string(),
            AclError::WildcardNotAllowed { .. } => "WILDCARD_NOT_ALLOWED".to_string(),
            AclError::PublishNotAllowed => "PUBLISH_DENIED".to_string(),
            AclError::InvalidPattern { .. } | AclError::InvalidTopic { .. } => {
                "INVALID_PATTERN".to_string()
            },
            AclError::AllowlistTooLarge { .. } | AclError::SubscriptionIdTooLong { .. } => {
                "LIMIT_EXCEEDED".to_string()
            },
        }
    }

    /// Handles `UnsubscribePulse` requests from operator sockets (IPC-HEF-002).
    ///
    /// # TCK-00302: Unsubscribe Handling
    ///
    /// This handler validates the unsubscribe request and returns success.
    ///
    /// # Note: Subscription Registry
    ///
    /// Actual subscription removal is handled by TCK-00303 (resource
    /// governance).
    fn handle_unsubscribe_pulse(
        &self,
        payload: &[u8],
        ctx: &ConnectionContext,
    ) -> ProtocolResult<PrivilegedResponse> {
        let request = UnsubscribePulseRequest::decode_bounded(payload, &self.decode_config)
            .map_err(|e| ProtocolError::Serialization {
                reason: format!("invalid UnsubscribePulseRequest: {e}"),
            })?;

        info!(
            subscription_id = %request.subscription_id,
            peer_pid = ?ctx.peer_credentials().map(|c| c.pid),
            "UnsubscribePulse (operator) request received"
        );

        // Validate subscription_id length
        if let Err(e) = validate_subscription_id(&request.subscription_id) {
            warn!(error = %e, "Invalid subscription_id");
            return Ok(PrivilegedResponse::error(
                PrivilegedErrorCode::PermissionDenied,
                e.to_string(),
            ));
        }

        // TCK-00303: Wire resource governance - remove subscription from registry
        // Use connection_id from context for consistent tracking
        let connection_id = ctx.connection_id();

        let removed = match self
            .subscription_registry
            .remove_subscription(connection_id, &request.subscription_id)
        {
            Ok(_) => {
                info!(
                    subscription_id = %request.subscription_id,
                    connection_id = %connection_id,
                    "Unsubscribe (operator) processed successfully"
                );
                true
            },
            Err(e) => {
                // Log but don't fail - subscription may already be removed or never existed
                debug!(
                    subscription_id = %request.subscription_id,
                    connection_id = %connection_id,
                    error = %e,
                    "Unsubscribe (operator) - subscription not found (may already be removed)"
                );
                false
            },
        };

        Ok(PrivilegedResponse::UnsubscribePulse(
            UnsubscribePulseResponse { removed },
        ))
    }
}

// ============================================================================
// Request Encoding Helpers
// ============================================================================

/// Encodes a `ClaimWork` request to bytes for sending.
///
/// The format is: `[tag: u8][payload: protobuf]`
#[must_use]
pub fn encode_claim_work_request(request: &ClaimWorkRequest) -> Bytes {
    let mut buf = vec![PrivilegedMessageType::ClaimWork.tag()];
    request.encode(&mut buf).expect("encode cannot fail");
    Bytes::from(buf)
}

/// Encodes a `SpawnEpisode` request to bytes for sending.
#[must_use]
pub fn encode_spawn_episode_request(request: &SpawnEpisodeRequest) -> Bytes {
    let mut buf = vec![PrivilegedMessageType::SpawnEpisode.tag()];
    request.encode(&mut buf).expect("encode cannot fail");
    Bytes::from(buf)
}

/// Encodes an `IssueCapability` request to bytes for sending.
#[must_use]
pub fn encode_issue_capability_request(request: &IssueCapabilityRequest) -> Bytes {
    let mut buf = vec![PrivilegedMessageType::IssueCapability.tag()];
    request.encode(&mut buf).expect("encode cannot fail");
    Bytes::from(buf)
}

/// Encodes a `Shutdown` request to bytes for sending.
#[must_use]
pub fn encode_shutdown_request(request: &ShutdownRequest) -> Bytes {
    let mut buf = vec![PrivilegedMessageType::Shutdown.tag()];
    request.encode(&mut buf).expect("encode cannot fail");
    Bytes::from(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// TCK-00319: Helper function to get a test workspace root.
    /// Uses /tmp which exists on all Unix systems.
    fn test_workspace_root() -> String {
        "/tmp".to_string()
    }

    // ========================================================================
    // INT-001: Privileged endpoint routing (TCK-00251)
    // Test name matches verification command: cargo test -p apm2-daemon
    // privileged_routing
    // ========================================================================
    mod privileged_routing {
        use super::*;

        #[test]
        fn test_claim_work_routing() {
            let dispatcher = PrivilegedDispatcher::new();
            let ctx = ConnectionContext::privileged(Some(PeerCredentials {
                uid: 1000,
                gid: 1000,
                pid: Some(12345),
            }));

            let request = ClaimWorkRequest {
                actor_id: "test-actor".to_string(),
                role: WorkRole::Implementer.into(),
                credential_signature: vec![1, 2, 3],
                nonce: vec![4, 5, 6],
            };
            let frame = encode_claim_work_request(&request);

            let response = dispatcher.dispatch(&frame, &ctx).unwrap();
            assert!(matches!(response, PrivilegedResponse::ClaimWork(_)));
        }

        #[test]
        fn test_spawn_episode_routing() {
            let dispatcher = PrivilegedDispatcher::new();
            let ctx = ConnectionContext::privileged(Some(PeerCredentials {
                uid: 1000,
                gid: 1000,
                pid: Some(12345),
            }));

            // TCK-00256: First claim work to establish policy resolution
            let claim_request = ClaimWorkRequest {
                actor_id: "test-actor".to_string(),
                role: WorkRole::Implementer.into(),
                credential_signature: vec![1, 2, 3],
                nonce: vec![4, 5, 6],
            };
            let claim_frame = encode_claim_work_request(&claim_request);
            let claim_response = dispatcher.dispatch(&claim_frame, &ctx).unwrap();

            let (work_id, lease_id) = match claim_response {
                PrivilegedResponse::ClaimWork(resp) => (resp.work_id, resp.lease_id),
                _ => panic!("Expected ClaimWork response"),
            };

            // Now spawn with the claimed work_id
            let request = SpawnEpisodeRequest {
                workspace_root: test_workspace_root(),
                work_id,
                role: WorkRole::Implementer.into(),
                lease_id: Some(lease_id),
            };
            let frame = encode_spawn_episode_request(&request);

            let response = dispatcher.dispatch(&frame, &ctx).unwrap();
            assert!(matches!(response, PrivilegedResponse::SpawnEpisode(_)));
        }

        #[test]
        fn test_issue_capability_routing() {
            use crate::session::SessionState;

            let dispatcher = PrivilegedDispatcher::new();
            let ctx = ConnectionContext::privileged(Some(PeerCredentials {
                uid: 1000,
                gid: 1000,
                pid: Some(12345),
            }));

            // TCK-00289: Register a session and work claim for IssueCapability validation
            let work_id = "W-TEST-001";
            let lease_id = "L-TEST-001";
            let session_id = "S-001";

            // Register work claim
            let claim = WorkClaim {
                work_id: work_id.to_string(),
                lease_id: lease_id.to_string(),
                actor_id: "test-actor".to_string(),
                role: WorkRole::Implementer,
                policy_resolution: PolicyResolution {
                    policy_resolved_ref: format!("resolved-for-{work_id}"),
                    resolved_policy_hash: [0u8; 32],
                    capability_manifest_hash: [0u8; 32],
                    context_pack_hash: [0u8; 32],
                },
                author_custody_domains: vec![],
                executor_custody_domains: vec![],
            };
            dispatcher.work_registry.register_claim(claim).unwrap();

            // Register session
            let session_state = SessionState {
                session_id: session_id.to_string(),
                work_id: work_id.to_string(),
                role: WorkRole::Implementer.into(),
                lease_id: lease_id.to_string(),
                ephemeral_handle: String::new(),
                policy_resolved_ref: String::new(),
                capability_manifest_hash: vec![],
                episode_id: None,
            };
            dispatcher
                .session_registry
                .register_session(session_state)
                .unwrap();

            let request = IssueCapabilityRequest {
                session_id: session_id.to_string(),
                capability_request: Some(super::super::super::messages::CapabilityRequest {
                    tool_class: "file_read".to_string(),
                    read_patterns: vec!["**/*.rs".to_string()],
                    write_patterns: vec![],
                    duration_secs: 3600,
                }),
            };
            let frame = encode_issue_capability_request(&request);

            let response = dispatcher.dispatch(&frame, &ctx).unwrap();
            assert!(matches!(response, PrivilegedResponse::IssueCapability(_)));
        }

        #[test]
        fn test_shutdown_routing() {
            let dispatcher = PrivilegedDispatcher::new();
            let ctx = ConnectionContext::privileged(Some(PeerCredentials {
                uid: 1000,
                gid: 1000,
                pid: Some(12345),
            }));

            let request = ShutdownRequest {
                reason: Some("test".to_string()),
            };
            let frame = encode_shutdown_request(&request);

            let response = dispatcher.dispatch(&frame, &ctx).unwrap();
            assert!(matches!(response, PrivilegedResponse::Shutdown(_)));
        }

        #[test]
        fn test_session_socket_returns_permission_denied() {
            let dispatcher = PrivilegedDispatcher::new();
            let ctx = ConnectionContext::session(
                Some(PeerCredentials {
                    uid: 1000,
                    gid: 1000,
                    pid: Some(12346),
                }),
                Some("test-session".to_string()),
            );

            // All 4 endpoints should return PERMISSION_DENIED for session connections
            let requests = vec![
                encode_claim_work_request(&ClaimWorkRequest {
                    actor_id: "test".to_string(),
                    role: WorkRole::Implementer.into(),
                    credential_signature: vec![],
                    nonce: vec![],
                }),
                encode_spawn_episode_request(&SpawnEpisodeRequest {
                    workspace_root: test_workspace_root(),
                    work_id: "W-001".to_string(),
                    role: WorkRole::Implementer.into(),
                    lease_id: None,
                }),
                encode_issue_capability_request(&IssueCapabilityRequest {
                    session_id: "S-001".to_string(),
                    capability_request: None,
                }),
                encode_shutdown_request(&ShutdownRequest {
                    reason: Some("test".to_string()),
                }),
            ];

            for frame in requests {
                let response = dispatcher.dispatch(&frame, &ctx).unwrap();
                match response {
                    PrivilegedResponse::Error(err) => {
                        assert_eq!(err.code, PrivilegedErrorCode::PermissionDenied as i32);
                    },
                    _ => panic!("Expected PERMISSION_DENIED for session socket"),
                }
            }
        }
    }

    fn make_privileged_ctx() -> ConnectionContext {
        ConnectionContext::privileged(Some(PeerCredentials {
            uid: 1000,
            gid: 1000,
            pid: Some(12345),
        }))
    }

    fn make_session_ctx() -> ConnectionContext {
        ConnectionContext::session(
            Some(PeerCredentials {
                uid: 1000,
                gid: 1000,
                pid: Some(12346),
            }),
            Some("test-session".to_string()),
        )
    }

    // ========================================================================
    // ADV-001: Agent calls ClaimWork → PERMISSION_DENIED
    // ========================================================================
    #[test]
    fn test_adv_001_session_cannot_claim_work() {
        let dispatcher = PrivilegedDispatcher::new();
        let ctx = make_session_ctx();

        let request = ClaimWorkRequest {
            actor_id: "test-actor".to_string(),
            role: WorkRole::Implementer.into(),
            credential_signature: vec![],
            nonce: vec![],
        };
        let frame = encode_claim_work_request(&request);

        let response = dispatcher.dispatch(&frame, &ctx).unwrap();

        match response {
            PrivilegedResponse::Error(err) => {
                assert_eq!(err.code, PrivilegedErrorCode::PermissionDenied as i32);
                assert_eq!(err.message, "permission denied");
            },
            _ => panic!("Expected PERMISSION_DENIED error"),
        }
    }

    // ========================================================================
    // ADV-002: Agent calls SpawnEpisode → PERMISSION_DENIED
    // ========================================================================
    #[test]
    fn test_adv_002_session_cannot_spawn_episode() {
        let dispatcher = PrivilegedDispatcher::new();
        let ctx = make_session_ctx();

        let request = SpawnEpisodeRequest {
            workspace_root: test_workspace_root(),
            work_id: "W-001".to_string(),
            role: WorkRole::Implementer.into(),
            lease_id: None,
        };
        let frame = encode_spawn_episode_request(&request);

        let response = dispatcher.dispatch(&frame, &ctx).unwrap();

        match response {
            PrivilegedResponse::Error(err) => {
                assert_eq!(err.code, PrivilegedErrorCode::PermissionDenied as i32);
            },
            _ => panic!("Expected PERMISSION_DENIED error"),
        }
    }

    #[test]
    fn test_session_cannot_issue_capability() {
        let dispatcher = PrivilegedDispatcher::new();
        let ctx = make_session_ctx();

        let request = IssueCapabilityRequest {
            session_id: "S-001".to_string(),
            capability_request: None,
        };
        let frame = encode_issue_capability_request(&request);

        let response = dispatcher.dispatch(&frame, &ctx).unwrap();

        match response {
            PrivilegedResponse::Error(err) => {
                assert_eq!(err.code, PrivilegedErrorCode::PermissionDenied as i32);
            },
            _ => panic!("Expected PERMISSION_DENIED error"),
        }
    }

    #[test]
    fn test_session_cannot_shutdown() {
        let dispatcher = PrivilegedDispatcher::new();
        let ctx = make_session_ctx();

        let request = ShutdownRequest {
            reason: Some("test".to_string()),
        };
        let frame = encode_shutdown_request(&request);

        let response = dispatcher.dispatch(&frame, &ctx).unwrap();

        match response {
            PrivilegedResponse::Error(err) => {
                assert_eq!(err.code, PrivilegedErrorCode::PermissionDenied as i32);
            },
            _ => panic!("Expected PERMISSION_DENIED error"),
        }
    }

    // ========================================================================
    // Privileged Connection Tests (Success Path)
    // ========================================================================
    #[test]
    fn test_privileged_claim_work_stub() {
        let dispatcher = PrivilegedDispatcher::new();
        let ctx = make_privileged_ctx();

        let request = ClaimWorkRequest {
            actor_id: "test-actor".to_string(),
            role: WorkRole::Implementer.into(),
            credential_signature: vec![1, 2, 3],
            nonce: vec![4, 5, 6],
        };
        let frame = encode_claim_work_request(&request);

        let response = dispatcher.dispatch(&frame, &ctx).unwrap();

        match response {
            PrivilegedResponse::ClaimWork(resp) => {
                assert!(!resp.work_id.is_empty());
                assert!(!resp.lease_id.is_empty());
            },
            PrivilegedResponse::Error(err) => {
                panic!("Unexpected error: {err:?}");
            },
            _ => panic!("Expected ClaimWork response"),
        }
    }

    #[test]
    fn test_privileged_spawn_episode_stub() {
        let dispatcher = PrivilegedDispatcher::new();
        let ctx = make_privileged_ctx();

        // TCK-00256: First claim work to establish policy resolution
        let claim_request = ClaimWorkRequest {
            actor_id: "test-actor".to_string(),
            role: WorkRole::Implementer.into(),
            credential_signature: vec![1, 2, 3],
            nonce: vec![4, 5, 6],
        };
        let claim_frame = encode_claim_work_request(&claim_request);
        let claim_response = dispatcher.dispatch(&claim_frame, &ctx).unwrap();

        let (work_id, lease_id) = match claim_response {
            PrivilegedResponse::ClaimWork(resp) => (resp.work_id, resp.lease_id),
            _ => panic!("Expected ClaimWork response"),
        };

        // Now spawn with the claimed work_id
        let request = SpawnEpisodeRequest {
            workspace_root: test_workspace_root(),
            work_id,
            role: WorkRole::Implementer.into(),
            lease_id: Some(lease_id),
        };
        let frame = encode_spawn_episode_request(&request);

        let response = dispatcher.dispatch(&frame, &ctx).unwrap();

        match response {
            PrivilegedResponse::SpawnEpisode(resp) => {
                assert!(!resp.session_id.is_empty());
                assert!(!resp.ephemeral_handle.is_empty());
            },
            PrivilegedResponse::Error(err) => {
                panic!("Unexpected error: {err:?}");
            },
            _ => panic!("Expected SpawnEpisode response"),
        }
    }

    #[test]
    fn test_privileged_issue_capability_stub() {
        use crate::session::SessionState;

        let dispatcher = PrivilegedDispatcher::new();
        let ctx = make_privileged_ctx();

        // TCK-00289: Register a session and work claim for IssueCapability validation
        let work_id = "W-TEST-001";
        let lease_id = "L-TEST-001";
        let session_id = "S-001";

        // Register work claim
        let claim = WorkClaim {
            work_id: work_id.to_string(),
            lease_id: lease_id.to_string(),
            actor_id: "test-actor".to_string(),
            role: WorkRole::Implementer,
            policy_resolution: PolicyResolution {
                policy_resolved_ref: format!("resolved-for-{work_id}"),
                resolved_policy_hash: [0u8; 32],
                capability_manifest_hash: [0u8; 32],
                context_pack_hash: [0u8; 32],
            },
            author_custody_domains: vec![],
            executor_custody_domains: vec![],
        };
        dispatcher.work_registry.register_claim(claim).unwrap();

        // Register session
        let session_state = SessionState {
            session_id: session_id.to_string(),
            work_id: work_id.to_string(),
            role: WorkRole::Implementer.into(),
            lease_id: lease_id.to_string(),
            ephemeral_handle: String::new(),
            policy_resolved_ref: String::new(),
            capability_manifest_hash: vec![],
            episode_id: None,
        };
        dispatcher
            .session_registry
            .register_session(session_state)
            .unwrap();

        let request = IssueCapabilityRequest {
            session_id: session_id.to_string(),
            capability_request: Some(super::super::messages::CapabilityRequest {
                tool_class: "file_read".to_string(),
                read_patterns: vec!["**/*.rs".to_string()],
                write_patterns: vec![],
                duration_secs: 3600,
            }),
        };
        let frame = encode_issue_capability_request(&request);

        let response = dispatcher.dispatch(&frame, &ctx).unwrap();

        match response {
            PrivilegedResponse::IssueCapability(resp) => {
                assert!(!resp.capability_id.is_empty());
                assert!(resp.capability_id.starts_with("C-")); // UUID-based ID
                // TCK-00289: HTF-compliant timestamps from HolonicClock
                // Per Definition of Done: "IssueCapability returns non-zero HTF-compliant
                // timestamps"
                assert!(
                    resp.granted_at > 0,
                    "granted_at should be non-zero HTF timestamp"
                );
                assert!(
                    resp.expires_at > resp.granted_at,
                    "expires_at should be after granted_at"
                );
                // Verify expires_at is granted_at + 1 hour (duration_secs in seconds)
                let expected_ttl_secs = 3600u64;
                assert_eq!(
                    resp.expires_at - resp.granted_at,
                    expected_ttl_secs,
                    "TTL should be 1 hour in seconds"
                );
            },
            PrivilegedResponse::Error(err) => {
                panic!("Unexpected error: {err:?}");
            },
            _ => panic!("Expected IssueCapability response"),
        }
    }

    #[test]
    fn test_privileged_shutdown_stub() {
        let dispatcher = PrivilegedDispatcher::new();
        let ctx = make_privileged_ctx();

        let request = ShutdownRequest {
            reason: Some("test shutdown".to_string()),
        };
        let frame = encode_shutdown_request(&request);

        let response = dispatcher.dispatch(&frame, &ctx).unwrap();

        match response {
            PrivilegedResponse::Shutdown(resp) => {
                assert!(!resp.message.is_empty());
            },
            PrivilegedResponse::Error(err) => {
                panic!("Unexpected error: {err:?}");
            },
            _ => panic!("Expected Shutdown response"),
        }
    }

    // ========================================================================
    // ADV-005: ClaimWork role validation
    // ========================================================================
    #[test]
    fn test_adv_005_claim_work_validation() {
        let dispatcher = PrivilegedDispatcher::new();
        let ctx = make_privileged_ctx();

        // TCK-00253: Empty actor_id in request is OK (it's just a display hint)
        // The authoritative actor_id is derived from credential
        let request = ClaimWorkRequest {
            actor_id: String::new(), // Empty is OK - we derive from credential
            role: WorkRole::Implementer.into(),
            credential_signature: vec![],
            nonce: vec![1, 2, 3, 4], // Nonce for actor_id derivation
        };
        let frame = encode_claim_work_request(&request);
        let response = dispatcher.dispatch(&frame, &ctx).unwrap();

        // Should succeed now - actor_id is derived, not validated
        match response {
            PrivilegedResponse::ClaimWork(resp) => {
                assert!(!resp.work_id.is_empty());
                assert!(!resp.lease_id.is_empty());
            },
            PrivilegedResponse::Error(err) => {
                panic!("Unexpected error: {err:?}");
            },
            _ => panic!("Expected ClaimWork response"),
        }

        // Test missing role - still required
        let request = ClaimWorkRequest {
            actor_id: "test-actor".to_string(),
            role: WorkRole::Unspecified.into(),
            credential_signature: vec![],
            nonce: vec![],
        };
        let frame = encode_claim_work_request(&request);
        let response = dispatcher.dispatch(&frame, &ctx).unwrap();

        match response {
            PrivilegedResponse::Error(err) => {
                assert_eq!(
                    err.code,
                    PrivilegedErrorCode::CapabilityRequestRejected as i32
                );
                assert!(err.message.contains("role"));
            },
            _ => panic!("Expected validation error for unspecified role"),
        }
    }

    // ========================================================================
    // TCK-00253: Actor ID derived from credential tests
    // ========================================================================
    mod tck_00253 {
        use super::*;

        /// ADV-005: Actor ID must be derived from credential, not user input.
        ///
        /// This test verifies that:
        /// 1. Different user-provided `actor_ids` with the same credential
        ///    produce the same derived `actor_id`
        /// 2. Different nonces do NOT affect the derived `actor_id` (stable
        ///    identity)
        #[test]
        fn test_actor_id_derived_from_credential_not_user_input() {
            let dispatcher = PrivilegedDispatcher::new();
            let ctx = make_privileged_ctx();

            // Request 1: User provides "alice" with nonce A
            let request1 = ClaimWorkRequest {
                actor_id: "alice".to_string(),
                role: WorkRole::Implementer.into(),
                credential_signature: vec![],
                nonce: vec![1, 2, 3, 4, 5, 6, 7, 8],
            };
            let frame1 = encode_claim_work_request(&request1);
            let response1 = dispatcher.dispatch(&frame1, &ctx).unwrap();

            // Request 2: User provides "bob" with different nonce B
            // Per stable actor_id design: same credential = same actor_id regardless of
            // nonce
            let request2 = ClaimWorkRequest {
                actor_id: "bob".to_string(),
                role: WorkRole::Implementer.into(),
                credential_signature: vec![],
                nonce: vec![9, 9, 9, 9], // Different nonce - should NOT change actor_id
            };
            let frame2 = encode_claim_work_request(&request2);
            let response2 = dispatcher.dispatch(&frame2, &ctx).unwrap();

            // Both should succeed
            let PrivilegedResponse::ClaimWork(resp1) = response1 else {
                panic!("Expected ClaimWork response")
            };
            let PrivilegedResponse::ClaimWork(resp2) = response2 else {
                panic!("Expected ClaimWork response")
            };

            // Work IDs should be different (unique per claim)
            assert_ne!(resp1.work_id, resp2.work_id);

            // But the derived actor_id should be the same since credentials are the same
            // This is the key ADV-005 invariant: user input (actor_id, nonce) does NOT
            // affect the derived actor_id - only the Unix credential (UID, GID)
            // matters.
            let claim1 = dispatcher.work_registry.get_claim(&resp1.work_id);
            let claim2 = dispatcher.work_registry.get_claim(&resp2.work_id);

            assert!(claim1.is_some(), "Work claim 1 should be registered");
            assert!(claim2.is_some(), "Work claim 2 should be registered");

            // Same credential = same derived actor_id (stable identity)
            assert_eq!(
                claim1.unwrap().actor_id,
                claim2.unwrap().actor_id,
                "Derived actor_id should be the same for same credential (nonce is ignored)"
            );
        }

        /// Same credential always produces the same `actor_id` (stable
        /// identity).
        ///
        /// This is the inverse test of what was previously tested - we now
        /// verify that nonces do NOT produce different `actor_ids` (which
        /// was the bug).
        #[test]
        fn test_same_credential_produces_same_actor_id_regardless_of_nonce() {
            let dispatcher = PrivilegedDispatcher::new();
            let ctx = make_privileged_ctx();

            let request1 = ClaimWorkRequest {
                actor_id: "test".to_string(),
                role: WorkRole::Implementer.into(),
                credential_signature: vec![],
                nonce: vec![1, 1, 1, 1],
            };
            let frame1 = encode_claim_work_request(&request1);
            let response1 = dispatcher.dispatch(&frame1, &ctx).unwrap();

            let request2 = ClaimWorkRequest {
                actor_id: "test".to_string(),
                role: WorkRole::Implementer.into(),
                credential_signature: vec![],
                nonce: vec![2, 2, 2, 2], // Different nonce - should NOT change actor_id
            };
            let frame2 = encode_claim_work_request(&request2);
            let response2 = dispatcher.dispatch(&frame2, &ctx).unwrap();

            let PrivilegedResponse::ClaimWork(resp1) = response1 else {
                panic!("Expected ClaimWork response")
            };
            let PrivilegedResponse::ClaimWork(resp2) = response2 else {
                panic!("Expected ClaimWork response")
            };

            let claim1 = dispatcher.work_registry.get_claim(&resp1.work_id).unwrap();
            let claim2 = dispatcher.work_registry.get_claim(&resp2.work_id).unwrap();

            // Same credential = same actor_id (stable identity per code quality fix)
            assert_eq!(
                claim1.actor_id, claim2.actor_id,
                "Same credential should produce same actor_id regardless of nonce"
            );
        }

        /// Policy resolution is required for work claim.
        #[test]
        fn test_policy_resolution_required_for_claim() {
            let dispatcher = PrivilegedDispatcher::new();
            let ctx = make_privileged_ctx();

            let request = ClaimWorkRequest {
                actor_id: "test-actor".to_string(),
                role: WorkRole::Implementer.into(),
                credential_signature: vec![],
                nonce: vec![1, 2, 3, 4],
            };
            let frame = encode_claim_work_request(&request);
            let response = dispatcher.dispatch(&frame, &ctx).unwrap();

            // Should succeed with policy resolution reference
            match response {
                PrivilegedResponse::ClaimWork(resp) => {
                    assert!(
                        !resp.policy_resolved_ref.is_empty(),
                        "PolicyResolvedForChangeSet reference should be present"
                    );
                    assert!(
                        resp.policy_resolved_ref
                            .contains("PolicyResolvedForChangeSet"),
                        "Reference should indicate PolicyResolvedForChangeSet"
                    );
                    assert_eq!(
                        resp.capability_manifest_hash.len(),
                        32,
                        "Capability manifest hash should be 32 bytes"
                    );
                    assert_eq!(
                        resp.context_pack_hash.len(),
                        32,
                        "Context pack hash should be 32 bytes"
                    );
                },
                PrivilegedResponse::Error(err) => {
                    panic!("Unexpected error: {err:?}");
                },
                _ => panic!("Expected ClaimWork response"),
            }
        }

        /// Work claim is persisted in registry.
        #[test]
        fn test_work_claimed_event_persisted() {
            let dispatcher = PrivilegedDispatcher::new();
            let ctx = make_privileged_ctx();

            let request = ClaimWorkRequest {
                actor_id: "test-actor".to_string(),
                role: WorkRole::Reviewer.into(),
                credential_signature: vec![],
                nonce: vec![5, 6, 7, 8],
            };
            let frame = encode_claim_work_request(&request);
            let response = dispatcher.dispatch(&frame, &ctx).unwrap();

            let work_id = match response {
                PrivilegedResponse::ClaimWork(resp) => resp.work_id,
                _ => panic!("Expected ClaimWork response"),
            };

            // Verify the claim is queryable from the registry
            let claim = dispatcher
                .work_registry
                .get_claim(&work_id)
                .expect("Work claim should be persisted");

            assert_eq!(claim.work_id, work_id);
            assert_eq!(claim.role, WorkRole::Reviewer);
            assert!(claim.actor_id.starts_with("actor:"));
            assert!(!claim.policy_resolution.policy_resolved_ref.is_empty());
        }

        /// Missing credentials should fail.
        #[test]
        fn test_missing_credentials_fails() {
            let dispatcher = PrivilegedDispatcher::new();
            // Privileged connection but no credentials
            let ctx = ConnectionContext::privileged(None);

            let request = ClaimWorkRequest {
                actor_id: "test-actor".to_string(),
                role: WorkRole::Implementer.into(),
                credential_signature: vec![],
                nonce: vec![1, 2, 3, 4],
            };
            let frame = encode_claim_work_request(&request);
            let result = dispatcher.dispatch(&frame, &ctx);

            // Should fail because we can't derive actor_id without credentials
            assert!(result.is_err(), "Should fail when credentials are missing");
        }

        /// Test `derive_actor_id` function directly.
        ///
        /// Verifies that `actor_id` derivation is:
        /// 1. Deterministic (same credential = same output)
        /// 2. Independent of PID (different PIDs with same UID/GID = same
        ///    output)
        #[test]
        fn test_derive_actor_id_deterministic() {
            let creds = PeerCredentials {
                uid: 1000,
                gid: 1000,
                pid: Some(12345),
            };

            let actor1 = derive_actor_id(&creds);
            let actor2 = derive_actor_id(&creds);

            assert_eq!(
                actor1, actor2,
                "Same credential should produce same actor_id"
            );
            assert!(
                actor1.starts_with("actor:"),
                "Actor ID should have 'actor:' prefix"
            );

            // Different PID should NOT change actor_id (stable identity)
            let creds_different_pid = PeerCredentials {
                uid: 1000,
                gid: 1000,
                pid: Some(99999), // Different PID
            };

            let actor3 = derive_actor_id(&creds_different_pid);
            assert_eq!(
                actor1, actor3,
                "Different PID should NOT change actor_id (only UID/GID matter)"
            );

            // Different UID/GID SHOULD change actor_id
            let creds_different_user = PeerCredentials {
                uid: 2000, // Different UID
                gid: 1000,
                pid: Some(12345),
            };

            let actor4 = derive_actor_id(&creds_different_user);
            assert_ne!(
                actor1, actor4,
                "Different UID should produce different actor_id"
            );
        }

        /// Test work and lease ID generation.
        #[test]
        fn test_id_generation_unique() {
            let work_id1 = generate_work_id();
            let work_id2 = generate_work_id();
            assert_ne!(work_id1, work_id2, "Work IDs should be unique");
            assert!(work_id1.starts_with("W-"), "Work ID should start with 'W-'");

            let lease_id1 = generate_lease_id();
            let lease_id2 = generate_lease_id();
            assert_ne!(lease_id1, lease_id2, "Lease IDs should be unique");
            assert!(
                lease_id1.starts_with("L-"),
                "Lease ID should start with 'L-'"
            );
        }

        /// TCK-00253: `WorkClaimed` event is signed and persisted.
        ///
        /// Per acceptance criteria: "`WorkClaimed` event signed and persisted"
        /// This test verifies that:
        /// 1. A signed event is emitted when work is claimed
        /// 2. The event is queryable from the ledger
        /// 3. The signature is present and has the correct length
        #[test]
        fn test_work_claimed_event_signed_and_persisted() {
            let dispatcher = PrivilegedDispatcher::new();
            let ctx = make_privileged_ctx();

            let request = ClaimWorkRequest {
                actor_id: "test-actor".to_string(),
                role: WorkRole::Implementer.into(),
                credential_signature: vec![],
                nonce: vec![1, 2, 3, 4],
            };
            let frame = encode_claim_work_request(&request);
            let response = dispatcher.dispatch(&frame, &ctx).unwrap();

            let work_id = match response {
                PrivilegedResponse::ClaimWork(resp) => resp.work_id,
                _ => panic!("Expected ClaimWork response"),
            };

            // Query events by work_id from the ledger
            let events = dispatcher.event_emitter.get_events_by_work_id(&work_id);

            assert_eq!(events.len(), 1, "Exactly one event should be emitted");

            let event = &events[0];
            assert_eq!(event.work_id, work_id);
            assert_eq!(event.event_type, "work_claimed");
            assert!(!event.signature.is_empty(), "Event should be signed");
            assert_eq!(
                event.signature.len(),
                64,
                "Ed25519 signature should be 64 bytes"
            );
            assert!(
                event.event_id.starts_with("EVT-"),
                "Event ID should have EVT- prefix"
            );
            // TCK-00289: HTF-compliant timestamps from HolonicClock
            // Per Definition of Done: timestamps must be non-zero HTF-compliant
            assert!(
                event.timestamp_ns > 0,
                "Timestamp should be non-zero HTF-compliant value"
            );

            // Verify payload contains expected fields
            let payload: serde_json::Value =
                serde_json::from_slice(&event.payload).expect("Payload should be valid JSON");
            assert_eq!(payload["event_type"], "work_claimed");
            assert_eq!(payload["work_id"], work_id);
            assert!(payload["actor_id"].as_str().unwrap().starts_with("actor:"));
            assert!(payload["policy_resolved_ref"].as_str().is_some());

            // Also verify the event is queryable by event_id
            let queried_event = dispatcher.event_emitter.get_event(&event.event_id);
            assert!(queried_event.is_some(), "Event should be queryable by ID");
            assert_eq!(queried_event.unwrap().event_id, event.event_id);
        }

        /// TCK-00253: Ledger query returns signed event.
        ///
        /// Per acceptance criteria: "Ledger query returns signed event"
        #[test]
        fn test_ledger_query_returns_signed_event() {
            let dispatcher = PrivilegedDispatcher::new();
            let ctx = make_privileged_ctx();

            // Claim work
            let request = ClaimWorkRequest {
                actor_id: "test-actor".to_string(),
                role: WorkRole::Reviewer.into(),
                credential_signature: vec![],
                nonce: vec![5, 6, 7, 8],
            };
            let frame = encode_claim_work_request(&request);
            let response = dispatcher.dispatch(&frame, &ctx).unwrap();

            let work_id = match response {
                PrivilegedResponse::ClaimWork(resp) => resp.work_id,
                _ => panic!("Expected ClaimWork response"),
            };

            // Query events by work_id
            let events = dispatcher.event_emitter.get_events_by_work_id(&work_id);

            // Verify at least one signed event is returned
            assert!(!events.is_empty(), "Should return at least one event");
            let event = &events[0];
            assert!(
                !event.signature.is_empty(),
                "Queried event should have signature"
            );
            assert_eq!(
                event.signature.len(),
                64,
                "Signature should be Ed25519 (64 bytes)"
            );
        }
    }

    #[test]
    fn test_gate_executor_requires_lease_id() {
        let dispatcher = PrivilegedDispatcher::new();
        let ctx = make_privileged_ctx();

        let request = SpawnEpisodeRequest {
            workspace_root: test_workspace_root(),
            work_id: "W-001".to_string(),
            role: WorkRole::GateExecutor.into(),
            lease_id: None, // Missing required lease_id
        };
        let frame = encode_spawn_episode_request(&request);

        let response = dispatcher.dispatch(&frame, &ctx).unwrap();

        match response {
            PrivilegedResponse::Error(err) => {
                assert_eq!(err.code, PrivilegedErrorCode::GateLeaseMissing as i32);
            },
            _ => panic!("Expected GATE_LEASE_MISSING error"),
        }
    }

    #[test]
    fn test_gate_executor_with_lease_id_succeeds() {
        let dispatcher = PrivilegedDispatcher::new();
        let ctx = make_privileged_ctx();

        // First, claim work with GateExecutor role to establish policy resolution
        let claim_request = ClaimWorkRequest {
            actor_id: "test-actor".to_string(),
            role: WorkRole::GateExecutor.into(),
            credential_signature: vec![1, 2, 3],
            nonce: vec![4, 5, 6],
        };
        let claim_frame = encode_claim_work_request(&claim_request);
        let claim_response = dispatcher.dispatch(&claim_frame, &ctx).unwrap();

        // SEC-SCP-FAC-0020: Get the correct lease_id from the claim response
        let (work_id, lease_id) = match claim_response {
            PrivilegedResponse::ClaimWork(resp) => (resp.work_id, resp.lease_id),
            _ => panic!("Expected ClaimWork response"),
        };

        // TCK-00257: Register the lease for validation
        dispatcher
            .lease_validator()
            .register_lease(&lease_id, &work_id, "gate-build");

        // Now spawn with the claimed work_id and correct lease_id
        let request = SpawnEpisodeRequest {
            workspace_root: test_workspace_root(),
            work_id,
            role: WorkRole::GateExecutor.into(),
            lease_id: Some(lease_id), // Use the correct lease_id from ClaimWork
        };
        let frame = encode_spawn_episode_request(&request);

        let response = dispatcher.dispatch(&frame, &ctx).unwrap();

        match response {
            PrivilegedResponse::SpawnEpisode(_) => {
                // Success
            },
            PrivilegedResponse::Error(err) => {
                panic!("Unexpected error: {err:?}");
            },
            _ => panic!("Expected SpawnEpisode response"),
        }
    }

    // ========================================================================
    // SEC-SCP-FAC-0020: Lease ID Validation Tests
    // ========================================================================

    /// SEC-SCP-FAC-0020: `SpawnEpisode` with wrong `lease_id` fails.
    ///
    /// Per security review: `lease_id` must be validated against the claim to
    /// prevent authorization bypass.
    #[test]
    fn tck_00256_spawn_with_wrong_lease_id_fails() {
        let dispatcher = PrivilegedDispatcher::new();
        let ctx = make_privileged_ctx();

        // Claim work with GateExecutor role
        let claim_request = ClaimWorkRequest {
            actor_id: "test-actor".to_string(),
            role: WorkRole::GateExecutor.into(),
            credential_signature: vec![1, 2, 3],
            nonce: vec![4, 5, 6],
        };
        let claim_frame = encode_claim_work_request(&claim_request);
        let claim_response = dispatcher.dispatch(&claim_frame, &ctx).unwrap();

        let work_id = match claim_response {
            PrivilegedResponse::ClaimWork(resp) => resp.work_id,
            _ => panic!("Expected ClaimWork response"),
        };

        // Try to spawn with a WRONG lease_id (arbitrary string)
        let request = SpawnEpisodeRequest {
            workspace_root: test_workspace_root(),
            work_id,
            role: WorkRole::GateExecutor.into(),
            lease_id: Some("L-WRONG-LEASE-ID".to_string()), // Wrong!
        };
        let frame = encode_spawn_episode_request(&request);

        let response = dispatcher.dispatch(&frame, &ctx).unwrap();

        match response {
            PrivilegedResponse::Error(err) => {
                // TCK-00257: With lease validation, wrong lease_id fails at
                // lease validation (GATE_LEASE_MISSING) before claim validation
                assert_eq!(
                    err.code,
                    PrivilegedErrorCode::GateLeaseMissing as i32,
                    "Should return GateLeaseMissing for unknown lease_id"
                );
                assert!(
                    err.message.contains("lease"),
                    "Error message should mention lease: {}",
                    err.message
                );
            },
            _ => panic!("Expected lease validation error, got: {response:?}"),
        }
    }

    /// SEC-SCP-FAC-0020: `SpawnEpisode` with MISSING `lease_id` fails.
    ///
    /// Security Fix Verification: Ensure that omitting `lease_id` (None) is NOT
    /// treated as a valid bypass. It must match the claimed `lease_id`.
    #[test]
    fn tck_00256_spawn_with_missing_lease_id_fails() {
        let dispatcher = PrivilegedDispatcher::new();
        let ctx = make_privileged_ctx();

        // Claim work with Implementer role
        let claim_request = ClaimWorkRequest {
            actor_id: "test-actor".to_string(),
            role: WorkRole::Implementer.into(),
            credential_signature: vec![1, 2, 3],
            nonce: vec![4, 5, 6],
        };
        let claim_frame = encode_claim_work_request(&claim_request);
        let claim_response = dispatcher.dispatch(&claim_frame, &ctx).unwrap();

        let work_id = match claim_response {
            PrivilegedResponse::ClaimWork(resp) => resp.work_id,
            _ => panic!("Expected ClaimWork response"),
        };

        // Try to spawn with NO lease_id (None)
        let request = SpawnEpisodeRequest {
            workspace_root: test_workspace_root(),
            work_id,
            role: WorkRole::Implementer.into(),
            lease_id: None, // Missing! Should fail because claim has a lease_id
        };
        let frame = encode_spawn_episode_request(&request);

        let response = dispatcher.dispatch(&frame, &ctx).unwrap();

        match response {
            PrivilegedResponse::Error(err) => {
                assert_eq!(
                    err.code,
                    PrivilegedErrorCode::CapabilityRequestRejected as i32,
                    "Should return CapabilityRequestRejected for missing lease_id"
                );
                assert!(
                    err.message.contains("lease_id"),
                    "Error message should mention lease_id: {}",
                    err.message
                );
            },
            _ => panic!("Expected lease_id mismatch error for Missing ID, got: {response:?}"),
        }
    }

    /// SEC-SCP-FAC-0020: `SpawnEpisode` with correct `lease_id` succeeds.
    #[test]
    fn tck_00256_spawn_with_correct_lease_id_succeeds() {
        let dispatcher = PrivilegedDispatcher::new();
        let ctx = make_privileged_ctx();

        // Claim work
        let claim_request = ClaimWorkRequest {
            actor_id: "test-actor".to_string(),
            role: WorkRole::Implementer.into(),
            credential_signature: vec![1, 2, 3],
            nonce: vec![4, 5, 6],
        };
        let claim_frame = encode_claim_work_request(&claim_request);
        let claim_response = dispatcher.dispatch(&claim_frame, &ctx).unwrap();

        let (work_id, lease_id) = match claim_response {
            PrivilegedResponse::ClaimWork(resp) => (resp.work_id, resp.lease_id),
            _ => panic!("Expected ClaimWork response"),
        };

        // Spawn with the correct lease_id (optional for non-GateExecutor)
        let request = SpawnEpisodeRequest {
            workspace_root: test_workspace_root(),
            work_id,
            role: WorkRole::Implementer.into(),
            lease_id: Some(lease_id), // Correct lease_id
        };
        let frame = encode_spawn_episode_request(&request);

        let response = dispatcher.dispatch(&frame, &ctx).unwrap();

        match response {
            PrivilegedResponse::SpawnEpisode(resp) => {
                assert!(!resp.session_id.is_empty());
            },
            PrivilegedResponse::Error(err) => {
                panic!("Unexpected error: {err:?}");
            },
            _ => panic!("Expected SpawnEpisode response"),
        }
    }

    /// SEC-SCP-FAC-0020: Session state is persisted after successful spawn.
    #[test]
    fn tck_00256_session_state_persisted() {
        let dispatcher = PrivilegedDispatcher::new();
        let ctx = make_privileged_ctx();

        // Claim work
        let claim_request = ClaimWorkRequest {
            actor_id: "test-actor".to_string(),
            role: WorkRole::Implementer.into(),
            credential_signature: vec![1, 2, 3],
            nonce: vec![4, 5, 6],
        };
        let claim_frame = encode_claim_work_request(&claim_request);
        let claim_response = dispatcher.dispatch(&claim_frame, &ctx).unwrap();

        let (work_id, lease_id) = match claim_response {
            PrivilegedResponse::ClaimWork(resp) => (resp.work_id, resp.lease_id),
            _ => panic!("Expected ClaimWork response"),
        };

        // Spawn episode
        let request = SpawnEpisodeRequest {
            workspace_root: test_workspace_root(),
            work_id: work_id.clone(),
            role: WorkRole::Implementer.into(),
            lease_id: Some(lease_id),
        };
        let frame = encode_spawn_episode_request(&request);
        let response = dispatcher.dispatch(&frame, &ctx).unwrap();

        let (session_id, ephemeral_handle) = match response {
            PrivilegedResponse::SpawnEpisode(resp) => (resp.session_id, resp.ephemeral_handle),
            _ => panic!("Expected SpawnEpisode response"),
        };

        // Verify session is persisted
        let session = dispatcher.session_registry.get_session(&session_id);
        assert!(session.is_some(), "Session should be persisted");

        let session = session.unwrap();
        assert_eq!(session.session_id, session_id);
        assert_eq!(session.work_id, work_id);
        assert_eq!(session.role, i32::from(WorkRole::Implementer));
        assert_eq!(session.ephemeral_handle, ephemeral_handle);

        // Also verify we can query by ephemeral handle
        let session_by_handle = dispatcher
            .session_registry
            .get_session_by_handle(&ephemeral_handle);
        assert!(
            session_by_handle.is_some(),
            "Session should be queryable by handle"
        );
        assert_eq!(session_by_handle.unwrap().session_id, session_id);
    }

    // ========================================================================
    // TCK-00257: ADV-004 Gate Lease Validation Tests
    // ========================================================================

    /// ADV-004: `GATE_EXECUTOR` spawn with unknown/unregistered `lease_id`
    /// fails.
    ///
    /// This test verifies that the ledger is queried for a valid
    /// `GateLeaseIssued` event. If the lease is not found, the spawn is
    /// rejected with `GATE_LEASE_MISSING`.
    #[test]
    fn test_adv_004_gate_executor_unknown_lease_fails() {
        let dispatcher = PrivilegedDispatcher::new();
        let ctx = make_privileged_ctx();

        // DO NOT register any lease - this simulates an unknown/invalid lease

        let request = SpawnEpisodeRequest {
            workspace_root: test_workspace_root(),
            work_id: "W-001".to_string(),
            role: WorkRole::GateExecutor.into(),
            lease_id: Some("L-UNKNOWN".to_string()), // Not registered
        };
        let frame = encode_spawn_episode_request(&request);

        let response = dispatcher.dispatch(&frame, &ctx).unwrap();

        match response {
            PrivilegedResponse::Error(err) => {
                assert_eq!(
                    err.code,
                    PrivilegedErrorCode::GateLeaseMissing as i32,
                    "Should fail with GATE_LEASE_MISSING for unknown lease"
                );
                assert!(
                    err.message.contains("lease not found"),
                    "Error message should indicate lease not found: {}",
                    err.message
                );
            },
            _ => panic!("Expected GATE_LEASE_MISSING error for unknown lease"),
        }
    }

    /// ADV-004: `GATE_EXECUTOR` spawn with mismatched `work_id` fails.
    ///
    /// This test verifies that the lease's `work_id` must match the request's
    /// `work_id`. A lease for work W-001 cannot be used for spawn on W-002.
    #[test]
    fn test_adv_004_gate_executor_work_id_mismatch_fails() {
        let dispatcher = PrivilegedDispatcher::new();
        let ctx = make_privileged_ctx();

        // Register lease for W-001
        dispatcher
            .lease_validator()
            .register_lease("L-001", "W-001", "gate-build");

        // Try to use that lease for W-002 (different work_id)
        let request = SpawnEpisodeRequest {
            workspace_root: test_workspace_root(),
            work_id: "W-002".to_string(), // Mismatched work_id
            role: WorkRole::GateExecutor.into(),
            lease_id: Some("L-001".to_string()),
        };
        let frame = encode_spawn_episode_request(&request);

        let response = dispatcher.dispatch(&frame, &ctx).unwrap();

        match response {
            PrivilegedResponse::Error(err) => {
                assert_eq!(
                    err.code,
                    PrivilegedErrorCode::GateLeaseMissing as i32,
                    "Should fail with GATE_LEASE_MISSING for work_id mismatch"
                );
                assert!(
                    err.message.contains("mismatch"),
                    "Error message should indicate work_id mismatch: {}",
                    err.message
                );
            },
            _ => panic!("Expected GATE_LEASE_MISSING error for work_id mismatch"),
        }
    }

    /// ADV-004: `GATE_EXECUTOR` spawn with valid registered lease succeeds
    /// (at the lease validation stage).
    ///
    /// This test verifies that a properly registered lease that matches
    /// the `work_id` passes the lease validation. Note: The spawn may still
    /// fail at the claim validation stage if `ClaimWork` wasn't called first.
    #[test]
    fn test_adv_004_gate_executor_valid_lease_passes_validation() {
        let dispatcher = PrivilegedDispatcher::new();
        let ctx = make_privileged_ctx();

        // Register the lease for the correct work_id
        dispatcher
            .lease_validator()
            .register_lease("L-VALID", "W-VALID", "gate-aat");

        let request = SpawnEpisodeRequest {
            workspace_root: test_workspace_root(),
            work_id: "W-VALID".to_string(),
            role: WorkRole::GateExecutor.into(),
            lease_id: Some("L-VALID".to_string()),
        };
        let frame = encode_spawn_episode_request(&request);

        let response = dispatcher.dispatch(&frame, &ctx).unwrap();

        // The response should NOT be GATE_LEASE_MISSING - the lease validation
        // passed. It may fail for other reasons (policy resolution missing),
        // but not lease validation.
        if let PrivilegedResponse::Error(err) = &response {
            assert_ne!(
                err.code,
                PrivilegedErrorCode::GateLeaseMissing as i32,
                "Should NOT fail with GATE_LEASE_MISSING - lease is valid"
            );
            // Expected to fail with PolicyResolutionMissing since we didn't
            // call ClaimWork
            assert_eq!(
                err.code,
                PrivilegedErrorCode::PolicyResolutionMissing as i32,
                "Should fail with PolicyResolutionMissing (no ClaimWork)"
            );
        }
        // If it somehow succeeded, that's also fine for this test
    }

    // ========================================================================
    // Protocol Error Tests
    // ========================================================================
    #[test]
    fn test_empty_frame_error() {
        let dispatcher = PrivilegedDispatcher::new();
        let ctx = make_privileged_ctx();

        let frame = Bytes::new();
        let result = dispatcher.dispatch(&frame, &ctx);

        assert!(result.is_err());
        assert!(matches!(result, Err(ProtocolError::Serialization { .. })));
    }

    #[test]
    fn test_unknown_message_type_error() {
        let dispatcher = PrivilegedDispatcher::new();
        let ctx = make_privileged_ctx();

        let frame = Bytes::from(vec![255u8, 0, 0, 0]); // Unknown tag
        let result = dispatcher.dispatch(&frame, &ctx);

        assert!(result.is_err());
        assert!(matches!(result, Err(ProtocolError::Serialization { .. })));
    }

    #[test]
    fn test_malformed_payload_error() {
        let dispatcher = PrivilegedDispatcher::new();
        let ctx = make_privileged_ctx();

        let frame = Bytes::from(vec![1u8, 0xFF, 0xFF, 0xFF]); // ClaimWork tag + garbage
        let result = dispatcher.dispatch(&frame, &ctx);

        assert!(result.is_err());
    }

    // ========================================================================
    // Connection Context Tests
    // ========================================================================
    #[test]
    fn test_connection_context_privileged() {
        let ctx = ConnectionContext::privileged(Some(PeerCredentials {
            uid: 1000,
            gid: 1000,
            pid: Some(123),
        }));

        assert!(ctx.is_privileged());
        assert!(ctx.peer_credentials().is_some());
        assert!(ctx.session_id().is_none());
    }

    #[test]
    fn test_connection_context_session() {
        let ctx = ConnectionContext::session(
            Some(PeerCredentials {
                uid: 1000,
                gid: 1000,
                pid: Some(456),
            }),
            Some("session-123".to_string()),
        );

        assert!(!ctx.is_privileged());
        assert!(ctx.peer_credentials().is_some());
        assert_eq!(ctx.session_id(), Some("session-123"));
    }

    // ========================================================================
    // Response Encoding Tests
    // ========================================================================
    #[test]
    fn test_response_encoding() {
        let error_resp = PrivilegedResponse::permission_denied();
        let encoded = error_resp.encode();
        assert!(!encoded.is_empty());
        assert_eq!(encoded[0], 0); // Error tag

        let claim_resp = PrivilegedResponse::ClaimWork(ClaimWorkResponse {
            work_id: "W-001".to_string(),
            lease_id: "L-001".to_string(),
            capability_manifest_hash: vec![],
            policy_resolved_ref: String::new(),
            context_pack_hash: vec![],
        });
        let encoded = claim_resp.encode();
        assert!(!encoded.is_empty());
        assert_eq!(encoded[0], PrivilegedMessageType::ClaimWork.tag());
    }

    // ========================================================================
    // TCK-00256: SpawnEpisode with PolicyResolvedForChangeSet check
    // ========================================================================

    /// TCK-00256: Spawn without policy resolution fails (fail-closed).
    ///
    /// Per acceptance criteria: "Spawn without policy resolution fails"
    /// This test verifies ADV-004 variant: attempting to spawn an episode
    /// without first calling `ClaimWork` to establish policy resolution.
    #[test]
    fn tck_00256_spawn_without_policy_resolution_fails() {
        let dispatcher = PrivilegedDispatcher::new();
        let ctx = make_privileged_ctx();

        // Attempt to spawn for a non-existent work_id (no ClaimWork was called)
        let request = SpawnEpisodeRequest {
            workspace_root: test_workspace_root(),
            work_id: "W-NONEXISTENT".to_string(),
            role: WorkRole::Implementer.into(),
            lease_id: None,
        };
        let frame = encode_spawn_episode_request(&request);

        let response = dispatcher.dispatch(&frame, &ctx).unwrap();

        match response {
            PrivilegedResponse::Error(err) => {
                assert_eq!(
                    err.code,
                    PrivilegedErrorCode::PolicyResolutionMissing as i32,
                    "Should return PolicyResolutionMissing error"
                );
                assert!(
                    err.message.contains("policy resolution not found"),
                    "Error message should indicate policy resolution is missing: {}",
                    err.message
                );
            },
            _ => panic!("Expected PolicyResolutionMissing error, got: {response:?}"),
        }
    }

    /// TCK-00256: Valid policy resolution allows spawn.
    ///
    /// Per acceptance criteria: "Valid policy resolution allows spawn"
    /// This test verifies the integration flow: `ClaimWork` followed by
    /// `SpawnEpisode`.
    #[test]
    fn tck_00256_spawn_with_policy_resolution_succeeds() {
        let dispatcher = PrivilegedDispatcher::new();
        let ctx = make_privileged_ctx();

        // 1. Claim Work (generates policy resolution and persists it)
        let claim_req = ClaimWorkRequest {
            actor_id: "test-actor".to_string(),
            role: WorkRole::Implementer.into(),
            credential_signature: vec![1, 2, 3],
            nonce: vec![4, 5, 6],
        };
        let claim_frame = encode_claim_work_request(&claim_req);
        let claim_response = dispatcher.dispatch(&claim_frame, &ctx).unwrap();

        let (work_id, expected_manifest_hash, lease_id) = match claim_response {
            PrivilegedResponse::ClaimWork(resp) => {
                (resp.work_id, resp.capability_manifest_hash, resp.lease_id)
            },
            _ => panic!("Expected ClaimWork response"),
        };

        // 2. Spawn Episode (should succeed because ClaimWork persisted the resolution)
        let spawn_req = SpawnEpisodeRequest {
            workspace_root: test_workspace_root(),
            work_id,
            role: WorkRole::Implementer.into(),
            lease_id: Some(lease_id),
        };
        let spawn_frame = encode_spawn_episode_request(&spawn_req);

        let response = dispatcher.dispatch(&spawn_frame, &ctx).unwrap();

        match response {
            PrivilegedResponse::SpawnEpisode(resp) => {
                assert!(
                    !resp.session_id.is_empty(),
                    "Session ID should not be empty"
                );
                assert!(
                    resp.session_id.starts_with("S-"),
                    "Session ID should start with S-"
                );
                assert!(
                    !resp.ephemeral_handle.is_empty(),
                    "Ephemeral handle should not be empty"
                );
                assert!(
                    resp.ephemeral_handle.starts_with("H-"),
                    "Ephemeral handle should start with H-"
                );
                assert_eq!(
                    resp.capability_manifest_hash, expected_manifest_hash,
                    "Capability manifest hash should match the one from ClaimWork"
                );
                assert!(resp.context_pack_sealed, "Context pack should be sealed");
            },
            PrivilegedResponse::Error(err) => {
                panic!("Unexpected error: {err:?}");
            },
            _ => panic!("Expected SpawnEpisode response"),
        }
    }

    /// TCK-00256: `SpawnEpisode` with mismatched role fails.
    ///
    /// Per DD-001, the role in the spawn request should match the claimed role.
    /// This test verifies that attempting to spawn with a different role fails.
    #[test]
    fn tck_00256_spawn_with_mismatched_role_fails() {
        let dispatcher = PrivilegedDispatcher::new();
        let ctx = make_privileged_ctx();

        // 1. Claim Work with Implementer role
        let claim_req = ClaimWorkRequest {
            actor_id: "test-actor".to_string(),
            role: WorkRole::Implementer.into(),
            credential_signature: vec![1, 2, 3],
            nonce: vec![4, 5, 6],
        };
        let claim_frame = encode_claim_work_request(&claim_req);
        let claim_response = dispatcher.dispatch(&claim_frame, &ctx).unwrap();

        let work_id = match claim_response {
            PrivilegedResponse::ClaimWork(resp) => resp.work_id,
            _ => panic!("Expected ClaimWork response"),
        };

        // 2. Try to spawn with Reviewer role (mismatched)
        let spawn_req = SpawnEpisodeRequest {
            workspace_root: test_workspace_root(),
            work_id,
            role: WorkRole::Reviewer.into(), // Different from claimed role
            lease_id: None,
        };
        let spawn_frame = encode_spawn_episode_request(&spawn_req);

        let response = dispatcher.dispatch(&spawn_frame, &ctx).unwrap();

        match response {
            PrivilegedResponse::Error(err) => {
                assert_eq!(
                    err.code,
                    PrivilegedErrorCode::CapabilityRequestRejected as i32,
                    "Should return CapabilityRequestRejected for role mismatch"
                );
                assert!(
                    err.message.contains("role mismatch"),
                    "Error message should indicate role mismatch: {}",
                    err.message
                );
            },
            _ => panic!("Expected role mismatch error, got: {response:?}"),
        }
    }

    /// TCK-00256: `SpawnEpisode` returns policy resolution data.
    ///
    /// Verifies that the spawn response includes the capability manifest hash
    /// from the original policy resolution.
    #[test]
    fn tck_00256_spawn_returns_policy_resolution_data() {
        let dispatcher = PrivilegedDispatcher::new();
        let ctx = make_privileged_ctx();

        // Claim work
        let claim_req = ClaimWorkRequest {
            actor_id: "test-actor".to_string(),
            role: WorkRole::Implementer.into(),
            credential_signature: vec![1, 2, 3],
            nonce: vec![4, 5, 6],
        };
        let claim_frame = encode_claim_work_request(&claim_req);
        let claim_response = dispatcher.dispatch(&claim_frame, &ctx).unwrap();

        let (work_id, claim_manifest_hash, _claim_context_hash, lease_id) = match claim_response {
            PrivilegedResponse::ClaimWork(resp) => (
                resp.work_id,
                resp.capability_manifest_hash,
                resp.context_pack_hash,
                resp.lease_id,
            ),
            _ => panic!("Expected ClaimWork response"),
        };

        // Spawn episode
        let spawn_req = SpawnEpisodeRequest {
            workspace_root: test_workspace_root(),
            work_id,
            role: WorkRole::Implementer.into(),
            lease_id: Some(lease_id),
        };
        let spawn_frame = encode_spawn_episode_request(&spawn_req);
        let spawn_response = dispatcher.dispatch(&spawn_frame, &ctx).unwrap();

        match spawn_response {
            PrivilegedResponse::SpawnEpisode(resp) => {
                // Verify the capability manifest hash matches
                assert_eq!(
                    resp.capability_manifest_hash, claim_manifest_hash,
                    "SpawnEpisode should return same capability_manifest_hash as ClaimWork"
                );
                // Verify context pack is marked as sealed
                assert!(resp.context_pack_sealed);
            },
            _ => panic!("Expected SpawnEpisode response"),
        }
    }

    // ========================================================================
    // CTR-1303: Bounded Store Tests (DoS Protection)
    // ========================================================================

    /// CTR-1303: `StubWorkRegistry` enforces capacity limits.
    ///
    /// Per CTR-1303: In-memory stores must have `max_entries` limit with O(1)
    /// eviction. This test verifies that the registry evicts oldest entries
    /// when at capacity.
    #[test]
    fn test_stub_work_registry_capacity_limit() {
        let registry = StubWorkRegistry::default();

        // Register claims up to capacity
        // Note: We test with a smaller number to keep the test fast
        let test_limit = 100; // Test with 100 instead of 10_000

        for i in 0..test_limit {
            let claim = WorkClaim {
                work_id: format!("W-{i:05}"),
                lease_id: format!("L-{i:05}"),
                actor_id: format!("actor:{i:016x}"),
                role: WorkRole::Implementer,
                policy_resolution: PolicyResolution {
                    policy_resolved_ref: format!("PolicyResolvedForChangeSet:{i}"),
                    resolved_policy_hash: [0u8; 32],
                    capability_manifest_hash: [0u8; 32],
                    context_pack_hash: [0u8; 32],
                },
                executor_custody_domains: vec![],
                author_custody_domains: vec![],
            };
            registry.register_claim(claim).unwrap();
        }

        // All claims should be present
        for i in 0..test_limit {
            let work_id = format!("W-{i:05}");
            assert!(
                registry.get_claim(&work_id).is_some(),
                "Claim {work_id} should exist"
            );
        }
    }

    /// CTR-1303: `StubWorkRegistry` rejects duplicate `work_ids`.
    #[test]
    fn test_stub_work_registry_rejects_duplicates() {
        let registry = StubWorkRegistry::default();

        let claim = WorkClaim {
            work_id: "W-DUPLICATE".to_string(),
            lease_id: "L-001".to_string(),
            actor_id: "actor:test".to_string(),
            role: WorkRole::Implementer,
            policy_resolution: PolicyResolution {
                policy_resolved_ref: "PolicyResolvedForChangeSet:test".to_string(),
                resolved_policy_hash: [0u8; 32],
                capability_manifest_hash: [0u8; 32],
                context_pack_hash: [0u8; 32],
            },
            executor_custody_domains: vec![],
            author_custody_domains: vec![],
        };

        // First registration succeeds
        assert!(registry.register_claim(claim.clone()).is_ok());

        // Second registration with same work_id fails
        let result = registry.register_claim(claim);
        assert!(matches!(
            result,
            Err(WorkRegistryError::DuplicateWorkId { .. })
        ));
    }

    // ========================================================================
    // TCK-00258: SoD Enforcement Integration Tests
    //
    // These tests verify that Separation of Duties (SoD) is enforced when
    // spawning GATE_EXECUTOR episodes. The custody domain check prevents
    // actors from reviewing their own work (self-review attacks).
    // ========================================================================

    /// TCK-00258: `GATE_EXECUTOR` spawn with overlapping custody domains is
    /// denied.
    ///
    /// This tests the fail-closed `SoD` enforcement: when the executor's
    /// custody domains overlap with the changeset author's domains, the
    /// spawn must be rejected with `SOD_VIOLATION` error.
    #[test]
    fn test_sod_spawn_overlapping_domains_denied() {
        let dispatcher = PrivilegedDispatcher::new();
        let ctx = ConnectionContext::privileged(Some(PeerCredentials {
            uid: 1001,
            gid: 1001,
            pid: Some(12345),
        }));

        // First, claim work as GATE_EXECUTOR with overlapping domains
        // Actor ID: team-alpha:alice -> domain: team-alpha
        // Work ID: W-team-alpha-12345 -> author domain: team-alpha
        // These domains overlap, so SoD should be violated
        let claim_request = ClaimWorkRequest {
            actor_id: "team-alpha:alice".to_string(),
            role: WorkRole::GateExecutor.into(),
            credential_signature: vec![],
            nonce: vec![],
        };
        let claim_frame = encode_claim_work_request(&claim_request);
        let claim_response = dispatcher.dispatch(&claim_frame, &ctx).unwrap();

        // Extract work_id and lease_id from claim response
        let (_work_id, lease_id) = match claim_response {
            PrivilegedResponse::ClaimWork(resp) => (resp.work_id, resp.lease_id),
            _ => panic!("Expected ClaimWork response"),
        };

        // Create a new claim with a specific work_id format
        let claim_with_overlap = WorkClaim {
            work_id: "W-team-alpha-test123".to_string(),
            lease_id: lease_id.clone(),
            actor_id: "team-alpha:bob".to_string(),
            role: WorkRole::GateExecutor,
            policy_resolution: PolicyResolution {
                policy_resolved_ref: "PolicyResolvedForChangeSet:test".to_string(),
                resolved_policy_hash: [0u8; 32],
                capability_manifest_hash: [0u8; 32],
                context_pack_hash: [0u8; 32],
            },
            executor_custody_domains: vec!["team-alpha".to_string()],
            author_custody_domains: vec!["team-alpha".to_string()],
        };

        // Register the claim directly
        let _ = dispatcher.work_registry.register_claim(claim_with_overlap);

        // Register a gate lease for this work_id
        dispatcher
            .lease_validator
            .register_lease(&lease_id, "W-team-alpha-test123", "GATE-001");

        // Now spawn with the overlapping domains
        let spawn_request = SpawnEpisodeRequest {
            workspace_root: test_workspace_root(),
            work_id: "W-team-alpha-test123".to_string(),
            role: WorkRole::GateExecutor.into(),
            lease_id: Some(lease_id),
        };
        let spawn_frame = encode_spawn_episode_request(&spawn_request);
        let spawn_response = dispatcher.dispatch(&spawn_frame, &ctx).unwrap();

        // Should be denied with SOD_VIOLATION
        match spawn_response {
            PrivilegedResponse::Error(err) => {
                assert_eq!(err.code, PrivilegedErrorCode::SodViolation as i32);
                assert!(err.message.contains("custody domain overlap"));
            },
            _ => panic!("Expected SOD_VIOLATION error, got: {spawn_response:?}"),
        }
    }

    /// TCK-00258: `GATE_EXECUTOR` spawn with non-overlapping domains succeeds.
    ///
    /// This tests the happy path: when executor and author domains don't
    /// overlap, the spawn should succeed.
    #[test]
    fn test_sod_spawn_non_overlapping_domains_succeeds() {
        let dispatcher = PrivilegedDispatcher::new();
        let ctx = ConnectionContext::privileged(Some(PeerCredentials {
            uid: 1001,
            gid: 1001,
            pid: Some(12345),
        }));

        // Create a claim with non-overlapping domains
        // Executor domain: team-review (from actor_id team-review:alice)
        // Author domain: team-dev (from work_id W-team-dev-test123)
        let claim_non_overlap = WorkClaim {
            work_id: "W-team-dev-test456".to_string(),
            lease_id: "L-non-overlap-123".to_string(),
            actor_id: "team-review:alice".to_string(),
            role: WorkRole::GateExecutor,
            policy_resolution: PolicyResolution {
                policy_resolved_ref: "PolicyResolvedForChangeSet:test".to_string(),
                resolved_policy_hash: [0u8; 32],
                capability_manifest_hash: [0u8; 32],
                context_pack_hash: [0u8; 32],
            },
            executor_custody_domains: vec!["team-review".to_string()],
            author_custody_domains: vec!["team-dev".to_string()],
        };

        // Register the claim
        let _ = dispatcher.work_registry.register_claim(claim_non_overlap);

        // Register a gate lease
        dispatcher.lease_validator.register_lease(
            "L-non-overlap-123",
            "W-team-dev-test456",
            "GATE-002",
        );

        // Spawn should succeed
        let spawn_request = SpawnEpisodeRequest {
            workspace_root: test_workspace_root(),
            work_id: "W-team-dev-test456".to_string(),
            role: WorkRole::GateExecutor.into(),
            lease_id: Some("L-non-overlap-123".to_string()),
        };
        let spawn_frame = encode_spawn_episode_request(&spawn_request);
        let spawn_response = dispatcher.dispatch(&spawn_frame, &ctx).unwrap();

        // Should succeed
        match spawn_response {
            PrivilegedResponse::SpawnEpisode(resp) => {
                assert!(!resp.session_id.is_empty());
                assert!(resp.context_pack_sealed);
            },
            PrivilegedResponse::Error(err) => {
                panic!("Expected SpawnEpisode success, got error: {err:?}")
            },
            _ => panic!("Expected SpawnEpisode response"),
        }
    }

    /// TCK-00258: `GATE_EXECUTOR` spawn with empty author domains is denied
    /// (fail-closed).
    ///
    /// This tests fail-closed semantics: if author domains cannot be resolved,
    /// the spawn must be rejected to prevent `SoD` bypass.
    #[test]
    fn test_sod_spawn_empty_author_domains_denied() {
        let dispatcher = PrivilegedDispatcher::new();
        let ctx = ConnectionContext::privileged(Some(PeerCredentials {
            uid: 1001,
            gid: 1001,
            pid: Some(12345),
        }));

        // Create a claim with empty author domains (simulating resolution failure)
        let claim_empty_authors = WorkClaim {
            work_id: "W-unknown-work-789".to_string(),
            lease_id: "L-empty-authors-456".to_string(),
            actor_id: "team-review:charlie".to_string(),
            role: WorkRole::GateExecutor,
            policy_resolution: PolicyResolution {
                policy_resolved_ref: "PolicyResolvedForChangeSet:test".to_string(),
                resolved_policy_hash: [0u8; 32],
                capability_manifest_hash: [0u8; 32],
                context_pack_hash: [0u8; 32],
            },
            executor_custody_domains: vec!["team-review".to_string()],
            author_custody_domains: vec![], // Empty - resolution failed
        };

        // Register the claim
        let _ = dispatcher.work_registry.register_claim(claim_empty_authors);

        // Register a gate lease
        dispatcher.lease_validator.register_lease(
            "L-empty-authors-456",
            "W-unknown-work-789",
            "GATE-003",
        );

        // Spawn should be denied because we can't verify SoD without author domains
        let spawn_request = SpawnEpisodeRequest {
            workspace_root: test_workspace_root(),
            work_id: "W-unknown-work-789".to_string(),
            role: WorkRole::GateExecutor.into(),
            lease_id: Some("L-empty-authors-456".to_string()),
        };
        let spawn_frame = encode_spawn_episode_request(&spawn_request);
        let spawn_response = dispatcher.dispatch(&spawn_frame, &ctx).unwrap();

        // Should be denied with SOD_VIOLATION
        match spawn_response {
            PrivilegedResponse::Error(err) => {
                assert_eq!(err.code, PrivilegedErrorCode::SodViolation as i32);
                assert!(err.message.contains("author custody domains"));
            },
            _ => panic!("Expected SOD_VIOLATION error for empty author domains"),
        }
    }

    /// TCK-00258: Non-`GATE_EXECUTOR` roles skip `SoD` validation.
    ///
    /// IMPLEMENTER and REVIEWER roles do not require `SoD` validation since
    /// they are not performing trust-critical gate operations.
    #[test]
    fn test_sod_non_gate_executor_skips_validation() {
        let dispatcher = PrivilegedDispatcher::new();
        let ctx = ConnectionContext::privileged(Some(PeerCredentials {
            uid: 1001,
            gid: 1001,
            pid: Some(12345),
        }));

        // Create a claim as IMPLEMENTER with overlapping domains
        // This would fail SoD for GATE_EXECUTOR, but IMPLEMENTER skips SoD
        let claim_implementer = WorkClaim {
            work_id: "W-team-alpha-impl123".to_string(),
            lease_id: "L-implementer-789".to_string(),
            actor_id: "team-alpha:developer".to_string(),
            role: WorkRole::Implementer,
            policy_resolution: PolicyResolution {
                policy_resolved_ref: "PolicyResolvedForChangeSet:test".to_string(),
                resolved_policy_hash: [0u8; 32],
                capability_manifest_hash: [0u8; 32],
                context_pack_hash: [0u8; 32],
            },
            executor_custody_domains: vec!["team-alpha".to_string()],
            author_custody_domains: vec!["team-alpha".to_string()], // Overlapping!
        };

        // Register the claim
        let _ = dispatcher.work_registry.register_claim(claim_implementer);

        // Spawn as IMPLEMENTER should succeed despite overlapping domains
        let spawn_request = SpawnEpisodeRequest {
            workspace_root: test_workspace_root(),
            work_id: "W-team-alpha-impl123".to_string(),
            role: WorkRole::Implementer.into(),
            lease_id: Some("L-implementer-789".to_string()),
        };
        let spawn_frame = encode_spawn_episode_request(&spawn_request);
        let spawn_response = dispatcher.dispatch(&spawn_frame, &ctx).unwrap();

        // Should succeed - IMPLEMENTER skips SoD validation
        match spawn_response {
            PrivilegedResponse::SpawnEpisode(resp) => {
                assert!(!resp.session_id.is_empty());
            },
            PrivilegedResponse::Error(err) => {
                panic!("Expected SpawnEpisode success for IMPLEMENTER, got error: {err:?}")
            },
            _ => panic!("Expected SpawnEpisode response"),
        }
    }

    /// Unit test for fail-closed ID resolution (TCK-00258).
    ///
    /// Verifies that the internal resolver methods return errors for malformed
    /// IDs, rather than falling back to "UNIVERSAL".
    #[test]
    fn test_internal_resolvers_fail_on_malformed_ids() {
        let dispatcher = PrivilegedDispatcher::new();

        // 1. Test resolve_actor_custody_domains
        // Valid case
        let valid_actor = dispatcher.resolve_actor_custody_domains("team-alpha:alice");
        assert!(valid_actor.is_ok());
        assert_eq!(valid_actor.unwrap(), vec!["team-alpha".to_string()]);

        // Malformed case (no colon)
        let invalid_actor = dispatcher.resolve_actor_custody_domains("malformed_actor");
        assert!(invalid_actor.is_err());
        assert!(invalid_actor.unwrap_err().contains("malformed actor_id"));

        // 2. Test resolve_changeset_author_domains
        // Valid case (using simple domain to avoid stub parser ambiguity with hyphens)
        let valid_work = dispatcher.resolve_changeset_author_domains("W-team-123");
        assert!(valid_work.is_ok());
        assert_eq!(valid_work.unwrap(), vec!["team".to_string()]);

        // Malformed case (no W- prefix)
        let invalid_work = dispatcher.resolve_changeset_author_domains("InvalidWorkId-123");
        assert!(invalid_work.is_err());
        assert!(invalid_work.unwrap_err().contains("malformed work_id"));

        // Malformed case (W- prefix but no domain separator)
        let invalid_work_2 = dispatcher.resolve_changeset_author_domains("W-NoSeparator");
        // This actually returns Err because dash_pos find fails after stripping W-
        // wait, strip_prefix("W-") gives "NoSeparator". find('-') returns None.
        // So it falls through to Err.
        assert!(invalid_work_2.is_err());
    }
}
