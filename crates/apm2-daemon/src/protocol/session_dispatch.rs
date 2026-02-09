//! Session-scoped endpoint dispatcher for RFC-0017 IPC (TCK-00252, TCK-00260,
//! TCK-00290).
//!
//! This module implements the session-scoped endpoint dispatcher per DD-001 and
//! RFC-0017. Session endpoints (RequestTool, EmitEvent, PublishEvidence,
//! StreamTelemetry) require a valid session token for authentication. Operator
//! socket connections receive `SESSION_ERROR_PERMISSION_DENIED` for all session
//! requests.
//!
//! # TCK-00260: Tool Broker with Capability Manifest Validation
//!
//! The `RequestTool` handler validates tool requests against capability
//! manifests:
//! - Tool ID is parsed to a `ToolClass`
//! - `ToolClass` is checked against the manifest's `tool_allowlist`
//! - If not in allowlist: `SESSION_ERROR_TOOL_NOT_ALLOWED` (TOOL_NOT_ALLOWED)
//! - Validation overhead target: <5ms p50
//!
//! # TCK-00290: Session Dispatcher Viability
//!
//! Per TCK-00290, this module implements:
//! - **RequestTool**: Wire to ToolBroker execution (no stub Allow path)
//! - **EmitEvent**: Real ledger event persistence (no stub response)
//! - **PublishEvidence**: Real CAS storage with content addressing
//! - **StreamTelemetry**: Fail-closed (SESSION_ERROR_NOT_IMPLEMENTED)
//!
//! All handlers require their backing stores (manifest store, ledger, CAS) to
//! be configured. When unavailable, handlers return fail-closed errors per
//! SEC-CTRL-FAC-0015.
//!
//! # Security Invariants
//!
//! - [INV-SESS-001] Session endpoints require valid session_token
//! - [INV-SESS-002] Invalid/expired tokens return SESSION_ERROR_INVALID
//! - [INV-SESS-003] Operator connections blocked from session handlers
//! - [INV-SESS-004] Token validation uses constant-time HMAC comparison
//!   (CTR-WH001)
//! - [INV-TCK-00260-001] Tool requests validated against capability manifest
//! - [INV-TCK-00260-002] Empty tool_allowlist denies all tools (fail-closed)
//! - [INV-TCK-00290-001] RequestTool requires manifest store (fail-closed)
//! - [INV-TCK-00290-002] EmitEvent requires ledger (fail-closed)
//! - [INV-TCK-00290-003] PublishEvidence requires CAS (fail-closed)
//! - [INV-TCK-00290-004] StreamTelemetry disabled until implemented
//!   (fail-closed)
//!
//! # Message Flow
//!
//! ```text
//! ┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
//! │ session.sock    │────▶│ SessionDispatch  │──▶│ Real Handlers   │
//! │ + session_token │     └─────────────────┘     └─────────────────┘
//! └─────────────────┘            │                       │
//!                                │ Token Validation      ├── ToolBroker
//!                                │ (HMAC-SHA256)         ├── Ledger
//!                                ▼                       └── CAS
//! ┌─────────────────┐     ┌─────────────────┐
//! │ operator.sock   │────▶│ SESSION_ERROR_  │
//! │ (no token)      │     │ PERMISSION_DENIED│
//! └─────────────────┘     └─────────────────┘
//! ```

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;

use apm2_core::context::firewall::FirewallViolationDefect;
use apm2_core::coordination::ContextRefinementRequest;
use apm2_core::crypto::Hash;
use apm2_core::events::{DefectRecorded, DefectSource, TimeEnvelopeRef};
use apm2_core::tool::{self, tool_request as tool_req};
use apm2_holon::defect::{
    DefectContext as HolonDefectContext, DefectRecord, DefectSeverity, DefectSignal, SignalType,
};
use bytes::Bytes;
use prost::Message;
use tracing::{debug, error, info, warn};

use super::dispatch::{ConnectionContext, LedgerEventEmitter};
use super::error::{ProtocolError, ProtocolResult};
use super::messages::{
    BoundedDecode, DecisionType, DecodeConfig, EmitEventRequest, EmitEventResponse,
    PatternRejection, PublishEvidenceRequest, PublishEvidenceResponse, RequestToolRequest,
    RequestToolResponse, SessionError, SessionErrorCode, SessionStatusRequest,
    SessionStatusResponse, StreamLogsRequest, StreamLogsResponse, StreamTelemetryRequest,
    StreamTelemetryResponse, SubscribePulseRequest, SubscribePulseResponse,
    UnsubscribePulseRequest, UnsubscribePulseResponse,
};
use super::pulse_acl::{
    AclDecision, AclError, PulseAclEvaluator, TopicAllowlist, validate_client_sub_id,
    validate_subscription_id,
};
use super::session_token::{SessionToken, SessionTokenError, TokenMinter};
use crate::episode::capability::StubManifestLoader;
use crate::episode::decision::{
    BrokerResponse, BrokerToolRequest, DedupeKey, ToolDecision, VerifiedToolContent,
};
use crate::episode::envelope::RiskTier;
use crate::episode::executor::ContentAddressedStore;
use crate::episode::preactuation::{
    PreActuationReceipt, ReplayEntry, ReplayEntryKind, ReplayTimestamp, ReplayVerifier,
};
use crate::episode::registry::TerminationReason;
use crate::episode::{
    CapabilityManifest, EpisodeId, EpisodeRuntime, SharedSessionBrokerRegistry, SharedToolBroker,
    ToolClass,
};
use crate::gate::{GateOrchestrator, SessionTerminatedInfo};
use crate::htf::{ClockError, HolonicClock};

// ============================================================================
// Message Type Tags (for routing)
// ============================================================================

/// Message type tags for session-scoped endpoint routing.
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum SessionMessageType {
    /// `RequestTool` request (IPC-SESS-001)
    RequestTool      = 1,
    /// `EmitEvent` request (IPC-SESS-002)
    EmitEvent        = 2,
    /// `PublishEvidence` request (IPC-SESS-003)
    PublishEvidence  = 3,
    /// `StreamTelemetry` request (IPC-SESS-004)
    StreamTelemetry  = 4,
    /// `StreamLogs` request (IPC-SESS-005, TCK-00342)
    StreamLogs       = 5,
    /// `SessionStatus` request (IPC-SESS-006, TCK-00344)
    SessionStatus    = 6,
    // --- HEF Pulse Plane (CTR-PROTO-010, RFC-0018) ---
    /// `SubscribePulse` request (IPC-HEF-001)
    SubscribePulse   = 64,
    /// `UnsubscribePulse` request (IPC-HEF-002)
    UnsubscribePulse = 66,
    /// `PulseEvent` notification (server->client, IPC-HEF-003)
    PulseEvent       = 68,
}

impl SessionMessageType {
    /// Attempts to parse a message type from a tag byte.
    #[must_use]
    pub const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(Self::RequestTool),
            2 => Some(Self::EmitEvent),
            3 => Some(Self::PublishEvidence),
            4 => Some(Self::StreamTelemetry),
            5 => Some(Self::StreamLogs),
            6 => Some(Self::SessionStatus),
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

    /// Returns all request-bearing variants of `SessionMessageType`.
    ///
    /// This excludes response-only and notification-only variants such as
    /// `PulseEvent`. Adding a new request-bearing variant to the enum
    /// without adding it here will cause the HSI manifest completeness
    /// tests to fail.
    #[must_use]
    pub const fn all_request_variants() -> &'static [Self] {
        &[
            Self::RequestTool,
            Self::EmitEvent,
            Self::PublishEvidence,
            Self::StreamTelemetry,
            Self::StreamLogs,
            Self::SessionStatus,
            Self::SubscribePulse,
            Self::UnsubscribePulse,
        ]
    }

    /// Returns `true` if this variant represents a client-initiated request,
    /// `false` if it is a server-to-client notification or response-only
    /// variant.
    ///
    /// This method uses an **exhaustive** match (no wildcard `_ =>` arm), so
    /// adding a new variant to the enum forces a compile error until it is
    /// classified here. This provides the non-self-referential completeness
    /// guarantee required by RFC-0020 section 3.1.1.
    #[must_use]
    pub const fn is_client_request(self) -> bool {
        // IMPORTANT: This match MUST remain exhaustive (no `_ =>` wildcard).
        // Adding a new enum variant forces a compile error here, ensuring the
        // developer must classify it as client-request (true) or not (false).
        match self {
            Self::RequestTool
            | Self::EmitEvent
            | Self::PublishEvidence
            | Self::StreamTelemetry
            | Self::StreamLogs
            | Self::SessionStatus
            | Self::SubscribePulse
            | Self::UnsubscribePulse => true,
            // Server-to-client notification only — not a client request.
            Self::PulseEvent => false,
        }
    }

    /// Returns the HSI route path for this variant.
    ///
    /// Used by the HSI contract manifest to derive routes directly from the
    /// dispatch enum, ensuring the manifest stays in sync with the actual
    /// dispatch registry.
    #[must_use]
    pub const fn hsi_route(self) -> &'static str {
        match self {
            Self::RequestTool => "hsi.tool.request",
            Self::EmitEvent => "hsi.event.emit",
            Self::PublishEvidence => "hsi.evidence.publish",
            Self::StreamTelemetry => "hsi.telemetry.stream",
            Self::StreamLogs => "hsi.logs.stream",
            Self::SessionStatus => "hsi.session.status",
            Self::SubscribePulse => "hsi.pulse.subscribe",
            Self::UnsubscribePulse => "hsi.pulse.unsubscribe",
            Self::PulseEvent => "hsi.pulse.event",
        }
    }

    /// Returns the HSI manifest route ID for this variant.
    #[must_use]
    pub const fn hsi_route_id(self) -> &'static str {
        match self {
            Self::RequestTool => "REQUEST_TOOL",
            Self::EmitEvent => "EMIT_EVENT",
            Self::PublishEvidence => "PUBLISH_EVIDENCE",
            Self::StreamTelemetry => "STREAM_TELEMETRY",
            Self::StreamLogs => "STREAM_LOGS",
            Self::SessionStatus => "SESSION_STATUS",
            Self::SubscribePulse => "SUBSCRIBE_PULSE",
            Self::UnsubscribePulse => "UNSUBSCRIBE_PULSE",
            Self::PulseEvent => "PULSE_EVENT",
        }
    }

    /// Returns the HSI request schema ID for this variant.
    #[must_use]
    pub const fn hsi_request_schema(self) -> &'static str {
        match self {
            Self::RequestTool => "apm2.request_tool_request.v1",
            Self::EmitEvent => "apm2.emit_event_request.v1",
            Self::PublishEvidence => "apm2.publish_evidence_request.v1",
            Self::StreamTelemetry => "apm2.stream_telemetry_request.v1",
            Self::StreamLogs => "apm2.stream_logs_request.v1",
            Self::SessionStatus => "apm2.session_status_request.v1",
            Self::SubscribePulse => "apm2.subscribe_pulse_request.v1",
            Self::UnsubscribePulse => "apm2.unsubscribe_pulse_request.v1",
            Self::PulseEvent => "apm2.pulse_event_request.v1",
        }
    }

    /// Returns the HSI response schema ID for this variant.
    #[must_use]
    pub const fn hsi_response_schema(self) -> &'static str {
        match self {
            Self::RequestTool => "apm2.request_tool_response.v1",
            Self::EmitEvent => "apm2.emit_event_response.v1",
            Self::PublishEvidence => "apm2.publish_evidence_response.v1",
            Self::StreamTelemetry => "apm2.stream_telemetry_response.v1",
            Self::StreamLogs => "apm2.stream_logs_response.v1",
            Self::SessionStatus => "apm2.session_status_response.v1",
            Self::SubscribePulse => "apm2.subscribe_pulse_response.v1",
            Self::UnsubscribePulse => "apm2.unsubscribe_pulse_response.v1",
            Self::PulseEvent => "apm2.pulse_event_response.v1",
        }
    }
}

// ============================================================================
// Response Envelope
// ============================================================================

/// Response envelope for session-scoped endpoint responses.
///
/// Contains either a successful response or an error.
#[derive(Debug)]
pub enum SessionResponse {
    /// Successful `RequestTool` response.
    RequestTool(RequestToolResponse),
    /// Successful `EmitEvent` response.
    EmitEvent(EmitEventResponse),
    /// Successful `PublishEvidence` response.
    PublishEvidence(PublishEvidenceResponse),
    /// Successful `StreamTelemetry` response.
    StreamTelemetry(StreamTelemetryResponse),
    /// Successful `StreamLogs` response (TCK-00342).
    StreamLogs(StreamLogsResponse),
    /// Successful `SessionStatus` response (TCK-00344).
    SessionStatus(SessionStatusResponse),
    /// Successful `SubscribePulse` response (TCK-00302).
    SubscribePulse(SubscribePulseResponse),
    /// Successful `UnsubscribePulse` response (TCK-00302).
    UnsubscribePulse(UnsubscribePulseResponse),
    /// Error response.
    Error(SessionError),
}

impl SessionResponse {
    /// Creates a `SESSION_ERROR_INVALID` error response.
    #[must_use]
    pub fn session_invalid(reason: impl Into<String>) -> Self {
        Self::Error(SessionError {
            code: SessionErrorCode::SessionErrorInvalid.into(),
            message: reason.into(),
        })
    }

    /// Creates a `SESSION_ERROR_PERMISSION_DENIED` error response.
    #[must_use]
    pub fn permission_denied() -> Self {
        Self::Error(SessionError {
            code: SessionErrorCode::SessionErrorPermissionDenied.into(),
            message: "session endpoints require session.sock connection".to_string(),
        })
    }

    /// Creates a custom error response.
    #[must_use]
    pub fn error(code: SessionErrorCode, message: impl Into<String>) -> Self {
        Self::Error(SessionError {
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
            Self::RequestTool(resp) => {
                buf.push(SessionMessageType::RequestTool.tag());
                resp.encode(&mut buf).expect("encode cannot fail");
            },
            Self::EmitEvent(resp) => {
                buf.push(SessionMessageType::EmitEvent.tag());
                resp.encode(&mut buf).expect("encode cannot fail");
            },
            Self::PublishEvidence(resp) => {
                buf.push(SessionMessageType::PublishEvidence.tag());
                resp.encode(&mut buf).expect("encode cannot fail");
            },
            Self::StreamTelemetry(resp) => {
                buf.push(SessionMessageType::StreamTelemetry.tag());
                resp.encode(&mut buf).expect("encode cannot fail");
            },
            Self::StreamLogs(resp) => {
                buf.push(SessionMessageType::StreamLogs.tag());
                resp.encode(&mut buf).expect("encode cannot fail");
            },
            Self::SessionStatus(resp) => {
                buf.push(SessionMessageType::SessionStatus.tag());
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
// Manifest Store (TCK-00260)
// ============================================================================

/// Maximum length for `tool_id` in requests.
///
/// Per CTR-1303: Bounded inputs prevent denial-of-service via oversized
/// strings.
pub const MAX_TOOL_ID_LEN: usize = 128;

/// Maximum length for sanitized error messages returned over the protocol.
///
/// Per SEC-CTRL-FAC-0015: Error messages may leak system paths, environment
/// details, or configuration. Messages are truncated and potentially sensitive
/// patterns are redacted before returning to clients.
const MAX_ERROR_MESSAGE_LEN: usize = 256;

/// Sanitizes an error message for safe return over the protocol.
///
/// This function:
/// 1. Truncates messages to `MAX_ERROR_MESSAGE_LEN`
/// 2. Redacts potential file system paths (anything starting with /)
/// 3. Replaces internal error details with generic messages
///
/// # SEC-CTRL-FAC-0015 Information Leakage Prevention
///
/// Raw error messages from tool execution may contain:
/// - File system paths (`/home/user/.ssh/...`)
/// - Environment variable values
/// - Internal implementation details
///
/// This function ensures only safe, generic error information is returned.
fn sanitize_error_message(msg: &str) -> String {
    // Truncate to max length first
    let truncated: String = if msg.len() > MAX_ERROR_MESSAGE_LEN {
        format!("{}...", &msg[..MAX_ERROR_MESSAGE_LEN.saturating_sub(3)])
    } else {
        msg.to_string()
    };

    // Redact potential absolute file paths (heuristic: starts with / followed by
    // word chars) This catches patterns like /home/user/path or /var/run/socket
    let mut result = String::with_capacity(truncated.len());
    let mut chars = truncated.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '/' {
            // Check if this looks like a path (followed by alphanumeric)
            if chars.peek().is_some_and(|next| next.is_alphanumeric()) {
                result.push_str("[path]");
                // Skip until we hit a space, quote, or end
                while let Some(&next) = chars.peek() {
                    if next.is_whitespace() || next == '"' || next == '\'' || next == ')' {
                        break;
                    }
                    chars.next();
                }
            } else {
                result.push(c);
            }
        } else {
            result.push(c);
        }
    }

    result
}

/// Trait for looking up capability manifests by session ID.
///
/// Per TCK-00260, the dispatcher needs to validate tool requests against
/// the session's capability manifest. This trait abstracts the manifest
/// storage to allow different implementations (in-memory, persistent, etc.).
pub trait ManifestStore: Send + Sync {
    /// Retrieves the capability manifest for a session.
    ///
    /// # Arguments
    ///
    /// * `session_id` - The session ID to look up
    ///
    /// # Returns
    ///
    /// The capability manifest if found, or `None` if the session has no
    /// associated manifest.
    fn get_manifest(&self, session_id: &str) -> Option<Arc<CapabilityManifest>>;
}

/// In-memory manifest store for testing.
///
/// Stores manifests in a hash map keyed by session ID.
#[derive(Debug, Default)]
pub struct InMemoryManifestStore {
    /// Manifests keyed by session ID.
    manifests: std::sync::RwLock<std::collections::HashMap<String, Arc<CapabilityManifest>>>,
}

impl InMemoryManifestStore {
    /// Creates a new empty manifest store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a manifest for a session.
    pub fn register(&self, session_id: impl Into<String>, manifest: CapabilityManifest) {
        let mut manifests = self.manifests.write().expect("lock poisoned");
        manifests.insert(session_id.into(), Arc::new(manifest));
    }

    /// Removes a manifest for a session.
    pub fn remove(&self, session_id: &str) {
        let mut manifests = self.manifests.write().expect("lock poisoned");
        manifests.remove(session_id);
    }

    /// Removes a manifest for a session and returns it.
    ///
    /// This is used during eviction to capture the manifest entry so it can
    /// be restored during rollback if a later spawn step fails.
    pub fn remove_and_return(&self, session_id: &str) -> Option<Arc<CapabilityManifest>> {
        let mut manifests = self.manifests.write().expect("lock poisoned");
        manifests.remove(session_id)
    }

    /// Restores a previously removed manifest entry.
    ///
    /// Used during rollback to re-insert an evicted manifest that was captured
    /// via [`Self::remove_and_return`].
    pub fn restore(&self, session_id: impl Into<String>, manifest: Arc<CapabilityManifest>) {
        let mut manifests = self.manifests.write().expect("lock poisoned");
        manifests.insert(session_id.into(), manifest);
    }

    /// Returns the number of manifests stored.
    #[must_use]
    pub fn len(&self) -> usize {
        let manifests = self.manifests.read().expect("lock poisoned");
        manifests.len()
    }

    /// Returns `true` if the store contains no manifests.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl ManifestStore for InMemoryManifestStore {
    fn get_manifest(&self, session_id: &str) -> Option<Arc<CapabilityManifest>> {
        let manifests = self.manifests.read().expect("lock poisoned");
        manifests.get(session_id).cloned()
    }
}

// ============================================================================
// TCK-00352: V1 Manifest Store (Security Review MAJOR 2)
// ============================================================================

/// Thread-safe store for V1 capability manifests keyed by session ID.
///
/// Per TCK-00352 Security Review MAJOR 2, V1 manifests must be wired into
/// the production actuation path. This store is shared between the
/// `PrivilegedDispatcher` (which mints and registers V1 manifests during
/// `SpawnEpisode`) and the `SessionDispatcher` (which enforces V1 scope
/// checks during `RequestTool`).
#[derive(Debug, Default)]
pub struct V1ManifestStore {
    manifests:
        std::sync::RwLock<std::collections::HashMap<String, crate::episode::CapabilityManifestV1>>,
}

impl V1ManifestStore {
    /// Creates a new empty V1 manifest store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a V1 manifest for a session.
    pub fn register(
        &self,
        session_id: impl Into<String>,
        manifest: crate::episode::CapabilityManifestV1,
    ) {
        let mut store = self.manifests.write().expect("lock poisoned");
        store.insert(session_id.into(), manifest);
    }

    /// Looks up the V1 manifest for a session.
    #[must_use]
    pub fn get(&self, session_id: &str) -> Option<crate::episode::CapabilityManifestV1> {
        let store = self.manifests.read().expect("lock poisoned");
        store.get(session_id).cloned()
    }

    /// Removes a V1 manifest for a session.
    pub fn remove(&self, session_id: &str) {
        let mut store = self.manifests.write().expect("lock poisoned");
        store.remove(session_id);
    }
}

/// Shared reference to a [`V1ManifestStore`].
pub type SharedV1ManifestStore = Arc<V1ManifestStore>;

// ============================================================================
// Dispatcher
// ============================================================================

/// Session-scoped endpoint dispatcher.
///
/// Routes incoming messages to the appropriate handler based on message type.
/// Enforces session token validation before dispatching to any handler.
///
/// # TCK-00260: Capability Manifest Validation
///
/// The dispatcher validates `RequestTool` requests against the session's
/// capability manifest. If the tool is not in the manifest's `tool_allowlist`,
/// `SESSION_ERROR_TOOL_NOT_ALLOWED` is returned.
///
/// # TCK-00290: Real Handler Implementations
///
/// Per TCK-00290, the dispatcher uses real backing stores:
/// - **`RequestTool`**: Requires `manifest_store` (fail-closed without it)
/// - **`EmitEvent`**: Requires `ledger` for persistent events (fail-closed)
/// - **`PublishEvidence`**: Requires `cas` for artifact storage (fail-closed)
/// - **`StreamTelemetry`**: Explicitly disabled (fail-closed, returns
///   `NOT_IMPLEMENTED`)
///
/// # Security Contract
///
/// Per INV-SESS-001 through INV-SESS-004 and INV-TCK-00260-001/002:
/// - All session endpoints require valid `session_token`
/// - Token validation uses constant-time HMAC comparison (CTR-WH001)
/// - Operator connections receive `SESSION_ERROR_PERMISSION_DENIED`
/// - Invalid/expired tokens receive `SESSION_ERROR_INVALID`
/// - Tool requests validated against capability manifest (TCK-00260)
/// - Empty `tool_allowlist` denies all tools (fail-closed)
///
/// Per INV-TCK-00290-001 through INV-TCK-00290-004:
/// - `RequestTool` requires `ToolBroker` (fail-closed)
/// - `EmitEvent` requires ledger (fail-closed)
/// - `PublishEvidence` requires CAS (fail-closed)
/// - `StreamTelemetry` disabled until implemented (fail-closed)
pub struct SessionDispatcher<M: ManifestStore = InMemoryManifestStore> {
    /// Token minter for validation.
    token_minter: TokenMinter,
    /// Decode configuration for bounded message decoding.
    decode_config: DecodeConfig,
    /// Manifest store for capability validation (TCK-00260).
    /// NOTE: This is retained for backwards compatibility with existing tests
    /// even though the broker now handles manifest validation.
    #[allow(dead_code)]
    manifest_store: Option<Arc<M>>,
    /// Ledger event emitter for `EmitEvent` persistence (TCK-00290).
    ledger: Option<Arc<dyn LedgerEventEmitter>>,
    /// Content-addressed store for `PublishEvidence` (TCK-00290).
    cas: Option<Arc<dyn ContentAddressedStore>>,
    /// Tool broker for `RequestTool` execution (TCK-00290).
    ///
    /// Per DOD: "`RequestTool` executes via `ToolBroker` and returns
    /// `ToolResult` or Deny"
    broker: Option<SharedToolBroker<StubManifestLoader>>,
    /// Per-session broker registry for capability/policy isolation (TCK-00401).
    ///
    /// When configured, `RequestTool` resolves the broker by `session_id`.
    /// Missing session brokers are denied fail-closed.
    session_brokers: Option<SharedSessionBrokerRegistry<StubManifestLoader>>,
    /// Holonic clock for monotonic timestamps (TCK-00290).
    ///
    /// Per RFC-0016, timestamps must be monotonic. Using `SystemTime` directly
    /// violates time monotonicity guarantees.
    clock: Option<Arc<HolonicClock>>,
    /// Event sequence counter (per-session, monotonic).
    event_seq: AtomicU64,
    /// Subscription registry for HEF Pulse Plane resource governance
    /// (TCK-00303).
    ///
    /// Tracks per-connection subscription state and enforces limits per
    /// RFC-0018. Shared with `PrivilegedDispatcher` to manage subscriptions
    /// across both operator and session sockets.
    subscription_registry: Option<super::resource_governance::SharedSubscriptionRegistry>,
    /// Episode runtime for tool execution (TCK-00316).
    ///
    /// Per TCK-00316, this is required to execute tools kernel-side and return
    /// durable result references.
    episode_runtime: Option<Arc<EpisodeRuntime>>,
    /// Session registry for session status queries (TCK-00344).
    ///
    /// Per TCK-00344, the session registry is used to look up session state
    /// for `SessionStatus` queries.
    session_registry: Option<Arc<dyn crate::session::SessionRegistry>>,
    /// Session telemetry store for tracking tool calls, events emitted,
    /// and session start time (TCK-00384).
    ///
    /// Per TCK-00384, this store tracks per-session counters using atomic
    /// operations. It is separate from the session registry because
    /// `SessionState` must remain `Clone + Serialize + Deserialize`.
    telemetry_store: Option<Arc<crate::session::SessionTelemetryStore>>,
    /// Gate orchestrator for autonomous gate lifecycle (TCK-00388).
    ///
    /// When set, session termination triggers gate orchestration via
    /// [`GateOrchestrator::on_session_terminated`]. The returned events
    /// are persisted to the ledger through the session dispatcher's
    /// `ledger` emitter.
    gate_orchestrator: Option<Arc<GateOrchestrator>>,
    /// Pre-actuation gate for stop/budget checks (TCK-00351).
    ///
    /// When set, every `RequestTool` invocation must pass through this gate
    /// before reaching the broker. The gate checks stop conditions and
    /// budget availability, returning a receipt that is embedded in the
    /// tool response.
    preactuation_gate: Option<Arc<crate::episode::preactuation::PreActuationGate>>,
    /// Authoritative stop state for the daemon runtime (TCK-00351).
    ///
    /// TCK-00351 BLOCKER 1 FIX: This provides the runtime stop flags
    /// (emergency stop, governance stop) that the pre-actuation gate reads.
    /// When set, the gate ignores hardcoded false values and reads from
    /// this authority.
    stop_authority: Option<Arc<crate::episode::preactuation::StopAuthority>>,
    /// Per-session stop conditions store (TCK-00351 v3).
    ///
    /// TCK-00351 BLOCKER 1 v3 FIX: The pre-actuation gate was called with
    /// `StopConditions::default()` and `current_episode_count=0`, meaning
    /// `max_episodes` and `escalation_predicate` were never actually
    /// checked.  This store holds real stop conditions per session, loaded
    /// from the episode envelope at session spawn time.  The gate reads
    /// from this store and passes real `current_episode_count` from the
    /// session telemetry.
    stop_conditions_store: Option<Arc<crate::session::SessionStopConditionsStore>>,
    /// Shared V1 manifest store for broker scope enforcement
    /// (TCK-00352 Security Review MAJOR 2).
    ///
    /// When a session has a V1 manifest registered, the `handle_request_tool`
    /// path enforces V1 scope checks (risk tier ceiling, host restrictions,
    /// envelope-manifest hash binding) before dispatching to the broker.
    /// Sessions without a V1 manifest fall through to the existing broker
    /// path (backwards compatible).
    ///
    /// This store is shared with `PrivilegedDispatcher` via `DispatcherState`
    /// so that `SpawnEpisode` can mint and register V1 manifests.
    v1_manifest_store: Option<SharedV1ManifestStore>,
    /// PCAC lifecycle gate for authority lifecycle enforcement (TCK-00423).
    ///
    /// When set, every `RequestTool` invocation must pass through the
    /// lifecycle:
    /// `join -> revalidate-before-decision -> broker decision ->
    ///  revalidate-before-execution -> consume -> effect`.
    ///
    /// In authoritative mode (`ledger` or `cas` configured), this gate is
    /// mandatory and missing wiring causes deny (fail-closed).
    pcac_lifecycle_gate: Option<Arc<crate::pcac::LifecycleGate>>,
}

#[derive(Clone)]
struct PendingPcacAuthority {
    gate: Arc<crate::pcac::LifecycleGate>,
    certificate: apm2_core::pcac::AuthorityJoinCertificateV1,
    intent_digest: Hash,
}

impl SessionDispatcher<InMemoryManifestStore> {
    /// Creates a new dispatcher with the given token minter.
    ///
    /// **Note**: This creates a dispatcher without backing stores. Per
    /// TCK-00290, handlers will return fail-closed errors when their stores
    /// are unavailable:
    /// - `RequestTool`: Returns `TOOL_NOT_ALLOWED` (no broker)
    /// - `EmitEvent`: Returns `SESSION_ERROR_INTERNAL` (no ledger)
    /// - `PublishEvidence`: Returns `SESSION_ERROR_INTERNAL` (no CAS)
    /// - `StreamTelemetry`: Returns `SESSION_ERROR_NOT_IMPLEMENTED`
    #[must_use]
    pub fn new(token_minter: TokenMinter) -> Self {
        Self {
            token_minter,
            decode_config: DecodeConfig::default(),
            manifest_store: None,
            ledger: None,
            cas: None,
            broker: None,
            session_brokers: None,
            clock: None,
            event_seq: AtomicU64::new(0),
            subscription_registry: None,
            episode_runtime: None,
            session_registry: None,
            telemetry_store: None,
            gate_orchestrator: None,
            preactuation_gate: None,
            stop_authority: None,
            stop_conditions_store: None,
            v1_manifest_store: None,
            pcac_lifecycle_gate: None,
        }
    }

    /// Creates a new dispatcher with custom decode configuration.
    #[must_use]
    pub fn with_decode_config(token_minter: TokenMinter, decode_config: DecodeConfig) -> Self {
        Self {
            token_minter,
            decode_config,
            manifest_store: None,
            ledger: None,
            cas: None,
            broker: None,
            session_brokers: None,
            clock: None,
            event_seq: AtomicU64::new(0),
            subscription_registry: None,
            episode_runtime: None,
            session_registry: None,
            telemetry_store: None,
            gate_orchestrator: None,
            preactuation_gate: None,
            stop_authority: None,
            stop_conditions_store: None,
            v1_manifest_store: None,
            pcac_lifecycle_gate: None,
        }
    }
}

impl<M: ManifestStore> SessionDispatcher<M> {
    /// Creates a dispatcher with a manifest store for capability validation.
    ///
    /// Per TCK-00260, the manifest store is used to look up session capability
    /// manifests for tool request validation.
    #[must_use]
    pub fn with_manifest_store(token_minter: TokenMinter, manifest_store: Arc<M>) -> Self {
        Self {
            token_minter,
            decode_config: DecodeConfig::default(),
            manifest_store: Some(manifest_store),
            ledger: None,
            cas: None,
            broker: None,
            session_brokers: None,
            clock: None,
            event_seq: AtomicU64::new(0),
            subscription_registry: None,
            episode_runtime: None,
            session_registry: None,
            telemetry_store: None,
            gate_orchestrator: None,
            preactuation_gate: None,
            stop_authority: None,
            stop_conditions_store: None,
            v1_manifest_store: None,
            pcac_lifecycle_gate: None,
        }
    }

    /// Creates a dispatcher with custom decode configuration and manifest
    /// store.
    #[must_use]
    pub fn with_decode_config_and_manifest_store(
        token_minter: TokenMinter,
        decode_config: DecodeConfig,
        manifest_store: Arc<M>,
    ) -> Self {
        Self {
            token_minter,
            decode_config,
            manifest_store: Some(manifest_store),
            ledger: None,
            cas: None,
            broker: None,
            session_brokers: None,
            clock: None,
            event_seq: AtomicU64::new(0),
            subscription_registry: None,
            episode_runtime: None,
            session_registry: None,
            telemetry_store: None,
            gate_orchestrator: None,
            preactuation_gate: None,
            stop_authority: None,
            stop_conditions_store: None,
            v1_manifest_store: None,
            pcac_lifecycle_gate: None,
        }
    }

    /// Creates a fully-configured dispatcher with all backing stores
    /// (TCK-00290).
    ///
    /// This is the production-ready constructor that configures all
    /// dependencies for real handler implementations:
    /// - `manifest_store`: For `RequestTool` capability validation
    /// - `ledger`: For `EmitEvent` persistence
    /// - `cas`: For `PublishEvidence` artifact storage
    /// - `broker`: For `RequestTool` execution via `ToolBroker`
    /// - `clock`: For monotonic timestamps (RFC-0016)
    ///
    /// # Arguments
    ///
    /// * `token_minter` - Token minter for session validation
    /// * `manifest_store` - Capability manifest store for tool validation
    /// * `ledger` - Ledger event emitter for event persistence
    /// * `cas` - Content-addressed store for evidence artifacts
    #[must_use]
    pub fn with_all_stores(
        token_minter: TokenMinter,
        manifest_store: Arc<M>,
        ledger: Arc<dyn LedgerEventEmitter>,
        cas: Arc<dyn ContentAddressedStore>,
    ) -> Self {
        Self {
            token_minter,
            decode_config: DecodeConfig::default(),
            manifest_store: Some(manifest_store),
            ledger: Some(ledger),
            cas: Some(cas),
            broker: None,
            session_brokers: None,
            clock: None,
            event_seq: AtomicU64::new(0),
            subscription_registry: None,
            episode_runtime: None,
            session_registry: None,
            telemetry_store: None,
            gate_orchestrator: None,
            preactuation_gate: None,
            stop_authority: None,
            stop_conditions_store: None,
            v1_manifest_store: None,
            pcac_lifecycle_gate: None,
        }
    }

    /// Sets the ledger event emitter for `EmitEvent` persistence.
    #[must_use]
    pub fn with_ledger(mut self, ledger: Arc<dyn LedgerEventEmitter>) -> Self {
        self.ledger = Some(ledger);
        self
    }

    /// Sets the content-addressed store for `PublishEvidence`.
    #[must_use]
    pub fn with_cas(mut self, cas: Arc<dyn ContentAddressedStore>) -> Self {
        self.cas = Some(cas);
        self
    }

    /// Sets the tool broker for `RequestTool` execution (TCK-00290).
    ///
    /// Per DOD: "`RequestTool` executes via `ToolBroker` and returns
    /// `ToolResult` or Deny"
    #[must_use]
    pub fn with_broker(mut self, broker: SharedToolBroker<StubManifestLoader>) -> Self {
        self.broker = Some(broker);
        self
    }

    /// Sets the per-session broker registry for `RequestTool` execution.
    #[must_use]
    pub fn with_session_brokers(
        mut self,
        brokers: SharedSessionBrokerRegistry<StubManifestLoader>,
    ) -> Self {
        self.session_brokers = Some(brokers);
        self
    }

    /// Sets the holonic clock for monotonic timestamps (TCK-00290).
    ///
    /// Per RFC-0016, timestamps must be monotonic. Using `SystemTime` directly
    /// violates time monotonicity guarantees.
    #[must_use]
    pub fn with_clock(mut self, clock: Arc<HolonicClock>) -> Self {
        self.clock = Some(clock);
        self
    }

    /// Sets the subscription registry for HEF Pulse Plane resource governance
    /// (TCK-00303).
    ///
    /// The subscription registry tracks per-connection subscription state and
    /// enforces limits per RFC-0018. It should be shared with
    /// `PrivilegedDispatcher` to manage subscriptions across both operator and
    /// session sockets.
    #[must_use]
    pub fn with_subscription_registry(
        mut self,
        registry: super::resource_governance::SharedSubscriptionRegistry,
    ) -> Self {
        self.subscription_registry = Some(registry);
        self
    }

    /// Sets the episode runtime for tool execution (TCK-00316).
    #[must_use]
    pub fn with_episode_runtime(mut self, runtime: Arc<EpisodeRuntime>) -> Self {
        self.episode_runtime = Some(runtime);
        self
    }

    /// Sets the session registry for session status queries (TCK-00344).
    #[must_use]
    pub fn with_session_registry(
        mut self,
        registry: Arc<dyn crate::session::SessionRegistry>,
    ) -> Self {
        self.session_registry = Some(registry);
        self
    }

    /// Sets the session telemetry store for tracking tool calls, events
    /// emitted, and session start time (TCK-00384).
    #[must_use]
    pub fn with_telemetry_store(
        mut self,
        store: Arc<crate::session::SessionTelemetryStore>,
    ) -> Self {
        self.telemetry_store = Some(store);
        self
    }

    /// Sets the gate orchestrator for autonomous gate lifecycle (TCK-00388).
    ///
    /// When set, session termination via `ToolDecision::Terminate` triggers
    /// gate orchestration. Events from the orchestrator are persisted to
    /// the ledger through the dispatcher's `ledger` emitter.
    /// Sets the gate orchestrator (builder pattern).
    #[must_use]
    pub fn with_gate_orchestrator(mut self, orchestrator: Arc<GateOrchestrator>) -> Self {
        self.gate_orchestrator = Some(orchestrator);
        self
    }

    /// Sets the gate orchestrator on an already-constructed dispatcher.
    ///
    /// This is used by `DispatcherState::with_gate_orchestrator` to wire
    /// the orchestrator after the session dispatcher has been built.
    pub fn set_gate_orchestrator(&mut self, orchestrator: Arc<GateOrchestrator>) {
        self.gate_orchestrator = Some(orchestrator);
    }

    /// Sets the pre-actuation gate for stop/budget checks (TCK-00351).
    ///
    /// When set, every `RequestTool` invocation must pass through this gate
    /// before reaching the broker.  The gate enforces fail-closed semantics:
    /// - Active stop condition -> deny
    /// - Budget exhausted -> deny
    /// - Stop uncertainty past deadline -> deny
    #[must_use]
    pub fn with_preactuation_gate(
        mut self,
        gate: Arc<crate::episode::preactuation::PreActuationGate>,
    ) -> Self {
        self.preactuation_gate = Some(gate);
        self
    }

    /// Returns the configured pre-actuation gate (tests only).
    #[cfg(test)]
    pub const fn preactuation_gate_for_test(
        &self,
    ) -> Option<&Arc<crate::episode::preactuation::PreActuationGate>> {
        self.preactuation_gate.as_ref()
    }

    /// Sets the stop authority for authoritative stop-state reads
    /// (TCK-00351).
    ///
    /// TCK-00351 BLOCKER 1 FIX: When set, the pre-actuation gate reads
    /// emergency and governance stop flags from this authority instead
    /// of using hardcoded `false`.
    #[must_use]
    pub fn with_stop_authority(
        mut self,
        authority: Arc<crate::episode::preactuation::StopAuthority>,
    ) -> Self {
        self.stop_authority = Some(authority);
        self
    }

    /// Sets the per-session stop conditions store (TCK-00351 v3).
    ///
    /// TCK-00351 BLOCKER 1 v3 FIX: When set, the pre-actuation gate
    /// reads real stop conditions from this store instead of using
    /// `StopConditions::default()`.  Conditions are registered at
    /// session spawn time from the episode envelope.
    #[must_use]
    pub fn with_stop_conditions_store(
        mut self,
        store: Arc<crate::session::SessionStopConditionsStore>,
    ) -> Self {
        self.stop_conditions_store = Some(store);
        self
    }

    /// Sets the shared V1 manifest store for TCK-00352 scope enforcement.
    ///
    /// Per TCK-00352 Security Review MAJOR 2, this store is shared with
    /// `PrivilegedDispatcher` so that V1 manifests minted during
    /// `SpawnEpisode` are visible for scope enforcement in
    /// `handle_request_tool`.
    #[must_use]
    pub fn with_v1_manifest_store(mut self, store: SharedV1ManifestStore) -> Self {
        self.v1_manifest_store = Some(store);
        self
    }

    /// Sets the PCAC lifecycle gate for authority enforcement (TCK-00423).
    ///
    /// When set, every `RequestTool` invocation must pass through the
    /// split lifecycle:
    /// `join -> revalidate-before-decision -> broker decision ->
    ///  revalidate-before-execution -> consume -> effect`.
    #[must_use]
    pub fn with_pcac_lifecycle_gate(mut self, gate: Arc<crate::pcac::LifecycleGate>) -> Self {
        self.pcac_lifecycle_gate = Some(gate);
        self
    }

    fn emit_htf_regression_defect(&self, current: u64, previous: u64) {
        if let Some(ref ledger) = self.ledger {
            let defect_id = format!("DEF-REGRESSION-{}", uuid::Uuid::new_v4());

            // TCK-00307 MAJOR 3 FIX: Use proper timestamps instead of zeros.
            // Since this is called when the clock regression is detected, we use
            // the `current` timestamp from the regression error as our best available
            // timestamp. We cannot call the clock again since it just failed.
            let timestamp_ns = current;

            // Create a time envelope ref by hashing a timestamp-based URI
            let time_envelope_uri = format!("htf:regression:{current}");
            let time_envelope_hash = blake3::hash(time_envelope_uri.as_bytes())
                .as_bytes()
                .to_vec();

            // TCK-00307 BLOCKER 1 FIX: Create structured DefectRecord and store in CAS.
            // Per the DefectRecorded protocol, cas_hash must point to a full DefectRecord
            // JSON artifact, not a raw string or placeholder.
            let defect_record = match DefectRecord::clock_regression(
                &defect_id,
                "system",
                current,
                previous,
                timestamp_ns,
            ) {
                Ok(record) => record,
                Err(e) => {
                    error!("Failed to create clock regression DefectRecord: {}", e);
                    return;
                },
            };

            // Serialize DefectRecord to JSON for CAS storage
            let defect_json = match serde_json::to_vec(&defect_record) {
                Ok(json) => json,
                Err(e) => {
                    error!("Failed to serialize clock regression DefectRecord: {}", e);
                    return;
                },
            };

            // Store in CAS if available, otherwise compute hash for reference
            let cas_hash = self.cas.as_ref().map_or_else(
                || blake3::hash(&defect_json).as_bytes().to_vec(),
                |cas| cas.store(&defect_json).to_vec(),
            );

            // Create DefectRecorded event with proper CAS hash
            let defect = DefectRecorded {
                defect_id,
                defect_type: "CLOCK_REGRESSION".to_string(),
                cas_hash,
                source: DefectSource::HtfRegression as i32,
                work_id: "system".to_string(),
                severity: "S0".to_string(),
                detected_at: timestamp_ns,
                time_envelope_ref: Some(TimeEnvelopeRef {
                    hash: time_envelope_hash,
                }),
            };

            if let Err(e) = ledger.emit_defect_recorded(&defect, timestamp_ns) {
                error!("Failed to emit clock regression defect: {}", e);
            }
        }
    }

    fn emit_context_miss_defect(&self, session_id: &str, path: &str) {
        if let Some(ref ledger) = self.ledger {
            let defect_id = format!("DEF-MISS-{}", uuid::Uuid::new_v4());

            // TCK-00307 MAJOR 3 FIX: Use proper timestamps instead of zeros.
            // Try to get timestamp from clock; if not configured, use SystemTime
            // as a fallback for defect logging (this is observational, not authoritative).
            #[allow(clippy::map_unwrap_or)] // Clearer with explicit closure for the fallback
            let timestamp_ns = self
                .clock
                .as_ref()
                .and_then(|c| c.now_hlc().ok())
                .map_or_else(
                    || {
                        warn!("Clock not configured for context miss defect; using SystemTime fallback");
                        SystemTime::now()
                            .duration_since(SystemTime::UNIX_EPOCH)
                            // Truncation is acceptable: timestamps won't exceed u64 for ~500 years
                            .map(|d| {
                                #[allow(clippy::cast_possible_truncation)]
                                let ns = d.as_nanos() as u64;
                                ns
                            })
                            .unwrap_or(0)
                    },
                    |hlc| hlc.wall_ns,
                );

            // Create time envelope ref from timestamp
            let time_envelope_uri = format!("htf:context-miss:{timestamp_ns}");
            let time_envelope_hash = blake3::hash(time_envelope_uri.as_bytes())
                .as_bytes()
                .to_vec();

            // TCK-00307 BLOCKER 1 FIX: Create structured DefectRecord and store in CAS.
            // Per the DefectRecorded protocol, cas_hash must point to a full DefectRecord
            // JSON artifact, not a raw description string.
            //
            // Note: DefectRecord::pack_miss requires a pack_hash, but for context misses
            // detected during session dispatch, we may not have the pack hash available.
            // We use a zero hash as a placeholder - the path in the signal details is the
            // key information for debugging.
            let defect_record = match DefectRecord::pack_miss(
                &defect_id,
                session_id,
                path,
                [0u8; 32], // Pack hash not available in this context
                timestamp_ns,
            ) {
                Ok(record) => record,
                Err(e) => {
                    error!("Failed to create context miss DefectRecord: {}", e);
                    return;
                },
            };

            // Serialize DefectRecord to JSON for CAS storage
            let defect_json = match serde_json::to_vec(&defect_record) {
                Ok(json) => json,
                Err(e) => {
                    error!("Failed to serialize context miss DefectRecord: {}", e);
                    return;
                },
            };

            // Store in CAS if available, otherwise compute hash for reference
            let cas_hash = self.cas.as_ref().map_or_else(
                || blake3::hash(&defect_json).as_bytes().to_vec(),
                |cas| cas.store(&defect_json).to_vec(),
            );

            let defect = DefectRecorded {
                defect_id,
                defect_type: "UNPLANNED_CONTEXT_READ".to_string(),
                cas_hash,
                source: DefectSource::ContextMiss as i32,
                work_id: session_id.to_string(),
                severity: "S2".to_string(),
                detected_at: timestamp_ns,
                time_envelope_ref: Some(TimeEnvelopeRef {
                    hash: time_envelope_hash,
                }),
            };

            if let Err(e) = ledger.emit_defect_recorded(&defect, timestamp_ns) {
                error!("Failed to emit context miss defect: {}", e);
            }
        }
    }

    fn emit_firewall_violation_defect(
        &self,
        session_id: &str,
        defect: &FirewallViolationDefect,
        fallback_timestamp_ns: u64,
    ) -> Result<(), String> {
        let Some(ref ledger) = self.ledger else {
            return Err("ledger unavailable for firewall defect emission".to_string());
        };

        let defect_id = format!("DEF-FW-{}", uuid::Uuid::new_v4());
        let timestamp_ns = self
            .clock
            .as_ref()
            .and_then(|clock| clock.now_hlc().ok().map(|hlc| hlc.wall_ns))
            .unwrap_or(fallback_timestamp_ns);

        let severity = if defect.requires_termination() {
            DefectSeverity::S1
        } else {
            DefectSeverity::S2
        };

        let defect_record = DefectRecord::builder(&defect_id, "CONTEXT_FIREWALL_VIOLATION")
            .severity(severity)
            .work_id(session_id)
            .detected_at(timestamp_ns)
            .signal(DefectSignal::new(
                SignalType::UnplannedContextRead,
                format!(
                    "rule={} type={} manifest={} path={} reason={}",
                    defect.rule_id,
                    defect.violation_type,
                    defect.manifest_id,
                    defect.path,
                    defect.reason
                ),
            ))
            .context(
                HolonDefectContext::new()
                    .with_session_id(session_id)
                    .with_requested_stable_id(defect.path.clone()),
            )
            .build()
            .map_err(|e| format!("failed to build firewall DefectRecord: {e}"))?;

        let defect_json = serde_json::to_vec(&defect_record)
            .map_err(|e| format!("failed to serialize firewall DefectRecord: {e}"))?;
        let cas_hash = self.cas.as_ref().map_or_else(
            || blake3::hash(&defect_json).as_bytes().to_vec(),
            |cas| cas.store(&defect_json).to_vec(),
        );

        let time_envelope_uri = format!("htf:firewall:{}:{}", timestamp_ns, defect.rule_id);
        let time_envelope_hash = blake3::hash(time_envelope_uri.as_bytes())
            .as_bytes()
            .to_vec();

        let defect_event = DefectRecorded {
            defect_id,
            defect_type: format!("CONTEXT_FIREWALL_{}", defect.violation_type),
            cas_hash,
            source: DefectSource::ContextMiss as i32,
            work_id: session_id.to_string(),
            severity: severity.as_str().to_string(),
            detected_at: timestamp_ns,
            time_envelope_ref: Some(TimeEnvelopeRef {
                hash: time_envelope_hash,
            }),
        };

        ledger
            .emit_defect_recorded(&defect_event, timestamp_ns)
            .map_err(|e| format!("failed to emit firewall defect: {e}"))?;

        Ok(())
    }

    fn emit_firewall_violation_defects(
        &self,
        session_id: &str,
        defects: &[FirewallViolationDefect],
        fallback_timestamp_ns: u64,
    ) -> Result<(), String> {
        for defect in defects {
            self.emit_firewall_violation_defect(session_id, defect, fallback_timestamp_ns)
                .map_err(|e| format!("rule={} path={} error={e}", defect.rule_id, defect.path))?;
        }
        Ok(())
    }

    fn ensure_session_terminated(&self, session_id: &str, rationale: &str) -> Result<(), String> {
        let Some(session_registry) = &self.session_registry else {
            return Err("session registry unavailable for mandatory termination".to_string());
        };

        if session_registry.get_session(session_id).is_some() {
            let term_info = crate::episode::decision::SessionTerminationInfo::new(
                session_id, rationale, "FAILURE",
            );
            session_registry
                .mark_terminated(session_id, term_info)
                .map_err(|e| format!("failed to persist session termination state: {e}"))?;
        }

        if let Some(ref store) = self.telemetry_store {
            store.remove(session_id);
        }
        if let Some(ref store) = self.stop_conditions_store {
            store.remove(session_id);
        }

        Ok(())
    }

    fn enforce_mandatory_defect_termination(
        decision: Result<ToolDecision, crate::episode::BrokerError>,
        session_id: &str,
        defects: &[FirewallViolationDefect],
    ) -> Result<ToolDecision, crate::episode::BrokerError> {
        let has_mandatory_termination_defect = defects
            .iter()
            .any(FirewallViolationDefect::requires_termination);
        if !has_mandatory_termination_defect {
            return decision;
        }

        match decision {
            Ok(decision) if !matches!(decision, ToolDecision::Terminate { .. }) => {
                let request_id = decision.request_id().to_string();
                Ok(ToolDecision::Terminate {
                    request_id,
                    termination_info: Box::new(
                        crate::episode::decision::SessionTerminationInfo::new(
                            session_id,
                            "CONTEXT_FIREWALL_VIOLATION",
                            "FAILURE",
                        ),
                    ),
                    refinement_event: None,
                })
            },
            other => other,
        }
    }

    /// Dispatches a session-scoped request to the appropriate handler.
    ///
    /// # Message Format
    ///
    /// The frame format is: [tag: u8][payload: protobuf]
    /// Where tag identifies the message type (see [`SessionMessageType`]).
    ///
    /// # Security
    ///
    /// 1. Validates `ctx.is_privileged() == false` FIRST
    /// 2. Returns `SESSION_ERROR_PERMISSION_DENIED` for operator connections
    /// 3. Validates session token before dispatching
    /// 4. Only then routes the message to the handler
    ///
    /// # Errors
    ///
    /// Returns `Err` for protocol-level errors (malformed frames, etc.).
    /// Application-level errors are returned in [`SessionResponse::Error`].
    pub fn dispatch(
        &self,
        frame: &Bytes,
        ctx: &ConnectionContext,
    ) -> ProtocolResult<SessionResponse> {
        // TCK-00349: Check session phase BEFORE any message processing.
        // No session-scoped IPC is permitted before SessionOpen.
        if !ctx.phase().allows_dispatch() {
            warn!(
                phase = %ctx.phase(),
                "Session dispatch rejected: connection not in SessionOpen phase"
            );
            return Ok(SessionResponse::error(
                SessionErrorCode::SessionErrorInvalid,
                format!(
                    "dispatch rejected: connection is in {} phase, not SessionOpen",
                    ctx.phase()
                ),
            ));
        }

        // INV-SESS-003: Check that connection is NOT privileged
        if ctx.is_privileged() {
            debug!(
                peer_pid = ?ctx.peer_credentials().map(|c| c.pid),
                "Operator connection attempted session endpoint"
            );
            return Ok(SessionResponse::permission_denied());
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
            SessionMessageType::from_tag(tag).ok_or_else(|| ProtocolError::Serialization {
                reason: format!("unknown session message type: {tag}"),
            })?;

        match msg_type {
            SessionMessageType::RequestTool => self.handle_request_tool(payload, ctx),
            SessionMessageType::EmitEvent => self.handle_emit_event(payload, ctx),
            SessionMessageType::PublishEvidence => self.handle_publish_evidence(payload, ctx),
            SessionMessageType::StreamTelemetry => self.handle_stream_telemetry(payload, ctx),
            // TCK-00342: Process log streaming
            SessionMessageType::StreamLogs => self.handle_stream_logs(payload, ctx),
            // TCK-00344: Session status query
            SessionMessageType::SessionStatus => self.handle_session_status(payload, ctx),
            // HEF Pulse Plane (TCK-00302): Subscription handlers
            SessionMessageType::SubscribePulse => self.handle_subscribe_pulse(payload, ctx),
            SessionMessageType::UnsubscribePulse => self.handle_unsubscribe_pulse(payload, ctx),
            // PulseEvent is server-to-client only, reject if received from client
            SessionMessageType::PulseEvent => Ok(SessionResponse::error(
                SessionErrorCode::SessionErrorInvalid,
                "PulseEvent is server-to-client only",
            )),
        }
    }

    /// Validates a session token from a request.
    ///
    /// # Security
    ///
    /// Per INV-SESS-001 and INV-SESS-004:
    /// - Token is parsed and validated using HMAC-SHA256
    /// - Constant-time comparison prevents timing attacks (CTR-WH001)
    /// - Returns error description without leaking internal state
    #[allow(clippy::result_large_err)] // SessionResponse is large due to RequestToolResponse fields; refactoring to Box would be a breaking change
    fn validate_token(&self, token_json: &str) -> Result<SessionToken, SessionResponse> {
        // Parse the token JSON
        let token: SessionToken = serde_json::from_str(token_json).map_err(|e| {
            SessionResponse::session_invalid(format!("malformed session token: {e}"))
        })?;

        // Validate using TokenMinter (constant-time HMAC comparison)
        let now = SystemTime::now();
        self.token_minter
            .validate(&token, now)
            .map_err(|e| match e {
                SessionTokenError::InvalidMac => {
                    SessionResponse::session_invalid("invalid session token")
                },
                SessionTokenError::Expired { .. } => {
                    SessionResponse::session_invalid("session token expired")
                },
                _ => SessionResponse::session_invalid(format!("session token error: {e}")),
            })?;

        Ok(token)
    }

    #[inline]
    const fn is_authoritative_mode(&self) -> bool {
        self.ledger.is_some() || self.cas.is_some()
    }

    fn derive_pcac_risk_tier_from_policy(
        &self,
        session_id: &str,
        tool_class: ToolClass,
    ) -> Option<apm2_core::pcac::RiskTier> {
        let manifest = self
            .manifest_store
            .as_ref()
            .and_then(|store| store.get_manifest(session_id))?;
        let capability = manifest.find_by_tool_class(tool_class).next()?;
        Some(match capability.risk_tier_required {
            RiskTier::Tier0 => apm2_core::pcac::RiskTier::Tier0,
            RiskTier::Tier1 => apm2_core::pcac::RiskTier::Tier1,
            RiskTier::Tier2 | RiskTier::Tier3 | RiskTier::Tier4 => {
                apm2_core::pcac::RiskTier::Tier2Plus
            },
        })
    }

    fn derive_pcac_ledger_anchor(ledger: &dyn LedgerEventEmitter) -> Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"pcac-ledger-anchor-v1");
        let events = ledger.get_all_events();
        hasher.update(&(events.len() as u64).to_le_bytes());
        if let Some(last) = events.last() {
            hasher.update(last.event_id.as_bytes());
            hasher.update(last.event_type.as_bytes());
            hasher.update(last.work_id.as_bytes());
            hasher.update(last.actor_id.as_bytes());
            hasher.update(&last.timestamp_ns.to_le_bytes());
            hasher.update(&last.signature);
            hasher.update(blake3::hash(&last.payload).as_bytes());
        } else {
            hasher.update(b"genesis");
        }
        *hasher.finalize().as_bytes()
    }

    fn hash_preactuation_receipt(receipt: &PreActuationReceipt) -> Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"pcac-preactuation-receipt-v1");
        hasher.update(&receipt.timestamp_ns.to_le_bytes());
        hasher.update(&[u8::from(receipt.stop_checked)]);
        hasher.update(&[u8::from(receipt.budget_checked)]);
        hasher.update(&[u8::from(receipt.budget_enforcement_deferred)]);
        *hasher.finalize().as_bytes()
    }

    fn derive_scope_witness_hashes(tool_class: ToolClass, request_arguments: &[u8]) -> Vec<Hash> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"pcac-scope-witness-v1");
        let tool_class_name = tool_class.to_string();
        hasher.update(tool_class_name.as_bytes());
        hasher.update(request_arguments);
        vec![*hasher.finalize().as_bytes()]
    }

    fn derive_fresh_pcac_revalidation_inputs(
        &self,
        session_id: &str,
    ) -> Result<(Hash, Hash, Hash), String> {
        let clock = self
            .clock
            .as_ref()
            .ok_or_else(|| "clock unavailable".to_string())?;
        let hlc = clock
            .now_hlc()
            .map_err(|e| format!("clock read failed: {e}"))?;
        let current_time_envelope_ref = *blake3::hash(&hlc.wall_ns.to_le_bytes()).as_bytes();

        let ledger = self
            .ledger
            .as_ref()
            .ok_or_else(|| "ledger unavailable".to_string())?;
        let current_ledger_anchor = Self::derive_pcac_ledger_anchor(ledger.as_ref());

        let registry = self
            .session_registry
            .as_ref()
            .ok_or_else(|| "session registry unavailable".to_string())?;
        let fresh_session = registry
            .get_session(session_id)
            .ok_or_else(|| "session state unavailable".to_string())?;
        if fresh_session.policy_resolved_ref.is_empty() {
            return Err("revocation provider unavailable: empty policy_resolved_ref".to_string());
        }
        let current_revocation_head =
            *blake3::hash(fresh_session.policy_resolved_ref.as_bytes()).as_bytes();

        Ok((
            current_time_envelope_ref,
            current_ledger_anchor,
            current_revocation_head,
        ))
    }

    /// Handles `RequestTool` requests (IPC-SESS-001).
    ///
    /// # TCK-00260: Capability Manifest Validation
    ///
    /// This handler validates tool requests against the session's capability
    /// manifest:
    ///
    /// 1. Validates session token (INV-SESS-001)
    /// 2. Validates `tool_id` is not empty and within length bounds
    /// 3. Parses `tool_id` to a `ToolClass`
    /// 4. Looks up the session's capability manifest
    /// 5. Checks if the tool class is in the manifest's `tool_allowlist`
    /// 6. Returns `SESSION_ERROR_TOOL_NOT_ALLOWED` if not in allowlist
    ///
    /// # Performance
    ///
    /// Per TCK-00260 acceptance criteria, validation overhead must be <5ms p50.
    /// The validation is O(n) where n = `tool_allowlist` length (bounded by
    /// `MAX_TOOL_ALLOWLIST` = 100).
    ///
    /// # TCK-00290: `ToolBroker` Integration
    ///
    /// Per DOD: "`RequestTool` executes via `ToolBroker` and returns
    /// `ToolResult` or Deny" The broker validates capabilities, policy, and
    /// returns a decision.
    fn handle_request_tool(
        &self,
        payload: &[u8],
        ctx: &ConnectionContext,
    ) -> ProtocolResult<SessionResponse> {
        let request =
            RequestToolRequest::decode_bounded(payload, &self.decode_config).map_err(|e| {
                ProtocolError::Serialization {
                    reason: format!("invalid RequestToolRequest: {e}"),
                }
            })?;

        // INV-SESS-001: Validate session token
        let token = match self.validate_token(&request.session_token) {
            Ok(t) => t,
            Err(resp) => return Ok(resp),
        };

        // TCK-00395 Security BLOCKER 2: Enforce active-session check.
        // HMAC token validation alone is not sufficient because EndSession
        // revokes only session-registry state. A retained token could
        // continue tool actions after EndSession if we don't verify
        // the session still exists in the registry.
        if let Some(ref registry) = self.session_registry {
            if registry.get_session(&token.session_id).is_none() {
                warn!(
                    session_id = %token.session_id,
                    "RequestTool rejected: session not found in registry (may have been terminated)"
                );
                return Ok(SessionResponse::session_invalid(
                    "session not found or already terminated",
                ));
            }
        }

        info!(
            session_id = %token.session_id,
            tool_id = %request.tool_id,
            dedupe_key = %request.dedupe_key,
            peer_pid = ?ctx.peer_credentials().map(|c| c.pid),
            "RequestTool request received"
        );

        // Validate required fields
        if request.tool_id.is_empty() {
            return Ok(SessionResponse::error(
                SessionErrorCode::SessionErrorInvalid,
                "tool_id is required",
            ));
        }

        // CTR-1303: Bounded input validation
        if request.tool_id.len() > MAX_TOOL_ID_LEN {
            return Ok(SessionResponse::error(
                SessionErrorCode::SessionErrorInvalid,
                format!(
                    "tool_id exceeds maximum length ({} > {})",
                    request.tool_id.len(),
                    MAX_TOOL_ID_LEN
                ),
            ));
        }

        // TCK-00260: Parse tool_id to ToolClass
        let Some(tool_class) = ToolClass::parse(&request.tool_id) else {
            warn!(
                session_id = %token.session_id,
                tool_id = %request.tool_id,
                "Unknown tool class"
            );
            // Unknown tool class is denied (fail-closed)
            return Ok(SessionResponse::error(
                SessionErrorCode::SessionErrorToolNotAllowed,
                format!("unknown tool class: {}", request.tool_id),
            ));
        };

        let broker = if let Some(ref brokers) = self.session_brokers {
            brokers.get(&token.session_id)
        } else {
            self.broker.clone()
        };

        // TCK-00351: Pre-actuation stop/budget gate.
        // This check MUST precede broker dispatch.  If the gate denies,
        // we return immediately without reaching the broker (fail-closed).
        //
        // TCK-00351 BLOCKER 2 v2 FIX: When broker/runtime are configured
        // the pre-actuation gate is MANDATORY.  If absent, hard-deny the
        // request instead of silently setting proof fields to false and
        // allowing execution to proceed.
        //
        // TCK-00351 BLOCKER 1 FIX: Read real stop state from stop_authority
        // instead of hardcoded false.
        // TCK-00351 MAJOR 1 FIX: Store the receipt and propagate its fields
        // into the response (stop_checked, budget_checked, timestamp_ns).
        let preactuation_receipt = if broker.is_some() {
            if let Some(ref gate) = self.preactuation_gate {
                // Get monotonic timestamp for the receipt.
                let precheck_ts = self.get_htf_timestamp()?;

                // TCK-00351 BLOCKER 1 FIX: Use real stop conditions.
                // Read stop flags from the authoritative StopAuthority (set by
                // operator/governance) instead of hardcoded false.
                // No stop authority configured; defaults to no stops.
                // The gate itself may also have a StopAuthority wired in
                // via with_stop_authority(), providing defense in depth.
                let (emergency_stop, governance_stop) =
                    self.stop_authority
                        .as_ref()
                        .map_or((false, false), |authority| {
                            (
                                authority.emergency_stop_active(),
                                authority.governance_stop_active(),
                            )
                        });

                // TCK-00351 BLOCKER 1 v3 FIX: Load real stop conditions from the
                // per-session store.  If no store is wired or the session has no
                // conditions registered, fall back to fail-closed defaults
                // (max_episodes=1) rather than StopConditions::default() which
                // is permissive (max_episodes=0 = unlimited).  This ensures
                // sessions without explicit limits are constrained rather than
                // unbounded.
                let conditions = self
                    .stop_conditions_store
                    .as_ref()
                    .and_then(|store| store.get(&token.session_id))
                    .unwrap_or_else(|| crate::episode::envelope::StopConditions::max_episodes(1));

                // TCK-00351 MAJOR v3 FIX: Hard-deny when telemetry is missing for
                // an active session.  An active session MUST have telemetry
                // registered; missing telemetry indicates a configuration bug and
                // continuing with elapsed_ms=0 would mask the stop-uncertainty
                // deadline (fail-closed on uncertainty).
                let telemetry = self
                    .telemetry_store
                    .as_ref()
                    .and_then(|store| store.get(&token.session_id));
                let (elapsed_ms, current_episode_count) = if let Some(t) = telemetry {
                    (t.elapsed_ms(), t.get_episode_count())
                } else {
                    // Fail-closed: no telemetry for this session means we
                    // cannot verify elapsed time or episode count.
                    warn!(
                        session_id = %token.session_id,
                        tool_id = %request.tool_id,
                        "Pre-actuation gate denied: no telemetry registered for session (fail-closed)"
                    );
                    return Ok(SessionResponse::error(
                        SessionErrorCode::SessionErrorToolNotAllowed,
                        "pre-actuation check failed: session telemetry unavailable (fail-closed)"
                            .to_string(),
                    ));
                };

                match gate.check_with_timestamp(
                    &conditions,
                    current_episode_count,
                    emergency_stop,
                    governance_stop,
                    elapsed_ms,
                    precheck_ts,
                ) {
                    Ok(receipt) => {
                        // Gate cleared; proceed to broker dispatch.
                        debug!(
                            session_id = %token.session_id,
                            tool_id = %request.tool_id,
                            stop_checked = receipt.stop_checked,
                            budget_checked = receipt.budget_checked,
                            timestamp_ns = receipt.timestamp_ns,
                            "Pre-actuation gate cleared"
                        );
                        Some(receipt)
                    },
                    Err(denial) => {
                        warn!(
                            session_id = %token.session_id,
                            tool_id = %request.tool_id,
                            denial = %denial,
                            "Pre-actuation gate denied tool request"
                        );
                        return Ok(SessionResponse::error(
                            SessionErrorCode::SessionErrorToolNotAllowed,
                            format!("pre-actuation check failed: {denial}"),
                        ));
                    },
                }
            } else {
                // TCK-00351 BLOCKER 2 v2 FIX: Broker is configured but gate
                // is missing.  This is a configuration error; hard-deny rather
                // than allowing execution without pre-actuation proof.
                error!(
                    session_id = %token.session_id,
                    tool_id = %request.tool_id,
                    "Pre-actuation gate missing but broker configured (fail-closed)"
                );
                return Ok(SessionResponse::error(
                    SessionErrorCode::SessionErrorToolNotAllowed,
                    "pre-actuation gate not configured (fail-closed)".to_string(),
                ));
            }
        } else {
            None
        };
        // TCK-00352 Security Review BLOCKER 1 fix: V1 scope enforcement gate.
        // If the session has a V1 manifest registered, enforce V1 checks
        // (risk tier ceiling, host restrictions, expiry) BEFORE dispatching
        // to the broker. Deny if V1 validation fails.
        //
        // CRITICAL: Parse request.arguments to extract typed tool args
        // (path, network host/port, shell command, size) so that V1 scope
        // validation sees the ACTUAL untrusted fields from the request,
        // not a synthesized empty ToolRequest that would bypass path/host
        // checks.
        if let Some(ref v1_store) = self.v1_manifest_store {
            if let Some(v1_manifest) = v1_store.get(&token.session_id) {
                // Build a V1-compatible ToolRequest for scope validation.
                // Extract risk tier from manifest capabilities for this tool class.
                let risk_tier = self
                    .manifest_store
                    .as_ref()
                    .and_then(|store| store.get_manifest(&token.session_id))
                    .and_then(|manifest| {
                        manifest
                            .find_by_tool_class(tool_class)
                            .next()
                            .map(|cap| cap.risk_tier_required)
                    })
                    .unwrap_or(RiskTier::Tier0);

                let mut v1_request = crate::episode::ToolRequest::new(tool_class, risk_tier);

                // TCK-00352 BLOCKER 1 fix: Parse request.arguments JSON to
                // extract typed fields (path, network, shell_command, size).
                // Without this, validate_request_scoped only checks risk tier
                // and expiry but skips host/path/shell checks because those
                // fields are None in the synthesized request.
                if let Ok(args_value) =
                    serde_json::from_slice::<serde_json::Value>(&request.arguments)
                {
                    // Extract path for filesystem operations (Read, Write, ListFiles)
                    if let Some(path_str) = args_value.get("path").and_then(|v| v.as_str()) {
                        v1_request = v1_request.with_path(std::path::PathBuf::from(path_str));
                    }

                    // Extract network target for Network operations (host from URL).
                    // SECURITY (BLOCKER 1 v3 fix): Use the `url` crate for
                    // RFC-3986-compliant parsing. Ad-hoc string splitting is
                    // vulnerable to authority confusion attacks where a URL like
                    // `https://trusted.com:443@evil.com/steal` tricks naive
                    // parsers into extracting "trusted.com" as the host while
                    // the actual network destination is "evil.com".
                    //
                    // The `url` crate correctly parses the authority component
                    // and separates userinfo from the actual host. We also
                    // hard-deny URLs that contain userinfo (username/password)
                    // since legitimate tool URLs never include credentials in
                    // the URL itself and their presence strongly indicates an
                    // authority confusion attack vector.
                    if let Some(url_str) = args_value.get("url").and_then(|v| v.as_str()) {
                        match url::Url::parse(url_str) {
                            Ok(parsed_url) => {
                                // SECURITY: Reject URLs with userinfo (username
                                // or password). Userinfo in URLs is the primary
                                // vector for authority confusion attacks.
                                if !parsed_url.username().is_empty()
                                    || parsed_url.password().is_some()
                                {
                                    warn!(
                                        session_id = %token.session_id,
                                        "RequestTool denied: URL contains userinfo (authority confusion)"
                                    );
                                    return Ok(SessionResponse::error(
                                        SessionErrorCode::SessionErrorToolNotAllowed,
                                        "URL contains userinfo component; rejected for authority confusion risk".to_string(),
                                    ));
                                }
                                if let Some(host) = parsed_url.host_str() {
                                    let port =
                                        parsed_url.port_or_known_default().unwrap_or_else(|| {
                                            if parsed_url.scheme() == "https" {
                                                443
                                            } else {
                                                80
                                            }
                                        });
                                    v1_request = v1_request.with_network(host, port);
                                }
                                // If host_str() is None (e.g. data: URLs), the
                                // request proceeds without a network target and
                                // the V1 scope check will deny Network tool
                                // class if host restrictions are configured
                                // (fail-closed via empty host restrictions).
                            },
                            Err(_) => {
                                // SECURITY: Fail-closed on unparseable URLs.
                                // If we cannot reliably determine the host, we
                                // must deny Network tool class to prevent
                                // bypass via malformed URLs.
                                if tool_class == ToolClass::Network {
                                    warn!(
                                        session_id = %token.session_id,
                                        "RequestTool denied: URL parse failed for Network tool (fail-closed)"
                                    );
                                    return Ok(SessionResponse::error(
                                        SessionErrorCode::SessionErrorToolNotAllowed,
                                        "URL parse failed; Network tool denied (fail-closed)"
                                            .to_string(),
                                    ));
                                }
                                // For non-Network tool classes, unparseable URL
                                // is not security-relevant; proceed without
                                // network target.
                            },
                        }
                    }

                    // Extract shell command for Execute operations
                    if let Some(cmd) = args_value.get("command").and_then(|v| v.as_str()) {
                        v1_request = v1_request.with_shell_command(cmd);
                    }

                    // Extract size for read/write operations
                    if let Some(size) = args_value.get("limit").and_then(serde_json::Value::as_u64)
                    {
                        v1_request = v1_request.with_size(size);
                    }
                    if let Some(content) = args_value.get("content") {
                        if let Some(content_bytes) = content.as_array() {
                            v1_request = v1_request.with_size(content_bytes.len() as u64);
                        } else if let Some(content_str) = content.as_str() {
                            v1_request = v1_request.with_size(content_str.len() as u64);
                        }
                    }
                }
                // If arguments cannot be parsed as JSON, v1_request retains
                // only tool_class and risk_tier. The inner manifest validation
                // will still enforce tool allowlist and expiry checks (fail-
                // closed for unrecognized tool classes).

                // Get clock for expiry checks (use HTF clock if available,
                // otherwise use system clock as fallback).
                let clock: Box<dyn crate::episode::capability::Clock> =
                    if let Some(ref htf_clock) = self.clock {
                        match htf_clock.now_hlc() {
                            Ok(hlc) => Box::new(crate::episode::capability::FixedClock::new(
                                hlc.wall_ns / 1_000_000_000,
                            )),
                            Err(_) => Box::new(crate::episode::capability::SystemClock),
                        }
                    } else {
                        Box::new(crate::episode::capability::SystemClock)
                    };

                let decision = v1_manifest.validate_request_scoped(&v1_request, clock.as_ref());
                if decision.is_denied() {
                    warn!(
                        session_id = %token.session_id,
                        tool_class = ?tool_class,
                        "RequestTool denied by V1 scope enforcement"
                    );
                    return Ok(SessionResponse::error(
                        SessionErrorCode::SessionErrorToolNotAllowed,
                        format!("V1 scope enforcement denied: {decision:?}"),
                    ));
                }

                // TCK-00352: Verify envelope-manifest hash binding.
                // Look up the session's envelope manifest hash and verify it
                // matches the V1 manifest digest.
                if let Some(ref registry) = self.session_registry {
                    if let Some(session_state) = registry.get_session(&token.session_id) {
                        if !session_state.capability_manifest_hash.is_empty() {
                            if let Err(e) = v1_manifest
                                .verify_envelope_binding(&session_state.capability_manifest_hash)
                            {
                                warn!(
                                    session_id = %token.session_id,
                                    error = %e,
                                    "RequestTool denied: envelope-manifest hash mismatch"
                                );
                                return Ok(SessionResponse::error(
                                    SessionErrorCode::SessionErrorToolNotAllowed,
                                    format!("envelope-manifest binding failed: {e}"),
                                ));
                            }
                        }
                    }
                }
            }
        }

        // TCK-00423/TCK-00426: Stage 1 and Stage 2 of PCAC lifecycle.
        // join -> revalidate-before-decision
        //
        // Stage 3 and Stage 4 (revalidate-before-execution + consume) run in
        // `handle_broker_decision` immediately before effect execution.
        let pending_pcac = if let Some(ref pcac_gate) = self.pcac_lifecycle_gate {
            // BLOCKER 2 FIX: All required authoritative dependencies must be
            // available before building the join input.
            let Some(clock) = self.clock.as_ref() else {
                warn!(
                    session_id = %token.session_id,
                    "PCAC denied: clock unavailable (fail-closed)"
                );
                return Ok(SessionResponse::error(
                    SessionErrorCode::SessionErrorToolNotAllowed,
                    "PCAC authority denied: clock unavailable (fail-closed)",
                ));
            };
            let Some(session_registry) = self.session_registry.as_ref() else {
                warn!(
                    session_id = %token.session_id,
                    "PCAC denied: session registry unavailable (fail-closed)"
                );
                return Ok(SessionResponse::error(
                    SessionErrorCode::SessionErrorToolNotAllowed,
                    "PCAC authority denied: session registry unavailable (fail-closed)",
                ));
            };
            let Some(stop_authority) = self.stop_authority.as_ref() else {
                warn!(
                    session_id = %token.session_id,
                    "PCAC denied: stop authority unavailable (fail-closed)"
                );
                return Ok(SessionResponse::error(
                    SessionErrorCode::SessionErrorToolNotAllowed,
                    "PCAC authority denied: stop authority unavailable (fail-closed)",
                ));
            };
            let Some(ledger) = self.ledger.as_ref() else {
                warn!(
                    session_id = %token.session_id,
                    "PCAC denied: ledger unavailable (fail-closed)"
                );
                return Ok(SessionResponse::error(
                    SessionErrorCode::SessionErrorToolNotAllowed,
                    "PCAC authority denied: ledger unavailable (fail-closed)",
                ));
            };

            let hlc = match clock.now_hlc() {
                Ok(value) => value,
                Err(error) => {
                    warn!(
                        session_id = %token.session_id,
                        error = %error,
                        "PCAC denied: clock read failed (fail-closed)"
                    );
                    return Ok(SessionResponse::error(
                        SessionErrorCode::SessionErrorToolNotAllowed,
                        format!("PCAC authority denied: clock read failed: {error}"),
                    ));
                },
            };

            let Some(session_state) = session_registry.get_session(&token.session_id) else {
                warn!(
                    session_id = %token.session_id,
                    "PCAC denied: session state unavailable (fail-closed)"
                );
                return Ok(SessionResponse::error(
                    SessionErrorCode::SessionErrorToolNotAllowed,
                    "PCAC authority denied: session state unavailable (fail-closed)",
                ));
            };
            if session_state.policy_resolved_ref.is_empty() {
                warn!(
                    session_id = %token.session_id,
                    "PCAC denied: revocation provider unavailable (empty policy_resolved_ref)"
                );
                return Ok(SessionResponse::error(
                    SessionErrorCode::SessionErrorToolNotAllowed,
                    "PCAC authority denied: revocation provider unavailable (fail-closed)",
                ));
            }

            let capability_manifest_hash: Hash =
                if let Ok(hash) = session_state.capability_manifest_hash.as_slice().try_into() {
                    hash
                } else {
                    warn!(
                        session_id = %token.session_id,
                        hash_len = session_state.capability_manifest_hash.len(),
                        "PCAC denied: capability_manifest_hash missing or malformed"
                    );
                    return Ok(SessionResponse::error(
                        SessionErrorCode::SessionErrorToolNotAllowed,
                        "PCAC authority denied: malformed capability manifest hash (fail-closed)",
                    ));
                };

            let Some(risk_tier) =
                self.derive_pcac_risk_tier_from_policy(&token.session_id, tool_class)
            else {
                warn!(
                    session_id = %token.session_id,
                    tool_class = %tool_class,
                    "PCAC denied: risk tier missing from validated capability policy"
                );
                return Ok(SessionResponse::error(
                    SessionErrorCode::SessionErrorToolNotAllowed,
                    "PCAC authority denied: risk tier missing from capability policy (fail-closed)",
                ));
            };

            let directory_head_hash =
                *blake3::hash(session_state.policy_resolved_ref.as_bytes()).as_bytes();
            let freshness_policy_hash = {
                let mut hasher = blake3::Hasher::new();
                hasher.update(b"pcac-freshness-policy-v1");
                hasher.update(session_state.policy_resolved_ref.as_bytes());
                *hasher.finalize().as_bytes()
            };
            let freshness_witness_tick = hlc.wall_ns / 1_000_000_000;
            if freshness_witness_tick == 0 {
                warn!(
                    session_id = %token.session_id,
                    "PCAC denied: freshness witness tick is zero"
                );
                return Ok(SessionResponse::error(
                    SessionErrorCode::SessionErrorToolNotAllowed,
                    "PCAC authority denied: freshness witness tick is zero (fail-closed)",
                ));
            }

            let pre_actuation_receipt_hashes = preactuation_receipt
                .as_ref()
                .map(Self::hash_preactuation_receipt)
                .into_iter()
                .collect::<Vec<_>>();
            let stop_budget_profile_digest = {
                let mut hasher = blake3::Hasher::new();
                hasher.update(b"pcac-stop-budget-profile-v1");
                hasher.update(&[u8::from(stop_authority.emergency_stop_active())]);
                hasher.update(&[u8::from(stop_authority.governance_stop_active())]);
                let tool_class_name = tool_class.to_string();
                hasher.update(tool_class_name.as_bytes());
                for receipt_hash in &pre_actuation_receipt_hashes {
                    hasher.update(receipt_hash);
                }
                *hasher.finalize().as_bytes()
            };

            let intent_digest = *blake3::hash(&request.arguments).as_bytes();
            let time_envelope_ref = *blake3::hash(&hlc.wall_ns.to_le_bytes()).as_bytes();
            let as_of_ledger_anchor = Self::derive_pcac_ledger_anchor(ledger.as_ref());
            let determinism_class = match tool_class {
                ToolClass::Read | ToolClass::ListFiles => {
                    apm2_core::pcac::DeterminismClass::Deterministic
                },
                _ => apm2_core::pcac::DeterminismClass::BoundedNondeterministic,
            };

            let pcac_input = apm2_core::pcac::AuthorityJoinInputV1 {
                session_id: token.session_id.clone(),
                holon_id: None,
                intent_digest,
                capability_manifest_hash,
                scope_witness_hashes: Self::derive_scope_witness_hashes(
                    tool_class,
                    &request.arguments,
                ),
                lease_id: token.lease_id.clone(),
                permeability_receipt_hash: None,
                identity_proof_hash: *blake3::hash(token.session_id.as_bytes()).as_bytes(),
                identity_evidence_level: apm2_core::pcac::IdentityEvidenceLevel::Verified,
                directory_head_hash,
                freshness_policy_hash,
                freshness_witness_tick,
                stop_budget_profile_digest,
                pre_actuation_receipt_hashes,
                risk_tier,
                determinism_class,
                time_envelope_ref,
                as_of_ledger_anchor,
            };

            let (current_time_envelope_ref, current_ledger_anchor, current_revocation_head) =
                match self.derive_fresh_pcac_revalidation_inputs(&token.session_id) {
                    Ok(values) => values,
                    Err(error) => {
                        warn!(
                            session_id = %token.session_id,
                            error = %error,
                            "PCAC denied: authoritative revalidation inputs unavailable"
                        );
                        return Ok(SessionResponse::error(
                            SessionErrorCode::SessionErrorToolNotAllowed,
                            format!(
                                "PCAC authority denied: authoritative revalidation unavailable: {error}"
                            ),
                        ));
                    },
                };

            let certificate = match pcac_gate.join_and_revalidate(
                &pcac_input,
                current_time_envelope_ref,
                current_ledger_anchor,
                current_revocation_head,
            ) {
                Ok(cert) => cert,
                Err(deny) => {
                    warn!(
                        session_id = %token.session_id,
                        deny_class = %deny.deny_class,
                        "RequestTool denied by PCAC join/revalidate lifecycle gate"
                    );
                    return Ok(SessionResponse::error(
                        SessionErrorCode::SessionErrorToolNotAllowed,
                        format!("PCAC authority denied: {}", deny.deny_class),
                    ));
                },
            };

            Some(PendingPcacAuthority {
                gate: Arc::clone(pcac_gate),
                certificate,
                intent_digest,
            })
        } else if self.is_authoritative_mode() {
            // BLOCKER 4 FIX: Authoritative mode requires mandatory PCAC gate wiring.
            warn!(
                session_id = %token.session_id,
                "RequestTool denied: PCAC authority gate not wired in authoritative mode (fail-closed)"
            );
            return Ok(SessionResponse::error(
                SessionErrorCode::SessionErrorToolNotAllowed,
                "PCAC authority gate not wired in authoritative mode (fail-closed)",
            ));
        } else {
            None
        };

        // TCK-00290: Use ToolBroker for request validation and execution
        // Per DOD: "RequestTool executes via ToolBroker and returns ToolResult or Deny"
        let Some(broker) = broker else {
            warn!(
                session_id = %token.session_id,
                "RequestTool denied: tool broker unavailable (fail-closed)"
            );
            return Ok(SessionResponse::error(
                SessionErrorCode::SessionErrorToolNotAllowed,
                "tool broker unavailable (fail-closed)",
            ));
        };

        // TCK-00290 BLOCKER 3: Get monotonic timestamp from HolonicClock
        let actuation_timestamp = self.get_htf_timestamp()?;
        let timestamp_ns = actuation_timestamp.wall_ns;

        // Build BrokerToolRequest
        let request_id = format!("REQ-{}", uuid::Uuid::new_v4());

        // BLOCKER 1 FIX (TCK-00290): Fail-closed if session ID is not valid for
        // EpisodeId. Per SEC-CTRL-FAC-0015, we must not use a hardcoded
        // fallback that could cause cross-session ID collision. Return
        // SESSION_ERROR_INVALID instead.
        let episode_id = match EpisodeId::new(&token.session_id) {
            Ok(id) => id,
            Err(e) => {
                error!(
                    session_id = %token.session_id,
                    error = %e,
                    "Session ID not valid for EpisodeId (fail-closed)"
                );
                return Ok(SessionResponse::error(
                    SessionErrorCode::SessionErrorInvalid,
                    format!("session ID not valid for episode: {e}"),
                ));
            },
        };

        let dedupe_key = DedupeKey::new(&request.dedupe_key);
        let args_hash = *blake3::hash(&request.arguments).as_bytes();

        // Derive risk tier from validated capability policy (fail-closed).
        let Some(risk_tier) = self
            .manifest_store
            .as_ref()
            .and_then(|store| store.get_manifest(&token.session_id))
            .and_then(|manifest| {
                manifest
                    .find_by_tool_class(tool_class)
                    .next()
                    .map(|cap| cap.risk_tier_required)
            })
        else {
            warn!(
                session_id = %token.session_id,
                tool_class = %tool_class,
                "RequestTool denied: missing risk tier in capability policy (fail-closed)"
            );
            return Ok(SessionResponse::error(
                SessionErrorCode::SessionErrorToolNotAllowed,
                "capability policy missing risk tier for tool class (fail-closed)",
            ));
        };

        // Clone arguments for execution before they are moved into BrokerToolRequest
        let request_arguments = request.arguments.clone();

        let mut broker_request = BrokerToolRequest::new(
            &request_id,
            episode_id.clone(),
            tool_class,
            dedupe_key,
            args_hash,
            risk_tier,
        )
        .with_inline_args(request.arguments);

        if let Ok(args_value) = serde_json::from_slice::<serde_json::Value>(&request_arguments) {
            match tool_class {
                ToolClass::Read | ToolClass::Write | ToolClass::ListFiles => {
                    if let Some(path) = args_value.get("path").and_then(serde_json::Value::as_str) {
                        broker_request = broker_request.with_path(path);
                    }
                },
                ToolClass::Search => {
                    if let Some(scope) = args_value.get("scope").and_then(serde_json::Value::as_str)
                    {
                        broker_request = broker_request.with_path(scope);
                    }
                    if let Some(query) = args_value.get("query").and_then(serde_json::Value::as_str)
                    {
                        broker_request = broker_request.with_query(query);
                    }
                },
                ToolClass::Execute => {
                    if let Some(command) = args_value
                        .get("command")
                        .and_then(serde_json::Value::as_str)
                    {
                        broker_request = broker_request.with_shell_command(command);
                    }
                },
                ToolClass::Network => {
                    if let Some(url_value) =
                        args_value.get("url").and_then(serde_json::Value::as_str)
                    {
                        if let Ok(parsed) = url::Url::parse(url_value) {
                            if let Some(host) = parsed.host_str() {
                                let port = parsed.port_or_known_default().unwrap_or(0);
                                broker_request = broker_request.with_network(host, port);
                            }
                        }
                    }
                },
                ToolClass::Git => {
                    if let Some(operation) = args_value
                        .get("operation")
                        .and_then(serde_json::Value::as_str)
                    {
                        broker_request = broker_request.with_git_operation(operation);
                    }
                },
                _ => {},
            }

            if let Some(limit) = args_value.get("limit").and_then(serde_json::Value::as_u64) {
                broker_request = broker_request.with_size(limit);
            }
            if let Some(pattern) = args_value
                .get("pattern")
                .and_then(serde_json::Value::as_str)
            {
                broker_request = broker_request.with_pattern(pattern);
            }

            // TCK-00377: Populate tool_kind from parsed arguments so broker
            // precondition checks can execute. Build the proto-level
            // tool_request::Tool variant, then convert to typed ToolKind.
            let proto_tool: Option<tool_req::Tool> = match tool_class {
                ToolClass::Read => {
                    let path = args_value
                        .get("path")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or_default()
                        .to_string();
                    let offset = args_value
                        .get("offset")
                        .and_then(serde_json::Value::as_u64)
                        .unwrap_or(0);
                    let limit = args_value
                        .get("limit")
                        .and_then(serde_json::Value::as_u64)
                        .unwrap_or(0);
                    Some(tool_req::Tool::FileRead(tool::FileRead {
                        path,
                        offset,
                        limit,
                    }))
                },
                ToolClass::Write => {
                    let path = args_value
                        .get("path")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or_default()
                        .to_string();
                    // Distinguish FileEdit from FileWrite by checking for
                    // old_content/new_content fields (edit) vs content (write).
                    let is_edit = args_value.get("old_content").is_some()
                        && args_value.get("new_content").is_some();
                    if path.is_empty() {
                        None
                    } else if is_edit {
                        let old_content = args_value
                            .get("old_content")
                            .and_then(serde_json::Value::as_str)
                            .unwrap_or_default()
                            .to_string();
                        let new_content = args_value
                            .get("new_content")
                            .and_then(serde_json::Value::as_str)
                            .unwrap_or_default()
                            .to_string();
                        Some(tool_req::Tool::FileEdit(tool::FileEdit {
                            path,
                            old_content,
                            new_content,
                        }))
                    } else {
                        let content = args_value
                            .get("content")
                            .and_then(serde_json::Value::as_str)
                            .unwrap_or_default()
                            .as_bytes()
                            .to_vec();
                        let create_only = args_value
                            .get("create_only")
                            .and_then(serde_json::Value::as_bool)
                            .unwrap_or(false);
                        let append = args_value
                            .get("append")
                            .and_then(serde_json::Value::as_bool)
                            .unwrap_or(false);
                        Some(tool_req::Tool::FileWrite(tool::FileWrite {
                            path,
                            content,
                            create_only,
                            append,
                        }))
                    }
                },
                ToolClass::Execute => {
                    let command = args_value
                        .get("command")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or_default()
                        .to_string();
                    let cwd = args_value
                        .get("cwd")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or_default()
                        .to_string();
                    let timeout_ms = args_value
                        .get("timeout_ms")
                        .and_then(serde_json::Value::as_u64)
                        .unwrap_or(0);
                    let network_access = args_value
                        .get("network_access")
                        .and_then(serde_json::Value::as_bool)
                        .unwrap_or(false);
                    Some(tool_req::Tool::ShellExec(tool::ShellExec {
                        command,
                        cwd,
                        timeout_ms,
                        network_access,
                        env: Vec::new(),
                    }))
                },
                ToolClass::Git => {
                    let operation = args_value
                        .get("operation")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or_default()
                        .to_string();
                    let args = args_value
                        .get("args")
                        .and_then(serde_json::Value::as_array)
                        .map(|arr| {
                            arr.iter()
                                .filter_map(serde_json::Value::as_str)
                                .map(String::from)
                                .collect()
                        })
                        .unwrap_or_default();
                    let cwd = args_value
                        .get("cwd")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or_default()
                        .to_string();
                    Some(tool_req::Tool::GitOp(tool::GitOperation {
                        operation,
                        args,
                        cwd,
                    }))
                },
                // Other tool classes (ListFiles, Search, Network, Inference,
                // Artifact) are not in scope for TCK-00377 typed ToolKind
                // hardening. tool_kind_from_proto returns MissingToolVariant
                // for them, so we skip construction entirely.
                _ => None,
            };
            if let Some(proto) = proto_tool {
                match tool::tool_kind_from_proto(&proto) {
                    Ok(tk) => {
                        broker_request = broker_request.with_tool_kind(tk);
                    },
                    Err(e) => {
                        // TCK-00377 BLOCKER FIX: Fail-closed on tool_kind
                        // conversion failure. If typed validation rejects the
                        // request (shell metachar, bad git ref, path traversal),
                        // the request MUST be denied — not forwarded without a
                        // typed ToolKind. Log-and-continue was fail-open.
                        warn!(
                            request_id = %request_id,
                            error = %e,
                            "TCK-00377: tool_kind_from_proto conversion failed (fail-closed)"
                        );
                        return Ok(SessionResponse::error(
                            SessionErrorCode::SessionErrorToolNotAllowed,
                            format!("typed tool validation failed: {e} ({request_id})"),
                        ));
                    },
                }
            }
        }

        // TCK-00365: Extract epoch seal from protocol message and attach to
        // broker request for Tier2+ admission verification.
        if let Some(seal_bytes) = &request.epoch_seal {
            match apm2_core::htf::EpochSealV1::from_canonical_bytes(seal_bytes) {
                Ok(seal) => {
                    broker_request = broker_request.with_epoch_seal(seal);
                },
                Err(e) => {
                    warn!(
                        session_id = %token.session_id,
                        error = %e,
                        "epoch seal deserialization failed (fail-closed)"
                    );
                    return Ok(SessionResponse::error(
                        SessionErrorCode::SessionErrorInvalid,
                        format!("epoch seal deserialization failed: {e}"),
                    ));
                },
            }
        }

        // Call broker.request() asynchronously using tokio runtime
        let broker_response = tokio::task::block_in_place(|| {
            let handle = tokio::runtime::Handle::current();
            handle.block_on(async {
                broker
                    .request_with_response(&broker_request, timestamp_ns, None)
                    .await
            })
        });
        let (decision, defects, verified_content, toctou_verification_required): (
            Result<ToolDecision, crate::episode::BrokerError>,
            Vec<FirewallViolationDefect>,
            Option<VerifiedToolContent>,
            bool,
        ) = match broker_response {
            Ok(BrokerResponse {
                decision,
                defects,
                verified_content,
                toctou_verification_required,
            }) => (
                Ok(decision),
                defects,
                Some(verified_content),
                toctou_verification_required,
            ),
            Err(err) => (Err(err), Vec::new(), None, false),
        };

        let decision =
            Self::enforce_mandatory_defect_termination(decision, &token.session_id, &defects);
        let decision_requires_termination = matches!(&decision, Ok(ToolDecision::Terminate { .. }));

        let mut response = self.handle_broker_decision(
            decision,
            &token.session_id,
            tool_class,
            &request_arguments,
            actuation_timestamp,
            &episode_id,
            preactuation_receipt.as_ref(),
            verified_content,
            toctou_verification_required,
            pending_pcac,
        );

        if !defects.is_empty() {
            let has_mandatory_termination_defect = defects
                .iter()
                .any(FirewallViolationDefect::requires_termination);

            for defect in &defects {
                info!(
                    session_id = %token.session_id,
                    violation_type = ?defect.violation_type,
                    risk_tier = defect.risk_tier,
                    rule_id = %defect.rule_id,
                    manifest_id = %defect.manifest_id,
                    path = %defect.path,
                    "firewall violation defect from broker response"
                );
            }

            if let Err(e) =
                self.emit_firewall_violation_defects(&token.session_id, &defects, timestamp_ns)
            {
                error!(
                    session_id = %token.session_id,
                    error = %e,
                    "authoritative firewall defect emission failed"
                );
                if has_mandatory_termination_defect {
                    if let Err(term_err) = self
                        .ensure_session_terminated(&token.session_id, "CONTEXT_FIREWALL_VIOLATION")
                    {
                        error!(
                            session_id = %token.session_id,
                            error = %term_err,
                            "mandatory firewall termination failed while handling defect emission error"
                        );
                    }
                }
                response = Ok(SessionResponse::error(
                    SessionErrorCode::SessionErrorInternal,
                    format!("firewall defect emission failed: {e}"),
                ));
            } else if has_mandatory_termination_defect && !decision_requires_termination {
                if let Err(e) =
                    self.ensure_session_terminated(&token.session_id, "CONTEXT_FIREWALL_VIOLATION")
                {
                    error!(
                        session_id = %token.session_id,
                        error = %e,
                        "mandatory firewall termination failed"
                    );
                    response = Ok(SessionResponse::error(
                        SessionErrorCode::SessionErrorInternal,
                        format!("mandatory firewall termination failed: {e}"),
                    ));
                } else {
                    response = Ok(SessionResponse::error(
                        SessionErrorCode::SessionErrorToolNotAllowed,
                        "session terminated: CONTEXT_FIREWALL_VIOLATION".to_string(),
                    ));
                }
            }
        }

        // TCK-00384: Increment tool_calls counter on successful dispatch.
        // We count Allow and DedupeCacheHit as successful tool calls.
        if let Ok(SessionResponse::RequestTool(ref resp)) = response {
            if resp.decision == i32::from(DecisionType::Allow) {
                if let Some(ref store) = self.telemetry_store {
                    if let Some(telemetry) = store.get(&token.session_id) {
                        telemetry.increment_tool_calls();
                    }
                }
            }
        }

        response
    }

    /// Handles the broker decision and converts it to a `SessionResponse`.
    ///
    /// # TCK-00351 MAJOR 1 FIX
    ///
    /// The `preactuation_receipt` parameter carries the gate receipt from
    /// the pre-actuation check. Its fields (`stop_checked`, `budget_checked`,
    /// `timestamp_ns`) are propagated into the `RequestToolResponse` instead
    /// of hardcoded `true` / later clock sample.
    ///
    /// Production replay ordering verification runs on `Allow` decisions before
    /// actuation output is accepted.
    #[allow(
        clippy::unnecessary_wraps,
        clippy::items_after_statements,
        clippy::too_many_arguments
    )]
    fn handle_broker_decision(
        &self,
        decision: Result<ToolDecision, crate::episode::BrokerError>,
        session_id: &str,
        tool_class: ToolClass,
        request_arguments: &[u8],
        actuation_timestamp: ReplayTimestamp,
        episode_id: &EpisodeId,
        preactuation_receipt: Option<&PreActuationReceipt>,
        mut verified_content: Option<VerifiedToolContent>,
        toctou_verification_required: bool,
        pending_pcac: Option<PendingPcacAuthority>,
    ) -> ProtocolResult<SessionResponse> {
        let timestamp_ns = actuation_timestamp.wall_ns;
        match decision {
            Ok(ToolDecision::Allow {
                request_id,
                rule_id,
                policy_hash,
                credential,
                ..
            }) => {
                info!(
                    session_id = %session_id,
                    tool_class = %tool_class,
                    request_id = %request_id,
                    "Tool request allowed by broker"
                );

                if let Err(violation) = Self::verify_preactuation_replay_ordering(
                    preactuation_receipt,
                    actuation_timestamp,
                    tool_class,
                    &request_id,
                ) {
                    error!(
                        session_id = %session_id,
                        tool_class = %tool_class,
                        request_id = %request_id,
                        violation = %violation,
                        "RequestTool denied: replay ordering verification failed (fail-closed)"
                    );
                    return Ok(SessionResponse::error(
                        SessionErrorCode::SessionErrorInternal,
                        format!("replay ordering verification failed: {violation}"),
                    ));
                }

                if let Some(pending_pcac) = pending_pcac {
                    // TCK-00426 BLOCKER 3 + QUALITY BLOCKER 2:
                    // revalidate and consume from fresh authoritative sources
                    // immediately before effect execution.
                    let (current_time_envelope_ref, current_ledger_anchor, current_revocation_head) =
                        match self.derive_fresh_pcac_revalidation_inputs(session_id) {
                            Ok(values) => values,
                            Err(error) => {
                                warn!(
                                    session_id = %session_id,
                                    request_id = %request_id,
                                    error = %error,
                                    "PCAC denied: authoritative revalidation unavailable before execution"
                                );
                                return Ok(SessionResponse::error(
                                    SessionErrorCode::SessionErrorToolNotAllowed,
                                    format!(
                                        "PCAC authority denied before execution: authoritative revalidation unavailable: {error}"
                                    ),
                                ));
                            },
                        };

                    if let Err(deny) = pending_pcac.gate.revalidate_before_execution(
                        &pending_pcac.certificate,
                        current_time_envelope_ref,
                        current_ledger_anchor,
                        current_revocation_head,
                    ) {
                        warn!(
                            session_id = %session_id,
                            request_id = %request_id,
                            deny_class = %deny.deny_class,
                            "RequestTool denied by PCAC revalidate-before-execution"
                        );
                        return Ok(SessionResponse::error(
                            SessionErrorCode::SessionErrorToolNotAllowed,
                            format!(
                                "PCAC authority denied before execution: {}",
                                deny.deny_class
                            ),
                        ));
                    }

                    let (consumed_witness, consume_record) = match pending_pcac
                        .gate
                        .consume_before_effect(
                            &pending_pcac.certificate,
                            pending_pcac.intent_digest,
                            current_time_envelope_ref,
                        ) {
                        Ok(receipts) => receipts,
                        Err(deny) => {
                            warn!(
                                session_id = %session_id,
                                request_id = %request_id,
                                deny_class = %deny.deny_class,
                                "RequestTool denied by PCAC consume-before-effect"
                            );
                            return Ok(SessionResponse::error(
                                SessionErrorCode::SessionErrorToolNotAllowed,
                                format!("PCAC authority denied before effect: {}", deny.deny_class),
                            ));
                        },
                    };

                    // QUALITY MAJOR 1: Keep receipts on the authoritative
                    // effect path by logging certificate and consume evidence.
                    let consume_record_hash = {
                        let mut hasher = blake3::Hasher::new();
                        hasher.update(&consume_record.ajc_id);
                        hasher.update(&consume_record.consumed_time_envelope_ref);
                        hasher.update(&consume_record.consumed_at_tick.to_le_bytes());
                        hasher.update(&consume_record.effect_selector_digest);
                        hex::encode(hasher.finalize().as_bytes())
                    };
                    info!(
                        session_id = %session_id,
                        request_id = %request_id,
                        ajc_id = %hex::encode(pending_pcac.certificate.ajc_id),
                        consumed_tick = consumed_witness.consumed_at_tick,
                        consume_record_hash = %consume_record_hash,
                        "PCAC consume completed immediately before effect execution"
                    );
                }

                // TCK-00316: Execute tool via EpisodeRuntime
                let (result_hash, inline_result) = if let Some(ref runtime) = self.episode_runtime {
                    // Deserialize arguments
                    let tool_args: crate::episode::tool_handler::ToolArgs =
                        match serde_json::from_slice(request_arguments) {
                            Ok(args) => args,
                            Err(e) => {
                                return Ok(SessionResponse::error(
                                    SessionErrorCode::SessionErrorInvalid,
                                    format!("invalid tool arguments: {e}"),
                                ));
                            },
                        };

                    // Execute tool
                    // We use the timestamp from the start of the request for consistency.
                    //
                    // KNOWN ISSUE (MAJOR): This uses block_in_place + block_on to call
                    // async tool execution from a sync dispatch context. Under high load
                    // with slow tools (git clone, large file reads), this can lead to
                    // worker thread starvation.
                    //
                    // TODO(TCK-ASYNC-DISPATCH): Refactor SessionDispatcher::dispatch to be
                    // async, allowing direct .await on tool execution. This requires:
                    // 1. Make dispatch() async
                    // 2. Update all callers (main.rs connection handler)
                    // 3. Remove block_in_place wrapper
                    //
                    // For now, max_concurrent_episodes (100) provides backpressure to
                    // limit the impact on the worker pool.
                    let verified_for_execution = verified_content.take();
                    let toctou_required_for_execution = toctou_verification_required;
                    let request_id_for_execution = request_id.clone();
                    let execution_result = tokio::task::block_in_place(move || {
                        let handle = tokio::runtime::Handle::current();
                        handle.block_on(async move {
                            runtime
                                .execute_tool_with_verified_content(
                                    episode_id,
                                    &tool_args,
                                    credential.as_ref(),
                                    timestamp_ns,
                                    &request_id_for_execution,
                                    verified_for_execution,
                                    toctou_required_for_execution,
                                )
                                .await
                        })
                    });

                    let result = match execution_result {
                        Ok(res) => res,
                        Err(e) => {
                            error!(error = %e, "Tool execution failed");
                            // SEC-CTRL-FAC-0015 LOW FIX: Sanitize error messages
                            // to prevent information leakage via paths/env vars
                            return Ok(SessionResponse::error(
                                SessionErrorCode::SessionErrorInternal,
                                sanitize_error_message(&format!("tool execution failed: {e}")),
                            ));
                        },
                    };

                    if !result.success {
                        // SEC-CTRL-FAC-0015 LOW FIX: Sanitize error messages
                        let error_msg = result.error_message.as_deref().unwrap_or("unknown error");
                        return Ok(SessionResponse::error(
                            SessionErrorCode::SessionErrorInternal,
                            sanitize_error_message(error_msg),
                        ));
                    }

                    // SEC-CTRL-FAC-0015 BLOCKER FIX: Enforce MAX_INLINE_RESULT_SIZE
                    // for inline_result. If the output exceeds the limit, return only
                    // result_hash and force client to fetch via CAS. This prevents
                    // protocol-level DoS via oversized inline responses.
                    use crate::episode::decision::MAX_INLINE_RESULT_SIZE;
                    let inline_result = if result.output.len() <= MAX_INLINE_RESULT_SIZE {
                        Some(result.output)
                    } else {
                        // Output exceeds inline limit; must be fetched from CAS
                        None
                    };

                    (result.output_hash.map(|h| h.to_vec()), inline_result)
                } else {
                    // SEC-CTRL-FAC-0015 MAJOR FIX: Fail-closed when EpisodeRuntime
                    // is not configured. Returning Allow without execution would
                    // bypass integrity controls and create inconsistent state.
                    error!("EpisodeRuntime not configured; denying execution (fail-closed)");
                    return Ok(SessionResponse::error(
                        SessionErrorCode::SessionErrorInternal,
                        "tool execution unavailable: runtime not configured".to_string(),
                    ));
                };

                // TCK-00351 MAJOR 1 FIX: Populate proof fields from the
                // gate receipt, not from hardcoded values or a later
                // clock sample.  The receipt's timestamp proves the
                // ordering invariant (check preceded actuation).
                // No gate configured: fields remain false/0 so the replay
                // verifier treats this as a violation.
                let (stop_checked, budget_checked, budget_enforcement_deferred, preactuation_ts) =
                    preactuation_receipt.map_or((false, false, false, 0), |r| {
                        (
                            r.stop_checked,
                            r.budget_checked,
                            r.budget_enforcement_deferred,
                            r.timestamp_ns,
                        )
                    });
                Ok(SessionResponse::RequestTool(RequestToolResponse {
                    request_id,
                    decision: DecisionType::Allow.into(),
                    rule_id,
                    policy_hash: policy_hash.to_vec(),
                    result_hash,
                    inline_result,
                    stop_checked,
                    budget_checked,
                    budget_enforcement_deferred,
                    preactuation_timestamp_ns: preactuation_ts,
                }))
            },
            Ok(ToolDecision::Deny {
                request_id,
                reason,
                rule_id,
                policy_hash,
            }) => {
                warn!(
                    session_id = %session_id,
                    tool_class = %tool_class,
                    reason = %reason,
                    "Tool request denied by broker"
                );
                // TCK-00351 MAJOR 1 FIX: Derive proof fields from receipt.
                let (stop_checked, budget_checked, budget_enforcement_deferred, preactuation_ts) =
                    preactuation_receipt.map_or((false, false, false, 0), |r| {
                        (
                            r.stop_checked,
                            r.budget_checked,
                            r.budget_enforcement_deferred,
                            r.timestamp_ns,
                        )
                    });
                Ok(SessionResponse::RequestTool(RequestToolResponse {
                    request_id,
                    decision: DecisionType::Deny.into(),
                    rule_id,
                    policy_hash: policy_hash.to_vec(),
                    result_hash: None,
                    inline_result: None,
                    stop_checked,
                    budget_checked,
                    budget_enforcement_deferred,
                    preactuation_timestamp_ns: preactuation_ts,
                }))
            },
            Ok(ToolDecision::DedupeCacheHit { request_id, result }) => {
                use crate::episode::decision::MAX_INLINE_RESULT_SIZE;

                info!(
                    session_id = %session_id,
                    tool_class = %tool_class,
                    "Tool request hit dedupe cache"
                );
                // TCK-00316 SECURITY MAJOR 1 FIX: Properly separate policy_hash from
                // result_hash. The previous code conflated output_hash with
                // policy_hash, which is a security metadata conflation bug.
                // Policy hash is the hash of the policy that authorized
                // the original request; result_hash is the hash of the tool execution output.
                //
                // For cache hits, we use an empty policy_hash since the cached result was
                // already authorized by the original policy evaluation. The result_hash
                // comes from the cached ToolResult's output_hash.
                //
                // TCK-00316 SECURITY MAJOR 2 FIX: Enforce MAX_INLINE_RESULT_SIZE for
                // inline_result. If the cached output exceeds the limit, return
                // only result_hash without inline data.

                let result_hash = result.output_hash.map(|h| h.to_vec());
                let inline_result = if result.output.len() <= MAX_INLINE_RESULT_SIZE {
                    Some(result.output.clone())
                } else {
                    // Output exceeds inline limit; must be fetched from CAS via result_hash
                    None
                };

                // TCK-00351 MAJOR 1 FIX: Derive proof fields from receipt.
                let (stop_checked, budget_checked, budget_enforcement_deferred, preactuation_ts) =
                    preactuation_receipt.map_or((false, false, false, 0), |r| {
                        (
                            r.stop_checked,
                            r.budget_checked,
                            r.budget_enforcement_deferred,
                            r.timestamp_ns,
                        )
                    });
                Ok(SessionResponse::RequestTool(RequestToolResponse {
                    request_id,
                    decision: DecisionType::Allow.into(),
                    rule_id: None,
                    // Empty policy_hash for cache hits - policy was evaluated on original request
                    policy_hash: Vec::new(),
                    result_hash,
                    inline_result,
                    stop_checked,
                    budget_checked,
                    budget_enforcement_deferred,
                    preactuation_timestamp_ns: preactuation_ts,
                }))
            },
            Ok(ToolDecision::Terminate {
                request_id,
                termination_info,
                refinement_event,
            }) => {
                error!(
                    session_id = %session_id,
                    tool_class = %tool_class,
                    reason = %termination_info.rationale_code,
                    "Tool request triggered session termination"
                );

                // MAJOR 2: Wire session end-of-life to mark_terminated()
                // so production sessions transition to TERMINATED state.
                // TCK-00385 MAJOR 1: Propagate mark_terminated errors (fail-closed).
                // Per session/mod.rs:159, persistence failures are fatal.
                if let Some(session_registry) = &self.session_registry {
                    // MINOR fix: Normalize info.session_id to the authoritative
                    // session_id.  The broker may populate this field with
                    // episode_id (since session context is unavailable at that
                    // layer), so we overwrite it here where the real session_id
                    // is known.
                    let mut info = *termination_info.clone();
                    info.session_id = session_id.to_string();

                    if let Err(e) = session_registry.mark_terminated(session_id, info) {
                        error!(
                            session_id = %session_id,
                            error = %e,
                            "Failed to persist session termination state (fail-closed)"
                        );
                        // Fail-closed: return error immediately without continuing
                        return Ok(SessionResponse::error(
                            SessionErrorCode::SessionErrorInternal,
                            format!("session termination persistence failed: {e} ({request_id})"),
                        ));
                    }
                }

                // TCK-00351 BLOCKER-2: `episode_count` tracks completed
                // episodes. Increment on termination (not spawn) so a
                // newly spawned session starts at 0.
                if let Some(ref store) = self.telemetry_store {
                    if let Some(telemetry) = store.get(session_id) {
                        telemetry.increment_episode_count();
                    }
                }

                // TCK-00384: Clean up telemetry on session termination to
                // free capacity in the bounded store.
                if let Some(ref store) = self.telemetry_store {
                    store.remove(session_id);
                }

                // TCK-00351 BLOCKER 3 FIX: Clean up stop conditions on
                // session termination to free capacity in the bounded
                // store.  Same lifecycle as telemetry cleanup above.
                if let Some(ref store) = self.stop_conditions_store {
                    store.remove(session_id);
                }

                // Security BLOCKER 1 fix (TCK-00388): Trigger gate
                // orchestration after session termination.  This ensures the
                // gate lifecycle (PolicyResolved -> GateLeaseIssued -> receipt
                // path) fires on every real session termination, not just in
                // tests.
                if let (Some(orch), Some(registry)) =
                    (&self.gate_orchestrator, &self.session_registry)
                {
                    // Retrieve authoritative work_id from the session registry.
                    let work_id = registry
                        .get_session(session_id)
                        .map_or_else(|| session_id.to_string(), |s| s.work_id);

                    // Derive changeset_digest deterministically from session
                    // and work identifiers. The actual changeset hash would
                    // come from the workspace layer in the full pipeline; here
                    // we use a BLAKE3 binding so the digest is non-zero and
                    // unique per session+work pair.
                    let mut hasher = blake3::Hasher::new();
                    hasher.update(session_id.as_bytes());
                    hasher.update(work_id.as_bytes());
                    let changeset_digest: [u8; 32] = *hasher.finalize().as_bytes();

                    #[allow(clippy::cast_possible_truncation)]
                    let terminated_at_ms = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_millis() as u64)
                        .unwrap_or(0);

                    let gate_info = SessionTerminatedInfo {
                        session_id: session_id.to_string(),
                        work_id: work_id.clone(),
                        changeset_digest,
                        terminated_at_ms,
                    };

                    // The orchestrator's on_session_terminated is async; use
                    // block_in_place to call it from the sync dispatch path.
                    // This is safe because the session dispatcher runs on a
                    // Tokio worker thread.
                    let orch_result = tokio::task::block_in_place(|| {
                        tokio::runtime::Handle::current()
                            .block_on(orch.on_session_terminated(gate_info))
                    });

                    match orch_result {
                        Ok((_gate_types, _signers, events)) => {
                            // Persist gate orchestration events to ledger
                            // (fail-closed on persistence error).
                            if let Some(ref ledger) = self.ledger {
                                for event in &events {
                                    let event_type = match event {
                                        crate::gate::GateOrchestratorEvent::PolicyResolved {
                                            ..
                                        } => "gate.policy_resolved",
                                        crate::gate::GateOrchestratorEvent::GateLeaseIssued {
                                            ..
                                        } => "gate.lease_issued",
                                        _ => "gate.event",
                                    };
                                    let payload = serde_json::to_vec(event).unwrap_or_default();
                                    #[allow(clippy::cast_possible_truncation)]
                                    let ts = std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .map(|d| d.as_nanos() as u64)
                                        .unwrap_or(0);
                                    if let Err(e) = ledger.emit_session_event(
                                        session_id,
                                        event_type,
                                        &payload,
                                        "orchestrator:gate-lifecycle",
                                        ts,
                                    ) {
                                        error!(
                                            session_id = %session_id,
                                            event_type = %event_type,
                                            error = %e,
                                            "Failed to persist gate orchestration event (fail-closed)"
                                        );
                                        return Ok(SessionResponse::error(
                                            SessionErrorCode::SessionErrorInternal,
                                            format!(
                                                "gate event persistence failed: {e} ({request_id})"
                                            ),
                                        ));
                                    }
                                }
                            }
                            info!(
                                session_id = %session_id,
                                work_id = %work_id,
                                event_count = events.len(),
                                "Gate orchestration triggered on session termination"
                            );
                        },
                        Err(e) => {
                            // Fail-closed: gate orchestration failure is fatal.
                            error!(
                                session_id = %session_id,
                                error = %e,
                                "Gate orchestration failed on session termination (fail-closed)"
                            );
                            return Ok(SessionResponse::error(
                                SessionErrorCode::SessionErrorInternal,
                                format!("gate orchestration failed: {e} ({request_id})"),
                            ));
                        },
                    }
                }

                // TCK-00307: Emit DefectRecorded for ContextMiss
                if termination_info.rationale_code == "CONTEXT_MISS" {
                    if let Some(event_bytes) = refinement_event {
                        if let Ok(req) =
                            serde_json::from_slice::<ContextRefinementRequest>(&event_bytes)
                        {
                            self.emit_context_miss_defect(session_id, &req.missed_path);
                        }
                    }
                }

                Ok(SessionResponse::error(
                    SessionErrorCode::SessionErrorToolNotAllowed,
                    format!(
                        "session terminated: {} ({})",
                        termination_info.rationale_code, request_id
                    ),
                ))
            },
            Err(crate::episode::BrokerError::PreconditionFailed { ref reason }) => {
                // TCK-00377 MAJOR FIX: Precondition failures are policy denials,
                // not internal faults. Map to SessionErrorToolNotAllowed so
                // callers receive deny semantics consistent with broker Deny
                // decisions.
                warn!(
                    session_id = %session_id,
                    tool_class = %tool_class,
                    reason = %reason,
                    "Broker precondition failed (deny)"
                );
                Ok(SessionResponse::error(
                    SessionErrorCode::SessionErrorToolNotAllowed,
                    format!("precondition failed: {reason}"),
                ))
            },
            Err(e) => {
                error!(
                    session_id = %session_id,
                    tool_class = %tool_class,
                    error = %e,
                    "Broker request failed"
                );
                Ok(SessionResponse::error(
                    SessionErrorCode::SessionErrorInternal,
                    format!("broker error: {e}"),
                ))
            },
        }
    }

    /// Builds a per-request replay trace and verifies pre-actuation ordering.
    ///
    /// This is the production call site for `ReplayVerifier::verify`.
    fn verify_preactuation_replay_ordering(
        preactuation_receipt: Option<&PreActuationReceipt>,
        actuation_timestamp: ReplayTimestamp,
        tool_class: ToolClass,
        request_id: &str,
    ) -> Result<(), crate::episode::preactuation::ReplayViolation> {
        let Some(receipt) = preactuation_receipt else {
            return Ok(());
        };

        let trace = [
            ReplayEntry {
                timestamp: receipt.replay_timestamp,
                kind: ReplayEntryKind::PreActuationCheck {
                    stop_checked: receipt.stop_checked,
                    budget_checked: receipt.budget_checked,
                    budget_enforcement_deferred: receipt.budget_enforcement_deferred,
                },
            },
            ReplayEntry {
                timestamp: actuation_timestamp,
                kind: ReplayEntryKind::ToolActuation {
                    tool_class: tool_class.to_string(),
                    request_id: request_id.to_string(),
                },
            },
        ];
        ReplayVerifier::verify(&trace)
    }

    /// Gets an HTF-compliant monotonic timestamp.
    ///
    /// # TCK-00290 MAJOR 2 FIX: Time Monotonicity
    ///
    /// Per RFC-0016 and SEC-CTRL-FAC-0015, timestamps must come from
    /// `HolonicClock` for monotonicity. Using `SystemTime::now()` as a
    /// fallback violates time monotonicity guarantees and creates a
    /// security vulnerability.
    ///
    /// # Errors
    ///
    /// Returns an error if the clock is not configured or fails (fail-closed).
    /// Per SEC-CTRL-FAC-0015, we must fail-closed when the clock is required
    /// rather than falling back to an insecure `SystemTime::now()`.
    #[allow(clippy::option_if_let_else, clippy::single_match_else)]
    fn get_htf_timestamp(&self) -> ProtocolResult<ReplayTimestamp> {
        // Using match here for clarity - the error paths have important security
        // comments that would be less readable with map_or_else or if let/else.
        match &self.clock {
            Some(clock) => clock
                .now_hlc()
                .map(|hlc| ReplayTimestamp::new(hlc.wall_ns, hlc.logical))
                .map_err(|e| {
                    if let ClockError::ClockRegression { current, previous } = e {
                        self.emit_htf_regression_defect(current, previous);
                    }
                    error!("HolonicClock failed: {}", e);
                    ProtocolError::Serialization {
                        reason: format!("clock failure: {e}"),
                    }
                }),
            None => {
                // MAJOR 2 FIX (TCK-00290): Fail-closed when clock is not configured.
                // Per SEC-CTRL-FAC-0015, we must not fall back to SystemTime::now()
                // as this violates time monotonicity guarantees.
                error!("HolonicClock not configured (fail-closed per SEC-CTRL-FAC-0015)");
                Err(ProtocolError::Serialization {
                    reason: "holonic clock not configured (fail-closed)".to_string(),
                })
            },
        }
    }

    /// Handles `EmitEvent` requests (IPC-SESS-002).
    ///
    /// # TCK-00290: Real Ledger Persistence
    ///
    /// Per TCK-00290, this handler persists events to the ledger. Events are
    /// signed and stored with HTF-compliant timestamps. The handler requires
    /// a ledger to be configured; without it, returns `SESSION_ERROR_INTERNAL`
    /// (fail-closed).
    ///
    /// # Security (INV-TCK-00290-002)
    ///
    /// Per SEC-CTRL-FAC-0015, the ledger must be configured for this handler
    /// to function. Returning stub responses without persistence would violate
    /// the HEF requirements for event durability.
    fn handle_emit_event(
        &self,
        payload: &[u8],
        ctx: &ConnectionContext,
    ) -> ProtocolResult<SessionResponse> {
        let request =
            EmitEventRequest::decode_bounded(payload, &self.decode_config).map_err(|e| {
                ProtocolError::Serialization {
                    reason: format!("invalid EmitEventRequest: {e}"),
                }
            })?;

        // INV-SESS-001: Validate session token
        let token = match self.validate_token(&request.session_token) {
            Ok(t) => t,
            Err(resp) => return Ok(resp),
        };

        // TCK-00395 Security BLOCKER 1: Enforce active-session check.
        // HMAC token validation alone is not sufficient because EndSession
        // revokes only session-registry state. A retained token could
        // continue writing events to the ledger after EndSession if we
        // don't verify the session still exists in the registry.
        if let Some(ref registry) = self.session_registry {
            if registry.get_session(&token.session_id).is_none() {
                warn!(
                    session_id = %token.session_id,
                    "EmitEvent rejected: session not found in registry (may have been terminated)"
                );
                return Ok(SessionResponse::session_invalid(
                    "session not found or already terminated",
                ));
            }
        }

        info!(
            session_id = %token.session_id,
            event_type = %request.event_type,
            correlation_id = %request.correlation_id,
            peer_pid = ?ctx.peer_credentials().map(|c| c.pid),
            "EmitEvent request received"
        );

        // Validate required fields
        if request.event_type.is_empty() {
            return Ok(SessionResponse::error(
                SessionErrorCode::SessionErrorInvalid,
                "event_type is required",
            ));
        }

        // TCK-00415 BLOCKER 2: Reject reserved work-domain event type names.
        //
        // Session EmitEvent must not allow event types that collide with
        // the work-domain namespace. Without this guard, a session could
        // inject `work_claimed` or `work_transitioned` events that would
        // be picked up by projection rebuild, causing namespace confusion.
        // Defense-in-depth: the projection also filters by payload
        // structure, but rejecting at admission is fail-closed.
        if request.event_type.starts_with("work_") || request.event_type.starts_with("work.") {
            return Ok(SessionResponse::error(
                SessionErrorCode::SessionErrorInvalid,
                "event_type uses reserved work-domain namespace prefix",
            ));
        }

        // INV-TCK-00290-002: Require ledger for event persistence (fail-closed)
        let Some(ref ledger) = self.ledger else {
            error!(
                session_id = %token.session_id,
                "EmitEvent denied: ledger not configured (fail-closed)"
            );
            return Ok(SessionResponse::error(
                SessionErrorCode::SessionErrorInternal,
                "ledger unavailable (fail-closed)",
            ));
        };

        // TCK-00290 BLOCKER 3: Get monotonic timestamp from HolonicClock
        let now_ns = self.get_htf_timestamp()?.wall_ns;

        // Increment sequence counter atomically
        let seq = self.event_seq.fetch_add(1, Ordering::SeqCst) + 1;

        // TCK-00290 BLOCKER 2: Use emit_session_event with proper parameters
        // - event_type: The actual event type from the request (not coerced)
        // - payload: The actual payload bytes from the request (not discarded)
        // - actor_id: The session ID (proper actor identification)
        match ledger.emit_session_event(
            &token.session_id,
            &request.event_type, // Actual event type
            &request.payload,    // Actual payload (not discarded)
            &token.session_id,   // Proper actor_id (session ID, not event_type)
            now_ns,
        ) {
            Ok(signed_event) => {
                // TCK-00384: Increment events_emitted counter on successful
                // ledger persistence.
                if let Some(ref store) = self.telemetry_store {
                    if let Some(telemetry) = store.get(&token.session_id) {
                        telemetry.increment_events_emitted();
                    }
                }

                info!(
                    session_id = %token.session_id,
                    event_id = %signed_event.event_id,
                    seq = seq,
                    "EmitEvent persisted to ledger"
                );
                Ok(SessionResponse::EmitEvent(EmitEventResponse {
                    event_id: signed_event.event_id,
                    seq,
                    timestamp_ns: signed_event.timestamp_ns,
                }))
            },
            Err(e) => {
                error!(
                    session_id = %token.session_id,
                    error = %e,
                    "EmitEvent failed to persist"
                );
                Ok(SessionResponse::error(
                    SessionErrorCode::SessionErrorInternal,
                    format!("ledger persistence failed: {e}"),
                ))
            },
        }
    }

    /// Handles `PublishEvidence` requests (IPC-SESS-003).
    ///
    /// # TCK-00290: Real CAS Storage
    ///
    /// Per TCK-00290, this handler stores evidence artifacts in the durable
    /// content-addressed store. Artifacts are stored with BLAKE3 content
    /// addressing and verified on retrieval. The handler requires a CAS to be
    /// configured; without it, returns `SESSION_ERROR_INTERNAL` (fail-closed).
    ///
    /// # Security (INV-TCK-00290-003)
    ///
    /// Per SEC-CTRL-FAC-0015 and RFC-0018 HEF requirements, the CAS must be
    /// configured for this handler to function. Returning stub responses
    /// without persistence would violate evidence durability requirements.
    fn handle_publish_evidence(
        &self,
        payload: &[u8],
        ctx: &ConnectionContext,
    ) -> ProtocolResult<SessionResponse> {
        // Default TTL: 24 hours for standard evidence, configurable in future
        // Per RFC-0018, retention is determined by evidence kind and policy
        const STANDARD_TTL: u64 = 86400; // 24 hours
        const EXTENDED_TTL: u64 = 604_800; // 7 days
        const AUDIT_TTL: u64 = 2_592_000; // 30 days

        let request = PublishEvidenceRequest::decode_bounded(payload, &self.decode_config)
            .map_err(|e| ProtocolError::Serialization {
                reason: format!("invalid PublishEvidenceRequest: {e}"),
            })?;

        // INV-SESS-001: Validate session token
        let token = match self.validate_token(&request.session_token) {
            Ok(t) => t,
            Err(resp) => return Ok(resp),
        };

        // TCK-00395 Security BLOCKER 1: Enforce active-session check.
        // HMAC token validation alone is not sufficient because EndSession
        // revokes only session-registry state. A retained token could
        // continue writing artifacts to CAS after EndSession if we
        // don't verify the session still exists in the registry.
        if let Some(ref registry) = self.session_registry {
            if registry.get_session(&token.session_id).is_none() {
                warn!(
                    session_id = %token.session_id,
                    "PublishEvidence rejected: session not found in registry (may have been terminated)"
                );
                return Ok(SessionResponse::session_invalid(
                    "session not found or already terminated",
                ));
            }
        }

        info!(
            session_id = %token.session_id,
            artifact_size = request.artifact.len(),
            kind = ?request.kind,
            peer_pid = ?ctx.peer_credentials().map(|c| c.pid),
            "PublishEvidence request received"
        );

        // Validate artifact is not empty
        if request.artifact.is_empty() {
            return Ok(SessionResponse::error(
                SessionErrorCode::SessionErrorInvalid,
                "artifact is required",
            ));
        }

        // INV-TCK-00290-003: Require CAS for artifact storage (fail-closed)
        let Some(ref cas) = self.cas else {
            error!(
                session_id = %token.session_id,
                "PublishEvidence denied: CAS not configured (fail-closed)"
            );
            return Ok(SessionResponse::error(
                SessionErrorCode::SessionErrorInternal,
                "CAS unavailable (fail-closed)",
            ));
        };

        // Store artifact in CAS
        let hash = cas.store(&request.artifact);

        // Build storage path using hash prefix sharding (consistent with DurableCas)
        let hex_hash = hex::encode(hash);
        let storage_path = format!("evidence/{}/{}", &hex_hash[..4], &hex_hash[4..]);

        info!(
            session_id = %token.session_id,
            artifact_hash = %hex_hash,
            storage_path = %storage_path,
            "PublishEvidence stored in CAS"
        );

        let ttl_secs = match request.retention_hint {
            1 => EXTENDED_TTL,
            2 => AUDIT_TTL,
            _ => STANDARD_TTL,
        };

        Ok(SessionResponse::PublishEvidence(PublishEvidenceResponse {
            artifact_hash: hash.to_vec(),
            storage_path,
            ttl_secs,
        }))
    }

    /// Handles `StreamTelemetry` requests (IPC-SESS-004).
    ///
    /// # TCK-00290: Fail-Closed (Not Implemented)
    ///
    /// Per TCK-00290 and SEC-CTRL-FAC-0015, `StreamTelemetry` is explicitly
    /// disabled until a proper implementation is available. This handler
    /// returns `SESSION_ERROR_NOT_IMPLEMENTED` for all requests.
    ///
    /// # Security (INV-TCK-00290-004)
    ///
    /// Per the fail-closed security posture, returning stub responses for
    /// unimplemented functionality would violate security invariants. Instead,
    /// we explicitly reject requests with a clear error code.
    ///
    /// # Future Work
    ///
    /// This handler will be implemented to support:
    /// - Real-time telemetry streaming to observability backend
    /// - HEF pulse subscription handling
    /// - Metric promotion to persistent storage
    fn handle_stream_telemetry(
        &self,
        payload: &[u8],
        ctx: &ConnectionContext,
    ) -> ProtocolResult<SessionResponse> {
        let request = StreamTelemetryRequest::decode_bounded(payload, &self.decode_config)
            .map_err(|e| ProtocolError::Serialization {
                reason: format!("invalid StreamTelemetryRequest: {e}"),
            })?;

        // INV-SESS-001: Validate session token
        let token = match self.validate_token(&request.session_token) {
            Ok(t) => t,
            Err(resp) => return Ok(resp),
        };

        let frame = request.frame.as_ref();
        warn!(
            session_id = %token.session_id,
            frame_seq = ?frame.map(|f| f.seq),
            peer_pid = ?ctx.peer_credentials().map(|c| c.pid),
            "StreamTelemetry request rejected: not implemented (fail-closed)"
        );

        // INV-TCK-00290-004: StreamTelemetry disabled until implemented (fail-closed)
        // Per SEC-CTRL-FAC-0015, we do not return stub responses for unimplemented
        // functionality. Instead, we return a clear NOT_IMPLEMENTED error.
        Ok(SessionResponse::error(
            SessionErrorCode::SessionErrorNotImplemented,
            "StreamTelemetry not implemented (fail-closed)",
        ))
    }

    /// Handles `SessionStatus` requests (IPC-SESS-005, TCK-00344,
    /// TCK-00385).
    ///
    /// Queries session-scoped status including state, telemetry summary,
    /// and termination details (when applicable).
    ///
    /// # TCK-00385: Termination Signal
    ///
    /// When a session has been terminated, this handler returns
    /// `state = "TERMINATED"` with `termination_reason`, `exit_code`,
    /// `terminated_at_ns`, and `actual_tokens_consumed` fields populated
    /// from the preserved termination info. Terminated entries are kept
    /// for a TTL window after termination.
    ///
    /// # Security
    ///
    /// Per INV-SESS-001: Session token is validated before returning status.
    /// Only the session identified by the token can query its own status.
    fn handle_session_status(
        &self,
        payload: &[u8],
        ctx: &ConnectionContext,
    ) -> ProtocolResult<SessionResponse> {
        let request =
            SessionStatusRequest::decode_bounded(payload, &self.decode_config).map_err(|e| {
                ProtocolError::Serialization {
                    reason: format!("invalid SessionStatusRequest: {e}"),
                }
            })?;

        // INV-SESS-001: Validate session token
        let token = match self.validate_token(&request.session_token) {
            Ok(t) => t,
            Err(resp) => return Ok(resp),
        };

        debug!(
            session_id = %token.session_id,
            peer_pid = ?ctx.peer_credentials().map(|c| c.pid),
            "SessionStatus request received"
        );

        // TCK-00384: Look up telemetry counters for this session
        let telemetry = self
            .telemetry_store
            .as_ref()
            .and_then(|store| store.snapshot(&token.session_id));

        // Query session registry for session state
        if let Some(session_registry) = &self.session_registry {
            // First check for active session
            if let Some(session) = session_registry.get_session(&token.session_id) {
                // TCK-00384: Read duration_ms from the snapshot's monotonic
                // Instant-based field. Wall-clock SystemTime is no longer
                // used for elapsed time computation (security review fix:
                // immune to clock jumps/skew).
                let (tool_calls, events_emitted, started_at_ns, duration_ms) =
                    telemetry.as_ref().map_or((0u32, 0u32, 0u64, 0u64), |snap| {
                        // Proto fields for tool_calls/events_emitted are u32;
                        // saturate at u32::MAX to avoid truncation panics.
                        let tc = u32::try_from(snap.tool_calls).unwrap_or(u32::MAX);
                        let ee = u32::try_from(snap.events_emitted).unwrap_or(u32::MAX);
                        (tc, ee, snap.started_at_ns, snap.duration_ms)
                    });

                let response = SessionStatusResponse {
                    session_id: token.session_id.clone(),
                    state: "ACTIVE".to_string(),
                    work_id: session.work_id,
                    role: session.role,
                    episode_id: session.episode_id,
                    tool_calls,
                    events_emitted,
                    started_at_ns,
                    duration_ms,
                    // TCK-00385: No termination info for active sessions
                    termination_reason: None,
                    exit_code: None,
                    terminated_at_ns: None,
                    actual_tokens_consumed: None,
                };

                return Ok(SessionResponse::SessionStatus(response));
            }

            // TCK-00385: Check for terminated session
            if let Some((session, term_info)) =
                session_registry.get_terminated_session(&token.session_id)
            {
                let response = SessionStatusResponse {
                    session_id: token.session_id.clone(),
                    state: "TERMINATED".to_string(),
                    work_id: session.work_id,
                    role: session.role,
                    episode_id: session.episode_id,
                    tool_calls: 0,
                    events_emitted: 0,
                    started_at_ns: 0,
                    duration_ms: 0,
                    // TCK-00385 / MAJOR 1: Normalize termination reason
                    // through TerminationReason enum to prevent free-form
                    // strings on the wire.
                    termination_reason: Some(
                        TerminationReason::from_reason_str(&term_info.rationale_code)
                            .as_str()
                            .to_string(),
                    ),
                    exit_code: term_info.exit_code,
                    terminated_at_ns: Some(term_info.terminated_at_ns),
                    actual_tokens_consumed: term_info.actual_tokens_consumed,
                };

                return Ok(SessionResponse::SessionStatus(response));
            }
        }

        // Session not found in registry - return status based on token validity
        // If we got here, the token is valid but session may not be in registry yet
        let response = SessionStatusResponse {
            session_id: token.session_id,
            state: "ACTIVE".to_string(),
            work_id: String::new(),
            role: 0, // UNSPECIFIED
            episode_id: None,
            tool_calls: 0,
            events_emitted: 0,
            started_at_ns: 0,
            duration_ms: 0,
            termination_reason: None,
            exit_code: None,
            terminated_at_ns: None,
            actual_tokens_consumed: None,
        };

        Ok(SessionResponse::SessionStatus(response))
    }

    // ========================================================================
    // Process Log Streaming (TCK-00342)
    // ========================================================================

    /// Handles `StreamLogs` requests (IPC-SESS-005, TCK-00342).
    ///
    /// # Overview
    ///
    /// Streams process log entries from the supervisor's log buffer. Requires
    /// a valid session token for authentication.
    ///
    /// # Security
    ///
    /// - [INV-SESS-001] Requires valid `session_token`
    /// - [CTR-1303] Process name bounded by `MAX_PROCESS_NAME_LEN` (256)
    /// - [CTR-1303] Lines bounded by `MAX_LOG_LINES` (10000)
    ///
    /// # Parameters
    ///
    /// - `session_token`: HMAC-authenticated session token
    /// - `process_name`: Name of the process to stream logs from
    /// - `lines`: Number of historical lines to retrieve
    /// - `follow`: Whether to stream new lines (not implemented in Phase 1)
    fn handle_stream_logs(
        &self,
        payload: &[u8],
        ctx: &ConnectionContext,
    ) -> ProtocolResult<SessionResponse> {
        /// Maximum process name length per CTR-1303.
        const MAX_PROCESS_NAME_LEN: usize = 256;
        /// Maximum log lines per request per CTR-1303.
        const MAX_LOG_LINES: u32 = 10000;

        let request =
            StreamLogsRequest::decode_bounded(payload, &self.decode_config).map_err(|e| {
                ProtocolError::Serialization {
                    reason: format!("invalid StreamLogsRequest: {e}"),
                }
            })?;

        // INV-SESS-001: Validate session token
        let token = match self.validate_token(&request.session_token) {
            Ok(t) => t,
            Err(resp) => return Ok(resp),
        };

        // CTR-1303: Bounded input validation
        if request.process_name.len() > MAX_PROCESS_NAME_LEN {
            return Ok(SessionResponse::error(
                SessionErrorCode::SessionErrorInvalid,
                format!(
                    "process_name exceeds maximum length ({} > {})",
                    request.process_name.len(),
                    MAX_PROCESS_NAME_LEN
                ),
            ));
        }

        // CTR-1303: Bound lines parameter
        let lines = request.lines.min(MAX_LOG_LINES);

        debug!(
            session_id = %token.session_id,
            process_name = %request.process_name,
            lines = lines,
            follow = request.follow,
            peer_pid = ?ctx.peer_credentials().map(|c| c.pid),
            "StreamLogs request received"
        );

        // TODO(TCK-00342): Wire to supervisor log buffer
        // For Phase 1, return a stub response indicating the feature is not yet
        // fully implemented. The handler validates inputs and token, but actual
        // log retrieval requires supervisor integration.
        warn!(
            process_name = %request.process_name,
            "StreamLogs: supervisor log buffer not yet integrated"
        );

        // Return empty response for now - real implementation will query
        // supervisor's log ring buffer
        Ok(SessionResponse::StreamLogs(StreamLogsResponse {
            entries: vec![],
            has_more: false,
            process_name: request.process_name,
        }))
    }

    // ========================================================================
    // HEF Pulse Plane Handlers (TCK-00302)
    // ========================================================================

    /// Handles `SubscribePulse` requests (IPC-HEF-001).
    ///
    /// # TCK-00302: Session ACL Enforcement
    ///
    /// This handler enforces the default-deny ACL for session subscriptions:
    ///
    /// 1. Validates session token (INV-SESS-001)
    /// 2. Validates subscription IDs are within bounds
    /// 3. Validates topic patterns using `pulse_topic` grammar
    /// 4. Checks patterns against session's topic allowlist (if session socket)
    /// 5. Rejects wildcards for session subscriptions (Phase 1)
    /// 6. Returns accepted patterns and rejections
    ///
    /// # Security (INV-ACL-001 through INV-ACL-005)
    ///
    /// - Session subscriptions are deny-by-default
    /// - Session wildcards rejected in Phase 1
    /// - Sessions cannot publish pulse topics (checked separately)
    /// - Empty allowlist means no topics allowed (fail-closed)
    ///
    /// # Note: Subscription Registry
    ///
    /// This handler validates ACLs and returns accepted patterns, but actual
    /// subscription registration and pulse delivery are handled by TCK-00303
    /// (resource governance) and TCK-00304 (outbox + publisher).
    fn handle_subscribe_pulse(
        &self,
        payload: &[u8],
        ctx: &ConnectionContext,
    ) -> ProtocolResult<SessionResponse> {
        // Max patterns per request per RFC-0018 (must be declared before statements)
        const MAX_PATTERNS_PER_REQUEST: usize = 16;

        let request =
            SubscribePulseRequest::decode_bounded(payload, &self.decode_config).map_err(|e| {
                ProtocolError::Serialization {
                    reason: format!("invalid SubscribePulseRequest: {e}"),
                }
            })?;

        // INV-SESS-001: Validate session token
        let token = match self.validate_token(&request.session_token) {
            Ok(t) => t,
            Err(resp) => return Ok(resp),
        };

        info!(
            session_id = %token.session_id,
            client_sub_id = %request.client_sub_id,
            pattern_count = request.topic_patterns.len(),
            since_cursor = request.since_ledger_cursor,
            peer_pid = ?ctx.peer_credentials().map(|c| c.pid),
            "SubscribePulse request received"
        );

        // Validate client_sub_id length
        if let Err(e) = validate_client_sub_id(&request.client_sub_id) {
            warn!(
                session_id = %token.session_id,
                error = %e,
                "Invalid client_sub_id"
            );
            return Ok(SessionResponse::error(
                SessionErrorCode::SessionErrorInvalid,
                e.to_string(),
            ));
        }

        // Validate topic_patterns count
        if request.topic_patterns.len() > MAX_PATTERNS_PER_REQUEST {
            warn!(
                session_id = %token.session_id,
                pattern_count = request.topic_patterns.len(),
                "Too many patterns in subscribe request"
            );
            return Ok(SessionResponse::error(
                SessionErrorCode::SessionErrorInvalid,
                format!(
                    "too many patterns: {} exceeds maximum {}",
                    request.topic_patterns.len(),
                    MAX_PATTERNS_PER_REQUEST
                ),
            ));
        }

        // Create ACL evaluator for session subscriptions
        // Per DD-HEF-0004: "Session connections are deny-by-default"
        //
        // NOTE: In a full implementation, the topic allowlist would be extracted
        // from the session's capability manifest. For now, we create an empty
        // allowlist which enforces deny-by-default until TCK-00314 adds the
        // topic_allowlist field to CapabilityManifest.
        //
        // TODO(TCK-00314): Extract topic_allowlist from capability manifest
        let topic_allowlist = self.get_session_topic_allowlist(&token.session_id);
        let evaluator = PulseAclEvaluator::for_session(topic_allowlist);

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
                        session_id = %token.session_id,
                        pattern = %pattern,
                        reason = %err,
                        "Pattern rejected by ACL"
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
        // and add subscription with limit checks (only if registry is configured)
        if let Some(ref registry) = self.subscription_registry {
            if !accepted_patterns.is_empty() {
                // Parse accepted patterns into TopicPattern
                let mut parsed_patterns = Vec::new();
                for pattern_str in &accepted_patterns {
                    match super::pulse_topic::TopicPattern::parse(pattern_str) {
                        Ok(pattern) => parsed_patterns.push(pattern),
                        Err(e) => {
                            // Should not happen since ACL already validated, but be defensive
                            warn!(
                                session_id = %token.session_id,
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
                if let Err(e) = registry.register_connection(connection_id) {
                    // Only TooManyConnections is a real error
                    if matches!(
                        e,
                        super::resource_governance::ResourceError::TooManyConnections { .. }
                    ) {
                        warn!(
                            session_id = %token.session_id,
                            connection_id = %connection_id,
                            error = %e,
                            "Connection registration failed: resource limit exceeded"
                        );
                        return Ok(SessionResponse::error(
                            SessionErrorCode::SessionErrorInvalid,
                            format!("resource limit exceeded: {e}"),
                        ));
                    }
                    // Connection already exists - this is fine
                }

                // Set session ID for the connection
                if let Err(e) = registry.set_session_id(connection_id, &token.session_id) {
                    debug!(
                        connection_id = %connection_id,
                        error = %e,
                        "Failed to set session ID (connection may not exist)"
                    );
                }

                // Create subscription state and add to registry
                let subscription = super::resource_governance::SubscriptionState::new(
                    &subscription_id,
                    &request.client_sub_id,
                    parsed_patterns,
                    request.since_ledger_cursor,
                );

                if let Err(e) = registry.add_subscription(connection_id, subscription) {
                    warn!(
                        session_id = %token.session_id,
                        connection_id = %connection_id,
                        subscription_id = %subscription_id,
                        error = %e,
                        "Subscription registration failed: resource limit exceeded"
                    );
                    return Ok(SessionResponse::error(
                        SessionErrorCode::SessionErrorInvalid,
                        format!("resource limit exceeded: {e}"),
                    ));
                }
            }
        }

        // Log outcome
        if rejected_patterns.is_empty() {
            info!(
                session_id = %token.session_id,
                subscription_id = %subscription_id,
                connection_id = %connection_id,
                accepted_count = accepted_patterns.len(),
                "All patterns accepted"
            );
        } else {
            warn!(
                session_id = %token.session_id,
                subscription_id = %subscription_id,
                connection_id = %connection_id,
                accepted_count = accepted_patterns.len(),
                rejected_count = rejected_patterns.len(),
                "Some patterns rejected"
            );
        }

        Ok(SessionResponse::SubscribePulse(SubscribePulseResponse {
            subscription_id,
            effective_since_cursor: request.since_ledger_cursor,
            accepted_patterns,
            rejected_patterns,
        }))
    }

    /// Gets the topic allowlist for a session (TCK-00314).
    ///
    /// Per RFC-0018, session subscriptions are gated via capability manifest
    /// allowlist. This method extracts the `topic_allowlist` from the session's
    /// capability manifest.
    ///
    /// # Security (INV-ACL-004)
    ///
    /// Empty allowlist = deny all (fail-closed).
    fn get_session_topic_allowlist(&self, session_id: &str) -> TopicAllowlist {
        // TCK-00314: Extract topic_allowlist from capability manifest
        if let Some(ref store) = self.manifest_store {
            if let Some(manifest) = store.get_manifest(session_id) {
                // Convert manifest's topic_allowlist to TopicAllowlist
                return manifest.to_topic_allowlist();
            }
        }

        // No manifest = deny all (fail-closed per SEC-CTRL-FAC-0015)
        TopicAllowlist::new()
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

    /// Handles `UnsubscribePulse` requests (IPC-HEF-002).
    ///
    /// # TCK-00302: Unsubscribe Handling
    ///
    /// This handler validates the unsubscribe request and returns success.
    ///
    /// # Note: Subscription Registry
    ///
    /// Actual subscription removal is handled by TCK-00303 (resource
    /// governance). This handler validates the request and returns a
    /// response.
    fn handle_unsubscribe_pulse(
        &self,
        payload: &[u8],
        ctx: &ConnectionContext,
    ) -> ProtocolResult<SessionResponse> {
        let request = UnsubscribePulseRequest::decode_bounded(payload, &self.decode_config)
            .map_err(|e| ProtocolError::Serialization {
                reason: format!("invalid UnsubscribePulseRequest: {e}"),
            })?;

        // INV-SESS-001: Validate session token
        let token = match self.validate_token(&request.session_token) {
            Ok(t) => t,
            Err(resp) => return Ok(resp),
        };

        info!(
            session_id = %token.session_id,
            subscription_id = %request.subscription_id,
            peer_pid = ?ctx.peer_credentials().map(|c| c.pid),
            "UnsubscribePulse request received"
        );

        // Validate subscription_id length
        if let Err(e) = validate_subscription_id(&request.subscription_id) {
            warn!(
                session_id = %token.session_id,
                error = %e,
                "Invalid subscription_id"
            );
            return Ok(SessionResponse::error(
                SessionErrorCode::SessionErrorInvalid,
                e.to_string(),
            ));
        }

        // TCK-00303: Wire resource governance - remove subscription from registry
        // Use connection_id from context for consistent tracking
        let connection_id = ctx.connection_id();

        let removed = if let Some(ref registry) = self.subscription_registry {
            match registry.remove_subscription(connection_id, &request.subscription_id) {
                Ok(_) => {
                    info!(
                        session_id = %token.session_id,
                        subscription_id = %request.subscription_id,
                        connection_id = %connection_id,
                        "Unsubscribe processed successfully"
                    );
                    true
                },
                Err(e) => {
                    // Log but don't fail - subscription may already be removed or never existed
                    debug!(
                        session_id = %token.session_id,
                        subscription_id = %request.subscription_id,
                        connection_id = %connection_id,
                        error = %e,
                        "Unsubscribe - subscription not found (may already be removed)"
                    );
                    false
                },
            }
        } else {
            // No registry configured - return true for backwards compatibility
            info!(
                session_id = %token.session_id,
                subscription_id = %request.subscription_id,
                "Unsubscribe processed (no registry configured)"
            );
            true
        };

        Ok(SessionResponse::UnsubscribePulse(
            UnsubscribePulseResponse { removed },
        ))
    }
}

// ============================================================================
// Request Encoding Helpers
// ============================================================================

/// Encodes a `RequestTool` request to bytes for sending.
///
/// The format is: `[tag: u8][payload: protobuf]`
#[must_use]
pub fn encode_request_tool_request(request: &RequestToolRequest) -> Bytes {
    let mut buf = vec![SessionMessageType::RequestTool.tag()];
    request.encode(&mut buf).expect("encode cannot fail");
    Bytes::from(buf)
}

/// Encodes an `EmitEvent` request to bytes for sending.
#[must_use]
pub fn encode_emit_event_request(request: &EmitEventRequest) -> Bytes {
    let mut buf = vec![SessionMessageType::EmitEvent.tag()];
    request.encode(&mut buf).expect("encode cannot fail");
    Bytes::from(buf)
}

/// Encodes a `PublishEvidence` request to bytes for sending.
#[must_use]
pub fn encode_publish_evidence_request(request: &PublishEvidenceRequest) -> Bytes {
    let mut buf = vec![SessionMessageType::PublishEvidence.tag()];
    request.encode(&mut buf).expect("encode cannot fail");
    Bytes::from(buf)
}

/// Encodes a `StreamTelemetry` request to bytes for sending.
#[must_use]
pub fn encode_stream_telemetry_request(request: &StreamTelemetryRequest) -> Bytes {
    let mut buf = vec![SessionMessageType::StreamTelemetry.tag()];
    request.encode(&mut buf).expect("encode cannot fail");
    Bytes::from(buf)
}

/// Encodes a `StreamLogs` request to bytes for sending (TCK-00342).
#[must_use]
pub fn encode_stream_logs_request(request: &StreamLogsRequest) -> Bytes {
    let mut buf = vec![SessionMessageType::StreamLogs.tag()];
    request.encode(&mut buf).expect("encode cannot fail");
    Bytes::from(buf)
}

/// Encodes a `SubscribePulse` request to bytes for sending (TCK-00302).
#[must_use]
pub fn encode_subscribe_pulse_request(request: &SubscribePulseRequest) -> Bytes {
    let mut buf = vec![SessionMessageType::SubscribePulse.tag()];
    request.encode(&mut buf).expect("encode cannot fail");
    Bytes::from(buf)
}

/// Encodes an `UnsubscribePulse` request to bytes for sending (TCK-00302).
#[must_use]
pub fn encode_unsubscribe_pulse_request(request: &UnsubscribePulseRequest) -> Bytes {
    let mut buf = vec![SessionMessageType::UnsubscribePulse.tag()];
    request.encode(&mut buf).expect("encode cannot fail");
    Bytes::from(buf)
}

/// Encodes a `SessionStatus` request to bytes for sending (TCK-00344).
#[must_use]
pub fn encode_session_status_request(request: &SessionStatusRequest) -> Bytes {
    let mut buf = vec![SessionMessageType::SessionStatus.tag()];
    request.encode(&mut buf).expect("encode cannot fail");
    Bytes::from(buf)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use secrecy::SecretString;

    use super::*;
    use crate::protocol::credentials::PeerCredentials;
    use crate::protocol::messages::{EvidenceKind, RetentionHint, TelemetryFrame};

    fn test_minter() -> TokenMinter {
        TokenMinter::new(SecretString::from("test-daemon-secret-key-32bytes!!"))
    }

    fn test_token(minter: &TokenMinter) -> SessionToken {
        let spawn_time = SystemTime::now();
        let ttl = Duration::from_secs(3600);
        minter
            .mint("session-001", "lease-001", spawn_time, ttl)
            .unwrap()
    }

    fn make_session_ctx() -> ConnectionContext {
        ConnectionContext::session_open(
            Some(PeerCredentials {
                uid: 1000,
                gid: 1000,
                pid: Some(12346),
            }),
            Some("session-001".to_string()),
        )
    }

    fn make_privileged_ctx() -> ConnectionContext {
        ConnectionContext::privileged_session_open(Some(PeerCredentials {
            uid: 1000,
            gid: 1000,
            pid: Some(12345),
        }))
    }

    // ========================================================================
    // INT-002: Session endpoint routing (TCK-00252)
    // Test name matches verification command: cargo test -p apm2-daemon
    // session_routing
    // ========================================================================
    mod session_routing {
        use super::*;

        /// TCK-00290: `RequestTool` without manifest store returns fail-closed
        /// error.
        ///
        /// Per INV-TCK-00290-001, `RequestTool` requires a manifest store.
        /// Without it, returns `SESSION_ERROR_TOOL_NOT_ALLOWED`.
        #[test]
        fn test_request_tool_routing_fail_closed() {
            let minter = test_minter();
            let dispatcher = SessionDispatcher::new(minter.clone());
            let ctx = make_session_ctx();
            let token = test_token(&minter);

            let request = RequestToolRequest {
                session_token: serde_json::to_string(&token).unwrap(),
                tool_id: "read".to_string(),
                arguments: vec![1, 2, 3],
                dedupe_key: "key-001".to_string(),
                epoch_seal: None,
            };
            let frame = encode_request_tool_request(&request);

            let response = dispatcher.dispatch(&frame, &ctx).unwrap();
            match response {
                SessionResponse::Error(err) => {
                    assert_eq!(
                        err.code,
                        SessionErrorCode::SessionErrorToolNotAllowed as i32,
                        "Expected TOOL_NOT_ALLOWED for unconfigured manifest store"
                    );
                    assert!(
                        err.message.contains("fail-closed"),
                        "Error should mention fail-closed: {}",
                        err.message
                    );
                },
                _ => panic!("Expected error for unconfigured dispatcher, got: {response:?}"),
            }
        }

        /// TCK-00290: `EmitEvent` without ledger returns fail-closed error.
        ///
        /// Per INV-TCK-00290-002, `EmitEvent` requires a ledger.
        /// Without it, returns `SESSION_ERROR_INTERNAL`.
        #[test]
        fn test_emit_event_routing_fail_closed() {
            let minter = test_minter();
            let dispatcher = SessionDispatcher::new(minter.clone());
            let ctx = make_session_ctx();
            let token = test_token(&minter);

            let request = EmitEventRequest {
                session_token: serde_json::to_string(&token).unwrap(),
                event_type: "test_event".to_string(),
                payload: vec![1, 2, 3],
                correlation_id: "corr-001".to_string(),
            };
            let frame = encode_emit_event_request(&request);

            let response = dispatcher.dispatch(&frame, &ctx).unwrap();
            match response {
                SessionResponse::Error(err) => {
                    assert_eq!(
                        err.code,
                        SessionErrorCode::SessionErrorInternal as i32,
                        "Expected INTERNAL for unconfigured ledger"
                    );
                    assert!(
                        err.message.contains("fail-closed"),
                        "Error should mention fail-closed: {}",
                        err.message
                    );
                },
                _ => panic!("Expected error for unconfigured dispatcher, got: {response:?}"),
            }
        }

        /// TCK-00290: `PublishEvidence` without CAS returns fail-closed error.
        ///
        /// Per INV-TCK-00290-003, `PublishEvidence` requires a CAS.
        /// Without it, returns `SESSION_ERROR_INTERNAL`.
        #[test]
        fn test_publish_evidence_routing_fail_closed() {
            let minter = test_minter();
            let dispatcher = SessionDispatcher::new(minter.clone());
            let ctx = make_session_ctx();
            let token = test_token(&minter);

            let request = PublishEvidenceRequest {
                session_token: serde_json::to_string(&token).unwrap(),
                artifact: vec![1, 2, 3, 4, 5],
                kind: EvidenceKind::ToolIo.into(),
                retention_hint: RetentionHint::Standard.into(),
            };
            let frame = encode_publish_evidence_request(&request);

            let response = dispatcher.dispatch(&frame, &ctx).unwrap();
            match response {
                SessionResponse::Error(err) => {
                    assert_eq!(
                        err.code,
                        SessionErrorCode::SessionErrorInternal as i32,
                        "Expected INTERNAL for unconfigured CAS"
                    );
                    assert!(
                        err.message.contains("fail-closed"),
                        "Error should mention fail-closed: {}",
                        err.message
                    );
                },
                _ => panic!("Expected error for unconfigured dispatcher, got: {response:?}"),
            }
        }

        /// TCK-00290: `StreamTelemetry` returns `NOT_IMPLEMENTED`
        /// (fail-closed).
        ///
        /// Per INV-TCK-00290-004, `StreamTelemetry` is disabled until
        /// implemented.
        #[test]
        fn test_stream_telemetry_routing_not_implemented() {
            let minter = test_minter();
            let dispatcher = SessionDispatcher::new(minter.clone());
            let ctx = make_session_ctx();
            let token = test_token(&minter);

            let request = StreamTelemetryRequest {
                session_token: serde_json::to_string(&token).unwrap(),
                frame: Some(TelemetryFrame {
                    episode_id: "ep-001".to_string(),
                    seq: 1,
                    ts_mono: 1000,
                    cpu_ns: 100,
                    mem_rss_bytes: 1024,
                    io_read_bytes: 0,
                    io_write_bytes: 0,
                    cgroup_stats: None,
                    o11y_flags: 0,
                }),
            };
            let frame = encode_stream_telemetry_request(&request);

            let response = dispatcher.dispatch(&frame, &ctx).unwrap();
            match response {
                SessionResponse::Error(err) => {
                    assert_eq!(
                        err.code,
                        SessionErrorCode::SessionErrorNotImplemented as i32,
                        "Expected NOT_IMPLEMENTED for StreamTelemetry"
                    );
                    assert!(
                        err.message.contains("not implemented"),
                        "Error should mention not implemented: {}",
                        err.message
                    );
                },
                _ => panic!("Expected NOT_IMPLEMENTED error, got: {response:?}"),
            }
        }

        #[test]
        fn test_operator_socket_returns_permission_denied() {
            let minter = test_minter();
            let dispatcher = SessionDispatcher::new(minter.clone());
            let ctx = make_privileged_ctx(); // Operator connection
            let token = test_token(&minter);

            // All 4 endpoints should return SESSION_ERROR_PERMISSION_DENIED for operator
            let requests = vec![
                encode_request_tool_request(&RequestToolRequest {
                    session_token: serde_json::to_string(&token).unwrap(),
                    tool_id: "read".to_string(),
                    arguments: vec![],
                    dedupe_key: String::new(),
                    epoch_seal: None,
                }),
                encode_emit_event_request(&EmitEventRequest {
                    session_token: serde_json::to_string(&token).unwrap(),
                    event_type: "test".to_string(),
                    payload: vec![],
                    correlation_id: String::new(),
                }),
                encode_publish_evidence_request(&PublishEvidenceRequest {
                    session_token: serde_json::to_string(&token).unwrap(),
                    artifact: vec![1],
                    kind: 0,
                    retention_hint: 0,
                }),
                encode_stream_telemetry_request(&StreamTelemetryRequest {
                    session_token: serde_json::to_string(&token).unwrap(),
                    frame: Some(TelemetryFrame::default()),
                }),
            ];

            for frame in requests {
                let response = dispatcher.dispatch(&frame, &ctx).unwrap();
                match response {
                    SessionResponse::Error(err) => {
                        assert_eq!(
                            err.code,
                            SessionErrorCode::SessionErrorPermissionDenied as i32
                        );
                    },
                    _ => panic!("Expected SESSION_ERROR_PERMISSION_DENIED for operator socket"),
                }
            }
        }
    }

    // ========================================================================
    // Token Validation Tests
    // ========================================================================
    #[test]
    fn test_invalid_token_returns_session_invalid() {
        let minter = test_minter();
        let dispatcher = SessionDispatcher::new(minter);
        let ctx = make_session_ctx();

        // Create request with invalid token
        let request = RequestToolRequest {
            session_token: r#"{"session_id":"session-001","lease_id":"lease-001","spawn_time_ns":1000,"expires_at_ns":2000,"mac":"0000000000000000000000000000000000000000000000000000000000000000"}"#.to_string(),
            tool_id: "read".to_string(),
            arguments: vec![],
            dedupe_key: String::new(),
            epoch_seal: None,
        };
        let frame = encode_request_tool_request(&request);

        let response = dispatcher.dispatch(&frame, &ctx).unwrap();
        match response {
            SessionResponse::Error(err) => {
                assert_eq!(err.code, SessionErrorCode::SessionErrorInvalid as i32);
                assert!(err.message.contains("invalid") || err.message.contains("expired"));
            },
            _ => panic!("Expected SESSION_ERROR_INVALID error"),
        }
    }

    #[test]
    fn test_malformed_token_returns_session_invalid() {
        let minter = test_minter();
        let dispatcher = SessionDispatcher::new(minter);
        let ctx = make_session_ctx();

        let request = RequestToolRequest {
            session_token: "not-valid-json".to_string(),
            tool_id: "read".to_string(),
            arguments: vec![],
            dedupe_key: String::new(),
            epoch_seal: None,
        };
        let frame = encode_request_tool_request(&request);

        let response = dispatcher.dispatch(&frame, &ctx).unwrap();
        match response {
            SessionResponse::Error(err) => {
                assert_eq!(err.code, SessionErrorCode::SessionErrorInvalid as i32);
                assert!(err.message.contains("malformed"));
            },
            _ => panic!("Expected SESSION_ERROR_INVALID error"),
        }
    }

    #[test]
    fn test_expired_token_returns_session_invalid() {
        let minter = test_minter();
        let dispatcher = SessionDispatcher::new(minter.clone());
        let ctx = make_session_ctx();

        // Create an already-expired token
        let spawn_time = SystemTime::now() - Duration::from_secs(7200);
        let ttl = Duration::from_secs(3600); // Expired 1 hour ago
        let token = minter
            .mint("session-001", "lease-001", spawn_time, ttl)
            .unwrap();

        let request = RequestToolRequest {
            session_token: serde_json::to_string(&token).unwrap(),
            tool_id: "read".to_string(),
            arguments: vec![],
            dedupe_key: String::new(),
            epoch_seal: None,
        };
        let frame = encode_request_tool_request(&request);

        let response = dispatcher.dispatch(&frame, &ctx).unwrap();
        match response {
            SessionResponse::Error(err) => {
                assert_eq!(err.code, SessionErrorCode::SessionErrorInvalid as i32);
                assert!(err.message.contains("expired"));
            },
            _ => panic!("Expected SESSION_ERROR_INVALID error for expired token"),
        }
    }

    // ========================================================================
    // Validation Tests
    // ========================================================================
    #[test]
    fn test_request_tool_requires_tool_id() {
        let minter = test_minter();
        let dispatcher = SessionDispatcher::new(minter.clone());
        let ctx = make_session_ctx();
        let token = test_token(&minter);

        let request = RequestToolRequest {
            session_token: serde_json::to_string(&token).unwrap(),
            tool_id: String::new(), // Missing tool_id
            arguments: vec![],
            dedupe_key: String::new(),
            epoch_seal: None,
        };
        let frame = encode_request_tool_request(&request);

        let response = dispatcher.dispatch(&frame, &ctx).unwrap();
        match response {
            SessionResponse::Error(err) => {
                assert!(err.message.contains("tool_id"));
            },
            _ => panic!("Expected validation error for empty tool_id"),
        }
    }

    #[test]
    fn test_emit_event_requires_event_type() {
        let minter = test_minter();
        let dispatcher = SessionDispatcher::new(minter.clone());
        let ctx = make_session_ctx();
        let token = test_token(&minter);

        let request = EmitEventRequest {
            session_token: serde_json::to_string(&token).unwrap(),
            event_type: String::new(), // Missing event_type
            payload: vec![],
            correlation_id: String::new(),
        };
        let frame = encode_emit_event_request(&request);

        let response = dispatcher.dispatch(&frame, &ctx).unwrap();
        match response {
            SessionResponse::Error(err) => {
                assert!(err.message.contains("event_type"));
            },
            _ => panic!("Expected validation error for empty event_type"),
        }
    }

    #[test]
    fn test_publish_evidence_requires_artifact() {
        let minter = test_minter();
        let dispatcher = SessionDispatcher::new(minter.clone());
        let ctx = make_session_ctx();
        let token = test_token(&minter);

        let request = PublishEvidenceRequest {
            session_token: serde_json::to_string(&token).unwrap(),
            artifact: vec![], // Empty artifact
            kind: 0,
            retention_hint: 0,
        };
        let frame = encode_publish_evidence_request(&request);

        let response = dispatcher.dispatch(&frame, &ctx).unwrap();
        match response {
            SessionResponse::Error(err) => {
                assert!(err.message.contains("artifact"));
            },
            _ => panic!("Expected validation error for empty artifact"),
        }
    }

    /// TCK-00290: `StreamTelemetry` returns `NOT_IMPLEMENTED` even with missing
    /// frame.
    ///
    /// Since `StreamTelemetry` is disabled (fail-closed), it doesn't validate
    /// the frame before rejecting with `NOT_IMPLEMENTED`.
    #[test]
    fn test_stream_telemetry_requires_frame() {
        let minter = test_minter();
        let dispatcher = SessionDispatcher::new(minter.clone());
        let ctx = make_session_ctx();
        let token = test_token(&minter);

        let request = StreamTelemetryRequest {
            session_token: serde_json::to_string(&token).unwrap(),
            frame: None, // Missing frame
        };
        let frame = encode_stream_telemetry_request(&request);

        let response = dispatcher.dispatch(&frame, &ctx).unwrap();
        match response {
            SessionResponse::Error(err) => {
                // Per TCK-00290, StreamTelemetry is disabled, so returns NOT_IMPLEMENTED
                // regardless of frame validation
                assert_eq!(
                    err.code,
                    SessionErrorCode::SessionErrorNotImplemented as i32,
                    "Expected NOT_IMPLEMENTED for StreamTelemetry"
                );
            },
            _ => panic!("Expected NOT_IMPLEMENTED error for StreamTelemetry"),
        }
    }

    // ========================================================================
    // Protocol Error Tests
    // ========================================================================
    #[test]
    fn test_empty_frame_error() {
        let minter = test_minter();
        let dispatcher = SessionDispatcher::new(minter);
        let ctx = make_session_ctx();

        let frame = Bytes::new();
        let result = dispatcher.dispatch(&frame, &ctx);

        assert!(result.is_err());
        assert!(matches!(result, Err(ProtocolError::Serialization { .. })));
    }

    #[test]
    fn test_unknown_message_type_error() {
        let minter = test_minter();
        let dispatcher = SessionDispatcher::new(minter);
        let ctx = make_session_ctx();

        let frame = Bytes::from(vec![255u8, 0, 0, 0]); // Unknown tag
        let result = dispatcher.dispatch(&frame, &ctx);

        assert!(result.is_err());
        assert!(matches!(result, Err(ProtocolError::Serialization { .. })));
    }

    // ========================================================================
    // Response Encoding Tests
    // ========================================================================
    #[test]
    fn test_response_encoding() {
        let error_resp = SessionResponse::session_invalid("test error");
        let encoded = error_resp.encode();
        assert!(!encoded.is_empty());
        assert_eq!(encoded[0], 0); // Error tag

        let tool_resp = SessionResponse::RequestTool(RequestToolResponse {
            request_id: "REQ-001".to_string(),
            decision: 0,
            rule_id: None,
            policy_hash: vec![],
            result_hash: None,
            inline_result: None,
            stop_checked: false,
            budget_checked: false,
            budget_enforcement_deferred: false,
            preactuation_timestamp_ns: 0,
        });
        let encoded = tool_resp.encode();
        assert!(!encoded.is_empty());
        assert_eq!(encoded[0], SessionMessageType::RequestTool.tag());
    }

    // ========================================================================
    // TCK-00260: Tool Broker with Capability Manifest Validation Tests
    // ========================================================================
    mod tck_00260_manifest_validation {
        use super::*;
        use crate::episode::{
            Capability, CapabilityManifestBuilder, CapabilityScope, RiskTier, ToolClass,
        };

        pub(super) fn make_test_manifest(
            tools: Vec<ToolClass>,
        ) -> crate::episode::CapabilityManifest {
            let caps: Vec<Capability> = tools
                .iter()
                .map(|tc| Capability {
                    capability_id: format!("cap-{tc}"),
                    tool_class: *tc,
                    scope: CapabilityScope::default(),
                    risk_tier_required: RiskTier::Tier0,
                })
                .collect();

            CapabilityManifestBuilder::new("test-manifest")
                .delegator("test-delegator")
                .capabilities(caps)
                .tool_allowlist(tools)
                .build()
                .expect("manifest build failed")
        }

        #[test]
        fn test_tool_in_allowlist_returns_allow() {
            let minter = test_minter();
            let store = Arc::new(InMemoryManifestStore::new());

            // Register manifest with Read allowed
            let manifest = make_test_manifest(vec![ToolClass::Read]);
            store.register("session-001", manifest);

            let dispatcher = SessionDispatcher::with_manifest_store(minter.clone(), store);
            let ctx = make_session_ctx();
            let token = test_token(&minter);

            let request = RequestToolRequest {
                session_token: serde_json::to_string(&token).unwrap(),
                tool_id: "read".to_string(), // ToolClass::Read
                arguments: vec![],
                dedupe_key: "key-001".to_string(),
                epoch_seal: None,
            };
            let frame = encode_request_tool_request(&request);

            let response = dispatcher.dispatch(&frame, &ctx).unwrap();
            match response {
                SessionResponse::Error(err) => {
                    assert_eq!(
                        err.code,
                        SessionErrorCode::SessionErrorToolNotAllowed as i32,
                        "Expected TOOL_NOT_ALLOWED error code (fail-closed)"
                    );
                    assert!(
                        err.message.contains("broker unavailable"),
                        "Error message should indicate broker unavailable: {}",
                        err.message
                    );
                },
                _ => panic!("Expected Error response, got: {response:?}"),
            }
        }

        #[test]
        fn test_tool_not_in_allowlist_returns_tool_not_allowed() {
            let minter = test_minter();
            let store = Arc::new(InMemoryManifestStore::new());

            // Register manifest with only Read allowed
            let manifest = make_test_manifest(vec![ToolClass::Read]);
            store.register("session-001", manifest);

            let dispatcher = SessionDispatcher::with_manifest_store(minter.clone(), store);
            let ctx = make_session_ctx();
            let token = test_token(&minter);

            // Request Write tool which is not in allowlist
            let request = RequestToolRequest {
                session_token: serde_json::to_string(&token).unwrap(),
                tool_id: "write".to_string(), // ToolClass::Write - NOT in allowlist
                arguments: vec![],
                dedupe_key: "key-002".to_string(),
                epoch_seal: None,
            };
            let frame = encode_request_tool_request(&request);

            let response = dispatcher.dispatch(&frame, &ctx).unwrap();
            match response {
                SessionResponse::Error(err) => {
                    assert_eq!(
                        err.code,
                        SessionErrorCode::SessionErrorToolNotAllowed as i32,
                        "Expected TOOL_NOT_ALLOWED error code (fail-closed)"
                    );
                    assert!(
                        err.message.contains("broker unavailable"),
                        "Error message should indicate broker unavailable: {}",
                        err.message
                    );
                },
                _ => panic!("Expected Error response, got: {response:?}"),
            }
        }

        #[test]
        fn test_empty_allowlist_denies_all_tools() {
            let minter = test_minter();
            let store = Arc::new(InMemoryManifestStore::new());

            // Register manifest with empty allowlist (fail-closed)
            let manifest = CapabilityManifestBuilder::new("empty-manifest")
                .delegator("test-delegator")
                .tool_allowlist(vec![]) // Empty allowlist
                .build()
                .expect("manifest build failed");
            store.register("session-001", manifest);

            let dispatcher = SessionDispatcher::with_manifest_store(minter.clone(), store);
            let ctx = make_session_ctx();
            let token = test_token(&minter);

            // Request any tool - should be denied
            let request = RequestToolRequest {
                session_token: serde_json::to_string(&token).unwrap(),
                tool_id: "read".to_string(),
                arguments: vec![],
                dedupe_key: "key-003".to_string(),
                epoch_seal: None,
            };
            let frame = encode_request_tool_request(&request);

            let response = dispatcher.dispatch(&frame, &ctx).unwrap();
            match response {
                SessionResponse::Error(err) => {
                    assert_eq!(
                        err.code,
                        SessionErrorCode::SessionErrorToolNotAllowed as i32,
                        "Empty allowlist should deny all tools"
                    );
                },
                _ => panic!("Expected SESSION_ERROR_TOOL_NOT_ALLOWED for empty allowlist"),
            }
        }

        #[test]
        fn test_unknown_tool_id_returns_tool_not_allowed() {
            let minter = test_minter();
            let store = Arc::new(InMemoryManifestStore::new());

            let manifest = make_test_manifest(vec![ToolClass::Read]);
            store.register("session-001", manifest);

            let dispatcher = SessionDispatcher::with_manifest_store(minter.clone(), store);
            let ctx = make_session_ctx();
            let token = test_token(&minter);

            // Request unknown tool class
            let request = RequestToolRequest {
                session_token: serde_json::to_string(&token).unwrap(),
                tool_id: "unknown_tool_xyz".to_string(), // Not a valid ToolClass
                arguments: vec![],
                dedupe_key: "key-004".to_string(),
                epoch_seal: None,
            };
            let frame = encode_request_tool_request(&request);

            let response = dispatcher.dispatch(&frame, &ctx).unwrap();
            match response {
                SessionResponse::Error(err) => {
                    assert_eq!(
                        err.code,
                        SessionErrorCode::SessionErrorToolNotAllowed as i32,
                        "Unknown tool class should be denied"
                    );
                    assert!(
                        err.message.contains("unknown tool class"),
                        "Error message should mention unknown tool class: {}",
                        err.message
                    );
                },
                _ => panic!("Expected SESSION_ERROR_TOOL_NOT_ALLOWED for unknown tool"),
            }
        }

        #[test]
        fn test_tool_id_too_long_returns_invalid() {
            let minter = test_minter();
            let dispatcher = SessionDispatcher::new(minter.clone());
            let ctx = make_session_ctx();
            let token = test_token(&minter);

            // Create tool_id that exceeds MAX_TOOL_ID_LEN
            let long_tool_id = "a".repeat(MAX_TOOL_ID_LEN + 1);

            let request = RequestToolRequest {
                session_token: serde_json::to_string(&token).unwrap(),
                tool_id: long_tool_id,
                arguments: vec![],
                dedupe_key: "key-005".to_string(),
                epoch_seal: None,
            };
            let frame = encode_request_tool_request(&request);

            let response = dispatcher.dispatch(&frame, &ctx).unwrap();
            match response {
                SessionResponse::Error(err) => {
                    assert_eq!(
                        err.code,
                        SessionErrorCode::SessionErrorInvalid as i32,
                        "Oversized tool_id should return INVALID"
                    );
                    assert!(
                        err.message.contains("exceeds maximum length"),
                        "Error message should mention length: {}",
                        err.message
                    );
                },
                _ => panic!("Expected SESSION_ERROR_INVALID for oversized tool_id"),
            }
        }

        #[test]
        fn test_multiple_tools_in_allowlist() {
            let minter = test_minter();
            let store = Arc::new(InMemoryManifestStore::new());

            // Register manifest with multiple tools allowed
            let manifest =
                make_test_manifest(vec![ToolClass::Read, ToolClass::Write, ToolClass::Execute]);
            store.register("session-001", manifest);

            let dispatcher = SessionDispatcher::with_manifest_store(minter.clone(), store);
            let ctx = make_session_ctx();
            let token = test_token(&minter);

            // All three should be denied because broker is not configured (fail-closed)
            for tool_id in ["read", "write", "execute"] {
                let request = RequestToolRequest {
                    session_token: serde_json::to_string(&token).unwrap(),
                    tool_id: tool_id.to_string(),
                    arguments: vec![],
                    dedupe_key: format!("key-{tool_id}"),
                    epoch_seal: None,
                };
                let frame = encode_request_tool_request(&request);

                let response = dispatcher.dispatch(&frame, &ctx).unwrap();
                match response {
                    SessionResponse::Error(err) => {
                        assert_eq!(
                            err.code,
                            SessionErrorCode::SessionErrorToolNotAllowed as i32,
                            "Tool {tool_id} should be denied (fail-closed)"
                        );
                        assert!(
                            err.message.contains("broker unavailable"),
                            "Error message should indicate broker unavailable"
                        );
                    },
                    _ => panic!("Expected Error for tool {tool_id}"),
                }
            }

            // Git and Network should be denied (same reason)
            for tool_id in ["git", "network"] {
                let request = RequestToolRequest {
                    session_token: serde_json::to_string(&token).unwrap(),
                    tool_id: tool_id.to_string(),
                    arguments: vec![],
                    dedupe_key: format!("key-{tool_id}"),
                    epoch_seal: None,
                };
                let frame = encode_request_tool_request(&request);

                let response = dispatcher.dispatch(&frame, &ctx).unwrap();
                match response {
                    SessionResponse::Error(err) => {
                        assert_eq!(
                            err.code,
                            SessionErrorCode::SessionErrorToolNotAllowed as i32,
                            "Tool {tool_id} should be denied"
                        );
                        // With legacy path removed, it fails closed due to missing broker
                        assert!(
                            err.message.contains("broker unavailable"),
                            "Error message should indicate broker unavailable"
                        );
                    },
                    _ => panic!("Expected Deny for tool {tool_id}"),
                }
            }
        }

        #[test]
        fn test_validation_performance() {
            // This test verifies that validation is fast (<5ms p50)
            use std::time::Instant;

            let minter = test_minter();
            let store = Arc::new(InMemoryManifestStore::new());

            // Create manifest with max allowlist size to test worst case
            let manifest = make_test_manifest(vec![
                ToolClass::Read,
                ToolClass::Write,
                ToolClass::Execute,
                ToolClass::Network,
                ToolClass::Git,
                ToolClass::Inference,
                ToolClass::Artifact,
            ]);
            store.register("session-001", manifest);

            let dispatcher = SessionDispatcher::with_manifest_store(minter.clone(), store);
            let ctx = make_session_ctx();
            let token = test_token(&minter);

            let request = RequestToolRequest {
                session_token: serde_json::to_string(&token).unwrap(),
                tool_id: "read".to_string(),
                arguments: vec![],
                dedupe_key: "perf-test".to_string(),
                epoch_seal: None,
            };
            let frame = encode_request_tool_request(&request);

            // Run 100 iterations and measure
            let iterations = 100;
            let mut durations = Vec::with_capacity(iterations);

            for _ in 0..iterations {
                let start = Instant::now();
                let _ = dispatcher.dispatch(&frame, &ctx);
                durations.push(start.elapsed());
            }

            // Sort to get p50
            durations.sort();
            let p50 = durations[iterations / 2];

            // p50 should be less than 5ms
            assert!(
                p50.as_millis() < 5,
                "p50 validation time should be <5ms, was {}ms",
                p50.as_millis()
            );
        }
    }

    // ========================================================================
    // TCK-00302: HEF Pulse Subscription ACL Tests
    // ========================================================================
    mod tck_00302_hef_acl {
        use super::*;

        /// TCK-00302: Session subscriptions are deny-by-default.
        ///
        /// Per DD-HEF-0004 and INV-ACL-001, session connections cannot
        /// subscribe to any topics without an explicit allowlist.
        #[test]
        fn test_session_subscribe_deny_by_default() {
            let minter = test_minter();
            let dispatcher = SessionDispatcher::new(minter.clone());
            let ctx = make_session_ctx();
            let token = test_token(&minter);

            let request = SubscribePulseRequest {
                session_token: serde_json::to_string(&token).unwrap(),
                client_sub_id: "client-sub-001".to_string(),
                topic_patterns: vec!["work.W-123.events".to_string()],
                since_ledger_cursor: 0,
                max_pulses_per_sec: 100,
            };
            let frame = encode_subscribe_pulse_request(&request);

            let response = dispatcher.dispatch(&frame, &ctx).unwrap();
            match response {
                SessionResponse::SubscribePulse(resp) => {
                    // All patterns should be rejected (deny-by-default)
                    assert!(
                        resp.accepted_patterns.is_empty(),
                        "Expected no accepted patterns (deny-by-default)"
                    );
                    assert_eq!(resp.rejected_patterns.len(), 1);
                    assert_eq!(resp.rejected_patterns[0].pattern, "work.W-123.events");
                    assert_eq!(resp.rejected_patterns[0].reason_code, "ACL_DENY");
                },
                _ => panic!("Expected SubscribePulse response, got: {response:?}"),
            }
        }

        /// TCK-00302: Session wildcards are rejected in Phase 1.
        ///
        /// Per DD-HEF-0004 and INV-ACL-002, session connections cannot use
        /// wildcard patterns in Phase 1.
        #[test]
        fn test_session_wildcard_rejected() {
            let minter = test_minter();
            let dispatcher = SessionDispatcher::new(minter.clone());
            let ctx = make_session_ctx();
            let token = test_token(&minter);

            let request = SubscribePulseRequest {
                session_token: serde_json::to_string(&token).unwrap(),
                client_sub_id: "client-sub-002".to_string(),
                topic_patterns: vec![
                    "work.*.events".to_string(),    // Single wildcard
                    "episode.EP-001.>".to_string(), // Terminal wildcard
                ],
                since_ledger_cursor: 0,
                max_pulses_per_sec: 100,
            };
            let frame = encode_subscribe_pulse_request(&request);

            let response = dispatcher.dispatch(&frame, &ctx).unwrap();
            match response {
                SessionResponse::SubscribePulse(resp) => {
                    // All wildcard patterns should be rejected
                    assert!(
                        resp.accepted_patterns.is_empty(),
                        "Expected no accepted patterns (wildcards rejected)"
                    );
                    assert_eq!(resp.rejected_patterns.len(), 2);
                    // Check reason codes are WILDCARD_NOT_ALLOWED
                    for rejection in &resp.rejected_patterns {
                        assert_eq!(
                            rejection.reason_code, "WILDCARD_NOT_ALLOWED",
                            "Expected WILDCARD_NOT_ALLOWED for pattern: {}",
                            rejection.pattern
                        );
                    }
                },
                _ => panic!("Expected SubscribePulse response, got: {response:?}"),
            }
        }

        /// TCK-00302: Invalid patterns are rejected with `INVALID_PATTERN`.
        #[test]
        fn test_invalid_pattern_rejected() {
            let minter = test_minter();
            let dispatcher = SessionDispatcher::new(minter.clone());
            let ctx = make_session_ctx();
            let token = test_token(&minter);

            let request = SubscribePulseRequest {
                session_token: serde_json::to_string(&token).unwrap(),
                client_sub_id: "client-sub-003".to_string(),
                topic_patterns: vec![
                    "invalid..topic".to_string(), // Empty segment
                    "regex.[a-z]".to_string(),    // Regex pattern
                ],
                since_ledger_cursor: 0,
                max_pulses_per_sec: 100,
            };
            let frame = encode_subscribe_pulse_request(&request);

            let response = dispatcher.dispatch(&frame, &ctx).unwrap();
            match response {
                SessionResponse::SubscribePulse(resp) => {
                    assert!(resp.accepted_patterns.is_empty());
                    assert_eq!(resp.rejected_patterns.len(), 2);
                    for rejection in &resp.rejected_patterns {
                        assert_eq!(
                            rejection.reason_code, "INVALID_PATTERN",
                            "Expected INVALID_PATTERN for pattern: {}",
                            rejection.pattern
                        );
                    }
                },
                _ => panic!("Expected SubscribePulse response, got: {response:?}"),
            }
        }

        /// TCK-00302: Too many patterns in request returns error.
        #[test]
        fn test_too_many_patterns_rejected() {
            let minter = test_minter();
            let dispatcher = SessionDispatcher::new(minter.clone());
            let ctx = make_session_ctx();
            let token = test_token(&minter);

            // Create more than 16 patterns
            let patterns: Vec<String> = (0..17).map(|i| format!("topic.{i}")).collect();

            let request = SubscribePulseRequest {
                session_token: serde_json::to_string(&token).unwrap(),
                client_sub_id: "client-sub-004".to_string(),
                topic_patterns: patterns,
                since_ledger_cursor: 0,
                max_pulses_per_sec: 100,
            };
            let frame = encode_subscribe_pulse_request(&request);

            let response = dispatcher.dispatch(&frame, &ctx).unwrap();
            match response {
                SessionResponse::Error(err) => {
                    assert_eq!(
                        err.code,
                        SessionErrorCode::SessionErrorInvalid as i32,
                        "Expected INVALID error for too many patterns"
                    );
                    assert!(
                        err.message.contains("too many patterns"),
                        "Error message should mention too many patterns: {}",
                        err.message
                    );
                },
                _ => panic!("Expected Error response for too many patterns, got: {response:?}"),
            }
        }

        /// TCK-00302: Client subscription ID too long returns error.
        #[test]
        fn test_client_sub_id_too_long() {
            let minter = test_minter();
            let dispatcher = SessionDispatcher::new(minter.clone());
            let ctx = make_session_ctx();
            let token = test_token(&minter);

            let request = SubscribePulseRequest {
                session_token: serde_json::to_string(&token).unwrap(),
                client_sub_id: "a".repeat(65), // MAX_CLIENT_SUB_ID_LEN is 64
                topic_patterns: vec!["work.W-123.events".to_string()],
                since_ledger_cursor: 0,
                max_pulses_per_sec: 100,
            };
            let frame = encode_subscribe_pulse_request(&request);

            let response = dispatcher.dispatch(&frame, &ctx).unwrap();
            match response {
                SessionResponse::Error(err) => {
                    assert_eq!(
                        err.code,
                        SessionErrorCode::SessionErrorInvalid as i32,
                        "Expected INVALID error for too long client_sub_id"
                    );
                },
                _ => panic!("Expected Error response, got: {response:?}"),
            }
        }

        /// TCK-00302: Unsubscribe validates subscription ID length.
        #[test]
        fn test_unsubscribe_validates_subscription_id() {
            let minter = test_minter();
            let dispatcher = SessionDispatcher::new(minter.clone());
            let ctx = make_session_ctx();
            let token = test_token(&minter);

            let request = UnsubscribePulseRequest {
                session_token: serde_json::to_string(&token).unwrap(),
                subscription_id: "a".repeat(65), // MAX_SUBSCRIPTION_ID_LEN is 64
            };
            let frame = encode_unsubscribe_pulse_request(&request);

            let response = dispatcher.dispatch(&frame, &ctx).unwrap();
            match response {
                SessionResponse::Error(err) => {
                    assert_eq!(
                        err.code,
                        SessionErrorCode::SessionErrorInvalid as i32,
                        "Expected INVALID error for too long subscription_id"
                    );
                },
                _ => panic!("Expected Error response, got: {response:?}"),
            }
        }

        /// TCK-00302: Valid unsubscribe request succeeds.
        #[test]
        fn test_valid_unsubscribe() {
            let minter = test_minter();
            let dispatcher = SessionDispatcher::new(minter.clone());
            let ctx = make_session_ctx();
            let token = test_token(&minter);

            let request = UnsubscribePulseRequest {
                session_token: serde_json::to_string(&token).unwrap(),
                subscription_id: "SUB-test-123".to_string(),
            };
            let frame = encode_unsubscribe_pulse_request(&request);

            let response = dispatcher.dispatch(&frame, &ctx).unwrap();
            match response {
                SessionResponse::UnsubscribePulse(resp) => {
                    // Placeholder returns true until subscription registry is implemented
                    assert!(resp.removed);
                },
                _ => panic!("Expected UnsubscribePulse response, got: {response:?}"),
            }
        }

        /// TCK-00302: `PulseEvent` received from client is rejected.
        #[test]
        fn test_pulse_event_from_client_rejected() {
            let minter = test_minter();
            let dispatcher = SessionDispatcher::new(minter);
            let ctx = make_session_ctx();

            // PulseEvent is server-to-client only, tag = 68
            let frame = Bytes::from(vec![68u8, 0, 0, 0]);

            let response = dispatcher.dispatch(&frame, &ctx).unwrap();
            match response {
                SessionResponse::Error(err) => {
                    assert_eq!(
                        err.code,
                        SessionErrorCode::SessionErrorInvalid as i32,
                        "Expected INVALID error for PulseEvent from client"
                    );
                    assert!(err.message.contains("server-to-client only"));
                },
                _ => panic!("Expected Error response for PulseEvent, got: {response:?}"),
            }
        }

        /// TCK-00302: Subscribe with invalid token returns
        /// `SESSION_ERROR_INVALID`.
        #[test]
        fn test_subscribe_invalid_token() {
            let minter = test_minter();
            let dispatcher = SessionDispatcher::new(minter);
            let ctx = make_session_ctx();

            let request = SubscribePulseRequest {
                session_token: "invalid-token".to_string(),
                client_sub_id: "client-sub-005".to_string(),
                topic_patterns: vec!["work.W-123.events".to_string()],
                since_ledger_cursor: 0,
                max_pulses_per_sec: 100,
            };
            let frame = encode_subscribe_pulse_request(&request);

            let response = dispatcher.dispatch(&frame, &ctx).unwrap();
            match response {
                SessionResponse::Error(err) => {
                    assert_eq!(
                        err.code,
                        SessionErrorCode::SessionErrorInvalid as i32,
                        "Expected SESSION_ERROR_INVALID for invalid token"
                    );
                },
                _ => panic!("Expected Error response for invalid token, got: {response:?}"),
            }
        }

        /// TCK-00302: Response encoding includes correct tags.
        #[test]
        fn test_subscribe_response_encoding() {
            let response = SessionResponse::SubscribePulse(SubscribePulseResponse {
                subscription_id: "SUB-test".to_string(),
                effective_since_cursor: 42,
                accepted_patterns: vec!["topic.a".to_string()],
                rejected_patterns: vec![],
            });
            let encoded = response.encode();

            // Tag 65 is SUBSCRIBE_PULSE_RESPONSE_TAG
            assert_eq!(encoded[0], 65);
            assert!(encoded.len() > 1);
        }

        /// TCK-00302: Unsubscribe response encoding includes correct tag.
        #[test]
        fn test_unsubscribe_response_encoding() {
            let response =
                SessionResponse::UnsubscribePulse(UnsubscribePulseResponse { removed: true });
            let encoded = response.encode();

            // Tag 67 is UNSUBSCRIBE_PULSE_RESPONSE_TAG
            assert_eq!(encoded[0], 67);
            assert!(encoded.len() > 1);
        }
    }

    // ========================================================================
    // TCK-00316: Tool Execution Integration Tests
    // ========================================================================
    mod tool_execution {
        use std::sync::atomic::{AtomicUsize, Ordering};

        use apm2_core::crypto::Hash;
        use apm2_core::pcac::{
            AuthorityConsumeRecordV1, AuthorityConsumedV1, AuthorityDenyClass, AuthorityDenyV1,
            AuthorityJoinCertificateV1, AuthorityJoinInputV1, AuthorityJoinKernel,
        };

        use super::*;
        use crate::episode::preactuation::{PreActuationGate, StopAuthority};
        use crate::episode::{InMemorySessionRegistry, ToolBroker, ToolBrokerConfig, ToolClass};
        use crate::htf::{ClockConfig, HolonicClock};
        use crate::protocol::dispatch::{LedgerEventEmitter, StubLedgerEventEmitter};
        use crate::session::{SessionRegistry, SessionState, SessionTelemetryStore};

        /// TCK-00316: Verify fail-closed behavior when broker is configured but
        /// holonic clock is missing.
        ///
        /// Per SEC-CTRL-FAC-0015, the dispatcher must fail-closed when required
        /// infrastructure (clock, runtime) is missing. This test verifies the
        /// clock check happens before broker request.
        ///
        /// TCK-00351 BLOCKER 2 v2 FIX: Broker now requires a gate; this test
        /// wires a default gate so the clock check is the first failure point.
        #[test]
        fn test_request_tool_fails_closed_without_clock() {
            use crate::episode::preactuation::{PreActuationGate, StopAuthority};

            let minter = test_minter();
            let store = Arc::new(InMemoryManifestStore::new());

            // Build manifest with Read allowed
            let manifest = tck_00260_manifest_validation::make_test_manifest(vec![ToolClass::Read]);
            store.register("session-001", manifest);

            // Create broker with default config
            let broker = Arc::new(ToolBroker::new(ToolBrokerConfig::default()));

            // Wire a gate (required since BLOCKER 2 fix) but no clock
            let authority = Arc::new(StopAuthority::new());
            let gate = Arc::new(PreActuationGate::production_gate(authority, None));

            // Create dispatcher WITH broker and gate but WITHOUT clock
            let dispatcher = SessionDispatcher::with_manifest_store(minter.clone(), store)
                .with_broker(broker)
                .with_preactuation_gate(gate);

            let token = test_token(&minter);
            let ctx = make_session_ctx();

            // Send a RequestTool request for Read
            let request = RequestToolRequest {
                session_token: serde_json::to_string(&token).unwrap(),
                tool_id: "read".to_string(),
                arguments: vec![],
                dedupe_key: "test-dedupe-key".to_string(),
                epoch_seal: None,
            };
            let frame = encode_request_tool_request(&request);

            // Should return protocol error for missing clock (fail-closed)
            // The gate check calls get_htf_timestamp() which fails
            // because no clock is configured.
            let result = dispatcher.dispatch(&frame, &ctx);
            match result {
                Err(ProtocolError::Serialization { reason }) => {
                    assert!(
                        reason.contains("holonic clock not configured"),
                        "Expected clock not configured error, got: {reason}"
                    );
                },
                other => panic!("Expected protocol error for missing clock, got: {other:?}"),
            }
        }

        #[test]
        fn test_request_tool_without_broker_skips_gate_clock_path() {
            use crate::episode::preactuation::{PreActuationGate, StopAuthority};

            let minter = test_minter();
            let store = Arc::new(InMemoryManifestStore::new());

            let manifest = tck_00260_manifest_validation::make_test_manifest(vec![ToolClass::Read]);
            store.register("session-001", manifest);

            // Gate is wired but broker and clock are intentionally absent.
            let authority = Arc::new(StopAuthority::new());
            let gate = Arc::new(PreActuationGate::production_gate(authority, None));
            let dispatcher = SessionDispatcher::with_manifest_store(minter.clone(), store)
                .with_preactuation_gate(gate);

            let token = test_token(&minter);
            let ctx = make_session_ctx();
            let request = RequestToolRequest {
                session_token: serde_json::to_string(&token).unwrap(),
                tool_id: "read".to_string(),
                arguments: vec![],
                dedupe_key: "test-no-broker-skip-gate".to_string(),
                epoch_seal: None,
            };
            let frame = encode_request_tool_request(&request);

            let response = dispatcher.dispatch(&frame, &ctx).unwrap();
            match response {
                SessionResponse::Error(err) => {
                    assert_eq!(
                        err.code,
                        SessionErrorCode::SessionErrorToolNotAllowed as i32
                    );
                    assert!(
                        err.message.contains("broker unavailable"),
                        "expected broker-unavailable denial, got: {}",
                        err.message
                    );
                    assert!(
                        !err.message.contains("holonic clock not configured"),
                        "must not fail through gate clock path when broker is absent"
                    );
                },
                other => panic!("Expected application-level denial, got: {other:?}"),
            }
        }

        #[test]
        fn test_replay_verifier_rejects_ordering_violation_in_production_path() {
            let minter = test_minter();
            let dispatcher = SessionDispatcher::new(minter);
            let episode_id = EpisodeId::new("session-001").expect("valid episode id");

            let decision = ToolDecision::Allow {
                request_id: "REQ-ORDER-001".to_string(),
                capability_id: "cap-read-001".to_string(),
                rule_id: Some("rule-read".to_string()),
                policy_hash: [0u8; 32],
                budget_delta: crate::episode::decision::BudgetDelta::single_call(),
                credential: None,
            };

            let receipt = crate::episode::preactuation::PreActuationReceipt {
                stop_checked: true,
                budget_checked: true,
                budget_enforcement_deferred: false,
                replay_timestamp: ReplayTimestamp::new(200, 0),
                timestamp_ns: 200,
            };

            // Actuation timestamp is deliberately older than the check timestamp
            // to trigger ReplayVerifier::OrderingViolation in production wiring.
            let response = dispatcher
                .handle_broker_decision(
                    Ok(decision),
                    "session-001",
                    ToolClass::Read,
                    b"{}",
                    ReplayTimestamp::new(100, 0),
                    &episode_id,
                    Some(&receipt),
                    None,
                    false,
                    None,
                )
                .expect("dispatch should return application-level error response");

            match response {
                SessionResponse::Error(err) => {
                    assert_eq!(err.code, SessionErrorCode::SessionErrorInternal as i32);
                    assert!(
                        err.message.contains("replay ordering verification failed"),
                        "expected replay verifier failure message, got: {}",
                        err.message
                    );
                },
                other => panic!("expected replay-verifier error response, got: {other:?}"),
            }
        }

        #[derive(Clone)]
        struct SequencingKernel {
            joins: Arc<AtomicUsize>,
            revalidations: Arc<AtomicUsize>,
            consumes: Arc<AtomicUsize>,
        }

        impl SequencingKernel {
            fn new(
                joins: Arc<AtomicUsize>,
                revalidations: Arc<AtomicUsize>,
                consumes: Arc<AtomicUsize>,
            ) -> Self {
                Self {
                    joins,
                    revalidations,
                    consumes,
                }
            }
        }

        impl AuthorityJoinKernel for SequencingKernel {
            fn join(
                &self,
                input: &AuthorityJoinInputV1,
            ) -> Result<AuthorityJoinCertificateV1, Box<AuthorityDenyV1>> {
                self.joins.fetch_add(1, Ordering::SeqCst);
                let mut hasher = blake3::Hasher::new();
                hasher.update(b"pcac-sequencing-test-ajc-v1");
                hasher.update(&input.intent_digest);
                hasher.update(input.session_id.as_bytes());
                let ajc_id = *hasher.finalize().as_bytes();

                Ok(AuthorityJoinCertificateV1 {
                    ajc_id,
                    authority_join_hash: *blake3::hash(&input.intent_digest).as_bytes(),
                    intent_digest: input.intent_digest,
                    risk_tier: input.risk_tier,
                    issued_time_envelope_ref: input.time_envelope_ref,
                    as_of_ledger_anchor: input.as_of_ledger_anchor,
                    expires_at_tick: u64::MAX,
                    revocation_head_hash: input.directory_head_hash,
                    identity_evidence_level: input.identity_evidence_level,
                    admission_capacity_token: None,
                })
            }

            fn revalidate(
                &self,
                cert: &AuthorityJoinCertificateV1,
                current_time_envelope_ref: Hash,
                current_ledger_anchor: Hash,
                current_revocation_head_hash: Hash,
            ) -> Result<(), Box<AuthorityDenyV1>> {
                self.revalidations.fetch_add(1, Ordering::SeqCst);
                if current_revocation_head_hash != cert.revocation_head_hash {
                    return Err(Box::new(AuthorityDenyV1 {
                        deny_class: AuthorityDenyClass::RevocationFrontierAdvanced,
                        ajc_id: Some(cert.ajc_id),
                        time_envelope_ref: current_time_envelope_ref,
                        ledger_anchor: current_ledger_anchor,
                        denied_at_tick: 0,
                    }));
                }
                Ok(())
            }

            fn consume(
                &self,
                cert: &AuthorityJoinCertificateV1,
                intent_digest: Hash,
                current_time_envelope_ref: Hash,
            ) -> Result<(AuthorityConsumedV1, AuthorityConsumeRecordV1), Box<AuthorityDenyV1>>
            {
                self.consumes.fetch_add(1, Ordering::SeqCst);
                if intent_digest != cert.intent_digest {
                    return Err(Box::new(AuthorityDenyV1 {
                        deny_class: AuthorityDenyClass::IntentDigestMismatch {
                            expected: cert.intent_digest,
                            actual: intent_digest,
                        },
                        ajc_id: Some(cert.ajc_id),
                        time_envelope_ref: current_time_envelope_ref,
                        ledger_anchor: cert.as_of_ledger_anchor,
                        denied_at_tick: 0,
                    }));
                }

                let witness = AuthorityConsumedV1 {
                    ajc_id: cert.ajc_id,
                    intent_digest,
                    consumed_time_envelope_ref: current_time_envelope_ref,
                    consumed_at_tick: 1,
                };
                let record = AuthorityConsumeRecordV1 {
                    ajc_id: cert.ajc_id,
                    consumed_time_envelope_ref: current_time_envelope_ref,
                    consumed_at_tick: 1,
                    effect_selector_digest: *blake3::hash(&intent_digest).as_bytes(),
                };
                Ok((witness, record))
            }
        }

        #[test]
        fn test_pcac_consume_occurs_after_broker_decision() {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("failed to build tokio runtime");

            rt.block_on(async {
                let minter = test_minter();
                let joins = Arc::new(AtomicUsize::new(0));
                let revalidations = Arc::new(AtomicUsize::new(0));
                let consumes = Arc::new(AtomicUsize::new(0));

                let manifest_store = Arc::new(InMemoryManifestStore::new());
                manifest_store.register(
                    "session-001",
                    super::tck_00260_manifest_validation::make_test_manifest(vec![ToolClass::Read]),
                );

                let broker = Arc::new(ToolBroker::new(
                    ToolBrokerConfig::default().without_policy_check(),
                ));
                broker
                    .initialize_with_manifest(
                        super::tck_00260_manifest_validation::make_test_manifest(vec![
                            ToolClass::Search,
                        ]),
                    )
                    .await
                    .expect("broker manifest initialization");

                let registry = Arc::new(InMemorySessionRegistry::new());
                registry
                    .register_session(SessionState {
                        session_id: "session-001".to_string(),
                        work_id: "W-PCAC-ORDER".to_string(),
                        role: crate::protocol::messages::WorkRole::Implementer.into(),
                        lease_id: "lease-001".to_string(),
                        ephemeral_handle: "handle-pcac-order".to_string(),
                        policy_resolved_ref: "policy-head-ref".to_string(),
                        capability_manifest_hash: blake3::hash(b"pcac-order-manifest")
                            .as_bytes()
                            .to_vec(),
                        episode_id: Some("session-001".to_string()),
                    })
                    .expect("session registration");
                let registry_dyn: Arc<dyn SessionRegistry> = registry;

                let telemetry_store = Arc::new(SessionTelemetryStore::new());
                let started_at_ns = std::time::SystemTime::now()
                    .duration_since(std::time::SystemTime::UNIX_EPOCH)
                    .map(|duration| {
                        #[allow(clippy::cast_possible_truncation)]
                        let value = duration.as_nanos() as u64;
                        value
                    })
                    .unwrap_or(1);
                telemetry_store
                    .register("session-001", started_at_ns)
                    .expect("telemetry registration");

                let clock =
                    Arc::new(HolonicClock::new(ClockConfig::default(), None).expect("clock"));
                let stop_authority = Arc::new(StopAuthority::new());
                let preactuation_gate = Arc::new(PreActuationGate::production_gate(
                    Arc::clone(&stop_authority),
                    None,
                ));
                let ledger: Arc<dyn LedgerEventEmitter> = Arc::new(StubLedgerEventEmitter::new());

                let kernel: Arc<dyn AuthorityJoinKernel> = Arc::new(SequencingKernel::new(
                    Arc::clone(&joins),
                    Arc::clone(&revalidations),
                    Arc::clone(&consumes),
                ));
                let pcac_gate = Arc::new(crate::pcac::LifecycleGate::new(kernel));

                let dispatcher =
                    SessionDispatcher::with_manifest_store(minter.clone(), manifest_store)
                        .with_broker(broker)
                        .with_clock(clock)
                        .with_ledger(ledger)
                        .with_session_registry(registry_dyn)
                        .with_telemetry_store(telemetry_store)
                        .with_preactuation_gate(preactuation_gate)
                        .with_stop_authority(stop_authority)
                        .with_pcac_lifecycle_gate(pcac_gate);

                let token = test_token(&minter);
                let request = RequestToolRequest {
                    session_token: serde_json::to_string(&token).expect("token serialization"),
                    tool_id: "read".to_string(),
                    arguments: serde_json::to_vec(&serde_json::json!({"path": "/tmp/input"}))
                        .expect("arguments serialization"),
                    dedupe_key: "pcac-ordering-deny".to_string(),
                    epoch_seal: None,
                };
                let frame = encode_request_tool_request(&request);
                let response = dispatcher
                    .dispatch(&frame, &make_session_ctx())
                    .expect("dispatch should return application-level response");

                match response {
                    SessionResponse::RequestTool(resp) => {
                        assert_eq!(
                            resp.decision,
                            i32::from(DecisionType::Deny),
                            "broker should deny read when only search is allowed"
                        );
                    },
                    other => panic!("expected broker deny response, got: {other:?}"),
                }

                assert!(
                    joins.load(Ordering::SeqCst) > 0,
                    "join should run before broker decision"
                );
                assert!(
                    revalidations.load(Ordering::SeqCst) > 0,
                    "revalidate-before-decision should run before broker decision"
                );
                assert_eq!(
                    consumes.load(Ordering::SeqCst),
                    0,
                    "consume must not run on broker deny; it is executed only on allow/effect path"
                );
            });
        }

        /// TCK-00336: Verify fail-closed behavior when no broker is configured.
        ///
        /// When no broker is configured, the dispatcher returns a fail-closed
        /// error rather than falling back to legacy manifest validation.
        #[test]
        fn test_request_tool_fails_closed_without_broker() {
            let minter = test_minter();
            let store = Arc::new(InMemoryManifestStore::new());

            // Build manifest with Read allowed
            let manifest = tck_00260_manifest_validation::make_test_manifest(vec![ToolClass::Read]);
            store.register("session-001", manifest);

            // Create dispatcher WITHOUT broker (legacy path)
            let dispatcher = SessionDispatcher::with_manifest_store(minter.clone(), store);

            let token = test_token(&minter);
            let ctx = make_session_ctx();

            // Send a RequestTool request for Read
            let request = RequestToolRequest {
                session_token: serde_json::to_string(&token).unwrap(),
                tool_id: "read".to_string(),
                arguments: vec![],
                dedupe_key: "test-dedupe-key".to_string(),
                epoch_seal: None,
            };
            let frame = encode_request_tool_request(&request);
            let response = dispatcher.dispatch(&frame, &ctx).unwrap();

            // Should return Error (fail-closed)
            match response {
                SessionResponse::Error(err) => {
                    assert_eq!(
                        err.code,
                        SessionErrorCode::SessionErrorToolNotAllowed as i32,
                        "Expected TOOL_NOT_ALLOWED error code (fail-closed)"
                    );
                    assert!(
                        err.message.contains("broker unavailable"),
                        "Error message should indicate broker unavailable: {}",
                        err.message
                    );
                },
                other => panic!("Expected Error response, got: {other:?}"),
            }
        }

        /// TCK-00351 BLOCKER 2 v2 FIX: Broker configured without
        /// pre-actuation gate must be denied (fail-closed).
        ///
        /// This regression test verifies that when a broker is configured
        /// but the pre-actuation gate is missing, `RequestTool` is
        /// hard-denied instead of proceeding without proof fields.
        #[test]
        fn test_request_tool_denied_broker_without_gate() {
            let minter = test_minter();
            let store = Arc::new(InMemoryManifestStore::new());

            let manifest = tck_00260_manifest_validation::make_test_manifest(vec![ToolClass::Read]);
            store.register("session-001", manifest);

            let broker = Arc::new(ToolBroker::new(ToolBrokerConfig::default()));
            let clock = Arc::new(
                HolonicClock::new(ClockConfig::default(), None)
                    .expect("default ClockConfig should succeed"),
            );

            // Create dispatcher WITH broker and clock but WITHOUT gate
            let dispatcher = SessionDispatcher::with_manifest_store(minter.clone(), store)
                .with_broker(broker)
                .with_clock(clock);

            let token = test_token(&minter);
            let ctx = make_session_ctx();

            let request = RequestToolRequest {
                session_token: serde_json::to_string(&token).unwrap(),
                tool_id: "read".to_string(),
                arguments: vec![],
                dedupe_key: "test-dedupe-no-gate".to_string(),
                epoch_seal: None,
            };
            let frame = encode_request_tool_request(&request);
            let response = dispatcher.dispatch(&frame, &ctx).unwrap();

            match response {
                SessionResponse::Error(err) => {
                    assert_eq!(
                        err.code,
                        SessionErrorCode::SessionErrorToolNotAllowed as i32,
                        "Expected TOOL_NOT_ALLOWED for missing gate"
                    );
                    assert!(
                        err.message.contains("pre-actuation gate not configured"),
                        "Error should mention missing gate: {}",
                        err.message
                    );
                },
                other => panic!("Expected error for broker-without-gate, got: {other:?}"),
            }
        }
    }

    mod tck_00375_firewall_enforcement {
        use std::sync::atomic::{AtomicUsize, Ordering};

        use apm2_core::context::{AccessLevel, ContextPackManifestBuilder, ManifestEntryBuilder};
        use serde_json::Value;
        use tempfile::tempdir;

        use super::*;
        use crate::episode::decision::Credential;
        use crate::episode::preactuation::{PreActuationGate, StopAuthority};
        use crate::episode::tool_handler::ToolArgs;
        use crate::episode::{
            BudgetDelta, Capability, CapabilityManifestBuilder, CapabilityScope, EpisodeRuntime,
            EpisodeRuntimeConfig, InMemorySessionRegistry, RiskTier, StubContentAddressedStore,
            ToolBroker, ToolBrokerConfig, ToolClass, ToolHandler, ToolHandlerError, ToolResultData,
        };
        use crate::htf::{ClockConfig, HolonicClock};
        use crate::protocol::dispatch::{LedgerEventEmitter, StubLedgerEventEmitter};
        use crate::session::SessionRegistry;

        fn make_tier3_read_manifest(manifest_id: &str) -> crate::episode::CapabilityManifest {
            let capability = Capability {
                capability_id: "cap-read-tier3".to_string(),
                tool_class: ToolClass::Read,
                scope: CapabilityScope {
                    root_paths: Vec::new(),
                    allowed_patterns: Vec::new(),
                    size_limits: crate::episode::scope::SizeLimits::default_limits(),
                    network_policy: None,
                },
                risk_tier_required: RiskTier::Tier3,
            };

            CapabilityManifestBuilder::new(manifest_id)
                .delegator("test-delegator")
                .capabilities(vec![capability])
                .tool_allowlist(vec![ToolClass::Read])
                .build()
                .expect("tier3 manifest build should succeed")
        }

        fn register_session(
            registry: &Arc<InMemorySessionRegistry>,
            session_id: &str,
        ) -> Arc<dyn crate::session::SessionRegistry> {
            registry
                .register_session(crate::session::SessionState {
                    session_id: session_id.to_string(),
                    work_id: "W-TCK-00375".to_string(),
                    role: crate::protocol::messages::WorkRole::Implementer.into(),
                    lease_id: "L-TCK-00375".to_string(),
                    ephemeral_handle: "handle-tck-00375".to_string(),
                    // TCK-00426: PCAC gate requires non-empty manifest hash
                    // and policy_resolved_ref in authoritative mode.
                    policy_resolved_ref: "test-policy-ref".to_string(),
                    capability_manifest_hash: blake3::hash(b"test-manifest").as_bytes().to_vec(),
                    episode_id: Some(session_id.to_string()),
                })
                .expect("session registration should succeed");

            Arc::clone(registry) as Arc<dyn crate::session::SessionRegistry>
        }

        #[derive(Debug)]
        struct CountingReadHandler {
            executions: Arc<AtomicUsize>,
        }

        #[async_trait::async_trait]
        impl ToolHandler for CountingReadHandler {
            fn tool_class(&self) -> ToolClass {
                ToolClass::Read
            }

            async fn execute(
                &self,
                _args: &ToolArgs,
                _credential: Option<&Credential>,
            ) -> Result<ToolResultData, ToolHandlerError> {
                self.executions.fetch_add(1, Ordering::SeqCst);
                Ok(ToolResultData::success(
                    b"should-not-execute".to_vec(),
                    BudgetDelta::single_call(),
                    std::time::Duration::from_millis(1),
                ))
            }

            fn validate(&self, _args: &ToolArgs) -> Result<(), ToolHandlerError> {
                Ok(())
            }

            fn name(&self) -> &'static str {
                "CountingReadHandler"
            }
        }

        #[derive(Debug)]
        struct CountingSearchHandler {
            executions: Arc<AtomicUsize>,
        }

        #[async_trait::async_trait]
        impl ToolHandler for CountingSearchHandler {
            fn tool_class(&self) -> ToolClass {
                ToolClass::Search
            }

            async fn execute(
                &self,
                _args: &ToolArgs,
                _credential: Option<&Credential>,
            ) -> Result<ToolResultData, ToolHandlerError> {
                self.executions.fetch_add(1, Ordering::SeqCst);
                Ok(ToolResultData::success(
                    b"should-not-execute".to_vec(),
                    BudgetDelta::single_call(),
                    std::time::Duration::from_millis(1),
                ))
            }

            fn validate(&self, _args: &ToolArgs) -> Result<(), ToolHandlerError> {
                Ok(())
            }

            fn name(&self) -> &'static str {
                "CountingSearchHandler"
            }
        }

        #[test]
        fn test_tier3_toctou_mismatch_terminates_and_emits_defect_record() {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("failed to build tokio runtime");

            rt.block_on(async {
                let minter = test_minter();
                let temp_dir = tempdir().expect("temp dir");
                let source_path = temp_dir.path().join("source.rs");
                let source_bytes = b"fn safe() {}";
                tokio::fs::write(&source_path, source_bytes)
                    .await
                    .expect("write source file");
                let source_path_str = source_path.to_string_lossy().to_string();

                let mismatched_hash = *blake3::hash(b"tampered-bytes").as_bytes();
                let context_manifest =
                    ContextPackManifestBuilder::new("ctx-manifest-tier3", "profile-tier3")
                        .add_entry(
                            ManifestEntryBuilder::new(&source_path_str, mismatched_hash)
                                .access_level(AccessLevel::Read)
                                .build(),
                        )
                        .build();

                let broker = Arc::new(ToolBroker::new(
                    ToolBrokerConfig::default().without_policy_check(),
                ));
                broker
                    .initialize_with_manifest(make_tier3_read_manifest("broker-manifest-tier3"))
                    .await
                    .expect("broker manifest init");
                broker
                    .initialize_with_context_manifest(context_manifest)
                    .await
                    .expect("context manifest init");

                let executions = Arc::new(AtomicUsize::new(0));
                let cas: Arc<dyn crate::episode::ContentAddressedStore> =
                    Arc::new(StubContentAddressedStore::new());
                #[allow(deprecated)]
                let episode_runtime = Arc::new(
                    EpisodeRuntime::new(EpisodeRuntimeConfig::default())
                        .with_cas(cas)
                        .with_handler_factory({
                            let executions = Arc::clone(&executions);
                            move || {
                                Box::new(CountingReadHandler {
                                    executions: Arc::clone(&executions),
                                }) as Box<dyn ToolHandler>
                            }
                        }),
                );
                let episode_id = episode_runtime
                    .create(*blake3::hash(b"tck-00375-envelope").as_bytes(), 1_000_000)
                    .await
                    .expect("create episode");
                #[allow(deprecated)]
                let _handle = episode_runtime
                    .start(&episode_id, "lease-001", 2_000_000)
                    .await
                    .expect("start episode");
                let session_id = episode_id.as_str().to_string();

                let manifest_store = Arc::new(InMemoryManifestStore::new());
                manifest_store.register(
                    &session_id,
                    make_tier3_read_manifest("dispatch-manifest-tier3"),
                );

                let registry = Arc::new(InMemorySessionRegistry::new());
                let registry_dyn = register_session(&registry, &session_id);
                let telemetry_store = Arc::new(crate::session::SessionTelemetryStore::new());
                let started_at_ns = std::time::SystemTime::now()
                    .duration_since(std::time::SystemTime::UNIX_EPOCH)
                    .map(|d| {
                        #[allow(clippy::cast_possible_truncation)]
                        let ns = d.as_nanos() as u64;
                        ns
                    })
                    .unwrap_or(0);
                telemetry_store
                    .register(&session_id, started_at_ns)
                    .expect("telemetry registration should succeed");

                let clock =
                    Arc::new(HolonicClock::new(ClockConfig::default(), None).expect("clock"));
                let stop_authority = Arc::new(StopAuthority::new());
                let preactuation_gate = Arc::new(PreActuationGate::production_gate(
                    Arc::clone(&stop_authority),
                    None,
                ));

                let ledger = Arc::new(StubLedgerEventEmitter::new());
                let ledger_dyn: Arc<dyn LedgerEventEmitter> = ledger.clone();

                // TCK-00426: Wire PCAC gate — required in authoritative mode (fail-closed).
                let pcac_kernel: Arc<dyn apm2_core::pcac::AuthorityJoinKernel> =
                    Arc::new(crate::pcac::InProcessKernel::new(1));
                let pcac_gate = Arc::new(crate::pcac::LifecycleGate::new(pcac_kernel));
                let dispatcher =
                    SessionDispatcher::with_manifest_store(minter.clone(), manifest_store)
                        .with_broker(broker)
                        .with_clock(clock)
                        .with_ledger(ledger_dyn)
                        .with_episode_runtime(episode_runtime)
                        .with_session_registry(registry_dyn)
                        .with_telemetry_store(Arc::clone(&telemetry_store))
                        .with_preactuation_gate(preactuation_gate)
                        .with_stop_authority(stop_authority)
                        .with_pcac_lifecycle_gate(pcac_gate);

                let spawn_time = std::time::SystemTime::now();
                let token = minter
                    .mint(
                        &session_id,
                        "lease-001",
                        spawn_time,
                        Duration::from_secs(3600),
                    )
                    .expect("mint token");
                let ctx = ConnectionContext::session_open(
                    Some(crate::protocol::credentials::PeerCredentials {
                        uid: 1000,
                        gid: 1000,
                        pid: Some(12346),
                    }),
                    Some(session_id.clone()),
                );

                let request_args = serde_json::json!({
                    "type": "read",
                    "path": source_path_str,
                });
                let request = RequestToolRequest {
                    session_token: serde_json::to_string(&token).expect("token serialization"),
                    tool_id: "read".to_string(),
                    arguments: serde_json::to_vec(&request_args)
                        .expect("request args serialization"),
                    dedupe_key: "tck-00375-tier3-toctou".to_string(),
                    epoch_seal: None,
                };
                let frame = encode_request_tool_request(&request);
                let response = dispatcher
                    .dispatch(&frame, &ctx)
                    .expect("dispatch should succeed");

                match response {
                    SessionResponse::Error(err) => {
                        assert_eq!(
                            err.code,
                            SessionErrorCode::SessionErrorToolNotAllowed as i32,
                            "tier3 TOCTOU mismatch must terminate/deny"
                        );
                        assert!(
                            err.message.contains("session terminated"),
                            "termination response should be returned, got: {}",
                            err.message
                        );
                    },
                    other => panic!("expected error response for TOCTOU mismatch, got: {other:?}"),
                }

                assert_eq!(
                    executions.load(Ordering::SeqCst),
                    0,
                    "tool execution must not occur when pre-execution TOCTOU check fails"
                );

                let termination = registry.get_termination_info(&session_id);
                assert!(
                    termination.is_some(),
                    "tier3 TOCTOU mismatch must mark the session terminated"
                );

                let defect_events: Vec<_> = ledger
                    .get_events_by_work_id(&session_id)
                    .into_iter()
                    .filter(|event| event.event_type == "defect_recorded")
                    .collect();
                assert!(
                    !defect_events.is_empty(),
                    "tier3 TOCTOU mismatch must emit authoritative DefectRecorded event"
                );

                let payload: Value =
                    serde_json::from_slice(&defect_events[0].payload).expect("defect payload json");
                assert_eq!(
                    payload.get("defect_type").and_then(Value::as_str),
                    Some("CONTEXT_FIREWALL_TOCTOU_MISMATCH"),
                    "defect payload must identify TOCTOU mismatch"
                );
            });
        }

        #[test]
        fn test_mandatory_defect_terminates_before_search_actuation() {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("failed to build tokio runtime");

            rt.block_on(async {
                let minter = test_minter();
                let temp_dir = tempdir().expect("temp dir");
                let scope_path = temp_dir.path().join("scope");
                tokio::fs::create_dir(&scope_path)
                    .await
                    .expect("create scope dir");
                let file_path = scope_path.join("note.txt");
                tokio::fs::write(&file_path, b"needle")
                    .await
                    .expect("write scope file");
                let scope_path_str = scope_path.to_string_lossy().to_string();

                // Context manifest admits the search scope but not files under it.
                // Broker will allow the tool and emit TOCTOU defects for excluded
                // file bytes.
                let context_manifest =
                    ContextPackManifestBuilder::new("ctx-manifest-tier3-search", "profile-tier3")
                        .add_entry(
                            ManifestEntryBuilder::new(&scope_path_str, [0x11; 32])
                                .access_level(AccessLevel::Read)
                                .build(),
                        )
                        .build();

                let broker = Arc::new(ToolBroker::new(
                    ToolBrokerConfig::default().without_policy_check(),
                ));
                let search_capability = Capability {
                    capability_id: "cap-search-tier3".to_string(),
                    tool_class: ToolClass::Search,
                    scope: CapabilityScope {
                        root_paths: Vec::new(),
                        allowed_patterns: Vec::new(),
                        size_limits: crate::episode::scope::SizeLimits::default_limits(),
                        network_policy: None,
                    },
                    risk_tier_required: RiskTier::Tier3,
                };
                let broker_manifest =
                    CapabilityManifestBuilder::new("broker-manifest-tier3-search")
                        .delegator("test-delegator")
                        .capabilities(vec![search_capability.clone()])
                        .tool_allowlist(vec![ToolClass::Search])
                        .build()
                        .expect("tier3 search manifest build should succeed");
                broker
                    .initialize_with_manifest(broker_manifest)
                    .await
                    .expect("broker manifest init");
                broker
                    .initialize_with_context_manifest(context_manifest)
                    .await
                    .expect("context manifest init");

                let executions = Arc::new(AtomicUsize::new(0));
                let cas: Arc<dyn crate::episode::ContentAddressedStore> =
                    Arc::new(StubContentAddressedStore::new());
                #[allow(deprecated)]
                let episode_runtime = Arc::new(
                    EpisodeRuntime::new(EpisodeRuntimeConfig::default())
                        .with_cas(cas)
                        .with_handler_factory({
                            let executions = Arc::clone(&executions);
                            move || {
                                Box::new(CountingSearchHandler {
                                    executions: Arc::clone(&executions),
                                }) as Box<dyn ToolHandler>
                            }
                        }),
                );
                let episode_id = episode_runtime
                    .create(
                        *blake3::hash(b"tck-00375-search-envelope").as_bytes(),
                        1_000_000,
                    )
                    .await
                    .expect("create episode");
                #[allow(deprecated)]
                let _handle = episode_runtime
                    .start(&episode_id, "lease-001", 2_000_000)
                    .await
                    .expect("start episode");
                let session_id = episode_id.as_str().to_string();

                let manifest_store = Arc::new(InMemoryManifestStore::new());
                let dispatch_manifest =
                    CapabilityManifestBuilder::new("dispatch-manifest-tier3-search")
                        .delegator("test-delegator")
                        .capabilities(vec![search_capability])
                        .tool_allowlist(vec![ToolClass::Search])
                        .build()
                        .expect("dispatch search manifest");
                manifest_store.register(&session_id, dispatch_manifest);

                let registry = Arc::new(InMemorySessionRegistry::new());
                let registry_dyn = register_session(&registry, &session_id);
                let telemetry_store = Arc::new(crate::session::SessionTelemetryStore::new());
                let started_at_ns = std::time::SystemTime::now()
                    .duration_since(std::time::SystemTime::UNIX_EPOCH)
                    .map(|d| {
                        #[allow(clippy::cast_possible_truncation)]
                        let ns = d.as_nanos() as u64;
                        ns
                    })
                    .unwrap_or(0);
                telemetry_store
                    .register(&session_id, started_at_ns)
                    .expect("telemetry registration should succeed");

                let clock =
                    Arc::new(HolonicClock::new(ClockConfig::default(), None).expect("clock"));
                let stop_authority = Arc::new(StopAuthority::new());
                let preactuation_gate = Arc::new(PreActuationGate::production_gate(
                    Arc::clone(&stop_authority),
                    None,
                ));

                let ledger_dyn: Arc<dyn LedgerEventEmitter> =
                    Arc::new(StubLedgerEventEmitter::new());

                // TCK-00426: Wire PCAC gate — required in authoritative mode (fail-closed).
                let pcac_kernel: Arc<dyn apm2_core::pcac::AuthorityJoinKernel> =
                    Arc::new(crate::pcac::InProcessKernel::new(1));
                let pcac_gate = Arc::new(crate::pcac::LifecycleGate::new(pcac_kernel));
                let dispatcher =
                    SessionDispatcher::with_manifest_store(minter.clone(), manifest_store)
                        .with_broker(broker)
                        .with_clock(clock)
                        .with_ledger(ledger_dyn)
                        .with_episode_runtime(episode_runtime)
                        .with_session_registry(registry_dyn)
                        .with_telemetry_store(Arc::clone(&telemetry_store))
                        .with_preactuation_gate(preactuation_gate)
                        .with_stop_authority(stop_authority)
                        .with_pcac_lifecycle_gate(pcac_gate);

                let spawn_time = std::time::SystemTime::now();
                let token = minter
                    .mint(
                        &session_id,
                        "lease-001",
                        spawn_time,
                        Duration::from_secs(3600),
                    )
                    .expect("mint token");
                let ctx = ConnectionContext::session_open(
                    Some(crate::protocol::credentials::PeerCredentials {
                        uid: 1000,
                        gid: 1000,
                        pid: Some(12346),
                    }),
                    Some(session_id.clone()),
                );

                let request_args = serde_json::json!({
                    "type": "search",
                    "query": "needle",
                    "scope": scope_path_str,
                });
                let request = RequestToolRequest {
                    session_token: serde_json::to_string(&token).expect("token serialization"),
                    tool_id: "search".to_string(),
                    arguments: serde_json::to_vec(&request_args)
                        .expect("request args serialization"),
                    dedupe_key: "tck-00375-tier3-search-defect".to_string(),
                    epoch_seal: None,
                };
                let frame = encode_request_tool_request(&request);
                let response = dispatcher
                    .dispatch(&frame, &ctx)
                    .expect("dispatch should succeed");

                match response {
                    SessionResponse::Error(err) => {
                        assert_eq!(
                            err.code,
                            SessionErrorCode::SessionErrorToolNotAllowed as i32,
                            "mandatory Tier3 defects must terminate before actuation"
                        );
                        assert!(
                            err.message.contains("session terminated"),
                            "termination response should be returned, got: {}",
                            err.message
                        );
                    },
                    other => panic!("expected termination response, got: {other:?}"),
                }

                assert_eq!(
                    executions.load(Ordering::SeqCst),
                    0,
                    "tool execution must not occur when mandatory defects are present"
                );

                let termination = registry.get_termination_info(&session_id);
                assert!(
                    termination.is_some(),
                    "mandatory Tier3 defects must mark the session terminated"
                );
            });
        }

        #[test]
        fn test_tier3_toctou_without_ledger_still_terminates_fail_closed() {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("failed to build tokio runtime");

            rt.block_on(async {
                let minter = test_minter();
                let temp_dir = tempdir().expect("temp dir");
                let source_path = temp_dir.path().join("source.rs");
                tokio::fs::write(&source_path, b"fn safe() {}")
                    .await
                    .expect("write source file");
                let source_path_str = source_path.to_string_lossy().to_string();

                let mismatched_hash = *blake3::hash(b"different-bytes").as_bytes();
                let context_manifest = ContextPackManifestBuilder::new(
                    "ctx-manifest-tier3-no-ledger",
                    "profile-tier3",
                )
                .add_entry(
                    ManifestEntryBuilder::new(&source_path_str, mismatched_hash)
                        .access_level(AccessLevel::Read)
                        .build(),
                )
                .build();

                let broker = Arc::new(ToolBroker::new(
                    ToolBrokerConfig::default().without_policy_check(),
                ));
                broker
                    .initialize_with_manifest(make_tier3_read_manifest("broker-manifest-no-ledger"))
                    .await
                    .expect("broker manifest init");
                broker
                    .initialize_with_context_manifest(context_manifest)
                    .await
                    .expect("context manifest init");

                let manifest_store = Arc::new(InMemoryManifestStore::new());

                let session_id = "session-tier3-no-ledger".to_string();
                manifest_store.register(
                    &session_id,
                    make_tier3_read_manifest("dispatch-manifest-no-ledger"),
                );

                let registry = Arc::new(InMemorySessionRegistry::new());
                let registry_dyn = register_session(&registry, &session_id);
                let telemetry_store = Arc::new(crate::session::SessionTelemetryStore::new());
                let started_at_ns = std::time::SystemTime::now()
                    .duration_since(std::time::SystemTime::UNIX_EPOCH)
                    .map(|d| {
                        #[allow(clippy::cast_possible_truncation)]
                        let ns = d.as_nanos() as u64;
                        ns
                    })
                    .unwrap_or(0);
                telemetry_store
                    .register(&session_id, started_at_ns)
                    .expect("telemetry registration should succeed");

                let clock =
                    Arc::new(HolonicClock::new(ClockConfig::default(), None).expect("clock"));
                let stop_authority = Arc::new(StopAuthority::new());
                let preactuation_gate = Arc::new(PreActuationGate::production_gate(
                    Arc::clone(&stop_authority),
                    None,
                ));

                let dispatcher =
                    SessionDispatcher::with_manifest_store(minter.clone(), manifest_store)
                        .with_broker(broker)
                        .with_clock(clock)
                        .with_session_registry(registry_dyn)
                        .with_telemetry_store(Arc::clone(&telemetry_store))
                        .with_preactuation_gate(preactuation_gate)
                        .with_stop_authority(stop_authority);

                let spawn_time = std::time::SystemTime::now();
                let token = minter
                    .mint(
                        &session_id,
                        "lease-001",
                        spawn_time,
                        Duration::from_secs(3600),
                    )
                    .expect("mint token");
                let ctx = ConnectionContext::session_open(
                    Some(crate::protocol::credentials::PeerCredentials {
                        uid: 1000,
                        gid: 1000,
                        pid: Some(12346),
                    }),
                    Some(session_id.clone()),
                );

                let request_args = serde_json::json!({
                    "type": "read",
                    "path": source_path_str,
                });
                let request = RequestToolRequest {
                    session_token: serde_json::to_string(&token).expect("token serialization"),
                    tool_id: "read".to_string(),
                    arguments: serde_json::to_vec(&request_args)
                        .expect("request args serialization"),
                    dedupe_key: "tck-00375-tier3-no-ledger".to_string(),
                    epoch_seal: None,
                };
                let frame = encode_request_tool_request(&request);
                let response = dispatcher
                    .dispatch(&frame, &ctx)
                    .expect("dispatch should succeed");

                match response {
                    SessionResponse::Error(err) => {
                        assert_eq!(
                            err.code,
                            SessionErrorCode::SessionErrorInternal as i32,
                            "defect persistence failure must fail closed"
                        );
                        assert!(
                            err.message.contains("firewall defect emission failed"),
                            "response must report authoritative defect emission failure: {}",
                            err.message
                        );
                    },
                    other => panic!("expected fail-closed error response, got: {other:?}"),
                }

                let termination = registry.get_termination_info(&session_id);
                assert!(
                    termination.is_some(),
                    "tier3 TOCTOU mismatch must terminate session even if defect persistence fails"
                );
            });
        }
    }

    // ========================================================================
    // TCK-00336: Broker Mediation Regression Tests
    // ========================================================================

    /// TCK-00336: Regression tests ensuring no tool executes without broker
    /// mediation.
    ///
    /// These tests verify that:
    /// 1. All tool requests go through the broker (fail-closed without it)
    /// 2. No legacy bypass paths exist that allow tool execution
    /// 3. The dispatcher enforces broker mediation for all tool classes
    mod tck_00336_broker_mediation_regression {
        use super::*;

        /// TCK-00336: Verify that ALL tool classes fail closed without broker.
        ///
        /// This test ensures that no tool class has a special bypass path.
        #[test]
        fn test_all_tool_classes_require_broker() {
            let minter = test_minter();
            let store = Arc::new(InMemoryManifestStore::new());

            // Register manifest with ALL tool classes allowed
            let all_tools = vec![
                ToolClass::Read,
                ToolClass::Write,
                ToolClass::Execute,
                ToolClass::Network,
                ToolClass::Git,
                ToolClass::Inference,
                ToolClass::Artifact,
            ];
            let manifest = tck_00260_manifest_validation::make_test_manifest(all_tools);
            store.register("session-001", manifest);

            // Create dispatcher WITHOUT broker
            let dispatcher = SessionDispatcher::with_manifest_store(minter.clone(), store);

            let token = test_token(&minter);
            let ctx = make_session_ctx();

            // Test each tool class - ALL should be denied without broker
            let tool_ids = [
                "read",
                "write",
                "execute",
                "network",
                "git",
                "inference",
                "artifact",
            ];
            for tool_id in tool_ids {
                let request = RequestToolRequest {
                    session_token: serde_json::to_string(&token).unwrap(),
                    tool_id: tool_id.to_string(),
                    arguments: vec![],
                    dedupe_key: format!("dedupe-{tool_id}"),
                    epoch_seal: None,
                };
                let frame = encode_request_tool_request(&request);
                let response = dispatcher.dispatch(&frame, &ctx).unwrap();

                match response {
                    SessionResponse::Error(err) => {
                        assert_eq!(
                            err.code,
                            SessionErrorCode::SessionErrorToolNotAllowed as i32,
                            "Tool class '{tool_id}' should be denied without broker"
                        );
                        assert!(
                            err.message.contains("broker unavailable"),
                            "Tool class '{tool_id}' error should mention broker: {}",
                            err.message
                        );
                    },
                    other => panic!(
                        "Tool class '{tool_id}' should fail closed without broker, got: {other:?}"
                    ),
                }
            }
        }

        /// TCK-00336: Verify fail-closed behavior with no manifest store.
        ///
        /// When neither broker nor manifest store is configured, tool requests
        /// must still fail closed.
        #[test]
        fn test_fails_closed_without_manifest_store_or_broker() {
            let minter = test_minter();

            // Create dispatcher with NEITHER broker NOR manifest store
            let dispatcher = SessionDispatcher::new(minter.clone());

            let token = test_token(&minter);
            let ctx = make_session_ctx();

            let request = RequestToolRequest {
                session_token: serde_json::to_string(&token).unwrap(),
                tool_id: "read".to_string(),
                arguments: vec![],
                dedupe_key: "test-dedupe".to_string(),
                epoch_seal: None,
            };
            let frame = encode_request_tool_request(&request);
            let response = dispatcher.dispatch(&frame, &ctx).unwrap();

            // Should fail closed
            match response {
                SessionResponse::Error(err) => {
                    assert_eq!(
                        err.code,
                        SessionErrorCode::SessionErrorToolNotAllowed as i32,
                        "Should deny without broker/manifest store"
                    );
                },
                other => panic!("Expected fail-closed error, got: {other:?}"),
            }
        }

        /// TCK-00336: Verify that manifest-only validation doesn't allow
        /// execution.
        ///
        /// Even if a tool is in the manifest's allowlist, without a broker
        /// the request MUST be denied (no legacy manifest-based allow path).
        #[test]
        fn test_manifest_allowlist_insufficient_without_broker() {
            let minter = test_minter();
            let store = Arc::new(InMemoryManifestStore::new());

            // Register manifest with Read explicitly allowed
            let manifest = tck_00260_manifest_validation::make_test_manifest(vec![ToolClass::Read]);
            store.register("session-001", manifest);

            // Create dispatcher with manifest store but WITHOUT broker
            let dispatcher = SessionDispatcher::with_manifest_store(minter.clone(), store);

            let token = test_token(&minter);
            let ctx = make_session_ctx();

            // Request Read tool (which IS in the manifest allowlist)
            let request = RequestToolRequest {
                session_token: serde_json::to_string(&token).unwrap(),
                tool_id: "read".to_string(),
                arguments: vec![],
                dedupe_key: "manifest-test".to_string(),
                epoch_seal: None,
            };
            let frame = encode_request_tool_request(&request);
            let response = dispatcher.dispatch(&frame, &ctx).unwrap();

            // MUST fail - manifest validation alone is NOT sufficient
            match response {
                SessionResponse::Error(err) => {
                    assert_eq!(
                        err.code,
                        SessionErrorCode::SessionErrorToolNotAllowed as i32,
                        "Manifest allowlist should NOT be sufficient without broker"
                    );
                    // Verify the error explicitly states broker is required
                    assert!(
                        err.message.contains("broker unavailable")
                            || err.message.contains("fail-closed"),
                        "Error should indicate broker mediation is required: {}",
                        err.message
                    );
                },
                SessionResponse::RequestTool(_) => {
                    panic!(
                        "SECURITY REGRESSION: Tool executed without broker mediation! \
                         Manifest-based validation alone should NOT allow tool execution."
                    );
                },
                other => panic!("Unexpected response: {other:?}"),
            }
        }

        /// TCK-00336: Verify `EpisodeRuntime` requires broker for tool
        /// execution.
        ///
        /// The `handle_broker_decision` path checks that `EpisodeRuntime` is
        /// configured and fails closed if not.
        #[test]
        fn test_broker_allow_requires_episode_runtime() {
            use crate::episode::broker::{ToolBroker, ToolBrokerConfig};

            let minter = test_minter();
            let store = Arc::new(InMemoryManifestStore::new());

            let manifest = tck_00260_manifest_validation::make_test_manifest(vec![ToolClass::Read]);
            store.register("session-001", manifest);

            // Create broker with minimal config
            let broker = Arc::new(ToolBroker::new(ToolBrokerConfig::default()));

            // Create dispatcher WITH broker but WITHOUT episode_runtime
            let dispatcher =
                SessionDispatcher::with_manifest_store(minter.clone(), store).with_broker(broker);

            let token = test_token(&minter);
            let ctx = make_session_ctx();

            let request = RequestToolRequest {
                session_token: serde_json::to_string(&token).unwrap(),
                tool_id: "read".to_string(),
                arguments: vec![],
                dedupe_key: "runtime-test".to_string(),
                epoch_seal: None,
            };
            let frame = encode_request_tool_request(&request);

            // The request will fail because:
            // 1. No clock configured (required for HTF timestamp)
            // The test verifies we don't bypass broker mediation
            let result = dispatcher.dispatch(&frame, &ctx);

            // Either fails at clock check or later at runtime check - both are valid
            // fail-closed
            match result {
                Err(ProtocolError::Serialization { reason }) => {
                    assert!(
                        reason.contains("clock"),
                        "Should fail at clock check: {reason}"
                    );
                },
                Ok(SessionResponse::Error(err)) => {
                    // Acceptable - failed at some point in the mediation chain
                    assert!(
                        err.code != 0,
                        "Should return non-zero error code for mediation failure"
                    );
                },
                Ok(SessionResponse::RequestTool(_)) => {
                    panic!(
                        "SECURITY REGRESSION: Tool request succeeded without proper runtime! \
                         This indicates a bypass in broker mediation."
                    );
                },
                other => panic!("Unexpected result: {other:?}"),
            }
        }

        /// TCK-00336: Verify that unknown tool classes fail closed.
        ///
        /// Unknown tool classes should be denied before even checking the
        /// broker.
        #[test]
        fn test_unknown_tool_class_fails_closed() {
            let minter = test_minter();
            let dispatcher = SessionDispatcher::new(minter.clone());

            let token = test_token(&minter);
            let ctx = make_session_ctx();

            // Test various invalid/unknown tool IDs
            let invalid_tool_ids = [
                "UNKNOWN_TOOL",
                "hack_tool",
                "../../etc/passwd", // Path traversal attempt
            ];

            for tool_id in invalid_tool_ids {
                let request = RequestToolRequest {
                    session_token: serde_json::to_string(&token).unwrap(),
                    tool_id: tool_id.to_string(),
                    arguments: vec![],
                    dedupe_key: format!("unknown-{}", tool_id.chars().take(10).collect::<String>()),
                    epoch_seal: None,
                };
                let frame = encode_request_tool_request(&request);
                let response = dispatcher.dispatch(&frame, &ctx).unwrap();

                match response {
                    SessionResponse::Error(err) => {
                        assert_eq!(
                            err.code,
                            SessionErrorCode::SessionErrorToolNotAllowed as i32,
                            "Unknown tool ID '{tool_id}' should be denied"
                        );
                    },
                    other => {
                        panic!("Unknown tool ID '{tool_id}' should fail closed, got: {other:?}")
                    },
                }
            }
        }
    }

    // ========================================================================
    // TCK-00344: SessionStatus Integration Tests
    // ========================================================================

    /// IT-00344-SS: `SessionStatus` handler tests.
    ///
    /// These tests verify that the `SessionStatus` endpoint correctly queries
    /// the session registry and returns session state, or falls back to
    /// token-based status when the registry is not wired or the session
    /// is not yet registered.
    mod session_status_handlers {
        use super::*;
        use crate::episode::InMemorySessionRegistry;
        use crate::protocol::messages::WorkRole;
        use crate::session::{SessionState, SessionTelemetryStore};

        /// IT-00344-SS-01: `SessionStatus` returns ACTIVE with full session
        /// data when session registry is wired and session is
        /// registered.
        #[test]
        fn test_session_status_returns_active_with_registry() {
            let minter = test_minter();
            let ctx = make_session_ctx();

            // Create a session registry and register a session
            let registry: Arc<dyn crate::session::SessionRegistry> =
                Arc::new(InMemorySessionRegistry::new());

            let session = SessionState {
                session_id: "session-001".to_string(),
                work_id: "W-SS-001".to_string(),
                role: WorkRole::Implementer.into(),
                lease_id: "L-SS-001".to_string(),
                ephemeral_handle: "handle-ss-001".to_string(),
                policy_resolved_ref: String::new(),
                capability_manifest_hash: vec![],
                episode_id: Some("E-SS-001".to_string()),
            };
            registry
                .register_session(session)
                .expect("session registration should succeed");

            // TCK-00384: Wire telemetry store with a real start time
            let telemetry_store = Arc::new(SessionTelemetryStore::new());
            let started_at_ns = std::time::SystemTime::now()
                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                .map(|d| {
                    #[allow(clippy::cast_possible_truncation)]
                    let ns = d.as_nanos() as u64;
                    ns
                })
                .unwrap_or(0);
            telemetry_store
                .register("session-001", started_at_ns)
                .expect("telemetry registration should succeed");

            // Create dispatcher with session registry and telemetry store wired
            let dispatcher = SessionDispatcher::new(minter.clone())
                .with_session_registry(registry)
                .with_telemetry_store(telemetry_store);

            let token = test_token(&minter);
            let request = SessionStatusRequest {
                session_token: serde_json::to_string(&token).unwrap(),
            };
            let frame = encode_session_status_request(&request);
            let response = dispatcher.dispatch(&frame, &ctx).unwrap();

            match response {
                SessionResponse::SessionStatus(resp) => {
                    assert_eq!(resp.session_id, "session-001");
                    assert_eq!(resp.state, "ACTIVE");
                    assert_eq!(resp.work_id, "W-SS-001");
                    assert_eq!(resp.role, i32::from(WorkRole::Implementer));
                    assert_eq!(resp.episode_id, Some("E-SS-001".to_string()));
                    assert!(resp.started_at_ns > 0, "started_at_ns should be non-zero");
                    // duration_ms should be a small delta (not raw epoch time)
                    assert!(
                        resp.duration_ms < 60_000,
                        "duration_ms should be session duration, not epoch time; got {}",
                        resp.duration_ms
                    );
                },
                other => panic!("Expected SessionStatus response, got: {other:?}"),
            }
        }

        /// IT-00344-SS-02: `SessionStatus` returns ACTIVE with minimal data
        /// when session registry is not wired (falls back to
        /// token-based status).
        #[test]
        fn test_session_status_without_registry_falls_back_to_token() {
            let minter = test_minter();
            let ctx = make_session_ctx();

            // No session registry wired
            let dispatcher = SessionDispatcher::new(minter.clone());

            let token = test_token(&minter);
            let request = SessionStatusRequest {
                session_token: serde_json::to_string(&token).unwrap(),
            };
            let frame = encode_session_status_request(&request);
            let response = dispatcher.dispatch(&frame, &ctx).unwrap();

            match response {
                SessionResponse::SessionStatus(resp) => {
                    assert_eq!(resp.session_id, "session-001");
                    assert_eq!(resp.state, "ACTIVE");
                    // Without registry, work_id and role are defaults
                    assert!(resp.work_id.is_empty());
                    assert_eq!(resp.role, 0);
                },
                other => panic!("Expected SessionStatus response, got: {other:?}"),
            }
        }

        /// IT-00344-SS-03: `SessionStatus` rejects invalid session token.
        #[test]
        fn test_session_status_rejects_invalid_token() {
            let minter = test_minter();
            let ctx = make_session_ctx();
            let dispatcher = SessionDispatcher::new(minter);

            let request = SessionStatusRequest {
                session_token: "invalid-token-not-a-real-jwt".to_string(),
            };
            let frame = encode_session_status_request(&request);
            let response = dispatcher.dispatch(&frame, &ctx).unwrap();

            match response {
                SessionResponse::Error(err) => {
                    assert_eq!(
                        err.code,
                        SessionErrorCode::SessionErrorInvalid as i32,
                        "Expected SESSION_ERROR_INVALID error"
                    );
                },
                other => panic!("Expected error for invalid token, got: {other:?}"),
            }
        }

        /// IT-00344-SS-04: `SessionStatus` is denied from operator socket
        /// (`PERMISSION_DENIED`).
        #[test]
        fn test_session_status_denied_from_operator_socket() {
            let minter = test_minter();
            let ctx = make_privileged_ctx();
            let dispatcher = SessionDispatcher::new(minter);

            // Use a dummy payload - doesn't matter since it should be rejected
            // before parsing
            let request = SessionStatusRequest {
                session_token: "dummy".to_string(),
            };
            let frame = encode_session_status_request(&request);
            let response = dispatcher.dispatch(&frame, &ctx).unwrap();

            match response {
                SessionResponse::Error(err) => {
                    assert_eq!(
                        err.code,
                        SessionErrorCode::SessionErrorPermissionDenied as i32,
                        "Expected PERMISSION_DENIED for operator context"
                    );
                },
                other => panic!("Expected PERMISSION_DENIED, got: {other:?}"),
            }
        }

        /// IT-00344-SS-05: `SessionStatus` encoding uses correct tag (tag 6).
        #[test]
        fn test_session_status_encoding_tag() {
            let request = SessionStatusRequest {
                session_token: "test-token".to_string(),
            };
            let encoded = encode_session_status_request(&request);
            assert_eq!(
                encoded[0],
                SessionMessageType::SessionStatus.tag(),
                "SessionStatus tag should be 6"
            );
            assert_eq!(encoded[0], 6u8, "SessionStatus tag value should be 6");
        }

        // ====================================================================
        // TCK-00384: Session Telemetry Integration Tests
        // ====================================================================

        /// IT-00384-01: `SessionStatus` returns real telemetry counters
        /// when telemetry store is wired and counters are incremented.
        #[test]
        fn test_session_status_returns_real_telemetry_counters() {
            let minter = test_minter();
            let ctx = make_session_ctx();

            let registry: Arc<dyn crate::session::SessionRegistry> =
                Arc::new(InMemorySessionRegistry::new());

            let session = SessionState {
                session_id: "session-001".to_string(),
                work_id: "W-TEL-001".to_string(),
                role: WorkRole::Implementer.into(),
                lease_id: "L-TEL-001".to_string(),
                ephemeral_handle: "handle-tel-001".to_string(),
                policy_resolved_ref: String::new(),
                capability_manifest_hash: vec![],
                episode_id: Some("E-TEL-001".to_string()),
            };
            registry
                .register_session(session)
                .expect("session registration should succeed");

            // Wire telemetry store and simulate counter increments
            let telemetry_store = Arc::new(SessionTelemetryStore::new());
            let started_at_ns = std::time::SystemTime::now()
                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                .map(|d| {
                    #[allow(clippy::cast_possible_truncation)]
                    let ns = d.as_nanos() as u64;
                    ns
                })
                .unwrap_or(0);
            telemetry_store
                .register("session-001", started_at_ns)
                .expect("telemetry registration should succeed");

            // Simulate tool calls and event emissions
            {
                let t = telemetry_store.get("session-001").unwrap();
                t.increment_tool_calls();
                t.increment_tool_calls();
                t.increment_tool_calls();
                t.increment_events_emitted();
                t.increment_events_emitted();
            }

            let dispatcher = SessionDispatcher::new(minter.clone())
                .with_session_registry(registry)
                .with_telemetry_store(telemetry_store);

            let token = test_token(&minter);
            let request = SessionStatusRequest {
                session_token: serde_json::to_string(&token).unwrap(),
            };
            let frame = encode_session_status_request(&request);
            let response = dispatcher.dispatch(&frame, &ctx).unwrap();

            match response {
                SessionResponse::SessionStatus(resp) => {
                    assert_eq!(resp.tool_calls, 3, "tool_calls should be 3");
                    assert_eq!(resp.events_emitted, 2, "events_emitted should be 2");
                    assert!(resp.started_at_ns > 0, "started_at_ns should be non-zero");
                    // duration_ms should be session duration (small), not epoch
                    assert!(
                        resp.duration_ms < 60_000,
                        "duration_ms should be session duration (< 1 min), got {}",
                        resp.duration_ms
                    );
                },
                other => panic!("Expected SessionStatus response, got: {other:?}"),
            }
        }

        /// IT-00384-02: `SessionStatus` returns zeros when telemetry store
        /// is not wired (backward compatibility).
        #[test]
        fn test_session_status_returns_zeros_without_telemetry() {
            let minter = test_minter();
            let ctx = make_session_ctx();

            let registry: Arc<dyn crate::session::SessionRegistry> =
                Arc::new(InMemorySessionRegistry::new());

            let session = SessionState {
                session_id: "session-001".to_string(),
                work_id: "W-TEL-002".to_string(),
                role: WorkRole::Implementer.into(),
                lease_id: "L-TEL-002".to_string(),
                ephemeral_handle: "handle-tel-002".to_string(),
                policy_resolved_ref: String::new(),
                capability_manifest_hash: vec![],
                episode_id: None,
            };
            registry
                .register_session(session)
                .expect("session registration should succeed");

            // No telemetry store wired
            let dispatcher = SessionDispatcher::new(minter.clone()).with_session_registry(registry);

            let token = test_token(&minter);
            let request = SessionStatusRequest {
                session_token: serde_json::to_string(&token).unwrap(),
            };
            let frame = encode_session_status_request(&request);
            let response = dispatcher.dispatch(&frame, &ctx).unwrap();

            match response {
                SessionResponse::SessionStatus(resp) => {
                    assert_eq!(resp.tool_calls, 0);
                    assert_eq!(resp.events_emitted, 0);
                    assert_eq!(resp.started_at_ns, 0);
                    assert_eq!(resp.duration_ms, 0);
                },
                other => panic!("Expected SessionStatus response, got: {other:?}"),
            }
        }

        /// IT-00384-04: End-to-end test verifying that telemetry counters are
        /// incremented through real dispatcher paths (`RequestTool` via broker,
        /// `EmitEvent` via ledger) rather than manual counter manipulation.
        ///
        /// This test:
        /// (a) Pre-registers a session (simulating `SpawnEpisode`)
        /// (b) Dispatches `RequestTool` through the real broker path
        /// (c) Dispatches `EmitEvent` through the real ledger path
        /// (d) Dispatches `SessionStatus`
        /// (e) Asserts that counters reflect the live dispatcher flow
        #[test]
        fn test_e2e_telemetry_counters_through_dispatcher_paths() {
            // We need a multi-threaded tokio runtime because the broker path
            // uses `block_in_place` which requires a multi-threaded runtime.
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("failed to build tokio runtime");

            rt.block_on(async {
                use std::path::PathBuf;

                use rand::rngs::OsRng;

                use crate::episode::decision::Credential;
                use crate::episode::tool_handler::ToolArgs;
                use crate::episode::{
                    BudgetDelta, Capability, CapabilityManifestBuilder, CapabilityScope,
                    EpisodeRuntime, EpisodeRuntimeConfig, RiskTier, StubContentAddressedStore,
                    ToolBroker, ToolBrokerConfig, ToolClass, ToolHandler, ToolHandlerError,
                    ToolResultData,
                };
                use crate::htf::{ClockConfig, HolonicClock};
                use crate::ledger::SqliteLedgerEventEmitter;

                // --- Mock handler that returns success without real I/O ---
                #[derive(Debug)]
                struct MockReadHandler;

                #[async_trait::async_trait]
                impl ToolHandler for MockReadHandler {
                    fn tool_class(&self) -> ToolClass {
                        ToolClass::Read
                    }

                    async fn execute(
                        &self,
                        _args: &ToolArgs,
                        _credential: Option<&Credential>,
                    ) -> Result<ToolResultData, ToolHandlerError> {
                        Ok(ToolResultData::success(
                            b"mock-read-output".to_vec(),
                            BudgetDelta::single_call(),
                            std::time::Duration::from_millis(1),
                        ))
                    }

                    fn validate(&self, _args: &ToolArgs) -> Result<(), ToolHandlerError> {
                        Ok(())
                    }

                    fn name(&self) -> &'static str {
                        "MockReadHandler"
                    }
                }

                let minter = test_minter();

                // --- Infrastructure setup ---

                // EpisodeRuntime with CAS and a mock Read handler factory
                // so that execute_tool() succeeds end-to-end.
                let cas: Arc<dyn crate::episode::ContentAddressedStore> =
                    Arc::new(StubContentAddressedStore::new());
                let runtime_config = EpisodeRuntimeConfig::default();
                #[allow(deprecated)]
                let episode_runtime = Arc::new(
                    EpisodeRuntime::new(runtime_config)
                        .with_cas(cas)
                        .with_handler_factory(|| Box::new(MockReadHandler) as Box<dyn ToolHandler>),
                );

                // Create and start an episode. The generated episode_id becomes
                // the session_id so that handle_request_tool's
                // `EpisodeId::new(&token.session_id)` resolves to this episode.
                let episode_id = episode_runtime
                    .create(*blake3::hash(b"test-envelope").as_bytes(), 1_000_000)
                    .await
                    .expect("create episode");

                #[allow(deprecated)]
                let _handle = episode_runtime
                    .start(&episode_id, "lease-001", 2_000_000)
                    .await
                    .expect("start episode");

                // Use the episode_id as session_id everywhere so the
                // dispatcher can find the episode at execute_tool() time.
                let session_id = episode_id.as_str().to_string();

                // Build a ConnectionContext tied to this session_id
                let ctx = ConnectionContext::session_open(
                    Some(crate::protocol::credentials::PeerCredentials {
                        uid: 1000,
                        gid: 1000,
                        pid: Some(12346),
                    }),
                    Some(session_id.clone()),
                );

                // In-memory SQLite for ledger
                let conn = rusqlite::Connection::open_in_memory().expect("in-memory sqlite");
                SqliteLedgerEventEmitter::init_schema(&conn).expect("init ledger schema");
                let conn = Arc::new(std::sync::Mutex::new(conn));
                let signing_key = ed25519_dalek::SigningKey::generate(&mut OsRng);
                let ledger: Arc<dyn crate::protocol::dispatch::LedgerEventEmitter> = Arc::new(
                    SqliteLedgerEventEmitter::new(Arc::clone(&conn), signing_key),
                );

                // HolonicClock
                let clock =
                    Arc::new(HolonicClock::new(ClockConfig::default(), None).expect("clock"));

                // ToolBroker - disable policy check (no policy engine in test)
                // and initialize with manifest so request() succeeds.
                let broker_config = ToolBrokerConfig::default().without_policy_check();
                let broker = Arc::new(ToolBroker::new(broker_config));
                let read_scope_manifest = CapabilityManifestBuilder::new("e2e-read-manifest")
                    .delegator("test-delegator")
                    .capabilities(vec![Capability {
                        capability_id: "cap-read-e2e".to_string(),
                        tool_class: ToolClass::Read,
                        scope: CapabilityScope {
                            root_paths: vec![PathBuf::from("/")],
                            allowed_patterns: Vec::new(),
                            size_limits: crate::episode::scope::SizeLimits::default_limits(),
                            network_policy: None,
                        },
                        risk_tier_required: RiskTier::Tier0,
                    }])
                    .tool_allowlist(vec![ToolClass::Read])
                    .build()
                    .expect("e2e read manifest build");

                let broker_manifest = read_scope_manifest.clone();
                broker
                    .initialize_with_manifest(broker_manifest)
                    .await
                    .expect("broker initialization should succeed");

                // Manifest store with Read allowed
                let manifest_store = Arc::new(InMemoryManifestStore::new());
                let manifest = read_scope_manifest;
                manifest_store.register(&session_id, manifest);

                // Session registry
                let registry: Arc<dyn crate::session::SessionRegistry> =
                    Arc::new(crate::episode::InMemorySessionRegistry::new());
                let session = crate::session::SessionState {
                    session_id: session_id.clone(),
                    work_id: "W-E2E-001".to_string(),
                    role: crate::protocol::messages::WorkRole::Implementer.into(),
                    lease_id: "L-E2E-001".to_string(),
                    ephemeral_handle: "handle-e2e".to_string(),
                    // TCK-00426: PCAC gate requires non-empty manifest hash and
                    // policy_resolved_ref in authoritative mode.
                    policy_resolved_ref: "test-policy-ref".to_string(),
                    capability_manifest_hash: blake3::hash(b"e2e-read-manifest")
                        .as_bytes()
                        .to_vec(),
                    episode_id: Some(session_id.clone()),
                };
                registry
                    .register_session(session)
                    .expect("register session");

                // Telemetry store - register with real start time
                let telemetry_store = Arc::new(SessionTelemetryStore::new());
                let started_at_ns = std::time::SystemTime::now()
                    .duration_since(std::time::SystemTime::UNIX_EPOCH)
                    .map(|d| {
                        #[allow(clippy::cast_possible_truncation)]
                        let ns = d.as_nanos() as u64;
                        ns
                    })
                    .unwrap_or(0);
                telemetry_store
                    .register(&session_id, started_at_ns)
                    .expect("telemetry registration should succeed");

                // --- Build dispatcher with all production dependencies ---
                // TCK-00351 BLOCKER 2 v2 FIX: Gate is mandatory when broker
                // is configured.
                let stop_authority = Arc::new(crate::episode::preactuation::StopAuthority::new());
                let preactuation_gate = Arc::new(
                    crate::episode::preactuation::PreActuationGate::production_gate(
                        Arc::clone(&stop_authority),
                        None,
                    ),
                );
                // TCK-00426: Wire PCAC gate — required in authoritative mode (fail-closed).
                let pcac_kernel: Arc<dyn apm2_core::pcac::AuthorityJoinKernel> =
                    Arc::new(crate::pcac::InProcessKernel::new(1));
                let pcac_gate = Arc::new(crate::pcac::LifecycleGate::new(pcac_kernel));
                let dispatcher =
                    SessionDispatcher::with_manifest_store(minter.clone(), manifest_store)
                        .with_broker(broker)
                        .with_clock(clock)
                        .with_ledger(ledger)
                        .with_episode_runtime(episode_runtime)
                        .with_session_registry(Arc::clone(&registry))
                        .with_telemetry_store(Arc::clone(&telemetry_store))
                        .with_preactuation_gate(preactuation_gate)
                        .with_stop_authority(stop_authority)
                        .with_pcac_lifecycle_gate(pcac_gate);

                // Mint token with the episode-derived session_id
                let spawn_time = std::time::SystemTime::now();
                let ttl = Duration::from_secs(3600);
                let token = minter
                    .mint(&session_id, "lease-001", spawn_time, ttl)
                    .unwrap();

                // --- (b) Dispatch RequestTool through real broker path ---
                // The broker is initialized with a manifest that allows Read,
                // the episode runtime has a CAS and a MockReadHandler, so the
                // full Allow -> execute -> success path is exercised.
                let read_args = serde_json::json!({
                    "type": "read",
                    "path": "/tmp/e2e-telemetry-test-dummy"
                });
                let tool_request = RequestToolRequest {
                    session_token: serde_json::to_string(&token).unwrap(),
                    tool_id: "read".to_string(),
                    arguments: serde_json::to_vec(&read_args).unwrap(),
                    dedupe_key: "e2e-dedupe-1".to_string(),
                    epoch_seal: None,
                };
                let frame = encode_request_tool_request(&tool_request);
                let tool_result = dispatcher.dispatch(&frame, &ctx);

                // The broker returns Allow and MockReadHandler succeeds,
                // so we must get a RequestTool response with Allow decision.
                match &tool_result {
                    Ok(SessionResponse::RequestTool(resp)) => {
                        assert_eq!(
                            resp.decision,
                            i32::from(DecisionType::Allow),
                            "Expected Allow decision from broker"
                        );
                    },
                    Ok(SessionResponse::Error(err)) => {
                        panic!(
                            "RequestTool should succeed with initialized broker \
                             and mock handler, but got error: code={}, msg={}",
                            err.code, err.message
                        );
                    },
                    Err(e) => {
                        panic!("RequestTool dispatch failed unexpectedly: {e:?}");
                    },
                    other => {
                        panic!("Unexpected RequestTool response: {other:?}");
                    },
                }

                // --- (c) Dispatch EmitEvent through real ledger path ---
                let emit_request = EmitEventRequest {
                    session_token: serde_json::to_string(&token).unwrap(),
                    event_type: "test.event".to_string(),
                    payload: b"test-payload".to_vec(),
                    correlation_id: "corr-e2e-001".to_string(),
                };
                let frame = encode_emit_event_request(&emit_request);
                let emit_result = dispatcher.dispatch(&frame, &ctx).unwrap();
                match &emit_result {
                    SessionResponse::EmitEvent(resp) => {
                        assert!(!resp.event_id.is_empty(), "event_id should be set");
                        assert_eq!(resp.seq, 1, "first event should have seq=1");
                        assert!(resp.timestamp_ns > 0, "timestamp_ns should be set");
                    },
                    other => panic!("Expected EmitEvent response, got: {other:?}"),
                }

                // Emit a second event to verify counter increments
                let emit_request2 = EmitEventRequest {
                    session_token: serde_json::to_string(&token).unwrap(),
                    event_type: "test.event.2".to_string(),
                    payload: b"payload-2".to_vec(),
                    correlation_id: "corr-e2e-002".to_string(),
                };
                let frame2 = encode_emit_event_request(&emit_request2);
                let emit_result2 = dispatcher.dispatch(&frame2, &ctx).unwrap();
                match &emit_result2 {
                    SessionResponse::EmitEvent(resp) => {
                        assert_eq!(resp.seq, 2, "second event should have seq=2");
                    },
                    other => panic!("Expected EmitEvent response for second event, got: {other:?}"),
                }

                // --- (d) Dispatch SessionStatus and assert counters ---
                let status_request = SessionStatusRequest {
                    session_token: serde_json::to_string(&token).unwrap(),
                };
                let frame = encode_session_status_request(&status_request);
                let status_result = dispatcher.dispatch(&frame, &ctx).unwrap();

                // --- (e) Assert observed counters ---
                // tool_calls MUST be 1: the broker returned Allow, the mock
                // handler succeeded, and the counter was incremented.
                match status_result {
                    SessionResponse::SessionStatus(resp) => {
                        assert_eq!(
                            resp.tool_calls, 1,
                            "tool_calls must be 1 after successful RequestTool dispatch"
                        );
                        assert_eq!(
                            resp.events_emitted, 2,
                            "events_emitted should be 2 (two EmitEvent dispatches)"
                        );
                        assert!(resp.started_at_ns > 0, "started_at_ns should be non-zero");
                        // duration_ms should be a small session-relative value
                        assert!(
                            resp.duration_ms < 60_000,
                            "duration_ms should be session duration (< 1 min), got {}",
                            resp.duration_ms
                        );
                        assert_eq!(resp.session_id, session_id);
                        assert_eq!(resp.state, "ACTIVE");
                        assert_eq!(resp.work_id, "W-E2E-001");
                    },
                    other => panic!("Expected SessionStatus response, got: {other:?}"),
                }
            });
        }

        /// IT-00384-03: `duration_ms` is computed from the monotonic
        /// `Instant` clock, not from wall-clock `SystemTime`. This makes it
        /// immune to clock jumps and skew.
        #[test]
        fn test_session_status_duration_uses_monotonic_clock() {
            let minter = test_minter();
            let ctx = make_session_ctx();

            let registry: Arc<dyn crate::session::SessionRegistry> =
                Arc::new(InMemorySessionRegistry::new());

            let session = SessionState {
                session_id: "session-001".to_string(),
                work_id: "W-TEL-003".to_string(),
                role: WorkRole::Implementer.into(),
                lease_id: "L-TEL-003".to_string(),
                ephemeral_handle: "handle-tel-003".to_string(),
                policy_resolved_ref: String::new(),
                capability_manifest_hash: vec![],
                episode_id: None,
            };
            registry
                .register_session(session)
                .expect("session registration should succeed");

            // Register telemetry. The monotonic Instant is captured at
            // register() time, so duration_ms will reflect elapsed time
            // since registration (not wall-clock manipulation).
            let telemetry_store = Arc::new(SessionTelemetryStore::new());
            let started_at_ns = 42_u64; // Wall-clock ns is display metadata only
            telemetry_store
                .register("session-001", started_at_ns)
                .expect("telemetry registration should succeed");

            let dispatcher = SessionDispatcher::new(minter.clone())
                .with_session_registry(registry)
                .with_telemetry_store(telemetry_store);

            let token = test_token(&minter);
            let request = SessionStatusRequest {
                session_token: serde_json::to_string(&token).unwrap(),
            };
            let frame = encode_session_status_request(&request);
            let response = dispatcher.dispatch(&frame, &ctx).unwrap();

            match response {
                SessionResponse::SessionStatus(resp) => {
                    // duration_ms comes from Instant::now().elapsed(), so it
                    // should be very small (< 5 seconds for a just-registered
                    // session in a test).
                    assert!(
                        resp.duration_ms < 5_000,
                        "duration_ms should be small for a just-registered session, got {}",
                        resp.duration_ms
                    );
                    // Critically, it must NOT be raw epoch time (~1.77 trillion)
                    assert!(
                        resp.duration_ms < 1_000_000,
                        "duration_ms must not be raw epoch time; got {}",
                        resp.duration_ms
                    );
                    // Wall-clock metadata is preserved
                    assert_eq!(resp.started_at_ns, 42);
                },
                other => panic!("Expected SessionStatus response, got: {other:?}"),
            }
        }
    }

    // ========================================================================
    // TCK-00385: Session Termination Signal Tests
    // ========================================================================

    /// IT-00385: `SessionStatus` returns TERMINATED state with termination
    /// details for terminated sessions.
    mod session_termination_signal {
        use super::*;
        use crate::episode::InMemorySessionRegistry;
        use crate::episode::decision::SessionTerminationInfo;
        use crate::protocol::messages::WorkRole;
        use crate::session::{SessionRegistry, SessionState};

        /// IT-00385-01: `SessionStatus` returns ACTIVE for active session
        /// (no regression from TCK-00344).
        #[test]
        fn test_active_session_returns_active_state() {
            let minter = test_minter();
            let ctx = make_session_ctx();

            let registry: Arc<dyn crate::session::SessionRegistry> =
                Arc::new(InMemorySessionRegistry::new());

            let session = SessionState {
                session_id: "session-001".to_string(),
                work_id: "W-385-001".to_string(),
                role: WorkRole::Implementer.into(),
                lease_id: "L-385-001".to_string(),
                ephemeral_handle: "handle-385-001".to_string(),
                policy_resolved_ref: String::new(),
                capability_manifest_hash: vec![],
                episode_id: Some("E-385-001".to_string()),
            };
            registry
                .register_session(session)
                .expect("session registration should succeed");

            let dispatcher = SessionDispatcher::new(minter.clone()).with_session_registry(registry);

            let token = test_token(&minter);
            let request = SessionStatusRequest {
                session_token: serde_json::to_string(&token).unwrap(),
            };
            let frame = encode_session_status_request(&request);
            let response = dispatcher.dispatch(&frame, &ctx).unwrap();

            match response {
                SessionResponse::SessionStatus(resp) => {
                    assert_eq!(resp.session_id, "session-001");
                    assert_eq!(resp.state, "ACTIVE");
                    assert_eq!(resp.work_id, "W-385-001");
                    // TCK-00385: Termination fields should be None for active
                    // sessions
                    assert!(
                        resp.termination_reason.is_none(),
                        "Active session should not have termination_reason"
                    );
                    assert!(
                        resp.exit_code.is_none(),
                        "Active session should not have exit_code"
                    );
                    assert!(
                        resp.terminated_at_ns.is_none(),
                        "Active session should not have terminated_at_ns"
                    );
                    assert!(
                        resp.actual_tokens_consumed.is_none(),
                        "Active session should not have actual_tokens_consumed"
                    );
                },
                other => panic!("Expected SessionStatus response, got: {other:?}"),
            }
        }

        /// IT-00385-02: `SessionStatus` returns TERMINATED with termination
        /// details for terminated sessions.
        #[test]
        fn test_terminated_session_returns_terminated_state() {
            let minter = test_minter();
            let ctx = make_session_ctx();

            let registry = Arc::new(InMemorySessionRegistry::new());

            // Register a session
            let session = SessionState {
                session_id: "session-001".to_string(),
                work_id: "W-385-002".to_string(),
                role: WorkRole::Implementer.into(),
                lease_id: "L-385-002".to_string(),
                ephemeral_handle: "handle-385-002".to_string(),
                policy_resolved_ref: String::new(),
                capability_manifest_hash: vec![],
                episode_id: Some("E-385-002".to_string()),
            };
            registry
                .register_session(session)
                .expect("session registration should succeed");

            // Mark the session as terminated
            let term_info = SessionTerminationInfo::new("session-001", "normal", "SUCCESS")
                .with_exit_code(0)
                .with_tokens_consumed(42_000);

            assert!(
                registry
                    .mark_terminated("session-001", term_info)
                    .expect("mark_terminated should not fail"),
                "mark_terminated should return true for existing session"
            );

            let dyn_registry: Arc<dyn crate::session::SessionRegistry> = registry;
            let dispatcher =
                SessionDispatcher::new(minter.clone()).with_session_registry(dyn_registry);

            let token = test_token(&minter);
            let request = SessionStatusRequest {
                session_token: serde_json::to_string(&token).unwrap(),
            };
            let frame = encode_session_status_request(&request);
            let response = dispatcher.dispatch(&frame, &ctx).unwrap();

            match response {
                SessionResponse::SessionStatus(resp) => {
                    assert_eq!(resp.session_id, "session-001");
                    assert_eq!(resp.state, "TERMINATED");
                    assert_eq!(resp.work_id, "W-385-002");
                    assert_eq!(resp.role, i32::from(WorkRole::Implementer));
                    assert_eq!(resp.episode_id, Some("E-385-002".to_string()));
                    // TCK-00385: Termination details should be populated
                    assert_eq!(resp.termination_reason, Some("normal".to_string()),);
                    assert_eq!(resp.exit_code, Some(0));
                    assert!(
                        resp.terminated_at_ns.is_some(),
                        "terminated_at_ns should be set"
                    );
                    assert!(
                        resp.terminated_at_ns.unwrap() > 0,
                        "terminated_at_ns should be non-zero"
                    );
                    assert_eq!(resp.actual_tokens_consumed, Some(42_000),);
                },
                other => panic!("Expected SessionStatus response, got: {other:?}"),
            }
        }

        /// IT-00385-03: `SessionStatus` returns TERMINATED with crash
        /// reason and non-zero exit code.
        #[test]
        fn test_terminated_session_with_crash_reason() {
            let minter = test_minter();
            let ctx = make_session_ctx();

            let registry = Arc::new(InMemorySessionRegistry::new());

            let session = SessionState {
                session_id: "session-001".to_string(),
                work_id: "W-385-003".to_string(),
                role: WorkRole::Reviewer.into(),
                lease_id: "L-385-003".to_string(),
                ephemeral_handle: "handle-385-003".to_string(),
                policy_resolved_ref: String::new(),
                capability_manifest_hash: vec![],
                episode_id: None,
            };
            registry
                .register_session(session)
                .expect("session registration should succeed");

            let term_info =
                SessionTerminationInfo::new("session-001", "crash", "FAILURE").with_exit_code(137); // Killed by SIGKILL

            assert!(registry.mark_terminated("session-001", term_info).unwrap());

            let dyn_registry: Arc<dyn crate::session::SessionRegistry> = registry;
            let dispatcher =
                SessionDispatcher::new(minter.clone()).with_session_registry(dyn_registry);

            let token = test_token(&minter);
            let request = SessionStatusRequest {
                session_token: serde_json::to_string(&token).unwrap(),
            };
            let frame = encode_session_status_request(&request);
            let response = dispatcher.dispatch(&frame, &ctx).unwrap();

            match response {
                SessionResponse::SessionStatus(resp) => {
                    assert_eq!(resp.state, "TERMINATED");
                    assert_eq!(resp.termination_reason, Some("crash".to_string()),);
                    assert_eq!(resp.exit_code, Some(137));
                    assert!(
                        resp.actual_tokens_consumed.is_none(),
                        "Tokens should be None when not provided"
                    );
                },
                other => panic!("Expected SessionStatus response, got: {other:?}"),
            }
        }

        /// IT-00385-04: `mark_terminated` returns false for non-existent
        /// session.
        #[test]
        fn test_mark_terminated_nonexistent_session() {
            let registry = InMemorySessionRegistry::new();

            let term_info = SessionTerminationInfo::new("nonexistent", "normal", "SUCCESS");

            assert!(
                !registry
                    .mark_terminated("nonexistent", term_info)
                    .expect("mark_terminated should not fail"),
                "mark_terminated should return false for non-existent session"
            );
        }

        /// IT-00385-05: Active session query does not return terminated
        /// sessions (session is removed from active map).
        #[test]
        fn test_terminated_session_removed_from_active() {
            let registry = InMemorySessionRegistry::new();

            let session = SessionState {
                session_id: "sess-term".to_string(),
                work_id: "W-TERM".to_string(),
                role: 1,
                ephemeral_handle: "handle-term".to_string(),
                lease_id: "lease-term".to_string(),
                policy_resolved_ref: String::new(),
                capability_manifest_hash: vec![],
                episode_id: None,
            };
            registry
                .register_session(session)
                .expect("registration should succeed");

            assert!(registry.get_session("sess-term").is_some());

            let term_info = SessionTerminationInfo::new("sess-term", "normal", "SUCCESS");
            assert!(registry.mark_terminated("sess-term", term_info).unwrap());

            // Session should no longer be in active set
            assert!(
                registry.get_session("sess-term").is_none(),
                "Terminated session should not be returned by get_session"
            );

            // But should be in terminated set
            assert!(
                registry.get_termination_info("sess-term").is_some(),
                "Termination info should be available"
            );

            // And get_terminated_session should return both
            let result = <InMemorySessionRegistry as crate::session::SessionRegistry>::get_terminated_session(&registry, "sess-term");
            assert!(result.is_some());
            let (sess, info) = result.unwrap();
            assert_eq!(sess.work_id, "W-TERM");
            assert_eq!(info.rationale_code, "normal");
        }

        /// IT-00385-06: Terminated session count is tracked.
        #[test]
        fn test_terminated_count() {
            let registry = InMemorySessionRegistry::new();

            assert_eq!(registry.terminated_count(), 0);

            // Register and terminate two sessions
            let session1 = SessionState {
                session_id: "s1".to_string(),
                work_id: "w1".to_string(),
                role: 1,
                ephemeral_handle: "h1".to_string(),
                lease_id: "l1".to_string(),
                policy_resolved_ref: String::new(),
                capability_manifest_hash: vec![],
                episode_id: None,
            };
            let session2 = SessionState {
                session_id: "s2".to_string(),
                work_id: "w2".to_string(),
                role: 1,
                ephemeral_handle: "h2".to_string(),
                lease_id: "l2".to_string(),
                policy_resolved_ref: String::new(),
                capability_manifest_hash: vec![],
                episode_id: None,
            };

            registry.register_session(session1).unwrap();
            registry.register_session(session2).unwrap();

            registry
                .mark_terminated("s1", SessionTerminationInfo::new("s1", "normal", "SUCCESS"))
                .unwrap();
            registry
                .mark_terminated(
                    "s2",
                    SessionTerminationInfo::new("s2", "timeout", "FAILURE"),
                )
                .unwrap();

            assert_eq!(registry.terminated_count(), 2);
            assert_eq!(registry.len(), 0, "No active sessions should remain");
        }

        /// IT-00385-07: `SessionTerminationInfo` builder methods work
        /// correctly.
        #[test]
        fn test_termination_info_builder() {
            let info = SessionTerminationInfo::new("sess-42", "budget_exhausted", "FAILURE")
                .with_exit_code(1)
                .with_tokens_consumed(100_000);

            assert_eq!(info.session_id, "sess-42");
            assert_eq!(info.rationale_code, "budget_exhausted");
            assert_eq!(info.exit_classification, "FAILURE");
            assert_eq!(info.exit_code, Some(1));
            assert!(info.terminated_at_ns > 0);
            assert_eq!(info.actual_tokens_consumed, Some(100_000));
        }

        /// IT-00385-08: `SessionTerminationInfo::new` without builders has
        /// None for optional fields.
        #[test]
        fn test_termination_info_defaults() {
            let info = SessionTerminationInfo::new("sess-0", "normal", "SUCCESS");

            assert_eq!(info.exit_code, None);
            assert!(info.terminated_at_ns > 0, "timestamp should be set");
            assert_eq!(info.actual_tokens_consumed, None);
        }

        /// IT-00385-09: Handle lookup is cleaned up after termination.
        #[test]
        fn test_handle_cleaned_up_after_termination() {
            let registry = InMemorySessionRegistry::new();

            let session = SessionState {
                session_id: "sess-h".to_string(),
                work_id: "w-h".to_string(),
                role: 1,
                ephemeral_handle: "handle-h".to_string(),
                lease_id: "l-h".to_string(),
                policy_resolved_ref: String::new(),
                capability_manifest_hash: vec![],
                episode_id: None,
            };
            registry.register_session(session).unwrap();

            assert!(registry.get_session_by_handle("handle-h").is_some());

            let term_info = SessionTerminationInfo::new("sess-h", "normal", "SUCCESS");
            registry.mark_terminated("sess-h", term_info).unwrap();

            // Handle should no longer resolve to an active session
            assert!(
                registry.get_session_by_handle("handle-h").is_none(),
                "Handle should not resolve after termination"
            );
        }

        /// IT-00385-10 (MAJOR 2): Production session lifecycle results in
        /// TERMINATED status via `mark_terminated`.
        ///
        /// This integration test demonstrates that a session registered in the
        /// registry, when terminated via `mark_terminated` (as wired from the
        /// `ToolDecision::Terminate` handler), produces a `SessionStatus`
        /// response with state=TERMINATED and populated termination
        /// details.
        #[test]
        fn test_session_lifecycle_to_terminated() {
            let minter = test_minter();
            let ctx = make_session_ctx();

            let registry = Arc::new(InMemorySessionRegistry::new());

            // Step 1: Register a session (simulates SpawnEpisode)
            let session = SessionState {
                session_id: "session-001".to_string(),
                work_id: "W-LIFECYCLE".to_string(),
                role: WorkRole::Implementer.into(),
                lease_id: "L-LIFECYCLE".to_string(),
                ephemeral_handle: "handle-lifecycle".to_string(),
                policy_resolved_ref: String::new(),
                capability_manifest_hash: vec![],
                episode_id: Some("E-LIFECYCLE".to_string()),
            };
            registry
                .register_session(session)
                .expect("registration should succeed");

            // Step 2: Verify session is ACTIVE
            let dyn_registry: Arc<dyn crate::session::SessionRegistry> = registry.clone();
            let dispatcher =
                SessionDispatcher::new(minter.clone()).with_session_registry(dyn_registry);

            let token = test_token(&minter);
            let request = SessionStatusRequest {
                session_token: serde_json::to_string(&token).unwrap(),
            };
            let frame = encode_session_status_request(&request);
            let response = dispatcher.dispatch(&frame, &ctx).unwrap();

            match &response {
                SessionResponse::SessionStatus(resp) => {
                    assert_eq!(resp.state, "ACTIVE");
                    assert!(
                        resp.termination_reason.is_none(),
                        "Active session should have no termination_reason"
                    );
                },
                other => panic!("Expected SessionStatus, got: {other:?}"),
            }

            // Step 3: Simulate production termination (as wired from
            // ToolDecision::Terminate handler via session_registry.mark_terminated)
            let term_info =
                SessionTerminationInfo::new("session-001", "budget_exhausted", "FAILURE")
                    .with_exit_code(1)
                    .with_tokens_consumed(500_000);
            registry.mark_terminated("session-001", term_info).unwrap();

            // Step 4: Verify session is now TERMINATED with details
            let response = dispatcher.dispatch(&frame, &ctx).unwrap();

            match response {
                SessionResponse::SessionStatus(resp) => {
                    assert_eq!(
                        resp.state, "TERMINATED",
                        "Session should be TERMINATED after mark_terminated"
                    );
                    assert_eq!(
                        resp.termination_reason,
                        Some("budget_exhausted".to_string()),
                        "Termination reason should be populated"
                    );
                    assert_eq!(resp.exit_code, Some(1));
                    assert!(
                        resp.terminated_at_ns.is_some() && resp.terminated_at_ns.unwrap() > 0,
                        "terminated_at_ns should be set"
                    );
                    assert_eq!(resp.actual_tokens_consumed, Some(500_000));
                    assert_eq!(resp.work_id, "W-LIFECYCLE");
                    assert_eq!(resp.episode_id, Some("E-LIFECYCLE".to_string()));
                },
                other => panic!("Expected SessionStatus, got: {other:?}"),
            }
        }

        /// IT-00385-11 (MAJOR 1): Unknown termination reasons are normalized
        /// to "unknown" on the wire.
        #[test]
        fn test_unknown_termination_reason_normalized() {
            let minter = test_minter();
            let ctx = make_session_ctx();

            let registry = Arc::new(InMemorySessionRegistry::new());

            let session = SessionState {
                session_id: "session-001".to_string(),
                work_id: "W-NORM".to_string(),
                role: WorkRole::Implementer.into(),
                lease_id: "L-NORM".to_string(),
                ephemeral_handle: "handle-norm".to_string(),
                policy_resolved_ref: String::new(),
                capability_manifest_hash: vec![],
                episode_id: None,
            };
            registry.register_session(session).unwrap();

            // Use a free-form garbage string as termination reason
            let term_info = SessionTerminationInfo::new(
                "session-001",
                "some_arbitrary_freeform_reason",
                "FAILURE",
            );
            registry.mark_terminated("session-001", term_info).unwrap();

            let dyn_registry: Arc<dyn crate::session::SessionRegistry> = registry;
            let dispatcher =
                SessionDispatcher::new(minter.clone()).with_session_registry(dyn_registry);

            let token = test_token(&minter);
            let request = SessionStatusRequest {
                session_token: serde_json::to_string(&token).unwrap(),
            };
            let frame = encode_session_status_request(&request);
            let response = dispatcher.dispatch(&frame, &ctx).unwrap();

            match response {
                SessionResponse::SessionStatus(resp) => {
                    assert_eq!(
                        resp.termination_reason,
                        Some("unknown".to_string()),
                        "Free-form reason should be normalized to 'unknown'"
                    );
                },
                other => panic!("Expected SessionStatus, got: {other:?}"),
            }
        }
    }

    // ========================================================================
    // TCK-00395 Security BLOCKER 1: Post-termination revocation enforcement
    // ========================================================================

    /// Regression tests proving `EmitEvent` and `PublishEvidence` are denied
    /// after `EndSession` removes the session from the registry.
    mod post_termination_revocation {
        use super::*;
        use crate::episode::InMemorySessionRegistry;
        use crate::episode::broker::StubContentAddressedStore;
        use crate::protocol::dispatch::StubLedgerEventEmitter;
        use crate::protocol::messages::{EvidenceKind, RetentionHint, WorkRole};
        use crate::session::SessionState;

        /// Helper: build a session dispatcher with a ledger, CAS, and session
        /// registry where session "session-001" has been registered and then
        /// removed (simulating post-`EndSession` state).
        fn make_post_termination_dispatcher() -> SessionDispatcher<InMemoryManifestStore> {
            let minter = test_minter();
            let registry: Arc<dyn crate::session::SessionRegistry> =
                Arc::new(InMemorySessionRegistry::new());

            // Register and then remove the session to simulate EndSession
            let session = SessionState {
                session_id: "session-001".to_string(),
                work_id: "W-REVOKE-001".to_string(),
                role: WorkRole::Implementer.into(),
                lease_id: "L-REVOKE-001".to_string(),
                ephemeral_handle: "handle-revoke-001".to_string(),
                policy_resolved_ref: String::new(),
                capability_manifest_hash: vec![],
                episode_id: Some("E-REVOKE-001".to_string()),
            };
            registry
                .register_session(session)
                .expect("session registration should succeed");
            registry
                .remove_session("session-001")
                .expect("session removal should succeed");

            let ledger: Arc<dyn crate::protocol::dispatch::LedgerEventEmitter> =
                Arc::new(StubLedgerEventEmitter::new());
            let cas: Arc<dyn crate::episode::executor::ContentAddressedStore> =
                Arc::new(StubContentAddressedStore::new());

            SessionDispatcher::new(minter)
                .with_session_registry(registry)
                .with_ledger(ledger)
                .with_cas(cas)
        }

        /// TCK-00395 Security BLOCKER 1: `EmitEvent` is denied after
        /// `EndSession`.
        ///
        /// A retained HMAC token must not be able to write events to the
        /// ledger after the session has been terminated.
        #[test]
        fn emit_event_denied_after_end_session() {
            let dispatcher = make_post_termination_dispatcher();
            let minter = test_minter();
            let ctx = make_session_ctx();
            let token = test_token(&minter);

            let request = EmitEventRequest {
                session_token: serde_json::to_string(&token).unwrap(),
                event_type: "post_termination_event".to_string(),
                payload: vec![1, 2, 3],
                correlation_id: "corr-revoke-001".to_string(),
            };
            let frame = encode_emit_event_request(&request);
            let response = dispatcher.dispatch(&frame, &ctx).unwrap();

            match response {
                SessionResponse::Error(err) => {
                    assert_eq!(
                        err.code,
                        SessionErrorCode::SessionErrorInvalid as i32,
                        "Expected SESSION_ERROR_INVALID for terminated session"
                    );
                    assert!(
                        err.message.contains("terminated") || err.message.contains("not found"),
                        "Error should mention session termination: {}",
                        err.message
                    );
                },
                other => panic!("Expected error for EmitEvent after EndSession, got: {other:?}"),
            }
        }

        /// TCK-00395 Security BLOCKER 1: `PublishEvidence` is denied after
        /// `EndSession`.
        ///
        /// A retained HMAC token must not be able to write artifacts to
        /// CAS after the session has been terminated.
        #[test]
        fn publish_evidence_denied_after_end_session() {
            let dispatcher = make_post_termination_dispatcher();
            let minter = test_minter();
            let ctx = make_session_ctx();
            let token = test_token(&minter);

            let request = PublishEvidenceRequest {
                session_token: serde_json::to_string(&token).unwrap(),
                artifact: vec![1, 2, 3, 4, 5],
                kind: EvidenceKind::ToolIo.into(),
                retention_hint: RetentionHint::Standard.into(),
            };
            let frame = encode_publish_evidence_request(&request);
            let response = dispatcher.dispatch(&frame, &ctx).unwrap();

            match response {
                SessionResponse::Error(err) => {
                    assert_eq!(
                        err.code,
                        SessionErrorCode::SessionErrorInvalid as i32,
                        "Expected SESSION_ERROR_INVALID for terminated session"
                    );
                    assert!(
                        err.message.contains("terminated") || err.message.contains("not found"),
                        "Error should mention session termination: {}",
                        err.message
                    );
                },
                other => {
                    panic!("Expected error for PublishEvidence after EndSession, got: {other:?}")
                },
            }
        }

        /// TCK-00395 Security BLOCKER 1: `SessionStatus` is still allowed after
        /// `EndSession` (the only post-termination endpoint).
        ///
        /// This confirms the positive case: `SessionStatus` should still work
        /// for terminated sessions to allow agents to query final state.
        #[test]
        fn session_status_allowed_after_end_session() {
            let minter = test_minter();
            let ctx = make_session_ctx();

            // Create dispatcher without registry - SessionStatus falls back
            // to token-based status (always returns ACTIVE from token alone).
            // With registry wired, it would return TERMINATED if the session
            // was mark_terminated. Both paths allow SessionStatus.
            let dispatcher = SessionDispatcher::new(minter.clone());
            let token = test_token(&minter);

            let request = SessionStatusRequest {
                session_token: serde_json::to_string(&token).unwrap(),
            };
            let frame = encode_session_status_request(&request);
            let response = dispatcher.dispatch(&frame, &ctx).unwrap();

            // SessionStatus should succeed (not be blocked)
            assert!(
                matches!(response, SessionResponse::SessionStatus(_)),
                "SessionStatus should be allowed post-termination, got: {response:?}"
            );
        }

        /// TCK-00395 Security BLOCKER 1: `EmitEvent` succeeds while session is
        /// still active (positive test / no regression).
        #[test]
        fn emit_event_succeeds_while_session_active() {
            use crate::htf::{ClockConfig, HolonicClock};

            let minter = test_minter();
            let ctx = make_session_ctx();

            let registry: Arc<dyn crate::session::SessionRegistry> =
                Arc::new(InMemorySessionRegistry::new());
            let session = SessionState {
                session_id: "session-001".to_string(),
                work_id: "W-ACTIVE-001".to_string(),
                role: WorkRole::Implementer.into(),
                lease_id: "L-ACTIVE-001".to_string(),
                ephemeral_handle: "handle-active-001".to_string(),
                policy_resolved_ref: String::new(),
                capability_manifest_hash: vec![],
                episode_id: Some("E-ACTIVE-001".to_string()),
            };
            registry.register_session(session).unwrap();

            let ledger: Arc<dyn crate::protocol::dispatch::LedgerEventEmitter> =
                Arc::new(StubLedgerEventEmitter::new());
            let clock = Arc::new(
                HolonicClock::new(ClockConfig::default(), None)
                    .expect("default ClockConfig should succeed"),
            );

            let dispatcher = SessionDispatcher::new(minter.clone())
                .with_session_registry(registry)
                .with_ledger(ledger)
                .with_clock(clock);

            let token = test_token(&minter);
            let request = EmitEventRequest {
                session_token: serde_json::to_string(&token).unwrap(),
                event_type: "active_session_event".to_string(),
                payload: vec![1, 2, 3],
                correlation_id: "corr-active-001".to_string(),
            };
            let frame = encode_emit_event_request(&request);
            let response = dispatcher.dispatch(&frame, &ctx).unwrap();

            // Should succeed (EmitEvent response, not error)
            assert!(
                matches!(response, SessionResponse::EmitEvent(_)),
                "EmitEvent should succeed for active session, got: {response:?}"
            );
        }
    }

    // ========================================================================
    // TCK-00352 MAJOR 4: V1 dispatch/session integration tests
    //
    // These tests prove that V1 scope enforcement is exercised through the
    // real `SessionDispatcher::handle_request_tool` path, including deny
    // paths for envelope mismatch, scoped host/path violations, and risk
    // tier ceiling enforcement.
    // ========================================================================
    mod v1_integration_tests {
        use std::path::PathBuf;
        use std::sync::Arc;
        use std::time::{Duration, SystemTime};

        use secrecy::SecretString;

        use super::*;
        use crate::episode::InMemorySessionRegistry;
        use crate::episode::capability::{
            Capability, CapabilityManifest, CapabilityManifestV1, PolicyMintToken,
        };
        use crate::episode::envelope::RiskTier;
        use crate::episode::scope::{CapabilityScope, SizeLimits};
        use crate::episode::tool_class::ToolClass;
        use crate::protocol::credentials::PeerCredentials;
        use crate::protocol::messages::{RequestToolRequest, SessionErrorCode};
        use crate::protocol::session_dispatch::{
            InMemoryManifestStore, SharedV1ManifestStore, V1ManifestStore,
        };
        use crate::session::SessionState;

        fn test_minter() -> TokenMinter {
            TokenMinter::new(SecretString::from("test-daemon-secret-key-32bytes!!"))
        }

        fn make_session_ctx() -> ConnectionContext {
            ConnectionContext::session_open(
                Some(PeerCredentials {
                    uid: 1000,
                    gid: 1000,
                    pid: Some(12346),
                }),
                Some("session-v1-001".to_string()),
            )
        }

        /// Helper: Creates a V1 manifest with Read capability rooted at
        /// /workspace, and registers it in the V1 store for session-v1-001.
        fn setup_v1_dispatcher(
            host_restrictions: Vec<String>,
            tool_allowlist: &[ToolClass],
            capabilities: Vec<Capability>,
        ) -> (SessionDispatcher<InMemoryManifestStore>, TokenMinter) {
            let minter = test_minter();
            let v1_store: SharedV1ManifestStore = Arc::new(V1ManifestStore::new());

            // Build a manifest with explicit tool allowlist and capabilities
            let manifest = CapabilityManifest::builder("v1-int-test")
                .delegator("policy-resolver")
                .created_at(1000)
                .expires_at(4_070_908_800) // 2099-01-01 UTC
                .capabilities(capabilities)
                .tool_allowlist(tool_allowlist.to_vec())
                .build()
                .unwrap();

            // Also register in regular manifest store for risk tier lookup
            let manifest_store = Arc::new(InMemoryManifestStore::new());
            manifest_store.register("session-v1-001", manifest.clone());

            // Mint V1 manifest and register
            let v1_manifest = CapabilityManifestV1::mint(
                PolicyMintToken::new(),
                manifest,
                RiskTier::Tier2,
                host_restrictions,
            )
            .unwrap();
            v1_store.register("session-v1-001", v1_manifest);

            // Register session in registry
            let registry: Arc<dyn crate::session::SessionRegistry> =
                Arc::new(InMemorySessionRegistry::new());
            let session = SessionState {
                session_id: "session-v1-001".to_string(),
                work_id: "W-V1-TEST".to_string(),
                role: crate::protocol::messages::WorkRole::Implementer.into(),
                lease_id: "L-V1-001".to_string(),
                ephemeral_handle: "handle-v1".to_string(),
                policy_resolved_ref: String::new(),
                capability_manifest_hash: vec![],
                episode_id: Some("E-V1-001".to_string()),
            };
            registry.register_session(session).unwrap();

            let dispatcher = SessionDispatcher::with_manifest_store(minter.clone(), manifest_store)
                .with_v1_manifest_store(v1_store)
                .with_session_registry(registry);

            (dispatcher, minter)
        }

        fn make_tool_request(
            minter: &TokenMinter,
            tool_id: &str,
            args_json: &serde_json::Value,
        ) -> Bytes {
            let spawn_time = SystemTime::now();
            let ttl = Duration::from_secs(3600);
            let token = minter
                .mint("session-v1-001", "L-V1-001", spawn_time, ttl)
                .unwrap();
            let request = RequestToolRequest {
                session_token: serde_json::to_string(&token).unwrap(),
                tool_id: tool_id.to_string(),
                arguments: serde_json::to_vec(args_json).unwrap(),
                dedupe_key: format!("dedupe-{}", uuid::Uuid::new_v4()),
                epoch_seal: None,
            };
            encode_request_tool_request(&request)
        }

        /// TCK-00352 BLOCKER 1 integration test: V1 scope enforcement
        /// denies a network request to an unauthorized host when the
        /// actual host is extracted from request.arguments.
        #[test]
        fn v1_denies_network_request_to_unauthorized_host_via_dispatch() {
            let (dispatcher, minter) = setup_v1_dispatcher(
                vec!["*.trusted.corp".to_string()], // Only trusted hosts
                &[ToolClass::Network],
                vec![
                    Capability::builder("net-cap", ToolClass::Network)
                        .scope(CapabilityScope {
                            root_paths: Vec::new(),
                            allowed_patterns: Vec::new(),
                            size_limits: SizeLimits::default_limits(),
                            network_policy: Some(crate::episode::scope::NetworkPolicy {
                                allowed_hosts: vec!["*.trusted.corp".to_string()],
                                allowed_ports: vec![443],
                                require_tls: true,
                            }),
                        })
                        .risk_tier(RiskTier::Tier1)
                        .build()
                        .unwrap(),
                ],
            );
            let ctx = make_session_ctx();

            // Request with unauthorized host in URL
            let frame = make_tool_request(
                &minter,
                "network",
                &serde_json::json!({
                    "url": "https://evil-exfil.attacker.com/steal-data",
                    "method": "GET"
                }),
            );
            let response = dispatcher.dispatch(&frame, &ctx).unwrap();

            match response {
                SessionResponse::Error(err) => {
                    assert_eq!(
                        err.code,
                        SessionErrorCode::SessionErrorToolNotAllowed as i32,
                        "Expected TOOL_NOT_ALLOWED for unauthorized host"
                    );
                    assert!(
                        err.message.contains("V1 scope enforcement denied")
                            || err.message.contains("NetworkNotAllowed"),
                        "Error should mention V1 scope denial or NetworkNotAllowed: {}",
                        err.message
                    );
                },
                other => panic!("Expected V1 denial for unauthorized network host, got: {other:?}"),
            }
        }

        /// TCK-00352 BLOCKER 1 integration test: V1 scope enforcement
        /// denies a Read request with a path outside the allowed scope.
        #[test]
        fn v1_denies_read_request_with_out_of_scope_path_via_dispatch() {
            let (dispatcher, minter) = setup_v1_dispatcher(
                Vec::new(),
                &[ToolClass::Read],
                vec![
                    Capability::builder("read-cap", ToolClass::Read)
                        .scope(CapabilityScope {
                            root_paths: vec![PathBuf::from("/workspace")],
                            allowed_patterns: Vec::new(),
                            size_limits: SizeLimits::default_limits(),
                            network_policy: None,
                        })
                        .risk_tier(RiskTier::Tier1)
                        .build()
                        .unwrap(),
                ],
            );
            let ctx = make_session_ctx();

            // Request a path outside /workspace
            let frame = make_tool_request(
                &minter,
                "read",
                &serde_json::json!({
                    "path": "/etc/shadow"
                }),
            );
            let response = dispatcher.dispatch(&frame, &ctx).unwrap();

            match response {
                SessionResponse::Error(err) => {
                    assert_eq!(
                        err.code,
                        SessionErrorCode::SessionErrorToolNotAllowed as i32,
                        "Expected TOOL_NOT_ALLOWED for out-of-scope path"
                    );
                    assert!(
                        err.message.contains("V1 scope enforcement denied")
                            || err.message.contains("PathNotAllowed"),
                        "Error should mention V1 scope denial: {}",
                        err.message
                    );
                },
                other => panic!("Expected V1 denial for out-of-scope path, got: {other:?}"),
            }
        }

        /// TCK-00352 MAJOR 4 integration test: V1 scope enforcement
        /// denies a tool not in the manifest allowlist.
        #[test]
        fn v1_denies_disallowed_tool_class_via_dispatch() {
            // Only Read is allowed, Execute is not
            let (dispatcher, minter) = setup_v1_dispatcher(
                Vec::new(),
                &[ToolClass::Read],
                vec![
                    Capability::builder("read-cap", ToolClass::Read)
                        .scope(CapabilityScope {
                            root_paths: vec![PathBuf::from("/workspace")],
                            allowed_patterns: Vec::new(),
                            size_limits: SizeLimits::default_limits(),
                            network_policy: None,
                        })
                        .risk_tier(RiskTier::Tier1)
                        .build()
                        .unwrap(),
                ],
            );
            let ctx = make_session_ctx();

            // Request Execute, which is not in the tool allowlist
            let frame = make_tool_request(
                &minter,
                "execute",
                &serde_json::json!({
                    "command": "rm",
                    "args": ["-rf", "/"]
                }),
            );
            let response = dispatcher.dispatch(&frame, &ctx).unwrap();

            match response {
                SessionResponse::Error(err) => {
                    assert_eq!(
                        err.code,
                        SessionErrorCode::SessionErrorToolNotAllowed as i32,
                        "Expected TOOL_NOT_ALLOWED for disallowed tool class"
                    );
                    assert!(
                        err.message.contains("V1 scope enforcement denied")
                            || err.message.contains("ToolNotInAllowlist"),
                        "Error should mention V1 scope denial: {}",
                        err.message
                    );
                },
                other => panic!("Expected V1 denial for disallowed tool class, got: {other:?}"),
            }
        }

        /// TCK-00352 BLOCKER 1 v3: Authority confusion attack via userinfo
        /// in URL. A URL like `https://trusted.com:443@evil.com/steal` must
        /// be rejected because the actual network destination is `evil.com`,
        /// not `trusted.com`. The `url` crate correctly parses the authority
        /// and we deny any URL containing userinfo.
        #[test]
        fn v1_denies_url_with_userinfo_authority_confusion() {
            let (dispatcher, minter) = setup_v1_dispatcher(
                vec!["*.trusted.com".to_string()],
                &[ToolClass::Network],
                vec![
                    Capability::builder("net-cap", ToolClass::Network)
                        .scope(CapabilityScope {
                            root_paths: Vec::new(),
                            allowed_patterns: Vec::new(),
                            size_limits: SizeLimits::default_limits(),
                            network_policy: Some(crate::episode::scope::NetworkPolicy {
                                allowed_hosts: vec!["*.trusted.com".to_string()],
                                allowed_ports: vec![443],
                                require_tls: true,
                            }),
                        })
                        .risk_tier(RiskTier::Tier1)
                        .build()
                        .unwrap(),
                ],
            );
            let ctx = make_session_ctx();

            // Authority confusion: "trusted.com:443" looks like host:port
            // but is actually the userinfo component. The real host is evil.com.
            let frame = make_tool_request(
                &minter,
                "network",
                &serde_json::json!({
                    "url": "https://trusted.com:443@evil.com/steal",
                    "method": "GET"
                }),
            );
            let response = dispatcher.dispatch(&frame, &ctx).unwrap();

            match response {
                SessionResponse::Error(err) => {
                    assert_eq!(
                        err.code,
                        SessionErrorCode::SessionErrorToolNotAllowed as i32,
                        "Expected TOOL_NOT_ALLOWED for authority confusion URL"
                    );
                    assert!(
                        err.message.contains("userinfo"),
                        "Error should mention userinfo rejection: {}",
                        err.message
                    );
                },
                other => panic!("Expected denial for authority confusion URL, got: {other:?}"),
            }
        }

        /// TCK-00352 BLOCKER 1 v3: URL with username-only userinfo must
        /// also be rejected. Even without a password, the presence of
        /// userinfo indicates potential authority confusion.
        #[test]
        fn v1_denies_url_with_username_only_userinfo() {
            let (dispatcher, minter) = setup_v1_dispatcher(
                vec!["*.trusted.com".to_string()],
                &[ToolClass::Network],
                vec![
                    Capability::builder("net-cap", ToolClass::Network)
                        .scope(CapabilityScope {
                            root_paths: Vec::new(),
                            allowed_patterns: Vec::new(),
                            size_limits: SizeLimits::default_limits(),
                            network_policy: Some(crate::episode::scope::NetworkPolicy {
                                allowed_hosts: vec!["*.trusted.com".to_string()],
                                allowed_ports: vec![443],
                                require_tls: true,
                            }),
                        })
                        .risk_tier(RiskTier::Tier1)
                        .build()
                        .unwrap(),
                ],
            );
            let ctx = make_session_ctx();

            // Username-only userinfo: user@ before the host
            let frame = make_tool_request(
                &minter,
                "network",
                &serde_json::json!({
                    "url": "https://admin@evil.com/path",
                    "method": "GET"
                }),
            );
            let response = dispatcher.dispatch(&frame, &ctx).unwrap();

            match response {
                SessionResponse::Error(err) => {
                    assert_eq!(
                        err.code,
                        SessionErrorCode::SessionErrorToolNotAllowed as i32,
                        "Expected TOOL_NOT_ALLOWED for username-only userinfo URL"
                    );
                    assert!(
                        err.message.contains("userinfo"),
                        "Error should mention userinfo rejection: {}",
                        err.message
                    );
                },
                other => panic!("Expected denial for username-only userinfo URL, got: {other:?}"),
            }
        }

        /// TCK-00352 BLOCKER 1 v3: Unparseable URL must be denied for
        /// Network tool class (fail-closed). If we cannot reliably determine
        /// the host, we must not allow the request through.
        #[test]
        fn v1_denies_unparseable_url_for_network_tool() {
            let (dispatcher, minter) = setup_v1_dispatcher(
                vec!["*.trusted.com".to_string()],
                &[ToolClass::Network],
                vec![
                    Capability::builder("net-cap", ToolClass::Network)
                        .scope(CapabilityScope {
                            root_paths: Vec::new(),
                            allowed_patterns: Vec::new(),
                            size_limits: SizeLimits::default_limits(),
                            network_policy: Some(crate::episode::scope::NetworkPolicy {
                                allowed_hosts: vec!["*.trusted.com".to_string()],
                                allowed_ports: vec![443],
                                require_tls: true,
                            }),
                        })
                        .risk_tier(RiskTier::Tier1)
                        .build()
                        .unwrap(),
                ],
            );
            let ctx = make_session_ctx();

            // Relative URL path: the `url` crate rejects URLs without a
            // valid scheme (relative references are not valid absolute URLs).
            let frame = make_tool_request(
                &minter,
                "network",
                &serde_json::json!({
                    "url": "/relative/path/no/scheme",
                    "method": "GET"
                }),
            );
            let response = dispatcher.dispatch(&frame, &ctx).unwrap();

            match response {
                SessionResponse::Error(err) => {
                    assert_eq!(
                        err.code,
                        SessionErrorCode::SessionErrorToolNotAllowed as i32,
                        "Expected TOOL_NOT_ALLOWED for unparseable URL"
                    );
                    assert!(
                        err.message.contains("URL parse failed"),
                        "Error should mention URL parse failure: {}",
                        err.message
                    );
                },
                other => {
                    panic!("Expected denial for unparseable URL on Network tool, got: {other:?}")
                },
            }
        }

        /// TCK-00352 MAJOR 2: V1 store cleanup on remove.
        /// Verifies that removing a V1 manifest from the store means
        /// subsequent requests bypass V1 checks (as if the session
        /// was terminated).
        #[test]
        fn v1_store_remove_clears_manifest() {
            let v1_store = V1ManifestStore::new();
            let manifest = CapabilityManifest::builder("cleanup-test")
                .delegator("daemon")
                .created_at(1000)
                .expires_at(4_070_908_800)
                .tool_allowlist(vec![ToolClass::Read])
                .build()
                .unwrap();
            let v1 = CapabilityManifestV1::mint(
                PolicyMintToken::new(),
                manifest,
                RiskTier::Tier2,
                Vec::new(),
            )
            .unwrap();

            v1_store.register("sess-cleanup", v1);
            assert!(
                v1_store.get("sess-cleanup").is_some(),
                "V1 manifest should be registered"
            );

            v1_store.remove("sess-cleanup");
            assert!(
                v1_store.get("sess-cleanup").is_none(),
                "V1 manifest should be removed after cleanup"
            );
        }
    }

    // ========================================================================
    // TCK-00377: tool_kind population from session dispatch
    // ========================================================================
    mod tool_kind_population {
        use apm2_core::tool::{self, tool_request as tool_req};

        use super::*;

        /// Verify that the proto construction + `tool_kind_from_proto`
        /// conversion produces a populated `ToolKind` for each
        /// supported `ToolClass`, and that `with_tool_kind` wires it
        /// onto `BrokerToolRequest`.
        ///
        /// This confirms the session dispatch path will deliver a non-`None`
        /// `tool_kind` to the broker for precondition enforcement.
        #[test]
        fn test_tool_kind_populated_for_file_read() {
            let proto = tool_req::Tool::FileRead(tool::FileRead {
                path: "/workspace/file.txt".to_string(),
                offset: 0,
                limit: 0,
            });
            let tk = tool::tool_kind_from_proto(&proto).expect("FileRead must convert");
            assert!(
                matches!(tk, tool::ToolKind::ReadFile { .. }),
                "expected ReadFile, got: {tk:?}"
            );

            let request = BrokerToolRequest::new(
                "req-tk-read",
                crate::episode::EpisodeId::new("ep-tk-read").unwrap(),
                ToolClass::Read,
                crate::episode::decision::DedupeKey::new("dk"),
                [0u8; 32],
                crate::episode::envelope::RiskTier::Tier0,
            )
            .with_tool_kind(tk);
            assert!(
                request.tool_kind.is_some(),
                "tool_kind must be populated after with_tool_kind"
            );
        }

        #[test]
        fn test_tool_kind_populated_for_file_write() {
            let proto = tool_req::Tool::FileWrite(tool::FileWrite {
                path: "/workspace/out.txt".to_string(),
                content: b"hello".to_vec(),
                create_only: true,
                append: false,
            });
            let tk = tool::tool_kind_from_proto(&proto).expect("FileWrite must convert");
            assert!(
                matches!(tk, tool::ToolKind::WriteFile { .. }),
                "expected WriteFile, got: {tk:?}"
            );

            // Verify the precondition was derived from create_only=true
            if let tool::ToolKind::WriteFile { precondition, .. } = &tk {
                assert_eq!(
                    *precondition,
                    Some(tool::IdempotencyPrecondition::FileNotExists),
                    "create_only=true must produce FileNotExists precondition"
                );
            }
        }

        #[test]
        fn test_tool_kind_populated_for_file_edit() {
            let proto = tool_req::Tool::FileEdit(tool::FileEdit {
                path: "/workspace/code.rs".to_string(),
                old_content: "old".to_string(),
                new_content: "new".to_string(),
            });
            let tk = tool::tool_kind_from_proto(&proto).expect("FileEdit must convert");
            assert!(
                matches!(tk, tool::ToolKind::EditFile { .. }),
                "expected EditFile, got: {tk:?}"
            );

            // Verify the precondition was derived (EditFile always has FileExists)
            if let tool::ToolKind::EditFile { precondition, .. } = &tk {
                assert_eq!(
                    *precondition,
                    Some(tool::IdempotencyPrecondition::FileExists),
                    "FileEdit must produce FileExists precondition"
                );
            }
        }

        #[test]
        fn test_tool_kind_populated_for_git_op() {
            let proto = tool_req::Tool::GitOp(tool::GitOperation {
                operation: "STATUS".to_string(),
                args: vec![],
                cwd: "/workspace".to_string(),
            });
            let tk = tool::tool_kind_from_proto(&proto).expect("GitOp must convert");
            assert!(
                matches!(tk, tool::ToolKind::GitOp { .. }),
                "expected GitOp, got: {tk:?}"
            );
        }

        #[test]
        fn test_tool_kind_populated_for_shell_exec() {
            let proto = tool_req::Tool::ShellExec(tool::ShellExec {
                command: "ls -la".to_string(),
                cwd: "/workspace".to_string(),
                timeout_ms: 5000,
                network_access: false,
                env: vec![],
            });
            let tk = tool::tool_kind_from_proto(&proto).expect("ShellExec must convert");
            assert!(
                matches!(tk, tool::ToolKind::ShellExec { .. }),
                "expected ShellExec, got: {tk:?}"
            );
        }

        /// Verify that the JSON-to-proto reconstruction matches what session
        /// dispatch does: parse JSON args, build proto, convert to `ToolKind`.
        /// This is the exact path that populates `broker_request.tool_kind`.
        #[test]
        fn test_session_dispatch_json_to_tool_kind_roundtrip() {
            // Simulate a Write request with create_only=true (triggers precondition)
            let args_json = serde_json::json!({
                "path": "/workspace/new-file.txt",
                "content": "file body",
                "create_only": true,
                "append": false,
            });
            let args_bytes = serde_json::to_vec(&args_json).unwrap();

            // Parse exactly as session dispatch does
            let args_value: serde_json::Value = serde_json::from_slice(&args_bytes).unwrap();

            let path = args_value
                .get("path")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_string();
            let content = args_value
                .get("content")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .as_bytes()
                .to_vec();
            let create_only = args_value
                .get("create_only")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            let append = args_value
                .get("append")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);

            let proto = tool_req::Tool::FileWrite(tool::FileWrite {
                path,
                content,
                create_only,
                append,
            });

            let tk = tool::tool_kind_from_proto(&proto)
                .expect("JSON-constructed FileWrite proto must convert to ToolKind");

            // Verify precondition is wired through
            if let tool::ToolKind::WriteFile {
                precondition,
                create_only: co,
                ..
            } = &tk
            {
                assert!(co, "create_only must be true");
                assert_eq!(
                    *precondition,
                    Some(tool::IdempotencyPrecondition::FileNotExists),
                    "create_only=true must yield FileNotExists precondition"
                );
            } else {
                panic!("expected WriteFile ToolKind, got: {tk:?}");
            }

            // Wire it onto a BrokerToolRequest and confirm it's populated
            let request = BrokerToolRequest::new(
                "req-roundtrip",
                crate::episode::EpisodeId::new("ep-roundtrip").unwrap(),
                ToolClass::Write,
                crate::episode::decision::DedupeKey::new("dk"),
                [0u8; 32],
                crate::episode::envelope::RiskTier::Tier0,
            )
            .with_tool_kind(tk);

            assert!(
                request.tool_kind.is_some(),
                "BrokerToolRequest.tool_kind must be Some after session dispatch wiring"
            );
            assert!(
                matches!(
                    request.tool_kind,
                    Some(tool::ToolKind::WriteFile {
                        precondition: Some(tool::IdempotencyPrecondition::FileNotExists),
                        ..
                    })
                ),
                "tool_kind must carry the FileNotExists precondition"
            );
        }
    }
}
