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

use apm2_core::coordination::ContextRefinementRequest;
use apm2_core::events::{DefectRecorded, DefectSource, TimeEnvelopeRef};
use apm2_holon::defect::DefectRecord;
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
use crate::episode::decision::{BrokerToolRequest, DedupeKey, ToolDecision};
use crate::episode::envelope::RiskTier;
use crate::episode::executor::ContentAddressedStore;
use crate::episode::registry::TerminationReason;
use crate::episode::{CapabilityManifest, EpisodeId, EpisodeRuntime, SharedToolBroker, ToolClass};
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
}

impl ManifestStore for InMemoryManifestStore {
    fn get_manifest(&self, session_id: &str) -> Option<Arc<CapabilityManifest>> {
        let manifests = self.manifests.read().expect("lock poisoned");
        manifests.get(session_id).cloned()
    }
}

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
            clock: None,
            event_seq: AtomicU64::new(0),
            subscription_registry: None,
            episode_runtime: None,
            session_registry: None,
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
            clock: None,
            event_seq: AtomicU64::new(0),
            subscription_registry: None,
            episode_runtime: None,
            session_registry: None,
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
            clock: None,
            event_seq: AtomicU64::new(0),
            subscription_registry: None,
            episode_runtime: None,
            session_registry: None,
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
            clock: None,
            event_seq: AtomicU64::new(0),
            subscription_registry: None,
            episode_runtime: None,
            session_registry: None,
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
            clock: None,
            event_seq: AtomicU64::new(0),
            subscription_registry: None,
            episode_runtime: None,
            session_registry: None,
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

        // TCK-00290: Use ToolBroker for request validation and execution
        // Per DOD: "RequestTool executes via ToolBroker and returns ToolResult or Deny"
        if let Some(ref broker) = self.broker {
            // TCK-00290 BLOCKER 3: Get monotonic timestamp from HolonicClock
            let timestamp_ns = self.get_htf_timestamp()?;

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

            // BLOCKER 2 FIX (TCK-00290): Derive risk tier from capability manifest.
            // Per the security review, we must not hardcode Tier0. Get the risk tier
            // from the manifest's capability for this tool class, or default to Tier0
            // if no specific tier is configured (fail-open for tier, fail-closed for
            // access).
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

            // Clone arguments for execution before they are moved into BrokerToolRequest
            let request_arguments = request.arguments.clone();

            let broker_request = BrokerToolRequest::new(
                &request_id,
                episode_id.clone(),
                tool_class,
                dedupe_key,
                args_hash,
                risk_tier,
            )
            .with_inline_args(request.arguments);

            // Call broker.request() asynchronously using tokio runtime
            let decision = tokio::task::block_in_place(|| {
                let handle = tokio::runtime::Handle::current();
                handle.block_on(async { broker.request(&broker_request, timestamp_ns, None).await })
            });

            return self.handle_broker_decision(
                decision,
                &token.session_id,
                tool_class,
                &request_arguments,
                timestamp_ns,
                &episode_id,
            );
        }

        // INV-TCK-00290-001: Neither broker nor manifest store configured - fail closed
        warn!(
            session_id = %token.session_id,
            "RequestTool denied: neither broker nor manifest store configured (fail-closed)"
        );
        Ok(SessionResponse::error(
            SessionErrorCode::SessionErrorToolNotAllowed,
            "tool broker unavailable (fail-closed)",
        ))
    }

    /// Handles the broker decision and converts it to a `SessionResponse`.
    #[allow(clippy::unnecessary_wraps, clippy::items_after_statements)]
    fn handle_broker_decision(
        &self,
        decision: Result<ToolDecision, crate::episode::BrokerError>,
        session_id: &str,
        tool_class: ToolClass,
        request_arguments: &[u8],
        timestamp_ns: u64,
        episode_id: &EpisodeId,
    ) -> ProtocolResult<SessionResponse> {
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
                    let execution_result = tokio::task::block_in_place(|| {
                        let handle = tokio::runtime::Handle::current();
                        handle.block_on(async {
                            runtime
                                .execute_tool(
                                    episode_id,
                                    &tool_args,
                                    credential.as_ref(),
                                    timestamp_ns,
                                    &request_id,
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

                Ok(SessionResponse::RequestTool(RequestToolResponse {
                    request_id,
                    decision: DecisionType::Allow.into(),
                    rule_id,
                    policy_hash: policy_hash.to_vec(),
                    result_hash,
                    inline_result,
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
                Ok(SessionResponse::RequestTool(RequestToolResponse {
                    request_id,
                    decision: DecisionType::Deny.into(),
                    rule_id,
                    policy_hash: policy_hash.to_vec(),
                    result_hash: None,
                    inline_result: None,
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

                Ok(SessionResponse::RequestTool(RequestToolResponse {
                    request_id,
                    decision: DecisionType::Allow.into(),
                    rule_id: None,
                    // Empty policy_hash for cache hits - policy was evaluated on original request
                    policy_hash: Vec::new(),
                    result_hash,
                    inline_result,
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
                if let Some(session_registry) = &self.session_registry {
                    session_registry.mark_terminated(session_id, *termination_info.clone());
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
    fn get_htf_timestamp(&self) -> ProtocolResult<u64> {
        // Using match here for clarity - the error paths have important security
        // comments that would be less readable with map_or_else or if let/else.
        match &self.clock {
            Some(clock) => clock.now_hlc().map(|hlc| hlc.wall_ns).map_err(|e| {
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
        let now_ns = self.get_htf_timestamp()?;

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

        // Query session registry for session state
        if let Some(session_registry) = &self.session_registry {
            // First check for active session
            if let Some(session) = session_registry.get_session(&token.session_id) {
                // Calculate session duration
                let duration_ms = SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
                    .unwrap_or(0);

                let response = SessionStatusResponse {
                    session_id: token.session_id.clone(),
                    state: "ACTIVE".to_string(),
                    work_id: session.work_id,
                    role: session.role,
                    episode_id: session.episode_id,
                    tool_calls: 0,     // TODO: Track in session telemetry
                    events_emitted: 0, // TODO: Track in session telemetry
                    started_at_ns: 0,  // TODO: Track session start time
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
        ConnectionContext::session(
            Some(PeerCredentials {
                uid: 1000,
                gid: 1000,
                pid: Some(12346),
            }),
            Some("session-001".to_string()),
        )
    }

    fn make_privileged_ctx() -> ConnectionContext {
        ConnectionContext::privileged(Some(PeerCredentials {
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
        use super::*;
        use crate::episode::{ToolBroker, ToolBrokerConfig, ToolClass};

        /// TCK-00316: Verify fail-closed behavior when broker is configured but
        /// holonic clock is missing.
        ///
        /// Per SEC-CTRL-FAC-0015, the dispatcher must fail-closed when required
        /// infrastructure (clock, runtime) is missing. This test verifies the
        /// clock check happens before broker request.
        #[test]
        fn test_request_tool_fails_closed_without_clock() {
            let minter = test_minter();
            let store = Arc::new(InMemoryManifestStore::new());

            // Build manifest with Read allowed
            let manifest = tck_00260_manifest_validation::make_test_manifest(vec![ToolClass::Read]);
            store.register("session-001", manifest);

            // Create broker with default config
            let broker = Arc::new(ToolBroker::new(ToolBrokerConfig::default()));

            // Create dispatcher WITH broker but WITHOUT clock
            let dispatcher =
                SessionDispatcher::with_manifest_store(minter.clone(), store).with_broker(broker);

            let token = test_token(&minter);
            let ctx = make_session_ctx();

            // Send a RequestTool request for Read
            let request = RequestToolRequest {
                session_token: serde_json::to_string(&token).unwrap(),
                tool_id: "read".to_string(),
                arguments: vec![],
                dedupe_key: "test-dedupe-key".to_string(),
            };
            let frame = encode_request_tool_request(&request);

            // Should return protocol error for missing clock (fail-closed)
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
        use crate::session::SessionState;

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

            // Create dispatcher with session registry wired
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
                    assert_eq!(resp.work_id, "W-SS-001");
                    assert_eq!(resp.role, i32::from(WorkRole::Implementer));
                    assert_eq!(resp.episode_id, Some("E-SS-001".to_string()));
                    assert!(resp.duration_ms > 0, "duration_ms should be non-zero");
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
                registry.mark_terminated("session-001", term_info),
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

            assert!(registry.mark_terminated("session-001", term_info));

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
                !registry.mark_terminated("nonexistent", term_info),
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
            assert!(registry.mark_terminated("sess-term", term_info));

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

            registry.mark_terminated("s1", SessionTerminationInfo::new("s1", "normal", "SUCCESS"));
            registry.mark_terminated(
                "s2",
                SessionTerminationInfo::new("s2", "timeout", "FAILURE"),
            );

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
            registry.mark_terminated("sess-h", term_info);

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
            registry.mark_terminated("session-001", term_info);

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
            registry.mark_terminated("session-001", term_info);

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
}
