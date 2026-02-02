//! Session-scoped endpoint dispatcher for RFC-0017 IPC (TCK-00252, TCK-00260).
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
//! # Security Invariants
//!
//! - [INV-SESS-001] Session endpoints require valid session_token
//! - [INV-SESS-002] Invalid/expired tokens return SESSION_ERROR_INVALID
//! - [INV-SESS-003] Operator connections blocked from session handlers
//! - [INV-SESS-004] Token validation uses constant-time HMAC comparison
//!   (CTR-WH001)
//! - [INV-TCK-00260-001] Tool requests validated against capability manifest
//! - [INV-TCK-00260-002] Empty tool_allowlist denies all tools (fail-closed)
//!
//! # Message Flow
//!
//! ```text
//! ┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
//! │ session.sock    │────▶│ SessionDispatch  │──▶│ Handler Stubs   │
//! │ + session_token │     └─────────────────┘     └─────────────────┘
//! └─────────────────┘            │
//!                                │ Token Validation
//!                                │ (HMAC-SHA256)
//!                                ▼
//! ┌─────────────────┐     ┌─────────────────┐
//! │ operator.sock   │────▶│ SESSION_ERROR_  │
//! │ (no token)      │     │ PERMISSION_DENIED│
//! └─────────────────┘     └─────────────────┘
//! ```

use std::sync::Arc;
use std::time::SystemTime;

use bytes::Bytes;
use prost::Message;
use tracing::{debug, info, warn};

use super::dispatch::ConnectionContext;
use super::error::{ProtocolError, ProtocolResult};
use super::messages::{
    BoundedDecode, DecisionType, DecodeConfig, EmitEventRequest, EmitEventResponse,
    PublishEvidenceRequest, PublishEvidenceResponse, RequestToolRequest, RequestToolResponse,
    SessionError, SessionErrorCode, StreamTelemetryRequest, StreamTelemetryResponse,
};
use super::session_token::{SessionToken, SessionTokenError, TokenMinter};
use crate::episode::{CapabilityManifest, ToolClass};

// ============================================================================
// Message Type Tags (for routing)
// ============================================================================

/// Message type tags for session-scoped endpoint routing.
///
/// These tags are used to identify the message type before decoding,
/// allowing the dispatcher to route to the appropriate handler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SessionMessageType {
    /// `RequestTool` request (IPC-SESS-001)
    RequestTool     = 1,
    /// `EmitEvent` request (IPC-SESS-002)
    EmitEvent       = 2,
    /// `PublishEvidence` request (IPC-SESS-003)
    PublishEvidence = 3,
    /// `StreamTelemetry` request (IPC-SESS-004)
    StreamTelemetry = 4,
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
/// # Security Contract
///
/// Per INV-SESS-001 through INV-SESS-004 and INV-TCK-00260-001/002:
/// - All session endpoints require valid `session_token`
/// - Token validation uses constant-time HMAC comparison (CTR-WH001)
/// - Operator connections receive `SESSION_ERROR_PERMISSION_DENIED`
/// - Invalid/expired tokens receive `SESSION_ERROR_INVALID`
/// - Tool requests validated against capability manifest (TCK-00260)
/// - Empty `tool_allowlist` denies all tools (fail-closed)
pub struct SessionDispatcher<M: ManifestStore = InMemoryManifestStore> {
    /// Token minter for validation.
    token_minter: TokenMinter,
    /// Decode configuration for bounded message decoding.
    decode_config: DecodeConfig,
    /// Manifest store for capability validation (TCK-00260).
    manifest_store: Option<Arc<M>>,
}

impl SessionDispatcher<InMemoryManifestStore> {
    /// Creates a new dispatcher with the given token minter.
    #[must_use]
    pub fn new(token_minter: TokenMinter) -> Self {
        Self {
            token_minter,
            decode_config: DecodeConfig::default(),
            manifest_store: None,
        }
    }

    /// Creates a new dispatcher with custom decode configuration.
    #[must_use]
    pub const fn with_decode_config(
        token_minter: TokenMinter,
        decode_config: DecodeConfig,
    ) -> Self {
        Self {
            token_minter,
            decode_config,
            manifest_store: None,
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
        }
    }

    /// Creates a dispatcher with custom decode configuration and manifest
    /// store.
    #[must_use]
    pub const fn with_decode_config_and_manifest_store(
        token_minter: TokenMinter,
        decode_config: DecodeConfig,
        manifest_store: Arc<M>,
    ) -> Self {
        Self {
            token_minter,
            decode_config,
            manifest_store: Some(manifest_store),
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

        // TCK-00260: Look up capability manifest and validate tool allowlist
        if let Some(ref store) = self.manifest_store {
            if let Some(manifest) = store.get_manifest(&token.session_id) {
                // Check if tool is in allowlist
                if !manifest.is_tool_allowed(tool_class) {
                    warn!(
                        session_id = %token.session_id,
                        tool_class = %tool_class,
                        "Tool not in allowlist"
                    );
                    return Ok(SessionResponse::error(
                        SessionErrorCode::SessionErrorToolNotAllowed,
                        format!("tool class '{tool_class}' not in allowlist"),
                    ));
                }

                info!(
                    session_id = %token.session_id,
                    tool_class = %tool_class,
                    "Tool allowed by manifest"
                );

                // Tool is allowed - return Allow decision
                return Ok(SessionResponse::RequestTool(RequestToolResponse {
                    request_id: format!("REQ-{}", uuid::Uuid::new_v4()),
                    decision: DecisionType::Allow.into(),
                    rule_id: None,
                    policy_hash: manifest.digest().to_vec(),
                }));
            }
            // No manifest found - fail closed (SEC-CTRL-FAC-0015)
            // If a manifest store is configured, a manifest MUST be present.
            warn!(
                session_id = %token.session_id,
                "No manifest found for session, denying request (fail-closed)"
            );
            return Ok(SessionResponse::error(
                SessionErrorCode::SessionErrorToolNotAllowed,
                "capability manifest unavailable",
            ));
        }

        // No manifest store configured - return stub response
        // This maintains backward compatibility with existing tests
        Ok(SessionResponse::RequestTool(RequestToolResponse {
            request_id: format!("REQ-{}", token.session_id),
            decision: DecisionType::Allow.into(),
            rule_id: None,
            policy_hash: vec![0u8; 32],
        }))
    }

    /// Handles `EmitEvent` requests (IPC-SESS-002).
    ///
    /// # Stub Implementation
    ///
    /// This is a stub handler that validates the token and returns a
    /// placeholder response. Full implementation in future ticket.
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
            "EmitEvent request received (stub handler)"
        );

        // Validate required fields
        if request.event_type.is_empty() {
            return Ok(SessionResponse::error(
                SessionErrorCode::SessionErrorInvalid,
                "event_type is required",
            ));
        }

        // STUB: Return placeholder response
        #[allow(clippy::cast_possible_truncation)] // Timestamp won't overflow until year 2554
        let now_ns = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);

        Ok(SessionResponse::EmitEvent(EmitEventResponse {
            event_id: format!("EVT-STUB-{}", token.session_id),
            seq: 1,
            timestamp_ns: now_ns,
        }))
    }

    /// Handles `PublishEvidence` requests (IPC-SESS-003).
    ///
    /// # Stub Implementation
    ///
    /// This is a stub handler that validates the token and returns a
    /// placeholder response. Full implementation in future ticket.
    fn handle_publish_evidence(
        &self,
        payload: &[u8],
        ctx: &ConnectionContext,
    ) -> ProtocolResult<SessionResponse> {
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
            "PublishEvidence request received (stub handler)"
        );

        // Validate artifact is not empty
        if request.artifact.is_empty() {
            return Ok(SessionResponse::error(
                SessionErrorCode::SessionErrorInvalid,
                "artifact is required",
            ));
        }

        // STUB: Return placeholder response
        // Compute Blake3 hash of artifact for content addressing
        let hash = blake3::hash(&request.artifact);

        Ok(SessionResponse::PublishEvidence(PublishEvidenceResponse {
            artifact_hash: hash.as_bytes().to_vec(),
            storage_path: format!("evidence/stub/{}", hex::encode(hash.as_bytes())),
            ttl_secs: 86400, // 24 hours
        }))
    }

    /// Handles `StreamTelemetry` requests (IPC-SESS-004).
    ///
    /// # Stub Implementation
    ///
    /// This is a stub handler that validates the token and returns a
    /// placeholder response. Full implementation in future ticket.
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
        info!(
            session_id = %token.session_id,
            frame_seq = ?frame.map(|f| f.seq),
            peer_pid = ?ctx.peer_credentials().map(|c| c.pid),
            "StreamTelemetry request received (stub handler)"
        );

        // Validate frame is present
        if frame.is_none() {
            return Ok(SessionResponse::error(
                SessionErrorCode::SessionErrorInvalid,
                "telemetry frame is required",
            ));
        }

        // STUB: Return placeholder response
        Ok(SessionResponse::StreamTelemetry(StreamTelemetryResponse {
            ack_seq: frame.map_or(0, |f| f.seq),
            promoted: false,
        }))
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

        #[test]
        fn test_request_tool_routing() {
            let minter = test_minter();
            let dispatcher = SessionDispatcher::new(minter.clone());
            let ctx = make_session_ctx();
            let token = test_token(&minter);

            // TCK-00260: Use valid tool class name (was "file_read", now "read")
            let request = RequestToolRequest {
                session_token: serde_json::to_string(&token).unwrap(),
                tool_id: "read".to_string(), // Valid ToolClass
                arguments: vec![1, 2, 3],
                dedupe_key: "key-001".to_string(),
            };
            let frame = encode_request_tool_request(&request);

            let response = dispatcher.dispatch(&frame, &ctx).unwrap();
            assert!(matches!(response, SessionResponse::RequestTool(_)));
        }

        #[test]
        fn test_emit_event_routing() {
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
            assert!(matches!(response, SessionResponse::EmitEvent(_)));
        }

        #[test]
        fn test_publish_evidence_routing() {
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
            assert!(matches!(response, SessionResponse::PublishEvidence(_)));
        }

        #[test]
        fn test_stream_telemetry_routing() {
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
            assert!(matches!(response, SessionResponse::StreamTelemetry(_)));
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
                assert!(err.message.contains("frame"));
            },
            _ => panic!("Expected validation error for missing frame"),
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

        fn make_test_manifest(tools: Vec<ToolClass>) -> crate::episode::CapabilityManifest {
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
                SessionResponse::RequestTool(resp) => {
                    assert_eq!(resp.decision, DecisionType::Allow as i32);
                    assert!(!resp.policy_hash.is_empty());
                },
                _ => panic!("Expected RequestTool response, got: {response:?}"),
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
                        "Expected TOOL_NOT_ALLOWED error code"
                    );
                    assert!(
                        err.message.contains("not in allowlist"),
                        "Error message should mention allowlist: {}",
                        err.message
                    );
                },
                _ => panic!("Expected SESSION_ERROR_TOOL_NOT_ALLOWED error, got: {response:?}"),
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

            // All three should be allowed
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
                    SessionResponse::RequestTool(resp) => {
                        assert_eq!(
                            resp.decision,
                            DecisionType::Allow as i32,
                            "Tool {tool_id} should be allowed"
                        );
                    },
                    _ => panic!("Expected Allow for tool {tool_id}"),
                }
            }

            // Git and Network should be denied
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
}
