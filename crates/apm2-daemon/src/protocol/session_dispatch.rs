//! Session-scoped endpoint dispatcher for RFC-0017 IPC (TCK-00252).
//!
//! This module implements the session-scoped endpoint dispatcher per DD-001 and
//! RFC-0017. Session endpoints (RequestTool, EmitEvent, PublishEvidence,
//! StreamTelemetry) require a valid session token for authentication. Operator
//! socket connections receive `SESSION_ERROR_PERMISSION_DENIED` for all session
//! requests.
//!
//! # Security Invariants
//!
//! - [INV-SESS-001] Session endpoints require valid session_token
//! - [INV-SESS-002] Invalid/expired tokens return SESSION_ERROR_INVALID
//! - [INV-SESS-003] Operator connections blocked from session handlers
//! - [INV-SESS-004] Token validation uses constant-time HMAC comparison
//!   (CTR-WH001)
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

use std::time::SystemTime;

use bytes::Bytes;
use prost::Message;
use tracing::{debug, info};

use super::dispatch::ConnectionContext;
use super::error::{ProtocolError, ProtocolResult};
use super::messages::{
    BoundedDecode, DecodeConfig, EmitEventRequest, EmitEventResponse, PublishEvidenceRequest,
    PublishEvidenceResponse, RequestToolRequest, RequestToolResponse, SessionError,
    SessionErrorCode, StreamTelemetryRequest, StreamTelemetryResponse,
};
use super::session_token::{SessionToken, SessionTokenError, TokenMinter};

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
// Dispatcher
// ============================================================================

/// Session-scoped endpoint dispatcher.
///
/// Routes incoming messages to the appropriate handler based on message type.
/// Enforces session token validation before dispatching to any handler.
///
/// # Security Contract
///
/// Per INV-SESS-001 through INV-SESS-004:
/// - All session endpoints require valid `session_token`
/// - Token validation uses constant-time HMAC comparison (CTR-WH001)
/// - Operator connections receive `SESSION_ERROR_PERMISSION_DENIED`
/// - Invalid/expired tokens receive `SESSION_ERROR_INVALID`
pub struct SessionDispatcher {
    /// Token minter for validation.
    token_minter: TokenMinter,
    /// Decode configuration for bounded message decoding.
    decode_config: DecodeConfig,
}

impl SessionDispatcher {
    /// Creates a new dispatcher with the given token minter.
    #[must_use]
    pub fn new(token_minter: TokenMinter) -> Self {
        Self {
            token_minter,
            decode_config: DecodeConfig::default(),
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
    /// # Stub Implementation
    ///
    /// This is a stub handler that validates the token and returns a
    /// placeholder response. Full implementation is in TCK-00260
    /// (tool broker with capability manifest validation).
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
            "RequestTool request received (stub handler)"
        );

        // Validate required fields
        if request.tool_id.is_empty() {
            return Ok(SessionResponse::error(
                SessionErrorCode::SessionErrorInvalid,
                "tool_id is required",
            ));
        }

        // STUB: Return placeholder response
        // Full implementation in TCK-00260
        Ok(SessionResponse::RequestTool(RequestToolResponse {
            request_id: format!("REQ-STUB-{}", token.session_id),
            decision: super::messages::DecisionType::Allow.into(),
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

            let request = RequestToolRequest {
                session_token: serde_json::to_string(&token).unwrap(),
                tool_id: "file_read".to_string(),
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
                    tool_id: "file_read".to_string(),
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
            tool_id: "file_read".to_string(),
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
            tool_id: "file_read".to_string(),
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
            tool_id: "file_read".to_string(),
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
}
