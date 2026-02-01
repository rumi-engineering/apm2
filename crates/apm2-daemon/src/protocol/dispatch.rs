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

use bytes::Bytes;
use prost::Message;
use tracing::{debug, info, warn};

use super::credentials::PeerCredentials;
use super::error::{ProtocolError, ProtocolResult};
use super::messages::{
    BoundedDecode, ClaimWorkRequest, ClaimWorkResponse, DecodeConfig, IssueCapabilityRequest,
    IssueCapabilityResponse, PrivilegedError, PrivilegedErrorCode, ShutdownRequest,
    ShutdownResponse, SpawnEpisodeRequest, SpawnEpisodeResponse, WorkRole,
};

// ============================================================================
// Connection Context
// ============================================================================

/// Connection context tracking privilege level and authentication state.
///
/// Per DD-001 (`privilege_predicate`), connections are classified as privileged
/// based on the socket path:
/// - operator.sock: `is_privileged = true`
/// - session.sock: `is_privileged = false`
#[derive(Debug, Clone)]
pub struct ConnectionContext {
    /// Whether this connection is privileged (operator socket).
    is_privileged: bool,

    /// Peer credentials extracted via `SO_PEERCRED`.
    peer_credentials: Option<PeerCredentials>,

    /// Session ID for session-scoped connections (None for operator
    /// connections).
    session_id: Option<String>,
}

impl ConnectionContext {
    /// Creates a new privileged connection context (operator socket).
    #[must_use]
    pub const fn privileged(peer_credentials: Option<PeerCredentials>) -> Self {
        Self {
            is_privileged: true,
            peer_credentials,
            session_id: None,
        }
    }

    /// Creates a new session-scoped connection context (session socket).
    #[must_use]
    pub const fn session(
        peer_credentials: Option<PeerCredentials>,
        session_id: Option<String>,
    ) -> Self {
        Self {
            is_privileged: false,
            peer_credentials,
            session_id,
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
}

// ============================================================================
// Message Type Tags (for routing)
// ============================================================================

/// Message type tags for privileged endpoint routing.
///
/// These tags are used to identify the message type before decoding,
/// allowing the dispatcher to route to the appropriate handler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PrivilegedMessageType {
    /// `ClaimWork` request (IPC-PRIV-001)
    ClaimWork       = 1,
    /// `SpawnEpisode` request (IPC-PRIV-002)
    SpawnEpisode    = 2,
    /// `IssueCapability` request (IPC-PRIV-003)
    IssueCapability = 3,
    /// Shutdown request (IPC-PRIV-004)
    Shutdown        = 4,
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
pub struct PrivilegedDispatcher {
    /// Decode configuration for bounded message decoding.
    decode_config: DecodeConfig,
}

impl Default for PrivilegedDispatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl PrivilegedDispatcher {
    /// Creates a new dispatcher with default decode configuration.
    #[must_use]
    pub fn new() -> Self {
        Self {
            decode_config: DecodeConfig::default(),
        }
    }

    /// Creates a new dispatcher with custom decode configuration.
    #[must_use]
    pub const fn with_decode_config(decode_config: DecodeConfig) -> Self {
        Self { decode_config }
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

        match msg_type {
            PrivilegedMessageType::ClaimWork => self.handle_claim_work(payload, ctx),
            PrivilegedMessageType::SpawnEpisode => self.handle_spawn_episode(payload, ctx),
            PrivilegedMessageType::IssueCapability => self.handle_issue_capability(payload, ctx),
            PrivilegedMessageType::Shutdown => self.handle_shutdown(payload, ctx),
        }
    }

    /// Handles `ClaimWork` requests (IPC-PRIV-001).
    ///
    /// # Stub Implementation
    ///
    /// This is a stub handler that validates the request and returns a
    /// placeholder response. Full implementation is in TCK-00253 (`ClaimWork`
    /// with governance policy resolution).
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

        info!(
            actor_id = %request.actor_id,
            role = ?WorkRole::try_from(request.role).unwrap_or(WorkRole::Unspecified),
            peer_pid = ?ctx.peer_credentials().map(|c| c.pid),
            "ClaimWork request received (stub handler)"
        );

        // Validate required fields
        if request.actor_id.is_empty() {
            return Ok(PrivilegedResponse::error(
                PrivilegedErrorCode::CapabilityRequestRejected,
                "actor_id is required",
            ));
        }

        if request.role == WorkRole::Unspecified as i32 {
            return Ok(PrivilegedResponse::error(
                PrivilegedErrorCode::CapabilityRequestRejected,
                "role is required",
            ));
        }

        // STUB: Return placeholder response
        // Full implementation in TCK-00253
        Ok(PrivilegedResponse::ClaimWork(ClaimWorkResponse {
            work_id: "W-STUB-001".to_string(),
            lease_id: "L-STUB-001".to_string(),
            capability_manifest_hash: vec![0u8; 32],
            policy_resolved_ref: "PolicyResolvedForChangeSet:STUB".to_string(),
            context_pack_hash: vec![0u8; 32],
        }))
    }

    /// Handles `SpawnEpisode` requests (IPC-PRIV-002).
    ///
    /// # Stub Implementation
    ///
    /// This is a stub handler that validates the request and returns a
    /// placeholder response. Full implementation is in TCK-00256
    /// (`SpawnEpisode` with `PolicyResolvedForChangeSet` check).
    fn handle_spawn_episode(
        &self,
        payload: &[u8],
        ctx: &ConnectionContext,
    ) -> ProtocolResult<PrivilegedResponse> {
        let request =
            SpawnEpisodeRequest::decode_bounded(payload, &self.decode_config).map_err(|e| {
                ProtocolError::Serialization {
                    reason: format!("invalid SpawnEpisodeRequest: {e}"),
                }
            })?;

        info!(
            work_id = %request.work_id,
            role = ?WorkRole::try_from(request.role).unwrap_or(WorkRole::Unspecified),
            lease_id = ?request.lease_id,
            peer_pid = ?ctx.peer_credentials().map(|c| c.pid),
            "SpawnEpisode request received (stub handler)"
        );

        // Validate required fields
        if request.work_id.is_empty() {
            return Ok(PrivilegedResponse::error(
                PrivilegedErrorCode::CapabilityRequestRejected,
                "work_id is required",
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

        // STUB: Return placeholder response
        // Full implementation in TCK-00256
        Ok(PrivilegedResponse::SpawnEpisode(SpawnEpisodeResponse {
            session_id: "S-STUB-001".to_string(),
            capability_manifest_hash: vec![0u8; 32],
            context_pack_sealed: true,
            ephemeral_handle: "H-STUB-001".to_string(),
        }))
    }

    /// Handles `IssueCapability` requests (IPC-PRIV-003).
    ///
    /// # Stub Implementation
    ///
    /// This is a stub handler that validates the request and returns a
    /// placeholder response. Full implementation in future ticket.
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
            "IssueCapability request received (stub handler)"
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

        // STUB: Return placeholder response
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        Ok(PrivilegedResponse::IssueCapability(
            IssueCapabilityResponse {
                capability_id: "C-STUB-001".to_string(),
                granted_at: now,
                expires_at: now + 3600, // 1 hour
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

            let request = SpawnEpisodeRequest {
                work_id: "W-001".to_string(),
                role: WorkRole::Implementer.into(),
                lease_id: None,
            };
            let frame = encode_spawn_episode_request(&request);

            let response = dispatcher.dispatch(&frame, &ctx).unwrap();
            assert!(matches!(response, PrivilegedResponse::SpawnEpisode(_)));
        }

        #[test]
        fn test_issue_capability_routing() {
            let dispatcher = PrivilegedDispatcher::new();
            let ctx = ConnectionContext::privileged(Some(PeerCredentials {
                uid: 1000,
                gid: 1000,
                pid: Some(12345),
            }));

            let request = IssueCapabilityRequest {
                session_id: "S-001".to_string(),
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

        let request = SpawnEpisodeRequest {
            work_id: "W-001".to_string(),
            role: WorkRole::Implementer.into(),
            lease_id: None,
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
        let dispatcher = PrivilegedDispatcher::new();
        let ctx = make_privileged_ctx();

        let request = IssueCapabilityRequest {
            session_id: "S-001".to_string(),
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
                assert!(resp.expires_at > resp.granted_at);
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
    // ADV-005: ClaimWork with capability parameters rejected
    // ========================================================================
    #[test]
    fn test_adv_005_claim_work_validation() {
        let dispatcher = PrivilegedDispatcher::new();
        let ctx = make_privileged_ctx();

        // Test missing actor_id
        let request = ClaimWorkRequest {
            actor_id: String::new(),
            role: WorkRole::Implementer.into(),
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
                assert!(err.message.contains("actor_id"));
            },
            _ => panic!("Expected validation error for empty actor_id"),
        }

        // Test missing role
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

    #[test]
    fn test_gate_executor_requires_lease_id() {
        let dispatcher = PrivilegedDispatcher::new();
        let ctx = make_privileged_ctx();

        let request = SpawnEpisodeRequest {
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

        let request = SpawnEpisodeRequest {
            work_id: "W-001".to_string(),
            role: WorkRole::GateExecutor.into(),
            lease_id: Some("L-001".to_string()),
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
}
