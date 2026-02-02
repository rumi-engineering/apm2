//! UDS protocol and framing module.
//!
//! This module handles Unix domain socket protocol implementation,
//! including message framing, handshake negotiation, and connection
//! lifecycle management.
//!
//! # Architecture
//!
//! The protocol stack is organized in layers:
//!
//! ```text
//! ┌─────────────────────────────────────────┐
//! │           Application Messages           │  Protobuf (messages)
//! ├─────────────────────────────────────────┤
//! │              Handshake                   │  Hello/HelloAck
//! ├─────────────────────────────────────────┤
//! │               Framing                    │  Length-prefixed
//! ├─────────────────────────────────────────┤
//! │            UDS Transport                 │  Unix socket
//! └─────────────────────────────────────────┘
//! ```
//!
//! # Module Overview
//!
//! - [`error`]: Protocol error types ([`ProtocolError`], [`ProtocolResult`])
//! - [`framing`]: Length-prefixed frame codec ([`FrameCodec`])
//! - [`golden_vectors`]: Golden test vectors for determinism verification
//! - [`handshake`]: Version negotiation ([`Hello`], [`HelloAck`],
//!   [`ServerHandshake`])
//! - [`messages`]: Protocol buffer message types ([`messages::Receipt`],
//!   [`messages::TelemetryFrame`], etc.)
//! - [`server`]: UDS server ([`ProtocolServer`], [`Connection`])
//! - [`session_token`]: Per-connection session tokens ([`SessionToken`],
//!   [`TokenMinter`]) for authenticating session-scoped requests (TCK-00250)
//!
//! # Wire Format
//!
//! Per AD-DAEMON-002, messages use length-prefixed binary framing:
//!
//! ```text
//! +----------------------------+------------------+
//! | Length (4 bytes, BE)       | Payload          |
//! +----------------------------+------------------+
//! ```
//!
//! - Maximum frame size: 16 MiB
//! - Length prefix: 4-byte big-endian unsigned integer
//! - Payload: Binary data (protobuf in future tickets)
//!
//! # Usage Example
//!
//! ## Server
//!
//! ```ignore
//! use apm2_daemon::protocol::{ProtocolServer, ServerConfig, ServerHandshake};
//! use futures::{SinkExt, StreamExt};
//!
//! let config = ServerConfig::default();
//! let server = ProtocolServer::bind(config).await?;
//!
//! loop {
//!     let (mut conn, _permit) = server.accept().await?;
//!     tokio::spawn(async move {
//!         // Handle connection
//!         while let Some(Ok(frame)) = conn.framed().next().await {
//!             // Process frame
//!         }
//!     });
//! }
//! ```
//!
//! ## Client
//!
//! ```ignore
//! use apm2_daemon::protocol::{connect, default_socket_path, ClientHandshake};
//! use futures::{SinkExt, StreamExt};
//!
//! let mut conn = connect(default_socket_path()).await?;
//! conn.framed().send(payload).await?;
//! let response = conn.framed().next().await;
//! ```
//!
//! # Security Considerations
//!
//! - Frame size validated BEFORE allocation (prevents denial of service)
//! - Socket created with restrictive permissions (0600)
//! - Handshake required before message exchange
//! - Version mismatch terminates connection

/// Peer credentials extraction from Unix sockets via `SO_PEERCRED`.
pub mod credentials;
/// Privileged endpoint dispatcher for RFC-0017 control-plane IPC.
pub mod dispatch;
pub mod error;
pub mod framing;
pub mod golden_vectors;
pub mod handshake;
pub mod messages;
pub mod server;
/// Session-scoped endpoint dispatcher for RFC-0017 IPC (TCK-00252).
pub mod session_dispatch;
pub mod session_token;
/// Dual-socket manager for privilege separation (TCK-00249).
pub mod socket_manager;

// Re-export commonly used types at module level.
// These re-exports form the public API of this module and may not be used
// within the crate itself.
#[allow(unused_imports)]
pub use credentials::PeerCredentials;
#[allow(unused_imports)]
pub use dispatch::{
    // Core dispatcher types
    ConnectionContext,
    // TCK-00253: Ledger event emitter types
    LedgerEventEmitter,
    LedgerEventError,
    MAX_LEDGER_EVENTS,
    MAX_WORK_CLAIMS,
    // TCK-00253: Policy resolution and work claim types
    PolicyResolution,
    PolicyResolutionError,
    PolicyResolver,
    PrivilegedDispatcher,
    PrivilegedMessageType,
    PrivilegedResponse,
    SignedLedgerEvent,
    StubLedgerEventEmitter,
    StubPolicyResolver,
    StubWorkRegistry,
    WORK_CLAIMED_DOMAIN_PREFIX,
    WorkClaim,
    WorkRegistry,
    WorkRegistryError,
    // TCK-00253: Actor ID derivation
    derive_actor_id,
    // Request encoding helpers
    encode_claim_work_request,
    encode_issue_capability_request,
    encode_shutdown_request,
    encode_spawn_episode_request,
    generate_lease_id,
    generate_work_id,
};
#[allow(unused_imports)]
pub use error::{
    MAX_FRAME_SIZE, MAX_HANDSHAKE_FRAME_SIZE, PROTOCOL_VERSION, ProtocolError, ProtocolResult,
};
#[allow(unused_imports)]
pub use framing::FrameCodec;
#[allow(unused_imports)]
pub use handshake::{
    ClientHandshake, HandshakeErrorCode, HandshakeMessage, HandshakeState, Hello, HelloAck,
    HelloNack, ServerHandshake, parse_handshake_message, parse_hello, serialize_handshake_message,
};
#[allow(unused_imports)]
pub use messages::{
    BoundedDecode,
    CanonicalBytes,
    Canonicalize,
    // CTR-PROTO-007: Privileged Endpoints (RFC-0017)
    CapabilityRequest,
    ClaimWorkRequest,
    ClaimWorkResponse,
    DEFAULT_MAX_MESSAGE_SIZE,
    DEFAULT_MAX_REPEATED_FIELD_COUNT,
    DecodeConfig,
    DecodeError,
    // CTR-PROTO-008: Session-Scoped Endpoints (RFC-0017, TCK-00252)
    EmitEventRequest,
    EmitEventResponse,
    IssueCapabilityRequest,
    IssueCapabilityResponse,
    // CTR-PROTO-009: Crash Recovery Signals (TCK-00267)
    LeaseRevoked,
    LeaseRevokedReason,
    PrivilegedError,
    PrivilegedErrorCode,
    PublishEvidenceRequest,
    PublishEvidenceResponse,
    RecoverSessionsRequest,
    RecoverSessionsResponse,
    RequestToolRequest,
    RequestToolResponse,
    SessionError,
    SessionErrorCode,
    ShutdownRequest,
    ShutdownResponse,
    SpawnEpisodeRequest,
    SpawnEpisodeResponse,
    StreamTelemetryRequest,
    StreamTelemetryResponse,
    WorkRole,
};
#[allow(unused_imports)]
pub use server::{
    Connection, ConnectionPermit, ProtocolServer, ServerConfig, connect, default_socket_path,
};
#[allow(unused_imports)]
pub use session_dispatch::{
    SessionDispatcher, SessionMessageType, SessionResponse, encode_emit_event_request,
    encode_publish_evidence_request, encode_request_tool_request, encode_stream_telemetry_request,
};
#[allow(unused_imports)]
pub use session_token::{SessionToken, SessionTokenError, TokenMinter};
#[allow(unused_imports)]
pub use socket_manager::{
    SocketManager, SocketManagerConfig, SocketType, default_operator_socket_path,
    default_session_socket_path,
};
