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
//! - [`pulse_topic`]: HEF topic grammar and wildcard matching
//!   ([`TopicPattern`], [`validate_topic`]) (RFC-0018, TCK-00301)
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

/// Connection handler for dual-socket ProtocolServer control plane (TCK-00279).
///
/// This module implements the connection handling logic including the mandatory
/// Hello/HelloAck handshake as specified in DD-001/DD-008.
pub mod connection_handler;
/// Peer credentials extraction from Unix sockets via `SO_PEERCRED`.
pub mod credentials;
/// Privileged endpoint dispatcher for RFC-0017 control-plane IPC.
pub mod dispatch;
pub mod error;
pub mod framing;
pub mod golden_vectors;
pub mod handshake;
pub mod messages;
/// ACL evaluation for HEF Pulse Plane subscriptions (RFC-0018, TCK-00302).
pub mod pulse_acl;
/// HEF Pulse Outbox and Publisher (RFC-0018, TCK-00304).
///
/// Implements the daemon-owned outbox that receives post-commit notifications
/// from the ledger and publishes `PulseEvent` messages to matching subscribers.
pub mod pulse_outbox;
/// Topic grammar and wildcard matching for HEF Pulse Plane (RFC-0018,
/// TCK-00301).
pub mod pulse_topic;
/// Resource governance and backpressure/drop policy for HEF Pulse Plane
/// (RFC-0018, TCK-00303).
pub mod resource_governance;
pub mod server;
/// Session-scoped endpoint dispatcher for RFC-0017 IPC (TCK-00252).
pub mod session_dispatch;
pub mod session_token;
/// Dual-socket manager for privilege separation (TCK-00249).
pub mod socket_manager;
/// Topic derivation for Work and Gate events (RFC-0018, TCK-00305).
///
/// Maps kernel events to pulse topics with deterministic derivation.
pub mod topic_derivation;

// Re-export commonly used types at module level.
// These re-exports form the public API of this module and may not be used
// within the crate itself.
#[allow(unused_imports)]
pub use connection_handler::{HandshakeResult, perform_handshake};
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
    // TCK-00342: Process management encoding helpers
    encode_list_processes_request,
    encode_process_status_request,
    encode_reload_process_request,
    encode_restart_process_request,
    encode_shutdown_request,
    encode_spawn_episode_request,
    encode_start_process_request,
    encode_stop_process_request,
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
    // CTR-PROTO-010: HEF Pulse Plane (RFC-0018, TCK-00300)
    BoundedWallInterval,
    CanonicalBytes,
    Canonicalize,
    // CTR-PROTO-007: Privileged Endpoints (RFC-0017)
    CapabilityRequest,
    CasRef,
    ClaimWorkRequest,
    ClaimWorkResponse,
    DEFAULT_MAX_MESSAGE_SIZE,
    DEFAULT_MAX_REPEATED_FIELD_COUNT,
    DecodeConfig,
    DecodeError,
    // CTR-PROTO-008: Session-Scoped Endpoints (RFC-0017, TCK-00252)
    EmitEventRequest,
    EmitEventResponse,
    EntityRef,
    HefError,
    HefErrorCode,
    HlcStamp,
    IssueCapabilityRequest,
    IssueCapabilityResponse,
    // CTR-PROTO-009: Crash Recovery Signals (TCK-00267)
    LeaseRevoked,
    LeaseRevokedReason,
    // CTR-PROTO-011: Process Management Endpoints (TCK-00342)
    ListProcessesRequest,
    ListProcessesResponse,
    LogEntry,
    PatternRejection,
    PrivilegedError,
    PrivilegedErrorCode,
    ProcessErrorCode,
    ProcessInfo,
    ProcessStateEnum,
    ProcessStatusRequest,
    ProcessStatusResponse,
    PublishEvidenceRequest,
    PublishEvidenceResponse,
    PulseEnvelopeV1,
    PulseEvent,
    RecoverSessionsRequest,
    RecoverSessionsResponse,
    ReloadProcessRequest,
    ReloadProcessResponse,
    RequestToolRequest,
    RequestToolResponse,
    RestartProcessRequest,
    RestartProcessResponse,
    SessionError,
    SessionErrorCode,
    ShutdownRequest,
    ShutdownResponse,
    SpawnEpisodeRequest,
    SpawnEpisodeResponse,
    StartProcessRequest,
    StartProcessResponse,
    StopProcessRequest,
    StopProcessResponse,
    StreamLogsRequest,
    StreamLogsResponse,
    StreamTelemetryRequest,
    StreamTelemetryResponse,
    SubscribePulseRequest,
    SubscribePulseResponse,
    UnsubscribePulseRequest,
    UnsubscribePulseResponse,
    WorkRole,
};
// CTR-PROTO-010: HEF Pulse ACL (RFC-0018, TCK-00302)
#[allow(unused_imports)]
pub use pulse_acl::{
    // Types
    AclDecision,
    AclError,
    ConnectionType,
    // Constants
    MAX_CLIENT_SUB_ID_LEN,
    MAX_SUBSCRIPTION_ID_LEN,
    MAX_TOPIC_ALLOWLIST,
    PulseAclEvaluator,
    TopicAllowlist,
    // Functions
    validate_client_sub_id,
    validate_subscription_id,
};
// CTR-PROTO-010: HEF Pulse Outbox (RFC-0018, TCK-00304)
#[allow(unused_imports)]
pub use pulse_outbox::{
    // Constants
    MAX_PULSE_ID_LEN,
    PULSE_ENVELOPE_SCHEMA_VERSION,
    PULSE_EVENT_TAG,
    // Types
    PulseFrameSender,
    PulseFrameSink,
    PulsePublisher,
    PulsePublisherConfig,
    TrySendResult,
    // Factory
    create_commit_notification_channel,
};
// CTR-PROTO-010: HEF Topic Grammar (RFC-0018, TCK-00301)
#[allow(unused_imports)]
pub use pulse_topic::{
    // Constants
    MAX_SEGMENT_COUNT,
    MAX_SEGMENT_LEN,
    MAX_TOPIC_LEN,
    MAX_WILDCARDS,
    MIN_SEGMENT_LEN,
    // Types
    PatternError,
    PatternValidationResult,
    SEGMENT_SEPARATOR,
    TopicError,
    TopicPattern,
    WILDCARD_SINGLE,
    WILDCARD_TERMINAL,
    // Functions
    validate_patterns,
    validate_topic,
};
// CTR-PROTO-010: HEF Resource Governance (RFC-0018, TCK-00303)
#[allow(unused_imports)]
pub use resource_governance::{
    // Types
    ConnectionState,
    ConnectionStats,
    DropPriority,
    MAX_BURST_PULSES_PER_SUBSCRIBER,
    // Constants
    MAX_BYTES_IN_FLIGHT_PER_SUBSCRIBER,
    MAX_PATTERNS_PER_SUBSCRIPTION,
    MAX_PULSE_PAYLOAD_BYTES,
    MAX_PULSES_PER_SEC_PER_SUBSCRIBER,
    MAX_QUEUE_DEPTH_PER_SUBSCRIBER,
    MAX_SUBSCRIPTIONS_PER_CONNECTION,
    MAX_TOTAL_PATTERNS_PER_CONNECTION,
    QueuedPulse,
    RateLimiter,
    ResourceError,
    ResourceQuotaConfig,
    SharedSubscriptionRegistry,
    SubscriptionRegistry,
    SubscriptionState,
};
#[allow(unused_imports)]
pub use server::{
    Connection, ConnectionPermit, ProtocolServer, ServerConfig, connect, default_socket_path,
};
#[allow(unused_imports)]
pub use session_dispatch::{
    SessionDispatcher, SessionMessageType, SessionResponse, encode_emit_event_request,
    encode_publish_evidence_request, encode_request_tool_request, encode_stream_logs_request,
    encode_stream_telemetry_request,
};
#[allow(unused_imports)]
pub use session_token::{SessionToken, SessionTokenError, TokenMinter};
#[allow(unused_imports)]
pub use socket_manager::{
    SocketManager, SocketManagerConfig, SocketType, default_operator_socket_path,
    default_session_socket_path,
};
// CTR-PROTO-010: HEF Topic Derivation (RFC-0018, TCK-00305)
#[allow(unused_imports)]
pub use topic_derivation::{
    // Types
    ChangesetWorkIndex,
    // Constants
    MAX_CHANGESET_INDEX_ENTRIES,
    TopicDerivationResult,
    TopicDeriver,
    // Functions
    encode_digest_for_topic,
    sanitize_segment,
};
