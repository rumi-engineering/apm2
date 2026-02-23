//! Protocol-based daemon clients for dual-socket IPC (TCK-00288).
//!
//! This module implements protocol clients for the operator and session sockets
//! using tag-based protobuf frames per DD-009 and RFC-0017.
//!
//! # Architecture
//!
//! The CLI communicates with the daemon via two sockets:
//! - **operator.sock**: For privileged operations (`ClaimWork`, `SpawnEpisode`,
//!   `IssueCapability`, Shutdown)
//! - **session.sock**: For session-scoped operations (`RequestTool`,
//!   `EmitEvent`, `PublishEvidence`, `StreamTelemetry`)
//!
//! # Wire Format
//!
//! Per AD-DAEMON-002, messages use length-prefixed binary framing:
//! ```text
//! +----------------------------+------------------+
//! | Length (4 bytes, BE)       | Payload          |
//! +----------------------------+------------------+
//! ```
//!
//! The payload is: `[tag: u8][protobuf message]`
//!
//! # Security Invariants
//!
//! - [INV-0001] CLI must never send JSON IPC over operator.sock/session.sock
//! - [DD-009] Protocol selection is strict and fail-closed
//! - [CTR-PROTO-001] Mandatory Hello/HelloAck handshake before any requests

use std::collections::VecDeque;
use std::io;
use std::path::Path;
use std::time::{Duration, Instant};

use apm2_daemon::protocol::{
    // Credential management types (CTR-PROTO-011, TCK-00343)
    AddCredentialRequest,
    AddCredentialResponse,
    // Message decoding
    BoundedDecode,
    // Capability request
    CapabilityRequest,
    // Privileged endpoint messages
    ClaimWorkRequest,
    ClaimWorkResponse,
    ClaimWorkV2Request,
    ClaimWorkV2Response,
    // Handshake
    ClientHandshake,
    // TCK-00345: Consensus query messages
    ConsensusByzantineEvidenceRequest,
    ConsensusByzantineEvidenceResponse,
    ConsensusError,
    ConsensusErrorCode,
    ConsensusMetricsRequest,
    ConsensusMetricsResponse,
    ConsensusStatusRequest,
    ConsensusStatusResponse,
    ConsensusValidatorsRequest,
    ConsensusValidatorsResponse,
    DecodeConfig,
    EmitEventRequest,
    EmitEventResponse,
    // Framing
    FrameCodec,
    HandshakeMessage,
    // TCK-00389: Review receipt ingestion
    IngestReviewReceiptRequest,
    IngestReviewReceiptResponse,
    IssueCapabilityRequest,
    IssueCapabilityResponse,
    ListCredentialsRequest,
    ListCredentialsResponse,
    // TCK-00342: Process management types
    ListProcessesRequest,
    ListProcessesResponse,
    LoginCredentialRequest,
    LoginCredentialResponse,
    // TCK-00635: OpenWork (RFC-0032 Phase 1)
    OpenWorkRequest,
    OpenWorkResponse,
    PrivilegedError,
    PrivilegedErrorCode,
    PrivilegedMessageType,
    ProcessStatusRequest,
    ProcessStatusResponse,
    // Error types
    ProtocolError,
    // TCK-00394: ChangeSet publishing
    PublishChangeSetRequest,
    PublishChangeSetResponse,
    // Evidence publishing
    PublishEvidenceRequest,
    PublishEvidenceResponse,
    PublishWorkContextEntryRequest,
    PublishWorkContextEntryResponse,
    PulseEvent,
    RecordWorkPrAssociationRequest,
    RecordWorkPrAssociationResponse,
    RefreshCredentialRequest,
    RefreshCredentialResponse,
    ReloadProcessRequest,
    ReloadProcessResponse,
    RemoveCredentialRequest,
    RemoveCredentialResponse,
    // Session endpoint messages
    RequestToolRequest,
    RequestToolResponse,
    // TCK-00636: Ticket alias resolution (RFC-0032 Phase 1)
    ResolveTicketAliasRequest,
    ResolveTicketAliasResponse,
    RestartProcessRequest,
    RestartProcessResponse,
    SessionError,
    SessionErrorCode,
    SessionMessageType,
    // TCK-00344: Status query messages
    SessionStatusRequest,
    SessionStatusResponse,
    ShutdownRequest,
    ShutdownResponse,
    SpawnEpisodeRequest,
    SpawnEpisodeResponse,
    StartProcessRequest,
    StartProcessResponse,
    StopProcessRequest,
    StopProcessResponse,
    // TCK-00342: Log streaming types
    StreamLogsRequest,
    StreamLogsResponse,
    SubscribePulseRequest,
    SubscribePulseResponse,
    SwitchCredentialRequest,
    SwitchCredentialResponse,
    UnsubscribePulseRequest,
    UnsubscribePulseResponse,
    WorkListRequest,
    WorkListResponse,
    // Work types
    WorkRole,
    // TCK-00344: Work status messages
    WorkStatusRequest,
    WorkStatusResponse,
    // Encoding helpers
    encode_add_credential_request,
    encode_claim_work_request,
    encode_claim_work_v2_request,
    // TCK-00345: Consensus query encoding
    encode_consensus_byzantine_evidence_request,
    encode_consensus_metrics_request,
    encode_consensus_status_request,
    encode_consensus_validators_request,
    encode_emit_event_request,
    // TCK-00389: Review receipt ingestion encoding
    encode_ingest_review_receipt_request,
    encode_issue_capability_request,
    encode_list_credentials_request,
    // TCK-00342: Process management encoding
    encode_list_processes_request,
    encode_login_credential_request,
    // TCK-00635: OpenWork encoding
    encode_open_work_request,
    encode_process_status_request,
    encode_publish_changeset_request,
    encode_publish_evidence_request,
    encode_publish_work_context_entry_request,
    encode_record_work_pr_association_request,
    encode_refresh_credential_request,
    encode_reload_process_request,
    encode_remove_credential_request,
    encode_request_tool_request,
    encode_resolve_ticket_alias_request,
    encode_restart_process_request,
    // TCK-00344: Status query encoding
    encode_session_status_request,
    encode_shutdown_request,
    encode_spawn_episode_request,
    encode_start_process_request,
    encode_stop_process_request,
    // TCK-00342: Log streaming encoding
    encode_stream_logs_request,
    encode_switch_credential_request,
    encode_work_list_request,
    encode_work_status_request,
    parse_handshake_message,
    serialize_handshake_message,
};
use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use prost::Message;
use tokio::net::UnixStream;
use tokio_util::codec::Framed;

/// Client version string for handshake.
const CLIENT_INFO: &str = concat!("apm2-cli/", env!("CARGO_PKG_VERSION"));

/// Default connection timeout in seconds.
pub const DEFAULT_TIMEOUT_SECS: u64 = 30;

/// Maximum frame size (16 MiB per AD-DAEMON-002).
/// Used for frame validation in protocol implementations.
///
/// Reserved for future use when client-side frame size validation is needed.
#[allow(dead_code)]
pub const MAX_FRAME_SIZE: usize = 16 * 1024 * 1024;
const DAEMON_SIGNING_PUBLIC_KEY_LEN: usize = 32;
const SUBSCRIBE_PULSE_RESPONSE_TAG: u8 = 65;
const UNSUBSCRIBE_PULSE_RESPONSE_TAG: u8 = 67;
const MAX_PENDING_PULSE_EVENTS: usize = 256;

#[derive(Debug, Clone)]
struct HandshakeInfo {
    server_info: String,
    daemon_signing_public_key: Option<[u8; DAEMON_SIGNING_PUBLIC_KEY_LEN]>,
}

#[derive(Debug)]
enum OperatorPulseFrame {
    Pulse(PulseEvent),
    Subscribe(SubscribePulseResponse),
    Unsubscribe(UnsubscribePulseResponse),
}

// ============================================================================
// Error Types
// ============================================================================

/// Error type for protocol client operations.
#[derive(Debug)]
pub enum ProtocolClientError {
    /// Daemon is not running (socket does not exist).
    DaemonNotRunning,
    /// Connection failed.
    ///
    /// Reserved for future use (e.g., connection-level errors beyond socket not
    /// found).
    #[allow(dead_code)]
    ConnectionFailed(String),
    /// Handshake failed.
    HandshakeFailed(String),
    /// Protocol version mismatch.
    ///
    /// Reserved for future use when version negotiation is implemented.
    #[allow(dead_code)]
    VersionMismatch { client: u32, server: u32 },
    /// I/O error during communication.
    IoError(io::Error),
    /// Frame too large.
    ///
    /// Reserved for future use when frame size validation is implemented.
    #[allow(dead_code)]
    FrameTooLarge { size: usize, max: usize },
    /// Protocol error from daemon.
    ProtocolError(ProtocolError),
    /// Decode error.
    DecodeError(String),
    /// Daemon returned an error response.
    DaemonError { code: String, message: String },
    /// Unexpected response type.
    UnexpectedResponse(String),
    /// Operation timed out.
    Timeout,
}

impl std::fmt::Display for ProtocolClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DaemonNotRunning => write!(f, "daemon is not running"),
            Self::ConnectionFailed(msg) => write!(f, "connection failed: {msg}"),
            Self::HandshakeFailed(msg) => write!(f, "handshake failed: {msg}"),
            Self::VersionMismatch { client, server } => {
                write!(
                    f,
                    "protocol version mismatch: client {client}, server {server}"
                )
            },
            Self::IoError(e) => write!(f, "I/O error: {e}"),
            Self::FrameTooLarge { size, max } => {
                write!(f, "frame too large: {size} bytes (max: {max})")
            },
            Self::ProtocolError(e) => write!(f, "protocol error: {e}"),
            Self::DecodeError(msg) => write!(f, "decode error: {msg}"),
            Self::DaemonError { code, message } => {
                write!(f, "daemon error ({code}): {message}")
            },
            Self::UnexpectedResponse(msg) => write!(f, "unexpected response: {msg}"),
            Self::Timeout => write!(f, "operation timed out"),
        }
    }
}

impl std::error::Error for ProtocolClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::IoError(e) => Some(e),
            Self::ProtocolError(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for ProtocolClientError {
    fn from(err: io::Error) -> Self {
        if err.kind() == io::ErrorKind::NotFound || err.kind() == io::ErrorKind::ConnectionRefused {
            Self::DaemonNotRunning
        } else {
            Self::IoError(err)
        }
    }
}

impl From<ProtocolError> for ProtocolClientError {
    fn from(err: ProtocolError) -> Self {
        Self::ProtocolError(err)
    }
}

// ============================================================================
// Operator Socket Client
// ============================================================================

/// Client for privileged operations on operator.sock.
///
/// This client connects to the operator socket and can execute privileged
/// operations like `ClaimWork`, `SpawnEpisode`, `IssueCapability`, and
/// Shutdown.
///
/// # Security
///
/// - Only operators (with correct UID) can connect to operator.sock
/// - All requests use tag-based protobuf framing (no JSON)
/// - Mandatory Hello/HelloAck handshake per CTR-PROTO-001
pub struct OperatorClient {
    framed: Framed<UnixStream, FrameCodec>,
    pending_pulses: VecDeque<PulseEvent>,
    /// Server info from handshake (reserved for future use in diagnostics).
    #[allow(dead_code)]
    server_info: String,
    #[allow(dead_code)]
    daemon_signing_public_key: Option<[u8; DAEMON_SIGNING_PUBLIC_KEY_LEN]>,
    timeout: Duration,
}

impl OperatorClient {
    /// Connects to the operator socket and performs the handshake.
    ///
    /// # Arguments
    ///
    /// * `socket_path` - Path to the operator socket
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The socket does not exist (daemon not running)
    /// - Connection fails
    /// - Handshake fails (version mismatch, rejected)
    pub async fn connect(socket_path: &Path) -> Result<Self, ProtocolClientError> {
        Self::connect_with_timeout(socket_path, Duration::from_secs(DEFAULT_TIMEOUT_SECS)).await
    }

    /// Connects with a custom timeout.
    pub async fn connect_with_timeout(
        socket_path: &Path,
        timeout: Duration,
    ) -> Result<Self, ProtocolClientError> {
        // Check if socket exists first (provides better error message)
        if !socket_path.exists() {
            return Err(ProtocolClientError::DaemonNotRunning);
        }

        // Connect to socket
        let stream = tokio::time::timeout(timeout, UnixStream::connect(socket_path))
            .await
            .map_err(|_| ProtocolClientError::Timeout)?
            .map_err(ProtocolClientError::from)?;

        let mut framed = Framed::new(stream, FrameCodec::new());

        // Perform handshake
        let handshake = Self::perform_handshake(&mut framed, timeout).await?;

        Ok(Self {
            framed,
            pending_pulses: VecDeque::new(),
            server_info: handshake.server_info,
            daemon_signing_public_key: handshake.daemon_signing_public_key,
            timeout,
        })
    }

    /// Computes the client's HSI contract manifest hash (TCK-00348).
    ///
    /// Per RFC-0020 section 3.1.2, the client MUST include its contract hash
    /// in the Hello message. This is derived from the same dispatch registry
    /// as the daemon's manifest.
    fn client_contract_hash() -> String {
        let cli_version = apm2_daemon::hsi_contract::CliVersion {
            semver: env!("CARGO_PKG_VERSION").to_string(),
            build_hash: String::new(),
        };
        apm2_daemon::hsi_contract::build_manifest(cli_version).map_or_else(
            |_| String::new(),
            |manifest| manifest.content_hash().unwrap_or_default(),
        )
    }

    /// Performs the Hello/HelloAck handshake.
    async fn perform_handshake(
        framed: &mut Framed<UnixStream, FrameCodec>,
        timeout: Duration,
    ) -> Result<HandshakeInfo, ProtocolClientError> {
        let mut client_handshake = ClientHandshake::new(CLIENT_INFO);

        // TCK-00348 BLOCKER-3: Populate Hello with client contract hash
        // and canonicalizer metadata per RFC-0020 section 3.1.2.
        let hello = client_handshake
            .create_hello()
            .with_contract_hash(Self::client_contract_hash())
            .with_canonicalizers(vec![apm2_daemon::hsi_contract::CanonicalizerInfo {
                id: "apm2.canonical.v1".to_string(),
                version: 1,
            }]);
        let hello_msg: HandshakeMessage = hello.into();
        let hello_bytes = serialize_handshake_message(&hello_msg)?;

        tokio::time::timeout(timeout, framed.send(hello_bytes))
            .await
            .map_err(|_| ProtocolClientError::Timeout)?
            .map_err(|e| ProtocolClientError::IoError(io::Error::other(e.to_string())))?;

        // Receive response
        let response_frame = tokio::time::timeout(timeout, framed.next())
            .await
            .map_err(|_| ProtocolClientError::Timeout)?
            .ok_or_else(|| ProtocolClientError::HandshakeFailed("connection closed".to_string()))?
            .map_err(|e| ProtocolClientError::IoError(io::Error::other(e.to_string())))?;

        let response = parse_handshake_message(&response_frame)?;
        client_handshake
            .process_response(response)
            .map_err(|e| ProtocolClientError::HandshakeFailed(e.to_string()))?;

        let daemon_signing_public_key = match client_handshake.daemon_signing_public_key() {
            Some(key_hex) => {
                let key_bytes = hex::decode(key_hex).map_err(|e| {
                    ProtocolClientError::HandshakeFailed(format!(
                        "invalid daemon_signing_public_key hex in handshake: {e}"
                    ))
                })?;
                let key: [u8; DAEMON_SIGNING_PUBLIC_KEY_LEN] =
                    key_bytes.as_slice().try_into().map_err(|_| {
                        ProtocolClientError::HandshakeFailed(format!(
                            "invalid daemon_signing_public_key length: expected {}, got {}",
                            DAEMON_SIGNING_PUBLIC_KEY_LEN,
                            key_bytes.len()
                        ))
                    })?;
                Some(key)
            },
            None => None,
        };

        Ok(HandshakeInfo {
            server_info: client_handshake
                .server_info()
                .unwrap_or("unknown")
                .to_string(),
            daemon_signing_public_key,
        })
    }

    /// Returns the daemon signing public key from handshake metadata.
    #[allow(dead_code)]
    #[must_use]
    pub const fn daemon_signing_public_key(&self) -> Option<&[u8; DAEMON_SIGNING_PUBLIC_KEY_LEN]> {
        self.daemon_signing_public_key.as_ref()
    }

    /// Sends a shutdown request to the daemon.
    ///
    /// # Arguments
    ///
    /// * `reason` - Optional reason for the shutdown
    ///
    /// # Returns
    ///
    /// The shutdown acknowledgment message.
    pub async fn shutdown(
        &mut self,
        reason: Option<&str>,
    ) -> Result<ShutdownResponse, ProtocolClientError> {
        let request = ShutdownRequest {
            reason: reason.map(String::from),
        };
        let request_bytes = encode_shutdown_request(&request);

        // Send request
        tokio::time::timeout(self.timeout, self.framed.send(request_bytes))
            .await
            .map_err(|_| ProtocolClientError::Timeout)?
            .map_err(|e| ProtocolClientError::IoError(io::Error::other(e.to_string())))?;

        // Receive response
        let response_frame = tokio::time::timeout(self.timeout, self.framed.next())
            .await
            .map_err(|_| ProtocolClientError::Timeout)?
            .ok_or_else(|| {
                ProtocolClientError::UnexpectedResponse("connection closed".to_string())
            })?
            .map_err(|e| ProtocolClientError::IoError(io::Error::other(e.to_string())))?;

        // Decode response
        Self::decode_privileged_response(&response_frame)
    }

    /// Claims work from the daemon.
    ///
    /// # Arguments
    ///
    /// * `actor_id` - Display hint for actor name (authoritative ID derived
    ///   from credential)
    /// * `role` - Role for work assignment
    /// * `credential_signature` - Ed25519 signature over (`actor_id` || role ||
    ///   nonce)
    /// * `nonce` - Nonce to prevent replay attacks
    pub async fn claim_work(
        &mut self,
        actor_id: &str,
        role: WorkRole,
        credential_signature: &[u8],
        nonce: &[u8],
    ) -> Result<ClaimWorkResponse, ProtocolClientError> {
        let request = ClaimWorkRequest {
            actor_id: actor_id.to_string(),
            role: role.into(),
            credential_signature: credential_signature.to_vec(),
            nonce: nonce.to_vec(),
        };
        let request_bytes = encode_claim_work_request(&request);

        // Send request
        tokio::time::timeout(self.timeout, self.framed.send(request_bytes))
            .await
            .map_err(|_| ProtocolClientError::Timeout)?
            .map_err(|e| ProtocolClientError::IoError(io::Error::other(e.to_string())))?;

        // Receive response
        let response_frame = tokio::time::timeout(self.timeout, self.framed.next())
            .await
            .map_err(|_| ProtocolClientError::Timeout)?
            .ok_or_else(|| {
                ProtocolClientError::UnexpectedResponse("connection closed".to_string())
            })?
            .map_err(|e| ProtocolClientError::IoError(io::Error::other(e.to_string())))?;

        // Decode response
        Self::decode_claim_work_response(&response_frame)
    }

    /// Spawns an episode for work execution.
    ///
    /// # Arguments
    ///
    /// * `work_id` - Work identifier from a prior `ClaimWork`
    /// * `role` - Role for this episode (IMPLEMENTER, `GATE_EXECUTOR`,
    ///   REVIEWER)
    /// * `lease_id` - Required for `GATE_EXECUTOR` role; must reference valid
    ///   `GateLeaseIssued`
    /// * `workspace_root` - Workspace root directory for this episode. All file
    ///   operations will be confined to this directory (TCK-00319).
    /// * `adapter_profile_hash` - Optional adapter profile CAS hash (32 bytes)
    pub async fn spawn_episode(
        &mut self,
        work_id: &str,
        role: WorkRole,
        lease_id: Option<&str>,
        workspace_root: &str,
        adapter_profile_hash: Option<&[u8]>,
    ) -> Result<SpawnEpisodeResponse, ProtocolClientError> {
        let request = SpawnEpisodeRequest {
            work_id: work_id.to_string(),
            role: role.into(),
            lease_id: lease_id.map(String::from),
            workspace_root: workspace_root.to_string(),
            adapter_profile_hash: adapter_profile_hash.map(<[u8]>::to_vec),
            max_episodes: None,
            escalation_predicate: None,
            permeability_receipt_hash: None,
        };
        let request_bytes = encode_spawn_episode_request(&request);

        // Send request
        tokio::time::timeout(self.timeout, self.framed.send(request_bytes))
            .await
            .map_err(|_| ProtocolClientError::Timeout)?
            .map_err(|e| ProtocolClientError::IoError(io::Error::other(e.to_string())))?;

        // Receive response
        let response_frame = tokio::time::timeout(self.timeout, self.framed.next())
            .await
            .map_err(|_| ProtocolClientError::Timeout)?
            .ok_or_else(|| {
                ProtocolClientError::UnexpectedResponse("connection closed".to_string())
            })?
            .map_err(|e| ProtocolClientError::IoError(io::Error::other(e.to_string())))?;

        // Decode response
        Self::decode_spawn_episode_response(&response_frame)
    }

    /// Decodes a privileged response for Shutdown.
    fn decode_privileged_response(frame: &Bytes) -> Result<ShutdownResponse, ProtocolClientError> {
        if frame.is_empty() {
            return Err(ProtocolClientError::DecodeError("empty frame".to_string()));
        }

        let tag = frame[0];
        let payload = &frame[1..];

        if tag == 0 {
            // Error response
            let err = PrivilegedError::decode_bounded(payload, &DecodeConfig::default())
                .map_err(|e| ProtocolClientError::DecodeError(e.to_string()))?;
            let code = PrivilegedErrorCode::try_from(err.code)
                .map_or_else(|_| err.code.to_string(), |c| format!("{c:?}"));
            return Err(ProtocolClientError::DaemonError {
                code,
                message: err.message,
            });
        }

        if tag != PrivilegedMessageType::Shutdown.tag() {
            return Err(ProtocolClientError::UnexpectedResponse(format!(
                "expected Shutdown response (tag {}), got tag {tag}",
                PrivilegedMessageType::Shutdown.tag()
            )));
        }

        ShutdownResponse::decode_bounded(payload, &DecodeConfig::default())
            .map_err(|e| ProtocolClientError::DecodeError(e.to_string()))
    }

    /// Decodes a `ClaimWork` response.
    fn decode_claim_work_response(frame: &Bytes) -> Result<ClaimWorkResponse, ProtocolClientError> {
        if frame.is_empty() {
            return Err(ProtocolClientError::DecodeError("empty frame".to_string()));
        }

        let tag = frame[0];
        let payload = &frame[1..];

        if tag == 0 {
            // Error response
            let err = PrivilegedError::decode_bounded(payload, &DecodeConfig::default())
                .map_err(|e| ProtocolClientError::DecodeError(e.to_string()))?;
            let code = PrivilegedErrorCode::try_from(err.code)
                .map_or_else(|_| err.code.to_string(), |c| format!("{c:?}"));
            return Err(ProtocolClientError::DaemonError {
                code,
                message: err.message,
            });
        }

        if tag != PrivilegedMessageType::ClaimWork.tag() {
            return Err(ProtocolClientError::UnexpectedResponse(format!(
                "expected ClaimWork response (tag {}), got tag {tag}",
                PrivilegedMessageType::ClaimWork.tag()
            )));
        }

        ClaimWorkResponse::decode_bounded(payload, &DecodeConfig::default())
            .map_err(|e| ProtocolClientError::DecodeError(e.to_string()))
    }

    /// Decodes a `SpawnEpisode` response.
    fn decode_spawn_episode_response(
        frame: &Bytes,
    ) -> Result<SpawnEpisodeResponse, ProtocolClientError> {
        if frame.is_empty() {
            return Err(ProtocolClientError::DecodeError("empty frame".to_string()));
        }

        let tag = frame[0];
        let payload = &frame[1..];

        if tag == 0 {
            // Error response
            let err = PrivilegedError::decode_bounded(payload, &DecodeConfig::default())
                .map_err(|e| ProtocolClientError::DecodeError(e.to_string()))?;
            let code = PrivilegedErrorCode::try_from(err.code)
                .map_or_else(|_| err.code.to_string(), |c| format!("{c:?}"));
            return Err(ProtocolClientError::DaemonError {
                code,
                message: err.message,
            });
        }

        if tag != PrivilegedMessageType::SpawnEpisode.tag() {
            return Err(ProtocolClientError::UnexpectedResponse(format!(
                "expected SpawnEpisode response (tag {}), got tag {tag}",
                PrivilegedMessageType::SpawnEpisode.tag()
            )));
        }

        SpawnEpisodeResponse::decode_bounded(payload, &DecodeConfig::default())
            .map_err(|e| ProtocolClientError::DecodeError(e.to_string()))
    }

    /// Issues a capability to a session.
    ///
    /// # Arguments
    ///
    /// * `session_id` - Target session identifier
    /// * `tool_class` - Tool class to grant access to
    /// * `read_patterns` - Path patterns for read access
    /// * `write_patterns` - Path patterns for write access
    /// * `duration_secs` - Duration in seconds for the capability grant
    pub async fn issue_capability(
        &mut self,
        session_id: &str,
        tool_class: &str,
        read_patterns: &[String],
        write_patterns: &[String],
        duration_secs: u64,
    ) -> Result<IssueCapabilityResponse, ProtocolClientError> {
        let request = IssueCapabilityRequest {
            session_id: session_id.to_string(),
            capability_request: Some(CapabilityRequest {
                tool_class: tool_class.to_string(),
                read_patterns: read_patterns.to_vec(),
                write_patterns: write_patterns.to_vec(),
                duration_secs,
            }),
        };
        let request_bytes = encode_issue_capability_request(&request);

        // Send request
        tokio::time::timeout(self.timeout, self.framed.send(request_bytes))
            .await
            .map_err(|_| ProtocolClientError::Timeout)?
            .map_err(|e| ProtocolClientError::IoError(io::Error::other(e.to_string())))?;

        // Receive response
        let response_frame = tokio::time::timeout(self.timeout, self.framed.next())
            .await
            .map_err(|_| ProtocolClientError::Timeout)?
            .ok_or_else(|| {
                ProtocolClientError::UnexpectedResponse("connection closed".to_string())
            })?
            .map_err(|e| ProtocolClientError::IoError(io::Error::other(e.to_string())))?;

        // Decode response
        Self::decode_issue_capability_response(&response_frame)
    }

    // =========================================================================
    // TCK-00345: Consensus Query Methods (RFC-0014)
    // =========================================================================

    /// Queries consensus status from the daemon.
    ///
    /// # Arguments
    ///
    /// * `verbose` - Whether to include extended status information
    ///
    /// # Returns
    ///
    /// Consensus status including cluster health, current term, and leader
    /// info. Returns `ConsensusNotConfigured` error if consensus subsystem
    /// is not active.
    pub async fn consensus_status(
        &mut self,
        verbose: bool,
    ) -> Result<ConsensusStatusResponse, ProtocolClientError> {
        let request = ConsensusStatusRequest { verbose };
        let request_bytes = encode_consensus_status_request(&request);

        // Send request
        tokio::time::timeout(self.timeout, self.framed.send(request_bytes))
            .await
            .map_err(|_| ProtocolClientError::Timeout)?
            .map_err(|e| ProtocolClientError::IoError(io::Error::other(e.to_string())))?;

        // Receive response
        let response_frame = tokio::time::timeout(self.timeout, self.framed.next())
            .await
            .map_err(|_| ProtocolClientError::Timeout)?
            .ok_or_else(|| {
                ProtocolClientError::UnexpectedResponse("connection closed".to_string())
            })?
            .map_err(|e| ProtocolClientError::IoError(io::Error::other(e.to_string())))?;

        // Decode response
        Self::decode_consensus_status_response(&response_frame)
    }

    /// Queries validator list from the daemon.
    ///
    /// # Arguments
    ///
    /// * `active_only` - Whether to return only active validators
    ///
    /// # Returns
    ///
    /// List of validators with their status information.
    /// Returns `ConsensusNotConfigured` error if consensus subsystem is not
    /// active.
    pub async fn consensus_validators(
        &mut self,
        active_only: bool,
    ) -> Result<ConsensusValidatorsResponse, ProtocolClientError> {
        let request = ConsensusValidatorsRequest { active_only };
        let request_bytes = encode_consensus_validators_request(&request);

        // Send request
        tokio::time::timeout(self.timeout, self.framed.send(request_bytes))
            .await
            .map_err(|_| ProtocolClientError::Timeout)?
            .map_err(|e| ProtocolClientError::IoError(io::Error::other(e.to_string())))?;

        // Receive response
        let response_frame = tokio::time::timeout(self.timeout, self.framed.next())
            .await
            .map_err(|_| ProtocolClientError::Timeout)?
            .ok_or_else(|| {
                ProtocolClientError::UnexpectedResponse("connection closed".to_string())
            })?
            .map_err(|e| ProtocolClientError::IoError(io::Error::other(e.to_string())))?;

        // Decode response
        Self::decode_consensus_validators_response(&response_frame)
    }

    /// Queries Byzantine evidence from the daemon.
    ///
    /// # Arguments
    ///
    /// * `fault_type` - Optional filter for specific fault type
    /// * `limit` - Maximum number of evidence entries to return
    ///
    /// # Returns
    ///
    /// List of detected Byzantine faults.
    /// Returns `ConsensusNotConfigured` error if consensus subsystem is not
    /// active.
    pub async fn consensus_byzantine_evidence(
        &mut self,
        fault_type: Option<&str>,
        limit: u32,
    ) -> Result<ConsensusByzantineEvidenceResponse, ProtocolClientError> {
        let request = ConsensusByzantineEvidenceRequest {
            fault_type: fault_type.map(String::from),
            limit,
        };
        let request_bytes = encode_consensus_byzantine_evidence_request(&request);

        // Send request
        tokio::time::timeout(self.timeout, self.framed.send(request_bytes))
            .await
            .map_err(|_| ProtocolClientError::Timeout)?
            .map_err(|e| ProtocolClientError::IoError(io::Error::other(e.to_string())))?;

        // Receive response
        let response_frame = tokio::time::timeout(self.timeout, self.framed.next())
            .await
            .map_err(|_| ProtocolClientError::Timeout)?
            .ok_or_else(|| {
                ProtocolClientError::UnexpectedResponse("connection closed".to_string())
            })?
            .map_err(|e| ProtocolClientError::IoError(io::Error::other(e.to_string())))?;

        // Decode response
        Self::decode_consensus_byzantine_evidence_response(&response_frame)
    }

    /// Queries consensus metrics from the daemon.
    ///
    /// # Arguments
    ///
    /// * `period_secs` - Time period for metrics aggregation (0 = current
    ///   snapshot)
    ///
    /// # Returns
    ///
    /// Consensus performance metrics.
    /// Returns `ConsensusNotConfigured` error if consensus subsystem is not
    /// active.
    pub async fn consensus_metrics(
        &mut self,
        period_secs: u64,
    ) -> Result<ConsensusMetricsResponse, ProtocolClientError> {
        let request = ConsensusMetricsRequest { period_secs };
        let request_bytes = encode_consensus_metrics_request(&request);

        // Send request
        tokio::time::timeout(self.timeout, self.framed.send(request_bytes))
            .await
            .map_err(|_| ProtocolClientError::Timeout)?
            .map_err(|e| ProtocolClientError::IoError(io::Error::other(e.to_string())))?;

        // Receive response
        let response_frame = tokio::time::timeout(self.timeout, self.framed.next())
            .await
            .map_err(|_| ProtocolClientError::Timeout)?
            .ok_or_else(|| {
                ProtocolClientError::UnexpectedResponse("connection closed".to_string())
            })?
            .map_err(|e| ProtocolClientError::IoError(io::Error::other(e.to_string())))?;

        // Decode response
        Self::decode_consensus_metrics_response(&response_frame)
    }

    /// Decodes an `IssueCapability` response.
    fn decode_issue_capability_response(
        frame: &Bytes,
    ) -> Result<IssueCapabilityResponse, ProtocolClientError> {
        if frame.is_empty() {
            return Err(ProtocolClientError::DecodeError("empty frame".to_string()));
        }

        let tag = frame[0];
        let payload = &frame[1..];

        if tag == 0 {
            // Error response
            let err = PrivilegedError::decode_bounded(payload, &DecodeConfig::default())
                .map_err(|e| ProtocolClientError::DecodeError(e.to_string()))?;
            let code = PrivilegedErrorCode::try_from(err.code)
                .map_or_else(|_| err.code.to_string(), |c| format!("{c:?}"));
            return Err(ProtocolClientError::DaemonError {
                code,
                message: err.message,
            });
        }

        if tag != PrivilegedMessageType::IssueCapability.tag() {
            return Err(ProtocolClientError::UnexpectedResponse(format!(
                "expected IssueCapability response (tag {}), got tag {tag}",
                PrivilegedMessageType::IssueCapability.tag()
            )));
        }

        IssueCapabilityResponse::decode_bounded(payload, &DecodeConfig::default())
            .map_err(|e| ProtocolClientError::DecodeError(e.to_string()))
    }

    // =========================================================================
    // TCK-00342: Process Management Operations
    // =========================================================================

    /// Lists all managed processes.
    ///
    /// # Returns
    ///
    /// A list of all processes with their current state and instance counts.
    pub async fn list_processes(&mut self) -> Result<ListProcessesResponse, ProtocolClientError> {
        let request = ListProcessesRequest {};
        let request_bytes = encode_list_processes_request(&request);

        // Send request
        tokio::time::timeout(self.timeout, self.framed.send(request_bytes))
            .await
            .map_err(|_| ProtocolClientError::Timeout)?
            .map_err(|e| ProtocolClientError::IoError(io::Error::other(e.to_string())))?;

        // Receive response
        let response_frame = tokio::time::timeout(self.timeout, self.framed.next())
            .await
            .map_err(|_| ProtocolClientError::Timeout)?
            .ok_or_else(|| {
                ProtocolClientError::UnexpectedResponse("connection closed".to_string())
            })?
            .map_err(|e| ProtocolClientError::IoError(io::Error::other(e.to_string())))?;

        // Decode response
        Self::decode_list_processes_response(&response_frame)
    }

    /// Gets the status of a specific process.
    ///
    /// # Arguments
    ///
    /// * `name` - Process name
    ///
    /// # Returns
    ///
    /// Detailed status including restart count, CPU, and memory usage.
    pub async fn process_status(
        &mut self,
        name: &str,
    ) -> Result<ProcessStatusResponse, ProtocolClientError> {
        let request = ProcessStatusRequest {
            name: name.to_string(),
        };
        let request_bytes = encode_process_status_request(&request);

        // Send request
        tokio::time::timeout(self.timeout, self.framed.send(request_bytes))
            .await
            .map_err(|_| ProtocolClientError::Timeout)?
            .map_err(|e| ProtocolClientError::IoError(io::Error::other(e.to_string())))?;

        // Receive response
        let response_frame = tokio::time::timeout(self.timeout, self.framed.next())
            .await
            .map_err(|_| ProtocolClientError::Timeout)?
            .ok_or_else(|| {
                ProtocolClientError::UnexpectedResponse("connection closed".to_string())
            })?
            .map_err(|e| ProtocolClientError::IoError(io::Error::other(e.to_string())))?;

        // Decode response
        Self::decode_process_status_response(&response_frame)
    }

    /// Starts a managed process.
    ///
    /// # Arguments
    ///
    /// * `name` - Process name to start
    ///
    /// # Returns
    ///
    /// Number of instances started.
    pub async fn start_process(
        &mut self,
        name: &str,
    ) -> Result<StartProcessResponse, ProtocolClientError> {
        let request = StartProcessRequest {
            name: name.to_string(),
        };
        let request_bytes = encode_start_process_request(&request);

        // Send request
        tokio::time::timeout(self.timeout, self.framed.send(request_bytes))
            .await
            .map_err(|_| ProtocolClientError::Timeout)?
            .map_err(|e| ProtocolClientError::IoError(io::Error::other(e.to_string())))?;

        // Receive response
        let response_frame = tokio::time::timeout(self.timeout, self.framed.next())
            .await
            .map_err(|_| ProtocolClientError::Timeout)?
            .ok_or_else(|| {
                ProtocolClientError::UnexpectedResponse("connection closed".to_string())
            })?
            .map_err(|e| ProtocolClientError::IoError(io::Error::other(e.to_string())))?;

        // Decode response
        Self::decode_start_process_response(&response_frame)
    }

    /// Stops a managed process.
    ///
    /// # Arguments
    ///
    /// * `name` - Process name to stop
    ///
    /// # Returns
    ///
    /// Number of instances stopped.
    pub async fn stop_process(
        &mut self,
        name: &str,
    ) -> Result<StopProcessResponse, ProtocolClientError> {
        let request = StopProcessRequest {
            name: name.to_string(),
        };
        let request_bytes = encode_stop_process_request(&request);

        // Send request
        tokio::time::timeout(self.timeout, self.framed.send(request_bytes))
            .await
            .map_err(|_| ProtocolClientError::Timeout)?
            .map_err(|e| ProtocolClientError::IoError(io::Error::other(e.to_string())))?;

        // Receive response
        let response_frame = tokio::time::timeout(self.timeout, self.framed.next())
            .await
            .map_err(|_| ProtocolClientError::Timeout)?
            .ok_or_else(|| {
                ProtocolClientError::UnexpectedResponse("connection closed".to_string())
            })?
            .map_err(|e| ProtocolClientError::IoError(io::Error::other(e.to_string())))?;

        // Decode response
        Self::decode_stop_process_response(&response_frame)
    }

    /// Restarts a managed process.
    ///
    /// # Arguments
    ///
    /// * `name` - Process name to restart
    ///
    /// # Returns
    ///
    /// Number of instances restarted.
    pub async fn restart_process(
        &mut self,
        name: &str,
    ) -> Result<RestartProcessResponse, ProtocolClientError> {
        let request = RestartProcessRequest {
            name: name.to_string(),
        };
        let request_bytes = encode_restart_process_request(&request);

        // Send request
        tokio::time::timeout(self.timeout, self.framed.send(request_bytes))
            .await
            .map_err(|_| ProtocolClientError::Timeout)?
            .map_err(|e| ProtocolClientError::IoError(io::Error::other(e.to_string())))?;

        // Receive response
        let response_frame = tokio::time::timeout(self.timeout, self.framed.next())
            .await
            .map_err(|_| ProtocolClientError::Timeout)?
            .ok_or_else(|| {
                ProtocolClientError::UnexpectedResponse("connection closed".to_string())
            })?
            .map_err(|e| ProtocolClientError::IoError(io::Error::other(e.to_string())))?;

        // Decode response
        Self::decode_restart_process_response(&response_frame)
    }

    /// Reloads a managed process (rolling restart).
    ///
    /// # Arguments
    ///
    /// * `name` - Process name to reload
    ///
    /// # Returns
    ///
    /// Success status and message.
    pub async fn reload_process(
        &mut self,
        name: &str,
    ) -> Result<ReloadProcessResponse, ProtocolClientError> {
        let request = ReloadProcessRequest {
            name: name.to_string(),
        };
        let request_bytes = encode_reload_process_request(&request);

        // Send request
        tokio::time::timeout(self.timeout, self.framed.send(request_bytes))
            .await
            .map_err(|_| ProtocolClientError::Timeout)?
            .map_err(|e| ProtocolClientError::IoError(io::Error::other(e.to_string())))?;

        // Receive response
        let response_frame = tokio::time::timeout(self.timeout, self.framed.next())
            .await
            .map_err(|_| ProtocolClientError::Timeout)?
            .ok_or_else(|| {
                ProtocolClientError::UnexpectedResponse("connection closed".to_string())
            })?
            .map_err(|e| ProtocolClientError::IoError(io::Error::other(e.to_string())))?;

        // Decode response
        Self::decode_reload_process_response(&response_frame)
    }

    /// Queries the status of a work item (TCK-00344).
    ///
    /// # Arguments
    ///
    /// * `work_id` - Work identifier to query status for
    ///
    /// # Returns
    ///
    /// Work status including state, actor, role, and timing information.
    pub async fn work_status(
        &mut self,
        work_id: &str,
    ) -> Result<WorkStatusResponse, ProtocolClientError> {
        let request = WorkStatusRequest {
            work_id: work_id.to_string(),
        };
        let request_bytes = encode_work_status_request(&request);

        // Send request
        tokio::time::timeout(self.timeout, self.framed.send(request_bytes))
            .await
            .map_err(|_| ProtocolClientError::Timeout)?
            .map_err(|e| ProtocolClientError::IoError(io::Error::other(e.to_string())))?;

        // Receive response
        let response_frame = tokio::time::timeout(self.timeout, self.framed.next())
            .await
            .map_err(|_| ProtocolClientError::Timeout)?
            .ok_or_else(|| {
                ProtocolClientError::UnexpectedResponse("connection closed".to_string())
            })?
            .map_err(|e| ProtocolClientError::IoError(io::Error::other(e.to_string())))?;

        // Decode response
        Self::decode_work_status_response(&response_frame)
    }

    /// Lists projection-known work items (TCK-00415).
    ///
    /// # Arguments
    ///
    /// * `claimable_only` - If true, return only claimable work items
    ///
    /// # Returns
    ///
    /// Projection-backed work rows ordered deterministically by work ID.
    pub async fn work_list(
        &mut self,
        claimable_only: bool,
    ) -> Result<WorkListResponse, ProtocolClientError> {
        let request = WorkListRequest {
            claimable_only,
            limit: 0,
            cursor: String::new(),
        };
        let request_bytes = encode_work_list_request(&request);

        // Send request
        tokio::time::timeout(self.timeout, self.framed.send(request_bytes))
            .await
            .map_err(|_| ProtocolClientError::Timeout)?
            .map_err(|e| ProtocolClientError::IoError(io::Error::other(e.to_string())))?;

        // Receive response
        let response_frame = tokio::time::timeout(self.timeout, self.framed.next())
            .await
            .map_err(|_| ProtocolClientError::Timeout)?
            .ok_or_else(|| {
                ProtocolClientError::UnexpectedResponse("connection closed".to_string())
            })?
            .map_err(|e| ProtocolClientError::IoError(io::Error::other(e.to_string())))?;

        // Decode response
        Self::decode_work_list_response(&response_frame)
    }

    // =========================================================================
    // TCK-00636: ResolveTicketAlias (RFC-0032 Phase 1)
    // =========================================================================

    /// Resolves a ticket alias to a canonical `work_id` via daemon projection
    /// state (TCK-00636).
    ///
    /// # Arguments
    ///
    /// * `ticket_alias` - Ticket alias to resolve (e.g. "TCK-00636")
    ///
    /// # Returns
    ///
    /// Resolution result containing the canonical `work_id` if found, or
    /// `found: false` when no match exists. Infrastructure/ambiguity errors
    /// are returned as `DaemonError`.
    pub async fn resolve_ticket_alias(
        &mut self,
        ticket_alias: &str,
    ) -> Result<ResolveTicketAliasResponse, ProtocolClientError> {
        let request = ResolveTicketAliasRequest {
            ticket_alias: ticket_alias.to_string(),
        };
        let request_bytes = encode_resolve_ticket_alias_request(&request);

        // Send request
        tokio::time::timeout(self.timeout, self.framed.send(request_bytes))
            .await
            .map_err(|_| ProtocolClientError::Timeout)?
            .map_err(|e| ProtocolClientError::IoError(io::Error::other(e.to_string())))?;

        // Receive response
        let response_frame = tokio::time::timeout(self.timeout, self.framed.next())
            .await
            .map_err(|_| ProtocolClientError::Timeout)?
            .ok_or_else(|| {
                ProtocolClientError::UnexpectedResponse("connection closed".to_string())
            })?
            .map_err(|e| ProtocolClientError::IoError(io::Error::other(e.to_string())))?;

        // Decode response
        Self::decode_resolve_ticket_alias_response(&response_frame)
    }

    // =========================================================================
    // TCK-00635: OpenWork (RFC-0032 Phase 1)
    // =========================================================================

    /// Opens a new work item by sending a validated `WorkSpec` to the daemon
    /// (TCK-00635).
    ///
    /// The daemon validates the `WorkSpec`, canonicalizes it, stores to CAS,
    /// and emits a `work.opened` event. Idempotent: same `work_id` + same
    /// spec hash returns success with `already_existed=true`.
    ///
    /// # Arguments
    ///
    /// * `work_spec_json` - Canonical JSON-encoded `WorkSpec` bytes
    ///
    /// # Returns
    ///
    /// [`OpenWorkResponse`] with `work_id`, spec hash, and idempotency flag.
    pub async fn open_work(
        &mut self,
        work_spec_json: &[u8],
        lease_id: &str,
    ) -> Result<OpenWorkResponse, ProtocolClientError> {
        let request = OpenWorkRequest {
            work_spec_json: work_spec_json.to_vec(),
            lease_id: lease_id.to_string(),
        };
        let request_bytes = encode_open_work_request(&request);

        // Send request
        tokio::time::timeout(self.timeout, self.framed.send(request_bytes))
            .await
            .map_err(|_| ProtocolClientError::Timeout)?
            .map_err(|e| ProtocolClientError::IoError(io::Error::other(e.to_string())))?;

        // Receive response
        let response_frame = tokio::time::timeout(self.timeout, self.framed.next())
            .await
            .map_err(|_| ProtocolClientError::Timeout)?
            .ok_or_else(|| {
                ProtocolClientError::UnexpectedResponse("connection closed".to_string())
            })?
            .map_err(|e| ProtocolClientError::IoError(io::Error::other(e.to_string())))?;

        // Decode response
        Self::decode_open_work_response(&response_frame)
    }

    /// Claims an existing work item via RFC-0032 `ClaimWorkV2` (TCK-00637).
    ///
    /// `ClaimWorkV2` claims an already opened work item and returns a
    /// role-scoped issued claim lease.
    pub async fn claim_work_v2(
        &mut self,
        work_id: &str,
        role: WorkRole,
        lease_id: &str,
    ) -> Result<ClaimWorkV2Response, ProtocolClientError> {
        let request = ClaimWorkV2Request {
            work_id: work_id.to_string(),
            role: role.into(),
            lease_id: lease_id.to_string(),
        };
        let request_bytes = encode_claim_work_v2_request(&request);

        tokio::time::timeout(self.timeout, self.framed.send(request_bytes))
            .await
            .map_err(|_| ProtocolClientError::Timeout)?
            .map_err(|e| ProtocolClientError::IoError(io::Error::other(e.to_string())))?;

        let response_frame = tokio::time::timeout(self.timeout, self.framed.next())
            .await
            .map_err(|_| ProtocolClientError::Timeout)?
            .ok_or_else(|| {
                ProtocolClientError::UnexpectedResponse("connection closed".to_string())
            })?
            .map_err(|e| ProtocolClientError::IoError(io::Error::other(e.to_string())))?;

        Self::decode_claim_work_v2_response(&response_frame)
    }

    // =========================================================================
    // TCK-00654: HEF Pulse Wait Integration (RFC-0032 section 12.5)
    // =========================================================================

    fn enqueue_pending_pulse(pending_pulses: &mut VecDeque<PulseEvent>, event: PulseEvent) {
        if pending_pulses.len() >= MAX_PENDING_PULSE_EVENTS {
            pending_pulses.pop_front();
        }
        pending_pulses.push_back(event);
    }

    /// Subscribes the operator connection to HEF pulse topics.
    ///
    /// Operator subscriptions use socket-authenticated privileges and therefore
    /// omit `session_token`.
    pub async fn subscribe_pulse(
        &mut self,
        client_sub_id: &str,
        topic_patterns: &[String],
        since_ledger_cursor: u64,
        max_pulses_per_sec: u32,
    ) -> Result<SubscribePulseResponse, ProtocolClientError> {
        let request = SubscribePulseRequest {
            session_token: String::new(),
            client_sub_id: client_sub_id.to_string(),
            topic_patterns: topic_patterns.to_vec(),
            since_ledger_cursor,
            max_pulses_per_sec,
        };

        let mut buf = vec![PrivilegedMessageType::SubscribePulse.tag()];
        request.encode(&mut buf).expect("encode cannot fail");

        tokio::time::timeout(self.timeout, self.framed.send(Bytes::from(buf)))
            .await
            .map_err(|_| ProtocolClientError::Timeout)?
            .map_err(|e| ProtocolClientError::IoError(io::Error::other(e.to_string())))?;

        let deadline = Instant::now() + self.timeout;
        loop {
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                return Err(ProtocolClientError::Timeout);
            };
            let frame = tokio::time::timeout(remaining, self.framed.next())
                .await
                .map_err(|_| ProtocolClientError::Timeout)?
                .ok_or_else(|| {
                    ProtocolClientError::UnexpectedResponse("connection closed".to_string())
                })?
                .map_err(|e| ProtocolClientError::IoError(io::Error::other(e.to_string())))?;

            match Self::decode_operator_pulse_frame(&frame)? {
                OperatorPulseFrame::Pulse(event) => {
                    Self::enqueue_pending_pulse(&mut self.pending_pulses, event);
                },
                OperatorPulseFrame::Subscribe(response) => return Ok(response),
                OperatorPulseFrame::Unsubscribe(_) => {
                    return Err(ProtocolClientError::UnexpectedResponse(
                        "received UnsubscribePulse response while waiting for SubscribePulse response"
                            .to_string(),
                    ));
                },
            }
        }
    }

    /// Waits for the next pulse event on an active subscription.
    ///
    /// Returns `Ok(None)` when `timeout` elapses without a pulse.
    pub async fn wait_for_pulse(
        &mut self,
        timeout: Duration,
    ) -> Result<Option<PulseEvent>, ProtocolClientError> {
        if let Some(pending) = self.pending_pulses.pop_front() {
            return Ok(Some(pending));
        }

        let Ok(frame) = tokio::time::timeout(timeout, self.framed.next()).await else {
            return Ok(None);
        };

        let frame = frame
            .ok_or_else(|| {
                ProtocolClientError::UnexpectedResponse("connection closed".to_string())
            })?
            .map_err(|e| ProtocolClientError::IoError(io::Error::other(e.to_string())))?;

        match Self::decode_operator_pulse_frame(&frame)? {
            OperatorPulseFrame::Pulse(event) => Ok(Some(event)),
            OperatorPulseFrame::Subscribe(response) => {
                Err(ProtocolClientError::UnexpectedResponse(format!(
                    "received unexpected SubscribePulse response while waiting for pulse event (subscription_id={})",
                    response.subscription_id
                )))
            },
            OperatorPulseFrame::Unsubscribe(response) => {
                Err(ProtocolClientError::UnexpectedResponse(format!(
                    "received unexpected UnsubscribePulse response while waiting for pulse event (removed={})",
                    response.removed
                )))
            },
        }
    }

    /// Unsubscribes a previously-created pulse subscription.
    pub async fn unsubscribe_pulse(
        &mut self,
        subscription_id: &str,
    ) -> Result<UnsubscribePulseResponse, ProtocolClientError> {
        let request = UnsubscribePulseRequest {
            session_token: String::new(),
            subscription_id: subscription_id.to_string(),
        };

        let mut buf = vec![PrivilegedMessageType::UnsubscribePulse.tag()];
        request.encode(&mut buf).expect("encode cannot fail");

        tokio::time::timeout(self.timeout, self.framed.send(Bytes::from(buf)))
            .await
            .map_err(|_| ProtocolClientError::Timeout)?
            .map_err(|e| ProtocolClientError::IoError(io::Error::other(e.to_string())))?;

        let deadline = Instant::now() + self.timeout;
        loop {
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                return Err(ProtocolClientError::Timeout);
            };
            let frame = tokio::time::timeout(remaining, self.framed.next())
                .await
                .map_err(|_| ProtocolClientError::Timeout)?
                .ok_or_else(|| {
                    ProtocolClientError::UnexpectedResponse("connection closed".to_string())
                })?
                .map_err(|e| ProtocolClientError::IoError(io::Error::other(e.to_string())))?;

            match Self::decode_operator_pulse_frame(&frame)? {
                OperatorPulseFrame::Pulse(event) => {
                    Self::enqueue_pending_pulse(&mut self.pending_pulses, event);
                },
                OperatorPulseFrame::Unsubscribe(response) => return Ok(response),
                OperatorPulseFrame::Subscribe(_) => {
                    return Err(ProtocolClientError::UnexpectedResponse(
                        "received SubscribePulse response while waiting for UnsubscribePulse response"
                            .to_string(),
                    ));
                },
            }
        }
    }

    /// Decodes a pulse-control frame on the operator socket.
    fn decode_operator_pulse_frame(
        frame: &Bytes,
    ) -> Result<OperatorPulseFrame, ProtocolClientError> {
        if frame.is_empty() {
            return Err(ProtocolClientError::DecodeError("empty frame".to_string()));
        }

        let tag = frame[0];
        let payload = &frame[1..];

        if tag == 0 {
            let err = PrivilegedError::decode_bounded(payload, &DecodeConfig::default())
                .map_err(|e| ProtocolClientError::DecodeError(e.to_string()))?;
            let code = PrivilegedErrorCode::try_from(err.code)
                .map_or_else(|_| err.code.to_string(), |c| format!("{c:?}"));
            return Err(ProtocolClientError::DaemonError {
                code,
                message: err.message,
            });
        }

        if tag == PrivilegedMessageType::PulseEvent.tag() {
            let event = PulseEvent::decode_bounded(payload, &DecodeConfig::default())
                .map_err(|e| ProtocolClientError::DecodeError(e.to_string()))?;
            return Ok(OperatorPulseFrame::Pulse(event));
        }

        if tag == SUBSCRIBE_PULSE_RESPONSE_TAG {
            let response =
                SubscribePulseResponse::decode_bounded(payload, &DecodeConfig::default())
                    .map_err(|e| ProtocolClientError::DecodeError(e.to_string()))?;
            return Ok(OperatorPulseFrame::Subscribe(response));
        }

        if tag == UNSUBSCRIBE_PULSE_RESPONSE_TAG {
            let response =
                UnsubscribePulseResponse::decode_bounded(payload, &DecodeConfig::default())
                    .map_err(|e| ProtocolClientError::DecodeError(e.to_string()))?;
            return Ok(OperatorPulseFrame::Unsubscribe(response));
        }

        Err(ProtocolClientError::UnexpectedResponse(format!(
            "unexpected operator pulse frame tag {tag}"
        )))
    }

    /// Decodes an `OpenWork` response (TCK-00635).
    fn decode_open_work_response(frame: &Bytes) -> Result<OpenWorkResponse, ProtocolClientError> {
        if frame.is_empty() {
            return Err(ProtocolClientError::DecodeError("empty frame".to_string()));
        }

        let tag = frame[0];
        let payload = &frame[1..];

        if tag == 0 {
            // Error response
            let err = PrivilegedError::decode_bounded(payload, &DecodeConfig::default())
                .map_err(|e| ProtocolClientError::DecodeError(e.to_string()))?;
            let code = PrivilegedErrorCode::try_from(err.code)
                .map_or_else(|_| err.code.to_string(), |c| format!("{c:?}"));
            return Err(ProtocolClientError::DaemonError {
                code,
                message: err.message,
            });
        }

        if tag != PrivilegedMessageType::OpenWork.tag() {
            return Err(ProtocolClientError::UnexpectedResponse(format!(
                "expected OpenWork response (tag {}), got tag {tag}",
                PrivilegedMessageType::OpenWork.tag()
            )));
        }

        OpenWorkResponse::decode_bounded(payload, &DecodeConfig::default())
            .map_err(|e| ProtocolClientError::DecodeError(e.to_string()))
    }

    /// Decodes a `ClaimWorkV2` response (TCK-00637).
    fn decode_claim_work_v2_response(
        frame: &Bytes,
    ) -> Result<ClaimWorkV2Response, ProtocolClientError> {
        if frame.is_empty() {
            return Err(ProtocolClientError::DecodeError("empty frame".to_string()));
        }

        let tag = frame[0];
        let payload = &frame[1..];

        if tag == 0 {
            let err = PrivilegedError::decode_bounded(payload, &DecodeConfig::default())
                .map_err(|e| ProtocolClientError::DecodeError(e.to_string()))?;
            let code = PrivilegedErrorCode::try_from(err.code)
                .map_or_else(|_| err.code.to_string(), |c| format!("{c:?}"));
            return Err(ProtocolClientError::DaemonError {
                code,
                message: err.message,
            });
        }

        if tag != PrivilegedMessageType::ClaimWorkV2.tag() {
            return Err(ProtocolClientError::UnexpectedResponse(format!(
                "expected ClaimWorkV2 response (tag {}), got tag {tag}",
                PrivilegedMessageType::ClaimWorkV2.tag()
            )));
        }

        ClaimWorkV2Response::decode_bounded(payload, &DecodeConfig::default())
            .map_err(|e| ProtocolClientError::DecodeError(e.to_string()))
    }

    // =========================================================================
    // TCK-00389: IngestReviewReceipt
    // =========================================================================

    /// Ingests a review receipt from an external reviewer (TCK-00389).
    ///
    /// Sends the review receipt to the daemon for ledger ingestion. The daemon
    /// validates the reviewer identity against the gate lease and emits either
    /// a `ReviewReceiptRecorded` or `ReviewBlockedRecorded` event.
    ///
    /// # Arguments
    ///
    /// * `request` - The `IngestReviewReceiptRequest` containing all review
    ///   receipt fields
    ///
    /// # Returns
    ///
    /// The `IngestReviewReceiptResponse` with the receipt ID, event type, and
    /// ledger event ID on success.
    ///
    /// # Errors
    ///
    /// Returns `ProtocolClientError` if:
    /// - Communication with daemon fails
    /// - Reviewer identity validation fails
    /// - Lease is not found
    /// - Event emission fails
    #[allow(dead_code)] // Scaffolding for TCK-00389 review receipt ingestion
    pub async fn ingest_review_receipt(
        &mut self,
        request: &IngestReviewReceiptRequest,
    ) -> Result<IngestReviewReceiptResponse, ProtocolClientError> {
        let request_bytes = encode_ingest_review_receipt_request(request);

        // Send request
        tokio::time::timeout(self.timeout, self.framed.send(request_bytes))
            .await
            .map_err(|_| ProtocolClientError::Timeout)?
            .map_err(|e| ProtocolClientError::IoError(io::Error::other(e.to_string())))?;

        // Receive response
        let response_frame = tokio::time::timeout(self.timeout, self.framed.next())
            .await
            .map_err(|_| ProtocolClientError::Timeout)?
            .ok_or_else(|| {
                ProtocolClientError::UnexpectedResponse("connection closed".to_string())
            })?
            .map_err(|e| ProtocolClientError::IoError(io::Error::other(e.to_string())))?;

        // Decode response
        Self::decode_ingest_review_receipt_response(&response_frame)
    }

    /// Decodes an `IngestReviewReceipt` response.
    #[allow(dead_code)] // Scaffolding for TCK-00389 review receipt ingestion
    fn decode_ingest_review_receipt_response(
        frame: &Bytes,
    ) -> Result<IngestReviewReceiptResponse, ProtocolClientError> {
        if frame.is_empty() {
            return Err(ProtocolClientError::DecodeError("empty frame".to_string()));
        }

        let tag = frame[0];
        let payload = &frame[1..];

        if tag == 0 {
            // Error response
            let err = PrivilegedError::decode_bounded(payload, &DecodeConfig::default())
                .map_err(|e| ProtocolClientError::DecodeError(e.to_string()))?;
            let code = PrivilegedErrorCode::try_from(err.code)
                .map_or_else(|_| err.code.to_string(), |c| format!("{c:?}"));
            return Err(ProtocolClientError::DaemonError {
                code,
                message: err.message,
            });
        }

        if tag != PrivilegedMessageType::IngestReviewReceipt.tag() {
            return Err(ProtocolClientError::UnexpectedResponse(format!(
                "expected IngestReviewReceipt response (tag {}), got tag {tag}",
                PrivilegedMessageType::IngestReviewReceipt.tag()
            )));
        }

        IngestReviewReceiptResponse::decode_bounded(payload, &DecodeConfig::default())
            .map_err(|e| ProtocolClientError::DecodeError(e.to_string()))
    }

    // =========================================================================
    // TCK-00342: Process Management Response Decoders
    // =========================================================================

    /// Decodes a `ListProcesses` response.
    fn decode_list_processes_response(
        frame: &Bytes,
    ) -> Result<ListProcessesResponse, ProtocolClientError> {
        if frame.is_empty() {
            return Err(ProtocolClientError::DecodeError("empty frame".to_string()));
        }

        let tag = frame[0];
        let payload = &frame[1..];

        if tag == 0 {
            // Error response
            let err = PrivilegedError::decode_bounded(payload, &DecodeConfig::default())
                .map_err(|e| ProtocolClientError::DecodeError(e.to_string()))?;
            let code = PrivilegedErrorCode::try_from(err.code)
                .map_or_else(|_| err.code.to_string(), |c| format!("{c:?}"));
            return Err(ProtocolClientError::DaemonError {
                code,
                message: err.message,
            });
        }

        if tag != PrivilegedMessageType::ListProcesses.tag() {
            return Err(ProtocolClientError::UnexpectedResponse(format!(
                "expected ListProcesses response (tag {}), got tag {tag}",
                PrivilegedMessageType::ListProcesses.tag()
            )));
        }

        ListProcessesResponse::decode_bounded(payload, &DecodeConfig::default())
            .map_err(|e| ProtocolClientError::DecodeError(e.to_string()))
    }

    /// Decodes a `ProcessStatus` response.
    fn decode_process_status_response(
        frame: &Bytes,
    ) -> Result<ProcessStatusResponse, ProtocolClientError> {
        if frame.is_empty() {
            return Err(ProtocolClientError::DecodeError("empty frame".to_string()));
        }

        let tag = frame[0];
        let payload = &frame[1..];

        if tag == 0 {
            let err = PrivilegedError::decode_bounded(payload, &DecodeConfig::default())
                .map_err(|e| ProtocolClientError::DecodeError(e.to_string()))?;
            let code = PrivilegedErrorCode::try_from(err.code)
                .map_or_else(|_| err.code.to_string(), |c| format!("{c:?}"));
            return Err(ProtocolClientError::DaemonError {
                code,
                message: err.message,
            });
        }

        if tag != PrivilegedMessageType::ProcessStatus.tag() {
            return Err(ProtocolClientError::UnexpectedResponse(format!(
                "expected ProcessStatus response (tag {}), got tag {tag}",
                PrivilegedMessageType::ProcessStatus.tag()
            )));
        }

        ProcessStatusResponse::decode_bounded(payload, &DecodeConfig::default())
            .map_err(|e| ProtocolClientError::DecodeError(e.to_string()))
    }

    /// Decodes a `StartProcess` response.
    fn decode_start_process_response(
        frame: &Bytes,
    ) -> Result<StartProcessResponse, ProtocolClientError> {
        if frame.is_empty() {
            return Err(ProtocolClientError::DecodeError("empty frame".to_string()));
        }

        let tag = frame[0];
        let payload = &frame[1..];

        if tag == 0 {
            let err = PrivilegedError::decode_bounded(payload, &DecodeConfig::default())
                .map_err(|e| ProtocolClientError::DecodeError(e.to_string()))?;
            let code = PrivilegedErrorCode::try_from(err.code)
                .map_or_else(|_| err.code.to_string(), |c| format!("{c:?}"));
            return Err(ProtocolClientError::DaemonError {
                code,
                message: err.message,
            });
        }

        if tag != PrivilegedMessageType::StartProcess.tag() {
            return Err(ProtocolClientError::UnexpectedResponse(format!(
                "expected StartProcess response (tag {}), got tag {tag}",
                PrivilegedMessageType::StartProcess.tag()
            )));
        }

        StartProcessResponse::decode_bounded(payload, &DecodeConfig::default())
            .map_err(|e| ProtocolClientError::DecodeError(e.to_string()))
    }

    /// Decodes a `StopProcess` response.
    fn decode_stop_process_response(
        frame: &Bytes,
    ) -> Result<StopProcessResponse, ProtocolClientError> {
        if frame.is_empty() {
            return Err(ProtocolClientError::DecodeError("empty frame".to_string()));
        }

        let tag = frame[0];
        let payload = &frame[1..];

        if tag == 0 {
            let err = PrivilegedError::decode_bounded(payload, &DecodeConfig::default())
                .map_err(|e| ProtocolClientError::DecodeError(e.to_string()))?;
            let code = PrivilegedErrorCode::try_from(err.code)
                .map_or_else(|_| err.code.to_string(), |c| format!("{c:?}"));
            return Err(ProtocolClientError::DaemonError {
                code,
                message: err.message,
            });
        }

        if tag != PrivilegedMessageType::StopProcess.tag() {
            return Err(ProtocolClientError::UnexpectedResponse(format!(
                "expected StopProcess response (tag {}), got tag {tag}",
                PrivilegedMessageType::StopProcess.tag()
            )));
        }

        StopProcessResponse::decode_bounded(payload, &DecodeConfig::default())
            .map_err(|e| ProtocolClientError::DecodeError(e.to_string()))
    }

    /// Decodes a `RestartProcess` response.
    fn decode_restart_process_response(
        frame: &Bytes,
    ) -> Result<RestartProcessResponse, ProtocolClientError> {
        if frame.is_empty() {
            return Err(ProtocolClientError::DecodeError("empty frame".to_string()));
        }

        let tag = frame[0];
        let payload = &frame[1..];

        if tag == 0 {
            let err = PrivilegedError::decode_bounded(payload, &DecodeConfig::default())
                .map_err(|e| ProtocolClientError::DecodeError(e.to_string()))?;
            let code = PrivilegedErrorCode::try_from(err.code)
                .map_or_else(|_| err.code.to_string(), |c| format!("{c:?}"));
            return Err(ProtocolClientError::DaemonError {
                code,
                message: err.message,
            });
        }

        if tag != PrivilegedMessageType::RestartProcess.tag() {
            return Err(ProtocolClientError::UnexpectedResponse(format!(
                "expected RestartProcess response (tag {}), got tag {tag}",
                PrivilegedMessageType::RestartProcess.tag()
            )));
        }

        RestartProcessResponse::decode_bounded(payload, &DecodeConfig::default())
            .map_err(|e| ProtocolClientError::DecodeError(e.to_string()))
    }

    /// Decodes a `ReloadProcess` response.
    fn decode_reload_process_response(
        frame: &Bytes,
    ) -> Result<ReloadProcessResponse, ProtocolClientError> {
        if frame.is_empty() {
            return Err(ProtocolClientError::DecodeError("empty frame".to_string()));
        }

        let tag = frame[0];
        let payload = &frame[1..];

        if tag == 0 {
            let err = PrivilegedError::decode_bounded(payload, &DecodeConfig::default())
                .map_err(|e| ProtocolClientError::DecodeError(e.to_string()))?;
            let code = PrivilegedErrorCode::try_from(err.code)
                .map_or_else(|_| err.code.to_string(), |c| format!("{c:?}"));
            return Err(ProtocolClientError::DaemonError {
                code,
                message: err.message,
            });
        }

        if tag != PrivilegedMessageType::ReloadProcess.tag() {
            return Err(ProtocolClientError::UnexpectedResponse(format!(
                "expected ReloadProcess response (tag {}), got tag {tag}",
                PrivilegedMessageType::ReloadProcess.tag()
            )));
        }

        ReloadProcessResponse::decode_bounded(payload, &DecodeConfig::default())
            .map_err(|e| ProtocolClientError::DecodeError(e.to_string()))
    }

    // =========================================================================
    // TCK-00345: Consensus Response Decoders
    // =========================================================================

    /// Decodes a `ConsensusStatus` response.
    fn decode_consensus_status_response(
        frame: &Bytes,
    ) -> Result<ConsensusStatusResponse, ProtocolClientError> {
        if frame.is_empty() {
            return Err(ProtocolClientError::DecodeError("empty frame".to_string()));
        }

        let tag = frame[0];
        let payload = &frame[1..];

        if tag == 0 {
            // Error response - check if it's a consensus error
            if let Ok(err) = ConsensusError::decode_bounded(payload, &DecodeConfig::default()) {
                let code = ConsensusErrorCode::try_from(err.code)
                    .map_or_else(|_| err.code.to_string(), |c| format!("{c:?}"));
                return Err(ProtocolClientError::DaemonError {
                    code,
                    message: err.message,
                });
            }
            // Fallback to privileged error
            let err = PrivilegedError::decode_bounded(payload, &DecodeConfig::default())
                .map_err(|e| ProtocolClientError::DecodeError(e.to_string()))?;
            let code = PrivilegedErrorCode::try_from(err.code)
                .map_or_else(|_| err.code.to_string(), |c| format!("{c:?}"));
            return Err(ProtocolClientError::DaemonError {
                code,
                message: err.message,
            });
        }

        if tag != PrivilegedMessageType::ConsensusStatus.tag() {
            return Err(ProtocolClientError::UnexpectedResponse(format!(
                "expected ConsensusStatus response (tag {}), got tag {tag}",
                PrivilegedMessageType::ConsensusStatus.tag()
            )));
        }

        ConsensusStatusResponse::decode_bounded(payload, &DecodeConfig::default())
            .map_err(|e| ProtocolClientError::DecodeError(e.to_string()))
    }

    /// Decodes a `ConsensusValidators` response.
    fn decode_consensus_validators_response(
        frame: &Bytes,
    ) -> Result<ConsensusValidatorsResponse, ProtocolClientError> {
        if frame.is_empty() {
            return Err(ProtocolClientError::DecodeError("empty frame".to_string()));
        }

        let tag = frame[0];
        let payload = &frame[1..];

        if tag == 0 {
            // Error response - check if it's a consensus error
            if let Ok(err) = ConsensusError::decode_bounded(payload, &DecodeConfig::default()) {
                let code = ConsensusErrorCode::try_from(err.code)
                    .map_or_else(|_| err.code.to_string(), |c| format!("{c:?}"));
                return Err(ProtocolClientError::DaemonError {
                    code,
                    message: err.message,
                });
            }
            // Fallback to privileged error
            let err = PrivilegedError::decode_bounded(payload, &DecodeConfig::default())
                .map_err(|e| ProtocolClientError::DecodeError(e.to_string()))?;
            let code = PrivilegedErrorCode::try_from(err.code)
                .map_or_else(|_| err.code.to_string(), |c| format!("{c:?}"));
            return Err(ProtocolClientError::DaemonError {
                code,
                message: err.message,
            });
        }

        if tag != PrivilegedMessageType::ConsensusValidators.tag() {
            return Err(ProtocolClientError::UnexpectedResponse(format!(
                "expected ConsensusValidators response (tag {}), got tag {tag}",
                PrivilegedMessageType::ConsensusValidators.tag()
            )));
        }

        ConsensusValidatorsResponse::decode_bounded(payload, &DecodeConfig::default())
            .map_err(|e| ProtocolClientError::DecodeError(e.to_string()))
    }

    /// Decodes a `ConsensusByzantineEvidence` response.
    fn decode_consensus_byzantine_evidence_response(
        frame: &Bytes,
    ) -> Result<ConsensusByzantineEvidenceResponse, ProtocolClientError> {
        if frame.is_empty() {
            return Err(ProtocolClientError::DecodeError("empty frame".to_string()));
        }

        let tag = frame[0];
        let payload = &frame[1..];

        if tag == 0 {
            // Error response - check if it's a consensus error
            if let Ok(err) = ConsensusError::decode_bounded(payload, &DecodeConfig::default()) {
                let code = ConsensusErrorCode::try_from(err.code)
                    .map_or_else(|_| err.code.to_string(), |c| format!("{c:?}"));
                return Err(ProtocolClientError::DaemonError {
                    code,
                    message: err.message,
                });
            }
            // Fallback to privileged error
            let err = PrivilegedError::decode_bounded(payload, &DecodeConfig::default())
                .map_err(|e| ProtocolClientError::DecodeError(e.to_string()))?;
            let code = PrivilegedErrorCode::try_from(err.code)
                .map_or_else(|_| err.code.to_string(), |c| format!("{c:?}"));
            return Err(ProtocolClientError::DaemonError {
                code,
                message: err.message,
            });
        }

        if tag != PrivilegedMessageType::ConsensusByzantineEvidence.tag() {
            return Err(ProtocolClientError::UnexpectedResponse(format!(
                "expected ConsensusByzantineEvidence response (tag {}), got tag {tag}",
                PrivilegedMessageType::ConsensusByzantineEvidence.tag()
            )));
        }

        ConsensusByzantineEvidenceResponse::decode_bounded(payload, &DecodeConfig::default())
            .map_err(|e| ProtocolClientError::DecodeError(e.to_string()))
    }

    /// Decodes a `ConsensusMetrics` response.
    fn decode_consensus_metrics_response(
        frame: &Bytes,
    ) -> Result<ConsensusMetricsResponse, ProtocolClientError> {
        if frame.is_empty() {
            return Err(ProtocolClientError::DecodeError("empty frame".to_string()));
        }

        let tag = frame[0];
        let payload = &frame[1..];

        if tag == 0 {
            // Error response - check if it's a consensus error
            if let Ok(err) = ConsensusError::decode_bounded(payload, &DecodeConfig::default()) {
                let code = ConsensusErrorCode::try_from(err.code)
                    .map_or_else(|_| err.code.to_string(), |c| format!("{c:?}"));
                return Err(ProtocolClientError::DaemonError {
                    code,
                    message: err.message,
                });
            }
            // Fallback to privileged error
            let err = PrivilegedError::decode_bounded(payload, &DecodeConfig::default())
                .map_err(|e| ProtocolClientError::DecodeError(e.to_string()))?;
            let code = PrivilegedErrorCode::try_from(err.code)
                .map_or_else(|_| err.code.to_string(), |c| format!("{c:?}"));
            return Err(ProtocolClientError::DaemonError {
                code,
                message: err.message,
            });
        }

        if tag != PrivilegedMessageType::ConsensusMetrics.tag() {
            return Err(ProtocolClientError::UnexpectedResponse(format!(
                "expected ConsensusMetrics response (tag {}), got tag {tag}",
                PrivilegedMessageType::ConsensusMetrics.tag()
            )));
        }

        ConsensusMetricsResponse::decode_bounded(payload, &DecodeConfig::default())
            .map_err(|e| ProtocolClientError::DecodeError(e.to_string()))
    }

    /// Decodes a `WorkStatus` response (TCK-00344).
    fn decode_work_status_response(
        frame: &Bytes,
    ) -> Result<WorkStatusResponse, ProtocolClientError> {
        if frame.is_empty() {
            return Err(ProtocolClientError::DecodeError("empty frame".to_string()));
        }

        let tag = frame[0];
        let payload = &frame[1..];

        if tag == 0 {
            let err = PrivilegedError::decode_bounded(payload, &DecodeConfig::default())
                .map_err(|e| ProtocolClientError::DecodeError(e.to_string()))?;
            let code = PrivilegedErrorCode::try_from(err.code)
                .map_or_else(|_| err.code.to_string(), |c| format!("{c:?}"));
            return Err(ProtocolClientError::DaemonError {
                code,
                message: err.message,
            });
        }

        if tag != PrivilegedMessageType::WorkStatus.tag() {
            return Err(ProtocolClientError::UnexpectedResponse(format!(
                "expected WorkStatus response (tag {}), got tag {tag}",
                PrivilegedMessageType::WorkStatus.tag()
            )));
        }

        WorkStatusResponse::decode_bounded(payload, &DecodeConfig::default())
            .map_err(|e| ProtocolClientError::DecodeError(e.to_string()))
    }

    /// Decodes a `WorkList` response (TCK-00415).
    fn decode_work_list_response(frame: &Bytes) -> Result<WorkListResponse, ProtocolClientError> {
        if frame.is_empty() {
            return Err(ProtocolClientError::DecodeError("empty frame".to_string()));
        }

        let tag = frame[0];
        let payload = &frame[1..];

        if tag == 0 {
            let err = PrivilegedError::decode_bounded(payload, &DecodeConfig::default())
                .map_err(|e| ProtocolClientError::DecodeError(e.to_string()))?;
            let code = PrivilegedErrorCode::try_from(err.code)
                .map_or_else(|_| err.code.to_string(), |c| format!("{c:?}"));
            return Err(ProtocolClientError::DaemonError {
                code,
                message: err.message,
            });
        }

        if tag != PrivilegedMessageType::WorkList.tag() {
            return Err(ProtocolClientError::UnexpectedResponse(format!(
                "expected WorkList response (tag {}), got tag {tag}",
                PrivilegedMessageType::WorkList.tag()
            )));
        }

        WorkListResponse::decode_bounded(payload, &DecodeConfig::default())
            .map_err(|e| ProtocolClientError::DecodeError(e.to_string()))
    }

    /// Decodes a `ResolveTicketAlias` response (TCK-00636).
    fn decode_resolve_ticket_alias_response(
        frame: &Bytes,
    ) -> Result<ResolveTicketAliasResponse, ProtocolClientError> {
        if frame.is_empty() {
            return Err(ProtocolClientError::DecodeError("empty frame".to_string()));
        }

        let tag = frame[0];
        let payload = &frame[1..];

        if tag == 0 {
            let err = PrivilegedError::decode_bounded(payload, &DecodeConfig::default())
                .map_err(|e| ProtocolClientError::DecodeError(e.to_string()))?;
            let code = PrivilegedErrorCode::try_from(err.code)
                .map_or_else(|_| err.code.to_string(), |c| format!("{c:?}"));
            return Err(ProtocolClientError::DaemonError {
                code,
                message: err.message,
            });
        }

        if tag != PrivilegedMessageType::ResolveTicketAlias.tag() {
            return Err(ProtocolClientError::UnexpectedResponse(format!(
                "expected ResolveTicketAlias response (tag {}), got tag {tag}",
                PrivilegedMessageType::ResolveTicketAlias.tag()
            )));
        }

        ResolveTicketAliasResponse::decode_bounded(payload, &DecodeConfig::default())
            .map_err(|e| ProtocolClientError::DecodeError(e.to_string()))
    }

    // =========================================================================
    // TCK-00394: ChangeSet Publishing
    // =========================================================================

    /// Publishes a `ChangeSetBundleV1` to the daemon.
    ///
    /// Stores the bundle in CAS, emits a `ChangeSetPublished` ledger event,
    /// and returns the changeset digest and CAS hash for subsequent gate
    /// lease binding.
    ///
    /// # Arguments
    ///
    /// * `work_id` - Work identifier this changeset belongs to
    /// * `bundle_bytes` - Serialized `ChangeSetBundleV1` (canonical JSON)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The daemon rejects the request (invalid `work_id`, bad bundle, etc.)
    /// - Communication fails
    #[allow(dead_code)] // Wired by future CLI subcommand
    pub async fn publish_changeset(
        &mut self,
        work_id: &str,
        bundle_bytes: Vec<u8>,
    ) -> Result<PublishChangeSetResponse, ProtocolClientError> {
        let request = PublishChangeSetRequest {
            work_id: work_id.to_string(),
            bundle_bytes,
        };
        let request_bytes = encode_publish_changeset_request(&request);

        // Send request
        tokio::time::timeout(self.timeout, self.framed.send(request_bytes))
            .await
            .map_err(|_| ProtocolClientError::Timeout)?
            .map_err(|e| ProtocolClientError::IoError(io::Error::other(e.to_string())))?;

        // Receive response
        let response_frame = tokio::time::timeout(self.timeout, self.framed.next())
            .await
            .map_err(|_| ProtocolClientError::Timeout)?
            .ok_or_else(|| {
                ProtocolClientError::UnexpectedResponse("connection closed".to_string())
            })?
            .map_err(|e| ProtocolClientError::IoError(io::Error::other(e.to_string())))?;

        // Decode response
        Self::decode_publish_changeset_response(&response_frame)
    }

    /// Decodes a `PublishChangeSet` response.
    #[allow(dead_code)] // Used by publish_changeset
    fn decode_publish_changeset_response(
        frame: &Bytes,
    ) -> Result<PublishChangeSetResponse, ProtocolClientError> {
        if frame.is_empty() {
            return Err(ProtocolClientError::DecodeError("empty frame".to_string()));
        }

        let tag = frame[0];
        let payload = &frame[1..];

        if tag == 0 {
            let err = PrivilegedError::decode_bounded(payload, &DecodeConfig::default())
                .map_err(|e| ProtocolClientError::DecodeError(e.to_string()))?;
            let code = PrivilegedErrorCode::try_from(err.code)
                .map_or_else(|_| err.code.to_string(), |c| format!("{c:?}"));
            return Err(ProtocolClientError::DaemonError {
                code,
                message: err.message,
            });
        }

        if tag != PrivilegedMessageType::PublishChangeSet.tag() {
            return Err(ProtocolClientError::UnexpectedResponse(format!(
                "expected PublishChangeSet response (tag {}), got tag {tag}",
                PrivilegedMessageType::PublishChangeSet.tag()
            )));
        }

        PublishChangeSetResponse::decode_bounded(payload, &DecodeConfig::default())
            .map_err(|e| ProtocolClientError::DecodeError(e.to_string()))
    }

    /// Records a canonical PR association for an existing `work_id`.
    pub async fn record_work_pr_association(
        &mut self,
        work_id: &str,
        pr_number: u64,
        commit_sha: &str,
        lease_id: &str,
        pr_url: Option<&str>,
        validate_only: bool,
    ) -> Result<RecordWorkPrAssociationResponse, ProtocolClientError> {
        let request = RecordWorkPrAssociationRequest {
            work_id: work_id.to_string(),
            pr_number,
            commit_sha: commit_sha.to_string(),
            lease_id: lease_id.to_string(),
            pr_url: pr_url.unwrap_or_default().to_string(),
            validate_only,
        };
        let request_bytes = encode_record_work_pr_association_request(&request);

        tokio::time::timeout(self.timeout, self.framed.send(request_bytes))
            .await
            .map_err(|_| ProtocolClientError::Timeout)?
            .map_err(|e| ProtocolClientError::IoError(io::Error::other(e.to_string())))?;

        let response_frame = tokio::time::timeout(self.timeout, self.framed.next())
            .await
            .map_err(|_| ProtocolClientError::Timeout)?
            .ok_or_else(|| {
                ProtocolClientError::UnexpectedResponse("connection closed".to_string())
            })?
            .map_err(|e| ProtocolClientError::IoError(io::Error::other(e.to_string())))?;

        Self::decode_record_work_pr_association_response(&response_frame)
    }

    fn decode_record_work_pr_association_response(
        frame: &Bytes,
    ) -> Result<RecordWorkPrAssociationResponse, ProtocolClientError> {
        if frame.is_empty() {
            return Err(ProtocolClientError::DecodeError("empty frame".to_string()));
        }

        let tag = frame[0];
        let payload = &frame[1..];

        if tag == 0 {
            let err = PrivilegedError::decode_bounded(payload, &DecodeConfig::default())
                .map_err(|e| ProtocolClientError::DecodeError(e.to_string()))?;
            let code = PrivilegedErrorCode::try_from(err.code)
                .map_or_else(|_| err.code.to_string(), |c| format!("{c:?}"));
            return Err(ProtocolClientError::DaemonError {
                code,
                message: err.message,
            });
        }

        if tag != PrivilegedMessageType::RecordWorkPrAssociation.tag() {
            return Err(ProtocolClientError::UnexpectedResponse(format!(
                "expected RecordWorkPrAssociation response (tag {}), got tag {tag}",
                PrivilegedMessageType::RecordWorkPrAssociation.tag()
            )));
        }

        RecordWorkPrAssociationResponse::decode_bounded(payload, &DecodeConfig::default())
            .map_err(|e| ProtocolClientError::DecodeError(e.to_string()))
    }

    /// Publishes a work context entry anchored by `(work_id, kind,
    /// dedupe_key)`.
    pub async fn publish_work_context_entry(
        &mut self,
        work_id: &str,
        kind: &str,
        dedupe_key: &str,
        entry_json: Vec<u8>,
        lease_id: &str,
    ) -> Result<PublishWorkContextEntryResponse, ProtocolClientError> {
        let request = PublishWorkContextEntryRequest {
            work_id: work_id.to_string(),
            kind: kind.to_string(),
            dedupe_key: dedupe_key.to_string(),
            entry_json,
            lease_id: lease_id.to_string(),
        };
        let request_bytes = encode_publish_work_context_entry_request(&request);

        tokio::time::timeout(self.timeout, self.framed.send(request_bytes))
            .await
            .map_err(|_| ProtocolClientError::Timeout)?
            .map_err(|e| ProtocolClientError::IoError(io::Error::other(e.to_string())))?;

        let response_frame = tokio::time::timeout(self.timeout, self.framed.next())
            .await
            .map_err(|_| ProtocolClientError::Timeout)?
            .ok_or_else(|| {
                ProtocolClientError::UnexpectedResponse("connection closed".to_string())
            })?
            .map_err(|e| ProtocolClientError::IoError(io::Error::other(e.to_string())))?;

        Self::decode_publish_work_context_entry_response(&response_frame)
    }

    fn decode_publish_work_context_entry_response(
        frame: &Bytes,
    ) -> Result<PublishWorkContextEntryResponse, ProtocolClientError> {
        if frame.is_empty() {
            return Err(ProtocolClientError::DecodeError("empty frame".to_string()));
        }

        let tag = frame[0];
        let payload = &frame[1..];

        if tag == 0 {
            let err = PrivilegedError::decode_bounded(payload, &DecodeConfig::default())
                .map_err(|e| ProtocolClientError::DecodeError(e.to_string()))?;
            let code = PrivilegedErrorCode::try_from(err.code)
                .map_or_else(|_| err.code.to_string(), |c| format!("{c:?}"));
            return Err(ProtocolClientError::DaemonError {
                code,
                message: err.message,
            });
        }

        if tag != PrivilegedMessageType::PublishWorkContextEntry.tag() {
            return Err(ProtocolClientError::UnexpectedResponse(format!(
                "expected PublishWorkContextEntry response (tag {}), got tag {tag}",
                PrivilegedMessageType::PublishWorkContextEntry.tag()
            )));
        }

        PublishWorkContextEntryResponse::decode_bounded(payload, &DecodeConfig::default())
            .map_err(|e| ProtocolClientError::DecodeError(e.to_string()))
    }

    // =========================================================================
    // Credential Management Methods (CTR-PROTO-012, TCK-00343)
    // =========================================================================

    /// Lists all credential profiles.
    ///
    /// Secrets are never included in the response.
    pub async fn list_credentials(
        &mut self,
        provider_filter: Option<i32>,
    ) -> Result<ListCredentialsResponse, ProtocolClientError> {
        let request = ListCredentialsRequest { provider_filter };
        let request_bytes = encode_list_credentials_request(&request);

        // Send request
        tokio::time::timeout(self.timeout, self.framed.send(request_bytes))
            .await
            .map_err(|_| ProtocolClientError::Timeout)?
            .map_err(|e| ProtocolClientError::IoError(io::Error::other(e.to_string())))?;

        // Receive response
        let response_frame = tokio::time::timeout(self.timeout, self.framed.next())
            .await
            .map_err(|_| ProtocolClientError::Timeout)?
            .ok_or_else(|| {
                ProtocolClientError::UnexpectedResponse("connection closed".to_string())
            })?
            .map_err(|e| ProtocolClientError::IoError(io::Error::other(e.to_string())))?;

        // Decode response
        Self::decode_list_credentials_response(&response_frame)
    }

    /// Adds a new credential profile.
    ///
    /// The secret is stored securely and never logged or returned.
    pub async fn add_credential(
        &mut self,
        profile_id: &str,
        provider: i32,
        auth_method: i32,
        credential_secret: &[u8],
        display_name: &str,
        expires_at: u64,
    ) -> Result<AddCredentialResponse, ProtocolClientError> {
        let request = AddCredentialRequest {
            profile_id: profile_id.to_string(),
            provider,
            auth_method,
            credential_secret: credential_secret.to_vec(),
            display_name: display_name.to_string(),
            expires_at,
        };
        let request_bytes = encode_add_credential_request(&request);

        // Send request
        tokio::time::timeout(self.timeout, self.framed.send(request_bytes))
            .await
            .map_err(|_| ProtocolClientError::Timeout)?
            .map_err(|e| ProtocolClientError::IoError(io::Error::other(e.to_string())))?;

        // Receive response
        let response_frame = tokio::time::timeout(self.timeout, self.framed.next())
            .await
            .map_err(|_| ProtocolClientError::Timeout)?
            .ok_or_else(|| {
                ProtocolClientError::UnexpectedResponse("connection closed".to_string())
            })?
            .map_err(|e| ProtocolClientError::IoError(io::Error::other(e.to_string())))?;

        // Decode response
        Self::decode_add_credential_response(&response_frame)
    }

    /// Removes a credential profile.
    pub async fn remove_credential(
        &mut self,
        profile_id: &str,
    ) -> Result<RemoveCredentialResponse, ProtocolClientError> {
        let request = RemoveCredentialRequest {
            profile_id: profile_id.to_string(),
        };
        let request_bytes = encode_remove_credential_request(&request);

        // Send request
        tokio::time::timeout(self.timeout, self.framed.send(request_bytes))
            .await
            .map_err(|_| ProtocolClientError::Timeout)?
            .map_err(|e| ProtocolClientError::IoError(io::Error::other(e.to_string())))?;

        // Receive response
        let response_frame = tokio::time::timeout(self.timeout, self.framed.next())
            .await
            .map_err(|_| ProtocolClientError::Timeout)?
            .ok_or_else(|| {
                ProtocolClientError::UnexpectedResponse("connection closed".to_string())
            })?
            .map_err(|e| ProtocolClientError::IoError(io::Error::other(e.to_string())))?;

        // Decode response
        Self::decode_remove_credential_response(&response_frame)
    }

    /// Refreshes an OAuth credential.
    pub async fn refresh_credential(
        &mut self,
        profile_id: &str,
    ) -> Result<RefreshCredentialResponse, ProtocolClientError> {
        let request = RefreshCredentialRequest {
            profile_id: profile_id.to_string(),
        };
        let request_bytes = encode_refresh_credential_request(&request);

        // Send request
        tokio::time::timeout(self.timeout, self.framed.send(request_bytes))
            .await
            .map_err(|_| ProtocolClientError::Timeout)?
            .map_err(|e| ProtocolClientError::IoError(io::Error::other(e.to_string())))?;

        // Receive response
        let response_frame = tokio::time::timeout(self.timeout, self.framed.next())
            .await
            .map_err(|_| ProtocolClientError::Timeout)?
            .ok_or_else(|| {
                ProtocolClientError::UnexpectedResponse("connection closed".to_string())
            })?
            .map_err(|e| ProtocolClientError::IoError(io::Error::other(e.to_string())))?;

        // Decode response
        Self::decode_refresh_credential_response(&response_frame)
    }

    /// Switches the active credential for a process.
    pub async fn switch_credential(
        &mut self,
        process_name: &str,
        profile_id: &str,
    ) -> Result<SwitchCredentialResponse, ProtocolClientError> {
        let request = SwitchCredentialRequest {
            process_name: process_name.to_string(),
            profile_id: profile_id.to_string(),
        };
        let request_bytes = encode_switch_credential_request(&request);

        // Send request
        tokio::time::timeout(self.timeout, self.framed.send(request_bytes))
            .await
            .map_err(|_| ProtocolClientError::Timeout)?
            .map_err(|e| ProtocolClientError::IoError(io::Error::other(e.to_string())))?;

        // Receive response
        let response_frame = tokio::time::timeout(self.timeout, self.framed.next())
            .await
            .map_err(|_| ProtocolClientError::Timeout)?
            .ok_or_else(|| {
                ProtocolClientError::UnexpectedResponse("connection closed".to_string())
            })?
            .map_err(|e| ProtocolClientError::IoError(io::Error::other(e.to_string())))?;

        // Decode response
        Self::decode_switch_credential_response(&response_frame)
    }

    /// Initiates an interactive login for a provider.
    pub async fn login_credential(
        &mut self,
        provider: i32,
        profile_id: Option<&str>,
        display_name: &str,
    ) -> Result<LoginCredentialResponse, ProtocolClientError> {
        let request = LoginCredentialRequest {
            provider,
            profile_id: profile_id.map(String::from),
            display_name: display_name.to_string(),
        };
        let request_bytes = encode_login_credential_request(&request);

        // Send request
        tokio::time::timeout(self.timeout, self.framed.send(request_bytes))
            .await
            .map_err(|_| ProtocolClientError::Timeout)?
            .map_err(|e| ProtocolClientError::IoError(io::Error::other(e.to_string())))?;

        // Receive response
        let response_frame = tokio::time::timeout(self.timeout, self.framed.next())
            .await
            .map_err(|_| ProtocolClientError::Timeout)?
            .ok_or_else(|| {
                ProtocolClientError::UnexpectedResponse("connection closed".to_string())
            })?
            .map_err(|e| ProtocolClientError::IoError(io::Error::other(e.to_string())))?;

        // Decode response
        Self::decode_login_credential_response(&response_frame)
    }

    // =========================================================================
    // Credential Response Decoders
    // =========================================================================

    fn decode_list_credentials_response(
        frame: &Bytes,
    ) -> Result<ListCredentialsResponse, ProtocolClientError> {
        if frame.is_empty() {
            return Err(ProtocolClientError::DecodeError("empty frame".to_string()));
        }

        let tag = frame[0];
        let payload = &frame[1..];

        if tag == 0 {
            let err = PrivilegedError::decode_bounded(payload, &DecodeConfig::default())
                .map_err(|e| ProtocolClientError::DecodeError(e.to_string()))?;
            let code = PrivilegedErrorCode::try_from(err.code)
                .map_or_else(|_| err.code.to_string(), |c| format!("{c:?}"));
            return Err(ProtocolClientError::DaemonError {
                code,
                message: err.message,
            });
        }

        if tag != PrivilegedMessageType::ListCredentials.tag() {
            return Err(ProtocolClientError::UnexpectedResponse(format!(
                "expected ListCredentials response (tag {}), got tag {tag}",
                PrivilegedMessageType::ListCredentials.tag()
            )));
        }

        ListCredentialsResponse::decode_bounded(payload, &DecodeConfig::default())
            .map_err(|e| ProtocolClientError::DecodeError(e.to_string()))
    }

    fn decode_add_credential_response(
        frame: &Bytes,
    ) -> Result<AddCredentialResponse, ProtocolClientError> {
        if frame.is_empty() {
            return Err(ProtocolClientError::DecodeError("empty frame".to_string()));
        }

        let tag = frame[0];
        let payload = &frame[1..];

        if tag == 0 {
            let err = PrivilegedError::decode_bounded(payload, &DecodeConfig::default())
                .map_err(|e| ProtocolClientError::DecodeError(e.to_string()))?;
            let code = PrivilegedErrorCode::try_from(err.code)
                .map_or_else(|_| err.code.to_string(), |c| format!("{c:?}"));
            return Err(ProtocolClientError::DaemonError {
                code,
                message: err.message,
            });
        }

        if tag != PrivilegedMessageType::AddCredential.tag() {
            return Err(ProtocolClientError::UnexpectedResponse(format!(
                "expected AddCredential response (tag {}), got tag {tag}",
                PrivilegedMessageType::AddCredential.tag()
            )));
        }

        AddCredentialResponse::decode_bounded(payload, &DecodeConfig::default())
            .map_err(|e| ProtocolClientError::DecodeError(e.to_string()))
    }

    fn decode_remove_credential_response(
        frame: &Bytes,
    ) -> Result<RemoveCredentialResponse, ProtocolClientError> {
        if frame.is_empty() {
            return Err(ProtocolClientError::DecodeError("empty frame".to_string()));
        }

        let tag = frame[0];
        let payload = &frame[1..];

        if tag == 0 {
            let err = PrivilegedError::decode_bounded(payload, &DecodeConfig::default())
                .map_err(|e| ProtocolClientError::DecodeError(e.to_string()))?;
            let code = PrivilegedErrorCode::try_from(err.code)
                .map_or_else(|_| err.code.to_string(), |c| format!("{c:?}"));
            return Err(ProtocolClientError::DaemonError {
                code,
                message: err.message,
            });
        }

        if tag != PrivilegedMessageType::RemoveCredential.tag() {
            return Err(ProtocolClientError::UnexpectedResponse(format!(
                "expected RemoveCredential response (tag {}), got tag {tag}",
                PrivilegedMessageType::RemoveCredential.tag()
            )));
        }

        RemoveCredentialResponse::decode_bounded(payload, &DecodeConfig::default())
            .map_err(|e| ProtocolClientError::DecodeError(e.to_string()))
    }

    fn decode_refresh_credential_response(
        frame: &Bytes,
    ) -> Result<RefreshCredentialResponse, ProtocolClientError> {
        if frame.is_empty() {
            return Err(ProtocolClientError::DecodeError("empty frame".to_string()));
        }

        let tag = frame[0];
        let payload = &frame[1..];

        if tag == 0 {
            let err = PrivilegedError::decode_bounded(payload, &DecodeConfig::default())
                .map_err(|e| ProtocolClientError::DecodeError(e.to_string()))?;
            let code = PrivilegedErrorCode::try_from(err.code)
                .map_or_else(|_| err.code.to_string(), |c| format!("{c:?}"));
            return Err(ProtocolClientError::DaemonError {
                code,
                message: err.message,
            });
        }

        if tag != PrivilegedMessageType::RefreshCredential.tag() {
            return Err(ProtocolClientError::UnexpectedResponse(format!(
                "expected RefreshCredential response (tag {}), got tag {tag}",
                PrivilegedMessageType::RefreshCredential.tag()
            )));
        }

        RefreshCredentialResponse::decode_bounded(payload, &DecodeConfig::default())
            .map_err(|e| ProtocolClientError::DecodeError(e.to_string()))
    }

    fn decode_switch_credential_response(
        frame: &Bytes,
    ) -> Result<SwitchCredentialResponse, ProtocolClientError> {
        if frame.is_empty() {
            return Err(ProtocolClientError::DecodeError("empty frame".to_string()));
        }

        let tag = frame[0];
        let payload = &frame[1..];

        if tag == 0 {
            let err = PrivilegedError::decode_bounded(payload, &DecodeConfig::default())
                .map_err(|e| ProtocolClientError::DecodeError(e.to_string()))?;
            let code = PrivilegedErrorCode::try_from(err.code)
                .map_or_else(|_| err.code.to_string(), |c| format!("{c:?}"));
            return Err(ProtocolClientError::DaemonError {
                code,
                message: err.message,
            });
        }

        if tag != PrivilegedMessageType::SwitchCredential.tag() {
            return Err(ProtocolClientError::UnexpectedResponse(format!(
                "expected SwitchCredential response (tag {}), got tag {tag}",
                PrivilegedMessageType::SwitchCredential.tag()
            )));
        }

        SwitchCredentialResponse::decode_bounded(payload, &DecodeConfig::default())
            .map_err(|e| ProtocolClientError::DecodeError(e.to_string()))
    }

    fn decode_login_credential_response(
        frame: &Bytes,
    ) -> Result<LoginCredentialResponse, ProtocolClientError> {
        if frame.is_empty() {
            return Err(ProtocolClientError::DecodeError("empty frame".to_string()));
        }

        let tag = frame[0];
        let payload = &frame[1..];

        if tag == 0 {
            let err = PrivilegedError::decode_bounded(payload, &DecodeConfig::default())
                .map_err(|e| ProtocolClientError::DecodeError(e.to_string()))?;
            let code = PrivilegedErrorCode::try_from(err.code)
                .map_or_else(|_| err.code.to_string(), |c| format!("{c:?}"));
            return Err(ProtocolClientError::DaemonError {
                code,
                message: err.message,
            });
        }

        if tag != PrivilegedMessageType::LoginCredential.tag() {
            return Err(ProtocolClientError::UnexpectedResponse(format!(
                "expected LoginCredential response (tag {}), got tag {tag}",
                PrivilegedMessageType::LoginCredential.tag()
            )));
        }

        LoginCredentialResponse::decode_bounded(payload, &DecodeConfig::default())
            .map_err(|e| ProtocolClientError::DecodeError(e.to_string()))
    }
}

// ============================================================================
// Session Socket Client
// ============================================================================

/// Client for session-scoped operations on session.sock.
///
/// This client connects to the session socket and can execute session-scoped
/// operations like `RequestTool`, `EmitEvent`, `PublishEvidence`, and
/// `StreamTelemetry`.
///
/// # Security
///
/// - Session operations require a valid `session_token`
/// - All requests use tag-based protobuf framing (no JSON)
/// - Mandatory Hello/HelloAck handshake per CTR-PROTO-001
pub struct SessionClient {
    framed: Framed<UnixStream, FrameCodec>,
    /// Server info from handshake (reserved for future use in diagnostics).
    #[allow(dead_code)]
    server_info: String,
    daemon_signing_public_key: Option<[u8; DAEMON_SIGNING_PUBLIC_KEY_LEN]>,
    timeout: Duration,
}

impl SessionClient {
    /// Connects to the session socket and performs the handshake.
    ///
    /// # Arguments
    ///
    /// * `socket_path` - Path to the session socket
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The socket does not exist (daemon not running)
    /// - Connection fails
    /// - Handshake fails (version mismatch, rejected)
    pub async fn connect(socket_path: &Path) -> Result<Self, ProtocolClientError> {
        Self::connect_with_timeout(socket_path, Duration::from_secs(DEFAULT_TIMEOUT_SECS)).await
    }

    /// Connects with a custom timeout.
    pub async fn connect_with_timeout(
        socket_path: &Path,
        timeout: Duration,
    ) -> Result<Self, ProtocolClientError> {
        // Check if socket exists first (provides better error message)
        if !socket_path.exists() {
            return Err(ProtocolClientError::DaemonNotRunning);
        }

        // Connect to socket
        let stream = tokio::time::timeout(timeout, UnixStream::connect(socket_path))
            .await
            .map_err(|_| ProtocolClientError::Timeout)?
            .map_err(ProtocolClientError::from)?;

        let mut framed = Framed::new(stream, FrameCodec::new());

        // Perform handshake (same as operator)
        let handshake = OperatorClient::perform_handshake(&mut framed, timeout).await?;

        Ok(Self {
            framed,
            server_info: handshake.server_info,
            daemon_signing_public_key: handshake.daemon_signing_public_key,
            timeout,
        })
    }

    /// Returns the daemon signing public key from handshake metadata.
    #[must_use]
    pub const fn daemon_signing_public_key(&self) -> Option<&[u8; DAEMON_SIGNING_PUBLIC_KEY_LEN]> {
        self.daemon_signing_public_key.as_ref()
    }

    /// Requests tool execution within session capability bounds.
    ///
    /// # Arguments
    ///
    /// * `session_token` - Session token for authentication
    /// * `tool_id` - Tool identifier (e.g., "`file_read`", "`shell_exec`")
    /// * `arguments` - Serialized tool arguments (JSON or binary)
    /// * `dedupe_key` - Deduplication key for idempotent requests
    pub async fn request_tool(
        &mut self,
        session_token: &str,
        tool_id: &str,
        arguments: &[u8],
        dedupe_key: &str,
    ) -> Result<RequestToolResponse, ProtocolClientError> {
        let request = RequestToolRequest {
            session_token: session_token.to_string(),
            tool_id: tool_id.to_string(),
            arguments: arguments.to_vec(),
            dedupe_key: dedupe_key.to_string(),
            epoch_seal: None,
        };
        let request_bytes = encode_request_tool_request(&request);

        // Send request
        tokio::time::timeout(self.timeout, self.framed.send(request_bytes))
            .await
            .map_err(|_| ProtocolClientError::Timeout)?
            .map_err(|e| ProtocolClientError::IoError(io::Error::other(e.to_string())))?;

        // Receive response
        let response_frame = tokio::time::timeout(self.timeout, self.framed.next())
            .await
            .map_err(|_| ProtocolClientError::Timeout)?
            .ok_or_else(|| {
                ProtocolClientError::UnexpectedResponse("connection closed".to_string())
            })?
            .map_err(|e| ProtocolClientError::IoError(io::Error::other(e.to_string())))?;

        // Decode response
        Self::decode_request_tool_response(&response_frame)
    }

    /// Emits a signed event to the ledger.
    ///
    /// # Arguments
    ///
    /// * `session_token` - Session token for authentication
    /// * `event_type` - Event type identifier
    /// * `payload` - Event payload (JSON or binary)
    /// * `correlation_id` - Correlation ID for event tracing
    pub async fn emit_event(
        &mut self,
        session_token: &str,
        event_type: &str,
        payload: &[u8],
        correlation_id: &str,
    ) -> Result<EmitEventResponse, ProtocolClientError> {
        let request = EmitEventRequest {
            session_token: session_token.to_string(),
            event_type: event_type.to_string(),
            payload: payload.to_vec(),
            correlation_id: correlation_id.to_string(),
        };
        let request_bytes = encode_emit_event_request(&request);

        // Send request
        tokio::time::timeout(self.timeout, self.framed.send(request_bytes))
            .await
            .map_err(|_| ProtocolClientError::Timeout)?
            .map_err(|e| ProtocolClientError::IoError(io::Error::other(e.to_string())))?;

        // Receive response
        let response_frame = tokio::time::timeout(self.timeout, self.framed.next())
            .await
            .map_err(|_| ProtocolClientError::Timeout)?
            .ok_or_else(|| {
                ProtocolClientError::UnexpectedResponse("connection closed".to_string())
            })?
            .map_err(|e| ProtocolClientError::IoError(io::Error::other(e.to_string())))?;

        // Decode response
        Self::decode_emit_event_response(&response_frame)
    }

    /// Decodes a `RequestTool` response.
    fn decode_request_tool_response(
        frame: &Bytes,
    ) -> Result<RequestToolResponse, ProtocolClientError> {
        if frame.is_empty() {
            return Err(ProtocolClientError::DecodeError("empty frame".to_string()));
        }

        let tag = frame[0];
        let payload = &frame[1..];

        if tag == 0 {
            // Error response
            let err = SessionError::decode_bounded(payload, &DecodeConfig::default())
                .map_err(|e| ProtocolClientError::DecodeError(e.to_string()))?;
            let code = SessionErrorCode::try_from(err.code)
                .map_or_else(|_| err.code.to_string(), |c| format!("{c:?}"));
            return Err(ProtocolClientError::DaemonError {
                code,
                message: err.message,
            });
        }

        if tag != SessionMessageType::RequestTool.tag() {
            return Err(ProtocolClientError::UnexpectedResponse(format!(
                "expected RequestTool response (tag {}), got tag {tag}",
                SessionMessageType::RequestTool.tag()
            )));
        }

        RequestToolResponse::decode_bounded(payload, &DecodeConfig::default())
            .map_err(|e| ProtocolClientError::DecodeError(e.to_string()))
    }

    /// Decodes an `EmitEvent` response.
    fn decode_emit_event_response(frame: &Bytes) -> Result<EmitEventResponse, ProtocolClientError> {
        if frame.is_empty() {
            return Err(ProtocolClientError::DecodeError("empty frame".to_string()));
        }

        let tag = frame[0];
        let payload = &frame[1..];

        if tag == 0 {
            // Error response
            let err = SessionError::decode_bounded(payload, &DecodeConfig::default())
                .map_err(|e| ProtocolClientError::DecodeError(e.to_string()))?;
            let code = SessionErrorCode::try_from(err.code)
                .map_or_else(|_| err.code.to_string(), |c| format!("{c:?}"));
            return Err(ProtocolClientError::DaemonError {
                code,
                message: err.message,
            });
        }

        if tag != SessionMessageType::EmitEvent.tag() {
            return Err(ProtocolClientError::UnexpectedResponse(format!(
                "expected EmitEvent response (tag {}), got tag {tag}",
                SessionMessageType::EmitEvent.tag()
            )));
        }

        EmitEventResponse::decode_bounded(payload, &DecodeConfig::default())
            .map_err(|e| ProtocolClientError::DecodeError(e.to_string()))
    }

    /// Publishes evidence artifact to content-addressed storage.
    ///
    /// # Arguments
    ///
    /// * `session_token` - Session token for authentication
    /// * `artifact` - Binary artifact content
    /// * `kind` - Evidence kind for categorization
    /// * `retention_hint` - Retention hint for storage policy
    pub async fn publish_evidence(
        &mut self,
        session_token: &str,
        artifact: &[u8],
        kind: i32,
        retention_hint: i32,
    ) -> Result<PublishEvidenceResponse, ProtocolClientError> {
        let request = PublishEvidenceRequest {
            session_token: session_token.to_string(),
            artifact: artifact.to_vec(),
            kind,
            retention_hint,
        };
        let request_bytes = encode_publish_evidence_request(&request);

        // Send request
        tokio::time::timeout(self.timeout, self.framed.send(request_bytes))
            .await
            .map_err(|_| ProtocolClientError::Timeout)?
            .map_err(|e| ProtocolClientError::IoError(io::Error::other(e.to_string())))?;

        // Receive response
        let response_frame = tokio::time::timeout(self.timeout, self.framed.next())
            .await
            .map_err(|_| ProtocolClientError::Timeout)?
            .ok_or_else(|| {
                ProtocolClientError::UnexpectedResponse("connection closed".to_string())
            })?
            .map_err(|e| ProtocolClientError::IoError(io::Error::other(e.to_string())))?;

        // Decode response
        Self::decode_publish_evidence_response(&response_frame)
    }

    /// Decodes a `PublishEvidence` response.
    fn decode_publish_evidence_response(
        frame: &Bytes,
    ) -> Result<PublishEvidenceResponse, ProtocolClientError> {
        if frame.is_empty() {
            return Err(ProtocolClientError::DecodeError("empty frame".to_string()));
        }

        let tag = frame[0];
        let payload = &frame[1..];

        if tag == 0 {
            // Error response
            let err = SessionError::decode_bounded(payload, &DecodeConfig::default())
                .map_err(|e| ProtocolClientError::DecodeError(e.to_string()))?;
            let code = SessionErrorCode::try_from(err.code)
                .map_or_else(|_| err.code.to_string(), |c| format!("{c:?}"));
            return Err(ProtocolClientError::DaemonError {
                code,
                message: err.message,
            });
        }

        if tag != SessionMessageType::PublishEvidence.tag() {
            return Err(ProtocolClientError::UnexpectedResponse(format!(
                "expected PublishEvidence response (tag {}), got tag {tag}",
                SessionMessageType::PublishEvidence.tag()
            )));
        }

        PublishEvidenceResponse::decode_bounded(payload, &DecodeConfig::default())
            .map_err(|e| ProtocolClientError::DecodeError(e.to_string()))
    }

    // =========================================================================
    // TCK-00342: Process Log Streaming
    // =========================================================================

    /// Streams process logs from a managed process.
    ///
    /// # Arguments
    ///
    /// * `session_token` - Session token for authentication
    /// * `process_name` - Name of the process to stream logs from
    /// * `lines` - Number of historical lines to retrieve
    /// * `follow` - Whether to stream new lines (not implemented in Phase 1)
    ///
    /// # Returns
    ///
    /// Log entries from the process.
    #[allow(dead_code)] // Scaffolding for when session token management is available
    pub async fn stream_logs(
        &mut self,
        session_token: &str,
        process_name: &str,
        lines: u32,
        follow: bool,
    ) -> Result<StreamLogsResponse, ProtocolClientError> {
        let request = StreamLogsRequest {
            session_token: session_token.to_string(),
            process_name: process_name.to_string(),
            lines,
            follow,
        };
        let request_bytes = encode_stream_logs_request(&request);

        // Send request
        tokio::time::timeout(self.timeout, self.framed.send(request_bytes))
            .await
            .map_err(|_| ProtocolClientError::Timeout)?
            .map_err(|e| ProtocolClientError::IoError(io::Error::other(e.to_string())))?;

        // Receive response
        let response_frame = tokio::time::timeout(self.timeout, self.framed.next())
            .await
            .map_err(|_| ProtocolClientError::Timeout)?
            .ok_or_else(|| {
                ProtocolClientError::UnexpectedResponse("connection closed".to_string())
            })?
            .map_err(|e| ProtocolClientError::IoError(io::Error::other(e.to_string())))?;

        // Decode response
        Self::decode_stream_logs_response(&response_frame)
    }

    /// Queries the status of a session (TCK-00344).
    ///
    /// # Arguments
    ///
    /// * `session_token` - Session token for authentication
    ///
    /// # Returns
    ///
    /// Session status including state, work association, and telemetry summary.
    pub async fn session_status(
        &mut self,
        session_token: &str,
    ) -> Result<SessionStatusResponse, ProtocolClientError> {
        let request = SessionStatusRequest {
            session_token: session_token.to_string(),
        };
        let request_bytes = encode_session_status_request(&request);

        // Send request
        tokio::time::timeout(self.timeout, self.framed.send(request_bytes))
            .await
            .map_err(|_| ProtocolClientError::Timeout)?
            .map_err(|e| ProtocolClientError::IoError(io::Error::other(e.to_string())))?;

        // Receive response
        let response_frame = tokio::time::timeout(self.timeout, self.framed.next())
            .await
            .map_err(|_| ProtocolClientError::Timeout)?
            .ok_or_else(|| {
                ProtocolClientError::UnexpectedResponse("connection closed".to_string())
            })?
            .map_err(|e| ProtocolClientError::IoError(io::Error::other(e.to_string())))?;

        // Decode response
        Self::decode_session_status_response(&response_frame)
    }

    /// Queries the status of a session with termination details (TCK-00385).
    ///
    /// This is equivalent to [`session_status`](Self::session_status) but
    /// clarifies that the response may include termination information when
    /// the session has ended. The caller can distinguish ACTIVE from
    /// TERMINATED by checking `response.state`:
    ///
    /// - `"ACTIVE"`: Session is running. Termination fields are `None`.
    /// - `"TERMINATED"`: Session has ended. `termination_reason`, `exit_code`,
    ///   `terminated_at_ns`, and `actual_tokens_consumed` may be populated.
    ///
    /// # Arguments
    ///
    /// * `session_token` - Session token for authentication
    ///
    /// # Returns
    ///
    /// Session status including state, work association, telemetry summary,
    /// and termination details (if applicable).
    pub async fn session_status_with_termination(
        &mut self,
        session_token: &str,
    ) -> Result<SessionStatusResponse, ProtocolClientError> {
        // Delegates to session_status -- the wire response is the same,
        // the new optional fields are populated server-side for TERMINATED
        // sessions.
        self.session_status(session_token).await
    }

    /// Decodes a `StreamLogs` response.
    #[allow(dead_code)] // Used by stream_logs which is scaffolding
    fn decode_stream_logs_response(
        frame: &Bytes,
    ) -> Result<StreamLogsResponse, ProtocolClientError> {
        if frame.is_empty() {
            return Err(ProtocolClientError::DecodeError("empty frame".to_string()));
        }

        let tag = frame[0];
        let payload = &frame[1..];

        if tag == 0 {
            // Error response
            let err = SessionError::decode_bounded(payload, &DecodeConfig::default())
                .map_err(|e| ProtocolClientError::DecodeError(e.to_string()))?;
            let code = SessionErrorCode::try_from(err.code)
                .map_or_else(|_| err.code.to_string(), |c| format!("{c:?}"));
            return Err(ProtocolClientError::DaemonError {
                code,
                message: err.message,
            });
        }

        if tag != SessionMessageType::StreamLogs.tag() {
            return Err(ProtocolClientError::UnexpectedResponse(format!(
                "expected StreamLogs response (tag {}), got tag {tag}",
                SessionMessageType::StreamLogs.tag()
            )));
        }

        StreamLogsResponse::decode_bounded(payload, &DecodeConfig::default())
            .map_err(|e| ProtocolClientError::DecodeError(e.to_string()))
    }

    /// Decodes a `SessionStatus` response (TCK-00344).
    fn decode_session_status_response(
        frame: &Bytes,
    ) -> Result<SessionStatusResponse, ProtocolClientError> {
        if frame.is_empty() {
            return Err(ProtocolClientError::DecodeError("empty frame".to_string()));
        }

        let tag = frame[0];
        let payload = &frame[1..];

        if tag == 0 {
            // Error response
            let err = SessionError::decode_bounded(payload, &DecodeConfig::default())
                .map_err(|e| ProtocolClientError::DecodeError(e.to_string()))?;
            let code = SessionErrorCode::try_from(err.code)
                .map_or_else(|_| err.code.to_string(), |c| format!("{c:?}"));
            return Err(ProtocolClientError::DaemonError {
                code,
                message: err.message,
            });
        }

        if tag != SessionMessageType::SessionStatus.tag() {
            return Err(ProtocolClientError::UnexpectedResponse(format!(
                "expected SessionStatus response (tag {}), got tag {tag}",
                SessionMessageType::SessionStatus.tag()
            )));
        }

        SessionStatusResponse::decode_bounded(payload, &DecodeConfig::default())
            .map_err(|e| ProtocolClientError::DecodeError(e.to_string()))
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_client_error_display() {
        let err = ProtocolClientError::DaemonNotRunning;
        assert_eq!(err.to_string(), "daemon is not running");

        let err = ProtocolClientError::FrameTooLarge { size: 100, max: 50 };
        assert!(err.to_string().contains("100"));
        assert!(err.to_string().contains("50"));

        let err = ProtocolClientError::VersionMismatch {
            client: 1,
            server: 2,
        };
        assert!(err.to_string().contains("client 1"));
        assert!(err.to_string().contains("server 2"));
    }

    #[test]
    fn test_io_error_conversion_not_found() {
        let io_err = io::Error::new(io::ErrorKind::NotFound, "not found");
        let client_err: ProtocolClientError = io_err.into();
        assert!(matches!(client_err, ProtocolClientError::DaemonNotRunning));
    }

    #[test]
    fn test_io_error_conversion_connection_refused() {
        let io_err = io::Error::new(io::ErrorKind::ConnectionRefused, "refused");
        let client_err: ProtocolClientError = io_err.into();
        assert!(matches!(client_err, ProtocolClientError::DaemonNotRunning));
    }

    #[test]
    fn test_io_error_conversion_other() {
        let io_err = io::Error::other("other error");
        let client_err: ProtocolClientError = io_err.into();
        assert!(matches!(client_err, ProtocolClientError::IoError(_)));
    }

    #[test]
    fn test_client_info_version() {
        // Verify the client info contains the package version
        assert!(CLIENT_INFO.starts_with("apm2-cli/"));
    }

    // =========================================================================
    // Operator Socket Routing Tests (IT-00288-01)
    // =========================================================================

    /// Tests that `OperatorClient` uses tag-based protocol frames (not JSON).
    ///
    /// Security invariant [INV-0001]: CLI must never send JSON IPC over
    /// operator.sock/session.sock.
    #[test]
    fn test_operator_socket_routing_no_json_ipc() {
        // OperatorClient encodes requests using encode_* functions which
        // produce tag-prefixed protobuf frames. Verify the encoding pattern.
        let request = ShutdownRequest {
            reason: Some("test".to_string()),
        };
        let encoded = encode_shutdown_request(&request);

        // Tag-based encoding: [tag: u8][protobuf payload]
        // The first byte is the message type tag
        assert!(!encoded.is_empty(), "Encoded message should not be empty");

        // Tag 4 = Shutdown per PrivilegedMessageType
        let tag = encoded[0];
        assert_eq!(
            tag,
            PrivilegedMessageType::Shutdown.tag(),
            "Shutdown request should use correct tag"
        );

        // Payload should be protobuf, not JSON (no '{' character at start)
        if encoded.len() > 1 {
            assert_ne!(
                encoded[1], b'{',
                "Encoded message should be protobuf, not JSON"
            );
        }
    }

    /// Tests that `ClaimWork` requests use tag-based encoding.
    #[test]
    fn test_operator_claim_work_routing() {
        let request = ClaimWorkRequest {
            actor_id: "test-actor".to_string(),
            role: WorkRole::Implementer.into(),
            credential_signature: vec![0u8; 64],
            nonce: vec![1, 2, 3, 4],
        };
        let encoded = encode_claim_work_request(&request);

        assert!(!encoded.is_empty());
        let tag = encoded[0];
        assert_eq!(
            tag,
            PrivilegedMessageType::ClaimWork.tag(),
            "ClaimWork request should use correct tag"
        );
    }

    /// Tests that `ClaimWorkV2` requests use tag-based encoding.
    #[test]
    fn test_operator_claim_work_v2_routing() {
        let request = ClaimWorkV2Request {
            work_id: "W-TCK-00640".to_string(),
            role: WorkRole::Implementer.into(),
            lease_id: "L-governing-001".to_string(),
        };
        let encoded = encode_claim_work_v2_request(&request);

        assert!(!encoded.is_empty());
        let tag = encoded[0];
        assert_eq!(
            tag,
            PrivilegedMessageType::ClaimWorkV2.tag(),
            "ClaimWorkV2 request should use correct tag"
        );
    }

    #[test]
    fn test_decode_claim_work_v2_response_success() {
        let response = ClaimWorkV2Response {
            work_id: "W-TCK-00640".to_string(),
            issued_lease_id: "L-issued-001".to_string(),
            authority_bindings_hash: "b3-256:abcd".to_string(),
            evidence_id: "WAB-001".to_string(),
            already_claimed: false,
        };
        let mut frame = vec![PrivilegedMessageType::ClaimWorkV2.tag()];
        response
            .encode(&mut frame)
            .expect("encode ClaimWorkV2Response");
        let decoded = OperatorClient::decode_claim_work_v2_response(&Bytes::from(frame))
            .expect("decode ClaimWorkV2 response");
        assert_eq!(decoded.work_id, "W-TCK-00640");
        assert_eq!(decoded.issued_lease_id, "L-issued-001");
    }

    #[test]
    fn test_decode_claim_work_v2_response_wrong_tag() {
        let response = ClaimWorkV2Response {
            work_id: "W-TCK-00640".to_string(),
            issued_lease_id: "L-issued-001".to_string(),
            authority_bindings_hash: "b3-256:abcd".to_string(),
            evidence_id: "WAB-001".to_string(),
            already_claimed: false,
        };
        let mut frame = vec![PrivilegedMessageType::OpenWork.tag()];
        response
            .encode(&mut frame)
            .expect("encode ClaimWorkV2Response");
        let err = OperatorClient::decode_claim_work_v2_response(&Bytes::from(frame))
            .expect_err("wrong tag must fail");
        assert!(
            matches!(err, ProtocolClientError::UnexpectedResponse(_)),
            "expected UnexpectedResponse, got {err:?}"
        );
    }

    /// Tests that `SpawnEpisode` requests use tag-based encoding.
    #[test]
    fn test_operator_spawn_episode_routing() {
        let request = SpawnEpisodeRequest {
            work_id: "work-123".to_string(),
            role: WorkRole::Implementer.into(),
            lease_id: Some("lease-456".to_string()),
            workspace_root: "/tmp".to_string(),
            adapter_profile_hash: None,
            max_episodes: None,
            escalation_predicate: None,
            permeability_receipt_hash: None,
        };
        let encoded = encode_spawn_episode_request(&request);

        assert!(!encoded.is_empty());
        let tag = encoded[0];
        assert_eq!(
            tag,
            PrivilegedMessageType::SpawnEpisode.tag(),
            "SpawnEpisode request should use correct tag"
        );
    }

    #[test]
    fn test_operator_pulse_request_tags() {
        let subscribe_request = SubscribePulseRequest {
            session_token: String::new(),
            client_sub_id: "client-sub-1".to_string(),
            topic_patterns: vec!["work.W-123.events".to_string()],
            since_ledger_cursor: 42,
            max_pulses_per_sec: 16,
        };
        let mut subscribe_encoded = vec![PrivilegedMessageType::SubscribePulse.tag()];
        subscribe_request
            .encode(&mut subscribe_encoded)
            .expect("encode subscribe request");
        assert_eq!(
            subscribe_encoded[0],
            PrivilegedMessageType::SubscribePulse.tag()
        );

        let unsubscribe_request = UnsubscribePulseRequest {
            session_token: String::new(),
            subscription_id: "SUB-123".to_string(),
        };
        let mut unsubscribe_encoded = vec![PrivilegedMessageType::UnsubscribePulse.tag()];
        unsubscribe_request
            .encode(&mut unsubscribe_encoded)
            .expect("encode unsubscribe request");
        assert_eq!(
            unsubscribe_encoded[0],
            PrivilegedMessageType::UnsubscribePulse.tag()
        );
    }

    #[test]
    fn test_decode_operator_pulse_frame_subscribe_response() {
        let response = SubscribePulseResponse {
            subscription_id: "SUB-123".to_string(),
            effective_since_cursor: 9,
            accepted_patterns: vec!["work.>".to_string()],
            rejected_patterns: Vec::new(),
        };
        let mut frame = vec![SUBSCRIBE_PULSE_RESPONSE_TAG];
        response
            .encode(&mut frame)
            .expect("encode subscribe response");

        let decoded = OperatorClient::decode_operator_pulse_frame(&Bytes::from(frame))
            .expect("decode subscribe response");
        match decoded {
            OperatorPulseFrame::Subscribe(resp) => {
                assert_eq!(resp.subscription_id, "SUB-123");
                assert_eq!(resp.accepted_patterns, vec!["work.>".to_string()]);
            },
            other => panic!("expected subscribe response, got {other:?}"),
        }
    }

    #[test]
    fn test_decode_operator_pulse_frame_pulse_event() {
        let pulse = PulseEvent {
            envelope: Some(apm2_daemon::protocol::PulseEnvelopeV1 {
                schema_version: 1,
                pulse_id: "pulse-1".to_string(),
                topic: "work.W-123.events".to_string(),
                ledger_cursor: 11,
                ledger_head: 11,
                event_hash: Some(vec![0xAB; 32]),
                event_type: "work.transitioned".to_string(),
                entities: Vec::new(),
                cas_refs: Vec::new(),
                time_envelope_hash: None,
                hlc: None,
                wall: None,
            }),
        };
        let mut frame = vec![PrivilegedMessageType::PulseEvent.tag()];
        pulse.encode(&mut frame).expect("encode pulse event");

        let decoded =
            OperatorClient::decode_operator_pulse_frame(&Bytes::from(frame)).expect("decode pulse");
        match decoded {
            OperatorPulseFrame::Pulse(event) => {
                assert_eq!(
                    event.envelope.as_ref().map(|entry| entry.topic.as_str()),
                    Some("work.W-123.events")
                );
            },
            other => panic!("expected pulse event, got {other:?}"),
        }
    }

    #[test]
    fn test_decode_operator_pulse_frame_daemon_error() {
        let err_payload = PrivilegedError {
            code: PrivilegedErrorCode::PermissionDenied as i32,
            message: "denied".to_string(),
        };
        let mut frame = vec![0];
        err_payload
            .encode(&mut frame)
            .expect("encode privileged error");

        let err = OperatorClient::decode_operator_pulse_frame(&Bytes::from(frame))
            .expect_err("decode should return daemon error");
        match err {
            ProtocolClientError::DaemonError { code, message } => {
                assert!(code.contains("PermissionDenied"));
                assert_eq!(message, "denied");
            },
            other => panic!("expected daemon error, got {other:?}"),
        }
    }

    #[test]
    fn test_operator_pending_pulse_queue_is_bounded() {
        let mut pending = VecDeque::new();

        for idx in 0..(MAX_PENDING_PULSE_EVENTS + 10) {
            let pulse = PulseEvent {
                envelope: Some(apm2_daemon::protocol::PulseEnvelopeV1 {
                    schema_version: 1,
                    pulse_id: format!("pulse-{idx}"),
                    topic: "work.W-123.events".to_string(),
                    ledger_cursor: idx as u64,
                    ledger_head: idx as u64,
                    event_hash: None,
                    event_type: "work.transitioned".to_string(),
                    entities: Vec::new(),
                    cas_refs: Vec::new(),
                    time_envelope_hash: None,
                    hlc: None,
                    wall: None,
                }),
            };
            OperatorClient::enqueue_pending_pulse(&mut pending, pulse);
        }

        assert_eq!(pending.len(), MAX_PENDING_PULSE_EVENTS);
        let oldest = pending
            .front()
            .and_then(|event| event.envelope.as_ref())
            .map(|envelope| envelope.pulse_id.as_str());
        assert_eq!(oldest, Some("pulse-10"));
    }

    // =========================================================================
    // Session Socket Routing Tests (IT-00288-02)
    // =========================================================================

    /// Tests that `SessionClient` uses tag-based protocol frames (not JSON).
    ///
    /// Security invariant [INV-0001]: CLI must never send JSON IPC over
    /// operator.sock/session.sock.
    #[test]
    fn test_session_socket_routing_no_json_ipc() {
        // SessionClient encodes requests using encode_* functions which
        // produce tag-prefixed protobuf frames. Verify the encoding pattern.
        let request = RequestToolRequest {
            session_token: "token-123".to_string(),
            tool_id: "file_read".to_string(),
            arguments: b"{}".to_vec(),
            dedupe_key: "dedupe-1".to_string(),
            epoch_seal: None,
        };
        let encoded = encode_request_tool_request(&request);

        // Tag-based encoding: [tag: u8][protobuf payload]
        assert!(!encoded.is_empty(), "Encoded message should not be empty");

        let tag = encoded[0];
        assert_eq!(
            tag,
            SessionMessageType::RequestTool.tag(),
            "RequestTool should use correct tag"
        );

        // Payload should be protobuf, not JSON
        if encoded.len() > 1 {
            assert_ne!(
                encoded[1], b'{',
                "Encoded message should be protobuf, not JSON"
            );
        }
    }

    /// Tests that `EmitEvent` requests use tag-based encoding.
    #[test]
    fn test_session_emit_event_routing() {
        let request = EmitEventRequest {
            session_token: "token-456".to_string(),
            event_type: "work.started".to_string(),
            payload: b"{}".to_vec(),
            correlation_id: "corr-789".to_string(),
        };
        let encoded = encode_emit_event_request(&request);

        assert!(!encoded.is_empty());
        let tag = encoded[0];
        assert_eq!(
            tag,
            SessionMessageType::EmitEvent.tag(),
            "EmitEvent should use correct tag"
        );
    }

    // =========================================================================
    // Deterministic Exit Code Tests
    // =========================================================================

    /// Tests that error types produce deterministic string representations.
    #[test]
    fn test_error_display_deterministic() {
        // Run multiple times to verify determinism
        for _ in 0..3 {
            let err = ProtocolClientError::DaemonError {
                code: "TEST_CODE".to_string(),
                message: "Test message".to_string(),
            };
            assert_eq!(err.to_string(), "daemon error (TEST_CODE): Test message");
        }
    }

    /// Tests that `DecodeError` conversion from protocol errors is
    /// deterministic.
    #[test]
    fn test_decode_error_deterministic() {
        let err = ProtocolClientError::DecodeError("test decode error".to_string());
        assert_eq!(err.to_string(), "decode error: test decode error");
    }
}
