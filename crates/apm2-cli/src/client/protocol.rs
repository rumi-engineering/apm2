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

use std::io;
use std::path::Path;
use std::time::Duration;

use apm2_daemon::protocol::{
    // Message decoding
    BoundedDecode,
    // Capability request
    CapabilityRequest,
    // Privileged endpoint messages
    ClaimWorkRequest,
    ClaimWorkResponse,
    // Handshake
    ClientHandshake,
    DecodeConfig,
    EmitEventRequest,
    EmitEventResponse,
    // Framing
    FrameCodec,
    HandshakeMessage,
    IssueCapabilityRequest,
    IssueCapabilityResponse,
    // TCK-00342: Process management types
    ListProcessesRequest,
    ListProcessesResponse,
    PrivilegedError,
    PrivilegedErrorCode,
    PrivilegedMessageType,
    ProcessStatusRequest,
    ProcessStatusResponse,
    // Error types
    ProtocolError,
    // Evidence publishing
    PublishEvidenceRequest,
    PublishEvidenceResponse,
    ReloadProcessRequest,
    ReloadProcessResponse,
    // Session endpoint messages
    RequestToolRequest,
    RequestToolResponse,
    RestartProcessRequest,
    RestartProcessResponse,
    SessionError,
    SessionErrorCode,
    SessionMessageType,
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
    // Work types
    WorkRole,
    encode_claim_work_request,
    encode_emit_event_request,
    encode_issue_capability_request,
    // TCK-00342: Process management encoding
    encode_list_processes_request,
    encode_process_status_request,
    encode_publish_evidence_request,
    encode_reload_process_request,
    encode_request_tool_request,
    encode_restart_process_request,
    encode_shutdown_request,
    encode_spawn_episode_request,
    encode_start_process_request,
    encode_stop_process_request,
    // TCK-00342: Log streaming encoding
    encode_stream_logs_request,
    parse_handshake_message,
    serialize_handshake_message,
};
use bytes::Bytes;
use futures::{SinkExt, StreamExt};
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
    /// Server info from handshake (reserved for future use in diagnostics).
    #[allow(dead_code)]
    server_info: String,
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
        let server_info = Self::perform_handshake(&mut framed, timeout).await?;

        Ok(Self {
            framed,
            server_info,
            timeout,
        })
    }

    /// Performs the Hello/HelloAck handshake.
    async fn perform_handshake(
        framed: &mut Framed<UnixStream, FrameCodec>,
        timeout: Duration,
    ) -> Result<String, ProtocolClientError> {
        let mut client_handshake = ClientHandshake::new(CLIENT_INFO);

        // Send Hello
        let hello = client_handshake.create_hello();
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

        Ok(client_handshake
            .server_info()
            .unwrap_or("unknown")
            .to_string())
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
    pub async fn spawn_episode(
        &mut self,
        work_id: &str,
        role: WorkRole,
        lease_id: Option<&str>,
        workspace_root: &str,
    ) -> Result<SpawnEpisodeResponse, ProtocolClientError> {
        let request = SpawnEpisodeRequest {
            work_id: work_id.to_string(),
            role: role.into(),
            lease_id: lease_id.map(String::from),
            workspace_root: workspace_root.to_string(),
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
        let server_info = OperatorClient::perform_handshake(&mut framed, timeout).await?;

        Ok(Self {
            framed,
            server_info,
            timeout,
        })
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

    /// Tests that `SpawnEpisode` requests use tag-based encoding.
    #[test]
    fn test_operator_spawn_episode_routing() {
        let request = SpawnEpisodeRequest {
            work_id: "work-123".to_string(),
            role: WorkRole::Implementer.into(),
            lease_id: Some("lease-456".to_string()),
            workspace_root: "/tmp".to_string(),
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
