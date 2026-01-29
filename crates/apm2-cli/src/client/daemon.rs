//! Daemon client for UDS communication.
//!
//! This module provides the client-side implementation for communicating with
//! the apm2 daemon via Unix domain sockets per AD-DAEMON-002.
//!
//! # Protocol
//!
//! - Transport: Unix domain socket at `${XDG_RUNTIME_DIR}/apm2/apm2d.sock`
//! - Framing: Length-prefixed (4-byte big-endian) JSON messages
//! - Pattern: Request-response (stateless per connection)
//!
//! # Contract References
//!
//! - AD-DAEMON-002: UDS transport with length-prefixed framing
//! - CTR-1601: Protocol framing is a first-class contract
//! - CTR-1603: Bounded reads with max frame size

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use apm2_core::ipc::{
    EpisodeBudgetSummary, EpisodeSummaryIpc, ErrorCode, IpcRequest, IpcResponse, frame_message,
};

/// Maximum frame size for IPC messages (16 MiB per AD-DAEMON-002).
pub const MAX_FRAME_SIZE: usize = 16 * 1024 * 1024;

/// Default connection timeout.
pub const DEFAULT_TIMEOUT_SECS: u64 = 30;

/// Daemon client for episode operations.
///
/// Provides a high-level interface for communicating with the apm2 daemon.
/// Each operation is stateless (connect, request, response, close).
pub struct DaemonClient<'a> {
    socket_path: &'a Path,
    timeout: Duration,
}

/// Error type for daemon client operations.
#[derive(Debug)]
pub enum DaemonClientError {
    /// Daemon is not running (socket does not exist).
    DaemonNotRunning,
    /// Connection failed.
    #[allow(dead_code)] // Used in error handling path for future connection scenarios
    ConnectionFailed(String),
    /// I/O error during communication.
    IoError(std::io::Error),
    /// Frame too large.
    FrameTooLarge { size: usize, max: usize },
    /// Serialization/deserialization error.
    SerdeError(String),
    /// Daemon returned an error response.
    DaemonError { code: ErrorCode, message: String },
    /// Unexpected response type.
    UnexpectedResponse(String),
}

impl std::fmt::Display for DaemonClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DaemonNotRunning => write!(f, "daemon is not running"),
            Self::ConnectionFailed(msg) => write!(f, "connection failed: {msg}"),
            Self::IoError(e) => write!(f, "I/O error: {e}"),
            Self::FrameTooLarge { size, max } => {
                write!(f, "frame too large: {size} bytes (max: {max})")
            },
            Self::SerdeError(msg) => write!(f, "serialization error: {msg}"),
            Self::DaemonError { code, message } => {
                write!(f, "daemon error ({code:?}): {message}")
            },
            Self::UnexpectedResponse(msg) => write!(f, "unexpected response: {msg}"),
        }
    }
}

impl std::error::Error for DaemonClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::IoError(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for DaemonClientError {
    fn from(err: std::io::Error) -> Self {
        if err.kind() == std::io::ErrorKind::NotFound
            || err.kind() == std::io::ErrorKind::ConnectionRefused
        {
            Self::DaemonNotRunning
        } else {
            Self::IoError(err)
        }
    }
}

/// Response from episode create operation.
#[derive(Debug, Clone)]
pub struct CreateEpisodeResponse {
    /// Daemon-generated episode ID.
    pub episode_id: String,
    /// Envelope hash (BLAKE3, hex-encoded).
    pub envelope_hash: String,
    /// Creation timestamp (RFC 3339).
    pub created_at: String,
}

/// Response from episode start operation.
#[derive(Debug, Clone)]
pub struct StartEpisodeResponse {
    /// Episode ID.
    pub episode_id: String,
    /// Session ID for the running episode.
    pub session_id: String,
    /// Lease ID.
    pub lease_id: String,
    /// Start timestamp (RFC 3339).
    pub started_at: String,
}

/// Response from episode stop operation.
#[derive(Debug, Clone)]
pub struct StopEpisodeResponse {
    /// Episode ID.
    pub episode_id: String,
    /// Termination class (SUCCESS, CANCELLED, FAILURE).
    pub termination_class: String,
    /// Stop timestamp (RFC 3339).
    pub stopped_at: String,
}

/// Response from episode status operation.
#[derive(Debug, Clone)]
pub struct EpisodeStatusResponse {
    /// Episode ID.
    pub episode_id: String,
    /// Current state.
    pub state: String,
    /// Envelope hash.
    pub envelope_hash: String,
    /// Creation timestamp.
    pub created_at: String,
    /// Start timestamp (if started).
    pub started_at: Option<String>,
    /// Session ID (if running).
    pub session_id: Option<String>,
    /// Lease ID (if running).
    pub lease_id: Option<String>,
    /// Termination timestamp (if terminated).
    pub terminated_at: Option<String>,
    /// Termination class (if terminated).
    pub termination_class: Option<String>,
    /// Budget summary.
    pub budget: Option<EpisodeBudgetSummary>,
}

/// Response from episode list operation.
#[derive(Debug, Clone)]
pub struct ListEpisodesResponse {
    /// Episode summaries.
    pub episodes: Vec<EpisodeSummaryIpc>,
    /// Total count.
    pub total: u32,
}

impl<'a> DaemonClient<'a> {
    /// Creates a new daemon client.
    ///
    /// # Arguments
    ///
    /// * `socket_path` - Path to the daemon Unix socket.
    #[must_use]
    pub const fn new(socket_path: &'a Path) -> Self {
        Self {
            socket_path,
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
        }
    }

    /// Sets the connection timeout.
    #[must_use]
    #[allow(dead_code)] // Public API for future use
    pub const fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Checks if the daemon is running (socket exists).
    #[must_use]
    #[allow(dead_code)] // Public API for future use
    pub fn is_daemon_running(&self) -> bool {
        self.socket_path.exists()
    }

    /// Creates a new episode from an envelope.
    ///
    /// # Arguments
    ///
    /// * `envelope_yaml` - The envelope YAML content.
    /// * `envelope_hash` - BLAKE3 hash of the envelope (hex-encoded).
    ///
    /// # Returns
    ///
    /// The daemon-generated episode ID and metadata.
    pub fn create_episode(
        &self,
        envelope_yaml: &str,
        envelope_hash: &str,
    ) -> Result<CreateEpisodeResponse, DaemonClientError> {
        let request = IpcRequest::CreateEpisode {
            envelope_yaml: envelope_yaml.to_string(),
            envelope_hash: envelope_hash.to_string(),
        };

        let response = self.send_request(&request)?;

        match response {
            IpcResponse::EpisodeCreated {
                episode_id,
                envelope_hash,
                created_at,
            } => Ok(CreateEpisodeResponse {
                episode_id,
                envelope_hash,
                created_at,
            }),
            IpcResponse::Error { code, message } => {
                Err(DaemonClientError::DaemonError { code, message })
            },
            other => Err(DaemonClientError::UnexpectedResponse(format!(
                "expected EpisodeCreated, got {other:?}"
            ))),
        }
    }

    /// Starts a created episode.
    ///
    /// # Arguments
    ///
    /// * `episode_id` - The episode ID to start.
    /// * `lease_id` - Optional lease ID (daemon generates if not provided).
    pub fn start_episode(
        &self,
        episode_id: &str,
        lease_id: Option<&str>,
    ) -> Result<StartEpisodeResponse, DaemonClientError> {
        let request = IpcRequest::StartEpisode {
            episode_id: episode_id.to_string(),
            lease_id: lease_id.map(String::from),
        };

        let response = self.send_request(&request)?;

        match response {
            IpcResponse::EpisodeStarted {
                episode_id,
                session_id,
                lease_id,
                started_at,
            } => Ok(StartEpisodeResponse {
                episode_id,
                session_id,
                lease_id,
                started_at,
            }),
            IpcResponse::Error { code, message } => {
                Err(DaemonClientError::DaemonError { code, message })
            },
            other => Err(DaemonClientError::UnexpectedResponse(format!(
                "expected EpisodeStarted, got {other:?}"
            ))),
        }
    }

    /// Stops a running episode.
    ///
    /// # Arguments
    ///
    /// * `episode_id` - The episode ID to stop.
    /// * `reason` - Stop reason (success, cancelled, failure).
    /// * `message` - Optional custom message.
    pub fn stop_episode(
        &self,
        episode_id: &str,
        reason: &str,
        message: Option<&str>,
    ) -> Result<StopEpisodeResponse, DaemonClientError> {
        let request = IpcRequest::StopEpisode {
            episode_id: episode_id.to_string(),
            reason: reason.to_string(),
            message: message.map(String::from),
        };

        let response = self.send_request(&request)?;

        match response {
            IpcResponse::EpisodeStopped {
                episode_id,
                termination_class,
                stopped_at,
            } => Ok(StopEpisodeResponse {
                episode_id,
                termination_class,
                stopped_at,
            }),
            IpcResponse::Error { code, message } => {
                Err(DaemonClientError::DaemonError { code, message })
            },
            other => Err(DaemonClientError::UnexpectedResponse(format!(
                "expected EpisodeStopped, got {other:?}"
            ))),
        }
    }

    /// Gets the status of an episode.
    ///
    /// # Arguments
    ///
    /// * `episode_id` - The episode ID to query.
    pub fn get_episode_status(
        &self,
        episode_id: &str,
    ) -> Result<EpisodeStatusResponse, DaemonClientError> {
        let request = IpcRequest::GetEpisodeStatus {
            episode_id: episode_id.to_string(),
        };

        let response = self.send_request(&request)?;

        match response {
            IpcResponse::EpisodeStatus {
                episode_id,
                state,
                envelope_hash,
                created_at,
                started_at,
                session_id,
                lease_id,
                terminated_at,
                termination_class,
                budget,
            } => Ok(EpisodeStatusResponse {
                episode_id,
                state,
                envelope_hash,
                created_at,
                started_at,
                session_id,
                lease_id,
                terminated_at,
                termination_class,
                budget,
            }),
            IpcResponse::Error { code, message } => {
                Err(DaemonClientError::DaemonError { code, message })
            },
            other => Err(DaemonClientError::UnexpectedResponse(format!(
                "expected EpisodeStatus, got {other:?}"
            ))),
        }
    }

    /// Lists episodes with optional state filter.
    ///
    /// # Arguments
    ///
    /// * `state_filter` - Optional state filter (all, created, running,
    ///   terminated, quarantined).
    /// * `limit` - Maximum number of episodes to return.
    pub fn list_episodes(
        &self,
        state_filter: Option<&str>,
        limit: u32,
    ) -> Result<ListEpisodesResponse, DaemonClientError> {
        let request = IpcRequest::ListEpisodes {
            state_filter: state_filter.map(String::from),
            limit,
        };

        let response = self.send_request(&request)?;

        match response {
            IpcResponse::EpisodeList { episodes, total } => {
                Ok(ListEpisodesResponse { episodes, total })
            },
            IpcResponse::Error { code, message } => {
                Err(DaemonClientError::DaemonError { code, message })
            },
            other => Err(DaemonClientError::UnexpectedResponse(format!(
                "expected EpisodeList, got {other:?}"
            ))),
        }
    }

    /// Sends an IPC request and receives a response.
    ///
    /// Per AD-DAEMON-002: UDS transport with length-prefixed framing.
    /// Per CTR-1603: Bounded reads with max frame size.
    fn send_request(&self, request: &IpcRequest) -> Result<IpcResponse, DaemonClientError> {
        // Check if daemon is running before attempting connection
        if !self.socket_path.exists() {
            return Err(DaemonClientError::DaemonNotRunning);
        }

        // Connect to daemon socket
        let mut stream = UnixStream::connect(self.socket_path)?;
        stream.set_read_timeout(Some(self.timeout))?;
        stream.set_write_timeout(Some(self.timeout))?;

        // Serialize and frame request
        let request_json = serde_json::to_vec(request)
            .map_err(|e| DaemonClientError::SerdeError(e.to_string()))?;

        if request_json.len() > MAX_FRAME_SIZE {
            return Err(DaemonClientError::FrameTooLarge {
                size: request_json.len(),
                max: MAX_FRAME_SIZE,
            });
        }

        let framed = frame_message(&request_json);
        stream.write_all(&framed)?;

        // Read response length prefix (4 bytes, big-endian)
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf)?;
        let response_len = u32::from_be_bytes(len_buf) as usize;

        // Validate response size (CTR-1603: bounded reads)
        if response_len > MAX_FRAME_SIZE {
            return Err(DaemonClientError::FrameTooLarge {
                size: response_len,
                max: MAX_FRAME_SIZE,
            });
        }

        // Read response body
        let mut response_buf = vec![0u8; response_len];
        stream.read_exact(&mut response_buf)?;

        // Deserialize response
        let response: IpcResponse = serde_json::from_slice(&response_buf)
            .map_err(|e| DaemonClientError::SerdeError(e.to_string()))?;

        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_daemon_client_error_display() {
        let err = DaemonClientError::DaemonNotRunning;
        assert_eq!(err.to_string(), "daemon is not running");

        let err = DaemonClientError::FrameTooLarge { size: 100, max: 50 };
        assert!(err.to_string().contains("100"));
        assert!(err.to_string().contains("50"));

        let err = DaemonClientError::DaemonError {
            code: ErrorCode::EpisodeNotFound,
            message: "not found".to_string(),
        };
        assert!(err.to_string().contains("not found"));
    }

    #[test]
    fn test_daemon_client_new() {
        let path = Path::new("/tmp/test.sock");
        let client = DaemonClient::new(path);
        assert_eq!(client.timeout, Duration::from_secs(DEFAULT_TIMEOUT_SECS));
    }

    #[test]
    fn test_daemon_client_with_timeout() {
        let path = Path::new("/tmp/test.sock");
        let client = DaemonClient::new(path).with_timeout(Duration::from_secs(60));
        assert_eq!(client.timeout, Duration::from_secs(60));
    }

    #[test]
    fn test_is_daemon_running_false() {
        let path = Path::new("/nonexistent/socket.sock");
        let client = DaemonClient::new(path);
        assert!(!client.is_daemon_running());
    }

    #[test]
    fn test_io_error_conversion_not_found() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "not found");
        let client_err: DaemonClientError = io_err.into();
        assert!(matches!(client_err, DaemonClientError::DaemonNotRunning));
    }

    #[test]
    fn test_io_error_conversion_other() {
        let io_err = std::io::Error::other("other error");
        let client_err: DaemonClientError = io_err.into();
        assert!(matches!(client_err, DaemonClientError::IoError(_)));
    }
}
