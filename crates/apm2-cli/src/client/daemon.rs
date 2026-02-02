//! Daemon client for UDS communication.
//!
//! This module provides the client-side implementation for communicating with
//! the apm2 daemon via Unix domain sockets.
//!
//! # TCK-00281: Legacy JSON IPC Removed
//!
//! Per DD-009 (RFC-0017), legacy JSON IPC has been removed from the daemon.
//! The CLI must be migrated to use protobuf-based communication in a
//! subsequent ticket. Until then, all daemon communication methods return
//! an error indicating the migration is pending.
//!
//! # Contract References
//!
//! - AD-DAEMON-002: UDS transport with length-prefixed framing
//! - DD-009: `ProtocolServer`-only control plane (JSON IPC removed)

use std::path::Path;
use std::time::Duration;

/// Maximum frame size for IPC messages (16 MiB per AD-DAEMON-002).
#[allow(dead_code)]
pub const MAX_FRAME_SIZE: usize = 16 * 1024 * 1024;

/// Default connection timeout.
pub const DEFAULT_TIMEOUT_SECS: u64 = 30;

/// Daemon client for episode operations.
///
/// # TCK-00281: Stub Implementation
///
/// This client is currently a stub. Legacy JSON IPC has been removed per
/// DD-009. The CLI must be migrated to protobuf-based communication.
pub struct DaemonClient<'a> {
    #[allow(dead_code)]
    socket_path: &'a Path,
    timeout: Duration,
}

/// Error type for daemon client operations.
#[derive(Debug)]
#[allow(dead_code)]
pub enum DaemonClientError {
    /// Daemon is not running (socket does not exist).
    DaemonNotRunning,
    /// Connection failed.
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
    /// Protocol migration required (TCK-00281).
    ProtocolMigrationRequired,
}

/// Error codes for daemon responses.
///
/// TCK-00281: This is a minimal subset of error codes retained for CLI
/// error handling until the CLI is migrated to protobuf.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum ErrorCode {
    /// Episode not found.
    EpisodeNotFound,
    /// Invalid request.
    InvalidRequest,
    /// Internal error.
    InternalError,
    /// Not supported (legacy JSON IPC removed).
    NotSupported,
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
            Self::ProtocolMigrationRequired => write!(
                f,
                "CLI requires protobuf migration (DD-009). Legacy JSON IPC has been removed."
            ),
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
#[allow(dead_code)]
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
#[allow(dead_code)]
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
#[allow(dead_code)]
pub struct StopEpisodeResponse {
    /// Episode ID.
    pub episode_id: String,
    /// Termination class (SUCCESS, CANCELLED, FAILURE).
    pub termination_class: String,
    /// Stop timestamp (RFC 3339).
    pub stopped_at: String,
}

/// Budget summary for episode status.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct EpisodeBudgetSummary {
    /// Tokens used / total.
    pub tokens: String,
    /// Tool calls used / total.
    pub tool_calls: String,
    /// Wall time used / total (ms).
    pub wall_ms: String,
}

/// Response from episode status operation.
#[derive(Debug, Clone)]
#[allow(dead_code)]
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

/// Episode summary for list responses.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct EpisodeSummaryIpc {
    /// Episode ID.
    pub episode_id: String,
    /// Current state.
    pub state: String,
    /// Creation timestamp.
    pub created_at: String,
    /// Session ID (if running).
    pub session_id: Option<String>,
}

/// Response from episode list operation.
#[derive(Debug, Clone)]
#[allow(dead_code)]
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
    #[allow(dead_code)]
    pub const fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Checks if the daemon is running (socket exists).
    #[must_use]
    #[allow(dead_code)]
    pub fn is_daemon_running(&self) -> bool {
        self.socket_path.exists()
    }

    /// Creates a new episode from an envelope.
    ///
    /// # TCK-00281: Stub
    ///
    /// Returns an error indicating protobuf migration is required.
    #[allow(clippy::unused_self)]
    pub const fn create_episode(
        &self,
        _envelope_yaml: &str,
        _envelope_hash: &str,
    ) -> Result<CreateEpisodeResponse, DaemonClientError> {
        Err(DaemonClientError::ProtocolMigrationRequired)
    }

    /// Starts a created episode.
    ///
    /// # TCK-00281: Stub
    ///
    /// Returns an error indicating protobuf migration is required.
    #[allow(clippy::unused_self)]
    pub const fn start_episode(
        &self,
        _episode_id: &str,
        _lease_id: Option<&str>,
    ) -> Result<StartEpisodeResponse, DaemonClientError> {
        Err(DaemonClientError::ProtocolMigrationRequired)
    }

    /// Stops a running episode.
    ///
    /// # TCK-00281: Stub
    ///
    /// Returns an error indicating protobuf migration is required.
    #[allow(clippy::unused_self)]
    pub const fn stop_episode(
        &self,
        _episode_id: &str,
        _reason: &str,
        _message: Option<&str>,
    ) -> Result<StopEpisodeResponse, DaemonClientError> {
        Err(DaemonClientError::ProtocolMigrationRequired)
    }

    /// Gets the status of an episode.
    ///
    /// # TCK-00281: Stub
    ///
    /// Returns an error indicating protobuf migration is required.
    #[allow(clippy::unused_self)]
    pub const fn get_episode_status(
        &self,
        _episode_id: &str,
    ) -> Result<EpisodeStatusResponse, DaemonClientError> {
        Err(DaemonClientError::ProtocolMigrationRequired)
    }

    /// Lists episodes with optional state filter.
    ///
    /// # TCK-00281: Stub
    ///
    /// Returns an error indicating protobuf migration is required.
    #[allow(clippy::unused_self)]
    pub const fn list_episodes(
        &self,
        _state_filter: Option<&str>,
        _limit: u32,
    ) -> Result<ListEpisodesResponse, DaemonClientError> {
        Err(DaemonClientError::ProtocolMigrationRequired)
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

        let err = DaemonClientError::ProtocolMigrationRequired;
        assert!(err.to_string().contains("protobuf migration"));
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

    #[test]
    fn test_stub_methods_return_migration_required() {
        let path = Path::new("/tmp/test.sock");
        let client = DaemonClient::new(path);

        assert!(matches!(
            client.create_episode("", ""),
            Err(DaemonClientError::ProtocolMigrationRequired)
        ));
        assert!(matches!(
            client.start_episode("", None),
            Err(DaemonClientError::ProtocolMigrationRequired)
        ));
        assert!(matches!(
            client.stop_episode("", "", None),
            Err(DaemonClientError::ProtocolMigrationRequired)
        ));
        assert!(matches!(
            client.get_episode_status(""),
            Err(DaemonClientError::ProtocolMigrationRequired)
        ));
        assert!(matches!(
            client.list_episodes(None, 10),
            Err(DaemonClientError::ProtocolMigrationRequired)
        ));
    }
}
