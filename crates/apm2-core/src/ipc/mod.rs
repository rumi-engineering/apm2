//! IPC (Inter-Process Communication) module.
//!
//! Provides Unix socket-based communication between CLI client and daemon.

use serde::{Deserialize, Serialize};

use crate::credentials::CredentialProfileMetadata;
use crate::process::{ProcessId, ProcessState};

/// IPC request from client to daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum IpcRequest {
    /// Ping the daemon.
    Ping,

    /// Get daemon status.
    Status,

    /// List all processes.
    ListProcesses,

    /// Get process details.
    GetProcess {
        /// Process name.
        name: String,
    },

    /// Start a process.
    StartProcess {
        /// Process name.
        name: String,
    },

    /// Stop a process.
    StopProcess {
        /// Process name.
        name: String,
    },

    /// Restart a process.
    RestartProcess {
        /// Process name.
        name: String,
    },

    /// Graceful reload (rolling restart).
    ReloadProcess {
        /// Process name.
        name: String,
    },

    /// Tail logs.
    TailLogs {
        /// Process name (optional, all if None).
        name: Option<String>,
        /// Number of lines to return.
        lines: u32,
        /// Follow mode (stream new lines).
        follow: bool,
    },

    /// List credential profiles.
    ListCredentials,

    /// Get credential profile details.
    GetCredential {
        /// Profile ID.
        profile_id: String,
    },

    /// Add a credential profile.
    AddCredential {
        /// Profile ID.
        profile_id: String,
        /// Provider name.
        provider: String,
        /// Auth method.
        auth_method: String,
    },

    /// Remove a credential profile.
    RemoveCredential {
        /// Profile ID.
        profile_id: String,
    },

    /// Refresh a credential profile.
    RefreshCredential {
        /// Profile ID.
        profile_id: String,
    },

    /// Switch credentials for a running process.
    SwitchCredential {
        /// Process name.
        process_name: String,
        /// New profile ID.
        profile_id: String,
    },

    /// Shutdown the daemon.
    Shutdown,

    // === Episode management (RFC-0013) ===
    /// Create a new episode from an envelope.
    CreateEpisode {
        /// Envelope content (YAML).
        envelope_yaml: String,
        /// Envelope content hash (BLAKE3, hex-encoded).
        envelope_hash: String,
    },

    /// Start a created episode.
    StartEpisode {
        /// Episode ID to start.
        episode_id: String,
        /// Optional lease ID (daemon may generate if not provided).
        lease_id: Option<String>,
    },

    /// Stop a running episode.
    StopEpisode {
        /// Episode ID to stop.
        episode_id: String,
        /// Stop reason (success, cancelled, failure).
        reason: String,
        /// Optional custom message.
        message: Option<String>,
    },

    /// Get episode status.
    GetEpisodeStatus {
        /// Episode ID to query.
        episode_id: String,
    },

    /// List episodes with optional state filter.
    ListEpisodes {
        /// State filter (all, created, running, terminated, quarantined).
        state_filter: Option<String>,
        /// Maximum number of episodes to return.
        limit: u32,
    },
}

/// IPC response from daemon to client.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum IpcResponse {
    /// Pong response.
    Pong {
        /// Daemon version.
        version: String,
        /// Daemon uptime in seconds.
        uptime_secs: u64,
    },

    /// Daemon status.
    Status {
        /// Daemon version.
        version: String,
        /// Daemon PID.
        pid: u32,
        /// Uptime in seconds.
        uptime_secs: u64,
        /// Number of managed processes.
        process_count: u32,
        /// Number of running instances.
        running_instances: u32,
    },

    /// List of processes.
    ProcessList {
        /// Process summaries.
        processes: Vec<ProcessSummary>,
    },

    /// Single process details.
    ProcessDetails {
        /// Process info.
        process: ProcessInfo,
    },

    /// Operation success.
    Ok {
        /// Optional message.
        message: Option<String>,
    },

    /// Operation error.
    Error {
        /// Error code.
        code: ErrorCode,
        /// Error message.
        message: String,
    },

    /// Log lines.
    LogLines {
        /// Log entries.
        lines: Vec<LogEntry>,
    },

    /// List of credential profiles.
    CredentialList {
        /// Credential profile metadata.
        profiles: Vec<CredentialProfileMetadata>,
    },

    /// Credential profile details.
    CredentialDetails {
        /// Profile metadata.
        profile: CredentialProfileMetadata,
    },

    // === Episode management responses (RFC-0013) ===
    /// Episode created successfully.
    EpisodeCreated {
        /// Created episode ID (daemon-generated).
        episode_id: String,
        /// Envelope hash (BLAKE3, hex-encoded).
        envelope_hash: String,
        /// Creation timestamp (RFC 3339).
        created_at: String,
    },

    /// Episode started successfully.
    EpisodeStarted {
        /// Episode ID.
        episode_id: String,
        /// Session ID for the running episode.
        session_id: String,
        /// Lease ID.
        lease_id: String,
        /// Start timestamp (RFC 3339).
        started_at: String,
    },

    /// Episode stopped successfully.
    EpisodeStopped {
        /// Episode ID.
        episode_id: String,
        /// Termination class (SUCCESS, CANCELLED, FAILURE).
        termination_class: String,
        /// Stop timestamp (RFC 3339).
        stopped_at: String,
    },

    /// Episode status response.
    EpisodeStatus {
        /// Episode ID.
        episode_id: String,
        /// Current state (Created, Running, Terminated, Quarantined).
        state: String,
        /// Envelope hash.
        envelope_hash: String,
        /// Creation timestamp.
        created_at: String,
        /// Start timestamp (if started).
        started_at: Option<String>,
        /// Session ID (if running).
        session_id: Option<String>,
        /// Lease ID (if running).
        lease_id: Option<String>,
        /// Termination timestamp (if terminated).
        terminated_at: Option<String>,
        /// Termination class (if terminated).
        termination_class: Option<String>,
        /// Budget summary (tokens used/total, tool calls, `wall_ms`).
        budget: Option<EpisodeBudgetSummary>,
    },

    /// Episode list response.
    EpisodeList {
        /// List of episode summaries.
        episodes: Vec<EpisodeSummaryIpc>,
        /// Total count (may be more than returned due to limit).
        total: u32,
    },
}

/// Error codes for IPC responses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// Process not found.
    ProcessNotFound,
    /// Process already running.
    ProcessAlreadyRunning,
    /// Process not running.
    ProcessNotRunning,
    /// Credential profile not found.
    CredentialNotFound,
    /// Credential profile already exists.
    CredentialExists,
    /// Invalid request.
    InvalidRequest,
    /// Internal error.
    InternalError,
    /// Operation not supported.
    NotSupported,
    /// Episode not found.
    EpisodeNotFound,
    /// Episode already exists.
    EpisodeExists,
    /// Episode not in expected state for operation.
    InvalidEpisodeState,
    /// Invalid envelope format or content.
    InvalidEnvelope,
}

/// Summary information about a process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessSummary {
    /// Process name.
    pub name: String,
    /// Number of configured instances.
    pub instances: u32,
    /// Number of running instances.
    pub running: u32,
    /// Overall status.
    pub status: ProcessState,
    /// CPU usage (sum of all instances).
    pub cpu_percent: Option<f32>,
    /// Memory usage (sum of all instances).
    pub memory_bytes: Option<u64>,
    /// Uptime of oldest running instance.
    pub uptime_secs: Option<u64>,
    /// Total restart count.
    pub restart_count: u32,
}

/// Detailed information about a process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    /// Process name.
    pub name: String,
    /// Process ID.
    pub id: ProcessId,
    /// Command.
    pub command: String,
    /// Arguments.
    pub args: Vec<String>,
    /// Working directory.
    pub cwd: Option<String>,
    /// Number of configured instances.
    pub instances: u32,
    /// Instance details.
    pub instance_details: Vec<InstanceInfo>,
    /// Bound credential profile.
    pub credential_profile: Option<String>,
}

/// Information about a single process instance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstanceInfo {
    /// Instance index.
    pub index: u32,
    /// OS process ID.
    pub pid: Option<u32>,
    /// Current state.
    pub state: ProcessState,
    /// CPU usage percentage.
    pub cpu_percent: Option<f32>,
    /// Memory usage in bytes.
    pub memory_bytes: Option<u64>,
    /// Uptime in seconds.
    pub uptime_secs: Option<u64>,
    /// Restart count.
    pub restart_count: u32,
}

/// Log entry for streaming.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    /// Timestamp.
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Process name.
    pub process_name: String,
    /// Instance index.
    pub instance: u32,
    /// Stream (stdout/stderr).
    pub stream: String,
    /// Log content.
    pub content: String,
}

// ============================================================================
// Episode management types (RFC-0013)
// ============================================================================

/// Episode summary for list responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
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

/// Budget summary for episode status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpisodeBudgetSummary {
    /// Tokens used / total.
    pub tokens: String,
    /// Tool calls used / total.
    pub tool_calls: String,
    /// Wall time used / total (ms).
    pub wall_ms: String,
}

/// Frame a message for IPC transport.
///
/// Format: 4-byte big-endian length prefix + JSON payload.
#[must_use]
#[allow(clippy::cast_possible_truncation)] // IPC messages won't exceed 4GB
pub fn frame_message(message: &[u8]) -> Vec<u8> {
    let len = message.len() as u32;
    let mut framed = Vec::with_capacity(4 + message.len());
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(message);
    framed
}

/// Parse a framed message length.
///
/// Returns the payload length if a complete length prefix is present.
#[must_use]
pub fn parse_frame_length(buffer: &[u8]) -> Option<usize> {
    if buffer.len() < 4 {
        return None;
    }
    let len = u32::from_be_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]);
    Some(len as usize)
}

/// IPC errors.
#[derive(Debug, thiserror::Error)]
pub enum IpcError {
    /// Connection failed.
    #[error("failed to connect to daemon: {0}")]
    ConnectionFailed(String),

    /// Daemon not running.
    #[error("daemon is not running")]
    DaemonNotRunning,

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Serialization error.
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Protocol error.
    #[error("protocol error: {0}")]
    Protocol(String),

    /// Timeout.
    #[error("operation timed out")]
    Timeout,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_message() {
        let message = b"hello";
        let framed = frame_message(message);

        assert_eq!(framed.len(), 4 + 5);
        assert_eq!(&framed[0..4], &[0, 0, 0, 5]); // Big-endian length
        assert_eq!(&framed[4..], b"hello");
    }

    #[test]
    fn test_parse_frame_length() {
        let framed = frame_message(b"test message");

        assert_eq!(parse_frame_length(&framed), Some(12));
        assert_eq!(parse_frame_length(&[0, 0, 1, 0]), Some(256));
        assert_eq!(parse_frame_length(&[1, 2, 3]), None); // Too short
    }

    #[test]
    fn test_request_serialization() {
        let request = IpcRequest::StartProcess {
            name: "test".to_string(),
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("start_process"));
        assert!(json.contains("test"));

        let parsed: IpcRequest = serde_json::from_str(&json).unwrap();
        match parsed {
            IpcRequest::StartProcess { name } => assert_eq!(name, "test"),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_response_serialization() {
        let response = IpcResponse::Ok {
            message: Some("Process started".to_string()),
        };

        let json = serde_json::to_string(&response).unwrap();
        let parsed: IpcResponse = serde_json::from_str(&json).unwrap();

        match parsed {
            IpcResponse::Ok { message } => assert_eq!(message, Some("Process started".to_string())),
            _ => panic!("wrong variant"),
        }
    }
}
