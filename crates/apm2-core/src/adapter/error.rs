//! Error types for adapter operations.

use std::path::PathBuf;

use thiserror::Error;

/// Errors that can occur during adapter operations.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AdapterError {
    /// Failed to spawn the agent process.
    #[error("failed to spawn process: {0}")]
    SpawnFailed(String),

    /// Process exited unexpectedly.
    #[error("process exited unexpectedly: exit_code={exit_code:?}, signal={signal:?}")]
    UnexpectedExit {
        /// Exit code if available.
        exit_code: Option<i32>,
        /// Signal if available.
        signal: Option<i32>,
    },

    /// Filesystem watcher error.
    #[error("filesystem watcher error: {0}")]
    WatcherError(String),

    /// Failed to watch a path.
    #[error("failed to watch path {path}: {reason}")]
    WatchPathFailed {
        /// The path that failed to be watched.
        path: PathBuf,
        /// Reason for failure.
        reason: String,
    },

    /// Configuration error.
    #[error("configuration error: {0}")]
    ConfigError(String),

    /// Session not found.
    #[error("session not found: {0}")]
    SessionNotFound(String),

    /// Session already exists.
    #[error("session already exists: {0}")]
    SessionExists(String),

    /// Adapter is not running.
    #[error("adapter is not running")]
    NotRunning,

    /// Adapter is already running.
    #[error("adapter is already running")]
    AlreadyRunning,

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Channel send error.
    #[error("channel send error: {0}")]
    ChannelSend(String),

    /// Channel receive error.
    #[error("channel receive error: {0}")]
    ChannelRecv(String),

    /// Internal error.
    #[error("internal error: {0}")]
    Internal(String),

    /// Seccomp filter failed to apply.
    #[error("seccomp filter failed: {0}")]
    SeccompFailed(String),
}

impl AdapterError {
    /// Returns `true` if this is a transient error that may succeed on retry.
    #[must_use]
    pub const fn is_transient(&self) -> bool {
        matches!(
            self,
            Self::WatcherError(_) | Self::ChannelSend(_) | Self::ChannelRecv(_)
        )
    }

    /// Returns `true` if this is a fatal error that requires restart.
    #[must_use]
    pub const fn is_fatal(&self) -> bool {
        matches!(
            self,
            Self::SpawnFailed(_)
                | Self::ConfigError(_)
                | Self::Internal(_)
                | Self::SeccompFailed(_)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = AdapterError::SpawnFailed("command not found".to_string());
        assert_eq!(
            err.to_string(),
            "failed to spawn process: command not found"
        );

        let err = AdapterError::UnexpectedExit {
            exit_code: Some(1),
            signal: None,
        };
        assert_eq!(
            err.to_string(),
            "process exited unexpectedly: exit_code=Some(1), signal=None"
        );

        let err = AdapterError::WatchPathFailed {
            path: PathBuf::from("/tmp/test"),
            reason: "permission denied".to_string(),
        };
        assert_eq!(
            err.to_string(),
            "failed to watch path /tmp/test: permission denied"
        );
    }

    #[test]
    fn test_is_transient() {
        assert!(AdapterError::WatcherError("timeout".to_string()).is_transient());
        assert!(AdapterError::ChannelSend("closed".to_string()).is_transient());
        assert!(!AdapterError::SpawnFailed("not found".to_string()).is_transient());
    }

    #[test]
    fn test_is_fatal() {
        assert!(AdapterError::SpawnFailed("not found".to_string()).is_fatal());
        assert!(AdapterError::ConfigError("invalid".to_string()).is_fatal());
        assert!(!AdapterError::WatcherError("timeout".to_string()).is_fatal());
    }
}
