//! `HarnessAdapter` trait and related types.
//!
//! This module defines the [`HarnessAdapter`] trait that normalizes behavior
//! across different agent harnesses (Claude Code, raw processes, etc.).
//!
//! # Design
//!
//! Per CTR-DAEMON-003, the `HarnessAdapter` trait provides a unified interface
//! for spawning and managing agent processes. Different adapters implement
//! harness-specific parsing and event emission logic.
//!
//! # Adapter Types
//!
//! - [`AdapterType::Raw`]: Baseline adapter that emits unstructured output
//! - [`AdapterType::ClaudeCode`]: (Future) Claude Code-specific parsing
//!
//! # Example
//!
//! ```rust,ignore
//! use apm2_daemon::episode::adapter::{AdapterType, HarnessAdapter, HarnessConfig};
//!
//! let adapter = registry.get(AdapterType::Raw)?;
//! let handle = adapter.spawn(config, pty_handle).await?;
//! let mut events = adapter.output_stream(&handle);
//!
//! while let Some(event) = events.next().await {
//!     match event {
//!         HarnessEvent::Output { chunk, .. } => { /* handle output */ }
//!         HarnessEvent::Terminated { exit_code, .. } => break,
//!         _ => {}
//!     }
//! }
//! ```

use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;
use std::pin::Pin;
use std::process::ExitStatus;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::mpsc;

/// Type alias for a boxed stream of harness events.
///
/// This uses a channel receiver as the underlying stream type, which is
/// more practical for our use case than a trait object stream.
pub type HarnessEventStream = mpsc::Receiver<HarnessEvent>;

/// Errors that can occur during adapter operations.
#[derive(Debug, Error)]
pub enum AdapterError {
    /// Failed to spawn the process.
    #[error("spawn failed: {reason}")]
    SpawnFailed {
        /// Description of the spawn failure.
        reason: String,
    },

    /// Failed to send input to the process.
    #[error("input failed: {reason}")]
    InputFailed {
        /// Description of the input failure.
        reason: String,
    },

    /// Failed to terminate the process.
    #[error("termination failed: {reason}")]
    TerminateFailed {
        /// Description of the termination failure.
        reason: String,
    },

    /// Handle is invalid or refers to a terminated process.
    #[error("invalid handle: {reason}")]
    InvalidHandle {
        /// Description of why the handle is invalid.
        reason: String,
    },

    /// I/O error during adapter operation.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

impl AdapterError {
    /// Create a spawn failed error.
    #[must_use]
    pub fn spawn_failed(reason: impl Into<String>) -> Self {
        Self::SpawnFailed {
            reason: reason.into(),
        }
    }

    /// Create an input failed error.
    #[must_use]
    pub fn input_failed(reason: impl Into<String>) -> Self {
        Self::InputFailed {
            reason: reason.into(),
        }
    }

    /// Create a termination failed error.
    #[must_use]
    pub fn terminate_failed(reason: impl Into<String>) -> Self {
        Self::TerminateFailed {
            reason: reason.into(),
        }
    }

    /// Create an invalid handle error.
    #[must_use]
    pub fn invalid_handle(reason: impl Into<String>) -> Self {
        Self::InvalidHandle {
            reason: reason.into(),
        }
    }
}

/// Result type for adapter operations.
pub type AdapterResult<T> = Result<T, AdapterError>;

/// Type of harness adapter.
///
/// Identifies which adapter implementation to use for a given harness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum AdapterType {
    /// Raw adapter that emits unstructured output.
    ///
    /// Does not parse tool calls or structured events - all PTY output
    /// is emitted as raw Output events.
    Raw,

    /// Claude Code adapter with structured event parsing.
    ///
    /// Parses Claude Code's output format to emit structured events
    /// including tool requests and progress updates.
    ClaudeCode,
}

impl fmt::Display for AdapterType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Raw => write!(f, "raw"),
            Self::ClaudeCode => write!(f, "claude_code"),
        }
    }
}

/// Configuration for spawning a harness process.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HarnessConfig {
    /// Command to execute.
    pub command: String,

    /// Command arguments.
    #[serde(default)]
    pub args: Vec<String>,

    /// Working directory for the process.
    #[serde(default)]
    pub cwd: Option<PathBuf>,

    /// Environment variables to set.
    #[serde(default)]
    pub env: HashMap<String, String>,

    /// PTY dimensions (columns, rows).
    #[serde(default = "default_pty_size")]
    pub pty_size: (u16, u16),

    /// Episode ID for tracking.
    pub episode_id: String,
}

/// Default PTY size (80x24).
const fn default_pty_size() -> (u16, u16) {
    (80, 24)
}

impl HarnessConfig {
    /// Create a new harness configuration.
    #[must_use]
    pub fn new(command: impl Into<String>, episode_id: impl Into<String>) -> Self {
        Self {
            command: command.into(),
            args: Vec::new(),
            cwd: None,
            env: HashMap::new(),
            pty_size: default_pty_size(),
            episode_id: episode_id.into(),
        }
    }

    /// Add command arguments.
    #[must_use]
    pub fn with_args(mut self, args: Vec<String>) -> Self {
        self.args = args;
        self
    }

    /// Set working directory.
    #[must_use]
    pub fn with_cwd(mut self, cwd: impl Into<PathBuf>) -> Self {
        self.cwd = Some(cwd.into());
        self
    }

    /// Set environment variable.
    #[must_use]
    pub fn with_env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.insert(key.into(), value.into());
        self
    }

    /// Set PTY dimensions.
    #[must_use]
    pub const fn with_pty_size(mut self, cols: u16, rows: u16) -> Self {
        self.pty_size = (cols, rows);
        self
    }
}

/// Handle to a running harness process.
///
/// This opaque handle is used to interact with a spawned process through
/// the adapter interface. The handle contains internal state that the
/// adapter uses to manage the process lifecycle.
#[derive(Debug)]
pub struct HarnessHandle {
    /// Unique handle ID.
    pub(crate) id: u64,

    /// Episode ID for tracking.
    pub(crate) episode_id: String,

    /// Adapter-specific internal state.
    ///
    /// The actual type depends on the adapter implementation.
    /// This field will be used when PTY integration is implemented.
    #[allow(dead_code)]
    pub(crate) inner: HarnessHandleInner,
}

/// Adapter-specific handle state.
#[derive(Debug)]
pub enum HarnessHandleInner {
    /// Placeholder for adapters not yet implemented.
    Placeholder,
}

impl HarnessHandle {
    /// Create a new harness handle.
    #[allow(clippy::missing_const_for_fn)] // String param prevents const fn on stable
    pub(crate) fn new(id: u64, episode_id: String, inner: HarnessHandleInner) -> Self {
        Self {
            id,
            episode_id,
            inner,
        }
    }

    /// Returns the handle ID.
    #[must_use]
    pub const fn id(&self) -> u64 {
        self.id
    }

    /// Returns the episode ID.
    #[must_use]
    pub fn episode_id(&self) -> &str {
        &self.episode_id
    }
}

/// Output stream kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum OutputKind {
    /// Standard output.
    Stdout,
    /// Standard error.
    Stderr,
    /// Combined/interleaved output (typical for PTY).
    Combined,
}

impl fmt::Display for OutputKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stdout => write!(f, "stdout"),
            Self::Stderr => write!(f, "stderr"),
            Self::Combined => write!(f, "combined"),
        }
    }
}

/// Classification of process termination.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum TerminationClassification {
    /// Process completed successfully (exit code 0).
    Success,
    /// Process exited with non-zero exit code.
    Failure,
    /// Process was killed by a signal.
    Killed,
    /// Process termination was requested by the adapter.
    Terminated,
    /// Process state is unknown or could not be determined.
    Unknown,
}

impl fmt::Display for TerminationClassification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Success => write!(f, "success"),
            Self::Failure => write!(f, "failure"),
            Self::Killed => write!(f, "killed"),
            Self::Terminated => write!(f, "terminated"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

/// Events emitted by a harness adapter.
///
/// These events represent the observable behavior of the harness process,
/// normalized across different adapter types.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum HarnessEvent {
    /// Output chunk from the process.
    Output {
        /// Raw output bytes (may not be valid UTF-8).
        #[serde(with = "serde_bytes")]
        chunk: Vec<u8>,
        /// Kind of output stream.
        kind: OutputKind,
        /// Sequence number for ordering.
        seq: u64,
        /// Timestamp in nanoseconds since epoch.
        ts: u64,
    },

    /// Tool request from the harness.
    ///
    /// Parsed from structured output (Claude Code format, etc.).
    /// Raw adapters do not emit this event type.
    ToolRequest {
        /// Unique request ID for correlation.
        request_id: String,
        /// Tool name being requested.
        tool: String,
        /// Tool arguments as JSON.
        args: serde_json::Value,
    },

    /// Progress update from the harness.
    Progress {
        /// Human-readable progress message.
        message: String,
        /// Completion percentage (0-100), if known.
        percent: Option<u8>,
    },

    /// Error from the harness.
    Error {
        /// Error code for programmatic handling.
        code: String,
        /// Human-readable error message.
        message: String,
    },

    /// Process has terminated.
    Terminated {
        /// Exit code, if available.
        exit_code: Option<i32>,
        /// Classification of the termination.
        classification: TerminationClassification,
    },
}

impl HarnessEvent {
    /// Create an output event.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // Vec param prevents const fn on stable
    pub fn output(chunk: Vec<u8>, kind: OutputKind, seq: u64, ts: u64) -> Self {
        Self::Output {
            chunk,
            kind,
            seq,
            ts,
        }
    }

    /// Create a tool request event.
    #[must_use]
    pub fn tool_request(
        request_id: impl Into<String>,
        tool: impl Into<String>,
        args: serde_json::Value,
    ) -> Self {
        Self::ToolRequest {
            request_id: request_id.into(),
            tool: tool.into(),
            args,
        }
    }

    /// Create a progress event.
    #[must_use]
    pub fn progress(message: impl Into<String>, percent: Option<u8>) -> Self {
        Self::Progress {
            message: message.into(),
            percent,
        }
    }

    /// Create an error event.
    #[must_use]
    pub fn error(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Error {
            code: code.into(),
            message: message.into(),
        }
    }

    /// Create a terminated event.
    #[must_use]
    pub const fn terminated(
        exit_code: Option<i32>,
        classification: TerminationClassification,
    ) -> Self {
        Self::Terminated {
            exit_code,
            classification,
        }
    }

    /// Returns true if this is a terminal event.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(self, Self::Terminated { .. })
    }

    /// Returns true if this is an output event.
    #[must_use]
    pub const fn is_output(&self) -> bool {
        matches!(self, Self::Output { .. })
    }

    /// Returns true if this is an error event.
    #[must_use]
    pub const fn is_error(&self) -> bool {
        matches!(self, Self::Error { .. })
    }
}

/// The `HarnessAdapter` trait for normalizing harness behavior.
///
/// Per CTR-DAEMON-003, this trait provides a unified interface for spawning
/// and managing agent processes across different harness types.
///
/// # Implementors
///
/// - [`crate::episode::raw_adapter::RawAdapter`]: Baseline adapter for raw
///   process output
/// - Future: `ClaudeCodeAdapter` for structured Claude Code events
///
/// # Lifecycle
///
/// 1. Call [`spawn`](HarnessAdapter::spawn) to start the process
/// 2. Use [`output_stream`](HarnessAdapter::output_stream) to receive events
/// 3. Optionally use [`send_input`](HarnessAdapter::send_input) to send data
/// 4. Call [`terminate`](HarnessAdapter::terminate) to stop the process
#[allow(clippy::type_complexity)]
pub trait HarnessAdapter: Send + Sync {
    /// Returns the adapter type.
    fn adapter_type(&self) -> AdapterType;

    /// Spawns a new harness process.
    ///
    /// # Arguments
    ///
    /// * `config` - Configuration for the harness process
    ///
    /// # Returns
    ///
    /// A tuple of the handle and the event stream.
    ///
    /// # Errors
    ///
    /// Returns `AdapterError::SpawnFailed` if the process cannot be started.
    fn spawn(
        &self,
        config: HarnessConfig,
    ) -> Pin<
        Box<
            dyn std::future::Future<Output = AdapterResult<(HarnessHandle, HarnessEventStream)>>
                + Send
                + '_,
        >,
    >;

    /// Sends input to the harness process.
    ///
    /// # Arguments
    ///
    /// * `handle` - Handle to the running process
    /// * `input` - Bytes to send to the process stdin/PTY
    ///
    /// # Errors
    ///
    /// Returns `AdapterError::InputFailed` if input cannot be sent.
    /// Returns `AdapterError::InvalidHandle` if the handle is invalid.
    fn send_input(
        &self,
        handle: &HarnessHandle,
        input: &[u8],
    ) -> Pin<Box<dyn std::future::Future<Output = AdapterResult<()>> + Send + '_>>;

    /// Terminates the harness process.
    ///
    /// This will attempt graceful shutdown first, then force kill if needed.
    ///
    /// # Arguments
    ///
    /// * `handle` - Handle to the running process
    ///
    /// # Returns
    ///
    /// The exit status of the process.
    ///
    /// # Errors
    ///
    /// Returns `AdapterError::TerminateFailed` if termination fails.
    /// Returns `AdapterError::InvalidHandle` if the handle is invalid.
    fn terminate(
        &self,
        handle: &HarnessHandle,
    ) -> Pin<Box<dyn std::future::Future<Output = AdapterResult<ExitStatus>> + Send + '_>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_adapter_type_display() {
        assert_eq!(AdapterType::Raw.to_string(), "raw");
        assert_eq!(AdapterType::ClaudeCode.to_string(), "claude_code");
    }

    #[test]
    fn test_adapter_type_serialize() {
        let raw = AdapterType::Raw;
        let json = serde_json::to_string(&raw).unwrap();
        assert_eq!(json, "\"raw\"");

        let claude = AdapterType::ClaudeCode;
        let json = serde_json::to_string(&claude).unwrap();
        assert_eq!(json, "\"claude_code\"");
    }

    #[test]
    fn test_adapter_type_deserialize() {
        let raw: AdapterType = serde_json::from_str("\"raw\"").unwrap();
        assert_eq!(raw, AdapterType::Raw);

        let claude: AdapterType = serde_json::from_str("\"claude_code\"").unwrap();
        assert_eq!(claude, AdapterType::ClaudeCode);
    }

    #[test]
    fn test_harness_config_builder() {
        let config = HarnessConfig::new("echo", "episode-123")
            .with_args(vec!["hello".to_string()])
            .with_cwd("/tmp")
            .with_env("FOO", "bar")
            .with_pty_size(120, 40);

        assert_eq!(config.command, "echo");
        assert_eq!(config.episode_id, "episode-123");
        assert_eq!(config.args, vec!["hello"]);
        assert_eq!(config.cwd, Some(PathBuf::from("/tmp")));
        assert_eq!(config.env.get("FOO"), Some(&"bar".to_string()));
        assert_eq!(config.pty_size, (120, 40));
    }

    #[test]
    fn test_harness_config_serialize() {
        let config = HarnessConfig::new("test", "ep-1");
        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains("\"command\":\"test\""));
        assert!(json.contains("\"episode_id\":\"ep-1\""));
    }

    #[test]
    fn test_harness_event_output() {
        let event = HarnessEvent::output(b"hello".to_vec(), OutputKind::Stdout, 1, 1_234_567_890);

        assert!(event.is_output());
        assert!(!event.is_terminal());
        assert!(!event.is_error());
    }

    #[test]
    fn test_harness_event_terminated() {
        let event = HarnessEvent::terminated(Some(0), TerminationClassification::Success);

        assert!(event.is_terminal());
        assert!(!event.is_output());
    }

    #[test]
    fn test_harness_event_error() {
        let event = HarnessEvent::error("E001", "something went wrong");

        assert!(event.is_error());
        assert!(!event.is_terminal());
    }

    #[test]
    fn test_harness_event_serialize_output() {
        let event = HarnessEvent::output(b"test".to_vec(), OutputKind::Combined, 42, 1_000_000_000);

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"type\":\"output\""));
        assert!(json.contains("\"kind\":\"combined\""));
        assert!(json.contains("\"seq\":42"));
    }

    #[test]
    fn test_harness_event_serialize_tool_request() {
        let event = HarnessEvent::tool_request(
            "req-123",
            "read_file",
            serde_json::json!({"path": "/tmp/test.txt"}),
        );

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"type\":\"tool_request\""));
        assert!(json.contains("\"request_id\":\"req-123\""));
        assert!(json.contains("\"tool\":\"read_file\""));
    }

    #[test]
    fn test_harness_event_serialize_progress() {
        let event = HarnessEvent::progress("Processing files...", Some(50));

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"type\":\"progress\""));
        assert!(json.contains("\"percent\":50"));
    }

    #[test]
    fn test_harness_event_serialize_terminated() {
        let event = HarnessEvent::terminated(Some(1), TerminationClassification::Failure);

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"type\":\"terminated\""));
        assert!(json.contains("\"exit_code\":1"));
        assert!(json.contains("\"classification\":\"failure\""));
    }

    #[test]
    fn test_harness_event_deserialize() {
        let json =
            r#"{"type":"output","chunk":[116,101,115,116],"kind":"stdout","seq":1,"ts":1000}"#;
        let event: HarnessEvent = serde_json::from_str(json).unwrap();

        match event {
            HarnessEvent::Output {
                chunk,
                kind,
                seq,
                ts,
            } => {
                assert_eq!(chunk, b"test");
                assert_eq!(kind, OutputKind::Stdout);
                assert_eq!(seq, 1);
                assert_eq!(ts, 1000);
            },
            _ => panic!("expected Output event"),
        }
    }

    #[test]
    fn test_output_kind_display() {
        assert_eq!(OutputKind::Stdout.to_string(), "stdout");
        assert_eq!(OutputKind::Stderr.to_string(), "stderr");
        assert_eq!(OutputKind::Combined.to_string(), "combined");
    }

    #[test]
    fn test_termination_classification_display() {
        assert_eq!(TerminationClassification::Success.to_string(), "success");
        assert_eq!(TerminationClassification::Failure.to_string(), "failure");
        assert_eq!(TerminationClassification::Killed.to_string(), "killed");
        assert_eq!(
            TerminationClassification::Terminated.to_string(),
            "terminated"
        );
        assert_eq!(TerminationClassification::Unknown.to_string(), "unknown");
    }

    #[test]
    fn test_adapter_error_constructors() {
        let err = AdapterError::spawn_failed("process not found");
        assert!(err.to_string().contains("spawn failed"));

        let err = AdapterError::input_failed("pipe broken");
        assert!(err.to_string().contains("input failed"));

        let err = AdapterError::terminate_failed("timeout");
        assert!(err.to_string().contains("termination failed"));

        let err = AdapterError::invalid_handle("already terminated");
        assert!(err.to_string().contains("invalid handle"));
    }

    #[test]
    fn test_harness_handle_accessors() {
        let handle = HarnessHandle::new(
            42,
            "episode-abc".to_string(),
            HarnessHandleInner::Placeholder,
        );

        assert_eq!(handle.id(), 42);
        assert_eq!(handle.episode_id(), "episode-abc");
    }
}
