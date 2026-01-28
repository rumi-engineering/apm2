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

use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::mpsc;

// ============================================================================
// Validation Constants
// ============================================================================

/// Maximum length for the command string (4096 characters).
///
/// This limit prevents excessively long command strings that could cause
/// issues with process spawning or shell parsing.
pub const MAX_COMMAND_LENGTH: usize = 4096;

/// Maximum number of arguments allowed (1000 args).
///
/// This limit prevents resource exhaustion from processing an excessive
/// number of command-line arguments.
pub const MAX_ARGS_COUNT: usize = 1000;

/// Maximum length for each argument string (4096 characters).
///
/// This limit prevents individual arguments from being excessively long.
pub const MAX_ARG_LENGTH: usize = 4096;

/// Maximum length for environment variable keys (256 characters).
pub const MAX_ENV_KEY_LENGTH: usize = 256;

/// Maximum length for environment variable values (32768 characters).
///
/// Environment values can be longer than commands/args to support
/// legitimate use cases like certificates or JSON payloads.
pub const MAX_ENV_VALUE_LENGTH: usize = 32768;

/// Maximum number of environment variables (500).
pub const MAX_ENV_COUNT: usize = 500;

/// Type alias for a boxed stream of harness events.
///
/// This uses a channel receiver as the underlying stream type, which is
/// more practical for our use case than a trait object stream.
pub type HarnessEventStream = mpsc::Receiver<HarnessEvent>;

/// Errors that can occur during configuration validation.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ValidationError {
    /// Command exceeds maximum length.
    #[error("command too long: {length} chars exceeds maximum {max}")]
    CommandTooLong {
        /// Actual length of the command.
        length: usize,
        /// Maximum allowed length.
        max: usize,
    },

    /// Command is empty.
    #[error("command cannot be empty")]
    CommandEmpty,

    /// Command contains invalid characters.
    #[error("command contains invalid character: {description}")]
    CommandInvalidChar {
        /// Description of the invalid character.
        description: String,
    },

    /// Too many arguments.
    #[error("too many arguments: {count} exceeds maximum {max}")]
    TooManyArgs {
        /// Actual number of arguments.
        count: usize,
        /// Maximum allowed count.
        max: usize,
    },

    /// Argument exceeds maximum length.
    #[error("argument {index} too long: {length} chars exceeds maximum {max}")]
    ArgTooLong {
        /// Index of the problematic argument.
        index: usize,
        /// Actual length of the argument.
        length: usize,
        /// Maximum allowed length.
        max: usize,
    },

    /// Argument contains invalid characters.
    #[error("argument {index} contains invalid character: {description}")]
    ArgInvalidChar {
        /// Index of the problematic argument.
        index: usize,
        /// Description of the invalid character.
        description: String,
    },

    /// Working directory path cannot be canonicalized.
    #[error("invalid working directory: {reason}")]
    InvalidCwd {
        /// Reason the path is invalid.
        reason: String,
    },

    /// Too many environment variables.
    #[error("too many environment variables: {count} exceeds maximum {max}")]
    TooManyEnvVars {
        /// Actual number of env vars.
        count: usize,
        /// Maximum allowed count.
        max: usize,
    },

    /// Environment variable key is invalid.
    #[error("environment variable key invalid: {reason}")]
    InvalidEnvKey {
        /// Reason the key is invalid.
        reason: String,
    },

    /// Environment variable value is too long.
    #[error("environment variable '{key}' value too long: {length} chars exceeds maximum {max}")]
    EnvValueTooLong {
        /// Key of the problematic env var.
        key: String,
        /// Actual length of the value.
        length: usize,
        /// Maximum allowed length.
        max: usize,
    },

    /// Environment variable value contains invalid characters.
    #[error("environment variable '{key}' contains invalid character: {description}")]
    EnvValueInvalidChar {
        /// Key of the problematic env var.
        key: String,
        /// Description of the invalid character.
        description: String,
    },
}

/// Errors that can occur during adapter operations.
#[derive(Debug, Error)]
pub enum AdapterError {
    /// Configuration validation failed.
    #[error("configuration validation failed: {0}")]
    ValidationFailed(#[from] ValidationError),

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

    /// Resource limit exceeded (too many concurrent adapters).
    #[error("resource limit exceeded: {reason}")]
    ResourceLimitExceeded {
        /// Description of which limit was exceeded.
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

    /// Create a resource limit exceeded error.
    #[must_use]
    pub fn resource_limit_exceeded(reason: impl Into<String>) -> Self {
        Self::ResourceLimitExceeded {
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
///
/// # Security
///
/// This struct validates all inputs to prevent injection attacks and resource
/// exhaustion. All string fields are checked for:
/// - Length bounds
/// - Absence of null bytes
/// - Absence of control characters (except common whitespace in env values)
///
/// Environment variable values use [`SecretString`] to prevent accidental
/// logging of sensitive data like API keys or tokens.
///
/// Use [`HarnessConfig::validate`] to check configuration before spawning.
#[derive(Clone, Serialize, Deserialize)]
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
    ///
    /// Values are stored as [`SecretString`] to protect sensitive data
    /// like API keys from accidental exposure in logs or debug output.
    #[serde(default, skip)]
    pub env: HashMap<String, SecretString>,

    /// PTY dimensions (columns, rows).
    #[serde(default = "default_pty_size")]
    pub pty_size: (u16, u16),

    /// Episode ID for tracking.
    pub episode_id: String,
}

impl fmt::Debug for HarnessConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HarnessConfig")
            .field("command", &self.command)
            .field("args", &self.args)
            .field("cwd", &self.cwd)
            // Redact env values to prevent secret leakage
            .field("env", &format!("<{} redacted entries>", self.env.len()))
            .field("pty_size", &self.pty_size)
            .field("episode_id", &self.episode_id)
            .finish()
    }
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
    ///
    /// The value is wrapped in [`SecretString`] to prevent accidental logging.
    #[must_use]
    pub fn with_env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env
            .insert(key.into(), SecretString::from(value.into()));
        self
    }

    /// Set environment variable with a pre-wrapped secret value.
    #[must_use]
    pub fn with_secret_env(mut self, key: impl Into<String>, value: SecretString) -> Self {
        self.env.insert(key.into(), value);
        self
    }

    /// Set PTY dimensions.
    #[must_use]
    pub const fn with_pty_size(mut self, cols: u16, rows: u16) -> Self {
        self.pty_size = (cols, rows);
        self
    }

    /// Validate the configuration.
    ///
    /// This method checks all fields for security constraints:
    /// - Command: non-empty, max 4096 chars, no null bytes or control chars
    /// - Args: max 1000 args, each max 4096 chars, no null bytes or control
    ///   chars
    /// - cwd: must be canonicalizable (if present)
    /// - env: max 500 vars, keys max 256 chars, values max 32768 chars
    ///
    /// # Errors
    ///
    /// Returns a [`ValidationError`] describing the first validation failure.
    ///
    /// # Example
    ///
    /// ```rust
    /// use apm2_daemon::episode::adapter::HarnessConfig;
    ///
    /// let config = HarnessConfig::new("echo", "episode-1")
    ///     .with_args(vec!["hello".to_string()]);
    ///
    /// config.validate().expect("validation should pass");
    /// ```
    pub fn validate(&self) -> Result<(), ValidationError> {
        self.validate_command()?;
        self.validate_args()?;
        self.validate_cwd()?;
        self.validate_env()?;
        Ok(())
    }

    /// Validate the command field.
    fn validate_command(&self) -> Result<(), ValidationError> {
        if self.command.is_empty() {
            return Err(ValidationError::CommandEmpty);
        }

        if self.command.len() > MAX_COMMAND_LENGTH {
            return Err(ValidationError::CommandTooLong {
                length: self.command.len(),
                max: MAX_COMMAND_LENGTH,
            });
        }

        if let Some(desc) = Self::check_invalid_chars(&self.command, false) {
            return Err(ValidationError::CommandInvalidChar { description: desc });
        }

        Ok(())
    }

    /// Validate the args field.
    fn validate_args(&self) -> Result<(), ValidationError> {
        if self.args.len() > MAX_ARGS_COUNT {
            return Err(ValidationError::TooManyArgs {
                count: self.args.len(),
                max: MAX_ARGS_COUNT,
            });
        }

        for (index, arg) in self.args.iter().enumerate() {
            if arg.len() > MAX_ARG_LENGTH {
                return Err(ValidationError::ArgTooLong {
                    index,
                    length: arg.len(),
                    max: MAX_ARG_LENGTH,
                });
            }

            if let Some(desc) = Self::check_invalid_chars(arg, false) {
                return Err(ValidationError::ArgInvalidChar {
                    index,
                    description: desc,
                });
            }
        }

        Ok(())
    }

    /// Validate the cwd field.
    fn validate_cwd(&self) -> Result<(), ValidationError> {
        if let Some(ref cwd) = self.cwd {
            // Check that the path can be canonicalized (exists and is accessible)
            std::fs::canonicalize(cwd).map_err(|e| ValidationError::InvalidCwd {
                reason: format!("cannot canonicalize '{}': {}", cwd.display(), e),
            })?;
        }
        Ok(())
    }

    /// Validate the env field.
    fn validate_env(&self) -> Result<(), ValidationError> {
        use secrecy::ExposeSecret;

        if self.env.len() > MAX_ENV_COUNT {
            return Err(ValidationError::TooManyEnvVars {
                count: self.env.len(),
                max: MAX_ENV_COUNT,
            });
        }

        for (key, value) in &self.env {
            // Validate key
            if key.is_empty() {
                return Err(ValidationError::InvalidEnvKey {
                    reason: "key cannot be empty".to_string(),
                });
            }

            if key.len() > MAX_ENV_KEY_LENGTH {
                return Err(ValidationError::InvalidEnvKey {
                    reason: format!(
                        "key '{}' too long: {} chars exceeds maximum {}",
                        key,
                        key.len(),
                        MAX_ENV_KEY_LENGTH
                    ),
                });
            }

            // Env var names should only contain alphanumeric chars and underscores
            if !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                return Err(ValidationError::InvalidEnvKey {
                    reason: format!(
                        "key '{key}' contains invalid characters (must be alphanumeric or underscore)"
                    ),
                });
            }

            // Validate value
            let value_str = value.expose_secret();

            if value_str.len() > MAX_ENV_VALUE_LENGTH {
                return Err(ValidationError::EnvValueTooLong {
                    key: key.clone(),
                    length: value_str.len(),
                    max: MAX_ENV_VALUE_LENGTH,
                });
            }

            // For env values, allow common whitespace but still reject null bytes and other
            // control chars
            if let Some(desc) = Self::check_invalid_chars(value_str, true) {
                return Err(ValidationError::EnvValueInvalidChar {
                    key: key.clone(),
                    description: desc,
                });
            }
        }

        Ok(())
    }

    /// Check for invalid characters in a string.
    ///
    /// Returns `Some(description)` if an invalid character is found.
    ///
    /// # Arguments
    ///
    /// * `s` - The string to check
    /// * `allow_whitespace` - If true, allows tab, newline, carriage return
    fn check_invalid_chars(s: &str, allow_whitespace: bool) -> Option<String> {
        for (i, c) in s.chars().enumerate() {
            // Null bytes are never allowed
            if c == '\0' {
                return Some(format!("null byte at position {i}"));
            }

            // Check for control characters (ASCII 0x00-0x1F, 0x7F)
            if c.is_ascii_control() {
                // Allow common whitespace if permitted
                if allow_whitespace && matches!(c, '\t' | '\n' | '\r') {
                    continue;
                }
                return Some(format!(
                    "control character 0x{:02X} at position {i}",
                    c as u32
                ));
            }
        }
        None
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
/// 1. Call [`spawn`](HarnessAdapter::spawn) to start the process and get the
///    event stream
/// 2. Consume the returned [`HarnessEventStream`] to receive events
/// 3. Optionally use [`send_input`](HarnessAdapter::send_input) to send data
/// 4. Call [`terminate`](HarnessAdapter::terminate) to stop the process
///
/// # Holon Factory
///
/// Per AD-LAYER-001 and AD-ADAPT-001, adapters can create per-episode Holon
/// instances via the
/// [`AdapterRegistry::create_holon`](crate::episode::AdapterRegistry::create_holon)
/// factory method. This requires the [`as_any`](HarnessAdapter::as_any) method
/// for safe downcasting.
#[allow(clippy::type_complexity)]
pub trait HarnessAdapter: Send + Sync {
    /// Returns the adapter type.
    fn adapter_type(&self) -> AdapterType;

    /// Returns self as `&dyn Any` for downcasting.
    ///
    /// This enables the registry to safely downcast adapters to their concrete
    /// types for creating per-episode Holon instances.
    fn as_any(&self) -> &dyn std::any::Any;

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
    use secrecy::ExposeSecret;

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
        // Env values are now SecretString, need ExposeSecret to verify
        assert_eq!(
            config.env.get("FOO").map(|s| s.expose_secret().to_string()),
            Some("bar".to_string())
        );
        assert_eq!(config.pty_size, (120, 40));
    }

    #[test]
    fn test_harness_config_with_secret_env() {
        let secret = SecretString::from("super-secret-api-key".to_string());
        let config = HarnessConfig::new("test", "ep-1").with_secret_env("API_KEY", secret);

        assert_eq!(
            config
                .env
                .get("API_KEY")
                .map(|s| s.expose_secret().to_string()),
            Some("super-secret-api-key".to_string())
        );
    }

    #[test]
    fn test_harness_config_debug_redacts_env() {
        let config = HarnessConfig::new("test", "ep-1")
            .with_env("SECRET_KEY", "do-not-leak-this")
            .with_env("API_TOKEN", "also-secret");

        let debug_str = format!("{config:?}");
        assert!(!debug_str.contains("do-not-leak-this"));
        assert!(!debug_str.contains("also-secret"));
        assert!(debug_str.contains("2 redacted entries"));
    }

    #[test]
    fn test_harness_config_serialize() {
        let config = HarnessConfig::new("test", "ep-1");
        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains("\"command\":\"test\""));
        assert!(json.contains("\"episode_id\":\"ep-1\""));
        // Env is skipped in serialization to prevent secret leakage
        assert!(!json.contains("env"));
    }

    // ========================================================================
    // Validation Tests
    // ========================================================================

    #[test]
    fn test_validate_valid_config() {
        let config = HarnessConfig::new("echo", "ep-1")
            .with_args(vec!["hello".to_string()])
            .with_cwd("/tmp")
            .with_env("MY_VAR", "value");

        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_empty_command() {
        let config = HarnessConfig::new("", "ep-1");
        let result = config.validate();
        assert!(matches!(result, Err(ValidationError::CommandEmpty)));
    }

    #[test]
    fn test_validate_command_too_long() {
        let long_command = "x".repeat(MAX_COMMAND_LENGTH + 1);
        let config = HarnessConfig::new(long_command, "ep-1");
        let result = config.validate();
        assert!(matches!(
            result,
            Err(ValidationError::CommandTooLong { .. })
        ));
    }

    #[test]
    fn test_validate_command_with_null_byte() {
        let config = HarnessConfig::new("echo\0hello", "ep-1");
        let result = config.validate();
        assert!(matches!(
            result,
            Err(ValidationError::CommandInvalidChar { .. })
        ));
    }

    #[test]
    fn test_validate_command_with_control_char() {
        let config = HarnessConfig::new("echo\x07", "ep-1"); // Bell character
        let result = config.validate();
        assert!(matches!(
            result,
            Err(ValidationError::CommandInvalidChar { .. })
        ));
    }

    #[test]
    fn test_validate_too_many_args() {
        let args: Vec<String> = (0..=MAX_ARGS_COUNT).map(|i| format!("arg{i}")).collect();
        let config = HarnessConfig::new("echo", "ep-1").with_args(args);
        let result = config.validate();
        assert!(matches!(result, Err(ValidationError::TooManyArgs { .. })));
    }

    #[test]
    fn test_validate_arg_too_long() {
        let long_arg = "x".repeat(MAX_ARG_LENGTH + 1);
        let config = HarnessConfig::new("echo", "ep-1").with_args(vec![long_arg]);
        let result = config.validate();
        assert!(matches!(result, Err(ValidationError::ArgTooLong { .. })));
    }

    #[test]
    fn test_validate_arg_with_null_byte() {
        let config = HarnessConfig::new("echo", "ep-1").with_args(vec!["hello\0world".to_string()]);
        let result = config.validate();
        assert!(matches!(
            result,
            Err(ValidationError::ArgInvalidChar { .. })
        ));
    }

    #[test]
    fn test_validate_invalid_cwd() {
        let config =
            HarnessConfig::new("echo", "ep-1").with_cwd("/nonexistent/path/that/does/not/exist");
        let result = config.validate();
        assert!(matches!(result, Err(ValidationError::InvalidCwd { .. })));
    }

    #[test]
    fn test_validate_valid_cwd() {
        let config = HarnessConfig::new("echo", "ep-1").with_cwd("/tmp");
        // /tmp should exist on all Unix systems
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_too_many_env_vars() {
        let mut config = HarnessConfig::new("echo", "ep-1");
        for i in 0..=MAX_ENV_COUNT {
            config = config.with_env(format!("VAR_{i}"), "value");
        }
        let result = config.validate();
        assert!(matches!(
            result,
            Err(ValidationError::TooManyEnvVars { .. })
        ));
    }

    #[test]
    fn test_validate_empty_env_key() {
        let mut config = HarnessConfig::new("echo", "ep-1");
        config
            .env
            .insert(String::new(), SecretString::from("value".to_string()));
        let result = config.validate();
        assert!(matches!(result, Err(ValidationError::InvalidEnvKey { .. })));
    }

    #[test]
    fn test_validate_env_key_with_invalid_chars() {
        let mut config = HarnessConfig::new("echo", "ep-1");
        config.env.insert(
            "MY-VAR".to_string(),
            SecretString::from("value".to_string()),
        );
        let result = config.validate();
        assert!(matches!(result, Err(ValidationError::InvalidEnvKey { .. })));
    }

    #[test]
    fn test_validate_env_value_too_long() {
        let long_value = "x".repeat(MAX_ENV_VALUE_LENGTH + 1);
        let config = HarnessConfig::new("echo", "ep-1").with_env("MY_VAR", long_value);
        let result = config.validate();
        assert!(matches!(
            result,
            Err(ValidationError::EnvValueTooLong { .. })
        ));
    }

    #[test]
    fn test_validate_env_value_with_null_byte() {
        let config = HarnessConfig::new("echo", "ep-1").with_env("MY_VAR", "value\0with\0nulls");
        let result = config.validate();
        assert!(matches!(
            result,
            Err(ValidationError::EnvValueInvalidChar { .. })
        ));
    }

    #[test]
    fn test_validate_env_value_allows_whitespace() {
        // Tabs, newlines, and carriage returns should be allowed in env values
        let config =
            HarnessConfig::new("echo", "ep-1").with_env("MY_VAR", "line1\nline2\ttabbed\rcarriage");
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_env_value_rejects_other_control_chars() {
        // Bell character should be rejected
        let config = HarnessConfig::new("echo", "ep-1").with_env("MY_VAR", "value\x07bell");
        let result = config.validate();
        assert!(matches!(
            result,
            Err(ValidationError::EnvValueInvalidChar { .. })
        ));
    }

    #[test]
    fn test_validation_error_display() {
        let err = ValidationError::CommandEmpty;
        assert_eq!(err.to_string(), "command cannot be empty");

        let err = ValidationError::CommandTooLong {
            length: 5000,
            max: 4096,
        };
        assert!(err.to_string().contains("5000"));
        assert!(err.to_string().contains("4096"));
    }

    #[test]
    fn test_adapter_error_from_validation_error() {
        let validation_err = ValidationError::CommandEmpty;
        let adapter_err: AdapterError = validation_err.into();
        assert!(matches!(adapter_err, AdapterError::ValidationFailed(_)));
        assert!(adapter_err.to_string().contains("command cannot be empty"));
    }

    #[test]
    fn test_adapter_error_resource_limit() {
        let err = AdapterError::resource_limit_exceeded("too many connections");
        assert!(err.to_string().contains("resource limit exceeded"));
        assert!(err.to_string().contains("too many connections"));
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
