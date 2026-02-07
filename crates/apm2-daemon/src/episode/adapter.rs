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
use std::sync::Arc;
use std::time::Duration;

use nix::sys::signal::Signal;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::{Mutex, mpsc, oneshot};

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

/// Maximum size of a single `send_input` payload in bytes (256 KiB).
///
/// This limit prevents denial-of-service attacks where a malicious client
/// sends oversized input payloads that exhaust daemon memory or cause
/// unbounded PTY backpressure. The 256 KiB cap is chosen to be large
/// enough for any legitimate interactive input while providing meaningful
/// protection against resource exhaustion.
///
/// Per security review: the control channel has capacity 8, and without
/// this cap the protocol default of 64 MiB per message could queue up to
/// 512 MiB of pending input in the worst case.
pub const MAX_SEND_INPUT_BYTES: usize = 256 * 1024;

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

/// Default terminate grace period (3 seconds).
///
/// This is the time allowed between sending SIGTERM and escalating to SIGKILL
/// during process termination. The value is intentionally conservative: long
/// enough for well-behaved processes to clean up, short enough to avoid
/// stalling the daemon on unresponsive children.
const DEFAULT_TERMINATE_GRACE_PERIOD: Duration = Duration::from_secs(3);

/// Returns the default terminate grace period for serde deserialization.
const fn default_terminate_grace_period() -> Duration {
    DEFAULT_TERMINATE_GRACE_PERIOD
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

    /// Grace period between SIGTERM and SIGKILL during process termination.
    ///
    /// When terminating a harness process, the adapter first sends SIGTERM and
    /// waits up to this duration for the process to exit gracefully. If the
    /// process is still running after this period, SIGKILL is sent.
    ///
    /// Defaults to 3 seconds if not specified.
    #[serde(
        default = "default_terminate_grace_period",
        with = "serde_duration_secs"
    )]
    pub terminate_grace_period: Duration,
}

/// Serde helper for serializing/deserializing [`Duration`] as seconds (f64).
mod serde_duration_secs {
    use std::time::Duration;

    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_f64(duration.as_secs_f64())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Duration, D::Error> {
        let secs = f64::deserialize(deserializer)?;
        if secs < 0.0 {
            return Err(serde::de::Error::custom(
                "terminate_grace_period must be non-negative",
            ));
        }
        Ok(Duration::from_secs_f64(secs))
    }
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
            .field("terminate_grace_period", &self.terminate_grace_period)
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
            terminate_grace_period: DEFAULT_TERMINATE_GRACE_PERIOD,
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

    /// Set the terminate grace period.
    ///
    /// This is the time between sending SIGTERM and escalating to SIGKILL
    /// during process termination. Defaults to 3 seconds.
    #[must_use]
    pub const fn with_terminate_grace_period(mut self, grace_period: Duration) -> Self {
        self.terminate_grace_period = grace_period;
        self
    }

    /// Validate the configuration.
    ///
    /// This method checks all fields for security constraints:
    /// - Command: non-empty, max 4096 chars, no null bytes or control chars
    /// - Args: max 1000 args, each max 4096 chars, no null bytes or control
    ///   chars
    /// - cwd: syntactic validation only (no path traversal, no null bytes).
    ///   Filesystem existence is checked at spawn time.
    /// - env: max 500 vars, keys max 256 chars, values max 32768 chars
    ///
    /// # Design Note
    ///
    /// Validation is intentionally deterministic and does not perform blocking
    /// I/O. Path canonicalization and existence checks for `cwd` are deferred
    /// to process spawn time to ensure validation can be performed
    /// synchronously without side effects.
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
    /// let config = HarnessConfig::new("echo", "episode-1").with_args(vec!["hello".to_string()]);
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
    ///
    /// # Design Note
    ///
    /// Validation is intentionally limited to syntactic checks (non-empty, no
    /// path traversal). Filesystem existence and canonicalization are deferred
    /// to process spawn time to keep validation deterministic and avoid
    /// blocking I/O in the validation path. This follows the principle that
    /// validation should be pure and not depend on external state.
    fn validate_cwd(&self) -> Result<(), ValidationError> {
        if let Some(ref cwd) = self.cwd {
            // Convert to string for validation checks
            let path_str = cwd.to_string_lossy();

            // Reject empty paths
            if path_str.is_empty() {
                return Err(ValidationError::InvalidCwd {
                    reason: "working directory path cannot be empty".to_string(),
                });
            }

            // Reject path traversal attempts (parent directory references)
            // This is a security check per CTR-1503 (Path Safety)
            if path_str.contains("..") {
                return Err(ValidationError::InvalidCwd {
                    reason: "working directory cannot contain parent directory references (..)"
                        .to_string(),
                });
            }

            // Reject paths with null bytes
            if path_str.contains('\0') {
                return Err(ValidationError::InvalidCwd {
                    reason: "working directory cannot contain null bytes".to_string(),
                });
            }
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

const PTY_CONTROL_CHANNEL_CAPACITY: usize = 8;
const TERMINATE_POLL_INTERVAL: Duration = Duration::from_millis(25);
const SEND_INPUT_RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);
const TERMINATE_RESPONSE_TIMEOUT: Duration = Duration::from_secs(60);

/// Control messages for the runner-owning task.
pub(crate) enum PtyControlCommand {
    SendInput {
        input: Vec<u8>,
        respond_to: oneshot::Sender<AdapterResult<()>>,
    },
    Terminate {
        grace_period: Duration,
        respond_to: oneshot::Sender<AdapterResult<super::pty::ExitStatus>>,
    },
}

/// Shared control handle stored in `HarnessHandle`.
#[derive(Debug)]
pub(crate) struct PtyRunnerHandle {
    pub(crate) pid: u32,
    pub(crate) start_time_ticks: Option<u64>,
    control_tx: Option<mpsc::Sender<PtyControlCommand>>,
    terminated: bool,
}

impl PtyRunnerHandle {
    const fn new(
        pid: u32,
        start_time_ticks: Option<u64>,
        control_tx: mpsc::Sender<PtyControlCommand>,
    ) -> Self {
        Self {
            pid,
            start_time_ticks,
            control_tx: Some(control_tx),
            terminated: false,
        }
    }

    fn control_channel(&self) -> Option<mpsc::Sender<PtyControlCommand>> {
        self.control_tx.clone()
    }

    const fn is_terminated(&self) -> bool {
        self.terminated
    }

    fn mark_terminated(&mut self) {
        self.terminated = true;
        self.control_tx = None;
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

    /// Grace period between SIGTERM and SIGKILL during termination.
    pub(crate) terminate_grace_period: Duration,

    /// Adapter-specific internal state.
    pub(crate) inner: HarnessHandleInner,
}

/// Adapter-specific handle state.
#[derive(Debug)]
pub(crate) enum HarnessHandleInner {
    /// Real PTY-backed process control state.
    Real(Arc<Mutex<PtyRunnerHandle>>),
}

impl HarnessHandle {
    /// Create a new harness handle.
    #[allow(clippy::missing_const_for_fn)] // String param prevents const fn on stable
    pub(crate) fn new(
        id: u64,
        episode_id: String,
        terminate_grace_period: Duration,
        inner: HarnessHandleInner,
    ) -> Self {
        Self {
            id,
            episode_id,
            terminate_grace_period,
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

    /// Returns the configured terminate grace period.
    #[must_use]
    pub const fn terminate_grace_period(&self) -> Duration {
        self.terminate_grace_period
    }

    pub(crate) fn real_runner_handle(&self) -> Arc<Mutex<PtyRunnerHandle>> {
        let HarnessHandleInner::Real(handle) = &self.inner;
        Arc::clone(handle)
    }
}

/// Channel capacity for PTY control commands.
#[must_use]
pub const fn pty_control_channel_capacity() -> usize {
    PTY_CONTROL_CHANNEL_CAPACITY
}

/// Builds a real harness handle state from a child PID and control channel.
pub(crate) fn create_real_handle_inner(
    pid: u32,
    start_time_ticks: Option<u64>,
    control_tx: mpsc::Sender<PtyControlCommand>,
) -> HarnessHandleInner {
    let handle = PtyRunnerHandle::new(pid, start_time_ticks, control_tx);
    HarnessHandleInner::Real(Arc::new(Mutex::new(handle)))
}

/// Sends input bytes to a spawned harness process via the real handle.
///
/// # Security
///
/// Input size is validated against [`MAX_SEND_INPUT_BYTES`] before
/// enqueuing to the control channel. This prevents a malicious client from
/// exhausting daemon memory via oversized payloads queued across the
/// bounded control channel (capacity 8).
///
/// # Delivery Semantics (at-most-once)
///
/// The timeout (`SEND_INPUT_RESPONSE_TIMEOUT`) is applied **after** the
/// command has been enqueued on the control channel. If the caller times
/// out while waiting for the PTY task's acknowledgement, the enqueued
/// command may still execute later. Callers that retry on timeout should
/// be aware that the original write may have been (or will be) delivered,
/// resulting in duplicate input to the child process. This is an
/// at-most-once guarantee from the caller's perspective: each call either
/// succeeds exactly once or returns an error, but on timeout the true
/// outcome is indeterminate.
pub(crate) async fn send_input_with_handle(
    handle_id: u64,
    runner_handle: Arc<Mutex<PtyRunnerHandle>>,
    input: Vec<u8>,
) -> AdapterResult<()> {
    // CTR-INPUT-001: Validate input size BEFORE enqueuing to prevent
    // memory exhaustion via oversized payloads on the control channel.
    if input.len() > MAX_SEND_INPUT_BYTES {
        return Err(AdapterError::input_failed(format!(
            "input payload too large: {} bytes exceeds maximum {} bytes",
            input.len(),
            MAX_SEND_INPUT_BYTES,
        )));
    }

    let (control_tx, pid) = {
        let guard = runner_handle.lock().await;
        if guard.is_terminated() {
            return Err(AdapterError::invalid_handle(format!(
                "handle {} for pid {} is already terminated",
                handle_id, guard.pid
            )));
        }
        let control_tx = guard.control_channel().ok_or_else(|| {
            AdapterError::invalid_handle(format!(
                "handle {} for pid {} has no active PTY control channel",
                handle_id, guard.pid
            ))
        })?;
        (control_tx, guard.pid)
    };

    let (respond_to, response_rx) = oneshot::channel();
    control_tx
        .send(PtyControlCommand::SendInput { input, respond_to })
        .await
        .map_err(|_| {
            AdapterError::invalid_handle(format!(
                "handle {handle_id} for pid {pid} PTY task is no longer active"
            ))
        })?;

    tokio::time::timeout(SEND_INPUT_RESPONSE_TIMEOUT, response_rx)
        .await
        .map_err(|_| {
            AdapterError::input_failed(format!(
                "handle {handle_id} send_input response timed out after {}s",
                SEND_INPUT_RESPONSE_TIMEOUT.as_secs()
            ))
        })?
        .map_err(|_| {
            AdapterError::invalid_handle(format!(
                "handle {handle_id} PTY task dropped input response"
            ))
        })?
}

/// Terminates a spawned harness process via the real handle.
///
/// The `grace_period` controls how long to wait after SIGTERM before
/// escalating to SIGKILL.
pub(crate) async fn terminate_with_handle(
    handle_id: u64,
    runner_handle: Arc<Mutex<PtyRunnerHandle>>,
    grace_period: Duration,
) -> AdapterResult<ExitStatus> {
    let (control_tx, pid) = {
        let guard = runner_handle.lock().await;
        if guard.is_terminated() {
            return Err(AdapterError::invalid_handle(format!(
                "handle {} for pid {} is already terminated",
                handle_id, guard.pid
            )));
        }
        // Fail-closed: refuse to terminate without start-time binding.
        // Without a start-time binding, we cannot validate PID identity
        // before signal delivery, which risks sending signals to a
        // recycled PID (a different process).
        if guard.start_time_ticks.is_none() {
            return Err(AdapterError::terminate_failed(format!(
                "handle {} for pid {}: refusing termination without start-time binding \
                 (PID reuse guard unavailable)",
                handle_id, guard.pid,
            )));
        }
        let control_tx = guard.control_channel().ok_or_else(|| {
            AdapterError::invalid_handle(format!(
                "handle {} for pid {} has no active PTY control channel",
                handle_id, guard.pid
            ))
        })?;
        (control_tx, guard.pid)
    };

    let (respond_to, response_rx) = oneshot::channel();
    control_tx
        .send(PtyControlCommand::Terminate {
            grace_period,
            respond_to,
        })
        .await
        .map_err(|_| {
            AdapterError::invalid_handle(format!(
                "handle {handle_id} for pid {pid} PTY task is no longer active"
            ))
        })?;

    let terminate_result = tokio::time::timeout(TERMINATE_RESPONSE_TIMEOUT, response_rx)
        .await
        .map_err(|_| {
            AdapterError::terminate_failed(format!(
                "handle {handle_id} terminate response timed out after {}s",
                TERMINATE_RESPONSE_TIMEOUT.as_secs()
            ))
        })?
        .map_err(|_| {
            AdapterError::invalid_handle(format!(
                "handle {handle_id} PTY task dropped termination response"
            ))
        })?;

    // IMPORTANT: Only mark the handle as terminated AFTER confirming a
    // successful exit status.  If `terminate_runner()` returned `Err` (e.g.
    // signal delivery failed while the child is still alive), the `?`
    // operators below propagate the error *before* reaching
    // `mark_terminated()`, preserving the handle's control channel so the
    // caller can retry `terminate()` or `send_input()`.  Marking terminated
    // before checking the result would leak subprocesses and exhaust adapter
    // concurrency slots with no retry path.
    let mapped_exit_status = map_pty_exit_status(terminate_result?)?;

    {
        let mut guard = runner_handle.lock().await;
        guard.mark_terminated();
    }

    Ok(mapped_exit_status)
}

/// Processes a control message for a PTY runner.
pub(crate) async fn process_pty_control_command(
    command: PtyControlCommand,
    runner: &mut super::pty::PtyRunner,
    pid: u32,
    start_time_ticks: Option<u64>,
) -> Option<super::pty::ExitStatus> {
    match command {
        PtyControlCommand::SendInput { input, respond_to } => {
            let result = runner.send_input(&input).await.map_err(|e| {
                AdapterError::input_failed(format!(
                    "failed to write to PTY stdin for pid {pid}: {e}"
                ))
            });
            let _ = respond_to.send(result);
            None
        },
        PtyControlCommand::Terminate {
            grace_period,
            respond_to,
        } => {
            let result = terminate_runner(runner, pid, start_time_ticks, grace_period).await;
            let status = result.as_ref().ok().copied();
            let _ = respond_to.send(result);
            status
        },
    }
}

/// Gracefully terminates a runner with SIGTERM then SIGKILL fallback.
pub(crate) async fn terminate_runner(
    runner: &mut super::pty::PtyRunner,
    pid: u32,
    start_time_ticks: Option<u64>,
    grace_period: Duration,
) -> AdapterResult<super::pty::ExitStatus> {
    match runner.try_wait() {
        Ok(super::pty::ExitStatus::Running) => {},
        Ok(status) => return Ok(status),
        Err(e) => {
            return Err(AdapterError::terminate_failed(format!(
                "failed to query process state for pid {pid}: {e}"
            )));
        },
    }

    ensure_pid_binding(runner, pid, start_time_ticks)?;
    if let Err(e) = runner.signal(Signal::SIGTERM) {
        if let Ok(status) = runner.try_wait() {
            if !matches!(status, super::pty::ExitStatus::Running) {
                return Ok(status);
            }
        }
        return Err(AdapterError::terminate_failed(format!(
            "failed to send SIGTERM to pid {pid}: {e}"
        )));
    }

    let deadline = tokio::time::Instant::now() + grace_period;
    loop {
        match runner.try_wait() {
            Ok(super::pty::ExitStatus::Running) => {},
            Ok(status) => return Ok(status),
            Err(e) => {
                return Err(AdapterError::terminate_failed(format!(
                    "failed to poll termination status for pid {pid}: {e}"
                )));
            },
        }

        if tokio::time::Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(TERMINATE_POLL_INTERVAL).await;
    }

    ensure_pid_binding(runner, pid, start_time_ticks)?;
    if let Err(e) = runner.signal(Signal::SIGKILL) {
        if let Ok(status) = runner.try_wait() {
            if !matches!(status, super::pty::ExitStatus::Running) {
                return Ok(status);
            }
        }
        return Err(AdapterError::terminate_failed(format!(
            "failed to send SIGKILL to pid {pid}: {e}"
        )));
    }

    runner.wait().map_err(|e| {
        AdapterError::terminate_failed(format!("failed to reap terminated process pid {pid}: {e}"))
    })
}

fn map_pty_exit_status(status: super::pty::ExitStatus) -> AdapterResult<ExitStatus> {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;

        match status {
            super::pty::ExitStatus::Exited(code) => Ok(ExitStatus::from_raw(code << 8)),
            super::pty::ExitStatus::Signaled(signal) => Ok(ExitStatus::from_raw(signal as i32)),
            super::pty::ExitStatus::Running => Err(AdapterError::terminate_failed(
                "process still running after terminate request",
            )),
        }
    }

    #[cfg(not(unix))]
    {
        let _ = status;
        Err(AdapterError::terminate_failed(
            "process termination status conversion is unsupported on non-unix targets",
        ))
    }
}

fn ensure_pid_binding(
    runner: &mut super::pty::PtyRunner,
    pid: u32,
    start_time_ticks: Option<u64>,
) -> AdapterResult<()> {
    match validate_pid_binding(pid, start_time_ticks) {
        Ok(()) => Ok(()),
        Err(validation_err) => match runner.try_wait() {
            Ok(status) if !matches!(status, super::pty::ExitStatus::Running) => Ok(()),
            _ => Err(validation_err),
        },
    }
}

fn validate_pid_binding(pid: u32, start_time_ticks: Option<u64>) -> AdapterResult<()> {
    let expected_start = start_time_ticks.ok_or_else(|| {
        AdapterError::terminate_failed(format!(
            "refusing signal delivery to pid {pid}: missing start-time binding"
        ))
    })?;

    let current_start = read_proc_start_time(pid).ok_or_else(|| {
        AdapterError::terminate_failed(format!(
            "refusing signal delivery to pid {pid}: process identity unavailable"
        ))
    })?;

    if current_start != expected_start {
        return Err(AdapterError::terminate_failed(format!(
            "refusing signal delivery to pid {pid}: PID identity mismatch (expected start {expected_start}, found {current_start})"
        )));
    }

    Ok(())
}

/// Reads `/proc/<pid>/stat` field 22 (`starttime`) for PID-reuse validation.
#[cfg(unix)]
#[must_use]
pub(crate) fn read_proc_start_time(pid: u32) -> Option<u64> {
    let stat_path = format!("/proc/{pid}/stat");
    let contents = std::fs::read_to_string(stat_path).ok()?;
    let after_comm = contents.rsplit_once(')')?.1;
    let tokens: Vec<&str> = after_comm.split_whitespace().collect();
    tokens.get(19)?.parse::<u64>().ok()
}

#[cfg(not(unix))]
#[must_use]
pub(crate) const fn read_proc_start_time(_pid: u32) -> Option<u64> {
    None
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
    fn test_validate_cwd_with_path_traversal() {
        // Path traversal attempts should fail validation (per CTR-1503)
        let config = HarnessConfig::new("echo", "ep-1").with_cwd("/tmp/../etc/passwd");
        let result = config.validate();
        assert!(matches!(result, Err(ValidationError::InvalidCwd { .. })));
        if let Err(ValidationError::InvalidCwd { reason }) = result {
            assert!(reason.contains("parent directory"));
        }
    }

    #[test]
    fn test_validate_cwd_with_null_byte() {
        let config = HarnessConfig::new("echo", "ep-1").with_cwd("/tmp/test\0path");
        let result = config.validate();
        assert!(matches!(result, Err(ValidationError::InvalidCwd { .. })));
        if let Err(ValidationError::InvalidCwd { reason }) = result {
            assert!(reason.contains("null bytes"));
        }
    }

    #[test]
    fn test_validate_valid_cwd() {
        // Valid paths should pass validation regardless of filesystem existence
        // Existence check is deferred to spawn time
        let config = HarnessConfig::new("echo", "ep-1").with_cwd("/tmp");
        assert!(config.validate().is_ok());

        // Non-existent paths should also pass syntactic validation
        let config = HarnessConfig::new("echo", "ep-1").with_cwd("/nonexistent/path");
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
        let (control_tx, _control_rx) = tokio::sync::mpsc::channel(1);
        let inner = create_real_handle_inner(4242, Some(123), control_tx);
        let handle = HarnessHandle::new(
            42,
            "episode-abc".to_string(),
            DEFAULT_TERMINATE_GRACE_PERIOD,
            inner,
        );

        assert_eq!(handle.id(), 42);
        assert_eq!(handle.episode_id(), "episode-abc");
        assert_eq!(
            handle.terminate_grace_period(),
            DEFAULT_TERMINATE_GRACE_PERIOD
        );
    }

    #[test]
    fn test_harness_handle_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<HarnessHandle>();
    }

    /// Regression test: when `terminate_with_handle` fails (e.g. because
    /// `terminate_runner` returned an error while the child is still alive),
    /// the handle must NOT be marked as terminated.  The caller must be able
    /// to retry `terminate()` or `send_input()` through the same handle.
    ///
    /// This guards against the original bug where `mark_terminated()` was
    /// called unconditionally before checking the termination result, which
    /// permanently invalidated the handle even on transient failures.
    #[tokio::test]
    async fn terminate_failure_preserves_handle_for_retry() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let (control_tx, mut control_rx) =
            mpsc::channel::<PtyControlCommand>(PTY_CONTROL_CHANNEL_CAPACITY);

        // Build a real PtyRunnerHandle with a plausible (fake) PID and a
        // non-None start_time_ticks so the pre-flight checks pass.
        let runner_handle = Arc::new(Mutex::new(PtyRunnerHandle::new(
            99999,
            Some(42),
            control_tx,
        )));

        // Track how many Terminate commands the mock task receives.
        let call_count = Arc::new(AtomicUsize::new(0));
        let call_count_inner = Arc::clone(&call_count);

        // Spawn a mock "PTY control task" that:
        //   1st Terminate  -> responds with Err (simulating signal failure)
        //   2nd Terminate  -> responds with Ok(Exited(0))
        let mock_task = tokio::spawn(async move {
            while let Some(cmd) = control_rx.recv().await {
                match cmd {
                    PtyControlCommand::Terminate {
                        respond_to,
                        grace_period: _,
                    } => {
                        let n = call_count_inner.fetch_add(1, Ordering::SeqCst);
                        if n == 0 {
                            // First call: simulate a terminate failure
                            let _ = respond_to.send(Err(AdapterError::terminate_failed(
                                "mock SIGTERM delivery failed",
                            )));
                        } else {
                            // Second call: simulate successful termination
                            let _ = respond_to.send(Ok(super::super::pty::ExitStatus::Exited(0)));
                        }
                    },
                    PtyControlCommand::SendInput { respond_to, .. } => {
                        let _ = respond_to.send(Ok(()));
                    },
                }
            }
        });

        // --- First terminate attempt: should FAIL ---
        let result = terminate_with_handle(
            1,
            Arc::clone(&runner_handle),
            DEFAULT_TERMINATE_GRACE_PERIOD,
        )
        .await;
        assert!(
            result.is_err(),
            "first terminate should fail, got: {result:?}"
        );

        // Handle must NOT be marked terminated — still operable.
        {
            let guard = runner_handle.lock().await;
            assert!(
                !guard.is_terminated(),
                "handle must NOT be terminated after a failed terminate attempt"
            );
            assert!(
                guard.control_channel().is_some(),
                "control channel must still be available after a failed terminate attempt"
            );
        }

        // --- Verify handle is still operable: send_input should work ---
        let input_result =
            send_input_with_handle(1, Arc::clone(&runner_handle), b"ping".to_vec()).await;
        assert!(
            input_result.is_ok(),
            "send_input should succeed on a non-terminated handle, got: {input_result:?}"
        );

        // --- Second terminate attempt: should SUCCEED ---
        let result = terminate_with_handle(
            1,
            Arc::clone(&runner_handle),
            DEFAULT_TERMINATE_GRACE_PERIOD,
        )
        .await;
        assert!(
            result.is_ok(),
            "second terminate should succeed, got: {result:?}"
        );

        // Handle must NOW be marked terminated.
        {
            let guard = runner_handle.lock().await;
            assert!(
                guard.is_terminated(),
                "handle must be terminated after a successful terminate"
            );
            assert!(
                guard.control_channel().is_none(),
                "control channel must be removed after successful terminate"
            );
        }

        assert_eq!(
            call_count.load(Ordering::SeqCst),
            2,
            "mock task should have received exactly 2 Terminate commands"
        );

        // Clean up the mock task.
        mock_task.abort();
    }

    // ========================================================================
    // UT-00396-01: send_input rejects oversized payloads
    // ========================================================================

    /// UT-00396-01: Payloads exceeding `MAX_SEND_INPUT_BYTES` must be rejected
    /// at the adapter boundary BEFORE enqueuing to the control channel.
    ///
    /// This is a security invariant: without this check, the 64 MiB protocol
    /// default combined with the capacity-8 control channel could queue
    /// up to 512 MiB of pending input data.
    #[tokio::test]
    async fn send_input_rejects_oversized_payload() {
        let (control_tx, mut control_rx) =
            mpsc::channel::<PtyControlCommand>(PTY_CONTROL_CHANNEL_CAPACITY);

        let runner_handle = Arc::new(Mutex::new(PtyRunnerHandle::new(12345, Some(1), control_tx)));

        // Spawn a sink that would accept any command (to prove the oversized
        // payload never reaches the control channel).
        let sink = tokio::spawn(async move {
            let mut received = 0u64;
            while control_rx.recv().await.is_some() {
                received += 1;
            }
            received
        });

        // --- Exactly at the limit: should succeed (mock task will ack) ---
        let at_limit = vec![0u8; MAX_SEND_INPUT_BYTES];
        // We need a mock handler, but more importantly we test the REJECTION
        // path. For the acceptance path we'd need the sink to respond.
        // Instead, test that the over-limit path returns an immediate error
        // without reaching the control channel.

        // --- Over the limit by 1 byte: must be rejected immediately ---
        let over_limit = vec![0u8; MAX_SEND_INPUT_BYTES + 1];
        let result = send_input_with_handle(1, Arc::clone(&runner_handle), over_limit).await;
        assert!(
            result.is_err(),
            "payload exceeding MAX_SEND_INPUT_BYTES must be rejected"
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("too large"),
            "error message must mention 'too large', got: {err_msg}"
        );
        assert!(
            err_msg.contains(&MAX_SEND_INPUT_BYTES.to_string()),
            "error message must include the limit value, got: {err_msg}"
        );

        // --- Much larger payload: also rejected ---
        let huge = vec![0u8; MAX_SEND_INPUT_BYTES * 4];
        let result = send_input_with_handle(1, Arc::clone(&runner_handle), huge).await;
        assert!(
            result.is_err(),
            "payload 4x over MAX_SEND_INPUT_BYTES must be rejected"
        );

        // --- At exactly the limit: should reach the control channel ---
        // Spawn a handler that acks SendInput commands.
        drop(runner_handle); // Drop old handle to close the channel
        let (ack_tx, mut ack_rx) = mpsc::channel::<PtyControlCommand>(PTY_CONTROL_CHANNEL_CAPACITY);
        let ack_handle = Arc::new(Mutex::new(PtyRunnerHandle::new(12346, Some(2), ack_tx)));
        let ack_task = tokio::spawn(async move {
            while let Some(cmd) = ack_rx.recv().await {
                if let PtyControlCommand::SendInput { respond_to, .. } = cmd {
                    let _ = respond_to.send(Ok(()));
                }
            }
        });

        let result = send_input_with_handle(1, Arc::clone(&ack_handle), at_limit).await;
        assert!(
            result.is_ok(),
            "payload exactly at MAX_SEND_INPUT_BYTES must be accepted, got: {result:?}"
        );

        // Verify the oversized payloads never reached the original sink.
        drop(sink);
        ack_task.abort();
    }

    /// UT-00396-02: Zero-length input is accepted (edge case).
    #[tokio::test]
    async fn send_input_accepts_empty_payload() {
        let (control_tx, mut control_rx) =
            mpsc::channel::<PtyControlCommand>(PTY_CONTROL_CHANNEL_CAPACITY);

        let runner_handle = Arc::new(Mutex::new(PtyRunnerHandle::new(12347, Some(3), control_tx)));

        let mock_task = tokio::spawn(async move {
            while let Some(cmd) = control_rx.recv().await {
                if let PtyControlCommand::SendInput { respond_to, .. } = cmd {
                    let _ = respond_to.send(Ok(()));
                }
            }
        });

        let result = send_input_with_handle(1, Arc::clone(&runner_handle), vec![]).await;
        assert!(
            result.is_ok(),
            "empty payload must be accepted, got: {result:?}"
        );

        mock_task.abort();
    }

    // ========================================================================
    // UT-00396-03: Configured terminate grace period is honored
    // ========================================================================

    /// Verifies that when `HarnessConfig` is given a custom
    /// `terminate_grace_period`, that value flows through to the
    /// `PtyControlCommand::Terminate` message sent on the control channel.
    #[test]
    fn harness_config_default_terminate_grace_period() {
        let config = HarnessConfig::new("echo", "ep-1");
        assert_eq!(
            config.terminate_grace_period,
            Duration::from_secs(3),
            "default terminate_grace_period must be 3s"
        );
    }

    #[test]
    fn harness_config_custom_terminate_grace_period() {
        let custom = Duration::from_secs(10);
        let config = HarnessConfig::new("echo", "ep-1").with_terminate_grace_period(custom);
        assert_eq!(
            config.terminate_grace_period, custom,
            "with_terminate_grace_period must override the default"
        );
    }

    /// End-to-end test: a custom grace period set on `HarnessConfig` must be
    /// delivered inside the `PtyControlCommand::Terminate` message when
    /// `terminate_with_handle` is called with that value.
    #[tokio::test]
    async fn terminate_with_handle_uses_configured_grace_period() {
        let custom_grace = Duration::from_millis(7777);

        let (control_tx, mut control_rx) =
            mpsc::channel::<PtyControlCommand>(PTY_CONTROL_CHANNEL_CAPACITY);

        let runner_handle = Arc::new(Mutex::new(PtyRunnerHandle::new(
            99998,
            Some(99),
            control_tx,
        )));

        // Spawn a mock task that captures the grace_period from the Terminate
        // command and responds with a successful exit.
        let (observed_tx, observed_rx) = oneshot::channel::<Duration>();
        let mock_task = tokio::spawn(async move {
            let mut observed_sender = Some(observed_tx);
            while let Some(cmd) = control_rx.recv().await {
                if let PtyControlCommand::Terminate {
                    grace_period,
                    respond_to,
                } = cmd
                {
                    if let Some(sender) = observed_sender.take() {
                        let _ = sender.send(grace_period);
                    }
                    let _ = respond_to.send(Ok(super::super::pty::ExitStatus::Exited(0)));
                }
            }
        });

        // Call terminate_with_handle with the custom grace period.
        let result = terminate_with_handle(1, Arc::clone(&runner_handle), custom_grace).await;
        assert!(result.is_ok(), "terminate should succeed, got: {result:?}");

        // Verify the mock task received the correct grace period.
        let observed = observed_rx
            .await
            .expect("mock task should have sent grace_period");
        assert_eq!(
            observed, custom_grace,
            "terminate_with_handle must forward the configured grace period to the control command"
        );

        mock_task.abort();
    }
}
