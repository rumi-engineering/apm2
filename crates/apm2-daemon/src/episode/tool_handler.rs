//! Tool handler trait and types for tool execution.
//!
//! This module defines the `ToolHandler` trait that tool implementations must
//! satisfy per TCK-00165. Handlers validate arguments, execute operations,
//! and report resource consumption.
//!
//! # Architecture
//!
//! ```text
//! ToolExecutor
//!     │
//!     ├── handlers: HashMap<ToolClass, Box<dyn ToolHandler>>
//!     │                 │
//!     │                 ├── ReadFileHandler
//!     │                 ├── WriteFileHandler
//!     │                 └── ExecuteHandler
//!     │
//!     └── budget_tracker: BudgetTracker
//! ```
//!
//! # Security Model
//!
//! - All handlers validate arguments before execution
//! - Handlers report actual resource consumption for budget charging
//! - Capability validation happens BEFORE handler dispatch (in `ToolBroker`)
//!
//! # Contract References
//!
//! - TCK-00165: Tool execution and budget charging
//! - AD-TOOL-001: Tool execution flow
//! - CTR-1303: Bounded collections with MAX_* constants

use std::fmt;
use std::path::PathBuf;
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::decision::BudgetDelta;
use super::runtime::Hash;
use super::tool_class::ToolClass;

// =============================================================================
// Limits (CTR-1303)
// =============================================================================

/// Maximum size for tool arguments in bytes.
pub const MAX_TOOL_ARGS_SIZE: usize = 1024 * 1024; // 1 MiB

/// Maximum length for tool result messages.
pub const MAX_RESULT_MESSAGE_LEN: usize = 4096;

/// Maximum number of registered tool handlers.
pub const MAX_HANDLERS: usize = 64;

/// Maximum bytes for artifact fetch operations (4 MiB per REQ-HEF-0010).
///
/// This limit ensures bounded output for artifact retrieval operations.
/// Requests for larger artifacts must be chunked or use streaming APIs.
pub const ARTIFACT_FETCH_MAX_BYTES: usize = 4 * 1024 * 1024; // 4 MiB

/// Maximum output bytes for git operations (256 KiB per REQ-HEF-0010).
pub const GIT_OUTPUT_MAX_BYTES: usize = 256 * 1024; // 256 KiB

/// Maximum output lines for git operations (4000 per REQ-HEF-0010).
pub const GIT_OUTPUT_MAX_LINES: usize = 4000;

// =============================================================================
// ToolArgs
// =============================================================================

/// Arguments for tool execution.
///
/// This enum represents the structured arguments for different tool classes.
/// Each variant is validated by the corresponding handler before execution.
///
/// # Security
///
/// Uses `deny_unknown_fields` on inner types to prevent field injection
/// attacks when deserializing from untrusted input.
///
/// # Note on Eq
///
/// Uses `PartialEq` only due to `InferenceArgs` containing f32 temperature
/// field.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[non_exhaustive]
pub enum ToolArgs {
    /// Arguments for read operations.
    Read(ReadArgs),

    /// Arguments for write operations.
    Write(WriteArgs),

    /// Arguments for execute operations.
    Execute(ExecuteArgs),

    /// Arguments for network operations.
    Network(NetworkArgs),

    /// Arguments for git operations.
    Git(GitArgs),

    /// Arguments for inference operations.
    Inference(InferenceArgs),

    /// Arguments for artifact fetch operations.
    Artifact(ArtifactArgs),

    /// Raw bytes for custom handlers.
    Raw(RawArgs),
}

impl ToolArgs {
    /// Returns the tool class for these arguments.
    #[must_use]
    pub const fn tool_class(&self) -> ToolClass {
        match self {
            Self::Write(_) => ToolClass::Write,
            Self::Execute(_) => ToolClass::Execute,
            Self::Network(_) => ToolClass::Network,
            Self::Git(_) => ToolClass::Git,
            Self::Inference(_) => ToolClass::Inference,
            Self::Artifact(_) => ToolClass::Artifact,
            Self::Read(_) | Self::Raw(_) => ToolClass::Read, // Default for raw
        }
    }

    /// Returns the estimated size of these arguments in bytes.
    #[must_use]
    pub fn estimated_size(&self) -> usize {
        match self {
            Self::Read(args) => args.path.to_string_lossy().len(),
            Self::Write(args) => {
                args.path.to_string_lossy().len() + args.content.as_ref().map_or(0, Vec::len)
            },
            Self::Execute(args) => {
                args.command.len()
                    + args.args.iter().map(String::len).sum::<usize>()
                    + args.stdin.as_ref().map_or(0, Vec::len)
            },
            Self::Network(args) => args.url.len() + args.body.as_ref().map_or(0, Vec::len),
            Self::Git(args) => {
                args.operation.len() + args.args.iter().map(String::len).sum::<usize>()
            },
            Self::Inference(args) => args.prompt.len(),
            Self::Artifact(args) => {
                args.stable_id.as_ref().map_or(0, String::len)
                    + args.content_hash.map_or(0, |_| 32)
                    + args.expected_hash.map_or(0, |_| 32)
                    + args.format.as_ref().map_or(0, String::len)
                    + 8 // max_bytes u64
            },
            Self::Raw(args) => args.data.len(),
        }
    }
}

/// Arguments for read operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadArgs {
    /// Path to read from.
    pub path: PathBuf,

    /// Optional byte offset to start reading from.
    pub offset: Option<u64>,

    /// Optional maximum bytes to read.
    pub limit: Option<u64>,
}

/// Arguments for write operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WriteArgs {
    /// Path to write to.
    pub path: PathBuf,

    /// Content to write (inline, for small files).
    pub content: Option<Vec<u8>>,

    /// Hash of content in CAS (for large files).
    pub content_hash: Option<Hash>,

    /// Whether to create parent directories.
    pub create_parents: bool,

    /// Whether to append instead of overwrite.
    pub append: bool,
}

/// Arguments for execute operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecuteArgs {
    /// Command to execute.
    pub command: String,

    /// Command arguments.
    #[serde(default)]
    pub args: Vec<String>,

    /// Working directory for command execution.
    pub cwd: Option<PathBuf>,

    /// Optional stdin content.
    pub stdin: Option<Vec<u8>>,

    /// Timeout in milliseconds.
    pub timeout_ms: Option<u64>,
}

/// Arguments for network operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkArgs {
    /// URL to access.
    pub url: String,

    /// HTTP method (GET, POST, etc.).
    #[serde(default = "default_method")]
    pub method: String,

    /// Request headers.
    #[serde(default)]
    pub headers: Vec<(String, String)>,

    /// Request body.
    pub body: Option<Vec<u8>>,

    /// Timeout in milliseconds.
    pub timeout_ms: Option<u64>,
}

fn default_method() -> String {
    "GET".to_string()
}

/// Arguments for git operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitArgs {
    /// Git operation (status, commit, push, etc.).
    pub operation: String,

    /// Additional arguments.
    #[serde(default)]
    pub args: Vec<String>,

    /// Repository path.
    pub repo_path: Option<PathBuf>,
}

/// Arguments for inference operations.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InferenceArgs {
    /// Prompt for the LLM.
    pub prompt: String,

    /// Model identifier.
    pub model: Option<String>,

    /// Maximum tokens to generate.
    pub max_tokens: Option<u32>,

    /// Temperature for sampling (0.0 to 2.0).
    /// Note: f32 doesn't implement `Eq`, so `InferenceArgs` uses `PartialEq`
    /// only.
    pub temperature: Option<f32>,
}

impl Eq for InferenceArgs {}

impl std::hash::Hash for InferenceArgs {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.prompt.hash(state);
        self.model.hash(state);
        self.max_tokens.hash(state);
        // Hash the temperature bits
        if let Some(t) = self.temperature {
            t.to_bits().hash(state);
        } else {
            state.write_u8(0);
        }
    }
}

/// Arguments for artifact fetch operations (matching proto `ArtifactFetch`).
///
/// Per REQ-HEF-0010, artifact fetch supports two resolution modes:
/// - `stable_id`: Stable identifier for resolution (e.g., "org:ticket:TCK-001")
/// - `content_hash`: Direct content hash reference (BLAKE3, 32 bytes)
///
/// Exactly one of these must be set (fail-closed validation).
///
/// # Security
///
/// Uses `deny_unknown_fields` to prevent field injection attacks when
/// deserializing from untrusted input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactArgs {
    /// Stable identifier for resolution (e.g., "org:ticket:TCK-001").
    ///
    /// If set, the kernel resolves this to a content hash. Currently not
    /// supported - requests using `stable_id` will fail closed.
    pub stable_id: Option<String>,

    /// Direct content hash reference (BLAKE3, 32 bytes).
    ///
    /// Policy may restrict usage in consumption mode to prevent side-channel
    /// bypass.
    pub content_hash: Option<Hash>,

    /// Expected content hash for validation when using `stable_id`.
    ///
    /// If resolution yields a different hash, the fetch fails.
    pub expected_hash: Option<Hash>,

    /// Maximum bytes to return (REQUIRED, <= `ARTIFACT_FETCH_MAX_BYTES`).
    ///
    /// Requests exceeding this limit will fail with `OutputTooLarge`.
    pub max_bytes: u64,

    /// Requested format (e.g., "json", "yaml", "raw").
    ///
    /// The kernel may perform transcoding if supported.
    pub format: Option<String>,
}

/// Raw bytes arguments for custom handlers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawArgs {
    /// Tool class identifier.
    pub tool_class: String,

    /// Raw argument bytes.
    pub data: Vec<u8>,
}

// =============================================================================
// ToolResultData
// =============================================================================

/// Result data from tool execution.
///
/// This captures the output and metadata from a completed tool execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolResultData {
    /// Whether the execution succeeded.
    pub success: bool,

    /// Output data (stdout for commands, response body for network).
    pub output: Vec<u8>,

    /// Error output data (stderr for commands).
    pub error_output: Option<Vec<u8>>,

    /// Exit code for commands.
    pub exit_code: Option<i32>,

    /// Actual resource consumption.
    pub budget_consumed: BudgetDelta,

    /// Execution duration.
    pub duration: Duration,

    /// Optional structured metadata.
    pub metadata: Option<ResultMetadata>,
}

impl ToolResultData {
    /// Creates a successful result.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // Vec arguments can't be const
    pub fn success(output: Vec<u8>, budget_consumed: BudgetDelta, duration: Duration) -> Self {
        Self {
            success: true,
            output,
            error_output: None,
            exit_code: Some(0),
            budget_consumed,
            duration,
            metadata: None,
        }
    }

    /// Creates a failed result.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // Vec::new() in body can't be const
    pub fn failure(
        error_output: Vec<u8>,
        exit_code: Option<i32>,
        budget_consumed: BudgetDelta,
        duration: Duration,
    ) -> Self {
        Self {
            success: false,
            output: Vec::new(),
            error_output: Some(error_output),
            exit_code,
            budget_consumed,
            duration,
            metadata: None,
        }
    }

    /// Sets the metadata.
    #[must_use]
    pub fn with_metadata(mut self, metadata: ResultMetadata) -> Self {
        self.metadata = Some(metadata);
        self
    }

    /// Returns the output as a UTF-8 string if valid.
    #[must_use]
    pub fn output_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.output).ok()
    }
}

/// Structured metadata for tool results.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResultMetadata {
    /// File size for read operations.
    pub file_size: Option<u64>,

    /// HTTP status code for network operations.
    pub http_status: Option<u16>,

    /// Number of tokens consumed for inference.
    pub tokens_consumed: Option<u64>,

    /// Content type for responses.
    pub content_type: Option<String>,
}

// =============================================================================
// ToolHandlerError
// =============================================================================

/// Errors that can occur during tool handler operations.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ToolHandlerError {
    /// Invalid arguments.
    #[error("invalid arguments: {reason}")]
    InvalidArgs {
        /// Reason for rejection.
        reason: String,
    },

    /// Arguments too large.
    #[error("arguments too large: {size} bytes (max {max})")]
    ArgsTooLarge {
        /// Actual size.
        size: usize,
        /// Maximum allowed size.
        max: usize,
    },

    /// Path validation failed.
    #[error("path validation failed: {path}: {reason}")]
    PathValidation {
        /// The invalid path.
        path: String,
        /// Reason for rejection.
        reason: String,
    },

    /// File not found.
    #[error("file not found: {path}")]
    FileNotFound {
        /// The missing path.
        path: String,
    },

    /// Permission denied.
    #[error("permission denied: {path}")]
    PermissionDenied {
        /// The path with denied access.
        path: String,
    },

    /// Execution failed.
    #[error("execution failed: {message}")]
    ExecutionFailed {
        /// Error message.
        message: String,
    },

    /// Timeout exceeded.
    #[error("timeout exceeded: {timeout_ms}ms")]
    Timeout {
        /// Configured timeout in milliseconds.
        timeout_ms: u64,
    },

    /// Network error.
    #[error("network error: {message}")]
    NetworkError {
        /// Error message.
        message: String,
    },

    /// I/O error.
    #[error("I/O error: {message}")]
    IoError {
        /// Error message.
        message: String,
    },

    /// Internal error.
    #[error("internal handler error: {message}")]
    Internal {
        /// Error message.
        message: String,
    },

    /// Output exceeded bounds (REQ-HEF-0010).
    ///
    /// Per RFC-0018 hardening requirements, handlers must fail hard when output
    /// exceeds configured bounds rather than truncating and returning success.
    #[error(
        "output too large: {bytes} bytes, {lines} lines (max {max_bytes} bytes, {max_lines} lines)"
    )]
    OutputTooLarge {
        /// Actual output size in bytes.
        bytes: usize,
        /// Actual output line count.
        lines: usize,
        /// Maximum allowed bytes.
        max_bytes: usize,
        /// Maximum allowed lines.
        max_lines: usize,
    },
}

impl ToolHandlerError {
    /// Returns the error kind as a string identifier.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::InvalidArgs { .. } => "invalid_args",
            Self::ArgsTooLarge { .. } => "args_too_large",
            Self::PathValidation { .. } => "path_validation",
            Self::FileNotFound { .. } => "file_not_found",
            Self::PermissionDenied { .. } => "permission_denied",
            Self::ExecutionFailed { .. } => "execution_failed",
            Self::Timeout { .. } => "timeout",
            Self::NetworkError { .. } => "network_error",
            Self::IoError { .. } => "io_error",
            Self::Internal { .. } => "internal",
            Self::OutputTooLarge { .. } => "output_too_large",
        }
    }

    /// Returns `true` if this error is retriable.
    #[must_use]
    pub const fn is_retriable(&self) -> bool {
        matches!(self, Self::Timeout { .. } | Self::NetworkError { .. })
    }
}

impl From<std::io::Error> for ToolHandlerError {
    fn from(err: std::io::Error) -> Self {
        Self::IoError {
            message: err.to_string(),
        }
    }
}

// =============================================================================
// ToolHandler Trait
// =============================================================================

/// Trait for tool handler implementations.
///
/// Tool handlers validate arguments and execute operations for a specific
/// tool class. They report actual resource consumption for budget tracking.
///
/// # Thread Safety
///
/// Handlers must be `Send + Sync` to be used with the async executor.
///
/// # Example
///
/// ```rust,ignore
/// use apm2_daemon::episode::tool_handler::{ToolHandler, ToolArgs, ToolResultData};
///
/// struct ReadFileHandler;
///
/// #[async_trait]
/// impl ToolHandler for ReadFileHandler {
///     fn tool_class(&self) -> ToolClass {
///         ToolClass::Read
///     }
///
///     async fn execute(&self, args: &ToolArgs) -> Result<ToolResultData, ToolHandlerError> {
///         // Validate and execute read operation
///     }
///
///     fn validate(&self, args: &ToolArgs) -> Result<(), ToolHandlerError> {
///         // Validate arguments before execution
///     }
/// }
/// ```
#[async_trait]
pub trait ToolHandler: Send + Sync + fmt::Debug {
    /// Returns the tool class this handler implements.
    fn tool_class(&self) -> ToolClass;

    /// Executes the tool with the given arguments.
    ///
    /// # Arguments
    ///
    /// * `args` - The validated tool arguments
    ///
    /// # Returns
    ///
    /// The result data including output and resource consumption.
    ///
    /// # Errors
    ///
    /// Returns an error if execution fails.
    async fn execute(&self, args: &ToolArgs) -> Result<ToolResultData, ToolHandlerError>;

    /// Validates the tool arguments before execution.
    ///
    /// This is called before `execute()` to catch invalid arguments early.
    ///
    /// # Arguments
    ///
    /// * `args` - The arguments to validate
    ///
    /// # Errors
    ///
    /// Returns an error if the arguments are invalid.
    fn validate(&self, args: &ToolArgs) -> Result<(), ToolHandlerError>;

    /// Returns the handler name for logging.
    fn name(&self) -> &'static str {
        "ToolHandler"
    }

    /// Returns the estimated resource consumption for the given arguments.
    ///
    /// This provides a pre-execution estimate for budget checking.
    /// The actual consumption may differ and is reported in the result.
    fn estimate_budget(&self, args: &ToolArgs) -> BudgetDelta {
        let _ = args;
        BudgetDelta::single_call()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tool_args_tool_class() {
        let read_args = ToolArgs::Read(ReadArgs {
            path: PathBuf::from("/workspace/file.rs"),
            offset: None,
            limit: None,
        });
        assert_eq!(read_args.tool_class(), ToolClass::Read);

        let write_args = ToolArgs::Write(WriteArgs {
            path: PathBuf::from("/workspace/file.rs"),
            content: Some(b"content".to_vec()),
            content_hash: None,
            create_parents: false,
            append: false,
        });
        assert_eq!(write_args.tool_class(), ToolClass::Write);

        let exec_args = ToolArgs::Execute(ExecuteArgs {
            command: "ls".to_string(),
            args: vec!["-la".to_string()],
            cwd: None,
            stdin: None,
            timeout_ms: Some(30_000),
        });
        assert_eq!(exec_args.tool_class(), ToolClass::Execute);
    }

    #[test]
    fn test_tool_args_estimated_size() {
        let args = ToolArgs::Read(ReadArgs {
            path: PathBuf::from("/workspace/file.rs"),
            offset: None,
            limit: None,
        });
        assert!(args.estimated_size() > 0);

        let args = ToolArgs::Write(WriteArgs {
            path: PathBuf::from("/workspace/file.rs"),
            content: Some(vec![0u8; 1000]),
            content_hash: None,
            create_parents: false,
            append: false,
        });
        assert!(args.estimated_size() >= 1000);
    }

    #[test]
    fn test_tool_result_data_success() {
        let result = ToolResultData::success(
            b"output".to_vec(),
            BudgetDelta::single_call(),
            Duration::from_millis(100),
        );

        assert!(result.success);
        assert_eq!(result.output, b"output");
        assert!(result.error_output.is_none());
        assert_eq!(result.exit_code, Some(0));
        assert_eq!(result.output_str(), Some("output"));
    }

    #[test]
    fn test_tool_result_data_failure() {
        let result = ToolResultData::failure(
            b"error message".to_vec(),
            Some(1),
            BudgetDelta::single_call(),
            Duration::from_millis(50),
        );

        assert!(!result.success);
        assert!(result.output.is_empty());
        assert!(result.error_output.is_some());
        assert_eq!(result.exit_code, Some(1));
    }

    #[test]
    fn test_tool_handler_error_kinds() {
        let err = ToolHandlerError::InvalidArgs {
            reason: "test".to_string(),
        };
        assert_eq!(err.kind(), "invalid_args");
        assert!(!err.is_retriable());

        let err = ToolHandlerError::Timeout { timeout_ms: 1000 };
        assert_eq!(err.kind(), "timeout");
        assert!(err.is_retriable());

        let err = ToolHandlerError::NetworkError {
            message: "connection refused".to_string(),
        };
        assert!(err.is_retriable());
    }

    #[test]
    fn test_tool_args_serialization() {
        let args = ToolArgs::Read(ReadArgs {
            path: PathBuf::from("/workspace/file.rs"),
            offset: Some(100),
            limit: Some(1000),
        });

        let json = serde_json::to_string(&args).unwrap();
        let deserialized: ToolArgs = serde_json::from_str(&json).unwrap();
        assert_eq!(args, deserialized);
    }

    #[test]
    fn test_execute_args_default() {
        let json = r#"{
            "type": "execute",
            "command": "ls"
        }"#;
        let args: ToolArgs = serde_json::from_str(json).unwrap();
        if let ToolArgs::Execute(exec) = args {
            assert_eq!(exec.command, "ls");
            assert!(exec.args.is_empty());
        } else {
            panic!("expected Execute args");
        }
    }

    #[test]
    fn test_network_args_default_method() {
        let json = r#"{
            "type": "network",
            "url": "https://example.com"
        }"#;
        let args: ToolArgs = serde_json::from_str(json).unwrap();
        if let ToolArgs::Network(net) = args {
            assert_eq!(net.method, "GET");
        } else {
            panic!("expected Network args");
        }
    }

    #[test]
    fn test_tool_handler_error_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let handler_err: ToolHandlerError = io_err.into();
        assert_eq!(handler_err.kind(), "io_error");
    }

    #[test]
    fn test_tool_args_artifact_class() {
        use super::*;
        let args = ToolArgs::Artifact(ArtifactArgs {
            stable_id: None,
            content_hash: Some([42u8; 32]),
            expected_hash: None,
            max_bytes: 1024,
            format: None,
        });
        assert_eq!(args.tool_class(), ToolClass::Artifact);
    }
}
