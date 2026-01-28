//! Stub tool handlers for core tool classes.
//!
//! This module provides stub implementations of the core tool handlers per
//! TCK-00165. These handlers validate arguments and return mock results,
//! serving as placeholders for future full implementations.
//!
//! # Implemented Handlers
//!
//! - `ReadFileHandler`: Stub for file read operations
//! - `WriteFileHandler`: Stub for file write operations
//! - `ExecuteHandler`: Stub for command execution
//!
//! # Security Model
//!
//! Even stub handlers perform basic validation:
//! - Argument type checking
//! - Path sanitization (reject `..` components)
//! - Size limit enforcement
//!
//! # Contract References
//!
//! - TCK-00165: Tool execution and budget charging
//! - CTR-1503: Path traversal prevention
//! - CTR-2609: Symlink metadata usage

use std::path::Path;
use std::time::Duration;

use async_trait::async_trait;

use super::decision::BudgetDelta;
use super::tool_class::ToolClass;
use super::tool_handler::{ToolArgs, ToolHandler, ToolHandlerError, ToolResultData};

// =============================================================================
// Path Validation Helper
// =============================================================================

/// Validates a path for security issues.
///
/// # Security
///
/// Per CTR-1503, rejects:
/// - Paths containing `..` components (directory traversal)
/// - Absolute paths (paths starting with `/` on Unix or drive letters on
///   Windows)
/// - Paths containing null bytes
///
/// All paths must be relative to the workspace root.
fn validate_path(path: &Path) -> Result<(), ToolHandlerError> {
    let path_str = path.to_string_lossy();

    // Reject absolute paths (CTR-1503 security fix)
    // This prevents access to system files like /etc/shadow
    if path.is_absolute() {
        return Err(ToolHandlerError::PathValidation {
            path: path_str.to_string(),
            reason: "absolute paths not allowed; use paths relative to workspace".to_string(),
        });
    }

    // Additional check for Windows-style absolute paths (C:\, D:\, etc.)
    // even on Unix systems (defense in depth)
    if path_str.len() >= 2 {
        let bytes = path_str.as_bytes();
        if bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
            return Err(ToolHandlerError::PathValidation {
                path: path_str.to_string(),
                reason: "absolute paths not allowed; use paths relative to workspace".to_string(),
            });
        }
    }

    // Reject parent directory traversal (CTR-1503)
    if path.components().any(|c| c.as_os_str() == "..") {
        return Err(ToolHandlerError::PathValidation {
            path: path_str.to_string(),
            reason: "path traversal ('..') not allowed".to_string(),
        });
    }

    // Reject null bytes
    if path_str.contains('\0') {
        return Err(ToolHandlerError::PathValidation {
            path: path_str.replace('\0', "\\0"),
            reason: "path cannot contain null bytes".to_string(),
        });
    }

    Ok(())
}

// =============================================================================
// ReadFileHandler
// =============================================================================

/// Stub handler for file read operations.
///
/// This handler validates read arguments and returns mock file contents.
/// The actual file system is not accessed in this stub implementation.
///
/// # Future Implementation
///
/// The full implementation will:
/// - Read actual file contents
/// - Respect offset and limit parameters
/// - Report actual I/O bytes consumed
/// - Handle symlinks safely (CTR-2609)
#[derive(Debug, Default)]
pub struct ReadFileHandler;

impl ReadFileHandler {
    /// Creates a new read file handler.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ToolHandler for ReadFileHandler {
    fn tool_class(&self) -> ToolClass {
        ToolClass::Read
    }

    async fn execute(&self, args: &ToolArgs) -> Result<ToolResultData, ToolHandlerError> {
        let ToolArgs::Read(read_args) = args else {
            return Err(ToolHandlerError::InvalidArgs {
                reason: "expected Read arguments".to_string(),
            });
        };

        // Stub: Return mock file contents based on path
        let path_str = read_args.path.to_string_lossy();
        let mock_content =
            format!("# Stub file content for: {path_str}\n# (ReadFileHandler stub)\n");
        let bytes = mock_content.into_bytes();
        let bytes_len = bytes.len() as u64;

        Ok(ToolResultData::success(
            bytes,
            BudgetDelta::single_call().with_bytes_io(bytes_len),
            Duration::from_millis(1), // Stub execution is fast
        ))
    }

    fn validate(&self, args: &ToolArgs) -> Result<(), ToolHandlerError> {
        let ToolArgs::Read(read_args) = args else {
            return Err(ToolHandlerError::InvalidArgs {
                reason: "expected Read arguments".to_string(),
            });
        };

        validate_path(&read_args.path)?;

        // Validate limit is reasonable
        if let Some(limit) = read_args.limit {
            if limit > 100 * 1024 * 1024 {
                // 100 MiB max
                return Err(ToolHandlerError::InvalidArgs {
                    reason: format!("read limit too large: {limit} bytes (max 100 MiB)"),
                });
            }
        }

        Ok(())
    }

    fn name(&self) -> &'static str {
        "ReadFileHandler"
    }

    fn estimate_budget(&self, args: &ToolArgs) -> BudgetDelta {
        let bytes = if let ToolArgs::Read(read_args) = args {
            read_args.limit.unwrap_or(4096) // Default estimate
        } else {
            4096
        };
        BudgetDelta::single_call().with_bytes_io(bytes)
    }
}

// =============================================================================
// WriteFileHandler
// =============================================================================

/// Stub handler for file write operations.
///
/// This handler validates write arguments and returns success without
/// actually writing to the file system.
///
/// # Future Implementation
///
/// The full implementation will:
/// - Write actual file contents atomically (CTR-1502)
/// - Create parent directories if requested
/// - Handle append mode
/// - Report actual I/O bytes consumed
#[derive(Debug, Default)]
pub struct WriteFileHandler;

impl WriteFileHandler {
    /// Creates a new write file handler.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ToolHandler for WriteFileHandler {
    fn tool_class(&self) -> ToolClass {
        ToolClass::Write
    }

    async fn execute(&self, args: &ToolArgs) -> Result<ToolResultData, ToolHandlerError> {
        let ToolArgs::Write(write_args) = args else {
            return Err(ToolHandlerError::InvalidArgs {
                reason: "expected Write arguments".to_string(),
            });
        };

        // Calculate bytes written
        let bytes_written = write_args.content.as_ref().map_or(0, Vec::len) as u64;

        // Stub: Return success without actually writing
        let path_str = write_args.path.to_string_lossy();
        let output = format!("Wrote {bytes_written} bytes to {path_str} (stub)");

        Ok(ToolResultData::success(
            output.into_bytes(),
            BudgetDelta::single_call().with_bytes_io(bytes_written),
            Duration::from_millis(1),
        ))
    }

    fn validate(&self, args: &ToolArgs) -> Result<(), ToolHandlerError> {
        let ToolArgs::Write(write_args) = args else {
            return Err(ToolHandlerError::InvalidArgs {
                reason: "expected Write arguments".to_string(),
            });
        };

        validate_path(&write_args.path)?;

        // Validate content size
        if let Some(ref content) = write_args.content {
            if content.len() > 100 * 1024 * 1024 {
                // 100 MiB max
                return Err(ToolHandlerError::InvalidArgs {
                    reason: format!("content too large: {} bytes (max 100 MiB)", content.len()),
                });
            }
        }

        // Must have either content or content_hash
        if write_args.content.is_none() && write_args.content_hash.is_none() {
            return Err(ToolHandlerError::InvalidArgs {
                reason: "either content or content_hash must be provided".to_string(),
            });
        }

        Ok(())
    }

    fn name(&self) -> &'static str {
        "WriteFileHandler"
    }

    fn estimate_budget(&self, args: &ToolArgs) -> BudgetDelta {
        let bytes = if let ToolArgs::Write(write_args) = args {
            write_args.content.as_ref().map_or(4096, Vec::len) as u64
        } else {
            4096
        };
        BudgetDelta::single_call().with_bytes_io(bytes)
    }
}

// =============================================================================
// ExecuteHandler
// =============================================================================

/// Stub handler for command execution.
///
/// This handler validates execute arguments and returns mock command output.
/// No actual commands are executed in this stub implementation.
///
/// # Future Implementation
///
/// The full implementation will:
/// - Execute commands in a sandboxed environment
/// - Capture stdout/stderr
/// - Enforce timeouts
/// - Report actual resource consumption
#[derive(Debug, Default)]
pub struct ExecuteHandler;

impl ExecuteHandler {
    /// Creates a new execute handler.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ToolHandler for ExecuteHandler {
    fn tool_class(&self) -> ToolClass {
        ToolClass::Execute
    }

    async fn execute(&self, args: &ToolArgs) -> Result<ToolResultData, ToolHandlerError> {
        let ToolArgs::Execute(exec_args) = args else {
            return Err(ToolHandlerError::InvalidArgs {
                reason: "expected Execute arguments".to_string(),
            });
        };

        // Stub: Return mock output without executing
        let cmd_str = format!("{} {}", exec_args.command, exec_args.args.join(" "));
        let output =
            format!("# Stub output for command: {cmd_str}\n# (ExecuteHandler stub)\nexit 0\n");

        let mut result = ToolResultData::success(
            output.into_bytes(),
            BudgetDelta::single_call()
                .with_wall_ms(10)
                .with_bytes_io(100),
            Duration::from_millis(10),
        );
        result.exit_code = Some(0);

        Ok(result)
    }

    fn validate(&self, args: &ToolArgs) -> Result<(), ToolHandlerError> {
        let ToolArgs::Execute(exec_args) = args else {
            return Err(ToolHandlerError::InvalidArgs {
                reason: "expected Execute arguments".to_string(),
            });
        };

        // Validate command is not empty
        if exec_args.command.is_empty() {
            return Err(ToolHandlerError::InvalidArgs {
                reason: "command cannot be empty".to_string(),
            });
        }

        // Validate command doesn't contain null bytes
        if exec_args.command.contains('\0') {
            return Err(ToolHandlerError::InvalidArgs {
                reason: "command cannot contain null bytes".to_string(),
            });
        }

        // Validate working directory if provided
        if let Some(ref cwd) = exec_args.cwd {
            validate_path(cwd)?;
        }

        // Validate timeout is reasonable
        if let Some(timeout_ms) = exec_args.timeout_ms {
            if timeout_ms > 3_600_000 {
                // 1 hour max
                return Err(ToolHandlerError::InvalidArgs {
                    reason: format!("timeout too large: {timeout_ms}ms (max 1 hour)"),
                });
            }
        }

        // Validate stdin size
        if let Some(ref stdin) = exec_args.stdin {
            if stdin.len() > 10 * 1024 * 1024 {
                // 10 MiB max
                return Err(ToolHandlerError::InvalidArgs {
                    reason: format!("stdin too large: {} bytes (max 10 MiB)", stdin.len()),
                });
            }
        }

        Ok(())
    }

    fn name(&self) -> &'static str {
        "ExecuteHandler"
    }

    fn estimate_budget(&self, args: &ToolArgs) -> BudgetDelta {
        let wall_ms = if let ToolArgs::Execute(exec_args) = args {
            exec_args.timeout_ms.unwrap_or(30_000).min(30_000)
        } else {
            30_000
        };
        BudgetDelta::single_call().with_wall_ms(wall_ms)
    }
}

// =============================================================================
// Handler Registry Helper
// =============================================================================

/// Registers all stub handlers with an executor.
///
/// This is a convenience function for setting up an executor with the
/// default stub handlers.
///
/// # Example
///
/// ```rust,ignore
/// use apm2_daemon::episode::executor::ToolExecutor;
/// use apm2_daemon::episode::handlers::register_stub_handlers;
///
/// let mut executor = ToolExecutor::new(tracker, cas);
/// register_stub_handlers(&mut executor).expect("handlers registered");
/// ```
pub fn register_stub_handlers(
    executor: &mut super::executor::ToolExecutor,
) -> Result<(), super::executor::ExecutorError> {
    executor.register_handler(Box::new(ReadFileHandler::new()))?;
    executor.register_handler(Box::new(WriteFileHandler::new()))?;
    executor.register_handler(Box::new(ExecuteHandler::new()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::episode::tool_handler::{ExecuteArgs, ReadArgs, WriteArgs};

    // =========================================================================
    // Path validation tests
    // =========================================================================

    #[test]
    fn test_validate_path_relative_ok() {
        let path = Path::new("workspace/src/main.rs");
        assert!(validate_path(path).is_ok());
    }

    #[test]
    fn test_validate_path_relative_nested_ok() {
        let path = Path::new("src/lib/module/file.rs");
        assert!(validate_path(path).is_ok());
    }

    #[test]
    fn test_validate_path_absolute_unix_rejected() {
        let path = Path::new("/etc/passwd");
        let result = validate_path(path);
        assert!(
            matches!(result, Err(ToolHandlerError::PathValidation { .. })),
            "Expected path validation error for absolute path"
        );
        if let Err(ToolHandlerError::PathValidation { reason, .. }) = result {
            assert!(
                reason.contains("absolute"),
                "Error should mention 'absolute': {reason}"
            );
        }
    }

    #[test]
    fn test_validate_path_absolute_shadow_rejected() {
        // Specific test for /etc/shadow (CTR-1503 bypass test)
        let path = Path::new("/etc/shadow");
        let result = validate_path(path);
        assert!(
            matches!(result, Err(ToolHandlerError::PathValidation { .. })),
            "Expected path validation error for /etc/shadow"
        );
    }

    #[test]
    fn test_validate_path_absolute_workspace_rejected() {
        // Even paths that look like workspace paths should be rejected if absolute
        let path = Path::new("/workspace/src/main.rs");
        let result = validate_path(path);
        assert!(
            matches!(result, Err(ToolHandlerError::PathValidation { .. })),
            "Expected path validation error for absolute workspace path"
        );
    }

    #[test]
    fn test_validate_path_windows_drive_rejected() {
        // Windows-style absolute paths should be rejected even on Unix
        let path = Path::new("C:\\Windows\\System32\\config\\SAM");
        let result = validate_path(path);
        assert!(
            matches!(result, Err(ToolHandlerError::PathValidation { .. })),
            "Expected path validation error for Windows drive path"
        );
    }

    #[test]
    fn test_validate_path_windows_drive_lowercase_rejected() {
        let path = Path::new("c:\\Users\\Admin\\secrets.txt");
        let result = validate_path(path);
        assert!(
            matches!(result, Err(ToolHandlerError::PathValidation { .. })),
            "Expected path validation error for lowercase Windows drive path"
        );
    }

    #[test]
    fn test_validate_path_traversal_rejected() {
        let path = Path::new("workspace/../etc/passwd");
        let result = validate_path(path);
        assert!(matches!(
            result,
            Err(ToolHandlerError::PathValidation { .. })
        ));
        if let Err(ToolHandlerError::PathValidation { reason, .. }) = result {
            assert!(
                reason.contains("traversal"),
                "Error should mention 'traversal': {reason}"
            );
        }
    }

    #[test]
    fn test_validate_path_null_byte_rejected() {
        let path = Path::new("workspace/file\0.txt");
        let result = validate_path(path);
        assert!(matches!(
            result,
            Err(ToolHandlerError::PathValidation { .. })
        ));
    }

    #[test]
    fn test_validate_path_current_dir_ok() {
        // Current directory reference is fine
        let path = Path::new("./src/main.rs");
        assert!(validate_path(path).is_ok());
    }

    #[test]
    fn test_validate_path_single_file_ok() {
        let path = Path::new("Cargo.toml");
        assert!(validate_path(path).is_ok());
    }

    // =========================================================================
    // ReadFileHandler tests
    // =========================================================================

    #[tokio::test]
    async fn test_read_handler_execute() {
        let handler = ReadFileHandler::new();
        let args = ToolArgs::Read(ReadArgs {
            path: PathBuf::from("workspace/file.rs"),
            offset: None,
            limit: None,
        });

        let result = handler.execute(&args).await.unwrap();
        assert!(result.success);
        assert!(!result.output.is_empty());
    }

    #[test]
    fn test_read_handler_validate_ok() {
        let handler = ReadFileHandler::new();
        let args = ToolArgs::Read(ReadArgs {
            path: PathBuf::from("workspace/file.rs"),
            offset: None,
            limit: Some(1024),
        });

        assert!(handler.validate(&args).is_ok());
    }

    #[test]
    fn test_read_handler_validate_absolute_rejected() {
        let handler = ReadFileHandler::new();
        let args = ToolArgs::Read(ReadArgs {
            path: PathBuf::from("/etc/passwd"),
            offset: None,
            limit: None,
        });

        let result = handler.validate(&args);
        assert!(result.is_err(), "Absolute paths should be rejected");
    }

    #[test]
    fn test_read_handler_validate_traversal() {
        let handler = ReadFileHandler::new();
        let args = ToolArgs::Read(ReadArgs {
            path: PathBuf::from("workspace/../etc/passwd"),
            offset: None,
            limit: None,
        });

        assert!(handler.validate(&args).is_err());
    }

    #[test]
    fn test_read_handler_validate_limit_too_large() {
        let handler = ReadFileHandler::new();
        let args = ToolArgs::Read(ReadArgs {
            path: PathBuf::from("workspace/file.rs"),
            offset: None,
            limit: Some(200 * 1024 * 1024), // 200 MiB
        });

        assert!(handler.validate(&args).is_err());
    }

    #[test]
    fn test_read_handler_wrong_args_type() {
        let handler = ReadFileHandler::new();
        let args = ToolArgs::Execute(ExecuteArgs {
            command: "ls".to_string(),
            args: vec![],
            cwd: None,
            stdin: None,
            timeout_ms: None,
        });

        assert!(handler.validate(&args).is_err());
    }

    // =========================================================================
    // WriteFileHandler tests
    // =========================================================================

    #[tokio::test]
    async fn test_write_handler_execute() {
        let handler = WriteFileHandler::new();
        let args = ToolArgs::Write(WriteArgs {
            path: PathBuf::from("workspace/output.txt"),
            content: Some(b"hello world".to_vec()),
            content_hash: None,
            create_parents: false,
            append: false,
        });

        let result = handler.execute(&args).await.unwrap();
        assert!(result.success);
        assert!(result.budget_consumed.bytes_io > 0);
    }

    #[test]
    fn test_write_handler_validate_ok() {
        let handler = WriteFileHandler::new();
        let args = ToolArgs::Write(WriteArgs {
            path: PathBuf::from("workspace/output.txt"),
            content: Some(b"content".to_vec()),
            content_hash: None,
            create_parents: true,
            append: false,
        });

        assert!(handler.validate(&args).is_ok());
    }

    #[test]
    fn test_write_handler_validate_absolute_rejected() {
        let handler = WriteFileHandler::new();
        let args = ToolArgs::Write(WriteArgs {
            path: PathBuf::from("/etc/crontab"),
            content: Some(b"malicious".to_vec()),
            content_hash: None,
            create_parents: false,
            append: false,
        });

        let result = handler.validate(&args);
        assert!(result.is_err(), "Absolute paths should be rejected");
    }

    #[test]
    fn test_write_handler_validate_no_content() {
        let handler = WriteFileHandler::new();
        let args = ToolArgs::Write(WriteArgs {
            path: PathBuf::from("workspace/output.txt"),
            content: None,
            content_hash: None,
            create_parents: false,
            append: false,
        });

        assert!(handler.validate(&args).is_err());
    }

    #[test]
    fn test_write_handler_validate_content_too_large() {
        let handler = WriteFileHandler::new();
        let args = ToolArgs::Write(WriteArgs {
            path: PathBuf::from("workspace/output.txt"),
            content: Some(vec![0u8; 200 * 1024 * 1024]), // 200 MiB
            content_hash: None,
            create_parents: false,
            append: false,
        });

        assert!(handler.validate(&args).is_err());
    }

    // =========================================================================
    // ExecuteHandler tests
    // =========================================================================

    #[tokio::test]
    async fn test_execute_handler_execute() {
        let handler = ExecuteHandler::new();
        let args = ToolArgs::Execute(ExecuteArgs {
            command: "ls".to_string(),
            args: vec!["-la".to_string()],
            cwd: None,
            stdin: None,
            timeout_ms: Some(5000),
        });

        let result = handler.execute(&args).await.unwrap();
        assert!(result.success);
        assert_eq!(result.exit_code, Some(0));
    }

    #[test]
    fn test_execute_handler_validate_ok() {
        let handler = ExecuteHandler::new();
        let args = ToolArgs::Execute(ExecuteArgs {
            command: "ls".to_string(),
            args: vec!["-la".to_string()],
            cwd: Some(PathBuf::from("workspace")),
            stdin: None,
            timeout_ms: Some(30_000),
        });

        assert!(handler.validate(&args).is_ok());
    }

    #[test]
    fn test_execute_handler_validate_cwd_absolute_rejected() {
        let handler = ExecuteHandler::new();
        let args = ToolArgs::Execute(ExecuteArgs {
            command: "ls".to_string(),
            args: vec![],
            cwd: Some(PathBuf::from("/etc")),
            stdin: None,
            timeout_ms: None,
        });

        let result = handler.validate(&args);
        assert!(result.is_err(), "Absolute cwd paths should be rejected");
    }

    #[test]
    fn test_execute_handler_validate_empty_command() {
        let handler = ExecuteHandler::new();
        let args = ToolArgs::Execute(ExecuteArgs {
            command: String::new(),
            args: vec![],
            cwd: None,
            stdin: None,
            timeout_ms: None,
        });

        assert!(handler.validate(&args).is_err());
    }

    #[test]
    fn test_execute_handler_validate_timeout_too_large() {
        let handler = ExecuteHandler::new();
        let args = ToolArgs::Execute(ExecuteArgs {
            command: "sleep".to_string(),
            args: vec!["infinity".to_string()],
            cwd: None,
            stdin: None,
            timeout_ms: Some(10_000_000), // Too large
        });

        assert!(handler.validate(&args).is_err());
    }

    #[test]
    fn test_execute_handler_validate_cwd_traversal() {
        let handler = ExecuteHandler::new();
        let args = ToolArgs::Execute(ExecuteArgs {
            command: "ls".to_string(),
            args: vec![],
            cwd: Some(PathBuf::from("workspace/../etc")),
            stdin: None,
            timeout_ms: None,
        });

        assert!(handler.validate(&args).is_err());
    }

    // =========================================================================
    // Handler properties tests
    // =========================================================================

    #[test]
    fn test_handler_tool_classes() {
        assert_eq!(ReadFileHandler::new().tool_class(), ToolClass::Read);
        assert_eq!(WriteFileHandler::new().tool_class(), ToolClass::Write);
        assert_eq!(ExecuteHandler::new().tool_class(), ToolClass::Execute);
    }

    #[test]
    fn test_handler_names() {
        assert_eq!(ReadFileHandler::new().name(), "ReadFileHandler");
        assert_eq!(WriteFileHandler::new().name(), "WriteFileHandler");
        assert_eq!(ExecuteHandler::new().name(), "ExecuteHandler");
    }

    #[test]
    fn test_handler_budget_estimates() {
        let read_args = ToolArgs::Read(ReadArgs {
            path: PathBuf::from("file"),
            offset: None,
            limit: Some(8192),
        });
        let estimate = ReadFileHandler::new().estimate_budget(&read_args);
        assert_eq!(estimate.tool_calls, 1);
        assert_eq!(estimate.bytes_io, 8192);

        let write_args = ToolArgs::Write(WriteArgs {
            path: PathBuf::from("file"),
            content: Some(vec![0u8; 1000]),
            content_hash: None,
            create_parents: false,
            append: false,
        });
        let estimate = WriteFileHandler::new().estimate_budget(&write_args);
        assert_eq!(estimate.bytes_io, 1000);

        let exec_args = ToolArgs::Execute(ExecuteArgs {
            command: "ls".to_string(),
            args: vec![],
            cwd: None,
            stdin: None,
            timeout_ms: Some(5000),
        });
        let estimate = ExecuteHandler::new().estimate_budget(&exec_args);
        assert_eq!(estimate.wall_ms, 5000);
    }
}
