//! Real tool handlers for core tool classes (TCK-00291).
//!
//! This module provides real implementations of the core tool handlers per
//! TCK-00291. These handlers perform actual I/O and command execution with
//! strict bounds and security controls.
//!
//! # Implemented Handlers
//!
//! - `ReadFileHandler`: Reads file contents with bounds and offset support
//! - `WriteFileHandler`: Writes files atomically with size limits
//! - `ExecuteHandler`: Executes commands in a sandboxed environment
//!
//! # Security Model
//!
//! - **Path Traversal**: All paths must be relative to the workspace root.
//!   Absolute paths and `..` components are rejected (CTR-1503).
//! - **Symlink Safety**: All paths are resolved via canonicalization to prevent
//!   symlink-based sandbox escapes.
//! - **Root Confinement**: Handlers are confined to a configurable root
//!   directory (defaulting to CWD).
//! - **Resource Limits**:
//!   - Read limit: 100 MiB (default 10 MiB)
//!   - Write limit: 100 MiB
//!   - Execution timeout: 1 hour (default 30s)
//!   - Output limit: `MAX_TOOL_OUTPUT_SIZE` (10 MB)
//! - **Atomic Writes**: File updates use write-to-temp-then-rename pattern.
//! - **Fail-Closed**: Errors during I/O or execution result in explicit
//!   failure.
//!
//! # Contract References
//!
//! - TCK-00291: Real tool handler implementation
//! - CTR-1503: Path traversal prevention
//! - CTR-1502: Atomic file updates

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

use super::decision::{BudgetDelta, MAX_TOOL_OUTPUT_SIZE};
use super::executor::ContentAddressedStore;
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

/// Validates that a resolved (canonicalized) path is within the workspace root.
///
/// # Security
///
/// This function prevents symlink-based sandbox escapes by verifying that the
/// resolved path (after following all symlinks) is still within the workspace
/// root directory. This is critical because an attacker could create a symlink
/// like `workspace/escape -> /etc/shadow` and bypass basic path validation.
///
/// # Arguments
///
/// * `resolved_path` - The canonicalized path (symlinks resolved)
/// * `root` - The workspace root directory (must also be canonicalized)
///
/// # Returns
///
/// Returns `Ok(())` if the path is within the root, or an error if it escapes.
fn validate_resolved_path_within_root(
    resolved_path: &Path,
    root: &Path,
) -> Result<(), ToolHandlerError> {
    // Check if the resolved path starts with the root path
    if !resolved_path.starts_with(root) {
        return Err(ToolHandlerError::PathValidation {
            path: resolved_path.display().to_string(),
            reason: format!(
                "resolved path escapes workspace root (symlink sandbox escape detected); \
                 resolved to '{}' which is outside root '{}'",
                resolved_path.display(),
                root.display()
            ),
        });
    }
    Ok(())
}

// =============================================================================
// ReadFileHandler
// =============================================================================

/// Real handler for file read operations.
///
/// This handler reads actual file contents from the filesystem, enforcing
/// strict bounds and path validation within a configured root.
///
/// # Security
///
/// - Validates paths are relative and free of traversal attacks
/// - Resolves paths relative to the configured root (default CWD)
/// - Enforces read limit (default 10MB, max 100MB)
/// - Respects offset for pagination
#[derive(Debug)]
pub struct ReadFileHandler {
    root: PathBuf,
}

impl Default for ReadFileHandler {
    fn default() -> Self {
        Self {
            root: PathBuf::from("."),
        }
    }
}

impl ReadFileHandler {
    /// Creates a new read file handler using CWD as root.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a new read file handler with a specific root directory.
    #[must_use]
    pub fn with_root(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }
}

#[async_trait]
impl ToolHandler for ReadFileHandler {
    fn tool_class(&self) -> ToolClass {
        ToolClass::Read
    }

    async fn execute(&self, args: &ToolArgs) -> Result<ToolResultData, ToolHandlerError> {
        // Validate arguments first (MAJOR 1 fix)
        self.validate(args)?;

        let ToolArgs::Read(read_args) = args else {
            return Err(ToolHandlerError::InvalidArgs {
                reason: "expected Read arguments".to_string(),
            });
        };

        // Start timing I/O operations (MAJOR 2 fix)
        let io_start = Instant::now();

        // Resolve path relative to root
        let full_path = self.root.join(&read_args.path);

        // Canonicalize root for comparison (BLOCKER 1 fix: symlink-aware validation)
        let canonical_root =
            std::fs::canonicalize(&self.root).map_err(|e| ToolHandlerError::ExecutionFailed {
                message: format!(
                    "failed to canonicalize root '{}': {}",
                    self.root.display(),
                    e
                ),
            })?;

        // Canonicalize the target path to resolve symlinks
        let canonical_path =
            std::fs::canonicalize(&full_path).map_err(|e| ToolHandlerError::ExecutionFailed {
                message: format!(
                    "failed to canonicalize path '{}': {}",
                    full_path.display(),
                    e
                ),
            })?;

        // Verify the resolved path is still within the workspace root
        validate_resolved_path_within_root(&canonical_path, &canonical_root)?;

        // Open file (use canonical path for safety)
        let mut file = tokio::fs::File::open(&canonical_path).await.map_err(|e| {
            ToolHandlerError::ExecutionFailed {
                message: format!("failed to open file '{}': {}", full_path.display(), e),
            }
        })?;

        // Seek if offset provided
        if let Some(offset) = read_args.offset {
            file.seek(std::io::SeekFrom::Start(offset))
                .await
                .map_err(|e| ToolHandlerError::ExecutionFailed {
                    message: format!("failed to seek: {e}"),
                })?;
        }

        // Determine read limit (default 10MB)
        let limit = read_args.limit.unwrap_or(10 * 1024 * 1024);

        // Read content with limit
        let mut buffer = Vec::new();
        let bytes_read = file
            .take(limit)
            .read_to_end(&mut buffer)
            .await
            .map_err(|e| ToolHandlerError::ExecutionFailed {
                message: format!("failed to read: {e}"),
            })?;

        // Capture actual I/O duration (MAJOR 2 fix)
        let io_duration = io_start.elapsed();

        Ok(ToolResultData::success(
            buffer,
            BudgetDelta::single_call().with_bytes_io(bytes_read as u64),
            io_duration,
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

/// Real handler for file write operations.
///
/// This handler writes content to the filesystem, enforcing atomicity and
/// size limits within a configured root.
///
/// # Security
///
/// - Validates paths are relative and free of traversal attacks
/// - Resolves paths relative to the configured root (default CWD)
/// - Enforces write size limit (100MB)
/// - Uses atomic write pattern (write-to-temp + rename) for non-append writes
///   (CTR-1502)
/// - Creates parent directories if requested
#[derive(Debug)]
pub struct WriteFileHandler {
    root: PathBuf,
}

impl Default for WriteFileHandler {
    fn default() -> Self {
        Self {
            root: PathBuf::from("."),
        }
    }
}

impl WriteFileHandler {
    /// Creates a new write file handler using CWD as root.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a new write file handler with a specific root directory.
    #[must_use]
    pub fn with_root(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }
}

#[async_trait]
impl ToolHandler for WriteFileHandler {
    fn tool_class(&self) -> ToolClass {
        ToolClass::Write
    }

    async fn execute(&self, args: &ToolArgs) -> Result<ToolResultData, ToolHandlerError> {
        // Validate arguments first (MAJOR 1 fix)
        self.validate(args)?;

        let ToolArgs::Write(write_args) = args else {
            return Err(ToolHandlerError::InvalidArgs {
                reason: "expected Write arguments".to_string(),
            });
        };

        // Start timing I/O operations (MAJOR 2 fix)
        let io_start = Instant::now();

        // Resolve path relative to root
        let full_path = self.root.join(&write_args.path);

        // Create parent directories if requested
        if write_args.create_parents {
            if let Some(parent) = full_path.parent() {
                tokio::fs::create_dir_all(parent).await.map_err(|e| {
                    ToolHandlerError::ExecutionFailed {
                        message: format!("failed to create parent directories: {e}"),
                    }
                })?;
            }
        }

        // Canonicalize root for comparison (BLOCKER 1 fix: symlink-aware validation)
        let canonical_root =
            std::fs::canonicalize(&self.root).map_err(|e| ToolHandlerError::ExecutionFailed {
                message: format!(
                    "failed to canonicalize root '{}': {}",
                    self.root.display(),
                    e
                ),
            })?;

        // For writes, we need to check if the target path (or its parent for new files)
        // would resolve outside the workspace. For existing files that are symlinks,
        // we canonicalize and check. For new files, we canonicalize the parent
        // directory.
        if full_path.exists() {
            // Target exists - canonicalize it to check for symlink escape
            let canonical_path = std::fs::canonicalize(&full_path).map_err(|e| {
                ToolHandlerError::ExecutionFailed {
                    message: format!(
                        "failed to canonicalize path '{}': {}",
                        full_path.display(),
                        e
                    ),
                }
            })?;
            validate_resolved_path_within_root(&canonical_path, &canonical_root)?;
        } else {
            // Target doesn't exist - canonicalize parent directory
            if let Some(parent) = full_path.parent() {
                if parent.exists() {
                    let canonical_parent = std::fs::canonicalize(parent).map_err(|e| {
                        ToolHandlerError::ExecutionFailed {
                            message: format!(
                                "failed to canonicalize parent '{}': {}",
                                parent.display(),
                                e
                            ),
                        }
                    })?;
                    validate_resolved_path_within_root(&canonical_parent, &canonical_root)?;
                }
            }
        }

        let content = write_args.content.as_deref().unwrap_or(&[]);
        let bytes_written = content.len() as u64;

        if write_args.append {
            // Append mode: cannot be strictly atomic, but standard O_APPEND is safe
            // for appends
            let mut file = tokio::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .append(true)
                .open(&full_path)
                .await
                .map_err(|e| ToolHandlerError::ExecutionFailed {
                    message: format!("failed to open file for append: {e}"),
                })?;

            file.write_all(content)
                .await
                .map_err(|e| ToolHandlerError::ExecutionFailed {
                    message: format!("failed to append content: {e}"),
                })?;
        } else {
            // Overwrite mode: use atomic write pattern (CTR-1502)
            // 1. Write to .tmp.<uuid>
            // 2. Rename to target path
            let file_name = full_path
                .file_name()
                .ok_or_else(|| ToolHandlerError::InvalidArgs {
                    reason: "invalid file path".to_string(),
                })?
                .to_string_lossy();

            let tmp_name = format!(".{}.tmp.{}", file_name, uuid::Uuid::new_v4());
            let tmp_path = full_path
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join(tmp_name);

            // Write to temp file
            if let Err(e) = tokio::fs::write(&tmp_path, content).await {
                // Try to clean up temp file on error
                let _ = tokio::fs::remove_file(&tmp_path).await;
                return Err(ToolHandlerError::ExecutionFailed {
                    message: format!("failed to write temp file: {e}"),
                });
            }

            // Atomic rename
            if let Err(e) = tokio::fs::rename(&tmp_path, &full_path).await {
                // Try to clean up temp file on error
                let _ = tokio::fs::remove_file(&tmp_path).await;
                return Err(ToolHandlerError::ExecutionFailed {
                    message: format!("failed to rename temp file to target: {e}"),
                });
            }
        }

        // Capture actual I/O duration (MAJOR 2 fix)
        let io_duration = io_start.elapsed();

        let output = format!(
            "Successfully wrote {} bytes to {}",
            bytes_written,
            write_args.path.display()
        );

        Ok(ToolResultData::success(
            output.into_bytes(),
            BudgetDelta::single_call().with_bytes_io(bytes_written),
            io_duration,
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

/// Real handler for command execution.
///
/// This handler executes commands in a sandboxed environment (restricted to
/// CWD/workspace), enforces timeouts, and bounds output capture.
///
/// # Security
///
/// - **Sandbox**: Commands execute in specified CWD (validated relative path),
///   anchored to the configured root.
/// - **Timeout**: Enforced per-execution timeout (default 30s, max 1h).
/// - **Output**: Stdout/Stderr captured up to `MAX_TOOL_OUTPUT_SIZE`.
/// - **Input**: Stdin pipe supported with size limits.
#[derive(Debug)]
pub struct ExecuteHandler {
    root: PathBuf,
}

impl Default for ExecuteHandler {
    fn default() -> Self {
        Self {
            root: PathBuf::from("."),
        }
    }
}

impl ExecuteHandler {
    /// Creates a new execute handler using CWD as root.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a new execute handler with a specific root directory.
    #[must_use]
    pub fn with_root(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }
}

#[async_trait]
impl ToolHandler for ExecuteHandler {
    fn tool_class(&self) -> ToolClass {
        ToolClass::Execute
    }

    async fn execute(&self, args: &ToolArgs) -> Result<ToolResultData, ToolHandlerError> {
        // Validate arguments first (MAJOR 1 fix)
        self.validate(args)?;

        let ToolArgs::Execute(exec_args) = args else {
            return Err(ToolHandlerError::InvalidArgs {
                reason: "expected Execute arguments".to_string(),
            });
        };

        // Start timing execution (MAJOR 2 fix)
        let exec_start = Instant::now();

        let mut cmd = tokio::process::Command::new(&exec_args.command);
        cmd.args(&exec_args.args);

        // Set working directory with symlink-aware validation (sandbox escape fix)
        // Canonicalize root for comparison
        let canonical_root =
            std::fs::canonicalize(&self.root).map_err(|e| ToolHandlerError::ExecutionFailed {
                message: format!(
                    "failed to canonicalize root '{}': {}",
                    self.root.display(),
                    e
                ),
            })?;

        // If cwd is provided, it's relative to root.
        // If not provided, use root as CWD.
        // In either case, we must validate the resolved path stays within the
        // workspace.
        let target_cwd = exec_args
            .cwd
            .as_ref()
            .map_or_else(|| self.root.clone(), |cwd| self.root.join(cwd));

        // Canonicalize the target cwd to resolve symlinks
        let canonical_cwd =
            std::fs::canonicalize(&target_cwd).map_err(|e| ToolHandlerError::ExecutionFailed {
                message: format!(
                    "failed to canonicalize cwd '{}': {}",
                    target_cwd.display(),
                    e
                ),
            })?;

        // Verify the resolved cwd is still within the workspace root
        validate_resolved_path_within_root(&canonical_cwd, &canonical_root)?;

        cmd.current_dir(&canonical_cwd);

        // Configure pipes
        cmd.stdin(Stdio::piped());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        // Kill child on drop to prevent orphan processes if future is cancelled
        cmd.kill_on_drop(true);

        let mut child = cmd.spawn().map_err(|e| ToolHandlerError::ExecutionFailed {
            message: format!("failed to spawn command: {e}"),
        })?;

        // Write stdin if provided, then close stdin pipe
        if let Some(ref input) = exec_args.stdin {
            if let Some(mut stdin) = child.stdin.take() {
                if let Err(e) = stdin.write_all(input).await {
                    // Failing to write stdin isn't always fatal (e.g. process exited early),
                    // but we should probably report it or at least not crash.
                    // For now, we'll return error to be safe.
                    let _ = child.kill().await;
                    return Err(ToolHandlerError::ExecutionFailed {
                        message: format!("failed to write stdin: {e}"),
                    });
                }
                // stdin is dropped here, closing the pipe
            }
        } else {
            // Close stdin even if no input provided
            drop(child.stdin.take());
        }

        let timeout_ms = exec_args.timeout_ms.unwrap_or(30_000);
        let timeout = Duration::from_millis(timeout_ms);

        // BLOCKER 2 FIX: Manual bounded pipe reading instead of wait_with_output()
        // This prevents OOM from processes that emit gigabytes of output before
        // timeout. We read stdout and stderr concurrently with bounded buffers.

        let mut stdout = child
            .stdout
            .take()
            .ok_or_else(|| ToolHandlerError::ExecutionFailed {
                message: "failed to capture stdout".to_string(),
            })?;
        let mut stderr = child
            .stderr
            .take()
            .ok_or_else(|| ToolHandlerError::ExecutionFailed {
                message: "failed to capture stderr".to_string(),
            })?;

        // Each stream gets half the budget to prevent one stream from starving the
        // other
        let per_stream_limit = MAX_TOOL_OUTPUT_SIZE / 2;

        // Read stdout with bounded buffer
        let stdout_future = async {
            let mut buf = Vec::new();
            let mut chunk = vec![0u8; 64 * 1024]; // 64KB chunks
            loop {
                match stdout.read(&mut chunk).await {
                    Ok(0) | Err(_) => break, // EOF or read error
                    Ok(n) => {
                        if buf.len() + n > per_stream_limit {
                            // Take only what fits
                            let remaining = per_stream_limit.saturating_sub(buf.len());
                            buf.extend_from_slice(&chunk[..remaining]);
                            return (buf, true); // exceeded
                        }
                        buf.extend_from_slice(&chunk[..n]);
                    },
                }
            }
            (buf, false)
        };

        // Read stderr with bounded buffer
        let stderr_future = async {
            let mut buf = Vec::new();
            let mut chunk = vec![0u8; 64 * 1024]; // 64KB chunks
            loop {
                match stderr.read(&mut chunk).await {
                    Ok(0) | Err(_) => break, // EOF or read error
                    Ok(n) => {
                        if buf.len() + n > per_stream_limit {
                            let remaining = per_stream_limit.saturating_sub(buf.len());
                            buf.extend_from_slice(&chunk[..remaining]);
                            return (buf, true); // exceeded
                        }
                        buf.extend_from_slice(&chunk[..n]);
                    },
                }
            }
            (buf, false)
        };

        // Wait for process with bounded output reading
        let read_result = tokio::time::timeout(timeout, async {
            // Run all three concurrently: stdout read, stderr read, and process wait
            let (stdout_result, stderr_result, wait_result) =
                tokio::join!(stdout_future, stderr_future, child.wait());

            let (stdout_buf, stdout_exceeded) = stdout_result;
            let (stderr_buf, stderr_exceeded) = stderr_result;
            let output_exceeded = stdout_exceeded || stderr_exceeded;

            match wait_result {
                Ok(status) => Ok((stdout_buf, stderr_buf, Some(status), output_exceeded)),
                Err(e) => Err(ToolHandlerError::ExecutionFailed {
                    message: format!("failed to wait for process: {e}"),
                }),
            }
        })
        .await;

        // Capture actual execution duration (MAJOR 2 fix)
        let exec_duration = exec_start.elapsed();

        match read_result {
            Ok(Ok((stdout_buf, stderr_buf, maybe_status, output_exceeded))) => {
                let stdout_len = stdout_buf.len();
                let stderr_len = stderr_buf.len();

                let mut combined_output = stdout_buf;
                if !stderr_buf.is_empty() {
                    combined_output.extend_from_slice(b"\n--- stderr ---\n");
                    combined_output.extend_from_slice(&stderr_buf);
                }

                if output_exceeded {
                    combined_output
                        .extend_from_slice(b"\n[Output truncated: exceeded maximum size limit]");
                }

                // Truncate duration to u64::MAX if it somehow exceeds (practically impossible)
                #[allow(clippy::cast_possible_truncation)]
                let wall_ms = exec_duration.as_millis().min(u128::from(u64::MAX)) as u64;

                let mut result = ToolResultData::success(
                    combined_output,
                    BudgetDelta::single_call()
                        .with_wall_ms(wall_ms)
                        .with_bytes_io((stdout_len + stderr_len) as u64),
                    exec_duration,
                );
                result.exit_code = maybe_status.and_then(|s| s.code());
                Ok(result)
            },
            Ok(Err(e)) => Err(e),
            Err(_) => {
                // Timeout. Kill the child process.
                let _ = child.kill().await;
                Err(ToolHandlerError::ExecutionFailed {
                    message: format!("command timed out after {timeout_ms}ms"),
                })
            },
        }
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
// GitOperationHandler (REQ-HEF-0010)
// =============================================================================

/// Hardened handler for git operations per REQ-HEF-0010.
///
/// This handler implements strict security controls for git operations:
///
/// # Allowed Operations
///
/// - `diff`: Show changes between commits, commit and working tree, etc.
/// - `status`: Show the working tree status (porcelain v1 format).
///
/// All other operations are rejected with `InvalidArgs`.
///
/// # Security Controls
///
/// - **Operation Allowlist**: Only "diff" and "status" are permitted.
/// - **Flag Rejection**: Args starting with `-` are rejected as potential
///   policy bypass vectors. Only pathspecs are allowed.
/// - **Pathspec Validation**: Pathspecs must be relative paths within
///   workspace.
/// - **Fixed Command Construction**: No user-controlled flags are passed.
/// - **Non-Interactive Mode**: `GIT_TERMINAL_PROMPT=0` prevents prompts.
/// - **Bounded Output**: Hard failure with `OutputTooLarge` if output exceeds
///   limits (diff: 256KB / 4000 lines; status: 16KB / 500 lines).
/// - **Timeout**: 30 second timeout to prevent hanging.
/// - **Repository Verification**: Confirms `.git` directory exists.
///
/// # Contract References
///
/// - REQ-HEF-0010: Tool handler hardening requirements
/// - TCK-00313: `GitOperation` + `ArtifactFetch` handler hardening
#[derive(Debug)]
pub struct GitOperationHandler {
    root: PathBuf,
}

impl Default for GitOperationHandler {
    fn default() -> Self {
        Self {
            root: PathBuf::from("."),
        }
    }
}

/// Git operation timeout in milliseconds (30 seconds).
const GIT_TIMEOUT_MS: u64 = 30_000;

impl GitOperationHandler {
    /// Creates a new git operation handler using CWD as root.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a new git operation handler with a specific root directory.
    #[must_use]
    pub fn with_root(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Validates that args contains only valid pathspecs (no flags).
    fn validate_args_as_pathspecs(args: &[String]) -> Result<(), ToolHandlerError> {
        for arg in args {
            // Reject any argument that looks like a flag
            if arg.starts_with('-') {
                return Err(ToolHandlerError::InvalidArgs {
                    reason: format!("git arg '{arg}' looks like a flag; only pathspecs allowed"),
                });
            }

            // Validate as a relative path within workspace
            let path = Path::new(arg);
            validate_path(path)?;
        }
        Ok(())
    }

    /// Counts lines in a byte buffer.
    #[allow(clippy::naive_bytecount)] // bytecount crate not needed for small buffers
    fn count_lines(data: &[u8]) -> usize {
        data.iter().filter(|&&b| b == b'\n').count()
    }
}

#[async_trait]
impl ToolHandler for GitOperationHandler {
    fn tool_class(&self) -> ToolClass {
        ToolClass::Git
    }

    async fn execute(&self, args: &ToolArgs) -> Result<ToolResultData, ToolHandlerError> {
        use tokio::io::AsyncReadExt;

        use super::tool_handler::{
            GIT_DIFF_MAX_BYTES, GIT_DIFF_MAX_LINES, GIT_STATUS_MAX_BYTES, GIT_STATUS_MAX_LINES,
        };

        // Validate arguments first
        self.validate(args)?;

        let ToolArgs::Git(git_args) = args else {
            return Err(ToolHandlerError::InvalidArgs {
                reason: "expected Git arguments".to_string(),
            });
        };

        let exec_start = Instant::now();

        // Determine working directory
        let work_dir = git_args
            .repo_path
            .as_ref()
            .map_or_else(|| self.root.clone(), |p| self.root.join(p));

        // Canonicalize root for comparison
        let canonical_root =
            std::fs::canonicalize(&self.root).map_err(|e| ToolHandlerError::ExecutionFailed {
                message: format!(
                    "failed to canonicalize root '{}': {}",
                    self.root.display(),
                    e
                ),
            })?;

        // Canonicalize the working directory
        let canonical_work_dir =
            std::fs::canonicalize(&work_dir).map_err(|e| ToolHandlerError::ExecutionFailed {
                message: format!(
                    "failed to canonicalize work dir '{}': {}",
                    work_dir.display(),
                    e
                ),
            })?;

        // Verify the working directory is within the workspace root
        validate_resolved_path_within_root(&canonical_work_dir, &canonical_root)?;

        // Verify .git exists (must be a git repository)
        let git_dir = canonical_work_dir.join(".git");
        if !git_dir.exists() {
            return Err(ToolHandlerError::ExecutionFailed {
                message: format!("'{}' is not a git repository", work_dir.display()),
            });
        }

        let operation = git_args.operation.to_lowercase();

        let (max_bytes, max_lines) = match operation.as_str() {
            "diff" => (GIT_DIFF_MAX_BYTES, GIT_DIFF_MAX_LINES),
            "status" => (GIT_STATUS_MAX_BYTES, GIT_STATUS_MAX_LINES),
            _ => unreachable!("validate() already rejected unknown operations"),
        };

        // Build the git command with hardened options
        let mut cmd = tokio::process::Command::new("git");
        // Clear inherited environment to prevent scope overrides (PROC-ENV)
        cmd.env_clear();
        if let Some(path) = std::env::var_os("PATH") {
            cmd.env("PATH", path);
        }
        if let Some(home) = std::env::var_os("HOME") {
            cmd.env("HOME", home);
        }
        if let Some(xdg_config) = std::env::var_os("XDG_CONFIG_HOME") {
            cmd.env("XDG_CONFIG_HOME", xdg_config);
        }
        // Fail closed on global/system git config
        cmd.env("GIT_CONFIG_NOSYSTEM", "1");
        cmd.env("GIT_CONFIG_GLOBAL", "/dev/null");
        // Explicitly remove repo override env vars (defense in depth)
        cmd.env_remove("GIT_DIR");
        cmd.env_remove("GIT_WORK_TREE");
        cmd.arg("-C").arg(&canonical_work_dir);
        cmd.args(["--no-pager", "-c", "color.ui=false", "-c", "core.pager=cat"]);

        // Add operation-specific args with fixed safe options
        match operation.as_str() {
            "diff" => {
                // Disable external diff tools
                cmd.arg("diff");
                cmd.arg("--no-ext-diff");
                cmd.arg("--");
                // Add validated pathspecs
                for pathspec in &git_args.args {
                    cmd.arg(pathspec);
                }
            },
            "status" => {
                cmd.arg("status");
                cmd.arg("--porcelain=v1");
                // Status doesn't use pathspecs from args
            },
            _ => unreachable!("validate() already rejected unknown operations"),
        }

        // Set non-interactive mode
        cmd.env("GIT_TERMINAL_PROMPT", "0");

        // Configure pipes
        cmd.stdin(Stdio::null());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());
        cmd.kill_on_drop(true);

        let mut child = cmd.spawn().map_err(|e| ToolHandlerError::ExecutionFailed {
            message: format!("failed to spawn git: {e}"),
        })?;

        let mut stdout = child
            .stdout
            .take()
            .ok_or_else(|| ToolHandlerError::ExecutionFailed {
                message: "failed to capture stdout".to_string(),
            })?;
        let mut stderr = child
            .stderr
            .take()
            .ok_or_else(|| ToolHandlerError::ExecutionFailed {
                message: "failed to capture stderr".to_string(),
            })?;

        // Each stream gets the full budget; total is enforced after read.
        let per_stream_limit = max_bytes;

        // Bounded read for stdout
        let stdout_future = async {
            let mut buf = Vec::new();
            let mut chunk = vec![0u8; 64 * 1024];
            loop {
                match stdout.read(&mut chunk).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if buf.len() + n > per_stream_limit {
                            let remaining = per_stream_limit.saturating_sub(buf.len());
                            buf.extend_from_slice(&chunk[..remaining]);
                            return (buf, true); // exceeded
                        }
                        buf.extend_from_slice(&chunk[..n]);
                    },
                }
            }
            (buf, false)
        };

        // Bounded read for stderr
        let stderr_future = async {
            let mut buf = Vec::new();
            let mut chunk = vec![0u8; 64 * 1024];
            loop {
                match stderr.read(&mut chunk).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if buf.len() + n > per_stream_limit {
                            let remaining = per_stream_limit.saturating_sub(buf.len());
                            buf.extend_from_slice(&chunk[..remaining]);
                            return (buf, true); // exceeded
                        }
                        buf.extend_from_slice(&chunk[..n]);
                    },
                }
            }
            (buf, false)
        };

        // Wait for process with timeout
        let timeout = Duration::from_millis(GIT_TIMEOUT_MS);
        let read_result = tokio::time::timeout(timeout, async {
            let (stdout_result, stderr_result, wait_result) =
                tokio::join!(stdout_future, stderr_future, child.wait());

            let (stdout_buf, stdout_exceeded) = stdout_result;
            let (stderr_buf, stderr_exceeded) = stderr_result;
            let output_exceeded = stdout_exceeded || stderr_exceeded;

            match wait_result {
                Ok(status) => Ok((stdout_buf, stderr_buf, Some(status), output_exceeded)),
                Err(e) => Err(ToolHandlerError::ExecutionFailed {
                    message: format!("failed to wait for git: {e}"),
                }),
            }
        })
        .await;

        let exec_duration = exec_start.elapsed();

        match read_result {
            Ok(Ok((stdout_buf, stderr_buf, maybe_status, output_exceeded))) => {
                let stdout_len = stdout_buf.len();
                let stderr_len = stderr_buf.len();
                let total_bytes = stdout_len + stderr_len;
                let line_count = Self::count_lines(&stdout_buf) + Self::count_lines(&stderr_buf);

                // Hard failure if output exceeded bounds
                if output_exceeded || total_bytes > max_bytes {
                    let _ = child.kill().await;
                    return Err(ToolHandlerError::OutputTooLarge {
                        bytes: total_bytes,
                        lines: line_count,
                        max_bytes,
                        max_lines,
                    });
                }

                // Hard failure if line count exceeded
                if line_count > max_lines {
                    return Err(ToolHandlerError::OutputTooLarge {
                        bytes: total_bytes,
                        lines: line_count,
                        max_bytes,
                        max_lines,
                    });
                }

                // Combine output
                let mut combined_output = stdout_buf;
                if !stderr_buf.is_empty() {
                    combined_output.extend_from_slice(b"\n--- stderr ---\n");
                    combined_output.extend_from_slice(&stderr_buf);
                }

                #[allow(clippy::cast_possible_truncation)]
                let wall_ms = exec_duration.as_millis().min(u128::from(u64::MAX)) as u64;

                let mut result = ToolResultData::success(
                    combined_output,
                    BudgetDelta::single_call()
                        .with_wall_ms(wall_ms)
                        .with_bytes_io(total_bytes as u64),
                    exec_duration,
                );
                result.exit_code = maybe_status.and_then(|s| s.code());
                Ok(result)
            },
            Ok(Err(e)) => Err(e),
            Err(_) => {
                let _ = child.kill().await;
                Err(ToolHandlerError::Timeout {
                    timeout_ms: GIT_TIMEOUT_MS,
                })
            },
        }
    }

    fn validate(&self, args: &ToolArgs) -> Result<(), ToolHandlerError> {
        let ToolArgs::Git(git_args) = args else {
            return Err(ToolHandlerError::InvalidArgs {
                reason: "expected Git arguments".to_string(),
            });
        };

        // Validate operation is allowed (only diff and status)
        let operation = git_args.operation.to_lowercase();
        if operation != "diff" && operation != "status" {
            return Err(ToolHandlerError::InvalidArgs {
                reason: format!(
                    "git operation '{}' not allowed; only 'diff' and 'status' are permitted",
                    git_args.operation
                ),
            });
        }

        // Validate repo_path if provided
        if let Some(ref repo_path) = git_args.repo_path {
            validate_path(repo_path)?;
        }

        // Validate args as pathspecs only (no flags)
        Self::validate_args_as_pathspecs(&git_args.args)?;

        Ok(())
    }

    fn name(&self) -> &'static str {
        "GitOperationHandler"
    }

    fn estimate_budget(&self, args: &ToolArgs) -> BudgetDelta {
        use super::tool_handler::{GIT_DIFF_MAX_BYTES, GIT_STATUS_MAX_BYTES};

        let max_bytes = match args {
            ToolArgs::Git(git_args) if git_args.operation.eq_ignore_ascii_case("status") => {
                GIT_STATUS_MAX_BYTES
            },
            _ => GIT_DIFF_MAX_BYTES,
        };

        BudgetDelta::single_call()
            .with_wall_ms(GIT_TIMEOUT_MS)
            .with_bytes_io(max_bytes as u64)
    }
}

// =============================================================================
// ArtifactFetchHandler (REQ-HEF-0010)
// =============================================================================

/// Hardened handler for artifact fetch operations per REQ-HEF-0010.
///
/// This handler retrieves content from the content-addressed store (CAS)
/// with strict validation and hard failure on bounds violation.
///
/// # Security Controls
///
/// - **Exactly One Reference**: Either `stable_id` or `content_hash` must be
///   set, not both (fail-closed validation).
/// - **Stable ID Not Supported**: Requests using `stable_id` fail closed until
///   a resolver is implemented.
/// - **Max Bytes Enforcement**: Requests with `max_bytes >
///   ARTIFACT_FETCH_MAX_BYTES` are rejected.
/// - **Hard Failure**: If content exceeds `max_bytes`, returns `OutputTooLarge`
///   instead of truncating.
///
/// # Contract References
///
/// - REQ-HEF-0010: Tool handler hardening requirements
/// - TCK-00313: `GitOperation` + `ArtifactFetch` handler hardening
#[derive(Debug)]
pub struct ArtifactFetchHandler {
    cas: std::sync::Arc<dyn ContentAddressedStore>,
}

impl ArtifactFetchHandler {
    /// Creates a new artifact fetch handler with the given CAS backend.
    pub fn new(cas: std::sync::Arc<dyn ContentAddressedStore>) -> Self {
        Self { cas }
    }
}

#[async_trait]
impl ToolHandler for ArtifactFetchHandler {
    fn tool_class(&self) -> ToolClass {
        ToolClass::Artifact
    }

    async fn execute(&self, args: &ToolArgs) -> Result<ToolResultData, ToolHandlerError> {
        // Validate arguments first
        self.validate(args)?;

        let ToolArgs::Artifact(artifact_args) = args else {
            return Err(ToolHandlerError::InvalidArgs {
                reason: "expected Artifact arguments".to_string(),
            });
        };

        let fetch_start = Instant::now();

        // content_hash must be present (validate ensures this)
        let hash =
            artifact_args
                .content_hash
                .as_ref()
                .ok_or_else(|| ToolHandlerError::Internal {
                    message: "content_hash missing after validation".to_string(),
                })?;

        // Retrieve content from CAS
        let content = self
            .cas
            .retrieve(hash)
            .ok_or_else(|| ToolHandlerError::FileNotFound {
                path: hex::encode(hash),
            })?;

        let fetch_duration = fetch_start.elapsed();

        // Hard failure if content exceeds max_bytes
        #[allow(clippy::cast_possible_truncation)]
        let max_bytes = artifact_args.max_bytes as usize;
        if content.len() > max_bytes {
            return Err(ToolHandlerError::OutputTooLarge {
                bytes: content.len(),
                lines: 0, // Artifacts don't have a line concept
                max_bytes,
                max_lines: 0,
            });
        }

        Ok(ToolResultData::success(
            content.clone(),
            BudgetDelta::single_call().with_bytes_io(content.len() as u64),
            fetch_duration,
        ))
    }

    fn validate(&self, args: &ToolArgs) -> Result<(), ToolHandlerError> {
        use super::tool_handler::ARTIFACT_FETCH_MAX_BYTES;

        let ToolArgs::Artifact(artifact_args) = args else {
            return Err(ToolHandlerError::InvalidArgs {
                reason: "expected Artifact arguments".to_string(),
            });
        };

        // Exactly one of stable_id or content_hash must be set
        let has_stable_id = artifact_args.stable_id.is_some();
        let has_content_hash = artifact_args.content_hash.is_some();

        if has_stable_id && has_content_hash {
            return Err(ToolHandlerError::InvalidArgs {
                reason: "exactly one of stable_id or content_hash must be set, not both".into(),
            });
        }
        if !has_stable_id && !has_content_hash {
            return Err(ToolHandlerError::InvalidArgs {
                reason: "exactly one of stable_id or content_hash must be set".into(),
            });
        }

        // stable_id not supported yet (fail-closed)
        if has_stable_id {
            return Err(ToolHandlerError::InvalidArgs {
                reason: "stable_id not supported yet; use content_hash".into(),
            });
        }

        // max_bytes must be within limit
        if artifact_args.max_bytes > ARTIFACT_FETCH_MAX_BYTES as u64 {
            return Err(ToolHandlerError::InvalidArgs {
                reason: format!(
                    "max_bytes {} exceeds limit {}",
                    artifact_args.max_bytes, ARTIFACT_FETCH_MAX_BYTES
                ),
            });
        }

        // max_bytes must be non-zero
        if artifact_args.max_bytes == 0 {
            return Err(ToolHandlerError::InvalidArgs {
                reason: "max_bytes must be greater than 0".into(),
            });
        }

        Ok(())
    }

    fn name(&self) -> &'static str {
        "ArtifactFetchHandler"
    }

    fn estimate_budget(&self, args: &ToolArgs) -> BudgetDelta {
        let bytes = if let ToolArgs::Artifact(artifact_args) = args {
            artifact_args.max_bytes
        } else {
            4096
        };
        BudgetDelta::single_call().with_bytes_io(bytes)
    }
}

// =============================================================================
// ListFilesHandler (TCK-00315)
// =============================================================================

/// Handler for directory listing operations per TCK-00315.
///
/// This handler lists files in a directory with strict bounds and security
/// controls for FAC v0 reviewer navigation.
///
/// # Security Controls
///
/// - **Path Validation**: Paths must be relative to workspace root (no `..`
///   traversal, no absolute paths)
/// - **Symlink Safety**: Resolved paths are verified to stay within workspace
/// - **Entry Limit**: Maximum 10,000 entries (default 1,000)
/// - **Output Bounds**: Hard failure at 65,536 bytes / 2,000 lines
/// - **Glob Safety**: Optional pattern filtering uses safe glob matching
///
/// # Contract References
///
/// - TCK-00315: Reviewer navigation tool surface
/// - REQ-HEF-0010: Tool handler security requirements
#[derive(Debug)]
pub struct ListFilesHandler {
    root: PathBuf,
}

impl Default for ListFilesHandler {
    fn default() -> Self {
        Self {
            root: PathBuf::from("."),
        }
    }
}

impl ListFilesHandler {
    /// Creates a new list files handler using CWD as root.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a new list files handler with a specific root directory.
    #[must_use]
    pub fn with_root(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Checks if a file name matches a glob pattern.
    ///
    /// Supports simple glob patterns:
    /// - `*` matches any sequence of characters
    /// - `?` matches a single character
    fn matches_pattern(name: &str, pattern: &str) -> bool {
        // Simple glob matching without external dependencies
        Self::glob_match(pattern.as_bytes(), name.as_bytes())
    }

    /// Simple glob matching (recursive, safe for bounded inputs).
    fn glob_match(pattern: &[u8], name: &[u8]) -> bool {
        let mut p_idx = 0;
        let mut n_idx = 0;
        let mut star_p = None;
        let mut star_n = 0;

        while n_idx < name.len() {
            if p_idx < pattern.len() && pattern[p_idx] == b'*' {
                // Record star position for backtracking
                star_p = Some(p_idx);
                star_n = n_idx;
                p_idx += 1;
            } else if p_idx < pattern.len()
                && (pattern[p_idx] == b'?' || pattern[p_idx] == name[n_idx])
            {
                // Match or wildcard ?
                p_idx += 1;
                n_idx += 1;
            } else if let Some(sp) = star_p {
                // Backtrack to star
                p_idx = sp + 1;
                star_n += 1;
                n_idx = star_n;
            } else {
                return false;
            }
        }

        // Consume remaining stars in pattern
        while p_idx < pattern.len() && pattern[p_idx] == b'*' {
            p_idx += 1;
        }

        p_idx == pattern.len()
    }

    /// Counts lines in output.
    #[allow(clippy::naive_bytecount)] // bytecount crate not needed for small buffers
    fn count_lines(data: &[u8]) -> usize {
        data.iter().filter(|&&b| b == b'\n').count()
    }
}

#[async_trait]
impl ToolHandler for ListFilesHandler {
    fn tool_class(&self) -> ToolClass {
        ToolClass::ListFiles
    }

    async fn execute(&self, args: &ToolArgs) -> Result<ToolResultData, ToolHandlerError> {
        use super::tool_handler::{
            LISTFILES_DEFAULT_ENTRIES, LISTFILES_MAX_ENTRIES, NAVIGATION_OUTPUT_MAX_BYTES,
            NAVIGATION_OUTPUT_MAX_LINES,
        };

        // Validate arguments first
        self.validate(args)?;

        let ToolArgs::ListFiles(ls_args) = args else {
            return Err(ToolHandlerError::InvalidArgs {
                reason: "expected ListFiles arguments".to_string(),
            });
        };

        let io_start = Instant::now();

        // Resolve path relative to root
        let target_path = self.root.join(&ls_args.path);

        // Canonicalize root for comparison
        let canonical_root =
            std::fs::canonicalize(&self.root).map_err(|e| ToolHandlerError::ExecutionFailed {
                message: format!(
                    "failed to canonicalize root '{}': {}",
                    self.root.display(),
                    e
                ),
            })?;

        // Canonicalize target path
        let canonical_target =
            std::fs::canonicalize(&target_path).map_err(|e| ToolHandlerError::ExecutionFailed {
                message: format!(
                    "failed to canonicalize path '{}': {}",
                    target_path.display(),
                    e
                ),
            })?;

        // Verify within workspace root
        validate_resolved_path_within_root(&canonical_target, &canonical_root)?;

        // Read directory entries
        let mut entries: Vec<String> = Vec::new();
        #[allow(clippy::cast_possible_truncation)] // Bounded by LISTFILES_MAX_ENTRIES
        let max_entries = ls_args.max_entries.map_or(LISTFILES_DEFAULT_ENTRIES, |n| {
            (n as usize).min(LISTFILES_MAX_ENTRIES)
        });

        let mut dir_iter = tokio::fs::read_dir(&canonical_target).await.map_err(|e| {
            ToolHandlerError::ExecutionFailed {
                message: format!(
                    "failed to read directory '{}': {}",
                    target_path.display(),
                    e
                ),
            }
        })?;

        // TCK-00315: Bound the number of entries *scanned* (not just returned) to
        // prevent denial-of-service on very large directories, especially when
        // a pattern is set that matches rarely.
        let mut scanned_entries = 0usize;

        while let Some(entry) =
            dir_iter
                .next_entry()
                .await
                .map_err(|e| ToolHandlerError::ExecutionFailed {
                    message: format!("failed to read directory entry: {e}"),
                })?
        {
            scanned_entries += 1;
            if scanned_entries > LISTFILES_MAX_ENTRIES {
                return Err(ToolHandlerError::InvalidArgs {
                    reason: format!(
                        "directory too large to list safely: scanned more than {LISTFILES_MAX_ENTRIES} entries",
                    ),
                });
            }

            if entries.len() >= max_entries {
                break;
            }

            let file_name = entry.file_name().to_string_lossy().to_string();

            // Apply pattern filter if specified
            if let Some(ref pattern) = ls_args.pattern {
                if !Self::matches_pattern(&file_name, pattern) {
                    continue;
                }
            }

            // Include type indicator
            let file_type = entry.file_type().await.ok();
            let type_indicator = if file_type.as_ref().is_some_and(std::fs::FileType::is_dir) {
                "/"
            } else if file_type
                .as_ref()
                .is_some_and(std::fs::FileType::is_symlink)
            {
                "@"
            } else {
                ""
            };

            entries.push(format!("{file_name}{type_indicator}"));
        }

        // Sort entries for deterministic output
        entries.sort();

        // Build output
        let output = entries.join("\n");
        let output_len = output.len();
        let line_count = Self::count_lines(output.as_bytes()) + usize::from(!output.is_empty());

        // Hard failure if output exceeds bounds
        if output_len > NAVIGATION_OUTPUT_MAX_BYTES {
            return Err(ToolHandlerError::OutputTooLarge {
                bytes: output_len,
                lines: line_count,
                max_bytes: NAVIGATION_OUTPUT_MAX_BYTES,
                max_lines: NAVIGATION_OUTPUT_MAX_LINES,
            });
        }

        if line_count > NAVIGATION_OUTPUT_MAX_LINES {
            return Err(ToolHandlerError::OutputTooLarge {
                bytes: output_len,
                lines: line_count,
                max_bytes: NAVIGATION_OUTPUT_MAX_BYTES,
                max_lines: NAVIGATION_OUTPUT_MAX_LINES,
            });
        }

        let io_duration = io_start.elapsed();

        Ok(ToolResultData::success(
            output.into_bytes(),
            BudgetDelta::single_call().with_bytes_io(output_len as u64),
            io_duration,
        ))
    }

    fn validate(&self, args: &ToolArgs) -> Result<(), ToolHandlerError> {
        use super::tool_handler::LISTFILES_MAX_ENTRIES;

        let ToolArgs::ListFiles(ls_args) = args else {
            return Err(ToolHandlerError::InvalidArgs {
                reason: "expected ListFiles arguments".to_string(),
            });
        };

        // Validate path
        validate_path(&ls_args.path)?;

        // Validate max_entries if provided
        if let Some(max_entries) = ls_args.max_entries {
            #[allow(clippy::cast_possible_truncation)] // Bounded by limit check
            if max_entries as usize > LISTFILES_MAX_ENTRIES {
                return Err(ToolHandlerError::InvalidArgs {
                    reason: format!(
                        "max_entries {max_entries} exceeds limit {LISTFILES_MAX_ENTRIES}",
                    ),
                });
            }
        }

        // Validate pattern length (prevent ReDoS-style attacks)
        if let Some(ref pattern) = ls_args.pattern {
            if pattern.len() > 256 {
                return Err(ToolHandlerError::InvalidArgs {
                    reason: format!("pattern too long: {} chars (max 256)", pattern.len()),
                });
            }
        }

        Ok(())
    }

    fn name(&self) -> &'static str {
        "ListFilesHandler"
    }

    fn estimate_budget(&self, args: &ToolArgs) -> BudgetDelta {
        use super::tool_handler::LISTFILES_DEFAULT_ENTRIES;

        let entries = if let ToolArgs::ListFiles(ls_args) = args {
            ls_args
                .max_entries
                .unwrap_or(LISTFILES_DEFAULT_ENTRIES as u64)
        } else {
            LISTFILES_DEFAULT_ENTRIES as u64
        };
        // Estimate ~50 bytes per entry
        BudgetDelta::single_call().with_bytes_io(entries * 50)
    }
}

// =============================================================================
// SearchHandler (TCK-00315)
// =============================================================================

/// Handler for text search operations per TCK-00315.
///
/// This handler searches for text within files with strict bounds and security
/// controls for FAC v0 reviewer navigation.
///
/// # Security Controls
///
/// - **Path Validation**: Scope path must be relative to workspace root
/// - **Symlink Safety**: Resolved paths are verified to stay within workspace
/// - **Literal Query**: No regex support in v0 (prevents `ReDoS`)
/// - **Output Bounds**: Hard failure at 65,536 bytes / 2,000 lines
/// - **File Traversal**: Bounded to prevent denial-of-service on large
///   directories
///
/// # Contract References
///
/// - TCK-00315: Reviewer navigation tool surface
/// - REQ-HEF-0010: Tool handler security requirements
#[derive(Debug)]
pub struct SearchHandler {
    root: PathBuf,
}

impl Default for SearchHandler {
    fn default() -> Self {
        Self {
            root: PathBuf::from("."),
        }
    }
}

/// Maximum files to search (prevent denial-of-service on large directories).
const SEARCH_MAX_FILES: usize = 10_000;

/// Maximum file size to search (skip large binaries).
const SEARCH_MAX_FILE_SIZE: u64 = 10 * 1024 * 1024; // 10 MiB

/// Search timeout in milliseconds.
const SEARCH_TIMEOUT_MS: u64 = 30_000;

/// Maximum number of directory entries to visit during traversal.
///
/// This bounds the amount of filesystem work even when `SEARCH_MAX_FILES` is
/// not reached (e.g., extremely deep/wide trees with many directories and few
/// qualifying files).
const SEARCH_MAX_VISITED_ENTRIES: usize = 100_000;

/// Maximum total file bytes to scan in a single search.
///
/// This prevents denial-of-service via repeatedly scanning large scopes that
/// produce little or no output.
const SEARCH_MAX_TOTAL_BYTES: u64 = 32 * 1024 * 1024; // 32 MiB

#[derive(Debug)]
struct SearchTarget {
    path: PathBuf,
    display_path: String,
    size: u64,
}

#[derive(Debug)]
struct SearchOutputState {
    max_bytes: usize,
    max_lines: usize,
    current_bytes: usize,
    current_lines: usize,
    results: Vec<String>,
}

impl SearchHandler {
    /// Creates a new search handler using CWD as root.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a new search handler with a specific root directory.
    #[must_use]
    pub fn with_root(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Counts lines in output.
    #[allow(clippy::naive_bytecount)] // bytecount crate not needed for small buffers
    fn count_lines(data: &[u8]) -> usize {
        data.iter().filter(|&&b| b == b'\n').count()
    }

    /// Recursively collects files from a directory.
    async fn collect_files(
        dir: &Path,
        root: &Path,
        files: &mut Vec<SearchTarget>,
        max_files: usize,
    ) -> Result<(), ToolHandlerError> {
        let mut to_visit: Vec<PathBuf> = vec![dir.to_path_buf()];
        let mut visited_entries = 0usize;

        while let Some(current_dir) = to_visit.pop() {
            if files.len() >= max_files {
                return Ok(());
            }

            let mut dir_iter = tokio::fs::read_dir(&current_dir).await.map_err(|e| {
                ToolHandlerError::ExecutionFailed {
                    message: format!(
                        "failed to read directory '{}': {}",
                        current_dir.display(),
                        e
                    ),
                }
            })?;

            loop {
                if files.len() >= max_files {
                    return Ok(());
                }

                let Some(entry) =
                    dir_iter
                        .next_entry()
                        .await
                        .map_err(|e| ToolHandlerError::ExecutionFailed {
                            message: format!("failed to read directory entry: {e}"),
                        })?
                else {
                    break;
                };

                visited_entries += 1;
                if visited_entries > SEARCH_MAX_VISITED_ENTRIES {
                    return Err(ToolHandlerError::InvalidArgs {
                        reason: format!(
                            "scope too large to search safely: visited more than {SEARCH_MAX_VISITED_ENTRIES} directory entries",
                        ),
                    });
                }

                let file_type =
                    entry
                        .file_type()
                        .await
                        .map_err(|e| ToolHandlerError::ExecutionFailed {
                            message: format!("failed to stat directory entry: {e}"),
                        })?;

                // Do not follow symlinks during traversal (prevents escapes and cycles).
                if file_type.is_symlink() {
                    continue;
                }

                let entry_path = entry.path();

                // Defense in depth: traversal must stay within root.
                if !entry_path.starts_with(root) {
                    continue;
                }

                if file_type.is_file() {
                    let metadata =
                        entry
                            .metadata()
                            .await
                            .map_err(|e| ToolHandlerError::ExecutionFailed {
                                message: format!(
                                    "failed to stat file '{}': {}",
                                    entry_path.display(),
                                    e
                                ),
                            })?;

                    // Skip large files
                    let size = metadata.len();
                    if size > SEARCH_MAX_FILE_SIZE {
                        continue;
                    }

                    let display_path = entry_path
                        .strip_prefix(root)
                        .unwrap_or(&entry_path)
                        .display()
                        .to_string();

                    files.push(SearchTarget {
                        path: entry_path,
                        display_path,
                        size,
                    });
                } else if file_type.is_dir() {
                    to_visit.push(entry_path);
                }
            }
        }

        Ok(())
    }

    /// Searches a file for the query and returns matching lines.
    async fn search_file(
        path: &Path,
        display_path: &str,
        query: &str,
        out: &mut SearchOutputState,
    ) -> Result<bool, ToolHandlerError> {
        let Ok(content) = tokio::fs::read_to_string(path).await else {
            return Ok(false); // Skip unreadable/binary files
        };

        for (line_num, line) in content.lines().enumerate() {
            if line.contains(query) {
                let result_line = format!("{display_path}:{}:{line}", line_num + 1);
                let line_bytes = result_line.len() + 1; // +1 for newline

                // Check bounds before adding
                if out.current_bytes + line_bytes > out.max_bytes
                    || out.current_lines + 1 > out.max_lines
                {
                    return Ok(true); // Signal bounds exceeded
                }

                out.results.push(result_line);
                out.current_bytes += line_bytes;
                out.current_lines += 1;
            }
        }

        Ok(false)
    }
}

#[async_trait]
impl ToolHandler for SearchHandler {
    fn tool_class(&self) -> ToolClass {
        ToolClass::Search
    }

    async fn execute(&self, args: &ToolArgs) -> Result<ToolResultData, ToolHandlerError> {
        use super::tool_handler::{NAVIGATION_OUTPUT_MAX_BYTES, NAVIGATION_OUTPUT_MAX_LINES};

        // Validate arguments first
        self.validate(args)?;

        let ToolArgs::Search(search_args) = args else {
            return Err(ToolHandlerError::InvalidArgs {
                reason: "expected Search arguments".to_string(),
            });
        };

        let search_start = Instant::now();

        // Resolve scope path relative to root
        let scope_path = self.root.join(&search_args.scope);

        // Canonicalize root for comparison
        let canonical_root =
            std::fs::canonicalize(&self.root).map_err(|e| ToolHandlerError::ExecutionFailed {
                message: format!(
                    "failed to canonicalize root '{}': {}",
                    self.root.display(),
                    e
                ),
            })?;

        // Canonicalize scope path
        let canonical_scope =
            std::fs::canonicalize(&scope_path).map_err(|e| ToolHandlerError::ExecutionFailed {
                message: format!(
                    "failed to canonicalize scope '{}': {}",
                    scope_path.display(),
                    e
                ),
            })?;

        // Verify within workspace root
        validate_resolved_path_within_root(&canonical_scope, &canonical_root)?;

        // Determine output bounds
        #[allow(clippy::cast_possible_truncation)] // Bounded by NAVIGATION_OUTPUT_MAX_BYTES
        let max_bytes = search_args
            .max_bytes
            .map_or(NAVIGATION_OUTPUT_MAX_BYTES, |n| {
                (n as usize).min(NAVIGATION_OUTPUT_MAX_BYTES)
            });
        #[allow(clippy::cast_possible_truncation)] // Bounded by NAVIGATION_OUTPUT_MAX_LINES
        let max_lines = search_args
            .max_lines
            .map_or(NAVIGATION_OUTPUT_MAX_LINES, |n| {
                (n as usize).min(NAVIGATION_OUTPUT_MAX_LINES)
            });

        let query = &search_args.query;
        let timeout = Duration::from_millis(SEARCH_TIMEOUT_MS);

        let (output, scanned_bytes) = match tokio::time::timeout(timeout, async {
            // Collect files to search (bounded traversal)
            let mut targets: Vec<SearchTarget> = Vec::new();
            let metadata = tokio::fs::metadata(&canonical_scope).await.map_err(|e| {
                ToolHandlerError::ExecutionFailed {
                    message: format!("failed to stat scope '{}': {}", scope_path.display(), e),
                }
            })?;

            if metadata.is_file() {
                let size = metadata.len();
                if size > SEARCH_MAX_FILE_SIZE {
                    return Err(ToolHandlerError::InvalidArgs {
                        reason: format!(
                            "scope file too large to search safely: {size} bytes (max {SEARCH_MAX_FILE_SIZE})",
                        ),
                    });
                }

                let display_path = canonical_scope
                    .strip_prefix(&canonical_root)
                    .unwrap_or(&canonical_scope)
                    .display()
                    .to_string();

                targets.push(SearchTarget {
                    path: canonical_scope.clone(),
                    display_path,
                    size,
                });
            } else if metadata.is_dir() {
                Self::collect_files(
                    &canonical_scope,
                    &canonical_root,
                    &mut targets,
                    SEARCH_MAX_FILES,
                )
                .await?;
            }

            // Deterministic traversal order
            targets.sort_by(|a, b| a.display_path.cmp(&b.display_path));

            let mut out = SearchOutputState {
                max_bytes,
                max_lines,
                current_bytes: 0,
                current_lines: 0,
                results: Vec::new(),
            };
            let mut bounds_exceeded = false;
            let mut scanned_bytes = 0u64;

            for target in &targets {
                if bounds_exceeded {
                    break;
                }

                // Bound total bytes scanned (economics / DoS control)
                if scanned_bytes.saturating_add(target.size) > SEARCH_MAX_TOTAL_BYTES {
                    return Err(ToolHandlerError::InvalidArgs {
                        reason: format!(
                            "scope too large to search safely: would scan more than {SEARCH_MAX_TOTAL_BYTES} bytes",
                        ),
                    });
                }

                scanned_bytes = scanned_bytes.saturating_add(target.size);

                bounds_exceeded = Self::search_file(
                    &target.path,
                    &target.display_path,
                    query,
                    &mut out,
                )
                .await?;
            }

            // Build output
            let output = out.results.join("\n");
            let output_len = output.len();
            let final_lines =
                Self::count_lines(output.as_bytes()) + usize::from(!output.is_empty());

            // Hard failure if bounds exceeded
            if output_len > max_bytes || final_lines > max_lines || bounds_exceeded {
                return Err(ToolHandlerError::OutputTooLarge {
                    bytes: output_len,
                    lines: final_lines,
                    max_bytes,
                    max_lines,
                });
            }

            Ok::<_, ToolHandlerError>((output, scanned_bytes))
        })
        .await
        {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                return Err(ToolHandlerError::Timeout {
                    timeout_ms: SEARCH_TIMEOUT_MS,
                });
            },
        };

        let search_duration = search_start.elapsed();
        #[allow(clippy::cast_possible_truncation)]
        let wall_ms = search_duration.as_millis().min(u128::from(u64::MAX)) as u64;
        let output_len = output.len();

        Ok(ToolResultData::success(
            output.into_bytes(),
            BudgetDelta::single_call()
                .with_wall_ms(wall_ms)
                .with_bytes_io(scanned_bytes.saturating_add(output_len as u64)),
            search_duration,
        ))
    }

    fn validate(&self, args: &ToolArgs) -> Result<(), ToolHandlerError> {
        use super::tool_handler::{NAVIGATION_OUTPUT_MAX_BYTES, NAVIGATION_OUTPUT_MAX_LINES};

        let ToolArgs::Search(search_args) = args else {
            return Err(ToolHandlerError::InvalidArgs {
                reason: "expected Search arguments".to_string(),
            });
        };

        // Validate scope path
        validate_path(&search_args.scope)?;

        // Validate query is not empty
        if search_args.query.is_empty() {
            return Err(ToolHandlerError::InvalidArgs {
                reason: "search query cannot be empty".to_string(),
            });
        }

        // Validate query length (prevent memory exhaustion)
        if search_args.query.len() > 1024 {
            return Err(ToolHandlerError::InvalidArgs {
                reason: format!(
                    "search query too long: {} chars (max 1024)",
                    search_args.query.len()
                ),
            });
        }

        // Validate max_bytes if provided
        if let Some(max_bytes) = search_args.max_bytes {
            #[allow(clippy::cast_possible_truncation)] // Bounded by limit check
            if max_bytes as usize > NAVIGATION_OUTPUT_MAX_BYTES {
                return Err(ToolHandlerError::InvalidArgs {
                    reason: format!(
                        "max_bytes {max_bytes} exceeds limit {NAVIGATION_OUTPUT_MAX_BYTES}",
                    ),
                });
            }
        }

        // Validate max_lines if provided
        if let Some(max_lines) = search_args.max_lines {
            #[allow(clippy::cast_possible_truncation)] // Bounded by limit check
            if max_lines as usize > NAVIGATION_OUTPUT_MAX_LINES {
                return Err(ToolHandlerError::InvalidArgs {
                    reason: format!(
                        "max_lines {max_lines} exceeds limit {NAVIGATION_OUTPUT_MAX_LINES}",
                    ),
                });
            }
        }

        Ok(())
    }

    fn name(&self) -> &'static str {
        "SearchHandler"
    }

    fn estimate_budget(&self, args: &ToolArgs) -> BudgetDelta {
        use super::tool_handler::NAVIGATION_OUTPUT_MAX_BYTES;

        let max_output_bytes = if let ToolArgs::Search(search_args) = args {
            search_args
                .max_bytes
                .unwrap_or(NAVIGATION_OUTPUT_MAX_BYTES as u64)
                .min(NAVIGATION_OUTPUT_MAX_BYTES as u64)
        } else {
            NAVIGATION_OUTPUT_MAX_BYTES as u64
        };

        BudgetDelta::single_call()
            .with_wall_ms(SEARCH_TIMEOUT_MS)
            .with_bytes_io(SEARCH_MAX_TOTAL_BYTES.saturating_add(max_output_bytes))
    }
}

// =============================================================================
// Handler Registry Helper
// =============================================================================

/// Registers all handlers with an executor.
///
/// This is a convenience function for setting up an executor with the
/// default handlers.
///
/// # Example
///
/// ```rust,ignore
/// use apm2_daemon::episode::executor::ToolExecutor;
/// use apm2_daemon::episode::handlers::register_stub_handlers;
///
/// let mut executor = ToolExecutor::new(tracker, cas.clone());
/// register_stub_handlers(&mut executor, cas).expect("handlers registered");
/// ```
pub fn register_stub_handlers(
    executor: &mut super::executor::ToolExecutor,
    cas: std::sync::Arc<dyn ContentAddressedStore>,
) -> Result<(), super::executor::ExecutorError> {
    executor.register_handler(Box::new(ReadFileHandler::new()))?;
    executor.register_handler(Box::new(WriteFileHandler::new()))?;
    executor.register_handler(Box::new(ExecuteHandler::new()))?;
    executor.register_handler(Box::new(GitOperationHandler::new()))?;
    executor.register_handler(Box::new(ArtifactFetchHandler::new(cas)))?;
    executor.register_handler(Box::new(ListFilesHandler::new()))?;
    executor.register_handler(Box::new(SearchHandler::new()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::process::Command;
    use std::sync::Arc;

    use tempfile::TempDir;

    use super::*;
    use crate::cas::{DurableCas, DurableCasConfig};
    use crate::episode::tool_handler::{
        ArtifactArgs, ExecuteArgs, GIT_DIFF_MAX_BYTES, GIT_STATUS_MAX_LINES, GitArgs, ReadArgs,
        ToolArgs, WriteArgs,
    };

    fn run_git(root: &Path, args: &[&str]) {
        let status = Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .status()
            .expect("git command");
        assert!(status.success(), "git {args:?} failed");
    }

    fn init_git_repo(root: &Path) {
        run_git(root, &["init"]);
        run_git(root, &["config", "user.email", "fac-v0@example.com"]);
        run_git(root, &["config", "user.name", "FAC V0 Harness"]);
    }

    fn git_commit_all(root: &Path, message: &str) {
        run_git(root, &["add", "."]);
        let status = Command::new("git")
            .arg("-C")
            .arg(root)
            .args(["commit", "-m", message])
            .env("GIT_AUTHOR_NAME", "FAC V0 Harness")
            .env("GIT_AUTHOR_EMAIL", "fac-v0@example.com")
            .env("GIT_COMMITTER_NAME", "FAC V0 Harness")
            .env("GIT_COMMITTER_EMAIL", "fac-v0@example.com")
            .status()
            .expect("git commit");
        assert!(status.success(), "git commit failed");
    }

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
    // Resolved path (symlink) validation tests
    // =========================================================================

    #[test]
    fn test_validate_resolved_path_within_root_ok() {
        let root = Path::new("/workspace");
        let resolved = Path::new("/workspace/src/main.rs");
        assert!(validate_resolved_path_within_root(resolved, root).is_ok());
    }

    #[test]
    fn test_validate_resolved_path_at_root_ok() {
        let root = Path::new("/workspace");
        let resolved = Path::new("/workspace");
        assert!(validate_resolved_path_within_root(resolved, root).is_ok());
    }

    #[test]
    fn test_validate_resolved_path_escapes_root_rejected() {
        // Simulates a symlink that resolves outside the workspace
        let root = Path::new("/workspace");
        let resolved = Path::new("/etc/shadow");
        let result = validate_resolved_path_within_root(resolved, root);
        assert!(
            matches!(result, Err(ToolHandlerError::PathValidation { .. })),
            "Paths escaping root should be rejected"
        );
        if let Err(ToolHandlerError::PathValidation { reason, .. }) = result {
            assert!(
                reason.contains("symlink") || reason.contains("escapes"),
                "Error should mention symlink escape: {reason}"
            );
        }
    }

    #[test]
    fn test_validate_resolved_path_sibling_rejected() {
        // Path resolves to sibling directory (not under root)
        let root = Path::new("/workspace/project1");
        let resolved = Path::new("/workspace/project2/secret.txt");
        let result = validate_resolved_path_within_root(resolved, root);
        assert!(
            matches!(result, Err(ToolHandlerError::PathValidation { .. })),
            "Sibling paths should be rejected"
        );
    }

    #[test]
    fn test_validate_resolved_path_parent_rejected() {
        // Path resolves to parent directory
        let root = Path::new("/workspace/project");
        let resolved = Path::new("/workspace/secret.txt");
        let result = validate_resolved_path_within_root(resolved, root);
        assert!(
            matches!(result, Err(ToolHandlerError::PathValidation { .. })),
            "Parent paths should be rejected"
        );
    }

    // =========================================================================
    // ReadFileHandler tests
    // =========================================================================

    // NOTE: Real I/O tests are moved to integration tests
    // (tck_00291_tool_handlers.rs) Unit tests here focus on validation logic.

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

    // =========================================================================
    // GitOperationHandler tests (TCK-00313)
    // =========================================================================

    #[test]
    fn test_git_handler_validate_diff_ok() {
        let handler = GitOperationHandler::new();
        let args = ToolArgs::Git(GitArgs {
            operation: "diff".to_string(),
            args: vec!["src/main.rs".to_string()],
            repo_path: None,
        });
        assert!(handler.validate(&args).is_ok());
    }

    #[test]
    fn test_git_handler_validate_status_ok() {
        let handler = GitOperationHandler::new();
        let args = ToolArgs::Git(GitArgs {
            operation: "status".to_string(),
            args: vec![],
            repo_path: None,
        });
        assert!(handler.validate(&args).is_ok());
    }

    #[test]
    fn test_git_handler_validate_case_insensitive() {
        let handler = GitOperationHandler::new();
        let args = ToolArgs::Git(GitArgs {
            operation: "DIFF".to_string(),
            args: vec![],
            repo_path: None,
        });
        assert!(handler.validate(&args).is_ok());
    }

    #[test]
    fn test_git_handler_rejects_push() {
        let handler = GitOperationHandler::new();
        let args = ToolArgs::Git(GitArgs {
            operation: "push".to_string(),
            args: vec![],
            repo_path: None,
        });
        let result = handler.validate(&args);
        assert!(matches!(result, Err(ToolHandlerError::InvalidArgs { .. })));
    }

    #[test]
    fn test_git_handler_rejects_flags() {
        let handler = GitOperationHandler::new();
        let args = ToolArgs::Git(GitArgs {
            operation: "diff".to_string(),
            args: vec!["--work-tree=/etc".to_string()],
            repo_path: None,
        });
        let result = handler.validate(&args);
        assert!(matches!(result, Err(ToolHandlerError::InvalidArgs { .. })));
        if let Err(ToolHandlerError::InvalidArgs { reason }) = result {
            assert!(
                reason.contains("flag"),
                "Error should mention flag: {reason}"
            );
        }
    }

    #[test]
    fn test_git_handler_rejects_short_flags() {
        let handler = GitOperationHandler::new();
        let args = ToolArgs::Git(GitArgs {
            operation: "diff".to_string(),
            args: vec!["-p".to_string()],
            repo_path: None,
        });
        let result = handler.validate(&args);
        assert!(matches!(result, Err(ToolHandlerError::InvalidArgs { .. })));
    }

    #[test]
    fn test_git_handler_rejects_absolute_pathspec() {
        let handler = GitOperationHandler::new();
        let args = ToolArgs::Git(GitArgs {
            operation: "diff".to_string(),
            args: vec!["/etc/passwd".to_string()],
            repo_path: None,
        });
        let result = handler.validate(&args);
        assert!(matches!(
            result,
            Err(ToolHandlerError::PathValidation { .. })
        ));
    }

    #[test]
    fn test_git_handler_rejects_traversal_pathspec() {
        let handler = GitOperationHandler::new();
        let args = ToolArgs::Git(GitArgs {
            operation: "diff".to_string(),
            args: vec!["../etc/passwd".to_string()],
            repo_path: None,
        });
        let result = handler.validate(&args);
        assert!(matches!(
            result,
            Err(ToolHandlerError::PathValidation { .. })
        ));
    }

    #[tokio::test]
    async fn test_git_diff_output_too_large() {
        let temp_dir = TempDir::new().expect("create temp dir");
        init_git_repo(temp_dir.path());

        let file_path = temp_dir.path().join("big.txt");
        std::fs::write(&file_path, b"base\n").expect("write base file");
        git_commit_all(temp_dir.path(), "init-big");

        let large = vec![b'x'; GIT_DIFF_MAX_BYTES + 1024];
        std::fs::write(&file_path, &large).expect("write large diff");

        let handler = GitOperationHandler::with_root(temp_dir.path());
        let args = ToolArgs::Git(GitArgs {
            operation: "diff".to_string(),
            args: vec!["big.txt".to_string()],
            repo_path: None,
        });

        let result = handler.execute(&args).await;
        assert!(
            matches!(result, Err(ToolHandlerError::OutputTooLarge { .. })),
            "expected output too large"
        );
    }

    #[tokio::test]
    async fn test_git_status_output_too_large() {
        let temp_dir = TempDir::new().expect("create temp dir");
        init_git_repo(temp_dir.path());

        let base_path = temp_dir.path().join("base.txt");
        std::fs::write(&base_path, b"base\n").expect("write base file");
        git_commit_all(temp_dir.path(), "init-status");

        let file_count = GIT_STATUS_MAX_LINES + 10;
        for idx in 0..file_count {
            let file_path = temp_dir.path().join(format!("untracked_{idx}.txt"));
            std::fs::write(&file_path, b"x").expect("write untracked file");
        }

        let handler = GitOperationHandler::with_root(temp_dir.path());
        let args = ToolArgs::Git(GitArgs {
            operation: "status".to_string(),
            args: Vec::new(),
            repo_path: None,
        });

        let result = handler.execute(&args).await;
        assert!(
            matches!(result, Err(ToolHandlerError::OutputTooLarge { .. })),
            "expected output too large"
        );
    }

    // =========================================================================
    // ArtifactFetchHandler validation tests (TCK-00313)
    // =========================================================================

    #[tokio::test]
    async fn test_artifact_fetch_output_too_large() {
        let temp_dir = TempDir::new().expect("create temp dir");
        let cas_dir = temp_dir.path().join("cas");
        std::fs::create_dir_all(&cas_dir).expect("create cas dir");
        let cas: Arc<dyn ContentAddressedStore> =
            Arc::new(DurableCas::new(DurableCasConfig::new(&cas_dir)).expect("cas"));
        let content = vec![0u8; 64];
        let hash = cas.store(&content);

        let handler = ArtifactFetchHandler::new(cas);
        let args = ToolArgs::Artifact(ArtifactArgs {
            stable_id: None,
            content_hash: Some(hash),
            expected_hash: None,
            max_bytes: 1,
            format: None,
        });

        let result = handler.execute(&args).await;
        assert!(
            matches!(result, Err(ToolHandlerError::OutputTooLarge { .. })),
            "expected output too large"
        );
    }

    #[tokio::test]
    async fn test_artifact_fetch_missing_returns_not_found() {
        let temp_dir = TempDir::new().expect("create temp dir");
        let cas_dir = temp_dir.path().join("cas");
        std::fs::create_dir_all(&cas_dir).expect("create cas dir");
        let cas: Arc<dyn ContentAddressedStore> =
            Arc::new(DurableCas::new(DurableCasConfig::new(&cas_dir)).expect("cas"));
        let handler = ArtifactFetchHandler::new(cas);
        let missing_hash = [0x22; 32];
        let args = ToolArgs::Artifact(ArtifactArgs {
            stable_id: None,
            content_hash: Some(missing_hash),
            expected_hash: None,
            max_bytes: 64,
            format: None,
        });

        let result = handler.execute(&args).await;
        assert!(
            matches!(result, Err(ToolHandlerError::FileNotFound { .. })),
            "expected missing artifact"
        );
    }

    // =========================================================================
    // ListFilesHandler tests (TCK-00315)
    // =========================================================================

    use crate::episode::tool_handler::{ListFilesArgs, SearchArgs};

    #[test]
    fn test_listfiles_validate_relative_path() {
        let handler = ListFilesHandler::new();
        let args = ToolArgs::ListFiles(ListFilesArgs {
            path: PathBuf::from("src"),
            pattern: None,
            max_entries: None,
        });
        assert!(handler.validate(&args).is_ok());
    }

    #[test]
    fn test_listfiles_validate_rejects_absolute_path() {
        let handler = ListFilesHandler::new();
        let args = ToolArgs::ListFiles(ListFilesArgs {
            path: PathBuf::from("/etc"),
            pattern: None,
            max_entries: None,
        });
        let result = handler.validate(&args);
        assert!(matches!(
            result,
            Err(ToolHandlerError::PathValidation { .. })
        ));
    }

    #[test]
    fn test_listfiles_validate_rejects_traversal() {
        let handler = ListFilesHandler::new();
        let args = ToolArgs::ListFiles(ListFilesArgs {
            path: PathBuf::from("src/../../../etc"),
            pattern: None,
            max_entries: None,
        });
        let result = handler.validate(&args);
        assert!(matches!(
            result,
            Err(ToolHandlerError::PathValidation { .. })
        ));
    }

    #[test]
    fn test_listfiles_validate_rejects_excessive_max_entries() {
        let handler = ListFilesHandler::new();
        let args = ToolArgs::ListFiles(ListFilesArgs {
            path: PathBuf::from("src"),
            pattern: None,
            max_entries: Some(100_000), // Exceeds LISTFILES_MAX_ENTRIES (10,000)
        });
        let result = handler.validate(&args);
        assert!(matches!(result, Err(ToolHandlerError::InvalidArgs { .. })));
    }

    #[test]
    fn test_listfiles_validate_rejects_long_pattern() {
        let handler = ListFilesHandler::new();
        let args = ToolArgs::ListFiles(ListFilesArgs {
            path: PathBuf::from("src"),
            pattern: Some("*".repeat(300)), // Exceeds 256 char limit
            max_entries: None,
        });
        let result = handler.validate(&args);
        assert!(matches!(result, Err(ToolHandlerError::InvalidArgs { .. })));
    }

    #[test]
    fn test_listfiles_glob_matching() {
        // Test the internal glob matcher
        assert!(ListFilesHandler::matches_pattern("main.rs", "*.rs"));
        assert!(ListFilesHandler::matches_pattern("lib.rs", "*.rs"));
        assert!(!ListFilesHandler::matches_pattern("main.txt", "*.rs"));
        assert!(ListFilesHandler::matches_pattern("test_main.rs", "test_*"));
        assert!(ListFilesHandler::matches_pattern(
            "foo.bar.baz",
            "foo.*.baz"
        ));
        assert!(ListFilesHandler::matches_pattern("exact", "exact"));
        assert!(!ListFilesHandler::matches_pattern("different", "exact"));
        assert!(ListFilesHandler::matches_pattern("file", "????"));
        assert!(!ListFilesHandler::matches_pattern("fi", "????"));
    }

    // =========================================================================
    // SearchHandler tests (TCK-00315)
    // =========================================================================

    #[test]
    fn test_search_validate_relative_scope() {
        let handler = SearchHandler::new();
        let args = ToolArgs::Search(SearchArgs {
            query: "fn main".to_string(),
            scope: PathBuf::from("src"),
            max_bytes: None,
            max_lines: None,
        });
        assert!(handler.validate(&args).is_ok());
    }

    #[test]
    fn test_search_validate_rejects_absolute_scope() {
        let handler = SearchHandler::new();
        let args = ToolArgs::Search(SearchArgs {
            query: "secret".to_string(),
            scope: PathBuf::from("/etc/shadow"),
            max_bytes: None,
            max_lines: None,
        });
        let result = handler.validate(&args);
        assert!(matches!(
            result,
            Err(ToolHandlerError::PathValidation { .. })
        ));
    }

    #[test]
    fn test_search_validate_rejects_traversal_scope() {
        let handler = SearchHandler::new();
        let args = ToolArgs::Search(SearchArgs {
            query: "secret".to_string(),
            scope: PathBuf::from("../../../etc"),
            max_bytes: None,
            max_lines: None,
        });
        let result = handler.validate(&args);
        assert!(matches!(
            result,
            Err(ToolHandlerError::PathValidation { .. })
        ));
    }

    #[test]
    fn test_search_validate_rejects_empty_query() {
        let handler = SearchHandler::new();
        let args = ToolArgs::Search(SearchArgs {
            query: String::new(),
            scope: PathBuf::from("src"),
            max_bytes: None,
            max_lines: None,
        });
        let result = handler.validate(&args);
        assert!(matches!(result, Err(ToolHandlerError::InvalidArgs { .. })));
    }

    #[test]
    fn test_search_validate_rejects_long_query() {
        let handler = SearchHandler::new();
        let args = ToolArgs::Search(SearchArgs {
            query: "a".repeat(2000), // Exceeds 1024 char limit
            scope: PathBuf::from("src"),
            max_bytes: None,
            max_lines: None,
        });
        let result = handler.validate(&args);
        assert!(matches!(result, Err(ToolHandlerError::InvalidArgs { .. })));
    }

    #[test]
    fn test_search_validate_rejects_excessive_max_bytes() {
        let handler = SearchHandler::new();
        let args = ToolArgs::Search(SearchArgs {
            query: "fn main".to_string(),
            scope: PathBuf::from("src"),
            max_bytes: Some(100_000), // Exceeds NAVIGATION_OUTPUT_MAX_BYTES (65536)
            max_lines: None,
        });
        let result = handler.validate(&args);
        assert!(matches!(result, Err(ToolHandlerError::InvalidArgs { .. })));
    }

    #[test]
    fn test_search_validate_rejects_excessive_max_lines() {
        let handler = SearchHandler::new();
        let args = ToolArgs::Search(SearchArgs {
            query: "fn main".to_string(),
            scope: PathBuf::from("src"),
            max_bytes: None,
            max_lines: Some(5000), // Exceeds NAVIGATION_OUTPUT_MAX_LINES (2000)
        });
        let result = handler.validate(&args);
        assert!(matches!(result, Err(ToolHandlerError::InvalidArgs { .. })));
    }

    #[test]
    fn test_search_count_lines() {
        assert_eq!(SearchHandler::count_lines(b""), 0);
        assert_eq!(SearchHandler::count_lines(b"no newlines"), 0);
        assert_eq!(SearchHandler::count_lines(b"one\n"), 1);
        assert_eq!(SearchHandler::count_lines(b"one\ntwo\n"), 2);
        assert_eq!(SearchHandler::count_lines(b"a\nb\nc"), 2);
    }

    #[tokio::test]
    async fn test_search_execute_uses_relative_paths_and_charges_budget() {
        let temp_dir = TempDir::new().expect("create temp dir");
        let file_path = temp_dir.path().join("file.txt");
        std::fs::write(&file_path, "hello\nfn main\n").expect("write file");
        let file_size = std::fs::metadata(&file_path).expect("stat file").len();

        let handler = SearchHandler::with_root(temp_dir.path());
        let args = ToolArgs::Search(SearchArgs {
            query: "fn main".to_string(),
            scope: PathBuf::from("file.txt"),
            max_bytes: None,
            max_lines: None,
        });

        let result = handler.execute(&args).await.expect("execute search");
        let output = result.output_str().expect("utf8 output");

        assert!(
            output.starts_with("file.txt:"),
            "expected relative path in output: {output:?}"
        );
        assert!(
            !output.contains(&temp_dir.path().display().to_string()),
            "output leaked absolute root path: {output:?}"
        );

        #[allow(clippy::cast_possible_truncation)]
        let expected_wall_ms = result.duration.as_millis().min(u128::from(u64::MAX)) as u64;
        assert_eq!(
            result.budget_consumed.wall_ms, expected_wall_ms,
            "expected wall_ms to match duration"
        );
        assert!(
            result.budget_consumed.bytes_io >= file_size,
            "expected bytes_io to include scanned file bytes"
        );
        assert!(
            result.budget_consumed.bytes_io >= result.output.len() as u64,
            "expected bytes_io to include output bytes"
        );
    }

    #[tokio::test]
    async fn test_search_execute_rejects_large_single_file_scope() {
        let temp_dir = TempDir::new().expect("create temp dir");
        let file_path = temp_dir.path().join("big.bin");
        let file = std::fs::File::create(&file_path).expect("create file");
        file.set_len(SEARCH_MAX_FILE_SIZE + 1)
            .expect("set file length");

        let handler = SearchHandler::with_root(temp_dir.path());
        let args = ToolArgs::Search(SearchArgs {
            query: "needle".to_string(),
            scope: PathBuf::from("big.bin"),
            max_bytes: None,
            max_lines: None,
        });

        let result = handler.execute(&args).await;
        assert!(matches!(result, Err(ToolHandlerError::InvalidArgs { .. })));
    }

    // =========================================================================
    // ToolArgs tests for ListFiles and Search (TCK-00315)
    // =========================================================================

    #[test]
    fn test_tool_args_listfiles_class() {
        let args = ToolArgs::ListFiles(ListFilesArgs {
            path: PathBuf::from("src"),
            pattern: None,
            max_entries: None,
        });
        assert_eq!(args.tool_class(), ToolClass::ListFiles);
    }

    #[test]
    fn test_tool_args_search_class() {
        let args = ToolArgs::Search(SearchArgs {
            query: "fn main".to_string(),
            scope: PathBuf::from("src"),
            max_bytes: None,
            max_lines: None,
        });
        assert_eq!(args.tool_class(), ToolClass::Search);
    }
}
