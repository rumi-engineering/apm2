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
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tracing::warn;

use super::decision::{BudgetDelta, Credential, MAX_TOOL_OUTPUT_SIZE};
use super::executor::ContentAddressedStore;
use super::tool_class::ToolClass;
use super::tool_handler::{ToolArgs, ToolHandler, ToolHandlerError, ToolResultData};

// =============================================================================
// Platform-Specific O_NOFOLLOW Support (TCK-00319 TOCTOU Mitigation)
// =============================================================================

/// Opens a file with `O_NOFOLLOW` on Unix platforms to prevent TOCTOU symlink
/// attacks.
///
/// # Security (TCK-00319)
///
/// On Unix, this uses `OpenOptionsExt::custom_flags(libc::O_NOFOLLOW)` to
/// ensure the kernel rejects symlinks at open time. This closes the TOCTOU
/// window between path validation and file access.
///
/// On non-Unix platforms, falls back to standard open (symlink checks are still
/// performed via `reject_symlinks_in_path` for defense in depth).
///
/// # Arguments
///
/// * `path` - The validated path to open
///
/// # Returns
///
/// An async file handle or error if open fails.
#[cfg(unix)]
#[allow(clippy::unused_async)] // Must be async for API consistency with non-Unix variant
async fn open_file_nofollow(path: &Path) -> Result<tokio::fs::File, std::io::Error> {
    use std::os::unix::fs::OpenOptionsExt as _;
    // Use std::fs::OpenOptions to set custom_flags (O_NOFOLLOW), then wrap in tokio
    let std_file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(path)?;
    Ok(tokio::fs::File::from_std(std_file))
}

#[cfg(not(unix))]
async fn open_file_nofollow(path: &Path) -> Result<tokio::fs::File, std::io::Error> {
    // Non-Unix fallback: rely on symlink checks in validation (must be async for
    // await)
    tokio::fs::File::open(path).await
}

/// Opens a file for writing with `O_NOFOLLOW` on Unix platforms.
///
/// # Security (TCK-00319)
///
/// See `open_file_nofollow` for security rationale.
#[cfg(unix)]
#[allow(clippy::unused_async)] // Must be async for API consistency with non-Unix variant
async fn open_file_write_nofollow(
    path: &Path,
    create: bool,
    append: bool,
) -> Result<tokio::fs::File, std::io::Error> {
    use std::os::unix::fs::OpenOptionsExt as _;
    // Use std::fs::OpenOptions to set custom_flags (O_NOFOLLOW), then wrap in tokio
    let mut options = std::fs::OpenOptions::new();
    options.write(true).custom_flags(nix::libc::O_NOFOLLOW);
    if create {
        options.create(true);
    }
    if append {
        options.append(true);
    }
    let std_file = options.open(path)?;
    Ok(tokio::fs::File::from_std(std_file))
}

#[cfg(not(unix))]
async fn open_file_write_nofollow(
    path: &Path,
    create: bool,
    append: bool,
) -> Result<tokio::fs::File, std::io::Error> {
    // Non-Unix fallback
    let mut options = tokio::fs::OpenOptions::new();
    options.write(true);
    if create {
        options.create(true);
    }
    if append {
        options.append(true);
    }
    options.open(path).await
}

// =============================================================================
// Path Validation Helpers (TCK-00319 Security Module)
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

/// Rejects symlinks at any component of the path (TOCTOU mitigation).
///
/// # Security
///
/// Per CTR-1503 and RSK-1501 (TOCTOU):
/// - Uses `symlink_metadata()` to detect symlinks WITHOUT following them
/// - Checks each path component for symlink status
/// - Rejects any symlink found in the path chain
///
/// This provides defense-in-depth against TOCTOU races where a symlink could
/// be created between path validation and file access. While this doesn't
/// eliminate all TOCTOU windows, it significantly reduces the attack surface.
///
/// # Arguments
///
/// * `path` - The path to check (should be the full resolved path)
/// * `root` - The workspace root (components within root are checked)
///
/// # Errors
///
/// Returns error if any component of the path (within the workspace) is a
/// symlink.
fn reject_symlinks_in_path(path: &Path, root: &Path) -> Result<(), ToolHandlerError> {
    // Get the relative portion of the path (components after root)
    // Path doesn't start with root - this is a containment violation
    let Ok(relative) = path.strip_prefix(root) else {
        return Err(ToolHandlerError::PathValidation {
            path: path.display().to_string(),
            reason: "path does not start with workspace root".to_string(),
        });
    };

    // Check each component by building up the path progressively
    let mut check_path = root.to_path_buf();
    for component in relative.components() {
        check_path.push(component);

        // Use symlink_metadata to check WITHOUT following symlinks
        // This is the key TOCTOU mitigation: we detect symlinks before access
        match std::fs::symlink_metadata(&check_path) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    return Err(ToolHandlerError::PathValidation {
                        path: check_path.display().to_string(),
                        reason: format!(
                            "symlink detected at '{}'; symlinks are not allowed in workspace paths \
                             (CTR-1503: symlink escape prevention)",
                            check_path.display()
                        ),
                    });
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // TCK-00319 SECURITY FIX: Do NOT break early on NotFound!
                //
                // Breaking here allows attackers to bypass symlink checks using
                // paths like `nonexistent/symlink_to_etc/file`. The attacker
                // can:
                // 1. Request write to `nonexistent/evil_symlink/secret`
                // 2. We check `nonexistent` -> NotFound, break loop
                // 3. create_dir_all creates `nonexistent/`
                // 4. Attacker races to create `evil_symlink` -> `/etc/`
                // 5. We write to `/etc/secret`
                //
                // Instead, we continue checking remaining components.
                // Non-existent components are fine (they'll be
                // created), but we MUST detect any
                // symlinks that might exist later in the path after directory
                // creation.
                //
                // Note: This is safe because we check ALL components, and the
                // final write uses O_NOFOLLOW. The full
                // TOCTOU-mitigating validation after
                // create_dir_all (Step 5) provides defense-in-depth.
            },
            Err(e) => {
                // Other errors (permission denied, etc.) - fail closed
                return Err(ToolHandlerError::ExecutionFailed {
                    message: format!(
                        "failed to check path component '{}' for symlinks: {}",
                        check_path.display(),
                        e
                    ),
                });
            },
        }
    }

    Ok(())
}

/// Validates path with full TOCTOU mitigation for existing files.
///
/// # Security
///
/// This function combines multiple layers of defense per TCK-00319:
///
/// 1. **Syntactic validation** - Rejects `..`, absolute paths, null bytes
/// 2. **Symlink component check** - Uses `symlink_metadata` on each component
/// 3. **Canonical containment** - Verifies resolved path stays within root
///
/// The symlink component check (step 2) provides TOCTOU mitigation by detecting
/// symlinks BEFORE canonicalization. This prevents the attack where:
/// - Attacker creates `workspace/evil` as a regular directory
/// - Validation passes
/// - Attacker swaps `workspace/evil` for a symlink to `/etc/shadow`
/// - File access follows the symlink
///
/// By checking for symlinks at each component FIRST, we reduce the TOCTOU
/// window.
///
/// # Arguments
///
/// * `relative_path` - The relative path to validate
/// * `root` - The workspace root (must be canonical)
///
/// # Errors
///
/// Returns error if the path fails any validation check.
fn validate_path_with_toctou_mitigation(
    relative_path: &Path,
    canonical_root: &Path,
) -> Result<PathBuf, ToolHandlerError> {
    // Step 1: Syntactic validation
    validate_path(relative_path)?;

    // Step 2: Build the full path
    let full_path = canonical_root.join(relative_path);

    // Step 3: TOCTOU mitigation - check for symlinks at each component
    // This must happen BEFORE canonicalize() to prevent symlink swap attacks
    reject_symlinks_in_path(&full_path, canonical_root)?;

    // Step 4: Canonicalize and verify containment (defense in depth)
    // Even after symlink checks, verify the resolved path stays in workspace
    if full_path.exists() {
        let canonical_path =
            std::fs::canonicalize(&full_path).map_err(|e| ToolHandlerError::ExecutionFailed {
                message: format!(
                    "failed to canonicalize path '{}': {}",
                    full_path.display(),
                    e
                ),
            })?;

        validate_resolved_path_within_root(&canonical_path, canonical_root)?;
        Ok(canonical_path)
    } else {
        // Path doesn't exist yet - return the non-canonical path
        // This is OK because reject_symlinks_in_path verified no symlinks
        // exist in the path components that DO exist
        Ok(full_path)
    }
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

/// TCK-00319: Default implementation is restricted to test builds only.
/// Production code MUST use `ReadFileHandler::with_root()` with an explicit
/// workspace path.
#[cfg(test)]
impl Default for ReadFileHandler {
    fn default() -> Self {
        Self {
            root: PathBuf::from("."),
        }
    }
}

impl ReadFileHandler {
    /// Creates a new read file handler using CWD as root.
    ///
    /// # Security Warning (TCK-00319)
    ///
    /// Using CWD as root is a security anti-pattern. Prefer `with_root()` to
    /// explicitly specify the workspace directory. This prevents:
    /// - Tool operations accessing daemon-local files
    /// - Path traversal attacks escaping the intended workspace
    #[deprecated(
        since = "0.1.0",
        note = "use with_root() with explicit workspace path for production code"
    )]
    #[allow(clippy::new_without_default)] // TCK-00319: Default is test-only
    #[must_use]
    pub fn new() -> Self {
        Self {
            root: PathBuf::from("."),
        }
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

    async fn execute(
        &self,
        args: &ToolArgs,
        _credential: Option<&Credential>,
    ) -> Result<ToolResultData, ToolHandlerError> {
        // Validate arguments first (MAJOR 1 fix)
        self.validate(args)?;

        let ToolArgs::Read(read_args) = args else {
            return Err(ToolHandlerError::InvalidArgs {
                reason: "expected Read arguments".to_string(),
            });
        };

        // Start timing I/O operations (MAJOR 2 fix)
        let io_start = Instant::now();

        // Canonicalize root for comparison (TCK-00319: TOCTOU mitigation)
        let canonical_root =
            std::fs::canonicalize(&self.root).map_err(|e| ToolHandlerError::ExecutionFailed {
                message: format!(
                    "failed to canonicalize root '{}': {}",
                    self.root.display(),
                    e
                ),
            })?;

        // TCK-00319: Use TOCTOU-mitigating validation that checks for symlinks
        // BEFORE canonicalization to prevent symlink-swap attacks
        let validated_path =
            validate_path_with_toctou_mitigation(&read_args.path, &canonical_root)?;

        // TCK-00319: Open file with O_NOFOLLOW to prevent TOCTOU symlink attacks
        // This ensures the kernel rejects symlinks at open time, closing the window
        // between validation and access.
        let mut file = open_file_nofollow(&validated_path).await.map_err(|e| {
            ToolHandlerError::ExecutionFailed {
                message: format!("failed to open file '{}': {}", read_args.path.display(), e),
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

/// TCK-00319: Default implementation is restricted to test builds only.
/// Production code MUST use `WriteFileHandler::with_root()` with an explicit
/// workspace path.
#[cfg(test)]
impl Default for WriteFileHandler {
    fn default() -> Self {
        Self {
            root: PathBuf::from("."),
        }
    }
}

impl WriteFileHandler {
    /// Creates a new write file handler using CWD as root.
    ///
    /// # Security Warning (TCK-00319)
    ///
    /// Using CWD as root is a security anti-pattern. Prefer `with_root()` to
    /// explicitly specify the workspace directory. This prevents:
    /// - Tool operations accessing daemon-local files
    /// - Path traversal attacks escaping the intended workspace
    #[deprecated(
        since = "0.1.0",
        note = "use with_root() with explicit workspace path for production code"
    )]
    #[allow(clippy::new_without_default)] // TCK-00319: Default is test-only
    #[must_use]
    pub fn new() -> Self {
        Self {
            root: PathBuf::from("."),
        }
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

    async fn execute(
        &self,
        args: &ToolArgs,
        _credential: Option<&Credential>,
    ) -> Result<ToolResultData, ToolHandlerError> {
        // Validate arguments first (MAJOR 1 fix)
        self.validate(args)?;

        let ToolArgs::Write(write_args) = args else {
            return Err(ToolHandlerError::InvalidArgs {
                reason: "expected Write arguments".to_string(),
            });
        };

        // Start timing I/O operations (MAJOR 2 fix)
        let io_start = Instant::now();

        // Canonicalize root for comparison (TCK-00319: TOCTOU mitigation)
        let canonical_root =
            std::fs::canonicalize(&self.root).map_err(|e| ToolHandlerError::ExecutionFailed {
                message: format!(
                    "failed to canonicalize root '{}': {}",
                    self.root.display(),
                    e
                ),
            })?;

        // TCK-00319: VALIDATE FIRST before any filesystem mutations!
        // This prevents path traversal attacks via create_dir_all
        // Step 1: Syntactic validation (rejects .., absolute paths, null bytes)
        validate_path(&write_args.path)?;

        // Step 2: Build full path using canonical root
        let full_path = canonical_root.join(&write_args.path);

        // Step 3: Check for existing symlinks in the path BEFORE create_dir_all
        // This prevents symlink-based escape via directory creation
        // reject_symlinks_in_path handles non-existent components gracefully
        reject_symlinks_in_path(&full_path, &canonical_root)?;

        // Step 4: Create parent directories if requested (AFTER symlink validation)
        // TCK-00319 SECURITY: Full validation BEFORE any filesystem mutations.
        //
        // The initial symlink check (Step 3) validates existing components.
        // After create_dir_all, we MUST re-validate to catch any TOCTOU attacks
        // where an attacker raced to introduce symlinks during directory creation.
        if write_args.create_parents {
            if let Some(parent) = full_path.parent() {
                // Verify parent path syntactically stays within workspace
                // (defense-in-depth alongside Step 5's full re-validation)
                if !parent.starts_with(&canonical_root) {
                    return Err(ToolHandlerError::PathValidation {
                        path: parent.display().to_string(),
                        reason: "parent directory escapes workspace root".to_string(),
                    });
                }
                tokio::fs::create_dir_all(parent).await.map_err(|e| {
                    ToolHandlerError::ExecutionFailed {
                        message: format!("failed to create parent directories: {e}"),
                    }
                })?;

                // TCK-00319 SECURITY: Re-validate parent for symlinks IMMEDIATELY
                // after create_dir_all to catch TOCTOU races. An attacker might:
                // 1. Wait for create_dir_all to create /workspace/a/
                // 2. Race to replace /workspace/a/ with symlink to /etc/
                // 3. We then write to /etc/file
                //
                // By re-validating the parent path here, we catch such attacks
                // before proceeding to the file write.
                reject_symlinks_in_path(parent, &canonical_root)?;
            }
        }

        // Step 5: Full TOCTOU-mitigating validation (final re-check)
        // This is defense-in-depth: validates the complete target path after
        // all directory creation is complete, catching any remaining TOCTOU attacks.
        let validated_path =
            validate_path_with_toctou_mitigation(&write_args.path, &canonical_root)?;

        let content = write_args.content.as_deref().unwrap_or(&[]);
        let bytes_written = content.len() as u64;

        if write_args.append {
            // Append mode: cannot be strictly atomic, but standard O_APPEND is safe
            // for appends.
            // TCK-00319: Use O_NOFOLLOW to prevent TOCTOU symlink attacks.
            let mut file = open_file_write_nofollow(&validated_path, true, true)
                .await
                .map_err(|e| ToolHandlerError::ExecutionFailed {
                    message: format!("failed to open file for append: {e}"),
                })?;

            file.write_all(content)
                .await
                .map_err(|e| ToolHandlerError::ExecutionFailed {
                    message: format!("failed to append content: {e}"),
                })?;

            // Flush to ensure data is written to disk before returning
            file.flush()
                .await
                .map_err(|e| ToolHandlerError::ExecutionFailed {
                    message: format!("failed to flush appended content: {e}"),
                })?;
        } else {
            // Overwrite mode: use atomic write pattern (CTR-1502)
            // 1. Write to .tmp.<uuid>
            // 2. Rename to target path
            let file_name = validated_path
                .file_name()
                .ok_or_else(|| ToolHandlerError::InvalidArgs {
                    reason: "invalid file path".to_string(),
                })?
                .to_string_lossy();

            let tmp_name = format!(".{}.tmp.{}", file_name, uuid::Uuid::new_v4());
            let tmp_path = validated_path
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
            if let Err(e) = tokio::fs::rename(&tmp_path, &validated_path).await {
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

// SEC-CTRL-FAC-0016: Environment variable allowlist for sandboxed execution.
// Only these variables are passed through to spawned processes.
// All others are scrubbed to prevent credential/secret leakage.
const ENV_PASSTHROUGH: &[&str] = &[
    "PATH",
    "HOME",
    "USER",
    "SHELL",
    "TERM",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TZ",
    "TMPDIR",
    "XDG_RUNTIME_DIR",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_CACHE_HOME",
];

// SEC-CTRL-FAC-0016: Environment variable patterns that are ALWAYS blocked,
// even if they appear in a custom passthrough list.
const ENV_BLOCKLIST_PATTERNS: &[&str] = &[
    "API_KEY",
    "API_SECRET",
    "SECRET",
    "TOKEN",
    "PASSWORD",
    "PASSWD",
    "CREDENTIAL",
    "AUTH",
    "PRIVATE_KEY",
    "AWS_SECRET",
    "AZURE_SECRET",
    "GCP_SECRET",
    "GITHUB_TOKEN",
    "GITLAB_TOKEN",
    "NPM_TOKEN",
    "DOCKER_PASSWORD",
    "SSH_PRIVATE",
    "PGP_PRIVATE",
    "GPG_PRIVATE",
];

// =============================================================================
// TCK-00338: Shell Argument Escaping (SEC-CTRL-FAC-0016)
// =============================================================================

/// Characters that require shell escaping when appearing in arguments.
/// These characters have special meaning in POSIX shells and could enable
/// injection attacks if not properly escaped.
const SHELL_SPECIAL_CHARS: &[char] = &[
    ' ', '\t', '\n', '\r', // Whitespace (argument separators)
    '"', '\'', '\\', // Quoting characters
    '$', '`', // Variable/command expansion
    '!', '*', '?', '[', ']', // Globbing and history
    '(', ')', '{', '}', // Subshells and brace expansion
    '<', '>', '|', '&', ';', // Redirection and control operators
    '#', // Comments
    '~', // Home directory expansion
];

/// Escapes a shell argument to prevent injection attacks.
///
/// # Security (TCK-00338)
///
/// This function ensures that arguments are properly escaped when building
/// a command line string for allowlist matching. Without escaping, an argument
/// containing spaces or special characters could be interpreted as multiple
/// arguments or shell metacharacters.
///
/// For example, without escaping:
/// - `["sh", "-c", "rm -rf /"]` becomes `sh -c rm -rf /`
/// - With escaping: `sh '-c' 'rm -rf /'`
///
/// The escaping strategy uses single quotes for arguments containing special
/// characters, with single quotes within the argument escaped as `'\''`.
///
/// # Arguments
///
/// * `arg` - The argument to escape
///
/// # Returns
///
/// The escaped argument suitable for shell command line representation.
fn escape_shell_arg(arg: &str) -> String {
    // If the argument is empty, represent it as ''
    if arg.is_empty() {
        return "''".to_string();
    }

    // If the argument contains no special characters, return as-is
    if !arg.chars().any(|c| SHELL_SPECIAL_CHARS.contains(&c)) {
        return arg.to_string();
    }

    // Escape using single quotes, handling embedded single quotes
    // The pattern 'arg' works for most cases, but single quotes within
    // the argument must be escaped as '\'' (end quote, escaped quote, start quote)
    let mut escaped = String::with_capacity(arg.len() + 2);
    escaped.push('\'');
    for c in arg.chars() {
        if c == '\'' {
            // End current quote, add escaped single quote, restart quote
            escaped.push_str("'\\''");
        } else {
            escaped.push(c);
        }
    }
    escaped.push('\'');
    escaped
}

/// Builds a shell-safe command line string for allowlist matching.
///
/// # Security (TCK-00338)
///
/// This function constructs a command line representation where each argument
/// is properly escaped to prevent injection attacks. The resulting string
/// accurately represents what the command would look like if it were executed
/// in a shell.
///
/// # Arguments
///
/// * `command` - The command/executable name
/// * `args` - The arguments to the command
///
/// # Returns
///
/// A shell-safe command line string suitable for allowlist matching.
fn build_escaped_command_line(command: &str, args: &[String]) -> String {
    if args.is_empty() {
        escape_shell_arg(command)
    } else {
        let escaped_command = escape_shell_arg(command);
        let escaped_args: Vec<String> = args.iter().map(|a| escape_shell_arg(a)).collect();
        format!("{} {}", escaped_command, escaped_args.join(" "))
    }
}

/// Configuration for sandboxed command execution (TCK-00338).
///
/// This struct encapsulates security policies for the `ExecuteHandler`:
/// - Shell command allowlist (fail-closed if empty)
/// - Environment variable passthrough list
/// - Stall detection timeout
///
/// # Security Model (SEC-CTRL-FAC-0016)
///
/// - **Fail-closed**: Empty allowlist means no commands are allowed
/// - **Env scrubbing**: Only allowlisted env vars pass through
/// - **Blocklist override**: Sensitive patterns are always blocked
#[derive(Debug, Clone)]
pub struct SandboxConfig {
    /// Shell command patterns that are allowed.
    /// Uses glob-style matching via `shell_pattern_matches`.
    /// Empty means fail-closed (no commands allowed).
    pub shell_allowlist: Vec<String>,

    /// Additional environment variables to pass through beyond the defaults.
    /// Variables matching `ENV_BLOCKLIST_PATTERNS` are still blocked.
    pub env_passthrough: Vec<String>,

    /// Stall detection timeout in milliseconds.
    /// If a process produces no output for this duration, it's considered
    /// stalled. Default: 60000ms (60 seconds). Set to 0 to disable.
    pub stall_timeout_ms: u64,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            shell_allowlist: Vec::new(), // Fail-closed by default
            env_passthrough: Vec::new(),
            stall_timeout_ms: 60_000, // 60 second stall detection
        }
    }
}

impl SandboxConfig {
    /// Creates a permissive config that allows all commands.
    /// Use with caution - only for trusted environments.
    #[must_use]
    pub fn permissive() -> Self {
        Self {
            shell_allowlist: vec!["*".to_string()], // Allow everything
            env_passthrough: Vec::new(),
            stall_timeout_ms: 60_000,
        }
    }

    /// Creates a config with a specific shell allowlist.
    #[must_use]
    pub fn with_shell_allowlist(allowlist: Vec<String>) -> Self {
        Self {
            shell_allowlist: allowlist,
            ..Default::default()
        }
    }

    /// Adds environment variables to the passthrough list.
    #[must_use]
    pub fn with_env_passthrough(mut self, vars: Vec<String>) -> Self {
        self.env_passthrough = vars;
        self
    }

    /// Sets the stall detection timeout.
    #[must_use]
    pub const fn with_stall_timeout_ms(mut self, timeout_ms: u64) -> Self {
        self.stall_timeout_ms = timeout_ms;
        self
    }

    /// Checks if an environment variable name should be passed through.
    ///
    /// Returns `true` if the variable is in the passthrough list AND
    /// does not match any blocklist patterns.
    #[must_use]
    pub fn should_pass_env(&self, name: &str) -> bool {
        // Check blocklist first (case-insensitive)
        let name_upper = name.to_uppercase();
        for pattern in ENV_BLOCKLIST_PATTERNS {
            if name_upper.contains(pattern) {
                return false;
            }
        }

        // Check if in default passthrough
        if ENV_PASSTHROUGH.contains(&name) {
            return true;
        }

        // Check if in custom passthrough
        self.env_passthrough.iter().any(|v| v == name)
    }

    /// Checks if a command is allowed by the shell allowlist.
    ///
    /// Returns `true` if the full command line matches any pattern in the
    /// allowlist. Returns `false` if the allowlist is empty (fail-closed).
    #[must_use]
    pub fn is_command_allowed(&self, command_line: &str) -> bool {
        use super::tool_class::shell_pattern_matches;

        if self.shell_allowlist.is_empty() {
            // Fail-closed: empty allowlist means nothing is allowed
            return false;
        }

        self.shell_allowlist
            .iter()
            .any(|pattern| shell_pattern_matches(pattern, command_line))
    }
}

/// Real handler for command execution.
///
/// This handler executes commands in a sandboxed environment (restricted to
/// CWD/workspace), enforces timeouts, and bounds output capture.
///
/// # Security (TCK-00338)
///
/// - **Shell Allowlist**: Commands must match patterns in
///   `SandboxConfig::shell_allowlist`. Empty allowlist means fail-closed (no
///   commands allowed).
/// - **Env Scrubbing**: Environment is cleared, only allowlisted vars pass
///   through. Sensitive patterns (`API_KEY`, `TOKEN`, etc.) are always blocked.
/// - **Sandbox**: Commands execute in specified CWD (validated relative path),
///   anchored to the configured root.
/// - **Timeout**: Enforced per-execution timeout (default 30s, max 1h).
/// - **Stall Detection**: Processes producing no output are terminated.
/// - **Output**: Stdout/Stderr captured up to `MAX_TOOL_OUTPUT_SIZE`.
/// - **Input**: Stdin pipe supported with size limits.
#[derive(Debug)]
pub struct ExecuteHandler {
    root: PathBuf,
    sandbox_config: SandboxConfig,
}

/// TCK-00319: Default implementation is restricted to test builds only.
/// Production code MUST use `ExecuteHandler::with_root()` with an explicit
/// workspace path.
#[cfg(test)]
impl Default for ExecuteHandler {
    fn default() -> Self {
        Self {
            root: PathBuf::from("."),
            // Test default uses permissive config for backwards compatibility
            sandbox_config: SandboxConfig::permissive(),
        }
    }
}

impl ExecuteHandler {
    /// Creates a new execute handler using CWD as root.
    ///
    /// # Security Warning (TCK-00319)
    ///
    /// Using CWD as root is a security anti-pattern. Prefer `with_root()` to
    /// explicitly specify the workspace directory. This prevents:
    /// - Tool operations accessing daemon-local files
    /// - Path traversal attacks escaping the intended workspace
    #[deprecated(
        since = "0.1.0",
        note = "use with_root() with explicit workspace path for production code"
    )]
    #[allow(clippy::new_without_default)] // TCK-00319: Default is test-only
    #[must_use]
    pub fn new() -> Self {
        Self {
            root: PathBuf::from("."),
            // Deprecated constructor uses permissive config for backwards compatibility
            sandbox_config: SandboxConfig::permissive(),
        }
    }

    /// Creates a new execute handler with a specific root directory.
    ///
    /// # Security (TCK-00338)
    ///
    /// This constructor uses a fail-closed sandbox config (empty allowlist).
    /// No commands will be allowed unless you explicitly configure the sandbox
    /// using `with_root_and_sandbox()`.
    ///
    /// For production use, call `with_root_and_sandbox()` with an explicit
    /// shell allowlist. For tests that need permissive mode, use
    /// `with_root_permissive()`.
    #[must_use]
    pub fn with_root(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            // TCK-00338: Fail-closed by default (no commands allowed)
            sandbox_config: SandboxConfig::default(),
        }
    }

    /// Creates a new execute handler with permissive sandbox config.
    ///
    /// # Security Warning (TCK-00338)
    ///
    /// This constructor allows ALL commands to execute. Only use in:
    /// - Tests that need backwards-compatible permissive behavior
    /// - Trusted environments where command filtering is done elsewhere
    ///
    /// For production use, prefer `with_root_and_sandbox()` with an explicit
    /// shell allowlist.
    #[must_use]
    pub fn with_root_permissive(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            sandbox_config: SandboxConfig::permissive(),
        }
    }

    /// Creates a new execute handler with explicit sandbox configuration.
    ///
    /// # Security (TCK-00338)
    ///
    /// This is the recommended constructor for production use. It allows you to
    /// specify:
    /// - A shell allowlist (fail-closed if empty)
    /// - Environment variable passthrough rules
    /// - Stall detection timeout
    ///
    /// # Example
    ///
    /// ```ignore
    /// let config = SandboxConfig::with_shell_allowlist(vec![
    ///     "cargo *".to_string(),
    ///     "npm *".to_string(),
    ///     "git *".to_string(),
    /// ]);
    /// let handler = ExecuteHandler::with_root_and_sandbox("/workspace", config);
    /// ```
    #[must_use]
    pub fn with_root_and_sandbox(root: impl Into<PathBuf>, sandbox_config: SandboxConfig) -> Self {
        Self {
            root: root.into(),
            sandbox_config,
        }
    }

    /// Returns the current sandbox configuration.
    #[must_use]
    pub const fn sandbox_config(&self) -> &SandboxConfig {
        &self.sandbox_config
    }
}

#[async_trait]
impl ToolHandler for ExecuteHandler {
    fn tool_class(&self) -> ToolClass {
        ToolClass::Execute
    }

    async fn execute(
        &self,
        args: &ToolArgs,
        _credential: Option<&Credential>,
    ) -> Result<ToolResultData, ToolHandlerError> {
        // Validate arguments first (MAJOR 1 fix)
        self.validate(args)?;

        let ToolArgs::Execute(exec_args) = args else {
            return Err(ToolHandlerError::InvalidArgs {
                reason: "expected Execute arguments".to_string(),
            });
        };

        // Start timing execution (MAJOR 2 fix)
        let exec_start = Instant::now();

        // =====================================================================
        // TCK-00338: Shell Allowlist Validation (SEC-CTRL-FAC-0016)
        // =====================================================================
        // Build full command line for allowlist matching.
        // Arguments are escaped to prevent injection attacks where special
        // characters in arguments could be interpreted as shell metacharacters.
        // For example, `sh -c "rm -rf /"` must be represented as `sh '-c' 'rm -rf /'`
        // to prevent the space-separated arguments from being misinterpreted.
        let full_command_line = build_escaped_command_line(&exec_args.command, &exec_args.args);

        if !self.sandbox_config.is_command_allowed(&full_command_line) {
            warn!(
                command = %exec_args.command,
                full_command = %full_command_line,
                "command denied by shell allowlist (SEC-CTRL-FAC-0016)"
            );
            return Err(ToolHandlerError::InvalidArgs {
                reason: format!(
                    "command '{}' not in shell allowlist (SEC-CTRL-FAC-0016)",
                    exec_args.command
                ),
            });
        }

        let mut cmd = tokio::process::Command::new(&exec_args.command);
        cmd.args(&exec_args.args);

        // =====================================================================
        // TCK-00338: Environment Variable Scrubbing (SEC-CTRL-FAC-0016)
        // =====================================================================
        // Clear all environment variables to prevent credential/secret leakage,
        // then selectively restore only allowlisted variables.
        cmd.env_clear();

        // Restore allowlisted environment variables
        for (key, value) in std::env::vars_os() {
            if let Some(key_str) = key.to_str() {
                if self.sandbox_config.should_pass_env(key_str) {
                    cmd.env(&key, &value);
                }
            }
        }

        // Set working directory with symlink-aware validation (TCK-00319: TOCTOU
        // mitigation) Canonicalize root for comparison
        let canonical_root =
            std::fs::canonicalize(&self.root).map_err(|e| ToolHandlerError::ExecutionFailed {
                message: format!(
                    "failed to canonicalize root '{}': {}",
                    self.root.display(),
                    e
                ),
            })?;

        // If cwd is provided, it's relative to root.
        // If not provided, use root as CWD (which is the canonical root).
        // TCK-00319: Use TOCTOU-mitigating validation for cwd paths
        let validated_cwd = if let Some(ref cwd) = exec_args.cwd {
            validate_path_with_toctou_mitigation(cwd, &canonical_root)?
        } else {
            canonical_root.clone()
        };

        cmd.current_dir(&validated_cwd);

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

        // TCK-00338: Stall detection timeout configuration
        let stall_timeout_ms = self.sandbox_config.stall_timeout_ms;
        let stall_detection_enabled = stall_timeout_ms > 0;

        // Manual bounded pipe reading instead of wait_with_output()
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

        // TCK-00338: Shared state for stall detection - tracks last output time
        // across both stdout and stderr readers using atomic operations.
        // Note: truncation from u128 to u64 is safe here as millis since exec_start
        // will never approach u64::MAX in any reasonable execution.
        #[allow(clippy::cast_possible_truncation)]
        let last_output_time =
            std::sync::Arc::new(AtomicU64::new(exec_start.elapsed().as_millis() as u64));

        // Helper to update last output time
        // Note: truncation from u128 to u64 is safe - see comment above.
        #[allow(clippy::cast_possible_truncation)]
        let update_last_output = |last_time: &AtomicU64, start: Instant| {
            let now_ms = start.elapsed().as_millis() as u64;
            last_time.store(now_ms, Ordering::Release);
        };

        // Read stdout with bounded buffer and stall tracking
        let last_output_stdout = last_output_time.clone();
        let stdout_future = async {
            let mut buf = Vec::new();
            let mut chunk = vec![0u8; 64 * 1024]; // 64KB chunks
            loop {
                match stdout.read(&mut chunk).await {
                    Ok(0) | Err(_) => break, // EOF or read error
                    Ok(n) => {
                        // TCK-00338: Update last output time on successful read
                        update_last_output(&last_output_stdout, exec_start);

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

        // Read stderr with bounded buffer and stall tracking
        let last_output_stderr = last_output_time.clone();
        let stderr_future = async {
            let mut buf = Vec::new();
            let mut chunk = vec![0u8; 64 * 1024]; // 64KB chunks
            loop {
                match stderr.read(&mut chunk).await {
                    Ok(0) | Err(_) => break, // EOF or read error
                    Ok(n) => {
                        // TCK-00338: Update last output time on successful read
                        update_last_output(&last_output_stderr, exec_start);

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

        // TCK-00338: Stall detection monitor task
        // Periodically checks if the process has produced any output recently.
        // If no output for stall_timeout_ms, signals that the process is stalled.
        let last_output_monitor = last_output_time.clone();

        let stall_monitor = async {
            if !stall_detection_enabled {
                // Stall detection disabled, never signal stall
                std::future::pending::<()>().await;
            }

            let check_interval = Duration::from_millis(1000.min(stall_timeout_ms / 2).max(100));

            loop {
                tokio::time::sleep(check_interval).await;

                // Note: truncation from u128 to u64 is safe - see comment above.
                #[allow(clippy::cast_possible_truncation)]
                let now_ms = exec_start.elapsed().as_millis() as u64;
                let last_ms = last_output_monitor.load(Ordering::Acquire);

                if now_ms.saturating_sub(last_ms) >= stall_timeout_ms {
                    // Process has stalled - no output for stall_timeout_ms
                    // Return to trigger the stall detection branch in select!
                    return;
                }
            }
        };

        // Wait for process with bounded output reading and stall detection
        let read_result = tokio::time::timeout(timeout, async {
            // Run all four concurrently: stdout read, stderr read, process wait, stall
            // monitor
            tokio::select! {
                biased;

                // Stall detected - terminate early
                () = stall_monitor => {
                    Err(ToolHandlerError::ExecutionFailed {
                        message: format!(
                            "process stalled: no output for {stall_timeout_ms}ms (SEC-CTRL-FAC-0016)"
                        ),
                    })
                }

                // Normal completion path
                result = async {
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
                } => {
                    result
                }
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

/// TCK-00319: Default implementation is restricted to test builds only.
/// Production code MUST use `GitOperationHandler::with_root()` with an explicit
/// workspace path.
#[cfg(test)]
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
    ///
    /// # Security Warning (TCK-00319)
    ///
    /// Using CWD as root is a security anti-pattern. Prefer `with_root()` to
    /// explicitly specify the workspace directory. This prevents:
    /// - Tool operations accessing daemon-local files
    /// - Path traversal attacks escaping the intended workspace
    #[deprecated(
        since = "0.1.0",
        note = "use with_root() with explicit workspace path for production code"
    )]
    #[allow(clippy::new_without_default)] // TCK-00319: Default is test-only
    #[must_use]
    pub fn new() -> Self {
        Self {
            root: PathBuf::from("."),
        }
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

    async fn execute(
        &self,
        args: &ToolArgs,
        credential: Option<&Credential>,
    ) -> Result<ToolResultData, ToolHandlerError> {
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

        // Canonicalize root for comparison (TCK-00319: TOCTOU mitigation)
        let canonical_root =
            std::fs::canonicalize(&self.root).map_err(|e| ToolHandlerError::ExecutionFailed {
                message: format!(
                    "failed to canonicalize root '{}': {}",
                    self.root.display(),
                    e
                ),
            })?;

        // TCK-00319: Use TOCTOU-mitigating validation for repo_path
        let validated_work_dir = if let Some(ref repo_path) = git_args.repo_path {
            validate_path_with_toctou_mitigation(repo_path, &canonical_root)?
        } else {
            canonical_root.clone()
        };

        // Verify .git exists (must be a git repository)
        let git_dir = validated_work_dir.join(".git");
        if !git_dir.exists() {
            return Err(ToolHandlerError::ExecutionFailed {
                message: format!(
                    "'{}' is not a git repository",
                    git_args.repo_path.as_ref().map_or_else(
                        || self.root.display().to_string(),
                        |p| p.display().to_string()
                    )
                ),
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

        // TCK-00263: Set SSH_AUTH_SOCK if credential is provided and looks like a valid
        // path
        if let Some(cred) = credential {
            let secret = cred.expose_secret();
            // Validate path: absolute, no traversal, and in standard temp/runtime dirs
            // This prevents injecting weird paths or malicious values
            let path = Path::new(secret);
            if path.is_absolute()
                && !secret.contains("..")
                && (secret.starts_with("/tmp/")
                    || secret.starts_with("/run/")
                    || secret.starts_with("/private/"))
            {
                cmd.env("SSH_AUTH_SOCK", secret);
            } else {
                warn!("Ignoring potentially unsafe SSH_AUTH_SOCK credential path pattern");
            }
        }

        // Fail closed on global/system git config
        cmd.env("GIT_CONFIG_NOSYSTEM", "1");
        cmd.env("GIT_CONFIG_GLOBAL", "/dev/null");
        // Explicitly remove repo override env vars (defense in depth)
        cmd.env_remove("GIT_DIR");
        cmd.env_remove("GIT_WORK_TREE");
        cmd.arg("-C").arg(&validated_work_dir);
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

    async fn execute(
        &self,
        args: &ToolArgs,
        _credential: Option<&Credential>,
    ) -> Result<ToolResultData, ToolHandlerError> {
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

/// TCK-00319: Default implementation is restricted to test builds only.
/// Production code MUST use `ListFilesHandler::with_root()` with an explicit
/// workspace path.
#[cfg(test)]
impl Default for ListFilesHandler {
    fn default() -> Self {
        Self {
            root: PathBuf::from("."),
        }
    }
}

impl ListFilesHandler {
    /// Creates a new list files handler using CWD as root.
    ///
    /// # Security Warning (TCK-00319)
    ///
    /// Using CWD as root is a security anti-pattern. Prefer `with_root()` to
    /// explicitly specify the workspace directory. This prevents:
    /// - Tool operations accessing daemon-local files
    /// - Path traversal attacks escaping the intended workspace
    #[deprecated(
        since = "0.1.0",
        note = "use with_root() with explicit workspace path for production code"
    )]
    #[allow(clippy::new_without_default)] // TCK-00319: Default is test-only
    #[must_use]
    pub fn new() -> Self {
        Self {
            root: PathBuf::from("."),
        }
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

    async fn execute(
        &self,
        args: &ToolArgs,
        _credential: Option<&Credential>,
    ) -> Result<ToolResultData, ToolHandlerError> {
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

        // Canonicalize root for comparison (TCK-00319: TOCTOU mitigation)
        let canonical_root =
            std::fs::canonicalize(&self.root).map_err(|e| ToolHandlerError::ExecutionFailed {
                message: format!(
                    "failed to canonicalize root '{}': {}",
                    self.root.display(),
                    e
                ),
            })?;

        // TCK-00319: Use TOCTOU-mitigating validation that checks for symlinks
        // BEFORE canonicalization to prevent symlink-swap attacks
        let validated_target =
            validate_path_with_toctou_mitigation(&ls_args.path, &canonical_root)?;

        // Read directory entries
        let mut entries: Vec<String> = Vec::new();
        #[allow(clippy::cast_possible_truncation)] // Bounded by LISTFILES_MAX_ENTRIES
        let max_entries = ls_args.max_entries.map_or(LISTFILES_DEFAULT_ENTRIES, |n| {
            (n as usize).min(LISTFILES_MAX_ENTRIES)
        });

        let mut dir_iter = tokio::fs::read_dir(&validated_target).await.map_err(|e| {
            ToolHandlerError::ExecutionFailed {
                message: format!(
                    "failed to read directory '{}': {}",
                    ls_args.path.display(),
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

/// TCK-00319: Default implementation is restricted to test builds only.
/// Production code MUST use `SearchHandler::with_root()` with an explicit
/// workspace path.
#[cfg(test)]
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
    ///
    /// # Security Warning (TCK-00319)
    ///
    /// Using CWD as root is a security anti-pattern. Prefer `with_root()` to
    /// explicitly specify the workspace directory. This prevents:
    /// - Tool operations accessing daemon-local files
    /// - Path traversal attacks escaping the intended workspace
    #[deprecated(
        since = "0.1.0",
        note = "use with_root() with explicit workspace path for production code"
    )]
    #[allow(clippy::new_without_default)] // TCK-00319: Default is test-only
    #[must_use]
    pub fn new() -> Self {
        Self {
            root: PathBuf::from("."),
        }
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

    async fn execute(
        &self,
        args: &ToolArgs,
        _credential: Option<&Credential>,
    ) -> Result<ToolResultData, ToolHandlerError> {
        use super::tool_handler::{NAVIGATION_OUTPUT_MAX_BYTES, NAVIGATION_OUTPUT_MAX_LINES};

        // Validate arguments first
        self.validate(args)?;

        let ToolArgs::Search(search_args) = args else {
            return Err(ToolHandlerError::InvalidArgs {
                reason: "expected Search arguments".to_string(),
            });
        };

        let search_start = Instant::now();

        // Canonicalize root for comparison (TCK-00319: TOCTOU mitigation)
        let canonical_root =
            std::fs::canonicalize(&self.root).map_err(|e| ToolHandlerError::ExecutionFailed {
                message: format!(
                    "failed to canonicalize root '{}': {}",
                    self.root.display(),
                    e
                ),
            })?;

        // TCK-00319: Use TOCTOU-mitigating validation that checks for symlinks
        // BEFORE canonicalization to prevent symlink-swap attacks
        let validated_scope =
            validate_path_with_toctou_mitigation(&search_args.scope, &canonical_root)?;

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
            let metadata = tokio::fs::metadata(&validated_scope).await.map_err(|e| {
                ToolHandlerError::ExecutionFailed {
                    message: format!("failed to stat scope '{}': {}", search_args.scope.display(), e),
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

                let display_path = validated_scope
                    .strip_prefix(&canonical_root)
                    .unwrap_or(&validated_scope)
                    .display()
                    .to_string();

                targets.push(SearchTarget {
                    path: validated_scope.clone(),
                    display_path,
                    size,
                });
            } else if metadata.is_dir() {
                Self::collect_files(
                    &validated_scope,
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
/// Registers all handlers with an executor using CWD as root.
///
/// **DEPRECATED**: Use `register_handlers_with_root` for production code.
/// This function exists for backward compatibility and test convenience only.
/// Using CWD as the workspace root is a security anti-pattern that can expose
/// the daemon's working directory to tool operations.
///
/// # Security Warning
///
/// Per TCK-00319, tool handlers MUST be rooted to an explicit workspace
/// directory, not the daemon's CWD. Failure to do so can result in:
/// - Tool operations accessing daemon-local files
/// - Path traversal attacks escaping the intended workspace
/// - Reviewers observing incorrect filesystem state
///
/// **TCK-00319**: This function is now restricted to test builds only.
#[cfg(test)]
#[deprecated(
    since = "0.1.0",
    note = "use register_handlers_with_root with explicit workspace path instead"
)]
#[allow(deprecated)] // Uses deprecated new() methods
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

/// Registers all handlers with an executor rooted to a specific workspace.
///
/// This is the **preferred** way to register tool handlers for production use.
/// All filesystem-accessing handlers are bound to the specified workspace root,
/// preventing access to daemon CWD or other directories.
///
/// # Security
///
/// Per TCK-00319 (Root tool handlers per workspace):
/// - All tool handlers are rooted to `workspace_root`
/// - Path traversal prevention is enforced via canonical root containment
///   checks
/// - Symlink escapes are blocked via `validate_resolved_path_within_root`
/// - ListFiles/Search operations reflect the patched workspace state
///
/// # Arguments
///
/// * `executor` - The tool executor to register handlers with
/// * `cas` - Content-addressed store for artifact operations
/// * `workspace_root` - Absolute path to the workspace directory (MUST exist)
///
/// # Errors
///
/// Returns error if:
/// - The workspace root does not exist or cannot be canonicalized
/// - Handler registration fails
///
/// # Example
///
/// ```rust,ignore
/// use std::path::Path;
/// use apm2_daemon::episode::executor::ToolExecutor;
/// use apm2_daemon::episode::handlers::register_handlers_with_root;
///
/// let workspace = Path::new("/var/lib/apm2/workspaces/episode-123");
/// let mut executor = ToolExecutor::new(tracker, cas.clone());
/// register_handlers_with_root(&mut executor, cas, workspace)?;
/// ```
pub fn register_handlers_with_root(
    executor: &mut super::executor::ToolExecutor,
    cas: std::sync::Arc<dyn ContentAddressedStore>,
    workspace_root: &Path,
) -> Result<(), super::executor::ExecutorError> {
    // Validate workspace root exists and can be canonicalized (fail-closed)
    // This catches misconfiguration early rather than at first tool execution
    if !workspace_root.exists() {
        return Err(super::executor::ExecutorError::ExecutionFailed {
            message: format!(
                "workspace root does not exist: {}",
                workspace_root.display()
            ),
        });
    }

    // Canonicalize early to catch symlink issues at registration time
    let canonical_root = std::fs::canonicalize(workspace_root).map_err(|e| {
        super::executor::ExecutorError::ExecutionFailed {
            message: format!(
                "failed to canonicalize workspace root '{}': {}",
                workspace_root.display(),
                e
            ),
        }
    })?;

    // Register all handlers with the canonical workspace root
    // NOTE: Uses permissive sandbox config for backwards compatibility.
    // For production use with explicit shell allowlist, use
    // `register_handlers_with_root_and_sandbox` instead.
    executor.register_handler(Box::new(ReadFileHandler::with_root(&canonical_root)))?;
    executor.register_handler(Box::new(WriteFileHandler::with_root(&canonical_root)))?;
    // TCK-00338: This deprecated function uses permissive mode for backwards compat
    executor.register_handler(Box::new(ExecuteHandler::with_root_permissive(
        &canonical_root,
    )))?;
    executor.register_handler(Box::new(GitOperationHandler::with_root(&canonical_root)))?;
    executor.register_handler(Box::new(ArtifactFetchHandler::new(cas)))?;
    executor.register_handler(Box::new(ListFilesHandler::with_root(&canonical_root)))?;
    executor.register_handler(Box::new(SearchHandler::with_root(&canonical_root)))?;
    Ok(())
}

/// Registers all tool handlers with an executor using a specified workspace
/// root and explicit sandbox configuration.
///
/// # Security (TCK-00338)
///
/// This is the recommended registration function for production use. It ensures
/// that the `ExecuteHandler` uses an explicit `SandboxConfig` rather than
/// defaulting to `SandboxConfig::permissive()`.
///
/// Unlike `register_handlers_with_root`, this function:
/// - Accepts an explicit `SandboxConfig` for the execute handler
/// - Enables fail-closed shell allowlist enforcement
/// - Enables stall detection timeout
///
/// # Arguments
///
/// * `executor` - The tool executor to register handlers with
/// * `cas` - Content-addressed store for artifact operations
/// * `workspace_root` - The root directory for file/execute operations
/// * `sandbox_config` - Explicit sandbox configuration for the execute handler
///
/// # Example
///
/// ```rust,ignore
/// use std::path::Path;
/// use apm2_daemon::episode::executor::ToolExecutor;
/// use apm2_daemon::episode::handlers::{register_handlers_with_root_and_sandbox, SandboxConfig};
///
/// let workspace = Path::new("/var/lib/apm2/workspaces/episode-123");
/// let config = SandboxConfig::with_shell_allowlist(vec![
///     "cargo *".to_string(),
///     "npm *".to_string(),
///     "git *".to_string(),
/// ]);
/// let mut executor = ToolExecutor::new(tracker, cas.clone());
/// register_handlers_with_root_and_sandbox(&mut executor, cas, workspace, config)?;
/// ```
pub fn register_handlers_with_root_and_sandbox(
    executor: &mut super::executor::ToolExecutor,
    cas: std::sync::Arc<dyn ContentAddressedStore>,
    workspace_root: &Path,
    sandbox_config: SandboxConfig,
) -> Result<(), super::executor::ExecutorError> {
    // Validate workspace root exists and can be canonicalized (fail-closed)
    // This catches misconfiguration early rather than at first tool execution
    if !workspace_root.exists() {
        return Err(super::executor::ExecutorError::ExecutionFailed {
            message: format!(
                "workspace root does not exist: {}",
                workspace_root.display()
            ),
        });
    }

    // Canonicalize early to catch symlink issues at registration time
    let canonical_root = std::fs::canonicalize(workspace_root).map_err(|e| {
        super::executor::ExecutorError::ExecutionFailed {
            message: format!(
                "failed to canonicalize workspace root '{}': {}",
                workspace_root.display(),
                e
            ),
        }
    })?;

    // Register all handlers with the canonical workspace root
    executor.register_handler(Box::new(ReadFileHandler::with_root(&canonical_root)))?;
    executor.register_handler(Box::new(WriteFileHandler::with_root(&canonical_root)))?;
    // Use explicit sandbox config for ExecuteHandler (TCK-00338: fail-closed)
    executor.register_handler(Box::new(ExecuteHandler::with_root_and_sandbox(
        &canonical_root,
        sandbox_config,
    )))?;
    executor.register_handler(Box::new(GitOperationHandler::with_root(&canonical_root)))?;
    executor.register_handler(Box::new(ArtifactFetchHandler::new(cas)))?;
    executor.register_handler(Box::new(ListFilesHandler::with_root(&canonical_root)))?;
    executor.register_handler(Box::new(SearchHandler::with_root(&canonical_root)))?;
    Ok(())
}

#[cfg(test)]
#[allow(deprecated)] // Tests use deprecated new() methods for convenience
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
    // Symlink escape prevention tests (TCK-00319)
    // =========================================================================

    #[test]
    fn test_reject_symlinks_in_path_no_symlink_ok() {
        // Create a real temp directory with no symlinks
        let temp_dir = TempDir::new().expect("temp dir");
        let root = temp_dir.path();

        // Create a nested directory structure
        let nested = root.join("subdir").join("deep");
        std::fs::create_dir_all(&nested).expect("create dirs");

        // Create a file in the nested directory
        let file_path = nested.join("file.txt");
        std::fs::write(&file_path, "content").expect("write file");

        // Should pass - no symlinks in path
        assert!(
            reject_symlinks_in_path(&file_path, root).is_ok(),
            "Path with no symlinks should be allowed"
        );
    }

    #[test]
    #[cfg(unix)]
    fn test_reject_symlinks_in_path_direct_symlink_blocked() {
        // Create a temp directory with a symlink to an external target
        let temp_dir = TempDir::new().expect("temp dir");
        let root = temp_dir.path();

        // Create a symlink pointing outside the workspace
        let symlink_path = root.join("escape");
        std::os::unix::fs::symlink("/etc/passwd", &symlink_path).expect("create symlink");

        // Should reject - direct symlink escape attempt
        let result = reject_symlinks_in_path(&symlink_path, root);
        assert!(
            matches!(result, Err(ToolHandlerError::PathValidation { .. })),
            "Direct symlink escape should be blocked"
        );
        if let Err(ToolHandlerError::PathValidation { reason, .. }) = result {
            assert!(
                reason.contains("symlink"),
                "Error should mention symlink: {reason}"
            );
        }
    }

    #[test]
    #[cfg(unix)]
    fn test_reject_symlinks_in_path_nested_symlink_blocked() {
        // Create a temp directory with a nested symlink
        let temp_dir = TempDir::new().expect("temp dir");
        let root = temp_dir.path();

        // Create a regular subdir
        let subdir = root.join("subdir");
        std::fs::create_dir(&subdir).expect("create subdir");

        // Create a symlink inside the subdir pointing outside
        let symlink_path = subdir.join("evil");
        std::os::unix::fs::symlink("/etc/shadow", &symlink_path).expect("create symlink");

        // Should reject - nested symlink escape attempt
        let result = reject_symlinks_in_path(&symlink_path, root);
        assert!(
            matches!(result, Err(ToolHandlerError::PathValidation { .. })),
            "Nested symlink escape should be blocked"
        );
    }

    #[test]
    #[cfg(unix)]
    fn test_reject_symlinks_in_path_directory_symlink_blocked() {
        // Create a temp directory with a symlinked directory
        let temp_dir = TempDir::new().expect("temp dir");
        let root = temp_dir.path();

        // Create a symlink to /etc (directory symlink)
        let symlink_dir = root.join("etc_link");
        std::os::unix::fs::symlink("/etc", &symlink_dir).expect("create symlink");

        // Try to access a file through the symlinked directory
        let target_path = symlink_dir.join("passwd");

        // Should reject - the directory component is a symlink
        let result = reject_symlinks_in_path(&target_path, root);
        assert!(
            matches!(result, Err(ToolHandlerError::PathValidation { .. })),
            "Directory symlink escape should be blocked"
        );
    }

    #[test]
    #[cfg(unix)]
    fn test_reject_symlinks_in_path_relative_symlink_escape_blocked() {
        // Create a temp directory structure with a relative symlink that escapes
        let temp_dir = TempDir::new().expect("temp dir");
        let root = temp_dir.path();

        // Create a subdir
        let subdir = root.join("subdir");
        std::fs::create_dir(&subdir).expect("create subdir");

        // Create a relative symlink that escapes via ../../../etc
        let symlink_path = subdir.join("escape");
        std::os::unix::fs::symlink("../../../etc/passwd", &symlink_path).expect("create symlink");

        // Should reject - relative symlink escape attempt
        let result = reject_symlinks_in_path(&symlink_path, root);
        assert!(
            matches!(result, Err(ToolHandlerError::PathValidation { .. })),
            "Relative symlink escape should be blocked"
        );
    }

    #[test]
    #[cfg(unix)]
    fn test_reject_symlinks_in_path_chain_escape_blocked() {
        // Create a temp directory with a chain of symlinks
        let temp_dir = TempDir::new().expect("temp dir");
        let root = temp_dir.path();

        // Create first symlink pointing to a directory in root
        let link1 = root.join("link1");
        let target_dir = root.join("target");
        std::fs::create_dir(&target_dir).expect("create target dir");
        std::os::unix::fs::symlink(&target_dir, &link1).expect("create symlink 1");

        // Should reject at the first symlink, even though it points inside workspace
        let result = reject_symlinks_in_path(&link1, root);
        assert!(
            matches!(result, Err(ToolHandlerError::PathValidation { .. })),
            "Any symlink in path should be blocked (defense in depth)"
        );
    }

    #[test]
    fn test_reject_symlinks_nonexistent_path_ok() {
        // Test that nonexistent paths are allowed (for write operations)
        let temp_dir = TempDir::new().expect("temp dir");
        let root = temp_dir.path();

        // Path that doesn't exist
        let new_file = root.join("subdir").join("newfile.txt");

        // Should pass - nonexistent paths are OK (checked at write time)
        assert!(
            reject_symlinks_in_path(&new_file, root).is_ok(),
            "Nonexistent paths should be allowed"
        );
    }

    #[test]
    fn test_validate_path_with_toctou_mitigation_ok() {
        // Test the full TOCTOU-mitigating validation
        let temp_dir = TempDir::new().expect("temp dir");
        let canonical_root = std::fs::canonicalize(temp_dir.path()).expect("canonicalize");

        // Create a file
        let file = temp_dir.path().join("test.txt");
        std::fs::write(&file, "content").expect("write");

        // Should pass
        let result = validate_path_with_toctou_mitigation(Path::new("test.txt"), &canonical_root);
        assert!(result.is_ok(), "Valid path should pass TOCTOU validation");
    }

    #[test]
    #[cfg(unix)]
    fn test_validate_path_with_toctou_mitigation_symlink_blocked() {
        // Test that TOCTOU validation blocks symlinks
        let temp_dir = TempDir::new().expect("temp dir");
        let canonical_root = std::fs::canonicalize(temp_dir.path()).expect("canonicalize");

        // Create a symlink to /etc/passwd
        let symlink = temp_dir.path().join("escape");
        std::os::unix::fs::symlink("/etc/passwd", &symlink).expect("create symlink");

        // Should fail - symlink detected
        let result = validate_path_with_toctou_mitigation(Path::new("escape"), &canonical_root);
        assert!(
            result.is_err(),
            "TOCTOU validation should block symlink escape"
        );
    }

    #[test]
    fn test_validate_path_with_toctou_mitigation_traversal_blocked() {
        // Test that TOCTOU validation blocks path traversal
        let temp_dir = TempDir::new().expect("temp dir");
        let canonical_root = std::fs::canonicalize(temp_dir.path()).expect("canonicalize");

        // Should fail - path traversal
        let result =
            validate_path_with_toctou_mitigation(Path::new("../../../etc/passwd"), &canonical_root);
        assert!(
            result.is_err(),
            "TOCTOU validation should block path traversal"
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

        let result = handler.execute(&args, None).await;
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

        let result = handler.execute(&args, None).await;
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

        let result = handler.execute(&args, None).await;
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

        let result = handler.execute(&args, None).await;
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

        let result = handler.execute(&args, None).await.expect("execute search");
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

        let result = handler.execute(&args, None).await;
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

    // =========================================================================
    // ListFilesHandler symlink escape tests (TCK-00319)
    // =========================================================================

    #[tokio::test]
    #[cfg(unix)]
    async fn test_listfiles_rejects_symlink_escape() {
        let temp_dir = TempDir::new().expect("create temp dir");
        let root = temp_dir.path();

        // Create a symlink pointing to /etc
        let symlink_path = root.join("escape");
        std::os::unix::fs::symlink("/etc", &symlink_path).expect("create symlink");

        let handler = ListFilesHandler::with_root(root);
        let args = ToolArgs::ListFiles(ListFilesArgs {
            path: PathBuf::from("escape"),
            pattern: None,
            max_entries: None,
        });

        // Should fail - symlink escape attempt
        let result = handler.execute(&args, None).await;
        assert!(
            result.is_err(),
            "ListFilesHandler should reject symlink escape"
        );
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn test_listfiles_rejects_nested_symlink_in_path() {
        let temp_dir = TempDir::new().expect("create temp dir");
        let root = temp_dir.path();

        // Create a regular subdir
        let subdir = root.join("subdir");
        std::fs::create_dir(&subdir).expect("create subdir");

        // Create a symlink inside the subdir pointing outside
        let symlink_path = subdir.join("evil");
        std::os::unix::fs::symlink("/etc", &symlink_path).expect("create symlink");

        let handler = ListFilesHandler::with_root(root);
        let args = ToolArgs::ListFiles(ListFilesArgs {
            path: PathBuf::from("subdir/evil"),
            pattern: None,
            max_entries: None,
        });

        // Should fail - nested symlink escape
        let result = handler.execute(&args, None).await;
        assert!(
            result.is_err(),
            "ListFilesHandler should reject nested symlink escape"
        );
    }

    // =========================================================================
    // SearchHandler symlink escape tests (TCK-00319)
    // =========================================================================

    #[tokio::test]
    #[cfg(unix)]
    async fn test_search_rejects_symlink_scope() {
        let temp_dir = TempDir::new().expect("create temp dir");
        let root = temp_dir.path();

        // Create a symlink pointing to /etc
        let symlink_path = root.join("escape");
        std::os::unix::fs::symlink("/etc", &symlink_path).expect("create symlink");

        let handler = SearchHandler::with_root(root);
        let args = ToolArgs::Search(SearchArgs {
            query: "root".to_string(),
            scope: PathBuf::from("escape"),
            max_bytes: None,
            max_lines: None,
        });

        // Should fail - symlink escape attempt
        let result = handler.execute(&args, None).await;
        assert!(result.is_err(), "SearchHandler should reject symlink scope");
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn test_search_skips_symlink_files_during_traversal() {
        let temp_dir = TempDir::new().expect("create temp dir");
        let root = temp_dir.path();

        // Create a regular file
        let file = root.join("safe.txt");
        std::fs::write(&file, "search me").expect("write file");

        // Create a symlink to /etc/passwd
        let symlink = root.join("danger.txt");
        std::os::unix::fs::symlink("/etc/passwd", &symlink).expect("create symlink");

        let handler = SearchHandler::with_root(root);
        let args = ToolArgs::Search(SearchArgs {
            query: "search".to_string(),
            scope: PathBuf::from("."),
            max_bytes: None,
            max_lines: None,
        });

        // Should succeed but only search safe.txt (symlinks are skipped in traversal)
        let result = handler.execute(&args, None).await.expect("execute search");
        let output = result.output_str().expect("utf8 output");

        // Should find the match in safe.txt
        assert!(
            output.contains("safe.txt"),
            "Should find content in regular file: {output}"
        );
        // Should NOT show results from /etc/passwd
        assert!(
            !output.contains("root:"),
            "Should not leak content from symlinked file: {output}"
        );
    }

    // =========================================================================
    // GitOperationHandler symlink tests (TCK-00319)
    // =========================================================================

    #[tokio::test]
    #[cfg(unix)]
    async fn test_git_handler_rejects_symlink_repo_path() {
        let temp_dir = TempDir::new().expect("create temp dir");
        let root = temp_dir.path();

        // Create a real git repo
        let real_repo = root.join("real_repo");
        std::fs::create_dir(&real_repo).expect("create dir");
        init_git_repo(&real_repo);

        // Create a symlink to /etc
        let symlink = root.join("evil_link");
        std::os::unix::fs::symlink("/etc", &symlink).expect("create symlink");

        let handler = GitOperationHandler::with_root(root);
        let args = ToolArgs::Git(GitArgs {
            operation: "status".to_string(),
            args: vec![],
            repo_path: Some(PathBuf::from("evil_link")),
        });

        // Should fail - symlink escape via repo_path
        let result = handler.execute(&args, None).await;
        assert!(
            result.is_err(),
            "GitOperationHandler should reject symlink repo_path"
        );
    }

    // =========================================================================
    // register_handlers_with_root tests (TCK-00319)
    // =========================================================================

    #[test]
    fn test_register_handlers_with_root_validates_existence() {
        use crate::episode::broker::StubContentAddressedStore;
        use crate::episode::budget::EpisodeBudget;
        use crate::episode::budget_tracker::BudgetTracker;
        use crate::episode::executor::ToolExecutor;

        let temp_dir = TempDir::new().expect("create temp dir");
        let cas = Arc::new(StubContentAddressedStore::new());
        let budget = EpisodeBudget::builder().tool_calls(100).build();
        let tracker = Arc::new(BudgetTracker::from_envelope(budget));
        let mut executor = ToolExecutor::new(tracker, cas.clone());

        // Try to register with nonexistent workspace
        let nonexistent = temp_dir.path().join("does_not_exist");
        let result = register_handlers_with_root(&mut executor, cas, &nonexistent);

        assert!(result.is_err(), "Should reject nonexistent workspace root");
    }

    #[test]
    fn test_register_handlers_with_root_works_with_valid_path() {
        use crate::episode::broker::StubContentAddressedStore;
        use crate::episode::budget::EpisodeBudget;
        use crate::episode::budget_tracker::BudgetTracker;
        use crate::episode::executor::ToolExecutor;

        let temp_dir = TempDir::new().expect("create temp dir");
        let workspace = temp_dir.path().join("workspace");
        std::fs::create_dir(&workspace).expect("create workspace");

        let cas = Arc::new(StubContentAddressedStore::new());
        let budget = EpisodeBudget::builder().tool_calls(100).build();
        let tracker = Arc::new(BudgetTracker::from_envelope(budget));
        let mut executor = ToolExecutor::new(tracker, cas.clone());

        // Register with valid workspace
        let result = register_handlers_with_root(&mut executor, cas, &workspace);

        assert!(
            result.is_ok(),
            "Should accept valid workspace root: {:?}",
            result.err()
        );
    }

    // =========================================================================
    // register_handlers_with_root_and_sandbox tests (TCK-00338)
    // =========================================================================

    #[test]
    fn test_register_handlers_with_root_and_sandbox_validates_existence() {
        use crate::episode::broker::StubContentAddressedStore;
        use crate::episode::budget::EpisodeBudget;
        use crate::episode::budget_tracker::BudgetTracker;
        use crate::episode::executor::ToolExecutor;

        let temp_dir = TempDir::new().expect("create temp dir");
        let cas = Arc::new(StubContentAddressedStore::new());
        let budget = EpisodeBudget::builder().tool_calls(100).build();
        let tracker = Arc::new(BudgetTracker::from_envelope(budget));
        let mut executor = ToolExecutor::new(tracker, cas.clone());

        // Try to register with nonexistent workspace
        let nonexistent = temp_dir.path().join("does_not_exist");
        let config = SandboxConfig::default();
        let result =
            register_handlers_with_root_and_sandbox(&mut executor, cas, &nonexistent, config);

        assert!(result.is_err(), "Should reject nonexistent workspace root");
    }

    #[test]
    fn test_register_handlers_with_root_and_sandbox_works_with_valid_path() {
        use crate::episode::broker::StubContentAddressedStore;
        use crate::episode::budget::EpisodeBudget;
        use crate::episode::budget_tracker::BudgetTracker;
        use crate::episode::executor::ToolExecutor;

        let temp_dir = TempDir::new().expect("create temp dir");
        let workspace = temp_dir.path().join("workspace");
        std::fs::create_dir(&workspace).expect("create workspace");

        let cas = Arc::new(StubContentAddressedStore::new());
        let budget = EpisodeBudget::builder().tool_calls(100).build();
        let tracker = Arc::new(BudgetTracker::from_envelope(budget));
        let mut executor = ToolExecutor::new(tracker, cas.clone());

        // Register with valid workspace and explicit sandbox config
        let config = SandboxConfig::with_shell_allowlist(vec!["echo *".to_string()]);
        let result =
            register_handlers_with_root_and_sandbox(&mut executor, cas, &workspace, config);

        assert!(
            result.is_ok(),
            "Should accept valid workspace root with sandbox config: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_register_handlers_with_root_and_sandbox_uses_provided_config() {
        use crate::episode::broker::StubContentAddressedStore;
        use crate::episode::budget::EpisodeBudget;
        use crate::episode::budget_tracker::BudgetTracker;
        use crate::episode::executor::ToolExecutor;

        let temp_dir = TempDir::new().expect("create temp dir");
        let workspace = temp_dir.path().join("workspace");
        std::fs::create_dir(&workspace).expect("create workspace");

        let cas = Arc::new(StubContentAddressedStore::new());
        let budget = EpisodeBudget::builder().tool_calls(100).build();
        let tracker = Arc::new(BudgetTracker::from_envelope(budget));
        let mut executor = ToolExecutor::new(tracker, cas.clone());

        // Register with fail-closed config (empty allowlist)
        let config = SandboxConfig::default(); // Fail-closed by default
        let result =
            register_handlers_with_root_and_sandbox(&mut executor, cas, &workspace, config);

        assert!(
            result.is_ok(),
            "Should accept valid workspace root: {:?}",
            result.err()
        );

        // The executor now has handlers registered with the provided config.
        // The ExecuteHandler should have the fail-closed config (tested
        // indirectly through the allowlist tests).
    }

    // =========================================================================
    // Stall detection tests (TCK-00338)
    // =========================================================================

    #[tokio::test]
    async fn test_sandbox_config_stall_timeout_default() {
        // Default config should have 60 second stall timeout
        let config = SandboxConfig::default();
        assert_eq!(config.stall_timeout_ms, 60_000);
    }

    #[tokio::test]
    async fn test_sandbox_config_stall_timeout_disabled() {
        // Should be able to disable stall detection
        let config = SandboxConfig::default().with_stall_timeout_ms(0);
        assert_eq!(config.stall_timeout_ms, 0);
    }

    #[tokio::test]
    async fn test_sandbox_config_stall_timeout_custom() {
        // Should be able to set custom stall timeout
        let config = SandboxConfig::default().with_stall_timeout_ms(5_000);
        assert_eq!(config.stall_timeout_ms, 5_000);
    }

    // =========================================================================
    // TOCTOU mitigation integration tests (TCK-00319)
    // =========================================================================

    #[tokio::test]
    #[cfg(unix)]
    async fn test_read_handler_toctou_rejects_symlink_in_path() {
        // Tests that ReadFileHandler uses TOCTOU mitigation to reject symlinks
        let temp_dir = TempDir::new().expect("create temp dir");
        let root = temp_dir.path();

        // Create a subdir with a symlink to /etc/passwd
        let subdir = root.join("subdir");
        std::fs::create_dir(&subdir).expect("create subdir");
        let symlink = subdir.join("passwd");
        std::os::unix::fs::symlink("/etc/passwd", &symlink).expect("create symlink");

        let handler = ReadFileHandler::with_root(root);
        let args = ToolArgs::Read(ReadArgs {
            path: PathBuf::from("subdir/passwd"),
            offset: None,
            limit: None,
        });

        // Should fail - TOCTOU mitigation should detect symlink
        let result = handler.execute(&args, None).await;
        assert!(
            result.is_err(),
            "ReadFileHandler should reject symlink via TOCTOU mitigation"
        );
        if let Err(ToolHandlerError::PathValidation { reason, .. }) = result {
            assert!(
                reason.contains("symlink"),
                "Error should mention symlink: {reason}"
            );
        }
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn test_write_handler_toctou_rejects_symlink_in_path() {
        // Tests that WriteFileHandler uses TOCTOU mitigation to reject symlinks
        let temp_dir = TempDir::new().expect("create temp dir");
        let root = temp_dir.path();

        // Create a symlink to an external location
        let symlink = root.join("escape");
        let external_target = temp_dir.path().join("external_file.txt");
        std::fs::write(&external_target, "original").expect("write external");

        // Create symlink pointing to the external file
        std::os::unix::fs::symlink(&external_target, &symlink).expect("create symlink");

        let handler = WriteFileHandler::with_root(root);
        let args = ToolArgs::Write(WriteArgs {
            path: PathBuf::from("escape"),
            content: Some(b"malicious".to_vec()),
            content_hash: None,
            create_parents: false,
            append: false,
        });

        // Should fail - TOCTOU mitigation should detect symlink
        let result = handler.execute(&args, None).await;
        assert!(
            result.is_err(),
            "WriteFileHandler should reject symlink via TOCTOU mitigation"
        );
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn test_execute_handler_toctou_rejects_symlink_cwd() {
        // Tests that ExecuteHandler uses TOCTOU mitigation for cwd
        let temp_dir = TempDir::new().expect("create temp dir");
        let root = temp_dir.path();

        // Create a symlink to /etc
        let symlink = root.join("evil_cwd");
        std::os::unix::fs::symlink("/etc", &symlink).expect("create symlink");

        // Use permissive mode for this test since we're testing TOCTOU, not allowlist
        let handler = ExecuteHandler::with_root_permissive(root);
        let args = ToolArgs::Execute(ExecuteArgs {
            command: "ls".to_string(),
            args: vec![],
            cwd: Some(PathBuf::from("evil_cwd")),
            stdin: None,
            timeout_ms: Some(5000),
        });

        // Should fail - TOCTOU mitigation should detect symlink in cwd
        let result = handler.execute(&args, None).await;
        assert!(
            result.is_err(),
            "ExecuteHandler should reject symlink cwd via TOCTOU mitigation"
        );
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn test_listfiles_handler_toctou_rejects_symlink_directory() {
        // Tests that ListFilesHandler uses TOCTOU mitigation
        let temp_dir = TempDir::new().expect("create temp dir");
        let root = temp_dir.path();

        // Create a symlink to /etc
        let symlink = root.join("etc_link");
        std::os::unix::fs::symlink("/etc", &symlink).expect("create symlink");

        let handler = ListFilesHandler::with_root(root);
        let args = ToolArgs::ListFiles(ListFilesArgs {
            path: PathBuf::from("etc_link"),
            pattern: None,
            max_entries: None,
        });

        // Should fail - TOCTOU mitigation should detect symlink
        let result = handler.execute(&args, None).await;
        assert!(
            result.is_err(),
            "ListFilesHandler should reject symlink via TOCTOU mitigation"
        );
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn test_search_handler_toctou_rejects_symlink_scope() {
        // Tests that SearchHandler uses TOCTOU mitigation
        let temp_dir = TempDir::new().expect("create temp dir");
        let root = temp_dir.path();

        // Create a symlink to /etc
        let symlink = root.join("etc_link");
        std::os::unix::fs::symlink("/etc", &symlink).expect("create symlink");

        let handler = SearchHandler::with_root(root);
        let args = ToolArgs::Search(SearchArgs {
            query: "root".to_string(),
            scope: PathBuf::from("etc_link"),
            max_bytes: None,
            max_lines: None,
        });

        // Should fail - TOCTOU mitigation should detect symlink
        let result = handler.execute(&args, None).await;
        assert!(
            result.is_err(),
            "SearchHandler should reject symlink scope via TOCTOU mitigation"
        );
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn test_git_handler_toctou_rejects_symlink_repo() {
        // Tests that GitOperationHandler uses TOCTOU mitigation for repo_path
        let temp_dir = TempDir::new().expect("create temp dir");
        let root = temp_dir.path();

        // Create a real git repo first (so we have valid .git)
        let real_repo = root.join("real_repo");
        std::fs::create_dir(&real_repo).expect("create dir");
        init_git_repo(&real_repo);

        // Create a symlink to /etc
        let symlink = root.join("evil_repo");
        std::os::unix::fs::symlink("/etc", &symlink).expect("create symlink");

        let handler = GitOperationHandler::with_root(root);
        let args = ToolArgs::Git(GitArgs {
            operation: "status".to_string(),
            args: vec![],
            repo_path: Some(PathBuf::from("evil_repo")),
        });

        // Should fail - TOCTOU mitigation should detect symlink in repo_path
        let result = handler.execute(&args, None).await;
        assert!(
            result.is_err(),
            "GitOperationHandler should reject symlink repo_path via TOCTOU mitigation"
        );
    }

    #[test]
    fn test_write_handler_create_parents_rejects_traversal() {
        // Tests that WriteFileHandler validates paths BEFORE creating parent
        // directories This prevents arbitrary directory creation outside the
        // workspace via path traversal
        let handler = WriteFileHandler::with_root("/tmp/test_workspace");
        let args = ToolArgs::Write(WriteArgs {
            path: PathBuf::from("../../../etc/evil"),
            content: Some(b"malicious".to_vec()),
            content_hash: None,
            create_parents: true,
            append: false,
        });

        // Should fail validation due to path traversal - BEFORE any filesystem
        // operations
        let result = handler.validate(&args);
        assert!(
            result.is_err(),
            "WriteFileHandler should reject path traversal via create_parents"
        );
        if let Err(ToolHandlerError::PathValidation { reason, .. }) = result {
            assert!(
                reason.contains("traversal"),
                "Error should mention traversal: {reason}"
            );
        }
    }

    #[test]
    fn test_write_handler_create_parents_rejects_absolute_path() {
        // Tests that WriteFileHandler rejects absolute paths for create_parents
        let handler = WriteFileHandler::with_root("/tmp/test_workspace");
        let args = ToolArgs::Write(WriteArgs {
            path: PathBuf::from("/etc/evil"),
            content: Some(b"malicious".to_vec()),
            content_hash: None,
            create_parents: true,
            append: false,
        });

        // Should fail validation due to absolute path - BEFORE any filesystem
        // operations
        let result = handler.validate(&args);
        assert!(
            result.is_err(),
            "WriteFileHandler should reject absolute path via create_parents"
        );
        if let Err(ToolHandlerError::PathValidation { reason, .. }) = result {
            assert!(
                reason.contains("absolute"),
                "Error should mention absolute: {reason}"
            );
        }
    }

    // =========================================================================
    // TCK-00338: SandboxConfig Tests (SEC-CTRL-FAC-0016)
    // =========================================================================

    #[test]
    fn test_sandbox_config_default_is_fail_closed() {
        // Default config should have empty allowlist (fail-closed)
        let config = SandboxConfig::default();
        assert!(config.shell_allowlist.is_empty());
        assert!(!config.is_command_allowed("echo hello"));
        assert!(!config.is_command_allowed("ls"));
    }

    #[test]
    fn test_sandbox_config_permissive_allows_all() {
        let config = SandboxConfig::permissive();
        assert!(config.is_command_allowed("echo hello"));
        assert!(config.is_command_allowed("rm -rf /"));
        assert!(config.is_command_allowed("any command at all"));
    }

    #[test]
    fn test_sandbox_config_shell_allowlist_exact_match() {
        let config = SandboxConfig::with_shell_allowlist(vec!["ls".to_string()]);
        assert!(config.is_command_allowed("ls"));
        assert!(!config.is_command_allowed("ls -la"));
        assert!(!config.is_command_allowed("echo"));
    }

    #[test]
    fn test_sandbox_config_shell_allowlist_wildcard() {
        let config = SandboxConfig::with_shell_allowlist(vec![
            "cargo *".to_string(),
            "npm *".to_string(),
            "git status".to_string(),
        ]);
        assert!(config.is_command_allowed("cargo build"));
        assert!(config.is_command_allowed("cargo test --release"));
        assert!(config.is_command_allowed("npm install"));
        assert!(config.is_command_allowed("git status"));
        assert!(!config.is_command_allowed("git push")); // Not in allowlist
        assert!(!config.is_command_allowed("rm -rf /"));
    }

    // =========================================================================
    // TCK-00338: Shell Argument Escaping Tests (SEC-CTRL-FAC-0016)
    // =========================================================================

    #[test]
    fn test_escape_shell_arg_simple() {
        // Simple alphanumeric args should not be escaped
        assert_eq!(escape_shell_arg("hello"), "hello");
        assert_eq!(escape_shell_arg("build"), "build");
        assert_eq!(escape_shell_arg("123"), "123");
        assert_eq!(escape_shell_arg("-la"), "-la");
        assert_eq!(escape_shell_arg("--release"), "--release");
    }

    #[test]
    fn test_escape_shell_arg_empty() {
        // Empty string should be quoted
        assert_eq!(escape_shell_arg(""), "''");
    }

    #[test]
    fn test_escape_shell_arg_spaces() {
        // Arguments with spaces should be quoted
        assert_eq!(escape_shell_arg("hello world"), "'hello world'");
        assert_eq!(escape_shell_arg("rm -rf /"), "'rm -rf /'");
    }

    #[test]
    fn test_escape_shell_arg_single_quotes() {
        // Single quotes within the argument should be escaped
        assert_eq!(escape_shell_arg("it's"), "'it'\\''s'");
        assert_eq!(escape_shell_arg("don't do that"), "'don'\\''t do that'");
    }

    #[test]
    fn test_escape_shell_arg_shell_metacharacters() {
        // Shell metacharacters should trigger quoting
        assert_eq!(escape_shell_arg("$HOME"), "'$HOME'");
        assert_eq!(escape_shell_arg("`whoami`"), "'`whoami`'");
        assert_eq!(escape_shell_arg("a|b"), "'a|b'");
        assert_eq!(escape_shell_arg("a;b"), "'a;b'");
        assert_eq!(escape_shell_arg("a&b"), "'a&b'");
        assert_eq!(escape_shell_arg("a>b"), "'a>b'");
        assert_eq!(escape_shell_arg("a<b"), "'a<b'");
        assert_eq!(escape_shell_arg("*.txt"), "'*.txt'");
        assert_eq!(escape_shell_arg("a?b"), "'a?b'");
        assert_eq!(escape_shell_arg("[abc]"), "'[abc]'");
    }

    #[test]
    fn test_build_escaped_command_line_no_args() {
        // Command only - should escape if needed
        assert_eq!(build_escaped_command_line("ls", &[]), "ls");
        assert_eq!(
            build_escaped_command_line("my command", &[]),
            "'my command'"
        );
    }

    #[test]
    fn test_build_escaped_command_line_simple_args() {
        // Simple args - no escaping needed
        let args = vec!["build".to_string()];
        assert_eq!(build_escaped_command_line("cargo", &args), "cargo build");

        let args = vec!["test".to_string(), "--release".to_string()];
        assert_eq!(
            build_escaped_command_line("cargo", &args),
            "cargo test --release"
        );
    }

    #[test]
    fn test_build_escaped_command_line_args_with_spaces() {
        // Arguments containing spaces must be quoted
        // Note: -c has no special chars, so it's not quoted
        let args = vec!["-c".to_string(), "rm -rf /".to_string()];
        assert_eq!(build_escaped_command_line("sh", &args), "sh -c 'rm -rf /'");
    }

    #[test]
    fn test_build_escaped_command_line_injection_prevention() {
        // This is the critical security test:
        // An attacker might try to use `sh -c "malicious; command"` as a single
        // argument Without proper escaping, this could be interpreted
        // differently
        let args = vec!["-c".to_string(), "echo hello; rm -rf /".to_string()];
        let escaped = build_escaped_command_line("sh", &args);
        // The semicolon should be inside quotes, preventing command injection
        // Note: -c has no special chars, so it's not quoted, but the dangerous arg is
        assert_eq!(escaped, "sh -c 'echo hello; rm -rf /'");
        // The key security property: "echo hello; rm -rf /" is a single quoted
        // arg, not multiple shell commands. This prevents the allowlist
        // from being bypassed via shell metacharacter injection.
    }

    #[test]
    fn test_build_escaped_command_line_allows_correct_matching() {
        // Verify that allowlist patterns work correctly with escaped commands
        let config = SandboxConfig::with_shell_allowlist(vec![
            "echo *".to_string(),
            "sh -c *".to_string(), // Matches "sh -c 'anything'"
        ]);

        // Simple echo should still work
        let echo_cmd = build_escaped_command_line("echo", &["hello".to_string()]);
        assert!(config.is_command_allowed(&echo_cmd));

        // sh -c with quoted argument should work - the allowlist sees "sh -c 'echo
        // hello'"
        let sh_cmd =
            build_escaped_command_line("sh", &["-c".to_string(), "echo hello".to_string()]);
        assert!(config.is_command_allowed(&sh_cmd));
    }

    #[test]
    fn test_sandbox_config_env_passthrough_defaults() {
        let config = SandboxConfig::default();
        // Default safe vars should pass
        assert!(config.should_pass_env("PATH"));
        assert!(config.should_pass_env("HOME"));
        assert!(config.should_pass_env("USER"));
        assert!(config.should_pass_env("TERM"));
        assert!(config.should_pass_env("LANG"));
        assert!(config.should_pass_env("TZ"));
        // Unknown vars should not pass
        assert!(!config.should_pass_env("MY_CUSTOM_VAR"));
        assert!(!config.should_pass_env("FOO"));
    }

    #[test]
    fn test_sandbox_config_env_blocklist_patterns() {
        let config = SandboxConfig::default();
        // Sensitive patterns should always be blocked
        assert!(!config.should_pass_env("API_KEY"));
        assert!(!config.should_pass_env("MY_API_KEY"));
        assert!(!config.should_pass_env("GITHUB_TOKEN"));
        assert!(!config.should_pass_env("AWS_SECRET_ACCESS_KEY"));
        assert!(!config.should_pass_env("NPM_TOKEN"));
        assert!(!config.should_pass_env("DOCKER_PASSWORD"));
        assert!(!config.should_pass_env("MY_SECRET_VALUE"));
        assert!(!config.should_pass_env("AUTH_TOKEN"));
        assert!(!config.should_pass_env("PRIVATE_KEY_PATH"));
    }

    #[test]
    fn test_sandbox_config_custom_env_passthrough() {
        let config = SandboxConfig::default()
            .with_env_passthrough(vec!["MY_SAFE_VAR".to_string(), "ANOTHER_VAR".to_string()]);
        // Custom vars should now pass
        assert!(config.should_pass_env("MY_SAFE_VAR"));
        assert!(config.should_pass_env("ANOTHER_VAR"));
        // But sensitive patterns should still be blocked
        assert!(!config.should_pass_env("MY_API_KEY"));
    }

    #[test]
    fn test_sandbox_config_blocklist_overrides_passthrough() {
        // Even if you add a sensitive var to passthrough, blocklist wins
        let config = SandboxConfig::default()
            .with_env_passthrough(vec!["API_KEY".to_string(), "MY_SECRET".to_string()]);
        // These should still be blocked due to pattern matching
        assert!(!config.should_pass_env("API_KEY"));
        assert!(!config.should_pass_env("MY_SECRET"));
    }

    #[tokio::test]
    async fn test_execute_handler_command_allowlist_blocks_disallowed() {
        // Create handler with restrictive allowlist
        let tmp = tempfile::tempdir().unwrap();
        let config = SandboxConfig::with_shell_allowlist(vec!["echo *".to_string()]);
        let handler = ExecuteHandler::with_root_and_sandbox(tmp.path(), config);

        // Try to run a command not in the allowlist
        let args = ToolArgs::Execute(ExecuteArgs {
            command: "ls".to_string(),
            args: vec![],
            cwd: None,
            stdin: None,
            timeout_ms: Some(1000),
        });

        let result = handler.execute(&args, None).await;
        assert!(result.is_err());
        if let Err(ToolHandlerError::InvalidArgs { reason }) = result {
            assert!(
                reason.contains("not in shell allowlist"),
                "Error should mention allowlist: {reason}"
            );
        } else {
            panic!("Expected InvalidArgs error");
        }
    }

    #[tokio::test]
    async fn test_execute_handler_command_allowlist_allows_matching() {
        // Create handler with allowlist that permits echo
        let tmp = tempfile::tempdir().unwrap();
        let config = SandboxConfig::with_shell_allowlist(vec!["echo *".to_string()]);
        let handler = ExecuteHandler::with_root_and_sandbox(tmp.path(), config);

        // Run allowed command
        let args = ToolArgs::Execute(ExecuteArgs {
            command: "echo".to_string(),
            args: vec!["hello".to_string()],
            cwd: None,
            stdin: None,
            timeout_ms: Some(1000),
        });

        let result = handler.execute(&args, None).await;
        assert!(result.is_ok(), "Allowed command should succeed: {result:?}");
        let data = result.unwrap();
        let output = String::from_utf8_lossy(&data.output);
        assert!(output.contains("hello"), "Output should contain 'hello'");
    }

    #[tokio::test]
    #[allow(unsafe_code)] // Required for env var manipulation in tests
    async fn test_execute_handler_env_scrubbing() {
        // Set a secret env var that should be scrubbed
        // SAFETY: This is a test running in isolation
        unsafe {
            std::env::set_var("TEST_API_KEY_SECRET", "supersecret123");
            std::env::set_var("TEST_SAFE_VAR", "safevalue");
        }

        let tmp = tempfile::tempdir().unwrap();
        let config =
            SandboxConfig::permissive().with_env_passthrough(vec!["TEST_SAFE_VAR".to_string()]);
        let handler = ExecuteHandler::with_root_and_sandbox(tmp.path(), config);

        // Run printenv to see what environment the child process sees
        let args = ToolArgs::Execute(ExecuteArgs {
            command: "env".to_string(),
            args: vec![],
            cwd: None,
            stdin: None,
            timeout_ms: Some(5000),
        });

        let result = handler.execute(&args, None).await;
        assert!(result.is_ok(), "env command should succeed");
        let data = result.unwrap();
        let output = String::from_utf8_lossy(&data.output);

        // Secret should NOT appear (blocked by pattern)
        assert!(
            !output.contains("supersecret123"),
            "Secret value should be scrubbed from env"
        );
        assert!(
            !output.contains("TEST_API_KEY_SECRET"),
            "Secret key should be scrubbed from env"
        );

        // Safe var should appear (in custom passthrough)
        assert!(
            output.contains("TEST_SAFE_VAR") || output.contains("safevalue"),
            "Safe var should be passed through"
        );

        // Clean up
        // SAFETY: This is a test running in isolation
        unsafe {
            std::env::remove_var("TEST_API_KEY_SECRET");
            std::env::remove_var("TEST_SAFE_VAR");
        }
    }

    #[tokio::test]
    async fn test_execute_handler_default_env_passthrough() {
        let tmp = tempfile::tempdir().unwrap();
        let config = SandboxConfig::permissive();
        let handler = ExecuteHandler::with_root_and_sandbox(tmp.path(), config);

        // Run printenv to check PATH is passed through
        let args = ToolArgs::Execute(ExecuteArgs {
            command: "env".to_string(),
            args: vec![],
            cwd: None,
            stdin: None,
            timeout_ms: Some(5000),
        });

        let result = handler.execute(&args, None).await;
        assert!(result.is_ok());
        let data = result.unwrap();
        let output = String::from_utf8_lossy(&data.output);

        // Default safe vars should be present
        assert!(output.contains("PATH="), "PATH should be passed through");
    }
}
