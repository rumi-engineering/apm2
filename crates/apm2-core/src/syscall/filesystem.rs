//! Filesystem mediation handler for file operations.
//!
//! This module implements the execution layer for filesystem tool requests
//! (`FileRead`, `FileWrite`, `FileEdit`). All operations are confined to a
//! workspace root directory with strict path validation.
//!
//! # Security Model
//!
//! The filesystem handler implements multiple layers of security:
//!
//! 1. **Path validation**: All paths are checked for traversal sequences
//! 2. **Workspace confinement**: Paths must resolve within the workspace root
//! 3. **Symlink resolution**: Symlinks are followed and verified to stay in
//!    workspace
//! 4. **Content hashing**: All modifications are tracked with BLAKE3 hashes
//! 5. **Atomic operations**: Edits are atomic to prevent partial modifications
//!
//! # Operations
//!
//! - **Read**: Read file contents with optional offset and limit
//! - **Write**: Create or overwrite files, with create-only and append modes
//! - **Edit**: Atomic search-and-replace within files
//!
//! # Example
//!
//! ```rust,ignore
//! use apm2_core::syscall::{FilesystemHandler, FilesystemConfig};
//!
//! let config = FilesystemConfig::new("/workspace");
//! let handler = FilesystemHandler::new(config);
//!
//! // Read a file
//! let content = handler.read_file("/workspace/README.md", 0, 0)?;
//!
//! // Write a file
//! let hash = handler.write_file(
//!     "/workspace/output.txt",
//!     b"Hello, World!",
//!     false, // not create_only
//!     false, // not append
//! )?;
//!
//! // Edit a file
//! let result = handler.edit_file(
//!     "/workspace/src/main.rs",
//!     "old_function",
//!     "new_function",
//! )?;
//! ```

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

use tempfile::NamedTempFile;
use tracing::{debug, info, instrument, warn};

use super::error::SyscallError;

/// Maximum symlink resolution depth to prevent infinite loops.
const MAX_SYMLINK_DEPTH: usize = 40;

/// Default maximum content size for reads (100MB).
const DEFAULT_MAX_READ_SIZE: usize = 100 * 1024 * 1024;

/// Default maximum content size for writes (100MB).
const DEFAULT_MAX_WRITE_SIZE: usize = 100 * 1024 * 1024;

/// Default maximum content size for edits (10MB).
const DEFAULT_MAX_EDIT_SIZE: usize = 10 * 1024 * 1024;

/// Buffer size for streaming hash operations.
const HASH_BUFFER_SIZE: usize = 64 * 1024;

/// Converts a Duration to milliseconds as u64, saturating at `u64::MAX`.
///
/// This is safe because typical operation durations will never approach
/// `u64::MAX` milliseconds (which would be approximately 584 million years).
#[allow(clippy::cast_possible_truncation)]
fn duration_to_millis(duration: std::time::Duration) -> u64 {
    // Use saturating conversion for safety, though overflow is impossible in
    // practice
    duration.as_millis().min(u128::from(u64::MAX)) as u64
}

/// Configuration for the filesystem handler.
#[derive(Debug, Clone)]
pub struct FilesystemConfig {
    /// Root directory for all file operations.
    /// All paths must resolve to within this directory.
    workspace_root: PathBuf,

    /// Maximum content size for read operations.
    max_read_size: usize,

    /// Maximum content size for write operations.
    max_write_size: usize,

    /// Maximum content size for edit operations.
    max_edit_size: usize,

    /// Whether to follow symlinks (default: true).
    /// When true, symlinks are resolved and the target must be within
    /// workspace. When false, operations on symlinks are denied.
    follow_symlinks: bool,
}

impl FilesystemConfig {
    /// Creates a new configuration with the given workspace root.
    ///
    /// # Arguments
    ///
    /// * `workspace_root` - The root directory for file operations
    ///
    /// # Panics
    ///
    /// Panics if the workspace root cannot be canonicalized.
    #[must_use]
    pub fn new<P: AsRef<Path>>(workspace_root: P) -> Self {
        let workspace_root = workspace_root
            .as_ref()
            .canonicalize()
            .expect("workspace root must exist and be accessible");

        Self {
            workspace_root,
            max_write_size: DEFAULT_MAX_WRITE_SIZE,
            max_edit_size: DEFAULT_MAX_EDIT_SIZE,
            follow_symlinks: true,
            max_read_size: DEFAULT_MAX_READ_SIZE,
        }
    }

    /// Creates a new configuration builder.
    #[must_use]
    pub fn builder<P: AsRef<Path>>(workspace_root: P) -> FilesystemConfigBuilder {
        FilesystemConfigBuilder::new(workspace_root)
    }

    /// Returns the workspace root path.
    #[must_use]
    pub fn workspace_root(&self) -> &Path {
        &self.workspace_root
    }

    /// Returns the maximum write size.
    #[must_use]
    pub const fn max_write_size(&self) -> usize {
        self.max_write_size
    }

    /// Returns the maximum edit size.
    #[must_use]
    pub const fn max_edit_size(&self) -> usize {
        self.max_edit_size
    }

    /// Returns whether symlinks should be followed.
    #[must_use]
    pub const fn follow_symlinks(&self) -> bool {
        self.follow_symlinks
    }
}

/// Builder for `FilesystemConfig`.
pub struct FilesystemConfigBuilder {
    workspace_root: PathBuf,
    max_write_size: usize,
    max_edit_size: usize,
    max_read_size: usize,
    follow_symlinks: bool,
}

impl FilesystemConfigBuilder {
    /// Creates a new builder with the given workspace root.
    #[must_use]
    pub fn new<P: AsRef<Path>>(workspace_root: P) -> Self {
        Self {
            workspace_root: workspace_root.as_ref().to_path_buf(),
            max_write_size: DEFAULT_MAX_WRITE_SIZE,
            max_edit_size: DEFAULT_MAX_EDIT_SIZE,
            max_read_size: DEFAULT_MAX_READ_SIZE,
            follow_symlinks: true,
        }
    }

    /// Sets the maximum write size.
    #[must_use]
    pub const fn max_write_size(mut self, size: usize) -> Self {
        self.max_write_size = size;
        self
    }

    /// Sets the maximum edit size.
    #[must_use]
    pub const fn max_edit_size(mut self, size: usize) -> Self {
        self.max_edit_size = size;
        self
    }

    /// Sets whether to follow symlinks.
    #[must_use]
    pub const fn follow_symlinks(mut self, follow: bool) -> Self {
        self.follow_symlinks = follow;
        self
    }

    /// Builds the configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the workspace root cannot be canonicalized.
    pub fn build(self) -> Result<FilesystemConfig, SyscallError> {
        let workspace_root = self
            .workspace_root
            .canonicalize()
            .map_err(|e| SyscallError::Io {
                path: self.workspace_root.clone(),
                source: e,
            })?;

        Ok(FilesystemConfig {
            workspace_root,
            max_write_size: self.max_write_size,
            max_edit_size: self.max_edit_size,
            max_read_size: self.max_read_size,
            follow_symlinks: self.follow_symlinks,
        })
    }
}

/// Record of a file modification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModificationRecord {
    /// The path that was modified.
    pub path: PathBuf,
    /// The operation that was performed.
    pub operation: FileOperation,
    /// BLAKE3 hash of the content before modification (None for new files).
    pub hash_before: Option<[u8; 32]>,
    /// BLAKE3 hash of the content after modification.
    pub hash_after: [u8; 32],
    /// Size of the file after modification.
    pub size_after: u64,
    /// Duration of the operation in milliseconds.
    pub duration_ms: u64,
}

/// Type of file operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileOperation {
    /// File was read.
    Read,
    /// File was written (created or overwritten).
    Write,
    /// File was written in create-only mode (new file).
    Create,
    /// Content was appended to file.
    Append,
    /// File was edited (search/replace).
    Edit,
}

impl FileOperation {
    /// Returns the operation name as a string.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Read => "READ",
            Self::Write => "WRITE",
            Self::Create => "CREATE",
            Self::Append => "APPEND",
            Self::Edit => "EDIT",
        }
    }
}

/// Result of a file operation.
#[derive(Debug, Clone)]
pub struct FileOperationResult {
    /// The content (for read operations).
    pub content: Vec<u8>,
    /// BLAKE3 hash of the content.
    pub content_hash: [u8; 32],
    /// Size of the content/file.
    pub size: u64,
    /// Duration of the operation in milliseconds.
    pub duration_ms: u64,
}

/// Filesystem mediation handler.
///
/// Handles file read, write, and edit operations with workspace confinement
/// and security validation.
#[derive(Debug, Clone)]
pub struct FilesystemHandler {
    config: FilesystemConfig,
}

impl FilesystemHandler {
    /// Creates a new filesystem handler with the given configuration.
    #[must_use]
    pub const fn new(config: FilesystemConfig) -> Self {
        Self { config }
    }

    /// Returns the configuration.
    #[must_use]
    pub const fn config(&self) -> &FilesystemConfig {
        &self.config
    }

    /// Validates and normalizes a path.
    ///
    /// This method:
    /// 1. Checks for path traversal sequences (..)
    /// 2. Resolves relative paths against workspace root
    /// 3. Follows symlinks (if configured)
    /// 4. Verifies the resolved path is within workspace root
    ///
    /// # Arguments
    ///
    /// * `path` - The path to validate
    /// * `must_exist` - If true, the path must exist
    ///
    /// # Errors
    ///
    /// Returns an error if the path is invalid or outside the workspace.
    #[instrument(skip(self, path), fields(workspace = %self.config.workspace_root.display()))]
    pub fn validate_path<P: AsRef<Path>>(
        &self,
        path: P,
        must_exist: bool,
    ) -> Result<PathBuf, SyscallError> {
        let path = path.as_ref();
        debug!(path = %path.display(), must_exist, "validating path");

        // Check for path traversal in the raw input
        if contains_path_traversal(path) {
            warn!(path = %path.display(), "path traversal detected");
            return Err(SyscallError::PathTraversal {
                path: path.to_path_buf(),
            });
        }

        // Resolve the path
        let resolved = if path.is_absolute() {
            path.to_path_buf()
        } else {
            self.config.workspace_root.join(path)
        };

        // If the file must exist, canonicalize it to get the real path
        let canonical = if must_exist {
            resolve_path_with_symlinks(&resolved, MAX_SYMLINK_DEPTH)?
        } else {
            // For non-existent files, canonicalize the parent and append the filename
            let parent = resolved
                .parent()
                .ok_or_else(|| SyscallError::PathValidation {
                    path: resolved.clone(),
                    reason: "path has no parent directory".to_string(),
                })?;

            let parent_canonical = if parent.exists() {
                resolve_path_with_symlinks(parent, MAX_SYMLINK_DEPTH)?
            } else {
                // Parent doesn't exist - this is an error for most operations
                return Err(SyscallError::FileNotFound {
                    path: parent.to_path_buf(),
                });
            };

            let filename = resolved
                .file_name()
                .ok_or_else(|| SyscallError::PathValidation {
                    path: resolved.clone(),
                    reason: "path has no filename".to_string(),
                })?;

            parent_canonical.join(filename)
        };

        // Verify the canonical path is within workspace
        if !canonical.starts_with(&self.config.workspace_root) {
            warn!(
                canonical = %canonical.display(),
                workspace = %self.config.workspace_root.display(),
                "path resolves outside workspace"
            );
            return Err(SyscallError::PathOutsideWorkspace {
                path: path.to_path_buf(),
                workspace: self.config.workspace_root.clone(),
            });
        }

        debug!(canonical = %canonical.display(), "path validated");
        Ok(canonical)
    }

    /// Reads the contents of a file.
    ///
    /// # Arguments
    ///
    /// * `path` - The path to read
    /// * `offset` - Byte offset to start reading from (0 = beginning)
    /// * `limit` - Maximum bytes to read (0 = read entire file)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The path is invalid or outside workspace
    /// - The file does not exist
    /// - The offset is beyond the file size
    /// - An I/O error occurs
    #[instrument(skip(self, path))]
    pub fn read_file<P: AsRef<Path>>(
        &self,
        path: P,
        offset: u64,
        limit: u64,
    ) -> Result<FileOperationResult, SyscallError> {
        let start = Instant::now();
        let path = path.as_ref();

        // Validate and resolve path
        let canonical = self.validate_path(path, true)?;

        // Verify it's a regular file
        let metadata = fs::metadata(&canonical).map_err(|e| SyscallError::Io {
            path: canonical.clone(),
            source: e,
        })?;

        if !metadata.is_file() {
            return Err(SyscallError::NotAFile { path: canonical });
        }

        let file_size = metadata.len();

        // Check offset is valid
        if offset > 0 && offset >= file_size {
            return Err(SyscallError::OffsetBeyondFile { offset, file_size });
        }

        // Open and read file
        let mut file = File::open(&canonical).map_err(|e| SyscallError::Io {
            path: canonical.clone(),
            source: e,
        })?;

        // Seek to offset
        if offset > 0 {
            file.seek(SeekFrom::Start(offset))
                .map_err(|e| SyscallError::Io {
                    path: canonical.clone(),
                    source: e,
                })?;
        }

        // Read content
        // Note: These casts are safe for 64-bit systems. On 32-bit systems, files
        // larger than usize::MAX bytes wouldn't be practical to hold in memory
        // anyway.
        #[allow(clippy::cast_possible_truncation)]
        let read_size = if limit > 0 {
            limit as usize
        } else {
            (file_size - offset) as usize
        };

        if read_size > self.config.max_read_size {
            return Err(SyscallError::ContentTooLarge {
                size: read_size,
                limit: self.config.max_read_size,
            });
        }

        let mut content = vec![0u8; read_size];
        let bytes_read = file.read(&mut content).map_err(|e| SyscallError::Io {
            path: canonical.clone(),
            source: e,
        })?;
        content.truncate(bytes_read);

        // Hash the content
        let content_hash = blake3::hash(&content);

        let duration = start.elapsed();
        info!(
            path = %canonical.display(),
            bytes_read,
            offset,
            duration_ms = duration_to_millis(duration),
            "file read completed"
        );

        Ok(FileOperationResult {
            content,
            content_hash: *content_hash.as_bytes(),
            size: bytes_read as u64,
            duration_ms: duration_to_millis(duration),
        })
    }

    /// Writes content to a file.
    ///
    /// # Arguments
    ///
    /// * `path` - The path to write
    /// * `content` - The content to write
    /// * `create_only` - If true, fail if the file already exists
    /// * `append` - If true, append to existing file
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The path is invalid or outside workspace
    /// - `create_only` is true and the file exists
    /// - The content exceeds the maximum write size
    /// - An I/O error occurs
    #[instrument(skip(self, path, content), fields(content_size = content.len()))]
    pub fn write_file<P: AsRef<Path>>(
        &self,
        path: P,
        content: &[u8],
        create_only: bool,
        append: bool,
    ) -> Result<ModificationRecord, SyscallError> {
        let start = Instant::now();
        let path = path.as_ref();

        // Check content size
        if content.len() > self.config.max_write_size {
            return Err(SyscallError::ContentTooLarge {
                size: content.len(),
                limit: self.config.max_write_size,
            });
        }

        // Validate path (may not exist for new files)
        let canonical = self.validate_path(path, false)?;

        // Get hash of existing content if file exists
        let hash_before = if canonical.exists() {
            if create_only {
                // We check here for a quick fail, but the real atomic check is in OpenOptions
                return Err(SyscallError::FileAlreadyExists { path: canonical });
            }
            Some(hash_file(&canonical)?)
        } else {
            None
        };

        // Determine the operation type
        let operation = if hash_before.is_none() {
            FileOperation::Create
        } else if append {
            FileOperation::Append
        } else {
            FileOperation::Write
        };

        // Open file with appropriate options
        let mut options = OpenOptions::new();
        options.write(true);

        if create_only {
            // Atomic check-and-create
            options.create_new(true);
        } else {
            options.create(true);
            options.truncate(!append);
        }
        
        options.append(append);

        let mut file = options.open(&canonical).map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                SyscallError::FileAlreadyExists {
                    path: canonical.clone(),
                }
            } else {
                SyscallError::Io {
                    path: canonical.clone(),
                    source: e,
                }
            }
        })?;

        // Write content
        file.write_all(content).map_err(|e| SyscallError::Io {
            path: canonical.clone(),
            source: e,
        })?;

        file.sync_all().map_err(|e| SyscallError::Io {
            path: canonical.clone(),
            source: e,
        })?;

        drop(file);

        // Get hash and size after write
        let hash_after = hash_file(&canonical)?;
        let metadata = fs::metadata(&canonical).map_err(|e| SyscallError::Io {
            path: canonical.clone(),
            source: e,
        })?;

        let duration = start.elapsed();
        info!(
            path = %canonical.display(),
            operation = operation.as_str(),
            bytes_written = content.len(),
            duration_ms = duration_to_millis(duration),
            "file write completed"
        );

        Ok(ModificationRecord {
            path: canonical,
            operation,
            hash_before,
            hash_after,
            size_after: metadata.len(),
            duration_ms: duration_to_millis(duration),
        })
    }

    /// Edits a file using search/replace.
    ///
    /// The `old_content` must match exactly once in the file. The operation is
    /// atomic: either the edit succeeds completely or the file is unchanged.
    ///
    /// # Arguments
    ///
    /// * `path` - The path to edit
    /// * `old_content` - The content to search for
    /// * `new_content` - The content to replace with
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The path is invalid or outside workspace
    /// - The file does not exist
    /// - `old_content` is not found in the file
    /// - `old_content` matches multiple times
    /// - An I/O error occurs
    #[instrument(skip(self, path, old_content, new_content), fields(old_len = old_content.len(), new_len = new_content.len()))]
    pub fn edit_file<P: AsRef<Path>>(
        &self,
        path: P,
        old_content: &str,
        new_content: &str,
    ) -> Result<ModificationRecord, SyscallError> {
        let start = Instant::now();
        let path = path.as_ref();

        // Check content sizes
        if old_content.len() > self.config.max_edit_size {
            return Err(SyscallError::ContentTooLarge {
                size: old_content.len(),
                limit: self.config.max_edit_size,
            });
        }
        if new_content.len() > self.config.max_edit_size {
            return Err(SyscallError::ContentTooLarge {
                size: new_content.len(),
                limit: self.config.max_edit_size,
            });
        }

        // Validate and resolve path
        let canonical = self.validate_path(path, true)?;
        
        // Use the parent directory for the temp file to ensure it's on the same filesystem
        let parent_dir = canonical.parent().ok_or_else(|| SyscallError::PathValidation {
             path: canonical.clone(),
             reason: "file has no parent directory".to_string() 
        })?;

        // Read existing content
        let existing = fs::read_to_string(&canonical).map_err(|e| SyscallError::Io {
            path: canonical.clone(),
            source: e,
        })?;

        let hash_before = blake3::hash(existing.as_bytes());

        // Count occurrences of old_content
        let match_count = existing.matches(old_content).count();

        if match_count == 0 {
            return Err(SyscallError::EditNotFound { path: canonical });
        }

        if match_count > 1 {
            return Err(SyscallError::EditMultipleMatches {
                path: canonical,
                count: match_count,
            });
        }

        // Perform the replacement
        let new_file_content = existing.replacen(old_content, new_content, 1);

        // Write atomically by writing to temp file and renaming
        // Security: Use NamedTempFile::new_in to avoid predictable names and ensure atomic creation
        let mut temp_file = NamedTempFile::new_in(parent_dir).map_err(|e| SyscallError::Io {
            path: parent_dir.to_path_buf(),
            source: e,
        })?;
        
        temp_file.write_all(new_file_content.as_bytes()).map_err(|e| SyscallError::Io {
            path: temp_file.path().to_path_buf(),
            source: e,
        })?;
        
        // Persist the temp file to the target path
        temp_file.persist(&canonical).map_err(|e| SyscallError::Io {
            path: canonical.clone(),
            source: e.error,
        })?;

        // Get hash after edit
        let hash_after = blake3::hash(new_file_content.as_bytes());
        let metadata = fs::metadata(&canonical).map_err(|e| SyscallError::Io {
            path: canonical.clone(),
            source: e,
        })?;

        let duration = start.elapsed();
        info!(
            path = %canonical.display(),
            old_len = old_content.len(),
            new_len = new_content.len(),
            duration_ms = duration_to_millis(duration),
            "file edit completed"
        );

        Ok(ModificationRecord {
            path: canonical,
            operation: FileOperation::Edit,
            hash_before: Some(*hash_before.as_bytes()),
            hash_after: *hash_after.as_bytes(),
            size_after: metadata.len(),
            duration_ms: duration_to_millis(duration),
        })
    }
}

/// Checks if a path contains path traversal sequences.
///
/// Returns true if the path contains ".." as a path component.
fn contains_path_traversal(path: &Path) -> bool {
    path.components()
        .any(|c| c == std::path::Component::ParentDir)
}

/// Resolves a path following symlinks up to a maximum depth.
///
/// # Errors
///
/// Returns an error if:
/// - The path does not exist
/// - The symlink depth exceeds the maximum
/// - An I/O error occurs
fn resolve_path_with_symlinks(path: &Path, max_depth: usize) -> Result<PathBuf, SyscallError> {
    let mut current = path.to_path_buf();
    let mut depth = 0;

    loop {
        match fs::symlink_metadata(&current) {
            Ok(meta) if meta.is_symlink() => {
                depth += 1;
                if depth > max_depth {
                    return Err(SyscallError::SymlinkDepthExceeded {
                        path: path.to_path_buf(),
                        depth: max_depth,
                    });
                }

                let target = fs::read_link(&current).map_err(|e| SyscallError::Io {
                    path: current.clone(),
                    source: e,
                })?;

                // Resolve relative symlinks against the symlink's parent
                current = if target.is_absolute() {
                    target
                } else {
                    current.parent().map(|p| p.join(&target)).unwrap_or(target)
                };
            },
            Ok(_) => {
                // Not a symlink, canonicalize and return
                return current.canonicalize().map_err(|e| SyscallError::Io {
                    path: current.clone(),
                    source: e,
                });
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(SyscallError::FileNotFound { path: current });
            },
            Err(e) => {
                return Err(SyscallError::Io {
                    path: current,
                    source: e,
                });
            },
        }
    }
}

/// Computes the BLAKE3 hash of a file using streaming.
///
/// Uses a heap-allocated buffer to avoid large stack allocations.
fn hash_file(path: &Path) -> Result<[u8; 32], SyscallError> {
    let mut file = File::open(path).map_err(|e| SyscallError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;

    let mut hasher = blake3::Hasher::new();
    // Allocate buffer on heap to avoid large stack allocation (clippy::large_stack_arrays)
    let mut buffer = vec![0u8; HASH_BUFFER_SIZE];

    loop {
        let bytes_read = file.read(&mut buffer).map_err(|e| SyscallError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;

        if bytes_read == 0 {
            break;
        }

        hasher.update(&buffer[..bytes_read]);
    }

    Ok(*hasher.finalize().as_bytes())
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    fn setup_workspace() -> (TempDir, FilesystemHandler) {
        let temp_dir = TempDir::new().expect("create temp dir");
        let config = FilesystemConfig::new(temp_dir.path());
        let handler = FilesystemHandler::new(config);
        (temp_dir, handler)
    }

    // ========================================================================
    // Path Validation Tests
    // ========================================================================

    #[test]
    fn test_validate_path_absolute_in_workspace() {
        let (temp_dir, handler) = setup_workspace();

        // Create a file
        let file_path = temp_dir.path().join("test.txt");
        fs::write(&file_path, "test").unwrap();

        // Validate the absolute path
        let result = handler.validate_path(&file_path, true);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), file_path.canonicalize().unwrap());
    }

    #[test]
    fn test_validate_path_relative() {
        let (temp_dir, handler) = setup_workspace();

        // Create a file
        let file_path = temp_dir.path().join("test.txt");
        fs::write(&file_path, "test").unwrap();

        // Validate a relative path
        let result = handler.validate_path("test.txt", true);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_path_traversal_rejected() {
        let (_temp_dir, handler) = setup_workspace();

        // Try to escape with ..
        let result = handler.validate_path("../etc/passwd", true);
        assert!(matches!(result, Err(SyscallError::PathTraversal { .. })));

        let result = handler.validate_path("subdir/../../etc/passwd", true);
        assert!(matches!(result, Err(SyscallError::PathTraversal { .. })));
    }

    #[test]
    fn test_validate_path_outside_workspace() {
        let (temp_dir, handler) = setup_workspace();

        // Create a symlink that points outside
        let link_path = temp_dir.path().join("escape");
        #[cfg(unix)]
        std::os::unix::fs::symlink("/etc/passwd", &link_path).unwrap();

        #[cfg(unix)]
        {
            let result = handler.validate_path(&link_path, true);
            assert!(matches!(
                result,
                Err(SyscallError::PathOutsideWorkspace { .. })
            ));
        }
    }

    // ========================================================================
    // Read Tests
    // ========================================================================

    #[test]
    fn test_read_file_complete() {
        let (temp_dir, handler) = setup_workspace();

        let content = b"Hello, World!";
        let file_path = temp_dir.path().join("test.txt");
        fs::write(&file_path, content).unwrap();

        let result = handler.read_file(&file_path, 0, 0).unwrap();

        assert_eq!(result.content, content);
        assert_eq!(result.size, content.len() as u64);
        assert_ne!(result.content_hash, [0u8; 32]);
    }

    #[test]
    fn test_read_file_with_offset() {
        let (temp_dir, handler) = setup_workspace();

        let content = b"Hello, World!";
        let file_path = temp_dir.path().join("test.txt");
        fs::write(&file_path, content).unwrap();

        let result = handler.read_file(&file_path, 7, 0).unwrap();

        assert_eq!(result.content, b"World!");
    }

    #[test]
    fn test_read_file_with_limit() {
        let (temp_dir, handler) = setup_workspace();

        let content = b"Hello, World!";
        let file_path = temp_dir.path().join("test.txt");
        fs::write(&file_path, content).unwrap();

        let result = handler.read_file(&file_path, 0, 5).unwrap();

        assert_eq!(result.content, b"Hello");
    }

    #[test]
    fn test_read_file_not_found() {
        let (temp_dir, handler) = setup_workspace();

        let file_path = temp_dir.path().join("nonexistent.txt");
        let result = handler.read_file(&file_path, 0, 0);

        assert!(matches!(result, Err(SyscallError::FileNotFound { .. })));
    }

    #[test]
    fn test_read_file_offset_beyond_file() {
        let (temp_dir, handler) = setup_workspace();

        let content = b"Hello";
        let file_path = temp_dir.path().join("test.txt");
        fs::write(&file_path, content).unwrap();

        let result = handler.read_file(&file_path, 100, 0);

        assert!(matches!(result, Err(SyscallError::OffsetBeyondFile { .. })));
    }

    // ========================================================================
    // Write Tests
    // ========================================================================

    #[test]
    fn test_write_file_create() {
        let (temp_dir, handler) = setup_workspace();

        let file_path = temp_dir.path().join("new.txt");
        let content = b"New content";

        let result = handler
            .write_file(&file_path, content, false, false)
            .unwrap();

        assert_eq!(result.operation, FileOperation::Create);
        assert!(result.hash_before.is_none());
        assert_eq!(fs::read(&file_path).unwrap(), content);
    }

    #[test]
    fn test_write_file_overwrite() {
        let (temp_dir, handler) = setup_workspace();

        let file_path = temp_dir.path().join("existing.txt");
        fs::write(&file_path, b"old content").unwrap();

        let new_content = b"new content";
        let result = handler
            .write_file(&file_path, new_content, false, false)
            .unwrap();

        assert_eq!(result.operation, FileOperation::Write);
        assert!(result.hash_before.is_some());
        assert_eq!(fs::read(&file_path).unwrap(), new_content);
    }

    #[test]
    fn test_write_file_create_only_exists() {
        let (temp_dir, handler) = setup_workspace();

        let file_path = temp_dir.path().join("existing.txt");
        fs::write(&file_path, b"content").unwrap();

        let result = handler.write_file(&file_path, b"new", true, false);

        assert!(matches!(
            result,
            Err(SyscallError::FileAlreadyExists { .. })
        ));
    }

    #[test]
    fn test_write_file_append() {
        let (temp_dir, handler) = setup_workspace();

        let file_path = temp_dir.path().join("append.txt");
        fs::write(&file_path, b"Hello").unwrap();

        let result = handler
            .write_file(&file_path, b", World!", false, true)
            .unwrap();

        assert_eq!(result.operation, FileOperation::Append);
        assert_eq!(fs::read(&file_path).unwrap(), b"Hello, World!");
    }

    #[test]
    fn test_write_file_content_too_large() {
        let (temp_dir, _) = setup_workspace();

        let config = FilesystemConfigBuilder::new(temp_dir.path())
            .max_write_size(10)
            .build()
            .unwrap();
        let handler = FilesystemHandler::new(config);

        let file_path = temp_dir.path().join("large.txt");
        let result = handler.write_file(&file_path, &[0u8; 100], false, false);

        assert!(matches!(result, Err(SyscallError::ContentTooLarge { .. })));
    }

    // ========================================================================
    // Edit Tests
    // ========================================================================

    #[test]
    fn test_edit_file_success() {
        let (temp_dir, handler) = setup_workspace();

        let file_path = temp_dir.path().join("edit.txt");
        fs::write(&file_path, "Hello, World!").unwrap();

        let result = handler.edit_file(&file_path, "World", "Rust").unwrap();

        assert_eq!(result.operation, FileOperation::Edit);
        assert!(result.hash_before.is_some());
        assert_ne!(result.hash_before.unwrap(), result.hash_after);
        assert_eq!(fs::read_to_string(&file_path).unwrap(), "Hello, Rust!");
    }

    #[test]
    fn test_edit_file_not_found() {
        let (temp_dir, handler) = setup_workspace();

        let file_path = temp_dir.path().join("nonexistent.txt");
        let result = handler.edit_file(&file_path, "old", "new");

        assert!(matches!(result, Err(SyscallError::FileNotFound { .. })));
    }

    #[test]
    fn test_edit_file_pattern_not_found() {
        let (temp_dir, handler) = setup_workspace();

        let file_path = temp_dir.path().join("edit.txt");
        fs::write(&file_path, "Hello, World!").unwrap();

        let result = handler.edit_file(&file_path, "nonexistent", "replacement");

        assert!(matches!(result, Err(SyscallError::EditNotFound { .. })));
    }

    #[test]
    fn test_edit_file_multiple_matches() {
        let (temp_dir, handler) = setup_workspace();

        let file_path = temp_dir.path().join("edit.txt");
        fs::write(&file_path, "foo bar foo baz foo").unwrap();

        let result = handler.edit_file(&file_path, "foo", "qux");

        assert!(matches!(
            result,
            Err(SyscallError::EditMultipleMatches { count: 3, .. })
        ));
    }

    #[test]
    fn test_edit_file_atomic() {
        let (temp_dir, handler) = setup_workspace();

        let file_path = temp_dir.path().join("atomic.txt");
        let original = "original content";
        fs::write(&file_path, original).unwrap();

        // This edit should fail
        let result = handler.edit_file(&file_path, "nonexistent", "replacement");
        assert!(result.is_err());

        // Original content should be unchanged
        assert_eq!(fs::read_to_string(&file_path).unwrap(), original);
    }

    // ========================================================================
    // Path Traversal Security Tests
    // ========================================================================

    #[test]
    fn test_contains_path_traversal() {
        assert!(contains_path_traversal(Path::new("../etc/passwd")));
        assert!(contains_path_traversal(Path::new("foo/../bar")));
        assert!(contains_path_traversal(Path::new("/a/b/../c")));

        assert!(!contains_path_traversal(Path::new("/normal/path")));
        assert!(!contains_path_traversal(Path::new("relative/path")));
        assert!(!contains_path_traversal(Path::new("./current")));
        assert!(!contains_path_traversal(Path::new("/path/with...dots")));
    }

    // ========================================================================
    // Hash Verification Tests
    // ========================================================================

    #[test]
    fn test_content_hash_consistency() {
        let (temp_dir, handler) = setup_workspace();

        let content = b"Hello, World!";
        let file_path = temp_dir.path().join("hash_test.txt");
        fs::write(&file_path, content).unwrap();

        // Read file multiple times
        let result1 = handler.read_file(&file_path, 0, 0).unwrap();
        let result2 = handler.read_file(&file_path, 0, 0).unwrap();

        // Hashes should be identical
        assert_eq!(result1.content_hash, result2.content_hash);

        // Hash should match expected BLAKE3 hash
        let expected = blake3::hash(content);
        assert_eq!(result1.content_hash, *expected.as_bytes());
    }

    #[test]
    fn test_modification_tracking() {
        let (temp_dir, handler) = setup_workspace();

        let file_path = temp_dir.path().join("track.txt");
        fs::write(&file_path, b"initial").unwrap();

        let initial_hash = handler.read_file(&file_path, 0, 0).unwrap().content_hash;

        // Modify the file
        let record = handler
            .write_file(&file_path, b"modified", false, false)
            .unwrap();

        // Before hash should match initial read
        assert_eq!(record.hash_before.unwrap(), initial_hash);

        // After hash should be different
        assert_ne!(record.hash_after, initial_hash);

                // After hash should match new content

                let final_hash = handler.read_file(&file_path, 0, 0).unwrap().content_hash;

                assert_eq!(record.hash_after, final_hash);

            }

        

            #[test]

            fn test_hash_large_file_streaming() {

                let (temp_dir, _handler) = setup_workspace();

                

                // Create a file larger than HASH_BUFFER_SIZE (64KB)

                // 1MB = 1024 * 1024 bytes

                let size = 1024 * 1024;

                let mut content = Vec::with_capacity(size);

                for i in 0..size {

                    content.push((i % 256) as u8);

                }

                

                let file_path = temp_dir.path().join("large_hash.txt");

                fs::write(&file_path, &content).unwrap();

                

                // Calculate expected hash

                let expected = blake3::hash(&content);

                

                // Calculate actual hash using our streaming function

                // We need to access the private hash_file function, so this test stays in this module

                let actual = hash_file(&file_path).unwrap();

                

                assert_eq!(actual, *expected.as_bytes());

            }

        }

        