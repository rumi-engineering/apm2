//! Filesystem tool implementation.
//!
//! Provides the execution logic for filesystem tools (`FileRead`, `FileWrite`,
//! `FileEdit`). All operations are sandboxed to a workspace root directory.

use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use tracing::{debug, info};

use super::{FileEdit, FileRead, FileWrite, ToolError};

/// Filesystem tool handler.
#[derive(Debug)]
pub struct FilesystemTool {
    workspace_root: PathBuf,
}

impl FilesystemTool {
    /// Create a new filesystem tool handler.
    #[must_use]
    pub const fn new(workspace_root: PathBuf) -> Self {
        Self { workspace_root }
    }

    /// Resolve a path relative to the workspace root.
    ///
    /// # Security
    ///
    /// This method ensures the resolved path is within the workspace root.
    /// Returns a `ToolError` if the path attempts to escape the workspace.
    fn resolve_path(&self, path_str: &str) -> Result<PathBuf, ToolError> {
        // Reject absolute paths that don't start with workspace root (optional,
        // but cleaner to enforce relative paths in API).
        // For now, treat all paths as relative to workspace.
        let path = Path::new(path_str);

        // Prevent simple traversal at string level (already done by validation,
        // but good defense in depth).
        if path_str.contains("..") {
            return Err(ToolError {
                error_code: "PATH_TRAVERSAL".to_string(),
                message: "Path traversal sequences (..) are not allowed".to_string(),
                retryable: false,
                retry_after_ms: 0,
            });
        }

        let resolved = self.workspace_root.join(path);

        // Canonicalize to resolve symlinks and '..' if any slipped through
        let canonical = match resolved.canonicalize() {
            Ok(p) => p,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                // If file doesn't exist, we can't canonicalize it directly.
                // We check the parent directory.
                if let Some(parent) = resolved.parent() {
                    match parent.canonicalize() {
                        Ok(p) => p.join(resolved.file_name().unwrap()),
                        Err(e) => return Err(Self::map_io_error(&e)),
                    }
                } else {
                    return Err(ToolError {
                        error_code: "INVALID_PATH".to_string(),
                        message: "Invalid path".to_string(),
                        retryable: false,
                        retry_after_ms: 0,
                    });
                }
            },
            Err(e) => return Err(Self::map_io_error(&e)),
        };

        // Verify it is still within workspace
        // We need to canonicalize workspace root too for comparison
        let canonical_root = self
            .workspace_root
            .canonicalize()
            .map_err(|e| Self::map_io_error(&e))?;

        if !canonical.starts_with(&canonical_root) {
            return Err(ToolError {
                error_code: "ACCESS_DENIED".to_string(),
                message: "Path escapes workspace root".to_string(),
                retryable: false,
                retry_after_ms: 0,
            });
        }

        Ok(canonical)
    }

    /// Map IO error to `ToolError`.
    fn map_io_error(err: &io::Error) -> ToolError {
        let (code, retryable) = match err.kind() {
            io::ErrorKind::NotFound => ("FILE_NOT_FOUND", false),
            io::ErrorKind::PermissionDenied => ("ACCESS_DENIED", false),
            io::ErrorKind::AlreadyExists => ("FILE_EXISTS", false),
            io::ErrorKind::Interrupted => ("INTERRUPTED", true),
            _ => ("IO_ERROR", true),
        };

        ToolError {
            error_code: code.to_string(),
            message: err.to_string(),
            retryable,
            retry_after_ms: if retryable { 100 } else { 0 },
        }
    }

    /// Execute a file read request.
    ///
    /// # Errors
    ///
    /// Returns a `ToolError` if the file cannot be read, if the path is
    /// invalid, or if the offset is out of bounds.
    pub fn read(&self, req: &FileRead) -> Result<Vec<u8>, ToolError> {
        let path = self.resolve_path(&req.path)?;
        debug!("Reading file: {:?}", path);

        let mut file = fs::File::open(&path).map_err(|e| Self::map_io_error(&e))?;
        let metadata = file.metadata().map_err(|e| Self::map_io_error(&e))?;
        let len = metadata.len();

        if req.offset > len {
            return Err(ToolError {
                error_code: "INVALID_OFFSET".to_string(),
                message: format!("Offset {} exceeds file length {}", req.offset, len),
                retryable: false,
                retry_after_ms: 0,
            });
        }

        if req.offset > 0 {
            use std::io::Seek;
            file.seek(io::SeekFrom::Start(req.offset))
                .map_err(|e| Self::map_io_error(&e))?;
        }

        let mut buffer = Vec::new();
        if req.limit > 0 {
            file.take(req.limit)
                .read_to_end(&mut buffer)
                .map_err(|e| Self::map_io_error(&e))?;
        } else {
            file.read_to_end(&mut buffer)
                .map_err(|e| Self::map_io_error(&e))?;
        }

        Ok(buffer)
    }

    /// Execute a file write request.
    ///
    /// # Errors
    ///
    /// Returns a `ToolError` if the file cannot be written, if the path is
    /// invalid, or if file creation flags conflict with existing state.
    pub fn write(&self, req: &FileWrite) -> Result<(), ToolError> {
        let path = self.resolve_path(&req.path)?;
        info!("Writing to file: {:?}", path);

        // Check if directory exists, create if needed
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| Self::map_io_error(&e))?;
        }

        let mut options = fs::OpenOptions::new();
        options.write(true);

        if req.create_only {
            options.create_new(true);
        } else if req.append {
            options.create(true).append(true);
        } else {
            options.create(true).truncate(true);
        }

        let mut file = options.open(path).map_err(|e| Self::map_io_error(&e))?;
        file.write_all(&req.content)
            .map_err(|e| Self::map_io_error(&e))?;
        file.flush().map_err(|e| Self::map_io_error(&e))?;

        Ok(())
    }

    /// Execute a file edit request.
    ///
    /// # Errors
    ///
    /// Returns a `ToolError` if the file cannot be read/written, if the old
    /// content is not found, or if multiple matches are found.
    pub fn edit(&self, req: &FileEdit) -> Result<(), ToolError> {
        let path = self.resolve_path(&req.path)?;
        info!("Editing file: {:?}", path);

        // Read entire file (enforce limit via validation/policy, here we assume it fits
        // in memory)
        let content = fs::read_to_string(&path).map_err(|e| Self::map_io_error(&e))?;

        match content.match_indices(&req.old_content).count() {
            0 => Err(ToolError {
                error_code: "CONTENT_NOT_FOUND".to_string(),
                message: "Old content not found in file".to_string(),
                retryable: false,
                retry_after_ms: 0,
            }),
            1 => {
                // Perform replacement
                let new_content = content.replace(&req.old_content, &req.new_content);
                fs::write(&path, new_content).map_err(|e| Self::map_io_error(&e))?;
                Ok(())
            },
            n => Err(ToolError {
                error_code: "MULTIPLE_MATCHES".to_string(),
                message: format!("Old content matched {n} times; must match exactly once"),
                retryable: false,
                retry_after_ms: 0,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    #[test]

    fn test_file_read_write() {
        let temp_dir = TempDir::new().unwrap();

        let tool = FilesystemTool::new(temp_dir.path().to_path_buf());

        let write_req = FileWrite {
            path: "test.txt".to_string(),

            content: b"Hello".to_vec(),

            create_only: false,

            append: false,
        };

        tool.write(&write_req).unwrap();

        let read_req = FileRead {
            path: "test.txt".to_string(),

            offset: 0,

            limit: 0,
        };

        let content = tool.read(&read_req).unwrap();

        assert_eq!(content, b"Hello");
    }

    #[test]

    fn test_file_edit() {
        let temp_dir = TempDir::new().unwrap();

        let tool = FilesystemTool::new(temp_dir.path().to_path_buf());

        tool.write(&FileWrite {
            path: "code.rs".to_string(),

            content: b"fn main() { println!(\"Hello\"); }".to_vec(),

            create_only: false,

            append: false,
        })
        .unwrap();

        tool.edit(&FileEdit {
            path: "code.rs".to_string(),

            old_content: "println!(\"Hello\")".to_string(),

            new_content: "println!(\"World\")".to_string(),
        })
        .unwrap();

        let content = tool
            .read(&FileRead {
                path: "code.rs".to_string(),

                offset: 0,

                limit: 0,
            })
            .unwrap();

        assert_eq!(content, b"fn main() { println!(\"World\"); }");
    }

    #[test]

    fn test_path_traversal_blocked() {
        let temp_dir = TempDir::new().unwrap();

        let tool = FilesystemTool::new(temp_dir.path().to_path_buf());

        let err = tool
            .read(&FileRead {
                path: "../outside.txt".to_string(),

                offset: 0,

                limit: 0,
            })
            .unwrap_err();

        assert_eq!(err.error_code, "PATH_TRAVERSAL");
    }
}
