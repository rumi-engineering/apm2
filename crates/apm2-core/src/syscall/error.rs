//! Error types for syscall mediation.

use std::path::PathBuf;

use thiserror::Error;

/// Errors that can occur during syscall execution.
#[derive(Debug, Error)]
pub enum SyscallError {
    /// Path validation failed.
    #[error("path validation failed: {reason}")]
    PathValidation {
        /// The path that failed validation.
        path: PathBuf,
        /// The reason for validation failure.
        reason: String,
    },

    /// Path is outside the workspace root.
    #[error("path '{path}' is outside workspace root '{workspace}'")]
    PathOutsideWorkspace {
        /// The requested path.
        path: PathBuf,
        /// The workspace root.
        workspace: PathBuf,
    },

    /// Path contains traversal sequence.
    #[error("path '{path}' contains path traversal sequence")]
    PathTraversal {
        /// The path containing traversal.
        path: PathBuf,
    },

    /// File not found.
    #[error("file not found: {path}")]
    FileNotFound {
        /// The path that was not found.
        path: PathBuf,
    },

    /// File already exists (for `create_only` mode).
    #[error("file already exists: {path}")]
    FileAlreadyExists {
        /// The path that already exists.
        path: PathBuf,
    },

    /// File is not a regular file.
    #[error("path is not a regular file: {path}")]
    NotAFile {
        /// The path that is not a file.
        path: PathBuf,
    },

    /// Edit match not found.
    #[error("edit pattern not found in file: {path}")]
    EditNotFound {
        /// The path being edited.
        path: PathBuf,
    },

    /// Edit pattern matches multiple times.
    #[error("edit pattern matches {count} times in file: {path} (must match exactly once)")]
    EditMultipleMatches {
        /// The path being edited.
        path: PathBuf,
        /// Number of matches found.
        count: usize,
    },

    /// Permission denied.
    #[error("permission denied: {path}")]
    PermissionDenied {
        /// The path with permission issues.
        path: PathBuf,
    },

    /// I/O error.
    #[error("I/O error on {path}: {source}")]
    Io {
        /// The path involved in the I/O error.
        path: PathBuf,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// Read offset is beyond file size.
    #[error("read offset {offset} is beyond file size {file_size}")]
    OffsetBeyondFile {
        /// The requested offset.
        offset: u64,
        /// The actual file size.
        file_size: u64,
    },

    /// Content too large.
    #[error("content size {size} exceeds limit {limit}")]
    ContentTooLarge {
        /// The content size.
        size: usize,
        /// The maximum allowed size.
        limit: usize,
    },

    /// Symlink resolution exceeded maximum depth.
    #[error("symlink resolution exceeded maximum depth ({depth}) for path: {path}")]
    SymlinkDepthExceeded {
        /// The path with excessive symlink depth.
        path: PathBuf,
        /// The maximum allowed depth.
        depth: usize,
    },

    /// Timeout during operation.
    #[error("operation timed out after {timeout_ms}ms")]
    Timeout {
        /// The timeout duration in milliseconds.
        timeout_ms: u64,
    },
}

impl SyscallError {
    /// Returns the error code for this error.
    ///
    /// Error codes are machine-readable strings suitable for programmatic
    /// handling and logging.
    #[must_use]
    pub const fn error_code(&self) -> &'static str {
        match self {
            Self::PathValidation { .. } => "PATH_VALIDATION_FAILED",
            Self::PathOutsideWorkspace { .. } => "PATH_OUTSIDE_WORKSPACE",
            Self::PathTraversal { .. } => "PATH_TRAVERSAL_DETECTED",
            Self::FileNotFound { .. } => "FILE_NOT_FOUND",
            Self::FileAlreadyExists { .. } => "FILE_ALREADY_EXISTS",
            Self::NotAFile { .. } => "NOT_A_FILE",
            Self::EditNotFound { .. } => "EDIT_NOT_FOUND",
            Self::EditMultipleMatches { .. } => "EDIT_MULTIPLE_MATCHES",
            Self::PermissionDenied { .. } => "PERMISSION_DENIED",
            Self::Io { .. } => "IO_ERROR",
            Self::OffsetBeyondFile { .. } => "OFFSET_BEYOND_FILE",
            Self::ContentTooLarge { .. } => "CONTENT_TOO_LARGE",
            Self::SymlinkDepthExceeded { .. } => "SYMLINK_DEPTH_EXCEEDED",
            Self::Timeout { .. } => "OPERATION_TIMEOUT",
        }
    }

    /// Returns whether this error is retryable.
    ///
    /// Retryable errors are transient failures that may succeed if retried.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        match self {
            // Transient I/O errors may be retryable
            Self::Io { .. } | Self::Timeout { .. } => true,
            // All other errors are not retryable
            Self::PathValidation { .. }
            | Self::PathOutsideWorkspace { .. }
            | Self::PathTraversal { .. }
            | Self::FileNotFound { .. }
            | Self::FileAlreadyExists { .. }
            | Self::NotAFile { .. }
            | Self::EditNotFound { .. }
            | Self::EditMultipleMatches { .. }
            | Self::PermissionDenied { .. }
            | Self::OffsetBeyondFile { .. }
            | Self::ContentTooLarge { .. }
            | Self::SymlinkDepthExceeded { .. } => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_codes_are_unique() {
        use std::collections::HashSet;

        let codes: Vec<&str> = vec![
            SyscallError::PathValidation {
                path: PathBuf::new(),
                reason: String::new(),
            }
            .error_code(),
            SyscallError::PathOutsideWorkspace {
                path: PathBuf::new(),
                workspace: PathBuf::new(),
            }
            .error_code(),
            SyscallError::PathTraversal {
                path: PathBuf::new(),
            }
            .error_code(),
            SyscallError::FileNotFound {
                path: PathBuf::new(),
            }
            .error_code(),
            SyscallError::FileAlreadyExists {
                path: PathBuf::new(),
            }
            .error_code(),
            SyscallError::NotAFile {
                path: PathBuf::new(),
            }
            .error_code(),
            SyscallError::EditNotFound {
                path: PathBuf::new(),
            }
            .error_code(),
            SyscallError::EditMultipleMatches {
                path: PathBuf::new(),
                count: 0,
            }
            .error_code(),
            SyscallError::PermissionDenied {
                path: PathBuf::new(),
            }
            .error_code(),
            SyscallError::Io {
                path: PathBuf::new(),
                source: std::io::Error::other("test"),
            }
            .error_code(),
            SyscallError::OffsetBeyondFile {
                offset: 0,
                file_size: 0,
            }
            .error_code(),
            SyscallError::ContentTooLarge { size: 0, limit: 0 }.error_code(),
            SyscallError::SymlinkDepthExceeded {
                path: PathBuf::new(),
                depth: 0,
            }
            .error_code(),
            SyscallError::Timeout { timeout_ms: 0 }.error_code(),
        ];

        let unique: HashSet<_> = codes.iter().collect();
        assert_eq!(codes.len(), unique.len(), "Error codes must be unique");
    }

    #[test]
    fn test_retryable_errors() {
        // Timeout is retryable
        assert!(SyscallError::Timeout { timeout_ms: 1000 }.is_retryable());

        // I/O errors are retryable
        assert!(
            SyscallError::Io {
                path: PathBuf::new(),
                source: std::io::Error::other("test"),
            }
            .is_retryable()
        );

        // Path errors are not retryable
        assert!(
            !SyscallError::PathOutsideWorkspace {
                path: PathBuf::new(),
                workspace: PathBuf::new(),
            }
            .is_retryable()
        );

        assert!(
            !SyscallError::FileNotFound {
                path: PathBuf::new(),
            }
            .is_retryable()
        );
    }
}
