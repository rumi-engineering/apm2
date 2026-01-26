//! Atomic file write operations for crash-safe updates.
//!
//! This module provides an atomic write function that ensures files are either
//! fully written or not modified at all. This is critical for configuration
//! files and other important data that must not be corrupted by crashes or
//! power loss.
//!
//! # Safety Guarantees
//!
//! The atomic write operation:
//! 1. Writes content to a temporary file in the same directory
//! 2. Calls fsync on the temporary file to ensure data is on disk
//! 3. Calls fsync on the parent directory (required on some filesystems)
//! 4. Atomically renames the temporary file to the target path
//! 5. Cleans up the temporary file on any error
//!
//! This ensures that even in the case of a crash or power loss, the target
//! file will either contain the complete old content or the complete new
//! content, never partial data.
//!
//! # Example
//!
//! ```no_run
//! use std::path::Path;
//!
//! use apm2_core::determinism::write_atomic;
//!
//! let content = b"important configuration data";
//! write_atomic(Path::new("/etc/app/config.yaml"), content).unwrap();
//! ```

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;

use thiserror::Error;

/// Errors that can occur during atomic write operations.
#[derive(Debug, Error)]
pub enum AtomicWriteError {
    /// Failed to create the temporary file.
    #[error("failed to create temporary file: {0}")]
    TempFileCreation(#[source] io::Error),

    /// Failed to write content to the temporary file.
    #[error("failed to write content: {0}")]
    WriteContent(#[source] io::Error),

    /// Failed to sync the temporary file to disk.
    #[error("failed to sync file to disk: {0}")]
    FileSync(#[source] io::Error),

    /// Failed to sync the parent directory.
    #[error("failed to sync parent directory: {0}")]
    DirSync(#[source] io::Error),

    /// Failed to rename the temporary file to the target path.
    #[error("failed to rename temporary file to target: {0}")]
    Rename(#[source] io::Error),

    /// The target path has no parent directory.
    #[error("target path has no parent directory")]
    NoParentDirectory,

    /// Failed to clean up the temporary file after an error.
    #[error(
        "failed to clean up temporary file after error: {cleanup_error}, original error: {original_error}"
    )]
    CleanupFailed {
        /// The original error that caused the cleanup.
        original_error: Box<Self>,
        /// The error that occurred during cleanup.
        cleanup_error: io::Error,
    },
}

/// Atomically writes content to a file.
///
/// This function ensures that the target file is either fully written or not
/// modified at all, even in the case of crashes or power loss.
///
/// # Arguments
///
/// * `path` - The target file path
/// * `content` - The content to write
///
/// # Errors
///
/// Returns an error if:
/// - The parent directory doesn't exist
/// - The temporary file cannot be created
/// - Writing or syncing fails
/// - The atomic rename fails
///
/// # Safety
///
/// The temporary file is created in the same directory as the target to ensure
/// the rename operation is atomic (same filesystem).
pub fn write_atomic(path: &Path, content: &[u8]) -> Result<(), AtomicWriteError> {
    let parent = path.parent().ok_or(AtomicWriteError::NoParentDirectory)?;

    // Create temp file in the same directory for atomic rename
    let temp_file = tempfile::Builder::new()
        .prefix(".tmp_atomic_")
        .suffix(".tmp")
        .tempfile_in(parent)
        .map_err(AtomicWriteError::TempFileCreation)?;

    let temp_path = temp_file.path().to_path_buf();

    // Write content to temp file
    let result = write_and_sync(&temp_file, content, parent);

    match result {
        Ok(()) => {
            // Persist the temp file (prevents auto-deletion) and rename atomically
            match temp_file.persist(path) {
                Ok(_) => Ok(()),
                Err(e) => Err(AtomicWriteError::Rename(e.error)),
            }
        },
        Err(e) => {
            // temp_file will be automatically cleaned up when dropped
            // But we need to ensure cleanup happens by explicitly dropping
            drop(temp_file);

            // Try to remove the temp file if it still exists
            if temp_path.exists() {
                if let Err(cleanup_err) = std::fs::remove_file(&temp_path) {
                    return Err(AtomicWriteError::CleanupFailed {
                        original_error: Box::new(e),
                        cleanup_error: cleanup_err,
                    });
                }
            }
            Err(e)
        },
    }
}

/// Writes content to a file and syncs both the file and parent directory.
fn write_and_sync(
    temp_file: &tempfile::NamedTempFile,
    content: &[u8],
    parent: &Path,
) -> Result<(), AtomicWriteError> {
    // Get a reference to the file
    let file = temp_file.as_file();

    // Write all content
    write_all_to_file(file, content)?;

    // Sync file to disk
    file.sync_all().map_err(AtomicWriteError::FileSync)?;

    // Sync parent directory (required on some filesystems like ext4)
    sync_directory(parent)?;

    Ok(())
}

/// Writes all content to a file, handling partial writes.
fn write_all_to_file(mut file: &File, content: &[u8]) -> Result<(), AtomicWriteError> {
    file.write_all(content)
        .map_err(AtomicWriteError::WriteContent)
}

/// Syncs a directory to disk.
#[cfg(unix)]
fn sync_directory(dir: &Path) -> Result<(), AtomicWriteError> {
    let dir_file = OpenOptions::new()
        .read(true)
        .open(dir)
        .map_err(AtomicWriteError::DirSync)?;
    dir_file.sync_all().map_err(AtomicWriteError::DirSync)
}

#[cfg(not(unix))]
fn sync_directory(_dir: &Path) -> Result<(), AtomicWriteError> {
    // On Windows, directory sync is not required for atomic rename
    Ok(())
}

#[cfg(test)]
pub mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::*;

    #[test]
    pub fn test_atomic_write_complete() {
        let temp_dir = TempDir::new().unwrap();
        let target_path = temp_dir.path().join("test_file.yaml");

        let content = b"key: value\nnested:\n  inner: data\n";
        write_atomic(&target_path, content).unwrap();

        // Verify file was written correctly
        let read_content = fs::read(&target_path).unwrap();
        assert_eq!(read_content, content);
    }

    #[test]
    fn test_atomic_write_overwrites_existing() {
        let temp_dir = TempDir::new().unwrap();
        let target_path = temp_dir.path().join("existing_file.yaml");

        // Write initial content
        fs::write(&target_path, b"old content").unwrap();

        // Atomically overwrite
        let new_content = b"new content";
        write_atomic(&target_path, new_content).unwrap();

        // Verify new content
        let read_content = fs::read(&target_path).unwrap();
        assert_eq!(read_content, new_content);
    }

    #[test]
    fn test_atomic_write_creates_new_file() {
        let temp_dir = TempDir::new().unwrap();
        let target_path = temp_dir.path().join("subdir").join("new_file.yaml");

        // Create parent directory
        fs::create_dir_all(target_path.parent().unwrap()).unwrap();

        let content = b"brand new content";
        write_atomic(&target_path, content).unwrap();

        assert!(target_path.exists());
        let read_content = fs::read(&target_path).unwrap();
        assert_eq!(read_content, content);
    }

    #[test]
    fn test_atomic_write_empty_content() {
        let temp_dir = TempDir::new().unwrap();
        let target_path = temp_dir.path().join("empty_file.yaml");

        write_atomic(&target_path, b"").unwrap();

        let read_content = fs::read(&target_path).unwrap();
        assert!(read_content.is_empty());
    }

    #[test]
    fn test_atomic_write_large_content() {
        let temp_dir = TempDir::new().unwrap();
        let target_path = temp_dir.path().join("large_file.yaml");

        // 1MB of content
        #[allow(clippy::cast_possible_truncation)]
        let content: Vec<u8> = (0u32..1_000_000).map(|i| (i % 256) as u8).collect();
        write_atomic(&target_path, &content).unwrap();

        let read_content = fs::read(&target_path).unwrap();
        assert_eq!(read_content, content);
    }

    #[test]
    fn test_atomic_write_preserves_on_error() {
        let temp_dir = TempDir::new().unwrap();
        let target_path = temp_dir.path().join("preserved.yaml");

        // Write initial content
        let original = b"original content that should be preserved";
        fs::write(&target_path, original).unwrap();

        // Try to write to a non-existent directory (should fail)
        let bad_path = temp_dir.path().join("nonexistent").join("file.yaml");
        let result = write_atomic(&bad_path, b"new content");
        assert!(result.is_err());

        // Original file should be unchanged
        let preserved = fs::read(&target_path).unwrap();
        assert_eq!(preserved, original);
    }

    #[test]
    pub fn test_atomic_write_cleanup_on_error() {
        let temp_dir = TempDir::new().unwrap();

        // Try to write to a path with no parent
        let bad_path = Path::new("/nonexistent_root_dir_12345/file.yaml");
        let result = write_atomic(bad_path, b"content");

        assert!(result.is_err());

        // Verify no temp files are left behind in the temp directory
        let has_temp_files = fs::read_dir(temp_dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .any(|e| e.file_name().to_string_lossy().starts_with(".tmp_atomic_"));

        assert!(!has_temp_files, "Temp files should be cleaned up on error");
    }

    #[test]
    fn test_atomic_write_no_parent_directory() {
        // Writing to a root path should fail (no parent to write temp file)
        let root_path = if cfg!(windows) {
            Path::new("C:\\")
        } else {
            Path::new("/")
        };

        let result = write_atomic(root_path, b"content");
        assert!(result.is_err());
    }

    #[test]
    fn test_atomic_write_binary_content() {
        let temp_dir = TempDir::new().unwrap();
        let target_path = temp_dir.path().join("binary.dat");

        // Binary content with null bytes and all byte values
        let content: Vec<u8> = (0..=255).collect();
        write_atomic(&target_path, &content).unwrap();

        let read_content = fs::read(&target_path).unwrap();
        assert_eq!(read_content, content);
    }

    #[test]
    fn test_atomic_write_unicode_path() {
        let temp_dir = TempDir::new().unwrap();
        let target_path = temp_dir.path().join("unicode_\u{1F600}_file.yaml");

        let content = b"content in unicode-named file";
        write_atomic(&target_path, content).unwrap();

        let read_content = fs::read(&target_path).unwrap();
        assert_eq!(read_content, content);
    }
}
