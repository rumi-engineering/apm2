//! Filesystem watcher for detecting file changes.
//!
//! This module provides a polling-based filesystem watcher that monitors
//! directories for changes and emits normalized events. It uses polling
//! to avoid external dependencies and ensure deterministic behavior.
//!
//! # Design
//!
//! The watcher uses a poll-based approach rather than inotify/FSEvents for:
//! - Deterministic testing (no race conditions with OS events)
//! - Cross-platform consistency
//! - Simpler state management
//!
//! For production use with many files, consider using inotify on Linux or
//! `FSEvents` on macOS via the `notify` crate.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use tokio::sync::mpsc;

use super::config::FilesystemConfig;
use super::error::AdapterError;
use super::event::{FileChangeType, FilesystemChange};

/// A snapshot of file metadata for change detection.
#[derive(Debug, Clone, PartialEq, Eq)]
struct FileSnapshot {
    /// Last modification time.
    modified: SystemTime,
    /// File size in bytes.
    size: u64,
    /// Whether this is a directory.
    is_dir: bool,
}

/// Filesystem watcher that detects changes via polling.
#[derive(Debug)]
pub struct FilesystemWatcher {
    /// Configuration for the watcher.
    config: FilesystemConfig,

    /// Current snapshot of file states.
    snapshots: BTreeMap<PathBuf, FileSnapshot>,

    /// Whether the watcher is running.
    running: bool,
}

impl FilesystemWatcher {
    /// Creates a new filesystem watcher with the given configuration.
    #[must_use]
    pub const fn new(config: FilesystemConfig) -> Self {
        Self {
            config,
            snapshots: BTreeMap::new(),
            running: false,
        }
    }

    /// Initializes the watcher by taking an initial snapshot.
    ///
    /// This should be called before starting to poll for changes.
    ///
    /// # Errors
    ///
    /// Returns an error if any watched path cannot be accessed.
    pub fn initialize(&mut self) -> Result<(), AdapterError> {
        self.snapshots.clear();

        for path in &self.config.watch_paths.clone() {
            self.scan_path(path)?;
        }

        self.running = true;
        Ok(())
    }

    /// Scans a path and adds its contents to the snapshot.
    fn scan_path(&mut self, path: &Path) -> Result<(), AdapterError> {
        if !path.exists() {
            return Ok(());
        }

        if path.is_file() {
            self.add_file_snapshot(path)?;
        } else if path.is_dir() {
            self.scan_directory(path)?;
        }

        Ok(())
    }

    /// Scans a directory and its contents.
    fn scan_directory(&mut self, dir: &Path) -> Result<(), AdapterError> {
        let entries = std::fs::read_dir(dir).map_err(|e| AdapterError::WatchPathFailed {
            path: dir.to_path_buf(),
            reason: e.to_string(),
        })?;

        for entry in entries {
            let entry = entry.map_err(|e| AdapterError::WatchPathFailed {
                path: dir.to_path_buf(),
                reason: e.to_string(),
            })?;

            let path = entry.path();

            // Check if path matches ignore patterns
            if self.should_ignore(&path) {
                continue;
            }

            if path.is_file() {
                self.add_file_snapshot(&path)?;
            } else if path.is_dir() && self.config.recursive {
                self.scan_directory(&path)?;
            }
        }

        Ok(())
    }

    /// Adds a file snapshot to the state.
    ///
    /// Uses `symlink_metadata` to avoid following symlinks, preventing
    /// infinite recursion on symlink loops.
    fn add_file_snapshot(&mut self, path: &Path) -> Result<(), AdapterError> {
        // Use symlink_metadata to avoid following symlinks (security: prevent loops)
        let metadata =
            std::fs::symlink_metadata(path).map_err(|e| AdapterError::WatchPathFailed {
                path: path.to_path_buf(),
                reason: e.to_string(),
            })?;

        // Skip symlinks entirely to prevent symlink-based attacks
        if metadata.file_type().is_symlink() {
            return Ok(());
        }

        let snapshot = FileSnapshot {
            modified: metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH),
            size: metadata.len(),
            is_dir: metadata.is_dir(),
        };

        self.snapshots.insert(path.to_path_buf(), snapshot);
        Ok(())
    }

    /// Checks if a path should be ignored based on configured patterns.
    fn should_ignore(&self, path: &Path) -> bool {
        let path_str = path.to_string_lossy();

        for pattern in &self.config.ignore_patterns {
            // Simple glob matching (handles common cases)
            if Self::matches_glob(pattern, &path_str) {
                return true;
            }
        }

        false
    }

    /// Simple glob pattern matching.
    ///
    /// Supports:
    /// - `*` matches any characters except path separator
    /// - `**` matches any characters including path separator
    ///
    /// Note: This is a simplified implementation. For production use with
    /// complex patterns, consider the `glob` or `globset` crates.
    fn matches_glob(pattern: &str, path: &str) -> bool {
        // Handle ** patterns (e.g., ".git/**", "node_modules/**")
        if pattern.contains("**") {
            let parts: Vec<&str> = pattern.split("**").collect();
            if parts.len() == 2 {
                let prefix = parts[0].trim_end_matches('/');
                if prefix.is_empty() {
                    return true; // "**" matches everything
                }
                // Check for path segment boundary: must match /prefix/ or /prefix at end
                // or be at the start of the path
                let with_leading = format!("/{prefix}/");
                let at_end = format!("/{prefix}");
                let at_start = format!("{prefix}/");
                return path.contains(&with_leading)
                    || path.ends_with(&at_end)
                    || path.starts_with(&at_start)
                    || path == prefix;
            }
        }

        // Handle extension patterns (e.g., "*.swp", "*~")
        if let Some(ext_pattern) = pattern.strip_prefix("*.") {
            if let Some(ext) = path.rsplit('.').next() {
                return ext == ext_pattern;
            }
        }

        // Handle single * suffix (e.g., "*~")
        if let Some(suffix) = pattern.strip_prefix('*') {
            return path.ends_with(suffix);
        }

        false
    }

    /// Polls for changes and returns detected filesystem changes.
    ///
    /// This compares the current filesystem state against the stored
    /// snapshot and returns any differences.
    ///
    /// # Errors
    ///
    /// Returns an error if filesystem operations fail.
    pub fn poll(&mut self) -> Result<Vec<FilesystemChange>, AdapterError> {
        if !self.running {
            return Ok(Vec::new());
        }

        let mut changes = Vec::new();
        let mut new_snapshots = BTreeMap::new();

        // Scan current state
        for path in &self.config.watch_paths.clone() {
            self.collect_current_state(path, &mut new_snapshots)?;
        }

        // Detect created and modified files
        for (path, new_snapshot) in &new_snapshots {
            if let Some(old_snapshot) = self.snapshots.get(path) {
                // File exists in both snapshots - check for modification
                if new_snapshot != old_snapshot {
                    changes.push(FilesystemChange {
                        path: path.clone(),
                        change_type: FileChangeType::Modified,
                        size_bytes: Some(new_snapshot.size),
                    });
                }
            } else {
                // File is new
                changes.push(FilesystemChange {
                    path: path.clone(),
                    change_type: FileChangeType::Created,
                    size_bytes: Some(new_snapshot.size),
                });
            }
        }

        // Detect deleted files
        for path in self.snapshots.keys() {
            if !new_snapshots.contains_key(path) {
                changes.push(FilesystemChange {
                    path: path.clone(),
                    change_type: FileChangeType::Deleted,
                    size_bytes: None,
                });
            }
        }

        // Update snapshot
        self.snapshots = new_snapshots;

        Ok(changes)
    }

    /// Collects the current state of files into the given map.
    ///
    /// Uses `symlink_metadata` to avoid following symlinks, preventing
    /// infinite recursion on symlink loops.
    fn collect_current_state(
        &self,
        path: &Path,
        snapshots: &mut BTreeMap<PathBuf, FileSnapshot>,
    ) -> Result<(), AdapterError> {
        // Use symlink_metadata to avoid following symlinks (security)
        let Ok(metadata) = std::fs::symlink_metadata(path) else {
            return Ok(()); // Path doesn't exist or is inaccessible
        };

        // Skip symlinks entirely to prevent symlink-based attacks
        if metadata.file_type().is_symlink() {
            return Ok(());
        }

        if metadata.is_file() {
            if !self.should_ignore(path) {
                let snapshot = FileSnapshot {
                    modified: metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH),
                    size: metadata.len(),
                    is_dir: false,
                };
                snapshots.insert(path.to_path_buf(), snapshot);
            }
        } else if metadata.is_dir() {
            if let Ok(entries) = std::fs::read_dir(path) {
                for entry in entries.flatten() {
                    let entry_path = entry.path();
                    if !self.should_ignore(&entry_path) {
                        // Get metadata for entry without following symlinks
                        if let Ok(entry_meta) = std::fs::symlink_metadata(&entry_path) {
                            // Skip symlinks
                            if entry_meta.file_type().is_symlink() {
                                continue;
                            }

                            if entry_meta.is_file() {
                                let snapshot = FileSnapshot {
                                    modified: entry_meta
                                        .modified()
                                        .unwrap_or(SystemTime::UNIX_EPOCH),
                                    size: entry_meta.len(),
                                    is_dir: false,
                                };
                                snapshots.insert(entry_path, snapshot);
                            } else if entry_meta.is_dir() && self.config.recursive {
                                self.collect_current_state(&entry_path, snapshots)?;
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Stops the watcher.
    pub const fn stop(&mut self) {
        self.running = false;
    }

    /// Returns whether the watcher is running.
    #[must_use]
    pub const fn is_running(&self) -> bool {
        self.running
    }

    /// Returns the number of files being watched.
    #[must_use]
    pub fn file_count(&self) -> usize {
        self.snapshots.len()
    }

    /// Returns the configured poll interval (debounce).
    #[must_use]
    pub const fn poll_interval(&self) -> Duration {
        self.config.debounce
    }
}

/// Handle for receiving filesystem events asynchronously.
#[derive(Debug)]
pub struct WatcherHandle {
    /// Receiver for filesystem changes.
    receiver: mpsc::Receiver<FilesystemChange>,
}

impl WatcherHandle {
    /// Creates a new watcher handle with the given receiver.
    #[must_use]
    pub const fn new(receiver: mpsc::Receiver<FilesystemChange>) -> Self {
        Self { receiver }
    }

    /// Receives the next filesystem change.
    ///
    /// Returns `None` if the channel is closed.
    pub async fn recv(&mut self) -> Option<FilesystemChange> {
        self.receiver.recv().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_watcher_creation() {
        let config = FilesystemConfig::default();
        let watcher = FilesystemWatcher::new(config);
        assert!(!watcher.is_running());
        assert_eq!(watcher.file_count(), 0);
    }

    #[test]
    fn test_glob_matching() {
        // Extension patterns
        assert!(FilesystemWatcher::matches_glob("*.swp", "file.swp"));
        assert!(!FilesystemWatcher::matches_glob("*.swp", "file.txt"));

        // Path patterns with **
        assert!(FilesystemWatcher::matches_glob(
            ".git/**",
            "/project/.git/objects"
        ));
        assert!(FilesystemWatcher::matches_glob(
            "node_modules/**",
            "/project/node_modules/lodash"
        ));
    }

    #[test]
    fn test_should_ignore() {
        let config = FilesystemConfig {
            ignore_patterns: vec!["*.swp".to_string(), ".git/**".to_string()],
            ..Default::default()
        };

        let watcher = FilesystemWatcher::new(config);

        assert!(watcher.should_ignore(Path::new("/tmp/file.swp")));
        assert!(watcher.should_ignore(Path::new("/project/.git/config")));
        assert!(!watcher.should_ignore(Path::new("/tmp/file.txt")));
    }

    #[test]
    fn test_watcher_initialization() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("test.txt");
        std::fs::write(&file_path, "content").unwrap();

        let config = FilesystemConfig {
            watch_paths: vec![dir.path().to_path_buf()],
            ignore_patterns: Vec::new(),
            ..Default::default()
        };

        let mut watcher = FilesystemWatcher::new(config);
        watcher.initialize().unwrap();

        assert!(watcher.is_running());
        assert!(watcher.file_count() > 0);
    }

    #[test]
    fn test_detect_file_creation() {
        let dir = tempfile::tempdir().unwrap();

        let config = FilesystemConfig {
            watch_paths: vec![dir.path().to_path_buf()],
            ignore_patterns: Vec::new(),
            ..Default::default()
        };

        let mut watcher = FilesystemWatcher::new(config);
        watcher.initialize().unwrap();

        // Create a new file
        let file_path = dir.path().join("new_file.txt");
        std::fs::write(&file_path, "new content").unwrap();

        // Poll for changes
        let changes = watcher.poll().unwrap();

        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].path, file_path);
        assert_eq!(changes[0].change_type, FileChangeType::Created);
    }

    #[test]
    fn test_detect_file_modification() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("test.txt");
        std::fs::write(&file_path, "initial content").unwrap();

        let config = FilesystemConfig {
            watch_paths: vec![dir.path().to_path_buf()],
            ignore_patterns: Vec::new(),
            ..Default::default()
        };

        let mut watcher = FilesystemWatcher::new(config);
        watcher.initialize().unwrap();

        // Modify the file
        std::fs::write(&file_path, "modified content that is longer").unwrap();

        // Poll for changes
        let changes = watcher.poll().unwrap();

        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].path, file_path);
        assert_eq!(changes[0].change_type, FileChangeType::Modified);
    }

    #[test]
    fn test_detect_file_deletion() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("to_delete.txt");
        std::fs::write(&file_path, "content").unwrap();

        let config = FilesystemConfig {
            watch_paths: vec![dir.path().to_path_buf()],
            ignore_patterns: Vec::new(),
            ..Default::default()
        };

        let mut watcher = FilesystemWatcher::new(config);
        watcher.initialize().unwrap();

        // Delete the file
        std::fs::remove_file(&file_path).unwrap();

        // Poll for changes
        let changes = watcher.poll().unwrap();

        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].path, file_path);
        assert_eq!(changes[0].change_type, FileChangeType::Deleted);
    }

    #[test]
    fn test_watcher_stop() {
        let config = FilesystemConfig {
            watch_paths: Vec::new(),
            ..Default::default()
        };

        let mut watcher = FilesystemWatcher::new(config);
        watcher.initialize().unwrap();
        assert!(watcher.is_running());

        watcher.stop();
        assert!(!watcher.is_running());

        // Polling should return empty when stopped
        let changes = watcher.poll().unwrap();
        assert!(changes.is_empty());
    }

    /// Security test: verify symlink loops don't cause infinite recursion.
    #[cfg(unix)]
    #[test]
    fn test_watcher_symlink_loop_protection() {
        use std::os::unix::fs::symlink;

        // Create a directory with a symlink loop: loop -> .
        let dir = tempfile::tempdir().unwrap();
        let loop_path = dir.path().join("loop");

        // ln -s . loop (creates a symlink that points to the same directory)
        symlink(dir.path(), &loop_path).unwrap();

        let config = FilesystemConfig {
            watch_paths: vec![dir.path().to_path_buf()],
            ignore_patterns: Vec::new(),
            ..Default::default()
        };

        let mut watcher = FilesystemWatcher::new(config);

        // This should not hang or crash - if it does, the test will timeout
        watcher.initialize().unwrap();
        let changes = watcher.poll().unwrap();

        // Should not detect the symlink itself as a file since we skip symlinks
        // The changes list should be empty (no real files, only the symlink)
        assert!(
            changes.is_empty(),
            "Should not report symlinks as file changes"
        );
    }
}
