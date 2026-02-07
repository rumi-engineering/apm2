//! Durable content-addressed storage (CAS) for evidence artifacts.
//!
//! This module provides a filesystem-based CAS that persists artifacts across
//! daemon restarts. Per TCK-00293 and RFC-0018, evidence artifacts must be
//! durable and content-addressed for FAC v0.
//!
//! # Architecture
//!
//! ```text
//! DurableCas
//!     ├── base_path: PathBuf (storage root)
//!     ├── max_artifact_size: usize (per-artifact limit)
//!     └── max_total_size: AtomicUsize (total storage limit)
//!
//! Storage Layout:
//!     {base_path}/
//!     ├── objects/
//!     │   ├── 01/
//!     │   │   └── 23456789abcdef...  (hash prefix sharding)
//!     │   ├── ab/
//!     │   │   └── cdef0123456789...
//!     │   └── ...
//!     └── metadata/
//!         └── total_size  (persistent size tracking)
//! ```
//!
//! # Security Properties
//!
//! - **Directory security**: CAS directories are created with mode 0700
//!   (owner-only access). The base path must be absolute, free of symlink
//!   components, and owned by the daemon UID. Existing directories are verified
//!   to have no group/other permissions (fail-closed).
//! - **Hash verification**: Content is verified against its BLAKE3 hash on both
//!   store and retrieve operations
//! - **Immutability**: Stored content cannot be modified; overwrite attempts
//!   are rejected
//! - **Size limits**: Per-artifact and total storage limits prevent resource
//!   exhaustion
//! - **Atomic writes**: Content is written to a temporary file and atomically
//!   renamed to prevent partial writes
//!
//! # Contract References
//!
//! - TCK-00293: Durable CAS backend + wiring
//! - RFC-0018: HEF requirements for evidence durability
//! - REQ-HEF-0009: `ChangeSetBundle` in CAS referenced by ledger

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use apm2_core::crypto::{EventHasher, HASH_SIZE, Hash};
use thiserror::Error;

// =============================================================================
// Constants
// =============================================================================

/// Maximum artifact size (100 MB) per TCK-00293.
pub const MAX_ARTIFACT_SIZE: usize = 100 * 1024 * 1024;

/// Default maximum total CAS size (10 GB).
pub const DEFAULT_MAX_TOTAL_SIZE: usize = 10 * 1024 * 1024 * 1024;

/// Minimum total CAS size (100 MB).
pub const MIN_TOTAL_SIZE: usize = 100 * 1024 * 1024;

/// Directory name for object storage.
const OBJECTS_DIR: &str = "objects";

/// Directory name for metadata storage.
const METADATA_DIR: &str = "metadata";

/// File name for total size tracking.
const TOTAL_SIZE_FILE: &str = "total_size";

// =============================================================================
// DurableCasError
// =============================================================================

/// Errors that can occur during durable CAS operations.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DurableCasError {
    /// Content not found for the given hash.
    #[error("content not found for hash: {hash}")]
    NotFound {
        /// The hash that was not found (hex-encoded).
        hash: String,
    },

    /// Hash mismatch between expected and actual content hash.
    #[error("hash mismatch: expected {expected}, got {actual}")]
    HashMismatch {
        /// The expected hash (hex-encoded).
        expected: String,
        /// The actual hash (hex-encoded).
        actual: String,
    },

    /// Content already exists (idempotent success, not an error condition).
    /// This variant is used internally to signal deduplication.
    #[error("content collision: hash {hash} already exists with different content")]
    Collision {
        /// The hash that collided (hex-encoded).
        hash: String,
    },

    /// Content exceeds maximum allowed size.
    #[error("content too large: {size} bytes exceeds maximum of {max_size} bytes")]
    ContentTooLarge {
        /// The actual size.
        size: usize,
        /// The maximum allowed size.
        max_size: usize,
    },

    /// Empty content is not allowed.
    #[error("empty content is not allowed")]
    EmptyContent,

    /// Invalid hash format.
    #[error("invalid hash: expected {expected} bytes, got {actual} bytes")]
    InvalidHash {
        /// The expected number of bytes.
        expected: usize,
        /// The actual number of bytes.
        actual: usize,
    },

    /// Total storage capacity exceeded.
    #[error(
        "storage full: total size {current_size} + {new_size} exceeds limit of {max_size} bytes"
    )]
    StorageFull {
        /// Current total size.
        current_size: usize,
        /// Size of new content.
        new_size: usize,
        /// Maximum allowed total size.
        max_size: usize,
    },

    /// I/O error during storage operation.
    #[error("I/O error: {context}: {source}")]
    Io {
        /// Description of what operation was being performed.
        context: String,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// Storage initialization failed.
    #[error("storage initialization failed: {message}")]
    InitializationFailed {
        /// Error message.
        message: String,
    },
}

impl DurableCasError {
    /// Returns the error kind as a string identifier.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::NotFound { .. } => "not_found",
            Self::HashMismatch { .. } => "hash_mismatch",
            Self::Collision { .. } => "collision",
            Self::ContentTooLarge { .. } => "content_too_large",
            Self::EmptyContent => "empty_content",
            Self::InvalidHash { .. } => "invalid_hash",
            Self::StorageFull { .. } => "storage_full",
            Self::Io { .. } => "io_error",
            Self::InitializationFailed { .. } => "init_failed",
        }
    }

    /// Returns `true` if this error is retriable.
    #[must_use]
    pub const fn is_retriable(&self) -> bool {
        matches!(self, Self::Io { .. })
    }

    /// Creates an I/O error with context.
    fn io(context: impl Into<String>, source: std::io::Error) -> Self {
        Self::Io {
            context: context.into(),
            source,
        }
    }
}

// =============================================================================
// StoreResult
// =============================================================================

/// Result of a store operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreResult {
    /// The content hash.
    pub hash: Hash,

    /// The size of the stored content in bytes.
    pub size: usize,

    /// Whether this was a new store (true) or deduplicated (false).
    pub is_new: bool,
}

// =============================================================================
// DurableCasConfig
// =============================================================================

/// Configuration for the durable CAS.
#[derive(Debug, Clone)]
pub struct DurableCasConfig {
    /// Base path for storage.
    pub base_path: PathBuf,

    /// Maximum size per artifact in bytes.
    pub max_artifact_size: usize,

    /// Maximum total storage size in bytes.
    pub max_total_size: usize,
}

impl DurableCasConfig {
    /// Creates a new configuration with the given base path.
    #[must_use]
    pub fn new(base_path: impl Into<PathBuf>) -> Self {
        Self {
            base_path: base_path.into(),
            max_artifact_size: MAX_ARTIFACT_SIZE,
            max_total_size: DEFAULT_MAX_TOTAL_SIZE,
        }
    }

    /// Sets the maximum artifact size.
    #[must_use]
    pub const fn with_max_artifact_size(mut self, size: usize) -> Self {
        self.max_artifact_size = size;
        self
    }

    /// Sets the maximum total storage size.
    #[must_use]
    pub const fn with_max_total_size(mut self, size: usize) -> Self {
        self.max_total_size = size;
        self
    }
}

// =============================================================================
// DurableCas
// =============================================================================

/// Durable filesystem-based content-addressed store.
///
/// This implementation persists artifacts to the filesystem using a hash-prefix
/// sharded directory structure. Artifacts are stored immutably and verified on
/// both store and retrieve operations.
///
/// # Thread Safety
///
/// `DurableCas` is `Send + Sync` and uses atomic operations for size tracking.
/// File system operations use atomic rename for safe concurrent access.
#[derive(Debug)]
pub struct DurableCas {
    /// Base path for storage.
    base_path: PathBuf,

    /// Path to objects directory.
    objects_path: PathBuf,

    /// Path to metadata directory.
    metadata_path: PathBuf,

    /// Maximum artifact size.
    max_artifact_size: usize,

    /// Maximum total storage size.
    max_total_size: usize,

    /// Current total size (atomic for thread safety).
    current_total_size: AtomicUsize,
}

impl DurableCas {
    /// Creates a new durable CAS with the given configuration.
    ///
    /// This will create the necessary directory structure if it doesn't exist
    /// and recover the total size from persistent storage.
    ///
    /// # Security
    ///
    /// The `base_path` is validated to enforce the following invariants:
    /// - **Absolute path**: The path must be absolute (no relative paths that
    ///   could resolve unexpectedly).
    /// - **No symlinks**: No component of the path may be a symbolic link,
    ///   preventing symlink redirection attacks.
    /// - **Owner match**: If the path exists, it must be owned by the current
    ///   effective UID (daemon UID).
    /// - **Mode 0700**: Directories are created with mode 0700 (owner-only
    ///   access). Existing directories are verified to have permissions no more
    ///   permissive than 0700.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `base_path` is not absolute
    /// - `base_path` contains symlink components
    /// - Existing directories are not owned by the daemon UID
    /// - Existing directories have permissions more permissive than 0700
    /// - Directory creation fails
    /// - Total size recovery fails
    pub fn new(config: DurableCasConfig) -> Result<Self, DurableCasError> {
        // SEC-CAS-001: Validate base_path is absolute
        if !config.base_path.is_absolute() {
            return Err(DurableCasError::InitializationFailed {
                message: format!(
                    "CAS base_path must be absolute, got: {}",
                    config.base_path.display()
                ),
            });
        }

        // SEC-CAS-002: Validate no symlink components in the path
        // Check each existing ancestor for symlinks to prevent redirection.
        validate_no_symlinks(&config.base_path)?;

        // SEC-CAS-003: If the base directory exists, verify ownership and
        // permissions
        if config.base_path.exists() {
            verify_directory_security(&config.base_path)?;
        }

        let objects_path = config.base_path.join(OBJECTS_DIR);
        let metadata_path = config.base_path.join(METADATA_DIR);

        // Create directory structure with mode 0700 (owner-only access)
        create_dir_secure(&config.base_path)?;
        create_dir_secure(&objects_path)?;
        create_dir_secure(&metadata_path)?;

        // Verify permissions on all directories after creation (defense-in-depth)
        for dir in [&config.base_path, &objects_path, &metadata_path] {
            verify_directory_security(dir)?;
        }

        let cas = Self {
            base_path: config.base_path,
            objects_path,
            metadata_path,
            max_artifact_size: config.max_artifact_size,
            max_total_size: config.max_total_size,
            current_total_size: AtomicUsize::new(0),
        };

        // Recover total size from persistent storage or recalculate
        cas.recover_total_size()?;

        Ok(cas)
    }

    /// Returns the base path of the CAS.
    #[must_use]
    pub fn base_path(&self) -> &Path {
        &self.base_path
    }

    /// Returns the current total size of stored content.
    #[must_use]
    pub fn total_size(&self) -> usize {
        self.current_total_size.load(Ordering::Relaxed)
    }

    /// Returns the maximum total size allowed.
    #[must_use]
    pub const fn max_total_size(&self) -> usize {
        self.max_total_size
    }

    /// Stores content and returns its hash.
    ///
    /// If content with the same hash already exists, this is a no-op and
    /// returns the existing hash (deduplication).
    ///
    /// # Errors
    ///
    /// - [`DurableCasError::EmptyContent`] if content is empty
    /// - [`DurableCasError::ContentTooLarge`] if content exceeds size limit
    /// - [`DurableCasError::StorageFull`] if total storage limit exceeded
    /// - [`DurableCasError::Collision`] if hash collision detected (should
    ///   never happen)
    /// - [`DurableCasError::Io`] if filesystem operations fail
    pub fn store(&self, content: &[u8]) -> Result<StoreResult, DurableCasError> {
        // Validate content
        if content.is_empty() {
            return Err(DurableCasError::EmptyContent);
        }
        if content.len() > self.max_artifact_size {
            return Err(DurableCasError::ContentTooLarge {
                size: content.len(),
                max_size: self.max_artifact_size,
            });
        }

        // Compute hash
        let hash = EventHasher::hash_content(content);
        let size = content.len();

        // Get storage path
        let (dir_path, file_path) = self.hash_to_paths(&hash);

        // Check if already exists (deduplication) — BEFORE reserving quota
        // so that duplicates never consume quota.
        if file_path.exists() {
            // Verify existing content matches (collision detection)
            let existing = self.read_file(&file_path)?;
            if existing != content {
                return Err(DurableCasError::Collision {
                    hash: hex_encode(&hash),
                });
            }
            return Ok(StoreResult {
                hash,
                size,
                is_new: false,
            });
        }

        // Atomically reserve quota using compare_exchange loop.
        // This prevents the TOCTOU race where two concurrent stores could
        // both pass a non-atomic size check and exceed max_total_size.
        let mut current = self.current_total_size.load(Ordering::Relaxed);
        loop {
            let new_total = current.saturating_add(size);
            if new_total > self.max_total_size {
                return Err(DurableCasError::StorageFull {
                    current_size: current,
                    new_size: size,
                    max_size: self.max_total_size,
                });
            }
            match self.current_total_size.compare_exchange_weak(
                current,
                new_total,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(actual) => current = actual,
            }
        }

        // From this point on, quota is reserved. Any failure must roll back
        // via fetch_sub before returning an error.

        // Create shard directory if needed (with 0700 permissions)
        if let Err(e) = create_dir_secure(&dir_path) {
            self.current_total_size.fetch_sub(size, Ordering::AcqRel);
            return Err(e);
        }

        // Write atomically via temp file + rename.
        // The temp path is deterministic (hash + ".tmp"), so concurrent stores
        // of the same content hash will collide.  When write or rename fails we
        // check whether a concurrent winner already placed the final file; if
        // its content matches, we treat this as a successful dedup.
        let temp_path = file_path.with_extension("tmp");
        if let Err(e) = self.write_file(&temp_path, content) {
            // A concurrent writer may have already completed the full
            // write-then-rename cycle.  If the final file exists with the
            // correct content, this is a benign duplicate — roll back quota
            // and return success.
            if self.concurrent_winner_exists(&file_path, &hash)? {
                self.current_total_size.fetch_sub(size, Ordering::AcqRel);
                return Ok(StoreResult {
                    hash,
                    size,
                    is_new: false,
                });
            }
            self.current_total_size.fetch_sub(size, Ordering::AcqRel);
            return Err(e);
        }

        // Atomic rename
        if let Err(e) = fs::rename(&temp_path, &file_path) {
            // Clean up temp file on failure
            let _ = fs::remove_file(&temp_path);
            // Same concurrent-winner check: the rename may have failed because
            // another thread already placed the file via its own rename.
            if self.concurrent_winner_exists(&file_path, &hash)? {
                self.current_total_size.fetch_sub(size, Ordering::AcqRel);
                return Ok(StoreResult {
                    hash,
                    size,
                    is_new: false,
                });
            }
            self.current_total_size.fetch_sub(size, Ordering::AcqRel);
            return Err(DurableCasError::io(
                format!("rename {} to {}", temp_path.display(), file_path.display()),
                e,
            ));
        }

        // Quota was already reserved atomically; persist the new total.
        self.persist_total_size()?;

        Ok(StoreResult {
            hash,
            size,
            is_new: true,
        })
    }

    /// Retrieves content by hash.
    ///
    /// The returned content is verified against the hash before returning.
    ///
    /// # Errors
    ///
    /// - [`DurableCasError::NotFound`] if content is not found
    /// - [`DurableCasError::HashMismatch`] if stored content doesn't match hash
    ///   (indicates corruption)
    /// - [`DurableCasError::Io`] if filesystem operations fail
    pub fn retrieve(&self, hash: &Hash) -> Result<Vec<u8>, DurableCasError> {
        let (_, file_path) = self.hash_to_paths(hash);

        if !file_path.exists() {
            return Err(DurableCasError::NotFound {
                hash: hex_encode(hash),
            });
        }

        let content = self.read_file(&file_path)?;

        // Verify content integrity
        let actual_hash = EventHasher::hash_content(&content);
        if actual_hash != *hash {
            return Err(DurableCasError::HashMismatch {
                expected: hex_encode(hash),
                actual: hex_encode(&actual_hash),
            });
        }

        Ok(content)
    }

    /// Checks if content with the given hash exists.
    #[must_use]
    pub fn exists(&self, hash: &Hash) -> bool {
        let (_, file_path) = self.hash_to_paths(hash);
        file_path.exists()
    }

    /// Returns the size of content with the given hash, without retrieving it.
    ///
    /// # Errors
    ///
    /// - [`DurableCasError::NotFound`] if content is not found
    /// - [`DurableCasError::Io`] if filesystem operations fail
    pub fn size(&self, hash: &Hash) -> Result<usize, DurableCasError> {
        let (_, file_path) = self.hash_to_paths(hash);

        if !file_path.exists() {
            return Err(DurableCasError::NotFound {
                hash: hex_encode(hash),
            });
        }

        let metadata = fs::metadata(&file_path)
            .map_err(|e| DurableCasError::io(format!("stat {}", file_path.display()), e))?;

        #[allow(clippy::cast_possible_truncation)]
        Ok(metadata.len() as usize)
    }

    /// Verifies that content matches the expected hash.
    ///
    /// # Errors
    ///
    /// - [`DurableCasError::HashMismatch`] if content doesn't match expected
    ///   hash
    pub fn verify(&self, content: &[u8], expected_hash: &Hash) -> Result<(), DurableCasError> {
        let actual_hash = EventHasher::hash_content(content);
        if actual_hash != *expected_hash {
            return Err(DurableCasError::HashMismatch {
                expected: hex_encode(expected_hash),
                actual: hex_encode(&actual_hash),
            });
        }
        Ok(())
    }

    /// Converts a hash to directory and file paths.
    ///
    /// Uses first 2 bytes (4 hex chars) as shard prefix for better
    /// distribution.
    fn hash_to_paths(&self, hash: &Hash) -> (PathBuf, PathBuf) {
        let hex = hex_encode(hash);
        let (prefix, suffix) = hex.split_at(4);
        let dir_path = self.objects_path.join(prefix);
        let file_path = dir_path.join(suffix);
        (dir_path, file_path)
    }

    /// Checks whether a concurrent writer already placed the final CAS file
    /// at `file_path` with content matching `expected_hash`.
    ///
    /// This is used after a write or rename failure to distinguish a genuine
    /// I/O error from a benign concurrent-duplicate race.
    fn concurrent_winner_exists(
        &self,
        file_path: &Path,
        expected_hash: &Hash,
    ) -> Result<bool, DurableCasError> {
        if !file_path.exists() {
            return Ok(false);
        }
        let existing = self.read_file(file_path)?;
        let actual_hash = EventHasher::hash_content(&existing);
        Ok(actual_hash == *expected_hash)
    }

    /// Reads a file's contents.
    #[allow(clippy::unused_self)]
    fn read_file(&self, path: &Path) -> Result<Vec<u8>, DurableCasError> {
        let mut file = File::open(path)
            .map_err(|e| DurableCasError::io(format!("open {}", path.display()), e))?;
        let mut content = Vec::new();
        file.read_to_end(&mut content)
            .map_err(|e| DurableCasError::io(format!("read {}", path.display()), e))?;
        Ok(content)
    }

    /// Writes content to a file.
    #[allow(clippy::unused_self)]
    fn write_file(&self, path: &Path, content: &[u8]) -> Result<(), DurableCasError> {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
            .map_err(|e| DurableCasError::io(format!("create {}", path.display()), e))?;

        file.write_all(content)
            .map_err(|e| DurableCasError::io(format!("write {}", path.display()), e))?;

        file.sync_all()
            .map_err(|e| DurableCasError::io(format!("sync {}", path.display()), e))?;

        Ok(())
    }

    /// Recovers total size from persistent storage or recalculates it.
    fn recover_total_size(&self) -> Result<(), DurableCasError> {
        let size_file = self.metadata_path.join(TOTAL_SIZE_FILE);

        // Try to read persisted size
        if size_file.exists() {
            if let Ok(content) = fs::read_to_string(&size_file) {
                if let Ok(size) = content.trim().parse::<usize>() {
                    self.current_total_size.store(size, Ordering::Relaxed);
                    return Ok(());
                }
            }
        }

        // Recalculate from filesystem
        let total = self.calculate_total_size()?;
        self.current_total_size.store(total, Ordering::Relaxed);
        self.persist_total_size()?;

        Ok(())
    }

    /// Calculates total size by walking the objects directory.
    fn calculate_total_size(&self) -> Result<usize, DurableCasError> {
        let mut total: usize = 0;

        if !self.objects_path.exists() {
            return Ok(0);
        }

        let entries = fs::read_dir(&self.objects_path)
            .map_err(|e| DurableCasError::io("read objects directory", e))?;

        for entry in entries {
            let entry =
                entry.map_err(|e| DurableCasError::io("read objects directory entry", e))?;
            let path = entry.path();

            if path.is_dir() {
                let subentries = fs::read_dir(&path).map_err(|e| {
                    DurableCasError::io(format!("read shard {}", path.display()), e)
                })?;

                for subentry in subentries {
                    let subentry = subentry.map_err(|e| {
                        DurableCasError::io(format!("read shard entry {}", path.display()), e)
                    })?;
                    let subpath = subentry.path();

                    if subpath.is_file() && subpath.extension().is_none_or(|ext| ext != "tmp") {
                        let metadata = fs::metadata(&subpath).map_err(|e| {
                            DurableCasError::io(format!("stat {}", subpath.display()), e)
                        })?;
                        #[allow(clippy::cast_possible_truncation)]
                        let file_size = metadata.len() as usize;
                        total = total.saturating_add(file_size);
                    }
                }
            }
        }

        Ok(total)
    }

    /// Persists the current total size to the metadata file.
    fn persist_total_size(&self) -> Result<(), DurableCasError> {
        let size_file = self.metadata_path.join(TOTAL_SIZE_FILE);
        let temp_file = size_file.with_extension("tmp");
        let size = self.current_total_size.load(Ordering::Relaxed);

        fs::write(&temp_file, size.to_string())
            .map_err(|e| DurableCasError::io("write total size temp file", e))?;

        fs::rename(&temp_file, &size_file)
            .map_err(|e| DurableCasError::io("rename total size file", e))?;

        Ok(())
    }
}

// =============================================================================
// ContentAddressedStore trait implementation
// =============================================================================

/// Trait for content-addressed storage operations (re-exported from executor).
///
/// This trait provides a unified interface for both in-memory and durable CAS
/// implementations.
impl crate::episode::executor::ContentAddressedStore for DurableCas {
    fn store(&self, content: &[u8]) -> crate::episode::Hash {
        Self::store(self, content).map_or_else(
            // For the trait interface, compute hash even on error
            // This matches StubContentAddressedStore behavior
            |_| EventHasher::hash_content(content),
            |result| result.hash,
        )
    }

    fn retrieve(&self, hash: &crate::episode::Hash) -> Option<Vec<u8>> {
        Self::retrieve(self, hash).ok()
    }

    fn contains(&self, hash: &crate::episode::Hash) -> bool {
        self.exists(hash)
    }
}

// =============================================================================
// Core ContentAddressedStore trait implementation (apm2_core::evidence)
// =============================================================================

/// Bridges `DurableCas` to the core CAS trait used by `apm2_core` types
/// (e.g., `AgentAdapterProfileV1::load_from_cas`).
///
/// This allows the same `DurableCas` instance to be shared with components
/// that require `apm2_core::evidence::ContentAddressedStore` (fallible API).
impl apm2_core::evidence::ContentAddressedStore for DurableCas {
    fn store(
        &self,
        content: &[u8],
    ) -> Result<apm2_core::evidence::StoreResult, apm2_core::evidence::CasError> {
        Self::store(self, content)
            .map(|r| apm2_core::evidence::StoreResult {
                hash: r.hash,
                size: r.size,
                is_new: r.is_new,
            })
            .map_err(durable_to_core_error)
    }

    fn retrieve(&self, hash: &Hash) -> Result<Vec<u8>, apm2_core::evidence::CasError> {
        Self::retrieve(self, hash).map_err(durable_to_core_error)
    }

    fn exists(&self, hash: &Hash) -> Result<bool, apm2_core::evidence::CasError> {
        Ok(Self::exists(self, hash))
    }

    fn size(&self, hash: &Hash) -> Result<usize, apm2_core::evidence::CasError> {
        Self::size(self, hash).map_err(durable_to_core_error)
    }
}

/// Maps `DurableCasError` to `apm2_core::evidence::CasError`.
fn durable_to_core_error(e: DurableCasError) -> apm2_core::evidence::CasError {
    match e {
        DurableCasError::NotFound { hash } => apm2_core::evidence::CasError::NotFound { hash },
        DurableCasError::HashMismatch { expected, actual } => {
            apm2_core::evidence::CasError::HashMismatch { expected, actual }
        },
        DurableCasError::Collision { hash } => apm2_core::evidence::CasError::Collision { hash },
        DurableCasError::ContentTooLarge { size, max_size } => {
            apm2_core::evidence::CasError::ContentTooLarge { size, max_size }
        },
        DurableCasError::EmptyContent => apm2_core::evidence::CasError::EmptyContent,
        DurableCasError::InvalidHash { expected, actual } => {
            apm2_core::evidence::CasError::InvalidHash { expected, actual }
        },
        DurableCasError::StorageFull {
            current_size,
            new_size,
            max_size,
        } => apm2_core::evidence::CasError::StorageFull {
            current_size,
            new_size,
            max_size,
        },
        DurableCasError::Io { context, source } => apm2_core::evidence::CasError::StorageError {
            message: format!("{context}: {source}"),
        },
        DurableCasError::InitializationFailed { message } => {
            apm2_core::evidence::CasError::StorageError { message }
        },
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Converts a hash to hex string.
fn hex_encode(hash: &Hash) -> String {
    use std::fmt::Write;
    hash.iter().fold(
        String::with_capacity(HASH_SIZE * 2),
        |mut acc: String, b| {
            let _ = write!(acc, "{b:02x}");
            acc
        },
    )
}

/// Creates a directory with mode 0700 if it does not already exist.
///
/// Uses `DirBuilderExt::mode()` to set owner-only permissions. If the
/// directory already exists, its permissions are not modified here (they
/// are verified separately by `verify_directory_security`).
fn create_dir_secure(path: &Path) -> Result<(), DurableCasError> {
    if path.exists() {
        return Ok(());
    }
    // Create parent directories recursively with 0700 mode
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true).mode(0o700);
    builder.create(path).map_err(|e| {
        DurableCasError::io(
            format!("create directory with mode 0700: {}", path.display()),
            e,
        )
    })
}

/// Validates that no component of the given path is a symbolic link.
///
/// This prevents symlink redirection attacks where an attacker creates a
/// symlink pointing to a sensitive directory.
fn validate_no_symlinks(path: &Path) -> Result<(), DurableCasError> {
    // SEC-CAS-002a: Reject `..` segments to prevent path traversal attacks.
    // Without this, paths like `missing/../link/cas_store` can bypass the
    // per-component symlink check because the `missing` component triggers
    // NotFound (skipped), then `..` climbs back up, so the cumulative path
    // never actually checks `link` as a symlink.
    //
    // Note: `Component::CurDir` (`.`) is already normalized away by
    // `Path::components()`, so only `ParentDir` needs explicit rejection.
    for component in path.components() {
        if matches!(component, Component::ParentDir) {
            return Err(DurableCasError::InitializationFailed {
                message: format!(
                    "CAS path must not contain '..' segments: {}",
                    path.display()
                ),
            });
        }
    }

    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component);
        // Use symlink_metadata() instead of exists() to detect dangling symlinks.
        // exists() returns false for dangling symlinks, which would bypass detection.
        match std::fs::symlink_metadata(&current) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    return Err(DurableCasError::InitializationFailed {
                        message: format!(
                            "CAS path contains symlink component: {}",
                            current.display()
                        ),
                    });
                }
            },
            // Component does not exist yet — that is fine, it will be created later.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {},
            // Any other I/O error: fail closed to avoid silent bypass.
            Err(e) => {
                return Err(DurableCasError::InitializationFailed {
                    message: format!(
                        "Cannot verify path component {} is not a symlink: {}",
                        current.display(),
                        e
                    ),
                });
            },
        }
    }
    Ok(())
}

/// Verifies that an existing directory has secure ownership and permissions.
///
/// # Security checks
///
/// - Owner must match the current effective UID (daemon UID)
/// - Permissions must not be more permissive than 0700 (no group/other access)
fn verify_directory_security(path: &Path) -> Result<(), DurableCasError> {
    // SEC-CAS-003: Use symlink_metadata instead of metadata to check the
    // actual entry rather than following symlinks. fs::metadata follows
    // symlinks, which would allow a symlink to masquerade as a directory.
    let metadata = fs::symlink_metadata(path)
        .map_err(|e| DurableCasError::io(format!("stat directory {}", path.display()), e))?;

    if !metadata.is_dir() {
        return Err(DurableCasError::InitializationFailed {
            message: format!("CAS path is not a directory: {}", path.display()),
        });
    }

    // SEC-CAS-003a: Verify owner matches daemon UID
    let dir_uid = metadata.uid();
    let daemon_uid = nix::unistd::geteuid().as_raw();
    if dir_uid != daemon_uid {
        return Err(DurableCasError::InitializationFailed {
            message: format!(
                "CAS directory {} is owned by UID {} but daemon runs as UID {}",
                path.display(),
                dir_uid,
                daemon_uid
            ),
        });
    }

    // SEC-CAS-003b: Verify permissions are not more permissive than 0700
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(DurableCasError::InitializationFailed {
            message: format!(
                "CAS directory {} has permissions {:04o} (expected 0700 or stricter)",
                path.display(),
                mode
            ),
        });
    }

    Ok(())
}

/// Converts a hex string to a hash.
///
/// # Errors
///
/// Returns `DurableCasError::InvalidHash` if the string is not a valid
/// hex-encoded hash.
#[allow(dead_code)]
pub fn hex_decode(s: &str) -> Result<Hash, DurableCasError> {
    if s.len() != HASH_SIZE * 2 {
        return Err(DurableCasError::InvalidHash {
            expected: HASH_SIZE,
            actual: s.len() / 2,
        });
    }

    let mut hash = [0u8; HASH_SIZE];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let high = hex_char_to_nibble(chunk[0]).ok_or(DurableCasError::InvalidHash {
            expected: HASH_SIZE,
            actual: 0,
        })?;
        let low = hex_char_to_nibble(chunk[1]).ok_or(DurableCasError::InvalidHash {
            expected: HASH_SIZE,
            actual: 0,
        })?;
        hash[i] = (high << 4) | low;
    }

    Ok(hash)
}

/// Converts a hex character to its nibble value.
const fn hex_char_to_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    fn create_test_cas() -> (DurableCas, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        // Use a subdirectory within the temp dir so DurableCas creates it
        // with 0700 permissions (the temp dir itself may have 0775).
        let cas_path = temp_dir.path().join("cas");
        let config = DurableCasConfig::new(&cas_path);
        let cas = DurableCas::new(config).unwrap();
        (cas, temp_dir)
    }

    #[test]
    fn test_store_and_retrieve() {
        let (cas, _temp_dir) = create_test_cas();
        let content = b"hello world";

        let result = cas.store(content).unwrap();
        assert!(result.is_new);
        assert_eq!(result.size, content.len());

        let retrieved = cas.retrieve(&result.hash).unwrap();
        assert_eq!(retrieved, content);
    }

    #[test]
    fn test_deduplication() {
        let (cas, _temp_dir) = create_test_cas();
        let content = b"duplicate content";

        let result1 = cas.store(content).unwrap();
        assert!(result1.is_new);

        let result2 = cas.store(content).unwrap();
        assert!(!result2.is_new);
        assert_eq!(result1.hash, result2.hash);
    }

    #[test]
    fn test_different_content_different_hash() {
        let (cas, _temp_dir) = create_test_cas();

        let result1 = cas.store(b"content 1").unwrap();
        let result2 = cas.store(b"content 2").unwrap();

        assert_ne!(result1.hash, result2.hash);
    }

    #[test]
    fn test_empty_content_rejected() {
        let (cas, _temp_dir) = create_test_cas();
        let result = cas.store(b"");
        assert!(matches!(result, Err(DurableCasError::EmptyContent)));
    }

    #[test]
    fn test_content_too_large() {
        let temp_dir = TempDir::new().unwrap();
        let config = DurableCasConfig::new(temp_dir.path().join("cas")).with_max_artifact_size(100);
        let cas = DurableCas::new(config).unwrap();

        let large_content = vec![0u8; 101];
        let result = cas.store(&large_content);
        assert!(matches!(
            result,
            Err(DurableCasError::ContentTooLarge { .. })
        ));
    }

    #[test]
    fn test_retrieve_not_found() {
        let (cas, _temp_dir) = create_test_cas();
        let fake_hash = [0u8; HASH_SIZE];
        let result = cas.retrieve(&fake_hash);
        assert!(matches!(result, Err(DurableCasError::NotFound { .. })));
    }

    #[test]
    fn test_exists() {
        let (cas, _temp_dir) = create_test_cas();
        let content = b"test content";

        let result = cas.store(content).unwrap();

        assert!(cas.exists(&result.hash));

        let fake_hash = [0u8; HASH_SIZE];
        assert!(!cas.exists(&fake_hash));
    }

    #[test]
    fn test_size() {
        let (cas, _temp_dir) = create_test_cas();
        let content = b"test content for size";

        let result = cas.store(content).unwrap();
        let size = cas.size(&result.hash).unwrap();
        assert_eq!(size, content.len());
    }

    #[test]
    fn test_verify() {
        let (cas, _temp_dir) = create_test_cas();
        let content = b"content to verify";
        let result = cas.store(content).unwrap();

        // Verification should pass for correct content
        assert!(cas.verify(content, &result.hash).is_ok());

        // Verification should fail for wrong content
        let wrong_content = b"wrong content";
        assert!(matches!(
            cas.verify(wrong_content, &result.hash),
            Err(DurableCasError::HashMismatch { .. })
        ));
    }

    #[test]
    fn test_total_size_tracking() {
        let (cas, _temp_dir) = create_test_cas();

        cas.store(b"12345").unwrap(); // 5 bytes
        cas.store(b"1234567890").unwrap(); // 10 bytes

        assert_eq!(cas.total_size(), 15);
    }

    #[test]
    fn test_storage_full() {
        let temp_dir = TempDir::new().unwrap();
        let config = DurableCasConfig::new(temp_dir.path().join("cas")).with_max_total_size(100);
        let cas = DurableCas::new(config).unwrap();

        // Fill storage
        cas.store(&[0u8; 50]).unwrap();
        cas.store(&[1u8; 40]).unwrap();

        // Should fail when exceeding limit
        let result = cas.store(&[2u8; 20]);
        assert!(matches!(result, Err(DurableCasError::StorageFull { .. })));
    }

    #[test]
    fn test_persistence_across_instances() {
        let temp_dir = TempDir::new().unwrap();
        let cas_path = temp_dir.path().join("cas");
        let content = b"persistent content";
        let hash;

        // First instance: store content
        {
            let config = DurableCasConfig::new(&cas_path);
            let cas = DurableCas::new(config).unwrap();
            let result = cas.store(content).unwrap();
            hash = result.hash;
            assert!(result.is_new);
        }

        // Second instance: retrieve content
        {
            let config = DurableCasConfig::new(&cas_path);
            let cas = DurableCas::new(config).unwrap();
            let retrieved = cas.retrieve(&hash).unwrap();
            assert_eq!(retrieved, content);

            // Store should detect duplicate
            let result = cas.store(content).unwrap();
            assert!(!result.is_new);
        }
    }

    #[test]
    fn test_total_size_persistence() {
        let temp_dir = TempDir::new().unwrap();
        let cas_path = temp_dir.path().join("cas");

        // First instance: store content
        {
            let config = DurableCasConfig::new(&cas_path);
            let cas = DurableCas::new(config).unwrap();
            cas.store(b"content 1").unwrap();
            cas.store(b"content 2").unwrap();
            assert!(cas.total_size() > 0);
        }

        // Second instance: verify size is recovered
        {
            let config = DurableCasConfig::new(&cas_path);
            let cas = DurableCas::new(config).unwrap();
            assert!(cas.total_size() > 0);
        }
    }

    #[test]
    fn test_deterministic_hash() {
        let (cas1, _temp_dir1) = create_test_cas();
        let (cas2, _temp_dir2) = create_test_cas();

        let content = b"deterministic content";
        let result1 = cas1.store(content).unwrap();
        let result2 = cas2.store(content).unwrap();

        assert_eq!(result1.hash, result2.hash);
    }

    #[test]
    fn test_hex_encode_decode_roundtrip() {
        let original: Hash = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
            0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67,
            0x89, 0xab, 0xcd, 0xef,
        ];

        let encoded = hex_encode(&original);
        let decoded = hex_decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    // =========================================================================
    // Security tests: CAS directory invariants
    // =========================================================================

    /// SEC-CAS-001: Reject relative paths for CAS `base_path`.
    #[test]
    fn test_reject_relative_path() {
        let config = DurableCasConfig::new("relative/cas/path");
        let result = DurableCas::new(config);
        assert!(
            matches!(result, Err(DurableCasError::InitializationFailed { .. })),
            "Expected InitializationFailed for relative path, got: {result:?}"
        );
        if let Err(DurableCasError::InitializationFailed { message }) = result {
            assert!(
                message.contains("absolute"),
                "Error should mention 'absolute': {message}"
            );
        }
    }

    /// SEC-CAS-002: Reject paths containing symlink components.
    #[test]
    fn test_reject_symlink_path() {
        let temp_dir = TempDir::new().unwrap();
        let real_dir = temp_dir.path().join("real_cas");
        fs::create_dir_all(&real_dir).unwrap();

        let symlink_path = temp_dir.path().join("symlink_cas");
        std::os::unix::fs::symlink(&real_dir, &symlink_path).unwrap();

        let config = DurableCasConfig::new(&symlink_path);
        let result = DurableCas::new(config);
        assert!(
            matches!(result, Err(DurableCasError::InitializationFailed { .. })),
            "Expected InitializationFailed for symlink path, got: {result:?}"
        );
        if let Err(DurableCasError::InitializationFailed { message }) = result {
            assert!(
                message.contains("symlink"),
                "Error should mention 'symlink': {message}"
            );
        }
    }

    /// SEC-CAS-002b: Reject paths containing dangling symlink components.
    ///
    /// A dangling symlink (target does not exist) must still be detected.
    /// Previously, `current.exists()` returned `false` for dangling symlinks,
    /// causing them to bypass detection.
    #[test]
    fn test_reject_dangling_symlink_path() {
        let temp_dir = TempDir::new().unwrap();

        // Create a symlink whose target does NOT exist (dangling).
        let dangling_symlink = temp_dir.path().join("dangling_link");
        std::os::unix::fs::symlink("/nonexistent/target", &dangling_symlink).unwrap();

        // Use the dangling symlink as a path component for the CAS base.
        let cas_path = dangling_symlink.join("cas_store");
        let config = DurableCasConfig::new(&cas_path);
        let result = DurableCas::new(config);
        assert!(
            matches!(result, Err(DurableCasError::InitializationFailed { .. })),
            "Expected InitializationFailed for dangling symlink path, got: {result:?}"
        );
        if let Err(DurableCasError::InitializationFailed { message }) = result {
            assert!(
                message.contains("symlink"),
                "Error should mention 'symlink': {message}"
            );
        }
    }

    /// SEC-CAS-003: Directories are created with mode 0700.
    #[test]
    fn test_directories_created_with_0700() {
        let temp_dir = TempDir::new().unwrap();
        let cas_path = temp_dir.path().join("secure_cas");

        let config = DurableCasConfig::new(&cas_path);
        let _cas = DurableCas::new(config).unwrap();

        // Verify base directory permissions
        let base_mode = fs::metadata(&cas_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            base_mode, 0o700,
            "Base directory should have mode 0700, got {base_mode:04o}",
        );

        // Verify objects directory permissions
        let objects_mode = fs::metadata(cas_path.join("objects"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            objects_mode, 0o700,
            "Objects directory should have mode 0700, got {objects_mode:04o}",
        );

        // Verify metadata directory permissions
        let metadata_mode = fs::metadata(cas_path.join("metadata"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            metadata_mode, 0o700,
            "Metadata directory should have mode 0700, got {metadata_mode:04o}",
        );
    }

    /// SEC-CAS-003b: Reject existing directories with group/other permissions.
    #[test]
    fn test_reject_permissive_existing_directory() {
        let temp_dir = TempDir::new().unwrap();
        let cas_path = temp_dir.path().join("permissive_cas");

        // Create directory with permissive mode (0755)
        fs::create_dir_all(&cas_path).unwrap();
        fs::set_permissions(&cas_path, fs::Permissions::from_mode(0o755)).unwrap();

        let config = DurableCasConfig::new(&cas_path);
        let result = DurableCas::new(config);
        assert!(
            matches!(result, Err(DurableCasError::InitializationFailed { .. })),
            "Expected InitializationFailed for permissive directory, got: {result:?}"
        );
        if let Err(DurableCasError::InitializationFailed { message }) = result {
            assert!(
                message.contains("permissions"),
                "Error should mention 'permissions': {message}"
            );
        }
    }

    /// SEC-CAS-002c: Regression test for `missing/../link/cas_store` path
    /// traversal bypass.
    ///
    /// Without dot-segment rejection, this path bypasses the symlink check
    /// because:
    /// 1. `missing` does not exist -> `NotFound` is silently skipped
    /// 2. `..` climbs back up, so the cumulative path never checks `link`
    #[test]
    fn test_reject_dot_dot_symlink_traversal() {
        let temp_dir = TempDir::new().unwrap();
        let base = temp_dir.path();

        // Create a real directory and a symlink to it
        let real_dir = base.join("real_target");
        fs::create_dir_all(&real_dir).unwrap();
        let link = base.join("link");
        std::os::unix::fs::symlink(&real_dir, &link).unwrap();

        // Construct a path that uses `missing/../link/cas_store` to bypass
        // the per-component symlink check
        let malicious_path = base
            .join("missing")
            .join("..")
            .join("link")
            .join("cas_store");

        let config = DurableCasConfig::new(&malicious_path);
        let result = DurableCas::new(config);
        assert!(
            matches!(result, Err(DurableCasError::InitializationFailed { .. })),
            "Expected InitializationFailed for dot-dot traversal path, got: {result:?}"
        );
        if let Err(DurableCasError::InitializationFailed { message }) = result {
            assert!(
                message.contains("..") || message.contains("dot"),
                "Error should mention dot segments: {message}"
            );
        }
    }

    /// SEC-CAS-002d: Reject paths containing `..` even without symlinks.
    ///
    /// Even if no symlink exists, `..` segments are dangerous because they
    /// could bypass the per-component check if a future parent directory
    /// is missing. Reject all `..` segments unconditionally.
    #[test]
    fn test_reject_parent_dir_segment() {
        let temp_dir = TempDir::new().unwrap();
        let path_with_dotdot = temp_dir.path().join("foo").join("..").join("cas_store");

        let config = DurableCasConfig::new(&path_with_dotdot);
        let result = DurableCas::new(config);
        assert!(
            matches!(result, Err(DurableCasError::InitializationFailed { .. })),
            "Expected InitializationFailed for '..' segment, got: {result:?}"
        );
    }

    /// SEC-CAS-004: Shard directories created during store also get 0700
    /// permissions.
    #[test]
    fn test_shard_directory_permissions() {
        let (cas, _temp_dir) = create_test_cas();
        let content = b"test shard perms";

        cas.store(content).unwrap();

        // Find the shard directory that was created
        let objects_path = cas.base_path.join("objects");
        for entry in fs::read_dir(&objects_path).unwrap() {
            let entry = entry.unwrap();
            if entry.path().is_dir() {
                let mode = entry.metadata().unwrap().permissions().mode() & 0o777;
                assert_eq!(
                    mode,
                    0o700,
                    "Shard directory {} should have mode 0700, got {:04o}",
                    entry.path().display(),
                    mode
                );
            }
        }
    }

    /// SEC-CAS-005: Concurrent stores must not exceed `max_total_size`.
    ///
    /// Regression test for the non-atomic quota enforcement TOCTOU race.
    /// Before the fix, two concurrent 60-byte stores against
    /// `max_total_size=100` could both pass the check and produce
    /// `total=120`.
    #[test]
    fn test_concurrent_stores_respect_quota() {
        use std::sync::Arc;
        use std::thread;

        let temp_dir = TempDir::new().unwrap();
        let config = DurableCasConfig::new(temp_dir.path().join("cas")).with_max_total_size(100);
        let cas = Arc::new(DurableCas::new(config).unwrap());

        let num_threads: usize = 8;
        // Each payload is 60 bytes — only one should succeed for a 100-byte
        // quota (60 + 60 = 120 > 100).
        let payload_size = 60;

        let handles: Vec<_> = (0..num_threads)
            .map(|i| {
                let cas = Arc::clone(&cas);
                thread::spawn(move || {
                    // Each thread writes distinct content so hashes differ
                    // (no deduplication).
                    let mut data = vec![0u8; payload_size];
                    #[allow(clippy::cast_possible_truncation)]
                    {
                        data[0] = i as u8;
                        data[1] = (i >> 8) as u8;
                    }
                    cas.store(&data)
                })
            })
            .collect();

        let mut successes = 0usize;
        let mut storage_full_count = 0usize;
        for handle in handles {
            match handle.join().unwrap() {
                Ok(result) => {
                    assert!(result.is_new);
                    successes += 1;
                },
                Err(DurableCasError::StorageFull { .. }) => {
                    storage_full_count += 1;
                },
                Err(e) => panic!("unexpected error: {e}"),
            }
        }

        // With a 100-byte quota and 60-byte payloads, at most 1 store can
        // succeed (60 <= 100, but 60+60 = 120 > 100).
        assert_eq!(
            successes, 1,
            "Expected exactly 1 successful store, got {successes} \
             (storage_full={storage_full_count})"
        );
        assert!(
            cas.total_size() <= 100,
            "Total size {} exceeds max_total_size 100 — quota race!",
            cas.total_size()
        );
    }
}
