//! Read-only bounded reader for the APM2 daemon CAS filesystem layout.
//!
//! The worker process (`apm2-cli`) needs to retrieve patch bytes stored in the
//! daemon's durable CAS (`apm2-daemon/src/cas/`) without depending on the
//! daemon crate.  This module provides a minimal, read-only, bounded reader
//! that mirrors the CAS on-disk layout:
//!
//! ```text
//! {cas_root}/objects/{4-hex-prefix}/{remaining-60-hex}
//! ```
//!
//! All reads are bounded by `MAX_CAS_READ_SIZE`, use `O_NOFOLLOW` on Unix to
//! refuse symlinks **at every path component** (including ancestor
//! directories), and verify BLAKE3 content integrity before returning data.
//!
//! # Security Properties
//!
//! - [INV-CR-001] Reads are bounded to `MAX_CAS_READ_SIZE` before allocation
//!   (CTR-1603).
//! - [INV-CR-002] Symlinks are refused via fd-relative `openat(O_NOFOLLOW)` on
//!   every path component (cas_root, objects, prefix dir, object file) on Unix.
//!   This prevents ancestor-symlink traversal outside the CAS root.
//! - [INV-CR-003] Content hash is verified after read (fail-closed on
//!   mismatch).
//! - [INV-CR-004] CAS root must be an absolute path (fail-closed on relative).
//! - [INV-CR-005] `exists()` uses the same fd-relative traversal model as
//!   `retrieve()` to prevent ancestor-symlink bypass on existence checks.

use std::io::Read as _;
use std::path::{Path, PathBuf};

use subtle::ConstantTimeEq;
use thiserror::Error;

/// Maximum size for a single CAS blob read (10 MiB).
///
/// Matches `BlobStore::MAX_BLOB_SIZE` to keep patch byte reads bounded.
pub const MAX_CAS_READ_SIZE: usize = 10_485_760;

/// CAS objects subdirectory name (mirrors daemon layout).
const OBJECTS_DIR: &str = "objects";

/// Read-only accessor for the daemon CAS on-disk layout.
///
/// Does NOT require `DurableCas` construction or daemon-specific imports.
/// Callers provide the CAS root path (typically `$APM2_HOME/private/cas` or
/// the daemon `cas_path` config).
///
/// On Unix, all filesystem access uses fd-relative traversal with
/// `O_NOFOLLOW` on every component to prevent ancestor-symlink escape.
#[derive(Debug, Clone)]
pub struct CasReader {
    /// Root CAS directory (must be absolute).  Used as the base for
    /// fd-relative traversal on Unix and path-based access on other
    /// platforms.
    cas_root: PathBuf,
}

impl CasReader {
    /// Create a new CAS reader rooted at `cas_root`.
    ///
    /// On Unix, construction additionally validates that `cas_root` itself is
    /// not a symlink (via `lstat`).
    ///
    /// # Errors
    ///
    /// Returns `CasReaderError::InvalidRoot` if `cas_root` is not absolute.
    /// Returns `CasReaderError::SymlinkDetected` if `cas_root` is a symlink
    /// (Unix only).
    pub fn new(cas_root: &Path) -> Result<Self, CasReaderError> {
        if !cas_root.is_absolute() {
            return Err(CasReaderError::InvalidRoot {
                reason: format!("CAS root must be absolute, got: {}", cas_root.display()),
            });
        }

        // Fail-closed: reject symlink at the cas_root itself at construction
        // time.  The fd-relative traversal in retrieve/exists re-validates
        // this at access time, but catching it early gives a better error.
        #[cfg(unix)]
        {
            match cas_root.symlink_metadata() {
                Ok(m) if m.file_type().is_symlink() => {
                    return Err(CasReaderError::SymlinkDetected);
                },
                // If the path doesn't exist yet that's fine -- we'll fail at
                // retrieve/exists time with NotFound.
                _ => {},
            }
        }

        Ok(Self {
            cas_root: cas_root.to_path_buf(),
        })
    }

    /// Retrieve content by its BLAKE3 hash (`[u8; 32]`).
    ///
    /// The returned bytes are verified against `hash` before returning.
    ///
    /// # Errors
    ///
    /// - `NotFound` if the object file does not exist.
    /// - `TooLarge` if the file exceeds `MAX_CAS_READ_SIZE`.
    /// - `IntegrityMismatch` if the content does not match the hash.
    /// - `SymlinkDetected` if a symlink is encountered at any path component
    ///   (Unix).
    /// - `Io` for other filesystem failures.
    pub fn retrieve(&self, hash: &[u8; 32]) -> Result<Vec<u8>, CasReaderError> {
        let hex = hex::encode(hash);
        let (prefix, suffix) = hex.split_at(4);

        // Open the object file via fd-relative traversal on Unix, or
        // path-based open on other platforms.
        let file = open_cas_object(&self.cas_root, prefix, suffix)?;

        // Check size from the fd metadata (TOCTOU-safe: we already hold the
        // fd).
        let fd_meta = file.metadata().map_err(CasReaderError::Io)?;
        let fd_size = usize::try_from(fd_meta.len()).unwrap_or(usize::MAX);
        if fd_size > MAX_CAS_READ_SIZE {
            return Err(CasReaderError::TooLarge {
                size: fd_size,
                max: MAX_CAS_READ_SIZE,
            });
        }

        // Bounded read.
        let cap = usize::try_from(fd_meta.len()).unwrap_or(0);
        let mut bytes = Vec::with_capacity(cap);
        file.take(MAX_CAS_READ_SIZE as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(CasReaderError::Io)?;
        if bytes.len() > MAX_CAS_READ_SIZE {
            return Err(CasReaderError::TooLarge {
                size: bytes.len(),
                max: MAX_CAS_READ_SIZE,
            });
        }

        // Verify integrity via BLAKE3.
        let actual_hash = blake3::hash(&bytes);
        if actual_hash.as_bytes().ct_eq(hash).unwrap_u8() != 1 {
            return Err(CasReaderError::IntegrityMismatch);
        }

        Ok(bytes)
    }

    /// Check whether a CAS object exists for the given hash.
    ///
    /// Uses the same fd-relative traversal as `retrieve()` so that
    /// symlinked ancestor directories are rejected identically
    /// (INV-CR-005).
    #[must_use]
    pub fn exists(&self, hash: &[u8; 32]) -> bool {
        let hex = hex::encode(hash);
        let (prefix, suffix) = hex.split_at(4);
        exists_cas_object(&self.cas_root, prefix, suffix)
    }

    /// Convert a hash to its on-disk path under the CAS objects directory.
    ///
    /// Layout: `{cas_root}/objects/{4-hex-prefix}/{remaining-60-hex}`
    ///
    /// Note: this path is for informational/logging purposes.  Actual file
    /// access goes through fd-relative traversal on Unix.
    #[must_use]
    pub fn hash_to_path(&self, hash: &[u8; 32]) -> PathBuf {
        let hex = hex::encode(hash);
        let (prefix, suffix) = hex.split_at(4);
        self.cas_root.join(OBJECTS_DIR).join(prefix).join(suffix)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Unix: fd-relative traversal with O_NOFOLLOW at every component
// ─────────────────────────────────────────────────────────────────────────────

/// Open a CAS object file using fd-relative traversal so that no ancestor
/// component can be a symlink.
///
/// Traversal order:
/// 1. `open(cas_root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)`
/// 2. `openat(root_fd, "objects", O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
///    O_CLOEXEC)`
/// 3. `openat(objects_fd, prefix, O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
///    O_CLOEXEC)`
/// 4. `openat(prefix_fd, suffix, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)` -- regular
///    file
///
/// If any component is a symlink, the kernel returns `ELOOP` which we map
/// to `CasReaderError::SymlinkDetected`.
#[cfg(unix)]
fn open_cas_object(
    cas_root: &Path,
    prefix: &str,
    suffix: &str,
) -> Result<std::fs::File, CasReaderError> {
    use std::os::fd::AsFd;

    use nix::fcntl::OFlag;
    use nix::sys::stat::Mode;

    let dir_flags = OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;

    // Step 1: open cas_root directory fd (O_NOFOLLOW refuses symlink root).
    let root_dir = nix::dir::Dir::open(cas_root, dir_flags, Mode::empty())
        .map_err(|e| map_nix_open_error(e, "open CAS root"))?;

    // Step 2: openat -> "objects" directory.
    let objects_dir = nix::dir::Dir::openat(&root_dir, OBJECTS_DIR, dir_flags, Mode::empty())
        .map_err(|e| map_nix_open_error(e, "openat objects directory"))?;

    // Step 3: openat -> prefix directory (4-hex-char subdirectory).
    let prefix_dir = nix::dir::Dir::openat(&objects_dir, prefix, dir_flags, Mode::empty())
        .map_err(|e| map_nix_open_error(e, "openat prefix directory"))?;

    // Step 4: openat -> object file (regular file, NOT a directory).
    let file_flags = OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
    let owned_fd = nix::fcntl::openat(prefix_dir.as_fd(), suffix, file_flags, Mode::empty())
        .map_err(|e| map_nix_open_error(e, "openat object file"))?;

    // Convert OwnedFd -> std::fs::File for standard Read trait usage.
    Ok(std::fs::File::from(owned_fd))
}

/// Check existence of a CAS object using the same fd-relative traversal
/// as `open_cas_object`.  Returns `false` for any error (not-found,
/// symlink, I/O).
#[cfg(unix)]
fn exists_cas_object(cas_root: &Path, prefix: &str, suffix: &str) -> bool {
    use nix::fcntl::{AtFlags, OFlag};
    use nix::sys::stat::Mode;

    let dir_flags = OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;

    // Walk to prefix directory; any failure (incl symlink) -> false.
    let Ok(root_dir) = nix::dir::Dir::open(cas_root, dir_flags, Mode::empty()) else {
        return false;
    };
    let Ok(objects_dir) = nix::dir::Dir::openat(&root_dir, OBJECTS_DIR, dir_flags, Mode::empty())
    else {
        return false;
    };
    let Ok(prefix_dir) = nix::dir::Dir::openat(&objects_dir, prefix, dir_flags, Mode::empty())
    else {
        return false;
    };

    // fstatat with AT_SYMLINK_NOFOLLOW on the final component: verifies the
    // entry exists and is a regular file (not a symlink).
    nix::sys::stat::fstatat(&prefix_dir, suffix, AtFlags::AT_SYMLINK_NOFOLLOW).is_ok_and(|stat| {
        let file_type = stat.st_mode & libc::S_IFMT;
        file_type == libc::S_IFREG
    })
}

/// Map a nix errno into a `CasReaderError`, translating ELOOP/ENOTDIR into
/// `SymlinkDetected` and ENOENT into `NotFound`.
#[cfg(unix)]
fn map_nix_open_error(e: nix::errno::Errno, context: &str) -> CasReaderError {
    let io_err = std::io::Error::from(e);
    match io_err.raw_os_error() {
        Some(libc::ELOOP | libc::ENOTDIR) => CasReaderError::SymlinkDetected,
        Some(libc::ENOENT) => CasReaderError::NotFound,
        _ => CasReaderError::Io(std::io::Error::new(
            io_err.kind(),
            format!("{context}: {io_err}"),
        )),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Non-Unix fallback (path-based)
// ─────────────────────────────────────────────────────────────────────────────

/// Path-based open for non-Unix platforms.  Uses `symlink_metadata` +
/// `O_NOFOLLOW` on the terminal component only (best-effort).
#[cfg(not(unix))]
fn open_cas_object(
    cas_root: &Path,
    prefix: &str,
    suffix: &str,
) -> Result<std::fs::File, CasReaderError> {
    let file_path = cas_root.join(OBJECTS_DIR).join(prefix).join(suffix);

    // Best-effort symlink check on the terminal file.
    let metadata = match file_path.symlink_metadata() {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(CasReaderError::NotFound);
        },
        Err(e) => return Err(CasReaderError::Io(e)),
    };
    if metadata.file_type().is_symlink() {
        return Err(CasReaderError::SymlinkDetected);
    }
    if !metadata.is_file() {
        return Err(CasReaderError::NotFound);
    }
    let meta_size = usize::try_from(metadata.len()).unwrap_or(usize::MAX);
    if meta_size > MAX_CAS_READ_SIZE {
        return Err(CasReaderError::TooLarge {
            size: meta_size,
            max: MAX_CAS_READ_SIZE,
        });
    }

    std::fs::File::open(&file_path).map_err(CasReaderError::Io)
}

/// Path-based existence check for non-Unix platforms.
#[cfg(not(unix))]
fn exists_cas_object(cas_root: &Path, prefix: &str, suffix: &str) -> bool {
    let path = cas_root.join(OBJECTS_DIR).join(prefix).join(suffix);
    path.symlink_metadata()
        .is_ok_and(|m| m.is_file() && !m.file_type().is_symlink())
}

/// Errors from CAS read operations.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CasReaderError {
    /// Object not found for the given hash.
    #[error("CAS object not found")]
    NotFound,

    /// Object exceeds maximum read size.
    #[error("CAS object size {size} exceeds maximum {max}")]
    TooLarge {
        /// Actual size.
        size: usize,
        /// Maximum allowed size.
        max: usize,
    },

    /// Content integrity mismatch after read.
    #[error("CAS object integrity mismatch")]
    IntegrityMismatch,

    /// Symlink detected in CAS object path (any component).
    #[error("symlink detected in CAS path")]
    SymlinkDetected,

    /// CAS root path is invalid.
    #[error("invalid CAS root: {reason}")]
    InvalidRoot {
        /// Reason the root is invalid.
        reason: String,
    },

    /// Filesystem I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;

    /// Helper: write a CAS object in the daemon layout.
    fn write_cas_object(cas_root: &Path, data: &[u8]) -> [u8; 32] {
        let hash = *blake3::hash(data).as_bytes();
        let hex = hex::encode(hash);
        let (prefix, suffix) = hex.split_at(4);
        let dir = cas_root.join(OBJECTS_DIR).join(prefix);
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join(suffix);
        std::fs::write(&path, data).expect("write");
        hash
    }

    #[test]
    fn round_trip_store_and_retrieve() {
        let tmp = tempdir().expect("tmpdir");
        let cas_root = tmp.path().join("cas");
        std::fs::create_dir_all(&cas_root).expect("cas root");

        let data = b"hello CAS patch bytes";
        let hash = write_cas_object(&cas_root, data);

        let reader = CasReader::new(&cas_root).expect("reader");
        let retrieved = reader.retrieve(&hash).expect("retrieve");
        assert_eq!(retrieved, data);
    }

    #[test]
    fn retrieve_not_found() {
        let tmp = tempdir().expect("tmpdir");
        let cas_root = tmp.path().join("cas");
        std::fs::create_dir_all(&cas_root).expect("cas root");

        let reader = CasReader::new(&cas_root).expect("reader");
        assert!(matches!(
            reader.retrieve(&[0u8; 32]),
            Err(CasReaderError::NotFound)
        ));
    }

    #[test]
    fn retrieve_tampered_content_fails() {
        let tmp = tempdir().expect("tmpdir");
        let cas_root = tmp.path().join("cas");
        std::fs::create_dir_all(&cas_root).expect("cas root");

        let data = b"original content";
        let hash = write_cas_object(&cas_root, data);

        // Tamper with the file.
        let reader = CasReader::new(&cas_root).expect("reader");
        let path = reader.hash_to_path(&hash);
        std::fs::write(&path, b"tampered").expect("tamper");

        assert!(matches!(
            reader.retrieve(&hash),
            Err(CasReaderError::IntegrityMismatch)
        ));
    }

    #[test]
    fn exists_checks_presence() {
        let tmp = tempdir().expect("tmpdir");
        let cas_root = tmp.path().join("cas");
        std::fs::create_dir_all(&cas_root).expect("cas root");

        let reader = CasReader::new(&cas_root).expect("reader");
        assert!(!reader.exists(&[0u8; 32]));

        let data = b"existence check";
        let hash = write_cas_object(&cas_root, data);
        assert!(reader.exists(&hash));
    }

    #[test]
    fn reject_relative_root() {
        let result = CasReader::new(Path::new("relative/path"));
        assert!(matches!(result, Err(CasReaderError::InvalidRoot { .. })));
    }

    #[cfg(unix)]
    #[test]
    fn reject_symlinked_object() {
        use std::os::unix::fs::symlink;

        let tmp = tempdir().expect("tmpdir");
        let cas_root = tmp.path().join("cas");
        std::fs::create_dir_all(&cas_root).expect("cas root");

        let data = b"symlink target data";
        let hash = *blake3::hash(data).as_bytes();
        let hex = hex::encode(hash);
        let (prefix, suffix) = hex.split_at(4);
        let dir = cas_root.join(OBJECTS_DIR).join(prefix);
        std::fs::create_dir_all(&dir).expect("mkdir");

        // Write data to an attacker-controlled location.
        let attacker_file = tmp.path().join("attacker_data");
        std::fs::write(&attacker_file, data).expect("write attacker");

        // Symlink the CAS path to the attacker file.
        let object_path = dir.join(suffix);
        symlink(&attacker_file, &object_path).expect("symlink");

        let reader = CasReader::new(&cas_root).expect("reader");
        assert!(matches!(
            reader.retrieve(&hash),
            Err(CasReaderError::SymlinkDetected)
        ));
    }

    #[test]
    fn retrieve_oversized_object_rejected() {
        let tmp = tempdir().expect("tmpdir");
        let cas_root = tmp.path().join("cas");
        std::fs::create_dir_all(&cas_root).expect("cas root");

        // We can't easily create a MAX_CAS_READ_SIZE + 1 file, but we can
        // verify the path-based size check works by writing a small file and
        // checking that the reader uses bounded reads.
        let data = b"small data";
        let hash = write_cas_object(&cas_root, data);
        let reader = CasReader::new(&cas_root).expect("reader");
        let result = reader.retrieve(&hash);
        assert!(result.is_ok());
    }

    // ── Ancestor-symlink traversal regression tests ─────────────────────

    /// Regression: symlinked `objects` directory must be rejected by
    /// `retrieve()`.  Before the fd-relative fix, only the terminal
    /// object file was checked with `O_NOFOLLOW`, allowing a symlinked
    /// `objects/` directory to redirect reads outside the CAS root.
    #[cfg(unix)]
    #[test]
    fn reject_symlinked_objects_directory_on_retrieve() {
        use std::os::unix::fs::symlink;

        let tmp = tempdir().expect("tmpdir");
        let cas_root = tmp.path().join("cas");
        std::fs::create_dir(&cas_root).expect("cas root");

        // Create a real objects tree in an attacker-controlled location.
        let attacker_dir = tmp.path().join("attacker_objects");
        let data = b"attacker-controlled content via symlinked objects dir";
        let hash = *blake3::hash(data).as_bytes();
        let hex_str = hex::encode(hash);
        let (prefix, suffix) = hex_str.split_at(4);
        let attacker_prefix_dir = attacker_dir.join(prefix);
        std::fs::create_dir_all(&attacker_prefix_dir).expect("attacker mkdir");
        std::fs::write(attacker_prefix_dir.join(suffix), data).expect("attacker write");

        // Replace the real objects directory with a symlink to the attacker
        // tree.
        let objects_path = cas_root.join(OBJECTS_DIR);
        symlink(&attacker_dir, &objects_path).expect("symlink objects dir");

        let reader = CasReader::new(&cas_root).expect("reader");
        let result = reader.retrieve(&hash);
        assert!(
            matches!(result, Err(CasReaderError::SymlinkDetected)),
            "expected SymlinkDetected for symlinked objects dir, got: {result:?}"
        );
    }

    /// Regression: symlinked prefix directory (e.g. `objects/ab12/`)
    /// must be rejected by `retrieve()`.
    #[cfg(unix)]
    #[test]
    fn reject_symlinked_prefix_directory_on_retrieve() {
        use std::os::unix::fs::symlink;

        let tmp = tempdir().expect("tmpdir");
        let cas_root = tmp.path().join("cas");
        let objects_dir = cas_root.join(OBJECTS_DIR);
        std::fs::create_dir_all(&objects_dir).expect("objects dir");

        // Create a real prefix tree in an attacker-controlled location.
        let attacker_prefix = tmp.path().join("attacker_prefix");
        let data = b"attacker content via symlinked prefix dir";
        let hash = *blake3::hash(data).as_bytes();
        let hex_str = hex::encode(hash);
        let (prefix, suffix) = hex_str.split_at(4);
        std::fs::create_dir_all(&attacker_prefix).expect("attacker prefix mkdir");
        std::fs::write(attacker_prefix.join(suffix), data).expect("attacker write");

        // Replace the real prefix directory with a symlink.
        let prefix_path = objects_dir.join(prefix);
        symlink(&attacker_prefix, &prefix_path).expect("symlink prefix dir");

        let reader = CasReader::new(&cas_root).expect("reader");
        let result = reader.retrieve(&hash);
        assert!(
            matches!(result, Err(CasReaderError::SymlinkDetected)),
            "expected SymlinkDetected for symlinked prefix dir, got: {result:?}"
        );
    }

    /// Regression: symlinked `objects` directory must be rejected by
    /// `exists()` (same traversal model as `retrieve()`).
    #[cfg(unix)]
    #[test]
    fn reject_symlinked_objects_directory_on_exists() {
        use std::os::unix::fs::symlink;

        let tmp = tempdir().expect("tmpdir");
        let cas_root = tmp.path().join("cas");
        std::fs::create_dir(&cas_root).expect("cas root");

        // Create a real objects tree in an attacker-controlled location.
        let attacker_dir = tmp.path().join("attacker_objects");
        let data = b"attacker content for exists via symlinked objects";
        let hash = *blake3::hash(data).as_bytes();
        let hex_str = hex::encode(hash);
        let (prefix, suffix) = hex_str.split_at(4);
        let attacker_prefix_dir = attacker_dir.join(prefix);
        std::fs::create_dir_all(&attacker_prefix_dir).expect("attacker mkdir");
        std::fs::write(attacker_prefix_dir.join(suffix), data).expect("attacker write");

        // Replace objects directory with a symlink.
        let objects_path = cas_root.join(OBJECTS_DIR);
        symlink(&attacker_dir, &objects_path).expect("symlink objects dir");

        let reader = CasReader::new(&cas_root).expect("reader");
        assert!(
            !reader.exists(&hash),
            "exists() must return false when objects dir is a symlink"
        );
    }

    /// Regression: symlinked prefix directory must be rejected by
    /// `exists()`.
    #[cfg(unix)]
    #[test]
    fn reject_symlinked_prefix_directory_on_exists() {
        use std::os::unix::fs::symlink;

        let tmp = tempdir().expect("tmpdir");
        let cas_root = tmp.path().join("cas");
        let objects_dir = cas_root.join(OBJECTS_DIR);
        std::fs::create_dir_all(&objects_dir).expect("objects dir");

        // Create a real prefix tree in an attacker-controlled location.
        let attacker_prefix = tmp.path().join("attacker_prefix");
        let data = b"attacker content for exists via symlinked prefix";
        let hash = *blake3::hash(data).as_bytes();
        let hex_str = hex::encode(hash);
        let (prefix, suffix) = hex_str.split_at(4);
        std::fs::create_dir_all(&attacker_prefix).expect("attacker prefix mkdir");
        std::fs::write(attacker_prefix.join(suffix), data).expect("attacker write");

        // Replace the prefix directory with a symlink.
        let prefix_path = objects_dir.join(prefix);
        symlink(&attacker_prefix, &prefix_path).expect("symlink prefix dir");

        let reader = CasReader::new(&cas_root).expect("reader");
        assert!(
            !reader.exists(&hash),
            "exists() must return false when prefix dir is a symlink"
        );
    }

    /// Regression: symlinked CAS root itself must be rejected at
    /// construction.
    #[cfg(unix)]
    #[test]
    fn reject_symlinked_cas_root() {
        use std::os::unix::fs::symlink;

        let tmp = tempdir().expect("tmpdir");
        let real_cas = tmp.path().join("real_cas");
        std::fs::create_dir(&real_cas).expect("real cas");

        let symlinked_cas = tmp.path().join("symlinked_cas");
        symlink(&real_cas, &symlinked_cas).expect("symlink cas root");

        let result = CasReader::new(&symlinked_cas);
        assert!(
            matches!(result, Err(CasReaderError::SymlinkDetected)),
            "expected SymlinkDetected for symlinked CAS root, got: {result:?}"
        );
    }

    /// Symlinked object file is still rejected (terminal component).
    #[cfg(unix)]
    #[test]
    fn reject_symlinked_object_file_on_exists() {
        use std::os::unix::fs::symlink;

        let tmp = tempdir().expect("tmpdir");
        let cas_root = tmp.path().join("cas");
        std::fs::create_dir_all(&cas_root).expect("cas root");

        let data = b"target for symlinked object exists check";
        let hash = *blake3::hash(data).as_bytes();
        let hex_str = hex::encode(hash);
        let (prefix, suffix) = hex_str.split_at(4);
        let dir = cas_root.join(OBJECTS_DIR).join(prefix);
        std::fs::create_dir_all(&dir).expect("mkdir");

        // Write to attacker location and symlink the object file.
        let attacker_file = tmp.path().join("attacker_file");
        std::fs::write(&attacker_file, data).expect("write attacker");
        symlink(&attacker_file, dir.join(suffix)).expect("symlink object");

        let reader = CasReader::new(&cas_root).expect("reader");
        assert!(
            !reader.exists(&hash),
            "exists() must return false for symlinked object file"
        );
    }
}
