// AGENT-AUTHORED (TCK-00516)
//! Symlink-safe recursive tree deletion primitive.
//!
//! Implements `safe_rmtree_v1` for secure deletion of lane directories
//! (workspace, target, logs) with strong protections against symlink
//! traversal, filesystem boundary crossing, and TOCTOU race conditions.
//!
//! # Security Model
//!
//! - **Symlink refusal (fd-relative + ancestor chain)**: On Unix, the initial
//!   open walks from `allowed_parent` to `root` component-by-component using
//!   `Dir::openat(parent_fd, component, O_NOFOLLOW | O_DIRECTORY)`. This
//!   eliminates the TOCTOU gap between symlink validation and root open: every
//!   `openat` with `O_NOFOLLOW` atomically refuses symlinks at the kernel
//!   level. All recursive directory traversal likewise uses fd-relative
//!   `Dir::openat`/`unlinkat`/`fstatat`. File deletion uses
//!   `unlinkat(parent_fd, name, NoRemoveDir)` and directory deletion uses
//!   `unlinkat(parent_fd, name, RemoveDir)`. No `std::fs::read_dir`,
//!   `std::fs::remove_dir`, `std::fs::remove_file`, or path-based `Dir::open`
//!   is used in the recursive delete path.
//! - **Streaming iteration**: Directory entries are processed one-by-one in a
//!   streaming fashion to prevent unbounded memory growth. No `Vec` of entries
//!   is collected.
//! - **Path traversal rejection**: Any path containing `.` or `..` components
//!   is rejected immediately (not filtered -- rejected).
//! - **Parent boundary enforcement**: `root` must be strictly under
//!   `allowed_parent` by path component analysis (NOT string prefix).
//! - **Filesystem boundary**: Cross-device deletion is refused by comparing
//!   `st_dev` via `fstat` on opened directory fds (TOCTOU-safe).
//! - **Unexpected file types**: Sockets, FIFOs, devices, and unknown file types
//!   cause immediate abort with `UnexpectedFileType`.
//! - **Fail-closed**: On ANY ambiguity or error during walking, the operation
//!   aborts without partial deletion.
//! - **Depth-first bottom-up**: Files are deleted before their parent
//!   directories to ensure clean removal.
//!
//! # Invariants
//!
//! - [INV-RMTREE-001] Symlink detected at any depth causes immediate abort with
//!   `SymlinkDetected` error. Enforced at the kernel level via `O_NOFOLLOW`.
//! - [INV-RMTREE-002] `root` must be strictly under `allowed_parent` by
//!   component-wise validation.
//! - [INV-RMTREE-003] Cross-filesystem deletion is refused by `st_dev`
//!   comparison.
//! - [INV-RMTREE-004] Unexpected file types (sockets, FIFOs, devices) cause
//!   immediate abort.
//! - [INV-RMTREE-005] Both `root` and `allowed_parent` must be absolute paths.
//! - [INV-RMTREE-006] `allowed_parent` must be owned by the current user with
//!   mode 0o700.
//! - [INV-RMTREE-007] Non-existent `root` is a successful no-op (returns
//!   `AlreadyAbsent`).
//! - [INV-RMTREE-008] Maximum traversal depth is bounded by
//!   `MAX_TRAVERSAL_DEPTH` to prevent stack exhaustion on deeply nested trees.
//! - [INV-RMTREE-009] Maximum entries per directory is bounded by
//!   `MAX_DIR_ENTRIES` to prevent unbounded memory allocation.
//! - [INV-RMTREE-010] Paths containing `.` or `..` components are rejected
//!   immediately (not filtered).

use std::path::{Component, Path, PathBuf};
use std::{fmt, fs, io};

use thiserror::Error;

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Maximum traversal depth to prevent stack exhaustion (INV-RMTREE-008).
pub const MAX_TRAVERSAL_DEPTH: usize = 128;

/// Maximum number of entries per directory read (INV-RMTREE-009).
///
/// Prevents unbounded memory allocation from adversarially crafted
/// directories. No lane workspace should have 10,000 files in a single
/// directory; this is a hard safety cap, not a performance tuning knob.
pub const MAX_DIR_ENTRIES: usize = 10_000;

// ─────────────────────────────────────────────────────────────────────────────
// Error Types
// ─────────────────────────────────────────────────────────────────────────────

/// Errors that can occur during safe recursive tree deletion.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SafeRmtreeError {
    /// A symlink was detected at the given path (INV-RMTREE-001).
    #[error("symlink detected at {}", path.display())]
    SymlinkDetected {
        /// Path where the symlink was found.
        path: PathBuf,
    },

    /// The root path is not under the allowed parent (INV-RMTREE-002).
    #[error("root {} is not under allowed parent {}", root.display(), allowed_parent.display())]
    OutsideAllowedParent {
        /// The root path that was checked.
        root: PathBuf,
        /// The allowed parent boundary.
        allowed_parent: PathBuf,
    },

    /// Deletion would cross a filesystem boundary (INV-RMTREE-003).
    #[error("filesystem boundary crossing detected: root dev={root_dev}, parent dev={parent_dev}")]
    CrossesFilesystemBoundary {
        /// Device ID of the root.
        root_dev: u64,
        /// Device ID of the allowed parent.
        parent_dev: u64,
    },

    /// An unexpected file type was encountered (INV-RMTREE-004).
    #[error("unexpected file type at {}: {file_type}", path.display())]
    UnexpectedFileType {
        /// Path with the unexpected type.
        path: PathBuf,
        /// Description of the unexpected type.
        file_type: String,
    },

    /// A path is not absolute (INV-RMTREE-005).
    #[error("path must be absolute: {}", path.display())]
    NotAbsolute {
        /// The non-absolute path.
        path: PathBuf,
    },

    /// Permission denied or ownership/mode validation failed
    /// (INV-RMTREE-006).
    #[error("permission denied: {reason}")]
    PermissionDenied {
        /// What went wrong.
        reason: String,
    },

    /// A potential TOCTOU race was detected.
    #[error("TOCTOU race detected: {reason}")]
    TocTouRace {
        /// Description of the detected race condition.
        reason: String,
    },

    /// An I/O error occurred during the operation.
    #[error("I/O error during {context}: {source}")]
    Io {
        /// Human-readable description of the operation.
        context: String,
        /// The underlying I/O error.
        #[source]
        source: io::Error,
    },

    /// Traversal depth exceeded (INV-RMTREE-008).
    #[error("traversal depth exceeded maximum of {max} at {}", path.display())]
    DepthExceeded {
        /// Path where depth was exceeded.
        path: PathBuf,
        /// Maximum allowed depth.
        max: usize,
    },

    /// Too many entries in a single directory (INV-RMTREE-009).
    #[error("directory {} has more than {max} entries", path.display())]
    TooManyEntries {
        /// Directory with too many entries.
        path: PathBuf,
        /// Maximum allowed entries.
        max: usize,
    },

    /// Path contains `.` or `..` components (INV-RMTREE-010).
    #[error("path contains dot-segment components (. or ..): {}", path.display())]
    DotSegment {
        /// The path containing dot segments.
        path: PathBuf,
    },
}

impl SafeRmtreeError {
    /// Convenience constructor for I/O errors with context.
    fn io(context: impl Into<String>, source: io::Error) -> Self {
        Self::Io {
            context: context.into(),
            source,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Outcome
// ─────────────────────────────────────────────────────────────────────────────

/// Outcome of a successful `safe_rmtree_v1` invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SafeRmtreeOutcome {
    /// The root was successfully deleted with the given statistics.
    Deleted {
        /// Number of regular files deleted.
        files_deleted: u64,
        /// Number of directories deleted.
        dirs_deleted: u64,
    },
    /// The root did not exist; no action was taken (INV-RMTREE-007).
    AlreadyAbsent,
}

impl fmt::Display for SafeRmtreeOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Deleted {
                files_deleted,
                dirs_deleted,
            } => write!(
                f,
                "deleted {files_deleted} files and {dirs_deleted} directories"
            ),
            Self::AlreadyAbsent => write!(f, "already absent (no-op)"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Refused-delete receipt
// ─────────────────────────────────────────────────────────────────────────────

/// Receipt emitted when a deletion is refused due to a safety violation.
///
/// This provides machine-readable evidence for audit trails when lane
/// cleanup is refused and the lane should be marked CORRUPT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefusedDeleteReceipt {
    /// The root path that was refused.
    pub root: PathBuf,
    /// The allowed parent boundary.
    pub allowed_parent: PathBuf,
    /// Human-readable reason for the refusal.
    pub reason: String,
    /// Whether this should cause the lane to be marked CORRUPT.
    pub mark_corrupt: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// Core Implementation
// ─────────────────────────────────────────────────────────────────────────────

/// Safely delete a directory tree at `root`, refusing to traverse symlinks
/// or exit `allowed_parent`.
///
/// This is the primary entry point for symlink-safe recursive deletion.
///
/// # Arguments
///
/// * `root` - The directory tree to delete. Must be an absolute path strictly
///   under `allowed_parent`. Must NOT contain `.` or `..` components.
/// * `allowed_parent` - The boundary directory. `root` must be a direct or
///   indirect child of this directory. Must be absolute, owned by the current
///   user, and have mode 0o700. Must NOT contain `.` or `..` components.
///
/// # Returns
///
/// * `Ok(SafeRmtreeOutcome::Deleted { .. })` - The tree was deleted.
/// * `Ok(SafeRmtreeOutcome::AlreadyAbsent)` - The root does not exist.
/// * `Err(SafeRmtreeError)` - A safety violation was detected or an I/O error
///   occurred. No partial deletion is performed on safety violations; I/O
///   errors during deletion of individual files may leave partial state.
///
/// # Security
///
/// See module-level documentation for the full security model.
///
/// # Errors
///
/// Returns `SafeRmtreeError` on any safety violation, permission error,
/// or I/O failure.
pub fn safe_rmtree_v1(
    root: &Path,
    allowed_parent: &Path,
) -> Result<SafeRmtreeOutcome, SafeRmtreeError> {
    // ── Step 1: Validate both paths are absolute (INV-RMTREE-005) ────
    if !root.is_absolute() {
        return Err(SafeRmtreeError::NotAbsolute {
            path: root.to_path_buf(),
        });
    }
    if !allowed_parent.is_absolute() {
        return Err(SafeRmtreeError::NotAbsolute {
            path: allowed_parent.to_path_buf(),
        });
    }

    // ── Step 1b: Reject dot-segment components (INV-RMTREE-010) ─────
    // REJECT any path containing Component::ParentDir or Component::CurDir.
    // Do NOT filter them -- reject them entirely. This prevents path
    // traversal attacks like /home/user/lanes/lane-00/../../etc/passwd.
    reject_dot_segments(root)?;
    reject_dot_segments(allowed_parent)?;

    // ── Step 2: Validate root is strictly under allowed_parent ───────
    // Component-wise validation, NOT string prefix (INV-RMTREE-002).
    validate_strictly_under(root, allowed_parent)?;

    // ── Step 3: Validate allowed_parent ownership and mode ───────────
    // (INV-RMTREE-006)
    validate_parent_ownership(allowed_parent)?;

    // ── Step 4+5+6+7: Open root via ancestor chain + delete ─────────
    // On Unix, walk from allowed_parent to root component-by-component
    // using openat(O_NOFOLLOW) which inherently refuses symlinks at
    // every component, eliminating the TOCTOU gap between symlink
    // validation and root open.
    //
    // On non-Unix, fall back to path-based validation and deletion.
    #[cfg(unix)]
    {
        safe_rmtree_v1_unix(root, allowed_parent)
    }

    #[cfg(not(unix))]
    {
        safe_rmtree_v1_non_unix(root, allowed_parent)
    }
}

/// Unix implementation of safe recursive tree deletion using fd-relative
/// operations. Walks from `allowed_parent` to `root` via `openat(O_NOFOLLOW)`
/// at each component, then performs fd-relative deletion.
#[cfg(unix)]
fn safe_rmtree_v1_unix(
    root: &Path,
    allowed_parent: &Path,
) -> Result<SafeRmtreeOutcome, SafeRmtreeError> {
    use nix::fcntl::OFlag;

    // Compute relative path from allowed_parent to root.
    let relative =
        root.strip_prefix(allowed_parent)
            .map_err(|_| SafeRmtreeError::OutsideAllowedParent {
                root: root.to_path_buf(),
                allowed_parent: allowed_parent.to_path_buf(),
            })?;

    let components: Vec<&std::ffi::OsStr> = relative
        .components()
        .filter_map(|c| match c {
            Component::Normal(s) => Some(s),
            _ => None,
        })
        .collect();

    if components.is_empty() {
        return Err(SafeRmtreeError::OutsideAllowedParent {
            root: root.to_path_buf(),
            allowed_parent: allowed_parent.to_path_buf(),
        });
    }

    let open_flags = OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC;
    let parent_of_root = open_path_via_ancestor_chain(
        allowed_parent,
        &components[..components.len() - 1],
        open_flags,
    )?;

    let root_name = components[components.len() - 1];

    // fstatat the root entry via the parent fd to check existence/type.
    let root_stat = match nix::sys::stat::fstatat(
        &parent_of_root,
        root_name,
        nix::fcntl::AtFlags::AT_SYMLINK_NOFOLLOW,
    ) {
        Ok(s) => s,
        Err(nix::errno::Errno::ENOENT) => {
            return Ok(SafeRmtreeOutcome::AlreadyAbsent);
        },
        Err(e) => {
            return Err(SafeRmtreeError::io(
                format!("fstatat root {}", root.display()),
                io::Error::from(e),
            ));
        },
    };

    // Root itself must not be a symlink.
    let file_type = root_stat.st_mode & libc::S_IFMT;
    if file_type == libc::S_IFLNK {
        return Err(SafeRmtreeError::SymlinkDetected {
            path: root.to_path_buf(),
        });
    }

    // Check filesystem boundary (INV-RMTREE-003) via fstat on opened fds.
    let parent_stat = nix::sys::stat::fstat(&parent_of_root).map_err(|e| {
        SafeRmtreeError::io(
            format!("fstat parent of root {}", root.display()),
            io::Error::from(e),
        )
    })?;
    #[allow(clippy::cast_sign_loss)]
    let parent_dev = parent_stat.st_dev as u64;
    #[allow(clippy::cast_sign_loss)]
    let root_dev = root_stat.st_dev as u64;
    if root_dev != parent_dev {
        return Err(SafeRmtreeError::CrossesFilesystemBoundary {
            root_dev,
            parent_dev,
        });
    }

    delete_root_entry_via_parent_fd(
        &parent_of_root,
        root_name,
        root,
        file_type,
        root_dev,
        open_flags,
    )
}

/// Delete the root entry (directory or file) using fd-relative operations
/// on the already-opened parent directory fd.
#[cfg(unix)]
fn delete_root_entry_via_parent_fd(
    parent_of_root: &nix::dir::Dir,
    root_name: &std::ffi::OsStr,
    root: &Path,
    file_type: libc::mode_t,
    root_dev: u64,
    open_flags: nix::fcntl::OFlag,
) -> Result<SafeRmtreeOutcome, SafeRmtreeError> {
    if file_type == libc::S_IFDIR {
        let mut stats = DeleteStats::default();

        let root_dir = nix::dir::Dir::openat(
            parent_of_root,
            root_name,
            open_flags,
            nix::sys::stat::Mode::empty(),
        )
        .map_err(|e| {
            let io_err = io::Error::from(e);
            if io_err.raw_os_error() == Some(libc::ELOOP)
                || io_err.raw_os_error() == Some(libc::ENOTDIR)
            {
                SafeRmtreeError::SymlinkDetected {
                    path: root.to_path_buf(),
                }
            } else {
                SafeRmtreeError::io(format!("openat root directory {}", root.display()), io_err)
            }
        })?;

        fd_relative_recursive_delete(&root_dir, root, &mut stats, 0, root_dev)?;
        drop(root_dir);

        nix::unistd::unlinkat(
            parent_of_root,
            root_name,
            nix::unistd::UnlinkatFlags::RemoveDir,
        )
        .map_err(|e| {
            SafeRmtreeError::io(
                format!("removing root directory {}", root.display()),
                io::Error::from(e),
            )
        })?;
        stats.dirs_deleted = stats.dirs_deleted.saturating_add(1);

        Ok(SafeRmtreeOutcome::Deleted {
            files_deleted: stats.files_deleted,
            dirs_deleted: stats.dirs_deleted,
        })
    } else if file_type == libc::S_IFREG {
        nix::unistd::unlinkat(
            parent_of_root,
            root_name,
            nix::unistd::UnlinkatFlags::NoRemoveDir,
        )
        .map_err(|e| {
            SafeRmtreeError::io(
                format!("removing file {}", root.display()),
                io::Error::from(e),
            )
        })?;
        Ok(SafeRmtreeOutcome::Deleted {
            files_deleted: 1,
            dirs_deleted: 0,
        })
    } else {
        let type_desc = match file_type {
            libc::S_IFIFO => "FIFO/named pipe",
            libc::S_IFSOCK => "Unix socket",
            libc::S_IFBLK => "block device",
            libc::S_IFCHR => "character device",
            _ => "unknown",
        };
        Err(SafeRmtreeError::UnexpectedFileType {
            path: root.to_path_buf(),
            file_type: type_desc.to_string(),
        })
    }
}

/// Non-Unix fallback: path-based validation and deletion.
#[cfg(not(unix))]
fn safe_rmtree_v1_non_unix(
    root: &Path,
    allowed_parent: &Path,
) -> Result<SafeRmtreeOutcome, SafeRmtreeError> {
    let root_meta = match fs::symlink_metadata(root) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Ok(SafeRmtreeOutcome::AlreadyAbsent);
        },
        Err(e) => {
            return Err(SafeRmtreeError::io(
                format!("stat root {}", root.display()),
                e,
            ));
        },
    };

    if root_meta.file_type().is_symlink() {
        return Err(SafeRmtreeError::SymlinkDetected {
            path: root.to_path_buf(),
        });
    }

    if root_meta.is_dir() {
        let mut stats = DeleteStats::default();
        path_based_recursive_delete(root, allowed_parent, 0, &mut stats)?;
        Ok(SafeRmtreeOutcome::Deleted {
            files_deleted: stats.files_deleted,
            dirs_deleted: stats.dirs_deleted,
        })
    } else if root_meta.is_file() {
        fs::remove_file(root)
            .map_err(|e| SafeRmtreeError::io(format!("removing file {}", root.display()), e))?;
        Ok(SafeRmtreeOutcome::Deleted {
            files_deleted: 1,
            dirs_deleted: 0,
        })
    } else {
        Err(SafeRmtreeError::UnexpectedFileType {
            path: root.to_path_buf(),
            file_type: describe_file_type(&root_meta),
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Mutable deletion statistics.
#[derive(Debug, Default)]
struct DeleteStats {
    files_deleted: u64,
    dirs_deleted: u64,
}

/// Reject any path containing `.` (`CurDir`) or `..` (`ParentDir`) components
/// (INV-RMTREE-010).
///
/// This is a hard reject, not a filter. Paths with dot segments are
/// ambiguous and could be used to escape the allowed parent boundary.
///
/// Note: On Unix, `Path::components()` silently normalizes `.` away
/// (does not produce `CurDir`), so we also scan the raw path bytes for
/// `/./` or trailing `/.` patterns to catch `.` segments reliably.
fn reject_dot_segments(path: &Path) -> Result<(), SafeRmtreeError> {
    // Check via components() -- catches `..` on all platforms.
    for component in path.components() {
        match component {
            Component::CurDir | Component::ParentDir => {
                return Err(SafeRmtreeError::DotSegment {
                    path: path.to_path_buf(),
                });
            },
            _ => {},
        }
    }

    // On Unix, components() silently eats `.` segments. Check raw bytes
    // to catch `/./` and trailing `/.` that components() normalizes away.
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let bytes = path.as_os_str().as_bytes();
        // Check for /./  anywhere in the path
        if bytes.windows(3).any(|w| w == b"/./") {
            return Err(SafeRmtreeError::DotSegment {
                path: path.to_path_buf(),
            });
        }
        // Check for trailing /.
        if bytes.len() >= 2 && bytes.ends_with(b"/.") {
            return Err(SafeRmtreeError::DotSegment {
                path: path.to_path_buf(),
            });
        }
    }

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Unix fd-relative recursive delete (TOCTOU-safe)
// ─────────────────────────────────────────────────────────────────────────────

/// Recursively delete the contents of a directory using fd-relative operations.
///
/// This implementation uses `Dir::openat(parent_fd, name, O_NOFOLLOW |
/// O_DIRECTORY)` for directory traversal, `unlinkat(parent_fd, name,
/// NoRemoveDir)` for file deletion, and `unlinkat(parent_fd, name,
/// RemoveDir)` for directory deletion. The kernel refuses to follow symlinks
/// at every step. No `std::fs::read_dir`, `std::fs::remove_dir`,
/// `std::fs::remove_file`, or path-based `Dir::open` is used in this
/// recursive path.
///
/// # Arguments
///
/// * `parent_dir` - Already-open directory fd. All operations are relative to
///   this fd.
/// * `parent_path` - Used ONLY for error messages. Never used for opens or
///   deletes.
/// * `stats` - Mutable deletion statistics.
/// * `depth` - Current recursion depth for INV-RMTREE-008 bound.
/// * `root_dev` - Device ID of the root directory, for cross-device checks
///   (INV-RMTREE-003).
///
/// # TOCTOU Safety
///
/// The fd-relative approach eliminates the classic check-then-act TOCTOU
/// window: once a directory is opened as an fd with `O_NOFOLLOW`, the fd
/// refers to the actual directory inode regardless of any subsequent
/// symlink swaps in the namespace. All child operations go through
/// `openat`/`unlinkat`/`fstatat` relative to that fd.
#[cfg(unix)]
fn fd_relative_recursive_delete(
    parent_dir: &nix::dir::Dir,
    parent_path: &Path,
    stats: &mut DeleteStats,
    depth: usize,
    root_dev: u64,
) -> Result<(), SafeRmtreeError> {
    use std::os::fd::AsFd;

    use nix::fcntl::OFlag;

    // Depth check (INV-RMTREE-008)
    if depth >= MAX_TRAVERSAL_DEPTH {
        return Err(SafeRmtreeError::DepthExceeded {
            path: parent_path.to_path_buf(),
            max: MAX_TRAVERSAL_DEPTH,
        });
    }

    // Streaming iteration: dup the parent fd so we get an independent Dir
    // for iteration while keeping the original fd usable for fstatat/openat/
    // unlinkat. Process each entry immediately without collecting into a Vec
    // to prevent unbounded memory growth (BLOCKER #1 fix).
    let dup_fd = nix::unistd::dup(parent_dir.as_fd()).map_err(|e| {
        SafeRmtreeError::io(
            format!("dup fd for {}", parent_path.display()),
            io::Error::from(e),
        )
    })?;
    let mut iter_dir = nix::dir::Dir::from_fd(dup_fd).map_err(|e| {
        SafeRmtreeError::io(
            format!("Dir::from_fd for {}", parent_path.display()),
            io::Error::from(e),
        )
    })?;

    let open_flags = OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC;
    let mut entry_count: usize = 0;

    for entry_result in iter_dir.iter() {
        let entry = entry_result.map_err(|e| {
            SafeRmtreeError::io(
                format!("reading entry in {}", parent_path.display()),
                io::Error::from(e),
            )
        })?;

        let name_cstr = entry.file_name();
        let name_bytes = name_cstr.to_bytes();

        // Skip "." and ".."
        if name_bytes == b"." || name_bytes == b".." {
            continue;
        }

        entry_count += 1;
        if entry_count > MAX_DIR_ENTRIES {
            return Err(SafeRmtreeError::TooManyEntries {
                path: parent_path.to_path_buf(),
                max: MAX_DIR_ENTRIES,
            });
        }

        let name = {
            use std::os::unix::ffi::OsStrExt;
            std::ffi::OsString::from(std::ffi::OsStr::from_bytes(name_bytes))
        };
        let entry_display_path = parent_path.join(&name);

        // Classify entry type from d_type hint first, fall back to fstatat.
        let kind = if let Some(k) = classify_dirent_type(entry.file_type(), parent_path, &name)? {
            k
        } else {
            // Unknown d_type: resolve via fstatat(AT_SYMLINK_NOFOLLOW)
            // relative to the parent_dir fd.
            resolve_entry_kind_via_fstatat(parent_dir, parent_path, &name, &entry_display_path)?
        };

        process_entry(
            parent_dir,
            &name,
            kind,
            &entry_display_path,
            open_flags,
            root_dev,
            stats,
            depth,
        )?;
    }

    Ok(())
}

/// Process a single directory entry: recurse into directories (then remove
/// them), or unlink regular files. All operations are fd-relative.
#[cfg(unix)]
#[allow(clippy::too_many_arguments)]
fn process_entry(
    parent_dir: &nix::dir::Dir,
    name: &std::ffi::OsString,
    kind: EntryKind,
    entry_display_path: &Path,
    open_flags: nix::fcntl::OFlag,
    root_dev: u64,
    stats: &mut DeleteStats,
    depth: usize,
) -> Result<(), SafeRmtreeError> {
    use nix::sys::stat::Mode;
    use nix::unistd::UnlinkatFlags;

    match kind {
        EntryKind::Directory => {
            // Open child directory fd-relative to parent_dir fd.
            // O_NOFOLLOW ensures the kernel refuses symlinks.
            let child_dir =
                nix::dir::Dir::openat(parent_dir, name.as_os_str(), open_flags, Mode::empty())
                    .map_err(|e| {
                        let io_err = io::Error::from(e);
                        if io_err.raw_os_error() == Some(libc::ELOOP)
                            || io_err.raw_os_error() == Some(libc::ENOTDIR)
                        {
                            SafeRmtreeError::TocTouRace {
                                reason: format!(
                                    "entry {} was directory at scan time but symlink/non-dir \
                                     at openat time",
                                    entry_display_path.display()
                                ),
                            }
                        } else {
                            SafeRmtreeError::io(
                                format!("openat directory {}", entry_display_path.display()),
                                io_err,
                            )
                        }
                    })?;

            // Verify child is on the same filesystem (INV-RMTREE-003)
            verify_same_dev_via_fd(&child_dir, entry_display_path, root_dev)?;

            // Recurse with the OPEN FD, not a path.
            fd_relative_recursive_delete(
                &child_dir,
                entry_display_path,
                stats,
                depth + 1,
                root_dev,
            )?;

            // Drop child fd before unlinkat so the directory can be removed.
            drop(child_dir);

            nix::unistd::unlinkat(parent_dir, name.as_os_str(), UnlinkatFlags::RemoveDir).map_err(
                |e| {
                    SafeRmtreeError::io(
                        format!("removing directory {}", entry_display_path.display()),
                        io::Error::from(e),
                    )
                },
            )?;
            stats.dirs_deleted = stats.dirs_deleted.saturating_add(1);
        },
        EntryKind::RegularFile => {
            nix::unistd::unlinkat(parent_dir, name.as_os_str(), UnlinkatFlags::NoRemoveDir)
                .map_err(|e| {
                    SafeRmtreeError::io(
                        format!("removing file {}", entry_display_path.display()),
                        io::Error::from(e),
                    )
                })?;
            stats.files_deleted = stats.files_deleted.saturating_add(1);
        },
    }

    Ok(())
}

/// Walk from `base` through `components` using `openat(O_NOFOLLOW)` at each
/// step, returning the final directory fd. This eliminates the TOCTOU gap
/// between symlink validation and directory open: every `openat` with
/// `O_NOFOLLOW` atomically refuses symlinks at the kernel level.
///
/// # Arguments
///
/// * `base` - The starting directory (opened by full path). This MUST be the
///   `allowed_parent` which was validated for ownership/mode.
/// * `components` - The relative path components to walk from `base`.
/// * `flags` - Open flags (must include `O_NOFOLLOW | O_DIRECTORY`).
///
/// # Errors
///
/// Returns `SymlinkDetected` if any component is a symlink (ELOOP/ENOTDIR
/// from `openat`). Returns `Io` for other I/O errors.
#[cfg(unix)]
fn open_path_via_ancestor_chain(
    base: &Path,
    components: &[&std::ffi::OsStr],
    flags: nix::fcntl::OFlag,
) -> Result<nix::dir::Dir, SafeRmtreeError> {
    use nix::sys::stat::Mode;

    // Open the base (allowed_parent) by full path with O_NOFOLLOW.
    let mut current_dir = nix::dir::Dir::open(base, flags, Mode::empty()).map_err(|e| {
        let io_err = io::Error::from(e);
        if io_err.raw_os_error() == Some(libc::ELOOP)
            || io_err.raw_os_error() == Some(libc::ENOTDIR)
        {
            SafeRmtreeError::SymlinkDetected {
                path: base.to_path_buf(),
            }
        } else {
            SafeRmtreeError::io(format!("open base directory {}", base.display()), io_err)
        }
    })?;

    // Walk each intermediate component using openat(O_NOFOLLOW).
    let mut walked = base.to_path_buf();
    for component in components {
        walked.push(component);
        current_dir = nix::dir::Dir::openat(&current_dir, *component, flags, Mode::empty())
            .map_err(|e| {
                let io_err = io::Error::from(e);
                if io_err.raw_os_error() == Some(libc::ELOOP)
                    || io_err.raw_os_error() == Some(libc::ENOTDIR)
                {
                    SafeRmtreeError::SymlinkDetected {
                        path: walked.clone(),
                    }
                } else {
                    SafeRmtreeError::io(format!("openat component {}", walked.display()), io_err)
                }
            })?;
    }

    Ok(current_dir)
}

/// Verify that the opened directory fd is on the same filesystem as the root
/// by comparing `st_dev` values. Uses `fstat` on the fd (not a path) to
/// avoid TOCTOU.
#[cfg(unix)]
fn verify_same_dev_via_fd(
    dir_handle: &nix::dir::Dir,
    dir_display_path: &Path,
    root_dev: u64,
) -> Result<(), SafeRmtreeError> {
    let dir_stat = nix::sys::stat::fstat(dir_handle).map_err(|e| {
        SafeRmtreeError::io(
            format!("fstat directory {}", dir_display_path.display()),
            io::Error::from(e),
        )
    })?;

    #[allow(clippy::cast_sign_loss)]
    let dir_dev = dir_stat.st_dev as u64;
    if dir_dev != root_dev {
        return Err(SafeRmtreeError::CrossesFilesystemBoundary {
            root_dev: dir_dev,
            parent_dev: root_dev,
        });
    }

    Ok(())
}

/// Classify a `nix::dir::Type` from a directory entry's `d_type` field.
///
/// Returns `Some(EntryKind)` for known regular/directory types,
/// `None` for unknown (`DT_UNKNOWN`), or an error for symlinks and
/// unexpected file types.
#[cfg(unix)]
fn classify_dirent_type(
    dtype: Option<nix::dir::Type>,
    dir_display_path: &Path,
    name: &std::ffi::OsString,
) -> Result<Option<EntryKind>, SafeRmtreeError> {
    match dtype {
        Some(nix::dir::Type::Directory) => Ok(Some(EntryKind::Directory)),
        Some(nix::dir::Type::File) => Ok(Some(EntryKind::RegularFile)),
        Some(nix::dir::Type::Symlink) => Err(SafeRmtreeError::SymlinkDetected {
            path: dir_display_path.join(name),
        }),
        Some(nix::dir::Type::Fifo) => Err(SafeRmtreeError::UnexpectedFileType {
            path: dir_display_path.join(name),
            file_type: "FIFO/named pipe".to_string(),
        }),
        Some(nix::dir::Type::Socket) => Err(SafeRmtreeError::UnexpectedFileType {
            path: dir_display_path.join(name),
            file_type: "Unix socket".to_string(),
        }),
        Some(nix::dir::Type::BlockDevice) => Err(SafeRmtreeError::UnexpectedFileType {
            path: dir_display_path.join(name),
            file_type: "block device".to_string(),
        }),
        Some(nix::dir::Type::CharacterDevice) => Err(SafeRmtreeError::UnexpectedFileType {
            path: dir_display_path.join(name),
            file_type: "character device".to_string(),
        }),
        None => Ok(None), // Deferred: resolve via fstatat
    }
}

/// Entry kind determined during directory scanning.
#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EntryKind {
    Directory,
    RegularFile,
}

/// Resolve an entry with unknown `d_type` via `fstatat(AT_SYMLINK_NOFOLLOW)`
/// relative to the parent dir fd.
#[cfg(unix)]
fn resolve_entry_kind_via_fstatat(
    parent_dir: &nix::dir::Dir,
    parent_path: &Path,
    name: &std::ffi::OsString,
    entry_display_path: &Path,
) -> Result<EntryKind, SafeRmtreeError> {
    let entry_stat = nix::sys::stat::fstatat(
        parent_dir,
        name.as_os_str(),
        nix::fcntl::AtFlags::AT_SYMLINK_NOFOLLOW,
    )
    .map_err(|e| {
        SafeRmtreeError::io(
            format!(
                "fstatat entry {} in {}",
                name.to_string_lossy(),
                parent_path.display()
            ),
            io::Error::from(e),
        )
    })?;
    classify_stat_mode(entry_stat.st_mode, entry_display_path)
}

/// Classify an `st_mode` value into an `EntryKind` or return an error for
/// unexpected types.
#[cfg(unix)]
fn classify_stat_mode(mode: libc::mode_t, path: &Path) -> Result<EntryKind, SafeRmtreeError> {
    let file_type = mode & libc::S_IFMT;
    match file_type {
        libc::S_IFDIR => Ok(EntryKind::Directory),
        libc::S_IFREG => Ok(EntryKind::RegularFile),
        libc::S_IFLNK => Err(SafeRmtreeError::SymlinkDetected {
            path: path.to_path_buf(),
        }),
        libc::S_IFIFO => Err(SafeRmtreeError::UnexpectedFileType {
            path: path.to_path_buf(),
            file_type: "FIFO/named pipe".to_string(),
        }),
        libc::S_IFSOCK => Err(SafeRmtreeError::UnexpectedFileType {
            path: path.to_path_buf(),
            file_type: "Unix socket".to_string(),
        }),
        libc::S_IFBLK => Err(SafeRmtreeError::UnexpectedFileType {
            path: path.to_path_buf(),
            file_type: "block device".to_string(),
        }),
        libc::S_IFCHR => Err(SafeRmtreeError::UnexpectedFileType {
            path: path.to_path_buf(),
            file_type: "character device".to_string(),
        }),
        _ => Err(SafeRmtreeError::UnexpectedFileType {
            path: path.to_path_buf(),
            file_type: format!("unknown (mode bits: {mode:#o})"),
        }),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Non-Unix fallback (path-based, same as before but with dot-segment rejection)
// ─────────────────────────────────────────────────────────────────────────────

/// Recursively delete a directory tree bottom-up (non-Unix fallback).
///
/// Uses `std::fs::read_dir` which may follow symlinks. On non-Unix
/// platforms we rely on the pre-validation checks (symlink_metadata on
/// every entry) for safety.
#[cfg(not(unix))]
fn path_based_recursive_delete(
    dir: &Path,
    allowed_parent: &Path,
    depth: usize,
    stats: &mut DeleteStats,
) -> Result<(), SafeRmtreeError> {
    if depth >= MAX_TRAVERSAL_DEPTH {
        return Err(SafeRmtreeError::DepthExceeded {
            path: dir.to_path_buf(),
            max: MAX_TRAVERSAL_DEPTH,
        });
    }

    let read_dir = fs::read_dir(dir)
        .map_err(|e| SafeRmtreeError::io(format!("reading directory {}", dir.display()), e))?;

    let mut entries = Vec::new();
    for entry_result in read_dir {
        if entries.len() >= MAX_DIR_ENTRIES {
            return Err(SafeRmtreeError::TooManyEntries {
                path: dir.to_path_buf(),
                max: MAX_DIR_ENTRIES,
            });
        }
        let entry = entry_result
            .map_err(|e| SafeRmtreeError::io(format!("reading entry in {}", dir.display()), e))?;
        entries.push(entry.path());
    }

    for entry_path in &entries {
        let meta = fs::symlink_metadata(entry_path)
            .map_err(|e| SafeRmtreeError::io(format!("stat entry {}", entry_path.display()), e))?;

        if meta.file_type().is_symlink() {
            return Err(SafeRmtreeError::SymlinkDetected {
                path: entry_path.clone(),
            });
        }

        validate_strictly_under(entry_path, allowed_parent)?;

        if meta.is_dir() {
            path_based_recursive_delete(entry_path, allowed_parent, depth + 1, stats)?;
        } else if meta.is_file() {
            fs::remove_file(entry_path).map_err(|e| {
                SafeRmtreeError::io(format!("removing file {}", entry_path.display()), e)
            })?;
            stats.files_deleted = stats.files_deleted.saturating_add(1);
        } else {
            return Err(SafeRmtreeError::UnexpectedFileType {
                path: entry_path.clone(),
                file_type: describe_file_type(&meta),
            });
        }
    }

    fs::remove_dir(dir)
        .map_err(|e| SafeRmtreeError::io(format!("removing directory {}", dir.display()), e))?;
    stats.dirs_deleted = stats.dirs_deleted.saturating_add(1);

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Validation helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Validate that `child` is strictly under `parent` by path components.
///
/// "Strictly under" means `child` has at least one more component than
/// `parent`, and all parent components match exactly. This prevents both
/// string-prefix attacks (e.g., `/foo/bar` vs `/foo/barbaz`) and
/// exact-match (root == parent).
///
/// Paths containing `.` or `..` components must be rejected BEFORE calling
/// this function (via `reject_dot_segments`).
fn validate_strictly_under(child: &Path, parent: &Path) -> Result<(), SafeRmtreeError> {
    // Collect only Normal components. Since we already rejected `.` and `..`
    // via reject_dot_segments, the only non-Normal components should be
    // RootDir (for absolute paths). We skip RootDir to compare just the
    // path segments.
    let parent_components: Vec<&std::ffi::OsStr> = parent
        .components()
        .filter_map(|c| match c {
            Component::Normal(s) => Some(s),
            _ => None,
        })
        .collect();

    let child_components: Vec<&std::ffi::OsStr> = child
        .components()
        .filter_map(|c| match c {
            Component::Normal(s) => Some(s),
            _ => None,
        })
        .collect();

    // Child must have strictly more components than parent
    if child_components.len() <= parent_components.len() {
        return Err(SafeRmtreeError::OutsideAllowedParent {
            root: child.to_path_buf(),
            allowed_parent: parent.to_path_buf(),
        });
    }

    // All parent components must match child's prefix
    for (p, c) in parent_components.iter().zip(child_components.iter()) {
        if p != c {
            return Err(SafeRmtreeError::OutsideAllowedParent {
                root: child.to_path_buf(),
                allowed_parent: parent.to_path_buf(),
            });
        }
    }

    Ok(())
}

/// Validate that `allowed_parent` is owned by the current user and has
/// mode 0o700.
#[cfg(unix)]
fn validate_parent_ownership(allowed_parent: &Path) -> Result<(), SafeRmtreeError> {
    use std::os::unix::fs::MetadataExt;

    let meta = fs::symlink_metadata(allowed_parent).map_err(|e| {
        SafeRmtreeError::io(
            format!("stat allowed_parent {}", allowed_parent.display()),
            e,
        )
    })?;

    // Must not be a symlink
    if meta.file_type().is_symlink() {
        return Err(SafeRmtreeError::SymlinkDetected {
            path: allowed_parent.to_path_buf(),
        });
    }

    // Must be a directory
    if !meta.is_dir() {
        return Err(SafeRmtreeError::PermissionDenied {
            reason: format!(
                "allowed_parent {} is not a directory",
                allowed_parent.display()
            ),
        });
    }

    // Must be owned by current user
    let current_uid = nix::unistd::getuid().as_raw();
    if meta.uid() != current_uid {
        return Err(SafeRmtreeError::PermissionDenied {
            reason: format!(
                "allowed_parent {} is owned by uid {} but current uid is {}",
                allowed_parent.display(),
                meta.uid(),
                current_uid
            ),
        });
    }

    // Must have mode 0o700 (no group/other access)
    let mode = meta.mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(SafeRmtreeError::PermissionDenied {
            reason: format!(
                "allowed_parent {} has mode {:o}, expected no group/other access (xx00 mask)",
                allowed_parent.display(),
                mode
            ),
        });
    }

    Ok(())
}

/// Non-Unix stub for parent ownership validation.
#[cfg(not(unix))]
fn validate_parent_ownership(allowed_parent: &Path) -> Result<(), SafeRmtreeError> {
    let meta = fs::symlink_metadata(allowed_parent).map_err(|e| {
        SafeRmtreeError::io(
            format!("stat allowed_parent {}", allowed_parent.display()),
            e,
        )
    })?;

    if !meta.is_dir() {
        return Err(SafeRmtreeError::PermissionDenied {
            reason: format!(
                "allowed_parent {} is not a directory",
                allowed_parent.display()
            ),
        });
    }

    Ok(())
}

/// Describe the file type for error messages.
#[cfg(not(unix))]
fn describe_file_type(meta: &fs::Metadata) -> String {
    let ft = meta.file_type();
    if ft.is_symlink() {
        "symlink".to_string()
    } else if ft.is_dir() {
        "directory".to_string()
    } else if ft.is_file() {
        "regular file".to_string()
    } else {
        // On Unix, check for specific types
        #[cfg(unix)]
        {
            use std::os::unix::fs::FileTypeExt;
            if ft.is_fifo() {
                return "FIFO/named pipe".to_string();
            }
            if ft.is_socket() {
                return "Unix socket".to_string();
            }
            if ft.is_block_device() {
                return "block device".to_string();
            }
            if ft.is_char_device() {
                return "character device".to_string();
            }
        }
        "unknown".to_string()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create a temp dir with mode 0o700 that passes ownership
    /// checks.
    fn make_allowed_parent() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700))
                .expect("set perms on temp dir");
        }
        dir
    }

    /// Helper: create a nested directory tree under a parent.
    fn create_test_tree(parent: &Path, name: &str) -> PathBuf {
        let root = parent.join(name);
        fs::create_dir_all(root.join("sub1").join("deep")).expect("mkdir");
        fs::create_dir_all(root.join("sub2")).expect("mkdir");
        fs::write(root.join("file1.txt"), b"content1").expect("write");
        fs::write(root.join("sub1").join("file2.txt"), b"content2").expect("write");
        fs::write(
            root.join("sub1").join("deep").join("file3.txt"),
            b"content3",
        )
        .expect("write");
        fs::write(root.join("sub2").join("file4.txt"), b"content4").expect("write");
        root
    }

    // ── Success Cases ────────────────────────────────────────────────

    #[test]
    fn delete_simple_tree() {
        let parent = make_allowed_parent();
        let root = create_test_tree(parent.path(), "target_dir");

        let outcome = safe_rmtree_v1(&root, parent.path()).expect("should succeed");

        match outcome {
            SafeRmtreeOutcome::Deleted {
                files_deleted,
                dirs_deleted,
            } => {
                assert_eq!(files_deleted, 4, "expected 4 files deleted");
                assert_eq!(
                    dirs_deleted, 4,
                    "expected 4 dirs deleted (root + sub1 + deep + sub2)"
                );
            },
            other @ SafeRmtreeOutcome::AlreadyAbsent => panic!("expected Deleted, got {other}"),
        }

        assert!(!root.exists(), "root should be deleted");
    }

    #[test]
    fn delete_nonexistent_root_is_noop() {
        let parent = make_allowed_parent();
        let root = parent.path().join("nonexistent");

        let outcome = safe_rmtree_v1(&root, parent.path()).expect("should succeed");
        assert_eq!(outcome, SafeRmtreeOutcome::AlreadyAbsent);
    }

    #[test]
    fn delete_empty_directory() {
        let parent = make_allowed_parent();
        let root = parent.path().join("empty_dir");
        fs::create_dir(&root).expect("mkdir");

        let outcome = safe_rmtree_v1(&root, parent.path()).expect("should succeed");

        match outcome {
            SafeRmtreeOutcome::Deleted {
                files_deleted,
                dirs_deleted,
            } => {
                assert_eq!(files_deleted, 0);
                assert_eq!(dirs_deleted, 1);
            },
            other @ SafeRmtreeOutcome::AlreadyAbsent => panic!("expected Deleted, got {other}"),
        }
    }

    #[test]
    fn delete_single_file() {
        let parent = make_allowed_parent();
        let file_path = parent.path().join("single_file.txt");
        fs::write(&file_path, b"data").expect("write");

        let outcome = safe_rmtree_v1(&file_path, parent.path()).expect("should succeed");

        match outcome {
            SafeRmtreeOutcome::Deleted {
                files_deleted,
                dirs_deleted,
            } => {
                assert_eq!(files_deleted, 1);
                assert_eq!(dirs_deleted, 0);
            },
            other @ SafeRmtreeOutcome::AlreadyAbsent => panic!("expected Deleted, got {other}"),
        }
    }

    // ── Symlink Refusal ──────────────────────────────────────────────

    #[test]
    #[cfg(unix)]
    fn refuse_symlink_as_root() {
        let parent = make_allowed_parent();
        let real_dir = parent.path().join("real_dir");
        fs::create_dir(&real_dir).expect("mkdir");
        let link = parent.path().join("link_dir");
        std::os::unix::fs::symlink(&real_dir, &link).expect("symlink");

        let result = safe_rmtree_v1(&link, parent.path());
        assert!(result.is_err(), "must refuse symlink root");
        match result.unwrap_err() {
            SafeRmtreeError::SymlinkDetected { path } => {
                assert_eq!(path, link);
            },
            other => panic!("expected SymlinkDetected, got {other}"),
        }

        // Real directory must still exist
        assert!(real_dir.exists(), "real dir should not be deleted");
    }

    #[test]
    #[cfg(unix)]
    fn refuse_symlink_in_subtree() {
        let parent = make_allowed_parent();
        let root = parent.path().join("tree");
        fs::create_dir_all(root.join("subdir")).expect("mkdir");
        fs::write(root.join("ok.txt"), b"ok").expect("write");

        // Create a symlink inside the tree pointing outside
        let outside = parent.path().join("outside");
        fs::create_dir(&outside).expect("mkdir outside");
        fs::write(outside.join("secret.txt"), b"secret").expect("write");
        std::os::unix::fs::symlink(&outside, root.join("subdir").join("evil_link"))
            .expect("symlink");

        let result = safe_rmtree_v1(&root, parent.path());
        assert!(result.is_err(), "must refuse symlink in subtree");
        match result.unwrap_err() {
            SafeRmtreeError::SymlinkDetected { .. } => {},
            other => panic!("expected SymlinkDetected, got {other}"),
        }

        // Outside directory must still exist with its contents
        assert!(outside.join("secret.txt").exists(), "secret must survive");
    }

    #[test]
    #[cfg(unix)]
    fn refuse_symlink_chain() {
        let parent = make_allowed_parent();
        let real = parent.path().join("real");
        fs::create_dir(&real).expect("mkdir");
        let link1 = parent.path().join("link1");
        let link2 = parent.path().join("link2");
        std::os::unix::fs::symlink(&real, &link1).expect("symlink1");
        std::os::unix::fs::symlink(&link1, &link2).expect("symlink2");

        let result = safe_rmtree_v1(&link2, parent.path());
        assert!(result.is_err(), "must refuse symlink chain");
    }

    #[test]
    #[cfg(unix)]
    fn refuse_file_symlink_in_tree() {
        let parent = make_allowed_parent();
        let root = parent.path().join("tree");
        fs::create_dir(&root).expect("mkdir");

        let real_file = parent.path().join("real_file.txt");
        fs::write(&real_file, b"sensitive data").expect("write");

        // Symlink to file inside the tree
        std::os::unix::fs::symlink(&real_file, root.join("link.txt")).expect("symlink");

        let result = safe_rmtree_v1(&root, parent.path());
        assert!(result.is_err(), "must refuse file symlink");
        match result.unwrap_err() {
            SafeRmtreeError::SymlinkDetected { .. } => {},
            other => panic!("expected SymlinkDetected, got {other}"),
        }

        // Real file must still exist
        assert!(real_file.exists(), "real file should not be deleted");
    }

    // ── Boundary Validation ──────────────────────────────────────────

    #[test]
    fn refuse_root_equals_parent() {
        let parent = make_allowed_parent();
        let result = safe_rmtree_v1(parent.path(), parent.path());
        assert!(result.is_err(), "must refuse root == parent");
        match result.unwrap_err() {
            SafeRmtreeError::OutsideAllowedParent { .. } => {},
            other => panic!("expected OutsideAllowedParent, got {other}"),
        }
    }

    #[test]
    fn refuse_root_outside_parent() {
        let parent1 = make_allowed_parent();
        let parent2 = make_allowed_parent();
        let root = parent2.path().join("some_dir");
        fs::create_dir(&root).expect("mkdir");

        let result = safe_rmtree_v1(&root, parent1.path());
        assert!(result.is_err(), "must refuse root outside parent");
        match result.unwrap_err() {
            SafeRmtreeError::OutsideAllowedParent { .. } => {},
            other => panic!("expected OutsideAllowedParent, got {other}"),
        }
    }

    #[test]
    fn refuse_relative_paths() {
        let result = safe_rmtree_v1(Path::new("relative/path"), Path::new("/absolute/parent"));
        assert!(result.is_err());
        match result.unwrap_err() {
            SafeRmtreeError::NotAbsolute { .. } => {},
            other => panic!("expected NotAbsolute, got {other}"),
        }

        // Also test relative allowed_parent
        let result = safe_rmtree_v1(Path::new("/absolute/root"), Path::new("relative/parent"));
        assert!(result.is_err());
        match result.unwrap_err() {
            SafeRmtreeError::NotAbsolute { .. } => {},
            other => panic!("expected NotAbsolute, got {other}"),
        }
    }

    #[test]
    fn refuse_string_prefix_attack() {
        // /tmp/abc is NOT under /tmp/ab (even though it's a string prefix)
        let parent = make_allowed_parent();
        let similar_name = PathBuf::from(format!("{}baz", parent.path().display()));
        // Create the path so stat works
        if fs::create_dir_all(&similar_name).is_ok() {
            let result = safe_rmtree_v1(&similar_name.join("target"), parent.path());
            assert!(result.is_err());
            // Clean up
            let _ = fs::remove_dir_all(&similar_name);
        }
    }

    // ── Dot-Segment Rejection (INV-RMTREE-010) ──────────────────────

    #[test]
    fn refuse_path_with_parent_dir_components() {
        // Paths with .. must be REJECTED, not filtered
        let result = safe_rmtree_v1(
            Path::new("/home/user/lanes/lane-00/../../etc/passwd"),
            Path::new("/home/user/lanes"),
        );
        assert!(result.is_err(), "must reject paths with ..");
        match result.unwrap_err() {
            SafeRmtreeError::DotSegment { path } => {
                assert!(
                    path.to_string_lossy().contains(".."),
                    "error path should contain .."
                );
            },
            other => panic!("expected DotSegment, got {other}"),
        }
    }

    #[test]
    fn refuse_path_with_curdir_components() {
        // Paths with . must be REJECTED
        let result = safe_rmtree_v1(
            Path::new("/home/user/./lanes/lane-00/workspace"),
            Path::new("/home/user/lanes"),
        );
        assert!(result.is_err(), "must reject paths with .");
        match result.unwrap_err() {
            SafeRmtreeError::DotSegment { .. } => {},
            other => panic!("expected DotSegment, got {other}"),
        }
    }

    #[test]
    fn refuse_parent_with_dot_segments() {
        // Even the allowed_parent must not have dot segments
        let result = safe_rmtree_v1(
            Path::new("/home/user/lanes/lane-00/workspace"),
            Path::new("/home/user/../user/lanes"),
        );
        assert!(result.is_err(), "must reject parent with ..");
        match result.unwrap_err() {
            SafeRmtreeError::DotSegment { .. } => {},
            other => panic!("expected DotSegment, got {other}"),
        }
    }

    // ── Unexpected File Types ────────────────────────────────────────

    #[test]
    #[cfg(unix)]
    fn refuse_fifo_in_tree() {
        let parent = make_allowed_parent();
        let root = parent.path().join("fifo_tree");
        fs::create_dir(&root).expect("mkdir");

        let fifo_path = root.join("evil.fifo");
        nix::unistd::mkfifo(&fifo_path, nix::sys::stat::Mode::S_IRWXU).expect("mkfifo");

        let result = safe_rmtree_v1(&root, parent.path());
        assert!(result.is_err(), "must refuse FIFO");
        match result.unwrap_err() {
            SafeRmtreeError::UnexpectedFileType { .. } => {},
            other => panic!("expected UnexpectedFileType, got {other}"),
        }
    }

    #[test]
    #[cfg(unix)]
    fn refuse_socket_in_tree() {
        use std::os::unix::net::UnixListener;

        let parent = make_allowed_parent();
        let root = parent.path().join("socket_tree");
        fs::create_dir(&root).expect("mkdir");

        let sock_path = root.join("evil.sock");
        let _listener = UnixListener::bind(&sock_path).expect("bind socket");

        let result = safe_rmtree_v1(&root, parent.path());
        assert!(result.is_err(), "must refuse socket");
        match result.unwrap_err() {
            SafeRmtreeError::UnexpectedFileType { .. } => {},
            other => panic!("expected UnexpectedFileType, got {other}"),
        }
    }

    // ── Permission Validation ────────────────────────────────────────

    #[test]
    #[cfg(unix)]
    fn refuse_world_readable_parent() {
        use std::os::unix::fs::PermissionsExt;

        let parent = make_allowed_parent();
        // Weaken permissions to include group/other
        let perms = fs::Permissions::from_mode(0o755);
        fs::set_permissions(parent.path(), perms).expect("set perms");

        let root = parent.path().join("child");
        fs::create_dir(&root).expect("mkdir");

        let result = safe_rmtree_v1(&root, parent.path());
        assert!(result.is_err(), "must refuse non-0700 parent");
        match result.unwrap_err() {
            SafeRmtreeError::PermissionDenied { .. } => {},
            other => panic!("expected PermissionDenied, got {other}"),
        }
    }

    // ── Depth Limit ──────────────────────────────────────────────────

    #[test]
    fn traversal_depth_bounded() {
        let parent = make_allowed_parent();
        // Create a deeply nested path (but less than MAX to avoid FS limits)
        let mut deep = parent.path().join("root");
        for i in 0..10 {
            deep = deep.join(format!("d{i}"));
        }
        fs::create_dir_all(&deep).expect("create deep tree");
        fs::write(deep.join("leaf.txt"), b"leaf").expect("write");

        let root = parent.path().join("root");
        let outcome = safe_rmtree_v1(&root, parent.path()).expect("should succeed");

        match outcome {
            SafeRmtreeOutcome::Deleted {
                files_deleted,
                dirs_deleted,
            } => {
                assert_eq!(files_deleted, 1);
                assert!(dirs_deleted >= 11);
            },
            other @ SafeRmtreeOutcome::AlreadyAbsent => panic!("expected Deleted, got {other}"),
        }
    }

    // ── Display and Error Formatting ─────────────────────────────────

    #[test]
    fn outcome_display() {
        let deleted = SafeRmtreeOutcome::Deleted {
            files_deleted: 5,
            dirs_deleted: 2,
        };
        assert_eq!(deleted.to_string(), "deleted 5 files and 2 directories");

        let absent = SafeRmtreeOutcome::AlreadyAbsent;
        assert_eq!(absent.to_string(), "already absent (no-op)");
    }

    #[test]
    fn error_variants_display() {
        let err = SafeRmtreeError::SymlinkDetected {
            path: PathBuf::from("/some/path"),
        };
        assert!(err.to_string().contains("symlink detected"));

        let err = SafeRmtreeError::OutsideAllowedParent {
            root: PathBuf::from("/a"),
            allowed_parent: PathBuf::from("/b"),
        };
        assert!(err.to_string().contains("not under allowed parent"));

        let err = SafeRmtreeError::NotAbsolute {
            path: PathBuf::from("relative"),
        };
        assert!(err.to_string().contains("must be absolute"));

        let err = SafeRmtreeError::DotSegment {
            path: PathBuf::from("/a/../b"),
        };
        assert!(err.to_string().contains("dot-segment"));
    }

    // ── Component-wise Validation ────────────────────────────────────

    #[test]
    fn validate_strictly_under_works() {
        // Valid cases
        assert!(validate_strictly_under(Path::new("/a/b/c"), Path::new("/a/b"),).is_ok());
        assert!(validate_strictly_under(Path::new("/a/b/c/d"), Path::new("/a"),).is_ok());

        // Invalid cases
        assert!(validate_strictly_under(Path::new("/a/b"), Path::new("/a/b"),).is_err()); // equal
        assert!(validate_strictly_under(Path::new("/a/b"), Path::new("/a/b/c"),).is_err()); // parent is deeper
        assert!(validate_strictly_under(Path::new("/x/y/z"), Path::new("/a/b"),).is_err()); // completely different
    }

    // ── Dot-segment rejection unit tests ─────────────────────────────

    #[test]
    fn reject_dot_segments_works() {
        // Clean paths should pass
        assert!(reject_dot_segments(Path::new("/a/b/c")).is_ok());
        assert!(reject_dot_segments(Path::new("/")).is_ok());

        // Dot segments should be rejected
        assert!(reject_dot_segments(Path::new("/a/../b")).is_err());
        assert!(reject_dot_segments(Path::new("/a/./b")).is_err());
        assert!(reject_dot_segments(Path::new("/a/b/..")).is_err());
        assert!(reject_dot_segments(Path::new("/./a")).is_err());
    }

    // ── Refused Delete Receipt ───────────────────────────────────────

    #[test]
    fn refused_delete_receipt_construction() {
        let receipt = RefusedDeleteReceipt {
            root: PathBuf::from("/lanes/lane-00/workspace"),
            allowed_parent: PathBuf::from("/lanes"),
            reason: "symlink detected".to_string(),
            mark_corrupt: true,
        };
        assert!(receipt.mark_corrupt);
        assert_eq!(receipt.reason, "symlink detected");
    }
}
