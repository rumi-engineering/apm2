//! FAC root permissions validation (TCK-00536).
//!
//! Enforces 0700 ownership checks on `$APM2_HOME` and `$APM2_HOME/private/fac`
//! before any FAC command executes. Refuses to run when permissions are unsafe,
//! printing actionable remediation. All newly created directories use
//! `DirBuilderExt::mode(0o700)` to prevent TOCTOU windows from
//! default-then-chmod patterns.
//!
//! # Security Contracts
//!
//! - [CTR-2611] Sensitive directories are created with restrictive permissions
//!   at create-time (never default-then-chmod).
//! - [CTR-2617] Permission masks for new directories default to 0700.
//! - Fail-closed: if ownership/permissions cannot be verified, deny.

use std::fmt;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

#[cfg(unix)]
use nix::unistd::geteuid;

/// Maximum mode bits allowed for FAC root directories.
/// 0700 = owner read/write/execute only.
const REQUIRED_MODE_MASK: u32 = 0o700;

/// Subdirectories under `$APM2_HOME` that must satisfy the permissions
/// invariant.
const FAC_SUBDIRS: &[&str] = &[
    "private",
    "private/fac",
    "private/fac/gate_cache",
    "private/fac/gate_cache_v2",
    "private/fac/evidence",
];

/// Errors from FAC root permissions validation.
#[derive(Debug)]
pub enum FacPermissionsError {
    /// The APM2 home directory could not be resolved.
    HomeResolutionFailed(String),
    /// A required directory has unsafe permissions.
    UnsafePermissions {
        path: PathBuf,
        actual_mode: u32,
        actual_uid: u32,
        expected_uid: u32,
    },
    /// A required directory is owned by the wrong user.
    OwnershipMismatch {
        path: PathBuf,
        actual_uid: u32,
        expected_uid: u32,
    },
    /// Failed to read metadata for a required directory.
    MetadataError {
        path: PathBuf,
        error: std::io::Error,
    },
    /// A required directory path is a symlink (TOCTOU risk).
    SymlinkDetected { path: PathBuf },
    /// Failed to create a required directory with safe permissions.
    CreationFailed {
        path: PathBuf,
        error: std::io::Error,
    },
    /// Path exists but is not a directory.
    NotDirectory { path: PathBuf, kind: String },
    /// Failed to create or open a file with safe mode.
    FileAccessError {
        path: PathBuf,
        error: std::io::Error,
    },
}

impl fmt::Display for FacPermissionsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HomeResolutionFailed(msg) => {
                write!(f, "cannot resolve APM2 home directory: {msg}")
            },
            Self::UnsafePermissions {
                path,
                actual_mode,
                actual_uid,
                expected_uid,
            } => {
                write!(
                    f,
                    "unsafe permissions on {}: owned by uid {actual_uid}, mode {:04o},\
                     expected owner uid {expected_uid}, and expected mode {:04o} or stricter\n\
                     Remediation: chown {expected_uid} {} and chmod 0700 {}",
                    path.display(),
                    actual_mode,
                    REQUIRED_MODE_MASK,
                    path.display(),
                    path.display()
                )
            },
            Self::OwnershipMismatch {
                path,
                actual_uid,
                expected_uid,
            } => {
                write!(
                    f,
                    "ownership mismatch on {}: owned by uid {actual_uid}, expected uid {expected_uid}\n\
                     Remediation: chown {expected_uid} {}",
                    path.display(),
                    path.display()
                )
            },
            Self::MetadataError { path, error } => {
                write!(
                    f,
                    "cannot read metadata for {}: {error} (fail-closed: refusing to proceed)",
                    path.display()
                )
            },
            Self::SymlinkDetected { path } => {
                write!(
                    f,
                    "symlink detected at {} (TOCTOU risk: refusing to proceed)\n\
                     Remediation: remove the symlink and recreate as a real directory",
                    path.display()
                )
            },
            Self::CreationFailed { path, error } => {
                write!(
                    f,
                    "failed to create directory {} with safe permissions: {error}",
                    path.display()
                )
            },
            Self::NotDirectory { path, kind } => {
                write!(
                    f,
                    "path exists but is not a directory: {} ({kind})",
                    path.display()
                )
            },
            Self::FileAccessError { path, error } => {
                write!(
                    f,
                    "failed to create/open FAC file {} with safe permissions: {error}",
                    path.display()
                )
            },
        }
    }
}

impl std::error::Error for FacPermissionsError {}

#[cfg(unix)]
fn path_kind(metadata: &std::fs::Metadata) -> String {
    let mode = metadata.permissions().mode();
    if metadata.file_type().is_file() {
        return "file".to_string();
    }
    if metadata.file_type().is_dir() {
        return "directory".to_string();
    }
    if metadata.file_type().is_symlink() {
        return "symlink".to_string();
    }
    format!("mode({mode:o})")
}

fn ensure_path_is_directory(path: &Path) -> Result<(), FacPermissionsError> {
    let metadata =
        std::fs::symlink_metadata(path).map_err(|error| FacPermissionsError::MetadataError {
            path: path.to_path_buf(),
            error,
        })?;
    if metadata.file_type().is_symlink() {
        return Err(FacPermissionsError::SymlinkDetected {
            path: path.to_path_buf(),
        });
    }
    #[cfg(unix)]
    let kind = path_kind(&metadata);
    #[cfg(not(unix))]
    let kind = "entry".to_string();
    if !metadata.is_dir() {
        return Err(FacPermissionsError::NotDirectory {
            path: path.to_path_buf(),
            kind,
        });
    }
    Ok(())
}

/// Resolve the APM2 home directory path.
///
/// Resolution order:
/// 1. `APM2_HOME` environment variable (must be non-empty)
/// 2. `~/.apm2` via `directories::BaseDirs`
///
/// This mirrors the resolution in `fac_review::types::apm2_home_dir()` and
/// `apm2_core::github::token_provider::resolve_apm2_home()`.
fn resolve_apm2_home() -> Result<PathBuf, FacPermissionsError> {
    if let Some(override_dir) = std::env::var_os("APM2_HOME") {
        let path = PathBuf::from(override_dir);
        if !path.as_os_str().is_empty() {
            return Ok(path);
        }
    }
    let base_dirs = directories::BaseDirs::new().ok_or_else(|| {
        FacPermissionsError::HomeResolutionFailed("could not resolve home directory".to_string())
    })?;
    Ok(base_dirs.home_dir().join(".apm2"))
}

/// Create a directory with mode 0700 at create-time, recursively creating
/// parent directories as needed (all with mode 0700).
///
/// Uses `DirBuilderExt::mode()` to set permissions atomically at creation
/// time, avoiding the TOCTOU window of `create_dir_all` + `set_permissions`.
///
/// # Errors
///
/// Returns `FacPermissionsError::CreationFailed` if directory creation fails.
#[cfg(unix)]
pub fn ensure_dir_with_mode(path: &Path) -> Result<(), FacPermissionsError> {
    if path.exists() {
        ensure_path_is_directory(path)?;
        return Ok(());
    }

    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
        .map_err(|error| FacPermissionsError::CreationFailed {
            path: path.to_path_buf(),
            error,
        })
}

#[cfg(not(unix))]
pub fn ensure_dir_with_mode(path: &Path) -> Result<(), FacPermissionsError> {
    if path.exists() {
        ensure_path_is_directory(path)?;
        return Ok(());
    }
    std::fs::create_dir_all(path).map_err(|error| FacPermissionsError::CreationFailed {
        path: path.to_path_buf(),
        error,
    })
}

fn ensure_parent_dir_for_file(path: &Path) -> Result<(), FacPermissionsError> {
    if path.exists() {
        ensure_path_is_directory(path)?;
        return Ok(());
    }
    ensure_dir_with_mode(path)
}

pub fn write_fac_file_with_mode(path: &Path, data: &[u8]) -> Result<(), FacPermissionsError> {
    let parent = path
        .parent()
        .ok_or_else(|| FacPermissionsError::MetadataError {
            path: path.to_path_buf(),
            error: std::io::Error::other("path has no parent"),
        })?;
    ensure_parent_dir_for_file(parent)?;

    if path.exists() {
        let metadata = std::fs::symlink_metadata(path).map_err(|error| {
            FacPermissionsError::MetadataError {
                path: path.to_path_buf(),
                error,
            }
        })?;
        if metadata.file_type().is_symlink() {
            return Err(FacPermissionsError::SymlinkDetected {
                path: path.to_path_buf(),
            });
        }
    }
    let mut options = std::fs::OpenOptions::new();
    options.create(true).write(true).truncate(true);
    #[cfg(unix)]
    {
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|error| FacPermissionsError::FileAccessError {
            path: path.to_path_buf(),
            error,
        })?;
    file.write_all(data)
        .map_err(|error| FacPermissionsError::FileAccessError {
            path: path.to_path_buf(),
            error,
        })?;
    Ok(())
}

pub fn append_fac_file_with_mode(path: &Path) -> Result<std::fs::File, FacPermissionsError> {
    let parent = path
        .parent()
        .ok_or_else(|| FacPermissionsError::MetadataError {
            path: path.to_path_buf(),
            error: std::io::Error::other("path has no parent"),
        })?;
    ensure_parent_dir_for_file(parent)?;

    if path.exists() {
        let metadata = std::fs::symlink_metadata(path).map_err(|error| {
            FacPermissionsError::MetadataError {
                path: path.to_path_buf(),
                error,
            }
        })?;
        if metadata.file_type().is_symlink() {
            return Err(FacPermissionsError::SymlinkDetected {
                path: path.to_path_buf(),
            });
        }
    }
    let mut options = std::fs::OpenOptions::new();
    options.create(true).append(true).write(true);
    #[cfg(unix)]
    {
        options.mode(0o600);
    }
    options
        .open(path)
        .map_err(|error| FacPermissionsError::FileAccessError {
            path: path.to_path_buf(),
            error,
        })
}

/// Validate that a single directory has safe permissions and ownership.
///
/// Checks:
/// 1. Path is not a symlink (TOCTOU defense).
/// 2. Owner matches the current effective UID.
/// 3. Mode has no group/world bits set (0700 or stricter).
///
/// If the directory does not exist, it is created with mode 0700.
///
/// # Errors
///
/// Returns a `FacPermissionsError` describing the first violation found.
#[cfg(unix)]
fn validate_directory(path: &Path, expected_uid: u32) -> Result<(), FacPermissionsError> {
    if !path.exists() {
        ensure_dir_with_mode(path)?;
    }
    ensure_path_is_directory(path)?;
    let metadata =
        std::fs::symlink_metadata(path).map_err(|error| FacPermissionsError::MetadataError {
            path: path.to_path_buf(),
            error,
        })?;

    // Check ownership and permissions atomically from metadata.
    let actual_uid = metadata.uid();
    let mode = metadata.mode() & 0o7777;
    if mode & 0o077 != 0 {
        return Err(FacPermissionsError::UnsafePermissions {
            path: path.to_path_buf(),
            actual_mode: mode,
            actual_uid,
            expected_uid,
        });
    }

    if actual_uid != expected_uid {
        return Err(FacPermissionsError::OwnershipMismatch {
            path: path.to_path_buf(),
            actual_uid,
            expected_uid,
        });
    }

    Ok(())
}

#[cfg(not(unix))]
fn validate_directory(path: &Path, _expected_uid: u32) -> Result<(), FacPermissionsError> {
    // On non-Unix platforms, ensure the directory exists but skip permission
    // checks.
    if !path.exists() {
        ensure_dir_with_mode(path)?;
    }
    ensure_path_is_directory(path)?;
    Ok(())
}

/// Validate FAC root permissions on entry to any FAC command.
///
/// Checks that `$APM2_HOME` and all critical subdirectories:
/// - Are owned by the current effective user.
/// - Have mode 0700 (or stricter: no group/world bits).
/// - Are not symlinks.
///
/// If a directory does not exist, it is created with mode 0700 at
/// creation time (CTR-2611: no default-then-chmod TOCTOU window).
///
/// # Errors
///
/// Returns a `FacPermissionsError` with actionable remediation text on
/// the first violation found. The caller should print the error and
/// refuse to proceed (fail-closed).
pub fn validate_fac_root_permissions() -> Result<(), FacPermissionsError> {
    let apm2_home = resolve_apm2_home()?;

    validate_fac_root_permissions_at(&apm2_home)
}

fn validate_fac_root_permissions_at(apm2_home: &Path) -> Result<(), FacPermissionsError> {
    #[cfg(unix)]
    let expected_uid = geteuid().as_raw();
    #[cfg(not(unix))]
    let expected_uid = 0u32;

    // Validate the APM2 home directory itself.
    validate_directory(apm2_home, expected_uid)?;

    // Validate each critical subdirectory.
    for subdir in FAC_SUBDIRS {
        let path = apm2_home.join(subdir);
        validate_directory(&path, expected_uid)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// TCK-00536: Verify that `ensure_dir_with_mode` creates directories with
    /// mode 0700.
    #[test]
    #[cfg(unix)]
    fn ensure_dir_creates_with_0700() {
        use std::os::unix::fs::MetadataExt;

        let dir = tempfile::TempDir::new().expect("create temp dir");
        let target = dir.path().join("fac_test_dir");

        ensure_dir_with_mode(&target).expect("should create directory");

        let metadata = std::fs::metadata(&target).expect("should read metadata");
        let mode = metadata.mode() & 0o7777;
        assert_eq!(
            mode, 0o700,
            "directory should have mode 0700, got {mode:04o}"
        );
    }

    /// TCK-00536: Verify that `ensure_dir_with_mode` creates nested directories
    /// with mode 0700.
    #[test]
    #[cfg(unix)]
    fn ensure_dir_creates_nested_with_0700() {
        use std::os::unix::fs::MetadataExt;

        let dir = tempfile::TempDir::new().expect("create temp dir");
        let target = dir.path().join("a").join("b").join("c");

        ensure_dir_with_mode(&target).expect("should create nested directory");

        // Check leaf directory.
        let metadata = std::fs::metadata(&target).expect("should read leaf metadata");
        let mode = metadata.mode() & 0o7777;
        assert_eq!(
            mode, 0o700,
            "leaf directory should have mode 0700, got {mode:04o}"
        );

        // Check intermediate directory.
        let parent = dir.path().join("a");
        let parent_meta = std::fs::metadata(&parent).expect("should read parent metadata");
        let parent_mode = parent_meta.mode() & 0o7777;
        assert_eq!(
            parent_mode, 0o700,
            "parent directory should have mode 0700, got {parent_mode:04o}"
        );
    }

    #[test]
    #[cfg(unix)]
    fn ensure_dir_with_mode_rejects_file_path() {
        let dir = tempfile::TempDir::new().expect("create temp dir");
        let target = dir.path().join("file_target");
        std::fs::write(&target, b"data").expect("create file");

        let err = ensure_dir_with_mode(&target).expect_err("must reject file path");
        let message = err.to_string();
        assert!(
            message.contains("not a directory"),
            "expected non-directory error: {message}"
        );
    }

    /// TCK-00536: Verify that `validate_directory` rejects group/world-writable
    /// directories.
    #[test]
    #[cfg(unix)]
    fn validate_directory_rejects_group_writable() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::TempDir::new().expect("create temp dir");
        let target = dir.path().join("unsafe_dir");
        std::fs::create_dir(&target).expect("create dir");

        // Set group-writable permissions.
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o770))
            .expect("set permissions");

        let uid = geteuid().as_raw();
        let result = validate_directory(&target, uid);
        assert!(result.is_err(), "should reject group-writable directory");

        let err = result.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("unsafe permissions"),
            "error should mention unsafe permissions: {msg}"
        );
        assert!(
            msg.contains("Remediation"),
            "error should include remediation: {msg}"
        );
    }

    /// TCK-00536: Verify that `validate_directory` rejects world-readable
    /// directories.
    #[test]
    #[cfg(unix)]
    fn validate_directory_rejects_world_readable() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::TempDir::new().expect("create temp dir");
        let target = dir.path().join("world_readable_dir");
        std::fs::create_dir(&target).expect("create dir");

        // Set world-readable permissions.
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o704))
            .expect("set permissions");

        let uid = geteuid().as_raw();
        let result = validate_directory(&target, uid);
        assert!(result.is_err(), "should reject world-readable directory");
    }

    /// TCK-00536: Verify that `validate_directory` accepts strict mode 0700.
    #[test]
    #[cfg(unix)]
    fn validate_directory_accepts_0700() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::TempDir::new().expect("create temp dir");
        let target = dir.path().join("safe_dir");
        std::fs::create_dir(&target).expect("create dir");

        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o700))
            .expect("set permissions");

        let uid = geteuid().as_raw();
        let result = validate_directory(&target, uid);
        assert!(result.is_ok(), "should accept mode 0700 directory");
    }

    /// TCK-00536: Verify that `validate_directory` accepts stricter mode 0500.
    #[test]
    #[cfg(unix)]
    fn validate_directory_accepts_stricter_than_0700() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::TempDir::new().expect("create temp dir");
        let target = dir.path().join("strict_dir");
        std::fs::create_dir(&target).expect("create dir");

        // Mode 0500 is stricter than 0700 (no write for owner).
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o500))
            .expect("set permissions");

        let uid = geteuid().as_raw();
        let result = validate_directory(&target, uid);
        assert!(
            result.is_ok(),
            "should accept mode 0500 (stricter than 0700)"
        );
    }

    /// TCK-00536: Verify that `validate_directory` rejects symlinks.
    #[test]
    #[cfg(unix)]
    fn validate_directory_rejects_symlink() {
        let dir = tempfile::TempDir::new().expect("create temp dir");
        let real_dir = dir.path().join("real_dir");
        let symlink_path = dir.path().join("symlink_dir");
        std::fs::create_dir(&real_dir).expect("create real dir");
        std::os::unix::fs::symlink(&real_dir, &symlink_path).expect("create symlink");

        let uid = geteuid().as_raw();
        let result = validate_directory(&symlink_path, uid);
        assert!(result.is_err(), "should reject symlink path");

        let err = result.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("symlink"),
            "error should mention symlink: {msg}"
        );
    }

    /// TCK-00536: Verify that `validate_directory` creates missing directories
    /// with mode 0700.
    #[test]
    #[cfg(unix)]
    fn validate_directory_creates_missing_dir_with_0700() {
        use std::os::unix::fs::MetadataExt;

        let dir = tempfile::TempDir::new().expect("create temp dir");
        let target = dir.path().join("auto_created");

        let uid = geteuid().as_raw();
        let result = validate_directory(&target, uid);
        assert!(
            result.is_ok(),
            "should create and validate missing directory"
        );

        let metadata = std::fs::metadata(&target).expect("should read metadata");
        let mode = metadata.mode() & 0o7777;
        assert_eq!(
            mode, 0o700,
            "auto-created directory should have mode 0700, got {mode:04o}"
        );
    }

    /// TCK-00536: Verify that `validate_directory` rejects ownership mismatch.
    /// Uses a fake UID that does not match the current user.
    #[test]
    #[cfg(unix)]
    fn validate_directory_rejects_ownership_mismatch() {
        let dir = tempfile::TempDir::new().expect("create temp dir");
        let target = dir.path().join("owned_dir");

        ensure_dir_with_mode(&target).expect("create dir");

        // Use a UID that definitely does not own the directory.
        let fake_uid = geteuid().as_raw().saturating_add(1);
        let result = validate_directory(&target, fake_uid);
        assert!(result.is_err(), "should reject ownership mismatch");

        let err = result.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("ownership mismatch"),
            "error should mention ownership mismatch: {msg}"
        );
    }

    /// TCK-00536: End-to-end test of `validate_fac_root_permissions` with a
    /// temporary `$APM2_HOME`.
    #[test]
    #[cfg(unix)]
    fn validate_fac_root_creates_all_dirs_with_0700() {
        use std::os::unix::fs::MetadataExt;

        let dir = tempfile::TempDir::new().expect("create temp dir");
        let apm2_home = dir.path().join("apm2_home");

        let result = validate_fac_root_permissions_at(&apm2_home);
        assert!(
            result.is_ok(),
            "should succeed with fresh temp dir: {result:?}"
        );

        // Verify all directories were created with correct permissions.
        let dirs_to_check =
            std::iter::once(apm2_home.clone()).chain(FAC_SUBDIRS.iter().map(|s| apm2_home.join(s)));

        for path in dirs_to_check {
            assert!(path.exists(), "directory should exist: {}", path.display());
            let metadata = std::fs::metadata(&path).expect("read metadata");
            let mode = metadata.mode() & 0o7777;
            assert_eq!(
                mode,
                0o700,
                "directory {} should have mode 0700, got {:04o}",
                path.display(),
                mode
            );
        }
    }
}
