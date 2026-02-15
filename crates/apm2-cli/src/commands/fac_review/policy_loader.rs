//! Shared FAC policy loading and managed `CARGO_HOME` creation.
//!
//! Extracted from duplicate implementations in `evidence.rs` and `gates.rs`
//! (TCK-00526). Both the gates path and the pipeline/evidence path use these
//! helpers to load-or-create the FAC policy and ensure the managed `CARGO_HOME`
//! directory exists.
//!
//! ## Bounded read invariant (CTR-1603)
//!
//! `load_or_create_fac_policy` opens the policy file with `O_NOFOLLOW`
//! semantics (kernel-level symlink rejection) and reads at most
//! `MAX_POLICY_SIZE + 1` bytes via `Read::take` before any allocation beyond
//! the read buffer. This prevents unbounded reads from oversized or malicious
//! policy files.

use std::fs;
use std::io::Read;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use apm2_core::fac::policy::MAX_POLICY_SIZE;
use apm2_core::fac::{FacPolicyV1, deserialize_policy, persist_policy};

/// Load or create the FAC policy from `$FAC_ROOT/policy/fac_policy.v1.json`.
///
/// Opens the file directly with `O_NOFOLLOW` instead of checking `exists()`
/// first, eliminating the TOCTOU window between stat and open. On `NotFound`,
/// creates and persists the default policy.
///
/// # Errors
/// Returns a human-readable error when the file cannot be opened, is a
/// symlink, exceeds the size cap, fails parsing, or fails validation.
pub fn load_or_create_fac_policy(fac_root: &Path) -> Result<FacPolicyV1, String> {
    let policy_path = fac_root.join("policy/fac_policy.v1.json");

    // Open the file directly instead of checking exists() first to eliminate
    // the TOCTOU window between stat and open. O_NOFOLLOW atomically rejects
    // symlinks at the kernel level (CTR-1603). Handle NotFound by creating
    // the default policy.
    match open_policy_nofollow(&policy_path) {
        Ok(file) => {
            let cap = u64::try_from(MAX_POLICY_SIZE)
                .unwrap_or(u64::MAX)
                .saturating_add(1);
            // MAX_POLICY_SIZE is 64 KiB which always fits in usize even on 32-bit,
            // so the truncation-safe fallback is purely defensive.
            let capacity = usize::try_from(cap).unwrap_or(MAX_POLICY_SIZE + 1);
            let mut buf = Vec::with_capacity(std::cmp::min(capacity, MAX_POLICY_SIZE + 1));
            file.take(cap)
                .read_to_end(&mut buf)
                .map_err(|e| format!("cannot read FAC policy at {}: {e}", policy_path.display()))?;
            if buf.len() > MAX_POLICY_SIZE {
                return Err(format!(
                    "FAC policy file exceeds max size: {} > {}",
                    buf.len(),
                    MAX_POLICY_SIZE,
                ));
            }
            deserialize_policy(&buf).map_err(|e| format!("invalid FAC policy: {e}"))
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // File does not exist — create and persist the default policy.
            let default_policy = FacPolicyV1::default_policy();
            persist_policy(fac_root, &default_policy)
                .map_err(|e| format!("cannot persist default FAC policy: {e}"))?;
            Ok(default_policy)
        },
        Err(e) => {
            // Any other error (permission denied, symlink via O_NOFOLLOW, etc.)
            // is a hard failure.
            Err(format!(
                "cannot open FAC policy at {}: {e}",
                policy_path.display()
            ))
        },
    }
}

/// Ensure the managed `CARGO_HOME` directory exists with restrictive
/// permissions (0o700 on Unix, CTR-2611). This is a one-time setup for
/// FAC-managed cargo home isolation (TCK-00526).
///
/// If the directory already exists, verifies that it is owned by the current
/// user and has mode 0o700 on Unix. Returns an error if permissions are too
/// permissive, preventing cross-user state leakage or cargo home poisoning.
pub fn ensure_managed_cargo_home(cargo_home: &Path) -> Result<(), String> {
    if cargo_home.exists() {
        #[cfg(unix)]
        {
            verify_cargo_home_permissions(cargo_home)?;
        }
        return Ok(());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(cargo_home)
            .map_err(|e| {
                format!(
                    "cannot create managed CARGO_HOME at {}: {e}",
                    cargo_home.display()
                )
            })?;
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(cargo_home).map_err(|e| {
            format!(
                "cannot create managed CARGO_HOME at {}: {e}",
                cargo_home.display()
            )
        })?;
    }
    Ok(())
}

/// Verify that an existing managed `CARGO_HOME` directory has restrictive
/// permissions (0o700) and is owned by the current user. Returns an error
/// if the directory is too permissive (CTR-2611).
#[cfg(unix)]
fn verify_cargo_home_permissions(cargo_home: &Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;

    let metadata = std::fs::metadata(cargo_home).map_err(|e| {
        format!(
            "cannot stat managed CARGO_HOME at {}: {e}",
            cargo_home.display()
        )
    })?;

    if !metadata.is_dir() {
        return Err(format!(
            "managed CARGO_HOME at {} is not a directory",
            cargo_home.display()
        ));
    }

    let current_uid = nix::unistd::geteuid().as_raw();
    if metadata.uid() != current_uid {
        return Err(format!(
            "managed CARGO_HOME at {} is owned by uid {} but current user is uid {}; \
             refusing to use a directory owned by another user",
            cargo_home.display(),
            metadata.uid(),
            current_uid,
        ));
    }

    let mode = metadata.mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(format!(
            "managed CARGO_HOME at {} has too-permissive mode {:#05o} \
             (group/other access detected); expected 0o700. \
             Fix with: chmod 700 {}",
            cargo_home.display(),
            mode,
            cargo_home.display(),
        ));
    }

    Ok(())
}

/// Open a policy file for reading with `O_NOFOLLOW` to atomically reject
/// symlinks at the kernel level (CTR-1603). Returns the raw `io::Error` so
/// callers can match on `ErrorKind::NotFound` without string parsing.
fn open_policy_nofollow(path: &Path) -> Result<fs::File, std::io::Error> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW);
    options.open(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_or_create_creates_default_when_absent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let fac_root = dir.path();
        let policy = load_or_create_fac_policy(fac_root).expect("load_or_create");
        assert_eq!(policy, FacPolicyV1::default_policy());
        // Verify persisted file exists.
        assert!(fac_root.join("policy/fac_policy.v1.json").exists());
    }

    #[test]
    fn load_or_create_reads_persisted_policy() {
        let dir = tempfile::tempdir().expect("tempdir");
        let fac_root = dir.path();
        let mut custom_policy = FacPolicyV1::default_policy();
        custom_policy.deny_ambient_cargo_home = false;
        persist_policy(fac_root, &custom_policy).expect("persist");
        let loaded = load_or_create_fac_policy(fac_root).expect("load");
        assert_eq!(loaded, custom_policy);
    }

    #[test]
    fn load_or_create_rejects_oversized_policy() {
        let dir = tempfile::tempdir().expect("tempdir");
        let fac_root = dir.path();
        let policy_dir = fac_root.join("policy");
        fs::create_dir_all(&policy_dir).expect("mkdir");
        let policy_path = policy_dir.join("fac_policy.v1.json");
        // Write more than MAX_POLICY_SIZE bytes.
        let big = vec![b'x'; MAX_POLICY_SIZE + 1];
        fs::write(&policy_path, &big).expect("write big");
        let err = load_or_create_fac_policy(fac_root).expect_err("oversized should fail");
        assert!(err.contains("exceeds max size"), "got: {err}");
    }

    #[test]
    fn ensure_managed_cargo_home_creates_dir() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cargo_home = dir.path().join("managed_cargo");
        assert!(!cargo_home.exists());
        ensure_managed_cargo_home(&cargo_home).expect("ensure");
        assert!(cargo_home.is_dir());
    }

    #[test]
    fn ensure_managed_cargo_home_noop_if_exists_with_correct_perms() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cargo_home = dir.path().join("existing_cargo");
        fs::create_dir_all(&cargo_home).expect("mkdir");
        // On Unix, ensure permissions are 0o700 (the verification check will
        // reject more permissive modes).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&cargo_home, fs::Permissions::from_mode(0o700))
                .expect("set permissions");
        }
        ensure_managed_cargo_home(&cargo_home).expect("ensure existing");
    }

    #[cfg(unix)]
    #[test]
    fn ensure_managed_cargo_home_rejects_permissive_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let cargo_home = dir.path().join("permissive_cargo");
        fs::create_dir_all(&cargo_home).expect("mkdir");
        fs::set_permissions(&cargo_home, fs::Permissions::from_mode(0o755))
            .expect("set permissions");
        let err = ensure_managed_cargo_home(&cargo_home).expect_err("should reject permissive");
        assert!(err.contains("too-permissive"), "got: {err}");
    }

    #[cfg(unix)]
    #[test]
    fn ensure_managed_cargo_home_accepts_correct_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let cargo_home = dir.path().join("correct_cargo");
        fs::create_dir_all(&cargo_home).expect("mkdir");
        fs::set_permissions(&cargo_home, fs::Permissions::from_mode(0o700))
            .expect("set permissions");
        ensure_managed_cargo_home(&cargo_home).expect("should accept 0o700");
    }
}
