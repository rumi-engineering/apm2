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
/// If a persisted policy exists it is read with bounded I/O (`O_NOFOLLOW` +
/// `Read::take`) and validated; otherwise the default policy is created,
/// persisted, and returned.
///
/// # Errors
/// Returns a human-readable error when the file cannot be opened, is a
/// symlink, exceeds the size cap, fails parsing, or fails validation.
pub fn load_or_create_fac_policy(fac_root: &Path) -> Result<FacPolicyV1, String> {
    let policy_path = fac_root.join("policy/fac_policy.v1.json");
    if policy_path.exists() {
        // CTR-1603: Open with O_NOFOLLOW to atomically reject symlinks at the
        // kernel level, then read with a strict cap via Read::take BEFORE any
        // large allocation.
        let file = open_policy_nofollow(&policy_path)?;
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
    } else {
        let default_policy = FacPolicyV1::default_policy();
        persist_policy(fac_root, &default_policy)
            .map_err(|e| format!("cannot persist default FAC policy: {e}"))?;
        Ok(default_policy)
    }
}

/// Ensure the managed `CARGO_HOME` directory exists with restrictive
/// permissions (0o700 on Unix). This is a one-time setup for FAC-managed
/// cargo home isolation (TCK-00526).
pub fn ensure_managed_cargo_home(cargo_home: &Path) -> Result<(), String> {
    if cargo_home.exists() {
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

/// Open a policy file for reading with `O_NOFOLLOW` to atomically reject
/// symlinks at the kernel level (CTR-1603).
fn open_policy_nofollow(path: &Path) -> Result<fs::File, String> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW);
    options
        .open(path)
        .map_err(|e| format!("cannot open FAC policy at {}: {e}", path.display()))
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
    fn ensure_managed_cargo_home_noop_if_exists() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cargo_home = dir.path().join("existing_cargo");
        fs::create_dir_all(&cargo_home).expect("mkdir");
        ensure_managed_cargo_home(&cargo_home).expect("ensure existing");
    }
}
