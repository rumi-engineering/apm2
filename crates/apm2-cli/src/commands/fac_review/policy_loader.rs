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

use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
#[cfg(unix)]
use std::os::unix::fs::DirBuilderExt;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use apm2_core::fac::execution_backend::{ExecutionBackend, select_backend};
use apm2_core::fac::policy::MAX_POLICY_SIZE;
use apm2_core::fac::{
    FacPolicyV1, apply_lane_env_overrides, deserialize_policy, ensure_lane_env_dirs, persist_policy,
};

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
/// permissions (0o700 in operator mode, 0o770 in system-mode, CTR-2611). This
/// is a one-time setup for FAC-managed cargo home isolation (TCK-00526).
///
/// Uses atomic creation (mkdir, handle `AlreadyExists`) to eliminate the
/// TOCTOU window between existence checks and creation. Rejects symlinks
/// via `symlink_metadata` to prevent isolation escape (INV-LANE-ENV-001).
///
/// If the directory already exists, verifies that it is owned by the current
/// runtime context and has restrictive permissions on Unix. Returns an error if
/// permissions are too permissive or the path is a symlink, preventing
/// cross-user state leakage or cargo home poisoning.
pub fn ensure_managed_cargo_home(cargo_home: &Path) -> Result<(), String> {
    // Atomic creation: attempt mkdir first, handle AlreadyExists.
    // This eliminates the TOCTOU window between exists() and create().
    #[cfg(unix)]
    {
        let mode = managed_cargo_home_mode();
        match std::fs::DirBuilder::new()
            .recursive(true)
            .mode(mode)
            .create(cargo_home)
        {
            Ok(()) => {
                // Created successfully — verify permissions (paranoid check
                // against race where attacker replaces with symlink).
                verify_cargo_home_permissions(cargo_home)?;
            },
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                // Already exists — verify permissions and reject symlinks.
                verify_cargo_home_permissions(cargo_home)?;
            },
            Err(e) => {
                return Err(format!(
                    "cannot create managed CARGO_HOME at {}: {e}",
                    cargo_home.display()
                ));
            },
        }
    }
    #[cfg(not(unix))]
    {
        match std::fs::create_dir_all(cargo_home) {
            Ok(()) => {},
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {},
            Err(e) => {
                return Err(format!(
                    "cannot create managed CARGO_HOME at {}: {e}",
                    cargo_home.display()
                ));
            },
        }
    }
    Ok(())
}

/// Apply a stable `RUSTUP_HOME` when the policy environment does not provide
/// one explicitly, or provides an invalid path.
///
/// FAC review gates run with lane-scoped `HOME`. If `RUSTUP_HOME` is unset,
/// rustup falls back to `$HOME/.rustup`, which is lane-local and may be wiped
/// during lane recovery. This helper pins `RUSTUP_HOME` to an existing shared
/// rustup home (ambient `RUSTUP_HOME` first, then ambient `HOME/.rustup`) when
/// that directory already contains `toolchains/`.
///
/// Existing `RUSTUP_HOME` values are preserved when valid and absolute. If an
/// existing value is invalid (missing path or missing `toolchains/`), it is
/// replaced by a discovered stable candidate when available.
pub fn apply_stable_rustup_home_if_available(
    policy_env: &mut BTreeMap<String, String>,
    ambient: &[(String, String)],
) {
    if let Some(existing) = policy_env.get("RUSTUP_HOME") {
        if validate_stable_rustup_home(PathBuf::from(existing)).is_some() {
            return;
        }
    }
    if let Some(path) = discover_stable_rustup_home(ambient) {
        policy_env.insert(
            "RUSTUP_HOME".to_string(),
            path.to_string_lossy().to_string(),
        );
    }
}

/// Apply lane-local environment isolation for FAC review execution.
///
/// This bundles the three required steps for deterministic, resilient lane
/// execution:
/// - ensure lane env directories exist with restricted permissions,
/// - override HOME/TMP/XDG variables to the lane directory,
/// - pin `RUSTUP_HOME` to a stable shared location when available.
pub fn apply_review_lane_environment(
    policy_env: &mut BTreeMap<String, String>,
    lane_dir: &Path,
    ambient: &[(String, String)],
) -> Result<(), String> {
    ensure_lane_env_dirs(lane_dir)?;
    apply_lane_env_overrides(policy_env, lane_dir);
    apply_stable_rustup_home_if_available(policy_env, ambient);
    Ok(())
}

fn discover_stable_rustup_home(ambient: &[(String, String)]) -> Option<PathBuf> {
    let explicit_rustup_home = ambient_env_value(ambient, "RUSTUP_HOME")
        .map(PathBuf::from)
        .and_then(validate_stable_rustup_home);
    if explicit_rustup_home.is_some() {
        return explicit_rustup_home;
    }

    ambient_env_value(ambient, "HOME")
        .map(PathBuf::from)
        .map(|home| home.join(".rustup"))
        .and_then(validate_stable_rustup_home)
}

fn ambient_env_value<'a>(ambient: &'a [(String, String)], key: &str) -> Option<&'a str> {
    ambient
        .iter()
        .find_map(|(candidate_key, value)| (candidate_key == key).then_some(value.as_str()))
}

fn validate_stable_rustup_home(path: PathBuf) -> Option<PathBuf> {
    if !path.is_absolute() {
        return None;
    }

    let canonical = path.canonicalize().unwrap_or(path);
    if !canonical.is_dir() {
        return None;
    }
    if !canonical.join("toolchains").is_dir() {
        return None;
    }

    Some(canonical)
}

/// Verify that an existing managed `CARGO_HOME` directory has restrictive
/// permissions, is owned by the current runtime context (CTR-2611), and is
/// not a symlink (INV-LANE-ENV-001).
///
/// Delegates to the shared [`apm2_core::fac::verify_dir_permissions`]
/// helper with a "managed `CARGO_HOME`" context label (TCK-00575 round 2
/// NIT: deduplicated permission verification).
#[cfg(unix)]
fn verify_cargo_home_permissions(cargo_home: &Path) -> Result<(), String> {
    apm2_core::fac::verify_dir_permissions(cargo_home, "managed CARGO_HOME")
}

#[cfg(unix)]
fn managed_cargo_home_mode() -> u32 {
    if matches!(select_backend(), Ok(ExecutionBackend::SystemMode)) {
        0o770
    } else {
        0o700
    }
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
        // On Unix, ensure permissions are valid for the active mode.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(
                &cargo_home,
                fs::Permissions::from_mode(managed_cargo_home_mode()),
            )
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
        fs::set_permissions(
            &cargo_home,
            fs::Permissions::from_mode(managed_cargo_home_mode()),
        )
        .expect("set permissions");
        ensure_managed_cargo_home(&cargo_home).expect("should accept mode for active backend");
    }

    /// Regression: a symlink at the managed `CARGO_HOME` path must be
    /// rejected to prevent cargo home poisoning via isolation escape.
    #[cfg(unix)]
    #[test]
    fn ensure_managed_cargo_home_rejects_symlink() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("symlink_target");
        fs::create_dir_all(&target).expect("create target");
        let cargo_home = dir.path().join("cargo_symlink");
        std::os::unix::fs::symlink(&target, &cargo_home).expect("create symlink");
        let err = ensure_managed_cargo_home(&cargo_home).expect_err("should reject symlink");
        assert!(
            err.contains("symlink"),
            "error should mention symlink, got: {err}"
        );
    }

    /// Regression: `verify_cargo_home_permissions` must reject a symlink
    /// even when the target directory has correct permissions and ownership.
    #[cfg(unix)]
    #[test]
    fn verify_cargo_home_permissions_rejects_symlink_to_valid_dir() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("valid_target");
        fs::create_dir_all(&target).expect("create target");
        fs::set_permissions(
            &target,
            fs::Permissions::from_mode(managed_cargo_home_mode()),
        )
        .expect("set permissions");
        let symlink_path = dir.path().join("link_to_valid");
        std::os::unix::fs::symlink(&target, &symlink_path).expect("create symlink");
        let err = verify_cargo_home_permissions(&symlink_path).expect_err("should reject");
        assert!(
            err.contains("symlink"),
            "should report symlink rejection, got: {err}"
        );
    }

    #[test]
    fn apply_stable_rustup_home_uses_ambient_rustup_home_when_toolchains_exist() {
        let dir = tempfile::tempdir().expect("tempdir");
        let rustup_home = dir.path().join("rustup");
        fs::create_dir_all(rustup_home.join("toolchains/stable")).expect("create toolchains");

        let ambient = vec![(
            "RUSTUP_HOME".to_string(),
            rustup_home.to_string_lossy().to_string(),
        )];
        let mut env = BTreeMap::new();

        apply_stable_rustup_home_if_available(&mut env, &ambient);

        assert_eq!(
            env.get("RUSTUP_HOME").map(String::as_str),
            Some(rustup_home.to_string_lossy().as_ref())
        );
    }

    #[test]
    fn apply_stable_rustup_home_falls_back_to_home_dot_rustup() {
        let dir = tempfile::tempdir().expect("tempdir");
        let home = dir.path().join("home");
        let rustup_home = home.join(".rustup");
        fs::create_dir_all(rustup_home.join("toolchains/stable")).expect("create toolchains");

        let ambient = vec![("HOME".to_string(), home.to_string_lossy().to_string())];
        let mut env = BTreeMap::new();

        apply_stable_rustup_home_if_available(&mut env, &ambient);

        assert_eq!(
            env.get("RUSTUP_HOME").map(String::as_str),
            Some(rustup_home.to_string_lossy().as_ref())
        );
    }

    #[test]
    fn apply_stable_rustup_home_does_not_override_existing_valid_value() {
        let dir = tempfile::tempdir().expect("tempdir");
        let existing = dir.path().join("existing-rustup");
        let ambient_rustup = dir.path().join("ambient-rustup");
        fs::create_dir_all(existing.join("toolchains/stable")).expect("create existing toolchains");
        fs::create_dir_all(ambient_rustup.join("toolchains/stable"))
            .expect("create ambient toolchains");

        let ambient = vec![(
            "RUSTUP_HOME".to_string(),
            ambient_rustup.to_string_lossy().to_string(),
        )];
        let mut env = BTreeMap::from([(
            "RUSTUP_HOME".to_string(),
            existing.to_string_lossy().to_string(),
        )]);

        apply_stable_rustup_home_if_available(&mut env, &ambient);

        assert_eq!(
            env.get("RUSTUP_HOME").map(String::as_str),
            Some(existing.to_string_lossy().as_ref())
        );
    }

    #[test]
    fn apply_stable_rustup_home_replaces_invalid_existing_value_when_candidate_exists() {
        let dir = tempfile::tempdir().expect("tempdir");
        let home = dir.path().join("home");
        let rustup_home = home.join(".rustup");
        fs::create_dir_all(rustup_home.join("toolchains/stable")).expect("create toolchains");

        let ambient = vec![("HOME".to_string(), home.to_string_lossy().to_string())];
        let mut env = BTreeMap::from([("RUSTUP_HOME".to_string(), "/does/not/exist".to_string())]);

        apply_stable_rustup_home_if_available(&mut env, &ambient);

        assert_eq!(
            env.get("RUSTUP_HOME").map(String::as_str),
            Some(rustup_home.to_string_lossy().as_ref())
        );
    }

    #[test]
    fn apply_stable_rustup_home_ignores_home_without_toolchains() {
        let dir = tempfile::tempdir().expect("tempdir");
        let rustup_home = dir.path().join("rustup");
        fs::create_dir_all(&rustup_home).expect("create rustup root");

        let ambient = vec![(
            "RUSTUP_HOME".to_string(),
            rustup_home.to_string_lossy().to_string(),
        )];
        let mut env = BTreeMap::new();

        apply_stable_rustup_home_if_available(&mut env, &ambient);

        assert!(
            !env.contains_key("RUSTUP_HOME"),
            "RUSTUP_HOME should remain unset without a toolchains/ directory"
        );
    }

    #[test]
    fn apply_review_lane_environment_sets_lane_overrides_and_stable_rustup() {
        let dir = tempfile::tempdir().expect("tempdir");
        let lane_dir = dir.path().join("lane-00");
        fs::create_dir_all(&lane_dir).expect("create lane dir");

        let home = dir.path().join("home");
        let rustup_home = home.join(".rustup");
        fs::create_dir_all(rustup_home.join("toolchains/stable")).expect("create toolchains");

        let ambient = vec![("HOME".to_string(), home.to_string_lossy().to_string())];
        let mut env = BTreeMap::new();
        apply_review_lane_environment(&mut env, &lane_dir, &ambient)
            .expect("apply review lane env");

        let lane_prefix = lane_dir.to_string_lossy();
        let expected_home = format!("{lane_prefix}/home");
        assert_eq!(
            env.get("HOME").map(String::as_str),
            Some(expected_home.as_str())
        );
        assert_eq!(
            env.get("RUSTUP_HOME").map(String::as_str),
            Some(rustup_home.to_string_lossy().as_ref())
        );
    }
}
