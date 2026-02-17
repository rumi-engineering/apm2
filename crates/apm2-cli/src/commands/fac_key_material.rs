//! Shared FAC signing-key lifecycle helpers.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use apm2_core::crypto::Signer;

use super::fac_secure_io;

/// Ed25519 secret key byte length for `Signer`.
pub const SIGNING_KEY_SIZE: usize = 64;

fn signing_key_path(fac_root: &Path) -> PathBuf {
    fac_root.join("signing_key")
}

fn fsync_parent_dir(path: &Path) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("path {} has no parent", path.display()))?;
    let dir_file =
        File::open(parent).map_err(|err| format!("open parent dir {}: {err}", parent.display()))?;
    dir_file
        .sync_all()
        .map_err(|err| format!("fsync parent dir {}: {err}", parent.display()))
}

fn ensure_parent_dir(path: &Path) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("path {} has no parent", path.display()))?;

    if parent.exists() {
        let metadata = fs::symlink_metadata(parent)
            .map_err(|err| format!("stat parent {}: {err}", parent.display()))?;
        if metadata.file_type().is_symlink() {
            return Err(format!(
                "parent {} is a symlink (fail-closed)",
                parent.display()
            ));
        }
        if !metadata.is_dir() {
            return Err(format!(
                "parent {} is not a directory (fail-closed)",
                parent.display()
            ));
        }
        return Ok(());
    }

    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        builder.mode(0o700);
    }
    builder
        .create(parent)
        .map_err(|err| format!("create parent {}: {err}", parent.display()))?;
    fsync_parent_dir(path)?;
    Ok(())
}

fn write_new_signing_key(path: &Path, key_bytes: &[u8]) -> Result<(), String> {
    ensure_parent_dir(path)?;

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        options.mode(0o600);
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }

    let mut file = options
        .open(path)
        .map_err(|err| format!("open {} for create_new: {err}", path.display()))?;
    file.write_all(key_bytes)
        .map_err(|err| format!("write {}: {err}", path.display()))?;
    file.sync_all()
        .map_err(|err| format!("fsync {}: {err}", path.display()))?;
    drop(file);
    fsync_parent_dir(path)?;
    Ok(())
}

/// Load existing persistent signer from `fac_root/signing_key`.
pub fn load_persistent_signer(fac_root: &Path) -> Result<Signer, String> {
    let key_path = signing_key_path(fac_root);
    let bytes = fac_secure_io::read_bounded(&key_path, SIGNING_KEY_SIZE)?;
    Signer::from_bytes(&bytes).map_err(|err| format!("invalid signing key: {err}"))
}

/// Load or create persistent signer with secure create-time permissions.
pub fn load_or_generate_persistent_signer(fac_root: &Path) -> Result<Signer, String> {
    let key_path = signing_key_path(fac_root);
    if key_path.exists() {
        return load_persistent_signer(fac_root);
    }

    let signer = Signer::generate();
    let key_bytes = signer.secret_key_bytes();
    match write_new_signing_key(&key_path, key_bytes.as_ref()) {
        Ok(()) => Ok(signer),
        Err(err) => {
            // Concurrent creators race here. If another process created the key
            // first, load the persisted key instead of failing open.
            if key_path.exists() {
                return load_persistent_signer(fac_root);
            }
            Err(format!(
                "cannot create persistent signing key {}: {err}",
                key_path.display()
            ))
        },
    }
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Arc;
    use std::thread;

    use super::*;

    #[test]
    fn concurrent_signer_creation_converges_to_single_key() {
        let dir = tempfile::tempdir().expect("tempdir");
        let fac_root = dir.path().join("private").join("fac");
        fs::create_dir_all(&fac_root).expect("create fac root");
        let fac_root = Arc::new(fac_root);

        let mut handles = Vec::new();
        for _ in 0..2 {
            let root = Arc::clone(&fac_root);
            handles.push(thread::spawn(move || {
                load_or_generate_persistent_signer(&root).expect("load_or_generate signer")
            }));
        }

        let first = handles
            .remove(0)
            .join()
            .expect("thread should join")
            .secret_key_bytes()
            .to_vec();
        let second = handles
            .remove(0)
            .join()
            .expect("thread should join")
            .secret_key_bytes()
            .to_vec();

        assert_eq!(first, second, "both creators must converge to same key");
        let on_disk = fac_secure_io::read_bounded(&fac_root.join("signing_key"), SIGNING_KEY_SIZE)
            .expect("read key");
        assert_eq!(on_disk, first);
    }

    #[cfg(unix)]
    #[test]
    fn create_parent_directory_with_0700_mode() {
        let dir = tempfile::tempdir().expect("tempdir");
        let fac_root = dir.path().join("private").join("fac-new");
        let _ = load_or_generate_persistent_signer(&fac_root).expect("create signer");

        let mode = fs::metadata(&fac_root)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700, "fac root mode must be 0700, got {mode:04o}");
    }

    #[cfg(unix)]
    #[test]
    fn reject_symlink_parent_directory() {
        let dir = tempfile::tempdir().expect("tempdir");
        let real = dir.path().join("real-fac");
        fs::create_dir_all(&real).expect("create real");
        let link = dir.path().join("fac-link");
        std::os::unix::fs::symlink(&real, &link).expect("create symlink");

        let Err(err) = load_or_generate_persistent_signer(&link) else {
            panic!("symlink parent must be rejected");
        };
        assert!(err.contains("symlink"), "unexpected error: {err}");
    }
}
