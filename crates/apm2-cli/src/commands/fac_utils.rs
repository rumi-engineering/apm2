// AGENT-AUTHORED (TCK-00535)
//! Shared utilities for FAC commands.

use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use apm2_core::fac::job_spec::{FacJobSpecV1, MAX_JOB_SPEC_SIZE};
use apm2_core::github::resolve_apm2_home;

/// Queue subdirectory under `$APM2_HOME`.
pub const QUEUE_DIR: &str = "queue";

/// Maximum number of directory entries to scan per directory.
/// Prevents unbounded memory growth (INV-QSTAT-001).
pub const MAX_SCAN_ENTRIES: usize = 4096;

/// Resolves the queue root directory from `$APM2_HOME/queue`.
pub fn resolve_queue_root() -> Result<PathBuf, String> {
    let home = resolve_apm2_home().ok_or_else(|| "could not resolve APM2 home".to_string())?;
    Ok(home.join(QUEUE_DIR))
}

/// Resolves the FAC root directory at `$APM2_HOME/private/fac`.
pub fn resolve_fac_root() -> Result<PathBuf, String> {
    let home = resolve_apm2_home().ok_or_else(|| "could not resolve APM2 home".to_string())?;
    Ok(home.join("private").join("fac"))
}

/// Validates that a path is a regular file and not a symlink.
///
/// Uses `symlink_metadata` (lstat semantics) to detect symlinks before
/// opening. This prevents symlink-based redirects outside FAC roots.
///
/// Returns `Ok(())` if the path is a regular file, `Err` otherwise.
fn validate_regular_file(path: &Path) -> Result<(), String> {
    let metadata =
        fs::symlink_metadata(path).map_err(|e| format!("cannot stat {}: {e}", path.display()))?;
    if metadata.file_type().is_symlink() {
        return Err(format!(
            "symlink rejected (fail-closed): {}",
            path.display()
        ));
    }
    if !metadata.is_file() {
        return Err(format!(
            "not a regular file (fail-closed): {}",
            path.display()
        ));
    }
    Ok(())
}

/// Validates that a path is a real directory and not a symlink.
///
/// Uses `symlink_metadata` (lstat semantics) to detect symlinks before
/// traversal. This prevents symlink-based redirects outside FAC roots.
///
/// Returns `Ok(())` if the path is a real directory, `Err` otherwise.
pub fn validate_real_directory(path: &Path) -> Result<(), String> {
    let metadata =
        fs::symlink_metadata(path).map_err(|e| format!("cannot stat {}: {e}", path.display()))?;
    if metadata.file_type().is_symlink() {
        return Err(format!(
            "symlink directory rejected (fail-closed): {}",
            path.display()
        ));
    }
    if !metadata.is_dir() {
        return Err(format!("not a directory: {}", path.display()));
    }
    Ok(())
}

/// Reads and deserializes a job spec from a file with bounded I/O.
///
/// Uses `symlink_metadata` to reject symlinks and non-regular files
/// before opening (O_NOFOLLOW-equivalent semantics). Then reads at most
/// `MAX_JOB_SPEC_SIZE + 1` bytes via `take()` to enforce the size limit
/// on the actual read operation. Prevents denial-of-service via special
/// files and symlink-based redirects outside FAC roots (INV-QSTAT-002).
pub fn read_job_spec_bounded(path: &Path) -> Result<FacJobSpecV1, String> {
    // Hardened open: reject symlinks and non-regular files before opening.
    validate_regular_file(path)?;

    let file = File::open(path).map_err(|e| format!("cannot open {}: {e}", path.display()))?;
    // Read at most MAX_JOB_SPEC_SIZE + 1 bytes.  If we get more than
    // MAX_JOB_SPEC_SIZE, the file is over the limit.
    let limit = (MAX_JOB_SPEC_SIZE as u64).saturating_add(1);
    let mut bounded_reader = file.take(limit);
    let mut bytes = Vec::with_capacity(MAX_JOB_SPEC_SIZE.min(8192));
    bounded_reader
        .read_to_end(&mut bytes)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    if bytes.len() > MAX_JOB_SPEC_SIZE {
        return Err(format!(
            "file content {} exceeds max {}",
            bytes.len(),
            MAX_JOB_SPEC_SIZE
        ));
    }
    serde_json::from_slice(&bytes).map_err(|e| format!("cannot parse {}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression: `read_job_spec_bounded` must reject symlinked queue entries
    /// fail-closed (Finding 1 — security MAJOR).
    #[test]
    #[cfg(unix)]
    fn test_read_job_spec_bounded_rejects_symlink() {
        let tmp = tempfile::tempdir().expect("tempdir");

        // Create a real job spec file.
        let real_path = tmp.path().join("real.json");
        let spec_json = r#"{"schema":"apm2.fac.job_spec.v1","job_id":"sym-test","job_spec_digest":"","kind":"gates","queue_lane":"bulk","priority":50,"enqueue_time":"2026-02-15T00:00:00Z","actuation":{"lease_id":"l","request_id":"","channel_context_token":null,"decoded_source":null},"source":{"kind":"mirror_commit","repo_id":"test/repo","head_sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","patch":null},"lane_requirements":{"lane_profile_hash":null},"constraints":{"require_nextest":false,"test_timeout_seconds":60,"memory_max_bytes":null},"cancel_target_job_id":null}"#;
        fs::write(&real_path, spec_json).unwrap();

        // Create a symlink to the real file.
        let symlink_path = tmp.path().join("symlink.json");
        std::os::unix::fs::symlink(&real_path, &symlink_path).unwrap();

        // The real file should be accepted.
        assert!(
            read_job_spec_bounded(&real_path).is_ok(),
            "real file should be accepted"
        );

        // The symlink MUST be rejected (fail-closed).
        let result = read_job_spec_bounded(&symlink_path);
        assert!(result.is_err(), "symlink must be rejected");
        let err = result.unwrap_err();
        assert!(
            err.contains("symlink rejected"),
            "error should mention symlink: {err}"
        );
    }

    /// Regression: `read_job_spec_bounded` must reject non-regular files
    /// (e.g., directories) fail-closed.
    #[test]
    fn test_read_job_spec_bounded_rejects_directory() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let dir_path = tmp.path().join("fakejob.json");
        fs::create_dir(&dir_path).unwrap();

        let result = read_job_spec_bounded(&dir_path);
        assert!(result.is_err(), "directory must be rejected");
        let err = result.unwrap_err();
        assert!(
            err.contains("not a regular file"),
            "error should mention non-regular file: {err}"
        );
    }

    /// `validate_real_directory` must reject symlinked directories.
    #[test]
    #[cfg(unix)]
    fn test_validate_real_directory_rejects_symlink() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let real_dir = tmp.path().join("real_dir");
        fs::create_dir(&real_dir).unwrap();

        let symlink_dir = tmp.path().join("sym_dir");
        std::os::unix::fs::symlink(&real_dir, &symlink_dir).unwrap();

        assert!(validate_real_directory(&real_dir).is_ok());

        let result = validate_real_directory(&symlink_dir);
        assert!(result.is_err(), "symlink directory must be rejected");
        assert!(result.unwrap_err().contains("symlink directory rejected"));
    }
}
