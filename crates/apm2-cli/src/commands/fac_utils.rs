// AGENT-AUTHORED (TCK-00535)
//! Shared utilities for FAC commands.

use std::fs::{self, File, OpenOptions};
use std::io::Read;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
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

/// Opens a file with `O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK` on Unix, then
/// verifies via `fstat` (handle-based `File::metadata()`) that the opened fd
/// is a regular file.
///
/// This is an open-once pattern that eliminates the TOCTOU race between
/// `symlink_metadata()` and `File::open()` that existed previously.
/// Matches the established pattern in `fac_secure_io::read_bounded`.
///
/// `O_NONBLOCK` prevents the open(2) call from blocking on FIFOs (named
/// pipes) — without it, opening a FIFO for read hangs until a writer
/// attaches, which is a local denial-of-service vector. For regular files,
/// `O_NONBLOCK` has no effect on open(2) and is harmless.
///
/// # Errors
///
/// - Returns `Err` if the path is a symlink (kernel refuses `O_NOFOLLOW`).
/// - Returns `Err` if the opened fd is not a regular file (FIFO, device,
///   socket, directory).
/// - Returns `Err` on any I/O failure (including ENXIO for write-only FIFOs).
fn open_regular_file_nofollow(path: &Path) -> Result<File, String> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    }

    let file = options
        .open(path)
        .map_err(|e| format!("symlink rejected (fail-closed): {}: {e}", path.display()))?;

    // fstat on the opened fd — not the path — to verify regular file.
    // This cannot race because the fd is already bound to the inode.
    let metadata = file
        .metadata()
        .map_err(|e| format!("cannot fstat {}: {e}", path.display()))?;
    if !metadata.is_file() {
        return Err(format!(
            "not a regular file (fail-closed): {}",
            path.display()
        ));
    }

    Ok(file)
}

/// Reads and deserializes a job spec from a file with bounded I/O.
///
/// Uses an open-once pattern to eliminate the TOCTOU race between
/// symlink validation and file open:
///
/// 1. Opens with `O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK` (Unix) to atomically
///    refuse symlinks at the kernel level and prevent FIFO blocking.
/// 2. Calls `fstat` on the opened fd (via `File::metadata()`) to verify the
///    target is a regular file (rejects FIFOs, devices, sockets).
/// 3. Reads at most `MAX_JOB_SPEC_SIZE + 1` bytes via `take()` to enforce the
///    size limit.
///
/// Prevents denial-of-service via special files and symlink-based
/// redirects outside FAC roots (INV-QSTAT-002).
pub fn read_job_spec_bounded(path: &Path) -> Result<FacJobSpecV1, String> {
    // Open-once with O_NOFOLLOW + fstat validation (no TOCTOU gap).
    let file = open_regular_file_nofollow(path)?;

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
    /// fail-closed via `O_NOFOLLOW` at the open(2) level — no TOCTOU gap
    /// (Finding 1 — security MAJOR).
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

        // The symlink MUST be rejected fail-closed at the open(2) level
        // (O_NOFOLLOW causes ELOOP).
        let result = read_job_spec_bounded(&symlink_path);
        assert!(result.is_err(), "symlink must be rejected");
        let err = result.unwrap_err();
        assert!(
            err.contains("symlink rejected") || err.contains("loop"),
            "error should indicate symlink refusal: {err}"
        );
    }

    /// Regression: `open_regular_file_nofollow` must reject symlinks at the
    /// open(2) level via `O_NOFOLLOW`, proving there is no TOCTOU gap between
    /// metadata check and open (Finding 1 — security MAJOR, Finding 2 — MINOR).
    #[test]
    #[cfg(unix)]
    fn test_open_regular_file_nofollow_rejects_symlink_atomically() {
        let tmp = tempfile::tempdir().expect("tempdir");

        let real_path = tmp.path().join("target.txt");
        fs::write(&real_path, b"content").unwrap();

        let sym_path = tmp.path().join("link.txt");
        std::os::unix::fs::symlink(&real_path, &sym_path).unwrap();

        // Real file must succeed.
        assert!(
            open_regular_file_nofollow(&real_path).is_ok(),
            "real file should open successfully"
        );

        // Symlink must be rejected at the kernel open(2) level.
        let result = open_regular_file_nofollow(&sym_path);
        assert!(
            result.is_err(),
            "symlink must be rejected by O_NOFOLLOW at open(2)"
        );
    }

    /// Regression: `open_regular_file_nofollow` must reject FIFO (named pipe)
    /// targets without blocking, even when no writer is attached.
    ///
    /// With `O_NONBLOCK` set, open(2) on a FIFO for read returns immediately
    /// (succeeds without a writer on Linux), then the fstat regular-file
    /// check rejects it. Without `O_NONBLOCK`, the open would block
    /// indefinitely waiting for a writer — a local denial-of-service vector.
    #[test]
    #[cfg(unix)]
    fn test_open_regular_file_nofollow_rejects_fifo() {
        use std::time::{Duration, Instant};

        let tmp = tempfile::tempdir().expect("tempdir");
        let fifo_path = tmp.path().join("malicious.fifo");

        // Create a named pipe (FIFO) — no writer attached.
        nix::unistd::mkfifo(&fifo_path, nix::sys::stat::Mode::S_IRWXU)
            .expect("mkfifo should succeed in temp dir");

        // O_NONBLOCK on the function ensures this open returns immediately
        // even without a writer. The fstat check then rejects the FIFO.
        let start = Instant::now();
        let result = open_regular_file_nofollow(&fifo_path);
        let elapsed = start.elapsed();

        assert!(
            result.is_err(),
            "FIFO must be rejected as not a regular file"
        );
        let err = result.unwrap_err();
        assert!(
            err.contains("not a regular file"),
            "error should mention non-regular file: {err}"
        );
        assert!(
            elapsed < Duration::from_secs(2),
            "open on FIFO must not block (O_NONBLOCK): took {elapsed:?}"
        );
    }

    /// Regression: `read_job_spec_bounded` must reject a FIFO in a queue
    /// directory without blocking indefinitely (denial-of-service prevention).
    ///
    /// Without `O_NONBLOCK`, opening a FIFO for read blocks until a writer
    /// attaches, so the fstat regular-file check never runs. This test
    /// creates a FIFO with no writer and verifies the function returns an
    /// error promptly (not a hang).
    #[test]
    #[cfg(unix)]
    fn test_read_job_spec_bounded_rejects_fifo_without_blocking() {
        use std::time::{Duration, Instant};

        let tmp = tempfile::tempdir().expect("tempdir");
        let fifo_path = tmp.path().join("malicious.json");

        // Create a FIFO disguised as a .json queue entry — no writer.
        nix::unistd::mkfifo(&fifo_path, nix::sys::stat::Mode::S_IRWXU)
            .expect("mkfifo should succeed in temp dir");

        // read_job_spec_bounded must return Err promptly, not hang.
        let start = Instant::now();
        let result = read_job_spec_bounded(&fifo_path);
        let elapsed = start.elapsed();

        assert!(result.is_err(), "FIFO queue entry must be rejected");
        let err = result.unwrap_err();
        assert!(
            err.contains("not a regular file"),
            "error should indicate non-regular file: {err}"
        );
        assert!(
            elapsed < Duration::from_secs(2),
            "read_job_spec_bounded on FIFO must not block (O_NONBLOCK): took {elapsed:?}"
        );
    }

    /// Regression: `read_job_spec_bounded` must reject non-regular files
    /// (e.g., directories) fail-closed via `fstat` on the opened fd.
    #[test]
    fn test_read_job_spec_bounded_rejects_directory() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let dir_path = tmp.path().join("fakejob.json");
        fs::create_dir(&dir_path).unwrap();

        let result = read_job_spec_bounded(&dir_path);
        assert!(result.is_err(), "directory must be rejected");
        let err = result.unwrap_err();
        // On Linux with O_NOFOLLOW, opening a directory may produce
        // EISDIR or the fstat check catches it as "not a regular file".
        assert!(
            err.contains("not a regular file") || err.contains("Is a directory"),
            "error should indicate non-regular file: {err}"
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
