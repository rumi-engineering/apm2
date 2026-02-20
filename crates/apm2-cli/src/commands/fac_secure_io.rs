//! Shared FAC file I/O helpers with fail-closed bounded reads.

use std::fs::OpenOptions;
use std::io::Read;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

/// Read a regular file with a strict byte cap.
///
/// Security properties:
/// - Refuses symlinks on Unix (`O_NOFOLLOW`).
/// - Refuses non-regular files (FIFOs, sockets, devices).
/// - Opens with `O_NONBLOCK` to prevent indefinite blocking on FIFOs
///   (defense-in-depth; primary guard is the `symlink_metadata` pre-check in
///   callers such as `promote_broker_requests`).
/// - Enforces `max_size` with `Read::take(max_size + 1)` (fail-closed).
pub fn read_bounded(path: &Path, max_size: usize) -> Result<Vec<u8>, String> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    }

    let file = options
        .open(path)
        .map_err(|err| format!("open {}: {err}", path.display()))?;
    let metadata = file
        .metadata()
        .map_err(|err| format!("stat {}: {err}", path.display()))?;
    if !metadata.is_file() {
        return Err(format!(
            "path {} is not a regular file (fail-closed)",
            path.display()
        ));
    }

    if metadata.len() > max_size as u64 {
        return Err(format!(
            "file {} too large: {} > {}",
            path.display(),
            metadata.len(),
            max_size
        ));
    }

    #[allow(clippy::cast_possible_truncation)]
    let alloc_size = metadata.len() as usize;
    let mut bytes = Vec::with_capacity(alloc_size.min(max_size));
    let mut reader = file.take(max_size.saturating_add(1) as u64);
    reader
        .read_to_end(&mut bytes)
        .map_err(|err| format!("read {}: {err}", path.display()))?;
    if bytes.len() > max_size {
        return Err(format!(
            "file {} grew to {} (exceeds max {})",
            path.display(),
            bytes.len(),
            max_size
        ));
    }
    Ok(bytes)
}

/// Read UTF-8-ish text with a strict byte cap.
pub fn read_bounded_text(path: &Path, max_size: usize) -> Result<String, String> {
    let bytes = read_bounded(path, max_size)?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}
