use std::io;
#[cfg(unix)]
use std::os::unix::io::AsRawFd;

#[cfg(unix)]
#[allow(unsafe_code)]
pub fn try_acquire_exclusive_nonblocking(file: &std::fs::File) -> io::Result<bool> {
    let fd = file.as_raw_fd();
    // SAFETY: `fd` is a valid file descriptor from an open `std::fs::File`.
    // `LOCK_EX | LOCK_NB` is a valid `flock` operation that cannot cause undefined
    // behavior in safe Rust.
    // The file handle remains alive for the duration of this call, so `fd` remains
    // valid.
    let rc = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
    if rc == 0 {
        return Ok(true);
    }
    let err = io::Error::last_os_error();
    if err.kind() == io::ErrorKind::WouldBlock || err.raw_os_error() == Some(libc::EWOULDBLOCK) {
        return Ok(false);
    }
    Err(err)
}

#[cfg(not(unix))]
pub fn try_acquire_exclusive_nonblocking(_: &std::fs::File) -> io::Result<bool> {
    Ok(true)
}

/// Acquire an exclusive `flock` on the given file descriptor, blocking until
/// the lock is available.
///
/// # Synchronization protocol
///
/// - **What is protected**: the cache index directory identified by the lock
///   file's path.
/// - **Who can mutate**: only the holder of the exclusive flock on this file
///   descriptor.
/// - **Lock ordering**: single lock per index key; no nested locks.
/// - **Happens-before**: `flock(LOCK_EX)` acquisition happens-after the
///   previous holder's `close(fd)` / `flock(LOCK_UN)`.
///
/// On non-Unix platforms, this is a no-op (returns `Ok(())`).
#[cfg(unix)]
#[allow(unsafe_code)]
pub fn acquire_exclusive_blocking(file: &std::fs::File) -> io::Result<()> {
    let fd = file.as_raw_fd();
    // SAFETY: `fd` is a valid file descriptor from an open `std::fs::File`.
    // `LOCK_EX` (blocking) is a valid `flock` operation. The file handle
    // remains alive for the duration of this call, so `fd` remains valid.
    let rc = unsafe { libc::flock(fd, libc::LOCK_EX) };
    if rc == 0 {
        return Ok(());
    }
    Err(io::Error::last_os_error())
}

#[cfg(not(unix))]
pub fn acquire_exclusive_blocking(_: &std::fs::File) -> io::Result<()> {
    Ok(())
}
