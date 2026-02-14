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
