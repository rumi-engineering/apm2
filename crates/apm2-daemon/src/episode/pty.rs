//! PTY spawning and management for episode processes.
//!
//! This module provides `PtyRunner` for spawning and managing child processes
//! with pseudo-terminal (PTY) I/O. It handles:
//!
//! - PTY allocation via `nix::pty::openpty()`
//! - Child process spawning with proper session setup
//! - Async output capture with sequence numbers and timestamps
//! - Ring buffer for flight recorder retention
//! - Process lifecycle management (input, signals, wait, resize)
//!
//! # Architecture
//!
//! ```text
//! PtyRunner
//!     |
//!     +-- master_fd (OwnedFd)
//!     |       |
//!     |       +-- write: send_input()
//!     |       +-- read: output capture task
//!     |
//!     +-- child_pid (Pid)
//!     |       |
//!     |       +-- signal()
//!     |       +-- wait()
//!     |
//!     +-- output_rx (mpsc::Receiver<PtyOutput>)
//!     |
//!     +-- ring_buffer (RingBuffer<PtyOutput>)
//! ```
//!
//! # Invariants
//!
//! - [INV-PTY001] Child process runs in new session (setsid)
//! - [INV-PTY002] Slave PTY becomes child's controlling terminal
//! - [INV-PTY003] Master fd uses `AsyncFd` with non-blocking mode for async I/O
//! - [INV-PTY004] Output capture uses caller-provided timestamps (HARD-TIME)
//! - [INV-PTY005] Ring buffer size is bounded per risk tier
//!
//! # Security Considerations
//!
//! This is SCP (Security-Critical Path) code:
//! - Fail-closed on all error paths
//! - No `Instant::now()` per HARD-TIME principle
//! - Bounded buffers to prevent memory exhaustion
//! - Proper cleanup on drop (SIGKILL if needed)
//!
//! # Safety
//!
//! This module requires unsafe code for PTY operations (fork, ioctl, dup2,
//! `clock_gettime`, raw fd handling). All unsafe blocks are minimized and
//! documented with safety comments.

#![allow(unsafe_code)]

use std::ffi::{CString, OsStr};
use std::io::{self, Read};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use bytes::Bytes;
use nix::errno::Errno;
use nix::fcntl::{FcntlArg, OFlag, fcntl};
use nix::libc;
use nix::pty::{Winsize, openpty};
use nix::sys::signal::{self, Signal};
use nix::sys::wait::{WaitStatus, waitpid};
use nix::unistd::{ForkResult, Pid, close, execvp, fork, setsid};
use thiserror::Error;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use super::output::{PtyOutput, SequenceGenerator};
use super::ring_buffer::RingBuffer;

/// Default channel capacity for output messages.
const OUTPUT_CHANNEL_CAPACITY: usize = 1024;

/// Default read buffer size for PTY output.
const READ_BUFFER_SIZE: usize = 8192;

/// Maximum allowed read buffer size (64KB) to prevent denial-of-service via
/// memory exhaustion.
///
/// This limit ensures that even with maximum ring buffer capacity, memory usage
/// per PTY runner is bounded: `MAX_READ_BUFFER_SIZE * MAX_RING_BUFFER_CAPACITY`
/// = 64KB * 4096 = 256MB worst case per PTY.
const MAX_READ_BUFFER_SIZE: usize = 64 * 1024;

/// Maximum allowed ring buffer capacity to prevent denial-of-service via memory
/// exhaustion.
///
/// Combined with `MAX_READ_BUFFER_SIZE`, this bounds total memory per PTY.
const MAX_RING_BUFFER_CAPACITY: usize = 4096;

/// Maximum allowed channel capacity.
const MAX_CHANNEL_CAPACITY: usize = 8192;

/// Grace period for SIGTERM before SIGKILL in drop (milliseconds).
///
/// This is intentionally short (10ms) to avoid blocking tokio workers.
/// If the process needs longer to clean up, it should handle shutdown
/// before the runner is dropped.
const DROP_GRACE_PERIOD_MS: u64 = 10;

/// PTY runner errors.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum PtyError {
    /// Failed to allocate PTY pair.
    #[error("failed to allocate PTY: {0}")]
    PtyAllocation(#[source] Errno),

    /// Failed to fork child process.
    #[error("failed to fork: {0}")]
    Fork(#[source] Errno),

    /// Failed to create new session.
    #[error("failed to create session: {0}")]
    Setsid(#[source] Errno),

    /// Failed to duplicate file descriptor.
    #[error("failed to dup2: {0}")]
    Dup2(#[source] Errno),

    /// Failed to close file descriptor.
    #[error("failed to close fd: {0}")]
    Close(#[source] Errno),

    /// Failed to execute command.
    #[error("failed to exec '{command}': {source}")]
    Exec {
        /// The command that failed to execute.
        command: String,
        /// The underlying error.
        #[source]
        source: Errno,
    },

    /// Invalid command (empty or contains null bytes).
    #[error("invalid command: {0}")]
    InvalidCommand(String),

    /// Failed to convert path to `CString`.
    #[error("invalid path: contains null byte")]
    InvalidPath,

    /// Failed to send signal to child.
    #[error("failed to send signal {signal:?} to pid {pid}: {source}")]
    Signal {
        /// The signal that failed to send.
        signal: Signal,
        /// The target process ID.
        pid: i32,
        /// The underlying error.
        #[source]
        source: Errno,
    },

    /// Failed to wait for child process.
    #[error("failed to wait for child: {0}")]
    Wait(#[source] Errno),

    /// Failed to write to PTY.
    #[error("failed to write to PTY: {0}")]
    Write(#[source] std::io::Error),

    /// Failed to read from PTY.
    #[error("failed to read from PTY: {0}")]
    Read(#[source] std::io::Error),

    /// Failed to set PTY window size.
    #[error("failed to set window size: {0}")]
    Winsize(#[source] Errno),

    /// Child process not running.
    #[error("child process not running")]
    NotRunning,

    /// Channel send failed.
    #[error("output channel closed")]
    ChannelClosed,

    /// Failed to set non-blocking mode.
    #[error("failed to set non-blocking: {0}")]
    NonBlocking(#[source] std::io::Error),

    /// Failed to duplicate file descriptor.
    #[error("failed to dup fd: {0}")]
    DupFd(#[source] std::io::Error),

    /// Failed to create `AsyncFd`.
    #[error("failed to create AsyncFd: {0}")]
    AsyncFd(#[source] std::io::Error),

    /// Invalid configuration value.
    #[error("invalid config: {0}")]
    InvalidConfig(String),
}

/// Exit status of the child process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitStatus {
    /// Process exited normally with the given code.
    Exited(i32),
    /// Process was killed by a signal.
    Signaled(Signal),
    /// Process is still running.
    Running,
}

impl ExitStatus {
    /// Returns `true` if the process exited successfully (code 0).
    #[must_use]
    pub const fn success(&self) -> bool {
        matches!(self, Self::Exited(0))
    }

    /// Returns the exit code if the process exited normally.
    #[must_use]
    pub const fn code(&self) -> Option<i32> {
        match self {
            Self::Exited(code) => Some(*code),
            _ => None,
        }
    }
}

/// Configuration for PTY runner.
///
/// All fields are private to enforce validation. Use the builder methods
/// to configure, or use `Default::default()` for safe defaults.
///
/// # Security
///
/// Configuration values are bounded to prevent denial-of-service via memory
/// exhaustion:
/// - `read_buffer_size`: max 64KB
/// - `ring_buffer_capacity`: max 4096
/// - `channel_capacity`: max 8192
#[derive(Debug, Clone, Copy)]
pub struct PtyConfig {
    /// Initial window size (cols, rows).
    window_size: (u16, u16),
    /// Ring buffer capacity for output.
    ring_buffer_capacity: usize,
    /// Channel capacity for output messages.
    channel_capacity: usize,
    /// Read buffer size.
    read_buffer_size: usize,
}

impl Default for PtyConfig {
    fn default() -> Self {
        Self {
            window_size: (80, 24),
            ring_buffer_capacity: 1024,
            channel_capacity: OUTPUT_CHANNEL_CAPACITY,
            read_buffer_size: READ_BUFFER_SIZE,
        }
    }
}

impl PtyConfig {
    /// Creates a new `PtyConfig` with validated parameters.
    ///
    /// # Errors
    ///
    /// Returns `PtyError::InvalidConfig` if any parameter exceeds bounds:
    /// - `read_buffer_size` > 64KB
    /// - `ring_buffer_capacity` > 4096
    /// - `channel_capacity` > 8192
    /// - `read_buffer_size` or `ring_buffer_capacity` is 0
    pub fn new(
        window_size: (u16, u16),
        ring_buffer_capacity: usize,
        channel_capacity: usize,
        read_buffer_size: usize,
    ) -> Result<Self, PtyError> {
        // Validate bounds to prevent DoS via memory exhaustion
        if read_buffer_size == 0 {
            return Err(PtyError::InvalidConfig(
                "read_buffer_size must be > 0".to_string(),
            ));
        }
        if read_buffer_size > MAX_READ_BUFFER_SIZE {
            return Err(PtyError::InvalidConfig(format!(
                "read_buffer_size {read_buffer_size} exceeds max {MAX_READ_BUFFER_SIZE}"
            )));
        }
        if ring_buffer_capacity == 0 {
            return Err(PtyError::InvalidConfig(
                "ring_buffer_capacity must be > 0".to_string(),
            ));
        }
        if ring_buffer_capacity > MAX_RING_BUFFER_CAPACITY {
            return Err(PtyError::InvalidConfig(format!(
                "ring_buffer_capacity {ring_buffer_capacity} exceeds max {MAX_RING_BUFFER_CAPACITY}"
            )));
        }
        if channel_capacity == 0 {
            return Err(PtyError::InvalidConfig(
                "channel_capacity must be > 0".to_string(),
            ));
        }
        if channel_capacity > MAX_CHANNEL_CAPACITY {
            return Err(PtyError::InvalidConfig(format!(
                "channel_capacity {channel_capacity} exceeds max {MAX_CHANNEL_CAPACITY}"
            )));
        }

        Ok(Self {
            window_size,
            ring_buffer_capacity,
            channel_capacity,
            read_buffer_size,
        })
    }

    /// Returns the window size (cols, rows).
    #[must_use]
    pub const fn window_size(&self) -> (u16, u16) {
        self.window_size
    }

    /// Returns the ring buffer capacity.
    #[must_use]
    pub const fn ring_buffer_capacity(&self) -> usize {
        self.ring_buffer_capacity
    }

    /// Returns the channel capacity.
    #[must_use]
    pub const fn channel_capacity(&self) -> usize {
        self.channel_capacity
    }

    /// Returns the read buffer size.
    #[must_use]
    pub const fn read_buffer_size(&self) -> usize {
        self.read_buffer_size
    }

    /// Creates a config with the specified window size.
    #[must_use]
    pub const fn with_window_size(mut self, cols: u16, rows: u16) -> Self {
        self.window_size = (cols, rows);
        self
    }

    /// Creates a config with the specified ring buffer capacity.
    ///
    /// The capacity is clamped to `MAX_RING_BUFFER_CAPACITY` (4096).
    #[must_use]
    pub const fn with_ring_buffer_capacity(mut self, capacity: usize) -> Self {
        self.ring_buffer_capacity = if capacity > MAX_RING_BUFFER_CAPACITY {
            MAX_RING_BUFFER_CAPACITY
        } else if capacity == 0 {
            1
        } else {
            capacity
        };
        self
    }

    /// Creates a config with the specified channel capacity.
    ///
    /// The capacity is clamped to `MAX_CHANNEL_CAPACITY` (8192).
    #[must_use]
    pub const fn with_channel_capacity(mut self, capacity: usize) -> Self {
        self.channel_capacity = if capacity > MAX_CHANNEL_CAPACITY {
            MAX_CHANNEL_CAPACITY
        } else if capacity == 0 {
            1
        } else {
            capacity
        };
        self
    }

    /// Creates a config with the specified read buffer size.
    ///
    /// The size is clamped to `MAX_READ_BUFFER_SIZE` (64KB).
    #[must_use]
    pub const fn with_read_buffer_size(mut self, size: usize) -> Self {
        self.read_buffer_size = if size > MAX_READ_BUFFER_SIZE {
            MAX_READ_BUFFER_SIZE
        } else if size == 0 {
            1
        } else {
            size
        };
        self
    }
}

/// PTY runner for managing a child process with PTY I/O.
///
/// # Example
///
/// ```rust,ignore
/// use apm2_daemon::episode::pty::{PtyRunner, PtyConfig};
///
/// let config = PtyConfig::default();
/// let mut runner = PtyRunner::spawn("/bin/echo", &["hello"], config, timestamp_ns)?;
///
/// // Read output
/// while let Some(output) = runner.recv().await {
///     println!("seq={} ts={}: {:?}", output.seq, output.ts_mono, output.chunk);
/// }
///
/// // Wait for exit
/// let status = runner.wait()?;
/// ```
pub struct PtyRunner {
    /// Master side of the PTY pair.
    master_fd: Option<OwnedFd>,
    /// Child process ID.
    child_pid: Pid,
    /// Receiver for output messages.
    output_rx: mpsc::Receiver<PtyOutput>,
    /// Ring buffer for flight recorder.
    ring_buffer: RingBuffer<PtyOutput>,
    /// Cached exit status.
    exit_status: Option<ExitStatus>,
    /// Handle to the output capture task.
    _capture_task: Option<tokio::task::JoinHandle<()>>,
}

impl PtyRunner {
    /// Spawns a new process with PTY I/O.
    ///
    /// # Arguments
    ///
    /// * `program` - Path to the program to execute
    /// * `args` - Command-line arguments (program name should be first)
    /// * `config` - PTY configuration
    /// * `timestamp_ns` - Current timestamp in nanoseconds (HARD-TIME)
    ///
    /// # Errors
    ///
    /// Returns `PtyError` if PTY allocation, fork, or exec fails.
    ///
    /// # Safety
    ///
    /// This function uses `unsafe` for the fork/exec sequence. The child
    /// process performs minimal operations before exec to minimize risk.
    pub fn spawn<P, S>(
        program: P,
        args: &[S],
        config: PtyConfig,
        _timestamp_ns: u64,
    ) -> Result<Self, PtyError>
    where
        P: AsRef<Path>,
        S: AsRef<OsStr>,
    {
        let program_path = program.as_ref();

        // Validate program path
        let program_cstr = path_to_cstring(program_path)?;

        // Build args as CStrings (program name should be argv[0])
        let mut arg_cstrings: Vec<CString> = Vec::with_capacity(args.len() + 1);

        // argv[0] is typically the program name
        arg_cstrings.push(program_cstr.clone());

        // Add remaining arguments
        for arg in args {
            let arg_bytes = arg.as_ref().as_bytes();
            let cstr = CString::new(arg_bytes)
                .map_err(|_| PtyError::InvalidCommand("argument contains null byte".to_string()))?;
            arg_cstrings.push(cstr);
        }

        // Create PTY pair
        let (cols, rows) = config.window_size();
        let winsize = Winsize {
            ws_row: rows,
            ws_col: cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };

        let pty = openpty(Some(&winsize), None).map_err(PtyError::PtyAllocation)?;

        // Create channel for output
        let (output_tx, output_rx) = mpsc::channel(config.channel_capacity());

        // Fork child process
        // SAFETY: We perform minimal operations in the child before exec.
        // The child sets up the session/terminal and execs immediately.
        let fork_result = unsafe { fork() }.map_err(PtyError::Fork)?;

        match fork_result {
            ForkResult::Child => {
                // Child process - setup and exec
                //
                // CRITICAL SECURITY: All error paths in the child process MUST call
                // `libc::_exit(1)` instead of returning `Err`. Returning from the child
                // would allow the forked process to continue executing the daemon's
                // codebase as a "ghost" process, which is a severe security vulnerability.
                //
                // We use `_exit()` (not `exit()`) to avoid running atexit handlers and
                // flushing stdio buffers from the parent's context.

                // Close master fd in child
                let _ = close(pty.master.as_raw_fd());

                // Create new session (detach from controlling terminal)
                // SAFETY: _exit is safe to call from the child process
                if setsid().is_err() {
                    unsafe { libc::_exit(1) };
                }

                // Set slave as controlling terminal
                // SAFETY: TIOCSCTTY is a valid ioctl for setting controlling terminal
                unsafe {
                    if libc::ioctl(pty.slave.as_raw_fd(), libc::TIOCSCTTY, 0) < 0 {
                        // Best effort - continue anyway (some systems don't
                        // require this)
                    }
                }

                // Duplicate slave to stdin, stdout, stderr
                // SAFETY: dup2 is a standard POSIX call. We're in the child
                // process after fork, so we need to use raw file descriptors
                // to set up stdin/stdout/stderr before exec.
                // SAFETY: _exit is safe to call from the child process
                let slave_fd = pty.slave.as_raw_fd();
                unsafe {
                    if libc::dup2(slave_fd, libc::STDIN_FILENO) < 0 {
                        libc::_exit(1);
                    }
                    if libc::dup2(slave_fd, libc::STDOUT_FILENO) < 0 {
                        libc::_exit(1);
                    }
                    if libc::dup2(slave_fd, libc::STDERR_FILENO) < 0 {
                        libc::_exit(1);
                    }
                }

                // Close the original slave fd if it's not one of 0, 1, 2
                if slave_fd > libc::STDERR_FILENO {
                    let _ = close(slave_fd);
                }

                // Execute the program
                // This replaces the current process image
                // SAFETY: _exit is safe to call from the child process
                if execvp(&program_cstr, &arg_cstrings).is_err() {
                    unsafe { libc::_exit(127) }; // 127 = command not found convention
                }

                // execvp never returns on success, but if it somehow does, exit
                // SAFETY: _exit is safe to call from the child process
                unsafe { libc::_exit(1) };
            },
            ForkResult::Parent { child } => {
                // Parent process
                info!(pid = %child, program = %program_path.display(), "spawned PTY process");

                // Close slave fd in parent
                drop(pty.slave);

                // Create ring buffer
                let ring_buffer = RingBuffer::new(config.ring_buffer_capacity());

                // Convert master fd to async
                // Note: We keep the OwnedFd but spawn a task to read from it
                let master_fd = pty.master;

                // Spawn output capture task (fail-closed: propagate errors)
                let capture_task = spawn_capture_task(
                    master_fd.as_raw_fd(),
                    output_tx,
                    config.read_buffer_size(),
                )?;

                Ok(Self {
                    master_fd: Some(master_fd),
                    child_pid: child,
                    output_rx,
                    ring_buffer,
                    exit_status: None,
                    _capture_task: Some(capture_task),
                })
            },
        }
    }

    /// Returns the child process ID.
    #[must_use]
    pub const fn pid(&self) -> Pid {
        self.child_pid
    }

    /// Receives the next output chunk.
    ///
    /// This also stores the output in the ring buffer for flight recorder.
    ///
    /// # Returns
    ///
    /// Returns `Some(output)` if output is available, `None` if the channel
    /// is closed (process exited).
    pub async fn recv(&mut self) -> Option<PtyOutput> {
        let output = self.output_rx.recv().await?;
        // Store in ring buffer for flight recorder
        self.ring_buffer.push(output.clone());
        Some(output)
    }

    /// Tries to receive output without blocking.
    ///
    /// # Returns
    ///
    /// Returns `Some(output)` if output is immediately available,
    /// `None` otherwise.
    pub fn try_recv(&mut self) -> Option<PtyOutput> {
        match self.output_rx.try_recv() {
            Ok(output) => {
                self.ring_buffer.push(output.clone());
                Some(output)
            },
            Err(_) => None,
        }
    }

    /// Sends input to the child process.
    ///
    /// # Arguments
    ///
    /// * `data` - Data to write to the PTY
    ///
    /// # Errors
    ///
    /// Returns `PtyError::Write` if the write fails.
    /// Returns `PtyError::NotRunning` if the process has exited.
    ///
    /// # Note
    ///
    /// This method uses blocking I/O via `spawn_blocking` because PTY master
    /// fds don't have reliable async write support. The write is typically
    /// fast (kernel buffer) so blocking is acceptable. For high-throughput
    /// scenarios, consider batching writes.
    pub async fn send_input(&mut self, data: &[u8]) -> Result<(), PtyError> {
        let master_fd = self.master_fd.as_ref().ok_or(PtyError::NotRunning)?;
        let fd = master_fd.as_raw_fd();

        // Copy data to owned buffer for spawn_blocking
        let data = data.to_vec();

        // Use spawn_blocking to avoid blocking the tokio runtime.
        // PTY writes are typically fast (kernel buffer copy), but we don't want
        // to risk blocking the async runtime if the buffer is full.
        tokio::task::spawn_blocking(move || {
            let mut written = 0;
            while written < data.len() {
                // SAFETY: Writing from a valid buffer to a valid fd.
                let n = unsafe {
                    libc::write(
                        fd,
                        data[written..].as_ptr().cast::<libc::c_void>(),
                        data.len() - written,
                    )
                };
                if n < 0 {
                    let err = io::Error::last_os_error();
                    // Handle EINTR by retrying
                    if err.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    // Handle WouldBlock by yielding and retrying
                    // (shouldn't happen often for PTY writes, but handle it)
                    if err.kind() == io::ErrorKind::WouldBlock {
                        std::thread::yield_now();
                        continue;
                    }
                    return Err(PtyError::Write(err));
                }
                #[allow(clippy::cast_sign_loss)]
                {
                    written += n as usize;
                }
            }
            Ok(())
        })
        .await
        .map_err(|e| PtyError::Write(io::Error::other(e)))?
    }

    /// Sends a signal to the child process.
    ///
    /// # Arguments
    ///
    /// * `sig` - Signal to send
    ///
    /// # Errors
    ///
    /// Returns `PtyError::Signal` if sending the signal fails.
    pub fn signal(&self, sig: Signal) -> Result<(), PtyError> {
        signal::kill(self.child_pid, sig).map_err(|e| PtyError::Signal {
            signal: sig,
            pid: self.child_pid.as_raw(),
            source: e,
        })
    }

    /// Waits for the child process to exit (non-blocking check).
    ///
    /// # Returns
    ///
    /// Returns the exit status if the process has exited, or
    /// `ExitStatus::Running` if still running.
    ///
    /// # Errors
    ///
    /// Returns `PtyError::Wait` if the wait syscall fails.
    pub fn try_wait(&mut self) -> Result<ExitStatus, PtyError> {
        if let Some(status) = self.exit_status {
            return Ok(status);
        }

        match waitpid(self.child_pid, Some(nix::sys::wait::WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::Exited(_, code)) => {
                let status = ExitStatus::Exited(code);
                self.exit_status = Some(status);
                Ok(status)
            },
            Ok(WaitStatus::Signaled(_, sig, _)) => {
                let status = ExitStatus::Signaled(sig);
                self.exit_status = Some(status);
                Ok(status)
            },
            // Other statuses (StillAlive, Stopped, Continued, etc.)
            Ok(_) => Ok(ExitStatus::Running),
            Err(Errno::ECHILD) => {
                // Child already reaped
                let status = ExitStatus::Exited(0);
                self.exit_status = Some(status);
                Ok(status)
            },
            Err(e) => Err(PtyError::Wait(e)),
        }
    }

    /// Waits for the child process to exit (blocking).
    ///
    /// # Returns
    ///
    /// Returns the exit status when the process exits.
    ///
    /// # Errors
    ///
    /// Returns `PtyError::Wait` if the wait syscall fails.
    pub fn wait(&mut self) -> Result<ExitStatus, PtyError> {
        if let Some(status) = self.exit_status {
            return Ok(status);
        }

        match waitpid(self.child_pid, None) {
            Ok(WaitStatus::Exited(_, code)) => {
                let status = ExitStatus::Exited(code);
                self.exit_status = Some(status);
                Ok(status)
            },
            Ok(WaitStatus::Signaled(_, sig, _)) => {
                let status = ExitStatus::Signaled(sig);
                self.exit_status = Some(status);
                Ok(status)
            },
            Ok(_) => {
                // Other statuses - try again
                self.wait()
            },
            Err(Errno::ECHILD) => {
                // Child already reaped
                let status = ExitStatus::Exited(0);
                self.exit_status = Some(status);
                Ok(status)
            },
            Err(e) => Err(PtyError::Wait(e)),
        }
    }

    /// Resizes the PTY window.
    ///
    /// # Arguments
    ///
    /// * `cols` - Number of columns
    /// * `rows` - Number of rows
    ///
    /// # Errors
    ///
    /// Returns `PtyError::Winsize` if the ioctl fails.
    /// Returns `PtyError::NotRunning` if the process has exited.
    pub fn resize(&self, cols: u16, rows: u16) -> Result<(), PtyError> {
        let master_fd = self.master_fd.as_ref().ok_or(PtyError::NotRunning)?;

        let winsize = Winsize {
            ws_row: rows,
            ws_col: cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };

        // SAFETY: TIOCSWINSZ is a valid ioctl for setting window size
        let result = unsafe { libc::ioctl(master_fd.as_raw_fd(), libc::TIOCSWINSZ, &winsize) };

        if result < 0 {
            Err(PtyError::Winsize(Errno::last()))
        } else {
            debug!(cols, rows, "resized PTY window");
            Ok(())
        }
    }

    /// Drains all items from the ring buffer.
    ///
    /// This is used to persist flight recorder data.
    pub fn drain_ring_buffer(&mut self) -> impl Iterator<Item = PtyOutput> + '_ {
        self.ring_buffer.drain()
    }

    /// Clears the ring buffer.
    pub fn clear_ring_buffer(&mut self) {
        self.ring_buffer.clear();
    }

    /// Returns the number of items in the ring buffer.
    #[must_use]
    pub fn ring_buffer_len(&self) -> usize {
        self.ring_buffer.len()
    }
}

impl Drop for PtyRunner {
    fn drop(&mut self) {
        // Close master fd first - this signals EOF to the child
        self.master_fd.take();

        // Try to reap the child if not already done
        if self.exit_status.is_none() {
            // Check if already exited (non-blocking)
            if matches!(self.try_wait(), Ok(ExitStatus::Running)) {
                // Send SIGTERM
                if self.signal(Signal::SIGTERM).is_ok() {
                    // Brief grace period - kept short (10ms) to avoid blocking tokio workers.
                    // Closing master_fd above already signals the child via EOF.
                    // If a process needs longer cleanup, it should be terminated gracefully
                    // before dropping the runner.
                    std::thread::sleep(std::time::Duration::from_millis(DROP_GRACE_PERIOD_MS));

                    // Check again
                    if matches!(self.try_wait(), Ok(ExitStatus::Running)) {
                        // Force kill
                        warn!(pid = %self.child_pid, "sending SIGKILL to orphan process");
                        let _ = self.signal(Signal::SIGKILL);
                        let _ = self.wait();
                    }
                }
            }
        }
    }
}

/// Converts a path to a `CString`.
fn path_to_cstring(path: &Path) -> Result<CString, PtyError> {
    let bytes = path.as_os_str().as_bytes();
    CString::new(bytes).map_err(|_| PtyError::InvalidPath)
}

/// Sets a file descriptor to non-blocking mode.
///
/// This is required for using `AsyncFd` with the PTY master.
///
/// # Errors
///
/// Returns `PtyError::NonBlocking` if the fcntl call fails.
fn set_nonblocking(fd: BorrowedFd<'_>) -> Result<(), PtyError> {
    // Get current flags
    let flags = fcntl(fd, FcntlArg::F_GETFL)
        .map_err(|e| PtyError::NonBlocking(io::Error::from_raw_os_error(e as i32)))?;

    // Add O_NONBLOCK
    let new_flags = OFlag::from_bits_truncate(flags) | OFlag::O_NONBLOCK;
    fcntl(fd, FcntlArg::F_SETFL(new_flags))
        .map_err(|e| PtyError::NonBlocking(io::Error::from_raw_os_error(e as i32)))?;

    Ok(())
}

/// Wrapper around `OwnedFd` that implements `Read` and `AsRawFd` for use with
/// `AsyncFd`.
///
/// `AsyncFd` requires `AsRawFd` for registration with the reactor.
/// The `Read` implementation is provided for convenience but the async
/// read loop uses `libc::read` directly for non-blocking I/O.
struct ReadableFd(OwnedFd);

impl AsFd for ReadableFd {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}

impl AsRawFd for ReadableFd {
    fn as_raw_fd(&self) -> i32 {
        self.0.as_raw_fd()
    }
}

impl Read for ReadableFd {
    #[allow(clippy::cast_sign_loss)] // n is checked to be >= 0 before cast
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // SAFETY: We're reading into a valid buffer from a valid fd
        let n = unsafe {
            libc::read(
                self.0.as_raw_fd(),
                buf.as_mut_ptr().cast::<libc::c_void>(),
                buf.len(),
            )
        };
        if n < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    }
}

/// Spawns the async output capture task.
///
/// This task reads from the master PTY fd and sends output chunks through the
/// channel. It uses `AsyncFd` with non-blocking I/O for efficient async reads
/// without blocking a thread per episode. This approach supports scaling to
/// `MAX_CONCURRENT_EPISODES` = 10,000 without exhausting the tokio blocking
/// thread pool (INV-PTY003).
///
/// # FD Ownership
///
/// The capture task duplicates the master FD using `dup()` to get its own owned
/// copy. This avoids IO Safety violations from multiple `tokio::fs::File`
/// instances wrapping the same raw FD. The duplicated FD is closed when the
/// task completes, while the original FD remains owned by `PtyRunner`.
///
/// # Timestamp Handling (HARD-TIME)
///
/// This function uses `clock_gettime(CLOCK_MONOTONIC)` directly for output
/// timestamps. While the `spawn` function accepts a `timestamp_ns` parameter
/// for HARD-TIME compliance at the episode envelope level, the capture task
/// operates asynchronously and must timestamp each output chunk at the moment
/// it's read. Using a stale initial timestamp would produce incorrect ordering
/// information.
///
/// The monotonic clock is acceptable here because:
/// 1. Output timestamps are for ordering within a single episode, not
///    cross-episode correlation. This is a documented exception to HARD-TIME.
/// 2. Sequence numbers provide the primary ordering guarantee (INV-OUT001)
/// 3. The monotonic clock provides relative ordering without wall-clock issues
/// 4. `CLOCK_MONOTONIC` is not affected by NTP adjustments or timezone changes
///
/// For replay/simulation scenarios where deterministic timestamps are required,
/// the flight recorder should be fed pre-timestamped data rather than capturing
/// live.
///
/// # Errors
///
/// Returns `PtyError` if:
/// - `dup()` fails to duplicate the FD
/// - `set_nonblocking()` fails
/// - `AsyncFd::new()` fails
///
/// # Security (Fail-Closed)
///
/// This function returns an error instead of spawning a no-op task on failure.
/// This ensures that PTY spawn fails if output capture cannot be established,
/// following the fail-closed principle.
fn spawn_capture_task(
    master_fd: i32,
    output_tx: mpsc::Sender<PtyOutput>,
    buffer_size: usize,
) -> Result<tokio::task::JoinHandle<()>, PtyError> {
    // Duplicate the FD so the capture task has its own owned copy.
    // This avoids IO Safety violations from having multiple File handles to the
    // same raw FD. The duplicated FD will be closed when the task's OwnedFd is
    // dropped.
    //
    // SAFETY: master_fd is a valid open file descriptor. dup() returns a new fd
    // that refers to the same open file description but has independent close
    // semantics.
    let capture_fd = unsafe { libc::dup(master_fd) };
    if capture_fd < 0 {
        // Fail-closed: return error instead of spawning no-op task
        return Err(PtyError::DupFd(io::Error::last_os_error()));
    }

    // SAFETY: capture_fd is a valid FD from dup(). We take ownership via
    // OwnedFd, which will close it when dropped.
    let owned_fd = unsafe { OwnedFd::from_raw_fd(capture_fd) };

    // Set to non-blocking mode for use with AsyncFd
    // Fail-closed: propagate error
    set_nonblocking(owned_fd.as_fd())?;

    // Wrap in ReadableFd for AsyncFd
    let readable_fd = ReadableFd(owned_fd);

    // Create AsyncFd for event-driven I/O
    // Fail-closed: propagate error
    let async_fd = AsyncFd::new(readable_fd).map_err(PtyError::AsyncFd)?;

    // Use tokio::spawn (not spawn_blocking) for async I/O.
    // This does not block a thread per PTY, enabling scale to 10,000+ episodes.
    Ok(tokio::spawn(async move {
        let mut seq_gen = SequenceGenerator::new();
        let mut buf = vec![0u8; buffer_size];

        loop {
            // Wait for the FD to be readable
            let mut guard = match async_fd.readable().await {
                Ok(guard) => guard,
                Err(e) => {
                    error!("AsyncFd readable error: {}", e);
                    break;
                },
            };

            // Attempt to read using try_io.
            // The closure performs a non-blocking read; if it would block,
            // try_io returns Err(_would_block) and we loop back to wait.
            #[allow(clippy::cast_sign_loss)] // n is checked to be >= 0 before cast
            match guard.try_io(|inner| {
                let fd = inner.get_ref().0.as_raw_fd();
                // SAFETY: Reading into a valid buffer from a valid fd.
                // The fd is non-blocking, so this won't block.
                let n =
                    unsafe { libc::read(fd, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len()) };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }) {
                Ok(Ok(0)) => {
                    // EOF - PTY closed
                    debug!("PTY EOF reached");
                    break;
                },
                Ok(Ok(n)) => {
                    // Get monotonic timestamp using clock_gettime.
                    // See function-level documentation for HARD-TIME rationale.
                    let ts_mono = get_monotonic_ns();
                    let seq = seq_gen.next();

                    let output =
                        PtyOutput::combined(Bytes::copy_from_slice(&buf[..n]), seq, ts_mono);

                    // Use send().await since we're in an async context
                    if output_tx.send(output).await.is_err() {
                        // Receiver dropped
                        debug!("output channel closed");
                        break;
                    }
                },
                Ok(Err(e)) => {
                    // Check if it's an I/O error due to child exit
                    if e.kind() == io::ErrorKind::Other || e.raw_os_error() == Some(libc::EIO) {
                        debug!("PTY read error (child likely exited): {}", e);
                        break;
                    }
                    error!("PTY read error: {}", e);
                    break;
                },
                Err(_would_block) => {
                    // Not actually ready, clear readiness and loop back to wait
                },
            }
        }

        // OwnedFd will close capture_fd when async_fd is dropped here
    }))
}

/// Gets the current monotonic timestamp in nanoseconds.
///
/// # HARD-TIME Compliance Note
///
/// This function uses `clock_gettime(CLOCK_MONOTONIC)` directly, which is an
/// exception to the HARD-TIME principle of caller-provided timestamps. This is
/// acceptable for PTY output capture because:
///
/// 1. **Async nature**: The capture task runs asynchronously and timestamps
///    each output chunk at read time. Using a stale initial timestamp would
///    produce incorrect ordering information.
///
/// 2. **Relative ordering**: Output timestamps are for ordering within a single
///    episode, not for cross-episode correlation. The monotonic clock provides
///    correct relative ordering.
///
/// 3. **Primary ordering via sequence numbers**: Sequence numbers (INV-OUT001)
///    provide the definitive ordering guarantee. Timestamps are supplementary.
///
/// 4. **No wall-clock dependency**: `CLOCK_MONOTONIC` is not affected by NTP
///    adjustments or timezone changes, avoiding the main HARD-TIME concerns.
///
/// For deterministic replay or simulation scenarios, pre-timestamped data
/// should be injected directly rather than using live capture.
#[allow(clippy::cast_sign_loss)]
fn get_monotonic_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: clock_gettime is safe with a valid clock id and timespec pointer.
    //
    // Return value check: clock_gettime() returns 0 on success and -1 on error.
    // For CLOCK_MONOTONIC, failure is extremely unlikely because:
    // 1. CLOCK_MONOTONIC is a standard POSIX clock supported on all Linux systems
    // 2. The only documented failure modes are EINVAL (invalid clock_id) and EFAULT
    //    (invalid pointer), neither of which can occur here
    // 3. The kernel guarantees CLOCK_MONOTONIC availability
    //
    // We use debug_assert to catch any theoretical issues in tests while avoiding
    // panic overhead in release builds for this hot path.
    let ret = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &raw mut ts) };
    debug_assert!(
        ret == 0,
        "clock_gettime(CLOCK_MONOTONIC) failed unexpectedly"
    );
    // Clock time should never be negative, so cast is safe
    (ts.tv_sec as u64) * 1_000_000_000 + (ts.tv_nsec as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // UT-00161-01: PTY spawn and output test
    // ========================================================================

    /// UT-00161-01: Test PTY spawn and output capture.
    #[tokio::test]
    async fn test_pty_spawn_and_output() {
        let config = PtyConfig::default();
        let timestamp_ns = 1_704_067_200_000_000_000_u64;

        // Spawn a simple echo command
        let mut runner = PtyRunner::spawn("/bin/echo", &["hello", "world"], config, timestamp_ns)
            .expect("failed to spawn");

        // Read output
        let mut output_data = Vec::new();
        while let Some(output) = runner.recv().await {
            output_data.extend_from_slice(&output.chunk);
            if output_data.ends_with(b"\n") {
                break;
            }
        }

        // Verify output contains expected text
        let output_str = String::from_utf8_lossy(&output_data);
        assert!(
            output_str.contains("hello world"),
            "expected 'hello world' in output, got: {output_str}"
        );

        // Wait for process to exit
        let status = runner.wait().expect("wait failed");
        assert!(status.success(), "expected exit code 0, got {status:?}");
    }

    #[tokio::test]
    async fn test_pty_exit_code() {
        let config = PtyConfig::default();
        let timestamp_ns = 0;

        // Spawn a command that exits with code 42
        let mut runner = PtyRunner::spawn("/bin/sh", &["-c", "exit 42"], config, timestamp_ns)
            .expect("failed to spawn");

        // Drain output
        while runner.recv().await.is_some() {}

        // Wait for exit
        let status = runner.wait().expect("wait failed");
        assert_eq!(status.code(), Some(42));
    }

    #[tokio::test]
    async fn test_pty_ring_buffer() {
        let config = PtyConfig::default().with_ring_buffer_capacity(5);
        let timestamp_ns = 0;

        // Spawn a command that produces output
        let mut runner = PtyRunner::spawn("/bin/echo", &["test"], config, timestamp_ns)
            .expect("failed to spawn");

        // Read output
        while runner.recv().await.is_some() {}

        // Check ring buffer
        assert!(runner.ring_buffer_len() > 0);

        // Drain and verify
        assert!(runner.drain_ring_buffer().next().is_some());

        // Ring buffer should be empty after drain
        assert_eq!(runner.ring_buffer_len(), 0);
    }

    #[tokio::test]
    async fn test_pty_signal() {
        let config = PtyConfig::default();
        let timestamp_ns = 0;

        // Spawn a long-running command
        let runner =
            PtyRunner::spawn("/bin/sleep", &["10"], config, timestamp_ns).expect("failed to spawn");

        // Send SIGTERM
        runner.signal(Signal::SIGTERM).expect("signal failed");

        // Process should be signaled
        // (we don't wait here to avoid test slowness)
    }

    #[test]
    fn test_exit_status() {
        assert!(ExitStatus::Exited(0).success());
        assert!(!ExitStatus::Exited(1).success());
        assert!(!ExitStatus::Signaled(Signal::SIGKILL).success());
        assert!(!ExitStatus::Running.success());

        assert_eq!(ExitStatus::Exited(42).code(), Some(42));
        assert_eq!(ExitStatus::Signaled(Signal::SIGTERM).code(), None);
        assert_eq!(ExitStatus::Running.code(), None);
    }

    #[test]
    fn test_pty_config_default() {
        let config = PtyConfig::default();
        assert_eq!(config.window_size(), (80, 24));
        assert_eq!(config.ring_buffer_capacity(), 1024);
        assert_eq!(config.channel_capacity(), OUTPUT_CHANNEL_CAPACITY);
        assert_eq!(config.read_buffer_size(), READ_BUFFER_SIZE);
    }

    #[test]
    fn test_pty_config_builder() {
        let config = PtyConfig::default()
            .with_window_size(120, 40)
            .with_ring_buffer_capacity(2048);

        assert_eq!(config.window_size(), (120, 40));
        assert_eq!(config.ring_buffer_capacity(), 2048);
    }

    #[test]
    fn test_pty_config_new_validation() {
        // Valid config
        let config = PtyConfig::new((80, 24), 1024, 1024, 8192);
        assert!(config.is_ok());

        // read_buffer_size too large
        let config = PtyConfig::new((80, 24), 1024, 1024, MAX_READ_BUFFER_SIZE + 1);
        assert!(config.is_err());
        assert!(config.unwrap_err().to_string().contains("read_buffer_size"));

        // ring_buffer_capacity too large
        let config = PtyConfig::new((80, 24), MAX_RING_BUFFER_CAPACITY + 1, 1024, 8192);
        assert!(config.is_err());
        assert!(
            config
                .unwrap_err()
                .to_string()
                .contains("ring_buffer_capacity")
        );

        // channel_capacity too large
        let config = PtyConfig::new((80, 24), 1024, MAX_CHANNEL_CAPACITY + 1, 8192);
        assert!(config.is_err());
        assert!(config.unwrap_err().to_string().contains("channel_capacity"));

        // Zero values
        let config = PtyConfig::new((80, 24), 0, 1024, 8192);
        assert!(config.is_err());

        let config = PtyConfig::new((80, 24), 1024, 0, 8192);
        assert!(config.is_err());

        let config = PtyConfig::new((80, 24), 1024, 1024, 0);
        assert!(config.is_err());
    }

    #[test]
    fn test_pty_config_builder_clamping() {
        // Builder methods should clamp values, not reject them
        let config = PtyConfig::default()
            .with_ring_buffer_capacity(MAX_RING_BUFFER_CAPACITY * 2)
            .with_channel_capacity(MAX_CHANNEL_CAPACITY * 2)
            .with_read_buffer_size(MAX_READ_BUFFER_SIZE * 2);

        assert_eq!(config.ring_buffer_capacity(), MAX_RING_BUFFER_CAPACITY);
        assert_eq!(config.channel_capacity(), MAX_CHANNEL_CAPACITY);
        assert_eq!(config.read_buffer_size(), MAX_READ_BUFFER_SIZE);

        // Zero values should be clamped to 1
        let config = PtyConfig::default()
            .with_ring_buffer_capacity(0)
            .with_channel_capacity(0)
            .with_read_buffer_size(0);

        assert_eq!(config.ring_buffer_capacity(), 1);
        assert_eq!(config.channel_capacity(), 1);
        assert_eq!(config.read_buffer_size(), 1);
    }

    #[test]
    fn test_path_to_cstring() {
        let path = Path::new("/bin/echo");
        let cstr = path_to_cstring(path).unwrap();
        assert_eq!(cstr.as_bytes(), b"/bin/echo");
    }

    #[test]
    fn test_pty_error_display() {
        let err = PtyError::InvalidCommand("test".to_string());
        assert!(err.to_string().contains("invalid command"));

        let err = PtyError::NotRunning;
        assert!(err.to_string().contains("not running"));
    }
}
