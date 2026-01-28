//! /proc fallback for degraded telemetry mode.
//!
//! This module provides `ProcReader` for collecting CPU, memory, and I/O
//! statistics from `/proc/{pid}/` when cgroup isolation is unavailable.
//!
//! # Degraded Mode
//!
//! Per AD-CGROUP-001, when cgroups v2 is unavailable, the daemon falls back to
//! `/proc/{pid}/` for basic metrics. These metrics are marked with
//! `MetricSource::Proc` to indicate reduced accuracy:
//!
//! - `/proc` metrics are per-process, not per-cgroup (may miss child processes)
//! - Some metrics may require elevated privileges to read
//! - Accuracy is lower than cgroup accounting
//!
//! # Proc Files Used
//!
//! - `/proc/{pid}/stat`: CPU time (utime, stime)
//! - `/proc/{pid}/statm`: Memory usage (resident pages)
//! - `/proc/{pid}/io`: I/O statistics (read/write bytes, ops)
//!
//! # Security Considerations
//!
//! - Only reads from `/proc/{pid}/` for the specified PID
//! - Validates PID is positive to prevent path traversal
//! - Fails closed on any read error
//!
//! # Contract References
//!
//! - AD-CGROUP-001: Degraded mode fallback to /proc

use std::fs;
use std::path::PathBuf;

use nix::unistd::Pid;
use thiserror::Error;
use tracing::debug;

use super::stats::{CpuStats, IoStats, MemoryStats, MetricSource};

/// System page size (typically 4096 bytes).
/// Used to convert page counts to bytes.
const PAGE_SIZE: u64 = 4096;

/// Clock ticks per second (typically 100 on Linux).
/// Used to convert jiffies to nanoseconds.
const CLK_TCK: u64 = 100;

/// Nanoseconds per jiffy (10,000,000 ns for 100 Hz).
const NS_PER_JIFFY: u64 = 1_000_000_000 / CLK_TCK;

/// Proc reader errors.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ProcError {
    /// Invalid PID.
    #[error("invalid PID: {pid}")]
    InvalidPid {
        /// The invalid PID.
        pid: i32,
    },

    /// Failed to read proc file.
    #[error("failed to read /proc/{pid}/{file}: {source}")]
    ReadFailed {
        /// Process ID.
        pid: i32,
        /// File name within /proc/{pid}/.
        file: String,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// Failed to parse proc file content.
    #[error("failed to parse /proc/{pid}/{file}: {reason}")]
    ParseFailed {
        /// Process ID.
        pid: i32,
        /// File name within /proc/{pid}/.
        file: String,
        /// Reason for parse failure.
        reason: String,
    },
}

/// Result type for proc operations.
pub type ProcResult<T> = Result<T, ProcError>;

/// Proc filesystem reader for process metrics.
///
/// Reads CPU, memory, and I/O statistics from `/proc/{pid}/` for processes
/// that are not in isolated cgroups.
///
/// # Example
///
/// ```rust,ignore
/// use apm2_daemon::telemetry::proc_fallback::ProcReader;
/// use nix::unistd::Pid;
///
/// let reader = ProcReader::new(Pid::from_raw(12345));
///
/// let cpu = reader.read_cpu()?;
/// println!("CPU time: {} ms", cpu.usage_ms());
///
/// let memory = reader.read_memory()?;
/// println!("RSS: {} MiB", memory.rss_mib());
/// ```
#[derive(Debug, Clone, Copy)]
pub struct ProcReader {
    /// Process ID to read metrics for.
    pid: Pid,
}

impl ProcReader {
    /// Creates a new proc reader for the given PID.
    #[must_use]
    pub const fn new(pid: Pid) -> Self {
        Self { pid }
    }

    /// Returns the PID being read.
    #[must_use]
    pub const fn pid(&self) -> Pid {
        self.pid
    }

    /// Validates that the PID is valid for reading.
    const fn validate_pid(self) -> ProcResult<()> {
        if self.pid.as_raw() <= 0 {
            return Err(ProcError::InvalidPid {
                pid: self.pid.as_raw(),
            });
        }
        Ok(())
    }

    /// Gets the proc path for this PID.
    fn proc_path(self, file: &str) -> PathBuf {
        PathBuf::from(format!("/proc/{}/{}", self.pid.as_raw(), file))
    }

    /// Reads a proc file as a string.
    fn read_file(self, file: &str) -> ProcResult<String> {
        self.validate_pid()?;
        let path = self.proc_path(file);
        fs::read_to_string(&path).map_err(|e| ProcError::ReadFailed {
            pid: self.pid.as_raw(),
            file: file.to_string(),
            source: e,
        })
    }

    /// Reads CPU statistics from `/proc/{pid}/stat`.
    ///
    /// Parses fields 14 (utime) and 15 (stime) from the stat file.
    /// Times are in clock ticks (jiffies) and converted to nanoseconds.
    ///
    /// # Format
    ///
    /// `/proc/{pid}/stat` contains space-separated fields:
    /// ```text
    /// pid (comm) state ppid pgrp session tty_nr tpgid flags minflt cminflt
    /// majflt cmajflt utime stime cutime cstime priority nice num_threads ...
    /// ```
    ///
    /// Fields of interest (1-indexed):
    /// - 14: utime (user mode jiffies)
    /// - 15: stime (kernel mode jiffies)
    pub fn read_cpu(&self) -> ProcResult<CpuStats> {
        let content = self.read_file("stat")?;

        // Find the end of (comm) field - it can contain spaces and special chars
        let comm_end = content.rfind(')').ok_or_else(|| ProcError::ParseFailed {
            pid: self.pid.as_raw(),
            file: "stat".to_string(),
            reason: "missing ')' in stat file".to_string(),
        })?;

        // Fields after (comm) start at index comm_end + 2
        let fields_str = &content[comm_end + 2..];
        let fields: Vec<&str> = fields_str.split_whitespace().collect();

        // After (comm), field indices are:
        // 0: state, 1: ppid, ..., 11: utime (field 14 overall), 12: stime (field 15
        // overall)
        if fields.len() < 13 {
            return Err(ProcError::ParseFailed {
                pid: self.pid.as_raw(),
                file: "stat".to_string(),
                reason: "insufficient fields in stat file".to_string(),
            });
        }

        let utime_jiffies: u64 = fields[11].parse().map_err(|_| ProcError::ParseFailed {
            pid: self.pid.as_raw(),
            file: "stat".to_string(),
            reason: format!("invalid utime value: '{}'", fields[11]),
        })?;

        let stime_jiffies: u64 = fields[12].parse().map_err(|_| ProcError::ParseFailed {
            pid: self.pid.as_raw(),
            file: "stat".to_string(),
            reason: format!("invalid stime value: '{}'", fields[12]),
        })?;

        // Convert jiffies to nanoseconds
        let user_ns = utime_jiffies.saturating_mul(NS_PER_JIFFY);
        let system_ns = stime_jiffies.saturating_mul(NS_PER_JIFFY);
        let usage_ns = user_ns.saturating_add(system_ns);

        debug!(
            pid = %self.pid,
            user_ns,
            system_ns,
            "read CPU from /proc"
        );

        Ok(CpuStats::new(
            usage_ns,
            user_ns,
            system_ns,
            MetricSource::Proc,
        ))
    }

    /// Reads memory statistics from `/proc/{pid}/statm` and `/proc/{pid}/stat`.
    ///
    /// # Format
    ///
    /// `/proc/{pid}/statm` contains (in pages):
    /// ```text
    /// size resident shared text lib data dt
    /// ```
    ///
    /// `/proc/{pid}/stat` contains page fault counts at fields 10 (minflt) and
    /// 12 (majflt).
    pub fn read_memory(&self) -> ProcResult<MemoryStats> {
        // Read statm for RSS
        let statm_content = self.read_file("statm")?;
        let statm_fields: Vec<&str> = statm_content.split_whitespace().collect();

        if statm_fields.len() < 2 {
            return Err(ProcError::ParseFailed {
                pid: self.pid.as_raw(),
                file: "statm".to_string(),
                reason: "insufficient fields in statm file".to_string(),
            });
        }

        let resident_pages: u64 = statm_fields[1]
            .parse()
            .map_err(|_| ProcError::ParseFailed {
                pid: self.pid.as_raw(),
                file: "statm".to_string(),
                reason: format!("invalid resident value: '{}'", statm_fields[1]),
            })?;

        let rss_bytes = resident_pages.saturating_mul(PAGE_SIZE);

        // Read stat for page faults
        let proc_stat = self.read_file("stat")?;
        let (page_faults_minor, page_faults_major) =
            parse_stat_page_faults(&proc_stat).unwrap_or((0, 0));

        debug!(
            pid = %self.pid,
            rss_bytes,
            page_faults_minor,
            page_faults_major,
            "read memory from /proc"
        );

        // Note: peak_bytes is set to rss_bytes since /proc doesn't track peak
        Ok(MemoryStats::new(
            rss_bytes,
            rss_bytes, // No peak tracking in /proc
            page_faults_major,
            page_faults_minor,
            MetricSource::Proc,
        ))
    }

    /// Reads I/O statistics from `/proc/{pid}/io`.
    ///
    /// # Format
    ///
    /// `/proc/{pid}/io` contains key: value pairs:
    /// ```text
    /// rchar: <bytes>
    /// wchar: <bytes>
    /// syscr: <count>
    /// syscw: <count>
    /// read_bytes: <bytes>
    /// write_bytes: <bytes>
    /// cancelled_write_bytes: <bytes>
    /// ```
    ///
    /// We use `read_bytes` and `write_bytes` (actual storage I/O) rather than
    /// `rchar`/`wchar` (which include pipe/socket I/O).
    ///
    /// # Permissions
    ///
    /// Reading `/proc/{pid}/io` may require `CAP_SYS_PTRACE` or same UID.
    pub fn read_io(&self) -> ProcResult<IoStats> {
        let content = self.read_file("io")?;

        let mut read_bytes: u64 = 0;
        let mut write_bytes: u64 = 0;
        let mut read_ops: u64 = 0;
        let mut write_ops: u64 = 0;

        for line in content.lines() {
            if let Some((key, value)) = line.split_once(':') {
                let value = value.trim();
                match key.trim() {
                    "read_bytes" => {
                        read_bytes = value.parse().unwrap_or(0);
                    },
                    "write_bytes" => {
                        write_bytes = value.parse().unwrap_or(0);
                    },
                    "syscr" => {
                        read_ops = value.parse().unwrap_or(0);
                    },
                    "syscw" => {
                        write_ops = value.parse().unwrap_or(0);
                    },
                    _ => {},
                }
            }
        }

        debug!(
            pid = %self.pid,
            read_bytes,
            write_bytes,
            read_ops,
            write_ops,
            "read I/O from /proc"
        );

        Ok(IoStats::new(
            read_bytes,
            write_bytes,
            read_ops,
            write_ops,
            MetricSource::Proc,
        ))
    }
}

/// Parses page fault counts from `/proc/{pid}/stat` content.
///
/// Returns `(minor_faults, major_faults)`.
fn parse_stat_page_faults(content: &str) -> Option<(u64, u64)> {
    // Find the end of (comm) field
    let comm_end = content.rfind(')')?;
    let fields_str = &content[comm_end + 2..];
    let fields: Vec<&str> = fields_str.split_whitespace().collect();

    // After (comm), field indices:
    // 7: minflt (field 10 overall)
    // 9: majflt (field 12 overall)
    if fields.len() < 10 {
        return None;
    }

    let minflt: u64 = fields[7].parse().ok()?;
    let majflt: u64 = fields[9].parse().ok()?;

    Some((minflt, majflt))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // UT-00168-02: proc_fallback tests
    // ========================================================================

    #[test]
    fn test_proc_reader_new() {
        let reader = ProcReader::new(Pid::from_raw(1234));
        assert_eq!(reader.pid().as_raw(), 1234);
    }

    #[test]
    fn test_proc_reader_invalid_pid() {
        let reader = ProcReader::new(Pid::from_raw(-1));
        let result = reader.read_cpu();
        assert!(matches!(result, Err(ProcError::InvalidPid { pid: -1 })));
    }

    #[test]
    fn test_proc_reader_zero_pid() {
        let reader = ProcReader::new(Pid::from_raw(0));
        let result = reader.read_cpu();
        assert!(matches!(result, Err(ProcError::InvalidPid { pid: 0 })));
    }

    #[test]
    fn test_proc_path() {
        let reader = ProcReader::new(Pid::from_raw(1234));
        assert_eq!(reader.proc_path("stat"), PathBuf::from("/proc/1234/stat"));
        assert_eq!(reader.proc_path("statm"), PathBuf::from("/proc/1234/statm"));
        assert_eq!(reader.proc_path("io"), PathBuf::from("/proc/1234/io"));
    }

    #[test]
    fn test_parse_stat_page_faults() {
        // Simulated /proc/pid/stat content
        let content = "1 (test) S 0 1 1 0 -1 4194304 100 0 50 0 10 20 0 0 20 0 1 0 1000 1000000 100 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0";
        let (minflt, majflt) = parse_stat_page_faults(content).unwrap();
        assert_eq!(minflt, 100);
        assert_eq!(majflt, 50);
    }

    #[test]
    fn test_parse_stat_page_faults_with_spaces_in_comm() {
        // Process name with spaces
        let content = "1 (test process name) S 0 1 1 0 -1 4194304 200 0 75 0 10 20 0 0 20 0 1 0 1000 1000000 100 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0";
        let (minflt, majflt) = parse_stat_page_faults(content).unwrap();
        assert_eq!(minflt, 200);
        assert_eq!(majflt, 75);
    }

    #[test]
    fn test_parse_stat_page_faults_malformed() {
        let content = "malformed content";
        assert!(parse_stat_page_faults(content).is_none());
    }

    #[test]
    fn test_proc_error_display() {
        let err = ProcError::InvalidPid { pid: -1 };
        assert!(err.to_string().contains("-1"));

        let err = ProcError::ParseFailed {
            pid: 123,
            file: "stat".to_string(),
            reason: "test".to_string(),
        };
        assert!(err.to_string().contains("123"));
        assert!(err.to_string().contains("stat"));
    }

    #[test]
    fn test_ns_per_jiffy_calculation() {
        // Verify the constant is correct for 100 Hz
        assert_eq!(NS_PER_JIFFY, 10_000_000);
    }

    // Integration test that reads from actual /proc
    #[test]
    fn test_proc_reader_self() {
        // Read metrics for current process
        // Note: process::id() returns u32, we use try_into to safely convert
        let pid_raw: i32 = std::process::id().try_into().expect("PID overflow");
        let pid = Pid::from_raw(pid_raw);
        let reader = ProcReader::new(pid);

        // CPU should succeed
        let cpu = reader.read_cpu();
        assert!(cpu.is_ok(), "CPU read failed: {:?}", cpu.err());
        let cpu = cpu.unwrap();
        assert!(cpu.source().is_proc());

        // Memory should succeed
        let memory = reader.read_memory();
        assert!(memory.is_ok(), "Memory read failed: {:?}", memory.err());
        let memory = memory.unwrap();
        assert!(memory.source().is_proc());
        assert!(memory.rss_bytes() > 0);

        // I/O may fail without permissions, so we don't assert success
        let io = reader.read_io();
        if let Ok(io_stats) = io {
            assert!(io_stats.source().is_proc());
        }
    }

    #[test]
    fn test_proc_reader_nonexistent_pid() {
        // Use a PID that almost certainly doesn't exist
        let reader = ProcReader::new(Pid::from_raw(999_999_999));
        let result = reader.read_cpu();
        assert!(matches!(result, Err(ProcError::ReadFailed { .. })));
    }
}
