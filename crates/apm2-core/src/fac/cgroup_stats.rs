// AGENT-AUTHORED
//! Cgroup v2 usage accounting for FAC job receipts (TCK-00572).
//!
//! This module provides best-effort collection of runtime resource stats
//! from a job unit's cgroup v2 hierarchy. Collected stats feed economics
//! calibration and metrics. All reads are bounded and fail-safe: a missing
//! or unreadable stat file yields `None` for that field rather than
//! failing the job.
//!
//! # Cgroup v2 Stat Files
//!
//! | File            | Parsed field(s)                  |
//! |-----------------|----------------------------------|
//! | `cpu.stat`      | `usage_usec` -> `cpu_time_us`    |
//! | `memory.peak`   | single value -> `peak_memory_bytes` (fallback: `memory.current`) |
//! | `io.stat`       | `rbytes`/`wbytes` summed across devices |
//! | `pids.current`  | single value -> `tasks_count`    |
//!
//! # Security Invariants
//!
//! - \[INV-CGSTAT-001\] All file reads are bounded by `MAX_CGROUP_STAT_READ`.
//! - \[INV-CGSTAT-002\] Parse failures yield `None`, never panic.
//! - \[INV-CGSTAT-003\] IO reads/writes are summed with saturating arithmetic.
//! - \[INV-CGSTAT-004\] Validation rejects out-of-bounds values (fail-closed).

use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

use serde::{Deserialize, Serialize};

// =============================================================================
// Constants
// =============================================================================

/// Maximum bytes to read from any single cgroup stat file (8 KiB).
///
/// Cgroup stat files are typically under 1 KiB. This cap prevents
/// denial-of-service via crafted cgroupfs entries (RSK-1601).
pub const MAX_CGROUP_STAT_READ: usize = 8192;

/// Maximum CPU time in microseconds (~30 days).
/// Any value exceeding this bound is rejected during validation.
pub const MAX_CPU_TIME_US: u64 = 30 * 24 * 60 * 60 * 1_000_000;

/// Maximum peak memory in bytes (~1 TiB).
pub const MAX_PEAK_MEMORY_BYTES: u64 = 1 << 40;

/// Maximum IO bytes (read or write) (~100 TiB).
pub const MAX_IO_BYTES: u64 = 100 * (1u64 << 40);

/// Maximum tasks count.
pub const MAX_TASKS_COUNT: u32 = 1_000_000;

// =============================================================================
// Types
// =============================================================================

/// Observed cgroup usage stats from a completed job unit.
///
/// All fields are `Option` — a `None` value means the stat could not be
/// read (e.g., kernel too old, cgroup controller not enabled, permission
/// denied). This is the best-effort contract: never fail the job because
/// stats cannot be collected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedCgroupUsage {
    /// Total CPU time consumed by the cgroup in microseconds.
    /// Parsed from `cpu.stat` `usage_usec` line.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_time_us: Option<u64>,

    /// Peak memory usage in bytes.
    /// Parsed from `memory.peak` (preferred) or `memory.current` (fallback).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peak_memory_bytes: Option<u64>,

    /// Total IO bytes read across all devices.
    /// Parsed from `io.stat` `rbytes` fields, summed across devices.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub io_read_bytes: Option<u64>,

    /// Total IO bytes written across all devices.
    /// Parsed from `io.stat` `wbytes` fields, summed across devices.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub io_write_bytes: Option<u64>,

    /// Number of tasks (threads/processes) in the cgroup at collection time.
    /// Parsed from `pids.current`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tasks_count: Option<u32>,
}

/// Validation error for observed cgroup usage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CgroupUsageValidationError {
    /// A field value exceeds the allowed maximum.
    OutOfBounds {
        /// Name of the field.
        field: &'static str,
        /// The actual value.
        actual: u64,
        /// The maximum allowed value.
        max: u64,
    },
}

impl std::fmt::Display for CgroupUsageValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OutOfBounds { field, actual, max } => {
                write!(
                    f,
                    "observed_usage.{field} value {actual} exceeds maximum {max}"
                )
            },
        }
    }
}

impl ObservedCgroupUsage {
    /// Validates all fields are within reasonable bounds.
    ///
    /// Returns the first out-of-bounds field found, or `Ok(())` if all are
    /// valid.
    ///
    /// # Errors
    ///
    /// Returns [`CgroupUsageValidationError::OutOfBounds`] if any field
    /// exceeds its configured maximum.
    pub fn validate(&self) -> Result<(), CgroupUsageValidationError> {
        if let Some(v) = self.cpu_time_us {
            if v > MAX_CPU_TIME_US {
                return Err(CgroupUsageValidationError::OutOfBounds {
                    field: "cpu_time_us",
                    actual: v,
                    max: MAX_CPU_TIME_US,
                });
            }
        }
        if let Some(v) = self.peak_memory_bytes {
            if v > MAX_PEAK_MEMORY_BYTES {
                return Err(CgroupUsageValidationError::OutOfBounds {
                    field: "peak_memory_bytes",
                    actual: v,
                    max: MAX_PEAK_MEMORY_BYTES,
                });
            }
        }
        if let Some(v) = self.io_read_bytes {
            if v > MAX_IO_BYTES {
                return Err(CgroupUsageValidationError::OutOfBounds {
                    field: "io_read_bytes",
                    actual: v,
                    max: MAX_IO_BYTES,
                });
            }
        }
        if let Some(v) = self.io_write_bytes {
            if v > MAX_IO_BYTES {
                return Err(CgroupUsageValidationError::OutOfBounds {
                    field: "io_write_bytes",
                    actual: v,
                    max: MAX_IO_BYTES,
                });
            }
        }
        if let Some(v) = self.tasks_count {
            if v > MAX_TASKS_COUNT {
                return Err(CgroupUsageValidationError::OutOfBounds {
                    field: "tasks_count",
                    actual: u64::from(v),
                    max: u64::from(MAX_TASKS_COUNT),
                });
            }
        }
        Ok(())
    }

    /// Returns `true` if all fields are `None` (no stats collected).
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.cpu_time_us.is_none()
            && self.peak_memory_bytes.is_none()
            && self.io_read_bytes.is_none()
            && self.io_write_bytes.is_none()
            && self.tasks_count.is_none()
    }
}

// =============================================================================
// Collection
// =============================================================================

/// Collects cgroup v2 usage stats from the given cgroup path.
///
/// This is the primary entry point. It reads stat files from the
/// filesystem root (i.e., `/sys/fs/cgroup/<cgroup_path>/...`).
///
/// All reads are best-effort: individual stat failures produce `None`
/// for that field. The function never returns an error — it always
/// returns a valid `ObservedCgroupUsage`.
#[must_use]
pub fn collect_cgroup_usage(cgroup_path: &str) -> ObservedCgroupUsage {
    collect_cgroup_usage_from_root(cgroup_path, Path::new("/sys/fs/cgroup"))
}

/// Collects cgroup v2 usage stats with a configurable cgroupfs root.
///
/// This variant enables testing with mock filesystem layouts.
#[must_use]
pub fn collect_cgroup_usage_from_root(
    cgroup_path: &str,
    cgroup_root: &Path,
) -> ObservedCgroupUsage {
    // Strip leading `/` from cgroup_path to join correctly.
    let relative_path = cgroup_path.trim_start_matches('/');
    let cgroup_dir = cgroup_root.join(relative_path);

    let cpu_time_us = read_cpu_stat(&cgroup_dir);
    let peak_memory_bytes = read_memory_peak(&cgroup_dir);
    let (io_read_bytes, io_write_bytes) = read_io_stat(&cgroup_dir);
    let tasks_count = read_pids_current(&cgroup_dir);

    ObservedCgroupUsage {
        cpu_time_us,
        peak_memory_bytes,
        io_read_bytes,
        io_write_bytes,
        tasks_count,
    }
}

// =============================================================================
// Individual stat readers (all best-effort, return Option)
// =============================================================================

/// Reads `cpu.stat` and extracts `usage_usec`.
///
/// Format: key-value pairs separated by whitespace, one per line.
/// Example:
/// ```text
/// usage_usec 123456
/// user_usec 100000
/// system_usec 23456
/// ```
fn read_cpu_stat(cgroup_dir: &Path) -> Option<u64> {
    let content = read_bounded_file(&cgroup_dir.join("cpu.stat"))?;
    for line in content.lines() {
        let line = line.trim();
        if let Some(value_str) = line.strip_prefix("usage_usec") {
            let value_str = value_str.trim();
            return value_str.parse::<u64>().ok();
        }
    }
    None
}

/// Reads `memory.peak` (preferred) or falls back to `memory.current`.
///
/// Both files contain a single integer value in bytes.
fn read_memory_peak(cgroup_dir: &Path) -> Option<u64> {
    // Try memory.peak first (available on newer kernels, e.g., Linux 5.19+).
    if let Some(content) = read_bounded_file(&cgroup_dir.join("memory.peak")) {
        if let Ok(v) = content.trim().parse::<u64>() {
            return Some(v);
        }
    }
    // Fallback to memory.current.
    let content = read_bounded_file(&cgroup_dir.join("memory.current"))?;
    content.trim().parse::<u64>().ok()
}

/// Reads `io.stat` and sums `rbytes` and `wbytes` across all devices.
///
/// Format: one line per device, space-separated key=value pairs.
/// Example:
/// ```text
/// 8:0 rbytes=1234 wbytes=5678 rios=10 wios=20
/// 8:16 rbytes=100 wbytes=200 rios=1 wios=2
/// ```
fn read_io_stat(cgroup_dir: &Path) -> (Option<u64>, Option<u64>) {
    let Some(content) = read_bounded_file(&cgroup_dir.join("io.stat")) else {
        return (None, None);
    };

    let mut total_read: u64 = 0;
    let mut total_write: u64 = 0;
    let mut found_any = false;

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        for kv in line.split_whitespace() {
            if let Some(val_str) = kv.strip_prefix("rbytes=") {
                if let Ok(v) = val_str.parse::<u64>() {
                    total_read = total_read.saturating_add(v);
                    found_any = true;
                }
            } else if let Some(val_str) = kv.strip_prefix("wbytes=") {
                if let Ok(v) = val_str.parse::<u64>() {
                    total_write = total_write.saturating_add(v);
                    found_any = true;
                }
            }
        }
    }

    if found_any {
        (Some(total_read), Some(total_write))
    } else {
        (None, None)
    }
}

/// Reads `pids.current` — single integer value (current task count).
fn read_pids_current(cgroup_dir: &Path) -> Option<u32> {
    let content = read_bounded_file(&cgroup_dir.join("pids.current"))?;
    content.trim().parse::<u32>().ok()
}

/// Bounded file read helper. Returns `None` if the file cannot be read
/// or exceeds [`MAX_CGROUP_STAT_READ`] bytes.
///
/// \[INV-CGSTAT-001\] Reads are bounded to prevent memory exhaustion.
fn read_bounded_file(path: &Path) -> Option<String> {
    let file = File::open(path).ok()?;
    let mut reader = BufReader::new(file.take(MAX_CGROUP_STAT_READ as u64 + 1));
    let mut buf = String::new();
    // read_to_string on a Take-bounded reader is safe: at most
    // MAX_CGROUP_STAT_READ+1 bytes are read.
    if reader.read_to_string(&mut buf).is_err() {
        return None;
    }
    // If we read more than the cap, the file is suspicious — reject.
    if buf.len() > MAX_CGROUP_STAT_READ {
        return None;
    }
    Some(buf)
}

// =============================================================================
// Canonical Bytes Helpers
// =============================================================================

/// Appends an `Option<u64>` with explicit presence marker for canonical
/// byte encoding.
///
/// Encoding: `0u8` for `None`, `1u8 + value.to_be_bytes()` for `Some(v)`.
pub fn append_option_u64(bytes: &mut Vec<u8>, value: Option<u64>) {
    match value {
        None => bytes.push(0u8),
        Some(v) => {
            bytes.push(1u8);
            bytes.extend_from_slice(&v.to_be_bytes());
        },
    }
}

/// Appends an `Option<u32>` with explicit presence marker for canonical
/// byte encoding.
///
/// Encoding: `0u8` for `None`, `1u8 + value.to_be_bytes()` for `Some(v)`.
pub fn append_option_u32(bytes: &mut Vec<u8>, value: Option<u32>) {
    match value {
        None => bytes.push(0u8),
        Some(v) => {
            bytes.push(1u8);
            bytes.extend_from_slice(&v.to_be_bytes());
        },
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -------------------------------------------------------------------------
    // Validation tests
    // -------------------------------------------------------------------------

    #[test]
    fn validate_all_none_is_ok() {
        let usage = ObservedCgroupUsage {
            cpu_time_us: None,
            peak_memory_bytes: None,
            io_read_bytes: None,
            io_write_bytes: None,
            tasks_count: None,
        };
        assert!(usage.validate().is_ok());
        assert!(usage.is_empty());
    }

    #[test]
    fn validate_valid_values() {
        let usage = ObservedCgroupUsage {
            cpu_time_us: Some(1_000_000),
            peak_memory_bytes: Some(1 << 30), // 1 GiB
            io_read_bytes: Some(1 << 20),     // 1 MiB
            io_write_bytes: Some(1 << 20),
            tasks_count: Some(100),
        };
        assert!(usage.validate().is_ok());
        assert!(!usage.is_empty());
    }

    #[test]
    fn validate_cpu_time_exceeds_bound() {
        let usage = ObservedCgroupUsage {
            cpu_time_us: Some(MAX_CPU_TIME_US + 1),
            peak_memory_bytes: None,
            io_read_bytes: None,
            io_write_bytes: None,
            tasks_count: None,
        };
        let err = usage.validate().unwrap_err();
        assert_eq!(
            err,
            CgroupUsageValidationError::OutOfBounds {
                field: "cpu_time_us",
                actual: MAX_CPU_TIME_US + 1,
                max: MAX_CPU_TIME_US,
            }
        );
    }

    #[test]
    fn validate_peak_memory_exceeds_bound() {
        let usage = ObservedCgroupUsage {
            cpu_time_us: None,
            peak_memory_bytes: Some(MAX_PEAK_MEMORY_BYTES + 1),
            io_read_bytes: None,
            io_write_bytes: None,
            tasks_count: None,
        };
        assert!(usage.validate().is_err());
    }

    #[test]
    fn validate_io_read_exceeds_bound() {
        let usage = ObservedCgroupUsage {
            cpu_time_us: None,
            peak_memory_bytes: None,
            io_read_bytes: Some(MAX_IO_BYTES + 1),
            io_write_bytes: None,
            tasks_count: None,
        };
        assert!(usage.validate().is_err());
    }

    #[test]
    fn validate_io_write_exceeds_bound() {
        let usage = ObservedCgroupUsage {
            cpu_time_us: None,
            peak_memory_bytes: None,
            io_read_bytes: None,
            io_write_bytes: Some(MAX_IO_BYTES + 1),
            tasks_count: None,
        };
        assert!(usage.validate().is_err());
    }

    #[test]
    fn validate_tasks_count_exceeds_bound() {
        let usage = ObservedCgroupUsage {
            cpu_time_us: None,
            peak_memory_bytes: None,
            io_read_bytes: None,
            io_write_bytes: None,
            tasks_count: Some(MAX_TASKS_COUNT + 1),
        };
        assert!(usage.validate().is_err());
    }

    #[test]
    fn validate_boundary_values_ok() {
        let usage = ObservedCgroupUsage {
            cpu_time_us: Some(MAX_CPU_TIME_US),
            peak_memory_bytes: Some(MAX_PEAK_MEMORY_BYTES),
            io_read_bytes: Some(MAX_IO_BYTES),
            io_write_bytes: Some(MAX_IO_BYTES),
            tasks_count: Some(MAX_TASKS_COUNT),
        };
        assert!(usage.validate().is_ok());
    }

    // -------------------------------------------------------------------------
    // Stat parsing tests (using temp directories to mock cgroup fs)
    // -------------------------------------------------------------------------

    #[test]
    fn parse_cpu_stat() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cgroup_dir = dir.path();
        std::fs::write(
            cgroup_dir.join("cpu.stat"),
            "usage_usec 123456\nuser_usec 100000\nsystem_usec 23456\n",
        )
        .unwrap();

        assert_eq!(read_cpu_stat(cgroup_dir), Some(123_456));
    }

    #[test]
    fn parse_cpu_stat_missing_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert_eq!(read_cpu_stat(dir.path()), None);
    }

    #[test]
    fn parse_cpu_stat_no_usage_usec() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("cpu.stat"), "user_usec 100000\n").unwrap();
        assert_eq!(read_cpu_stat(dir.path()), None);
    }

    #[test]
    fn parse_cpu_stat_invalid_value() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("cpu.stat"), "usage_usec not_a_number\n").unwrap();
        assert_eq!(read_cpu_stat(dir.path()), None);
    }

    #[test]
    fn parse_memory_peak() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("memory.peak"), "1073741824\n").unwrap();
        assert_eq!(read_memory_peak(dir.path()), Some(1_073_741_824));
    }

    #[test]
    fn parse_memory_peak_fallback_to_current() {
        let dir = tempfile::tempdir().expect("tempdir");
        // No memory.peak, but memory.current exists.
        std::fs::write(dir.path().join("memory.current"), "536870912\n").unwrap();
        assert_eq!(read_memory_peak(dir.path()), Some(536_870_912));
    }

    #[test]
    fn parse_memory_peak_neither_exists() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert_eq!(read_memory_peak(dir.path()), None);
    }

    #[test]
    fn parse_io_stat_multi_device() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("io.stat"),
            "8:0 rbytes=1000 wbytes=2000 rios=10 wios=20\n\
             8:16 rbytes=500 wbytes=300 rios=5 wios=3\n",
        )
        .unwrap();

        let (r, w) = read_io_stat(dir.path());
        assert_eq!(r, Some(1500));
        assert_eq!(w, Some(2300));
    }

    #[test]
    fn parse_io_stat_empty_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("io.stat"), "").unwrap();
        let (r, w) = read_io_stat(dir.path());
        assert_eq!(r, None);
        assert_eq!(w, None);
    }

    #[test]
    fn parse_io_stat_missing_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (r, w) = read_io_stat(dir.path());
        assert_eq!(r, None);
        assert_eq!(w, None);
    }

    #[test]
    fn parse_pids_current() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("pids.current"), "42\n").unwrap();
        assert_eq!(read_pids_current(dir.path()), Some(42));
    }

    #[test]
    fn parse_pids_current_missing() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert_eq!(read_pids_current(dir.path()), None);
    }

    // -------------------------------------------------------------------------
    // End-to-end collection test
    // -------------------------------------------------------------------------

    #[test]
    fn collect_from_mock_cgroup_root() {
        let root = tempfile::tempdir().expect("tempdir");
        let cgroup_path = "system.slice/test-unit.scope";
        let cgroup_dir = root.path().join(cgroup_path);
        std::fs::create_dir_all(&cgroup_dir).unwrap();

        std::fs::write(
            cgroup_dir.join("cpu.stat"),
            "usage_usec 999\nuser_usec 500\nsystem_usec 499\n",
        )
        .unwrap();
        std::fs::write(cgroup_dir.join("memory.peak"), "4096\n").unwrap();
        std::fs::write(cgroup_dir.join("io.stat"), "8:0 rbytes=100 wbytes=200\n").unwrap();
        std::fs::write(cgroup_dir.join("pids.current"), "7\n").unwrap();

        let usage = collect_cgroup_usage_from_root(cgroup_path, root.path());

        assert_eq!(usage.cpu_time_us, Some(999));
        assert_eq!(usage.peak_memory_bytes, Some(4096));
        assert_eq!(usage.io_read_bytes, Some(100));
        assert_eq!(usage.io_write_bytes, Some(200));
        assert_eq!(usage.tasks_count, Some(7));
        assert!(usage.validate().is_ok());
    }

    #[test]
    fn collect_from_nonexistent_cgroup_returns_all_none() {
        let root = tempfile::tempdir().expect("tempdir");
        let usage = collect_cgroup_usage_from_root("nonexistent/cgroup", root.path());
        assert!(usage.is_empty());
    }

    #[test]
    fn collect_with_leading_slash_in_path() {
        let root = tempfile::tempdir().expect("tempdir");
        let cgroup_dir = root.path().join("system.slice/unit.scope");
        std::fs::create_dir_all(&cgroup_dir).unwrap();
        std::fs::write(cgroup_dir.join("pids.current"), "3\n").unwrap();

        let usage = collect_cgroup_usage_from_root("/system.slice/unit.scope", root.path());
        assert_eq!(usage.tasks_count, Some(3));
    }

    // -------------------------------------------------------------------------
    // Canonical bytes helpers
    // -------------------------------------------------------------------------

    #[test]
    fn append_option_u64_none() {
        let mut bytes = Vec::new();
        append_option_u64(&mut bytes, None);
        assert_eq!(bytes, vec![0u8]);
    }

    #[test]
    fn append_option_u64_some() {
        let mut bytes = Vec::new();
        append_option_u64(&mut bytes, Some(42));
        let mut expected = vec![1u8];
        expected.extend_from_slice(&42u64.to_be_bytes());
        assert_eq!(bytes, expected);
    }

    #[test]
    fn append_option_u64_some_zero() {
        let mut bytes_none = Vec::new();
        append_option_u64(&mut bytes_none, None);

        let mut bytes_zero = Vec::new();
        append_option_u64(&mut bytes_zero, Some(0));

        // None and Some(0) must produce distinct bytes (injectivity).
        assert_ne!(bytes_none, bytes_zero);
    }

    #[test]
    fn append_option_u32_none_vs_some_zero() {
        let mut bytes_none = Vec::new();
        append_option_u32(&mut bytes_none, None);

        let mut bytes_zero = Vec::new();
        append_option_u32(&mut bytes_zero, Some(0));

        assert_ne!(bytes_none, bytes_zero);
    }

    // -------------------------------------------------------------------------
    // Serde round-trip
    // -------------------------------------------------------------------------

    #[test]
    fn serde_round_trip_full() {
        let usage = ObservedCgroupUsage {
            cpu_time_us: Some(100_000),
            peak_memory_bytes: Some(1 << 20),
            io_read_bytes: Some(5000),
            io_write_bytes: Some(3000),
            tasks_count: Some(10),
        };
        let json = serde_json::to_string(&usage).unwrap();
        let parsed: ObservedCgroupUsage = serde_json::from_str(&json).unwrap();
        assert_eq!(usage, parsed);
    }

    #[test]
    fn serde_round_trip_all_none() {
        let usage = ObservedCgroupUsage {
            cpu_time_us: None,
            peak_memory_bytes: None,
            io_read_bytes: None,
            io_write_bytes: None,
            tasks_count: None,
        };
        let json = serde_json::to_string(&usage).unwrap();
        let parsed: ObservedCgroupUsage = serde_json::from_str(&json).unwrap();
        assert_eq!(usage, parsed);
    }

    #[test]
    fn bounded_file_read_rejects_oversized() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("huge.stat");
        // Write a file larger than MAX_CGROUP_STAT_READ.
        let content = "x".repeat(MAX_CGROUP_STAT_READ + 100);
        std::fs::write(&path, &content).unwrap();
        assert!(read_bounded_file(&path).is_none());
    }

    #[test]
    fn io_stat_saturating_sum() {
        let dir = tempfile::tempdir().expect("tempdir");
        // Two devices with values close to u64::MAX.
        std::fs::write(
            dir.path().join("io.stat"),
            format!(
                "8:0 rbytes={} wbytes={}\n8:16 rbytes={} wbytes={}\n",
                u64::MAX - 1,
                u64::MAX - 1,
                10,
                10,
            ),
        )
        .unwrap();
        let (r, w) = read_io_stat(dir.path());
        // saturating_add should cap at u64::MAX
        assert_eq!(r, Some(u64::MAX));
        assert_eq!(w, Some(u64::MAX));
    }
}
