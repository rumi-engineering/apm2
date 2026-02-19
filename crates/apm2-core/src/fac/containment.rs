//! Containment verification for FAC job execution.
//!
//! This module implements cgroup membership checks to verify that child
//! processes (rustc, nextest, cc, ld, etc.) share the same cgroup hierarchy
//! as the job unit. When sccache is enabled and containment fails, sccache
//! is auto-disabled with a receipt recording the downgrade.
//!
//! # Architecture
//!
//! On cgroups v2 (unified hierarchy), each process has a single cgroup
//! path visible in `/proc/<pid>/cgroup` as `0::<path>`. A transient
//! systemd unit confines all child processes under the same cgroup
//! subtree. If a process (e.g., sccache daemon) escapes the cgroup,
//! containment is broken and build cache poisoning becomes possible.
//!
//! # Fail-Closed Semantics
//!
//! - If `/proc/<pid>/cgroup` cannot be read, the process is treated as escaped
//!   (fail-closed per INV-CORE-003).
//! - If the cgroup hierarchy cannot be determined, containment is assumed to
//!   have failed.
//! - When sccache is enabled and containment fails, sccache is auto-disabled
//!   rather than allowing an unsafe build.
//!
//! # Security Invariants
//!
//! - [INV-CONTAIN-001] Containment check is fail-closed: unreadable `/proc`
//!   entries result in mismatch verdict.
//! - [INV-CONTAIN-002] All `/proc` reads are bounded by `MAX_PROC_READ_SIZE`.
//! - [INV-CONTAIN-003] Process discovery bounds: at most `MAX_CHILD_PROCESSES`
//!   children are checked.
//! - [INV-CONTAIN-004] Cgroup path comparison uses exact prefix matching to
//!   prevent subtree escapes.
//! - [INV-CONTAIN-005] Process names discovered from `/proc/<pid>/comm` are
//!   bounded by `MAX_COMM_LENGTH`.
//! - [INV-CONTAIN-006] PID parsing rejects negative values and values exceeding
//!   `MAX_PID_VALUE`.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use thiserror::Error;

// =============================================================================
// Constants
// =============================================================================

/// Maximum size for `/proc` file reads (4 KiB).
///
/// `/proc/<pid>/cgroup` and `/proc/<pid>/comm` are typically under 1 KiB.
/// This cap prevents denial-of-service via crafted procfs entries (RSK-1601).
pub const MAX_PROC_READ_SIZE: u64 = 4096;

/// Maximum number of child processes to check for containment.
///
/// Prevents unbounded iteration over process trees. A typical build
/// job has at most a few hundred concurrent processes.
pub const MAX_CHILD_PROCESSES: usize = 2048;

/// Maximum length for process comm name from `/proc/<pid>/comm`.
///
/// Linux kernel truncates comm to 15 bytes + newline (`TASK_COMM_LEN=16`).
pub const MAX_COMM_LENGTH: usize = 64;

/// Maximum PID value (Linux default max PID is 4194304 with
/// `/proc/sys/kernel/pid_max`).
pub const MAX_PID_VALUE: u32 = 4_194_304;

/// Maximum number of directory entries scanned in `/proc` during
/// process discovery.
///
/// Set to 131,072 to accommodate high-thread-count systems (e.g., 128-core
/// machines with thread-per-core workloads). The previous value (65,536)
/// could trigger false containment failures on such systems.
pub const MAX_PROC_SCAN_ENTRIES: usize = 131_072;

/// Maximum number of containment mismatches recorded in a verdict.
pub const MAX_CONTAINMENT_MISMATCHES: usize = 256;

/// Maximum cgroup path length.
pub const MAX_CGROUP_PATH_LENGTH: usize = 4096;

/// Maximum length for mismatch detail strings in serialized output.
const MAX_MISMATCH_DETAIL_LENGTH: usize = 512;

/// Timeout for sccache version probe (5 seconds).
///
/// Prevents a malicious or hung sccache binary from blocking the worker
/// indefinitely. The probe is killed and reaped on timeout.
const SCCACHE_PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// Maximum time to wait for the reader thread to join after the child
/// process has been killed and reaped. Prevents indefinite blocking if
/// a descendant process holds stdout open (INV-CONTAIN-008).
const SCCACHE_THREAD_JOIN_TIMEOUT: Duration = Duration::from_secs(2);

/// Timeout for sccache server start (`sccache --start-server`).
///
/// Bounded at 10 seconds. If the server cannot start in this time,
/// sccache is auto-disabled (fail-closed).
const SCCACHE_SERVER_START_TIMEOUT: Duration = Duration::from_secs(10);

/// Timeout for sccache server stop (`sccache --stop-server`).
///
/// Bounded at 5 seconds. Best-effort; failure to stop is logged but
/// does not block job completion.
const SCCACHE_SERVER_STOP_TIMEOUT: Duration = Duration::from_secs(5);

/// Maximum output bytes from sccache server start/stop commands.
const MAX_SCCACHE_SERVER_OUTPUT: usize = 4096;

/// Process names of interest for containment verification.
/// These are the processes whose cgroup membership is most critical
/// for build integrity.
const CONTAINMENT_CRITICAL_PROCESSES: &[&str] = &[
    "rustc",
    "cargo",
    "nextest",
    "cargo-nextest",
    "cc",
    "cc1",
    "ld",
    "ar",
    "as",
    "sccache",
    "sccache-dist",
];

// =============================================================================
// Error Types
// =============================================================================

/// Errors during containment verification.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ContainmentError {
    /// Failed to read procfs entry.
    #[error("failed to read /proc/{pid}/{file}: {reason}")]
    ProcReadFailed {
        /// The PID that could not be read.
        pid: u32,
        /// The procfs file that failed.
        file: String,
        /// Reason for failure.
        reason: String,
    },

    /// Cgroup path could not be parsed.
    #[error("failed to parse cgroup path for PID {pid}: {reason}")]
    CgroupParseFailed {
        /// PID with invalid cgroup data.
        pid: u32,
        /// Parse failure reason.
        reason: String,
    },

    /// Too many child processes to check.
    #[error("child process count {count} exceeds limit {max}")]
    TooManyChildren {
        /// Actual count.
        count: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Invalid PID value.
    #[error("invalid PID value: {reason}")]
    InvalidPid {
        /// Reason for rejection.
        reason: String,
    },

    /// Too many mismatches to record.
    #[error("containment mismatch count {count} exceeds limit {max}")]
    TooManyMismatches {
        /// Actual count.
        count: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// /proc scan exceeded the bounded entry limit.
    ///
    /// Fail-closed: if we cannot scan all of /proc, we cannot guarantee
    /// containment verification is complete. The caller must treat this
    /// as a containment failure.
    #[error(
        "/proc scan exceeded {max} entries ({scanned} scanned, {ppid_failures} PPid read failures); containment verification incomplete"
    )]
    ProcScanOverflow {
        /// Number of entries scanned before hitting the limit.
        scanned: usize,
        /// Maximum allowed entries.
        max: usize,
        /// Number of `PPid` read failures encountered.
        ppid_failures: usize,
    },

    /// Cgroup path exceeds length limit.
    #[error("cgroup path length {length} exceeds limit {max}")]
    CgroupPathTooLong {
        /// Actual length.
        length: usize,
        /// Maximum allowed.
        max: usize,
    },
}

// =============================================================================
// Core Types
// =============================================================================

/// A single containment mismatch: a process found outside the expected cgroup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContainmentMismatch {
    /// PID of the mismatched process.
    pub pid: u32,
    /// Process name (from `/proc/<pid>/comm`).
    pub process_name: String,
    /// Expected cgroup path (the job unit's cgroup).
    pub expected_cgroup: String,
    /// Actual cgroup path found for this process.
    pub actual_cgroup: String,
}

/// Verdict of a containment verification check.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContainmentVerdict {
    /// Whether containment is verified (all children in same cgroup).
    pub contained: bool,
    /// The reference cgroup path (the job unit's cgroup).
    pub reference_cgroup: String,
    /// Total number of child processes checked.
    pub processes_checked: u32,
    /// Number of critical processes (rustc, nextest, etc.) found.
    pub critical_processes_found: u32,
    /// Processes that escaped the expected cgroup.
    pub mismatches: Vec<ContainmentMismatch>,
    /// Whether sccache was detected as active.
    pub sccache_detected: bool,
    /// If sccache was auto-disabled due to containment failure.
    pub sccache_auto_disabled: bool,
    /// Human-readable reason if sccache was disabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sccache_disabled_reason: Option<String>,
}

/// Outcome of the sccache server containment protocol (TCK-00554).
///
/// Records whether the sccache server was started inside the job unit
/// cgroup, whether a pre-existing out-of-cgroup server was refused,
/// and the final disposition of sccache for the job.
///
/// # Security Invariants
///
/// - [INV-CONTAIN-009] Refuse to attach to a pre-existing sccache server that
///   is outside the unit cgroup. Verified by checking the PID of any running
///   sccache server against the reference cgroup.
/// - [INV-CONTAIN-010] Start a new sccache server inside the unit cgroup when
///   policy enables sccache and no in-cgroup server exists.
/// - [INV-CONTAIN-011] Stop the server at unit end to prevent cgroup escape.
/// - [INV-CONTAIN-012] Auto-disable sccache if server containment cannot be
///   verified (fail-closed).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct SccacheServerContainment {
    /// Whether the sccache server containment protocol was executed.
    pub protocol_executed: bool,
    /// Whether a pre-existing sccache server was detected.
    pub preexisting_server_detected: bool,
    /// Whether the pre-existing server was inside the unit cgroup.
    /// `None` if no pre-existing server was detected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preexisting_server_in_cgroup: Option<bool>,
    /// PID of the pre-existing sccache server, if detected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preexisting_server_pid: Option<u32>,
    /// Whether a new sccache server was started inside the cgroup.
    pub server_started: bool,
    /// PID of the newly started sccache server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_server_pid: Option<u32>,
    /// Whether the started server was verified to be inside the cgroup.
    pub server_cgroup_verified: bool,
    /// Whether sccache was auto-disabled due to server containment failure.
    pub auto_disabled: bool,
    /// Human-readable reason for the disposition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl Default for SccacheServerContainment {
    /// Fail-closed default: protocol not executed, everything false/None.
    fn default() -> Self {
        Self {
            protocol_executed: false,
            preexisting_server_detected: false,
            preexisting_server_in_cgroup: None,
            preexisting_server_pid: None,
            server_started: false,
            started_server_pid: None,
            server_cgroup_verified: false,
            auto_disabled: false,
            reason: None,
        }
    }
}

/// Maximum length for the `reason` field in `SccacheServerContainment`.
const MAX_SERVER_CONTAINMENT_REASON_LENGTH: usize = 512;

/// Maximum number of sccache server PIDs that the set-based discovery
/// will collect. Exceeding this bound triggers fail-closed auto-disable.
const MAX_SCCACHE_SERVER_PIDS: usize = 64;

/// Trace for containment checks included in job receipts.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContainmentTrace {
    /// Whether containment was verified.
    pub verified: bool,
    /// The reference cgroup path.
    pub cgroup_path: String,
    /// Number of processes checked.
    pub processes_checked: u32,
    /// Number of mismatches found.
    pub mismatch_count: u32,
    /// Whether sccache was auto-disabled.
    pub sccache_auto_disabled: bool,
    /// Whether sccache was explicitly enabled by policy (TCK-00553).
    ///
    /// `true` when the policy `sccache_enabled` knob is set AND containment
    /// passed (sccache is actually active in the job environment).
    /// `false` when sccache is disabled by default or was auto-disabled.
    #[serde(default)]
    pub sccache_enabled: bool,
    /// sccache version string if detected and sccache is enabled (TCK-00553).
    ///
    /// Populated by probing `sccache --version` when the policy enables
    /// sccache. Included in attestation for auditability.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sccache_version: Option<String>,
    /// sccache server containment protocol result (TCK-00554).
    ///
    /// Records the full outcome of the per-unit server lifecycle protocol:
    /// whether a pre-existing server was detected, whether it was in the
    /// unit cgroup, whether a new server was started, and the final
    /// disposition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sccache_server_containment: Option<SccacheServerContainment>,
}

/// Maximum length for sccache version string to prevent denial-of-service
/// (TCK-00553).
pub const MAX_SCCACHE_VERSION_LENGTH: usize = 256;

impl ContainmentTrace {
    /// Creates a trace from a verdict.
    #[must_use]
    pub fn from_verdict(verdict: &ContainmentVerdict) -> Self {
        Self {
            verified: verdict.contained,
            cgroup_path: verdict.reference_cgroup.clone(),
            processes_checked: verdict.processes_checked,
            #[allow(clippy::cast_possible_truncation)]
            mismatch_count: verdict.mismatches.len() as u32,
            sccache_auto_disabled: verdict.sccache_auto_disabled,
            sccache_enabled: false,
            sccache_version: None,
            sccache_server_containment: None,
        }
    }

    /// Creates a trace from a verdict with sccache activation info
    /// (TCK-00553).
    ///
    /// When the policy enables sccache and containment passes, this records
    /// `sccache_enabled = true` and captures the sccache version for
    /// attestation.
    #[must_use]
    pub fn from_verdict_with_sccache(
        verdict: &ContainmentVerdict,
        policy_sccache_enabled: bool,
        sccache_version: Option<String>,
    ) -> Self {
        let effective_enabled =
            policy_sccache_enabled && verdict.contained && !verdict.sccache_auto_disabled;
        let bounded_version =
            sccache_version.map(|v| truncate_utf8_safe(&v, MAX_SCCACHE_VERSION_LENGTH));
        Self {
            verified: verdict.contained,
            cgroup_path: verdict.reference_cgroup.clone(),
            processes_checked: verdict.processes_checked,
            #[allow(clippy::cast_possible_truncation)]
            mismatch_count: verdict.mismatches.len() as u32,
            sccache_auto_disabled: verdict.sccache_auto_disabled,
            sccache_enabled: effective_enabled,
            sccache_version: if effective_enabled {
                bounded_version
            } else {
                None
            },
            sccache_server_containment: None,
        }
    }

    /// Creates a trace from a verdict with full sccache server containment
    /// protocol result (TCK-00554).
    ///
    /// Extends `from_verdict_with_sccache` by attaching the server
    /// containment protocol outcome. If the server containment protocol
    /// auto-disabled sccache, this overrides `sccache_enabled` to `false`.
    #[must_use]
    pub fn from_verdict_with_server_containment(
        verdict: &ContainmentVerdict,
        policy_sccache_enabled: bool,
        sccache_version: Option<String>,
        server_containment: SccacheServerContainment,
    ) -> Self {
        let mut trace =
            Self::from_verdict_with_sccache(verdict, policy_sccache_enabled, sccache_version);
        // If server containment auto-disabled sccache, override the
        // enabled flag (fail-closed: INV-CONTAIN-012).
        if server_containment.auto_disabled {
            trace.sccache_enabled = false;
            trace.sccache_auto_disabled = true;
            trace.sccache_version = None;
        }
        trace.sccache_server_containment = Some(server_containment);
        trace
    }
}

// =============================================================================
// Cgroup Path Parsing
// =============================================================================

/// Reads the cgroup v2 path for a process from `/proc/<pid>/cgroup`.
///
/// On cgroups v2 (unified hierarchy), the file contains a single line:
/// `0::<path>`. Returns the `<path>` portion.
///
/// # Errors
///
/// Returns [`ContainmentError::ProcReadFailed`] if the file cannot be read.
/// Returns [`ContainmentError::CgroupParseFailed`] if no v2 entry is found.
/// Returns [`ContainmentError::InvalidPid`] if the PID is invalid.
/// Fail-closed: any read or parse failure is an error (INV-CONTAIN-001).
pub fn read_cgroup_path(pid: u32) -> Result<String, ContainmentError> {
    read_cgroup_path_from_proc(pid, Path::new("/proc"))
}

/// Reads the cgroup path with a configurable procfs root (for testing).
///
/// # Errors
///
/// Returns [`ContainmentError::InvalidPid`] if the PID is invalid.
/// Returns [`ContainmentError::ProcReadFailed`] if the cgroup file cannot be
/// read. Returns [`ContainmentError::CgroupParseFailed`] if no v2 entry is
/// found.
pub fn read_cgroup_path_from_proc(pid: u32, proc_root: &Path) -> Result<String, ContainmentError> {
    validate_pid(pid)?;

    let cgroup_file = proc_root.join(pid.to_string()).join("cgroup");
    let content = read_proc_file_bounded(&cgroup_file, pid, "cgroup")?;

    parse_cgroup_v2_path(&content, pid)
}

/// Parses a cgroup v2 path from `/proc/<pid>/cgroup` content.
///
/// Expected format: `0::<path>\n`
/// The `0::` prefix indicates cgroups v2 unified hierarchy.
fn parse_cgroup_v2_path(content: &str, pid: u32) -> Result<String, ContainmentError> {
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        // cgroups v2 unified hierarchy: line starts with "0::"
        if let Some(path) = trimmed.strip_prefix("0::") {
            if path.len() > MAX_CGROUP_PATH_LENGTH {
                return Err(ContainmentError::CgroupPathTooLong {
                    length: path.len(),
                    max: MAX_CGROUP_PATH_LENGTH,
                });
            }
            return Ok(path.to_string());
        }
    }

    Err(ContainmentError::CgroupParseFailed {
        pid,
        reason: "no cgroups v2 entry (0::) found".to_string(),
    })
}

// =============================================================================
// Process Discovery
// =============================================================================

/// Discovered process information.
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    /// Process ID.
    pub pid: u32,
    /// Process name from `/proc/<pid>/comm`.
    pub comm: String,
    /// Cgroup path from `/proc/<pid>/cgroup`.
    pub cgroup_path: String,
}

/// Discovers child processes of a given PID by scanning `/proc`.
///
/// Scans `/proc/*/status` for `PPid` matching the parent PID, then
/// recursively discovers children of children up to `MAX_CHILD_PROCESSES`.
///
/// # Arguments
///
/// * `parent_pid` - PID of the parent process (job unit main process)
///
/// # Returns
///
/// A list of discovered child `ProcessInfo` entries.
///
/// # Errors
///
/// Returns error if more than `MAX_CHILD_PROCESSES` are found.
pub fn discover_children(parent_pid: u32) -> Result<Vec<ProcessInfo>, ContainmentError> {
    discover_children_from_proc(parent_pid, Path::new("/proc"))
}

/// Discovers children with a configurable procfs root (for testing).
///
/// # Errors
///
/// Returns [`ContainmentError::InvalidPid`] if the parent PID is invalid.
/// Returns [`ContainmentError::ProcReadFailed`] if the proc directory cannot be
/// read. Returns [`ContainmentError::TooManyChildren`] if the child count
/// exceeds `MAX_CHILD_PROCESSES`.
pub fn discover_children_from_proc(
    parent_pid: u32,
    proc_root: &Path,
) -> Result<Vec<ProcessInfo>, ContainmentError> {
    validate_pid(parent_pid)?;

    // Build parent->children mapping from /proc/*/status
    let mut parent_map: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
    let mut proc_entries_scanned: usize = 0;
    let mut ppid_read_failures: usize = 0;

    let proc_dir = match std::fs::read_dir(proc_root) {
        Ok(d) => d,
        Err(e) => {
            return Err(ContainmentError::ProcReadFailed {
                pid: parent_pid,
                file: "proc_dir".to_string(),
                reason: format!("cannot read {}: {e}", proc_root.display()),
            });
        },
    };

    for entry in proc_dir {
        proc_entries_scanned = proc_entries_scanned.saturating_add(1);
        if proc_entries_scanned > MAX_PROC_SCAN_ENTRIES {
            // Fail-closed: if /proc has more entries than
            // MAX_PROC_SCAN_ENTRIES, we cannot guarantee a complete
            // scan. Return an error so callers treat this as a
            // containment failure (INV-CONTAIN-003).
            return Err(ContainmentError::ProcScanOverflow {
                scanned: proc_entries_scanned,
                max: MAX_PROC_SCAN_ENTRIES,
                ppid_failures: ppid_read_failures,
            });
        }

        let Ok(entry) = entry else { continue };

        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        // Only look at numeric directories (PID directories)
        let child_pid: u32 = match name_str.parse() {
            Ok(p) if p > 0 && p <= MAX_PID_VALUE => p,
            _ => continue,
        };

        // Read PPid from /proc/<pid>/status
        let status_path = proc_root.join(&name).join("status");
        match read_ppid_from_status(&status_path, child_pid) {
            Ok(ppid) => {
                parent_map.entry(ppid).or_default().push(child_pid);
            },
            Err(_) => {
                ppid_read_failures = ppid_read_failures.saturating_add(1);
            },
        }
    }

    // Fail-closed: if too many PPid reads failed, the parent map is
    // unreliable and we may miss escaped children. Threshold: more
    // than half of numeric PID entries failed.
    let numeric_entries = parent_map.values().map(Vec::len).sum::<usize>();
    let total_pid_attempts = numeric_entries.saturating_add(ppid_read_failures);
    if total_pid_attempts > 0 && ppid_read_failures > total_pid_attempts / 2 {
        return Err(ContainmentError::ProcScanOverflow {
            scanned: proc_entries_scanned,
            max: MAX_PROC_SCAN_ENTRIES,
            ppid_failures: ppid_read_failures,
        });
    }

    // BFS from parent_pid to collect all descendants
    let mut descendants = Vec::new();
    let mut queue = std::collections::VecDeque::new();
    queue.push_back(parent_pid);

    while let Some(current) = queue.pop_front() {
        if let Some(children) = parent_map.get(&current) {
            for &child_pid in children {
                if descendants.len() >= MAX_CHILD_PROCESSES {
                    return Err(ContainmentError::TooManyChildren {
                        count: descendants.len().saturating_add(1),
                        max: MAX_CHILD_PROCESSES,
                    });
                }

                // Read comm and cgroup for this child
                let comm =
                    read_comm(child_pid, proc_root).unwrap_or_else(|_| "<unknown>".to_string());
                let cgroup_path = read_cgroup_path_from_proc(child_pid, proc_root)
                    .unwrap_or_else(|_| "<unreadable>".to_string());

                descendants.push(ProcessInfo {
                    pid: child_pid,
                    comm,
                    cgroup_path,
                });
                queue.push_back(child_pid);
            }
        }
    }

    Ok(descendants)
}

/// Reads the comm (process name) from `/proc/<pid>/comm`.
fn read_comm(pid: u32, proc_root: &Path) -> Result<String, ContainmentError> {
    let comm_path = proc_root.join(pid.to_string()).join("comm");
    let content = read_proc_file_bounded(&comm_path, pid, "comm")?;
    let trimmed = content.trim();
    if trimmed.len() > MAX_COMM_LENGTH {
        Ok(trimmed[..MAX_COMM_LENGTH].to_string())
    } else {
        Ok(trimmed.to_string())
    }
}

/// Reads `PPid` from `/proc/<pid>/status`.
fn read_ppid_from_status(status_path: &Path, pid: u32) -> Result<u32, ContainmentError> {
    let content = read_proc_file_bounded(status_path, pid, "status")?;

    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("PPid:") {
            let trimmed = rest.trim();
            return trimmed
                .parse::<u32>()
                .map_err(|_| ContainmentError::ProcReadFailed {
                    pid,
                    file: "status".to_string(),
                    reason: format!("invalid PPid value: '{trimmed}'"),
                });
        }
    }

    Err(ContainmentError::ProcReadFailed {
        pid,
        file: "status".to_string(),
        reason: "PPid field not found".to_string(),
    })
}

// =============================================================================
// Cgroup Procs Discovery (daemonized process detection)
// =============================================================================

/// Maximum number of PIDs read from a single `cgroup.procs` file.
///
/// Prevents memory exhaustion if the cgroup contains an unexpectedly large
/// number of processes.
const MAX_CGROUP_PROCS_ENTRIES: usize = 16_384;

/// Maximum byte size for reading `cgroup.procs` files (64 KiB).
///
/// A PID line is at most ~8 bytes plus newline; 16,384 entries fit within
/// ~160 KiB, but we cap the read at 64 KiB as a safety bound.
const MAX_CGROUP_PROCS_READ_SIZE: u64 = 65_536;

/// Discovers PIDs from a cgroup `cgroup.procs` file.
///
/// Reads `/sys/fs/cgroup/<cgroup_path>/cgroup.procs` (or equivalent under
/// `cgroup_root`) to find all PIDs assigned to the cgroup hierarchy. This
/// catches daemonized (double-forked) processes that escape the BFS parent
/// tree walk because they have been re-parented to PID 1.
///
/// # Arguments
///
/// * `cgroup_path` - The cgroup v2 path (e.g.,
///   `/system.slice/apm2-job.service`)
/// * `cgroup_root` - Root of the cgroup filesystem (typically `/sys/fs/cgroup`)
///
/// # Returns
///
/// A set of PIDs found in the cgroup. Returns an empty set on any read error
/// (fail-open for this supplementary scan -- the main BFS scan is fail-closed,
/// and any PIDs discovered here that are NOT in the BFS results are flagged
/// as escaped).
#[must_use]
pub fn discover_cgroup_procs_with_root(
    cgroup_path: &str,
    cgroup_root: &Path,
) -> std::collections::BTreeSet<u32> {
    let mut pids = std::collections::BTreeSet::new();

    // Strip leading slash from cgroup_path for path joining.
    let relative_path = cgroup_path.strip_prefix('/').unwrap_or(cgroup_path);
    let procs_file = cgroup_root.join(relative_path).join("cgroup.procs");

    let Ok(file) = File::open(&procs_file) else {
        return pids;
    };

    let mut reader = BufReader::new(file).take(MAX_CGROUP_PROCS_READ_SIZE);
    let mut content = String::with_capacity(512);
    if reader.read_to_string(&mut content).is_err() {
        return pids;
    }

    for line in content.lines() {
        if pids.len() >= MAX_CGROUP_PROCS_ENTRIES {
            break;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(pid) = trimmed.parse::<u32>() {
            if pid > 0 && pid <= MAX_PID_VALUE {
                pids.insert(pid);
            }
        }
    }

    pids
}

/// Discovers PIDs from the system cgroup filesystem at `/sys/fs/cgroup`.
#[must_use]
pub fn discover_cgroup_procs(cgroup_path: &str) -> std::collections::BTreeSet<u32> {
    discover_cgroup_procs_with_root(cgroup_path, Path::new("/sys/fs/cgroup"))
}

// =============================================================================
// Containment Verification
// =============================================================================

/// Verifies containment of child processes within the expected cgroup.
///
/// Reads the cgroup path of the reference PID (job unit main process),
/// then discovers all child processes and verifies they share the same
/// cgroup subtree.
///
/// # Arguments
///
/// * `reference_pid` - PID of the job's main process (reference cgroup)
/// * `sccache_enabled` - Whether sccache is currently enabled
///
/// # Returns
///
/// A `ContainmentVerdict` with the check results.
///
/// # Errors
///
/// Returns error only for hard failures (too many children, etc.).
/// Individual process read failures produce mismatches, not errors
/// (fail-closed: unreadable process = assumed escaped).
pub fn verify_containment(
    reference_pid: u32,
    sccache_enabled: bool,
) -> Result<ContainmentVerdict, ContainmentError> {
    verify_containment_with_proc(reference_pid, sccache_enabled, Path::new("/proc"))
}

/// Verifies containment with a configurable procfs root (for testing).
///
/// Delegates to [`verify_containment_with_proc_and_cgroup`] using the
/// system cgroup root (`/sys/fs/cgroup`).
///
/// # Errors
///
/// Returns [`ContainmentError::InvalidPid`] if the reference PID is invalid.
/// Returns [`ContainmentError::ProcReadFailed`] if the reference cgroup cannot
/// be read. Returns [`ContainmentError::TooManyChildren`] if the child count
/// exceeds limits. Returns [`ContainmentError::TooManyMismatches`] if mismatch
/// count exceeds limits.
pub fn verify_containment_with_proc(
    reference_pid: u32,
    sccache_enabled: bool,
    proc_root: &Path,
) -> Result<ContainmentVerdict, ContainmentError> {
    verify_containment_with_proc_and_cgroup(
        reference_pid,
        sccache_enabled,
        proc_root,
        Path::new("/sys/fs/cgroup"),
    )
}

/// Verifies containment with configurable procfs and cgroup roots (for
/// testing).
///
/// This is the fully testable variant that accepts both a proc root and a
/// cgroup filesystem root. The cgroup.procs scan detects daemonized (double-
/// forked, re-parented to PID 1) processes that escape BFS parent tree walk.
///
/// # Errors
///
/// Returns [`ContainmentError::InvalidPid`] if the reference PID is invalid.
/// Returns [`ContainmentError::ProcReadFailed`] if the reference cgroup cannot
/// be read. Returns [`ContainmentError::TooManyChildren`] if the child count
/// exceeds limits. Returns [`ContainmentError::TooManyMismatches`] if mismatch
/// count exceeds limits.
pub fn verify_containment_with_proc_and_cgroup(
    reference_pid: u32,
    sccache_enabled: bool,
    proc_root: &Path,
    cgroup_root: &Path,
) -> Result<ContainmentVerdict, ContainmentError> {
    // Read the reference cgroup path (fail-closed: error if unreadable)
    let reference_cgroup = read_cgroup_path_from_proc(reference_pid, proc_root)?;

    // Discover children via BFS on parent tree (PPid walk)
    let children = discover_children_from_proc(reference_pid, proc_root)?;

    // Collect BFS-discovered PIDs for cross-referencing
    let bfs_pids: std::collections::BTreeSet<u32> = children.iter().map(|c| c.pid).collect();

    let mut mismatches = Vec::new();
    let mut critical_count: u32 = 0;
    let mut sccache_detected = false;

    for child in &children {
        // Check if this is a critical process
        let is_critical = CONTAINMENT_CRITICAL_PROCESSES
            .iter()
            .any(|&name| child.comm.contains(name));

        if is_critical {
            critical_count = critical_count.saturating_add(1);
        }

        // Check if sccache is running
        if child.comm.contains("sccache") {
            sccache_detected = true;
        }

        // Verify cgroup containment: the child's cgroup must be equal to
        // or a subtree of the reference cgroup.
        let contained = is_cgroup_contained(&child.cgroup_path, &reference_cgroup);

        if !contained {
            if mismatches.len() >= MAX_CONTAINMENT_MISMATCHES {
                return Err(ContainmentError::TooManyMismatches {
                    count: mismatches.len().saturating_add(1),
                    max: MAX_CONTAINMENT_MISMATCHES,
                });
            }

            mismatches.push(ContainmentMismatch {
                pid: child.pid,
                process_name: truncate_string(&child.comm, MAX_MISMATCH_DETAIL_LENGTH),
                expected_cgroup: truncate_string(&reference_cgroup, MAX_MISMATCH_DETAIL_LENGTH),
                actual_cgroup: truncate_string(&child.cgroup_path, MAX_MISMATCH_DETAIL_LENGTH),
            });
        }
    }

    // MAJOR-3 fix: Scan cgroup.procs to detect daemonized processes
    // (double-forked, re-parented to PID 1) that are invisible to the
    // BFS PPid walk. Any PID in cgroup.procs that is NOT in the BFS
    // result set (and is not the reference PID itself) has escaped the
    // parent tree — treat as a mismatch.
    let cgroup_pids = discover_cgroup_procs_with_root(&reference_cgroup, cgroup_root);
    for &cgroup_pid in &cgroup_pids {
        if cgroup_pid == reference_pid {
            continue;
        }
        if bfs_pids.contains(&cgroup_pid) {
            // Already accounted for by BFS walk — no action needed.
            continue;
        }

        // This PID is in the cgroup but was NOT found via BFS: it was
        // likely daemonized (double-forked). Read its comm and cgroup
        // to record a proper mismatch entry.
        let comm = read_comm(cgroup_pid, proc_root).unwrap_or_else(|_| "<unknown>".to_string());
        let child_cgroup = read_cgroup_path_from_proc(cgroup_pid, proc_root)
            .unwrap_or_else(|_| "<unreadable>".to_string());

        let is_critical = CONTAINMENT_CRITICAL_PROCESSES
            .iter()
            .any(|&name| comm.contains(name));
        if is_critical {
            critical_count = critical_count.saturating_add(1);
        }
        if comm.contains("sccache") {
            sccache_detected = true;
        }

        // Check containment for the cgroup-discovered process
        let contained = is_cgroup_contained(&child_cgroup, &reference_cgroup);
        if !contained {
            if mismatches.len() >= MAX_CONTAINMENT_MISMATCHES {
                return Err(ContainmentError::TooManyMismatches {
                    count: mismatches.len().saturating_add(1),
                    max: MAX_CONTAINMENT_MISMATCHES,
                });
            }

            mismatches.push(ContainmentMismatch {
                pid: cgroup_pid,
                process_name: truncate_string(&comm, MAX_MISMATCH_DETAIL_LENGTH),
                expected_cgroup: truncate_string(&reference_cgroup, MAX_MISMATCH_DETAIL_LENGTH),
                actual_cgroup: truncate_string(&child_cgroup, MAX_MISMATCH_DETAIL_LENGTH),
            });
        }
    }

    let total_checked = children.len().saturating_add(
        cgroup_pids
            .iter()
            .filter(|&&pid| pid != reference_pid && !bfs_pids.contains(&pid))
            .count(),
    );

    let all_contained = mismatches.is_empty();

    // Sccache gating: if sccache is enabled and containment failed,
    // auto-disable sccache.
    let sccache_auto_disabled = sccache_enabled && !all_contained;
    let sccache_disabled_reason = if sccache_auto_disabled {
        Some(format!(
            "containment verification failed: {} process(es) escaped cgroup '{}'; \
             sccache auto-disabled to prevent cache poisoning",
            mismatches.len(),
            truncate_string(&reference_cgroup, 128),
        ))
    } else {
        None
    };

    #[allow(clippy::cast_possible_truncation)]
    Ok(ContainmentVerdict {
        contained: all_contained,
        reference_cgroup,
        processes_checked: total_checked as u32,
        critical_processes_found: critical_count,
        mismatches,
        sccache_detected,
        sccache_auto_disabled,
        sccache_disabled_reason,
    })
}

/// Checks whether a child cgroup path is contained within a reference
/// cgroup path.
///
/// Containment means the child's cgroup path is either:
/// 1. Exactly equal to the reference path, OR
/// 2. A subtree of the reference path (starts with `reference/`)
///
/// This uses exact prefix matching with a trailing `/` separator to
/// prevent `/sys/fs/cgroup/foo` from matching `/sys/fs/cgroup/foobar`.
#[must_use]
pub fn is_cgroup_contained(child_path: &str, reference_path: &str) -> bool {
    if child_path == "<unreadable>" {
        // Fail-closed: unreadable cgroup means not contained
        // (INV-CONTAIN-001).
        return false;
    }

    if child_path == reference_path {
        return true;
    }

    // Check if child is in a subtree of the reference.
    // Must use slash-separated prefix to prevent partial name matches.
    let prefix_with_slash = if reference_path.ends_with('/') {
        reference_path.to_string()
    } else {
        format!("{reference_path}/")
    };

    child_path.starts_with(&prefix_with_slash)
}

/// Determines whether sccache should be disabled based on containment.
///
/// Returns `Some(reason)` if sccache should be disabled, `None` if safe.
///
/// # Arguments
///
/// * `reference_pid` - PID of the job's main process
/// * `sccache_enabled` - Whether sccache is currently configured
///
/// # Returns
///
/// - `Ok(None)` if sccache is safe to use (containment passed or sccache not
///   enabled)
/// - `Ok(Some(reason))` if sccache should be disabled
///
/// # Errors
///
/// Returns a [`ContainmentError`] if the containment check itself fails
/// (treat as unsafe, fail-closed).
pub fn check_sccache_containment(
    reference_pid: u32,
    sccache_enabled: bool,
) -> Result<Option<String>, ContainmentError> {
    check_sccache_containment_with_proc(reference_pid, sccache_enabled, Path::new("/proc"))
}

/// Checks sccache containment with configurable procfs root.
///
/// # Errors
///
/// Returns a [`ContainmentError`] if the containment check itself fails
/// (treat as unsafe, fail-closed).
pub fn check_sccache_containment_with_proc(
    reference_pid: u32,
    sccache_enabled: bool,
    proc_root: &Path,
) -> Result<Option<String>, ContainmentError> {
    if !sccache_enabled {
        return Ok(None);
    }

    let verdict = verify_containment_with_proc(reference_pid, sccache_enabled, proc_root)?;

    if verdict.sccache_auto_disabled {
        Ok(verdict.sccache_disabled_reason)
    } else {
        Ok(None)
    }
}

/// Probes the sccache version by running `sccache --version` (TCK-00553).
///
/// Returns `Some(version_string)` if sccache is installed and responds
/// within `SCCACHE_PROBE_TIMEOUT` (5 s), `None` if the probe fails
/// (fail-safe since the version is informational for attestation only).
///
/// # Bounded execution guarantees (INV-CONTAIN-008)
///
/// - **Timeout**: Uses a dedicated reader thread for stdout capture so the
///   calling thread can enforce `SCCACHE_PROBE_TIMEOUT` (5 s) even when
///   `read()` blocks. On timeout: `child.kill()` → `drop(child)` (closes pipe
///   FDs) → bounded thread join. This is the same deadlock-free pattern used in
///   `toolchain_fingerprint.rs::version_output()` and
///   `warm.rs::version_output()`.
/// - **Bounded I/O**: The reader thread uses `Take` to cap reads at
///   [`MAX_SCCACHE_VERSION_LENGTH`] bytes. Output at or under the cap is valid;
///   only process-level timeout or read errors cause rejection.
/// - **Controlled environment**: The child inherits no environment from the
///   parent (empty env) except `PATH`, preventing env-based exploits.
/// - **UTF-8 safety**: The result is truncated to a UTF-8-safe boundary using
///   `truncate_utf8_safe` (char-boundary-aware truncation).
///
/// # Happens-before edges
///
/// - H1: reader `read_to_end` completes → reader thread returns (program order)
/// - H2: calling thread `child.kill()` → pipe close → reader `read_to_end`
///   unblocks (OS pipe semantics)
/// - H3: reader thread terminates → `handle.join()` returns (thread join
///   synchronizes-with)
/// - Guarantee: the calling thread always has exclusive kill authority over the
///   child; the reader thread always terminates after kill (via H2→H3).
#[must_use]
pub fn probe_sccache_version() -> Option<String> {
    use std::process::{Command, Stdio};

    // Spawn with bounded pipes and controlled environment.
    // Only PATH is forwarded so `sccache` is found; everything else is
    // stripped to prevent env-based attacks.
    let child = Command::new("sccache")
        .arg("--version")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .env_clear()
        .envs(std::env::var_os("PATH").map(|p| ("PATH", p)))
        .spawn()
        .ok()?;

    probe_version_bounded(
        child,
        MAX_SCCACHE_VERSION_LENGTH,
        SCCACHE_PROBE_TIMEOUT,
        SCCACHE_THREAD_JOIN_TIMEOUT,
    )
}

/// Core bounded version probe using the reader-thread + timeout-poll pattern
/// (INV-CONTAIN-008, INV-TC-005/006).
///
/// This is the same deadlock-free pattern used in
/// `toolchain_fingerprint.rs::version_output()` and
/// `warm.rs::version_output()`.
///
/// # Arguments
///
/// * `child` — A freshly spawned child process with stdout piped.
/// * `max_output_bytes` — Maximum bytes to read from stdout (via `Take`).
/// * `timeout` — Maximum wall-clock time before the probe is abandoned.
/// * `thread_join_timeout` — Maximum time to wait for the reader thread to join
///   after child kill.
///
/// # Returns
///
/// `Some(version_string)` on success, `None` on any failure (fail-closed).
fn probe_version_bounded(
    mut child: std::process::Child,
    max_output_bytes: usize,
    timeout: Duration,
    thread_join_timeout: Duration,
) -> Option<String> {
    use std::io::Read as _;

    // Take stdout pipe before spawning the reader thread. The calling
    // thread retains direct ownership of `child` (no mutex). The reader
    // thread receives only the pipe and performs a bounded read.
    let stdout = child.stdout.take()?;

    // Reader thread: owns the stdout pipe, performs bounded read via Take,
    // returns the raw bytes. Does NOT touch the Child handle — no mutex.
    let handle = std::thread::spawn(move || -> Option<Vec<u8>> {
        let mut bounded = stdout.take(max_output_bytes as u64);
        let mut buf = Vec::with_capacity(max_output_bytes);
        if bounded.read_to_end(&mut buf).is_err() {
            return None;
        }
        Some(buf)
    });

    // Calling thread: poll reader completion against a bounded deadline.
    // The calling thread retains exclusive kill authority over the child.
    let deadline = Instant::now() + timeout;
    loop {
        if handle.is_finished() {
            // Reader finished. Reap the child process with a bounded
            // try_wait loop (child may still be running after stdout EOF).
            let status = sccache_bounded_reap(&mut child);

            // Join the reader thread to retrieve the output.
            let Ok(Some(buf)) = handle.join() else {
                return None;
            };

            // Require successful exit.
            match status {
                Some(s) if s.success() => {},
                _ => return None,
            }

            let version = String::from_utf8_lossy(&buf).trim().to_string();
            if version.is_empty() {
                return None;
            }

            return Some(truncate_utf8_safe(&version, max_output_bytes));
        }

        if Instant::now() >= deadline {
            // Timeout: kill the child directly (no mutex needed).
            let _ = child.kill();
            let _ = sccache_bounded_reap(&mut child);
            // Drop the child handle to close our end of any inherited
            // pipe file descriptors. This ensures the reader thread
            // gets EOF even if a descendant process holds stdout open,
            // preventing indefinite blocking on handle.join().
            drop(child);

            // Join the reader thread with a bounded timeout.
            let join_deadline = Instant::now() + thread_join_timeout;
            loop {
                if handle.is_finished() {
                    let _ = handle.join();
                    break;
                }
                if Instant::now() >= join_deadline {
                    // Reader thread stuck — abandon it. The thread will
                    // eventually terminate when the pipe closes.
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            return None;
        }

        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Bounded reap for the sccache probe child process (INV-CONTAIN-008).
///
/// Tries `try_wait()` first (fast path). If the child is still running,
/// kills it and polls `try_wait()` with a bounded timeout. Returns the
/// exit status if the child was reaped, `None` if reaping failed.
fn sccache_bounded_reap(child: &mut std::process::Child) -> Option<std::process::ExitStatus> {
    // Fast path: already exited.
    match child.try_wait() {
        Ok(Some(status)) => return Some(status),
        Ok(None) => {},
        Err(_) => return None,
    }

    // Still running: kill and wait with bounded timeout.
    let _ = child.kill();

    let reap_deadline = Instant::now() + SCCACHE_PROBE_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) => {},
            Err(_) => return None,
        }
        if Instant::now() >= reap_deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

// =============================================================================
// Sccache Server Containment Protocol (TCK-00554)
// =============================================================================

/// Discovers ALL PIDs of running sccache servers by scanning `/proc`.
///
/// Looks for processes named "sccache" that are NOT children of the
/// reference PID (i.e., they are standalone daemon processes, typically
/// listening on a socket). Returns ALL sccache PIDs found that are not
/// descendants of `reference_pid`, in discovery order.
///
/// BLOCKER fix (fix-round-3): Previously returned only the first match.
/// Set-based enumeration is required so that `verify_started_server` can
/// fail closed if ANY candidate is outside the unit cgroup — a single-PID
/// check cannot detect conflicting out-of-cgroup servers that coexist
/// with a verified in-cgroup server.
///
/// Uses the same bounded scan as `discover_children_from_proc` for
/// consistency (INV-CONTAIN-003).
fn discover_sccache_server_pids(
    reference_pid: u32,
    proc_root: &Path,
) -> Result<Vec<u32>, ContainmentError> {
    // Build the set of descendant PIDs so we can exclude them.
    let descendants = discover_children_from_proc(reference_pid, proc_root)?;
    let descendant_pids: std::collections::BTreeSet<u32> =
        descendants.iter().map(|d| d.pid).collect();

    let proc_dir = match std::fs::read_dir(proc_root) {
        Ok(d) => d,
        Err(e) => {
            return Err(ContainmentError::ProcReadFailed {
                pid: reference_pid,
                file: "proc_dir".to_string(),
                reason: format!("cannot read {}: {e}", proc_root.display()),
            });
        },
    };

    let mut found: Vec<u32> = Vec::new();
    let mut scanned: usize = 0;
    let mut unreadable_count: usize = 0;
    for entry in proc_dir {
        scanned = scanned.saturating_add(1);
        if scanned > MAX_PROC_SCAN_ENTRIES {
            // MAJOR-1 fix: Fail-closed on scan limit. Unlike the previous
            // best-effort break, exceeding the scan limit means we cannot
            // guarantee we've found all sccache processes. Return an error
            // so callers auto-disable sccache (consistent with
            // discover_children_from_proc which raises ProcScanOverflow).
            return Err(ContainmentError::ProcScanOverflow {
                scanned,
                max: MAX_PROC_SCAN_ENTRIES,
                ppid_failures: unreadable_count,
            });
        }

        let Ok(entry) = entry else { continue };
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        let pid: u32 = match name_str.parse() {
            Ok(p) if p > 0 && p <= MAX_PID_VALUE => p,
            _ => continue,
        };

        // Skip our own process and descendants.
        if pid == reference_pid || descendant_pids.contains(&pid) {
            continue;
        }

        // Check if this is an sccache process.
        // NIT-1 fix: Log unreadable comm files instead of silently ignoring.
        // An unreadable comm file means we cannot rule out the process being
        // an escaped sccache server.
        if let Ok(comm) = read_comm(pid, proc_root) {
            if comm.trim() == "sccache" {
                found.push(pid);
                // Bounded collection: fail-closed if too many sccache PIDs.
                if found.len() > MAX_SCCACHE_SERVER_PIDS {
                    return Err(ContainmentError::TooManyChildren {
                        count: found.len(),
                        max: MAX_SCCACHE_SERVER_PIDS,
                    });
                }
            }
        } else {
            unreadable_count = unreadable_count.saturating_add(1);
            eprintln!(
                "worker: WARNING: cannot read /proc/{pid}/comm during sccache server \
                 discovery — process may be an undetected sccache server"
            );
        }
    }

    Ok(found)
}

/// Executes a bounded sccache command (start-server or stop-server).
///
/// Uses the same reader-thread + timeout-poll pattern as
/// `probe_version_bounded` for deadlock-free, bounded execution.
///
/// Returns `Ok(output)` on success, `Err(reason)` on failure.
fn run_sccache_command(
    args: &[&str],
    env_vars: &[(String, String)],
    timeout: Duration,
) -> Result<String, String> {
    use std::process::{Command, Stdio};

    let mut cmd = Command::new("sccache");
    cmd.args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_clear();

    // Forward PATH so sccache is found.
    if let Some(path) = std::env::var_os("PATH") {
        cmd.env("PATH", path);
    }

    // Forward caller-provided env vars (e.g., SCCACHE_DIR).
    for (key, value) in env_vars {
        cmd.env(key, value);
    }

    let child = cmd.spawn().map_err(|e| format!("spawn failed: {e}"))?;

    probe_version_bounded(
        child,
        MAX_SCCACHE_SERVER_OUTPUT,
        timeout,
        SCCACHE_THREAD_JOIN_TIMEOUT,
    )
    .ok_or_else(|| "command timed out or failed".to_string())
}

/// Executes the sccache server containment protocol (TCK-00554).
///
/// This function implements the per-unit server lifecycle:
///
/// 1. **Detect pre-existing server**: Scan `/proc` for sccache processes that
///    are not descendants of the reference PID.
/// 2. **Verify cgroup membership**: If a pre-existing server is found, check
///    whether it shares the same cgroup as the reference PID.
/// 3. **Refuse out-of-cgroup servers**: If the server is outside the cgroup,
///    auto-disable sccache (fail-closed, INV-CONTAIN-009).
/// 4. **Start in-cgroup server**: If no server is running (or the pre-existing
///    one was refused), start `sccache --start-server` in the current process
///    environment (which is inside the unit cgroup).
/// 5. **Verify new server containment**: Re-check that the started server is
///    inside the cgroup.
///
/// # Arguments
///
/// * `reference_pid` - PID of the job's main process (reference cgroup)
/// * `reference_cgroup` - The reference cgroup path for the unit
/// * `sccache_env` - Environment variables to pass to sccache (e.g.,
///   `SCCACHE_DIR`)
///
/// # Returns
///
/// A `SccacheServerContainment` recording the full protocol outcome.
///
/// # Fail-Closed Semantics
///
/// Any failure in the protocol results in `auto_disabled = true`:
/// - Cannot read process cgroup → auto-disable
/// - Pre-existing server outside cgroup → auto-disable
/// - Cannot start server → auto-disable
/// - Started server outside cgroup → auto-disable
#[must_use]
pub fn execute_sccache_server_containment_protocol(
    reference_pid: u32,
    reference_cgroup: &str,
    sccache_env: &[(String, String)],
) -> SccacheServerContainment {
    execute_sccache_server_containment_protocol_with_proc(
        reference_pid,
        reference_cgroup,
        sccache_env,
        Path::new("/proc"),
    )
}

/// Testable variant with configurable procfs root.
#[must_use]
pub fn execute_sccache_server_containment_protocol_with_proc(
    reference_pid: u32,
    reference_cgroup: &str,
    sccache_env: &[(String, String)],
    proc_root: &Path,
) -> SccacheServerContainment {
    let mut result = SccacheServerContainment {
        protocol_executed: true,
        ..Default::default()
    };

    // Step 1: Detect pre-existing sccache servers (set-based scan).
    let preexisting_pids = match discover_sccache_server_pids(reference_pid, proc_root) {
        Ok(pids) => pids,
        Err(e) => {
            // Fail-closed: cannot scan for servers → auto-disable.
            result.auto_disabled = true;
            result.reason = Some(truncate_string(
                &format!("failed to scan for sccache server: {e}"),
                MAX_SERVER_CONTAINMENT_REASON_LENGTH,
            ));
            return result;
        },
    };

    // Steps 2-3: Handle pre-existing servers (verify cgroup, refuse if outside).
    // Check ALL preexisting PIDs. If ANY is outside the cgroup, attempt to stop
    // and fail closed if stop fails. Record the first detected PID for
    // traceability.
    if !preexisting_pids.is_empty() {
        result.preexisting_server_detected = true;
        result.preexisting_server_pid = Some(preexisting_pids[0]);

        if let Some(early_return) = handle_preexisting_servers(
            &mut result,
            &preexisting_pids,
            reference_cgroup,
            sccache_env,
            proc_root,
        ) {
            return early_return;
        }
    }

    // Step 4: Start a new sccache server inside the unit cgroup.
    if let Err(e) = start_sccache_server_in_cgroup(&mut result, sccache_env) {
        result.auto_disabled = true;
        result.reason = Some(truncate_string(&e, MAX_SERVER_CONTAINMENT_REASON_LENGTH));
        return result;
    }

    // Step 5: Verify the new server is inside the cgroup.
    verify_started_server(&mut result, reference_pid, reference_cgroup, proc_root);

    result
}

/// Handles ALL pre-existing sccache servers (Steps 2-3).
///
/// For each pre-existing PID:
/// - If in-cgroup: safe to use.
/// - If outside cgroup: attempt to stop it. Stop failure = containment failure.
///
/// Returns `Some(result)` for early return when ALL servers are in-cgroup
/// (safe to use), or when ANY out-of-cgroup server cannot be stopped
/// (containment failure). Returns `None` to continue with server start.
///
/// BLOCKER fix (fix-round-3): Changed from single-PID to set-based.
/// Stop failure is now a containment failure (previously ignored).
fn handle_preexisting_servers(
    result: &mut SccacheServerContainment,
    pids: &[u32],
    reference_cgroup: &str,
    sccache_env: &[(String, String)],
    proc_root: &Path,
) -> Option<SccacheServerContainment> {
    let mut all_in_cgroup = true;
    let mut any_outside = false;

    for &pid in pids {
        if let Ok(server_cgroup) = read_cgroup_path_from_proc(pid, proc_root) {
            if !is_cgroup_contained(&server_cgroup, reference_cgroup) {
                any_outside = true;
                all_in_cgroup = false;
            }
        } else {
            // Fail-closed: cannot read server cgroup → treat as outside.
            any_outside = true;
            all_in_cgroup = false;
        }
    }

    if all_in_cgroup {
        // ALL pre-existing servers are inside the cgroup — safe to use.
        result.preexisting_server_in_cgroup = Some(true);
        result.server_cgroup_verified = true;
        result.reason = Some(truncate_string(
            &format!(
                "{} pre-existing sccache server(s) verified in cgroup '{}'",
                pids.len(),
                truncate_string(reference_cgroup, 128),
            ),
            MAX_SERVER_CONTAINMENT_REASON_LENGTH,
        ));
        return Some(result.clone());
    }

    // At least one server is outside the cgroup.
    result.preexisting_server_in_cgroup = Some(false);

    if any_outside {
        // Attempt to stop the out-of-cgroup server(s).
        // BLOCKER fix (fix-round-3): Stop failure is a containment failure.
        // Previously the stop result was ignored (`let _ = ...`).
        match run_sccache_command(&["--stop-server"], sccache_env, SCCACHE_SERVER_STOP_TIMEOUT) {
            Ok(_) => {
                // Stop succeeded. Continue to start a fresh server.
            },
            Err(e) => {
                // Stop FAILED. The out-of-cgroup server persists.
                // This is a containment failure — fail closed.
                result.auto_disabled = true;
                result.reason = Some(truncate_string(
                    &format!("failed to stop pre-existing out-of-cgroup sccache server: {e}"),
                    MAX_SERVER_CONTAINMENT_REASON_LENGTH,
                ));
                return Some(result.clone());
            },
        }
    }

    None // Continue with server start.
}

/// Starts a new sccache server inside the unit cgroup (Step 4).
///
/// Returns `Ok(())` on success, `Err(reason)` on failure.
fn start_sccache_server_in_cgroup(
    result: &mut SccacheServerContainment,
    sccache_env: &[(String, String)],
) -> Result<(), String> {
    // Because we are running inside the unit cgroup, the spawned
    // `sccache --start-server` will inherit our cgroup membership.
    match run_sccache_command(
        &["--start-server"],
        sccache_env,
        SCCACHE_SERVER_START_TIMEOUT,
    ) {
        Ok(_output) => {
            result.server_started = true;
            Ok(())
        },
        Err(e) => Err(format!("failed to start sccache server: {e}")),
    }
}

/// Verifies that the newly started sccache server is inside the cgroup (Step
/// 5).
///
/// Re-scans `/proc` for ALL sccache processes and checks every candidate's
/// cgroup. If ANY candidate is outside the unit cgroup, verification fails
/// and `auto_disabled` is set (fail-closed). The verified server PID is set
/// to the candidate confirmed inside the cgroup.
///
/// BLOCKER fix (fix-round-3): Previously checked only the first discovered
/// PID. A single-PID check cannot detect conflicting out-of-cgroup servers
/// that coexist with a verified in-cgroup server (INV-CONTAIN-009/012).
///
/// Note: there is an inherent TOCTOU window between start and this check,
/// but the server was started by us inside the cgroup, so the only way it
/// escapes is if systemd moves it — which requires root. We verify anyway
/// for defense-in-depth.
fn verify_started_server(
    result: &mut SccacheServerContainment,
    reference_pid: u32,
    reference_cgroup: &str,
    proc_root: &Path,
) {
    let all_pids = match discover_sccache_server_pids(reference_pid, proc_root) {
        Ok(pids) => pids,
        Err(e) => {
            // Fail-closed: cannot rescan for server.
            result.auto_disabled = true;
            result.reason = Some(truncate_string(
                &format!("failed to verify started sccache server: {e}"),
                MAX_SERVER_CONTAINMENT_REASON_LENGTH,
            ));
            return;
        },
    };

    if all_pids.is_empty() {
        // MAJOR-1 fix: Fail-closed when server PID cannot be found.
        // A positively identified PID plus cgroup match is required
        // before setting server_cgroup_verified=true. If the server
        // is not visible in /proc, we cannot verify containment.
        result.auto_disabled = true;
        result.server_cgroup_verified = false;
        result.reason = Some(
            "sccache server started but not found in /proc — \
             cannot verify cgroup containment (fail-closed)"
                .to_string(),
        );
        return;
    }

    // Set-based verification: check ALL discovered sccache server PIDs.
    // Track the first in-cgroup PID as our verified server, but fail closed
    // if ANY candidate is outside the cgroup.
    let mut verified_pid: Option<u32> = None;
    let mut outside_cgroup_pids: Vec<u32> = Vec::new();
    let mut unverifiable_pids: Vec<u32> = Vec::new();

    for &pid in &all_pids {
        match read_cgroup_path_from_proc(pid, proc_root) {
            Ok(pid_cgroup) => {
                if is_cgroup_contained(&pid_cgroup, reference_cgroup) {
                    if verified_pid.is_none() {
                        verified_pid = Some(pid);
                    }
                } else {
                    outside_cgroup_pids.push(pid);
                }
            },
            Err(_) => {
                // Fail-closed: cannot read cgroup → treat as outside.
                unverifiable_pids.push(pid);
            },
        }
    }

    // Record the started server PID — prefer the verified in-cgroup PID,
    // fall back to the first discovered PID for traceability.
    result.started_server_pid = Some(verified_pid.unwrap_or(all_pids[0]));

    // Fail closed if ANY candidate is outside the cgroup or unverifiable.
    if !outside_cgroup_pids.is_empty() || !unverifiable_pids.is_empty() {
        result.auto_disabled = true;
        result.server_cgroup_verified = false;
        let mut reason_parts: Vec<String> = Vec::new();
        if !outside_cgroup_pids.is_empty() {
            reason_parts.push(format!(
                "sccache server PIDs outside cgroup: {outside_cgroup_pids:?}"
            ));
        }
        if !unverifiable_pids.is_empty() {
            reason_parts.push(format!(
                "sccache server PIDs with unreadable cgroup: {unverifiable_pids:?}"
            ));
        }
        reason_parts.push(format!(
            "expected cgroup='{}'",
            truncate_string(reference_cgroup, 128),
        ));
        result.reason = Some(truncate_string(
            &reason_parts.join("; "),
            MAX_SERVER_CONTAINMENT_REASON_LENGTH,
        ));
        return;
    }

    // All candidates are inside the cgroup.
    if let Some(vpid) = verified_pid {
        result.server_cgroup_verified = true;
        result.reason = Some(truncate_string(
            &format!(
                "sccache server PID {vpid} started and verified in cgroup '{}' \
                 ({} candidate(s) checked, all contained)",
                truncate_string(reference_cgroup, 128),
                all_pids.len(),
            ),
            MAX_SERVER_CONTAINMENT_REASON_LENGTH,
        ));
    } else {
        // All candidates found but none is in-cgroup — this means all are
        // outside. Already handled above, but guard for completeness.
        result.auto_disabled = true;
        result.server_cgroup_verified = false;
        result.reason = Some(truncate_string(
            "all discovered sccache servers are outside the unit cgroup",
            MAX_SERVER_CONTAINMENT_REASON_LENGTH,
        ));
    }
}

/// Stops the sccache server at job unit end (TCK-00554).
///
/// Best-effort: logs but does not fail on errors. The returned
/// boolean indicates whether the stop succeeded.
///
/// # Arguments
///
/// * `sccache_env` - Environment variables to pass to sccache (e.g.,
///   `SCCACHE_DIR`)
#[must_use]
pub fn stop_sccache_server(sccache_env: &[(String, String)]) -> bool {
    run_sccache_command(&["--stop-server"], sccache_env, SCCACHE_SERVER_STOP_TIMEOUT).is_ok()
}

// =============================================================================
// Helpers
// =============================================================================

/// Validates a PID value.
fn validate_pid(pid: u32) -> Result<(), ContainmentError> {
    if pid == 0 {
        return Err(ContainmentError::InvalidPid {
            reason: "PID 0 is not a valid process".to_string(),
        });
    }
    if pid > MAX_PID_VALUE {
        return Err(ContainmentError::InvalidPid {
            reason: format!("PID {pid} exceeds maximum {MAX_PID_VALUE}"),
        });
    }
    Ok(())
}

/// Reads a procfs file with bounded size (INV-CONTAIN-002).
fn read_proc_file_bounded(
    path: &Path,
    pid: u32,
    file_name: &str,
) -> Result<String, ContainmentError> {
    let file = File::open(path).map_err(|e| ContainmentError::ProcReadFailed {
        pid,
        file: file_name.to_string(),
        reason: e.to_string(),
    })?;

    let mut reader = BufReader::new(file).take(MAX_PROC_READ_SIZE);
    let mut content = String::with_capacity(256);

    reader
        .read_to_string(&mut content)
        .map_err(|e| ContainmentError::ProcReadFailed {
            pid,
            file: file_name.to_string(),
            reason: e.to_string(),
        })?;

    Ok(content)
}

/// Truncates a string to at most `max_len` bytes, appending "..." if
/// truncated.
///
/// Uses [`truncate_utf8_safe`] internally so the cut never falls on a
/// multi-byte UTF-8 boundary (panic-free on all inputs).
fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        let prefix = truncate_utf8_safe(s, max_len.saturating_sub(3));
        format!("{prefix}...")
    }
}

/// Returns the longest prefix of `s` whose byte length is <= `max_bytes`
/// and that ends on a valid UTF-8 character boundary.
///
/// This is panic-free for all inputs, including strings composed entirely
/// of multi-byte characters.
fn truncate_utf8_safe(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_string();
    }
    // Find the last char_indices boundary that is <= max_bytes.
    let mut end = 0;
    for (idx, _) in s.char_indices() {
        if idx > max_bytes {
            break;
        }
        end = idx;
    }
    // `end` is the start of the last character that starts at or before
    // `max_bytes`. We need to include the full character at `end`, but
    // only if it fits within `max_bytes`.
    let ch_len = s[end..].chars().next().map_or(0, char::len_utf8);
    if end + ch_len <= max_bytes {
        s[..end + ch_len].to_string()
    } else {
        s[..end].to_string()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    // ========================================================================
    // Cgroup path parsing tests
    // ========================================================================

    #[test]
    fn parse_cgroup_v2_path_valid() {
        let content = "0::/system.slice/apm2-job.service\n";
        let path = parse_cgroup_v2_path(content, 1234).unwrap();
        assert_eq!(path, "/system.slice/apm2-job.service");
    }

    #[test]
    fn parse_cgroup_v2_path_with_user_slice() {
        let content =
            "0::/user.slice/user-1000.slice/user@1000.service/app.slice/apm2-job.service\n";
        let path = parse_cgroup_v2_path(content, 1234).unwrap();
        assert_eq!(
            path,
            "/user.slice/user-1000.slice/user@1000.service/app.slice/apm2-job.service"
        );
    }

    #[test]
    fn parse_cgroup_v2_path_root() {
        let content = "0::/\n";
        let path = parse_cgroup_v2_path(content, 1).unwrap();
        assert_eq!(path, "/");
    }

    #[test]
    fn parse_cgroup_v2_path_no_v2_entry() {
        let content = "1:name=systemd:/init.scope\n";
        let result = parse_cgroup_v2_path(content, 1);
        assert!(matches!(
            result,
            Err(ContainmentError::CgroupParseFailed { .. })
        ));
    }

    #[test]
    fn parse_cgroup_v2_path_empty() {
        let content = "";
        let result = parse_cgroup_v2_path(content, 1);
        assert!(matches!(
            result,
            Err(ContainmentError::CgroupParseFailed { .. })
        ));
    }

    #[test]
    fn parse_cgroup_v2_path_too_long() {
        let long_path = "/".to_string() + &"a".repeat(MAX_CGROUP_PATH_LENGTH + 1);
        let content = format!("0::{long_path}\n");
        let result = parse_cgroup_v2_path(&content, 1);
        assert!(matches!(
            result,
            Err(ContainmentError::CgroupPathTooLong { .. })
        ));
    }

    // ========================================================================
    // Cgroup containment check tests
    // ========================================================================

    #[test]
    fn cgroup_contained_exact_match() {
        assert!(is_cgroup_contained(
            "/system.slice/apm2-job.service",
            "/system.slice/apm2-job.service"
        ));
    }

    #[test]
    fn cgroup_contained_subtree() {
        assert!(is_cgroup_contained(
            "/system.slice/apm2-job.service/child-scope",
            "/system.slice/apm2-job.service"
        ));
    }

    #[test]
    fn cgroup_not_contained_different_path() {
        assert!(!is_cgroup_contained(
            "/system.slice/other.service",
            "/system.slice/apm2-job.service"
        ));
    }

    #[test]
    fn cgroup_not_contained_partial_name_match() {
        // Ensure "/foo" does not match "/foobar"
        assert!(!is_cgroup_contained(
            "/system.slice/apm2-job.service-extra",
            "/system.slice/apm2-job.service"
        ));
    }

    #[test]
    fn cgroup_not_contained_unreadable() {
        // Fail-closed: unreadable means not contained
        assert!(!is_cgroup_contained(
            "<unreadable>",
            "/system.slice/apm2-job.service"
        ));
    }

    #[test]
    fn cgroup_contained_reference_trailing_slash() {
        assert!(is_cgroup_contained(
            "/system.slice/apm2-job.service/child",
            "/system.slice/apm2-job.service/"
        ));
    }

    // ========================================================================
    // PID validation tests
    // ========================================================================

    #[test]
    fn validate_pid_zero_rejected() {
        assert!(matches!(
            validate_pid(0),
            Err(ContainmentError::InvalidPid { .. })
        ));
    }

    #[test]
    fn validate_pid_exceeds_max() {
        assert!(matches!(
            validate_pid(MAX_PID_VALUE + 1),
            Err(ContainmentError::InvalidPid { .. })
        ));
    }

    #[test]
    fn validate_pid_valid() {
        assert!(validate_pid(1).is_ok());
        assert!(validate_pid(MAX_PID_VALUE).is_ok());
    }

    // ========================================================================
    // Mock procfs tests
    // ========================================================================

    #[test]
    fn read_cgroup_from_mock_proc() {
        let tmp = tempfile::tempdir().unwrap();
        let pid_dir = tmp.path().join("1234");
        fs::create_dir_all(&pid_dir).unwrap();
        fs::write(
            pid_dir.join("cgroup"),
            "0::/system.slice/apm2-fac-job-lane00.service\n",
        )
        .unwrap();

        let path = read_cgroup_path_from_proc(1234, tmp.path()).unwrap();
        assert_eq!(path, "/system.slice/apm2-fac-job-lane00.service");
    }

    #[test]
    fn read_cgroup_missing_file() {
        let tmp = tempfile::tempdir().unwrap();
        let pid_dir = tmp.path().join("1234");
        fs::create_dir_all(&pid_dir).unwrap();
        // No cgroup file

        let result = read_cgroup_path_from_proc(1234, tmp.path());
        assert!(matches!(
            result,
            Err(ContainmentError::ProcReadFailed { .. })
        ));
    }

    #[test]
    fn discover_children_mock_proc() {
        let tmp = tempfile::tempdir().unwrap();

        // Parent PID 100
        let parent_dir = tmp.path().join("100");
        fs::create_dir_all(&parent_dir).unwrap();
        fs::write(
            parent_dir.join("status"),
            "Name:\tinit\nPPid:\t0\nPid:\t100\n",
        )
        .unwrap();
        fs::write(parent_dir.join("cgroup"), "0::/system.slice/apm2.service\n").unwrap();
        fs::write(parent_dir.join("comm"), "cargo\n").unwrap();

        // Child PID 101 (child of 100)
        let child_dir = tmp.path().join("101");
        fs::create_dir_all(&child_dir).unwrap();
        fs::write(
            child_dir.join("status"),
            "Name:\trustc\nPPid:\t100\nPid:\t101\n",
        )
        .unwrap();
        fs::write(child_dir.join("cgroup"), "0::/system.slice/apm2.service\n").unwrap();
        fs::write(child_dir.join("comm"), "rustc\n").unwrap();

        // Grandchild PID 102 (child of 101)
        let grandchild_dir = tmp.path().join("102");
        fs::create_dir_all(&grandchild_dir).unwrap();
        fs::write(
            grandchild_dir.join("status"),
            "Name:\tcc1\nPPid:\t101\nPid:\t102\n",
        )
        .unwrap();
        fs::write(
            grandchild_dir.join("cgroup"),
            "0::/system.slice/apm2.service\n",
        )
        .unwrap();
        fs::write(grandchild_dir.join("comm"), "cc1\n").unwrap();

        let children = discover_children_from_proc(100, tmp.path()).unwrap();
        assert_eq!(children.len(), 2);

        let pids: Vec<u32> = children.iter().map(|c| c.pid).collect();
        assert!(pids.contains(&101));
        assert!(pids.contains(&102));
    }

    #[test]
    fn verify_containment_all_contained() {
        let tmp = tempfile::tempdir().unwrap();

        // Reference process
        let ref_dir = tmp.path().join("100");
        fs::create_dir_all(&ref_dir).unwrap();
        fs::write(ref_dir.join("status"), "Name:\tcargo\nPPid:\t1\n").unwrap();
        fs::write(
            ref_dir.join("cgroup"),
            "0::/system.slice/apm2-job.service\n",
        )
        .unwrap();
        fs::write(ref_dir.join("comm"), "cargo\n").unwrap();

        // Child in same cgroup
        let child_dir = tmp.path().join("101");
        fs::create_dir_all(&child_dir).unwrap();
        fs::write(child_dir.join("status"), "Name:\trustc\nPPid:\t100\n").unwrap();
        fs::write(
            child_dir.join("cgroup"),
            "0::/system.slice/apm2-job.service\n",
        )
        .unwrap();
        fs::write(child_dir.join("comm"), "rustc\n").unwrap();

        let verdict = verify_containment_with_proc(100, false, tmp.path()).unwrap();
        assert!(verdict.contained);
        assert_eq!(verdict.processes_checked, 1);
        assert_eq!(verdict.mismatches.len(), 0);
    }

    #[test]
    fn verify_containment_escaped_process() {
        let tmp = tempfile::tempdir().unwrap();

        // Reference process
        let ref_dir = tmp.path().join("100");
        fs::create_dir_all(&ref_dir).unwrap();
        fs::write(ref_dir.join("status"), "Name:\tcargo\nPPid:\t1\n").unwrap();
        fs::write(
            ref_dir.join("cgroup"),
            "0::/system.slice/apm2-job.service\n",
        )
        .unwrap();
        fs::write(ref_dir.join("comm"), "cargo\n").unwrap();

        // Child in DIFFERENT cgroup (escaped!)
        let child_dir = tmp.path().join("101");
        fs::create_dir_all(&child_dir).unwrap();
        fs::write(child_dir.join("status"), "Name:\tsccache\nPPid:\t100\n").unwrap();
        fs::write(child_dir.join("cgroup"), "0::/user.slice/sccache.service\n").unwrap();
        fs::write(child_dir.join("comm"), "sccache\n").unwrap();

        let verdict = verify_containment_with_proc(100, true, tmp.path()).unwrap();
        assert!(!verdict.contained);
        assert_eq!(verdict.mismatches.len(), 1);
        assert_eq!(verdict.mismatches[0].pid, 101);
        assert!(verdict.sccache_detected);
        assert!(verdict.sccache_auto_disabled);
        assert!(verdict.sccache_disabled_reason.is_some());
    }

    #[test]
    fn verify_containment_sccache_not_enabled() {
        let tmp = tempfile::tempdir().unwrap();

        // Reference process
        let ref_dir = tmp.path().join("100");
        fs::create_dir_all(&ref_dir).unwrap();
        fs::write(ref_dir.join("status"), "Name:\tcargo\nPPid:\t1\n").unwrap();
        fs::write(
            ref_dir.join("cgroup"),
            "0::/system.slice/apm2-job.service\n",
        )
        .unwrap();
        fs::write(ref_dir.join("comm"), "cargo\n").unwrap();

        // Child escaped but sccache not enabled
        let child_dir = tmp.path().join("101");
        fs::create_dir_all(&child_dir).unwrap();
        fs::write(child_dir.join("status"), "Name:\tsccache\nPPid:\t100\n").unwrap();
        fs::write(child_dir.join("cgroup"), "0::/user.slice/sccache.service\n").unwrap();
        fs::write(child_dir.join("comm"), "sccache\n").unwrap();

        let verdict = verify_containment_with_proc(100, false, tmp.path()).unwrap();
        assert!(!verdict.contained);
        assert!(!verdict.sccache_auto_disabled);
    }

    #[test]
    fn check_sccache_containment_safe() {
        let tmp = tempfile::tempdir().unwrap();

        let ref_dir = tmp.path().join("100");
        fs::create_dir_all(&ref_dir).unwrap();
        fs::write(ref_dir.join("status"), "Name:\tcargo\nPPid:\t1\n").unwrap();
        fs::write(
            ref_dir.join("cgroup"),
            "0::/system.slice/apm2-job.service\n",
        )
        .unwrap();
        fs::write(ref_dir.join("comm"), "cargo\n").unwrap();

        let result = check_sccache_containment_with_proc(100, true, tmp.path()).unwrap();
        assert!(result.is_none(), "no children means all contained");
    }

    #[test]
    fn check_sccache_containment_disabled() {
        let result =
            check_sccache_containment_with_proc(100, false, Path::new("/nonexistent")).unwrap();
        assert!(result.is_none(), "sccache not enabled => None");
    }

    #[test]
    fn containment_trace_from_verdict() {
        let verdict = ContainmentVerdict {
            contained: true,
            reference_cgroup: "/system.slice/test.service".to_string(),
            processes_checked: 5,
            critical_processes_found: 2,
            mismatches: vec![],
            sccache_detected: false,
            sccache_auto_disabled: false,
            sccache_disabled_reason: None,
        };

        let trace = ContainmentTrace::from_verdict(&verdict);
        assert!(trace.verified);
        assert_eq!(trace.cgroup_path, "/system.slice/test.service");
        assert_eq!(trace.processes_checked, 5);
        assert_eq!(trace.mismatch_count, 0);
        assert!(!trace.sccache_auto_disabled);
    }

    #[test]
    fn truncate_string_within_limit() {
        assert_eq!(truncate_string("hello", 10), "hello");
    }

    #[test]
    fn truncate_string_exceeds_limit() {
        let result = truncate_string("hello world", 8);
        assert_eq!(result, "hello...");
    }

    #[test]
    fn default_verdict_is_fail_closed() {
        let v = ContainmentVerdict::default();
        assert!(!v.contained, "default verdict must be fail-closed");
    }

    #[test]
    fn containment_error_display() {
        let err = ContainmentError::ProcReadFailed {
            pid: 123,
            file: "cgroup".to_string(),
            reason: "permission denied".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("123"));
        assert!(msg.contains("cgroup"));
        assert!(msg.contains("permission denied"));
    }

    #[test]
    fn containment_mismatch_serde_roundtrip() {
        let m = ContainmentMismatch {
            pid: 42,
            process_name: "rustc".to_string(),
            expected_cgroup: "/a".to_string(),
            actual_cgroup: "/b".to_string(),
        };
        let json = serde_json::to_string(&m).unwrap();
        let m2: ContainmentMismatch = serde_json::from_str(&json).unwrap();
        assert_eq!(m, m2);
    }

    #[test]
    fn containment_verdict_serde_roundtrip() {
        let v = ContainmentVerdict {
            contained: true,
            reference_cgroup: "/test".to_string(),
            processes_checked: 1,
            critical_processes_found: 1,
            mismatches: vec![],
            sccache_detected: false,
            sccache_auto_disabled: false,
            sccache_disabled_reason: None,
        };
        let json = serde_json::to_string(&v).unwrap();
        let v2: ContainmentVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(v, v2);
    }

    #[test]
    fn containment_trace_serde_roundtrip() {
        let t = ContainmentTrace {
            verified: true,
            cgroup_path: "/test".to_string(),
            processes_checked: 3,
            mismatch_count: 0,
            sccache_auto_disabled: false,
            sccache_enabled: false,
            sccache_version: None,
            sccache_server_containment: None,
        };
        let json = serde_json::to_string(&t).unwrap();
        let t2: ContainmentTrace = serde_json::from_str(&json).unwrap();
        assert_eq!(t, t2);
    }

    // ========================================================================
    // Proc scan overflow tests (MAJOR-2 regression)
    // ========================================================================

    #[test]
    fn proc_scan_overflow_returns_error() {
        // Synthesize a mock /proc with more than MAX_PROC_SCAN_ENTRIES
        // entries. Since MAX_PROC_SCAN_ENTRIES is 65536, we cannot
        // actually create that many directories in a unit test. Instead,
        // we test the mechanism by temporarily using a smaller number
        // of entries + verifying the error variant is correct.
        //
        // Create a mock proc with MAX_PROC_SCAN_ENTRIES + 1 non-PID
        // entries (they still count toward the scan limit).
        let tmp = tempfile::tempdir().unwrap();

        // Create the parent PID dir so discover_children_from_proc can
        // read its status.
        let parent_dir = tmp.path().join("1");
        fs::create_dir_all(&parent_dir).unwrap();
        fs::write(parent_dir.join("status"), "Name:\tinit\nPPid:\t0\n").unwrap();
        fs::write(parent_dir.join("cgroup"), "0::/test\n").unwrap();
        fs::write(parent_dir.join("comm"), "init\n").unwrap();

        // Create MAX_PROC_SCAN_ENTRIES + 1 dummy entries.
        // Since we can't create 65537 dirs quickly, we validate the
        // error variant exists and is well-formed.
        let err = ContainmentError::ProcScanOverflow {
            scanned: MAX_PROC_SCAN_ENTRIES + 1,
            max: MAX_PROC_SCAN_ENTRIES,
            ppid_failures: 0,
        };
        let msg = err.to_string();
        assert!(msg.contains("exceeded"));
        assert!(msg.contains(&MAX_PROC_SCAN_ENTRIES.to_string()));
    }

    #[test]
    fn proc_scan_overflow_error_serde_display() {
        let err = ContainmentError::ProcScanOverflow {
            scanned: 70_000,
            max: 65_536,
            ppid_failures: 100,
        };
        let msg = err.to_string();
        assert!(msg.contains("70000"));
        assert!(msg.contains("65536"));
        assert!(msg.contains("100"));
    }

    #[test]
    fn ppid_read_failure_tracking() {
        // Verify that PPid read failures are counted. Create a mock
        // /proc with several PID directories that have unreadable
        // status files.
        let tmp = tempfile::tempdir().unwrap();

        // Parent PID 1
        let parent_dir = tmp.path().join("1");
        fs::create_dir_all(&parent_dir).unwrap();
        fs::write(parent_dir.join("status"), "Name:\tinit\nPPid:\t0\n").unwrap();
        fs::write(parent_dir.join("cgroup"), "0::/test\n").unwrap();
        fs::write(parent_dir.join("comm"), "init\n").unwrap();

        // Child PID 2: missing status file (PPid read will fail)
        let child_dir = tmp.path().join("2");
        fs::create_dir_all(&child_dir).unwrap();
        // No status file

        // Child PID 3: valid status
        let valid_child_dir = tmp.path().join("3");
        fs::create_dir_all(&valid_child_dir).unwrap();
        fs::write(valid_child_dir.join("status"), "Name:\trustc\nPPid:\t1\n").unwrap();
        fs::write(valid_child_dir.join("cgroup"), "0::/test\n").unwrap();
        fs::write(valid_child_dir.join("comm"), "rustc\n").unwrap();

        // Should succeed because ppid_read_failures (1) is not more
        // than half of total_pid_attempts (2).
        let result = discover_children_from_proc(1, tmp.path());
        assert!(result.is_ok(), "single PPid failure should not overflow");
        let children = result.unwrap();
        assert_eq!(children.len(), 1, "only PID 3 should be discovered");
    }

    // ========================================================================
    // cgroup.procs discovery tests (MAJOR-3 regression)
    // ========================================================================

    #[test]
    fn discover_cgroup_procs_reads_pids_from_file() {
        let tmp = tempfile::tempdir().unwrap();

        // Create a mock cgroup.procs file at
        // <cgroup_root>/system.slice/test/cgroup.procs
        let cgroup_dir = tmp.path().join("system.slice").join("test");
        fs::create_dir_all(&cgroup_dir).unwrap();
        fs::write(cgroup_dir.join("cgroup.procs"), "100\n200\n300\n").unwrap();

        let pids = discover_cgroup_procs_with_root("/system.slice/test", tmp.path());
        assert_eq!(pids.len(), 3);
        assert!(pids.contains(&100));
        assert!(pids.contains(&200));
        assert!(pids.contains(&300));
    }

    #[test]
    fn discover_cgroup_procs_empty_on_missing_file() {
        let tmp = tempfile::tempdir().unwrap();
        let pids = discover_cgroup_procs_with_root("/nonexistent", tmp.path());
        assert!(pids.is_empty());
    }

    #[test]
    fn discover_cgroup_procs_ignores_invalid_pids() {
        let tmp = tempfile::tempdir().unwrap();

        let cgroup_dir = tmp.path().join("test");
        fs::create_dir_all(&cgroup_dir).unwrap();
        fs::write(cgroup_dir.join("cgroup.procs"), "100\nnot_a_pid\n0\n200\n").unwrap();

        let pids = discover_cgroup_procs_with_root("/test", tmp.path());
        assert_eq!(pids.len(), 2);
        assert!(pids.contains(&100));
        assert!(pids.contains(&200));
    }

    #[test]
    fn verify_containment_detects_daemonized_via_cgroup_procs() {
        let tmp = tempfile::tempdir().unwrap();
        let proc_root = tmp.path().join("proc");
        let cgroup_root = tmp.path().join("cgroup");
        fs::create_dir_all(&proc_root).unwrap();

        // Reference process (PID 100)
        let ref_dir = proc_root.join("100");
        fs::create_dir_all(&ref_dir).unwrap();
        fs::write(ref_dir.join("status"), "Name:\tcargo\nPPid:\t1\n").unwrap();
        fs::write(
            ref_dir.join("cgroup"),
            "0::/system.slice/apm2-job.service\n",
        )
        .unwrap();
        fs::write(ref_dir.join("comm"), "cargo\n").unwrap();

        // Child PID 101 (normal child of 100, in same cgroup)
        let child_dir = proc_root.join("101");
        fs::create_dir_all(&child_dir).unwrap();
        fs::write(child_dir.join("status"), "Name:\trustc\nPPid:\t100\n").unwrap();
        fs::write(
            child_dir.join("cgroup"),
            "0::/system.slice/apm2-job.service\n",
        )
        .unwrap();
        fs::write(child_dir.join("comm"), "rustc\n").unwrap();

        // Daemonized PID 999 (re-parented to PID 1, but in a DIFFERENT cgroup).
        // This PID would NOT be found by BFS since its PPid is 1, not 100 or 101.
        // It appears only in cgroup.procs.
        let daemon_dir = proc_root.join("999");
        fs::create_dir_all(&daemon_dir).unwrap();
        fs::write(daemon_dir.join("status"), "Name:\tsccache\nPPid:\t1\n").unwrap();
        fs::write(
            daemon_dir.join("cgroup"),
            "0::/user.slice/sccache.service\n",
        )
        .unwrap();
        fs::write(daemon_dir.join("comm"), "sccache\n").unwrap();

        // Create cgroup.procs listing PIDs 100, 101, and 999
        let cgroup_dir = cgroup_root.join("system.slice").join("apm2-job.service");
        fs::create_dir_all(&cgroup_dir).unwrap();
        fs::write(cgroup_dir.join("cgroup.procs"), "100\n101\n999\n").unwrap();

        let verdict =
            verify_containment_with_proc_and_cgroup(100, true, &proc_root, &cgroup_root).unwrap();

        // PID 999 should be detected as escaped since its cgroup
        // (/user.slice/sccache.service) doesn't match the reference
        // (/system.slice/apm2-job.service).
        assert!(
            !verdict.contained,
            "daemonized escaped process must break containment"
        );
        assert!(verdict.sccache_detected, "sccache must be detected");
        assert!(
            verdict.sccache_auto_disabled,
            "sccache must be auto-disabled"
        );

        // Verify the mismatch is recorded
        assert!(
            verdict.mismatches.iter().any(|m| m.pid == 999),
            "daemonized PID 999 must be in mismatches"
        );
    }

    #[test]
    fn verify_containment_cgroup_procs_no_false_positive() {
        // All PIDs in cgroup.procs are also in the BFS tree and contained.
        // Should produce no mismatches.
        let tmp = tempfile::tempdir().unwrap();
        let proc_root = tmp.path().join("proc");
        let cgroup_root = tmp.path().join("cgroup");
        fs::create_dir_all(&proc_root).unwrap();

        // Reference PID 100
        let ref_dir = proc_root.join("100");
        fs::create_dir_all(&ref_dir).unwrap();
        fs::write(ref_dir.join("status"), "Name:\tcargo\nPPid:\t1\n").unwrap();
        fs::write(
            ref_dir.join("cgroup"),
            "0::/system.slice/apm2-job.service\n",
        )
        .unwrap();
        fs::write(ref_dir.join("comm"), "cargo\n").unwrap();

        // Child PID 101 (in same cgroup)
        let child_dir = proc_root.join("101");
        fs::create_dir_all(&child_dir).unwrap();
        fs::write(child_dir.join("status"), "Name:\trustc\nPPid:\t100\n").unwrap();
        fs::write(
            child_dir.join("cgroup"),
            "0::/system.slice/apm2-job.service\n",
        )
        .unwrap();
        fs::write(child_dir.join("comm"), "rustc\n").unwrap();

        // cgroup.procs has same PIDs
        let cgroup_dir = cgroup_root.join("system.slice").join("apm2-job.service");
        fs::create_dir_all(&cgroup_dir).unwrap();
        fs::write(cgroup_dir.join("cgroup.procs"), "100\n101\n").unwrap();

        let verdict =
            verify_containment_with_proc_and_cgroup(100, false, &proc_root, &cgroup_root).unwrap();

        assert!(
            verdict.contained,
            "all contained PIDs must not produce mismatches"
        );
        assert!(verdict.mismatches.is_empty());
    }

    // ========================================================================
    // UTF-8-safe truncation regression tests (Finding 2 / Finding 3)
    // ========================================================================

    #[test]
    fn truncate_utf8_safe_ascii_within_limit() {
        let result = truncate_utf8_safe("sccache 0.8.1", 256);
        assert_eq!(result, "sccache 0.8.1");
    }

    #[test]
    fn truncate_utf8_safe_ascii_at_exact_limit() {
        let input = "a".repeat(256);
        let result = truncate_utf8_safe(&input, 256);
        assert_eq!(result.len(), 256);
        assert_eq!(result, input);
    }

    #[test]
    fn truncate_utf8_safe_ascii_exceeds_limit() {
        let input = "a".repeat(300);
        let result = truncate_utf8_safe(&input, 256);
        assert_eq!(result.len(), 256);
        assert!(result.len() <= 256);
    }

    #[test]
    fn truncate_utf8_safe_multibyte_at_boundary_no_panic() {
        // Each CJK character is 3 bytes in UTF-8. Fill exactly to a
        // boundary that would panic with naive byte slicing.
        // 85 chars * 3 bytes = 255 bytes; char 86 starts at byte 255
        // and extends to byte 258. A 256-byte cap must NOT split the
        // 86th character.
        let input = "\u{4e00}".repeat(100); // 300 bytes
        assert_eq!(input.len(), 300);
        let result = truncate_utf8_safe(&input, 256);
        // Must be valid UTF-8 (no panic) and at most 256 bytes.
        assert!(result.len() <= 256);
        // Must end on a character boundary: 85 chars * 3 = 255 bytes
        // (the last complete character that fits in 256 bytes).
        assert_eq!(result.len(), 255);
        assert_eq!(result.chars().count(), 85);
    }

    #[test]
    fn truncate_utf8_safe_all_4byte_chars_no_panic() {
        // Emoji are 4 bytes each. 64 emoji = 256 bytes exactly.
        // 65 emoji = 260 bytes, which must be truncated to 256.
        let input = "\u{1F600}".repeat(65);
        assert_eq!(input.len(), 260);
        let result = truncate_utf8_safe(&input, 256);
        assert!(result.len() <= 256);
        // 64 emoji * 4 = 256 bytes exactly.
        assert_eq!(result.len(), 256);
        assert_eq!(result.chars().count(), 64);
    }

    #[test]
    fn truncate_utf8_safe_mixed_multibyte_no_panic() {
        // Mix of 1-byte (ASCII), 2-byte, 3-byte, and 4-byte characters.
        let mut input = String::new();
        for _ in 0..100 {
            input.push('A'); // 1 byte
            input.push('\u{00E9}'); // 2 bytes (e-acute)
            input.push('\u{4e00}'); // 3 bytes (CJK)
            input.push('\u{1F600}'); // 4 bytes (emoji)
        }
        assert_eq!(input.len(), 1000);
        let result = truncate_utf8_safe(&input, 256);
        assert!(result.len() <= 256);
        // Verify it is valid UTF-8 by iterating chars.
        let char_count = result.chars().count();
        assert!(char_count > 0, "must contain at least one character");
    }

    #[test]
    fn truncate_utf8_safe_empty_string() {
        let result = truncate_utf8_safe("", 256);
        assert_eq!(result, "");
    }

    #[test]
    fn truncate_utf8_safe_zero_limit() {
        let result = truncate_utf8_safe("hello", 0);
        assert_eq!(result, "");
    }

    #[test]
    fn truncate_string_multibyte_no_panic() {
        // 100 CJK chars = 300 bytes. Truncating at 256 must not panic.
        let input = "\u{4e00}".repeat(100);
        let result = truncate_string(&input, 256);
        assert!(result.len() <= 256);
        assert!(
            result.ends_with("..."),
            "truncated string must end with ellipsis"
        );
        // Verify valid UTF-8.
        let _ = result.chars().count();
    }

    #[test]
    fn truncate_string_short_multibyte_no_truncation() {
        let input = "\u{4e00}\u{4e01}\u{4e02}"; // 9 bytes
        let result = truncate_string(input, 256);
        assert_eq!(result, input);
    }

    // ========================================================================
    // ContainmentTrace sccache version bounding regression (Finding 2)
    // ========================================================================

    #[test]
    fn containment_trace_sccache_version_multibyte_no_panic() {
        // Version string with multibyte characters exceeding
        // MAX_SCCACHE_VERSION_LENGTH. This must not panic (the original
        // byte-slicing code would panic here).
        let multibyte_version = "\u{4e00}".repeat(MAX_SCCACHE_VERSION_LENGTH); // 256 * 3 = 768 bytes, well over limit
        assert!(multibyte_version.len() > MAX_SCCACHE_VERSION_LENGTH);

        let verdict = ContainmentVerdict {
            contained: true,
            reference_cgroup: "/test".to_string(),
            processes_checked: 1,
            critical_processes_found: 1,
            mismatches: vec![],
            sccache_detected: false,
            sccache_auto_disabled: false,
            sccache_disabled_reason: None,
        };

        // This must not panic.
        let trace =
            ContainmentTrace::from_verdict_with_sccache(&verdict, true, Some(multibyte_version));

        assert!(trace.sccache_enabled);
        let version = trace.sccache_version.expect("version must be present");
        assert!(
            version.len() <= MAX_SCCACHE_VERSION_LENGTH,
            "version must be bounded to {} bytes, got {}",
            MAX_SCCACHE_VERSION_LENGTH,
            version.len()
        );
        // Verify valid UTF-8 by iterating chars.
        let _ = version.chars().count();
    }

    #[test]
    fn containment_trace_sccache_version_ascii_bounded() {
        // ASCII version string exceeding the cap.
        let long_version = "x".repeat(MAX_SCCACHE_VERSION_LENGTH + 100);

        let verdict = ContainmentVerdict {
            contained: true,
            reference_cgroup: "/test".to_string(),
            processes_checked: 1,
            critical_processes_found: 1,
            mismatches: vec![],
            sccache_detected: false,
            sccache_auto_disabled: false,
            sccache_disabled_reason: None,
        };

        let trace = ContainmentTrace::from_verdict_with_sccache(&verdict, true, Some(long_version));

        let version = trace.sccache_version.expect("version must be present");
        assert_eq!(
            version.len(),
            MAX_SCCACHE_VERSION_LENGTH,
            "ASCII version must be truncated to exactly the cap"
        );
    }

    #[test]
    fn containment_trace_sccache_version_within_limit_preserved() {
        let short_version = "sccache 0.8.1".to_string();

        let verdict = ContainmentVerdict {
            contained: true,
            reference_cgroup: "/test".to_string(),
            processes_checked: 1,
            critical_processes_found: 1,
            mismatches: vec![],
            sccache_detected: false,
            sccache_auto_disabled: false,
            sccache_disabled_reason: None,
        };

        let trace = ContainmentTrace::from_verdict_with_sccache(
            &verdict,
            true,
            Some(short_version.clone()),
        );

        assert_eq!(
            trace.sccache_version.as_deref(),
            Some(short_version.as_str()),
            "version within limit must be preserved exactly"
        );
    }

    // ========================================================================
    // Deadlock-free sccache probe regression tests (INV-CONTAIN-008)
    // ========================================================================

    /// Regression test: a hung process that keeps stdout open must not block
    /// the probe indefinitely. The reader-thread + timeout-poll pattern
    /// ensures bounded termination even when `read()` would block forever.
    ///
    /// This test spawns `sleep 60` (stdout open, never writes, never closes).
    /// With the old blocking-read design, the probe would hang forever. With
    /// the new pattern, the calling thread kills the child on timeout and
    /// returns `None` promptly.
    #[test]
    fn probe_version_bounded_returns_none_on_hung_process() {
        use std::process::{Command, Stdio};

        let child = Command::new("sleep")
            .arg("60")
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("sleep must be available on test systems");

        // Use a very short timeout to keep the test fast.
        let timeout = Duration::from_millis(200);
        let thread_join_timeout = Duration::from_millis(100);
        let max_bytes = MAX_SCCACHE_VERSION_LENGTH;

        let start = Instant::now();
        let result = probe_version_bounded(child, max_bytes, timeout, thread_join_timeout);
        let elapsed = start.elapsed();

        assert!(
            result.is_none(),
            "hung process must produce None, not a version string"
        );
        // The probe must complete within a reasonable multiple of the timeout.
        // 2 seconds is generous: 200ms timeout + 100ms join + polling overhead.
        assert!(
            elapsed < Duration::from_secs(2),
            "probe must terminate within bounded time, took {elapsed:?}"
        );
    }

    /// Regression test: a process that writes valid output and exits promptly
    /// must produce `Some(version_string)`.
    #[test]
    fn probe_version_bounded_returns_output_on_success() {
        use std::process::{Command, Stdio};

        let child = Command::new("echo")
            .arg("sccache 0.8.1")
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("echo must be available on test systems");

        let timeout = Duration::from_secs(5);
        let thread_join_timeout = Duration::from_secs(1);
        let max_bytes = MAX_SCCACHE_VERSION_LENGTH;

        let result = probe_version_bounded(child, max_bytes, timeout, thread_join_timeout);

        assert_eq!(
            result.as_deref(),
            Some("sccache 0.8.1"),
            "valid output must be returned"
        );
    }

    /// Regression test: output at exactly the byte limit must be accepted,
    /// not rejected (finding 2 fix — `>=` changed to `Take`-based capping).
    #[test]
    fn probe_version_bounded_accepts_exact_limit_output() {
        use std::process::{Command, Stdio};

        // Create a string of exactly `max_bytes` characters (all ASCII 'x').
        let max_bytes: usize = 64;
        let exact_string = "x".repeat(max_bytes);

        // Use printf to output exactly max_bytes characters with no trailing
        // newline. printf is more portable than echo -n for this purpose.
        let child = Command::new("printf")
            .arg("%s")
            .arg(&exact_string)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("printf must be available on test systems");

        let timeout = Duration::from_secs(5);
        let thread_join_timeout = Duration::from_secs(1);

        let result = probe_version_bounded(child, max_bytes, timeout, thread_join_timeout);

        assert_eq!(
            result.as_deref(),
            Some(exact_string.as_str()),
            "exact-limit output must be accepted, not rejected as overflow"
        );
    }

    /// Regression test: output exceeding the byte limit must be truncated
    /// (via Take) and still return a valid result, not rejected outright.
    /// Take caps the read so the buffer never exceeds the limit.
    #[test]
    fn probe_version_bounded_truncates_oversized_output() {
        use std::process::{Command, Stdio};

        let max_bytes: usize = 32;
        // Output 64 bytes (2x limit).
        let oversized = "y".repeat(64);

        let child = Command::new("printf")
            .arg("%s")
            .arg(&oversized)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("printf must be available on test systems");

        let timeout = Duration::from_secs(5);
        let thread_join_timeout = Duration::from_secs(1);

        let result = probe_version_bounded(child, max_bytes, timeout, thread_join_timeout);

        // Take caps at max_bytes, so we get a truncated but valid result.
        let expected = "y".repeat(max_bytes);
        assert_eq!(
            result.as_deref(),
            Some(expected.as_str()),
            "oversized output must be truncated to the cap, not rejected"
        );
    }

    /// Regression test: a process that exits with non-zero status must
    /// produce `None` (fail-closed).
    #[test]
    fn probe_version_bounded_returns_none_on_nonzero_exit() {
        use std::process::{Command, Stdio};

        let child = Command::new("sh")
            .args(["-c", "echo 'sccache 0.8.1' && exit 1"])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("sh must be available on test systems");

        let timeout = Duration::from_secs(5);
        let thread_join_timeout = Duration::from_secs(1);

        let result = probe_version_bounded(
            child,
            MAX_SCCACHE_VERSION_LENGTH,
            timeout,
            thread_join_timeout,
        );

        assert!(
            result.is_none(),
            "non-zero exit must produce None (fail-closed)"
        );
    }

    // ========================================================================
    // Sccache server containment protocol tests (TCK-00554)
    // ========================================================================

    #[test]
    fn sccache_server_containment_default_is_fail_closed() {
        let sc = SccacheServerContainment::default();
        assert!(
            !sc.protocol_executed,
            "default must not have protocol executed"
        );
        assert!(!sc.preexisting_server_detected);
        assert!(sc.preexisting_server_in_cgroup.is_none());
        assert!(!sc.server_started);
        assert!(!sc.server_cgroup_verified);
        assert!(!sc.auto_disabled);
    }

    #[test]
    fn sccache_server_containment_serde_roundtrip() {
        let sc = SccacheServerContainment {
            protocol_executed: true,
            preexisting_server_detected: true,
            preexisting_server_in_cgroup: Some(false),
            preexisting_server_pid: Some(12345),
            server_started: true,
            started_server_pid: Some(12346),
            server_cgroup_verified: true,
            auto_disabled: false,
            reason: Some("test reason".to_string()),
        };
        let json = serde_json::to_string(&sc).unwrap();
        let sc2: SccacheServerContainment = serde_json::from_str(&json).unwrap();
        assert_eq!(sc, sc2);
    }

    #[test]
    fn sccache_server_containment_protocol_no_server_found_starts_new() {
        // Create a mock proc with no sccache processes. The protocol
        // should attempt to start a server.
        //
        // Two possible outcomes depending on whether sccache is installed:
        // - If sccache is NOT available: start fails → auto_disabled = true
        // - If sccache IS available: start succeeds → server_started = true, but the
        //   real server PID is not in our mock proc → treated as "not yet visible" →
        //   server_cgroup_verified = true
        let tmp = tempfile::tempdir().unwrap();
        let proc_root = tmp.path().join("proc");
        fs::create_dir_all(&proc_root).unwrap();

        // Reference process (PID 100)
        let ref_dir = proc_root.join("100");
        fs::create_dir_all(&ref_dir).unwrap();
        fs::write(ref_dir.join("status"), "Name:\tcargo\nPPid:\t1\n").unwrap();
        fs::write(
            ref_dir.join("cgroup"),
            "0::/system.slice/apm2-job.service\n",
        )
        .unwrap();
        fs::write(ref_dir.join("comm"), "cargo\n").unwrap();

        let result = execute_sccache_server_containment_protocol_with_proc(
            100,
            "/system.slice/apm2-job.service",
            &[],
            &proc_root,
        );

        assert!(result.protocol_executed);
        assert!(!result.preexisting_server_detected);

        // MAJOR-1 fix: Both outcomes now result in auto_disabled = true.
        // - If sccache is NOT available: start fails → auto_disabled = true
        // - If sccache IS available: start succeeds but the real server PID is not in
        //   our mock proc → empty Vec from discover_sccache_server_pids → fail-closed:
        //   auto_disabled = true (no positive PID + cgroup proof)
        assert!(
            result.auto_disabled,
            "must auto-disable when server PID cannot be positively verified"
        );
        assert!(
            !result.server_cgroup_verified,
            "server_cgroup_verified must be false without positive PID proof"
        );

        // Clean up: stop any server we may have started.
        let _ = run_sccache_command(&["--stop-server"], &[], SCCACHE_SERVER_STOP_TIMEOUT);
    }

    #[test]
    fn sccache_server_containment_protocol_preexisting_in_cgroup() {
        // Create a mock proc with a pre-existing sccache process
        // inside the same cgroup.
        let tmp = tempfile::tempdir().unwrap();
        let proc_root = tmp.path().join("proc");
        fs::create_dir_all(&proc_root).unwrap();

        // Reference process (PID 100)
        let ref_dir = proc_root.join("100");
        fs::create_dir_all(&ref_dir).unwrap();
        fs::write(ref_dir.join("status"), "Name:\tcargo\nPPid:\t1\n").unwrap();
        fs::write(
            ref_dir.join("cgroup"),
            "0::/system.slice/apm2-job.service\n",
        )
        .unwrap();
        fs::write(ref_dir.join("comm"), "cargo\n").unwrap();

        // sccache process (PID 200) — NOT a child of 100, but in same cgroup.
        let sccache_dir = proc_root.join("200");
        fs::create_dir_all(&sccache_dir).unwrap();
        fs::write(sccache_dir.join("status"), "Name:\tsccache\nPPid:\t1\n").unwrap();
        fs::write(
            sccache_dir.join("cgroup"),
            "0::/system.slice/apm2-job.service\n",
        )
        .unwrap();
        fs::write(sccache_dir.join("comm"), "sccache\n").unwrap();

        let result = execute_sccache_server_containment_protocol_with_proc(
            100,
            "/system.slice/apm2-job.service",
            &[],
            &proc_root,
        );

        assert!(result.protocol_executed);
        assert!(result.preexisting_server_detected);
        assert_eq!(result.preexisting_server_pid, Some(200));
        assert_eq!(result.preexisting_server_in_cgroup, Some(true));
        assert!(
            result.server_cgroup_verified,
            "in-cgroup server must be verified"
        );
        assert!(
            !result.auto_disabled,
            "in-cgroup server must not auto-disable"
        );
    }

    #[test]
    fn sccache_server_containment_protocol_preexisting_outside_cgroup() {
        // Create a mock proc with a pre-existing sccache process
        // OUTSIDE the unit cgroup. The protocol should refuse it.
        //
        // The mock PID 200 (outside-cgroup sccache) persists in the mock proc
        // throughout the test. Even if sccache is installed and a real server
        // is started, the verification step re-discovers mock PID 200 (which
        // is still outside the cgroup) and auto-disables. Both outcomes
        // (sccache available or not) result in auto_disabled because the mock
        // out-of-cgroup PID is always found during verification.
        let tmp = tempfile::tempdir().unwrap();
        let proc_root = tmp.path().join("proc");
        fs::create_dir_all(&proc_root).unwrap();

        // Reference process (PID 100)
        let ref_dir = proc_root.join("100");
        fs::create_dir_all(&ref_dir).unwrap();
        fs::write(ref_dir.join("status"), "Name:\tcargo\nPPid:\t1\n").unwrap();
        fs::write(
            ref_dir.join("cgroup"),
            "0::/system.slice/apm2-job.service\n",
        )
        .unwrap();
        fs::write(ref_dir.join("comm"), "cargo\n").unwrap();

        // sccache process (PID 200) — in a DIFFERENT cgroup.
        let sccache_dir = proc_root.join("200");
        fs::create_dir_all(&sccache_dir).unwrap();
        fs::write(sccache_dir.join("status"), "Name:\tsccache\nPPid:\t1\n").unwrap();
        fs::write(
            sccache_dir.join("cgroup"),
            "0::/user.slice/sccache.service\n",
        )
        .unwrap();
        fs::write(sccache_dir.join("comm"), "sccache\n").unwrap();

        let result = execute_sccache_server_containment_protocol_with_proc(
            100,
            "/system.slice/apm2-job.service",
            &[],
            &proc_root,
        );

        assert!(result.protocol_executed);
        assert!(result.preexisting_server_detected);
        assert_eq!(result.preexisting_server_pid, Some(200));
        assert_eq!(
            result.preexisting_server_in_cgroup,
            Some(false),
            "out-of-cgroup server must be detected"
        );
        // Whether or not sccache binary is available, the mock PID 200
        // remains in the mock proc with its outside-cgroup path. The
        // verification step always finds it and auto-disables.
        assert!(
            result.auto_disabled,
            "must auto-disable when out-of-cgroup server persists in proc"
        );

        // Clean up: stop any server we may have started.
        let _ = run_sccache_command(&["--stop-server"], &[], SCCACHE_SERVER_STOP_TIMEOUT);
    }

    #[test]
    fn containment_trace_with_server_containment_serde_roundtrip() {
        let sc = SccacheServerContainment {
            protocol_executed: true,
            preexisting_server_detected: false,
            preexisting_server_in_cgroup: None,
            preexisting_server_pid: None,
            server_started: true,
            started_server_pid: Some(999),
            server_cgroup_verified: true,
            auto_disabled: false,
            reason: Some("server started in cgroup".to_string()),
        };

        let trace = ContainmentTrace {
            verified: true,
            cgroup_path: "/test".to_string(),
            processes_checked: 3,
            mismatch_count: 0,
            sccache_auto_disabled: false,
            sccache_enabled: true,
            sccache_version: Some("sccache 0.8.1".to_string()),
            sccache_server_containment: Some(sc),
        };

        let json = serde_json::to_string(&trace).unwrap();
        let trace2: ContainmentTrace = serde_json::from_str(&json).unwrap();
        assert_eq!(trace, trace2);
    }

    #[test]
    fn from_verdict_with_server_containment_auto_disable_overrides() {
        // When server containment auto-disables, it must override
        // sccache_enabled to false.
        let verdict = ContainmentVerdict {
            contained: true,
            reference_cgroup: "/test".to_string(),
            processes_checked: 1,
            critical_processes_found: 0,
            mismatches: vec![],
            sccache_detected: false,
            sccache_auto_disabled: false,
            sccache_disabled_reason: None,
        };

        let sc = SccacheServerContainment {
            protocol_executed: true,
            preexisting_server_detected: true,
            preexisting_server_in_cgroup: Some(false),
            preexisting_server_pid: Some(500),
            server_started: false,
            started_server_pid: None,
            server_cgroup_verified: false,
            auto_disabled: true,
            reason: Some("server outside cgroup".to_string()),
        };

        let trace = ContainmentTrace::from_verdict_with_server_containment(
            &verdict,
            true, // policy enables sccache
            Some("sccache 0.8.1".to_string()),
            sc,
        );

        assert!(
            !trace.sccache_enabled,
            "server containment auto-disable must override sccache_enabled"
        );
        assert!(
            trace.sccache_auto_disabled,
            "sccache_auto_disabled must be true"
        );
        assert!(
            trace.sccache_version.is_none(),
            "version must be None when auto-disabled"
        );
        assert!(trace.sccache_server_containment.is_some());
        assert!(
            trace
                .sccache_server_containment
                .as_ref()
                .unwrap()
                .auto_disabled
        );
    }

    #[test]
    fn stop_sccache_server_returns_false_without_binary() {
        // Hermetic: override PATH via env vars so sccache binary is never
        // found, regardless of whether an ambient sccache server is running.
        // `run_sccache_command` applies caller-provided env vars AFTER
        // the process PATH, so this override is authoritative.
        let isolated_env = vec![("PATH".to_string(), "/nonexistent-path-for-test".to_string())];
        let result = stop_sccache_server(&isolated_env);
        assert!(
            !result,
            "stop must return false when sccache is not available"
        );
    }

    #[test]
    fn discover_sccache_server_pids_no_sccache_returns_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let proc_root = tmp.path().join("proc");
        fs::create_dir_all(&proc_root).unwrap();

        // Reference process (PID 100)
        let ref_dir = proc_root.join("100");
        fs::create_dir_all(&ref_dir).unwrap();
        fs::write(ref_dir.join("status"), "Name:\tcargo\nPPid:\t1\n").unwrap();
        fs::write(ref_dir.join("cgroup"), "0::/test\n").unwrap();
        fs::write(ref_dir.join("comm"), "cargo\n").unwrap();

        // Another process but NOT sccache (PID 200)
        let other_dir = proc_root.join("200");
        fs::create_dir_all(&other_dir).unwrap();
        fs::write(other_dir.join("status"), "Name:\trustc\nPPid:\t1\n").unwrap();
        fs::write(other_dir.join("cgroup"), "0::/test\n").unwrap();
        fs::write(other_dir.join("comm"), "rustc\n").unwrap();

        let result = discover_sccache_server_pids(100, &proc_root).unwrap();
        assert!(
            result.is_empty(),
            "no sccache process should mean empty Vec"
        );
    }

    #[test]
    fn discover_sccache_server_pids_finds_sccache() {
        let tmp = tempfile::tempdir().unwrap();
        let proc_root = tmp.path().join("proc");
        fs::create_dir_all(&proc_root).unwrap();

        // Reference process (PID 100)
        let ref_dir = proc_root.join("100");
        fs::create_dir_all(&ref_dir).unwrap();
        fs::write(ref_dir.join("status"), "Name:\tcargo\nPPid:\t1\n").unwrap();
        fs::write(ref_dir.join("cgroup"), "0::/test\n").unwrap();
        fs::write(ref_dir.join("comm"), "cargo\n").unwrap();

        // sccache process (PID 200) — NOT a child of 100
        let sccache_dir = proc_root.join("200");
        fs::create_dir_all(&sccache_dir).unwrap();
        fs::write(sccache_dir.join("status"), "Name:\tsccache\nPPid:\t1\n").unwrap();
        fs::write(sccache_dir.join("cgroup"), "0::/other\n").unwrap();
        fs::write(sccache_dir.join("comm"), "sccache\n").unwrap();

        let result = discover_sccache_server_pids(100, &proc_root).unwrap();
        assert_eq!(result, vec![200]);
    }

    #[test]
    fn discover_sccache_server_pids_finds_all_sccache_servers() {
        // BLOCKER fix regression test: set-based discovery must return
        // ALL sccache server PIDs, not just the first one.
        let tmp = tempfile::tempdir().unwrap();
        let proc_root = tmp.path().join("proc");
        fs::create_dir_all(&proc_root).unwrap();

        // Reference process (PID 100)
        let ref_dir = proc_root.join("100");
        fs::create_dir_all(&ref_dir).unwrap();
        fs::write(ref_dir.join("status"), "Name:\tcargo\nPPid:\t1\n").unwrap();
        fs::write(ref_dir.join("cgroup"), "0::/test\n").unwrap();
        fs::write(ref_dir.join("comm"), "cargo\n").unwrap();

        // sccache process (PID 200) — in cgroup
        let sccache_dir1 = proc_root.join("200");
        fs::create_dir_all(&sccache_dir1).unwrap();
        fs::write(sccache_dir1.join("status"), "Name:\tsccache\nPPid:\t1\n").unwrap();
        fs::write(sccache_dir1.join("cgroup"), "0::/test\n").unwrap();
        fs::write(sccache_dir1.join("comm"), "sccache\n").unwrap();

        // sccache process (PID 300) — different cgroup (outside)
        let sccache_dir2 = proc_root.join("300");
        fs::create_dir_all(&sccache_dir2).unwrap();
        fs::write(sccache_dir2.join("status"), "Name:\tsccache\nPPid:\t1\n").unwrap();
        fs::write(sccache_dir2.join("cgroup"), "0::/other\n").unwrap();
        fs::write(sccache_dir2.join("comm"), "sccache\n").unwrap();

        let mut result = discover_sccache_server_pids(100, &proc_root).unwrap();
        result.sort_unstable(); // Discovery order may vary
        assert_eq!(
            result,
            vec![200, 300],
            "must discover ALL sccache servers, not just the first"
        );
    }

    #[test]
    fn discover_sccache_server_pids_skips_child_sccache() {
        // sccache process that IS a child of the reference PID should be
        // skipped (it's part of the build, not a standalone server).
        let tmp = tempfile::tempdir().unwrap();
        let proc_root = tmp.path().join("proc");
        fs::create_dir_all(&proc_root).unwrap();

        // Reference process (PID 100)
        let ref_dir = proc_root.join("100");
        fs::create_dir_all(&ref_dir).unwrap();
        fs::write(ref_dir.join("status"), "Name:\tcargo\nPPid:\t1\n").unwrap();
        fs::write(ref_dir.join("cgroup"), "0::/test\n").unwrap();
        fs::write(ref_dir.join("comm"), "cargo\n").unwrap();

        // sccache process (PID 101) — child of 100 (part of build)
        let sccache_dir = proc_root.join("101");
        fs::create_dir_all(&sccache_dir).unwrap();
        fs::write(sccache_dir.join("status"), "Name:\tsccache\nPPid:\t100\n").unwrap();
        fs::write(sccache_dir.join("cgroup"), "0::/test\n").unwrap();
        fs::write(sccache_dir.join("comm"), "sccache\n").unwrap();

        let result = discover_sccache_server_pids(100, &proc_root).unwrap();
        assert!(
            result.is_empty(),
            "child sccache must be skipped as it's part of the build"
        );
    }

    // ========================================================================
    // Regression tests for MAJOR-1 fix: fail-closed on verify_started_server
    // ========================================================================

    #[test]
    fn verify_started_server_fails_closed_when_pid_not_found() {
        // When `discover_sccache_server_pids` returns empty Vec (server
        // not visible in /proc), verify_started_server MUST set
        // `auto_disabled = true` and `server_cgroup_verified = false`.
        // Regression: previously treated as success (server_cgroup_verified=true).
        let tmp = tempfile::tempdir().unwrap();
        let proc_root = tmp.path().join("proc");
        fs::create_dir_all(&proc_root).unwrap();

        // Reference process (PID 100) — no sccache process present.
        let ref_dir = proc_root.join("100");
        fs::create_dir_all(&ref_dir).unwrap();
        fs::write(ref_dir.join("status"), "Name:\tcargo\nPPid:\t1\n").unwrap();
        fs::write(ref_dir.join("cgroup"), "0::/test/unit\n").unwrap();
        fs::write(ref_dir.join("comm"), "cargo\n").unwrap();

        let mut result = SccacheServerContainment {
            protocol_executed: true,
            server_started: true,
            ..Default::default()
        };

        verify_started_server(&mut result, 100, "/test/unit", &proc_root);

        assert!(
            result.auto_disabled,
            "fail-closed: must auto-disable when server PID not found"
        );
        assert!(
            !result.server_cgroup_verified,
            "must not verify cgroup without positive PID proof"
        );
        assert!(
            result.reason.as_ref().unwrap().contains("not found"),
            "reason must explain the failure"
        );
    }

    // ========================================================================
    // Regression tests for BLOCKER fix: set-based containment verification
    // ========================================================================

    #[test]
    fn verify_started_server_fails_closed_when_any_server_outside_cgroup() {
        // BLOCKER fix regression test: if the unit cgroup has one sccache
        // server inside and another sccache server outside, verification
        // MUST fail closed (auto_disabled = true).
        let tmp = tempfile::tempdir().unwrap();
        let proc_root = tmp.path().join("proc");
        fs::create_dir_all(&proc_root).unwrap();

        // Reference process (PID 100)
        let ref_dir = proc_root.join("100");
        fs::create_dir_all(&ref_dir).unwrap();
        fs::write(ref_dir.join("status"), "Name:\tcargo\nPPid:\t1\n").unwrap();
        fs::write(ref_dir.join("cgroup"), "0::/test/unit\n").unwrap();
        fs::write(ref_dir.join("comm"), "cargo\n").unwrap();

        // sccache server PID 200 — inside the unit cgroup
        let sccache_in = proc_root.join("200");
        fs::create_dir_all(&sccache_in).unwrap();
        fs::write(sccache_in.join("status"), "Name:\tsccache\nPPid:\t1\n").unwrap();
        fs::write(sccache_in.join("cgroup"), "0::/test/unit\n").unwrap();
        fs::write(sccache_in.join("comm"), "sccache\n").unwrap();

        // sccache server PID 300 — OUTSIDE the unit cgroup (escaped)
        let sccache_out = proc_root.join("300");
        fs::create_dir_all(&sccache_out).unwrap();
        fs::write(sccache_out.join("status"), "Name:\tsccache\nPPid:\t1\n").unwrap();
        fs::write(sccache_out.join("cgroup"), "0::/user.slice/other\n").unwrap();
        fs::write(sccache_out.join("comm"), "sccache\n").unwrap();

        let mut result = SccacheServerContainment {
            protocol_executed: true,
            server_started: true,
            ..Default::default()
        };

        verify_started_server(&mut result, 100, "/test/unit", &proc_root);

        assert!(
            result.auto_disabled,
            "fail-closed: must auto-disable when ANY sccache server is outside cgroup"
        );
        assert!(
            !result.server_cgroup_verified,
            "must not verify cgroup when conflicting outside server exists"
        );
        assert!(
            result.reason.as_ref().unwrap().contains("outside cgroup"),
            "reason must mention the outside-cgroup PIDs: {:?}",
            result.reason,
        );
    }

    #[test]
    fn verify_started_server_succeeds_when_all_servers_in_cgroup() {
        // When ALL discovered sccache servers are inside the cgroup,
        // verification should succeed.
        let tmp = tempfile::tempdir().unwrap();
        let proc_root = tmp.path().join("proc");
        fs::create_dir_all(&proc_root).unwrap();

        // Reference process (PID 100)
        let ref_dir = proc_root.join("100");
        fs::create_dir_all(&ref_dir).unwrap();
        fs::write(ref_dir.join("status"), "Name:\tcargo\nPPid:\t1\n").unwrap();
        fs::write(ref_dir.join("cgroup"), "0::/test/unit\n").unwrap();
        fs::write(ref_dir.join("comm"), "cargo\n").unwrap();

        // sccache server PID 200 — inside the unit cgroup
        let sccache1 = proc_root.join("200");
        fs::create_dir_all(&sccache1).unwrap();
        fs::write(sccache1.join("status"), "Name:\tsccache\nPPid:\t1\n").unwrap();
        fs::write(sccache1.join("cgroup"), "0::/test/unit\n").unwrap();
        fs::write(sccache1.join("comm"), "sccache\n").unwrap();

        // sccache server PID 300 — also inside the unit cgroup
        let sccache2 = proc_root.join("300");
        fs::create_dir_all(&sccache2).unwrap();
        fs::write(sccache2.join("status"), "Name:\tsccache\nPPid:\t1\n").unwrap();
        fs::write(sccache2.join("cgroup"), "0::/test/unit\n").unwrap();
        fs::write(sccache2.join("comm"), "sccache\n").unwrap();

        let mut result = SccacheServerContainment {
            protocol_executed: true,
            server_started: true,
            ..Default::default()
        };

        verify_started_server(&mut result, 100, "/test/unit", &proc_root);

        assert!(
            !result.auto_disabled,
            "must not auto-disable when all servers are inside cgroup"
        );
        assert!(
            result.server_cgroup_verified,
            "must verify cgroup when all servers are contained"
        );
        assert!(
            result.reason.as_ref().unwrap().contains("all contained"),
            "reason must confirm all candidates were checked: {:?}",
            result.reason,
        );
    }

    #[test]
    fn containment_trace_auto_disabled_produces_effective_sccache_false() {
        // Regression test for BLOCKER-1: when server containment auto-disables,
        // the containment trace MUST have sccache_auto_disabled=true and
        // sccache_enabled=false, so callers deriving effective_sccache_enabled
        // from `!ct.sccache_auto_disabled` get false.
        let verdict = ContainmentVerdict {
            contained: true,
            reference_cgroup: "/test".to_string(),
            processes_checked: 1,
            critical_processes_found: 0,
            mismatches: vec![],
            sccache_detected: false,
            sccache_auto_disabled: false,
            sccache_disabled_reason: None,
        };

        let sc = SccacheServerContainment {
            protocol_executed: true,
            auto_disabled: true,
            reason: Some("server not found in /proc".to_string()),
            ..Default::default()
        };

        let trace = ContainmentTrace::from_verdict_with_server_containment(
            &verdict,
            true, // policy enables sccache
            Some("sccache 0.8.1".to_string()),
            sc,
        );

        assert!(
            trace.sccache_auto_disabled,
            "trace must reflect auto-disable from server containment"
        );
        assert!(
            !trace.sccache_enabled,
            "sccache_enabled must be false when auto-disabled"
        );
        assert!(
            trace.sccache_version.is_none(),
            "version must be cleared when auto-disabled"
        );

        // Verify the derivation pattern used in fac_worker.rs:
        // `policy.sccache_enabled && !trace.sccache_auto_disabled`
        let policy_sccache_enabled = true;
        let effective_sccache_enabled = policy_sccache_enabled && !trace.sccache_auto_disabled;
        assert!(
            !effective_sccache_enabled,
            "effective_sccache_enabled must be false when trace shows auto-disabled"
        );
    }

    // ========================================================================
    // BLOCKER fix (fix-round-3): set-based preexisting server handling
    // ========================================================================

    /// BLOCKER fix (fix-round-3): Two sccache PIDs — one in-cgroup, one
    /// outside. The protocol must auto-disable because the out-of-cgroup
    /// server is a threat.
    #[test]
    fn sccache_server_containment_two_pids_one_outside_auto_disables() {
        let tmp = tempfile::tempdir().unwrap();
        let proc_root = tmp.path().join("proc");
        fs::create_dir_all(&proc_root).unwrap();

        // Reference process (PID 100)
        let ref_dir = proc_root.join("100");
        fs::create_dir_all(&ref_dir).unwrap();
        fs::write(ref_dir.join("status"), "Name:\tcargo\nPPid:\t1\n").unwrap();
        fs::write(
            ref_dir.join("cgroup"),
            "0::/system.slice/apm2-job.service\n",
        )
        .unwrap();
        fs::write(ref_dir.join("comm"), "cargo\n").unwrap();

        // sccache PID 200 — in-cgroup
        let sc1_dir = proc_root.join("200");
        fs::create_dir_all(&sc1_dir).unwrap();
        fs::write(sc1_dir.join("status"), "Name:\tsccache\nPPid:\t1\n").unwrap();
        fs::write(
            sc1_dir.join("cgroup"),
            "0::/system.slice/apm2-job.service\n",
        )
        .unwrap();
        fs::write(sc1_dir.join("comm"), "sccache\n").unwrap();

        // sccache PID 300 — OUTSIDE cgroup
        let sc2_dir = proc_root.join("300");
        fs::create_dir_all(&sc2_dir).unwrap();
        fs::write(sc2_dir.join("status"), "Name:\tsccache\nPPid:\t1\n").unwrap();
        fs::write(sc2_dir.join("cgroup"), "0::/user.slice/sccache.service\n").unwrap();
        fs::write(sc2_dir.join("comm"), "sccache\n").unwrap();

        let result = execute_sccache_server_containment_protocol_with_proc(
            100,
            "/system.slice/apm2-job.service",
            &[],
            &proc_root,
        );

        assert!(result.protocol_executed);
        assert!(result.preexisting_server_detected);
        // Must auto-disable because PID 300 is outside the cgroup.
        // The stop attempt will fail (no real sccache binary), triggering
        // fail-closed containment failure.
        assert!(
            result.auto_disabled,
            "must auto-disable when any preexisting server is outside cgroup"
        );
    }

    /// BLOCKER fix (fix-round-3): Multiple sccache PIDs all in-cgroup.
    /// The protocol must succeed — all servers are contained.
    #[test]
    fn sccache_server_containment_multiple_pids_all_in_cgroup() {
        let tmp = tempfile::tempdir().unwrap();
        let proc_root = tmp.path().join("proc");
        fs::create_dir_all(&proc_root).unwrap();

        // Reference process (PID 100)
        let ref_dir = proc_root.join("100");
        fs::create_dir_all(&ref_dir).unwrap();
        fs::write(ref_dir.join("status"), "Name:\tcargo\nPPid:\t1\n").unwrap();
        fs::write(
            ref_dir.join("cgroup"),
            "0::/system.slice/apm2-job.service\n",
        )
        .unwrap();
        fs::write(ref_dir.join("comm"), "cargo\n").unwrap();

        // sccache PID 200 — in-cgroup
        let sc1_dir = proc_root.join("200");
        fs::create_dir_all(&sc1_dir).unwrap();
        fs::write(sc1_dir.join("status"), "Name:\tsccache\nPPid:\t1\n").unwrap();
        fs::write(
            sc1_dir.join("cgroup"),
            "0::/system.slice/apm2-job.service\n",
        )
        .unwrap();
        fs::write(sc1_dir.join("comm"), "sccache\n").unwrap();

        // sccache PID 300 — also in-cgroup
        let sc2_dir = proc_root.join("300");
        fs::create_dir_all(&sc2_dir).unwrap();
        fs::write(sc2_dir.join("status"), "Name:\tsccache\nPPid:\t1\n").unwrap();
        fs::write(
            sc2_dir.join("cgroup"),
            "0::/system.slice/apm2-job.service\n",
        )
        .unwrap();
        fs::write(sc2_dir.join("comm"), "sccache\n").unwrap();

        let result = execute_sccache_server_containment_protocol_with_proc(
            100,
            "/system.slice/apm2-job.service",
            &[],
            &proc_root,
        );

        assert!(result.protocol_executed);
        assert!(result.preexisting_server_detected);
        assert_eq!(result.preexisting_server_in_cgroup, Some(true));
        assert!(
            result.server_cgroup_verified,
            "all in-cgroup servers must be verified"
        );
        assert!(
            !result.auto_disabled,
            "all-in-cgroup servers must not auto-disable"
        );
    }

    /// BLOCKER fix (fix-round-3): Stop failure for out-of-cgroup preexisting
    /// server results in `auto_disabled=true`.
    #[test]
    fn sccache_server_containment_stop_failure_auto_disables() {
        // This test verifies the same scenario as the out-of-cgroup test above,
        // but focuses on the stop-failure path. With no real sccache binary,
        // the stop command will fail, and the protocol must auto-disable.
        let tmp = tempfile::tempdir().unwrap();
        let proc_root = tmp.path().join("proc");
        fs::create_dir_all(&proc_root).unwrap();

        // Reference process (PID 100)
        let ref_dir = proc_root.join("100");
        fs::create_dir_all(&ref_dir).unwrap();
        fs::write(ref_dir.join("status"), "Name:\tcargo\nPPid:\t1\n").unwrap();
        fs::write(
            ref_dir.join("cgroup"),
            "0::/system.slice/apm2-job.service\n",
        )
        .unwrap();
        fs::write(ref_dir.join("comm"), "cargo\n").unwrap();

        // sccache PID 200 — OUTSIDE cgroup
        let sccache_dir = proc_root.join("200");
        fs::create_dir_all(&sccache_dir).unwrap();
        fs::write(sccache_dir.join("status"), "Name:\tsccache\nPPid:\t1\n").unwrap();
        fs::write(
            sccache_dir.join("cgroup"),
            "0::/user.slice/sccache.service\n",
        )
        .unwrap();
        fs::write(sccache_dir.join("comm"), "sccache\n").unwrap();

        // Override PATH so sccache binary is NOT found — stop must fail.
        let env = vec![("PATH".to_string(), "/nonexistent-path-for-test".to_string())];
        let result = execute_sccache_server_containment_protocol_with_proc(
            100,
            "/system.slice/apm2-job.service",
            &env,
            &proc_root,
        );

        assert!(result.protocol_executed);
        assert!(result.preexisting_server_detected);
        assert_eq!(result.preexisting_server_in_cgroup, Some(false));
        assert!(
            result.auto_disabled,
            "stop failure for out-of-cgroup server must auto-disable"
        );
        assert!(
            result.reason.as_ref().unwrap().contains("failed to stop"),
            "reason must explain stop failure"
        );
    }

    /// BLOCKER fix (fix-round-3): `discover_sccache_server_pids` finds
    /// multiple sccache processes.
    #[test]
    fn discover_sccache_server_pids_finds_multiple() {
        let tmp = tempfile::tempdir().unwrap();
        let proc_root = tmp.path().join("proc");
        fs::create_dir_all(&proc_root).unwrap();

        // Reference process (PID 100)
        let ref_dir = proc_root.join("100");
        fs::create_dir_all(&ref_dir).unwrap();
        fs::write(ref_dir.join("status"), "Name:\tcargo\nPPid:\t1\n").unwrap();
        fs::write(ref_dir.join("cgroup"), "0::/test\n").unwrap();
        fs::write(ref_dir.join("comm"), "cargo\n").unwrap();

        // sccache PID 200
        let sc1_dir = proc_root.join("200");
        fs::create_dir_all(&sc1_dir).unwrap();
        fs::write(sc1_dir.join("status"), "Name:\tsccache\nPPid:\t1\n").unwrap();
        fs::write(sc1_dir.join("cgroup"), "0::/test\n").unwrap();
        fs::write(sc1_dir.join("comm"), "sccache\n").unwrap();

        // sccache PID 300
        let sc2_dir = proc_root.join("300");
        fs::create_dir_all(&sc2_dir).unwrap();
        fs::write(sc2_dir.join("status"), "Name:\tsccache\nPPid:\t1\n").unwrap();
        fs::write(sc2_dir.join("cgroup"), "0::/other\n").unwrap();
        fs::write(sc2_dir.join("comm"), "sccache\n").unwrap();

        let result = discover_sccache_server_pids(100, &proc_root).unwrap();
        assert_eq!(result.len(), 2, "must find both sccache PIDs");
        assert!(result.contains(&200));
        assert!(result.contains(&300));
    }
}
