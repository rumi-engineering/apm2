//! Seccomp BPF sandbox for agent processes on Linux.
//!
//! This module provides syscall filtering using seccomp-bpf to restrict
//! what agent processes can do at the kernel level. It implements a
//! **default-deny, least-privilege, fail-closed** security model.
//!
//! # Security Model
//!
//! The seccomp profile blocks direct network and filesystem syscalls,
//! ensuring agents can only communicate via mediated channels (stdout/stderr,
//! watched directories). Profile violations are fatal and terminate the
//! process immediately.
//!
//! # Platform Support
//!
//! This module is only available on Linux systems. On other platforms,
//! a no-op implementation is provided that always reports as "not enforced."
//!
//! # Example
//!
//! ```rust,ignore
//! use apm2_core::adapter::seccomp::{SeccompProfile, SeccompProfileLevel};
//!
//! // Create a restricted profile (blocks network, limits filesystem)
//! let profile = SeccompProfile::new(SeccompProfileLevel::Restricted);
//!
//! // Apply the profile to child processes (must be done before exec)
//! // This is typically done via pre_exec hooks in std::process::Command
//! ```

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Security profile level for seccomp filtering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub enum SeccompProfileLevel {
    /// No seccomp filtering applied.
    ///
    /// This should only be used for debugging or on non-Linux platforms.
    #[default]
    None,

    /// Baseline filtering - blocks dangerous syscalls but allows most
    /// operations.
    ///
    /// Blocks:
    /// - `ptrace`, `process_vm_readv`, `process_vm_writev` (debugging)
    /// - `kexec_load`, `kexec_file_load` (kernel replacement)
    /// - `reboot` (system shutdown)
    /// - `pivot_root`, `chroot` (filesystem escape)
    /// - `init_module`, `delete_module`, `finit_module` (kernel modules)
    Baseline,

    /// Restricted filtering - for agent processes.
    ///
    /// Includes Baseline blocks, plus:
    /// - All network syscalls (`socket`, `connect`, `bind`, `listen`, etc.)
    /// - Raw filesystem creation syscalls (`open` with `O_CREAT` outside
    ///   allowed paths)
    /// - `mount`, `umount`, `umount2` (filesystem manipulation)
    /// - `setuid`, `setgid`, `setgroups` (privilege escalation)
    Restricted,

    /// Strict filtering - maximum restriction.
    ///
    /// Includes Restricted blocks, plus:
    /// - `execve`, `execveat` (new process execution)
    /// - `fork`, `vfork`, `clone` for new processes
    ///
    /// This level is very restrictive and may break many legitimate use cases.
    Strict,
}

impl SeccompProfileLevel {
    /// Returns true if this level enforces any restrictions.
    #[must_use]
    pub const fn is_enforced(&self) -> bool {
        !matches!(self, Self::None)
    }

    /// Returns a human-readable name for this level.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Baseline => "baseline",
            Self::Restricted => "restricted",
            Self::Strict => "strict",
        }
    }
}

/// Seccomp profile configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeccompProfile {
    /// The filtering level to apply.
    pub level: SeccompProfileLevel,

    /// Paths where file creation is allowed (for Restricted level).
    ///
    /// Only applies when `level` is `Restricted`. These paths are
    /// checked against the first argument of filesystem syscalls.
    pub allowed_write_paths: Vec<PathBuf>,

    /// Whether to log violations before terminating.
    ///
    /// When enabled, uses `SECCOMP_RET_TRAP` for blocked syscalls
    /// which sends SIGSYS (can be logged), otherwise uses
    /// `SECCOMP_RET_KILL_PROCESS` for immediate termination.
    pub log_violations: bool,
}

impl SeccompProfile {
    /// Creates a new seccomp profile with the given level.
    #[must_use]
    pub const fn new(level: SeccompProfileLevel) -> Self {
        Self {
            level,
            allowed_write_paths: Vec::new(),
            log_violations: true,
        }
    }

    /// Creates a profile with no filtering.
    #[must_use]
    pub const fn none() -> Self {
        Self::new(SeccompProfileLevel::None)
    }

    /// Creates a baseline profile.
    #[must_use]
    pub const fn baseline() -> Self {
        Self::new(SeccompProfileLevel::Baseline)
    }

    /// Creates a restricted profile suitable for agent processes.
    #[must_use]
    pub const fn restricted() -> Self {
        Self::new(SeccompProfileLevel::Restricted)
    }

    /// Creates a strict profile with maximum restrictions.
    #[must_use]
    pub const fn strict() -> Self {
        Self::new(SeccompProfileLevel::Strict)
    }

    /// Adds an allowed write path (builder pattern).
    #[must_use]
    pub fn with_allowed_write_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.allowed_write_paths.push(path.into());
        self
    }

    /// Sets whether to log violations (builder pattern).
    #[must_use]
    pub const fn with_log_violations(mut self, log: bool) -> Self {
        self.log_violations = log;
        self
    }

    /// Returns true if this profile enforces restrictions.
    #[must_use]
    pub const fn is_enforced(&self) -> bool {
        self.level.is_enforced()
    }
}

impl Default for SeccompProfile {
    fn default() -> Self {
        Self::none()
    }
}

/// Error type for seccomp operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeccompError {
    /// Error message describing what went wrong.
    pub message: String,
    /// The syscall number that caused the error, if applicable.
    pub syscall: Option<i32>,
}

impl std::fmt::Display for SeccompError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(syscall) = self.syscall {
            write!(f, "seccomp error (syscall {}): {}", syscall, self.message)
        } else {
            write!(f, "seccomp error: {}", self.message)
        }
    }
}

impl std::error::Error for SeccompError {}

impl SeccompError {
    /// Creates a new seccomp error with a message.
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            syscall: None,
        }
    }

    /// Creates a seccomp error with syscall context.
    #[must_use]
    pub const fn with_syscall(mut self, syscall: i32) -> Self {
        self.syscall = Some(syscall);
        self
    }
}

/// Result of applying a seccomp filter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeccompResult {
    /// Whether the filter was successfully applied.
    pub applied: bool,
    /// The profile level that was applied.
    pub level: SeccompProfileLevel,
    /// Number of syscalls blocked by the filter.
    pub blocked_syscall_count: usize,
    /// Human-readable summary of the filter.
    pub summary: String,
}

// Platform-specific implementation
#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
pub use linux::apply_seccomp_filter;

// Stub implementation for non-Linux platforms
#[cfg(not(target_os = "linux"))]
mod stub;

#[cfg(not(target_os = "linux"))]
pub use stub::apply_seccomp_filter;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_profile_level_names() {
        assert_eq!(SeccompProfileLevel::None.name(), "none");
        assert_eq!(SeccompProfileLevel::Baseline.name(), "baseline");
        assert_eq!(SeccompProfileLevel::Restricted.name(), "restricted");
        assert_eq!(SeccompProfileLevel::Strict.name(), "strict");
    }

    #[test]
    fn test_profile_level_enforced() {
        assert!(!SeccompProfileLevel::None.is_enforced());
        assert!(SeccompProfileLevel::Baseline.is_enforced());
        assert!(SeccompProfileLevel::Restricted.is_enforced());
        assert!(SeccompProfileLevel::Strict.is_enforced());
    }

    #[test]
    fn test_profile_builders() {
        let profile = SeccompProfile::none();
        assert_eq!(profile.level, SeccompProfileLevel::None);
        assert!(!profile.is_enforced());

        let profile = SeccompProfile::baseline();
        assert_eq!(profile.level, SeccompProfileLevel::Baseline);
        assert!(profile.is_enforced());

        let profile = SeccompProfile::restricted();
        assert_eq!(profile.level, SeccompProfileLevel::Restricted);

        let profile = SeccompProfile::strict();
        assert_eq!(profile.level, SeccompProfileLevel::Strict);
    }

    #[test]
    fn test_profile_with_allowed_paths() {
        let profile = SeccompProfile::restricted()
            .with_allowed_write_path("/tmp/workspace")
            .with_allowed_write_path("/home/user/project");

        assert_eq!(profile.allowed_write_paths.len(), 2);
        assert!(
            profile
                .allowed_write_paths
                .contains(&PathBuf::from("/tmp/workspace"))
        );
        assert!(
            profile
                .allowed_write_paths
                .contains(&PathBuf::from("/home/user/project"))
        );
    }

    #[test]
    fn test_profile_with_log_violations() {
        let profile = SeccompProfile::restricted().with_log_violations(false);
        assert!(!profile.log_violations);

        let profile = SeccompProfile::restricted().with_log_violations(true);
        assert!(profile.log_violations);
    }

    #[test]
    fn test_seccomp_error_display() {
        let err = SeccompError::new("filter compilation failed");
        assert_eq!(err.to_string(), "seccomp error: filter compilation failed");

        let err = SeccompError::new("syscall blocked").with_syscall(57);
        assert_eq!(
            err.to_string(),
            "seccomp error (syscall 57): syscall blocked"
        );
    }

    #[test]
    fn test_default_profile_is_none() {
        let profile = SeccompProfile::default();
        assert_eq!(profile.level, SeccompProfileLevel::None);
        assert!(!profile.is_enforced());
    }
}
