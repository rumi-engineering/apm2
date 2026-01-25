//! Seccomp BPF sandbox for agent processes on Linux.
//!
//! This module provides syscall filtering using seccomp-bpf to restrict
//! what agent processes can do at the kernel level. It implements a
//! **blocklist-based, defense-in-depth, fail-closed** security model.
//!
//! # Security Model
//!
//! The seccomp profile blocks dangerous syscalls that are unlikely to be
//! needed by agent processes. This is a **blocklist** approach (default-allow
//! with specific syscalls blocked) rather than a whitelist (default-deny).
//! While a whitelist would be more secure, it's impractical for general-purpose
//! agent processes that may need various syscalls.
//!
//! **Limitations:**
//! - Seccomp-bpf cannot filter on string arguments (like file paths) because it
//!   cannot dereference pointers. For filesystem access control, consider
//!   Landlock LSM or mount namespaces.
//! - This is defense-in-depth, not a complete sandbox.
//!
//! Profile violations are fatal and terminate the process immediately
//! (fail-closed).
//!
//! # Platform Support
//!
//! This module is only available on Linux `x86_64` systems. On other platforms,
//! a no-op implementation is provided that always reports as "not enforced."
//!
//! # Example
//!
//! ```rust,ignore
//! use apm2_core::adapter::seccomp::{SeccompProfile, SeccompProfileLevel};
//!
//! // Create a restricted profile (blocks network, dangerous syscalls)
//! let profile = SeccompProfile::new(SeccompProfileLevel::Restricted);
//!
//! // Apply the profile to child processes (must be done before exec)
//! // This is typically done via pre_exec hooks in std::process::Command
//! ```

use serde::{Deserialize, Serialize};

/// Security profile level for seccomp filtering.
///
/// Each level is a **blocklist** that adds more syscalls to block.
/// Higher levels are more restrictive but may break legitimate functionality.
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
    /// - `ptrace`, `process_vm_readv`, `process_vm_writev`
    ///   (debugging/inspection)
    /// - `kexec_load`, `kexec_file_load` (kernel replacement)
    /// - `reboot` (system shutdown)
    /// - `pivot_root`, `chroot` (filesystem escape)
    /// - `init_module`, `delete_module`, `finit_module` (kernel modules)
    /// - `bpf` (BPF program loading)
    /// - `userfaultfd` (page fault handling)
    /// - `unshare` (namespace creation)
    /// - `io_uring_setup`, `io_uring_enter`, `io_uring_register` (async I/O
    ///   bypass)
    Baseline,

    /// Restricted filtering - for agent processes.
    ///
    /// Includes Baseline blocks, plus:
    /// - All network syscalls (`socket`, `connect`, `bind`, `listen`, etc.)
    /// - `mount`, `umount`, `umount2` (filesystem manipulation)
    /// - `setuid`, `setgid`, `setgroups` (privilege escalation)
    /// - `memfd_create` (anonymous memory files)
    ///
    /// Note: This does NOT block filesystem read/write syscalls. Agents can
    /// still access files through normal means. Use other mechanisms (like
    /// Landlock or mount namespaces) for filesystem access control.
    Restricted,

    /// Strict filtering - maximum restriction.
    ///
    /// Includes Restricted blocks, plus:
    /// - `execve`, `execveat` (new process execution)
    /// - `fork`, `vfork`, `clone`, `clone3` (process creation)
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

// Platform-specific implementation (x86_64 Linux only)
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod linux;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub use linux::{CompiledSeccompFilter, apply_seccomp_filter, compile_seccomp_filter};

// Stub implementation for non-Linux or non-x86_64 platforms
#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
mod stub;

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
pub use stub::apply_seccomp_filter;

// Stub types for non-Linux platforms
#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
/// Placeholder for compiled filter on non-Linux platforms.
#[derive(Clone)]
pub struct CompiledSeccompFilter;

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
impl CompiledSeccompFilter {
    /// No-op apply on non-Linux platforms.
    pub fn apply(&self) -> Result<SeccompResult, SeccompError> {
        Ok(SeccompResult {
            applied: false,
            level: SeccompProfileLevel::None,
            blocked_syscall_count: 0,
            summary: "Seccomp not available on this platform".to_string(),
        })
    }
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
/// No-op compile on non-Linux platforms.
pub fn compile_seccomp_filter(
    _profile: &SeccompProfile,
) -> Result<Option<CompiledSeccompFilter>, SeccompError> {
    Ok(None)
}

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
