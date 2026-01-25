//! Linux-specific seccomp BPF implementation.
//!
//! This module provides the actual seccomp filter implementation using
//! the Linux kernel's seccomp-bpf facility. It must be applied in a
//! `pre_exec` hook before the child process executes the target program.
//!
//! # Safety
//!
//! The seccomp filter uses raw syscalls and BPF bytecode. The filter
//! is constructed using the `seccompiler` crate which validates the
//! BPF program at compile time.
//!
//! # Kernel Requirements
//!
//! - Kernel 3.5+ for basic seccomp-bpf support
//! - Kernel 4.14+ for `SECCOMP_RET_LOG` support (violation logging)
//! - Kernel 4.17+ for `SECCOMP_RET_KILL_PROCESS` (vs `KILL_THREAD`)

use std::collections::BTreeMap;

use super::{SeccompError, SeccompProfile, SeccompProfileLevel, SeccompResult};

// Syscall numbers for x86_64 Linux
// See: /usr/include/asm/unistd_64.h or `ausyscall --dump`
mod syscall {
    // Process control - dangerous
    pub const PTRACE: i64 = 101;
    pub const PROCESS_VM_READV: i64 = 310;
    pub const PROCESS_VM_WRITEV: i64 = 311;

    // System control - dangerous
    pub const REBOOT: i64 = 169;
    pub const KEXEC_LOAD: i64 = 246;
    pub const KEXEC_FILE_LOAD: i64 = 320;

    // Kernel modules - dangerous
    pub const INIT_MODULE: i64 = 175;
    pub const DELETE_MODULE: i64 = 176;
    pub const FINIT_MODULE: i64 = 313;

    // Filesystem escape - dangerous
    pub const PIVOT_ROOT: i64 = 155;
    pub const CHROOT: i64 = 161;
    pub const MOUNT: i64 = 165;
    pub const UMOUNT2: i64 = 166;

    // Privilege escalation - dangerous
    pub const SETUID: i64 = 105;
    pub const SETGID: i64 = 106;
    pub const SETGROUPS: i64 = 116;
    pub const SETREUID: i64 = 113;
    pub const SETREGID: i64 = 114;
    pub const SETRESUID: i64 = 117;
    pub const SETRESGID: i64 = 119;
    pub const SETFSUID: i64 = 122;
    pub const SETFSGID: i64 = 123;

    // Network syscalls - blocked at Restricted level
    pub const SOCKET: i64 = 41;
    pub const CONNECT: i64 = 42;
    pub const ACCEPT: i64 = 43;
    pub const SENDTO: i64 = 44;
    pub const RECVFROM: i64 = 45;
    pub const SENDMSG: i64 = 46;
    pub const RECVMSG: i64 = 47;
    pub const BIND: i64 = 49;
    pub const LISTEN: i64 = 50;
    pub const GETSOCKNAME: i64 = 51;
    pub const GETPEERNAME: i64 = 52;
    pub const SOCKETPAIR: i64 = 53;
    pub const SETSOCKOPT: i64 = 54;
    pub const GETSOCKOPT: i64 = 55;
    pub const ACCEPT4: i64 = 288;
    pub const RECVMMSG: i64 = 299;
    pub const SENDMMSG: i64 = 307;

    // Process creation - blocked at Strict level
    pub const FORK: i64 = 57;
    pub const VFORK: i64 = 58;
    pub const CLONE: i64 = 56;
    pub const CLONE3: i64 = 435;
    pub const EXECVE: i64 = 59;
    pub const EXECVEAT: i64 = 322;
}

/// Applies the seccomp filter to the current process.
///
/// This function should be called in a `pre_exec` hook before executing
/// the target program. Once applied, the filter cannot be removed or
/// relaxed (only made more restrictive).
///
/// # Errors
///
/// Returns an error if:
/// - The filter cannot be compiled (should not happen with valid profiles)
/// - The `prctl` syscall fails to apply the filter
/// - The kernel does not support seccomp-bpf
///
/// # Safety
///
/// This function applies kernel-level restrictions that cannot be undone.
/// After calling this function, any blocked syscall will terminate the
/// process immediately with SIGSYS.
pub fn apply_seccomp_filter(profile: &SeccompProfile) -> Result<SeccompResult, SeccompError> {
    use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, SeccompRule, TargetArch};

    if !profile.is_enforced() {
        return Ok(SeccompResult {
            applied: false,
            level: profile.level,
            blocked_syscall_count: 0,
            summary: "No seccomp filter applied (level=none)".to_string(),
        });
    }

    // Build the list of blocked syscalls based on profile level
    let blocked_syscalls = get_blocked_syscalls(profile.level);
    let blocked_count = blocked_syscalls.len();

    // Create rules map: syscall number -> rules
    // Empty rules vec means unconditional match (block this syscall)
    let rules: BTreeMap<i64, Vec<SeccompRule>> = blocked_syscalls
        .into_iter()
        .map(|nr| (nr, vec![]))
        .collect();

    // Determine the action for blocked syscalls
    let block_action = if profile.log_violations {
        // SECCOMP_RET_TRAP sends SIGSYS which can be caught and logged
        SeccompAction::Trap
    } else {
        // SECCOMP_RET_KILL_PROCESS terminates immediately
        SeccompAction::KillProcess
    };

    // Build the filter
    // match_action: action taken when a rule matches (blocked syscalls)
    // mismatch_action: default action when no rule matches (allow everything else)
    let filter = SeccompFilter::new(
        rules,
        block_action,         // Action for rules that match (blocked syscalls)
        SeccompAction::Allow, // Default action (allow everything else)
        TargetArch::x86_64,
    )
    .map_err(|e| SeccompError::new(format!("failed to create seccomp filter: {e}")))?;

    // Compile to BPF program
    let bpf_prog: BpfProgram = filter.try_into().map_err(|e: seccompiler::BackendError| {
        SeccompError::new(format!("failed to compile BPF program: {e}"))
    })?;

    // Apply the filter
    seccompiler::apply_filter(&bpf_prog)
        .map_err(|e| SeccompError::new(format!("failed to apply seccomp filter: {e}")))?;

    let level_name = profile.level.name();
    let summary =
        format!("Seccomp filter applied: level={level_name}, blocked={blocked_count} syscalls");

    Ok(SeccompResult {
        applied: true,
        level: profile.level,
        blocked_syscall_count: blocked_count,
        summary,
    })
}

/// Returns the list of syscalls to block for a given profile level.
fn get_blocked_syscalls(level: SeccompProfileLevel) -> Vec<i64> {
    let mut blocked = Vec::new();

    if matches!(
        level,
        SeccompProfileLevel::Baseline
            | SeccompProfileLevel::Restricted
            | SeccompProfileLevel::Strict
    ) {
        // Baseline: dangerous syscalls
        blocked.extend([
            syscall::PTRACE,
            syscall::PROCESS_VM_READV,
            syscall::PROCESS_VM_WRITEV,
            syscall::REBOOT,
            syscall::KEXEC_LOAD,
            syscall::KEXEC_FILE_LOAD,
            syscall::INIT_MODULE,
            syscall::DELETE_MODULE,
            syscall::FINIT_MODULE,
            syscall::PIVOT_ROOT,
            syscall::CHROOT,
        ]);
    }

    if matches!(
        level,
        SeccompProfileLevel::Restricted | SeccompProfileLevel::Strict
    ) {
        // Restricted: network and privilege syscalls
        blocked.extend([
            // Network
            syscall::SOCKET,
            syscall::CONNECT,
            syscall::ACCEPT,
            syscall::SENDTO,
            syscall::RECVFROM,
            syscall::SENDMSG,
            syscall::RECVMSG,
            syscall::BIND,
            syscall::LISTEN,
            syscall::GETSOCKNAME,
            syscall::GETPEERNAME,
            syscall::SOCKETPAIR,
            syscall::SETSOCKOPT,
            syscall::GETSOCKOPT,
            syscall::ACCEPT4,
            syscall::RECVMMSG,
            syscall::SENDMMSG,
            // Filesystem manipulation
            syscall::MOUNT,
            syscall::UMOUNT2,
            // Privilege
            syscall::SETUID,
            syscall::SETGID,
            syscall::SETGROUPS,
            syscall::SETREUID,
            syscall::SETREGID,
            syscall::SETRESUID,
            syscall::SETRESGID,
            syscall::SETFSUID,
            syscall::SETFSGID,
        ]);
    }

    if matches!(level, SeccompProfileLevel::Strict) {
        // Strict: process creation
        blocked.extend([
            syscall::FORK,
            syscall::VFORK,
            syscall::CLONE,
            syscall::CLONE3,
            syscall::EXECVE,
            syscall::EXECVEAT,
        ]);
    }

    blocked
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blocked_syscalls_baseline() {
        let blocked = get_blocked_syscalls(SeccompProfileLevel::Baseline);

        // Should block dangerous syscalls
        assert!(blocked.contains(&syscall::PTRACE));
        assert!(blocked.contains(&syscall::REBOOT));
        assert!(blocked.contains(&syscall::KEXEC_LOAD));
        assert!(blocked.contains(&syscall::INIT_MODULE));

        // Should NOT block network syscalls at baseline
        assert!(!blocked.contains(&syscall::SOCKET));
        assert!(!blocked.contains(&syscall::CONNECT));
    }

    #[test]
    fn test_blocked_syscalls_restricted() {
        let blocked = get_blocked_syscalls(SeccompProfileLevel::Restricted);

        // Should include baseline blocks
        assert!(blocked.contains(&syscall::PTRACE));
        assert!(blocked.contains(&syscall::REBOOT));

        // Should block network syscalls
        assert!(blocked.contains(&syscall::SOCKET));
        assert!(blocked.contains(&syscall::CONNECT));
        assert!(blocked.contains(&syscall::BIND));
        assert!(blocked.contains(&syscall::LISTEN));

        // Should block privilege escalation
        assert!(blocked.contains(&syscall::SETUID));
        assert!(blocked.contains(&syscall::SETGID));

        // Should NOT block process creation at restricted
        assert!(!blocked.contains(&syscall::FORK));
        assert!(!blocked.contains(&syscall::EXECVE));
    }

    #[test]
    fn test_blocked_syscalls_strict() {
        let blocked = get_blocked_syscalls(SeccompProfileLevel::Strict);

        // Should include restricted blocks
        assert!(blocked.contains(&syscall::SOCKET));
        assert!(blocked.contains(&syscall::SETUID));

        // Should block process creation
        assert!(blocked.contains(&syscall::FORK));
        assert!(blocked.contains(&syscall::VFORK));
        assert!(blocked.contains(&syscall::CLONE));
        assert!(blocked.contains(&syscall::EXECVE));
        assert!(blocked.contains(&syscall::EXECVEAT));
    }

    #[test]
    fn test_blocked_syscalls_none() {
        let blocked = get_blocked_syscalls(SeccompProfileLevel::None);
        assert!(blocked.is_empty());
    }

    #[test]
    fn test_filter_compilation_baseline() {
        // Test that we can compile a filter (without applying it)
        use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, SeccompRule, TargetArch};

        let blocked_syscalls = get_blocked_syscalls(SeccompProfileLevel::Baseline);
        let rules: BTreeMap<i64, Vec<SeccompRule>> = blocked_syscalls
            .into_iter()
            .map(|nr| (nr, vec![]))
            .collect();

        let filter = SeccompFilter::new(
            rules,
            SeccompAction::Trap,
            SeccompAction::Allow,
            TargetArch::x86_64,
        )
        .expect("filter creation should succeed");

        let _bpf_prog: BpfProgram = filter.try_into().expect("BPF compilation should succeed");
    }

    #[test]
    fn test_filter_compilation_restricted() {
        use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, SeccompRule, TargetArch};

        let blocked_syscalls = get_blocked_syscalls(SeccompProfileLevel::Restricted);
        let rules: BTreeMap<i64, Vec<SeccompRule>> = blocked_syscalls
            .into_iter()
            .map(|nr| (nr, vec![]))
            .collect();

        let filter = SeccompFilter::new(
            rules,
            SeccompAction::KillProcess,
            SeccompAction::Allow,
            TargetArch::x86_64,
        )
        .expect("filter creation should succeed");

        let _bpf_prog: BpfProgram = filter.try_into().expect("BPF compilation should succeed");
    }

    #[test]
    fn test_filter_compilation_strict() {
        use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, SeccompRule, TargetArch};

        let blocked_syscalls = get_blocked_syscalls(SeccompProfileLevel::Strict);
        let rules: BTreeMap<i64, Vec<SeccompRule>> = blocked_syscalls
            .into_iter()
            .map(|nr| (nr, vec![]))
            .collect();

        let filter = SeccompFilter::new(
            rules,
            SeccompAction::Trap,
            SeccompAction::Allow,
            TargetArch::x86_64,
        )
        .expect("filter creation should succeed");

        let _bpf_prog: BpfProgram = filter.try_into().expect("BPF compilation should succeed");
    }

    #[test]
    fn test_apply_filter_none_level_does_nothing() {
        // Test that applying a "none" level profile returns without doing anything
        let profile = SeccompProfile::none();
        let result = apply_seccomp_filter(&profile).expect("should succeed for none level");

        assert!(!result.applied);
        assert_eq!(result.level, SeccompProfileLevel::None);
        assert_eq!(result.blocked_syscall_count, 0);
    }

    // Note: We cannot easily test apply_seccomp_filter with actual enforcement
    // in unit tests because:
    // 1. It applies kernel-level restrictions that persist
    // 2. It would affect the test process itself
    // 3. It requires specific kernel capabilities
    //
    // Integration tests should be used to verify filter application in
    // a child process context.
}
