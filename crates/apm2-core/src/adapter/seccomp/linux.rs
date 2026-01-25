//! Linux-specific seccomp BPF implementation (`x86_64` only).
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
// Using libc constants where available, hardcoded values for newer syscalls.
// See: /usr/include/asm/unistd_64.h or `ausyscall --dump`
mod syscall {
    // Process control - dangerous
    pub const PTRACE: i64 = libc::SYS_ptrace;
    pub const PROCESS_VM_READV: i64 = libc::SYS_process_vm_readv;
    pub const PROCESS_VM_WRITEV: i64 = libc::SYS_process_vm_writev;

    // System control - dangerous
    pub const REBOOT: i64 = libc::SYS_reboot;
    pub const KEXEC_LOAD: i64 = libc::SYS_kexec_load;
    pub const KEXEC_FILE_LOAD: i64 = libc::SYS_kexec_file_load;

    // Kernel modules - dangerous
    pub const INIT_MODULE: i64 = libc::SYS_init_module;
    pub const DELETE_MODULE: i64 = libc::SYS_delete_module;
    pub const FINIT_MODULE: i64 = libc::SYS_finit_module;

    // Filesystem escape - dangerous
    pub const PIVOT_ROOT: i64 = libc::SYS_pivot_root;
    pub const CHROOT: i64 = libc::SYS_chroot;
    pub const MOUNT: i64 = libc::SYS_mount;
    pub const UMOUNT2: i64 = libc::SYS_umount2;

    // BPF and advanced kernel features - dangerous
    pub const BPF: i64 = libc::SYS_bpf;
    pub const USERFAULTFD: i64 = libc::SYS_userfaultfd;
    pub const UNSHARE: i64 = libc::SYS_unshare;

    // Privilege escalation - dangerous
    pub const SETUID: i64 = libc::SYS_setuid;
    pub const SETGID: i64 = libc::SYS_setgid;
    pub const SETGROUPS: i64 = libc::SYS_setgroups;
    pub const SETREUID: i64 = libc::SYS_setreuid;
    pub const SETREGID: i64 = libc::SYS_setregid;
    pub const SETRESUID: i64 = libc::SYS_setresuid;
    pub const SETRESGID: i64 = libc::SYS_setresgid;
    pub const SETFSUID: i64 = libc::SYS_setfsuid;
    pub const SETFSGID: i64 = libc::SYS_setfsgid;

    // Network syscalls - blocked at Restricted level
    pub const SOCKET: i64 = libc::SYS_socket;
    pub const CONNECT: i64 = libc::SYS_connect;
    pub const ACCEPT: i64 = libc::SYS_accept;
    pub const SENDTO: i64 = libc::SYS_sendto;
    pub const RECVFROM: i64 = libc::SYS_recvfrom;
    pub const SENDMSG: i64 = libc::SYS_sendmsg;
    pub const RECVMSG: i64 = libc::SYS_recvmsg;
    pub const BIND: i64 = libc::SYS_bind;
    pub const LISTEN: i64 = libc::SYS_listen;
    pub const GETSOCKNAME: i64 = libc::SYS_getsockname;
    pub const GETPEERNAME: i64 = libc::SYS_getpeername;
    pub const SOCKETPAIR: i64 = libc::SYS_socketpair;
    pub const SETSOCKOPT: i64 = libc::SYS_setsockopt;
    pub const GETSOCKOPT: i64 = libc::SYS_getsockopt;
    pub const ACCEPT4: i64 = libc::SYS_accept4;
    pub const RECVMMSG: i64 = libc::SYS_recvmmsg;
    pub const SENDMMSG: i64 = libc::SYS_sendmmsg;

    // Memory-related dangerous syscalls
    pub const MEMFD_CREATE: i64 = libc::SYS_memfd_create;

    // io_uring syscalls (newer, may not be in all libc versions)
    // These are hardcoded for x86_64 as they may not be in older libc
    pub const IO_URING_SETUP: i64 = 425;
    pub const IO_URING_ENTER: i64 = 426;
    pub const IO_URING_REGISTER: i64 = 427;

    // Process creation - blocked at Strict level
    pub const FORK: i64 = libc::SYS_fork;
    pub const VFORK: i64 = libc::SYS_vfork;
    pub const CLONE: i64 = libc::SYS_clone;
    pub const CLONE3: i64 = libc::SYS_clone3;
    pub const EXECVE: i64 = libc::SYS_execve;
    pub const EXECVEAT: i64 = libc::SYS_execveat;
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
    //
    // Note: This is a BLOCKLIST approach - we block specific syscalls and allow
    // everything else. This is less secure than a whitelist but more practical
    // for general-purpose agent processes.
    let filter = SeccompFilter::new(
        rules,
        block_action,         // Action for rules that match (blocked syscalls)
        SeccompAction::Allow, // Default action (allow everything else)
        TargetArch::x86_64,   // Hardcoded to x86_64 - this module only supports x86_64
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
        // Baseline: dangerous syscalls that most processes should never need
        blocked.extend([
            // Process inspection/debugging
            syscall::PTRACE,
            syscall::PROCESS_VM_READV,
            syscall::PROCESS_VM_WRITEV,
            // System control
            syscall::REBOOT,
            syscall::KEXEC_LOAD,
            syscall::KEXEC_FILE_LOAD,
            // Kernel modules
            syscall::INIT_MODULE,
            syscall::DELETE_MODULE,
            syscall::FINIT_MODULE,
            // Filesystem escape
            syscall::PIVOT_ROOT,
            syscall::CHROOT,
            // Advanced kernel features
            syscall::BPF,
            syscall::USERFAULTFD,
            syscall::UNSHARE,
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
            // Memory/file tricks
            syscall::MEMFD_CREATE,
            // io_uring (bypass for many restrictions)
            syscall::IO_URING_SETUP,
            syscall::IO_URING_ENTER,
            syscall::IO_URING_REGISTER,
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
        assert!(blocked.contains(&syscall::BPF));
        assert!(blocked.contains(&syscall::USERFAULTFD));
        assert!(blocked.contains(&syscall::UNSHARE));

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
        assert!(blocked.contains(&syscall::BPF));

        // Should block network syscalls
        assert!(blocked.contains(&syscall::SOCKET));
        assert!(blocked.contains(&syscall::CONNECT));
        assert!(blocked.contains(&syscall::BIND));
        assert!(blocked.contains(&syscall::LISTEN));

        // Should block privilege escalation
        assert!(blocked.contains(&syscall::SETUID));
        assert!(blocked.contains(&syscall::SETGID));

        // Should block io_uring
        assert!(blocked.contains(&syscall::IO_URING_SETUP));
        assert!(blocked.contains(&syscall::IO_URING_ENTER));
        assert!(blocked.contains(&syscall::IO_URING_REGISTER));

        // Should block memfd_create
        assert!(blocked.contains(&syscall::MEMFD_CREATE));

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
        assert!(blocked.contains(&syscall::IO_URING_SETUP));

        // Should block process creation
        assert!(blocked.contains(&syscall::FORK));
        assert!(blocked.contains(&syscall::VFORK));
        assert!(blocked.contains(&syscall::CLONE));
        assert!(blocked.contains(&syscall::CLONE3));
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
