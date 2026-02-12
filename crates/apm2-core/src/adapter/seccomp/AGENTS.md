# Seccomp Module

> Syscall-level sandboxing for agent processes using Linux seccomp-BPF, implementing a blocklist-based, defense-in-depth, fail-closed security model.

## Overview

The `apm2_core::adapter::seccomp` module provides kernel-level syscall filtering for agent processes spawned by the APM2 adapter layer. It sits below the adapter's process spawning and is applied via `pre_exec` hooks before the child process executes the target program.

```text
+-------------------+
|    Supervisor     |
+--------+----------+
         |
+--------v----------+
|  BlackBoxAdapter  |
|   (pre_exec hook) |
+--------+----------+
         | compile_seccomp_filter()
         v
+-------------------+       +-------------------+
| CompiledSeccomp   | --->  | Linux Kernel      |
|     Filter        |       | seccomp-BPF       |
+-------------------+       +-------------------+
         |
         v
+-------------------+
|  Agent Process    |  <-- Blocked syscalls cause SIGSYS or KILL
+-------------------+
```

The module uses a **blocklist approach** (default-allow with specific syscalls blocked) rather than an allowlist, because agent processes are general-purpose and may need a wide range of syscalls. Three tiered restriction levels provide progressive sandboxing:

- **Baseline**: Blocks dangerous kernel-level syscalls (ptrace, kexec, kernel modules, io_uring, BPF)
- **Restricted**: Adds network, filesystem manipulation, privilege escalation, and memfd blocks
- **Strict**: Additionally blocks all process creation (fork, clone, execve)

On non-Linux or non-x86_64 platforms, a no-op stub is provided that always reports "not enforced."

## Key Types

### `SeccompProfileLevel`

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub enum SeccompProfileLevel {
    #[default]
    None,
    Baseline,
    Restricted,
    Strict,
}
```

**Invariants:**

- [INV-SC01] Levels are strictly cumulative: `Restricted` includes all `Baseline` blocks; `Strict` includes all `Restricted` blocks.
- [INV-SC02] `None` applies zero filtering. It is the default and should only be used for debugging or non-Linux platforms.
- [INV-SC03] The enum is `#[non_exhaustive]`, allowing future levels without breaking changes.

**Contracts:**

- [CTR-SC01] `is_enforced()` returns `false` only for `None`; `true` for all other levels.
- [CTR-SC02] `name()` returns a stable, unique string identifier for each level (`"none"`, `"baseline"`, `"restricted"`, `"strict"`).

### `SeccompProfile`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeccompProfile {
    pub level: SeccompProfileLevel,
    pub log_violations: bool,
}
```

**Invariants:**

- [INV-SC04] When `log_violations` is `true`, blocked syscalls use `SECCOMP_RET_TRAP` (sends SIGSYS, can be logged). When `false`, uses `SECCOMP_RET_KILL_PROCESS` (immediate termination).
- [INV-SC05] Default profile is `None` with `log_violations: true`.

**Contracts:**

- [CTR-SC03] Builder methods (`none()`, `baseline()`, `restricted()`, `strict()`) return profiles with `log_violations: true` by default.
- [CTR-SC04] `with_log_violations(bool)` returns a new profile (builder pattern, const-compatible).

### `SeccompError`

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeccompError {
    pub message: String,
    pub syscall: Option<i32>,
}
```

**Contracts:**

- [CTR-SC05] `new(message)` creates an error without syscall context. `with_syscall(i32)` adds syscall context (builder pattern).

### `SeccompResult`

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeccompResult {
    pub applied: bool,
    pub level: SeccompProfileLevel,
    pub blocked_syscall_count: usize,
    pub summary: String,
}
```

**Invariants:**

- [INV-SC06] `applied` is `true` only when a BPF filter was successfully loaded into the kernel. On non-Linux platforms or `None` level, `applied` is always `false`.

### `CompiledSeccompFilter` (Linux x86_64 only)

```rust
#[derive(Clone)]
pub struct CompiledSeccompFilter {
    bpf_prog: seccompiler::BpfProgram,
    level: SeccompProfileLevel,
    blocked_syscall_count: usize,
}
```

**Invariants:**

- [INV-SC07] The compiled BPF program is validated at compile time by the `seccompiler` crate.
- [INV-SC08] `apply()` performs no heap allocations, making it safe for use inside `pre_exec` hooks (async-signal-safe context).

**Contracts:**

- [CTR-SC06] `apply()` calls `prctl(PR_SET_SECCOMP)` and returns `SeccompResult` on success or `SeccompError` on kernel rejection.

## Public API

### `compile_seccomp_filter(profile: &SeccompProfile) -> Result<Option<CompiledSeccompFilter>, SeccompError>`

Compiles a BPF filter program from the given profile. Must be called in the parent process before `fork()`. Returns `Ok(None)` if the profile level is `None`.

### `apply_seccomp_filter(profile: &SeccompProfile) -> Result<SeccompResult, SeccompError>`

Convenience function that compiles and immediately applies a seccomp filter to the current process. **Not async-signal-safe** -- for `pre_exec` hooks, use `compile_seccomp_filter` followed by `CompiledSeccompFilter::apply()`.

### `SeccompProfile::new(level) -> Self`

Creates a profile with the given level and `log_violations: true`.

### `SeccompProfile::{none, baseline, restricted, strict}() -> Self`

Named constructors for each level.

### `SeccompProfileLevel::{is_enforced, name}(&self)`

Query methods for level properties.

## Examples

### Applying a Filter to a Child Process

```rust
use apm2_core::adapter::seccomp::{SeccompProfile, compile_seccomp_filter};

let profile = SeccompProfile::restricted();

// Compile in parent (allocates memory)
let filter = compile_seccomp_filter(&profile)?;

if let Some(compiled) = filter {
    // Apply in pre_exec (no allocations)
    unsafe {
        cmd.pre_exec(move || {
            compiled.apply()
                .map(|_| ())
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
        });
    }
}
```

### Querying Profile Properties

```rust
use apm2_core::adapter::seccomp::{SeccompProfile, SeccompProfileLevel};

let profile = SeccompProfile::strict().with_log_violations(false);

assert!(profile.is_enforced());
assert_eq!(profile.level.name(), "strict");
assert!(!profile.log_violations);
```

## Related Modules

- [`apm2_core::adapter`](../AGENTS.md) - Parent adapter module; seccomp filters are applied during process spawning
- [`apm2_core::supervisor`](../../supervisor/AGENTS.md) - Supervisor that configures adapter security profiles

## References

- [APM2 Rust Standards - Security-Adjacent Rust](/documents/skills/rust-standards/references/34_security_adjacent_rust.md) - Sandboxing and defense-in-depth patterns
- [Linux seccomp(2) man page](https://man7.org/linux/man-pages/man2/seccomp.2.html) - Kernel seccomp-BPF documentation
- [seccompiler crate](https://docs.rs/seccompiler/) - BPF program compilation library used by this module
