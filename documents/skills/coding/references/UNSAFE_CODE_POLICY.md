# Unsafe Code Policy

This document defines when and how `unsafe` code may be used in the APM2 codebase.

## Workspace Lint Configuration

APM2 enforces safe code through workspace-level lints in `Cargo.toml`:

```toml
[workspace.lints.rust]
unsafe_code = "warn"
```

This causes the compiler to emit warnings for any `unsafe` blocks, ensuring they are intentional and reviewed.

---

## When Unsafe is Prohibited

Avoid `unsafe` for:
- Memory management (use standard collections, `Box`, `Arc`, `Rc`)
- Pointer manipulation (use references and slices)
- Type coercion (use `From`/`Into` traits)
- FFI unless absolutely necessary (prefer safe crate wrappers)
- Performance optimization (profile first; safe code is usually fast enough)

---

## When Unsafe May Be Necessary

Unsafe might be justified for:
- System calls with no safe wrapper (e.g., `fork()`)
- Performance-critical hot paths (only after profiling proves necessity)
- Interfacing with C libraries that lack safe Rust bindings

---

## Required Documentation for Unsafe Code

Any `unsafe` block must:
1. Have `#[allow(unsafe_code)]` with a comment explaining why it's necessary
2. Be isolated to the smallest possible scope
3. Use platform gates (`#[cfg(unix)]`) when platform-specific
4. Include a safety comment explaining invariants

Example from our codebase:
```rust
#[allow(unsafe_code)] // fork() requires unsafe
if !args.no_daemon {
    #[cfg(unix)]
    {
        match unsafe { fork() }? {
            // ...
        }
    }
}
```

---

## The fork() Exception: Case Study

The only `unsafe` code in APM2 is the Unix daemonization in `crates/apm2-daemon/src/main.rs:243-274`.

### Why fork() Requires Unsafe

The POSIX `fork()` system call has semantics that cannot be expressed safely in Rust:
- It duplicates the entire process, including memory state
- The parent and child share file descriptors
- Thread safety guarantees are complex

The `nix` crate provides a wrapper, but the call itself is inherently `unsafe`.

### How It's Isolated

```rust
#[allow(unsafe_code)] // fork() requires unsafe
if !args.no_daemon {
    #[cfg(unix)]
    {
        use nix::unistd::{ForkResult, fork, setsid};

        match unsafe { fork() }? {
            ForkResult::Parent { .. } => std::process::exit(0),
            ForkResult::Child => {},
        }

        setsid()?;

        match unsafe { fork() }? {
            ForkResult::Parent { .. } => std::process::exit(0),
            ForkResult::Child => {},
        }
    }
}
```

**Isolation strategies used:**
1. **Smallest scope:** `unsafe` wraps only the `fork()` call, not surrounding logic
2. **Platform-gated:** `#[cfg(unix)]` ensures this only compiles on Unix
3. **Documented:** The `#[allow(unsafe_code)]` comment explains necessity
4. **Fallback:** Non-Unix platforms get a warning and run in foreground

---

## Review Checklist for Unsafe Code

Before adding `unsafe` code, verify:

- [ ] No safe alternative exists (checked crates.io, std library)
- [ ] The unsafe operation is isolated to minimum scope
- [ ] Platform gates are used if platform-specific
- [ ] Safety invariants are documented in comments
- [ ] The `#[allow(unsafe_code)]` annotation includes justification
- [ ] Tests exist for both the happy path and error cases
