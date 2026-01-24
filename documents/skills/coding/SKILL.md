---
name: coding-standards
description: Safe Rust patterns, CI expectations, and security protocols for APM2 development. Reference during implementation.
user-invocable: false
---

# APM2 Coding Standards

This skill provides coding guidelines for APM2 development. Reference these during implementation to ensure safe, consistent code.

## Quick Reference Checklist

When writing new code, ask yourself:

- [ ] **Shared state?** Use `Arc<RwLock<T>>` instead of raw pointers or global mutable state
- [ ] **Multiple ID types?** Use newtype wrappers to prevent mixing them up
- [ ] **Complex construction?** Use the builder pattern with validation
- [ ] **Sensitive data?** Use `SecretString` from the `secrecy` crate
- [ ] **Distinct states?** Use an enum with predicate methods
- [ ] **Fallible operation?** Return `Result<T, E>` with a custom error type
- [ ] **File writes?** Use write-then-rename for atomicity
- [ ] **Retry logic?** Implement a circuit breaker to prevent runaway failures
- [ ] **Return value matters?** Add `#[must_use]` to the function

If you find yourself reaching for `unsafe`:
1. Stop and search for a safe crate that wraps the functionality
2. Check if std library provides a safe alternative
3. If truly necessary, follow the isolation and documentation patterns in UNSAFE_CODE_POLICY.md
4. Request review from a maintainer before merging

## Reference Documents

| Document | When to Consult |
|----------|-----------------|
| [SAFE_RUST_PATTERNS.md](references/SAFE_RUST_PATTERNS.md) | Implementing new features; need safe patterns for common scenarios |
| [UNSAFE_CODE_POLICY.md](references/UNSAFE_CODE_POLICY.md) | Considering `unsafe` code; need to understand policy and isolation requirements |
| [CI_EXPECTATIONS.md](references/CI_EXPECTATIONS.md) | CI failures; need to understand checks and fix procedures |
| [SECURITY_CHECKLIST.md](references/SECURITY_CHECKLIST.md) | Handling secrets, paths, or cryptographic data |

## Workspace Lint Configuration

APM2 enforces safe code through workspace-level lints in `Cargo.toml`:

```toml
[workspace.lints.rust]
unsafe_code = "warn"
```

This causes the compiler to emit warnings for any `unsafe` blocks, ensuring they are intentional and reviewed.
