# 15 — Paths, Filesystems, OS Boundaries (Portability and TOCTOU)

[CONTRACT: CTR-1501] Paths Are Not UTF-8 Strings.
- REJECT IF: APIs force `Path` through UTF-8 without a contract requirement.
- ENFORCE BY: `Path`/`PathBuf` and `OsStr`/`OsString` at boundaries; convert to UTF-8 only where explicitly required.
[PROVENANCE] std path and OS string types exist to represent platform-native encodings.

[HAZARD: RSK-1501] Canonicalization as a Security Decision (TOCTOU).
- TRIGGER: `canonicalize()` used for access control, sandboxing, or path validation.
- FAILURE MODE: symlink races; path meaning changes between check and use.
- REJECT IF: canonicalization is used as a security primitive without an open-by-handle strategy.
- ENFORCE BY: avoid check-then-open; use OS-specific safe-open patterns; treat symlink traversal explicitly.
[PROVENANCE] Filesystem operations are inherently racy; std `canonicalize` resolves symlinks and performs I/O.
[VERIFICATION] Integration tests with symlink race harnesses where feasible; platform-specific tests for safe-open behavior.

[CONTRACT: CTR-1503] Symlink Awareness and Rejection.
- REJECT IF: security-sensitive operations follow symlinks without an explicit policy.
- ENFORCE BY:
  - use `symlink_metadata()` to detect symlinks before access.
  - reject symlinks at the boundary for workspace-confined paths.
[PROVENANCE] APM2 Security Policy; CTR-2609.

```rust
// Pattern: Reject if symlink
pub fn reject_if_any_symlink(path: &Path) -> io::Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "symlink disallowed"));
    }
    Ok(())
}
```

[HAZARD: RSK-1502] Predictable Temp File Names and Permissions.
- TRIGGER: Uses of `std::env::temp_dir()` or direct `/tmp/` paths with predictable names.
- FAILURE MODE: symlink attacks; race conditions; information disclosure via world-readable permissions; state leakage via missing cleanup.
- REJECT IF: temp paths are derived from PID/time/user input in shared temp directories.
- ENFORCE BY:
  - use `tempfile::NamedTempFile` or `TempDir` (provides unpredictable names, 0600 permissions, and RAII cleanup).
  - explicitly manage cleanup in error handlers if manual temp files are used.
  - verify no sensitive data (keys, prompts) is written to predictable paths.
[PROVENANCE] APM2 Security Policy; CTR-2607.

[CONTRACT: CTR-1504] Path Sanitization and Traversal Rejection.
- REJECT IF: untrusted paths are used without sanitizing `..` components or absolute path prefixes.
- ENFORCE BY:
  - normalize paths and check against an allowed root.
  - iterate over `components()` and reject `ParentDir`, `RootDir`, or `Prefix`.
  - protect against symlink tricks in workspace-confined paths.
[PROVENANCE] APM2 Security Policy; CTR-2609.

[CONTRACT: CTR-1505] Permissions and Secret Leakage.
- REJECT IF: secret material (keys, session tokens) appears in logs or error dumps.
- REJECT IF: key files are created with permissive (non-0600) permissions.
- ENFORCE BY: `secrecy` crate; explicit `umask` or restrictive `mode` at create-time; filter logs for sensitive patterns.
[PROVENANCE] SECRETS_MANAGEMENT.md; CTR-2611.

```rust
// Pattern: Path Sanitization
pub fn sanitize_relative_path(p: &Path) -> Result<PathBuf, Error> {
    if p.is_absolute() { return Err(Error::NotRelative); }
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            Component::Normal(seg) => out.push(seg),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(Error::ForbiddenComponent)
            }
        }
    }
    Ok(out)
}
```

[CONTRACT: CTR-1502] Atomic Write Protocol for State Files.
- REJECT IF: files are written in-place when partial writes can corrupt state.
- ENFORCE BY: write-to-temp, fsync (when durability required), atomic rename, permission/ownership management.
[PROVENANCE] std filesystem APIs provide rename; atomicity is platform-dependent and must be treated as a contract.

[INVARIANT: INV-1501] Resource Lifetime Discipline.
- REJECT IF: OS handles can leak across error paths or panics.
- ENFORCE BY: RAII; explicit scope boundaries; avoid hidden global handles.
[PROVENANCE] Drop closes resources; drop order is defined by scopes.
[VERIFICATION] Tests that force early returns and panics; leak detection tooling where available.

## References (Normative Anchors)

- std path module: https://doc.rust-lang.org/std/path/
- std fs module: https://doc.rust-lang.org/std/fs/
