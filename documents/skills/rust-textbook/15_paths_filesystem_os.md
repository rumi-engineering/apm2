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
