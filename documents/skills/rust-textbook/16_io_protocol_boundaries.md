# 16 — I/O and Protocol Boundaries (Partial Progress and Untrusted Inputs)

[INVARIANT: INV-1601] Partial Progress Is the Default at I/O Boundaries.
- Reads may return fewer bytes than requested.
- Writes may write fewer bytes than provided.
- REJECT IF: code assumes "one call == full transfer" without using an API that promises it.
- ENFORCE BY: looped read/write protocols; explicit framing; use `read_exact`/`write_all` only when their semantics match the contract.
[PROVENANCE] std I/O docs: read/write semantics allow partial progress.
[VERIFICATION] Tests with artificial short reads/writes (mock streams); property tests for framing.

[CONTRACT: CTR-1601] Protocol Framing Is a First-Class Contract.
- REJECT IF: boundary formats are implicit (no length prefix, delimiter rules, versioning).
- ENFORCE BY: explicit frame format; version fields; max-size caps; deterministic encoding.
[PROVENANCE] Protocol correctness requires explicit framing; std does not impose framing.

[HAZARD: RSK-1601] Parsing Is a DoS Surface Even in Safe Rust.
- FAILURE MODE: quadratic behavior, oversized allocations, deep recursion (stack exhaustion), panic-as-DoS.
- REJECT IF: parsers allocate based on untrusted lengths without caps.
- REJECT IF: parsers use recursion without depth limits.
- ENFORCE BY: checked arithmetic; allocation caps; iterative parsing; explicit error returns.
[PROVENANCE] Rust memory safety does not prevent resource-exhaustion attacks.
[VERIFICATION] Fuzzing (mutation and structure-aware when available); property tests for size/depth bounds.

[CONTRACT: CTR-1602] Serialization Formats Must Be Versioned and Endianness-Specified.
- REJECT IF: a persisted/wire format depends on Rust layout (`repr(Rust)` or enum niches).
- ENFORCE BY: explicit byte-level format; endianness and alignment rules; backward compatibility tests.
[PROVENANCE] Rust Reference: layout is unspecified unless constrained; persistence requires explicit format contracts.
[VERIFICATION] Golden test vectors; backward/forward compatibility tests across versions.

## References (Normative Anchors)

- std I/O module: https://doc.rust-lang.org/std/io/
- Rust Reference: type layout is largely unspecified: https://doc.rust-lang.org/reference/type-layout.html
