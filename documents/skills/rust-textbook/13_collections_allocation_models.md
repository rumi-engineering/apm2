# 13 — Collections and Allocation Models (Address Stability and Size Discipline)

[INVARIANT: INV-1301] Moving Storage Invalidates References.
- `Vec`/`String` reallocation moves elements/bytes.
- REJECT IF: APIs return references into moving storage while also permitting mutation that can reallocate without lifetime coupling that forbids the mutation.
- ENFORCE BY: borrow tying (`&self` vs `&mut self`); indices/handles; chunked arenas; slabs with stable handles.
[PROVENANCE] std docs: `Vec` and `String` capacity growth implies reallocation and movement.

[HAZARD: RSK-1301] Use-After-Realloc via Stale Pointers/References.
- TRIGGER: storing raw pointers into `Vec`/`String` buffers across pushes/reserves; returning slices and later mutating the backing buffer.
- FAILURE MODE: stale pointer dereference (UB if unsafe); logic corruption in safe code.
- REJECT IF: any pointer/reference escapes without a proof it cannot be invalidated.
- ENFORCE BY: avoid raw pointers into moving buffers; make reallocation impossible for the borrow lifetime; use `Pin` only with explicit invariants.
[PROVENANCE] Rust Abstract Machine reference validity (INV-0004); std docs for `Vec`/`String`.
[VERIFICATION] Miri for unsafe pointer dereference; tests that force reallocation paths.

[CONTRACT: CTR-1301] Identity Strategy Must Match Invariants.
- Stable address required: use non-moving storage or indirection.
- Stable identity required: use handles; add generation counters when reuse is possible.
- Bulk free/reset required: bump arenas with explicit lifetime boundary.
- REJECT IF: identity assumptions are implicit (pointer address equality, index reuse without generation).
[PROVENANCE] Stable identity is not implied by Rust collections; it is a design contract.

[HAZARD: RSK-1302] Size Math and Allocation Are Attacker-Controlled at Boundaries.
- TRIGGER: parsing lengths from inputs; `len * size_of::<T>()` computations; `reserve`/`with_capacity` from untrusted sizes.
- FAILURE MODE: integer overflow; oversized allocation; quadratic behavior due to repeated growth.
- REJECT IF: size computations are unchecked in boundary code.
- ENFORCE BY: `checked_*` arithmetic; explicit caps; amortization control (`reserve_exact` policy) where required.
[PROVENANCE] Rust Reference: overflow behavior differs by build; correctness requires explicit checked math where overflow is a risk.
[VERIFICATION] Property tests for size boundaries; fuzzers for parsers; overflow-focused tests.

[HAZARD: RSK-1303] Hash Iteration Order Is Nondeterministic.
- FAILURE MODE: flaky tests; unstable serialization/spec drift.
- REJECT IF: tests/specs rely on hash iteration order.
- ENFORCE BY: sort keys; use ordered maps/sets for deterministic output; define ordering in the format contract.
[PROVENANCE] std docs: hash maps do not guarantee iteration order.
[VERIFICATION] Deterministic snapshot tests that sort before asserting.

## References (Normative Anchors)

- std `Vec`: https://doc.rust-lang.org/std/vec/struct.Vec.html
- std `String`: https://doc.rust-lang.org/std/string/struct.String.html
- Rust Reference: Behavior considered undefined (invalid dereference): https://doc.rust-lang.org/reference/behavior-considered-undefined.html
