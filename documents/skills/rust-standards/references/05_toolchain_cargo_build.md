# 02 — Toolchain, Cargo, Builds (Reproducibility and Build-Surface Control)

This chapter is intentionally “process-heavy” because in Rust the build system is part of the TCB:
Cargo resolves code, runs build scripts, runs proc-macros, and selects feature sets.

---

[CONTRACT: CTR-0201] Two-Toolchain Contract (Compatibility vs Tooling).
- APM2 distinguishes:
  - **MSRV toolchain**: the minimum stable compiler the workspace claims to support (`package.rust-version`).
  - **Tooling toolchain**: a pinned toolchain used to run extended tooling (Miri / llvm-cov / etc).
- REJECT IF: the workspace compiles only on the tooling toolchain and silently violates MSRV.
- ENFORCE BY:
  - keep `package.rust-version` accurate and enforced by CI (`cargo +<MSRV> check`),
  - allow a pinned nightly for tooling, but keep the codebase free of nightly-only language features unless explicitly contracted.
[PROVENANCE] Cargo `rust-version` defines the declared toolchain floor; some tools (Miri / llvm-tools) require nightly.
[VERIFICATION] APM2 CI runs an MSRV check plus tool-extended checks (see `scripts/ci/run_local_ci_orchestrator.sh`).

[CONTRACT: CTR-0202] Toolchain Pin Changes Are Security/Correctness Changes.
- TRIGGER: changes to `rust-toolchain.toml`, `Cargo.toml` workspace lints, `deny.toml`, `Cargo.lock`.
- REJECT IF: toolchain pins are changed without:
  - a plan-of-record (ticket/RFC),
  - a rationale (what bug/security issue is fixed),
  - and CI evidence that the full suite still passes.
- ENFORCE BY: treat toolchain pin updates as QCP (see `M02`).
[PROVENANCE] Toolchain changes affect codegen, lint behavior, UB diagnostics, and supply-chain surfaces.

[HAZARD: RSK-0201] Feature Unification and Hidden `std`/Build Surfaces.
- FAILURE MODE: dependency default-features pull `std`, heavy graphs, build scripts, proc macros.
- REJECT IF: dependency default-features are enabled without explicit justification.
- ENFORCE BY: `default-features = false` on dependencies; explicit feature wiring; minimal feature sets tested.
[PROVENANCE] Cargo book: features and feature resolution.
[VERIFICATION] CI: defaults, `--no-default-features`, `--all-features`, plus curated feature combinations when feature count is non-trivial.

[INVARIANT: INV-0201] Profile-Independent Correctness.
- REJECT IF: correctness depends on debug-only behavior (`debug_assert!`, overflow-checking expectations, `cfg(debug_assertions)`).
- ENFORCE BY: treat `debug_assert!` as diagnostics only; enforce invariants at runtime where required; design APIs so invalid states are unrepresentable.
[PROVENANCE] Rust Reference: no optimization/codegen guarantees; behavior differences exist across profiles.
[VERIFICATION] CI: test in debug and release for crates with unsafe/concurrency risk anchors.

[HAZARD: RSK-0202] Build Scripts Are Host Code Execution.
- TRIGGER: `build.rs`, `links = ...`, `cargo:rustc-cfg=...`, `cargo:rustc-env=...`, bindgen.
- FAILURE MODE: nondeterministic builds; supply-chain risk; environment-dependent compilation.
- REJECT IF: build scripts read ambient environment or filesystem without a declared input set.
- REJECT IF: build scripts perform network I/O.
- ENFORCE BY: strict input surface (Cargo-provided env only); deterministic outputs; minimized deps; documented `cargo:` outputs.
[PROVENANCE] Cargo book: build scripts; rerun-if-* semantics.
[VERIFICATION] CI in restricted environment; committed generated outputs guarded by a diff check (when applicable).

[HAZARD: RSK-0203] Proc Macros Are Host Code Execution + Code Generation.
- TRIGGER: proc-macro crates; derive/attribute macros.
- FAILURE MODE: hidden allocations/IO; hidden `unsafe`; expansion drift across versions.
- REJECT IF: proc macros introduce semantic logic that cannot be validated by compile tests.
- ENFORCE BY: minimal proc-macro dependency graph; expansion tests; keep proc macros syntactic where possible.
[PROVENANCE] Rust Reference: procedural macros (conceptual); Cargo book: proc-macro crates and build phases.
[VERIFICATION] CI: compile-pass/compile-fail tests; expansion inspection in a trusted environment (e.g. `cargo expand`) when needed.

[CONTRACT: CTR-0203] Lockfile and Dependency Graph Are Part of the Artifact.
- REJECT IF: `Cargo.lock` is removed or large lockfile churn is introduced without a dependency rationale.
- ENFORCE BY: commit `Cargo.lock` for the workspace; use `cargo deny` and `cargo audit` gates.
[PROVENANCE] Reproducible builds require a pinned dependency graph.

[CONTRACT: CTR-0204] rustdoc and doctests are public API.
- REJECT IF: public APIs lack usage examples when the safe usage protocol is non-obvious.
- REJECT IF: doctests are not executed in CI.
- ENFORCE BY: doctestable examples that encode correct usage; deny rustdoc warnings for public surfaces.
[PROVENANCE] Rustdoc documentation and doctest execution model.
[VERIFICATION] `cargo test --doc` and `cargo doc -D warnings` in CI.

[CONTRACT: CTR-0205] CI Is the Ground-Truth Execution Environment.
- REJECT IF: acceptance depends on local, ad-hoc execution of untrusted code.
- ENFORCE BY: treat the CI orchestrator as authoritative for merges.
[PROVENANCE] APM2 runs a canonical check suite (see `scripts/ci/run_local_ci_orchestrator.sh`).

---

## APM2 canonical check surface (informative)

The local CI orchestrator documents the expected gate set and is the best “single source” for what counts as a passing Rust change.

Expected gates include (non-exhaustive):
- `cargo fmt --check`
- `cargo clippy ... -D warnings`
- `cargo doc -D warnings`
- `cargo nextest run ...`
- `cargo test --doc`
- `cargo +<MSRV> check --workspace --all-features`
- `cargo deny check all`
- `cargo audit ...`
- `cargo llvm-cov ...`
- `cargo build --release`

## References (Normative Anchors)

- Cargo book: https://doc.rust-lang.org/cargo/
- Cargo build scripts: https://doc.rust-lang.org/cargo/reference/build-scripts.html
- Rust Reference: Conditional compilation: https://doc.rust-lang.org/reference/conditional-compilation.html
- Rustdoc: https://doc.rust-lang.org/rustdoc/
