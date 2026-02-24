# 26 — APM2 Safe Patterns and Anti-Patterns (Token-Efficient Index)

This chapter replaces the legacy APM2 safe patterns catalog.

Goal: keep project-specific guidance compact and point to deeper contracts in Chapters 07/09/10/12/15/16/19/20/24/25.

## Safe Patterns (Defaults)

[CONTRACT: CTR-2601] Shared Mutable State Uses Standard Primitives.
- REJECT IF: shared mutable state uses ad-hoc interior mutability or custom synchronization without a protocol (CTR-1002).
- ENFORCE BY: `Arc<RwLock<T>>` for read-heavy state; `Arc<Mutex<T>>` otherwise; explicit lock ordering; no guards across `.await` (RSK-1003).

[CONTRACT: CTR-2602] Type-Safe Identifiers (No Raw `String`/`Uuid` for IDs).
- REJECT IF: distinct ID domains share the same primitive type in public APIs (mix-up risk).
- ENFORCE BY: newtypes (`struct ProcessId(Uuid);`) + `FromStr/TryFrom` for parsing; keep constructors validated.
- NOTE: legacy surfaces that currently use `String` IDs are not excused—validation and canonicalization must happen at the boundary; new code should migrate toward newtypes.

[CONTRACT: CTR-2603] Construction Is Validated (Builders/Typestate).
- APPLY: CTR-1205.
- REJECT IF: invalid states are constructible in safe code.

[CONTRACT: CTR-2604] Secrets Are Strongly Typed and Non-Loggable.
- REJECT IF: secrets (keys, tokens, passwords) are passed as `String`, `&str`, or `Vec<u8>` in public APIs.
- REJECT IF: secrets are stored in types that `Debug`/`Display` the raw value.
- ENFORCE BY: `secrecy::Secret<T>` or a custom NewType wrapper that implements `Drop` (zeroize) and `Debug` (redact: `***`).
- ENFORCE BY: `ExposeSecret` only at the I/O boundary.
[PROVENANCE] CTR-1505 (Secret Leakage); Prevent accidental logging (CWE-312).

[CONTRACT: CTR-2605] State Machines Are Explicit Enums With Total Transition Logic.
- REJECT IF: state is modeled as booleans/ints without a closed set of states and explicit transitions.
- REJECT IF: session/process restart logic fails to distinguish "new session" from "resume session" (ID collision risk).
- ENFORCE BY: enum state machine + exhaustive matches; store resume cursors/restart attempts in all state structs; verify restart counters are strictly increasing (`>` not `>=`).
- ENFORCE BY: helper predicates (`is_running`, `has_exited`) are `#[must_use]` (CTR-0704).

[CONTRACT: CTR-2606] Errors Are Typed and Actionable.
- APPLY: CTR-0701/0703.
- ENFORCE BY: `thiserror`-derived enums are acceptable for internal/public error typing; avoid stringly-typed branching.

[CONTRACT: CTR-2607] State Files Use Atomic Write Protocol.
- APPLY: CTR-1502.
- ENFORCE BY: write-to-temp + rename; fsync when durability is required; preserve permissions/ownership.

[CONTRACT: CTR-2608] Retry Loops Have Backoff and a Circuit Breaker.
- REJECT IF: retry loops can spin indefinitely or amplify failures (restart loops, external calls).
- ENFORCE BY: exponential backoff + cap + "circuit open" state with cooldown; record failure history; require explicit reset conditions.

[CONTRACT: CTR-2609] Paths Are Treated as an Input Boundary.
- APPLY: CTR-1501 (Not UTF-8) and CTR-1504 (Sanitization).
- REJECT IF: untrusted identifiers are joined into paths without strict validation (path traversal).
- ENFORCE BY: validate/parse IDs into constrained types; never `join(user_input)`; prefer mapping IDs to safe filenames.

[CONTRACT: CTR-2610] Canonical Representation Is Defined at Boundaries.
- REJECT IF: critical values have multiple semantic encodings (e.g., "null hash" as `None` vs `[0;32]`) without normalization.
- ENFORCE BY: one canonical encoding; normalize at boundary (parse/serialize); test round-trips.

[CONTRACT: CTR-2611] Sensitive Directories Are Created With Restrictive Permissions at Create-Time.
- REJECT IF: sensitive dirs are created with default perms then chmodded (TOCTOU window).
- ENFORCE BY: on Unix, `DirBuilderExt::mode(0o700)`; on files, ensure 0600 where applicable.

[CONTRACT: CTR-2612] Deterministic Ordering Before Hashing/Signing.
- REJECT IF: signatures/hashes depend on iteration order of maps/sets or input collection order.
- ENFORCE BY: sort by a stable key before serialization; specify ordering in the contract.

[CONTRACT: CTR-2613] Portability Is Enforced With `#[cfg]` Gates + CI Coverage.
- APPLY: INV-2001 and RSK-2001.
- REJECT IF: platform-specific code is not gated and tested in the build matrix.

[CONTRACT: CTR-2614] Backend Implementations Must Match Edge-Case Semantics.
- REJECT IF: memory/mock backends silently accept states the persistent backend rejects (or vice versa).
- ENFORCE BY: shared conformance tests; identical overwrite/error semantics; fuzz/property tests for equivalence.

[INVARIANT: INV-2615] Counters and Attempts Are Monotonic.
- APPLY: INV-2502 for monotonic counter semantics.
- REJECT IF: restart attempts / sequence numbers can decrease or reset across terminal states.
- ENFORCE BY: store last-seen attempt in terminal states; require `attempt > previous`.

[CONTRACT: CTR-2617] Distributed Capabilities Are Fail-Closed.
- REJECT IF: any distributed capability, network listener, or entry point defaults to an "Enabled" or "Open" state.
- ENFORCE BY:
  - Capability structs MUST return empty/zero permissions in their `Default` implementation.
  - Feature flags for network egress/ingress MUST default to `false`.
  - Permission masks for new files/directories MUST default to `0600`/`0700` unless explicitly overridden.
[PROVENANCE] SEC-AUDIT-003: Missing Global Fail-Closed requirement.

[CONTRACT: CTR-2616] Hash Chain Integrity.
- REJECT IF: hash chains do not commit to ALL related state (lifecycle events, data payloads).
- ENFORCE BY: combine all relevant event hashes into the final committed hash.
[PROVENANCE] APM2 Implementation Standard.

[CONTRACT: CTR-2618] Safe Locking (Poison Handling).
- REJECT IF: `lock().unwrap()` is used in production code (panics if a previous holder panicked).
- ENFORCE BY:
  - If state corruption is fatal: propagate the error (don't unwrap).
  - If state corruption is acceptable/recoverable (e.g., metrics, cache): use `.lock().unwrap_or_else(|e| e.into_inner())` to ignore poison.
  - Optionally: propose `parking_lot` (no poisoning) **only** via `M12` dependency review; do not add it ad-hoc.
[PROVENANCE] std `Mutex` poisons on panic; `unwrap` propagates the panic, causing cascading DoS.

[CONTRACT: CTR-2619] Infallible Serialization Wrapper.
- REJECT IF: `serde_json::to_string(&val).unwrap()` is used on internal types without a "no-fail" proof.
- ENFORCE BY:
  - Return `Result` even if "it should never fail" (defensive coding).
  - Or use a wrapper `must_serialize` that logs a critical error and returns a fallback/empty string (if crashing is worse than missing data).
  - NEVER unwrap serialization on data that contains user-controlled strings (recursion/depth limits).
[PROVENANCE] Serde can fail on map keys, recursion limits, or custom `Serialize` impls.

[CONTRACT: CTR-2620] Input Parsing Must Be Fallible.
- REJECT IF: `parse().unwrap()`, `from_str().unwrap()`, or `try_into().unwrap()` is used on any input that originates outside the binary.
- ENFORCE BY:
  - `let val = input.parse().map_err(|_| Error::InvalidInput)?`
  - Use `unwrap_or(default)` for permissive parsing.
[PROVENANCE] RSK-0701 (Panic-as-DoS).

[CONTRACT: CTR-2622] Centralized Configuration.
- REJECT IF: `std::env::var` is called in business logic (outside `crate::config`).
- ENFORCE BY: Load all config into a typed `Config` struct at startup; pass `Config` or specific fields to components.
[PROVENANCE] Ensures 12-factor app compliance and testability (environment injection).

[CONTRACT: CTR-2623] No Boolean Blindness in APIs.
- REJECT IF: public function arguments use `bool` for logic options (e.g., `validate(true)`).
- ENFORCE BY: Use specific `enum`s (e.g., `ValidationMode::Strict`) or `struct` options patterns.
[PROVENANCE] Improves readability and prevents regression when refactoring (swapped booleans).

[CONTRACT: CTR-2624] Finite State Machines Are Typed.
- REJECT IF: internal state or status is represented as a `String` (e.g., `status: "running"`).
- ENFORCE BY: Use `enum` for all finite states; use `String` only for arbitrary user input or unbounded identifiers.
[PROVENANCE] Enables compiler-checked exhaustive matching and prevents invalid states.

[HAZARD: RSK-2625] Unbounded Channels.
- APPLY: CTR-1004 (Bounded Concurrency).
- REJECT IF: `std::sync::mpsc::channel()` or `tokio::sync::mpsc::unbounded_channel()` is used without strict, proven upper bounds on production rates.
- ENFORCE BY: `mpsc::sync_channel(bound)` or `tokio::sync::mpsc::channel(bound)` to provide backpressure.
[PROVENANCE] Prevents OOM DoS attacks (CWE-400).

[CONTRACT: CTR-2626] Technical Debt Must Be Accounted.
- REJECT IF: `TODO`, `FIXME`, or `HACK` comments exist without a referenced Ticket ID (e.g., `TODO(TCK-123): ...`).
- ENFORCE BY: CI lint (grep) that rejects orphaned TODOs.
[PROVENANCE] Prevents "temporary" hacks from becoming permanent load-bearing tech debt.

[INVARIANT: INV-2627] Identity Boundaries Use Shared Spec-Driven Contracts.
- REJECT IF: canonical identity parse/encode paths implement ad-hoc wire/tag handling instead of the shared identity abstraction (`IdentitySpec` + `IdentityWireKernel`) without an explicit documented waiver.
- REJECT IF: digest-first identity forms silently coerce unresolved semantics into resolved semantics.
- ENFORCE BY: define all four semantic axes (`wire_form`, `tag_semantics`, `derivation_semantics`, `resolution_semantics`) per identity type; use fail-closed resolver contracts where text omits semantics; preserve canonical text/binary acceptance boundaries.
[PROVENANCE] RFC-0020 REQ-0007/REQ-0008 boundary determinism and fail-closed identity semantics.

## Anti-Patterns (Lessons Learned)

### ANTI-1

[HAZARD: RSK-2616] Shell Argument Escaping for Complex Strings.
- REJECT IF: prompts/markdown/complex strings are passed as shell/CLI arguments.
- ENFORCE BY: write to a temp file and redirect stdin; quote paths using the project’s shell escaping helpers; prefer `std::process::Command` with explicit argv when possible.

### ANTI-2

[HAZARD: RSK-2617] Predictable Temp File Names (`temp_dir().join(format!(...))`).
- REJECT IF: temp paths are derived from PID/time/user input in shared temp directories.
- ENFORCE BY: `tempfile::NamedTempFile` / `TempDir` (random name, 0600/0700, RAII cleanup); persist only when necessary and then clean up explicitly.

### ANTI-3

[CONTRACT: CTR-2628] Orchestrator-Kernel Cursor Selection.
- New orchestrator-kernel consumers MUST NOT assume epoch timestamps are the cursor.
- REJECT IF: a `LedgerReader` implementation hardcodes `CompositeCursor` when the
  underlying ledger has a natural sequence or commit-index cursor.
- ENFORCE BY: choose a `KernelCursor` implementation matching ledger truth
  (sequence number, commit index, or `CompositeCursor` for timestamp+id ledgers).
  See `crates/apm2-core/src/orchestrator_kernel/types.rs` for the `KernelCursor` trait
  and `CompositeCursor` as the default.

### ANTI-4

[HAZARD: RSK-2618] Incomplete Struct/Enum Field Updates.
- REJECT IF: adding a field/variant does not update constructors, matches, serialization, and invariants.
- REJECT IF: `match` expressions use `..` or default arms for structs/enums that appear in SCP boundaries (hides missing field handling).
- ENFORCE BY: exhaustive matches (avoid `_ =>` for owned enums); clippy patterns; tests that construct and round-trip every variant; verify new fields are included in all comparison and serialization logic.
