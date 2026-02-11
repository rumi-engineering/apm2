title: Common Review Findings — Lessons from AI Reviews (PRs #423–#438)
purpose: "BLOCKER/MAJOR patterns consistently flagged by AI reviewers. Check EVERY pattern before committing."

## How to Use

Before pushing code for review, verify your implementation against each category below.
For each applicable category, confirm the **verification check** passes. Skipping these
checks is the #1 cause of multi-round review failures.

---

## 1. Missing Production Wiring (Most Common — 5 PRs)

**Frequency:** PRs #437, #436, #433, #427, #425

**Anti-pattern:** Feature code is implemented behind `with_X()` builder methods, unit tests
manually inject dependencies and pass, but production constructors in `state.rs` / `main.rs`
never call the wiring method. The feature is dead in production despite green tests.

**Examples:**
- `SessionTelemetryStore` never wired into `DispatcherState` — telemetry counters always zero (#433)
- `PrivilegedDispatcher` not wired to `DaemonState` — process management commands all fail (#427)
- `SessionRegistry` missing from `DispatcherState` — `handle_session_status` always returns "not found" (#425)
- `EpisodeRuntime` termination wiring not enabled — `stop()`/`quarantine()` cannot call `mark_terminated()` (#436)

**Correct pattern:** Every `with_X()` builder method MUST be called in ALL production constructor
paths in `state.rs` and `main.rs`. Integration tests must exercise the real `DispatcherState`
composition, not manually injected dependencies.

**Verification check:**
1. For every new `with_X()` method: `grep` for its usage in `state.rs` and `main.rs`
2. Confirm at least one integration test constructs via the production path
3. If production wiring is deferred, document why and add a `TODO(TCK-XXXXX)` with ticket

---

## 2. Persistence Integrity Gaps (5 occurrences)

**Frequency:** PRs #436, #434, #424

**Anti-pattern:** State transitions happen in-memory but are not persisted, or persistence
errors are silently swallowed. After restart, stale/missing state breaks lifecycle integrity.

**Examples:**
- `mark_terminated()` mutates memory but skips `persist()` — terminated sessions lost on restart (#436)
- Persistence failure logged and ignored — violates fail-closed contract (#436)
- Startup clears session registry even when recovery returns timeout error — unrecovered sessions lost (#434)
- Recovery truncates to `MAX_RECOVERY_SESSIONS` then clears ALL — sessions above cap never get cleanup (#434)
- `CredentialStore` maintains profile list only in memory — `creds list` empty after restart (#424)

**Correct pattern:** Every state mutation with durable semantics MUST call `persist()` and treat
persistence failure as lifecycle-fatal (fail-closed). Persistent serialization must include ALL
relevant state (active AND terminated). Recovery must handle partial completion without clearing
unprocessed state.

**Verification check:**
1. For every state mutation: confirm `persist()` is called afterward
2. Confirm persistence errors propagate as `Err`, not logged-and-ignored
3. Confirm `load()` restores ALL state variants (not just "active" subset)
4. Confirm recovery handles partial completion without discarding unprocessed entries

---

## 3. Unbounded Resource / DoS Vulnerabilities (4 occurrences)

**Frequency:** PRs #436, #424, #431

**Anti-pattern:** Collections grow without hard caps, or caps are not enforced on all
write/load paths, enabling memory exhaustion under churn.

**Examples:**
- Terminated-session store unbounded — only active sessions capped (#436)
- `load_from_file()` inserts all persisted entries without enforcing `MAX_*` (#436)
- `CredentialStore` cache grows unbounded with no eviction (#424)
- `DurableCas::store` uses non-atomic check-then-commit for quota — concurrent over-admission (#431)

**Correct pattern:** Every in-memory collection MUST have a hard `MAX_*` constant with
deterministic eviction. Caps must be enforced on ALL write paths including bulk load/reload.
Resource reservation must be atomic (CAS loop or mutex) to prevent concurrent over-admission.

**Verification check:**
1. For every `Vec`/`HashMap`/`HashSet`: confirm `MAX_*` constant exists
2. Confirm overflow produces an error, not silent truncation
3. Confirm load/reload paths enforce the same cap as insert paths
4. Confirm concurrent writers cannot exceed the cap via TOCTOU

---

## 4. Fail-Open / Missing Authorization Gates (4 occurrences)

**Frequency:** PRs #436, #423

**Anti-pattern:** Security-critical state transitions are not enforced as gates. Terminated
sessions can continue operating. Error/ambiguous states resolve to PASS/ACTIVE instead of
DENY/FAIL.

**Examples:**
- `TERMINATED` state not checked before `RequestTool` — terminated sessions keep working (#436)
- `SessionStatus` falls back to `ACTIVE` for missing entries — expired terminated sessions look active (#436)
- `observe_session_termination` returns `Success` on connection failure — classic fail-open (#423)
- Crash/OOM-kill inferred as `SUCCEEDED` because session became unreachable (#423)

**Correct pattern:** All ambiguous/error states MUST resolve to DENY/FAILURE (fail-closed).
Terminated sessions must be checked before ALL subsequent operations. Status queries must
never synthesize ACTIVE for missing/expired entries.

**Verification check:**
1. For every status fallback: confirm missing/unknown → explicit error, not default-pass
2. For every session operation: confirm terminated-state check precedes execution
3. For every observation: confirm connection failure → FAILURE, not SUCCESS

---

## 5. Gate / Receipt Integrity (5 occurrences)

**Frequency:** PRs #435, #423

**Anti-pattern:** Gate receipts are accepted without validation, or outcomes are hardcoded
to pass. Evidence artifacts contain fabricated values.

**Examples:**
- Receipts accepted without signature verification or `lease_id`/`gate_id` binding checks (#435)
- Gate outcome hardcoded to pass — failing gates can be marked as passing (#435)
- `build_receipt` hardcodes all work items to `SKIPPED` with `attempts: 0` (#423)
- `tokens_consumed` hardcoded to `1000`, bypassing budget enforcement (#423)

**Correct pattern:** Gate receipts MUST be cryptographically verified before acceptance.
Derive verdict from validated typed payload, never default to pass. Evidence artifacts must
reflect actual execution state, never hardcoded values.

**Verification check:**
1. Confirm every receipt acceptance includes signature verification
2. Confirm `final_outcome` is derived from actual execution, not hardcoded
3. Confirm evidence fields (`tokens_consumed`, `attempts`, etc.) reflect real values

---

## 6. Process Containment Failures (3 occurrences)

**Frequency:** PR #432

**Anti-pattern:** Shutdown paths have cancellation safety issues. Child processes survive
daemon exit. PID-only kill paths are vulnerable to PID reuse.

**Examples:**
- Timeout cancels `shutdown_all_processes` after runner removed from state but before stop — orphan (#432)
- `force_kill_all_processes` kills by PID without validating process identity — PID reuse risk (#432)
- Missing `start_time` validation treated as "skip check" instead of "refuse to kill" (#432)

**Correct pattern:** Shutdown must be cancellation-safe — do not remove runners from state
before stop completes. Use stable process identity (`(pid, start_time)` binding) validated
before kill. Treat missing identity as "unknown" and refuse `SIGKILL`.

**Verification check:**
1. Confirm state removal happens AFTER stop completes, not before
2. Confirm kill paths validate `(pid, start_time)` binding
3. Confirm missing identity → refuse to kill, not skip validation

---

## 7. Missing End-to-End Integration Tests (8 occurrences)

**Frequency:** PRs #437, #433, #432, #431, #427, #425

**Anti-pattern:** Tests manually inject dependencies or increment counters directly instead
of exercising the real production path. Side effects are not asserted. Tests prove nothing
about actual wiring.

**Examples:**
- Tests manually increment telemetry counters instead of validating dispatcher-driven updates (#433)
- Tests dispatch directly in memory, not via real IPC (#432)
- Tests verify response format but not side effects (process not actually started) (#427)
- Tests don't execute `RequestTool`/`EmitEvent` against wired dispatcher (#431)

**Correct pattern:** Integration tests MUST exercise real production wiring paths
(`DispatcherState` composition). Side-effect assertions are mandatory. Test assertions on
counts must use specific non-zero literals, never `expected` variables that can be 0.

**Verification check:**
1. Confirm integration tests construct via production `DispatcherState` path
2. Confirm tests assert side effects (state changed, events emitted), not just response format
3. Confirm count assertions use specific non-zero literals (e.g., `assert_eq!(count, 3)`)

---

## 8. Stub Handlers Shipped as Complete (3 occurrences)

**Frequency:** PRs #427, #424

**Anti-pattern:** Handlers are implemented as read-only stubs that don't mutate state, but
the PR claims the feature is functional. CLI reports success but nothing happens.

**Examples:**
- Process management handlers only acquire read lock — calculate but never mutate `Supervisor` (#427)
- Log streaming returns empty list and warning — non-functional stub (#427)
- Credential handlers marked `// TODO` — `creds add` reports success but discards credential (#424)

**Correct pattern:** Handlers MUST perform the actual state mutation or explicitly document
stub status as out-of-scope. DoD verification must include side-effect assertions, not just
response format checks.

**Verification check:**
1. Confirm handlers acquire write locks when mutating state
2. Confirm tests assert the state actually changed after the handler runs
3. Confirm no `// TODO` stubs are shipped as complete features

---

## 9. Filesystem / Path Traversal (3 occurrences)

**Frequency:** PRs #423, #431

**Anti-pattern:** Path validation uses string equality instead of component-aware checks.
Symlink validation can be bypassed with dangling symlinks or dot-segments.

**Examples:**
- `validate_workspace_root` uses `==` against blocklist — `/var/log` bypasses `/var` block (#423)
- `validate_no_symlinks` skips check when `!current.exists()` — dangling symlinks pass (#431)
- `create_dir_all` without `0700` permissions despite docs claiming restricted permissions (#431)

**Correct pattern:** Use `Path::starts_with` for component-aware blocking. Use
`symlink_metadata` (not `metadata`) to detect symlinks even when targets don't exist.
Canonicalize and reject dot-segments before validation. Create directories with explicit
`DirBuilderExt::mode(0o700)`.

**Verification check:**
1. Confirm path blocking uses `starts_with`, not `==`
2. Confirm symlink checks use `symlink_metadata`
3. Confirm directory creation uses explicit `mode(0o700)`

---

## 10. Proto Verify Cascading Failure (PR #450)

**Frequency:** PR #450 (4 consecutive CI failures)

**Anti-pattern:** Agent edits `apm2.daemon.v1.rs` directly or edits `.proto` without
rebuilding. CI's Proto Verify step regenerates from `.proto` source and diffs — stale
bindings cause ALL downstream checks to fail (clippy, test, doc, MSRV, release).

**Examples:**
- Agent adds proto messages to `.proto` but pushes stale `.rs` file — 8 CI checks fail (#450)
- Agent manually patches `.rs` file to match expected types — CI rebuilds differently (#450)
- Proto file missing trailing newline causes diff mismatch (#450)

**Correct pattern:** NEVER edit `apm2.daemon.v1.rs`. Edit `.proto`, run
`cargo build -p apm2-daemon`, commit both files. Verify trailing newline.

**Verification check:**
1. Confirm `.proto` changes include corresponding `.rs` regeneration
2. Run `cargo build -p apm2-daemon` locally before pushing
3. Diff `apm2.daemon.v1.rs` against previous commit — changes should match `.proto` edits

---

## 11. Serde Default on Security-Critical Fields (PR #450)

**Frequency:** PR #450 (flagged 2 rounds)

**Anti-pattern:** Using `#[serde(default)]` on enum fields where the default variant
is the LEAST restrictive. Deserializing missing fields grants maximum permissions.

**Examples:**
- `resolved_risk_tier: RiskTier` with `#[serde(default)]` defaults to `Tier0` (least restrictive) (#450)
- Missing attestation data deserializes as "no attestation required" instead of "maximum attestation" (#450)

**Correct pattern:** Security-critical defaults must be MOST restrictive. Use custom
deserializer that maps missing → highest tier / most restrictive option.

**Verification check:**
1. Search for `#[serde(default)]` on any security-related field
2. Confirm default variant is the MOST restrictive, not least
3. If in doubt, use custom deserializer with explicit fail-closed default

---

## 12. Missing Caller Authorization in IPC Handlers (PR #450)

**Frequency:** PR #450 (flagged 3 rounds)

**Anti-pattern:** IPC handler validates structural fields (format, non-empty, size)
but does not verify that the caller is authorized to perform the operation.

**Examples:**
- `DelegateSublease` validates sublease fields but not caller authority over parent lease (#450)
- Handler accepts any authenticated client request for any resource (#450)

**Correct pattern:** Every security-sensitive handler must bind caller identity
(from `ctx.peer_credentials()`) to resource authorization. Reject if caller lacks
authority over the requested resource.

**Verification check:**
1. For every new handler: identify who the caller is and what they're requesting
2. Confirm caller identity is checked against resource ownership/delegation authority
3. Add negative test: unauthorized caller → explicit rejection error

---

## Quick Pre-Commit Checklist

Before pushing, verify these top-8 failure modes:

- [ ] Every `with_X()` builder method is called in production `state.rs` / `main.rs`
- [ ] Every state mutation calls `persist()` with error propagation
- [ ] Every collection has a `MAX_*` cap enforced on all write paths
- [ ] Every error/unknown state resolves to DENY/FAIL, not PASS/ACTIVE
- [ ] Integration tests exercise real production wiring, not manual injection
- [ ] Proto changes include regenerated `.rs` file (`cargo build -p apm2-daemon`)
- [ ] No `#[serde(default)]` on security-critical enum fields
- [ ] Every IPC handler checks caller authorization, not just field validation
