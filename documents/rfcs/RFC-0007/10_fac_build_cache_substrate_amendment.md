# RFC-0007 Amendment A1: FAC Execution Substrate (Target Pool), Nextest Policy, and Resource Hygiene

* **Document:** `documents/rfcs/RFC-0007/10_fac_build_cache_substrate_amendment.md`
* **Amends:** RFC-0007 (DRAFT)
* **Date:** 2026-02-11
* **Primary surfaces touched by this amendment:**

  * `crates/apm2-cli/src/commands/fac.rs`
  * `crates/apm2-cli/src/commands/fac_review/{gates,evidence,gate_attestation}.rs`
  * `scripts/ci/run_bounded_tests.sh`
  * `flake.nix`
  * `documents/skills/implementor-default/SKILL.md`
  * (NEW) `crates/apm2-cli/src/commands/fac_review/{fac_resources,target_pool}.rs` (or equivalent module placement)
* **Motivating operational constraints (explicit):**

  * Ubuntu 24.04
  * 96 GB RAM
  * Frequently **≤ 3 simultaneous** `gate` executions across **3 worktrees**
  * Often **~13 worktrees exist concurrently** (not all active)
  * Near-term: heavy bash → Rust migration (security + perf)
  * Long-term: assimilate to **NixOS substrate** across the holonic network
  * Primary goal: **maximize FAC loop throughput** while guaranteeing **no catastrophic host failure** (disk/mem/CPU exhaustion), with **automatic/enforced cleanup**

---

## 1. Repo-grounded baseline: what actually runs today

This amendment is written against the **current apm2 repo state** in the provided ZIP.

### 1.1 FAC gates execution path (local)

`apm2 fac gates` is implemented in:

* `crates/apm2-cli/src/commands/fac.rs` → routes to
* `crates/apm2-cli/src/commands/fac_review/gates.rs::run_gates(...)`

`run_gates` calls:

* `fac_review/evidence.rs::run_evidence_gates(...)`

Evidence gates include:

* `cargo fmt --all --check`
* `cargo clippy --workspace --all-targets --all-features -- -D warnings`
* `cargo doc --workspace --no-deps`
* `scripts/ci/test_safety_guard.sh`
* `scripts/ci/review_artifact_lint.sh`
* **test gate**: uses `cargo nextest run ...` inside `scripts/ci/run_bounded_tests.sh` when cgroup v2 is available.

Key fact: **nextest is already the default execution for the test gate** on modern Linux via `run_bounded_tests.sh` (the command constructed in `evidence.rs::build_pipeline_test_command` is explicitly `cargo nextest run ...`). The old "cargo test" path exists only as a fallback when the bounded runner is unavailable.

Clarification (missing in the draft): **there are two "fallback" paths today**:

* **Pipeline path** (`run_evidence_gates_with_status`) uses `build_pipeline_test_command(...)` and falls back to `cargo test` if bounded runner isn't available.
* **Local `apm2 fac gates` path** (`run_evidence_gates(...)` via `gates.rs`) runs whatever `gates.rs` passes as `EvidenceGateOptions.test_command`. If `gates.rs` does **not** pass a command (e.g., bounded runner unavailable), `run_evidence_gates` falls back to `cargo test` directly.

If we "mandate nextest", we must fix **both** call paths (pipeline + local), not just the pipeline builder.

### 1.2 Bounded test environment today

The bounded runner:

* Uses `systemd-run --user` transient scope/service under a name like `apm2-ci-bounded-...`
* Enforces:

  * timeout (defaults bounded by `gates.rs` max 240s)
  * memory max (default 24G passed from CLI)
  * pids max
  * CPU quota
* Uses an **explicit allowlist** to propagate selected env vars into the unit (`run_bounded_tests.sh` has `SETENV_ARGS` built from a for-loop allowlist).

Operational footgun not called out in the draft:

* `systemd-run --user` requires a functioning user bus. On headless/VPS setups this frequently fails unless the user session is correctly configured (and CI uses a documented workaround). This amendment therefore treats "bounded runner availability" as a **first-class availability constraint**, not a "maybe".

### 1.3 Gate cache and attestation today

Gate cache receipts are written (in full mode) under:

* `~/.apm2/private/fac/gate_cache_v2/<SHA>/...`

Attestation digest computation is in:

* `crates/apm2-cli/src/commands/fac_review/gate_attestation.rs`

Important details:

* `command_digest()` hashes an allowlisted set of environment variables (e.g., `RUSTFLAGS`, `RUSTDOCFLAGS`, `CARGO_BUILD_JOBS`, `CARGO_INCREMENTAL`, `RUSTUP_TOOLCHAIN`).
* `gate_input_digest()` hashes selected paths (e.g., `.config/nextest.toml`, `scripts/ci/run_bounded_tests.sh`), but **does not currently include `.cargo/config.toml`**.
* `environment_digest()` includes versions for: kernel, rustc, cargo, rustfmt, clippy, nextest, systemd-run. **No sccache version** is captured today.

Correction (repo-grounded): `environment_digest()` currently captures:

* kernel (`uname -r`)
* rustc (`rustc -Vv`)
* cargo (`cargo -Vv`)
* clippy (`cargo clippy --version`)
* nextest (`cargo nextest --version`)
* systemd-run (`systemd-run --version`)

It does **not** currently capture `rustfmt --version` (this is a latent fail-open in gate-cache semantics for the fmt gate).

This matters: any "build cache substrate" change must be surfaced into attestation in a way that remains **fail-closed** (no unsafe reuse).

Also repo-grounded and missing from the draft threat discussion:

* `.cargo/config.toml` already exists in-repo and materially changes builds (e.g., linker + rustflags). It is currently **not** included in attestation input digests.

---

## 2. Problem re-statement (with hard constraints)

### 2.1 Why you’re hitting the 240s / 24G wall

Observed operational pattern:

* Many git worktrees exist simultaneously (often ~13).
* Each worktree has its own `target/` directory by default.
* Compilation-heavy gates (`clippy`, `doc`, `test`) can each trigger distinct compilation flows and output sets.
* The **bounded** test gate is sensitive: if it has to do a large cold compile, it can exceed:

  * **Wall-time 240s** (by policy; should not be increased)
  * **MemoryMax 24G** (policy default)

Your stated goal is not to “relax the box”; it is to **make cold-start rare** and **keep the host stable** under parallel agents.

### 2.2 Second-order failure modes you must treat as first-class

The initial planning doc does not cover these adequately:

1. **Disk exhaustion is the dominant catastrophic failure mode** in multi-worktree Rust development (targets balloon fast).
2. **Parallelism without a global governor** can still destroy a host even if one gate is bounded (because:

   * only the test gate is bounded today
   * unbounded clippy/doc builds can thrash CPU, IO, and memory
3. Build caching tools (sccache) can introduce **containment bypass risks** if they daemonize or spawn compiler processes outside your intended cgroup containment strategy (details in §6.4).
4. "cargo test aliased to nextest" is an *ambient state dependency* that fights your stated requirement: **instant environment reproducibility across new VPS nodes**.

5. **CPU oversubscription is currently guaranteed** under 3 concurrent gate runs unless you explicitly cap nextest runtime concurrency:
   * nextest defaults its test scheduling to machine parallelism; with 3 simultaneous runs, you can easily spawn "3× full CPU" worth of test processes. CPUQuota helps, but without aligning nextest's own concurrency knobs, you get unnecessary context switching and tail latency.

6. **Disk-full failure is "fast and dumb"**: it usually happens mid-build, leaving half-written artifacts that make subsequent runs slower and more failure-prone. Therefore, "GC exists" is insufficient; we need **enforced preflight**.

---

## 3. Amendment scope: what this document changes in RFC-0007

RFC-0007 (currently DRAFT) is about build optimizations; it already contains:

* `TB-002: Compilation Cache` (sccache) in `03_trust_boundaries.yaml`
* Optional nextest decisions (`DD-002`, `DD-003`) in `02_design_decisions.yaml`

This amendment modifies RFC-0007 in two ways:

1. It upgrades "optional nextest" to a **mandatory FAC policy** (for the FAC gate execution substrate), without requiring every developer shell alias behavior.
2. It turns "cross-worktree build reuse" from an RFC-0007 "nice-to-have" into an **implemented and governed FAC substrate**, with the following ordering:

   **Primary accelerator (new):** slot-scoped `CARGO_TARGET_DIR` pool ("target pool").

   **Secondary accelerator (optional, gated):** sccache, only after containment + benefit verification.

   This ordering is deliberate: the target pool attacks the dominant observed cost (duplicated `target/` trees across worktrees) without introducing a daemon boundary.

3. It adds an "enforced resource hygiene" control plane (GC + disk preflight) as a FAC primitive, not an optional human ritual.

4. It adds a "global concurrency governor" as a FAC primitive, reusing patterns already present in-repo (e.g., provider slot leasing).

   * cache warm interfaces (optional but useful)
   * strict resource hygiene / GC policy (enforced)
   * explicit attestation surfacing (fail-closed)
   * staged migration path from bash → Rust and to NixOS

This amendment explicitly **does not** attempt to redesign FAC protocol cryptography; it is about the **local execution substrate** and safety of running many agents.

---

## 4. Goals, non-goals, and invariants

### 4.1 Goals

G1. **Bounded test gate reliability:** after a one-time warm (per worktree lifecycle), running `apm2 fac gates` (full mode) must reliably complete the test gate within **240s/24G** on this node class, without “raise the timeout” pressure.

G2. **Parallel agent safety:** enable up to **3 simultaneous gate executions** (your current reality) without:

* disk filling
* system-wide swap thrash
* wedging the shell environment
* requiring manual cleanup “heroics”

G3. **Automatic, enforced cleanup:** implement guardrails that prevent unbounded growth of:

* worktree `target/` artifacts
* FAC evidence / cache artifacts
* compilation caches

G4. **Reproducibility across nodes:** remove hidden reliance on user shell aliases; encode toolchain + policy in:

* repo (Nix flake + configs)
* `apm2` commands (explicit nextest usage, explicit cache policy)
* receipts / attestation (fail-closed)

G5. **Incremental path to Rust + NixOS:** every new control plane surface introduced here must be representable as:

* Rust code (no new long-lived bash daemons)
* Nix (flake now; NixOS module later)

### 4.2 Non-goals (for this amendment)

NG1. Remote/distributed compilation cache across untrusted nodes (TB-002 explicitly warns; keep local-only for now).
NG2. Replacing `scripts/ci/run_bounded_tests.sh` entirely today (we will reduce its responsibilities and migrate later).
NG3. Solving “1 worktree = 1 ticket” globally immediately; we will provide an execution pool path that can **replace** that model when ready.

### 4.3 Hard invariants

I1. **Do not increase bounded test timeout** beyond 240s. This must be enforced in code (reject >240 unless an explicit unsafe override is present).
I2. **Fail-closed on attestation ambiguity.** If policy/tooling/env changes in ways that *might* affect correctness, gate cache reuse must not occur.
I3. **Host survivability > speed.** If any speed optimization risks host instability, it must be gated behind explicit opt-in and measured.

I4. **Disk preflight is mandatory.** No heavy FAC operation may start if the relevant filesystem(s) are below `min-free` after an attempt to GC.

I5. **No ambient build-policy inheritance.** FAC must ignore user ambient state for the following knobs unless explicitly set via FAC flags:
* `CARGO_TARGET_DIR` (must be set by FAC target pool)
* nextest runtime concurrency knobs (must be set by FAC policy)
* (if later enabled) `RUSTC_WRAPPER` / sccache knobs (must be set by FAC policy)

---

## 5. Nextest policy: stop relying on ambient aliasing

### 5.1 Explicit recommendation

**Do not alias `cargo test` → nextest** as part of the canonical FAC substrate.

Reasons (practical, not ideological):

* It is an **ambient global mutation** of tooling semantics that your attestation cannot reliably see (unless you treat `~/.cargo/config.toml` as a formal input, which you should not).
* It can break commands that expect `cargo test` semantics (including compile-only patterns like `cargo test --no-run`, or third-party scripts that assume cargo behavior).
* It undermines the “instantly reproduce environment across VPSs” objective; you will forget one node or one systemd unit will not pick up shell alias state.

### 5.2 What we do instead (mandatory, encoded)

**FAC test execution uses nextest explicitly** in the code path.

Concrete repo changes:

* In `crates/apm2-cli/src/commands/fac_review/evidence.rs` (pipeline path) and in `crates/apm2-cli/src/commands/fac_review/gates.rs` (local gates path):

  * Replace **all** non-bounded fallbacks from `cargo test --workspace` to:

    * `cargo nextest run --workspace --all-features --config-file .config/nextest.toml --profile ci`
  * If nextest is missing in any scenario, fail with a clear error that nextest is required for FAC gates (FAC substrate mandate).

This turns nextest into a **declared dependency** of the FAC substrate, consistent with `flake.nix` already including `cargo-nextest`.

Missing-but-required detail: align nextest's own concurrency knobs with the global governor:

* `NEXTEST_TEST_THREADS` must be set (or `--test-threads`) to match the per-slot CPU budget, otherwise you still get oversubscription even with CPUQuota.

### 5.3 Optional dev convenience (safe)

If you want a shortcut, add a **non-overriding** cargo alias (repo-local, not user-global):

* In `.cargo/config.toml` add:

```toml
[alias]
nt = "nextest run --workspace --all-features --config-file .config/nextest.toml --profile ci"
```

Key: **do not override `test`**. Provide a new alias.

---

## 6. Build cache substrate: target pool (primary), sccache (optional)

### 6.1 Primary accelerator: slot-scoped `CARGO_TARGET_DIR` ("target pool")

Why this exists:

* The dominant real-world cost in your described regime is **duplicated `target/` trees** across worktrees.
* RFC-0007 rejected a global shared `CARGO_TARGET_DIR` because cargo uses a target-dir lock that prevents parallel builds.
* This amendment introduces a global concurrency governor (compute slots). **Once you have slots, you can have "N target dirs"**:
  * each slot has its own target dir
  * at most one heavy build runs per slot
  * parallelism is preserved up to N without cargo lock contention

Policy:

* Every "heavy" FAC operation (gates, pipeline evidence, warm) acquires a compute slot.
* On slot acquisition, FAC sets:
  * `CARGO_TARGET_DIR=$APM2_HOME/private/fac/target_pool/<toolchain_fingerprint>/slot_<i>`
  * `CARGO_BUILD_JOBS=<computed>`
  * `NEXTEST_TEST_THREADS=<computed>`
* FAC must **override** any ambient `CARGO_TARGET_DIR` rather than inheriting it.

Result:

* Cross-worktree reuse of compiled dependencies without sccache.
* Disk usage collapses from "~13 targets" to "≤ slot_count targets".
* No new daemon boundary, so containment is straightforward.

### 6.2 Security boundary alignment (TB-002)

RFC-0007 TB-002 already establishes:

* Compilation cache is local, trusted
* Remote caches are not assumed safe

This amendment enforces:

* target pool directories are under explicit control (`$APM2_HOME/private/fac/target_pool`)
* they are subject to GC policy
* optional sccache use is local-only and explicitly controlled (if/when enabled)

### 6.3 Optional secondary accelerator: sccache (only if it actually helps)

We choose the **explicit-activation model** for sccache (if/when implemented):

* `apm2` commands decide when to use sccache
* We do **not** make sccache an always-on implicit requirement by hardcoding `build.rustc-wrapper="sccache"` in `.cargo/config.toml`

Rationale:

* `.cargo/config.toml` is always present; making it require sccache causes a hard failure on any node missing sccache.
* More importantly, FAC runs under bounded systemd units; implicit wrappers are harder to reason about and attest.
* Explicit activation makes it possible to:

  * run “safe mode” (no sccache) if needed for debugging
  * record activation in receipts and attestation
  * migrate to NixOS without hidden assumptions

### 6.4 Standard cache locations

We standardize:

* `FAC_TARGET_POOL_ROOT = $APM2_HOME/private/fac/target_pool`
* `CARGO_TARGET_DIR = $FAC_TARGET_POOL_ROOT/<toolchain_fingerprint>/slot_<i>`

If sccache is enabled later:

* `SCCACHE_DIR = $APM2_HOME/private/cache/sccache`

Why under APM2_HOME?

* makes GC and backup policy coherent
* avoids scattered caches across `$HOME/.cache`
* makes “restore environment on new VPS” more predictable

Implementation note:

* `apm2_home_dir()` already exists in `fac_review/types.rs`; use it to derive the path.

### 6.4 Critical containment caveat: sccache + cgroups

This is where the original planning doc was dangerously under-specified.

Because the test gate is executed under a bounded `systemd-run` unit, we must assume:

* any compilation or compilation-adjacent process must remain inside the bounded cgroup to preserve the 24G/240s guarantees.

**Risk:** If sccache uses a long-lived daemon that spawns compiler processes outside the transient unit cgroup, your “bounded tests” aren’t actually bounded. That is an unacceptable integrity regression.

**Mitigation policy in this amendment:**

* Default stance: **do not enable sccache inside bounded units** until proven safe and beneficial.

If/when you try to enable it:

* You must ensure the sccache server that spawns compiler processes is inside the unit cgroup.
* The earlier draft conflated `SCCACHE_NO_DAEMON` with "no server". In sccache, `SCCACHE_NO_DAEMON=1` only prevents daemonization (it does not eliminate the server boundary).
* A safer pattern (if needed) is: start the server inside the unit (`sccache --start-server`), and stop it when the unit finishes (`sccache --stop-server`) while ensuring it cannot connect to an already-running out-of-cgroup server (e.g., via per-unit socket config).

Otherwise, keep sccache off for bounded units and rely on:

* target pool reuse + warm/prebuild (see §7)

Because sccache behavior may differ by version, this amendment requires a **verification check** (see §11) that confirms rustc processes remain inside the bounded cgroup when sccache is enabled.

If verification fails, the "safe fallback" is:

* **do not enable sccache inside bounded units**
* rely on pre-warm compilation outside bounded units to keep bounded test runs as "run-only" as possible

This is not optional hand-waving; it is the containment guarantee.

### 6.5 Attestation surfacing

We must make cache substrate visible to the gate attestation so cache reuse is fail-closed.

Changes:

1. **Add `.cargo/config.toml` to `gate_input_paths`** for all cargo-based gates in `gate_attestation.rs`:

   * `rustfmt`, `clippy`, `doc`, `test` should all include `.cargo/config.toml` as an input
   * Rationale: cargo behavior can be influenced by repo-local config; attestation must see it

2. **Fix existing fail-open first, then extend**:

   * Add `rustfmt --version` to `environment_facts` (fmt gate correctness can change across toolchain updates).

3. **Add env vars to `command_digest` allowlist** (future-proof; harmless when unset):

   * `RUSTC_WRAPPER`
   * `SCCACHE_DIR`
   * `SCCACHE_CACHE_SIZE` (if we set it)
   * `SCCACHE_NO_DAEMON` (if we set it)
   * (Optional) `SCCACHE_LOG` / `SCCACHE_ERROR_LOG` if used; otherwise omit

4. **Add sccache version to `environment_facts`** (only matters when sccache is enabled; still safe to record if present):

   * record `sccache --version` output (if present)
   * If sccache becomes required for any FAC profile, absence must fail the invoking FAC command (not just "string = unavailable").

---

## 7. `apm2 fac warm`: pre-warming as a first-class, attested maintenance action

### 7.1 Why warm is required (and where it belongs)

Given the “240s/24G bounded test SLA,” we treat warm as:

* a **worktree lifecycle step**, not a per-run step
* required:

  * on fresh worktree creation
  * after toolchain upgrades (rustc/cargo changes)
  * after aggressive GC/cargo clean

Warm is how we turn bounded tests into “run-only” rather than “build + run.”

### 7.2 CLI interface

Add to `crates/apm2-cli/src/commands/fac.rs`:

```rust
/// Pre-warm compilation caches for FAC evidence gates.
Warm(WarmArgs),
```

Proposed args (minimum viable + future-proof):

* `--json` already supported by root
* `WarmArgs`:

  * `--phases fetch,build,clippy,doc` (default: `fetch,build,clippy,doc`)
  * `--jobs <N>` (optional override; otherwise computed)
  * `--no-target-pool` (debug-only escape hatch; uses per-worktree `target/` and will be slower)
  * (future) `--sccache` / `--no-sccache` only if/when sccache is implemented
  * `--bounded` (optional: run warm under a resource governor scope; default true on multi-agent boxes)

### 7.3 Execution plan

Warm runs these phases (with timing):

1. `cargo fetch --locked`
2. `cargo build --workspace --all-targets --all-features --locked` (optional; see phase selection)
3. `cargo nextest run --workspace --all-features --config-file .config/nextest.toml --profile ci --no-run`
4. (optional) `cargo clippy ...`
5. (optional) `cargo doc ...`

All commands run with:

* target pool enabled by default (`CARGO_TARGET_DIR` set by the acquired compute slot)
* `CARGO_BUILD_JOBS = computed_or_override`
* `NEXTEST_TEST_THREADS = computed_or_override`
* (future) sccache env only if enabled

### 7.4 Warm locking and concurrency

Warm must not stampede, but **do not serialize warm globally**: global warm locks reduce throughput and create single-point deadlocks.

Instead:

* warm acquires a compute slot; that is the concurrency control.
* per-slot target pool already eliminates "13 worktrees compiling 13 times" — the stampede surface is drastically reduced.

Behavior:

* If no compute slots are available:
  * default: wait (bounded by a reasonable max, or with `--no-wait` to fail fast)

### 7.5 Warm receipts

Warm must write a durable receipt:

* Path: `$APM2_HOME/private/fac/maintenance/warm/<ts>_<sha256>.json`
* Schema: `apm2.fac.warm_receipt.v1`

Suggested fields:

```jsonc
{
  "schema": "apm2.fac.warm_receipt.v1",
  "workspace_root": "/abs/path",
  "git_head_sha": "abc123...",
  "started_at": "2026-02-11T...",
  "finished_at": "2026-02-11T...",
  "phases": [
    { "name": "fetch", "cmd": "...", "exit_code": 0, "duration_ms": 1234 },
    { "name": "build", "cmd": "...", "exit_code": 0, "duration_ms": 5678 },
    ...
  ],
  "tool_versions": {
    "rustc": "...",
    "cargo": "...",
    "clippy": "...",
    "nextest": "...",
    "sccache": "..."
  },
  "sccache": {
    "dir": "...",
    "cache_size_policy": "...",
    "stats": "raw output or parsed summary"
  }
}
```

This receipt is intentionally similar in spirit to FAC receipts: structured, auditable, machine-ingestible.

---

## 8. Resource hygiene: `apm2 fac gc` as an enforced safety valve

### 8.1 Why GC must exist as a FAC primitive

You have:

* many worktrees
* large `target/` dirs
* parallel agents
* a strict “host must remain functional” requirement

Therefore GC cannot remain an informal human action.

Also missing from the draft: "GC as a manual command" does not satisfy the stated goal of **automatic and enforced cleanup**.
This amendment therefore requires:

* enforced disk preflight in `gates`, `warm`, and pipeline evidence
* GC auto-invocation when below `min-free`

### 8.2 CLI interface

Add:

* `apm2 fac gc` (maintenance command)

Args:

* `--json`
* `--dry-run`
* `--min-free <SIZE|PERCENT>` (default policy: see below)
* `--keep-hot-worktrees <N>` (default: derived from concurrency)
* `--ttl-days <D>` for “cold worktree targets”
* `--sccache-trim` (default true)
* `--gate-cache-ttl-days <D>` (default: 30)
* `--aggressive` (enables deeper deletions)

### 8.3 What GC is allowed to delete (safe set)

GC is allowed to delete:

1. Worktree-local `target/` directories for "cold" worktrees (legacy artifacts once target pool is enabled)
2. Target-pool slot directories that are not currently leased (LRU policy) **if disk preflight still fails after pruning cold worktrees**
3. `$APM2_HOME/private/cache/sccache` directory (delete as a last resort) if sccache is enabled
4. `$APM2_HOME/private/fac/gate_cache_v2` entries beyond TTL (optional; low ROI but safe)
5. Any **known scratch** artifacts (e.g., `target/ci/**` snapshots) as part of deleting target dirs

GC must **not** delete:

* keys / identity material under `$APM2_HOME/private/*` unless explicitly in a separate “nuke” command
* git worktrees themselves (only their build artifacts)

### 8.4 “Active worktree” definition

A worktree is **active** if any of the following are true:

* It is the current working directory of the invoking process (obviously)
* It has a live FAC lock lease file (see §9)
* It has a running `systemd-run` unit associated with it (optional detection)
* It has been used recently (mtime heuristic):

  * any file under worktree `.git` metadata updated recently
  * OR last warm receipt references it within TTL window

Everything else is eligible for target pruning.

Required amendment: "active" must be defined in terms of the actual global governor, not heuristics.

* A worktree is active iff it is referenced by an active compute-slot lease record (see §9.2.3).
* Heuristics (mtime) may be used as a fallback only when lease metadata is missing.

### 8.5 Default policy for your current box

Given 96GB RAM and up to 3 simultaneous gate executions:

* **Keep-hot-worktrees:** 3
* **Cold worktree TTL:** 7 days (targets older than this are prunable)
* **Min free disk:** `max(20 GiB, 10%)` on the filesystem containing the repo roots
  (use both: a percent for big disks, a floor for small disks)

If min-free is violated:

* GC must escalate in layers:

  1. prune cold worktree targets
  2. trim sccache to target size
  3. prune old gate cache entries
  4. if still below min-free: **fail with a hard error** (host is at risk)

Missing detail: enforce on both relevant mounts.

* Evaluate `min-free` for the filesystem containing `workspace_root`.
* Evaluate `min-free` for the filesystem containing `$APM2_HOME`.
* The preflight passes only if both pass, because disk-full on either breaks FAC.

### 8.6 GC receipts

GC writes:

* `$APM2_HOME/private/fac/maintenance/gc/<ts>_<sha256>.json`
* Schema: `apm2.fac.gc_receipt.v1`

Include:

* disk free before/after
* bytes freed by category
* list of deleted directories (or hashes, if you want to avoid path disclosure)
* policy parameters used

---

## 9. Global resource governor: stop pretending per-command limits are sufficient

### 9.1 The missing control plane

Today, only the test gate is bounded by `systemd-run`. That does not provide “host survivability” under multiple agents.

This amendment introduces a minimal, incremental control plane:

* A local **compute lease** system (file-lock-based) that limits concurrent heavy operations.

### 9.2 Compute lease model (Phase 1)

Implement a token semaphore under:

* `$APM2_HOME/private/fac/locks/compute_slot_<i>.lock` for i ∈ [0, N)

Do not invent this from scratch: the repo already has a proven pattern for "slot leasing via file locks"
(`fac_review/model_pool.rs::acquire_provider_slot`). Reuse that approach (jitter, timeout, RAII guard).

Default N computed as:

* `N = min(3, floor((total_mem_gib - reserve_gib) / mem_per_gate_gib))`

  * reserve_gib default: 20
  * mem_per_gate_gib default: 24 (aligned with bounded tests)

For your box, N should evaluate to 3.

Any heavy operation must acquire a slot:

* `apm2 fac gates` (full mode)
* `apm2 fac warm`
* `apm2 fac pipeline` evidence phase (background push/restart path)
* `apm2 fac gc` when invoked in enforcement mode (preflight-triggered), because it competes for IO

Lease is held for the duration; released on exit (Drop guard).

### 9.2.3 Lease metadata (required for GC safety + debugging)

On acquisition, write a sidecar JSON (not locked, but best-effort, overwrite-safe):

* `$APM2_HOME/private/fac/locks/compute_slot_<i>.json`

Fields:

* pid
* command (gates/warm/pipeline/gc)
* workspace_root
* started_at
* toolchain_fingerprint (see §6.1)

This single mechanism prevents:

* 10 agents all running clippy/doc simultaneously
* warm stampedes
* silent death-by-IO

### 9.3 Compute-aware `CARGO_BUILD_JOBS` (Phase 1)

When a process acquires a compute slot, it computes a default `CARGO_BUILD_JOBS`:

Inputs:

* CPU count
* acquired slot index (not required, but useful)
* total concurrent slots N
* per-slot CPU quota target

Policy:

* `jobs = clamp(2, floor(cpu_count / N), 12)` (raise the cap; 8 is an unjustified throttle on typical 24–64 core VPS nodes)

This is intentionally conservative on 96GB: it trades a small amount of peak speed for avoiding memory spikes and IO contention.

Missing-but-required: nextest runtime concurrency alignment:

* `NEXTEST_TEST_THREADS = clamp(1, floor(cpu_count / N), 8)` (separate from build jobs; prioritize host responsiveness)

Optional: if bounded tests keep CPUQuota, compute CPUQuota from CPU count and N instead of hardcoding `200%`.

### 9.4 Phase 2: long-lived “FAC Execution Pool” (the thing you’re gesturing at)

You asked whether “1 worktree = 1 ticket” is the right primitive. For exabyte/100B-agent scale, it isn’t.

This amendment defines the target architecture:

* A local **FAC Execution Pool (FEP)** with:

  * **N long-lived slots**
  * each slot is a *cullable, instantly refreshable* execution context
  * each slot has:

    * a dedicated worktree root (or ephemeral checkout)
    * a dedicated target dir
    * optionally, a dedicated sccache server if needed for containment

Agents request a slot lease; the slot runs gates inside its preconfigured cgroup/slice.

Why this matters:

* the pool becomes the natural place to integrate:

  * systemd slice budgets
  * per-slot and global disk quotas
  * sccache containment rules
  * fast “reset slot” on corruption

This is the correct “control surface” for scaling to many nodes and many agents. Phase 1 leases are the minimal stepping stone.

---

## 10. Nix integration: environment must be declarative

### 10.1 flake.nix updates

`flake.nix` already includes `cargo-nextest`. This amendment requires adding:

* (optional) `sccache` only if/when we decide to ship it as part of the FAC substrate

This amendment does require:

* nothing new for the target pool (it's policy + env)

so the dev shell is a complete reproduction unit for FAC warm/gates.

### 10.2 Backup/restore implications

Because you have a backup node on the same headscale network:

* treat caches as *optional accelerants*, not required state
* back up:

  * `$APM2_HOME` excluding bulky caches by default
  * include:

    * FAC receipts (gate cache + maintenance receipts)
    * config files
    * keys / identity material (with appropriate protection)
* optionally back up:

  * sccache dir (large, but can accelerate restore)
  * cargo registry cache (also large)

The “instant reproduction” story should be:

1. clone repo at known commit
2. `nix develop` (tools pinned)
3. restore `$APM2_HOME` minimal set
4. run `apm2 fac warm`

---

## 11. Verification and hard checks

This amendment is only acceptable if these checks pass.

### 11.1 Functional checks

1. `nix develop` provides:

   * `cargo nextest` available
   * (optional) `sccache` available if enabled

2. `apm2 fac warm`:

   * produces receipt
   * produces target-pool artifacts (slot target dir size increases; subsequent gates are faster)
   * respects compute slots (no stampede, no global warm lock)

3. `apm2 fac gates` (full mode):

   * after warm, test gate completes within 240s and does not OOM under 24G
   * produces gate cache receipts

4. Attestation tests remain stable and fail-closed:

   * changing `.cargo/config.toml` changes input digest (cargo gates)
   * changing rustfmt version changes environment digest (fmt gate)
   * (if enabled) changing `RUSTC_WRAPPER` changes attestation digest

### 11.2 Containment check (mandatory)

If we enable sccache inside bounded units, we must verify:

* rustc processes spawned during bounded tests are inside the same cgroup as the systemd-run unit.

A practical check:

* During a bounded test run, capture cgroup path of the main process and of a rustc child.
* If mismatch → **disable sccache inside bounded units** and rely on warm/prebuild.

This check can be implemented as:

* a test harness script
* or a debug mode in `run_bounded_tests.sh` / Rust replacement later

---

## 12. Concrete file-level deltas (amendment plan)

### 12.1 Code changes

* `crates/apm2-cli/src/commands/fac.rs`

  * add `Warm(WarmArgs)` and `Gc(GcArgs)` subcommands
  * route to `fac_review::{warm,gc}::run_*`

* `crates/apm2-cli/src/commands/fac_review/`

  * new: `warm.rs` (implements warm, receipts, locks)
  * new: `gc.rs` (implements policy, receipts, pruning)
  * new: `fac_resources.rs` (compute slots + disk preflight helpers; reuse existing slot leasing patterns)
  * new: `target_pool.rs` (derive toolchain fingerprint + slot target dir path)
  * modify: `gate_attestation.rs`

    * include `.cargo/config.toml` in input digests for cargo gates
    * add rustfmt version to environment facts
    * (future) allowlist env vars (`RUSTC_WRAPPER`, `SCCACHE_*`)
  * modify: `evidence.rs`

    * nextest fallback: remove `cargo test` fallback; prefer nextest always (pipeline + local)
    * ensure pipeline and local gates share a single "build test command" helper
    * optionally add env plumbing to run cargo gates with computed `CARGO_BUILD_JOBS` and sccache env
    * set `NEXTEST_TEST_THREADS` for bounded tests (propagate through allowlist)

* `crates/apm2-cli/src/commands/fac_review/gates.rs`

  * enforce I1 (timeout cap) and other resource caps unless unsafe override
  * ensure non-bounded test path still uses nextest
  * acquire compute slot for the entire gates run and set env (`CARGO_TARGET_DIR`, etc.) once

* `scripts/ci/run_bounded_tests.sh`

  * extend env propagation allowlist to include:

    * `CARGO_BUILD_JOBS`
    * `CARGO_TARGET_DIR`
    * `NEXTEST_TEST_THREADS`
    * `RUSTUP_TOOLCHAIN` (align with attestation allowlist)

* `flake.nix`

  * add `sccache` to devShell packages only if we decide to ship it as part of FAC substrate

* `documents/skills/implementor-default/SKILL.md`

  * add CACHE_WARM (or equivalent) node as a lifecycle step after worktree prep and before editing

### 12.2 RFC-0007 doc changes

Update `documents/rfcs/RFC-0007/02_design_decisions.yaml`:

* Replace “optional nextest” decisions with:

  * **FAC substrate mandates nextest** (explicit invocation)
  * cargo test aliasing is not relied upon

Update `documents/rfcs/RFC-0007/03_trust_boundaries.yaml` TB-002:

* Add containment requirement language (bounded units)
* Add requirement that cache dir is under APM2_HOME and subject to GC policy

Add a new section (or amendment file) describing:

* warm and GC interfaces
* compute lease concept
* Nix reproduction

---

## 13. Ticket YAMLs (drop-in proposals)

Below are proposed new tickets using the current ticket schema (`schema_version: "2026-01-29"`). IDs start from `TCK-00503` (next available after existing tickets).

Required correction: the original draft omitted a ticket for "mandate nextest everywhere" and conflated sccache with the primary acceleration lever.
This amendment adds an explicit ticket for nextest mandate and moves "cross-worktree reuse" to the target pool.

### TCK-00503 — Add `apm2 fac warm` command with receipts + compute-slot integration

```yaml
ticket_meta:
  schema_version: "2026-01-29"
  template_version: "2026-01-29"
  ticket:
    id: "TCK-00503"
    title: "Implement `apm2 fac warm` pre-warm command with receipt (compute-slot + target pool)"
    status: "OPEN"
  binds:
    prd_id: "PRD-0009"
    rfc_id: "RFC-0007"
    requirements: []
    evidence_artifacts: []
  custody:
    agent_roles: ["AGENT_IMPLEMENTER"]
    responsibility_domains: ["DOMAIN_RUNTIME", "DOMAIN_SECURITY"]
  dependencies:
    tickets:
      - ticket_id: "TCK-00506"
        reason: "Warm must acquire a compute slot and use the target pool; do not implement a second locking scheme."
  scope:
    in_scope:
      - "Add `apm2 fac warm` subcommand routed via crates/apm2-cli/src/commands/fac.rs."
      - "Acquire a FAC compute slot for warm (reuse compute-slot leasing from TCK-00488)."
      - "Enable target pool by default (CARGO_TARGET_DIR derived from slot + toolchain fingerprint)."
      - "Implement warm phases (selectable): cargo fetch --locked; cargo build --workspace --all-targets --all-features --locked; cargo nextest run ... --no-run; optional clippy/doc phases."
      - "Set CARGO_BUILD_JOBS and NEXTEST_TEST_THREADS from compute-slot policy unless explicitly overridden."
      - "Write warm receipt under $APM2_HOME/private/fac/maintenance/warm/ with schema apm2.fac.warm_receipt.v1."
      - "Do NOT add a global warm lock; compute slots are the stampede control."
    out_of_scope:
      - "Distributed cache or remote build farm."
      - "Replacing run_bounded_tests.sh."
  plan:
    steps:
      - "Add FacSubcommand::Warm and WarmArgs in fac.rs and route to fac_review::warm::run_warm."
      - "Implement warm.rs: phase runner with timings, env injection (target pool + jobs + test threads), receipt writer."
      - "Add JSON output mode and human output mode."
      - "Run fmt/clippy/doc/nextest checks."
  definition_of_done:
    evidence_ids: []
    criteria:
      - "`apm2 fac warm` succeeds on a clean main branch and writes a receipt."
      - "Warm respects compute-slot capacity (concurrent warm invocations block or fail fast according to flags)."
      - "Warm increases target-pool artifact reuse: running `apm2 fac gates` immediately after warm is measurably faster than a cold run (qualitative confirmation acceptable initially)."
  notes:
    security: |
      Warm must not read secrets or propagate uncontrolled env into subprocesses beyond
      an allowlist. Receipt must not include credentials.
    verification: |
      Manual: run apm2 fac warm twice; second run should be faster. Confirm that CARGO_TARGET_DIR is under APM2_HOME/private/fac/target_pool.
```

### TCK-00504 — Attestation surfacing for sccache + include `.cargo/config.toml` in input digests

```yaml
ticket_meta:
  schema_version: "2026-01-29"
  template_version: "2026-01-29"
  ticket:
    id: "TCK-00504"
    title: "Fail-closed attestation: include .cargo/config.toml + rustfmt version; future-proof sccache env"
    status: "OPEN"
  binds:
    prd_id: "PRD-0009"
    rfc_id: "RFC-0007"
    requirements: []
    evidence_artifacts: []
  custody:
    agent_roles: ["AGENT_IMPLEMENTER"]
    responsibility_domains: ["DOMAIN_SECURITY", "DOMAIN_RUNTIME"]
  dependencies:
    tickets: []
  scope:
    in_scope:
      - "Update gate_input_paths to include .cargo/config.toml for cargo-based gates (rustfmt/clippy/doc/test)."
      - "Add rustfmt --version to environment_facts (environment_digest) to eliminate fmt-gate fail-open across toolchain updates."
      - "(Future-proof) Update command_digest allowlist to include RUSTC_WRAPPER and SCCACHE_* env vars (harmless when unset)."
      - "(Optional) Add sccache --version to environment_facts (record if present; do not make mandatory unless a FAC profile requires it)."
      - "Add/adjust tests to ensure digests change when cargo config changes and when rustfmt version changes (fail-closed)."
    out_of_scope:
      - "Expanding environment_digest to every tool on the machine."
  plan:
    steps:
      - "Modify allowlisted env array in command_digest()."
      - "Modify gate_input_paths() to include .cargo/config.toml."
      - "Extend environment_facts() to include sccache version."
      - "Run existing attestation tests and update expected digests accordingly."
  definition_of_done:
    evidence_ids: []
    criteria:
      - "Attestation digest changes when RUSTC_WRAPPER changes."
      - "Attestation digest changes when .cargo/config.toml changes."
      - "Attestation digest changes when rustfmt version changes."
      - "No gate cache reuse occurs across these changes."
```

### TCK-00505 — Implement `apm2 fac gc` with enforced disk preflight (worktree targets + target pool + caches)

```yaml
ticket_meta:
  schema_version: "2026-01-29"
  template_version: "2026-01-29"
  ticket:
    id: "TCK-00505"
    title: "Implement `apm2 fac gc` with enforced disk preflight (worktree targets + target pool + caches)"
    status: "OPEN"
  binds:
    prd_id: "PRD-0009"
    rfc_id: "RFC-0007"
    requirements: []
    evidence_artifacts: []
  custody:
    agent_roles: ["AGENT_IMPLEMENTER"]
    responsibility_domains: ["DOMAIN_RUNTIME", "DOMAIN_SECURITY"]
  dependencies:
    tickets: []
  scope:
    in_scope:
      - "Add `apm2 fac gc` subcommand producing a deterministic plan and optional enforcement."
      - "Implement disk preflight helper (min-free) used by gates/warm/pipeline to auto-invoke gc when below threshold."
      - "Enumerate git worktrees and delete target/ dirs for cold worktrees (policy: keep hot N, TTL days)."
      - "If target pool is enabled: delete target-pool slot dirs that are not currently leased (LRU policy) when disk is still below min-free after pruning cold worktrees."
      - "(Optional) If sccache is enabled: delete SCCACHE_DIR as a last resort (do not rely on non-existent `sccache --trim`)."
      - "Write gc receipt under $APM2_HOME/private/fac/maintenance/gc/ with schema apm2.fac.gc_receipt.v1."
      - "Support --dry-run and --json."
    out_of_scope:
      - "Deleting worktrees or branches."
      - "Backing up state to the headscale peer (separate ticket)."
  plan:
    steps:
      - "Define GC policy defaults (min-free, ttl-days, keep-hot-worktrees)."
      - "Implement worktree enumeration and target pruning."
      - "Implement target-pool pruning logic using compute-slot lease metadata (do not delete leased slots)."
      - "Implement receipt writer + dry-run mode."
      - "Add a basic integration test for plan generation (unit test style)."
  definition_of_done:
    evidence_ids: []
    criteria:
      - "`apm2 fac gc --dry-run` prints a coherent plan without side effects."
      - "`apm2 fac gc` reclaims space by deleting cold worktree targets."
      - "Receipt is written and includes bytes freed."
  notes:
    security: |
      GC must never delete identity material. Only delete explicitly permitted cache paths.
      MUST protect against symlink traversal: only delete canonical paths under allowed roots, and refuse if any path component is a symlink.
```

### TCK-00506 — Compute lease semaphore + target pool substrate (cap concurrency, reuse builds)

```yaml
ticket_meta:
  schema_version: "2026-01-29"
  template_version: "2026-01-29"
  ticket:
    id: "TCK-00506"
    title: "Add FAC compute slots + target pool substrate (cap concurrency, reuse builds across worktrees)"
    status: "OPEN"
  binds:
    prd_id: "PRD-0009"
    rfc_id: "RFC-0007"
    requirements: []
    evidence_artifacts: []
  custody:
    agent_roles: ["AGENT_IMPLEMENTER"]
    responsibility_domains: ["DOMAIN_RUNTIME"]
  dependencies:
    tickets: []
  scope:
    in_scope:
      - "Introduce file-lock-based compute slots under $APM2_HOME/private/fac/locks/compute_slot_<i>.lock."
      - "Acquire a slot for apm2 fac warm, apm2 fac gates (full mode), and pipeline evidence execution."
      - "Use slot count default derived from memory policy (96GB -> 3 slots)."
      - "Compute conservative default CARGO_BUILD_JOBS based on cpu_count / slots."
      - "Set NEXTEST_TEST_THREADS based on cpu_count / slots to prevent runtime oversubscription."
      - "Implement slot metadata sidecar ($APM2_HOME/private/fac/locks/compute_slot_<i>.json) for GC safety + debugging."
      - "Implement target pool: on slot acquisition set CARGO_TARGET_DIR=$APM2_HOME/private/fac/target_pool/<toolchain_fingerprint>/slot_<i> (override any ambient CARGO_TARGET_DIR)."
    out_of_scope:
      - "Distributed leasing across nodes (future holonic lease integration)."
  plan:
    steps:
      - "Reuse the existing slot-leasing implementation pattern from fac_review/model_pool.rs (RAII + jitter) to implement compute slots."
      - "Implement toolchain fingerprint derivation (rustc -Vv hash) for target pool namespace."
      - "Integrate slot acquisition + env setting into gates/warm/pipeline."
      - "Expose slot count override via env var (FAC_MAX_CONCURRENT_SLOTS)."
  definition_of_done:
    evidence_ids: []
    criteria:
      - "Concurrent invocations of warm/gates do not exceed configured slot count."
      - "Slots release on process exit even on failure."
      - "CARGO_TARGET_DIR is set by FAC to the slot target pool for all cargo-based gates (including bounded tests via env allowlist propagation)."
```

### TCK-00507 — Mandate nextest for all FAC test execution paths + enforce bounded test caps

```yaml
ticket_meta:
  schema_version: "2026-01-29"
  template_version: "2026-01-29"
  ticket:
    id: "TCK-00507"
    title: "Mandate nextest for all FAC test execution paths + enforce bounded test caps"
    status: "OPEN"
  binds:
    prd_id: "PRD-0009"
    rfc_id: "RFC-0007"
    requirements: []
    evidence_artifacts: []
  custody:
    agent_roles:
      - "AGENT_IMPLEMENTER"
    responsibility_domains:
      - "DOMAIN_RUNTIME"
      - "DOMAIN_SECURITY"
  dependencies:
    tickets: []
  scope:
    in_scope:
      - "Remove cargo-test fallback for FAC tests across all call paths (pipeline + local gates)."
      - "Update gate_attestation default test command to nextest (eliminate reliance on callers passing overrides correctly)."
      - "Enforce bounded test caps in code: reject timeout_seconds > 240 unless explicit unsafe override is set."
      - "Propagate NEXTEST_TEST_THREADS (and other required env) through run_bounded_tests.sh allowlist."
      - "Improve error messaging when nextest is missing: fail fast with actionable remediation (nix develop / install cargo-nextest)."
    out_of_scope:
      - "Changing nextest config semantics or profiles beyond concurrency defaults."
  plan:
    steps:
      - "Update evidence.rs: build_pipeline_test_command() returns nextest always; remove cargo test fallback."
      - "Update gates.rs: ensure non-bounded local gates still use nextest; do not silently fall back to cargo test."
      - "Update gate_attestation.rs: default 'test' gate command uses cargo nextest run ... (matching policy)."
      - "Update run_bounded_tests.sh allowlist to include NEXTEST_TEST_THREADS (+ any missing env required by new policy)."
      - "Add regression tests: verify that nextest is used; verify caps enforcement; verify attestation uses nextest command."
  definition_of_done:
    evidence_ids: []
    criteria:
      - "No FAC test run path uses cargo test."
      - "Bounded test timeout cannot be increased above 240s without explicit unsafe override."
      - "Bounded test runner sees NEXTEST_TEST_THREADS when set by FAC policy."
  notes:
    security: |
      This ticket is policy enforcement. The goal is to eliminate ambient-state ambiguity and
      prevent accidental host-destabilizing overrides.
```

---

## 14. Summary of "what you should revert" from your current practice

* **Revert**: “`cargo test` aliases to nextest” as part of the canonical environment.
* **Keep/encode**: nextest as the **explicit** FAC test runner (already true on the bounded path; we make it true on the fallback path too).
* **Stop**: "one worktree = one target dir = one disk bomb". Move FAC to slot-scoped target pool.
* **Encode reproducibility** via:

  * `flake.nix` including `cargo-nextest` and `sccache`
  * repo-local cargo alias `cargo nt` (optional)
  * FAC commands that explicitly run nextest and explicitly manage cache policy

If you do only one thing from this amendment, do the target pool + enforced disk preflight. sccache is not the first lever.

That is the cleanest route to "scale out to more VPS nodes and instantly reproduce."
