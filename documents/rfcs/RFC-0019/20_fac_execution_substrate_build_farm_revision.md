# RFC-0019 Amendment A1: FAC Local Execution Substrate (FESv1)
#
# Why RFC-0019 (not RFC-0007):
# - This spec defines host-safety, provenance, attestation, and receipt semantics for FAC execution.
# - RFC-0007 is build-tooling optimization (mold/sccache/nextest recommendations), not FAC kernel semantics.
# - RFC-0007 is still referenced for build-tooling constraints (e.g., .cargo/config.toml, nextest profile),
#   but authority/receipt semantics must compose with RFC-0019 (FAC v0) invariants.

* **Document:** `documents/rfcs/RFC-0019/19_fac_execution_substrate_local_kernel.md`
* **Amends:** RFC-0019 (APPROVED) — operational substrate addendum (no PCAC/crypto changes)
* **Informs:** RFC-0007 — build-tooling decisions are constrained by this substrate (cache safety, isolation)
* **Integrates:** RFC-0028 + RFC-0029 (implemented) — external I/O security + economics primitives; this amendment defines explicit FAC↔EIO integration seams so these controls do not rot unused.
* **Date:** 2026-02-12
* **Target outcome (measurable; required for acceptance):**
  * **10x host-safe throughput** of FAC evidence cycles on the current host class **without** any increase in "catastrophic host failure" incidents (disk full, OOM, PID exhaustion, runaway CPU/IO thrash).
  * **0 "unauthorized actuation" executions** (jobs executed without RFC-0028 typed tool-intent authorization) in the default path.
  * **RFC-0028 + RFC-0029 are exercised in default flows**:
    * Every FAC job execution MUST validate a daemon-signed RFC-0028 `ChannelBoundaryCheck` (fail-closed).
    * Every job admission/order decision MUST produce an RFC-0029 admission trace (fail-closed), even in local-only mode.
  * **Forensic integrity**: evidence logs and receipts remain non-clobbering and attributable under ≥3 concurrent runs.
* **Primary surfaces touched by this amendment:**

  * `crates/apm2-cli/src/commands/fac.rs`
  * `crates/apm2-cli/src/commands/fac_review/{gates,evidence,gate_attestation,gate_cache}.rs`
  * `scripts/ci/run_bounded_tests.sh`
  * `flake.nix`
  * (INTEGRATION) `crates/apm2-core/src/channel/*` (RFC-0028 external I/O boundary enforcement; transport seam)
  * (INTEGRATION) `crates/apm2-core/src/economics/{admission,queue_admission}.rs` (RFC-0029 economics + queue admission; scheduler seam)
  * `documents/skills/implementor-default/SKILL.md`
  * (NEW) `crates/apm2-cli/src/commands/fac_review/{fac_resources,target_pool,repo_mirror,io_safety}.rs` (layout flexible; semantics are not)
  * (OPTIONAL, Phase ≥2) `crates/apm2-daemon/src/htf/HolonicClock` integration for authoritative time-stamping
* **Motivating operational constraints (explicit, measured on current host class):**

  * Ubuntu 24.04
  * 96 GB RAM
  * Frequently **≤ 3 simultaneous** `gate` executions across **3 worktrees**
  * Often **~13 worktrees exist concurrently** (not all active)
  * Near-term: heavy bash → Rust migration (security + perf)
  * Long-term: standardize **toolchain parity via Nix flakes** across the holonic network (NixOS is optional on greenfield nodes only; do **not** migrate the current host OS as part of FESv1)
  * Primary goal: **maximize FAC loop throughput** while guaranteeing **no catastrophic host failure** (disk/mem/CPU exhaustion), with **automatic/enforced cleanup**
  * Networking is **not available yet**; all semantics MUST be local-first with clean seams for later distribution.

---

## 0. Non-negotiable requirements (normative)

This amendment is a build-farm "kernel" spec. The following are MUSTs:

1. **Safety > speed.** The substrate MUST prevent catastrophic host failure (disk/mem/CPU/PIDs/IO exhaustion) even with multiple autonomous agents.
2. **Incremental deployability.** Every phase MUST be useful on a single VPS, MUST have rollback, and MUST NOT require a distributed system.
3. **Networkless control-plane semantics.** Job/lane semantics MUST NOT assume inter-node networking or remote services. Networking MAY exist for tool/dependency retrieval (e.g., crates.io), but MUST NOT be required for correctness of scheduling, leases, receipts, or cache-reuse decisions. Any network use MUST be explicit, best-effort, and never authoritative. If/when networking is added for job/receipt transport, remote inputs MUST be treated as **external I/O** and validated via RFC-0028 channel boundary enforcement + RFC-0029 economics (fail-closed).
4. **Declarative substrate target.** The design MUST map cleanly to flakes now and to a systemd-first Debian/Ubuntu host baseline. NixOS modules MAY be added later for greenfield nodes, but must not be assumed or required by FESv1.
5. **Fail-closed attestation semantics.** If anything that can affect correctness changes, gate-cache reuse MUST NOT silently continue.
6. **No ambient user state reliance.** FAC MUST NOT depend on aliases/dotfiles/`~/.cargo/config.toml`; FAC MUST set policy explicitly.
7. **No new long-lived bash daemons.** Control plane MUST be Rust and/or systemd-managed units. Bash scripts may exist only as transitional leaf executors.
8. **Brokered actuation is mandatory (RFC-0028).** Any FAC job that executes code (gates/warm/pipeline evidence/GC/reset) MUST be authorized by a **daemon-signed** RFC-0028 `ChannelContextToken` and MUST validate via `apm2_core::channel::decode_channel_context_token` + `validate_channel_boundary` before execution. Jobs lacking a valid token MUST be denied (fail-closed) and quarantined.
9. **RFC-0029 admission is mandatory.** Any job scheduling/admission decision MUST be representable as RFC-0029 and MUST emit an RFC-0029 decision trace (queue admission, and where applicable budget admission). "Local FIFO without trace" is explicitly forbidden in default mode.

## 0.2 Scope and non-goals (normative)

This amendment is explicitly scoped to **local host survivability + correctness** for running FAC evidence gates on a single node, with seams for later distribution.

### In scope
* Resource governance + backpressure for **evidence-gate execution** (`apm2 fac gates`, `apm2 fac pipeline` evidence phase, and new warm/GC maintenance).
* Correctness fail-closed semantics for **gate-cache reuse** (attestation inputs, provenance binding, policy hashing).
* Deterministic, symlink-safe cleanup primitives and disk preflight/GC enforcement.
* Local-first queue/leasing semantics that do **not** require networking.

### Out of scope (non-goals)
* Any redesign of FAC cryptography, PCAC/AJC semantics, or ledger protocol.
* "Full sandboxing" (containers/VMs) as a hard requirement in v1.
* Distributed routing, remote compilation caches, or multi-node consensus scheduling (later phases may add transport, not new semantics).

## 0.3 Repo-grounded primitives to reuse (normative)

To avoid inventing redundant mechanisms, FESv1 MUST reuse existing repo primitives where they already meet the safety/correctness needs:

* **APM2 home root:** `apm2_home_dir()` already defines `$APM2_HOME` and is used by FAC gate cache + evidence logs today.
* **Existing v2 gate cache + attestation:** `private/fac/gate_cache_v2` and `fac_review/gate_attestation.rs` are the current authority for reuse decisions; amendments must compose with that, not fork it.
* **Proven slot leasing pattern:** `fac_review/model_pool.rs::acquire_provider_slot` is the existing file-lock + jitter + RAII pattern; reuse it rather than inventing a second locking scheme.
* **Canonical JSON:** `apm2_core::determinism::canonicalize_json` is the canonicalizer; do not create ad-hoc "sorted keys" serializers.
* **RFC-0028 channel boundary enforcement:** `apm2_core::channel` implements fail-closed boundary checks (typed intent, declassification receipts, leakage budgets). Any future FAC transport/evidence ingress MUST route through these primitives instead of inventing parallel auth.
* **RFC-0029 economics + queue admission:** `apm2_core::economics` implements deterministic budget admission and HTF-bound queue admission (lane reservations + anti-starvation). FESv1 MUST treat these as the canonical semantics surface for scheduler admission once HTF envelopes are available.
* **Hash vocabulary alignment:** the repo already standardizes BLAKE3 "hash refs" with the `b3-256:` prefix (see `apm2_core::crypto` / schema registry traits).
  * New FESv1 substrate objects (job specs, receipts, logs, blobs) MUST use `b3-256:`.
  * Legacy FAC v0/v1 artifacts that still use SHA-256 (notably the current gate-cache v2 key material) MUST be explicitly tagged as `sha256:` when referenced.
  * The `blake3:` prefix MUST NOT be introduced; use `b3-256:` for BLAKE3-256 digests.

If this amendment proposes a new primitive that overlaps an existing one, it MUST justify why reuse is insufficient (and what the migration path is).

## 0.4 RFC-0028 / RFC-0029 integration seams (normative)

RFC-0028 and RFC-0029 are already implemented in this repository (`apm2_core::channel` and `apm2_core::economics`), but they are not meaningfully exercised by the current FAC local execution path. Unused security/economics primitives rot; late integration turns into a high-risk "big bang" change.

FESv1 MUST therefore introduce **explicit integration seams** so that:

1. **Transport seam = External I/O boundary.**
   Any future transport of FAC jobs, receipts, cache artifacts, or evidence bundles across process/node boundaries MUST be mediated by RFC-0028 channel boundary enforcement, with policy-digest binding and fail-closed behavior.

2. **Queue admission seam.**
   Scheduler admission and ordering MUST be **executed** in terms of RFC-0029 queue admission traces from day one.
   **Default mode MUST NOT use `NoOpVerifier`** because RFC-0029 explicitly fail-closes TP001 when signature verification is not configured.
   Local-only mode therefore requires the broker to expose a verifying key and workers to verify envelope signatures.

3. **Economics/budget seam.**
   Any budgets that become authoritative beyond local systemd/cgroup limits (e.g., evidence streaming backpressure, anti-entropy pull limits, network byte caps in distributed mode) MUST use RFC-0029 budget admission primitives rather than inventing new ad-hoc counters.

## 0.5 Authority surfaces and trust boundaries (normative)

FESv1 makes one security stance explicit:

*Everything under `$APM2_HOME/private/fac/**` is attacker-writable by A2 (local hostile process) unless proven otherwise.*

Therefore:

1. **Filesystem state is never authoritative by itself.** Queue items, lease files, cached receipts, evidence bundles, patch blobs, and logs MUST be treated as **external inputs** to the current process. Any state that can cause actuation or cache reuse MUST be authenticated and validated.
2. **FAC has a required broker.** A local Rust broker (implemented as part of `apm2-daemon` or a dedicated `fac-broker` unit) is the authority that:
   * issues RFC-0028 channel context tokens for job actuation,
   * issues RFC-0029 time authority envelopes (TP-EIO29-001),
   * and maintains the admitted policy roots used for RFC-0028 policy binding checks.
3. **Workers never trust "raw ChannelBoundaryCheck JSON".** A `ChannelBoundaryCheck` is authoritative only if reconstructed by decoding a daemon-signed channel context token (`decode_channel_context_token`). Accepting raw JSON is forbidden.
4. **Quarantine is first-class.** Any job/evidence/cache artifact that fails RFC-0028 or RFC-0029 validation MUST be moved to a quarantine directory and MUST NOT be deleted blindly. Quarantine is how you preserve forensics for A2/A1 events.

## 0.1 Terminology (local build-farm primitives)

* **Lane**: A bounded, cullable execution context with deterministic identity, dedicated workspace+target namespace, and a fixed resource profile.
  **Normative clarification:** In FESv1, *lanes are the sole concurrency primitive*. Any "slot" terminology elsewhere is an alias for "lane" and MUST NOT be implemented as a second independent semaphore. ("Lane leases" are the lease records for lanes, not a separate concurrency unit.)
  **Normative clarification 2:** The term **compute slot** is forbidden in FESv1. If the codebase uses "slot" in legacy modules (e.g., model pool), that is an implementation detail; the substrate contract is **lane**.
* **Job**: An immutable spec (what to run, against which inputs) that is queued, leased to a lane, executed, and yields receipts.
* **Queue lane (RFC-0029):** A *scheduling class* used for fairness/anti-starvation and control-plane priority (e.g., `stop_revoke`, `control`, `bulk`).
  This is **not** an execution lane. FESv1 records queue lanes in `FacJobSpecV1.queue_lane` to align with `apm2_core::economics::QueueLane` and to make RFC-0029 queue admission pluggable without schema churn.
* **Receipt stream**: An append-only, mergeable set of immutable receipts; receipts are the ground truth, not runtime state.
  Ordering for presentation MUST be derived from HTF stamps when available, otherwise from a deterministic fallback tuple
  `(monotonic_time_ns, node_fingerprint, receipt_digest)`.
* **Execution profile**: The attested environment+policy facts (including lane profile hash + toolchain fingerprint) that gate-cache keys depend on.

* **FAC Broker**: The local authority service (Rust; systemd-managed) that issues:
  * RFC-0028 channel context tokens (typed tool-intent actuation authorization),
  * RFC-0029 time authority envelopes (TP-EIO29-001) and horizon references (TP-EIO29-002/003),
  * and admitted policy root digests for RFC-0028 policy-binding checks.
  The broker is required for default-mode execution.

* **Channel context token (RFC-0028):** A base64-encoded, daemon-signed token that reconstructs a `ChannelBoundaryCheck` via `decode_channel_context_token`.
  This is the only acceptable authorization carrier for FAC actuation.

* **Time authority envelope (RFC-0029):** A signed `TimeAuthorityEnvelopeV1` used for queue admission TP-EIO29-001.
  In local-only mode, this is still required and MUST be issued by the broker (not synthesized by workers).

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
* `scripts/ci/workspace_integrity_guard.sh`
* `scripts/ci/review_artifact_lint.sh`
* **test gate**: uses `cargo nextest run ...` inside `scripts/ci/run_bounded_tests.sh` when cgroup v2 is available.

Key fact: **nextest is already the default execution for the test gate** when the bounded runner path is active (the pipeline builder constructs `cargo nextest run ...`). **However, both the pipeline and local gates paths still fall back to `cargo test`** when bounded execution is unavailable or when `EvidenceGateOptions.test_command` is unset.

Clarification (missing in the draft): **there are two "fallback" paths today**:

* **Pipeline path** (`run_evidence_gates_with_status`) uses `build_pipeline_test_command(...)` and falls back to `cargo test` if bounded runner isn't available.
* **Local `apm2 fac gates` path** (`run_evidence_gates(...)` via `gates.rs`) runs whatever `gates.rs` passes as `EvidenceGateOptions.test_command`. If `gates.rs` does **not** pass a command (e.g., bounded runner unavailable), `run_evidence_gates` falls back to `cargo test` directly.

If we "mandate nextest", we must fix **both** call paths (pipeline + local), not just the pipeline builder.

### 1.1.1 Repo-grounded correction: local full-mode already enforces "clean tree"

The **local** `apm2 fac gates` path already fail-closes on dirty state in **full mode**:
* `--quick` explicitly accepts dirty and skips gate-cache read/write.
* full mode requires a clean working tree before any cacheable gate execution.

This means "dirty tree cache reuse" is **not** the dominant correctness risk for local full-mode runs.

### 1.1.2 The actual correctness hole: pipeline-mode may execute against a drifting or dirty workspace

The **pipeline** mode (`apm2 fac pipeline`) receives a `sha` argument and executes gates in `cwd`
without proving:
1) `git rev-parse HEAD == sha`, and
2) the working tree is clean.

Worse: the current attestation `input_digest()` uses `HEAD^{tree}` and `git rev-parse HEAD:<path>`
for tracked inputs, which **does not reflect uncommitted working-tree modifications**. Therefore:
* A dirty workspace can run gates against dirty content,
* while producing an attestation digest that still corresponds to the *clean HEAD tree*,
* enabling false-positive reuse (fail-open) for the `sha` directory in gate cache.

**This amendment treats "pipeline SHA drift" and "dirty-but-attests-clean" as correctness-critical.**
The substrate MUST either (a) hard-reset to the target SHA in an isolated checkout, or
(b) incorporate a dirty-diff digest that is *actually* bound into attestation inputs.

### 1.2 Bounded test environment today

The bounded runner:

* Uses `systemd-run --user` transient scope/service under a name like `apm2-ci-bounded-...`
* Enforces:

  * timeout (defaults bounded by `gates.rs` max 240s)
  * memory max (default 24G passed from CLI)
  * pids max
  * CPU quota
* Uses an **explicit allowlist** to propagate selected env vars into the unit (`run_bounded_tests.sh` has `SETENV_ARGS` built from a for-loop allowlist).

Operational footgun (needs to be treated as a *substrate requirement*, not a "maybe"):

* `systemd-run --user` requires a functioning user bus. On headless/VPS setups this frequently fails unless the user session is correctly configured (and CI uses a documented workaround). This amendment therefore treats "bounded runner availability" as a **first-class availability constraint**, not a "maybe".

Correctness footgun (missing in the draft, and currently **fail-open**):

* The substrate's correctness risk is specifically **(pipeline)** "execution workspace != intended SHA" and
  **(attestation)** "tracked file inputs hashed via `HEAD:<path>` ignore dirty content."
  The substrate MUST:
  * prove `HEAD==sha` + clean tree for any cacheable pipeline run, OR
  * execute from an isolated checkout at `sha` (preferred), OR
  * incorporate a dirty-diff digest into attestation input material and disable cache reuse when unknown.

### 1.2.1 Repo-grounded additional hazard: evidence logs are global and race-prone

Today, evidence logs are written under a fixed path per gate:
* `~/.apm2/private/fac/evidence/{gate}.log`

This is **not concurrency-safe**. Multiple simultaneous `apm2 fac gates` runs (across worktrees, or pipeline + local gates) can:
* truncate each other's logs,
* interleave output,
* and destroy forensic value during incident/debugging.

FESv1 MUST define **per-job (or per-lane) log namespaces** and MUST NOT write to a single global `{gate}.log` path once concurrent execution is supported.

### 1.3 Gate cache and attestation today

Gate cache receipts are written (in full mode) under:

* `~/.apm2/private/fac/gate_cache_v2/<SHA>/...`

Attestation digest computation is in:

* `crates/apm2-cli/src/commands/fac_review/gate_attestation.rs`

Important details:

* `command_digest()` hashes an allowlisted set of environment variables (e.g., `RUSTFLAGS`, `RUSTDOCFLAGS`, `CARGO_BUILD_JOBS`, `CARGO_INCREMENTAL`, `RUSTUP_TOOLCHAIN`).
* `gate_input_digest()` hashes selected paths (e.g., `.config/nextest.toml`, `scripts/ci/run_bounded_tests.sh`), but **does not currently include `.cargo/config.toml`**.
* `environment_digest()` includes versions for: kernel, rustc, cargo, rustfmt, clippy, nextest, systemd-run. **No sccache version** is captured today.

Correction (repo-grounded): `environment_digest()` currently captures **string outputs** from:

* kernel (`uname -sr`)
* rustc (`rustc --version`)
* cargo (`cargo --version`)
* clippy (`cargo clippy --version`)
* nextest (`cargo nextest --version`)
* systemd-run (`systemd-run --version`)

It does **not** capture `rustfmt --version` today (latent fail-open for fmt-gate correctness across toolchain changes).

This matters: any "build cache substrate" change must be surfaced into attestation in a way that remains **fail-closed** (no unsafe reuse).

Repo-grounded missing pieces that matter to fail-closed semantics:

* `.cargo/config.toml` already exists in-repo and materially changes builds (e.g., linker + rustflags). It is currently **not** included in attestation input digests.
* `~/.cargo/config.toml` (ambient) can also change builds. The substrate MUST NOT depend on it; the safe approach is to set `CARGO_HOME` under `$APM2_HOME` for FAC executions and treat the FAC-managed cargo config as authoritative policy input.

---

## 2. Problem statement (what must become true)

### 2.1 The real bottleneck is not "tests are slow"; it's uncontrolled shared-host resource collapse

Observed operational pattern:

* Many git worktrees exist simultaneously (often ~13).
* Each worktree has its own `target/` directory by default.
* Compilation-heavy gates (`clippy`, `doc`, `test`) can each trigger distinct compilation flows and output sets.
* The **bounded** test gate is sensitive: if it has to do a large cold compile, it can exceed:

  * **Wall-time 240s** (by policy; should not be increased)
  * **MemoryMax 24G** (policy default)

Your stated goal is not to "relax the box"; it is to **make cold-start rare** and **keep the host stable** under parallel agents.

### 2.2 Failure modes to treat as first-class (explicitly in substrate semantics)

1. **Disk exhaustion** (targets/logs/evidence artifacts) is the dominant catastrophic failure mode.
2. **CPU/IO thrash** from unbounded parallel cargo/clippy/doc/test invocations is the second.
3. **PID exhaustion** and **runaway processes** are the third (especially with nextest default concurrency).
4. **Containment bypass** is a security and correctness risk if any helper (e.g., sccache) can execute compilers outside the bounded unit.
5. **Incorrect cache reuse** (dirty tree, missing inputs, missing tool versions) is correctness failure, not just "cache isn't perfect".
6. **Symlink/rmtree disasters** during cleanup/reset are catastrophic and must be engineered out.

The current "compute slots + target pool" proposal is necessary but insufficient: it addresses concurrency and caching, but it does not define the **unit of containment** (lane), **job semantics**, **queueing**, **leases**, or **receipts as ground truth**.

### 2.3 Threat model (normative)

This substrate is a **host-safety kernel**. We therefore model both accidental overload and adversarial behavior.

#### 2.3.1 Adversaries
* **A0: Accidental overload** — multiple agents trigger overlapping builds/tests/logging.
* **A1: Malicious repo content** — PR introduces tests/build scripts that attempt to exhaust resources, escape containment, or sabotage cleanup.
* **A2: Local hostile process** — another process on the host attempts symlink/TOCTOU attacks against GC/reset, or races queue/lease files.
* **A3: Local artifact forgery** — a process writes forged queue items, forged "successful gate receipts", or forged evidence bundles under `$APM2_HOME/private/fac/**` to trick the system into:
  * executing unauthorized actuation,
  * accepting false-positive gate cache reuse,
  * or suppressing alerts by overwriting logs.

#### 2.3.2 In-scope attacks and required mitigations
1) **Unbounded stdout/stderr capture → RAM blow-up**
   * Current evidence execution captures entire stdout/stderr into memory before writing logs.
   * FESv1 MUST stream output to files with hard byte caps (see §6.3) and avoid unbounded in-memory buffering.

2) **Log file bloat → disk exhaustion**
   * FESv1 MUST enforce per-gate log caps and per-lane log quotas; GC MUST be able to reclaim space deterministically.

3) **Symlink/TOCTOU deletion attack → catastrophic data loss**
   * FESv1 MUST use a single symlink-safe deletion primitive with an allowlisted root set (see §4.7 and §6.2).

4) **Containment bypass via helper daemons (e.g., compiler wrappers)**
   * Any helper that can spawn compilers/tests outside the bounded cgroup is treated as an integrity regression.
   * Default posture: helpers are disabled unless proven to preserve cgroup membership (see §15.2).

5) **Queue/lease corruption and double execution**
   * Queue claim MUST be atomic; lease ownership MUST be exclusive; crash recovery MUST be defined by receipts (see §4.5–§4.6).

6) **Forged job specs / forged receipts / forged evidence bundles**
   * Default mode MUST require RFC-0028 daemon-signed tokens for actuation authorization; workers MUST deny/quarantine jobs lacking valid tokens (§4.5).
   * Gate-cache reuse MUST be fail-closed if the cached artifact cannot be bound to:
     * a valid attestation digest, AND
     * a receipt that includes RFC-0028 authorization + RFC-0029 admission traces.
     Legacy `gate_cache_v2` entries without these bindings MUST be treated as "untrusted legacy" and MAY be reused only under explicit `--allow-legacy-cache` (unsafe).

---

## 3. What this amendment changes in RFC-0007 (and why it still belongs in RFC-0007)

RFC-0007 (currently DRAFT) is about build optimizations; it already contains:

* `TB-002: Compilation Cache` (sccache) in `03_trust_boundaries.yaml`
* Optional nextest decisions (`DD-002`, `DD-003`) in `02_design_decisions.yaml`

This amendment modifies RFC-0007 in four ways (execution substrate is a build optimization when done correctly):

1. It upgrades "optional nextest" to a **mandatory FAC test runner policy** (explicit invocation; no alias reliance).
2. It replaces "worktree is the execution unit" with a **finite execution lane pool** (lane = blast radius).
3. It turns "cross-worktree build reuse" into a **lane-scoped target namespace** (target pool per lane, per toolchain fingerprint).
4. It makes **resource hygiene and enforced preflight** part of the FAC substrate contract, not a human ritual.

Ordering of accelerators remains:

   **Primary accelerator (new):** slot-scoped `CARGO_TARGET_DIR` pool ("target pool").

   **Secondary accelerator (optional, gated):** sccache, only after containment + benefit verification.

This amendment explicitly **does not** attempt to redesign FAC protocol cryptography; it is about the **local execution substrate** and safety of running many agents.

---

## 4. FAC Execution Substrate v1 (FESv1): execution lanes + local scheduler (networkless)

FESv1 is the "local build farm kernel" for APM2 agents.

### 4.1 Entities (stable semantics; distribution later)

* **Node**: a single host instance (today: one Ubuntu VPS). Future: many nodes under headscale.
* **Lane**: a bounded execution context on a node with deterministic identity and a fixed resource profile.
* **Job**: an immutable spec that produces receipts and evidence artifacts.
* **Scheduler**: local-only dispatcher that leases jobs to lanes with backpressure.
* **Receipt**: an append-only record; the ground truth (ledger-first).

### 4.2 Execution lanes (required model)

Each lane is:

* a **clean checkout** rooted at: `$APM2_HOME/private/fac/lanes/<lane_id>/workspace`
  produced from a node-local **bare mirror** (see §4.2.1)
* a long-lived, **cullable** execution context (resettable without touching other lanes)
* a fixed resource profile (enforced via systemd/cgroups)
* a dedicated target namespace (**the** target pool): `$APM2_HOME/private/fac/lanes/<lane_id>/target/<toolchain_fingerprint>`
* a dedicated log namespace: `$APM2_HOME/private/fac/lanes/<lane_id>/logs`

Lane lifecycle (persisted via receipts + lease records; runtime is not authoritative):

`IDLE → LEASED → RUNNING → CLEANUP → IDLE`

Exceptional:

`* → CORRUPT → RESET → IDLE`

#### 4.2.1 Repository substrate (mandatory): node-local bare mirror + lane checkouts

FESv1 introduces a repository substrate layer to eliminate ambient worktree contamination and to create
clean seams for later multi-node transport.

* Mirror root: `$APM2_HOME/private/fac/repo_mirror/<repo_id_sanitized>.git/` (bare)
* Lane checkout source: the mirror, not the developer's worktree.
* Default execution source is a **clean commit** (`head_sha`).
* Dirty trees are handled only by explicit **patch injection** (see §5.3.3).

Minimum required invariants:
* If `job.source.kind == "mirror_commit"`, the lane workspace MUST be reset to the attested commit SHA before execution.
* If `job.source.kind == "patch_injection"`, the injected patch digest MUST be included in attestation material and cache keys.
* If neither invariant can be met, gate-cache reuse MUST be disabled (fail-closed).

### 4.3 Backpressure is lane-count + lane profiles (not "worktrees")

The substrate MUST enforce a finite number of concurrent heavy jobs by construction:

* `lane_count` is finite (default derived from memory policy; on the current box: 3).
* each lane runs **at most one job at a time** (exclusive lease).
* each job executes under lane resource limits (CPU/memory/PIDs/IO + timeouts).

**Non-duplication invariant:** FESv1 MUST NOT introduce a second concurrency governor ("compute slots") independent from lane leasing. If a later section discusses "slots", those slots MUST map 1:1 to lanes and reuse the lane lock/lease record.

### 4.4 Leasing (mechanism, not vibes)

Leasing is a file-lock + durable lease record:

* Lock file: `$APM2_HOME/private/fac/locks/lanes/<lane_id>.lock`
* Lease record: `$APM2_HOME/private/fac/lanes/<lane_id>/lease.v1.json`

Rules:

* lease acquisition MUST be atomic and exclusive (reuse the existing file-lock leasing pattern used by `fac_review/model_pool.rs`).
* lease record MUST include: `job_id`, `pid`, `started_at`, `lane_profile_hash`, `toolchain_fingerprint`.
* stale lease handling MUST be fail-closed:
  * if lock is free but lease record claims RUNNING and the pid is alive → treat as CORRUPT and require reset
  * if lock is free and pid is dead → scheduler may transition to CLEANUP and then IDLE (writing receipts)

### 4.5 Job queue (local-first; distribution later)

Queue is a filesystem-backed ordered set of job specs under `$APM2_HOME/private/fac/queue`.

Required properties:

* FIFO within a **(queue_lane, priority)** band
* explicit priority levels (small integer; higher wins within the same queue lane)
* explicit **queue lanes** aligned with RFC-0029 (`apm2_core::economics::QueueLane`)
  * minimum v1 set: `stop_revoke`, `control`, `bulk`
* cancellation by job id
* atomic claiming (no double-execution)
* crash tolerance (claimed jobs must requeue or be marked failed with receipt)

Minimal viable layout:

* `queue/pending/`
* `queue/claimed/`
* `queue/done/`
* `queue/cancelled/`
* `queue/denied/` (new; RFC-0028/0029 fail-closed outcomes with reason sidecar)
* `queue/quarantine/` (new; malformed/tampered/unparseable inputs preserved for forensics)

Ordering rule (v1, local):

1. `queue_lane` priority order MUST match RFC-0029 lane ordering (highest first): `stop_revoke > control > consume > replay > projection_replay > bulk`.
   (FESv1 may initially only emit `{stop_revoke, control, bulk}`, but MUST preserve ordering semantics for forward compatibility.)
2. Within a `queue_lane`, `priority` (descending) wins.
3. Ties break by `enqueue_time` (oldest first), then `job_id` (lexicographic) for determinism.

Claim algorithm (local-only):

1. Workers (either CLI or daemonized `apm2-daemon` later) scan `pending/` for highest priority then oldest `enqueued_at`.
2. Claim uses atomic `rename()` from `pending/<job_id>.json` → `claimed/<job_id>.json`.
3. The claiming worker then acquires a lane lease and executes the job.

Claim algorithm (required amendments for RFC-0028 + RFC-0029):

0. **Precondition:** workers MUST treat `queue/pending/*.json` as untrusted external input.
1. Before claiming, worker MUST parse `FacJobSpecV1` with bounded deserialization and verify:
   * `job_spec_digest` is correct (§5.3.3),
   * `actuation.channel_context_token` is present,
   * token decodes with `decode_channel_context_token(...)` and passes `validate_channel_boundary(...)`.
   If any check fails, worker MUST move the job file to `queue/quarantine/` (new) and MUST emit a denial receipt.
2. Worker MUST compute an RFC-0029 `QueueAdmissionDecision` for the job (using broker-issued envelopes/horizons; §4.5.1).
   If verdict != Allow, worker MUST not claim the job; instead it MUST leave it pending (or move to `queue/denied/` with reason).
3. Only after RFC-0028 + RFC-0029 checks pass may the worker claim via atomic `rename()`.

RFC-0029 integration seam:

* Phase 1 MUST still compute and record an RFC-0029 `QueueAdmissionDecision` (see `apm2_core::economics::evaluate_queue_admission`) using broker-issued local envelopes/horizons.
* Phase ≥2 strengthens the authority source (HTF-backed envelopes from HolonicClock) but does **not** introduce new semantics.

#### 4.5.1 Local RFC-0029 envelope/horizon strategy (mandatory; v1)

To avoid "economics implemented but unused", FESv1 defines a local-only strategy that still satisfies TP-EIO29-001/002/003:

* **Boundary id:** `boundary_id = "apm2.fac.local"` (stable).
* **Authority clock id:** `authority_clock = "apm2-daemon.holonic_clock.v1"` (stable string).
* **Tick source:** broker uses `HolonicClock` (or equivalent monotonic authority) to produce current tick and short-lived envelopes.
* **TP-EIO29-001 envelope:** broker issues `TimeAuthorityEnvelopeV1` signed by the daemon signing key; workers verify signatures (no `NoOpVerifier` in default mode).
* **TP-EIO29-002 freshness horizon:** broker maintains a resolved `FreshnessHorizonRef` whose `tick_end` is always ≥ current evaluation window end; `horizon_hash` binds to broker state.
  The broker also maintains a `RevocationFrontierSnapshot { current: true }` with a non-zero `frontier_hash`.
  In local-only mode these hashes can be commitments to "single-node trivially current" state, but they MUST still be non-zero and replay-stable.
* **TP-EIO29-003 convergence horizon:** broker emits `ConvergenceHorizonRef { resolved: true }` plus a single "local authority set" hash and a `ConvergenceReceipt { converged: true }`.
  This exercises the predicate without requiring multi-node networking.

Workers MUST:
* build `QueueAdmissionRequest` from broker-issued state + job cost,
* build `QueueSchedulerState` from observed queue snapshot,
* call `evaluate_queue_admission(...)`,
* deny/quarantine if verdict != Allow,
* write the decision trace into receipts (§5.3.4).

This is the networkless seam: a future distributed scheduler can transport `FacJobSpecV1` objects and still use the same lane/job semantics.

### 4.6 Containment: all compilers/tests MUST run inside bounded units

Baseline requirement: cargo, rustc, nextest, and any helper processes spawned by the job MUST remain inside the intended cgroup boundary for the lane/job.

Mechanism (Phase 1, user-mode):

* execute each job via `systemd-run --user` transient units with explicit properties derived from `LaneProfileV1`.

Mechanism (Phase 3, stronger brokered mode; optional but recommended for hostile workloads):

* a systemd **system** unit executes jobs as a dedicated service user (no user-bus), preventing "spawn new user units" escape hatches.

If bounded execution cannot be proven available, FAC MUST fail closed with actionable remediation (enable linger / run via systemd-managed apm2-daemon).

### 4.7 Cleanup/reset MUST be symlink-safe (rmtree disasters are catastrophic)

GC and lane reset MUST NOT use naive recursive deletion (e.g., `rm -rf` or `std::fs::remove_dir_all`) on paths influenced by lane/job state.

Required deletion primitive: `safe_rmtree_v1(root, allowed_parent)`:

* Inputs MUST be absolute paths. `allowed_parent` MUST be a directory owned by the current user and mode 0700 (or stricter).
* The implementation MUST NOT rely on `std::fs::canonicalize()` as its primary safety check (it follows symlinks and creates TOCTOU windows).
* The implementation MUST enforce **no symlink traversal** using one of:
  * (preferred) file-descriptor-relative walking (`openat`/`cap-std`) with `O_NOFOLLOW` and `AT_SYMLINK_NOFOLLOW`-style checks, or
  * a conservative "refuse-on-ambiguity" walk that verifies each component with `symlink_metadata()` immediately before opening/removing it.
* `root` MUST be verified to be strictly under `allowed_parent` **by path component**, not by string prefix.
* The deleter MUST:
  * unlink symlinks as files (never follow),
  * refuse to cross filesystem boundaries unless explicitly allowed by policy,
  * and refuse to delete if it encounters unexpected file types (device nodes, sockets) unless policy explicitly allows.
* On any ambiguity or suspicious race, `safe_rmtree_v1` MUST:
  * abort,
  * write a "refused_delete" receipt,
  * and mark the lane CORRUPT.

This is non-negotiable: one symlink bug can delete the host.

### 4.8 Cross-job contamination controls (lane reset protocol)

Each job MUST end in a cleanup step before the lane returns to IDLE:

* hard reset the git worktree to the job's attested revision
* `git clean -ffdx` (or equivalent) inside the lane workspace
* remove lane-local temp dirs (`target/tmp`, nextest temp, etc.)
* enforce log retention/quota per lane (size and TTL)

If cleanup fails, the lane MUST be marked CORRUPT and refused for further leases until reset.

## 4.9 Output handling (normative): bounded streaming, never unbounded buffering

Evidence gate execution MUST NOT capture unbounded stdout/stderr into memory.
Implementations MUST:
* stream stdout/stderr to per-gate log files,
* enforce `max_gate_log_bytes` (truncate with an explicit sentinel),
* enforce `max_gate_capture_bytes` for any in-memory summaries (e.g., last N KB),
* record truncation in receipts/metadata so debugging remains possible without risking host stability.

Additional hard requirements (normative):
* Log paths MUST be unique per (lane_id, job_id, gate_name). A global `{gate}.log` path is forbidden once concurrency exists.
* Implementations MUST continue draining pipes after `max_gate_log_bytes` is reached to avoid child-process deadlock (i.e., "truncate on disk, discard thereafter").
* If logs are truncated, the receipt MUST include:
  * `log_truncated: true`
  * `log_bytes_written`
  * `log_bytes_discarded_estimate` (best-effort counter)
  * and the sentinel marker MUST be deterministic (stable bytes) so the log digest is stable.

---

## 5. Interfaces (precise; implementable)

This section is normative. If an interface is not specified here, it is not part of the substrate contract.

### 5.1 Directory layout under `$APM2_HOME` (authoritative)

All FAC lane execution state MUST live under `$APM2_HOME/private/fac` so that:
* GC can be enforced coherently
* backup/restore is well-defined
* ambient `$HOME/.cache` sprawl is avoided

Required layout:

* `private/fac/lanes/<lane_id>/workspace/`
* `private/fac/lanes/<lane_id>/target/<toolchain_fingerprint>/`
* `private/fac/lanes/<lane_id>/logs/`
* `private/fac/lanes/<lane_id>/logs/<job_id>/` (per-job log namespace; required once queueing/concurrency exists)
* `private/fac/queue/{pending,claimed,done,cancelled}/`
* `private/fac/queue/{denied,quarantine}/` (new; §4.5)
* `private/fac/receipts/` (content-addressed receipt objects; see §5.3)
* `private/fac/locks/` (lane locks, queue locks, optional global locks)
* `private/fac/evidence/` (**legacy**; existing global per-gate logs; will be deprecated in favor of per-lane/per-job logs)
* `private/fac/repo_mirror/` (bare mirrors; §4.2.1)
* `private/fac/cargo_home/` (FAC-managed `CARGO_HOME`; §5.4 / §10.4)
* `private/fac/broker/` (new; broker-admitted roots + RFC-0029 horizons; §0.5, §4.5.1)
  * `private/fac/broker/admitted_policy_root.v1` (non-secret; digest only)
  * `private/fac/broker/admitted_canonicalizer_tuple.v1` (non-secret; digest only)
  * `private/fac/broker/time_envelopes/` (short-lived envelopes; optional cache)
  * `private/fac/broker/horizons/` (freshness + convergence refs; replay-stable commitments)
* `private/fac/scheduler/` (new; RFC-0029 scheduler snapshot persistence)
  * `private/fac/scheduler/state.v1.json` (serialized queue lane backlog + max_wait_ticks)

Legacy compatibility:
* `private/fac/gate_cache_v2/` remains during migration; new receipts MUST record enough to migrate away from it later.

### 5.2 CLI (required commands)

All commands MUST support `--json` for machine output and MUST fail with non-zero exit codes on invariant violations.

#### 5.2.1 `apm2 fac lane status`

Shows all lane states derived from (a) lock state, (b) lease record, (c) last receipt.

* human output: table (lane_id, state, job_id, started_at, toolchain_fingerprint, last_exit)
* json output: array of `LaneStatusV1` objects (schema may be embedded; not required in this amendment)

#### 5.2.2 `apm2 fac lane reset <lane_id>`

Resets a lane to a known-good state.

Rules:
* MUST refuse to reset if lane is RUNNING unless `--force` is provided.
* `--force` MUST stop/kill the lane's active unit (KillMode=control-group) before deletion.
* MUST use `safe_rmtree_v1` for deletion (see §4.7).
* MUST write a `FacJobReceiptV1`-style receipt with `kind="lane_reset"` (or a dedicated `LaneResetReceiptV1`; either is acceptable if schema-id is stable).

#### 5.2.3 `apm2 fac enqueue <job_spec>`

Enqueues a job without executing it immediately.

* `<job_spec>` is a path to a JSON file containing `FacJobSpecV1` OR `-` (stdin).
* on success: prints `job_id` (human) or a JSON object with `{ job_id, queued_path }`

Cancellation (mandatory for queue semantics):
* `apm2 fac enqueue --cancel <job_id>` MUST move the job to `queue/cancelled/` if pending, or mark it cancelled if claimed/running (best-effort signal).

#### 5.2.4 `apm2 fac warm`

Lane-scoped cache warm.

* default: warm **all lanes** to reduce cold-start probability
* `--lane <lane_id>`: warm only one lane
* MUST acquire lane lease(s) internally
* MUST write `WarmReceiptV1`

#### 5.2.5 `apm2 fac gc`

Global and lane-scoped enforced GC.

* default: global GC across all FAC-controlled roots
* `--lane <lane_id>`: only prune that lane's logs/targets
* MUST write `GcReceiptV1`
* MUST be callable automatically from disk preflight (see §6.2)

#### 5.2.6 `apm2 fac gates`

Runs evidence gates using the lane substrate.

Rules:
* MUST acquire a lane lease internally (no "run directly in caller worktree" once Phase 1 is complete)
* MUST use nextest explicitly (no cargo-test fallback)
* MUST fail closed if nextest is missing
* MUST enforce the 240s/24G test policy (no override without explicit unsafe flag)

Default execution mode change (required):
* `apm2 fac gates` MUST default to **brokered queue execution**:
  * create `FacJobSpecV1(kind="gates")`,
  * obtain an RFC-0028 channel context token from the broker for this job spec digest,
  * enqueue to `queue/pending/`,
  * and wait for completion by default.
* `apm2 fac gates --direct` is allowed only as **explicit unsafe mode** and MUST:
  * disable gate-cache read/write,
  * emit a receipt marked `unsafe_direct: true`,
  * still acquire a lane lease and enforce containment, but MUST NOT be considered an authoritative "acceptance fact".

#### 5.2.7 `apm2 fac worker` (new; mandatory for default mode)

Consumes the local queue and executes jobs in lanes.

* `apm2 fac worker --once` runs a single claim/execute cycle then exits.
* `apm2 fac worker` without `--once` runs continuously (systemd-managed recommended).
* Worker MUST implement RFC-0028 authorization checks and RFC-0029 admission checks (§4.5).
* Worker MUST write receipts for:
  * deny/quarantine outcomes (authorization/admission failures),
  * and execution outcomes (success/failure).

### 5.3 JSON schemas (required; with hashing rules + storage locations)

All schemas MUST:
* include `schema` (stable ID with version suffix)
* use `#[serde(deny_unknown_fields)]` in implementation
* be bounded in size on read (reuse apm2-core FAC bounded deserialization primitives)

Canonical hashing rules:
* Hash input is canonical JSON bytes. Implementations MUST reuse the repo's canonicalization primitive
  (`apm2_core::determinism::canonicalize_json`) rather than ad-hoc "sorted keys" serializers.
* Hash algorithm for substrate receipts/specs is **BLAKE3-256**, aligned with existing APM2 hash refs.
  Implementations MUST use the same hex encoding and prefix format used in the repo (`b3-256:<hex>`).
* Domain separation is achieved by hashing `schema` + NUL + canonical JSON:
  `hash_bytes = (schema_id || "\0" || canonical_json_bytes)`
  `digest = blake3(hash_bytes)`

Storage rules:
* Each receipt is stored content-addressed:
  * `$APM2_HOME/private/fac/receipts/<hex>.json` (filename is hex only; `b3-256:` prefix is a logical ref, not part of the path)
* Queue objects are stored by job_id:
  * `$APM2_HOME/private/fac/queue/pending/<job_id>.json`

#### 5.3.1 `LaneProfileV1`

```jsonc
{
  "schema": "apm2.fac.lane_profile.v1",
  "lane_id": "lane-00",
  "node_fingerprint": "b3-256:…",
  "resource_profile": {
    "cpu_quota_percent": 200,
    "memory_max_bytes": 25769803776,
    "pids_max": 1536,
    "io_weight": 100
  },
  "timeouts": {
    "test_timeout_seconds": 240,
    "job_runtime_max_seconds": 1800
  },
  "policy": {
    "fac_policy_hash": "b3-256:…",
    "nextest_profile": "ci",
    "deny_ambient_cargo_home": true
  }
}
```

Lane profile storage:
* `$APM2_HOME/private/fac/lanes/<lane_id>/profile.v1.json`

Lane profile hash:
* `LaneProfileHash = b3-256(canonical(LaneProfileV1))`

#### 5.3.1.1 `FacPolicyV1` (mandatory hashed policy object)

`FacPolicyV1` is the single authoritative knob surface that cache reuse depends on.
It MUST include (at minimum):
* resource caps (cpu/mem/pids/timeouts)
* disk preflight thresholds and GC escalation order
* env allowlist/denylist and explicit `CARGO_HOME` / `CARGO_TARGET_DIR` policy
* log/output caps: `max_gate_log_bytes`, `max_gate_capture_bytes`
* safe deletion root allowlist (GC and resets)
* provenance policy (mirror_commit vs patch_injection admission rules)
* **economics profile binding (RFC-0029):**
  * `economics_profile_hash` (content-addressed hash of an `EconomicsProfile` in CAS)
  * `default_risk_tier` (e.g., `tier1`)
  * `default_boundary_intent_class` (for FAC actuation this is normally `actuate`)

Required environment policy fields (normative minimum):
* `env_clear_by_default: bool` (default true for bounded execution)
* `env_allowlist: [string]` (exact variable names)
* `env_denylist_prefixes: [string]` (e.g., `AWS_`, `GITHUB_`, `SSH_`, `OPENAI_`), applied after allowlist to prevent "oops we allowed too much"
* `env_set: { key: value }` for enforced variables:
  * `CARGO_HOME=$APM2_HOME/private/fac/cargo_home`
  * `CARGO_TARGET_DIR=$APM2_HOME/private/fac/lanes/<lane_id>/target/<toolchain_fingerprint>`
  * `NEXTEST_TEST_THREADS=<computed>`
  * `CARGO_BUILD_JOBS=<computed>`

If `env_clear_by_default` is true, implementations MUST ensure required runtime variables (PATH, TERM when needed) are explicitly set, not inherited implicitly.

Any change to `FacPolicyV1` MUST change `FacPolicyHash` (fail-closed).
`FacPolicyHash` MUST be computed using the same `b3-256:` hash ref rules as other substrate objects.

Economics admission (normative):
* Before executing a job, the worker MUST run `apm2_core::economics::BudgetAdmissionEvaluator` with:
  * `profile_hash = FacPolicyV1.economics_profile_hash`,
  * `(tier, intent_class)` resolved from job kind (defaults from policy unless explicitly escalated),
  * `ObservedUsage` constructed from the job's declared budgets (timeouts, log caps, expected I/O caps).
* Any unresolved/missing profile state MUST deny (fail-closed), by design of RFC-0029.

#### 5.3.2 `LaneLeaseV1`

```jsonc
{
  "schema": "apm2.fac.lane_lease.v1",
  "lane_id": "lane-00",
  "job_id": "job_20260212T031500Z_…",
  "pid": 12345,
  "state": "RUNNING",
  "started_at": "2026-02-12T03:15:00Z",
  "lane_profile_hash": "b3-256:…",
  "toolchain_fingerprint": "b3-256:…"
}
```

Storage:
* `$APM2_HOME/private/fac/lanes/<lane_id>/lease.v1.json`

#### 5.3.3 `FacJobSpecV1`

```jsonc
{
  "schema": "apm2.fac.job_spec.v1",
  "job_id": "job_20260212T031500Z_…",
  "job_spec_digest": "b3-256:…", // REQUIRED: digest of canonical JSON with `actuation.channel_context_token` = null
  "kind": "gates",
  "queue_lane": "bulk",
  "priority": 50,
  "enqueue_time": "2026-02-12T03:15:00Z",
  "actuation": {
    "lease_id": "L-FAC-LOCAL",              // REQUIRED; token binding input
    "request_id": "b3-256:…",              // REQUIRED; MUST equal job_spec_digest
    "channel_context_token": "BASE64…",    // REQUIRED in default mode; RFC-0028 token
    "decoded_source": "typed_tool_intent"  // OPTIONAL hint; worker ignores unless token verifies
  },
  "source": {
    "kind": "mirror_commit", // mirror_commit | patch_injection
    "repo_id": "guardian-intelligence/apm2", // stable logical id, not a filesystem path
    "head_sha": "012345…",
    "patch": null // if kind=patch_injection: { "format":"git_diff_v1", "digest":"b3-256:…", "bytes_cas":"b3-256:…" }
  },
  "lane_requirements": {
    "lane_profile_hash": null
  },
  "constraints": {
    "require_nextest": true,
    "test_timeout_seconds": 240,
    "memory_max_bytes": 25769803776
  }
}
```

`job_spec_digest` computation rules (normative):
* Serialize the job spec to canonical JSON (using `apm2_core::determinism::canonicalize_json`).
* Set `actuation.channel_context_token = null` before hashing (so the digest is stable across token rotations).
* Hash bytes as `b3-256(schema_id || "\0" || canonical_json_bytes)` (same domain separation as §5.3).
* `actuation.request_id` MUST equal `job_spec_digest`. Workers MUST decode the token using this request id.

Dirty-tree rule (reframed to match FESv1 provenance):
* `patch_injection` is the **only** way to run dirty content while preserving fail-closed cache semantics.
* Any run executed from an ambient caller worktree is permitted only in explicitly-uncacheable modes (e.g., `--quick`).

**Required schema correction (digest vocabulary):**
If `patch_injection` is used, the patch object MUST use `b3-256:` digests (not `blake3:`) and MUST specify where bytes live.
This amendment allows two storage backends (choose one; do not invent a third):
1) `bytes_backend: "fac_blobs_v1"` with bytes stored under `$APM2_HOME/private/fac/blobs/<hex>`
2) `bytes_backend: "apm2_cas"` with bytes stored under the existing CAS root (requires explicit GC policy decisions; see §6.2)

If `bytes_backend` is omitted or unknown, gate-cache reuse MUST be disabled (fail-closed).

Queue lane rule:
* `queue_lane` MUST be one of the RFC-0029 `QueueLane` strings (`snake_case`).
* v1 producers SHOULD default:
  * `bulk` for `gates` and `warm` jobs
  * `control` for `gc` / lane reset / maintenance
  * `stop_revoke` for cancellation / kill / revoke operations

#### 5.3.4 `FacJobReceiptV1`

```jsonc
{
  "schema": "apm2.fac.job_receipt.v1",
  "job_id": "job_…",
  "job_spec_digest": "b3-256:…",
  "kind": "gates",
  "queue_lane": "bulk",
  "lane_id": "lane-00",
  "lane_profile_hash": "b3-256:…",
  "toolchain_fingerprint": "b3-256:…",
  "fac_policy_hash": "b3-256:…",
  "eio29_queue_admission": { /* REQUIRED: serialized apm2_core::economics::QueueAdmissionDecision */ },
  "eio29_budget_admission": { /* REQUIRED when job kind implies external effect: serialized apm2_core::economics::BudgetAdmissionDecision */ },
  "rfc0028_channel_boundary": { /* REQUIRED: reconstructed ChannelBoundaryCheck (post-decode), for receipt audit */ },
  "started_at": "…",
  "finished_at": "…",
  "status": "SUCCESS",
  "exit_code": 0,
  "artifacts": {
    "log_bundle_hash": "b3-256:…",
    "gate_cache_keys": ["b3-256:…"]
  }
}
```

Notes (normative):
* `eio29_queue_admission` is REQUIRED and MUST be compatible with `apm2_core::economics::QueueAdmissionDecision`.
* `eio29_budget_admission` is REQUIRED for any job that executes commands (gates/warm/gc/reset), and MUST be compatible with `apm2_core::economics::BudgetAdmissionDecision`.
* `rfc0028_channel_boundary` is REQUIRED and MUST be the decoded+validated `ChannelBoundaryCheck` used to authorize actuation.

#### 5.3.5 `WarmReceiptV1`

```jsonc
{
  "schema": "apm2.fac.warm_receipt.v1",
  "lane_id": "lane-00",
  "lane_profile_hash": "b3-256:…",
  "toolchain_fingerprint": "b3-256:…",
  "started_at": "…",
  "finished_at": "…",
  "steps": [
    { "name": "cargo_fetch", "exit_code": 0, "duration_ms": 1234 },
    { "name": "cargo_build", "exit_code": 0, "duration_ms": 5678 }
  ]
}
```

#### 5.3.6 `GcReceiptV1`

```jsonc
{
  "schema": "apm2.fac.gc_receipt.v1",
  "started_at": "…",
  "finished_at": "…",
  "policy": { "min_free_bytes": 21474836480, "min_free_percent": 10 },
  "before": { "free_bytes": 123, "free_percent": 1.2 },
  "after": { "free_bytes": 456, "free_percent": 12.3 },
  "freed_bytes": 333,
  "actions": [
    { "kind": "prune_lane_targets", "lane_id": "lane-01", "freed_bytes": 123 }
  ]
}
```

### 5.4 Attestation integration (fail-closed)

The following MUST be present in gate-cache key material (directly or via digests):

* `LaneProfileHash`
* `ToolchainFingerprint`
* `FacPolicyHash` (authoritative policy version)

Minimum required changes to the current attestation:

* include `.cargo/config.toml` in gate input digests for cargo-based gates
* include `rustfmt --version` in environment facts
* extend command/environment allowlist to include:
  * `CARGO_HOME`, `CARGO_TARGET_DIR`, `CARGO_BUILD_JOBS`, `NEXTEST_TEST_THREADS`
  * `RUSTC_WRAPPER` and `SCCACHE_*` (future-proof; no effect when unset)

Policy hashing:

* define a single authoritative `FacPolicyV1` in Rust (and optionally emitted to `$APM2_HOME/private/fac/policy/fac_policy.v1.json` for inspection)
* `FacPolicyHash = b3-256(canonical_json(FacPolicyV1))`
* any change to timeouts, resource caps, allowlists, or tool requirements MUST change `FacPolicyHash`

---

## 6. Enforced hygiene: disk preflight + GC (cannot be optional)

### 6.1 Disk preflight (mandatory gate before heavy jobs)

Before a job enters RUNNING, the scheduler MUST:

1. compute free space for:
   * filesystem containing the lane workspace
   * filesystem containing `$APM2_HOME`
2. compare against policy (`min_free_bytes` AND `min_free_percent`)
3. if below threshold:
   * run `apm2 fac gc` in enforcement mode
   * re-check
4. if still below threshold:
   * FAIL CLOSED (do not start the job; host is at risk)

Default policy for the current node class:
* `min_free_bytes = 20 GiB`
* `min_free_percent = 10%`

### 6.2 What GC is allowed to delete (explicit allowlist)

GC MAY delete only:
* lane targets under `private/fac/lanes/*/target/*` (excluding leased/running lanes)
* lane logs under `private/fac/lanes/*/logs` beyond retention/quota
* FAC evidence logs under `private/fac/evidence` beyond retention/quota (legacy; eventually only per-lane/per-job logs)
* FAC-managed cargo cache roots under `private/fac/cargo_home` **only as an escalation step** (cargo registry/git caches can dominate disk usage on small disks)
* (optional) gate cache entries beyond TTL (legacy)
* (future) sccache dirs under FAC-controlled roots, if enabled

GC MUST NOT delete:
* identity/keys under `$APM2_HOME/private` that are not explicitly marked as FAC cache
* git worktrees themselves outside FAC lane roots

All deletions MUST use `safe_rmtree_v1`.

---

## 7. Migration plan (staged, rollbackable)

This is the incremental deployment plan required by the prompt.

### Phase 0 — Instrumentation + invariants (no behavior change)

Deliverables:
* add missing fail-closed attestation inputs (`.cargo/config.toml`, `rustfmt --version`)
* remove cargo-test fallback for FAC tests; nextest required (fail fast if missing)
* add dirty-tree protection (disable cache or incorporate diff digest)
* add disk preflight checks (warn-only at first; no GC yet)
* integrate RFC-0028 + RFC-0029 in "audit-only" mode:
  * generate and record RFC-0028 channel boundary checks in receipts (but do not deny yet),
  * generate and record RFC-0029 admission traces in receipts (but do not deny yet).

Acceptance criteria:
* no regressions to existing `apm2 fac gates` UX on a healthy machine
* cache keys change when `.cargo/config.toml` changes
* receipts include RFC-0028 + RFC-0029 traces for every run (even if not enforced yet)

Rollback:
* single PR revert (no persistent state changes required)

### Phase 1 — Local lanes + lane leases + target namespaces (single VPS)

Deliverables:
* implement `LaneProfileV1`, deterministic `lane_id` set (default 3 lanes on this box)
* implement lane lease locks + lease records
* implement per-lane `CARGO_TARGET_DIR` under lane target namespace (**this is the target pool; no separate target_pool root**)
* implement `apm2 fac lane status`
* implement `apm2 fac gates` acquiring a lane lease internally
* introduce broker + worker:
  * broker issues RFC-0028 channel context tokens
  * broker issues RFC-0029 time authority envelopes + horizon refs
  * worker validates RFC-0028 + RFC-0029 and executes jobs

Acceptance criteria:
* three concurrent `apm2 fac gates` invocations never exceed lane count
* target reuse collapses disk usage vs many worktrees (qualitative)
* evidence logs are per-lane/per-job and do not clobber across concurrent runs
* in default mode, workers deny/quarantine any job lacking a valid RFC-0028 token
* in default mode, workers deny any job with RFC-0029 verdict != Allow (except stop_revoke emergency semantics)

Rollback:
* `APM2_FAC_LANES=0` (or `--legacy`) runs old path; lane directories remain but are inert

### Phase 2 — Queueing + priority + cancellation + lane reset + enforced GC

Deliverables:
* implement filesystem job queue (`pending/claimed/done/cancelled`)
* implement `apm2 fac enqueue` and `apm2 fac gates --queued`
* implement `apm2 fac lane reset` with symlink-safe deletion
* turn disk preflight from warn-only to enforced (auto GC, fail closed if still low)
* implement `apm2 fac gc` + `GcReceiptV1`

Acceptance criteria:
* enqueue + cancellation works correctly under concurrent clients
* disk preflight demonstrably prevents "disk full mid-build" failures in normal operation

Rollback:
* disable queue consumption; run direct lane acquisition mode

### Phase 3 — Add a second VPS with flake-pinned toolchain parity (Ubuntu baseline; NixOS optional only on greenfield)

Deliverables:
* "assimilate node" playbook:
  * clone repo at pinned commit
  * `nix develop`
  * restore minimal `$APM2_HOME` state (receipts, configs, keys; not bulky caches)
  * run `apm2 fac warm` to rehydrate caches
* local scheduler per host; no distributed routing required
* define a transport-agnostic evidence bundle export/import contract (see §8)

Acceptance criteria:
* catastrophic failure recovery on primary host is reproducible within a single playbook run
* developer shell/toolchain parity achieved via flakes

Rollback:
* none; this is additive documentation + optional tooling

### Phase 4 — 100+ nodes (design only): distributed routing + receipt stream merge

Deliverables:
* stable job spec + receipt schemas sufficient for routing without semantic refactor
* define trust boundaries + authentication using PCAC/AJC (no implementation)

---

## 8. Evidence bundle streaming seam (contract; no networking implementation)

### 8.1 Evidence bundle contents (build success / failure)

An evidence bundle is a content-addressed set with a manifest:

* `FacJobReceiptV1`
* gate attestation objects referenced by hash
* logs (possibly compressed) referenced by hash
* optional artifacts (binary size summaries, nextest junit, etc.) referenced by hash

### 8.2 Hashing + addressing

* each blob is addressed by `b3-256:<hex>`
* manifest schema (proposed): `apm2.fac.evidence_bundle_manifest.v1`
* bundle id = b3-256(canonical(manifest))

### 8.3 Transport-agnostic envelope

Define an envelope format that can be shipped later over any transport.
**Normative:** even in local-only mode, any "export/import" of evidence bundles across process boundaries MUST use this envelope and MUST validate RFC-0028 + RFC-0029 fields.

* `schema: apm2.fac.evidence_bundle_envelope.v1`
* `bundle_id`
* `origin_node_fingerprint` (same semantics as `LaneProfileV1.node_fingerprint`)
* `boundary_id` (stable string boundary identifier; MUST be consistent with RFC-0029 `HtfEvaluationWindow.boundary_id` when HTF is used)
* `compression` (none|zstd)
* `chunks[]` (each chunk references a blob hash)
* OPTIONAL forward-compat fields (reserved for RFC-0028/RFC-0029 integration):
  * `channel_boundary_check` (serialized `apm2_core::channel::ChannelBoundaryCheck`)  // REQUIRED for any import/export operation
  * `pcac_chain_hash` (content-addressed reference to the PCAC/AJC chain used to authorize the execution)
  * `economics_receipts[]` (content-addressed refs to RFC-0029 budget/admission receipts for transport/backpressure decisions)

No networking code is defined here; only the object contract.

Normative enforcement:
* `apm2 fac bundle export` MUST emit `channel_boundary_check` and MUST bind it to the active `FacPolicyHash`.
* `apm2 fac bundle import` MUST fail-closed unless `validate_channel_boundary(channel_boundary_check)` passes and embedded economics receipts validate.

### 8.4 Receipt stream merge (CRDT-ish)

Receipt streams MUST be mergeable by set union:

* receipts are immutable content-addressed objects
* stream merge = union of receipt digests + deterministic presentation ordering:
  1) primary: HTF time envelope stamp (RFC-0016) if present
  2) fallback: monotonic timestamp + node_fingerprint + receipt digest

### 8.5 Authentication boundary (future PCAC/AJC seam)

Future distributed mode MUST authenticate + authorize **at the boundary**:

* which node produced the bundle (node identity)
* which capabilities authorized job execution (PCAC/AJC chain)
* which channel/source produced the envelope (typed intent vs free-form), using RFC-0028 channel boundary enforcement

Normative integration requirements:

* Any envelope ingested from outside the local host MUST be treated as an **external I/O actuation input** and MUST pass `apm2_core::channel::validate_channel_boundary(...)` checks (fail-closed).
* `channel_boundary_check` (if present) MUST be validated (including `channel_source_witness` via `verify_channel_source_witness`) and MUST bind the same policy digest used by the receiver.
* RFC-0029 economics receipts (if present) MUST be validated before being used to relax backpressure limits; unknown receipts MUST be ignored (fail-closed).

In v1 (local-only), these fields may be present but unsigned; v2 adds signatures and broker verification without changing schema semantics.

---

## 9. Nextest policy: stop relying on ambient aliasing

### 9.1 Explicit recommendation

**Do not alias `cargo test` → nextest** as part of the canonical FAC substrate.

Reasons (practical, not ideological):

* It is an **ambient global mutation** of tooling semantics that your attestation cannot reliably see (unless you treat `~/.cargo/config.toml` as a formal input, which you should not).
* It can break commands that expect `cargo test` semantics (including compile-only patterns like `cargo test --no-run`, or third-party scripts that assume cargo behavior).
* It undermines the "instantly reproduce environment across VPSs" objective; you will forget one node or one systemd unit will not pick up shell alias state.

### 9.2 What we do instead (mandatory, encoded)

**FAC test execution uses nextest explicitly** in the code path.

Concrete repo changes:

* In `crates/apm2-cli/src/commands/fac_review/evidence.rs` (pipeline path) and in `crates/apm2-cli/src/commands/fac_review/gates.rs` (local gates path):

  * Replace **all** non-bounded fallbacks from `cargo test --workspace` to:

    * `cargo nextest run --workspace --all-features --config-file .config/nextest.toml --profile ci`
  * If nextest is missing in any scenario, fail with a clear error that nextest is required for FAC gates (FAC substrate mandate).

This turns nextest into a **declared dependency** of the FAC substrate, consistent with `flake.nix` already including `cargo-nextest`.

Missing-but-required detail: align nextest's own concurrency knobs with the global governor:

* `NEXTEST_TEST_THREADS` must be set (or `--test-threads`) to match the per-slot CPU budget, otherwise you still get oversubscription even with CPUQuota.

### 9.3 Optional dev convenience (safe)

If you want a shortcut, add a **non-overriding** cargo alias (repo-local, not user-global):

* In `.cargo/config.toml` add:

```toml
[alias]
nt = "nextest run --workspace --all-features --config-file .config/nextest.toml --profile ci"
```

Key: **do not override `test`**. Provide a new alias.

---

## 10. Build cache substrate: target pool (primary), sccache (optional)

### 10.1 Primary accelerator: lane-scoped `CARGO_TARGET_DIR` ("target pool")

Why this exists:

* The dominant real-world cost in your described regime is **duplicated `target/` trees** across worktrees.
* RFC-0007 rejected a global shared `CARGO_TARGET_DIR` because cargo uses a target-dir lock that prevents parallel builds.
* This amendment introduces a global concurrency governor (lane leases). **Once you have lanes, you can have "N target dirs"**:
  * each lane has its own target dir
  * at most one heavy build runs per lane
  * parallelism is preserved up to N without cargo lock contention

Policy:

* Every "heavy" FAC operation (gates, pipeline evidence, warm) acquires a **lane lease**.
* On lane acquisition, FAC sets:
  * `CARGO_TARGET_DIR=$APM2_HOME/private/fac/lanes/<lane_id>/target/<toolchain_fingerprint>`
  * `CARGO_BUILD_JOBS=<computed>`
  * `NEXTEST_TEST_THREADS=<computed>`
* FAC must **override** any ambient `CARGO_TARGET_DIR` rather than inheriting it.

Result:

* Cross-worktree reuse of compiled dependencies without sccache.
* Disk usage collapses from "~13 targets" to "≤ slot_count targets".
* No new daemon boundary, so containment is straightforward.

### 10.2 Security boundary alignment (TB-002)

RFC-0007 TB-002 already establishes:

* Compilation cache is local, trusted
* Remote caches are not assumed safe

This amendment enforces:

* target pool directories are under explicit control (`$APM2_HOME/private/fac/target_pool`)
* they are subject to GC policy
* optional sccache use is local-only and explicitly controlled (if/when enabled)

### 10.3 Optional secondary accelerator: sccache (only if it actually helps)

We choose the **explicit-activation model** for sccache (if/when implemented):

* `apm2` commands decide when to use sccache
* We do **not** make sccache an always-on implicit requirement by hardcoding `build.rustc-wrapper="sccache"` in `.cargo/config.toml`

Rationale:

* `.cargo/config.toml` is always present; making it require sccache causes a hard failure on any node missing sccache.
* More importantly, FAC runs under bounded systemd units; implicit wrappers are harder to reason about and attest.
* Explicit activation makes it possible to:

  * run "safe mode" (no sccache) if needed for debugging
  * record activation in receipts and attestation
  * migrate to NixOS without hidden assumptions

### 10.4 Standard cache locations

We standardize:

* `CARGO_TARGET_DIR = $APM2_HOME/private/fac/lanes/<lane_id>/target/<toolchain_fingerprint>`

If sccache is enabled later:

* `SCCACHE_DIR = $APM2_HOME/private/cache/sccache`

Why under APM2_HOME?

* makes GC and backup policy coherent
* avoids scattered caches across `$HOME/.cache`
* makes "restore environment on new VPS" more predictable

Implementation note:

* `apm2_home_dir()` already exists in `fac_review/types.rs`; use it to derive the path.

### 10.5 Critical containment caveat: sccache + cgroups

This is where the original planning doc was dangerously under-specified.

Because the test gate is executed under a bounded `systemd-run` unit, we must assume:

* any compilation or compilation-adjacent process must remain inside the bounded cgroup to preserve the 24G/240s guarantees.

**Risk:** If sccache uses a long-lived daemon that spawns compiler processes outside the transient unit cgroup, your "bounded tests" aren't actually bounded. That is an unacceptable integrity regression.

**Mitigation policy in this amendment:**

* Default stance: **do not enable sccache inside bounded units** until proven safe and beneficial.

If/when you try to enable it:

* You must ensure the sccache server that spawns compiler processes is inside the unit cgroup.
* The earlier draft conflated `SCCACHE_NO_DAEMON` with "no server". In sccache, `SCCACHE_NO_DAEMON=1` only prevents daemonization (it does not eliminate the server boundary).
* A safer pattern (if needed) is: start the server inside the unit (`sccache --start-server`), and stop it when the unit finishes (`sccache --stop-server`) while ensuring it cannot connect to an already-running out-of-cgroup server (e.g., via per-unit socket config).

Otherwise, keep sccache off for bounded units and rely on:

* target pool reuse + warm/prebuild (see §11)

Because sccache behavior may differ by version, this amendment requires a **verification check** (see §15) that confirms rustc processes remain inside the bounded cgroup when sccache is enabled.

If verification fails, the "safe fallback" is:

* **do not enable sccache inside bounded units**
* rely on pre-warm compilation outside bounded units to keep bounded test runs as "run-only" as possible

This is not optional hand-waving; it is the containment guarantee.

### 10.6 Attestation surfacing

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

## 11. `apm2 fac warm`: pre-warming as a first-class, attested maintenance action

### 11.1 Why warm is required (and where it belongs)

Given the "240s/24G bounded test SLA," we treat warm as:

* a **worktree lifecycle step**, not a per-run step
* required:

  * on fresh worktree creation
  * after toolchain upgrades (rustc/cargo changes)
  * after aggressive GC/cargo clean

Warm is how we turn bounded tests into "run-only" rather than "build + run."

### 11.2 CLI interface

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

### 11.3 Execution plan

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

### 11.4 Warm locking and concurrency

Warm must not stampede, but **do not serialize warm globally**: global warm locks reduce throughput and create single-point deadlocks.

Instead:

* warm acquires a lane lease; that is the concurrency control.
* per-slot target pool already eliminates "13 worktrees compiling 13 times" — the stampede surface is drastically reduced.

Behavior:

* If no lanes are available:
  * default: wait (bounded by a reasonable max, or with `--no-wait` to fail fast)

### 11.5 Warm receipts

Warm must write a durable receipt:

* Content-addressed receipt path: `$APM2_HOME/private/fac/receipts/<b3-256-hex>.json`
* Schema: `apm2.fac.warm_receipt.v1`
* Optional human index: `$APM2_HOME/private/fac/maintenance/warm/<ts>_<lane_id>.ref` containing the receipt digest (or a symlink to `receipts/<hex>.json`)

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

## 12. Resource hygiene: `apm2 fac gc` as an enforced safety valve

### 12.1 Why GC must exist as a FAC primitive

You have:

* many worktrees
* large `target/` dirs
* parallel agents
* a strict "host must remain functional" requirement

Therefore GC cannot remain an informal human action.

Also missing from the draft: "GC as a manual command" does not satisfy the stated goal of **automatic and enforced cleanup**.
This amendment therefore requires:

* enforced disk preflight in `gates`, `warm`, and pipeline evidence
* GC auto-invocation when below `min-free`

### 12.2 CLI interface

Add:

* `apm2 fac gc` (maintenance command)

Args:

* `--json`
* `--dry-run`
* `--min-free <SIZE|PERCENT>` (default policy: see below)
* `--keep-hot-worktrees <N>` (default: derived from concurrency)
* `--ttl-days <D>` for "cold worktree targets"
* `--sccache-trim` (default true)
* `--gate-cache-ttl-days <D>` (default: 30)
* `--aggressive` (enables deeper deletions)

### 12.3 What GC is allowed to delete (safe set)

GC is allowed to delete:

1. Worktree-local `target/` directories for "cold" worktrees (legacy artifacts once target pool is enabled)
2. Target-pool slot directories that are not currently leased (LRU policy) **if disk preflight still fails after pruning cold worktrees**
3. `$APM2_HOME/private/cache/sccache` directory (delete as a last resort) if sccache is enabled
4. `$APM2_HOME/private/fac/gate_cache_v2` entries beyond TTL (optional; low ROI but safe)
5. Any **known scratch** artifacts (e.g., `target/ci/**` snapshots) as part of deleting target dirs

GC must **not** delete:

* keys / identity material under `$APM2_HOME/private/*` unless explicitly in a separate "nuke" command
* git worktrees themselves (only their build artifacts)

### 12.4 "Active worktree" definition

A worktree is **active** if any of the following are true:

* It is the current working directory of the invoking process (obviously)
* It has a live FAC lock lease file (see §13)
* It has a running `systemd-run` unit associated with it (optional detection)
* It has been used recently (mtime heuristic):

  * any file under worktree `.git` metadata updated recently
  * OR last warm receipt references it within TTL window

Everything else is eligible for target pruning.

Required amendment: "active" must be defined in terms of the actual global governor, not heuristics.

* A worktree is active iff it is referenced by an active lane lease record (see §4.4 and `LaneLeaseV1`).
* Heuristics (mtime) may be used as a fallback only when lease metadata is missing.

### 12.5 Default policy for your current box

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

### 12.6 GC receipts

GC writes:

* Content-addressed receipt path: `$APM2_HOME/private/fac/receipts/<b3-256-hex>.json`
* Schema: `apm2.fac.gc_receipt.v1`
* Optional human index: `$APM2_HOME/private/fac/maintenance/gc/<ts>.ref` containing the receipt digest (or a symlink to `receipts/<hex>.json`)

Include:

* disk free before/after
* bytes freed by category
* list of deleted directories (or hashes, if you want to avoid path disclosure)
* policy parameters used

---

## 13. Global resource governor: stop pretending per-command limits are sufficient

### 13.1 Lane leasing is the global resource governor (normative)

This section is **subsumed by lane leasing (§4.4)**. FESv1 MUST NOT implement an additional independent "compute slot" semaphore.
Instead:
* Lane count is the concurrency limit.
* The lane lock file is the lease token.
* The lane lease record is the metadata sidecar used by GC/debugging.

All "heavy" FAC operations MUST acquire a lane lease:
* `apm2 fac gates` (full mode)
* `apm2 fac warm`
* `apm2 fac pipeline` evidence phase
* `apm2 fac gc` when invoked in enforcement mode (preflight-triggered), because it competes for IO

### 13.2 Lane-aware `CARGO_BUILD_JOBS` + `NEXTEST_TEST_THREADS` (Phase 1)

When a process acquires a lane lease, it computes a default `CARGO_BUILD_JOBS`:

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

### 13.4 Phase 2: long-lived "FAC Execution Pool" (the thing you're gesturing at)

You asked whether "1 worktree = 1 ticket" is the right primitive. For exabyte/100B-agent scale, it isn't.

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
  * fast "reset slot" on corruption

This is the correct "control surface" for scaling to many nodes and many agents. Phase 1 leases are the minimal stepping stone.

---

## 14. Nix integration: environment must be declarative

> **Non-goal:** converting the current primary host to NixOS. The baseline for FESv1 is an existing Debian/Ubuntu VPS with systemd.
> Nix is used for toolchain pinning (`nix develop`) and optional packaging; NixOS modules are a future convenience, not a requirement.

### 14.1 flake.nix updates

`flake.nix` already includes `cargo-nextest`. This amendment requires adding:

* (optional) `sccache` only if/when we decide to ship it as part of the FAC substrate

This amendment does require:

* nothing new for the target pool (it's policy + env)

so the dev shell is a complete reproduction unit for FAC warm/gates.

### 14.2 Backup/restore implications

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

The "instant reproduction" story should be:

1. clone repo at known commit
2. `nix develop` (tools pinned)
3. restore `$APM2_HOME` minimal set
4. run `apm2 fac warm`

---

## 15. Verification and hard checks

This amendment is only acceptable if these checks pass.

### 15.1 Functional checks

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

### 15.2 Containment check (mandatory)

If we enable sccache inside bounded units, we must verify:

* rustc processes spawned during bounded tests are inside the same cgroup as the systemd-run unit.

A practical check:

* During a bounded test run, capture cgroup path of the main process and of a rustc child.
* If mismatch → **disable sccache inside bounded units** and rely on warm/prebuild.

This check can be implemented as:

* a test harness script
* or a debug mode in `run_bounded_tests.sh` / Rust replacement later

---

## 16. Concrete file-level deltas (amendment plan)

### 16.1 Code changes

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

### 16.2 RFC-0007 doc changes

Update `documents/rfcs/RFC-0007/02_design_decisions.yaml`:

* Replace "optional nextest" decisions with:

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

## 17. Ticket YAMLs (drop-in proposals)

Below are proposed tickets aligned with the latest amendments (brokered RFC-0028 actuation + mandatory RFC-0029 admission traces, lane-only governor, queue quarantine/denied, receipts-as-ground-truth). All ticket IDs are placeholder numbers; renumber as needed.

### TCK-00510 — FAC Broker service: RFC-0028 channel tokens + RFC-0029 envelopes/horizons (mandatory default-mode authority)

```yaml
ticket_meta:
  schema_version: "2026-01-29"
  template_version: "2026-01-29"
  ticket:
    id: "TCK-00510"
    title: "FAC Broker service: RFC-0028 channel tokens + RFC-0029 envelopes/horizons (mandatory default-mode authority)"
    status: "OPEN"
  binds:
    prd_id: "PRD-PLACEHOLDER"
    rfc_id: "RFC-0019"
    requirements: []
    evidence_artifacts: []
  custody:
    agent_roles: ["AGENT_IMPLEMENTER"]
    responsibility_domains: ["DOMAIN_SECURITY", "DOMAIN_RUNTIME"]
  dependencies:
    tickets: []
  scope:
    in_scope:
      - "Implement a local broker authority service (systemd-managed Rust) responsible for FAC actuation authorization and economics/time authority."
      - "Expose an API to issue RFC-0028 ChannelContextToken bound to `job_spec_digest` + lease_id."
      - "Expose an API to issue RFC-0029 `TimeAuthorityEnvelopeV1` for boundary_id + evaluation window (TP-EIO29-001)."
      - "Expose APIs to serve TP-EIO29-002 freshness horizon refs and revocation frontier snapshot (resolved/current)."
      - "Expose APIs to serve TP-EIO29-003 convergence horizon refs and convergence receipts (resolved/converged) for local-only mode."
      - "Publish a verifying key for envelope signature verification to workers (no `NoOpVerifier` in default mode)."
      - "Persist broker non-secret state under `$APM2_HOME/private/fac/broker/**` per RFC."
    out_of_scope:
      - "Multi-node networking or remote trust distribution."
      - "PCAC/AJC redesign."
  plan:
    steps:
      - "Define broker API surface (local-only transport: unix socket or loopback HTTP; implementation detail)."
      - "Implement RFC-0028 token issuance using the existing daemon signing key."
      - "Implement RFC-0029 envelope/horizon issuance using HolonicClock (or broker-owned monotonic authority) and real signature verification support."
      - "Add broker state persistence for horizon refs and admitted policy digests."
      - "Provide CLI diagnostics: `apm2 fac broker status` (optional) and structured logs."
  definition_of_done:
    evidence_ids: []
    criteria:
      - "A worker can obtain a broker-issued ChannelContextToken and successfully decode+validate it via `decode_channel_context_token` + `validate_channel_boundary`."
      - "A worker can obtain a broker-issued `TimeAuthorityEnvelopeV1` and verify signatures with a real verifier."
      - "Broker serves TP002 and TP003 refs/receipts with non-zero, replay-stable hashes in local-only mode."
  notes:
    security: |
      Broker must be the only authority issuing actuation tokens and economics envelopes in default mode.
      Key material must never be stored under `$APM2_HOME/private/fac/**` in plaintext.
    verification: |
      Integration test: request token for a known digest; validate; request envelope; verify signature; request horizons; verify non-zero commitments.
```

### TCK-00511 — FAC Worker: queue consumer with RFC-0028 authorization + RFC-0029 admission gating (default-mode executor)

```yaml
ticket_meta:
  schema_version: "2026-01-29"
  template_version: "2026-01-29"
  ticket:
    id: "TCK-00511"
    title: "FAC Worker: queue consumer with RFC-0028 authorization + RFC-0029 admission gating (default-mode executor)"
    status: "OPEN"
  binds:
    prd_id: "PRD-PLACEHOLDER"
    rfc_id: "RFC-0019"
    requirements: []
    evidence_artifacts: []
  custody:
    agent_roles: ["AGENT_IMPLEMENTER"]
    responsibility_domains: ["DOMAIN_RUNTIME", "DOMAIN_SECURITY"]
  dependencies:
    tickets:
      - ticket_id: "TCK-00510"
        reason: "Worker requires broker-issued RFC-0028 tokens and RFC-0029 envelopes/horizons."
      - ticket_id: "TCK-00515"
        reason: "Worker must acquire lane leases and execute within lanes."
  scope:
    in_scope:
      - "Add `apm2 fac worker` command (`--once` and continuous modes)."
      - "Scan pending queue; treat queue files as untrusted external input."
      - "Validate job spec bounded-deserialization + `job_spec_digest` correctness."
      - "RFC-0028: decode+validate ChannelContextToken before claim; deny/quarantine on failure."
      - "RFC-0029: compute QueueAdmissionDecision before claim using broker-issued TP001/002/003 state; deny on non-Allow."
      - "Atomic claim via rename pending→claimed."
      - "Acquire lane lease, execute job under containment, write authoritative receipts."
      - "Write denial/quarantine receipts for failed validations (with reason codes)."
    out_of_scope:
      - "Distributed routing."
  plan:
    steps:
      - "Implement queue scanning + deterministic ordering."
      - "Implement RFC-0028 pre-claim validation using broker token decode."
      - "Implement RFC-0029 admission path: build request/state, call `evaluate_queue_admission`, persist trace."
      - "Implement claimed execution path + receipt emission."
      - "Implement systemd unit recommendation / sample unit for long-running worker."
  definition_of_done:
    evidence_ids: []
    criteria:
      - "Worker denies jobs without valid RFC-0028 token (moves to quarantine/denied) and emits denial receipts."
      - "Worker produces RFC-0029 admission traces for every attempted job and denies non-Allow."
      - "Worker never double-executes a job under concurrent workers."
  notes:
    security: |
      Worker must not accept raw ChannelBoundaryCheck JSON. Authorization must come from token decode.
      Queue is attacker-writable; all reads must be bounded and fail-closed.
```

### TCK-00512 — Job spec hardening: add `job_spec_digest` + `actuation` block (RFC-0028 binding) to FacJobSpecV1

```yaml
ticket_meta:
  schema_version: "2026-01-29"
  template_version: "2026-01-29"
  ticket:
    id: "TCK-00512"
    title: "Job spec hardening: add `job_spec_digest` + `actuation` block (RFC-0028 binding) to FacJobSpecV1"
    status: "OPEN"
  binds:
    prd_id: "PRD-PLACEHOLDER"
    rfc_id: "RFC-0019"
    requirements: []
    evidence_artifacts: []
  custody:
    agent_roles: ["AGENT_IMPLEMENTER"]
    responsibility_domains: ["DOMAIN_SECURITY"]
  dependencies:
    tickets: []
  scope:
    in_scope:
      - "Define and implement `job_spec_digest` computation (canonical JSON; token field null; schema_id domain separation)."
      - "Extend `FacJobSpecV1` schema with `actuation{ lease_id, request_id, channel_context_token }`."
      - "Update queue writer paths (`fac enqueue`, `fac gates`, etc.) to populate digest + request_id."
      - "Update worker parser to validate digest and request_id match."
      - "Update receipts to include `job_spec_digest`."
    out_of_scope:
      - "Any PCAC/AJC redesign."
  plan:
    steps:
      - "Add schema structs with `deny_unknown_fields`."
      - "Add canonical JSON hashing helper for job specs."
      - "Wire into enqueue path and worker validation."
  definition_of_done:
    evidence_ids: []
    criteria:
      - "A tampered job spec file is detected (digest mismatch) and denied/quarantined."
      - "Token request_id mismatch is detected and denied."
```

### TCK-00513 — Receipt hardening: require RFC-0028 boundary + RFC-0029 queue/budget decisions in FacJobReceiptV1

```yaml
ticket_meta:
  schema_version: "2026-01-29"
  template_version: "2026-01-29"
  ticket:
    id: "TCK-00513"
    title: "Receipt hardening: require RFC-0028 boundary + RFC-0029 queue/budget decisions in FacJobReceiptV1"
    status: "OPEN"
  binds:
    prd_id: "PRD-PLACEHOLDER"
    rfc_id: "RFC-0019"
    requirements: []
    evidence_artifacts: []
  custody:
    agent_roles: ["AGENT_IMPLEMENTER"]
    responsibility_domains: ["DOMAIN_SECURITY", "DOMAIN_RUNTIME"]
  dependencies:
    tickets:
      - ticket_id: "TCK-00511"
        reason: "Worker is responsible for generating authoritative receipts."
  scope:
    in_scope:
      - "Extend `FacJobReceiptV1` to include `job_spec_digest`."
      - "Add required fields: `rfc0028_channel_boundary`, `eio29_queue_admission`, `eio29_budget_admission` (as applicable)."
      - "Standardize denial receipts (authorization denied, economics denied, malformed input, etc.)."
      - "Persist receipts content-addressed under `$APM2_HOME/private/fac/receipts/<hex>.json`."
      - "Ensure receipts are emitted for BOTH deny/quarantine outcomes and execution outcomes."
    out_of_scope:
      - "Receipt stream merge tooling (separate ticket)."
  plan:
    steps:
      - "Define receipt schema extensions + serialization rules."
      - "Update worker to always emit these artifacts."
      - "Add minimal tests: receipt includes required fields in default mode."
  definition_of_done:
    evidence_ids: []
    criteria:
      - "No successful execution receipt exists without RFC-0028 boundary + RFC-0029 admission artifacts."
      - "Denied jobs produce denial receipts with stable reason codes."
```

### TCK-00514 — Queue hygiene: add denied/quarantine dirs + denial/quarantine receipts + retention policy

```yaml
ticket_meta:
  schema_version: "2026-01-29"
  template_version: "2026-01-29"
  ticket:
    id: "TCK-00514"
    title: "Queue hygiene: add denied/quarantine dirs + denial/quarantine receipts + retention policy"
    status: "OPEN"
  binds:
    prd_id: "PRD-PLACEHOLDER"
    rfc_id: "RFC-0019"
    requirements: []
    evidence_artifacts: []
  custody:
    agent_roles: ["AGENT_IMPLEMENTER"]
    responsibility_domains: ["DOMAIN_SECURITY", "DOMAIN_RUNTIME"]
  dependencies:
    tickets:
      - ticket_id: "TCK-00513"
        reason: "Denial/quarantine receipts schema must exist."
  scope:
    in_scope:
      - "Add queue layout: `queue/denied/` and `queue/quarantine/`."
      - "Implement deterministic move rules for malformed/tampered jobs vs policy-denied jobs."
      - "Write denial/quarantine receipts and link them to moved job files."
      - "Define retention policy: quarantined jobs preserved until GC prunes by TTL/quota (never silently deleted)."
      - "Ensure `apm2 fac gc` respects quarantine retention rules and emits receipts for prunes."
    out_of_scope:
      - "Remote forensics transport."
  plan:
    steps:
      - "Implement directory creation and atomic rename targets."
      - "Implement reason sidecar file format (e.g., `<job_id>.reason.json`) or embed in denial receipt."
      - "Implement basic quota (max bytes) and TTL policy for quarantine."
  definition_of_done:
    evidence_ids: []
    criteria:
      - "Poison jobs do not loop forever; they are moved aside and a denial receipt is emitted."
      - "Quarantine is not deleted by routine cleanup; only by explicit GC policy with receipts."
```

### TCK-00515 — Lanes v1: lane directories + LaneProfileV1 + LaneLeaseV1 + `apm2 fac lane status`

```yaml
ticket_meta:
  schema_version: "2026-01-29"
  template_version: "2026-01-29"
  ticket:
    id: "TCK-00515"
    title: "Lanes v1: lane directories + LaneProfileV1 + LaneLeaseV1 + `apm2 fac lane status`"
    status: "OPEN"
  binds:
    prd_id: "PRD-PLACEHOLDER"
    rfc_id: "RFC-0019"
    requirements: []
    evidence_artifacts: []
  custody:
    agent_roles: ["AGENT_IMPLEMENTER"]
    responsibility_domains: ["DOMAIN_RUNTIME"]
  dependencies:
    tickets: []
  scope:
    in_scope:
      - "Create lane directory layout under `$APM2_HOME/private/fac/lanes/<lane_id>/{workspace,target,logs}`."
      - "Implement `LaneProfileV1` persistence per lane and hash computation."
      - "Implement lock+lease record mechanism (`locks/lanes/<lane_id>.lock`, `lanes/<lane_id>/lease.v1.json`)."
      - "Implement stale lease detection rules (pid alive vs dead)."
      - "Add `apm2 fac lane status` (human + JSON)."
    out_of_scope:
      - "Distributed lanes."
  plan:
    steps:
      - "Implement lane ID allocation (static default set; configurable lane_count)."
      - "Implement lock acquisition using existing proven pattern (RAII + jitter)."
      - "Implement lease record updates and crash recovery semantics."
  definition_of_done:
    evidence_ids: []
    criteria:
      - "At most one job executes in a lane at a time under concurrency."
      - "Lane status reports correct state derived from lock + lease record + last receipt."
```

### TCK-00516 — Symlink-safe deletion primitive: `safe_rmtree_v1` + lane reset command

```yaml
ticket_meta:
  schema_version: "2026-01-29"
  template_version: "2026-01-29"
  ticket:
    id: "TCK-00516"
    title: "Symlink-safe deletion primitive: `safe_rmtree_v1` + lane reset command"
    status: "OPEN"
  binds:
    prd_id: "PRD-PLACEHOLDER"
    rfc_id: "RFC-0019"
    requirements: []
    evidence_artifacts: []
  custody:
    agent_roles: ["AGENT_IMPLEMENTER"]
    responsibility_domains: ["DOMAIN_SECURITY", "DOMAIN_RUNTIME"]
  dependencies:
    tickets:
      - ticket_id: "TCK-00515"
        reason: "Lane reset targets lane roots and uses lane metadata."
  scope:
    in_scope:
      - "Implement `safe_rmtree_v1(root, allowed_parent)` using fd-relative walking (preferred) or conservative refuse-on-ambiguity."
      - "Refuse symlink traversal; refuse unexpected file types; refuse crossing FS boundaries unless allowed."
      - "Emit `refused_delete` receipts and mark lane CORRUPT on ambiguity."
      - "Implement `apm2 fac lane reset <lane_id>` with `--force` that killstops cgroup then deletes."
    out_of_scope:
      - "Generic filesystem library publication."
  plan:
    steps:
      - "Implement primitive + unit tests (symlink tests, TOCTOU resilience smoke tests)."
      - "Wire into lane reset and GC codepaths."
  definition_of_done:
    evidence_ids: []
    criteria:
      - "Deletion refuses if a symlink is encountered along the path."
      - "Lane reset cannot delete outside allowed parent even if attacker races path components."
```

### TCK-00517 — Repo substrate: bare mirror + lane checkouts + patch injection provenance (eliminate pipeline SHA drift)

```yaml
ticket_meta:
  schema_version: "2026-01-29"
  template_version: "2026-01-29"
  ticket:
    id: "TCK-00517"
    title: "Repo substrate: bare mirror + lane checkouts + patch injection provenance (eliminate pipeline SHA drift)"
    status: "OPEN"
  binds:
    prd_id: "PRD-PLACEHOLDER"
    rfc_id: "RFC-0019"
    requirements: []
    evidence_artifacts: []
  custody:
    agent_roles: ["AGENT_IMPLEMENTER"]
    responsibility_domains: ["DOMAIN_RUNTIME", "DOMAIN_SECURITY"]
  dependencies:
    tickets:
      - ticket_id: "TCK-00515"
        reason: "Lane workspaces must be created/reset from mirror."
      - ticket_id: "TCK-00516"
        reason: "Repo reset/clean operations must not risk rmtree disasters."
  scope:
    in_scope:
      - "Implement node-local bare mirror under `$APM2_HOME/private/fac/repo_mirror/<repo_id>.git`."
      - "Lane workspace checkouts MUST be sourced from mirror, not caller worktree."
      - "Implement source kinds: `mirror_commit` and `patch_injection`."
      - "Define patch bytes backend (fac_blobs_v1 or existing CAS) and bind patch digest into attestation."
      - "Ensure pipeline-style execution cannot run on drifting/dirty workspace without explicit patch injection."
    out_of_scope:
      - "Remote mirroring."
  plan:
    steps:
      - "Implement mirror bootstrap/update logic."
      - "Implement lane workspace reset to SHA + clean."
      - "Implement patch application + digest binding."
  definition_of_done:
    evidence_ids: []
    criteria:
      - "A job targeting SHA always executes on that SHA in lane workspace."
      - "Dirty content execution requires patch injection and changes cache/attestation material."
```

### TCK-00518 — Default-mode gates: enqueue+wait; add `--direct` unsafe; integrate with worker + broker

```yaml
ticket_meta:
  schema_version: "2026-01-29"
  template_version: "2026-01-29"
  ticket:
    id: "TCK-00518"
    title: "Default-mode gates: enqueue+wait; add `--direct` unsafe; integrate with worker + broker"
    status: "OPEN"
  binds:
    prd_id: "PRD-PLACEHOLDER"
    rfc_id: "RFC-0019"
    requirements: []
    evidence_artifacts: []
  custody:
    agent_roles: ["AGENT_IMPLEMENTER"]
    responsibility_domains: ["DOMAIN_RUNTIME", "DOMAIN_SECURITY"]
  dependencies:
    tickets:
      - ticket_id: "TCK-00510"
        reason: "Need broker to issue actuation tokens."
      - ticket_id: "TCK-00511"
        reason: "Need worker to consume queue."
      - ticket_id: "TCK-00512"
        reason: "Need job spec digest + actuation schema."
  scope:
    in_scope:
      - "`apm2 fac gates` creates job spec, obtains token, enqueues, and waits by default."
      - "Implement `apm2 fac gates --direct` as explicit unsafe mode that disables cache read/write and marks receipt `unsafe_direct:true`."
      - "Implement `apm2 fac enqueue` paths to request tokens from broker."
      - "Implement wait-for-completion using receipt presence (not process state)."
    out_of_scope:
      - "Distributed queue transport."
  plan:
    steps:
      - "Refactor gates entrypoint to produce job specs rather than running gates inline."
      - "Add waiter that watches done/receipt stream with bounded polling/backoff."
  definition_of_done:
    evidence_ids: []
    criteria:
      - "Default `apm2 fac gates` path exercises broker token issuance, worker claim, RFC-0029 admission, lane lease execution, and receipt emission."
      - "Direct mode produces receipts but never writes gate cache."
```

### TCK-00519 — Nextest mandate: remove cargo-test fallbacks across all call paths; enforce caps; propagate env into bounded runner

```yaml
ticket_meta:
  schema_version: "2026-01-29"
  template_version: "2026-01-29"
  ticket:
    id: "TCK-00519"
    title: "Nextest mandate: remove cargo-test fallbacks across all call paths; enforce caps; propagate env into bounded runner"
    status: "OPEN"
  binds:
    prd_id: "PRD-PLACEHOLDER"
    rfc_id: "RFC-0019"
    requirements: []
    evidence_artifacts: []
  custody:
    agent_roles: ["AGENT_IMPLEMENTER"]
    responsibility_domains: ["DOMAIN_RUNTIME", "DOMAIN_SECURITY"]
  dependencies:
    tickets:
      - ticket_id: "TCK-00515"
        reason: "Nextest thread/jobserver policy is lane-derived."
  scope:
    in_scope:
      - "Remove ALL cargo-test fallbacks (pipeline + local) and require explicit `cargo nextest run ...`."
      - "Fail closed if nextest missing in default mode."
      - "Enforce test caps: timeout ≤240s and MemoryMax ≤24G unless explicit unsafe override."
      - "Set `NEXTEST_TEST_THREADS` and `CARGO_BUILD_JOBS` based on lane policy."
      - "Update bounded runner env allowlist to pass: `CARGO_TARGET_DIR`, `CARGO_BUILD_JOBS`, `NEXTEST_TEST_THREADS`, `CARGO_HOME`, `RUSTUP_TOOLCHAIN`."
    out_of_scope:
      - "Nextest config redesign."
  plan:
    steps:
      - "Unify test command construction in one helper used by both pipeline and local gates."
      - "Update run_bounded_tests.sh allowlist."
      - "Add regression tests ensuring nextest is used everywhere."
  definition_of_done:
    evidence_ids: []
    criteria:
      - "No FAC path executes `cargo test`."
      - "Bounded test runner receives and respects computed env knobs."
```

### TCK-00520 — Logs v1: per-(lane,job,gate) log namespaces + streaming/caps + log bundle hashing

```yaml
ticket_meta:
  schema_version: "2026-01-29"
  template_version: "2026-01-29"
  ticket:
    id: "TCK-00520"
    title: "Logs v1: per-(lane,job,gate) log namespaces + streaming/caps + log bundle hashing"
    status: "OPEN"
  binds:
    prd_id: "PRD-PLACEHOLDER"
    rfc_id: "RFC-0019"
    requirements: []
    evidence_artifacts: []
  custody:
    agent_roles: ["AGENT_IMPLEMENTER"]
    responsibility_domains: ["DOMAIN_RUNTIME", "DOMAIN_SECURITY"]
  dependencies:
    tickets:
      - ticket_id: "TCK-00515"
        reason: "Logs are lane/job scoped."
      - ticket_id: "TCK-00513"
        reason: "Receipts must reference log bundle hashes."
  scope:
    in_scope:
      - "Replace global `private/fac/evidence/{gate}.log` with `private/fac/lanes/<lane_id>/logs/<job_id>/<gate>.log`."
      - "Stream stdout/stderr to files; enforce max bytes; continue draining after cap."
      - "Record truncation metadata in receipts."
      - "Build a content-addressed log bundle and record `log_bundle_hash` (b3-256)."
    out_of_scope:
      - "Remote log shipping."
  plan:
    steps:
      - "Implement streaming logger with truncation sentinel + byte counters."
      - "Implement bundle manifest and hashing."
      - "Update evidence execution to use streaming logger."
  definition_of_done:
    evidence_ids: []
    criteria:
      - "≥3 concurrent runs do not clobber logs."
      - "Log caps prevent disk blowups and do not deadlock child processes."
```

### TCK-00521 — FacPolicyV1: implement authoritative policy object + hashing + policy binding for RFC-0028

```yaml
ticket_meta:
  schema_version: "2026-01-29"
  template_version: "2026-01-29"
  ticket:
    id: "TCK-00521"
    title: "FacPolicyV1: implement authoritative policy object + hashing + policy binding for RFC-0028"
    status: "OPEN"
  binds:
    prd_id: "PRD-PLACEHOLDER"
    rfc_id: "RFC-0019"
    requirements: []
    evidence_artifacts: []
  custody:
    agent_roles: ["AGENT_IMPLEMENTER"]
    responsibility_domains: ["DOMAIN_SECURITY"]
  dependencies:
    tickets:
      - ticket_id: "TCK-00510"
        reason: "Broker must admit/publish policy digests used for RFC-0028 policy binding."
  scope:
    in_scope:
      - "Implement `FacPolicyV1` struct, canonicalization, and `FacPolicyHash` computation (b3-256)."
      - "Persist policy to `$APM2_HOME/private/fac/policy/fac_policy.v1.json` (inspection) and record hash in receipts."
      - "Include env clear/allowlist/denylist prefixes; enforced env_set for CARGO_HOME/CARGO_TARGET_DIR/etc."
      - "Bind RFC-0028 channel boundary checks to admitted policy digest; deny if mismatch."
    out_of_scope:
      - "User-facing policy editor UI."
  plan:
    steps:
      - "Define policy schema + default policy for current host class."
      - "Integrate policy hash into gate attestation and receipts."
      - "Broker publishes admitted policy digest; worker validates binding."
  definition_of_done:
    evidence_ids: []
    criteria:
      - "Changing policy changes FacPolicyHash and invalidates cache reuse."
      - "Authorization tokens fail validation if policy digest binding mismatches."
```

### TCK-00522 — Economics integration: enforce RFC-0029 BudgetAdmissionDecision using EconomicsProfile bound in FacPolicyV1

```yaml
ticket_meta:
  schema_version: "2026-01-29"
  template_version: "2026-01-29"
  ticket:
    id: "TCK-00522"
    title: "Economics integration: enforce RFC-0029 BudgetAdmissionDecision using EconomicsProfile bound in FacPolicyV1"
    status: "OPEN"
  binds:
    prd_id: "PRD-PLACEHOLDER"
    rfc_id: "RFC-0019"
    requirements: []
    evidence_artifacts: []
  custody:
    agent_roles: ["AGENT_IMPLEMENTER"]
    responsibility_domains: ["DOMAIN_SECURITY", "DOMAIN_RUNTIME"]
  dependencies:
    tickets:
      - ticket_id: "TCK-00521"
        reason: "Policy must include economics_profile_hash and defaults."
      - ticket_id: "TCK-00511"
        reason: "Worker must evaluate budgets before execution."
  scope:
    in_scope:
      - "Add `economics_profile_hash` and default tier/intent class fields to policy."
      - "Worker evaluates `BudgetAdmissionEvaluator` prior to job execution and records decision in receipt."
      - "Denies on missing/unknown economics profile state (fail-closed)."
      - "Define job-kind to (tier,intent_class) mapping: gates/warm/gc/reset are actuation intents."
    out_of_scope:
      - "Tuning economics parameters for multi-node throughput."
  plan:
    steps:
      - "Define baseline EconomicsProfile artifact (CAS content-addressed)."
      - "Wire worker evaluation and receipt emission."
      - "Add tests: missing profile → deny; valid profile → allow."
  definition_of_done:
    evidence_ids: []
    criteria:
      - "Every executed job receipt includes `eio29_budget_admission`."
      - "Budget admission denies when profile/horizons/envelopes are absent or invalid."
```

### TCK-00523 — Attestation fail-closed fixes: include .cargo/config.toml + rustfmt version; extend env allowlist (future-proof wrappers)

```yaml
ticket_meta:
  schema_version: "2026-01-29"
  template_version: "2026-01-29"
  ticket:
    id: "TCK-00523"
    title: "Attestation fail-closed fixes: include .cargo/config.toml + rustfmt version; extend env allowlist (future-proof wrappers)"
    status: "OPEN"
  binds:
    prd_id: "PRD-PLACEHOLDER"
    rfc_id: "RFC-0019"
    requirements: []
    evidence_artifacts: []
  custody:
    agent_roles: ["AGENT_IMPLEMENTER"]
    responsibility_domains: ["DOMAIN_SECURITY"]
  dependencies:
    tickets: []
  scope:
    in_scope:
      - "Add `.cargo/config.toml` to gate input digests for cargo-based gates."
      - "Add `rustfmt --version` to environment digest."
      - "Extend command/environment allowlist to include `CARGO_HOME`, `CARGO_TARGET_DIR`, `CARGO_BUILD_JOBS`, `NEXTEST_TEST_THREADS`, `RUSTC_WRAPPER`, `SCCACHE_*`."
      - "Optionally record `sccache --version` if present."
    out_of_scope:
      - "Gate cache v2 redesign."
  plan:
    steps:
      - "Modify gate_attestation input paths and environment facts."
      - "Update tests/fixtures expecting digest changes."
  definition_of_done:
    evidence_ids: []
    criteria:
      - "Changing `.cargo/config.toml` changes attestation digest and prevents cache reuse."
      - "Changing rustfmt version changes environment digest and prevents cache reuse."
```

### TCK-00524 — Disk preflight + enforced GC: implement `apm2 fac gc` + auto-GC escalation + GC receipts

```yaml
ticket_meta:
  schema_version: "2026-01-29"
  template_version: "2026-01-29"
  ticket:
    id: "TCK-00524"
    title: "Disk preflight + enforced GC: implement `apm2 fac gc` + auto-GC escalation + GC receipts"
    status: "OPEN"
  binds:
    prd_id: "PRD-PLACEHOLDER"
    rfc_id: "RFC-0019"
    requirements: []
    evidence_artifacts: []
  custody:
    agent_roles: ["AGENT_IMPLEMENTER"]
    responsibility_domains: ["DOMAIN_RUNTIME", "DOMAIN_SECURITY"]
  dependencies:
    tickets:
      - ticket_id: "TCK-00516"
        reason: "GC must use safe_rmtree_v1 for all deletions."
      - ticket_id: "TCK-00515"
        reason: "GC must respect lane leases and lane roots."
  scope:
    in_scope:
      - "Implement disk preflight before RUNNING: check `$APM2_HOME` FS and lane workspace FS."
      - "If below min-free threshold: run GC enforcement, re-check, fail closed if still low."
      - "GC allowed deletions per RFC allowlist (lane targets/logs, fac cargo_home caches, legacy evidence logs, optional gate cache TTL)."
      - "Write `GcReceiptV1` content-addressed receipt with before/after free space and actions."
      - "GC respects quarantine retention rules and emits receipts when pruning quarantine by policy."
    out_of_scope:
      - "Deleting worktrees outside lane roots."
  plan:
    steps:
      - "Implement preflight helper and wire into worker before executing jobs."
      - "Implement GC planner + executor + receipt writer."
      - "Add dry-run + json output."
  definition_of_done:
    evidence_ids: []
    criteria:
      - "Low disk triggers auto-GC and prevents starting risky jobs."
      - "GC never deletes outside allowed roots; uses safe_rmtree_v1."
```

### TCK-00525 — `apm2 fac warm`: lane-scoped prewarm with receipts + economics + authorization

```yaml
ticket_meta:
  schema_version: "2026-01-29"
  template_version: "2026-01-29"
  ticket:
    id: "TCK-00525"
    title: "`apm2 fac warm`: lane-scoped prewarm with receipts + economics + authorization"
    status: "OPEN"
  binds:
    prd_id: "PRD-PLACEHOLDER"
    rfc_id: "RFC-0019"
    requirements: []
    evidence_artifacts: []
  custody:
    agent_roles: ["AGENT_IMPLEMENTER"]
    responsibility_domains: ["DOMAIN_RUNTIME"]
  dependencies:
    tickets:
      - ticket_id: "TCK-00510"
        reason: "Warm requires broker-issued RFC-0028 token and RFC-0029 admissions."
      - ticket_id: "TCK-00511"
        reason: "Warm runs as a queued job executed by worker."
      - ticket_id: "TCK-00515"
        reason: "Warm must acquire a lane lease and use lane target namespace."
  scope:
    in_scope:
      - "Add `apm2 fac warm` that enqueues warm jobs (default) and optionally waits."
      - "Warm phases: fetch/build/nextest --no-run/clippy/doc; selectable via flags."
      - "Warm uses lane target namespace and FAC-managed CARGO_HOME."
      - "Warm emits WarmReceiptV1 and job receipt with RFC-0028/0029 artifacts."
    out_of_scope:
      - "sccache enablement (separate ticket)."
  plan:
    steps:
      - "Implement warm job kind and executor."
      - "Integrate with worker and receipts."
  definition_of_done:
    evidence_ids: []
    criteria:
      - "Warm is runnable as queued job and produces receipts."
      - "Warm reduces cold compile probability for subsequent gates in same lane target namespace."
```

### TCK-00526 — FAC-managed CARGO_HOME + env clearing policy (eliminate ambient user state)

```yaml
ticket_meta:
  schema_version: "2026-01-29"
  template_version: "2026-01-29"
  ticket:
    id: "TCK-00526"
    title: "FAC-managed CARGO_HOME + env clearing policy (eliminate ambient user state)"
    status: "OPEN"
  binds:
    prd_id: "PRD-PLACEHOLDER"
    rfc_id: "RFC-0019"
    requirements: []
    evidence_artifacts: []
  custody:
    agent_roles: ["AGENT_IMPLEMENTER"]
    responsibility_domains: ["DOMAIN_SECURITY", "DOMAIN_RUNTIME"]
  dependencies:
    tickets:
      - ticket_id: "TCK-00521"
        reason: "Policy must define deny_ambient_cargo_home and env clearing/allowlist."
  scope:
    in_scope:
      - "Set `CARGO_HOME=$APM2_HOME/private/fac/cargo_home` for all FAC jobs."
      - "Clear environment by default and pass only allowlisted env vars into bounded units."
      - "Deny ambient cargo home and ambient cargo config reliance."
      - "Ensure bounded runner allowlist includes required env for correct execution."
    out_of_scope:
      - "Rustup toolchain installation automation."
  plan:
    steps:
      - "Implement env builder from policy."
      - "Propagate into systemd-run invocation and non-bounded paths."
  definition_of_done:
    evidence_ids: []
    criteria:
      - "FAC runs are reproducible without relying on `~/.cargo/*` state."
      - "Ambient secret env vars are not propagated into jobs by default."
```

### TCK-00527 — Evidence bundle export/import commands exercising RFC-0028 boundary validation + RFC-0029 receipt validation (local-only)

```yaml
ticket_meta:
  schema_version: "2026-01-29"
  template_version: "2026-01-29"
  ticket:
    id: "TCK-00527"
    title: "Evidence bundle export/import commands exercising RFC-0028 boundary validation + RFC-0029 receipt validation (local-only)"
    status: "OPEN"
  binds:
    prd_id: "PRD-PLACEHOLDER"
    rfc_id: "RFC-0019"
    requirements: []
    evidence_artifacts: []
  custody:
    agent_roles: ["AGENT_IMPLEMENTER"]
    responsibility_domains: ["DOMAIN_SECURITY", "DOMAIN_RUNTIME"]
  dependencies:
    tickets:
      - ticket_id: "TCK-00513"
        reason: "Receipts must include required RFC-0028/0029 artifacts."
      - ticket_id: "TCK-00510"
        reason: "Import/export must validate broker-admitted policy bindings."
  scope:
    in_scope:
      - "Implement `apm2 fac bundle export <job_id>` producing envelope + blobs."
      - "Implement `apm2 fac bundle import <path>` that fails closed unless `validate_channel_boundary(...)` passes and embedded economics receipts validate."
      - "Use this tool as a forced integration harness to ensure RFC-0028 and RFC-0029 are exercised."
    out_of_scope:
      - "Network transfer."
  plan:
    steps:
      - "Define manifest/envelope serialization; store under fac blobs or temp export dir."
      - "Implement import validation pipeline."
  definition_of_done:
    evidence_ids: []
    criteria:
      - "Import refuses when boundary check invalid or policy binding mismatched."
      - "Import refuses when economics receipts unverifiable."
```

### TCK-00528 — Systemd units + runbook: broker + worker as managed services (user+system modes)

```yaml
ticket_meta:
  schema_version: "2026-01-29"
  template_version: "2026-01-29"
  ticket:
    id: "TCK-00528"
    title: "Systemd units + runbook: broker + worker as managed services (user+system modes)"
    status: "OPEN"
  binds:
    prd_id: "PRD-PLACEHOLDER"
    rfc_id: "RFC-0019"
    requirements: []
    evidence_artifacts: []
  custody:
    agent_roles: ["AGENT_IMPLEMENTER"]
    responsibility_domains: ["DOMAIN_RUNTIME", "DOMAIN_SECURITY"]
  dependencies:
    tickets:
      - ticket_id: "TCK-00510"
        reason: "Broker must exist before unit packaging."
      - ticket_id: "TCK-00511"
        reason: "Worker must exist before unit packaging."
  scope:
    in_scope:
      - "Provide systemd unit templates for: FAC Broker and FAC Worker."
      - "Support both user-mode units (with linger guidance) and system-mode units (preferred hardening)."
      - "Define dedicated runtime directories under `$APM2_HOME/private/fac/**` with strict permissions."
      - "Provide a minimal runbook: start/stop/status, logs, key rotation notes, failure modes."
      - "Add `apm2 fac services status` command (optional) that reports unit health."
    out_of_scope:
      - "Multi-node orchestration."
  plan:
    steps:
      - "Author unit files with explicit WorkingDirectory, EnvironmentFile (optional), Restart policies, and hardening knobs."
      - "For system units: run as dedicated service user; define slices if needed."
      - "Add docs: how to enable linger for user-mode; how to run system-mode safely."
  definition_of_done:
    evidence_ids: []
    criteria:
      - "On a clean Ubuntu VPS, broker and worker can be started and stay running under systemd."
      - "Worker can execute at least one queued job end-to-end under unit management."
  notes:
    security: |
      Ensure units do not run with excessive privileges by default.
      Default should avoid reliance on a user-bus for correctness.
```

### TCK-00529 — System-mode execution path: run jobs without user-bus dependency (broker-managed transient units)

```yaml
ticket_meta:
  schema_version: "2026-01-29"
  template_version: "2026-01-29"
  ticket:
    id: "TCK-00529"
    title: "System-mode execution path: run jobs without user-bus dependency (broker-managed transient units)"
    status: "OPEN"
  binds:
    prd_id: "PRD-PLACEHOLDER"
    rfc_id: "RFC-0019"
    requirements: []
    evidence_artifacts: []
  custody:
    agent_roles: ["AGENT_IMPLEMENTER"]
    responsibility_domains: ["DOMAIN_RUNTIME", "DOMAIN_SECURITY"]
  dependencies:
    tickets:
      - ticket_id: "TCK-00528"
        reason: "Needs service deployment model for broker/worker."
      - ticket_id: "TCK-00515"
        reason: "Needs lanes and lane profiles."
  scope:
    in_scope:
      - "Add an execution backend that does NOT require `systemd-run --user`."
      - "Broker (or worker) creates system-scoped transient units (or uses a system service template) for job execution."
      - "Jobs run as a dedicated low-privilege service user, with KillMode=control-group."
      - "Preserve the same semantics: lane lease -> bounded unit -> streaming logs -> receipts."
      - "Auto-select backend: prefer system-mode if configured, otherwise user-mode with explicit failure messaging."
    out_of_scope:
      - "Containers/VM sandboxing."
  plan:
    steps:
      - "Implement systemd D-Bus integration or a safe wrapper for system transient units."
      - "Implement backend selection + clear diagnostic errors."
      - "Add kill/stop support used by cancellation and lane reset."
  definition_of_done:
    evidence_ids: []
    criteria:
      - "On a headless VPS without a working user-bus, FAC jobs can still run bounded via system-mode backend."
      - "Cgroup membership is correct (child processes remain inside the job unit)."
```

### TCK-00530 — LaneProfile→systemd unit properties: single authoritative builder for CPU/mem/PIDs/IO/timeouts

```yaml
ticket_meta:
  schema_version: "2026-01-29"
  template_version: "2026-01-29"
  ticket:
    id: "TCK-00530"
    title: "LaneProfile→systemd unit properties: single authoritative builder for CPU/mem/PIDs/IO/timeouts"
    status: "OPEN"
  binds:
    prd_id: "PRD-PLACEHOLDER"
    rfc_id: "RFC-0019"
    requirements: []
    evidence_artifacts: []
  custody:
    agent_roles: ["AGENT_IMPLEMENTER"]
    responsibility_domains: ["DOMAIN_RUNTIME"]
  dependencies:
    tickets:
      - ticket_id: "TCK-00515"
        reason: "LaneProfileV1 must exist."
  scope:
    in_scope:
      - "Implement a single builder that maps LaneProfileV1 + FacPolicyV1 to systemd properties."
      - "Ensure consistent enforcement across backends (user-mode/system-mode)."
      - "Centralize defaults for CPUQuota, MemoryMax, TasksMax(PIDs), IOWeight, TimeoutStartSec/RuntimeMaxSec, KillMode."
      - "Expose a `--print-unit` debug mode (optional) to show computed properties."
    out_of_scope:
      - "Dynamic per-testcase tuning."
  plan:
    steps:
      - "Define property mapping table."
      - "Implement builder + tests verifying deterministic output."
      - "Wire into both execution backends."
  definition_of_done:
    evidence_ids: []
    criteria:
      - "All job executions use the builder (no ad-hoc unit property duplication)."
      - "Changing LaneProfileV1 changes runtime unit properties deterministically."
```

### TCK-00531 — RFC-0029 scheduler state persistence: stable state file + restart safety + anti-starvation continuity

```yaml
ticket_meta:
  schema_version: "2026-01-29"
  template_version: "2026-01-29"
  ticket:
    id: "TCK-00531"
    title: "RFC-0029 scheduler state persistence: stable state file + restart safety + anti-starvation continuity"
    status: "OPEN"
  binds:
    prd_id: "PRD-PLACEHOLDER"
    rfc_id: "RFC-0019"
    requirements: []
    evidence_artifacts: []
  custody:
    agent_roles: ["AGENT_IMPLEMENTER"]
    responsibility_domains: ["DOMAIN_RUNTIME", "DOMAIN_SECURITY"]
  dependencies:
    tickets:
      - ticket_id: "TCK-00511"
        reason: "Worker must compute admissions."
      - ticket_id: "TCK-00510"
        reason: "Broker provides envelopes/horizons."
  scope:
    in_scope:
      - "Persist scheduler state under `$APM2_HOME/private/fac/scheduler/state.v1.json`."
      - "State must include: lane backlog snapshots, max_wait_ticks per lane, last evaluation tick, and any RFC-0029 state required to preserve anti-starvation across restarts."
      - "Worker loads state on startup; if missing/corrupt, reconstructs conservatively and emits a recovery receipt."
      - "State file writes are atomic and symlink-safe."
    out_of_scope:
      - "Distributed scheduler convergence."
  plan:
    steps:
      - "Define SchedulerStateV1 schema."
      - "Implement atomic writer and bounded reader."
      - "Integrate with RFC-0029 evaluation input construction."
  definition_of_done:
    evidence_ids: []
    criteria:
      - "Restarting worker preserves fairness/anti-starvation behavior (no permanent starvation regression)."
      - "Malformed state triggers fail-closed conservative behavior and a recovery receipt."
```

### TCK-00532 — RFC-0029 cost model: job cost estimation + post-run calibration from receipts

```yaml
ticket_meta:
  schema_version: "2026-01-29"
  template_version: "2026-01-29"
  ticket:
    id: "TCK-00532"
    title: "RFC-0029 cost model: job cost estimation + post-run calibration from receipts"
    status: "OPEN"
  binds:
    prd_id: "PRD-PLACEHOLDER"
    rfc_id: "RFC-0019"
    requirements: []
    evidence_artifacts: []
  custody:
    agent_roles: ["AGENT_IMPLEMENTER"]
    responsibility_domains: ["DOMAIN_RUNTIME"]
  dependencies:
    tickets:
      - ticket_id: "TCK-00513"
        reason: "Receipts must include admissions and runtime stats."
      - ticket_id: "TCK-00531"
        reason: "Scheduler state must exist."
  scope:
    in_scope:
      - "Define per-job-kind cost estimates used for queue admission (e.g., expected ticks or wait units)."
      - "Record observed runtime/cost metrics in receipts."
      - "Implement a calibration mechanism that updates cost estimates conservatively over time (bounded, monotone-safe)."
      - "Expose `apm2 fac scheduler stats` (optional) showing cost model and denial reasons."
    out_of_scope:
      - "ML-based prediction."
  plan:
    steps:
      - "Define CostModelV1 with conservative defaults."
      - "Add receipt fields for duration/cpu_time/bytes_written (best-effort)."
      - "Update worker to refine estimates within policy bounds."
  definition_of_done:
    evidence_ids: []
    criteria:
      - "Queue admission inputs contain a deterministic cost estimate for every job."
      - "Calibration never makes the system less safe (never increases concurrency or budgets)."
```

### TCK-00533 — Cancellation semantics: stop_revoke lane + kill running unit + receipts

```yaml
ticket_meta:
  schema_version: "2026-01-29"
  template_version: "2026-01-29"
  ticket:
    id: "TCK-00533"
    title: "Cancellation semantics: stop_revoke lane + kill running unit + receipts"
    status: "OPEN"
  binds:
    prd_id: "PRD-PLACEHOLDER"
    rfc_id: "RFC-0019"
    requirements: []
    evidence_artifacts: []
  custody:
    agent_roles: ["AGENT_IMPLEMENTER"]
    responsibility_domains: ["DOMAIN_RUNTIME", "DOMAIN_SECURITY"]
  dependencies:
    tickets:
      - ticket_id: "TCK-00511"
        reason: "Worker must interpret stop_revoke jobs and manage running units."
      - ticket_id: "TCK-00529"
        reason: "System-mode kill path should be supported."
  scope:
    in_scope:
      - "Add `apm2 fac job cancel <job_id>` command."
      - "If pending: move to cancelled and emit cancellation receipt."
      - "If claimed/running: enqueue a `stop_revoke` job (highest priority) to kill the active unit (KillMode=control-group) and mark the target job cancelled."
      - "Ensure cancellations are authenticated (RFC-0028) and admitted (RFC-0029)."
      - "Ensure cancellation never deletes evidence/logs; it only stops execution and writes receipts."
    out_of_scope:
      - "Remote cancellation transport."
  plan:
    steps:
      - "Implement cancel command and job kind."
      - "Implement worker logic to locate and kill job unit."
      - "Write receipts and update job state deterministically."
  definition_of_done:
    evidence_ids: []
    criteria:
      - "A running job can be cancelled reliably without leaving orphan processes."
      - "Cancellation produces receipts in all cases (pending/claimed/running)."
```

### TCK-00534 — Crash recovery + reconcile: repair queue/leases on worker startup; emit recovery receipts

```yaml
ticket_meta:
  schema_version: "2026-01-29"
  template_version: "2026-01-29"
  ticket:
    id: "TCK-00534"
    title: "Crash recovery + reconcile: repair queue/leases on worker startup; emit recovery receipts"
    status: "OPEN"
  binds:
    prd_id: "PRD-PLACEHOLDER"
    rfc_id: "RFC-0019"
    requirements: []
    evidence_artifacts: []
  custody:
    agent_roles: ["AGENT_IMPLEMENTER"]
    responsibility_domains: ["DOMAIN_RUNTIME"]
  dependencies:
    tickets:
      - ticket_id: "TCK-00515"
        reason: "Leases exist and must be reconciled."
      - ticket_id: "TCK-00511"
        reason: "Worker is the reconciler in default mode."
  scope:
    in_scope:
      - "On worker startup: reconcile `queue/claimed` and lane leases."
      - "Detect stale leases (pid dead) and transition lane through CLEANUP to IDLE with receipts."
      - "Detect claimed jobs without running unit: requeue or mark failed deterministically (policy-driven)."
      - "Implement `apm2 fac reconcile --dry-run|--apply` command (optional)."
      - "All reconciliations emit receipts."
    out_of_scope:
      - "Distributed reconciliation."
  plan:
    steps:
      - "Define recovery policy defaults."
      - "Implement reconciler and atomic moves."
      - "Add integration test simulating crash mid-job."
  definition_of_done:
    evidence_ids: []
    criteria:
      - "After an unclean shutdown, the system converges to a consistent queue+lane state without manual file edits."
      - "No job is silently dropped; outcomes are recorded as receipts."
```

### TCK-00535 — Introspection CLI: queue status + job show + receipts list (forensics-first UX)

```yaml
ticket_meta:
  schema_version: "2026-01-29"
  template_version: "2026-01-29"
  ticket:
    id: "TCK-00535"
    title: "Introspection CLI: queue status + job show + receipts list (forensics-first UX)"
    status: "OPEN"
  binds:
    prd_id: "PRD-PLACEHOLDER"
    rfc_id: "RFC-0019"
    requirements: []
    evidence_artifacts: []
  custody:
    agent_roles: ["AGENT_IMPLEMENTER"]
    responsibility_domains: ["DOMAIN_RUNTIME"]
  dependencies:
    tickets:
      - ticket_id: "TCK-00513"
        reason: "Receipts are authoritative and must be queryable."
  scope:
    in_scope:
      - "Add `apm2 fac queue status` (counts by dir, oldest job, denial/quarantine stats)."
      - "Add `apm2 fac job show <job_id>` (spec + last receipt + logs pointers)."
      - "Add `apm2 fac receipts list --since ...` with deterministic ordering rules."
      - "All commands support `--json` and bounded reads."
    out_of_scope:
      - "GUI."
  plan:
    steps:
      - "Implement directory scans with bounded parsing."
      - "Implement receipt index scanning (best-effort)."
      - "Add basic filtering and output."
  definition_of_done:
    evidence_ids: []
    criteria:
      - "Operators can diagnose denial/quarantine/cancellation states without reading raw JSON files manually."
```

### TCK-00536 — Permissions hardening: enforce 0700 roots, safe ownership checks, and refuse unsafe `$APM2_HOME/private/fac` perms

```yaml
ticket_meta:
  schema_version: "2026-01-29"
  template_version: "2026-01-29"
  ticket:
    id: "TCK-00536"
    title: "Permissions hardening: enforce 0700 roots, safe ownership checks, and refuse unsafe `$APM2_HOME/private/fac` perms"
    status: "OPEN"
  binds:
    prd_id: "PRD-PLACEHOLDER"
    rfc_id: "RFC-0019"
    requirements: []
    evidence_artifacts: []
  custody:
    agent_roles: ["AGENT_IMPLEMENTER"]
    responsibility_domains: ["DOMAIN_SECURITY"]
  dependencies:
    tickets: []
  scope:
    in_scope:
      - "On any FAC command entry, verify `$APM2_HOME/private/fac` and critical subdirs are owned by the current user/service user and are mode 0700 (or stricter)."
      - "Refuse to run in default mode if permissions are unsafe; print actionable remediation."
      - "Ensure all newly created FAC dirs/files are created with safe perms (umask handling)."
    out_of_scope:
      - "SELinux/AppArmor policy authoring."
  plan:
    steps:
      - "Implement a FAC root validator."
      - "Add to broker/worker startup and CLI entrypoints."
  definition_of_done:
    evidence_ids: []
    criteria:
      - "FAC refuses to run if fac roots are group/world-writable or owned by unexpected user."
```

### TCK-00537 — Safe atomic file I/O primitives: atomic JSON write + O_NOFOLLOW open + bounded read helper (queue/leases/receipts)

```yaml
ticket_meta:
  schema_version: "2026-01-29"
  template_version: "2026-01-29"
  ticket:
    id: "TCK-00537"
    title: "Safe atomic file I/O primitives: atomic JSON write + O_NOFOLLOW open + bounded read helper (queue/leases/receipts)"
    status: "OPEN"
  binds:
    prd_id: "PRD-PLACEHOLDER"
    rfc_id: "RFC-0019"
    requirements: []
    evidence_artifacts: []
  custody:
    agent_roles: ["AGENT_IMPLEMENTER"]
    responsibility_domains: ["DOMAIN_SECURITY", "DOMAIN_RUNTIME"]
  dependencies:
    tickets: []
  scope:
    in_scope:
      - "Implement atomic writer: write to temp file in same directory, fsync, rename."
      - "Implement safe opener: refuse symlinks with O_NOFOLLOW (where available) and verify metadata."
      - "Implement bounded JSON reader (size cap, deny_unknown_fields) reused across queue and receipts."
      - "Migrate queue/lease/scheduler state writers to these helpers."
    out_of_scope:
      - "General-purpose FS library."
  plan:
    steps:
      - "Implement helper module."
      - "Refactor call sites to use helper."
      - "Add tests for symlink refusal and atomicity."
  definition_of_done:
    evidence_ids: []
    criteria:
      - "Queue and lease files cannot be replaced via symlink tricks in default mode."
      - "Partial writes do not produce malformed state; atomic rename ensures consistency."
```

### TCK-00538 — ToolchainFingerprintV1: stable derivation, caching, and inclusion in receipts/attestation

```yaml
ticket_meta:
  schema_version: "2026-01-29"
  template_version: "2026-01-29"
  ticket:
    id: "TCK-00538"
    title: "ToolchainFingerprintV1: stable derivation, caching, and inclusion in receipts/attestation"
    status: "OPEN"
  binds:
    prd_id: "PRD-PLACEHOLDER"
    rfc_id: "RFC-0019"
    requirements: []
    evidence_artifacts: []
  custody:
    agent_roles: ["AGENT_IMPLEMENTER"]
    responsibility_domains: ["DOMAIN_RUNTIME"]
  dependencies:
    tickets:
      - ticket_id: "TCK-00515"
        reason: "Lane target namespaces require toolchain fingerprint."
  scope:
    in_scope:
      - "Define toolchain fingerprint derivation (e.g., rustc -Vv + cargo -V + nextest -V + systemd-run -V as needed)."
      - "Compute a stable `b3-256:` fingerprint."
      - "Cache fingerprint per boot/session under `$APM2_HOME/private/fac/toolchain/` with safe perms."
      - "Ensure all job receipts include toolchain_fingerprint and lane target dir uses it."
    out_of_scope:
      - "Pinning toolchain via nix (handled separately)."
  plan:
    steps:
      - "Define fingerprint inputs and canonicalization."
      - "Implement derivation and caching."
      - "Wire into lane profile and target path computation."
  definition_of_done:
    evidence_ids: []
    criteria:
      - "Fingerprint changes when underlying toolchain changes."
      - "Fingerprint is consistent across processes on the same node."
```

### TCK-00539 — Lane init/reconcile: create lanes, write profiles, and repair missing lane roots (operator-friendly bootstrap)

```yaml
ticket_meta:
  schema_version: "2026-01-29"
  template_version: "2026-01-29"
  ticket:
    id: "TCK-00539"
    title: "Lane init/reconcile: create lanes, write profiles, and repair missing lane roots (operator-friendly bootstrap)"
    status: "OPEN"
  binds:
    prd_id: "PRD-PLACEHOLDER"
    rfc_id: "RFC-0019"
    requirements: []
    evidence_artifacts: []
  custody:
    agent_roles: ["AGENT_IMPLEMENTER"]
    responsibility_domains: ["DOMAIN_RUNTIME"]
  dependencies:
    tickets:
      - ticket_id: "TCK-00515"
        reason: "Lane structures must exist."
  scope:
    in_scope:
      - "Implement `apm2 fac lanes init` to create lane directories and default profiles."
      - "Implement `apm2 fac lanes reconcile` to repair missing dirs and mark lanes CORRUPT if unrecoverable."
      - "Allow configuring lane_count via config/env; ensure deterministic lane IDs."
      - "Emit receipts for init/reconcile operations."
    out_of_scope:
      - "Auto-scaling lane count based on load."
  plan:
    steps:
      - "Implement init and reconcile commands."
      - "Add docs for first-time bootstrap."
  definition_of_done:
    evidence_ids: []
    criteria:
      - "A fresh `$APM2_HOME` can be bootstrapped into a ready lane pool with one command."
```

### TCK-00540 — Legacy gate cache v2 reuse policy: default deny unless bound to RFC-0028/0029 receipts; add unsafe override flag

```yaml
ticket_meta:
  schema_version: "2026-01-29"
  template_version: "2026-01-29"
  ticket:
    id: "TCK-00540"
    title: "Legacy gate cache v2 reuse policy: default deny unless bound to RFC-0028/0029 receipts; add unsafe override flag"
    status: "OPEN"
  binds:
    prd_id: "PRD-PLACEHOLDER"
    rfc_id: "RFC-0019"
    requirements: []
    evidence_artifacts: []
  custody:
    agent_roles: ["AGENT_IMPLEMENTER"]
    responsibility_domains: ["DOMAIN_SECURITY"]
  dependencies:
    tickets:
      - ticket_id: "TCK-00513"
        reason: "Receipts must contain RFC-0028/0029 binding info."
  scope:
    in_scope:
      - "Define legacy cache reuse posture: gate_cache_v2 entries are treated as untrusted unless a corresponding receipt exists with RFC-0028 authorization + RFC-0029 admissions."
      - "Default-mode behavior: do not reuse unbound legacy cache entries."
      - "Add explicit `--allow-legacy-cache` (unsafe) flag that permits fallback reuse and marks receipts accordingly."
      - "Document migration expectation: gradually populate bound receipts; legacy cache becomes safe over time."
    out_of_scope:
      - "Full gate cache redesign (separate ticket)."
  plan:
    steps:
      - "Implement mapping between cache entries and receipts (best-effort)."
      - "Enforce default deny on unbound legacy cache."
      - "Add CLI flag and receipt markings."
  definition_of_done:
    evidence_ids: []
    criteria:
      - "Default mode never accepts a cache hit unless there is an auditable receipt with RFC-0028/0029 bindings."
```

### TCK-00541 — Gate cache v3 (optional): receipt-indexed cache store keyed by attestation+policy+toolchain (fail-closed by construction)

```yaml
ticket_meta:
  schema_version: "2026-01-29"
  template_version: "2026-01-29"
  ticket:
    id: "TCK-00541"
    title: "Gate cache v3 (optional): receipt-indexed cache store keyed by attestation+policy+toolchain (fail-closed by construction)"
    status: "OPEN"
  binds:
    prd_id: "PRD-PLACEHOLDER"
    rfc_id: "RFC-0019"
    requirements: []
    evidence_artifacts: []
  custody:
    agent_roles: ["AGENT_IMPLEMENTER"]
    responsibility_domains: ["DOMAIN_SECURITY", "DOMAIN_RUNTIME"]
  dependencies:
    tickets:
      - ticket_id: "TCK-00513"
        reason: "Receipts and bindings are required."
      - ticket_id: "TCK-00523"
        reason: "Attestation inputs must be fail-closed."
  scope:
    in_scope:
      - "Define a v3 cache index driven by receipts rather than ad-hoc paths."
      - "Cache hit requires: matching attestation digest + FacPolicyHash + ToolchainFingerprint + RFC-0028/0029 receipt bindings."
      - "Provide read compatibility: can read v2 but only writes v3 in default mode."
      - "Define GC policy and on-disk layout under `$APM2_HOME/private/fac/gate_cache_v3/`."
    out_of_scope:
      - "Remote cache distribution."
  plan:
    steps:
      - "Define v3 index schema and storage layout."
      - "Implement read/write paths and migrate hot entries opportunistically."
  definition_of_done:
    evidence_ids: []
    criteria:
      - "A cache hit in v3 is provably tied to an authoritative receipt and cannot be forged by simple file writes."
```

### TCK-00542 — Evidence bundle schemas in code: manifest+envelope + hashing + bounded parsing + export/import integration

```yaml
ticket_meta:
  schema_version: "2026-01-29"
  template_version: "2026-01-29"
  ticket:
    id: "TCK-00542"
    title: "Evidence bundle schemas in code: manifest+envelope + hashing + bounded parsing + export/import integration"
    status: "OPEN"
  binds:
    prd_id: "PRD-PLACEHOLDER"
    rfc_id: "RFC-0019"
    requirements: []
    evidence_artifacts: []
  custody:
    agent_roles: ["AGENT_IMPLEMENTER"]
    responsibility_domains: ["DOMAIN_SECURITY", "DOMAIN_RUNTIME"]
  dependencies:
    tickets:
      - ticket_id: "TCK-00527"
        reason: "Export/import commands need formal schemas and validation."
  scope:
    in_scope:
      - "Define `apm2.fac.evidence_bundle_manifest.v1` and `apm2.fac.evidence_bundle_envelope.v1` structs with deny_unknown_fields."
      - "Implement canonical hashing rules and b3-256 addressing."
      - "Implement bounded parsing for import; fail-closed on unknown/malformed fields."
      - "Ensure `channel_boundary_check` is required for import/export operations."
    out_of_scope:
      - "Network transport."
  plan:
    steps:
      - "Define structs and hashing helpers."
      - "Refactor export/import to use them."
  definition_of_done:
    evidence_ids: []
    criteria:
      - "Bundle import refuses malformed or oversized manifests/envelopes."
      - "Bundle hashes are stable and deterministic."
```

### TCK-00543 — Receipt stream merge tool: set-union merge + deterministic ordering + conflict audit report

```yaml
ticket_meta:
  schema_version: "2026-01-29"
  template_version: "2026-01-29"
  ticket:
    id: "TCK-00543"
    title: "Receipt stream merge tool: set-union merge + deterministic ordering + conflict audit report"
    status: "OPEN"
  binds:
    prd_id: "PRD-PLACEHOLDER"
    rfc_id: "RFC-0019"
    requirements: []
    evidence_artifacts: []
  custody:
    agent_roles: ["AGENT_IMPLEMENTER"]
    responsibility_domains: ["DOMAIN_RUNTIME"]
  dependencies:
    tickets:
      - ticket_id: "TCK-00513"
        reason: "Receipts must be content-addressed and queryable."
  scope:
    in_scope:
      - "Implement `apm2 fac receipts merge --from <dir> --into <dir>` as set union on receipt digests."
      - "Provide deterministic presentation ordering: HTF stamp if present else fallback tuple."
      - "Emit audit report: duplicates, mismatched job_id for same digest (should never happen), parse failures."
    out_of_scope:
      - "CRDT beyond set-union."
  plan:
    steps:
      - "Implement directory scanning + digest validation."
      - "Implement merge with atomic writes."
  definition_of_done:
    evidence_ids: []
    criteria:
      - "Receipt sets can be merged without semantic refactor and without losing provenance."
```

### TCK-00544 — `apm2 fac pipeline` integration: route evidence phase through queue/lanes (eliminate SHA drift + dirty attests-clean hazard)

```yaml
ticket_meta:
  schema_version: "2026-01-29"
  template_version: "2026-01-29"
  ticket:
    id: "TCK-00544"
    title: "`apm2 fac pipeline` integration: route evidence phase through queue/lanes (eliminate SHA drift + dirty attests-clean hazard)"
    status: "OPEN"
  binds:
    prd_id: "PRD-PLACEHOLDER"
    rfc_id: "RFC-0019"
    requirements: []
    evidence_artifacts: []
  custody:
    agent_roles: ["AGENT_IMPLEMENTER"]
    responsibility_domains: ["DOMAIN_RUNTIME", "DOMAIN_SECURITY"]
  dependencies:
    tickets:
      - ticket_id: "TCK-00517"
        reason: "Pipeline must run on lane checkout from mirror."
      - ticket_id: "TCK-00518"
        reason: "Default gates path already uses queue; pipeline should align."
  scope:
    in_scope:
      - "Modify pipeline evidence execution to enqueue job specs rather than running in caller cwd."
      - "Ensure pipeline provides a `mirror_commit` source with head_sha binding (no implicit HEAD)."
      - "Prohibit dirty workspace execution unless via patch injection."
      - "Ensure receipts produced include RFC-0028/0029 artifacts."
    out_of_scope:
      - "Pipeline protocol redesign."
  plan:
    steps:
      - "Refactor pipeline evidence phase to produce job spec and wait for completion."
      - "Verify attestation now reflects executed content."
  definition_of_done:
    evidence_ids: []
    criteria:
      - "Pipeline evidence runs cannot execute against drifting or dirty caller workspace."
      - "Cache reuse no longer fails open due to HEAD:<path> ignoring dirty state."
```

### TCK-00545 — Patch bytes backend: implement `fac_blobs_v1` store under `$APM2_HOME/private/fac/blobs` + GC policy

```yaml
ticket_meta:
  schema_version: "2026-01-29"
  template_version: "2026-01-29"
  ticket:
    id: "TCK-00545"
    title: "Patch bytes backend: implement `fac_blobs_v1` store under `$APM2_HOME/private/fac/blobs` + GC policy"
    status: "OPEN"
  binds:
    prd_id: "PRD-PLACEHOLDER"
    rfc_id: "RFC-0019"
    requirements: []
    evidence_artifacts: []
  custody:
    agent_roles: ["AGENT_IMPLEMENTER"]
    responsibility_domains: ["DOMAIN_RUNTIME", "DOMAIN_SECURITY"]
  dependencies:
    tickets:
      - ticket_id: "TCK-00517"
        reason: "Patch injection needs a bytes store."
      - ticket_id: "TCK-00524"
        reason: "GC must know how to prune blobs."
  scope:
    in_scope:
      - "Implement content-addressed blob store for patch bytes: `$APM2_HOME/private/fac/blobs/<hex>`."
      - "Write/read APIs with bounded sizes and safe permissions."
      - "Define blob retention policy and integrate with GC."
      - "Bind patch digest in job spec and attestation."
    out_of_scope:
      - "Dedup across nodes."
  plan:
    steps:
      - "Implement blob writer/reader and hashing."
      - "Wire into patch injection flow."
      - "Add GC pruning based on reachability from recent receipts/jobs."
  definition_of_done:
    evidence_ids: []
    criteria:
      - "Patch injection can execute without relying on ambient caller worktree."
      - "Blobs are safely prunable without breaking active jobs."
```

### TCK-00546 — Optional patch bytes backend: integrate existing APM2 CAS as storage (with explicit GC decisions)

```yaml
ticket_meta:
  schema_version: "2026-01-29"
  template_version: "2026-01-29"
  ticket:
    id: "TCK-00546"
    title: "Optional patch bytes backend: integrate existing APM2 CAS as storage (with explicit GC decisions)"
    status: "OPEN"
  binds:
    prd_id: "PRD-PLACEHOLDER"
    rfc_id: "RFC-0019"
    requirements: []
    evidence_artifacts: []
  custody:
    agent_roles: ["AGENT_IMPLEMENTER"]
    responsibility_domains: ["DOMAIN_RUNTIME"]
  dependencies:
    tickets:
      - ticket_id: "TCK-00545"
        reason: "Start with fac_blobs_v1; CAS backend is optional."
  scope:
    in_scope:
      - "Add support for `bytes_backend: apm2_cas` in patch injection."
      - "Define how CAS blobs are retained and pruned by FAC GC (explicit allowlist)."
      - "Fail-closed if backend is unknown or CAS policies not configured."
    out_of_scope:
      - "CAS redesign."
  plan:
    steps:
      - "Implement CAS read/write integration."
      - "Implement explicit FAC GC hooks for CAS paths used."
  definition_of_done:
    evidence_ids: []
    criteria:
      - "CAS-backed patch bytes can be used safely without expanding GC authority to unrelated CAS data."
```

### TCK-00547 — `apm2 fac doctor`: verify prerequisites (cgroup v2, systemd backend, broker reachable, nextest present, permissions safe)

```yaml
ticket_meta:
  schema_version: "2026-01-29"
  template_version: "2026-01-29"
  ticket:
    id: "TCK-00547"
    title: "`apm2 fac doctor`: verify prerequisites (cgroup v2, systemd backend, broker reachable, nextest present, permissions safe)"
    status: "OPEN"
  binds:
    prd_id: "PRD-PLACEHOLDER"
    rfc_id: "RFC-0019"
    requirements: []
    evidence_artifacts: []
  custody:
    agent_roles: ["AGENT_IMPLEMENTER"]
    responsibility_domains: ["DOMAIN_RUNTIME"]
  dependencies:
    tickets:
      - ticket_id: "TCK-00528"
        reason: "Doctor should check service units."
      - ticket_id: "TCK-00519"
        reason: "Doctor should verify nextest requirement."
  scope:
    in_scope:
      - "Add `apm2 fac doctor` command."
      - "Checks: cgroup v2 availability, systemd backend selection viability, broker status, worker status, nextest availability, FAC root permissions, disk free policy."
      - "Outputs actionable remediation steps."
    out_of_scope:
      - "Automated remediation."
  plan:
    steps:
      - "Implement checks with clear categorization (ERROR/WARN/OK)."
      - "Add `--json` output for automation."
  definition_of_done:
    evidence_ids: []
    criteria:
      - "`apm2 fac doctor` correctly identifies common failure modes (user-bus missing, nextest missing, unsafe perms)."
```

### TCK-00548 — Containment verification: cgroup membership check for rustc/nextest children; enforce gating when sccache enabled

```yaml
ticket_meta:
  schema_version: "2026-01-29"
  template_version: "2026-01-29"
  ticket:
    id: "TCK-00548"
    title: "Containment verification: cgroup membership check for rustc/nextest children; enforce gating when sccache enabled"
    status: "OPEN"
  binds:
    prd_id: "PRD-PLACEHOLDER"
    rfc_id: "RFC-0019"
    requirements: []
    evidence_artifacts: []
  custody:
    agent_roles: ["AGENT_IMPLEMENTER"]
    responsibility_domains: ["DOMAIN_SECURITY", "DOMAIN_RUNTIME"]
  dependencies:
    tickets:
      - ticket_id: "TCK-00529"
        reason: "Containment checks depend on the execution backend."
  scope:
    in_scope:
      - "Implement a containment check routine: verify child processes (rustc/nextest) share the same cgroup as the job unit."
      - "Expose `apm2 fac verify containment --job <job_id>` (or similar)."
      - "When sccache is enabled, require this check to pass (else auto-disable sccache and emit receipt)."
      - "Record containment verdict in receipts."
    out_of_scope:
      - "Kernel-level sandboxing."
  plan:
    steps:
      - "Implement process discovery during job execution and sample cgroup paths."
      - "Implement verdict logic and receipt recording."
  definition_of_done:
    evidence_ids: []
    criteria:
      - "Containment mismatches are detected reliably."
      - "System refuses to run with unsafe sccache containment in default mode."
```

### TCK-00549 — Bounded executor rewrite: replace bash bounded runner with Rust streaming executor (policy-driven env + caps)

```yaml
ticket_meta:
  schema_version: "2026-01-29"
  template_version: "2026-01-29"
  ticket:
    id: "TCK-00549"
    title: "Bounded executor rewrite: replace bash bounded runner with Rust streaming executor (policy-driven env + caps)"
    status: "OPEN"
  binds:
    prd_id: "PRD-PLACEHOLDER"
    rfc_id: "RFC-0019"
    requirements: []
    evidence_artifacts: []
  custody:
    agent_roles: ["AGENT_IMPLEMENTER"]
    responsibility_domains: ["DOMAIN_RUNTIME", "DOMAIN_SECURITY"]
  dependencies:
    tickets:
      - ticket_id: "TCK-00520"
        reason: "Streaming logs/caps must exist."
      - ticket_id: "TCK-00521"
        reason: "Policy-driven env allowlist/denylist required."
  scope:
    in_scope:
      - "Implement Rust bounded executor that creates transient systemd units and streams logs with caps."
      - "Replace `scripts/ci/run_bounded_tests.sh` usage in FAC paths (keep script as fallback only during transition)."
      - "Use FacPolicyV1 env_clear/allowlist/denylist to pass env; no ad-hoc allowlists."
      - "Ensure timeouts/memory/pids are enforced by unit properties, not by shell timers."
    out_of_scope:
      - "Replacing other CI scripts unrelated to execution."
  plan:
    steps:
      - "Implement executor library used by gates/warm/pipeline."
      - "Add feature flag for transition period."
      - "Deprecate shell runner once stable."
  definition_of_done:
    evidence_ids: []
    criteria:
      - "Bounded tests run with streaming logs and hard caps without relying on a brittle shell allowlist."
      - "Failure modes produce receipts with actionable diagnostics."
```

### TCK-00550 — CI guardrails: ban NoOpVerifier in default builds; enforce RFC-0028/0029 fields present in execution receipts

```yaml
ticket_meta:
  schema_version: "2026-01-29"
  template_version: "2026-01-29"
  ticket:
    id: "TCK-00550"
    title: "CI guardrails: ban NoOpVerifier in default builds; enforce RFC-0028/0029 fields present in execution receipts"
    status: "OPEN"
  binds:
    prd_id: "PRD-PLACEHOLDER"
    rfc_id: "RFC-0019"
    requirements: []
    evidence_artifacts: []
  custody:
    agent_roles: ["AGENT_IMPLEMENTER"]
    responsibility_domains: ["DOMAIN_SECURITY"]
  dependencies:
    tickets:
      - ticket_id: "TCK-00513"
        reason: "Receipt fields must exist."
      - ticket_id: "TCK-00510"
        reason: "Verifier integration must be real."
  scope:
    in_scope:
      - "Add compile-time/CI checks that `NoOpVerifier` is not used in default mode."
      - "Add integration tests asserting: execution receipts include RFC-0028 boundary + RFC-0029 admission traces."
      - "Add tests asserting: jobs without broker token are denied/quarantined."
    out_of_scope:
      - "Full formal verification."
  plan:
    steps:
      - "Add feature flags if needed: `--features unsafe_no_verify` only for dev/testing."
      - "Add CI checks and minimal end-to-end harness."
  definition_of_done:
    evidence_ids: []
    criteria:
      - "A PR that reintroduces NoOpVerifier or omits RFC-0028/0029 receipt fields fails CI."
```

### TCK-00551 — Observability: metrics from receipts (throughput, queue latency, denial/quarantine rate, disk usage) + status summaries

```yaml
ticket_meta:
  schema_version: "2026-01-29"
  template_version: "2026-01-29"
  ticket:
    id: "TCK-00551"
    title: "Observability: metrics from receipts (throughput, queue latency, denial/quarantine rate, disk usage) + status summaries"
    status: "OPEN"
  binds:
    prd_id: "PRD-PLACEHOLDER"
    rfc_id: "RFC-0019"
    requirements: []
    evidence_artifacts: []
  custody:
    agent_roles: ["AGENT_IMPLEMENTER"]
    responsibility_domains: ["DOMAIN_RUNTIME"]
  dependencies:
    tickets:
      - ticket_id: "TCK-00513"
        reason: "Receipts are the data source."
  scope:
    in_scope:
      - "Implement metrics extraction from receipts."
      - "Expose `apm2 fac metrics --since ... --json` for automation."
      - "Include: throughput (jobs/hour), queue wait, denial counts (by reason), quarantine volume, GC freed bytes, disk preflight failures."
    out_of_scope:
      - "Prometheus exporter (optional future)."
  plan:
    steps:
      - "Define metrics schema."
      - "Implement scanner and summary."
  definition_of_done:
    evidence_ids: []
    criteria:
      - "Operator can quantify progress toward 10x throughput and detect regressions from receipt-derived metrics."
```

### TCK-00552 — Benchmark harness: measure cold/warm gate times, disk footprint collapse, and concurrency stability (prove 10x claim)

```yaml
ticket_meta:
  schema_version: "2026-01-29"
  template_version: "2026-01-29"
  ticket:
    id: "TCK-00552"
    title: "Benchmark harness: measure cold/warm gate times, disk footprint collapse, and concurrency stability (prove 10x claim)"
    status: "OPEN"
  binds:
    prd_id: "PRD-PLACEHOLDER"
    rfc_id: "RFC-0019"
    requirements: []
    evidence_artifacts: []
  custody:
    agent_roles: ["AGENT_IMPLEMENTER"]
    responsibility_domains: ["DOMAIN_RUNTIME"]
  dependencies:
    tickets:
      - ticket_id: "TCK-00525"
        reason: "Warm must exist."
      - ticket_id: "TCK-00524"
        reason: "GC and preflight affect stability."
  scope:
    in_scope:
      - "Add `apm2 fac bench` that runs a standardized sequence: cold gates, warm, warm gates, multi-concurrent gates."
      - "Record results as receipts/artifacts."
      - "Compute headline deltas: cold->warm improvement, target dir size collapse vs many worktrees, denial rate."
    out_of_scope:
      - "Performance tuning beyond reporting."
  plan:
    steps:
      - "Define benchmark scenario and guardrails."
      - "Implement runner and report generator."
  definition_of_done:
    evidence_ids: []
    criteria:
      - "Bench results can be compared across commits to validate 10x improvements and detect regressions."
```

### TCK-00553 — sccache explicit activation (optional): policy-gated enablement + receipt/attestation surfacing + safe defaults

```yaml
ticket_meta:
  schema_version: "2026-01-29"
  template_version: "2026-01-29"
  ticket:
    id: "TCK-00553"
    title: "sccache explicit activation (optional): policy-gated enablement + receipt/attestation surfacing + safe defaults"
    status: "OPEN"
  binds:
    prd_id: "PRD-PLACEHOLDER"
    rfc_id: "RFC-0019"
    requirements: []
    evidence_artifacts: []
  custody:
    agent_roles: ["AGENT_IMPLEMENTER"]
    responsibility_domains: ["DOMAIN_RUNTIME", "DOMAIN_SECURITY"]
  dependencies:
    tickets:
      - ticket_id: "TCK-00523"
        reason: "Attestation must surface wrapper/env/version."
      - ticket_id: "TCK-00548"
        reason: "Containment verification required when enabling sccache."
  scope:
    in_scope:
      - "Add explicit `--sccache` enablement flag or policy knob (default off)."
      - "Ensure sccache env is injected explicitly (no ambient .cargo wrapper requirement)."
      - "Set SCCACHE_DIR under APM2_HOME and integrate with GC."
      - "Record sccache enablement and version in receipts and attestation."
    out_of_scope:
      - "Remote sccache caches."
  plan:
    steps:
      - "Add policy knob and CLI flag."
      - "Wire env injection."
      - "Add receipts for sccache stats (best-effort)."
  definition_of_done:
    evidence_ids: []
    criteria:
      - "sccache can be enabled explicitly and is visible in attestation."
      - "Default remains safe: disabled unless containment is proven."
```

### TCK-00554 — sccache containment protocol: per-unit server lifecycle + refusal to attach to out-of-cgroup servers

```yaml
ticket_meta:
  schema_version: "2026-01-29"
  template_version: "2026-01-29"
  ticket:
    id: "TCK-00554"
    title: "sccache containment protocol: per-unit server lifecycle + refusal to attach to out-of-cgroup servers"
    status: "OPEN"
  binds:
    prd_id: "PRD-PLACEHOLDER"
    rfc_id: "RFC-0019"
    requirements: []
    evidence_artifacts: []
  custody:
    agent_roles: ["AGENT_IMPLEMENTER"]
    responsibility_domains: ["DOMAIN_SECURITY"]
  dependencies:
    tickets:
      - ticket_id: "TCK-00553"
        reason: "sccache activation exists."
      - ticket_id: "TCK-00529"
        reason: "System-mode backend needed for reliable containment."
  scope:
    in_scope:
      - "Define and implement a protocol that ensures sccache server (if used) runs inside the job unit cgroup."
      - "Refuse to connect to a pre-existing server that is outside the unit cgroup."
      - "Start server inside unit and stop at unit end (or ensure same-cgroup server)."
      - "Record containment check verdict in receipt; auto-disable if mismatch."
    out_of_scope:
      - "Optimizing sccache performance."
  plan:
    steps:
      - "Implement per-unit server start/stop hooks."
      - "Integrate with containment verification routine."
  definition_of_done:
    evidence_ids: []
    criteria:
      - "With sccache enabled, rustc processes remain inside the bounded unit cgroup."
      - "If not possible, system fails closed or auto-disables sccache with receipt."
```

### TCK-00555 — RFC-0028 leakage budgets integration: enforce evidence/log export caps and declassification receipts

```yaml
ticket_meta:
  schema_version: "2026-01-29"
  template_version: "2026-01-29"
  ticket:
    id: "TCK-00555"
    title: "RFC-0028 leakage budgets integration: enforce evidence/log export caps and declassification receipts"
    status: "OPEN"
  binds:
    prd_id: "PRD-PLACEHOLDER"
    rfc_id: "RFC-0019"
    requirements: []
    evidence_artifacts: []
  custody:
    agent_roles: ["AGENT_IMPLEMENTER"]
    responsibility_domains: ["DOMAIN_SECURITY"]
  dependencies:
    tickets:
      - ticket_id: "TCK-00527"
        reason: "Bundle import/export exists."
      - ticket_id: "TCK-00520"
        reason: "Logs have caps and bundles."
  scope:
    in_scope:
      - "Use RFC-0028 leakage budgets to bound exported evidence bundles (bytes and classes)."
      - "Require a declassification receipt (RFC-0028) for any export that includes logs/artifacts beyond a configured cap."
      - "Bind leakage budget decisions into export receipts."
    out_of_scope:
      - "Network transport security."
  plan:
    steps:
      - "Define leakage budget policy defaults."
      - "Wire export path to consult channel policy and require receipts."
  definition_of_done:
    evidence_ids: []
    criteria:
      - "Evidence export cannot exceed configured leakage budgets without explicit declassification receipts."
```

### TCK-00556 — Node identity primitives: node_fingerprint derivation + boundary_id configuration + stable emission into LaneProfileV1

```yaml
ticket_meta:
  schema_version: "2026-01-29"
  template_version: "2026-01-29"
  ticket:
    id: "TCK-00556"
    title: "Node identity primitives: node_fingerprint derivation + boundary_id configuration + stable emission into LaneProfileV1"
    status: "OPEN"
  binds:
    prd_id: "PRD-PLACEHOLDER"
    rfc_id: "RFC-0019"
    requirements: []
    evidence_artifacts: []
  custody:
    agent_roles: ["AGENT_IMPLEMENTER"]
    responsibility_domains: ["DOMAIN_SECURITY"]
  dependencies:
    tickets:
      - ticket_id: "TCK-00515"
        reason: "LaneProfileV1 contains node_fingerprint."
  scope:
    in_scope:
      - "Implement node_fingerprint derivation and persistence (stable across restarts; changes only on explicit reset)."
      - "Define and persist boundary_id (default `apm2.fac.local`)."
      - "Ensure broker and worker consistently use same boundary_id."
    out_of_scope:
      - "Multi-node identity distribution."
  plan:
    steps:
      - "Define fingerprint inputs and persistence path."
      - "Update LaneProfileV1 writer and broker config."
  definition_of_done:
    evidence_ids: []
    criteria:
      - "Receipts and lane profiles include stable node_fingerprint and boundary_id; RFC-0029 evaluation uses it consistently."
```

### TCK-00557 — flake.nix + packaging: ensure devShell invariants and (optional) package broker/worker binaries

```yaml
ticket_meta:
  schema_version: "2026-01-29"
  template_version: "2026-01-29"
  ticket:
    id: "TCK-00557"
    title: "flake.nix + packaging: ensure devShell invariants and (optional) package broker/worker binaries"
    status: "OPEN"
  binds:
    prd_id: "PRD-PLACEHOLDER"
    rfc_id: "RFC-0019"
    requirements: []
    evidence_artifacts: []
  custody:
    agent_roles: ["AGENT_IMPLEMENTER"]
    responsibility_domains: ["DOMAIN_RUNTIME"]
  dependencies:
    tickets: []
  scope:
    in_scope:
      - "Ensure devShell includes required tools (cargo-nextest, git, any broker/worker deps)."
      - "Optionally provide Nix packages for broker/worker for reproducible deployment."
      - "Document how to run broker/worker under nix develop on Ubuntu baseline."
    out_of_scope:
      - "NixOS migration."
  plan:
    steps:
      - "Update flake devShell."
      - "Optionally define packages and apps."
  definition_of_done:
    evidence_ids: []
    criteria:
      - "`nix develop` provides all mandatory FAC substrate tools for running gates/warm/worker locally."
```

### TCK-00558 — Docs updates: Implementor SKILL + RFC-0007 amendments + operational runbooks (broker/worker/lanes/gc)

```yaml
ticket_meta:
  schema_version: "2026-01-29"
  template_version: "2026-01-29"
  ticket:
    id: "TCK-00558"
    title: "Docs updates: Implementor SKILL + RFC-0007 amendments + operational runbooks (broker/worker/lanes/gc)"
    status: "OPEN"
  binds:
    prd_id: "PRD-PLACEHOLDER"
    rfc_id: "RFC-0019"
    requirements: []
    evidence_artifacts: []
  custody:
    agent_roles: ["AGENT_IMPLEMENTER"]
    responsibility_domains: ["DOMAIN_RUNTIME"]
  dependencies:
    tickets: []
  scope:
    in_scope:
      - "Update SKILL.md to include warm lifecycle, queue-based execution, and failure mode handling."
      - "Update RFC-0007: mandate nextest and add containment constraints for caching."
      - "Add runbook docs: bootstrap lanes, start services, respond to quarantine/denials, do safe lane reset."
    out_of_scope:
      - "Marketing docs."
  plan:
    steps:
      - "Draft doc changes and cross-link from RFC-0019 amendment."
      - "Add example commands and expected outputs."
  definition_of_done:
    evidence_ids: []
    criteria:
      - "A new operator can bootstrap and run default-mode FAC with broker/worker without tribal knowledge."
```

### TCK-00559 — Security regression tests: fuzz job spec parsing + adversarial queue file tests + safe_rmtree property tests

```yaml
ticket_meta:
  schema_version: "2026-01-29"
  template_version: "2026-01-29"
  ticket:
    id: "TCK-00559"
    title: "Security regression tests: fuzz job spec parsing + adversarial queue file tests + safe_rmtree property tests"
    status: "OPEN"
  binds:
    prd_id: "PRD-PLACEHOLDER"
    rfc_id: "RFC-0019"
    requirements: []
    evidence_artifacts: []
  custody:
    agent_roles: ["AGENT_IMPLEMENTER"]
    responsibility_domains: ["DOMAIN_SECURITY"]
  dependencies:
    tickets:
      - ticket_id: "TCK-00537"
        reason: "Safe bounded parsing primitives should exist."
      - ticket_id: "TCK-00516"
        reason: "safe_rmtree_v1 must exist to test it."
  scope:
    in_scope:
      - "Add fuzzing targets for FacJobSpecV1 bounded parsing and denial/quarantine behavior."
      - "Add tests for queue tampering (digest mismatch, token mismatch, unknown fields)."
      - "Add property-style tests for safe_rmtree (symlink refusal, no parent escape, TOCTOU smoke)."
    out_of_scope:
      - "Full formal proofs."
  plan:
    steps:
      - "Add fuzz harness and CI hooks (time-bounded)."
      - "Add deterministic adversarial fixtures."
  definition_of_done:
    evidence_ids: []
    criteria:
      - "Common tamper vectors are caught by tests, preventing regression to fail-open behaviors."
```

### TCK-00560 — Receipt Index v1: rebuildable index for fast job/receipt lookup (non-authoritative cache)

```yaml
ticket_meta:
  schema_version: "2026-01-29"
  template_version: "2026-01-29"
  ticket:
    id: "TCK-00560"
    title: "Receipt Index v1: rebuildable index for fast job/receipt lookup (non-authoritative cache)"
    status: "OPEN"
  binds:
    prd_id: "PRD-PLACEHOLDER"
    rfc_id: "RFC-0019"
    requirements: []
    evidence_artifacts: []
  custody:
    agent_roles: ["AGENT_IMPLEMENTER"]
    responsibility_domains: ["DOMAIN_RUNTIME", "DOMAIN_SECURITY"]
  dependencies:
    tickets:
      - ticket_id: "TCK-00513"
        reason: "Receipts must be content-addressed and include required fields."
      - ticket_id: "TCK-00537"
        reason: "Needs atomic safe file I/O primitives for index updates."
  scope:
    in_scope:
      - "Implement a **non-authoritative**, rebuildable index to avoid scanning all receipts repeatedly."
      - "Index lives under `$APM2_HOME/private/fac/receipts/index/`."
      - "Index entries map at minimum:"
      - "  - job_id -> latest receipt digest"
      - "  - receipt digest -> parsed header fields (kind, status, started_at, finished_at, lane_id, queue_lane)"
      - "  - optional: time bucket -> list of receipt digests for efficient `--since` queries"
      - "Index MUST be treated as a cache: on any inconsistency, rebuild from receipt store."
      - "Index writes MUST be atomic and symlink-safe; index reads bounded."
      - "Add `apm2 fac receipts reindex` (optional) to force rebuild."
      - "Update waiters (`gates` enqueue+wait, job show, metrics) to consult index first."
    out_of_scope:
      - "Distributed indexing."
      - "Making index authoritative for any decision (forbidden)."
  plan:
    steps:
      - "Define `ReceiptIndexV1` schema(s): a small stable header index plus optional per-job pointers."
      - "Implement incremental update on receipt write: append/update pointer atomically."
      - "Implement rebuild: scan receipts directory, validate digests, rebuild index deterministically."
      - "Add integrity checks: if index references missing receipt or mismatched digest, trigger rebuild."
  definition_of_done:
    evidence_ids: []
    criteria:
      - "Common operations do not require full receipt directory scans (job show, wait, metrics, list)."
      - "Corrupt/missing index never breaks correctness: system rebuilds or falls back safely."
  notes:
    security: |
      Index is attacker-writable under A2 assumptions; never trust it for authorization/admission/caching.
      Only receipts (validated by digest) are ground truth.
```

### TCK-00561 — Policy update + adoption protocol: broker-admitted FacPolicyHash rotation with receipts + rollback

```yaml
ticket_meta:
  schema_version: "2026-01-29"
  template_version: "2026-01-29"
  ticket:
    id: "TCK-00561"
    title: "Policy update + adoption protocol: broker-admitted FacPolicyHash rotation with receipts + rollback"
    status: "OPEN"
  binds:
    prd_id: "PRD-PLACEHOLDER"
    rfc_id: "RFC-0019"
    requirements: []
    evidence_artifacts: []
  custody:
    agent_roles: ["AGENT_IMPLEMENTER"]
    responsibility_domains: ["DOMAIN_SECURITY", "DOMAIN_RUNTIME"]
  dependencies:
    tickets:
      - ticket_id: "TCK-00510"
        reason: "Broker must exist as the authority for admitted policy digests."
      - ticket_id: "TCK-00521"
        reason: "FacPolicyV1 + FacPolicyHash must exist."
      - ticket_id: "TCK-00513"
        reason: "Need receipts to record policy adoption events."
  scope:
    in_scope:
      - "Define how a new `FacPolicyV1` becomes authoritative (admitted) in default mode."
      - "Broker maintains admitted policy digest under `$APM2_HOME/private/fac/broker/admitted_policy_root.v1` (digest only; non-secret)."
      - "Introduce a CLI surface:"
      - "  - `apm2 fac policy show` (prints current policy + hash)"
      - "  - `apm2 fac policy validate <path|stdin>` (checks schema + computes hash)"
      - "  - `apm2 fac policy adopt <path|stdin>` (requests broker to adopt new policy digest)"
      - "Policy adoption MUST be atomic and rollbackable:"
      - "  - broker writes `admitted_policy_root.v1` via atomic rename"
      - "  - broker retains `admitted_policy_root.prev.v1` for rollback"
      - "  - worker refuses actuation tokens whose policy binding does not match admitted digest"
      - "Every policy adoption and rollback MUST emit a durable receipt:"
      - "  - `apm2.fac.policy_adoption_receipt.v1` (new) OR a FacJobReceiptV1(kind=policy_adopt)"
      - "Receipt includes old_digest, new_digest, actor identity (broker), and reason string."
    out_of_scope:
      - "Remote policy distribution."
      - "UI for policy editing."
  plan:
    steps:
      - "Implement broker endpoint: adopt_policy(fac_policy_hash) with atomic persistence."
      - "Implement CLI commands and guardrails (must be run by operator role / local admin)."
      - "Implement adoption receipt emission."
      - "Implement rollback command: `apm2 fac policy rollback`."
  definition_of_done:
    evidence_ids: []
    criteria:
      - "Policy changes are reflected in new actuation tokens and validated by workers."
      - "Workers fail-closed when policy binding mismatches (no silent drift)."
      - "Rollback works and is recorded as receipts."
  notes:
    security: |
      This is a critical control plane. Adoption must not accept an arbitrary file path without schema+hash validation.
      Policy adoption should require explicit operator action (not something an untrusted job can trigger).
```

### TCK-00562 — Quarantine management: explicit prune policy (TTL+quota) + commands + GC integration + receipts

```yaml
ticket_meta:
  schema_version: "2026-01-29"
  template_version: "2026-01-29"
  ticket:
    id: "TCK-00562"
    title: "Quarantine management: explicit prune policy (TTL+quota) + commands + GC integration + receipts"
    status: "OPEN"
  binds:
    prd_id: "PRD-PLACEHOLDER"
    rfc_id: "RFC-0019"
    requirements: []
    evidence_artifacts: []
  custody:
    agent_roles: ["AGENT_IMPLEMENTER"]
    responsibility_domains: ["DOMAIN_SECURITY", "DOMAIN_RUNTIME"]
  dependencies:
    tickets:
      - ticket_id: "TCK-00514"
        reason: "Queue denied/quarantine directories and move rules must exist."
      - ticket_id: "TCK-00524"
        reason: "GC must exist and be able to prune allowed roots with receipts."
      - ticket_id: "TCK-00513"
        reason: "Denial/quarantine receipts must exist."
  scope:
    in_scope:
      - "Implement explicit retention policy for `queue/quarantine/` and `queue/denied/`:"
      - "  - `quarantine_max_bytes` (hard quota; default conservative)"
      - "  - `quarantine_ttl_days` (default e.g. 14)"
      - "  - `denied_ttl_days` (default e.g. 7)"
      - "Quarantine deletion MUST be explicit and receipted; never silent."
      - "Add commands:"
      - "  - `apm2 fac quarantine list` (shows size/age/reason summary; --json)"
      - "  - `apm2 fac quarantine prune --dry-run|--apply` (policy-driven)"
      - "Integrate with `apm2 fac gc`:"
      - "  - GC may prune quarantine ONLY after reaching deeper escalation stage (and must emit receipts)."
      - "  - GC must never delete quarantined items newer than TTL unless quota hard exceeded (still receipted)."
    out_of_scope:
      - "Remote forensic upload."
  plan:
    steps:
      - "Define policy knobs in FacPolicyV1 for quarantine quotas/TTLs."
      - "Implement scanner (bounded parsing) for quarantine/denied directories."
      - "Implement prune planner with deterministic ordering (oldest-first, then largest) and atomic deletes using safe_rmtree_v1."
      - "Emit prune receipts with counts and bytes reclaimed."
  definition_of_done:
    evidence_ids: []
    criteria:
      - "Quarantine does not grow unbounded; pruning is deterministic and always receipted."
      - "Operators can inspect and prune quarantine without manual filesystem spelunking."
  notes:
    security: |
      Quarantine content is potentially attacker-supplied. Parsing must be bounded; display must avoid terminal escapes; do not auto-execute or auto-open files.
```

### TCK-00563 — Canonicalizer Tuple pinning: broker-admitted canonicalization version commitment + worker enforcement

```yaml
ticket_meta:
  schema_version: "2026-01-29"
  template_version: "2026-01-29"
  ticket:
    id: "TCK-00563"
    title: "Canonicalizer Tuple pinning: broker-admitted canonicalization version commitment + worker enforcement"
    status: "OPEN"
  binds:
    prd_id: "PRD-PLACEHOLDER"
    rfc_id: "RFC-0019"
    requirements: []
    evidence_artifacts: []
  custody:
    agent_roles: ["AGENT_IMPLEMENTER"]
    responsibility_domains: ["DOMAIN_SECURITY"]
  dependencies:
    tickets:
      - ticket_id: "TCK-00510"
        reason: "Broker stores admitted canonicalizer tuple commitment."
      - ticket_id: "TCK-00537"
        reason: "Atomic safe file IO for storing the tuple."
      - ticket_id: "TCK-00512"
        reason: "Job spec digest relies on canonicalization semantics."
  scope:
    in_scope:
      - "Define a `CanonicalizerTupleV1` commitment describing canonical JSON semantics used for digesting job specs/receipts."
      - "Broker stores admitted tuple digest under `$APM2_HOME/private/fac/broker/admitted_canonicalizer_tuple.v1`."
      - "Worker verifies canonicalizer tuple digest matches the broker-admitted digest at startup."
      - "If mismatch: default mode MUST fail-closed (deny execution) with actionable remediation."
      - "Record canonicalizer tuple digest in receipts for audit."
    out_of_scope:
      - "Cross-node tuple negotiation."
  plan:
    steps:
      - "Define tuple inputs (e.g., `apm2_core::determinism` version string + schema canonicalization mode id)."
      - "Implement broker persistence and CLI introspection."
      - "Implement worker validation and denial behavior."
  definition_of_done:
    evidence_ids: []
    criteria:
      - "Digest/canonicalization drift between broker and worker is detected and blocks actuation in default mode."
      - "Receipts include canonicalizer tuple digest for forensic audit."
  notes:
    security: |
      Without tuple pinning, a canonicalization behavior change can silently break digest binding, opening tamper windows.
```

### TCK-00564 — Receipt write pipeline: emit receipt + update index + link job state atomically (avoid torn states)

```yaml
ticket_meta:
  schema_version: "2026-01-29"
  template_version: "2026-01-29"
  ticket:
    id: "TCK-00564"
    title: "Receipt write pipeline: emit receipt + update index + link job state atomically (avoid torn states)"
    status: "OPEN"
  binds:
    prd_id: "PRD-PLACEHOLDER"
    rfc_id: "RFC-0019"
    requirements: []
    evidence_artifacts: []
  custody:
    agent_roles: ["AGENT_IMPLEMENTER"]
    responsibility_domains: ["DOMAIN_RUNTIME", "DOMAIN_SECURITY"]
  dependencies:
    tickets:
      - ticket_id: "TCK-00513"
        reason: "Receipts schema exists."
      - ticket_id: "TCK-00560"
        reason: "Receipt index exists."
      - ticket_id: "TCK-00537"
        reason: "Needs atomic safe I/O helpers."
  scope:
    in_scope:
      - "Define and implement an atomic 'commit protocol' when finishing a job:"
      - "  1) write receipt content-addressed file"
      - "  2) update receipt index pointer(s)"
      - "  3) move job file claimed→done (or claimed→denied/cancelled) with atomic rename"
      - "Ensure crash safety: after crash, reconcile can complete or rollback without losing receipts."
      - "Emit recovery receipts if torn state is detected and repaired."
    out_of_scope:
      - "Distributed commit/consensus."
  plan:
    steps:
      - "Implement a small transaction-like helper for these three steps."
      - "Update worker completion paths to use it."
      - "Add crash simulation test (kill worker mid-commit) and ensure reconcile converges."
  definition_of_done:
    evidence_ids: []
    criteria:
      - "No scenario exists where a job is marked done without its receipt present."
      - "Receipt index does not point to missing receipts after crashes (or triggers rebuild automatically)."
```
---

### TCK-00565 — RFC-0028 token binding contract: bind tokens to (job_spec_digest, FacPolicyHash, canonicalizer tuple, boundary_id) + expiry

```yaml
ticket_meta:
  schema_version: "2026-01-29"
  template_version: "2026-01-29"
  ticket:
    id: "TCK-00565"
    title: "RFC-0028 token binding contract: bind tokens to (job_spec_digest, FacPolicyHash, canonicalizer tuple, boundary_id) + expiry"
    status: "OPEN"
  binds:
    prd_id: "PRD-PLACEHOLDER"
    rfc_id: "RFC-0019"
    requirements: []
    evidence_artifacts: []
  custody:
    agent_roles: ["AGENT_IMPLEMENTER"]
    responsibility_domains: ["DOMAIN_SECURITY"]
  dependencies:
    tickets:
      - ticket_id: "TCK-00510"
        reason: "Broker issues tokens."
      - ticket_id: "TCK-00521"
        reason: "FacPolicyHash exists."
      - ticket_id: "TCK-00563"
        reason: "Canonicalizer tuple commitment exists."
      - ticket_id: "TCK-00556"
        reason: "Boundary id is stabilized."
  scope:
    in_scope:
      - "Define and enforce a token binding schema for FAC actuation tokens:"
      - "  - request_id MUST equal job_spec_digest"
      - "  - token MUST bind FacPolicyHash"
      - "  - token MUST bind canonicalizer tuple digest"
      - "  - token MUST bind boundary_id"
      - "  - token MUST include issued_at_tick + expiry_tick (short TTL)"
      - "Worker validation MUST deny if any binding mismatches or token expired."
      - "Receipt MUST record token bindings used (from decoded boundary check)."
    out_of_scope:
      - "PCAC/AJC redesign."
  plan:
    steps:
      - "Extend broker token issuance to include binding fields."
      - "Extend worker token validation to enforce bindings."
      - "Add tests: policy rotation invalidates old tokens; canonicalizer drift invalidates; expired token invalidates."
  definition_of_done:
    evidence_ids: []
    criteria:
      - "A token cannot be replayed across policy or canonicalization changes."
      - "Tokens expire and workers fail-closed on expiration."
```
---

### TCK-00566 — Token replay protection: broker-side one-time use (or bounded reuse) ledger + revocation

```yaml
ticket_meta:
  schema_version: "2026-01-29"
  template_version: "2026-01-29"
  ticket:
    id: "TCK-00566"
    title: "Token replay protection: broker-side one-time use (or bounded reuse) ledger + revocation"
    status: "OPEN"
  binds:
    prd_id: "PRD-PLACEHOLDER"
    rfc_id: "RFC-0019"
    requirements: []
    evidence_artifacts: []
  custody:
    agent_roles: ["AGENT_IMPLEMENTER"]
    responsibility_domains: ["DOMAIN_SECURITY"]
  dependencies:
    tickets:
      - ticket_id: "TCK-00565"
        reason: "Token binding and expiry must exist first."
  scope:
    in_scope:
      - "Implement replay resistance for RFC-0028 tokens in default mode:"
      - "  - broker maintains a small token-use ledger keyed by request_id/job_spec_digest"
      - "  - worker reports token use to broker (or broker encodes single-use nonce)"
      - "  - broker can revoke tokens (explicit) and workers consult revocation state when validating"
      - "Define bounded retention (TTL) for the ledger to avoid unbounded growth."
      - "Emit receipts for token revocation events."
    out_of_scope:
      - "Distributed replay protection."
  plan:
    steps:
      - "Define broker storage for used tokens under `$APM2_HOME/private/fac/broker/token_ledger/`."
      - "Implement worker callback or nonce scheme."
      - "Add denial path: reused token -> deny/quarantine + receipt."
  definition_of_done:
    evidence_ids: []
    criteria:
      - "A token reused for the same digest is detected and denied."
      - "Revoked tokens are denied even if unexpired."
```
---

### TCK-00567 — RFC-0028 intent taxonomy for FAC: typed tool-intent classes and per-kind authorization policy

```yaml
ticket_meta:
  schema_version: "2026-01-29"
  template_version: "2026-01-29"
  ticket:
    id: "TCK-00567"
    title: "RFC-0028 intent taxonomy for FAC: typed tool-intent classes and per-kind authorization policy"
    status: "OPEN"
  binds:
    prd_id: "PRD-PLACEHOLDER"
    rfc_id: "RFC-0019"
    requirements: []
    evidence_artifacts: []
  custody:
    agent_roles: ["AGENT_IMPLEMENTER"]
    responsibility_domains: ["DOMAIN_SECURITY"]
  dependencies:
    tickets:
      - ticket_id: "TCK-00510"
        reason: "Broker issues typed intent tokens."
      - ticket_id: "TCK-00521"
        reason: "FacPolicyV1 must define allowed intents."
  scope:
    in_scope:
      - "Define a stable mapping from FAC job kinds to RFC-0028 typed intents:"
      - "  - gates -> intent.fac.execute_gates"
      - "  - warm -> intent.fac.warm"
      - "  - gc -> intent.fac.gc"
      - "  - lane_reset -> intent.fac.lane_reset"
      - "  - stop_revoke -> intent.fac.cancel"
      - "  - bundle_export/import -> intent.fac.bundle"
      - "Broker issues tokens only for allowed intents per FacPolicyV1."
      - "Worker denies if token intent does not match job kind."
    out_of_scope:
      - "User-defined arbitrary intents."
  plan:
    steps:
      - "Add intent fields to broker token issuance."
      - "Add intent checks to worker validation."
      - "Add policy knobs: allowed_intents list."
  definition_of_done:
    evidence_ids: []
    criteria:
      - "A token for GC cannot be used to execute gates (kind/intent mismatch denial)."
```
---

### TCK-00568 — Broker rate limits + quotas: bound token issuance, queue growth, and expensive operations using RFC-0029 budgets

```yaml
ticket_meta:
  schema_version: "2026-01-29"
  template_version: "2026-01-29"
  ticket:
    id: "TCK-00568"
    title: "Broker rate limits + quotas: bound token issuance, queue growth, and expensive operations using RFC-0029 budgets"
    status: "OPEN"
  binds:
    prd_id: "PRD-PLACEHOLDER"
    rfc_id: "RFC-0019"
    requirements: []
    evidence_artifacts: []
  custody:
    agent_roles: ["AGENT_IMPLEMENTER"]
    responsibility_domains: ["DOMAIN_SECURITY", "DOMAIN_RUNTIME"]
  dependencies:
    tickets:
      - ticket_id: "TCK-00522"
        reason: "Budget admission evaluator integration exists."
      - ticket_id: "TCK-00510"
        reason: "Broker implements the authority surface."
  scope:
    in_scope:
      - "Apply RFC-0029 budget admission to control-plane actions:"
      - "  - token issuance rate"
      - "  - queue enqueue rate and maximum queue bytes"
      - "  - bundle export bytes"
      - "Broker denies requests exceeding configured budgets and emits receipts."
      - "Expose broker metrics for denial counts (optional)."
    out_of_scope:
      - "Distributed quotas."
  plan:
    steps:
      - "Define control-plane budgets in EconomicsProfile."
      - "Add budget checks in broker APIs."
      - "Add denial receipts."
  definition_of_done:
    evidence_ids: []
    criteria:
      - "Flooding enqueue/token requests hits a deny path with receipts, not host resource collapse."
```
---

### TCK-00569 — Lane cleanup state machine: post-job cleanup, failure handling, CORRUPT transitions, and cleanup receipts

```yaml
ticket_meta:
  schema_version: "2026-01-29"
  template_version: "2026-01-29"
  ticket:
    id: "TCK-00569"
    title: "Lane cleanup state machine: post-job cleanup, failure handling, CORRUPT transitions, and cleanup receipts"
    status: "OPEN"
  binds:
    prd_id: "PRD-PLACEHOLDER"
    rfc_id: "RFC-0019"
    requirements: []
    evidence_artifacts: []
  custody:
    agent_roles: ["AGENT_IMPLEMENTER"]
    responsibility_domains: ["DOMAIN_RUNTIME", "DOMAIN_SECURITY"]
  dependencies:
    tickets:
      - ticket_id: "TCK-00515"
        reason: "Lane leasing exists."
      - ticket_id: "TCK-00516"
        reason: "safe_rmtree_v1 exists for controlled deletion."
      - ticket_id: "TCK-00517"
        reason: "Lane workspace provenance exists (mirror checkout)."
  scope:
    in_scope:
      - "Implement lane lifecycle transitions with explicit cleanup phase:"
      - "  - after job execution, run cleanup: reset to SHA, git clean -ffdx, prune lane temp, enforce log quota hooks"
      - "  - if cleanup fails, mark lane CORRUPT and refuse future leases until reset"
      - "Persist CORRUPT marker and cleanup receipts."
      - "Expose in `lane status`."
    out_of_scope:
      - "Automatic lane reset without operator policy (optional later)."
  plan:
    steps:
      - "Define LaneCleanupReceiptV1 (or reuse FacJobReceiptV1(kind=lane_cleanup))."
      - "Implement cleanup runner and CORRUPT marker file."
      - "Wire worker to enforce cleanup before lane returns IDLE."
  definition_of_done:
    evidence_ids: []
    criteria:
      - "A cleanup failure prevents lane reuse and is visible via status."
      - "Cleanup actions are receipted for audit."
```
---

### TCK-00570 — Lane CORRUPT persistence + refusal semantics: marker file, reasons, and operator workflow

```yaml
ticket_meta:
  schema_version: "2026-01-29"
  template_version: "2026-01-29"
  ticket:
    id: "TCK-00570"
    title: "Lane CORRUPT persistence + refusal semantics: marker file, reasons, and operator workflow"
    status: "OPEN"
  binds:
    prd_id: "PRD-PLACEHOLDER"
    rfc_id: "RFC-0019"
    requirements: []
    evidence_artifacts: []
  custody:
    agent_roles: ["AGENT_IMPLEMENTER"]
    responsibility_domains: ["DOMAIN_RUNTIME"]
  dependencies:
    tickets:
      - ticket_id: "TCK-00569"
        reason: "Cleanup failures produce CORRUPT state."
  scope:
    in_scope:
      - "Define `lanes/<lane_id>/corrupt.v1.json` marker schema (reason, receipt digest, detected_at)."
      - "Worker refuses to lease a CORRUPT lane and optionally enqueues a control job recommending reset."
      - "CLI: `apm2 fac lane mark-corrupt <lane_id> --reason ...` (optional) for operators."
    out_of_scope:
      - "Automated remediation policies beyond refusal."
  plan:
    steps:
      - "Implement marker and status integration."
      - "Implement refusal paths and messaging."
  definition_of_done:
    evidence_ids: []
    criteria:
      - "CORRUPT lanes are never used inadvertently."
      - "Operators have clear reset workflow."
```
---

### TCK-00571 — Lane log retention + quotas: per-lane max bytes + per-job retention windows; GC integration

```yaml
ticket_meta:
  schema_version: "2026-01-29"
  template_version: "2026-01-29"
  ticket:
    id: "TCK-00571"
    title: "Lane log retention + quotas: per-lane max bytes + per-job retention windows; GC integration"
    status: "OPEN"
  binds:
    prd_id: "PRD-PLACEHOLDER"
    rfc_id: "RFC-0019"
    requirements: []
    evidence_artifacts: []
  custody:
    agent_roles: ["AGENT_IMPLEMENTER"]
    responsibility_domains: ["DOMAIN_RUNTIME"]
  dependencies:
    tickets:
      - ticket_id: "TCK-00520"
        reason: "Per-job logs exist."
      - ticket_id: "TCK-00524"
        reason: "GC exists."
  scope:
    in_scope:
      - "Define log retention policy knobs in FacPolicyV1:"
      - "  - per_lane_log_max_bytes"
      - "  - per_job_log_ttl_days"
      - "  - keep_last_n_jobs_per_lane"
      - "Implement pruning logic that runs:"
      - "  - after job completion (best-effort), and"
      - "  - in `apm2 fac gc` escalation."
      - "Emit pruning receipts (bytes freed)."
    out_of_scope:
      - "Remote log archival."
  plan:
    steps:
      - "Implement lane log directory scanner and deterministic prune planner."
      - "Wire into cleanup and GC."
  definition_of_done:
    evidence_ids: []
    criteria:
      - "Logs cannot grow without bound; retention is deterministic and auditable."
```
---

### TCK-00572 — Cgroup usage accounting: record cpu/mem/IO stats per job and store in receipts (feeds economics calibration)

```yaml
ticket_meta:
  schema_version: "2026-01-29"
  template_version: "2026-01-29"
  ticket:
    id: "TCK-00572"
    title: "Cgroup usage accounting: record cpu/mem/IO stats per job and store in receipts (feeds economics calibration)"
    status: "OPEN"
  binds:
    prd_id: "PRD-PLACEHOLDER"
    rfc_id: "RFC-0019"
    requirements: []
    evidence_artifacts: []
  custody:
    agent_roles: ["AGENT_IMPLEMENTER"]
    responsibility_domains: ["DOMAIN_RUNTIME"]
  dependencies:
    tickets:
      - ticket_id: "TCK-00530"
        reason: "Unit properties and cgroup identity exist."
      - ticket_id: "TCK-00513"
        reason: "Receipts schema exists."
  scope:
    in_scope:
      - "Collect best-effort runtime stats from job unit cgroup:"
      - "  - CPU time"
      - "  - peak memory / MemoryCurrent"
      - "  - IO bytes read/write"
      - "  - tasks count high watermark"
      - "Store in FacJobReceiptV1 under `observed_usage` block."
      - "Expose to economics calibration and metrics."
    out_of_scope:
      - "Perfect accuracy across all kernels."
  plan:
    steps:
      - "Implement cgroup stat reader for v2."
      - "Wire into job completion path."
  definition_of_done:
    evidence_ids: []
    criteria:
      - "Receipts contain observed usage stats for executed jobs in bounded mode."
```
---

### TCK-00573 — Job unit sandbox hardening: NoNewPrivileges, PrivateTmp, Protect*, Restrict*, safe defaults without breaking builds

```yaml
ticket_meta:
  schema_version: "2026-01-29"
  template_version: "2026-01-29"
  ticket:
    id: "TCK-00573"
    title: "Job unit sandbox hardening: NoNewPrivileges, PrivateTmp, Protect*, Restrict*, safe defaults without breaking builds"
    status: "OPEN"
  binds:
    prd_id: "PRD-PLACEHOLDER"
    rfc_id: "RFC-0019"
    requirements: []
    evidence_artifacts: []
  custody:
    agent_roles: ["AGENT_IMPLEMENTER"]
    responsibility_domains: ["DOMAIN_SECURITY", "DOMAIN_RUNTIME"]
  dependencies:
    tickets:
      - ticket_id: "TCK-00530"
        reason: "Need centralized unit builder."
  scope:
    in_scope:
      - "Add systemd hardening directives to job units (prefer system-mode backend):"
      - "  - NoNewPrivileges=yes"
      - "  - PrivateTmp=yes"
      - "  - ProtectControlGroups=yes"
      - "  - ProtectKernelTunables=yes"
      - "  - ProtectKernelLogs=yes"
      - "  - RestrictSUIDSGID=yes"
      - "  - LockPersonality=yes"
      - "  - RestrictRealtime=yes"
      - "  - RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 (policy controlled)"
      - "  - SystemCallArchitectures=native"
      - "Make hardening policy-driven (FacPolicyV1), with a known-good default profile."
      - "Emit unit hardening settings into receipts for audit (hash or normalized list)."
    out_of_scope:
      - "Container sandboxing."
  plan:
    steps:
      - "Define hardening profile knobs in policy."
      - "Update unit builder."
      - "Run gates suite and iteratively tighten without breaking."
  definition_of_done:
    evidence_ids: []
    criteria:
      - "Default hardening reduces attack surface measurably (documented directives) while preserving successful gates execution."
```
---

### TCK-00574 — Network policy for job units: default deny network for gates, allow only for explicit fetch/warm phases (policy-driven)

```yaml
ticket_meta:
  schema_version: "2026-01-29"
  template_version: "2026-01-29"
  ticket:
    id: "TCK-00574"
    title: "Network policy for job units: default deny network for gates, allow only for explicit fetch/warm phases (policy-driven)"
    status: "OPEN"
  binds:
    prd_id: "PRD-PLACEHOLDER"
    rfc_id: "RFC-0019"
    requirements: []
    evidence_artifacts: []
  custody:
    agent_roles: ["AGENT_IMPLEMENTER"]
    responsibility_domains: ["DOMAIN_SECURITY"]
  dependencies:
    tickets:
      - ticket_id: "TCK-00573"
        reason: "Unit hardening framework exists."
  scope:
    in_scope:
      - "Define policy knobs for network access by job kind and phase."
      - "Default posture:"
      - "  - gates/test/clippy/doc: network denied"
      - "  - warm/fetch: network allowed (if needed)"
      - "Enforce via systemd directives (IPAddressDeny/Allow, PrivateNetwork) where feasible."
      - "Record network policy decision in receipts."
    out_of_scope:
      - "Network shaping and bandwidth accounting."
  plan:
    steps:
      - "Add network policy fields to FacPolicyV1."
      - "Implement unit builder mapping."
      - "Add smoke tests (gates still run after warm)."
  definition_of_done:
    evidence_ids: []
    criteria:
      - "In default mode, evidence gates cannot open network connections unless explicitly allowed by policy."
```
---

### TCK-00575 — Env & path hygiene completion: set HOME/TMPDIR/XDG dirs per lane; prevent writes to ambient user locations

```yaml
ticket_meta:
  schema_version: "2026-01-29"
  template_version: "2026-01-29"
  ticket:
    id: "TCK-00575"
    title: "Env & path hygiene completion: set HOME/TMPDIR/XDG dirs per lane; prevent writes to ambient user locations"
    status: "OPEN"
  binds:
    prd_id: "PRD-PLACEHOLDER"
    rfc_id: "RFC-0019"
    requirements: []
    evidence_artifacts: []
  custody:
    agent_roles: ["AGENT_IMPLEMENTER"]
    responsibility_domains: ["DOMAIN_SECURITY", "DOMAIN_RUNTIME"]
  dependencies:
    tickets:
      - ticket_id: "TCK-00526"
        reason: "FAC-managed env clearing exists."
  scope:
    in_scope:
      - "Set deterministic per-lane/per-job environment roots:"
      - "  - HOME=$APM2_HOME/private/fac/lanes/<lane_id>/home"
      - "  - TMPDIR=$APM2_HOME/private/fac/lanes/<lane_id>/tmp"
      - "  - XDG_CACHE_HOME=$APM2_HOME/private/fac/lanes/<lane_id>/xdg_cache"
      - "  - XDG_CONFIG_HOME=$APM2_HOME/private/fac/lanes/<lane_id>/xdg_config"
      - "Enforce directory creation and quotas via GC policy."
      - "Ensure cargo/git respect these envs in job units."
    out_of_scope:
      - "Rewriting third-party tools."
  plan:
    steps:
      - "Add env_set entries to FacPolicyV1 defaults."
      - "Update executor to create dirs safely and set env."
  definition_of_done:
    evidence_ids: []
    criteria:
      - "FAC jobs do not write into `~/.cache`, `~/.cargo`, or other ambient user dirs by default."
```
---

### TCK-00576 — Signed receipts: broker/worker signature on receipts + verification tooling + gate-cache requires valid signature in default mode

```yaml
ticket_meta:
  schema_version: "2026-01-29"
  template_version: "2026-01-29"
  ticket:
    id: "TCK-00576"
    title: "Signed receipts: broker/worker signature on receipts + verification tooling + gate-cache requires valid signature in default mode"
    status: "OPEN"
  binds:
    prd_id: "PRD-PLACEHOLDER"
    rfc_id: "RFC-0019"
    requirements: []
    evidence_artifacts: []
  custody:
    agent_roles: ["AGENT_IMPLEMENTER"]
    responsibility_domains: ["DOMAIN_SECURITY"]
  dependencies:
    tickets:
      - ticket_id: "TCK-00510"
        reason: "Broker has signing key."
      - ticket_id: "TCK-00513"
        reason: "Receipt schema exists."
  scope:
    in_scope:
      - "Wrap receipts in a signed container (reuse existing signing primitives; no PCAC redesign)."
      - "Receipt verification MUST be performed when:"
      - "  - reading receipts for gate-cache reuse decisions"
      - "  - importing evidence bundles"
      - "Provide `apm2 fac receipts verify <digest|path>` command."
      - "Default mode: gate-cache reuse MUST require signature verification success."
    out_of_scope:
      - "Ledger protocol changes."
  plan:
    steps:
      - "Define SignedReceiptV1 container: payload digest + signature + signer id."
      - "Implement signing on write (worker) and verifying on read."
      - "Wire verification into cache reuse logic."
  definition_of_done:
    evidence_ids: []
    criteria:
      - "Forged receipts (unsigned or invalid signature) are rejected for cache reuse."
      - "Receipt verify tooling works and is bounded."
  notes:
    security: |
      This is the A3 mitigation that makes "receipts are ground truth" true under realistic local threat models.
```
---

### TCK-00577 — Receipt store permissions model: dedicated service user ownership + CLI writes only via broker APIs (minimize attacker write access)

```yaml
ticket_meta:
  schema_version: "2026-01-29"
  template_version: "2026-01-29"
  ticket:
    id: "TCK-00577"
    title: "Receipt store permissions model: dedicated service user ownership + CLI writes only via broker APIs (minimize attacker write access)"
    status: "OPEN"
  binds:
    prd_id: "PRD-PLACEHOLDER"
    rfc_id: "RFC-0019"
    requirements: []
    evidence_artifacts: []
  custody:
    agent_roles: ["AGENT_IMPLEMENTER"]
    responsibility_domains: ["DOMAIN_SECURITY", "DOMAIN_RUNTIME"]
  dependencies:
    tickets:
      - ticket_id: "TCK-00528"
        reason: "Systemd units and service user model exist."
      - ticket_id: "TCK-00536"
        reason: "Permissions validation exists."
  scope:
    in_scope:
      - "Define a dedicated FAC service user (system-mode recommended)."
      - "Ensure `$APM2_HOME/private/fac/receipts` and queue directories are owned and writable only by that user."
      - "CLI commands that enqueue jobs MUST interact with broker/worker APIs rather than writing directly to queue when not running as service user."
      - "Maintain backward compatibility only via explicit `--unsafe-local-write` mode."
    out_of_scope:
      - "Multi-user ACL UI."
  plan:
    steps:
      - "Update runbooks and systemd units to run broker/worker as service user."
      - "Update CLI to request enqueue via broker endpoint when not privileged."
      - "Add permission checks and clear errors."
  definition_of_done:
    evidence_ids: []
    criteria:
      - "Non-service-user processes cannot forge receipts/queue files in default deployment."
      - "CLI still works via broker-mediated enqueue."
```
---

### TCK-00578 — Queue bounds + backpressure: max pending jobs/bytes; denial with receipts; integrate RFC-0029 control-plane budgets

```yaml
ticket_meta:
  schema_version: "2026-01-29"
  template_version: "2026-01-29"
  ticket:
    id: "TCK-00578"
    title: "Queue bounds + backpressure: max pending jobs/bytes; denial with receipts; integrate RFC-0029 control-plane budgets"
    status: "OPEN"
  binds:
    prd_id: "PRD-PLACEHOLDER"
    rfc_id: "RFC-0019"
    requirements: []
    evidence_artifacts: []
  custody:
    agent_roles: ["AGENT_IMPLEMENTER"]
    responsibility_domains: ["DOMAIN_RUNTIME", "DOMAIN_SECURITY"]
  dependencies:
    tickets:
      - ticket_id: "TCK-00568"
        reason: "Broker quotas/budgets exist."
      - ticket_id: "TCK-00514"
        reason: "Denied/quarantine queues exist."
  scope:
    in_scope:
      - "Define policy knobs:"
      - "  - max_pending_jobs"
      - "  - max_pending_bytes"
      - "  - per_lane_max_pending_jobs (optional)"
      - "Enforce at enqueue time (broker), fail-closed with denial receipts."
      - "Add `queue/quota_exceeded` denial reason."
    out_of_scope:
      - "Distributed rate limiting."
  plan:
    steps:
      - "Implement enqueue-side checks."
      - "Emit denial receipts and place job in denied dir (or refuse creation)."
  definition_of_done:
    evidence_ids: []
    criteria:
      - "Queue cannot grow unbounded and exhaust disk; excess enqueue attempts are denied with receipts."
```
---

### TCK-00579 — Strict job spec validation policy: allowed kinds/repos; size caps; patch backend allowlist; deny unknown

```yaml
ticket_meta:
  schema_version: "2026-01-29"
  template_version: "2026-01-29"
  ticket:
    id: "TCK-00579"
    title: "Strict job spec validation policy: allowed kinds/repos; size caps; patch backend allowlist; deny unknown"
    status: "OPEN"
  binds:
    prd_id: "PRD-PLACEHOLDER"
    rfc_id: "RFC-0019"
    requirements: []
    evidence_artifacts: []
  custody:
    agent_roles: ["AGENT_IMPLEMENTER"]
    responsibility_domains: ["DOMAIN_SECURITY"]
  dependencies:
    tickets:
      - ticket_id: "TCK-00512"
        reason: "Job spec schema exists."
  scope:
    in_scope:
      - "Implement strict validation for `FacJobSpecV1` beyond serde deny_unknown_fields:"
      - "  - max JSON bytes on read"
      - "  - allowed `kind` values only"
      - "  - allowed `repo_id` set (policy-driven allowlist)"
      - "  - allowed patch bytes_backend values only"
      - "  - reject absolute paths or filesystem paths in job specs (repo_id is logical only)"
      - "Deny/quarantine any job failing these validations, emit receipts."
    out_of_scope:
      - "General job schema for non-FAC subsystems."
  plan:
    steps:
      - "Implement validator function and call from enqueue and worker pre-claim."
      - "Add adversarial fixtures."
  definition_of_done:
    evidence_ids: []
    criteria:
      - "Malformed or oversized job specs cannot cause memory blowups or undefined behavior; they are denied/quarantined deterministically."
```
---

### TCK-00580 — Git safety hardening in lane workspaces: disable hooks, enforce safe.directory, refuse unsafe configs

```yaml
ticket_meta:
  schema_version: "2026-01-29"
  template_version: "2026-01-29"
  ticket:
    id: "TCK-00580"
    title: "Git safety hardening in lane workspaces: disable hooks, enforce safe.directory, refuse unsafe configs"
    status: "OPEN"
  binds:
    prd_id: "PRD-PLACEHOLDER"
    rfc_id: "RFC-0019"
    requirements: []
    evidence_artifacts: []
  custody:
    agent_roles: ["AGENT_IMPLEMENTER"]
    responsibility_domains: ["DOMAIN_SECURITY"]
  dependencies:
    tickets:
      - ticket_id: "TCK-00517"
        reason: "Lane workspaces are created from mirror."
  scope:
    in_scope:
      - "Ensure lane workspace git config is hardened:"
      - "  - disable hooks (`core.hooksPath` to empty dir controlled by FAC)"
      - "  - enforce `safe.directory` for lane workspace path"
      - "  - refuse repo configs that attempt to run external commands via filters/smudge if policy forbids"
      - "Record git hardening status in receipts."
    out_of_scope:
      - "Git sandboxing beyond configuration."
  plan:
    steps:
      - "Implement post-checkout git config setup for lanes."
      - "Add tests ensuring hooks do not run."
  definition_of_done:
    evidence_ids: []
    criteria:
      - "Malicious repo hooks do not execute during lane operations in default mode."
```
---

### TCK-00581 — Patch injection hardening: path traversal rejection, safe apply mode, and patch provenance receipts

```yaml
ticket_meta:
  schema_version: "2026-01-29"
  template_version: "2026-01-29"
  ticket:
    id: "TCK-00581"
    title: "Patch injection hardening: path traversal rejection, safe apply mode, and patch provenance receipts"
    status: "OPEN"
  binds:
    prd_id: "PRD-PLACEHOLDER"
    rfc_id: "RFC-0019"
    requirements: []
    evidence_artifacts: []
  custody:
    agent_roles: ["AGENT_IMPLEMENTER"]
    responsibility_domains: ["DOMAIN_SECURITY"]
  dependencies:
    tickets:
      - ticket_id: "TCK-00517"
        reason: "Patch injection flow exists."
      - ticket_id: "TCK-00545"
        reason: "Patch bytes store exists."
  scope:
    in_scope:
      - "Validate patch content before apply:"
      - "  - reject paths containing `..`, absolute paths, or weird prefixes"
      - "  - restrict patch format to git_diff_v1 rules"
      - "Apply patch in safe mode and verify resulting tree matches expected patch digest binding."
      - "Emit PatchApplyReceiptV1 including patch digest, applied files count, and any refusals."
    out_of_scope:
      - "Binary patch formats."
  plan:
    steps:
      - "Implement patch parser/validator."
      - "Implement safe apply and post-apply verification."
  definition_of_done:
    evidence_ids: []
    criteria:
      - "A patch attempting to write outside the workspace is denied/quarantined with receipts."
```
---

### TCK-00582 — Repo mirror update hardening: locked updates, bounded fetch, remote URL allowlist, and receipts

```yaml
ticket_meta:
  schema_version: "2026-01-29"
  template_version: "2026-01-29"
  ticket:
    id: "TCK-00582"
    title: "Repo mirror update hardening: locked updates, bounded fetch, remote URL allowlist, and receipts"
    status: "OPEN"
  binds:
    prd_id: "PRD-PLACEHOLDER"
    rfc_id: "RFC-0019"
    requirements: []
    evidence_artifacts: []
  custody:
    agent_roles: ["AGENT_IMPLEMENTER"]
    responsibility_domains: ["DOMAIN_SECURITY", "DOMAIN_RUNTIME"]
  dependencies:
    tickets:
      - ticket_id: "TCK-00517"
        reason: "Repo mirror is used for lanes."
  scope:
    in_scope:
      - "Protect mirror updates against races and malicious configuration:"
      - "  - lock mirror update with file lock"
      - "  - enforce remote URL allowlist (policy-driven)"
      - "  - bound fetch size/time (best-effort) to prevent disk blowups"
      - "  - refuse symlink components in mirror path"
      - "Emit mirror update receipts with before/after refs."
    out_of_scope:
      - "Mirroring across multiple remotes."
  plan:
    steps:
      - "Implement mirror update function with locking."
      - "Add policy config for allowed remotes."
      - "Emit receipts."
  definition_of_done:
    evidence_ids: []
    criteria:
      - "Mirror update is deterministic, bounded, and auditable."
```
---

### TCK-00583 — Receipt/index compaction + GC: prune old index buckets, rebuild deterministically, and emit compaction receipts

```yaml
ticket_meta:
  schema_version: "2026-01-29"
  template_version: "2026-01-29"
  ticket:
    id: "TCK-00583"
    title: "Receipt/index compaction + GC: prune old index buckets, rebuild deterministically, and emit compaction receipts"
    status: "OPEN"
  binds:
    prd_id: "PRD-PLACEHOLDER"
    rfc_id: "RFC-0019"
    requirements: []
    evidence_artifacts: []
  custody:
    agent_roles: ["AGENT_IMPLEMENTER"]
    responsibility_domains: ["DOMAIN_RUNTIME"]
  dependencies:
    tickets:
      - ticket_id: "TCK-00560"
        reason: "Receipt index exists."
      - ticket_id: "TCK-00524"
        reason: "GC exists."
  scope:
    in_scope:
      - "Implement policies for index retention (not receipt retention)."
      - "Allow pruning old time buckets and rebuilding from receipts as needed."
      - "Integrate with `apm2 fac gc` escalation as a low-impact step."
      - "Emit `IndexCompactionReceiptV1`."
    out_of_scope:
      - "Deleting receipts as routine GC (forbidden by default)."
  plan:
    steps:
      - "Define index bucket layout and compaction rules."
      - "Implement prune/rebuild and receipts."
  definition_of_done:
    evidence_ids: []
    criteria:
      - "Index remains bounded in disk usage without sacrificing correctness (rebuildable)."
```
---

### TCK-00584 — EconomicsProfile adoption protocol: broker-admitted economics_profile_hash with rollback + receipts

```yaml
ticket_meta:
  schema_version: "2026-01-29"
  template_version: "2026-01-29"
  ticket:
    id: "TCK-00584"
    title: "EconomicsProfile adoption protocol: broker-admitted economics_profile_hash with rollback + receipts"
    status: "OPEN"
  binds:
    prd_id: "PRD-PLACEHOLDER"
    rfc_id: "RFC-0019"
    requirements: []
    evidence_artifacts: []
  custody:
    agent_roles: ["AGENT_IMPLEMENTER"]
    responsibility_domains: ["DOMAIN_SECURITY", "DOMAIN_RUNTIME"]
  dependencies:
    tickets:
      - ticket_id: "TCK-00510"
        reason: "Broker authority exists."
      - ticket_id: "TCK-00522"
        reason: "Economics profile binding is used."
  scope:
    in_scope:
      - "Define broker-admitted economics profile digest storage:"
      - "  - `$APM2_HOME/private/fac/broker/admitted_economics_profile.v1`"
      - "Add CLI:"
      - "  - `apm2 fac economics show`"
      - "  - `apm2 fac economics adopt <hash|path>`"
      - "  - `apm2 fac economics rollback`"
      - "Worker denies budget admissions if profile hash mismatches admitted digest."
      - "Emit adoption/rollback receipts."
    out_of_scope:
      - "Multi-node economics coordination."
  plan:
    steps:
      - "Implement broker endpoints + atomic persistence."
      - "Implement CLI and receipts."
  definition_of_done:
    evidence_ids: []
    criteria:
      - "Economics parameters become an auditable, broker-admitted control surface with rollback."
```
---

### TCK-00585 — Horizon/authority health monitoring: broker validates TP001/TP002/TP003 invariants and emits health receipts

```yaml
ticket_meta:
  schema_version: "2026-01-29"
  template_version: "2026-01-29"
  ticket:
    id: "TCK-00585"
    title: "Horizon/authority health monitoring: broker validates TP001/TP002/TP003 invariants and emits health receipts"
    status: "OPEN"
  binds:
    prd_id: "PRD-PLACEHOLDER"
    rfc_id: "RFC-0019"
    requirements: []
    evidence_artifacts: []
  custody:
    agent_roles: ["AGENT_IMPLEMENTER"]
    responsibility_domains: ["DOMAIN_SECURITY"]
  dependencies:
    tickets:
      - ticket_id: "TCK-00510"
        reason: "Broker serves envelopes/horizons."
  scope:
    in_scope:
      - "Broker periodically self-checks RFC-0029 invariants:"
      - "  - TP001 envelope signature validity"
      - "  - TP002 refs resolved/current with non-zero commitments"
      - "  - TP003 refs resolved/converged with non-zero commitments"
      - "Expose `apm2 fac broker health` (optional) and emit periodic HealthReceiptV1."
      - "Worker refuses to admit jobs if broker health is degraded (policy-driven)."
    out_of_scope:
      - "Distributed horizon resolution."
  plan:
    steps:
      - "Implement health checker and receipts."
      - "Add worker gate on health status."
  definition_of_done:
    evidence_ids: []
    criteria:
      - "If horizons/envelopes are misconfigured, the system fails closed with clear diagnostic receipts."
```
---

### TCK-00586 — Multi-worker fairness & scan efficiency: avoid stampede scanning; optional queue scan lease; deterministic behavior preserved

```yaml
ticket_meta:
  schema_version: "2026-01-29"
  template_version: "2026-01-29"
  ticket:
    id: "TCK-00586"
    title: "Multi-worker fairness & scan efficiency: avoid stampede scanning; optional queue scan lease; deterministic behavior preserved"
    status: "OPEN"
  binds:
    prd_id: "PRD-PLACEHOLDER"
    rfc_id: "RFC-0019"
    requirements: []
    evidence_artifacts: []
  custody:
    agent_roles: ["AGENT_IMPLEMENTER"]
    responsibility_domains: ["DOMAIN_RUNTIME"]
  dependencies:
    tickets:
      - ticket_id: "TCK-00511"
        reason: "Worker exists."
  scope:
    in_scope:
      - "Reduce overhead of multiple workers scanning large pending dirs:"
      - "  - optional short-lived `queue/scan.lock` lease for scan ownership"
      - "  - others wait/jitter and rely on atomic claim"
      - "Maintain determinism of claim selection order."
      - "Emit a receipt if scan lock is held too long (stuck worker detection)."
    out_of_scope:
      - "Distributed queue sharding."
  plan:
    steps:
      - "Implement optional scan lock with TTL and jitter."
      - "Integrate with worker loop."
  definition_of_done:
    evidence_ids: []
    criteria:
      - "Multiple workers do not cause excessive CPU/IO overhead scanning pending jobs."
```
---

### TCK-00587 — stop_revoke semantics: guarantee cancellation progress under load while still enforcing RFC-0028/0029 (explicit policy)

```yaml
ticket_meta:
  schema_version: "2026-01-29"
  template_version: "2026-01-29"
  ticket:
    id: "TCK-00587"
    title: "stop_revoke semantics: guarantee cancellation progress under load while still enforcing RFC-0028/0029 (explicit policy)"
    status: "OPEN"
  binds:
    prd_id: "PRD-PLACEHOLDER"
    rfc_id: "RFC-0019"
    requirements: []
    evidence_artifacts: []
  custody:
    agent_roles: ["AGENT_IMPLEMENTER"]
    responsibility_domains: ["DOMAIN_SECURITY", "DOMAIN_RUNTIME"]
  dependencies:
    tickets:
      - ticket_id: "TCK-00533"
        reason: "Cancellation job kind exists."
      - ticket_id: "TCK-00511"
        reason: "Worker admission gating exists."
  scope:
    in_scope:
      - "Define explicit policy for stop_revoke jobs:"
      - "  - still require valid RFC-0028 token (no unauth cancel)"
      - "  - RFC-0029 admission: policy may allow a reserved lane share for stop_revoke to avoid deadlock"
      - "  - stop_revoke executes even when queue is congested (anti-starvation)"
      - "Record explicit stop_revoke admission trace in receipts."
    out_of_scope:
      - "Remote kill protocols."
  plan:
    steps:
      - "Add economics lane reservation for stop_revoke."
      - "Add worker logic to prioritize cancellation safely."
  definition_of_done:
    evidence_ids: []
    criteria:
      - "Cancellation is reliable under heavy load without opening a bypass for unauthorized actuation."
```
---

### TCK-00588 — End-to-end default-mode harness: spin up broker+worker, enqueue gates, verify RFC-0028/0029 receipts, and test denial paths

```yaml
ticket_meta:
  schema_version: "2026-01-29"
  template_version: "2026-01-29"
  ticket:
    id: "TCK-00588"
    title: "End-to-end default-mode harness: spin up broker+worker, enqueue gates, verify RFC-0028/0029 receipts, and test denial paths"
    status: "OPEN"
  binds:
    prd_id: "PRD-PLACEHOLDER"
    rfc_id: "RFC-0019"
    requirements: []
    evidence_artifacts: []
  custody:
    agent_roles: ["AGENT_IMPLEMENTER"]
    responsibility_domains: ["DOMAIN_SECURITY", "DOMAIN_RUNTIME"]
  dependencies:
    tickets:
      - ticket_id: "TCK-00510"
        reason: "Broker exists."
      - ticket_id: "TCK-00511"
        reason: "Worker exists."
      - ticket_id: "TCK-00518"
        reason: "gates defaults to enqueue+wait."
  scope:
    in_scope:
      - "Implement an e2e test harness runnable in CI or local dev that:"
      - "  - starts broker and worker (in-process or subprocess)"
      - "  - enqueues a minimal job"
      - "  - asserts receipt contains: RFC-0028 boundary, RFC-0029 queue admission, budget admission"
      - "  - asserts missing token job is denied/quarantined"
      - "  - asserts expired token job is denied"
      - "  - asserts NoOpVerifier is not used (signature verified)"
    out_of_scope:
      - "Benchmarking (separate)."
  plan:
    steps:
      - "Add harness as integration test crate or script."
      - "Use lightweight job kind for CI if full gates too heavy."
  definition_of_done:
    evidence_ids: []
    criteria:
      - "CI proves RFC-0028/0029 are exercised and enforced end-to-end."
```
---

### TCK-00589 — Legacy evidence log deprecation: migrate to per-job logs, keep legacy read-only, and remove clobbering paths

```yaml
ticket_meta:
  schema_version: "2026-01-29"
  template_version: "2026-01-29"
  ticket:
    id: "TCK-00589"
    title: "Legacy evidence log deprecation: migrate to per-job logs, keep legacy read-only, and remove clobbering paths"
    status: "OPEN"
  binds:
    prd_id: "PRD-PLACEHOLDER"
    rfc_id: "RFC-0019"
    requirements: []
    evidence_artifacts: []
  custody:
    agent_roles: ["AGENT_IMPLEMENTER"]
    responsibility_domains: ["DOMAIN_RUNTIME"]
  dependencies:
    tickets:
      - ticket_id: "TCK-00520"
        reason: "Per-job logs exist."
  scope:
    in_scope:
      - "Ensure no writes occur to `private/fac/evidence/{gate}.log` once worker mode is default."
      - "Provide compatibility reads (optional) for old tooling."
      - "Add a one-time migration helper to move legacy logs into a `legacy/` namespace and emit a migration receipt."
    out_of_scope:
      - "Remote log archival."
  plan:
    steps:
      - "Search and remove remaining global log writes."
      - "Implement migration command."
  definition_of_done:
    evidence_ids: []
    criteria:
      - "Concurrent runs never clobber logs because legacy path is not written."
```
---

### TCK-00590 — `apm2 fac config show`: show resolved policy, boundary id, backend, lane count, admitted digests (operator correctness tool)

```yaml
ticket_meta:
  schema_version: "2026-01-29"
  template_version: "2026-01-29"
  ticket:
    id: "TCK-00590"
    title: "`apm2 fac config show`: show resolved policy, boundary id, backend, lane count, admitted digests (operator correctness tool)"
    status: "OPEN"
  binds:
    prd_id: "PRD-PLACEHOLDER"
    rfc_id: "RFC-0019"
    requirements: []
    evidence_artifacts: []
  custody:
    agent_roles: ["AGENT_IMPLEMENTER"]
    responsibility_domains: ["DOMAIN_RUNTIME"]
  dependencies:
    tickets:
      - ticket_id: "TCK-00561"
        reason: "Policy adoption exists."
      - ticket_id: "TCK-00584"
        reason: "Economics adoption exists."
      - ticket_id: "TCK-00556"
        reason: "Boundary id exists."
  scope:
    in_scope:
      - "Implement a single introspection command that prints:"
      - "  - current FacPolicyHash and path"
      - "  - admitted policy digest (broker) and canonicalizer tuple digest"
      - "  - admitted economics profile digest"
      - "  - boundary_id"
      - "  - execution backend (system/user)"
      - "  - lane_count and lane ids"
      - "  - queue bounds"
      - "Supports `--json`."
    out_of_scope:
      - "Editing config (separate)."
  plan:
    steps:
      - "Aggregate info from broker and filesystem state in bounded manner."
  definition_of_done:
    evidence_ids: []
    criteria:
      - "Operators can validate the system is configured as intended without reading files manually."
```
---

### TCK-00591 — Backup/restore tooling (minimal set): export/import FAC control-plane state (receipts, policy, horizons) without bulky caches

```yaml
ticket_meta:
  schema_version: "2026-01-29"
  template_version: "2026-01-29"
  ticket:
    id: "TCK-00591"
    title: "Backup/restore tooling (minimal set): export/import FAC control-plane state (receipts, policy, horizons) without bulky caches"
    status: "OPEN"
  binds:
    prd_id: "PRD-PLACEHOLDER"
    rfc_id: "RFC-0019"
    requirements: []
    evidence_artifacts: []
  custody:
    agent_roles: ["AGENT_IMPLEMENTER"]
    responsibility_domains: ["DOMAIN_RUNTIME"]
  dependencies:
    tickets:
      - ticket_id: "TCK-00543"
        reason: "Receipt merge tools help restore."
      - ticket_id: "TCK-00542"
        reason: "Bundle schemas exist."
  scope:
    in_scope:
      - "Implement `apm2 fac backup export <path>`:"
      - "  - exports: receipts, receipt index, admitted policy/economics digests, broker horizons/refs"
      - "  - excludes: target dirs, cargo caches, sccache by default"
      - "Implement `apm2 fac backup import <path>`:"
      - "  - imports into a fresh node with bounded validation"
      - "  - emits receipts for import event"
    out_of_scope:
      - "Encrypting backups (optional future)."
  plan:
    steps:
      - "Define backup manifest."
      - "Implement export/import with signature verification for receipts if enabled."
  definition_of_done:
    evidence_ids: []
    criteria:
      - "A node can be rebuilt with minimal authoritative state and warmed after restore, matching the RFC restore story."
```
---

### TCK-00592 — Explicit cache purge command: `apm2 fac caches nuke` (dangerous) with hard confirmations and receipts

```yaml
ticket_meta:
  schema_version: "2026-01-29"
  template_version: "2026-01-29"
  ticket:
    id: "TCK-00592"
    title: "Explicit cache purge command: `apm2 fac caches nuke` (dangerous) with hard confirmations and receipts"
    status: "OPEN"
  binds:
    prd_id: "PRD-PLACEHOLDER"
    rfc_id: "RFC-0019"
    requirements: []
    evidence_artifacts: []
  custody:
    agent_roles: ["AGENT_IMPLEMENTER"]
    responsibility_domains: ["DOMAIN_RUNTIME", "DOMAIN_SECURITY"]
  dependencies:
    tickets:
      - ticket_id: "TCK-00516"
        reason: "safe_rmtree_v1 used for deletion."
      - ticket_id: "TCK-00524"
        reason: "GC policy exists; nuke is separate."
  scope:
    in_scope:
      - "Add an explicit operator-only command to delete bulky caches:"
      - "  - lane targets"
      - "  - cargo_home"
      - "  - sccache dir (if present)"
      - "  - optional gate cache dirs"
      - "Must require multiple confirmations / `--i-know-what-im-doing` flag."
      - "Must never delete receipts or broker keys."
      - "Must emit a nuke receipt recording what was deleted."
    out_of_scope:
      - "Automated nuking."
  plan:
    steps:
      - "Implement deletion plan with allowed roots."
      - "Add safety prompts and `--json` dry-run."
  definition_of_done:
    evidence_ids: []
    criteria:
      - "Operators can recover disk space deterministically without ad-hoc rm -rf, with audit receipts."
```
---

### TCK-00593 — Schema registry + bounded deserialization enforcement for all new FAC schemas (job/lease/profile/receipts/manifests)

```yaml
ticket_meta:
  schema_version: "2026-01-29"
  template_version: "2026-01-29"
  ticket:
    id: "TCK-00593"
    title: "Schema registry + bounded deserialization enforcement for all new FAC schemas (job/lease/profile/receipts/manifests)"
    status: "OPEN"
  binds:
    prd_id: "PRD-PLACEHOLDER"
    rfc_id: "RFC-0019"
    requirements: []
    evidence_artifacts: []
  custody:
    agent_roles: ["AGENT_IMPLEMENTER"]
    responsibility_domains: ["DOMAIN_SECURITY"]
  dependencies:
    tickets: []
  scope:
    in_scope:
      - "Ensure every new schema in this RFC is implemented with:"
      - "  - stable schema id strings"
      - "  - deny_unknown_fields"
      - "  - bounded read size caps"
      - "  - canonicalization via apm2_core::determinism::canonicalize_json"
      - "Add a central registry list (or tests) preventing accidental schema id drift."
    out_of_scope:
      - "General schema evolution framework beyond FAC."
  plan:
    steps:
      - "Add schema structs and unit tests verifying schema ids."
      - "Add bounded parsing wrappers reused across code."
  definition_of_done:
    evidence_ids: []
    criteria:
      - "No schema is parsed without size bounds and deny_unknown_fields in default mode."
```
