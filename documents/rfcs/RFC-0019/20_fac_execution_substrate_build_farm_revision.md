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
6. **No ambient user state reliance.** FAC MUST NOT depend on aliases/dotfiles/`~/.cargo/config.toml`/`~/.config/gh` or other user-scoped mutable config; FAC MUST set policy explicitly (including `HOME`, `XDG_*`, and `CARGO_HOME`) for any bounded execution.
7. **No new long-lived bash daemons.** Control plane MUST be Rust and/or systemd-managed units. Bash scripts may exist only as transitional leaf executors.
8. **Brokered actuation is mandatory (RFC-0028).** Any FAC job that executes code (gates/warm/pipeline evidence/GC/reset) MUST be authorized by a **daemon-signed** RFC-0028 `ChannelContextToken` and MUST validate via `apm2_core::channel::decode_channel_context_token` + `validate_channel_boundary` before execution. Jobs lacking a valid token MUST be denied (fail-closed) and quarantined.
9. **RFC-0029 admission is mandatory.** Any job scheduling/admission decision MUST be representable as RFC-0029 and MUST emit an RFC-0029 decision trace (queue admission, and where applicable budget admission). "Local FIFO without trace" is explicitly forbidden in default mode.
10. **Deterministic control-plane availability.** Default-mode FAC commands MUST require a reachable broker and a liveness-observable worker pool. If the broker/worker are unavailable, commands MUST fail fast with actionable diagnostics. Indefinite hangs waiting for a worker are forbidden; waiters MUST have timeouts and MUST consult worker liveness signals.
11. **Secrets posture is explicit.** Credentials required for external I/O MUST be injected via explicit mechanisms (systemd credentials preferred) and MUST NOT be a hidden precondition stored in interactive dotfiles or shell state. Secrets MUST NOT appear in job specs, receipts, logs, or error messages.

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
2. **FAC has a required broker.** In FESv1 the broker MUST be implemented inside `apm2-daemon` (shared signing key + admitted policy roots) and exposed over a dedicated local IPC surface. A separate `apm2-fac-broker` binary/unit is OPTIONAL, but MUST reuse the same on-disk trust roots (no forked signing keys or policy roots). The broker is the authority that:
   * issues RFC-0028 channel context tokens for job actuation,
   * issues RFC-0029 time authority envelopes (TP-EIO29-001),
   * and maintains the admitted policy roots used for RFC-0028 policy binding checks.
   * IPC requirements:
     * The broker IPC surface MUST be a Unix domain socket with filesystem permissions restricting access to the intended service user/group (0600/0660).
     * The broker MUST authenticate peers via OS-level peer credentials (e.g., `SO_PEERCRED`) and MUST fail closed on mismatch.
     * The broker MUST be systemd-managed (Restart=always or socket-activated). Manual/interactive startup as a prerequisite for default-mode FAC is forbidden.
3. **Workers never trust "raw ChannelBoundaryCheck JSON".** A `ChannelBoundaryCheck` is authoritative only if reconstructed by decoding a daemon-signed channel context token (`decode_channel_context_token`). Accepting raw JSON is forbidden.
4. **Quarantine is first-class.** Any job/evidence/cache artifact that fails RFC-0028 or RFC-0029 validation MUST be moved to a quarantine directory and MUST NOT be deleted blindly. Quarantine is how you preserve forensics for A2/A1 events.

## 0.6 Secrets and credentials (normative)

FAC must sometimes perform external I/O (e.g., fetching private git dependencies, posting GitHub statuses/comments, reading PR metadata). These actions require **credentials**, which are distinct from the **authorization** primitives introduced by RFC-0028 and RFC-0029:

* **RFC-0028 ChannelContextToken**: authorizes *what intent is allowed* (typed tool intent), with fail-closed boundary checks.
* **RFC-0029 economics**: authorizes *whether the intent is admissible* under deterministic budgets, lanes, and anti-starvation rules.
* **Credentials**: enable *successful execution* of the allowed intent (e.g., `GH_TOKEN`, SSH keys, GitHub App private key).

FESv1 requirements:

1. **No secrets in specs/receipts.**
   * `FacJobSpecV1`, `FacJobReceiptV1`, lane profiles, and policy objects MUST NOT contain secret material.
   * Any required secret MUST be referenced indirectly (by handle/name) and injected at runtime by the broker/worker execution environment.

2. **Credentials are job-kind scoped and fail-closed without collateral damage.**
   * `gates`, `warm`, `gc`, and lane reset jobs MUST be executable in a **no-secrets** posture.
   * Missing GitHub credentials MUST NOT prevent running local gates; they may only block job kinds that explicitly require GitHub actuation.

3. **No interactive authentication as a hidden precondition.**
   * The execution substrate MUST NOT rely on `gh auth login`, user dotfiles, or other interactive/manual state to succeed.
   * Where GitHub access is required, the substrate MUST support non-interactive credentials injection (e.g., `GH_TOKEN`), under explicit policy control.

4. **Credential injection mechanisms (ordered preference).**
   * **Preferred (system services):** systemd credentials (`LoadCredential=`) delivered via `$CREDENTIALS_DIRECTORY`, then mapped into subprocesses as needed.
   * **Acceptable (local user mode):** a broker-managed credential store (future extension) or explicit operator-managed files under `$APM2_HOME/private/creds/**` with strict permissions (0700 directories, 0600 files).
   * **Forbidden:** plaintext secrets committed in repo, embedded in policy JSON, or present in job specs/receipts.

   * GitHub App credential note: `APM2_GITHUB_APP_ID` and `APM2_GITHUB_INSTALLATION_ID` are non-secret configuration and SHOULD live in `$APM2_HOME/github_app.toml`; the private key MUST be provisioned via an approved secret mechanism (systemd credentials preferred).
   * Reliance on shell-exported `APM2_GITHUB_*` environment variables MUST NOT be a prerequisite for non-GitHub job kinds (e.g., `gates`).

5. **Redaction is mandatory.**
   * Any credential handle, file path, or environment variable carrying secrets MUST be treated as sensitive in logs and receipts.
   * Error messages MUST not echo secret values (even if they originate from environment variables).

This section exists because "it worked in my shell" authentication is a frequent source of flakiness and accidental secret leakage. FESv1 makes credential requirements explicit and mechanically enforced.

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

* **Credential mount**: A policy-level description of how secret material is injected into an execution context at runtime (env var and/or file), referenced by a handle. Credential mounts MUST NOT embed secret values and MUST be job-kind scoped.
* **Service user**: A dedicated Unix user (recommended) under which broker/worker services execute, used to enforce filesystem and IPC ACL boundaries.

* **FAC Broker**: The local authority surface (Rust; systemd-managed; implemented inside `apm2-daemon`) that issues:
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

  * timeout (defaults bounded by `gates.rs` max 600s)
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

  * **Wall-time 600s** (by policy; configurable via --timeout-seconds)
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
* MUST enforce the 600s/24G test policy (no override without explicit unsafe flag)

Default execution mode change (normative):

* `apm2 fac gates` MUST default to **brokered queue execution**:
  * create `FacJobSpecV1(kind="gates")`,
  * obtain an RFC-0028 channel context token from the broker for this job spec digest,
  * enqueue to `queue/pending/`,
  * and wait for completion by default.
  * Waiting MUST be bounded (default `--wait-timeout`; MUST NOT hang indefinitely) and MUST consult broker liveness/queue state; if no worker is live, `apm2 fac gates` MUST fail fast with actionable remediation (start services or run `--direct`).

* `apm2 fac gates --direct` MUST remain available as an explicit unsafe fallback:
  * executes immediately in-process,
  * does **not** read/write gate cache,
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

#### 5.2.8 `apm2 fac services` (new; recommended)

Service-management helpers for non-flaky default-mode operation.

* `apm2 fac services status` MUST report:
  * whether the broker socket is reachable,
  * whether at least one worker is live (liveness signal),
  * and (where applicable) the systemd unit status for the broker/worker/daemon.
* `apm2 fac services ensure` MUST attempt to start (and optionally enable) the broker/worker services, then re-run readiness checks.
  * If automatic start is not possible (e.g., no systemd, insufficient privilege), it MUST print deterministic remediation steps.
* These commands MUST NOT perform any destructive action (no GC, no lane reset).

#### 5.2.9 `apm2 fac bootstrap` (new; recommended)

One-shot provisioning for a compute host.

* MUST create the required `$APM2_HOME/private/fac/**` directory tree with correct permissions and ownership.
* MUST write a minimal default `FacPolicyV1` (safe no-secrets posture) and a stub lane set (or point to an existing one).
* SHOULD offer flags for systemd deployment:
  * `--system` to install/enable system services (broker/worker/daemon) under a dedicated service user,
  * `--user` to install/enable user services for local development.
* MUST run `apm2 fac doctor` and fail with actionable output if the host cannot support FESv1.

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
    "test_timeout_seconds": 600,
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
* `env_allowlist: [string]` (exact variable names; applies only to inherited environment)
* `env_denylist_prefixes: [string]` (e.g., `AWS_`, `GITHUB_`, `SSH_`, `OPENAI_`), applied to inherited env after allowlist to prevent accidental leakage
* `env_set: { key: value }` for enforced **non-secret** variables (policy + computed):
  * `CARGO_HOME=$APM2_HOME/private/fac/cargo_home`
  * `CARGO_TARGET_DIR=$APM2_HOME/private/fac/lanes/<lane_id>/target/<toolchain_fingerprint>`
  * `NEXTEST_TEST_THREADS=<computed>`
  * `CARGO_BUILD_JOBS=<computed>`
* `credential_mounts: [CredentialMountV1]` (OPTIONAL in pure no-secrets profiles; REQUIRED for any job kind that performs authenticated external I/O)
  * Credential mounts are **handles**, not secrets. The secret bytes MUST come from systemd credentials or a broker-managed credential store at runtime.
  * Credential mounts MAY inject secrets as env vars (e.g., `GH_TOKEN`) and/or as files (e.g., `github_app_private_key.pem` under `$CREDENTIALS_DIRECTORY`).
  * `env_denylist_prefixes` MUST NOT block secrets injected via `credential_mounts`; denylists apply to inherited env only.

Execution-order requirement (normative):
* Start from an empty environment if `env_clear_by_default` is true.
* Apply `env_set` (non-secret policy/computed values).
* Import inherited env filtered by `env_allowlist`, then remove any remaining inherited vars matching `env_denylist_prefixes`.
* Apply `credential_mounts` last (secret injection), without serializing secrets into receipts/logs.

If `env_clear_by_default` is true, the worker MUST start with an empty environment and then inject required runtime variables via `env_set` and `env_allowlist` (not inherited implicitly).

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
    "test_timeout_seconds": 600,
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
* add deterministic service management primitives:
  * systemd unit(s) for broker/worker/daemon (and/or socket activation)
  * `apm2 fac services status/ensure` for startup + readiness
  * bounded waiting semantics (no indefinite hangs)

Acceptance criteria:
* three concurrent `apm2 fac gates` invocations never exceed lane count
* target reuse collapses disk usage vs many worktrees (qualitative)
* evidence logs are per-lane/per-job and do not clobber across concurrent runs
* in default mode, workers deny/quarantine any job lacking a valid RFC-0028 token
* in default mode, workers deny any job with RFC-0029 verdict != Allow (except stop_revoke emergency semantics)
* if broker/worker are unavailable, default-mode commands fail fast with actionable remediation (no hangs)
* `apm2 fac gates` does not require GitHub credentials; missing GitHub auth may only block GitHub-specific commands

Rollback:
* `APM2_FAC_LANES=0` (or `--legacy`) runs old path; lane directories remain but are inert

### Phase 2 — Queueing + priority + cancellation + lane reset + enforced GC

Deliverables:
* implement filesystem job queue (`pending/claimed/done/cancelled`)
* implement `apm2 fac enqueue` and `apm2 fac gates --queued`
* implement worker liveness/heartbeat signals surfaced via broker APIs for waiters + `apm2 fac services status`
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
  * provision required credentials via systemd credentials (no interactive `gh auth login`)
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

* any compilation or compilation-adjacent process must remain inside the bounded cgroup to preserve the 24G/600s guarantees.

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

Given the "600s/24G bounded test SLA," we treat warm as:

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

   * after warm, test gate completes within 600s and does not OOM under 24G
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