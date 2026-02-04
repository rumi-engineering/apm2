# RFC-0019 — Automated FAC v0: Ingest → Episode → Receipt → Projection (Holarchy protocol v1, multi-cell compatible)

## Status

* **State:** Draft / Sketch
* **Depends on:** RFC-0018, PRD-0009, PRD-0010
* **Assumes landing:** PR #387 (HEF/FAC v0 E2E harness + tool primitives), PR #389 (ListFiles/Search tool handlers)

## Abstract

RFC-0018 and the recent PRs establish **FAC v0 primitives** (ChangeSetBundle, ReviewReceipt, tool handlers, and an E2E harness). However, **automated FAC does not yet exist** as an end-to-end system because the daemon control-plane wiring is incomplete: sessions are not viable (no real RequestTool execution path; PublishEvidence/EmitEvent are not consistently wired to durable stores), workspace apply is stubbed, tool-result hashes are not surfaced into receipts, and projection is present but not integrated into a long-running reducer loop.

RFC-0019 specifies the **remaining integration + operational work** to reach an **automated FAC v0** where:

1. A PR/changeset is ingested into CAS+ledger.
2. A reviewer episode runs with bounded tools over an isolated workspace.
3. Review artifacts are stored durably in CAS and anchored by ledger events.
4. A projection worker posts results to **GitHub** as *output only*.

This RFC treats "FAC v0 automation" as the **first concrete holon** in the wider APM2 holarchy: a bounded, auditable **closed-loop control system** that converts an untrusted external diff into (1) a ledger-anchored, evidence-bearing receipt and (2) an output-only projection. The design must remain **holon-ready**: every artifact produced here must be verifiable and replayable by any supervising holon (or any other cell) without trusting process memory or external platforms.

This RFC explicitly stages **xtask authority reduction** but keeps `xtask` as the orchestrator until the daemon FAC loop is stable.

## Module contract (spine alignment; normative)
This RFC is not "just wiring." It is a **boundary + loop** module in the APM2 spine, and must declare which physics it enforces.

* **Spine role:** Boundary + Loop (episode loop + admission control loop)
* **Laws upheld (minimum):** LAW-01, LAW-02, LAW-03, LAW-05, LAW-06, LAW-07, LAW-09, LAW-10, LAW-11, LAW-12, LAW-15
* **Core invariants (minimum):**
  * TRUTH-AX-01..05 (truth as hash-chained events; projections are overwritable; compaction is monotone)
  * INV-F-13 (bounded views must commit to ledger head + provide selectors)
  * INV-F-14 (constraint precedence: containment > verification > liveness)
  * INV-F-15 (LLMs cannot be sole authority for high-risk promotion)
* **Typed boundary I/O (minimum):**
  * Inputs: `work_id`, `changeset_digest`, `lease_id`, `budgets`, `capability_manifest_hash`, `context_pack_hash`, `stop_condition_hash`
  * Outputs: `receipt_hash`, `ledger_anchor`, `summary_receipt_hash` (+ optional defect IDs)
* **Failure modes are first-class:** missing pins, missing stop-state, tool escape, pack miss, non-determinism → terminal blockage + defect recording

## Design north stars (non-negotiable intent)

These are *not new features*. They are the minimal "physics" that keep recursion + federation stable at civilization scale:

1. **Closed-loop promotion only**: actuation is never promoted without a verifiable receipt.
2. **Boundary discipline**: internal reasoning is ephemeral; only selected outputs cross the boundary as receipts + evidence pointers.
3. **Compression-first**: coordination is via hashes/selectors and verifiable summaries, not transcripts.
4. **Recursion by default**: every holon is both supervisor and subordinate; interfaces must compose without bespoke coupling.
5. **Crash-only recovery**: restart from committed facts; never depend on process memory for truth.

## Non-negotiable constraints (normative)

* **Truth is internal (LAW-03)**: ledger + CAS are the system of record; external systems (GitHub, git remote) are inputs/actuators, not truth.
* **Fail closed (LAW-01, LAW-15)**: no stub allow paths for tool execution, event emission, evidence publication, or temporal stamping. Missing a dependency is an error, not an implicit downgrade.
* **OCAP only (LAW-05)**: capabilities are not discoverable; tool authority enters the episode only via explicit delegation (capability manifest by hash).
* **Stop-order gating is mandatory (LAW-05, LAW-12, LAW-15):** before any actuation (tool execution, evidence publish, event emission, external projection), the kernel MUST verify stop-state. If stop-state is missing or unverifiable: deny (fail-closed).
* **View commitments are mandatory (LAW-03, LAW-09)**: every episode + receipt must bind to a ledger anchor and a pinned "world" (repo/deps/policy/toolchain/model digests). No ambient HEAD / filesystem truth.
* **Idempotent actuation (LAW-11)**: every external side-effect uses a dedupe key and emits an execution/projection receipt; retries are safe by construction.
* **Small messages, big evidence**: inter-holon communication is receipts + selectors; large payloads live in CAS and are referenced by hash.
* **No regression to legacy JSON IPC**: new functionality lands on ProtocolServer tag-based dispatchers and structured protocols (RFC-0017 line).
* **Constraint precedence (normative):** when constraints conflict, apply **Security/Containment > Verification/Correctness > Liveness/Progress**. If containment blocks sufficient context/capabilities, terminate, decompose/escalate, and record a defect/decision.
* **Typed quantities only (LAW-13):** budgets/timeouts/limits MUST be typed quantities (unitful) at the boundary. Never interpret naked integers as "seconds/tokens/bytes" across holons.

### Holonic boundary discipline (normative)

* **Seclusion (HB-01)**: episode internal state (model scratchpad, in-memory logs, transient summaries) is non-durable and MUST be treated as garbage after completion.
* **Commitment filter (HB-02)**: only explicitly selected artifacts may cross the boundary into CAS/ledger; "nice to have" logs are not admissible truth.
* **Crash-only corollary (HB-03)**: if an episode violates invariants (missing pins, missing broker, tool escape attempt, entropy runaway), terminate and restart from last committed checkpoint; do not attempt to "continue on best effort."
* **Interface variety control (HB-05)**: supervisors control **typed signals/contracts** (receipts, selectors, budgets), not internal agent complexity. This RFC must not introduce untyped "chatty" coordination as an interface.

### Channel separation (normative)

Holons MUST communicate using four channels with distinct trust/bandwidth/budgets:

* **Discovery**: low trust, low bandwidth, prune aggressively.
* **Handshake**: audited authority exchange (leases, manifests, identities).
* **Work**: contract-bound execution on WorkID; explicit stop conditions.
* **Evidence**: cryptographic, content-addressed artifacts + anti-entropy ready receipts.

FAC v0 is allowed to *use* discovery minimally, but must be correct if discovery is absent (ZTI direction).

---

## Scope and scaling model

This RFC is a *control-plane integration RFC*, not a "global autonomy" RFC. The deliverable is **FAC v0 automation inside one daemon deployment** ("one cell"). The way we keep this compatible with civilizational scale is by ensuring the *interfaces and artifacts* are federation-ready, while the implementation remains minimal.

### Holarchy protocol v1 (normative): ordered interaction without "chat"

At civilizational scale, holons must coordinate via **small, typed, hash-addressed** messages. Anything else collapses under bandwidth + ambiguity.

FAC v0 is the "leaf holon" archetype. The key is not adding more roles; it is defining the **minimal ordered protocol** that any holon can use to:
1) acquire authority, 2) execute bounded work, 3) emit receipts, 4) replicate facts via anti-entropy.

#### Channel classes (normative)

Holons communicate on four channels with distinct budgets and trust:
* **Discovery**: low trust, low bandwidth, prune aggressively.
* **Handshake**: audited authority exchange (leases, manifests, identities).
* **Work**: contract-bound execution on WorkID; explicit stop conditions.
* **Evidence**: cryptographic artifacts + anti-entropy-ready receipts.

#### PermeabilityReceipt (normative)

Capabilities MUST NOT be discovered; they only enter a holon via explicit delegation events/receipts.
This RFC names that delegation artifact **PermeabilityReceiptV1**:
* binds: `delegator_holon_id`, `delegatee_holon_id`, `work_id`, `lease_id`
* delegates: `capability_manifest_hash`, `context_pack_hash`
* bounds: `budgets`, `stop_condition_hash`, `expiry` (HTF time envelope ref)
* commits: `view_commitment_hash` (or a selector to derive it)
PermeabilityReceiptV1 MUST be stored in CAS and referenced by hash from any episode/receipt that uses its authority.

#### Holon interface contract v1 (what must compose recursively)

Every holon MUST present the same minimal surface:

1. **Inputs**
   * `holon_id` (stable identity)
   * `work_id` (stable)
   * `changeset_digest` (stable)
   * `lease_id` (explicit)
   * `permeability_receipt_hash` (explicit authority entry)
   * `capability_manifest_hash` + `context_pack_hash` (delegated handles)
   * `budgets` (typed quantities) + `stop_condition_hash`
2. **Outputs**
   * `receipt_hash` (CAS)
   * `ledger_anchor` (event hash / seq)
   * `summary_receipt_hash` (lossy but verifiable; zoom-in via selectors)
   * `defect_ids` (optional)
3. **State**
   * no durable hidden state; all durable state is reducible from ledger+CAS

#### Ordered interaction (normative)

The minimal ordered sequence between supervisor → subordinate:
1) **Handshake**: supervisor issues lease + permeability receipt (by hash).
2) **Work**: subordinate runs bounded episode(s) under that receipt.
3) **Commit**: subordinate emits ReviewReceipt/Blocked + summary receipt.
4) **Evidence**: supervisor fetches by hash on demand; anti-entropy replicates facts.

### What this RFC delivers (strict)

* One end-to-end FAC loop per changeset: **ingest -> episode -> receipt -> project**.
* All durable outputs are **verifiable from ledger+CAS** with no reliance on process memory.
* Tool execution is mediated by **capability manifests** and (when enabled) **context firewalling**.

### What this RFC does NOT deliver (explicitly)

* Global scheduling, global consensus, or multi-region HA.
* Cross-repo / cross-org policy governance.
* "Autonomous merging" beyond minimal review/projection semantics.

### Civilizational-scale constraints (design invariants, not work scope)

To support a globally distributed holarchy that can scale toward exabyte evidence volumes without collapsing under coordination overhead, FAC v0 MUST obey:

1. **Compression + addressability over chatty coordination**
   * Holons communicate via **receipts, digests, selectors, and summary receipts**, not by replaying raw evidence.
   * If a downstream holon needs more detail, it "zooms in" by hash via tools—this is auditable, budgeted, and replayable.

2. **Recursion is the default**
   * A "reviewer episode" is a leaf holon that may request refinement or escalate.
   * Supervisory holons (governance, orchestration, adjudication) are strictly above; FAC v0 is not allowed to embed their logic.

3. **Failure is normal**
   * Retries, duplication, and partitions are expected. The only valid response is idempotency + receipts, not locks + hope.

4. **No ambient workspace truth**
   * A workspace is a projection. Every episode must bind to a **View Commitment** (ledger anchor + pinned world + optional workspace delta).

5. **Anti-entropy readiness (LAW-10)**
   * Every durable artifact produced by FAC MUST be content-addressed and retrievable by hash.
   * Every ledger event emitted by FAC MUST be deterministic and replayable.
   * Any non-monotone projection (workspace, GitHub comments/status) MUST be derivable from receipts via a pure reducer and MUST be safe to replay (LAW-11).

6. **Verifiable summaries (LAW-07)**
   * Supervisory holons MUST be able to operate primarily on **summary receipts** plus selectors.
   * Raw transcripts/logs are not a scalable interface; they are evidence retrieved on demand by hash.

7. **Monotone compaction + summarization (TRUTH-AX-05)**
   * Exabyte scale requires compaction/summarization as monotone operations: derived artifacts MUST reference prior history by hash/range and declare derivation method/version and loss profile.
   * Local GC/TTL is non-semantic; auditability must survive compaction via receipts and tombstones.

### Minimal holon-to-holon interface (what scales)

Holons exchange only:

* **IDs and digests**: `work_id`, `changeset_digest`, `artifact_bundle_hash`, `projection_receipt_hash`
* **Delegations**: `capability_manifest_hash`, `context_pack_hash` (or manifest hash)
* **Outcomes**: `ReviewReceiptRecorded`, `ReviewBlockedRecorded`, `DefectRecorded`, `ContextRefinementRequest`

Additionally (for recursion stability), holons MUST exchange:

* **Budgets**: tool_call_budget, token_budget, wall_clock_budget, evidence_budget
* **Stop conditions**: terminal predicates for the loop (pass/fail/needs-input)
* **Summary receipts**: lossy but verifiable "front pages" for exabyte-scale evidence sets

Everything else is retrieved on-demand from CAS/ledger by hash.

---

## Definitions (normative where stated)

* **Holon (BACKGROUND)**: a bounded agent/service with explicit inputs/outputs and bounded authority (leases/budgets), capable of producing evidence-bearing receipts.
* **Cell (NORMATIVE for this RFC)**: one daemon deployment boundary that owns a local ledger+CAS instance and runs the FAC control loop. Cells may later replicate facts via anti-entropy, but that is out-of-scope here.
* **Truth plane (NORMATIVE)**: ledger + CAS. Only truth-plane artifacts may drive admission/projection decisions.
* **Pulse plane (EXPLANATORY)**: derived wakeups (HEF pulses) that hint "something changed" but are never authoritative.
* **ChangeSetBundleV1 (NORMATIVE)**: the canonical diff/manifest stored in CAS and anchored by `ChangeSetPublished`.
* **Reviewer episode (NORMATIVE)**: a bounded tool-using execution with explicit capabilities + context pack and explicit stop conditions.
* **ReviewArtifactBundleV1 (NORMATIVE)**: CAS bundle containing review output + tool result references + view commitment material.
* **View Commitment (NORMATIVE)**: a compact header binding an episode/receipt to (ledger anchor + pinned world + selectors) so any other holon can verify and replay.
* **PermeabilityReceiptV1 (NORMATIVE)**: explicit authority delegation artifact that introduces capability/context/budget handles into a holon without discovery.
* **ToolExecutionReceipt (NORMATIVE)**: signed receipt proving a tool call occurred, binding args/result hashes + policy/time envelope under the episode envelope.
* **ToolLogIndexV1 (NORMATIVE)**: a canonical, chunkable index (Merkle-friendly) of ToolExecutionReceipt hashes for an episode.
* **SummaryReceipt (NORMATIVE)**: a compact lossy artifact that declares loss profile and provides selectors to zoom into evidence by hash.

---

## Current state (post PR #387 + PR #389)

### What is in place (usable primitives)

* FAC v0 artifact schemas and canonicalization exist (ChangeSetBundleV1, ReviewArtifactBundleV1, ReviewReceiptRecorded).
* E2E harness exists (PR #387 added `crates/apm2-daemon/tests/hef_fac_v0_e2e.rs`), demonstrating the intended ledger→receipt flow at test level.
* Reviewer navigation tools **ListFiles** and **Search** handlers exist post-PR #389 (see handlers below).
* Projection adapter primitives exist (write-only projection + projection receipts), but no long-running reducer wiring.
* Tool broker + context firewall primitives exist, but are not consistently initialized from sealed context packs.

### What is **not** in place (blocking automation)

1. **Session dispatcher is not wired to the real stores/broker**:

   * `DispatcherState::with_persistence` constructs `SessionDispatcher` without CAS, ledger, clock, or broker.
     Evidence (repo snapshot): `crates/apm2-daemon/src/state.rs:349-352`
2. **Session RequestTool still has a legacy “allow” fallback path**, and because broker is not configured, that path is the *effective* behavior:

   * `SessionDispatcher::handle_request_tool` explicitly returns ALLOW based on the manifest allowlist when no broker is present.
     Evidence (repo snapshot): `crates/apm2-daemon/src/protocol/session_dispatch.rs:967-997` and `1016-1029`
3. **SpawnEpisode produces an empty capability allowlist** (fail-closed), meaning even the “allow-by-manifest” path denies everything:

   * `CapabilityManifest` is created with an empty allowlist; comment calls out this is a stub.
     Evidence (repo snapshot): `crates/apm2-daemon/src/protocol/dispatch.rs:2911-2920`
4. **Workspace apply is stubbed**:

   * `apply_changeset` is a placeholder, and snapshot operations are TODO.
     Evidence (repo snapshot): `crates/apm2-daemon/src/episode/workspace.rs:691-766`
5. **Tool results are stored to CAS, but the CAS hash is not surfaced for receipts/tool events**:

   * `ToolExecutor::execute` stores `ToolResultData` in CAS and obtains `result_hash`, but does not return it or aggregate it for ReviewArtifactBundle tool logs.
     Evidence (repo snapshot): `crates/apm2-daemon/src/episode/executor.rs:481-512`
6. **ToolExecutionReceipt framework exists but is not used by FAC runtime**:

   * `crates/apm2-daemon/src/evidence/receipt.rs` + `receipt_builder.rs` define signed tool receipts per AD-RECEIPT-001, but ToolExecutor does not emit them.
7. **Episode runtime does not persist enough ledger events to support HEF topics (episode lifecycle + tool events)**:

   * It buffers events in memory and explicitly states it should stream to ledger in production.
     Evidence (repo snapshot): `crates/apm2-daemon/src/episode/runtime.rs:1162-1209`
8. **Projection is present but not integrated as an idempotent long-running reducer**:

   * Module comment: “not wired into main daemon.”
     Evidence: `crates/apm2-daemon/src/projection/mod.rs:3-12`【crates/apm2-daemon/src/projection/mod.rs:3-12】
9. **ListFiles/Search handlers default root is `"."`**:

   * This is acceptable only if the executor is rooted per-episode; otherwise it is unsafe/incorrect for isolated workspaces.
     Evidence (repo snapshot): `crates/apm2-daemon/src/episode/handlers.rs:1441-1460` and `1753-1768`

---

## Goals

### G0 — Automated FAC v0 (the deliverable of this RFC)

For each ingested changeset:

1. **Ingest** diff + ChangeSetBundle into CAS.
2. **Anchor** ChangeSetPublished (and work association events) into ledger.
3. **Run** one reviewer episode in an isolated workspace with bounded tools.
4. **Store** review artifacts + tool logs in CAS.
5. **Anchor** ReviewReceiptRecorded event in ledger.
6. **Project** the result to GitHub (status + comment) based purely on ledger+CAS.

### G0.1 — Holon-ready receipts (federation-ready without federation work)

For every review outcome (success or blocked), store enough structured material in CAS to allow *any other holon* to verify:

* the exact pinned world (View Commitment)
* the exact tool I/O (tool result hashes + time envelopes when available)
* the exact decision boundary (capability manifest hash + context pack hash)

### G1 — Stage authority reduction of xtask

* `xtask` remains the orchestrator initially.
* `xtask` writes to GitHub only when explicit “allow writes” gates are present, and we progressively shift writes to projection worker.

Evidence we already have guardrails in xtask: `xtask/src/util.rs:287-330` (strict mode and explicit allow flags).【xtask/src/util.rs:287-330】

## Non-goals (for RFC-0019)

* Full merge automation (MergeReceipt, auto-merge) beyond a minimal “review gate + projection”.
* Production-grade distributed scheduling.
* Replacing all legacy codepaths in one sweep (we cut over incrementally).

---

## Architecture overview

### FAC v0 as a holonic control loop (ordered interaction)

This RFC implements one closed loop with a strict truth substrate:

1. **Ingress (adapter)**: external diff -> CAS artifact -> `ChangeSetPublished`
2. **Episode (contained execution)**: bounded tools + rooted workspace -> CAS tool results
3. **Receipt (truth-plane commit)**: `ReviewArtifactBundleV1` -> `ReviewReceiptRecorded` / `ReviewBlockedRecorded`
4. **Projection (output-only reducer)**: ledger->GitHub write -> ProjectionReceipt (CAS) -> optional ledger anchor

At larger scales, this loop recurses: supervisory holons decide *which* episodes to run and *how* to decompose work, but the leaf execution and its receipts follow the same pattern.

### FAC admission state machine v0 (normative ordering)

FAC v0 MUST implement the following ordered transitions. Each transition is driven by truth-plane events and produces a durable receipt or a durable blockage:

1. **INGESTED**
   * CAS: `diff_bytes` stored → `diff_hash`
   * CAS: `ChangeSetBundleV1` stored → `bundle_hash`
   * Ledger: `ChangeSetPublished(changeset_digest, bundle_hash, time_envelope_ref)`

2. **POLICY_BOUND**
   * Ledger: `PolicyResolvedForChangeSet(work_id, changeset_digest, risk/determinism/rcp/verifier hashes, ...)`
   * (Out-of-scope in this RFC: governance semantics; in-scope: FAC refuses to proceed without a valid binding)

3. **AUTHORITY_BOUND** (new; normative)
   * Preconditions:
     * valid `LeaseIssued` exists for `work_id`
     * valid `PermeabilityReceiptV1` exists in CAS and is referenced by hash
     * `capability_manifest_hash`, `context_pack_hash`, `budgets`, `stop_condition_hash` are bound by that receipt
   * Stop gating (mandatory):
     * kernel verifies stop-state prior to continuing; deny if unverifiable
   * Any failure → durable `ReviewBlockedRecorded(reason=LEASE_MISSING|DELEGATION_MISSING|STOP_STATE_MISSING, ...)`

4. **WORKSPACE_READY**
   * Projection: workspace materialized from pinned base + diff_hash
   * CAS: `ViewCommitment` stored → `view_commitment_hash`
   * Any failure → durable `ReviewBlockedRecorded(reason=APPLY_FAILED|PIN_MISSING|ESCAPE_ATTEMPT, ...)`

5. **EPISODE_EXECUTED**
   * Ledger: episode lifecycle + tool events streamed during execution (HEF-ready)
   * CAS: each tool result stored; tool-log index stored (hash-first)
   * CAS: ToolExecutionReceipt stored for each tool actuation
   * Stop gating is checked before each tool actuation (deny if unverifiable)

6. **RECEIPT_RECORDED**
   * CAS: review artifacts bundle stored (includes bindings + tool log index)
   * Ledger: `ReviewReceiptRecorded(changeset_digest, artifact_bundle_hash, time_envelope_ref, ...)`
   * CAS: `ReviewSummaryReceiptV1` stored and referenced by hash from artifacts

7. **PROJECTED**
   * Reducer derives GitHub writes (status/comment) from ledger+CAS
   * CAS: projection receipt stored (dedupe key + request/response hashes)
   * Optional Ledger: `ProjectionReceiptRecorded(...)` (recommended)
   * Stop gating is checked before any external write (deny if unverifiable)

**Idempotency rule (normative):** every transition MUST be replay-safe. If the daemon restarts, replaying ledger events MUST converge to the same projected state without duplicate external side-effects.

### Key components to implement/integrate

1. **FAC Ingress (adapter)**

   * Accepts a PR/patch/diff as untrusted input.
   * Stores diff bytes in CAS (producing `diff_hash`).
   * Constructs `ChangeSetBundleV1` referencing that diff hash.
   * Stores ChangeSetBundle bytes in CAS.
   * Appends `KernelEvent(ChangeSetPublished)` to ledger.

2. **Workspace Manager (sandbox)**

   * Materializes an isolated workspace for `(repo, base_commit_sha, diff_hash)`.
   * Applies the patch safely.
   * Produces a view commitment + optional workspace delta.
   * Provides a workspace root to tool execution (rooting tool handlers).

3. **Episode Runner (review holon)**

   * Spawns a reviewer “runtime” (or adapter) and mediates tool calls.
   * Tool requests:

     * Evaluated against capability manifests/policy.
     * Mediated by a (sealed) context pack firewall.
     * Executed inside the kernel (no client-side exec).
     * Results stored to CAS; CAS hashes collected.

4. **Review Receipt Builder (truth-plane commit)**

   * Stores:

     * Review body artifact
     * Tool logs (hashes of ToolResultData or ToolLog bundle)
     * ReviewArtifactBundleV1
   * Appends `KernelEvent(ReviewReceiptRecorded)` to ledger.

5. **Projection Worker (reducer)**

   * Watches ledger head.
   * Optionally subscribes to HEF pulses to reduce latency.
   * Derives projection operations (status + comment) from internal receipts.
   * Writes to GitHub.
   * Stores a projection receipt (durable, idempotent) to prevent duplication and detect tamper.

---

## Required changes and workstreams

### Workstream A — Make sessions viable (no stub paths)

**Problem:** The session plane is currently not viable for FAC automation: it lacks CAS/ledger/broker wiring, and still has legacy allow behavior. Evidence: state wiring【crates/apm2-daemon/src/state.rs:309-331】 and fallback allow path【crates/apm2-daemon/src/protocol/session_dispatch.rs:956-1059】.

**Deliverables:**

* SessionDispatcher must be constructed with:

  * CAS access (with allowlist enforcement)
  * Ledger append (kernel events)
  * Clock
  * ToolBroker (executing tools, not just deciding)
* Remove or gate the legacy allow path:

  * In production mode: **deny if broker absent**.

**Acceptance criteria:**

* `RequestTool` causes actual execution and returns a result (or returns a request_id that is then executed kernel-side; but the “result must be kernel-produced, CAS-backed”).
* `PublishEvidence` stores to CAS and returns hash.
* `EmitEvent` appends canonical kernel event bytes to ledger.

**Notes (modes used):**

* 40 mechanistic: traced the wiring chain from `state.rs` → `session_dispatch.rs`.
* 6 constraint-sat: fail-closed and “kernel executes tools” constraints.
* 79 adversarial: legacy allow path is a bypass surface.
* 70 eng design: minimal change set to close TCK-00290.

### Workstream B — Capability manifests must be real (delegation by hash)

**Problem:** SpawnEpisode currently installs an empty allowlist stub【crates/apm2-daemon/src/protocol/dispatch.rs:2916-2926】, meaning the system cannot progress beyond “deny all”.

**Deliverables:**

* Define role-based capability manifests for at least:

  * reviewer v0
  * implementor v0 (optional for this RFC)
* Store capability manifests as CAS artifacts (hash-addressed), and have SpawnEpisode load and register them.
* Policy resolution should decide which manifest hash is assigned to the session.

**Acceptance criteria:**

* Reviewer session can request:

  * GitOperation (read-only operations)
  * ArtifactFetch
  * ListFiles
  * Search
  * (Optional) ReadFile
    with deterministic allowlist behavior.

**Modes:** 6 (constraints), 70 (design), 79 (bypass prevention).

### Workstream C — Workspace apply and isolation (no ambient roots)

**Problem:** workspace apply is stubbed【crates/apm2-daemon/src/episode/workspace.rs:683-707】, so tool navigation/search occurs on the wrong filesystem state.

**Deliverables:**

* Implement `WorkspaceManager::apply_changeset`:

  * Create workspace dir per session (or per changeset+session).
  * Checkout base commit from local mirror.
  * Apply patch bytes safely (validate paths; no outside-root writes).
  * Record failure as `KernelEvent(ReviewBlockedRecorded)` with appropriate reason.
* Ensure tool handlers are rooted to workspace, not daemon CWD:

  * Amend handlers (including PR #389 ones) to be instantiated with the workspace root.

**Acceptance criteria:**

* After apply, ListFiles/Search reflect patched workspace.
* Path traversal is impossible (symlink escapes blocked; canonical root checks).
* A failed apply does not crash; it yields a durable “blocked” event.

**Modes:** 40 (mechanistic: tool root), 79 (escape vectors), 70 (design).

### Workstream D — Tool log capture into review artifacts (hash-first)

**Problem:** Tool execution stores results to CAS but does not surface/store hashes for receipts【crates/apm2-daemon/src/episode/executor.rs:458-501】. ReviewArtifactBundle expects `tool_log_hashes`【crates/apm2-daemon/src/episode/workspace.rs:480-515】.

**Deliverables (normative):**
1. **ToolResultData remains per-call** and is stored in CAS (one hash per tool execution).
2. For every tool execution, the kernel MUST also generate a **ToolExecutionReceipt** (signed) that binds:
   * `episode_envelope_hash` (or equivalent)
   * `policy_hash`
   * `request_id`, `capability_id`
   * `args_hash`, `result_hash`
   * `time_envelope_ref` + duration
   This receipt is stored in CAS and referenced by hash from the episode log.
3. Define and store a **ToolLogIndexV1** CAS artifact per episode:
   * canonical ordering (sorted by tool sequence number; ties broken deterministically)
   * list of ToolExecutionReceipt hashes (not raw blobs)
   * bounded metadata (episode_id, counts, budget consumption)
   * chunking support (multi-part index) to support exabyte logs without changing the interface
4. Ensure review artifacts reference **tool_log_index_hash** (single pointer), not an unstructured list.
5. Generate a **ReviewSummaryReceiptV1**:
   * verdict + top findings + loss profile + selectors to evidence
   * intended to be the primary inter-holon artifact at scale

**Acceptance criteria:**

* Review receipt references a review artifact bundle that references `tool_log_index_hash`.
* ToolLogIndexV1 resolves and every referenced ToolExecutionReceipt resolves in CAS.
* Every ToolExecutionReceipt resolves and binds to args/result hashes that resolve in CAS.
* A verifier can replay the episode's tool I/O deterministically without reading daemon filesystem state.

**Modes:** 6 (invariant: receipts must be replayable), 40 (call chain), 70 (design).

### Workstream E — Persist episode/tool lifecycle events to ledger (HEF-ready)

**Problem:** EpisodeRuntime buffers events and notes it should stream to ledger in production【crates/apm2-daemon/src/episode/runtime.rs:1192-1211】.

**Deliverables:**

* Provide an episode event sink that appends to the kernel ledger as the episode runs (episode lifecycle + tool requested/decided/executed) so reducers can be driven by ledger cursors with pulse wakeups.
* Ensure the receipt event is appended atomically at episode completion.

**Acceptance criteria:**

* Episode event stream survives daemon restart (ledger-backed).
* ReviewReceiptRecorded always appears after its referenced CAS artifacts exist.

**Modes:** 70 (design), 6 (ordering constraints), 79 (consistency).

### Workstream F — Projection worker wiring (GitHub output-only, idempotent reducer)

**Problem:** Projection code exists but “not wired”【crates/apm2-daemon/src/projection/mod.rs:3-12】.

**Deliverables:**

* Implement a long-running projection task inside daemon:

  * Reads ledger commits (tailer).
  * Builds a work index:

    * changeset_digest → work_id (from ChangeSetPublished)
    * work_id → PR metadata (from WorkPrAssociated or config)
  * On ReviewReceiptRecorded:

    * Fetch review artifacts from CAS.
    * Apply projection via GitHub adapter.
    * Store a projection receipt (durable) and anchor it (see next).
* Define a kernel event for projection receipts, or re-use existing event class:

  * **Recommended:** add `ProjectionReceiptRecorded` event type referencing CAS hash of a projection receipt bundle.

**Acceptance criteria:**

* Running projection worker results in GitHub status + comment that matches internal review receipt.
* Projection is idempotent (restarts don’t duplicate comments).
* Projection can detect tamper (optional v0.1).

**Modes:** 70 (design), 6 (truth boundary), 79 (tamper + idempotency).

### Workstream G — xtask authority reduction staging

**Current:** xtask already has explicit guardrails for status writes【xtask/src/util.rs:287-330】.

**Deliverables:**

* Add xtask mode to “emit internal receipts + request projection” instead of direct GitHub writes.
* Stage the cutover:

  1. xtask does both (write + projection receipts) under explicit flags.
  2. xtask stops writes by default; projection worker writes.
  3. xtask write path removed or restricted to local/dev.

**Acceptance criteria:**

* No GitHub write occurs without explicit allow flags.
* FAC projection receipts are durable and independently auditable.

**Modes:** 6 (safety constraints), 70 (rollout plan), 79 (bypass via env flags).

### Workstream H — ViewCommitment + ContextPack binding (holon-ready receipts)

**Problem:** Review outcomes do not yet bind to a verifiable View Commitment and sealed ContextPack **in a way that is self-contained and replayable across holons/cells**.

Today, `ReviewReceiptRecorded` binds only:
* `changeset_digest`
* `artifact_bundle_hash`
* `time_envelope_ref`

and `ReviewArtifactBundleV1` binds only:
* `review_text_hash`
* `tool_log_hashes`
* `time_envelope_ref`

That is insufficient for holon-ready replay because it does not bind the episode to:
* a `ViewCommitment` (ledger anchor + pinned world)
* a `capability_manifest_hash` (delegated authority)
* a `context_pack_hash` (bounded read surface / firewall)

This RFC must close that binding gap.

**Deliverables (minimal, v0-compatible):**
1. Define `ReviewArtifactBundleV2` (or `ReviewArtifactBundleV1` + required binding sub-artifact) that includes:
   * `view_commitment_hash`
   * `capability_manifest_hash`
   * `context_pack_hash`
   * `policy_resolved_ref` (or equivalent stable binding)
   * `tool_log_index_hash` (see Workstream D update below)
2. Store the View Commitment as a CAS artifact using the glossary schema (`apm2.view_commitment.v1`) and reference it by hash.
3. Initialize the broker context firewall from `context_pack_hash` (fail-closed if missing/unsealable).

**Acceptance criteria:**

* Review artifacts include explicit bindings (view_commitment_hash, capability_manifest_hash, context_pack_hash).
* A verifier can replay/verify from CAS+ledger without trusting local disk state or process memory.
* Missing bindings are a hard failure resulting in `ReviewBlockedRecorded` (not "best effort").

**Modes:** 6 (invariants), 70 (design), 79 (context poisoning).

---

## Milestones

### M1 — Control plane viability (sessions + broker + durable evidence)

* Close TCK-00290 in practice:

  * SessionDispatcher wired to CAS/ledger/broker/clock.
  * Remove legacy allow path in production.
  * PublishEvidence + EmitEvent real.
* Implement reviewer capability manifest.

### M2 — Workspace apply + rooted tools (no ambient roots)

* Implement changeset apply + isolated workspace.
* Amend tool handlers (including PR #389) to be per-workspace rooted.

### M3 — Holon-ready receipts (tool hashes + view commitment + context pack refs)

* Capture tool logs as CAS artifacts (hashes surfaced).
* Store review body + bundle + view commitment + context pack refs; emit ReviewReceiptRecorded.

### M4 — Projection v0 (idempotent reducer loop)

* Wire projection worker in daemon.
* Minimal GitHub projection: status + single comment.
* Durable projection receipts + idempotency.

### M5 — xtask demotion step

* Default xtask path no longer writes GitHub; it triggers ingestion + waits for projection.

---

## Ticket decomposition (new deltas after PR #387/#389)

> numbering starts after TCK-00315.

### TCK-00316 — Session dispatcher viability closure

* **Implements:** the missing wiring shown in `state.rs` and removes legacy allow behavior.
* **Depends on:** TCK-00290, plus CAS/ledger instantiation in state.
* **DoD:** session tool execution is kernel-side and CAS-backed.

### TCK-00317 — Reviewer capability manifest (real allowlist)

* Replace empty allowlist stub with reviewer v0 manifest.
* Store manifest bytes in CAS; SpawnEpisode loads by hash.

### TCK-00318 — Workspace apply implementation (safe patch apply)

* Implement `apply_changeset` and emit ReviewBlockedRecorded on failure.

### TCK-00319 — Root tool handlers per workspace

* Amend PR #389 work (and GitOperation) so handler roots are workspace roots (not `"."`).
* This is likely the “amendment” you want before merging, because otherwise tools aren’t correct for isolated FAC runs.【crates/apm2-daemon/src/episode/handlers.rs:1461-1466】

### TCK-00320 — Tool result hash propagation (ToolExecutor -> artifacts/events)

* Surface CAS hashes from ToolExecutor, accumulate per episode, and propagate into artifacts/events (ReviewArtifactBundle + tool lifecycle events).

### TCK-00321 — Episode/tool lifecycle event sink to ledger (HEF-ready)

* Replace in-memory buffering with ledger-backed streaming. Evidence of current buffering behavior【crates/apm2-daemon/src/episode/runtime.rs:1192-1211】.

### TCK-00322 — Projection worker (daemon integration)

* Wire projection module; build work index; implement durable receipt store.

### TCK-00323 — ProjectionReceiptRecorded kernel event (optional but recommended)

* Add event schema + canonicalization + topic derivation.
* Enables tamper detection and strong idempotency.

### TCK-00324 — xtask cutover stage 1

* xtask runs ingestion + waits for projection; direct GitHub writes only under explicit override.

### TCK-00325 — ViewCommitment capture + embedding in ReviewArtifactBundleV1

* Capture View Commitment material during episode execution and embed it in ReviewArtifactBundleV1.
* Ensure receipt verification can reconstruct the pinned world without ambient filesystem state.

### TCK-00326 — ContextPack sealing + broker firewall initialization (end-to-end)

* Seal ContextPacks as CAS artifacts and reference them by hash.
* Initialize broker context firewall from the sealed ContextPack for every episode.

---

## Operational risks & mitigations

1. **Authority bypass risk**
   - Mitigation: remove/gate legacy allow path; broker required in prod; OCAP-only manifests by hash; fail-closed if broker/cas/ledger/clock missing.

2. **Workspace escape / ambient root risk**
   - Mitigation: strict path validation + canonical root containment; handlers must be rooted to workspace; view commitment must bind pinned base + delta.

3. **Receipt integrity / replay risk**
   - Mitigation: propagate CAS hashes for all tool I/O; bundle must include view commitment + manifest hashes; ledger anchors bind digests to CAS hashes.

4. **Projection duplication / side-effect replay risk**
   - Mitigation: durable projection receipts + idempotency keys; reducer uses ledger cursor + dedupe key, never external reads as truth.

5. **Context poisoning / prompt injection via diffs and logs**
   - Mitigation: treat all tool outputs and diffs as adversarial; enforce context firewall; require bounded views (ContextPacks) and structured tool APIs; record evidence hashes and require zoom-in for gates.

6. **Exabyte evidence growth / DoS risk**
   - Mitigation: hard artifact size ceilings in v0; store only hashes in receipts; add chunking/container formats later (out-of-scope) while keeping the receipt interface stable.

7. **Non-stationarity / drift risk (deps, tools, models)**
   - Mitigation: view commitments pin toolchain/model/policy digests; if pins unavailable, fail-closed for high-risk tiers; record drift as defects.

---

## Research alignment (informative, non-normative)

### Agent runtime architecture for FAC reviewer episodes (informative)

This RFC intentionally rejects "chatty multi-agent orchestration" as a scaling strategy. Frontier results repeatedly show that **tool/interface design + verification discipline** dominate gains, not number of agents.

#### 1) Compiled multi-role, not conversational multi-agent

If you want Planner/Reviewer/Verifier "roles," they must compile down to:
* a single bounded episode plan (non-durable)
* tool actuation receipts + evidence pointers (durable)
* a SummaryReceipt with declared loss profile (durable)
No inter-role chat logs cross holon boundaries.

#### 2) ACI-first tool design is the agent's main lever

Structure tools as the "agent-computer interface" and keep them narrow and typed; prefer read-only repo tools to shells.

#### 3) Verifiable tool use and hazard-aware control

Frontier work on safe agent tool use emphasizes:
* explicit system-level hazard analysis (e.g., STPA-style) for tool sequences
* information-flow controls and sandboxing
* "proof-carrying" tool outputs (receipts binding inputs/outputs)
FAC v0 adopts the proof-carrying direction via ToolExecutionReceipt + ViewCommitment bindings.

#### 4) Termination discipline as a first-class contract

Budget exhaustion, repeated denials, repeated pack misses, or repeated tool failures are not "try harder" moments; they are terminal conditions that yield Blocked + defect signals.

### Evaluation and telemetry (informative, but required to be measurable)

To prevent Goodharting on "PRs merged," FAC v0 SHOULD measure:
* pack_miss_rate (ContextPackMiss / episode)
* unplanned_context_discovery_calls (ZTI gap)
* tool_denial_rate (capability/policy denials)
* receipt_completeness_rate (missing bindings should be 0 in prod)
* projection_duplication_rate (idempotency failures)
* verifier_disagreement_rate (nondeterminism envelope punctures)

### Selected references (informative)

* Safe/verifiable tool use for LLM agents (hazard analysis + info-flow controls).
* Agent architecture taxonomies (coordination topologies; why mesh is expensive).
* Agent evaluation surveys (benchmarking beyond "success rate": cost, robustness, safety).

### Workstream I — Agent Adapter Profiles (Required for Real‑World CLIs)

[IMPORTANT SECTION] -- ADAPTERS HAVE NOT YET BEEN ADDRESSED IN THE ABOVE RFC BUT **MUST** BE INCLUDED IN THE PLAN FOR A FULLY AUTONOMOUS FORGE ADMISSION CYCLE.

**Problem:** FAC v0 assumes a “reviewer runtime (or adapter)” but does not define a concrete, reproducible integration contract for third‑party agent CLIs (Claude Code, Gemini, Codex) or local inference. Without an explicit adapter profile system, FAC v0 cannot be executed out‑of‑the‑box across heterogeneous agents, and the kernel lacks deterministic control over tool execution, evidence capture, and policy enforcement.

**Deliverables (normative):**
1. Define `AgentAdapterProfileV1` (schema + canonicalization) as a CAS‑addressed artifact.
2. Provide profiles for `claude-code`, `gemini-cli`, `codex-cli`, and `local-inference` (minimum).
3. Implement AdapterRegistry selection by profile hash, not by ambient defaults.
4. Enforce **kernel‑side tool execution** for every profile. Agent outputs are untrusted hints; the ledger is authoritative.
5. Emit ledger events that attribute agent execution by `(work_id, episode_id, session_id, adapter_profile_hash)`.
6. Add conformance tests proving each profile can run a non‑interactive episode and produce a receipt.

**AgentAdapterProfileV1 fields (normative):**
- `profile_id` (stable string)
- `adapter_mode` (`black_box`, `structured_output`, `mcp_bridge`, or `hooked_vendor`)
- `command`
- `args_template`
- `env_template`
- `cwd`
- `requires_pty` (bool)
- `input_mode` (`arg`, `stdin`, `file`, `stream-json`)
- `output_mode` (`raw`, `json`, `jsonl`, `stream-json`)
- `permission_mode_map` (maps local policy tiers to CLI flags)
- `tool_bridge` (see options below)
- `capability_map` (external tool names or intents -> kernel tool classes)
- `version_probe` (command + regex)
- `health_checks` (timeouts, stall thresholds)
- `budget_defaults` (tool_calls, tokens, wall_clock, evidence)
- `evidence_policy` (what is recorded vs discarded)

**Options for tool bridging (choose one per profile; mixing allowed across profiles):**

**Option A — MCP Bridge (complex, not preferred)**
- Kernel exposes an MCP server and publishes tool schemas.
- Agent CLI connects via MCP configuration (per‑agent install/config is required).
- Tool calls are received via MCP; kernel executes tools and returns results.
- Ledger events record `ToolRequested`, `ToolDecided`, `ToolExecuted` with CAS hashes.
- Risks: high configuration complexity, fragile install paths, schema sanitization drift, and MCP client behavior differences. This option is allowed but not recommended unless a target agent provides first‑class MCP with stable UX.

**Option B — Structured Output Parsing (JSONL / stream‑json)**
- Agent CLI runs in a deterministic output mode (JSONL or stream‑json).
- Adapter parses structured tool‑request events from stdout.
- Kernel validates and executes tool calls; results are injected back to the agent via stdin or prompt continuation.
- Ledger remains authoritative; structured output is treated as untrusted hints.
- Risks: output‑format drift, vendor version fragility, and tool call parsing failures. Requires strict rate limiting and fail‑closed behavior.

**Option C — Black‑Box Ledger‑Mediated Driver (preferred)**
- Agent runs with native tools disabled or restricted to read‑only, and is treated as an untrusted black box.
- The adapter establishes a minimal, stable **ToolIntent grammar** embedded in the system prompt (not JSONL). Example: a single‑line, delimiter‑framed tool request format with bounded size.
- The kernel only acts on ToolIntents that pass schema validation and capability checks; all actual tool execution is kernel‑side.
- Tool results are injected back into the agent as context; the ledger records every tool lifecycle event and CAS hash.
- This preserves holonic boundary discipline: the ledger is the sole authority for tool execution, not the agent’s internal protocol.
- Works across Claude Code, Gemini CLI, Codex, and local inference with minimal vendor‑specific parsing.

**Acceptance criteria:**
- Each of the three target CLIs can run a non‑interactive episode under a profile and produce a ReviewReceipt.
- No tool execution occurs without kernel‑side policy evaluation and ledger events.
- Profile selection is explicit and hash‑addressed; ambient defaults are forbidden.
- Misconfigured profiles fail closed with `ReviewBlockedRecorded(reason=ADAPTER_MISCONFIGURED)`.

**Notes:**
- Option C is the default path for FAC v0. Options A and B are permitted only when they do not violate holonic boundary discipline and when they reduce total risk for a specific agent.

