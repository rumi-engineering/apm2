# RFC: Kernel-Native Forge Admission Cycle vNext

**Unifying Work Object, Work Graph, Work Context, and Implementer/Reviewer Loops onto the Core Ledger + CAS (while preserving `apm2 fac push` as the terminal command through cutover)**

**Status:** Draft (implementation-grade)
**Audience:** APM2 daemon/CLI maintainers, FAC maintainers (`fac_review`), projection/pulse owners, gate/merge owners
**Repo scope:** `crates/apm2-core`, `crates/apm2-daemon`, `crates/apm2-cli`, `proto/*`, `documents/rfcs/*`
**Primary documents referenced (in-repo):**

* `documents/rfcs/RFC-0018/TECHNICAL_PROPOSAL_WORKOBJECT_LEDGER_CUTOVER.md`
* `documents/rfcs/RFC-0019/AUTONOMOUS_FORGE_ADMISSION_CYCLE.md`
  **Key code touchpoints referenced (in-repo):**
* Legacy daemon ledger + registry: `crates/apm2-daemon/src/ledger.rs` (e.g. `work_claims`, `ledger_events`)
* Core ledger read-mode split + legacy compat: `crates/apm2-core/src/ledger/storage.rs` (`determine_read_mode`, `append_verified`)
* Work truth via projections (already moving directionally): `crates/apm2-daemon/src/work/authority.rs`, `crates/apm2-daemon/src/work/projection.rs`
* Operator protocol handlers: `crates/apm2-daemon/src/protocol/dispatch.rs` (notably `handle_claim_work`, `handle_publish_changeset`, `handle_spawn_episode`)
* CAS: `crates/apm2-daemon/src/cas/mod.rs`, `crates/apm2-core/src/evidence/cas.rs`
* Pulse plane scaffolding: `crates/apm2-daemon/src/protocol/pulse_outbox.rs`, `topic_derivation.rs`, `pulse_topic.rs`
* CLI entrypoints: `crates/apm2-cli/src/commands/fac.rs`, `crates/apm2-cli/src/commands/fac_review/push.rs`, `crates/apm2-cli/src/commands/work.rs`
* Evidence categories: `crates/apm2-core/src/evidence/category.rs`

---

## 0. Reader guide: terms, identifiers, and event families

This RFC spans three partially-overlapping "planes" that exist in the repo today: legacy signed JSON
events, reducer-facing dot events, and HEF/pulse typed discriminants. The document is easy to misread
unless we pin down vocabulary and the constraints those planes impose.

### 0.1 Terminology

* **Work**: a state machine instance reduced by `apm2-core` (`crates/apm2-core/src/work/*`).
* **WorkSpec**: immutable, content-addressed "what is this work?" document stored in CAS and
  referenced by `WorkOpened.spec_snapshot_hash`.
* **WorkObject**: a *projection / unified view* of work + graph + context (see RFC-0018), not an
  additional truth source.
* **Work graph**: directed dependency edges between works (this RFC introduces canonical events +
  projections for mutable edges and waivers).
* **Work context stream**: append-only, CAS-backed notes/artifacts anchored in the ledger via
  `evidence.published`.
* **Episode / Session**: runtime execution units spawned via `SpawnEpisode` and tracked via session
  events. Session reduction exists in `crates/apm2-core/src/session/*`.
* **Lease**: daemon-issued capability binding a role+actor to a work. Today it is required for
  spawning episodes (see `handle_spawn_episode` in `crates/apm2-daemon/src/protocol/dispatch.rs`).
* **Projection**: derived SQLite tables/materialized views that are fully replayable from
  (ledger + CAS). These are caches, never authority.

### 0.2 Identifier formats (repo reality today)

The daemon currently generates identifiers as UUIDv4 strings (not timestamps):

* `work_id`: `W-<uuid_v4>` (`generate_work_id` in `crates/apm2-daemon/src/protocol/dispatch.rs`)
* `lease_id`: `L-<uuid_v4>` (`generate_lease_id` in the same module)
* `session_id`: `S-<uuid_v4>` (created in `handle_spawn_episode`)

This RFC keeps these formats through cutover unless a future identity RFC changes them.

### 0.3 Event families and payload encodings

APM2 currently has **three** event "families" that refer to the same semantic facts:

| Family | Example `event_type` | Where it exists today | Payload encoding | Primary consumer |
|---|---|---|---|---|
| Legacy signed (underscore) | `work_claimed`, `session_started`, `changeset_published` | daemon `ledger_events` + WorkRegistry | canonical JSON bytes, Ed25519 signature over `domain_prefix || payload` (`crates/apm2-daemon/src/ledger.rs`) | daemon projections, legacy CLI flows |
| Reducer-domain (dot) | `work.opened`, `work.transitioned`, `session.started`, `evidence.published` | core reducer world | protobuf bytes (`WorkEvent`, `SessionEvent`, `EvidenceEvent`) | `apm2-core` reducers (`work/reducer.rs`, `session/reducer.rs`) |
| HEF/pulse typed | `WorkOpened`, `SessionStarted`, `GateLeaseIssued` | pulse/topic taxonomy + commit notifications | typed discriminant used for topic derivation (RFC-0018 `02_design_decisions.yaml`, `topic_derivation.rs`) | push-based waits, outbox fanout |

Two constraints follow immediately:

* Any new event whose `event_type` starts with **`work.`** is decoded as a `WorkEvent` by
  `WorkReducer` (`crates/apm2-core/src/work/reducer.rs`). Introducing `work.*` types whose payload is
  not a `WorkEvent` will hard-fail reduction (this is a sharp edge in the current code).
* The repo already contains an explicit parity/convergence mapping for work lifecycle facts across
  families (`crates/apm2-core/src/work/parity.rs`). Any bridge window must maintain parity (or
  explicitly declare which family is being retired).

## 1. Problem statement (grounded in current APM2)

APM2 currently has **two ledger planes** plus several “shadow truth” stores that collectively represent FAC reality:

1. **Daemon legacy signed ledger** (`ledger_events` + domain-separated signatures) and **WorkRegistry** tables (`work_claims`, policy resolution JSON, etc.) in `crates/apm2-daemon/src/ledger.rs`.

   * `ClaimWork` in `crates/apm2-daemon/src/protocol/dispatch.rs` **generates a new `work_id`** and persists claim metadata in WorkRegistry (SQLite), plus emits `work_claimed`/`work_transitioned` legacy events.
   * `PublishChangeSet` similarly requires WorkRegistry to authorize and uses registry state not fully reconstructible from legacy event payloads (policy resolution details, adapter profile hash, etc.).

2. **Core ledger** (`events` table + hash chaining + optional BFT wrapper) in `crates/apm2-core/src/ledger/*`.

   * Today, the core ledger is frequently forced into **`LegacyModeReadOnly`** (see `determine_read_mode`), because `ledger_events` exists and the canonical `events` table is empty. This blocks forward progress: you cannot safely “just start writing kernel events” without a unification plan.

3. **FAC v0 (CLI-local) ticket/YAML truth** and `fac_review` orchestrator state:

   * `apm2 fac push` is implemented via `crates/apm2-cli/src/commands/fac_review/push.rs` and still relies heavily on ticket YAML and local projections.

4. **Pulse plane** exists but is **not end-to-end consistent with the actual ledger encoding**:

   * `PulsePublisher` currently decodes `KernelEvent` envelopes in `pulse_outbox.rs`, while most real emitted facts today are legacy signed events and/or protobuf domain events (not the KernelEvent envelope).
   * `topic_derivation.rs` tests currently treat event types like `"WorkOpened"` whereas core reducer naming uses dot prefixes (e.g. `work.opened`) and legacy uses underscores (e.g. `work_claimed`). This mismatch is not merely cosmetic: it blocks “push-based wait” from being reliable.

This fragmentation causes concrete, code-real failures:

* **Implementer lifecycle isn’t closed**: daemon runs `SpawnEpisode` and records `session_started/session_terminated`, but there is no daemon-authoritative loop ensuring that an implementer attempt produces a durable terminal marker (`fac push`) and a handoff note before proceeding.
* **Work dependencies are not first-class**: there is no authoritative, mutable work DAG. At best there are ad-hoc dependency lists (`dependency_work_ids`) in claim requests, or static `parent_work_ids` in `WorkOpened`, but no mutable edges + waivers.
* **Work context isn’t authoritative**: handoff notes, diagnoses, reviewer findings/verdict summaries live in local files or GitHub comments, not in the kernel truth plane (ledger + CAS). Nothing can reliably replay them.
* **Authority state is still split**: WorkRegistry holds security/authority-relevant data (policy resolution, adapter profile hashes, etc.) that is not fully derivable from ledger + CAS.

---

## 2. Goals, non-goals, constraints

### 2.1 Goals

G1. **Single canonical truth plane** for FAC: **Core ledger `events` table + CAS**.
G2. **No SQLite-only authority**: all authority decisions needed for “what happens next” must be reconstructible from **(ledger events + CAS artifacts)** with deterministic projection logic.
G3. **Work graph as first-class**: add/remove dependency edges post-open; enforce closure for claimability; support waivers without mutating history.
G4. **Work context stream as first-class**: append-only, ledger-anchored, CAS-backed, queryable, replayable; supports handoffs, findings, diagnoses, linkouts.
G5. **Closed implementer + reviewer loops** with daemon-governed nudging/reaping; terminal act preserved (`apm2 fac push`).
G6. **Pulse-driven waits**: remove polling as the default “wait” mechanism; `--wait` subscribes to work-centric topics.
G7. **Configurable operational knobs**: workspace roots, retry/nudge/backoff budgets are policy/config driven, not hard-coded in control-plane logic.

### 2.2 Non-goals (this RFC)

NG1. Fully replacing GitHub or `fac_review` internals immediately.
NG2. Requiring mediated tool execution (AdmissionKernel tool bridge) on the critical path. System must work in unmediated mode.
NG3. Designing the final cryptographic actor identity model (hex key ids vs string identities) beyond what is required to make the FAC truth plane reconstructible and operational.

### 2.3 Hard constraints (from repo reality)

C1. **Core ledger is currently often in legacy read-only mode**: any plan that “starts writing kernel events” must include ledger unification.
C2. **`apm2 fac push` remains the terminal command** through cutover; no bypassing.
C3. Daemon is the authority boundary: ledger/CAS mutations go through the daemon operator socket (UDS) unless explicitly delegated later.

---

## 3. Canonical architecture

### 3.1 End state overview

* **Core ledger (`apm2-core`)** stores all authoritative FAC events in the canonical `events` table.
* **CAS (`apm2-daemon DurableCas`, implementing `apm2_core::evidence::ContentAddressedStore`)** stores immutable artifacts (work specs, context entries, evidence bundles, change sets, etc.).
* **Projections** (SQLite tables and/or in-memory reducers) are derived from ledger + CAS and are **replayable**.

### 3.2 Event family convergence plan (legacy signed ↔ reducer-domain ↔ HEF typed)

The repo already models three work-event "families" (see `crates/apm2-core/src/work/parity.rs`):

* **Daemon legacy signed**: underscored `work_claimed`, `work_transitioned`, … (canonical JSON payloads,
  domain-separated signatures).
* **Reducer-domain**: dotted `work.opened`, `work.transitioned`, … (protobuf `WorkEvent` payloads).
* **Typed discriminants**: `WorkOpened`, `WorkTransitioned`, … (used by HEF topic derivation and some
  tests today).

This RFC standardizes on:

* **Authority** = reducer-domain dotted events in the **core `events` table** + CAS artifacts.
* **Compatibility** = legacy underscored events may continue to be *ingested* for a bounded window,
  but they must be deterministically translatable into reducer-domain facts.
* **Push-based waits** = pulse topics must be derivable from either dotted event types *or* typed
  discriminants, and must resolve to the same work-centric topics.

Implementation consequences:

1. **Do not introduce new `work.*` event types unless the payload is a `WorkEvent`.**
   `WorkReducer` decodes any `event_type` beginning with `work.` as a `WorkEvent` and will error if
   decoding fails.
2. **Bridge translations must be explicit.**
   The daemon already does this for work lifecycle (`crates/apm2-daemon/src/work/projection.rs`
   translates legacy signed events into `WorkEvent` payloads). This RFC extends that pattern for
   work graph + work context.
3. **Sunset is per-family, per-event-type.**
   The migration plan must explicitly state when:
   * legacy underscored writers are frozen, and
   * typed discriminants stop being emitted/relied upon (or the topic deriver learns parity).

---

## 4. Data model (CAS documents)

All CAS documents in this RFC are **canonicalized JSON** using `apm2_core::determinism::canonicalize_json` and then hashed via the existing BLAKE3 content hash (same pattern used throughout `DurableCas`).

### 4.1 WorkSpec: `apm2.work_spec.v1` (immutable)

Stored in CAS; referenced by `WorkOpened.spec_snapshot_hash` (bytes).

This RFC **aligns WorkSpec with the existing work cutover proposal (RFC-0018)**: WorkSpec is “what the work is,” not “what attempts happened.”

```json
{
  "schema": "apm2.work_spec.v1",
  "work_id": "work-2026-02-18T12:34:56Z-abcdef",
  "ticket_alias": "TCK-00606",
  "title": "Make fac push emit terminal markers and bind work_id",
  "summary": "Kernel-native FAC push integration; add context markers; wire PR association.",
  "work_type": "forge_admission",
  "repo": {
    "owner": "openai",
    "name": "apm2",
    "remote": "origin",
    "default_branch": "main"
  },
  "touch_set": {
    "paths": ["crates/apm2-cli/", "crates/apm2-daemon/"],
    "labels": ["cli", "daemon", "fac"]
  },
  "requirements": ["REQ-HEF-0013", "REQ-0010"],
  "metadata": {
    "source": "ticket_yaml_import",
    "ticket_path": "documents/work/tickets/TCK-00606.yaml",
    "ticket_sha256": "…"
  }
}
```

**Important correction vs the earlier draft:**
Do **not** require “ticket id becomes `work_id`.” The codebase already has an explicit alias reconciliation design (`apm2_core::events::alias_reconcile`) and even an alias reconciliation gate stub in `handle_spawn_episode`. Use it. Ticket IDs are aliases, not canonical ids.

### 4.2 WorkLoopProfile: `apm2.work_loop_profile.v1` (mutable policy/config knobs)

Stored in CAS; referenced by claim/session dispatch events (see §5, §6). This is operational tuning, **not** privilege escalation.

**Mutability note (important):** CAS is immutable. "Mutable" here means:
publish a new profile document + anchor it in the ledger, and treat "latest anchored profile" as active
in projections. See §6.6 `PublishWorkLoopProfile`.

```json
{
  "schema": "apm2.work_loop_profile.v1",
  "work_id": "…",
  "workspace": {
    "strategy": "git_worktree",
    "root": "~/.apm2/worktrees",
    "reuse_per_work": true,
    "cleanup_on_complete": true
  },
  "implementer": {
    "nudge_policy": { "max_nudges": 50, "backoff_seconds": [30, 120, 600] },
    "retry_policy": { "git_apply_max_retries": 25 }
  },
  "reviewer": {
    "nudge_policy": { "max_nudges": 50, "backoff_seconds": [60, 300, 900] }
  }
}
```

**Security rule:** WorkLoopProfile cannot override the role spec / capability manifest / adapter profile constraints resolved by policy (those are already validated in `handle_spawn_episode` today via hashes).

### 4.3 WorkContextEntry: `apm2.work_context_entry.v1` (immutable, append-only stream)

Stored in CAS; anchored by a ledger event (`evidence.published` with category `WORK_CONTEXT_ENTRY`).

```json
{
  "schema": "apm2.work_context_entry.v1",
  "work_id": "…",
  "entry_id": "ctx-2026-02-18T12:35:02Z-…",
  "kind": "HANDOFF_NOTE",
  "dedupe_key": "session-…",
  "actor_id": "…",
  "created_at_ns": 0,
  "body": {
    "format": "markdown",
    "text": "Summary of changes, risks, how to review…"
  },
  "linkouts": [
    { "kind": "PR", "url": "…" },
    { "kind": "CI", "url": "…" }
  ]
}
```

---

## 5. Ledger event model

### 5.1 Canonical work lifecycle events (existing)

Use the existing protobuf `WorkEvent` types (`WorkOpened`, `WorkTransitioned`, `WorkCompleted`, `WorkAborted`, `WorkPrAssociated`) and their reducer (`crates/apm2-core/src/work/reducer.rs`).

Canonical event types are dot-prefixed (as already referenced in `work/authority.rs`):

* `work.opened`
* `work.transitioned`
* `work.completed`
* `work.aborted`
* `work.pr_associated`

### 5.2 Work graph events (new): `WorkGraphEvent`

We introduce a new protobuf message family in `proto/kernel_events.proto`:

```proto
message WorkGraphEvent {
  oneof event {
    WorkEdgeAdded edge_added = 1;
    WorkEdgeRemoved edge_removed = 2;
    WorkEdgeWaived edge_waived = 3;
  }
}

message WorkEdgeAdded {
  string edge_id = 1;
  string from_work_id = 2;
  string to_work_id = 3;
  string edge_type = 4;        // "BLOCKS" initially
  string rationale = 5;
}

message WorkEdgeRemoved {
  string edge_id = 1;
  string rationale = 2;
}

message WorkEdgeWaived {
  string edge_id = 1;
  string waiver_id = 2;
  uint64 expires_at_ns = 3;    // 0 = never
  string rationale = 4;
}
```

Canonical event types:

* `work_graph.edge.added`
* `work_graph.edge.removed`
* `work_graph.edge.waived`

**Why separate from WorkEvent:** WorkReducer currently rejects unknown `WorkEvent` variants; work graph should not require touching the work state machine reducer.

### 5.3 Work context anchoring via evidence events (existing event, extended categories)

We use the existing protobuf `EvidenceEvent::Published` and extend evidence categories.

Canonical event type:

* `evidence.published`

Category additions in `crates/apm2-core/src/evidence/category.rs`:

* `WORK_CONTEXT_ENTRY`
* `WORK_AUTHORITY_BINDINGS`
* `WORK_LOOP_PROFILE`

This avoids inventing a parallel “context event family” and leverages the evidence pipeline already present.

### 5.4 PR association and repo identity (make collisions impossible without bloating work state)

Repo identity already lives in the WorkSpec proposed by this RFC (`WorkSpec.repo.owner/name`) and is
immutable by construction. The reducer-facing `Work` state only needs `(pr_number, commit_sha)` to
support CI/gate association; projections that need `(repo_owner, repo_name)` can join against WorkSpec
via `spec_snapshot_hash`.

This avoids a high-churn proto change to `WorkPrAssociated` and avoids duplicating repo identity across
multiple event streams.

Design rule:

* `work.pr_associated` (WorkEvent) remains `(work_id, pr_number, commit_sha)` only.
* Repo identity for indexing and linkouts is sourced from WorkSpec; PR URL is recorded as a
  `WORK_CONTEXT_ENTRY` linkout (preferred) rather than a WorkEvent field.

Projection rule:

* PR mapping must be keyed by `(repo_owner, repo_name, pr_number)` using repo identity from WorkSpec.

---

## 6. Protocol changes (operator socket)

All additions are to `proto/apm2d_runtime_v1.proto` and implemented in `crates/apm2-daemon/src/protocol/dispatch.rs`, with corresponding CLI client updates.

### 6.0 RPC contract: atomicity, idempotency, and error mapping (required)

Many of the new RPCs have the shape "store bytes in CAS, then append an anchoring ledger event."
Without explicit atomicity/idempotency rules, retries will produce divergent state and projections.

#### 6.0.1 Atomicity rule (daemon)

For any RPC that writes both CAS and ledger:

1. Canonicalize + validate input (fail fast).
2. Store artifact to CAS first (content addressed; duplicates are no-ops).
3. Append the anchoring ledger event second.

If step (3) fails, the CAS object may be orphaned, but the truth plane remains consistent.
The daemon MAY implement a best-effort orphan reaper, but correctness must not depend on it.

#### 6.0.2 Idempotency rules (per RPC)

* `OpenWork`: idempotent on `work_id`.
  * If `work_id` exists with the same `spec_snapshot_hash`, return success (no-op).
  * If `work_id` exists with a different `spec_snapshot_hash`, return `ALREADY_EXISTS`.
* `ClaimWorkV2`: idempotent on `(work_id, role, actor_id)`.
  * Same actor re-claim returns existing lease.
  * Different actor returns `FAILED_PRECONDITION` ("already claimed").
* `PublishWorkLoopProfile`: idempotent on `(work_id, dedupe_key)`.
* `PublishWorkContextEntry`: idempotent on `(work_id, kind, dedupe_key)` (as already stated).
* `RecordWorkPrAssociation`: idempotent on `(work_id, pr_number, commit_sha)` and SHOULD be checked
  against existing association to avoid "PR flapping."
* Work graph RPCs:
  * `AddWorkEdge` MUST support caller-supplied idempotency (dedupe key or explicit edge_id).
  * `RemoveWorkEdge`/`WaiveWorkEdge` are idempotent by `edge_id`.

#### 6.0.3 Error mapping

Unless a new error code is introduced, map to existing `PrivilegedErrorCode` classes:

* invalid schema / canonicalization failure → `INVALID_ARGUMENT`
* missing work / missing edge → `NOT_FOUND`
* violates dependency closure / cycle detected → `FAILED_PRECONDITION`
* lease/role mismatch → `PERMISSION_DENIED`
* idempotency conflict (same key, different content) → `ALREADY_EXISTS`

### 6.1 OpenWork (new)

**Purpose:** create a work item with a stable `work_id` and an immutable WorkSpec hash, without implicitly claiming it.

Request:

```proto
message OpenWorkRequest {
  string work_id = 1;
  bytes work_spec_json = 2; // canonical JSON bytes
  repeated string requirement_ids = 3;
  repeated string parent_work_ids = 4; // optional legacy field; edges are preferred
}
```

Behavior:

1. Canonicalize JSON (`canonicalize_json`)
2. Store to CAS; get `spec_hash`
3. Append canonical ledger event `work.opened` (payload = `WorkEvent{opened=…}`)
4. Emit pulses for `work.<work_id>.events`

### 6.2 ClaimWork v2 (new semantics; keep v1 temporarily)

Current `ClaimWork` generates a new `work_id` and writes to WorkRegistry. We add a new RPC that claims an existing work.

Request:

```proto
message ClaimWorkV2Request {
  string work_id = 1;
  WorkRole role = 2; // IMPLEMENTER, REVIEWER, etc.
  bytes work_loop_profile_hash = 3; // optional override; else daemon default
}
```

Daemon behavior:

* Validate work exists (`work.opened` present)
* Enforce dependency closure for implementer claims (see §7)
* Transition:

  * IMPLEMENTER: `work.transitioned(Open -> Claimed)`
  * REVIEWER: `work.transitioned(ReadyForReview -> Review)`
* Issue/renew lease + store authority bindings (see §8; this removes WorkRegistry as authority)
* Return lease/session capability material consistent with current claim response patterns

**Bridge rule:** Keep existing `ClaimWork` for “queue claim” until downstream is migrated, but treat it as legacy and ensure it opens work explicitly (calls OpenWork internally) rather than implicitly synthesizing `work.opened`.

### 6.3 Add/Remove/Waive WorkEdge (new)

Requests:

* `AddWorkEdgeRequest { from_work_id, to_work_id, edge_type, rationale }`
* `RemoveWorkEdgeRequest { edge_id, rationale }`
* `WaiveWorkEdgeRequest { edge_id, expires_at_ns, rationale }`

Emit `work_graph.*` events and update projections.

### 6.4 PublishWorkContextEntry (new)

Request:

```proto
message PublishWorkContextEntryRequest {
  string work_id = 1;
  string kind = 2;
  string dedupe_key = 3;
  bytes entry_json = 4; // canonical JSON bytes
}
```

Daemon behavior:

1. Canonicalize and store `entry_json` to CAS → `entry_hash`
2. Append `evidence.published` with category `WORK_CONTEXT_ENTRY`, `evidence_hash=entry_hash`
3. Enforce idempotency on `(work_id, kind, dedupe_key)` via projection uniqueness

### 6.5 RecordWorkPrAssociation (new)

Because the daemon does not speak GitHub, the CLI must supply PR info.

Request:

```proto
message RecordWorkPrAssociationRequest {
  string work_id = 1;
  string repo_owner = 2;
  string repo_name = 3;
  uint64 pr_number = 4;
  bytes commit_sha = 5;
  string pr_url = 6;
}
```

Emit `work.pr_associated` canonical work event and (optionally) also publish a `WORK_CONTEXT_ENTRY` LINKOUT.

### 6.6 DispatchImplementer/DispatchReviewer (recommended convenience)

This makes the daemon authoritative over workspace allocation and reduces CLI/agent drift.

* `DispatchImplementerRequest { work_id, work_loop_profile_hash? }`

  * Allocates workspace path deterministically (see §9), ensures directory exists, then calls internal SpawnEpisode with correct parameters, then emits `session.started` (canonical).
* Similar for reviewer.

### 6.7 PublishWorkLoopProfile (new; required to make WorkLoopProfile "mutable")

Request:

```proto
message PublishWorkLoopProfileRequest {
  string work_id = 1;
  string dedupe_key = 2;     // required for idempotency (e.g., "default", "ops_override_2026_02_18")
  bytes profile_json = 3;    // canonical JSON bytes for apm2.work_loop_profile.v1
}
```

Daemon behavior:

1. Canonicalize + validate JSON schema (`apm2.work_loop_profile.v1`).
2. Store to CAS → `profile_hash`
3. Append `evidence.published` with category `WORK_LOOP_PROFILE`, `evidence_hash=profile_hash`,
   and metadata containing `dedupe_key`.
4. Projections treat the latest anchored profile as active for `(work_id)`.

---

## 7. Work graph semantics and claimability enforcement

### 7.1 Edge type

Initial required edge type:

* `BLOCKS`: prerequisite (`from_work_id`) must be `Completed` or waived before dependent (`to_work_id`) is implementer-claimable.

### 7.2 Claimability rule (implementer role)

A work **cannot** be claimed for implementation if it has any unsatisfied incoming `BLOCKS` edges:

* Unsatisfied = prerequisite not `Done/Completed` and no active waiver.

Where this is enforced:

* In daemon handler for `ClaimWorkV2(IMPLEMENTER)` **and** in WorkDoctor recommendation logic.

### 7.3 Waivers

Waivers are separate events, do not mutate history:

* A waiver applies to an edge id
* It may have expiry
* It must be included in doctor diagnostics

### 7.4 Edge identifiers, idempotency, and cycles (required for implementability)

This RFC introduces mutable DAG edges; without explicit edge idempotency and cycle handling the system
will diverge under retries and/or deadlock under accidental cycles.

* **Edge IDs**: generated by the daemon as `EDGE-<uuid_v4>` (same style as `W-`, `L-`, `S-`), returned
  to callers in the RPC response.
* **Idempotency**:
  * `AddWorkEdge` must accept an optional `dedupe_key` (client-supplied) OR accept a caller-supplied
    `edge_id`. Without this, retries can introduce duplicate edges and make claimability non-deterministic.
  * `RemoveWorkEdge` and `WaiveWorkEdge` are idempotent: re-applying the same operation to the same
    `edge_id` must be a no-op.
* **Cycle detection**: `AddWorkEdge(BLOCKS)` must reject any edge that creates a cycle in the active
  `BLOCKS` graph. Otherwise the daemon can create works that are permanently unclaimable without waivers.
  Cycle detection is performed against the current projection graph, not by scanning history.

### 7.5 Late edges and in-flight work (explicit policy)

If a `BLOCKS` edge is added where `to_work_id` is already `Claimed`/`InProgress`/`CiPending`:

* The edge is still recorded (history is append-only).
* The daemon MUST NOT auto-transition the work state (the `WorkReducer` state machine remains the only
  authority for work state transitions).
* Doctor output MUST surface the late edge as a high-severity diagnostic and recommend either:
  * adding a waiver, or
  * intentionally transitioning the work to `Blocked` via a policy-controlled system actor.

---

## 8. Eliminating WorkRegistry as authority (hard requirement)

### 8.1 What WorkRegistry currently contains that ledger does not

WorkRegistry stores (at least):

* Claim actor identity
* Role
* Lease id
* Policy resolution hashes (role_spec_hash, context_pack_recipe_hash, expected_adapter_profile_hash, stop condition hash, etc.)
* Potentially other binding material used in `handle_spawn_episode` validations

This is a direct violation of “ledger + CAS reconstructibility.”

### 8.2 Replacement: Authority Bindings as CAS + ledger anchor

Introduce a CAS document:

* `apm2.work_authority_bindings.v1`

This document must contain the *exact* authority-relevant material currently persisted in WorkRegistry
(`WorkClaim`, `PolicyResolution`, custody domains, permeability receipt references, etc.) so that
`handle_spawn_episode` can be implemented purely as "read projections + fetch CAS artifacts."

Grounding in repo reality:

* `WorkClaim` and `PolicyResolution` already exist as concrete structs in
  `crates/apm2-daemon/src/protocol/dispatch.rs`.
* `TransitionAuthorityBindings` (including `capability_manifest_hash`, `context_pack_hash`,
  `stop_condition_hash`, `typed_budget_contract_hash`, and optional `permeability_receipt_hash`) is
  already derived and validated in `handle_spawn_episode` via `derive_transition_authority_bindings`
  and `validate_and_store_transition_authority`.

#### Ledger anchoring: use `evidence.published` (not `work.*`)

Do **not** introduce `work.authority_bound` as written in the previous draft. Any `work.*` event type
is decoded as a `WorkEvent` by `WorkReducer`; a standalone `WorkAuthorityBound` payload would hard-fail
reduction.

Instead, authority bindings are anchored using the existing evidence pipeline:

* emit `evidence.published`
* `category = WORK_AUTHORITY_BINDINGS`
* `evidence_hash = bindings_hash` (CAS hash of `apm2.work_authority_bindings.v1`)
* `metadata` MUST include: `role`, `lease_id`, and (optionally) `policy_resolution_hash` so that
  projections can be built without fetching the CAS document in the hot path.

SpawnEpisode then reads bindings from projections/CAS instead of WorkRegistry.

**Outcome:** WorkRegistry becomes a derived cache at most, then removable.

---

## 9. Workspace management (configurable, deterministic)

The daemon currently requires `SpawnEpisodeRequest.workspace_root` to exist and be provided by the caller. This produces drift and violates “daemon-governed loop.”

### 9.1 WorktreeManager (new daemon component)

Config sources, in order:

1. `daemon.workspaces.*` config defaults
2. `WorkLoopProfile.workspace.*` override

Deterministic path:

* `<root>/<repo_slug>/<work_id>/`

  * repo_slug = `${owner}_${repo}`

Strategies:

* `git_worktree` (default)
* `git_clone_shared` (fallback)

Policies:

* `reuse_per_work=true` keeps workspace stable across nudges
* `cleanup_on_complete=true` reaps after `work.completed`

---

## 10. Implementer lifecycle (closed loop, terminal contract preserved)

### 10.1 State machine (matches existing `WorkState` in `crates/apm2-core/src/work/state.rs`)

* `Open` → `Claimed` (ClaimWorkV2 implementer)
* `Claimed` → `InProgress` (DispatchImplementer / SpawnEpisode)
* `InProgress` → `CiPending` (CI processor acknowledges latest changeset published by **terminal command `apm2 fac push`**)
* `CiPending` → `ReadyForReview` or `Blocked` (gate orchestrator/system actor)
* `Blocked` → `InProgress` (fix loop)
* `ReadyForReview` → `Review` (review claim)
* `Review` → `Completed` (merge admission) or back to `Blocked`

### 10.2 Terminal contract (hard)

A session attempt is not “complete” unless:

* A `WORK_CONTEXT_ENTRY` of kind `IMPLEMENTER_TERMINAL` exists with `dedupe_key=session_id`, **and**
* A `WORK_CONTEXT_ENTRY` of kind `HANDOFF_NOTE` exists for the same session (same dedupe key or session-bound linkage)

### 10.3 `apm2 fac push` changes (bridge, not replacement)

Add:

* `--work-id <id>` (or `--ticket-alias` resolving to work_id)

Required post-push behavior:

1. Publish change set to daemon (`PublishChangeSet`) **bound to work_id**
2. Record PR association (`RecordWorkPrAssociation`)
3. Publish context entries:

   * `HANDOFF_NOTE` (required)
   * `IMPLEMENTER_TERMINAL` (required; idempotent dedupe)
   * optional LINKOUTs (PR/CI)

Then daemon transitions:

* `apm2 fac push` MUST NOT directly emit `work.transitioned(InProgress -> CiPending)` as the caller's
  actor. In `apm2-core`, the `InProgress -> CiPending` transition is currently authorized only for the
  CI system actor (`CI_SYSTEM_ACTOR_ID = "system:ci-processor"` in `crates/apm2-core/src/work/reducer.rs`).

Instead:

1. `apm2 fac push` publishes the latest changeset + required context markers.
2. A daemon-side **CI processor** (which may be the gate orchestrator) observes `changeset_published`
   for the work's latest digest and emits:
   * `work.transitioned(InProgress -> CiPending)` as actor `"system:ci-processor"`

### 10.4 Reaper/nudge loop (new daemon WorkLoopManager)

Trigger conditions:

* `session.terminated` arrives for an implementer session
* work state remains `InProgress`
* missing terminal contract markers

Behavior:

* schedule a nudge attempt using the same workspace
* nudge content includes: current doctor status, missing markers, exact command to run (`apm2 fac push --work-id ... --handoff-note ...`)

Budgets and backoff come from WorkLoopProfile; no hard-coded “3 nudges.”

---

## 11. Gate loop + merge completion alignment

### 11.1 CI actor identity (don’t hard-code string)

Repo reality: `WorkReducer` currently hard-codes `"system:ci-processor"` for CI-authorized transitions.
Changing this is non-trivial because `WorkReducer` runs in `apm2-core` (no daemon config).

For this RFC's scope:

* Keep `"system:ci-processor"` as the CI actor id to satisfy current reducer checks.
* Track "configurable CI actor id" as an identity RFC follow-up that must also specify how reducer
  configuration is plumbed (constructor parameter, environment override, or wrapper reducer).

### 11.2 Latest changeset rule

Gate outcomes must apply only to the latest changeset for a work.

Projection requirement:

* `work_latest_changeset(work_id -> changeset_digest)` maintained from `changeset_published` / canonical changeset events.

GateOrchestrator transitions `CiPending -> ReadyForReview/Blocked` only if receipt binds to latest digest.

### 11.3 Merge completion event naming bug fix (required)

`crates/apm2-daemon/src/gate/merge_executor.rs` currently writes a `WorkCompleted`-shaped event where `gate_receipt_id` field actually carries a merge receipt id (`merge-receipt-<sha>`). This must be renamed and semantically aligned:

* Introduce `merge_receipt_id` field (or carry merge receipt hash in evidence bundle)
* Make merge executor append:

  * `merge.receipt_recorded` (or equivalent canonical)
  * `work.completed` with evidence bundle that references merge receipt + final gate/review receipts

---

## 12. Pulse plane: making wait push-based and correct

### 12.1 Fix the type mismatch

Current pulse publisher assumes `KernelEvent` envelope decoding; in repo reality, commit notifications
already provide `(event_type, namespace)` and payload bytes may be either:
* legacy JSON facts,
* reducer-domain protobuf wrapper events, or
* typed discriminant payloads (depending on which plane emitted the event).

PulsePublisher must operate on:

* `(event_type, namespace, payload_bytes)` and decode only when required.

### 12.2 Multi-topic derivation (required)

Topic derivation must return `Vec<String>`, not a single topic, because:

* work graph edges touch two work ids
* receipts can affect both work and PR indices

### 12.3 Topic namespace

Standard topics:

* `work.<work_id>.events`
* `ledger.head` (required by RFC-0018 topic taxonomy; enables "follow the chain" consumers)
* `work.<work_id>.gates.events` (optional)
* `work.<work_id>.reviews.events` (optional)
* `session.<session_id>.events`

Rule: anything that can change doctor output for a work MUST emit `work.<work_id>.events`.

### 12.4 Typed discriminants vs dotted event types (explicit requirement)

Topic derivation must work for both:

* dotted reducer-domain event types (`work.opened`, `work.transitioned`, …), and
* typed discriminants (`WorkOpened`, `WorkTransitioned`, …) used by current topic derivation tests
  and RFC-0018 `02_design_decisions.yaml`.

Implementation guidance:

* Maintain a parity mapping layer for work lifecycle events (reuse `crates/apm2-core/src/work/parity.rs`
  concepts) so both forms map to identical work topics.

### 12.5 CLI wait integration

Add operator client support for:

* `SubscribePulse`
* `WaitForPulse`

Update doctor flows (`apm2 fac doctor` and/or new `apm2 work doctor`) so `--wait` subscribes to:

* `work.<work_id>.>` and re-runs doctor evaluation on pulse arrival.

---

## 13. Projections (derived, replayable)

Add projection tables (daemon projection DB):

### 13.1 work_edges

(as in the earlier draft; unchanged conceptually)

### 13.2 work_context

* keyed by `(work_id, entry_id)`
* unique index on `(work_id, kind, dedupe_key)` where dedupe_key not null

### 13.3 work_authority_bindings

* keyed by `(work_id, role)`
* stores `lease_id`, `bindings_hash`, `evidence_id`, `claimed_at_ns`, released fields
* derived from `evidence.published` where `category = WORK_AUTHORITY_BINDINGS`

### 13.4 work_latest_changeset

* keyed by work_id
* stores latest digest and time

**Critical rule:** All these tables must be derivable from ledger + CAS. No WorkRegistry-only state.

---

## 14. Migration plan (no cutover cliff, but no permanent dual truth)

### Phase 0 — Ledger unification (blocking prerequisite)

Implement a daemon startup migration that turns the core `events` table into the sole append target.

Grounding in repo reality:

* `determine_read_mode` in `crates/apm2-core/src/ledger/storage.rs` forces `LegacyModeReadOnly` when
  `ledger_events` exists and `events` is empty. This is the exact state that blocks kernel-native
  writes today.
* The existing compat view `events_legacy_compat_v1` returns `NULL` for `prev_hash`/`event_hash`,
  which prevents core-ledger appenders from building a hash chain (`last_event_hash()` falls back to
  genesis when `event_hash` is NULL).

Migration requirements (implementation-grade):

1. **Single transaction, exclusive lock**
   * Acquire an exclusive SQLite transaction for the duration of the copy + hash chain computation.
2. **Preserve ordering**
   * Read `ledger_events` ordered by `seq_id ASC`.
   * Insert into `events` in the same order. (Whether `seq_id` is preserved or re-numbered is a local
     choice; ordering must remain identical.)
3. **Compute a real 32-byte hash chain**
   * Compute `prev_hash`/`event_hash` using `apm2_core::crypto::EventHasher` (BLAKE3) with a genesis
     previous hash of 32 zero bytes.
   * Persist computed hashes into `events.prev_hash` and `events.event_hash` for every migrated row.
4. **Signature handling**
   * Preserve legacy `signature` bytes as opaque data; do not attempt to retrofit "verified" mode during
     this migration (legacy actor ids are not hex-encoded verifying keys, so `append_verified` cannot
     validate them without a separate identity migration).
5. **Freeze legacy writers**
   * After successful migration, prevent further writes to `ledger_events` (rename table, drop triggers,
     or hard-fail in the daemon emitter).
   * Daemon must switch to appending to core `events` immediately after migration.
6. **Idempotency**
   * If `events` already contains rows, migration is a no-op.
   * If migration partially completed, daemon must detect and fail fast (do not attempt to "continue").

### Phase 1 — Work open (CAS WorkSpec + work.opened)

* Add `OpenWork` RPC and `apm2 work open --from-ticket <yaml>` importer
* Store WorkSpec in CAS and emit `work.opened`
* Emit ticket alias bindings via WorkSpec metadata; wire into alias reconciliation gate (replacing current identity stub)

### Phase 2 — `fac push --work-id` terminal contract bridge

* Extend `apm2 fac push` to accept `--work-id`
* After GitHub push/PR update, call daemon:

  * PublishChangeSet(work_id)
  * RecordWorkPrAssociation(work_id, repo, pr_number, sha)
  * PublishWorkContextEntry(HANDOFF_NOTE, IMPLEMENTER_TERMINAL)
  * Transition InProgress → CiPending

### Phase 3 — Work graph + dependency enforcement

* Add work graph RPCs and projections
* Enforce in claim + doctor

### Phase 4 — Reviewer bridge + configurable nudge

* On verdict set, publish WorkContext entries and canonical review receipt events
* Remove hard-coded nudge caps from `fac_review` path by moving to WorkLoopProfile

### Phase 5 — Merge completion alignment + naming fix

* Emit merge receipt + work.completed atomically and consistently

### Phase 6 — Remove WorkRegistry authority

* All authority reads come from projections over ledger + CAS
* WorkRegistry becomes an internal cache or is deleted

---

## 15. Acceptance tests (system-level)

AT-0: Ledger unification

* Start with db containing legacy `ledger_events` only (events empty)
* Run migration
* Verify core ledger read mode becomes canonical and daemon can append new events

AT-1: Work open + graph enforcement

1. Open A, Open B
2. Add edge A BLOCKS B
3. Claim B (implementer) must fail with “blocked by A”
4. Complete A, then claim B succeeds

AT-2: Implementer terminal contract

1. Claim + dispatch implementer on W
2. End session without push → doctor recommends terminal command + nudge scheduled
3. Run `apm2 fac push --work-id W --handoff-note …`
4. Verify context entries exist (dedupe), state transitions to CiPending

AT-3: PR association repo identity

* RecordWorkPrAssociation with repo owner/name
* Projection keys `(owner,name,pr_number)` map to work_id without collisions

AT-4: Pulse-driven wait

* Subscribe to `work.<id>.>`
* Append a relevant event (context publish or transition)
* Verify pulse delivered and doctor reevaluated without polling

AT-5: Merge completion alignment

* Merge executor emits merge receipt + work.completed
* Evidence bundle references correct receipt ids; no misnamed `gate_receipt_id`

---

## 16. Key design corrections vs the initial proposal

1. **Ticket IDs are aliases, not canonical work ids**: the repo already contains alias reconciliation infrastructure; use it instead of forcing `work_id == TCK-*`.
2. **Core ledger can be read-only today**: any kernel-native plan must include a ledger unification migration or a clean new ledger file strategy.
3. **No canonical `work.claimed` event in the target reducer space**: claim is a `work.transitioned(Open→Claimed)`; additional authority bindings must be anchored separately (this RFC uses `evidence.published` with category `WORK_AUTHORITY_BINDINGS`).
4. **Pulse plane must derive topics from actual canonical event types**: current `KernelEvent`-envelope decoding assumptions are inconsistent with reducer-facing event families; fix is required for push-based waits to be real.

---

## 17. Implementation map (first cut)

### Daemon

* Add unification migration: `crates/apm2-core/src/ledger/storage.rs` + daemon startup path
* New RPC handlers: `crates/apm2-daemon/src/protocol/dispatch.rs`

  * OpenWork, ClaimWorkV2, AddWorkEdge/Remove/Waive, PublishWorkContextEntry, RecordWorkPrAssociation
* New work loop manager: `crates/apm2-daemon/src/work/*` (new module)
* Projections: extend `crates/apm2-daemon/src/projection/worker.rs` (or new projection module)
* EvidenceCategory: extend `crates/apm2-core/src/evidence/category.rs`
* Proto changes: `proto/kernel_events.proto`, `proto/apm2d_runtime_v1.proto`

### CLI

* `apm2 fac push`: `crates/apm2-cli/src/commands/fac.rs` + `fac_review/push.rs`
* Add protocol client calls for new RPCs
* Add `apm2 work open`, `apm2 work doctor` (or extend `fac doctor` to accept work id)

### Pulse

* Fix `PulsePublisher` decode path and topic deriver:

  * `crates/apm2-daemon/src/protocol/pulse_outbox.rs`
  * `crates/apm2-daemon/src/protocol/topic_derivation.rs`

---

## 18. Open issues (must be resolved during implementation)

O1. Actor identity model: reconcile string actor ids (`system:ci-processor`) with verification-bound ids; this RFC proposes a config indirection as an interim fix.
O2. Canonical event naming convergence: this RFC pushes canonical dot-prefixed events for reducers; legacy underscore intake remains for a bridge window. Decide timeline for freezing underscored emissions.
O3. Exact change set bundle construction from `fac push`: define how to produce `ChangeSetBundleV1` deterministically from git state in the CLI, and how to bind it to PR association.
O4. Ledger signature scheme during/after migration: migrated legacy signatures cannot be "verified-mode"
    without an actor-id/key migration. Decide:
    * whether to treat legacy signatures as opaque historical artifacts, or
    * implement an identity bridge that maps legacy actor ids to verifying keys.
O5. Reducer configuration plumbing: if CI actor ids (and similar) are to become configurable, specify
    how config is injected into `apm2-core` reducers (constructor parameter vs wrapper).
O6. WorkSpec schema validation and size bounds: define a hard maximum size for WorkSpec and context
    entry artifacts to prevent CAS abuse, and specify daemon-side JSON schema validation behavior.
O7. Backfill strategy for existing WorkRegistry authority records: define how existing `work_claims`
    rows are converted into `WORK_AUTHORITY_BINDINGS` evidence on migration (or how long the system
    tolerates mixed sources).
