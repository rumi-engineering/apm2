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

   * Today, the core ledger is frequently in `LedgerReadMode::LegacyLedgerEvents` (see `determine_read_mode`) because `ledger_events` exists and the canonical `events` table is empty.

     * In this mode, `LedgerStorage::ensure_writable()` rejects canonical appends with `LedgerStorageError::LegacyModeReadOnly`.
     * If both `ledger_events` **and** `events` contain rows, `determine_read_mode` fails fast with `LedgerReadModeError::AmbiguousSchemaState`.

     This blocks forward progress: you cannot safely start writing canonical events without first eliminating the ambiguous two-ledger state.

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

C1. **Core ledger is currently often in `LedgerReadMode::LegacyLedgerEvents`**: any plan that starts writing canonical events must first eliminate the ambiguous two-ledger state (see `determine_read_mode`).
C2. **`apm2 fac push` remains the terminal command** through cutover; no bypassing.
C3. Daemon is the authority boundary: ledger/CAS mutations go through the daemon operator socket (UDS) unless explicitly delegated later.

### 2.4 Drift-control guardrails (mandatory)

**Biggest risk:** implementation drift that *appears* to implement this RFC while silently diverging from the existing spine contracts already embedded in code + prior RFCs (event naming/encoding mismatches, missing authority pins, non-replayable state, "temporary" SQLite authority that never gets removed).

This RFC therefore declares the following drift barriers as **mandatory**, not "nice to have":

**D1. Single source-of-truth registries (code-enforced)**

1. **CAS schema ids**: every CAS JSON schema id introduced by this RFC MUST be added to
   `crates/apm2-core/src/schema_registry/fac_schemas.rs` (and must pass its uniqueness + prefix tests; see `test_fac_schema_ids_are_unique` / `test_fac_schema_id_prefixes`).
2. **Topic derivation coverage**: every new canonical event type introduced by this RFC MUST have a dedicated topic-derivation test in
   `crates/apm2-daemon/src/protocol/topic_derivation.rs` that asserts the exact topic set emitted.
3. **Parity gate integration**: if we are in a bridge window where both legacy and canonical work events exist, parity MUST be continuously checked using
   `apm2_core::work::parity::{ParityValidator, EventFamilyPromotionGate}` (see existing production usage in `crates/apm2-daemon/src/gate/merge_executor.rs`), and promotion MUST be blocked on defects (fail-closed).

**D2. Fail-closed bounded decoding (DoS + schema drift defense)**

Any IPC surface that accepts user-provided bytes for CAS-backed JSON MUST:

* validate schema id using `fac_schemas::validate_schema_id`,
* decode using `fac_schemas::bounded_from_slice_with_limit` (or equivalent) with an explicit per-artifact byte limit,
* use `#[serde(deny_unknown_fields)]` on all CAS JSON structs defined by this RFC.

**D3. Preserve the existing promotion-blocking gates**

This RFC may add additional gates, but MUST NOT weaken existing ones already present in code:

* **alias reconciliation promotion gate** (`crates/apm2-daemon/src/work/authority.rs`) remains promotion-blocking (fail-closed) per CTR-ALIAS-002.
* **merge executor promotion gate** (parity/defect blocking) remains promotion-blocking.

**D4. "Done" is measurable**

Each migration phase MUST include a checklist that is both:

* **machine-verifiable** (tests, invariants, metrics), and
* **promotion-blocking** (gates deny on missing checklist items in production mode).

### 2.5 Alignment commitments with RFC-0018 and RFC-0019 (normative)

This RFC is vNext wiring, not a rewrite of the FAC physics. It MUST preserve the contracts already declared as mandatory in earlier RFCs and already partially embedded in code:

* **RFC-0018 §6.3 Authority and Boundary Contract**: transitions/episodes/receipts require a complete set of boundary pins (lease id, permeability receipt hash, capability manifest hash, context pack hash, stop-condition hash, typed budgets). Missing pins are fail-closed and MUST be recorded as defects; best-effort is forbidden.
* **RFC-0018 §7.3 Parity mapping**: legacy underscore work events must map cleanly to canonical reducer work events, including `previous_transition_count` monotonicity.
* **RFC-0019 boundary discipline**: idempotent actuation, digest-first interfaces, and explicit stop/budget pins remain non-negotiable.

If a requirement is "not yet implemented" in this RFC's phases, the RFC MUST specify which existing event/artifact currently carries the pin and how it survives ledger unification without losing replayability.

---

## 3. Canonical architecture

### 3.1 End state overview

* **Core ledger (`apm2-core`)** stores all authoritative FAC events in the canonical `events` table.
* **CAS (`apm2-daemon DurableCas`, implementing `apm2_core::evidence::ContentAddressedStore`)** stores immutable artifacts (work specs, context entries, evidence bundles, change sets, etc.).
* **Projections** (SQLite tables and/or in-memory reducers) are derived from ledger + CAS and are **replayable**.

### 3.2 Event taxonomy: classify by encoding + trust boundary, not punctuation

The repo already contains multiple event families. **Underscore vs dot is not the correct classifier**:

* Some underscore events are **daemon-signed JSON** (`work_claimed`, `work_transitioned`, `session_started`, ...).
* Many underscore events are daemon-signed JSON today (including FAC spine facts like `changeset_published` and review receipts). The corresponding domain prefixes already exist in `crates/apm2-core/src/ledger/storage.rs::domain_prefix_for_event_type`, and this RFC upgrades the canonical encoding for those facts to protobuf in the core ledger.
* Dot-prefixed events (`work.opened`, `work.transitioned`, `evidence.published`) are reducer-facing canonical event types.

This RFC therefore uses the following taxonomy (normative):

1. **DaemonSignedJson events (legacy compatibility family)**
   * Storage (today): daemon `ledger_events` table (legacy plane).
   * Payload: canonical JSON bytes (JCS-style determinism).
   * Signature: daemon domain-separated signature.
   * Examples (non-exhaustive): `work_claimed`, `work_transitioned`, `session_started`, `session_terminated`, `session_event`, `stop_flags_mutated`.
   * Policy: these events may be ingested for replay parity during cutover, but are not the target canonical encoding. Do not extend them with new semantics.

2. **ReducerProtobuf events (canonical truth for reducers)**
   * Storage: core ledger `events` table (post-unification).
   * Payload: protobuf bytes (e.g., `WorkEvent`, `EvidenceEvent`) with canonicalization rules already established by `apm2_core::events::Canonicalize`.
   * Event types: `work.opened`, `work.transitioned`, `work.completed`, `work.aborted`, `evidence.published`, etc.
   * Reducers: `apm2_core::work::WorkReducer`, `apm2_core::evidence::EvidenceReducer`, etc.

3. **KernelTyped events (FAC spine facts that are not reducers' `WorkEvent`)**
   * Storage: core ledger `events` table (post-unification).
   * Payload encoding:
     * **Today (repo reality):** these facts are emitted by the daemon as **signed JSON payloads** in the legacy ledger (`crates/apm2-daemon/src/ledger.rs`).
     * **End state (this RFC):** these facts are emitted as **protobuf payloads** using the corresponding messages in `proto/kernel_events.proto` and canonicalized via `apm2_core::events::Canonicalize`.
   * Event types: `changeset_published`, `review_receipt_recorded`, `review_blocked_recorded`, `projection_receipt_recorded`, etc.
   * Policy: these are canonical kernel facts and MUST NOT be lumped into "legacy intake" just because they use underscores. During the bridge, topic derivation + projections MUST accept **both** encodings for the same `event_type` until emissions are frozen.

**Key rule (bridge):** during cutover windows where both DaemonSignedJson work events and ReducerProtobuf work events exist, reducer truth MUST be checked for equivalence using
`apm2_core::work::parity::{ParityValidator, EventFamilyPromotionGate}`, and any promotion-capable system actor MUST fail-closed on parity defects.

### 3.3 Payload encoding + canonicalization matrix (drift barrier)

To prevent "it worked locally" drift, every event type introduced or relied on by this RFC MUST declare:

* **payload encoding** (JSON vs protobuf),
* **canonicalization contract** (what must be normalized before hashing/signing),
* **topic derivation source-of-truth** (what fields are used to derive pulse topics).

Minimum required declarations for this RFC:

| Event type family | Example event types | Payload encoding | Canonicalization source | Topic derivation must use |
|---|---|---:|---|---|
| ReducerProtobuf (`WorkEvent`) | `work.opened`, `work.transitioned`, `work.completed` | protobuf | `apm2_core::events::Canonicalize` on payload structs | `work_id` extracted from decoded `WorkEvent` |
| ReducerProtobuf (`EvidenceEvent`) | `evidence.published` | protobuf | `apm2_core::events::Canonicalize` | `work_id` from decoded `EvidencePublished.work_id` |
| KernelTyped (bridge: JSON → protobuf) | `changeset_published`, `review_receipt_recorded` | **bridge:** JSON today; **end:** protobuf | **end state:** `apm2_core::events::Canonicalize` on the protobuf payload | `work_id` from decoded payload (bridge: JSON parse; end: protobuf decode) |
| DaemonSignedJson | `work_claimed`, `work_transitioned` | JSON | `canonicalize_json` before signing | `work_id` from payload JSON |

**Pulse implication:** `PulsePublisher` MUST NOT assume a `KernelEvent` envelope; it MUST route on `(event_type, payload_bytes)` and decode only enough to derive topics and (optionally) render doctor hints.

**Normative decision:** the core ledger stores **event-type-specific payload bytes** in `events.payload` (e.g., `WorkEvent` bytes for `work.*`, `EvidenceEvent` bytes for `evidence.*`, and typed bytes for kernel facts). `KernelEvent` is treated as a *derived* representation (useful for network APIs), not the on-disk payload encoding.

---

## 4. Data model (CAS documents)

All CAS documents in this RFC are **canonicalized JSON** using `apm2_core::determinism::canonicalize_json` and then hashed via the existing BLAKE3 content hash (same pattern used throughout `DurableCas`).

### 4.0 Schema governance + bounded decoding (mandatory)

To prevent long-lived drift between "what the RFC intended" and "what got serialized in production," all CAS-backed JSON documents introduced here MUST:

1. Carry a stable `schema` id string (e.g., `apm2.work_spec.v1`).
2. Be registered in `crates/apm2-core/src/schema_registry/fac_schemas.rs` (schema id allowlist).
3. Be decoded from IPC bytes using bounded deserialization:
   * `fac_schemas::bounded_from_slice_with_limit::<T>(bytes, limit)`
   * `#[serde(deny_unknown_fields)]` on the struct `T`.
4. Define an explicit maximum size per artifact (fail-closed).

Hard caps (normative; fail-closed):

* WorkSpec: **≤ 256 KiB**
* WorkLoopProfile: **≤ 64 KiB**
* WorkContextEntry: **≤ 256 KiB**
* WorkAuthorityBindings: **≤ 256 KiB**

**Hashing rule:** the daemon MUST canonicalize the JSON bytes first and store the canonical bytes in CAS (the hash is of canonical bytes). The daemon MUST NOT hash/store raw non-canonical input bytes.

### 4.0.1 Deterministic IDs for idempotent evidence anchors (mandatory)

Several RPCs in this RFC are *idempotent* and anchor CAS artifacts via `evidence.published`. To make idempotency implementable without "read-before-write" races, the daemon MUST generate **deterministic identifiers** for:

* `entry_id` (for `WorkContextEntry`)
* `evidence_id` (for the anchoring `EvidencePublished`)
* optional `edge_id` (when callers do not supply one)

**Rule:** when an RPC defines idempotency on `(work_id, kind, dedupe_key)` (or `(work_id, dedupe_key)`), the daemon MUST deterministically derive:

* `entry_id` and `evidence_id` from `(category, work_id, kind, dedupe_key)`
* using BLAKE3 over canonical UTF-8 bytes, and a stable prefix.

Recommended format (normative prefixes; exact base encoding is an implementation detail):

* `WorkContextEntry`:
  * `entry_id = "CTX-" + blake3("WORK_CONTEXT_ENTRY" || work_id || kind || dedupe_key)`
  * `evidence_id = entry_id`
* `WorkLoopProfile`:
  * `evidence_id = "WLP-" + blake3("WORK_LOOP_PROFILE" || work_id || dedupe_key)`
* `WorkAuthorityBindings`:
  * `evidence_id = "WAB-" + blake3("WORK_AUTHORITY_BINDINGS" || work_id || role || lease_id)`
* `WorkEdge` (when callers do not supply `edge_id`):
  * `edge_id = "EDGE-" + blake3("WORK_EDGE" || from_work_id || to_work_id || edge_type || dedupe_key)`

**Fail-closed:** if `dedupe_key` is required by the RPC, empty `dedupe_key` MUST be rejected.

### 4.1 WorkSpec: `apm2.work_spec.v1` (immutable)

Stored in CAS; referenced by `WorkOpened.spec_snapshot_hash` (bytes).

This RFC **aligns WorkSpec with the existing work cutover proposal (RFC-0018)**: WorkSpec is “what the work is,” not “what attempts happened.”

```json
{
  "schema": "apm2.work_spec.v1",
  "work_id": "W-<uuid>",
  "ticket_alias": "TCK-00606",
  "title": "Make fac push emit terminal markers and bind work_id",
  "summary": "Kernel-native FAC push integration; add context markers; wire PR association.",
  "work_type": "TICKET",
  "fac": { "cycle": "forge_admission" },
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
Do **not** require "ticket id becomes `work_id`." The codebase already has an explicit alias reconciliation design (`apm2_core::events::alias_reconcile`) and even an alias reconciliation gate stub in `handle_spawn_episode`. Use it. Ticket IDs are aliases, not canonical ids.

**WorkType constraint (repo-aligned):**
`work_type` MUST be one of the string forms accepted by `apm2_core::work::WorkType` (`TICKET`, `PRD_REFINEMENT`, `RFC_REFINEMENT`, `REVIEW`). If FAC needs additional sub-typing ("forge admission"), carry it as a WorkSpec facet (e.g., `fac.cycle`) rather than changing the reducer's WorkType without a dedicated RFC.

### 4.2 WorkLoopProfile: `apm2.work_loop_profile.v1` (mutable policy/config knobs)

Stored in CAS; referenced by claim/session dispatch events (see §5, §6). This is operational tuning, **not** privilege escalation.

**Immutability note:** CAS documents are immutable; "mutable" here means "a newer profile hash can be published and selected." The RFC MUST specify how selection occurs (event + projection), not imply in-place mutation.

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
  "entry_id": "CTX-<blake3>",
  "kind": "HANDOFF_NOTE",
  "dedupe_key": "session:S-…",
  "source_session_id": "S-…",
  "actor_id": "actor:uid:…:gid:…",
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

**Actor/time attribution rule (repo-aligned):**
`actor_id` MUST be derived by the daemon from peer credentials (as `ClaimWork` already does); clients MUST NOT be the authority for `actor_id`.
`created_at_ns` SHOULD equal the ledger event timestamp used to anchor the entry (or be derived directly from the daemon's authoritative clock source).

**Kind allowlist (mandatory):** `kind` MUST be one of:

* `HANDOFF_NOTE`
* `IMPLEMENTER_TERMINAL`
* `DIAGNOSIS`
* `REVIEW_FINDING`
* `REVIEW_VERDICT`
* `GATE_NOTE`
* `LINKOUT`

**Normalization rule:** the daemon MUST verify that `entry_json.kind` equals request `kind` and `entry_json.dedupe_key` equals request `dedupe_key`. If the client omits `entry_id`, `actor_id`, or `created_at_ns`, the daemon MUST fill them prior to canonicalization. If the client supplies them, the daemon MUST overwrite them with authoritative values (fail-closed if overwriting would change a non-empty client value).

### 4.4 WorkAuthorityBindings: `apm2.work_authority_bindings.v1` (immutable, append-only)

Stored in CAS; anchored by `evidence.published` with category `WORK_AUTHORITY_BINDINGS`.

**Purpose:** eliminate WorkRegistry as an authority source by recording all authority-relevant pins required by RFC-0018 §6.3 for claim → spawn → privileged actions.

```json
{
  "schema": "apm2.work_authority_bindings.v1",
  "work_id": "W-…",
  "role": "IMPLEMENTER",
  "lease_id": "L-…",
  "actor_id": "actor:uid:…:gid:…",
  "claimed_at_ns": 0,
  "transition_count": 1,
  "policy_resolution": {
    "resolved_policy_hash": "…",
    "policy_resolved_ref": "…",
    "resolved_risk_tier": 2,
    "role_spec_hash": "…",
    "context_pack_recipe_hash": "…",
    "context_pack_hash": "…",
    "capability_manifest_hash": "…",
    "expected_adapter_profile_hash": "…"
  },
  "boundary_pins": {
    "permeability_receipt_hash": null,
    "stop_condition_hash": "…",
    "typed_budget_contract_hash": "…",
    "typed_budget_hash": "…",
    "typed_budgets": { "entropy_budget": 1234 },
    "stop_conditions": [ { "type": "manual_stop" } ]
  }
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

**Session boundary pins (required by RFC-0018 §6.3):** session-start events MUST record the complete boundary pin set used to spawn the episode. Implementation choice: extend `SessionStarted` in `proto/kernel_events.proto` to include these hash fields so `session.started` is replay-self-contained.

### 5.2 Work graph events (new): `WorkGraphEvent`

We introduce a new protobuf message family in `proto/kernel_events.proto`:

```proto
// Kernel events for the mutable dependency graph.
// NOTE: event types are `work_graph.*` (do not start with `work.`) to avoid WorkReducer decoding.

message WorkGraphEvent {
  oneof event {
    WorkEdgeAdded edge_added = 1;
    WorkEdgeRemoved edge_removed = 2;
    WorkEdgeWaived edge_waived = 3;
  }
}

enum WorkEdgeType {
  WORK_EDGE_TYPE_UNSPECIFIED = 0;
  WORK_EDGE_TYPE_BLOCKS = 1;
}

message WorkEdgeAdded {
  string edge_id = 1;          // "EDGE-…" unless caller supplies
  string from_work_id = 2;
  string to_work_id = 3;
  WorkEdgeType edge_type = 4;
  string rationale = 5;
  string dedupe_key = 6;       // required when edge_id not supplied (idempotency)
}

message WorkEdgeRemoved {
  string edge_id = 1;
  string from_work_id = 2;
  string to_work_id = 3;
  WorkEdgeType edge_type = 4;
  string rationale = 5;
}

message WorkEdgeWaived {
  string edge_id = 1;
  string from_work_id = 2;
  string to_work_id = 3;
  WorkEdgeType edge_type = 4;
  string waiver_id = 5;
  uint64 expires_at_ns = 6;
  string rationale = 7;
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

### 6.0 Protocol conventions (applies to all new RPCs)

To prevent replay/duplication drift (and to align with RFC-0019's idempotent actuation requirement), all state-mutating RPCs introduced by this RFC MUST define:

1. **Idempotency**: a deterministic dedupe key (explicit field or projection-enforced uniqueness) such that retrying the same request does not emit additional ledger events.
2. **Actor attribution**: `actor_id` is derived by daemon from credentials; request fields may carry display hints but are not authoritative.
3. **Atomicity boundary**:
   * for "CAS then ledger" operations, the daemon stores the canonical bytes to CAS first (idempotent by hash), then appends the ledger event.
   * if ledger append fails, the CAS object is allowed to exist "unreferenced" (garbage-collectable later); the daemon MUST NOT emit a partial ledger event that references a CAS hash that was not successfully stored.
4. **Sequence correctness for work transitions**:
   * any emission of `work.transitioned` MUST supply correct `previous_transition_count` as required by `apm2_core::work::WorkReducer` (monotone, fail-closed).

### 6.0.1 RPC contract: atomicity, idempotency, and error mapping (required)

Many of the new RPCs have the shape "store bytes in CAS, then append an anchoring ledger event."
Without explicit atomicity/idempotency rules, retries will produce divergent state and projections.

#### 6.0.1.1 Atomicity rule (daemon)

For any RPC that writes both CAS and ledger:

1. Canonicalize + validate input (fail fast).
2. Store artifact to CAS first (content addressed; duplicates are no-ops).
3. Append the anchoring ledger event second.

If step (3) fails, the CAS object may be orphaned, but the truth plane remains consistent.
The daemon MAY implement a best-effort orphan reaper, but correctness must not depend on it.

#### 6.0.1.2 Idempotency rules (per RPC)

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
  * `AddWorkEdge` is idempotent on `(from_work_id, to_work_id, edge_type, dedupe_key)`; daemon derives `edge_id` deterministically if not supplied.
  * `RemoveWorkEdge` and `WaiveWorkEdge` are idempotent by `edge_id`.

#### 6.0.1.3 Error mapping

Map to existing `PrivilegedErrorCode` variants in `proto/apm2d_runtime_v1.proto`:

* invalid schema / canonicalization failure / invalid hashes → `INVALID_ARGUMENT`
* missing work → `WORK_NOT_FOUND`
* missing session → `SESSION_NOT_FOUND`
* missing edge / missing artifact reference → `VALIDATION_FAILED`
* violates dependency closure / cycle detected / graph policy violation → `CAPABILITY_REQUEST_REJECTED`
* lease/role mismatch / role not authorized for operation → `CAPABILITY_DENIED` (or `PERMISSION_DENIED` when the caller lacks daemon-level privilege)
* idempotency conflict (same key, different content) → `VALIDATION_FAILED` (include a stable machine-readable reason string)

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

Requests (authorization + idempotency are explicit):

* `AddWorkEdgeRequest { from_work_id, to_work_id, edge_type, rationale, dedupe_key, lease_id }`
  * `lease_id` MUST be a valid `COORDINATOR` lease for `to_work_id` (see §7.6).
* `RemoveWorkEdgeRequest { edge_id, from_work_id, to_work_id, edge_type, rationale, lease_id }`
* `WaiveWorkEdgeRequest { edge_id, from_work_id, to_work_id, edge_type, expires_at_ns, rationale, lease_id }`

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

1. Validate + canonicalize `entry_json` (schema id + bounded decode).
2. Fill/overwrite daemon-authoritative fields (`entry_id`, `actor_id`, `created_at_ns`) and re-canonicalize.
   * `entry_id` MUST be derived deterministically from `(work_id, kind, dedupe_key)` per §4.0.1.
3. Store canonical bytes to CAS → `entry_hash`
4. Append `evidence.published` (protobuf `EvidencePublished`) with:
   * `category = WORK_CONTEXT_ENTRY`
   * `artifact_hash = entry_hash`
   * `artifact_size = len(canonical_entry_bytes)`
   * `classification = "INTERNAL"` (unless explicitly overridden by a policy-controlled surface)
   * `verification_command_ids = []` (work context entries are not verification results)
   * `metadata` includes `kind=<kind>` and `dedupe_key=<dedupe_key>` (for low-cost indexing)
5. Enforce idempotency on `(work_id, kind, dedupe_key)` via projection uniqueness; on duplicate, return success without emitting additional events.

**Note:** `EvidenceReducer` rejects duplicate `evidence_id`. This RFC requires `evidence_id = entry_id` (see §4.0.1).

### 6.5 RecordWorkPrAssociation (new)

Because the daemon does not speak GitHub, the CLI must supply PR info.

Request:

```proto
message RecordWorkPrAssociationRequest {
  string work_id = 1;
  uint64 pr_number = 2;
  string commit_sha = 3; // 40-hex; daemon validates
  string pr_url = 4;     // optional; stored as a linkout context entry when present
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

1. Canonicalize + validate JSON schema (`apm2.work_loop_profile.v1`) via the fac schema registry.
2. Reject empty `dedupe_key`.
3. Store canonical bytes to CAS → `profile_hash`
4. Append `evidence.published` with deterministic `evidence_id` derived from `(work_id, dedupe_key)` per §4.0.1, category `WORK_LOOP_PROFILE`, `evidence_hash=profile_hash`, and metadata containing `dedupe_key`.
5. Projections treat the latest anchored profile as active for `(work_id)`.

---

## 7. Work graph semantics and claimability enforcement

### 7.1 Edge type

Initial required edge type:

* `BLOCKS` (`WORK_EDGE_TYPE_BLOCKS`): prerequisite (`from_work_id`) must be `Completed` or waived before dependent (`to_work_id`) is implementer-claimable.

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

* **Edge IDs**
  * Caller MAY supply `edge_id`, otherwise daemon MUST derive:
    * `edge_id = "EDGE-" + blake3("WORK_EDGE" || from_work_id || to_work_id || edge_type || dedupe_key)`
  * `dedupe_key` required when caller does not supply `edge_id`.

* **Idempotency**
  * `AddWorkEdge` idempotent on `(from_work_id, to_work_id, edge_type, dedupe_key)`.
  * `RemoveWorkEdge` / `WaiveWorkEdge` idempotent by `edge_id`.

* **Cycle detection**
  * Reject edges creating cycles in the **active** BLOCKS graph (removed/waived edges excluded).
  * Implementation MUST be bounded and fail-closed on bound exceed.

### 7.5 Late edges and in-flight work (explicit policy)

If a `BLOCKS` edge is added where `to_work_id` is already `Claimed`/`InProgress`/`CiPending`:

* The edge is still recorded (history is append-only).
* The daemon MUST NOT auto-transition the work state (the `WorkReducer` state machine remains the only
  authority for work state transitions).
* Doctor output MUST surface the late edge as a high-severity diagnostic and recommend either:
  * adding a waiver, or
  * intentionally transitioning the work to `Blocked` via a policy-controlled system actor.

### 7.6 Edge mutation authorization (mandatory)

Work graph edits change claimability and therefore admission behavior. They are **not** implementer-controlled.

**Authorization rule:** edge mutations MUST require either:

1. an active `COORDINATOR` lease for `to_work_id`, provided in the request, or
2. a daemon-internal system actor.

**Audit rule:** actor identity is taken from the ledger envelope; clients MUST NOT set `actor_id` in payloads.

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
* `Review` → `Completed` (merge admission) or back to `InProgress` (rework loop)

**Repo alignment note:** `WorkState::can_transition_to` currently allows `Review -> InProgress` but does not allow `Review -> Blocked`. "Blocked" should remain CI/gate-centric; review failures are rework (`InProgress`) or escalation (`NeedsInput` / `NeedsAdjudication`) depending on policy.

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

* **This RFC's rule:** `apm2 fac push` MUST NOT emit any `work.transitioned` events. It publishes the latest changeset + required context markers only.

Instead:

* **CI processor responsibility:** a daemon-side CI processor observes `changeset_published` for the work's latest digest and emits:

  * `work.transitioned(InProgress -> CiPending)` as actor `"system:ci-processor"`
  * `work.transitioned(CiPending -> ReadyForReview)` **or** `work.transitioned(CiPending -> Blocked)` as actor `"system:ci-processor"` (these transitions are CI-restricted today by `WorkReducer`).

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

* work graph edges touch two work ids (and work_graph payloads MUST carry both ids so the deriver can be stateless)
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

* `determine_read_mode` selects `LedgerReadMode::LegacyLedgerEvents` when `ledger_events` exists and `events` is empty.

  * Canonical append APIs then fail-closed via `LedgerStorageError::LegacyModeReadOnly`.
  * If we copy into `events` without removing/renaming `ledger_events`, startup will fail fast with `LedgerReadModeError::AmbiguousSchemaState`.

  Phase 0 must therefore both (a) migrate rows and (b) eliminate the legacy table name from the active schema.

* The existing compat view `events_legacy_compat_v1` returns `NULL` for `prev_hash`/`event_hash`,
  which prevents core-ledger appenders from building a hash chain (`last_event_hash()` falls back to
  genesis when `event_hash` is NULL).

Migration requirements (implementation-grade):

1. **Single transaction, exclusive lock**
   * Acquire an exclusive SQLite transaction for the duration of the copy + hash-chain computation.

2. **Preserve ordering (legacy truth)**
   * Read `ledger_events` ordered by `rowid ASC` (matches legacy hash-chain ordering; see `backfill_hash_chain`).
   * Insert into `events` in the same order. `seq_id` is auto-assigned by `events`; ordering is what matters.

3. **Populate required core columns**
   * `record_version = 1`
   * `namespace = 'default'` (schema default)
   * `session_id`: parse for session events; else set `''` (empty string).
   * Leave `schema_digest`, `canonicalizer_id`, `consensus_*`, `hlc_*` NULL during migration.

4. **Compute a real 32-byte hash chain**
   * `event_hash = blake3(prev_hash || payload_bytes)` with genesis `prev_hash = 32x00`, via `apm2_core::crypto::EventHasher`.

5. **Signature handling (explicitly unverified)**
   * Copy signature bytes unchanged; do not attempt verification during migration.

6. **Eliminate ambiguous schema state**
   * Rename `ledger_events` to `ledger_events_legacy_frozen` (or export+drop) so `determine_read_mode` cannot enter `AmbiguousSchemaState`.

7. **Freeze legacy writers**
   * Hard-fail any codepath that tries to write the legacy emitter; new facts MUST append to `events`.

8. **Idempotency**
   * If `events` already contains rows, migration is a no-op.
   * If migration partially completed, fail fast (do not attempt to continue).

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

## 18. Resolved decisions and follow-ups

This RFC removes "open issue" blockers by making explicit vNext decisions.

### 18.1 Actor identity and signature mode

* Actor IDs remain daemon-derived strings (not verifying keys).
* Ledger writes run in unverified mode for vNext; signatures retained for tamper evidence.
* Verified actor identity is deferred to a dedicated identity RFC.

### 18.2 Canonical event naming and encoding convergence

* Work/evidence lifecycle: only `work.*`, `session.*`, `evidence.*` post-Phase-2; freeze legacy underscore lifecycle emissions.
* Kernel facts with underscore names may keep event_type strings, but payload encoding converges to protobuf in core ledger; JSON supported only for historical migrated rows.

### 18.3 Deterministic changeset bundle construction

* `apm2 fac push` MUST build changesets via `crates/apm2-core/src/fac/changeset_bundle.rs` and publish the computed digest + CAS hash.

### 18.4 Reducer configuration plumbing

* Keep `CI_SYSTEM_ACTOR_ID = "system:ci-processor"`; configurable reducer identities are out of scope.

### 18.5 Size bounds and schema validation

* Hard caps in §4.0 are mandatory and fail-closed.

### 18.6 Backfilling legacy WorkRegistry authority

* During Phase 6, backfill `WORK_AUTHORITY_BINDINGS` evidence for each active `work_claims` row.
* Missing boundary pins MUST be marked incomplete; incomplete claims are non-authoritative for new episode spawns until re-claimed under ClaimWorkV2.
