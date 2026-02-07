# Technical Proposal: WorkObject Ledger Cutover (Filesystem Ticket Exit)

Date: 2026-02-07
Authoring Context: FAC acceleration, WorkObject-first migration, xtask authority reduction, HTF-constrained cutover

## 1. Summary

This proposal defines a non-RFC technical implementation plan to:

1. Remove runtime dependency on filesystem `TCK-*.yaml` tickets.
2. Make `WorkObject` the canonical unit of merged code (one merge unit, usually one PR).
3. Store work lifecycle in a shared ledger-backed path (starting with current daemon SQLite ledger).
4. Reduce `xtask` authority in RFC-0019 staged mode while converging operator workflows to daemon-backed `apm2 fac`.
5. Preserve replayability and boundary authority at scale (receipt-first interfaces, selector-based evidence access, no ambient runtime truth).

This is an implementation blueprint, not a full RFC rewrite.

## 2. RFC Pin Recommendation

Recommendation: **pin this work to RFC-0019** as an implementation addendum/change package.

Why RFC-0019:

1. RFC-0019 is already `APPROVED` and is the active FAC automation substrate.
2. The target lifecycle (claim -> episode -> gate/review -> merge/projection) is already encoded there.
3. This cutover is primarily execution substrate convergence, not a new product protocol family.

Why not use other RFCs as primary pin:

1. RFC-0015 is still `DRAFT` and focused on hardening semantics.
2. RFC-0014 is foundational for distributed consensus, but this cutover starts on current daemon SQLite path.
3. RFC-0020 and RFC-0021 are `DRAFT` and should remain secondary references until stabilized.

Secondary references:

1. RFC-0014 for future multi-node/shared consensus backend.
2. RFC-0020 for interface discipline once HSI contracts are finalized.

## 3. Problem Statement

Current work management is fragmented across three abstractions:

1. Filesystem ticket YAML (`documents/work/tickets/TCK-*.yaml`) used heavily by `xtask`.
2. `apm2-holon` `WorkObject` (`crates/apm2-holon/src/work.rs`), rich lifecycle/attempt model.
3. `apm2-core` reducer `Work` (`crates/apm2-core/src/work/*`), event-sourced work projection model.

Operational issues:

1. Runtime FAC flow does not use filesystem tickets as system of record.
2. `xtask` is a separate operational plane and slows autonomous flow.
3. Daemon event model (`work_claimed`/`work_transitioned`) and core reducer model (`work.opened`/`work.transitioned`) are not fully converged.
4. Intent sources (RFC, bug stream, oracle directive, agent request) are not unified into one ledger-native path.

## 4. Goals

1. **Canonicalize WorkObject** as the primary runtime work unit.
2. **Ledger as truth** for work state and transitions; no filesystem truth for runtime scheduling.
3. **Intent-to-merge pipeline** fully automatable through daemon/CLI APIs.
4. **Reduce then remove xtask dependency** for ticket/work lifecycle control paths according to RFC-0019 staged authority reduction.
5. Keep compatibility only where needed for transition visibility and traceability.

## 5. Non-Goals

1. Full multi-node consensus cutover in this phase.
2. Rewriting all historical RFC decomposition artifacts.
3. Deleting all YAML docs immediately; only runtime dependence is targeted.
4. Full FAC hardening redesign beyond existing RFC-0019 contracts.

## 6. Canonical Model: WorkObjectV1

`WorkObjectV1` becomes canonical for runtime work management. One object corresponds to one merge candidate unit.

Required fields:

1. `work_id` (stable, `W-<uuid>`)
2. `intent_id` (source intent linkage)
3. `work_kind` (`code_change`, `review`, `policy_update`, `ops_change`)
4. `state`
5. `title`
6. `source_kind` (`rfc_requirement`, `oracle_directive`, `bug_report`, `defect_stream`, `holon_request`, `aat_request`)
7. `source_ref` (opaque stable reference)
8. `requirement_ids` (traceability)
9. `parent_work_ids`
10. `dependency_work_ids`
11. `lease_id` (required for `CLAIMED` and all downstream executable states)
12. `session_id` (required once episode starts)
13. `changeset_digest` (required at/after publish)
14. `pr_ref` (provider + repo + PR number + head SHA)
15. `evidence_refs` (CAS hashes)
16. `capability_manifest_hash` (delegated authority binding; required for executable episodes)
17. `context_pack_hash` (bounded context binding; required for executable episodes)
18. `stop_condition_hash` (required stop-order gate binding)
19. `budgets` (typed quantities; no naked integers)
20. `policy_resolved_ref` (stable binding to policy resolution)
21. `permeability_receipt_hash` (explicit delegated authority entry)
22. `view_commitment_hash` (required for replayable review/projection outcomes)
23. `tool_log_index_hash` (required once tool execution occurs)
24. `summary_receipt_hash` (required for scalable supervision surfaces)
25. `time_envelope_ref` (HTF authority binding for authoritative transitions/receipts)
26. `issued_at_tick` (optional, required for lease/gate semantics)
27. `tick_rate_hz` (optional, required when tick fields are present)
28. `ticket_alias` (optional `TCK-XXXXX` tracking alias; non-authoritative)
29. `created_at_ns`, `updated_at_ns` (observational metadata only)
30. `version` (monotone object version)

### 6.1 Temporal Authority Rule (HTF)

1. Authoritative lifecycle transitions MUST bind `time_envelope_ref`.
2. `time_envelope_ref` MUST resolve to a CAS `cac.time_envelope.v1` artifact, not an in-memory-only value.
3. Resolved envelopes MUST pin `clock_profile_hash`; profile admissibility MUST be policy-checked by risk tier before transition acceptance.
4. Tick-based lease/gate semantics MUST use HTF ticks (`issued_at_tick` + `tick_rate_hz`) when evaluated.
5. Ledger ordering authority MUST come from envelope ledger anchor + ledger sequence, not wall timestamps.
6. `created_at_ns` and `updated_at_ns` are observational only and MUST NOT be used for protocol authority.

`WorkObject` state baseline:

1. `OPEN`
2. `CLAIMED`
3. `IN_PROGRESS`
4. `CI_PENDING`
5. `READY_FOR_REVIEW`
6. `REVIEW`
7. `NEEDS_INPUT`
8. `NEEDS_ADJUDICATION`
9. `COMPLETED`
10. `ABORTED`
11. `BLOCKED`

State semantics should remain compatible with current `apm2-core` `WorkState` where possible.

### 6.2 State Compatibility Matrix (Mandatory)

1. Maintain explicit mapping between `apm2-holon::work`, `apm2-core::work`, and `WorkObjectV1`.
2. `MERGE_PENDING` is a projection/view alias only (derived from review-passed + merge-queue pending), not a canonical lifecycle state.
3. Every adapter transition MUST be monotonic and replay-equivalent under ledger rebuild.
4. Any unmapped state or non-monotonic transition is fail-closed and emits a structured defect event.

Reference mapping matrix (minimum required rows):

| `apm2-holon::WorkLifecycle` | `apm2-core::WorkState` | `WorkObjectV1.state` | Notes |
| --- | --- | --- | --- |
| `Created` | `OPEN` | `OPEN` | Newly admitted, claimable |
| `Leased` | `CLAIMED` | `CLAIMED` | Requires valid lease + delegation bindings |
| `InProgress` | `IN_PROGRESS` | `IN_PROGRESS` | Execution active |
| `InProgress` | `CI_PENDING` | `CI_PENDING` | CI gate pending; claimability false |
| `InProgress` | `READY_FOR_REVIEW` | `READY_FOR_REVIEW` | CI passed; review claimable |
| `InProgress` | `REVIEW` | `REVIEW` | Review execution phase |
| `Blocked` | `BLOCKED` | `BLOCKED` | Bounded failure/liveness pause |
| `Blocked` | `NEEDS_INPUT` | `NEEDS_INPUT` | External info dependency |
| `Escalated` | `NEEDS_ADJUDICATION` | `NEEDS_ADJUDICATION` | Supervisor decision required |
| `Completed` | `COMPLETED` | `COMPLETED` | Terminal success |
| `Failed`/`Cancelled` | `ABORTED` | `ABORTED` | Terminal non-success |

### 6.3 Authority and Boundary Contract (Mandatory)

1. Transition acceptance into `CLAIMED` or beyond requires: `lease_id`, `permeability_receipt_hash`, `capability_manifest_hash`, `context_pack_hash`, `stop_condition_hash`, and typed `budgets`.
2. Review/projection outcomes require: `view_commitment_hash`, `tool_log_index_hash`, `summary_receipt_hash`, and `policy_resolved_ref` bindings.
3. Missing required bindings are fail-closed and MUST emit durable defect records; best-effort success is forbidden.
4. All boundary hashes must be CAS-resolvable during validation, not deferred.

### 6.4 Scale Envelope and Evidence Economics

1. Inter-holon/operator interfaces are digest-first: status surfaces carry hashes/selectors, not raw transcripts.
2. Supervisory workflows consume `summary_receipt_hash` first; zoom-in is by selector to CAS evidence.
3. Projections are non-authoritative and replay-rebuildable from ledger+CAS only.
4. Replay budgets and anti-entropy posture must assume exabyte-scale evidence and continuous partial-failure recovery.

## 7. Shared Ledger Strategy (Phase 1)

Use existing daemon SQLite ledger path immediately. Authority remains append-only ledger events; projections are derived.

### 7.1 Authority

1. `ledger_events` is authoritative sequence of facts.
2. `work_objects_projection` is a rebuildable projection table.
3. No runtime scheduler reads filesystem tickets.

### 7.2 New/Updated Projection Tables

1. `work_objects_projection`
2. `work_dependencies_projection`
3. `intent_projection`
4. `work_transition_audit_projection`

All projection tables are replay-derived and safe to rebuild.

### 7.3 Event Naming Convergence

Canonical target: converge semantics across three active families while preserving replay identity:

1. daemon ledger events (underscore): `work_claimed`, `work_transitioned`.
2. core reducer events (dotted): `work.opened`, `work.transitioned`, `work.completed`, `work.aborted`.
3. kernel typed events (protobuf): `WorkOpened`, `WorkTransitioned`, `WorkCompleted`, `WorkAborted`.

Transitional policy:

1. Continue reading existing daemon events for compatibility.
2. Emit canonical reducer/typed events in parallel during migration.
3. Enforce parity checks using actual mappings:
   - `work_claimed` -> `work.transitioned` with `OPEN -> CLAIMED` (there is no canonical `work.claimed` event).
   - `work_transitioned` -> `work.transitioned` with state/rationale/sequence equivalence.
   - reducer `work.transitioned` payload -> protobuf `WorkTransitioned` field-equivalence.
4. Parity checks MUST include sequence monotonicity (`previous_transition_count`) and actor attribution equivalence.
5. Retire legacy underscore event names only after replay-equivalence tests pass for two consecutive cutover windows.
6. Any parity failure blocks promotion and emits a defect record with offending event ids and mapping class.

## 8. Intent-to-Merge Pipeline

### 8.1 Intent Ingestion

New logical artifact: `IntentEnvelopeV1` (CAS-addressed), containing:

1. source metadata
2. normalized objective
3. scope constraints
4. optional requirement bindings
5. priority/risk hints

Ledger event: `intent.ingested` (or equivalent canonical type).

### 8.2 Work Creation

`WorkObject` created from intent by policy-governed compiler/orchestrator:

1. `OPEN` work object emitted to ledger.
2. dependency edges created in projection.
3. scheduler chooses next claimable object.

### 8.3 Execution

1. claim -> lease issuance -> `CLAIMED`
2. spawn episode -> `IN_PROGRESS`
3. changeset publication -> `CI_PENDING`
4. gate/review receipts -> `READY_FOR_REVIEW` / `REVIEW` / `NEEDS_INPUT`
5. merge receipt -> `COMPLETED`

## 9. API and Protocol Changes

### 9.1 Privileged Daemon APIs (add)

1. `IngestIntent`
2. `OpenWorkObject`
3. `ClaimNextWork`
4. `TransitionWorkObject`
5. `AttachPullRequest`
6. `ListWorkObjects` (filter by state/source/age)
7. `GetWorkGraph`

### 9.2 Existing APIs (adjust)

1. `ClaimWork`: should operate on canonical ledger-projected claimable `WorkObject`.
2. `WorkStatus`: read from `work_objects_projection`, not session/work_claim registry-only logic.

### 9.3 CLI Surface

Primary operator path should live in `apm2`:

1. `apm2 fac intent ingest ...`
2. `apm2 fac work claim-next ...`
3. `apm2 fac work list/status ...`
4. `apm2 fac work transition ...`

## 10. xtask Authority Reduction Plan (RFC-0019 Staged)

`xtask` must stop being the control plane for work lifecycle.

### 10.1 Immediate Stop-Using Areas

1. `start-ticket` as runtime scheduler input.
2. ticket status derivation from git branches/PR names.
3. push/check/finish dependency on filesystem ticket state.

### 10.2 Replacement Path (Staged Authority Demotion)

1. Stage 1 (`REQ-0007`): keep xtask path available behind explicit write controls; every write path MUST emit durable projection receipts.
2. Stage 2 (`REQ-0007`): default xtask behavior becomes projection-request/receipt mode; direct writes disabled by default.
3. Stage 3 (`REQ-0007`): direct write path removed or restricted to local/dev breakglass only; runtime lifecycle control path is `apm2 fac`.
4. RoleSpec and skill instruction surfaces are cut over to `apm2 fac` lifecycle semantics in lockstep with Stage 2 defaults.
5. If command naming is still evolving, use a thin `apm2 fac` compatibility shim (not lifecycle logic in xtask) with explicit deprecation horizon.

### 10.3 Hard Exit Criteria

1. no production workflow requires `cargo xtask`.
2. no authoritative work state read from `documents/work/tickets`.
3. `xtask` can be removed without losing merge automation.
4. active RoleSpec templates and agent skills are hash-rotated/updated to `apm2 fac` lifecycle commands.
5. CI lint blocks reintroduction of `cargo xtask` lifecycle calls in instruction assets.
6. RFC-0019 `REQ-0007` staged demotion acceptance criteria are satisfied without active waiver.

## 11. TCK Nomenclature Observation Window (Ledger-Authoritative)

Observation policy:

1. Keep `TCK-*` as human/operator identifiers for a 72-hour human-facing observation window after cutover.
2. YAML tickets are optional snapshots/metadata only; runtime authority remains ledger/CAS.
3. No runtime component reads ticket YAML for claimability, ordering, or state transitions.
4. Observation-window gate decisions are based on ledger windows and HTF tick spans; wall-time labels are operator overlays only.
5. Observation-window exit criteria:
   - zero runtime lifecycle reads from filesystem tickets,
   - zero reconciliation mismatches between `ticket_alias` and `work_id` projections,
   - no open sev1/sev2 defects in cutover surfaces,
   - no authoritative admission/gate decision consuming wall-time values.
6. After exit criteria pass, remove snapshot emitters and keep `ticket_alias` only as historical trace field.

## 12. Migration Phases

### Phase 0: Foundations

1. Define WorkObjectV1 canonical schema and mapping.
2. Add projection table set and replay builder.
3. Add intent envelope schema + ingestion endpoint.
4. Complete fail-closed publish/ingest baseline (`TCK-00412`) and drift guards (`TCK-00409`).
5. Verify HTF prerequisites in cutover path (`TCK-00239`, `TCK-00240`, `TCK-00241`, `TCK-00246`) are active or explicitly tracked as blocking dependencies.

### Phase 1: Runtime Cutover

1. Route `ClaimWork` and `WorkStatus` to projection-backed data.
2. Emit converged canonical work events.
3. Stop daemon/runtime dependency on filesystem tickets.
4. Enforce fail-closed side-effect cutover + durable projection ack (`TCK-00408`).
5. Close residual instruction/status-write drift in executable prompts/contracts (`TCK-00411`).
6. Enforce mandatory authority bindings (`capability_manifest_hash`, `context_pack_hash`, `stop_condition_hash`, typed budgets, permeability receipt) in transition contract.

### Phase 2: CLI Cutover + xtask Stage-2 Default

1. Provide full `apm2 fac` parity for active xtask workflows.
2. Set xtask to projection-request/receipt default with explicit write override only.
3. Mark xtask commands deprecated and block new ticket-lifecycle logic there.
4. Run FAC-local deterministic gate execution path and projection-only GitHub updates (`TCK-00410`).

### Phase 3: Model Convergence + xtask Stage-3 Exit

1. Complete convergence between daemon event path and `apm2-core::work` reducer contracts.
2. Consolidate duplicate work abstractions to one canonical object + adapters.
3. Remove legacy event name aliases after parity windows pass.
4. Remove or localize xtask write-path authority (Stage 3) once hard exit criteria are met.

## 13. Test and Verification Plan

### 13.1 Unit

1. WorkObject state transition validity.
2. Projection replay determinism from event streams.
3. Dependency/claimability rules.
4. HTF binding validation: transitions lacking required `time_envelope_ref` are rejected.
5. State-mapping tests: holon/core/workobject mappings are total, deterministic, and monotonic.
6. Authority-binding tests: transitions missing required delegation/context/stop/budget fields are rejected fail-closed.
7. Envelope validation tests: `time_envelope_ref` must resolve in CAS and pin an admissible `clock_profile_hash`.
8. Event mapping tests: underscore/dotted/protobuf families remain semantically equivalent under adapters.

### 13.2 Integration

1. intent ingestion -> open work -> claim -> spawn -> review -> merge completion.
2. restart/replay rebuilds identical projection state.
3. no filesystem ticket reads in runtime claim path.
4. authoritative transitions and terminal receipts carry valid HTF envelope references.
5. staged xtask behavior matches RFC-0019: explicit-write controls in Stage 1, projection-request default in Stage 2.
6. RoleSpec + skill instruction surfaces execute only approved lifecycle commands (`apm2 fac`) in default paths.

### 13.3 Regression

1. existing FAC E2E still passes.
2. `WorkStatus` reflects ledger truth under concurrent operations.
3. mixed old/new event readers remain correct during transition.
4. state mapping remains replay-equivalent across migration toggles.
5. projection idempotency remains stable under retries/restarts and partial failures.
6. no wall-time authority regressions in admission/gate/reducer paths.

### 13.4 Scale and Evidence-Economics Verification

1. Selector-first status surfaces remain bounded under large evidence sets (no transcript fan-out in control plane).
2. Summary receipt verification time remains sublinear relative to raw evidence volume.
3. Replay from checkpointed ledger heads converges without side-effect duplication.
4. Anti-entropy/rebuild drills validate recoverability from partial projection loss using only ledger+CAS.

## 14. Risks and Mitigations

1. **Risk:** event-contract divergence between daemon and core.
   Mitigation: canonical event alias layer + replay equivalence tests.
2. **Risk:** losing operator ergonomics when xtask is removed.
   Mitigation: RFC-0019 staged demotion with explicit breakglass and measured Stage 3 exit.
3. **Risk:** partial migration with two truths.
   Mitigation: strict rule that runtime reads ledger/projection only.
4. **Risk:** migration churn in CI/review automation.
   Mitigation: staged cutover flags and temporary wrappers.
5. **Risk:** authority-binding omissions create silent policy bypasses.
   Mitigation: mandatory binding validation + fail-closed defects on missing hashes/receipts.
6. **Risk:** wall-time leakage re-enters authority paths.
   Mitigation: HTF envelope/profile enforcement and lint/test gates inherited from RFC-0016.

## 15. Acceptance Criteria

1. New work can be created and completed with zero filesystem ticket reads in runtime.
2. `WorkObject` is the canonical merge unit in daemon/CLI flows.
3. `WorkObject` transition contracts enforce mandatory authority bindings (`lease_id`, delegation/context/stop/budget hashes, policy refs, view commitments).
4. `apm2 fac` provides replacement of active xtask lifecycle commands.
5. xtask authority reduction follows RFC-0019 staged semantics (`REQ-0007`) and reaches Stage 3 exit criteria.
6. `xtask` is removable (or local/dev-only) without breaking intent-to-merge automation.
7. no authoritative work state is sourced from filesystem tickets.
5. Proposal is tracked as RFC-0019 implementation addendum with explicit ticket/work plan.
8. RoleSpec and SKILL instruction surfaces are cut over in lockstep with runtime (no split-brain operator instructions).
9. No authoritative lifecycle transition can be committed without HTF authority binding where required by event contract.
10. HTF envelope validation includes CAS resolution + `clock_profile_hash` pinning/policy admissibility checks.
11. Event-family parity and replay-equivalence checks pass with zero unresolved defects in `TCK-00408/410/411/412` scope.
12. Scale-facing verification passes: summary-first supervision, replay-safe projection, and bounded control-plane payload behavior under large evidence sets.

## 16. Recommended Tracking Shape (Non-RFC)

Track this document as an RFC-0019 implementation package:

1. Root proposal (this file) for engineering execution.
2. Ticket/work package linked to RFC-0019 using `TCK-004xx` nomenclature through the observation window; revisit ledger-native naming only after exit criteria pass.
3. No new standalone RFC required unless protocol boundaries materially change.
