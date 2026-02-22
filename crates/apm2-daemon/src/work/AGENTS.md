# Work Module

> Work lifecycle authority with projection-backed status and alias reconciliation.

## Overview

The `work` module provides projection-backed lifecycle authority for work items within the daemon. All runtime authority decisions come from ledger-backed projections only -- filesystem ticket YAML is explicitly non-authoritative. The module implements:

- **`WorkAuthority` trait**: Projection-derived status queries and claimability checks
- **`ProjectionWorkAuthority`**: Implementation that rebuilds state from ledger events via `WorkReducer`
- **`WorkObjectProjection`**: Ledger-event projection with deterministic replay ordering
- **`AliasReconciliationGate`**: Alias reconciliation for the promotion gate (TCK-00420)

## Key Types

### `WorkAuthority` (trait)

```rust
pub trait WorkAuthority: Send + Sync {
    fn get_work_status(&self, work_id: &str) -> Result<WorkAuthorityStatus, WorkAuthorityError>;
    fn list_claimable(&self, limit: usize, cursor: &str) -> Result<Vec<WorkAuthorityStatus>, WorkAuthorityError>;
    fn list_all(&self, limit: usize, cursor: &str) -> Result<Vec<WorkAuthorityStatus>, WorkAuthorityError>;
    fn is_claimable(&self, work_id: &str) -> Result<bool, WorkAuthorityError>;
}
```

Work lifecycle authority contract. Provides projection-derived status queries.

**Invariants:**

- [INV-WK01] Authority is derived from ledger events only; filesystem state is never consulted.
- [INV-WK02] `list_claimable()` and `list_all()` are bounded to `MAX_WORK_LIST_ROWS` (500).

### `ProjectionWorkAuthority`

```rust
pub struct ProjectionWorkAuthority {
    event_emitter: Arc<dyn LedgerEventEmitter>,
    projection: Arc<RwLock<WorkObjectProjection>>,
    last_event_count: Arc<RwLock<usize>>,
}
```

Projection-backed `WorkAuthority` implementation. Cached projection is only rebuilt when the event count changes.

**Contracts:**

- [CTR-WK01] Projection is rebuilt lazily -- only when the emitter reports a different event count.
- [CTR-WK02] Full replay is O(N) but amortized by caching.

### `WorkAuthorityStatus`

```rust
pub struct WorkAuthorityStatus {
    pub work_id: String,
    pub state: WorkState,
    pub claimable: bool,
    pub created_at_ns: u64,
    pub last_transition_at_ns: u64,
    pub transition_count: u32,
    pub claimed_at_ns: Option<u64>,
}
```

Projection-derived authority view for a single work item.

### `WorkObjectProjection`

```rust
pub struct WorkObjectProjection {
    reducer: WorkReducer,
    ordered_work: BTreeMap<String, Work>,
}
```

Ledger-backed work object projection rebuilt through `WorkReducer`.

**Invariants:**

- [INV-WK03] Events are replayed deterministically by `(timestamp_ns, seq_id, original_index)`.
- [INV-WK04] Signature verification is fail-closed: events with invalid signatures are rejected.

**Contracts:**

- [CTR-WK03] `rebuild_from_events()` resets reducer and replays in deterministic order.
- [CTR-WK04] `rebuild_from_signed_events()` translates signed events before replay.

### `WorkProjectionError`

```rust
pub enum WorkProjectionError {
    Reducer(WorkError),
    InvalidPayload { event_type: String, reason: String },
    InvalidTransitionCount { event_type: String, value: u64 },
    SignatureVerificationFailed { event_id: String, reason: String },
}
```

### `WorkAuthorityError`

```rust
pub enum WorkAuthorityError {
    ProjectionLock { message: String },
    ProjectionRebuild(WorkProjectionError),
    WorkNotFound { work_id: String },
}
```

### `AliasReconciliationGate` (trait)

Wires the `apm2_core::events::alias_reconcile` module into the daemon work authority layer for reconciliation, promotion gating, and snapshot-emitter sunset evaluation.

**Methods:**

- `check_promotion()` -- Validates alias bindings for promotion eligibility (fail-closed on ambiguity)
- `resolve_ticket_alias()` -- Resolves a ticket alias to a canonical `work_id` via projection state (TCK-00636). Default implementation returns `Ok(None)` for backward compatibility. `ProjectionAliasReconciliationGate` overrides with CAS-backed `WorkSpec` lookup when a CAS store is configured.

### `ProjectionAliasReconciliationGate`

Projection-backed alias reconciliation gate implementation. Bridges the alias reconciliation module to the daemon work authority layer.

**Fields:**

- `projection` -- Shared `WorkObjectProjection` rebuilt from ledger events
- `event_emitter` -- Ledger event emitter for projection refresh
- `cas` -- Optional CAS store for `WorkSpec` retrieval (TCK-00636)

**Contracts:**

- [CTR-AG01] `build_canonical_projections()` enriches alias projections with CAS-backed `ticket_alias` -> `work_id_hash` mappings when CAS is available (TCK-00636).
- [CTR-AG02] `resolve_ticket_alias()` scans work items (bounded by `MAX_WORK_LIST_ROWS`), performs CAS lookup for each `spec_snapshot_hash`, and returns the matching `work_id` or `Err` on ambiguity (fail-closed).
- [CTR-AG03] CAS miss or malformed `WorkSpec` for individual work items is treated as skip (not hard error), maintaining fail-closed semantics at the aggregate level.

## Public API

- `WorkAuthority` (trait), `ProjectionWorkAuthority`
- `WorkAuthorityStatus`, `WorkAuthorityError`
- `WorkObjectProjection`, `WorkProjectionError`
- `MAX_WORK_LIST_ROWS`: 500

## Related Modules

- [`apm2_daemon::protocol`](../protocol/AGENTS.md) -- Privileged dispatch for `ClaimWork`, `WorkStatus`, `WorkList`
- [`apm2_daemon::gate`](../gate/AGENTS.md) -- Gate orchestrator triggers on work state transitions
- [`apm2_core::work`](../../../apm2-core/src/work/AGENTS.md) -- Core `Work`, `WorkReducer`, `WorkState` types
- [`apm2_core::reducer`](../../../apm2-core/src/reducer/AGENTS.md) -- Reducer framework for event-sourced state

## References

- RFC-0017: Daemon as Control Plane -- work lifecycle management
- RFC-0019: Automated FAC v0 -- work claim and completion flow
- TCK-00415: Work lifecycle authority module
- TCK-00420: Alias reconciliation gate
- TCK-00636: RFC-0032 Phase 1 WorkSpec projection plumbing + ticket-alias reconciliation integration (CAS-backed `resolve_ticket_alias`, `with_cas()` builder, enriched `build_canonical_projections`)
