# orchestrator_kernel — Agent Instructions

## Purpose

`orchestrator_kernel` is the **canonical control-loop abstraction** for any daemon
orchestrator that reads the ledger incrementally and produces durable receipts.

The kernel enforces a strict four-phase contract:

```
Observe → Plan → Execute → Receipt
```

Any new orchestration loop that tails the ledger and emits receipts **MUST** use this
kernel.  Hand-rolled observe/plan/execute/receipt loops are a **MAJOR** code-quality
finding.

---

## Phase Contracts

| Phase   | Guarantee |
|---------|-----------|
| Observe | Reads ledger events strictly after a durable cursor; never re-processes the same span. |
| Plan    | Derives intents deterministically from folded state; same cursor → same intents. |
| Execute | Dispatches a bounded batch of intents behind effect-journal fencing; each intent is idempotent. |
| Receipt | Persists receipt events durably **before** advancing the cursor or acknowledging completion. |

---

## Non-Negotiable Invariants

### INV-OK-01 — Durable cursor (monotonic progression)
The cursor is persisted to a durable store before each tick completes.  Cursor
advancement must never happen before receipt durability for the same observed span.

### INV-OK-02 — Deterministic planning
Given identical cursor state and ledger input, the Plan phase MUST produce identical
intents.  No randomness, wall-clock reads, or external side-effects are permitted in
Plan.

### INV-OK-03 — Effect journal — fail-closed in-doubt resolution
An effect that is in-doubt (`Unknown` state in the journal) MUST be resolved via
`resolve_in_doubt` before the kernel emits a success receipt.  The default resolution
for unknown effects is **Deny** (fail-closed).  Domain-specific reconciliation is
allowed only when it can guarantee at-most-once semantics.

### INV-OK-04 — Bounded per-tick work
Every tick is bounded by `TickConfig::observe_limit` and `TickConfig::execute_limit`.
Unbounded loops inside a tick are forbidden.

### INV-OK-05 — No blocking operations on async executor
All storage I/O (SQLite, CAS, etc.) accessed from async tick paths MUST be offloaded
via `tokio::task::spawn_blocking` or equivalent.  Direct rusqlite calls on the tokio
thread pool are forbidden.

---

## Cursor Contract

Cursors are **ledger-specific**.  The kernel only requires `KernelCursor: Ord`.

- **`CompositeCursor` (`timestamp_ns` + `event_id`)** — default for timestamp-based
  ledgers.  `event_id` **MUST** be zero-padded to 20 digits (`canonical-{seq:020}`)
  so that lexicographic order matches sequence order.
- **Sequence / commit-index cursors** — valid for BFT or seq-indexed ledgers.
- **Mixing cursor types** across ledger readers in the same kernel instance is
  forbidden; the cursor type is fixed by the `LedgerReader::Cursor` associated type.

### Time rule — monotonic is a cache, not durable truth

`Instant`-derived (monotonic) timestamps are **process-local**.  They **MUST NOT**
be stored as durable truth and **MUST NOT** trigger irreversible actions after a
process restart (monotonic epoch resets on restart).

If monotonic values are persisted for performance caching, they **MUST** be rebased
on load using a wall-clock anchor (e.g. `GateLease.expires_at`).  See
`ObservedLeaseState::rebase` in `crates/apm2-daemon/src/gate/timeout_kernel.rs` as
the reference implementation.

---

## Storage Kit (daemon consumers)

Daemon orchestrators use the **`orchestrator_runtime` adapter kit** in
`crates/apm2-daemon/src/orchestrator_runtime/` for durable kernel storage.

**Required adapters (keyed by `orchestrator_id`):**

| Adapter | Table | Purpose |
|---------|-------|---------|
| `SqliteCursorStore` | `orchestrator_kernel_cursors` | Durable cursor persistence |
| `SqliteIntentStore` | `orchestrator_kernel_intents` | Durable intent buffer |
| `SqliteEffectJournal` | `orchestrator_kernel_effect_journal` | Effect idempotency journal |

**Forbidden patterns:**
- Per-orchestrator sqlite tables for cursor / intent / effect journal concerns.
- New `.sqlite` files for effect journals.
- Direct rusqlite calls on async paths without `spawn_blocking`.

---

## Reference Implementations

| Component | Location |
|-----------|----------|
| Gate timeout kernel | `crates/apm2-daemon/src/gate/timeout_kernel.rs` |
| Kernel trait types | `crates/apm2-core/src/orchestrator_kernel/types.rs` |
| Controller loop | `crates/apm2-core/src/orchestrator_kernel/controller_loop.rs` |

---

## Reviewer Checklist

When reviewing a PR that adds or modifies an orchestration loop:

1. Does it use `apm2_core::orchestrator_kernel`?  If not → MAJOR finding.
2. Does it use `orchestrator_runtime` adapters for cursor/intent/effect journal?  If not → MAJOR finding.
3. Are all rusqlite calls in `spawn_blocking`?  If not → MAJOR finding.
4. Are any persisted monotonic values rebased on load?  If not → MAJOR finding (INV-OK-TIME).
5. Are canonical event IDs zero-padded (`canonical-{seq:020}`)?  If not → MAJOR finding.
