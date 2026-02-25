title: OrchestratorKernel Architecture Doctrine
status: active

## Purpose

This document defines the required architecture for APM2 orchestrators that tail
ledger events and produce durable effects/receipts.

The canonical control-loop shape is:

`Observe -> Plan -> Execute -> Receipt`

Implemented by `apm2_core::orchestrator_kernel`.

## Kernel Contract

1. `LedgerReader` is the authoritative read boundary for ordered observations.
2. `OrchestratorDomain` is deterministic and pure with respect to observed data.
3. `EffectJournal` enforces idempotent effect execution and fail-closed
   `resolve_in_doubt` behavior.
4. `CursorStore` advances only after durable receipt persistence for the same
   observation span.
5. `TickConfig` bounds per-tick observe/execute work.

## Cursor Doctrine

Cursor type is ledger-specific and must match ledger ordering truth.

- Use `KernelCursor` (total order required).
- `CompositeCursor` is valid for `(timestamp_ns, event_id)` ledgers.
- Sequence/commit-index cursors are preferred when the ledger is sequence-native.
- Kernel consumers must not assume timestamp cursors by default.

## Daemon Storage Doctrine

Daemon orchestrators must use `crates/apm2-daemon/src/orchestrator_runtime`:

- `SqliteCursorStore` -> `orchestrator_kernel_cursors`
- `SqliteIntentStore` -> `orchestrator_kernel_intents`
- `SqliteEffectJournal` -> `orchestrator_kernel_effect_journal`

All adapters are keyed by stable `orchestrator_id`.

Per-orchestrator sqlite tables/files for cursor/intent/effect-journal concerns are
forbidden.

## Ledger Polling Doctrine

Any canonical+legacy merge read must use
`crates/apm2-daemon/src/ledger_poll.rs`.

Required helpers:

- `canonical_event_id(seq_id) -> canonical-{seq_id:020}`
- `poll_events_blocking(...)`
- `poll_events_async(...)`

Hand-rolled merge SQL in orchestrators is forbidden.

## Time Doctrine

Monotonic timestamps (`Instant`-derived values) are process-local and not durable
truth.

If monotonic values are persisted for cache performance, they must be rebased on
load using wall-clock authority before any irreversible action.

Reference implementation:
`crates/apm2-daemon/src/gate/timeout_kernel.rs` (`ObservedLeaseState::rebase`).

## CAS and Ledger Composition

- Large payloads belong in CAS.
- Ledger events/intents carry stable references (digest/id), not full mutable
  payload copies.
- Receipt verification and evidence anchoring happen before cursor advancement.

## Migration Pattern for Existing Loops

1. Model existing loop as `OrchestratorDomain`.
2. Lift poller to `ledger_poll` helper.
3. Replace local cursor/intent/effect storage with orchestrator_runtime adapters.
4. Add one-time idempotent migration from legacy storage artifacts.
5. Add replay/idempotency tests and malformed-row progress tests.

## Grep Anchors for Review

- `run_tick`
- `LedgerReader`
- `orchestrator_runtime`
- `orchestrator_kernel_cursors`
- `orchestrator_kernel_intents`
- `orchestrator_kernel_effect_journal`
- `poll_events_async`
- `canonical_event_id`
- `MONO_EPOCH`
