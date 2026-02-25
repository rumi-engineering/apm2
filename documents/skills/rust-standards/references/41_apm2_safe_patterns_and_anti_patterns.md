title: 41. APM2 Safe Patterns and Anti-Patterns

## Safe Pattern: Kernelized Orchestrator Loop

Use `apm2_core::orchestrator_kernel` for all ledger-tailing orchestration loops.

Checklist:

- `LedgerReader` returns events ordered by the selected `KernelCursor`.
- `CursorStore` durability is keyed by stable `orchestrator_id`.
- `IntentStore` is idempotent (`INSERT OR IGNORE` semantics).
- `EffectJournal` enforces fail-closed ambiguity handling (`resolve_in_doubt`).
- Cursor is persisted only after receipt durability.

Preferred daemon adapters:

- `crates/apm2-daemon/src/orchestrator_runtime/sqlite.rs`
- Tables: `orchestrator_kernel_cursors`, `orchestrator_kernel_intents`,
  `orchestrator_kernel_effect_journal`.

## Safe Pattern: Shared Freeze-Aware Polling

Use `crates/apm2-daemon/src/ledger_poll.rs` for any merge of legacy
`ledger_events` and canonical `events`.

Required helpers:

- `canonical_event_id(seq_id)` (zero-padded lexical ordering)
- `poll_events_blocking(...)`
- `poll_events_async(...)`

## Anti-Pattern: Bespoke Orchestration Loop

Do not implement ad-hoc observe/plan/execute/receipt loops that bypass
`orchestrator_kernel`.

Why this is unsafe:

- Inconsistent idempotency windows.
- Cursor advancement race windows.
- Divergent fail-closed behavior across orchestrators.

## Anti-Pattern: Per-Orchestrator SQLite Stores

Do not create new tables/files such as:

- `*_cursor`
- `*_intent*`
- custom `*_effect_journal*.sqlite`

Use shared runtime adapters keyed by `orchestrator_id` instead.

## Anti-Pattern: Blocking SQLite in Async Paths

Do not run `rusqlite` directly on tokio async execution paths.

Use `spawn_blocking` wrappers provided by runtime adapters/pollers.

## Anti-Pattern: Persisted Monotonic as Durable Truth

`Instant`/monotonic timestamps are process-local and reset on restart.

Do not trigger irreversible decisions from persisted monotonic values without
rebase-on-load against wall-clock authority.

Reference grep anchors:

- `observed_monotonic_ns`
- `deadline_monotonic_ns`
- `MONO_EPOCH`
- `Instant::now`

## Reviewer Quick Anchors

- `run_tick`
- `orchestrator_runtime`
- `ledger_poll`
- `canonical_event_id`
- `orchestrator_kernel_cursors`
- `orchestrator_kernel_intents`
- `orchestrator_kernel_effect_journal`
