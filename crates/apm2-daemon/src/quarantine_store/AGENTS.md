# Quarantine Store Module

> Durable quarantine store with priority-aware eviction, per-session quota isolation, saturation-safe insertion, and restart-safe persistence (RFC-0028 REQ-0004, TCK-00496).

## Overview

The `quarantine_store` module implements the `QuarantineGuard` trait from `admission_kernel` with SQLite-backed persistence, priority-aware eviction, and per-session quota isolation. It provides fail-closed quarantine capacity reservation for the Forge Admission Cycle.

## Key Types

### `DurableQuarantineGuard` (store.rs)

Production implementation of `QuarantineGuard`. Wraps an in-memory `QuarantineStore` with SQLite persistence.

**Synchronization Protocol:**

- All mutable operations serialized through `Mutex<QuarantineStore>`.
- Lock ordering: inner `Mutex` first, SQLite connection `Mutex` second.
- Happens-before: `Mutex` release at end of `reserve()` establishes happens-before with subsequent calls.

**Invariants:**

- [INV-QS01] Persistence failure rolls back in-memory state (fail-closed).
- [INV-QS02] Missing SQLite backend = deny all reservations.
- [INV-QS03] Recovery loads persisted entries on construction.
- [INV-QS04] All collections bounded by `MAX_*` constants.
- [INV-QS05] `QuarantineGuard::reserve()` uses the caller-provided `session_id` for per-session quota isolation. No shared default session bucket exists.
- [INV-QS06] Evicted entries are removed from both in-memory store AND SQLite backend. `insert()` returns `InsertResult` containing `evicted_id` and `evicted_entry` which callers MUST propagate to `backend.remove_entry()`. Failure to do so causes ghost records that permanently consume capacity on restart. If the eviction-delete fails, the evicted entry MUST be restored to the in-memory store to maintain memory/DB parity.
- [INV-QS08] `load_all()` validates that `id > 0`, `created_at_tick >= 0`, `expires_at_tick >= 0`, and `expires_at_tick >= created_at_tick` before casting i64 to u64. Corrupted/tampered negative values are rejected as `PersistenceError` (fail-closed).
- [INV-QS07] `find_by_reservation_hash()` uses `subtle::ConstantTimeEq` with full linear scan (no short-circuit) to prevent timing side-channel leakage about reservation hash values (RSK-1909).

### `QuarantineStore` (store.rs)

In-memory store with `BTreeMap<EntryId, Entry>` and `HashMap<SessionId, count>`.

**Eviction Strategy:**

1. Expired entries evicted first (any priority, oldest first by ID).
2. Unexpired entries with priority strictly below incoming evicted next.
3. No evictable entry = deny insertion (fail-closed / saturation-safe).
4. `insert()` returns `InsertResult { entry_id, evicted_id }` — callers with persistence MUST delete the evicted entry from DB.

**Contracts:**

- [CTR-QS01] Per-session quota: max `MAX_PER_SESSION_ENTRIES` per session.
- [CTR-QS02] Global capacity: max `MAX_GLOBAL_ENTRIES` total entries.
- [CTR-QS03] Session tracking: max `MAX_TRACKED_SESSIONS` distinct sessions.
- [CTR-QS04] Input validation: session ID and reason bounded by `MAX_SESSION_ID_LENGTH` / `MAX_REASON_LENGTH`.
- [CTR-QS05] Unexpired entries with priority >= incoming are never evicted.
- [CTR-QS06] Reservation hash lookup uses constant-time comparison (`subtle::ConstantTimeEq`) to prevent timing attacks.

### `SqliteQuarantineBackend` (store.rs)

SQLite persistence layer with WAL mode and `synchronous=FULL`.

**Contracts:**

- [CTR-QS06] `load_all()` bounded by `MAX_GLOBAL_ENTRIES` (no memory exhaustion from corrupted DB).
- [CTR-QS07] String fields validated from DB on load (defense in depth).
- [CTR-QS08] Deterministic ordering by `id ASC` (rowid tiebreaker).

### `QuarantineEntry` (store.rs)

Entry with priority, HTF tick-based expiry, and audit binding fields (`request_id`, `bundle_digest`, `reservation_hash`).

### `QuarantinePriority` (store.rs)

Four-level priority: `Low(0)`, `Normal(1)`, `High(2)`, `Critical(3)`.

## Resource Limits

| Constant                  | Value | Purpose                     |
|---------------------------|-------|-----------------------------|
| `MAX_GLOBAL_ENTRIES`      | 4096  | Global capacity bound       |
| `MAX_PER_SESSION_ENTRIES` | 64    | Per-session quota isolation  |
| `MAX_SESSION_ID_LENGTH`   | 256   | Input validation (DoS)      |
| `MAX_REASON_LENGTH`       | 1024  | Input validation (DoS)      |
| `MAX_TRACKED_SESSIONS`    | 4096  | Session tracking bound      |
| `DEFAULT_TTL_TICKS`       | 3.6B  | 1 hour at 1MHz tick rate    |

## Production Wiring

`DurableQuarantineGuard` is wired into `AdmissionKernelV1` via `with_quarantine_guard()` in `DispatcherState::with_persistence_and_cas_and_key()` (state.rs). The quarantine database is co-located in the CAS directory for per-instance isolation.

## Security Properties

- Fail-closed on all error paths (storage, quota, saturation).
- No panics on untrusted input.
- BLAKE3 domain-separated reservation hashes (`apm2-quarantine-reservation-v1`).
- HTF tick-based expiry (monotonic `Instant`, not wall clock `SystemTime`).
- Bounded SQL queries prevent memory exhaustion from corrupted databases.
- Quarantine DB files created with 0600 permissions (owner-only access).
- Per-session quota isolation via caller-provided `session_id` (no shared default bucket).
- Constant-time hash comparison via `subtle::ConstantTimeEq` for reservation hash lookup (RSK-1909 timing side-channel prevention).
- Eviction-on-insert synchronizes both in-memory and SQLite backend, preventing ghost records that would cause permanent capacity loss on restart.

## Related Modules

- [`admission_kernel`](../admission_kernel/AGENTS.md) -- `QuarantineGuard` trait and kernel integration
- [`state`](../state.rs) -- Production wiring in `DispatcherState`

## References

- RFC-0028: Context Integrity and Admission Evidence
- REQ-0004: Priority-aware quarantine lifecycle
- TCK-00496: Implementation ticket
- TCK-00489: Priority-aware quarantine lifecycle with saturation-safe insertion (dependency)
