# Projection Module

> Write-only projection adapters for synchronizing ledger state to external systems.

## Overview

The `projection` module implements write-only projection adapters that synchronize ledger state to external systems, primarily GitHub. The key design principle is that the ledger is always the source of truth -- projections are one-way writes that never read external state as authoritative.

### Components

- **`ProjectionWorker`**: Long-running worker that tails the ledger for `ReviewReceiptRecorded` events and projects review results to GitHub
- **`GitHubProjectionAdapter`**: Write-only GitHub commit status projection with signed receipts
- **`ProjectionReceipt`**: Signed proof of projection with idempotency keys (legacy, backwards-compatible)
- **`ProjectionAdmissionReceipt`**: Temporal-bound projection receipt bridging daemon receipts to economics `DeferredReplayReceiptV1` (TCK-00506)
- **`DeferredReplayReceiptInput`**: Input assembly for constructing `DeferredReplayReceiptV1` from admission receipts
- **`DivergenceWatchdog`**: Monitors for ledger/trunk HEAD divergence (TCK-00213)
- **`FreezeRegistry`**: Tracks active intervention freezes
- **`IntentBuffer`**: SQLite-backed durable buffer for projection intents and deferred replay backlog (TCK-00504)

### Security Model

- **Write-only**: Adapters NEVER read external state as truth
- **Ledger is truth**: All decisions are based on ledger state
- **Signed receipts**: Every projection generates a signed receipt with domain separation (`PROJECTION_RECEIPT:` for legacy, `PROJECTION_ADMISSION_RECEIPT:` for temporal-bound)
- **Domain isolation**: Legacy `PROJECTION_RECEIPT:` signatures MUST NOT be accepted as proof of temporal binding; admission receipts use a distinct domain
- **Idempotent**: Safe for retries with `(work_id, changeset_digest, ledger_head)` key
- **Persistent cache**: Idempotency cache survives restarts
- **Bounded deserialization**: String fields (`boundary_id`, `receipt_id`, `work_id`) reject oversized values before allocation

## Key Types

### `ProjectionWorker`

```rust
pub struct ProjectionWorker { /* conn, config, work_index, adapter, tailer */ }
```

Long-running worker that tails ledger and projects review results to GitHub.

**Invariants:**

- [INV-PJ01] Watermark is NOT advanced for events that fail due to missing dependencies (NACK/Retry).
- [INV-PJ02] Worker is idempotent: restarts do not duplicate comments.

**Contracts:**

- [CTR-PJ01] Reads ledger commits via `LedgerTailer`.
- [CTR-PJ02] Stores projection receipts in CAS for idempotency.

### `GitHubProjectionAdapter`

Write-only GitHub commit status projection adapter.

**Invariants:**

- [INV-PJ03] Adapter never reads GitHub status as truth.
- [INV-PJ04] Every projection generates a signed `ProjectionReceipt`.

**Contracts:**

- [CTR-PJ03] Uses persistent idempotency cache (SQLite-backed).
- [CTR-PJ04] Tamper detection overwrites GitHub status to match ledger truth.

### `ProjectionAdapter` (trait)

```rust
#[async_trait]
pub trait ProjectionAdapter: Send + Sync {
    async fn project_status(
        &self,
        work_id: &str,
        changeset_digest: [u8; 32],
        ledger_head: [u8; 32],
        status: ProjectedStatus,
    ) -> Result<ProjectionReceipt, ProjectionError>;
}
```

### `ProjectionReceipt`

```rust
pub struct ProjectionReceipt {
    pub receipt_id: String,
    pub work_id: String,
    pub changeset_digest: [u8; 32],
    pub ledger_head: [u8; 32],
    pub status: ProjectedStatus,
    pub timestamp_ns: u64,
    pub signature: [u8; 64],
    // ...
}
```

**Contracts:**

- [CTR-PJ05] Domain separation with `PROJECTION_RECEIPT:` prefix.
- [CTR-PJ06] `IdempotencyKey = (work_id, changeset_digest, ledger_head)`.
- [CTR-PJ09] Optional temporal fields (`boundary_id`, `time_authority_ref`, `window_ref`, `eval_tick`) are backwards-compatible: old payloads deserialize with `None`.

### `ProjectionAdmissionReceipt` (TCK-00506)

```rust
pub struct ProjectionAdmissionReceipt {
    pub receipt_id: String,
    pub work_id: String,
    pub changeset_digest: [u8; 32],
    pub ledger_head: [u8; 32],
    pub projected_status: ProjectedStatus,
    pub projected_at: u64,
    pub boundary_id: String,            // required
    pub time_authority_ref: [u8; 32],   // required, non-zero
    pub window_ref: [u8; 32],           // required, non-zero
    pub eval_tick: u64,                 // required
    pub adapter_signature: [u8; 64],
}
```

Temporal-bound projection receipt for economics gate compatibility. All temporal fields are required (non-Option). Uses `PROJECTION_ADMISSION_RECEIPT:` domain for signing.

**Invariants:**

- [INV-PJ07] `PROJECTION_ADMISSION_RECEIPT:` domain is distinct from `PROJECTION_RECEIPT:` -- cross-type signature confusion is prevented.
- [INV-PJ08] `time_authority_ref` and `window_ref` must not be zero (fail-closed at construction).
- [INV-PJ09] `boundary_id` must not be empty and must not exceed `MAX_BOUNDARY_ID_LENGTH` (256).

**Contracts:**

- [CTR-PJ07] `From<&ProjectionAdmissionReceipt>` produces `DeferredReplayReceiptInput` with lossless field mapping.
- [CTR-PJ08] Bounded serde deserialization rejects oversized `boundary_id` before allocation.

### `DeferredReplayReceiptInput` (TCK-00506)

Bridge type for assembling `DeferredReplayReceiptV1::create_signed` inputs from admission receipts.

**Field mapping:**

| Admission Receipt | DeferredReplayReceiptInput | DeferredReplayReceiptV1 |
|---|---|---|
| `receipt_id` | `receipt_id` | `receipt_id` |
| `boundary_id` | `boundary_id` | `boundary_id` |
| `changeset_digest` | `backlog_digest` | `backlog_digest` |
| `time_authority_ref` | `time_authority_ref` | `time_authority_ref` |
| `window_ref` | `window_ref` | `window_ref` |
| `eval_tick` | `eval_tick` | `replay_horizon_tick` |

### `ProjectedStatus`

```rust
pub enum ProjectedStatus {
    Pending, Success, Failure, Error,
}
```

### `DivergenceWatchdog`

Monitors for discrepancies between ledger `MergeReceipt` and external trunk HEAD.

**Invariants:**

- [INV-PJ05] Divergence triggers `DefectRecord(PROJECTION_DIVERGENCE)`.
- [INV-PJ06] Creates `InterventionFreeze` to halt admissions until adjudicated.

### `FreezeRegistry`

Tracks active intervention freezes. Freezes require adjudication-based `InterventionUnfreeze` to resume.

### `WorkIndex`

Maps `changeset_digest` to `work_id` to PR metadata for projection routing.

### `LedgerTailer`

Ledger event tailer that drives projection decisions.

### `IntentBuffer` (TCK-00504)

```rust
pub struct IntentBuffer { /* conn: Arc<Mutex<Connection>> */ }
```

SQLite-backed durable buffer for projection intents and deferred replay backlog. Provides insert, admit, deny, evict, and query methods for economics-gated admission decisions.

**Invariants:**

- [INV-IB01] `deferred_replay_backlog` never exceeds `MAX_BACKLOG_ITEMS` (65536). When the cap is reached, oldest entries (by rowid) are evicted and recorded as denied.
- [INV-IB02] Duplicate `(work_id, changeset_digest)` inserts into `projection_intents` are idempotent -- the existing row is preserved.
- [INV-IB03] Evicted backlog entries are returned to the caller for deny receipt emission; they are never silently dropped.
- [INV-IB04] All queries use `ORDER BY rowid` for deterministic ordering.

**Contracts:**

- [CTR-IB01] Schema uses `CREATE TABLE IF NOT EXISTS` -- does not alter existing `projection_receipts` or `comment_receipts` tables.
- [CTR-IB02] All state mutations (admit/deny) check verdict == 'pending' BEFORE mutating -- no double-admit or double-deny.
- [CTR-IB03] Eviction and insert happen within a single mutex acquisition to prevent TOCTOU between count-check and insert.
- [CTR-IB04] String fields are bounded by `MAX_FIELD_LENGTH` (1024) -- prevents DoS via oversized input.

### `IntentVerdict`

```rust
pub enum IntentVerdict { Pending, Admitted, Denied }
```

Fail-closed: unknown verdict values parsed from the database are treated as `Denied`.

## Public API

- `ProjectionWorker`, `ProjectionWorkerConfig`, `ProjectionWorkerError`
- `GitHubProjectionAdapter`, `GitHubAdapterConfig`, `ProjectionAdapter`, `ProjectionError`
- `ProjectionReceipt`, `ProjectionReceiptBuilder`, `ProjectedStatus`, `IdempotencyKey`
- `ProjectionAdmissionReceipt`, `ProjectionAdmissionReceiptBuilder`, `DeferredReplayReceiptInput`, `MAX_BOUNDARY_ID_LENGTH`
- `DivergenceWatchdog`, `DivergenceWatchdogConfig`, `DivergenceError`
- `FreezeRegistry`, `InterventionFreeze`, `InterventionUnfreeze`
- `TamperEvent`, `TamperResult`
- `WorkIndex`, `PrMetadata`, `LedgerTailer`
- `IntentBuffer`, `IntentBufferError`, `IntentVerdict`, `ProjectionIntent`, `DeferredReplayEntry`, `MAX_BACKLOG_ITEMS`

## Related Modules

- [`apm2_daemon::gate`](../gate/AGENTS.md) -- Gate results trigger projection
- [`apm2_daemon::cas`](../cas/AGENTS.md) -- Projection receipts stored in CAS
- [`apm2_daemon::protocol`](../protocol/AGENTS.md) -- Ledger event emission

## References

- RFC-0015: Forge Admission Cycle (FAC) -- projection adapters
- RFC-0019: Automated FAC v0 -- projection worker (Workstream F)
- TCK-00212: GitHub projection adapter
- TCK-00213: Divergence watchdog
- TCK-00214: Tamper detection
- TCK-00322: Projection worker implementation
- TCK-00504: Projection intent schema and durable buffer for economics-gated admission
- TCK-00506: Projection receipt format bridge for economics gate compatibility
