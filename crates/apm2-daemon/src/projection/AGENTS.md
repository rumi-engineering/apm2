# Projection Module

> Write-only projection adapters for synchronizing ledger state to external systems.

## Overview

The `projection` module implements write-only projection adapters that synchronize ledger state to external systems, primarily GitHub. The key design principle is that the ledger is always the source of truth -- projections are one-way writes that never read external state as authoritative.

### Components

- **`ProjectionWorker`**: Long-running worker that tails the ledger for `ReviewReceiptRecorded` events and projects review results to GitHub
- **`GitHubProjectionAdapter`**: Write-only GitHub commit status projection with signed receipts
- **`ProjectionReceipt`**: Signed proof of projection with idempotency keys
- **`DivergenceWatchdog`**: Monitors for ledger/trunk HEAD divergence (TCK-00213)
- **`FreezeRegistry`**: Tracks active intervention freezes

### Security Model

- **Write-only**: Adapters NEVER read external state as truth
- **Ledger is truth**: All decisions are based on ledger state
- **Signed receipts**: Every projection generates a signed receipt with domain separation (`PROJECTION_RECEIPT:`)
- **Idempotent**: Safe for retries with `(work_id, changeset_digest, ledger_head)` key
- **Persistent cache**: Idempotency cache survives restarts

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

## Public API

- `ProjectionWorker`, `ProjectionWorkerConfig`, `ProjectionWorkerError`
- `GitHubProjectionAdapter`, `GitHubAdapterConfig`, `ProjectionAdapter`, `ProjectionError`
- `ProjectionReceipt`, `ProjectionReceiptBuilder`, `ProjectedStatus`, `IdempotencyKey`
- `DivergenceWatchdog`, `DivergenceWatchdogConfig`, `DivergenceError`
- `FreezeRegistry`, `InterventionFreeze`, `InterventionUnfreeze`
- `TamperEvent`, `TamperResult`
- `WorkIndex`, `PrMetadata`, `LedgerTailer`

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
