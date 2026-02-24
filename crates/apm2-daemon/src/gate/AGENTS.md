# Gate Module

> Gate execution orchestrator and merge executor for the autonomous FAC gate lifecycle.

## Overview

The `gate` module implements the autonomous gate lifecycle within the Forge Admission Cycle (FAC). Gate start is publication-driven: authoritative `changeset_published` ledger events feed `GateStartKernel`, which calls `GateOrchestrator::start_for_changeset` to drive policy resolution and lease issuance. Session termination remains lifecycle/accounting-only and MUST NOT bootstrap gate start. When all required gates pass, the `MergeExecutor` autonomously merges the PR via the GitHub API and emits a signed `MergeReceipt`.

### FAC Gate State Machine

```text
changeset_published -> RUN_GATES -> gate_receipt -> AWAIT_REVIEW
                                                -> ALL_PASS -> MERGE -> Completed
                                                -> CONFLICT -> ReviewBlocked
```

## Key Types

### `GateOrchestrator`

Consumes authoritative changeset publication identity and autonomously orchestrates the gate lifecycle.

**Invariants:**

- [INV-GT01] `PolicyResolvedForChangeSet` MUST be emitted before any `GateLeaseIssued` event for the same `work_id`.
- [INV-GT02] Maximum concurrent orchestrations bounded to `MAX_CONCURRENT_ORCHESTRATIONS` (1,000).
- [INV-GT03] Maximum gate types per orchestration bounded to `MAX_GATE_TYPES` (8).
- [INV-GT04] Expired gate leases produce FAIL verdict (fail-closed timeouts).
- [INV-GT05] Changeset digest in each lease matches the authoritative `ChangeSetPublished` digest.
- [INV-GT12] Gate start entrypoint is `start_for_changeset` (CSID-003). Session lifecycle timeout progression is polled via `poll_session_lifecycle`; there is no session-termination gate-start entrypoint.
- [INV-GT13] Idempotency key is `(work_id, changeset_digest)`, a pure function of authoritative publication inputs (CSID-003).
- [INV-GT14] Orchestrations map keyed by `(work_id, changeset_digest)` composite key (CSID-003) but enforces a **one-active-per-work_id** invariant (latest changeset wins per RFC-0032). Starting `(work, digest2)` while `(work, digest1)` is active supersedes the old entry; starting the same `(work, digest1)` twice is denied. This ensures `find_by_work_id` helpers always resolve unambiguously.
- [INV-GT15] Event payloads enforce `MAX_PAYLOAD_BYTES` (1 MiB) size limit BEFORE JSON deserialization to prevent memory exhaustion.
- [INV-GT16] `publisher_actor_id` is derived from the verified `actor_id` column of the ledger row (signed envelope), not from untrusted payload content. Cross-validation rejects identity mismatches.
- [INV-GT17] `publisher_actor_id` length is validated against `MAX_STRING_LENGTH` consistent with other string fields.
- [INV-GT18] `GateStartKernel` cursor migration safety: on upgrade from pre-unified to unified event reader, persisted cursors with raw event IDs (no `legacy:` or `canonical:` prefix) are detected and reset to the beginning. Re-processing is safe because the intent store's `state='done'` markers provide idempotent deduplication (CSID-003).
- [INV-GT19] `GateStartKernel` malformed-row resilience: `parse_changeset_publication_payload` errors do NOT propagate with `?` during the observe poll. Malformed rows are logged, and a cursor-advancing event with `publication = None` is emitted so the kernel advances past the bad row. `apply_events` skips `None` publications. This prevents permanent deadlock on corrupt ledger data.

**Contracts:**

- [CTR-GT01] All gate leases use `GATE_LEASE_ISSUED:` Ed25519 domain prefix.
- [CTR-GT02] Gate receipt signatures are verified against the executor's verifying key.
- [CTR-GT03] Events are returned per-invocation, not buffered in shared state.
- [CTR-GT04] Idempotency keys bounded to `MAX_IDEMPOTENCY_KEYS`.
- [CTR-GT07] Both `GateStartKernel` and `GateTimeoutKernel` implement the cursor-generic `orchestrator_kernel` traits (`CursorEvent<CompositeCursor>`, `LedgerReader` with `type Cursor = CompositeCursor`, `CursorStore<CompositeCursor>`). New kernel consumers should choose a `KernelCursor` matching their ledger truth.

### `GateType`

```rust
pub enum GateType {
    Aat,      // Agent Acceptance Testing
    Quality,  // Code quality review
    Security, // Security review
}
```

### `GateStatus` / `GateOutcome`

Tracks per-gate execution state and final verdict.

### `GateOrchestratorConfig`

Configuration including timeout, clock, and signer.

### `Clock` (trait)

```rust
pub trait Clock: Send + Sync + fmt::Debug {
    fn now_ms(&self) -> u64;
    fn monotonic_now(&self) -> Instant;
}
```

Abstraction over time sources. Production uses `SystemClock`; tests inject mocks.

### `MergeExecutor`

Watches for all required gate receipts reaching PASS verdict and autonomously executes the merge.

**Invariants:**

- [INV-GT06] Policy hash from gate receipts is verified against the `PolicyResolvedForChangeSet` anchor (anti-downgrade).
- [INV-GT07] `MergeReceipt` atomically binds inputs to the observed result (new commit SHA).
- [INV-GT08] Gate receipt IDs are sorted before inclusion in `MergeReceipt` for determinism.
- [INV-GT09] Merge conflicts produce `ReviewBlockedRecorded` events, not silent failure.
- [INV-GT10] Pending merges bounded to `MAX_PENDING_MERGES` (1,000).
- [INV-GT11] `MergeExecutorEvent::WorkCompleted` emits `merge_receipt_id` (derived from result SHA) separately from `evidence_gate_receipt_ids` (TCK-00650). The merge receipt is NOT placed in `gate_receipt_id`.

**Contracts:**

- [CTR-GT05] Uses `MERGE_RECEIPT:` domain separator for signing.
- [CTR-GT06] Returns `ExecuteOrBlockResult` tuple with merge receipt or blocked event.

### `MergeExecutorError`

```rust
pub enum MergeExecutorError {
    GatesNotAllPassed { work_id: String },
    PolicyHashMismatch { work_id: String, expected: String, actual: String },
    MergeConflict { work_id: String, reason: String },
    GitHubApiError { work_id: String, reason: String },
    ReceiptCreationFailed { work_id: String, reason: String },
    NoGateOutcomes { work_id: String },
    // ...
}
```

### `GitHubMergeAdapter` (trait)

Abstraction over GitHub merge operations for testability.

## Public API

- `GateOrchestrator`, `GateOrchestratorConfig`, `GateOrchestratorError`, `GateOrchestratorEvent`
- `GateType`, `GateStatus`, `GateOutcome`
- `MergeExecutor`, `MergeExecutorError`, `MergeExecutorEvent`, `MergeInput`, `MergeResult`
- `GitHubMergeAdapter`, `ExecuteOrBlockResult`
- `Clock`, `SystemClock`
- `create_timeout_receipt`, `TIMEOUT_AUTHORITY_ACTOR_ID`

## Related Modules

- [`apm2_daemon::episode`](../episode/AGENTS.md) -- Episode runtime for spawning gate executors
- [`apm2_daemon::projection`](../projection/AGENTS.md) -- Projects gate results to GitHub
- [`apm2_daemon::protocol`](../protocol/AGENTS.md) -- Ledger event emission for gate receipts
- [`apm2_core::fac`](../../../apm2-core/src/evidence/AGENTS.md) -- FAC types (`GateReceipt`, `MergeReceipt`, `PolicyResolvedForChangeSet`)

## References

- RFC-0015: Forge Admission Cycle
- RFC-0019: Automated FAC v0
- RFC-0032: FAC vNext changeset identity
- TCK-00388: Gate orchestrator implementation
- TCK-00390: Merge executor implementation
- TCK-00672: End-to-end changeset identity wiring (CSID-003 gate-start migration)
