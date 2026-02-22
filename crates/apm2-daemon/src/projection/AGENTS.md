# Projection Module

> Write-only projection adapters for synchronizing ledger state to external systems.

## Overview

The `projection` module implements write-only projection adapters that synchronize ledger state to external systems, primarily GitHub. The key design principle is that the ledger is always the source of truth -- projections are one-way writes that never read external state as authoritative.

### Components

- **`ProjectionWorker`**: Long-running worker that tails the ledger for `ReviewReceiptRecorded` events and projects review results to GitHub. Also tails `evidence.published` events for `work_context` projection (TCK-00638) and `work_active_loop_profile` projection (TCK-00645). The `handle_evidence_published` method decodes the production JSON-envelope wire format (`emit_session_event` stores events as `{"payload": "<hex-encoded-protobuf>", ...}`): it first parses the JSON, extracts the hex-encoded inner payload, hex-decodes it, then protobuf-decodes the `EvidenceEvent`, and routes by category (`WORK_CONTEXT_ENTRY` or `WORK_LOOP_PROFILE`). Economics + lifecycle gates are enforced for authoritative external projection effects (`ReviewReceiptRecorded` -> GitHub); `evidence.published` indexing is deterministic replay of already-admitted ledger facts.
- **`AdmissionTelemetry`**: Thread-safe atomic counters for economics admit/deny decisions per subcategory (TCK-00505)
- **`lifecycle_deny`**: Constants for denial subcategories (consumed, revoked, stale, missing_gate, missing_economics_selectors, missing_lifecycle_selectors) used in replay prevention and gate failure scenarios (TCK-00505)
- **`GitHubProjectionAdapter`**: Write-only GitHub commit status projection with signed receipts
- **`ProjectionReceipt`**: Signed proof of projection with idempotency keys (legacy, backwards-compatible)
- **`ProjectionAdmissionReceipt`**: Temporal-bound projection receipt bridging daemon receipts to economics `DeferredReplayReceiptV1` (TCK-00506)
- **`DeferredReplayReceiptInput`**: Input assembly for constructing `DeferredReplayReceiptV1` from admission receipts
- **`DivergenceWatchdog`**: Monitors for ledger/trunk HEAD divergence (TCK-00213)
- **`FreezeRegistry`**: Tracks active intervention freezes
- **`IntentBuffer`**: SQLite-backed durable buffer for projection intents and deferred replay backlog (TCK-00504)
- **`ConfigBackedResolver`**: Config-backed continuity profile resolver for economics gate input assembly (TCK-00507)
- **`ContinuityProfileResolver`**: Trait for resolving continuity profiles, sink snapshots, and continuity windows
- **`DeferredReplayWorker`**: Worker that drains the deferred replay backlog after sink recovery, re-evaluating economics gate AND PCAC lifecycle enforcement for each replayed intent (TCK-00508)
- **`JobLifecycleRehydrationReconciler`**: RFC-0032 queue projection reconciler that rebuilds filesystem witness state from `fac.job.*` ledger events with bounded event/fs-op budgets (TCK-00669)

### Security Model

- **Write-only**: Adapters NEVER read external state as truth
- **Ledger is truth**: All decisions are based on ledger state
- **Signed receipts**: Every projection generates a signed receipt with domain separation (`PROJECTION_RECEIPT:` for legacy, `PROJECTION_ADMISSION_RECEIPT:` for temporal-bound)
- **Domain isolation**: Legacy `PROJECTION_RECEIPT:` signatures MUST NOT be accepted as proof of temporal binding; admission receipts use a distinct domain
- **Idempotent**: Safe for retries with `(work_id, changeset_digest, ledger_head)` key
- **Persistent cache**: Idempotency cache survives restarts
- **Bounded deserialization**: String fields (`boundary_id`, `receipt_id`, `work_id`) reject oversized values before allocation
- **Economics admission gate**: `ReviewReceiptRecorded` events pass through the economics gate before external side effects. Events without economics selectors are DENIED (fail-closed: no bypass path). Events with selectors pass through `evaluate_projection_continuity()` (TCK-00505)
- **Lifecycle gate before effect**: Economics ALLOW is necessary but not sufficient; projection side effects require lifecycle `join -> revalidate -> consume` success first (TCK-00505).
- **Idempotent-insert replay prevention**: Duplicate `(work_id, changeset_digest)` intents are denied, preventing double-projection (TCK-00505).
- **Fail-closed gate defaults**: Missing gate inputs (temporal authority, profile, snapshot, window) result in DENY, never default ALLOW. Gate init failure also denies events with economics selectors (TCK-00505)
- **Post-projection admission**: Intent is inserted as PENDING before projection, then admitted only AFTER successful projection side effects, ensuring at-least-once semantics (TCK-00505)
- **Bounded lifecycle replay**: Job lifecycle reconciliation must use cursor-bounded event reads (`get_events_since`) with fixed `max_events_per_tick`; full-ledger materialization per tick is forbidden (TCK-00669).
- **Terminal witness preservation**: Unknown-file cleanup for job lifecycle repair is restricted to `pending/`; `completed/` and `denied/` witness files remain durable evidence even after in-memory projection eviction (TCK-00669).
- **Terminal projection eviction**: Job lifecycle projection keeps a bounded terminal insertion-order queue and evicts oldest terminal jobs first when `MAX_PROJECTED_JOBS` is reached; active non-terminal saturation fails closed (TCK-00669).

## Key Types

### `ProjectionWorker`

```rust
pub struct ProjectionWorker { /* conn, config, work_index, adapter, tailer */ }
```

Long-running worker that tails ledger and projects review results to GitHub.

**Invariants:**

- [INV-PJ01] Watermark is NOT advanced for events that fail due to missing dependencies (NACK/Retry).
- [INV-PJ02] Worker is idempotent: restarts do not duplicate comments.
- [INV-PJ10] No `ReviewReceiptRecorded` projection occurs without passing the economics admission gate. When the gate is NOT wired, those events are DENIED (fail-closed) (TCK-00505).
- [INV-PJ11] Missing gate inputs (temporal authority, profile, snapshot, window) result in DENY, not default ALLOW (TCK-00505).
- [INV-PJ12] Events without economics selectors are DENIED with `missing_economics_selectors` subcategory — no bypass path exists (TCK-00505).
- [INV-PJ13] Already-projected intents (same `work_id + changeset_digest`) result in DENY via IntentBuffer uniqueness -- idempotent-insert replay prevention (TCK-00505).
- [INV-PJ14] No external projection side effect executes unless lifecycle gate `join -> revalidate -> consume` succeeds (TCK-00505).
- [INV-PJ15] Permanently malformed `evidence.published` events (InvalidPayload) are acknowledged and skipped to prevent head-of-line blocking; transient errors retry on next poll cycle (TCK-00638 R4 fix).

**Contracts:**

- [CTR-PJ01] Reads ledger commits via `LedgerTailer`.
- [CTR-PJ02] Stores projection receipts in CAS for idempotency.
- [CTR-PJ10] `evaluate_economics_admission_blocking()` is called in `handle_review_receipt()` before `adapter.project_status()` for events carrying economics selectors. Events without selectors are DENIED before reaching the gate. When the gate is not wired, all events are DENIED with durable recording (TCK-00505).
- [CTR-PJ11] Admitted intents are recorded in IntentBuffer: inserted as PENDING before projection, admitted AFTER successful projection side effects (TCK-00505).
- [CTR-PJ12] Denied intents are recorded with structured deny reason in IntentBuffer. Deny recording failure prevents event ACK (durable deny guarantee) (TCK-00505).
- [CTR-PJ13] `AdmissionTelemetry` counters increment atomically (Relaxed ordering -- observability only) for each verdict path (TCK-00505).
- [CTR-PJ14] Lifecycle gate (`join -> revalidate -> consume`) is executed after economics ALLOW and before `adapter.project_status()`. Lifecycle denial marks the pending intent denied before ACK (TCK-00505).
- [CTR-PJ15] Admitted intents persist lifecycle artifact references (`ajc_id`, `intent_digest`, `consume_selector_digest`, `consume_tick`, `time_envelope_ref`) before final admit transition (TCK-00505).

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

Maps `changeset_digest` to `work_id` to PR metadata for projection routing. Also manages the `work_context` projection table (TCK-00638) with `register_work_context_entry()` for idempotent INSERT OR IGNORE, the `work_active_loop_profile` projection table (TCK-00645) with `register_work_active_loop_profile()` for latest-wins upsert, and the `work_spec_snapshot` projection table (TCK-00636) with `register_work_spec_snapshot()` for idempotent INSERT OR IGNORE.

**Tables:**

- `changeset_map`, `pr_metadata` -- projection routing tables
- `work_context` -- work context entries projected from `evidence.published` events (TCK-00638). Primary key `(work_id, entry_id)`, unique constraint on `(work_id, kind, dedupe_key)`, indexed by `work_id` and `created_at_ns`. Included in `evict_expired` / `evict_expired_async` TTL-based eviction using `created_at_ns` (nanoseconds) with seconds-to-nanoseconds conversion (BLOCKER fix: unbounded state growth).
- `work_active_loop_profile` -- active work loop profile per `work_id` projected from `evidence.published` events with category `WORK_LOOP_PROFILE` (TCK-00645). Primary key `work_id`, indexed by `work_id` and `anchored_at_ns`. Stores `dedupe_key` plus canonical ledger `seq_id`; latest-wins semantics are `(anchored_at_ns DESC, seq_id DESC)` so same-timestamp events resolve deterministically to the higher sequence. Included in `evict_expired` / `evict_expired_async` TTL-based eviction using `anchored_at_ns` (nanoseconds).
- `work_spec_snapshot` -- maps `work_id` to `spec_snapshot_hash` (32-byte BLAKE3 hash) derived from `work.opened` events (TCK-00636, RFC-0032 Phase 1). Primary key `work_id`, indexed by `created_at_ns`. Uses `INSERT OR IGNORE` for idempotent replay and is consumed by the work-authority alias reconciliation gate for CAS-backed ticket alias resolution. Included in `evict_expired` / `evict_expired_async` TTL-based eviction using `created_at_ns` (nanoseconds).

### `LedgerTailer`

Ledger event tailer that drives projection decisions. Uses a composite cursor `(timestamp_ns, event_id)` for deterministic ordering and at-least-once delivery semantics.

**Freeze-aware canonical reads (TCK-00638):** When the canonical `events` table exists (freeze mode active), `poll_events` and `poll_events_async` merge results from both `ledger_events` (legacy) and `events` (canonical) tables, sorted by `(timestamp_ns, event_id)` and truncated to the batch limit. Canonical events use synthesised `event_id` = `"canonical-{seq_id:020}"` (20-digit zero-padded) and map `session_id` to `work_id`. Canonical mode is lazily detected via `sqlite_master` probe and cached in an `AtomicU8` (0=unknown, 1=legacy-only, 2=canonical-active). The zero-padded format ensures lexicographic ordering matches numeric `seq_id` ordering, preventing cursor skip when >9 canonical events share the same timestamp (MAJOR fix: timestamp collision cursor skip).

**Invariants:**

- [INV-LT01] Canonical mode detection is cached after first probe -- no repeated `sqlite_master` queries per poll cycle.
- [INV-LT02] Merged results are always sorted by `(timestamp_ns, event_id)` for deterministic cursor advancement.
- [INV-LT03] When no canonical `events` table exists, the tailer operates in legacy-only mode with no error.

### `IntentBuffer` (TCK-00504)

```rust
pub struct IntentBuffer { /* conn: Arc<Mutex<Connection>> */ }
```

SQLite-backed durable buffer for projection intents and deferred replay backlog. Provides insert, admit, deny, lifecycle-artifact attachment, evict, and query methods for economics/lifecycle-gated admission decisions.

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

### `ConfigBackedResolver` (TCK-00507)

```rust
pub struct ConfigBackedResolver { /* profiles, snapshots, windows */ }
```

Config-backed continuity profile resolver for economics gate input assembly. Loads per-sink continuity profiles from daemon TOML configuration at startup. Trusted signer keys are pre-decoded and validated before the resolver is made available.

**Invariants:**

- [INV-CR01] All stored `trusted_signer_keys` are valid 32-byte Ed25519 public keys (validated at construction time).
- [INV-CR02] The resolver is immutable after construction -- no runtime mutations.
- [INV-CR03] Missing sink returns `None` (caller enforces DENY).

**Contracts:**

- [CTR-CR01] Construction fails if any trusted signer hex is invalid, preventing daemon startup.
- [CTR-CR02] `resolve_*` methods are `O(1)` hash map lookups.
- [CTR-CR03] The resolver is `Send + Sync` for concurrent access.

### `ReplayProjectionEffect` (trait, TCK-00508)

```rust
pub trait ReplayProjectionEffect: Send + Sync {
    fn execute_projection(
        &self,
        work_id: &str,
        changeset_digest: [u8; 32],
        ledger_head: [u8; 32],
        status: ProjectedStatus,
    ) -> Result<(), String>;
}
```

Synchronous projection effect callback injected into `DeferredReplayWorker`. In production, this wraps the async `ProjectionAdapter::project_status` call via a sync bridge (e.g., `tokio::task::block_in_place`). Required dependency -- construction of `DeferredReplayWorker` fails without it.

### `ContinuityProfileResolver` (trait, TCK-00507)

```rust
pub trait ContinuityProfileResolver: Send + Sync {
    fn resolve_continuity_profile(&self, sink_id: &str) -> Option<ResolvedContinuityProfile>;
    fn resolve_sink_snapshot(&self, sink_id: &str) -> Option<MultiSinkIdentitySnapshotV1>;
    fn resolve_continuity_window(&self, boundary_id: &str) -> Option<ResolvedContinuityWindow>;
}
```

Trait boundary for resolving continuity profiles, sink snapshots, and continuity windows. All methods return `Option` -- callers MUST treat `None` as DENY (fail-closed).

### `ResolvedContinuityProfile` / `ResolvedContinuityWindow` (TCK-00507)

Pre-validated value types that map directly to economics module input types (`ProjectionSinkContinuityProfileV1`, `ProjectionContinuityWindowV1`) without lossy conversion.

### `DeferredReplayWorker` (TCK-00508)

```rust
pub struct DeferredReplayWorker {
    config: DeferredReplayWorkerConfig,
    intent_buffer: Arc<IntentBuffer>,
    resolver: Arc<dyn ContinuityProfileResolver>,
    gate_signer: Arc<Signer>,
    lifecycle_gate: Arc<LifecycleGate>,
    telemetry: Arc<AdmissionTelemetry>,
    projection_effect: Arc<dyn ReplayProjectionEffect>,
}
```

Worker that drains the deferred replay backlog after sink recovery. For each replayed intent, the worker performs: (1) replay window check, (2) idempotency check, (3) economics gate re-evaluation via `evaluate_projection_continuity()`, (4) PCAC lifecycle enforcement (`join -> revalidate -> consume`), (5) projection side effect via `ReplayProjectionEffect`, (6) intent admission/convergence. Emits a convergence receipt (`DeferredReplayReceiptV1`) when the backlog is fully drained.

**Invariants:**

- [INV-DR01] Authority revocation dominance: a buffered intent carrying authority that was valid at buffer time but has since been revoked is DENIED, even if the economics gate returns ALLOW.
- [INV-DR02] Single-use consume semantics: intents whose authority token was consumed through an alternate path during the outage are DENIED.
- [INV-DR03] Fail-closed: missing gate inputs, missing lifecycle gate, or unknown state always results in DENY.
- [INV-DR04] Bounded replay: configurable batch size (default 64, max 512) prevents post-outage thundering herd.
- [INV-DR05] Deterministic ordering: backlog entries are drained in `ORDER BY rowid` (ledger order).
- [INV-DR06] Intents outside the replay window are expired with a deny receipt (not silently dropped).
- [INV-DR07] Projection side effect executes BEFORE intent is marked admitted/converged. Projection failure results in DENY with `DENY_REPLAY_PROJECTION_EFFECT` reason.
- [INV-DR08] All IntentBuffer state-transition booleans (`admit()`, `deny()`, `mark_replayed()`, `mark_converged()` returning `Ok(false)`) are checked; `false` is treated as a hard error (no silent partial state commits).
- [INV-DR09] Idempotent: already-admitted or already-denied intents are skipped without error.

**Contracts:**

- [CTR-DR01] `drain_cycle()` processes at most `replay_batch_size` entries per invocation and returns a `ReplayCycleResult` with counts and convergence status.
- [CTR-DR02] `backlog_digest` is computed as Blake3 over ordered intent digests of successfully replayed intents, included in the convergence receipt.
- [CTR-DR03] Economics gate re-evaluation calls `evaluate_projection_continuity()` with current resolver state, not cached/stale state.
- [CTR-DR04] Lifecycle gate evaluation uses `current_revocation_head` (passed into `drain_cycle` from the authoritative system/ledger revocation frontier) as the revocation head hash. This ensures intents with revoked authority are denied even if the economics gate returns ALLOW. Uses `PrivilegedPcacInputBuilder` for join input construction (RS-42) with `RiskTier::Tier2Plus` (fail-closed).
- [CTR-DR05] Convergence receipt is only emitted when the backlog is fully drained (no remaining entries after the batch).
- [CTR-DR06] All deny/expire paths record structured reasons via `IntentBuffer.deny()` before the entry is counted.
- [CTR-DR07] `ReplayProjectionEffect::execute_projection()` is called after lifecycle gate success but before `IntentBuffer::admit()`. Failure triggers deny-and-converge with `DENY_REPLAY_PROJECTION_EFFECT` prefix.

## Public API

- `ProjectionWorker`, `ProjectionWorkerConfig`, `ProjectionWorkerError`, `AdmissionTelemetry`, `lifecycle_deny`
- `GitHubProjectionAdapter`, `GitHubAdapterConfig`, `ProjectionAdapter`, `ProjectionError`
- `ProjectionReceipt`, `ProjectionReceiptBuilder`, `ProjectedStatus`, `IdempotencyKey`
- `ProjectionAdmissionReceipt`, `ProjectionAdmissionReceiptBuilder`, `DeferredReplayReceiptInput`, `MAX_BOUNDARY_ID_LENGTH`
- `DivergenceWatchdog`, `DivergenceWatchdogConfig`, `DivergenceError`
- `FreezeRegistry`, `InterventionFreeze`, `InterventionUnfreeze`
- `TamperEvent`, `TamperResult`
- `WorkIndex`, `PrMetadata`, `LedgerTailer`
- `IntentBuffer`, `IntentBufferError`, `IntentVerdict`, `ProjectionIntent`, `DeferredReplayEntry`, `MAX_BACKLOG_ITEMS`
- `ConfigBackedResolver`, `ConfigResolverError`, `ContinuityProfileResolver`, `ResolvedContinuityProfile`, `ResolvedContinuityWindow`, `MAX_RESOLVED_PROFILES`
- `DeferredReplayWorker`, `DeferredReplayWorkerConfig`, `DeferredReplayError`, `ReplayCycleResult`, `ReplayProjectionEffect`, `DEFAULT_REPLAY_BATCH_SIZE`, `MAX_REPLAY_BATCH_SIZE`
- `DENY_REPLAY_HORIZON_OUT_OF_WINDOW`, `DENY_REPLAY_ALREADY_PROJECTED`, `DENY_REPLAY_ECONOMICS_GATE`, `DENY_REPLAY_LIFECYCLE_GATE`, `DENY_REPLAY_MISSING_DEPENDENCY`, `DENY_REPLAY_PROJECTION_EFFECT`

## Related Modules

- [`apm2_daemon::gate`](../gate/AGENTS.md) -- Gate results trigger projection
- [`apm2_daemon::cas`](../cas/AGENTS.md) -- Projection receipts stored in CAS
- [`apm2_daemon::protocol`](../protocol/AGENTS.md) -- Ledger event emission
- [`apm2_core::config`] -- Daemon TOML configuration schema with `ProjectionSinkProfileConfig`
- [`apm2_core::economics::projection_continuity`] -- Economics module types that resolver feeds into

## References

- RFC-0015: Forge Admission Cycle (FAC) -- projection adapters
- RFC-0019: Automated FAC v0 -- projection worker (Workstream F)
- RFC-0029: External IO Efficiency -- economics gate input assembly
- TCK-00212: GitHub projection adapter
- TCK-00213: Divergence watchdog
- TCK-00214: Tamper detection
- TCK-00322: Projection worker implementation
- TCK-00504: Projection intent schema and durable buffer for economics-gated admission
- TCK-00506: Projection receipt format bridge for economics gate compatibility
- TCK-00505: Wire economics admission gate into projection worker pre-projection path
- TCK-00507: Continuity profile and sink snapshot resolution for economics gate input assembly
- TCK-00508: Deferred replay worker for projection intent buffer drain after outage recovery
- TCK-00638: RFC-0032 Phase 2 `work_context` projection table and `evidence.published` tailer for work context entries
- TCK-00636: RFC-0032 Phase 1 `work_spec_snapshot` projection table mapping `work_id` to `spec_snapshot_hash` for work-authority alias reconciliation, `work.opened` event tailer
- TCK-00645: RFC-0032 Phase 4 `work_active_loop_profile` projection table for active loop profile selection, `PublishWorkLoopProfile` CAS + evidence anchor
