# PCAC Module

> Proof-Carrying Authority Continuity (PCAC) lifecycle gate for `RequestTool` authority control.

## Overview

The `pcac` module wires RFC-0027's `AuthorityJoinKernel` lifecycle into the daemon's session dispatch path. Every authoritative side effect (tool execution) must pass through the `join -> revalidate -> consume` sequence before the effect is permitted. The module enforces all seven semantic laws from RFC-0027 section 4:

1. **Linear Consumption**: Each AJC authorizes at most one side effect.
2. **Intent Equality**: Consume requires exact intent digest match.
3. **Freshness Dominance**: Tier2+ denies on stale freshness.
4. **Revocation Dominance**: Revocation frontier advancement denies.
5. **Delegation Narrowing**: Delegated joins are strict-subset.
6. **Boundary Monotonicity**: `join < revalidate <= consume <= effect`.
7. **Evidence Sufficiency**: Authoritative outcomes need replay receipts.

### Integration Point

The `LifecycleGate` is injected into `SessionDispatcher` and called in split stages from `handle_request_tool`:

```text
join -> revalidate-before-decision -> broker decision ->
 revalidate-before-execution -> consume-before-effect
```

## Key Types

### `InProcessKernel`

```rust
pub struct InProcessKernel {
    consumed: Mutex<HashSet<Hash>>,
    manual_tick: Mutex<u64>,
    clock: Option<Arc<HolonicClock>>,
    verifier_economics_checker: Option<VerifierEconomicsChecker>,
}
```

Phase 1 in-process `AuthorityJoinKernel` implementation. Validates authority locally against daemon state.

**Invariants:**

- [INV-PC01] Each AJC ID is consumed at most once (Linear Consumption).
- [INV-PC02] Consumed set is held in memory; `DurableConsumeIndex` provides persistent backing.
- [INV-PC03] When constructed with `with_clock()`, ticks derive from `HolonicClock` (never frozen).
- [INV-PC04] Clock regression fails closed rather than falling back.

**Contracts:**

- [CTR-PC01] `join()` validates authority certificate and returns `AuthorityJoinCertificateV1`.
- [CTR-PC02] `revalidate()` checks freshness and revocation state at current tick.
- [CTR-PC03] `consume()` verifies intent digest match and marks AJC as consumed.
- [CTR-PC04] Verifier-economics bounds enforcement denies Tier2+ operations that exceed timing/proof-check budgets.

### `LifecycleGate`

Wraps an `InProcessKernel` and provides a single-call entry point for `handle_request_tool` executing the full `join -> revalidate -> consume` sequence.

**Contracts:**

- [CTR-PC05] Returns `LifecycleReceipts` on success with all generated certificates/receipts.
- [CTR-PC06] `enforce_anti_entropy_economics()` is available as a runtime hook for catch-up sync.

### `SovereigntyChecker`

```rust
pub struct SovereigntyChecker {
    trusted_signer_key: [u8; 32],
    epoch_staleness_threshold: u64,
    max_future_skew_ticks: u64,
}
```

Validates sovereignty inputs for Tier2+ authority operations. Tier0/1 operations bypass all checks.

**Invariants:**

- [INV-PC05] Stale sovereignty epochs are denied (epoch freshness check).
- [INV-PC06] Future-skewed epochs trigger hard freeze (anti-clock-manipulation).
- [INV-PC07] Missing or ambiguous sovereignty state produces denial (fail-closed).

### `SovereigntyState`

```rust
pub struct SovereigntyState {
    pub epoch: Option<SovereigntyEpoch>,
    pub principal_id: String,
    pub revocation_head_known: bool,
    pub autonomy_ceiling: Option<AutonomyCeiling>,
    pub active_freeze: FreezeAction,
}
```

### `DurableConsumeIndex` (trait)

```rust
pub trait DurableConsumeIndex: Send + Sync {
    fn record_consume(&self, ajc_id: Hash) -> Result<(), ConsumeError>;
    fn is_consumed(&self, ajc_id: &Hash) -> bool;
}
```

Abstraction for durable AJC consumption tracking. The consume record MUST be fsynced to durable storage before any side effect is accepted.

### `FileBackedConsumeIndex`

Append-only file implementation of `DurableConsumeIndex` with fsync and crash-replay safety.

**Invariants:**

- [INV-PC08] `record_consume()` returns `Ok(())` only after fsync completes.
- [INV-PC09] On startup, the append-only log is replayed to rebuild the in-memory index.
- [INV-PC10] Capacity is bounded; exhaustion triggers fail-closed denial.

### `ConsumeError`

```rust
pub enum ConsumeError {
    AlreadyConsumed { ajc_id: Hash },
    IoError(std::io::Error),
    CorruptLog { line: usize, reason: String },
    CapacityExhausted { count: usize, max: usize },
}
```

### `TemporalArbitrationError`

Error from temporal arbitration receipt validation.

## Public API

- `InProcessKernel`, `LifecycleGate`, `LifecycleReceipts`
- `SovereigntyChecker`, `SovereigntyState`
- `DurableConsumeIndex`, `DurableKernel`, `DurableKernelShared`
- `FileBackedConsumeIndex`, `ConsumeError`, `DurableConsumeMetrics`

## Related Modules

- [`apm2_daemon::htf`](../htf/AGENTS.md) -- `HolonicClock` provides tick source for certificate expiry
- [`apm2_daemon::protocol`](../protocol/AGENTS.md) -- Session dispatch calls `LifecycleGate`
- [`apm2_daemon::episode`](../episode/AGENTS.md) -- Tool execution gated by PCAC lifecycle
- [`apm2_core::pcac`](../../../apm2-core/src/pcac/AGENTS.md) -- Core PCAC types (`AuthorityJoinKernel`, `RiskTier`, etc.)

## References

- RFC-0027: Proof-Carrying Authority Continuity (PCAC)
- RFC-0027 section 3.3: `AuthorityJoinKernel` lifecycle
- RFC-0027 section 4: Seven semantic laws
- RFC-0027 section 6.6: Sovereignty composition
- RFC-0027 section 12: Pre-effect durability barrier
- TCK-00423: Lifecycle gate implementation
- TCK-00426: Durable consume index
- TCK-00427: Sovereignty checker
