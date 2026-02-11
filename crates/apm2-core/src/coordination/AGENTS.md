# Coordination Module

> Agent coordination layer for autonomous work loop execution with budget enforcement, circuit breaker protection, and evidence receipts.

## Overview

The `apm2_core::coordination` module implements the coordination layer specified in RFC-0012. It enables autonomous processing of work queues with serial session execution, budget constraints, and circuit breaker protection. The coordination layer is a **peer reducer** to the session and work modules -- it observes their events but does NOT directly modify their state (AD-COORD-002).

```text
┌─────────────────────────────────────────────────────────────┐
│                    Coordination Layer                       │
│                                                             │
│  CoordinationController                                     │
│    │                                                        │
│    ├── start() ──────────> coordination.started             │
│    ├── prepare_session_spawn() ──> coordination.session_bound│
│    ├── (caller spawns session via SessionSpawner)           │
│    ├── record_session_termination() ──> .session_unbound    │
│    ├── check_stop_condition() ──> budget / circuit breaker  │
│    └── complete() / abort() ──> .completed / .aborted       │
│                                                             │
│  CoordinationReducer                                        │
│    └── Projects: CoordinationState                          │
│                                                             │
│  SessionSpawner (trait)                                     │
│    └── Decouples session execution from coordination logic  │
│                                                             │
│  ReceiptBuilder                                             │
│    └── Builds tamper-evident CoordinationReceipt            │
│                                                             │
│  EfeObjective (planner)                                     │
│    └── Advisory prioritization (no authority)               │
│                                                             │
└────────────────────┬────────────────┬───────────────────────┘
                     │ observes       │ emits
                     ▼                ▼
               ┌───────────┐   ┌───────────┐
               │  Session  │   │  Ledger   │
               │  Reducer  │   │           │
               └───────────┘   └───────────┘
```

## Key Types

### `CoordinationController`

```rust
pub struct CoordinationController {
    // Internal: config, state machine, budget tracking, circuit breaker
}
```

State machine and event generation logic for serial execution of work items.

**Invariants:**

- [INV-CO01] Serial execution: one session at a time (AD-COORD-002)
- [INV-CO02] Session ID generated BEFORE binding event (AD-COORD-007)
- [INV-CO03] Binding events bracket session lifecycle: `session_bound` before spawn, `session_unbound` after termination (AD-COORD-003)
- [INV-CO04] Circuit breaker aborts after `CIRCUIT_BREAKER_THRESHOLD` (3) consecutive work item failures (AD-COORD-005)

**Contracts:**

- [CTR-CO01] `start()` generates `coordination.started` event
- [CTR-CO02] `prepare_session_spawn()` generates `session_bound` event; caller must write to ledger BEFORE spawning
- [CTR-CO03] `record_session_termination()` generates `session_unbound` event
- [CTR-CO04] `complete()` / `abort()` generate terminal events

### `CoordinationConfig`

```rust
pub struct CoordinationConfig {
    pub work_ids: Vec<String>,
    pub budget: CoordinationBudget,
    pub max_attempts_per_work: u32,
    pub max_work_queue_size: usize,
}
```

**Contracts:**

- [CTR-CO05] `new()` rejects empty work queues (`ControllerError::EmptyWorkQueue`)
- [CTR-CO06] `new()` rejects queues exceeding `MAX_WORK_QUEUE_SIZE` (1000)
- [CTR-CO07] `max_attempts_per_work` must be >= 1 and <= `MAX_ATTEMPTS_LIMIT` (100)

### `CoordinationBudget`

```rust
pub struct CoordinationBudget {
    pub max_episodes: u32,
    pub max_duration_ticks: u64,
    pub tick_rate_hz: u64,
    pub max_tokens: Option<u64>,
}
```

Budget constraints using tick-based duration tracking for replay stability (HTF-compliant per TCK-00242).

**Invariants:**

- [INV-CO05] `max_episodes` and `max_duration_ticks` must be positive (non-zero)
- [INV-CO06] `tick_rate_hz` must be positive (non-zero)

**Contracts:**

- [CTR-CO08] `new()` returns `CoordinationError::InvalidBudget` for zero values
- [CTR-CO09] Legacy `max_duration_ms` alias supported for backward-compatible deserialization

### `BudgetUsage`

```rust
pub struct BudgetUsage {
    pub consumed_episodes: u32,
    pub elapsed_ticks: u64,
    pub tick_rate_hz: u64,
    pub consumed_tokens: u64,
}
```

Monotonically non-decreasing budget consumption tracking.

**Invariants:**

- [INV-CO07] All counters are monotonically non-decreasing within a coordination
- [INV-CO08] Tick rate must be consistent across all updates (fail-closed on mismatch)

### `CoordinationSession`

```rust
pub struct CoordinationSession {
    pub coordination_id: String,
    pub status: CoordinationStatus,
    pub work_queue: Vec<String>,
    pub budget: CoordinationBudget,
    pub budget_usage: BudgetUsage,
    pub work_tracking: HashMap<String, WorkItemTracking>,
    // ...
}
```

Individual coordination tracking state within the reducer projection.

### `CoordinationStatus`

```rust
pub enum CoordinationStatus {
    Initializing,
    Running,
    Completed(StopCondition),
    Aborted(AbortReason),
}
```

### `StopCondition`

```rust
pub enum StopCondition {
    AllWorkCompleted,
    BudgetExhausted(BudgetType),
    CircuitBreakerTripped,
    UserRequested,
    Error(CoordinationError),
}
```

Priority-ordered per AD-COORD-013.

### `SessionSpawner` (trait)

```rust
pub trait SessionSpawner: Send + Sync {
    fn spawn(&self, session_id: &str, work_id: &str) -> Result<(), SpawnError>;
    fn observe_termination(&self, session_id: &str) -> Result<SessionTerminationInfo, SpawnError>;
}
```

Decouples the controller from specific session spawning implementations (local thread, daemon IPC, etc.) per AD-COORD-014.

**Contracts:**

- [CTR-CO10] Controller MUST commit `session_bound` event BEFORE calling `spawn` (CAS-at-Commit ordering, AD-COORD-006)
- [CTR-CO11] If `spawn` returns an error, controller MUST emit `session_unbound(reason=SPAWN_FAILED)`

### `CoordinationReducer`

```rust
pub struct CoordinationReducer {
    state: CoordinationState,
}
```

Deterministic event-sourcing reducer for coordination lifecycle events. Implements `Reducer` trait.

**Invariants:**

- [INV-CO09] Deterministic: same event sequence always produces same state
- [INV-CO10] Idempotent: replayed `coordination.started` does not reset accumulated state
- [INV-CO11] Bounded: enforces `MAX_HASHMAP_SIZE` (10,000) on state maps

### `CoordinationReceipt`

```rust
pub struct CoordinationReceipt {
    pub coordination_id: String,
    pub work_outcomes: Vec<WorkOutcome>,
    pub budget_usage: BudgetUsage,
    pub budget_ceiling: CoordinationBudget,
    pub stop_condition: StopCondition,
    pub started_at: u64,
    pub completed_at: u64,
    pub total_sessions: u32,
    pub successful_sessions: u32,
    pub failed_sessions: u32,
}
```

Tamper-evident evidence artifact proving coordination execution. Stored in CAS before completion event emission.

**Invariants:**

- [INV-CO12] Receipt hash in completion event must match CAS content
- [INV-CO13] `work_outcomes` bounded by `MAX_WORK_OUTCOMES` (1000)

**Contracts:**

- [CTR-CO12] `compute_hash()` uses length-prefixed binary encoding (immune to delimiter injection)
- [CTR-CO13] `verify(expected_hash)` validates receipt integrity

### `ReceiptBuilder`

```rust
pub struct ReceiptBuilder { /* ... */ }
```

Incremental builder for receipt construction during the coordination loop.

### `EfeObjective` / `EfeWeights` / `EfeComponents` (planner)

Advisory bounded expected free energy planner types for work prioritization. Strictly advisory -- cannot authorize actuation or bypass gates.

**Invariants:**

- [INV-CO14] EFE weights clamped to `[0.0, 1.0]`; NaN/infinite rejected
- [INV-CO15] EFE component scores in `[0.0, 1.0]`; 0.0 is best

## Public API

### Controller

- `CoordinationController::new(config)` - Create controller
- `controller.start(timestamp_ns)` - Start coordination, returns ID and started event
- `controller.check_stop_condition()` - Check budget/circuit breaker
- `controller.check_work_freshness(work_id, seq_id, is_claimable)` - Validate work state
- `controller.prepare_session_spawn(work_id, seq_id, timestamp_ns)` - Generate session ID and binding event
- `controller.record_session_termination(session_id, work_id, outcome, tokens, timestamp_ns)` - Record completion
- `controller.complete(stop, timestamp_ns)` / `controller.abort(reason, timestamp_ns)` - Terminal

### Reducer

- `CoordinationReducer::new()` - Create empty reducer
- `reducer.apply(event, ctx)` - Process event (implements `Reducer` trait)
- `reducer.state()` - Access projection state

### Evidence

- `ReceiptBuilder::new(coordination_id, budget, started_at)` - Start building
- `builder.record_work_outcome(...)` - Record per-work outcome
- `builder.build(stop_condition, completed_at)` - Finalize receipt
- `receipt.compute_hash()` - Tamper-evident hash
- `receipt.store(cas)` - Store in CAS
- `receipt.verify(expected_hash)` - Verify integrity

### Planner

- `EfeObjective::new(work_id, components, weights)` - Create advisory objective
- `EfeComponents::compute_efe(weights)` - Weighted sum of bounded components
- `CoordinationObjectiveReceiptV1::new(...)` - Auditable receipt of planner decisions

## Resource Limit Constants

| Constant | Value | Purpose |
|---|---|---|
| `MAX_WORK_QUEUE_SIZE` | 1,000 | Max work items per coordination |
| `MAX_HASHMAP_SIZE` | 10,000 | Max entries in state maps |
| `MAX_SESSION_IDS_PER_WORK` | 100 | Max session IDs per work tracking |
| `CIRCUIT_BREAKER_THRESHOLD` | 3 | Consecutive failures before abort |
| `DEFAULT_MAX_ATTEMPTS_PER_WORK` | 3 | Default retry limit |
| `MAX_WORK_OUTCOMES` | 1,000 | Max work outcomes in receipt |
| `MAX_SESSION_IDS_PER_OUTCOME` | 100 | Max session IDs per outcome |
| `MAX_TRACKED_OBJECTIVES` | 1,000 | Max planner objectives |
| `TIER3_ESCALATION_THRESHOLD` | 3 | Tier3+ escalation receipt trigger |

## Examples

### Creating and Running a Coordination

```rust
use apm2_core::coordination::{
    CoordinationConfig, CoordinationController, CoordinationBudget,
};

let budget = CoordinationBudget::new(
    10,           // max 10 episodes
    5_000_000,    // max 5M ticks
    1_000_000,    // 1MHz tick rate (5 seconds)
    Some(100_000) // max 100k tokens
).unwrap();

let config = CoordinationConfig::new(
    vec!["work-1".to_string(), "work-2".to_string()],
    budget,
    3, // max 3 attempts per work
).unwrap();

let mut controller = CoordinationController::new(config);
let started_event = controller.start(timestamp_ns).unwrap();
```

### Implementing a SessionSpawner

```rust
use apm2_core::coordination::{SessionSpawner, SessionTerminationInfo, SpawnError};

struct LocalSpawner;

impl SessionSpawner for LocalSpawner {
    fn spawn(&self, session_id: &str, work_id: &str) -> Result<(), SpawnError> {
        // Start session (implementation-specific)
        Ok(())
    }

    fn observe_termination(
        &self,
        session_id: &str,
    ) -> Result<SessionTerminationInfo, SpawnError> {
        Ok(SessionTerminationInfo::success(session_id, 1000))
    }
}
```

## Related Modules

- [`apm2_core::session`](../session/AGENTS.md) - Session lifecycle and entropy tracking (observed by coordination)
- [`apm2_core::work`](../work/AGENTS.md) - Work item state machine (observed by coordination)
- [`apm2_core::lease`](../lease/AGENTS.md) - Lease management for work claims
- [`apm2_core::reducer`](../reducer/AGENTS.md) - `Reducer` trait, `ReducerContext`, checkpoint support
- [`apm2_core::ledger`](../ledger/AGENTS.md) - `EventRecord` structure, event storage
- [`apm2_core::evidence`](../evidence/AGENTS.md) - CAS for receipt storage
- [`apm2_core::htf`](../htf/AGENTS.md) - `HtfTick` for tick-based budget tracking
- [`apm2_core::budget`](../budget/AGENTS.md) - Budget enforcement framework

## References

- [RFC-0012: Agent Coordination Layer for Autonomous Work Loop Execution](../../../../documents/rfcs/RFC-0012/)
- [RFC-0016: Holonic Time Fabric (HTF)](../../../../documents/rfcs/RFC-0016/) - Tick-based duration tracking
- [APM2 Rust Standards: Testing Evidence](/documents/skills/rust-standards/references/20_testing_evidence_and_ci.md) - Property-based determinism tests
