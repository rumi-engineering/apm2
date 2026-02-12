# Orchestration

> FAC revision loop state machine with crash-only recovery from ledger events.

## Overview

The `orchestration` module implements the Forge Admission Cycle (FAC) orchestration layer as specified in RFC-0019 and TCK-00332. The orchestrator drives implementer + reviewer episodes iteratively until a terminal condition is reached (pass, blocked, budget exhausted, operator stop, max iterations, or error).

The module follows a crash-only recovery model: all state is derived from ledger events, enabling deterministic restart from any checkpoint without duplicating projections.

The module is split into two sub-modules:

1. **Events** (`events.rs`): Ledger event types for orchestration lifecycle (started, iteration completed, terminated).
2. **State** (`state.rs`): The `OrchestrationStateV1` state machine, `OrchestrationConfig`, `OrchestrationDriver`, and termination/blocking reason types.

## Key Types

### `OrchestrationStateV1`

```rust
#[serde(deny_unknown_fields)]
pub struct OrchestrationStateV1 {
    work_id: String,
    orchestration_id: String,
    iteration_count: u64,
    max_iterations: u64,
    initial_token_budget: u64,
    tokens_consumed: u64,
    initial_time_budget_ms: u64,
    time_consumed_ms: u64,
    started_at_ns: u64,
    last_iteration_at_ns: Option<u64>,
    termination_reason: Option<TerminationReason>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_changeset_hash: Option<[u8; 32]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_receipt_hash: Option<[u8; 32]>,
}
```

The current state of an orchestration session. Designed to be reconstructed from ledger events for crash-only recovery.

**Invariants:**

- [INV-OR01] `iteration_count` is monotonically increasing (incremented via `record_iteration`).
- [INV-OR02] `tokens_consumed` and `time_consumed_ms` are monotonically increasing (saturating addition).
- [INV-OR03] Once `termination_reason` is `Some`, the state is terminal; `terminate()` returns `false` on subsequent calls.
- [INV-OR04] `iteration_count` never exceeds `max_iterations` (enforced by `record_iteration` returning a termination reason).
- [INV-OR05] Rejects unknown fields during deserialization (`deny_unknown_fields`).

**Contracts:**

- [CTR-OR01] `try_new()` validates `work_id` and `orchestration_id` via `validate_id()`, and ensures `max_iterations` is in `[1, 100]` and budgets are positive. Returns `HolonError::InvalidInput` on failure.
- [CTR-OR02] `new()` clamps `max_iterations` to `[1, 100]` and budgets to minimum 1 without returning errors.
- [CTR-OR03] `record_iteration()` returns `Some(TerminationReason)` if tokens exhausted, time exhausted, or max iterations reached; returns `None` otherwise.
- [CTR-OR04] `terminate()` returns `true` on first call, `false` on subsequent calls (first-write-wins semantics).
- [CTR-OR05] `as_budget()` converts remaining orchestration resources to a `Budget` struct, setting `tool_calls` to `u64::MAX` (not tracked at orchestration level).

### `OrchestrationConfig`

```rust
#[serde(deny_unknown_fields)]
pub struct OrchestrationConfig {
    pub max_iterations: u64,
    pub token_budget: u64,
    pub time_budget_ms: u64,
    pub emit_events: bool,
    pub fail_fast: bool,
}
```

Configuration for the orchestration driver. Defaults: `max_iterations = 100`, `token_budget = 10_000_000`, `time_budget_ms = 3_600_000`, `emit_events = true`, `fail_fast = true`.

**Invariants:**

- [INV-OR06] Rejects unknown fields during deserialization.

**Contracts:**

- [CTR-OR06] `with_max_iterations()` panics if the value is outside `[1, 100]`.
- [CTR-OR07] `validate()` returns `HolonError::InvalidInput` if `max_iterations` is outside `[1, 100]`, or if `token_budget` or `time_budget_ms` is zero.

### `OrchestrationDriver`

```rust
#[derive(Debug, Clone)]
pub struct OrchestrationDriver {
    config: OrchestrationConfig,
}
```

Driver that manages the orchestration loop lifecycle.

**Contracts:**

- [CTR-OR08] `create_state()` validates config and IDs before constructing state.
- [CTR-OR09] `resume_from_events()` reconstructs state from an event sequence, validating: iteration number continuity, timestamp monotonicity, termination summary totals matching reconstructed state (LAW-07). Returns `HolonError::InvalidState` on inconsistencies.
- [CTR-OR10] `check_termination()` evaluates stop conditions in priority order: already terminated > token budget exhausted > time budget exhausted > max iterations reached.

### `TerminationReason`

```rust
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub enum TerminationReason {
    Pass,
    Blocked(BlockedReasonCode),
    BudgetExhausted { resource: String, consumed: u64, limit: u64 },
    OperatorStop { reason: String, operator_id: Option<String> },
    MaxIterationsReached { iterations: u64 },
    Error { error: String },
}
```

Why orchestration terminated (6 variants, non-exhaustive).

**Contracts:**

- [CTR-OR11] `is_success()` returns `true` only for `Pass`.
- [CTR-OR12] `is_blocked()` returns `true` only for `Blocked(_)`.
- [CTR-OR13] `is_resource_limit()` returns `true` for `BudgetExhausted` and `MaxIterationsReached`.
- [CTR-OR14] `is_error()` returns `true` only for `Error`.
- [CTR-OR15] `validate()` enforces `MAX_ROLE_LENGTH` (256) on resource names and operator IDs, and `MAX_REASON_LENGTH` (1024) on reason/error strings. Delegates to `BlockedReasonCode::validate()` for the `Blocked` variant.

### `BlockedReasonCode`

```rust
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub enum BlockedReasonCode {
    ReviewerBlocked { reviewer_role: String, finding_summary: Option<String> },
    ChangeSetApplyFailed { error: String },
    MissingDependency { dependency: String },
    PolicyViolation { policy: String },
    ImplementerStalled { reason: String },
    Other { description: String },
}
```

Structured reason codes for blocked termination (6 variants).

**Invariants:**

- [INV-OR07] Rejects unknown fields during deserialization.

**Contracts:**

- [CTR-OR16] `validate()` enforces `MAX_ROLE_LENGTH` (256) on `reviewer_role` and `MAX_REASON_LENGTH` (1024) on all other string fields.

### `IterationOutcome`

```rust
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub enum IterationOutcome {
    ChangeSetProduced,
    AllReviewsPassed,
    ReviewsBlocked { blocked_by: Vec<String> },
    ImplementerStalled { reason: String },
    Error { error: String },
}
```

Outcome of a single revision iteration (5 variants).

**Contracts:**

- [CTR-OR17] `is_success()` returns `true` only for `AllReviewsPassed`.
- [CTR-OR18] `is_blocked()` returns `true` for `ReviewsBlocked` and `ImplementerStalled`.
- [CTR-OR19] `is_error()` returns `true` only for `Error`.
- [CTR-OR20] `validate()` enforces `MAX_VECTOR_ENTRIES` (100) on `blocked_by`, `MAX_ROLE_LENGTH` (256) on role strings, and `MAX_REASON_LENGTH` (1024) on reason/error strings.

### `OrchestrationStarted`

```rust
#[serde(deny_unknown_fields)]
pub struct OrchestrationStarted {
    orchestration_id: String,
    work_id: String,
    max_iterations: u64,
    token_budget: u64,
    time_budget_ms: u64,
    started_at_ns: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    initial_changeset_hash: Option<[u8; 32]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    capability_manifest_hash: Option<[u8; 32]>,
}
```

Event emitted when orchestration begins. Captures initial configuration and optional BLAKE3 hashes for changeset and capability manifest.

**Contracts:**

- [CTR-OR21] `try_new()` validates both IDs via `validate_id()`.
- [CTR-OR22] `new()` skips validation for internal use.

### `IterationCompleted`

```rust
#[serde(deny_unknown_fields)]
pub struct IterationCompleted {
    orchestration_id: String,
    work_id: String,
    iteration_number: u64,
    outcome: IterationOutcome,
    tokens_consumed: u64,
    time_consumed_ms: u64,
    completed_at_ns: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    changeset_hash: Option<[u8; 32]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    receipt_hash: Option<[u8; 32]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    implementer_episode_id: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    reviewer_episode_ids: Vec<String>,
}
```

Event emitted after each revision cycle completes.

**Contracts:**

- [CTR-OR23] `validate()` validates the outcome and enforces `MAX_VECTOR_ENTRIES` (100) on `reviewer_episode_ids` and `MAX_ROLE_LENGTH` (256) on all episode ID strings.

### `OrchestrationTerminated`

```rust
#[serde(deny_unknown_fields)]
pub struct OrchestrationTerminated {
    orchestration_id: String,
    work_id: String,
    reason: TerminationReason,
    total_iterations: u64,
    total_tokens_consumed: u64,
    total_time_consumed_ms: u64,
    terminated_at_ns: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    final_changeset_hash: Option<[u8; 32]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    final_receipt_hash: Option<[u8; 32]>,
}
```

Event emitted when orchestration terminates. Captures summary totals for verification during crash recovery.

**Contracts:**

- [CTR-OR24] `is_success()` delegates to `TerminationReason::is_success()`.

### `OrchestrationEvent`

```rust
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub enum OrchestrationEvent {
    Started(OrchestrationStarted),
    IterationCompleted(IterationCompleted),
    Terminated(OrchestrationTerminated),
}
```

Wrapper enum for all orchestration-related ledger events. Implements `From` conversions from each inner type.

### Constants

```rust
// From state.rs
pub const MAX_ITERATIONS_LIMIT: u64 = 100;
pub const MIN_ITERATIONS: u64 = 1;
pub const MAX_REASON_LENGTH: usize = 1024;
pub const MAX_ROLE_LENGTH: usize = 256;

// From events.rs (re-exported with aliases)
pub const EVENT_MAX_ROLE_LENGTH: usize = 256;
pub const EVENT_MAX_REASON_LENGTH: usize = 1024;
pub const MAX_VECTOR_ENTRIES: usize = 100;
```

## Public API

| Function / Method | Description |
|---|---|
| `OrchestrationStateV1::try_new(...)` | Creates validated state. |
| `OrchestrationStateV1::new(...)` | Creates state with clamped values. |
| `OrchestrationStateV1::record_iteration(...)` | Records iteration consumption; returns optional termination. |
| `OrchestrationStateV1::terminate(reason)` | Sets terminal state (first-write-wins). |
| `OrchestrationStateV1::as_budget()` | Converts remaining resources to `Budget`. |
| `OrchestrationStateV1::budget_exhausted()` | Returns `true` if any resource is exhausted. |
| `OrchestrationConfig::default()` | Creates default configuration. |
| `OrchestrationConfig::validate()` | Validates configuration. |
| `OrchestrationConfig::with_max_iterations(n)` | Builder method (panics on out-of-range). |
| `OrchestrationConfig::with_token_budget(n)` | Builder method. |
| `OrchestrationConfig::with_time_budget_ms(n)` | Builder method. |
| `OrchestrationConfig::with_emit_events(b)` | Builder method. |
| `OrchestrationConfig::with_fail_fast(b)` | Builder method. |
| `OrchestrationDriver::new(config)` | Creates a driver with the given config. |
| `OrchestrationDriver::with_defaults()` | Creates a driver with default config. |
| `OrchestrationDriver::create_state(work_id, orch_id)` | Creates initial state. |
| `OrchestrationDriver::resume_from_events(events)` | Reconstructs state from ledger events. |
| `OrchestrationDriver::check_termination(state)` | Evaluates stop conditions. |
| `TerminationReason::pass()` | Factory for Pass. |
| `TerminationReason::blocked(code)` | Factory for Blocked. |
| `TerminationReason::budget_exhausted(resource, consumed, limit)` | Factory for BudgetExhausted. |
| `TerminationReason::operator_stop(reason)` | Factory for OperatorStop. |
| `TerminationReason::max_iterations_reached(n)` | Factory for MaxIterationsReached. |
| `TerminationReason::error(msg)` | Factory for Error. |
| `OrchestrationStarted::try_new(...)` / `new(...)` | Validated / unvalidated constructors. |
| `IterationCompleted::try_new(...)` / `new(...)` | Validated / unvalidated constructors. |
| `OrchestrationTerminated::try_new(...)` / `new(...)` | Validated / unvalidated constructors. |

## Examples

### Creating and Running Orchestration State

```rust
use apm2_holon::orchestration::{
    OrchestrationConfig, OrchestrationDriver, OrchestrationStateV1, TerminationReason,
};

let driver = OrchestrationDriver::new(
    OrchestrationConfig::default()
        .with_max_iterations(10)
        .with_token_budget(100_000),
);

let mut state = driver.create_state("work-123", "orch-001").unwrap();

// Record iterations until termination
loop {
    let termination = state.record_iteration(
        5000,    // tokens
        1000,    // time_ms
        state.started_at_ns() + (state.iteration_count() + 1) * 1_000_000_000,
        None,    // changeset_hash
        None,    // receipt_hash
    );

    if let Some(reason) = termination {
        state.terminate(reason);
        break;
    }
}

assert!(state.is_terminated());
```

### Crash Recovery from Events

```rust
use apm2_holon::orchestration::{
    OrchestrationDriver, OrchestrationEvent, OrchestrationStarted,
    IterationCompleted, IterationOutcome,
};

let driver = OrchestrationDriver::with_defaults();

let events: Vec<OrchestrationEvent> = vec![
    OrchestrationStarted::new("orch-001", "work-123", 100, 1_000_000, 3_600_000, 1_000_000_000).into(),
    IterationCompleted::new("orch-001", "work-123", 1, IterationOutcome::ChangeSetProduced, 5000, 10_000, 2_000_000_000).into(),
];

let state = driver.resume_from_events(events.iter()).unwrap().unwrap();
assert_eq!(state.iteration_count(), 1);
assert!(!state.is_terminated());
```

## Related Modules

- [Episode controller](../episode/AGENTS.md) - Runs individual episodes within each iteration
- [Ledger events](../ledger/AGENTS.md) - Base event types and validation functions used by orchestration events
- [Resource management](../resource/AGENTS.md) - `Budget` type used for resource tracking
- [Holon trait (crate root)](../../AGENTS.md) - The `Holon` trait that orchestration drives

## References

- [RFC-0019] Automated FAC v0 - End-to-end ingestion, review episode, durable receipt, GitHub projection
- [TCK-00332] Orchestration state machine specification
- [LAW-07] Termination summary totals must match reconstructed state
