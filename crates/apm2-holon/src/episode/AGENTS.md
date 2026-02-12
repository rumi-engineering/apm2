# Episode

> Bounded episode execution controller for holonic work loops.

## Overview

The `episode` module implements the episode controller that manages the execution loop for holons. It sits between the orchestration layer (which decides *what* to execute) and the `Holon` trait (which performs the actual work). The controller follows the Active Inference pattern (Axiom V from Principia Holonica): episodes are bounded units of execution that minimize free energy through iterative refinement until a stop condition is met.

The controller handles:

- Constructing `EpisodeContext` from work state and lease constraints
- Executing bounded episodes via `Holon::execute_episode`
- Evaluating stop conditions after each episode (budget, goal, escalation, error)
- Emitting ledger events for episode lifecycle
- Enforcing budget limits and deducting from lease budgets
- Generating `RunReceipt` with context pack sufficiency data (when configured)
- Recording pack miss defects (foundational plumbing for TCK-00138)

## Key Types

### `EpisodeController`

```rust
pub struct EpisodeController {
    config: EpisodeControllerConfig,
}
```

The core controller that manages the episode execution loop. Generic over any `Holon` implementation.

**Invariants:**

- [INV-EP01] Episode numbers are monotonically increasing within a loop and across restarts (via `initial_episode_number` parameter).
- [INV-EP02] `initial_episode_number` of 0 is clamped to 1 (episodes are 1-indexed).
- [INV-EP03] Budget deduction from the lease is applied after each episode; if deduction fails, the loop terminates with `BudgetExhausted`.
- [INV-EP04] Stop conditions are evaluated in priority order: context budget exhaustion > holon stop condition > max episodes reached.

**Contracts:**

- [CTR-EP01] `run_episode_loop` validates `work_id` and `lease_id` via `validate_id()` before processing. Returns `HolonError::InvalidInput` on invalid IDs.
- [CTR-EP02] `run_episode_loop` validates `goal_spec` via `validate_goal_spec()` if provided. Returns `HolonError::InvalidInput` if spec exceeds `MAX_GOAL_SPEC_LENGTH` or contains null bytes.
- [CTR-EP03] In strict budget enforcement mode, non-recoverable errors propagate as `Err`; otherwise the loop breaks and returns the error as an `EpisodeLoopOutcome::Error`.
- [CTR-EP04] When a context pack is configured, a `RunReceipt` is generated at the end of the loop capturing pack sufficiency and budget delta.

### `EpisodeControllerConfig`

```rust
#[serde(deny_unknown_fields)]
pub struct EpisodeControllerConfig {
    pub max_episodes: u64,
    pub episode_timeout_ms: u64,
    pub emit_events: bool,
    pub strict_budget_enforcement: bool,
    pub context_pack: Option<ContextPackConfig>,
}
```

Configuration for the episode controller. Supports builder-style construction.

**Invariants:**

- [INV-EP05] Rejects unknown fields during deserialization (`deny_unknown_fields`) to prevent fail-open parsing.

### `ContextPackConfig`

```rust
#[serde(deny_unknown_fields)]
pub struct ContextPackConfig {
    pub pack_hash: Hash,
    pub manifest_hash: Option<Hash>,
}
```

Configuration for context pack tracking. When present, the controller generates `RunReceipt` with sufficiency information.

### `EpisodeLoopOutcome`

```rust
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub enum EpisodeLoopOutcome {
    Completed { episodes_executed: u64, tokens_consumed: u64 },
    BudgetExhausted { resource: String, episodes_executed: u64, tokens_consumed: u64 },
    MaxEpisodesReached { episodes_executed: u64, tokens_consumed: u64 },
    Blocked { reason: String, episodes_executed: u64 },
    Escalated { reason: String, episodes_executed: u64 },
    Error { error: String, episodes_executed: u64, recoverable: bool },
}
```

**Contracts:**

- [CTR-EP05] `is_successful()` returns `true` only for `Completed`.
- [CTR-EP06] `can_continue()` returns `true` for `BudgetExhausted`, `MaxEpisodesReached`, and `Blocked` (work could resume with more resources or unblocking).

### `EpisodeLoopResult<T>`

```rust
pub struct EpisodeLoopResult<T> {
    pub outcome: EpisodeLoopOutcome,
    pub events: Vec<EpisodeEvent>,
    pub output: Option<T>,
    pub final_stop_condition: StopCondition,
    pub run_receipt: Option<RunReceipt>,
    pub defect_records: Vec<DefectRecord>,
}
```

Complete result of an episode loop execution, including emitted events, optional output, receipt, and defect records.

### `Hash`

```rust
pub type Hash = [u8; 32];
```

Type alias for BLAKE3-256 hashes (32 bytes).

### Constants

```rust
pub const DEFAULT_MAX_EPISODES: u64 = 100;
pub const DEFAULT_EPISODE_TIMEOUT_MS: u64 = 300_000; // 5 minutes
```

## Public API

| Function / Method | Description |
|---|---|
| `EpisodeController::new(config)` | Creates a controller with the given configuration. |
| `EpisodeController::with_defaults()` | Creates a controller with default configuration. |
| `EpisodeController::config()` | Returns the controller configuration. |
| `EpisodeController::build_context(work_id, lease, episode_number, goal_spec, progress_state, timestamp_ns)` | Constructs an `EpisodeContext` from work state and lease. |
| `EpisodeController::evaluate_stop_condition(ctx, holon_stop)` | Evaluates stop conditions in priority order. |
| `EpisodeController::run_episode_loop(holon, work_id, lease, goal_spec, initial_episode_number, clock)` | Main entry point: runs the episode loop until a stop condition is met. |
| `EpisodeController::record_pack_miss(builder, defect_records, work_id, stable_id, timestamp_ns, reason, pack_hash)` | Records a context pack miss; emits `DefectRecord` on first miss only. |

## Examples

### Running an Episode Loop

```rust
use apm2_holon::episode::{EpisodeController, EpisodeControllerConfig};
use apm2_holon::resource::{Budget, Lease, LeaseScope};

let controller = EpisodeController::new(
    EpisodeControllerConfig::default()
        .with_max_episodes(10)
        .with_emit_events(true),
);

let mut holon = MyHolon::new();
let mut lease = Lease::builder()
    .lease_id("lease-001")
    .issuer_id("registrar")
    .holder_id("agent")
    .scope(LeaseScope::unlimited())
    .budget(Budget::new(10, 100, 10_000, 60_000))
    .expires_at_ns(u64::MAX)
    .build()
    .unwrap();

let result = controller.run_episode_loop(
    &mut holon,
    "work-001",
    &mut lease,
    Some("Complete the task"),
    1, // initial_episode_number
    || current_timestamp_ns(),
)?;

if result.is_successful() {
    println!("Completed in {} episodes", result.episodes_executed());
}
```

### Resuming with Monotonic Episode Numbers

```rust
// First run: episodes 1-3
let result1 = controller.run_episode_loop(
    &mut holon, "work-001", &mut lease, None, 1, clock,
)?;

// Second run: episodes 4-6 (monotonically increasing)
let result2 = controller.run_episode_loop(
    &mut holon2, "work-001", &mut lease, None,
    result1.episodes_executed() + 1, // Continue from where we left off
    clock,
)?;
```

## Related Modules

- [Holon trait (crate root)](../../AGENTS.md) - The `Holon` trait that episode controller drives
- [Ledger events](../ledger/AGENTS.md) - `EpisodeEvent`, `EpisodeStarted`, `EpisodeCompleted` types emitted by the controller
- [Resource management](../resource/AGENTS.md) - `Lease` and `Budget` consumed during execution
- [Orchestration](../orchestration/AGENTS.md) - Higher-level FAC orchestration that uses the episode controller

## References

- [RFC-0019] Automated FAC v0 - End-to-end ingestion, review episode, durable receipt, GitHub projection
- [TCK-00138] Context pack miss tracking infrastructure
- [rust-standards: 40_time_monotonicity_determinism.md] - Monotonic episode numbering
