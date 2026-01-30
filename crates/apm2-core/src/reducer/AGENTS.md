# Reducer Module

> Event-sourcing reducer framework for deterministic state projection from an append-only ledger.

## Overview

The `apm2_core::reducer` module implements the reducer pattern central to APM2's event-sourced architecture. Reducers process events from the ledger and maintain derived state (projections), enabling:

1. **Crash recovery**: State is reconstructed by replaying events from genesis or checkpoint
2. **Audit trails**: Full history is preserved in the ledger; projections are derived views
3. **Distributed consistency verification**: Deterministic reducers allow state comparison across nodes

The architecture flows as:

```text
Events (Ledger) --> Reducer --> Projection State
                       |
                  Checkpoint (SQLite)
```

Reducers are integrated with the ledger layer (`apm2_core::ledger`) and used by domain-specific reducers (`SessionReducer`, `LeaseReducer`, `EvidenceReducer`, `WorkReducer`).

## Key Types

### `Reducer` (trait)

```rust
pub trait Reducer: Send + Sync {
    /// The projection state type.
    type State: Debug + Clone + Send + Sync;

    /// Error type for apply operations.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Returns the unique name of this reducer (used as checkpoint key).
    fn name(&self) -> &'static str;

    /// Applies an event to update the projection state.
    fn apply(&mut self, event: &EventRecord, ctx: &ReducerContext) -> Result<(), Self::Error>;

    /// Returns a reference to the current projection state.
    fn state(&self) -> &Self::State;

    /// Returns a mutable reference to the current projection state.
    fn state_mut(&mut self) -> &mut Self::State;

    /// Resets the reducer to its initial state.
    fn reset(&mut self);
}
```

**Invariants:**

- [INV-0101] **Determinism**: Given the same event sequence and initial state, `apply` MUST produce identical final states. This is verified by property tests comparing replay-from-genesis with replay-from-checkpoint.
- [INV-0102] **Purity**: `apply` must not perform I/O, access global state, or depend on wall-clock time. All state changes derive solely from the event and current state.
- [INV-0103] **Totality**: `apply` must handle all event types relevant to the reducer, returning `Ok(())` for irrelevant events.

**Contracts:**

- [CTR-0101] `name()` must return a unique, stable string used as the checkpoint storage key.
- [CTR-0102] `reset()` must restore the reducer to an empty initial state equivalent to `Default::default()`.

### `CheckpointableReducer` (trait)

```rust
pub trait CheckpointableReducer: Reducer
where
    Self::State: serde::Serialize + serde::de::DeserializeOwned,
{
    /// Serializes the current state for checkpointing.
    fn serialize_state(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self.state())
    }

    /// Deserializes state from a checkpoint.
    fn deserialize_state(&mut self, data: &[u8]) -> Result<(), serde_json::Error> {
        let state: Self::State = serde_json::from_slice(data)?;
        *self.state_mut() = state;
        Ok(())
    }
}
```

**Invariants:**

- [INV-0201] **Round-trip losslessness**: `deserialize_state(serialize_state())` MUST restore identical state.

**Note**: Blanket-implemented for all `Reducer` types with `Serialize + DeserializeOwned` state.

### `ReducerContext`

```rust
#[derive(Debug, Clone)]
pub struct ReducerContext {
    /// Current sequence position in the ledger.
    pub seq_id: u64,

    /// Whether this is a replay from checkpoint (vs genesis).
    pub is_replay: bool,

    /// The checkpoint sequence ID we're replaying from (if any).
    pub checkpoint_seq_id: Option<u64>,
}
```

Provides metadata to reducers during event processing. Useful for reducers that need to distinguish replay from live processing.

### `Checkpoint`

```rust
#[derive(Debug, Clone)]
pub struct Checkpoint {
    /// Unique identifier for this checkpoint.
    pub id: Option<u64>,

    /// Name of the reducer this checkpoint belongs to.
    pub reducer_name: String,

    /// The sequence ID this checkpoint was taken at.
    pub seq_id: u64,

    /// Serialized state data.
    pub state_data: Vec<u8>,

    /// Timestamp when the checkpoint was created.
    pub created_at_ns: u64,
}
```

Represents a saved state snapshot at a specific ledger position.

### `CheckpointStore`

```rust
pub struct CheckpointStore {
    conn: Arc<Mutex<Connection>>,
}
```

SQLite-backed storage for checkpoints. Separate from the event ledger, allowing checkpoints to be recreated from ledger replay if corrupted.

**Key methods:**

- `open(path)` / `in_memory()`: Create persistent or in-memory store
- `save(checkpoint)`: Save checkpoint (upserts at same seq_id)
- `load_latest(reducer_name)`: Load most recent checkpoint
- `load_at_or_before(reducer_name, seq_id)`: Find best replay starting point
- `prune(reducer_name, keep_after_seq_id)`: Delete old checkpoints

### `ReducerRunner`

```rust
pub struct ReducerRunner<'a> {
    ledger: &'a Ledger,
    checkpoint_store: &'a CheckpointStore,
    config: ReducerRunnerConfig,
}
```

Orchestrates reducer execution with checkpoint support.

**Key methods:**

- `run(reducer)`: Run from latest checkpoint (or genesis) to ledger head
- `run_from_genesis(reducer)`: Ignore checkpoints, replay all events
- `run_from_checkpoint(reducer, seq_id)`: Resume from specific checkpoint

### `ReducerRunnerConfig`

```rust
#[derive(Debug, Clone)]
pub struct ReducerRunnerConfig {
    /// Number of events before saving checkpoint (0 disables).
    pub checkpoint_interval: u64,  // default: 1000

    /// Batch size for reading events from ledger.
    pub batch_size: u64,           // default: 100
}
```

### `ReducerRunResult`

```rust
#[derive(Debug, Clone)]
pub struct ReducerRunResult {
    pub last_seq_id: u64,
    pub events_processed: u64,
    pub checkpoint_created: bool,
    pub resumed_from_checkpoint: bool,
}
```

## Public API

### `apply_event(reducer, event, seq_id) -> Result<(), ReducerRunnerError>`

Processes a single event without checkpointing. Useful for real-time event processing where checkpointing is handled separately.

```rust
pub fn apply_event<R>(
    reducer: &mut R,
    event: &EventRecord,
    seq_id: u64,
) -> Result<(), ReducerRunnerError>
where
    R: Reducer,
```

### `ReducerContext::new(seq_id) -> ReducerContext`

Creates context for normal (non-replay) processing.

### `ReducerContext::replay(seq_id, checkpoint_seq_id) -> ReducerContext`

Creates context for checkpoint replay.

## Determinism Requirements

Reducers MUST be deterministic. This is the critical property enabling:

1. **State reconstruction from ledger replay**
2. **Checkpoint restoration correctness**
3. **Distributed consistency verification**

Property tests verify determinism:

```rust
// Property: replay from genesis produces deterministic state
fn prop_replay_from_genesis_is_deterministic(events in arb_events(100)) {
    let mut reducer1 = SessionCountReducer::default();
    let mut reducer2 = SessionCountReducer::default();

    runner.run_from_genesis(&mut reducer1).unwrap();
    runner.run_from_genesis(&mut reducer2).unwrap();

    assert_eq!(reducer1.state(), reducer2.state());
}

// Property: checkpoint + remaining events = full replay
fn prop_checkpoint_replay_equals_genesis_replay(events in arb_events(50)) {
    let mut reducer_checkpoint = SessionCountReducer::default();
    let mut reducer_genesis = SessionCountReducer::default();

    runner.run(&mut reducer_checkpoint).unwrap();       // Uses checkpoints
    runner.run_from_genesis(&mut reducer_genesis).unwrap(); // Full replay

    assert_eq!(reducer_checkpoint.state(), reducer_genesis.state());
}
```

## Examples

### Implementing a Simple Reducer

```rust
use apm2_core::reducer::{Reducer, ReducerContext};
use apm2_core::ledger::EventRecord;

#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
struct CounterState {
    total: u64,
    by_type: HashMap<String, u64>,
}

#[derive(Debug, Default)]
struct EventCountReducer {
    state: CounterState,
}

impl Reducer for EventCountReducer {
    type State = CounterState;
    type Error = std::convert::Infallible;

    fn name(&self) -> &'static str {
        "event-counter"
    }

    fn apply(&mut self, event: &EventRecord, _ctx: &ReducerContext) -> Result<(), Self::Error> {
        self.state.total += 1;
        *self.state.by_type.entry(event.event_type.clone()).or_default() += 1;
        Ok(())
    }

    fn state(&self) -> &Self::State {
        &self.state
    }

    fn state_mut(&mut self) -> &mut Self::State {
        &mut self.state
    }

    fn reset(&mut self) {
        self.state = CounterState::default();
    }
}
```

### Running a Reducer with Checkpoints

```rust
use apm2_core::ledger::Ledger;
use apm2_core::reducer::{CheckpointStore, ReducerRunner, ReducerRunnerConfig};

let ledger = Ledger::open("events.db")?;
let checkpoint_store = CheckpointStore::open("checkpoints.db")?;

let config = ReducerRunnerConfig {
    checkpoint_interval: 1000,  // Checkpoint every 1000 events
    batch_size: 100,
};

let runner = ReducerRunner::with_config(&ledger, &checkpoint_store, config);

let mut reducer = SessionReducer::new();
let result = runner.run(&mut reducer)?;

println!(
    "Processed {} events, resumed: {}, checkpoint: {}",
    result.events_processed,
    result.resumed_from_checkpoint,
    result.checkpoint_created
);
```

### Real-time Event Processing

```rust
use apm2_core::reducer::apply_event;

// Process events as they arrive (checkpointing handled separately)
for (seq_id, event) in event_stream {
    apply_event(&mut reducer, &event, seq_id)?;

    // Periodically save checkpoint
    if seq_id % 1000 == 0 {
        let state_data = reducer.serialize_state()?;
        let checkpoint = Checkpoint::new(reducer.name(), seq_id, state_data);
        checkpoint_store.save(&checkpoint)?;
    }
}
```

## Domain Reducers

APM2 includes four domain-specific reducers implementing this framework:

### `SessionReducer` (`apm2_core::session::reducer`)

Tracks session lifecycle: `Running -> Quarantined | Terminated`

- **Name**: `"session-lifecycle"`
- **State**: `SessionReducerState` (HashMap of session_id to SessionState)
- **Events**: `session.started`, `session.progress`, `session.terminated`, `session.quarantined`, `policy.violation`, `policy.budget_exceeded`
- **Security**: Enforces restart attempt monotonicity (prevents replay attacks)

### `LeaseReducer` (`apm2_core::lease::reducer`)

Manages lease lifecycle: `Active -> Released | Expired`

- **Name**: `"lease-registrar"`
- **State**: `LeaseReducerState` (leases + active_leases_by_work index)
- **Events**: `lease.issued`, `lease.renewed`, `lease.released`, `lease.expired`, `lease.conflict`
- **Security**: Enforces at-most-one lease per work item; requires registrar signature

### `EvidenceReducer` (`apm2_core::evidence::reducer`)

Indexes published evidence artifacts.

- **Name**: `"evidence-publisher"`
- **State**: `EvidenceReducerState` (evidence + evidence_by_work index + bundles)
- **Events**: `evidence.published`, `evidence.gate_receipt`
- **Trust boundary**: Does NOT verify content hashes (CAS layer responsibility)

### `WorkReducer` (`apm2_core::work::reducer`)

Tracks work item lifecycle: `Open -> Claimed -> InProgress -> Review -> Completed | Aborted`

- **Name**: `"work-lifecycle"`
- **State**: `WorkReducerState` (HashMap of work_id to Work)
- **Events**: `work.opened`, `work.transitioned`, `work.completed`, `work.aborted`
- **Security**: Validates transition sequence via `previous_transition_count` (replay protection)

## Related Modules

- [`apm2_core::ledger`](../ledger/AGENTS.md) - Append-only event storage (SQLite with WAL)
- [`apm2_core::session`](../session/AGENTS.md) - Session lifecycle and entropy tracking
- [`apm2_core::lease`](../lease/AGENTS.md) - Lease management and at-most-one enforcement
- [`apm2_core::evidence`](../evidence/AGENTS.md) - Evidence publishing and CAS integration
- [`apm2_core::work`](../work/AGENTS.md) - Work item state machine

## References

- [rust-textbook Chapter 25: Time, Monotonicity, Determinism](/documents/skills/rust-standards/references/40_time_monotonicity_determinism.md) - Determinism requirements for event sourcing
- [rust-textbook Chapter 17: Testing](/documents/skills/rust-standards/references/20_testing_evidence_and_ci.md) - Property-based testing patterns
- [Event Sourcing Pattern](https://martinfowler.com/eaaDev/EventSourcing.html) - Martin Fowler's foundational article
