# Work Module

> Event-sourced work lifecycle management with reducer-based state projection.

## Overview

The `apm2_core::work` module provides kernel-level work item tracking infrastructure for the APM2 process supervision framework. It implements an event-sourced state machine that processes work lifecycle events from the ledger and maintains a projection of all work items and their states.

This module is distinct from `apm2_holon::work` which defines the holon-level `WorkObject` and `WorkLifecycle` types. The core work module provides:

- **Ledger Integration**: Processes protobuf-encoded work events from the append-only event ledger
- **State Projection**: Maintains a `HashMap`-based projection of work items via the `WorkReducer`
- **Replay Protection**: Validates transition sequences to prevent replay attacks
- **Strict Parsing**: Rejects unknown work types and states (fail-closed)

### Architecture

```text
WorkOpened --> Work (OPEN)
              |
              v
WorkTransitioned --> Work (CLAIMED/IN_PROGRESS/REVIEW/NEEDS_INPUT)
              |
              v
WorkCompleted/WorkAborted --> Work (COMPLETED/ABORTED)
```

## Key Types

### `WorkState`

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum WorkState {
    Open,              // Work is open and available for claiming
    Claimed,           // Work has been claimed by an agent
    InProgress,        // Work is actively being processed
    Review,            // Work is under review
    NeedsInput,        // Work is blocked waiting for input
    NeedsAdjudication, // Work requires human decision
    Completed,         // Terminal: successfully completed
    Aborted,           // Terminal: aborted
}
```

**Invariants:**
- [INV-0101] Terminal states (`Completed`, `Aborted`) allow no further transitions
- [INV-0102] `is_terminal()` returns true only for `Completed` and `Aborted`
- [INV-0103] `is_active()` is the logical negation of `is_terminal()`

**Contracts:**
- [CTR-0101] `can_transition_to()` returns `true` only for valid state machine edges
- [CTR-0102] `parse()` rejects unknown state strings with `WorkError::InvalidWorkState`

### `WorkType`

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum WorkType {
    Ticket,        // Implementation of a specific ticket
    PrdRefinement, // PRD refinement task
    RfcRefinement, // RFC refinement task
    Review,        // Code or artifact review
}
```

**Contracts:**
- [CTR-0103] `parse()` is case-insensitive but rejects unknown types with `WorkError::InvalidWorkType`
- [CTR-0104] `as_str()` returns uppercase canonical form (e.g., `"TICKET"`, `"PRD_REFINEMENT"`)

### `Work`

```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[non_exhaustive]
pub struct Work {
    pub work_id: String,
    pub work_type: WorkType,
    pub state: WorkState,
    pub spec_snapshot_hash: Vec<u8>,
    pub requirement_ids: Vec<String>,
    pub parent_work_ids: Vec<String>,
    pub opened_at: u64,
    pub last_transition_at: u64,
    pub transition_count: u32,
    pub last_rationale_code: String,
    pub evidence_bundle_hash: Option<Vec<u8>>,
    pub evidence_ids: Vec<String>,
    pub gate_receipt_id: Option<String>,
    pub abort_reason: Option<String>,
}
```

**Invariants:**
- [INV-0104] `spec_snapshot_hash` is immutable after creation
- [INV-0105] `transition_count` monotonically increases on each transition
- [INV-0106] `evidence_bundle_hash` and `evidence_ids` are populated only on completion
- [INV-0107] `abort_reason` is populated only on abort

**Contracts:**
- [CTR-0105] `Work::new()` initializes state to `Open` with `transition_count = 0`

### `WorkReducer`

```rust
#[derive(Debug, Default)]
pub struct WorkReducer {
    state: WorkReducerState,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkReducerState {
    pub work_items: HashMap<String, Work>,
}
```

**Invariants:**
- [INV-0108] Reducer is deterministic: same event sequence produces identical state
- [INV-0109] Only events with `event_type.starts_with("work.")` are processed

**Contracts:**
- [CTR-0106] `apply()` returns `Ok(())` for non-work events (no-op)
- [CTR-0107] `reset()` clears all state to empty `WorkReducerState`

### `WorkError`

```rust
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum WorkError {
    WorkAlreadyExists { work_id: String },
    WorkNotFound { work_id: String },
    InvalidTransition { from_state: String, event_type: String },
    TransitionNotAllowed { from_state: WorkState, to_state: WorkState },
    CompletionWithoutEvidence { work_id: String },
    InvalidWorkState { value: String },
    InvalidWorkType { value: String },
    SequenceMismatch { work_id: String, expected: u32, actual: u32 },
    ProtobufDecode(#[from] prost::DecodeError),
}
```

## State Machine Transitions

| From | To | Condition |
|------|----|-----------|
| `Open` | `Claimed` | Agent claims work |
| `Open` | `Aborted` | Explicit cancellation |
| `Claimed` | `InProgress` | Work started |
| `Claimed` | `Open` | Claim released |
| `Claimed` | `Aborted` | Explicit cancellation |
| `InProgress` | `Review` | Submitted for review |
| `InProgress` | `NeedsInput` | Blocked on input |
| `InProgress` | `NeedsAdjudication` | Requires human decision |
| `InProgress` | `Aborted` | Explicit cancellation |
| `Review` | `Completed` | Review approved (requires evidence) |
| `Review` | `InProgress` | Changes requested |
| `Review` | `Aborted` | Explicit cancellation |
| `NeedsInput` | `InProgress` | Input received |
| `NeedsInput` | `Aborted` | Explicit cancellation |
| `NeedsAdjudication` | `InProgress` | Decision received |
| `NeedsAdjudication` | `Aborted` | Explicit cancellation |

## Public API

### `WorkReducer::new() -> Self`

Creates a new work reducer with empty state.

### `WorkReducer::apply(&mut self, event: &EventRecord, ctx: &ReducerContext) -> Result<(), WorkError>`

Applies a work event to update the projection state. Processes:
- `work.opened`: Creates new work item in `Open` state
- `work.transitioned`: Validates and applies state transition
- `work.completed`: Transitions to `Completed` (requires evidence)
- `work.aborted`: Transitions to `Aborted`

### `WorkReducerState::get(&self, work_id: &str) -> Option<&Work>`

Returns the work item for a given ID.

### `WorkReducerState::in_state(&self, state: WorkState) -> Vec<&Work>`

Returns all work items in a specific state.

### `WorkReducerState::active_work(&self) -> Vec<&Work>`

Returns all non-terminal work items.

### `WorkReducerState::by_requirement(&self, requirement_id: &str) -> Vec<&Work>`

Returns work items bound to a specific requirement ID.

### Helper Functions (`helpers` module)

```rust
pub fn work_opened_payload(
    work_id: &str,
    work_type: &str,
    spec_snapshot_hash: Vec<u8>,
    requirement_ids: Vec<String>,
    parent_work_ids: Vec<String>,
) -> Vec<u8>

pub fn work_transitioned_payload_with_sequence(
    work_id: &str,
    from_state: &str,
    to_state: &str,
    rationale_code: &str,
    previous_transition_count: u32,
) -> Vec<u8>

pub fn work_completed_payload(
    work_id: &str,
    evidence_bundle_hash: Vec<u8>,
    evidence_ids: Vec<String>,
    gate_receipt_id: &str,
) -> Vec<u8>

pub fn work_aborted_payload(
    work_id: &str,
    abort_reason: &str,
    rationale_code: &str,
) -> Vec<u8>
```

## Examples

### Creating and Transitioning Work

```rust
use apm2_core::work::{WorkReducer, WorkState, helpers};
use apm2_core::reducer::{Reducer, ReducerContext};
use apm2_core::ledger::EventRecord;

let mut reducer = WorkReducer::new();
let ctx = ReducerContext::new(1);

// Open work
let payload = helpers::work_opened_payload(
    "WORK-001",
    "TICKET",
    vec![0xDE, 0xAD, 0xBE, 0xEF], // spec snapshot hash
    vec!["REQ-001".to_string()],
    vec![],
);
let event = EventRecord::with_timestamp("work.opened", "session-1", "actor", payload, 1_000_000);
reducer.apply(&event, &ctx).unwrap();

// Claim work (transition_count is 0)
let claim_payload = helpers::work_transitioned_payload_with_sequence(
    "WORK-001", "OPEN", "CLAIMED", "agent_claimed", 0
);
let claim_event = EventRecord::with_timestamp(
    "work.transitioned", "session-1", "actor", claim_payload, 2_000_000
);
reducer.apply(&claim_event, &ctx).unwrap();

let work = reducer.state().get("WORK-001").unwrap();
assert_eq!(work.state, WorkState::Claimed);
assert_eq!(work.transition_count, 1);
```

### Querying Work State

```rust
// Get all work in review
let in_review = reducer.state().in_state(WorkState::Review);

// Get active (non-terminal) work
let active = reducer.state().active_work();

// Find work by requirement
let req_work = reducer.state().by_requirement("REQ-001");
```

## Security Considerations

### Replay Protection

Work transitions include a `previous_transition_count` field that must match the work item's current `transition_count`. This prevents:

1. **Direct replay attacks**: Replaying an old transition event fails because the sequence number no longer matches
2. **Cyclic replay attacks**: After `Open -> Claimed -> Open`, replaying the first `Claimed` transition fails because `transition_count` has advanced

```rust
// This will fail with WorkError::SequenceMismatch
let stale_transition = helpers::work_transitioned_payload_with_sequence(
    "WORK-001",
    "OPEN",
    "CLAIMED",
    "claim",
    0,  // Wrong: work.transition_count is now 2 after release
);
```

### Strict Parsing

Unknown work types and states are rejected (fail-closed):

```rust
// WorkError::InvalidWorkType
let bad_type = helpers::work_opened_payload("WORK-001", "UNKNOWN_TYPE", vec![], vec![], vec![]);

// WorkError::InvalidWorkState
let bad_state = helpers::work_transitioned_payload_with_sequence(
    "WORK-001", "INVALID_STATE", "CLAIMED", "test", 0
);
```

### Completion Evidence Requirement

Work cannot transition to `Completed` without evidence:

```rust
// WorkError::CompletionWithoutEvidence
let no_evidence = helpers::work_completed_payload("WORK-001", vec![], vec![], "");
```

## Related Modules

- [`apm2_core::reducer`](../reducer/AGENTS.md) - Reducer trait and checkpoint infrastructure
- [`apm2_core::ledger`](../ledger/AGENTS.md) - Event ledger and `EventRecord` type
- [`apm2_core::events`](../events/AGENTS.md) - Protobuf event definitions (`WorkEvent`, `WorkOpened`, etc.)
- [`apm2_holon::work`](../../../../apm2-holon/src/work.rs) - Holon-level `WorkObject` and `WorkLifecycle`

## Holon vs Core Work Types

| Aspect | `apm2_holon::work` | `apm2_core::work` |
|--------|-------------------|-------------------|
| Purpose | Holon execution tracking | Kernel event projection |
| State Machine | `WorkLifecycle` (8 states) | `WorkState` (8 states) |
| Persistence | In-memory with methods | Event-sourced via reducer |
| Transitions | Method calls (`transition_to_leased()`) | Event replay (`WorkTransitioned`) |
| Concurrency | `version` field for OCC | `transition_count` for replay protection |
| Attempts | `Vec<AttemptRecord>` (max 100) | Not tracked (ledger has full history) |

The holon types are used by agent implementations, while core types are used by the kernel for coordination and audit.

## References

- Rust-textbook Chapter 07: Errors, Panics, Diagnostics - Error type design
- Rust-textbook Chapter 12: API Design, stdlib Quality - State machine patterns
- README.md: Work Lifecycle State Machine section
