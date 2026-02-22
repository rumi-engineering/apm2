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
#[repr(u8)]
pub enum WorkState {
    Open              = 0,  // Work is open and available for claiming
    Claimed           = 1,  // Work has been claimed by an agent
    InProgress        = 2,  // Work is actively being processed
    Review            = 3,  // Work is under review
    NeedsInput        = 4,  // Work is blocked waiting for input
    NeedsAdjudication = 5,  // Work requires human decision
    Completed         = 6,  // Terminal: successfully completed
    Aborted           = 7,  // Terminal: aborted
    CiPending         = 8,  // CI-gated: waiting for CI completion (not claimable)
    ReadyForReview    = 9,  // CI-gated: CI passed, ready for review (claimable)
    Blocked           = 10, // CI-gated: CI failed or blocked (not claimable)
}
```

**Invariants:**
- [INV-0101] Terminal states (`Completed`, `Aborted`) allow no further transitions
- [INV-0102] `is_terminal()` returns true only for `Completed` and `Aborted`
- [INV-0103] `is_active()` is the logical negation of `is_terminal()`
- [INV-0110] Discriminant values are stable for semver compatibility

**Contracts:**
- [CTR-0101] `can_transition_to()` returns `true` only for valid state machine edges
- [CTR-0102] `parse()` rejects unknown state strings with `WorkError::InvalidWorkState`
- [CTR-0108] `is_claimable()` returns `true` only for `Open` and `ReadyForReview`

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
    pub merge_receipt_id: Option<String>,
    pub abort_reason: Option<String>,
    pub pr_number: Option<u64>,      // CI gating: PR number for CI event matching
    pub commit_sha: Option<String>,  // CI gating: commit SHA for CI verification
}
```

**Invariants:**
- [INV-0104] `spec_snapshot_hash` is immutable after creation
- [INV-0105] `transition_count` monotonically increases on each transition
- [INV-0106] `evidence_bundle_hash` and `evidence_ids` are populated only on completion
- [INV-0107] `abort_reason` is populated only on abort
- [INV-0113] `gate_receipt_id` MUST NOT contain merge receipt identifiers (values starting with `merge-receipt-`); use `merge_receipt_id` instead (fail-closed gate)
- [INV-0114] `merge_receipt_id`, when non-empty, MUST start with `merge-receipt-` (positive allowlist); distinct from `gate_receipt_id`. Together with INV-0113 this enforces bidirectional domain separation at the reducer boundary
- [INV-0111] `pr_number` is set only via `WorkPrAssociated` event from pre-CI states (`Claimed` or `InProgress`)
- [INV-0112] `commit_sha` is set together with `pr_number` for CI verification

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
- [INV-0115] Stage-bound digest admission is fail-closed: CI transitions (`CiPending -> ReadyForReview/Blocked`) and `work.completed` admission require a known latest `changeset_published` digest and matching receipt-bound digest context
- [INV-0116] Receipt events bound to stale digests are never admitted into gate/review/merge digest projections
- [INV-0117] Gate receipt collection enforces latest-digest validation: gate receipts bound to superseded changesets are silently dropped (logged, not stored in `ci_receipt_digest_by_work`)
- [INV-0118] Review-start stage boundary (`ReadyForReview -> Review`) requires a known latest changeset and, if a review receipt digest exists, it must match the latest digest

**Contracts:**
- [CTR-0106] `apply()` returns `Ok(())` for non-work events (no-op)
- [CTR-0107] `reset()` clears all state to empty `WorkReducerState`
- [CTR-0111] Non-work digest events (`changeset_published`, gate/review/merge receipt events) are observed before work-event decoding so stage boundaries can enforce latest-digest checks
- [CTR-0112] `enforce_stage_boundary_guards` is called on every state transition, enforcing latest-digest validation at CI completion, review-start, and completion boundaries

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
    MergeReceiptInGateReceiptField { work_id: String, value: String },
    InvalidMergeReceiptId { work_id: String, value: String },
    ProtobufDecode(#[from] prost::DecodeError),
    PrAssociationNotAllowed { work_id: String, current_state: WorkState },
    PrNumberAlreadyAssociated { pr_number: u64, existing_work_id: String },
    CiGatedTransitionUnauthorized { from_state: WorkState, to_state: WorkState, rationale_code: String },
    CiGatedTransitionUnauthorizedActor { from_state: WorkState, actor_id: String },
}
```

## State Machine Transitions

### Standard Transitions

| From | To | Condition |
|------|----|-----------|
| `Open` | `Claimed` | Agent claims work |
| `Open` | `Aborted` | Explicit cancellation |
| `Claimed` | `InProgress` | Work started |
| `Claimed` | `Open` | Claim released |
| `Claimed` | `Aborted` | Explicit cancellation |
| `InProgress` | `Review` | Submitted for review (non-CI path) |
| `InProgress` | `CiPending` | PR created, waiting for CI |
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

### CI-Gated Transitions

| From | To | Condition |
|------|----|-----------|
| `CiPending` | `ReadyForReview` | CI passed (`CIWorkflowCompleted` with success) |
| `CiPending` | `Blocked` | CI failed (`CIWorkflowCompleted` with failure) |
| `CiPending` | `Aborted` | Explicit cancellation |
| `ReadyForReview` | `Review` | Review agent claims work |
| `ReadyForReview` | `Aborted` | Explicit cancellation |
| `Blocked` | `CiPending` | CI retried (after fix pushed) |
| `Blocked` | `InProgress` | Work returned to implementation |
| `Blocked` | `Aborted` | Explicit cancellation |

## Public API

### `WorkReducer::new() -> Self`

Creates a new work reducer with empty state.

### `WorkReducer::apply(&mut self, event: &EventRecord, ctx: &ReducerContext) -> Result<(), WorkError>`

Applies a work event to update the projection state. Processes:
- `work.opened`: Creates new work item in `Open` state
- `work.transitioned`: Validates and applies state transition
- `work.completed`: Transitions to `Completed` (requires evidence)
- `work.aborted`: Transitions to `Aborted`
- `work.pr_associated`: Associates a PR number and commit SHA with a work item (CI gating)

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
    merge_receipt_id: &str,
) -> Vec<u8>

pub fn work_aborted_payload(
    work_id: &str,
    abort_reason: &str,
    rationale_code: &str,
) -> Vec<u8>

pub fn work_pr_associated_payload(
    work_id: &str,
    pr_number: u64,
    commit_sha: &str,
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
let no_evidence = helpers::work_completed_payload("WORK-001", vec![], vec![], "", "");
```

### Gate Receipt / Merge Receipt Domain Separation (TCK-00650)

The `gate_receipt_id` field is reserved for gate-level receipts (AAT, Quality, Security). Merge receipt identifiers (values matching `merge-receipt-*`) MUST be placed in the dedicated `merge_receipt_id` field. The reducer enforces **bidirectional** domain separation at event application time:

1. **INV-0113 (gate field guard)**: `gate_receipt_id` MUST NOT start with `merge-receipt-`. Violators receive `WorkError::MergeReceiptInGateReceiptField`.
2. **INV-0114 (merge field allowlist)**: `merge_receipt_id`, when non-empty, MUST start with `merge-receipt-`. Violators receive `WorkError::InvalidMergeReceiptId`.

Both checks execute before any state mutation (admission-before-mutation).

```rust
// WorkError::MergeReceiptInGateReceiptField
let bad1 = helpers::work_completed_payload(
    "WORK-001", vec![1], vec!["E1".into()], "merge-receipt-abc123", "",
);
// Fails: merge receipt pattern rejected in gate_receipt_id

// WorkError::InvalidMergeReceiptId
let bad2 = helpers::work_completed_payload(
    "WORK-001", vec![1], vec!["E1".into()], "", "gate-receipt-in-wrong-field",
);
// Fails: merge_receipt_id doesn't start with "merge-receipt-"

// Correct usage: merge receipt in dedicated field
let good = helpers::work_completed_payload(
    "WORK-001", vec![1], vec!["E1".into()], "", "merge-receipt-abc123",
);
```

### PR Association Constraints (CI Gating)

PR association is restricted to prevent CI gating bypass:

1. **State Restriction**: PR association is only allowed from `Claimed` or `InProgress` state. This permits manual/operator-supervised push flows before explicit `InProgress` transition while still preventing CI gating bypass from `CiPending`, `Blocked`, and terminal states.

```rust
// WorkError::PrAssociationNotAllowed - work must be in Claimed/InProgress
let bad_pr = helpers::work_pr_associated_payload("WORK-001", 42, "sha123");
// Fails if work is in CiPending, Blocked, or terminal states
```

2. **Uniqueness Constraint (CTR-CIQ002)**: A PR number cannot be associated with multiple active work items. This prevents CI result confusion where CI events could incorrectly transition unrelated work.

```rust
// WorkError::PrNumberAlreadyAssociated - PR 42 already used by WORK-001
let duplicate_pr = helpers::work_pr_associated_payload("WORK-002", 42, "sha456");
```

3. **Commit SHA Storage**: The commit SHA is stored alongside the PR number to enable verification that CI results match the specific commit pushed by the agent (preventing stale CI results from triggering transitions).

4. **CI-Gated Transition Authorization**: Transitions from CI-gated states (`CiPending`) require BOTH:
   - **Authorized rationale codes** (`ci_passed` or `ci_failed`) that only the CI processor emits
   - **Authorized actor ID** (`system:ci-processor`) that identifies the CI event processor

This two-layer check prevents agents from bypassing CI gating by directly emitting `WorkTransitioned` events with the correct rationale code but an unauthorized actor identity.

```rust
// WorkError::CiGatedTransitionUnauthorized - unauthorized rationale
let bypass_attempt = helpers::work_transitioned_payload_with_sequence(
    "WORK-001", "CI_PENDING", "READY_FOR_REVIEW", "manual_bypass", 3
);
// Fails because "manual_bypass" is not an authorized CI rationale code

// WorkError::CiGatedTransitionUnauthorizedActor - unauthorized actor
// Even with correct rationale, wrong actor is rejected
let actor_bypass = helpers::work_transitioned_payload_with_sequence(
    "WORK-001", "CI_PENDING", "READY_FOR_REVIEW", "ci_passed", 3
);
// Fails if signed by actor other than "system:ci-processor"
```

5. **Commit SHA Verification in CI Queue**: The CI event processor verifies that the CI event's `commit_sha` matches the work item's stored `commit_sha`. This prevents stale CI results (from old commits) from incorrectly transitioning work items that have been updated with new commits.

### WorkReadyForNextPhase Event

The `WorkReadyForNextPhase` event is an **audit event** emitted by the CI event processor (outside the reducer) when CI results trigger a phase transition. It is NOT processed by the `WorkReducer`.

The actual state transition is done via `WorkTransitioned` events:
- CI success: `CiPending` -> `ReadyForReview` via `WorkTransitioned`
- CI failure: `CiPending` -> `Blocked` via `WorkTransitioned`

The `WorkReadyForNextPhase` event provides audit trail for:
- Which CI event triggered the transition
- The previous and next phases
- Timestamp of the transition decision

This separation allows the reducer to remain focused on state management while the audit event captures the full context of CI-triggered transitions.

## Related Modules

- [`apm2_core::reducer`](../reducer/AGENTS.md) - Reducer trait and checkpoint infrastructure
- [`apm2_core::ledger`](../ledger/AGENTS.md) - Event ledger and `EventRecord` type
- [`apm2_core::events`](../events/AGENTS.md) - Protobuf event definitions (`WorkEvent`, `WorkOpened`, etc.)
- [`apm2_holon::work`](../../../apm2-holon/src/work.rs) - Holon-level `WorkObject` and `WorkLifecycle`

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

- `documents/skills/rust-standards/references/15_errors_panics_diagnostics.md` - Error type design
- `documents/skills/rust-standards/references/25_api_design_stdlib_quality.md` - State machine patterns
- README.md: Work Lifecycle State Machine section
- RFC-0032: FAC vNext changeset identity
- TCK-00672: End-to-end changeset identity wiring (CSID-004 stage boundary guards)
