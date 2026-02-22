# Events Module

> Protocol Buffer-based kernel event types for APM2's event-sourced architecture.

## Overview

The `apm2_core::events` module defines all event types that flow through the APM2 kernel's append-only ledger. Events are generated from Protocol Buffer definitions via `prost-build` and provide deterministic serialization required for cryptographic signatures.

This module is the foundation of APM2's event-sourcing architecture:
- Events are the single source of truth for all state changes
- The ledger stores events immutably with hash-chain linking
- Reducers project events into queryable state
- Signatures ensure authenticity and non-repudiation

### Canonical Encoding Constraints

Protocol Buffers do not guarantee deterministic serialization for repeated fields. To ensure signature verification works correctly:

- No maps are used in message types (maps have non-deterministic ordering)
- All repeated fields must be sorted via `Canonicalize::canonicalize()` before signing
- `BTreeMap` is used for any map-like structures in Rust code

## Key Types

### `KernelEvent`

The universal envelope wrapping all kernel events.

```rust
pub struct KernelEvent {
    /// Monotonic sequence number within this ledger
    pub sequence: u64,
    /// Hash of the previous event (32 zero bytes for genesis)
    pub previous_hash: Vec<u8>,
    /// Timestamp when event was created
    pub timestamp: Option<prost_types::Timestamp>,
    /// Actor ID that produced this event
    pub actor_id: String,
    /// Session ID (if applicable)
    pub session_id: String,
    /// Ed25519 signature over canonical bytes
    pub signature: Vec<u8>,
    /// Schema version (current: 1)
    pub schema_version: u32,
    /// Event payload (oneof)
    pub payload: Option<kernel_event::Payload>,
}

pub enum kernel_event::Payload {
    Session(SessionEvent),
    Work(WorkEvent),
    Tool(ToolEvent),
    Lease(LeaseEvent),
    Policy(PolicyEvent),
    Adjudication(AdjudicationEvent),
    Evidence(EvidenceEvent),
    Key(KeyEvent),
}
```

**Invariants:**
- [INV-0001] `sequence` must be monotonically increasing within a ledger
- [INV-0002] `previous_hash` must equal the hash of the event with `sequence - 1`, or 32 zero bytes for genesis
- [INV-0003] `signature` must be valid Ed25519 over canonical encoding (excluding signature field)

**Contracts:**
- [CTR-0001] Events must be canonicalized before signing via `Canonicalize::canonicalize()`
- [CTR-0002] Genesis events must use 32 zero bytes for `previous_hash` at API boundaries

### `SessionEvent`

Lifecycle events for agent sessions.

```rust
pub enum session_event::Event {
    Started(SessionStarted),
    Progress(SessionProgress),
    Terminated(SessionTerminated),
    Quarantined(SessionQuarantined),
    CrashDetected(SessionCrashDetected),
    RestartScheduled(SessionRestartScheduled),
}
```

| Event | Description |
|-------|-------------|
| `SessionStarted` | Session process launched with entropy budget |
| `SessionProgress` | Heartbeat, tool completion, or milestone |
| `SessionTerminated` | Normal exit (SUCCESS, FAILURE, TIMEOUT, ENTROPY_EXCEEDED) |
| `SessionQuarantined` | Session isolated due to policy violation |
| `SessionCrashDetected` | Unexpected process exit or crash |
| `SessionRestartScheduled` | Restart scheduled with backoff |

### `WorkEvent`

Lifecycle events for work items (tickets, PRDs, RFCs, reviews).

```rust
pub enum work_event::Event {
    Opened(WorkOpened),
    Transitioned(WorkTransitioned),
    Completed(WorkCompleted),
    Aborted(WorkAborted),
}
```

**Invariants:**
- [INV-0004] `WorkTransitioned.previous_transition_count` must match the work's current transition count (replay protection)

### `ToolEvent`

Tool request, decision, and execution events.

```rust
pub enum tool_event::Event {
    Requested(ToolRequested),
    Decided(ToolDecided),
    Executed(ToolExecuted),
}
```

| Event | Description |
|-------|-------------|
| `ToolRequested` | Agent requests tool execution |
| `ToolDecided` | Policy engine allows/denies (ALLOW, DENY) |
| `ToolExecuted` | Execution result (SUCCESS, FAILURE, TIMEOUT) |

### `LeaseEvent`

Work item lease management for exclusive access.

```rust
pub enum lease_event::Event {
    Issued(LeaseIssued),
    Renewed(LeaseRenewed),
    Released(LeaseReleased),
    Expired(LeaseExpired),
    Conflict(LeaseConflict),
}
```

### `PolicyEvent`

Policy enforcement events.

```rust
pub enum policy_event::Event {
    Loaded(PolicyLoaded),
    Violation(PolicyViolation),
    BudgetExceeded(BudgetExceeded),
}
```

### `AdjudicationEvent`

Human-in-the-loop decision events.

```rust
pub enum adjudication_event::Event {
    Requested(AdjudicationRequested),
    Vote(AdjudicationVote),
    Resolved(AdjudicationResolved),
    Timeout(AdjudicationTimeout),
}
```

### `EvidenceEvent`

Artifact and gate receipt events.

```rust
pub enum evidence_event::Event {
    Published(EvidencePublished),
    GateReceipt(GateReceiptGenerated),
}
```

### `WorkGraphEvent` (RFC-0032, TCK-00642)

Dependency edge events between work items in the work graph.

```rust
pub enum work_graph_event::Event {
    Added(WorkEdgeAdded),
    Removed(WorkEdgeRemoved),
    Waived(WorkEdgeWaived),
}
```

| Event | Description |
|-------|-------------|
| `WorkEdgeAdded` | Directional dependency edge added (from -> to) |
| `WorkEdgeRemoved` | Previously established edge removed |
| `WorkEdgeWaived` | Edge intentionally overridden with audit justification |

**Invariants:**
- [INV-TOPIC-005] Event type strings use `work_graph.edge.*` prefix, NOT `work.*`, to avoid WorkReducer decoding collision
- Topic derivation emits topics for BOTH `from_work_id` and `to_work_id` (multi-topic derivation)

### `KeyEvent`

Key rotation events for actor signing keys.

```rust
pub enum key_event::Event {
    Rotated(KeyRotated),
}
```

**Contracts:**
- [CTR-0003] `KeyRotated.old_key_signature` must be signed by the old key to prove chain of custody

### `Canonicalize` Trait

Ensures deterministic encoding by sorting repeated fields.

```rust
pub trait Canonicalize {
    /// Sorts all repeated fields to ensure canonical encoding.
    fn canonicalize(&mut self);
}
```

Implemented for types with repeated fields:
- `KernelEvent` (delegates to nested payload)
- `WorkOpened` (sorts `requirement_ids`, `parent_work_ids`)
- `WorkCompleted` (sorts `evidence_ids`)
- `AdjudicationRequested` (sorts `options`)
- `EvidencePublished` (sorts `verification_command_ids`)
- `GateReceiptGenerated` (sorts `evidence_ids`)
- `LeaseConflict` (sorts `conflicting_lease_ids`)

## Public API

### Event Construction and Encoding

```rust
use apm2_core::events::{KernelEvent, SessionEvent, SessionStarted};
use apm2_core::events::kernel_event::Payload;
use apm2_core::events::session_event::Event;
use prost::Message;

// Create event
let started = SessionStarted {
    session_id: "session-123".to_string(),
    actor_id: "actor-456".to_string(),
    adapter_type: "claude-code".to_string(),
    work_id: "work-789".to_string(),
    lease_id: "lease-012".to_string(),
    entropy_budget: 1000,
    resume_cursor: 0,
    restart_attempt: 0,
};

let kernel_event = KernelEvent {
    sequence: 1,
    session_id: "session-123".to_string(),
    payload: Some(Payload::Session(SessionEvent {
        event: Some(Event::Started(started)),
    })),
    ..Default::default()
};

// Encode to bytes
let bytes = kernel_event.encode_to_vec();

// Decode from bytes
let decoded = KernelEvent::decode(bytes.as_slice()).unwrap();
```

### Canonicalization Before Signing

```rust
use apm2_core::events::{Canonicalize, WorkOpened};

let mut opened = WorkOpened {
    work_id: "work-1".to_string(),
    work_type: "TICKET".to_string(),
    spec_snapshot_hash: vec![],
    requirement_ids: vec!["REQ-C".into(), "REQ-A".into(), "REQ-B".into()],
    parent_work_ids: vec!["parent-2".into(), "parent-1".into()],
};

// Sort repeated fields before signing
opened.canonicalize();

// Now requirement_ids is ["REQ-A", "REQ-B", "REQ-C"]
// and parent_work_ids is ["parent-1", "parent-2"]
```

## Examples

### Full Event Lifecycle

```rust
use apm2_core::events::{
    Canonicalize, KernelEvent, WorkEvent, WorkOpened, WorkTransitioned,
    kernel_event::Payload, work_event::Event,
};
use prost::Message;

// 1. Create work opened event
let mut opened = WorkOpened {
    work_id: "TCK-00001".to_string(),
    work_type: "TICKET".to_string(),
    spec_snapshot_hash: vec![0xab; 32],
    requirement_ids: vec!["REQ-002".into(), "REQ-001".into()],
    parent_work_ids: vec![],
};

// 2. Canonicalize before wrapping
opened.canonicalize();

// 3. Wrap in kernel event
let mut kernel_event = KernelEvent {
    sequence: 1,
    previous_hash: vec![0u8; 32], // Genesis
    actor_id: "orchestrator".to_string(),
    session_id: String::new(),
    schema_version: 1,
    payload: Some(Payload::Work(WorkEvent {
        event: Some(Event::Opened(opened)),
    })),
    ..Default::default()
};

// 4. Encode canonical bytes for signing
let canonical_bytes = kernel_event.encode_to_vec();

// 5. Sign and attach signature (using crypto module)
// kernel_event.signature = signer.sign(&canonical_bytes);

// 6. Store in ledger
let final_bytes = kernel_event.encode_to_vec();
```

### Pattern Matching on Payloads

```rust
use apm2_core::events::{KernelEvent, kernel_event, session_event, work_event};

fn handle_event(event: &KernelEvent) {
    match &event.payload {
        Some(kernel_event::Payload::Session(session)) => {
            match &session.event {
                Some(session_event::Event::Started(s)) => {
                    println!("Session {} started", s.session_id);
                }
                Some(session_event::Event::Terminated(t)) => {
                    println!("Session {} terminated: {}", t.session_id, t.exit_classification);
                }
                _ => {}
            }
        }
        Some(kernel_event::Payload::Work(work)) => {
            match &work.event {
                Some(work_event::Event::Opened(w)) => {
                    println!("Work {} opened", w.work_id);
                }
                Some(work_event::Event::Completed(w)) => {
                    println!("Work {} completed", w.work_id);
                }
                _ => {}
            }
        }
        _ => {}
    }
}
```

## Related Modules

- [`apm2_core::ledger`](../ledger/AGENTS.md) - Append-only SQLite storage for events
- [`apm2_core::reducer`](../reducer/AGENTS.md) - Event processing and state projection
- [`apm2_core::crypto`](../crypto/AGENTS.md) - Hash-chain and Ed25519 signatures for events
- [`apm2_core::session`](../session/AGENTS.md) - Session management (emits SessionEvents)
- [`apm2_core::work`](../work/AGENTS.md) - Work item management (emits WorkEvents)
- [`apm2_core::lease`](../lease/AGENTS.md) - Lease management (emits LeaseEvents)
- [`apm2_core::evidence`](../evidence/AGENTS.md) - Evidence artifacts (emits EvidenceEvents)
