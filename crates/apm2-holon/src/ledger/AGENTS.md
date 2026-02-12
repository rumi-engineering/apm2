# Ledger

> Append-only, hash-chained event log for holonic execution auditing and replay.

## Overview

The `ledger` module provides an immutable, tamper-evident event log for recording all holonic operations. It has two sub-layers:

1. **Episode events** (`events.rs`): Structured events for episode lifecycle (start, completion) with validated IDs and bounded string fields.
2. **Chain events** (`chain.rs`): General-purpose `LedgerEvent` with BLAKE3 hash chaining, deterministic serialization (RFC 8785 / JCS), and signature support.

The ledger enables auditing, replay, metrics, and tamper detection. Events are linked via a hash chain where each event references the hash of the previous event, creating a structure that detects any modification.

## Key Types

### `EventHash`

```rust
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EventHash([u8; 32]);
```

A 32-byte BLAKE3 hash of a ledger event's canonical representation.

**Invariants:**

- [INV-LG01] `EventHash::ZERO` is the sentinel value for genesis events (all bytes zero).
- [INV-LG02] Hash computation is pure and deterministic: identical events always produce identical hashes.
- [INV-LG03] `from_hex` requires exactly 64 hexadecimal characters.

### `EventHashError`

```rust
pub enum EventHashError {
    InvalidLength { expected: usize, actual: usize },
    InvalidHex,
}
```

Errors from parsing hex-encoded hashes.

### `EventType`

```rust
#[serde(tag = "type", rename_all = "snake_case")]
#[non_exhaustive]
pub enum EventType {
    WorkCreated { title: String },
    WorkClaimed { lease_id: String },
    WorkProgressed { description: String, new_state: WorkLifecycle },
    WorkCompleted { evidence_ids: Vec<String> },
    WorkFailed { reason: String, recoverable: bool },
    WorkEscalated { to_holon_id: String, reason: String },
    WorkCancelled { reason: String },
    EpisodeStarted { episode_id: String, attempt_number: u32 },
    EpisodeCompleted { episode_id: String, outcome: EpisodeOutcome, tokens_consumed: u64 },
    ArtifactEmitted { artifact_id: String, artifact_kind: String, content_hash: Option<String> },
    EvidencePublished { evidence_id: String, requirement_id: String, content_hash: String },
    LeaseIssued { lease_id: String, holder_id: String, expires_at_ns: u64 },
    LeaseRenewed { lease_id: String, new_expires_at_ns: u64 },
    LeaseReleased { lease_id: String, reason: String },
    LeaseExpired { lease_id: String },
    BudgetConsumed { resource_type: String, amount: u64, remaining: u64 },
    BudgetExhausted { resource_type: String, total_used: u64, limit: u64 },
}
```

Discriminated union of all holonic event types (17 variants). Covers work lifecycle, episode, artifact, lease, and resource events.

**Invariants:**

- [INV-LG04] Event type discriminants are stable across versions; new types may be added but existing representations do not change.
- [INV-LG05] `validate()` enforces `MAX_STRING_LEN` (4096) on all string fields and `MAX_EVIDENCE_IDS` (1000) on evidence ID vectors, providing DoS protection.

**Contracts:**

- [CTR-LG01] `type_name()` returns a stable `&'static str` identifier for each variant.
- [CTR-LG02] Category predicates (`is_work_event`, `is_episode_event`, `is_artifact_event`, `is_lease_event`, `is_resource_event`) are mutually exclusive.
- [CTR-LG03] `is_terminal_work_event()` returns `true` only for `WorkCompleted`, `WorkFailed`, and `WorkCancelled`.

### `LedgerEvent`

```rust
pub struct LedgerEvent {
    id: String,
    timestamp_ns: u64,
    work_id: String,
    holon_id: String,
    event_type: EventType,
    previous_hash: EventHash,
    #[serde(with = "serde_bytes")]
    signature: Vec<u8>,
}
```

A single event in the hash-chained ledger. Contains identity, payload, chain linkage, and optional signature.

**Invariants:**

- [INV-LG06] Genesis events have `previous_hash == EventHash::ZERO`.
- [INV-LG07] `canonical_bytes()` produces RFC 8785 (JCS) deterministic JSON, excluding the `signature` field.
- [INV-LG08] `compute_hash()` uses BLAKE3 over `canonical_bytes()`, so the hash is independent of the signature.
- [INV-LG09] `validate()` enforces `MAX_STRING_LEN` on `id`, `work_id`, `holon_id` and `MAX_SIGNATURE_LEN` (128) on signature bytes.

**Contracts:**

- [CTR-LG04] `verify_previous(other)` returns `true` if and only if `self.previous_hash == other.compute_hash()`.
- [CTR-LG05] `canonical_bytes()` is deterministic: two events with identical field values always produce identical byte sequences.
- [CTR-LG06] Signature changes do not affect `compute_hash()` -- this is by design so events can be created unsigned and signed later.

### `LedgerEventBuilder`

```rust
#[derive(Debug, Default)]
pub struct LedgerEventBuilder { /* ... */ }
```

Builder for constructing `LedgerEvent` instances. Required fields: `event_id`, `work_id`, `holon_id`, `event_type`. Optional: `timestamp_ns` (defaults to `current_timestamp_ns()`), `previous_hash` (defaults to `EventHash::ZERO`), `signature`.

**Contracts:**

- [CTR-LG07] `build()` panics if any required field (`event_id`, `work_id`, `holon_id`, `event_type`) is not set.
- [CTR-LG08] When `previous_hash` is not set, the built event is a genesis event.

### `EpisodeStarted`

```rust
#[serde(deny_unknown_fields)]
pub struct EpisodeStarted {
    episode_id: String,
    work_id: String,
    lease_id: String,
    episode_number: u64,
    started_at_ns: u64,
    parent_episode_id: Option<String>,
    remaining_tokens: Option<u64>,
    remaining_time_ms: Option<u64>,
    goal_spec: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    role_spec_hash: Option<[u8; 32]>,
}
```

Event emitted when an episode begins execution.

**Invariants:**

- [INV-LG10] Rejects unknown fields during deserialization (`deny_unknown_fields`).
- [INV-LG11] `role_spec_hash` is a BLAKE3 hash of the `RoleSpecV1` governing the episode (TCK-00331). Optional for backward compatibility.

**Contracts:**

- [CTR-LG09] `try_new()` validates all ID fields via `validate_id()`: non-empty, at most 256 bytes, no `/` or null bytes. Returns `HolonError::InvalidInput` on failure.
- [CTR-LG10] `new()` skips validation; callers must ensure IDs satisfy `validate_id()` preconditions.

### `EpisodeCompleted`

```rust
#[serde(deny_unknown_fields)]
pub struct EpisodeCompleted {
    episode_id: String,
    reason: EpisodeCompletionReason,
    completed_at_ns: u64,
    tokens_consumed: u64,
    time_consumed_ms: u64,
    artifact_count: u64,
    progress_update: Option<String>,
    error_message: Option<String>,
}
```

Event emitted when an episode finishes. Builder-style `with_*` methods set optional consumption metrics.

**Invariants:**

- [INV-LG12] Rejects unknown fields during deserialization.

**Contracts:**

- [CTR-LG11] `is_successful()` returns `true` if and only if `reason` is `GoalSatisfied`.

### `EpisodeCompletionReason`

```rust
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub enum EpisodeCompletionReason {
    GoalSatisfied,
    NeedsContinuation,
    BudgetExhausted { resource: String },
    MaxEpisodesReached { count: u64 },
    TimeoutReached { limit_ms: u64 },
    Blocked { reason: String },
    Escalated { reason: String },
    Error { error: String },
    ExternalSignal { signal: String },
    Stalled { reason: String },
    PolicyViolation { policy: String },
}
```

Why an episode ended (11 variants, non-exhaustive).

**Contracts:**

- [CTR-LG12] `is_successful()` returns `true` only for `GoalSatisfied`.
- [CTR-LG13] `should_continue()` returns `true` only for `NeedsContinuation`.
- [CTR-LG14] `is_resource_limit()` returns `true` for `BudgetExhausted`, `MaxEpisodesReached`, and `TimeoutReached`.
- [CTR-LG15] `is_error()` returns `true` for `Error` and `PolicyViolation`.
- [CTR-LG16] Implements `From<StopCondition>` for bidirectional conversion with the episode controller's stop conditions.

### `EpisodeEvent`

```rust
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub enum EpisodeEvent {
    Started(EpisodeStarted),
    Completed(EpisodeCompleted),
}
```

Wrapper enum for episode-related ledger events. Implements `From<EpisodeStarted>` and `From<EpisodeCompleted>`.

### `EpisodeOutcome`

```rust
#[serde(rename_all = "snake_case")]
pub enum EpisodeOutcome {
    Completed,
    Continuation,
    Failed,
    Interrupted,
    Escalated,
}
```

Outcome discriminant used within `EventType::EpisodeCompleted`.

### `ChainError`

```rust
pub enum ChainError {
    EmptyChain,
    MissingGenesis { event_id: String },
    BrokenLink { event_index: usize, event_id: String, expected_hash: EventHash, actual_hash: EventHash },
    OutOfOrder { event_index: usize, event_id: String },
}
```

Errors from `verify_chain()`. Each variant identifies the specific integrity violation.

### `LedgerValidationError`

```rust
pub enum LedgerValidationError {
    StringTooLong { field: String, max_len: usize, actual_len: usize },
    TooManyEvidenceIds { max_count: usize, actual_count: usize },
    SignatureTooLong { max_len: usize, actual_len: usize },
}
```

Validation errors for DoS protection against oversized payloads.

### Validation Functions

```rust
pub fn validate_id(id: &str, field_name: &str) -> Result<(), HolonError>;
pub fn validate_goal_spec(goal_spec: &str) -> Result<(), HolonError>;
```

**Contracts:**

- [CTR-LG17] `validate_id()` rejects: empty strings, strings exceeding `MAX_ID_LENGTH` (256), strings containing `/` (path traversal prevention), strings containing null bytes.
- [CTR-LG18] `validate_goal_spec()` rejects: strings exceeding `MAX_GOAL_SPEC_LENGTH` (4096), strings containing null bytes. Empty strings are allowed.

### Constants

```rust
pub const MAX_ID_LENGTH: usize = 256;
pub const MAX_GOAL_SPEC_LENGTH: usize = 4096;
```

Internal (non-public) validation constants in `chain.rs`:

```rust
const MAX_STRING_LEN: usize = 4096;
const MAX_EVIDENCE_IDS: usize = 1000;
const MAX_SIGNATURE_LEN: usize = 128;
```

## Public API

| Function / Method | Description |
|---|---|
| `EventHash::ZERO` | Zero-hash sentinel for genesis events. |
| `EventHash::from_bytes(bytes)` | Creates a hash from raw 32-byte array. |
| `EventHash::from_hex(s)` | Parses a hash from 64-character hex string. |
| `EventHash::to_hex()` | Returns the 64-character hex representation. |
| `EventHash::is_zero()` | Returns `true` if this is the zero hash. |
| `EventType::type_name()` | Returns stable string identifier for the event type. |
| `EventType::validate()` | Validates all string/vector fields against size limits. |
| `EventType::is_work_event()` | Category predicate for work lifecycle events. |
| `EventType::is_episode_event()` | Category predicate for episode events. |
| `EventType::is_artifact_event()` | Category predicate for artifact events. |
| `EventType::is_lease_event()` | Category predicate for lease events. |
| `EventType::is_resource_event()` | Category predicate for resource events. |
| `EventType::is_terminal_work_event()` | Returns `true` for terminal work states. |
| `LedgerEvent::builder()` | Returns a `LedgerEventBuilder`. |
| `LedgerEvent::canonical_bytes()` | Produces deterministic JCS bytes for hashing. |
| `LedgerEvent::compute_hash()` | Computes BLAKE3 hash of canonical bytes. |
| `LedgerEvent::verify_previous(event)` | Verifies hash chain linkage. |
| `LedgerEvent::validate()` | Validates all fields against size limits. |
| `LedgerEvent::is_genesis()` | Returns `true` if `previous_hash` is zero. |
| `LedgerEvent::is_signed()` | Returns `true` if signature is non-empty. |
| `EpisodeStarted::try_new(...)` | Creates with ID validation. |
| `EpisodeStarted::new(...)` | Creates without validation (internal use). |
| `EpisodeCompleted::new(...)` | Creates a completion event with builder methods. |
| `verify_chain(events)` | Verifies chain integrity: genesis, hash links, timestamp ordering. |
| `validate_id(id, field_name)` | Validates an ID string. |
| `validate_goal_spec(goal_spec)` | Validates a goal specification string. |
| `current_timestamp_ns()` | Returns current wall-clock time in nanoseconds. |

## Examples

### Building a Hash Chain

```rust
use apm2_holon::ledger::{EventType, LedgerEvent, verify_chain};

let genesis = LedgerEvent::builder()
    .event_id("evt-001")
    .work_id("work-001")
    .holon_id("holon-001")
    .timestamp_ns(1000)
    .event_type(EventType::WorkCreated {
        title: "Implement feature X".to_string(),
    })
    .build();

let second = LedgerEvent::builder()
    .event_id("evt-002")
    .work_id("work-001")
    .holon_id("holon-001")
    .timestamp_ns(2000)
    .event_type(EventType::WorkClaimed {
        lease_id: "lease-001".to_string(),
    })
    .previous_hash(genesis.compute_hash())
    .build();

assert!(verify_chain(&[genesis, second]).is_ok());
```

### Recording Episode Lifecycle

```rust
use apm2_holon::ledger::{
    EpisodeStarted, EpisodeCompleted, EpisodeCompletionReason, EpisodeEvent,
};

let started = EpisodeStarted::try_new("ep-001", "work-123", "lease-456", 1, 1_000_000_000)
    .expect("valid IDs");

let completed = EpisodeCompleted::new(
    "ep-001",
    EpisodeCompletionReason::GoalSatisfied,
    1_500_000_000,
)
.with_tokens_consumed(500)
.with_artifact_count(2);

let events: Vec<EpisodeEvent> = vec![started.into(), completed.into()];
```

## Related Modules

- [Episode controller](../episode/AGENTS.md) - Emits `EpisodeEvent` during execution loops
- [Resource management](../resource/AGENTS.md) - `Lease` and `Budget` referenced in lease events
- [Orchestration](../orchestration/AGENTS.md) - Higher-level orchestration events that wrap ledger events
- [Holon trait (crate root)](../../AGENTS.md) - `StopCondition` converts to `EpisodeCompletionReason`

## References

- [RFC-0019] Automated FAC v0 - End-to-end ingestion, review episode, durable receipt, GitHub projection
- [RFC 8785] JSON Canonicalization Scheme (JCS) - Used for deterministic serialization
- [TCK-00331] Role spec hash attribution in episode events
