# Lease Module

> Lease registrar for work item ownership tracking with at-most-one exclusive claim semantics.

## Overview

The lease module provides the lease management infrastructure for the APM2 kernel. Leases ensure **at-most-one** agent can claim a work item at any time, implementing the exclusive access pattern required for safe concurrent work distribution.

```text
LeaseIssued --> Lease (ACTIVE)
               |
               v
LeaseRenewed --> Lease (ACTIVE, new expires_at)
               |
               v
LeaseReleased/LeaseExpired --> Lease (RELEASED/EXPIRED)
```

The module follows the **event sourcing** pattern: all state changes are driven by events from the ledger, and the `LeaseReducer` maintains the current projection state. This separation allows:

- **Deterministic replay**: The same event sequence always produces the same state
- **Checkpointing**: State can be serialized and restored efficiently
- **Audit trail**: The ledger provides a complete history of lease operations

### Key Concepts

- **Lease**: A time-bounded exclusive claim on a work item
- **Registrar**: The authority that issues and signs leases
- **At-most-one**: Only one active lease per `work_id` at any time
- **Signature**: Registrar signs all lease operations for authenticity

## Key Types

### `LeaseState`

```rust
#[non_exhaustive]
pub enum LeaseState {
    /// Lease is active and valid.
    Active,
    /// Lease has been released by the holder.
    Released,
    /// Lease has expired due to timeout.
    Expired,
}
```

**Invariants:**
- [INV-0101] State transitions are irreversible: `Active -> {Released, Expired}` with no cycles
- [INV-0102] `is_terminal()` returns `true` for `Released` and `Expired`; operations on terminal leases fail

**Contracts:**
- [CTR-0101] `parse()` is case-insensitive and returns `LeaseError::InvalidLeaseState` for unknown values
- [CTR-0102] `as_str()` returns canonical uppercase representation for serialization

### `ReleaseReason`

```rust
#[non_exhaustive]
pub enum ReleaseReason {
    /// Work was completed successfully.
    Completed,
    /// Work was aborted.
    Aborted,
    /// Lease holder voluntarily released the lease.
    Voluntary,
}
```

**Contracts:**
- [CTR-0201] `parse()` is case-insensitive; invalid values return `LeaseError::InvalidReleaseReason`
- [CTR-0202] Release reason is recorded for audit; affects no runtime behavior

### `Lease`

```rust
#[non_exhaustive]
pub struct Lease {
    /// Unique identifier for this lease.
    pub lease_id: String,
    /// The work item this lease grants access to.
    pub work_id: String,
    /// The actor holding this lease.
    pub actor_id: String,
    /// Current lifecycle state.
    pub state: LeaseState,
    /// Timestamp when the lease was issued (Unix nanos).
    pub issued_at: u64,
    /// Timestamp when the lease expires (Unix nanos).
    pub expires_at: u64,
    /// Monotonic tick when the lease was issued (RFC-0016 HTF).
    pub issued_at_tick: Option<HtfTick>,
    /// Monotonic tick when the lease expires (RFC-0016 HTF).
    pub expires_at_tick: Option<HtfTick>,
    /// Registrar signature over the lease issuance.
    pub registrar_signature: Vec<u8>,
    /// Number of times this lease has been renewed.
    pub renewal_count: u32,
    /// Timestamp of the last renewal (Unix nanos), if any.
    pub last_renewed_at: Option<u64>,
    /// Release reason, if the lease was released.
    pub release_reason: Option<ReleaseReason>,
    /// Timestamp when the lease was terminated (released or expired).
    pub terminated_at: Option<u64>,
}
```

**Time Model (RFC-0016 HTF):**
- `issued_at_tick` / `expires_at_tick`: Authoritative for expiry checks (tick-based, monotonic)
- `issued_at` / `expires_at`: Retained for backwards compatibility and audit (wall time)
- Wall time changes do not affect lease validity when tick-based fields are present
- SEC-CTRL-FAC-0015: Fail-closed behavior if tick data is missing

**Invariants:**
- [INV-0301] `lease_id` is unique across all leases; duplicates are rejected
- [INV-0302] `expires_at > issued_at` (enforced at issuance; zero/negative duration rejected)
- [INV-0303] `renewal_count` uses saturating arithmetic; cannot overflow
- [INV-0304] `terminated_at` is set from lease's `expires_at` (not event's `expired_at`) to prevent pruning evasion
- [INV-0305] Tick-based expiry is immune to wall-clock manipulation (RFC-0016 HTF)

**Contracts:**
- [CTR-0301] `is_expired_at_tick(t)` returns `true` iff `state == Active && t.value() >= expires_at_tick.value()` OR tick data missing (fail-closed)
- [CTR-0302] `ticks_remaining(t)` returns `expires_at_tick.value() - t.value()` (saturating to 0), or 0 if tick data missing
- [CTR-0303] `summary()` returns a lightweight view excluding signature bytes
- [CTR-0304] `is_expired_at(t)` (DEPRECATED) uses wall time - prefer tick-based methods
- [CTR-0305] `time_remaining(t)` (DEPRECATED) uses wall time - prefer tick-based methods

### `LeaseReducerState`

```rust
pub struct LeaseReducerState {
    /// Map of lease ID to lease.
    pub leases: HashMap<String, Lease>,
    /// Map of work ID to active lease ID (only one lease per work allowed).
    pub active_leases_by_work: HashMap<String, String>,
}
```

**Invariants:**
- [INV-0401] For every entry in `active_leases_by_work`, the referenced lease exists in `leases` and has `state == Active`
- [INV-0402] At most one entry in `active_leases_by_work` per `work_id` (at-most-one enforcement)

**Contracts:**
- [CTR-0401] `get_active_lease_for_work(work_id)` returns `Some` only if work has an active lease
- [CTR-0402] `prune_terminal_leases()` removes only `Released`/`Expired` leases; active leases untouched
- [CTR-0403] `prune_terminal_leases_before(ts)` uses `terminated_at` for comparison (not event timestamp)

### `LeaseReducer`

```rust
pub struct LeaseReducer {
    state: LeaseReducerState,
}
```

The reducer processes lease events and maintains the current state projection.

**Invariants:**
- [INV-0501] State machine: `(none) -> Active -> {Released, Expired}` (no cycles)
- [INV-0502] `apply()` is deterministic; same event sequence produces identical state
- [INV-0503] Events with `event_type` not starting with `"lease."` are ignored (Ok returned)

**Contracts:**
- [CTR-0501] `apply()` returns `LeaseError::WorkAlreadyLeased` if attempting to issue for already-leased work
- [CTR-0502] `apply()` returns `LeaseError::LeaseAlreadyExists` if lease ID already exists
- [CTR-0503] `apply()` returns `LeaseError::MissingSignature` if `registrar_signature` is empty
- [CTR-0504] `apply()` returns `LeaseError::LeaseAlreadyTerminal` for operations on Released/Expired leases
- [CTR-0505] `apply()` returns `LeaseError::Unauthorized` if actor releasing lease is not the holder

### `LeaseError`

```rust
#[non_exhaustive]
pub enum LeaseError {
    WorkAlreadyLeased { work_id: String, existing_lease_id: String },
    LeaseNotFound { lease_id: String },
    LeaseAlreadyTerminal { lease_id: String, current_state: String },
    LeaseExpired { lease_id: String, expired_at: u64 },
    InvalidReleaseReason { value: String },
    InvalidLeaseState { value: String },
    InvalidSignature { lease_id: String },
    MissingSignature { lease_id: String },
    RenewalDoesNotExtend { lease_id: String, current_expires_at: u64, new_expires_at: u64 },
    DecodeError(prost::DecodeError),
    LeaseAlreadyExists { lease_id: String },
    Unauthorized { lease_id: String, actor_id: String },
    InvalidExpiration { lease_id: String, provided: u64, lease_expires_at: u64 },
    InvalidInput { field: String, reason: String },
}
```

**Contracts:**
- [CTR-0601] All error variants include sufficient context for diagnosis
- [CTR-0602] `#[non_exhaustive]` ensures forward compatibility

## Public API

### Reducer Interface

The `LeaseReducer` implements the `Reducer` trait from `apm2_core::reducer`:

```rust
impl Reducer for LeaseReducer {
    type State = LeaseReducerState;
    type Error = LeaseError;

    fn name(&self) -> &'static str { "lease-registrar" }
    fn apply(&mut self, event: &EventRecord, ctx: &ReducerContext) -> Result<(), Self::Error>;
    fn state(&self) -> &Self::State;
    fn state_mut(&mut self) -> &mut Self::State;
    fn reset(&mut self);
}
```

### Helper Functions

The `helpers` module provides functions for creating lease event payloads:

```rust
pub mod helpers {
    pub fn lease_issued_payload(
        lease_id: &str,
        work_id: &str,
        actor_id: &str,
        issued_at: u64,
        expires_at: u64,
        registrar_signature: Vec<u8>,
    ) -> Vec<u8>;

    pub fn lease_renewed_payload(
        lease_id: &str,
        new_expires_at: u64,
        registrar_signature: Vec<u8>,
    ) -> Vec<u8>;

    pub fn lease_released_payload(lease_id: &str, release_reason: &str) -> Vec<u8>;

    pub fn lease_expired_payload(lease_id: &str, expired_at: u64) -> Vec<u8>;

    pub fn lease_conflict_payload(
        work_id: &str,
        conflicting_lease_ids: Vec<String>,
        resolution: &str,
    ) -> Vec<u8>;
}
```

### State Queries

```rust
impl LeaseReducerState {
    /// Returns the lease for a given ID.
    pub fn get(&self, lease_id: &str) -> Option<&Lease>;

    /// Returns the active lease for a work ID.
    pub fn get_active_lease_for_work(&self, work_id: &str) -> Option<&Lease>;

    /// Checks if a work item has an active lease.
    pub fn has_active_lease(&self, work_id: &str) -> bool;

    /// Returns all active leases.
    pub fn active_leases(&self) -> Vec<&Lease>;

    /// Returns all leases for a given actor.
    pub fn leases_by_actor(&self, actor_id: &str) -> Vec<&Lease>;

    /// Returns leases that have expired by the given tick (RFC-0016 HTF).
    /// Tick-based, immune to wall-clock manipulation.
    pub fn get_expired_but_active_at_tick(&self, current_tick: &HtfTick) -> Vec<&Lease>;

    /// Returns leases that have expired but are still marked Active.
    /// DEPRECATED: Use get_expired_but_active_at_tick for tick-based expiry.
    pub fn get_expired_but_active(&self, current_time: u64) -> Vec<&Lease>;

    /// Returns count statistics.
    pub fn len(&self) -> usize;
    pub fn active_count(&self) -> usize;
    pub fn released_count(&self) -> usize;
    pub fn expired_count(&self) -> usize;
    pub fn terminal_count(&self) -> usize;

    /// Prune terminal leases to prevent unbounded memory growth.
    pub fn prune_terminal_leases(&mut self) -> usize;
    pub fn prune_terminal_leases_before(&mut self, before_timestamp: u64) -> usize;
}
```

## Security Model

The lease module follows **default-deny, least-privilege, fail-closed** principles:

### Trust Boundaries

1. **Signature Verification**: The reducer checks that `registrar_signature` is non-empty but does NOT perform cryptographic verification. This assumes:
   - Events are verified by the Command Handler layer before ledger append
   - Replay is from a trusted ledger instance

2. **Replay Protection**: The reducer relies on the ledger layer for event deduplication. If terminal leases are pruned, the reducer no longer remembers those lease IDs. Protection must be enforced at the ledger layer.

### Security Properties

- **Registrar signing**: All lease events require a registrar signature
- **Duplicate rejection**: Attempting to issue a lease for already-leased work fails
- **Expiration enforcement**: Expired leases are auto-detected via `get_expired_but_active()`
- **Authorization**: Only the lease holder can release their lease
- **Pruning evasion prevention**: `terminated_at` uses lease's `expires_at`, not attacker-provided `expired_at`
- **Input validation**: IDs limited to 128 bytes; signatures limited to 512 bytes

### Attack Mitigations

1. **Early Expiration Attack**: Rejected if `event.expired_at < lease.expires_at`
2. **Unauthorized Release Attack**: Rejected if `actor_id != lease.actor_id`
3. **Pruning Evasion Attack**: `terminated_at` set from `lease.expires_at`, not event payload

## Examples

### Basic Usage

```rust
use apm2_core::lease::{LeaseReducer, LeaseState};
use apm2_core::lease::helpers;
use apm2_core::ledger::EventRecord;
use apm2_core::reducer::{Reducer, ReducerContext};

let mut reducer = LeaseReducer::new();
let ctx = ReducerContext::new(1);

// Issue a lease
let payload = helpers::lease_issued_payload(
    "lease-001",
    "work-001",
    "agent-001",
    1_000_000_000,  // issued_at
    2_000_000_000,  // expires_at
    vec![1, 2, 3, 4],  // registrar signature
);
let event = EventRecord::new("lease.issued", "session-1", "registrar", payload);
reducer.apply(&event, &ctx).unwrap();

// Query the lease
let lease = reducer.state().get("lease-001").unwrap();
assert_eq!(lease.state, LeaseState::Active);
assert!(reducer.state().has_active_lease("work-001"));
```

### Lease Lifecycle

```rust
// Renew the lease
let renew_payload = helpers::lease_renewed_payload(
    "lease-001",
    3_000_000_000,  // new expiration
    vec![5, 6, 7, 8],  // new signature
);
reducer.apply(&EventRecord::new("lease.renewed", "s", "registrar", renew_payload), &ctx)?;

// Release the lease
let release_payload = helpers::lease_released_payload("lease-001", "COMPLETED");
reducer.apply(&EventRecord::new("lease.released", "s", "agent-001", release_payload), &ctx)?;

// Work is now available for a new lease
assert!(!reducer.state().has_active_lease("work-001"));
```

### State Pruning

```rust
// Prune all terminal leases
let pruned = reducer.state_mut().prune_terminal_leases();
println!("Pruned {} terminal leases", pruned);

// Or prune only leases terminated before a timestamp
let pruned = reducer.state_mut().prune_terminal_leases_before(1_500_000_000);
```

### Detecting Expired Leases

```rust
let current_time = 2_500_000_000;  // Current timestamp

// Find leases that have expired but haven't been marked as Expired yet
let expired = reducer.state().get_expired_but_active(current_time);
for lease in expired {
    // Emit LeaseExpired events for these
    let payload = helpers::lease_expired_payload(&lease.lease_id, current_time);
    reducer.apply(&EventRecord::new("lease.expired", "s", "registrar", payload), &ctx)?;
}
```

## Related Modules

- [`apm2_core::reducer`](../reducer/AGENTS.md) - Defines the `Reducer` trait implemented by `LeaseReducer`
- [`apm2_core::ledger`](../ledger/AGENTS.md) - Event storage and replay; source of `EventRecord`
- [`apm2_core::work`](../work/AGENTS.md) - Work item tracking; leases grant access to work items
- [`apm2_holon::resource::Lease`](../../../apm2-holon/src/resource/lease.rs) - Holonic lease type with scoped budgets and derivation

### Relationship to apm2_holon::Lease

The `apm2_holon::resource::Lease` type extends the kernel lease concept with:

- **Scope**: `LeaseScope` constraining allowed work IDs, tools, and namespaces
- **Budget**: `Budget` tracking episodes, tool calls, tokens, and duration
- **Derivation**: Parent-child lease relationships for sub-holons
- **Signing**: Canonical byte representation for cryptographic signatures

The kernel `apm2_core::lease` module tracks lease lifecycle via event sourcing, while `apm2_holon::Lease` provides the runtime authorization primitive with scope and budget enforcement.

## References

- [APM2 Rust Standards] [Errors, Panics, Diagnostics](/documents/skills/rust-standards/references/15_errors_panics_diagnostics.md) - Error type design
- [APM2 Rust Standards] [API Design](/documents/skills/rust-standards/references/18_api_design_and_semver.md) - `#[non_exhaustive]` and builder patterns
- [APM2 Rust Standards] [Security-Adjacent Rust](/documents/skills/rust-standards/references/34_security_adjacent_rust.md) - Trust boundaries and input validation
