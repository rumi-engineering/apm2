# Session Module

> Event-sourced session lifecycle state machine with entropy-based health monitoring and crash recovery.

## Overview

The session module (`apm2_core::session`) implements the session lifecycle state machine for the APM2 kernel. Sessions represent agent execution contexts that progress through states based on events, enabling deterministic session management with state transitions, event emission, and checkpoint support.

This module is central to APM2's crash-only design philosophy: sessions track accumulated "chaos" (errors, stalls, violations) via an entropy budget, and when that budget is exceeded, the session must be terminated or quarantined.

### Architectural Position

```
apm2_core::ledger (EventRecord)
          |
          v
apm2_core::session (SessionReducer)
          |
          v
SessionState projection
          |
          +---> Crash Detection & Classification
          |
          +---> Quarantine Management
          |
          +---> Restart Coordination
```

### State Machine

```text
                    SessionStarted
        +---------------------------------------+
        |                                       v
    +-------+                              +---------+
    |(none) |                              | Running |<----------+
    +-------+                              +----+----+           |
                                                |           SessionProgress
                +-------------------------------+---------------------------+
                |                               |                           |
    SessionTerminated                  SessionQuarantined          (loop back)
                |                               |
                v                               v
        +------------+                 +-------------+
        | Terminated |                 | Quarantined |
        +------------+                 +-------------+
```

## Key Types

### `SessionState`

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum SessionState {
    Running {
        started_at: u64,
        actor_id: String,
        work_id: String,
        lease_id: String,
        adapter_type: String,
        entropy_budget: u64,
        progress_count: u64,
        entropy_consumed: u64,
        error_count: u64,
        violation_count: u64,
        stall_count: u64,
        timeout_count: u64,
        resume_cursor: u64,
        restart_attempt: u32,
    },
    Terminated {
        started_at: u64,
        terminated_at: u64,
        exit_classification: ExitClassification,
        rationale_code: String,
        final_entropy: u64,
        last_restart_attempt: u32,
    },
    Quarantined {
        started_at: u64,
        quarantined_at: u64,
        reason: String,
        quarantine_until: u64,
        last_restart_attempt: u32,
    },
}
```

**Invariants:**
- [INV-0001] Sessions can only transition from `Running` to terminal states (`Terminated`, `Quarantined`)
- [INV-0002] `restart_attempt` must be strictly monotonically increasing across session restarts (prevents replay attacks)
- [INV-0003] `entropy_consumed` is monotonically non-decreasing within a session lifecycle
- [INV-0004] Terminal states (`Terminated`, `Quarantined`) preserve `last_restart_attempt` for monotonicity enforcement

**Contracts:**
- [CTR-0001] `is_active()` returns `true` only for `Running` state
- [CTR-0002] `is_terminal()` returns `true` for `Terminated` and `Quarantined` states
- [CTR-0003] `is_entropy_exceeded()` returns `true` when `entropy_consumed >= entropy_budget`

### `ExitClassification`

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExitClassification {
    Success,
    Failure,
    Timeout,
    EntropyExceeded,
}
```

**Contracts:**
- [CTR-0004] `parse()` defaults to `Failure` for unknown classification strings
- [CTR-0005] `as_str()` returns uppercase string representation (e.g., "SUCCESS", "FAILURE")

### `QuarantineReason`

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum QuarantineReason {
    EntropyExceeded { budget: u64, consumed: u64 },
    ExcessiveViolations { violation_count: u64, threshold: u64 },
    CrashLoop { restart_count: u32, threshold: u32 },
    NonRestartableCrash { signal: i32, signal_name: String },
    Manual { reason: String },
}
```

**Invariants:**
- [INV-0005] Quarantine triggers are evaluated in priority order: entropy > violations > crash loop > signals

### `CrashType`

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CrashType {
    CleanExit,
    ErrorExit { exit_code: i32 },
    Signal { signal: i32, signal_name: String },
    Timeout,
    EntropyExceeded,
    Unknown,
}
```

**Contracts:**
- [CTR-0006] `is_restartable()` returns `false` for: `CleanExit`, `EntropyExceeded`, and non-restartable signals (SIGSEGV, SIGBUS, SIGFPE, SIGILL, SIGABRT, SIGSYS)
- [CTR-0007] `is_success()` returns `true` only for `CleanExit`

### `EntropyBudgetConfig`

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntropyBudgetConfig {
    pub budget: u64,
    pub error_weight: u64,
    pub violation_weight: u64,
    pub stall_weight: u64,
    pub timeout_weight: u64,
}
```

**Default Weights:**
| Source | Default | Strict | Lenient |
|--------|---------|--------|---------|
| Error | 10 | 25 | 5 |
| Violation | 50 | 100 | 25 |
| Stall | 25 | 50 | 10 |
| Timeout | 15 | 30 | 8 |
| Budget | 1000 | (configurable) | (configurable) |

### `EntropyTracker`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyTracker {
    session_id: String,
    config: EntropyBudgetConfig,
    consumed: u64,
    error_count: u64,
    violation_count: u64,
    stall_count: u64,
    timeout_count: u64,
    events: Vec<EntropyEvent>,
}
```

**Invariants:**
- [INV-0006] `consumed` uses saturating arithmetic to prevent overflow
- [INV-0007] `remaining()` returns `budget.saturating_sub(consumed)`

### `SessionReducer`

```rust
#[derive(Debug, Default)]
pub struct SessionReducer {
    state: SessionReducerState,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionReducerState {
    pub sessions: HashMap<String, SessionState>,
}
```

**Invariants:**
- [INV-0008] Reducer is deterministic: same event sequence produces identical final state
- [INV-0009] State counts satisfy: `len() == active_count() + terminated_count() + quarantined_count()`

**Contracts:**
- [CTR-0008] Implements `Reducer` trait with `name() = "session-lifecycle"`
- [CTR-0009] Handles event types: `session.started`, `session.progress`, `session.terminated`, `session.quarantined`, `session.crash_detected`, `session.restart_scheduled`, `policy.violation`, `policy.budget_exceeded`

## Public API

### Session State

#### `SessionState::is_active() -> bool`
Returns `true` if the session is in `Running` state.

#### `SessionState::is_terminal() -> bool`
Returns `true` if the session is in `Terminated` or `Quarantined` state.

#### `SessionState::is_entropy_exceeded() -> bool`
Returns `true` if entropy budget has been exhausted.

#### `SessionState::entropy_summary(session_id) -> Option<EntropyTrackerSummary>`
Returns entropy tracking summary for `Running` sessions.

#### `SessionState::last_restart_attempt() -> u32`
Returns the restart attempt number (for monotonicity enforcement).

### Entropy Tracking

#### `EntropyTracker::new(session_id, config) -> Self`
Creates a new entropy tracker for a session.

#### `EntropyTracker::record_error(details) -> u64`
Records an error event and returns the entropy cost charged.

#### `EntropyTracker::record_violation(details) -> u64`
Records a policy violation and returns the entropy cost charged.

#### `EntropyTracker::record_stall(details) -> u64`
Records a stall detection and returns the entropy cost charged.

#### `EntropyTracker::record_timeout(details) -> u64`
Records a timeout and returns the entropy cost charged.

#### `EntropyTracker::is_exceeded() -> bool`
Returns `true` if the entropy budget has been exceeded.

### Quarantine Management

#### `QuarantineManager::should_quarantine(eval) -> Option<QuarantineReason>`
Evaluates whether a session should be quarantined based on its state.

#### `QuarantineManager::calculate_duration(previous_quarantines) -> Duration`
Calculates quarantine duration using exponential backoff (wall clock).

#### `QuarantineManager::calculate_duration_ticks(previous_quarantines) -> Option<u64>`
Calculates quarantine duration in ticks using exponential backoff (RFC-0016 HTF).

#### `QuarantineManager::is_quarantine_expired_at_tick(quarantine_until_tick, current_tick) -> bool`
Checks if a quarantine has expired based on ticks (RFC-0016 HTF). Returns `false` (NOT expired) on tick rate mismatch to keep quarantine active (fail-closed).

#### `QuarantineManager::quarantine_until_tick(current_tick, duration_ticks) -> HtfTick`
Calculates the quarantine expiry tick (RFC-0016 HTF).

#### `QuarantineInfo::is_expired_at_tick(current_tick) -> bool`
Checks if a quarantine has expired based on ticks (RFC-0016 HTF). Returns `false` on tick rate mismatch or legacy quarantine (fail-closed).

#### `QuarantineInfo::is_expired_at_tick_or_wall(current_tick, current_wall_ns) -> bool`
Checks if a quarantine has expired with wall-clock fallback for legacy quarantines. Returns `false` on tick rate mismatch (fail-closed).

#### `QuarantineInfo::ticks_remaining(current_tick) -> u64`
Returns remaining ticks until quarantine expires (RFC-0016 HTF). Returns `u64::MAX` on tick rate mismatch or legacy quarantine (fail-closed).

### Crash Detection

#### `classify_exit_status(status) -> CrashType`
Classifies an exit status into a `CrashType`.

#### `classify_signal(signal) -> (String, bool)`
Returns signal name and whether it's restartable.

#### `is_signal_restartable(signal) -> bool`
Returns whether a signal is considered restartable.

#### `to_exit_classification(crash_type) -> ExitClassification`
Converts a `CrashType` to session `ExitClassification`.

### Restart Coordination

#### `RestartCoordinator::should_restart(crash_event, entropy_summary) -> RestartDecision`
Determines whether a crashed session should be restarted.

#### `RestartCoordinator::should_restart_with_quarantine(...) -> RestartDecision`
Determines restart decision with quarantine integration.

### Recovery

#### `find_last_session_cursor(events, session_id) -> Result<u64, RecoveryError>`
Finds the last ledger sequence ID for a session.

#### `find_last_progress_cursor(events, session_id) -> Result<u64, RecoveryError>`
Finds the sequence ID of the last progress event.

#### `replay_session_state(events, session_id, up_to_seq_id) -> Result<SessionRecoveryState, RecoveryError>`
Replays session state from ledger events.

#### `validate_recovery_point(events, seq_id, session_id) -> Result<bool, RecoveryError>`
Validates that a recovery point is valid for a session.

## Valid State Transitions

| From | Event | To | Notes |
|------|-------|----|-------|
| (none) | `SessionStarted` | Running | Initial session creation |
| Running | `SessionProgress` | Running | Counters updated, entropy tracked |
| Running | `SessionTerminated` | Terminated | Final state, preserves restart_attempt |
| Running | `SessionQuarantined` | Quarantined | Temporary block, preserves restart_attempt |
| Terminated | `SessionStarted` | Running | Restart allowed if `restart_attempt` monotonically increases |
| Quarantined | `SessionStarted` | Running | Restart allowed if `restart_attempt` monotonically increases and quarantine expired |

**Invalid transitions return `SessionError::InvalidTransition`.**

## Examples

### Basic Session Lifecycle

```rust
use apm2_core::ledger::EventRecord;
use apm2_core::reducer::{Reducer, ReducerContext};
use apm2_core::session::{
    ExitClassification, SessionReducer, SessionState, helpers,
};

// Create a reducer
let mut reducer = SessionReducer::new();
let ctx = ReducerContext::new(1);

// Start a session
let payload = helpers::session_started_payload(
    "session-123",
    "actor-456",
    "claude-code",
    "work-789",
    "lease-012",
    1000, // entropy budget
);
let event = EventRecord::with_timestamp(
    "session.started",
    "session-123",
    "actor-456",
    payload,
    1_000_000_000,
);
reducer.apply(&event, &ctx).unwrap();

// Check state
let state = reducer.state().get("session-123").unwrap();
assert!(state.is_active());
assert_eq!(state.entropy_budget(), Some(1000));
```

### Entropy Tracking

```rust
use apm2_core::session::entropy::{EntropyBudgetConfig, EntropyTracker};

let config = EntropyBudgetConfig::default();
let mut tracker = EntropyTracker::new("session-123", config);

// Record errors (10 entropy each by default)
tracker.record_error("tool_failure");
tracker.record_error("tool_failure");

// Record a violation (50 entropy by default)
tracker.record_violation("unauthorized_access");

// Check status
println!("Consumed: {}", tracker.consumed());     // 70
println!("Remaining: {}", tracker.remaining());   // 930
println!("Exceeded: {}", tracker.is_exceeded());  // false
```

### Quarantine Decision

```rust
use apm2_core::session::quarantine::{
    QuarantineConfig, QuarantineEvaluation, QuarantineManager,
};

let manager = QuarantineManager::with_defaults();

// Evaluate session state
let eval = QuarantineEvaluation::new("session-123")
    .with_entropy(1000, 1500)  // exceeded
    .with_violations(3)
    .with_restarts(2);

if let Some(reason) = manager.should_quarantine(&eval) {
    let duration = manager.calculate_duration(0); // first quarantine
    println!("Quarantine: {} for {:?}", reason, duration);
}
```

### Restart Coordination

```rust
use apm2_core::session::crash::{CrashEvent, CrashType};
use apm2_core::session::restart_coordinator::{RestartCoordinator, RestartDecision};

let coordinator = RestartCoordinator::with_defaults("session-123", "work-456");

let crash = CrashEvent::new(
    "session-123",
    "work-456",
    CrashType::ErrorExit { exit_code: 1 },
    1_000_000_000, // timestamp_ns
    42,            // last_ledger_cursor
    0,             // restart_count
    5000,          // uptime_ms
);

match coordinator.should_restart(&crash, None) {
    RestartDecision::Restart { delay, resume_cursor, attempt_number } => {
        println!("Restart in {:?} from cursor {}", delay, resume_cursor);
    }
    RestartDecision::Terminate { reason } => {
        println!("Terminate: {}", reason);
    }
    RestartDecision::Quarantine { reason, until } => {
        println!("Quarantine until {}: {}", until, reason);
    }
}
```

### Session Restart with Monotonicity

```rust
use apm2_core::session::{SessionReducer, helpers};

let mut reducer = SessionReducer::new();
let ctx = ReducerContext::new(1);

// Initial session (restart_attempt = 0)
let start = helpers::session_started_payload(
    "session-123", "actor", "claude-code", "work", "lease", 1000,
);
reducer.apply(&EventRecord::with_timestamp(
    "session.started", "session-123", "actor", start, 1_000_000_000,
), &ctx).unwrap();

// Terminate
let term = helpers::session_terminated_payload(
    "session-123", "FAILURE", "crashed", 500,
);
reducer.apply(&EventRecord::with_timestamp(
    "session.terminated", "session-123", "actor", term, 2_000_000_000,
), &ctx).unwrap();

// Restart with attempt=1 (MUST be > 0)
let restart = helpers::session_started_payload_with_restart(
    "session-123", "actor", "claude-code", "work", "lease",
    1000,  // entropy_budget
    500,   // resume_cursor
    1,     // restart_attempt (monotonically increasing)
);
reducer.apply(&EventRecord::with_timestamp(
    "session.started", "session-123", "actor", restart, 3_000_000_000,
), &ctx).unwrap();

// Attempting restart_attempt=0 again would fail with RestartAttemptNotMonotonic
```

## Error Types

### `SessionError`

```rust
pub enum SessionError {
    InvalidTransition { from_state: String, event_type: String },
    SessionNotFound { session_id: String },
    SessionAlreadyExists { session_id: String },
    RestartAttemptNotMonotonic {
        session_id: String,
        previous_attempt: u32,
        new_attempt: u32,
    },
    DecodeError(prost::DecodeError),
}
```

### `RecoveryError`

```rust
pub enum RecoveryError {
    SessionNotFound { session_id: String },
    InvalidRecoveryPoint { seq_id: u64, session_id: String },
    DecodeError(String),
}
```

## Related Modules

- [`apm2_core::ledger`](../ledger/AGENTS.md) - Event storage and hash chain verification
- [`apm2_core::reducer`](../reducer/AGENTS.md) - Reducer trait and checkpoint support
- [`apm2_core::restart`](../restart/AGENTS.md) - Restart policies and backoff strategies
- [`apm2_core::events`](../events/AGENTS.md) - Protobuf event definitions (SessionEvent, PolicyEvent)
- [`apm2_holon::resource`](../../../apm2-holon/AGENTS.md) - Budget and lease types

## References

### rust-standards References

- [15_errors_panics_diagnostics.md](/documents/skills/rust-standards/references/15_errors_panics_diagnostics.md) - Error handling patterns used in SessionError and RecoveryError
- [32_testing_fuzz_miri_evidence.md](/documents/skills/rust-standards/references/32_testing_fuzz_miri_evidence.md) - Property-based testing with proptest (see tests.rs)
- [40_time_monotonicity_determinism.md](/documents/skills/rust-standards/references/40_time_monotonicity_determinism.md) - Monotonicity enforcement for restart_attempt

### Design Principles

1. **Crash-Only Design**: Sessions are designed to be stopped and restarted at any time. State is reconstructed from the event ledger.

2. **Entropy Budget**: A quantitative measure of session health. Different event types have configurable weights, and when the budget is exhausted, the session must be terminated.

3. **Monotonicity Enforcement**: The `restart_attempt` counter prevents replay attacks by requiring strictly increasing values across session restarts.

4. **Deterministic Replay**: The `SessionReducer` is a pure function - replaying the same events produces identical state, enabling crash recovery and distributed consistency verification.

5. **Quarantine as Circuit Breaker**: Quarantine prevents problematic sessions from consuming resources through exponential backoff on repeated failures.
