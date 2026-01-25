# Budget Module

> Resource budget enforcement for session limits implementing default-deny, fail-closed semantics.

## Overview

The `apm2_core::budget` module tracks and enforces resource budgets for agent sessions. It implements three budget types:

1. **Token budget**: Maximum inference tokens consumed
2. **Tool call budget**: Maximum number of tool invocations
3. **Time budget**: Maximum elapsed time for the session

This module integrates with the policy layer (TCK-00010) to deny requests when budgets are exceeded and emits `BudgetExceeded` events when limits are hit.

### Security Model

Budget enforcement is a **fail-closed** mechanism:

- Requests are denied when any budget is exceeded
- Budget checks occur before tool execution
- Exceeding a budget results in a `BudgetExceeded` event
- Time budgets are tracked automatically (cannot be manipulated)

## Key Types

### `BudgetType`

```rust
pub enum BudgetType {
    Token,      // Inference tokens
    ToolCalls,  // Tool invocation count
    Time,       // Elapsed time in ms
}
```

**Contracts:**
- [CTR-0001] `as_str()` returns protocol-compatible strings: `TOKEN`, `TOOL_CALLS`, `TIME`
- [CTR-0002] `all()` returns all budget types for iteration

### `BudgetConfig`

```rust
pub struct BudgetConfig {
    pub token_budget: u64,     // 0 = unlimited
    pub tool_call_budget: u64, // 0 = unlimited
    pub time_budget_ms: u64,   // 0 = unlimited
}
```

**Invariants:**
- [INV-0001] A budget of `0` means unlimited (no enforcement)
- [INV-0002] Budgets are immutable once a session starts

**Contracts:**
- [CTR-0003] `default()` provides reasonable defaults for typical sessions
- [CTR-0004] `unlimited()` creates a config with all budgets disabled

### `BudgetTracker`

```rust
pub struct BudgetTracker {
    session_id: String,
    config: BudgetConfig,
    tokens_consumed: u64,
    tool_calls_consumed: u64,
    started_at: Instant,
    started_at_ns: u64,
}
```

**Invariants:**
- [INV-0003] Consumption counters use saturating arithmetic (no overflow)
- [INV-0004] Time budget tracks wall-clock time from session start
- [INV-0005] Time cannot be charged directly (tracked automatically)

**Contracts:**
- [CTR-0005] `charge()` returns `Err(BudgetChargeError::TimeCannotBeCharged)` for `BudgetType::Time` (time is tracked automatically)
- [CTR-0006] `try_charge()` returns result without side effect on exceeded
- [CTR-0007] `is_exceeded()` returns `false` for unlimited budgets

### `BudgetCheckResult`

```rust
pub enum BudgetCheckResult {
    Allowed { budget_type, current, limit, charge },
    Exceeded { budget_type, consumed, limit, requested },
    Unlimited { budget_type },
}
```

**Contracts:**
- [CTR-0008] `is_allowed()` returns `true` for `Allowed` and `Unlimited`
- [CTR-0009] `is_exceeded()` returns `true` only for `Exceeded`

## Public API

### Creating a Tracker

```rust
use apm2_core::budget::{BudgetConfig, BudgetTracker};

let config = BudgetConfig::builder()
    .token_budget(100_000)
    .tool_call_budget(500)
    .time_budget_ms(3_600_000)
    .build();

let mut tracker = BudgetTracker::new("session-123", config);
```

### Checking and Charging Budgets

```rust
use apm2_core::budget::BudgetType;

// Check before execution
if tracker.can_charge(BudgetType::ToolCalls, 1) {
    // Execute tool...
    tracker.record_tool_call();
}

// Or use try_charge for atomic check-and-charge
let result = tracker.try_charge(BudgetType::Token, 5000);
if result.is_exceeded() {
    // Handle budget exceeded
}
```

### Checking for Exceeded Budgets

```rust
// Check specific budget
if tracker.is_exceeded(BudgetType::Token) {
    // Emit BudgetExceeded event
}

// Find first exceeded budget
if let Some(budget_type) = tracker.first_exceeded() {
    // Handle exceeded budget
}

// Check if any budget is exceeded
if tracker.is_any_exceeded() {
    // Session should be terminated
}
```

## Integration Points

### With Policy Layer (TCK-00010)

The `PolicyEngine::evaluate_with_budget()` method integrates budget enforcement with policy evaluation:

```rust
use apm2_core::budget::{BudgetConfig, BudgetTracker};
use apm2_core::policy::{LoadedPolicy, PolicyEngine, BUDGET_EXCEEDED_RULE_ID};

let policy = LoadedPolicy::from_yaml("...").unwrap();
let engine = PolicyEngine::new(&policy);
let tracker = BudgetTracker::new("session-123", BudgetConfig::default());

// Evaluate with budget checking (budget is checked BEFORE policy rules)
let result = engine.evaluate_with_budget(&request, &tracker);

if result.is_denied() && result.rule_id == BUDGET_EXCEEDED_RULE_ID {
    // Budget exceeded - emit BudgetExceeded event
    let event = create_budget_exceeded_event(&tracker, tracker.first_exceeded().unwrap());
}
```

**Key properties:**
- Budget checks occur BEFORE policy rule evaluation (fail-closed gate)
- Budget exceeded decisions use `rule_id = "BUDGET_EXCEEDED"`
- Budget exceeded decisions use `rationale_code = "{TYPE}_BUDGET_EXCEEDED"`
- Policy rules cannot override budget limits

### With Event Emission

Use the helper functions to create `BudgetExceeded` events:

```rust
use apm2_core::budget::{BudgetTracker, BudgetType, create_budget_exceeded_event};

if let Some(exceeded) = tracker.first_exceeded() {
    let event = create_budget_exceeded_event(&tracker, exceeded);
    // Emit to ledger...
}
```

Or create events from parts:

```rust
use apm2_core::budget::{BudgetType, create_budget_exceeded_event_from_parts};

let event = create_budget_exceeded_event_from_parts(
    "session-123".to_string(),
    BudgetType::Token,
    100_000,  // limit
    150_000,  // consumed
);
```

### With Session Lifecycle

Budget exhaustion should trigger session termination:

```rust
// In session supervisor
if tracker.is_any_exceeded() {
    // Terminate session with appropriate classification
    terminate_session(
        session_id,
        ExitClassification::BudgetExceeded,
        format!("{}_EXHAUSTED", tracker.first_exceeded().unwrap().as_str()),
    );
}
```

## Related Modules

- [`apm2_core::events`](../events/AGENTS.md) - `BudgetExceeded` event definition
- [`apm2_core::session`](../session/AGENTS.md) - Session lifecycle integration
- [`apm2_core::tool`](../tool/AGENTS.md) - Tool request validation
- [`apm2_core::session::entropy`](../session/AGENTS.md) - Entropy budget (distinct from resource budgets)

## References

- PRD-0001 REQ-0019: Budgeting and resource accounting requirement
- PRD-0001 REQ-0005: Deterministic policy evaluation and provenance
- RFC-0001 TCK-00011: Budget enforcement ticket
