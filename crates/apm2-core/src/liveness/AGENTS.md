# Liveness Module

> Liveness heartbeat receipts and bounded restart policy primitives for launch execution monitoring (RFC-0020).

## Overview

The `apm2_core::liveness` module implements liveness probes for the APM2 kernel. It provides two core capabilities:

1. **Heartbeat receipts** -- Deterministic `LivenessHeartbeatReceiptV1` structures that capture agent health state, bound to HTF (Holonic Time Fabric) ticks and episode identity.
2. **Bounded restart policy** -- A `RestartController` that enforces windowed restart limits and circuit-breaker semantics to prevent crash loops.

The module also exposes a top-level gate function `check_liveness_for_progression` that evaluates whether an agent's liveness state permits authoritative progression. This gate is fail-closed: ambiguous, stalled, or crashed verdicts always deny progression.

```text
LivenessHeartbeatReceiptV1
       |
       v
check_liveness_for_progression(heartbeat, current_tick, max_age)
       |
       +--- Ok(())  --> healthy, fresh, within restart limits
       +--- Err(LivenessGateDenial) --> deny with reason code
                |
                +--- UnhealthyVerdict (Stalled | Crashed)
                +--- AmbiguousState
                +--- StaleHeartbeat
                +--- RestartLimitExceeded

RestartController
       |
       +--- record_restart(tick) --> Allow { attempt } | Deny { reason }
       +--- record_terminal(reason) --> Deny { reason }
       +--- check_stall(last_heartbeat_tick, current_tick) --> bool
```

## Key Types

### `HealthVerdict`

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HealthVerdict {
    Healthy,
    Stalled,
    Crashed,
    Ambiguous,
}
```

**Invariants:**

- [INV-LV01] `Ambiguous` is fail-closed: treated as unhealthy for all authoritative gate checks.
- [INV-LV02] Only `Healthy` permits authoritative progression.

### `LivenessHeartbeatReceiptV1`

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LivenessHeartbeatReceiptV1 {
    pub run_id: String,
    pub episode_id: [u8; 32],
    pub emitted_at_tick: u64,
    pub time_envelope_ref: [u8; 32],
    pub health_verdict: HealthVerdict,
    pub restart_count: u32,
    pub max_restarts: u32,
    pub uptime_ms: u64,
    pub detail: Option<String>,
}
```

**Invariants:**

- [INV-LV03] `run_id` is bounded to `MAX_RUN_ID_LENGTH` (256 bytes) at deserialization time.
- [INV-LV04] `detail` is bounded to `MAX_HEARTBEAT_DETAIL_LENGTH` (512 bytes) at deserialization time.
- [INV-LV05] Serialization round-trip is lossless for valid receipts.

**Contracts:**

- [CTR-LV01] `has_valid_bounds()` returns `true` only if all string fields are within their length limits.
- [CTR-LV02] Deserialization rejects `run_id` exceeding `MAX_RUN_ID_LENGTH` and `detail` exceeding `MAX_HEARTBEAT_DETAIL_LENGTH`.

### `LivenessGateDenial`

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LivenessGateDenial {
    pub reason: LivenessDenialReason,
    pub detail: String,
}
```

**Invariants:**

- [INV-LV06] `detail` is always truncated to `MAX_LIVENESS_DENIAL_DETAIL_LENGTH` (512 bytes), respecting UTF-8 char boundaries.

**Contracts:**

- [CTR-LV03] `new()` truncates detail if it exceeds the maximum length.
- [CTR-LV04] Deserialization rejects detail strings exceeding the maximum length.

### `LivenessDenialReason`

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LivenessDenialReason {
    UnhealthyVerdict,
    StaleHeartbeat,
    RestartLimitExceeded,
    AmbiguousState,
}
```

### `RestartPolicyConfig`

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestartPolicyConfig {
    pub max_restarts: u32,
    pub window_ticks: u64,
    pub circuit_breaker_threshold_ticks: u64,
    pub circuit_breaker_max_failures: u32,
    pub stall_timeout_ticks: u64,
}
```

**Contracts:**

- [CTR-LV05] `validate()` rejects `max_restarts > MAX_RESTARTS_LIMIT` (1000).
- [CTR-LV06] `validate()` rejects `circuit_breaker_max_failures > MAX_CIRCUIT_BREAKER_FAILURES` (100).

### `RestartController`

```rust
#[derive(Debug, Clone)]
pub struct RestartController {
    config: RestartPolicyConfig,
    restart_ticks: Vec<u64>,
    circuit_breaker_open: bool,
    terminal_reason: Option<TerminalReason>,
}
```

**Invariants:**

- [INV-LV07] Once a terminal reason is recorded, all subsequent `record_restart` calls return `Deny` with that reason (monotone terminal).
- [INV-LV08] Circuit breaker is monotone: once opened, it never closes.
- [INV-LV09] Restart window pruning uses `saturating_sub` to prevent underflow.

**Contracts:**

- [CTR-LV07] `new(config)` validates the config before constructing the controller.
- [CTR-LV08] `record_restart(tick)` returns `Allow { attempt }` if within limits, or `Deny { reason }` with a `TerminalReason`.
- [CTR-LV09] `record_terminal(reason)` is idempotent: sets the terminal reason and returns `Deny`.
- [CTR-LV10] `check_stall(last_heartbeat_tick, current_tick)` returns `true` if the gap exceeds `stall_timeout_ticks`.

### `RestartDecision`

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RestartDecision {
    Allow { attempt: u32 },
    Deny { reason: TerminalReason },
}
```

### `TerminalReason`

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TerminalReason {
    CleanExit,
    RestartLimitExceeded,
    CircuitBreakerOpen,
    StallTimeout,
    OperatorShutdown,
    UnrecoverableError,
}
```

### `RestartPolicyConfigError`

```rust
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RestartPolicyConfigError {
    MaxRestartsExceedsLimit { actual: u32, limit: u32 },
    CircuitBreakerFailuresExceedsLimit { actual: u32, limit: u32 },
}
```

## Public API

### Gate Function

- `check_liveness_for_progression(latest_heartbeat, current_tick, max_heartbeat_age_ticks) -> Result<(), LivenessGateDenial>` -- Fail-closed liveness gate. Returns `Ok(())` only when the heartbeat is healthy, fresh, and within restart limits.

### Heartbeat

- `LivenessHeartbeatReceiptV1::has_valid_bounds() -> bool` -- Checks all bounded string constraints.

### Restart Controller

- `RestartController::new(config) -> Result<Self, RestartPolicyConfigError>` -- Creates a controller with validated config.
- `RestartController::record_restart(current_tick) -> RestartDecision` -- Records a restart and returns the decision.
- `RestartController::record_terminal(reason) -> RestartDecision` -- Marks the lifecycle as terminal.
- `RestartController::check_stall(last_heartbeat_tick, current_tick) -> bool` -- Checks stall timeout.
- `RestartController::terminal_reason() -> Option<TerminalReason>` -- Returns the terminal reason, if any.

### Constants

- `MAX_HEARTBEAT_DETAIL_LENGTH: usize = 512`
- `MAX_RUN_ID_LENGTH: usize = 256`
- `MAX_LIVENESS_DENIAL_DETAIL_LENGTH: usize = 512`
- `MAX_RESTARTS_LIMIT: u32 = 1000`
- `MAX_CIRCUIT_BREAKER_FAILURES: u32 = 100`

## Examples

### Checking Liveness for Progression

```rust
use apm2_core::liveness::{
    check_liveness_for_progression, HealthVerdict,
    LivenessHeartbeatReceiptV1,
};

let heartbeat = LivenessHeartbeatReceiptV1 {
    run_id: "run-001".to_string(),
    episode_id: [1; 32],
    emitted_at_tick: 100,
    time_envelope_ref: [2; 32],
    health_verdict: HealthVerdict::Healthy,
    restart_count: 0,
    max_restarts: 3,
    uptime_ms: 60_000,
    detail: None,
};

// Heartbeat is fresh (current_tick=105, max_age=10)
let result = check_liveness_for_progression(&heartbeat, 105, 10);
assert!(result.is_ok());
```

### Using the Restart Controller

```rust
use apm2_core::liveness::{
    RestartController, RestartDecision, RestartPolicyConfig, TerminalReason,
};

let config = RestartPolicyConfig {
    max_restarts: 3,
    window_ticks: 50,
    circuit_breaker_threshold_ticks: 5,
    circuit_breaker_max_failures: 3,
    stall_timeout_ticks: 10,
};

let mut controller = RestartController::new(config).expect("valid config");

// First restart is allowed
assert_eq!(
    controller.record_restart(100),
    RestartDecision::Allow { attempt: 1 },
);

// Clean exit terminates the controller
assert_eq!(
    controller.record_terminal(TerminalReason::CleanExit),
    RestartDecision::Deny { reason: TerminalReason::CleanExit },
);

// Further restarts are denied
assert_eq!(
    controller.record_restart(200),
    RestartDecision::Deny { reason: TerminalReason::CleanExit },
);
```

## Related Modules

- [`apm2_core::health`](../health/AGENTS.md) -- System-level health checks (distinct from per-agent liveness)
- [`apm2_core::restart`](../restart/AGENTS.md) -- Restart orchestration at the session level
- [`apm2_core::session`](../session/AGENTS.md) -- Session lifecycle that consumes liveness signals
- [`apm2_core::supervisor`](../supervisor/AGENTS.md) -- Supervisor that coordinates restart decisions

## References

- RFC-0020: Holonic Substrate Interface (HSI) -- defines launch liveness and restart semantics
- RFC-0016: Holonic Time Fabric (HTF) -- defines tick-based time model used by heartbeats
- [40 -- Time, Monotonicity, Determinism](/documents/skills/rust-standards/references/40_time_monotonicity_determinism.md)
