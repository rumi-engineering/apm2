# Restart Module

> Process restart policy configuration with backoff strategies and circuit breaker protection.

## Overview

The `apm2_core::restart` module provides restart policy management for supervised processes. It implements three backoff strategies (fixed, exponential, linear), tracks restart history within a configurable time window, and incorporates circuit breaker behavior to prevent restart storms when processes enter failure loops.

This module integrates with the process supervision layer (`apm2_core::supervisor`) and session management (`apm2_core::session::restart_coordinator`) to make intelligent restart decisions based on exit codes, uptime metrics, and accumulated failure patterns.

## Key Types

### `RestartConfig`

```rust
pub struct RestartConfig {
    pub max_restarts: u32,           // default: 5
    pub restart_window: Duration,    // default: 60s
    pub min_uptime: Duration,        // default: 30s
    pub backoff: BackoffConfig,
    pub restart_on_success: bool,    // default: false
}
```

**Invariants:**
- [INV-0101] `max_restarts` bounds the number of restart attempts within `restart_window`
- [INV-0102] `min_uptime` defines the threshold for considering a run "successful" (resetting backoff)
- [INV-0103] `restart_on_success = false` prevents restarting processes that exit cleanly (code 0)

**Contracts:**
- [CTR-0101] Configuration is immutable after `RestartManager` creation
- [CTR-0102] All `Duration` fields serialize via `humantime_serde` for human-readable TOML/JSON

### `BackoffConfig`

```rust
pub enum BackoffConfig {
    Fixed {
        delay: Duration,
    },
    Exponential {
        initial_delay: Duration,
        max_delay: Duration,
        multiplier: f64,           // default: 2.0
    },
    Linear {
        initial_delay: Duration,
        increment: Duration,
        max_delay: Duration,
    },
}
```

**Invariants:**
- [INV-0201] `delay_for_attempt(n)` is monotonically non-decreasing for `n >= 1`
- [INV-0202] All strategies cap at `max_delay` to prevent unbounded waits
- [INV-0203] Default strategy is `Exponential { initial_delay: 1s, max_delay: 300s, multiplier: 2.0 }`

**Contracts:**
- [CTR-0201] `delay_for_attempt(attempt)` accepts 1-based attempt numbers
- [CTR-0202] Exponential delay formula: `initial_delay * multiplier^(attempt-1)`, capped at `max_delay`
- [CTR-0203] Linear delay formula: `initial_delay + increment * (attempt-1)`, capped at `max_delay`

### `RestartManager`

```rust
pub struct RestartManager {
    config: RestartConfig,
    history: Vec<RestartEntry>,
    backoff_attempt: u32,
    circuit_open: bool,
    circuit_opened_at: Option<DateTime<Utc>>,
}
```

**Invariants:**
- [INV-0301] `history` contains only entries within `config.restart_window` (auto-pruned)
- [INV-0302] `circuit_open = true` when `history.len() >= config.max_restarts`
- [INV-0303] `backoff_attempt` resets to 0 on `record_success()` call

**Contracts:**
- [CTR-0301] `should_restart(exit_code)` returns `false` if circuit is open
- [CTR-0302] `should_restart(Some(0))` returns `false` unless `restart_on_success = true`
- [CTR-0303] `record_restart()` increments `backoff_attempt`, adds to history, and may open circuit
- [CTR-0304] `record_success()` resets backoff counter and closes circuit breaker

### `RestartEntry`

```rust
pub struct RestartEntry {
    pub timestamp: DateTime<Utc>,
    pub exit_code: Option<i32>,
    pub uptime: Duration,
    pub delay: Duration,
}
```

**Invariants:**
- [INV-0401] `timestamp` records the moment of restart (not exit or delay completion)
- [INV-0402] `delay` is the backoff delay that was applied before this restart

## Public API

### Configuration

```rust
// Default configuration
let config = RestartConfig::default();

// Custom configuration
let config = RestartConfig {
    max_restarts: 3,
    restart_window: Duration::from_secs(120),
    min_uptime: Duration::from_secs(60),
    backoff: BackoffConfig::Exponential {
        initial_delay: Duration::from_millis(500),
        max_delay: Duration::from_secs(60),
        multiplier: 1.5,
    },
    restart_on_success: false,
};
```

### Manager Operations

```rust
// Create manager
let mut manager = RestartManager::new(config);

// Check if restart should proceed
if manager.should_restart(exit_code) {
    // Record restart and get delay
    let delay = manager.record_restart(exit_code, uptime);
    tokio::time::sleep(delay).await;
    // ... spawn process ...
}

// Process ran successfully (uptime > min_uptime)
manager.record_success();

// Query state
let count = manager.restart_count();
let is_open = manager.is_circuit_open();
let config = manager.config();

// Reset all state
manager.reset();
```

### Backoff Calculation

```rust
let config = BackoffConfig::Exponential {
    initial_delay: Duration::from_secs(1),
    max_delay: Duration::from_secs(60),
    multiplier: 2.0,
};

assert_eq!(config.delay_for_attempt(1), Duration::from_secs(1));
assert_eq!(config.delay_for_attempt(2), Duration::from_secs(2));
assert_eq!(config.delay_for_attempt(3), Duration::from_secs(4));
assert_eq!(config.delay_for_attempt(7), Duration::from_secs(60)); // capped
```

## Examples

### Basic Process Supervision

```rust
use std::time::Duration;
use apm2_core::restart::{RestartConfig, RestartManager, BackoffConfig};

let config = RestartConfig {
    max_restarts: 5,
    restart_window: Duration::from_secs(60),
    min_uptime: Duration::from_secs(30),
    backoff: BackoffConfig::Exponential {
        initial_delay: Duration::from_secs(1),
        max_delay: Duration::from_secs(300),
        multiplier: 2.0,
    },
    restart_on_success: false,
};

let mut manager = RestartManager::new(config);

loop {
    let start = std::time::Instant::now();
    let exit_code = run_process().await;
    let uptime = start.elapsed();

    // Check if process ran long enough to be considered stable
    if uptime >= manager.config().min_uptime {
        manager.record_success();
    }

    // Decide whether to restart
    if !manager.should_restart(exit_code) {
        if manager.is_circuit_open() {
            log::error!("Circuit breaker open - too many restarts");
        }
        break;
    }

    // Apply backoff delay before restarting
    let delay = manager.record_restart(exit_code, uptime);
    log::info!("Restarting in {:?}", delay);
    tokio::time::sleep(delay).await;
}
```

### Integration with ProcessSpec

```rust
use apm2_core::process::ProcessSpec;
use apm2_core::restart::{RestartConfig, BackoffConfig};

let spec = ProcessSpec::builder()
    .name("claude-code")
    .command("claude")
    .args(["--session", "project"])
    .restart(RestartConfig {
        max_restarts: 3,
        restart_window: Duration::from_secs(300),
        min_uptime: Duration::from_secs(60),
        backoff: BackoffConfig::Linear {
            initial_delay: Duration::from_secs(5),
            increment: Duration::from_secs(10),
            max_delay: Duration::from_secs(120),
        },
        restart_on_success: false,
    })
    .build();
```

### TOML Configuration

```toml
[restart]
max_restarts = 5
restart_window = "60s"
min_uptime = "30s"
restart_on_success = false

[restart.backoff]
type = "exponential"
initial_delay = "1s"
max_delay = "5m"
multiplier = 2.0
```

## Circuit Breaker Behavior

The circuit breaker prevents restart storms by tracking restart frequency:

1. **Closed State**: Normal operation, restarts allowed
2. **Open State**: After `max_restarts` within `restart_window`, restarts blocked
3. **Reset**: Circuit closes on `record_success()` or `reset()`

```
Process Exit
     |
     v
+--------------------+
| should_restart()   |
+--------------------+
     |
     +-- circuit_open? --> NO (blocked)
     |
     +-- exit_code == 0 && !restart_on_success? --> NO
     |
     +-- restarts_in_window >= max_restarts? --> NO (opens circuit)
     |
     v
    YES (restart allowed)
```

## Related Modules

- [`apm2_core::process`](../process/AGENTS.md) - Uses `RestartConfig` in `ProcessSpec` for process lifecycle management
- [`apm2_core::supervisor`](../supervisor/AGENTS.md) - Maintains `RestartManager` instances per process instance
- [`apm2_core::session::restart_coordinator`](../session/AGENTS.md) - Wraps `RestartManager` with entropy tracking and quarantine integration
- [`apm2_core::shutdown`](../shutdown/AGENTS.md) - Coordinates graceful shutdown alongside restart policies
