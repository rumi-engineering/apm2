# Health Module

> Health check infrastructure for monitoring managed process liveness and responsiveness.

## Overview

The `apm2_core::health` module provides configurable health checking mechanisms for processes managed by APM2. It supports multiple check types (HTTP, TCP, script-based, and simple liveness) with threshold-based status transitions.

This module integrates with the process management layer:
- `ProcessSpec` includes an optional `HealthCheckConfig` field
- `EcosystemConfig` propagates health settings to spawned processes
- The supervisor can use health status to inform restart decisions

## Key Types

### `HealthCheckConfig`

```rust
pub struct HealthCheckConfig {
    pub check_type: HealthCheckType,
    pub interval: Duration,           // default: 30s
    pub timeout: Duration,            // default: 5s
    pub unhealthy_threshold: u32,     // default: 3
    pub healthy_threshold: u32,       // default: 1
    pub initial_delay: Duration,      // default: 0s
}
```

**Invariants:**
- [INV-0001] `timeout` must be less than `interval` for meaningful check scheduling
- [INV-0002] Thresholds must be >= 1 (enforced by defaults, not types)

**Contracts:**
- [CTR-0001] Serializes with `humantime_serde` for human-readable duration strings (e.g., "30s", "5m")
- [CTR-0002] `check_type` uses `#[serde(flatten)]` - the type discriminator appears at the same level as other fields

### `HealthCheckType`

```rust
pub enum HealthCheckType {
    None,
    Http {
        url: String,
        expected_status: Vec<u16>,    // default: [200]
        expected_body: Option<String>,
    },
    Tcp {
        host: String,
        port: u16,
    },
    Script {
        path: PathBuf,
        args: Vec<String>,
    },
    Liveness,
}
```

**Invariants:**
- [INV-0003] `None` variant disables health checking entirely
- [INV-0004] `Http` with empty `expected_status` should accept any 2xx response (implementation-dependent)
- [INV-0005] `Script` execution must respect the parent `timeout` configuration

**Contracts:**
- [CTR-0003] Uses `#[serde(tag = "type", rename_all = "snake_case")]` for JSON representation

### `HealthCheckResult`

```rust
pub struct HealthCheckResult {
    pub healthy: bool,
    pub timestamp: DateTime<Utc>,
    pub duration: Duration,
    pub error: Option<String>,
    pub details: Option<String>,
}
```

**Invariants:**
- [INV-0006] If `healthy == false`, then `error` should be `Some(_)` explaining the failure
- [INV-0007] `duration` represents wall-clock time of the check execution

**Contracts:**
- [CTR-0004] Constructors `healthy()` and `unhealthy()` set `timestamp` to `Utc::now()`

### `HealthStatus`

```rust
pub enum HealthStatus {
    Unknown,    // Not yet checked or not configured
    Healthy,    // Passed healthy_threshold consecutive checks
    Unhealthy,  // Failed unhealthy_threshold consecutive checks
    Checking,   // Check in progress
}
```

**Invariants:**
- [INV-0008] Initial state is always `Unknown`
- [INV-0009] Transitions require threshold crossings, not single check results

### `HealthChecker`

```rust
pub struct HealthChecker {
    config: HealthCheckConfig,
    status: HealthStatus,
    history: Vec<HealthCheckResult>,  // max 100 entries
    consecutive_success: u32,
    consecutive_failure: u32,
    last_check: Option<DateTime<Utc>>,
}
```

**Invariants:**
- [INV-0010] `history` is bounded to 100 entries (FIFO eviction)
- [INV-0011] `consecutive_success` and `consecutive_failure` are mutually exclusive (one resets when the other increments)
- [INV-0012] Status transitions only occur when thresholds are met

**Contracts:**
- [CTR-0005] `record_result()` updates both counters and potentially transitions `status`
- [CTR-0006] `reset()` returns the checker to initial `Unknown` state

## Public API

### Construction

```rust
let config = HealthCheckConfig::default();  // None check type
let checker = HealthChecker::new(config);
```

### Recording Results

```rust
// Record a successful check
checker.record_result(HealthCheckResult::healthy(Duration::from_millis(50)));

// Record a failure
checker.record_result(
    HealthCheckResult::unhealthy(Duration::from_millis(100), "Connection refused")
);

// With additional details
checker.record_result(
    HealthCheckResult::healthy(Duration::from_millis(25))
        .with_details("HTTP 200, body matched")
);
```

### Querying State

```rust
let status: HealthStatus = checker.status();
let is_due: bool = checker.is_check_due();
let history: &[HealthCheckResult] = checker.history();
let config: &HealthCheckConfig = checker.config();
```

## Examples

### Configuration via YAML

```yaml
processes:
  - name: api-server
    command: ./server
    health:
      type: http
      url: "http://localhost:8080/health"
      expected_status: [200, 204]
      interval: 10s
      timeout: 2s
      unhealthy_threshold: 3
      healthy_threshold: 2
      initial_delay: 5s
```

### TCP Health Check

```yaml
health:
  type: tcp
  host: localhost
  port: 5432
  interval: 30s
  timeout: 5s
```

### Script-Based Check

```yaml
health:
  type: script
  path: /usr/local/bin/check-health.sh
  args: ["--verbose"]
  timeout: 10s
```

### Programmatic Usage

```rust
use apm2_core::health::{HealthCheckConfig, HealthCheckType, HealthChecker, HealthCheckResult};
use std::time::Duration;

// Configure an HTTP health check
let config = HealthCheckConfig {
    check_type: HealthCheckType::Http {
        url: "http://localhost:8080/health".to_string(),
        expected_status: vec![200],
        expected_body: Some("OK".to_string()),
    },
    interval: Duration::from_secs(10),
    timeout: Duration::from_secs(2),
    unhealthy_threshold: 3,
    healthy_threshold: 2,
    initial_delay: Duration::from_secs(5),
};

let mut checker = HealthChecker::new(config);

// Simulate check results
checker.record_result(HealthCheckResult::healthy(Duration::from_millis(50)));
checker.record_result(HealthCheckResult::healthy(Duration::from_millis(45)));

// After 2 successes (healthy_threshold), status transitions
assert_eq!(checker.status(), apm2_core::health::HealthStatus::Healthy);
```

## State Machine

```
                    +-------------+
                    |   Unknown   |
                    +------+------+
                           |
           +---------------+---------------+
           |                               |
           v                               v
    [success x N]                   [failure x M]
           |                               |
           v                               v
    +------+------+                 +------+------+
    |   Healthy   |<--------------->|  Unhealthy  |
    +-------------+  [thresholds]   +-------------+
```

Where:
- N = `healthy_threshold`
- M = `unhealthy_threshold`

## Related Modules

- [`apm2_core::process`](../process/) - `ProcessSpec` includes `health: Option<HealthCheckConfig>`
- [`apm2_core::config`](../config/) - `EcosystemConfig` propagates health settings
- [`apm2_core::supervisor`](../supervisor/) - May use health status for restart decisions
- [`apm2_core::restart`](../restart/) - Restart policies complement health checking

## Verification Checklist

- [VERIFICATION] Unit tests in `mod tests` cover status transitions
- [VERIFICATION] Threshold boundary conditions tested (exactly N successes/failures)
- [VERIFICATION] History bounded to 100 entries (memory safety)

## Hazards

- [HAZARD: RSK-0001] Script health checks execute arbitrary code - ensure `path` is validated
- [HAZARD: RSK-0002] HTTP checks may leak credentials if URL contains auth tokens
- [HAZARD: RSK-0003] `is_check_due()` uses `Utc::now()` which can be affected by clock adjustments
