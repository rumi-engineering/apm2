# Shutdown Module

> Graceful shutdown coordination with signal handling and timeout-based force kill.

## Overview

The `apm2_core::shutdown` module provides a state-machine-based approach to gracefully terminating processes. It coordinates the shutdown sequence: executing pre-shutdown commands, sending graceful signals (e.g., SIGTERM), waiting for the process to exit within a configurable timeout, and escalating to SIGKILL if necessary.

This module is a critical component of APM2's process lifecycle management. The `Supervisor` maintains a `ShutdownManager` for each process instance, enabling per-process shutdown coordination with configurable timeouts and signal handling.

## Key Types

### `ShutdownConfig`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShutdownConfig {
    /// Timeout for graceful shutdown before force kill.
    #[serde(default = "default_timeout")]
    #[serde(with = "humantime_serde")]
    pub timeout: Duration,

    /// Signal to send for graceful shutdown.
    #[serde(default = "default_signal")]
    pub signal: String,

    /// Delay before sending SIGKILL after timeout.
    #[serde(default = "default_kill_delay")]
    #[serde(with = "humantime_serde")]
    pub kill_delay: Duration,

    /// Whether to send SIGKILL if graceful shutdown times out.
    #[serde(default = "default_force_kill")]
    pub force_kill: bool,

    /// Commands to run before shutdown (cleanup scripts).
    #[serde(default)]
    pub pre_shutdown_commands: Vec<String>,
}
```

**Invariants:**
- [INV-0001] `timeout` defaults to 30 seconds; must be non-zero for meaningful graceful shutdown.
- [INV-0002] `signal` defaults to "SIGTERM"; must be a valid Unix signal name.
- [INV-0003] `kill_delay` defaults to 5 seconds; represents delay before SIGKILL after timeout.

**Contracts:**
- [CTR-0001] Duration fields serialize/deserialize via `humantime_serde` for human-readable config (e.g., "30s", "5m").
- [CTR-0002] Default configuration enables force kill with sensible timeouts for production use.

### `ShutdownState`

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownState {
    /// Not shutting down.
    Running,
    /// Pre-shutdown commands are running.
    PreShutdown,
    /// Graceful shutdown signal sent, waiting for process to exit.
    GracefulShutdown,
    /// Graceful shutdown timed out, force kill pending.
    ForceKillPending,
    /// Process has exited.
    Completed,
}
```

**Invariants:**
- [INV-0004] State transitions are unidirectional: `Running -> PreShutdown -> GracefulShutdown -> ForceKillPending -> Completed`.
- [INV-0005] `PreShutdown` is skipped if `pre_shutdown_commands` is empty.
- [INV-0006] `ForceKillPending` is only reachable if `force_kill` is enabled and timeout elapsed.

**Contracts:**
- [CTR-0003] `Display` implementation provides snake_case state names for logging/metrics.

### `ShutdownManager`

```rust
#[derive(Debug)]
pub struct ShutdownManager {
    /// Shutdown configuration.
    config: ShutdownConfig,

    /// Current shutdown state.
    state: ShutdownState,

    /// Time when shutdown was initiated.
    shutdown_started_at: Option<std::time::Instant>,

    /// Time when graceful shutdown signal was sent.
    graceful_signal_sent_at: Option<std::time::Instant>,
}
```

**Invariants:**
- [INV-0007] `shutdown_started_at` is `Some` only when `state != Running`.
- [INV-0008] `graceful_signal_sent_at` is `Some` only after transitioning to `GracefulShutdown`.

**Contracts:**
- [CTR-0004] `is_shutting_down()` returns `true` only for intermediate states (`PreShutdown`, `GracefulShutdown`, `ForceKillPending`).
- [CTR-0005] `has_timed_out()` returns `true` only in `GracefulShutdown` state when elapsed time exceeds `timeout`.

### `ShutdownError`

```rust
#[derive(Debug, thiserror::Error)]
pub enum ShutdownError {
    /// Invalid signal name.
    #[error("invalid signal name: {0}")]
    InvalidSignal(String),

    /// Failed to send signal.
    #[error("failed to send signal: {0}")]
    SignalFailed(String),

    /// Pre-shutdown command failed.
    #[error("pre-shutdown command failed: {0}")]
    PreShutdownFailed(String),

    /// Shutdown timed out.
    #[error("shutdown timed out after {0:?}")]
    Timeout(Duration),
}
```

**Contracts:**
- [CTR-0006] Error variants provide actionable context for diagnostics and recovery decisions.

## Public API

### Constructor and State Queries

```rust
impl ShutdownManager {
    /// Create a new shutdown manager with the given configuration.
    pub const fn new(config: ShutdownConfig) -> Self;

    /// Get the current shutdown state.
    pub const fn state(&self) -> ShutdownState;

    /// Check if shutdown is in progress (not Running or Completed).
    pub const fn is_shutting_down(&self) -> bool;

    /// Check if graceful shutdown has timed out.
    pub fn has_timed_out(&self) -> bool;

    /// Get elapsed time since shutdown was initiated.
    pub fn elapsed(&self) -> Option<Duration>;
}
```

### State Transitions

```rust
impl ShutdownManager {
    /// Initiate shutdown. Transitions to PreShutdown or GracefulShutdown.
    pub fn initiate(&mut self);

    /// Mark pre-shutdown commands as complete. Transitions to GracefulShutdown.
    pub fn pre_shutdown_complete(&mut self);

    /// Transition to ForceKillPending state (if force_kill enabled).
    pub fn initiate_force_kill(&mut self);

    /// Mark shutdown as complete.
    pub const fn complete(&mut self);

    /// Reset the manager to Running state.
    pub const fn reset(&mut self);
}
```

### Configuration Accessors

```rust
impl ShutdownManager {
    pub fn signal(&self) -> &str;
    pub fn pre_shutdown_commands(&self) -> &[String];
    pub const fn timeout(&self) -> Duration;
    pub const fn kill_delay(&self) -> Duration;
    pub const fn force_kill_enabled(&self) -> bool;
    pub const fn config(&self) -> &ShutdownConfig;
}
```

### Signal Parsing

```rust
/// Parse a signal name to the corresponding nix signal.
/// Accepts formats: "SIGTERM", "TERM", "sigterm", etc.
pub fn parse_signal(name: &str) -> Result<nix::sys::signal::Signal, ShutdownError>;
```

Supported signals: `TERM`, `INT`, `QUIT`, `KILL`, `HUP`, `USR1`, `USR2`.

## Examples

### Basic Shutdown Flow

```rust
use apm2_core::shutdown::{ShutdownConfig, ShutdownManager, ShutdownState};
use std::time::Duration;

// Create with default configuration (30s timeout, SIGTERM, force kill enabled)
let config = ShutdownConfig::default();
let mut manager = ShutdownManager::new(config);

assert_eq!(manager.state(), ShutdownState::Running);
assert!(!manager.is_shutting_down());

// Initiate shutdown (skips PreShutdown since no pre_shutdown_commands)
manager.initiate();
assert_eq!(manager.state(), ShutdownState::GracefulShutdown);
assert!(manager.is_shutting_down());

// Check timeout and escalate if needed
if manager.has_timed_out() {
    manager.initiate_force_kill();
    assert_eq!(manager.state(), ShutdownState::ForceKillPending);
}

// Mark complete when process exits
manager.complete();
assert_eq!(manager.state(), ShutdownState::Completed);
```

### With Pre-Shutdown Commands

```rust
use apm2_core::shutdown::{ShutdownConfig, ShutdownManager, ShutdownState};

let config = ShutdownConfig {
    pre_shutdown_commands: vec![
        "cleanup.sh".to_string(),
        "notify-shutdown".to_string(),
    ],
    ..Default::default()
};

let mut manager = ShutdownManager::new(config);
manager.initiate();

// Goes through PreShutdown first
assert_eq!(manager.state(), ShutdownState::PreShutdown);

// After running pre-shutdown commands:
manager.pre_shutdown_complete();
assert_eq!(manager.state(), ShutdownState::GracefulShutdown);
```

### Signal Parsing

```rust
use apm2_core::shutdown::parse_signal;
use nix::sys::signal::Signal;

assert_eq!(parse_signal("SIGTERM").unwrap(), Signal::SIGTERM);
assert_eq!(parse_signal("term").unwrap(), Signal::SIGTERM);
assert_eq!(parse_signal("HUP").unwrap(), Signal::SIGHUP);
assert!(parse_signal("INVALID").is_err());
```

### Integration with ProcessSpec

```rust
use apm2_core::process::ProcessSpec;
use apm2_core::shutdown::ShutdownConfig;
use std::time::Duration;

let spec = ProcessSpec::builder()
    .name("my-service")
    .command("/usr/bin/my-service")
    .shutdown(ShutdownConfig {
        timeout: Duration::from_secs(60),
        signal: "SIGINT".to_string(),
        force_kill: true,
        ..Default::default()
    })
    .build();
```

## Related Modules

- [`apm2_core::process`](../process/mod.rs) - Defines `ProcessSpec` which embeds `ShutdownConfig`, and `ProcessState::Stopping` which corresponds to active shutdown.
- [`apm2_core::supervisor`](../supervisor/mod.rs) - Maintains a `ShutdownManager` per process instance via `shutdown_managers` map; provides `get_shutdown_manager()` accessor.
- [`apm2_core::restart`](../restart/mod.rs) - Complementary lifecycle module; restart decisions occur after shutdown completes. The `RestartManager` coordinates with shutdown timing.

## State Machine Diagram

```
                    +-----------+
                    |  Running  |
                    +-----+-----+
                          |
                    initiate()
                          |
          +---------------+---------------+
          |                               |
   (has pre_shutdown_commands)    (no pre_shutdown_commands)
          |                               |
          v                               |
    +------------+                        |
    | PreShutdown|                        |
    +-----+------+                        |
          |                               |
   pre_shutdown_complete()                |
          |                               |
          +---------------+---------------+
                          |
                          v
                  +----------------+
                  |GracefulShutdown|<----+
                  +-------+--------+     |
                          |              |
             +------------+------------+ |
             |                         | |
      (process exits)         (timeout && force_kill)
             |                         |
             v                         v
        +---------+           +----------------+
        |Completed|<----------|ForceKillPending|
        +---------+  complete +----------------+
```

## Design Rationale

1. **State Machine Pattern**: Explicit states prevent invalid transitions and simplify reasoning about shutdown progress.

2. **Configurable Escalation**: The `force_kill` flag and `kill_delay` enable both aggressive and lenient shutdown policies depending on application requirements.

3. **Pre-Shutdown Hooks**: The `pre_shutdown_commands` field enables cleanup scripts (database connections, cache flushing, etc.) before signal delivery.

4. **Human-Readable Durations**: The `humantime_serde` integration allows configuration files to use natural duration syntax ("30s", "5m") instead of raw milliseconds.
