# Supervisor Module

> Manages process collection lifecycles with restart policies and graceful shutdown coordination.

## Overview

The supervisor module (`apm2_core::supervisor`) provides centralized management for a collection of agent processes within the APM2 runtime. It coordinates process registration, state tracking, restart decisions, and shutdown sequencing. The supervisor does not directly spawn or kill processes; instead, it maintains the data structures and policies that inform the process runner about lifecycle decisions.

This module implements Axiom III (Bounded Authority) from the Principia Holonica by ensuring processes operate within constrained restart budgets and graceful shutdown timeouts.

**Architectural Position:**
- Sits between the daemon runtime and individual process runners
- Aggregates per-process state into a unified view
- Delegates restart decisions to `RestartManager` instances
- Delegates shutdown orchestration to `ShutdownManager` instances

## Key Types

### `Supervisor`

```rust
#[derive(Debug)]
pub struct Supervisor {
    /// Process specifications by ID.
    specs: HashMap<ProcessId, ProcessSpec>,

    /// Process handles by (`spec_id`, `instance_index`).
    handles: HashMap<(ProcessId, u32), ProcessHandle>,

    /// Restart managers by (`spec_id`, `instance_index`).
    restart_managers: HashMap<(ProcessId, u32), RestartManager>,

    /// Shutdown managers by (`spec_id`, `instance_index`).
    shutdown_managers: HashMap<(ProcessId, u32), ShutdownManager>,
}
```

**Invariants:**

- [INV-0001] Process names are unique across all registered specifications
- [INV-0002] For each registered spec with `n` instances, exactly `n` handles exist at keys `(spec_id, 0)` through `(spec_id, n-1)`
- [INV-0003] Each handle has a corresponding `RestartManager` and `ShutdownManager` at the same key
- [INV-0004] Running processes cannot be unregistered (must stop first)

**Contracts:**

- [CTR-0001] `register()` rejects duplicate process names with `SupervisorError::DuplicateName`
- [CTR-0002] `unregister()` rejects removal of running processes with `SupervisorError::StillRunning`
- [CTR-0003] State updates via `update_state()` are idempotent if handle exists

### `SupervisorError`

```rust
#[derive(Debug, thiserror::Error)]
pub enum SupervisorError {
    /// Process with name already exists.
    #[error("process with name '{0}' already exists")]
    DuplicateName(String),

    /// Process not found.
    #[error("process '{0}' not found")]
    NotFound(String),

    /// Process is still running.
    #[error("process '{0}' is still running")]
    StillRunning(String),

    /// Invalid instance index.
    #[error("invalid instance index {0}")]
    InvalidInstance(u32),
}
```

### `ProcessHandle` (from `apm2_core::process`)

```rust
#[derive(Debug)]
pub struct ProcessHandle {
    pub spec: ProcessSpec,
    pub instance: u32,
    pub state: ProcessState,
    pub pid: Option<u32>,
    pub started_at: Option<DateTime<Utc>>,
    pub restart_count: u32,
    pub last_restart: Option<DateTime<Utc>>,
    pub cpu_percent: Option<f32>,
    pub memory_bytes: Option<u64>,
}
```

### `ProcessState` (from `apm2_core::process`)

```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProcessState {
    Starting,
    Running,
    Unhealthy,
    Stopping,
    Stopped { exit_code: Option<i32> },
    Crashed { exit_code: Option<i32> },
    Terminated,
}
```

**State Predicates:**
- `is_running()` returns `true` for `Starting`, `Running`, `Unhealthy`
- `has_exited()` returns `true` for `Stopped`, `Crashed`, `Terminated`

## Public API

### `Supervisor::new() -> Self`

Create a new empty supervisor.

### `register(&mut self, spec: ProcessSpec) -> Result<(), SupervisorError>`

Register a process specification. Creates handles and managers for each instance (0 to `spec.instances - 1`).

**Errors:** `SupervisorError::DuplicateName` if a process with the same name exists.

### `unregister(&mut self, name: &str) -> Result<(), SupervisorError>`

Remove a process specification and all associated handles/managers.

**Errors:**
- `SupervisorError::NotFound` if no process with that name exists
- `SupervisorError::StillRunning` if any instance is still running

### `get_spec(&self, name: &str) -> Option<&ProcessSpec>`

Retrieve a process specification by name.

### `get_handle(&self, name: &str, instance: u32) -> Option<&ProcessHandle>`

Retrieve a process handle by name and instance index.

### `get_handle_mut(&mut self, name: &str, instance: u32) -> Option<&mut ProcessHandle>`

Retrieve a mutable process handle for state updates.

### `get_handles(&self, name: &str) -> Vec<&ProcessHandle>`

Retrieve all handles for a given process name (all instances).

### `get_restart_manager(&mut self, name: &str, instance: u32) -> Option<&mut RestartManager>`

Get the restart manager for a specific process instance to query/update restart state.

### `get_shutdown_manager(&mut self, name: &str, instance: u32) -> Option<&mut ShutdownManager>`

Get the shutdown manager for a specific process instance to initiate/track shutdown.

### `list_names(&self) -> Vec<&str>`

List all registered process names.

### `process_count(&self) -> usize`

Get the number of registered process specifications.

### `running_count(&self) -> usize`

Count instances currently in a running state (`Starting`, `Running`, or `Unhealthy`).

### `specs(&self) -> impl Iterator<Item = &ProcessSpec>`

Iterate over all process specifications.

### `update_state(&mut self, name: &str, instance: u32, state: ProcessState)`

Update the state of a process instance. No-op if handle not found.

### `update_pid(&mut self, name: &str, instance: u32, pid: Option<u32>)`

Update the PID of a process instance. Also sets `started_at` timestamp when PID is set.

### `increment_restart(&mut self, name: &str, instance: u32)`

Increment the restart counter and update `last_restart` timestamp for an instance.

## Examples

### Basic Registration and State Tracking

```rust
use apm2_core::supervisor::Supervisor;
use apm2_core::process::{ProcessSpec, ProcessState};

let mut supervisor = Supervisor::new();

// Register a process with 2 instances
let spec = ProcessSpec::builder()
    .name("claude-code")
    .command("claude")
    .args(["--session", "project"])
    .instances(2)
    .build();

supervisor.register(spec)?;

// Check registration
assert_eq!(supervisor.process_count(), 1);
assert!(supervisor.get_handle("claude-code", 0).is_some());
assert!(supervisor.get_handle("claude-code", 1).is_some());

// Update state when process starts
supervisor.update_state("claude-code", 0, ProcessState::Running);
supervisor.update_pid("claude-code", 0, Some(12345));

assert_eq!(supervisor.running_count(), 1);
```

### Restart Decision Flow

```rust
use apm2_core::supervisor::Supervisor;
use apm2_core::process::{ProcessSpec, ProcessState};
use std::time::Duration;

let mut supervisor = Supervisor::new();

let spec = ProcessSpec::builder()
    .name("agent")
    .command("agent-binary")
    .build();

supervisor.register(spec)?;

// Process crashes
supervisor.update_state("agent", 0, ProcessState::Crashed { exit_code: Some(1) });

// Check restart policy
if let Some(restart_mgr) = supervisor.get_restart_manager("agent", 0) {
    if restart_mgr.should_restart(Some(1)) {
        let delay = restart_mgr.record_restart(Some(1), Duration::from_secs(45));
        // Wait `delay`, then restart
        supervisor.increment_restart("agent", 0);
        supervisor.update_state("agent", 0, ProcessState::Starting);
    } else {
        // Circuit breaker is open, do not restart
    }
}
```

### Graceful Shutdown Sequence

```rust
use apm2_core::supervisor::Supervisor;
use apm2_core::process::{ProcessSpec, ProcessState};
use apm2_core::shutdown::ShutdownState;

let mut supervisor = Supervisor::new();

let spec = ProcessSpec::builder()
    .name("worker")
    .command("worker-binary")
    .build();

supervisor.register(spec)?;
supervisor.update_state("worker", 0, ProcessState::Running);

// Initiate shutdown
if let Some(shutdown_mgr) = supervisor.get_shutdown_manager("worker", 0) {
    shutdown_mgr.initiate();
    // Send signal based on shutdown_mgr.signal()

    // Later, check timeout
    if shutdown_mgr.has_timed_out() {
        shutdown_mgr.initiate_force_kill();
        // Send SIGKILL
    }

    // When process exits
    shutdown_mgr.complete();
}

supervisor.update_state("worker", 0, ProcessState::Stopped { exit_code: Some(0) });

// Now safe to unregister
supervisor.unregister("worker")?;
```

## Delegation Patterns

The supervisor delegates specialized concerns to dedicated managers:

### RestartManager

Handles restart decisions with:
- Configurable restart limits within a time window
- Backoff strategies (fixed, exponential, linear)
- Circuit breaker pattern to prevent restart storms
- Minimum uptime tracking for successful runs

### ShutdownManager

Handles shutdown orchestration with:
- Pre-shutdown command execution
- Graceful signal delivery (configurable signal type)
- Timeout-based escalation to force kill
- State machine: `Running -> PreShutdown -> GracefulShutdown -> ForceKillPending -> Completed`

## Related Modules

- [`apm2_core::process`](../process/mod.rs) - `ProcessSpec`, `ProcessHandle`, `ProcessState` definitions
- [`apm2_core::restart`](../restart/mod.rs) - `RestartConfig`, `RestartManager`, `BackoffConfig`
- [`apm2_core::shutdown`](../shutdown/mod.rs) - `ShutdownConfig`, `ShutdownManager`, `ShutdownState`
- [`apm2_core::process::runner`](../process/runner.rs) - Async process runner that consumes supervisor state
- [`apm2_core::process::spawner`](../process/spawner.rs) - Process spawning utilities

## References

- Rust Textbook Chapter 07: Errors, Panics, Diagnostics - Error type design with `thiserror`
- Rust Textbook Chapter 12: API Design, stdlib Quality - Builder pattern for `ProcessSpec`
- Rust Textbook Chapter 13: Collections, Allocation Models - `HashMap` keying patterns
