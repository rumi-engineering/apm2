# Process Module

> Manages agent process lifecycles including spawning, monitoring, and controlled shutdown.

## Overview

The `apm2_core::process` module provides the foundational process supervision infrastructure for APM2. It handles the complete lifecycle of agent processes (Claude Code, Gemini CLI, Codex CLI, or custom agents) from spawning through graceful termination.

This module implements the process layer of APM2's four-layer runtime topology: CLI -> Daemon -> **Process** -> Agent. The `Supervisor` (in `apm2_core::supervisor`) uses these types to manage collections of processes with restart policies and health monitoring.

Key responsibilities:
- Process specification and configuration via builder pattern
- Async process lifecycle management (start, stop, wait)
- State machine tracking (Starting, Running, Unhealthy, Stopping, Stopped, Crashed, Terminated)
- Signal handling (SIGTERM for graceful shutdown, SIGKILL for force termination)
- Instance management for multi-instance process specifications

## Key Types

### `ProcessId`

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProcessId(Uuid);

impl ProcessId {
    pub fn new() -> Self { Self(Uuid::new_v4()) }
}
```

**Invariants:**
- [INV-0001] Each `ProcessId` is globally unique (UUID v4)
- [INV-0002] `ProcessId` is `Copy` and cheap to pass by value

### `ProcessSpec`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessSpec {
    pub id: ProcessId,
    pub name: String,
    pub command: String,
    pub args: Vec<String>,
    pub cwd: Option<PathBuf>,
    pub env: HashMap<String, String>,
    pub instances: u32,
    pub restart: RestartConfig,
    pub health: Option<HealthCheckConfig>,
    pub log: LogConfig,
    pub shutdown: ShutdownConfig,
    pub credentials: Option<CredentialConfig>,
}
```

**Invariants:**
- [INV-0003] `name` is non-empty (enforced by builder)
- [INV-0004] `command` is non-empty (enforced by builder)
- [INV-0005] `instances >= 1` (builder defaults 0 to 1)

**Contracts:**
- [CTR-0001] Builder pattern requires `name()` and `command()` before `build()`
- [CTR-0002] `build()` panics if required fields are missing

### `ProcessSpecBuilder`

```rust
#[derive(Debug, Default)]
pub struct ProcessSpecBuilder {
    name: Option<String>,
    command: Option<String>,
    args: Vec<String>,
    cwd: Option<PathBuf>,
    env: HashMap<String, String>,
    instances: u32,
    restart: RestartConfig,
    health: Option<HealthCheckConfig>,
    log: LogConfig,
    shutdown: ShutdownConfig,
    credentials: Option<CredentialConfig>,
}
```

**Contracts:**
- [CTR-0003] All builder methods return `Self` for chaining
- [CTR-0004] All builder methods are marked `#[must_use]`

### `ProcessState`

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

**Invariants:**
- [INV-0006] State machine transitions are unidirectional (no cycles except via restart)
- [INV-0007] `Stopped`, `Crashed`, and `Terminated` are terminal states

**State Transitions:**
```
Starting -> Running -> Stopping -> Stopped
         |          |          `-> Terminated (SIGKILL)
         |          `-> Unhealthy -> Stopping
         `-> Crashed (spawn failure)
Running -> Crashed (non-zero exit)
```

### `ProcessHandle`

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

**Invariants:**
- [INV-0008] `pid.is_some()` iff `state.is_running()`
- [INV-0009] `started_at.is_some()` iff process has been started at least once
- [INV-0010] `instance < spec.instances`

### `ProcessRunner`

```rust
pub struct ProcessRunner {
    spec: ProcessSpec,
    instance: u32,
    child: Option<Child>,
    state: ProcessState,
    pid: Option<u32>,
}
```

**Invariants:**
- [INV-0011] `child.is_some()` iff process is actively running
- [INV-0012] State is always consistent with child process status

**Contracts:**
- [CTR-0005] `start()` fails if already running (`InvalidState` error)
- [CTR-0006] `stop()` fails if not running (`InvalidState` error)
- [CTR-0007] `stop()` sends SIGTERM, then SIGKILL after timeout

### `SpawnedProcess`

```rust
pub struct SpawnedProcess {
    pub child: Child,
    pub pid: u32,
}
```

**Contracts:**
- [CTR-0008] `spawn()` returns error if command not found or spawn fails
- [CTR-0009] `spawn()` configures stdin=null, stdout=piped, stderr=piped

### `ProcessError`

```rust
#[derive(Debug, thiserror::Error)]
pub enum ProcessError {
    #[error("failed to spawn process: {0}")]
    SpawnFailed(String),

    #[error("process not found: {0}")]
    NotFound(String),

    #[error("process already exists: {0}")]
    AlreadyExists(String),

    #[error("invalid state for operation: {0}")]
    InvalidState(String),

    #[error("failed to send signal: {0}")]
    SignalFailed(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
```

## Public API

### `ProcessSpec::builder() -> ProcessSpecBuilder`

Creates a new builder for constructing `ProcessSpec` instances.

### `ProcessSpecBuilder::name(impl Into<String>) -> Self`

Sets the process name (required).

### `ProcessSpecBuilder::command(impl Into<String>) -> Self`

Sets the command to execute (required).

### `ProcessSpecBuilder::args<I, S>(I) -> Self`

Sets command arguments where `I: IntoIterator<Item = S>` and `S: Into<String>`.

### `ProcessSpecBuilder::cwd(impl Into<PathBuf>) -> Self`

Sets the working directory for the process.

### `ProcessSpecBuilder::env(impl Into<String>, impl Into<String>) -> Self`

Adds an environment variable.

### `ProcessSpecBuilder::instances(u32) -> Self`

Sets the number of instances to run (default: 1).

### `ProcessSpecBuilder::build() -> ProcessSpec`

Builds the `ProcessSpec`. Panics if `name` or `command` not set.

### `ProcessState::is_running() -> bool`

Returns `true` for `Starting`, `Running`, or `Unhealthy` states.

### `ProcessState::has_exited() -> bool`

Returns `true` for `Stopped`, `Crashed`, or `Terminated` states.

### `ProcessHandle::new(ProcessSpec, u32) -> Self`

Creates a new handle in `Stopped` state.

### `ProcessHandle::display_name() -> String`

Returns `"name-instance"` for multi-instance specs, or just `"name"` for single instance.

### `ProcessHandle::uptime_secs() -> Option<i64>`

Returns uptime in seconds if running.

### `ProcessRunner::new(ProcessSpec, u32) -> Self`

Creates a new runner in `Stopped` state.

### `ProcessRunner::start() -> Result<(), ProcessError>`

Starts the process. Fails if already running.

### `ProcessRunner::stop(Duration) -> Result<(), ProcessError>` (async)

Stops the process gracefully with timeout. Sends SIGTERM, then SIGKILL after timeout.

### `ProcessRunner::wait() -> Option<ExitStatus>` (async)

Waits for process to exit. Returns `None` if no process running.

### `ProcessRunner::try_wait() -> Option<ExitStatus>`

Non-blocking check if process has exited.

### `spawn(ProcessSpec) -> Result<SpawnedProcess, ProcessError>`

Spawns a process according to specification.

## Examples

### Basic Process Lifecycle

```rust
use apm2_core::process::{ProcessSpec, ProcessRunner};
use std::time::Duration;

// Build a process specification
let spec = ProcessSpec::builder()
    .name("claude-code")
    .command("claude")
    .args(["--session", "project"])
    .env("ANTHROPIC_API_KEY", api_key)
    .cwd("/workspace")
    .build();

// Create and start the runner
let mut runner = ProcessRunner::new(spec, 0);
runner.start()?;

assert!(runner.state().is_running());
assert!(runner.pid().is_some());

// Stop gracefully with 5-second timeout
runner.stop(Duration::from_secs(5)).await?;

assert!(runner.state().has_exited());
```

### Multi-Instance Process

```rust
use apm2_core::process::ProcessSpec;

let spec = ProcessSpec::builder()
    .name("worker")
    .command("python")
    .args(["worker.py"])
    .instances(4)
    .build();

// Creates handles for worker-0, worker-1, worker-2, worker-3
for i in 0..spec.instances {
    let handle = ProcessHandle::new(spec.clone(), i);
    println!("Instance: {}", handle.display_name());
}
```

### Waiting for Process Exit

```rust
use apm2_core::process::{ProcessSpec, ProcessRunner, ProcessState};

let spec = ProcessSpec::builder()
    .name("task")
    .command("sh")
    .args(["-c", "echo hello && exit 0"])
    .build();

let mut runner = ProcessRunner::new(spec, 0);
runner.start()?;

// Wait for completion
let status = runner.wait().await;
assert!(status.is_some());
assert!(status.unwrap().success());
assert!(matches!(runner.state(), ProcessState::Stopped { exit_code: Some(0) }));
```

### Handling Crashed Processes

```rust
use apm2_core::process::{ProcessSpec, ProcessRunner, ProcessState};

let spec = ProcessSpec::builder()
    .name("failing-task")
    .command("sh")
    .args(["-c", "exit 1"])
    .build();

let mut runner = ProcessRunner::new(spec, 0);
runner.start()?;

let status = runner.wait().await;
assert!(!status.unwrap().success());
assert!(matches!(runner.state(), ProcessState::Crashed { exit_code: Some(1) }));
```

## Related Modules

- [`apm2_core::supervisor`](../supervisor/AGENTS.md) - Manages collections of processes with the `Supervisor` type
- [`apm2_core::restart`](../restart/AGENTS.md) - Restart policies and backoff strategies (`RestartConfig`, `BackoffConfig`, `RestartManager`)
- [`apm2_core::shutdown`](../shutdown/AGENTS.md) - Graceful shutdown coordination (`ShutdownConfig`, `ShutdownManager`)
- [`apm2_core::health`](../health/AGENTS.md) - Health check configuration (`HealthCheckConfig`)
- [`apm2_core::credentials`](../credentials/AGENTS.md) - Credential binding for processes (`CredentialConfig`)
- [`apm2_core::adapter`](../adapter/AGENTS.md) - Agent adapters that observe process behavior

## Submodules

### `runner`

Provides `ProcessRunner` for managing individual process instance lifecycles.

### `spawner`

Provides the `spawn()` function and `SpawnedProcess` type for low-level process creation.

## References

- [APM2 Rust Standards] [Paths, Filesystem, OS](/documents/skills/rust-standards/references/30_paths_filesystem_os.md) - Path handling for `cwd`
- [APM2 Rust Standards] [Async, Pin, Cancellation](/documents/skills/rust-standards/references/23_async_pin_cancellation.md) - Async process operations
- [tokio::process](https://docs.rs/tokio/latest/tokio/process/) - Underlying async process management
- [nix::sys::signal](https://docs.rs/nix/latest/nix/sys/signal/) - Unix signal handling
