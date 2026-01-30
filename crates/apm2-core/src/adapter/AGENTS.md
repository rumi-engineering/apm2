# Adapter Module

> Normalizes heterogeneous agent runtimes into a common event contract for unified supervision.

## Overview

The adapter module sits between the APM2 supervisor and agent processes, providing a uniform interface for observing and controlling agents regardless of their implementation. It follows the **Markov Blanket** principle from Principia Holonica: each adapter defines an explicit boundary through which all agent observations flow.

```text
+---------------+
|  Supervisor   |
+-------+-------+
        | AdapterEvent
        v
+---------------+
|    Adapter    | <-- Common interface (Adapter trait)
+-------+-------+
        | spawn/observe
        v
+---------------+
| Agent Process | <-- Claude Code, Gemini CLI, custom agents, etc.
+---------------+
```

The module supports two adapter paradigms:
- **Black-box adapters**: Derive events from side effects without agent cooperation (implemented)
- **Instrumented adapters**: Receive events directly from agents implementing the APM2 event protocol (future)

## Key Types

### `AdapterEvent`

```rust
pub struct AdapterEvent {
    /// Monotonically increasing sequence number for ordering.
    pub sequence: u64,
    /// Timestamp when the event was detected (nanoseconds since Unix epoch).
    pub timestamp_nanos: u64,
    /// The session ID this event belongs to.
    pub session_id: String,
    /// The specific event payload.
    pub payload: AdapterEventPayload,
}
```

**Invariants:**
- [INV-0101] `sequence` is strictly monotonically increasing within a single adapter instance
- [INV-0102] First event is always `ProcessStarted`; last event is always `ProcessExited` (unless adapter crashes)
- [INV-0103] `session_id` is immutable for the lifetime of the adapter

**Contracts:**
- [CTR-0101] All adapters emit normalized `AdapterEvent` instances regardless of adapter type
- [CTR-0102] Events are ordered by `sequence` within a session; cross-session ordering uses `timestamp_nanos`

### `AdapterEventPayload`

```rust
#[non_exhaustive]
pub enum AdapterEventPayload {
    /// Agent process has started.
    ProcessStarted(ProcessStarted),
    /// Agent process has exited.
    ProcessExited(ProcessExited),
    /// Progress signal derived from activity.
    Progress(ProgressSignal),
    /// Filesystem change detected.
    FilesystemChange(FilesystemChange),
    /// Tool request detected (from side effects or instrumentation).
    ToolRequestDetected(ToolRequestDetected),
    /// Stall detected (no activity for configured duration).
    StallDetected(StallDetected),
}
```

**Invariants:**
- [INV-0201] `#[non_exhaustive]` ensures forward compatibility; new variants may be added

### `BlackBoxAdapter`

```rust
pub struct BlackBoxAdapter {
    config: BlackBoxConfig,
    state: AdapterState,
    sequence: AtomicU64,
    event_tx: Option<mpsc::Sender<AdapterEvent>>,
    event_rx: Option<mpsc::Receiver<AdapterEvent>>,
}

enum AdapterState {
    Idle,
    Running {
        child: Child,
        pid: u32,
        started_at: Instant,
        watcher: FilesystemWatcher,
        last_activity: Instant,
        stall_count: u32,
        shutdown: Arc<AtomicBool>,
    },
    Stopped {
        exit_code: Option<i32>,
        signal: Option<i32>,
    },
}
```

**Invariants:**
- [INV-0301] State machine: `Idle -> Running -> Stopped` (no cycles)
- [INV-0302] `event_rx` can only be taken once; subsequent `take_event_receiver()` returns `None`
- [INV-0303] Process spawned with `kill_on_drop(true)` ensures cleanup on adapter drop

**Contracts:**
- [CTR-0301] `start()` fails with `AlreadyRunning` if called while in `Running` state
- [CTR-0302] `poll()` fails with `NotRunning` if called while in `Idle` state
- [CTR-0303] Environment variables in `exclude` list are never passed to child process

### `ExitClassification`

```rust
pub enum ExitClassification {
    CleanSuccess,      // exit code 0
    CleanError,        // non-zero exit code
    Signal,            // terminated by signal
    Timeout,           // process timed out
    EntropyExceeded,   // entropy budget exceeded
    Unknown,           // unexpected termination
}
```

**Contracts:**
- [CTR-0401] Classification is deterministic given `(exit_code, signal)` tuple

### `DetectionMethod`

```rust
pub enum DetectionMethod {
    FilesystemObservation,  // Detected from filesystem changes
    ProcessObservation,     // Detected from process tree changes
    NetworkObservation,     // Detected from network activity
    OutputParsing,          // Detected from stdout/stderr parsing
    Instrumentation,        // Detected from instrumentation (future)
}
```

### `AdapterError`

```rust
#[non_exhaustive]
pub enum AdapterError {
    SpawnFailed(String),
    UnexpectedExit { exit_code: Option<i32>, signal: Option<i32> },
    WatcherError(String),
    WatchPathFailed { path: PathBuf, reason: String },
    ConfigError(String),
    SessionNotFound(String),
    SessionExists(String),
    NotRunning,
    AlreadyRunning,
    Io(std::io::Error),
    ChannelSend(String),
    ChannelRecv(String),
    Internal(String),
}
```

**Contracts:**
- [CTR-0501] `is_transient()` returns `true` for errors that may succeed on retry
- [CTR-0502] `is_fatal()` returns `true` for errors requiring restart

## Configuration Types

### `BlackBoxConfig`

```rust
pub struct BlackBoxConfig {
    pub session_id: String,
    pub process: ProcessConfig,
    pub filesystem: FilesystemConfig,
    pub stall_detection: StallDetectionConfig,
    pub progress: ProgressConfig,
    pub environment: EnvironmentConfig,
}
```

Builder pattern usage:
```rust
BlackBoxConfig::new("session-123", "claude")
    .with_working_dir("/workspace")
    .with_args(["--session", "project"])
    .with_watch_path("/workspace")
    .with_stall_timeout(Duration::from_secs(120))
```

### `EnvironmentConfig`

```rust
pub struct EnvironmentConfig {
    pub variables: Vec<(String, String)>,
    pub inherit: bool,     // Default: false (default-deny)
    pub exclude: Vec<String>,
}
```

**Invariants:**
- [INV-0601] Default `inherit = false` enforces default-deny security model
- [INV-0602] Default `exclude` list contains sensitive keys: `AWS_SECRET_ACCESS_KEY`, `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GITHUB_TOKEN`, `NPM_TOKEN`, `DOCKER_PASSWORD`, `SSH_PRIVATE_KEY`

### `FilesystemConfig`

```rust
pub struct FilesystemConfig {
    pub watch_paths: Vec<PathBuf>,
    pub recursive: bool,           // Default: true
    pub ignore_patterns: Vec<String>,
    pub debounce: Duration,        // Default: 100ms
    pub buffer_size: usize,        // Default: 1024
}
```

Default ignore patterns: `*.swp`, `*~`, `.git/**`, `node_modules/**`, `target/**`, `__pycache__/**`

### `StallDetectionConfig`

```rust
pub struct StallDetectionConfig {
    pub timeout: Duration,    // Default: 60s
    pub enabled: bool,        // Default: true
    pub max_stalls: u32,      // Default: 5
}
```

## Public API

### `Adapter` Trait

```rust
pub trait Adapter: Send {
    fn start(&mut self) -> BoxFuture<'_, Result<(), AdapterError>>;
    fn poll(&mut self) -> BoxFuture<'_, Result<Option<AdapterEvent>, AdapterError>>;
    fn stop(&mut self) -> BoxFuture<'_, Result<(), AdapterError>>;
    fn take_event_receiver(&mut self) -> Option<mpsc::Receiver<AdapterEvent>>;
    fn session_id(&self) -> &str;
    fn is_running(&self) -> bool;
    fn pid(&self) -> Option<u32>;
    fn adapter_type(&self) -> &'static str;
}
```

### `BlackBoxAdapter::new(config) -> Self`

Creates a new black-box adapter with the given configuration. Initializes event channels but does not spawn the process.

### `BlackBoxAdapter::start(&mut self) -> Result<(), AdapterError>`

Spawns the agent process and begins monitoring. Emits `ProcessStarted` event on success.

**Errors:**
- `AlreadyRunning`: Adapter is already in `Running` state
- `SpawnFailed`: Process failed to spawn
- `WatchPathFailed`: Filesystem watcher initialization failed

### `BlackBoxAdapter::poll(&mut self) -> Result<Option<AdapterEvent>, AdapterError>`

Non-blocking poll that checks for:
1. Process exit status
2. Filesystem changes (emits `FilesystemChange` and infers `ToolRequestDetected`)
3. Stall detection (emits `StallDetected` if idle duration exceeds threshold)

Returns `Ok(None)` if no event is available.

### `BlackBoxAdapter::run(&mut self) -> Result<(), AdapterError>`

Convenience method that runs the poll loop until process exits or shutdown is requested.

### `BlackBoxAdapter::stop(&mut self) -> Result<(), AdapterError>`

Terminates the agent process and performs cleanup.

### `BlackBoxAdapter::take_event_receiver(&mut self) -> Option<mpsc::Receiver<AdapterEvent>>`

Returns the event receiver for async consumption. Can only be called once.

## Security Model

The adapter module follows **default-deny, least-privilege, fail-closed** principles:

1. **Environment Isolation**: Default `inherit = false` prevents environment leakage
2. **Credential Filtering**: Sensitive keys in `exclude` list are never passed to child processes
3. **Symlink Protection**: Filesystem watcher uses `symlink_metadata()` and skips symlinks to prevent loops and symlink-based attacks
4. **Untrusted Observations**: All observations from black-box monitoring are treated as untrusted
5. **Fail-Closed**: Errors result in session termination rather than degraded operation

## Examples

### Basic Usage

```rust
use apm2_core::adapter::{BlackBoxAdapter, BlackBoxConfig, AdapterEventPayload};
use std::time::Duration;

// Configure the adapter
let config = BlackBoxConfig::new("session-123", "claude")
    .with_working_dir("/workspace")
    .with_watch_path("/workspace")
    .with_stall_timeout(Duration::from_secs(120));

// Create and start
let mut adapter = BlackBoxAdapter::new(config);
adapter.start().await?;

// Poll for events
while adapter.is_running() {
    if let Some(event) = adapter.poll().await? {
        match event.payload {
            AdapterEventPayload::ProcessStarted(e) => {
                println!("Started: PID {}", e.pid);
            }
            AdapterEventPayload::Progress(e) => {
                println!("Progress: {:?}", e.signal_type);
            }
            AdapterEventPayload::FilesystemChange(e) => {
                println!("File changed: {:?}", e.path);
            }
            AdapterEventPayload::ToolRequestDetected(e) => {
                println!("Tool detected: {} (confidence: {}%)",
                    e.tool_name, e.confidence_percent);
            }
            AdapterEventPayload::StallDetected(e) => {
                println!("Stall #{}: idle for {:?}", e.stall_count, e.idle_duration);
            }
            AdapterEventPayload::ProcessExited(e) => {
                println!("Exited: {:?}", e.classification);
                break;
            }
        }
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
}
```

### Using Event Receiver

```rust
let mut adapter = BlackBoxAdapter::new(config);

// Take the receiver before starting
let mut rx = adapter.take_event_receiver().unwrap();

adapter.start().await?;

// Spawn polling task
tokio::spawn(async move {
    while let Ok(_) = adapter.poll().await {
        if !adapter.is_running() { break; }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
});

// Receive events asynchronously
while let Some(event) = rx.recv().await {
    println!("Event: {:?}", event);
    if matches!(event.payload, AdapterEventPayload::ProcessExited(_)) {
        break;
    }
}
```

## Related Modules

- [`apm2_core::supervisor`](../supervisor/AGENTS.md) - Uses adapters to supervise agent processes
- [`apm2_core::session`](../session/AGENTS.md) - Session lifecycle management; receives adapter events
- [`apm2_holon`](../../apm2-holon/AGENTS.md) - Defines the `Holon` trait that agents implement

## References

- rust-standards [Chapter 11: Async, Pin, and Cancellation](/documents/skills/rust-standards/references/23_async_pin_cancellation.md) - Async patterns used in adapter implementation
- rust-standards [Chapter 12: API Design](/documents/skills/rust-standards/references/18_api_design_and_semver.md) - Builder pattern and trait design
- rust-standards [Chapter 19: Security-Adjacent Rust](/documents/skills/rust-standards/references/34_security_adjacent_rust.md) - Environment filtering and symlink protection
