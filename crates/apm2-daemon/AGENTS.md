# apm2-daemon

> Unix socket daemon for managing AI CLI processes through IPC handlers and shared state.

## Overview

The `apm2-daemon` crate implements the persistent daemon process in APM2's four-layer runtime architecture. It provides:

- Unix domain socket server for CLI-to-daemon communication
- Thread-safe shared state with `RwLock` protection
- Request dispatch to typed handlers
- Process lifecycle management via the supervisor
- Signal handling (SIGTERM, SIGINT) for graceful shutdown
- Double-fork daemonization for background operation

```
┌─────────────────┐
│   apm2-cli      │  CLI client
└────────┬────────┘
         │ Unix socket (JSON framed)
┌────────▼────────┐
│  apm2-daemon    │  ◄── This crate
│  ┌───────────┐  │
│  │IPC Server │──┼──► Handlers ──► SharedState
│  └───────────┘  │                    │
└─────────────────┘                    ▼
                                  Supervisor
                                       │
                              ┌────────┼────────┐
                              ▼        ▼        ▼
                           Agent    Agent    Agent
```

## Key Types

### `DaemonStateHandle`

```rust
pub struct DaemonStateHandle {
    inner: RwLock<DaemonState>,
    shutdown: AtomicBool,
    started_at: DateTime<Utc>,
}
```

Thread-safe wrapper for daemon state with interior mutability.

**Invariants:**
- [INV-D001] `shutdown` flag is monotonic: once set to `true`, it never reverts to `false`.
- [INV-D002] `started_at` is immutable after construction.
- [INV-D003] All access to `inner` state requires acquiring the `RwLock`.

**Contracts:**
- [CTR-D001] `is_shutdown_requested()` is lock-free (uses `AtomicBool`).
- [CTR-D002] `read()` and `write()` methods are async and may block waiting for lock.

### `DaemonState`

```rust
pub struct DaemonState {
    pub supervisor: Supervisor,
    pub runners: HashMap<RunnerKey, ProcessRunner>,
    pub config: EcosystemConfig,
}
```

Inner mutable state protected by `DaemonStateHandle`.

**Invariants:**
- [INV-D004] `runners` map only contains entries for processes defined in `supervisor`.
- [INV-D005] Each `RunnerKey` (`ProcessId`, instance index) is unique.

**Contracts:**
- [CTR-D003] `get_runner()` returns `Some` only if the process exists in supervisor and has an active runner.
- [CTR-D004] `insert_runner()` overwrites any existing runner for the same key.

### `SharedState`

```rust
pub type SharedState = Arc<DaemonStateHandle>;
```

Type alias for the shared daemon state reference. Passed to all handlers and tasks.

### `RunnerKey`

```rust
pub type RunnerKey = (ProcessId, u32);
```

Composite key for process runners: (`ProcessId`, instance index).

**Invariants:**
- [INV-D006] Instance index is always `< spec.instances` for the corresponding process.

## IPC Server (ProtocolServer-only, DD-009)

### `ProtocolServer::bind` + `accept`

```rust
pub fn bind(config: ServerConfig) -> ProtocolResult<ProtocolServer>
pub async fn accept(&self) -> ProtocolResult<(Connection, ConnectionPermit)>
```

Control-plane IPC uses the ProtocolServer stack only (DD-009). Legacy JSON IPC
(`apm2_core::ipc` + `ipc_server.rs`) is forbidden and must not be used for any
control-plane path.

**Contracts (ProtocolServer):**
- [CTR-D005] Removes stale socket file before binding.
- [CTR-D006] Creates parent directory with restrictive permissions.
- [CTR-D007] Cleans up socket file on shutdown.
- [CTR-D008] Each connection is handled in a separate spawned task.
- [CTR-D009] Handshake completes before any control-plane message exchange.

### Wire Protocol

Uses length-prefixed binary framing with Hello/HelloAck handshake. JSON framing
is explicitly forbidden by DD-009.

**Invariants:**
- [INV-D007] Maximum frame size enforced before allocation.
- [INV-D008] Connection closes on any framing or parse error.
- [INV-D009] Legacy JSON IPC listeners/adapters are prohibited in default builds.

## Daemonization

When started without `--no-daemon`, the daemon performs double-fork:

1. First fork: parent exits, child continues
2. `setsid()`: create new session, become session leader
3. Second fork: parent exits, child continues (no longer session leader)
4. Change working directory to `/`
5. Write PID file

**Contracts:**
- [CTR-D014] PID file is written after successful daemonization.
- [CTR-D015] PID file is removed on graceful shutdown.
- [CTR-D016] Daemonization is skipped on non-Unix platforms.

## Signal Handling

The daemon handles Unix signals for graceful shutdown:

- **SIGTERM**: Initiate graceful shutdown
- **SIGINT**: Initiate graceful shutdown

**Contracts:**
- [CTR-D017] Signal handler sets `shutdown` flag via `request_shutdown()`.
- [CTR-D018] Graceful shutdown stops all running processes with 10-second timeout.
- [CTR-D019] Socket file and PID file are cleaned up on shutdown.

## Public API

### State Access

```rust
impl DaemonStateHandle {
    pub fn new(config: EcosystemConfig, supervisor: Supervisor) -> Self;
    pub async fn read(&self) -> RwLockReadGuard<'_, DaemonState>;
    pub async fn write(&self) -> RwLockWriteGuard<'_, DaemonState>;
    pub fn is_shutdown_requested(&self) -> bool;
    pub fn request_shutdown(&self);
    pub fn uptime_secs(&self) -> u64;
}
```

### Runner Management

```rust
impl DaemonState {
    pub fn get_runner(&self, name: &str, instance: u32) -> Option<&ProcessRunner>;
    pub fn get_runner_mut(&mut self, name: &str, instance: u32) -> Option<&mut ProcessRunner>;
    pub fn insert_runner(&mut self, spec_id: ProcessId, instance: u32, runner: ProcessRunner);
    pub fn remove_runner(&mut self, spec_id: ProcessId, instance: u32) -> Option<ProcessRunner>;
    pub fn get_runners(&self, name: &str) -> Vec<&ProcessRunner>;
}
```

## Examples

### Starting the Daemon

```bash
# Start in background (daemonizes)
apm2-daemon --config ecosystem.toml

# Start in foreground
apm2-daemon --config ecosystem.toml --no-daemon
```

Socket paths are configured via `[daemon].operator_socket` and
`[daemon].session_socket` in `ecosystem.toml`. Single-socket CLI flags/keys are
forbidden by DD-009.

## Related Modules

- [`apm2_core::process`](../apm2-core/src/process/AGENTS.md) - `ProcessSpec`, `ProcessState`, `ProcessRunner`
- [`apm2_core::supervisor`](../apm2-core/src/supervisor/AGENTS.md) - Process collection management
- [`apm2_core::config`](../apm2-core/src/config/AGENTS.md) - `EcosystemConfig` for daemon configuration
- [`apm2_cli`](../apm2-cli/AGENTS.md) - CLI client that communicates with this daemon

## References

- [Unix Domain Sockets](https://man7.org/linux/man-pages/man7/unix.7.html)
- [daemon(7)](https://man7.org/linux/man-pages/man7/daemon.7.html) - Linux daemon design
