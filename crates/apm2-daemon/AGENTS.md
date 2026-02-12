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
- PCAC verifier-economics enforcement wired through `InProcessKernel` lifecycle stages (`join`, `revalidate`, `consume`, anti-entropy verification) via `apm2_core::pcac::verifier_economics`

**Performance/Security Constraint:** verifier-economics bounds are containment controls. Tier2+ lifecycle operations fail closed on timing/proof-check budget exceedance; Tier0/1 stays monitor-only.

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

### `SocketManager` (TCK-00249)

```rust
pub fn bind(config: SocketManagerConfig) -> ProtocolResult<SocketManager>
pub async fn accept(&self) -> ProtocolResult<(Connection, ConnectionPermit, SocketType)>
```

Dual-socket manager for privilege separation. Creates two Unix sockets:

- **`operator.sock`** (mode 0600): Privileged operations (ClaimWork, SpawnEpisode, IssueCapability, Shutdown)
- **`session.sock`** (mode 0660): Session-scoped operations (RequestTool, EmitEvent, PublishEvidence, StreamTelemetry)

**Invariants (SocketManager):**
- [INV-SM-001] Operator socket always has mode 0600.
- [INV-SM-002] Session socket always has mode 0660.
- [INV-SM-003] `is_privileged` is determined solely by which socket accepted the connection.
- [INV-SM-004] Both sockets share the same parent directory (mode 0700).

**Contracts (SocketManager):**
- [CTR-SM-001] Removes stale socket files before binding.
- [CTR-SM-002] Creates parent directory with mode 0700.
- [CTR-SM-003] Sets socket permissions after binding (0600 for operator, 0660 for session).
- [CTR-SM-004] Cleans up both socket files on shutdown.
- [CTR-SM-005] Connection type (`SocketType::Operator` or `SocketType::Session`) is routed
  based on which listener accepted the connection.

### `SocketType`

```rust
pub enum SocketType {
    Operator,  // is_privileged() = true
    Session,   // is_privileged() = false
}
```

Represents the type of socket a connection arrived on. Used to determine
which handler namespaces are accessible.

### `SessionDispatcher` (TCK-00252)

```rust
pub struct SessionDispatcher { ... }
pub fn dispatch(&self, frame: &Bytes, ctx: &ConnectionContext) -> ProtocolResult<SessionResponse>
```

Session-scoped endpoint dispatcher for RFC-0017. Routes session requests to the
appropriate handler after validating the session token.

**Session Endpoints (CTR-PROTO-008):**
- `RequestTool`: Request tool execution within capability bounds
- `EmitEvent`: Emit signed event to ledger
- `PublishEvidence`: Publish evidence artifact to content-addressed storage
- `StreamTelemetry`: Stream telemetry frames for observability

**Invariants (SessionDispatcher):**
- [INV-SESS-001] Session endpoints require valid `session_token`.
- [INV-SESS-002] Invalid/expired tokens return `SESSION_ERROR_INVALID`.
- [INV-SESS-003] Operator connections receive `SESSION_ERROR_PERMISSION_DENIED`.
- [INV-SESS-004] Token validation uses constant-time HMAC comparison (CTR-WH001).

**Contracts (SessionDispatcher):**
- [CTR-SD-001] Token is validated BEFORE any handler logic executes.
- [CTR-SD-002] Messages use bounded decoding (CTR-1603).
- [CTR-SD-003] Session ID from token is used for authorization, not user input.

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

## Projection Recovery Handlers (TCK-00469)

### `PrivilegedDispatcher::handle_register_recovery_evidence` (IPC-PRIV-074)

Registers durable recovery evidence for frozen projections. Requires full
PCAC lifecycle enforcement (join, revalidate, consume, effect) before any
mutation.

**Security Invariants:**
- [INV-PRV-001] Caller identity is bound to authenticated peer credentials
  via `derive_actor_id(peer_creds)` before processing.
- [INV-PRV-002] `lease_id` is required and validated (non-empty, bounded
  length) for PCAC lifecycle authority binding.
- [INV-PRV-003] `receipts_json` payload is bounded by `MAX_RECEIPTS_JSON_SIZE`
  (256 KiB) before deserialization, and receipt count by
  `MAX_RECEIPTS_PER_REQUEST` (4096) after, to prevent memory/CPU exhaustion.
- [INV-PRV-004] PCAC lifecycle gate must be wired; missing gate returns
  fail-closed `CapabilityRequestRejected`.

### `PrivilegedDispatcher::handle_request_unfreeze` (IPC-PRIV-075)

Creates and applies an unfreeze event for frozen projections. Requires full
PCAC lifecycle enforcement before mutation.

**Security Invariants:**
- [INV-PRV-005] Same caller identity binding as IPC-PRIV-074.
- [INV-PRV-006] Same `lease_id` validation as IPC-PRIV-074.
- [INV-PRV-007] PCAC lifecycle gate enforced before create+apply mutation
  sequence.

### Divergence Watchdog

**Security Invariants (TCK-00469):**
- [INV-DW-001] All cryptographic digest comparisons (merge receipt HEAD vs.
  external trunk HEAD, temporal authority refs, window refs) use
  `subtle::ConstantTimeEq::ct_eq()` to prevent timing side-channels.
- [INV-DW-002] `sink_endpoint_evidence()` emits `tracing::warn!` when using
  local-signer fallback (self-attested endpoint identity).
- [INV-DW-003] GitHub API tokens are stored as `secrecy::SecretString` and
  exposed only at the HTTP header construction boundary via `ExposeSecret`.

## Related Modules

- [`apm2_core::process`](../apm2-core/src/process/AGENTS.md) - `ProcessSpec`, `ProcessState`, `ProcessRunner`
- [`apm2_core::supervisor`](../apm2-core/src/supervisor/AGENTS.md) - Process collection management
- [`apm2_core::config`](../apm2-core/src/config/AGENTS.md) - `EcosystemConfig` for daemon configuration
- [`apm2_cli`](../apm2-cli/AGENTS.md) - CLI client that communicates with this daemon

## References

- [Unix Domain Sockets](https://man7.org/linux/man-pages/man7/unix.7.html)
- [daemon(7)](https://man7.org/linux/man-pages/man7/daemon.7.html) - Linux daemon design
