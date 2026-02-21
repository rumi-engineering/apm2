# client

> Daemon communication clients using Unix domain sockets with protobuf-based framing.

## Overview

The `client` module provides the client-side IPC layer for communicating with the `apm2-daemon` via Unix domain sockets. It contains two sub-modules:

- **`daemon`**: Legacy stub client (all methods return `ProtocolMigrationRequired` per DD-009). Retained for type signatures and error handling until full protobuf migration is complete.
- **`protocol`**: Active protocol clients (`OperatorClient` and `SessionClient`) that implement tag-based protobuf framing over dual sockets (`operator.sock` and `session.sock`).

The protocol module is the primary integration surface. All CLI commands that communicate with the daemon go through either `OperatorClient` (privileged operations) or `SessionClient` (session-scoped operations).

```
CLI Command
    |
    +-- OperatorClient (operator.sock)
    |       Privileged: Shutdown, ClaimWork, SpawnEpisode, IssueCapability,
    |                   Process mgmt, Credential mgmt, Consensus queries,
    |                   ReviewReceipt ingestion, ChangeSet publishing
    |
    +-- SessionClient (session.sock)
            Session-scoped: RequestTool, EmitEvent, PublishEvidence,
                           StreamLogs, SessionStatus
```

## Key Types

### `DaemonClient<'a>` (daemon.rs)

```rust
pub struct DaemonClient<'a> {
    socket_path: &'a Path,
    timeout: Duration,
}
```

Legacy stub client. All episode operations return `DaemonClientError::ProtocolMigrationRequired`.

**Invariants:**
- [INV-DC-001] All methods return `Err(ProtocolMigrationRequired)` per DD-009.
- [INV-DC-002] Default timeout is `DEFAULT_TIMEOUT_SECS` (30 seconds).

### `DaemonClientError` (daemon.rs)

```rust
pub enum DaemonClientError {
    DaemonNotRunning,
    ConnectionFailed(String),
    IoError(std::io::Error),
    FrameTooLarge { size: usize, max: usize },
    SerdeError(String),
    DaemonError { code: ErrorCode, message: String },
    UnexpectedResponse(String),
    ProtocolMigrationRequired,
}
```

**Contracts:**
- [CTR-DC-001] `io::ErrorKind::NotFound` and `ConnectionRefused` map to `DaemonNotRunning`.

### `ErrorCode` (daemon.rs)

```rust
pub enum ErrorCode {
    EpisodeNotFound,
    InvalidRequest,
    InternalError,
    NotSupported,
}
```

Minimal error code subset retained for CLI error handling.

### `ProtocolClientError` (protocol.rs)

```rust
pub enum ProtocolClientError {
    DaemonNotRunning,
    ConnectionFailed(String),
    HandshakeFailed(String),
    VersionMismatch { client: u32, server: u32 },
    IoError(io::Error),
    FrameTooLarge { size: usize, max: usize },
    ProtocolError(ProtocolError),
    DecodeError(String),
    DaemonError { code: String, message: String },
    UnexpectedResponse(String),
    Timeout,
}
```

**Contracts:**
- [CTR-PC-001] `io::ErrorKind::NotFound` and `ConnectionRefused` map to `DaemonNotRunning`.
- [CTR-PC-002] `ProtocolError` from daemon is wrapped directly.

### `OperatorClient` (protocol.rs)

```rust
pub struct OperatorClient {
    framed: Framed<UnixStream, FrameCodec>,
    server_info: String,
    daemon_signing_public_key: Option<[u8; 32]>,
    timeout: Duration,
}
```

Client for privileged operations on `operator.sock`.

**Invariants:**
- [INV-OP-001] Mandatory Hello/HelloAck handshake before any requests (CTR-PROTO-001).
- [INV-OP-002] All requests use tag-based protobuf framing; JSON is prohibited.
- [INV-OP-003] Handshake includes client contract hash per RFC-0020 section 3.1.2.

### `SessionClient` (protocol.rs)

```rust
pub struct SessionClient {
    framed: Framed<UnixStream, FrameCodec>,
    server_info: String,
    daemon_signing_public_key: Option<[u8; 32]>,
    timeout: Duration,
}
```

Client for session-scoped operations on `session.sock`.

**Invariants:**
- [INV-SC-001] Session operations require a valid `session_token`.
- [INV-SC-002] Same handshake protocol as `OperatorClient`.

### Response Types (daemon.rs)

```rust
pub struct CreateEpisodeResponse { pub episode_id: String, pub envelope_hash: String, pub created_at: String }
pub struct StartEpisodeResponse  { pub episode_id: String, pub session_id: String, pub lease_id: String, pub started_at: String }
pub struct StopEpisodeResponse   { pub episode_id: String, pub termination_class: String, pub stopped_at: String }
pub struct EpisodeStatusResponse { pub episode_id: String, pub state: String, /* ... */ }
pub struct EpisodeSummaryIpc     { pub episode_id: String, pub state: String, /* ... */ }
pub struct ListEpisodesResponse  { pub episodes: Vec<EpisodeSummaryIpc>, pub total: u32 }
pub struct EpisodeBudgetSummary  { pub tokens: String, pub tool_calls: String, pub wall_ms: String }
```

## Public API

### `DaemonClient` (daemon.rs)

| Method | Description |
|--------|-------------|
| `new(socket_path)` | Create client bound to a socket path |
| `with_timeout(timeout)` | Builder: set connection timeout |
| `is_daemon_running()` | Check if socket path exists |
| `create_episode(yaml, hash)` | Stub: returns `ProtocolMigrationRequired` |
| `start_episode(id, lease)` | Stub: returns `ProtocolMigrationRequired` |
| `stop_episode(id, reason, msg)` | Stub: returns `ProtocolMigrationRequired` |
| `get_episode_status(id)` | Stub: returns `ProtocolMigrationRequired` |
| `list_episodes(filter, limit)` | Stub: returns `ProtocolMigrationRequired` |

### `OperatorClient` (protocol.rs)

| Method | Description |
|--------|-------------|
| `connect(socket_path)` | Connect and handshake with default timeout |
| `connect_with_timeout(path, timeout)` | Connect with custom timeout |
| `daemon_signing_public_key()` | Get daemon Ed25519 public key from handshake |
| `shutdown(reason)` | Send shutdown request |
| `claim_work(actor, role, sig, nonce)` | Claim work assignment |
| `spawn_episode(token, envelope, hash)` | Spawn an episode |
| `issue_capability(token, cap_req)` | Issue a capability token |
| `consensus_status(token)` | Query consensus status |
| `consensus_validators(token)` | List consensus validators |
| `consensus_byzantine_evidence(token)` | Query byzantine fault evidence |
| `consensus_metrics(token)` | Query consensus metrics |
| `list_processes()` | List managed processes |
| `process_status(name)` | Get process status |
| `start_process(name)` | Start a process |
| `stop_process(name)` | Stop a process |
| `restart_process(name)` | Restart a process |
| `reload_process(name)` | Rolling restart a process |
| `work_status(session_token)` | Get work assignment status |
| `work_list()` | List work assignments |
| `ingest_review_receipt(...)` | Ingest review receipt (TCK-00389) |
| `publish_changeset(...)` | Publish change set (TCK-00394) |
| `list_credentials()` | List credential profiles |
| `add_credential(...)` | Add credential profile |
| `remove_credential(profile_id)` | Remove credential profile |
| `refresh_credential(profile_id)` | Force refresh credentials |
| `switch_credential(process, profile)` | Switch process credentials |
| `login_credential(provider, profile)` | Interactive login |
| `open_work(work_spec_json)` | Open a new work item (TCK-00635) |

### `SessionClient` (protocol.rs)

| Method | Description |
|--------|-------------|
| `connect(socket_path)` | Connect and handshake with default timeout |
| `connect_with_timeout(path, timeout)` | Connect with custom timeout |
| `daemon_signing_public_key()` | Get daemon Ed25519 public key from handshake |
| `request_tool(token, tool, args, key)` | Request tool execution |
| `emit_event(token, type, payload)` | Emit a session event |
| `publish_evidence(token, type, data)` | Publish evidence artifact |
| `stream_logs(token, lines, follow)` | Stream process logs |
| `session_status(token)` | Get session status |
| `session_status_with_termination(...)` | Get session status with termination info |

### Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `MAX_FRAME_SIZE` | 16 MiB | Maximum IPC frame size (AD-DAEMON-002) |
| `DEFAULT_TIMEOUT_SECS` | 30 | Default connection timeout |

## Related Modules

- [`apm2-cli` (crate)](../../AGENTS.md) -- Crate-level CLI architecture
- [`apm2_daemon::protocol`](../../../apm2-daemon/AGENTS.md) -- Server-side protocol implementation
- [`apm2_core::config`](../../../apm2-core/src/config/AGENTS.md) -- Socket path resolution

## References

- DD-009: `ProtocolServer`-only control plane
- RFC-0017: Protocol migration from JSON to protobuf
- RFC-0020 section 3.1.2: HSI contract manifest in handshake
- AD-DAEMON-002: UDS transport with length-prefixed framing
- TCK-00281: Legacy JSON IPC removal
- TCK-00288: Protocol client implementation
- TCK-00348: HSI contract hash in Hello message
