# IPC Module

> Unix socket-based inter-process communication between CLI client and daemon using length-prefixed JSON frames.

**Legacy notice:** This module defines the legacy JSON IPC surface. RFC-0017
DD-009 forbids JSON IPC in default builds; ProtocolServer is the only supported
control-plane IPC. This module is retained temporarily for removal under
TCK-00281 and must not be used for new development.

## Overview

The `apm2_core::ipc` module defines the legacy wire protocol for CLI-to-daemon
communication in APM2. It provides:

- Request/response enums for all daemon operations
- Length-prefixed framing for message boundaries over stream sockets
- Typed error codes for structured error handling
- DTOs for process and credential information

This module historically established the contract boundary between `apm2-cli`
(client) and `apm2-daemon` (server). Under DD-009, default builds must not
expose this JSON IPC surface, and any JSON framing sent to ProtocolServer
sockets must be rejected before handler logic.

## Key Types

### `IpcRequest`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum IpcRequest {
    Ping,
    Status,
    ListProcesses,
    GetProcess { name: String },
    StartProcess { name: String },
    StopProcess { name: String },
    RestartProcess { name: String },
    ReloadProcess { name: String },
    TailLogs { name: Option<String>, lines: u32, follow: bool },
    ListCredentials,
    GetCredential { profile_id: String },
    AddCredential { profile_id: String, provider: String, auth_method: String },
    RemoveCredential { profile_id: String },
    RefreshCredential { profile_id: String },
    SwitchCredential { process_name: String, profile_id: String },
    Shutdown,
}
```

**Invariants:**
- [INV-1601] All variants serialize to JSON with `{"type": "variant_name", ...}` structure via `#[serde(tag = "type")]`.
- [INV-1602] String fields must be non-empty for operations requiring identifiers (process name, profile_id).

**Contracts:**
- [CTR-1601] Clients must serialize requests using `serde_json` before framing.
- [CTR-1602] The daemon must handle all variants; unrecognized types return `ErrorCode::InvalidRequest`.

### `IpcResponse`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum IpcResponse {
    Pong { version: String, uptime_secs: u64 },
    Status { version: String, pid: u32, uptime_secs: u64, process_count: u32, running_instances: u32 },
    ProcessList { processes: Vec<ProcessSummary> },
    ProcessDetails { process: ProcessInfo },
    Ok { message: Option<String> },
    Error { code: ErrorCode, message: String },
    LogLines { lines: Vec<LogEntry> },
    CredentialList { profiles: Vec<CredentialProfileMetadata> },
    CredentialDetails { profile: CredentialProfileMetadata },
}
```

**Invariants:**
- [INV-1603] Every request produces exactly one response (request-response protocol, not streaming except `TailLogs` with `follow: true`).
- [INV-1604] `Error` responses always include both a machine-readable `code` and human-readable `message`.

**Contracts:**
- [CTR-1603] Daemon must respond with `Error` for any request it cannot fulfill, never silently drop.
- [CTR-1604] Clients must handle all response variants, including unknown future variants gracefully.

### `ErrorCode`

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    ProcessNotFound,
    ProcessAlreadyRunning,
    ProcessNotRunning,
    CredentialNotFound,
    CredentialExists,
    InvalidRequest,
    InternalError,
    NotSupported,
}
```

**Invariants:**
- [INV-1605] Error codes are stable across versions for client compatibility.

### `ProcessSummary`

```rust
pub struct ProcessSummary {
    pub name: String,
    pub instances: u32,
    pub running: u32,
    pub status: ProcessState,
    pub cpu_percent: Option<f32>,
    pub memory_bytes: Option<u64>,
    pub uptime_secs: Option<u64>,
    pub restart_count: u32,
}
```

**Invariants:**
- [INV-1606] `running <= instances` always holds.
- [INV-1607] `uptime_secs` is `None` when no instances are running.

### `ProcessInfo`

```rust
pub struct ProcessInfo {
    pub name: String,
    pub id: ProcessId,
    pub command: String,
    pub args: Vec<String>,
    pub cwd: Option<String>,
    pub instances: u32,
    pub instance_details: Vec<InstanceInfo>,
    pub credential_profile: Option<String>,
}
```

**Invariants:**
- [INV-1608] `instance_details.len() == instances as usize` when fully populated.

### `InstanceInfo`

```rust
pub struct InstanceInfo {
    pub index: u32,
    pub pid: Option<u32>,
    pub state: ProcessState,
    pub cpu_percent: Option<f32>,
    pub memory_bytes: Option<u64>,
    pub uptime_secs: Option<u64>,
    pub restart_count: u32,
}
```

**Invariants:**
- [INV-1609] `pid` is `Some` only when `state` is `Running`.
- [INV-1610] `index` is unique within parent `ProcessInfo.instance_details`.

### `LogEntry`

```rust
pub struct LogEntry {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub process_name: String,
    pub instance: u32,
    pub stream: String,
    pub content: String,
}
```

**Contracts:**
- [CTR-1605] `stream` is either `"stdout"` or `"stderr"`.
- [CTR-1606] `timestamp` is always UTC.

### `IpcError`

```rust
#[derive(Debug, thiserror::Error)]
pub enum IpcError {
    #[error("failed to connect to daemon: {0}")]
    ConnectionFailed(String),
    #[error("daemon is not running")]
    DaemonNotRunning,
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("operation timed out")]
    Timeout,
}
```

**Contracts:**
- [CTR-1607] `DaemonNotRunning` is returned when socket file exists but connection is refused.
- [CTR-1608] `ConnectionFailed` is returned when socket file does not exist or path is invalid.

## Public API

### Frame Format

The wire protocol uses length-prefixed framing over Unix domain sockets:

```
+----------------------------+------------------+
| Length (4 bytes, big-endian) | JSON payload     |
+----------------------------+------------------+
```

**Invariants:**
- [INV-1611] Length prefix is always exactly 4 bytes, big-endian unsigned 32-bit integer.
- [INV-1612] Length value equals the exact byte length of the JSON payload (not including the 4-byte prefix).
- [INV-1613] Maximum message size is `u32::MAX` bytes (4 GiB), though practical limits are much smaller.

### `frame_message`

```rust
#[must_use]
pub fn frame_message(message: &[u8]) -> Vec<u8>
```

Prepends a 4-byte big-endian length prefix to the message bytes.

**Contracts:**
- [CTR-1609] Input must be a valid JSON-serialized `IpcRequest` or `IpcResponse`.
- [CTR-1610] Returns a new `Vec<u8>` with capacity `4 + message.len()`.

### `parse_frame_length`

```rust
#[must_use]
pub fn parse_frame_length(buffer: &[u8]) -> Option<usize>
```

Extracts the payload length from a buffer's first 4 bytes.

**Contracts:**
- [CTR-1611] Returns `None` if `buffer.len() < 4`.
- [CTR-1612] Returns `Some(len)` where `len` is the payload size (excluding the 4-byte prefix).

## Examples

### Sending a Request (Client)

```rust
use apm2_core::ipc::{IpcRequest, frame_message};
use std::os::unix::net::UnixStream;
use std::io::Write;

let request = IpcRequest::Status;
let json = serde_json::to_vec(&request)?;
let framed = frame_message(&json);

// Legacy JSON IPC socket (unsupported in default builds).
let mut stream = UnixStream::connect("/run/apm2/daemon.sock")?;
stream.write_all(&framed)?;
```

### Receiving a Response (Client)

```rust
use apm2_core::ipc::{IpcResponse, parse_frame_length};
use std::io::Read;

// Read length prefix
let mut len_buf = [0u8; 4];
stream.read_exact(&mut len_buf)?;
let payload_len = parse_frame_length(&len_buf).unwrap();

// Read payload
let mut payload = vec![0u8; payload_len];
stream.read_exact(&mut payload)?;

let response: IpcResponse = serde_json::from_slice(&payload)?;
match response {
    IpcResponse::Status { version, pid, uptime_secs, process_count, running_instances } => {
        println!("Daemon v{version} (PID {pid}) - {running_instances}/{process_count} processes running");
    }
    IpcResponse::Error { code, message } => {
        eprintln!("Error [{code:?}]: {message}");
    }
    _ => {}
}
```

### Processing Requests (Daemon)

```rust
use apm2_core::ipc::{IpcRequest, IpcResponse, ErrorCode, frame_message};

fn handle_request(request: IpcRequest) -> IpcResponse {
    match request {
        IpcRequest::Ping => IpcResponse::Pong {
            version: env!("CARGO_PKG_VERSION").to_string(),
            uptime_secs: get_uptime_secs(),
        },
        IpcRequest::StartProcess { name } => {
            match start_process(&name) {
                Ok(_) => IpcResponse::Ok { message: Some(format!("Started {name}")) },
                Err(e) => IpcResponse::Error {
                    code: ErrorCode::ProcessNotFound,
                    message: e.to_string(),
                },
            }
        }
        // ... handle other variants
        _ => IpcResponse::Error {
            code: ErrorCode::NotSupported,
            message: "Operation not implemented".to_string(),
        },
    }
}
```

## Protocol Considerations

### Socket Location

Legacy JSON IPC socket paths (unsupported in default builds) were typically:
- Linux: `/run/apm2/daemon.sock` or `$XDG_RUNTIME_DIR/apm2/daemon.sock`
- macOS: `$HOME/.apm2/daemon.sock`

### Timeout Handling

Clients should implement timeouts for all operations. The `IpcError::Timeout` variant indicates the daemon did not respond within the expected window. Recommended default: 30 seconds for most operations, longer for operations that may block (credential refresh).

### Connection Lifecycle

1. Client connects to Unix socket
2. Client sends one framed request
3. Daemon sends one framed response (or stream for `TailLogs` with `follow: true`)
4. Connection closes (stateless protocol)

For `TailLogs` with `follow: true`, the connection remains open and the daemon sends multiple `LogLines` responses until the client disconnects.

## Related Modules

- [`apm2_core::process`](../process/AGENTS.md) - Provides `ProcessId` and `ProcessState` types used in responses
- [`apm2_core::credentials`](../credentials/AGENTS.md) - Provides `CredentialProfileMetadata` for credential operations
- [`apm2_daemon`](../../../../apm2-daemon/AGENTS.md) - Legacy server implementation (disabled by DD-009)
- [`apm2_cli`](../../../../apm2-cli/AGENTS.md) - Legacy client implementation (de-scoped under DD-009)
