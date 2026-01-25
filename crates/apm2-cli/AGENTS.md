# apm2-cli

> Command-line interface for managing AI CLI processes via IPC communication with the daemon.

## Overview

The `apm2-cli` crate implements the CLI client in APM2's four-layer runtime architecture. It provides:

- Clap-based argument parsing with subcommands
- Unix socket client for daemon communication
- Formatted output for process status and credential information
- Human-readable byte and duration formatting

```
┌─────────────────┐
│   apm2-cli      │  ◄── This crate
│  ┌───────────┐  │
│  │  Clap     │──┼──► Commands ──► IPC Client
│  │  Parser   │  │                     │
│  └───────────┘  │                     │
└─────────────────┘                     │
         │                              │
         │ Unix socket (JSON framed)    │
         │                              │
┌────────▼──────────────────────────────▼─┐
│              apm2-daemon                │
└─────────────────────────────────────────┘
```

## Key Types

### `Cli`

```rust
#[derive(Parser, Debug)]
#[command(name = "apm2")]
struct Cli {
    #[arg(short, long, default_value = "ecosystem.toml")]
    config: PathBuf,

    #[arg(long)]
    socket: Option<PathBuf>,

    #[arg(long, default_value = "warn")]
    log_level: String,

    #[command(subcommand)]
    command: Commands,
}
```

Top-level CLI argument parser with global options.

**Invariants:**
- [INV-CLI-001] `config` defaults to `ecosystem.toml` in current directory.
- [INV-CLI-002] `socket` path resolution: CLI arg > config file > `/var/run/apm2/apm2.sock`.

### `Commands`

```rust
#[derive(Subcommand, Debug)]
enum Commands {
    // Daemon management
    Daemon { no_daemon: bool },
    Kill,

    // Process management
    Start { name: String },
    Stop { name: String },
    Restart { name: String },
    Reload { name: String },

    // Process info
    List,
    Status { name: String },
    Logs { name: String, lines: u32, follow: bool },

    // Credential management
    Creds(CredsCommands),
}
```

Primary command enum with subcommands for all daemon operations.

**Contracts:**
- [CTR-CLI-001] `Daemon` spawns `apm2-daemon` binary, does not implement daemon logic directly.
- [CTR-CLI-002] `Kill` sends `IpcRequest::Shutdown` to daemon.
- [CTR-CLI-003] Process commands require daemon to be running.

### `CredsCommands`

```rust
#[derive(Subcommand, Debug)]
enum CredsCommands {
    List,
    Add { profile_id: String, provider: String, auth_method: String },
    Remove { profile_id: String },
    Refresh { profile_id: String },
    Switch { process: String, profile: String },
    Login { provider: String, profile_id: Option<String> },
}
```

Credential management subcommands.

**Contracts:**
- [CTR-CLI-004] `Login` is client-side only, does not communicate with daemon.
- [CTR-CLI-005] All other credential commands require daemon connection.

## Command Structure

### Daemon Lifecycle

| Command | Description | IPC Request |
|---------|-------------|-------------|
| `apm2 daemon` | Start the daemon | N/A (spawns binary) |
| `apm2 daemon --no-daemon` | Start in foreground | N/A (spawns binary) |
| `apm2 kill` | Stop the daemon | `Shutdown` |

### Process Management

| Command | Description | IPC Request |
|---------|-------------|-------------|
| `apm2 start <name>` | Start a process | `StartProcess { name }` |
| `apm2 stop <name>` | Stop a process | `StopProcess { name }` |
| `apm2 restart <name>` | Restart a process | `RestartProcess { name }` |
| `apm2 reload <name>` | Rolling restart | `ReloadProcess { name }` |
| `apm2 list` (alias: `ls`) | List all processes | `ListProcesses` |
| `apm2 status <name>` | Show process details | `GetProcess { name }` |
| `apm2 logs <name>` | Tail process logs | `TailLogs { name, lines, follow }` |

### Credential Management

| Command | Description | IPC Request |
|---------|-------------|-------------|
| `apm2 creds list` | List credential profiles | `ListCredentials` |
| `apm2 creds add` | Add credential profile | `AddCredential { ... }` |
| `apm2 creds remove` | Remove credential profile | `RemoveCredential { profile_id }` |
| `apm2 creds refresh` | Force refresh credentials | `RefreshCredential { profile_id }` |
| `apm2 creds switch` | Switch process credentials | `SwitchCredential { ... }` |
| `apm2 creds login` | Interactive login (client-side) | N/A |

## IPC Client

Each command module implements `send_request` for daemon communication:

```rust
fn send_request(socket_path: &Path, request: &IpcRequest) -> Result<IpcResponse> {
    // 1. Connect to Unix socket
    let mut stream = UnixStream::connect(socket_path)?;

    // 2. Serialize and frame request
    let json = serde_json::to_vec(&request)?;
    let framed = frame_message(&json);
    stream.write_all(&framed)?;

    // 3. Read response length prefix
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;

    // 4. Read and parse response
    let mut response_buf = vec![0u8; len];
    stream.read_exact(&mut response_buf)?;
    let response: IpcResponse = serde_json::from_slice(&response_buf)?;

    Ok(response)
}
```

**Invariants:**
- [INV-CLI-003] Uses length-prefixed JSON framing per `apm2_core::ipc` protocol.
- [INV-CLI-004] Connection is closed after each request-response cycle (stateless).

**Contracts:**
- [CTR-CLI-101] Returns `Error` with context if socket connection fails.
- [CTR-CLI-102] Returns `Error` if daemon returns `IpcResponse::Error`.
- [CTR-CLI-103] Exits with non-zero status on any error.

## Output Formatting

### Process Table (`apm2 list`)

```
NAME                  RUNNING    TOTAL STATUS       CPU        MEM     UPTIME
------------------------------------------------------------------------------
claude-code                 1        1 Running      2.3%    156.2M    1h 23m
gemini-cli                  0        1 Stopped        0%       0B         0s
```

**Contracts:**
- [CTR-CLI-104] Process names are truncated to 20 characters with `...` suffix.
- [CTR-CLI-105] Memory is formatted as human-readable (B, K, M, G).

### Human-Readable Formatting

#### `format_bytes`

```rust
fn format_bytes(bytes: u64) -> String
```

Formats byte counts with appropriate unit suffix:
- `< 1024`: `"123B"`
- `< 1 MiB`: `"1.5K"`
- `< 1 GiB`: `"156.2M"`
- `>= 1 GiB`: `"2.3G"`

#### `format_duration`

```rust
fn format_duration(secs: u64) -> String
```

Formats durations for human readability:
- `< 60s`: `"45s"`
- `< 1h`: `"5m 30s"`
- `< 1d`: `"2h 15m"`
- `>= 1d`: `"3d 12h"`

## Examples

### List Processes

```bash
$ apm2 list
NAME                  RUNNING    TOTAL STATUS       CPU        MEM     UPTIME
------------------------------------------------------------------------------
claude-code                 1        1 Running      2.3%    156.2M    1h 23m
gemini-cli                  0        1 Stopped      0.0%       0B         0s
```

### Show Process Status

```bash
$ apm2 status claude-code
Name:        claude-code
ID:          1
Command:     claude --resume
Working Dir: /home/user/project
Instances:   1
Credentials: claude-api

Instance Details:
  [0] PID:  12345  State: Running       CPU:   2.3%  Mem:   156.2M  Uptime:   1h 23m  Restarts: 0
```

### Start a Process

```bash
$ apm2 start claude-code
Started 'claude-code': Process 'claude-code' started
```

### Manage Credentials

```bash
$ apm2 creds list
ID                   PROVIDER     AUTH METHOD     EXPIRES              LAST USED
---------------------------------------------------------------------------------------
claude-api           claude       api_key         N/A                  2024-01-15 10:30

$ apm2 creds add gemini-key --provider gemini --auth-method api_key
Created credential profile 'gemini-key'

Next steps:
  1. Store your credentials securely:
     apm2 creds login gemini --profile-id gemini-key
  2. Or manually add to OS keyring
```

## Error Handling

Commands handle daemon responses uniformly:

```rust
match send_request(socket_path, &request)? {
    IpcResponse::Ok { message } => {
        println!("Success{}", message.map(|m| format!(": {m}")).unwrap_or_default());
    }
    IpcResponse::Error { code, message } => {
        bail!("Failed: {message} ({code:?})");
    }
    _ => bail!("Unexpected response"),
}
```

**Contracts:**
- [CTR-CLI-106] All error messages include the `ErrorCode` for debugging.
- [CTR-CLI-107] Connection errors suggest checking if daemon is running.

## Related Modules

- [`apm2_core::ipc`](../apm2-core/src/ipc/AGENTS.md) - Wire protocol types and framing functions
- [`apm2_core::config`](../apm2-core/src/config/AGENTS.md) - `EcosystemConfig` for socket path resolution
- [`apm2_daemon`](../apm2-daemon/AGENTS.md) - Server-side implementation

## References

- [Clap Derive Tutorial](https://docs.rs/clap/latest/clap/_derive/_tutorial/index.html)
- [Unix Domain Sockets](https://man7.org/linux/man-pages/man7/unix.7.html)
