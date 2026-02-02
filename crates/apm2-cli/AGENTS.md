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
- [INV-CLI-002] Socket path resolution follows dual-socket architecture (TCK-00249, TCK-00280):
  - `--socket` CLI arg overrides config file settings for the operator socket
  - Config file must specify both `operator_socket` and `session_socket` in `[daemon]` section
  - Defaults: `${XDG_RUNTIME_DIR}/apm2/operator.sock` and `${XDG_RUNTIME_DIR}/apm2/session.sock`
  - Falls back to `/tmp/apm2/operator.sock` and `/tmp/apm2/session.sock` if `XDG_RUNTIME_DIR` not set

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
- [CTR-CLI-002] `Kill` issues a shutdown request via ProtocolServer; legacy JSON IPC is forbidden.
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

| Command | Description |
|---------|-------------|
| `apm2 start <name>` | Start a process |
| `apm2 stop <name>` | Stop a process |
| `apm2 restart <name>` | Restart a process |
| `apm2 reload <name>` | Rolling restart |
| `apm2 list` (alias: `ls`) | List all processes |
| `apm2 status <name>` | Show process details |
| `apm2 logs <name>` | Tail process logs |

### Credential Management

| Command | Description |
|---------|-------------|
| `apm2 creds list` | List credential profiles |
| `apm2 creds add` | Add credential profile |
| `apm2 creds remove` | Remove credential profile |
| `apm2 creds refresh` | Force refresh credentials |
| `apm2 creds switch` | Switch process credentials |
| `apm2 creds login` | Interactive login (client-side) |

## IPC Client (ProtocolServer-only, DD-009)

CLI control-plane IPC must use ProtocolServer handshake + binary framing only.
Legacy JSON IPC (`apm2_core::ipc`) is forbidden by DD-009 and must not be used.
Until ProtocolServer wiring is complete, CLI control-plane usage is de-scoped and
must not be treated as an authority surface.

**Dual-Socket Architecture (TCK-00249, TCK-00280):**
- `operator_socket` (mode 0600): Used for privileged operations requiring owner access
  - Process control: start, stop, restart, reload
  - Credential management: add, remove, refresh, switch
  - Daemon control: kill
- `session_socket` (mode 0660): Used for session-scoped read operations
  - Status queries: list, status, logs
  - Credential listing: creds list
- Both sockets are **required** in the ecosystem config `[daemon]` section
- Legacy single `socket` field is rejected with DD-009 validation error

**Invariants:**
- [INV-CLI-003] Uses ProtocolServer framing and handshake; JSON framing is prohibited.
- [INV-CLI-004] Connection is closed after each request-response cycle (stateless).
- [INV-CLI-005] Operator vs session sockets are distinct; privileged calls use operator.sock only.
- [INV-CLI-006] Both `operator_socket` and `session_socket` must be configured (TCK-00280).

**Contracts:**
- [CTR-CLI-101] Returns `Error` with context if socket connection fails.
- [CTR-CLI-102] Returns `Error` if daemon returns protocol error status.
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

Commands surface daemon errors and exit non-zero on failure.

**Contracts:**
- [CTR-CLI-106] All error messages include a structured error code when available.
- [CTR-CLI-107] Connection errors suggest checking if daemon is running.

## Related Modules

- [`apm2_core::config`](../apm2-core/src/config/AGENTS.md) - `EcosystemConfig` for socket path resolution
- [`apm2_daemon`](../apm2-daemon/AGENTS.md) - Server-side implementation

## References

- [Clap Derive Tutorial](https://docs.rs/clap/latest/clap/_derive/_tutorial/index.html)
- [Unix Domain Sockets](https://man7.org/linux/man-pages/man7/unix.7.html)
