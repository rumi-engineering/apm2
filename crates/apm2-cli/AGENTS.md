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

### FAC Lane Management (TCK-00515, TCK-00516, TCK-00539)

| Command | Description |
|---------|-------------|
| `apm2 fac lane init` | Bootstrap a fresh lane pool with directories and default profiles |
| `apm2 fac lane init --json` | Same, with JSON receipt output |
| `apm2 fac lane reconcile` | Repair missing lane directories/profiles, mark unrecoverable lanes CORRUPT |
| `apm2 fac lane reconcile --json` | Same, with JSON receipt output |
| `apm2 fac lane status` | Show all lane states (lock + lease + PID liveness) |
| `apm2 fac lane status --state RUNNING` | Filter lanes by state |
| `apm2 fac lane reset <lane_id>` | Reset lane: delete workspace/target/logs, remove lease |
| `apm2 fac lane reset <lane_id> --force` | Force-reset RUNNING lane (kills process first) |
| `apm2 fac services status` | Check daemon/worker service status with health verdicts |

### FAC Reconciliation (TCK-00534)

| Command | Description |
|---------|-------------|
| `apm2 fac reconcile --dry-run` | Preview crash recovery actions without mutating state |
| `apm2 fac reconcile --apply` | Apply crash recovery: reconcile stale leases and orphaned claimed jobs |

**Overview:** The `reconcile` subcommand performs deterministic crash recovery
on worker startup (or on-demand via CLI). After an unclean shutdown (crash,
SIGKILL, OOM-kill), queue and lane state can become inconsistent. Reconciliation
detects and repairs these inconsistencies:

1. **Lane reconciliation (Phase 1):** Scans all lanes for stale leases (dead PID
   + free lock). Stale leases are transitioned through CLEANUP to IDLE with
   receipts. Ambiguous PID states are marked CORRUPT (fail-closed).
2. **Queue reconciliation (Phase 2):** Scans `queue/claimed/` for orphaned jobs
   not backed by any active lane. Orphaned jobs are requeued (moved to
   `pending/`) or marked failed (moved to `denied/`) based on policy.

**Security Invariants:**

- [INV-RECON-001] No job is silently dropped; all outcomes recorded as receipts.
  Receipt persistence is mandatory in apply mode for both the final receipt and
  partial receipts after Phase-1 or Phase-2 failures.
- [INV-RECON-002] Stale lease detection is fail-closed: ambiguous PID state
  results in CORRUPT marking, not recovery. Corrupt markers are durably
  persisted.
- [INV-RECON-005] Queue reads are bounded by `MAX_CLAIMED_SCAN_ENTRIES`. Every
  directory entry counts toward the cap before file-type filtering.
- [INV-RECON-006] Stale lease recovery transitions through CLEANUP to IDLE with
  durable evidence before lease removal.
- [INV-RECON-007] Move operations are fail-closed: counters only increment after
  confirmed rename success.
- [INV-RECON-008] The `queue/claimed` directory is verified via
  `symlink_metadata()` before traversal; symlinked directories are rejected.
- [INV-RECON-012] Reconciliation is exempt from AJC lifecycle (RS-42, RFC-0027)
  as it runs at startup before the worker accepts any external authority.
- File operations use `O_NOFOLLOW` and reject symlinks/non-regular files.
- Directories are created with mode 0o700; files with mode 0o600.
- Best-effort lane cleanup catches `safe_rmtree_v1` permission failures
  (e.g., SystemMode 0o770 lanes) and marks the lane CORRUPT instead of
  aborting worker startup.

**Services Status Enhancements (TCK-00600):**
- Per-service `health` field: `healthy` / `degraded` / `unhealthy` (deterministic).
- Per-service `watchdog_sec` field: configured WatchdogSec in seconds.
- Overall `overall_health` field: worst-case across all services.
- `worker_heartbeat` field: heartbeat file freshness, age, PID from worker.
- Worker heartbeat read via `apm2_core::fac::worker_heartbeat::read_heartbeat`.

**Worker Watchdog Integration (TCK-00600):**
- Worker sends `READY=1` after broker connection via `sd_notify::notify_ready()`.
- Worker sends periodic `WATCHDOG=1` via `WatchdogTicker::ping_if_due()`.
- Worker writes heartbeat file each poll cycle via `write_heartbeat()`.

**Invariants:**
- [INV-LANE-001] At most one job executes in a lane at a time (enforced via `flock(LOCK_EX)`).
- [INV-LANE-004] Stale lease detection is fail-closed: ambiguous PID state reports CORRUPT.
- Lane commands operate directly on filesystem (no daemon required).
- [INV-RMTREE-001] Lane reset refuses symlink traversal at any depth.
- [INV-RMTREE-002] Lane reset cannot delete outside allowed parent boundary.

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

**Invariants:**
- [INV-CLI-003] Uses ProtocolServer framing and handshake; JSON framing is prohibited.
- [INV-CLI-004] Connection is closed after each request-response cycle (stateless).
- [INV-CLI-005] Operator vs session sockets are distinct; privileged calls use operator.sock only.

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

## TCK-00536 Security Posture Update

- Added FAC root preflight validation (`run_fac`) to enforce `private/fac` hierarchy ownership and mode checks before executing FAC commands.
- New `fac_permissions` helper module is now part of command-level security hardening for directory/file creation under FAC paths.

- [`apm2_core::config`](../apm2-core/src/config/AGENTS.md) - `EcosystemConfig` for socket path resolution
- [`apm2_daemon`](../apm2-daemon/AGENTS.md) - Server-side implementation

## E2E Test Coverage (TCK-00601)

- `tests/tck_00601_e2e_deterministic_failures.rs`: 15 tests covering FAC gates
  deterministic failure modes and secrets posture.
  - **Deterministic failures**: Broker absent fails fast (no hang), worker absent
    heartbeat returns false immediately, bounded receipt wait times out within
    bounds, heartbeat reads on missing/malformed files complete in < 1s.
  - **Credential posture separation**: Gates path (broker init) does NOT require
    GitHub credentials; push path requires them. `require_github_credentials`
    error includes actionable remediation (env vars, systemd, file path,
    auth-setup command).
  - **Secrets posture**: Error messages, Debug output, and serialized receipts
    are verified to not leak token values (ghp_, ghs_ prefixes). Known secret
    env var values are checked against receipt JSON.
  - All tests use hermetic `tempdir`-based `APM2_HOME` isolation.
  - Hang guard: `TEST_HANG_GUARD_SECS = 30` enforced via `assert_no_hang` wrapper.

## References

- [Clap Derive Tutorial](https://docs.rs/clap/latest/clap/_derive/_tutorial/index.html)
- [Unix Domain Sockets](https://man7.org/linux/man-pages/man7/unix.7.html)
