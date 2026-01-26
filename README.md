# APM2

Process supervision for AI agent CLIs (Claude Code, Gemini CLI, Codex CLI, and custom tools).

[![CI](https://github.com/Anveio/apm2/actions/workflows/ci.yml/badge.svg)](https://github.com/Anveio/apm2/actions/workflows/ci.yml)
[![Rust 1.85+](https://img.shields.io/badge/rust-1.85%2B-blue.svg)](https://www.rust-lang.org)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-MIT)

APM2 runs as a local daemon (`apm2-daemon`) controlled by a CLI (`apm2`). The daemon reads an `ecosystem.toml`, registers a set of processes, and exposes a Unix-socket API for starting/stopping them and querying status.

**Status:** pre-1.0 (expect breaking changes).

## Features

- Linux daemon + CLI architecture (Unix socket IPC)
- Config-driven process registry (`ecosystem.toml`)
- Start/stop/restart processes (all configured instances)
- Query process state (`list`, `status`)
- Spec-driven “factory” runner (`apm2 factory run`) for executing a Markdown spec with an agent CLI

**Planned / in progress:**

- `logs`, `reload`, and daemon-backed `creds` commands (CLI exists; daemon handlers are not implemented yet)
- Automatic restarts/backoff, health checks, and richer runtime metrics
- Event-sourced ledger + evidence/CAS integration end-to-end

## Install

APM2 is **Linux-only**. macOS and Windows are not currently supported.

## Supported platforms

| Platform | Support | Notes |
|----------|---------|-------|
| Linux (x86_64) | Supported | CI-tested (Ubuntu 24.04) |
| Linux (aarch64) | Best-effort | Not in CI; please report build issues |
| macOS | Not supported | Linux-only project |
| Windows | Not supported | Requires Unix domain sockets |

### Prerequisites

- Rust 1.85+
- `protoc` (Protocol Buffers compiler)

Ubuntu/Debian:

```bash
sudo apt-get update
sudo apt-get install -y protobuf-compiler
```

Other distros: install `protoc` via your package manager.

### From source

```bash
git clone https://github.com/Anveio/apm2.git
cd apm2

cargo install --path crates/apm2-daemon --locked
cargo install --path crates/apm2-cli --locked
```

### From git (no clone)

```bash
cargo install --git https://github.com/Anveio/apm2 --tag <TAG> apm2-daemon
cargo install --git https://github.com/Anveio/apm2 --tag <TAG> apm2-cli
```

`<TAG>` is a crate tag like `apm2-daemon-v0.3.0` / `apm2-cli-v0.3.0`.

## Quickstart

1. Create `ecosystem.toml` (or copy `ecosystem.example.toml`).
2. Start the daemon.
3. Start a configured process.

Minimal `ecosystem.toml` for local development (no root required):

```toml
[daemon]
socket = "/tmp/apm2/apm2.sock"
pid_file = "/tmp/apm2/apm2.pid"

[[processes]]
name = "claude"
command = "claude"
cwd = "/path/to/your/project"
```

Start the daemon in the foreground:

```bash
apm2 daemon --no-daemon
```

In another terminal:

```bash
apm2 list
apm2 start claude
apm2 status claude
```

## Configuration

APM2 reads `ecosystem.toml` by default (override with `--config <path>`).

- `[daemon]`: the daemon’s socket + pid file paths (defaults to `/var/run/apm2/...`)
- `[[processes]]`: supervised processes (name, command, args, `cwd`, `env`, and `instances`)

Other configuration sections exist and are parsed, but are not enforced end-to-end yet (for example: `[[credentials]]`, restart/backoff, shutdown policy, log routing, health checks).

See `ecosystem.example.toml` for a full annotated example.

## CLI commands (what they actually do)

APM2 is split into two binaries:

- `apm2`: the user-facing CLI (reads config to find the socket path; makes IPC requests)
- `apm2-daemon`: the daemon (loads config; manages processes; serves the Unix socket)

Most `apm2` subcommands require the daemon to already be running.

### Command reference (current)

| Command | Requires daemon | Current behavior |
|---------|------------------|------------------|
| `apm2 daemon [--no-daemon]` | No | Spawns `apm2-daemon` |
| `apm2 kill` | Yes | Requests daemon shutdown |
| `apm2 list` / `apm2 ls` | Yes | Lists configured processes |
| `apm2 status <name>` | Yes | Shows per-instance state/PIDs |
| `apm2 start <name>` | Yes | Starts all instances of `<name>` |
| `apm2 stop <name>` | Yes | Stops all instances of `<name>` |
| `apm2 restart <name>` | Yes | Stop then start `<name>` |
| `apm2 reload <name>` | Yes | Not implemented yet (errors) |
| `apm2 logs <name> ...` | Yes | Not implemented yet (errors) |
| `apm2 creds login <provider>` | No | Prints provider login guidance |
| `apm2 creds list/add/remove/refresh/switch` | Yes | Not implemented yet (errors) |
| `apm2 factory run <spec.md>` | No | Runs a spec via agent adapter |

### Global options

These apply to **every** `apm2` command:

- `--config <path>`: ecosystem config file path (default: `ecosystem.toml`)
- `--socket <path>`: override socket path (otherwise: config file socket, or `/var/run/apm2/apm2.sock`)
- `--log-level <trace|debug|info|warn|error>`: CLI logging verbosity (default: `warn`)

### Daemon lifecycle

#### `apm2 daemon [--no-daemon]`

Starts the daemon by spawning the `apm2-daemon` binary.

- Always passes `--config <path>` through to `apm2-daemon`
- Default mode: the daemon **daemonizes itself** (double-fork), and `apm2` returns immediately
- With `--no-daemon`: runs the daemon in the foreground (useful for development)

Common pitfalls:

- `apm2 daemon` needs `apm2-daemon` in your `PATH` (install both binaries).
- The default config uses `/var/run/apm2/...` paths; for local development, set `[daemon].socket` and `[daemon].pid_file` to a writable location like `/tmp/apm2/...`.

#### `apm2 kill`

Sends an IPC shutdown request to the daemon.

- The daemon sets a shutdown flag, stops managed processes (SIGTERM then SIGKILL after a timeout), and removes the socket + pid file.
- This is a *graceful shutdown request*, not a blind `kill -9`.

### Process management (implemented)

All process commands operate on process **names** from `[[processes]]` in `ecosystem.toml`.

#### `apm2 list` (alias: `apm2 ls`)

Lists all configured processes and a high-level summary:

- how many instances are configured
- how many instances are currently running
- a coarse status derived from the per-instance state

#### `apm2 status <name>`

Shows detailed information for one configured process:

- the configured command, args, working directory, and instance count
- per-instance state and PID

Note: CPU/memory fields currently display as `0` unless the daemon has been extended to collect metrics.

#### `apm2 start <name>`

Starts **all instances** of the named process.

- Fails if *any* instance of that process is already running.
- If multiple instances are configured, the daemon attempts to start each instance; it reports partial success if some instances fail to spawn.

#### `apm2 stop <name>`

Stops **all running instances** of the named process.

- Sends SIGTERM and waits up to a timeout for graceful exit.
- Escalates to SIGKILL on timeout.

#### `apm2 restart <name>`

Restarts the named process by performing:

1. stop (if running)
2. start

### Commands present in the CLI, but not yet supported by the daemon

These commands exist in `apm2 --help`, but the daemon currently returns a `not_supported` response for their IPC requests.

#### `apm2 reload <name>`

Intended to perform a rolling restart (“reload”), but not implemented yet.

#### `apm2 logs <name> [--lines N] [--follow]`

Intended to tail captured stdout/stderr logs for a process, but not implemented yet.

### Credential commands (scaffolded)

`apm2 creds login` is client-side and prints provider-specific setup hints.

All other `apm2 creds ...` subcommands are designed to be daemon-backed (keyring storage, refresh, hot-swap) but are not wired up yet.

### Factory (agent runner)

#### `apm2 factory run <spec.md> [--format text|json]`

Runs an agent session from a Markdown spec file.

What it does today:

- Reads the spec file (bounded to 1 MiB).
- Builds a prompt that includes the spec text.
- Writes the prompt to a temporary file (avoids giant argv / process listing leakage).
- Spawns the agent adapter (currently the **Claude Code CLI** adapter) and streams events.

This command does **not** require the daemon.

Requirements:

- The `claude` CLI must be installed and available in `PATH` (until other adapters are wired up).

## Concepts (holonic runtime)

- **Holon**: an autonomous unit that is also part of a larger supervisor (“holarchy”).
- **Lease / Budget**: time-bounded, scope-bounded authority with explicit resource limits.
- **Reducer**: a pure event → state transition function used to rebuild projections from the ledger.
- **Work substrate**: the coordination plane built from work objects + an append-only event ledger.

See `documents/skills/glossary/` and `AGENTS.md` for deeper definitions and module-level docs.

## Documentation

- [AGENTS.md](AGENTS.md): architecture + module index
- [CONTRIBUTING.md](CONTRIBUTING.md): development workflow and tooling
- [SECURITY.md](SECURITY.md): vulnerability reporting and security docs pointers
- [documents/](documents/): PRDs, RFCs, security docs, and specs

## Roadmap

This project is pre-1.0; the roadmap is directional and may change.

- Stabilize the `ecosystem.toml` schema and IPC protocol ahead of 1.0
- Ship systemd-oriented operational docs and examples (service unit, directories, permissions)
- Improve crash recovery by wiring up `state_file` snapshots and restore paths
- Expand adapter documentation and ergonomics for custom agents
- Publish signed release artifacts for common Linux targets (x86_64, aarch64)

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) and open an issue/PR.

## Security

Please report vulnerabilities via GitHub Security Advisories. See [SECURITY.md](SECURITY.md).

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.
