# APM2

Process supervision for AI agent CLIs (Claude Code, Gemini CLI, Codex CLI, and custom tools).

[![CI](https://github.com/Anveio/apm2/actions/workflows/ci.yml/badge.svg)](https://github.com/Anveio/apm2/actions/workflows/ci.yml)
[![Rust 1.85+](https://img.shields.io/badge/rust-1.85%2B-blue.svg)](https://www.rust-lang.org)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-MIT)

APM2 runs as a local daemon that supervises agent processes with restart policies, credential hot-swapping, and an event-sourced ledger for audit and replay.

**Status:** pre-1.0 (expect breaking changes).

## Features

- Supervise processes with instances, restart/backoff, and graceful shutdown
- Unix socket IPC between `apm2` (CLI) and `apm2-daemon` (daemon)
- Credential profiles backed by the OS keyring (hot-swappable per process)
- Event-sourced state (append-only SQLite ledger)
- Spec-driven “factory” workflows (`apm2 factory ...`) for orchestrating agent work

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
apm2 logs claude --follow
```

## Configuration

APM2 reads `ecosystem.toml` by default (override with `--config <path>`).

- `[daemon]`: PID/socket paths (defaults to `/var/run/apm2/...`), plus audit settings
- `[[credentials]]`: credential profiles (stored in the OS keyring)
- `[[processes]]`: supervised processes (command, args, env, instances, restart/log/shutdown policies)

See `ecosystem.example.toml` for a full annotated example.

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
