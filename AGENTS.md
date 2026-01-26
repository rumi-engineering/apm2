# APM2 - Holonic AI Process Manager

**Version:** 0.3.0 | **Edition:** 2024 | **MSRV:** 1.85

APM2 is a process supervision framework for orchestrating heterogeneous AI agents through holonic coordination, event-sourced state management, and capability-based resource control.

| Crate | Description | LOC (approx) |
|-------|-------------|--------------|
| `apm2-holon` | Holon trait, resource types, work lifecycle | ~4,500 |
| `apm2-core` | Daemon runtime, reducers, adapters, evidence | ~35,000 |
| `apm2-daemon` | Unix socket server, IPC handlers | ~1,000 |
| `apm2-cli` | Command-line interface | ~1,200 |
| `xtask` | Development automation | ~2,000 |

## Table of Contents

- [Architectural Overview](#architectural-overview)
- [Technology Stack](#technology-stack)
- [Documentation Convention](#documentation-convention)
- [Module Index](#module-index)
- [Type Glossary](#type-glossary)
- [Security](#security)

---

## Architectural Overview

APM2 implements a four-layer runtime: CLI communicates over Unix domain sockets with a persistent daemon, which supervises agent processes through adapter abstractions.

The **CLI** (`apm2-cli`) serializes JSON requests to the **daemon** (`apm2-daemon`), which maintains in-memory state projections derived from an append-only event ledger. **Agent processes** (Claude Code, Gemini CLI, Codex CLI, or custom agents) are observed through the adapter layer.

Three architectural patterns pervade the implementation:

1. **Event Sourcing**: All state changes are recorded as immutable events in a SQLite-backed ledger with WAL mode. State is reconstructed by replaying events through reducer functions.

2. **Reducer Pattern**: State transitions are computed by pure functions (`Reducer::apply`) that take an event and current state, returning the next state.

3. **Content-Addressed Storage**: Evidence artifacts are stored by BLAKE3 hash in a CAS layer, providing deduplication, integrity verification, and progressive disclosure.

The crate dependency graph flows downward: `apm2-cli` and `apm2-daemon` depend on `apm2-core`, which depends on `apm2-holon`. The holon crate has no dependencies on core runtime infrastructure, establishing a clean contract boundary.

---

## Technology Stack

### Language & Toolchain

| Component | Version | Notes |
|-----------|---------|-------|
| **Rust** | 2024 edition | MSRV 1.85 |
| **Cargo** | Workspace | Multi-crate monorepo |
| **Clippy** | pedantic + nursery | Strict linting |

### Runtime & Async

| Crate | Purpose |
|-------|---------|
| [tokio](https://tokio.rs/) | Async runtime (full features) |
| [tracing](https://tracing.rs/) | Structured logging and diagnostics |
| [tracing-subscriber](https://docs.rs/tracing-subscriber/) | Log formatting and filtering |

### Serialization & Protocol

| Crate | Purpose |
|-------|---------|
| [serde](https://serde.rs/) | Serialization framework |
| [serde_json](https://docs.rs/serde_json/) | JSON serialization (IPC protocol) |
| [toml](https://docs.rs/toml/) | Configuration files |
| [serde_yaml](https://docs.rs/serde_yaml/) | YAML parsing (skills, tickets) |
| [prost](https://docs.rs/prost/) | Protocol Buffers (event schema) |

### Persistence

| Crate | Purpose |
|-------|---------|
| [rusqlite](https://docs.rs/rusqlite/) | SQLite database (WAL mode) |
| [blake3](https://docs.rs/blake3/) | Content-addressed storage hashing |

### Cryptography & Security

| Crate | Purpose |
|-------|---------|
| [blake3](https://docs.rs/blake3/) | Fast cryptographic hashing (CAS) |
| [ed25519-dalek](https://docs.rs/ed25519-dalek/) | Ed25519 signatures (event signing) |
| [keyring](https://docs.rs/keyring/) | OS keychain integration |
| [secrecy](https://docs.rs/secrecy/) | Secret value handling |
| [zeroize](https://docs.rs/zeroize/) | Secure memory zeroing |

### CLI & IPC

| Crate | Purpose |
|-------|---------|
| [clap](https://docs.rs/clap/) | Command-line argument parsing |
| [nix](https://docs.rs/nix/) | Unix APIs (signals, fork, sockets) |
| [chrono](https://docs.rs/chrono/) | Date/time handling |

### Testing & Quality

| Crate | Purpose |
|-------|---------|
| [proptest](https://docs.rs/proptest/) | Property-based testing |
| [criterion](https://docs.rs/criterion/) | Benchmarking |
| [tempfile](https://docs.rs/tempfile/) | Temporary file fixtures |

### Wire Protocols

**IPC Protocol** (CLI ↔ Daemon): Length-prefixed JSON over Unix domain sockets. See [`apm2_core::ipc`](crates/apm2-core/src/ipc/AGENTS.md).

**Event Schema**: Protocol Buffers via prost for the append-only event ledger. Canonical encoding ensures deterministic signatures. See [`proto/kernel_events.proto`](proto/kernel_events.proto).

**Tool Protocol**: Protocol Buffers for agent-to-kernel tool requests. Default-deny, least-privilege enforcement. See [`proto/tool_protocol.proto`](proto/tool_protocol.proto).

---

## Documentation Convention

Each module contains an `AGENTS.md` file providing AI-agent-optimized documentation with:

- **Overview**: Module purpose and architectural context
- **Key Types**: Rust type definitions with field documentation
- **Invariants**: Tagged as `[INV-XXXX]` - properties that must always hold
- **Contracts**: Tagged as `[CTR-XXXX]` - pre/post conditions for operations
- **Public API**: Primary functions and methods
- **Examples**: Usage patterns and code samples
- **Related Modules**: Cross-references to dependent modules
- **References**: Links to external specifications

See individual `AGENTS.md` files linked in the Module Index below for detailed documentation.

---

## Module Index

### apm2-holon

| Module | Description | Documentation |
|--------|-------------|---------------|
| `apm2_holon::traits` | `Holon` trait definition | [AGENTS.md](crates/apm2-holon/AGENTS.md) |
| `apm2_holon::context` | `EpisodeContext` for bounded execution | [AGENTS.md](crates/apm2-holon/AGENTS.md) |
| `apm2_holon::result` | `EpisodeResult` and `EpisodeOutcome` | [AGENTS.md](crates/apm2-holon/AGENTS.md) |
| `apm2_holon::stop` | `StopCondition` enumeration | [AGENTS.md](crates/apm2-holon/AGENTS.md) |
| `apm2_holon::artifact` | `Artifact` type for evidence | [AGENTS.md](crates/apm2-holon/AGENTS.md) |
| `apm2_holon::error` | `HolonError` error type | [AGENTS.md](crates/apm2-holon/AGENTS.md) |
| `apm2_holon::work` | `WorkObject`, `WorkLifecycle`, `AttemptRecord` | [AGENTS.md](crates/apm2-holon/AGENTS.md) |
| `apm2_holon::resource` | `Budget`, `Lease`, `LeaseScope` | [AGENTS.md](crates/apm2-holon/AGENTS.md) |
| `apm2_holon::skill` | Skill frontmatter parsing | [AGENTS.md](crates/apm2-holon/AGENTS.md) |

### apm2-core

| Module | Description | Documentation |
|--------|-------------|---------------|
| `apm2_core::adapter` | Agent adapter abstractions | [AGENTS.md](crates/apm2-core/src/adapter/AGENTS.md) |
| `apm2_core::config` | Ecosystem configuration | [AGENTS.md](crates/apm2-core/src/config/AGENTS.md) |
| `apm2_core::credentials` | Credential profiles and stores | [AGENTS.md](crates/apm2-core/src/credentials/AGENTS.md) |
| `apm2_core::crypto` | Cryptographic primitives | [AGENTS.md](crates/apm2-core/src/crypto/AGENTS.md) |
| `apm2_core::events` | Event type definitions | [AGENTS.md](crates/apm2-core/src/events/AGENTS.md) |
| `apm2_core::evidence` | Evidence publishing and CAS | [AGENTS.md](crates/apm2-core/src/evidence/AGENTS.md) |
| `apm2_core::health` | Health check configurations | [AGENTS.md](crates/apm2-core/src/health/AGENTS.md) |
| `apm2_core::ipc` | IPC protocol types | [AGENTS.md](crates/apm2-core/src/ipc/AGENTS.md) |
| `apm2_core::lease` | Lease management runtime | [AGENTS.md](crates/apm2-core/src/lease/AGENTS.md) |
| `apm2_core::ledger` | Append-only event ledger | [AGENTS.md](crates/apm2-core/src/ledger/AGENTS.md) |
| `apm2_core::log` | Structured logging | [AGENTS.md](crates/apm2-core/src/log/AGENTS.md) |
| `apm2_core::process` | Process lifecycle management | [AGENTS.md](crates/apm2-core/src/process/AGENTS.md) |
| `apm2_core::reducer` | Reducer trait and implementations | [AGENTS.md](crates/apm2-core/src/reducer/AGENTS.md) |
| `apm2_core::restart` | Restart policies and backoff | [AGENTS.md](crates/apm2-core/src/restart/AGENTS.md) |
| `apm2_core::session` | Session lifecycle | [AGENTS.md](crates/apm2-core/src/session/AGENTS.md) |
| `apm2_core::shutdown` | Graceful shutdown coordination | [AGENTS.md](crates/apm2-core/src/shutdown/AGENTS.md) |
| `apm2_core::state` | Global state aggregation | [AGENTS.md](crates/apm2-core/src/state/AGENTS.md) |
| `apm2_core::supervisor` | Process collection supervisor | [AGENTS.md](crates/apm2-core/src/supervisor/AGENTS.md) |
| `apm2_core::tool` | Tool request protocol | [AGENTS.md](crates/apm2-core/src/tool/AGENTS.md) |
| `apm2_core::work` | Work queue management | [AGENTS.md](crates/apm2-core/src/work/AGENTS.md) |

### apm2-daemon

| Module | Description | Documentation |
|--------|-------------|---------------|
| `apm2_daemon::state` | Thread-safe shared daemon state | [AGENTS.md](crates/apm2-daemon/AGENTS.md) |
| `apm2_daemon::ipc_server` | Unix socket server, framing | [AGENTS.md](crates/apm2-daemon/AGENTS.md) |
| `apm2_daemon::handlers` | IPC request handlers | [AGENTS.md](crates/apm2-daemon/AGENTS.md) |

### apm2-cli

| Module | Description | Documentation |
|--------|-------------|---------------|
| `apm2_cli::commands::daemon` | Daemon lifecycle commands | [AGENTS.md](crates/apm2-cli/AGENTS.md) |
| `apm2_cli::commands::process` | Process management commands | [AGENTS.md](crates/apm2-cli/AGENTS.md) |
| `apm2_cli::commands::creds` | Credential management commands | [AGENTS.md](crates/apm2-cli/AGENTS.md) |

---

## Type Glossary

| Type | Module | Description |
|------|--------|-------------|
| `Artifact` | `apm2_holon::artifact` | Evidence artifact with content hash |
| `AttemptRecord` | `apm2_holon::work` | Record of attempt execution |
| `BackoffConfig` | `apm2_core::restart` | Backoff strategy (Fixed/Exponential/Linear) |
| `BlackBoxAdapter` | `apm2_core::adapter` | Observation-based agent adapter |
| `Budget` | `apm2_holon::resource` | Four-dimensional resource limits |
| `ContentAddressedStore` | `apm2_core::evidence` | CAS trait for artifact storage |
| `CredentialProfile` | `apm2_core::credentials` | Credential configuration |
| `DataClassification` | `apm2_core::evidence` | Data sensitivity level |
| `EpisodeContext` | `apm2_holon::context` | Execution context for episodes |
| `EpisodeResult` | `apm2_holon::result` | Episode execution result |
| `EventRecord` | `apm2_core::ledger` | Ledger event with hash chain |
| `Holon` | `apm2_holon::traits` | Core agent trait |
| `HolonError` | `apm2_holon::error` | Holon operation errors |
| `Lease` | `apm2_holon::resource` | Time-bounded authorization |
| `LeaseScope` | `apm2_holon::resource` | Authority boundaries |
| `Ledger` | `apm2_core::ledger` | Append-only event store |
| `ProcessSpec` | `apm2_core::process` | Process configuration |
| `ProcessState` | `apm2_core::process` | Process lifecycle state |
| `Reducer` | `apm2_core::reducer` | Event application trait |
| `RestartConfig` | `apm2_core::restart` | Restart policy configuration |
| `SessionState` | `apm2_core::session` | Session lifecycle state |
| `StopCondition` | `apm2_holon::stop` | Episode termination predicate |
| `Supervisor` | `apm2_core::supervisor` | Process collection manager |
| `ToolRequest` | `apm2_core::tool` | Agent tool invocation |
| `WorkLifecycle` | `apm2_holon::work` | Work state machine |
| `WorkObject` | `apm2_holon::work` | Tracked work unit |
| `DaemonStateHandle` | `apm2_daemon::state` | Thread-safe daemon state wrapper |
| `SharedState` | `apm2_daemon::state` | Type alias for `Arc<DaemonStateHandle>` |
| `RunnerKey` | `apm2_daemon::state` | Composite key: `(ProcessId, instance)` |
| `Cli` | `apm2_cli` | Top-level CLI argument parser |
| `Commands` | `apm2_cli` | Primary command enum |
| `CredsCommands` | `apm2_cli::commands::creds` | Credential subcommands |

---

## Security

Security documentation is maintained in [`documents/security/`](documents/security/):

| Document | Description |
|----------|-------------|
| [SECURITY.md](SECURITY.md) | Vulnerability reporting and security contacts |
| [SECURITY_POLICY.md](documents/security/SECURITY_POLICY.md) | Security policies and compliance requirements |
| [THREAT_MODEL.md](documents/security/THREAT_MODEL.md) | Threat analysis and attack surface documentation |
| [SECRETS_MANAGEMENT.md](documents/security/SECRETS_MANAGEMENT.md) | Credential handling and secret storage |
| [CI_SECURITY_GATES.md](documents/security/CI_SECURITY_GATES.md) | CI/CD security checks and gates |
| [SIGNING_AND_VERIFICATION.md](documents/security/SIGNING_AND_VERIFICATION.md) | Release signing and artifact verification |
| [RELEASE_PROCEDURE.md](documents/security/RELEASE_PROCEDURE.md) | Secure release process |
| [INCIDENT_RESPONSE.md](documents/security/INCIDENT_RESPONSE.md) | Security incident handling procedures |

For security vulnerability reports, see [SECURITY.md](SECURITY.md).

---

## License

Licensed under either of:
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.
