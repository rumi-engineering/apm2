# apm2-core

> Core library for APM2 -- provides the foundational types, event-sourced state management, cryptographic primitives, and authority lifecycle infrastructure used by daemon, CLI, and holon crates.

## Overview

`apm2-core` is the largest crate in the APM2 workspace and serves as the shared kernel library. It contains all domain logic for process supervision, credential management, event sourcing, holonic coordination, and security enforcement. The daemon (`apm2-daemon`), CLI (`apm2-cli`), and holon framework (`apm2-holon`) all depend on types and infrastructure defined here.

The crate is organized around several architectural layers:

1. **Foundational primitives** -- cryptography, determinism, time framework, event definitions
2. **Persistence and state** -- append-only ledger, event-sourcing reducers, state snapshots
3. **Process management** -- process lifecycle, supervision, restart policies, health checks, shutdown
4. **Authority and security** -- PCAC authority lifecycle, leases, policy enforcement, capsule containment
5. **Coordination and work** -- session management, work lifecycle, budget enforcement, agent coordination
6. **Pipeline tooling** -- CCP compiler, RFC framing, ticket emission, impact mapping, refactor radar

**Crate path:** `apm2_core`

## Module Map

### Foundational Primitives

| Module | Description | AGENTS.md |
|--------|-------------|-----------|
| `crypto` | Cryptographic primitives (BLAKE3 hashing, Ed25519 signing) for hash-chain integrity and event authentication | [src/crypto/AGENTS.md](src/crypto/AGENTS.md) |
| `determinism` | Primitives for reproducible, crash-safe file output in the compiler pipeline | [src/determinism/AGENTS.md](src/determinism/AGENTS.md) |
| `htf` | Hierarchical Time Framework (RFC-0016) -- consistent time tracking across distributed nodes with uncertainty and authority | -- |
| `events` | Protocol Buffer-based kernel event types for the event-sourced architecture | [src/events/AGENTS.md](src/events/AGENTS.md) |
| `channel` | Channel boundary enforcement primitives -- fail-closed channel classification preventing non-authoritative actuation inputs | -- |

### Persistence and State

| Module | Description | AGENTS.md |
|--------|-------------|-----------|
| `ledger` | Append-only event ledger with SQLite WAL storage and cryptographic hash chaining | [src/ledger/AGENTS.md](src/ledger/AGENTS.md) |
| `reducer` | Event-sourcing reducer framework for deterministic state projection from the append-only ledger | [src/reducer/AGENTS.md](src/reducer/AGENTS.md) |
| `state` | Persists daemon and process state to disk for crash recovery and restart resilience | [src/state/AGENTS.md](src/state/AGENTS.md) |
| `schema_registry` | Distributed schema governance with fail-closed validation for the consensus layer | [src/schema_registry/AGENTS.md](src/schema_registry/AGENTS.md) |
| `orchestrator_kernel` | Cursor-generic Observe-Plan-Execute-Receipt control loop harness reusable across daemon orchestrators. Cursor type is determined by each `LedgerReader` via the `KernelCursor` trait; `CompositeCursor` is the default for timestamp+id ledgers. | -- |

### Process Management

| Module | Description | AGENTS.md |
|--------|-------------|-----------|
| `process` | Process lifecycle management -- spawning, monitoring, controlled shutdown of agent processes | [src/process/AGENTS.md](src/process/AGENTS.md) |
| `supervisor` | Process collection lifecycle management with restart policies and graceful shutdown | [src/supervisor/AGENTS.md](src/supervisor/AGENTS.md) |
| `restart` | Restart policy configuration with backoff strategies and circuit breaker protection | [src/restart/AGENTS.md](src/restart/AGENTS.md) |
| `health` | Health check infrastructure for monitoring managed process liveness and responsiveness | [src/health/AGENTS.md](src/health/AGENTS.md) |
| `shutdown` | Graceful shutdown coordination with signal handling and timeout-based force kill | [src/shutdown/AGENTS.md](src/shutdown/AGENTS.md) |
| `liveness` | Launch liveness heartbeat and bounded restart policy primitives (RFC-0020) | -- |

### Authority, Security, and Policy

| Module | Description | AGENTS.md |
|--------|-------------|-----------|
| `pcac` | Proof-Carrying Authority Continuity (RFC-0027) -- authority lifecycle contract (join, revalidate, consume, effect) | -- |
| `crypto` | (See Foundational) BLAKE3 + Ed25519 underpinning for all signed authority artifacts | [src/crypto/AGENTS.md](src/crypto/AGENTS.md) |
| `policy` | Policy DSL parser -- default-deny rules governing agent tool access and resource permissions | -- |
| `capsule` | Agent capsule containment (RFC-0020 Section 4) -- linux-ns-v1 profile for no-ambient-authority enforcement | -- |
| `governance` | Governance control-plane messages and authorization types for cross-cell stop, rotation, and ratchet (RFC-0020) | -- |
| `fac` | Forge Admission Cycle -- CI attestation, domain separators, quality gate validation for merge governance | -- |
| `continuity` | Business continuity types -- drill receipts, stop-path SLO enforcement, RPO/RTO tracking (RFC-0020 Section 11) | -- |

### Credentials and Configuration

| Module | Description | AGENTS.md |
|--------|-------------|-----------|
| `credentials` | Secure storage, retrieval, and hot-swapping of credentials for AI CLI tools | [src/credentials/AGENTS.md](src/credentials/AGENTS.md) |
| `config` | Configuration parsing and management for ecosystem files (TOML/JSON) | [src/config/AGENTS.md](src/config/AGENTS.md) |
| `log` | Log management, rotation, streaming, and secret redaction for managed processes | [src/log/AGENTS.md](src/log/AGENTS.md) |

### Coordination and Work

| Module | Description | AGENTS.md |
|--------|-------------|-----------|
| `session` | Event-sourced session lifecycle state machine with entropy-based health monitoring and crash recovery | [src/session/AGENTS.md](src/session/AGENTS.md) |
| `work` | Event-sourced work lifecycle management with reducer-based state projection | [src/work/AGENTS.md](src/work/AGENTS.md) |
| `lease` | Lease registrar for work item ownership tracking with at-most-one exclusive claim semantics | [src/lease/AGENTS.md](src/lease/AGENTS.md) |
| `budget` | Resource budget enforcement for session limits implementing default-deny, fail-closed semantics | [src/budget/AGENTS.md](src/budget/AGENTS.md) |
| `coordination` | Agent coordination layer for autonomous work loop execution with circuit breaker protection | -- |
| `economics` | Canonical economics profiles and deterministic budget admission (RFC-0029 REQ-0001) | -- |
| `context` | File access control via context pack manifests (OCAP allowlist) and context firewall middleware | -- |

### Agent and Tool Communication

| Module | Description | AGENTS.md |
|--------|-------------|-----------|
| `agent` | Agent module guidelines and conventions | [src/agent/AGENTS.md](src/agent/AGENTS.md) |
| `adapter` | Normalizes heterogeneous agent runtimes into a common event contract for unified supervision | [src/adapter/AGENTS.md](src/adapter/AGENTS.md) |
| `tool` | Protocol Buffers-based agent-kernel communication protocol with default-deny, least-privilege, fail-closed security | [src/tool/AGENTS.md](src/tool/AGENTS.md) |
| `syscall` | Syscall mediation layer bridging tool requests to host system execution | -- |
| `webhook` | GitHub webhook handler for CI completion events with HMAC-SHA256 signature validation | [src/webhook/AGENTS.md](src/webhook/AGENTS.md) |
| `github` | Tiered GitHub App access control for holonic agents with capability-bound, auditable token management | [src/github/AGENTS.md](src/github/AGENTS.md) |
| `model_router` | Multi-model orchestration with configurable routing profiles and fail-closed fallback | -- |

### Pipeline Tooling (CCP Compiler Stack)

| Module | Description | AGENTS.md |
|--------|-------------|-----------|
| `ccp` | Code Context Protocol -- semantic codebase discovery, component atlas, and AGENTS.md parsing | -- |
| `cac` | Context-as-Code (CAC) v1 validation infrastructure for context artifacts | [src/cac/AGENTS.md](src/cac/AGENTS.md) |
| `bootstrap` | Embedded bootstrap schema bundle forming the CAC trust root | [src/bootstrap/AGENTS.md](src/bootstrap/AGENTS.md) |
| `impact_map` | Impact mapping for change analysis and dependency tracing | [src/impact_map/AGENTS.md](src/impact_map/AGENTS.md) |
| `rfc_framer` | RFC skeleton generation from Impact Map and CCP with cryptographic proof of CCP state | -- |
| `ticket_emitter` | Decomposes RFCs into atomic implementation tickets with stable IDs and verified file paths | -- |
| `refactor_radar` | Aggregates CCP signals (hotspots, duplication, complexity) into prioritized maintenance recommendations | -- |
| `run_manifest` | Cryptographically signed pipeline execution records with input/output hashes and routing decisions | -- |

### Consensus and Distribution

| Module | Description | AGENTS.md |
|--------|-------------|-----------|
| `consensus` | Network transport and peer discovery for the distributed consensus layer | [src/consensus/AGENTS.md](src/consensus/AGENTS.md) |
| `evidence` | Content-addressed artifact storage with integrity verification and progressive disclosure | [src/evidence/AGENTS.md](src/evidence/AGENTS.md) |

## Architecture

### Layer Diagram

```
                         apm2-cli        apm2-daemon
                            |                |
                            +-------+--------+
                                    |
                                apm2-core
                                    |
            +-----------+-----------+-----------+-----------+
            |           |           |           |           |
     Foundational   Persistence   Process    Authority   Coordination
     Primitives     & State       Mgmt       & Security  & Work
            |           |           |           |           |
         crypto      ledger      process      pcac       session
         events      reducer     supervisor   policy     work
         htf         state       restart      capsule    lease
         determinism schema_reg  health       fac        budget
         channel                 shutdown     governance coordination
                                 liveness     continuity economics
                                                         context
```

### Dependency Flow

Modules follow a strict layering where higher-level modules depend on lower-level ones, never the reverse:

1. **Foundational** (`crypto`, `events`, `determinism`, `htf`, `channel`) -- no internal dependencies
2. **Persistence** (`ledger`, `reducer`, `state`) -- depends on `crypto`, `events`
3. **Process Management** (`process`, `supervisor`, `restart`, `health`, `shutdown`) -- depends on `config`, `state`
4. **Authority** (`pcac`, `policy`, `capsule`, `fac`, `governance`) -- depends on `crypto`, `events`, `ledger`
5. **Coordination** (`session`, `work`, `lease`, `budget`, `coordination`) -- depends on `events`, `ledger`, `reducer`
6. **Pipeline Tooling** (`ccp`, `cac`, `rfc_framer`, `ticket_emitter`, `impact_map`, `refactor_radar`, `run_manifest`, `bootstrap`) -- depends on `crypto`, `determinism`
7. **Integration** (`adapter`, `tool`, `syscall`, `webhook`, `github`, `model_router`) -- depends on various layers

### Event Sourcing Flow

The core architectural pattern is event sourcing through the ledger and reducer stack:

```
  Agent Action
       |
       v
  Tool/Syscall Request
       |
       v
  Policy Check (default-deny)
       |
       v
  Event Emitted -----> Ledger (append-only, hash-chained)
       |                    |
       v                    v
  Side Effect           Reducer Replay
  (if authorized)           |
                            v
                     Projected State
                     (session, work, lease)
```

## Key Architectural Patterns

### Event Sourcing via Ledger + Reducer

All kernel state is derived from an append-only event ledger. The `ledger` module stores hash-chained, optionally signed events in SQLite WAL mode. The `reducer` module provides a framework for deterministic state projection by replaying events in order. Domain modules (`session`, `work`, `lease`) each implement their own reducer to project domain-specific views.

### Content-Addressed Storage

The `evidence` module provides content-addressed artifact storage using BLAKE3 hashes. Artifacts are stored by their content hash, enabling deduplication, integrity verification, and progressive disclosure patterns. The `cac` module extends this to Context-as-Code artifacts with validation against the `bootstrap` trust root.

### PCAC Authority Lifecycle

Proof-Carrying Authority Continuity (RFC-0027) gates all authority-bearing side effects through a linear consumption protocol:

1. **Join**: Compute admissible authority from inputs, producing an Authority Join Certificate (AJC)
2. **Revalidate**: Verify the AJC remains valid (freshness, revocation checks)
3. **Consume**: One-time consumption of the AJC to authorize a specific side effect
4. **Effect**: Execute the authorized side effect

Each step produces a cryptographic receipt. The AJC is single-use (linear consumption), and all steps enforce fail-closed semantics.

### Holonic Boundaries

Agents operate within holonic boundaries (Principia Holonica) where:

- **Markov Blanket** (Axiom I): Each holon has a clear boundary defined by its trait contract (`apm2-holon`)
- **Bounded Authority** (Axiom III): Leases constrain operations, time, and resource consumption
- **Capsule Containment**: Linux namespace isolation enforces no-ambient-authority (RFC-0020)
- Work flows through `intake -> execute_episode -> emit_artifact -> escalate` lifecycle

### Default-Deny, Fail-Closed Security

Throughout the crate, security follows a consistent pattern:

- **Tool access**: Denied unless explicitly permitted by policy
- **Budget enforcement**: Operations fail when any budget dimension is exhausted
- **Schema validation**: Unknown fields rejected (`deny_unknown_fields`)
- **Channel classification**: Non-authoritative actuation inputs rejected at boundary
- **Lease scope**: Empty permission sets mean "no access", not "unlimited"

## Crate-Level Invariants

- **[INV-CORE-001] Deterministic reducers**: All reducer implementations must produce identical state given identical event sequences. No randomness, no wall-clock reads during replay.
- **[INV-CORE-002] Hash-chain integrity**: Every event appended to the ledger must include the hash of the preceding event. Breaking the chain is a hard error.
- **[INV-CORE-003] Fail-closed security**: Missing configuration, unknown fields, expired leases, and exhausted budgets all result in denial, never silent permissiveness.
- **[INV-CORE-004] Linear authority consumption**: Authority Join Certificates (AJCs) authorize at most one side effect. Re-use is a hard error.
- **[INV-CORE-005] Monotonic version counters**: State objects (work, session, lease) use monotonically increasing version numbers for optimistic concurrency. Versions never decrease.
- **[INV-CORE-006] Saturating arithmetic for budgets**: Budget deductions use `saturating_sub` to prevent underflow. Exhaustion is permanent once reached.
- **[INV-CORE-007] No path traversal**: Namespace and file path validation rejects `..` sequences unconditionally, even for unlimited-scope leases.
- **[INV-CORE-008] Proto event evolution**: Protobuf-generated event types (in `events`) may add fields and enum variants across versions. This is standard proto evolution and these types are internal to the kernel. Public-facing library APIs must not use these relaxed semver rules.

## Build and Features

### Build Script

The build script (`build.rs`) compiles Protocol Buffer definitions and generates the bootstrap schema manifest:

- **Proto compilation**: `kernel_events.proto` and `tool_protocol.proto` are compiled via `prost-build` with `BTreeMap` for deterministic ordering and additional `Eq`/`Hash` derives
- **Bootstrap manifest**: Generates a content-addressed schema manifest from the `bootstrap/` directory, embedding BLAKE3 hashes at compile time

### Cargo Features

| Feature | Description |
|---------|-------------|
| `default` | No features enabled by default |
| `test-utils` | Enables test utilities for deterministic testing (e.g., `MockHolon`, clock injection) |
| `test_vectors` | Enables canonicalization test vectors for cross-platform verification |
| `clap-introspection` | Enables clap dependency for CLI command enumeration |
| `yubihsm` | Enables YubiHSM hardware support for T1 validator keys; without this, `YubiHsmProvider` operates in mock mode |

### Conditional Compilation

- **`cfg(unix)`**: `libc` dependency for TOCTOU mitigation via `O_NOFOLLOW`
- **`cfg(target_os = "linux")`**: `seccompiler` dependency for syscall sandboxing
- **`cfg(test)`**: Allows `clippy::large_stack_arrays` for schema registry handshake limit testing

### Lints

The crate enables `warn(missing_docs)`, `warn(clippy::all)`, and `warn(clippy::pedantic)`. All public items require documentation.

### Benchmarks

| Benchmark | File |
|-----------|------|
| `supervisor_benchmarks` | `benches/supervisor_benchmarks.rs` |
| `shutdown_benchmarks` | `benches/shutdown_benchmarks.rs` |
| `spawn_benchmarks` | `benches/spawn_benchmarks.rs` |
| `state_benchmarks` | `benches/state_benchmarks.rs` |
| `hotswap_benchmarks` | `benches/hotswap_benchmarks.rs` |

## Prelude and Re-exports

The crate provides a `prelude` module and root-level re-exports for commonly used types:

```rust
// Prelude imports
pub use crate::config::EcosystemConfig;
pub use crate::credentials::{AuthMethod, CredentialProfile, Provider};
pub use crate::process::{ProcessHandle, ProcessSpec, ProcessState};
pub use crate::restart::RestartConfig;
pub use crate::supervisor::Supervisor;
```

## Related Crates

| Crate | Relationship | AGENTS.md |
|-------|-------------|-----------|
| `apm2-daemon` | Consumes `apm2-core` types for daemon runtime -- supervisor, shared state, IPC handlers | [crates/apm2-daemon/AGENTS.md](../apm2-daemon/AGENTS.md) |
| `apm2-cli` | Consumes `apm2-core` types for CLI argument parsing and IPC client formatting | [crates/apm2-cli/AGENTS.md](../apm2-cli/AGENTS.md) |
| `apm2-holon` | Defines the `Holon` trait contract surface; no runtime dependency on `apm2-core` | [crates/apm2-holon/AGENTS.md](../apm2-holon/AGENTS.md) |
