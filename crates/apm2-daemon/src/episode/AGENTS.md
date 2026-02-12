# Episode Module

> Daemon-layer episode runtime managing bounded execution episodes for agent processes.

## Overview

The `episode` module is the largest module in `apm2-daemon`. It implements the authoritative plant controller for daemon-hosted episodes per AD-LAYER-001. An episode is a bounded execution unit with an immutable envelope, resource budget, capability manifest, and state machine governing its lifecycle. The module provides:

- **Episode envelope and budget**: Immutable configuration with deterministic canonical bytes
- **State machine**: `CREATED -> RUNNING -> TERMINATED | QUARANTINED`
- **Harness adapters**: Abstraction over agent processes (Claude Code, Codex CLI, Raw)
- **Tool broker**: Capability-validated tool execution with deduplication
- **Budget tracking**: Per-episode resource accounting (tokens, tool calls, time, I/O)
- **Workspace management**: File change validation and artifact bundling
- **Pre-actuation gate**: Stop-condition evaluation before side effects
- **Path ratchet**: No-bypass enforcement for filesystem path restrictions
- **Crash recovery**: Session/episode state reconstruction after daemon restart

### State Machine (AD-EPISODE-002)

```text
CREATED ──────> RUNNING ──────> TERMINATED
                   |
                   └──────────> QUARANTINED
```

## Key Types

### `EpisodeRuntime`

Daemon-layer runtime managing episode lifecycle. Owns process lifetime, enforces budgets, emits kernel events.

**Invariants:**

- [INV-EP01] Maximum concurrent episodes is bounded (`MAX_CONCURRENT_EPISODES = 10,000`).
- [INV-EP02] All state transitions emit `EpisodeEvent` entries.
- [INV-EP03] Terminal states (TERMINATED, QUARANTINED) have no outgoing transitions.
- [INV-EP04] Episode IDs are unique within the runtime.

### `EpisodeState`

```rust
pub enum EpisodeState {
    Created,
    Running,
    Terminated { class: TerminationClass },
    Quarantined { reason: QuarantineReason },
}
```

**Invariants:**

- [INV-EP05] No transitions from TERMINATED or QUARANTINED.
- [INV-EP06] State timestamps are monotonically increasing.

### `EpisodeEnvelope` / `EpisodeEnvelopeV1`

Immutable episode configuration with deterministic canonical bytes and content-addressed digest. Built via `EpisodeEnvelopeBuilder`.

**Invariants:**

- [INV-EP07] Envelope is immutable after construction.
- [INV-EP08] `canonical_bytes()` produces deterministic output for signing.

### `EpisodeBudget`

```rust
pub struct EpisodeBudget { /* token limit, tool call limit, wall-clock timeout, I/O bounds */ }
```

Resource limits for an episode, built via `EpisodeBudgetBuilder`.

### `ToolBroker`

Capability-validated tool execution broker. Validates requests against the capability manifest, checks policy, and routes to the appropriate `ToolHandler`.

**Invariants:**

- [INV-EP09] Tool requests are denied if the capability manifest does not grant access.
- [INV-EP10] Policy decisions are logged for audit.

**Contracts:**

- [CTR-EP01] Broker validates capability before invoking any handler.
- [CTR-EP02] Deduplicated requests return cached results without re-execution.

### `CapabilityManifest` / `Capability`

Defines what tools and resources an episode is authorized to use. Capabilities are minted by the governance layer via `PolicyMintToken` (not publicly exported).

**Invariants:**

- [INV-EP11] `PolicyMintToken` is `pub(crate)` only; external crates cannot mint capabilities.
- [INV-EP12] Capability manifests are bounded (`MAX_CAPABILITIES`).

### `BudgetTracker`

Per-episode resource accounting. Tracks consumed tokens, tool calls, wall-clock time, and I/O bytes.

**Contracts:**

- [CTR-EP03] `charge()` returns `BudgetExhaustedError` when any limit is reached.
- [CTR-EP04] Budget snapshots are monotonically increasing.

### `PreActuationGate`

Evaluates stop conditions before side effects are permitted. Implements pre-actuation denial when budget is near exhaustion or stop conditions are met.

**Contracts:**

- [CTR-EP05] Pre-actuation denial prevents side effects when budget is exhausted.
- [CTR-EP06] Replay verification detects tool result tampering.

### `HarnessAdapter` (trait)

```rust
pub trait HarnessAdapter: Send + Sync {
    fn adapter_type(&self) -> AdapterType;
    async fn start(&mut self, config: HarnessConfig) -> AdapterResult<HarnessHandle>;
    async fn stop(&mut self, handle: &HarnessHandle) -> AdapterResult<()>;
}
```

Abstraction over agent process types. Implementations: `ClaudeCodeAdapter`, `CodexCliAdapter`, `RawAdapter`.

### `AdapterRegistry`

Manages harness adapter instances and session lifecycle with persistent backing and TTL eviction.

### `TerminationClass`

```rust
pub enum TerminationClass {
    Success, Failure, BudgetExhausted, Timeout, Cancelled, Crashed, Killed,
}
```

### `PathRatchet`

No-bypass enforcement for filesystem path restrictions per TCK-00376.

**Invariants:**

- [INV-EP13] Once a path restriction is ratcheted, it cannot be relaxed.

## Public API

Key re-exports from submodules:

- `EpisodeRuntime`, `EpisodeEvent`, `EpisodeRuntimeConfig`, `new_shared_runtime`
- `EpisodeEnvelope`, `EpisodeEnvelopeBuilder`, `EpisodeBudget`, `EpisodeBudgetBuilder`
- `ToolBroker`, `SharedToolBroker`, `ToolBrokerConfig`, `new_shared_broker`
- `CapabilityManifest`, `Capability`, `CapabilityValidator`
- `BudgetTracker`, `BudgetSnapshot`, `BudgetExhaustedError`
- `PreActuationGate`, `PreActuationReceipt`, `StopConditionEvaluator`
- `HarnessAdapter`, `AdapterRegistry`, `ClaudeCodeAdapter`, `CodexCliAdapter`, `RawAdapter`
- `WorkspaceManager`, `WorkspaceSnapshot`, `ReviewCompletionResult`
- `PathRatchet`, `PathRatchetError`
- `SessionHandle`, `EpisodeState`, `TerminationClass`, `QuarantineReason`

## Related Modules

- [`apm2_daemon::session`](../session/AGENTS.md) -- Session management and state registry
- [`apm2_daemon::evidence`](../evidence/AGENTS.md) -- Tool receipts and evidence artifacts
- [`apm2_daemon::telemetry`](../telemetry/AGENTS.md) -- Per-episode resource telemetry
- [`apm2_daemon::protocol`](../protocol/AGENTS.md) -- IPC dispatch for episode control
- [`apm2_daemon::pcac`](../pcac/AGENTS.md) -- PCAC lifecycle gate for tool authority
- [`apm2_daemon::cas`](../cas/AGENTS.md) -- Content-addressed store for artifacts

## References

- AD-EPISODE-001: Immutable episode envelope
- AD-EPISODE-002: Session state machine
- AD-LAYER-001: `EpisodeRuntime` extends `EpisodeController`
- AD-VERIFY-001: Deterministic Protobuf serialization
- AD-TOOL-002: Capability manifest and validation
- CTR-1303: Bounded collections with `MAX_*` constants
- RFC-0017: Daemon as Control Plane
