# Agent Module - Agent Guidelines

## Purpose

This module defines protocol definitions for agent communication with the APM2 runtime, including exit signals for clean session handoff.

## Module Overview

```
agent/
├── mod.rs           # Module index and re-exports
├── exit.rs          # Exit signal protocol and events
└── AGENTS.md        # This file
```

## Key Types

- **`ExitSignal`**: JSON-serializable exit signal emitted by agents on phase completion
- **`ExitReason`**: Why the agent is exiting (completed, blocked, error)
- **`WorkPhase`**: The work phase that was completed
- **`AgentSessionCompleted`**: Ledger event emitted when a valid exit signal is received

## Invariants

### [INV-EXIT001] Valid Exit Signals Emit Events

A valid `ExitSignal` that passes `validate()` **MUST** result in an `AgentSessionCompleted` event being emitted to the ledger.

### [INV-EXIT002] Invalid Signals Never Modify State

An invalid `ExitSignal` (wrong protocol, unsupported version, malformed JSON) **MUST NOT** modify any work item state or emit any events.

### [INV-EXIT003] Feature Flag Caching

The `AGENT_EXIT_PROTOCOL_ENABLED` feature flag is read once on first access and cached for the lifetime of the process. This ensures:
- No hot-path `env::var` calls
- Consistent behavior within a process lifetime
- Predictable performance characteristics

## Contracts

### [CTR-EXIT001] Exit Signal Immutability

Exit signals are immutable once emitted. There is no protocol for "updating" or "canceling" an exit signal.

### [CTR-EXIT002] Protocol Field Validation

The `protocol` field **MUST** be exactly `"apm2_agent_exit"`. Any other value is rejected with `ExitSignalError::UnknownProtocol`.

### [CTR-EXIT003] Version Compatibility

The `version` field **MUST** start with `"1."` for semver compatibility with the 1.x protocol series. Version 2.x and higher are reserved for breaking changes.

### [CTR-EXIT004] Phase Validation

The `phase_completed` field **MUST** be one of the defined `WorkPhase` enum variants. Unknown phases are rejected.

### [CTR-EXIT005] Exit Reason Validation

The `exit_reason` field **MUST** be one of: `completed`, `blocked`, `error`.

### [CTR-EXIT006] Deny Unknown Fields

The `ExitSignal` and `AgentSessionCompleted` types use `#[serde(deny_unknown_fields)]` to reject JSON with unexpected fields. This prevents:
- Injection attacks via unhandled fields
- Forward compatibility issues
- Processing of malformed signals

## Security Considerations

### Fail-Closed Default

The `AGENT_EXIT_PROTOCOL_ENABLED` feature flag defaults to `false`. This means:
- Exit signals are NOT processed by default
- Explicit opt-in is required
- Security review should precede enabling

### Trust Boundary

Exit signals are emitted by agents running within the APM2 runtime. The protocol assumes:
- Agents are authenticated via session/actor IDs
- Agents are authorized to complete the work they claim
- The runtime validates signals before accepting them

Exit signals themselves are NOT cryptographically signed because:
1. They're emitted by trusted agents within the runtime
2. They're validated immediately upon receipt
3. The resulting `AgentSessionCompleted` event IS persisted with hash chain integrity

## Usage Examples

### Creating an Exit Signal

```rust
use apm2_core::agent::{ExitSignal, ExitReason, WorkPhase};

let signal = ExitSignal::new(WorkPhase::Implementation, ExitReason::Completed)
    .with_pr_url("https://github.com/org/repo/pull/123")
    .with_notes("Implementation complete");

// Validate before serializing
signal.validate()?;

// Serialize for output
let json = serde_json::to_string_pretty(&signal)?;
```

### Parsing an Exit Signal

```rust
use apm2_core::agent::ExitSignal;

let json = r#"{"protocol":"apm2_agent_exit","version":"1.0.0",...}"#;
let signal = ExitSignal::from_json(json)?;

// Or with feature flag check
let signal = ExitSignal::from_json_if_enabled(json)?;
```

### Creating a Completion Event

```rust
use apm2_core::agent::{AgentSessionCompleted, ExitSignal, ExitReason, WorkPhase};

let signal = ExitSignal::new(WorkPhase::Implementation, ExitReason::Completed);
let event = AgentSessionCompleted::from_exit_signal(
    "session-123",
    "actor-456",
    signal,
);
```

## Testing Guidelines

1. **Always test validation**: Test both valid and invalid inputs
2. **Test serialization roundtrips**: Ensure JSON survives encode/decode
3. **Test `deny_unknown_fields`**: Verify extra fields are rejected
4. **Test feature flag behavior**: Test both enabled and disabled states
5. **Test all work phases**: Each phase should serialize/deserialize correctly
6. **Test all exit reasons**: Each reason should produce correct behavior

## Related Modules

- `session`: Session lifecycle management
- `work`: Work item state transitions
- `events`: Ledger event definitions
- `ledger`: Event persistence
