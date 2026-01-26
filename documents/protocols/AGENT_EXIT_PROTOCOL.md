# Agent Exit Protocol

**Version:** 1.0.0
**Status:** Active
**RFC:** RFC-0008 (Event-Driven Agent Handoff)
**Ticket:** TCK-00088

## Overview

The Agent Exit Protocol defines how agents signal completion of a work phase to enable clean handoff to the next agent without polling.

When an agent completes a work phase, it **MUST** emit a structured JSON exit signal. The system validates the signal and:

1. Emits an `AgentSessionCompleted` event to the ledger
2. Updates the work item phase based on `phase_completed`
3. Releases the session's lease
4. Allows a fresh agent to claim the next phase

## Why This Matters

Without a structured exit protocol:

- Agents poll CI status, wasting context window and tokens
- Work state is unclear after agent exits
- Manual intervention is required to continue work
- Agents may attempt to "game" CI status out of frustration

The exit protocol solves these problems by providing a clear, structured way for agents to signal "I'm done, here's what I accomplished."

## JSON Schema

```json
{
  "protocol": "apm2_agent_exit",
  "version": "1.0.0",
  "phase_completed": "IMPLEMENTATION",
  "exit_reason": "completed",
  "pr_url": "https://github.com/org/repo/pull/123",
  "evidence_bundle_ref": "evidence/work/W-00042/phase_implementation.yaml",
  "notes": "Implementation complete, ready for CI"
}
```

## Required Fields

| Field | Type | Description |
|-------|------|-------------|
| `protocol` | string | Must be `"apm2_agent_exit"` |
| `version` | string | Protocol version (currently `"1.0.0"`) |
| `phase_completed` | string | The work phase that was just completed |
| `exit_reason` | string | Why the session is ending |

### Protocol Field

The `protocol` field **MUST** be exactly `"apm2_agent_exit"`. This allows the system to identify exit signals and prevents accidental parsing of unrelated JSON output.

### Version Field

The `version` field **MUST** be semver-compatible with `1.x`. Currently supported versions:

- `1.0.0` (initial release)

Version `2.x` and higher are reserved for future breaking changes.

### Phase Completed

Valid values for `phase_completed`:

| Value | Description |
|-------|-------------|
| `DRAFT` | Initial drafting phase |
| `IMPLEMENTATION` | Code implementation phase |
| `CI_PENDING` | Waiting for CI to complete |
| `READY_FOR_REVIEW` | CI passed, awaiting human review |
| `REVIEW` | Under human review |
| `READY_FOR_MERGE` | Review approved, ready to merge |
| `COMPLETED` | Work has been completed and merged |
| `BLOCKED` | Work is blocked and cannot proceed |

### Exit Reason

Valid values for `exit_reason`:

| Value | Description | Next Action |
|-------|-------------|-------------|
| `completed` | Work phase finished successfully | Transition to next phase |
| `blocked` | Cannot proceed due to external blocker | Mark work as blocked |
| `error` | Session ending due to error | Mark work as blocked |

## Optional Fields

| Field | Type | Description |
|-------|------|-------------|
| `pr_url` | string | GitHub PR URL if a PR was created |
| `evidence_bundle_ref` | string | Path to evidence bundle for this phase |
| `notes` | string | Human-readable notes about the exit |

## Phase Transitions

When the system receives a valid exit signal, it determines the next phase:

| Phase Completed | Exit Reason | Next Phase |
|-----------------|-------------|------------|
| `IMPLEMENTATION` | `completed` | `CI_PENDING` |
| `CI_PENDING` | `completed` | `READY_FOR_REVIEW` |
| `READY_FOR_REVIEW` | `completed` | `REVIEW` |
| `REVIEW` | `completed` | `READY_FOR_MERGE` |
| `READY_FOR_MERGE` | `completed` | `COMPLETED` |
| Any | `blocked` | `BLOCKED` |
| Any | `error` | `BLOCKED` |

## Examples

### Implementation Complete

Agent has finished implementing a feature and created a PR:

```json
{
  "protocol": "apm2_agent_exit",
  "version": "1.0.0",
  "phase_completed": "IMPLEMENTATION",
  "exit_reason": "completed",
  "pr_url": "https://github.com/org/repo/pull/123",
  "notes": "Implemented feature X, all tests passing locally"
}
```

### Review Complete

Reviewer has approved the PR:

```json
{
  "protocol": "apm2_agent_exit",
  "version": "1.0.0",
  "phase_completed": "REVIEW",
  "exit_reason": "completed",
  "evidence_bundle_ref": "evidence/work/W-00042/review.yaml",
  "notes": "Code review approved, no issues found"
}
```

### Blocked by External Dependency

Agent cannot proceed due to missing information:

```json
{
  "protocol": "apm2_agent_exit",
  "version": "1.0.0",
  "phase_completed": "IMPLEMENTATION",
  "exit_reason": "blocked",
  "notes": "Blocked: Waiting for API credentials from infra team"
}
```

### Error Exit

Agent encountered an unrecoverable error:

```json
{
  "protocol": "apm2_agent_exit",
  "version": "1.0.0",
  "phase_completed": "IMPLEMENTATION",
  "exit_reason": "error",
  "notes": "Error: Build system configuration issue prevents compilation"
}
```

## What Happens After Exit

1. **Signal Validation**: System validates the exit signal format and protocol version
2. **Event Emission**: `AgentSessionCompleted` event is emitted to the ledger
3. **Phase Transition**: Work item transitions to the next appropriate phase
4. **Lease Release**: Session's lease is released, freeing the work for claiming
5. **CI Runs** (if applicable): For `CI_PENDING` phase, CI runs automatically
6. **Next Agent Claims**: A fresh agent can claim the work when it's ready

## Feature Flag

Exit signal validation is controlled by the `AGENT_EXIT_PROTOCOL_ENABLED` environment variable:

- `false` (default): Exit signals are not validated (fail-closed security)
- `true`, `1`, or `yes`: Exit signals are validated and processed

To enable:

```bash
export AGENT_EXIT_PROTOCOL_ENABLED=true
```

## Error Handling

### Invalid Protocol

```
Error: unknown protocol: expected 'apm2_agent_exit', got 'wrong_protocol'
```

**Resolution**: Use exactly `"apm2_agent_exit"` for the protocol field.

### Unsupported Version

```
Error: unsupported version: expected '1.x', got '2.0.0'
```

**Resolution**: Use a version starting with `1.` (e.g., `1.0.0`, `1.1.0`).

### Invalid JSON

```
Error: invalid JSON: expected `"` at line 3 column 5
```

**Resolution**: Ensure the exit signal is valid JSON with correct quoting.

### Validation Disabled

```
Error: exit signal validation is disabled (AGENT_EXIT_PROTOCOL_ENABLED=false)
```

**Resolution**: Enable the feature flag or contact the system administrator.

## Integration Guide

### For Agent Implementers

1. At the end of each work phase, emit the exit signal as JSON to stdout
2. Include all required fields
3. Set `exit_reason` appropriately:
   - `completed` if the phase finished successfully
   - `blocked` if external dependencies prevent progress
   - `error` if an error occurred
4. Include optional fields when relevant (PR URL, evidence bundle, notes)
5. Do NOT poll for CI status after emitting the exit signal

### For System Integrators

1. Parse agent stdout for the exit signal pattern
2. Validate using `ExitSignal::from_json_if_enabled()`
3. Create `AgentSessionCompleted` event from the signal
4. Persist event to ledger
5. Trigger work item phase transition
6. Release session lease

## Rust API

```rust
use apm2_core::agent::exit::{ExitSignal, ExitReason, WorkPhase, AgentSessionCompleted};

// Create an exit signal
let signal = ExitSignal::new(WorkPhase::Implementation, ExitReason::Completed)
    .with_pr_url("https://github.com/org/repo/pull/123")
    .with_notes("Implementation complete");

// Validate
signal.validate()?;

// Serialize to JSON
let json = serde_json::to_string_pretty(&signal)?;

// Parse from JSON
let parsed = ExitSignal::from_json(&json)?;

// Create completion event
let event = AgentSessionCompleted::from_exit_signal(
    "session-123",
    "actor-456",
    parsed,
);
```

## Security Considerations

### Fail-Closed Default

The feature flag defaults to disabled (fail-closed security). This ensures that:

- Untested deployments don't accidentally process exit signals
- Security review is required before enabling
- Gradual rollout is possible

### Unknown Field Rejection

The `#[serde(deny_unknown_fields)]` attribute ensures that exit signals with unexpected fields are rejected. This prevents:

- Injection of malicious data via unhandled fields
- Forward compatibility issues with unknown fields
- Accidental processing of malformed signals

### Signature Verification

Exit signals themselves are not cryptographically signed because they are:

1. Emitted by trusted agents within the APM2 runtime
2. Validated immediately upon receipt
3. Used to generate signed ledger events

The `AgentSessionCompleted` event that results from a valid exit signal **IS** persisted to the append-only ledger with cryptographic hash chaining.

## Changelog

### 1.0.0 (2026-01-26)

- Initial release
- Core exit signal schema
- Work phase transitions
- Feature flag support
- `AgentSessionCompleted` event emission
