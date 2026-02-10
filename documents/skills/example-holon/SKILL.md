---
name: example-holon
description: Example holon pattern for bounded execution integration tests
user-invocable: false
holon:
  contract:
    input_type: TaskRequest
    output_type: TaskResult
    state_type: TaskProgress
  stop_conditions:
    max_episodes: 10
    timeout_ms: 300000
    max_stall_episodes: 3
    budget:
      tokens: 50000
      tool_calls: 100
  tools:
    - read_file
    - write_file
    - glob
    - grep
---

# Example Holon Skill

## Purpose

This fixture documents a holon pattern for bounded execution with explicit
tool restriction and deterministic stop condition behavior.

## Usage Pattern

The holon accepts intake work, executes bounded episodes, and emits progress.
When a local strategy cannot complete safely, it uses escalation.

## Episode Lifecycle

1. `intake` validates the request and lease.
2. `execute_episode` advances work in bounded steps.
3. The loop continues until completion or a stop condition is reached.

## Stop Conditions

Configured limits are `max_episodes`, `timeout_ms`, and budget tokens.
The fixture uses max_episodes=10, timeout_ms=300000, and tokens=50000.

## Tool Permissions

Allowed tools are explicit and fail-close by default.
Only listed tools are available to prevent accidental capability expansion.

## Integration with spawn_holon

Use `spawn_holon` with a lease budget derived from this configuration.

```rust
let config = SpawnConfig::builder()
    .work_id("example-work")
    .work_title("Example")
    .issuer_id("test-registrar")
    .holder_id("example-holon")
    .scope(LeaseScope::builder().tools(&["read_file", "write_file"]).build())
    .budget(Budget::new(10, 100, 50_000, 300_000))
    .expires_at_ns(10_000_000_000)
    .build()?;

let result = spawn_holon(&mut holon, "task".to_string(), config, clock)?;
```

## Related Documentation

This fixture supports integration tests for TCK-00047 in `skill_integration.rs`.

## Invariants

- bounded execution: every run has finite budgets.
- stop condition checks are deterministic for identical inputs.
- tool restriction remains explicit and minimal.
- escalation occurs when local completion is not feasible.
