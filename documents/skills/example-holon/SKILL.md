---
name: example-holon
description: A sample skill demonstrating the holon pattern for task execution.
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

> **Note:** This skill is a legacy Markdown-based definition. It needs to be converted to a Context-as-Code approach in the future.

## Purpose

This skill serves as a reference implementation and test fixture for the holon execution pattern. It demonstrates how to configure discrete episodes, resource budgets, and tool permissions.

## Usage Pattern

Holons are designed for **bounded execution** where tasks are decomposed into multiple episodes. Each episode follows a strict lifecycle: **intake**, **execute_episode**, and state update.

## Episode Lifecycle

The holon executes in discrete episodes, each attempting to progress the task until a **stop condition** is met. This ensures the system remains responsive and can handle **escalation** if needed.

## Stop Conditions

To prevent runaway processes, the following limits are enforced:
- **Max Episodes:** 10 (max_episodes)
- **Timeout:** 5 minutes (timeout_ms)
- **Max Stall:** 3 episodes without progress
- **Token Budget:** 50,000 tokens
- **Tool Budget:** 100 calls

## Tool Permissions

All tool access is subject to **tool restriction** and **fail-close** policy enforcement.
- `read_file`: To examine workspace state.
- `write_file`: To apply changes.
- `glob`: To locate files.
- `grep`: To search content.

## Integration with spawn_holon

The skill configuration is used to initialize the `SpawnConfig` which is then passed to `spawn_holon`.

```rust
let config = spawn_config_from_holon_config("task-id", &holon_config)?;
let result = spawn_holon(&mut holon, intake_data, config, clock)?;
```

## Related Documentation

Refer to the Holonic Theory for more details on the architecture.

## Invariants

- Total **tokens** consumed must not exceed the configured budget.
- Execution must terminate if any stop condition is triggered.

## Contract

This holon follows the standard `TaskRequest` -> `TaskResult` contract, maintaining `TaskProgress` state between episodes.