# Process

**Agent-Native Definition**: A **Process** is the operating-system-level execution unit of a **Holon**. In APM2, processes are treated as "Ephemeral Workers" managed by a **Supervisor**. The life of a process is strictly governed by its **ProcessSpec**, and its current condition is reflected in its **ProcessState**.

## Core Concepts

### Process Specification (Spec)
The `ProcessSpec` is the blueprint for a process. It defines the command, arguments, environment variables, working directory, and resource limits. In the APM2 ecosystem, these are typically derived from the `ecosystem.toml` configuration.

### Process State
The `ProcessState` is the real-time projection of a process's condition. Transitions between states (e.g., `Starting` -> `Running` -> `Stopped`) are triggered by OS signals, supervisor actions, or the process's own exit.

### Isolation
While APM2 currently runs processes on the host Linux system, the architecture is designed for "Default-Deny" isolation. Future iterations and specific adapters (like `seccomp`) restrict what a process can do at the syscall level.

## Data Structure References

*   **`ProcessSpec`** (`crates/apm2-core/src/process/mod.rs`): The immutable configuration for a process.
*   **`ProcessState`** (`crates/apm2-core/src/process/mod.rs`): Enum representing the lifecycle status (e.g., `Running { pid, started_at }`, `Stopped { exit_code, finished_at }`, `Crashed`).

## See Also
*   **Supervisor**: The role that manages these processes.
*   **Restart and Backoff**: The logic applied when a process enters a `Stopped` or `Crashed` state.
