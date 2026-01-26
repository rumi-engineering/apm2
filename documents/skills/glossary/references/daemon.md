# Daemon State

**Agent-Native Definition**: **Daemon State** represents the "Living Memory" of the APM2 Kernel (`apm2-daemon`). It is the in-memory projection of the system's current condition, aggregated from the **Ledger** and real-time process observations. It provides the low-latency state required for IPC handlers to respond to CLI requests.

## Core Concepts

### Thread-Safe Shared State
Because the daemon handles multiple concurrent IPC requests and manages background process watchers, the state is wrapped in thread-safe primitives (`Arc<RwLock<...>>`). This allows the `SharedState` to be passed across task boundaries safely.

### Projections
The Daemon State is a projection. It is not the source of truth (the Ledger is). If the daemon restarts, it re-populates its state by replaying the ledger. This ensures that the in-memory view is always consistent with the durable history.

### Runner Registry
A key component of the state is the registry of active process "Runners." Each runner is identified by a `RunnerKey`, which uniquely maps a process specification and instance index to a specific OS process handle and monitoring task.

## Data Structure References

*   **`DaemonStateHandle`** (`crates/apm2-daemon/src/state.rs`): The struct managing the core daemon state, including process collections and system settings.
*   **`SharedState`** (`crates/apm2-daemon/src/state.rs`): A type alias for `Arc<DaemonStateHandle>`, the standard way to share state across the daemon's async tasks.
*   **`RunnerKey`** (`crates/apm2-daemon/src/state.rs`): A composite key `(ProcessId, instance_index)` used to lookup active process runners.

## See Also
*   **Ledger**: The durable source for the Daemon State.
*   **Process**: The entities tracked within the state.
