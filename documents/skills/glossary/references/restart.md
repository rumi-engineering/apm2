# Restart and Backoff

**Agent-Native Definition**: **Restart and Backoff** mechanisms define the system's resilience physics for autonomous agents. They govern how the **Supervisor** reacts to agent failures (crashes, timeouts, or policy violations) by applying deterministic retry strategies with increasing delays to prevent cascading failures or resource exhaustion.

## Core Concepts

### Restart Policy
A policy that determines if and how a process should be restarted after exit. Policies include:
*   **Always**: Restart regardless of exit status.
*   **OnFailure**: Restart only if the process exited with a non-zero status.
*   **Never**: Do not restart.

### Backoff Strategy
To prevent "thundering herd" problems or tight-loop crashing, the system applies a backoff strategy to the delay between restarts:
*   **Fixed**: A constant delay (e.g., 5 seconds).
*   **Linear**: Delay increases linearly (e.g., 5s, 10s, 15s...).
*   **Exponential**: Delay doubles each time (e.g., 1s, 2s, 4s, 8s...), usually with a jitter and a maximum cap.

### Circuit Breaker
If a process fails too many times within a specific window, the Supervisor may "open the circuit," transitioning the process to a `Failed` or `Quarantined` state and requiring manual intervention or a longer "cool-down" period.

## Data Structure References

*   **`RestartConfig`** (`crates/apm2-core/src/restart/mod.rs`): Configuration defining the restart policy and backoff strategy.
*   **`BackoffConfig`** (`crates/apm2-core/src/restart/mod.rs`): Enum defining the specific backoff algorithm and parameters (e.g., `Exponential { initial_ms, max_ms, factor }`).

## See Also
*   **Supervisor**: The component that enforces restart policies.
*   **Process State**: The state transitions triggered by restarts.
