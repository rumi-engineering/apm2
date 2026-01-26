# Session

**Agent-Native Definition**: A **Session** is the "Temporal Continuity" of an agent's interaction with a specific goal. It spans across multiple **Episodes** and potentially across process restarts. The **SessionState** tracks the persistent progress, context, and accumulated evidence of the agent's journey toward satisfying a **Plan**.

## Core Concepts

### Continuity
Unlike an Episode, which is transient and bounded, a Session provides the memory of what has already been tried and what has been learned. This state is reconstructed from the **Ledger** after a crash or restart, ensuring the agent doesn't "lose its place."

### Session Token
Every **ToolRequest** must include a `session_token`. The Kernel uses this to authenticate the request, verify it against the session's active **Lease**, and ensure the agent is operating within its authorized temporal window.

### Session Recovery
If the daemon or the agent process fails, the session can be recovered by replaying the `SessionStarted` and subsequent events. This allows for "Resume-at-Failure" capability, which is critical for long-running autonomous tasks.

## Data Structure References

*   **`SessionState`** (`crates/apm2-core/src/session/state.rs`): The aggregated state of an active session, including its ID, associated work ID, and current progress.
*   **`RestartCoordinator`** (`crates/apm2-core/src/session/restart_coordinator.rs`): The logic used to decide how to recover a session after a failure.

## See Also
*   **Episode**: The discrete execution window within a session.
*   **Ledger**: The source of truth for session recovery.
