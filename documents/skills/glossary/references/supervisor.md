# Supervisor

**Agent-Native Definition**: A **Supervisor** is an infrastructure role responsible for the **Lifecycle Management**, **Budget Enforcement**, and **Recovery** of agent processes. It acts as the "Operating System" for holons, ensuring that they run within their constraints and do not destabilize the system.

## Core Concepts

### Process Supervision
The Supervisor manages the actual OS-level processes (or logical equivalents) of agents. It handles startup, shutdown, and monitoring of exit statuses. It maintains a registry of active processes and their specifications.

### Budget Enforcement
Supervisors enforce the economic constraints of the system. They track resource usage (tokens, time, episodes) against the assigned **Lease**. If an agent exceeds its budget, the Supervisor intervenes—potentially terminating the agent to preserve system integrity.

### Escalation Handling
When a worker or coordinator fails and cannot recover locally, it "escalates" to the Supervisor. The Supervisor then applies recovery strategies defined in the policy (e.g., restart with backoff, quarantine, or alert a human).

## Data Structure References

*   **`apm2_core::supervisor::Supervisor`** (`crates/apm2-core/src/supervisor/mod.rs`): The primary struct implementing the supervision logic, managing process handles and specifications.
*   **`apm2_core::process::ProcessHandle`** (`crates/apm2-core/src/process/mod.rs`): The handle used by the Supervisor to interact with running processes.
*   **`apm2_core::restart::RestartManager`** (`crates/apm2-core/src/restart/mod.rs`): The component used by the Supervisor to determine restart policies.

## See Also

*   **[Coordinator](coordinator.md)**: A strategic role that delegates work (often supervised by this component).
*   **[Lease / Budget](lease_and_budget.md)**: The resource contracts enforced by the Supervisor.
*   **[Holon](holon.md)**: The entities being supervised.
