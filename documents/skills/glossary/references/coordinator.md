# Coordinator

**Agent-Native Definition**: A **Coordinator** is a specialized agent role responsible for **Work Decomposition** and **Delegation**. Unlike a standard worker holon that executes a specific task, a Coordinator manages the lifecycle of complex goals by breaking them down into atomic **Plans**, assigning them to sub-holons, and synthesizing the results.

## Core Concepts

### Work Decomposition
The primary function of a Coordinator is to take a high-level objective (e.g., "Implement Feature X") and decompose it into a dependency graph of smaller, executable units (Plans). This requires understanding the system architecture and the capabilities of available tools.

### Delegation & Orchestration
Coordinators do not execute the leaf tasks themselves. Instead, they act as "parents" in the holonic hierarchy, spawning or leasing "child" holons to perform the work. They monitor progress, handle inter-dependencies, and aggregate outputs.

### Fault Recovery
A Coordinator is responsible for the resilience of its subgraph. If a child holon fails, the Coordinator must decide whether to retry, re-plan, or escalate the failure to its own supervisor.

## Data Structure References

*   **`apm2_core::session::RestartCoordinator`** (`crates/apm2-core/src/session/restart_coordinator.rs`): A concrete implementation of coordination logic focused on session recovery and restart decisions.
*   **`apm2_holon::episode::EpisodeController`** (`crates/apm2-holon/src/episode/controller.rs`): The mechanism by which a Coordinator executes its own control loop to manage sub-episodes.
*   **`apm2_holon::work::WorkObject`** (`crates/apm2-holon/src/work.rs`): The objects managed and delegated by the Coordinator.

## See Also

*   **[Supervisor](supervisor.md)**: The role responsible for budget enforcement and higher-level failure handling (often the "boss" of a Coordinator).
*   **[Holon](holon.md)**: The fundamental unit that can act as a Coordinator.
*   **[Plan](plan.md)**: The work units created and assigned by the Coordinator.
