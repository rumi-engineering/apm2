# Episode

**Agent-Native Definition**: An **Episode** is a "Bounded Context Window" of execution for a Holon. It represents a discrete unit of work where an agent perceives its environment, reasons about its goal, acts upon the environment, and evaluates the outcome, all within a strictly enforced resource budget.

Episodes are the fundamental "tick" of the Holonic execution loop, enabling the system to guarantee termination, manage resource consumption, and maintain a verifiable audit trail of agent behavior.

## Core Concepts

### Bounded Context Window
An episode is bounded in two dimensions:
1.  **Time/Budget**: Every episode has a strict limit on tokens, wall-clock time, and tool calls.
2.  **Scope**: The agent's context is refreshed or updated at the start of each episode, ensuring it operates on the latest state of the world.

### Episode Lifecycle
The `EpisodeController` manages the lifecycle:
1.  **Context Construction**: The `EpisodeContext` is built from the current work state, accumulating previous events and current constraints.
2.  **Execution**: The Holon executes, performing reasoning and actions.
3.  **Result Evaluation**: The `EpisodeResult` is analyzed to determine if the goal is met or if a stop condition is triggered.

### Stop Conditions
The execution loop terminates when one of the following priority-ordered conditions is met:
1.  **Budget Exhausted**: The `Lease` for the episode or the global budget is depleted.
2.  **Goal Satisfied**: The Holon signals that the assigned work is complete.
3.  **Blocked**: The Holon cannot make further progress (e.g., waiting for external input).
4.  **Escalated**: The Holon determines the task is beyond its capabilities and requests supervisor intervention.
5.  **Error**: An unrecoverable system error occurs.

### Budget & Max Episodes
To prevent runaway agents, the system enforces a `max_episodes` limit (default: 100) per execution loop. Each episode also consumes from a `Budget` allocated by a `Lease`. If the budget runs out, the episode is forcibly terminated, ensuring predictable cost and performance.

## Data Structure References
*   **`EpisodeContext`** (`crates/apm2-holon/src/context.rs`): Contains the input state for the episode, including budgets and work IDs.
*   **`EpisodeResult`** (`crates/apm2-holon/src/result.rs`): Captures the output of the episode, including the outcome (`Completed`, `Failed`, etc.) and resource consumption.
*   **`EpisodeController`** (`crates/apm2-holon/src/episode/controller.rs`): The engine that drives the execution loop.

## See Also
*   **Holon**: The entity that executes the episode.
*   **Lease / Budget**: The resource constraints applied to the episode.
