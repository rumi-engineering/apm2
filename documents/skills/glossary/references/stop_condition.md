# Stop Condition

**Agent-Native Definition**: A **Stop Condition** is the "Termination Predicate" that signals the end of a Holon's execution window (Episode). It defines the boundary where an agent must stop acting and yield control back to the **Supervisor**. Stop conditions ensure that autonomous execution is always bounded, safe, and governed by policy.

## Core Concepts

### Priority-Ordered Termination
Stop conditions are evaluated by the **EpisodeController** in a specific priority order to ensure safety:
1.  **Budget Exhaustion**: (Highest Priority) Stops execution immediately when resources (tokens, time) are spent.
2.  **Goal Satisfaction**: Stops when the agent signals it has completed the task.
3.  **External Signal**: Stops when the system or user sends a termination signal (e.g., `SIGTERM`).
4.  **Failure/Error**: Stops when a critical system or reasoning error occurs.

### Success vs. Failure
Not all stop conditions are errors. `GoalSatisfied` and `Escalated` are considered "Successful" terminations of the control loop, as they represent a logical conclusion to the agent's reasoning process. `BudgetExhausted` and `ErrorCondition` are "Unsuccessful" and may trigger retry or recovery logic.

## Data Structure References

*   **`StopCondition`** (`crates/apm2-holon/src/stop.rs`): Enum defining the various reasons for termination (e.g., `GoalSatisfied`, `BudgetExhausted { resource }`, `MaxEpisodesReached`, `PolicyViolation`).

## See Also
*   **Episode**: The execution window governed by stop conditions.
*   **Lease / Budget**: The source of the resource-based stop conditions.
